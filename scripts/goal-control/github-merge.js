'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ControlError, assertControl } = require('./errors');
const {
  authorizeGoalSession,
  hashesEqual,
  readCapabilityFile,
} = require('./auth');
const { actorSequenceKey } = require('./fsm');
const { ensurePrivateDirectory } = require('./init-receipt');
const {
  acceptedEventFiles,
  atomicCreate,
  atomicWriteJson,
  canonicalTransactionKey,
  ensureDir,
  goalDir,
  goalMergeTargetReservations,
  withLock,
} = require('./store');
const {
  assertFullSha,
  assertIsolatedTestMode,
  controlRoot,
  hashFile,
  hashObject,
  normalizeHash,
  nowIso,
  readJson,
  safeId,
  sha256,
} = require('./util');
const { parsePullRequestUrl, validateEvent } = require('./validation');
const { trustedExecutableCandidates } = require('./gate-adapters');

const POLICY = 'goalctl-github-squash-v1';
const RESERVATION_TYPE = 'GITHUB_MERGE_RESERVED';
const INTENT_KIND = 'GITHUB_MERGE_INTENT';
const INVOCATION_KIND = 'GITHUB_MERGE_DISPATCH_AUTHORIZATION';
const RECEIPT_KIND = 'GITHUB_MERGE_RECEIPT';
const COMPLETION_KIND = 'GITHUB_MERGE_COMPLETION';
const MAX_CAPTURE_BYTES = 1024 * 1024;
const EXTERNAL_TIMEOUT_MS = 30 * 1000;
const MERGE_FETCH_MARKER = '.goalctl-fetch-owner';
const PROCESS_HOST_ID = os.hostname();

function processStartToken(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  const observed = spawnSync(
    'ps',
    ['-o', 'lstart=', '-p', String(pid)],
    {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5_000,
    },
  );
  if (observed.status !== 0) return null;
  const value = String(observed.stdout || '').trim().replace(/\s+/g, ' ');
  return value.length > 0 ? value : null;
}

const PROCESS_START_TOKEN = processStartToken(process.pid);
const MERGE_ARTIFACT_STAGES = Object.freeze([
  ['intent', 'intents', INTENT_KIND, 'intent_sha256'],
  ['invocation', 'invocations', INVOCATION_KIND, 'invocation_sha256'],
  ['receipt', 'receipts', RECEIPT_KIND, 'receipt_sha256'],
  ['completion', 'completions', COMPLETION_KIND, 'completion_sha256'],
]);
const PR_FIELDS = [
  'number',
  'url',
  'state',
  'isDraft',
  'baseRefName',
  'baseRefOid',
  'headRefName',
  'headRefOid',
  'headRepository',
  'headRepositoryOwner',
  'isCrossRepository',
  'mergeCommit',
  'mergedAt',
  'mergedBy',
  'mergeable',
  'mergeStateStatus',
  'statusCheckRollup',
  'closingIssuesReferences',
  'body',
].join(',');

function mergePolicyEnabled(manifest) {
  return Boolean(
    manifest
      && manifest.repository
      && manifest.repository.merge_policy === POLICY,
  );
}

function reservationEventId(request) {
  return `github-merge-reservation-${sha256([
    request.goal_id,
    request.task_id,
    request.event_id,
    hashObject(request),
  ].join('\n')).slice(0, 32)}`;
}

function mergeTaskPaths(root, goalId, taskId, eventId = null) {
  safeId(goalId, 'goal_id');
  safeId(taskId, 'task_id');
  const base = goalDir(root, goalId);
  const directories = {
    intents: path.join(base, 'github-merge-intents', taskId),
    invocations: path.join(base, 'github-merge-invocations', taskId),
    receipts: path.join(base, 'github-merge-receipts', taskId),
    completions: path.join(base, 'github-merge-completions', taskId),
  };
  if (!eventId) return directories;
  safeId(eventId, 'merge event_id');
  return {
    ...directories,
    intent: path.join(directories.intents, `${eventId}.json`),
    invocation: path.join(directories.invocations, `${eventId}.json`),
    receipt: path.join(directories.receipts, `${eventId}.json`),
    completion: path.join(directories.completions, `${eventId}.json`),
  };
}

function assertPrivateFile(file, label) {
  const stat = fs.lstatSync(file);
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && (stat.mode & 0o777) === 0o600
      && (
        typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
      ),
    'CORRUPT_STORE',
    `${label} 必须是当前 owner 的 0600 普通文件`,
  );
}

function sealed(record, sealKey) {
  return { ...record, [sealKey]: hashObject(record) };
}

function readSealed(file, sealKey, label) {
  if (!fs.existsSync(file)) return null;
  assertPrivateFile(file, label);
  const value = readJson(file, label);
  const unsigned = { ...value };
  delete unsigned[sealKey];
  assertControl(
    value[sealKey] === hashObject(unsigned),
    'CORRUPT_STORE',
    `${label} seal 不匹配`,
  );
  return value;
}

function assertRecordIdentity(value, kind, goalId, taskId, eventId, label) {
  assertControl(
    value
      && value.schema_version === 1
      && value.kind === kind
      && value.goal_id === goalId
      && value.task_id === taskId
      && value.event_id === eventId,
    'CORRUPT_STORE',
    `${label} identity 非法`,
  );
  return value;
}

function atomicTempEventId(name) {
  const match = name.match(
    /^\.([A-Za-z0-9][A-Za-z0-9._:-]{0,199})\.json\.([1-9][0-9]*)\.tmp-([0-9a-f]{24})$/,
  );
  if (!match) return null;
  safeId(match[1], 'GitHub merge atomic temp event_id');
  return match[1];
}

function scanArtifactDirectory(directory, label) {
  if (!fs.existsSync(directory)) {
    return { ids: [], temporaries: new Map() };
  }
  ensurePrivateDirectory(directory);
  const ids = new Set();
  const temporaries = new Map();
  for (const name of fs.readdirSync(directory).sort()) {
    if (name.endsWith('.json') && !name.startsWith('.')) {
      const eventId = name.slice(0, -'.json'.length);
      safeId(eventId, `${label} event_id`);
      ids.add(eventId);
      continue;
    }
    const eventId = atomicTempEventId(name);
    assertControl(
      eventId,
      'CORRUPT_STORE',
      `${label} 含非 canonical artifact ${name}`,
    );
    const file = path.join(directory, name);
    assertPrivateFile(file, `${label} atomic temp ${name}`);
    const entries = temporaries.get(eventId) || [];
    entries.push(file);
    temporaries.set(eventId, entries);
    ids.add(eventId);
  }
  for (const [eventId, entries] of temporaries.entries()) {
    assertControl(
      entries.length === 1,
      'CORRUPT_STORE',
      `${label} event ${eventId} 含多个 atomic temp`,
    );
  }
  return { ids: [...ids].sort(), temporaries };
}

function readMergeTransaction(root, goalId, taskId, eventId) {
  const files = mergeTaskPaths(root, goalId, taskId, eventId);
  const reservations = goalMergeTargetReservations(root, goalId, eventId);
  assertControl(
    reservations.every((event) => event.task_id === taskId),
    'EVENT_ID_CONFLICT',
    `GitHub merge target ${eventId} 已由其它 task reservation 占用`,
  );
  const reservation = reservations.length === 1 ? reservations[0] : null;
  const temporaries = {};
  for (const [stage, directoryKey] of MERGE_ARTIFACT_STAGES) {
    const inventory = scanArtifactDirectory(
      files[directoryKey],
      `GitHub merge ${directoryKey}`,
    );
    temporaries[stage] = inventory.temporaries.get(eventId) || [];
  }
  const intent = readSealed(
    files.intent,
    'intent_sha256',
    `GitHub merge intent ${eventId}`,
  );
  const invocation = readSealed(
    files.invocation,
    'invocation_sha256',
    `GitHub merge invocation ${eventId}`,
  );
  const receipt = readSealed(
    files.receipt,
    'receipt_sha256',
    `GitHub merge receipt ${eventId}`,
  );
  const completion = readSealed(
    files.completion,
    'completion_sha256',
    `GitHub merge completion ${eventId}`,
  );
  if (!intent) {
    assertControl(
      !invocation && !receipt && !completion,
      'CORRUPT_STORE',
      `GitHub merge ${eventId} 有 artifact 但缺 intent`,
    );
    return {
      files,
      intent: null,
      invocation: null,
      receipt: null,
      completion: null,
      reservation,
      temporaries,
    };
  }
  assertRecordIdentity(intent, INTENT_KIND, goalId, taskId, eventId, 'GitHub merge intent');
  assertControl(
    intent.request
      && intent.request_sha256 === hashObject(intent.request)
      && intent.request.goal_id === goalId
      && intent.request.task_id === taskId
      && intent.request.event_id === eventId
      && intent.task_anchor
      && intent.repository
      && intent.pull_request
      && intent.acceptance_authority
      && intent.reservation
      && intent.reservation.event_id
        === reservationEventId(intent.request)
      && intent.preflight_attestation
      && intent.preflight_attestation.required_checks
      && intent.preflight_attestation.required_checks.status === 'PASS'
      && intent.preflight_attestation.gh_executable
      && /^sha256:[0-9a-f]{64}$/.test(
        intent.preflight_attestation.gh_executable.sha256,
      )
      && intent.serialization_policy
      && intent.serialization_policy.base_compare_and_swap
        === 'UNAVAILABLE_IN_GITHUB_MERGE_API',
    'CORRUPT_STORE',
    `GitHub merge intent ${eventId} binding 非法`,
  );
  if (reservation) {
    assertControl(
      reservation.type === RESERVATION_TYPE
        && reservation.event_id === intent.reservation.event_id
        && reservation.payload.target_event_id === eventId
        && reservation.payload.request_sha256 === intent.request_sha256
        && reservation.payload.repository
          === intent.repository.name_with_owner
        && reservation.payload.pull_request_number
          === intent.pull_request.number
        && reservation.payload.pull_request_url
          === intent.pull_request.url
        && reservation.payload.base_branch
          === intent.repository.base_branch
        && reservation.payload.expected_main_head
          === intent.pull_request.expected_main_head
        && reservation.payload.candidate_head
          === intent.pull_request.head
        && reservation.payload.task_cycle === intent.task_anchor.task_cycle
        && reservation.payload.phase === intent.task_anchor.phase
        && reservation.payload.issue === intent.pull_request.issue
        && reservation.payload.head_ref_name
          === intent.pull_request.head_ref_name
        && reservation.payload.body_sha256
          === intent.pull_request.body_sha256
        && reservation.payload.pr_contract_sha256
          === intent.pull_request.contract_sha256
        && hashObject(reservation.payload.preflight_attestation)
          === hashObject(intent.preflight_attestation),
      'CORRUPT_STORE',
      `GitHub merge reservation ${reservation.event_id} 与 intent 不一致`,
    );
  }
  if (invocation) {
    assertRecordIdentity(invocation, INVOCATION_KIND, goalId, taskId, eventId, 'GitHub merge invocation');
    assertControl(
      invocation.intent_sha256 === intent.intent_sha256
        && invocation.request_sha256 === intent.request_sha256
        && invocation.command
        && invocation.command.executable === 'gh'
        && hashObject(invocation.command.argv)
          === invocation.command.argv_sha256
        && hashObject(invocation.command.argv)
          === hashObject(invocationArgv(intent))
        && [
          'AUTHORIZED_BEFORE_DISPATCH',
          'OBSERVED_AFTER_RESERVATION',
        ].includes(invocation.dispatch_mode)
        && (
          invocation.dispatch_mode !== 'OBSERVED_AFTER_RESERVATION'
            || invocation.external_dispatch_claimed === false
        )
        && typeof invocation.dispatch_authorized_at === 'string'
        && Number.isFinite(Date.parse(invocation.dispatch_authorized_at)),
      'CORRUPT_STORE',
      `GitHub merge invocation ${eventId} binding 非法`,
    );
  }
  if (receipt) {
    assertControl(
      invocation && reservation,
      'CORRUPT_STORE',
      `GitHub merge receipt ${eventId} 缺 dispatch authorization/reservation`,
    );
    assertRecordIdentity(receipt, RECEIPT_KIND, goalId, taskId, eventId, 'GitHub merge receipt');
    assertControl(
      receipt.intent_sha256 === intent.intent_sha256
        && receipt.invocation_sha256 === invocation.invocation_sha256
        && receipt.request_sha256 === intent.request_sha256
        && receipt.repository
        && receipt.repository.name_with_owner
          === intent.repository.name_with_owner
        && receipt.repository.base_branch === intent.repository.base_branch
        && receipt.pull_request
        && receipt.pull_request.number === intent.pull_request.number
        && receipt.pull_request.url === intent.pull_request.url
        && receipt.pull_request.base_ref_name
          === intent.repository.base_branch
        && receipt.pull_request.base_ref_oid
          === intent.pull_request.expected_main_head
        && receipt.pull_request.head_ref_name
          === intent.pull_request.head_ref_name
        && receipt.pull_request.head_ref_oid === intent.pull_request.head
        && typeof receipt.pull_request.head_repository === 'string'
        && receipt.pull_request.head_repository.toLowerCase()
          === intent.repository.name_with_owner.toLowerCase()
        && receipt.pull_request.body_sha256
          === intent.pull_request.body_sha256
        && typeof receipt.pull_request.merged_at === 'string'
        && Number.isFinite(Date.parse(receipt.pull_request.merged_at))
        && typeof receipt.pull_request.merged_by === 'string'
        && receipt.pull_request.merged_by.length > 0
        && receipt.result
        && /^[0-9a-f]{40}$/.test(receipt.result.main_merge_sha)
        && receipt.result.candidate_head === intent.pull_request.head
        && receipt.result.parent_sha
          === intent.pull_request.expected_main_head
        && receipt.result.remote_ref
          === `refs/heads/${intent.repository.base_branch}`
        && receipt.result.remote_ref_sha
          === receipt.result.main_merge_sha
        && (
          (
            receipt.result.remote_tracking_ref === null
              && receipt.result.remote_tracking_sha === null
          )
            || (
              receipt.result.remote_tracking_ref
                === `refs/remotes/origin/${intent.repository.base_branch}`
              && receipt.result.remote_tracking_sha
                === receipt.result.main_merge_sha
            )
        )
        && receipt.result.merge_tree === receipt.result.candidate_tree
        && receipt.result.task_patch_sha256
          === receipt.result.merged_patch_sha256
        && /^sha256:[0-9a-f]{64}$/.test(
          receipt.result.task_patch_sha256,
        )
        && receipt.event_anchor
        && receipt.event_anchor.event_id === eventId
        && hashObject(receipt.event_anchor)
          === hashObject(eventAnchor({ intent, reservation }))
        && receipt.event_anchor.goal_id === goalId
        && receipt.event_anchor.task_id === taskId
        && typeof receipt.reserved_event_at === 'string'
        && Number.isFinite(Date.parse(receipt.reserved_event_at)),
      'CORRUPT_STORE',
      `GitHub merge receipt ${eventId} binding 非法`,
    );
  }
  if (completion) {
    assertControl(receipt, 'CORRUPT_STORE', `GitHub merge completion ${eventId} 缺 receipt`);
    assertRecordIdentity(completion, COMPLETION_KIND, goalId, taskId, eventId, 'GitHub merge completion');
    assertControl(
      completion.intent_sha256 === intent.intent_sha256
        && completion.receipt_sha256 === receipt.receipt_sha256
        && reservation
        && completion.reservation_event_id === reservation.event_id
        && completion.reservation_event_sha256
          === reservation.event_sha256
        && completion.request_sha256 === intent.request_sha256
        && typeof completion.event_sha256 === 'string',
      'CORRUPT_STORE',
      `GitHub merge completion ${eventId} binding 非法`,
    );
  }
  return {
    files,
    intent,
    invocation,
    receipt,
    completion,
    reservation,
    temporaries,
  };
}

function acceptedMergeEvent(root, goalId, taskId, eventId) {
  const matches = acceptedEventFiles(root, goalId, taskId)
    .map((file) => readJson(file, `accepted event ${path.basename(file)}`))
    .filter((event) => event.event_id === eventId);
  assertControl(matches.length <= 1, 'CORRUPT_STORE', `merge event ${eventId} 重复`);
  if (matches.length === 0) return null;
  assertControl(matches[0].type === 'MERGED', 'EVENT_ID_CONFLICT', `${eventId} 已用于非 MERGED event`);
  return matches[0];
}

function transactionTempFiles(transaction) {
  return Object.values(transaction.temporaries || {}).flat();
}

function listGitHubMergeOperations(root, goalId, taskId) {
  const paths = mergeTaskPaths(root, goalId, taskId);
  const ids = new Set();
  for (const [label, directory] of Object.entries(paths)) {
    const inventory = scanArtifactDirectory(directory, `GitHub merge ${label}`);
    for (const eventId of inventory.ids) {
      ids.add(eventId);
    }
  }
  for (const reservation of goalMergeTargetReservations(root, goalId)) {
    if (reservation.task_id === taskId) {
      ids.add(reservation.payload.target_event_id);
    }
  }
  const pending = [];
  for (const eventId of [...ids].sort()) {
    const transaction = readMergeTransaction(root, goalId, taskId, eventId);
    const tempFiles = transactionTempFiles(transaction);
    if (!transaction.intent) {
      assertControl(
        tempFiles.length === 1 || transaction.reservation,
        'CORRUPT_STORE',
        `GitHub merge ${eventId} 缺 intent 或含多个未恢复 atomic temp`,
      );
      const reservationFile = transaction.reservation
        ? acceptedEventFiles(root, goalId, taskId).find((file) => (
          readJson(file, `accepted event ${path.basename(file)}`).event_id
            === transaction.reservation.event_id
        ))
        : null;
      pending.push({
        kind: 'GITHUB_MERGE',
        operation_id: eventId,
        request_sha256: transaction.reservation
          ? transaction.reservation.payload.request_sha256
          : null,
        goal_id: goalId,
        task_id: taskId,
        marker_file: tempFiles[0] || reservationFile,
        stage: tempFiles.length > 0
          ? 'RECOVERY_CHECKPOINT_REQUIRED'
          : 'RESERVATION_ACCEPTED_RECOVERY_REQUIRED',
      });
      continue;
    }
    const accepted = acceptedMergeEvent(root, goalId, taskId, eventId);
    if (transaction.completion) {
      assertControl(
        accepted
          && accepted.event_sha256 === transaction.completion.event_sha256
          && accepted.payload
          && accepted.payload.merge_receipt_sha256
            === transaction.receipt.receipt_sha256,
        'CORRUPT_STORE',
        `GitHub merge completion ${eventId} 没有 matching accepted event`,
      );
      continue;
    }
    pending.push({
      kind: 'GITHUB_MERGE',
      operation_id: eventId,
      request_sha256: transaction.intent.request_sha256,
      goal_id: goalId,
      task_id: taskId,
      marker_file: tempFiles[0] || (
        transaction.receipt
          ? transaction.files.receipt
          : transaction.invocation
            ? transaction.files.invocation
            : transaction.files.intent
      ),
      stage: tempFiles.length > 0
        ? 'RECOVERY_CHECKPOINT_REQUIRED'
        : accepted
          ? 'EVENT_ACCEPTED'
          : transaction.receipt
            ? 'RECEIPT_SEALED'
            : transaction.invocation
              ? 'DISPATCH_AUTHORIZED'
              : 'INTENT_SEALED',
    });
  }
  assertControl(
    pending.length <= 1,
    'CORRUPT_STORE',
    `task ${taskId} 同时存在多个 GitHub merge pending operation`,
  );
  return pending;
}

function fsyncDirectory(directory) {
  let fd;
  try {
    fd = fs.openSync(directory, 'r');
    fs.fsyncSync(fd);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code)) throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function exactMergeRecoveryInventory(root, request) {
  const files = mergeTaskPaths(
    root,
    request.goal_id,
    request.task_id,
    request.event_id,
  );
  const candidates = [];
  const foreign = [];
  for (const [stage, directoryKey, kind, sealKey] of MERGE_ARTIFACT_STAGES) {
    const directory = files[directoryKey];
    const inventory = scanArtifactDirectory(
      directory,
      `GitHub merge ${directoryKey}`,
    );
    foreign.push(
      ...[...inventory.temporaries.keys()]
        .filter((eventId) => eventId !== request.event_id)
        .map((eventId) => ({ stage, event_id: eventId })),
    );
    const entries = inventory.temporaries.get(request.event_id) || [];
    if (entries.length === 1) {
      candidates.push({
        stage,
        kind,
        sealKey,
        directory,
        final: files[stage],
        temporary: entries[0],
      });
    }
  }
  const reservations = goalMergeTargetReservations(
    root,
    request.goal_id,
    request.event_id,
  );
  assertControl(
    reservations.every((event) => event.task_id === request.task_id),
    'EVENT_ID_CONFLICT',
    `GitHub merge target ${request.event_id} 已由其它 task reservation 占用`,
  );
  const reservation = reservations.length === 1 ? reservations[0] : null;
  const finalStages = MERGE_ARTIFACT_STAGES
    .filter(([stage]) => fs.existsSync(files[stage]))
    .map(([stage]) => stage);
  return {
    files,
    candidates,
    foreign,
    reservation,
    finalStages,
    hasExactEvidence: Boolean(
      reservation || candidates.length > 0 || finalStages.length > 0,
    ),
  };
}

function initialIntentResidualPrefix(request) {
  const header = JSON.stringify({
    schema_version: 1,
    kind: INTENT_KIND,
    goal_id: request.goal_id,
    task_id: request.task_id,
    event_id: request.event_id,
    request,
    request_sha256: hashObject(request),
  }, null, 2);
  assertControl(
    header.endsWith('\n}'),
    'CORRUPT_STORE',
    'GitHub merge intent residual header 无法序列化',
  );
  return `${header.slice(0, -2)},`;
}

function initialIntentResidualCandidate(root, request, knownInventory = null) {
  const inventory = knownInventory
    || exactMergeRecoveryInventory(root, request);
  if (
    inventory.foreign.length > 0
      || inventory.reservation
      || inventory.finalStages.length > 0
      || inventory.candidates.length !== 1
      || inventory.candidates[0].stage !== 'intent'
  ) {
    return null;
  }
  const candidate = inventory.candidates[0];
  try {
    const sealedIntent = readSealed(
      candidate.temporary,
      candidate.sealKey,
      `GitHub merge ${candidate.stage} residual temp`,
    );
    if (sealedIntent) return null;
  } catch (error) {
    if (
      !(error instanceof ControlError)
        || !['CORRUPT_STORE', 'INVALID_JSON'].includes(error.code)
    ) {
      throw error;
    }
  }
  const before = fs.lstatSync(candidate.temporary);
  assertControl(
    before.isFile()
      && !before.isSymbolicLink()
      && before.size <= MAX_CAPTURE_BYTES,
    'MERGE_RECOVERY_SCOPE_CONFLICT',
    'GitHub merge initial intent residual 不是 bounded 普通文件',
  );
  const body = fs.readFileSync(candidate.temporary);
  const after = fs.lstatSync(candidate.temporary);
  assertControl(
    before.dev === after.dev
      && before.ino === after.ino
      && before.size === after.size
      && before.mtimeMs === after.mtimeMs,
    'MERGE_RECOVERY_SCOPE_CONFLICT',
    'GitHub merge initial intent residual 在检查期间漂移',
  );
  const text = body.toString('utf8');
  assertControl(
    Buffer.from(text, 'utf8').equals(body),
    'MERGE_RECOVERY_SCOPE_CONFLICT',
    'GitHub merge initial intent residual 不是 UTF-8 JSON prefix',
  );
  const prefix = initialIntentResidualPrefix(request);
  if (
    !prefix.startsWith(text)
      && !text.startsWith(`${prefix}\n`)
  ) {
    return null;
  }
  return { inventory, candidate, body };
}

function discardInitialIntentResidualUnderLock(root, request) {
  const residual = initialIntentResidualCandidate(root, request);
  if (!residual) return false;
  fs.unlinkSync(residual.candidate.temporary);
  fsyncDirectory(residual.candidate.directory);
  return true;
}

function assertReservationExactRequest(reservation, request) {
  assertControl(
    reservation
      && reservation.type === RESERVATION_TYPE
      && reservation.goal_id === request.goal_id
      && reservation.task_id === request.task_id
      && reservation.payload
      && reservation.payload.target_event_id === request.event_id
      && reservation.payload.request_sha256 === hashObject(request),
    'PREPARED_REQUEST_MISMATCH',
    `GitHub merge reservation ${request.event_id} 不是 exact request retry`,
  );
}

function authorizeExactMergeOddRecovery(
  root,
  request,
  actorCapabilityFile,
) {
  const { authorizeHistoricalActorCapability, loadGoalStateUnlocked } = require('./goal');
  const inventory = exactMergeRecoveryInventory(root, request);
  assertControl(
    inventory.foreign.length === 0,
    'MERGE_RECOVERY_SCOPE_CONFLICT',
    `exact merge retry 发现其它 event atomic temp: ${
      inventory.foreign.map((entry) => entry.event_id).join(', ')
    }`,
  );
  assertControl(
    inventory.candidates.length <= 1,
    'MERGE_RECOVERY_SCOPE_CONFLICT',
    `exact merge retry 同时发现 ${inventory.candidates.length} 个 atomic temp`,
  );
  const loaded = loadGoalStateUnlocked(root, request.goal_id, {
    repairHeads: false,
    repairBootstrapConsumption: false,
    allowIncompleteRecoveryRead: true,
    allowIncompleteGoalOperationRead: true,
  });
  const state = loaded.snapshot.tasks[request.task_id];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${request.task_id}`);
  let temporaryWitness = null;
  const candidate = inventory.candidates[0] || null;
  if (candidate) {
    try {
      temporaryWitness = readSealed(
        candidate.temporary,
        candidate.sealKey,
        `GitHub merge ${candidate.stage} odd-recovery temp`,
      );
    } catch (error) {
      if (
        !(error instanceof ControlError)
          || !['CORRUPT_STORE', 'INVALID_JSON'].includes(error.code)
      ) {
        throw error;
      }
      temporaryWitness = null;
    }
    if (temporaryWitness) {
      assertRecordIdentity(
        temporaryWitness,
        candidate.kind,
        request.goal_id,
        request.task_id,
        request.event_id,
        `GitHub merge ${candidate.stage} odd-recovery temp`,
      );
      const exactTemporaryRequest = candidate.stage === 'intent'
        ? (
          temporaryWitness.request_sha256 === hashObject(request)
            && hashObject(temporaryWitness.request) === hashObject(request)
        )
        : temporaryWitness.request_sha256 === hashObject(request);
      assertControl(
        exactTemporaryRequest,
        'PREPARED_REQUEST_MISMATCH',
        `GitHub merge ${candidate.stage} odd-recovery temp 不是 exact request`,
      );
    }
  }
  let intent = null;
  if (fs.existsSync(inventory.files.intent)) {
    intent = readSealed(
      inventory.files.intent,
      'intent_sha256',
      `GitHub merge recovery intent ${request.event_id}`,
    );
    assertRecordIdentity(
      intent,
      INTENT_KIND,
      request.goal_id,
      request.task_id,
      request.event_id,
      'GitHub merge recovery intent',
    );
    assertControl(
      intent.request_sha256 === hashObject(request)
        && hashObject(intent.request) === hashObject(request),
      'PREPARED_REQUEST_MISMATCH',
      `GitHub merge ${request.event_id} 不是 exact request retry`,
    );
  }
  if (inventory.reservation) {
    assertReservationExactRequest(inventory.reservation, request);
    const authority = inventory.reservation.goal_foreman_authority;
    assertControl(
      authority
        && authority.thread_id === inventory.reservation.actor.thread_id
        && authority.host_id === inventory.reservation.actor.host_id,
      'CORRUPT_STORE',
      `GitHub merge reservation ${inventory.reservation.event_id} 缺 FOREMAN authority`,
    );
    authorizeHistoricalActorCapability(
      loaded.snapshot,
      actorCapabilityFile,
      { role: 'FOREMAN', ...authority },
      { goalWide: true, taskId: request.task_id },
    );
    return true;
  }
  if (intent) {
    exactHistoricalAuthority(loaded, intent, actorCapabilityFile);
    return true;
  }
  if (candidate && candidate.stage === 'intent' && temporaryWitness) {
    exactHistoricalAuthority(
      loaded,
      temporaryWitness,
      actorCapabilityFile,
    );
    return true;
  }
  const accepted = acceptedMergeEvent(
    root,
    request.goal_id,
    request.task_id,
    request.event_id,
  );
  if (
    accepted
      && accepted.payload
      && accepted.payload.merge_request_sha256 === hashObject(request)
  ) {
    const authority = accepted.goal_foreman_authority;
    assertControl(
      authority,
      'CORRUPT_STORE',
      `accepted MERGED ${request.event_id} 缺 FOREMAN authority`,
    );
    authorizeHistoricalActorCapability(
      loaded.snapshot,
      actorCapabilityFile,
      { role: 'FOREMAN', ...authority },
      { goalWide: true, taskId: request.task_id },
    );
    return true;
  }
  return false;
}

function mergeLockOptions(
  root,
  request,
  actorCapabilityFile,
  options = {},
) {
  let exactOddRecoveryAuthorized = false;
  let pristineOddRecoveryAuthorized = false;
  const transactionKey = canonicalTransactionKey(
    'GITHUB_MERGE',
    {
      goal_id: request.goal_id,
      task_id: request.task_id,
    },
    request.event_id,
    hashObject(request),
  );
  return {
    beforeGeneration: () => {
      exactOddRecoveryAuthorized = authorizeExactMergeOddRecovery(
        root,
        request,
        actorCapabilityFile,
      );
      pristineOddRecoveryAuthorized = false;
      if (
        !exactOddRecoveryAuthorized
          && options.allowPristineStart === true
      ) {
        pristineOddRecoveryAuthorized =
          authorizePristineMergeOddRecovery(
            options.cwd,
            root,
            request,
            actorCapabilityFile,
            options.dependencies,
          );
      }
      if (options.requireExactWitness === true) {
        assertControl(
          exactOddRecoveryAuthorized,
          'MERGE_RECOVERY_WITNESS_REQUIRED',
          `GitHub merge ${request.event_id} 缺 exact durable recovery witness`,
        );
      }
    },
    transactionKey,
    authorizeOddRecovery: () => exactOddRecoveryAuthorized,
    ...(options.allowPristineStart === true
      ? {
        authorizePristineOddRecovery: () =>
          pristineOddRecoveryAuthorized,
      }
      : {}),
    ...(typeof options.afterGenerationBeforeCallback === 'function'
      ? {
        afterGenerationBeforeCallback:
          options.afterGenerationBeforeCallback,
      }
      : {}),
  };
}

function rootGenerationNeedsExactRecovery(root) {
  const file = path.join(root, '.generation.json');
  if (!fs.existsSync(file)) return false;
  const value = readJson(file, 'root generation recovery probe');
  return Number.isSafeInteger(value.generation) && value.generation % 2 === 1;
}

function exactMergeRecoveryCheckpoint(
  root,
  request,
  actorCapabilityFile,
) {
  const inventory = exactMergeRecoveryInventory(root, request);
  const {
    files,
    candidates,
    foreign,
    reservation,
  } = inventory;
  assertControl(
    foreign.length === 0,
    'MERGE_RECOVERY_SCOPE_CONFLICT',
    `exact merge retry 发现其它 event atomic temp: ${
      foreign.map((entry) => entry.event_id).join(', ')
    }`,
  );
  assertControl(
    candidates.length <= 1,
    'MERGE_RECOVERY_SCOPE_CONFLICT',
    `exact merge retry 同时发现 ${candidates.length} 个 atomic temp`,
  );
  const { loadGoalStateUnlocked } = require('./goal');
  const loaded = loadGoalStateUnlocked(root, request.goal_id, {
    repairHeads: false,
    repairBootstrapConsumption: false,
    allowIncompleteRecoveryRead: true,
    allowIncompleteGoalOperationRead: true,
  });
  const state = loaded.snapshot.tasks[request.task_id];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${request.task_id}`);
  let authorityIntent = null;
  if (fs.existsSync(files.intent)) {
    authorityIntent = readSealed(
      files.intent,
      'intent_sha256',
      `GitHub merge intent ${request.event_id}`,
    );
    assertRecordIdentity(
      authorityIntent,
      INTENT_KIND,
      request.goal_id,
      request.task_id,
      request.event_id,
      'GitHub merge recovery intent',
    );
    assertControl(
      authorityIntent.request_sha256 === hashObject(request)
        && hashObject(authorityIntent.request) === hashObject(request),
      'PREPARED_REQUEST_MISMATCH',
      `GitHub merge ${request.event_id} 不是 exact request retry`,
    );
  }
  if (authorityIntent) {
    exactHistoricalAuthority(
      loaded,
      authorityIntent,
      actorCapabilityFile,
    );
  } else if (reservation) {
    assertReservationExactRequest(reservation, request);
    const { authorizeHistoricalActorCapability } = require('./goal');
    authorizeHistoricalActorCapability(
      loaded.snapshot,
      actorCapabilityFile,
      { role: 'FOREMAN', ...reservation.goal_foreman_authority },
      { goalWide: true, taskId: request.task_id },
    );
  } else {
    authorizeGoalSession(
      loaded.snapshot,
      actorCapabilityFile,
      {
        role: 'FOREMAN',
        threadId: request.foreman_thread_id,
      },
    );
  }
  for (const candidate of candidates) {
    let temporaryValue = null;
    try {
      temporaryValue = readSealed(
        candidate.temporary,
        candidate.sealKey,
        `GitHub merge ${candidate.stage} recovery temp`,
      );
    } catch (error) {
      if (
        !(error instanceof ControlError)
          || !['CORRUPT_STORE', 'INVALID_JSON'].includes(error.code)
      ) {
        throw error;
      }
      // The only canonical writer uses an fsynced 0600 temp and rename. A
      // truncated/zero-byte temp means the writer died before publication.
      // Once exact authority is proven, discarding that unpublished stage is
      // safe; the durable prior stage (or reservation) drives reconstruction.
      fs.unlinkSync(candidate.temporary);
      fsyncDirectory(candidate.directory);
      continue;
    }
    assertRecordIdentity(
      temporaryValue,
      candidate.kind,
      request.goal_id,
      request.task_id,
      request.event_id,
      `GitHub merge ${candidate.stage} recovery temp`,
    );
    // A valid sealed record is durable evidence, even when it binds another
    // request. Never delete it on a mismatched retry.
    if (candidate.stage === 'intent') {
      assertControl(
        temporaryValue.request_sha256 === hashObject(request)
          && hashObject(temporaryValue.request) === hashObject(request),
        'PREPARED_REQUEST_MISMATCH',
        `GitHub merge ${candidate.stage} recovery temp 不是 exact request`,
      );
    } else {
      assertControl(
        temporaryValue.request_sha256 === hashObject(request),
        'PREPARED_REQUEST_MISMATCH',
        `GitHub merge ${candidate.stage} recovery temp request hash 与 exact retry 不匹配`,
      );
    }
    if (fs.existsSync(candidate.final)) {
      const finalValue = readSealed(
        candidate.final,
        candidate.sealKey,
        `GitHub merge ${candidate.stage}`,
      );
      assertControl(
        hashObject(finalValue) === hashObject(temporaryValue),
        'CORRUPT_STORE',
        `GitHub merge ${request.event_id} ${candidate.stage} final/temp 不一致`,
      );
      fs.unlinkSync(candidate.temporary);
      fsyncDirectory(candidate.directory);
      continue;
    }
    fs.renameSync(candidate.temporary, candidate.final);
    fsyncDirectory(candidate.directory);
  }
  if (candidates.length > 0) {
    readMergeTransaction(
      root,
      request.goal_id,
      request.task_id,
      request.event_id,
    );
  }
  return { recovered_atomic_temps: candidates.length };
}

function testDependency(dependencies, name) {
  if (dependencies[name] === undefined) return null;
  assertIsolatedTestMode();
  assertControl(
    typeof dependencies[name] === 'function'
      || typeof dependencies[name] === 'string',
    'INVALID_TEST_DEPENDENCY',
    `${name} test dependency 非法`,
  );
  return dependencies[name];
}

function trustedHomeDirectory() {
  const home = os.userInfo().homedir;
  assertControl(path.isAbsolute(home), 'TRUSTED_HOME_MISSING', 'OS home 不是绝对路径');
  return fs.realpathSync(home);
}

function resolveGh(dependencies) {
  const injected = testDependency(dependencies, 'resolveExecutable');
  if (injected) {
    const value = injected('gh');
    assertControl(
      value && path.isAbsolute(value.executable),
      'INVALID_TEST_DEPENDENCY',
      'test gh executable 必须是绝对路径',
    );
    return value.executable;
  }
  for (const candidate of trustedExecutableCandidates('gh')) {
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) return fs.realpathSync(candidate);
    } catch {
      // Try the next fixed path.
    }
  }
  throw new ControlError('GH_CANARY_FAILED', '固定可信路径中找不到 gh');
}

function capture(value) {
  const text = String(value || '');
  if (Buffer.byteLength(text) <= MAX_CAPTURE_BYTES) return text;
  return text.slice(0, MAX_CAPTURE_BYTES);
}

function sanitizedExternalEnvironment(executable) {
  const environment = {
    PATH: [
      path.dirname(executable),
      path.dirname(process.execPath),
      '/opt/homebrew/bin',
      '/usr/local/bin',
      '/usr/bin',
      '/bin',
      '/usr/sbin',
      '/sbin',
    ].join(path.delimiter),
    HOME: trustedHomeDirectory(),
    CI: '1',
    GH_PROMPT_DISABLED: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: '/usr/bin/false',
    SSH_ASKPASS: '/usr/bin/false',
    GCM_INTERACTIVE: 'Never',
    GIT_SSH_COMMAND: 'ssh -oBatchMode=yes -oConnectTimeout=15',
    NO_COLOR: '1',
    TZ: 'Asia/Shanghai',
  };
  const sshAgent = process.env.SSH_AUTH_SOCK;
  if (sshAgent && path.isAbsolute(sshAgent)) {
    try {
      if (fs.statSync(sshAgent).isSocket()) environment.SSH_AUTH_SOCK = sshAgent;
    } catch {
      // A missing or non-socket agent is deliberately not inherited.
    }
  }
  return environment;
}

function runExternal(executable, args, cwd, dependencies) {
  const runner = testDependency(dependencies, 'runner') || spawnSync;
  const result = runner(executable, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: MAX_CAPTURE_BYTES,
    env: sanitizedExternalEnvironment(executable),
    timeout: EXTERNAL_TIMEOUT_MS,
    killSignal: 'SIGKILL',
  });
  if (result.error || result.signal) {
    throw new ControlError(
      'GH_CANARY_FAILED',
      'gh 未能在非交互硬超时内完成（输出已隐藏）',
    );
  }
  return {
    exit_code: Number.isSafeInteger(result.status) ? result.status : 1,
    stdout: capture(result.stdout),
    stderr: capture(result.stderr),
  };
}

function resolveGit(dependencies) {
  const injected = testDependency(dependencies, 'resolveGitExecutable');
  if (injected) {
    const value = injected('git');
    assertControl(
      value && path.isAbsolute(value.executable),
      'INVALID_TEST_DEPENDENCY',
      'test git executable 必须是绝对路径',
    );
    return value.executable;
  }
  for (const candidate of trustedExecutableCandidates('git')) {
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) {
        return fs.realpathSync(candidate);
      }
    } catch {
      // Try the next fixed path.
    }
  }
  throw new ControlError('GIT_FAILED', '固定可信路径中找不到 git');
}

function runGitBounded(
  executable,
  args,
  cwd,
  dependencies,
  code,
  allowedExitCodes = [0],
  environmentOverrides = {},
) {
  const runner = testDependency(dependencies, 'gitRunner') || spawnSync;
  const result = runner(executable, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: MAX_CAPTURE_BYTES,
    env: {
      ...sanitizedExternalEnvironment(executable),
      ...environmentOverrides,
    },
    timeout: EXTERNAL_TIMEOUT_MS,
    killSignal: 'SIGKILL',
  });
  assertControl(
    !result.error
      && !result.signal
      && allowedExitCodes.includes(
        Number.isSafeInteger(result.status) ? result.status : 1,
      ),
    code,
    `git ${args[0]} 未能在非交互硬超时内成功（输出已隐藏）`,
  );
  return {
    exit_code: Number.isSafeInteger(result.status) ? result.status : 1,
    stdout: capture(result.stdout).trim(),
  };
}

function runGitNetwork(worktree, args, dependencies, code) {
  return runGitBounded(
    resolveGit(dependencies),
    args,
    worktree,
    dependencies,
    code,
  ).stdout;
}

function runTrustedGit(
  worktree,
  args,
  dependencies,
  code = 'GIT_FAILED',
  allowedExitCodes = [0],
  environmentOverrides = {},
) {
  return runGitBounded(
    resolveGit(dependencies),
    args,
    worktree,
    dependencies,
    code,
    allowedExitCodes,
    environmentOverrides,
  );
}

function trustedRepoRoot(cwd, dependencies) {
  const root = runTrustedGit(
    cwd,
    ['rev-parse', '--show-toplevel'],
    dependencies,
    'GIT_FAILED',
  ).stdout;
  assertControl(path.isAbsolute(root), 'GIT_FAILED', 'git repository root 不是绝对路径');
  return fs.realpathSync(root);
}

function runGh(executable, args, cwd, dependencies, code) {
  const result = runExternal(executable, args, cwd, dependencies);
  assertControl(
    result.exit_code === 0,
    code,
    `gh ${args.slice(0, 3).join(' ')} 失败 (exit=${result.exit_code})`,
  );
  return result;
}

function runGhJson(executable, args, cwd, dependencies, code) {
  const result = runGh(executable, args, cwd, dependencies, code);
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new ControlError(code, `gh JSON 非法: ${error.message}`);
  }
}

function canonicalOriginRepository(value) {
  const normalized = String(value || '')
    .trim()
    .replace(/^git@github\.com:/i, 'https://github.com/')
    .replace(/^ssh:\/\/git@github\.com\//i, 'https://github.com/')
    .replace(/\.git$/i, '')
    .replace(/\/$/, '');
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new ControlError('ORIGIN_MISMATCH', 'origin URL 不是 canonical GitHub repository');
  }
  assertControl(
    parsed.protocol === 'https:'
      && parsed.hostname.toLowerCase() === 'github.com'
      && !parsed.username
      && !parsed.password
      && !parsed.search
      && !parsed.hash,
    'ORIGIN_MISMATCH',
    'origin 必须是无凭证 canonical GitHub URL',
  );
  const match = parsed.pathname.match(/^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  assertControl(match, 'ORIGIN_MISMATCH', 'origin path 必须是 /owner/repo');
  return `${match[1]}/${match[2]}`;
}

function originRepository(worktree, dependencies) {
  const injected = testDependency(dependencies, 'originRepository');
  if (injected) return injected;
  return canonicalOriginRepository(
    runTrustedGit(
      worktree,
      ['remote', 'get-url', 'origin'],
      dependencies,
      'ORIGIN_MISMATCH',
    ).stdout,
  );
}

function requiredIssueLine(body, issue) {
  return new RegExp(`^Closes #${issue}[ \\t]*$`, 'im').test(String(body || ''));
}

function hasSemanticClosingIssue(pr, expected) {
  const references = Array.isArray(pr.closingIssuesReferences)
    ? pr.closingIssuesReferences
    : [];
  return references.some((reference) => (
    reference
      && reference.number === expected.issue
      && reference.repository
      && String(reference.repository.nameWithOwner || '').toLowerCase()
        === expected.repository.toLowerCase()
  ));
}

function pullRequestContractSha256(pr) {
  const closing = (Array.isArray(pr.closingIssuesReferences)
    ? pr.closingIssuesReferences
    : [])
    .map((reference) => ({
      number: reference && reference.number,
      repository: reference
        && reference.repository
        && reference.repository.nameWithOwner
        ? String(reference.repository.nameWithOwner).toLowerCase()
        : null,
    }))
    .sort((left, right) => (
      String(left.repository).localeCompare(String(right.repository))
        || Number(left.number) - Number(right.number)
    ));
  return hashObject({
    number: pr.number,
    url: pr.url,
    base_ref_name: pr.baseRefName,
    base_ref_oid: pr.baseRefOid,
    head_ref_name: pr.headRefName,
    head_ref_oid: pr.headRefOid,
    head_repository: pr.headRepository
      ? String(pr.headRepository.nameWithOwner || '').toLowerCase()
      : null,
    is_draft: pr.isDraft,
    is_cross_repository: pr.isCrossRepository,
    body_sha256: `sha256:${sha256(String(pr.body || ''))}`,
    closing_issues: closing,
  });
}

function normalizePr(pr, expected, expectedState) {
  assertControl(pr && typeof pr === 'object', 'PULL_REQUEST_QUERY_FAILED', 'PR response 非对象');
  assertControl(
    pr.number === expected.number
      && pr.url === expected.url
      && pr.baseRefName === expected.base
      && pr.baseRefOid === expected.expected_main_head
      && pr.headRefOid === expected.head
      && pr.isDraft === false
      && pr.isCrossRepository === false
      && pr.headRepository
      && String(pr.headRepository.nameWithOwner).toLowerCase()
        === expected.repository.toLowerCase()
      && requiredIssueLine(pr.body, expected.issue)
      && hasSemanticClosingIssue(pr, expected),
    'PULL_REQUEST_IDENTITY_MISMATCH',
    'PR repo/base/head/draft/fork/Closes + semantic closing issue binding 不匹配',
  );
  if (expected.contract_sha256) {
    assertControl(
      pullRequestContractSha256(pr) === expected.contract_sha256,
      'PULL_REQUEST_IDENTITY_MISMATCH',
      'PR body/closing semantic contract 已偏离 append-only reservation',
    );
  }
  assertControl(
    pr.state === expectedState,
    expectedState === 'OPEN'
      ? 'PULL_REQUEST_NOT_OPEN'
      : 'PULL_REQUEST_NOT_MERGED',
    `PR state=${pr.state}，期望 ${expectedState}`,
  );
  return pr;
}

function queryPullRequest(gh, worktree, expected, dependencies) {
  return runGhJson(
    gh,
    [
      'pr', 'view', String(expected.number),
      '--repo', expected.repository,
      '--json', PR_FIELDS,
    ],
    worktree,
    dependencies,
    'PULL_REQUEST_QUERY_FAILED',
  );
}

function githubExecutableIdentity(gh) {
  const resolved = fs.realpathSync(gh);
  const stat = fs.statSync(resolved);
  assertControl(
    stat.isFile() && (stat.mode & 0o111) !== 0,
    'GH_CANARY_FAILED',
    'gh executable identity 非普通可执行文件',
  );
  return {
    path: resolved,
    sha256: hashFile(resolved),
    size: stat.size,
    device: stat.dev,
    inode: stat.ino,
  };
}

function githubReadCanary(gh, worktree, expected, dependencies) {
  runGh(
    gh,
    ['auth', 'status', '--hostname', 'github.com'],
    worktree,
    dependencies,
    'GH_AUTH_UNAVAILABLE',
  );
  const repo = runGhJson(
    gh,
    [
      'repo', 'view', expected.repository,
      '--json',
      'nameWithOwner,defaultBranchRef,viewerPermission,squashMergeAllowed,isArchived',
    ],
    worktree,
    dependencies,
    'GH_REPOSITORY_ACCESS_DENIED',
  );
  assertControl(
    String(repo.nameWithOwner || '').toLowerCase()
        === expected.repository.toLowerCase()
      && repo.defaultBranchRef
      && repo.defaultBranchRef.name === expected.base
      && repo.isArchived === false,
    'GH_REPOSITORY_ACCESS_DENIED',
    'GitHub repo identity/default branch/read canary 失败',
  );
  return repo;
}

function githubWriteCanary(
  gh,
  worktree,
  expected,
  dependencies,
  repositoryObservation,
) {
  const repo = repositoryObservation
    || githubReadCanary(gh, worktree, expected, dependencies);
  assertControl(
    ['WRITE', 'MAINTAIN', 'ADMIN'].includes(repo.viewerPermission)
      && repo.squashMergeAllowed === true,
    'GH_REPOSITORY_ACCESS_DENIED',
    'GitHub write permission/squash policy canary 失败',
  );
  const checks = runGh(
    gh,
    [
      'pr', 'checks', String(expected.number),
      '--repo', expected.repository,
      '--required',
    ],
    worktree,
    dependencies,
    'REQUIRED_CHECKS_NOT_GREEN',
  );
  return {
    schema_version: 1,
    auth: { hostname: 'github.com', status: 'PASS' },
    repository: {
      name_with_owner: repo.nameWithOwner,
      default_branch: repo.defaultBranchRef.name,
      viewer_permission: repo.viewerPermission,
      squash_merge_allowed: repo.squashMergeAllowed,
      archived: repo.isArchived,
    },
    required_checks: {
      status: 'PASS',
      output_sha256: `sha256:${sha256(checks.stdout)}`,
    },
    gh_executable: githubExecutableIdentity(gh),
    observed_at: nowIso(),
  };
}

function fault(dependencies, name) {
  const callback = testDependency(dependencies, name);
  if (callback) callback();
}

function mergeRequest(options) {
  return {
    schema_version: 1,
    kind: 'GITHUB_MERGE_REQUEST',
    goal_id: safeId(options.goalId, 'goal_id'),
    task_id: safeId(options.taskId, 'task_id'),
    event_id: safeId(options.eventId, 'merge event_id'),
    foreman_thread_id: safeId(options.threadId, 'FOREMAN thread_id'),
    expected_state_revision: Number(options.expectedStateRevision),
    expected_control_epoch: Number(options.expectedControlEpoch),
  };
}

function assertRequest(request) {
  assertControl(
    Number.isSafeInteger(request.expected_state_revision)
      && request.expected_state_revision >= 0,
    'INVALID_ARGUMENT',
    '--expected-state-revision 必须是非负整数',
  );
  assertControl(
    Number.isSafeInteger(request.expected_control_epoch)
      && request.expected_control_epoch >= 0,
    'INVALID_ARGUMENT',
    '--expected-control-epoch 必须是非负整数',
  );
  return request;
}

function taskAnchor(loaded, state) {
  return {
    state_revision: state.state_revision,
    control_epoch: loaded.control.epoch,
    event_head_sha256: loaded.lastEventHashes[state.task_id] || null,
    task_cycle: state.task_cycle,
    phase: state.phase,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    base_head: state.base_head,
    full_head: state.full_head,
  };
}

function authorityAnchor(state, actor) {
  const actorKey = actorSequenceKey(actor);
  return {
    role: 'FOREMAN',
    thread_id: actor.thread_id,
    host_id: actor.host_id,
    attempt: actor.attempt,
    capability_file: actor.capability_file,
    capability_sha256: actor.capability_sha256,
    lease_until: actor.lease_until,
    prior_actor_sequence: state.actor_sequences[actorKey] || 0,
  };
}

function expectedPullRequest(loaded, task, state) {
  const parsed = parsePullRequestUrl(
    state.pr,
    loaded.manifest.repository.name_with_owner,
  );
  assertControl(
    Number.isSafeInteger(task.issue) && task.issue > 0,
    'ISSUE_BINDING_MISSING',
    'canonical merge policy 要求 manifest task.issue',
  );
  const { mergeExpectedMainHead } = require('./goal');
  return {
    repository: loaded.manifest.repository.name_with_owner,
    number: parsed.number,
    url: parsed.url,
    base: loaded.manifest.repository.base_branch,
    head: state.full_head,
    expected_main_head: mergeExpectedMainHead(loaded, task),
    issue: task.issue,
  };
}

function assertTaskReady(
  cwd,
  loaded,
  task,
  state,
  request,
  reservation = null,
  dependencies = {},
) {
  const { assertFrozenInputs } = require('./goal');
  assertControl(
    mergePolicyEnabled(loaded.manifest),
    'GITHUB_MERGE_POLICY_REQUIRED',
    `Goal 未启用 ${POLICY}`,
  );
  assertFrozenInputs(cwd, loaded, request.task_id);
  assertControl(
    state.phase === 'ACCEPTED_PENDING_MERGE',
    'MERGE_PHASE_MISMATCH',
    `merge-pr 要求 ACCEPTED_PENDING_MERGE，当前 ${state.phase}`,
  );
  assertControl(
    state.state_revision
      === request.expected_state_revision + (reservation ? 1 : 0),
    'STALE_STATE_REVISION',
    `expected state revision ${request.expected_state_revision}，当前 ${state.state_revision}`,
  );
  assertControl(
    loaded.control.epoch === request.expected_control_epoch
      && !state.reconcile_required,
    'STALE_CONTROL_EPOCH',
    `expected control epoch ${request.expected_control_epoch}，当前 ${loaded.control.epoch}`,
  );
  assertControl(state.holds.length === 0, 'TASK_HELD', 'merge-pr 禁止越过 hold');
  assertControl(
    state.evidence
      && state.evidence.dev
      && state.evidence.review
      && state.evidence.receipt,
    'EVIDENCE_REQUIRED',
    'merge-pr 缺 DEV/REVIEW/RECEIPT evidence',
  );
  assertControl(typeof state.pr === 'string', 'PULL_REQUEST_REQUIRED', 'merge-pr 缺 PR binding');
  assertFullSha(state.full_head, 'merge candidate head');
  runTrustedGit(
    trustedRepoRoot(cwd, dependencies),
    ['cat-file', '-e', `${state.full_head}^{commit}`],
    dependencies,
    'GIT_FAILED',
  );
  return expectedPullRequest(loaded, task, state);
}

function goalWideEventIdOccurrences(root, loaded, eventId) {
  const occurrences = [];
  for (const task of loaded.manifest.tasks) {
    for (const file of acceptedEventFiles(
      root,
      loaded.manifest.goal_id,
      task.id,
    )) {
      const event = readJson(file, `accepted event ${path.basename(file)}`);
      if (event.event_id === eventId) {
        occurrences.push({ domain: 'TASK', task_id: task.id, event });
      }
    }
  }
  for (const event of loaded.control.events || []) {
    if (event.event_id === eventId) {
      occurrences.push({ domain: 'CONTROL', task_id: null, event });
    }
  }
  return occurrences;
}

function assertGoalWideEventIdBoundary(
  root,
  loaded,
  request,
  transaction = null,
) {
  const occurrences = goalWideEventIdOccurrences(
    root,
    loaded,
    request.event_id,
  );
  if (occurrences.length === 0) return null;
  const matching = occurrences.length === 1
    && occurrences[0].domain === 'TASK'
    && occurrences[0].task_id === request.task_id
    && occurrences[0].event.type === 'MERGED'
    && transaction
    && transaction.receipt
    && occurrences[0].event.input_sha256
      === hashObject(buildMergeEvent(transaction))
    && occurrences[0].event.payload
    && occurrences[0].event.payload.merge_receipt_sha256
      === transaction.receipt.receipt_sha256;
  assertControl(
    matching,
    'EVENT_ID_CONFLICT',
    `merge event id ${request.event_id} 已被 Goal-wide ledger 使用`,
  );
  return occurrences[0].event;
}

function assertCandidateLineage(worktree, expected, dependencies) {
  const result = runGitBounded(
    resolveGit(dependencies),
    [
      'merge-base',
      '--is-ancestor',
      expected.expected_main_head,
      expected.head,
    ],
    worktree,
    dependencies,
    'CANDIDATE_LINEAGE_MISMATCH',
    [0, 1],
  );
  assertControl(
    result.exit_code === 0,
    'CANDIDATE_LINEAGE_MISMATCH',
    'merge candidate 不是 expected_main_head 的 descendant',
  );
}

function assertOriginIdentity(worktree, repository, dependencies) {
  assertControl(
    originRepository(worktree, dependencies).toLowerCase()
      === repository.toLowerCase(),
    'ORIGIN_MISMATCH',
    `origin repository 不是 ${repository}`,
  );
}

function exactHistoricalAuthority(loaded, intent, actorCapabilityFile) {
  const { authorizeHistoricalActorCapability } = require('./goal');
  return authorizeHistoricalActorCapability(
    loaded.snapshot,
    actorCapabilityFile,
    intent.acceptance_authority,
    { goalWide: true, taskId: intent.task_id },
  );
}

function assertIntentAnchor(loaded, state, intent, reservation = null) {
  const anchor = intent.task_anchor;
  const invariantMatches = (
    loaded.control.epoch === anchor.control_epoch
      && state.task_cycle === anchor.task_cycle
      && state.phase === anchor.phase
      && state.packet.revision === anchor.packet.revision
      && state.packet.sha256 === anchor.packet.sha256
      && state.base_head === anchor.base_head
      && state.full_head === anchor.full_head
      && state.pr === intent.pull_request.url
  );
  if (reservation) {
    const authority = intent.acceptance_authority;
    const actorKey = actorSequenceKey({
      role: 'FOREMAN',
      thread_id: authority.thread_id,
      host_id: authority.host_id,
    });
    assertControl(
      invariantMatches
        && reservation.event_id === intent.reservation.event_id
        && reservation.type === RESERVATION_TYPE
        && reservation.expected_state_revision === anchor.state_revision
        && reservation.previous_event_sha256 === anchor.event_head_sha256
        && reservation.actor_sequence
          === authority.prior_actor_sequence + 1
        && reservation.control_epoch === anchor.control_epoch
        && state.state_revision === anchor.state_revision + 1
        && (loaded.lastEventHashes[state.task_id] || null)
          === reservation.event_sha256
        && state.actor_sequences[actorKey]
          === authority.prior_actor_sequence + 1
        && state.merge_reservation
        && state.merge_reservation.status === 'ACTIVE'
        && state.merge_reservation.reservation_event_id
          === reservation.event_id
        && state.merge_reservation.target_event_id === intent.event_id
        && state.merge_reservation.request_sha256 === intent.request_sha256,
      'TASK_OPERATION_DIVERGED',
      `GitHub merge ${intent.event_id} post-reservation anchor 已漂移`,
    );
    return;
  }
  assertControl(
    invariantMatches
      && state.state_revision === anchor.state_revision
      && (loaded.lastEventHashes[state.task_id] || null)
        === anchor.event_head_sha256
      && !state.merge_reservation,
    'TASK_OPERATION_DIVERGED',
    `GitHub merge ${intent.event_id} task/control anchor 已漂移`,
  );
}

function publishRecord(file, directory, value, sealKey, label) {
  ensureDir(directory);
  ensurePrivateDirectory(directory);
  const expected = sealed(value, sealKey);
  if (fs.existsSync(file)) {
    const existing = readSealed(file, sealKey, label);
    assertControl(
      hashObject(existing) === hashObject(expected),
      'PREPARED_REQUEST_MISMATCH',
      `${label} 已绑定不同内容`,
    );
    return existing;
  }
  atomicWriteJson(file, expected);
  return readSealed(file, sealKey, label);
}

function prepareIntentUnderLock(
  cwd,
  root,
  request,
  actorCapabilityFile,
  observed,
  dependencies,
  preflightAttestation,
) {
  const {
    assertNoPendingTaskOperations,
  } = require('./pending-operations');
  const {
    loadGoalStateUnlocked,
  } = require('./goal');
  const loaded = loadGoalStateUnlocked(root, request.goal_id);
  const task = loaded.manifest.tasks.find((item) => item.id === request.task_id);
  const state = loaded.snapshot.tasks[request.task_id];
  assertControl(task && state, 'UNKNOWN_TASK', `未知 task ${request.task_id}`);
  const initialResidual = initialIntentResidualCandidate(root, request);
  assertNoPendingTaskOperations(
    root,
    request.goal_id,
    request.task_id,
    initialResidual
      ? {
        allowOperationKind: 'GITHUB_MERGE',
        allowOperationId: request.event_id,
        allowUnboundOperationMarkerFile:
          initialResidual.candidate.temporary,
      }
      : {},
  );
  assertGoalWideEventIdBoundary(root, loaded, request);
  const expected = assertTaskReady(
    cwd,
    loaded,
    task,
    state,
    request,
    null,
    dependencies,
  );
  const worktree = trustedRepoRoot(cwd, dependencies);
  assertOriginIdentity(worktree, expected.repository, dependencies);
  assertCandidateLineage(worktree, expected, dependencies);
  const actor = authorizeGoalSession(
    loaded.snapshot,
    actorCapabilityFile,
    { role: 'FOREMAN', threadId: request.foreman_thread_id },
  );
  assertControl(
    hashObject({
      number: observed.number,
      url: observed.url,
      state: observed.state,
      baseRefName: observed.baseRefName,
      baseRefOid: observed.baseRefOid,
      headRefOid: observed.headRefOid,
      headRepository: observed.headRepository,
      isDraft: observed.isDraft,
      isCrossRepository: observed.isCrossRepository,
      body_sha256: `sha256:${sha256(String(observed.body || ''))}`,
    }) === hashObject({
      number: expected.number,
      url: expected.url,
      state: 'OPEN',
      baseRefName: expected.base,
      baseRefOid: expected.expected_main_head,
      headRefOid: expected.head,
      headRepository: observed.headRepository,
      isDraft: false,
      isCrossRepository: false,
      body_sha256: `sha256:${sha256(String(observed.body || ''))}`,
    }),
    'PULL_REQUEST_IDENTITY_MISMATCH',
    'intent commit 前 PR observation 漂移',
  );
  normalizePr(observed, expected, 'OPEN');
  assertControl(
    preflightAttestation
      && preflightAttestation.schema_version === 1
      && preflightAttestation.required_checks
      && preflightAttestation.required_checks.status === 'PASS'
      && preflightAttestation.gh_executable
      && /^sha256:[0-9a-f]{64}$/.test(
        preflightAttestation.gh_executable.sha256,
      ),
    'GH_CANARY_FAILED',
    'intent 缺脱敏 GitHub write canary attestation',
  );
  const intent = {
    schema_version: 1,
    kind: INTENT_KIND,
    goal_id: request.goal_id,
    task_id: request.task_id,
    event_id: request.event_id,
    request,
    request_sha256: hashObject(request),
    task_anchor: taskAnchor(loaded, state),
    acceptance_authority: authorityAnchor(state, actor),
    repository: {
      name_with_owner: expected.repository,
      base_branch: expected.base,
      merge_policy: POLICY,
    },
    pull_request: {
      number: expected.number,
      url: expected.url,
      head: expected.head,
      expected_main_head: expected.expected_main_head,
      issue: expected.issue,
      head_ref_name: observed.headRefName,
      body_sha256: `sha256:${sha256(String(observed.body || ''))}`,
      contract_sha256: pullRequestContractSha256(observed),
    },
    reservation: {
      type: RESERVATION_TYPE,
      event_id: reservationEventId(request),
    },
    merge_method: 'SQUASH',
    preflight_attestation: preflightAttestation,
    serialization_policy: {
      provider: 'GITHUB',
      operation: 'PR_SQUASH_MERGE',
      head_compare_and_swap: '--match-head-commit',
      base_compare_and_swap: 'UNAVAILABLE_IN_GITHUB_MERGE_API',
      pre_dispatch_observation: 'LS_REMOTE_PLUS_PR_VIEW',
      residual_race:
        'base may advance after the final observation and before GitHub accepts the merge; post-merge exact-parent verification fails closed',
    },
    reserved_event_at: nowIso(),
    prepared_at: nowIso(),
  };
  return publishRecord(
    mergeTaskPaths(root, request.goal_id, request.task_id, request.event_id).intent,
    mergeTaskPaths(root, request.goal_id, request.task_id).intents,
    intent,
    'intent_sha256',
    `GitHub merge intent ${request.event_id}`,
  );
}

function rebuildIntentFromReservationUnderLock(
  root,
  request,
  actorCapabilityFile,
) {
  const { authorizeHistoricalActorCapability, loadGoalStateUnlocked } = require('./goal');
  const loaded = loadGoalStateUnlocked(root, request.goal_id, {
    allowIncompleteGoalOperationRead: true,
  });
  const task = loaded.manifest.tasks.find((item) => item.id === request.task_id);
  const state = loaded.snapshot.tasks[request.task_id];
  assertControl(task && state, 'UNKNOWN_TASK', `未知 task ${request.task_id}`);
  const transaction = readMergeTransaction(
    root,
    request.goal_id,
    request.task_id,
    request.event_id,
  );
  assertControl(
    !transaction.intent && transaction.reservation,
    'GITHUB_MERGE_RESERVATION_REQUIRED',
    `GitHub merge ${request.event_id} 没有可重建的 append-only reservation`,
  );
  const reservation = transaction.reservation;
  assertReservationExactRequest(reservation, request);
  const authority = reservation.goal_foreman_authority;
  assertControl(
    authority
      && authority.thread_id === reservation.actor.thread_id
      && authority.host_id === reservation.actor.host_id
      && authority.attempt > 0
      && authority.capability_file
      && authority.capability_sha256,
    'CORRUPT_STORE',
    `GitHub merge reservation ${reservation.event_id} 缺 FOREMAN authority`,
  );
  authorizeHistoricalActorCapability(
    loaded.snapshot,
    actorCapabilityFile,
    { role: 'FOREMAN', ...authority },
    { goalWide: true, taskId: request.task_id },
  );
  const payload = reservation.payload;
  assertControl(
    task.issue === payload.issue,
    'TASK_OPERATION_DIVERGED',
    `GitHub merge reservation ${reservation.event_id} issue binding 已漂移`,
  );
  const intent = {
    schema_version: 1,
    kind: INTENT_KIND,
    goal_id: request.goal_id,
    task_id: request.task_id,
    event_id: request.event_id,
    request,
    request_sha256: hashObject(request),
    task_anchor: {
      state_revision: reservation.expected_state_revision,
      control_epoch: reservation.control_epoch,
      event_head_sha256: reservation.previous_event_sha256,
      task_cycle: payload.task_cycle,
      phase: payload.phase,
      packet: { ...reservation.packet },
      base_head: reservation.base_head,
      full_head: reservation.full_head,
    },
    acceptance_authority: {
      role: 'FOREMAN',
      thread_id: authority.thread_id,
      host_id: authority.host_id,
      attempt: authority.attempt,
      capability_file: authority.capability_file,
      capability_sha256: authority.capability_sha256,
      lease_until: authority.lease_until,
      prior_actor_sequence: reservation.actor_sequence - 1,
    },
    repository: {
      name_with_owner: payload.repository,
      base_branch: payload.base_branch,
      merge_policy: POLICY,
    },
    pull_request: {
      number: payload.pull_request_number,
      url: payload.pull_request_url,
      head: payload.candidate_head,
      expected_main_head: payload.expected_main_head,
      issue: payload.issue,
      head_ref_name: payload.head_ref_name,
      body_sha256: payload.body_sha256,
      contract_sha256: payload.pr_contract_sha256,
    },
    reservation: {
      type: RESERVATION_TYPE,
      event_id: reservation.event_id,
    },
    merge_method: 'SQUASH',
    preflight_attestation: JSON.parse(JSON.stringify(
      payload.preflight_attestation,
    )),
    serialization_policy: {
      provider: 'GITHUB',
      operation: 'PR_SQUASH_MERGE',
      head_compare_and_swap: '--match-head-commit',
      base_compare_and_swap: 'UNAVAILABLE_IN_GITHUB_MERGE_API',
      pre_dispatch_observation: 'LS_REMOTE_PLUS_PR_VIEW',
      residual_race:
        'base may advance after the final observation and before GitHub accepts the merge; post-merge exact-parent verification fails closed',
    },
    recovered_from_append_only_reservation: true,
    reserved_event_at: reservation.accepted_at,
    prepared_at: reservation.accepted_at,
  };
  const installed = publishRecord(
    transaction.files.intent,
    transaction.files.intents,
    intent,
    'intent_sha256',
    `GitHub merge intent ${request.event_id}`,
  );
  const fresh = readMergeTransaction(
    root,
    request.goal_id,
    request.task_id,
    request.event_id,
  );
  assertControl(
    fresh.intent
      && fresh.intent.intent_sha256 === installed.intent_sha256
      && fresh.reservation
      && fresh.reservation.event_id === reservation.event_id,
    'CORRUPT_STORE',
    `GitHub merge ${request.event_id} reservation 重建无法 exact reread`,
  );
  assertIntentAnchor(loaded, state, fresh.intent, fresh.reservation);
  return fresh.intent;
}

function assertExactRequest(
  transaction,
  request,
  actorCapabilityFile,
  cwd,
  dependencies,
) {
  assertControl(
    transaction.intent
      && transaction.intent.request_sha256 === hashObject(request)
      && hashObject(transaction.intent.request) === hashObject(request),
    'PREPARED_REQUEST_MISMATCH',
    `GitHub merge ${request.event_id} 不是 exact request retry`,
  );
  const { loadGoalStateReadOnly } = require('./goal');
  const loaded = loadGoalStateReadOnly(cwd, request.goal_id, null, {
    allowIncompleteRecoveryRead: true,
  });
  const task = loaded.manifest.tasks.find((item) => item.id === request.task_id);
  const state = loaded.snapshot.tasks[request.task_id];
  assertControl(task && state, 'UNKNOWN_TASK', `未知 task ${request.task_id}`);
  assertGoalWideEventIdBoundary(
    controlRoot(cwd),
    loaded,
    request,
    transaction,
  );
  const expected = assertTaskReady(
    cwd,
    loaded,
    task,
    state,
    request,
    transaction.reservation,
    dependencies,
  );
  const intentExpected = expectedFromIntent(transaction.intent);
  delete intentExpected.contract_sha256;
  assertControl(
    hashObject(intentExpected) === hashObject(expected)
      && state.pr === transaction.intent.pull_request.url,
    'TASK_OPERATION_DIVERGED',
    `GitHub merge ${request.event_id} manifest/state/repository/PR anchor 已漂移`,
  );
  const worktree = trustedRepoRoot(cwd, dependencies);
  assertOriginIdentity(worktree, expected.repository, dependencies);
  assertControl(
    runTrustedGit(worktree, [
      'status',
      '--porcelain=v1',
      '--untracked-files=all',
    ], dependencies, 'GIT_FAILED').stdout === '',
    'DIRTY_WORKTREE',
    'merge-pr exact retry 要求 clean control worktree',
  );
  assertIntentAnchor(
    loaded,
    state,
    transaction.intent,
    transaction.reservation,
  );
  exactHistoricalAuthority(loaded, transaction.intent, actorCapabilityFile);
  return loaded;
}

function invocationArgv(intent) {
  return [
    'pr',
    'merge',
    String(intent.pull_request.number),
    '--repo',
    intent.repository.name_with_owner,
    '--squash',
    '--match-head-commit',
    intent.pull_request.head,
  ];
}

function publishInvocationUnderLock(
  cwd,
  root,
  transaction,
  actorCapabilityFile,
  dependencies,
  gh,
) {
  const { loadGoalStateUnlocked } = require('./goal');
  const loaded = loadGoalStateUnlocked(root, transaction.intent.goal_id);
  const state = loaded.snapshot.tasks[transaction.intent.task_id];
  assertGoalWideEventIdBoundary(
    root,
    loaded,
    transaction.intent.request,
    transaction,
  );
  assertIntentAnchor(
    loaded,
    state,
    transaction.intent,
    transaction.reservation,
  );
  exactHistoricalAuthority(loaded, transaction.intent, actorCapabilityFile);
  assertCandidateLineage(
    trustedRepoRoot(cwd, dependencies),
    expectedFromIntent(transaction.intent),
    dependencies,
  );
  assertControl(
    hashObject(githubExecutableIdentity(gh))
      === hashObject(transaction.intent.preflight_attestation.gh_executable),
    'GH_EXECUTABLE_CHANGED',
    'dispatch 使用的 gh executable identity 与 sealed intent 不一致',
  );
  const invocation = {
    schema_version: 1,
    kind: INVOCATION_KIND,
    goal_id: transaction.intent.goal_id,
    task_id: transaction.intent.task_id,
    event_id: transaction.intent.event_id,
    request_sha256: transaction.intent.request_sha256,
    intent_sha256: transaction.intent.intent_sha256,
    command: {
      executable: 'gh',
      argv: invocationArgv(transaction.intent),
      argv_sha256: hashObject(invocationArgv(transaction.intent)),
    },
    dispatch_mode: 'AUTHORIZED_BEFORE_DISPATCH',
    external_dispatch_claimed: true,
    dispatch_authorized_at: nowIso(),
  };
  return publishRecord(
    transaction.files.invocation,
    transaction.files.invocations,
    invocation,
    'invocation_sha256',
    `GitHub merge invocation ${transaction.intent.event_id}`,
  );
}

function publishObservedInvocationUnderLock(
  cwd,
  root,
  transaction,
  actorCapabilityFile,
  dependencies,
  gh,
) {
  const { loadGoalStateUnlocked } = require('./goal');
  const loaded = loadGoalStateUnlocked(root, transaction.intent.goal_id);
  const state = loaded.snapshot.tasks[transaction.intent.task_id];
  assertControl(
    transaction.reservation && !transaction.invocation,
    'GITHUB_MERGE_RESERVATION_REQUIRED',
    'observed recovery 要求 reservation 且不得覆盖 invocation',
  );
  assertGoalWideEventIdBoundary(
    root,
    loaded,
    transaction.intent.request,
    transaction,
  );
  assertIntentAnchor(
    loaded,
    state,
    transaction.intent,
    transaction.reservation,
  );
  exactHistoricalAuthority(loaded, transaction.intent, actorCapabilityFile);
  assertCandidateLineage(
    trustedRepoRoot(cwd, dependencies),
    expectedFromIntent(transaction.intent),
    dependencies,
  );
  assertControl(
    hashObject(githubExecutableIdentity(gh))
      === hashObject(transaction.intent.preflight_attestation.gh_executable),
    'GH_EXECUTABLE_CHANGED',
    'observed recovery 使用的 gh executable identity 与 reservation 不一致',
  );
  const invocation = {
    schema_version: 1,
    kind: INVOCATION_KIND,
    goal_id: transaction.intent.goal_id,
    task_id: transaction.intent.task_id,
    event_id: transaction.intent.event_id,
    request_sha256: transaction.intent.request_sha256,
    intent_sha256: transaction.intent.intent_sha256,
    command: {
      executable: 'gh',
      argv: invocationArgv(transaction.intent),
      argv_sha256: hashObject(invocationArgv(transaction.intent)),
    },
    dispatch_mode: 'OBSERVED_AFTER_RESERVATION',
    external_dispatch_claimed: false,
    reservation_event_id: transaction.reservation.event_id,
    observation_reason:
      'PR already MERGED while append-only reservation survived and sideband dispatch marker was absent',
    dispatch_authorized_at: transaction.reservation.accepted_at,
  };
  return publishRecord(
    transaction.files.invocation,
    transaction.files.invocations,
    invocation,
    'invocation_sha256',
    `GitHub merge invocation ${transaction.intent.event_id}`,
  );
}

function expectedFromIntent(intent) {
  return {
    repository: intent.repository.name_with_owner,
    number: intent.pull_request.number,
    url: intent.pull_request.url,
    base: intent.repository.base_branch,
    head: intent.pull_request.head,
    expected_main_head: intent.pull_request.expected_main_head,
    issue: intent.pull_request.issue,
    contract_sha256: intent.pull_request.contract_sha256,
  };
}

function mergeReservationPayload(intent) {
  return {
    target_event_id: intent.event_id,
    request_sha256: intent.request_sha256,
    repository: intent.repository.name_with_owner,
    pull_request_number: intent.pull_request.number,
    pull_request_url: intent.pull_request.url,
    base_branch: intent.repository.base_branch,
    expected_main_head: intent.pull_request.expected_main_head,
    candidate_head: intent.pull_request.head,
    task_cycle: intent.task_anchor.task_cycle,
    phase: intent.task_anchor.phase,
    issue: intent.pull_request.issue,
    head_ref_name: intent.pull_request.head_ref_name,
    body_sha256: intent.pull_request.body_sha256,
    preflight_attestation: JSON.parse(JSON.stringify(
      intent.preflight_attestation,
    )),
    pr_contract_sha256: intent.pull_request.contract_sha256,
  };
}

function buildReservationEvent(intent) {
  const anchor = intent.task_anchor;
  const authority = intent.acceptance_authority;
  return validateEvent({
    schema_version: 1,
    event_id: intent.reservation.event_id,
    goal_id: intent.goal_id,
    task_id: intent.task_id,
    type: RESERVATION_TYPE,
    actor: {
      role: 'FOREMAN',
      thread_id: authority.thread_id,
      host_id: authority.host_id,
    },
    actor_sequence: authority.prior_actor_sequence + 1,
    expected_state_revision: anchor.state_revision,
    control_epoch: anchor.control_epoch,
    packet: { ...anchor.packet },
    base_head: anchor.base_head,
    full_head: anchor.full_head,
    payload: mergeReservationPayload(intent),
  });
}

function verifyMergeReservationForEvent(
  root,
  loaded,
  state,
  event,
  authorization = null,
) {
  assertControl(
    mergePolicyEnabled(loaded.manifest),
    'GITHUB_MERGE_POLICY_REQUIRED',
    'Goal 未启用 canonical GitHub merge policy',
  );
  assertControl(
    authorization
      && authorization.kind === 'GITHUB_MERGE_RESERVATION_OPERATION'
      && authorization.reservationEventId === event.event_id
      && authorization.targetEventId === event.payload.target_event_id,
    'GITHUB_MERGE_WRAPPER_REQUIRED',
    'GITHUB_MERGE_RESERVED 只能由 canonical merge-pr 提交',
  );
  const transaction = readMergeTransaction(
    root,
    loaded.manifest.goal_id,
    state.task_id,
    event.payload.target_event_id,
  );
  assertControl(
    transaction.intent
      && !transaction.reservation
      && transaction.intent.reservation.event_id === event.event_id
      && transaction.intent.request_sha256
        === authorization.requestSha256,
    'GITHUB_MERGE_WRAPPER_REQUIRED',
    'GitHub merge reservation 缺 exact sealed intent',
  );
  assertGoalWideEventIdBoundary(
    root,
    loaded,
    transaction.intent.request,
    transaction,
  );
  assertIntentAnchor(loaded, state, transaction.intent, null);
  assertControl(
    hashObject(buildReservationEvent(transaction.intent))
      === hashObject(event),
    'GITHUB_MERGE_RESERVATION_MISMATCH',
    'GitHub merge reservation 与 sealed intent 不一致',
  );
  return transaction;
}

function remoteBaseHead(worktree, expected, dependencies) {
  const output = runGitNetwork(
    worktree,
    [
      'ls-remote',
      '--exit-code',
      'origin',
      `refs/heads/${expected.base}`,
    ],
    dependencies,
    'REMOTE_REF_MISMATCH',
  );
  const rows = output.split('\n').filter(Boolean);
  assertControl(
    rows.length === 1,
    'REMOTE_REF_MISMATCH',
    'ls-remote 未返回唯一 base ref',
  );
  const [sha, ref] = rows[0].split(/\s+/);
  assertControl(
    ref === `refs/heads/${expected.base}`
      && /^[0-9a-f]{40}$/.test(sha),
    'REMOTE_REF_MISMATCH',
    'ls-remote base ref 非 canonical',
  );
  return { sha, ref };
}

function assertExternalWriteBoundary(
  cwd,
  root,
  request,
  transaction,
  actorCapabilityFile,
  dependencies,
) {
  const loaded = assertExactRequest(
    transaction,
    request,
    actorCapabilityFile,
    cwd,
    dependencies,
  );
  assertGoalWideEventIdBoundary(root, loaded, request, transaction);
  assertCandidateLineage(
    trustedRepoRoot(cwd, dependencies),
    expectedFromIntent(transaction.intent),
    dependencies,
  );
}

function finalPreDispatchObservation(
  cwd,
  root,
  request,
  transaction,
  actorCapabilityFile,
  gh,
  dependencies,
) {
  assertExternalWriteBoundary(
    cwd,
    root,
    request,
    transaction,
    actorCapabilityFile,
    dependencies,
  );
  const worktree = trustedRepoRoot(cwd, dependencies);
  const expected = expectedFromIntent(transaction.intent);
  const remote = remoteBaseHead(worktree, expected, dependencies);
  assertControl(
    remote.sha === expected.expected_main_head,
    'BASE_HEAD_CHANGED',
    'origin base 已偏离 sealed expected_main_head，禁止 dispatch',
  );
  const observed = queryPullRequest(gh, worktree, expected, dependencies);
  normalizePr(observed, expected, 'OPEN');
  return observed;
}

function mergeFetchOwnerPaths(root, commonGitDir, intent, mergeSha) {
  const identity = {
    schema_version: 1,
    kind: 'GITHUB_MERGE_OBJECT_FETCH',
    goal_id: intent.goal_id,
    task_id: intent.task_id,
    event_id: intent.event_id,
    request_sha256: intent.request_sha256,
    intent_sha256: intent.intent_sha256,
    merge_sha: mergeSha,
    common_git_dir: commonGitDir,
  };
  const digest = hashObject(identity).slice('sha256:'.length);
  const parent = path.join(root, 'github-merge-object-fetch');
  return {
    identity,
    parent,
    ownerFile: path.join(parent, `${digest}.owner.json`),
    objectDirectory: path.join(parent, `${digest}.objects`),
    markerFile: path.join(
      parent,
      `${digest}.objects`,
      MERGE_FETCH_MARKER,
    ),
    quarantineDirectory: path.join(parent, `${digest}.cleanup`),
  };
}

function mergeFetchPathExists(file) {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

function processAppearsLive(owner) {
  const pid = owner && owner.pid;
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    if (owner.host_id !== PROCESS_HOST_ID) return true;
    const observedStart = processStartToken(pid);
    if (observedStart === null) return true;
    return observedStart === owner.process_start_token;
  } catch (error) {
    if (error && error.code === 'ESRCH') return false;
    if (error && error.code === 'EPERM') return true;
    throw error;
  }
}

function validateMergeFetchOwner(file, expected) {
  assertPrivateFile(file, 'GitHub merge object fetch owner');
  const owner = readJson(file, 'GitHub merge object fetch owner');
  const keys = [
    ...Object.keys(expected.identity),
    'object_directory',
    'marker_file',
    'pid',
    'host_id',
    'process_start_token',
    'created_at',
    'owner_sha256',
  ];
  assertControl(
    owner
      && typeof owner === 'object'
      && !Array.isArray(owner)
      && Object.keys(owner).length === keys.length
      && keys.every((key) => Object.prototype.hasOwnProperty.call(owner, key)),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch owner fields 非协议集合',
  );
  const unsigned = { ...owner };
  delete unsigned.owner_sha256;
  assertControl(
    Object.entries(expected.identity).every(([key, value]) => (
      owner[key] === value
    ))
      && owner.object_directory === expected.objectDirectory
      && owner.marker_file === expected.markerFile
      && Number.isSafeInteger(owner.pid)
      && owner.pid > 0
      && typeof owner.host_id === 'string'
      && owner.host_id.length > 0
      && typeof owner.process_start_token === 'string'
      && owner.process_start_token.length > 0
      && typeof owner.created_at === 'string'
      && Number.isFinite(Date.parse(owner.created_at))
      && owner.owner_sha256 === hashObject(unsigned),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch owner identity/seal 漂移',
  );
  return {
    owner,
    stat: fs.lstatSync(file),
    body: fs.readFileSync(file),
  };
}

function assertSafeMergeFetchTree(directory) {
  if (!mergeFetchPathExists(directory)) return false;
  const visit = (candidate) => {
    const stat = fs.lstatSync(candidate);
    assertControl(
      !stat.isSymbolicLink()
        && (stat.isDirectory() || stat.isFile())
        && (
          typeof process.getuid !== 'function'
            || stat.uid === process.getuid()
        ),
      'MERGE_GIT_EVIDENCE_OWNER_INVALID',
      `GitHub merge object fetch tree 含 foreign entry: ${candidate}`,
    );
    if (!stat.isDirectory()) return;
    for (const name of fs.readdirSync(candidate)) {
      assertControl(
        name !== '.' && name !== '..' && !name.includes(path.sep),
        'MERGE_GIT_EVIDENCE_OWNER_INVALID',
        'GitHub merge object fetch tree entry name 非法',
      );
      visit(path.join(candidate, name));
    }
  };
  visit(directory);
  return true;
}

function assertMergeFetchDirectoryBinding(paths, inspected) {
  assertControl(
    mergeFetchPathExists(paths.objectDirectory)
      && mergeFetchPathExists(paths.markerFile)
      && mergeFetchPathExists(paths.ownerFile),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch directory binding 文件缺失',
  );
  const directory = fs.lstatSync(paths.objectDirectory);
  assertControl(
    directory.isDirectory()
      && !directory.isSymbolicLink()
      && (
        typeof process.getuid !== 'function'
          || directory.uid === process.getuid()
      ),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch directory 不是当前 owner 的普通目录',
  );
  const marker = fs.lstatSync(paths.markerFile);
  const owner = fs.lstatSync(paths.ownerFile);
  assertControl(
    marker.isFile()
      && !marker.isSymbolicLink()
      && marker.dev === owner.dev
      && marker.ino === owner.ino
      && owner.dev === inspected.stat.dev
      && owner.ino === inspected.stat.ino
      && marker.nlink === 2
      && owner.nlink === 2
      && fs.readFileSync(paths.markerFile).equals(inspected.body)
      && fs.readFileSync(paths.ownerFile).equals(inspected.body),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch directory 未由 exact owner hard-link 绑定',
  );
  return {
    directory,
    marker,
  };
}

function removeExactMergeFetchOwner(paths, inspected) {
  const before = fs.lstatSync(paths.ownerFile);
  assertControl(
    before.dev === inspected.stat.dev
      && before.ino === inspected.stat.ino
      && fs.readFileSync(paths.ownerFile).equals(inspected.body),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch owner cleanup 前 inode/bytes 漂移',
  );
  fs.unlinkSync(paths.ownerFile);
  fsyncDirectory(paths.parent);
}

function cleanupMergeFetchArtifacts(paths, inspected, dependencies = {}) {
  if (!mergeFetchPathExists(paths.objectDirectory)) {
    if (mergeFetchPathExists(paths.quarantineDirectory)) {
      const quarantined = {
        ...paths,
        objectDirectory: paths.quarantineDirectory,
        markerFile: path.join(
          paths.quarantineDirectory,
          MERGE_FETCH_MARKER,
        ),
      };
      assertMergeFetchDirectoryBinding(quarantined, inspected);
      assertSafeMergeFetchTree(quarantined.objectDirectory);
      fs.rmSync(quarantined.objectDirectory, {
        recursive: true,
        force: false,
      });
      fsyncDirectory(paths.parent);
      const refreshed = validateMergeFetchOwner(paths.ownerFile, paths);
      assertControl(
        refreshed.stat.dev === inspected.stat.dev
          && refreshed.stat.ino === inspected.stat.ino
          && refreshed.stat.nlink === 1,
        'MERGE_GIT_EVIDENCE_OWNER_INVALID',
        'GitHub merge object fetch quarantine cleanup 后 owner lineage 漂移',
      );
      removeExactMergeFetchOwner(paths, refreshed);
      return;
    }
    assertControl(
      inspected.stat.nlink === 1,
      'MERGE_GIT_EVIDENCE_OWNER_INVALID',
      'GitHub merge object fetch directory 缺失但 owner 仍有 foreign hard-link',
    );
    removeExactMergeFetchOwner(paths, inspected);
    return;
  }
  assertControl(
    !mergeFetchPathExists(paths.quarantineDirectory),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch cleanup quarantine 已被占用',
  );
  const bound = assertMergeFetchDirectoryBinding(paths, inspected);
  assertSafeMergeFetchTree(paths.objectDirectory);
  fs.renameSync(paths.objectDirectory, paths.quarantineDirectory);
  fsyncDirectory(paths.parent);
  fault(dependencies, 'afterMergeFetchCleanupRename');
  const quarantined = {
    ...paths,
    objectDirectory: paths.quarantineDirectory,
    markerFile: path.join(
      paths.quarantineDirectory,
      MERGE_FETCH_MARKER,
    ),
  };
  const moved = fs.lstatSync(quarantined.objectDirectory);
  assertControl(
    moved.dev === bound.directory.dev
      && moved.ino === bound.directory.ino,
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch cleanup rename 后 directory identity 漂移',
  );
  assertMergeFetchDirectoryBinding(quarantined, inspected);
  assertSafeMergeFetchTree(quarantined.objectDirectory);
  fs.rmSync(quarantined.objectDirectory, { recursive: true, force: false });
  fsyncDirectory(paths.parent);
  const refreshedOwner = validateMergeFetchOwner(paths.ownerFile, paths);
  assertControl(
    refreshedOwner.stat.dev === inspected.stat.dev
      && refreshedOwner.stat.ino === inspected.stat.ino
      && refreshedOwner.stat.nlink === 1,
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch cleanup 后 owner lineage 漂移',
  );
  removeExactMergeFetchOwner(paths, refreshedOwner);
}

function publishMergeFetchOwner(paths) {
  assertControl(
    !mergeFetchPathExists(paths.ownerFile)
      && !mergeFetchPathExists(paths.objectDirectory)
      && !mergeFetchPathExists(paths.quarantineDirectory),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch stable path 已被 foreign 占用',
  );
  const unsigned = {
    ...paths.identity,
    object_directory: paths.objectDirectory,
    marker_file: paths.markerFile,
    pid: process.pid,
    host_id: PROCESS_HOST_ID,
    process_start_token: PROCESS_START_TOKEN,
    created_at: nowIso(),
  };
  assertControl(
    typeof PROCESS_START_TOKEN === 'string'
      && PROCESS_START_TOKEN.length > 0,
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    '无法 seal 当前 process start identity',
  );
  const owner = {
    ...unsigned,
    owner_sha256: hashObject(unsigned),
  };
  assertControl(
    atomicCreate(
      paths.ownerFile,
      `${JSON.stringify(owner, null, 2)}\n`,
    ),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch owner no-clobber publication 失败',
  );
  const inspected = validateMergeFetchOwner(paths.ownerFile, paths);
  assertControl(
    inspected.owner.pid === process.pid,
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    '新建 GitHub merge object fetch owner pid 漂移',
  );
  fs.mkdirSync(paths.objectDirectory, { mode: 0o700 });
  fsyncDirectory(paths.parent);
  ensurePrivateDirectory(paths.objectDirectory);
  try {
    fs.linkSync(paths.ownerFile, paths.markerFile);
  } catch (error) {
    throw new ControlError(
      'MERGE_GIT_EVIDENCE_OWNER_INVALID',
      `GitHub merge object fetch owner marker no-clobber publication 失败: ${error.message}`,
    );
  }
  fsyncDirectory(paths.objectDirectory);
  const bound = validateMergeFetchOwner(paths.ownerFile, paths);
  assertMergeFetchDirectoryBinding(paths, bound);
  return bound;
}

function acquireMergeObjectFetchDirectory(
  root,
  worktree,
  intent,
  mergeSha,
  dependencies,
) {
  const commonGitDir = fs.realpathSync(runTrustedGit(
    worktree,
    ['rev-parse', '--path-format=absolute', '--git-common-dir'],
    dependencies,
    'GIT_FAILED',
  ).stdout);
  const sharedObjects = fs.realpathSync(runTrustedGit(
    worktree,
    ['rev-parse', '--path-format=absolute', '--git-path', 'objects'],
    dependencies,
    'GIT_FAILED',
  ).stdout);
  const paths = mergeFetchOwnerPaths(
    root,
    commonGitDir,
    intent,
    mergeSha,
  );
  if (!mergeFetchPathExists(paths.parent)) {
    fs.mkdirSync(paths.parent, { mode: 0o700 });
    fsyncDirectory(path.dirname(paths.parent));
  }
  ensurePrivateDirectory(paths.parent);
  const ownerExists = mergeFetchPathExists(paths.ownerFile);
  const objectsExist = mergeFetchPathExists(paths.objectDirectory);
  const quarantineExists = mergeFetchPathExists(paths.quarantineDirectory);
  assertControl(
    ownerExists || (!objectsExist && !quarantineExists),
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch 缺 owner seal 但 residual directory 已存在',
  );
  if (ownerExists) {
    const retained = validateMergeFetchOwner(paths.ownerFile, paths);
    if (
      retained.owner.pid !== process.pid
        && processAppearsLive(retained.owner)
    ) {
      throw new ControlError(
        'MERGE_GIT_EVIDENCE_BUSY',
        `GitHub merge object fetch 仍由 live pid ${retained.owner.pid} 持有`,
      );
    }
    cleanupMergeFetchArtifacts(paths, retained, dependencies);
  }
  const owner = publishMergeFetchOwner(paths);
  return {
    ...paths,
    owner,
    sharedObjects,
    dependencies,
  };
}

function releaseMergeObjectFetchDirectory(fetch) {
  const retained = validateMergeFetchOwner(fetch.ownerFile, fetch);
  assertControl(
    retained.owner.pid === process.pid
      && retained.stat.dev === fetch.owner.stat.dev
      && retained.stat.ino === fetch.owner.stat.ino,
    'MERGE_GIT_EVIDENCE_OWNER_INVALID',
    'GitHub merge object fetch release 时 owner identity 漂移',
  );
  cleanupMergeFetchArtifacts(fetch, retained, fetch.dependencies);
}

function withReadableMergeCommit(
  root,
  worktree,
  intent,
  mergeSha,
  dependencies,
  callback,
) {
  const local = runTrustedGit(
    worktree,
    ['cat-file', '-e', `${mergeSha}^{commit}`],
    dependencies,
    'GIT_FAILED',
    [0, 1, 128],
  );
  if (local.exit_code === 0) return callback({});
  const fetch = acquireMergeObjectFetchDirectory(
    root,
    worktree,
    intent,
    mergeSha,
    dependencies,
  );
  fault(dependencies, 'afterMergeFetchOwner');
  try {
    const environment = {
      GIT_OBJECT_DIRECTORY: fetch.objectDirectory,
      GIT_ALTERNATE_OBJECT_DIRECTORIES: fetch.sharedObjects,
    };
    runGitBounded(
      resolveGit(dependencies),
      [
        '-c', 'gc.auto=0',
        'fetch',
        '--no-tags',
        '--no-write-fetch-head',
        '--refmap=',
        'origin',
        `refs/heads/${intent.repository.base_branch}`,
      ],
      worktree,
      dependencies,
      'GIT_FETCH_FAILED',
      [0],
      environment,
    );
    runTrustedGit(
      worktree,
      ['cat-file', '-e', `${mergeSha}^{commit}`],
      dependencies,
      'GIT_FAILED',
      [0],
      environment,
    );
    return callback(environment);
  } finally {
    releaseMergeObjectFetchDirectory(fetch);
  }
}

function postMergeGitEvidence(
  cwd,
  root,
  request,
  transaction,
  actorCapabilityFile,
  worktree,
  intent,
  pr,
  dependencies,
) {
  assertExternalWriteBoundary(
    cwd,
    root,
    request,
    transaction,
    actorCapabilityFile,
    dependencies,
  );
  return readOnlyMergeGitEvidence(
    root,
    worktree,
    intent,
    pr,
    dependencies,
  );
}

function mergeGitEvidenceFromEnvironment(
  worktree,
  intent,
  mergeSha,
  remote,
  remoteTrackingSha,
  dependencies,
  environment,
) {
  const base = intent.repository.base_branch;
  const parents = runTrustedGit(
    worktree,
    ['rev-list', '--parents', '-n', '1', mergeSha],
    dependencies,
    'GIT_FAILED',
    [0],
    environment,
  ).stdout.split(/\s+/);
  assertControl(
    parents.length === 2
      && parents[0] === mergeSha
      && parents[1] === intent.pull_request.expected_main_head,
    'MERGE_PARENT_MISMATCH',
    'squash merge commit 必须精确以 expected_main_head 为唯一 parent',
  );
  const mergeTree = runTrustedGit(
    worktree,
    ['rev-parse', `${mergeSha}^{tree}`],
    dependencies,
    'GIT_FAILED',
    [0],
    environment,
  ).stdout;
  const candidateTree = runTrustedGit(
    worktree,
    ['rev-parse', `${intent.pull_request.head}^{tree}`],
    dependencies,
    'GIT_FAILED',
    [0],
    environment,
  ).stdout;
  assertControl(
    mergeTree === candidateTree,
    'MERGE_CONTENT_MISMATCH',
    'squash merge tree 与 accepted candidate tree 不一致',
  );
  const taskPatch = runTrustedGit(
    worktree,
    [
      'diff',
      '--binary',
      '--full-index',
      intent.pull_request.expected_main_head,
      intent.pull_request.head,
    ],
    dependencies,
    'GIT_FAILED',
    [0],
    environment,
  ).stdout;
  const mergedPatch = runTrustedGit(
    worktree,
    [
      'diff',
      '--binary',
      '--full-index',
      intent.pull_request.expected_main_head,
      mergeSha,
    ],
    dependencies,
    'GIT_FAILED',
    [0],
    environment,
  ).stdout;
  assertControl(
    hashObject(taskPatch) === hashObject(mergedPatch),
    'MERGE_CONTENT_MISMATCH',
    'squash merge patch 与 accepted candidate patch 不一致',
  );
  return {
    main_merge_sha: mergeSha,
    candidate_head: intent.pull_request.head,
    remote_ref: remote.ref,
    remote_ref_sha: remote.sha,
    remote_tracking_ref: remoteTrackingSha
      ? `refs/remotes/origin/${base}`
      : null,
    remote_tracking_sha: remoteTrackingSha,
    parent_sha: parents[1],
    merge_tree: mergeTree,
    candidate_tree: candidateTree,
    task_patch_sha256: hashObject(taskPatch),
    merged_patch_sha256: hashObject(mergedPatch),
  };
}

function promoteVerifiedMergeObjects(
  worktree,
  intent,
  mergeSha,
  evidence,
  dependencies,
) {
  fault(dependencies, 'beforeMergeObjectPromotion');
  const local = runTrustedGit(
    worktree,
    ['cat-file', '-e', `${mergeSha}^{commit}`],
    dependencies,
    'GIT_FAILED',
    [0, 1, 128],
  );
  if (local.exit_code !== 0) {
    const before = remoteBaseHead(
      worktree,
      expectedFromIntent(intent),
      dependencies,
    );
    assertControl(
      before.sha === mergeSha,
      'REMOTE_REF_MISMATCH',
      'shared ODB promotion 前 remote base 已漂移',
    );
    runGitBounded(
      resolveGit(dependencies),
      [
        '-c', 'gc.auto=0',
        'fetch',
        '--no-tags',
        '--no-write-fetch-head',
        '--refmap=',
        'origin',
        mergeSha,
      ],
      worktree,
      dependencies,
      'GIT_FETCH_FAILED',
      [0],
    );
    fault(dependencies, 'afterMergeObjectPromotionFetch');
  }
  const after = remoteBaseHead(
    worktree,
    expectedFromIntent(intent),
    dependencies,
  );
  assertControl(
    after.sha === mergeSha,
    'REMOTE_REF_MISMATCH',
    'shared ODB promotion 后 remote base 已漂移',
  );
  const promoted = mergeGitEvidenceFromEnvironment(
    worktree,
    intent,
    mergeSha,
    after,
    evidence.remote_tracking_sha,
    dependencies,
    {},
  );
  assertControl(
    hashObject(promoted) === hashObject(evidence),
    'MERGE_GIT_EVIDENCE_MISMATCH',
    'shared ODB promotion 后 exact Git evidence 漂移',
  );
  fault(dependencies, 'afterMergeObjectPromotion');
}

function readOnlyMergeGitEvidence(
  root,
  worktree,
  intent,
  pr,
  dependencies,
) {
  const mergeSha = pr.mergeCommit && pr.mergeCommit.oid;
  assertFullSha(mergeSha, 'GitHub mergeCommit.oid');
  const base = intent.repository.base_branch;
  const remote = remoteBaseHead(
    worktree,
    expectedFromIntent(intent),
    dependencies,
  );
  const remoteSha = remote.sha;
  const remoteRef = remote.ref;
  const remoteTrackingObservation = runTrustedGit(
    worktree,
    ['rev-parse', '--verify', `refs/remotes/origin/${base}`],
    dependencies,
    'GIT_FAILED',
    [0, 1, 128],
  );
  const remoteTrackingSha =
    remoteTrackingObservation.exit_code === 0
      && remoteTrackingObservation.stdout === mergeSha
      ? mergeSha
      : null;
  assertControl(
    remoteRef === `refs/heads/${base}`
      && remoteSha === mergeSha,
    'REMOTE_REF_MISMATCH',
    'mergeCommit 与 remote base ref 不一致',
  );
  return withReadableMergeCommit(
    root,
    worktree,
    intent,
    mergeSha,
    dependencies,
    (environment) => {
      const evidence = mergeGitEvidenceFromEnvironment(
        worktree,
        intent,
        mergeSha,
        remote,
        remoteTrackingSha,
        dependencies,
        environment,
      );
      if (environment.GIT_OBJECT_DIRECTORY) {
        promoteVerifiedMergeObjects(
          worktree,
          intent,
          mergeSha,
          evidence,
          dependencies,
        );
      }
      return evidence;
    },
  );
}

function revalidateReceiptEvidence(
  cwd,
  root,
  request,
  transaction,
  actorCapabilityFile,
  dependencies,
) {
  assertExactRequest(
    transaction,
    request,
    actorCapabilityFile,
    cwd,
    dependencies,
  );
  const worktree = trustedRepoRoot(cwd, dependencies);
  const expected = expectedFromIntent(transaction.intent);
  const gh = resolveGh(dependencies);
  assertControl(
    hashObject(githubExecutableIdentity(gh))
      === hashObject(transaction.intent.preflight_attestation.gh_executable),
    'GH_EXECUTABLE_CHANGED',
    'receipt acceptance 使用的 gh executable identity 与 reservation 不一致',
  );
  githubReadCanary(gh, worktree, expected, dependencies);
  const observed = queryPullRequest(gh, worktree, expected, dependencies);
  normalizePr(observed, expected, 'MERGED');
  const observedProviderMetadata = {
    number: observed.number,
    url: observed.url,
    base_ref_name: observed.baseRefName,
    base_ref_oid: observed.baseRefOid,
    head_ref_name: observed.headRefName,
    head_ref_oid: observed.headRefOid,
    head_repository: observed.headRepository
      && observed.headRepository.nameWithOwner,
    merged_at: observed.mergedAt,
    merged_by: observed.mergedBy && observed.mergedBy.login
      ? observed.mergedBy.login
      : null,
    body_sha256: `sha256:${sha256(String(observed.body || ''))}`,
  };
  assertControl(
    hashObject(observedProviderMetadata)
      === hashObject(transaction.receipt.pull_request),
    'MERGE_RECEIPT_MISMATCH',
    'receipt provider metadata 与当前只读 observation 不一致',
  );
  const evidence = readOnlyMergeGitEvidence(
    root,
    worktree,
    transaction.intent,
    observed,
    dependencies,
  );
  assertControl(
    hashObject(evidence) === hashObject(transaction.receipt.result),
    'MERGE_RECEIPT_MISMATCH',
    'receipt acceptance 的只读 provider/git evidence 与 sealed result 不一致',
  );
  return { observed, evidence };
}

function eventAnchor(transaction) {
  const intent = transaction.intent;
  const reservation = transaction.reservation;
  assertControl(
    reservation
      && reservation.event_id === intent.reservation.event_id,
    'GITHUB_MERGE_RESERVATION_REQUIRED',
    'MERGED event 前缺 append-only reservation',
  );
  return {
    schema_version: 1,
    event_id: intent.event_id,
    goal_id: intent.goal_id,
    task_id: intent.task_id,
    type: 'MERGED',
    actor: {
      role: 'FOREMAN',
      thread_id: reservation.actor.thread_id,
      host_id: reservation.actor.host_id,
    },
    actor_sequence: reservation.actor_sequence + 1,
    expected_state_revision: reservation.expected_state_revision + 1,
    control_epoch: reservation.control_epoch,
    packet: { ...reservation.packet },
    base_head: reservation.base_head,
    full_head: reservation.full_head,
  };
}

function buildMergeEvent(transaction) {
  assertControl(
    transaction.intent && transaction.receipt,
    'GITHUB_MERGE_RECEIPT_REQUIRED',
    'MERGED event 前缺 sealed merge intent/receipt',
  );
  const expectedAnchor = eventAnchor(transaction);
  assertControl(
    hashObject(transaction.receipt.event_anchor) === hashObject(expectedAnchor),
    'CORRUPT_STORE',
    `GitHub merge ${transaction.intent.event_id} event anchor 漂移`,
  );
  return validateEvent({
    ...expectedAnchor,
    payload: {
      expected_main_head:
        transaction.intent.pull_request.expected_main_head,
      main_merge_sha: transaction.receipt.result.main_merge_sha,
      merge_receipt_sha256: transaction.receipt.receipt_sha256,
      merge_reservation_event_id:
        transaction.reservation.event_id,
      merge_request_sha256: transaction.intent.request_sha256,
    },
  });
}

function publishReceiptUnderLock(
  cwd,
  root,
  transaction,
  actorCapabilityFile,
  pr,
  gitEvidence,
) {
  const { loadGoalStateUnlocked } = require('./goal');
  const loaded = loadGoalStateUnlocked(root, transaction.intent.goal_id);
  const state = loaded.snapshot.tasks[transaction.intent.task_id];
  assertIntentAnchor(
    loaded,
    state,
    transaction.intent,
    transaction.reservation,
  );
  exactHistoricalAuthority(loaded, transaction.intent, actorCapabilityFile);
  assertControl(
    transaction.invocation,
    'GITHUB_MERGE_INVOCATION_REQUIRED',
    'merge receipt 前缺 invocation marker',
  );
  const expected = expectedFromIntent(transaction.intent);
  normalizePr(pr, expected, 'MERGED');
  assertControl(
    pr.mergeCommit
      && pr.mergeCommit.oid === gitEvidence.main_merge_sha,
    'MERGE_COMMIT_MISMATCH',
    'GitHub mergeCommit 与 Git evidence 不一致',
  );
  const receipt = {
    schema_version: 1,
    kind: RECEIPT_KIND,
    goal_id: transaction.intent.goal_id,
    task_id: transaction.intent.task_id,
    event_id: transaction.intent.event_id,
    request_sha256: transaction.intent.request_sha256,
    intent_sha256: transaction.intent.intent_sha256,
    invocation_sha256: transaction.invocation.invocation_sha256,
    repository: { ...transaction.intent.repository },
    pull_request: {
      number: expected.number,
      url: expected.url,
      base_ref_name: pr.baseRefName,
      base_ref_oid: pr.baseRefOid,
      head_ref_name: pr.headRefName,
      head_ref_oid: pr.headRefOid,
      head_repository: pr.headRepository.nameWithOwner,
      merged_at: pr.mergedAt,
      merged_by: pr.mergedBy && pr.mergedBy.login
        ? pr.mergedBy.login
        : null,
      body_sha256: `sha256:${sha256(String(pr.body || ''))}`,
    },
    merge_method: 'SQUASH',
    result: gitEvidence,
    event_anchor: eventAnchor(transaction),
    reserved_event_at: transaction.reservation.accepted_at,
    observed_at: nowIso(),
  };
  return publishRecord(
    transaction.files.receipt,
    transaction.files.receipts,
    receipt,
    'receipt_sha256',
    `GitHub merge receipt ${transaction.intent.event_id}`,
  );
}

function verifyMergeReceiptForEvent(
  root,
  loaded,
  state,
  event,
  authorization = null,
) {
  assertControl(
    mergePolicyEnabled(loaded.manifest),
    'GITHUB_MERGE_POLICY_REQUIRED',
    'Goal 未启用 canonical GitHub merge policy',
  );
  assertControl(
    authorization
      && authorization.kind === 'GITHUB_MERGE_OPERATION'
      && authorization.eventId === event.event_id,
    'GITHUB_MERGE_WRAPPER_REQUIRED',
    '该 Goal 的 MERGED 只能由 goalctl merge-pr 提交',
  );
  const transaction = readMergeTransaction(
    root,
    loaded.manifest.goal_id,
    state.task_id,
    event.event_id,
  );
  assertControl(
    transaction.intent
      && transaction.invocation
      && transaction.receipt
      && transaction.reservation
      && !transaction.completion
      && authorization.requestSha256
        === transaction.intent.request_sha256
      && authorization.receiptSha256
        === transaction.receipt.receipt_sha256,
    'GITHUB_MERGE_WRAPPER_REQUIRED',
    'MERGED 缺 exact sealed GitHub merge transaction',
  );
  assertIntentAnchor(
    loaded,
    state,
    transaction.intent,
    transaction.reservation,
  );
  const expectedEvent = buildMergeEvent(transaction);
  assertControl(
    hashObject(expectedEvent) === hashObject(event),
    'MERGE_RECEIPT_MISMATCH',
    'MERGED event 与 sealed receipt 不一致',
  );
  return transaction;
}

function verifyAcceptedMergeReceipt(root, loaded, state, event) {
  if (!mergePolicyEnabled(loaded.manifest)) return null;
  const transaction = readMergeTransaction(
    root,
    loaded.manifest.goal_id,
    state.task_id,
    event.event_id,
  );
  assertControl(
    transaction.intent
      && transaction.invocation
      && transaction.receipt
      && transaction.reservation,
    'MERGE_RECEIPT_INVALID',
    `accepted MERGED ${event.event_id} 缺 sealed transaction`,
  );
  assertIntentAnchor(
    loaded,
    state,
    transaction.intent,
    transaction.reservation,
  );
  assertControl(
    hashObject(buildMergeEvent(transaction)) === hashObject({
      schema_version: event.schema_version,
      event_id: event.event_id,
      goal_id: event.goal_id,
      task_id: event.task_id,
      type: event.type,
      actor: event.actor,
      actor_sequence: event.actor_sequence,
      expected_state_revision: event.expected_state_revision,
      control_epoch: event.control_epoch,
      packet: event.packet,
      base_head: event.base_head,
      full_head: event.full_head,
      payload: event.payload,
    }),
    'MERGE_RECEIPT_INVALID',
    `accepted MERGED ${event.event_id} 与 receipt 不一致`,
  );
  return transaction;
}

function completeTransaction(
  root,
  transaction,
  accepted,
) {
  assertControl(
    accepted
      && accepted.type === 'MERGED'
      && accepted.event_id === transaction.intent.event_id
      && accepted.payload.merge_receipt_sha256
        === transaction.receipt.receipt_sha256
      && transaction.reservation
      && accepted.payload.merge_reservation_event_id
        === transaction.reservation.event_id,
    'MERGE_RECEIPT_INVALID',
    'GitHub merge completion 缺 matching accepted event',
  );
  const completion = {
    schema_version: 1,
    kind: COMPLETION_KIND,
    goal_id: transaction.intent.goal_id,
    task_id: transaction.intent.task_id,
    event_id: transaction.intent.event_id,
    request_sha256: transaction.intent.request_sha256,
    intent_sha256: transaction.intent.intent_sha256,
    receipt_sha256: transaction.receipt.receipt_sha256,
    reservation_event_id: transaction.reservation.event_id,
    reservation_event_sha256: transaction.reservation.event_sha256,
    event_sha256: accepted.event_sha256,
    main_merge_sha: transaction.receipt.result.main_merge_sha,
    completed_at: accepted.accepted_at,
  };
  return publishRecord(
    transaction.files.completion,
    transaction.files.completions,
    completion,
    'completion_sha256',
    `GitHub merge completion ${transaction.intent.event_id}`,
  );
}

function publicResult(transaction, accepted, idempotent) {
  return {
    accepted: true,
    idempotent,
    event_id: transaction.intent.event_id,
    event_sha256: accepted.event_sha256,
    main_merge_sha: transaction.receipt.result.main_merge_sha,
    merge_receipt_sha256: transaction.receipt.receipt_sha256,
    completion_sha256: transaction.completion
      ? transaction.completion.completion_sha256
      : null,
  };
}

function finishAcceptedTransaction(
  cwd,
  root,
  transaction,
  actorCapabilityFile,
) {
  const accepted = acceptedMergeEvent(
    root,
    transaction.intent.goal_id,
    transaction.intent.task_id,
    transaction.intent.event_id,
  );
  if (!accepted) return null;
  assertControl(
    transaction.receipt
      && accepted.payload.merge_receipt_sha256
        === transaction.receipt.receipt_sha256
      && transaction.reservation
      && accepted.payload.merge_reservation_event_id
        === transaction.reservation.event_id,
    'MERGE_RECEIPT_INVALID',
    'accepted MERGED 与 transaction receipt 不匹配',
  );
  withLock(root, () => {
    const {
      loadGoalStateUnlocked,
    } = require('./goal');
    const loaded = loadGoalStateUnlocked(
      root,
      transaction.intent.goal_id,
      { allowPendingOperation: true },
    );
    exactHistoricalAuthority(
      loaded,
      transaction.intent,
      actorCapabilityFile,
    );
    const fresh = readMergeTransaction(
      root,
      transaction.intent.goal_id,
      transaction.intent.task_id,
      transaction.intent.event_id,
    );
    if (!fresh.completion) {
      completeTransaction(root, fresh, accepted);
    }
  }, mergeLockOptions(
    root,
    transaction.intent.request,
    actorCapabilityFile,
  ));
  const final = readMergeTransaction(
    root,
    transaction.intent.goal_id,
    transaction.intent.task_id,
    transaction.intent.event_id,
  );
  return publicResult(final, accepted, true);
}

function acceptReservationUnderLock(
  cwd,
  transaction,
  actorCapabilityFile,
) {
  const { acceptEventUnderLock } = require('./goal');
  const event = buildReservationEvent(transaction.intent);
  return acceptEventUnderLock(
    cwd,
    event,
    actorCapabilityFile,
    {
      githubMergeReservationOperation: {
        kind: 'GITHUB_MERGE_RESERVATION_OPERATION',
        reservationEventId: transaction.intent.reservation.event_id,
        targetEventId: transaction.intent.event_id,
        requestSha256: transaction.intent.request_sha256,
      },
    },
  );
}

function acceptReceiptTransaction(
  cwd,
  root,
  transaction,
  actorCapabilityFile,
  dependencies,
) {
  revalidateReceiptEvidence(
    cwd,
    root,
    transaction.intent.request,
    transaction,
    actorCapabilityFile,
    dependencies,
  );
  const event = buildMergeEvent(transaction);
  const result = withLock(root, () => {
    const {
      acceptEventUnderLock,
    } = require('./goal');
    const acceptedResult = acceptEventUnderLock(
      cwd,
      event,
      actorCapabilityFile,
      {
        githubMergeOperation: {
          kind: 'GITHUB_MERGE_OPERATION',
          eventId: transaction.intent.event_id,
          requestSha256: transaction.intent.request_sha256,
          receiptSha256: transaction.receipt.receipt_sha256,
        },
      },
    );
    fault(dependencies, 'afterEvent');
    const accepted = acceptedMergeEvent(
      root,
      transaction.intent.goal_id,
      transaction.intent.task_id,
      transaction.intent.event_id,
    );
    const fresh = readMergeTransaction(
      root,
      transaction.intent.goal_id,
      transaction.intent.task_id,
      transaction.intent.event_id,
    );
    completeTransaction(root, fresh, accepted);
    return acceptedResult;
  }, mergeLockOptions(
    root,
    transaction.intent.request,
    actorCapabilityFile,
  ));
  const final = readMergeTransaction(
    root,
    transaction.intent.goal_id,
    transaction.intent.task_id,
    transaction.intent.event_id,
  );
  const accepted = acceptedMergeEvent(
    root,
    transaction.intent.goal_id,
    transaction.intent.task_id,
    transaction.intent.event_id,
  );
  return {
    ...publicResult(final, accepted, result.idempotent === true),
    task: result.task,
  };
}

function initialBoundaryFromLoaded(
  cwd,
  root,
  request,
  actorCapabilityFile,
  dependencies,
  loaded,
) {
  const {
    assertNoPendingTaskOperations,
  } = require('./pending-operations');
  const task = loaded.manifest.tasks.find((item) => item.id === request.task_id);
  const state = loaded.snapshot.tasks[request.task_id];
  assertControl(task && state, 'UNKNOWN_TASK', `未知 task ${request.task_id}`);
  const initialResidual = initialIntentResidualCandidate(root, request);
  assertNoPendingTaskOperations(
    root,
    request.goal_id,
    request.task_id,
    initialResidual
      ? {
        allowOperationKind: 'GITHUB_MERGE',
        allowOperationId: request.event_id,
        allowUnboundOperationMarkerFile:
          initialResidual.candidate.temporary,
      }
      : {},
  );
  assertGoalWideEventIdBoundary(root, loaded, request);
  const expected = assertTaskReady(
    cwd,
    loaded,
    task,
    state,
    request,
    null,
    dependencies,
  );
  authorizeGoalSession(
    loaded.snapshot,
    actorCapabilityFile,
    { role: 'FOREMAN', threadId: request.foreman_thread_id },
  );
  const worktree = trustedRepoRoot(cwd, dependencies);
  assertOriginIdentity(worktree, expected.repository, dependencies);
  assertCandidateLineage(worktree, expected, dependencies);
  assertControl(
    runTrustedGit(
      worktree,
      ['status', '--porcelain=v1', '--untracked-files=all'],
      dependencies,
      'GIT_FAILED',
    ).stdout === '',
    'DIRTY_WORKTREE',
    'merge-pr 要求 clean control worktree',
  );
  return { loaded, task, state, expected, worktree };
}

function initialBoundary(
  cwd,
  root,
  request,
  actorCapabilityFile,
  dependencies,
) {
  const {
    loadGoalStateReadOnly,
  } = require('./goal');
  return initialBoundaryFromLoaded(
    cwd,
    root,
    request,
    actorCapabilityFile,
    dependencies,
    loadGoalStateReadOnly(cwd, request.goal_id),
  );
}

function initialBoundaryUnderLock(
  cwd,
  root,
  request,
  actorCapabilityFile,
  dependencies,
) {
  const {
    loadGoalStateUnlocked,
  } = require('./goal');
  return initialBoundaryFromLoaded(
    cwd,
    root,
    request,
    actorCapabilityFile,
    dependencies,
    loadGoalStateUnlocked(root, request.goal_id, {
      repairHeads: false,
      repairBootstrapConsumption: false,
      allowIncompleteRecoveryRead: true,
      allowIncompleteGoalOperationRead: true,
    }),
  );
}

function authorizePristineMergeOddRecovery(
  cwd,
  root,
  request,
  actorCapabilityFile,
  dependencies,
) {
  const inventory = exactMergeRecoveryInventory(root, request);
  const residual = initialIntentResidualCandidate(
    root,
    request,
    inventory,
  );
  assertControl(
    inventory.foreign.length === 0
      && !inventory.reservation
      && inventory.finalStages.length === 0,
    'MERGE_RECOVERY_WITNESS_REQUIRED',
    `GitHub merge ${request.event_id} pristine recovery 发现 durable witness`,
  );
  assertControl(
    inventory.candidates.length === 0
      || (
        residual
          && inventory.candidates.length === 1
          && inventory.candidates[0].stage === 'intent'
      ),
    'MERGE_RECOVERY_WITNESS_REQUIRED',
    `GitHub merge ${request.event_id} pristine recovery 发现非 initial-intent residual`,
  );
  const boundary = initialBoundaryUnderLock(
    cwd,
    root,
    request,
    actorCapabilityFile,
    dependencies,
  );
  assertControl(
    !boundary.state.merge_reservation,
    'TASK_OPERATION_DIVERGED',
    `task ${request.task_id} 已有 merge reservation`,
  );
  return true;
}

function collectFreshMergePreflight(boundary, dependencies) {
  const gh = resolveGh(dependencies);
  const repositoryObservation = githubReadCanary(
    gh,
    boundary.worktree,
    boundary.expected,
    dependencies,
  );
  let observed = queryPullRequest(
    gh,
    boundary.worktree,
    boundary.expected,
    dependencies,
  );
  normalizePr(observed, boundary.expected, 'OPEN');
  const preflightAttestation = githubWriteCanary(
    gh,
    boundary.worktree,
    boundary.expected,
    dependencies,
    repositoryObservation,
  );
  observed = queryPullRequest(
    gh,
    boundary.worktree,
    boundary.expected,
    dependencies,
  );
  normalizePr(observed, boundary.expected, 'OPEN');
  return {
    observed,
    preflightAttestation,
  };
}

function mergePullRequest(cwd, options, dependencies = {}) {
  const request = assertRequest(mergeRequest(options));
  const root = controlRoot(cwd);
  const recoveryInventory = exactMergeRecoveryInventory(root, request);
  const initialIntentResidual = initialIntentResidualCandidate(
    root,
    request,
    recoveryInventory,
  );
  const recoveryGenerationOdd = rootGenerationNeedsExactRecovery(root);
  if (
    !initialIntentResidual
      && (
        recoveryInventory.candidates.length > 0
      || recoveryInventory.foreign.length > 0
      || (
        recoveryGenerationOdd
          && recoveryInventory.hasExactEvidence
      )
      )
  ) {
    withLock(root, () => exactMergeRecoveryCheckpoint(
      root,
      request,
      options.actorCapabilityFile,
    ), mergeLockOptions(
      root,
      request,
      options.actorCapabilityFile,
      { requireExactWitness: true },
    ));
  }
  let transaction = readMergeTransaction(
    root,
    request.goal_id,
    request.task_id,
    request.event_id,
  );
  if (!transaction.intent && transaction.reservation) {
    withLock(root, () => rebuildIntentFromReservationUnderLock(
      root,
      request,
      options.actorCapabilityFile,
    ), mergeLockOptions(
      root,
      request,
      options.actorCapabilityFile,
    ));
    transaction = readMergeTransaction(
      root,
      request.goal_id,
      request.task_id,
      request.event_id,
    );
  }
  if (!transaction.intent) {
    const pristineOddStart = rootGenerationNeedsExactRecovery(root);
    const freshBoundary = initialBoundary(
      cwd,
      root,
      request,
      options.actorCapabilityFile,
      dependencies,
    );
    let preflight = null;
    if (!pristineOddStart) {
      preflight = collectFreshMergePreflight(
        freshBoundary,
        dependencies,
      );
    }
    const generationBoundaryFault = testDependency(
      dependencies,
      'afterGenerationBeforeCallback',
    );
    withLock(root, () => {
      discardInitialIntentResidualUnderLock(root, request);
      if (preflight === null) {
        preflight = collectFreshMergePreflight(
          initialBoundaryUnderLock(
            cwd,
            root,
            request,
            options.actorCapabilityFile,
            dependencies,
          ),
          dependencies,
        );
      }
      const preparedIntent = prepareIntentUnderLock(
        cwd,
        root,
        request,
        options.actorCapabilityFile,
        preflight.observed,
        dependencies,
        preflight.preflightAttestation,
      );
      const prepared = readMergeTransaction(
        root,
        request.goal_id,
        request.task_id,
        request.event_id,
      );
      assertControl(
        prepared.intent
          && prepared.intent.intent_sha256
            === preparedIntent.intent_sha256,
        'CORRUPT_STORE',
        'GitHub merge intent publish 后无法 exact reread',
      );
      acceptReservationUnderLock(
        cwd,
        prepared,
        options.actorCapabilityFile,
      );
    }, mergeLockOptions(
      root,
      request,
      options.actorCapabilityFile,
      {
        allowPristineStart: true,
        cwd,
        dependencies,
        afterGenerationBeforeCallback: generationBoundaryFault,
      },
    ));
    fault(dependencies, 'afterIntent');
    transaction = readMergeTransaction(
      root,
      request.goal_id,
      request.task_id,
      request.event_id,
    );
  }

  assertControl(
    transaction.intent.request_sha256 === hashObject(request)
      && hashObject(transaction.intent.request) === hashObject(request),
    'PREPARED_REQUEST_MISMATCH',
    `GitHub merge ${request.event_id} 不是 exact request retry`,
  );
  if (!transaction.reservation) {
    withLock(root, () => {
      const fresh = readMergeTransaction(
        root,
        request.goal_id,
        request.task_id,
        request.event_id,
      );
      acceptReservationUnderLock(
        cwd,
        fresh,
        options.actorCapabilityFile,
      );
    }, mergeLockOptions(
      root,
      request,
      options.actorCapabilityFile,
    ));
    transaction = readMergeTransaction(
      root,
      request.goal_id,
      request.task_id,
      request.event_id,
    );
  }
  assertControl(
    transaction.reservation,
    'GITHUB_MERGE_RESERVATION_REQUIRED',
    '外部 GitHub 操作前缺 append-only reservation',
  );
  const alreadyAccepted = finishAcceptedTransaction(
    cwd,
    root,
    transaction,
    options.actorCapabilityFile,
  );
  if (alreadyAccepted) return alreadyAccepted;
  assertExactRequest(
    transaction,
    request,
    options.actorCapabilityFile,
    cwd,
    dependencies,
  );
  if (transaction.receipt) {
    return acceptReceiptTransaction(
      cwd,
      root,
      transaction,
      options.actorCapabilityFile,
      dependencies,
    );
  }
  assertControl(
    !transaction.completion,
    'CORRUPT_STORE',
    `GitHub merge ${request.event_id} completion 没有 accepted event`,
  );

  const worktree = trustedRepoRoot(cwd, dependencies);
  const expected = expectedFromIntent(transaction.intent);
  assertOriginIdentity(worktree, expected.repository, dependencies);
  const gh = resolveGh(dependencies);
  const repositoryObservation = githubReadCanary(
    gh,
    worktree,
    expected,
    dependencies,
  );
  let observed = queryPullRequest(gh, worktree, expected, dependencies);

  if (observed.state === 'MERGED') {
    normalizePr(observed, expected, 'MERGED');
    if (!transaction.invocation) {
      withLock(root, () => {
        const fresh = readMergeTransaction(
          root,
          request.goal_id,
          request.task_id,
          request.event_id,
        );
        publishObservedInvocationUnderLock(
          cwd,
          root,
          fresh,
          options.actorCapabilityFile,
          dependencies,
          gh,
        );
      }, mergeLockOptions(
        root,
        request,
        options.actorCapabilityFile,
      ));
      transaction = readMergeTransaction(
        root,
        request.goal_id,
        request.task_id,
        request.event_id,
      );
    }
  } else {
    normalizePr(observed, expected, 'OPEN');
    githubWriteCanary(
      gh,
      worktree,
      expected,
      dependencies,
      repositoryObservation,
    );
  }

  if (!transaction.invocation) {
    observed = finalPreDispatchObservation(
      cwd,
      root,
      request,
      transaction,
      options.actorCapabilityFile,
      gh,
      dependencies,
    );
    withLock(root, () => {
      const fresh = readMergeTransaction(
        root,
        request.goal_id,
        request.task_id,
        request.event_id,
      );
      publishInvocationUnderLock(
        cwd,
        root,
        fresh,
        options.actorCapabilityFile,
        dependencies,
        gh,
      );
    }, mergeLockOptions(
      root,
      request,
      options.actorCapabilityFile,
    ));
    fault(dependencies, 'afterInvocation');
    transaction = readMergeTransaction(
      root,
      request.goal_id,
      request.task_id,
      request.event_id,
    );
  }

  if (observed.state !== 'MERGED') {
    observed = finalPreDispatchObservation(
      cwd,
      root,
      request,
      transaction,
      options.actorCapabilityFile,
      gh,
      dependencies,
    );
    assertControl(
      hashObject(githubExecutableIdentity(gh))
        === hashObject(transaction.intent.preflight_attestation.gh_executable),
      'GH_EXECUTABLE_CHANGED',
      '不可逆 dispatch 前 gh executable identity 与 sealed preflight 不一致',
    );
    const execution = runExternal(
      gh,
      invocationArgv(transaction.intent),
      worktree,
      dependencies,
    );
    fault(dependencies, 'afterMerge');
    observed = queryPullRequest(gh, worktree, expected, dependencies);
    if (observed.state !== 'MERGED') {
      normalizePr(observed, expected, 'OPEN');
      throw new ControlError(
        execution.exit_code === 0
          ? 'GITHUB_MERGE_PENDING'
          : 'GITHUB_MERGE_FAILED',
        execution.exit_code === 0
          ? 'GitHub 已接受 exact merge request 但 PR 尚未 MERGED；按同一 event ID/request/capability 重试'
          : `gh merge exit=${execution.exit_code} 且 PR 仍 OPEN；按同一 event ID/request/capability 重试`,
      );
    }
  }

  normalizePr(observed, expected, 'MERGED');
  const gitEvidence = postMergeGitEvidence(
    cwd,
    root,
    request,
    transaction,
    options.actorCapabilityFile,
    worktree,
    transaction.intent,
    observed,
    dependencies,
  );
  withLock(root, () => {
    const fresh = readMergeTransaction(
      root,
      request.goal_id,
      request.task_id,
      request.event_id,
    );
    publishReceiptUnderLock(
      cwd,
      root,
      fresh,
      options.actorCapabilityFile,
      observed,
      gitEvidence,
    );
  }, mergeLockOptions(
    root,
    request,
    options.actorCapabilityFile,
  ));
  fault(dependencies, 'afterReceipt');
  transaction = readMergeTransaction(
    root,
    request.goal_id,
    request.task_id,
    request.event_id,
  );
  return acceptReceiptTransaction(
    cwd,
    root,
    transaction,
    options.actorCapabilityFile,
    dependencies,
  );
}

module.exports = {
  POLICY,
  buildMergeEvent,
  listGitHubMergeOperations,
  mergePolicyEnabled,
  mergePullRequest,
  readMergeTransaction,
  verifyAcceptedMergeReceipt,
  verifyMergeReservationForEvent,
  verifyMergeReceiptForEvent,
};
