'use strict';

const crypto = require('crypto');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { fileURLToPath } = require('url');
const { ControlError, assertControl } = require('./errors');
const {
  MAX_ROLE_LEASE_MS,
  assertCoherentGoalForemanLineage,
  authorizeGoalSession,
  authorizeSession,
  createCapabilityFile,
  hashesEqual,
  readCapabilityFile,
} = require('./auth');
const {
  bindAcceptedEventEvidence,
  resolveEventEvidence,
  resolveTrustedEvidence,
} = require('./evidence');
const { assertDevCandidateLineage } = require('./candidate-lineage');
const {
  LAUNCH_HOLD_CLASSIFICATION,
  assertSourceCheckpointAdvance,
  canonicalRuntimeLaunchFile,
  classifyLaunchIdentityHold,
  isSourceCheckpointHoldIntent,
  readControllerIncidentCandidate,
  readIdentityIncidentSourceBytes,
  runtimeRotationHoldEligible,
} = require('./launch-source-checkpoint');
const {
  actorSequenceKey,
  allowedActions,
  applyEvent,
  expectedRoleForPhase,
  foremanRootRecoveryStatusEligible,
  initialTaskState,
} = require('./fsm');
const {
  adoptLegacyInitReceipt,
  ensurePrivateDirectory,
  finalizeLegacyInitReceiptMetadata,
  fsyncDirectory,
  maybeExitAfterInitCommit,
  maybeInjectPostPublishFault,
  readAndVerifyInitReceipt,
  writeInitReceipt,
} = require('./init-receipt');
const { renderMarkdown, taskLedgerRow } = require('./ledger');
const {
  acceptedEventFiles,
  atomicCreate,
  atomicWrite,
  atomicWriteJson,
  canonicalTransactionKey,
  ensureDir,
  ensureRootProtocol,
  eventHeadFile,
  goalDir,
  goalMergeTargetReservations,
  historicalTransactionKeySha256,
  isHistoricalTransactionRetry,
  isPreWitnessTransactionRetry,
  readJsonIfExists,
  sealChainedRecord,
  sealedEventHead,
  withLock,
  withStableRead,
  writeAcceptedEvent,
} = require('./store');
const {
  assertFullSha,
  assertIsolatedTestMode,
  canonicalJson,
  controlRoot,
  git,
  hashFile,
  hashObject,
  normalizeHash,
  nowIso,
  randomId,
  readOnlyGitEnvironment,
  readJson,
  realpathWithin,
  repoRoot,
  runtimeNowMilliseconds,
  safeId,
  sha256,
} = require('./util');
const {
  assertLiveRoleLostTargetBinding,
  matchesMechanicalP1WritePattern,
  parsePullRequestUrl,
  validateEvent,
  validateLaunchManifest,
  validateManifest,
} = require('./validation');
const { sessionOperationalScope } = require('./operational-scope');
const {
  assertLaunchRuntimeIncarnation,
  assertRotationSuccessorLaunch,
  currentRuntimeIncarnation,
  isRuntimeRotationHoldLane,
  localPreviewPorts,
  predecessorLaunchForRotation,
  validateRuntimeRotationBoundary,
} = require('./runtime-incarnation');
const { verifyPreclaimReceipt } = require('./preclaim-issues');
const {
  assertControllerProvenanceStable,
  controllerProvenanceCapture,
} = require('./canary-controller-attestation');
const {
  validateWorkerBootstrapReceipt,
} = require('./canary-bootstrap');
const {
  assertRequiredLiveBinding: assertRequiredLiveProbeObservationBinding,
  protocolRequired: probeObservationProtocolRequired,
  receiptOptions: probeObservationOptions,
  requestMatchesBinding: probeObservationRequestMatchesBinding,
  validateReceipt: validateProbeObservationReceipt,
} = require('./canary-observation-receipt');
const {
  publicRoleIdentityIntent,
  validateRoleIdentityIntent,
  validateRoleIdentityObservation,
} = require('./role-identity-intent');
const {
  assertWorkerBootstrapCurrentWorktree,
  assertWorkerBootstrapLaunchBinding,
  registrationRequiresWorkerBootstrap,
  requiredWorkerBootstrapBinding,
  sealWorkerBootstrapBinding,
  workerBootstrapEventAllowsHeadAdvance,
  workerBootstrapOptions,
  workerBootstrapRequestMatchesBinding,
} = require('./worker-bootstrap-binding');
const {
  abandonmentReceiptsForTask,
  abandonP1CommitRef,
  acceptedP1Event,
  cleanupExactUnsealedAbandonmentStaging,
  completeP1Abandonment,
  completeP1CommitTransaction,
  inspectExactUnsealedAbandonmentStaging,
  inspectP1Abandonment,
  inspectP1CommitPreparation,
  listP1CommitOperations,
  p1CommitAbandonmentHandoffSha256,
  p1CommitPaths,
  publishP1AbandonmentIntent,
  publishP1CommitAbandonOnlyIntent,
  publishP1CommitAbandonHandoff,
  publishP1CommitIntent,
  publishP1CommitRef,
  readAbandonmentIntent,
  readP1AbandonmentReceipt,
  readP1CommitIntent,
  readP1CommitReceipt,
  repositoryIdentity,
  restoreP1CommitObject,
  verifyP1AbandonmentRecoveryLineage,
  verifyP1CommitRecoveryLineage,
} = require('./p1-commit-transaction');

function maybeInjectRecoveryBatchFault(cwd, environmentName, code, message) {
  const mode = process.env[environmentName];
  if (mode === undefined || mode === '') return;
  assertControl(
    ['1', 'throw', 'exit'].includes(mode),
    'INVALID_TEST_FAULT',
    `${environmentName} 只能是 1/throw/exit`,
  );
  assertIsolatedTestMode(cwd);
  if (mode === 'exit') process.exit(86);
  throw new ControlError(code, message);
}

function maybeInjectGenerationBoundaryFault(cwd, environmentName) {
  const mode = process.env[environmentName];
  if (mode === undefined || mode === '') return;
  assertControl(
    ['1', 'throw', 'exit', 'sigkill'].includes(mode),
    'INVALID_TEST_FAULT',
    `${environmentName} 只能是 1/throw/exit/sigkill`,
  );
  assertIsolatedTestMode(cwd);
  if (mode === 'sigkill') {
    process.kill(process.pid, 'SIGKILL');
    return;
  }
  if (mode === 'exit') process.exit(86);
  throw new ControlError(
    'TEST_FAULT_AFTER_GENERATION',
    `injected generation boundary failure: ${environmentName}`,
  );
}

function generationBoundaryFaultHook(cwd, environmentName) {
  const mode = process.env[environmentName];
  if (mode === undefined || mode === '') return undefined;
  assertIsolatedTestMode(cwd);
  return () => maybeInjectGenerationBoundaryFault(cwd, environmentName);
}

const PRISTINE_PREFLIGHT_GIT_ENVIRONMENT = Object.freeze({
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  GCM_INTERACTIVE: 'Never',
});

function withPristinePreflightGitEnvironment(callback) {
  const previous = new Map(
    Object.keys(PRISTINE_PREFLIGHT_GIT_ENVIRONMENT).map((name) => (
      [name, process.env[name]]
    )),
  );
  try {
    for (const [name, value] of Object.entries(
      PRISTINE_PREFLIGHT_GIT_ENVIRONMENT,
    )) {
      process.env[name] = value;
    }
    return callback();
  } finally {
    for (const [name, value] of previous.entries()) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

function readSealedRootGenerationSummary(root) {
  const file = path.join(root, '.generation.json');
  if (!fs.existsSync(file)) {
    return { parity: 'EVEN', activeTransaction: null, updatedAt: null };
  }
  try {
    const seal = JSON.parse(fs.readFileSync(file, 'utf8'));
    const unsigned = { ...seal };
    delete unsigned.seal_sha256;
    if (
      !seal
        || typeof seal !== 'object'
        || Array.isArray(seal)
        || !Number.isSafeInteger(seal.generation)
        || seal.generation < 0
        || typeof seal.seal_sha256 !== 'string'
        || hashObject(unsigned) !== seal.seal_sha256
        || (
          seal.generation % 2 === 0
            ? seal.active_transaction !== null
              && seal.active_transaction !== undefined
            : !seal.active_transaction
        )
    ) {
      return { parity: 'UNKNOWN', activeTransaction: null, updatedAt: null };
    }
    return {
      parity: seal.generation % 2 === 0 ? 'EVEN' : 'ODD',
      activeTransaction: seal.active_transaction || null,
      updatedAt: seal.updated_at,
    };
  } catch {
    return { parity: 'UNKNOWN', activeTransaction: null, updatedAt: null };
  }
}

function readSealedRootGenerationParity(root) {
  return readSealedRootGenerationSummary(root).parity;
}

function rejectionCapabilitySnapshot(cwd, capabilityFile) {
  if (typeof capabilityFile !== 'string' || capabilityFile.length === 0) {
    return {
      schema_version: 1,
      path_sha256: hashObject(null),
      state: 'MISSING',
      metadata: null,
      bytes_sha256: null,
    };
  }
  let resolved;
  try {
    resolved = path.resolve(cwd, capabilityFile);
  } catch {
    return {
      schema_version: 1,
      path_sha256: hashObject(String(capabilityFile)),
      state: 'UNREADABLE',
      metadata: null,
      bytes_sha256: null,
    };
  }
  const base = {
    schema_version: 1,
    path_sha256: hashObject(resolved),
  };
  let stat;
  try {
    stat = fs.lstatSync(resolved);
  } catch (error) {
    return {
      ...base,
      state: error && error.code === 'ENOENT' ? 'MISSING' : 'UNREADABLE',
      metadata: null,
      bytes_sha256: null,
    };
  }
  const kind = stat.isFile()
    ? 'REGULAR'
    : stat.isDirectory()
      ? 'DIRECTORY'
      : stat.isSymbolicLink()
        ? 'SYMLINK'
        : 'OTHER';
  const metadata = {
    kind,
    mode: stat.mode & 0o7777,
    uid: stat.uid,
    gid: stat.gid,
    size: stat.size,
    dev: String(stat.dev),
    ino: String(stat.ino),
  };
  if (kind !== 'REGULAR') {
    return {
      ...base,
      state: 'NON_REGULAR',
      metadata,
      bytes_sha256: null,
    };
  }
  try {
    return {
      ...base,
      state: 'REGULAR',
      metadata,
      bytes_sha256: `sha256:${sha256(fs.readFileSync(resolved))}`,
    };
  } catch {
    return {
      ...base,
      state: 'UNREADABLE',
      metadata,
      bytes_sha256: null,
    };
  }
}

function redactRejectedEvent(value) {
  if (Array.isArray(value)) return value.map(redactRejectedEvent);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key,
    /token|secret|password|authorization|cookie|credential|capability/i.test(key)
      ? '[REDACTED]'
      : redactRejectedEvent(child),
  ]));
}

function deterministicErrorSnapshot(error) {
  const details = error && error.details !== undefined
    ? redactRejectedEvent(error.details)
    : null;
  return {
    code: error && typeof error.code === 'string'
      ? error.code
      : 'UNEXPECTED',
    message_sha256: hashObject(
      error && typeof error.message === 'string' ? error.message : '',
    ),
    details_sha256: hashObject(details),
  };
}

function prepareGoalEventRejection(
  cwd,
  root,
  rawEvent,
  actorCapabilityFile,
  error,
) {
  const rawEventSha256 = hashObject(rawEvent);
  const caller = rejectionCapabilitySnapshot(cwd, actorCapabilityFile);
  const errorSnapshot = deterministicErrorSnapshot(error);
  const rejectionRequest = {
    schema_version: 1,
    kind: 'GOAL_EVENT_REJECTION_REQUEST',
    raw_event_sha256: rawEventSha256,
    error: errorSnapshot,
    caller,
  };
  const requestSha256 = hashObject(rejectionRequest);
  const unsignedReceipt = {
    schema_version: 1,
    kind: 'GOAL_EVENT_REJECTION_RECEIPT',
    raw_event_sha256: rawEventSha256,
    request_sha256: requestSha256,
    error: errorSnapshot,
    caller,
    event: redactRejectedEvent(rawEvent),
  };
  const receipt = {
    ...unsignedReceipt,
    receipt_sha256: hashObject(unsignedReceipt),
  };
  const rawDigest = rawEventSha256.slice('sha256:'.length);
  const requestDigest = requestSha256.slice('sha256:'.length);
  // Empty/partial bytes cannot authenticate themselves after a crash. The
  // deterministic pathname therefore commits the exact caller, request, and
  // sealed receipt before the O_EXCL inode is created.
  const temporaryBindingSha256 = hashObject({
    schema_version: 1,
    kind: 'GOAL_EVENT_REJECTION_TEMPORARY_BINDING',
    request_sha256: requestSha256,
    caller_sha256: hashObject(caller),
    receipt_sha256: receipt.receipt_sha256,
  });
  const baseName = `.goal-event-rejection-${rawDigest}-${requestDigest}.json`;
  return {
    caller,
    canonical: path.join(root, baseName),
    temporary: path.join(
      root,
      `${baseName}.tmp-${temporaryBindingSha256.slice('sha256:'.length)}`,
    ),
    temporaryPrefix: `${baseName}.tmp`,
    temporaryBindingSha256,
    bytes: `${JSON.stringify(receipt, null, 2)}\n`,
    receipt,
    transactionKey: canonicalTransactionKey(
      'GOAL_EVENT_REJECTION',
      { lane: 'deterministic_event_rejection_v2' },
      rawEventSha256,
      requestSha256,
    ),
  };
}

function inspectGoalEventRejectionReceipt(prepared) {
  const directory = path.dirname(prepared.canonical);
  const temporaryCandidates = fs.readdirSync(directory)
    .filter((name) => name.startsWith(prepared.temporaryPrefix))
    .sort();
  assertControl(
    temporaryCandidates.length <= 1
      && (
        temporaryCandidates.length === 0
          || path.join(directory, temporaryCandidates[0])
            === prepared.temporary
      ),
    'REJECTION_RECEIPT_CONFLICT',
    'rejection receipt temporary inventory 含 foreign/lookalike/multiple pathname',
  );
  const expectedBytes = Buffer.from(prepared.bytes);
  const inspect = (file, label, allowExactPrefix) => {
    if (!fs.existsSync(file)) return null;
    const stat = fs.lstatSync(file);
    assertControl(
      stat.isFile()
        && !stat.isSymbolicLink()
        && (stat.mode & 0o777) === 0o600
        && (
          typeof process.getuid !== 'function'
            || stat.uid === process.getuid()
        ),
      'REJECTION_RECEIPT_CONFLICT',
      `${label} 必须是当前 owner 的 0600 普通文件`,
    );
    const bytes = fs.readFileSync(file);
    const complete = bytes.equals(expectedBytes);
    assertControl(
      complete
        || (
          allowExactPrefix
            && bytes.length < expectedBytes.length
            && expectedBytes.subarray(0, bytes.length).equals(bytes)
        ),
      'REJECTION_RECEIPT_CONFLICT',
      `${label} 不是 exact sealed receipt 或其 exact partial prefix`,
    );
    return { stat, complete, byteLength: bytes.length };
  };
  const canonical = inspect(
    prepared.canonical,
    'rejection receipt',
    false,
  );
  const temporary = inspect(
    prepared.temporary,
    'rejection receipt temporary',
    true,
  );
  if (canonical && temporary) {
    assertControl(
      temporary.complete
        && canonical.stat.dev === temporary.stat.dev
        && canonical.stat.ino === temporary.stat.ino,
      'REJECTION_RECEIPT_CONFLICT',
      'rejection receipt canonical/temp 不是同一 exact no-clobber inode',
    );
  }
  if (canonical) return { kind: 'CANONICAL', canonical, temporary };
  if (temporary) return { kind: 'TEMPORARY', canonical, temporary };
  return { kind: 'PRISTINE', canonical: null, temporary: null };
}

function writeGoalEventRejectionReceiptRange(
  descriptor,
  body,
  start,
  end,
) {
  let offset = start;
  while (offset < end) {
    const written = fs.writeSync(
      descriptor,
      body,
      offset,
      end - offset,
      offset,
    );
    assertControl(
      written > 0,
      'REJECTION_RECEIPT_CONFLICT',
      'rejection receipt temporary write 未推进',
    );
    offset += written;
  }
}

function createGoalEventRejectionReceiptTemporary(cwd, prepared) {
  const flags = fs.constants.O_WRONLY
    | fs.constants.O_CREAT
    | fs.constants.O_EXCL
    | (fs.constants.O_NOFOLLOW || 0);
  let descriptor;
  try {
    descriptor = fs.openSync(prepared.temporary, flags, 0o600);
    const opened = fs.fstatSync(descriptor);
    assertControl(
      opened.isFile()
        && (opened.mode & 0o777) === 0o600
        && (
          typeof process.getuid !== 'function'
            || opened.uid === process.getuid()
        ),
      'REJECTION_RECEIPT_CONFLICT',
      'rejection receipt temporary create 未形成当前 owner 的 0600 inode',
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(prepared.temporary));
  maybeInjectGenerationBoundaryFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_CREATE',
  );
}

function installGoalEventRejectionReceiptTemporary(cwd, prepared, state) {
  assertControl(
    state.kind === 'TEMPORARY' && state.temporary,
    'REJECTION_RECEIPT_CONFLICT',
    'rejection receipt install 缺 deterministic temporary',
  );
  const body = Buffer.from(prepared.bytes);
  let descriptor;
  try {
    const before = fs.lstatSync(prepared.temporary);
    descriptor = fs.openSync(
      prepared.temporary,
      fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0),
    );
    const opened = fs.fstatSync(descriptor);
    assertControl(
      before.isFile()
        && !before.isSymbolicLink()
        && before.dev === opened.dev
        && before.ino === opened.ino
        && (opened.mode & 0o777) === 0o600
        && (
          typeof process.getuid !== 'function'
            || opened.uid === process.getuid()
        ),
      'REJECTION_RECEIPT_CONFLICT',
      'rejection receipt temporary open 时 inode/mode 漂移',
    );
    if (!state.temporary.complete) {
      fs.ftruncateSync(descriptor, 0);
      const firstChunkLength = Math.max(1, Math.floor(body.length / 2));
      writeGoalEventRejectionReceiptRange(
        descriptor,
        body,
        0,
        firstChunkLength,
      );
      maybeInjectGenerationBoundaryFault(
        cwd,
        'GOAL_CONTROL_TEST_FAULT_DURING_REJECTION_TEMP_WRITE',
      );
      writeGoalEventRejectionReceiptRange(
        descriptor,
        body,
        firstChunkLength,
        body.length,
      );
    }
    fs.fsyncSync(descriptor);
    maybeInjectGenerationBoundaryFault(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_FSYNC',
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  state = inspectGoalEventRejectionReceipt(prepared);
  assertControl(
    state.kind === 'TEMPORARY'
      && state.temporary
      && state.temporary.complete,
    'REJECTION_RECEIPT_CONFLICT',
    'rejection receipt temporary write 未形成 exact sealed bytes',
  );
  try {
    fs.linkSync(prepared.temporary, prepared.canonical);
  } catch (error) {
    if (!error || error.code !== 'EEXIST') throw error;
  }
  state = inspectGoalEventRejectionReceipt(prepared);
  assertControl(
    state.kind === 'CANONICAL'
      && state.canonical
      && state.temporary
      && state.temporary.complete,
    'REJECTION_RECEIPT_CONFLICT',
    'rejection receipt no-clobber publication 未形成同 inode lineage',
  );
  maybeInjectGenerationBoundaryFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_LINK',
  );
  fsyncDirectory(path.dirname(prepared.canonical));
  return state;
}

function publishGoalEventRejectionReceipt(cwd, prepared) {
  let state = inspectGoalEventRejectionReceipt(prepared);
  if (state.kind === 'PRISTINE') {
    createGoalEventRejectionReceiptTemporary(cwd, prepared);
    state = inspectGoalEventRejectionReceipt(prepared);
  }
  if (state.kind === 'TEMPORARY') {
    state = installGoalEventRejectionReceiptTemporary(cwd, prepared, state);
  }
  if (state.temporary) {
    state = inspectGoalEventRejectionReceipt(prepared);
    assertControl(
      state.kind === 'CANONICAL'
        && state.canonical
        && state.temporary
        && state.temporary.complete,
      'REJECTION_RECEIPT_CONFLICT',
      'rejection receipt cleanup 前 canonical/temporary inode 漂移',
    );
    fs.unlinkSync(prepared.temporary);
    fsyncDirectory(path.dirname(prepared.temporary));
  }
  const finalState = inspectGoalEventRejectionReceipt(prepared);
  assertControl(
    finalState.kind === 'CANONICAL' && !finalState.temporary,
    'REJECTION_RECEIPT_CONFLICT',
    'rejection receipt publication 未收敛到 exact canonical',
  );
  return prepared.receipt;
}

function goalPaths(root, goalId) {
  const dir = goalDir(root, goalId);
  return {
    dir,
    manifest: path.join(dir, 'manifest.json'),
    meta: path.join(dir, 'goal.json'),
    state: path.join(dir, 'state.json'),
    ledgerJson: path.join(dir, 'ledger.json'),
    ledgerMarkdown: path.join(dir, 'ledger.md'),
    controlEvents: path.join(dir, 'control-events'),
    controlHead: path.join(dir, 'control-head.json'),
    foremanRecoveryBatches: path.join(dir, 'foreman-recovery-batches'),
    registrationIntents: path.join(dir, 'registration-intents'),
    probeObservationChallenges:
      path.join(dir, 'probe-observation-challenges'),
    roleIdentityIntents:
      path.join(dir, 'probe-observation-challenges'),
    probeObservationEvidence:
      path.join(dir, 'probe-observation-evidence'),
  };
}

function probeObservationChallengeFile(paths, eventId) {
  return path.join(
    paths.probeObservationChallenges,
    `${sha256(eventId)}.json`,
  );
}

function probeObservationChallengeRecord(paths, options, planSha256) {
  const file = probeObservationChallengeFile(
    paths,
    options.registrationEventId,
  );
  assertControl(
    fs.existsSync(file),
    'CANARY_OBSERVATION_CHALLENGE_REQUIRED',
    '必须先由 controller prepare-probe-observation-challenge',
  );
  const record = readJson(file, 'probe observation challenge');
  assertControl(
    record.canary_plan_sha256 === planSha256,
    'CANARY_OBSERVATION_CHALLENGE_INVALID',
    'controller challenge 未绑定当前 canary plan',
  );
  return record;
}

function publicProbeObservationChallenge(record) {
  return JSON.parse(JSON.stringify(record));
}

function roleIdentityIntentFile(paths, operationId) {
  return path.join(
    paths.roleIdentityIntents,
    `${sha256(operationId)}.role-identity-intent.json`,
  );
}

function readRoleIdentityIntent(paths, operationId) {
  const file = roleIdentityIntentFile(paths, operationId);
  if (!fs.existsSync(file)) return null;
  return validateRoleIdentityIntent(
    readJson(file, `role identity intent ${operationId}`),
  );
}

function controllerDerivedRoleAttempt(loaded, taskId, role) {
  const state = loaded.snapshot.tasks[taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
  if (role === 'FOREMAN' && !state.sessions.FOREMAN) {
    const lineage = Object.values(loaded.snapshot.tasks || {})
      .map((candidate) => candidate.sessions && candidate.sessions.FOREMAN)
      .filter(Boolean);
    if (lineage.length > 0) {
      const attempt = Math.max(
        ...lineage.map((session) => session.attempt),
      );
      const current = lineage.filter(
        (session) => session.attempt === attempt,
      );
      assertControl(
        current.every((session) => (
          session.thread_id === current[0].thread_id
            && session.host_id === current[0].host_id
        )),
        'GOAL_FOREMAN_LINEAGE_DIVERGED',
        `Goal FOREMAN attempt=${attempt} identity 分叉`,
      );
      return attempt;
    }
  }
  const current = state.sessions[role] || null;
  if (current && ['active', 'idle'].includes(current.status)) {
    return current.attempt;
  }
  const attempts = [
    ...(current ? [current.attempt] : []),
    ...((state.session_history && state.session_history[role]) || [])
      .map((session) => session.attempt),
  ].filter((attempt) => Number.isSafeInteger(attempt) && attempt > 0);
  return attempts.length === 0 ? 1 : Math.max(...attempts) + 1;
}

function challengeIssuerAuthority(loaded, options, supplied) {
  const state = loaded.snapshot.tasks[options.taskId];
  const now = runtimeNowMilliseconds();
  const sessions = Object.entries(loaded.snapshot.tasks || {})
    .flatMap(([sourceTaskId, task]) => (
      Object.values(task.sessions || {}).map((session) => ({
        ...session,
        source_task_id: sourceTaskId,
      }))
    ))
    .filter((session) => (
      session.capability_sha256 === supplied.sha256
        && session.capability_file === supplied.file
        && ['active', 'idle'].includes(session.status)
        && Date.parse(session.lease_until) > now
    ))
    .sort((left, right) => (
      left.source_task_id.localeCompare(right.source_task_id)
    ));
  assertControl(
    sessions.every((session) => (
      sessions.length === 0
        || (
          session.role === sessions[0].role
            && session.thread_id === sessions[0].thread_id
            && session.host_id === sessions[0].host_id
            && session.attempt === sessions[0].attempt
            && session.lease_until === sessions[0].lease_until
            && (
              session.role_identity
                ? session.role_identity.session_id
                : null
            ) === (
              sessions[0].role_identity
                ? sessions[0].role_identity.session_id
                : null
            )
        )
    )),
    'CORRUPT_STORE',
    'probe observation challenge issuer capability identity 分叉',
  );
  const bootstrapIssuer = !loaded.meta.bootstrap_consumed_at
    && supplied.file === loaded.meta.bootstrap_capability_file
    && hashesEqual(
      supplied.sha256,
      loaded.meta.bootstrap_capability_sha256,
    );
  const recoveryIssuer =
    supplied.file === loaded.meta.foreman_recovery_capability_file
    && hashesEqual(
      supplied.sha256,
      loaded.meta.foreman_recovery_capability_sha256,
    );
  const currentTarget = state.sessions[options.role] || null;
  if (
    currentTarget
      && sessions.length > 0
      && sessions[0].role === options.role
  ) {
    assertControl(
      sessions[0].role === options.role
        && sessions[0].thread_id === currentTarget.thread_id
        && sessions[0].host_id === currentTarget.host_id
        && sessions[0].attempt === currentTarget.attempt,
      'CAPABILITY_INVALID',
      'current role canary refresh 必须由 exact current session 签发',
    );
    return {
      kind: 'CURRENT_SESSION',
      capability_sha256: supplied.sha256,
      session: sessions[0],
    };
  }
  if (options.role === 'FOREMAN' && bootstrapIssuer) {
    assertControl(
      Object.values(loaded.snapshot.tasks || {})
        .every((task) => !task.sessions.FOREMAN),
      'CAPABILITY_CONSUMED',
      'bootstrap 只能签发首次 FOREMAN identity intent',
    );
    return {
      kind: 'BOOTSTRAP',
      capability_sha256: supplied.sha256,
      session: null,
    };
  }
  if (options.role === 'FOREMAN' && recoveryIssuer) {
    assertControl(
      currentTarget
        && (
          (
            state.recovery
              && state.recovery.role === 'FOREMAN'
          )
            || (
              foremanRootRecoveryStatusEligible(state, currentTarget)
                && Date.parse(currentTarget.lease_until) <= now
            )
        ),
      'CAPABILITY_INVALID',
      'Goal recovery authority 只签发已进入 recovery 或 lease-expired root recovery 的 FOREMAN successor',
    );
    return {
      kind: 'GOAL_RECOVERY',
      capability_sha256: supplied.sha256,
      session: null,
    };
  }
  const requiredRole = ['FOREMAN', 'CAPTAIN'].includes(options.role)
    ? 'FOREMAN'
    : 'CAPTAIN';
  assertControl(
    sessions.length > 0 && sessions[0].role === requiredRole,
    'CAPABILITY_INVALID',
    `role identity intent issuer 必须是 ${requiredRole}`,
  );
  if (options.role !== 'FOREMAN') {
    assertControl(
      sessions[0].source_task_id === options.taskId,
      'CAPABILITY_INVALID',
      'role identity intent issuer 不属于目标 task',
    );
  }
  return {
    kind: 'SESSION',
    capability_sha256: supplied.sha256,
    session: sessions[0],
  };
}

function sanitizedChallengeIssuerAuthority(loaded, state, authority) {
  const session = authority.session
    || (
      authority.kind === 'GOAL_RECOVERY'
        ? state.sessions.FOREMAN || null
        : null
    );
  const sessionIdentity = session && session.role_identity
    ? session.role_identity.session_id
    : null;
  return {
    kind: authority.kind,
    capability_sha256: authority.capability_sha256,
    source_task_id: session ? session.source_task_id || state.task_id : null,
    role: session ? session.role : null,
    thread_id: session ? session.thread_id : null,
    host_id: session ? session.host_id : null,
    attempt: session ? session.attempt : null,
    session_id: sessionIdentity,
    lease_until: session ? session.lease_until : null,
    registration_event_id:
      session && session.registration_event_id
        ? session.registration_event_id
        : null,
    bootstrap_init_receipt_sha256:
      authority.kind === 'BOOTSTRAP'
        ? loaded.meta.init_receipt_sha256
        : null,
    recovery_scope_sha256:
      authority.kind === 'GOAL_RECOVERY'
        ? foremanRecoveryScope(loaded).scope_sha256
        : null,
  };
}

function prepareChallengeIdentity(root, options, transactionStartedAt) {
  const loaded = loadGoalStateUnlocked(root, options.goalId, {
    repairHeads: false,
    repairBootstrapConsumption: false,
  });
  assertControl(
    probeObservationProtocolRequired(loaded.manifest),
    'PROBE_OBSERVATION_PROTOCOL_UNSUPPORTED',
    'manifest 未启用 probe observation receipts',
  );
  const state = loaded.snapshot.tasks[options.taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
  const operationId = safeId(options.eventId, 'registration event_id');
  const role = options.role;
  assertControl(
    ['FOREMAN', 'CAPTAIN', 'DEV', 'REVIEW', 'RECEIPT'].includes(role),
    'INVALID_ROLE',
    `未知 role ${role}`,
  );
  const attempt = controllerDerivedRoleAttempt(
    loaded,
    options.taskId,
    role,
  );
  const issuer = readCapabilityFile(options.issuerCapabilityFile);
  const authority = challengeIssuerAuthority(loaded, options, issuer);
  const validatedObservation = validateRoleIdentityObservation({
    receiptFile: options.identityReceipt,
    receiptSha256: options.identityReceiptSha256,
    operationId,
    goalId: options.goalId,
    taskId: options.taskId,
    role,
    repositoryHead: state.full_head,
    acceptanceTime: transactionStartedAt,
    maxTtlMs:
      loaded.manifest.probe_observation_receipts.max_ttl_ms,
    hostAttestation:
      loaded.manifest.probe_observation_receipts.host_attestation,
  });
  const observation = validatedObservation.record;
  if (authority.kind === 'CURRENT_SESSION') {
    const currentRoleIdentity = authority.session.role_identity;
    const currentWorkerBootstrap =
      authority.session.worker_bootstrap || null;
    assertControl(
      observation.thread_id === authority.session.thread_id
        && observation.host_id === authority.session.host_id
        && attempt === authority.session.attempt
        && currentRoleIdentity
        && observation.session_id === currentRoleIdentity.session_id
        && observation.launch_id === authority.session.launch_id
        && observation.worker_bootstrap_binding_sha256
          === (
            currentWorkerBootstrap
              ? currentWorkerBootstrap.binding_sha256
              : null
          ),
      'ROLE_IDENTITY_OBSERVATION_BINDING_MISMATCH',
      'current session refresh observation identity/session/launch/bootstrap 不匹配',
    );
  }
  if (role === 'FOREMAN' && authority.kind === 'SESSION') {
    assertControl(
      observation.thread_id === authority.session.thread_id
        && observation.host_id === authority.session.host_id
        && attempt === authority.session.attempt
        && authority.session.role_identity
        && observation.session_id
          === authority.session.role_identity.session_id
        && observation.launch_id === null
        && observation.worker_bootstrap_binding_sha256 === null,
      'GOAL_FOREMAN_PROJECTION_REQUIRED',
      'later-task FOREMAN intent 必须复用 exact Goal authority identity',
    );
  }
  if (!state.sessions[role]) {
    if (!(role === 'FOREMAN' && authority.kind === 'SESSION')) {
      assertFreshGoalRoleIdentity(
        loaded.snapshot,
        options.taskId,
        role,
        observation.thread_id,
      );
    }
  } else if (authority.kind !== 'CURRENT_SESSION') {
    assertControl(
      (state.recovery && state.recovery.role === role)
        || state.sessions[role].status === 'terminal'
        || authority.kind === 'GOAL_RECOVERY',
      'ROLE_REPLACEMENT_REQUIRES_RECOVERY',
      `${role} successor identity intent 需要 durable recovery 或 terminal predecessor`,
    );
  }
  if (['DEV', 'REVIEW', 'RECEIPT'].includes(role)) {
    assertControl(
      observation.launch_id,
      'LAUNCH_ID_REQUIRED',
      `${role} identity observation 必须绑定 upstream launch_id`,
    );
  } else {
    assertControl(
      observation.launch_id === null
        && observation.worker_bootstrap_binding_sha256 === null,
      'ROLE_IDENTITY_OBSERVATION_BINDING_MISMATCH',
      `${role} control identity observation 禁止 worker launch/bootstrap binding`,
    );
  }
  if (registrationRequiresWorkerBootstrap(loaded.manifest, role)) {
    assertControl(
      observation.worker_bootstrap_binding_sha256,
      'WORKER_BOOTSTRAP_REGISTRATION_REQUIRED',
      `${role} identity observation 缺 worker bootstrap binding`,
    );
  }
  const intentUnsigned = {
    schema_version: 1,
    kind: 'ROLE_IDENTITY_INTENT',
    operation_id: operationId,
    goal_id: options.goalId,
    task_id: options.taskId,
    role,
    thread_id: observation.thread_id,
    host_id: observation.host_id,
    attempt,
    session_id: observation.session_id,
    launch_id: observation.launch_id,
    state_revision: state.state_revision,
    control_epoch: loaded.control.epoch,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    base_head: state.base_head,
    full_head: state.full_head,
    task_cycle: state.task_cycle,
    identity_observation: {
      receipt_sha256: normalizeHash(
        options.identityReceiptSha256,
        'role identity observation receipt sha256',
      ),
      receipt_file_identity_sha256:
        validatedObservation.receipt_file_identity_sha256,
      record_sha256: observation.record_sha256,
      attestation_key_id: observation.attestation.key_id,
      observed_at: observation.observed_at,
      expires_at: observation.expires_at,
      worker_bootstrap_binding_sha256:
        observation.worker_bootstrap_binding_sha256,
    },
    issuer_authority: {
      ...sanitizedChallengeIssuerAuthority(
        loaded,
        state,
        authority,
      ),
    },
    created_at: transactionStartedAt,
  };
  return {
    loaded,
    state,
    observation,
    authority,
    intent: validateRoleIdentityIntent({
      ...intentUnsigned,
      intent_sha256: hashObject(intentUnsigned),
    }),
  };
}

function prepareProbeObservationChallenge(cwd, options) {
  const root = controlRoot(cwd);
  let preparedIdentity = null;
  return withLock(root, () => {
    const {
      loaded,
      observation,
      authority,
      intent,
    } = preparedIdentity;
    const eventId = safeId(
      options.eventId,
      'registration event_id',
    );
    const role = options.role;
    assertControl(
      ['FOREMAN', 'CAPTAIN', 'DEV', 'REVIEW', 'RECEIPT'].includes(role),
      'INVALID_ROLE',
      `未知 role ${role}`,
    );
    const hostId = observation.host_id;
    const attempt = intent.attempt;
    const planSha256 = normalizeHash(
      options.planSha256,
      'canary plan sha256',
    );
    if (!fs.existsSync(loaded.paths.probeObservationChallenges)) {
      ensureDir(loaded.paths.probeObservationChallenges);
    }
    ensurePrivateDirectory(loaded.paths.probeObservationChallenges, {
      repair: true,
    });
    ensurePrivateDirectory(loaded.paths.roleIdentityIntents, {
      repair: true,
    });
    const file = probeObservationChallengeFile(loaded.paths, eventId);
    const intentFile = roleIdentityIntentFile(loaded.paths, eventId);
    const hostAttestation =
      loaded.manifest.probe_observation_receipts.host_attestation;
    const request = {
      schema_version: 1,
      kind: 'PROBE_OBSERVATION_CHALLENGE',
      goal_id: options.goalId,
      task_id: options.taskId,
      role,
      thread_id: observation.thread_id,
      host_id: hostId,
      attempt,
      registration_event_id: eventId,
      canary_plan_sha256: planSha256,
      producer_namespace:
        process.env.GOAL_CONTROL_TEST_MODE === '1'
            ? 'ISOLATED_TEST_FAKE'
            : 'HOST_ADAPTER',
      issuer_capability_sha256: authority.capability_sha256,
      attestation_algorithm: hostAttestation.algorithm,
      attestation_key_id: hostAttestation.key_id,
      attestation_public_key_sha256:
        hostAttestation.public_key_sha256,
    };
    if (fs.existsSync(file)) {
      const existing = readJson(file, 'probe observation challenge');
      const existingIntent = readRoleIdentityIntent(
        loaded.paths,
        eventId,
      );
      const unsigned = { ...existing };
      delete unsigned.record_sha256;
      assertControl(
        existing.record_sha256 === hashObject(unsigned)
          && existingIntent
          && existingIntent.intent_sha256 === intent.intent_sha256
          && Object.entries(request).every(
            ([key, value]) => existing[key] === value,
          ),
        'CANARY_OBSERVATION_REPLAY_CONFLICT',
        'challenge stable event 已绑定不同 request',
      );
      return publicProbeObservationChallenge(existing);
    }
    assertControl(
      !fs.existsSync(intentFile),
      'CANARY_OBSERVATION_REPLAY_CONFLICT',
      'role identity intent/challenge publication 分叉',
    );
    const issuedAt = nowIso();
    const unsigned = {
      ...request,
      challenge: sha256(
        `${randomId('probe-challenge')}:${eventId}:${issuedAt}`,
      ),
      issued_at: issuedAt,
      expires_at: new Date(
        Date.parse(issuedAt)
          + loaded.manifest.probe_observation_receipts.max_ttl_ms,
      ).toISOString(),
    };
    const record = {
      ...unsigned,
      record_sha256: hashObject(unsigned),
    };
    atomicCreate(intentFile, `${canonicalJson(intent)}\n`);
    fs.chmodSync(intentFile, 0o600);
    atomicWriteJson(file, record);
    return publicProbeObservationChallenge(record);
  }, {
    transactionKey: () => {
      const eventId = safeId(
        options.eventId,
        'registration event_id',
      );
      const request = {
        schema_version: 1,
        kind: 'PROBE_OBSERVATION_CHALLENGE',
        goal_id: safeId(options.goalId, 'goal_id'),
        task_id: safeId(options.taskId, 'task_id'),
        role: options.role,
        registration_event_id: eventId,
        canary_plan_sha256: normalizeHash(
          options.planSha256,
          'canary plan sha256',
        ),
        producer_namespace:
          process.env.GOAL_CONTROL_TEST_MODE === '1'
            ? 'ISOLATED_TEST_FAKE'
            : 'HOST_ADAPTER',
        issuer_capability_file: path.resolve(
          options.issuerCapabilityFile,
        ),
        identity_receipt_file: path.resolve(
          options.identityReceipt,
        ),
        identity_receipt_sha256: normalizeHash(
          options.identityReceiptSha256,
          'role identity observation receipt sha256',
        ),
      };
      return canonicalTransactionKey(
        'PROBE_OBSERVATION_CHALLENGE',
        { goal_id: request.goal_id },
        eventId,
        hashObject(request),
      );
    },
    sameStableOperationMismatchCode:
      'CANARY_OBSERVATION_REPLAY_CONFLICT',
    sameStableOperationMismatchMessage:
      'probe challenge/role identity stable operation 已绑定不同 request',
    beforeGeneration: (transaction) => {
      const paths = goalPaths(root, safeId(options.goalId, 'goal_id'));
      const operationId = safeId(
        options.eventId,
        'registration event_id',
      );
      const existingIntent = readRoleIdentityIntent(
        paths,
        operationId,
      );
      const existingChallengeFile = probeObservationChallengeFile(
        paths,
        operationId,
      );
      if (existingIntent || fs.existsSync(existingChallengeFile)) {
        assertControl(
          existingIntent && fs.existsSync(existingChallengeFile),
          'CANARY_OBSERVATION_REPLAY_CONFLICT',
          'role identity intent/challenge publication 分叉',
        );
        const loaded = loadGoalStateUnlocked(root, options.goalId, {
          repairHeads: false,
          repairBootstrapConsumption: false,
          allowIncompleteGoalOperationRead: true,
        });
        const retryObservation = validateRoleIdentityObservation({
          receiptFile: options.identityReceipt,
          receiptSha256: options.identityReceiptSha256,
          operationId,
          goalId: options.goalId,
          taskId: options.taskId,
          role: options.role,
          repositoryHead: existingIntent.full_head,
          acceptanceTime: existingIntent.created_at,
          maxTtlMs:
            loaded.manifest.probe_observation_receipts.max_ttl_ms,
          hostAttestation:
            loaded.manifest.probe_observation_receipts.host_attestation,
        });
        assertControl(
          existingIntent.goal_id === options.goalId
            && existingIntent.task_id === options.taskId
            && existingIntent.role === options.role
            && existingIntent.operation_id === operationId
            && existingIntent.identity_observation.receipt_sha256
              === normalizeHash(
                options.identityReceiptSha256,
                'role identity observation receipt sha256',
              )
            && existingIntent.identity_observation
              .receipt_file_identity_sha256
              === retryObservation.receipt_file_identity_sha256
            && existingIntent.identity_observation.record_sha256
              === retryObservation.record.record_sha256
            && existingIntent.thread_id
              === retryObservation.record.thread_id
            && existingIntent.host_id
              === retryObservation.record.host_id
            && existingIntent.session_id
              === retryObservation.record.session_id
            && existingIntent.launch_id
              === retryObservation.record.launch_id,
          'CANARY_OBSERVATION_REPLAY_CONFLICT',
          'role identity intent exact retry input 漂移',
        );
        preparedIdentity = {
          loaded,
          observation: {
            thread_id: existingIntent.thread_id,
            host_id: existingIntent.host_id,
          },
          authority: {
            capability_sha256:
              existingIntent.issuer_authority.capability_sha256,
          },
          intent: existingIntent,
        };
      } else {
        preparedIdentity = prepareChallengeIdentity(
          root,
          options,
          transaction.transaction_started_at,
        );
      }
    },
  });
}

function goalInitTransactionKey(
  manifest,
  sourceManifestSha256,
  repositoryRoot,
  goalInputSource,
) {
  const request = {
    schema_version: 1,
    kind: 'GOAL_INIT_TRANSACTION_REQUEST',
    goal_id: manifest.goal_id,
    manifest_sha256: manifest.manifest_sha256,
    source_manifest_sha256: sourceManifestSha256,
    repository_root: repositoryRoot,
    goal_input_source: goalInputSource,
  };
  return canonicalTransactionKey(
    'GOAL_INIT',
    { goal_id: manifest.goal_id },
    manifest.goal_id,
    hashObject(request),
  );
}

function goalEventTransactionKey(rawEvent) {
  let event;
  try {
    event = validateEvent(rawEvent);
  } catch (error) {
    if (!(error instanceof ControlError)) throw error;
    const rawRequestHash = hashObject(rawEvent);
    return canonicalTransactionKey(
      'GOAL_EVENT',
      { lane: 'invalid_event_v2' },
      rawRequestHash,
      rawRequestHash,
    );
  }
  const request = JSON.parse(JSON.stringify(event));
  return canonicalTransactionKey(
    event.type === 'P1_COMMITTED' ? 'P1_COMMIT' : 'GOAL_EVENT',
    {
      goal_id: event.goal_id,
      task_id: event.task_id,
    },
    event.event_id,
    hashObject(request),
  );
}

function registrationStableEventId(options) {
  const attempt = Number(options.attempt || 1);
  const hostId = options.hostId || 'local';
  return safeId(
    options.eventId
      || `register-${options.role.toLowerCase()}-${attempt}-${
        sha256(`${options.taskId}:${hostId}:${options.threadId}`).slice(0, 12)
      }`,
    'registration event_id',
  );
}

function registrationWorkerBootstrapBinding(loaded, state, options) {
  const request = workerBootstrapOptions(options);
  const required = registrationRequiresWorkerBootstrap(
    loaded.manifest,
    options.role,
  );
  assertControl(
    !required || request !== null,
    'WORKER_BOOTSTRAP_REGISTRATION_REQUIRED',
    'manifest 启用 worker canary bootstrap 后，worker registration 必须携带同一 receipt/hash/operation/challenge/plan',
  );
  assertControl(
    required || request === null,
    'WORKER_CANARY_BOOTSTRAP_PROTOCOL_UNSUPPORTED',
    '当前 manifest/role 不接受 worker bootstrap registration binding',
  );
  if (request === null) return null;

  const repositoryRoot = assertFrozenInputs(
    options.repositoryWorktree,
    loaded,
    options.taskId,
  );
  const controller = controllerProvenanceCapture();
  const sourceManifest = path.resolve(
    repositoryRoot,
    loaded.manifest.source_manifest,
  );
  const receipt = validateWorkerBootstrapReceipt({
    receiptFile: request.receipt_file,
    expectedReceiptSha256: request.receipt_sha256,
    expectedOperationId: request.operation_id,
    expectedChallenge: request.challenge,
    expectedIdentityPlanSha256: request.identity_plan_sha256,
    workerThread: options.threadId,
    workerHost: options.hostId || 'local',
    invocationCwd: options.invocationCwd,
    controller: controller.provenance,
    repositoryRoot,
    repositoryHead: git(repositoryRoot, ['rev-parse', 'HEAD']),
    manifestPath: loaded.manifest.source_manifest,
    manifestSha256: hashFile(sourceManifest),
    validatedManifestSha256: loaded.manifest.manifest_sha256,
    repositoryNameWithOwner:
      loaded.manifest.repository.name_with_owner,
    baseBranch: loaded.manifest.repository.base_branch,
    goalId: loaded.manifest.goal_id,
    taskId: options.taskId,
    role: options.role,
    canaryPolicy: loaded.manifest.worker_canary_bootstrap.policy,
  });
  assertControl(
    receipt.head === state.full_head,
    'WORKER_BOOTSTRAP_REGISTRATION_HEAD_MISMATCH',
    `worker bootstrap HEAD ${receipt.head} 与 task full_head ${state.full_head} 不一致`,
  );
  assertControllerProvenanceStable(controller);
  return sealWorkerBootstrapBinding(receipt);
}

function registrationProbeObservationBinding(
  loaded,
  state,
  options,
  eventId = registrationStableEventId(options),
) {
  const request = probeObservationOptions(options);
  const required = probeObservationProtocolRequired(loaded.manifest);
  assertControl(
    !required || request !== null,
    'CANARY_OBSERVATION_REQUIRED',
    'manifest 启用 probe observation receipts 后，registration 必须携带 sealed PASS receipt',
  );
  assertControl(
    required || request === null,
    'PROBE_OBSERVATION_PROTOCOL_UNSUPPORTED',
    '当前 manifest 不接受 probe observation registration binding',
  );
  if (request === null) return null;
  const challengeRecord = probeObservationChallengeRecord(
    loaded.paths,
    {
      ...options,
      registrationEventId: eventId,
    },
    request.canary_plan_sha256,
  );
  return validateProbeObservationReceipt({
    ...options,
    registrationEventId: eventId,
    goalId: loaded.manifest.goal_id,
    taskId: options.taskId,
    role: options.role,
    threadId: options.threadId,
    hostId: options.hostId || 'local',
    attempt: Number(options.attempt || 1),
    repositoryHead: git(
      options.invocationCwd || options.repositoryWorktree,
      ['rev-parse', 'HEAD'],
    ),
    validatedManifestSha256: loaded.manifest.manifest_sha256,
    manifest: loaded.manifest,
    challengeRecord,
    acceptanceTime: options.acceptanceTime,
    evidenceDirectory: path.join(
      loaded.paths.probeObservationEvidence,
      sha256(eventId),
    ),
  });
}

function registrationTransactionKey(options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const eventId = registrationStableEventId(options);
  const request = {
    schema_version: 1,
    kind: 'REGISTRATION_TRANSACTION_REQUEST',
    event_id: eventId,
    goal_id: goalId,
    task_id: taskId,
    role: options.role,
    thread_id: options.threadId,
    host_id: options.hostId || 'local',
    attempt: Number(options.attempt || 1),
    lease_ms: Number(options.leaseMs || 3600000),
    status: options.status || 'active',
    launch_id: options.launchId || null,
    authorizer_thread_id: options.authorizerThreadId || null,
    ...(workerBootstrapOptions(options)
      ? { worker_bootstrap: workerBootstrapOptions(options) }
      : {}),
    ...(probeObservationOptions(options)
      ? { probe_observation: probeObservationOptions(options) }
      : {}),
  };
  return canonicalTransactionKey(
    'REGISTRATION',
    { goal_id: goalId, task_id: taskId },
    eventId,
    hashObject(request),
  );
}

function foremanRecoveryTransactionKey(options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const eventId = safeId(options.eventId, 'root recovery event_id');
  const request = {
    schema_version: 1,
    kind: 'FOREMAN_RECOVERY_TRANSACTION_REQUEST',
    event_id: eventId,
    goal_id: goalId,
    task_id: taskId,
    thread_id: options.threadId,
    host_id: options.hostId || 'local',
    attempt: Number(options.attempt),
    lease_ms: Number(options.leaseMs),
    expected_goal_scope_sha256: normalizeHash(
      options.expectedGoalScopeSha256,
      'expected Goal FOREMAN recovery scope sha256',
    ),
    expected_control_epoch: options.expectedControlEpoch ?? null,
    expected_state_revision: options.expectedStateRevision ?? null,
    expected_event_head: options.expectedEventHead ?? null,
    expected_packet_revision: options.expectedPacketRevision ?? null,
    expected_packet_sha256: options.expectedPacketSha256
      ? normalizeHash(
        options.expectedPacketSha256,
        'expected packet sha256',
      )
      : null,
    expected_full_head: options.expectedFullHead ?? null,
    expected_foreman_thread_id:
      options.expectedForemanThreadId ?? null,
    expected_foreman_host_id: options.expectedForemanHostId ?? null,
    expected_foreman_attempt: options.expectedForemanAttempt ?? null,
    expected_foreman_lease_until:
      options.expectedForemanLeaseUntil ?? null,
    reason: typeof options.reason === 'string'
      ? options.reason.trim()
      : '',
    incident_ref: typeof options.incidentRef === 'string'
      ? options.incidentRef.trim()
      : '',
    ...(probeObservationOptions(options)
      ? { probe_observation: probeObservationOptions(options) }
      : {}),
  };
  return canonicalTransactionKey(
    'FOREMAN_RECOVERY',
    { goal_id: goalId },
    eventId,
    hashObject(request),
  );
}

function goalControlTransactionRequest(options) {
  return {
    schema_version: 1,
    kind: 'GOAL_CONTROL_TRANSACTION_REQUEST',
    event_id: safeId(options.eventId, 'control event_id'),
    goal_id: safeId(options.goalId, 'goal_id'),
    expected_epoch: Number(options.expectedEpoch),
    thread_id: options.threadId || null,
    reason: typeof options.reason === 'string'
      ? options.reason.trim()
      : '',
    instruction_ref: typeof options.instructionRef === 'string'
      ? options.instructionRef.trim()
      : '',
  };
}

function goalControlTransactionKey(options) {
  const request = goalControlTransactionRequest(options);
  return canonicalTransactionKey(
    'GOAL_CONTROL_EVENT',
    { goal_id: request.goal_id },
    request.event_id,
    hashObject(request),
  );
}

function preparedDigest(value, label) {
  const normalized = normalizeHash(value, label);
  return normalized.slice('sha256:'.length);
}

function preparedStagingName(kind, stableId, requestSha256) {
  return `.init-${kind}-${sha256(stableId)}-${preparedDigest(
    requestSha256,
    `${kind} prepared request sha256`,
  )}`;
}

function atomicTemporaryPattern(fileName) {
  const escaped = fileName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `^\\.${escaped}\\.[1-9][0-9]*\\.tmp-[0-9a-f]{24}$`,
  );
}

function assertPreparedDirectory(directory, label) {
  const stat = fs.lstatSync(directory);
  assertControl(
    stat.isDirectory()
      && !stat.isSymbolicLink()
      && (stat.mode & 0o777) === 0o700
      && (
        typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
      ),
    'PREPARED_STAGING_INVALID',
    `${label} 必须是当前 owner 的 0700 普通目录`,
  );
}

function assertPreparedFile(file, label) {
  const stat = fs.lstatSync(file);
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && (stat.mode & 0o777) === 0o600
      && (
        typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
      ),
    'PREPARED_STAGING_INVALID',
    `${label} 必须是当前 owner 的 0600 普通文件`,
  );
}

function protocolPreparedEntries(parent, expectedName, pattern, label) {
  if (!fs.existsSync(parent)) return [];
  const candidates = [];
  for (const name of fs.readdirSync(parent).sort()) {
    if (!name.startsWith('.init-')) continue;
    assertControl(
      pattern.test(name),
      'PREPARED_STAGING_CONFLICT',
      `${label} 发现 foreign/lookalike staging ${name}`,
    );
    const directory = path.join(parent, name);
    assertPreparedDirectory(directory, `${label} ${name}`);
    candidates.push({ name, directory });
  }
  assertControl(
    candidates.length <= 1,
    'PREPARED_STAGING_CONFLICT',
    `${label} 同时存在多个 prepared staging`,
  );
  if (candidates.length === 1) {
    assertControl(
      candidates[0].name === expectedName,
      'PREPARED_REQUEST_MISMATCH',
      `${label} prepared staging 已绑定不同 stable ID/request`,
    );
  }
  return candidates;
}

function removeValidatedPreparedTree(
  parent,
  directory,
  rootFiles,
  childDirectories = [],
) {
  for (const child of childDirectories) {
    for (const file of child.files) {
      fs.rmSync(path.join(child.directory, file), { force: true });
    }
    if (child.files.length > 0) fsyncDirectory(child.directory);
    fs.rmdirSync(child.directory);
  }
  for (const file of rootFiles) {
    fs.rmSync(path.join(directory, file), { force: true });
  }
  if (rootFiles.length > 0 || childDirectories.length > 0) {
    fsyncDirectory(directory);
  }
  fs.rmdirSync(directory);
  fsyncDirectory(parent);
}

function validateUnsealedInitStaging(directory, options = {}) {
  const rootEntries = fs.readdirSync(directory).sort();
  const canonicalRoot = new Set([
    'capabilities',
    'manifest.json',
    'init-receipt.json',
    'goal.json',
  ]);
  const rootAtomicPatterns = [
    atomicTemporaryPattern('manifest.json'),
    atomicTemporaryPattern('init-receipt.json'),
    atomicTemporaryPattern('goal.json'),
  ];
  for (const [index, canonical] of [
    'manifest.json',
    'init-receipt.json',
    'goal.json',
  ].entries()) {
    assertControl(
      rootEntries.filter((name) => (
        name === canonical || rootAtomicPatterns[index].test(name)
      )).length <= 1,
      'PREPARED_STAGING_INVALID',
      `init staging ${canonical} canonical/temp lineage 分叉`,
    );
  }
  const rootFiles = [];
  let capabilitiesDirectory = null;
  for (const name of rootEntries) {
    const file = path.join(directory, name);
    if (name === 'capabilities') {
      const capabilityStat = fs.lstatSync(file);
      const capabilityEntries = capabilityStat.isDirectory()
        && !capabilityStat.isSymbolicLink()
        ? fs.readdirSync(file)
        : [];
      assertControl(
        capabilityStat.isDirectory()
          && !capabilityStat.isSymbolicLink()
          && (
            typeof process.getuid !== 'function'
              || capabilityStat.uid === process.getuid()
          )
          && (
            (capabilityStat.mode & 0o777) === 0o700
              || (
                (capabilityStat.mode & 0o777) === 0o755
                  && capabilityEntries.length === 0
              )
          ),
        'PREPARED_STAGING_INVALID',
        'init capabilities staging 不是私有目录或 legacy empty 0755 窗口',
      );
      if (
        (capabilityStat.mode & 0o777) === 0o755
          && options.repairLegacyMode !== false
      ) {
        fs.chmodSync(file, 0o700);
        fsyncDirectory(directory);
      }
      if ((capabilityStat.mode & 0o777) === 0o700) {
        assertPreparedDirectory(file, 'init capabilities staging');
      }
      capabilitiesDirectory = file;
      continue;
    }
    assertControl(
      canonicalRoot.has(name)
        || rootAtomicPatterns.some((pattern) => pattern.test(name)),
      'PREPARED_STAGING_INVALID',
      `init staging 含未知文件 ${name}`,
    );
    assertPreparedFile(file, `init staging ${name}`);
    rootFiles.push(name);
  }
  const childDirectories = [];
  if (capabilitiesDirectory) {
    const capabilityEntries = fs.readdirSync(capabilitiesDirectory).sort();
    const capabilityNamePattern =
      /^(?:bootstrap|foreman-recovery)-[0-9a-f]{24}\.cap$/;
    const capabilityAtomicPattern =
      /^\.(?:bootstrap|foreman-recovery)-[0-9a-f]{24}\.cap\.[1-9][0-9]*\.tmp-[0-9a-f]{24}$/;
    for (const prefix of ['bootstrap', 'foreman-recovery']) {
      const prefixPattern = new RegExp(
        `^(?:${prefix}\\.cap|${prefix}-[0-9a-f]{24}\\.cap|\\.${prefix}-[0-9a-f]{24}\\.cap\\.[1-9][0-9]*\\.tmp-[0-9a-f]{24})$`,
      );
      assertControl(
        capabilityEntries.filter((name) => prefixPattern.test(name)).length
          <= 1,
        'PREPARED_STAGING_INVALID',
        `init capability ${prefix} lineage 分叉`,
      );
    }
    for (const name of capabilityEntries) {
      assertControl(
        ['bootstrap.cap', 'foreman-recovery.cap'].includes(name)
          || capabilityNamePattern.test(name)
          || capabilityAtomicPattern.test(name),
        'PREPARED_STAGING_INVALID',
        `init capability staging 含未知文件 ${name}`,
      );
      assertPreparedFile(
        path.join(capabilitiesDirectory, name),
        `init capability staging ${name}`,
      );
    }
    childDirectories.push({
      directory: capabilitiesDirectory,
      files: capabilityEntries,
    });
  }
  return { rootFiles, childDirectories };
}

function authorizeCoreGoalInitOddRecovery(
  paths,
  manifest,
  sourceManifestSha256,
  repositoryRoot,
) {
  const requestSha256 = hashObject({
    schema_version: 1,
    kind: 'GOAL_INIT_REQUEST',
    goal_id: manifest.goal_id,
    manifest_sha256: manifest.manifest_sha256,
    source_manifest_sha256: sourceManifestSha256,
    repository_root: repositoryRoot,
  });
  const candidates = protocolPreparedEntries(
    path.dirname(paths.dir),
    preparedStagingName(
      'goal',
      manifest.goal_id,
      requestSha256,
    ),
    /^\.init-goal-[0-9a-f]{64}-[0-9a-f]{64}$/,
    `Goal ${manifest.goal_id} init odd recovery`,
  );
  const expectedReceipt = {
    goalId: manifest.goal_id,
    manifestSha256: manifest.manifest_sha256,
    sourceManifestSha256,
    repositoryRoot,
  };
  if (fs.existsSync(paths.dir)) {
    if (candidates.length !== 0) return false;
    return assertPublishedGoalInitInventory(
      paths,
      manifest,
      expectedReceipt,
    );
  }
  if (candidates.length === 0) return false;
  const prepared = candidates[0];
  const entries = fs.readdirSync(prepared.directory).sort();
  const capabilitiesDirectory = path.join(
    prepared.directory,
    'capabilities',
  );
  const sealed = hashObject(entries) === hashObject([
    'capabilities',
    'goal.json',
    'init-receipt.json',
    'manifest.json',
  ]) && fs.existsSync(capabilitiesDirectory)
    && hashObject(fs.readdirSync(capabilitiesDirectory).sort())
      === hashObject(['bootstrap.cap', 'foreman-recovery.cap']);
  if (sealed) {
    readAndVerifyInitReceipt(prepared.directory, {
      ...expectedReceipt,
      publishedGoalDirectory: paths.dir,
    });
  } else {
    validateUnsealedInitStaging(prepared.directory, {
      repairLegacyMode: false,
    });
  }
  return true;
}

function recoverPreparedGoalInit(
  paths,
  requestSha256,
  expectedReceipt,
) {
  const parent = path.dirname(paths.dir);
  const expectedName = preparedStagingName(
    'goal',
    expectedReceipt.goalId,
    requestSha256,
  );
  const pattern = /^\.init-goal-[0-9a-f]{64}-[0-9a-f]{64}$/;
  const candidates = protocolPreparedEntries(
    parent,
    expectedName,
    pattern,
    `Goal ${expectedReceipt.goalId} init`,
  );
  if (candidates.length === 0) return null;
  assertControl(
    !fs.existsSync(paths.dir),
    'PREPARED_STAGING_CONFLICT',
    `Goal ${expectedReceipt.goalId} final/staging 并存`,
  );
  const prepared = candidates[0];
  const rootEntries = fs.readdirSync(prepared.directory).sort();
  const capabilitiesDirectory = path.join(
    prepared.directory,
    'capabilities',
  );
  const sealed = hashObject(rootEntries) === hashObject([
    'capabilities',
    'goal.json',
    'init-receipt.json',
    'manifest.json',
  ]) && fs.existsSync(capabilitiesDirectory)
    && hashObject(fs.readdirSync(capabilitiesDirectory).sort())
      === hashObject(['bootstrap.cap', 'foreman-recovery.cap']);
  if (!sealed) {
    const inventory = validateUnsealedInitStaging(prepared.directory);
    removeValidatedPreparedTree(
      parent,
      prepared.directory,
      inventory.rootFiles,
      inventory.childDirectories,
    );
    return { cleaned: true };
  }
  readAndVerifyInitReceipt(prepared.directory, {
    ...expectedReceipt,
    publishedGoalDirectory: paths.dir,
  });
  fs.renameSync(prepared.directory, paths.dir);
  fsyncDirectory(parent);
  return { adopted: true };
}

function readMechanicalP1InitBinding(
  goalDirectory,
  expected,
  publishedGoalDirectory = goalDirectory,
) {
  const metadataFile = path.join(goalDirectory, 'goal.json');
  assertControl(
    fs.existsSync(metadataFile),
    'INIT_RECEIPT_MISSING',
    `Goal ${expected.goalId} 缺 sealed mechanical P1 metadata`,
  );
  const metadata = readJson(metadataFile, 'mechanical P1 Goal metadata');
  const unsignedMetadata = { ...metadata };
  delete unsignedMetadata.meta_sha256;
  assertControl(
    metadata.goal_id === expected.goalId
      && metadata.schema_version === 1
      && hashObject(unsignedMetadata) === metadata.meta_sha256,
    'INIT_RECEIPT_TAMPERED',
    'mechanical P1 Goal metadata identity/seal 不匹配',
  );
  assertFullSha(metadata.goal_input_head, 'sealed goal_input_head');
  assertControl(
    metadata.goal_input_source === expected.goalInputSource,
    'INIT_RECEIPT_TAMPERED',
    'mechanical P1 Goal metadata 的 goal_input_source 不匹配',
  );
  readAndVerifyInitReceipt(goalDirectory, {
    goalId: expected.goalId,
    manifestSha256: expected.manifestSha256,
    sourceManifestSha256: expected.sourceManifestSha256,
    repositoryRoot: expected.repositoryRoot,
    goalInputHead: metadata.goal_input_head,
    goalInputSource: metadata.goal_input_source,
    publishedGoalDirectory,
  });
  return {
    goalInputHead: metadata.goal_input_head,
    goalInputSource: metadata.goal_input_source,
  };
}

const GOAL_INIT_DERIVED_FILES = Object.freeze([
  'control-head.json',
  'ledger.json',
  'ledger.md',
  'state.json',
]);

function assertPublishedGoalInitInventory(paths, manifest, expected) {
  assertPreparedDirectory(paths.dir, `Goal ${manifest.goal_id} published init`);
  const required = new Set([
    'capabilities',
    'goal.json',
    'init-receipt.json',
    'manifest.json',
  ]);
  const allowed = new Set([
    ...required,
    ...GOAL_INIT_DERIVED_FILES,
    'event-heads',
  ]);
  const entries = fs.readdirSync(paths.dir).sort();
  assertControl(
    [...required].every((name) => entries.includes(name))
      && entries.every((name) => allowed.has(name)),
    'PREPARED_STAGING_INVALID',
    `Goal ${manifest.goal_id} published init 含未知或缺失条目`,
  );

  const capabilitiesDirectory = path.join(paths.dir, 'capabilities');
  assertPreparedDirectory(
    capabilitiesDirectory,
    `Goal ${manifest.goal_id} published init capabilities`,
  );
  const capabilityEntries = fs.readdirSync(capabilitiesDirectory).sort();
  assertControl(
    hashObject(capabilityEntries)
      === hashObject(['bootstrap.cap', 'foreman-recovery.cap']),
    'PREPARED_STAGING_INVALID',
    `Goal ${manifest.goal_id} published init capability inventory 非法`,
  );
  for (const name of capabilityEntries) {
    assertPreparedFile(
      path.join(capabilitiesDirectory, name),
      `Goal ${manifest.goal_id} published init capability ${name}`,
    );
  }

  for (const name of GOAL_INIT_DERIVED_FILES) {
    const file = path.join(paths.dir, name);
    if (fs.existsSync(file)) {
      assertPreparedFile(
        file,
        `Goal ${manifest.goal_id} published init derived ${name}`,
      );
    }
  }
  const eventHeadsDirectory = path.join(paths.dir, 'event-heads');
  if (fs.existsSync(eventHeadsDirectory)) {
    assertPreparedDirectory(
      eventHeadsDirectory,
      `Goal ${manifest.goal_id} published init event-heads`,
    );
    const allowedHeads = new Set(
      manifest.tasks.map((task) => `${task.id}.json`),
    );
    for (const name of fs.readdirSync(eventHeadsDirectory).sort()) {
      assertControl(
        allowedHeads.has(name),
        'PREPARED_STAGING_INVALID',
        `Goal ${manifest.goal_id} published init 含未知 event head ${name}`,
      );
      assertPreparedFile(
        path.join(eventHeadsDirectory, name),
        `Goal ${manifest.goal_id} published init event head ${name}`,
      );
    }
  }

  if (expected.goalInputSource) {
    readMechanicalP1InitBinding(paths.dir, expected);
  } else {
    readAndVerifyInitReceipt(paths.dir, expected);
  }
  return true;
}

function discardPublishedGoalInitDerived(paths) {
  let changed = false;
  for (const name of GOAL_INIT_DERIVED_FILES) {
    const file = path.join(paths.dir, name);
    if (!fs.existsSync(file)) continue;
    fs.unlinkSync(file);
    changed = true;
  }
  const eventHeadsDirectory = path.join(paths.dir, 'event-heads');
  if (fs.existsSync(eventHeadsDirectory)) {
    for (const name of fs.readdirSync(eventHeadsDirectory)) {
      fs.unlinkSync(path.join(eventHeadsDirectory, name));
    }
    fsyncDirectory(eventHeadsDirectory);
    fs.rmdirSync(eventHeadsDirectory);
    changed = true;
  }
  if (changed) fsyncDirectory(paths.dir);
}

function discoverSealedMechanicalP1InitBinding(paths, expected) {
  const parent = path.dirname(paths.dir);
  if (!fs.existsSync(parent)) return null;
  const stablePrefix = `.init-goal-${sha256(expected.goalId)}-`;
  const pattern = /^\.init-goal-[0-9a-f]{64}-[0-9a-f]{64}$/;
  const candidates = [];
  for (const name of fs.readdirSync(parent).sort()) {
    if (!name.startsWith('.init-')) continue;
    assertControl(
      pattern.test(name) && name.startsWith(stablePrefix),
      'PREPARED_STAGING_CONFLICT',
      `Goal ${expected.goalId} init 发现 foreign/lookalike staging ${name}`,
    );
    const directory = path.join(parent, name);
    assertPreparedDirectory(directory, `Goal ${expected.goalId} init ${name}`);
    candidates.push({ name, directory });
  }
  assertControl(
    candidates.length <= 1,
    'PREPARED_STAGING_CONFLICT',
    `Goal ${expected.goalId} init 同时存在多个 prepared staging`,
  );
  if (candidates.length === 0) return null;
  const prepared = candidates[0];
  const rootEntries = fs.readdirSync(prepared.directory).sort();
  const capabilitiesDirectory = path.join(
    prepared.directory,
    'capabilities',
  );
  const sealed = hashObject(rootEntries) === hashObject([
    'capabilities',
    'goal.json',
    'init-receipt.json',
    'manifest.json',
  ]) && fs.existsSync(capabilitiesDirectory)
    && hashObject(fs.readdirSync(capabilitiesDirectory).sort())
      === hashObject(['bootstrap.cap', 'foreman-recovery.cap']);
  if (!sealed) return null;
  return readMechanicalP1InitBinding(
    prepared.directory,
    expected,
    paths.dir,
  );
}

function authorizePreparedGoalInitOddRecovery(
  paths,
  manifest,
  sourceManifestSha256,
  repositoryRoot,
  goalInputSource,
) {
  const expected = {
    goalId: manifest.goal_id,
    manifestSha256: manifest.manifest_sha256,
    sourceManifestSha256,
    repositoryRoot,
    goalInputSource,
  };
  if (fs.existsSync(paths.dir)) {
    return assertPublishedGoalInitInventory(
      paths,
      manifest,
      expected,
    );
  }
  const binding = discoverSealedMechanicalP1InitBinding(paths, expected);
  if (!binding) return false;
  const requestSha256 = hashObject({
    schema_version: 1,
    kind: 'GOAL_INIT_REQUEST',
    goal_id: manifest.goal_id,
    manifest_sha256: manifest.manifest_sha256,
    source_manifest_sha256: sourceManifestSha256,
    repository_root: repositoryRoot,
    goal_input_head: binding.goalInputHead,
    goal_input_source: binding.goalInputSource,
  });
  const candidates = protocolPreparedEntries(
    path.dirname(paths.dir),
    preparedStagingName(
      'goal',
      manifest.goal_id,
      requestSha256,
    ),
    /^\.init-goal-[0-9a-f]{64}-[0-9a-f]{64}$/,
    `Goal ${manifest.goal_id} init odd recovery`,
  );
  assertControl(
    candidates.length === 1,
    'STORE_REPAIR_REQUIRED',
    `Goal ${manifest.goal_id} init odd recovery 缺 exact sealed staging`,
  );
  return true;
}

function authorizeGoalInitPristineOddRecovery(paths, manifest) {
  if (fs.existsSync(paths.dir)) return false;
  const parent = path.dirname(paths.dir);
  if (!fs.existsSync(parent)) return true;
  const stablePrefix = `.init-goal-${sha256(manifest.goal_id)}-`;
  return !fs.readdirSync(parent).some((name) => (
    name.startsWith(stablePrefix)
  ));
}

function sealedMetadata(value) {
  const unsigned = { ...value };
  delete unsigned.meta_sha256;
  return { ...unsigned, meta_sha256: hashObject(unsigned) };
}

function publicProjection(source) {
  const value = JSON.parse(JSON.stringify(source));
  const redact = (candidate) => {
    if (Array.isArray(candidate)) {
      for (const item of candidate) redact(item);
      return;
    }
    if (!candidate || typeof candidate !== 'object') return;
    delete candidate.capability_file;
    delete candidate.capability_sha256;
    for (const nested of Object.values(candidate)) redact(nested);
  };
  redact(value);
  return value;
}

function publicSession(session) {
  return publicProjection(session);
}

function workerBootstrapWorktreeIdentity(worktree) {
  const canonicalWorktree = fs.realpathSync(worktree);
  return {
    worktree: canonicalWorktree,
    git_dir: fs.realpathSync(path.resolve(
      git(
        canonicalWorktree,
        ['rev-parse', '--path-format=absolute', '--absolute-git-dir'],
      ),
    )),
    common_git_dir: fs.realpathSync(path.resolve(
      git(
        canonicalWorktree,
        ['rev-parse', '--path-format=absolute', '--git-common-dir'],
      ),
    )),
    head: git(canonicalWorktree, ['rev-parse', 'HEAD']),
    branch: git(canonicalWorktree, ['branch', '--show-current']),
  };
}

function assertProjectedWorkerBootstrapIdentity(
  state,
  session,
  launch,
  worktree,
) {
  const identity = workerBootstrapWorktreeIdentity(worktree);
  const devSourceMayAdvance =
    session.role === 'DEV' && Boolean(session.worker_bootstrap);
  assertWorkerBootstrapLaunchBinding(
    session,
    launch,
    { allowHeadAdvance: devSourceMayAdvance },
  );
  assertWorkerBootstrapCurrentWorktree(
    session,
    identity,
    { allowHeadAdvance: devSourceMayAdvance },
  );
  if (devSourceMayAdvance && state.phase !== 'DEV_ACTIVE') {
    assertControl(
      identity.head === state.full_head,
      'STALE_HEAD',
      `phase=${state.phase} 的 DEV worker HEAD 必须冻结在控制面 full_head`,
    );
  }
  return identity;
}

function publicTaskState(state, actionProjection = null) {
  const value = publicProjection(state);
  if (actionProjection) {
    value.launch_scope = actionProjection.launch_scope;
    // Backward-compatible alias. Session operational_scope remains the
    // recovery capability scope; task launch_scope is the launch/action gate.
    value.operational_scope = actionProjection.launch_scope;
    value.next_actions = publicProjection(actionProjection.actions);
    value.maintenance_actions = publicProjection(actionProjection.maintenance_actions);
    value.pending_operations = publicProjection(actionProjection.pending_operations || []);
    if (actionProjection.launch_error_code) {
      value.launch_error_code = actionProjection.launch_error_code;
    }
  }
  return value;
}

function publicSnapshot(snapshot, paths = null, manifest = null, options = {}) {
  const value = JSON.parse(JSON.stringify(snapshot));
  for (const [taskId, state] of Object.entries(value.tasks || {})) {
    const manifestTask = manifest && manifest.tasks.find((task) => task.id === taskId);
    const projection = paths && manifestTask
      ? taskActionProjection(
        paths,
        snapshot.tasks[taskId],
        manifest.goal_id,
        manifestTask,
        {
          ...options,
          manifest,
          goalSnapshot: snapshot,
        },
      )
      : null;
    value.tasks[taskId] = publicTaskState(state, projection);
  }
  return value;
}

function assertCommittedGoalInputs(repositoryRoot, manifest) {
  const inputs = new Map([[manifest.source_manifest, 'manifest']]);
  for (const [name, protocol] of Object.entries(manifest.protocol || {})) {
    inputs.set(protocol.path, `protocol.${name}`);
  }
  for (const task of manifest.tasks) {
    inputs.set(task.packet.path, `${task.id}.packet`);
    if (task.p1) {
      inputs.set(task.p1.authority.path, `${task.id}.p1.authority`);
    }
  }
  for (const [relative, label] of inputs.entries()) {
    const currentFile = path.join(repositoryRoot, relative);
    let currentStat;
    try {
      currentStat = fs.lstatSync(currentFile);
    } catch (error) {
      throw new ControlError('GOAL_INPUT_NOT_COMMITTED', `${label} 当前文件不存在: ${relative} (${error.message})`);
    }
    assertControl(
      currentStat.isFile() && !currentStat.isSymbolicLink(),
      'GOAL_INPUT_SYMLINK',
      `${label} 必须是仓库内非 symlink 普通文件: ${relative}`,
    );
    let committed;
    try {
      const treeEntry = execFileSync('git', ['ls-tree', '-z', 'HEAD', '--', relative], {
        cwd: repositoryRoot,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: readOnlyGitEnvironment(),
      });
      assertControl(
        treeEntry.length > 0,
        'GOAL_INPUT_NOT_COMMITTED',
        `${label} 尚未进入当前 HEAD: ${relative}`,
      );
      assertControl(
        /^(100644|100755) blob [0-9a-f]{40}\t[^\0]+\0$/.test(treeEntry),
        'GOAL_INPUT_SYMLINK',
        `${label} 在当前 HEAD 中必须是普通 blob，禁止 symlink/submodule: ${relative}`,
      );
      committed = execFileSync('git', ['show', `HEAD:${relative}`], {
        cwd: repositoryRoot,
        encoding: null,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: readOnlyGitEnvironment(),
      });
    } catch (error) {
      if (error instanceof ControlError) throw error;
      throw new ControlError(
        'GOAL_INPUT_NOT_COMMITTED',
        `${label} 尚未进入当前 HEAD: ${relative}${error.stderr ? ` (${String(error.stderr).trim()})` : ''}`,
      );
    }
    const current = fs.readFileSync(currentFile);
    assertControl(
      sha256(committed) === sha256(current),
      'GOAL_INPUT_DIRTY',
      `${label} 与当前 HEAD 中的 Git blob 不一致: ${relative}`,
    );
  }
}

function initializeGoal(cwd, manifestFile) {
  const repositoryRoot = repoRoot(cwd);
  const repositoryCommonRoot = path.dirname(path.resolve(git(repositoryRoot, ['rev-parse', '--path-format=absolute', '--git-common-dir'])));
  const absoluteManifest = path.resolve(cwd, manifestFile);
  const manifest = validateManifest(readJson(absoluteManifest, 'Goal manifest'), absoluteManifest, repositoryRoot);
  const sourceManifestSha256 = hashFile(absoluteManifest);
  assertCommittedGoalInputs(repositoryRoot, manifest);
  verifyPreclaimReceipt(cwd, manifest, absoluteManifest);
  const mechanicalP1Enabled = manifest.tasks.some((task) => Boolean(task.p1));
  const configuredGoalInputSource = mechanicalP1Enabled
    ? `refs/remotes/origin/${manifest.repository.base_branch}`
    : null;
  const root = controlRoot(cwd);
  const paths = goalPaths(root, manifest.goal_id);
  let oddRecoveryAuthorized = false;
  let pristineOddRecoveryAuthorized = false;
  let publishedGoalInitRecovery = false;
  const result = withLock(root, () => {
    let manifestExists = fs.existsSync(paths.manifest);
    let metaExists = fs.existsSync(paths.meta);
    assertControl(manifestExists === metaExists, 'CORRUPT_STORE', `Goal ${manifest.goal_id} 处于半初始化状态`);
    if (manifestExists) {
      const existing = readJson(paths.manifest, '已初始化 manifest');
      assertControl(existing.manifest_sha256 === manifest.manifest_sha256, 'GOAL_ALREADY_INITIALIZED', `Goal ${manifest.goal_id} 已用不同 manifest 初始化`);
      if (publishedGoalInitRecovery) {
        discardPublishedGoalInitDerived(paths);
      }
    }
    let goalInputHead = null;
    let goalInputSource = configuredGoalInputSource;
    if (mechanicalP1Enabled) {
      const expectedBinding = {
        goalId: manifest.goal_id,
        manifestSha256: manifest.manifest_sha256,
        sourceManifestSha256,
        repositoryRoot: repositoryCommonRoot,
        goalInputSource: configuredGoalInputSource,
      };
      const sealedBinding = manifestExists
        ? readMechanicalP1InitBinding(paths.dir, expectedBinding)
        : discoverSealedMechanicalP1InitBinding(paths, expectedBinding);
      if (sealedBinding) {
        goalInputHead = sealedBinding.goalInputHead;
        goalInputSource = sealedBinding.goalInputSource;
      } else {
        const currentBranch = git(repositoryRoot, ['branch', '--show-current']);
        assertControl(
          currentBranch === manifest.repository.base_branch,
          'P1_INIT_BRANCH_MISMATCH',
          `机械 P1 Goal 必须从 ${manifest.repository.base_branch} branch init，当前为 ${currentBranch || 'DETACHED'}`,
        );
        assertControl(
          git(repositoryRoot, ['status', '--porcelain=v1', '--untracked-files=all']) === '',
          'P1_INIT_WORKTREE_DIRTY',
          '机械 P1 Goal init 要求 clean worktree',
        );
        goalInputHead = git(repositoryRoot, ['rev-parse', 'HEAD']);
        const remoteMainHead = git(repositoryRoot, ['rev-parse', goalInputSource]);
        assertControl(
          goalInputHead === remoteMainHead,
          'P1_INIT_REMOTE_MAIN_MISMATCH',
          `机械 P1 Goal init HEAD 必须等于 ${goalInputSource}`,
        );
      }
      assertFullSha(goalInputHead, 'goal_input_head');
    }
    const initRequestSha256 = hashObject({
      schema_version: 1,
      kind: 'GOAL_INIT_REQUEST',
      goal_id: manifest.goal_id,
      manifest_sha256: manifest.manifest_sha256,
      source_manifest_sha256: sourceManifestSha256,
      repository_root: repositoryCommonRoot,
      ...(goalInputHead ? { goal_input_head: goalInputHead } : {}),
      ...(goalInputSource ? { goal_input_source: goalInputSource } : {}),
    });
    if (!manifestExists) {
      // A post-rename crash must not turn this fresh root into an unsealed
      // "legacy" root that the exact retry can no longer open.
      ensureRootProtocol(root);
      ensureDir(path.dirname(paths.dir));
    }
    recoverPreparedGoalInit(paths, initRequestSha256, {
      goalId: manifest.goal_id,
      manifestSha256: manifest.manifest_sha256,
      sourceManifestSha256,
      repositoryRoot: repositoryCommonRoot,
      ...(goalInputHead ? { goalInputHead } : {}),
      ...(goalInputSource ? { goalInputSource } : {}),
    });
    manifestExists = fs.existsSync(paths.manifest);
    metaExists = fs.existsSync(paths.meta);
    assertControl(manifestExists === metaExists, 'CORRUPT_STORE', `Goal ${manifest.goal_id} 处于半初始化状态`);
    if (manifestExists) {
      const loaded = loadGoalStateUnlocked(root, manifest.goal_id);
      if (!fs.existsSync(path.join(paths.dir, 'init-receipt.json'))) {
        assertControl(
          loaded.meta.init_receipt_schema_version === undefined,
          'INIT_RECEIPT_MISSING',
          `Goal ${manifest.goal_id} 的 receipt-required metadata 已存在，但 init receipt 缺失`,
        );
        const bootstrapConsumed = !fs.existsSync(loaded.meta.bootstrap_capability_file);
        const bootstrapLineage = goalBootstrapForemanLineage(root, loaded);
        assertControl(
          !bootstrapConsumed || bootstrapLineage.length === 1,
          'INIT_LEGACY_ADOPTION_REJECTED',
          'legacy Goal bootstrap 已缺失，但没有唯一 append-only BOOTSTRAP FOREMAN lineage',
        );
        adoptLegacyInitReceipt(paths.dir, {
          goalId: manifest.goal_id,
          manifestSha256: manifest.manifest_sha256,
          sourceManifestSha256,
          repositoryRoot: repositoryCommonRoot,
          bootstrapConsumed,
          bootstrapLineageSha256: bootstrapConsumed ? hashObject(bootstrapLineage[0]) : null,
          recordedAt: nowIso(),
        });
      }
      const receipt = readAndVerifyInitReceipt(paths.dir, {
        goalId: manifest.goal_id,
        manifestSha256: manifest.manifest_sha256,
        sourceManifestSha256,
        repositoryRoot: repositoryCommonRoot,
        ...(goalInputHead ? { goalInputHead } : {}),
        ...(goalInputSource ? { goalInputSource } : {}),
      });
      if (loaded.meta.init_receipt_schema_version === undefined) {
        finalizeLegacyInitReceiptMetadata(paths.dir, {
          receiptSha256: receipt.receipt_sha256,
          recordedAt: receipt.receipt_publication_recorded_at,
          legacySourceSha256: receipt.legacy_source_sha256,
        });
      }
      let rebuilt = null;
      let cacheDegraded = false;
      try {
        rebuilt = rebuildAndWriteUnlocked(root, manifest.goal_id);
      } catch {
        cacheDegraded = true;
      }
      return {
        goal_id: manifest.goal_id,
        initialized: false,
        idempotent: true,
        init_receipt_adopted: receipt.receipt_publication === 'LOCKED_LEGACY_ADOPTION',
        ...receipt,
        cache_degraded: cacheDegraded,
        state: publicSnapshot(rebuilt || loaded.snapshot),
      };
    }
    const initParent = path.dirname(paths.dir);
    const temporaryGoalDir = path.join(
      initParent,
      preparedStagingName(
        'goal',
        manifest.goal_id,
        initRequestSha256,
      ),
    );
    assertControl(
      !fs.existsSync(temporaryGoalDir),
      'PREPARED_STAGING_CONFLICT',
      `Goal ${manifest.goal_id} init staging 已存在`,
    );
    fs.mkdirSync(temporaryGoalDir, { mode: 0o700 });
    ensurePrivateDirectory(temporaryGoalDir, { repair: true });
    const temporaryCapabilitiesDir = path.join(temporaryGoalDir, 'capabilities');
    fs.mkdirSync(temporaryCapabilitiesDir, { mode: 0o700 });
    ensurePrivateDirectory(temporaryCapabilitiesDir, { repair: true });
    maybeInjectRecoveryBatchFault(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_INIT_CAPABILITIES_DIRECTORY',
      'TEST_FAULT_AFTER_INIT_CAPABILITIES_DIRECTORY',
      'injected failure after private init capabilities directory creation',
    );
    const finalBootstrapFile = path.join(paths.dir, 'capabilities', 'bootstrap.cap');
    const finalForemanRecoveryFile = path.join(paths.dir, 'capabilities', 'foreman-recovery.cap');
    const initializedAt = nowIso();
    let receipt;
    try {
      const bootstrap = createCapabilityFile(temporaryCapabilitiesDir, 'bootstrap');
      const temporaryBootstrapFile = bootstrap.file;
      fs.renameSync(temporaryBootstrapFile, path.join(temporaryCapabilitiesDir, 'bootstrap.cap'));
      const foremanRecovery = createCapabilityFile(temporaryCapabilitiesDir, 'foreman-recovery');
      fs.renameSync(foremanRecovery.file, path.join(temporaryCapabilitiesDir, 'foreman-recovery.cap'));
      fsyncDirectory(temporaryCapabilitiesDir);
      atomicWriteJson(path.join(temporaryGoalDir, 'manifest.json'), manifest);
      receipt = writeInitReceipt(temporaryGoalDir, {
        schema_version: 1,
        goal_id: manifest.goal_id,
        manifest_sha256: manifest.manifest_sha256,
        source_manifest_sha256: sourceManifestSha256,
        repository_root: repositoryCommonRoot,
        ...(goalInputHead ? { goal_input_head: goalInputHead } : {}),
        ...(goalInputSource ? { goal_input_source: goalInputSource } : {}),
        initialized_at: initializedAt,
        bootstrap_capability_file: finalBootstrapFile,
        bootstrap_capability_sha256: bootstrap.sha256,
        foreman_recovery_capability_file: finalForemanRecoveryFile,
        foreman_recovery_capability_sha256: foremanRecovery.sha256,
        publication_kind: 'ATOMIC_DIRECTORY_RENAME',
        publication_recorded_at: initializedAt,
        legacy_source_sha256: null,
      });
      atomicWriteJson(path.join(temporaryGoalDir, 'goal.json'), sealedMetadata({
        schema_version: 1,
        goal_id: manifest.goal_id,
        mode: manifest.mode,
        control_epoch: 0,
        initialized_at: initializedAt,
        repository_root: repositoryCommonRoot,
        ...(goalInputHead ? { goal_input_head: goalInputHead } : {}),
        ...(goalInputSource ? { goal_input_source: goalInputSource } : {}),
        bootstrap_capability_file: finalBootstrapFile,
        bootstrap_capability_sha256: bootstrap.sha256,
        foreman_recovery_capability_file: finalForemanRecoveryFile,
        foreman_recovery_capability_sha256: foremanRecovery.sha256,
        init_receipt_schema_version: 1,
        init_receipt_sha256: receipt.receipt.receipt_sha256,
      }));
      fsyncDirectory(temporaryGoalDir);
      maybeInjectRecoveryBatchFault(
        cwd,
        'GOAL_CONTROL_TEST_FAULT_AFTER_INIT_STAGING',
        'TEST_FAULT_AFTER_INIT_STAGING',
        'injected failure after complete init staging before atomic publish',
      );
      fs.renameSync(temporaryGoalDir, paths.dir);
      fsyncDirectory(path.dirname(paths.dir));
      maybeInjectPostPublishFault(root);
    } catch (error) {
      // Never recursively sweep a prepared tree. Exact retry will either
      // validate+promote a sealed tree or strictly inventory an unsealed one.
      throw error;
    }
    const verifiedReceipt = readAndVerifyInitReceipt(paths.dir, {
      goalId: manifest.goal_id,
      manifestSha256: manifest.manifest_sha256,
      sourceManifestSha256,
      repositoryRoot: repositoryCommonRoot,
      ...(goalInputHead ? { goalInputHead } : {}),
      ...(goalInputSource ? { goalInputSource } : {}),
    });
    assertControl(
      verifiedReceipt.receipt_sha256 === receipt.receipt.receipt_sha256,
      'INIT_RECEIPT_TAMPERED',
      'published init receipt 与 staged receipt 不一致',
    );
    let snapshot;
    let cache_degraded = false;
    try {
      snapshot = rebuildAndWriteUnlocked(root, manifest.goal_id);
    } catch {
      cache_degraded = true;
    }
    return {
      goal_id: manifest.goal_id,
      initialized: true,
      idempotent: false,
      ...verifiedReceipt,
      cache_degraded,
      state: snapshot ? publicSnapshot(snapshot) : null,
    };
  }, {
    transactionKey: () => goalInitTransactionKey(
      manifest,
      sourceManifestSha256,
      repositoryCommonRoot,
      configuredGoalInputSource,
    ),
    sameStableOperationMismatchCode: 'PREPARED_REQUEST_MISMATCH',
    sameStableOperationMismatchMessage:
      'Goal init stable operation 已绑定不同 prepared request',
    beforeGeneration: () => {
      oddRecoveryAuthorized = false;
      pristineOddRecoveryAuthorized = false;
      publishedGoalInitRecovery = false;
      if (readSealedRootGenerationParity(root) !== 'ODD') return;
      oddRecoveryAuthorized = mechanicalP1Enabled
        ? authorizePreparedGoalInitOddRecovery(
          paths,
          manifest,
          sourceManifestSha256,
          repositoryCommonRoot,
          configuredGoalInputSource,
        )
        : authorizeCoreGoalInitOddRecovery(
          paths,
          manifest,
          sourceManifestSha256,
          repositoryCommonRoot,
        );
      publishedGoalInitRecovery =
        oddRecoveryAuthorized && fs.existsSync(paths.dir);
      if (
        !oddRecoveryAuthorized
      ) {
        pristineOddRecoveryAuthorized =
          authorizeGoalInitPristineOddRecovery(paths, manifest);
      }
    },
    authorizeOddRecovery: () => oddRecoveryAuthorized,
    authorizePristineOddRecovery: () => pristineOddRecoveryAuthorized,
    afterGenerationBeforeCallback: generationBoundaryFaultHook(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_INIT_GENERATION',
    ),
  });
  maybeExitAfterInitCommit(root);
  return result;
}

function loadGoalFiles(root, goalId, options = {}) {
  safeId(goalId, 'goal_id');
  const paths = goalPaths(root, goalId);
  assertControl(fs.existsSync(paths.manifest) && fs.existsSync(paths.meta), 'GOAL_NOT_INITIALIZED', `Goal ${goalId} 尚未 init`);
  const manifest = readJson(paths.manifest, 'control manifest');
  const manifestHash = manifest.manifest_sha256;
  const unsignedManifest = { ...manifest };
  delete unsignedManifest.manifest_sha256;
  assertControl(hashObject(unsignedManifest) === manifestHash, 'CORRUPT_STORE', 'control manifest hash 不匹配');
  const meta = readJson(paths.meta, 'goal metadata');
  assertControl(meta.goal_id === goalId && meta.schema_version === 1, 'CORRUPT_STORE', 'goal metadata 身份不匹配');
  const unsignedMeta = { ...meta };
  delete unsignedMeta.meta_sha256;
  assertControl(hashObject(unsignedMeta) === meta.meta_sha256, 'CORRUPT_STORE', 'goal metadata hash 不匹配');
  assertControl(meta.mode === manifest.mode && path.resolve(meta.repository_root) === path.resolve(path.dirname(path.resolve(git(meta.repository_root, ['rev-parse', '--path-format=absolute', '--git-common-dir'])))), 'CORRUPT_STORE', 'goal metadata repository/mode 不匹配');
  const mechanicalP1Enabled = manifest.tasks.some((task) => Boolean(task.p1));
  if (mechanicalP1Enabled) {
    assertControl(
      typeof meta.goal_input_head === 'string' && /^[0-9a-f]{40}$/.test(meta.goal_input_head),
      'CORRUPT_STORE',
      '机械 P1 Goal 缺 sealed goal_input_head',
    );
    assertControl(
      meta.goal_input_source
        === `refs/remotes/origin/${manifest.repository.base_branch}`,
      'CORRUPT_STORE',
      '机械 P1 Goal 的 sealed goal_input_source 非法',
    );
    git(meta.repository_root, ['cat-file', '-e', `${meta.goal_input_head}^{commit}`]);
  } else {
    assertControl(
      meta.goal_input_head === undefined
        && meta.goal_input_source === undefined,
      'CORRUPT_STORE',
      'legacy Goal 不得注入 goal_input_head',
    );
  }
  assertControl(meta.control_epoch === 0, 'CORRUPT_STORE', 'goal metadata 的初始 control_epoch 被改写');
  const control = loadControlState(paths, goalId, options);
  return {
    paths,
    manifest,
    meta,
    control,
  };
}

function loadControlState(paths, goalId, options = {}) {
  const files = fs.existsSync(paths.controlEvents)
    ? fs.readdirSync(paths.controlEvents).filter((name) => name.endsWith('.json')).sort()
    : [];
  let previousHash = null;
  let epoch = 0;
  let lastEvent = null;
  const events = [];
  for (let index = 0; index < files.length; index += 1) {
    const expectedEpoch = index + 1;
    const file = path.join(paths.controlEvents, files[index]);
    assertControl(files[index] === `${String(expectedEpoch).padStart(8, '0')}.json`, 'CORRUPT_STORE', `control event 序号缺口: ${files[index]}`);
    const event = readJson(file, `control event ${files[index]}`);
    const allowed = ['schema_version', 'event_id', 'goal_id', 'from_epoch', 'to_epoch', 'expected_epoch', 'reason', 'instruction_ref', 'actor', 'accepted_at', 'log_sequence', 'previous_event_sha256', 'event_sha256'];
    assertControl(Object.keys(event).every((key) => allowed.includes(key)), 'CORRUPT_STORE', `control event ${event.event_id} 含未知字段`);
    assertControl(event.schema_version === 1 && event.goal_id === goalId, 'CORRUPT_STORE', 'control event 身份不匹配');
    assertControl(event.from_epoch === epoch && event.expected_epoch === epoch && event.to_epoch === expectedEpoch, 'CORRUPT_STORE', `control event ${event.event_id} epoch 链断裂`);
    assertControl(event.log_sequence === expectedEpoch && event.previous_event_sha256 === previousHash, 'CORRUPT_STORE', `control event ${event.event_id} hash 链断裂`);
    const unsigned = { ...event };
    delete unsigned.event_sha256;
    assertControl(hashObject(unsigned) === event.event_sha256, 'CORRUPT_STORE', `control event ${event.event_id} hash 不匹配`);
    assertControl(typeof event.reason === 'string' && event.reason.trim().length > 0, 'CORRUPT_STORE', `control event ${event.event_id} 缺 reason`);
    assertControl(event.actor && event.actor.role === 'FOREMAN' && event.actor.thread_id, 'CORRUPT_STORE', `control event ${event.event_id} actor 非法`);
    previousHash = event.event_sha256;
    epoch = event.to_epoch;
    lastEvent = event;
    events.push(event);
  }
  const head = readJsonIfExists(paths.controlHead, null);
  if (head) {
    const allowedHeadKeys = ['schema_version', 'goal_id', 'event_count', 'control_epoch', 'last_event_sha256', 'updated_at', 'head_sha256'];
    assertControl(Object.keys(head).length === allowedHeadKeys.length && Object.keys(head).every((key) => allowedHeadKeys.includes(key)), 'CORRUPT_STORE', 'control head 字段非法');
    const unsignedHead = { ...head };
    delete unsignedHead.head_sha256;
    assertControl(hashObject(unsignedHead) === head.head_sha256, 'CORRUPT_STORE', 'control head hash 不匹配');
    assertControl(head.schema_version === 1 && head.goal_id === goalId && head.control_epoch === head.event_count, 'CORRUPT_STORE', 'control head 身份非法');
    assertControl(Number.isSafeInteger(head.event_count) && head.event_count <= files.length, 'CORRUPT_STORE', 'control event tail 被删除');
    const anchoredHash = head.event_count === 0 ? null : events[head.event_count - 1].event_sha256;
    assertControl(head.last_event_sha256 === anchoredHash, 'CORRUPT_STORE', 'control head anchor 不匹配');
  } else {
    assertControl(files.length === 0, 'CORRUPT_STORE', 'control head 缺失，无法证明 tail 完整');
  }
  if (!head || head.event_count < files.length) {
    if (options.repairHeads === false) {
      assertControl(
        options.allowLaggingHeads === true
          || (!head && files.length === 0),
        'STORE_REPAIR_REQUIRED',
        `control head 落后 event tail；须由写权限控制角色运行 repair/rebuild`,
      );
    } else {
      atomicWriteJson(paths.controlHead, sealedEventHead({
        schema_version: 1,
        goal_id: goalId,
        event_count: files.length,
        control_epoch: epoch,
        last_event_sha256: previousHash,
        updated_at: lastEvent ? lastEvent.accepted_at : nowIso(),
      }));
    }
  }
  return { epoch, lastEventHash: previousHash, lastEvent, eventCount: files.length, events };
}

function validateStoredP1CommitTransaction(raw) {
  const marker = raw.p1_commit_transaction;
  if (!marker) return null;
  const allowed = [
    'schema_version',
    'kind',
    'goal_id',
    'task_id',
    'task_cycle',
    'event_id',
    'request_sha256',
    'intent_sha256',
    'commit_ref',
    'commit_sha',
    'bundle_sha256',
  ];
  assertControl(
    raw.type === 'P1_COMMITTED'
      && marker
      && typeof marker === 'object'
      && !Array.isArray(marker)
      && Object.keys(marker).length === allowed.length
      && Object.keys(marker).every((key) => allowed.includes(key))
      && marker.schema_version === 1
      && marker.kind === 'P1_COMMIT_REF_TRANSACTION'
      && marker.goal_id === raw.goal_id
      && marker.task_id === raw.task_id
      && marker.event_id === raw.event_id
      && Number.isSafeInteger(marker.task_cycle)
      && marker.task_cycle > 0
      && /^sha256:[0-9a-f]{64}$/.test(marker.request_sha256)
      && /^sha256:[0-9a-f]{64}$/.test(marker.intent_sha256)
      && /^sha256:[0-9a-f]{64}$/.test(marker.bundle_sha256)
      && typeof marker.commit_ref === 'string'
      && marker.commit_ref.startsWith('refs/heads/codex/goal-control/p1/')
      && /^[0-9a-f]{40}$/.test(marker.commit_sha)
      && marker.request_sha256 === raw.input_sha256
      && marker.commit_ref === raw.payload.p1_commit_ref
      && marker.commit_sha === raw.full_head,
    'CORRUPT_STORE',
    `event ${raw.event_id} P1 transaction marker 非法`,
  );
  return JSON.parse(JSON.stringify(marker));
}

function loadTaskEvents(root, goalId, taskId, options = {}) {
  const files = acceptedEventFiles(root, goalId, taskId);
  const events = [];
  let previousEventHash = null;
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    const expectedSequence = index + 1;
    assertControl(path.basename(file).startsWith(`${String(expectedSequence).padStart(8, '0')}-`), 'CORRUPT_STORE', `event log 序号缺口: ${path.basename(file)}`);
    const raw = readJson(file, `event ${path.basename(file)}`);
    const allowedStoredKeys = ['schema_version', 'event_id', 'goal_id', 'task_id', 'type', 'actor', 'actor_sequence', 'expected_state_revision', 'control_epoch', 'packet', 'base_head', 'full_head', 'payload', 'input_sha256', 'evidence_registry_sha256', 'accepted_at', 'log_sequence', 'previous_event_sha256', 'event_sha256', 'goal_foreman_authority', 'goal_foreman_coauthority', 'p1_commit_transaction', 'prepared_identity_incident_authority'];
    const unknown = Object.keys(raw).filter((key) => !allowedStoredKeys.includes(key));
    assertControl(unknown.length === 0, 'CORRUPT_STORE', `accepted event 含未知字段: ${unknown.join(', ')}`);
    assertControl(raw.log_sequence === expectedSequence, 'CORRUPT_STORE', `event log_sequence 应为 ${expectedSequence}`);
    assertControl(raw.previous_event_sha256 === previousEventHash, 'CORRUPT_STORE', `event ${raw.event_id} hash chain 断裂`);
    assertControl(typeof raw.accepted_at === 'string' && Number.isFinite(Date.parse(raw.accepted_at)), 'CORRUPT_STORE', `event ${raw.event_id} accepted_at 非法`);
    const unsigned = { ...raw };
    delete unsigned.event_sha256;
    assertControl(hashObject(unsigned) === raw.event_sha256, 'CORRUPT_STORE', `event ${raw.event_id} 内容 hash 不匹配`);
    const envelope = {};
    for (const key of allowedStoredKeys.slice(0, 13)) envelope[key] = raw[key];
    const normalized = validateEvent(envelope);
    assertControl(hashObject(normalized) === raw.input_sha256, 'CORRUPT_STORE', `event ${raw.event_id} input hash 不匹配`);
    const p1CommitTransaction = validateStoredP1CommitTransaction(raw);
    const preparedIdentityIncidentAuthority =
      raw.prepared_identity_incident_authority;
    if (preparedIdentityIncidentAuthority !== undefined) {
      assertControl(
        raw.type === 'ADD_HOLD'
          && raw.payload
          && raw.payload.kind === 'ENV_IDENTITY_INCIDENT'
          && Object.keys(preparedIdentityIncidentAuthority).length === 3
          && preparedIdentityIncidentAuthority.schema_version === 1
          && preparedIdentityIncidentAuthority.evidence_id
            === raw.payload.evidence_id
          && /^sha256:[0-9a-f]{64}$/.test(
            preparedIdentityIncidentAuthority.authority_sha256,
          ),
        'CORRUPT_STORE',
        `event ${raw.event_id} prepared identity incident marker 非法`,
      );
    }
    events.push({
      ...normalized,
      input_sha256: raw.input_sha256,
      ...(raw.evidence_registry_sha256 ? { evidence_registry_sha256: raw.evidence_registry_sha256 } : {}),
      ...(raw.goal_foreman_authority ? { goal_foreman_authority: raw.goal_foreman_authority } : {}),
      ...(raw.goal_foreman_coauthority ? { goal_foreman_coauthority: raw.goal_foreman_coauthority } : {}),
      ...(p1CommitTransaction
        ? { p1_commit_transaction: p1CommitTransaction }
        : {}),
      ...(preparedIdentityIncidentAuthority
        ? {
          prepared_identity_incident_authority:
            JSON.parse(JSON.stringify(preparedIdentityIncidentAuthority)),
        }
        : {}),
      accepted_at: raw.accepted_at,
      log_sequence: raw.log_sequence,
      previous_event_sha256: raw.previous_event_sha256,
      event_sha256: raw.event_sha256,
    });
    previousEventHash = raw.event_sha256;
  }
  const headFile = eventHeadFile(root, goalId, taskId);
  const head = readJsonIfExists(headFile, null);
  if (head) {
    const allowedHeadKeys = ['schema_version', 'task_id', 'event_count', 'state_revision', 'last_event_sha256', 'updated_at', 'head_sha256'];
    assertControl(Object.keys(head).length === allowedHeadKeys.length && Object.keys(head).every((key) => allowedHeadKeys.includes(key)), 'CORRUPT_STORE', `task ${taskId} event head 字段非法`);
    const unsignedHead = { ...head };
    delete unsignedHead.head_sha256;
    assertControl(hashObject(unsignedHead) === head.head_sha256, 'CORRUPT_STORE', `task ${taskId} event head hash 不匹配`);
    assertControl(head.schema_version === 1 && head.task_id === taskId && head.state_revision === head.event_count, 'CORRUPT_STORE', `task ${taskId} event head 身份非法`);
    assertControl(Number.isSafeInteger(head.event_count) && head.event_count <= events.length, 'CORRUPT_STORE', `task ${taskId} event tail 被删除`);
    const anchoredHash = head.event_count === 0 ? null : events[head.event_count - 1].event_sha256;
    assertControl(head.last_event_sha256 === anchoredHash, 'CORRUPT_STORE', `task ${taskId} event head anchor 不匹配`);
  } else {
    assertControl(events.length === 0, 'CORRUPT_STORE', `task ${taskId} event head 缺失，无法证明 tail 完整`);
  }
  if (!head || head.event_count < events.length) {
    if (options.repairHeads === false) {
      assertControl(
        options.allowLaggingHeads === true
          || (!head && events.length === 0),
        'STORE_REPAIR_REQUIRED',
        `task ${taskId} event head 落后 event tail；须由写权限控制角色运行 repair/rebuild`,
      );
    } else {
      atomicWriteJson(headFile, sealedEventHead({
        schema_version: 1,
        task_id: taskId,
        event_count: events.length,
        state_revision: events.length,
        last_event_sha256: previousEventHash,
        updated_at: events.length ? events[events.length - 1].accepted_at : nowIso(),
      }));
    }
  }
  return events;
}

function rebuildTask(root, manifest, control, task, options = {}) {
  let state = initialTaskState(task, manifest);
  const eventIds = new Map();
  for (const event of loadTaskEvents(root, manifest.goal_id, task.id, options)) {
    assertControl(!eventIds.has(event.event_id), 'CORRUPT_STORE', `event id 重复: ${event.event_id}`);
    eventIds.set(event.event_id, event.input_sha256 || hashObject(event));
    if (event.control_epoch > state.last_reconciled_epoch) {
      const controlEvent = control.events[event.control_epoch - 1];
      assertControl(controlEvent, 'CORRUPT_STORE', `task event 引用了不存在的 control epoch ${event.control_epoch}`);
      state.control_epoch = event.control_epoch;
      state.reconcile_required = {
        from_epoch: state.last_reconciled_epoch,
        to_epoch: event.control_epoch,
        control_event_id: controlEvent.event_id,
        reason: controlEvent.reason,
      };
    }
    if (event.type === 'RECOVERY_HANDOFF_BOUND') {
      const { verifyAcceptedRecoveryHandoffArtifacts } = require('./source-handoff');
      verifyAcceptedRecoveryHandoffArtifacts(root, {
        goalId: manifest.goal_id,
        taskId: task.id,
        payload: event.payload,
        eventId: event.event_id,
        eventInputSha256: event.input_sha256,
        eventSha256: event.event_sha256,
        eventAcceptedAt: event.accepted_at,
        eventPayloadSha256: hashObject(event.payload),
        legacyRecoveryHandoffBindingCollector:
          options.legacyRecoveryHandoffBindingCollector,
        legacyRecoveryHandoffRepositoryWorktree:
          options.legacyRecoveryHandoffRepositoryWorktree,
      });
    }
    if (
      event.type === 'MERGED'
        && manifest.repository.merge_policy === 'goalctl-github-squash-v1'
    ) {
      const {
        verifyAcceptedMergeReceipt,
      } = require('./github-merge');
      verifyAcceptedMergeReceipt(root, {
        manifest,
        snapshot: { tasks: { [task.id]: state } },
        control,
        lastEventHashes: { [task.id]: state.last_event && state.last_event.event_sha256 },
      }, state, event);
    }
    const prepared = resolveEventEvidence(
      root,
      manifest.goal_id,
      state,
      event,
      task,
      {
        readOnly: options.repairHeads === false,
        acceptedReplay: true,
        verifyAcceptedBinding: true,
        legacyEvidenceBindingCollector: options.legacyEvidenceBindingCollector,
        legacyIdentityIncidentCollector:
          options.legacyIdentityIncidentCollector,
      },
    );
    state = applyEvent(state, prepared, event.control_epoch);
    state.last_event.event_sha256 = event.event_sha256;
  }
  state.control_epoch = control.epoch;
  const terminalTask = ['MERGED_TO_MAIN', 'ARCHIVED'].includes(state.phase);
  state.reconcile_required = !terminalTask && state.last_reconciled_epoch < control.epoch
    ? {
      from_epoch: state.last_reconciled_epoch,
      to_epoch: control.epoch,
      control_event_id: control.lastEvent && control.lastEvent.event_id,
      reason: control.lastEvent && control.lastEvent.reason,
    }
    : null;
  return { state, eventIds, lastEventHash: state.last_event && state.last_event.event_sha256 };
}

function buildSnapshot(root, manifest, control, options = {}) {
  const tasks = {};
  const eventIndexes = {};
  const lastEventHashes = {};
  for (const task of manifest.tasks) {
    const rebuilt = rebuildTask(root, manifest, control, task, options);
    tasks[task.id] = rebuilt.state;
    eventIndexes[task.id] = rebuilt.eventIds;
    lastEventHashes[task.id] = rebuilt.lastEventHash;
  }
  return {
    snapshot: {
      schema_version: 1,
      goal_id: manifest.goal_id,
      manifest_sha256: manifest.manifest_sha256,
      control_epoch: control.epoch,
      mode: manifest.mode,
      generated_at: nowIso(),
      tasks,
    },
    eventIndexes,
    lastEventHashes,
  };
}

function buildLedgerProjection(paths, manifest, snapshot, options = {}) {
  return {
    schema_version: 1,
    goal_id: snapshot.goal_id,
    manifest_sha256: snapshot.manifest_sha256,
    control_epoch: snapshot.control_epoch,
    generated_at: snapshot.generated_at,
    tasks: manifest.tasks.map((task) => {
      const projection = taskActionProjection(
        paths,
        snapshot.tasks[task.id],
        manifest.goal_id,
        task,
        {
          ...options,
          manifest,
          goalSnapshot: snapshot,
        },
      );
      return taskLedgerRow(task, snapshot.tasks[task.id], projection.actions, projection.launch_scope);
    }),
  };
}

function writeProjections(paths, manifest, snapshot) {
  atomicWriteJson(paths.state, snapshot);
  const ledger = buildLedgerProjection(paths, manifest, snapshot);
  atomicWriteJson(paths.ledgerJson, ledger);
  atomicWrite(paths.ledgerMarkdown, renderMarkdown(ledger));
  return ledger;
}

function rebuildAndWriteUnlocked(root, goalId) {
  const { paths, manifest, control } = loadGoalFiles(root, goalId);
  const { snapshot } = buildSnapshot(root, manifest, control);
  const ledger = writeProjections(paths, manifest, snapshot);
  return { ...snapshot, ledger };
}

function loadGoalStateUnlocked(root, goalId, options = {}) {
  const { paths, manifest, meta, control } = loadGoalFiles(root, goalId, options);
  const { snapshot, eventIndexes, lastEventHashes } = buildSnapshot(root, manifest, control, options);
  const bootstrapConsumption = reconcileBootstrapConsumption(
    root,
    {
      paths,
      manifest,
      meta,
      control,
      snapshot,
    },
    { repair: options.repairBootstrapConsumption !== false },
  );
  if (options.requireBootstrapConsumptionReconciled === true) {
    assertControl(
      bootstrapConsumption.reconciliation_required === false,
      'STORE_PROTOCOL_MIGRATION_REPAIR_REQUIRED',
      'BOOTSTRAP consumption marker/capability 尚待 audited repair；protocol migration/rotation 只允许零写入 replay',
    );
  }
  const preparedProbe = options.allowPreparedGoalOperationProbe || null;
  const pendingForemanRecoveryBatches = pendingRecoveryBatches(
    paths,
    goalId,
    {
      includePreparedStaging:
        preparedProbe !== 'FOREMAN_RECOVERY_BATCH',
    },
  );
  if (pendingForemanRecoveryBatches.length > 0 && options.allowIncompleteRecoveryRead !== true) {
    const pendingRecovery = pendingForemanRecoveryBatches[0];
    assertControl(
      options.allowPendingRecoveryId === pendingRecovery.root_recovery_id
        && options.allowPendingRecoveryRequestSha256
          === pendingRecovery.intent.request_sha256,
      'RECOVERY_BATCH_INCOMPLETE',
      `Goal 有未完成 FOREMAN recovery batch ${pendingRecovery.root_recovery_id}；只允许 exact retry`,
    );
  }
  let pendingGoalOperations = [];
  if (preparedProbe === 'REGISTRATION') {
    pendingGoalOperations = pendingCanonicalRegistrationIntents(
      root,
      paths,
      goalId,
    ).map((intent) => ({
      kind: 'REGISTRATION',
      operation_id: intent.event_id,
      request_sha256: intent.request_sha256,
    }));
  } else if (preparedProbe === 'FOREMAN_RECOVERY_BATCH') {
    const {
      listPendingGoalRegistrationIntents,
    } = require('./pending-operations');
    pendingGoalOperations = listPendingGoalRegistrationIntents(
      root,
      goalId,
    ).map((intent) => ({
      kind: 'REGISTRATION',
      operation_id: intent.event_id,
      request_sha256: intent.request_sha256,
    }));
  } else {
    const {
      listPendingGoalOperations,
    } = require('./pending-operations');
    pendingGoalOperations = listPendingGoalOperations(root, goalId)
      .filter((operation) => operation.kind !== 'FOREMAN_RECOVERY_BATCH');
  }
  if (
    pendingGoalOperations.length > 0
    && options.allowIncompleteGoalOperationRead !== true
  ) {
    const allowed = options.allowPendingGoalOperation || {};
    const pending = pendingGoalOperations[0];
    const stableIdentityMatches = pending.stable_id_unavailable === true
      ? (
        typeof allowed.operation_id === 'string'
          && allowed.operation_id.length > 0
          && normalizeHash(
            pending.stable_id_sha256,
            `${pending.kind} pending stable_id_sha256`,
          ) === `sha256:${sha256(allowed.operation_id)}`
      )
      : (
        typeof pending.operation_id === 'string'
          && pending.operation_id.length > 0
          && pending.operation_id === allowed.operation_id
      );
    assertControl(
      pending.kind === allowed.kind
        && stableIdentityMatches
        && typeof pending.request_sha256 === 'string'
        && typeof allowed.request_sha256 === 'string'
        && pending.request_sha256 === allowed.request_sha256,
      'TASK_OPERATION_PENDING',
      `Goal 有未完成 ${pending.kind} ${
        pendingOperationDisplayId(pending)
      }；只允许 exact retry`,
    );
  }
  return {
    paths,
    manifest,
    meta,
    control,
    snapshot,
    eventIndexes,
    lastEventHashes,
    pendingForemanRecoveryBatches,
    pendingGoalOperations,
  };
}

function loadGoalState(cwd, goalId) {
  const root = controlRoot(cwd);
  return withStableRead(root, () => {
    const loaded = loadGoalStateUnlocked(root, goalId, {
      repairHeads: false,
      repairBootstrapConsumption: false,
      allowIncompleteGoalOperationRead: true,
    });
    const ledger = buildLedgerProjection(
      loaded.paths,
      loaded.manifest,
      loaded.snapshot,
      { readOnly: true },
    );
    return { ...loaded, ledger };
  }, { allowOddCrashInspection: true });
}

function pendingRoleIdentityIntent(root, loaded, taskId) {
  const directory = loaded.paths.roleIdentityIntents;
  if (!fs.existsSync(directory)) return null;
  ensurePrivateDirectory(directory, { repair: false });
  const candidates = [];
  for (const name of fs.readdirSync(directory).sort()) {
    if (/^[0-9a-f]{64}\.json$/.test(name)) continue;
    assertControl(
      /^[0-9a-f]{64}\.role-identity-intent\.json$/.test(name),
      'ROLE_IDENTITY_INTENT_INVALID',
      `role identity intent inventory 含未知文件 ${name}`,
    );
    const file = path.join(directory, name);
    const stat = fs.lstatSync(file);
    assertControl(
      stat.isFile()
        && !stat.isSymbolicLink()
        && (stat.mode & 0o077) === 0
        && (
          typeof process.getuid !== 'function'
            || stat.uid === process.getuid()
        ),
      'ROLE_IDENTITY_INTENT_INVALID',
      `role identity intent ${name} 不是当前 owner 私有普通文件`,
    );
    const intent = validateRoleIdentityIntent(
      readJson(file, `role identity intent ${name}`),
    );
    assertControl(
      name === `${sha256(intent.operation_id)}.role-identity-intent.json`,
      'ROLE_IDENTITY_INTENT_INVALID',
      `role identity intent ${name} path binding 非法`,
    );
    if (
      intent.goal_id !== loaded.manifest.goal_id
        || intent.task_id !== taskId
    ) {
      continue;
    }
    const state = loaded.snapshot.tasks[taskId];
    const accepted = goalEventIdOccurrences(
      loaded,
      intent.operation_id,
    );
    if (accepted.length > 0) continue;
    if (
      intent.state_revision !== state.state_revision
        || intent.control_epoch !== loaded.control.epoch
        || intent.packet.revision !== state.packet.revision
        || intent.packet.sha256 !== state.packet.sha256
        || intent.base_head !== state.base_head
        || intent.full_head !== state.full_head
        || intent.task_cycle !== state.task_cycle
        || Date.parse(intent.identity_observation.expires_at)
          <= runtimeNowMilliseconds()
    ) {
      continue;
    }
    const session = state.sessions[intent.role] || null;
    if (
      session
        && ['active', 'idle'].includes(session.status)
        && Date.parse(session.lease_until) > runtimeNowMilliseconds()
    ) {
      continue;
    }
    candidates.push(intent);
  }
  assertControl(
    candidates.length <= 1,
    'ROLE_IDENTITY_INTENT_CONFLICT',
    `task ${taskId} 同时存在多个 current role identity intent`,
  );
  return candidates.length === 0
    ? null
    : publicRoleIdentityIntent(candidates[0]);
}

function registrationRoleIdentityBinding(
  loaded,
  state,
  options,
  eventId = registrationStableEventId(options),
  workerBootstrap = null,
) {
  if (!probeObservationProtocolRequired(loaded.manifest)) return null;
  const intent = readRoleIdentityIntent(loaded.paths, eventId);
  assertControl(
    intent,
    'ROLE_IDENTITY_INTENT_REQUIRED',
    'probe-enabled registration 必须消费 upstream canary transaction 的 durable role identity intent',
  );
  if (
    registrationRequiresWorkerBootstrap(
      loaded.manifest,
      intent.role,
    )
  ) {
    assertControl(
      workerBootstrap
        && intent.identity_observation
          .worker_bootstrap_binding_sha256
          === workerBootstrap.binding_sha256,
      'ROLE_IDENTITY_WORKER_BOOTSTRAP_MISMATCH',
      'worker role identity observation 必须绑定 exact validated worker bootstrap receipt',
    );
  }
  const hostId = options.hostId || 'local';
  const attempt = Number(options.attempt || 1);
  assertControl(
    intent.goal_id === loaded.manifest.goal_id
      && intent.task_id === options.taskId
      && intent.role === options.role
      && intent.thread_id === options.threadId
      && intent.host_id === hostId
      && intent.attempt === attempt
      && intent.launch_id === (options.launchId || null)
      && intent.state_revision === state.state_revision
      && intent.control_epoch === loaded.control.epoch
      && intent.packet.revision === state.packet.revision
      && intent.packet.sha256 === state.packet.sha256
      && intent.base_head === state.base_head
      && intent.full_head === state.full_head
      && intent.task_cycle === state.task_cycle,
    'ROLE_IDENTITY_INTENT_MISMATCH',
    'registration identity/launch/session/revision/HEAD 与 upstream intent 不一致',
  );
  assertControl(
    Date.parse(intent.identity_observation.expires_at)
      > runtimeNowMilliseconds(),
    'ROLE_IDENTITY_INTENT_EXPIRED',
    'upstream role identity intent 已过期',
  );
  return {
    protocol: 'goalctl-role-identity-intent-v1',
    operation_id: intent.operation_id,
    intent_sha256: intent.intent_sha256,
    session_id: intent.session_id,
    thread_id: intent.thread_id,
    host_id: intent.host_id,
    attempt: intent.attempt,
    launch_id: intent.launch_id,
    identity_observation_receipt_sha256:
      intent.identity_observation.receipt_sha256,
  };
}

function loadGoalStateReadOnly(cwd, goalId, consume = null, options = {}) {
  const root = controlRoot(cwd);
  return withStableRead(root, () => {
    const loaded = loadGoalStateUnlocked(root, goalId, {
      repairHeads: false,
      repairBootstrapConsumption: false,
      allowIncompleteRecoveryRead: options.allowIncompleteRecoveryRead === true,
      allowIncompleteGoalOperationRead: true,
    });
    const ledger = buildLedgerProjection(loaded.paths, loaded.manifest, loaded.snapshot, { readOnly: true });
    const result = { ...loaded, ledger, readOnly: true };
    if (typeof consume === 'function') return consume(result);
    const public_snapshot = publicSnapshot(
      loaded.snapshot,
      loaded.paths,
      loaded.manifest,
      { readOnly: true },
    );
    for (const taskId of Object.keys(public_snapshot.tasks || {})) {
      const identityIntent = pendingRoleIdentityIntent(
        root,
        loaded,
        taskId,
      );
      if (identityIntent) {
        public_snapshot.tasks[taskId].role_identity_intent =
          identityIntent;
      }
    }
    if (loaded.meta.goal_input_head) {
      public_snapshot.goal_input_head = loaded.meta.goal_input_head;
      public_snapshot.goal_input_source = loaded.meta.goal_input_source;
      for (const task of loaded.manifest.tasks) {
        if (!task.p1) continue;
        public_snapshot.tasks[task.id].required_start_head =
          mechanicalP1RequiredStartHead(loaded, task);
        public_snapshot.tasks[task.id].dependency_gate =
          task.p1.dependency_gate;
      }
    }
    const pendingOperations = new Map();
    for (const task of Object.values(public_snapshot.tasks || {})) {
      for (const operation of task.pending_operations || []) {
        const key = pendingOperationKey(operation);
        if (!pendingOperations.has(key)) pendingOperations.set(key, operation);
      }
    }
    return {
      ...result,
      public_snapshot,
      pending_operations: [...pendingOperations.values()],
      foreman_recovery_scope: foremanRecoveryScope(loaded),
      pending_foreman_recovery: loaded.pendingForemanRecoveryBatches.length === 0
        ? null
        : {
          root_recovery_id: loaded.pendingForemanRecoveryBatches[0].root_recovery_id,
          request_sha256: loaded.pendingForemanRecoveryBatches[0].intent.request_sha256,
          goal_scope_sha256: loaded.pendingForemanRecoveryBatches[0].intent.goal_scope_sha256,
          target_task_ids: loaded.pendingForemanRecoveryBatches[0].intent.target_task_ids,
          source_task_ids: loaded.pendingForemanRecoveryBatches[0].intent.source_task_ids,
        },
    };
  }, { allowOddCrashInspection: true });
}

function goalEventIdOccurrences(loaded, eventId) {
  return Object.entries(loaded.eventIndexes)
    .filter(([, index]) => index.has(eventId))
    .map(([taskId, index]) => ({
      task_id: taskId,
      input_sha256: index.get(eventId),
    }));
}

function goalControlEventOccurrences(loaded, eventId) {
  return loaded.control.events.filter((event) => event.event_id === eventId);
}

function acceptedGoalEvent(root, loaded, taskId, eventId) {
  for (const file of acceptedEventFiles(root, loaded.manifest.goal_id, taskId)) {
    const event = readJson(file, `accepted event ${path.basename(file)}`);
    if (event.event_id === eventId) return event;
  }
  return null;
}

function goalBootstrapForemanLineage(root, loaded) {
  const lineage = [];
  for (const task of loaded.manifest.tasks) {
    for (const file of acceptedEventFiles(root, loaded.manifest.goal_id, task.id)) {
      const event = readJson(file, `accepted event ${path.basename(file)}`);
      if (
        event.type === 'REGISTER_ROLE'
        && event.payload
        && event.payload.role === 'FOREMAN'
        && event.payload.authorized_by
        && event.payload.authorized_by.role === 'BOOTSTRAP'
      ) {
        lineage.push({
          task_id: task.id,
          event_id: event.event_id,
          input_sha256: event.input_sha256,
          event_sha256: event.event_sha256,
          accepted_at: event.accepted_at,
        });
      }
    }
  }
  assertControl(
    lineage.length <= 1,
    'CORRUPT_STORE',
    `Goal append-only lineage 含 ${lineage.length} 个 BOOTSTRAP FOREMAN registration`,
  );
  return lineage;
}

function reconcileBootstrapConsumption(root, loaded, { repair = true } = {}) {
  const lineage = goalBootstrapForemanLineage(root, loaded);
  const capabilityFile = loaded.meta.bootstrap_capability_file;
  if (lineage.length === 0) {
    assertControl(
      loaded.meta.bootstrap_consumed_at === undefined,
      'CORRUPT_STORE',
      'bootstrap consumption marker 缺少 append-only BOOTSTRAP lineage',
    );
    return {
      consumed: false,
      repaired: false,
      reconciliation_required: false,
    };
  }
  const acceptedAt = lineage[0].accepted_at;
  assertControl(
    typeof acceptedAt === 'string'
      && Number.isFinite(Date.parse(acceptedAt))
      && (
        loaded.meta.bootstrap_consumed_at === undefined
          || loaded.meta.bootstrap_consumed_at === acceptedAt
      ),
    'CORRUPT_STORE',
    'bootstrap consumption marker 与唯一 append-only lineage 不一致',
  );
  const reconciliationRequired =
    loaded.meta.bootstrap_consumed_at === undefined
      || fs.existsSync(capabilityFile);
  let repaired = false;
  if (loaded.meta.bootstrap_consumed_at === undefined && repair) {
    maybeInjectRecoveryBatchFault(
      loaded.meta.repository_root,
      'GOAL_CONTROL_TEST_FAULT_BEFORE_BOOTSTRAP_CONSUMPTION_MARKER',
      'TEST_FAULT_BEFORE_BOOTSTRAP_CONSUMPTION_MARKER',
      'injected failure after BOOTSTRAP event commit before consumption marker',
    );
    const updated = sealedMetadata({
      ...loaded.meta,
      bootstrap_consumed_at: acceptedAt,
    });
    atomicWriteJson(loaded.paths.meta, updated);
    Object.assign(loaded.meta, updated);
    repaired = true;
  }
  if (fs.existsSync(capabilityFile)) {
    const capability = readCapabilityFile(capabilityFile, capabilityFile);
    assertControl(
      hashesEqual(capability.sha256, loaded.meta.bootstrap_capability_sha256),
      'CORRUPT_STORE',
      'residual bootstrap capability bytes 与 metadata 不一致',
    );
    if (repair) {
      assertControl(
        loaded.meta.bootstrap_consumed_at === acceptedAt,
        'CORRUPT_STORE',
        '删除 bootstrap capability 前 consumption marker 尚未 durable',
      );
      maybeInjectRecoveryBatchFault(
        loaded.meta.repository_root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_BOOTSTRAP_CONSUMPTION_MARKER',
        'TEST_FAULT_AFTER_BOOTSTRAP_CONSUMPTION_MARKER',
        'injected failure after BOOTSTRAP marker before capability delete',
      );
      fs.rmSync(capabilityFile);
      fsyncDirectory(path.dirname(capabilityFile));
      repaired = true;
      maybeInjectRecoveryBatchFault(
        loaded.meta.repository_root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_BOOTSTRAP_CAPABILITY_DELETE',
        'TEST_FAULT_AFTER_BOOTSTRAP_CAPABILITY_DELETE',
        'injected failure after BOOTSTRAP capability delete',
      );
    }
  }
  return {
    consumed: !fs.existsSync(capabilityFile),
    repaired,
    reconciliation_required: reconciliationRequired,
  };
}

function authorizeHistoricalActorCapability(
  snapshot,
  capabilityFile,
  actor,
  options = {},
) {
  const states = options.goalWide
    ? Object.values(snapshot.tasks || {})
    : [snapshot.tasks[options.taskId]].filter(Boolean);
  const candidates = states.flatMap((state) => [
    ...Object.values(state.sessions || {}),
    ...Object.values(state.session_history || {}).flat(),
  ]).filter((session) => (
    session.role === actor.role
      && session.thread_id === actor.thread_id
      && session.host_id === actor.host_id
      && (
        actor.attempt === undefined
        || actor.attempt === null
        || session.attempt === actor.attempt
      )
  ));
  assertControl(
    candidates.length > 0,
    'CAPABILITY_INVALID',
    `accepted actor ${actor.role}:${actor.thread_id} 不在 current/session_history`,
  );
  const supplied = readCapabilityFile(capabilityFile);
  const session = candidates.find((candidate) => (
    candidate.capability_file === supplied.file
      && hashesEqual(candidate.capability_sha256, supplied.sha256)
  ));
  assertControl(
    session,
    'CAPABILITY_INVALID',
    'capability 不属于 accepted actor 的原始 session',
  );
  return session;
}

function authorizeAcceptedEventRetry(loaded, taskId, accepted, capabilityFile) {
  assertControl(
    accepted && accepted.actor,
    'CORRUPT_STORE',
    'accepted event 缺 actor',
  );
  const authority = accepted.goal_foreman_authority;
  if (accepted.actor.role === 'FOREMAN' && authority) {
    assertControl(
      authority.thread_id === accepted.actor.thread_id
        && authority.host_id === accepted.actor.host_id
        && typeof authority.attempt === 'number',
      'CORRUPT_STORE',
      'accepted FOREMAN authority anchor 与 actor identity 不一致',
    );
    const supplied = readCapabilityFile(capabilityFile);
    assertControl(
      supplied.file === authority.capability_file
        && hashesEqual(supplied.sha256, authority.capability_sha256),
      'CAPABILITY_INVALID',
      'capability 不属于 accepted FOREMAN authority anchor',
    );
    return authority;
  }
  return authorizeHistoricalActorCapability(
    loaded.snapshot,
    capabilityFile,
    accepted.actor,
    {
      goalWide: accepted.actor.role === 'FOREMAN',
      taskId,
    },
  );
}

function retryAcceptedCommandEvent(cwd, options) {
  safeId(options.eventId, 'command event_id');
  return loadGoalStateReadOnly(cwd, options.goalId, (loaded) => {
    const state = loaded.snapshot.tasks[options.taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
    assertControl(
      goalControlEventOccurrences(loaded, options.eventId).length === 0,
      'EVENT_ID_CONFLICT',
      `command event id ${options.eventId} 已被 Goal control event 使用`,
    );
    const occurrences = goalEventIdOccurrences(loaded, options.eventId);
    assertControl(
      occurrences.every((occurrence) => occurrence.task_id === options.taskId),
      'EVENT_ID_CONFLICT',
      `command event id ${options.eventId} 已被 Goal 中其它 task 使用`,
    );
    if (occurrences.length === 0) return null;
    assertControl(
      occurrences.length === 1,
      'CORRUPT_STORE',
      `command event id ${options.eventId} 在 task event chain 中重复`,
    );
    const accepted = acceptedGoalEvent(
      controlRoot(cwd),
      loaded,
      options.taskId,
      options.eventId,
    );
    assertControl(
      accepted
        && accepted.type === options.type
        && accepted.input_sha256 === occurrences[0].input_sha256,
      'EVENT_ID_CONFLICT',
      `command event id ${options.eventId} 已绑定不同 operation`,
    );
    authorizeAcceptedEventRetry(
      loaded,
      options.taskId,
      accepted,
      options.actorCapabilityFile,
    );
    if (typeof options.assertRequest === 'function') {
      options.assertRequest(accepted, loaded);
    }
    return {
      accepted: true,
      idempotent: true,
      event_id: options.eventId,
      task: publicTaskState(state),
      accepted_event: accepted,
    };
  });
}

function authorizeRegistrationRetry(root, loaded, state, options, accepted) {
  assertControl(
    accepted
      && accepted.type === 'REGISTER_ROLE'
      && accepted.goal_id === options.goalId
      && accepted.task_id === options.taskId
      && accepted.actor
      && accepted.actor.role === options.role
      && accepted.actor.thread_id === options.threadId
      && accepted.actor.host_id === (options.hostId || 'local')
      && accepted.payload
      && accepted.payload.role === options.role
      && accepted.payload.thread_id === options.threadId
      && accepted.payload.host_id === (options.hostId || 'local')
      && accepted.payload.attempt === Number(options.attempt || 1)
      && accepted.payload.lease_ms === Number(options.leaseMs || 3600000)
      && accepted.payload.status === (options.status || 'active')
      && accepted.payload.launch_id === (options.launchId || null)
      && workerBootstrapRequestMatchesBinding(
        accepted.payload.worker_bootstrap || null,
        options,
      )
      && probeObservationRequestMatchesBinding(
        accepted.payload.probe_observation || null,
        options,
      ),
    'EVENT_ID_CONFLICT',
    `registration event id ${accepted && accepted.event_id} 已被不同请求使用`,
  );
  const session = [
    state.sessions[options.role],
    ...(state.session_history[options.role] || []),
  ].filter(Boolean).find((candidate) => (
    candidate.registration_event_id === accepted.event_id
      && candidate.thread_id === accepted.actor.thread_id
      && candidate.host_id === accepted.actor.host_id
      && candidate.attempt === accepted.payload.attempt
      && candidate.capability_file === accepted.payload.capability_file
      && candidate.capability_sha256 === accepted.payload.capability_sha256
  ));
  assertControl(
    session,
    'REGISTRATION_IDEMPOTENCY_MISMATCH',
    'accepted registration 在 current/session_history 中缺少原始 session',
  );
  if (options.actorCapabilityFile) {
    const actorCapability = readCapabilityFile(
      options.actorCapabilityFile,
      session.capability_file,
    );
    assertControl(
      hashesEqual(actorCapability.sha256, session.capability_sha256),
      'CAPABILITY_INVALID',
      'registration retry actor capability 不匹配',
    );
    return session;
  }
  const authority = accepted.payload.authorized_by || {};
  if (authority.role === 'BOOTSTRAP') {
    const lineage = goalBootstrapForemanLineage(root, loaded);
    assertControl(
      lineage.length === 1
        && lineage[0].task_id === options.taskId
        && lineage[0].event_id === accepted.event_id
        && lineage[0].input_sha256 === accepted.input_sha256,
      'CAPABILITY_CONSUMED',
      'bootstrap retry 未绑定唯一 Goal append-only FOREMAN lineage',
    );
    assertControl(
      typeof options.bootstrapCapabilityFile === 'string'
        && path.resolve(options.bootstrapCapabilityFile) === path.resolve(loaded.meta.bootstrap_capability_file)
        && authority.capability_file === loaded.meta.bootstrap_capability_file,
      'CAPABILITY_INVALID',
      'bootstrap retry capability path 与原始 registration 不一致',
    );
    if (fs.existsSync(loaded.meta.bootstrap_capability_file)) {
      const bootstrap = readCapabilityFile(
        options.bootstrapCapabilityFile,
        loaded.meta.bootstrap_capability_file,
      );
      assertControl(
        hashesEqual(bootstrap.sha256, loaded.meta.bootstrap_capability_sha256),
        'CAPABILITY_INVALID',
        'bootstrap retry capability 不匹配',
      );
    }
  } else if (authority.role === 'GOAL_RECOVERY') {
    const recovery = readCapabilityFile(
      options.foremanRecoveryCapabilityFile,
      loaded.meta.foreman_recovery_capability_file,
    );
    assertControl(
      hashesEqual(recovery.sha256, loaded.meta.foreman_recovery_capability_sha256),
      'CAPABILITY_INVALID',
      'Goal FOREMAN recovery capability 不匹配',
    );
  } else {
    const requiredRole = ['FOREMAN', 'CAPTAIN'].includes(options.role) ? 'FOREMAN' : 'CAPTAIN';
    assertControl(
      authority.role === requiredRole
        && typeof authority.thread_id === 'string'
        && authority.thread_id.length > 0,
      'REGISTRATION_AUTHORITY_REQUIRED',
      'accepted registration 原始授权者无效',
    );
    assertControl(
      !options.authorizerThreadId || options.authorizerThreadId === authority.thread_id,
      'REGISTRATION_AUTHORITY_REQUIRED',
      'registration retry authorizer thread 与原始授权者不一致',
    );
    const authorityStates = requiredRole === 'FOREMAN'
      ? Object.values(loaded.snapshot.tasks || {})
      : [state];
    const originalAuthorities = authorityStates.flatMap((candidateState) => [
      candidateState.sessions[requiredRole],
      ...(candidateState.session_history[requiredRole] || []),
    ]).filter((candidate) => (
      candidate
        && candidate.role === requiredRole
        && candidate.thread_id === authority.thread_id
        && candidate.host_id === authority.host_id
        && candidate.attempt === authority.attempt
    ));
    assertControl(
      originalAuthorities.length > 0,
      'REGISTRATION_AUTHORITY_REQUIRED',
      'accepted registration 原始授权者不在 current/session_history',
    );
    const supplied = readCapabilityFile(options.authorizerCapabilityFile);
    assertControl(
      originalAuthorities.some((candidate) => (
        candidate.capability_file === supplied.file
          && hashesEqual(candidate.capability_sha256, supplied.sha256)
      )),
      'CAPABILITY_INVALID',
      'registration retry capability 不属于原始授权者',
    );
  }
  const capability = readCapabilityFile(session.capability_file, session.capability_file);
  assertControl(
    hashesEqual(capability.sha256, session.capability_sha256),
    'CORRUPT_STORE',
    'accepted registration capability 与 session hash 不一致',
  );
  return session;
}

function assertFreshGoalRoleIdentity(snapshot, taskId, role, threadId) {
  for (const [candidateTaskId, state] of Object.entries(snapshot.tasks || {})) {
    for (const session of Object.values(state.sessions || {})) {
      if (candidateTaskId === taskId && session.role === role && session.thread_id === threadId) continue;
      assertControl(
        session.thread_id !== threadId,
        session.role === role ? 'ROLE_IDENTITY_REUSE' : 'THREAD_ROLE_COLLISION',
        `thread ${threadId} 已在 Goal task ${candidateTaskId} 登记为 ${session.role}`,
      );
    }
    for (const session of Object.values(state.session_history || {}).flat()) {
      assertControl(
        session.thread_id !== threadId,
        'ROLE_IDENTITY_REUSE',
        `thread ${threadId} 已在 Goal task ${candidateTaskId} 历史中使用`,
      );
    }
  }
}

function foremanRecoveryTaskBinding(loaded, taskId) {
  const state = loaded.snapshot.tasks[taskId];
  const publicActor = (session) => (session ? {
    role: session.role,
    thread_id: session.thread_id,
    host_id: session.host_id,
    attempt: session.attempt,
    status: session.status,
    lease_until: session.lease_until,
    registration_event_id: session.registration_event_id || null,
    recovery_event_id: session.recovery_event_id || null,
  } : null);
  return {
    task_id: taskId,
    phase: state.phase,
    state_revision: state.state_revision,
    event_head: loaded.lastEventHashes[taskId] || null,
    control_epoch: loaded.control.epoch,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    base_head: state.base_head,
    full_head: state.full_head,
    foreman: state.sessions.FOREMAN
      ? publicActor(state.sessions.FOREMAN)
      : null,
    captain: publicActor(state.sessions.CAPTAIN),
    recovery_sha256: state.recovery ? hashObject(state.recovery) : null,
    recovery_backlog_sha256: hashObject(state.recovery_backlog || []),
  };
}

function assertUsableGoalForemanReplica(snapshot, session, observedNow) {
  const lineage = assertCoherentGoalForemanLineage(snapshot);
  assertControl(
    lineage.replicas.length > 0
      && session.attempt === lineage.attempt
      && session.thread_id === lineage.anchor.thread_id
      && session.host_id === lineage.anchor.host_id
      && session.capability_file === lineage.anchor.capability_file
      && session.capability_sha256 === lineage.anchor.capability_sha256,
    'CAPABILITY_SUPERSEDED',
    `FOREMAN attempt=${session.attempt} 已被 Goal attempt=${lineage.attempt} supersede`,
  );
  assertControl(
    lineage.replicas.some((candidate) => (
      ['active', 'idle'].includes(candidate.status)
        && Date.parse(candidate.lease_until) > observedNow
    )),
    'ACTOR_LEASE_EXPIRED',
    `Goal FOREMAN replicas lease 均已过期: ${lineage.replicas.map((candidate) => candidate.lease_until).join(',')}`,
  );
}

function foremanRecoveryScope(loaded) {
  const scope = {
    schema_version: 1,
    goal_id: loaded.manifest.goal_id,
    control_epoch: loaded.control.epoch,
    control_event_head: loaded.control.lastEventHash || null,
    tasks: loaded.manifest.tasks
      .map((task) => foremanRecoveryTaskBinding(loaded, task.id))
      .sort((left, right) => left.task_id.localeCompare(right.task_id)),
  };
  return {
    ...scope,
    scope_sha256: hashObject(scope),
    recoverable_task_ids: scope.tasks
      .filter((task) => task.phase !== 'ARCHIVED' && task.foreman)
      .map((task) => task.task_id),
    archived_source_task_ids: scope.tasks
      .filter((task) => task.phase === 'ARCHIVED' && task.foreman)
      .map((task) => task.task_id),
    adoption_candidate_task_ids: scope.tasks
      .filter((task) => task.phase !== 'ARCHIVED' && !task.foreman)
      .map((task) => task.task_id),
  };
}

function recoveryScopeCore(scope) {
  return {
    schema_version: scope.schema_version,
    goal_id: scope.goal_id,
    control_epoch: scope.control_epoch,
    control_event_head: scope.control_event_head,
    tasks: scope.tasks,
  };
}

function assertRecoveryScopeSeal(scope) {
  assertControl(
    scope
      && scope.schema_version === 1
      && Array.isArray(scope.tasks)
      && scope.scope_sha256 === hashObject(recoveryScopeCore(scope)),
    'CORRUPT_STORE',
    'FOREMAN recovery Goal scope seal 不匹配',
  );
}

function recoveryEventId(rootRecoveryId, taskId) {
  const prefix = rootRecoveryId.slice(0, 150);
  return `${prefix}.task.${sha256(taskId).slice(0, 16)}`;
}

function buildForemanRecoveryEvent(options) {
  const {
    adoptionTargetTaskId,
    attempt,
    binding,
    capability,
    goalId,
    hostId,
    incidentRef,
    leaseMilliseconds,
    originalScope,
    probeObservation,
    roleIdentity,
    reason,
    requestSha256,
    rootRecoveryId,
    sourceBinding,
    sourceTaskIds,
    targetTaskIds,
    taskEventId,
    taskId,
    threadId,
  } = options;
  const localForeman = binding.foreman;
  return {
    schema_version: 1,
    event_id: taskEventId,
    goal_id: goalId,
    task_id: taskId,
    type: 'RECOVER_EXPIRED_FOREMAN',
    actor: { role: 'FOREMAN', thread_id: threadId, host_id: hostId },
    actor_sequence: 1,
    expected_state_revision: binding.state_revision,
    control_epoch: originalScope.control_epoch,
    packet: { revision: binding.packet.revision, sha256: binding.packet.sha256 },
    base_head: binding.base_head,
    full_head: binding.full_head,
    payload: {
      attempt,
      lease_ms: leaseMilliseconds,
      status: 'active',
      capability_sha256: capability.sha256,
      capability_file: capability.file,
      reason,
      incident_ref: incidentRef,
      request_sha256: requestSha256,
      ...(probeObservation
        ? { probe_observation: probeObservation }
        : {}),
      ...(roleIdentity
        ? { role_identity: roleIdentity }
        : {}),
      root_recovery_id: rootRecoveryId,
      goal_scope: originalScope,
      goal_scope_sha256: originalScope.scope_sha256,
      scope_task_ids: targetTaskIds,
      source_task_ids: sourceTaskIds,
      adoption_target_task_id: adoptionTargetTaskId,
      adopt_without_local_foreman: taskId === adoptionTargetTaskId,
      source_foreman: {
        task_id: sourceBinding.task_id,
        ...sourceBinding.foreman,
      },
      expected_event_head: binding.event_head,
      expected_foreman_thread_id: localForeman
        ? localForeman.thread_id
        : sourceBinding.foreman.thread_id,
      expected_foreman_host_id: localForeman
        ? localForeman.host_id
        : sourceBinding.foreman.host_id,
      expected_foreman_attempt: localForeman
        ? localForeman.attempt
        : sourceBinding.foreman.attempt,
      expected_foreman_lease_until: localForeman
        ? localForeman.lease_until
        : sourceBinding.foreman.lease_until,
      authorized_by: { role: 'GOAL_RECOVERY' },
    },
  };
}

function goalRecoveryBatchEvents(root, loaded, rootRecoveryId) {
  const events = [];
  for (const task of loaded.manifest.tasks) {
    for (const file of acceptedEventFiles(root, loaded.manifest.goal_id, task.id)) {
      const event = readJson(file, `accepted event ${path.basename(file)}`);
      if (
        event.type === 'RECOVER_EXPIRED_FOREMAN'
        && event.payload
        && event.payload.root_recovery_id === rootRecoveryId
      ) {
        events.push(event);
      }
    }
  }
  return events;
}

function sealedRecoveryBatchRecord(record) {
  return { ...record, record_sha256: hashObject(record) };
}

function sealedRegistrationIntent(record) {
  return { ...record, intent_sha256: hashObject(record) };
}

function registrationIntentPaths(paths, eventId) {
  safeId(eventId, 'registration event_id');
  const dir = path.join(paths.registrationIntents, eventId);
  return {
    dir,
    intent: path.join(dir, 'intent.json'),
  };
}

function preparedIntentCandidate(
  parent,
  kind,
  stableId,
  label,
  stableIdMismatchCode = 'PREPARED_REQUEST_MISMATCH',
) {
  if (!fs.existsSync(parent)) return null;
  const escapedKind = kind.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(
    `^\\.init-${escapedKind}-([0-9a-f]{64})-([0-9a-f]{64})$`,
  );
  const candidates = [];
  for (const name of fs.readdirSync(parent).sort()) {
    if (!name.startsWith('.init-')) continue;
    const match = pattern.exec(name);
    assertControl(
      match,
      'PREPARED_STAGING_CONFLICT',
      `${label} 发现 foreign/lookalike staging ${name}`,
    );
    const directory = path.join(parent, name);
    assertPreparedDirectory(directory, `${label} ${name}`);
    candidates.push({
      name,
      directory,
      stableDigest: match[1],
      requestDigest: match[2],
    });
  }
  assertControl(
    candidates.length <= 1,
    'PREPARED_STAGING_CONFLICT',
    `${label} 同时存在多个 prepared staging`,
  );
  if (candidates.length === 0) return null;
  assertControl(
    candidates[0].stableDigest === sha256(stableId),
    stableIdMismatchCode,
    stableIdMismatchCode === 'TASK_OPERATION_PENDING'
      ? `${label} 被另一个 Goal-wide prepared operation 阻塞`
      : `${label} prepared staging 已绑定不同 stable ID`,
  );
  return candidates[0];
}

function inspectPreparedIntentInventory(
  candidate,
  finalizedCapabilityPattern,
  label,
) {
  const entries = fs.readdirSync(candidate.directory).sort();
  const intentTemporaries = entries.filter((name) => (
    atomicTemporaryPattern('intent.json').test(name)
  ));
  const finalizedCapabilities = entries.filter((name) => (
    finalizedCapabilityPattern.test(name)
  ));
  const capabilityTemporaries = entries.filter((name) => (
    name.startsWith('.')
      && name.includes('.cap.')
      && /\.[1-9][0-9]*\.tmp-[0-9a-f]{24}$/.test(name)
      && finalizedCapabilityPattern.test(
        name.slice(1).replace(/\.[1-9][0-9]*\.tmp-[0-9a-f]{24}$/, ''),
      )
  ));
  const known = new Set([
    ...intentTemporaries,
    ...finalizedCapabilities,
    ...capabilityTemporaries,
    ...(entries.includes('intent.json') ? ['intent.json'] : []),
  ]);
  const unknown = entries.filter((name) => !known.has(name));
  assertControl(
    unknown.length === 0
      && intentTemporaries.length <= 1
      && finalizedCapabilities.length <= 1
      && capabilityTemporaries.length <= 1
      && !(finalizedCapabilities.length && capabilityTemporaries.length),
    'PREPARED_STAGING_INVALID',
    `${label} inventory 非协议状态: ${entries.join(', ')}`,
  );
  for (const name of entries) {
    assertPreparedFile(
      path.join(candidate.directory, name),
      `${label} ${name}`,
    );
  }
  const sealed = entries.includes('intent.json')
    && finalizedCapabilities.length === 1
    && intentTemporaries.length === 0
    && capabilityTemporaries.length === 0
    && entries.length === 2;
  assertControl(
    !entries.includes('intent.json') || sealed,
    'PREPARED_STAGING_INVALID',
    `${label} canonical intent 未绑定唯一 finalized capability`,
  );
  return {
    entries,
    sealed,
    capabilityName: finalizedCapabilities[0] || null,
  };
}

function recoverPreparedIntent(options) {
  const {
    finalDirectory,
    kind,
    label,
    matchIncoming,
    parent,
    readRecord,
    stableId,
    stableIdMismatchCode,
    validateCapabilityName,
    validatePreparedBinding,
  } = options;
  const candidate = preparedIntentCandidate(
    parent,
    kind,
    stableId,
    label,
    stableIdMismatchCode,
  );
  if (!candidate) return null;
  assertControl(
    !fs.existsSync(finalDirectory),
    'PREPARED_STAGING_CONFLICT',
    `${label} final/staging 并存`,
  );
  const capabilityPattern = validateCapabilityName();
  const inventory = inspectPreparedIntentInventory(
    candidate,
    capabilityPattern,
    label,
  );
  if (!inventory.sealed) return { candidate, inventory, sealed: false };
  const record = readRecord(
    path.join(candidate.directory, 'intent.json'),
  );
  validatePreparedBinding(record);
  assertControl(
    candidate.requestDigest
      === preparedDigest(
        record.prepared_request_sha256,
        `${label} prepared request sha256`,
      )
      && matchIncoming(record),
    'PREPARED_REQUEST_MISMATCH',
    `${label} prepared request 与当前命令不一致`,
  );
  const stagedCapabilityFile = path.join(
    candidate.directory,
    inventory.capabilityName,
  );
  const capability = readCapabilityFile(
    stagedCapabilityFile,
    stagedCapabilityFile,
  );
  assertControl(
    record.capability_file
      === path.join(finalDirectory, inventory.capabilityName)
      && hashesEqual(capability.sha256, record.capability_sha256),
    'PREPARED_STAGING_INVALID',
    `${label} capability path/bytes 与 sealed intent 不一致`,
  );
  fs.renameSync(candidate.directory, finalDirectory);
  fsyncDirectory(parent);
  return { candidate, inventory, sealed: true, record, capability };
}

function cleanupExactUnsealedPreparedIntent(
  parent,
  kind,
  stableId,
  preparedRequestSha256,
  finalizedCapabilityPattern,
  label,
) {
  const candidate = preparedIntentCandidate(parent, kind, stableId, label);
  if (!candidate) return;
  assertControl(
    candidate.name === preparedStagingName(
      kind,
      stableId,
      preparedRequestSha256,
    ),
    'PREPARED_REQUEST_MISMATCH',
    `${label} unsealed staging 已绑定不同 request`,
  );
  const inventory = inspectPreparedIntentInventory(
    candidate,
    finalizedCapabilityPattern,
    label,
  );
  assertControl(
    !inventory.sealed,
    'PREPARED_STAGING_CONFLICT',
    `${label} sealed staging 必须先走 validate+promote`,
  );
  removeValidatedPreparedTree(
    parent,
    candidate.directory,
    inventory.entries,
  );
}

function readRegistrationIntentFile(file, eventId) {
  assertPreparedFile(file, `registration intent ${eventId}`);
  const intent = readJson(file, `registration intent ${eventId}`);
  const unsigned = { ...intent };
  delete unsigned.intent_sha256;
  assertControl(
    intent.schema_version === 1
      && intent.kind === 'REGISTRATION_INTENT'
      && intent.event_id === eventId
      && intent.intent_sha256 === hashObject(unsigned),
    'CORRUPT_STORE',
    `registration intent ${eventId} seal 不匹配`,
  );
  return intent;
}

function readRegistrationIntent(paths, eventId) {
  const files = registrationIntentPaths(paths, eventId);
  if (!fs.existsSync(files.dir)) return null;
  assertPreparedDirectory(files.dir, `registration intent ${eventId}`);
  return readRegistrationIntentFile(files.intent, eventId);
}

function pendingCanonicalRegistrationIntents(root, paths, goalId) {
  if (!fs.existsSync(paths.registrationIntents)) return [];
  const pending = [];
  for (const eventId of fs.readdirSync(paths.registrationIntents).sort()) {
    if (eventId.startsWith('.init-')) continue;
    safeId(eventId, 'registration intent directory');
    const intent = readRegistrationIntent(paths, eventId);
    assertControl(
      intent
        && intent.goal_id === goalId
        && typeof intent.task_id === 'string'
        && intent.request
        && intent.request.event_id === eventId
        && intent.request.goal_id === goalId
        && intent.request.task_id === intent.task_id
        && intent.request_sha256 === hashObject(intent.request),
      'CORRUPT_STORE',
      `registration intent ${eventId} Goal/task/request binding 漂移`,
    );
    safeId(intent.task_id, 'registration intent task_id');
    const accepted = acceptedEventFiles(root, goalId, intent.task_id)
      .some((file) => (
        readJson(file, `accepted event ${path.basename(file)}`).event_id
          === eventId
      ));
    if (!accepted) pending.push(intent);
  }
  assertControl(
    pending.length <= 1,
    'CORRUPT_STORE',
    'Goal 同时存在多个未完成 registration intent',
  );
  return pending;
}

function registrationIntentMatchesOptions(intent, eventId, options) {
  const request = intent.request || {};
  const attempt = Number(options.attempt || 1);
  const hostId = options.hostId || 'local';
  return request.event_id === eventId
    && request.goal_id === options.goalId
    && request.task_id === options.taskId
    && request.role === options.role
    && request.thread_id === options.threadId
    && request.host_id === hostId
    && request.attempt === attempt
    && request.lease_ms === Number(options.leaseMs || 3600000)
    && request.status === (options.status || 'active')
    && request.launch_id === (options.launchId || null)
    && workerBootstrapRequestMatchesBinding(
      request.worker_bootstrap || null,
      options,
    )
    && probeObservationRequestMatchesBinding(
      request.probe_observation || null,
      options,
    );
}

function recoverPreparedRegistrationIntent(paths, eventId, options) {
  const attempt = Number(options.attempt || 1);
  const finalFiles = registrationIntentPaths(paths, eventId);
  return recoverPreparedIntent({
    parent: paths.registrationIntents,
    kind: 'registration',
    stableId: eventId,
    finalDirectory: finalFiles.dir,
    label: `registration ${eventId}`,
    stableIdMismatchCode: 'TASK_OPERATION_PENDING',
    validateCapabilityName: () => new RegExp(
      `^${options.role.toLowerCase()}-${attempt}-[0-9a-f]{24}\\.cap$`,
    ),
    readRecord: (file) => readRegistrationIntentFile(file, eventId),
    validatePreparedBinding: (intent) => {
      assertControl(
        intent.goal_id === options.goalId
          && intent.task_id === options.taskId
          && intent.request
          && intent.request_sha256 === hashObject(intent.request)
          && intent.authorizer_authority
          && intent.prepared_request_sha256 === hashObject({
            request: intent.request,
            authorizer_authority: intent.authorizer_authority,
          }),
        'PREPARED_STAGING_INVALID',
        `registration ${eventId} prepared request/authority seal 不匹配`,
      );
    },
    matchIncoming: (intent) => (
      registrationIntentMatchesOptions(intent, eventId, options)
    ),
  });
}

function publishRegistrationIntent(
  cwd,
  paths,
  eventId,
  role,
  attempt,
  preparedRequestSha256,
  buildUnsignedIntent,
) {
  ensureDir(paths.registrationIntents);
  const finalFiles = registrationIntentPaths(paths, eventId);
  const capabilityPattern = new RegExp(
    `^${role.toLowerCase()}-${attempt}-[0-9a-f]{24}\\.cap$`,
  );
  cleanupExactUnsealedPreparedIntent(
    paths.registrationIntents,
    'registration',
    eventId,
    preparedRequestSha256,
    capabilityPattern,
    `registration ${eventId}`,
  );
  assertControl(
    !fs.existsSync(finalFiles.dir),
    'EVENT_ID_CONFLICT',
    `registration intent ${eventId} 已存在`,
  );
  const staging = path.join(
    paths.registrationIntents,
    preparedStagingName(
      'registration',
      eventId,
      preparedRequestSha256,
    ),
  );
  fs.mkdirSync(staging, { mode: 0o700 });
  const stagedCapability = createCapabilityFile(
    staging,
    `${role.toLowerCase()}-${attempt}`,
  );
  const finalCapabilityFile = path.join(
    finalFiles.dir,
    path.basename(stagedCapability.file),
  );
  const intent = sealedRegistrationIntent(buildUnsignedIntent({
    file: finalCapabilityFile,
    sha256: stagedCapability.sha256,
  }));
  atomicWriteJson(path.join(staging, 'intent.json'), intent);
  fsyncDirectory(staging);
  maybeInjectRecoveryBatchFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_STAGING_SEAL',
    'TEST_FAULT_AFTER_REGISTRATION_STAGING_SEAL',
    'injected failure after sealed registration staging fsync',
  );
  fs.renameSync(staging, finalFiles.dir);
  fsyncDirectory(paths.registrationIntents);
  return {
    intent,
    capability: {
      file: fs.realpathSync(finalCapabilityFile),
      sha256: stagedCapability.sha256,
    },
  };
}

function recoveryBatchPaths(paths, rootRecoveryId) {
  safeId(rootRecoveryId, 'root recovery event_id');
  const dir = path.join(paths.foremanRecoveryBatches, rootRecoveryId);
  return {
    dir,
    intent: path.join(dir, 'intent.json'),
    commit: path.join(dir, 'commit.json'),
  };
}

function readRecoveryBatchRecord(file, kind, goalId, rootRecoveryId) {
  if (!fs.existsSync(file)) return null;
  assertPreparedFile(
    file,
    `FOREMAN recovery batch ${kind} ${rootRecoveryId}`,
  );
  const record = readJson(file, `FOREMAN recovery batch ${kind}`);
  const unsigned = { ...record };
  delete unsigned.record_sha256;
  assertControl(
    record.schema_version === 1
      && record.kind === kind
      && record.goal_id === goalId
      && record.root_recovery_id === rootRecoveryId
      && record.record_sha256 === hashObject(unsigned),
    'CORRUPT_STORE',
    `FOREMAN recovery batch ${kind} seal 不匹配`,
  );
  return record;
}

function recoveryBatchState(paths, goalId, rootRecoveryId) {
  const files = recoveryBatchPaths(paths, rootRecoveryId);
  const intent = readRecoveryBatchRecord(
    files.intent,
    'FOREMAN_RECOVERY_INTENT',
    goalId,
    rootRecoveryId,
  );
  const commit = readRecoveryBatchRecord(
    files.commit,
    'FOREMAN_RECOVERY_COMMIT',
    goalId,
    rootRecoveryId,
  );
  assertControl(!commit || intent, 'CORRUPT_STORE', 'FOREMAN recovery batch commit 缺 intent');
  if (commit) {
    assertControl(
      commit.intent_sha256 === intent.record_sha256
        && commit.request_sha256 === intent.request_sha256,
      'CORRUPT_STORE',
      'FOREMAN recovery batch commit 未绑定 intent',
    );
  }
  return { files, intent, commit };
}

function recoveryIntentMatchesOptions(intent, rootRecoveryId, options) {
  const request = intent.request || {};
  const reason = typeof options.reason === 'string'
    ? options.reason.trim()
    : '';
  const incidentRef = typeof options.incidentRef === 'string'
    ? options.incidentRef.trim()
    : '';
  const hostId = options.hostId || 'local';
  return request.root_recovery_id === rootRecoveryId
    && request.goal_id === options.goalId
    && request.anchor_task_id === options.taskId
    && request.successor
    && request.successor.role === 'FOREMAN'
    && request.successor.thread_id === options.threadId
    && request.successor.host_id === hostId
    && request.successor.attempt === Number(options.attempt)
    && request.successor.lease_ms === Number(options.leaseMs)
    && request.expected_goal_scope_sha256 === normalizeHash(
      options.expectedGoalScopeSha256,
      'expected Goal FOREMAN recovery scope sha256',
    )
    && request.reason === reason
    && request.incident_ref === incidentRef
    && probeObservationRequestMatchesBinding(
      request.probe_observation || null,
      {
        ...options,
        role: 'FOREMAN',
        taskId: options.taskId,
        threadId: options.threadId,
        hostId,
        attempt: Number(options.attempt),
      },
    );
}

function recoverPreparedRecoveryBatch(paths, rootRecoveryId, options) {
  const attempt = Number(options.attempt);
  const finalFiles = recoveryBatchPaths(paths, rootRecoveryId);
  return recoverPreparedIntent({
    parent: paths.foremanRecoveryBatches,
    kind: 'foreman-recovery',
    stableId: rootRecoveryId,
    finalDirectory: finalFiles.dir,
    label: `FOREMAN recovery ${rootRecoveryId}`,
    validateCapabilityName: () => new RegExp(
      `^foreman-${attempt}-[0-9a-f]{24}\\.cap$`,
    ),
    readRecord: (file) => readRecoveryBatchRecord(
      file,
      'FOREMAN_RECOVERY_INTENT',
      options.goalId,
      rootRecoveryId,
    ),
    validatePreparedBinding: (intent) => {
      const request = intent.request;
      assertControl(
        request
          && intent.request_sha256 === hashObject(request)
          && intent.prepared_request_sha256 === intent.request_sha256
          && intent.goal_scope
          && intent.goal_scope_sha256 === intent.goal_scope.scope_sha256
          && hashObject(recoveryScopeCore(intent.goal_scope))
            === intent.goal_scope_sha256
          && hashObject(intent.target_task_ids)
            === hashObject(request.target_task_ids)
          && hashObject(intent.source_task_ids)
            === hashObject(request.source_task_ids)
          && (intent.adoption_target_task_id || null)
            === (request.adoption_target_task_id || null)
          && hashObject(intent.successor) === hashObject(request.successor),
        'PREPARED_STAGING_INVALID',
        `FOREMAN recovery ${rootRecoveryId} prepared request/scope seal 不匹配`,
      );
    },
    matchIncoming: (intent) => (
      recoveryIntentMatchesOptions(intent, rootRecoveryId, options)
    ),
  });
}

function publishRecoveryBatchIntent(
  cwd,
  paths,
  rootRecoveryId,
  attempt,
  preparedRequestSha256,
  buildUnsignedIntent,
) {
  ensureDir(paths.foremanRecoveryBatches);
  const finalFiles = recoveryBatchPaths(paths, rootRecoveryId);
  const capabilityPattern = new RegExp(
    `^foreman-${attempt}-[0-9a-f]{24}\\.cap$`,
  );
  cleanupExactUnsealedPreparedIntent(
    paths.foremanRecoveryBatches,
    'foreman-recovery',
    rootRecoveryId,
    preparedRequestSha256,
    capabilityPattern,
    `FOREMAN recovery ${rootRecoveryId}`,
  );
  assertControl(
    !fs.existsSync(finalFiles.dir),
    'EVENT_ID_CONFLICT',
    `root recovery batch ${rootRecoveryId} 已存在`,
  );
  const staging = path.join(
    paths.foremanRecoveryBatches,
    preparedStagingName(
      'foreman-recovery',
      rootRecoveryId,
      preparedRequestSha256,
    ),
  );
  fs.mkdirSync(staging, { mode: 0o700 });
  const stagedCapability = createCapabilityFile(staging, `foreman-${attempt}`);
  const finalCapabilityFile = path.join(
    finalFiles.dir,
    path.basename(stagedCapability.file),
  );
  const intent = sealedRecoveryBatchRecord(buildUnsignedIntent({
    file: finalCapabilityFile,
    sha256: stagedCapability.sha256,
  }));
  atomicWriteJson(path.join(staging, 'intent.json'), intent);
  fsyncDirectory(staging);
  maybeInjectRecoveryBatchFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_STAGING_SEAL',
    'TEST_FAULT_AFTER_RECOVERY_STAGING_SEAL',
    'injected failure after sealed FOREMAN recovery staging fsync',
  );
  fs.renameSync(staging, finalFiles.dir);
  fsyncDirectory(paths.foremanRecoveryBatches);
  return {
    intent,
    capability: {
      file: fs.realpathSync(finalCapabilityFile),
      sha256: stagedCapability.sha256,
    },
  };
}

function pendingRecoveryBatches(
  paths,
  goalId,
  { includePreparedStaging = true } = {},
) {
  if (!fs.existsSync(paths.foremanRecoveryBatches)) return [];
  const pending = [];
  for (const rootRecoveryId of fs.readdirSync(paths.foremanRecoveryBatches).sort()) {
    if (rootRecoveryId.startsWith('.init-')) continue;
    const entry = path.join(paths.foremanRecoveryBatches, rootRecoveryId);
    const stat = fs.lstatSync(entry);
    assertControl(stat.isDirectory() && !stat.isSymbolicLink(), 'CORRUPT_STORE', 'FOREMAN recovery batch entry 非普通目录');
    const batch = recoveryBatchState(paths, goalId, rootRecoveryId);
    assertControl(batch.intent, 'CORRUPT_STORE', `FOREMAN recovery batch ${rootRecoveryId} 缺 intent`);
    if (!batch.commit) pending.push({ root_recovery_id: rootRecoveryId, ...batch });
  }
  if (includePreparedStaging) {
    const root = path.dirname(path.dirname(paths.dir));
    const {
      listPendingGoalRecoveryStagings,
    } = require('./pending-operations');
    for (const operation of listPendingGoalRecoveryStagings(root, goalId)) {
      const intent = readRecoveryBatchRecord(
        operation.marker_file,
        'FOREMAN_RECOVERY_INTENT',
        goalId,
        operation.root_recovery_id,
      );
      pending.push({
        root_recovery_id: operation.root_recovery_id,
        files: {
          dir: operation.staging_directory,
          intent: operation.marker_file,
          commit: null,
        },
        intent,
        commit: null,
        staged: true,
      });
    }
  }
  assertControl(pending.length <= 1, 'CORRUPT_STORE', 'Goal 同时存在多个未完成 FOREMAN recovery batch');
  return pending;
}

function assertFrozenInputs(cwd, loaded, taskId = null) {
  const worktree = repoRoot(cwd);
  const commonGitDir = path.resolve(git(worktree, ['rev-parse', '--path-format=absolute', '--git-common-dir']));
  assertControl(
    path.dirname(commonGitDir) === path.resolve(loaded.meta.repository_root),
    'REPOSITORY_ROOT_MISMATCH',
    '当前 worktree 不属于 Goal 初始化仓库',
  );
  for (const [name, protocol] of Object.entries(loaded.manifest.protocol || {})) {
    const file = path.resolve(worktree, protocol.path);
    assertControl(fs.existsSync(file), 'PROTOCOL_DRIFT', `${name} protocol 缺失: ${protocol.path}`);
    const protocolStat = fs.lstatSync(file);
    assertControl(
      protocolStat.isFile() && !protocolStat.isSymbolicLink(),
      'PROTOCOL_DRIFT',
      `${name} protocol 必须是普通文件: ${protocol.path}`,
    );
    realpathWithin(worktree, file, `${name} protocol`);
    assertControl(hashFile(file) === protocol.sha256, 'PROTOCOL_DRIFT', `${name} protocol bytes 已漂移: ${protocol.path}`);
  }
  const taskIds = taskId ? [taskId] : loaded.manifest.tasks.map((task) => task.id);
  for (const id of taskIds) {
    const state = loaded.snapshot.tasks[id];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${id}`);
    const packetFile = path.resolve(worktree, state.packet.path);
    assertControl(fs.existsSync(packetFile), 'PACKET_DRIFT', `task ${id} packet 缺失: ${state.packet.path}`);
    const packetStat = fs.lstatSync(packetFile);
    assertControl(
      packetStat.isFile() && !packetStat.isSymbolicLink(),
      'PACKET_DRIFT',
      `task ${id} packet 必须是普通文件: ${state.packet.path}`,
    );
    realpathWithin(worktree, packetFile, `task ${id} packet`);
    assertControl(hashFile(packetFile) === state.packet.sha256, 'PACKET_DRIFT', `task ${id} packet bytes 已漂移: ${state.packet.path}`);
    const manifestTask = loaded.manifest.tasks.find((task) => task.id === id);
    if (manifestTask && manifestTask.p1) {
      const authorityFile = path.resolve(worktree, manifestTask.p1.authority.path);
      assertControl(
        fs.existsSync(authorityFile),
        'P1_AUTHORITY_DRIFT',
        `task ${id} P1 authority 缺失: ${manifestTask.p1.authority.path}`,
      );
      const authorityStat = fs.lstatSync(authorityFile);
      assertControl(
        authorityStat.isFile() && !authorityStat.isSymbolicLink(),
        'P1_AUTHORITY_DRIFT',
        `task ${id} P1 authority 必须是普通文件`,
      );
      realpathWithin(worktree, authorityFile, `task ${id} P1 authority`);
      assertControl(
        hashFile(authorityFile) === manifestTask.p1.authority.sha256,
        'P1_AUTHORITY_DRIFT',
        `task ${id} P1 authority bytes 已漂移: ${manifestTask.p1.authority.path}`,
      );
      if (state.p1.commit_sha) {
        assertMechanicalP1CommitRef(worktree, loaded, state);
      }
    }
  }
  const sourceManifestFile = path.resolve(
    worktree,
    loaded.manifest.source_manifest,
  );
  assertControl(
    fs.existsSync(sourceManifestFile),
    'SOURCE_MANIFEST_DRIFT',
    `Goal source manifest 缺失: ${loaded.manifest.source_manifest}`,
  );
  const sourceManifestStat = fs.lstatSync(sourceManifestFile);
  assertControl(
    sourceManifestStat.isFile() && !sourceManifestStat.isSymbolicLink(),
    'SOURCE_MANIFEST_DRIFT',
    `Goal source manifest 必须是普通文件: ${loaded.manifest.source_manifest}`,
  );
  realpathWithin(worktree, sourceManifestFile, 'Goal source manifest');
  let currentManifest;
  try {
    currentManifest = validateManifest(
      readJson(sourceManifestFile, 'Goal source manifest'),
      sourceManifestFile,
      worktree,
    );
  } catch (error) {
    throw new ControlError(
      'SOURCE_MANIFEST_DRIFT',
      `Goal source manifest 当前 bytes 无法重建 sealed manifest: ${error.code || error.message}`,
    );
  }
  assertControl(
    currentManifest.manifest_sha256 === loaded.manifest.manifest_sha256,
    'SOURCE_MANIFEST_DRIFT',
    'Goal source manifest normalized digest 与 sealed manifest 不一致',
  );
  return worktree;
}

function validatePacketUpdateAtBoundary(cwd, loaded, taskId, event) {
  const worktree = repoRoot(cwd);
  const previousHead = loaded.snapshot.tasks[taskId].full_head;
  const commonGitDir = path.resolve(git(worktree, ['rev-parse', '--path-format=absolute', '--git-common-dir']));
  assertControl(path.dirname(commonGitDir) === path.resolve(loaded.meta.repository_root), 'REPOSITORY_ROOT_MISMATCH', '当前 worktree 不属于 Goal 初始化仓库');
  const packetFile = path.resolve(worktree, event.payload.path);
  realpathWithin(worktree, packetFile, 'packet update path');
  assertControl(hashFile(packetFile) === normalizePacketHash(event.payload.sha256), 'PACKET_HASH_MISMATCH', 'PACKET_UPDATED 声明 hash 与文件不一致');
  assertControl(git(worktree, ['rev-parse', 'HEAD']) === event.full_head, 'STALE_HEAD', 'PACKET_UPDATED full_head 必须是当前 worktree HEAD');
  assertControl(git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '', 'DIRTY_WORKTREE', 'PACKET_UPDATED 只接受 clean committed packet');
  git(worktree, ['cat-file', '-e', `${previousHead}^{commit}`]);
  git(worktree, ['cat-file', '-e', `${event.full_head}^{commit}`]);
  try {
    git(worktree, ['merge-base', '--is-ancestor', previousHead, event.full_head]);
  } catch {
    assertControl(false, 'PACKET_HEAD_NOT_DESCENDANT', 'PACKET_UPDATED full_head 必须是旧 task full_head 的后代，禁止用历史改写切断已审计 lineage');
  }
  let committedPacket;
  try {
    committedPacket = execFileSync('git', ['show', `${event.full_head}:${event.payload.path}`], {
      cwd: worktree,
      encoding: null,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: readOnlyGitEnvironment(),
    });
  } catch (error) {
    assertControl(false, 'PACKET_NOT_COMMITTED', `packet 不存在于 event.full_head: ${String(error.stderr || error.message).trim()}`);
  }
  assertControl(`sha256:${sha256(committedPacket)}` === normalizePacketHash(event.payload.sha256), 'PACKET_COMMIT_MISMATCH', 'event.full_head 中的 packet blob 与声明 hash 不一致');
  const manifestTask = loaded.manifest.tasks.find((candidate) => candidate.id === taskId);
  assertControl(manifestTask, 'UNKNOWN_TASK', `未知 task ${taskId}`);
  const { nonTerminalTaskLeasesUnlocked } = require('./resources');
  const liveLeases = nonTerminalTaskLeasesUnlocked(controlRoot(cwd), loaded.manifest.goal_id, taskId);
  assertControl(
    liveLeases.length === 0,
    'PACKET_UPDATE_RESOURCE_LEASES_ACTIVE',
    `PACKET_UPDATED 会终止旧执行身份；须先由 owner 正常 release 或由 broker 隔离 ${liveLeases.length} 个非终态 lease`,
  );
}

function mechanicalP1RequiredStartHeadFrom(
  manifest,
  snapshot,
  goalInputHead,
  task,
) {
  if (!task.p1) return null;
  if (task.dependencies.length === 0) {
    assertFullSha(goalInputHead, 'sealed goal_input_head');
    return goalInputHead;
  }
  const byId = new Map(
    manifest.tasks.map((candidate) => [candidate.id, candidate]),
  );
  const highestDependency = [...task.dependencies]
    .map((dependencyId) => byId.get(dependencyId))
    .sort((left, right) => left.integration_order - right.integration_order)
    .at(-1);
  assertControl(
    highestDependency,
    'CORRUPT_STORE',
    `task ${task.id} 的 P1 dependency 不在 manifest`,
  );
  const dependencyState = snapshot.tasks[highestDependency.id];
  if (
    !dependencyState
      || !dependencyState.merge
      || typeof dependencyState.merge.main_merge_sha !== 'string'
  ) {
    return null;
  }
  assertFullSha(
    dependencyState.merge.main_merge_sha,
    `${highestDependency.id}.merge.main_merge_sha`,
  );
  return dependencyState.merge.main_merge_sha;
}

function mechanicalP1RequiredStartHead(loaded, task) {
  return mechanicalP1RequiredStartHeadFrom(
    loaded.manifest,
    loaded.snapshot,
    loaded.meta.goal_input_head,
    task,
  );
}

function mechanicalP1CommitRef(goalId, taskId, taskCycle) {
  assertControl(
    Number.isSafeInteger(taskCycle) && taskCycle > 0,
    'CORRUPT_STORE',
    `机械 P1 task_cycle 非法: ${taskCycle}`,
  );
  return [
    'refs/heads/codex/goal-control/p1',
    sha256(goalId),
    sha256(taskId),
    `cycle-${taskCycle}`,
  ].join('/');
}

function readExactGitRef(worktree, ref) {
  try {
    return execFileSync(
      'git',
      ['rev-parse', '--verify', '--quiet', ref],
      {
        cwd: worktree,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: readOnlyGitEnvironment(),
      },
    ).trim();
  } catch (error) {
    if (error && error.status === 1) return null;
    const detail = String(error.stderr || error.message || '').trim();
    throw new ControlError(
      'GIT_FAILED',
      `git rev-parse --verify ${ref} 失败${detail ? `: ${detail}` : ''}`,
    );
  }
}

function assertMechanicalP1CommitRef(cwd, loaded, state) {
  const worktree = repoRoot(cwd);
  const expectedRef = mechanicalP1CommitRef(
    loaded.manifest.goal_id,
    state.task_id,
    state.task_cycle,
  );
  assertControl(
    state.p1.commit_ref === expectedRef
      && state.p1.commit_branch
        === expectedRef.slice('refs/heads/'.length),
    'P1_COMMIT_REF_INVALID',
    `task ${state.task_id} durable P1 ref 与 task cycle 不一致`,
  );
  assertFullSha(state.p1.commit_sha, `${state.task_id}.p1.commit_sha`);
  git(worktree, ['cat-file', '-e', `${state.p1.commit_sha}^{commit}`]);
  const actual = readExactGitRef(worktree, expectedRef);
  assertControl(
    actual === state.p1.commit_sha,
    actual
      ? 'P1_COMMIT_REF_CONFLICT'
      : 'P1_COMMIT_REF_MISSING',
    actual
      ? `${expectedRef} 指向 ${actual}，预期 ${state.p1.commit_sha}`
      : `${expectedRef} 尚未发布；须 exact retry P1_COMMITTED 修复`,
  );
  return expectedRef;
}

function verifyLegacyMechanicalP1CommitRef(
  cwd,
  loaded,
  state,
) {
  const worktree = repoRoot(cwd);
  const expectedRef = mechanicalP1CommitRef(
    loaded.manifest.goal_id,
    state.task_id,
    state.task_cycle,
  );
  assertControl(
    state.p1
      && state.p1.commit_sha
      && state.p1.commit_ref === expectedRef,
    'P1_COMMIT_REF_INVALID',
    'accepted P1_COMMITTED state 缺 deterministic durable ref binding',
  );
  assertFullSha(state.p1.commit_sha, `${state.task_id}.p1.commit_sha`);
  git(worktree, ['cat-file', '-e', `${state.p1.commit_sha}^{commit}`]);
  const current = readExactGitRef(worktree, expectedRef);
  assertControl(
    current !== null,
    'P1_COMMIT_LEGACY_MIGRATION_REQUIRED',
    `legacy accepted P1 ref ${expectedRef} 缺失；正常 decoder 禁止猜测旧 Git lock 或直接修复，须走显式 audited migration`,
  );
  assertControl(
    current === state.p1.commit_sha,
    'P1_COMMIT_REF_CONFLICT',
    `${expectedRef} 已指向 ${current}，禁止覆盖为 ${state.p1.commit_sha}`,
  );
  return assertMechanicalP1CommitRef(worktree, loaded, state);
}

function mechanicalP1TaskAnchor(loaded, state) {
  return {
    phase: state.phase,
    state_revision: state.state_revision,
    control_epoch: loaded.control.epoch,
    task_cycle: state.task_cycle,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    base_head: state.base_head,
    full_head: state.full_head,
    prior_event_sha256: loaded.lastEventHashes[state.task_id] || null,
  };
}

function mechanicalP1Authority(session) {
  return {
    role: session.role,
    thread_id: session.thread_id,
    host_id: session.host_id,
    attempt: session.attempt,
    capability_file: session.capability_file,
    capability_sha256: session.capability_sha256,
    lease_until: session.lease_until,
  };
}

function authorizeHistoricalMechanicalP1Capability(
  snapshot,
  capabilityFile,
  expectedAuthoritySha256,
  options,
) {
  const supplied = readCapabilityFile(capabilityFile);
  const states = options.goalWide
    ? Object.values(snapshot.tasks || {})
    : [snapshot.tasks[options.taskId]].filter(Boolean);
  const candidates = states.flatMap((state) => [
    ...Object.values(state.sessions || {}),
    ...Object.values(state.session_history || {}).flat(),
  ]).filter((session) => (
    session.role === options.role
      && session.thread_id === options.threadId
      && (
        !options.hostId
          || session.host_id === options.hostId
      )
      && session.capability_file === supplied.file
      && hashesEqual(session.capability_sha256, supplied.sha256)
  ));
  assertControl(
    candidates.length > 0,
    'CAPABILITY_INVALID',
    `capability 不属于 original ${options.role}:${options.threadId} session`,
  );
  const authoritySha256 = normalizeHash(
    expectedAuthoritySha256,
    `original ${options.role} authority sha256`,
  );
  const exact = candidates.filter((session) => (
    hashObject(mechanicalP1Authority(session)) === authoritySha256
  ));
  assertControl(
    exact.length > 0,
    'CAPABILITY_INVALID',
    `capability 不属于 prepared operation 的 original ${options.role} authority`,
  );
  assertControl(
    exact.every((session) => (
      hashObject(mechanicalP1Authority(session))
        === hashObject(mechanicalP1Authority(exact[0]))
    )),
    'CORRUPT_STORE',
    `historical ${options.role} capability identity 分叉`,
  );
  return exact[0];
}

function assertMechanicalP1IntentAnchor(loaded, state, intent) {
  const anchor = intent.task_anchor;
  const current = mechanicalP1TaskAnchor(loaded, state);
  assertControl(
    anchor.phase === 'P1_APPROVED'
      && anchor.phase === current.phase
      && anchor.state_revision === current.state_revision
      && anchor.control_epoch === current.control_epoch
      && anchor.task_cycle === current.task_cycle
      && anchor.packet.revision === current.packet.revision
      && anchor.packet.sha256 === current.packet.sha256
      && anchor.base_head === current.base_head
      && anchor.full_head === current.full_head
      && anchor.prior_event_sha256 === current.prior_event_sha256,
    'P1_COMMIT_INTENT_DIVERGED',
    `P1 commit intent ${intent.event_id} 后 task state 已漂移`,
  );
  assertControl(
    intent.request.expected_state_revision === anchor.state_revision
      && intent.request.control_epoch === anchor.control_epoch
      && intent.request.packet.revision === anchor.packet.revision
      && intent.request.packet.sha256 === anchor.packet.sha256
      && intent.request.base_head === anchor.base_head
      && intent.request.full_head === intent.ref_binding.new_commit
      && intent.task_cycle === anchor.task_cycle,
    'CORRUPT_STORE',
    `P1 commit intent ${intent.event_id} request/state anchor 漂移`,
  );
}

function assertMechanicalP1ObjectBoundary(cwd, loaded, state, event) {
  const manifestTask = loaded.manifest.tasks.find(
    (candidate) => candidate.id === state.task_id,
  );
  assertControl(
    manifestTask && manifestTask.p1,
    'CORRUPT_STORE',
    `task ${state.task_id} 缺 mechanical P1 policy`,
  );
  const requiredStartHead = mechanicalP1RequiredStartHead(
    loaded,
    manifestTask,
  );
  assertControl(
    requiredStartHead
      && state.p1.required_start_head === requiredStartHead
      && state.base_head === requiredStartHead,
    'P1_START_HEAD_MISMATCH',
    'P1 prepared retry required_start_head 漂移',
  );
  git(cwd, ['cat-file', '-e', `${event.full_head}^{commit}`]);
  const commitLineage = git(
    cwd,
    ['rev-list', '--parents', '-n', '1', event.full_head],
  ).split(/\s+/);
  assertControl(
    commitLineage.length === 2
      && commitLineage[1] === requiredStartHead,
    'P1_COMMIT_LINEAGE_MISMATCH',
    `P1 commit 必须是 parent=${requiredStartHead} 的单一新 commit`,
  );
  const changedPaths = gitNullSeparatedPaths(
    cwd,
    [
      'diff',
      '--name-only',
      '-z',
      requiredStartHead,
      event.full_head,
      '--',
    ],
  );
  const forbiddenPaths = changedPaths.filter(
    (relativePath) => (
      !isAllowedP1ArtifactPath(manifestTask.p1, relativePath)
    ),
  );
  assertControl(
    forbiddenPaths.length === 0,
    'P1_COMMIT_SCOPE_VIOLATION',
    `P1 commit 含 artifact_root 外改动: ${
      forbiddenPaths.slice(0, 10).join(', ')
    }`,
  );
  const artifacts = p1ArtifactPaths(manifestTask.p1);
  const bindings = [
    [
      artifacts.plan,
      state.p1.plan_sha256,
      event.payload.plan_path,
      event.payload.plan_sha256,
    ],
    [
      artifacts.context,
      state.p1.context_sha256,
      event.payload.context_path,
      event.payload.context_sha256,
    ],
  ];
  for (const [
    relativePath,
    stateHash,
    eventPath,
    eventHash,
  ] of bindings) {
    assertControl(
      eventPath === relativePath
        && normalizePacketHash(eventHash) === stateHash,
      'P1_COMMIT_MISMATCH',
      `P1 commit ${relativePath} binding 与 approved state 不一致`,
    );
    let blob;
    try {
      blob = execFileSync(
        'git',
        ['cat-file', 'blob', `${event.full_head}:${relativePath}`],
        {
          cwd,
          env: readOnlyGitEnvironment(),
        },
      );
    } catch {
      assertControl(
        false,
        'P1_ARTIFACT_NOT_COMMITTED',
        `P1_COMMITTED ${relativePath} 不存在于 commit`,
      );
    }
    assertControl(
      `sha256:${sha256(blob)}` === stateHash,
      'P1_ARTIFACT_MISMATCH',
      `P1_COMMITTED ${relativePath} blob 与批准 digest 不一致`,
    );
  }
  const inventory = committedP1ArtifactInventory(
    cwd,
    manifestTask.p1,
    event.full_head,
  );
  assertControl(
    inventory.sha256 === state.p1.artifact_manifest_sha256
      && inventory.sha256 === normalizePacketHash(
        event.payload.artifact_manifest_sha256,
      ),
    'P1_ARTIFACT_MANIFEST_MISMATCH',
    'P1 prepared commit artifact inventory 与批准版本不一致',
  );
  const expectedRef = mechanicalP1CommitRef(
    loaded.manifest.goal_id,
    state.task_id,
    state.task_cycle,
  );
  assertControl(
    event.payload.p1_worktree === state.p1.worktree
      && event.payload.p1_branch === state.p1.branch
      && event.payload.approval_event_id === state.p1.approval_event_id
      && event.payload.p1_commit_ref === expectedRef,
    'P1_COMMIT_MISMATCH',
    'P1 prepared commit payload 与批准 worktree/branch/approval/ref 不一致',
  );
  return inventory;
}

function assertMechanicalP1CycleNotAbandoned(
  root,
  loaded,
  state,
  event,
) {
  if (event.type !== 'P1_COMMITTED') return;
  const tombstone = state.p1 && state.p1.commit_abandonment;
  if (tombstone) {
    assertControl(
      tombstone.prepared_event_id !== event.event_id,
      'P1_COMMIT_ABANDONED',
      `P1_COMMITTED ${event.event_id} 已由 append-only abandonment tombstone 永久废止`,
    );
    const currentRef = mechanicalP1CommitRef(
      loaded.manifest.goal_id,
      state.task_id,
      state.task_cycle,
    );
    assertControl(
      tombstone.task_cycle !== state.task_cycle
        || tombstone.commit_ref !== currentRef,
      'P1_RESTART_REQUIRED',
      `P1 cycle ${state.task_cycle} 已 abandon；须 P1_RESTARTED 后使用新 cycle/ref`,
    );
  }
  const receipts = abandonmentReceiptsForTask(
    root,
    loaded.manifest.goal_id,
    state.task_id,
  );
  const exact = receipts.find(
    (receipt) => receipt.prepared_event_id === event.event_id,
  );
  assertControl(
    !exact,
    'P1_COMMIT_ABANDONED',
    `P1_COMMITTED ${event.event_id} 已由 audited abandonment 永久废止`,
  );
  const currentRef = mechanicalP1CommitRef(
    loaded.manifest.goal_id,
    state.task_id,
    state.task_cycle,
  );
  const sameCycle = receipts.find(
    (receipt) => (
      receipt.task_cycle === state.task_cycle
        && receipt.commit_ref === currentRef
    ),
  );
  assertControl(
    !sameCycle,
    'P1_RESTART_REQUIRED',
    `P1 cycle ${state.task_cycle} 已 abandon；须 P1_RESTARTED 后使用新 cycle/ref`,
  );
}

function buildMechanicalP1CommitIntent(
  cwd,
  loaded,
  state,
  eventRequest,
  event,
  actorAuthority,
  inventory,
) {
  const repository = repositoryIdentity(
    cwd,
    loaded.meta.repository_root,
  );
  const ref = mechanicalP1CommitRef(
    loaded.manifest.goal_id,
    state.task_id,
    state.task_cycle,
  );
  return {
    schema_version: 1,
    kind: 'P1_COMMIT_REF_INTENT',
    goal_id: loaded.manifest.goal_id,
    task_id: state.task_id,
    task_cycle: state.task_cycle,
    event_id: event.event_id,
    request: eventRequest,
    request_sha256: event.input_sha256,
    task_anchor: mechanicalP1TaskAnchor(loaded, state),
    acceptance_authority: mechanicalP1Authority(actorAuthority),
    p1_binding: {
      plan_path: state.p1.plan_path,
      plan_sha256: state.p1.plan_sha256,
      context_path: state.p1.context_path,
      context_sha256: state.p1.context_sha256,
      artifact_manifest: inventory ? inventory.manifest : null,
      artifact_manifest_sha256: inventory
        ? inventory.sha256
        : state.p1.artifact_manifest_sha256,
      approval_event_id: state.p1.approval_event_id,
      p1_worktree: state.p1.worktree,
      p1_branch: state.p1.branch,
    },
    ref_binding: {
      ...repository,
      expected_old_ref: '0'.repeat(40),
      new_commit: event.full_head,
      commit_ref: ref,
    },
    accepted_at: event.accepted_at,
  };
}

function maybeInjectP1CommitFault(cwd, name, code, message) {
  if (process.env[name] === undefined) return;
  assertControl(
    process.env[name] === '1',
    'INVALID_TEST_FAULT',
    `${name} 只能是 1`,
  );
  assertIsolatedTestMode(cwd);
  throw new ControlError(code, message);
}

function finalizeAcceptedMechanicalP1Transaction(
  cwd,
  root,
  loaded,
  taskId,
  accepted,
) {
  const state = loaded.snapshot.tasks[taskId];
  const receipt = readP1CommitReceipt(
    root,
    loaded.manifest.goal_id,
    taskId,
    accepted.event_id,
  );
  const prepared = readP1CommitIntent(
    root,
    loaded.manifest.goal_id,
    taskId,
    accepted.event_id,
  );
  if (!prepared) {
    assertControl(
      !accepted.p1_commit_transaction,
      'CORRUPT_STORE',
      `accepted P1 transaction ${accepted.event_id} 缺 retained intent/bundle`,
    );
    if (receipt) {
      assertControl(
        receipt.request_sha256 === accepted.input_sha256
          && receipt.accepted_event_sha256 === accepted.event_sha256
          && receipt.commit_sha === state.p1.commit_sha
          && receipt.commit_ref === state.p1.commit_ref,
        'CORRUPT_STORE',
        `P1 completion ${accepted.event_id} 与 accepted event/state 漂移`,
      );
      assertMechanicalP1CommitRef(cwd, loaded, state);
      return receipt;
    }
    // A legacy accepted event has no durable ownership witness for a missing
    // Git ref or any residual ref lock. Normal decoding therefore verifies
    // only; an audited migration must seal ownership before any repair.
    verifyLegacyMechanicalP1CommitRef(
      cwd,
      loaded,
      state,
    );
    return null;
  }
  const { intent } = prepared;
  assertControl(
    intent.request_sha256 === accepted.input_sha256
      && intent.ref_binding.new_commit === state.p1.commit_sha
      && intent.ref_binding.commit_ref === state.p1.commit_ref,
    'CORRUPT_STORE',
    `P1 intent ${accepted.event_id} 与 accepted event/state 漂移`,
  );
  restoreP1CommitObject(cwd, prepared, intent.ref_binding.new_commit);
  publishP1CommitRef(cwd, intent);
  return completeP1CommitTransaction(
    root,
    loaded.manifest.goal_id,
    taskId,
    intent,
    accepted,
  );
}

function mechanicalP1Dependencies(loaded, task) {
  return task.dependencies.map((dependencyId) => ({
    id: dependencyId,
    phase: loaded.snapshot.tasks[dependencyId].phase,
  }));
}

function assertMechanicalP1DependenciesArchived(loaded, task) {
  const dependencies = mechanicalP1Dependencies(loaded, task);
  const blocked = dependencies.filter((dependency) => dependency.phase !== 'ARCHIVED');
  assertControl(
    blocked.length === 0,
    'P1_DEPENDENCY_NOT_ARCHIVED',
    `${task.id} P1 依赖尚未 ARCHIVED: ${blocked
      .map((dependency) => `${dependency.id}:${dependency.phase}`)
      .join(',')}`,
  );
}

function mechanicalP1LinkedCheckout(cwd, loaded, requiredStartHead = null) {
  const worktree = repoRoot(cwd);
  const canonicalWorktree = fs.realpathSync(worktree);
  const gitDirectory = path.resolve(git(
    worktree,
    ['rev-parse', '--path-format=absolute', '--git-dir'],
  ));
  const commonGitDirectory = path.resolve(git(
    worktree,
    ['rev-parse', '--path-format=absolute', '--git-common-dir'],
  ));
  assertControl(
    path.dirname(commonGitDirectory)
      === path.resolve(loaded.meta.repository_root),
    'REPOSITORY_ROOT_MISMATCH',
    '当前 worktree 不属于 Goal 初始化仓库',
  );
  assertControl(
    gitDirectory !== commonGitDirectory,
    'P1_LINKED_WORKTREE_REQUIRED',
    '机械 P1 只能在拥有专属 gitdir 的 linked worktree 执行',
  );
  const branch = git(worktree, ['branch', '--show-current']);
  assertControl(
    branch.length > 0,
    'P1_BRANCH_REQUIRED',
    '机械 P1 不接受 detached HEAD worktree',
  );
  assertControl(
    branch !== loaded.manifest.repository.base_branch,
    'P1_BASE_BRANCH_FORBIDDEN',
    `机械 P1 禁止直接使用 base branch ${loaded.manifest.repository.base_branch}`,
  );
  if (requiredStartHead) {
    assertControl(
      git(worktree, ['rev-parse', 'HEAD']) === requiredStartHead,
      'P1_START_HEAD_MISMATCH',
      `机械 P1 worktree HEAD 必须是 ${requiredStartHead}`,
    );
  }
  return {
    worktree,
    canonicalWorktree,
    branch,
  };
}

function p1ArtifactPaths(policy) {
  return {
    plan: `${policy.artifact_root}/plan.md`,
    context: `${policy.artifact_root}/context.md`,
    refs: `${policy.artifact_root}/_ref`,
  };
}

function isAllowedP1ArtifactPath(policy, relativePath) {
  const artifacts = p1ArtifactPaths(policy);
  return relativePath === artifacts.plan
    || relativePath === artifacts.context
    || relativePath.startsWith(`${artifacts.refs}/`);
}

function gitNullSeparatedPaths(worktree, args) {
  let output;
  try {
    output = execFileSync('git', args, {
      cwd: worktree,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: readOnlyGitEnvironment(),
    });
  } catch (error) {
    throw new ControlError(
      'GIT_FAILED',
      `git ${args.join(' ')} 失败: ${String(error.stderr || error.message).trim()}`,
    );
  }
  return output.split('\0').filter((entry) => entry.length > 0);
}

function assertP1DirtyInventory(worktree, policy) {
  const dirtyPaths = new Set([
    ...gitNullSeparatedPaths(
      worktree,
      ['diff', '--name-only', '-z', 'HEAD', '--'],
    ),
    ...gitNullSeparatedPaths(
      worktree,
      ['ls-files', '--others', '--exclude-standard', '-z', '--'],
    ),
  ]);
  const forbidden = [...dirtyPaths]
    .filter((relativePath) => !isAllowedP1ArtifactPath(policy, relativePath))
    .sort();
  assertControl(
    forbidden.length === 0,
    'P1_DIRTY_SCOPE_VIOLATION',
    `P1 worktree 含 artifact_root 外改动: ${forbidden.slice(0, 10).join(', ')}`,
  );
  return [...dirtyPaths].sort();
}

function worktreeP1ArtifactInventory(worktree, policy) {
  const artifacts = p1ArtifactPaths(policy);
  const files = [];
  const addFile = (absolute, relative) => {
    let stat;
    try {
      stat = fs.lstatSync(absolute);
    } catch (error) {
      throw new ControlError(
        'P1_ARTIFACT_MISSING',
        `P1 artifact 缺失: ${relative} (${error.message})`,
      );
    }
    assertControl(
      stat.isFile() && !stat.isSymbolicLink(),
      'P1_ARTIFACT_TYPE_INVALID',
      `P1 artifact 必须是普通文件: ${relative}`,
    );
    realpathWithin(worktree, absolute, `P1 artifact ${relative}`);
    files.push({
      path: relative,
      mode: (stat.mode & 0o111) === 0 ? '100644' : '100755',
      sha256: hashFile(absolute),
    });
  };
  addFile(path.resolve(worktree, artifacts.plan), artifacts.plan);
  addFile(path.resolve(worktree, artifacts.context), artifacts.context);
  const refsDirectory = path.resolve(worktree, artifacts.refs);
  if (fs.existsSync(refsDirectory)) {
    const visit = (directory) => {
      const directoryStat = fs.lstatSync(directory);
      assertControl(
        directoryStat.isDirectory() && !directoryStat.isSymbolicLink(),
        'P1_ARTIFACT_TYPE_INVALID',
        `P1 _ref 路径必须是普通目录: ${path.relative(worktree, directory)}`,
      );
      realpathWithin(worktree, directory, 'P1 _ref directory');
      for (const name of fs.readdirSync(directory).sort()) {
        const absolute = path.join(directory, name);
        const stat = fs.lstatSync(absolute);
        if (stat.isDirectory() && !stat.isSymbolicLink()) {
          visit(absolute);
          continue;
        }
        const relative = path.relative(worktree, absolute).split(path.sep).join('/');
        addFile(absolute, relative);
      }
    };
    visit(refsDirectory);
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  const manifest = {
    schema_version: 1,
    artifact_root: policy.artifact_root,
    files,
  };
  return {
    manifest,
    sha256: hashObject(manifest),
  };
}

function committedP1ArtifactInventory(worktree, policy, commit) {
  const artifacts = p1ArtifactPaths(policy);
  const entries = gitNullSeparatedPaths(worktree, [
    'ls-tree',
    '-r',
    '-z',
    '--full-tree',
    commit,
    '--',
    artifacts.plan,
    artifacts.context,
    artifacts.refs,
  ]);
  const files = entries.map((entry) => {
    const match = entry.match(/^([0-9]{6}) ([a-z]+) ([0-9a-f]{40})\t([\s\S]+)$/);
    assertControl(match, 'P1_ARTIFACT_TREE_INVALID', `无法解析 P1 tree entry: ${entry}`);
    const [, mode, type, objectId, relativePath] = match;
    assertControl(
      type === 'blob'
        && ['100644', '100755'].includes(mode)
        && isAllowedP1ArtifactPath(policy, relativePath),
      'P1_ARTIFACT_TREE_INVALID',
      `P1 tree 含非普通 artifact: ${relativePath}`,
    );
    const body = execFileSync('git', ['cat-file', 'blob', objectId], {
      cwd: worktree,
      encoding: null,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: readOnlyGitEnvironment(),
    });
    return {
      path: relativePath,
      mode,
      sha256: `sha256:${sha256(body)}`,
    };
  }).sort((left, right) => left.path.localeCompare(right.path));
  assertControl(
    files.some((file) => file.path === artifacts.plan)
      && files.some((file) => file.path === artifacts.context),
    'P1_ARTIFACT_NOT_COMMITTED',
    'P1 commit tree 缺 plan.md 或 context.md',
  );
  const manifest = {
    schema_version: 1,
    artifact_root: policy.artifact_root,
    files,
  };
  return {
    manifest,
    sha256: hashObject(manifest),
  };
}

function completeMechanicalP1EventPayload(
  cwd,
  loaded,
  state,
  task,
  eventType,
  suppliedPayload = {},
) {
  if (!task.p1) return suppliedPayload;
  let expected;
  if (eventType === 'START_P1') {
    assertMechanicalP1DependenciesArchived(loaded, task);
    const requiredStartHead = mechanicalP1RequiredStartHead(loaded, task);
    assertControl(
      requiredStartHead,
      'P1_START_HEAD_UNAVAILABLE',
      `${task.id} 无法解析 required_start_head`,
    );
    const checkout = mechanicalP1LinkedCheckout(
      cwd,
      loaded,
      requiredStartHead,
    );
    assertControl(
      git(
        checkout.worktree,
        ['status', '--porcelain=v1', '--untracked-files=all'],
      ) === '',
      'P1_START_WORKTREE_DIRTY',
      'START_P1 只接受 clean linked worktree',
    );
    expected = {
      required_start_head: requiredStartHead,
      p1_worktree: checkout.canonicalWorktree,
      p1_branch: checkout.branch,
    };
  } else if (eventType === 'P1_READY') {
    const requiredStartHead = mechanicalP1RequiredStartHead(loaded, task);
    const checkout = mechanicalP1LinkedCheckout(
      cwd,
      loaded,
      requiredStartHead,
    );
    assertControl(
      checkout.canonicalWorktree === state.p1.worktree
        && checkout.branch === state.p1.branch,
      'P1_WORKTREE_BINDING_MISMATCH',
      'P1_READY 必须来自 START_P1 绑定的同一 linked worktree/branch',
    );
    assertP1DirtyInventory(checkout.worktree, task.p1);
    const artifacts = p1ArtifactPaths(task.p1);
    const inventory = worktreeP1ArtifactInventory(checkout.worktree, task.p1);
    expected = {
      plan_path: artifacts.plan,
      plan_sha256: hashFile(path.resolve(checkout.worktree, artifacts.plan)),
      context_path: artifacts.context,
      context_sha256: hashFile(path.resolve(checkout.worktree, artifacts.context)),
      artifact_manifest_sha256: inventory.sha256,
      p1_worktree: checkout.canonicalWorktree,
      p1_branch: checkout.branch,
    };
  } else if (eventType === 'P1_APPROVED') {
    assertControl(
      state.p1.required_approval_ref,
      'P1_APPROVAL_REQUIRED',
      'P1_READY 尚未形成 mechanical approval binding',
    );
    expected = {
      plan_path: state.p1.plan_path,
      plan_sha256: state.p1.plan_sha256,
      context_path: state.p1.context_path,
      context_sha256: state.p1.context_sha256,
      artifact_manifest_sha256: state.p1.artifact_manifest_sha256,
      p1_worktree: state.p1.worktree,
      p1_branch: state.p1.branch,
      approval_ref: state.p1.required_approval_ref,
    };
  } else if (eventType === 'P1_COMMITTED') {
    assertControl(
      state.p1.approval_event_id,
      'P1_APPROVAL_REQUIRED',
      'P1 尚未批准',
    );
    expected = {
      plan_path: state.p1.plan_path,
      plan_sha256: state.p1.plan_sha256,
      context_path: state.p1.context_path,
      context_sha256: state.p1.context_sha256,
      artifact_manifest_sha256: state.p1.artifact_manifest_sha256,
      p1_worktree: state.p1.worktree,
      p1_branch: state.p1.branch,
      approval_event_id: state.p1.approval_event_id,
      p1_commit_ref: mechanicalP1CommitRef(
        loaded.manifest.goal_id,
        task.id,
        state.task_cycle,
      ),
    };
  } else if (eventType === 'P1_RESTARTED') {
    const captain = state.sessions.CAPTAIN;
    const recoveredFrom = captain && captain.recovered_from;
    assertControl(
      captain
        && recoveredFrom
        && recoveredFrom.role === 'CAPTAIN'
        && recoveredFrom.recovery_event_id,
      'P1_RESTART_NOT_ELIGIBLE',
      'P1_RESTARTED 缺 lost CAPTAIN recovery lineage',
    );
    assertControl(
      typeof suppliedPayload.reason === 'string'
        && suppliedPayload.reason.trim().length > 0
        && typeof suppliedPayload.incident_ref === 'string'
        && suppliedPayload.incident_ref.trim().length > 0,
      'P1_RESTART_JUSTIFICATION_REQUIRED',
      'P1_RESTARTED 需要 payload-file 提供 reason/incident_ref',
    );
    expected = {
      captain_recovery_event_id: recoveredFrom.recovery_event_id,
      predecessor_thread_id: recoveredFrom.thread_id,
      predecessor_host_id: recoveredFrom.host_id,
      predecessor_attempt: recoveredFrom.attempt,
      successor_thread_id: captain.thread_id,
      successor_host_id: captain.host_id,
      successor_attempt: captain.attempt,
      abandoned_p1_worktree: state.p1.worktree,
      abandoned_p1_branch: state.p1.branch,
      reason: suppliedPayload.reason,
      incident_ref: suppliedPayload.incident_ref,
    };
  } else {
    return suppliedPayload;
  }
  for (const [key, value] of Object.entries(suppliedPayload)) {
    assertControl(
      Object.prototype.hasOwnProperty.call(expected, key)
        && expected[key] === value,
      'P1_PAYLOAD_MISMATCH',
      `${eventType}.${key} 与机械派生值不一致`,
    );
  }
  return expected;
}

function validateP1Boundary(cwd, loaded, state, event) {
  if (!['START_P1', 'P1_READY', 'P1_COMMITTED'].includes(event.type)) return;
  const manifestTask = loaded.manifest.tasks.find(
    (candidate) => candidate.id === state.task_id,
  );
  assertControl(manifestTask, 'CORRUPT_STORE', `manifest 缺 task ${state.task_id}`);
  if (!manifestTask.p1) {
    if (event.type === 'START_P1') return;
    const legacyWorktree = repoRoot(cwd);
    const legacyCommonGitDir = path.resolve(git(legacyWorktree, ['rev-parse', '--path-format=absolute', '--git-common-dir']));
    assertControl(path.dirname(legacyCommonGitDir) === path.resolve(loaded.meta.repository_root), 'REPOSITORY_ROOT_MISMATCH', '当前 worktree 不属于 Goal 初始化仓库');
    const legacyBindings = [
      ['plan', event.payload.plan_path, normalizePacketHash(event.payload.plan_sha256)],
      ['context', event.payload.context_path, normalizePacketHash(event.payload.context_sha256)],
    ];
    if (event.type === 'P1_READY') {
      for (const [label, relativePath, expectedHash] of legacyBindings) {
        const absolute = path.resolve(legacyWorktree, relativePath);
        realpathWithin(legacyWorktree, absolute, `P1 ${label} path`);
        assertControl(hashFile(absolute) === expectedHash, 'P1_ARTIFACT_MISMATCH', `P1_READY ${label} 文件与声明 digest 不一致`);
      }
      return;
    }
    assertControl(git(legacyWorktree, ['rev-parse', 'HEAD']) === event.full_head, 'STALE_HEAD', 'P1_COMMITTED full_head 必须是当前 worktree HEAD');
    for (const [label, relativePath, expectedHash] of legacyBindings) {
      let blob;
      try {
        blob = execFileSync(
          'git',
          ['cat-file', 'blob', `${event.full_head}:${relativePath}`],
          {
            cwd: legacyWorktree,
            env: readOnlyGitEnvironment(),
          },
        );
      } catch {
        assertControl(false, 'P1_ARTIFACT_NOT_COMMITTED', `P1_COMMITTED ${label} 不存在于 current HEAD`);
      }
      assertControl(`sha256:${sha256(blob)}` === expectedHash, 'P1_ARTIFACT_MISMATCH', `P1_COMMITTED ${label} blob 与批准 digest 不一致`);
    }
    assertControl(event.payload.plan_path === state.p1.plan_path && event.payload.context_path === state.p1.context_path, 'P1_COMMIT_MISMATCH', 'P1_COMMITTED path 与当前批准产物不一致');
    return;
  }
  const worktree = repoRoot(cwd);
  assertMechanicalP1DependenciesArchived(loaded, manifestTask);
  const requiredStartHead = mechanicalP1RequiredStartHead(loaded, manifestTask);
  assertControl(
    requiredStartHead,
    'P1_START_HEAD_UNAVAILABLE',
    `${manifestTask.id} 无法解析 required_start_head`,
  );
  git(worktree, ['cat-file', '-e', `${requiredStartHead}^{commit}`]);
  if (event.type === 'START_P1') {
    const checkout = mechanicalP1LinkedCheckout(
      cwd,
      loaded,
      requiredStartHead,
    );
    assertControl(
      event.payload.required_start_head === requiredStartHead
        && event.payload.p1_worktree === checkout.canonicalWorktree
        && event.payload.p1_branch === checkout.branch,
      'P1_START_HEAD_MISMATCH',
      'START_P1 payload 与当前 linked worktree/branch/required head 不一致',
    );
    assertControl(
      git(
        checkout.worktree,
        ['status', '--porcelain=v1', '--untracked-files=all'],
      ) === '',
      'P1_START_WORKTREE_DIRTY',
      'START_P1 只接受 clean linked worktree',
    );
    return;
  }
  assertControl(
    state.p1.required_start_head === requiredStartHead
      && state.base_head === requiredStartHead,
    'P1_START_HEAD_MISMATCH',
    'P1 state 未绑定当前 required_start_head',
  );
  const bindings = [
    ['plan', event.payload.plan_path, normalizePacketHash(event.payload.plan_sha256)],
    ['context', event.payload.context_path, normalizePacketHash(event.payload.context_sha256)],
  ];
  const artifactPaths = p1ArtifactPaths(manifestTask.p1);
  assertControl(
    event.payload.plan_path === artifactPaths.plan
      && event.payload.context_path === artifactPaths.context,
    'P1_ARTIFACT_SCOPE_VIOLATION',
    `P1 plan/context 必须位于 ${manifestTask.p1.artifact_root}`,
  );
  if (event.type === 'P1_READY') {
    const checkout = mechanicalP1LinkedCheckout(
      cwd,
      loaded,
      requiredStartHead,
    );
    assertControl(
      checkout.canonicalWorktree === state.p1.worktree
        && checkout.branch === state.p1.branch
        && event.payload.p1_worktree === checkout.canonicalWorktree
        && event.payload.p1_branch === checkout.branch,
      'P1_WORKTREE_BINDING_MISMATCH',
      'P1_READY worktree/branch binding 与 START/current checkout 不一致',
    );
    assertP1DirtyInventory(worktree, manifestTask.p1);
    for (const [label, relativePath, expectedHash] of bindings) {
      const absolute = path.resolve(worktree, relativePath);
      realpathWithin(worktree, absolute, `P1 ${label} path`);
      assertControl(hashFile(absolute) === expectedHash, 'P1_ARTIFACT_MISMATCH', `P1_READY ${label} 文件与声明 digest 不一致`);
    }
    const inventory = worktreeP1ArtifactInventory(worktree, manifestTask.p1);
    assertControl(
      inventory.sha256 === normalizePacketHash(event.payload.artifact_manifest_sha256),
      'P1_ARTIFACT_MANIFEST_MISMATCH',
      `P1_READY artifact manifest digest 应为 ${inventory.sha256}`,
    );
    return;
  }

  assertControl(git(worktree, ['rev-parse', 'HEAD']) === event.full_head, 'STALE_HEAD', 'P1_COMMITTED full_head 必须是当前 worktree HEAD');
  mechanicalP1LinkedCheckout(cwd, loaded);
  assertControl(
    fs.realpathSync(worktree) === state.p1.worktree
      && git(worktree, ['branch', '--show-current']) === state.p1.branch
      && event.payload.p1_worktree === state.p1.worktree
      && event.payload.p1_branch === state.p1.branch,
    'P1_WORKTREE_BINDING_MISMATCH',
    'P1_COMMITTED 必须来自 READY 绑定的同一 canonical worktree/branch',
  );
  assertControl(
    git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '',
    'P1_COMMIT_WORKTREE_DIRTY',
    'P1_COMMITTED 只接受 clean worktree',
  );
  const commitLineage = git(
    worktree,
    ['rev-list', '--parents', '-n', '1', event.full_head],
  ).split(/\s+/);
  assertControl(
    commitLineage.length === 2 && commitLineage[1] === requiredStartHead,
    'P1_COMMIT_LINEAGE_MISMATCH',
    `P1 commit 必须是 parent=${requiredStartHead} 的单一新 commit`,
  );
  const changedPaths = gitNullSeparatedPaths(
    worktree,
    ['diff', '--name-only', '-z', requiredStartHead, event.full_head, '--'],
  );
  const forbiddenPaths = changedPaths.filter(
    (relativePath) => !isAllowedP1ArtifactPath(manifestTask.p1, relativePath),
  );
  assertControl(
    forbiddenPaths.length === 0,
    'P1_COMMIT_SCOPE_VIOLATION',
    `P1 commit 含 artifact_root 外改动: ${forbiddenPaths.slice(0, 10).join(', ')}`,
  );
  for (const [label, relativePath, expectedHash] of bindings) {
    let blob;
    try {
      blob = execFileSync(
        'git',
        ['cat-file', 'blob', `${event.full_head}:${relativePath}`],
        {
          cwd: worktree,
          env: readOnlyGitEnvironment(),
        },
      );
    } catch {
      assertControl(false, 'P1_ARTIFACT_NOT_COMMITTED', `P1_COMMITTED ${label} 不存在于 current HEAD`);
    }
    assertControl(`sha256:${sha256(blob)}` === expectedHash, 'P1_ARTIFACT_MISMATCH', `P1_COMMITTED ${label} blob 与批准 digest 不一致`);
  }
  assertControl(event.payload.plan_path === state.p1.plan_path && event.payload.context_path === state.p1.context_path, 'P1_COMMIT_MISMATCH', 'P1_COMMITTED path 与当前批准产物不一致');
  const committedInventory = committedP1ArtifactInventory(
    worktree,
    manifestTask.p1,
    event.full_head,
  );
  assertControl(
    committedInventory.sha256 === state.p1.artifact_manifest_sha256
      && committedInventory.sha256
        === normalizePacketHash(event.payload.artifact_manifest_sha256),
    'P1_ARTIFACT_MANIFEST_MISMATCH',
    'P1 commit tree artifact inventory 与 READY/APPROVED 不一致',
  );
  assertControl(
    event.payload.p1_commit_ref === mechanicalP1CommitRef(
      loaded.manifest.goal_id,
      manifestTask.id,
      state.task_cycle,
    ),
    'P1_COMMIT_REF_INVALID',
    'P1_COMMITTED durable ref 未绑定当前 Goal/task/cycle',
  );
}

function assertMechanicalP1CandidateArtifacts(
  worktree,
  manifestTask,
  state,
  candidateHead,
) {
  if (!manifestTask.p1) return;
  assertControl(
    state.p1
      && typeof state.p1.artifact_manifest_sha256 === 'string',
    'CORRUPT_STORE',
    `task ${state.task_id} 缺 mechanical P1 approved artifact inventory`,
  );
  let inventory;
  try {
    inventory = committedP1ArtifactInventory(
      worktree,
      manifestTask.p1,
      candidateHead,
    );
  } catch (error) {
    if (
      error instanceof ControlError
        && error.code === 'P1_ARTIFACT_NOT_COMMITTED'
    ) {
      throw new ControlError(
        'P1_ARTIFACT_DRIFT',
        `DEV candidate 删除了 approved P1 artifact: ${error.message}`,
      );
    }
    throw error;
  }
  assertControl(
    inventory.sha256 === state.p1.artifact_manifest_sha256,
    'P1_ARTIFACT_DRIFT',
    'DEV candidate 改写了 approved plan/context/_ref inventory',
  );
}

function mechanicalP1CandidateChangedPaths(
  worktree,
  baselineHead,
  candidateHead,
) {
  let output;
  try {
    output = execFileSync(
      'git',
      [
        'diff',
        '--name-only',
        '-z',
        '--no-renames',
        baselineHead,
        candidateHead,
      ],
      {
        cwd: worktree,
        encoding: null,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: readOnlyGitEnvironment(),
      },
    );
  } catch (error) {
    const detail = String(error.stderr || error.message || '').trim();
    throw new ControlError(
      'GIT_FAILED',
      `无法计算 mechanical P1 DEV delta${detail ? `: ${detail}` : ''}`,
    );
  }
  if (output.length === 0) return [];
  assertControl(
    output[output.length - 1] === 0,
    'GIT_OUTPUT_INVALID',
    'git diff --name-only -z 未返回 NUL-terminated path list',
  );
  return output.subarray(0, output.length - 1).toString('utf8').split('\0');
}

function assertMechanicalP1CandidateWriteSet(
  worktree,
  manifestTask,
  state,
  candidateHead,
) {
  if (!manifestTask.p1) return [];
  assertControl(
    state.p1 && typeof state.p1.commit_sha === 'string',
    'CORRUPT_STORE',
    `task ${state.task_id} 缺 immutable mechanical P1 commit baseline`,
  );
  const baselineHead = state.p1.commit_sha;
  assertFullSha(baselineHead, `${state.task_id}.p1.commit_sha`);
  assertFullSha(candidateHead, `${state.task_id}.candidate_head`);
  try {
    git(worktree, ['merge-base', '--is-ancestor', baselineHead, candidateHead]);
  } catch {
    throw new ControlError(
      'P1_BASELINE_NOT_ANCESTOR',
      `DEV candidate ${candidateHead} 不是 immutable P1 commit ${baselineHead} 的后代`,
    );
  }
  const changedPaths = mechanicalP1CandidateChangedPaths(
    worktree,
    baselineHead,
    candidateHead,
  );
  const patterns = manifestTask.expected_write_set || [];
  const outside = changedPaths.filter(
    (candidatePath) => !patterns.some(
      (pattern) => matchesMechanicalP1WritePattern(pattern, candidatePath),
    ),
  );
  assertControl(
    outside.length === 0,
    'P1_WRITE_SET_VIOLATION',
    `DEV candidate 超出 expected_write_set: ${outside.slice(0, 20).join(', ')}`,
  );
  return changedPaths;
}

function validateCandidateBoundary(cwd, loaded, state, event) {
  if (event.type !== 'DEV_READY') return;
  const worktree = assertFrozenInputs(cwd, loaded);
  assertControl(git(worktree, ['rev-parse', 'HEAD']) === event.full_head, 'STALE_HEAD', 'DEV_READY full_head 必须是当前 worktree HEAD');
  assertDevCandidateLineage(worktree, state, state.sessions.DEV, event.full_head);
  const manifestTask = loaded.manifest.tasks.find(
    (candidate) => candidate.id === state.task_id,
  );
  assertControl(
    manifestTask,
    'CORRUPT_STORE',
    `manifest 缺 task ${state.task_id}`,
  );
  assertMechanicalP1CandidateArtifacts(
    worktree,
    manifestTask,
    state,
    event.full_head,
  );
  assertMechanicalP1CandidateWriteSet(
    worktree,
    manifestTask,
    state,
    event.full_head,
  );
  const dirty = git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']);
  assertControl(dirty === '', 'DIRTY_WORKTREE', `DEV_READY 只接受 clean committed HEAD: ${dirty.split('\n').slice(0, 5).join(', ')}`);
  git(worktree, ['diff', '--check', 'HEAD']);
}

function validatePullRequestBoundary(loaded, event) {
  if (event.type !== 'DEV_READY') return;
  const binding = parsePullRequestUrl(event.payload.pr, loaded.manifest.repository.name_with_owner);
  assertControl(binding.url === event.payload.pr, 'INVALID_PULL_REQUEST', `DEV_READY.pr 必须使用 canonical URL ${binding.url}`);
}

const EVENT_LAUNCH_ROLE = Object.freeze({
  LAUNCH_DEV: 'DEV',
  DEV_READY: 'DEV',
  LAUNCH_REVIEW: 'REVIEW',
  REVIEW_REWORK: 'REVIEW',
  REVIEW_PASS: 'REVIEW',
  LAUNCH_RECEIPT: 'RECEIPT',
  RECEIPT_FAIL: 'RECEIPT',
  RECEIPT_PASS: 'RECEIPT',
  REOPEN_DEV: 'DEV',
  REOPEN_REVIEW: 'REVIEW',
});

function validateRoleHoldBoundary(state, event) {
  if (!EVENT_LAUNCH_ROLE[event.type]) return;
  assertControl(
    state.holds.length === 0,
    'TASK_HELD',
    `任务存在 hold: ${state.holds.map((hold) => hold.kind).join(', ')}`,
  );
}

function validateRoleLaunchBoundary(
  cwd,
  root,
  loaded,
  state,
  event,
  options = {},
) {
  const role = EVENT_LAUNCH_ROLE[event.type];
  if (!role) return;
  validateRoleHoldBoundary(state, event);
  const session = state.sessions[role];
  assertControl(session && ['active', 'idle'].includes(session.status), 'FRESH_SESSION_REQUIRED', `${event.type} 需要 active ${role} session`);
  const acceptedAt = Date.parse(event.accepted_at);
  const receiptHead = event.type === 'DEV_READY'
    ? event.full_head
    : state.full_head;
  assertRequiredLiveProbeObservationBinding(
    loaded.manifest,
    session,
    `${event.type} durable boundary`,
    acceptedAt,
    {
      repositoryHead: receiptHead,
      role,
      taskId: state.task_id,
    },
  );
  if (event.type.startsWith('LAUNCH_')) {
    const captain = state.sessions.CAPTAIN;
    assertControl(
      captain
        && event.actor.role === 'CAPTAIN'
        && event.actor.thread_id === captain.thread_id
        && event.actor.host_id === captain.host_id,
      'CAPTAIN_ACTOR_REQUIRED',
      `${event.type} 必须由 current CAPTAIN actor 启动`,
    );
    assertRequiredLiveProbeObservationBinding(
      loaded.manifest,
      captain,
      `${event.type} CAPTAIN actor durable boundary`,
      acceptedAt,
      {
        repositoryHead: receiptHead,
        role: 'CAPTAIN',
        taskId: state.task_id,
      },
    );
  }
  const launchId = event.payload.launch_id || session.launch_id;
  assertControl(launchId && launchId === session.launch_id, 'LAUNCH_ID_MISMATCH', `${event.type} launch_id 与 ${role} session 不一致`);
  const resolvedPreflight = event.type === 'DEV_READY'
    && event.payload.evidence
    && event.payload.evidence.preflight;
  const launchFile = resolvedPreflight
    ? fileURLToPath(new URL(resolvedPreflight.launch_uri))
    : path.join(loaded.paths.dir, 'launches', state.task_id, `${launchId}.json`);
  assertControl(fs.existsSync(launchFile), 'PREFLIGHT_REQUIRED', `${role} launch ${launchId} 尚未通过 deterministic preflight`);
  if (resolvedPreflight) {
    assertControl(
      resolvedPreflight.kind === 'PREFLIGHT'
        && resolvedPreflight.status === 'PASS'
        && resolvedPreflight.launch_id === launchId
        && normalizeHash(resolvedPreflight.launch_sha256) === hashFile(launchFile)
        && resolvedPreflight.full_head === event.full_head,
      'PREFLIGHT_EVIDENCE_MISMATCH',
      'DEV_READY 必须使用绑定当前 candidate HEAD 的 sealed preflight launch',
    );
  }
  const launch = validateLaunchManifest(readJson(launchFile, `${role} launch ${launchId}`));
  assertControl(launch.goal_id === loaded.manifest.goal_id && launch.task_id === state.task_id && launch.role === role, 'LAUNCH_IDENTITY_MISMATCH', 'launch goal/task/role 不一致');
  assertControl(launch.thread.id === session.thread_id && launch.thread.host_id === session.host_id, 'LAUNCH_IDENTITY_MISMATCH', 'launch thread/host 不一致');
  requiredWorkerBootstrapBinding(
    loaded.manifest,
    session,
    role,
  );
  const allowDevWorkerHeadAdvance =
    workerBootstrapEventAllowsHeadAdvance(role, event.type);
  assertWorkerBootstrapLaunchBinding(
    session,
    launch,
    { allowHeadAdvance: allowDevWorkerHeadAdvance },
  );
  assertLaunchRuntimeIncarnation(session, launch);
  const predecessor = predecessorLaunchForRotation(loaded, state, session);
  if (predecessor) {
    assertRotationSuccessorLaunch(predecessor, session, launch);
  }
  assertControl(launch.state_revision === session.registered_state_revision, 'STALE_STATE_REVISION', 'launch registration revision 陈旧');
  assertControl(launch.control_epoch === loaded.control.epoch && session.registered_control_epoch === loaded.control.epoch, 'STALE_CONTROL_EPOCH', 'launch/session control epoch 陈旧');
  assertControl(launch.packet.revision === state.packet.revision && normalizePacketHash(launch.packet.sha256) === state.packet.sha256, 'STALE_PACKET', 'launch packet 陈旧');
  const worktree = repoRoot(cwd);
  const workerIdentity = workerBootstrapWorktreeIdentity(worktree);
  assertWorkerBootstrapCurrentWorktree(
    session,
    workerIdentity,
    { allowHeadAdvance: allowDevWorkerHeadAdvance },
  );
  if (
    event.type === 'REOPEN_DEV'
      && session.worker_bootstrap
  ) {
    assertControl(
      workerIdentity.head === state.full_head,
      'STALE_HEAD',
      'REOPEN_DEV 前 receipt-bound DEV worktree HEAD 必须等于控制面 full_head',
    );
  }
  assertControl(launch.repository.base_head === state.base_head, 'STALE_HEAD', 'launch base HEAD 与 task 不一致');
  if (event.type === 'DEV_READY' && role === 'DEV') {
    assertDevLaunchHead(worktree, state, session, launch, event.full_head);
  } else {
    assertControl(
      launch.repository.full_head === session.registered_full_head,
      'STALE_HEAD',
      'launch initial HEAD 与 session registration 不一致',
    );
  }
  assertControl(launch.execution.task_nonce === session.task_nonce, 'TASK_NONCE_MISMATCH', 'launch task_nonce 不匹配');
  assertControl(fs.realpathSync(launch.repository.worktree) === fs.realpathSync(worktree), 'WORKTREE_MISMATCH', 'launch worktree 不一致');
  if (['REVIEW', 'RECEIPT'].includes(role)) {
    const expectedPr = parsePullRequestUrl(state.pr, loaded.manifest.repository.name_with_owner);
    assertControl(launch.pull_request, 'PULL_REQUEST_REQUIRED', `${role} launch 缺 PR binding`);
    assertControl(
      launch.pull_request.repository === expectedPr.repository
        && launch.pull_request.number === expectedPr.number
        && launch.pull_request.base === expectedPr.base
        && launch.pull_request.head === state.full_head,
      'PULL_REQUEST_MISMATCH',
      `${role} launch PR 与控制面不一致`,
    );
  }
  const manifestTask = loaded.manifest.tasks.find((candidate) => candidate.id === state.task_id);
  const { verifyLaunchResourceRequirementsUnlocked } = require('./resources');
  verifyLaunchResourceRequirementsUnlocked(root, manifestTask, launch, state, {
    repairHeads: options.readOnly !== true,
    historical: options.historical === true,
  });
  if (['REVIEW_REWORK', 'REVIEW_PASS', 'RECEIPT_FAIL', 'RECEIPT_PASS'].includes(event.type)) {
    assertControl(git(worktree, ['rev-parse', 'HEAD']) === state.full_head, 'STALE_HEAD', `${event.type} worktree HEAD 已移动`);
    assertControl(git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '', 'DIRTY_WORKTREE', `${event.type} 只接受 clean worktree`);
  }
}

function validateRecoveryHandoffBoundary(cwd, loaded, state, event) {
  if (event.type !== 'RECOVERY_HANDOFF_BOUND') return;
  assertControl(
    !(state.sessions.DEV && state.sessions.DEV.recovery_retarget_required),
    'RECOVERY_RETARGET_REQUIRED',
    '已废止 handoff 的 successor 必须先 ROLE_LOST 并登记 fresh attempt',
  );
  const { verifyRecoveryHandoff } = require('./source-handoff');
  verifyRecoveryHandoff(cwd, {
    loaded,
    state,
    payload: event.payload,
    captainThreadId: event.actor.thread_id,
  });
}

function validateRecoveryHandoffAbandonBoundary(
  root,
  loaded,
  state,
  event,
  authorization = {},
) {
  if (event.type !== 'RECOVERY_HANDOFF_ABANDONED') return null;
  const successor = state.sessions.DEV;
  assertControl(
    successor
      && successor.thread_id === event.payload.successor_thread_id
      && successor.operational_scope === 'PREFLIGHT_ONLY'
      && successor.recovery_handoff
      && !successor.recovery_promotion,
    'RECOVERY_HANDOFF_NOT_APPLICABLE',
    'handoff abandon 只适用于未 promotion 的当前 PREFLIGHT_ONLY DEV',
  );
  assertControl(
    successor.recovery_handoff.event_id === event.payload.handoff_event_id,
    'RECOVERY_HANDOFF_MISMATCH',
    'handoff abandon 引用了不同 sealed handoff',
  );
  const foreman = authorization.pristineEventRecovery === true
    ? authorizeHistoricalActorCapability(
      loaded.snapshot,
      authorization.foremanCapabilityFile,
      {
        role: 'FOREMAN',
        thread_id: event.payload.foreman_thread_id,
        host_id: event.payload.foreman_host_id,
        attempt: event.payload.foreman_attempt,
      },
      { goalWide: true, taskId: state.task_id },
    )
    : authorizeGoalSession(
      loaded.snapshot,
      authorization.foremanCapabilityFile,
      { role: 'FOREMAN', threadId: event.payload.foreman_thread_id },
    );
  assertControl(
    foreman.host_id === event.payload.foreman_host_id
      && foreman.attempt === event.payload.foreman_attempt,
    'RECOVERY_AUTHORITY',
    'FOREMAN 联合授权 identity 与事件不一致',
  );
  const { nonTerminalTaskLeasesUnlocked } = require('./resources');
  const successorLeases = nonTerminalTaskLeasesUnlocked(
    root,
    loaded.manifest.goal_id,
    state.task_id,
  ).filter((lease) => (
    lease.owner.role === 'DEV'
      && lease.owner.thread_id === successor.thread_id
      && lease.owner.host_id === successor.host_id
  ));
  assertControl(
    successorLeases.length === 0,
    'RECOVERY_RUNTIME_NOT_RELEASED',
    `handoff abandon 前必须释放/隔离 successor runtime leases: ${successorLeases.map((lease) => lease.lease_id).join(', ')}`,
  );
  return foreman;
}

function validateRecoveryPromotionBoundary(cwd, root, loaded, state, event) {
  if (event.type !== 'RECOVERY_PROMOTED') return;
  const session = state.sessions.DEV;
  assertControl(session && session.thread_id === event.payload.successor_thread_id, 'SUCCESSOR_NOT_REGISTERED', 'promotion successor 不是当前 DEV');
  assertControl(session.recovery_handoff, 'RECOVERY_HANDOFF_REQUIRED', 'promotion 前缺 source handoff');
  assertControl(session.operational_scope === 'PREFLIGHT_ONLY', 'RECOVERY_PROMOTION_NOT_APPLICABLE', `DEV scope=${session.operational_scope}`);
  assertControl(session.recovery_handoff.event_id === event.payload.handoff_event_id, 'RECOVERY_HANDOFF_MISMATCH', 'promotion handoff event 不匹配');

  const launchFile = path.join(
    loaded.paths.dir,
    'launches',
    state.task_id,
    `${session.launch_id}.json`,
  );
  assertControl(fs.existsSync(launchFile), 'PREFLIGHT_REQUIRED', `DEV launch ${session.launch_id} 尚未通过 deterministic preflight`);
  assertControl(hashFile(launchFile) === normalizeHash(event.payload.launch_sha256), 'LAUNCH_HASH_MISMATCH', 'promotion launch digest 不匹配');
  const launch = validateLaunchManifest(readJson(launchFile, `promotion launch ${session.launch_id}`));
  const handoff = session.recovery_handoff;
  const launchWorktree = fs.realpathSync(launch.repository.worktree);
  assertControl(
    launch.goal_id === loaded.manifest.goal_id
      && launch.task_id === state.task_id
      && launch.role === 'DEV'
      && launch.launch_id === session.launch_id
      && launch.thread.id === session.thread_id
      && launch.thread.host_id === session.host_id
      && launch.execution.task_nonce === session.task_nonce,
    'LAUNCH_IDENTITY_MISMATCH',
    'promotion launch 与 recovered DEV identity 不一致',
  );
  assertControl(
    launch.state_revision === session.registered_state_revision
      && launch.control_epoch === loaded.control.epoch
      && launch.packet.revision === state.packet.revision
      && normalizePacketHash(launch.packet.sha256) === state.packet.sha256
      && launch.repository.base_head === state.base_head,
    'STALE_LAUNCH',
    'promotion launch control/packet/base binding 陈旧',
  );
  assertControl(
    launchWorktree === fs.realpathSync(handoff.destination_worktree)
      && launch.repository.worktree === launchWorktree,
    'WORKTREE_MISMATCH',
    'promotion launch 未绑定 sealed destination worktree',
  );
  assertControl(
    launch.repository.branch === handoff.destination_branch
      && git(launchWorktree, ['branch', '--show-current']) === handoff.destination_branch,
    'BRANCH_MISMATCH',
    'promotion launch 未绑定 sealed destination branch',
  );
  const actualHead = git(launchWorktree, ['rev-parse', 'HEAD']);
  assertControl(
    actualHead === launch.repository.full_head
      && actualHead === handoff.import_commit,
    'STALE_HEAD',
    'promotion launch/当前 HEAD 必须精确等于 sealed import checkpoint',
  );
  assertControl(
    git(launchWorktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '',
    'DIRTY_WORKTREE',
    'promotion 只接受 clean destination worktree',
  );
  const manifestTask = loaded.manifest.tasks.find((candidate) => candidate.id === state.task_id);
  const { verifyLaunchResourceRequirementsUnlocked } = require('./resources');
  verifyLaunchResourceRequirementsUnlocked(root, manifestTask, launch, state);

  const evidenceId = safeId(event.payload.preflight_evidence_id, 'preflight evidence');
  const evidenceFile = path.join(loaded.paths.dir, 'evidence', state.task_id, `${evidenceId}.json`);
  assertControl(fs.existsSync(evidenceFile), 'PREFLIGHT_REQUIRED', `preflight evidence ${evidenceId} 不存在`);
  const evidence = readJson(evidenceFile, `preflight evidence ${evidenceId}`);
  const unsigned = { ...evidence };
  delete unsigned.registry_sha256;
  assertControl(hashObject(unsigned) === evidence.registry_sha256, 'CORRUPT_STORE', 'preflight evidence registry seal 不匹配');
  assertControl(
    evidence.evidence_id === evidenceId
      && evidence.kind === 'PREFLIGHT'
      && evidence.status === 'PASS'
      && evidence.goal_id === loaded.manifest.goal_id
      && evidence.task_id === state.task_id
      && evidence.state_revision === state.state_revision
      && evidence.producer
      && evidence.producer.role === 'DEV'
      && evidence.producer.thread_id === session.thread_id
      && (evidence.producer.host_id || 'local') === session.host_id
      && evidence.launch_id === session.launch_id
      && normalizeHash(evidence.launch_sha256) === hashFile(launchFile)
      && evidence.full_head === actualHead,
    'PREFLIGHT_EVIDENCE_MISMATCH',
    'promotion preflight evidence 未绑定当前 state/session/launch/HEAD',
  );
}

function normalizePacketHash(value) {
  assertControl(typeof value === 'string' && /^(?:sha256:)?[0-9a-f]{64}$/.test(value), 'INVALID_HASH', 'packet sha256 非法');
  return value.startsWith('sha256:') ? value : `sha256:${value}`;
}

function recoveredDevPredecessor(state, session) {
  const handoff = session && session.recovered_from;
  if (
    !handoff
    || handoff.role !== 'DEV'
    || handoff.resume_phase !== 'DEV_ACTIVE'
    || state.phase !== 'DEV_ACTIVE'
  ) return null;
  const predecessor = [...(state.session_history.DEV || [])]
    .reverse()
    .find((candidate) => (
      candidate.thread_id === handoff.thread_id
      && candidate.host_id === handoff.host_id
      && candidate.attempt === handoff.attempt
  ));
  assertControl(predecessor && predecessor.status === 'lost', 'SOURCE_RECOVERY_INVALID', 'source recovery 缺对应 lost DEV predecessor');
  assertControl(predecessor.attempt < session.attempt, 'SOURCE_RECOVERY_INVALID', 'source recovery successor attempt 非法');
  for (let attempt = predecessor.attempt + 1; attempt < session.attempt; attempt += 1) {
    const abandoned = (state.session_history.DEV || []).find((candidate) => candidate.attempt === attempt);
    assertControl(
      abandoned && abandoned.status === 'lost',
      'SOURCE_RECOVERY_INVALID',
      `source recovery attempt ${attempt} 缺失 lost lineage`,
    );
  }
  return predecessor;
}

function assertDevLaunchHead(worktree, state, session, launch, expectedHead) {
  assertDevCandidateLineage(worktree, state, session, expectedHead);
  const recovered = recoveredDevPredecessor(state, session);
  const handoff = session.recovery_handoff;
  if (recovered) {
    assertControl(handoff, 'RECOVERY_HANDOFF_REQUIRED', 'recovered DEV candidate 缺 source handoff');
    assertControl(session.operational_scope === 'FULL', 'RECOVERY_PROMOTION_REQUIRED', `recovered DEV scope=${session.operational_scope}`);
  }
  assertControl(session.registered_full_head === state.full_head, 'STALE_HEAD', 'DEV registration HEAD 已跨 task phase/cycle');
  assertControl(session.registered_task_cycle === state.task_cycle, 'STALE_ROLE_REGISTRATION', 'recovered DEV registration cycle 陈旧');
  assertControl(
    session.registered_control_epoch === state.control_epoch
      && session.registered_packet_revision === state.packet.revision
      && session.registered_packet_sha256 === state.packet.sha256,
    'STALE_ROLE_REGISTRATION',
    'recovered DEV registration control/packet binding 陈旧',
  );
  assertDevCandidateLineage(
    worktree,
    state,
    session,
    launch.repository.full_head,
  );
  assertControl(
    !handoff || fs.realpathSync(worktree) === fs.realpathSync(handoff.destination_worktree),
    'WORKTREE_MISMATCH',
    'recovered DEV launch 未使用 sealed destination worktree',
  );
  assertControl(
    !handoff || (
      launch.repository.branch === handoff.destination_branch
        && git(worktree, ['branch', '--show-current']) === handoff.destination_branch
    ),
    'BRANCH_MISMATCH',
    'recovered DEV launch 未使用 sealed destination branch',
  );
  try {
    git(worktree, [
      'merge-base',
      '--is-ancestor',
      launch.repository.full_head,
      expectedHead,
    ]);
  } catch {
    throw new ControlError(
      'CANDIDATE_HEAD_NOT_DESCENDANT',
      `当前 candidate ${expectedHead} 不是 launch checkpoint ${launch.repository.full_head} 的后代`,
    );
  }
  return launch.repository.full_head === expectedHead;
}

function heartbeatMaintenanceActions(state, goalSnapshot = null) {
  const observedNow = runtimeNowMilliseconds();
  const actions = Object.values(state.sessions || {})
    .filter((session) => (
      ['active', 'idle'].includes(session.status)
        && Date.parse(session.lease_until) > observedNow
    ))
    .map((session) => ({
      type: 'HEARTBEAT',
      actor_role: session.role,
      lease_until: session.lease_until,
    }));
  const foreman = state.sessions.FOREMAN;
  if (
    goalSnapshot
      && foreman
      && foreman.status === 'systemError'
  ) {
    try {
      assertUsableGoalForemanReplica(
        goalSnapshot,
        foreman,
        observedNow,
      );
      const digest = sha256([
        'FOREMAN_REPLICA_RESTORE_V1',
        state.task_id,
        foreman.thread_id,
        foreman.host_id,
        String(foreman.attempt),
        foreman.lease_until,
      ].join('\0')).slice(0, 32);
      actions.push({
        type: 'HEARTBEAT',
        actor_role: 'FOREMAN',
        requested_action: 'EVENT_TEMPLATE_AND_ACCEPT',
        execution_condition: 'GOAL_FOREMAN_REPLICA_REPAIR',
        event_id: `heartbeat-foreman-replica-restore-${digest}`,
        payload: {
          status: 'active',
          lease_ms: 3600000,
        },
        target: {
          task_id: state.task_id,
          thread_id: foreman.thread_id,
          host_id: foreman.host_id,
          attempt: foreman.attempt,
          status: foreman.status,
          lease_until: foreman.lease_until,
        },
        dispatch: {
          executor_binding: 'EXACT_USABLE_GOAL_FOREMAN_REPLICA',
          executor: {
            role: 'FOREMAN',
            thread_id: foreman.thread_id,
            host_id: foreman.host_id,
            attempt: foreman.attempt,
          },
          capability_mode: 'GOAL_FOREMAN_CAPABILITY',
        },
      });
    } catch (error) {
      if (
        !error
          || !['ACTOR_LEASE_EXPIRED', 'CAPABILITY_SUPERSEDED']
            .includes(error.code)
      ) {
        throw error;
      }
    }
  }
  return actions;
}

function captainCanSubmitForemanRoleLost(
  state,
  goalSnapshot,
  observedNow,
) {
  if (
    !goalSnapshot
      || state.phase === 'ARCHIVED'
      || state.reconcile_required
      || state.recovery
      || (state.recovery_backlog || []).length > 0
  ) {
    return false;
  }
  const foreman = state.sessions.FOREMAN;
  const captain = state.sessions.CAPTAIN;
  if (
    !foreman
      || !captain
      || !['active', 'idle', 'systemError'].includes(foreman.status)
      || !['active', 'idle'].includes(captain.status)
      || Date.parse(captain.lease_until) <= observedNow
      || (
        ['active', 'idle'].includes(foreman.status)
          && Date.parse(foreman.lease_until) > observedNow
      )
  ) {
    return false;
  }
  try {
    assertUsableGoalForemanReplica(
      goalSnapshot,
      foreman,
      observedNow,
    );
    return false;
  } catch (error) {
    if (error && error.code === 'ACTOR_LEASE_EXPIRED') return true;
    if (error && error.code === 'CAPABILITY_SUPERSEDED') return false;
    throw error;
  }
}

function goalNormalForemanRecoveryPath(
  goalSnapshot,
  sourceTaskIds,
  observedNow,
) {
  const normalRecoveryAlreadyStarted = sourceTaskIds.some((taskId) => {
    const state = goalSnapshot.tasks[taskId];
    const foreman = state && state.sessions.FOREMAN;
    return foreman
      && foreman.status === 'lost'
      && state.recovery
      && state.recovery.role === 'FOREMAN'
      && state.recovery.lost_thread_id === foreman.thread_id;
  });
  const captainTaskId = sourceTaskIds.find((taskId) => (
    captainCanSubmitForemanRoleLost(
      goalSnapshot.tasks[taskId],
      goalSnapshot,
      observedNow,
    )
  )) || null;
  return {
    normal_recovery_already_started: normalRecoveryAlreadyStarted,
    captain_task_id: captainTaskId,
    available: normalRecoveryAlreadyStarted || Boolean(captainTaskId),
  };
}

function exactRoleLostActions(state, goalSnapshot = null) {
  if (
    state.phase === 'ARCHIVED'
      || state.reconcile_required
      || state.recovery
  ) {
    return [];
  }
  const observedNow = runtimeNowMilliseconds();
  const usable = (session) => (
    session
      && ['active', 'idle'].includes(session.status)
      && Date.parse(session.lease_until) > observedNow
  );
  const expired = (session) => (
    session
      && ['active', 'idle'].includes(session.status)
      && Date.parse(session.lease_until) <= observedNow
  );
  const available = (session) => (
    session && ['active', 'idle', 'systemError'].includes(session.status)
  );
  const mechanicallyLost = (session) => (
    session && (
      session.status === 'systemError'
        || expired(session)
    )
  );
  const foreman = state.sessions.FOREMAN;
  const captain = state.sessions.CAPTAIN;
  const actions = [];
  const append = (
    actorRole,
    targetRole,
    target,
    {
      kind = target.status === 'systemError'
        ? 'ACTOR_SYSTEM_ERROR'
        : 'ACTOR_LEASE_EXPIRED',
      reason = target.status === 'systemError'
        ? `registered ${targetRole} entered durable systemError status`
        : `registered ${targetRole} lease expired at ${target.lease_until}`,
      executionCondition = target.status === 'systemError'
        ? 'ACTOR_SYSTEM_ERROR'
        : 'LEASE_EXPIRED',
    } = {},
  ) => {
    const fingerprint = hashObject({
      schema_version: 1,
      kind,
      task_id: state.task_id,
      role: targetRole,
      thread_id: target.thread_id,
      host_id: target.host_id,
      attempt: target.attempt,
      lease_until: target.lease_until,
    });
    actions.push({
      type: 'ROLE_LOST',
      actor_role: actorRole,
      target_role: targetRole,
      target: {
        thread_id: target.thread_id,
        host_id: target.host_id,
        attempt: target.attempt,
        lease_until: target.lease_until,
      },
      event_id: [
        'role-lost',
        targetRole.toLowerCase(),
        state.task_id.toLowerCase(),
        `a${target.attempt}`,
        fingerprint.slice('sha256:'.length, 'sha256:'.length + 16),
      ].join('-'),
      payload: {
        role: targetRole,
        reason,
        fingerprint,
        attempts: 1,
        expected_thread_id: target.thread_id,
        expected_host_id: target.host_id,
        expected_attempt: target.attempt,
        expected_lease_until: target.lease_until,
      },
      requested_action: 'EVENT_TEMPLATE_AND_ACCEPT',
      execution_condition: executionCondition,
    });
  };
  if ((state.recovery_backlog || []).length > 0) {
    if (
      usable(foreman)
        && available(captain)
    ) {
      append('FOREMAN', 'CAPTAIN', captain, {
        kind: 'RECOVERY_BACKLOG_CONTROL_REPLACEMENT',
        reason:
          'Goal root recovery parked worker recovery; replace the exact '
          + 'predecessor CAPTAIN before draining recovery_backlog',
        executionCondition:
          'RECOVERY_BACKLOG_CONTROL_REPLACEMENT_REQUIRED',
      });
    }
    return actions;
  }
  const foremanRecoveryAvailable =
    captainCanSubmitForemanRoleLost(
      state,
      goalSnapshot,
      observedNow,
    );
  if (usable(captain) && foremanRecoveryAvailable) {
    append('CAPTAIN', 'FOREMAN', foreman);
  }
  if (usable(foreman) && mechanicallyLost(captain)) {
    append('FOREMAN', 'CAPTAIN', captain);
  }
  if (usable(captain)) {
    for (const role of ['DEV', 'REVIEW', 'RECEIPT']) {
      const session = state.sessions[role];
      if (mechanicallyLost(session)) append('CAPTAIN', role, session);
    }
  }
  return actions;
}

function runtimeRotationMaintenanceActions(
  paths,
  state,
  goalId,
) {
  const root = path.dirname(path.dirname(paths.dir));
  const observedNow = runtimeNowMilliseconds();
  const expectedRole = expectedRoleForPhase(state.phase);
  if (
    !['DEV', 'REVIEW', 'RECEIPT'].includes(expectedRole)
      || state.recovery
      || state.reconcile_required
      || (state.recovery_backlog || []).length > 0
      || state.holds.length !== 1
      || state.holds[0].kind !== 'ENV_IDENTITY_INCIDENT'
      || state.holds[0].hard !== true
  ) {
    return [];
  }
  const session = state.sessions[expectedRole];
  const captain = state.sessions.CAPTAIN;
  if (
    !session
      || !['active', 'idle'].includes(session.status)
      || !session.launch_id
      || Date.parse(session.lease_until) <= observedNow
      || !captain
      || !['active', 'idle'].includes(captain.status)
      || Date.parse(captain.lease_until) <= observedNow
  ) {
    return [];
  }
  if (isRuntimeRotationHoldLane(state, session)) {
    const successorFile = path.join(
      paths.dir,
      'launches',
      state.task_id,
      `${session.launch_id}.json`,
    );
    if (fs.existsSync(successorFile)) return [];
    let predecessor;
    let repositoryWorktree;
    try {
      predecessor = predecessorLaunchForRotation(
        { paths },
        state,
        session,
      );
      localPreviewPorts(predecessor);
      repositoryWorktree = fs.realpathSync(
        predecessor.repository.worktree,
      );
    } catch {
      return [];
    }
    const rotation = session.last_runtime_rotation;
    const predecessorPorts = localPreviewPorts(predecessor);
    const operationDigest = sha256([
      'RUNTIME_PREFLIGHT_ACTION_V1',
      goalId,
      state.task_id,
      expectedRole,
      session.thread_id,
      session.host_id,
      String(session.attempt),
      rotation.event_id,
      rotation.hold_id,
      String(rotation.successor_incarnation),
      rotation.successor_launch_id,
      rotation.runtime_nonce,
    ].join('\0')).slice(0, 32);
    const operationId = `runtime-preflight-${operationDigest}`;
    const requiredRuntime =
      'FRESH_PREVIEW_PID_AND_FRESH_WEB_PROXY_PORT_GROUP';
    const resourceLeases = [...predecessor.resource_leases];
    const freshnessContract = {
      predecessor: {
        pid: predecessor.execution.target.pid,
        started_at: predecessor.execution.target.started_at,
        preview_port: predecessorPorts.preview_port,
        proxy_port: predecessorPorts.proxy_port,
      },
      successor: {
        pid: 'FRESH',
        started_at: 'AFTER_PREDECESSOR',
        preview_port: 'FRESH',
        proxy_port: 'FRESH_DERIVED_GROUP',
        same_executable: true,
        same_node_version: true,
        same_pnpm_version: true,
      },
    };
    const workerCapability = {
      argument: '--actor-capability-file',
      source: 'EXACT_WORKER_CAPABILITY',
    };
    return [{
      type: 'REQUEST_RUNTIME_PREFLIGHT',
      actor_role: 'CAPTAIN',
      requested_action: 'LAUNCH_TEMPLATE_AND_PREFLIGHT',
      command: 'runtime-successor-preflight',
      goal_id: goalId,
      task_id: state.task_id,
      repository_worktree: repositoryWorktree,
      operation_id: operationId,
      role: expectedRole,
      worker: {
        thread_id: session.thread_id,
        host_id: session.host_id,
        attempt: session.attempt,
      },
      dispatch: {
        coordinator_role: 'CAPTAIN',
        executor_binding: `EXACT_ACTIVE_${expectedRole}`,
        executor: {
          role: expectedRole,
          thread_id: session.thread_id,
          host_id: session.host_id,
          attempt: session.attempt,
        },
        capability_mode: 'EXACT_WORKER_CAPABILITY',
      },
      rotation_event_id: rotation.event_id,
      hold_id: rotation.hold_id,
      runtime_nonce: rotation.runtime_nonce,
      successor_incarnation: rotation.successor_incarnation,
      successor_launch_id: rotation.successor_launch_id,
      expected_state_revision: state.state_revision,
      expected_control_epoch: state.control_epoch,
      required_runtime: requiredRuntime,
      resource_leases: resourceLeases,
      freshness_contract: freshnessContract,
      evidence_id_mode: {
        kind: 'AUTO_FROM_EXACT_LAUNCH',
        algorithm: 'RUNTIME_PREFLIGHT_EVIDENCE_V1',
        prefix: 'preflight-runtime-',
      },
      execution_plan: {
        schema_version: 1,
        runtime_broker: {
          required_runtime: requiredRuntime,
          repository_worktree: repositoryWorktree,
          role: expectedRole,
          worker_thread: session.thread_id,
          predecessor: freshnessContract.predecessor,
          successor: freshnessContract.successor,
          executable_path:
            predecessor.execution.target.executable_path,
          node_version: predecessor.runtime.node_version,
          pnpm_version: predecessor.runtime.pnpm_version,
          resource_leases: resourceLeases,
          execution: {
            environment: 'none',
            write_mode: 'NONE',
            target_kind: 'PREVIEW',
          },
        },
        launch_template: {
          command: 'launch-template',
          repository_worktree: repositoryWorktree,
          goal: goalId,
          task: state.task_id,
          role: expectedRole,
          thread: session.thread_id,
          input_file: 'REQUIRED_FRESH_RUNTIME_INPUT',
          successor_launch_id: rotation.successor_launch_id,
          resource_leases: resourceLeases,
          capability: workerCapability,
        },
        preflight: {
          command: 'preflight',
          repository_worktree: repositoryWorktree,
          goal: goalId,
          task: state.task_id,
          launch: 'EXACT_LAUNCH_TEMPLATE_OUTPUT',
          stage: expectedRole,
          evidence_id_mode: 'AUTO_FROM_EXACT_LAUNCH',
          capability: workerCapability,
        },
      },
    }];
  }
  if (!runtimeRotationHoldEligible(root, state, goalId)) return [];
  const launchFile = path.join(
    paths.dir,
    'launches',
    state.task_id,
    `${session.launch_id}.json`,
  );
  if (!fs.existsSync(launchFile)) return [];
  let launch;
  let repositoryWorktree;
  try {
    launch = validateLaunchManifest(
      readJson(launchFile, `runtime rotation launch ${session.launch_id}`),
    );
    localPreviewPorts(launch);
    repositoryWorktree = fs.realpathSync(
      launch.repository.worktree,
    );
  } catch {
    return [];
  }
  const hold = state.holds[0];
  const holdEventId = activeHoldEventId(
    root,
    goalId,
    state,
    hold,
  );
  const predecessorIncarnation = currentRuntimeIncarnation(session);
  const predecessorLaunchSha256 = hashFile(launchFile);
  const operationDigest = sha256([
    'RUNTIME_ROTATION_ACTION_V1',
    goalId,
    state.task_id,
    expectedRole,
    captain.thread_id,
    captain.host_id,
    String(captain.attempt),
    session.thread_id,
    session.host_id,
    String(session.attempt),
    hold.hold_id,
    holdEventId,
    String(predecessorIncarnation),
    session.launch_id,
    predecessorLaunchSha256,
  ].join('\0')).slice(0, 32);
  const operationId = `runtime-rotation-${operationDigest}`;
  const eventId = `runtime-rotated-${operationDigest}`;
  const successorIncarnation = predecessorIncarnation + 1;
  const successorLaunchId = [
    'launch',
    expectedRole.toLowerCase(),
    'runtime',
    `i${successorIncarnation}`,
    operationDigest,
  ].join('-');
  const reason =
    `replace failed local PREVIEW runtime for ${expectedRole}`;
  const incidentRef = `goal-control:event:${holdEventId}`;
  const argumentsMap = {
    repository_worktree: repositoryWorktree,
    goal: goalId,
    task: state.task_id,
    role: expectedRole,
    worker_thread: session.thread_id,
    predecessor_incarnation: predecessorIncarnation,
    predecessor_launch: session.launch_id,
    expected_predecessor_launch_sha256: predecessorLaunchSha256,
    successor_launch: successorLaunchId,
    hold: hold.hold_id,
    expected_state_revision: state.state_revision,
    expected_control_epoch: state.control_epoch,
    reason,
    incident_ref: incidentRef,
    captain_thread: captain.thread_id,
    event_id: eventId,
    json: true,
  };
  return [{
    type: 'REQUEST_RUNTIME_ROTATION',
    actor_role: 'CAPTAIN',
    requested_action: 'ROTATE_RUNTIME',
    command: 'rotate-runtime',
    goal_id: goalId,
    task_id: state.task_id,
    repository_worktree: repositoryWorktree,
    operation_id: operationId,
    event_id: eventId,
    role: expectedRole,
    worker: {
      thread_id: session.thread_id,
      host_id: session.host_id,
      attempt: session.attempt,
    },
    dispatch: {
      coordinator_role: 'CAPTAIN',
      executor_binding: 'EXACT_ACTIVE_CAPTAIN',
      executor: {
        role: 'CAPTAIN',
        thread_id: captain.thread_id,
        host_id: captain.host_id,
        attempt: captain.attempt,
      },
      capability_mode: 'EXACT_CAPTAIN_CAPABILITY',
    },
    hold_id: hold.hold_id,
    hold_event_id: holdEventId,
    predecessor_incarnation: predecessorIncarnation,
    predecessor_launch_id: session.launch_id,
    predecessor_launch_sha256: predecessorLaunchSha256,
    successor_incarnation: successorIncarnation,
    successor_launch_id: successorLaunchId,
    expected_state_revision: state.state_revision,
    expected_control_epoch: state.control_epoch,
    reason,
    incident_ref: incidentRef,
    required_successor: 'FRESH_LAUNCH_ID_AND_FRESH_PREVIEW_PORT_GROUP',
    execution_plan: {
      schema_version: 1,
      command: 'rotate-runtime',
      arguments: argumentsMap,
      capability: {
        argument: '--captain-capability-file',
        source: 'EXACT_CAPTAIN_CAPABILITY',
      },
    },
  }];
}

function activeHoldEventId(root, goalId, state, hold) {
  let active = null;
  for (const file of acceptedEventFiles(
    root,
    goalId,
    state.task_id,
  )) {
    const event = readJson(
      file,
      `hold incarnation event ${path.basename(file)}`,
    );
    assertControl(
      event.goal_id === goalId && event.task_id === state.task_id,
      'CORRUPT_STORE',
      `hold incarnation event ${event.event_id} goal/task binding 非法`,
    );
    if (event.type === 'ADD_HOLD') {
      const eventHoldId = event.payload.hold_id || event.event_id;
      if (eventHoldId === hold.hold_id) active = event;
    } else if (
      event.type === 'RESOLVE_HOLD'
        && event.payload.hold_id === hold.hold_id
    ) {
      active = null;
    }
  }
  assertControl(
    active
      && active.payload
      && active.payload.kind === hold.kind
      && active.payload.evidence_id === hold.evidence.evidence_id
      && (
        active.evidence_registry_sha256 === undefined
          || active.evidence_registry_sha256 === hashObject({
            [hold.evidence.evidence_id]:
              hold.evidence.registry_sha256,
          })
      ),
    'CORRUPT_STORE',
    `active hold ${hold.hold_id} 缺 append-only ADD_HOLD incarnation`,
  );
  return active.event_id;
}

function inspectSourceCheckpointHold(
  paths,
  state,
  goalId,
  _manifestTask,
  options = {},
) {
  if (
    state.phase !== 'DEV_ACTIVE'
      ||
    state.holds.length !== 1
      || state.holds[0].kind !== 'ENV_IDENTITY_INCIDENT'
      || state.holds[0].hard !== true
  ) {
    return null;
  }
  const hold = state.holds[0];
  const root = path.dirname(path.dirname(paths.dir));
  assertControl(
    isSourceCheckpointHoldIntent(root, state, goalId),
    'SOURCE_CHECKPOINT_HOLD_INVALID',
    'ENV identity hold 未机械分类为 SOURCE_ONLY',
  );
  const holdEventId = activeHoldEventId(
    root,
    goalId,
    state,
    hold,
  );
  assertControl(
    !options.expectedHoldEventId
      || holdEventId === options.expectedHoldEventId,
    'SOURCE_CHECKPOINT_HOLD_CHANGED',
    `hold ${hold.hold_id} 已被不同 ADD_HOLD incarnation 复用`,
  );
  const session = state.sessions.DEV;
  if (
    !session
      || !['active', 'idle'].includes(session.status)
      || !session.launch_id
  ) {
    return null;
  }
  const canonicalFile = canonicalRuntimeLaunchFile(
    root,
    goalId,
    state.task_id,
    session.launch_id,
  );
  if (!fs.existsSync(canonicalFile)) return null;
  const canonicalLaunch = validateLaunchManifest(
    readJson(canonicalFile, `source checkpoint runtime ${session.launch_id}`),
  );
  assertControl(
    canonicalLaunch.role === 'DEV'
      && canonicalLaunch.goal_id === goalId
      && canonicalLaunch.task_id === state.task_id
      && canonicalLaunch.thread.id === session.thread_id
      && (canonicalLaunch.thread.host_id || 'local') === session.host_id
      && canonicalLaunch.execution.task_nonce === session.task_nonce,
    'SOURCE_CHECKPOINT_HOLD_INVALID',
    'source checkpoint hold canonical runtime/session identity 不匹配',
  );
  const launchWorktree = fs.realpathSync(
    canonicalLaunch.repository.worktree,
  );
  const observedCandidateHead = git(
    launchWorktree,
    ['rev-parse', 'HEAD'],
  );
  const candidateHead = options.expectedCandidateHead
    ? assertFullSha(
      options.expectedCandidateHead,
      'expected source checkpoint candidate HEAD',
    )
    : observedCandidateHead;
  const checks = state.holds[0].evidence
    && Array.isArray(state.holds[0].evidence.checks)
    ? state.holds[0].evidence.checks
    : [];
  const failed = checks.filter((check) => check.status === 'FAIL');
  let parentEvidenceId = null;
  let candidateLaunch = null;
  const explicitSourceOnly = failed.length > 0
    && failed.every((check) => (
        check.name === 'launch-invalid-stale-head'
          || check.name === 'source-checkpoint-stale'
      ))
    && failed.every((check) => (
      typeof check.detail === 'string'
        && check.detail.includes(canonicalLaunch.repository.full_head)
        && check.detail.includes(candidateHead)
    ));
  if (explicitSourceOnly) {
    candidateLaunch = JSON.parse(JSON.stringify(canonicalLaunch));
    candidateLaunch.repository.full_head = candidateHead;
    if (candidateLaunch.execution.target.kind === 'NONE') {
      delete candidateLaunch.execution.target.build_head;
    } else {
      candidateLaunch.execution.target.build_head = candidateHead;
    }
  } else {
    const controllerSourceFailures = failed.length > 0
      && failed.every((check) => (
        check.name === 'launch-runtime-binding'
          && typeof check.detail === 'string'
          && check.detail.startsWith('LAUNCH_ID_CONFLICT:')
      ));
    assertControl(
      controllerSourceFailures,
      'SOURCE_CHECKPOINT_HOLD_INVALID',
      'ENV identity hold 不是可机械重验证的 source checkpoint 事故',
    );
    let holdSource;
    try {
      holdSource = JSON.parse(
        readIdentityIncidentSourceBytes(
          root,
          state,
          goalId,
          hold,
        ).toString('utf8'),
      );
    } catch (error) {
      throw new ControlError(
        'SOURCE_CHECKPOINT_HOLD_INVALID',
        `source checkpoint hold source 无法读取: ${error.message}`,
      );
    }
    assertControl(
      holdSource
        && holdSource.request
        && typeof holdSource.request.parent_evidence_id === 'string',
      'SOURCE_CHECKPOINT_HOLD_INVALID',
      'source checkpoint hold 缺 parent PREFLIGHT binding',
    );
    parentEvidenceId = holdSource.request.parent_evidence_id;
    try {
      candidateLaunch = readControllerIncidentCandidate(
        root,
        state,
        goalId,
        session,
        hold,
        failed,
      );
    } catch (error) {
      throw new ControlError(
        'SOURCE_CHECKPOINT_HOLD_INVALID',
        `source checkpoint hold candidate 无法读取: ${error.message}`,
      );
    }
  }
  assertSourceCheckpointAdvance(canonicalLaunch, candidateLaunch);
  assertControl(
    candidateLaunch.repository.full_head === candidateHead,
    'SOURCE_CHECKPOINT_HOLD_INVALID',
    'source checkpoint hold candidate 与 exact checkpoint 不一致',
  );
  assertControl(
    options.allowCurrentHeadDrift === true
      || candidateHead === observedCandidateHead,
    'SOURCE_CHECKPOINT_HOLD_INVALID',
    'source checkpoint hold candidate 已不是当前 DEV HEAD',
  );
  return {
    hold,
    hold_event_id: holdEventId,
    session,
    canonical_launch_file: canonicalFile,
    canonical_launch_sha256: hashFile(canonicalFile),
    canonical_head: canonicalLaunch.repository.full_head,
    candidate_head: candidateHead,
    observed_candidate_head: observedCandidateHead,
    candidate_launch_sha256: hashObject(candidateLaunch),
    parent_evidence_id: parentEvidenceId,
  };
}

function sourceCheckpointHoldMaintenanceActions(
  paths,
  state,
  goalId,
  manifestTask,
) {
  let inspection;
  try {
    inspection = inspectSourceCheckpointHold(
      paths,
      state,
      goalId,
      manifestTask,
    );
  } catch {
    return [];
  }
  if (!inspection) return [];
  const foreman = state.sessions.FOREMAN;
  if (
    !foreman
      || !['active', 'idle'].includes(foreman.status)
  ) {
    return [];
  }
  const operationDigest = sha256([
    goalId,
    state.task_id,
    inspection.hold.hold_id,
    inspection.hold_event_id,
    inspection.canonical_launch_sha256,
    inspection.candidate_head,
    foreman.thread_id,
    foreman.host_id,
    String(foreman.attempt),
  ].join('\0')).slice(0, 32);
  const resolutionEvidenceId =
    `source-checkpoint-resolution-${operationDigest}`;
  const resolveEventId =
    `resolve-source-checkpoint-hold-${operationDigest}`;
  const operationId =
    `source-checkpoint-revalidation-${operationDigest}`;
  return [{
    type: 'REQUEST_CANDIDATE_HOLD_REVALIDATION',
    actor_role: 'FOREMAN',
    requested_action: 'REVALIDATE_SOURCE_CHECKPOINT_HOLD',
    command: 'revalidate-source-checkpoint-hold',
    operation_id: operationId,
    hold_id: inspection.hold.hold_id,
    hold_event_id: inspection.hold_event_id,
    canonical_launch_sha256: inspection.canonical_launch_sha256,
    canonical_head: inspection.canonical_head,
    candidate_head: inspection.candidate_head,
    parent_evidence_id: inspection.parent_evidence_id,
    foreman: {
      thread_id: foreman.thread_id,
      host_id: foreman.host_id,
      attempt: foreman.attempt,
    },
    resolution_evidence_id: resolutionEvidenceId,
    resolve_event_id: resolveEventId,
    forbidden_action: 'ROTATE_RUNTIME',
    reason: 'canonical runtime identity is preserved; the current decoder mechanically revalidated a source-only checkpoint advance',
  }];
}

function trustedCandidatePreflight(
  paths,
  state,
  goalId,
  manifestTask,
  candidateHead,
) {
  const root = path.dirname(path.dirname(paths.dir));
  const directory = path.join(
    paths.dir,
    'evidence',
    state.task_id,
  );
  if (!fs.existsSync(directory)) return null;
  const session = state.sessions.DEV;
  const candidates = fs.readdirSync(directory)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .reverse();
  for (const name of candidates) {
    const evidenceId = name.slice(0, -'.json'.length);
    try {
      const raw = readJson(
        path.join(directory, name),
        `candidate preflight ${evidenceId}`,
      );
      if (
        raw.kind !== 'PREFLIGHT'
          || raw.status !== 'PASS'
          || raw.full_head !== candidateHead
          || raw.launch_id !== session.launch_id
          || !raw.producer
          || raw.producer.role !== 'DEV'
          || raw.producer.thread_id !== session.thread_id
          || (raw.producer.host_id || 'local') !== session.host_id
      ) {
        continue;
      }
      return resolveTrustedEvidence(root, state, evidenceId, {
        goalId,
        kind: 'PREFLIGHT',
        fullHead: candidateHead,
        manifestTask,
        readOnly: true,
        requireSourceCheckpointRuntimeBinding: true,
      });
    } catch {
      // Keep searching. A stale or foreign evidence record is not a current
      // candidate checkpoint and must not suppress the projected action.
    }
  }
  return null;
}

function candidatePreflightMaintenanceActions(
  paths,
  state,
  goalId,
  manifestTask,
) {
  if (
    state.phase !== 'DEV_ACTIVE'
      || state.recovery
      || state.reconcile_required
      || (state.recovery_backlog || []).length > 0
      || state.holds.length > 0
  ) {
    return [];
  }
  const session = state.sessions.DEV;
  if (
    !session
      || !['active', 'idle'].includes(session.status)
      || !session.launch_id
      || sessionOperationalScope(state, 'DEV') !== 'FULL'
  ) {
    return [];
  }
  const launchFile = path.join(
    paths.dir,
    'launches',
    state.task_id,
    `${session.launch_id}.json`,
  );
  if (!fs.existsSync(launchFile)) return [];
  try {
    const launch = validateLaunchManifest(
      readJson(launchFile, `launch ${session.launch_id}`),
    );
    if (
      !['NONE', 'CLI', 'PREVIEW'].includes(
        launch.execution.target.kind,
      )
    ) {
      return [];
    }
    const worktree = fs.realpathSync(launch.repository.worktree);
    if (!sourceRuntimeBindingStatus(worktree, launch).lockfile.matches) {
      return [];
    }
    const candidateHead = git(worktree, ['rev-parse', 'HEAD']);
    if (launch.repository.full_head === candidateHead) return [];
    assertDevLaunchHead(worktree, state, session, launch, candidateHead);
    const existing = trustedCandidatePreflight(
      paths,
      state,
      goalId,
      manifestTask,
      candidateHead,
    );
    if (existing) return [];
    return [{
      type: 'REQUEST_CANDIDATE_PREFLIGHT',
      actor_role: 'CAPTAIN',
      requested_action: 'LAUNCH_TEMPLATE_AND_PREFLIGHT',
      dispatch: {
        coordinator_role: 'CAPTAIN',
        executor_binding: 'EXACT_ACTIVE_DEV',
        executor: {
          role: 'DEV',
          thread_id: session.thread_id,
          host_id: session.host_id,
        },
        capability_mode: 'EXACT_DEV_CAPABILITY',
      },
      launch_id: session.launch_id,
      canonical_head: launch.repository.full_head,
      candidate_head: candidateHead,
      evidence_id: `preflight-candidate-${sha256(
        `${goalId}\0${state.task_id}\0${session.launch_id}\0${candidateHead}`,
      ).slice(0, 32)}`,
      mutable_fields: [
        'repository.full_head',
        'execution.target.build_head',
      ],
      execution_plan: {
        schema_version: 1,
        launch_template: {
          command: 'launch-template',
          role: 'DEV',
          input_mode: 'CLONE_CANONICAL',
          input_file_required: false,
        },
        preflight: {
          command: 'preflight',
          stage: 'DEV',
          evidence_id: `preflight-candidate-${sha256(
            `${goalId}\0${state.task_id}\0${session.launch_id}\0${candidateHead}`,
          ).slice(0, 32)}`,
        },
      },
      forbidden_action: 'ROTATE_RUNTIME',
    }];
  } catch {
    return [];
  }
}

function activeOwnerResourceRenewalActions(paths, state, goalId) {
  const hardHolds = state.holds.filter((hold) => hold.hard === true);
  let runtimeIdentityPreservationHold = null;
  if (hardHolds.length > 0) {
    const expectedRole = expectedRoleForPhase(state.phase);
    const session = state.sessions[expectedRole];
    if (
      hardHolds.length !== 1
        || state.holds.length !== 1
        || hardHolds[0].kind !== 'ENV_IDENTITY_INCIDENT'
        || !['DEV', 'REVIEW', 'RECEIPT'].includes(expectedRole)
        || !session
        || !['active', 'idle'].includes(session.status)
        || !session.launch_id
    ) {
      return [];
    }
    runtimeIdentityPreservationHold = hardHolds[0];
  }
  const observedNow = runtimeNowMilliseconds();
  const root = path.dirname(path.dirname(paths.dir));
  const {
    assertOwnerCapabilityDisclosureBoundary,
    nonTerminalTaskLeasesUnlocked,
    rebuildResourcesReadOnlyUnlocked,
    resourceRenewalEventId,
    resourceRenewalPolicy,
  } = require('./resources');
  const resourceState = rebuildResourcesReadOnlyUnlocked(root).state;
  const workerRoles = new Set(['DEV', 'REVIEW', 'RECEIPT']);
  const ownerSession = (owner) => {
    if (!workerRoles.has(owner.role)) return null;
    const session = state.sessions[owner.role];
    if (
      !session
        || !['active', 'idle'].includes(session.status)
        || session.thread_id !== owner.thread_id
        || session.host_id !== owner.host_id
        || Date.parse(session.lease_until) <= observedNow
    ) {
      return null;
    }
    return session;
  };
  return nonTerminalTaskLeasesUnlocked(root, goalId, state.task_id)
    .map((lease) => {
      if (
        lease.status !== 'ACTIVE'
          || !ownerSession(lease.owner)
      ) {
        return null;
      }
      if (runtimeIdentityPreservationHold !== null) {
        try {
          return {
            lease,
            boundary: assertOwnerCapabilityDisclosureBoundary(
              state,
              resourceState,
              lease,
              observedNow,
            ),
          };
        } catch {
          return null;
        }
      }
      if (Date.parse(lease.expires_at) <= observedNow) return null;
      const policy = resourceRenewalPolicy(lease);
      if (
        Date.parse(lease.expires_at) - observedNow
          > policy.leadMilliseconds
      ) {
        return null;
      }
      return {
        lease,
        boundary: {
          expiry_state: 'RENEWAL_WINDOW',
          policy,
        },
      };
    })
    .filter(Boolean)
    .sort((left, right) => (
      left.lease.lease_id.localeCompare(right.lease.lease_id)
    ))
    .map(({ lease, boundary }) => {
      const { policy } = boundary;
      const owner = {
        role: lease.owner.role,
        thread_id: lease.owner.thread_id,
        host_id: lease.owner.host_id,
      };
      return {
        type: 'REQUEST_RESOURCE_RENEW',
        // Backward-compatible coordinator field. Resource mutation authority
        // remains bound to the exact owner described by dispatch.executor.
        actor_role: 'CAPTAIN',
        requested_action: 'RENEW_RESOURCE',
        dispatch: {
          coordinator_role: 'CAPTAIN',
          executor_binding: 'EXACT_RESOURCE_OWNER',
          executor: { ...owner },
          capability_mode: 'EXACT_OWNER_DUAL_CAPABILITY',
        },
        event_id: resourceRenewalEventId(lease),
        lease_id: lease.lease_id,
        resource: lease.resource,
        expected_revision: lease.revision,
        ttl_ms: policy.ttlMilliseconds,
        expires_at: lease.expires_at,
        renewal_window_ms: policy.leadMilliseconds,
        expiry_state: boundary.expiry_state,
        ...(runtimeIdentityPreservationHold
          ? { hold_id: runtimeIdentityPreservationHold.hold_id }
          : {}),
        owner,
      };
    });
}

function terminalOwnerResourceReleaseActions(paths, state, goalId) {
  if (state.holds.some((hold) => hold.hard === true)) return [];
  const root = path.dirname(path.dirname(paths.dir));
  const { nonTerminalTaskLeasesUnlocked } = require('./resources');
  const workerRoles = new Set(['DEV', 'REVIEW', 'RECEIPT']);
  const ownerIsTerminal = (owner) => {
    if (!workerRoles.has(owner.role)) return false;
    const candidates = [
      state.sessions[owner.role],
      ...((state.session_history && state.session_history[owner.role]) || []),
    ].filter(Boolean);
    return candidates.some((session) => (
      session.status === 'terminal'
        && session.thread_id === owner.thread_id
        && session.host_id === owner.host_id
    ));
  };
  return nonTerminalTaskLeasesUnlocked(root, goalId, state.task_id)
    // UNVERIFIED_REVOKE requires broker repair and cannot be released by the
    // historical owner. Raw ACTIVE also covers a logically expired lease,
    // which exact-owner cleanup is explicitly allowed to release.
    .filter((lease) => lease.status === 'ACTIVE' && ownerIsTerminal(lease.owner))
    .sort((left, right) => left.lease_id.localeCompare(right.lease_id))
    .map((lease) => ({
      type: 'REQUEST_RESOURCE_RELEASE',
      actor_role: 'CAPTAIN',
      requested_action: 'RELEASE_RESOURCE',
      lease_id: lease.lease_id,
      resource: lease.resource,
      expected_revision: lease.revision,
      owner: {
        role: lease.owner.role,
        thread_id: lease.owner.thread_id,
        host_id: lease.owner.host_id,
      },
    }));
}

function publicPendingOperation(operation, scope, taskId = null) {
  const operationId = operation.operation_id
    || operation.event_id
    || operation.root_recovery_id;
  const stableIdUnavailable = operation.stable_id_unavailable === true
    || operation.hashed_identity === true;
  assertControl(
    stableIdUnavailable
      || (typeof operationId === 'string' && operationId.length > 0),
    'CORRUPT_STORE',
    `${operation.kind} pending operation 缺 stable ID`,
  );
  const stableIdSha256 = stableIdUnavailable
    ? normalizeHash(
      operation.stable_id_sha256 || operationId,
      `${operation.kind} pending stable_id_sha256`,
    )
    : null;
  const sourceCheckpoint = operation.kind === 'SOURCE_CHECKPOINT';
  const p1Commit = operation.kind === 'P1_COMMIT_REF';
  const p1AbandonmentRequired = p1Commit
    && operation.abandonment_required === true;
  const p1Abandon = operation.kind === 'P1_COMMIT_REF_ABANDON';
  const githubMerge = operation.kind === 'GITHUB_MERGE';
  return {
    kind: operation.kind,
    ...(stableIdUnavailable
      ? {
        stable_id_sha256: stableIdSha256,
        stable_id_unavailable: true,
      }
      : { operation_id: operationId }),
    scope,
    ...(taskId || operation.task_id
      ? { task_id: taskId || operation.task_id }
      : {}),
    ...(operation.request_sha256
      ? { request_sha256: operation.request_sha256 }
      : {}),
    ...(sourceCheckpoint
      ? {
        snapshot_id: operation.snapshot_id,
        import_receipt_id: operation.import_receipt_id,
        checkpoint_sha: operation.checkpoint_sha,
        git_dir_fenced: operation.git_dir_fenced === true,
        index_lock_present: operation.index_lock_present === true,
        completion_sealed: operation.completed === true,
      }
      : {}),
    ...((p1Commit || p1Abandon)
      ? {
        prepared_stage: operation.prepared_stage || null,
        prepared_event_id: operation.prepared_event_id
          || operation.operation_id
          || null,
        intent_sha256: operation.intent_sha256 || null,
        commit_ref: operation.commit_ref || null,
        commit_sha: operation.commit_sha || null,
        ...(p1AbandonmentRequired
          ? { abandonment_required: true }
          : {}),
      }
      : {}),
    retry: githubMerge
      ? {
        command: 'merge-pr',
        stable_id: operationId,
        request: 'EXACT_WITH_ORIGINAL_FOREMAN_CAPABILITY',
        stage: operation.stage || null,
      }
      : p1AbandonmentRequired
      ? {
        command: 'p1-abandon-commit',
        stable_id: operationId,
        request: 'NEW_STABLE_ABANDON_ID_WITH_LIVE_FOREMAN_CAPABILITY',
      }
      : p1Commit
      ? {
        command: 'event',
        stable_id: stableIdUnavailable ? null : operationId,
        request: 'EXACT_WITH_ORIGINAL_EVENT_AND_CAPABILITY',
      }
      : p1Abandon
        ? {
          command: 'p1-abandon-commit',
          stable_id: operationId,
          request: 'EXACT_WITH_ORIGINAL_ARGUMENTS_AND_FOREMAN_CAPABILITY',
        }
        : sourceCheckpoint
      ? {
        command: 'recovery-checkpoint-source',
        snapshot_id: operation.snapshot_id,
        import_receipt_id: operation.import_receipt_id,
        request: 'EXACT_WITH_ORIGINAL_CLI_AND_DEV_CAPABILITY',
      }
      : stableIdUnavailable
      ? {
        stable_id_sha256: stableIdSha256,
        stable_id_unavailable: true,
        request: 'EXACT_WITH_PERSISTED_STABLE_ID',
      }
      : {
        stable_id: operationId,
        request: 'EXACT',
      },
  };
}

function pendingOperationKey(operation) {
  return [
    operation.scope,
    operation.task_id || '',
    operation.kind,
    operation.operation_id
      || operation.stable_id_sha256
      || '<stable-id-unavailable>',
  ].join(':');
}

function pendingOperationDisplayId(operation) {
  return operation.operation_id
    || operation.stable_id_sha256
    || '<stable-id-unavailable>';
}

function pendingActionOperations(paths, state, goalId) {
  const root = path.dirname(path.dirname(paths.dir));
  const {
    listPendingGoalRegistrationIntents,
    listPendingTaskOperations,
  } = require('./pending-operations');
  const pending = new Map();
  const add = (operation) => {
    const key = pendingOperationKey(operation);
    if (!pending.has(key)) pending.set(key, operation);
  };
  for (const batch of pendingRecoveryBatches(paths, goalId)) {
    add(publicPendingOperation({
      kind: 'FOREMAN_RECOVERY_BATCH',
      operation_id: batch.root_recovery_id,
      request_sha256: batch.intent.request_sha256,
    }, 'GOAL'));
  }
  for (const intent of listPendingGoalRegistrationIntents(root, goalId)) {
    add(publicPendingOperation({
      kind: 'REGISTRATION',
      operation_id: intent.event_id,
      request_sha256: intent.request_sha256,
      task_id: intent.task_id,
    }, 'GOAL'));
  }
  for (const operation of listPendingTaskOperations(
    root,
    goalId,
    state.task_id,
  )) {
    if (operation.kind === 'REGISTRATION') continue;
    add(publicPendingOperation(operation, 'TASK', state.task_id));
  }
  return [...pending.values()];
}

function sourceRuntimeBindingStatus(worktree, launch) {
  const lockfile = path.join(worktree, 'pnpm-lock.yaml');
  const actualLockfileSha256 = fs.existsSync(lockfile)
    ? hashFile(lockfile)
    : null;
  return {
    lockfile: {
      path: lockfile,
      expected_sha256: launch.runtime.lockfile_sha256,
      actual_sha256: actualLockfileSha256,
      matches:
        actualLockfileSha256 === launch.runtime.lockfile_sha256,
    },
  };
}

function freshDevRecoveryForSourceAdvance(
  state,
  goalId,
  session,
  launch,
  actualLaunchHead,
  {
    trigger,
    reason,
    runtimeBinding = null,
  },
) {
  const fingerprint = hashObject({
    schema_version: 1,
    kind: trigger,
    goal_id: goalId,
    task_id: state.task_id,
    launch_id: session.launch_id,
    target_kind: launch.execution.target.kind,
    canonical_head: launch.repository.full_head,
    candidate_head: actualLaunchHead,
    ...(runtimeBinding ? { runtime_binding: runtimeBinding } : {}),
    worker: {
      thread_id: session.thread_id,
      host_id: session.host_id,
      attempt: session.attempt,
    },
  });
  return {
    type: 'ROLE_LOST',
    actor_role: 'CAPTAIN',
    target_role: 'DEV',
    trigger,
    target: {
      thread_id: session.thread_id,
      host_id: session.host_id,
      attempt: session.attempt,
      lease_until: session.lease_until,
    },
    event_id: [
      'role-lost-dev',
      state.task_id.toLowerCase(),
      `a${session.attempt}`,
      fingerprint.slice(
        'sha256:'.length,
        'sha256:'.length + 16,
      ),
    ].join('-'),
    payload: {
      role: 'DEV',
      reason,
      fingerprint,
      attempts: 1,
      expected_thread_id: session.thread_id,
      expected_host_id: session.host_id,
      expected_attempt: session.attempt,
      expected_lease_until: session.lease_until,
    },
    requested_action:
      'EVENT_TEMPLATE_AND_ACCEPT_THEN_STANDARD_SOURCE_RECOVERY',
    forbidden_action: 'SOURCE_CHECKPOINT_PREFLIGHT',
  };
}

function taskActionProjection(paths, state, goalId, manifestTask, options = {}) {
  let actions = allowedActions(state);
  const exactCurrentRoleActions = exactRoleLostActions(
    state,
    options.goalSnapshot || null,
  );
  actions = [
    ...actions.filter((action) => action.type !== 'ROLE_LOST'),
    ...exactCurrentRoleActions,
  ];
  const pending_operations = pendingActionOperations(paths, state, goalId);
  if (pending_operations.length > 0) {
    return {
      launch_scope: 'OPERATION_PENDING',
      actions: [],
      maintenance_actions: [],
      pending_operations,
    };
  }
  const sourceCheckpointHoldActions =
    sourceCheckpointHoldMaintenanceActions(
      paths,
      state,
      goalId,
      manifestTask,
    );
  const maintenance_actions = [
    ...runtimeRotationMaintenanceActions(paths, state, goalId),
    ...sourceCheckpointHoldActions,
    ...candidatePreflightMaintenanceActions(
      paths,
      state,
      goalId,
      manifestTask,
    ),
    ...heartbeatMaintenanceActions(
      state,
      options.goalSnapshot || null,
    ),
    ...activeOwnerResourceRenewalActions(paths, state, goalId),
    ...terminalOwnerResourceReleaseActions(paths, state, goalId),
  ];
  try {
    for (const workerSession of Object.values(state.sessions || {})) {
      if (
        !['DEV', 'REVIEW', 'RECEIPT'].includes(workerSession.role)
          || !['active', 'idle'].includes(workerSession.status)
          || !workerSession.launch_id
      ) {
        continue;
      }
      requiredWorkerBootstrapBinding(
        options.manifest,
        workerSession,
        workerSession.role,
      );
      const workerLaunchFile = path.join(
        paths.dir,
        'launches',
        state.task_id,
        `${workerSession.launch_id}.json`,
      );
      if (!fs.existsSync(workerLaunchFile)) continue;
      const workerLaunch = validateLaunchManifest(
        readJson(
          workerLaunchFile,
          `launch ${workerSession.launch_id}`,
        ),
      );
      const workerLaunchWorktree =
        fs.realpathSync(workerLaunch.repository.worktree);
      assertProjectedWorkerBootstrapIdentity(
        state,
        workerSession,
        workerLaunch,
        workerLaunchWorktree,
      );
    }
  } catch (error) {
    return {
      launch_scope: 'LAUNCH_INVALID',
      launch_error_code: error.code === 'ENOENT'
        ? 'WORKTREE_MISSING'
        : (error.code || 'INVALID_LAUNCH'),
      actions: actions.filter(
        (action) => ['ADD_HOLD', 'ROLE_LOST'].includes(action.type),
      ),
      maintenance_actions,
      pending_operations,
    };
  }
  const launchTargetRoles = new Map([
    ['LAUNCH_DEV', 'DEV'],
    ['LAUNCH_REVIEW', 'REVIEW'],
    ['LAUNCH_RECEIPT', 'RECEIPT'],
  ]);
  const projectedLaunches = actions.filter(
    (action) => launchTargetRoles.has(action.type),
  );
  if (projectedLaunches.length > 0) {
    try {
      const observedNow = runtimeNowMilliseconds();
      assertRequiredLiveProbeObservationBinding(
        options.manifest,
        state.sessions.CAPTAIN,
        'CAPTAIN public launch action projection',
        observedNow,
        {
          repositoryHead: state.full_head,
          role: 'CAPTAIN',
          taskId: state.task_id,
        },
      );
      for (const action of projectedLaunches) {
        const targetRole = launchTargetRoles.get(action.type);
        assertRequiredLiveProbeObservationBinding(
          options.manifest,
          state.sessions[targetRole],
          `${targetRole} public launch action projection`,
          observedNow,
          {
            repositoryHead: state.full_head,
            role: targetRole,
            taskId: state.task_id,
          },
        );
      }
    } catch (error) {
      const blockedLaunchTypes = new Set(
        projectedLaunches.map((action) => action.type),
      );
      return {
        launch_scope: 'PREFLIGHT_ONLY',
        launch_error_code:
          error.code || 'CANARY_OBSERVATION_INVALID',
        actions: actions.filter(
          (action) => !blockedLaunchTypes.has(action.type),
        ),
        maintenance_actions: maintenance_actions.filter(
          (action) => action.type !== 'REQUEST_CANDIDATE_PREFLIGHT',
        ),
        pending_operations,
      };
    }
  }
  const expectedRole = expectedRoleForPhase(state.phase);
  if (!['DEV', 'REVIEW', 'RECEIPT'].includes(expectedRole)) {
    return {
      launch_scope: null,
      actions,
      maintenance_actions,
      pending_operations,
    };
  }
  const blockedByRole = {
    DEV: new Set(['DEV_READY']),
    REVIEW: new Set(['REVIEW_REWORK', 'REVIEW_PASS']),
    RECEIPT: new Set(['RECEIPT_FAIL', 'RECEIPT_PASS']),
  };
  const withoutWorkerVerdict = () => (
    actions.filter((action) => !blockedByRole[expectedRole].has(action.type))
  );
  const session = state.sessions[expectedRole];
  if (!session || !session.launch_id || !['active', 'idle'].includes(session.status)) {
    return {
      launch_scope: session && !['active', 'idle'].includes(session.status)
        ? 'ROLE_UNAVAILABLE'
        : 'LAUNCH_NOT_VALIDATED',
      actions: withoutWorkerVerdict(),
      maintenance_actions,
      pending_operations,
    };
  }
  const operationalScope = sessionOperationalScope(state, expectedRole);
  if (operationalScope !== 'FULL') {
    return {
      launch_scope: operationalScope,
      actions: withoutWorkerVerdict(),
      maintenance_actions,
      pending_operations,
    };
  }
  try {
    const observedNow = runtimeNowMilliseconds();
    assertRequiredLiveProbeObservationBinding(
      options.manifest,
      session,
      `${expectedRole} action projection`,
      observedNow,
      {
        role: expectedRole,
        taskId: state.task_id,
      },
    );
    const captain = state.sessions.CAPTAIN;
    assertRequiredLiveProbeObservationBinding(
      options.manifest,
      captain,
      'CAPTAIN action projection',
      observedNow,
      {
        role: 'CAPTAIN',
        taskId: state.task_id,
      },
    );
  } catch (error) {
    return {
      launch_scope: 'PREFLIGHT_ONLY',
      launch_error_code: error.code || 'CANARY_OBSERVATION_INVALID',
      actions: withoutWorkerVerdict(),
      maintenance_actions: maintenance_actions.filter(
        (action) => action.type !== 'REQUEST_CANDIDATE_PREFLIGHT',
      ),
      pending_operations,
    };
  }
  try {
    requiredWorkerBootstrapBinding(
      options.manifest,
      session,
      expectedRole,
    );
  } catch (error) {
    return {
      launch_scope: 'LAUNCH_INVALID',
      launch_error_code: error.code || 'INVALID_LAUNCH',
      actions: withoutWorkerVerdict(),
      maintenance_actions,
      pending_operations,
    };
  }
  const launchFile = path.join(paths.dir, 'launches', state.task_id, `${session.launch_id}.json`);
  if (fs.existsSync(launchFile)) {
    try {
      const launch = validateLaunchManifest(readJson(launchFile, `launch ${session.launch_id}`));
      const launchWorktree = fs.realpathSync(launch.repository.worktree);
      assertLaunchRuntimeIncarnation(session, launch);
      const predecessor = predecessorLaunchForRotation(
        { paths },
        state,
        session,
      );
      if (predecessor) {
        assertRotationSuccessorLaunch(predecessor, session, launch);
      }
      assertControl(
        launch.goal_id === goalId
          && launch.task_id === state.task_id
          && launch.role === expectedRole
          && launch.thread.id === session.thread_id
          && launch.thread.host_id === session.host_id
          && launch.execution.task_nonce === session.task_nonce
          && launch.state_revision === session.registered_state_revision
          && launch.control_epoch === state.control_epoch
          && launch.packet.revision === state.packet.revision
          && normalizePacketHash(launch.packet.sha256) === state.packet.sha256
          && launch.repository.base_head === state.base_head,
        'STALE_LAUNCH',
        'launch projection binding 陈旧',
      );
      assertControl(launch.repository.worktree === launchWorktree, 'WORKTREE_MISMATCH', 'launch worktree 不是 canonical path');
      assertProjectedWorkerBootstrapIdentity(
        state,
        session,
        launch,
        launchWorktree,
      );
      assertControl(launch.repository.branch === git(launchWorktree, ['branch', '--show-current']), 'BRANCH_MISMATCH', 'launch branch 与 worktree 不一致');
      const actualLaunchHead = git(launchWorktree, ['rev-parse', 'HEAD']);
      const projectionObservedAt = runtimeNowMilliseconds();
      assertRequiredLiveProbeObservationBinding(
        options.manifest,
        session,
        `${expectedRole} live launch projection`,
        projectionObservedAt,
        {
          repositoryHead: actualLaunchHead,
          role: expectedRole,
          taskId: state.task_id,
        },
      );
      assertRequiredLiveProbeObservationBinding(
        options.manifest,
        state.sessions.CAPTAIN,
        'CAPTAIN live launch projection',
        projectionObservedAt,
        {
          repositoryHead: actualLaunchHead,
          role: 'CAPTAIN',
          taskId: state.task_id,
        },
      );
      if (expectedRole === 'DEV') {
        const exactRuntimeHead = assertDevLaunchHead(
          launchWorktree,
          state,
          session,
          launch,
          actualLaunchHead,
        );
        if (!exactRuntimeHead) {
          const targetRequiresFreshRuntime =
            ['BROWSER', 'ELECTRON'].includes(
              launch.execution.target.kind,
            );
          const runtimeBinding = sourceRuntimeBindingStatus(
            launchWorktree,
            launch,
          );
          const runtimeBindingChanged =
            !runtimeBinding.lockfile.matches;
          if (targetRequiresFreshRuntime || runtimeBindingChanged) {
            const trigger = targetRequiresFreshRuntime
              ? 'SOURCE_HEAD_REQUIRES_FRESH_RUNTIME'
              : 'SOURCE_RUNTIME_BINDING_CHANGED';
            const freshRuntimeRecoveryAction =
              freshDevRecoveryForSourceAdvance(
                state,
                goalId,
                session,
                launch,
                actualLaunchHead,
                {
                  trigger,
                  reason: targetRequiresFreshRuntime
                    ? `${launch.execution.target.kind} source HEAD advanced;`
                      + ' fresh runtime/worker recovery is required'
                    : 'source HEAD advanced and pnpm lockfile binding '
                      + 'changed; fresh runtime/worker recovery is required',
                  runtimeBinding: runtimeBindingChanged
                    ? runtimeBinding
                    : null,
                },
              );
            return {
              launch_scope: 'FRESH_RUNTIME_RECOVERY_REQUIRED',
              actions: [
                ...withoutWorkerVerdict().filter((action) => (
                  action.type !== 'ROLE_LOST'
                    || action.target_role
                )),
                freshRuntimeRecoveryAction,
              ],
              maintenance_actions: maintenance_actions.filter(
                (action) => (
                  action.type !== 'REQUEST_CANDIDATE_PREFLIGHT'
                ),
              ),
              pending_operations,
            };
          }
          const sourceHoldPending = maintenance_actions.some(
            (action) => (
              action.type === 'REQUEST_CANDIDATE_HOLD_REVALIDATION'
            ),
          );
          const candidatePreflight = sourceHoldPending
            ? null
            : trustedCandidatePreflight(
              paths,
              state,
              goalId,
              manifestTask,
              actualLaunchHead,
            );
          if (!candidatePreflight) {
            return {
              launch_scope: sourceHoldPending
                ? 'SOURCE_CHECKPOINT_HOLD_PENDING_REVALIDATION'
                : 'SOURCE_CHECKPOINT_PREFLIGHT_REQUIRED',
              actions: withoutWorkerVerdict(),
              maintenance_actions,
              pending_operations,
            };
          }
        }
      } else {
        assertControl(
          launch.repository.full_head === state.full_head
            && actualLaunchHead === state.full_head,
          'STALE_HEAD',
          `${expectedRole} launch/worktree HEAD 与 task full HEAD 不一致`,
        );
      }
      const root = path.dirname(path.dirname(paths.dir));
      const { verifyLaunchResourceRequirementsUnlocked } = require('./resources');
      verifyLaunchResourceRequirementsUnlocked(root, manifestTask, launch, state, {
        repairHeads: options.readOnly !== true,
        allowRuntimeRotationHold: isRuntimeRotationHoldLane(
          state,
          session,
          launch,
        ),
      });
      return {
        launch_scope: isRuntimeRotationHoldLane(state, session, launch)
          ? 'RUNTIME_HOLD_PENDING_RESOLUTION'
          : 'FULL',
        actions,
        maintenance_actions,
        pending_operations,
      };
    } catch (error) {
      return {
        launch_scope: 'LAUNCH_INVALID',
        launch_error_code: error.code === 'ENOENT'
          ? 'WORKTREE_MISSING'
          : (error.code || 'INVALID_LAUNCH'),
        actions: withoutWorkerVerdict(),
        maintenance_actions,
        pending_operations,
      };
    }
  }

  actions = withoutWorkerVerdict();
  return {
    launch_scope: isRuntimeRotationHoldLane(state, session)
      ? 'RUNTIME_PREFLIGHT_REQUIRED'
      : 'LAUNCH_NOT_VALIDATED',
    actions,
    maintenance_actions,
    pending_operations,
  };
}

function mergeExpectedMainHead(loaded, task) {
  const lowerTasks = loaded.manifest.tasks.filter((candidate) => candidate.integration_order < task.integration_order);
  for (const lower of lowerTasks) {
    const lowerState = loaded.snapshot.tasks[lower.id];
    assertControl(['MERGED_TO_MAIN', 'ARCHIVED'].includes(lowerState.phase), 'INTEGRATION_ORDER_BLOCKED', `${task.id} 前置集成任务 ${lower.id} 尚未 merge`);
  }
  if (lowerTasks.length > 0) {
    const latestLowerState = loaded.snapshot.tasks[
      lowerTasks[lowerTasks.length - 1].id
    ];
    assertControl(
      latestLowerState.merge
        && typeof latestLowerState.merge.main_merge_sha === 'string',
      'CORRUPT_STORE',
      `${task.id} 前置集成任务缺 main_merge_sha`,
    );
    assertFullSha(
      latestLowerState.merge.main_merge_sha,
      `${task.id}.expected_main_head`,
    );
    return latestLowerState.merge.main_merge_sha;
  }
  const expectedMainHead = task.p1
    ? loaded.meta.goal_input_head
    : loaded.manifest.base_head;
  assertFullSha(expectedMainHead, `${task.id}.expected_main_head`);
  return expectedMainHead;
}

function validateMergeBoundary(cwd, loaded, task, state, event) {
  const worktree = repoRoot(cwd);
  if (task.p1) assertMechanicalP1DependenciesArchived(loaded, task);
  const expectedMainHead = mergeExpectedMainHead(loaded, task);
  assertControl(event.payload.expected_main_head === expectedMainHead, 'STALE_MAIN_HEAD', `expected_main_head 应为 ${expectedMainHead}`);
  git(worktree, ['cat-file', '-e', `${expectedMainHead}^{commit}`]);
  git(worktree, ['cat-file', '-e', `${event.payload.main_merge_sha}^{commit}`]);
  git(worktree, ['cat-file', '-e', `${state.full_head}^{commit}`]);
  const taskPatch = git(worktree, ['diff', '--binary', '--full-index', expectedMainHead, state.full_head]);
  const mergedPatch = git(worktree, ['diff', '--binary', '--full-index', expectedMainHead, event.payload.main_merge_sha]);
  assertControl(hashObject(taskPatch) === hashObject(mergedPatch), 'MERGE_CONTENT_MISMATCH', 'main merge 内容与已验收 task HEAD 不一致');
  if (loaded.manifest.mode === 'enforce') {
    const originMain = git(worktree, ['rev-parse', `refs/remotes/origin/${loaded.manifest.repository.base_branch}`]);
    assertControl(originMain === event.payload.main_merge_sha, 'STALE_MAIN_HEAD', 'enforce 模式要求 origin/main 已指向 main_merge_sha');
  }
}

function validateArchiveBoundary(cwd, root, loaded, state, event) {
  if (event.type !== 'ARCHIVED') return;
  assertControl(
    state.merge && typeof state.merge.main_merge_sha === 'string',
    'ARCHIVE_MERGE_REQUIRED',
    'ARCHIVED 前缺 durable merge boundary',
  );
  const worktree = repoRoot(cwd);
  git(worktree, ['cat-file', '-e', `${state.merge.main_merge_sha}^{commit}`]);
  assertControl(
    git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '',
    'ARCHIVE_WORKTREE_DIRTY',
    'ARCHIVED 只接受 clean control worktree；未提交/未归档内容必须先形成 durable checkpoint',
  );
  const devPreflight = state.evidence
    && state.evidence.dev
    && state.evidence.dev.preflight;
  assertControl(
    devPreflight && typeof devPreflight.launch_uri === 'string',
    'ARCHIVE_DEV_EVIDENCE_REQUIRED',
    'ARCHIVED 前缺 DEV candidate launch evidence',
  );
  const devLaunchFile = fileURLToPath(new URL(devPreflight.launch_uri));
  assertControl(
    fs.existsSync(devLaunchFile) && fs.statSync(devLaunchFile).isFile(),
    'ARCHIVE_DEV_LAUNCH_MISSING',
    'ARCHIVED 前 DEV candidate launch artifact 必须仍可验证',
  );
  assertControl(
    hashFile(devLaunchFile) === normalizeHash(devPreflight.launch_sha256),
    'ARCHIVE_DEV_LAUNCH_TAMPERED',
    'ARCHIVED 前 DEV candidate launch artifact hash 漂移',
  );
  const devLaunch = validateLaunchManifest(readJson(devLaunchFile, 'archive DEV candidate launch'));
  const devSession = state.sessions.DEV;
  assertControl(
    devSession,
    'FRESH_SESSION_REQUIRED',
    'ARCHIVED 前缺 DEV session',
  );
  requiredWorkerBootstrapBinding(
    loaded.manifest,
    devSession,
    'DEV',
  );
  assertWorkerBootstrapLaunchBinding(
    devSession,
    devLaunch,
    { allowHeadAdvance: true },
  );
  assertControl(
    devLaunch.role === 'DEV'
      && devLaunch.goal_id === loaded.manifest.goal_id
      && devLaunch.task_id === state.task_id
      && devLaunch.repository.full_head === state.full_head,
    'ARCHIVE_DEV_LAUNCH_MISMATCH',
    'ARCHIVED 前 DEV candidate launch 未绑定当前 task/full HEAD',
  );
  assertControl(
    fs.existsSync(devLaunch.repository.worktree)
      && fs.statSync(devLaunch.repository.worktree).isDirectory(),
    'ARCHIVE_DEV_WORKTREE_MISSING',
    'ARCHIVED 前 DEV candidate worktree 必须存在；先做机械 clean/unpushed 检查，不能先 App archive',
  );
  const devWorktree = fs.realpathSync(devLaunch.repository.worktree);
  assertWorkerBootstrapCurrentWorktree(
    devSession,
    workerBootstrapWorktreeIdentity(devWorktree),
    { allowHeadAdvance: true },
  );
  assertControl(
    devWorktree === devLaunch.repository.worktree,
    'ARCHIVE_DEV_WORKTREE_MISMATCH',
    'ARCHIVED 前 DEV candidate worktree canonical path 漂移',
  );
  assertControl(
    git(devWorktree, ['rev-parse', 'HEAD']) === state.full_head,
    'ARCHIVE_DEV_HEAD_MOVED',
    'ARCHIVED 前 DEV worktree HEAD 已在验收后移动；必须重新走 candidate gates',
  );
  assertControl(
    git(devWorktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '',
    'ARCHIVE_DEV_WORKTREE_DIRTY',
    'ARCHIVED 前 DEV worktree 必须 clean；不得回收 dirty/untracked delta',
  );
  git(devWorktree, ['diff', '--check', 'HEAD']);
  const { nonTerminalTaskLeasesUnlocked } = require('./resources');
  const leases = nonTerminalTaskLeasesUnlocked(
    root,
    loaded.manifest.goal_id,
    state.task_id,
  );
  assertControl(
    leases.length === 0,
    'ARCHIVE_RESOURCE_LEASES_ACTIVE',
    `ARCHIVED 前必须释放或隔离全部 task resource leases: ${leases.map((lease) => lease.lease_id).join(', ')}`,
  );
}

function validatePreparedIdentityIncidentAuthorization(
  root,
  loaded,
  state,
  event,
  actorCapabilityFile,
  authorization,
) {
  const prepared = authorization
    && authorization.preparedIdentityIncident;
  assertControl(
    prepared
      && typeof prepared.evidenceId === 'string'
      && typeof prepared.authoritySha256 === 'string',
    'INCIDENT_AUTHORITY_REQUIRED',
    `pending identity incident ${event.event_id} 只能由 sealed prepared authority 完成`,
  );
  const evidenceId = safeId(
    prepared.evidenceId,
    'prepared identity incident evidence_id',
  );
  const registryFile = path.join(
    loaded.paths.dir,
    'evidence',
    state.task_id,
    `${evidenceId}.json`,
  );
  const registry = readJson(
    registryFile,
    `identity incident evidence ${evidenceId}`,
  );
  const unsignedRegistry = { ...registry };
  delete unsignedRegistry.registry_sha256;
  assertControl(
    registry.registry_sha256 === hashObject(unsignedRegistry)
      && registry.goal_id === loaded.manifest.goal_id
      && registry.task_id === state.task_id
      && registry.evidence_id === evidenceId
      && registry.kind === 'HOLD_ASSERTION'
      && registry.status === 'BLOCKED'
      && registry.producer
      && registry.producer.role === event.actor.role
      && registry.producer.thread_id === event.actor.thread_id
      && registry.producer.host_id === event.actor.host_id,
    'INCIDENT_AUTHORITY_INVALID',
    `identity incident evidence ${evidenceId} registry binding 非法`,
  );
  let sourceFile;
  try {
    sourceFile = fileURLToPath(new URL(registry.uri));
  } catch {
    assertControl(false, 'INCIDENT_AUTHORITY_INVALID', 'identity incident source uri 非法');
  }
  assertControl(
    fs.existsSync(sourceFile)
      && fs.lstatSync(sourceFile).isFile()
      && !fs.lstatSync(sourceFile).isSymbolicLink()
      && hashFile(sourceFile) === registry.source_sha256,
    'INCIDENT_AUTHORITY_INVALID',
    `identity incident evidence ${evidenceId} source 漂移`,
  );
  const source = readJson(sourceFile, `identity incident source ${evidenceId}`);
  const authority = source.event_authority;
  const unsignedAuthority = { ...authority };
  delete unsignedAuthority.authority_sha256;
  assertControl(
    authority
      && authority.kind === 'IDENTITY_INCIDENT_EVENT_AUTHORITY'
      && authority.authority_sha256 === hashObject(unsignedAuthority)
      && authority.authority_sha256 === prepared.authoritySha256
      && authority.goal_id === loaded.manifest.goal_id
      && authority.task_id === state.task_id
      && authority.evidence_id === evidenceId
      && authority.event_id === event.event_id
      && authority.event_input_sha256 === hashObject(event)
      && source.incident_event
      && hashObject(source.incident_event) === hashObject(event)
      && event.type === 'ADD_HOLD'
      && event.payload
      && event.payload.kind === 'ENV_IDENTITY_INCIDENT'
      && event.payload.evidence_id === evidenceId,
    'INCIDENT_AUTHORITY_INVALID',
    `identity incident ${event.event_id} prepared event binding 漂移`,
  );
  const producer = authority.producer;
  const anchor = authority.task_anchor;
  assertControl(
    producer
      && producer.role === event.actor.role
      && producer.thread_id === event.actor.thread_id
      && producer.host_id === event.actor.host_id
      && Number.isSafeInteger(producer.attempt)
      && typeof producer.lease_until === 'string'
      && Number.isFinite(Date.parse(producer.lease_until))
      && typeof authority.prepared_accepted_at === 'string'
      && Number.isFinite(Date.parse(authority.prepared_accepted_at))
      && Date.parse(authority.prepared_accepted_at)
        <= Date.parse(producer.lease_until)
      && anchor
      && anchor.control_epoch === loaded.control.epoch
      && anchor.state_revision === state.state_revision
      && anchor.packet.revision === state.packet.revision
      && anchor.packet.sha256 === state.packet.sha256
      && anchor.base_head === state.base_head
      && anchor.full_head === state.full_head
      && event.expected_state_revision === anchor.state_revision
      && event.control_epoch === anchor.control_epoch
      && event.packet.revision === anchor.packet.revision
      && event.packet.sha256 === anchor.packet.sha256
      && event.base_head === anchor.base_head
      && event.full_head === anchor.full_head
      && event.actor_sequence === anchor.prior_actor_sequence + 1,
    'INCIDENT_AUTHORITY_INVALID',
    `identity incident ${event.event_id} producer/task anchor 漂移`,
  );
  const supplied = readCapabilityFile(
    actorCapabilityFile,
    producer.capability_file,
  );
  assertControl(
    hashesEqual(supplied.sha256, producer.capability_sha256),
    'CAPABILITY_INVALID',
    'identity incident capability 未匹配 sealed producer authority',
  );
  const candidateStates = producer.role === 'FOREMAN'
    ? Object.values(loaded.snapshot.tasks)
    : [state];
  const sessions = candidateStates.flatMap((candidateState) => [
    ...Object.values(candidateState.sessions || {}),
    ...Object.values(candidateState.session_history || {}).flat(),
  ]).filter((session) => (
    session
      && session.role === producer.role
      && session.thread_id === producer.thread_id
      && session.host_id === producer.host_id
      && session.attempt === producer.attempt
      && session.lease_until === producer.lease_until
      && session.capability_file === producer.capability_file
      && hashesEqual(
        session.capability_sha256,
        producer.capability_sha256,
      )
  ));
  assertControl(
    sessions.length > 0,
    'CAPABILITY_INVALID',
    'identity incident sealed producer 不在 Goal registration lineage',
  );
  return {
    acceptedAt: authority.prepared_accepted_at,
    authoritySha256: authority.authority_sha256,
    evidenceId,
    session: sessions[0],
  };
}

function validatePreparedP1AbandonmentAuthorization(
  root,
  loaded,
  state,
  event,
  authorization,
) {
  const operation = authorization.p1AbandonmentOperation;
  assertControl(
    operation
      && operation.prepared_event_id === event.payload.prepared_event_id,
    'P1_ABANDON_COMMAND_REQUIRED',
    'P1_COMMIT_ABANDONED 只允许 p1-abandon-commit canonical append',
  );
  const abandonment = readAbandonmentIntent(
    root,
    loaded.manifest.goal_id,
    state.task_id,
    event.payload.prepared_event_id,
  );
  const receipt = readP1AbandonmentReceipt(
    root,
    loaded.manifest.goal_id,
    state.task_id,
    event.payload.prepared_event_id,
  );
  const prepared = readP1CommitIntent(
    root,
    loaded.manifest.goal_id,
    state.task_id,
    event.payload.prepared_event_id,
  );
  assertControl(
    abandonment
      && abandonment.completion
      && receipt
      && prepared
      && operation.request_sha256 === abandonment.intent.request_sha256
      && operation.receipt_sha256 === receipt.receipt_sha256
      && abandonment.intent.p1_intent_sha256
        === prepared.intent.intent_sha256
      && abandonment.intent.request.p1_abandon_handoff_sha256
        === p1CommitAbandonmentHandoffSha256(prepared)
      && event.event_id === abandonment.intent.request.abandon_event_id
      && event.actor.role === 'FOREMAN'
      && event.actor.thread_id
        === abandonment.intent.foreman_authority.thread_id
      && event.actor.host_id
        === abandonment.intent.foreman_authority.host_id,
    'P1_ABANDON_AUTHORITY_INVALID',
    `P1_COMMIT_ABANDONED ${event.event_id} sideband/actor binding 非法`,
  );
  const anchor = abandonment.intent.task_anchor;
  const expectedPayload = {
    prepared_event_id: abandonment.intent.prepared_event_id,
    task_cycle: prepared.intent.task_cycle,
    p1_intent_sha256: prepared.intent.intent_sha256,
    abandon_intent_sha256: abandonment.intent.intent_sha256,
    abandon_request_sha256: abandonment.intent.request_sha256,
    abandon_receipt_sha256: receipt.receipt_sha256,
    commit_ref: prepared.intent.ref_binding.commit_ref,
    commit_sha: prepared.intent.ref_binding.new_commit,
    predecessor_event_sha256: anchor.prior_event_sha256,
    reason: abandonment.intent.request.reason,
    incident_ref: abandonment.intent.request.incident_ref,
  };
  assertControl(
    hashObject(event.payload) === hashObject(expectedPayload)
      && event.expected_state_revision === anchor.state_revision
      && event.control_epoch === anchor.control_epoch
      && event.packet.revision === anchor.packet.revision
      && event.packet.sha256 === anchor.packet.sha256
      && event.base_head === anchor.base_head
      && event.full_head === anchor.full_head
      && event.actor_sequence
        === anchor.foreman_prior_actor_sequence + 1,
    'P1_ABANDON_AUTHORITY_INVALID',
    `P1_COMMIT_ABANDONED ${event.event_id} task predecessor anchor 漂移`,
  );
  return { abandonment, receipt, prepared };
}

function acceptEventUnderLock(cwd, rawEvent, actorCapabilityFile, authorization = {}) {
  const root = controlRoot(cwd);
  let event = rawEvent;
  let goalId = rawEvent && rawEvent.goal_id;
  let taskId = rawEvent && rawEvent.task_id;
  let durableCommit = null;
  try {
      event = validateEvent(rawEvent);
      const eventRequest = JSON.parse(JSON.stringify(event));
      goalId = event.goal_id;
      taskId = event.task_id;
      const loaded = authorization.pristinePreflight === true
        ? loadOddRecoveryGoalState(root, goalId)
        : loadGoalStateUnlocked(root, goalId);
      const task = loaded.manifest.tasks.find((candidate) => candidate.id === taskId);
      const state = loaded.snapshot.tasks[taskId];
      assertControl(task, 'UNKNOWN_TASK', `Goal ${goalId} 没有 task ${taskId}`);
      assertControl(event.type !== 'REGISTER_ROLE', 'REGISTRATION_COMMAND_REQUIRED', 'REGISTER_ROLE 只能通过 register-role 授权命令提交');
      assertControl(event.type !== 'RECOVER_EXPIRED_FOREMAN', 'RECOVERY_COMMAND_REQUIRED', 'RECOVER_EXPIRED_FOREMAN 只能通过 recover-expired-foreman 授权命令提交');
      assertControl(
        event.type !== 'P1_COMMIT_ABANDONED'
          || authorization.p1AbandonmentOperation,
        'P1_ABANDON_COMMAND_REQUIRED',
        'P1_COMMIT_ABANDONED 只能通过 p1-abandon-commit 提交',
      );
      assertControl(
        event.type !== 'GITHUB_MERGE_RESERVED'
          || authorization.githubMergeReservationOperation,
        'GITHUB_MERGE_WRAPPER_REQUIRED',
        'GITHUB_MERGE_RESERVED 只能通过 canonical merge-pr 提交',
      );
      assertControl(
        event.type !== 'RUNTIME_ROTATED'
          || authorization.runtimeRotationOperation === true,
        'RUNTIME_ROTATION_COMMAND_REQUIRED',
        'RUNTIME_ROTATED 只能通过 rotate-runtime 提交',
      );
      assertControl(
        event.type === 'RUNTIME_ROTATED'
          || authorization.runtimeRotationOperation !== true,
        'RUNTIME_ROTATION_COMMAND_REQUIRED',
        'runtime rotation authorization 只能用于 RUNTIME_ROTATED',
      );
      const inputHash = hashObject(eventRequest);
      const p1Preparation = event.type === 'P1_COMMITTED' && task.p1
        ? inspectP1CommitPreparation(
          root,
          goalId,
          taskId,
          event.event_id,
          inputHash,
        )
        : null;
      const p1AbandonmentPreparation =
        event.type === 'P1_COMMIT_ABANDONED'
          ? validatePreparedP1AbandonmentAuthorization(
            root,
            loaded,
            state,
            event,
            authorization,
          )
          : null;
      assertControl(
        p1AbandonmentPreparation
          || !authorization.p1AbandonmentOperation,
        'P1_ABANDON_COMMAND_REQUIRED',
        'P1 abandonment authorization 只允许 canonical event 使用',
      );
      const githubMergeReservationPreparation = (
        event.type === 'GITHUB_MERGE_RESERVED'
          && loaded.manifest.repository.merge_policy
            === 'goalctl-github-squash-v1'
      )
        ? require('./github-merge').verifyMergeReservationForEvent(
          root,
          loaded,
          state,
          event,
          authorization.githubMergeReservationOperation || null,
        )
        : null;
      assertControl(
        githubMergeReservationPreparation
          || !authorization.githubMergeReservationOperation,
        'GITHUB_MERGE_WRAPPER_REQUIRED',
        'GitHub merge reservation authorization 只允许 canonical merge-pr 使用',
      );
      const githubMergePreparation = (
        event.type === 'MERGED'
          && loaded.manifest.repository.merge_policy
            === 'goalctl-github-squash-v1'
      )
        ? require('./github-merge').verifyMergeReceiptForEvent(
          root,
          loaded,
          state,
          event,
          authorization.githubMergeOperation || null,
        )
        : null;
      assertControl(
        githubMergePreparation || !authorization.githubMergeOperation,
        'GITHUB_MERGE_WRAPPER_REQUIRED',
        'GitHub merge authorization 只允许 canonical merge-pr 使用',
      );
      assertControl(
        goalControlEventOccurrences(loaded, event.event_id).length === 0,
        'EVENT_ID_CONFLICT',
        `event id ${event.event_id} 已被 Goal control event 使用`,
      );
      const eventIdOccurrences = goalEventIdOccurrences(loaded, event.event_id);
      assertControl(
        eventIdOccurrences.every((occurrence) => occurrence.task_id === taskId),
        'EVENT_ID_CONFLICT',
        `event id ${event.event_id} 已被 Goal 中其它 task 使用`,
      );
      const duplicateHash = eventIdOccurrences.length === 1
        ? eventIdOccurrences[0].input_sha256
        : null;
      if (duplicateHash) {
        assertControl(duplicateHash === inputHash, 'EVENT_ID_CONFLICT', `event id ${event.event_id} 已被不同内容使用`);
        const accepted = acceptedGoalEvent(root, loaded, taskId, event.event_id);
        assertControl(
          accepted && accepted.input_sha256 === duplicateHash,
          'CORRUPT_STORE',
          `accepted event ${event.event_id} 缺失或 input hash 不一致`,
        );
        authorizeAcceptedEventRetry(
          loaded,
          taskId,
          accepted,
          actorCapabilityFile,
        );
        const duplicateState = loaded.snapshot.tasks[taskId];
        if (
          accepted.type === 'P1_COMMITTED'
            && duplicateState.p1
            && duplicateState.p1.policy
        ) {
          finalizeAcceptedMechanicalP1Transaction(
            cwd,
            root,
            loaded,
            taskId,
            accepted,
          );
        }
        let ledger = null;
        let cache_degraded = false;
        try {
          ledger = writeProjections(loaded.paths, loaded.manifest, loaded.snapshot);
        } catch {
          cache_degraded = true;
        }
        return { accepted: true, idempotent: true, cache_degraded, event_id: event.event_id, task: publicTaskState(loaded.snapshot.tasks[taskId]), ledger };
      }
      assertLiveRoleLostTargetBinding(event);
      assertMechanicalP1CycleNotAbandoned(
        root,
        loaded,
        state,
        event,
      );
      const {
        assertNoPendingTaskOperations,
        listPendingTaskOperations,
      } = require('./pending-operations');
      const pendingOperations = listPendingTaskOperations(
        root,
        goalId,
        taskId,
      );
      const pendingIdentityIncident = pendingOperations.some((operation) => (
        operation.allowed_event_id === event.event_id
          && operation.kind.endsWith('IDENTITY_INCIDENT')
      ));
      let preparedIdentityIncident = null;
      if (pendingIdentityIncident) {
        preparedIdentityIncident = validatePreparedIdentityIncidentAuthorization(
          root,
          loaded,
          loaded.snapshot.tasks[taskId],
          event,
          actorCapabilityFile,
          authorization,
        );
      } else {
        assertControl(
          !authorization.preparedIdentityIncident,
          'INCIDENT_AUTHORITY_INVALID',
          'prepared identity incident authority 没有对应 pending operation',
        );
      }
      assertNoPendingTaskOperations(root, goalId, taskId, {
        ...(p1Preparation
          ? {
            allowOperationKind: 'P1_COMMIT_REF',
            allowOperationId: event.event_id,
            allowRequestSha256: inputHash,
          }
          : p1AbandonmentPreparation
            ? {
              allowOperationKind: 'P1_COMMIT_REF_ABANDON',
              allowOperationId: event.event_id,
              allowRequestSha256:
                p1AbandonmentPreparation.abandonment.intent.request_sha256,
            }
          : githubMergePreparation
            ? {
              allowOperationKind: 'GITHUB_MERGE',
              allowOperationId: event.event_id,
              allowRequestSha256:
                githubMergePreparation.intent.request_sha256,
            }
            : githubMergeReservationPreparation
              ? {
                allowOperationKind: 'GITHUB_MERGE',
                allowOperationId:
                  githubMergeReservationPreparation.intent.event_id,
                allowRequestSha256:
                  githubMergeReservationPreparation.intent.request_sha256,
              }
          : {
            allowEventId: event.event_id,
            allowEventSha256: inputHash,
          }),
        forArchive: event.type === 'ARCHIVED',
      });
      assertFrozenInputs(cwd, loaded, taskId);
      let goalForemanAuthority = null;
      let actorAuthority = null;
      if (p1AbandonmentPreparation) {
        actorAuthority = authorizeHistoricalActorCapability(
          loaded.snapshot,
          actorCapabilityFile,
          p1AbandonmentPreparation.abandonment.intent.foreman_authority,
          { goalWide: true, taskId },
        );
        goalForemanAuthority = {
          ...actorAuthority,
          task_id: actorAuthority.task_id || taskId,
        };
      } else if (githubMergePreparation) {
        assertControl(
          event.actor.role === 'FOREMAN'
            && event.actor.thread_id
              === githubMergePreparation.intent.acceptance_authority.thread_id
            && event.actor.host_id
              === githubMergePreparation.intent.acceptance_authority.host_id,
          'CAPABILITY_INVALID',
          'prepared GitHub merge event actor 与 sealed FOREMAN authority 不一致',
        );
        actorAuthority = authorizeHistoricalActorCapability(
          loaded.snapshot,
          actorCapabilityFile,
          githubMergePreparation.intent.acceptance_authority,
          { goalWide: true, taskId },
        );
        goalForemanAuthority = {
          ...actorAuthority,
          task_id: actorAuthority.task_id || taskId,
        };
      } else if (githubMergeReservationPreparation) {
        assertControl(
          event.actor.role === 'FOREMAN'
            && event.actor.thread_id
              === githubMergeReservationPreparation.intent
                .acceptance_authority.thread_id
            && event.actor.host_id
              === githubMergeReservationPreparation.intent
                .acceptance_authority.host_id,
          'CAPABILITY_INVALID',
          'prepared GitHub merge reservation actor 与 sealed FOREMAN authority 不一致',
        );
        actorAuthority = authorizeHistoricalActorCapability(
          loaded.snapshot,
          actorCapabilityFile,
          githubMergeReservationPreparation.intent.acceptance_authority,
          { goalWide: true, taskId },
        );
        goalForemanAuthority = {
          ...actorAuthority,
          task_id: actorAuthority.task_id || taskId,
        };
      } else if (p1Preparation) {
        assertControl(
          event.actor.role === 'CAPTAIN',
          'P1_COMMIT_AUTHORITY_INVALID',
          'prepared P1_COMMITTED 只能由原 CAPTAIN exact retry',
        );
        if (p1Preparation.intent) {
          assertMechanicalP1IntentAnchor(
            loaded,
            state,
            p1Preparation.intent,
          );
          actorAuthority = authorizeHistoricalActorCapability(
            loaded.snapshot,
            actorCapabilityFile,
            p1Preparation.intent.acceptance_authority,
            { taskId },
          );
          assertControl(
            event.actor.thread_id
              === p1Preparation.intent.acceptance_authority.thread_id
              && event.actor.host_id
                === p1Preparation.intent.acceptance_authority.host_id,
            'CAPABILITY_INVALID',
            'prepared P1 event actor 与 sealed authority 不一致',
          );
        } else {
          actorAuthority = authorizeHistoricalMechanicalP1Capability(
            loaded.snapshot,
            actorCapabilityFile,
            p1Preparation.acceptance_authority_sha256,
            {
              role: 'CAPTAIN',
              threadId: event.actor.thread_id,
              hostId: event.actor.host_id,
              taskId,
            },
          );
        }
      } else if (preparedIdentityIncident) {
        actorAuthority = preparedIdentityIncident.session;
        if (event.actor.role === 'FOREMAN') {
          goalForemanAuthority = {
            ...preparedIdentityIncident.session,
            task_id: preparedIdentityIncident.session.task_id || taskId,
          };
        }
      } else if (authorization.pristineEventRecovery === true) {
        actorAuthority = authorizeHistoricalActorCapability(
          loaded.snapshot,
          actorCapabilityFile,
          event.actor,
          {
            goalWide: event.actor.role === 'FOREMAN',
            taskId,
          },
        );
        if (event.actor.role === 'FOREMAN') {
          goalForemanAuthority = {
            ...actorAuthority,
            task_id: actorAuthority.task_id || taskId,
          };
        }
      } else if (event.actor.role === 'FOREMAN') {
        goalForemanAuthority = authorizeGoalSession(loaded.snapshot, actorCapabilityFile, {
          role: 'FOREMAN',
          threadId: event.actor.thread_id,
        });
        actorAuthority = goalForemanAuthority;
      } else {
        actorAuthority = authorizeSession(state, actorCapabilityFile, {
          role: event.actor.role,
          threadId: event.actor.thread_id,
        });
      }
      event.input_sha256 = inputHash;
      event.accepted_at = p1AbandonmentPreparation
        ? p1AbandonmentPreparation.abandonment.intent.accepted_at
        : githubMergePreparation
        ? githubMergePreparation.receipt.reserved_event_at
        : githubMergeReservationPreparation
        ? githubMergeReservationPreparation.intent.reserved_event_at
        : p1Preparation && p1Preparation.intent
        ? p1Preparation.intent.accepted_at
        : preparedIdentityIncident
          ? preparedIdentityIncident.acceptedAt
          : (
            authorization.pristineEventRecovery === true
                && authorization.pristineEventAcceptedAt
              ? authorization.pristineEventAcceptedAt
              : nowIso()
          );
      if (preparedIdentityIncident) {
        event.prepared_identity_incident_authority = {
          schema_version: 1,
          evidence_id: preparedIdentityIncident.evidenceId,
          authority_sha256: preparedIdentityIncident.authoritySha256,
        };
      }
      if (
        p1Preparation
          && p1Preparation.intent
          && (
            p1Preparation.intent.abort_only === true
              || p1Preparation.abandonHandoff
              || p1Preparation.abandonHandoffTemporary
          )
      ) {
        assertMechanicalP1IntentAnchor(
          loaded,
          state,
          p1Preparation.intent,
        );
        const installed = p1Preparation.intent.abort_only === true
          ? publishP1CommitAbandonOnlyIntent({
            cwd,
            root,
            goalId,
            taskId,
            eventId: event.event_id,
            requestSha256: inputHash,
            unsignedIntent: null,
          })
          : publishP1CommitAbandonHandoff({
            cwd,
            root,
            goalId,
            taskId,
            preparation: p1Preparation,
          });
        return {
          accepted: false,
          idempotent: p1Preparation.staging !== true
            && !p1Preparation.abandonHandoffTemporary,
          prepared: true,
          abandonment_required: true,
          event_id: event.event_id,
          request_sha256: installed.intent.request_sha256,
          intent_sha256: installed.intent.intent_sha256,
          ...(installed.abandonHandoff
            ? {
              abandon_handoff_sha256:
                installed.abandonHandoff.handoff_sha256,
            }
            : {}),
          commit_ref: installed.intent.ref_binding.commit_ref,
          commit_sha: installed.intent.ref_binding.new_commit,
          reason_code: installed.abandonHandoff
            ? installed.abandonHandoff.reason_code
            : installed.intent.abort_binding.reason_code,
          task: publicTaskState(state),
        };
      }
      if (goalForemanAuthority) {
        event.goal_foreman_authority = {
          source_task_id: goalForemanAuthority.task_id,
          thread_id: goalForemanAuthority.thread_id,
          host_id: goalForemanAuthority.host_id,
          attempt: goalForemanAuthority.attempt,
          capability_file: goalForemanAuthority.capability_file,
          capability_sha256: goalForemanAuthority.capability_sha256,
          lease_until: goalForemanAuthority.lease_until,
        };
      }
      let p1Inventory = null;
      if (p1Preparation) {
        try {
          restoreP1CommitObject(cwd, p1Preparation, event.full_head);
        } catch (error) {
          if (
            !(
              error instanceof ControlError
                && error.code === 'P1_COMMIT_CARRIER_UNAVAILABLE'
                && p1Preparation.staging === true
                && !p1Preparation.intent
            )
          ) {
            throw error;
          }
          const installed = publishP1CommitAbandonOnlyIntent({
            cwd,
            root,
            goalId,
            taskId,
            eventId: event.event_id,
            requestSha256: inputHash,
            unsignedIntent: buildMechanicalP1CommitIntent(
              cwd,
              loaded,
              state,
              eventRequest,
              event,
              actorAuthority,
              null,
            ),
          });
          return {
            accepted: false,
            idempotent: false,
            prepared: true,
            abandonment_required: true,
            event_id: event.event_id,
            request_sha256: installed.intent.request_sha256,
            intent_sha256: installed.intent.intent_sha256,
            commit_ref: installed.intent.ref_binding.commit_ref,
            commit_sha: installed.intent.ref_binding.new_commit,
            reason_code: installed.intent.abort_binding.reason_code,
            task: publicTaskState(state),
          };
        }
        p1Inventory = assertMechanicalP1ObjectBoundary(
          cwd,
          loaded,
          state,
          event,
        );
      } else {
        validateP1Boundary(cwd, loaded, state, event);
        if (event.type === 'P1_COMMITTED' && task.p1) {
          p1Inventory = committedP1ArtifactInventory(
            cwd,
            task.p1,
            event.full_head,
          );
        }
      }
      validateCandidateBoundary(cwd, loaded, state, event);
      validatePullRequestBoundary(loaded, event);
      validateRecoveryHandoffBoundary(cwd, loaded, state, event);
      const goalForemanCoauthority = validateRecoveryHandoffAbandonBoundary(
        root,
        loaded,
        state,
        event,
        authorization,
      );
      if (goalForemanCoauthority) {
        event.goal_foreman_coauthority = {
          source_task_id: goalForemanCoauthority.task_id,
          thread_id: goalForemanCoauthority.thread_id,
          host_id: goalForemanCoauthority.host_id,
          attempt: goalForemanCoauthority.attempt,
          capability_file: goalForemanCoauthority.capability_file,
          capability_sha256: goalForemanCoauthority.capability_sha256,
          lease_until: goalForemanCoauthority.lease_until,
        };
      }
      validateRecoveryPromotionBoundary(cwd, root, loaded, state, event);
      if (event.type === 'RUNTIME_ROTATED') {
        validateRuntimeRotationBoundary(
          root,
          loaded,
          state,
          task,
          event,
        );
      }
      if (event.type === 'PACKET_UPDATED') validatePacketUpdateAtBoundary(cwd, loaded, taskId, event);
      if (event.type === 'MERGED') validateMergeBoundary(cwd, loaded, task, state, event);
      validateArchiveBoundary(cwd, root, loaded, state, event);
      validateRoleHoldBoundary(state, event);
      const preparedEvent = resolveEventEvidence(
        root,
        goalId,
        state,
        event,
        task,
        {
          readOnly: authorization.pristinePreflight === true
            || authorization.pristineEventRecovery === true,
          acceptedReplay: authorization.pristinePreflight === true
            || authorization.pristineEventRecovery === true,
        },
      );
      bindAcceptedEventEvidence(event, preparedEvent);
      validateRoleLaunchBoundary(
        cwd,
        root,
        loaded,
        state,
        preparedEvent,
        {
          readOnly: authorization.pristinePreflight === true,
          historical: authorization.pristineEventRecovery === true,
        },
      );
      const nextState = applyEvent(
        state,
        preparedEvent,
        loaded.control.epoch,
      );
      if (authorization.pristinePreflight === true) {
        return {
          pristine_preflight_authorized: true,
          event_id: event.event_id,
          request_sha256: inputHash,
        };
      }
      let p1Transaction = p1Preparation;
      if (event.type === 'P1_COMMITTED' && task.p1) {
        if (!p1Transaction || !p1Transaction.intent) {
          p1Transaction = publishP1CommitIntent({
            cwd,
            root,
            goalId,
            taskId,
            eventId: event.event_id,
            requestSha256: inputHash,
            requiredStartHead: mechanicalP1RequiredStartHead(
              loaded,
              task,
            ),
            unsignedIntent: buildMechanicalP1CommitIntent(
              cwd,
              loaded,
              state,
              eventRequest,
              event,
              actorAuthority,
              p1Inventory,
            ),
          });
        }
        assertMechanicalP1IntentAnchor(
          loaded,
          state,
          p1Transaction.intent,
        );
        maybeInjectP1CommitFault(
          cwd,
          'GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL',
          'TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL',
          'injected failure after durable P1 commit intent install',
        );
        restoreP1CommitObject(
          cwd,
          p1Transaction,
          p1Transaction.intent.ref_binding.new_commit,
        );
        try {
          publishP1CommitRef(
            cwd,
            p1Transaction.intent,
            p1Transaction.abandonHandoff,
          );
        } catch (error) {
          if (
            !(
              error instanceof ControlError
                && error.code === 'P1_COMMIT_REF_CONFLICT'
            )
          ) {
            throw error;
          }
          const handedOff = publishP1CommitAbandonHandoff({
            cwd,
            root,
            goalId,
            taskId,
            preparation: p1Transaction,
          });
          return {
            accepted: false,
            idempotent: false,
            prepared: true,
            abandonment_required: true,
            event_id: event.event_id,
            request_sha256: handedOff.intent.request_sha256,
            intent_sha256: handedOff.intent.intent_sha256,
            abandon_handoff_sha256:
              handedOff.abandonHandoff.handoff_sha256,
            commit_ref: handedOff.intent.ref_binding.commit_ref,
            commit_sha: handedOff.intent.ref_binding.new_commit,
            reason_code: handedOff.abandonHandoff.reason_code,
            task: publicTaskState(state),
          };
        }
        maybeInjectP1CommitFault(
          cwd,
          'GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_REF',
          'TEST_FAULT_AFTER_P1_COMMIT_REF',
          'injected failure after P1 commit ref CAS before event append',
        );
        event.p1_commit_transaction = {
          schema_version: 1,
          kind: 'P1_COMMIT_REF_TRANSACTION',
          goal_id: goalId,
          task_id: taskId,
          task_cycle: p1Transaction.intent.task_cycle,
          event_id: event.event_id,
          request_sha256: p1Transaction.intent.request_sha256,
          intent_sha256: p1Transaction.intent.intent_sha256,
          commit_ref: p1Transaction.intent.ref_binding.commit_ref,
          commit_sha: p1Transaction.intent.ref_binding.new_commit,
          bundle_sha256: p1Transaction.intent.bundle.sha256,
        };
        nextState.p1.commit_transaction = JSON.parse(JSON.stringify(
          event.p1_commit_transaction,
        ));
      }
      durableCommit = writeAcceptedEvent(
        root,
        goalId,
        taskId,
        nextState.state_revision,
        event,
        loaded.lastEventHashes[taskId] || null,
      );
      if (p1Transaction && p1Transaction.intent) {
        maybeInjectP1CommitFault(
          cwd,
          'GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_APPEND',
          'TEST_FAULT_AFTER_P1_COMMIT_APPEND',
          'injected failure after P1 event append before completion seal',
        );
        completeP1CommitTransaction(
          root,
          goalId,
          taskId,
          p1Transaction.intent,
          durableCommit.event,
        );
      }
      nextState.last_event.event_sha256 = durableCommit.event.event_sha256;
      loaded.snapshot.tasks[taskId] = nextState;
      loaded.snapshot.generated_at = nowIso();
      let ledger = null;
      let cache_degraded = Boolean(durableCommit.headError);
      try {
        ledger = writeProjections(loaded.paths, loaded.manifest, loaded.snapshot);
      } catch {
        cache_degraded = true;
      }
      return { accepted: true, idempotent: false, cache_degraded, event_id: event.event_id, event_sha256: durableCommit.event.event_sha256, task: publicTaskState(nextState), ledger };
    } catch (error) {
      const controlError = error instanceof ControlError
        ? error
        : new ControlError('UNEXPECTED', error.message);
      throw controlError;
  }
}

function loadOddRecoveryGoalState(root, goalId) {
  return loadGoalStateUnlocked(root, goalId, {
    repairHeads: false,
    allowLaggingHeads: true,
    repairBootstrapConsumption: false,
    allowIncompleteRecoveryRead: true,
    allowIncompleteGoalOperationRead: true,
  });
}

function assertExactP1CommitOddWitness(
  root,
  goalId,
  taskId,
  eventId,
  requestSha256,
  accepted,
) {
  const preparation = verifyP1CommitRecoveryLineage(
    root,
    goalId,
    taskId,
    eventId,
    requestSha256,
    accepted,
  );
  if (!preparation) return null;
  const operations = listP1CommitOperations(
    root,
    goalId,
    taskId,
  );
  if (!accepted && operations.length === 0) {
    return null;
  }
  assertControl(
    operations.length === 1 || (accepted && operations.length === 0),
    'CORRUPT_STORE',
    `P1 odd recovery ${eventId} 缺唯一 durable operation witness`,
  );
  if (operations.length === 1) {
    const operation = operations[0];
    const identityMatches = operation.stable_id_unavailable === true
      ? (
        operation.stable_id_sha256
          === `sha256:${sha256(eventId)}`
      )
      : operation.operation_id === eventId;
    assertControl(
      operation.kind === 'P1_COMMIT_REF'
        && identityMatches
        && operation.request_sha256 === requestSha256,
      'PREPARED_REQUEST_MISMATCH',
      `P1 odd recovery ${eventId} 不是 exact durable operation`,
    );
  }
  return preparation;
}

function authorizeP1CommitOddRecovery(
  root,
  rawEvent,
  actorCapabilityFile,
) {
  const event = validateEvent(rawEvent);
  if (event.type !== 'P1_COMMITTED') return false;
  const eventRequest = JSON.parse(JSON.stringify(event));
  const goalId = safeId(event.goal_id, 'goal_id');
  const taskId = safeId(event.task_id, 'task_id');
  const eventId = safeId(event.event_id, 'event_id');
  const requestSha256 = hashObject(eventRequest);
  const loaded = loadOddRecoveryGoalState(root, goalId);
  const task = loaded.manifest.tasks.find(
    (candidate) => candidate.id === taskId,
  );
  if (!task || !task.p1 || !loaded.snapshot.tasks[taskId]) {
    return false;
  }
  const accepted = acceptedP1Event(
    root,
    goalId,
    taskId,
    eventId,
  );
  let preparation;
  try {
    preparation = assertExactP1CommitOddWitness(
      root,
      goalId,
      taskId,
      eventId,
      requestSha256,
      accepted,
    );
  } catch (error) {
    if (
      error instanceof ControlError
        && error.code === 'PREPARED_REQUEST_MISMATCH'
    ) {
      return false;
    }
    throw error;
  }
  if (!preparation) return false;
  if (accepted) {
    assertControl(
      accepted.input_sha256 === requestSha256,
      'EVENT_ID_CONFLICT',
      `accepted P1 event ${eventId} 不是 exact request`,
    );
    authorizeAcceptedEventRetry(
      loaded,
      taskId,
      accepted,
      actorCapabilityFile,
    );
    return true;
  }
  assertControl(
    event.actor.role === 'CAPTAIN',
    'P1_COMMIT_AUTHORITY_INVALID',
    'prepared P1_COMMITTED 只能由原 CAPTAIN exact retry',
  );
  if (preparation.intent) {
    assertMechanicalP1IntentAnchor(
      loaded,
      loaded.snapshot.tasks[taskId],
      preparation.intent,
    );
    assertControl(
      preparation.intent.request_sha256 === requestSha256
        && event.actor.thread_id
          === preparation.intent.acceptance_authority.thread_id
        && event.actor.host_id
          === preparation.intent.acceptance_authority.host_id,
      'PREPARED_REQUEST_MISMATCH',
      `prepared P1 event ${eventId} request/actor binding 漂移`,
    );
    authorizeHistoricalActorCapability(
      loaded.snapshot,
      actorCapabilityFile,
      preparation.intent.acceptance_authority,
      { taskId },
    );
    return true;
  }
  authorizeHistoricalMechanicalP1Capability(
    loaded.snapshot,
    actorCapabilityFile,
    preparation.acceptance_authority_sha256,
    {
      role: 'CAPTAIN',
      threadId: event.actor.thread_id,
      hostId: event.actor.host_id,
      taskId,
    },
  );
  return true;
}

const PRISTINE_GOAL_EVENT_TYPES = new Set([
  'START_P1',
  'P1_READY',
  'P1_APPROVED',
  'P1_RESTARTED',
  'LAUNCH_DEV',
  'DEV_READY',
  'LAUNCH_REVIEW',
  'REVIEW_REWORK',
  'REVIEW_PASS',
  'LAUNCH_RECEIPT',
  'RECEIPT_FAIL',
  'REOPEN_DEV',
  'REOPEN_REVIEW',
  'RECEIPT_PASS',
  'READY_FOR_MERGE',
  'TASK_REOPEN',
  'ARCHIVED',
  'HEARTBEAT',
  'CONTROL_RECONCILED',
  'ADD_HOLD',
  'RESOLVE_HOLD',
  'RUNTIME_ROTATED',
  'ROLE_LOST',
  'ROLE_RECOVERED',
  'RECOVERY_HANDOFF_BOUND',
  'RECOVERY_HANDOFF_ABANDONED',
  'RECOVERY_PROMOTED',
  'PACKET_UPDATED',
]);

function authorizeGoalEventPristineOddRecovery(
  cwd,
  root,
  rawEvent,
  actorCapabilityFile,
  authorization,
  acceptedAt,
) {
  const event = validateEvent(rawEvent);
  if (!PRISTINE_GOAL_EVENT_TYPES.has(event.type)) return false;
  const goalId = safeId(event.goal_id, 'goal_id');
  const taskId = safeId(event.task_id, 'task_id');
  const eventId = safeId(event.event_id, 'event_id');
  const requestSha256 = hashObject(JSON.parse(JSON.stringify(event)));
  const loaded = loadOddRecoveryGoalState(root, goalId);
  assertControl(
    loaded.snapshot.tasks[taskId],
    'UNKNOWN_TASK',
    `未知 task ${taskId}`,
  );
  assertControl(
    goalControlEventOccurrences(loaded, eventId).length === 0,
    'EVENT_ID_CONFLICT',
    `event id ${eventId} 已被 Goal control event 使用`,
  );
  assertControl(
    goalEventIdOccurrences(loaded, eventId).length === 0
      && !acceptedGoalEvent(root, loaded, taskId, eventId),
    'EVENT_ID_CONFLICT',
    `event id ${eventId} 已有 durable event，不能按 pristine recovery`,
  );
  const preflight = withPristinePreflightGitEnvironment(
    () => acceptEventUnderLock(
      cwd,
      rawEvent,
      actorCapabilityFile,
      {
        ...authorization,
        pristineEventRecovery: true,
        pristinePreflight: true,
        pristineEventAcceptedAt: acceptedAt,
      },
    ),
  );
  assertControl(
    preflight
      && preflight.pristine_preflight_authorized === true
      && preflight.event_id === eventId
      && preflight.request_sha256 === requestSha256,
    'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
    `event ${eventId} pristine preflight 未形成 exact request proof`,
  );
  return true;
}

function exactGoalEventCompletionExists(root, rawEvent) {
  let event;
  try {
    event = validateEvent(rawEvent);
  } catch (error) {
    if (error instanceof ControlError) return false;
    throw error;
  }
  const goalId = safeId(event.goal_id, 'goal_id');
  const taskId = safeId(event.task_id, 'task_id');
  const eventId = safeId(event.event_id, 'event_id');
  const requestSha256 = hashObject(JSON.parse(JSON.stringify(event)));
  let loaded;
  try {
    loaded = loadOddRecoveryGoalState(root, goalId);
  } catch (error) {
    if (
      error instanceof ControlError
        && ['GOAL_NOT_INITIALIZED', 'UNKNOWN_TASK'].includes(error.code)
    ) {
      return false;
    }
    throw error;
  }
  const occurrences = goalEventIdOccurrences(loaded, eventId);
  if (
    occurrences.length === 1
      && occurrences[0].task_id === taskId
      && occurrences[0].input_sha256 === requestSha256
  ) {
    const accepted = acceptedGoalEvent(root, loaded, taskId, eventId);
    if (accepted && accepted.input_sha256 === requestSha256) return true;
  }
  if (event.type === 'P1_COMMITTED') {
    const preparation = inspectP1CommitPreparation(
      root,
      goalId,
      taskId,
      eventId,
      requestSha256,
    );
    if (preparation) return true;
  }
  const { listPendingTaskOperations } = require('./pending-operations');
  const pending = listPendingTaskOperations(root, goalId, taskId);
  if (pending.some((operation) => (
    (
      operation.operation_id === eventId
        || operation.allowed_event_id === eventId
        || operation.target_event_id === eventId
    )
      && (
        operation.request_sha256 === undefined
          || operation.request_sha256 === requestSha256
          || operation.allowed_event_sha256 === requestSha256
      )
  ))) {
    return true;
  }
  return goalMergeTargetReservations(root, goalId, eventId).length > 0;
}

function recordGoalEventRejection(
  cwd,
  root,
  rawEvent,
  actorCapabilityFile,
  originalError,
) {
  const prepared = prepareGoalEventRejection(
    cwd,
    root,
    rawEvent,
    actorCapabilityFile,
    originalError,
  );
  let witnessAuthorized = false;
  let pristineAuthorized = false;
  return withLock(root, () => {
    assertControl(
      hashObject(rejectionCapabilitySnapshot(cwd, actorCapabilityFile))
        === hashObject(prepared.caller),
      'REJECTION_CALLER_CHANGED',
      'rejection caller capability snapshot 在 receipt publication 前漂移',
    );
    if (exactGoalEventCompletionExists(root, rawEvent)) {
      return {
        recorded: false,
        skipped_exact_completion: true,
      };
    }
    const receipt = publishGoalEventRejectionReceipt(cwd, prepared);
    maybeInjectGenerationBoundaryFault(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_RECEIPT',
    );
    return {
      recorded: true,
      receipt_sha256: receipt.receipt_sha256,
    };
  }, {
    transactionKey: prepared.transactionKey,
    beforeGeneration: () => {
      assertControl(
        hashObject(rejectionCapabilitySnapshot(cwd, actorCapabilityFile))
          === hashObject(prepared.caller),
        'REJECTION_CALLER_CHANGED',
        'rejection caller capability snapshot 在 transaction preflight 前漂移',
      );
      const receiptState = inspectGoalEventRejectionReceipt(prepared);
      if (readSealedRootGenerationParity(root) === 'ODD') {
        witnessAuthorized = receiptState.kind !== 'PRISTINE';
        pristineAuthorized = receiptState.kind === 'PRISTINE';
      }
    },
    authorizeOddRecovery: () => witnessAuthorized,
    authorizePristineOddRecovery: () => pristineAuthorized,
    afterGenerationBeforeCallback: generationBoundaryFaultHook(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_GENERATION',
    ),
  });
}

function acceptEvent(cwd, rawEvent, actorCapabilityFile, authorization = {}) {
  assertControl(
    authorization.pristineEventAcceptedAt === undefined,
    'INTERNAL_AUTHORIZATION_FORBIDDEN',
    'pristineEventAcceptedAt 只能由 acceptEvent 内部的 sealed odd-recovery preflight 注入',
  );
  const root = controlRoot(cwd);
  const entryGeneration = readSealedRootGenerationSummary(root);
  if (
    entryGeneration.parity === 'ODD'
      && entryGeneration.activeTransaction
      && entryGeneration.activeTransaction.kind === 'GOAL_EVENT_REJECTION'
  ) {
    let replayError = null;
    try {
      const replay = acceptEventUnderLock(
        cwd,
        rawEvent,
        actorCapabilityFile,
        {
          ...authorization,
          pristineEventRecovery: false,
          pristinePreflight: true,
        },
      );
      assertControl(
        !replay || replay.pristine_preflight_authorized !== true,
        'REJECTION_REPLAY_DIVERGED',
        'durable rejection receipt 对应的 event 现在不再产生同一 rejection',
      );
    } catch (error) {
      replayError = error instanceof ControlError
        ? error
        : new ControlError('UNEXPECTED', error.message);
    }
    assertControl(
      replayError,
      'REJECTION_REPLAY_DIVERGED',
      'durable rejection receipt 缺可重放的原始 validation error',
    );
    recordGoalEventRejection(
      cwd,
      root,
      rawEvent,
      actorCapabilityFile,
      replayError,
    );
    throw replayError;
  }
  let oddRecoveryAuthorized = false;
  let pristineOddRecoveryAuthorized = false;
  let pristineEventAcceptedAt = null;
  let eventCallbackEntered = false;
  try {
    return withLock(
      root,
      () => {
        eventCallbackEntered = true;
        const accept = () => acceptEventUnderLock(
          cwd,
          rawEvent,
          actorCapabilityFile,
          {
            ...authorization,
            pristineEventRecovery: pristineOddRecoveryAuthorized,
            ...(pristineEventAcceptedAt
              ? { pristineEventAcceptedAt }
              : {}),
          },
        );
        return pristineOddRecoveryAuthorized
          ? withPristinePreflightGitEnvironment(accept)
          : accept();
      },
      {
        transactionKey: () => goalEventTransactionKey(rawEvent),
        beforeGeneration: (transactionContext) => {
          oddRecoveryAuthorized = false;
          pristineOddRecoveryAuthorized = false;
          pristineEventAcceptedAt = null;
          // This hook may enter semantic pristine preflight. Fence a foreign
          // odd transaction before pending-operation checks; withLock remains
          // the single source of the canonical transaction mismatch error.
          if (isHistoricalTransactionRetry(transactionContext.mode)) {
            const requestedTransaction = goalEventTransactionKey(rawEvent);
            if (
              requestedTransaction.key_sha256
                !== historicalTransactionKeySha256(transactionContext)
            ) {
              return;
            }
          }
          const rawGoalId = rawEvent && rawEvent.goal_id;
          const rawTaskId = rawEvent && rawEvent.task_id;
          const rawEventId = rawEvent && rawEvent.event_id;
          if (
            typeof rawGoalId !== 'string'
              || typeof rawTaskId !== 'string'
              || typeof rawEventId !== 'string'
          ) {
            return;
          }
          let goalId;
          let taskId;
          let eventId;
          try {
            goalId = safeId(rawGoalId, 'goal_id');
            taskId = safeId(rawTaskId, 'task_id');
            eventId = safeId(rawEventId, 'event_id');
          } catch {
            return;
          }
          const durableCandidate = acceptedEventFiles(root, goalId, taskId)
            .map((file) => readJson(
              file,
              `accepted event ${path.basename(file)}`,
            ))
            .find((candidate) => candidate.event_id === eventId);
          if (!durableCandidate) {
            if (isPreWitnessTransactionRetry(transactionContext.mode)) {
              pristineEventAcceptedAt =
                transactionContext.transaction_started_at;
              pristineOddRecoveryAuthorized =
                authorizeGoalEventPristineOddRecovery(
                  cwd,
                  root,
                  rawEvent,
                  actorCapabilityFile,
                  authorization,
                  pristineEventAcceptedAt,
                );
              return;
            }
            oddRecoveryAuthorized = authorizeP1CommitOddRecovery(
              root,
              rawEvent,
              actorCapabilityFile,
            );
            if (
              !oddRecoveryAuthorized
                && readSealedRootGenerationParity(root) === 'ODD'
            ) {
              const generation = readSealedRootGenerationSummary(root);
              assertControl(
                generation.parity === 'ODD'
                  && typeof generation.updatedAt === 'string'
                  && Number.isFinite(Date.parse(generation.updatedAt)),
                'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
                'event pristine recovery 缺 sealed generation timestamp',
              );
              pristineEventAcceptedAt = generation.updatedAt;
              pristineOddRecoveryAuthorized =
                authorizeGoalEventPristineOddRecovery(
                  cwd,
                  root,
                  rawEvent,
                  actorCapabilityFile,
                  authorization,
                  pristineEventAcceptedAt,
                );
            }
            return;
          }
          const event = validateEvent(rawEvent);
          const inputHash = hashObject(JSON.parse(JSON.stringify(event)));
          const loaded = loadOddRecoveryGoalState(root, goalId);
          const occurrences = goalEventIdOccurrences(loaded, eventId);
          assertControl(
            occurrences.length === 1
              && occurrences[0].task_id === taskId
              && occurrences[0].input_sha256 === inputHash,
            'EVENT_ID_CONFLICT',
            `event id ${eventId} 已被不同 durable operation 使用`,
          );
          const accepted = acceptedGoalEvent(root, loaded, taskId, eventId);
          assertControl(
            accepted && accepted.input_sha256 === inputHash,
            'CORRUPT_STORE',
            `accepted event ${eventId} 缺失或 input hash 不一致`,
          );
          const task = loaded.manifest.tasks.find(
            (candidate) => candidate.id === taskId,
          );
          if (accepted.type === 'P1_COMMITTED' && task && task.p1) {
            assertControl(
              assertExactP1CommitOddWitness(
                root,
                goalId,
                taskId,
                eventId,
                inputHash,
                accepted,
              ),
              'CORRUPT_STORE',
              `accepted P1 event ${eventId} 缺 retained transaction witness`,
            );
          }
          authorizeAcceptedEventRetry(
            loaded,
            taskId,
            accepted,
            actorCapabilityFile,
          );
          oddRecoveryAuthorized = true;
        },
        authorizeOddRecovery: () => oddRecoveryAuthorized,
        authorizePristineOddRecovery: () => pristineOddRecoveryAuthorized,
        afterGenerationBeforeCallback: generationBoundaryFaultHook(
          cwd,
          'GOAL_CONTROL_TEST_FAULT_AFTER_EVENT_GENERATION',
        ),
      },
    );
  } catch (error) {
    const originalError = error instanceof ControlError
      ? error
      : new ControlError('UNEXPECTED', error.message);
    if (
      !eventCallbackEntered
        || readSealedRootGenerationParity(root) !== 'EVEN'
    ) {
      throw originalError;
    }
    recordGoalEventRejection(
      cwd,
      root,
      rawEvent,
      actorCapabilityFile,
      originalError,
    );
    throw originalError;
  }
}

function p1AbandonTransactionRequest(root, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const preparedEventId = safeId(
    options.preparedEventId,
    'prepared P1 event_id',
  );
  const abandonEventId = safeId(
    options.eventId,
    'P1 abandonment event_id',
  );
  const expectedIntentSha256 = normalizeHash(
    options.expectedIntentSha256,
    'expected P1 intent sha256',
  );
  assertFullSha(options.expectedRefHead, 'expected P1 ref head');
  const prepared = readP1CommitIntent(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  assertControl(
    prepared
      && prepared.intent.intent_sha256 === expectedIntentSha256
      && prepared.intent.ref_binding.commit_ref
        === options.expectedCommitRef
      && prepared.intent.ref_binding.new_commit
        === options.expectedRefHead,
    'P1_COMMIT_INTENT_MISMATCH',
    `P1 intent ${preparedEventId} 不存在或不是 exact abandonment anchor`,
  );
  return {
    goal_id: goalId,
    task_id: taskId,
    prepared_event_id: preparedEventId,
    abandon_event_id: abandonEventId,
    expected_intent_sha256: expectedIntentSha256,
    expected_commit_ref: options.expectedCommitRef,
    expected_ref_head: options.expectedRefHead,
    p1_abandon_handoff_sha256:
      p1CommitAbandonmentHandoffSha256(prepared),
    foreman_thread_id: options.threadId,
    reason: typeof options.reason === 'string'
      ? options.reason.trim()
      : '',
    incident_ref: typeof options.incidentRef === 'string'
      ? options.incidentRef.trim()
      : '',
  };
}

function p1AbandonTransactionKey(root, options) {
  const request = p1AbandonTransactionRequest(root, options);
  return canonicalTransactionKey(
    'P1_COMMIT_ABANDON',
    {
      goal_id: request.goal_id,
      task_id: request.task_id,
      prepared_event_id: request.prepared_event_id,
    },
    request.abandon_event_id,
    hashObject(request),
  );
}

function authorizeP1AbandonOddRecovery(root, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const preparedEventId = safeId(
    options.preparedEventId,
    'prepared P1 event_id',
  );
  const abandonEventId = safeId(
    options.eventId,
    'P1 abandonment event_id',
  );
  const reason = typeof options.reason === 'string'
    ? options.reason.trim()
    : '';
  const incidentRef = typeof options.incidentRef === 'string'
    ? options.incidentRef.trim()
    : '';
  assertControl(
    reason.length > 0
      && reason.length <= 2000
      && incidentRef.length > 0
      && incidentRef.length <= 2000,
    'P1_ABANDON_JUSTIFICATION_REQUIRED',
    'p1-abandon-commit 必须提供 1-2000 字符 reason/incident-ref',
  );
  const expectedIntentSha256 = normalizeHash(
    options.expectedIntentSha256,
    'expected P1 intent sha256',
  );
  const expectedRefHead = options.expectedRefHead;
  assertFullSha(expectedRefHead, 'expected P1 ref head');
  assertControl(
    typeof options.expectedCommitRef === 'string'
      && options.expectedCommitRef.startsWith(
        'refs/heads/codex/goal-control/p1/',
      ),
    'P1_COMMIT_REF_INVALID',
    'p1-abandon-commit 缺 deterministic expected commit ref',
  );
  const request = p1AbandonTransactionRequest(root, options);
  const requestSha256 = hashObject(request);
  const preparedCommit = readP1CommitIntent(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  assertControl(
    preparedCommit
      && preparedCommit.intent.intent_sha256
        === expectedIntentSha256
      && preparedCommit.intent.ref_binding.commit_ref
        === options.expectedCommitRef
      && preparedCommit.intent.ref_binding.new_commit
        === expectedRefHead
      && request.p1_abandon_handoff_sha256
        === p1CommitAbandonmentHandoffSha256(preparedCommit),
    'P1_COMMIT_INTENT_MISMATCH',
    `P1 intent ${preparedEventId} 不存在或不是 exact abandonment anchor`,
  );
  const abandonment = inspectP1Abandonment(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  const unsealed = abandonment
    ? null
    : inspectExactUnsealedAbandonmentStaging(
      root,
      goalId,
      taskId,
      preparedEventId,
      requestSha256,
    );
  if (!abandonment && !unsealed) return false;
  if (abandonment) {
    assertControl(
      abandonment.intent.request_sha256 === requestSha256
        && hashObject(abandonment.intent.request) === requestSha256
        && abandonment.intent.p1_intent_sha256
          === preparedCommit.intent.intent_sha256,
      'PREPARED_REQUEST_MISMATCH',
      `P1 abandonment ${abandonEventId} 不是 exact request`,
    );
  }
  const recoveryLineage = abandonment
    ? verifyP1AbandonmentRecoveryLineage(
      root,
      goalId,
      taskId,
      preparedEventId,
      abandonEventId,
      requestSha256,
    )
    : null;
  const loaded = loadOddRecoveryGoalState(root, goalId);
  const state = loaded.snapshot.tasks[taskId];
  const task = loaded.manifest.tasks.find(
    (candidate) => candidate.id === taskId,
  );
  assertControl(
    state && task && task.p1,
    'UNKNOWN_TASK',
    `Goal ${goalId} 没有 mechanical P1 task ${taskId}`,
  );
  const accepted = recoveryLineage
    ? recoveryLineage.accepted
    : null;
  if (accepted) {
    assertControl(
      accepted.type === 'P1_COMMIT_ABANDONED',
      'CORRUPT_STORE',
      `accepted event ${abandonEventId} 不是 P1 abandonment`,
    );
    const occurrences = goalEventIdOccurrences(loaded, abandonEventId);
    assertControl(
      occurrences.length === 1
        && occurrences[0].task_id === taskId
        && occurrences[0].input_sha256 === accepted.input_sha256,
      'EVENT_ID_CONFLICT',
      `accepted P1 abandonment ${abandonEventId} 不是唯一 durable event`,
    );
    authorizeAcceptedEventRetry(
      loaded,
      taskId,
      accepted,
      options.foremanCapabilityFile,
    );
    return true;
  }
  const operations = listP1CommitOperations(
    root,
    goalId,
    taskId,
  );
  assertControl(
    operations.length === 1,
    'CORRUPT_STORE',
    `P1 abandonment ${abandonEventId} 缺唯一 durable operation witness`,
  );
  const operation = operations[0];
  const identityMatches = operation.stable_id_unavailable === true
    ? operation.stable_id_sha256
      === `sha256:${sha256(preparedEventId)}`
    : operation.operation_id === abandonEventId;
  assertControl(
    operation.kind === 'P1_COMMIT_REF_ABANDON'
      && identityMatches
      && operation.request_sha256 === requestSha256,
    'PREPARED_REQUEST_MISMATCH',
    `P1 abandonment ${abandonEventId} 不是 exact durable operation`,
  );
  if (abandonment) {
    authorizeHistoricalActorCapability(
      loaded.snapshot,
      options.foremanCapabilityFile,
      abandonment.intent.foreman_authority,
      { goalWide: true, taskId },
    );
  } else {
    authorizeHistoricalMechanicalP1Capability(
      loaded.snapshot,
      options.foremanCapabilityFile,
      unsealed.foreman_authority_sha256,
      {
        role: 'FOREMAN',
        threadId: options.threadId,
        goalWide: true,
        taskId,
      },
    );
  }
  return true;
}

function abandonMechanicalP1Commit(cwd, options) {
  const root = controlRoot(cwd);
  let oddRecoveryAuthorized = false;
  return withLock(root, () => {
    const goalId = safeId(options.goalId, 'goal_id');
    const taskId = safeId(options.taskId, 'task_id');
    const preparedEventId = safeId(
      options.preparedEventId,
      'prepared P1 event_id',
    );
    const abandonEventId = safeId(
      options.eventId,
      'P1 abandonment event_id',
    );
    const reason = typeof options.reason === 'string'
      ? options.reason.trim()
      : '';
    const incidentRef = typeof options.incidentRef === 'string'
      ? options.incidentRef.trim()
      : '';
    assertControl(
      reason.length > 0
        && reason.length <= 2000
        && incidentRef.length > 0
        && incidentRef.length <= 2000,
      'P1_ABANDON_JUSTIFICATION_REQUIRED',
      'p1-abandon-commit 必须提供 1-2000 字符 reason/incident-ref',
    );
    const expectedIntentSha256 = normalizeHash(
      options.expectedIntentSha256,
      'expected P1 intent sha256',
    );
    const expectedRefHead = options.expectedRefHead;
    assertFullSha(expectedRefHead, 'expected P1 ref head');
    assertControl(
      typeof options.expectedCommitRef === 'string'
        && options.expectedCommitRef.startsWith(
          'refs/heads/codex/goal-control/p1/',
        ),
      'P1_COMMIT_REF_INVALID',
      'p1-abandon-commit 缺 deterministic expected commit ref',
    );
    const loaded = loadGoalStateUnlocked(root, goalId);
    const state = loaded.snapshot.tasks[taskId];
    const task = loaded.manifest.tasks.find(
      (candidate) => candidate.id === taskId,
    );
    assertControl(
      state && task && task.p1,
      'UNKNOWN_TASK',
      `Goal ${goalId} 没有 mechanical P1 task ${taskId}`,
    );
    assertFrozenInputs(cwd, loaded, taskId);
    const p1Prepared = readP1CommitIntent(
      root,
      goalId,
      taskId,
      preparedEventId,
    );
    assertControl(
      p1Prepared
        && p1Prepared.intent.intent_sha256 === expectedIntentSha256,
      'P1_COMMIT_INTENT_MISMATCH',
      `P1 intent ${preparedEventId} 不存在或 seal 与 expected 不一致`,
    );
    const p1Intent = p1Prepared.intent;
    const committedAbandonment = state.p1.commit_abandonment || null;
    if (committedAbandonment) {
      assertControl(
        committedAbandonment.prepared_event_id === preparedEventId
          && committedAbandonment.event_id === abandonEventId
          && committedAbandonment.task_cycle === p1Intent.task_cycle
          && committedAbandonment.p1_intent_sha256
            === p1Intent.intent_sha256
          && committedAbandonment.commit_ref
            === p1Intent.ref_binding.commit_ref
          && committedAbandonment.commit_sha
            === p1Intent.ref_binding.new_commit,
        'P1_COMMIT_ABANDONED',
        `P1 cycle ${p1Intent.task_cycle} 已由其它 append-only tombstone 废止`,
      );
    } else {
      assertMechanicalP1IntentAnchor(loaded, state, p1Intent);
    }
    assertControl(
      state.phase === 'P1_APPROVED'
        && state.task_cycle === p1Intent.task_cycle
        && p1Intent.ref_binding.commit_ref
          === options.expectedCommitRef
        && p1Intent.ref_binding.new_commit === expectedRefHead,
      'P1_COMMIT_INTENT_DIVERGED',
      `P1 intent ${preparedEventId} state/cycle/ref anchor 漂移`,
    );
    assertControl(
      goalEventIdOccurrences(loaded, preparedEventId).length === 0
        && !acceptedP1Event(
          root,
          goalId,
          taskId,
          preparedEventId,
        ),
      'P1_COMMIT_ALREADY_ACCEPTED',
      `P1_COMMITTED ${preparedEventId} 已存在，禁止 abandon`,
    );
    const existing = inspectP1Abandonment(
      root,
      goalId,
      taskId,
      preparedEventId,
    );
    const request = p1AbandonTransactionRequest(root, options);
    const requestSha256 = hashObject(request);
    let foreman;
    let acceptedAt;
    if (existing) {
      assertControl(
        existing.intent.request_sha256 === requestSha256
          && hashObject(existing.intent.request) === requestSha256,
        'PREPARED_REQUEST_MISMATCH',
        `P1 abandonment ${abandonEventId} 不是 exact request`,
      );
      foreman = authorizeHistoricalActorCapability(
        loaded.snapshot,
        options.foremanCapabilityFile,
        existing.intent.foreman_authority,
        { goalWide: true, taskId },
      );
      acceptedAt = existing.intent.accepted_at;
    } else {
      acceptedAt = nowIso();
      const {
        assertNoPendingTaskOperations,
      } = require('./pending-operations');
      const unsealedAbandonment =
        inspectExactUnsealedAbandonmentStaging(
          root,
          goalId,
          taskId,
          preparedEventId,
          requestSha256,
        );
      foreman = unsealedAbandonment
        ? authorizeHistoricalMechanicalP1Capability(
          loaded.snapshot,
          options.foremanCapabilityFile,
          unsealedAbandonment.foreman_authority_sha256,
          {
            role: 'FOREMAN',
            threadId: options.threadId,
            goalWide: true,
            taskId,
          },
        )
        : authorizeGoalSession(
          loaded.snapshot,
          options.foremanCapabilityFile,
          {
            role: 'FOREMAN',
            threadId: options.threadId,
          },
        );
      assertNoPendingTaskOperations(
        root,
        goalId,
        taskId,
        unsealedAbandonment
          ? {
            allowOperationKind: 'P1_COMMIT_REF_ABANDON',
            allowOperationId: preparedEventId,
            allowRequestSha256: requestSha256,
          }
          : {
            allowOperationKind: 'P1_COMMIT_REF',
            allowOperationId: preparedEventId,
            allowRequestSha256: p1Intent.request_sha256,
          },
      );
      if (unsealedAbandonment) {
        cleanupExactUnsealedAbandonmentStaging(
          root,
          goalId,
          taskId,
          preparedEventId,
          requestSha256,
          hashObject(mechanicalP1Authority(foreman)),
        );
      }
    }
    const taskAnchor = existing
      ? existing.intent.task_anchor
      : {
        ...mechanicalP1TaskAnchor(loaded, state),
        foreman_prior_actor_sequence:
          state.actor_sequences[actorSequenceKey({
            role: 'FOREMAN',
            thread_id: foreman.thread_id,
            host_id: foreman.host_id,
          })] || 0,
      };
    const foremanAuthority = existing
      ? existing.intent.foreman_authority
      : mechanicalP1Authority(foreman);
    const unsignedIntent = {
      schema_version: 1,
      kind: 'P1_COMMIT_REF_ABANDON_INTENT',
      goal_id: goalId,
      task_id: taskId,
      prepared_event_id: preparedEventId,
      request,
      request_sha256: requestSha256,
      task_anchor: taskAnchor,
      foreman_authority: foremanAuthority,
      p1_intent_sha256: p1Intent.intent_sha256,
      prepared_request_sha256: hashObject({
        request,
        task_anchor: taskAnchor,
        foreman_authority: foremanAuthority,
        p1_intent_sha256: p1Intent.intent_sha256,
      }),
      accepted_at: acceptedAt,
    };
    const abandonment = publishP1AbandonmentIntent(
      cwd,
      root,
      goalId,
      taskId,
      preparedEventId,
      unsignedIntent,
    );
    maybeInjectP1CommitFault(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_ABANDON_INTENT_INSTALL',
      'TEST_FAULT_AFTER_P1_ABANDON_INTENT_INSTALL',
      'injected failure after P1 abandonment intent install',
    );
    assertControl(
      abandonment.intent.intent_sha256
        === hashObject({
          ...unsignedIntent,
        }),
      'CORRUPT_STORE',
      `P1 abandonment ${abandonEventId} sealed intent 漂移`,
    );
    abandonP1CommitRef(cwd, abandonment.intent, p1Prepared);
    maybeInjectP1CommitFault(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_ABANDON_REF',
      'TEST_FAULT_AFTER_P1_ABANDON_REF',
      'injected failure after P1 ref CAS abandon',
    );
    const receipt = completeP1Abandonment(
      root,
      goalId,
      taskId,
      abandonment,
    );
    const anchor = abandonment.intent.task_anchor;
    const canonicalEvent = {
      schema_version: 1,
      event_id: abandonEventId,
      goal_id: goalId,
      task_id: taskId,
      type: 'P1_COMMIT_ABANDONED',
      actor: {
        role: 'FOREMAN',
        thread_id: abandonment.intent.foreman_authority.thread_id,
        host_id: abandonment.intent.foreman_authority.host_id,
      },
      actor_sequence: anchor.foreman_prior_actor_sequence + 1,
      expected_state_revision: anchor.state_revision,
      control_epoch: anchor.control_epoch,
      packet: JSON.parse(JSON.stringify(anchor.packet)),
      base_head: anchor.base_head,
      full_head: anchor.full_head,
      payload: {
        prepared_event_id: preparedEventId,
        task_cycle: p1Intent.task_cycle,
        p1_intent_sha256: p1Intent.intent_sha256,
        abandon_intent_sha256: abandonment.intent.intent_sha256,
        abandon_request_sha256: abandonment.intent.request_sha256,
        abandon_receipt_sha256: receipt.receipt_sha256,
        commit_ref: p1Intent.ref_binding.commit_ref,
        commit_sha: p1Intent.ref_binding.new_commit,
        predecessor_event_sha256: anchor.prior_event_sha256,
        reason: abandonment.intent.request.reason,
        incident_ref: abandonment.intent.request.incident_ref,
      },
    };
    const acceptedAbandonment = acceptEventUnderLock(
      cwd,
      canonicalEvent,
      options.foremanCapabilityFile,
      {
        p1AbandonmentOperation: {
          prepared_event_id: preparedEventId,
          request_sha256: abandonment.intent.request_sha256,
          receipt_sha256: receipt.receipt_sha256,
        },
      },
    );
    return {
      abandoned: true,
      idempotent: acceptedAbandonment.idempotent,
      goal_id: goalId,
      task_id: taskId,
      prepared_event_id: preparedEventId,
      abandon_event_id: abandonEventId,
      request_sha256: requestSha256,
      receipt_sha256: receipt.receipt_sha256,
      commit_ref: receipt.commit_ref,
      commit_sha: receipt.commit_sha,
      event_sha256: acceptedAbandonment.event_sha256
        || (
          state.p1.commit_abandonment
            ? state.last_event.event_sha256
            : undefined
        ),
    };
  }, {
    transactionKey: () => p1AbandonTransactionKey(root, options),
    beforeGeneration: () => {
      oddRecoveryAuthorized = authorizeP1AbandonOddRecovery(
        root,
        options,
      );
    },
    authorizeOddRecovery: () => oddRecoveryAuthorized,
  });
}

function foremanRecoveryCapabilityPattern(attempt) {
  return new RegExp(`^foreman-${attempt}-[0-9a-f]{24}\\.cap$`);
}

function buildForemanRecoveryRequest(
  rootRecoveryId,
  options,
  scope,
  targetTaskIds,
  sourceTaskIds,
  adoptionTargetTaskId,
) {
  return {
    schema_version: 2,
    root_recovery_id: rootRecoveryId,
    goal_id: options.goalId,
    anchor_task_id: options.taskId,
    successor: {
      role: 'FOREMAN',
      thread_id: options.threadId,
      host_id: options.hostId || 'local',
      attempt: Number(options.attempt),
      lease_ms: Number(options.leaseMs),
    },
    expected_goal_scope_sha256: scope.scope_sha256,
    target_task_ids: targetTaskIds,
    source_task_ids: sourceTaskIds,
    adoption_target_task_id: adoptionTargetTaskId,
    reason: typeof options.reason === 'string' ? options.reason.trim() : '',
    incident_ref: typeof options.incidentRef === 'string'
      ? options.incidentRef.trim()
      : '',
  };
}

function assertForemanRecoveryLegacyAnchorCas(binding, options) {
  assertControl(binding, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
  if (options.expectedControlEpoch !== undefined) {
    assertControl(
      Number(options.expectedControlEpoch) === binding.control_epoch,
      'STALE_CONTROL_EPOCH',
      `expected control epoch ${options.expectedControlEpoch}，当前为 ${binding.control_epoch}`,
    );
  }
  if (options.expectedStateRevision !== undefined) {
    assertControl(
      Number(options.expectedStateRevision) === binding.state_revision,
      'STALE_STATE_REVISION',
      `expected state revision ${options.expectedStateRevision}，当前为 ${binding.state_revision}`,
    );
  }
  if (options.expectedEventHead !== undefined) {
    assertControl(
      options.expectedEventHead === binding.event_head,
      'STALE_EVENT_HEAD',
      'expected task event head 已漂移',
    );
  }
  if (
    options.expectedPacketRevision !== undefined
      || options.expectedPacketSha256 !== undefined
  ) {
    assertControl(
      Number(options.expectedPacketRevision) === binding.packet.revision
        && normalizeHash(
          options.expectedPacketSha256,
          'expected packet sha256',
        ) === binding.packet.sha256,
      'STALE_PACKET',
      'expected packet 已漂移',
    );
  }
  if (options.expectedFullHead !== undefined) {
    assertFullSha(options.expectedFullHead, 'expected full HEAD');
    assertControl(
      options.expectedFullHead === binding.full_head,
      'STALE_HEAD',
      'expected full HEAD 已漂移',
    );
  }
  const expectedForemanFields = [
    options.expectedForemanThreadId,
    options.expectedForemanHostId,
    options.expectedForemanAttempt,
    options.expectedForemanLeaseUntil,
  ];
  if (expectedForemanFields.some((value) => value !== undefined)) {
    assertControl(
      binding.foreman,
      'UNREGISTERED_ACTOR',
      'FOREMAN 尚未登记',
    );
    assertControl(
      binding.foreman.thread_id === options.expectedForemanThreadId
        && binding.foreman.host_id === options.expectedForemanHostId,
      'STALE_FOREMAN_IDENTITY',
      'expected FOREMAN identity 已漂移',
    );
    assertControl(
      binding.foreman.attempt === Number(options.expectedForemanAttempt),
      'STALE_ROLE_ATTEMPT',
      'expected FOREMAN attempt 已漂移',
    );
    assertControl(
      binding.foreman.lease_until === options.expectedForemanLeaseUntil,
      'STALE_FOREMAN_LEASE',
      'expected FOREMAN lease 已漂移',
    );
  }
}

function assertForemanRecoveryIntentRecoveryBoundary(
  root,
  loaded,
  options,
  rootRecoveryId,
  intent,
  commit,
  stagedCapabilityFile = null,
) {
  const request = intent && intent.request;
  const originalScope = intent && intent.goal_scope;
  assertRecoveryScopeSeal(originalScope);
  assertControl(
    request
      && request.schema_version === 2
      && intent.request_sha256 === hashObject(request)
      && intent.prepared_request_sha256 === intent.request_sha256
      && intent.goal_scope_sha256 === originalScope.scope_sha256
      && hashObject(intent.target_task_ids)
        === hashObject(request.target_task_ids)
      && hashObject(intent.source_task_ids)
        === hashObject(request.source_task_ids)
      && (intent.adoption_target_task_id || null)
        === (request.adoption_target_task_id || null)
      && hashObject(intent.successor) === hashObject(request.successor)
      && typeof intent.accepted_at === 'string'
      && Number.isFinite(Date.parse(intent.accepted_at)),
    'PREPARED_STAGING_INVALID',
    `FOREMAN recovery ${rootRecoveryId} prepared request/scope seal 不匹配`,
  );
  assertControl(
    recoveryIntentMatchesOptions(intent, rootRecoveryId, options),
    'PREPARED_REQUEST_MISMATCH',
    `FOREMAN recovery ${rootRecoveryId} 不是 exact request retry`,
  );
  assertForemanRecoveryLegacyAnchorCas(
    originalScope.tasks.find(
      (binding) => binding.task_id === options.taskId,
    ),
    options,
  );
  const targetTaskIds = [...intent.target_task_ids];
  const sourceTaskIds = [...intent.source_task_ids];
  assertControl(
    targetTaskIds.length > 0
      && sourceTaskIds.length > 0
      && new Set(targetTaskIds).size === targetTaskIds.length
      && new Set(sourceTaskIds).size === sourceTaskIds.length
      && targetTaskIds.every((taskId) => (
        originalScope.tasks.some((binding) => binding.task_id === taskId)
      ))
      && sourceTaskIds.every((taskId) => (
        originalScope.tasks.some((binding) => binding.task_id === taskId)
      )),
    'PREPARED_STAGING_INVALID',
    `FOREMAN recovery ${rootRecoveryId} task scope 非法`,
  );
  const capabilityFile = stagedCapabilityFile || intent.capability_file;
  const capability = readCapabilityFile(capabilityFile, capabilityFile);
  const finalDirectory = recoveryBatchPaths(
    loaded.paths,
    rootRecoveryId,
  ).dir;
  assertControl(
    intent.capability_file === path.join(
      finalDirectory,
      path.basename(capabilityFile),
    )
      && foremanRecoveryCapabilityPattern(
        Number(options.attempt),
      ).test(path.basename(capabilityFile))
      && hashesEqual(capability.sha256, intent.capability_sha256),
    'PREPARED_STAGING_INVALID',
    `FOREMAN recovery ${rootRecoveryId} successor capability 漂移`,
  );
  const installedEvents = goalRecoveryBatchEvents(
    root,
    loaded,
    rootRecoveryId,
  );
  const installedByTask = new Map();
  for (const event of installedEvents) {
    const expectedEventId = event.task_id === options.taskId
      ? rootRecoveryId
      : recoveryEventId(rootRecoveryId, event.task_id);
    const occurrences = goalEventIdOccurrences(loaded, event.event_id);
    assertControl(
      targetTaskIds.includes(event.task_id)
        && !installedByTask.has(event.task_id)
        && event.event_id === expectedEventId
        && event.type === 'RECOVER_EXPIRED_FOREMAN'
        && occurrences.length === 1
        && occurrences[0].task_id === event.task_id
        && occurrences[0].input_sha256 === event.input_sha256
        && event.payload
        && event.payload.root_recovery_id === rootRecoveryId
        && event.payload.request_sha256 === intent.request_sha256
        && event.payload.goal_scope_sha256 === originalScope.scope_sha256
        && hashObject(event.payload.goal_scope) === hashObject(originalScope)
        && JSON.stringify(event.payload.scope_task_ids)
          === JSON.stringify(targetTaskIds)
        && JSON.stringify(event.payload.source_task_ids)
          === JSON.stringify(sourceTaskIds)
        && (event.payload.adoption_target_task_id || null)
          === (intent.adoption_target_task_id || null)
        && event.actor
        && event.actor.role === 'FOREMAN'
        && event.actor.thread_id === options.threadId
        && event.actor.host_id === (options.hostId || 'local')
        && event.payload.attempt === Number(options.attempt)
        && event.payload.lease_ms === Number(options.leaseMs)
        && event.payload.capability_file === intent.capability_file
        && event.payload.capability_sha256 === intent.capability_sha256
        && event.accepted_at === intent.accepted_at,
      'EVENT_ID_CONFLICT',
      `root recovery ${rootRecoveryId} accepted task event 不是 exact batch`,
    );
    installedByTask.set(event.task_id, event);
  }
  if (commit) {
    const eventSha256ByTask = Object.fromEntries(
      installedEvents.map((event) => [event.task_id, event.event_sha256]),
    );
    assertControl(
      commit.intent_sha256 === intent.record_sha256
        && commit.request_sha256 === intent.request_sha256
        && installedEvents.length === targetTaskIds.length
        && targetTaskIds.every((taskId) => installedByTask.has(taskId))
        && hashObject(commit.event_sha256_by_task)
          === hashObject(eventSha256ByTask),
      'CORRUPT_STORE',
      `FOREMAN recovery ${rootRecoveryId} commit 未被 exact events 支撑`,
    );
    return true;
  }
  for (const binding of originalScope.tasks) {
    const currentBinding = foremanRecoveryTaskBinding(
      loaded,
      binding.task_id,
    );
    const installed = installedByTask.get(binding.task_id);
    if (installed) {
      const currentForeman =
        loaded.snapshot.tasks[binding.task_id].sessions.FOREMAN;
      assertControl(
        currentBinding.state_revision === binding.state_revision + 1
          && currentBinding.event_head === installed.event_sha256
          && currentForeman
          && currentForeman.thread_id === options.threadId
          && currentForeman.host_id === (options.hostId || 'local')
          && currentForeman.attempt === Number(options.attempt)
          && currentForeman.recovery_event_id === rootRecoveryId
          && currentForeman.recovery_request_sha256
            === intent.request_sha256,
        'RECOVERY_BATCH_DIVERGED',
        `task ${binding.task_id} partial root recovery state 已漂移`,
      );
    } else {
      assertControl(
        hashObject(currentBinding) === hashObject(binding),
        'STALE_FOREMAN_SCOPE',
        `task ${binding.task_id} 在 root recovery batch 完成前已漂移`,
      );
    }
  }
  return true;
}

function exactUnsealedForemanRecoveryPreparedRequest(
  loaded,
  options,
  rootRecoveryId,
) {
  const originalScope = foremanRecoveryScope(loaded);
  assertRecoveryScopeSeal(originalScope);
  const expectedGoalScopeSha256 = normalizeHash(
    options.expectedGoalScopeSha256,
    'expected Goal FOREMAN recovery scope sha256',
  );
  assertControl(
    expectedGoalScopeSha256 === originalScope.scope_sha256,
    'STALE_FOREMAN_SCOPE',
    `expected Goal recovery scope ${expectedGoalScopeSha256}，当前为 ${originalScope.scope_sha256}`,
  );
  const anchorBinding = originalScope.tasks.find(
    (binding) => binding.task_id === options.taskId,
  );
  assertForemanRecoveryLegacyAnchorCas(anchorBinding, options);
  const currentForemanLineage = assertCoherentGoalForemanLineage(
    loaded.snapshot,
  );
  const activeForemanTasks = originalScope.tasks.filter((binding) => (
    binding.phase !== 'ARCHIVED' && binding.foreman
  ));
  let targetTaskIds;
  let sourceTaskIds;
  let adoptionTargetTaskId;
  if (activeForemanTasks.length > 0) {
    const activeAttempt = Math.max(
      ...activeForemanTasks.map((binding) => binding.foreman.attempt),
    );
    assertControl(
      activeForemanTasks.every(
        (binding) => binding.foreman.attempt === activeAttempt,
      )
        && currentForemanLineage.replicas.length > 0
        && activeAttempt === currentForemanLineage.attempt,
      'GOAL_FOREMAN_LINEAGE_DIVERGED',
      '非 ARCHIVED FOREMAN generation 已分叉',
    );
    targetTaskIds = activeForemanTasks.map((binding) => binding.task_id);
    sourceTaskIds = originalScope.tasks
      .filter((binding) => (
        binding.foreman && binding.foreman.attempt === activeAttempt
      ))
      .map((binding) => binding.task_id);
    adoptionTargetTaskId = null;
    assertControl(
      targetTaskIds.includes(options.taskId),
      'GOAL_FOREMAN_SCOPE_MISMATCH',
      `anchor task ${options.taskId} 不在 Goal recovery target scope`,
    );
  } else {
    const archivedSources = originalScope.tasks.filter((binding) => (
      binding.phase === 'ARCHIVED' && binding.foreman
    ));
    assertControl(
      archivedSources.length > 0,
      'UNREGISTERED_ACTOR',
      'Goal 没有可作为 root recovery lineage 的 FOREMAN',
    );
    assertControl(
      anchorBinding.phase !== 'ARCHIVED' && !anchorBinding.foreman,
      'GOAL_FOREMAN_ADOPTION_TARGET_INVALID',
      'archived FOREMAN detach 必须指定一个未登记 FOREMAN 的非 ARCHIVED task',
    );
    const latestAttempt = Math.max(
      ...archivedSources.map((binding) => binding.foreman.attempt),
    );
    assertControl(
      currentForemanLineage.replicas.length > 0
        && latestAttempt === currentForemanLineage.attempt,
      'GOAL_FOREMAN_LINEAGE_DIVERGED',
      'ARCHIVED source generation 不是 Goal current max-attempt lineage',
    );
    targetTaskIds = [options.taskId];
    sourceTaskIds = archivedSources
      .filter((binding) => binding.foreman.attempt === latestAttempt)
      .map((binding) => binding.task_id);
    adoptionTargetTaskId = options.taskId;
  }
  const sourceBindings = sourceTaskIds.map((taskId) => (
    originalScope.tasks.find((binding) => binding.task_id === taskId)
  ));
  const sourceAttempts = new Set(
    sourceBindings.map((binding) => binding.foreman.attempt),
  );
  assertControl(
    sourceAttempts.size === 1,
    'GOAL_FOREMAN_LINEAGE_DIVERGED',
    'Goal 当前 FOREMAN attempts 已分叉，禁止猜测 successor attempt',
  );
  const attempt = Number(options.attempt);
  assertControl(
    attempt === sourceBindings[0].foreman.attempt + 1,
    'STALE_ROLE_ATTEMPT',
    `Goal FOREMAN attempt 必须恰好为 ${sourceBindings[0].foreman.attempt + 1}`,
  );
  const observedAt = runtimeNowMilliseconds();
  const normalRecoveryPath = goalNormalForemanRecoveryPath(
    loaded.snapshot,
    sourceTaskIds,
    observedAt,
  );
  if (!normalRecoveryPath.normal_recovery_already_started) {
    assertControl(
      !normalRecoveryPath.captain_task_id,
      'CAPTAIN_RECOVERY_PATH_AVAILABLE',
      `task ${normalRecoveryPath.captain_task_id} CAPTAIN lease 仍有效；必须先走 ROLE_LOST(FOREMAN) 常规恢复链`,
    );
  }
  for (const binding of sourceBindings) {
    const state = loaded.snapshot.tasks[binding.task_id];
    const foreman = state.sessions.FOREMAN;
    assertControl(
      foremanRootRecoveryStatusEligible(state, foreman)
        && Date.parse(foreman.lease_until) <= observedAt,
      'FOREMAN_RECOVERY_NOT_ELIGIBLE',
      `task ${binding.task_id} FOREMAN 尚不可恢复`,
    );
  }
  assertFreshGoalRoleIdentity(
    loaded.snapshot,
    '__GOAL_ROOT_RECOVERY__',
    'FOREMAN',
    options.threadId,
  );
  return hashObject(buildForemanRecoveryRequest(
    rootRecoveryId,
    options,
    originalScope,
    targetTaskIds,
    sourceTaskIds,
    adoptionTargetTaskId,
  ));
}

function authorizeForemanRecoveryOddRecovery(root, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const rootRecoveryId = safeId(
    options.eventId,
    'root recovery event_id',
  );
  const attempt = Number(options.attempt);
  const leaseMilliseconds = Number(options.leaseMs);
  assertControl(
    Number.isSafeInteger(attempt) && attempt > 1,
    'INVALID_REGISTRATION',
    'successor attempt 必须是大于 1 的整数',
  );
  assertControl(
    Number.isSafeInteger(leaseMilliseconds)
      && leaseMilliseconds > 0
      && leaseMilliseconds <= MAX_ROLE_LEASE_MS,
    'INVALID_REGISTRATION',
    `lease_ms 必须在 1-${MAX_ROLE_LEASE_MS}`,
  );
  const paths = goalPaths(root, goalId);
  let candidate;
  try {
    candidate = preparedIntentCandidate(
      paths.foremanRecoveryBatches,
      'foreman-recovery',
      rootRecoveryId,
      `FOREMAN recovery ${rootRecoveryId}`,
    );
  } catch (error) {
    if (
      error instanceof ControlError
        && error.code === 'PREPARED_REQUEST_MISMATCH'
    ) {
      return false;
    }
    throw error;
  }
  const exactBatch = recoveryBatchState(paths, goalId, rootRecoveryId);
  if (!candidate && !exactBatch.intent) return false;
  assertControl(
    !(candidate && exactBatch.intent),
    'PREPARED_STAGING_CONFLICT',
    `FOREMAN recovery ${rootRecoveryId} final/staging 并存`,
  );
  const inventory = candidate
    ? inspectPreparedIntentInventory(
      candidate,
      foremanRecoveryCapabilityPattern(attempt),
      `FOREMAN recovery ${rootRecoveryId}`,
    )
    : null;
  const loaded = candidate
    ? loadGoalStateUnlocked(root, goalId, {
      repairHeads: false,
      allowLaggingHeads: true,
      repairBootstrapConsumption: false,
      allowIncompleteRecoveryRead: true,
      allowIncompleteGoalOperationRead: true,
      allowPreparedGoalOperationProbe: 'FOREMAN_RECOVERY_BATCH',
    })
    : loadOddRecoveryGoalState(root, goalId);
  assertControl(
    loaded.snapshot.tasks[options.taskId],
    'UNKNOWN_TASK',
    `未知 task ${options.taskId}`,
  );
  const recoveryAuthority = readCapabilityFile(
    options.foremanRecoveryCapabilityFile,
    loaded.meta.foreman_recovery_capability_file,
  );
  assertControl(
    hashesEqual(
      recoveryAuthority.sha256,
      loaded.meta.foreman_recovery_capability_sha256,
    ),
    'CAPABILITY_INVALID',
    'Goal FOREMAN recovery capability 不匹配',
  );
  if (exactBatch.intent) {
    return assertForemanRecoveryIntentRecoveryBoundary(
      root,
      loaded,
      options,
      rootRecoveryId,
      exactBatch.intent,
      exactBatch.commit,
    );
  }
  if (inventory.sealed) {
    const intent = readRecoveryBatchRecord(
      path.join(candidate.directory, 'intent.json'),
      'FOREMAN_RECOVERY_INTENT',
      goalId,
      rootRecoveryId,
    );
    assertControl(
      candidate.requestDigest === preparedDigest(
        intent.prepared_request_sha256,
        `FOREMAN recovery ${rootRecoveryId} prepared request sha256`,
      ),
      'PREPARED_REQUEST_MISMATCH',
      `FOREMAN recovery ${rootRecoveryId} staging path 与 intent 不一致`,
    );
    return assertForemanRecoveryIntentRecoveryBoundary(
      root,
      loaded,
      options,
      rootRecoveryId,
      intent,
      null,
      path.join(candidate.directory, inventory.capabilityName),
    );
  }
  const preparedRequestSha256 =
    exactUnsealedForemanRecoveryPreparedRequest(
      loaded,
      options,
      rootRecoveryId,
    );
  assertControl(
    candidate.name === preparedStagingName(
      'foreman-recovery',
      rootRecoveryId,
      preparedRequestSha256,
    ),
    'PREPARED_REQUEST_MISMATCH',
    `FOREMAN recovery ${rootRecoveryId} unsealed staging 已绑定不同 request`,
  );
  return true;
}

function authorizeForemanRecoveryPristineOddRecovery(root, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const rootRecoveryId = safeId(
    options.eventId,
    'root recovery event_id',
  );
  const paths = goalPaths(root, goalId);
  const candidate = preparedIntentCandidate(
    paths.foremanRecoveryBatches,
    'foreman-recovery',
    rootRecoveryId,
    `FOREMAN recovery ${rootRecoveryId}`,
  );
  const exactBatch = recoveryBatchState(paths, goalId, rootRecoveryId);
  if (candidate || exactBatch.intent || exactBatch.commit) return false;
  const loaded = loadOddRecoveryGoalState(root, goalId);
  assertControl(
    loaded.snapshot.tasks[options.taskId],
    'UNKNOWN_TASK',
    `未知 task ${options.taskId}`,
  );
  const recoveryAuthority = readCapabilityFile(
    options.foremanRecoveryCapabilityFile,
    loaded.meta.foreman_recovery_capability_file,
  );
  assertControl(
    hashesEqual(
      recoveryAuthority.sha256,
      loaded.meta.foreman_recovery_capability_sha256,
    ),
    'CAPABILITY_INVALID',
    'Goal FOREMAN recovery capability 不匹配',
  );
  exactUnsealedForemanRecoveryPreparedRequest(
    loaded,
    options,
    rootRecoveryId,
  );
  return true;
}

function recoverExpiredForeman(cwd, options) {
  options.repositoryWorktree = fs.realpathSync(repoRoot(cwd));
  options.invocationCwd = fs.realpathSync(
    options.invocationCwd || cwd,
  );
  const root = controlRoot(cwd);
  let oddRecoveryAuthorized = false;
  let pristineOddRecoveryAuthorized = false;
  return withLock(root, () => {
    safeId(options.goalId, 'goal_id');
    assertControl(
      typeof options.eventId === 'string' && options.eventId.length > 0,
      'ARG_REQUIRED',
      'recover-expired-foreman 必须显式提供 --event-id，供 crash 后 exact retry',
    );
    const reason = typeof options.reason === 'string' ? options.reason.trim() : '';
    const incidentRef = typeof options.incidentRef === 'string' ? options.incidentRef.trim() : '';
    assertControl(reason.length > 0 && reason.length <= 2000, 'RECOVERY_REASON_REQUIRED', 'recover-expired-foreman 必须提供 1-2000 字符 reason');
    assertControl(incidentRef.length > 0 && incidentRef.length <= 2000, 'RECOVERY_INCIDENT_REQUIRED', 'recover-expired-foreman 必须提供 1-2000 字符 incident-ref');
    const rootRecoveryId = options.eventId;
    safeId(rootRecoveryId, 'root recovery event_id');
    const hostId = options.hostId || 'local';
    const attempt = Number(options.attempt);
    const leaseMilliseconds = Number(options.leaseMs);
    assertControl(Number.isSafeInteger(attempt) && attempt > 1, 'INVALID_REGISTRATION', 'successor attempt 必须是大于 1 的整数');
    assertControl(
      Number.isSafeInteger(leaseMilliseconds) && leaseMilliseconds > 0 && leaseMilliseconds <= MAX_ROLE_LEASE_MS,
      'INVALID_REGISTRATION',
      `lease_ms 必须在 1-${MAX_ROLE_LEASE_MS}`,
    );
    assertControl(typeof options.threadId === 'string' && options.threadId.length > 0, 'INVALID_REGISTRATION', 'successor thread 缺失');
    assertControl(typeof hostId === 'string' && hostId.length > 0, 'INVALID_REGISTRATION', 'successor host 缺失');
    const expectedGoalScopeSha256 = normalizeHash(
      options.expectedGoalScopeSha256,
      'expected Goal FOREMAN recovery scope sha256',
    );

    const paths = goalPaths(root, options.goalId);
    const preparedRecovery = recoverPreparedRecoveryBatch(
      paths,
      rootRecoveryId,
      options,
    );
    const preparedProbe = Boolean(
      preparedRecovery && preparedRecovery.sealed === false,
    );
    const existingBatch = preparedProbe
      ? null
      : recoveryBatchState(paths, options.goalId, rootRecoveryId);
    if (
      existingBatch
      && existingBatch.intent
      && existingBatch.intent.request !== undefined
    ) {
      assertControl(
        recoveryIntentMatchesOptions(
          existingBatch.intent,
          rootRecoveryId,
          options,
        ),
        'PREPARED_REQUEST_MISMATCH',
        `FOREMAN recovery ${rootRecoveryId} 不是 exact request retry`,
      );
    }
    const loaded = loadGoalStateUnlocked(root, options.goalId, {
      allowPendingRecoveryId: existingBatch && existingBatch.intent
        ? rootRecoveryId
        : null,
      allowPendingRecoveryRequestSha256:
        existingBatch && existingBatch.intent
          ? existingBatch.intent.request_sha256
          : null,
      allowPreparedGoalOperationProbe: preparedProbe
        ? 'FOREMAN_RECOVERY_BATCH'
        : null,
    });
    const anchorState = loaded.snapshot.tasks[options.taskId];
    assertControl(anchorState, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);

    const recoveryAuthority = readCapabilityFile(
      options.foremanRecoveryCapabilityFile,
      loaded.meta.foreman_recovery_capability_file,
    );
    assertControl(
      hashesEqual(recoveryAuthority.sha256, loaded.meta.foreman_recovery_capability_sha256),
      'CAPABILITY_INVALID',
      'Goal FOREMAN recovery capability 不匹配',
    );

    const installedEvents = goalRecoveryBatchEvents(root, loaded, rootRecoveryId);
    const batch = recoveryBatchState(loaded.paths, options.goalId, rootRecoveryId);
    assertControl(
      installedEvents.length === 0 || batch.intent,
      'CORRUPT_STORE',
      `root recovery ${rootRecoveryId} 有 task event 但缺 batch intent`,
    );
    let originalScope;
    let targetTaskIds;
    let sourceTaskIds;
    let adoptionTargetTaskId;
    let request;
    let requestSha256;
    let capability;
    let acceptedAt;
    let probeObservation;
    let roleIdentity;
    let intentRecord = batch.intent;

    const buildRequest = (
      scope,
      targets,
      sources,
      adoptionTarget,
      observation,
      identity,
    ) => ({
      schema_version: 2,
      root_recovery_id: rootRecoveryId,
      goal_id: options.goalId,
      anchor_task_id: options.taskId,
      successor: {
        role: 'FOREMAN',
        thread_id: options.threadId,
        host_id: hostId,
        attempt,
        lease_ms: leaseMilliseconds,
      },
      expected_goal_scope_sha256: scope.scope_sha256,
      target_task_ids: targets,
      source_task_ids: sources,
      adoption_target_task_id: adoptionTarget,
      reason,
      incident_ref: incidentRef,
      ...(observation ? { probe_observation: observation } : {}),
      ...(identity ? { role_identity: identity } : {}),
    });

    const assertLegacyAnchorCas = (binding) => {
      if (options.expectedControlEpoch !== undefined) {
        assertControl(
          Number(options.expectedControlEpoch) === binding.control_epoch,
          'STALE_CONTROL_EPOCH',
          `expected control epoch ${options.expectedControlEpoch}，当前为 ${binding.control_epoch}`,
        );
      }
      if (options.expectedStateRevision !== undefined) {
        assertControl(
          Number(options.expectedStateRevision) === binding.state_revision,
          'STALE_STATE_REVISION',
          `expected state revision ${options.expectedStateRevision}，当前为 ${binding.state_revision}`,
        );
      }
      if (options.expectedEventHead !== undefined) {
        assertControl(options.expectedEventHead === binding.event_head, 'STALE_EVENT_HEAD', 'expected task event head 已漂移');
      }
      if (options.expectedPacketRevision !== undefined || options.expectedPacketSha256 !== undefined) {
        assertControl(
          Number(options.expectedPacketRevision) === binding.packet.revision
            && normalizeHash(options.expectedPacketSha256, 'expected packet sha256') === binding.packet.sha256,
          'STALE_PACKET',
          'expected packet 已漂移',
        );
      }
      if (options.expectedFullHead !== undefined) {
        assertFullSha(options.expectedFullHead, 'expected full HEAD');
        assertControl(options.expectedFullHead === binding.full_head, 'STALE_HEAD', 'expected full HEAD 已漂移');
      }
      const expectedForemanFields = [
        options.expectedForemanThreadId,
        options.expectedForemanHostId,
        options.expectedForemanAttempt,
        options.expectedForemanLeaseUntil,
      ];
      if (expectedForemanFields.some((value) => value !== undefined)) {
        assertControl(binding.foreman, 'UNREGISTERED_ACTOR', 'FOREMAN 尚未登记');
        assertControl(
          binding.foreman.thread_id === options.expectedForemanThreadId
            && binding.foreman.host_id === options.expectedForemanHostId,
          'STALE_FOREMAN_IDENTITY',
          'expected FOREMAN identity 已漂移',
        );
        assertControl(
          binding.foreman.attempt === Number(options.expectedForemanAttempt),
          'STALE_ROLE_ATTEMPT',
          'expected FOREMAN attempt 已漂移',
        );
        assertControl(
          binding.foreman.lease_until === options.expectedForemanLeaseUntil,
          'STALE_FOREMAN_LEASE',
          'expected FOREMAN lease 已漂移',
        );
      }
    };

    if (intentRecord) {
      originalScope = intentRecord.goal_scope;
      assertRecoveryScopeSeal(originalScope);
      targetTaskIds = [...intentRecord.target_task_ids];
      sourceTaskIds = [...intentRecord.source_task_ids];
      adoptionTargetTaskId = intentRecord.adoption_target_task_id || null;
      request = buildRequest(
        originalScope,
        targetTaskIds,
        sourceTaskIds,
        adoptionTargetTaskId,
        intentRecord.request.probe_observation || null,
        intentRecord.request.role_identity || null,
      );
      probeObservation = intentRecord.request.probe_observation || null;
      roleIdentity = intentRecord.request.role_identity || null;
      requestSha256 = hashObject(request);
      assertControl(
        expectedGoalScopeSha256 === originalScope.scope_sha256,
        'EVENT_ID_CONFLICT',
        'root recovery exact retry 使用了不同 Goal scope CAS',
      );
      assertControl(
        intentRecord.request_sha256 === requestSha256
          && (
            intentRecord.request === undefined
            || hashObject(intentRecord.request) === requestSha256
          )
          && intentRecord.goal_scope_sha256 === originalScope.scope_sha256
          && intentRecord.successor.thread_id === options.threadId
          && intentRecord.successor.host_id === hostId
          && intentRecord.successor.attempt === attempt
          && intentRecord.successor.lease_ms === leaseMilliseconds,
        'EVENT_ID_CONFLICT',
        `root recovery intent ${rootRecoveryId} 已被不同请求使用`,
      );
      assertControl(
        installedEvents.every((event) => (
          event.payload.request_sha256 === requestSha256
            && event.payload.goal_scope_sha256 === originalScope.scope_sha256
            && hashObject(event.payload.goal_scope) === hashObject(originalScope)
            && JSON.stringify(event.payload.scope_task_ids) === JSON.stringify(targetTaskIds)
            && JSON.stringify(event.payload.source_task_ids) === JSON.stringify(sourceTaskIds)
            && (event.payload.adoption_target_task_id || null) === adoptionTargetTaskId
            && event.actor.thread_id === options.threadId
            && event.actor.host_id === hostId
            && event.payload.attempt === attempt
            && event.payload.lease_ms === leaseMilliseconds
            && event.payload.capability_file === intentRecord.capability_file
            && event.payload.capability_sha256 === intentRecord.capability_sha256
            && event.accepted_at === intentRecord.accepted_at
        )),
        'EVENT_ID_CONFLICT',
        `root recovery id ${rootRecoveryId} 已被不同请求使用`,
      );
      acceptedAt = intentRecord.accepted_at;
      capability = {
        file: intentRecord.capability_file,
        sha256: intentRecord.capability_sha256,
      };
      const existingCapability = readCapabilityFile(capability.file, capability.file);
      assertControl(
        hashesEqual(existingCapability.sha256, capability.sha256),
        'CORRUPT_STORE',
        'root recovery successor capability 与 accepted batch 不一致',
      );
    } else {
      assertFrozenInputs(cwd, loaded);
      const currentForemanLineage = assertCoherentGoalForemanLineage(
        loaded.snapshot,
      );
      originalScope = foremanRecoveryScope(loaded);
      assertRecoveryScopeSeal(originalScope);
      const anchorBinding = originalScope.tasks.find((task) => task.task_id === options.taskId);
      assertLegacyAnchorCas(anchorBinding);
      assertControl(
        expectedGoalScopeSha256 === originalScope.scope_sha256,
        'STALE_FOREMAN_SCOPE',
        `expected Goal recovery scope ${expectedGoalScopeSha256}，当前为 ${originalScope.scope_sha256}`,
      );
      const activeForemanTasks = originalScope.tasks.filter((task) => (
        task.phase !== 'ARCHIVED' && task.foreman
      ));
      if (activeForemanTasks.length > 0) {
        const activeAttempt = Math.max(
          ...activeForemanTasks.map((task) => task.foreman.attempt),
        );
        assertControl(
          activeForemanTasks.every((task) => task.foreman.attempt === activeAttempt),
          'GOAL_FOREMAN_LINEAGE_DIVERGED',
          '非 ARCHIVED task 的当前 FOREMAN attempts 已分叉',
        );
        assertControl(
          currentForemanLineage.replicas.length > 0
            && activeAttempt === currentForemanLineage.attempt,
          'GOAL_FOREMAN_LINEAGE_DIVERGED',
          '非 ARCHIVED FOREMAN generation 不是 Goal current max-attempt lineage',
        );
        targetTaskIds = activeForemanTasks.map((task) => task.task_id);
        sourceTaskIds = originalScope.tasks
          .filter((task) => task.foreman && task.foreman.attempt === activeAttempt)
          .map((task) => task.task_id);
        adoptionTargetTaskId = null;
        assertControl(
          targetTaskIds.includes(options.taskId),
          'GOAL_FOREMAN_SCOPE_MISMATCH',
          `anchor task ${options.taskId} 不在 Goal recovery target scope`,
        );
      } else {
        const allArchivedSources = originalScope.tasks.filter((task) => (
          task.phase === 'ARCHIVED' && task.foreman
        ));
        assertControl(
          allArchivedSources.length > 0,
          'UNREGISTERED_ACTOR',
          'Goal 没有可作为 root recovery lineage 的 FOREMAN',
        );
        assertControl(
          anchorBinding.phase !== 'ARCHIVED' && !anchorBinding.foreman,
          'GOAL_FOREMAN_ADOPTION_TARGET_INVALID',
          'archived FOREMAN detach 必须指定一个未登记 FOREMAN 的非 ARCHIVED task',
        );
        targetTaskIds = [options.taskId];
        const latestArchivedAttempt = Math.max(
          ...allArchivedSources.map((task) => task.foreman.attempt),
        );
        assertControl(
          currentForemanLineage.replicas.length > 0
            && latestArchivedAttempt === currentForemanLineage.attempt,
          'GOAL_FOREMAN_LINEAGE_DIVERGED',
          'ARCHIVED source generation 不是 Goal current max-attempt lineage',
        );
        sourceTaskIds = allArchivedSources
          .filter((task) => task.foreman.attempt === latestArchivedAttempt)
          .map((task) => task.task_id);
        adoptionTargetTaskId = options.taskId;
      }

      request = buildRequest(
        originalScope,
        targetTaskIds,
        sourceTaskIds,
        adoptionTargetTaskId,
        null,
      );
      const { assertNoPendingTaskOperations } = require('./pending-operations');
      for (const taskId of targetTaskIds) {
        assertNoPendingTaskOperations(root, options.goalId, taskId, {
          excludeGoalOperations: preparedProbe,
        });
      }
      const {
        listPendingGoalRegistrationIntents,
      } = require('./pending-operations');
      assertControl(
        listPendingGoalRegistrationIntents(root, options.goalId).length === 0,
        'TASK_OPERATION_PENDING',
        'Goal 有未完成 registration intent，root recovery 必须等待其 exact retry 完成',
      );
      const sourceBindings = sourceTaskIds.map((taskId) => (
        originalScope.tasks.find((task) => task.task_id === taskId)
      ));
      const sourceAttempts = new Set(sourceBindings.map((binding) => binding.foreman.attempt));
      assertControl(
        sourceAttempts.size === 1,
        'GOAL_FOREMAN_LINEAGE_DIVERGED',
        'Goal 当前 FOREMAN attempts 已分叉，禁止猜测 successor attempt',
      );
      const incumbentAttempt = sourceBindings[0].foreman.attempt;
      assertControl(
        attempt === incumbentAttempt + 1,
        'STALE_ROLE_ATTEMPT',
        `Goal FOREMAN attempt 必须恰好为 ${incumbentAttempt + 1}`,
      );
      acceptedAt = nowIso();
      const normalRecoveryPath = goalNormalForemanRecoveryPath(
        loaded.snapshot,
        sourceTaskIds,
        Date.parse(acceptedAt),
      );
      if (!normalRecoveryPath.normal_recovery_already_started) {
        assertControl(
          !normalRecoveryPath.captain_task_id,
          'CAPTAIN_RECOVERY_PATH_AVAILABLE',
          `task ${normalRecoveryPath.captain_task_id} CAPTAIN lease 仍有效；必须先走 ROLE_LOST(FOREMAN) 常规恢复链`,
        );
      }
      for (const binding of sourceBindings) {
        const state = loaded.snapshot.tasks[binding.task_id];
        const foreman = state.sessions.FOREMAN;
        assertControl(
          foremanRootRecoveryStatusEligible(state, foreman),
          'FOREMAN_RECOVERY_NOT_ELIGIBLE',
          `task ${binding.task_id} FOREMAN status=${foreman.status} 不适用 Goal root recovery`,
        );
        assertControl(
          Date.parse(foreman.lease_until) <= Date.parse(acceptedAt),
          'FOREMAN_LEASE_ACTIVE',
          `task ${binding.task_id} FOREMAN lease ${foreman.lease_until} 尚未过期`,
        );
      }
      assertFreshGoalRoleIdentity(
        loaded.snapshot,
        '__GOAL_ROOT_RECOVERY__',
        'FOREMAN',
        options.threadId,
      );
      probeObservation = registrationProbeObservationBinding(
        loaded,
        anchorState,
        {
          ...options,
          role: 'FOREMAN',
          taskId: options.taskId,
          threadId: options.threadId,
          hostId,
          attempt,
          acceptanceTime: acceptedAt,
        },
        rootRecoveryId,
      );
      roleIdentity = registrationRoleIdentityBinding(
        loaded,
        anchorState,
        {
          ...options,
          role: 'FOREMAN',
          taskId: options.taskId,
          threadId: options.threadId,
          hostId,
          attempt,
          launchId: null,
        },
        rootRecoveryId,
      );
      request = buildRequest(
        originalScope,
        targetTaskIds,
        sourceTaskIds,
        adoptionTargetTaskId,
        probeObservation,
        roleIdentity,
      );
      requestSha256 = hashObject(request);
      if (preparedProbe) {
        cleanupExactUnsealedPreparedIntent(
          loaded.paths.foremanRecoveryBatches,
          'foreman-recovery',
          rootRecoveryId,
          requestSha256,
          new RegExp(`^foreman-${attempt}-[0-9a-f]{24}\\.cap$`),
          `FOREMAN recovery ${rootRecoveryId}`,
        );
      }
      const previewCapability = {
        file: path.join(
          recoveryBatchPaths(loaded.paths, rootRecoveryId).dir,
          'pending.cap',
        ),
        sha256: '0'.repeat(64),
      };
      const previewEventIds = new Set();
      for (const taskId of targetTaskIds) {
        const taskEventId = taskId === options.taskId
          ? rootRecoveryId
          : recoveryEventId(rootRecoveryId, taskId);
        safeId(taskEventId, 'task recovery event_id');
        assertControl(
          !previewEventIds.has(taskEventId),
          'EVENT_ID_CONFLICT',
          `root recovery 派生了重复 task event id ${taskEventId}`,
        );
        previewEventIds.add(taskEventId);
        assertControl(
          goalControlEventOccurrences(loaded, taskEventId).length === 0,
          'EVENT_ID_CONFLICT',
          `derived recovery event id ${taskEventId} 已被 Goal control event 使用`,
        );
        assertControl(
          goalEventIdOccurrences(loaded, taskEventId).length === 0,
          'EVENT_ID_CONFLICT',
          `derived recovery event id ${taskEventId} 已被使用`,
        );
        const binding = originalScope.tasks.find(
          (task) => task.task_id === taskId,
        );
        const previewEvent = validateEvent(buildForemanRecoveryEvent({
          adoptionTargetTaskId,
          attempt,
          binding,
          capability: previewCapability,
          goalId: options.goalId,
          hostId,
          incidentRef,
          leaseMilliseconds,
          originalScope,
          probeObservation,
          roleIdentity,
          reason,
          requestSha256,
          rootRecoveryId,
          sourceBinding: sourceBindings[0],
          sourceTaskIds,
          targetTaskIds,
          taskEventId,
          taskId,
          threadId: options.threadId,
        }));
        previewEvent.accepted_at = acceptedAt;
        applyEvent(
          loaded.snapshot.tasks[taskId],
          previewEvent,
          loaded.control.epoch,
        );
      }
      const published = publishRecoveryBatchIntent(
        cwd,
        loaded.paths,
        rootRecoveryId,
        attempt,
        requestSha256,
        (publishedCapability) => ({
          schema_version: 1,
          kind: 'FOREMAN_RECOVERY_INTENT',
          goal_id: options.goalId,
          root_recovery_id: rootRecoveryId,
          request,
          request_sha256: requestSha256,
          prepared_request_sha256: requestSha256,
          goal_scope: originalScope,
          goal_scope_sha256: originalScope.scope_sha256,
          target_task_ids: targetTaskIds,
          source_task_ids: sourceTaskIds,
          adoption_target_task_id: adoptionTargetTaskId,
          successor: request.successor,
          capability_file: publishedCapability.file,
          capability_sha256: publishedCapability.sha256,
          accepted_at: acceptedAt,
        }),
      );
      intentRecord = published.intent;
      capability = published.capability;
      maybeInjectRecoveryBatchFault(
        cwd,
        'GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_INTENT_INSTALL',
        'TEST_FAULT_AFTER_RECOVERY_INTENT',
        'injected failure after FOREMAN recovery intent install',
      );
    }

    const anchorOriginalBinding = originalScope.tasks.find((task) => (
      task.task_id === options.taskId
    ));
    assertLegacyAnchorCas(anchorOriginalBinding);
    const installedByTask = new Map(installedEvents.map((event) => [event.task_id, event]));
    assertControl(
      installedByTask.size === installedEvents.length
        && installedEvents.every((event) => targetTaskIds.includes(event.task_id)),
      'CORRUPT_STORE',
      'root recovery batch 含重复或 scope 外 task event',
    );
    if (batch.commit) {
      const committedEventHashes = Object.fromEntries(
        installedEvents.map((event) => [event.task_id, event.event_sha256]),
      );
      assertControl(
        installedEvents.length === targetTaskIds.length
          && targetTaskIds.every((taskId) => installedByTask.has(taskId))
          && hashObject(committedEventHashes)
            === hashObject(batch.commit.event_sha256_by_task),
        'CORRUPT_STORE',
        'root recovery commit 未被完整 accepted task events 支撑',
      );
      const currentAnchor = loaded.snapshot.tasks[options.taskId];
      const currentForeman = currentAnchor.sessions.FOREMAN;
      return {
        recovered: true,
        idempotent: true,
        cache_degraded: false,
        event_id: rootRecoveryId,
        event_sha256_by_task: committedEventHashes,
        recovered_task_ids: targetTaskIds,
        source_task_ids: sourceTaskIds,
        task: publicTaskState(currentAnchor),
        tasks: Object.fromEntries(targetTaskIds.map((taskId) => [
          taskId,
          publicTaskState(loaded.snapshot.tasks[taskId]),
        ])),
        session: currentForeman
          && currentForeman.thread_id === options.threadId
          && currentForeman.attempt === attempt
          ? publicSession(currentForeman)
          : {
            role: 'FOREMAN',
            thread_id: options.threadId,
            host_id: hostId,
            attempt,
            status: 'superseded',
          },
        actor_capability_file: capability.file,
        ledger: buildLedgerProjection(
          loaded.paths,
          loaded.manifest,
          loaded.snapshot,
          { readOnly: true },
        ),
      };
    }

    for (const binding of originalScope.tasks) {
      const currentBinding = foremanRecoveryTaskBinding(loaded, binding.task_id);
      const installed = installedByTask.get(binding.task_id);
      if (installed) {
        const currentForeman = loaded.snapshot.tasks[binding.task_id].sessions.FOREMAN;
        assertControl(
          currentBinding.state_revision === binding.state_revision + 1
            && currentBinding.event_head === installed.event_sha256
            && currentForeman
            && currentForeman.thread_id === options.threadId
            && currentForeman.host_id === hostId
            && currentForeman.attempt === attempt
            && currentForeman.recovery_event_id === rootRecoveryId
            && currentForeman.recovery_request_sha256 === requestSha256,
          'RECOVERY_BATCH_DIVERGED',
          `task ${binding.task_id} partial root recovery state 已漂移`,
        );
      } else {
        assertControl(
          hashObject(currentBinding) === hashObject(binding),
          'STALE_FOREMAN_SCOPE',
          `task ${binding.task_id} 在 root recovery batch 完成前已漂移`,
        );
      }
    }

    const sourceBinding = originalScope.tasks.find((task) => (
      task.task_id === sourceTaskIds[0]
    ));
    let cacheDegraded = false;
    const eventSha256ByTask = {};
    let installedAny = installedEvents.length > 0;
    try {
      for (const taskId of targetTaskIds) {
        const taskEventId = taskId === options.taskId
          ? rootRecoveryId
          : recoveryEventId(rootRecoveryId, taskId);
        safeId(taskEventId, 'task recovery event_id');
        assertControl(
          goalControlEventOccurrences(loaded, taskEventId).length === 0,
          'EVENT_ID_CONFLICT',
          `derived recovery event id ${taskEventId} 已被 Goal control event 使用`,
        );
        const priorInstalled = installedByTask.get(taskId);
        if (priorInstalled) {
          eventSha256ByTask[taskId] = priorInstalled.event_sha256;
          continue;
        }
        const binding = originalScope.tasks.find((task) => task.task_id === taskId);
        assertControl(
          goalEventIdOccurrences(loaded, taskEventId).length === 0,
          'EVENT_ID_CONFLICT',
          `derived recovery event id ${taskEventId} 已被使用`,
        );
        const recoveryEvent = buildForemanRecoveryEvent({
          adoptionTargetTaskId,
          attempt,
          binding,
          capability,
          goalId: options.goalId,
          hostId,
          incidentRef,
          leaseMilliseconds,
          originalScope,
          probeObservation,
          roleIdentity,
          reason,
          requestSha256,
          rootRecoveryId,
          sourceBinding,
          sourceTaskIds,
          targetTaskIds,
          taskEventId,
          taskId,
          threadId: options.threadId,
        });
        const validated = validateEvent(recoveryEvent);
        validated.input_sha256 = hashObject(validated);
        validated.accepted_at = acceptedAt;
        const nextState = applyEvent(
          loaded.snapshot.tasks[taskId],
          validated,
          loaded.control.epoch,
        );
        const durableCommit = writeAcceptedEvent(
          root,
          options.goalId,
          taskId,
          nextState.state_revision,
          validated,
          loaded.lastEventHashes[taskId] || null,
        );
        installedAny = true;
        cacheDegraded = cacheDegraded || Boolean(durableCommit.headError);
        nextState.last_event.event_sha256 = durableCommit.event.event_sha256;
        loaded.snapshot.tasks[taskId] = nextState;
        loaded.lastEventHashes[taskId] = durableCommit.event.event_sha256;
        eventSha256ByTask[taskId] = durableCommit.event.event_sha256;
        if (Object.keys(eventSha256ByTask).length === 1) {
          maybeInjectRecoveryBatchFault(
            cwd,
            'GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_TASK_EVENT_INSTALL',
            'TEST_FAULT_AFTER_RECOVERY_TASK_EVENT',
            'injected failure after first FOREMAN recovery task event install',
          );
        }
      }
      const commitRecord = sealedRecoveryBatchRecord({
        schema_version: 1,
        kind: 'FOREMAN_RECOVERY_COMMIT',
        goal_id: options.goalId,
        root_recovery_id: rootRecoveryId,
        intent_sha256: intentRecord.record_sha256,
        request_sha256: requestSha256,
        event_sha256_by_task: eventSha256ByTask,
        committed_at: nowIso(),
      });
      const batchFiles = recoveryBatchPaths(loaded.paths, rootRecoveryId);
      if (batch.commit) {
        assertControl(
          batch.commit.intent_sha256 === commitRecord.intent_sha256
            && batch.commit.request_sha256 === commitRecord.request_sha256
            && hashObject(batch.commit.event_sha256_by_task)
              === hashObject(commitRecord.event_sha256_by_task),
          'CORRUPT_STORE',
          'root recovery commit 与 durable task events 不一致',
        );
      } else {
        atomicWriteJson(batchFiles.commit, commitRecord);
      }
      loaded.snapshot.generated_at = nowIso();
      let ledger = null;
      try {
        ledger = writeProjections(loaded.paths, loaded.manifest, loaded.snapshot);
      } catch {
        cacheDegraded = true;
      }
      const anchor = loaded.snapshot.tasks[options.taskId];
      return {
        recovered: true,
        idempotent: installedEvents.length === targetTaskIds.length,
        cache_degraded: cacheDegraded,
        event_id: rootRecoveryId,
        event_sha256_by_task: eventSha256ByTask,
        recovered_task_ids: targetTaskIds,
        source_task_ids: sourceTaskIds,
        task: publicTaskState(anchor),
        tasks: Object.fromEntries(targetTaskIds.map((taskId) => [
          taskId,
          publicTaskState(loaded.snapshot.tasks[taskId]),
        ])),
        session: publicSession(anchor.sessions.FOREMAN),
        actor_capability_file: capability.file,
        ledger,
      };
    } catch (error) {
      if (!installedAny) {
        const installedAfterFailure = goalRecoveryBatchEvents(
          root,
          loaded,
          rootRecoveryId,
        );
        installedAny = installedAfterFailure.length > 0;
      }
      // A capability visible here is already bound by a sealed staging/final
      // intent. Never guess that it is orphaned from outer assignment state:
      // exact retry inventories and promotes that durable operation.
      throw error;
    }
  }, {
    transactionKey: () => foremanRecoveryTransactionKey(options),
    sameStableOperationMismatchCode: 'PREPARED_REQUEST_MISMATCH',
    sameStableOperationMismatchMessage:
      `FOREMAN recovery ${safeId(
        options.eventId,
        'root recovery event_id',
      )} 不是 exact request retry`,
    beforeGeneration: (transaction) => {
      oddRecoveryAuthorized = false;
      pristineOddRecoveryAuthorized = false;
      if (transaction.mode === 'FRESH') {
        const recoveryPaths = goalPaths(
          root,
          safeId(options.goalId, 'goal_id'),
        );
        const existingRecovery = recoveryBatchState(
          recoveryPaths,
          options.goalId,
          safeId(options.eventId, 'root recovery event_id'),
        );
        if (
          !existingRecovery.intent
            && options.probeObservationReceipt
        ) {
          const prevalidated = loadGoalStateUnlocked(
            root,
            options.goalId,
            {
              repairHeads: false,
              repairBootstrapConsumption: false,
            },
          );
          const prevalidatedState =
            prevalidated.snapshot.tasks[options.taskId];
          assertControl(
            prevalidatedState,
            'UNKNOWN_TASK',
            `未知 task ${options.taskId}`,
          );
          registrationRoleIdentityBinding(
            prevalidated,
            prevalidatedState,
            {
              ...options,
              role: 'FOREMAN',
              taskId: options.taskId,
              threadId: options.threadId,
              hostId: options.hostId,
              attempt: options.attempt,
              launchId: null,
            },
            options.eventId,
          );
        }
      }
      oddRecoveryAuthorized = authorizeForemanRecoveryOddRecovery(
        root,
        options,
      );
      if (
        !oddRecoveryAuthorized
          && readSealedRootGenerationParity(root) === 'ODD'
      ) {
        pristineOddRecoveryAuthorized =
          authorizeForemanRecoveryPristineOddRecovery(root, options);
      }
    },
    authorizeOddRecovery: () => oddRecoveryAuthorized,
    authorizePristineOddRecovery: () => pristineOddRecoveryAuthorized,
    afterGenerationBeforeCallback: generationBoundaryFaultHook(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_FOREMAN_RECOVERY_GENERATION',
    ),
  });
}

function registrationCapabilityPattern(role, attempt) {
  return new RegExp(
    `^${role.toLowerCase()}-${attempt}-[0-9a-f]{24}\\.cap$`,
  );
}

function authorizeRegistrationIntentAuthority(loaded, options, authority) {
  assertControl(
    authority && typeof authority.kind === 'string',
    'CORRUPT_STORE',
    'registration intent 缺 sealed authorizer authority',
  );
  if (authority.kind === 'SESSION') {
    assertControl(
      typeof authority.role === 'string'
        && typeof authority.thread_id === 'string'
        && typeof authority.host_id === 'string'
        && Number.isSafeInteger(authority.attempt)
        && authority.attempt > 0,
      'CORRUPT_STORE',
      'registration intent SESSION authority identity 不完整',
    );
    return authorizeHistoricalActorCapability(
      loaded.snapshot,
      options.authorizerCapabilityFile,
      authority,
      {
        goalWide: authority.role === 'FOREMAN',
        taskId: authority.source_task_id || options.taskId,
      },
    );
  }
  const expectedFile = authority.kind === 'BOOTSTRAP'
    ? loaded.meta.bootstrap_capability_file
    : loaded.meta.foreman_recovery_capability_file;
  const suppliedFile = authority.kind === 'BOOTSTRAP'
    ? options.bootstrapCapabilityFile
    : options.foremanRecoveryCapabilityFile;
  assertControl(
    ['BOOTSTRAP', 'GOAL_RECOVERY'].includes(authority.kind)
      && authority.capability_file === expectedFile,
    'CAPABILITY_INVALID',
    'registration intent sealed authority kind/path 不匹配',
  );
  const supplied = readCapabilityFile(suppliedFile, expectedFile);
  assertControl(
    hashesEqual(supplied.sha256, authority.capability_sha256)
      && (
        authority.kind !== 'BOOTSTRAP'
        || hashesEqual(
          supplied.sha256,
          loaded.meta.bootstrap_capability_sha256,
        )
      )
      && (
        authority.kind !== 'GOAL_RECOVERY'
        || hashesEqual(
          supplied.sha256,
          loaded.meta.foreman_recovery_capability_sha256,
        )
      ),
    'CAPABILITY_INVALID',
    'registration intent sealed authority capability 不匹配',
  );
  return authority;
}

function assertRegistrationIntentRecoveryBoundary(
  loaded,
  state,
  options,
  eventId,
  intent,
  stagedCapabilityFile = null,
) {
  const request = intent && intent.request;
  const authority = intent && intent.authorizer_authority;
  assertControl(
    intent
      && intent.goal_id === options.goalId
      && intent.task_id === options.taskId
      && request
      && intent.request_sha256 === hashObject(request)
      && authority
      && intent.prepared_request_sha256 === hashObject({
        request,
        authorizer_authority: authority,
      }),
    'PREPARED_STAGING_INVALID',
    `registration ${eventId} prepared request/authority seal 不匹配`,
  );
  assertControl(
    registrationIntentMatchesOptions(intent, eventId, options),
    'PREPARED_REQUEST_MISMATCH',
    `registration ${eventId} prepared request 与当前命令不一致`,
  );
  assertControl(
    request.expected
      && request.expected.state_revision === state.state_revision
      && request.expected.control_epoch === loaded.control.epoch
      && request.expected.packet
      && request.expected.packet.revision === state.packet.revision
      && request.expected.packet.sha256 === state.packet.sha256
      && request.expected.base_head === state.base_head
      && request.expected.full_head === state.full_head,
    'REGISTRATION_INTENT_DIVERGED',
    `registration intent ${eventId} 后 task state 已漂移`,
  );
  if (authority.kind === 'SESSION') {
    assertControl(
      request.authorized_by
        && request.authorized_by.role === authority.role
        && request.authorized_by.thread_id === authority.thread_id
        && request.authorized_by.host_id === authority.host_id
        && request.authorized_by.attempt === authority.attempt,
      'PREPARED_STAGING_INVALID',
      `registration ${eventId} request/SESSION authority binding 漂移`,
    );
  } else {
    assertControl(
      request.authorized_by
        && request.authorized_by.role === (
          authority.kind === 'BOOTSTRAP'
            ? 'BOOTSTRAP'
            : 'GOAL_RECOVERY'
        )
        && request.authorized_by.capability_file
          === authority.capability_file,
      'PREPARED_STAGING_INVALID',
      `registration ${eventId} request/capability authority binding 漂移`,
    );
  }
  authorizeRegistrationIntentAuthority(loaded, options, authority);
  const capabilityFile = stagedCapabilityFile || intent.capability_file;
  const capability = readCapabilityFile(capabilityFile, capabilityFile);
  const expectedFinalDirectory = registrationIntentPaths(
    loaded.paths,
    eventId,
  ).dir;
  assertControl(
    intent.capability_file === path.join(
      expectedFinalDirectory,
      path.basename(capabilityFile),
    )
      && registrationCapabilityPattern(
        options.role,
        Number(options.attempt || 1),
      ).test(path.basename(capabilityFile))
      && hashesEqual(capability.sha256, intent.capability_sha256),
    'PREPARED_STAGING_INVALID',
    `registration ${eventId} capability path/bytes 与 intent 不一致`,
  );
  return true;
}

function historicalRegistrationAuthorizer(
  loaded,
  options,
  requiredRole,
  goalWide,
  authorizationAt = null,
) {
  const supplied = readCapabilityFile(options.authorizerCapabilityFile);
  const states = goalWide
    ? Object.values(loaded.snapshot.tasks || {})
    : [loaded.snapshot.tasks[options.taskId]].filter(Boolean);
  const candidates = states.flatMap((taskState) => [
    ...Object.values(taskState.sessions || {}).map((session) => ({
      ...session,
      task_id: taskState.task_id,
    })),
    ...Object.values(taskState.session_history || {}).flat().map((session) => ({
      ...session,
      task_id: taskState.task_id,
    })),
  ]).filter((session) => (
    session.role === requiredRole
      && (
        !options.authorizerThreadId
        || session.thread_id === options.authorizerThreadId
      )
      && session.capability_file === supplied.file
      && hashesEqual(session.capability_sha256, supplied.sha256)
  ));
  assertControl(
    candidates.length > 0,
    'CAPABILITY_INVALID',
    `capability 不属于 historical ${requiredRole} authorizer`,
  );
  assertControl(
    candidates.every((candidate) => (
      candidate.role === candidates[0].role
        && candidate.thread_id === candidates[0].thread_id
        && candidate.host_id === candidates[0].host_id
        && candidate.attempt === candidates[0].attempt
    )),
    'CORRUPT_STORE',
    `historical ${requiredRole} capability identity 分叉`,
  );
  if (authorizationAt === null) return candidates[0];
  const boundaryMilliseconds = Date.parse(authorizationAt);
  assertControl(
    typeof authorizationAt === 'string'
      && Number.isFinite(boundaryMilliseconds),
    'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
    `historical ${requiredRole} authorization 缺 transaction boundary timestamp`,
  );
  const registeredAtBoundary = candidates.filter((candidate) => (
    typeof candidate.registered_at === 'string'
      && Number.isFinite(Date.parse(candidate.registered_at))
      && Date.parse(candidate.registered_at) <= boundaryMilliseconds
  ));
  assertControl(
    registeredAtBoundary.length > 0,
    'CAPABILITY_INVALID',
    `historical ${requiredRole} capability 在 transaction boundary 尚未登记`,
  );
  const usableAtBoundary = registeredAtBoundary
    .filter((candidate) => (
      ['active', 'idle'].includes(candidate.status)
        && typeof candidate.lease_until === 'string'
        && Number.isFinite(Date.parse(candidate.lease_until))
        && Date.parse(candidate.lease_until) > boundaryMilliseconds
    ))
    .sort((left, right) => (
      Date.parse(right.lease_until) - Date.parse(left.lease_until)
    ));
  assertControl(
    usableAtBoundary.length > 0,
    registeredAtBoundary.some((candidate) => (
      ['active', 'idle'].includes(candidate.status)
    ))
      ? 'ACTOR_LEASE_EXPIRED'
      : 'ACTOR_UNUSABLE',
    registeredAtBoundary.some((candidate) => (
      ['active', 'idle'].includes(candidate.status)
    ))
      ? `historical ${requiredRole} capability 在 transaction boundary 已过期`
      : `historical ${requiredRole} capability 在 transaction boundary 不可用`,
  );
  return usableAtBoundary[0];
}

function exactUnsealedRegistrationPreparedRequest(
  root,
  loaded,
  state,
  options,
  eventId,
  authorizationAt = null,
  returnDetails = false,
) {
  const attempt = Number(options.attempt || 1);
  const hostId = options.hostId || 'local';
  const existing = state.sessions[options.role];
  const bootstrapLineage = goalBootstrapForemanLineage(root, loaded);
  const bootstrapSpent = Boolean(loaded.meta.bootstrap_consumed_at)
    || bootstrapLineage.length > 0;
  let authorizedBy;
  let authorizerAuthority;
  let sharedGoalForeman = null;
  if (
    options.role === 'FOREMAN'
      && !existing
      && options.bootstrapCapabilityFile
  ) {
    assertControl(
      !bootstrapSpent,
      'CAPABILITY_CONSUMED',
      'bootstrap capability 已由 Goal append-only FOREMAN lineage 消费',
    );
    const bootstrap = readCapabilityFile(
      options.bootstrapCapabilityFile,
      loaded.meta.bootstrap_capability_file,
    );
    assertControl(
      hashesEqual(
        bootstrap.sha256,
        loaded.meta.bootstrap_capability_sha256,
      ),
      'CAPABILITY_INVALID',
      'bootstrap capability 不匹配',
    );
    authorizedBy = {
      role: 'BOOTSTRAP',
      capability_file: bootstrap.file,
    };
    authorizerAuthority = {
      kind: 'BOOTSTRAP',
      capability_file: bootstrap.file,
      capability_sha256: bootstrap.sha256,
    };
  } else {
    const recoveringForeman = options.role === 'FOREMAN'
      && existing
      && state.recovery
      && state.recovery.role === 'FOREMAN';
    if (recoveringForeman) {
      const nonArchivedForemanProjections = Object.values(
        loaded.snapshot.tasks,
      ).filter((taskState) => (
        taskState.phase !== 'ARCHIVED'
          && taskState.sessions
          && taskState.sessions.FOREMAN
      ));
      assertControl(
        nonArchivedForemanProjections.length <= 1,
        'GOAL_FOREMAN_BATCH_REQUIRED',
        'Goal-wide FOREMAN 有多个活动 task projection；禁止单 task replacement，必须使用 recover-expired-foreman 批量恢复',
      );
      const recovery = readCapabilityFile(
        options.foremanRecoveryCapabilityFile,
        loaded.meta.foreman_recovery_capability_file,
      );
      assertControl(
        hashesEqual(
          recovery.sha256,
          loaded.meta.foreman_recovery_capability_sha256,
        ),
        'CAPABILITY_INVALID',
        'Goal FOREMAN recovery capability 不匹配',
      );
      authorizedBy = {
        role: 'GOAL_RECOVERY',
        capability_file: recovery.file,
      };
      authorizerAuthority = {
        kind: 'GOAL_RECOVERY',
        capability_file: recovery.file,
        capability_sha256: recovery.sha256,
      };
    } else {
      const requiredRole = ['FOREMAN', 'CAPTAIN'].includes(options.role)
        ? 'FOREMAN'
        : 'CAPTAIN';
      assertControl(
        options.role !== 'FOREMAN' || !existing,
        'GOAL_FOREMAN_PROJECTION_REQUIRED',
        '已有 local FOREMAN 的 task 禁止普通 registration mint/替换；只能走 sealed recovery',
      );
      const authorizer = historicalRegistrationAuthorizer(
        loaded,
        options,
        requiredRole,
        options.role === 'FOREMAN',
        authorizationAt,
      );
      if (options.role === 'FOREMAN' && !existing) {
        assertControl(
          authorizer.thread_id === options.threadId
            && authorizer.host_id === hostId
            && authorizer.attempt === attempt
            && (options.status || 'active') === authorizer.status,
          'GOAL_FOREMAN_PROJECTION_REQUIRED',
          '已有 Goal FOREMAN 时，新 task 只能投影同一 identity/attempt/status，禁止 mint 第二 authority',
        );
        sharedGoalForeman = authorizer;
      }
      authorizedBy = {
        role: authorizer.role,
        thread_id: authorizer.thread_id,
        host_id: authorizer.host_id,
        attempt: authorizer.attempt,
      };
      authorizerAuthority = {
        kind: 'SESSION',
        source_task_id: authorizer.task_id || options.taskId,
        role: authorizer.role,
        thread_id: authorizer.thread_id,
        host_id: authorizer.host_id,
        attempt: authorizer.attempt,
        capability_file: authorizer.capability_file,
        capability_sha256: authorizer.capability_sha256,
      };
    }
  }
  if (!sharedGoalForeman) {
    assertFreshGoalRoleIdentity(
      loaded.snapshot,
      options.taskId,
      options.role,
      options.threadId,
    );
  }
  if (existing) {
    assertControl(
      (state.recovery && state.recovery.role === options.role)
        || existing.status === 'terminal',
      'ROLE_REPLACEMENT_REQUIRES_RECOVERY',
      `${options.role} 仍活跃，不能直接 higher-attempt 接管`,
    );
  }
  const workerLaunchId = options.launchId || null;
  assertControl(
    !['DEV', 'REVIEW', 'RECEIPT'].includes(options.role)
      || workerLaunchId,
    'LAUNCH_ID_REQUIRED',
    `${options.role} registration 必须带 --launch-id`,
  );
  const workerBootstrap = registrationWorkerBootstrapBinding(
    loaded,
    state,
    options,
  );
  const probeObservation = registrationProbeObservationBinding(
    loaded,
    state,
    {
      ...options,
      acceptanceTime: authorizationAt || nowIso(),
    },
    eventId,
  );
  const roleIdentity = registrationRoleIdentityBinding(
    loaded,
    state,
    options,
    eventId,
    workerBootstrap,
  );
  const request = {
    schema_version: 1,
    event_id: eventId,
    goal_id: options.goalId,
    task_id: options.taskId,
    role: options.role,
    thread_id: options.threadId,
    host_id: hostId,
    attempt,
    lease_ms: Number(options.leaseMs || 3600000),
    status: options.status || 'active',
    launch_id: workerLaunchId,
    ...(workerBootstrap
      ? { worker_bootstrap: workerBootstrap }
      : {}),
    ...(probeObservation
      ? { probe_observation: probeObservation }
      : {}),
    ...(roleIdentity
      ? { role_identity: roleIdentity }
      : {}),
    authorized_by: authorizedBy,
    expected: {
      state_revision: state.state_revision,
      control_epoch: loaded.control.epoch,
      packet: {
        revision: state.packet.revision,
        sha256: state.packet.sha256,
      },
      base_head: state.base_head,
      full_head: state.full_head,
    },
  };
  const prepared = {
    request,
    authorizer_authority: authorizerAuthority,
  };
  return returnDetails
    ? {
      prepared,
      shared_goal_foreman: sharedGoalForeman,
    }
    : hashObject(prepared);
}

function authorizeRegistrationOddRecovery(root, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const attempt = Number(options.attempt || 1);
  assertControl(
    Number.isSafeInteger(attempt) && attempt > 0,
    'INVALID_REGISTRATION',
    'attempt 必须是正整数',
  );
  const hostId = options.hostId || 'local';
  const eventId = safeId(
    options.eventId
      || `register-${options.role.toLowerCase()}-${attempt}-${sha256(`${taskId}:${hostId}:${options.threadId}`).slice(0, 12)}`,
    'registration event_id',
  );
  const paths = goalPaths(root, goalId);
  let candidate;
  try {
    candidate = preparedIntentCandidate(
      paths.registrationIntents,
      'registration',
      eventId,
      `registration ${eventId}`,
      'TASK_OPERATION_PENDING',
    );
  } catch (error) {
    if (error instanceof ControlError && error.code === 'TASK_OPERATION_PENDING') {
      return false;
    }
    throw error;
  }
  const canonicalIntent = readRegistrationIntent(paths, eventId);
  assertControl(
    !(candidate && canonicalIntent),
    'PREPARED_STAGING_CONFLICT',
    `registration ${eventId} final/staging 并存`,
  );
  const candidateInventory = candidate
    ? inspectPreparedIntentInventory(
      candidate,
      registrationCapabilityPattern(options.role, attempt),
      `registration ${eventId}`,
    )
    : null;
  const loaded = candidate
    ? loadGoalStateUnlocked(root, goalId, {
      repairHeads: false,
      allowLaggingHeads: true,
      repairBootstrapConsumption: false,
      allowIncompleteRecoveryRead: true,
      allowIncompleteGoalOperationRead: true,
      allowPreparedGoalOperationProbe: 'REGISTRATION',
    })
    : loadOddRecoveryGoalState(root, goalId);
  const state = loaded.snapshot.tasks[taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
  assertControl(
    goalControlEventOccurrences(loaded, eventId).length === 0,
    'EVENT_ID_CONFLICT',
    `registration event id ${eventId} 已被 Goal control event 使用`,
  );
  const occurrences = goalEventIdOccurrences(loaded, eventId);
  assertControl(
    occurrences.every((occurrence) => occurrence.task_id === taskId),
    'EVENT_ID_CONFLICT',
    `registration event id ${eventId} 已被 Goal 中其它 task 使用`,
  );
  if (occurrences.length > 0) {
    assertControl(
      occurrences.length === 1,
      'CORRUPT_STORE',
      `registration event id ${eventId} 在 task event chain 中重复`,
    );
    const accepted = acceptedGoalEvent(root, loaded, taskId, eventId);
    assertControl(
      accepted
        && accepted.input_sha256 === occurrences[0].input_sha256,
      'CORRUPT_STORE',
      `accepted registration ${eventId} 缺失或 input hash 不一致`,
    );
    authorizeRegistrationRetry(root, loaded, state, options, accepted);
    const authority = accepted.payload.authorized_by || {};
    if (
      !options.actorCapabilityFile
        && !['BOOTSTRAP', 'GOAL_RECOVERY'].includes(authority.role)
    ) {
      authorizeHistoricalActorCapability(
        loaded.snapshot,
        options.authorizerCapabilityFile,
        authority,
        {
          goalWide: authority.role === 'FOREMAN',
          taskId,
        },
      );
    }
    return true;
  }
  if (canonicalIntent) {
    return assertRegistrationIntentRecoveryBoundary(
      loaded,
      state,
      options,
      eventId,
      canonicalIntent,
    );
  }
  if (!candidate) return false;
  const inventory = candidateInventory;
  if (inventory.sealed) {
    const intent = readRegistrationIntentFile(
      path.join(candidate.directory, 'intent.json'),
      eventId,
    );
    assertControl(
      candidate.requestDigest === preparedDigest(
        intent.prepared_request_sha256,
        `registration ${eventId} prepared request sha256`,
      ),
      'PREPARED_REQUEST_MISMATCH',
      `registration ${eventId} staging path 与 sealed intent 不一致`,
    );
    return assertRegistrationIntentRecoveryBoundary(
      loaded,
      state,
      options,
      eventId,
      intent,
      path.join(candidate.directory, inventory.capabilityName),
    );
  }
  const expectedPreparedRequestSha256 =
    exactUnsealedRegistrationPreparedRequest(
      root,
      loaded,
      state,
      options,
      eventId,
    );
  assertControl(
    candidate.name === preparedStagingName(
      'registration',
      eventId,
      expectedPreparedRequestSha256,
    ),
    'PREPARED_REQUEST_MISMATCH',
    `registration ${eventId} unsealed staging 已绑定不同 request`,
  );
  return true;
}

function authorizeRegistrationPristineOddRecovery(
  root,
  options,
  authorizationAt,
) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const eventId = registrationStableEventId(options);
  const paths = goalPaths(root, goalId);
  const candidate = preparedIntentCandidate(
    paths.registrationIntents,
    'registration',
    eventId,
    `registration ${eventId}`,
    'TASK_OPERATION_PENDING',
  );
  if (candidate || readRegistrationIntent(paths, eventId)) return false;
  const loaded = loadOddRecoveryGoalState(root, goalId);
  const state = loaded.snapshot.tasks[taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
  assertControl(
    goalControlEventOccurrences(loaded, eventId).length === 0
      && goalEventIdOccurrences(loaded, eventId).length === 0,
    'EVENT_ID_CONFLICT',
    `registration event id ${eventId} 已有 durable operation`,
  );
  exactUnsealedRegistrationPreparedRequest(
    root,
    loaded,
    state,
    options,
    eventId,
    authorizationAt,
  );
  return true;
}

function registerRole(cwd, options) {
  options.repositoryWorktree = fs.realpathSync(repoRoot(cwd));
  options.invocationCwd = fs.realpathSync(
    options.invocationCwd || cwd,
  );
  const root = controlRoot(cwd);
  let oddRecoveryAuthorized = false;
  let pristineOddRecoveryAuthorized = false;
  let pristineAuthorizationAt = null;
  return withLock(root, () => {
    safeId(options.goalId, 'goal_id');
    const attempt = Number(options.attempt || 1);
    assertControl(Number.isSafeInteger(attempt) && attempt > 0, 'INVALID_REGISTRATION', 'attempt 必须是正整数');
    const hostId = options.hostId || 'local';
    const eventId = options.eventId || `register-${options.role.toLowerCase()}-${attempt}-${sha256(`${options.taskId}:${hostId}:${options.threadId}`).slice(0, 12)}`;
    safeId(eventId, 'registration event_id');
    const paths = goalPaths(root, options.goalId);
    const preparedRegistration = recoverPreparedRegistrationIntent(
      paths,
      eventId,
      options,
    );
    const preparedProbe = Boolean(
      preparedRegistration && preparedRegistration.sealed === false,
    );
    const exactRegistrationIntent = preparedProbe
      ? null
      : readRegistrationIntent(paths, eventId);
    if (exactRegistrationIntent) {
      assertControl(
        registrationIntentMatchesOptions(
          exactRegistrationIntent,
          eventId,
          options,
        ),
        'PREPARED_REQUEST_MISMATCH',
        `registration ${eventId} 不是 exact request retry`,
      );
    }
    const loaded = loadGoalStateUnlocked(root, options.goalId, {
      allowPendingGoalOperation: exactRegistrationIntent
        ? {
          kind: 'REGISTRATION',
          operation_id: eventId,
          request_sha256: exactRegistrationIntent.request_sha256,
        }
        : null,
      allowPreparedGoalOperationProbe: preparedProbe
        ? 'REGISTRATION'
        : null,
    });
    const state = loaded.snapshot.tasks[options.taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
    assertControl(
      goalControlEventOccurrences(loaded, eventId).length === 0,
      'EVENT_ID_CONFLICT',
      `registration event id ${eventId} 已被 Goal control event 使用`,
    );
    const eventIdOccurrences = goalEventIdOccurrences(loaded, eventId);
    assertControl(
      eventIdOccurrences.every((occurrence) => occurrence.task_id === options.taskId),
      'EVENT_ID_CONFLICT',
      `registration event id ${eventId} 已被 Goal 中其它 task 使用`,
    );
    const existing = state.sessions[options.role];
    if (eventIdOccurrences.length === 1) {
      const accepted = acceptedGoalEvent(root, loaded, options.taskId, eventId);
      const retriedSession = authorizeRegistrationRetry(
        root,
        loaded,
        state,
        options,
        accepted,
      );
      let ledger = null;
      let cacheDegraded = false;
      try {
        ledger = writeProjections(loaded.paths, loaded.manifest, loaded.snapshot);
      } catch {
        cacheDegraded = true;
      }
      return {
        registered: true,
        idempotent: true,
        cache_degraded: cacheDegraded,
        task: publicTaskState(state),
        session: publicSession(retriedSession),
        actor_capability_file: retriedSession.capability_file,
        ...(retriedSession.task_nonce ? { task_nonce: retriedSession.task_nonce } : {}),
        ledger,
      };
    }
    const pendingRegistrationIntent = readRegistrationIntent(
      loaded.paths,
      eventId,
    );
    const {
      listPendingGoalRegistrationIntents,
    } = require('./pending-operations');
    const goalRegistrationIntents = preparedProbe
      ? pendingCanonicalRegistrationIntents(
        root,
        loaded.paths,
        options.goalId,
      )
      : listPendingGoalRegistrationIntents(root, options.goalId);
    const otherRegistrationIntents = goalRegistrationIntents
      .filter((intent) => intent.event_id !== eventId);
    assertControl(
      !otherRegistrationIntents.some((intent) => (
        intent.request
          && intent.request.thread_id === options.threadId
      )),
      'ROLE_IDENTITY_REUSE',
      `thread identity ${options.threadId} 已被 pending Goal registration intent 保留`,
    );
    assertControl(
      otherRegistrationIntents.length === 0,
      'TASK_OPERATION_PENDING',
      `Goal 有未完成 registration intent: ${otherRegistrationIntents
        .map((intent) => intent.event_id)
        .join(', ')}`,
    );
    if (pendingRegistrationIntent) {
      const request = pendingRegistrationIntent.request;
      assertControl(
        pendingRegistrationIntent.goal_id === options.goalId
          && pendingRegistrationIntent.task_id === options.taskId
          && request
          && request.event_id === eventId
          && request.goal_id === options.goalId
          && request.task_id === options.taskId
          && request.role === options.role
          && request.thread_id === options.threadId
          && request.host_id === hostId
          && request.attempt === attempt
          && request.lease_ms === Number(options.leaseMs || 3600000)
          && request.status === (options.status || 'active')
          && request.launch_id === (options.launchId || null)
          && workerBootstrapRequestMatchesBinding(
            request.worker_bootstrap || null,
            options,
          )
          && probeObservationRequestMatchesBinding(
            request.probe_observation || null,
            options,
          )
          && (
            !probeObservationProtocolRequired(loaded.manifest)
              || (
                request.role_identity
                && readRoleIdentityIntent(
                  loaded.paths,
                  eventId,
                )
                && request.role_identity.intent_sha256
                  === readRoleIdentityIntent(
                    loaded.paths,
                    eventId,
                  ).intent_sha256
              )
          )
          && pendingRegistrationIntent.request_sha256 === hashObject(request),
        'EVENT_ID_CONFLICT',
        `registration intent ${eventId} 已绑定不同请求`,
      );
      const authority = pendingRegistrationIntent.authorizer_authority;
      assertControl(
        authority && typeof authority.kind === 'string',
        'CORRUPT_STORE',
        `registration intent ${eventId} 缺 sealed authorizer authority`,
      );
      if (authority.kind === 'SESSION') {
        authorizeHistoricalActorCapability(
          loaded.snapshot,
          options.authorizerCapabilityFile,
          authority,
          {
            goalWide: authority.role === 'FOREMAN',
            taskId: options.taskId,
          },
        );
      } else {
        const suppliedFile = authority.kind === 'BOOTSTRAP'
          ? options.bootstrapCapabilityFile
          : options.foremanRecoveryCapabilityFile;
        const supplied = readCapabilityFile(
          suppliedFile,
          authority.capability_file,
        );
        assertControl(
          ['BOOTSTRAP', 'GOAL_RECOVERY'].includes(authority.kind)
            && hashesEqual(supplied.sha256, authority.capability_sha256),
          'CAPABILITY_INVALID',
          `registration intent ${eventId} sealed authority 不匹配`,
        );
      }
      const { assertNoPendingTaskOperations } = require('./pending-operations');
      assertNoPendingTaskOperations(root, options.goalId, options.taskId, {
        allowOperationKind: 'REGISTRATION',
        allowOperationId: eventId,
        allowRequestSha256: pendingRegistrationIntent.request_sha256,
      });
      assertControl(
        request.expected
          && request.expected.state_revision === state.state_revision
          && request.expected.control_epoch === loaded.control.epoch
          && request.expected.packet.revision === state.packet.revision
          && request.expected.packet.sha256 === state.packet.sha256
          && request.expected.base_head === state.base_head
          && request.expected.full_head === state.full_head,
        'REGISTRATION_INTENT_DIVERGED',
        `registration intent ${eventId} 后 task state 已漂移`,
      );
      const capability = readCapabilityFile(
        pendingRegistrationIntent.capability_file,
        pendingRegistrationIntent.capability_file,
      );
      assertControl(
        hashesEqual(
          capability.sha256,
          pendingRegistrationIntent.capability_sha256,
        ),
        'CORRUPT_STORE',
        `registration intent ${eventId} actor capability 漂移`,
      );
      const registration = {
        schema_version: 1,
        event_id: eventId,
        goal_id: options.goalId,
        task_id: options.taskId,
        type: 'REGISTER_ROLE',
        actor: {
          role: options.role,
          thread_id: options.threadId,
          host_id: hostId,
        },
        actor_sequence: 1,
        expected_state_revision: state.state_revision,
        control_epoch: loaded.control.epoch,
        packet: {
          revision: state.packet.revision,
          sha256: state.packet.sha256,
        },
        base_head: state.base_head,
        full_head: state.full_head,
        payload: {
          role: options.role,
          thread_id: options.threadId,
          host_id: hostId,
          attempt,
          lease_ms: request.lease_ms,
          status: request.status,
          launch_id: request.launch_id,
          task_nonce: pendingRegistrationIntent.task_nonce || null,
          ...(request.worker_bootstrap
            ? { worker_bootstrap: request.worker_bootstrap }
            : {}),
          ...(request.probe_observation
            ? { probe_observation: request.probe_observation }
            : {}),
          ...(request.role_identity
            ? { role_identity: request.role_identity }
            : {}),
          capability_sha256: capability.sha256,
          capability_file: capability.file,
          authorized_by: request.authorized_by,
        },
      };
      const validated = validateEvent(registration);
      validated.input_sha256 = hashObject(validated);
      validated.accepted_at = pendingRegistrationIntent.accepted_at;
      const nextState = applyEvent(state, validated, loaded.control.epoch);
      const durableCommit = writeAcceptedEvent(
        root,
        options.goalId,
        options.taskId,
        nextState.state_revision,
        validated,
        loaded.lastEventHashes[options.taskId] || null,
      );
      nextState.last_event.event_sha256 = durableCommit.event.event_sha256;
      let cacheDegraded = Boolean(durableCommit.headError);
      if (request.authorized_by.role === 'BOOTSTRAP') {
        reconcileBootstrapConsumption(root, loaded);
      }
      loaded.snapshot.tasks[options.taskId] = nextState;
      loaded.snapshot.generated_at = nowIso();
      try {
        writeProjections(loaded.paths, loaded.manifest, loaded.snapshot);
      } catch {
        cacheDegraded = true;
      }
      return {
        registered: true,
        idempotent: false,
        recovered_from_intent: true,
        cache_degraded: cacheDegraded,
        task: publicTaskState(nextState),
        session: publicSession(nextState.sessions[options.role]),
        actor_capability_file: capability.file,
        ...(pendingRegistrationIntent.task_nonce
          ? { task_nonce: pendingRegistrationIntent.task_nonce }
          : {}),
      };
    }
    assertFrozenInputs(cwd, loaded, options.taskId);
    const registrationAcceptedAt =
      pristineAuthorizationAt || nowIso();
    const workerBootstrap = registrationWorkerBootstrapBinding(
      loaded,
      state,
      options,
    );
    const probeObservation = registrationProbeObservationBinding(
      loaded,
      state,
      {
        ...options,
        acceptanceTime: registrationAcceptedAt,
      },
      eventId,
    );
    const roleIdentity = registrationRoleIdentityBinding(
      loaded,
      state,
      options,
      eventId,
      workerBootstrap,
    );
    const existingIsCurrent = existing
      && existing.registered_control_epoch === loaded.control.epoch
      && existing.registered_packet_revision === state.packet.revision
      && existing.registered_packet_sha256 === state.packet.sha256
      && existing.registered_full_head === state.full_head
      && existing.registered_task_cycle === state.task_cycle;
    if (existing && existingIsCurrent && existing.attempt === attempt && existing.thread_id === options.threadId && existing.host_id === hostId) {
      assertControl(
        existing.registration_event_id === eventId,
        'REGISTRATION_IDEMPOTENCY_MISMATCH',
        '重复 registration event_id 不一致',
      );
      authorizeSession(state, options.actorCapabilityFile, { role: options.role, threadId: options.threadId });
      const requestedLease = Number(options.leaseMs || 3600000);
      const currentLease = Date.parse(existing.lease_until) - Date.parse(existing.last_seen_at);
      assertControl((options.launchId || null) === existing.launch_id, 'REGISTRATION_IDEMPOTENCY_MISMATCH', '重复 registration launch_id 不一致');
      assertControl((options.status || 'active') === existing.status, 'REGISTRATION_IDEMPOTENCY_MISMATCH', '重复 registration status 不一致');
      assertControl(requestedLease === currentLease, 'REGISTRATION_IDEMPOTENCY_MISMATCH', '重复 registration lease_ms 不一致');
      assertControl(
        workerBootstrapRequestMatchesBinding(
          existing.worker_bootstrap || null,
          options,
        ),
        'REGISTRATION_IDEMPOTENCY_MISMATCH',
        '重复 registration worker bootstrap binding 不一致',
      );
      assertControl(
        probeObservationRequestMatchesBinding(
          existing.probe_observation || null,
          options,
        ),
        'REGISTRATION_IDEMPOTENCY_MISMATCH',
        '重复 registration probe observation binding 不一致',
      );
      return { registered: true, idempotent: true, session: publicSession(existing), actor_capability_file: existing.capability_file, task_nonce: existing.task_nonce || undefined };
    }
    const {
      assertNoPendingTaskOperations,
    } = require('./pending-operations');
    if (!preparedProbe) {
      assertNoPendingTaskOperations(root, options.goalId, options.taskId);
    }
    if (existing && options.role === 'FOREMAN' && options.bootstrapCapabilityFile) {
      assertControl(false, 'CAPABILITY_CONSUMED', 'bootstrap capability 只能签发首个 FOREMAN');
    }
    const bootstrapLineage = goalBootstrapForemanLineage(root, loaded);
    const bootstrapSpent = Boolean(loaded.meta.bootstrap_consumed_at) || bootstrapLineage.length > 0;
    let authorizedBy;
    let authorizerAuthority;
    let sharedGoalForeman = null;
    if (options.role === 'FOREMAN' && !existing && options.bootstrapCapabilityFile) {
      assertControl(!bootstrapSpent, 'CAPABILITY_CONSUMED', 'bootstrap capability 已由 Goal append-only FOREMAN lineage 消费');
      const bootstrap = readCapabilityFile(options.bootstrapCapabilityFile, loaded.meta.bootstrap_capability_file);
      assertControl(hashesEqual(bootstrap.sha256, loaded.meta.bootstrap_capability_sha256), 'CAPABILITY_INVALID', 'bootstrap capability 不匹配');
      authorizedBy = { role: 'BOOTSTRAP', capability_file: bootstrap.file };
      authorizerAuthority = {
        kind: 'BOOTSTRAP',
        capability_file: bootstrap.file,
        capability_sha256: bootstrap.sha256,
      };
    } else {
      const recoveringForeman = options.role === 'FOREMAN' && existing && state.recovery && state.recovery.role === 'FOREMAN';
      if (recoveringForeman) {
        const nonArchivedForemanProjections = Object.values(
          loaded.snapshot.tasks,
        ).filter((taskState) => (
          taskState.phase !== 'ARCHIVED'
            && taskState.sessions
            && taskState.sessions.FOREMAN
        ));
        assertControl(
          nonArchivedForemanProjections.length <= 1,
          'GOAL_FOREMAN_BATCH_REQUIRED',
          'Goal-wide FOREMAN 有多个活动 task projection；禁止单 task replacement，必须使用 recover-expired-foreman 批量恢复',
        );
        const recovery = readCapabilityFile(
          options.foremanRecoveryCapabilityFile,
          loaded.meta.foreman_recovery_capability_file,
        );
        assertControl(
          hashesEqual(recovery.sha256, loaded.meta.foreman_recovery_capability_sha256),
          'CAPABILITY_INVALID',
          'Goal FOREMAN recovery capability 不匹配',
        );
        authorizedBy = { role: 'GOAL_RECOVERY', capability_file: recovery.file };
        authorizerAuthority = {
          kind: 'GOAL_RECOVERY',
          capability_file: recovery.file,
          capability_sha256: recovery.sha256,
        };
      } else {
        const requiredRole = ['FOREMAN', 'CAPTAIN'].includes(options.role) ? 'FOREMAN' : 'CAPTAIN';
        assertControl(
          options.role !== 'FOREMAN' || !existing,
          'GOAL_FOREMAN_PROJECTION_REQUIRED',
          '已有 local FOREMAN 的 task 禁止普通 registration mint/替换；只能走 sealed recovery',
        );
        const authorizer = pristineOddRecoveryAuthorized
          ? historicalRegistrationAuthorizer(
            loaded,
            options,
            requiredRole,
            options.role === 'FOREMAN',
            pristineAuthorizationAt,
          )
          : options.role === 'FOREMAN'
            ? authorizeGoalSession(
              loaded.snapshot,
              options.authorizerCapabilityFile,
              {
                role: requiredRole,
                threadId: options.authorizerThreadId || null,
              },
            )
            : authorizeSession(
              state,
              options.authorizerCapabilityFile,
              {
                role: requiredRole,
                threadId: options.authorizerThreadId || null,
              },
            );
        if (options.role === 'FOREMAN' && !existing) {
          assertControl(
            authorizer.thread_id === options.threadId
              && authorizer.host_id === hostId
              && authorizer.attempt === attempt
              && (options.status || 'active') === authorizer.status,
            'GOAL_FOREMAN_PROJECTION_REQUIRED',
            '已有 Goal FOREMAN 时，新 task 只能投影同一 identity/attempt/status，禁止 mint 第二 authority',
          );
          sharedGoalForeman = authorizer;
        }
        authorizedBy = { role: authorizer.role, thread_id: authorizer.thread_id, host_id: authorizer.host_id, attempt: authorizer.attempt };
        authorizerAuthority = {
          kind: 'SESSION',
          source_task_id: authorizer.task_id || options.taskId,
          role: authorizer.role,
          thread_id: authorizer.thread_id,
          host_id: authorizer.host_id,
          attempt: authorizer.attempt,
          capability_file: authorizer.capability_file,
          capability_sha256: authorizer.capability_sha256,
        };
      }
    }
    if (!sharedGoalForeman) {
      assertFreshGoalRoleIdentity(
        loaded.snapshot,
        options.taskId,
        options.role,
        options.threadId,
      );
    }
    if (existing) {
      assertControl(
        (state.recovery && state.recovery.role === options.role) || existing.status === 'terminal',
        'ROLE_REPLACEMENT_REQUIRES_RECOVERY',
        `${options.role} 仍活跃，不能直接 higher-attempt 接管`
      );
    }
    const workerLaunchId = options.launchId || null;
    assertControl(!['DEV', 'REVIEW', 'RECEIPT'].includes(options.role) || workerLaunchId, 'LAUNCH_ID_REQUIRED', `${options.role} registration 必须带 --launch-id`);
    const registrationRequest = {
      schema_version: 1,
      event_id: eventId,
      goal_id: options.goalId,
      task_id: options.taskId,
      role: options.role,
      thread_id: options.threadId,
      host_id: hostId,
      attempt,
      lease_ms: Number(options.leaseMs || 3600000),
      status: options.status || 'active',
      launch_id: workerLaunchId,
      ...(workerBootstrap
        ? { worker_bootstrap: workerBootstrap }
        : {}),
      ...(probeObservation
        ? { probe_observation: probeObservation }
        : {}),
      ...(roleIdentity
        ? { role_identity: roleIdentity }
        : {}),
      authorized_by: authorizedBy,
      expected: {
        state_revision: state.state_revision,
        control_epoch: loaded.control.epoch,
        packet: {
          revision: state.packet.revision,
          sha256: state.packet.sha256,
        },
        base_head: state.base_head,
        full_head: state.full_head,
      },
    };
    const registrationRequestSha256 = hashObject(registrationRequest);
    const preparedRegistrationRequestSha256 = hashObject({
      request: registrationRequest,
      authorizer_authority: authorizerAuthority,
    });
    if (preparedProbe) {
      cleanupExactUnsealedPreparedIntent(
        loaded.paths.registrationIntents,
        'registration',
        eventId,
        preparedRegistrationRequestSha256,
        new RegExp(
          `^${options.role.toLowerCase()}-${attempt}-[0-9a-f]{24}\\.cap$`,
        ),
        `registration ${eventId}`,
      );
      assertNoPendingTaskOperations(root, options.goalId, options.taskId);
    }
    let registrationIntent = null;
    let capability;
    const taskNonce = workerLaunchId ? randomId('nonce') : null;
    const buildRegistrationEvent = (actorCapability) => ({
      schema_version: 1,
      event_id: eventId,
      goal_id: options.goalId,
      task_id: options.taskId,
      type: 'REGISTER_ROLE',
      actor: {
        role: options.role,
        thread_id: options.threadId,
        host_id: hostId,
      },
      actor_sequence: 1,
      expected_state_revision: state.state_revision,
      control_epoch: loaded.control.epoch,
      packet: {
        revision: state.packet.revision,
        sha256: state.packet.sha256,
      },
      base_head: state.base_head,
      full_head: state.full_head,
      payload: {
        role: options.role,
        thread_id: options.threadId,
        host_id: hostId,
        attempt,
        lease_ms: registrationRequest.lease_ms,
        status: registrationRequest.status,
        launch_id: registrationRequest.launch_id,
        task_nonce: taskNonce,
        ...(registrationRequest.worker_bootstrap
          ? {
            worker_bootstrap:
              registrationRequest.worker_bootstrap,
          }
          : {}),
        ...(registrationRequest.probe_observation
          ? {
            probe_observation:
              registrationRequest.probe_observation,
          }
          : {}),
        ...(registrationRequest.role_identity
          ? {
            role_identity:
              registrationRequest.role_identity,
          }
          : {}),
        capability_sha256: actorCapability.sha256,
        capability_file: actorCapability.file,
        authorized_by: authorizedBy,
        ...(sharedGoalForeman
          ? {
            goal_foreman_projection: true,
            projected_lease_until: sharedGoalForeman.lease_until,
          }
          : {}),
      },
    });

    // Registration intent publication is the first durable mutation. Run the
    // complete schema/FSM decision with a shape-valid placeholder first so a
    // routine PREMATURE/ILLEGAL request cannot strand a durable pending intent.
    const previewCapability = sharedGoalForeman
      ? {
        file: sharedGoalForeman.capability_file,
        sha256: sharedGoalForeman.capability_sha256,
      }
      : {
        file: path.join(
          loaded.paths.registrationIntents,
          eventId,
          'pending.cap',
        ),
        sha256: '0'.repeat(64),
      };
    const previewRegistration = validateEvent(
      buildRegistrationEvent(previewCapability),
    );
    previewRegistration.accepted_at = registrationAcceptedAt;
    applyEvent(state, previewRegistration, loaded.control.epoch);

    if (sharedGoalForeman) {
      capability = {
        file: sharedGoalForeman.capability_file,
        sha256: sharedGoalForeman.capability_sha256,
      };
    } else {
      const published = publishRegistrationIntent(
        cwd,
        loaded.paths,
        eventId,
        options.role,
        attempt,
        preparedRegistrationRequestSha256,
        (publishedCapability) => ({
          schema_version: 1,
          kind: 'REGISTRATION_INTENT',
          event_id: eventId,
          goal_id: options.goalId,
          task_id: options.taskId,
          request: registrationRequest,
          request_sha256: registrationRequestSha256,
          authorizer_authority: authorizerAuthority,
          prepared_request_sha256: preparedRegistrationRequestSha256,
          capability_file: publishedCapability.file,
          capability_sha256: publishedCapability.sha256,
          task_nonce: taskNonce,
          accepted_at: registrationAcceptedAt,
        }),
      );
      registrationIntent = published.intent;
      capability = published.capability;
      maybeInjectRecoveryBatchFault(
        cwd,
        'GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_INTENT_INSTALL',
        'TEST_FAULT_AFTER_REGISTRATION_INTENT',
        'injected failure after registration intent install',
      );
    }
    const capabilityMinted = !sharedGoalForeman;
    const registration = buildRegistrationEvent(capability);
    let durableCommit = null;
    let validated = null;
    try {
      validated = validateEvent(registration);
      const inputHash = hashObject(validated);
      validated.input_sha256 = inputHash;
      validated.accepted_at = registrationAcceptedAt;
      const nextState = applyEvent(state, validated, loaded.control.epoch);
      durableCommit = writeAcceptedEvent(root, options.goalId, options.taskId, nextState.state_revision, validated, loaded.lastEventHashes[options.taskId] || null);
      nextState.last_event.event_sha256 = durableCommit.event.event_sha256;
      let cache_degraded = Boolean(durableCommit.headError);
      if (authorizedBy.role === 'BOOTSTRAP') {
        reconcileBootstrapConsumption(root, loaded);
      }
      loaded.snapshot.tasks[options.taskId] = nextState;
      loaded.snapshot.generated_at = nowIso();
      try {
        writeProjections(loaded.paths, loaded.manifest, loaded.snapshot);
      } catch {
        cache_degraded = true;
      }
      return { registered: true, idempotent: false, cache_degraded, task: publicTaskState(nextState), session: publicSession(nextState.sessions[options.role]), actor_capability_file: capability.file, ...(taskNonce ? { task_nonce: taskNonce } : {}) };
    } catch (error) {
      let eventInstalled = Boolean(durableCommit);
      if (!eventInstalled && validated) {
        eventInstalled = acceptedEventFiles(root, options.goalId, options.taskId).some((file) => {
          try {
            const accepted = readJson(file, `accepted registration event ${path.basename(file)}`);
            return accepted.event_id === eventId && accepted.input_sha256 === validated.input_sha256;
          } catch {
            return false;
          }
        });
      }
      if (!eventInstalled && capabilityMinted && !registrationIntent) {
        fs.rmSync(capability.file, { force: true });
      }
      throw error;
    }
  }, {
    transactionKey: () => registrationTransactionKey(options),
    sameStableOperationMismatchCode: 'PREPARED_REQUEST_MISMATCH',
    sameStableOperationMismatchMessage:
      'registration stable operation 已绑定不同 prepared request',
    beforeGeneration: (transaction) => {
      oddRecoveryAuthorized = false;
      pristineOddRecoveryAuthorized = false;
      pristineAuthorizationAt = null;
      if (transaction.mode === 'FRESH') {
        const prevalidated = loadGoalStateUnlocked(
          root,
          options.goalId,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const prevalidatedState =
          prevalidated.snapshot.tasks[options.taskId];
        assertControl(
          prevalidatedState,
          'UNKNOWN_TASK',
          `未知 task ${options.taskId}`,
        );
        const stableRegistrationEventId =
          registrationStableEventId(options);
        const prevalidatedWorkerBootstrap =
          registrationWorkerBootstrapBinding(
          prevalidated,
          prevalidatedState,
          options,
          );
        if (
          goalEventIdOccurrences(
            prevalidated,
            stableRegistrationEventId,
          ).length === 0
        ) {
          registrationRoleIdentityBinding(
            prevalidated,
            prevalidatedState,
            options,
            stableRegistrationEventId,
            prevalidatedWorkerBootstrap,
          );
        }
      }
      oddRecoveryAuthorized = authorizeRegistrationOddRecovery(root, options);
      if (
        !oddRecoveryAuthorized
          && readSealedRootGenerationParity(root) === 'ODD'
      ) {
        const generation = readSealedRootGenerationSummary(root);
        assertControl(
          generation.parity === 'ODD'
            && typeof generation.updatedAt === 'string'
            && Number.isFinite(Date.parse(generation.updatedAt)),
          'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
          'registration pristine recovery 缺 sealed generation timestamp',
        );
        pristineAuthorizationAt = generation.updatedAt;
        pristineOddRecoveryAuthorized =
          authorizeRegistrationPristineOddRecovery(
            root,
            options,
            pristineAuthorizationAt,
          );
      }
    },
    authorizeOddRecovery: () => oddRecoveryAuthorized,
    authorizePristineOddRecovery: () => pristineOddRecoveryAuthorized,
    afterGenerationBeforeCallback: generationBoundaryFaultHook(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_GENERATION',
    ),
  });
}

function probeObservationRefreshRequest(options) {
  return {
    schema_version: 1,
    kind: 'PROBE_OBSERVATION_REFRESH',
    event_id: safeId(options.eventId, 'refresh event_id'),
    goal_id: safeId(options.goalId, 'goal_id'),
    task_id: safeId(options.taskId, 'task_id'),
    role: options.role,
    thread_id: safeId(options.threadId, 'thread_id'),
    host_id: safeId(options.hostId || 'local', 'host_id'),
    attempt: Number(options.attempt),
    expected_state_revision: Number(options.expectedStateRevision),
    expected_binding_sha256: normalizeHash(
      options.expectedBindingSha256,
      'expected probe observation binding sha256',
    ),
    probe_observation: probeObservationOptions(options),
  };
}

function refreshProbeObservation(cwd, options) {
  options.repositoryWorktree = fs.realpathSync(repoRoot(cwd));
  const root = controlRoot(cwd);
  const request = probeObservationRefreshRequest(options);
  assertControl(
    request.probe_observation,
    'CANARY_OBSERVATION_REQUIRED',
    'probe observation refresh 必须携带完整 fresh receipt request',
  );
  const requestSha256 = hashObject(request);
  return withLock(root, () => {
    const loaded = loadGoalStateUnlocked(root, request.goal_id);
    assertControl(
      probeObservationProtocolRequired(loaded.manifest),
      'PROBE_OBSERVATION_PROTOCOL_UNSUPPORTED',
      'manifest 未启用 probe observation refresh',
    );
    const state = loaded.snapshot.tasks[request.task_id];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${request.task_id}`);
    assertControl(
      goalControlEventOccurrences(loaded, request.event_id).length === 0,
      'EVENT_ID_CONFLICT',
      `refresh event id ${request.event_id} 已被 Goal control event 使用`,
    );
    const occurrences = goalEventIdOccurrences(
      loaded,
      request.event_id,
    );
    assertControl(
      occurrences.every(
        (occurrence) => occurrence.task_id === request.task_id,
      ),
      'EVENT_ID_CONFLICT',
      `refresh event id ${request.event_id} 已被其它 task 使用`,
    );
    if (occurrences.length > 0) {
      assertControl(
        occurrences.length === 1,
        'CORRUPT_STORE',
        `refresh event ${request.event_id} 重复`,
      );
      const accepted = acceptedGoalEvent(
        root,
        loaded,
        request.task_id,
        request.event_id,
      );
      assertControl(
        accepted
          && accepted.type === 'PROBE_OBSERVATION_REFRESHED'
          && accepted.payload.request_sha256 === requestSha256,
        'EVENT_ID_CONFLICT',
        `refresh event ${request.event_id} 已绑定不同 request`,
      );
      authorizeAcceptedEventRetry(
        loaded,
        request.task_id,
        accepted,
        options.actorCapabilityFile,
      );
      const current = loaded.snapshot.tasks[request.task_id]
        .sessions[request.role];
      assertControl(
        current
          && current.probe_observation
          && current.probe_observation.binding_sha256
            === accepted.payload.probe_observation.binding_sha256,
        'CORRUPT_STORE',
        'accepted refresh 与 current session binding 漂移',
      );
      return {
        refreshed: true,
        idempotent: true,
        event_id: request.event_id,
        session: publicSession(current),
      };
    }
    const {
      assertNoPendingTaskOperations,
    } = require('./pending-operations');
    assertNoPendingTaskOperations(
      root,
      request.goal_id,
      request.task_id,
    );
    assertFrozenInputs(cwd, loaded, request.task_id);
    assertControl(
      request.expected_state_revision === state.state_revision,
      'STALE_STATE_REVISION',
      'probe observation refresh state revision CAS 漂移',
    );
    const session = authorizeSession(
      state,
      options.actorCapabilityFile,
      {
        role: request.role,
        threadId: request.thread_id,
      },
    );
    assertControl(
      session.host_id === request.host_id
        && session.attempt === request.attempt,
      'CANARY_OBSERVATION_CROSS_IDENTITY',
      'probe observation refresh host/attempt 不匹配',
    );
    assertControl(
      session.probe_observation
        && session.probe_observation.binding_sha256
          === request.expected_binding_sha256,
      'CANARY_OBSERVATION_REFRESH_CAS_MISMATCH',
      'probe observation refresh old binding CAS 漂移',
    );
    const acceptedAt = nowIso();
    assertRequiredLiveProbeObservationBinding(
      loaded.manifest,
      session,
      'probe observation refresh previous binding',
      Date.parse(acceptedAt),
      {
        repositoryHead: git(
          options.invocationCwd || cwd,
          ['rev-parse', 'HEAD'],
        ),
        role: request.role,
        taskId: request.task_id,
      },
    );
    const refreshed = registrationProbeObservationBinding(
      loaded,
      state,
      {
        ...options,
        goalId: request.goal_id,
        taskId: request.task_id,
        role: request.role,
        threadId: request.thread_id,
        hostId: request.host_id,
        attempt: request.attempt,
        acceptanceTime: acceptedAt,
      },
      request.event_id,
    );
    assertControl(
      refreshed.binding_sha256 !== request.expected_binding_sha256
        && refreshed.accepted_at === acceptedAt,
      'CANARY_OBSERVATION_REFRESH_INVALID',
      'fresh probe observation 未替换 old binding',
    );
    const actorKey = actorSequenceKey({
      role: request.role,
      thread_id: request.thread_id,
      host_id: request.host_id,
    });
    const event = validateEvent({
      schema_version: 1,
      event_id: request.event_id,
      goal_id: request.goal_id,
      task_id: request.task_id,
      type: 'PROBE_OBSERVATION_REFRESHED',
      actor: {
        role: request.role,
        thread_id: request.thread_id,
        host_id: request.host_id,
      },
      actor_sequence: (state.actor_sequences[actorKey] || 0) + 1,
      expected_state_revision: state.state_revision,
      control_epoch: loaded.control.epoch,
      packet: {
        revision: state.packet.revision,
        sha256: state.packet.sha256,
      },
      base_head: state.base_head,
      full_head: state.full_head,
      payload: {
        role: request.role,
        attempt: request.attempt,
        previous_binding_sha256: request.expected_binding_sha256,
        probe_observation: refreshed,
        request_sha256: requestSha256,
      },
    });
    event.input_sha256 = hashObject(event);
    event.accepted_at = acceptedAt;
    const nextState = applyEvent(state, event, loaded.control.epoch);
    const durableCommit = writeAcceptedEvent(
      root,
      request.goal_id,
      request.task_id,
      nextState.state_revision,
      event,
      loaded.lastEventHashes[request.task_id] || null,
    );
    nextState.last_event.event_sha256 =
      durableCommit.event.event_sha256;
    loaded.snapshot.tasks[request.task_id] = nextState;
    loaded.snapshot.generated_at = nowIso();
    let cacheDegraded = Boolean(durableCommit.headError);
    try {
      writeProjections(
        loaded.paths,
        loaded.manifest,
        loaded.snapshot,
      );
    } catch {
      cacheDegraded = true;
    }
    return {
      refreshed: true,
      idempotent: false,
      cache_degraded: cacheDegraded,
      event_id: request.event_id,
      session: publicSession(nextState.sessions[request.role]),
    };
  }, {
    transactionKey: () => canonicalTransactionKey(
      'PROBE_OBSERVATION_REFRESH',
      {
        goal_id: request.goal_id,
        task_id: request.task_id,
      },
      request.event_id,
      requestSha256,
    ),
    sameStableOperationMismatchCode: 'EVENT_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      'probe observation refresh stable event 已绑定不同 request',
  });
}

function authorizeGoalControlOddRecovery(root, options) {
  const request = goalControlTransactionRequest(options);
  assertControl(
    request.reason.length > 0
      && request.instruction_ref.length > 0
      && Number.isSafeInteger(request.expected_epoch)
      && request.expected_epoch >= 0,
    'INVALID_ARGUMENT',
    'control odd recovery request 非法',
  );
  const loaded = loadOddRecoveryGoalState(root, request.goal_id);
  const matches = loaded.control.events.filter(
    (event) => event.event_id === request.event_id,
  );
  if (matches.length === 0) return false;
  assertControl(
    matches.length === 1,
    'CORRUPT_STORE',
    `control event id ${request.event_id} 在 append-only chain 中重复`,
  );
  const accepted = matches[0];
  assertControl(
    accepted.goal_id === request.goal_id
      && accepted.expected_epoch === request.expected_epoch
      && accepted.reason === request.reason
      && accepted.instruction_ref === request.instruction_ref
      && (
        request.thread_id === null
          || accepted.actor.thread_id === request.thread_id
      ),
    'EVENT_ID_CONFLICT',
    `control event id ${request.event_id} 不是 exact durable request`,
  );
  authorizeHistoricalActorCapability(
    loaded.snapshot,
    options.actorCapabilityFile,
    accepted.actor,
    { goalWide: true },
  );
  return true;
}

function authorizeGoalControlPristineOddRecovery(
  root,
  options,
  authorizationAt,
) {
  const request = goalControlTransactionRequest(options);
  assertControl(
    request.reason.length > 0
      && request.instruction_ref.length > 0
      && Number.isSafeInteger(request.expected_epoch)
      && request.expected_epoch >= 0,
    'INVALID_ARGUMENT',
    'control pristine recovery request 非法',
  );
  const loaded = loadOddRecoveryGoalState(root, request.goal_id);
  assertControl(
    loaded.control.events.every(
      (event) => event.event_id !== request.event_id,
    )
      && goalEventIdOccurrences(loaded, request.event_id).length === 0
      && goalMergeTargetReservations(
        root,
        request.goal_id,
        request.event_id,
      ).length === 0,
    'EVENT_ID_CONFLICT',
    `control event id ${request.event_id} 已有 durable operation`,
  );
  const { assertNoPendingTaskOperations } = require('./pending-operations');
  for (const task of loaded.manifest.tasks) {
    assertNoPendingTaskOperations(root, request.goal_id, task.id);
  }
  assertControl(
    request.expected_epoch === loaded.control.epoch,
    'STALE_CONTROL_EPOCH',
    `expected control epoch ${request.expected_epoch}，当前为 ${loaded.control.epoch}`,
  );
  historicalRegistrationAuthorizer(
    loaded,
    {
      ...options,
      taskId: loaded.manifest.tasks[0].id,
      authorizerCapabilityFile: options.actorCapabilityFile,
      authorizerThreadId: options.threadId || null,
    },
    'FOREMAN',
    true,
    authorizationAt,
  );
  return true;
}

function advanceControlEpoch(cwd, options) {
  const root = controlRoot(cwd);
  let oddRecoveryAuthorized = false;
  let pristineOddRecoveryAuthorized = false;
  let pristineAuthorizationAt = null;
  return withLock(root, () => {
    assertControl(
      typeof options.eventId === 'string' && options.eventId.length > 0,
      'ARG_REQUIRED',
      'control 必须显式提供 --event-id，供响应丢失后的历史精确重试',
    );
    const loaded = loadGoalStateUnlocked(root, options.goalId);
    const reason = typeof options.reason === 'string' ? options.reason.trim() : '';
    const instructionRef = typeof options.instructionRef === 'string' ? options.instructionRef.trim() : '';
    assertControl(reason, 'CONTROL_REASON_REQUIRED', '推进 control epoch 必须写 reason');
    assertControl(instructionRef, 'CONTROL_INSTRUCTION_REQUIRED', '推进 control epoch 必须引用用户指令或批准记录');
    const expectedEpoch = Number(options.expectedEpoch);
    assertControl(Number.isSafeInteger(expectedEpoch) && expectedEpoch >= 0, 'INVALID_ARGUMENT', 'expected-epoch 必须是非负整数');
    const eventId = options.eventId;
    safeId(eventId, 'control event_id');
    assertControl(
      goalMergeTargetReservations(root, options.goalId, eventId).length === 0,
      'EVENT_ID_RESERVED',
      `control event id ${eventId} 已由 append-only GitHub merge reservation 占用`,
    );
    const priorControlEvents = loaded.control.events.filter((event) => (
      event.event_id === eventId
    ));
    assertControl(
      goalEventIdOccurrences(loaded, eventId).length === 0,
      'EVENT_ID_CONFLICT',
      `control event id ${eventId} 已被 task event 使用`,
    );
    assertControl(
      priorControlEvents.length <= 1,
      'CORRUPT_STORE',
      `control event id ${eventId} 在 append-only chain 中重复`,
    );
    if (priorControlEvents.length === 1) {
      const previous = priorControlEvents[0];
      assertControl(
        previous.expected_epoch === expectedEpoch
          && previous.reason === reason
          && previous.instruction_ref === instructionRef
          && (!options.threadId || previous.actor.thread_id === options.threadId),
        'EVENT_ID_CONFLICT',
        `control event id ${eventId} 已被不同内容使用`
      );
      authorizeHistoricalActorCapability(
        loaded.snapshot,
        options.actorCapabilityFile,
        previous.actor,
        { goalWide: true },
      );
      return {
        goal_id: options.goalId,
        control_epoch: previous.to_epoch,
        current_control_epoch: loaded.control.epoch,
        event_id: eventId,
        idempotent: true,
        state: publicSnapshot(loaded.snapshot),
      };
    }
    const { assertNoPendingTaskOperations } = require('./pending-operations');
    for (const task of loaded.manifest.tasks) {
      assertNoPendingTaskOperations(root, options.goalId, task.id);
    }
    const actor = pristineOddRecoveryAuthorized
      ? historicalRegistrationAuthorizer(
        loaded,
        {
          ...options,
          taskId: loaded.manifest.tasks[0].id,
          authorizerCapabilityFile: options.actorCapabilityFile,
          authorizerThreadId: options.threadId || null,
        },
        'FOREMAN',
        true,
        pristineAuthorizationAt,
      )
      : authorizeGoalSession(
        loaded.snapshot,
        options.actorCapabilityFile,
        {
          role: 'FOREMAN',
          threadId: options.threadId || null,
        },
      );
    assertControl(expectedEpoch === loaded.control.epoch, 'STALE_CONTROL_EPOCH', `expected control epoch ${expectedEpoch}，当前为 ${loaded.control.epoch}`);
    const nextEpoch = expectedEpoch + 1;
    const baseEvent = {
      schema_version: 1,
      event_id: eventId,
      goal_id: options.goalId,
      from_epoch: expectedEpoch,
      to_epoch: nextEpoch,
      expected_epoch: expectedEpoch,
      reason,
      instruction_ref: instructionRef,
      actor: {
        role: 'FOREMAN',
        thread_id: actor.thread_id,
        host_id: actor.host_id,
        task_id: actor.task_id,
        attempt: actor.attempt,
      },
      accepted_at: pristineAuthorizationAt || nowIso(),
    };
    const event = sealChainedRecord(baseEvent, nextEpoch, loaded.control.lastEventHash);
    ensureDir(loaded.paths.controlEvents);
    atomicWriteJson(path.join(loaded.paths.controlEvents, `${String(nextEpoch).padStart(8, '0')}.json`), event);
    let cache_degraded = false;
    try {
      atomicWriteJson(loaded.paths.controlHead, sealedEventHead({
        schema_version: 1,
        goal_id: options.goalId,
        event_count: nextEpoch,
        control_epoch: nextEpoch,
        last_event_sha256: event.event_sha256,
        updated_at: event.accepted_at,
      }));
    } catch {
      cache_degraded = true;
    }
    let rebuilt = null;
    try {
      rebuilt = rebuildAndWriteUnlocked(root, options.goalId);
    } catch {
      cache_degraded = true;
    }
    return { goal_id: options.goalId, control_epoch: nextEpoch, event_id: event.event_id, event_sha256: event.event_sha256, idempotent: false, cache_degraded, state: rebuilt ? publicSnapshot(rebuilt) : null };
  }, {
    transactionKey: () => goalControlTransactionKey(options),
    beforeGeneration: () => {
      oddRecoveryAuthorized = false;
      pristineOddRecoveryAuthorized = false;
      pristineAuthorizationAt = null;
      oddRecoveryAuthorized = authorizeGoalControlOddRecovery(
        root,
        options,
      );
      if (
        !oddRecoveryAuthorized
          && readSealedRootGenerationParity(root) === 'ODD'
      ) {
        const generation = readSealedRootGenerationSummary(root);
        assertControl(
          generation.parity === 'ODD'
            && typeof generation.updatedAt === 'string'
            && Number.isFinite(Date.parse(generation.updatedAt)),
          'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
          'control pristine recovery 缺 sealed generation timestamp',
        );
        pristineAuthorizationAt = generation.updatedAt;
        pristineOddRecoveryAuthorized =
          authorizeGoalControlPristineOddRecovery(
            root,
            options,
            pristineAuthorizationAt,
          );
      }
    },
    authorizeOddRecovery: () => oddRecoveryAuthorized,
    authorizePristineOddRecovery: () => pristineOddRecoveryAuthorized,
    afterGenerationBeforeCallback: generationBoundaryFaultHook(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_CONTROL_GENERATION',
    ),
  });
}

function nextTasks(cwd, goalId) {
  return loadGoalStateReadOnly(cwd, goalId, (loaded) => {
    assertFrozenInputs(cwd, loaded);
    const {
      listPendingGoalRegistrationIntents,
      listPendingTaskOperations,
    } = require('./pending-operations');
    const goalRegistrationIntents = listPendingGoalRegistrationIntents(
      controlRoot(cwd),
      loaded.manifest.goal_id,
    );
    const goalPendingOperations = [
      ...loaded.pendingForemanRecoveryBatches.map((batch) => (
        publicPendingOperation({
          kind: 'FOREMAN_RECOVERY_BATCH',
          operation_id: batch.root_recovery_id,
          request_sha256: batch.intent.request_sha256,
        }, 'GOAL')
      )),
      ...goalRegistrationIntents.map((intent) => (
        publicPendingOperation({
          kind: 'REGISTRATION',
          operation_id: intent.event_id,
          request_sha256: intent.request_sha256,
          task_id: intent.task_id,
        }, 'GOAL')
      )),
    ];
    const pendingByTask = new Map(
      loaded.manifest.tasks.map((task) => [
        task.id,
        listPendingTaskOperations(
          controlRoot(cwd),
          loaded.manifest.goal_id,
          task.id,
        ),
      ]),
    );
    const terminalPhases = new Set(['MERGED_TO_MAIN', 'ARCHIVED']);
    const activeTasks = loaded.manifest.tasks.filter((task) => {
      const phase = loaded.snapshot.tasks[task.id].phase;
      return phase !== 'QUEUED' && !terminalPhases.has(phase);
    });
    const rows = loaded.manifest.tasks.map((task) => {
      const state = loaded.snapshot.tasks[task.id];
      const dependencyStates = task.dependencies.map((id) => ({ id, phase: loaded.snapshot.tasks[id].phase }));
      const dependencyTerminalPhases = task.p1
        ? ['ARCHIVED']
        : ['MERGED_TO_MAIN', 'ARCHIVED'];
      const dependenciesReady = dependencyStates.every(
        (dependency) => dependencyTerminalPhases.includes(dependency.phase),
      );
      const reasons = [];
      if (state.phase !== 'QUEUED') reasons.push(`phase=${state.phase}`);
      if (!dependenciesReady) reasons.push(`dependencies=${dependencyStates.filter((dependency) => !dependencyTerminalPhases.includes(dependency.phase)).map((dependency) => `${dependency.id}:${dependency.phase}`).join(',')}`);
      if (state.holds.length) reasons.push(`holds=${state.holds.map((hold) => hold.kind).join(',')}`);
      if (state.recovery) reasons.push(`recovery=${state.recovery.role}`);
      if (state.reconcile_required) reasons.push(`control-reconcile=${state.reconcile_required.to_epoch}`);
      if (goalRegistrationIntents.length > 0) {
        reasons.push(
          `goal-registration-pending=${goalRegistrationIntents
            .map((intent) => `${intent.task_id}:${intent.event_id}`)
            .join(',')}`,
        );
      }
      if (loaded.pendingForemanRecoveryBatches.length > 0) {
        reasons.push(
          `goal-recovery-pending=${
            loaded.pendingForemanRecoveryBatches[0].root_recovery_id
          }`,
        );
      }
      const pending = pendingByTask.get(task.id);
      if (pending.length > 0) {
        reasons.push(
          `pending=${pending
            .map((operation) => (
              `${operation.kind}:${pendingOperationDisplayId(operation)}`
            ))
            .join(',')}`,
        );
      }
      const activeConflicts = activeTasks.filter((active) => active.id !== task.id && tasksConflict(task, active));
      if (state.phase === 'QUEUED' && activeConflicts.length) reasons.push(`active-conflicts=${activeConflicts.map((item) => item.id).join(',')}`);
      const actionProjection = taskActionProjection(
        loaded.paths,
        state,
        loaded.manifest.goal_id,
        task,
        {
          readOnly: true,
          manifest: loaded.manifest,
          goalSnapshot: loaded.snapshot,
        },
      );
      return {
        task_id: task.id,
        eligible: reasons.length === 0,
        reasons,
        integration_order: task.integration_order,
        ...(task.p1
          ? {
            required_start_head: mechanicalP1RequiredStartHead(loaded, task),
            dependency_gate: task.p1.dependency_gate,
          }
          : {}),
        launch_scope: actionProjection.launch_scope,
        ...(actionProjection.launch_error_code
          ? { launch_error_code: actionProjection.launch_error_code }
          : {}),
        operational_scope: actionProjection.launch_scope,
        next_actions: actionProjection.actions,
        maintenance_actions: actionProjection.maintenance_actions,
        pending_operations: actionProjection.pending_operations || [],
      };
    });
    const eligibleRows = rows.filter((row) => row.eligible).sort((left, right) => left.integration_order - right.integration_order);
    const batch = [];
    for (const row of eligibleRows) {
      const task = loaded.manifest.tasks.find((candidate) => candidate.id === row.task_id);
      const conflicting = batch.find((selected) => tasksConflict(task, loaded.manifest.tasks.find((candidate) => candidate.id === selected.task_id)));
      if (conflicting) row.deferred_by_conflict = conflicting.task_id;
      else batch.push(row);
    }
    const pendingOperations = new Map(
      goalPendingOperations.map((operation) => [
        pendingOperationKey(operation),
        operation,
      ]),
    );
    for (const row of rows) {
      for (const operation of row.pending_operations) {
        const key = pendingOperationKey(operation);
        if (!pendingOperations.has(key)) pendingOperations.set(key, operation);
      }
    }
    return {
      goal_id: goalId,
      ...(loaded.meta.goal_input_head
        ? {
          goal_input_head: loaded.meta.goal_input_head,
          goal_input_source: loaded.meta.goal_input_source,
        }
        : {}),
      control_epoch: loaded.control.epoch,
      pending_operations: [...pendingOperations.values()],
      batch,
      eligible: eligibleRows,
      tasks: rows,
    };
  }, { allowIncompleteRecoveryRead: true });
}

function tasksConflict(left, right) {
  const intersects = (first, second) => first.some((value) => second.includes(value));
  if (intersects(left.conflict_domains || [], right.conflict_domains || [])) return true;
  const normalizeWrite = (value) => {
    const text = String(value);
    const wildcardIndex = text.search(/[*?\[]/);
    return (wildcardIndex === -1 ? text : text.slice(0, wildcardIndex)).replace(/\/$/, '');
  };
  for (const leftPath of left.expected_write_set || []) {
    for (const rightPath of right.expected_write_set || []) {
      const a = normalizeWrite(leftPath);
      const b = normalizeWrite(rightPath);
      if (a && b && (a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`))) return true;
    }
  }
  for (const leftResource of left.resource_requirements || []) {
    for (const rightResource of right.resource_requirements || []) {
      if (leftResource.kind === rightResource.kind && leftResource.id === rightResource.id
        && (leftResource.access === 'EXCLUSIVE' || rightResource.access === 'EXCLUSIVE')) return true;
    }
  }
  return false;
}

function doctor(cwd, goalId, now = null) {
  return loadGoalStateReadOnly(cwd, goalId, (loaded) => {
    const observedNow = now === null ? runtimeNowMilliseconds() : now;
    const findings = [];
    const notices = [];
    const worktree = repoRoot(cwd);
    const goalRecoveryScope = foremanRecoveryScope(loaded);
    const activeForemanRecoveryBindings = goalRecoveryScope.tasks.filter(
      (binding) => binding.phase !== 'ARCHIVED' && binding.foreman,
    );
    const foremanRecoverySourceAttempt =
      activeForemanRecoveryBindings.length > 0
        ? Math.max(...activeForemanRecoveryBindings.map(
          (binding) => binding.foreman.attempt,
        ))
        : Math.max(
          -1,
          ...goalRecoveryScope.tasks
            .filter((binding) => binding.foreman)
            .map((binding) => binding.foreman.attempt),
        );
    const foremanRecoverySourceTaskIds = goalRecoveryScope.tasks
      .filter((binding) => (
        binding.foreman
          && binding.foreman.attempt === foremanRecoverySourceAttempt
      ))
      .map((binding) => binding.task_id);
    assertCoherentGoalForemanLineage(loaded.snapshot);
    const goalRootForemanRecoveryEligible =
      foremanRecoverySourceTaskIds.length > 0
      && foremanRecoverySourceTaskIds.every((taskId) => {
        const state = loaded.snapshot.tasks[taskId];
        const foreman = state && state.sessions.FOREMAN;
        return foremanRootRecoveryStatusEligible(state, foreman)
          && Date.parse(foreman.lease_until) <= observedNow;
      });
    const goalNormalRecoveryPath = goalNormalForemanRecoveryPath(
      loaded.snapshot,
      foremanRecoverySourceTaskIds,
      observedNow,
    );
    try {
      assertFrozenInputs(cwd, loaded);
    } catch (error) {
      findings.push({
        severity: 'ERROR',
        code: error.code || 'FROZEN_INPUT_INVALID',
        role: 'CONTROL',
        detail: error.message,
      });
    }
    const goalForemanReplicaLive = (session) => {
      try {
        assertUsableGoalForemanReplica(loaded.snapshot, session, observedNow);
        return true;
      } catch {
        return false;
      }
    };
    if (loaded.pendingForemanRecoveryBatches.length > 0) {
      const pending = loaded.pendingForemanRecoveryBatches[0];
      findings.push({
        severity: 'ERROR',
        code: 'RECOVERY_BATCH_INCOMPLETE',
        role: 'GOAL_RECOVERY',
        detail: `只允许 exact retry --event-id ${pending.root_recovery_id}`,
      });
    }
    for (const [name, protocol] of Object.entries(loaded.manifest.protocol || {})) {
      const file = path.resolve(worktree, protocol.path);
      if (!fs.existsSync(file) || hashFile(file) !== protocol.sha256) {
        findings.push({ severity: 'ERROR', code: 'PROTOCOL_DRIFT', detail: `${name}:${protocol.path}` });
      }
    }
    for (const task of loaded.manifest.tasks) {
      const state = loaded.snapshot.tasks[task.id];
      const { listPendingTaskOperations } = require('./pending-operations');
      for (const operation of listPendingTaskOperations(
        controlRoot(cwd),
        loaded.manifest.goal_id,
        task.id,
      )) {
        findings.push({
          task_id: task.id,
          severity: 'ERROR',
          code: 'TASK_OPERATION_PENDING',
          role: 'CONTROL',
          detail: operation.stable_id_unavailable
            ? `${operation.kind}:${pendingOperationDisplayId(operation)};`
              + ' 使用首次调用前持久化的原 stable ID exact retry'
            : `${operation.kind}:${pendingOperationDisplayId(operation)};`
              + ' 使用同一 stable ID exact retry 完成该 durable operation',
        });
      }
      const packetFile = path.resolve(worktree, state.packet.path);
      if (!fs.existsSync(packetFile) || hashFile(packetFile) !== state.packet.sha256) {
        findings.push({ task_id: task.id, severity: 'ERROR', code: 'PACKET_DRIFT', detail: state.packet.path });
      }
      if (state.reconcile_required) {
        findings.push({ task_id: task.id, severity: 'ERROR', code: 'CONTROL_RECONCILE_REQUIRED', role: 'FOREMAN', detail: `epoch ${state.reconcile_required.to_epoch}` });
      }
      for (const hold of state.holds) {
        if (hold.hard) findings.push({ task_id: task.id, severity: 'ERROR', code: hold.kind, role: 'FOREMAN', detail: hold.reason || hold.hold_id });
      }
      if (
        isSourceCheckpointHoldIntent(
          controlRoot(cwd),
          state,
          loaded.manifest.goal_id,
        )
        && sourceCheckpointHoldMaintenanceActions(
          loaded.paths,
          state,
          loaded.manifest.goal_id,
          task,
        ).length === 0
      ) {
        findings.push({
          task_id: task.id,
          severity: 'ERROR',
          code: 'SOURCE_CHECKPOINT_HOLD_REVALIDATION_BLOCKED',
          role: 'FOREMAN',
          detail:
            'sealed source-checkpoint intent no longer matches the current canonical/candidate lineage; runtime rotation remains forbidden',
        });
      }
      if (
        state.holds.length === 1
          && state.holds[0].kind === 'ENV_IDENTITY_INCIDENT'
          && state.holds[0].hard === true
          && !isRuntimeRotationHoldLane(
            state,
            state.sessions[expectedRoleForPhase(state.phase)],
          )
          && classifyLaunchIdentityHold(
            controlRoot(cwd),
            state,
            loaded.manifest.goal_id,
          ) === LAUNCH_HOLD_CLASSIFICATION.UNKNOWN
      ) {
        findings.push({
          task_id: task.id,
          severity: 'ERROR',
          code: 'LAUNCH_IDENTITY_HOLD_UNCLASSIFIED',
          role: 'FOREMAN',
          detail:
            'ENV identity hold 无法机械归类为 SOURCE_ONLY 或 RUNTIME_IDENTITY；两个恢复 lane 均保持关闭',
        });
      }
      for (const session of Object.values(state.sessions)) {
        if (['systemError', 'lost'].includes(session.status)) {
          findings.push({ task_id: task.id, severity: 'ERROR', code: 'RECOVERY_REQUIRED', role: session.role, detail: `session status=${session.status}` });
        } else if (
          ['active', 'idle'].includes(session.status)
          && Date.parse(session.lease_until) <= observedNow
          && !(session.role === 'FOREMAN' && goalForemanReplicaLive(session))
        ) {
          findings.push({ task_id: task.id, severity: 'ERROR', code: 'ROLE_LEASE_EXPIRED', role: session.role, detail: `lease expired ${session.lease_until}` });
        }
        if (session.launch_id && ['active', 'idle'].includes(session.status)) {
          try {
            requiredWorkerBootstrapBinding(
              loaded.manifest,
              session,
              session.role,
            );
          } catch (error) {
            findings.push({
              task_id: task.id,
              severity: 'ERROR',
              code: error.code || 'INVALID_LAUNCH',
              role: session.role,
              detail: error.message,
            });
            continue;
          }
          const operationalScope = sessionOperationalScope(state, session.role);
          const launchFile = path.join(loaded.paths.dir, 'launches', task.id, `${session.launch_id}.json`);
          if (operationalScope !== 'FULL') {
            findings.push({
              task_id: task.id,
              severity: 'ERROR',
              code: operationalScope === 'RECOVERY_BLOCKED'
                ? 'RECOVERY_HANDOFF_REQUIRED'
                : 'RECOVERY_PROMOTION_REQUIRED',
              role: session.role,
              detail: `${session.launch_id}: operational_scope=${operationalScope}`,
            });
            continue;
          }
          if (!fs.existsSync(launchFile)) {
            findings.push({
              task_id: task.id,
              severity: 'ERROR',
              code: isRuntimeRotationHoldLane(state, session)
                ? 'RUNTIME_PREFLIGHT_REQUIRED'
                : 'LAUNCH_NOT_VALIDATED',
              role: session.role,
              detail: session.launch_id,
            });
          } else {
            try {
              const launch = validateLaunchManifest(readJson(launchFile, `launch ${session.launch_id}`));
              const launchWorktree = fs.realpathSync(launch.repository.worktree);
              assertLaunchRuntimeIncarnation(session, launch);
              const predecessor = predecessorLaunchForRotation(
                loaded,
                state,
                session,
              );
              if (predecessor) {
                assertRotationSuccessorLaunch(
                  predecessor,
                  session,
                  launch,
                );
              }
              assertControl(
                launch.goal_id === loaded.manifest.goal_id
                  && launch.task_id === task.id
                  && launch.role === session.role
                  && launch.thread.id === session.thread_id
                  && launch.thread.host_id === session.host_id
                  && launch.execution.task_nonce === session.task_nonce,
                'LAUNCH_IDENTITY_MISMATCH',
                'launch/session identity mismatch',
              );
              assertControl(
                launch.state_revision === session.registered_state_revision
                  && launch.control_epoch === loaded.control.epoch
                  && launch.packet.revision === state.packet.revision
                  && normalizePacketHash(launch.packet.sha256) === state.packet.sha256
                  && launch.repository.base_head === state.base_head,
                'STALE_LAUNCH',
                'launch binding 陈旧',
              );
              assertControl(launch.repository.worktree === launchWorktree, 'WORKTREE_MISMATCH', 'launch worktree 不是 canonical path');
              assertProjectedWorkerBootstrapIdentity(
                state,
                session,
                launch,
                launchWorktree,
              );
              assertControl(launch.repository.branch === git(launchWorktree, ['branch', '--show-current']), 'BRANCH_MISMATCH', 'launch branch 与 worktree 不一致');
              const actualLaunchHead = git(launchWorktree, ['rev-parse', 'HEAD']);
              if (session.role === 'DEV') {
                const exactRuntimeHead = assertDevLaunchHead(
                  launchWorktree,
                  state,
                  session,
                  launch,
                  actualLaunchHead,
                );
                if (
                  !exactRuntimeHead
                    && state.holds.length === 0
                ) {
                  const runtimeBinding = sourceRuntimeBindingStatus(
                    launchWorktree,
                    launch,
                  );
                  assertControl(
                    !['BROWSER', 'ELECTRON'].includes(
                      launch.execution.target.kind,
                    )
                      && runtimeBinding.lockfile.matches,
                    'FRESH_RUNTIME_RECOVERY_REQUIRED',
                    runtimeBinding.lockfile.matches
                      ? `${launch.execution.target.kind} DEV source HEAD 前进后必须走 fresh worker/runtime recovery`
                      : 'DEV source HEAD 前进时 pnpm lockfile binding 已变化；'
                        + '必须走 fresh worker/runtime recovery',
                  );
                  assertControl(
                    trustedCandidatePreflight(
                      loaded.paths,
                      state,
                      loaded.manifest.goal_id,
                      task,
                      actualLaunchHead,
                    ),
                    'SOURCE_CHECKPOINT_PREFLIGHT_REQUIRED',
                    `DEV candidate ${actualLaunchHead} 缺 source checkpoint PREFLIGHT`,
                  );
                }
              } else {
                assertControl(
                  launch.repository.full_head === state.full_head
                    && actualLaunchHead === state.full_head,
                  'STALE_HEAD',
                  `${session.role} launch/worktree HEAD 与 task full HEAD 不一致`,
                );
              }
              const { verifyLaunchResourceRequirementsUnlocked } = require('./resources');
              verifyLaunchResourceRequirementsUnlocked(
                controlRoot(cwd),
                task,
                launch,
                state,
                {
                  repairHeads: false,
                  allowRuntimeRotationHold: isRuntimeRotationHoldLane(
                    state,
                    session,
                    launch,
                  ),
                },
              );
            } catch (error) {
              findings.push({ task_id: task.id, severity: 'ERROR', code: error.code || 'ENV_IDENTITY_INCIDENT_REQUIRED', role: session.role, detail: `${error.code || 'INVALID_LAUNCH'}: ${error.message}` });
            }
          }
        }
      }
      if (
        goalRootForemanRecoveryEligible
          && foremanRecoverySourceTaskIds.includes(task.id)
          && !goalNormalRecoveryPath.available
      ) {
        findings.push({
          task_id: task.id,
          severity: 'ERROR',
          code: 'FOREMAN_RECOVERY_DEADLOCK',
          role: 'GOAL_RECOVERY',
          detail: `Goal-scope ${goalRecoveryScope.scope_sha256}；运行 goalctl help recover-expired-foreman，以同一 --event-id 完成全部 target`,
        });
      }
      const expectedRole = expectedRoleForPhase(state.phase);
      if (state.recovery) {
        findings.push({ task_id: task.id, severity: 'ERROR', code: 'RECOVERY_REQUIRED', role: state.recovery.role, detail: state.recovery.reason });
        continue;
      }
      if (Array.isArray(state.recovery_backlog) && state.recovery_backlog.length > 0) {
        findings.push({
          task_id: task.id,
          severity: 'ERROR',
          code: 'RECOVERY_BACKLOG_REQUIRED',
          role: 'CAPTAIN',
          detail: state.recovery_backlog.map((item) => item.role).join(','),
        });
        continue;
      }
      if (!expectedRole || ['MERGED_TO_MAIN', 'ARCHIVED'].includes(state.phase)) continue;
      const session = state.sessions[expectedRole];
      if (!session) {
        findings.push({ task_id: task.id, severity: 'ERROR', code: 'ROLE_NOT_REGISTERED', role: expectedRole, detail: `phase ${state.phase} 需要 ${expectedRole}` });
        continue;
      }
    }
    return {
      goal_id: goalId,
      healthy: findings.length === 0,
      checked_at: new Date(observedNow).toISOString(),
      findings,
      notices,
    };
  }, { allowIncompleteRecoveryRead: true });
}

function resumeCapsule(cwd, goalId, taskId, role, threadId) {
  return loadGoalStateReadOnly(cwd, goalId, (loaded) => {
    const worktree = assertFrozenInputs(cwd, loaded, taskId);
    const state = loaded.snapshot.tasks[taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
    const session = state.sessions[role];
    assertControl(session, 'UNREGISTERED_ACTOR', `${role} 尚未登记 session`);
    assertControl(session.thread_id === threadId, 'WRONG_ACTOR_THREAD', `${role} thread 与登记值不一致`);
    if (role === 'FOREMAN') {
      assertControl(
        ['active', 'idle', 'systemError'].includes(session.status),
        'RECOVERY_REQUIRED',
        `${role} session status=${session.status}`,
      );
      assertUsableGoalForemanReplica(
        loaded.snapshot,
        session,
        runtimeNowMilliseconds(),
      );
    } else {
      assertControl(['active', 'idle'].includes(session.status), 'RECOVERY_REQUIRED', `${role} session status=${session.status}`);
      assertControl(Date.parse(session.lease_until) > runtimeNowMilliseconds(), 'ROLE_LEASE_EXPIRED', `${role} lease 已于 ${session.lease_until} 过期`);
    }
    requiredWorkerBootstrapBinding(
      loaded.manifest,
      session,
      role,
    );
    const manifestTask = loaded.manifest.tasks.find(
      (candidate) => candidate.id === taskId,
    );
    const actionProjection = taskActionProjection(
      loaded.paths,
      state,
      loaded.manifest.goal_id,
      manifestTask,
      {
        readOnly: true,
        manifest: loaded.manifest,
        goalSnapshot: loaded.snapshot,
      },
    );
    const actions = actionProjection.actions.filter(
      (action) => action.actor_role.split('|').includes(role),
    );
    const pendingOperations = actionProjection.pending_operations || [];
    const maintenanceActions = actionProjection.maintenance_actions.filter(
      (action) => action.actor_role === role,
    );
    let launch = null;
    let launchFile = null;
    const launchScope = sessionOperationalScope(state, role);
    const reportedLaunchScope = actionProjection.launch_scope;
    const actualHead = git(worktree, ['rev-parse', 'HEAD']);
    if (launchScope !== 'FULL') {
      assertControl(role === 'DEV' && session.recovered_from, 'RECOVERY_SCOPE_VIOLATION', `${role} scope=${launchScope}`);
      return {
        role,
        goal_id: goalId,
        task_id: taskId,
        state_revision: state.state_revision,
        control_epoch: loaded.control.epoch,
        packet_revision: state.packet.revision,
        packet_sha256: state.packet.sha256,
        phase: state.phase,
        holds: state.holds.map((hold) => `${hold.kind}:${hold.hold_id}`),
        full_head: state.full_head,
        worktree_head: actualHead,
        launch_id: session.launch_id || null,
        launch_file: null,
        launch_scope: reportedLaunchScope,
        operational_scope: launchScope,
        pending_operations: pendingOperations,
        ...(session.recovery_handoff ? { recovery_handoff: publicSession(session).recovery_handoff } : {}),
        resource_leases: [],
        protocols: Object.fromEntries(Object.entries(loaded.manifest.protocol || {}).map(([key, value]) => [key, `${value.path}@${value.sha256}`])),
        allowed_actions: actions,
        maintenance_actions: maintenanceActions,
        forbidden: '源码修改/测试/commit/push/Preview/login/TIM/UI/environment/resource use/DEV_READY；等待 CAPTAIN 完成 isolated handoff 与 fresh preflight promotion',
      };
    }
    if (session.launch_id) {
      launchFile = path.join(loaded.paths.dir, 'launches', taskId, `${session.launch_id}.json`);
      if (
        !fs.existsSync(launchFile)
          && isRuntimeRotationHoldLane(state, session)
      ) {
        const predecessor = predecessorLaunchForRotation(
          loaded,
          state,
          session,
        );
        return {
          role,
          goal_id: goalId,
          task_id: taskId,
          state_revision: state.state_revision,
          control_epoch: loaded.control.epoch,
          packet_revision: state.packet.revision,
          packet_sha256: state.packet.sha256,
          phase: state.phase,
          holds: state.holds.map((hold) => `${hold.kind}:${hold.hold_id}`),
          full_head: state.full_head,
          worktree_head: actualHead,
          launch_id: session.launch_id,
          launch_file: null,
          launch_scope: 'RUNTIME_PREFLIGHT_REQUIRED',
          operational_scope: launchScope,
          pending_operations: pendingOperations,
          runtime_rotation: publicProjection(
            session.last_runtime_rotation,
          ),
          resource_leases: [...predecessor.resource_leases],
          protocols: Object.fromEntries(
            Object.entries(loaded.manifest.protocol || {})
              .map(([key, value]) => [
                key,
                `${value.path}@${value.sha256}`,
              ]),
          ),
          allowed_actions: actions,
          maintenance_actions: maintenanceActions,
          forbidden: 'worker verdict/业务推进/旧 launch 或旧端口复用；先用 successor launch ID + fresh web/proxy port 执行 launch-template 与 preflight，hold 仅由 FOREMAN 另行解除',
        };
      }
      assertControl(fs.existsSync(launchFile), 'LAUNCH_NOT_VALIDATED', `active session launch ${session.launch_id} 尚未通过 preflight`);
      launch = validateLaunchManifest(readJson(launchFile, `launch ${session.launch_id}`));
      assertControl(launch.goal_id === goalId && launch.task_id === taskId, 'LAUNCH_IDENTITY_MISMATCH', 'persisted launch goal/task 不一致');
      assertControl(launch.launch_id === session.launch_id && launch.role === role, 'LAUNCH_ID_MISMATCH', 'persisted launch 与 active session 不一致');
      assertControl(launch.thread.id === threadId && launch.thread.host_id === session.host_id, 'WRONG_ACTOR_THREAD', 'persisted launch thread 与 active session 不一致');
      assertLaunchRuntimeIncarnation(session, launch);
      const predecessor = predecessorLaunchForRotation(
        loaded,
        state,
        session,
      );
      if (predecessor) {
        assertRotationSuccessorLaunch(predecessor, session, launch);
      }
      assertControl(launch.control_epoch === loaded.control.epoch && !state.reconcile_required, 'STALE_CONTROL_EPOCH', 'persisted launch control epoch 陈旧');
      assertControl(launch.packet.revision === state.packet.revision && normalizePacketHash(launch.packet.sha256) === state.packet.sha256, 'STALE_PACKET', 'persisted launch packet 陈旧');
      assertControl(launch.state_revision === session.registered_state_revision, 'STALE_STATE_REVISION', 'persisted launch registration revision 陈旧');
      const canonicalWorktree = fs.realpathSync(worktree);
      assertProjectedWorkerBootstrapIdentity(
        state,
        session,
        launch,
        canonicalWorktree,
      );
      assertControl(
        launch.repository.worktree === canonicalWorktree
          && fs.realpathSync(launch.repository.worktree) === canonicalWorktree
          && fs.realpathSync(launch.thread.cwd) === canonicalWorktree,
        'WORKTREE_MISMATCH',
        'resume 必须从 persisted launch 绑定的 canonical worktree 运行',
      );
      assertControl(
        launch.repository.branch === git(worktree, ['branch', '--show-current']),
        'BRANCH_MISMATCH',
        'resume 当前 branch 与 persisted launch 不一致',
      );
      assertDevLaunchHead(worktree, state, session, launch, actualHead);
      assertControl(launch.execution.task_nonce === session.task_nonce, 'TASK_NONCE_MISMATCH', 'persisted launch task_nonce 不匹配');
      const { verifyLaunchResourceRequirementsReadOnly } = require('./resources');
      verifyLaunchResourceRequirementsReadOnly(
        cwd,
        manifestTask,
        launch,
        state,
        {
          allowRuntimeRotationHold: isRuntimeRotationHoldLane(
            state,
            session,
            launch,
          ),
        },
      );
    }
    if (role === 'DEV' && state.phase === 'DEV_ACTIVE') {
      git(worktree, ['merge-base', '--is-ancestor', state.full_head, actualHead]);
    } else if (['DEV', 'REVIEW', 'RECEIPT'].includes(role)) {
      assertControl(actualHead === state.full_head, 'STALE_HEAD', `worktree HEAD ${actualHead} 与控制面 ${state.full_head} 不一致`);
    }
    const protocols = Object.fromEntries(Object.entries(loaded.manifest.protocol || {}).map(([key, value]) => [key, `${value.path}@${value.sha256}`]));
    return {
      role,
      goal_id: goalId,
      task_id: taskId,
      state_revision: state.state_revision,
      control_epoch: loaded.control.epoch,
      packet_revision: state.packet.revision,
      packet_sha256: state.packet.sha256,
      phase: state.phase,
      holds: state.holds.map((hold) => `${hold.kind}:${hold.hold_id}`),
      full_head: state.full_head,
      worktree_head: actualHead,
      launch_id: session.launch_id || null,
      launch_file: launchFile,
      launch_scope: reportedLaunchScope,
      operational_scope: launchScope,
      pending_operations: pendingOperations,
      resource_leases: launch ? launch.resource_leases : [],
      protocols,
      allowed_actions: actions,
      maintenance_actions: maintenanceActions,
      forbidden: role === 'FOREMAN'
          ? '业务代码/测试/详细 finding'
          : role === 'CAPTAIN'
            ? '业务代码/审 diff/产品裁决/merge'
            : '代替其它角色推进状态',
    };
  });
}

function actionsForTask(cwd, goalId, taskId, role = null, threadId = null) {
  return loadGoalStateReadOnly(cwd, goalId, (loaded) => {
    assertFrozenInputs(cwd, loaded, taskId);
    const state = loaded.snapshot.tasks[taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
    if (role) {
      const session = state.sessions[role];
      assertControl(session, 'UNREGISTERED_ACTOR', `${role} 尚未登记 session`);
      if (threadId) assertControl(session.thread_id === threadId, 'WRONG_ACTOR_THREAD', `${role} thread 与登记值不一致`);
      if (role === 'FOREMAN') {
        assertControl(
          ['active', 'idle', 'systemError'].includes(session.status),
          'RECOVERY_REQUIRED',
          `${role} session status=${session.status}`,
        );
        assertUsableGoalForemanReplica(
          loaded.snapshot,
          session,
          runtimeNowMilliseconds(),
        );
      } else {
        assertControl(['active', 'idle'].includes(session.status), 'RECOVERY_REQUIRED', `${role} session status=${session.status}`);
        assertControl(Date.parse(session.lease_until) > runtimeNowMilliseconds(), 'ROLE_LEASE_EXPIRED', `${role} lease 已于 ${session.lease_until} 过期`);
      }
    }
    const manifestTask = loaded.manifest.tasks.find((candidate) => candidate.id === taskId);
    const projection = taskActionProjection(
      loaded.paths,
      state,
      loaded.manifest.goal_id,
      manifestTask,
      {
        readOnly: true,
        manifest: loaded.manifest,
        goalSnapshot: loaded.snapshot,
      },
    );
    const actions = projection.actions.filter((action) => !role || action.actor_role.split('|').includes(role));
    const identityIntent = pendingRoleIdentityIntent(
      controlRoot(cwd),
      loaded,
      taskId,
    );
    return {
      goal_id: goalId,
      task_id: taskId,
      state_revision: state.state_revision,
      control_epoch: loaded.control.epoch,
      ...(manifestTask.p1
        ? {
          required_start_head: mechanicalP1RequiredStartHead(
            loaded,
            manifestTask,
          ),
          dependency_gate: manifestTask.p1.dependency_gate,
        }
        : {}),
      launch_scope: projection.launch_scope,
      ...(projection.launch_error_code
        ? { launch_error_code: projection.launch_error_code }
        : {}),
      operational_scope: role
        ? sessionOperationalScope(state, role)
        : null,
      pending_operations: projection.pending_operations || [],
      ...(identityIntent
        ? { role_identity_intent: identityIntent }
        : {}),
      actions,
      maintenance_actions: projection.maintenance_actions.filter(
        (action) => !role || action.actor_role === role,
      ),
    };
  });
}

function rebuildLedger(cwd, goalId) {
  const root = controlRoot(cwd);
  const safeGoalId = safeId(goalId, 'goal_id');
  return withLock(
    root,
    () => publicSnapshot(rebuildAndWriteUnlocked(root, safeGoalId)),
    {
      transactionKey: () => canonicalTransactionKey(
        'LEDGER_REBUILD',
        { goal_id: safeGoalId },
        `rebuild-ledger:${safeGoalId}`,
        hashObject({
          schema_version: 1,
          kind: 'GOAL_LEDGER_REBUILD',
          goal_id: safeGoalId,
        }),
      ),
      authorizePristineOddRecovery: () => true,
      afterGenerationBeforeCallback: generationBoundaryFaultHook(
        cwd,
        'GOAL_CONTROL_TEST_FAULT_AFTER_LEDGER_REBUILD_GENERATION',
      ),
    },
  );
}

module.exports = {
  acceptEvent,
  acceptEventUnderLock,
  actionsForTask,
  advanceControlEpoch,
  abandonMechanicalP1Commit,
  authorizeHistoricalActorCapability,
  assertDevLaunchHead,
  assertFrozenInputs,
  doctor,
  initializeGoal,
  inspectSourceCheckpointHold,
  loadGoalStateUnlocked,
  loadGoalState,
  loadGoalStateReadOnly,
  mechanicalP1RequiredStartHead,
  assertMechanicalP1DependenciesArchived,
  assertMechanicalP1CandidateWriteSet,
  completeMechanicalP1EventPayload,
  mergeExpectedMainHead,
  validateCandidateBoundary,
  nextTasks,
  publicSnapshot,
  prepareProbeObservationChallenge,
  refreshProbeObservation,
  rebuildLedger,
  recoveryIntentMatchesOptions,
  recoverExpiredForeman,
  registerRole,
  retryAcceptedCommandEvent,
  resumeCapsule,
  taskActionProjection,
  validateRoleLaunchBoundary,
};
