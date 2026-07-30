'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { ControlError, assertControl } = require('./errors');
const {
  executeLooseRefTransaction,
  inspectLooseRefFence,
} = require('./git-loose-ref-transaction');
const { fsyncDirectory } = require('./init-receipt');
const {
  acceptedEventFiles,
  atomicWriteJson,
  ensureDir,
  goalDir,
} = require('./store');
const {
  controlRoot,
  hashFile,
  hashObject,
  normalizeHash,
  readJson,
  readOnlyGitEnvironment,
  safeId,
  sha256,
} = require('./util');

const INTENT_KIND = 'P1_COMMIT_REF_INTENT';
const RECEIPT_KIND = 'P1_COMMIT_REF_COMPLETION';
const ABANDON_INTENT_KIND = 'P1_COMMIT_REF_ABANDON_INTENT';
const ABANDON_RECEIPT_KIND = 'P1_COMMIT_REF_ABANDONMENT';
const BUNDLE_FILE = 'commit.bundle';
const UNAVAILABLE_CARRIER_FILE = 'carrier-unavailable.json';
const UNAVAILABLE_CARRIER_KIND = 'P1_COMMIT_CARRIER_UNAVAILABLE';
const P1_COMMIT_RECEIPT_MISSING_INTENT_MESSAGE =
  'P1 commit receipt 缺 retained intent';
const ACCEPTED_P1_TRANSACTION_MISSING_INTENT_MESSAGE =
  'accepted P1 transaction 缺 retained intent/bundle';
const INTENT_FILE = 'intent.json';
const ABANDON_HANDOFF_FILE = 'abandon-handoff.json';
const ABANDON_HANDOFF_KIND = 'P1_COMMIT_ABANDON_HANDOFF';
const ABANDON_HANDOFF_TEMP_PREFIX = '.abandon-handoff-';
const ABANDON_HANDOFF_TEMP_PATTERN =
  /^\.abandon-handoff-([0-9a-f]{40})-([0-9a-f]{64})\.tmp$/;
const REF_LOCK_FENCE_PREFIX = '.ref-lock-fence-';
const REF_LOCK_FENCE_PATTERN =
  /^\.ref-lock-fence-([0-9a-f]{64})$/;
const COMPLETION_FILE = 'completion.json';
const ZERO_OID = '0'.repeat(40);
const P1_COMMIT_REF_PATTERN =
  /^refs\/heads\/codex\/goal-control\/p1\/([0-9a-f]{64})\/([0-9a-f]{64})\/cycle-([1-9][0-9]*)$/;
const PREPARED_PATTERN =
  /^\.init-p1-commit-([0-9a-f]{64})-([0-9a-f]{64})-([0-9a-f]{64})$/;
const PREPARED_ABANDON_PATTERN =
  /^\.init-abandon-([0-9a-f]{64})-([0-9a-f]{64})-([0-9a-f]{64})$/;
const ATOMIC_TEMP_SUFFIX_PATTERN = /^([1-9][0-9]*)\.tmp-([0-9a-f]{24})$/;

function atomicTemporaryBase(name) {
  if (!name.startsWith('.')) return null;
  const pieces = name.slice(1).split('.');
  if (pieces.length < 4) return null;
  const suffix = pieces.slice(-2).join('.');
  if (!ATOMIC_TEMP_SUFFIX_PATTERN.test(suffix)) return null;
  const base = pieces.slice(0, -2).join('.');
  return base.length > 0 ? base : null;
}

function p1RefLockFenceName(options) {
  const {
    operation,
    intentSha256,
    ref,
    expectedOld,
    expectedNew,
  } = options;
  assertControl(
    operation === 'publish'
      && /^sha256:[0-9a-f]{64}$/.test(intentSha256)
      && P1_COMMIT_REF_PATTERN.test(ref)
      && /^[0-9a-f]{40}$/.test(expectedOld)
      && /^[0-9a-f]{40}$/.test(expectedNew),
    'CORRUPT_STORE',
    'P1 ref-lock fence binding 非法',
  );
  const binding = {
    schema_version: 1,
    kind: 'P1_COMMIT_REF_LOCK_FENCE',
    operation,
    intent_sha256: intentSha256,
    ref,
    expected_old: expectedOld,
    expected_new: expectedNew,
  };
  return `${REF_LOCK_FENCE_PREFIX}${
    hashObject(binding).slice('sha256:'.length)
  }`;
}

function p1CommitRefLockFenceName(intent) {
  return p1RefLockFenceName({
    operation: 'publish',
    intentSha256: intent.intent_sha256,
    ref: intent.ref_binding.commit_ref,
    expectedOld: intent.ref_binding.expected_old_ref,
    expectedNew: intent.ref_binding.new_commit,
  });
}

function inspectP1RefLockFenceFile(file, expectedNew, label) {
  return inspectLooseRefFence({
    fenceFile: file,
    expectedNew,
    codes: {
      fenceConflict: 'CORRUPT_STORE',
    },
    label,
  });
}

function assertExactInventory(directory, expectedEntries, label) {
  const actual = fs.readdirSync(directory).sort();
  const expected = [...expectedEntries].sort();
  assertControl(
    actual.length === expected.length
      && actual.every((entry, index) => entry === expected[index]),
    'PREPARED_STAGING_CONFLICT',
    `${label} cleanup 前 inventory 漂移`,
  );
}

function removeValidatedFiles(directory, entries, label) {
  assertExactInventory(directory, entries, label);
  for (const entry of entries) {
    const file = path.join(directory, entry);
    assertPrivateFile(file, `${label}/${entry}`);
    fs.unlinkSync(file);
  }
  fs.rmdirSync(directory);
  fsyncDirectory(path.dirname(directory));
}

function removeExactTemporary(directory, temporaryName, label) {
  const file = path.join(directory, temporaryName);
  assertPrivateFile(file, `${label}/${temporaryName}`);
  assertControl(
    fs.readdirSync(directory).includes(temporaryName),
    'PREPARED_STAGING_CONFLICT',
    `${label} temporary cleanup 前 inventory 漂移`,
  );
  fs.unlinkSync(file);
  fsyncDirectory(directory);
}

function runGit(cwd, args, options = {}) {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: options.encoding === null ? null : 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: readOnlyGitEnvironment(),
    });
  } catch (error) {
    const detail = String(error.stderr || error.message || '').trim();
    throw new ControlError(
      options.code || 'GIT_FAILED',
      `${options.label || `git ${args.join(' ')}`} 失败${
        detail ? `: ${detail}` : ''
      }`,
    );
  }
}

function assertPrivateDirectory(directory, label) {
  const stat = fs.lstatSync(directory);
  assertControl(
    stat.isDirectory()
      && !stat.isSymbolicLink()
      && (stat.mode & 0o777) === 0o700
      && (
        typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
      ),
    'CORRUPT_STORE',
    `${label} 必须是当前 owner 的 0700 普通目录`,
  );
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

function ensurePrivateDirectory(directory) {
  if (!fs.existsSync(directory)) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  assertPrivateDirectory(directory, directory);
}

function p1CommitTaskPaths(root, goalId, taskId) {
  safeId(goalId, 'goal_id');
  safeId(taskId, 'task_id');
  const base = goalDir(root, goalId);
  return {
    intents: path.join(base, 'p1-commit-intents', taskId),
    receipts: path.join(base, 'p1-commit-receipts', taskId),
    abandonments: path.join(base, 'p1-commit-abandonments', taskId),
    abandonmentReceipts: path.join(
      base,
      'p1-commit-abandonment-receipts',
      taskId,
    ),
  };
}

function p1CommitPaths(root, goalId, taskId, eventId) {
  safeId(eventId, 'P1 commit event_id');
  const task = p1CommitTaskPaths(root, goalId, taskId);
  const intentDirectory = path.join(task.intents, eventId);
  return {
    ...task,
    intentDirectory,
    intent: path.join(intentDirectory, INTENT_FILE),
    abandonHandoff: path.join(
      intentDirectory,
      ABANDON_HANDOFF_FILE,
    ),
    bundle: path.join(intentDirectory, BUNDLE_FILE),
    receipt: path.join(task.receipts, `${eventId}.json`),
    abandonmentDirectory: path.join(task.abandonments, eventId),
    abandonmentIntent: path.join(
      task.abandonments,
      eventId,
      INTENT_FILE,
    ),
    abandonmentCompletion: path.join(
      task.abandonments,
      eventId,
      COMPLETION_FILE,
    ),
    abandonmentReceipt: path.join(
      task.abandonmentReceipts,
      `${eventId}.json`,
    ),
  };
}

function receiptInventory(directory, label) {
  const canonical = new Map();
  const temporaries = new Map();
  if (!fs.existsSync(directory)) return { canonical, temporaries };
  assertPrivateDirectory(directory, label);
  for (const name of fs.readdirSync(directory).sort()) {
    let eventId = null;
    let temporary = false;
    if (!name.startsWith('.') && name.endsWith('.json')) {
      eventId = name.slice(0, -'.json'.length);
    } else {
      const base = atomicTemporaryBase(name);
      if (base && base.endsWith('.json')) {
        eventId = base.slice(0, -'.json'.length);
        temporary = true;
      }
    }
    assertControl(
      eventId,
      'CORRUPT_STORE',
      `${label} 发现 foreign/lookalike entry ${name}`,
    );
    safeId(eventId, `${label} receipt event_id`);
    assertPrivateFile(path.join(directory, name), `${label}/${name}`);
    const target = temporary ? temporaries : canonical;
    assertControl(
      !target.has(eventId),
      'CORRUPT_STORE',
      `${label} ${eventId} 同时存在多个 ${
        temporary ? 'temporary' : 'canonical'
      } receipt`,
    );
    target.set(eventId, name);
  }
  for (const eventId of canonical.keys()) {
    assertControl(
      !temporaries.has(eventId),
      'CORRUPT_STORE',
      `${label} ${eventId} canonical/temporary receipt 并存`,
    );
  }
  return { canonical, temporaries };
}

function sealRecord(record, sealKey) {
  return { ...record, [sealKey]: hashObject(record) };
}

function readSealedRecord(file, sealKey, label) {
  assertPrivateFile(file, label);
  const record = readJson(file, label);
  const unsigned = { ...record };
  delete unsigned[sealKey];
  assertControl(
    record[sealKey] === hashObject(unsigned),
    'CORRUPT_STORE',
    `${label} seal 不匹配`,
  );
  return record;
}

function validateP1CommitAbandonHandoff(
  handoff,
  intent,
  label,
) {
  const expectedKeys = [
    'acceptance_authority',
    'acceptance_authority_sha256',
    'bundle_sha256',
    'event_id',
    'goal_id',
    'handoff_sha256',
    'intent_sha256',
    'kind',
    'reason_code',
    'ref_binding',
    'request_sha256',
    'schema_version',
    'task_anchor',
    'task_anchor_sha256',
    'task_cycle',
    'task_id',
  ].sort();
  const actualKeys = Object.keys(handoff).sort();
  assertControl(
    actualKeys.length === expectedKeys.length
      && actualKeys.every(
        (key, index) => key === expectedKeys[index],
      )
      && handoff.schema_version === 1
      && handoff.kind === ABANDON_HANDOFF_KIND
      && intent.abort_only !== true
      && handoff.goal_id === intent.goal_id
      && handoff.task_id === intent.task_id
      && handoff.event_id === intent.event_id
      && handoff.task_cycle === intent.task_cycle
      && handoff.request_sha256 === intent.request_sha256
      && handoff.intent_sha256 === intent.intent_sha256
      && handoff.bundle_sha256 === intent.bundle.sha256
      && handoff.reason_code === 'FOREIGN_REF_CONFLICT'
      && handoff.task_anchor_sha256 === hashObject(intent.task_anchor)
      && hashObject(handoff.task_anchor)
        === hashObject(intent.task_anchor)
      && handoff.acceptance_authority_sha256
        === hashObject(intent.acceptance_authority)
      && hashObject(handoff.acceptance_authority)
        === hashObject(intent.acceptance_authority)
      && handoff.ref_binding
      && Object.keys(handoff.ref_binding).sort().join(',')
        === [
          'commit_ref',
          'expected_old_ref',
          'expected_ref_head',
          'observed_actual_ref',
        ].sort().join(',')
      && handoff.ref_binding.commit_ref
        === intent.ref_binding.commit_ref
      && handoff.ref_binding.expected_old_ref
        === intent.ref_binding.expected_old_ref
      && handoff.ref_binding.expected_ref_head
        === intent.ref_binding.new_commit
      && /^[0-9a-f]{40}$/.test(
        handoff.ref_binding.observed_actual_ref,
      )
      && handoff.ref_binding.observed_actual_ref !== ZERO_OID
      && handoff.ref_binding.observed_actual_ref
        !== intent.ref_binding.new_commit,
    'CORRUPT_STORE',
    `${label} binding 非法`,
  );
  return handoff;
}

function readP1CommitAbandonHandoff(directory, intent, label) {
  const file = path.join(directory, ABANDON_HANDOFF_FILE);
  if (!fs.existsSync(file)) return null;
  try {
    return validateP1CommitAbandonHandoff(
      readSealedRecord(file, 'handoff_sha256', label),
      intent,
      label,
    );
  } catch (error) {
    if (
      error instanceof ControlError
        && ['INVALID_JSON', 'READ_FAILED'].includes(error.code)
    ) {
      throw new ControlError(
        'CORRUPT_STORE',
        `${label} canonical handoff 不是完整 sealed JSON`,
      );
    }
    throw error;
  }
}

function sealedRecordBytes(record) {
  return Buffer.from(`${JSON.stringify(record, null, 2)}\n`, 'utf8');
}

function expectedP1CommitAbandonHandoff(
  intent,
  observedActualRef,
) {
  assertControl(
    intent.abort_only !== true
      && /^[0-9a-f]{40}$/.test(observedActualRef)
      && observedActualRef !== ZERO_OID
      && observedActualRef !== intent.ref_binding.new_commit,
    'P1_COMMIT_REF_CONFLICT',
    `P1 commit ${intent.event_id} 没有 exact foreign ref witness`,
  );
  return sealRecord({
    schema_version: 1,
    kind: ABANDON_HANDOFF_KIND,
    goal_id: intent.goal_id,
    task_id: intent.task_id,
    task_cycle: intent.task_cycle,
    event_id: intent.event_id,
    request_sha256: intent.request_sha256,
    intent_sha256: intent.intent_sha256,
    task_anchor: JSON.parse(JSON.stringify(intent.task_anchor)),
    task_anchor_sha256: hashObject(intent.task_anchor),
    acceptance_authority: JSON.parse(JSON.stringify(
      intent.acceptance_authority,
    )),
    acceptance_authority_sha256: hashObject(
      intent.acceptance_authority,
    ),
    ref_binding: {
      commit_ref: intent.ref_binding.commit_ref,
      expected_old_ref: intent.ref_binding.expected_old_ref,
      expected_ref_head: intent.ref_binding.new_commit,
      observed_actual_ref: observedActualRef,
    },
    bundle_sha256: intent.bundle.sha256,
    reason_code: 'FOREIGN_REF_CONFLICT',
  }, 'handoff_sha256');
}

function abandonHandoffTemporaryName(handoff) {
  return `${ABANDON_HANDOFF_TEMP_PREFIX}${
    handoff.ref_binding.observed_actual_ref
  }-${handoff.handoff_sha256.slice('sha256:'.length)}.tmp`;
}

function sameFileIdentity(left, right) {
  const leftStat = fs.statSync(left);
  const rightStat = fs.statSync(right);
  return leftStat.dev === rightStat.dev && leftStat.ino === rightStat.ino;
}

function inspectP1CommitAbandonHandoffTemporary(
  directory,
  name,
  intent,
  label,
) {
  const match = ABANDON_HANDOFF_TEMP_PATTERN.exec(name);
  assertControl(
    match,
    'CORRUPT_STORE',
    `${label} temporary name 不是 deterministic handoff commitment`,
  );
  const file = path.join(directory, name);
  assertPrivateFile(file, label);
  const expected = expectedP1CommitAbandonHandoff(intent, match[1]);
  assertControl(
    match[2] === expected.handoff_sha256.slice('sha256:'.length),
    'PREPARED_REQUEST_MISMATCH',
    `${label} temporary name 不是 exact immutable handoff`,
  );
  const body = fs.readFileSync(file);
  const expectedBody = sealedRecordBytes(expected);
  if (body.equals(expectedBody)) {
    return {
      file,
      name,
      complete: true,
      record: expected,
      expected,
      observedActualRef: match[1],
      bodySha256: `sha256:${sha256(body)}`,
    };
  }
  let parsed = null;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    // An empty/truncated exact deterministic temporary is recoverable.
  }
  if (
    parsed
      && typeof parsed === 'object'
      && !Array.isArray(parsed)
      && Object.prototype.hasOwnProperty.call(
        parsed,
        'handoff_sha256',
      )
  ) {
    const unsigned = { ...parsed };
    delete unsigned.handoff_sha256;
    assertControl(
      parsed.handoff_sha256 === hashObject(unsigned),
      'CORRUPT_STORE',
      `${label} temporary seal 不匹配`,
    );
    validateP1CommitAbandonHandoff(parsed, intent, label);
    assertControl(
      hashObject(parsed) === hashObject(expected),
      'PREPARED_REQUEST_MISMATCH',
      `${label} temporary 不是 exact immutable handoff`,
    );
    assertControl(
      false,
      'CORRUPT_STORE',
      `${label} complete handoff bytes 非 canonical encoding`,
    );
  }
  return {
    file,
    name,
    complete: false,
    record: null,
    expected,
    observedActualRef: match[1],
    bodySha256: `sha256:${sha256(body)}`,
  };
}

function inspectSealedAtomicTemporary(file, sealKey, label) {
  assertPrivateFile(file, label);
  const body = fs.readFileSync(file);
  if (body.length === 0) return { complete: false, record: null };
  let record;
  try {
    record = JSON.parse(body.toString('utf8'));
  } catch {
    return { complete: false, record: null };
  }
  assertControl(
    record
      && typeof record === 'object'
      && !Array.isArray(record),
    'CORRUPT_STORE',
    `${label} 必须是 sealed JSON object`,
  );
  const unsigned = { ...record };
  delete unsigned[sealKey];
  assertControl(
    record[sealKey] === hashObject(unsigned),
    'CORRUPT_STORE',
    `${label} seal 不匹配`,
  );
  return { complete: true, record };
}

function assertExactRecoveryRecord(
  record,
  expected,
  identityFields,
  bindingFields,
  label,
) {
  assertControl(
    record.schema_version === expected.schema_version
      && record.kind === expected.kind,
    'CORRUPT_STORE',
    `${label} schema/kind 非法`,
  );
  assertControl(
    identityFields.every(
      (field) => record[field] === expected[field],
    ),
    'PREPARED_REQUEST_MISMATCH',
    `${label} identity 不是 exact request`,
  );
  assertControl(
    bindingFields.every(
      (field) => record[field] === expected[field],
    ),
    'PREPARED_REQUEST_MISMATCH',
    `${label} request/intent binding 不是 exact request`,
  );
  assertControl(
    hashObject(record) === hashObject(expected),
    'PREPARED_REQUEST_MISMATCH',
    `${label} 不是 exact completion`,
  );
}

function recoverSealedAtomicTemporary(options) {
  const {
    directory,
    temporaryName,
    target,
    sealKey,
    expected,
    identityFields,
    bindingFields,
    label,
  } = options;
  const temporary = path.join(directory, temporaryName);
  assertControl(
    path.dirname(target) === directory
      && atomicTemporaryBase(temporaryName) === path.basename(target),
    'PREPARED_STAGING_CONFLICT',
    `${label} 不是 target 的 atomic temporary`,
  );
  const inspected = inspectSealedAtomicTemporary(
    temporary,
    sealKey,
    label,
  );
  if (!inspected.complete) {
    removeExactTemporary(directory, temporaryName, label);
    return null;
  }
  assertExactRecoveryRecord(
    inspected.record,
    expected,
    identityFields,
    bindingFields,
    label,
  );
  assertControl(
    !fs.existsSync(target)
      && fs.readdirSync(directory).includes(temporaryName),
    'PREPARED_STAGING_CONFLICT',
    `${label} promotion 前 inventory 漂移`,
  );
  fs.renameSync(temporary, target);
  fsyncDirectory(directory);
  return inspected.record;
}

function validateIntentRecord(intent, expected = {}) {
  const abortOnly = intent.abort_only === true;
  assertControl(
    intent.schema_version === 1
      && intent.kind === INTENT_KIND
      && typeof intent.goal_id === 'string'
      && typeof intent.task_id === 'string'
      && typeof intent.event_id === 'string'
      && Number.isSafeInteger(intent.task_cycle)
      && intent.task_cycle > 0
      && intent.request
      && intent.request.event_id === intent.event_id
      && intent.request.goal_id === intent.goal_id
      && intent.request.task_id === intent.task_id
      && intent.request.type === 'P1_COMMITTED'
      && intent.request_sha256 === hashObject(intent.request)
      && intent.task_anchor
      && intent.acceptance_authority
      && intent.p1_binding
      && intent.ref_binding
      && intent.bundle
      && (!abortOnly || intent.abort_binding)
      && intent.prepared_request_sha256 === hashObject({
        request: intent.request,
        task_anchor: intent.task_anchor,
        acceptance_authority: intent.acceptance_authority,
        p1_binding: intent.p1_binding,
        ref_binding: intent.ref_binding,
        bundle: intent.bundle,
        accepted_at: intent.accepted_at,
      })
      && typeof intent.accepted_at === 'string'
      && Number.isFinite(Date.parse(intent.accepted_at)),
    'CORRUPT_STORE',
    `P1 commit intent ${intent.event_id || '<unknown>'} binding 非法`,
  );
  safeId(intent.goal_id, 'P1 commit intent goal_id');
  safeId(intent.task_id, 'P1 commit intent task_id');
  safeId(intent.event_id, 'P1 commit intent event_id');
  assertControl(
    (!expected.goalId || intent.goal_id === expected.goalId)
      && (!expected.taskId || intent.task_id === expected.taskId)
      && (!expected.eventId || intent.event_id === expected.eventId)
      && (
        !expected.requestSha256
          || intent.request_sha256 === expected.requestSha256
      ),
    'PREPARED_REQUEST_MISMATCH',
    `P1 commit intent ${intent.event_id} 不是 exact request`,
  );
  const ref = intent.ref_binding;
  assertControl(
    typeof ref.repository_root === 'string'
      && path.isAbsolute(ref.repository_root)
      && path.normalize(ref.repository_root) === ref.repository_root
      && typeof ref.common_git_dir === 'string'
      && path.isAbsolute(ref.common_git_dir)
      && path.normalize(ref.common_git_dir) === ref.common_git_dir
      && /^[0-9a-f]{40}$/.test(ref.new_commit)
      && ref.expected_old_ref === ZERO_OID
      && typeof ref.commit_ref === 'string'
      && ref.commit_ref.startsWith(
        'refs/heads/codex/goal-control/p1/',
      ),
    'CORRUPT_STORE',
    `P1 commit intent ${intent.event_id} ref binding 非法`,
  );
  assertControl(
    (
      (
        !abortOnly
          && intent.bundle.file === BUNDLE_FILE
          && intent.bundle.available !== false
      )
        || (
          abortOnly
            && intent.bundle.file === UNAVAILABLE_CARRIER_FILE
            && intent.bundle.available === false
            && intent.bundle.reason_code
              === 'PRE_SEAL_COMMIT_CARRIER_UNAVAILABLE'
            && intent.abort_binding.reason_code
              === 'PRE_SEAL_COMMIT_CARRIER_UNAVAILABLE'
            && Array.isArray(intent.abort_binding.residue_inventory)
            && intent.abort_binding.residue_inventory_sha256
              === hashObject(intent.abort_binding.residue_inventory)
        )
    )
      && /^sha256:[0-9a-f]{64}$/.test(intent.bundle.sha256)
      && intent.bundle.head === ref.new_commit,
    'CORRUPT_STORE',
    `P1 commit intent ${intent.event_id} bundle binding 非法`,
  );
  return intent;
}

function validateResidueInventory(directory, inventory, label) {
  assertControl(
    Array.isArray(inventory)
      && inventory.every((entry) => (
        entry
          && typeof entry.file === 'string'
          && entry.file.length > 0
          && path.basename(entry.file) === entry.file
          && entry.file !== INTENT_FILE
          && entry.file !== UNAVAILABLE_CARRIER_FILE
          && entry.file !== ABANDON_HANDOFF_FILE
          && /^sha256:[0-9a-f]{64}$/.test(entry.sha256)
          && Number.isSafeInteger(entry.size)
          && entry.size >= 0
      ))
      && new Set(inventory.map((entry) => entry.file)).size
        === inventory.length,
    'CORRUPT_STORE',
    `${label} residue inventory 非法`,
  );
  for (const entry of inventory) {
    const file = path.join(directory, entry.file);
    assertPrivateFile(file, `${label}/${entry.file}`);
    const stat = fs.statSync(file);
    assertControl(
      stat.size === entry.size && hashFile(file) === entry.sha256,
      'CORRUPT_STORE',
      `${label}/${entry.file} residue bytes 漂移`,
    );
  }
}

function validateUnavailableCarrierRecord(
  marker,
  directory,
  expected,
  label,
) {
  assertControl(
    marker.schema_version === 1
      && marker.kind === UNAVAILABLE_CARRIER_KIND
      && typeof marker.goal_id === 'string'
      && typeof marker.task_id === 'string'
      && typeof marker.event_id === 'string'
      && Number.isSafeInteger(marker.task_cycle)
      && marker.task_cycle > 0
      && /^sha256:[0-9a-f]{64}$/.test(marker.request_sha256)
      && typeof marker.commit_ref === 'string'
      && marker.commit_ref.startsWith(
        'refs/heads/codex/goal-control/p1/',
      )
      && /^[0-9a-f]{40}$/.test(marker.commit_sha)
      && /^sha256:[0-9a-f]{64}$/.test(
        marker.task_anchor_sha256,
      )
      && /^sha256:[0-9a-f]{64}$/.test(
        marker.acceptance_authority_sha256,
      )
      && marker.reason_code
        === 'PRE_SEAL_COMMIT_CARRIER_UNAVAILABLE'
      && Array.isArray(marker.residue_inventory)
      && marker.residue_inventory_sha256
        === hashObject(marker.residue_inventory),
    'CORRUPT_STORE',
    `${label} unavailable carrier binding 非法`,
  );
  safeId(marker.goal_id, `${label} goal_id`);
  safeId(marker.task_id, `${label} task_id`);
  safeId(marker.event_id, `${label} event_id`);
  assertControl(
    marker.goal_id === expected.goalId
      && marker.task_id === expected.taskId
      && marker.event_id === expected.eventId
      && marker.request_sha256 === expected.requestSha256
      && marker.commit_sha === expected.commitSha
      && (
        !expected.commitRef
          || marker.commit_ref === expected.commitRef
      )
      && (
        !expected.taskCycle
          || marker.task_cycle === expected.taskCycle
      )
      && (
        !expected.taskAnchorSha256
          || marker.task_anchor_sha256
            === expected.taskAnchorSha256
      )
      && (
        !expected.acceptanceAuthoritySha256
          || marker.acceptance_authority_sha256
            === expected.acceptanceAuthoritySha256
      ),
    'PREPARED_REQUEST_MISMATCH',
    `${label} unavailable carrier 不是 exact request`,
  );
  validateResidueInventory(
    directory,
    marker.residue_inventory,
    label,
  );
  return marker;
}

function readUnavailableCarrier(file, intent, label) {
  const marker = readSealedRecord(
    file,
    'marker_sha256',
    `${label} unavailable carrier`,
  );
  validateUnavailableCarrierRecord(
    marker,
    path.dirname(file),
    {
      goalId: intent.goal_id,
      taskId: intent.task_id,
      eventId: intent.event_id,
      requestSha256: intent.request_sha256,
      commitRef: intent.ref_binding.commit_ref,
      commitSha: intent.ref_binding.new_commit,
      taskCycle: intent.task_cycle,
      taskAnchorSha256: hashObject(intent.task_anchor),
      acceptanceAuthoritySha256: hashObject(
        intent.acceptance_authority,
      ),
    },
    label,
  );
  const binding = intent.abort_binding;
  assertControl(
    marker.reason_code === binding.reason_code
      && marker.residue_inventory_sha256
        === binding.residue_inventory_sha256
      && hashObject(marker.residue_inventory)
        === hashObject(binding.residue_inventory),
    'CORRUPT_STORE',
    `${label} unavailable carrier binding 漂移`,
  );
  return marker;
}

function readP1CommitIntentDirectory(
  directory,
  goalId,
  taskId,
  eventId,
  label,
) {
  assertPrivateDirectory(
    directory,
    label,
  );
  const entries = fs.readdirSync(directory).sort();
  assertControl(
    entries.includes(INTENT_FILE),
    'CORRUPT_STORE',
    `${label} 缺 ${INTENT_FILE}`,
  );
  const intent = validateIntentRecord(
    readSealedRecord(
      path.join(directory, INTENT_FILE),
      'intent_sha256',
      label,
    ),
    { goalId, taskId, eventId },
  );
  const carrierFile = path.join(directory, intent.bundle.file);
  const residueNames = intent.abort_only
    ? intent.abort_binding.residue_inventory.map((entry) => entry.file)
    : [];
  const abandonHandoffTemporaryNames = entries.filter(
    (entry) => entry.startsWith(ABANDON_HANDOFF_TEMP_PREFIX),
  );
  const refLockFenceNames = entries.filter(
    (entry) => REF_LOCK_FENCE_PATTERN.test(entry),
  );
  assertControl(
    abandonHandoffTemporaryNames.length <= 1
      && (
        abandonHandoffTemporaryNames.length === 0
          || intent.abort_only !== true
      ),
    'CORRUPT_STORE',
    `${label} handoff temporary inventory 非协议状态`,
  );
  const expectedRefLockFenceName = intent.abort_only
    ? null
    : p1CommitRefLockFenceName(intent);
  assertControl(
    refLockFenceNames.length <= 1
      && (
        refLockFenceNames.length === 0
          || refLockFenceNames[0] === expectedRefLockFenceName
      ),
    'CORRUPT_STORE',
    `${label} ref-lock fence 不是 exact sealed intent binding`,
  );
  const expectedEntries = [
    INTENT_FILE,
    intent.bundle.file,
    ...residueNames,
    ...refLockFenceNames,
    ...(entries.includes(ABANDON_HANDOFF_FILE)
      ? [ABANDON_HANDOFF_FILE]
      : []),
    ...abandonHandoffTemporaryNames,
  ].sort();
  assertControl(
    entries.length === expectedEntries.length
      && entries.every((entry, index) => entry === expectedEntries[index]),
    'CORRUPT_STORE',
    `${label} inventory 非协议状态`,
  );
  assertPrivateFile(carrierFile, `${label}/${intent.bundle.file}`);
  assertControl(
    hashFile(carrierFile) === intent.bundle.sha256,
    'CORRUPT_STORE',
    `${label} carrier bytes 漂移`,
  );
  if (intent.abort_only) {
    validateResidueInventory(
      directory,
      intent.abort_binding.residue_inventory,
      label,
    );
    readUnavailableCarrier(carrierFile, intent, label);
  }
  const refLockFence = refLockFenceNames.length === 1
    ? path.join(directory, refLockFenceNames[0])
    : null;
  if (refLockFence) {
    inspectP1RefLockFenceFile(
      refLockFence,
      intent.ref_binding.new_commit,
      `${label}/${refLockFenceNames[0]}`,
    );
  }
  const abandonHandoff = entries.includes(ABANDON_HANDOFF_FILE)
    ? readP1CommitAbandonHandoff(
      directory,
      intent,
      `${label} abandon handoff`,
    )
    : null;
  const abandonHandoffTemporary =
    abandonHandoffTemporaryNames.length === 1
      ? inspectP1CommitAbandonHandoffTemporary(
        directory,
        abandonHandoffTemporaryNames[0],
        intent,
        `${label} abandon handoff temporary`,
      )
      : null;
  if (abandonHandoff && abandonHandoffTemporary) {
    assertControl(
      abandonHandoffTemporary.complete
        && sameFileIdentity(
          path.join(directory, ABANDON_HANDOFF_FILE),
          abandonHandoffTemporary.file,
        )
        && hashObject(abandonHandoff)
          === hashObject(abandonHandoffTemporary.record),
      'CORRUPT_STORE',
      `${label} canonical/temporary handoff 不是同一 promoted inode`,
    );
  }
  return {
    intent,
    abandonHandoff,
    abandonHandoffTemporary,
    refLockFence,
  };
}

function readP1CommitIntent(root, goalId, taskId, eventId) {
  const files = p1CommitPaths(root, goalId, taskId, eventId);
  if (!fs.existsSync(files.intentDirectory)) return null;
  const retained = readP1CommitIntentDirectory(
    files.intentDirectory,
    goalId,
    taskId,
    eventId,
    `P1 commit intent ${eventId}`,
  );
  return { ...retained, files, staging: false };
}

function preparedDirectoryName(
  eventId,
  requestSha256,
  acceptanceAuthoritySha256,
) {
  return `.init-p1-commit-${sha256(eventId)}-${
    normalizeHash(requestSha256, 'P1 request sha256')
      .slice('sha256:'.length)
  }-${
    normalizeHash(
      acceptanceAuthoritySha256,
      'P1 acceptance authority sha256',
    ).slice('sha256:'.length)
  }`;
}

function inspectCommitStaging(directory, name) {
  assertPrivateDirectory(directory, `P1 commit staging ${name}`);
  const entries = fs.readdirSync(directory).sort();
  const bundleTemporary = entries.filter(
    (entry) => entry === '.commit.bundle.tmp',
  );
  const intentTemporaries = entries.filter(
    (entry) => atomicTemporaryBase(entry) === INTENT_FILE,
  );
  const unavailableCarrierTemporaries = entries.filter(
    (entry) => atomicTemporaryBase(entry) === UNAVAILABLE_CARRIER_FILE,
  );
  const abandonHandoffTemporaries = entries.filter(
    (entry) => entry.startsWith(ABANDON_HANDOFF_TEMP_PREFIX),
  );
  const known = new Set([
    ...bundleTemporary,
    ...intentTemporaries,
    ...unavailableCarrierTemporaries,
    ...abandonHandoffTemporaries,
    ...(entries.includes(BUNDLE_FILE) ? [BUNDLE_FILE] : []),
    ...(entries.includes(INTENT_FILE) ? [INTENT_FILE] : []),
    ...(entries.includes(ABANDON_HANDOFF_FILE)
      ? [ABANDON_HANDOFF_FILE]
      : []),
    ...(entries.includes(UNAVAILABLE_CARRIER_FILE)
      ? [UNAVAILABLE_CARRIER_FILE]
      : []),
  ]);
  const unknown = entries.filter((entry) => !known.has(entry));
  assertControl(
    unknown.length === 0
      && bundleTemporary.length <= 1
      && intentTemporaries.length <= 1
      && unavailableCarrierTemporaries.length <= 1
      && abandonHandoffTemporaries.length <= 1
      && (
        !entries.includes(ABANDON_HANDOFF_FILE)
          || entries.includes(INTENT_FILE)
      )
      && (
        abandonHandoffTemporaries.length === 0
          || (
            entries.includes(INTENT_FILE)
              && ABANDON_HANDOFF_TEMP_PATTERN.test(
                abandonHandoffTemporaries[0],
              )
          )
      )
      && !(bundleTemporary.length && entries.includes(BUNDLE_FILE))
      && !(
        unavailableCarrierTemporaries.length
          && entries.includes(UNAVAILABLE_CARRIER_FILE)
      ),
    'PREPARED_STAGING_INVALID',
    `P1 commit staging ${name} inventory 非协议状态: ${
      entries.join(', ')
    }`,
  );
  for (const entry of entries) {
    assertPrivateFile(
      path.join(directory, entry),
      `P1 commit staging ${name}/${entry}`,
    );
  }
  let stage = 'EMPTY_STAGING';
  if (
    entries.includes(ABANDON_HANDOFF_FILE)
      && abandonHandoffTemporaries.length
  ) {
    stage = 'ABANDON_HANDOFF_PROMOTION_CLEANUP';
  } else if (entries.includes(ABANDON_HANDOFF_FILE)) {
    stage = 'ABANDON_HANDOFF_STAGING';
  } else if (abandonHandoffTemporaries.length) {
    stage = 'ABANDON_HANDOFF_TEMP';
  } else if (entries.includes(INTENT_FILE)) stage = 'SEALED_STAGING';
  else if (
    entries.includes(UNAVAILABLE_CARRIER_FILE)
      || unavailableCarrierTemporaries.length
  ) stage = 'ABANDON_ONLY_PREPARING';
  else if (intentTemporaries.length) stage = 'INTENT_TEMP';
  else if (entries.includes(BUNDLE_FILE)) stage = 'BUNDLE_ONLY';
  else if (bundleTemporary.length) stage = 'BUNDLE_TEMP';
  return {
    directory,
    name,
    entries,
    stage,
    bundle: entries.includes(BUNDLE_FILE)
      ? path.join(directory, BUNDLE_FILE)
      : null,
    bundleTemporary: bundleTemporary.length
      ? path.join(directory, bundleTemporary[0])
      : null,
    intent: entries.includes(INTENT_FILE)
      ? path.join(directory, INTENT_FILE)
      : null,
    abandonHandoff: entries.includes(ABANDON_HANDOFF_FILE)
      ? path.join(directory, ABANDON_HANDOFF_FILE)
      : null,
    abandonHandoffTemporary: abandonHandoffTemporaries.length
      ? path.join(directory, abandonHandoffTemporaries[0])
      : null,
    abandonHandoffTemporaries: abandonHandoffTemporaries.map(
      (entry) => path.join(directory, entry),
    ),
    intentTemporary: intentTemporaries.length
      ? path.join(directory, intentTemporaries[0])
      : null,
    intentTemporaries: intentTemporaries.map(
      (entry) => path.join(directory, entry),
    ),
    unavailableCarrier: entries.includes(UNAVAILABLE_CARRIER_FILE)
      ? path.join(directory, UNAVAILABLE_CARRIER_FILE)
      : null,
    unavailableCarrierTemporary:
      unavailableCarrierTemporaries.length
        ? path.join(directory, unavailableCarrierTemporaries[0])
        : null,
    unavailableCarrierTemporaries: unavailableCarrierTemporaries.map(
      (entry) => path.join(directory, entry),
    ),
  };
}

function preparedCandidates(root, goalId, taskId) {
  const paths = p1CommitTaskPaths(root, goalId, taskId);
  if (!fs.existsSync(paths.intents)) return [];
  assertPrivateDirectory(paths.intents, `P1 commit intents ${taskId}`);
  const candidates = [];
  for (const name of fs.readdirSync(paths.intents).sort()) {
    if (!name.startsWith('.init-')) continue;
    const match = PREPARED_PATTERN.exec(name);
    assertControl(
      match,
      'PREPARED_STAGING_CONFLICT',
      `P1 commit intents 发现 foreign/lookalike staging ${name}`,
    );
    const directory = path.join(paths.intents, name);
    const inventory = inspectCommitStaging(directory, name);
    let sealedIntent = null;
    let retained = null;
    if (inventory.intent) {
      const candidateIntent = readSealedRecord(
        inventory.intent,
        'intent_sha256',
        `P1 commit staging ${name}`,
      );
      retained = readP1CommitIntentDirectory(
        directory,
        goalId,
        taskId,
        candidateIntent.event_id,
        `P1 commit staging ${name}`,
      );
      sealedIntent = retained.intent;
      assertControl(
        `sha256:${match[1]}` === `sha256:${sha256(sealedIntent.event_id)}`
          && `sha256:${match[2]}` === sealedIntent.request_sha256
          && `sha256:${match[3]}` === hashObject(
            sealedIntent.acceptance_authority,
          ),
        'CORRUPT_STORE',
        `P1 commit staging ${name} sealed identity 漂移`,
      );
    }
    candidates.push({
      ...inventory,
      ...(retained && retained.abandonHandoffTemporary
        ? {
          stage: retained.abandonHandoff
            ? 'ABANDON_HANDOFF_PROMOTION_CLEANUP'
            : retained.abandonHandoffTemporary.complete
              ? 'ABANDON_HANDOFF_TEMP_COMPLETE'
              : 'ABANDON_HANDOFF_TEMP_PARTIAL',
        }
        : {}),
      sealedIntent,
      abandonHandoff: retained
        ? retained.abandonHandoff
        : null,
      abandonHandoffTemporary: retained
        ? retained.abandonHandoffTemporary
        : null,
      event_id_sha256: `sha256:${match[1]}`,
      request_sha256: `sha256:${match[2]}`,
      acceptance_authority_sha256: `sha256:${match[3]}`,
    });
  }
  assertControl(
    candidates.length <= 1,
    'CORRUPT_STORE',
    `task ${taskId} 同时存在多个 P1 commit staging`,
  );
  return candidates;
}

function inspectP1CommitPreparation(
  root,
  goalId,
  taskId,
  eventId,
  requestSha256,
  acceptanceAuthoritySha256 = null,
) {
  const canonical = readP1CommitIntent(
    root,
    goalId,
    taskId,
    eventId,
  );
  if (canonical) {
    validateIntentRecord(canonical.intent, {
      goalId,
      taskId,
      eventId,
      requestSha256,
    });
    if (acceptanceAuthoritySha256) {
      assertControl(
        hashObject(canonical.intent.acceptance_authority)
          === normalizeHash(
            acceptanceAuthoritySha256,
            'P1 acceptance authority sha256',
          ),
        'PREPARED_REQUEST_MISMATCH',
        `P1 commit intent ${eventId} 不是 exact original authority`,
      );
    }
    return canonical;
  }
  const candidates = preparedCandidates(root, goalId, taskId);
  if (candidates.length === 0) return null;
  const candidate = candidates[0];
  assertControl(
    candidate.event_id_sha256 === `sha256:${sha256(eventId)}`
      && candidate.request_sha256
        === normalizeHash(requestSha256, 'P1 request sha256')
      && (
        !acceptanceAuthoritySha256
          || candidate.acceptance_authority_sha256
            === normalizeHash(
              acceptanceAuthoritySha256,
              'P1 acceptance authority sha256',
            )
      ),
    'PREPARED_REQUEST_MISMATCH',
    `P1 commit staging 不是 ${eventId} exact request`,
  );
  if (candidate.intent) {
    const retained = readP1CommitIntentDirectory(
      candidate.directory,
      goalId,
      taskId,
      eventId,
      `P1 commit staging intent ${eventId}`,
    );
    const intent = retained.intent;
    assertControl(
      intent.request_sha256 === requestSha256,
      'PREPARED_REQUEST_MISMATCH',
      `P1 commit staging intent ${eventId} 不是 exact request`,
    );
    return {
      ...candidate,
      ...retained,
      intent,
      staging: true,
    };
  }
  return {
    ...candidate,
    intent: null,
    staging: true,
    exactBinding: {
      goalId,
      taskId,
      eventId,
      requestSha256,
      acceptanceAuthoritySha256:
        candidate.acceptance_authority_sha256,
    },
  };
}

function bundleHead(bundleFile) {
  assertPrivateFile(bundleFile, `P1 commit bundle ${bundleFile}`);
  const lines = runGit(
    path.dirname(bundleFile),
    ['bundle', 'list-heads', bundleFile],
    { label: `git bundle list-heads ${bundleFile}` },
  ).trim().split('\n').filter(Boolean);
  assertControl(
    lines.length === 1
      && /^[0-9a-f]{40} HEAD$/.test(lines[0]),
    'P1_COMMIT_BUNDLE_INVALID',
    `P1 commit bundle 必须只含 HEAD`,
  );
  return lines[0].slice(0, 40);
}

function repositoryIdentity(cwd, repositoryRoot) {
  const actualRepositoryRoot = path.resolve(
    runGit(cwd, ['rev-parse', '--show-toplevel']).trim(),
  );
  const commonGitDir = path.resolve(
    runGit(cwd, [
      'rev-parse',
      '--path-format=absolute',
      '--git-common-dir',
    ]).trim(),
  );
  assertControl(
    actualRepositoryRoot === path.resolve(cwd)
      || path.dirname(commonGitDir) === path.resolve(repositoryRoot),
    'REPOSITORY_ROOT_MISMATCH',
    '当前 worktree 不属于 P1 intent 初始化仓库',
  );
  assertControl(
    path.dirname(commonGitDir) === path.resolve(repositoryRoot),
    'REPOSITORY_ROOT_MISMATCH',
    'P1 intent common git dir 不属于 Goal repository root',
  );
  return {
    repository_root: path.resolve(repositoryRoot),
    common_git_dir: commonGitDir,
  };
}

function createBundle(staging, worktree, commit, parent) {
  const temporary = path.join(staging, '.commit.bundle.tmp');
  assertControl(
    readExactRef(worktree, 'HEAD') === commit,
    'P1_COMMIT_HEAD_DRIFT',
    `P1 bundle create 前 HEAD 未绑定显式 commit ${commit}`,
  );
  runGit(
    worktree,
    ['bundle', 'create', temporary, 'HEAD', `^${parent}`],
    { label: 'git bundle create P1 commit' },
  );
  fs.chmodSync(temporary, 0o600);
  const fd = fs.openSync(temporary, 'r');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  maybeFault(
    worktree,
    'GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_BUNDLE_TEMP',
    'TEST_FAULT_AFTER_P1_COMMIT_BUNDLE_TEMP',
    'injected failure after P1 commit bundle temporary fsync',
  );
  assertControl(
    readExactRef(worktree, 'HEAD') === commit,
    'P1_COMMIT_HEAD_DRIFT',
    `P1 bundle create 后 HEAD 已漂移离开 ${commit}`,
  );
  assertControl(
    bundleHead(temporary) === commit,
    'P1_COMMIT_BUNDLE_INVALID',
    `P1 bundle temporary HEAD 未绑定显式 commit ${commit}`,
  );
  const target = path.join(staging, BUNDLE_FILE);
  fs.renameSync(temporary, target);
  fsyncDirectory(staging);
  assertControl(
    bundleHead(target) === commit,
    'P1_COMMIT_BUNDLE_INVALID',
    `P1 bundle HEAD 未绑定 ${commit}`,
  );
  return target;
}

function maybeFault(cwd, environmentName, code, message) {
  const mode = process.env[environmentName];
  if (mode === undefined || mode === '') return;
  const { assertIsolatedTestMode } = require('./util');
  assertControl(
    ['1', 'throw', 'exit'].includes(mode),
    'INVALID_TEST_FAULT',
    `${environmentName} 只能是 1/throw/exit`,
  );
  assertIsolatedTestMode(cwd);
  if (mode === 'exit') process.exit(86);
  throw new ControlError(code, message);
}

function cleanupExactUnsealedCommitStaging(
  prepared,
  eventId,
  requestSha256,
  acceptanceAuthoritySha256,
) {
  assertControl(
    prepared
      && prepared.staging === true
      && !prepared.intent
      && prepared.name === preparedDirectoryName(
        eventId,
        requestSha256,
        acceptanceAuthoritySha256,
      ),
    'PREPARED_REQUEST_MISMATCH',
    `P1 commit staging 不是 ${eventId} exact unsealed request`,
  );
  removeValidatedFiles(
    prepared.directory,
    prepared.entries,
    `P1 commit staging ${prepared.name}`,
  );
}

function commitObjectExists(cwd, commit) {
  try {
    runGit(cwd, ['cat-file', '-e', `${commit}^{commit}`]);
    return true;
  } catch {
    return false;
  }
}

function exactBundleCarrier(bundle, expectedCommit) {
  if (!bundle) return false;
  try {
    return bundleHead(bundle) === expectedCommit;
  } catch {
    return false;
  }
}

function unsealedCommitCarrierStatus(cwd, prepared, expectedCommit) {
  assertControl(
    prepared && prepared.staging === true && !prepared.intent,
    'PREPARED_REQUEST_MISMATCH',
    'P1 commit carrier probe 只允许 exact unsealed staging',
  );
  const canonicalBundle = exactBundleCarrier(
    prepared.bundle,
    expectedCommit,
  );
  const temporaryBundle = exactBundleCarrier(
    prepared.bundleTemporary,
    expectedCommit,
  );
  const objectAvailable = commitObjectExists(cwd, expectedCommit);
  const headAvailable = objectAvailable
    && readExactRef(cwd, 'HEAD') === expectedCommit;
  return {
    canonicalBundle,
    temporaryBundle,
    objectAvailable,
    headAvailable,
    recoverable: canonicalBundle || temporaryBundle || headAvailable,
  };
}

function removeKnownAtomicTemporary(directory, temporary, label) {
  if (!temporary) return;
  const name = path.basename(temporary);
  assertControl(
    path.dirname(temporary) === directory
      && atomicTemporaryBase(name),
    'PREPARED_STAGING_CONFLICT',
    `${label} 不是已知 atomic temporary`,
  );
  removeExactTemporary(directory, name, label);
}

function preparedUnavailableCarrierMarker(prepared, expectedCommit) {
  const markerTemporary = prepared.unavailableCarrierTemporary;
  if (!prepared.unavailableCarrier && !markerTemporary) return null;
  assertControl(
    prepared.exactBinding,
    'CORRUPT_STORE',
    `P1 commit staging ${prepared.name} 缺 exact binding`,
  );
  let markerFile = prepared.unavailableCarrier;
  let marker;
  if (markerFile) {
    marker = readSealedRecord(
      markerFile,
      'marker_sha256',
      `P1 commit staging ${prepared.name} unavailable carrier`,
    );
  } else {
    const inspected = inspectSealedAtomicTemporary(
      markerTemporary,
      'marker_sha256',
      `P1 commit staging ${prepared.name} unavailable carrier temporary`,
    );
    if (!inspected.complete) return null;
    marker = inspected.record;
  }
  validateUnavailableCarrierRecord(
    marker,
    prepared.directory,
    {
      ...prepared.exactBinding,
      commitSha: expectedCommit,
    },
    `P1 commit staging ${prepared.name}`,
  );
  if (!markerFile) {
    markerFile = path.join(
      prepared.directory,
      UNAVAILABLE_CARRIER_FILE,
    );
    assertControl(
      !fs.existsSync(markerFile),
      'PREPARED_STAGING_CONFLICT',
      `P1 commit staging ${prepared.name} unavailable carrier canonical 已存在`,
    );
    fs.renameSync(markerTemporary, markerFile);
    fsyncDirectory(prepared.directory);
  }
  return { marker, markerFile };
}

function promoteReusableUnsealedCarrier(
  prepared,
  expectedCommit,
  carrierStatus,
) {
  const unavailableCarrier = preparedUnavailableCarrierMarker(
    prepared,
    expectedCommit,
  );
  assertControl(
    !unavailableCarrier,
    'P1_COMMIT_CARRIER_UNAVAILABLE',
    `P1 commit staging ${prepared.name} 已 durable 标记 carrier unavailable；禁止恢复为可接受 intent`,
  );
  const removeAtomicTemporaries = () => {
    for (const temporary of [
      ...(prepared.intentTemporaries || []),
      ...(prepared.unavailableCarrierTemporaries || []),
    ]) {
      removeKnownAtomicTemporary(
        prepared.directory,
        temporary,
        `P1 commit staging ${prepared.name}`,
      );
    }
  };
  if (carrierStatus.canonicalBundle) {
    removeAtomicTemporaries();
    return prepared.bundle;
  }
  if (carrierStatus.temporaryBundle) {
    removeAtomicTemporaries();
    const target = path.join(prepared.directory, BUNDLE_FILE);
    assertControl(
      !fs.existsSync(target),
      'PREPARED_STAGING_CONFLICT',
      `P1 commit staging ${prepared.name} 已有 canonical bundle`,
    );
    fs.renameSync(prepared.bundleTemporary, target);
    fsyncDirectory(prepared.directory);
    assertControl(
      bundleHead(target) === expectedCommit,
      'P1_COMMIT_BUNDLE_INVALID',
      `P1 bundle temporary promotion 未绑定 ${expectedCommit}`,
    );
    return target;
  }
  return null;
}

function publishP1CommitIntent(options) {
  const {
    cwd,
    root,
    goalId,
    taskId,
    eventId,
    requestSha256,
    requiredStartHead,
    unsignedIntent,
  } = options;
  const acceptanceAuthoritySha256 = unsignedIntent
    ? hashObject(unsignedIntent.acceptance_authority)
    : null;
  const files = p1CommitPaths(root, goalId, taskId, eventId);
  withPrivateUmask(() => ensureDir(files.intents));
  ensurePrivateDirectory(files.intents);
  let prepared = inspectP1CommitPreparation(
    root,
    goalId,
    taskId,
    eventId,
    requestSha256,
    acceptanceAuthoritySha256,
  );
  if (prepared && !prepared.staging) return prepared;
  if (prepared && !prepared.intent) {
    const carrierStatus = unsealedCommitCarrierStatus(
      cwd,
      prepared,
      unsignedIntent.ref_binding.new_commit,
    );
    const reusableBundle = promoteReusableUnsealedCarrier(
      prepared,
      unsignedIntent.ref_binding.new_commit,
      carrierStatus,
    );
    if (!reusableBundle) {
      assertControl(
        carrierStatus.headAvailable,
        'P1_COMMIT_CARRIER_UNAVAILABLE',
        `P1 commit ${eventId} pre-seal carrier 不可恢复；只能 seal ABANDON_ONLY 后由 live FOREMAN 废止`,
      );
      cleanupExactUnsealedCommitStaging(
        prepared,
        eventId,
        requestSha256,
        acceptanceAuthoritySha256,
      );
      prepared = null;
    } else {
      prepared = inspectP1CommitPreparation(
        root,
        goalId,
        taskId,
        eventId,
        requestSha256,
        acceptanceAuthoritySha256,
      );
    }
  }
  let staging;
  if (prepared) {
    staging = prepared.directory;
  } else {
    staging = path.join(
      files.intents,
      preparedDirectoryName(
        eventId,
        requestSha256,
        acceptanceAuthoritySha256,
      ),
    );
    assertControl(
      !fs.existsSync(staging),
      'PREPARED_STAGING_CONFLICT',
      `P1 commit staging ${eventId} 已存在`,
    );
    fs.mkdirSync(staging, { mode: 0o700 });
    fsyncDirectory(files.intents);
    maybeFault(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY',
      'TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY',
      'injected failure after empty P1 commit staging directory fsync',
    );
  }
  let bundle = path.join(staging, BUNDLE_FILE);
  if (!fs.existsSync(bundle)) {
    bundle = createBundle(
      staging,
      cwd,
      unsignedIntent.ref_binding.new_commit,
      requiredStartHead,
    );
  }
  assertControl(
    bundleHead(bundle) === unsignedIntent.ref_binding.new_commit,
    'P1_COMMIT_BUNDLE_INVALID',
    'prepared P1 bundle HEAD 与 request commit 不一致',
  );
  maybeFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_BUNDLE',
    'TEST_FAULT_AFTER_P1_COMMIT_BUNDLE',
    'injected failure after P1 commit bundle fsync before sealed intent',
  );
  const intent = sealRecord({
    ...unsignedIntent,
    bundle: {
      file: BUNDLE_FILE,
      sha256: hashFile(bundle),
      head: unsignedIntent.ref_binding.new_commit,
    },
  }, 'intent_sha256');
  intent.prepared_request_sha256 = hashObject({
    request: intent.request,
    task_anchor: intent.task_anchor,
    acceptance_authority: intent.acceptance_authority,
    p1_binding: intent.p1_binding,
    ref_binding: intent.ref_binding,
    bundle: intent.bundle,
    accepted_at: intent.accepted_at,
  });
  delete intent.intent_sha256;
  intent.intent_sha256 = hashObject(intent);
  atomicWriteJson(path.join(staging, INTENT_FILE), intent);
  fsyncDirectory(staging);
  maybeFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_INTENT_SEAL',
    'TEST_FAULT_AFTER_P1_COMMIT_INTENT_SEAL',
    'injected failure after sealed P1 commit staging before install',
  );
  assertControl(
    !fs.existsSync(files.intentDirectory),
    'EVENT_ID_CONFLICT',
    `P1 commit intent ${eventId} 已存在`,
  );
  fs.renameSync(staging, files.intentDirectory);
  fsyncDirectory(files.intents);
  return readP1CommitIntent(root, goalId, taskId, eventId);
}

function stagingResidueInventory(directory) {
  const entries = fs.readdirSync(directory).sort().filter(
    (entry) => (
      entry !== INTENT_FILE && entry !== UNAVAILABLE_CARRIER_FILE
        && entry !== ABANDON_HANDOFF_FILE
    ),
  );
  return entries.map((entry) => {
    const file = path.join(directory, entry);
    assertPrivateFile(file, `P1 abort-only residue ${entry}`);
    return {
      file: entry,
      sha256: hashFile(file),
      size: fs.statSync(file).size,
    };
  });
}

function publishP1CommitAbandonOnlyIntent(options) {
  const {
    cwd,
    root,
    goalId,
    taskId,
    eventId,
    requestSha256,
    unsignedIntent,
  } = options;
  const acceptanceAuthoritySha256 = unsignedIntent
    ? hashObject(unsignedIntent.acceptance_authority)
    : null;
  const files = p1CommitPaths(root, goalId, taskId, eventId);
  const prepared = inspectP1CommitPreparation(
    root,
    goalId,
    taskId,
    eventId,
    requestSha256,
    acceptanceAuthoritySha256,
  );
  assertControl(
    prepared,
    'PREPARED_REQUEST_MISMATCH',
    `P1 commit ${eventId} 缺 exact pre-seal preparation`,
  );
  if (prepared.intent) {
    assertControl(
      prepared.intent.abort_only === true,
      'P1_COMMIT_ALREADY_SEALED',
      `P1 commit ${eventId} 已 seal 为可接受 transaction，不能降级`,
    );
    if (!prepared.staging) return prepared;
    assertControl(
      !fs.existsSync(files.intentDirectory),
      'PREPARED_STAGING_CONFLICT',
      `P1 commit intent ${eventId} final/staging 并存`,
    );
    fs.renameSync(prepared.directory, files.intentDirectory);
    fsyncDirectory(files.intents);
    return readP1CommitIntent(root, goalId, taskId, eventId);
  }
  assertControl(
    prepared.staging === true,
    'PREPARED_REQUEST_MISMATCH',
    `P1 commit ${eventId} 不是 unsealed staging`,
  );
  const existingMarker = preparedUnavailableCarrierMarker(
    prepared,
    unsignedIntent.ref_binding.new_commit,
  );
  const currentResidueInventory = stagingResidueInventory(
    prepared.directory,
  );
  const residueInventory = existingMarker
    ? existingMarker.marker.residue_inventory
    : currentResidueInventory;
  if (existingMarker) {
    assertControl(
      hashObject(currentResidueInventory)
        === hashObject(residueInventory),
      'PREPARED_STAGING_CONFLICT',
      `P1 commit ${eventId} unavailable carrier 后 residue inventory 漂移`,
    );
  }
  const abortBinding = {
    reason_code: 'PRE_SEAL_COMMIT_CARRIER_UNAVAILABLE',
    residue_inventory: residueInventory,
    residue_inventory_sha256: hashObject(residueInventory),
  };
  const unsignedMarker = {
    schema_version: 1,
    kind: UNAVAILABLE_CARRIER_KIND,
    goal_id: goalId,
    task_id: taskId,
    event_id: eventId,
    task_cycle: unsignedIntent.task_cycle,
    request_sha256: requestSha256,
    commit_ref: unsignedIntent.ref_binding.commit_ref,
    commit_sha: unsignedIntent.ref_binding.new_commit,
    task_anchor_sha256: hashObject(unsignedIntent.task_anchor),
    acceptance_authority_sha256: hashObject(
      unsignedIntent.acceptance_authority,
    ),
    reason_code: abortBinding.reason_code,
    residue_inventory: residueInventory,
    residue_inventory_sha256: abortBinding.residue_inventory_sha256,
  };
  const marker = sealRecord(unsignedMarker, 'marker_sha256');
  const markerFile = path.join(
    prepared.directory,
    UNAVAILABLE_CARRIER_FILE,
  );
  if (existingMarker) {
    assertControl(
      hashObject(existingMarker.marker) === hashObject(marker),
      'PREPARED_REQUEST_MISMATCH',
      `P1 commit ${eventId} unavailable carrier 不是 exact request`,
    );
  } else {
    atomicWriteJson(markerFile, marker);
    fsyncDirectory(prepared.directory);
  }
  maybeFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_P1_ABORT_ONLY_MARKER',
    'TEST_FAULT_AFTER_P1_ABORT_ONLY_MARKER',
    'injected failure after P1 ABANDON_ONLY carrier marker',
  );
  const intent = sealRecord({
    ...unsignedIntent,
    abort_only: true,
    abort_binding: abortBinding,
    bundle: {
      file: UNAVAILABLE_CARRIER_FILE,
      sha256: hashFile(markerFile),
      head: unsignedIntent.ref_binding.new_commit,
      available: false,
      reason_code: abortBinding.reason_code,
    },
  }, 'intent_sha256');
  intent.prepared_request_sha256 = hashObject({
    request: intent.request,
    task_anchor: intent.task_anchor,
    acceptance_authority: intent.acceptance_authority,
    p1_binding: intent.p1_binding,
    ref_binding: intent.ref_binding,
    bundle: intent.bundle,
    accepted_at: intent.accepted_at,
  });
  delete intent.intent_sha256;
  intent.intent_sha256 = hashObject(intent);
  atomicWriteJson(path.join(prepared.directory, INTENT_FILE), intent);
  fsyncDirectory(prepared.directory);
  maybeFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_P1_ABORT_ONLY_INTENT',
    'TEST_FAULT_AFTER_P1_ABORT_ONLY_INTENT',
    'injected failure after P1 ABANDON_ONLY intent seal',
  );
  assertControl(
    !fs.existsSync(files.intentDirectory),
    'EVENT_ID_CONFLICT',
    `P1 commit intent ${eventId} 已存在`,
  );
  fs.renameSync(prepared.directory, files.intentDirectory);
  fsyncDirectory(files.intents);
  const installed = readP1CommitIntent(
    root,
    goalId,
    taskId,
    eventId,
  );
  assertControl(
    installed && installed.intent.abort_only === true,
    'CORRUPT_STORE',
    `P1 commit ${eventId} ABANDON_ONLY install 未完成`,
  );
  return installed;
}

function restoreP1CommitObject(cwd, preparation, expectedCommit) {
  if (preparation.staging === true && !preparation.intent) {
    const unavailableCarrier = preparedUnavailableCarrierMarker(
      preparation,
      expectedCommit,
    );
    assertControl(
      !unavailableCarrier,
      'P1_COMMIT_CARRIER_UNAVAILABLE',
      `P1 commit ${expectedCommit} 已 durable 标记 carrier unavailable；只能 seal ABANDON_ONLY`,
    );
    const carrier = unsealedCommitCarrierStatus(
      cwd,
      preparation,
      expectedCommit,
    );
    if (!carrier.objectAvailable) {
      const bundle = carrier.canonicalBundle
        ? preparation.bundle
        : carrier.temporaryBundle
          ? preparation.bundleTemporary
          : null;
      if (bundle) {
        runGit(cwd, ['bundle', 'unbundle', bundle], {
          label: `git bundle unbundle ${bundle}`,
        });
      }
    }
    assertControl(
      commitObjectExists(cwd, expectedCommit),
      'P1_COMMIT_CARRIER_UNAVAILABLE',
      `P1 commit ${expectedCommit} pre-seal object/carrier 均不可恢复`,
    );
    assertControl(
      carrier.canonicalBundle
        || carrier.temporaryBundle
        || readExactRef(cwd, 'HEAD') === expectedCommit,
      'P1_COMMIT_CARRIER_UNAVAILABLE',
      `P1 commit ${expectedCommit} 只有未引用 object，缺 durable carrier/HEAD`,
    );
    return expectedCommit;
  }
  assertControl(
    preparation.intent
      && preparation.intent.abort_only !== true
      && !preparation.abandonHandoff
      && !preparation.abandonHandoffTemporary,
    'P1_COMMIT_ABANDONMENT_REQUIRED',
    `P1 commit ${preparation.intent && preparation.intent.event_id} 已 handoff 给 live FOREMAN；只能运行 p1-abandon-commit`,
  );
  assertControl(
    bundleHead(preparation.files
      ? preparation.files.bundle
      : preparation.bundle) === expectedCommit,
    'P1_COMMIT_BUNDLE_INVALID',
    `P1 bundle HEAD 未绑定 ${expectedCommit}`,
  );
  const bundle = preparation.files
    ? preparation.files.bundle
    : preparation.bundle;
  try {
    runGit(cwd, ['cat-file', '-e', `${expectedCommit}^{commit}`]);
  } catch {
    runGit(cwd, ['bundle', 'unbundle', bundle], {
      label: `git bundle unbundle ${bundle}`,
    });
  }
  runGit(cwd, ['cat-file', '-e', `${expectedCommit}^{commit}`], {
    code: 'P1_COMMIT_OBJECT_MISSING',
    label: `P1 commit object ${expectedCommit}`,
  });
  return expectedCommit;
}

function readExactRef(cwd, ref) {
  try {
    return execFileSync(
      'git',
      ['rev-parse', '--verify', '--quiet', ref],
      {
        cwd,
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
      `git rev-parse --verify ${ref} 失败${
        detail ? `: ${detail}` : ''
      }`,
    );
  }
}

function withPrivateUmask(callback) {
  const previous = process.umask(0o077);
  try {
    return callback();
  } finally {
    process.umask(previous);
  }
}

function assertP1CommitRefName(ref, goalId, taskId, taskCycle) {
  const match = P1_COMMIT_REF_PATTERN.exec(ref);
  assertControl(
    match
      && match[1] === sha256(goalId)
      && match[2] === sha256(taskId)
      && match[3] === String(taskCycle),
    'P1_COMMIT_REF_INVALID',
    `${ref} 不是 exact deterministic loose P1 ref`,
  );
}

function injectP1RefTransactionFault(cwd, stage, label) {
  const faults = {
    'fence-partial': [
      'GOAL_CONTROL_TEST_FAULT_DURING_P1_REF_LOCK_FENCE',
      'TEST_FAULT_DURING_P1_REF_LOCK_FENCE',
    ],
    'fence-durable': [
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_LOCK_FENCE',
      'TEST_FAULT_AFTER_P1_REF_LOCK_FENCE',
    ],
    'packed-lock-linked': [
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_PACKED_LOCK_LINK',
      'TEST_FAULT_AFTER_P1_PACKED_LOCK_LINK',
    ],
    'ref-lock-linked': [
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_LOCK_LINK',
      'TEST_FAULT_AFTER_P1_REF_LOCK_LINK',
    ],
    'canonical-mutated': [
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_CANONICAL_MUTATION',
      'TEST_FAULT_AFTER_P1_REF_CANONICAL_MUTATION',
    ],
    'ref-lock-released': [
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_LOCK_RELEASE',
      'TEST_FAULT_AFTER_P1_REF_LOCK_RELEASE',
    ],
    'packed-lock-released': [
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_PACKED_LOCK_RELEASE',
      'TEST_FAULT_AFTER_P1_PACKED_LOCK_RELEASE',
    ],
    'fence-cleaned': [
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_FENCE_CLEANUP',
      'TEST_FAULT_AFTER_P1_REF_FENCE_CLEANUP',
    ],
  };
  const fault = faults[stage];
  if (!fault) return;
  maybeFault(
    cwd,
    fault[0],
    fault[1],
    `injected failure at ${label} ${stage}`,
  );
}

function publishP1CommitRef(cwd, intent, abandonHandoff = null) {
  assertControl(
    intent.abort_only !== true && !abandonHandoff,
    'P1_COMMIT_ABANDONMENT_REQUIRED',
    `P1 commit ${intent.event_id} 已 handoff，禁止发布 commit ref`,
  );
  const root = controlRoot(cwd);
  const retained = readP1CommitIntent(
    root,
    intent.goal_id,
    intent.task_id,
    intent.event_id,
  );
  assertControl(
    retained
      && retained.staging === false
      && hashObject(retained.intent) === hashObject(intent),
    'P1_COMMIT_INTENT_MISMATCH',
    `P1 commit ${intent.event_id} 缺 exact sealed ref mutation fence anchor`,
  );
  const canonicalIntent = retained.intent;
  const identity = repositoryIdentity(
    cwd,
    canonicalIntent.ref_binding.repository_root,
  );
  assertControl(
    identity.common_git_dir === canonicalIntent.ref_binding.common_git_dir,
    'REPOSITORY_ROOT_MISMATCH',
    'P1 commit intent common git dir 漂移',
  );
  const ref = canonicalIntent.ref_binding.commit_ref;
  const commit = canonicalIntent.ref_binding.new_commit;
  assertP1CommitRefName(
    ref,
    canonicalIntent.goal_id,
    canonicalIntent.task_id,
    canonicalIntent.task_cycle,
  );
  const fenceName = p1CommitRefLockFenceName(canonicalIntent);
  const fenceFile = path.join(
    retained.files.intentDirectory,
    fenceName,
  );
  assertControl(
    retained.refLockFence === null
      || retained.refLockFence === fenceFile,
    'CORRUPT_STORE',
    `P1 commit ${intent.event_id} ref-lock fence path 漂移`,
  );
  executeLooseRefTransaction({
    cwd,
    commonGitDir: identity.common_git_dir,
    ref,
    expectedOld: canonicalIntent.ref_binding.expected_old_ref,
    expectedNew: commit,
    fenceFile,
    fenceInstalledAtEntry: retained.refLockFence === fenceFile,
    reflogPolicy: 'absent',
    assertRefPolicy(candidate) {
      assertP1CommitRefName(
        candidate,
        canonicalIntent.goal_id,
        canonicalIntent.task_id,
        canonicalIntent.task_cycle,
      );
    },
    onStage(stage) {
      injectP1RefTransactionFault(
        cwd,
        stage,
        `P1 publish ${ref}`,
      );
    },
    codes: {
      refConflict: 'P1_COMMIT_REF_CONFLICT',
      lockConflict: 'P1_COMMIT_REF_LOCK_CONFLICT',
      fenceConflict: 'CORRUPT_STORE',
      invalidRef: 'P1_COMMIT_REF_INVALID',
    },
    label: `P1 publish ${ref}`,
  });
  assertControl(
    readExactRef(cwd, ref) === commit,
    'P1_COMMIT_REF_CONFLICT',
    `${ref} CAS publish 后未指向 ${commit}`,
  );
  return ref;
}

function installP1CommitAbandonHandoffTemporary(options) {
  const {
    cwd,
    directory,
    intent,
    temporary: retainedTemporary,
  } = options;
  const label = `P1 commit ${intent.event_id} abandon handoff`;
  const target = path.join(directory, ABANDON_HANDOFF_FILE);
  let temporary = inspectP1CommitAbandonHandoffTemporary(
    directory,
    retainedTemporary.name,
    intent,
    `${label} temporary`,
  );
  assertControl(
    temporary.observedActualRef
      === retainedTemporary.observedActualRef
      && temporary.expected.handoff_sha256
        === retainedTemporary.expected.handoff_sha256,
    'PREPARED_REQUEST_MISMATCH',
    `${label} temporary commitment 漂移`,
  );
  const body = sealedRecordBytes(temporary.expected);
  let descriptor;
  try {
    const before = fs.lstatSync(temporary.file);
    descriptor = fs.openSync(
      temporary.file,
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
      'CORRUPT_STORE',
      `${label} temporary open 时 inode/mode 漂移`,
    );
    if (!temporary.complete) {
      fs.ftruncateSync(descriptor, 0);
      const firstChunkLength = Math.max(
        1,
        Math.floor(body.length / 2),
      );
      fs.writeSync(
        descriptor,
        body,
        0,
        firstChunkLength,
        0,
      );
      maybeFault(
        cwd,
        'GOAL_CONTROL_TEST_FAULT_DURING_P1_HANDOFF_TEMP_WRITE',
        'TEST_FAULT_DURING_P1_HANDOFF_TEMP_WRITE',
        'injected failure during P1 handoff temporary write',
      );
      fs.writeSync(
        descriptor,
        body,
        firstChunkLength,
        body.length - firstChunkLength,
        firstChunkLength,
      );
      maybeFault(
        cwd,
        'GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_TEMP_WRITE',
        'TEST_FAULT_AFTER_P1_HANDOFF_TEMP_WRITE',
        'injected failure after P1 handoff temporary write',
      );
    }
    fs.fsyncSync(descriptor);
    maybeFault(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_TEMP_FSYNC',
      'TEST_FAULT_AFTER_P1_HANDOFF_TEMP_FSYNC',
      'injected failure after P1 handoff temporary fsync',
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  temporary = inspectP1CommitAbandonHandoffTemporary(
    directory,
    temporary.name,
    intent,
    `${label} temporary`,
  );
  assertControl(
    temporary.complete,
    'CORRUPT_STORE',
    `${label} temporary write 未完成`,
  );
  if (!fs.existsSync(target)) {
    try {
      fs.linkSync(temporary.file, target);
    } catch (error) {
      assertControl(
        error && error.code === 'EEXIST',
        'PREPARED_STAGING_CONFLICT',
        `${label} no-clobber promotion 失败: ${error.message}`,
      );
    }
  }
  const canonical = readP1CommitAbandonHandoff(
    directory,
    intent,
    label,
  );
  assertControl(
    canonical
      && canonical.handoff_sha256
        === temporary.expected.handoff_sha256
      && sameFileIdentity(target, temporary.file),
    'CORRUPT_STORE',
    `${label} canonical 被 foreign/racing inode 占用`,
  );
  maybeFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_LINK',
    'TEST_FAULT_AFTER_P1_HANDOFF_LINK',
    'injected failure after P1 handoff no-clobber link',
  );
  fsyncDirectory(directory);
  maybeFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_PROMOTION',
    'TEST_FAULT_AFTER_P1_HANDOFF_PROMOTION',
    'injected failure after durable P1 handoff promotion',
  );
  const promotedTemporary = inspectP1CommitAbandonHandoffTemporary(
    directory,
    temporary.name,
    intent,
    `${label} promoted temporary`,
  );
  assertControl(
    promotedTemporary.complete
      && sameFileIdentity(target, promotedTemporary.file),
    'CORRUPT_STORE',
    `${label} cleanup 前 canonical/temporary inode 漂移`,
  );
  fs.unlinkSync(promotedTemporary.file);
  fsyncDirectory(directory);
  return canonical;
}

function createP1CommitAbandonHandoffTemporary(options) {
  const {
    cwd,
    directory,
    intent,
    expected,
  } = options;
  const name = abandonHandoffTemporaryName(expected);
  const file = path.join(directory, name);
  let descriptor;
  try {
    descriptor = fs.openSync(file, 'wx', 0o600);
    fsyncDirectory(directory);
    maybeFault(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_TEMP_CREATE',
      'TEST_FAULT_AFTER_P1_HANDOFF_TEMP_CREATE',
      'injected failure after durable empty P1 handoff temporary create',
    );
  } catch (error) {
    if (error && error.code === 'EEXIST') {
      throw new ControlError(
        'PREPARED_STAGING_CONFLICT',
        `P1 commit ${intent.event_id} handoff temporary 已被并发占用`,
      );
    }
    throw error;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  return inspectP1CommitAbandonHandoffTemporary(
    directory,
    name,
    intent,
    `P1 commit ${intent.event_id} abandon handoff temporary`,
  );
}

function publishP1CommitAbandonHandoff(options) {
  const {
    cwd,
    root,
    goalId,
    taskId,
    preparation,
  } = options;
  assertControl(
    preparation
      && preparation.intent
      && preparation.intent.abort_only !== true
      && preparation.intent.goal_id === goalId
      && preparation.intent.task_id === taskId
      && !acceptedP1Event(
        root,
        goalId,
        taskId,
        preparation.intent.event_id,
      ),
    'P1_COMMIT_ABANDONMENT_REQUIRED',
    '只有未接受的 sealed normal P1 intent 可以生成 ABANDON_HANDOFF',
  );
  const intent = preparation.intent;
  const directory = preparation.directory
    || preparation.files.intentDirectory;
  let retained = readP1CommitIntentDirectory(
    directory,
    goalId,
    taskId,
    intent.event_id,
    `P1 commit ${intent.event_id}`,
  );
  assertControl(
    retained.intent.intent_sha256 === intent.intent_sha256,
    'PREPARED_REQUEST_MISMATCH',
    `P1 commit ${intent.event_id} handoff intent 漂移`,
  );
  if (!retained.abandonHandoffTemporary && !retained.abandonHandoff) {
    const current = readExactRef(
      intent.ref_binding.repository_root,
      intent.ref_binding.commit_ref,
    );
    const expected = expectedP1CommitAbandonHandoff(
      intent,
      current,
    );
    const temporary = createP1CommitAbandonHandoffTemporary({
      cwd,
      directory,
      intent,
      expected,
    });
    retained = {
      ...retained,
      abandonHandoffTemporary: temporary,
    };
  }
  let handoff = retained.abandonHandoff;
  if (retained.abandonHandoffTemporary) {
    handoff = installP1CommitAbandonHandoffTemporary({
      cwd,
      directory,
      intent,
      temporary: retained.abandonHandoffTemporary,
    });
  }
  assertControl(
    handoff,
    'CORRUPT_STORE',
    `P1 commit ${intent.event_id} abandon handoff install 缺失`,
  );
  if (preparation.staging === true) {
    const files = p1CommitPaths(
      root,
      goalId,
      taskId,
      intent.event_id,
    );
    assertControl(
      !fs.existsSync(files.intentDirectory),
      'PREPARED_STAGING_CONFLICT',
      `P1 commit intent ${intent.event_id} final/staging 并存`,
    );
    fs.renameSync(preparation.directory, files.intentDirectory);
    fsyncDirectory(files.intents);
  }
  const installed = readP1CommitIntent(
    root,
    goalId,
    taskId,
    intent.event_id,
  );
  assertControl(
    installed
      && installed.abandonHandoff
      && !installed.abandonHandoffTemporary
      && installed.abandonHandoff.handoff_sha256
        === handoff.handoff_sha256,
    'CORRUPT_STORE',
    `P1 commit ${intent.event_id} abandon handoff install 未完成`,
  );
  return installed;
}

function p1CommitAbandonmentHandoffSha256(prepared) {
  assertControl(
    prepared && prepared.intent,
    'P1_COMMIT_INTENT_MISMATCH',
    'P1 abandonment 缺 retained P1 intent',
  );
  assertControl(
    !prepared.abandonHandoffTemporary,
    'P1_COMMIT_ABANDONMENT_REQUIRED',
    `P1 commit ${prepared.intent.event_id} handoff 尚未完成 exact promotion cleanup`,
  );
  if (prepared.intent.abort_only === true) {
    return prepared.intent.intent_sha256;
  }
  assertControl(
    prepared.abandonHandoff
      && /^sha256:[0-9a-f]{64}$/.test(
        prepared.abandonHandoff.handoff_sha256,
      ),
    'P1_COMMIT_ABANDONMENT_REQUIRED',
    `P1 commit ${prepared.intent.event_id} 缺 immutable ABANDON_HANDOFF`,
  );
  return prepared.abandonHandoff.handoff_sha256;
}

function p1CommitRefIsAbandoned(current, prepared) {
  if (current === null) return true;
  return Boolean(
    prepared
      && (
        (
          prepared.intent
            && current === prepared.intent.ref_binding.new_commit
        )
          || (
            prepared.abandonHandoff
              && current
                === prepared.abandonHandoff.ref_binding.observed_actual_ref
          )
      ),
  );
}

function readP1CommitReceipt(root, goalId, taskId, eventId) {
  const files = p1CommitPaths(root, goalId, taskId, eventId);
  if (!fs.existsSync(files.receipt)) return null;
  const receipt = readSealedRecord(
    files.receipt,
    'receipt_sha256',
    `P1 commit completion ${eventId}`,
  );
  assertControl(
    receipt.schema_version === 1
      && receipt.kind === RECEIPT_KIND
      && receipt.goal_id === goalId
      && receipt.task_id === taskId
      && receipt.event_id === eventId
      && typeof receipt.intent_sha256 === 'string'
      && typeof receipt.request_sha256 === 'string'
      && typeof receipt.accepted_event_sha256 === 'string'
      && typeof receipt.commit_ref === 'string'
      && /^[0-9a-f]{40}$/.test(receipt.commit_sha),
    'CORRUPT_STORE',
    `P1 commit completion ${eventId} binding 非法`,
  );
  return receipt;
}

function expectedP1CommitReceipt(
  goalId,
  taskId,
  intent,
  acceptedEvent,
) {
  return sealRecord({
    schema_version: 1,
    kind: RECEIPT_KIND,
    goal_id: goalId,
    task_id: taskId,
    task_cycle: intent.task_cycle,
    event_id: intent.event_id,
    request_sha256: intent.request_sha256,
    intent_sha256: intent.intent_sha256,
    accepted_event_sha256: acceptedEvent.event_sha256,
    commit_ref: intent.ref_binding.commit_ref,
    commit_sha: intent.ref_binding.new_commit,
    completed_at: acceptedEvent.accepted_at,
  }, 'receipt_sha256');
}

function assertExactSealedAtomicTemporary(options) {
  const {
    directory,
    temporaryName,
    target,
    sealKey,
    expected,
    identityFields,
    bindingFields,
    label,
  } = options;
  assertControl(
    path.dirname(target) === directory
      && atomicTemporaryBase(temporaryName) === path.basename(target),
    'PREPARED_STAGING_CONFLICT',
    `${label} 不是 target 的 atomic temporary`,
  );
  const inspected = inspectSealedAtomicTemporary(
    path.join(directory, temporaryName),
    sealKey,
    label,
  );
  if (inspected.complete) {
    assertExactRecoveryRecord(
      inspected.record,
      expected,
      identityFields,
      bindingFields,
      label,
    );
  }
  return inspected;
}

function verifyP1CommitRecoveryLineage(
  root,
  goalId,
  taskId,
  eventId,
  requestSha256,
  acceptedEvent = null,
) {
  const preparation = inspectP1CommitPreparation(
    root,
    goalId,
    taskId,
    eventId,
    requestSha256,
  );
  if (!preparation) return null;
  if (!preparation.intent) return preparation;

  const intent = preparation.intent;
  if (intent.abort_only !== true) {
    const bundle = preparation.files
      ? preparation.files.bundle
      : preparation.bundle;
    assertControl(
      bundleHead(bundle) === intent.ref_binding.new_commit,
      'P1_COMMIT_BUNDLE_INVALID',
      `P1 bundle HEAD 未绑定 ${intent.ref_binding.new_commit}`,
    );
  }
  const ref = readExactRef(
    intent.ref_binding.repository_root,
    intent.ref_binding.commit_ref,
  );
  const handoffRef = preparation.abandonHandoff
    ? preparation.abandonHandoff.ref_binding.observed_actual_ref
    : null;
  assertControl(
    acceptedEvent
      ? (
        !preparation.abandonHandoff
          && !preparation.abandonHandoffTemporary
          && (
            ref === null
              || ref === intent.ref_binding.new_commit
          )
      )
      : preparation.abandonHandoff
          && !preparation.abandonHandoffTemporary
        ? (
          ref === null
            || ref === intent.ref_binding.new_commit
            || ref === handoffRef
        )
        : (
          ref === null
            || /^[0-9a-f]{40}$/.test(ref)
        ),
    'P1_COMMIT_REF_CONFLICT',
    `${intent.ref_binding.commit_ref} 指向 ${ref}，与 intent 冲突`,
  );
  if (!acceptedEvent) return preparation;

  assertControl(
    acceptedEvent.type === 'P1_COMMITTED'
      && acceptedEvent.event_id === eventId
      && acceptedEvent.goal_id === goalId
      && acceptedEvent.task_id === taskId
      && acceptedEvent.input_sha256 === requestSha256,
    'CORRUPT_STORE',
    `accepted P1 transaction ${eventId} 不是 exact request`,
  );
  const expected = expectedP1CommitReceipt(
    goalId,
    taskId,
    intent,
    acceptedEvent,
  );
  const files = p1CommitPaths(root, goalId, taskId, eventId);
  const inventory = receiptInventory(
    files.receipts,
    `P1 commit receipts ${taskId}`,
  );
  const temporaryName = inventory.temporaries.get(eventId);
  if (temporaryName) {
    assertExactSealedAtomicTemporary({
      directory: files.receipts,
      temporaryName,
      target: files.receipt,
      sealKey: 'receipt_sha256',
      expected,
      identityFields: ['goal_id', 'task_id', 'event_id'],
      bindingFields: [
        'request_sha256',
        'intent_sha256',
        'accepted_event_sha256',
      ],
      label: `P1 commit receipt temporary ${eventId}`,
    });
  }
  const receipt = readP1CommitReceipt(
    root,
    goalId,
    taskId,
    eventId,
  );
  if (receipt) {
    assertExactRecoveryRecord(
      receipt,
      expected,
      ['goal_id', 'task_id', 'event_id'],
      [
        'request_sha256',
        'intent_sha256',
        'accepted_event_sha256',
      ],
      `P1 commit completion ${eventId}`,
    );
  }
  return preparation;
}

function completeP1CommitTransaction(
  root,
  goalId,
  taskId,
  intent,
  acceptedEvent,
) {
  assertControl(
    intent.abort_only !== true,
    'P1_COMMIT_ABANDONMENT_REQUIRED',
    `P1 commit ${intent.event_id} 已 seal ABANDON_ONLY，禁止生成 completion`,
  );
  const files = p1CommitPaths(
    root,
    goalId,
    taskId,
    intent.event_id,
  );
  const expected = expectedP1CommitReceipt(
    goalId,
    taskId,
    intent,
    acceptedEvent,
  );
  ensurePrivateDirectory(files.receipts);
  const inventory = receiptInventory(
    files.receipts,
    `P1 commit receipts ${taskId}`,
  );
  const receiptTemporary = inventory.temporaries.get(intent.event_id);
  if (receiptTemporary) {
    recoverSealedAtomicTemporary({
      directory: files.receipts,
      temporaryName: receiptTemporary,
      target: files.receipt,
      sealKey: 'receipt_sha256',
      expected,
      identityFields: ['goal_id', 'task_id', 'event_id'],
      bindingFields: [
        'request_sha256',
        'intent_sha256',
        'accepted_event_sha256',
      ],
      label: `P1 commit receipt temporary ${intent.event_id}`,
    });
  }
  const existing = readP1CommitReceipt(
    root,
    goalId,
    taskId,
    intent.event_id,
  );
  if (existing) {
    assertControl(
      hashObject(existing) === hashObject(expected),
      'CORRUPT_STORE',
      `P1 commit completion ${intent.event_id} 与 exact retry 不一致`,
    );
  } else {
    atomicWriteJson(files.receipt, expected);
  }
  return expected;
}

function acceptedP1Event(root, goalId, taskId, eventId) {
  for (const file of acceptedEventFiles(root, goalId, taskId)) {
    const event = readJson(file, `accepted event ${path.basename(file)}`);
    if (event.event_id === eventId) return event;
  }
  return null;
}

function assertP1AbandonmentLedgerBinding(
  accepted,
  prepared,
  abandonment,
  receipt,
) {
  const intent = abandonment.intent;
  const anchor = intent.task_anchor;
  const authority = intent.foreman_authority;
  const expectedPayload = {
    prepared_event_id: intent.prepared_event_id,
    task_cycle: prepared.intent.task_cycle,
    p1_intent_sha256: prepared.intent.intent_sha256,
    abandon_intent_sha256: intent.intent_sha256,
    abandon_request_sha256: intent.request_sha256,
    abandon_receipt_sha256: receipt.receipt_sha256,
    commit_ref: prepared.intent.ref_binding.commit_ref,
    commit_sha: prepared.intent.ref_binding.new_commit,
    predecessor_event_sha256: anchor.prior_event_sha256,
    reason: intent.request.reason,
    incident_ref: intent.request.incident_ref,
  };
  const acceptedAuthority = accepted.goal_foreman_authority;
  assertControl(
    accepted.type === 'P1_COMMIT_ABANDONED'
      && accepted.event_id === intent.request.abandon_event_id
      && accepted.goal_id === intent.goal_id
      && accepted.task_id === intent.task_id
      && accepted.actor
      && accepted.actor.role === 'FOREMAN'
      && accepted.actor.thread_id === authority.thread_id
      && accepted.actor.host_id === authority.host_id
      && accepted.actor_sequence === anchor.foreman_prior_actor_sequence + 1
      && accepted.expected_state_revision === anchor.state_revision
      && accepted.control_epoch === anchor.control_epoch
      && accepted.packet
      && accepted.packet.revision === anchor.packet.revision
      && accepted.packet.sha256 === anchor.packet.sha256
      && accepted.base_head === anchor.base_head
      && accepted.full_head === anchor.full_head
      && accepted.previous_event_sha256 === anchor.prior_event_sha256
      && accepted.accepted_at === intent.accepted_at
      && hashObject(accepted.payload) === hashObject(expectedPayload)
      && acceptedAuthority
      && acceptedAuthority.thread_id === authority.thread_id
      && acceptedAuthority.host_id === authority.host_id
      && acceptedAuthority.attempt === authority.attempt
      && acceptedAuthority.capability_file === authority.capability_file
      && acceptedAuthority.capability_sha256 === authority.capability_sha256
      && acceptedAuthority.lease_until === authority.lease_until,
    'CORRUPT_STORE',
    `P1 abandonment ${intent.prepared_event_id} 与 append-only ledger anchor 漂移`,
  );
}

function readAbandonmentIntent(root, goalId, taskId, preparedEventId) {
  const files = p1CommitPaths(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  if (!fs.existsSync(files.abandonmentDirectory)) return null;
  assertPrivateDirectory(
    files.abandonmentDirectory,
    `P1 abandonment ${preparedEventId}`,
  );
  const entries = fs.readdirSync(files.abandonmentDirectory).sort();
  const completionTemporaries = entries.filter(
    (entry) => atomicTemporaryBase(entry) === COMPLETION_FILE,
  );
  const known = new Set([
    INTENT_FILE,
    ...(entries.includes(COMPLETION_FILE) ? [COMPLETION_FILE] : []),
    ...completionTemporaries,
  ]);
  const unknown = entries.filter((entry) => !known.has(entry));
  assertControl(
    unknown.length === 0
      && entries.length >= 1
      && entries.length
        === 1
          + (
            entries.includes(COMPLETION_FILE)
              || completionTemporaries.length > 0
              ? 1
              : 0
          )
      && entries.includes(INTENT_FILE)
      && completionTemporaries.length <= 1
      && !(
        entries.includes(COMPLETION_FILE)
          && completionTemporaries.length > 0
      ),
    'CORRUPT_STORE',
    `P1 abandonment ${preparedEventId} inventory 非协议状态: ${
      entries.join(', ')
    }`,
  );
  for (const entry of entries) {
    assertPrivateFile(
      path.join(files.abandonmentDirectory, entry),
      `P1 abandonment ${preparedEventId}/${entry}`,
    );
  }
  const intent = readSealedRecord(
    files.abandonmentIntent,
    'intent_sha256',
    `P1 abandonment intent ${preparedEventId}`,
  );
  assertControl(
    intent.schema_version === 1
      && intent.kind === ABANDON_INTENT_KIND
      && intent.goal_id === goalId
      && intent.task_id === taskId
      && intent.prepared_event_id === preparedEventId
      && intent.request
      && intent.request_sha256 === hashObject(intent.request)
      && intent.task_anchor
      && Number.isInteger(intent.task_anchor.task_cycle)
      && intent.foreman_authority
      && typeof intent.accepted_at === 'string'
      && Number.isFinite(Date.parse(intent.accepted_at))
      && intent.prepared_request_sha256 === hashObject({
        request: intent.request,
        task_anchor: intent.task_anchor,
        foreman_authority: intent.foreman_authority,
        p1_intent_sha256: intent.p1_intent_sha256,
      }),
    'CORRUPT_STORE',
    `P1 abandonment intent ${preparedEventId} binding 非法`,
  );
  let completion = null;
  if (entries.includes(COMPLETION_FILE)) {
    completion = readSealedRecord(
      files.abandonmentCompletion,
      'completion_sha256',
      `P1 abandonment completion ${preparedEventId}`,
    );
    assertControl(
      completion.schema_version === 1
        && completion.kind === ABANDON_RECEIPT_KIND
        && completion.prepared_event_id === preparedEventId
        && completion.intent_sha256 === intent.intent_sha256
        && completion.request_sha256 === intent.request_sha256,
      'CORRUPT_STORE',
      `P1 abandonment completion ${preparedEventId} binding 非法`,
    );
  }
  return {
    intent,
    completion,
    files,
    completionTemporary: completionTemporaries[0] || null,
  };
}

function inspectP1Abandonment(
  root,
  goalId,
  taskId,
  preparedEventId,
) {
  const canonical = readAbandonmentIntent(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  if (canonical) return { ...canonical, staging: false };
  const prepared = preparedAbandonmentCandidates(
    root,
    goalId,
    taskId,
  ).find(
    (candidate) => (
      candidate.intent
        ? candidate.intent.prepared_event_id === preparedEventId
        : candidate.prepared_event_id_sha256
          === `sha256:${sha256(preparedEventId)}`
    ),
  );
  return prepared && prepared.intent
    ? { ...prepared, staging: true }
    : null;
}

function preparedAbandonmentDirectoryName(
  preparedEventId,
  requestSha256,
  foremanAuthoritySha256,
) {
  return `.init-abandon-${sha256(preparedEventId)}-${
    normalizeHash(
      requestSha256,
      'P1 abandonment request sha256',
    ).slice('sha256:'.length)
  }-${
    normalizeHash(
      foremanAuthoritySha256,
      'P1 abandonment FOREMAN authority sha256',
    ).slice('sha256:'.length)
  }`;
}

function readP1AbandonmentReceipt(
  root,
  goalId,
  taskId,
  preparedEventId,
) {
  const files = p1CommitPaths(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  if (!fs.existsSync(files.abandonmentReceipt)) return null;
  const receipt = readSealedRecord(
    files.abandonmentReceipt,
    'receipt_sha256',
    `P1 abandonment receipt ${preparedEventId}`,
  );
  assertControl(
    receipt.schema_version === 1
      && receipt.kind === ABANDON_RECEIPT_KIND
      && receipt.goal_id === goalId
      && receipt.task_id === taskId
      && receipt.prepared_event_id === preparedEventId
      && typeof receipt.abandon_event_id === 'string'
      && typeof receipt.request_sha256 === 'string'
      && typeof receipt.p1_intent_sha256 === 'string'
      && typeof receipt.commit_ref === 'string'
      && /^[0-9a-f]{40}$/.test(receipt.commit_sha),
    'CORRUPT_STORE',
    `P1 abandonment receipt ${preparedEventId} binding 非法`,
  );
  return receipt;
}

function preparedAbandonmentCandidates(root, goalId, taskId) {
  const paths = p1CommitTaskPaths(root, goalId, taskId);
  if (!fs.existsSync(paths.abandonments)) return [];
  assertPrivateDirectory(
    paths.abandonments,
    `P1 commit abandonments ${taskId}`,
  );
  const candidates = [];
  for (const name of fs.readdirSync(paths.abandonments).sort()) {
    if (!name.startsWith('.init-abandon-')) continue;
    const match = PREPARED_ABANDON_PATTERN.exec(name);
    assertControl(
      match,
      'PREPARED_STAGING_CONFLICT',
      `P1 abandonment 发现 foreign/lookalike staging ${name}`,
    );
    const directory = path.join(paths.abandonments, name);
    assertPrivateDirectory(directory, `P1 abandonment staging ${name}`);
    const entries = fs.readdirSync(directory).sort();
    const intentTemporaries = entries.filter(
      (entry) => atomicTemporaryBase(entry) === INTENT_FILE,
    );
    const known = new Set([
      ...intentTemporaries,
      ...(entries.includes(INTENT_FILE) ? [INTENT_FILE] : []),
    ]);
    const unknown = entries.filter((entry) => !known.has(entry));
    assertControl(
      unknown.length === 0
        && intentTemporaries.length <= 1
        && !(
          entries.includes(INTENT_FILE)
            && intentTemporaries.length > 0
        )
        && entries.length <= 1,
      'PREPARED_STAGING_INVALID',
      `P1 abandonment staging ${name} inventory 非协议状态: ${
        entries.join(', ')
      }`,
    );
    for (const entry of entries) {
      assertPrivateFile(
        path.join(directory, entry),
        `P1 abandonment staging ${name}/${entry}`,
      );
    }
    const intentFile = entries.includes(INTENT_FILE)
      ? path.join(directory, INTENT_FILE)
      : null;
    let intent = null;
    if (intentFile) {
      intent = readSealedRecord(
        intentFile,
        'intent_sha256',
        `P1 abandonment staging ${name}`,
      );
      assertControl(
        intent.schema_version === 1
          && intent.kind === ABANDON_INTENT_KIND
          && intent.goal_id === goalId
          && intent.task_id === taskId
          && intent.request
          && intent.request_sha256 === hashObject(intent.request)
          && `sha256:${match[1]}` === `sha256:${
            sha256(intent.prepared_event_id)
          }`
          && `sha256:${match[2]}` === intent.request_sha256
          && `sha256:${match[3]}` === hashObject(
            intent.foreman_authority,
          ),
        'CORRUPT_STORE',
        `P1 abandonment staging ${name} binding 非法`,
      );
    }
    candidates.push({
      directory,
      name,
      entries,
      intent,
      intentFile,
      prepared_event_id_sha256: `sha256:${match[1]}`,
      request_sha256: `sha256:${match[2]}`,
      foreman_authority_sha256: `sha256:${match[3]}`,
      stage: intent
        ? 'SEALED_STAGING'
        : (intentTemporaries.length ? 'INTENT_TEMP' : 'EMPTY_STAGING'),
    });
  }
  assertControl(
    candidates.length <= 1,
    'CORRUPT_STORE',
    `task ${taskId} 同时存在多个 P1 abandonment staging`,
  );
  return candidates;
}

function cleanupExactUnsealedAbandonmentStaging(
  root,
  goalId,
  taskId,
  preparedEventId,
  requestSha256,
  foremanAuthoritySha256,
) {
  const expectedName = preparedAbandonmentDirectoryName(
    preparedEventId,
    requestSha256,
    foremanAuthoritySha256,
  );
  const candidates = preparedAbandonmentCandidates(
    root,
    goalId,
    taskId,
  );
  if (candidates.length === 0) return false;
  const prepared = candidates[0];
  assertControl(
    !prepared.intent && prepared.name === expectedName,
    'PREPARED_REQUEST_MISMATCH',
    `P1 abandonment ${preparedEventId} staging 不是 exact unsealed request`,
  );
  removeValidatedFiles(
    prepared.directory,
    prepared.entries,
    `P1 abandonment staging ${prepared.name}`,
  );
  return true;
}

function inspectExactUnsealedAbandonmentStaging(
  root,
  goalId,
  taskId,
  preparedEventId,
  requestSha256,
  foremanAuthoritySha256 = null,
) {
  const candidates = preparedAbandonmentCandidates(
    root,
    goalId,
    taskId,
  );
  if (candidates.length === 0 || candidates[0].intent) return null;
  const candidate = candidates[0];
  assertControl(
    candidate.prepared_event_id_sha256
      === `sha256:${sha256(preparedEventId)}`
      && candidate.request_sha256
        === normalizeHash(
          requestSha256,
          'P1 abandonment request sha256',
        )
      && (
        !foremanAuthoritySha256
          || candidate.foreman_authority_sha256
            === normalizeHash(
              foremanAuthoritySha256,
              'P1 abandonment FOREMAN authority sha256',
            )
      ),
    'PREPARED_REQUEST_MISMATCH',
    `P1 abandonment ${preparedEventId} staging 不是 exact request`,
  );
  return candidate;
}

function hasExactUnsealedAbandonmentStaging(
  root,
  goalId,
  taskId,
  preparedEventId,
  requestSha256,
  foremanAuthoritySha256 = null,
) {
  return Boolean(inspectExactUnsealedAbandonmentStaging(
    root,
    goalId,
    taskId,
    preparedEventId,
    requestSha256,
    foremanAuthoritySha256,
  ));
}

function publishP1AbandonmentIntent(
  cwd,
  root,
  goalId,
  taskId,
  preparedEventId,
  unsignedIntent,
) {
  const files = p1CommitPaths(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  withPrivateUmask(() => ensureDir(files.abandonments));
  ensurePrivateDirectory(files.abandonments);
  const foremanAuthoritySha256 = hashObject(
    unsignedIntent.foreman_authority,
  );
  const stagingName = preparedAbandonmentDirectoryName(
    preparedEventId,
    unsignedIntent.request_sha256,
    foremanAuthoritySha256,
  );
  const prepared = preparedAbandonmentCandidates(
    root,
    goalId,
    taskId,
  );
  if (prepared.length === 1) {
    if (!prepared[0].intent) {
      assertControl(
        prepared[0].name === stagingName,
        'PREPARED_REQUEST_MISMATCH',
        `P1 abandonment ${preparedEventId} staging 不是 exact request`,
      );
      cleanupExactUnsealedAbandonmentStaging(
        root,
        goalId,
        taskId,
        preparedEventId,
        unsignedIntent.request_sha256,
        foremanAuthoritySha256,
      );
    } else {
    assertControl(
      prepared[0].name === stagingName
        && hashObject(prepared[0].intent)
          === hashObject(sealRecord(unsignedIntent, 'intent_sha256')),
      'PREPARED_REQUEST_MISMATCH',
      `P1 abandonment ${preparedEventId} staging 不是 exact request`,
    );
    assertControl(
      !fs.existsSync(files.abandonmentDirectory),
      'PREPARED_STAGING_CONFLICT',
      `P1 abandonment ${preparedEventId} final/staging 并存`,
    );
    fs.renameSync(
      prepared[0].directory,
      files.abandonmentDirectory,
    );
    fsyncDirectory(files.abandonments);
    return readAbandonmentIntent(
      root,
      goalId,
      taskId,
      preparedEventId,
    );
    }
  }
  const existing = readAbandonmentIntent(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  if (existing) return existing;
  const staging = path.join(files.abandonments, stagingName);
  assertControl(
    !fs.existsSync(staging)
      && !fs.existsSync(files.abandonmentDirectory),
    'PREPARED_STAGING_CONFLICT',
    `P1 abandonment ${preparedEventId} 已存在`,
  );
  fs.mkdirSync(staging, { mode: 0o700 });
  fsyncDirectory(files.abandonments);
  maybeFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_P1_ABANDON_STAGING_DIRECTORY',
    'TEST_FAULT_AFTER_P1_ABANDON_STAGING_DIRECTORY',
    'injected failure after empty P1 abandonment staging directory fsync',
  );
  const intent = sealRecord(unsignedIntent, 'intent_sha256');
  atomicWriteJson(path.join(staging, INTENT_FILE), intent);
  fsyncDirectory(staging);
  maybeFault(
    cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_P1_ABANDON_INTENT_SEAL',
    'TEST_FAULT_AFTER_P1_ABANDON_INTENT_SEAL',
    'injected failure after sealed P1 abandonment staging',
  );
  fs.renameSync(staging, files.abandonmentDirectory);
  fsyncDirectory(files.abandonments);
  return readAbandonmentIntent(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
}

function expectedP1AbandonmentCompletion(goalId, taskId, intent) {
  return sealRecord({
    schema_version: 1,
    kind: ABANDON_RECEIPT_KIND,
    goal_id: goalId,
    task_id: taskId,
    task_cycle: intent.task_anchor.task_cycle,
    prepared_event_id: intent.prepared_event_id,
    abandon_event_id: intent.request.abandon_event_id,
    request_sha256: intent.request_sha256,
    intent_sha256: intent.intent_sha256,
    p1_intent_sha256: intent.p1_intent_sha256,
    commit_ref: intent.request.expected_commit_ref,
    commit_sha: intent.request.expected_ref_head,
    incident_ref: intent.request.incident_ref,
    reason: intent.request.reason,
    completed_at: intent.accepted_at,
  }, 'completion_sha256');
}

function expectedP1AbandonmentReceipt(completion) {
  const receipt = { ...completion };
  delete receipt.completion_sha256;
  delete receipt.receipt_sha256;
  receipt.receipt_sha256 = hashObject(receipt);
  return receipt;
}

function verifyP1AbandonmentRecoveryLineage(
  root,
  goalId,
  taskId,
  preparedEventId,
  abandonEventId,
  requestSha256,
) {
  const prepared = readP1CommitIntent(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  if (!prepared) return null;
  const abandonment = inspectP1Abandonment(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  if (!abandonment) return null;
  const intent = abandonment.intent;
  assertControl(
    intent.goal_id === goalId
      && intent.task_id === taskId
      && intent.prepared_event_id === preparedEventId
      && intent.request.abandon_event_id === abandonEventId
      && intent.request.expected_intent_sha256
        === prepared.intent.intent_sha256
      && intent.request.expected_commit_ref
        === prepared.intent.ref_binding.commit_ref
      && intent.request.expected_ref_head
        === prepared.intent.ref_binding.new_commit
      && intent.request.p1_abandon_handoff_sha256
        === p1CommitAbandonmentHandoffSha256(prepared)
      && intent.request_sha256 === requestSha256
      && hashObject(intent.request) === requestSha256
      && intent.p1_intent_sha256 === prepared.intent.intent_sha256
      && intent.task_anchor.task_cycle === prepared.intent.task_cycle,
    'PREPARED_REQUEST_MISMATCH',
    `P1 abandonment ${abandonEventId} 不是 exact retained request`,
  );
  if (prepared.intent.abort_only !== true) {
    assertControl(
      bundleHead(prepared.files.bundle)
        === prepared.intent.ref_binding.new_commit,
      'P1_COMMIT_BUNDLE_INVALID',
      `P1 bundle HEAD 未绑定 ${prepared.intent.ref_binding.new_commit}`,
    );
  }
  const ref = readExactRef(
    prepared.intent.ref_binding.repository_root,
    prepared.intent.ref_binding.commit_ref,
  );
  assertControl(
    ref === null
      || ref === prepared.intent.ref_binding.new_commit
      || (
        prepared.abandonHandoff
          && ref
            === prepared.abandonHandoff.ref_binding.observed_actual_ref
      ),
    'P1_COMMIT_REF_CONFLICT',
    `${prepared.intent.ref_binding.commit_ref} 指向 ${ref}，与 abandonment 冲突`,
  );

  const files = p1CommitPaths(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  const completion = expectedP1AbandonmentCompletion(
    goalId,
    taskId,
    intent,
  );
  if (abandonment.completion) {
    assertExactRecoveryRecord(
      abandonment.completion,
      completion,
      [
        'goal_id',
        'task_id',
        'prepared_event_id',
        'abandon_event_id',
      ],
      [
        'request_sha256',
        'intent_sha256',
        'p1_intent_sha256',
      ],
      `P1 abandonment completion ${preparedEventId}`,
    );
  }
  if (abandonment.completionTemporary) {
    assertExactSealedAtomicTemporary({
      directory: files.abandonmentDirectory,
      temporaryName: abandonment.completionTemporary,
      target: files.abandonmentCompletion,
      sealKey: 'completion_sha256',
      expected: completion,
      identityFields: [
        'goal_id',
        'task_id',
        'prepared_event_id',
        'abandon_event_id',
      ],
      bindingFields: [
        'request_sha256',
        'intent_sha256',
        'p1_intent_sha256',
      ],
      label: `P1 abandonment completion temporary ${preparedEventId}`,
    });
  }

  const receipt = expectedP1AbandonmentReceipt(completion);
  const inventory = receiptInventory(
    files.abandonmentReceipts,
    `P1 abandonment receipts ${taskId}`,
  );
  const receiptTemporary = inventory.temporaries.get(preparedEventId);
  if (receiptTemporary) {
    assertExactSealedAtomicTemporary({
      directory: files.abandonmentReceipts,
      temporaryName: receiptTemporary,
      target: files.abandonmentReceipt,
      sealKey: 'receipt_sha256',
      expected: receipt,
      identityFields: [
        'goal_id',
        'task_id',
        'prepared_event_id',
        'abandon_event_id',
      ],
      bindingFields: [
        'request_sha256',
        'intent_sha256',
        'p1_intent_sha256',
      ],
      label: `P1 abandonment receipt temporary ${preparedEventId}`,
    });
  }
  const retainedReceipt = readP1AbandonmentReceipt(
    root,
    goalId,
    taskId,
    preparedEventId,
  );
  if (retainedReceipt) {
    assertExactRecoveryRecord(
      retainedReceipt,
      receipt,
      [
        'goal_id',
        'task_id',
        'prepared_event_id',
        'abandon_event_id',
      ],
      [
        'request_sha256',
        'intent_sha256',
        'p1_intent_sha256',
      ],
      `P1 abandonment receipt ${preparedEventId}`,
    );
  }
  const acceptedMatches = acceptedEventFiles(root, goalId, taskId)
    .map((file) => readJson(
      file,
      `accepted event ${path.basename(file)}`,
    ))
    .filter((event) => event.event_id === abandonEventId);
  assertControl(
    acceptedMatches.length <= 1,
    'CORRUPT_STORE',
    `P1 abandonment ${abandonEventId} 存在多个 accepted event`,
  );
  const accepted = acceptedMatches[0] || null;
  if (accepted) {
    assertControl(
      abandonment.staging !== true,
      'CORRUPT_STORE',
      `accepted P1 abandonment ${preparedEventId} 仍在 staging`,
    );
    assertP1AbandonmentLedgerBinding(
      accepted,
      prepared,
      abandonment,
      receipt,
    );
  }
  return {
    abandonment,
    accepted,
    completion,
    prepared,
    receipt,
    retainedReceipt,
    ref,
  };
}

function completeP1Abandonment(
  root,
  goalId,
  taskId,
  abandonment,
) {
  const { intent, files } = abandonment;
  const completion = expectedP1AbandonmentCompletion(
    goalId,
    taskId,
    intent,
  );
  let retainedCompletion = abandonment.completion;
  if (abandonment.completionTemporary) {
    retainedCompletion = recoverSealedAtomicTemporary({
      directory: files.abandonmentDirectory,
      temporaryName: abandonment.completionTemporary,
      target: files.abandonmentCompletion,
      sealKey: 'completion_sha256',
      expected: completion,
      identityFields: [
        'goal_id',
        'task_id',
        'prepared_event_id',
      ],
      bindingFields: [
        'request_sha256',
        'intent_sha256',
        'p1_intent_sha256',
      ],
      label: `P1 abandonment completion temporary ${
        intent.prepared_event_id
      }`,
    });
  }
  if (!retainedCompletion) {
    atomicWriteJson(files.abandonmentCompletion, completion);
  } else {
    assertControl(
      hashObject(retainedCompletion) === hashObject(completion),
      'CORRUPT_STORE',
      `P1 abandonment ${intent.prepared_event_id} completion 漂移`,
    );
  }
  const receipt = expectedP1AbandonmentReceipt(completion);
  ensurePrivateDirectory(files.abandonmentReceipts);
  const inventory = receiptInventory(
    files.abandonmentReceipts,
    `P1 abandonment receipts ${taskId}`,
  );
  const receiptTemporary = inventory.temporaries.get(
    intent.prepared_event_id,
  );
  if (receiptTemporary) {
    recoverSealedAtomicTemporary({
      directory: files.abandonmentReceipts,
      temporaryName: receiptTemporary,
      target: files.abandonmentReceipt,
      sealKey: 'receipt_sha256',
      expected: receipt,
      identityFields: [
        'goal_id',
        'task_id',
        'prepared_event_id',
      ],
      bindingFields: [
        'request_sha256',
        'intent_sha256',
        'p1_intent_sha256',
      ],
      label: `P1 abandonment receipt temporary ${
        intent.prepared_event_id
      }`,
    });
  }
  const existing = readP1AbandonmentReceipt(
    root,
    goalId,
    taskId,
    intent.prepared_event_id,
  );
  if (existing) {
    assertControl(
      hashObject(existing) === hashObject(receipt),
      'CORRUPT_STORE',
      `P1 abandonment receipt ${intent.prepared_event_id} 漂移`,
    );
  } else {
    atomicWriteJson(files.abandonmentReceipt, receipt);
  }
  return receipt;
}

function abandonP1CommitRef(cwd, intent, preparedCommit) {
  const root = controlRoot(cwd);
  const retainedAbandonment = readAbandonmentIntent(
    root,
    intent.goal_id,
    intent.task_id,
    intent.prepared_event_id,
  );
  assertControl(
    retainedAbandonment
      && hashObject(retainedAbandonment.intent)
        === hashObject(intent),
    'P1_COMMIT_INTENT_MISMATCH',
    `P1 abandonment ${intent.prepared_event_id} 缺 exact sealed ref mutation fence anchor`,
  );
  const canonicalIntent = retainedAbandonment.intent;
  const retainedPrepared = readP1CommitIntent(
    root,
    canonicalIntent.goal_id,
    canonicalIntent.task_id,
    canonicalIntent.prepared_event_id,
  );
  assertControl(
    retainedPrepared
      && retainedPrepared.intent.intent_sha256
        === canonicalIntent.p1_intent_sha256
      && (
        !preparedCommit
          || (
            preparedCommit.intent
              && hashObject(preparedCommit.intent)
                === hashObject(retainedPrepared.intent)
          )
      ),
    'P1_COMMIT_INTENT_MISMATCH',
    `P1 abandonment ${intent.prepared_event_id} 缺 exact retained P1 intent`,
  );
  const preparedIntent = retainedPrepared.intent;
  const identity = repositoryIdentity(
    cwd,
    preparedIntent.ref_binding.repository_root,
  );
  assertControl(
    identity.common_git_dir === preparedIntent.ref_binding.common_git_dir,
    'REPOSITORY_ROOT_MISMATCH',
    'P1 abandonment common git dir 漂移',
  );
  const ref = canonicalIntent.request.expected_commit_ref;
  const commit = canonicalIntent.request.expected_ref_head;
  assertControl(
    preparedIntent.ref_binding.commit_ref === ref
      && preparedIntent.ref_binding.new_commit === commit,
    'P1_COMMIT_INTENT_MISMATCH',
    `P1 abandonment ${intent.prepared_event_id} old/new ref 与 P1 intent 漂移`,
  );
  assertP1CommitRefName(
    ref,
    preparedIntent.goal_id,
    preparedIntent.task_id,
    preparedIntent.task_cycle,
  );
  const retainedForeignRef = retainedPrepared.abandonHandoff
    && retainedPrepared.abandonHandoff.ref_binding.observed_actual_ref;
  const current = readExactRef(cwd, ref);
  assertControl(
    current === commit
      || current === null
      || current === retainedForeignRef,
    'P1_COMMIT_REF_CONFLICT',
    `${ref} 已指向 ${current}，不是 exact prepared/retained ref`,
  );
  // Abandonment is an append-only authority tombstone. The deterministic
  // prepared ref remains as an audit/GC root; physical deletion is a
  // separate future audited-GC concern.
  assertControl(
    p1CommitRefIsAbandoned(
      current,
      retainedPrepared,
    ),
    'P1_COMMIT_REF_CONFLICT',
    `${ref} abandonment 后不是 retained prepared/foreign ref`,
  );
}

function listP1CommitOperations(root, goalId, taskId) {
  const paths = p1CommitTaskPaths(root, goalId, taskId);
  const pending = [];
  const commitReceiptInventory = receiptInventory(
    paths.receipts,
    `P1 commit receipts ${taskId}`,
  );
  const abandonmentReceiptInventory = receiptInventory(
    paths.abandonmentReceipts,
    `P1 abandonment receipts ${taskId}`,
  );
  const commitIntentIds = new Set();
  const abandonmentIds = new Set();
  const acceptedP1Transactions = new Map();
  const acceptedP1Abandonments = new Map();
  for (const file of acceptedEventFiles(root, goalId, taskId)) {
    const event = readJson(file, `accepted event ${path.basename(file)}`);
    if (event.p1_commit_transaction) {
      assertControl(
        event.type === 'P1_COMMITTED'
          && event.p1_commit_transaction.event_id === event.event_id
          && event.p1_commit_transaction.goal_id === goalId
          && event.p1_commit_transaction.task_id === taskId,
        'CORRUPT_STORE',
        `accepted P1 transaction ${event.event_id} marker binding 漂移`,
      );
      acceptedP1Transactions.set(event.event_id, event);
    }
    if (event.type === 'P1_COMMIT_ABANDONED') {
      const preparedEventId = event.payload
        && event.payload.prepared_event_id;
      safeId(preparedEventId, 'accepted P1 abandonment prepared_event_id');
      assertControl(
        !acceptedP1Abandonments.has(preparedEventId),
        'CORRUPT_STORE',
        `P1 intent ${preparedEventId} 存在多个 abandonment ledger event`,
      );
      acceptedP1Abandonments.set(preparedEventId, event);
    }
  }
  const abandonmentReceipts = new Map(
    abandonmentReceiptsForTask(root, goalId, taskId)
      .map((receipt) => [receipt.prepared_event_id, receipt]),
  );
  const stagedAbandonments = preparedAbandonmentCandidates(
    root,
    goalId,
    taskId,
  );
  for (const prepared of preparedCandidates(root, goalId, taskId)) {
    const sealedIntent = prepared.sealedIntent || null;
    const stableIdUnavailable = !sealedIntent;
    const abandonmentRequired = Boolean(
      sealedIntent
        && (
          sealedIntent.abort_only === true
            || (
              prepared.abandonHandoff
                && !prepared.abandonHandoffTemporary
            )
        ),
    );
    pending.push({
      kind: 'P1_COMMIT_REF',
      operation_id: sealedIntent ? sealedIntent.event_id : null,
      ...(stableIdUnavailable
        ? {
          stable_id_sha256: prepared.event_id_sha256,
          stable_id_unavailable: true,
        }
        : {}),
      request_sha256: prepared.request_sha256,
      acceptance_authority_sha256:
        prepared.acceptance_authority_sha256,
      goal_id: goalId,
      task_id: taskId,
      allowed_event_id: sealedIntent ? sealedIntent.event_id : null,
      allowed_event_sha256: prepared.request_sha256,
      marker_file: prepared.intent || prepared.bundle || prepared.directory,
      prepared_stage: prepared.abandonHandoffTemporary
        ? (
          prepared.abandonHandoff
            ? 'ABANDON_HANDOFF_PROMOTION_CLEANUP'
            : prepared.abandonHandoffTemporary.complete
              ? 'ABANDON_HANDOFF_TEMP_COMPLETE'
              : 'ABANDON_HANDOFF_TEMP_PARTIAL'
        )
        : abandonmentRequired
        ? (
          prepared.abandonHandoff
            ? 'ABANDON_HANDOFF_INSTALL_PENDING'
            : 'ABANDON_ONLY_INSTALL_PENDING'
        )
        : prepared.stage,
      ...(sealedIntent
        ? {
          intent_sha256: sealedIntent.intent_sha256,
          commit_ref: sealedIntent.ref_binding.commit_ref,
          commit_sha: sealedIntent.ref_binding.new_commit,
          ...(prepared.abandonHandoff
              && !prepared.abandonHandoffTemporary
            ? {
              abandon_handoff_sha256:
                prepared.abandonHandoff.handoff_sha256,
            }
            : {}),
        }
        : {}),
      ...(abandonmentRequired ? { abandonment_required: true } : {}),
    });
  }
  if (fs.existsSync(paths.intents)) {
    assertPrivateDirectory(paths.intents, `P1 commit intents ${taskId}`);
    for (const eventId of fs.readdirSync(paths.intents).sort()) {
      if (eventId.startsWith('.init-')) continue;
      safeId(eventId, 'P1 commit intent directory');
      commitIntentIds.add(eventId);
      const prepared = readP1CommitIntent(
        root,
        goalId,
        taskId,
        eventId,
      );
      const accepted = acceptedP1Event(root, goalId, taskId, eventId);
      const receipt = readP1CommitReceipt(
        root,
        goalId,
        taskId,
        eventId,
      );
      assertControl(
        !commitReceiptInventory.temporaries.has(eventId) || accepted,
        'CORRUPT_STORE',
        `P1 commit receipt temporary ${eventId} 缺 accepted event`,
      );
      const ref = readExactRef(
        prepared.intent.ref_binding.repository_root,
        prepared.intent.ref_binding.commit_ref,
      );
      assertControl(
        accepted
          ? (
            !prepared.abandonHandoff
              && !prepared.abandonHandoffTemporary
              && (
                ref === null
                  || ref === prepared.intent.ref_binding.new_commit
              )
          )
          : prepared.abandonHandoff
              && !prepared.abandonHandoffTemporary
            ? (
              ref === null
                || ref === prepared.intent.ref_binding.new_commit
                || ref
                  === prepared.abandonHandoff.ref_binding
                    .observed_actual_ref
            )
            : (
              ref === null
                || /^[0-9a-f]{40}$/.test(ref)
            ),
        'P1_COMMIT_REF_CONFLICT',
        `${prepared.intent.ref_binding.commit_ref} 指向 ${ref}，与 intent 冲突`,
      );
      const abandonment = readAbandonmentIntent(
        root,
        goalId,
        taskId,
        eventId,
      );
      const abandonmentReceipt = abandonmentReceipts.get(eventId) || null;
      const acceptedAbandonment =
        acceptedP1Abandonments.get(eventId) || null;
      const stagedAbandonment = stagedAbandonments.find(
        (candidate) => (
          candidate.intent
            ? candidate.intent.prepared_event_id === eventId
            : candidate.prepared_event_id_sha256
              === `sha256:${sha256(eventId)}`
        ),
      );
      if (abandonment || abandonmentReceipt || stagedAbandonment) {
        assertControl(
          !accepted
            && (
              !abandonment
                || abandonment.intent.p1_intent_sha256
                  === prepared.intent.intent_sha256
            )
            && (
              !abandonmentReceipt
                || abandonmentReceipt.p1_intent_sha256
                  === prepared.intent.intent_sha256
            )
            && (
              !stagedAbandonment
                || !stagedAbandonment.intent
                || stagedAbandonment.intent.p1_intent_sha256
                  === prepared.intent.intent_sha256
            ),
          'CORRUPT_STORE',
          `P1 abandonment ${eventId} 与 intent/accepted lineage 冲突`,
        );
        if (acceptedAbandonment) {
          assertControl(
            abandonment
              && abandonment.completion
              && abandonmentReceipt
              && !stagedAbandonment,
            'CORRUPT_STORE',
            `accepted P1 abandonment ${eventId} 缺 retained sideband lineage`,
          );
          assertP1AbandonmentLedgerBinding(
            acceptedAbandonment,
            prepared,
            abandonment,
            abandonmentReceipt,
          );
        }
        continue;
      }
      assertControl(
        !acceptedAbandonment,
        'CORRUPT_STORE',
        `accepted P1 abandonment ${eventId} 缺 retained sideband lineage`,
      );
      assertControl(
        (
          prepared.intent.abort_only !== true
            && !prepared.abandonHandoff
            && !prepared.abandonHandoffTemporary
        )
          || (!accepted && !receipt),
        'CORRUPT_STORE',
        `P1 abandonment-required intent ${eventId} 禁止存在 accepted/completion`,
      );
      if (accepted) {
        assertControl(
          accepted.input_sha256 === prepared.intent.request_sha256,
          'CORRUPT_STORE',
          `P1 commit intent ${eventId} accepted lineage 漂移`,
        );
        const marker = accepted.p1_commit_transaction;
        if (marker) {
          assertControl(
            marker.task_cycle === prepared.intent.task_cycle
              && marker.request_sha256
                === prepared.intent.request_sha256
              && marker.intent_sha256
                === prepared.intent.intent_sha256
              && marker.commit_ref
                === prepared.intent.ref_binding.commit_ref
              && marker.commit_sha
                === prepared.intent.ref_binding.new_commit
              && marker.bundle_sha256 === prepared.intent.bundle.sha256,
            'CORRUPT_STORE',
            `accepted P1 transaction ${eventId} 与 retained intent 漂移`,
          );
        }
      }
      if (receipt) {
        assertControl(
          accepted
            && receipt.task_cycle === prepared.intent.task_cycle
            && receipt.request_sha256
              === prepared.intent.request_sha256
            && receipt.intent_sha256
              === prepared.intent.intent_sha256
            && receipt.accepted_event_sha256
              === accepted.event_sha256
            && receipt.commit_ref
              === prepared.intent.ref_binding.commit_ref
            && receipt.commit_sha
              === prepared.intent.ref_binding.new_commit
            && receipt.completed_at === accepted.accepted_at,
          'CORRUPT_STORE',
          `P1 commit completion ${eventId} 与 intent/accepted lineage 漂移`,
        );
      }
      const abandonmentRequired = Boolean(
        prepared.intent.abort_only === true
          || (
            prepared.abandonHandoff
              && !prepared.abandonHandoffTemporary
          ),
      );
      if (abandonmentRequired || !(accepted && receipt && ref)) {
        pending.push({
          kind: 'P1_COMMIT_REF',
          operation_id: eventId,
          request_sha256: prepared.intent.request_sha256,
          goal_id: goalId,
          task_id: taskId,
          allowed_event_id: eventId,
          allowed_event_sha256: prepared.intent.request_sha256,
          marker_file: prepared.files.intent,
          intent_sha256: prepared.intent.intent_sha256,
          commit_ref: prepared.intent.ref_binding.commit_ref,
          commit_sha: prepared.intent.ref_binding.new_commit,
          prepared_stage: prepared.abandonHandoffTemporary
            ? (
              prepared.abandonHandoff
                ? 'ABANDON_HANDOFF_PROMOTION_CLEANUP'
                : prepared.abandonHandoffTemporary.complete
                  ? 'ABANDON_HANDOFF_TEMP_COMPLETE'
                  : 'ABANDON_HANDOFF_TEMP_PARTIAL'
            )
            : abandonmentRequired
            ? (
              prepared.abandonHandoff
                ? 'ABANDON_HANDOFF'
                : 'ABANDON_ONLY'
            )
            : (
              accepted
                ? (
                  commitReceiptInventory.temporaries.has(eventId)
                    ? 'COMPLETION_TEMP'
                    : 'COMPLETION_PENDING'
                )
                : (
                  ref === prepared.intent.ref_binding.new_commit
                    ? 'REF_PUBLISHED'
                    : (ref ? 'REF_CONFLICT' : 'INTENT_PUBLISHED')
                )
            ),
          ...(abandonmentRequired
            ? {
              abandonment_required: true,
              ...(prepared.abandonHandoff
                ? {
                  abandon_handoff_sha256:
                    prepared.abandonHandoff.handoff_sha256,
                }
                : {}),
            }
            : {}),
        });
      }
    }
  }
  for (const eventId of new Set([
    ...commitReceiptInventory.canonical.keys(),
    ...commitReceiptInventory.temporaries.keys(),
  ])) {
    assertControl(
      commitIntentIds.has(eventId),
      'CORRUPT_STORE',
      P1_COMMIT_RECEIPT_MISSING_INTENT_MESSAGE,
    );
  }
  for (const eventId of acceptedP1Transactions.keys()) {
    assertControl(
      commitIntentIds.has(eventId),
      'CORRUPT_STORE',
      ACCEPTED_P1_TRANSACTION_MISSING_INTENT_MESSAGE,
    );
  }
  if (fs.existsSync(paths.abandonments)) {
    assertPrivateDirectory(
      paths.abandonments,
      `P1 commit abandonments ${taskId}`,
    );
    for (const preparedEventId of fs.readdirSync(paths.abandonments).sort()) {
      if (preparedEventId.startsWith('.init-abandon-')) continue;
      safeId(preparedEventId, 'P1 abandonment prepared event_id');
      abandonmentIds.add(preparedEventId);
      const abandonment = readAbandonmentIntent(
        root,
        goalId,
        taskId,
        preparedEventId,
      );
      const receipt = abandonmentReceipts.get(preparedEventId) || null;
      const acceptedAbandonment =
        acceptedP1Abandonments.get(preparedEventId) || null;
      const preparedCommit = readP1CommitIntent(
        root,
        goalId,
        taskId,
        preparedEventId,
      );
      assertControl(
        preparedCommit
          && abandonment.intent.p1_intent_sha256
            === preparedCommit.intent.intent_sha256
          && abandonment.intent.request.p1_abandon_handoff_sha256
            === p1CommitAbandonmentHandoffSha256(preparedCommit),
        'CORRUPT_STORE',
        `P1 abandonment ${preparedEventId} 缺 retained P1 intent`,
      );
      const ref = readExactRef(
        preparedCommit.intent.ref_binding.repository_root,
        abandonment.intent.request.expected_commit_ref,
      );
      assertControl(
        ref === null
          || ref === abandonment.intent.request.expected_ref_head
          || (
            preparedCommit.abandonHandoff
              && ref
                === preparedCommit.abandonHandoff.ref_binding
                  .observed_actual_ref
          ),
        'P1_COMMIT_REF_CONFLICT',
        `${abandonment.intent.request.expected_commit_ref} 指向 ${ref}，与 abandonment 冲突`,
      );
      const refAbandoned = p1CommitRefIsAbandoned(
        ref,
        preparedCommit,
      );
      if (acceptedAbandonment) {
        assertControl(
          abandonment.completion && receipt,
          'CORRUPT_STORE',
          `accepted P1 abandonment ${preparedEventId} 缺 completion/receipt`,
        );
        assertP1AbandonmentLedgerBinding(
          acceptedAbandonment,
          preparedCommit,
          abandonment,
          receipt,
        );
      }
      if (
        !abandonment.completion
          || !receipt
          || !refAbandoned
          || !acceptedAbandonment
      ) {
        pending.push({
          kind: 'P1_COMMIT_REF_ABANDON',
          operation_id: abandonment.intent.request.abandon_event_id,
          request_sha256: abandonment.intent.request_sha256,
          goal_id: goalId,
          task_id: taskId,
          allowed_event_id: null,
          allowed_event_sha256: null,
          marker_file: abandonment.files.abandonmentIntent,
          intent_sha256: abandonment.intent.intent_sha256,
          prepared_event_id: preparedEventId,
          commit_ref: abandonment.intent.request.expected_commit_ref,
          commit_sha: abandonment.intent.request.expected_ref_head,
          prepared_stage: !refAbandoned
            ? 'REF_RESTORED'
            : (
              abandonment.completionTemporary
                ? 'COMPLETION_TEMP'
                : (!abandonment.completion
                    ? 'COMPLETION_PENDING'
                    : (
                      abandonmentReceiptInventory.temporaries.has(
                        preparedEventId,
                      )
                        ? 'RECEIPT_TEMP'
                        : (
                          !receipt
                            ? 'RECEIPT_PENDING'
                            : 'LEDGER_PENDING'
                        )
                    ))
            ),
        });
      }
    }
  }
  for (const preparedEventId of new Set([
    ...abandonmentReceiptInventory.canonical.keys(),
    ...abandonmentReceiptInventory.temporaries.keys(),
  ])) {
    assertControl(
      abandonmentIds.has(preparedEventId),
      'CORRUPT_STORE',
      `P1 abandonment receipt ${preparedEventId} 缺 retained intent`,
    );
  }
  for (const preparedEventId of acceptedP1Abandonments.keys()) {
    assertControl(
      abandonmentIds.has(preparedEventId),
      'CORRUPT_STORE',
      `accepted P1 abandonment ${preparedEventId} 缺 retained intent`,
    );
  }
  for (const prepared of stagedAbandonments) {
    const sealed = Boolean(prepared.intent);
    pending.push({
      kind: 'P1_COMMIT_REF_ABANDON',
      operation_id: sealed
        ? prepared.intent.request.abandon_event_id
        : null,
      ...(sealed
        ? {}
        : {
          stable_id_sha256: prepared.prepared_event_id_sha256,
          stable_id_unavailable: true,
        }),
      request_sha256: sealed
        ? prepared.intent.request_sha256
        : prepared.request_sha256,
      foreman_authority_sha256: sealed
        ? hashObject(prepared.intent.foreman_authority)
        : prepared.foreman_authority_sha256,
      goal_id: goalId,
      task_id: taskId,
      allowed_event_id: null,
      allowed_event_sha256: null,
      marker_file: prepared.intentFile || prepared.directory,
      intent_sha256: sealed ? prepared.intent.intent_sha256 : null,
      prepared_event_id: sealed
        ? prepared.intent.prepared_event_id
        : null,
      commit_ref: sealed
        ? prepared.intent.request.expected_commit_ref
        : null,
      commit_sha: sealed
        ? prepared.intent.request.expected_ref_head
        : null,
      prepared_stage: prepared.stage,
    });
  }
  assertControl(
    pending.length <= 1,
    'CORRUPT_STORE',
    `task ${taskId} 同时存在多个 P1 commit pending operation`,
  );
  return pending;
}

function abandonmentReceiptsForTask(root, goalId, taskId) {
  const paths = p1CommitTaskPaths(root, goalId, taskId);
  const inventory = receiptInventory(
    paths.abandonmentReceipts,
    `P1 abandonment receipts ${taskId}`,
  );
  const receipts = [...inventory.canonical.keys()]
    .sort()
    .map((eventId) => {
      return readP1AbandonmentReceipt(
        root,
        goalId,
        taskId,
        eventId,
      );
    });
  for (const receipt of receipts) {
    const abandonment = readAbandonmentIntent(
      root,
      goalId,
      taskId,
      receipt.prepared_event_id,
    );
    const prepared = readP1CommitIntent(
      root,
      goalId,
      taskId,
      receipt.prepared_event_id,
    );
    assertControl(
      abandonment
        && abandonment.completion
        && prepared
        && abandonment.intent.p1_intent_sha256
          === prepared.intent.intent_sha256
        && abandonment.intent.task_anchor.task_cycle
          === prepared.intent.task_cycle
        && abandonment.intent.request.expected_commit_ref
          === prepared.intent.ref_binding.commit_ref
        && abandonment.intent.request.expected_ref_head
          === prepared.intent.ref_binding.new_commit
        && abandonment.intent.request.p1_abandon_handoff_sha256
          === p1CommitAbandonmentHandoffSha256(prepared),
      'CORRUPT_STORE',
      `P1 abandonment receipt ${receipt.prepared_event_id} 缺少完整 retained lineage`,
    );
    const expectedReceipt = {
      ...abandonment.completion,
    };
    delete expectedReceipt.completion_sha256;
    delete expectedReceipt.receipt_sha256;
    expectedReceipt.receipt_sha256 = hashObject(expectedReceipt);
    assertControl(
      receipt.task_cycle === abandonment.intent.task_anchor.task_cycle
        && receipt.abandon_event_id
          === abandonment.intent.request.abandon_event_id
        && receipt.request_sha256 === abandonment.intent.request_sha256
        && receipt.intent_sha256 === abandonment.intent.intent_sha256
        && receipt.p1_intent_sha256
          === abandonment.intent.p1_intent_sha256
        && receipt.commit_ref
          === abandonment.intent.request.expected_commit_ref
        && receipt.commit_sha
          === abandonment.intent.request.expected_ref_head
        && receipt.incident_ref === abandonment.intent.request.incident_ref
        && receipt.reason === abandonment.intent.request.reason
        && receipt.completed_at === abandonment.intent.accepted_at
        && hashObject(receipt) === hashObject(expectedReceipt),
      'CORRUPT_STORE',
      `P1 abandonment receipt ${receipt.prepared_event_id} lineage 漂移`,
    );
  }
  return receipts;
}

module.exports = {
  ACCEPTED_P1_TRANSACTION_MISSING_INTENT_MESSAGE,
  ABANDON_RECEIPT_KIND,
  INTENT_KIND,
  P1_COMMIT_RECEIPT_MISSING_INTENT_MESSAGE,
  abandonmentReceiptsForTask,
  abandonP1CommitRef,
  acceptedP1Event,
  bundleHead,
  cleanupExactUnsealedAbandonmentStaging,
  completeP1Abandonment,
  completeP1CommitTransaction,
  hasExactUnsealedAbandonmentStaging,
  inspectExactUnsealedAbandonmentStaging,
  inspectP1Abandonment,
  inspectP1CommitPreparation,
  listP1CommitOperations,
  p1CommitAbandonmentHandoffSha256,
  p1CommitPaths,
  publishP1AbandonmentIntent,
  publishP1CommitAbandonHandoff,
  publishP1CommitAbandonOnlyIntent,
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
};
