'use strict';

const fs = require('fs');
const path = require('path');
const { fileURLToPath } = require('url');
const { readCapabilityFile } = require('./auth');
const { ControlError, assertControl } = require('./errors');
const {
  inspectLooseRefFence,
} = require('./git-loose-ref-transaction');
const {
  IDENTITY_INCIDENT_SOURCE_MAX_BYTES,
  readProtocolSealedIdentityIncidentEvidenceSource,
} = require('./launch-source-checkpoint');
const { acceptedEventFiles } = require('./store');
const {
  hashObject,
  normalizeHash,
  readJson,
  safeId,
  sha256,
} = require('./util');

const REGISTRATION_STAGING_PATTERN =
  /^\.init-registration-([0-9a-f]{64})-([0-9a-f]{64})$/;
const FOREMAN_RECOVERY_STAGING_PATTERN =
  /^\.init-foreman-recovery-([0-9a-f]{64})-([0-9a-f]{64})$/;
const LEGACY_SOURCE_EXPORT_STAGING_PATTERN =
  /^\.([A-Za-z0-9][A-Za-z0-9._:-]{0,199})\.([1-9][0-9]*)\.tmp-([0-9a-f]{24})$/;
const SOURCE_EXPORT_STAGING_V2_PATTERN =
  /^\.init-source-([0-9a-f]{64})-([0-9a-f]{64})-([0-9a-f]{64})$/;
const SOURCE_EXPORT_DISCARD_PATTERN =
  /^\.discard-source-([0-9a-f]{64})-([0-9a-f]{64})$/;
const LEGACY_SOURCE_IMPORT_STAGING_PATTERN =
  /^\.init-([A-Za-z0-9][A-Za-z0-9._:-]{0,199})\.([1-9][0-9]*)\.tmp-([0-9a-f]{24})$/;
const SOURCE_IMPORT_STAGING_V2_PATTERN =
  /^\.init-import-([0-9a-f]{64})-([0-9a-f]{64})-([0-9a-f]{64})$/;
const CHECKPOINT_GIT_FENCE_KIND =
  'goalctl-recovery-checkpoint-git-fence-v1';
const CHECKPOINT_GIT_FENCE_COMPLETION_KIND =
  'goalctl-recovery-checkpoint-git-fence-completion-v1';
const PARTIAL_SOURCE_BINDING_FILE = 'operation-binding.json';
const PARTIAL_SOURCE_BINDING_KEYS = [
  'schema_version',
  'snapshot_id',
  'goal_id',
  'task_id',
  'operation_kind',
  'operation_request_sha256',
  'execution_sha256',
  'binding_sha256',
];
const SOURCE_IMPORT_INTENT_KEYS = [
  'schema_version',
  'kind',
  'import_id',
  'goal_id',
  'task_id',
  'snapshot_id',
  'snapshot_sha256',
  'successor_thread_id',
  'request',
  'request_sha256',
  'prepared_request_sha256',
  'task_anchor',
  'acceptance_authority',
  'accepted_at',
  'intent_sha256',
];

const PREFLIGHT_IDENTITY_FAILURES = new Set([
  'goal-task-binding',
  'packet-binding',
  'repository-identity',
  'origin-identity',
  'pull-request-binding',
  'registered-session',
  'environment-identity',
  'runtime-identity',
  'execution-target',
  'resource-leases',
  'launch-runtime-binding',
]);
const PREFLIGHT_POLICY_FAILURES = new Set([
  'TASK_HELD',
  'CONTROL_RECONCILE_REQUIRED',
]);

function escapedPattern(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hashDigest(value, label) {
  return normalizeHash(value, label).slice('sha256:'.length);
}

function assertCurrentOwnerOrdinary(
  stat,
  expectedKind,
  label,
  { privateMode = false, exactMode = null } = {},
) {
  const expectedType = expectedKind === 'directory'
    ? stat.isDirectory()
    : stat.isFile();
  assertControl(
    expectedType
      && !stat.isSymbolicLink()
      && (
        typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
      )
      && (exactMode === null || (stat.mode & 0o777) === exactMode)
      && (!privateMode || (stat.mode & 0o077) === 0),
    'CORRUPT_STORE',
    `${label} 非当前 owner 私有普通${expectedKind === 'directory' ? '目录' : '文件'}`,
  );
}

function assertExactDirectoryEntries(directory, expected, label) {
  const entries = fs.readdirSync(directory).sort();
  const wanted = [...expected].sort();
  assertControl(
    entries.length === wanted.length
      && entries.every((entry, index) => entry === wanted[index]),
    'CORRUPT_STORE',
    `${label} entries 非协议集合`,
  );
  return entries;
}

function validatePreparedCapability(
  stagingDirectory,
  finalDirectory,
  intent,
  capabilityPattern,
  label,
) {
  assertControl(
    typeof intent.capability_file === 'string'
      && path.isAbsolute(intent.capability_file)
      && path.normalize(intent.capability_file) === intent.capability_file
      && path.dirname(intent.capability_file) === finalDirectory,
    'CORRUPT_STORE',
    `${label} capability final path binding 非法`,
  );
  const capabilityName = path.basename(intent.capability_file);
  assertControl(
    capabilityPattern.test(capabilityName),
    'CORRUPT_STORE',
    `${label} capability protocol name 非法`,
  );
  assertExactDirectoryEntries(
    stagingDirectory,
    ['intent.json', capabilityName],
    label,
  );
  const stagedCapabilityFile = path.join(stagingDirectory, capabilityName);
  const stagedCapabilityStat = fs.lstatSync(stagedCapabilityFile);
  assertCurrentOwnerOrdinary(
    stagedCapabilityStat,
    'file',
    `${label}/${capabilityName}`,
    { privateMode: true },
  );
  const stagedCapability = readCapabilityFile(stagedCapabilityFile);
  assertControl(
    normalizeHash(
      stagedCapability.sha256,
      `${label} staged capability sha256`,
    ) === normalizeHash(
      intent.capability_sha256,
      `${label} intent capability_sha256`,
    ),
    'CORRUPT_STORE',
    `${label} staged capability seal 漂移`,
  );
}

function jsonFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => path.join(directory, name));
}

function sealedRecord(file, sealKey, label) {
  const record = readJson(file, label);
  const unsigned = { ...record };
  delete unsigned[sealKey];
  assertControl(
    record && record[sealKey] === hashObject(unsigned),
    'CORRUPT_STORE',
    `${label} seal 不匹配`,
  );
  return record;
}

function registryFile(root, goalId, taskId, evidenceId) {
  return path.join(
    root,
    'goals',
    goalId,
    'evidence',
    taskId,
    `${safeId(evidenceId, 'evidence_id')}.json`,
  );
}

function acceptedEventIds(root, goalId, taskId) {
  return new Set(
    acceptedEventFiles(root, goalId, taskId)
      .map((file) => readJson(file, `accepted event ${path.basename(file)}`))
      .map((event) => event.event_id),
  );
}

function acceptedResourceEvents(root) {
  const directory = path.join(root, 'resources', 'events');
  const events = new Map();
  for (const file of jsonFiles(directory)) {
    const event = readJson(file, `resource event ${path.basename(file)}`);
    const unsigned = { ...event };
    delete unsigned.event_sha256;
    assertControl(
      event
        && typeof event.event_id === 'string'
        && typeof event.type === 'string'
        && event.event_sha256 === hashObject(unsigned)
        && !events.has(event.event_id),
      'CORRUPT_STORE',
      `resource event ${path.basename(file)} seal/identity 非法`,
    );
    events.set(event.event_id, event);
  }
  return events;
}

function listPendingResourceOperations(root) {
  const pending = [];
  const acceptedEvents = acceptedResourceEvents(root);
  const intentRoot = path.join(root, 'resources', 'acquire-intents');
  if (!fs.existsSync(intentRoot)) return pending;
  const intentEntries = fs.readdirSync(intentRoot).sort();
  const intentEntryNames = new Set(intentEntries);
  for (const name of intentEntries) {
    const directory = path.join(intentRoot, name);
    const stat = fs.lstatSync(directory);
    let directoryEventId = name;
    let staged = false;
    if (name.startsWith('.init-')) {
      staged = true;
      directoryEventId = name.slice('.init-'.length);
      safeId(directoryEventId, 'staged resource acquire event_id');
      assertControl(
        !intentEntryNames.has(directoryEventId),
        'CORRUPT_STORE',
        `resource acquire intent ${directoryEventId} final/staging 并存`,
      );
      assertControl(
        stat.isDirectory()
          && !stat.isSymbolicLink()
          && (typeof process.getuid !== 'function'
            || stat.uid === process.getuid()),
        'CORRUPT_STORE',
        `resource acquire staging ${name} 非本进程用户普通目录`,
      );
      const entries = fs.readdirSync(directory).sort();
      assertControl(
        entries.length <= 1
          && entries.every((entry) => entry === 'intent.json'),
        'CORRUPT_STORE',
        `resource acquire staging ${name} 含未知文件`,
      );
      if (entries.length === 0) continue;
    }
    assertControl(
      stat.isDirectory() && !stat.isSymbolicLink(),
      'CORRUPT_STORE',
      `resource acquire intent ${name} 非普通目录`,
    );
    const file = path.join(directory, 'intent.json');
    const fileStat = fs.lstatSync(file);
    assertControl(
      fileStat.isFile() && !fileStat.isSymbolicLink(),
      'CORRUPT_STORE',
      `resource acquire intent ${name}/intent.json 非普通文件`,
    );
    const intent = sealedRecord(
      file,
      'intent_sha256',
      `resource acquire intent ${name}`,
    );
    const request = intent.request;
    const owner = request && request.owner;
    assertControl(
      intent.schema_version === 1
        && intent.type === 'LEASE_ACQUIRE_INTENT'
        && request
        && request.schema_version === 1
        && request.event_id === directoryEventId
        && owner
        && intent.actor
        && hashObject(intent.actor) === hashObject(owner)
        && intent.actor_authority
        && intent.actor_authority.role === owner.role
        && intent.actor_authority.thread_id === owner.thread_id
        && intent.actor_authority.host_id === owner.host_id
        && intent.lease_template
        && intent.lease_template.resource === request.resource
        && intent.lease_template.access === request.access
        && hashObject(intent.lease_template.owner) === hashObject(owner)
        && intent.resource_head,
      'CORRUPT_STORE',
      `resource acquire intent ${name} binding 非法`,
    );
    safeId(request.event_id, 'resource acquire event_id');
    safeId(owner.goal_id, 'resource acquire owner.goal_id');
    safeId(owner.task_id, 'resource acquire owner.task_id');
    const accepted = acceptedEvents.get(request.event_id);
    if (accepted) {
      assertControl(
        !staged,
        'CORRUPT_STORE',
        `resource acquire staging ${name} 与 accepted event 并存`,
      );
      const acquired = accepted.type === 'LEASE_ACQUIRED'
        && hashObject(accepted.actor) === hashObject(owner)
        && accepted.lease
        && accepted.lease.lease_id === intent.lease_template.lease_id
        && accepted.lease.resource === request.resource
        && accepted.lease.access === request.access
        && hashObject(accepted.lease.owner) === hashObject(owner);
      const aborted = accepted.type === 'LEASE_ACQUIRE_ABORTED'
        && accepted.request_sha256 === hashObject(request)
        && hashObject(accepted.actor) === hashObject(owner)
        && accepted.lease_id === intent.lease_template.lease_id
        && accepted.resource === request.resource
        && accepted.access === request.access
        && accepted.fencing_token === intent.lease_template.fencing_token
        && accepted.ttl_ms === request.ttl_ms;
      assertControl(
        acquired || aborted,
        'CORRUPT_STORE',
        `resource acquire intent ${name} 与 accepted event lineage 不一致`,
      );
      continue;
    }
    pending.push({
      kind: 'RESOURCE_ACQUIRE',
      operation_id: request.event_id,
      request_sha256: hashObject(request),
      goal_id: owner.goal_id,
      task_id: owner.task_id,
      allowed_event_id: null,
      allowed_resource_event_id: request.event_id,
      marker_file: file,
    });
  }
  return pending;
}

function sourceRecord(root, evidence) {
  let file;
  try {
    const source = new URL(evidence.uri);
    assertControl(
      source.protocol === 'file:',
      'CORRUPT_STORE',
      `incident evidence ${evidence.evidence_id} source 必须是 file URI`,
    );
    file = fileURLToPath(source);
  } catch {
    assertControl(
      false,
      'CORRUPT_STORE',
      `incident evidence ${evidence.evidence_id} uri 非法`,
    );
  }
  let body;
  try {
    const before = fs.lstatSync(file);
    assertControl(
      before.isFile()
        && !before.isSymbolicLink()
        && before.size <= IDENTITY_INCIDENT_SOURCE_MAX_BYTES,
      'CORRUPT_STORE',
      `incident evidence ${evidence.evidence_id} source 类型或大小非法`,
    );
    body = fs.readFileSync(file);
    const after = fs.lstatSync(file);
    assertControl(
      after.isFile()
        && !after.isSymbolicLink()
        && before.dev === after.dev
        && before.ino === after.ino
        && before.size === after.size
        && before.mtimeMs === after.mtimeMs
        && body.length === before.size,
      'CORRUPT_STORE',
      `incident evidence ${evidence.evidence_id} source 在读取期间变化`,
    );
  } catch (error) {
    if (!error || !['ENOENT', 'ENOTDIR'].includes(error.code)) throw error;
    if (
      evidence.kind !== 'HOLD_ASSERTION'
        || evidence.stage !== 'PREFLIGHT'
    ) {
      throw new ControlError(
        'EVIDENCE_SOURCE_MISSING',
        `incident evidence ${evidence.evidence_id} source 不存在: ${error.message}`,
      );
    }
    body = readProtocolSealedIdentityIncidentEvidenceSource(root, evidence);
  }
  assertControl(
    `sha256:${sha256(body)}` === normalizeHash(evidence.source_sha256),
    'CORRUPT_STORE',
    `incident evidence ${evidence.evidence_id} source hash 漂移`,
  );
  try {
    const source = JSON.parse(body.toString('utf8'));
    assertControl(
      source && typeof source === 'object' && !Array.isArray(source),
      'CORRUPT_STORE',
      `incident evidence ${evidence.evidence_id} source 格式非法`,
    );
    return source;
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'CORRUPT_STORE',
      `incident evidence ${evidence.evidence_id} source 无法解析: ${error.message}`,
    );
  }
}

function preflightNeedsIdentityIncident(evidence) {
  return evidence.kind === 'PREFLIGHT'
    && evidence.status === 'FAIL'
    && (evidence.checks || []).some((check) => {
      const match = typeof check.detail === 'string'
        ? /^([A-Z][A-Z0-9_]*):/.exec(check.detail)
        : null;
      return check.status === 'FAIL'
        && PREFLIGHT_IDENTITY_FAILURES.has(check.name)
        && !PREFLIGHT_POLICY_FAILURES.has(match && match[1]);
    });
}

function validateRegistrationIntentRecord(
  intent,
  eventId,
  goalId,
  { requirePreparedRequest = false } = {},
) {
  const request = intent && intent.request;
  const authority = intent && intent.authorizer_authority;
  safeId(eventId, 'registration event_id');
  assertControl(
    intent
      && intent.schema_version === 1
      && intent.kind === 'REGISTRATION_INTENT'
      && intent.event_id === eventId
      && intent.goal_id === goalId
      && typeof intent.task_id === 'string'
      && request
      && request.schema_version === 1
      && request.event_id === eventId
      && request.goal_id === goalId
      && request.task_id === intent.task_id
      && ['FOREMAN', 'CAPTAIN', 'DEV', 'REVIEW', 'RECEIPT'].includes(
        request.role,
      )
      && typeof request.thread_id === 'string'
      && typeof request.host_id === 'string'
      && Number.isSafeInteger(request.attempt)
      && request.attempt > 0
      && Number.isSafeInteger(request.lease_ms)
      && request.lease_ms > 0
      && authority
      && typeof authority === 'object'
      && !Array.isArray(authority)
      && intent.request_sha256 === hashObject(request)
      && Number.isFinite(Date.parse(intent.accepted_at)),
    'CORRUPT_STORE',
    `registration intent ${eventId} Goal/task/request binding 漂移`,
  );
  safeId(intent.task_id, 'registration task_id');
  safeId(request.thread_id, 'registration thread_id');
  safeId(request.host_id, 'registration host_id');
  const preparedRequestSha256 = hashObject({
    request,
    authorizer_authority: authority,
  });
  assertControl(
    !requirePreparedRequest
      ? (
        intent.prepared_request_sha256 === undefined
          || intent.prepared_request_sha256 === preparedRequestSha256
      )
      : intent.prepared_request_sha256 === preparedRequestSha256,
    'CORRUPT_STORE',
    `registration intent ${eventId} prepared request binding 漂移`,
  );
  return {
    intent,
    request,
    preparedRequestSha256,
  };
}

function preparedRegistrationIntent(root, goalId, directory, name, match) {
  const stat = fs.lstatSync(directory);
  assertCurrentOwnerOrdinary(
    stat,
    'directory',
    `registration staging ${name}`,
    { privateMode: true },
  );
  const intentFile = path.join(directory, 'intent.json');
  assertControl(
    fs.existsSync(intentFile),
    'CORRUPT_STORE',
    `registration staging ${name}/intent.json 缺失`,
  );
  assertCurrentOwnerOrdinary(
    fs.lstatSync(intentFile),
    'file',
    `registration staging ${name}/intent.json`,
    { privateMode: true },
  );
  const intent = sealedRecord(
    intentFile,
    'intent_sha256',
    `registration staging ${name}`,
  );
  const validated = validateRegistrationIntentRecord(
    intent,
    intent.event_id,
    goalId,
    { requirePreparedRequest: true },
  );
  assertControl(
    match[1] === sha256(intent.event_id)
      && match[2] === hashDigest(
        validated.preparedRequestSha256,
        `registration staging ${name} prepared_request_sha256`,
      ),
    'CORRUPT_STORE',
    `registration staging ${name} protocol name 未绑定 sealed request`,
  );
  const finalDirectory = path.join(
    root,
    'goals',
    goalId,
    'registration-intents',
    intent.event_id,
  );
  assertControl(
    !fs.existsSync(finalDirectory),
    'CORRUPT_STORE',
    `registration staging ${name} 与 final intent ${intent.event_id} 并存`,
  );
  validatePreparedCapability(
    directory,
    finalDirectory,
    intent,
    new RegExp(
      `^${escapedPattern(intent.request.role.toLowerCase())}`
        + `-${intent.request.attempt}-[0-9a-f]{24}\\.cap$`,
    ),
    `registration staging ${name}`,
  );
  return {
    ...intent,
    marker_file: intentFile,
    staged: true,
    staging_directory: directory,
  };
}

function listPendingGoalRegistrationIntents(root, goalId) {
  safeId(goalId, 'goal_id');
  const directory = path.join(
    root,
    'goals',
    goalId,
    'registration-intents',
  );
  if (!fs.existsSync(directory)) return [];
  const acceptedByTask = new Map();
  const pending = [];
  const entries = fs.readdirSync(directory).sort();
  const stagedEntries = entries.filter((name) => name.startsWith('.init-'));
  assertControl(
    stagedEntries.length <= 1,
    'CORRUPT_STORE',
    'Goal 同时存在多个 registration prepared staging',
  );
  const candidates = [];
  for (const name of entries) {
    if (name.startsWith('.init-')) {
      const match = REGISTRATION_STAGING_PATTERN.exec(name);
      assertControl(
        match,
        'CORRUPT_STORE',
        `registration staging ${name} 不是 protocol deterministic name`,
      );
      candidates.push(preparedRegistrationIntent(
        root,
        goalId,
        path.join(directory, name),
        name,
        match,
      ));
      continue;
    }
    safeId(name, 'registration intent directory');
    const intentDirectory = path.join(directory, name);
    const stat = fs.lstatSync(intentDirectory);
    assertControl(
      stat.isDirectory() && !stat.isSymbolicLink(),
      'CORRUPT_STORE',
      `registration intent ${name} 非普通目录`,
    );
    const file = path.join(intentDirectory, 'intent.json');
    const intent = sealedRecord(
      file,
      'intent_sha256',
      `registration intent ${name}`,
    );
    validateRegistrationIntentRecord(
      intent,
      name,
      goalId,
    );
    candidates.push({ ...intent, marker_file: file, staged: false });
  }
  for (const intent of candidates) {
    if (!acceptedByTask.has(intent.task_id)) {
      acceptedByTask.set(
        intent.task_id,
        acceptedEventIds(root, goalId, intent.task_id),
      );
    }
    if (acceptedByTask.get(intent.task_id).has(intent.event_id)) {
      assertControl(
        intent.staged !== true,
        'CORRUPT_STORE',
        `registration staging ${path.basename(intent.staging_directory || '')}`
          + ' 与 accepted event 并存',
      );
    } else {
      pending.push(intent);
    }
  }
  assertControl(
    pending.length <= 1,
    'CORRUPT_STORE',
    'Goal 同时存在多个未完成 registration intent',
  );
  return pending;
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

function validateRecoveryScope(scope, goalId, label) {
  assertControl(
    scope
      && scope.schema_version === 1
      && scope.goal_id === goalId
      && Number.isSafeInteger(scope.control_epoch)
      && scope.control_epoch >= 0
      && Array.isArray(scope.tasks)
      && scope.scope_sha256 === hashObject(recoveryScopeCore(scope)),
    'CORRUPT_STORE',
    `${label} Goal scope seal/binding 漂移`,
  );
  const taskIds = scope.tasks.map((task) => {
    assertControl(
      task && typeof task.task_id === 'string',
      'CORRUPT_STORE',
      `${label} Goal scope task identity 非法`,
    );
    return safeId(task.task_id, `${label} scope task_id`);
  });
  assertControl(
    new Set(taskIds).size === taskIds.length,
    'CORRUPT_STORE',
    `${label} Goal scope 含重复 task`,
  );
  return new Set(taskIds);
}

function validateForemanRecoveryIntent(intent, goalId, rootRecoveryId) {
  const request = intent && intent.request;
  const scope = intent && intent.goal_scope;
  safeId(rootRecoveryId, 'root recovery event_id');
  const scopeTaskIds = validateRecoveryScope(
    scope,
    goalId,
    `FOREMAN recovery staging ${rootRecoveryId}`,
  );
  assertControl(
    intent
      && intent.schema_version === 1
      && intent.kind === 'FOREMAN_RECOVERY_INTENT'
      && intent.goal_id === goalId
      && intent.root_recovery_id === rootRecoveryId
      && request
      && request.schema_version === 2
      && request.root_recovery_id === rootRecoveryId
      && request.goal_id === goalId
      && request.expected_goal_scope_sha256 === scope.scope_sha256
      && request.successor
      && request.successor.role === 'FOREMAN'
      && intent.successor
      && hashObject(intent.successor) === hashObject(request.successor)
      && Array.isArray(request.target_task_ids)
      && Array.isArray(request.source_task_ids)
      && Array.isArray(intent.target_task_ids)
      && Array.isArray(intent.source_task_ids)
      && hashObject(intent.target_task_ids)
        === hashObject(request.target_task_ids)
      && hashObject(intent.source_task_ids)
        === hashObject(request.source_task_ids)
      && (intent.adoption_target_task_id || null)
        === (request.adoption_target_task_id || null)
      && intent.goal_scope_sha256 === scope.scope_sha256
      && intent.request_sha256 === hashObject(request)
      && intent.prepared_request_sha256 === intent.request_sha256
      && Number.isFinite(Date.parse(intent.accepted_at)),
    'CORRUPT_STORE',
    `FOREMAN recovery staging ${rootRecoveryId} request binding 漂移`,
  );
  safeId(request.anchor_task_id, 'root recovery anchor_task_id');
  safeId(request.successor.thread_id, 'root recovery successor thread_id');
  safeId(request.successor.host_id, 'root recovery successor host_id');
  assertControl(
    Number.isSafeInteger(request.successor.attempt)
      && request.successor.attempt > 1
      && Number.isSafeInteger(request.successor.lease_ms)
      && request.successor.lease_ms > 0
      && request.target_task_ids.length > 0
      && request.source_task_ids.length > 0
      && request.target_task_ids.every((taskId) => (
        typeof taskId === 'string'
          && scopeTaskIds.has(safeId(taskId, 'root recovery target task_id'))
      ))
      && request.source_task_ids.every((taskId) => (
        typeof taskId === 'string'
          && scopeTaskIds.has(safeId(taskId, 'root recovery source task_id'))
      ))
      && new Set(request.target_task_ids).size === request.target_task_ids.length
      && new Set(request.source_task_ids).size === request.source_task_ids.length
      && scopeTaskIds.has(request.anchor_task_id)
      && (
        request.adoption_target_task_id === null
          || (
            typeof request.adoption_target_task_id === 'string'
              && request.target_task_ids.includes(
                safeId(
                  request.adoption_target_task_id,
                  'root recovery adoption_target_task_id',
                ),
              )
          )
      ),
    'CORRUPT_STORE',
    `FOREMAN recovery staging ${rootRecoveryId} scope/successor binding 非法`,
  );
  return {
    intent,
    request,
    requestSha256: hashObject(request),
  };
}

function preparedForemanRecoveryIntent(
  root,
  goalId,
  directory,
  name,
  match,
) {
  const stat = fs.lstatSync(directory);
  assertCurrentOwnerOrdinary(
    stat,
    'directory',
    `FOREMAN recovery staging ${name}`,
    { privateMode: true },
  );
  const intentFile = path.join(directory, 'intent.json');
  assertControl(
    fs.existsSync(intentFile),
    'CORRUPT_STORE',
    `FOREMAN recovery staging ${name}/intent.json 缺失`,
  );
  assertCurrentOwnerOrdinary(
    fs.lstatSync(intentFile),
    'file',
    `FOREMAN recovery staging ${name}/intent.json`,
    { privateMode: true },
  );
  const intent = sealedRecord(
    intentFile,
    'record_sha256',
    `FOREMAN recovery staging ${name}`,
  );
  const validated = validateForemanRecoveryIntent(
    intent,
    goalId,
    intent.root_recovery_id,
  );
  assertControl(
    match[1] === sha256(intent.root_recovery_id)
      && match[2] === hashDigest(
        validated.requestSha256,
        `FOREMAN recovery staging ${name} request_sha256`,
      ),
    'CORRUPT_STORE',
    `FOREMAN recovery staging ${name} protocol name 未绑定 sealed request`,
  );
  const finalDirectory = path.join(
    root,
    'goals',
    goalId,
    'foreman-recovery-batches',
    intent.root_recovery_id,
  );
  assertControl(
    !fs.existsSync(finalDirectory),
    'CORRUPT_STORE',
    `FOREMAN recovery staging ${name} 与 final batch`
      + ` ${intent.root_recovery_id} 并存`,
  );
  validatePreparedCapability(
    directory,
    finalDirectory,
    intent,
    new RegExp(
      `^foreman-${intent.request.successor.attempt}-[0-9a-f]{24}\\.cap$`,
    ),
    `FOREMAN recovery staging ${name}`,
  );
  return {
    kind: 'FOREMAN_RECOVERY_BATCH',
    operation_id: intent.root_recovery_id,
    root_recovery_id: intent.root_recovery_id,
    request_sha256: validated.requestSha256,
    goal_id: goalId,
    allowed_event_id: null,
    marker_file: intentFile,
    staged: true,
    staging_directory: directory,
  };
}

function listPendingGoalRecoveryStagings(root, goalId) {
  safeId(goalId, 'goal_id');
  const directory = path.join(
    root,
    'goals',
    goalId,
    'foreman-recovery-batches',
  );
  if (!fs.existsSync(directory)) return [];
  const staged = [];
  for (const name of fs.readdirSync(directory).sort()) {
    if (!name.startsWith('.')) {
      safeId(name, 'FOREMAN recovery batch directory');
      continue;
    }
    const match = FOREMAN_RECOVERY_STAGING_PATTERN.exec(name);
    assertControl(
      match,
      'CORRUPT_STORE',
      `FOREMAN recovery staging ${name} 不是 protocol deterministic name`,
    );
    staged.push(preparedForemanRecoveryIntent(
      root,
      goalId,
      path.join(directory, name),
      name,
      match,
    ));
  }
  assertControl(
    staged.length <= 1,
    'CORRUPT_STORE',
    'Goal 同时存在多个 FOREMAN recovery prepared staging',
  );
  return staged;
}

function listPendingGoalOperations(root, goalId) {
  const pending = [
    ...listPendingGoalRegistrationIntents(root, goalId).map((intent) => ({
      kind: 'REGISTRATION',
      operation_id: intent.event_id,
      event_id: intent.event_id,
      request_sha256: intent.request_sha256,
      goal_id: goalId,
      task_id: intent.task_id,
      allowed_event_id: intent.event_id,
      marker_file: intent.marker_file,
      staged: intent.staged === true,
      ...(intent.staging_directory
        ? { staging_directory: intent.staging_directory }
        : {}),
    })),
    ...listPendingGoalRecoveryStagings(root, goalId).map((operation) => ({
      kind: operation.kind,
      operation_id: operation.operation_id,
      root_recovery_id: operation.root_recovery_id,
      request_sha256: operation.request_sha256,
      goal_id: operation.goal_id,
      allowed_event_id: operation.allowed_event_id,
      marker_file: operation.marker_file,
      staged: operation.staged,
      staging_directory: operation.staging_directory,
    })),
    ...listPendingGoalSourceImportHashOperations(root, goalId),
  ];
  assertControl(
    pending.length <= 1,
    'CORRUPT_STORE',
    `Goal ${goalId} 同时存在多个 prepared/pending writer`,
  );
  return pending;
}

function readPartialSourceBindingFile(
  file,
  goalId,
  taskId,
  snapshotId,
) {
  const snapshotLabel = snapshotId || '<pathname-hash-bound>';
  assertCurrentOwnerOrdinary(
    fs.lstatSync(file),
    'file',
    `source export partial staging ${snapshotLabel}/operation-binding.json`,
    { exactMode: 0o600 },
  );
  const binding = readJson(
    file,
    `source export partial staging ${snapshotLabel} operation binding`,
  );
  assertControl(
    binding
      && typeof binding === 'object'
      && !Array.isArray(binding)
      && Object.keys(binding).length === PARTIAL_SOURCE_BINDING_KEYS.length
      && PARTIAL_SOURCE_BINDING_KEYS.every((key) => (
        Object.prototype.hasOwnProperty.call(binding, key)
      )),
    'CORRUPT_STORE',
    `source export partial staging ${snapshotLabel} binding 字段非协议集合`,
  );
  const unsigned = { ...binding };
  delete unsigned.binding_sha256;
  assertControl(
    binding.schema_version === 1
      && typeof binding.snapshot_id === 'string'
      && (snapshotId === null || binding.snapshot_id === snapshotId)
      && binding.goal_id === goalId
      && binding.task_id === taskId
      && ['SOURCE_WORKTREE', 'CODEX_ROLLOUT'].includes(
        binding.operation_kind,
      )
      && normalizeHash(
        binding.binding_sha256,
        `source export ${snapshotLabel} binding_sha256`,
      ) === hashObject(unsigned),
    'CORRUPT_STORE',
    `source export partial staging ${snapshotLabel} binding seal/identity 漂移`,
  );
  safeId(binding.snapshot_id, 'source export binding snapshot_id');
  return {
    file,
    binding: {
      ...binding,
      operation_request_sha256: normalizeHash(
        binding.operation_request_sha256,
        `source export ${snapshotLabel} operation_request_sha256`,
      ),
      execution_sha256: normalizeHash(
        binding.execution_sha256,
        `source export ${snapshotLabel} execution_sha256`,
      ),
    },
  };
}

function sourceAtomicTarget(name) {
  const match =
    /^\.([^\0/]+)\.[1-9][0-9]*\.tmp-[0-9a-f]{24}$/.exec(name);
  return match ? match[1] : null;
}

function sourceInventoryTarget(name, directoryKind) {
  const atomicTarget = sourceAtomicTarget(name);
  const target = atomicTarget || name;
  let allowed;
  if (directoryKind === 'root') {
    allowed = [
      PARTIAL_SOURCE_BINDING_FILE,
      'tracked.patch',
      'snapshot.json',
    ].includes(target);
  } else if (directoryKind === 'untracked') {
    allowed = /^[0-9]{6}\.bin$/.test(target);
  } else {
    allowed = [
      'codex-rollout-events.jsonl',
      'codex-shell-audit.json',
      'codex-shell-records.jsonl',
    ].includes(target);
  }
  return allowed
    ? { target, temporary: atomicTarget !== null }
    : null;
}

function sourceStagingInventory(directory, identityLabel) {
  const rootTargets = new Map();
  let child = null;
  for (const name of fs.readdirSync(directory).sort()) {
    const candidate = path.join(directory, name);
    const stat = fs.lstatSync(candidate);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      assertCurrentOwnerOrdinary(
        stat,
        'directory',
        `${identityLabel}/${name}`,
        { exactMode: 0o700 },
      );
      assertControl(
        ['untracked', 'provenance'].includes(name) && child === null,
        'CORRUPT_STORE',
        `${identityLabel} 含未知/重复子目录`,
      );
      child = {
        directory: candidate,
        kind: name,
        targets: new Map(),
      };
      continue;
    }
    assertCurrentOwnerOrdinary(
      stat,
      'file',
      `${identityLabel}/${name}`,
      { exactMode: 0o600 },
    );
    const artifact = sourceInventoryTarget(name, 'root');
    assertControl(
      artifact && !rootTargets.has(artifact.target),
      'CORRUPT_STORE',
      `${identityLabel} 含未知、重复或 canonical+temp root artifact`,
    );
    rootTargets.set(artifact.target, {
      ...artifact,
      file: candidate,
      name,
    });
  }
  if (child) {
    for (const name of fs.readdirSync(child.directory).sort()) {
      const candidate = path.join(child.directory, name);
      assertCurrentOwnerOrdinary(
        fs.lstatSync(candidate),
        'file',
        `${identityLabel}/${child.kind}/${name}`,
        { exactMode: 0o600 },
      );
      const artifact = sourceInventoryTarget(name, child.kind);
      assertControl(
        artifact && !child.targets.has(artifact.target),
        'CORRUPT_STORE',
        `${identityLabel} 含未知、重复或 canonical+temp child artifact`,
      );
      child.targets.set(artifact.target, {
        ...artifact,
        file: candidate,
        name,
      });
    }
  }
  return { rootTargets, child };
}

function inspectSealedSourceManifest(
  directory,
  goalId,
  taskId,
  snapshotId,
  manifestName,
) {
  const sourceHandoff = require('./source-handoff');
  assertControl(
    typeof sourceHandoff.inspectPendingSourceSnapshotStaging === 'function',
    'CORRUPT_STORE',
    'source staging decoder 未提供完整 sealed snapshot inspector',
  );
  return sourceHandoff.inspectPendingSourceSnapshotStaging(
    directory,
    goalId,
    taskId,
    snapshotId,
    manifestName,
  );
}

function preliminarySourceExportRequest(operationRequest) {
  if (operationRequest.kind === 'SOURCE_WORKTREE') return operationRequest;
  assertControl(
    operationRequest.kind === 'CODEX_ROLLOUT',
    'CORRUPT_STORE',
    `source export operation kind 非法: ${String(operationRequest.kind)}`,
  );
  return {
    ...operationRequest,
    rollout_file: typeof operationRequest.rollout_file === 'string'
      ? operationRequest.rollout_file
      : operationRequest.rollout_file.path,
    shell_audit_file: operationRequest.shell_audit_file === null
      ? null
      : (
        typeof operationRequest.shell_audit_file === 'string'
          ? operationRequest.shell_audit_file
          : operationRequest.shell_audit_file.path
      ),
  };
}

function hashedSourcePending(candidate, goalId, taskId) {
  const stableIdSha256 = `sha256:${candidate.snapshotDigest}`;
  return {
    kind: 'SOURCE_EXPORT',
    operation_id: null,
    stable_id_sha256: stableIdSha256,
    stable_id_unavailable: true,
    request_sha256: candidate.operationRequestDigest
      ? `sha256:${candidate.operationRequestDigest}`
      : null,
    goal_id: goalId,
    task_id: taskId,
    allowed_event_id: null,
    marker_file: candidate.directory,
    partial: true,
    hashed_identity: true,
    ...(candidate.discarded ? { cleanup_pending: true } : {}),
  };
}

function sourcePendingFromCandidate(candidate, goalId, taskId) {
  const label = `source export ${path.basename(candidate.directory)}`;
  const inventory = sourceStagingInventory(candidate.directory, label);
  const bindingArtifact = inventory.rootTargets.get(
    PARTIAL_SOURCE_BINDING_FILE,
  );
  if (!bindingArtifact) {
    assertControl(
      inventory.rootTargets.size === 0
        && inventory.child === null
        && (candidate.format === 'v2' || candidate.discarded),
      'CORRUPT_STORE',
      `${label} 无 binding 时不是合法 empty v2/discard`,
    );
    return hashedSourcePending(candidate, goalId, taskId);
  }
  const partial = readPartialSourceBindingFile(
    bindingArtifact.file,
    goalId,
    taskId,
    candidate.snapshotId,
  );
  const binding = partial.binding;
  if (!candidate.snapshotId) {
    assertControl(
      binding.snapshot_id
        && sha256(binding.snapshot_id) === candidate.snapshotDigest,
      'CORRUPT_STORE',
      `${label} snapshot pathname hash/binding 漂移`,
    );
    candidate.snapshotId = safeId(
      binding.snapshot_id,
      'source export snapshot_id',
    );
  }
  assertControl(
    binding.snapshot_id === candidate.snapshotId,
    'CORRUPT_STORE',
    `${label} snapshot identity 漂移`,
  );
  const bindingDigest = hashDigest(
    binding.binding_sha256,
    `${label} binding_sha256`,
  );
  const operationRequestDigest = hashDigest(
    binding.operation_request_sha256,
    `${label} operation_request_sha256`,
  );
  assertControl(
    (
      candidate.format !== 'v2'
        || (
          candidate.snapshotDigest === sha256(binding.snapshot_id)
            && candidate.operationRequestDigest === operationRequestDigest
            && candidate.bindingDigest === bindingDigest
        )
    )
      && (
        !candidate.discarded
          || (
            candidate.snapshotDigest === sha256(binding.snapshot_id)
              && candidate.bindingDigest === bindingDigest
          )
      ),
    'CORRUPT_STORE',
    `${label} pathname/binding hash lineage 漂移`,
  );
  const allowedChild = binding.operation_kind === 'SOURCE_WORKTREE'
    ? 'untracked'
    : 'provenance';
  const trackedArtifact = inventory.rootTargets.get('tracked.patch');
  assertControl(
    !bindingArtifact.temporary
      || (
        !candidate.discarded
          && inventory.rootTargets.size === 1
          && inventory.child === null
      ),
    'CORRUPT_STORE',
    `${label} binding atomic temp 不是唯一 durable artifact`,
  );
  assertControl(
    (inventory.child === null || inventory.child.kind === allowedChild)
      && (!inventory.child || trackedArtifact),
    'CORRUPT_STORE',
    `${label} child inventory 与 operation_kind/patch 顺序不一致`,
  );
  const manifestArtifact = inventory.rootTargets.get('snapshot.json');
  assertControl(
    !manifestArtifact || trackedArtifact,
    'CORRUPT_STORE',
    `${label} snapshot manifest 缺先行 tracked.patch`,
  );
  if (candidate.discarded && manifestArtifact && !manifestArtifact.temporary) {
    assertControl(
      false,
      'CORRUPT_STORE',
      `${label} discard 禁止携带 canonical sealed snapshot`,
    );
  }
  let requestSha256 = binding.operation_request_sha256;
  let markerFile = bindingArtifact.file;
  if (manifestArtifact) {
    const inspected = inspectSealedSourceManifest(
      candidate.directory,
      goalId,
      taskId,
      binding.snapshot_id,
      manifestArtifact.name,
    );
    requestSha256 = hashObject(preliminarySourceExportRequest(
      inspected.snapshot.operation_request,
    ));
    assertControl(
      inspected.snapshot.snapshot_id === binding.snapshot_id
        && inspected.snapshot.goal_id === goalId
        && inspected.snapshot.task_id === taskId
        && inspected.snapshot.operation_request.kind === binding.operation_kind
        && requestSha256 === binding.operation_request_sha256,
      'CORRUPT_STORE',
      `${label} sealed snapshot/binding request lineage 漂移`,
    );
    markerFile = inspected.manifest_file;
  }
  return {
    kind: 'SOURCE_EXPORT',
    operation_id: binding.snapshot_id,
    request_sha256: requestSha256,
    goal_id: goalId,
    task_id: taskId,
    allowed_event_id: null,
    marker_file: markerFile,
    partial: !manifestArtifact,
    ...(bindingArtifact.temporary
      ? { binding_atomic_pending: true }
      : {}),
    ...(manifestArtifact && manifestArtifact.temporary
      ? { snapshot_atomic_pending: true }
      : {}),
    ...(candidate.discarded ? { cleanup_pending: true } : {}),
  };
}

function listPendingSourceExportOperations(root, goalId, taskId) {
  const snapshotDirectory = path.join(
    root,
    'goals',
    goalId,
    'recovery-handoffs',
    taskId,
    'snapshots',
  );
  if (!fs.existsSync(snapshotDirectory)) return [];
  const candidates = [];
  const entries = fs.readdirSync(snapshotDirectory).sort();
  const stableSnapshotIds = entries
    .filter((name) => !name.startsWith('.'))
    .map((name) => safeId(name, 'source export stable snapshot_id'));
  for (const name of entries) {
    if (!name.startsWith('.')) {
      continue;
    }
    const v2 = SOURCE_EXPORT_STAGING_V2_PATTERN.exec(name);
    const legacy = LEGACY_SOURCE_EXPORT_STAGING_PATTERN.exec(name);
    const discarded = SOURCE_EXPORT_DISCARD_PATTERN.exec(name);
    assertControl(
      v2 || legacy || discarded,
      'CORRUPT_STORE',
      `source export staging/discard ${name} 不是 protocol name`,
    );
    const directory = path.join(snapshotDirectory, name);
    assertCurrentOwnerOrdinary(
      fs.lstatSync(directory),
      'directory',
      `source export staging/discard ${name}`,
      { exactMode: 0o700 },
    );
    candidates.push({
      directory,
      format: v2 ? 'v2' : (legacy ? 'legacy' : 'discard'),
      discarded: Boolean(discarded),
      snapshotId: legacy
        ? safeId(legacy[1], 'legacy source export snapshot_id')
        : null,
      snapshotDigest: v2 ? v2[1] : (discarded ? discarded[1] : null),
      operationRequestDigest: v2 ? v2[2] : null,
      bindingDigest: v2 ? v2[3] : (discarded ? discarded[2] : null),
    });
  }
  assertControl(
    candidates.length <= 1,
    'CORRUPT_STORE',
    `task ${taskId} 同时存在多个 source staging/discard`,
  );
  assertControl(
    candidates.every((candidate) => (
      candidate.snapshotId
        ? !stableSnapshotIds.includes(candidate.snapshotId)
        : !stableSnapshotIds.some((snapshotId) => (
          sha256(snapshotId) === candidate.snapshotDigest
        ))
    )),
    'CORRUPT_STORE',
    `task ${taskId} source final/staging snapshot 并存`,
  );
  return candidates.map((candidate) => (
    sourcePendingFromCandidate(candidate, goalId, taskId)
  ));
}

function validateSourceImportIntentFile(
  file,
  goalId,
  taskId,
  importId = null,
) {
  const importLabel = importId || '<pathname-hash-bound>';
  assertCurrentOwnerOrdinary(
    fs.lstatSync(file),
    'file',
    `source import intent ${importLabel}`,
    { exactMode: 0o600 },
  );
  const intent = readJson(file, `source import intent ${importLabel}`);
  assertControl(
    intent
      && typeof intent === 'object'
      && !Array.isArray(intent)
      && Object.keys(intent).length === SOURCE_IMPORT_INTENT_KEYS.length
      && SOURCE_IMPORT_INTENT_KEYS.every((key) => (
        Object.prototype.hasOwnProperty.call(intent, key)
      )),
    'CORRUPT_STORE',
    `source import intent ${importLabel} fields 非协议集合`,
  );
  const unsigned = { ...intent };
  delete unsigned.intent_sha256;
  const request = intent.request;
  assertControl(
    intent.schema_version === 1
      && intent.kind === 'RECOVERY_IMPORT_INTENT'
      && typeof intent.import_id === 'string'
      && (importId === null || intent.import_id === importId)
      && intent.goal_id === goalId
      && intent.task_id === taskId
      && request
      && request.schema_version === 1
      && request.import_id === intent.import_id
      && request.goal_id === goalId
      && request.task_id === taskId
      && request.snapshot_id === intent.snapshot_id
      && normalizeHash(
        request.snapshot_sha256,
        `source import ${importLabel} request snapshot_sha256`,
      ) === normalizeHash(
        intent.snapshot_sha256,
        `source import ${importLabel} intent snapshot_sha256`,
      )
      && request.successor_thread_id === intent.successor_thread_id
      && intent.task_anchor
      && typeof intent.task_anchor === 'object'
      && !Array.isArray(intent.task_anchor)
      && intent.acceptance_authority
      && typeof intent.acceptance_authority === 'object'
      && !Array.isArray(intent.acceptance_authority)
      && intent.request_sha256 === hashObject(request)
      && intent.prepared_request_sha256 === hashObject({
        request,
        task_anchor: intent.task_anchor,
        acceptance_authority: intent.acceptance_authority,
      })
      && intent.intent_sha256 === hashObject(unsigned)
      && Number.isFinite(Date.parse(intent.accepted_at)),
    'CORRUPT_STORE',
    `source import intent ${importLabel} seal/request binding 漂移`,
  );
  safeId(intent.import_id, 'source import intent import_id');
  safeId(intent.snapshot_id, 'source import intent snapshot_id');
  safeId(intent.successor_thread_id, 'source import successor_thread_id');
  return intent;
}

function sourceImportStagingInventory(directory, label) {
  const entries = fs.readdirSync(directory).sort();
  const canonical = entries.filter((name) => name === 'intent.json');
  const temporaries = entries.filter((name) => (
    sourceAtomicTarget(name) === 'intent.json'
  ));
  assertControl(
    entries.length <= 1
      && canonical.length <= 1
      && temporaries.length <= 1
      && !(canonical.length && temporaries.length)
      && entries.every((name) => (
        name === 'intent.json' || temporaries.includes(name)
      )),
    'CORRUPT_STORE',
    `${label} inventory 非协议状态`,
  );
  if (entries.length === 0) return null;
  const name = canonical[0] || temporaries[0];
  return {
    file: path.join(directory, name),
    name,
    temporary: temporaries.length === 1,
  };
}

function hashedSourceImportPending(candidate, goalId, taskId) {
  const stableIdSha256 = `sha256:${candidate.importDigest}`;
  return {
    kind: 'SOURCE_IMPORT',
    operation_id: null,
    stable_id_sha256: stableIdSha256,
    stable_id_unavailable: true,
    request_sha256: `sha256:${candidate.requestDigest}`,
    goal_id: goalId,
    task_id: taskId,
    allowed_event_id: null,
    marker_file: candidate.directory,
    partial: true,
    hashed_identity: true,
  };
}

function listPendingSourceImportOperations(root, goalId, taskId) {
  const parent = path.join(
    root,
    'goals',
    goalId,
    'recovery-handoffs',
    taskId,
    'import-intents',
  );
  if (!fs.existsSync(parent)) return [];
  const entries = fs.readdirSync(parent).sort();
  const stableImportIds = entries
    .filter((name) => !name.startsWith('.'))
    .map((name) => safeId(name, 'source import stable import_id'));
  const pending = [];
  const staged = [];
  for (const name of entries) {
    const directory = path.join(parent, name);
    if (!name.startsWith('.')) {
      assertCurrentOwnerOrdinary(
        fs.lstatSync(directory),
        'directory',
        `source import stable intent ${name}`,
        { exactMode: 0o700 },
      );
      assertExactDirectoryEntries(
        directory,
        ['intent.json'],
        `source import stable intent ${name}`,
      );
      const intentFile = path.join(directory, 'intent.json');
      const intent = validateSourceImportIntentFile(
        intentFile,
        goalId,
        taskId,
        name,
      );
      const receipt = path.join(
        root,
        'goals',
        goalId,
        'recovery-handoffs',
        taskId,
        'import-receipts',
        `${name}.json`,
      );
      if (!fs.existsSync(receipt)) {
        pending.push({
          kind: 'SOURCE_IMPORT',
          operation_id: intent.import_id,
          request_sha256: intent.request_sha256,
          goal_id: goalId,
          task_id: taskId,
          allowed_event_id: null,
          marker_file: intentFile,
        });
      }
      continue;
    }
    const v2 = SOURCE_IMPORT_STAGING_V2_PATTERN.exec(name);
    const legacy = LEGACY_SOURCE_IMPORT_STAGING_PATTERN.exec(name);
    assertControl(
      v2 || legacy,
      'CORRUPT_STORE',
      `source import staging ${name} 不是 protocol name`,
    );
    assertCurrentOwnerOrdinary(
      fs.lstatSync(directory),
      'directory',
      `source import staging ${name}`,
      { exactMode: 0o700 },
    );
    staged.push({
      directory,
      format: v2 ? 'v2' : 'legacy',
      importId: legacy
        ? safeId(legacy[1], 'legacy source import import_id')
        : null,
      importDigest: v2 ? v2[1] : null,
      requestDigest: v2 ? v2[2] : null,
      preparedDigest: v2 ? v2[3] : null,
    });
  }
  assertControl(
    staged.length <= 1,
    'CORRUPT_STORE',
    `task ${taskId} 同时存在多个 source import staging`,
  );
  for (const candidate of staged) {
    assertControl(
      candidate.importId
        ? !stableImportIds.includes(candidate.importId)
        : !stableImportIds.some((importId) => (
          sha256(importId) === candidate.importDigest
        )),
      'CORRUPT_STORE',
      `task ${taskId} source import final/staging 并存`,
    );
    const label = `source import staging ${path.basename(candidate.directory)}`;
    const artifact = sourceImportStagingInventory(
      candidate.directory,
      label,
    );
    if (!artifact) {
      assertControl(
        candidate.format === 'v2',
        'CORRUPT_STORE',
        `${label} legacy empty staging 无 durable request identity`,
      );
      pending.push(hashedSourceImportPending(candidate, goalId, taskId));
      continue;
    }
    const intent = validateSourceImportIntentFile(
      artifact.file,
      goalId,
      taskId,
      candidate.importId,
    );
    assertControl(
      candidate.format !== 'v2'
        || (
          candidate.importDigest === sha256(intent.import_id)
            && candidate.requestDigest === hashDigest(
              intent.request_sha256,
              `${label} request_sha256`,
            )
            && candidate.preparedDigest === hashDigest(
              intent.prepared_request_sha256,
              `${label} prepared_request_sha256`,
            )
        ),
      'CORRUPT_STORE',
      `${label} pathname/intent hash lineage 漂移`,
    );
    const receipt = path.join(
      root,
      'goals',
      goalId,
      'recovery-handoffs',
      taskId,
      'import-receipts',
      `${intent.import_id}.json`,
    );
    assertControl(
      !fs.existsSync(receipt),
      'CORRUPT_STORE',
      `${label} 与 completed import receipt 并存`,
    );
    pending.push({
      kind: 'SOURCE_IMPORT',
      operation_id: intent.import_id,
      request_sha256: intent.request_sha256,
      goal_id: goalId,
      task_id: taskId,
      allowed_event_id: null,
      marker_file: artifact.file,
      staged: true,
      ...(artifact.temporary ? { intent_atomic_pending: true } : {}),
    });
  }
  assertControl(
    pending.length <= 1,
    'CORRUPT_STORE',
    `task ${taskId} 同时存在多个未完成 source import intent`,
  );
  return pending;
}

function listPendingGoalSourceImportHashOperations(root, goalId) {
  const handoffRoot = path.join(
    root,
    'goals',
    goalId,
    'recovery-handoffs',
  );
  if (!fs.existsSync(handoffRoot)) return [];
  const pending = [];
  for (const taskId of fs.readdirSync(handoffRoot).sort()) {
    if (taskId.startsWith('.')) {
      assertControl(
        false,
        'CORRUPT_STORE',
        `Goal ${goalId} recovery handoff task entry ${taskId} 非法`,
      );
    }
    safeId(taskId, 'source import handoff task_id');
    const taskDirectory = path.join(handoffRoot, taskId);
    const stat = fs.lstatSync(taskDirectory);
    assertControl(
      stat.isDirectory() && !stat.isSymbolicLink(),
      'CORRUPT_STORE',
      `Goal ${goalId} recovery handoff task ${taskId} 非普通目录`,
    );
    for (const operation of listPendingSourceImportOperations(
      root,
      goalId,
      taskId,
    )) {
      if (operation.hashed_identity) pending.push(operation);
    }
  }
  return pending;
}

function listPendingSourceCheckpointOperations(root, goalId, taskId) {
  const parent = path.join(
    root,
    'goals',
    goalId,
    'recovery-handoffs',
    taskId,
    'checkpoint-fences',
  );
  if (!fs.existsSync(parent)) return [];
  assertCurrentOwnerOrdinary(
    fs.lstatSync(parent),
    'directory',
    `task ${taskId} checkpoint fence root`,
    { exactMode: 0o700 },
  );
  const pending = [];
  for (const digest of fs.readdirSync(parent).sort()) {
    assertControl(
      /^[0-9a-f]{64}$/.test(digest),
      'CORRUPT_STORE',
      `task ${taskId} checkpoint fence request digest 非法`,
    );
    const directory = path.join(parent, digest);
    assertCurrentOwnerOrdinary(
      fs.lstatSync(directory),
      'directory',
      `task ${taskId} checkpoint fence ${digest}`,
      { exactMode: 0o700 },
    );
    const entries = fs.readdirSync(directory).sort();
    const allowedEntries = new Set([
      'completed.json',
      'prepared.json',
      'ref-transaction.fence',
    ]);
    assertControl(
      entries.length >= 1
        && entries.length <= allowedEntries.size
        && entries.includes('prepared.json')
        && entries.every((entry) => allowedEntries.has(entry)),
      'CORRUPT_STORE',
      `task ${taskId} checkpoint fence ${digest} inventory 非协议状态`,
    );
    const preparedFile = path.join(directory, 'prepared.json');
    assertCurrentOwnerOrdinary(
      fs.lstatSync(preparedFile),
      'file',
      `task ${taskId} checkpoint fence prepared`,
      { exactMode: 0o600 },
    );
    const marker = sealedRecord(
      preparedFile,
      'fence_sha256',
      `task ${taskId} checkpoint fence prepared`,
    );
    assertControl(
      marker.schema_version === 1
        && marker.kind === CHECKPOINT_GIT_FENCE_KIND
        && marker.request
        && marker.request.goal_id === goalId
        && marker.request.task_id === taskId
        && marker.request_sha256 === hashObject(marker.request)
        && marker.request_sha256.slice('sha256:'.length) === digest
        && marker.worktree === marker.request.destination_worktree
        && typeof marker.git_dir === 'string'
        && path.isAbsolute(marker.git_dir)
        && path.normalize(marker.git_dir) === marker.git_dir
        && typeof marker.index_lock_file === 'string'
        && path.isAbsolute(marker.index_lock_file)
        && path.normalize(marker.index_lock_file)
          === marker.index_lock_file
        && Number.isSafeInteger(marker.original_git_dir_mode)
        && Number.isSafeInteger(marker.fenced_git_dir_mode)
        && marker.fenced_git_dir_mode
          === (marker.original_git_dir_mode & ~0o222)
        && typeof marker.lock_token === 'string'
        && marker.ref_transaction
        && typeof marker.ref_transaction === 'object'
        && !Array.isArray(marker.ref_transaction)
        && Object.keys(marker.ref_transaction).sort().join(',')
          === 'expected_reflog,fence_file,ref'
        && marker.ref_transaction.ref === marker.request.branch_ref
        && marker.ref_transaction.fence_file
          === path.join(directory, 'ref-transaction.fence'),
      'CORRUPT_STORE',
      `task ${taskId} checkpoint fence ${digest} binding 非法`,
    );
    safeId(marker.request.snapshot_id, 'checkpoint fence snapshot_id');
    safeId(
      marker.request.import_receipt_id,
      'checkpoint fence import_receipt_id',
    );
    safeId(marker.lock_token, 'checkpoint fence lock_token');
    const refFencePresent = entries.includes('ref-transaction.fence');
    if (refFencePresent) {
      const inspected = inspectLooseRefFence({
        fenceFile: marker.ref_transaction.fence_file,
        expectedNew: marker.request.checkpoint_sha,
        codes: {
          refConflict: 'CORRUPT_STORE',
          lockConflict: 'CORRUPT_STORE',
          fenceConflict: 'CORRUPT_STORE',
          invalidRef: 'CORRUPT_STORE',
        },
        label: `task ${taskId} checkpoint ref transaction fence`,
      });
      assertControl(
        inspected !== null,
        'CORRUPT_STORE',
        `task ${taskId} checkpoint ref transaction fence inventory 漂移`,
      );
    }
    let completed = null;
    if (entries.includes('completed.json')) {
      const completedFile = path.join(directory, 'completed.json');
      assertCurrentOwnerOrdinary(
        fs.lstatSync(completedFile),
        'file',
        `task ${taskId} checkpoint fence completion`,
        { exactMode: 0o600 },
      );
      completed = sealedRecord(
        completedFile,
        'completion_sha256',
        `task ${taskId} checkpoint fence completion`,
      );
      assertControl(
        completed.schema_version === 1
          && completed.kind === CHECKPOINT_GIT_FENCE_COMPLETION_KIND
          && completed.request_sha256 === marker.request_sha256
          && completed.fence_sha256 === marker.fence_sha256
          && completed.checkpoint_sha === marker.request.checkpoint_sha,
        'CORRUPT_STORE',
        `task ${taskId} checkpoint fence completion binding 非法`,
      );
    }
    let gitDirFenced = false;
    let gitDirExists = false;
    if (fs.existsSync(marker.git_dir)) {
      gitDirExists = true;
      const gitDirStat = fs.lstatSync(marker.git_dir);
      assertControl(
        gitDirStat.isDirectory()
          && !gitDirStat.isSymbolicLink()
          && String(gitDirStat.dev) === marker.git_dir_dev
          && String(gitDirStat.ino) === marker.git_dir_ino,
        'CORRUPT_STORE',
        `task ${taskId} checkpoint fence gitdir identity 漂移`,
      );
      const mode = gitDirStat.mode & 0o7777;
      assertControl(
        mode === marker.original_git_dir_mode
          || mode === marker.fenced_git_dir_mode,
        'CORRUPT_STORE',
        `task ${taskId} checkpoint fence gitdir mode 漂移`,
      );
      gitDirFenced = mode === marker.fenced_git_dir_mode;
    }
    const lockExists = fs.existsSync(marker.index_lock_file);
    if (lockExists) {
      assertCurrentOwnerOrdinary(
        fs.lstatSync(marker.index_lock_file),
        'file',
        `task ${taskId} checkpoint index lock`,
        { exactMode: 0o600 },
      );
      assertControl(
        fs.readFileSync(marker.index_lock_file, 'utf8')
          === `${marker.lock_token}\n`,
        'CORRUPT_STORE',
        `task ${taskId} checkpoint index lock token 漂移`,
      );
    }
    if (!completed || lockExists || gitDirFenced || refFencePresent) {
      pending.push({
        kind: 'SOURCE_CHECKPOINT',
        operation_id: null,
        stable_id_sha256: marker.request_sha256,
        stable_id_unavailable: true,
        request_sha256: marker.request_sha256,
        goal_id: goalId,
        task_id: taskId,
        allowed_event_id: null,
        marker_file: preparedFile,
        snapshot_id: marker.request.snapshot_id,
        import_receipt_id: marker.request.import_receipt_id,
        checkpoint_sha: marker.request.checkpoint_sha,
        git_dir_exists: gitDirExists,
        git_dir_fenced: gitDirFenced,
        index_lock_present: lockExists,
        ref_transaction_fence_present: refFencePresent,
        completed: completed !== null,
      });
    }
  }
  assertControl(
    pending.length <= 1,
    'CORRUPT_STORE',
    `task ${taskId} 同时存在多个未完成 source checkpoint fence`,
  );
  return pending;
}

function listPendingTaskOperations(root, goalId, taskId, options = {}) {
  safeId(goalId, 'goal_id');
  safeId(taskId, 'task_id');
  const pending = [];
  const seen = new Set();
  const acceptedIds = acceptedEventIds(root, goalId, taskId);
  const add = (operation) => {
    const key = `${operation.kind}:${
      operation.operation_id || operation.stable_id_sha256 || '<unbound>'
    }`;
    if (seen.has(key)) return;
    seen.add(key);
    pending.push(operation);
  };

  if (options.excludeGoalOperations !== true) {
    for (const operation of listPendingGoalOperations(root, goalId)) {
      add(operation);
    }
  }

  for (const operation of listPendingResourceOperations(root)) {
    if (operation.goal_id === goalId && operation.task_id === taskId) {
      add(operation);
    }
  }

  for (const operation of listPendingSourceExportOperations(
    root,
    goalId,
    taskId,
  )) {
    add(operation);
  }

  for (const operation of listPendingSourceImportOperations(
    root,
    goalId,
    taskId,
  )) {
    add(operation);
  }

  for (const operation of listPendingSourceCheckpointOperations(
    root,
    goalId,
    taskId,
  )) {
    add(operation);
  }

  const {
    listP1CommitOperations,
  } = require('./p1-commit-transaction');
  for (const operation of listP1CommitOperations(
    root,
    goalId,
    taskId,
  )) {
    add(operation);
  }

  const {
    listGitHubMergeOperations,
  } = require('./github-merge');
  for (const operation of listGitHubMergeOperations(
    root,
    goalId,
    taskId,
  )) {
    add(operation);
  }

  const genericDirectory = path.join(
    root,
    'goals',
    goalId,
    'evidence-ingress',
    taskId,
  );
  for (const file of jsonFiles(genericDirectory)) {
    const prepared = sealedRecord(
      file,
      'prepared_sha256',
      `prepared evidence ingress ${path.basename(file)}`,
    );
    assertControl(
      prepared.goal_id === goalId && prepared.task_id === taskId,
      'CORRUPT_STORE',
      `prepared evidence ingress ${path.basename(file)} task binding 漂移`,
    );
    if (!fs.existsSync(registryFile(
      root,
      goalId,
      taskId,
      prepared.evidence_id,
    ))) {
      add({
        kind: 'GENERIC_EVIDENCE',
        operation_id: prepared.evidence_id,
        request_sha256: prepared.ingress_sha256,
        allowed_event_id: null,
        marker_file: file,
      });
    }
  }

  const artifactDirectory = path.join(
    root,
    'goals',
    goalId,
    'evidence-artifacts',
    taskId,
  );
  for (const file of jsonFiles(artifactDirectory)) {
    const name = path.basename(file);
    let prepared = null;
    let evidenceId = null;
    let kind = null;
    if (name.endsWith('-preflight-prepared.json')) {
      prepared = sealedRecord(file, 'prepared_sha256', `prepared preflight ${name}`);
      evidenceId = prepared.request && prepared.request.evidence_id;
      kind = 'PREFLIGHT';
    } else if (name.endsWith('-artifact.json')) {
      prepared = sealedRecord(file, 'artifact_sha256', `prepared gate ${name}`);
      evidenceId = prepared.request && prepared.request.evidence_id;
      kind = prepared.adapter;
    }
    if (!prepared) continue;
    const preparedGoalId = prepared.goal_id
      || (prepared.request && prepared.request.goal_id);
    const preparedTaskId = prepared.task_id
      || (prepared.request && prepared.request.task_id);
    assertControl(
      preparedGoalId === goalId
        && preparedTaskId === taskId
        && typeof evidenceId === 'string',
      'CORRUPT_STORE',
      `prepared artifact ${name} task binding 漂移`,
    );
    if (!fs.existsSync(registryFile(root, goalId, taskId, evidenceId))) {
      add({
        kind,
        operation_id: evidenceId,
        request_sha256: hashObject(prepared.request),
        allowed_event_id: null,
        marker_file: file,
      });
    }
  }

  const evidenceDirectory = path.join(
    root,
    'goals',
    goalId,
    'evidence',
    taskId,
  );
  for (const file of jsonFiles(evidenceDirectory)) {
    const candidate = readJson(
      file,
      `evidence directory record ${path.basename(file)}`,
    );
    if (
      !candidate
        || typeof candidate.evidence_id !== 'string'
        || path.basename(file)
          !== `${safeId(candidate.evidence_id, 'evidence_id')}.json`
    ) {
      continue;
    }
    const evidence = sealedRecord(
      file,
      'registry_sha256',
      `evidence registry ${path.basename(file)}`,
    );
    if (preflightNeedsIdentityIncident(evidence)) {
      const digest = sha256(evidence.evidence_id).slice(0, 32);
      const eventId = `env-identity-hold-${digest}`;
      const incidentEvidenceId = `env-incident-${digest}`;
      const incidentRegistry = registryFile(
        root,
        goalId,
        taskId,
        incidentEvidenceId,
      );
      if (!acceptedIds.has(eventId) && !fs.existsSync(incidentRegistry)) {
        add({
          kind: 'PREFLIGHT_IDENTITY_INCIDENT',
          operation_id: evidence.evidence_id,
          request_sha256: hashObject({
            evidence_id: evidence.evidence_id,
            checks: evidence.checks,
          }),
          allowed_event_id: null,
          allowed_event_sha256: null,
          allowed_evidence_id: incidentEvidenceId,
          expected_event_id: eventId,
          marker_file: file,
        });
      }
    }
    if (
      evidence.kind !== 'HOLD_ASSERTION'
        || !['PREFLIGHT', 'RESOURCE_VERIFY'].includes(evidence.stage)
    ) {
      continue;
    }
    const source = sourceRecord(root, evidence);
    const incident = source.incident_event;
    const recognized = source.adapter === 'PREFLIGHT_IDENTITY_INCIDENT'
      || source.kind === 'RESOURCE_IDENTITY_INCIDENT';
    if (
      recognized
        && incident
        && typeof incident.event_id === 'string'
        && !acceptedIds.has(incident.event_id)
    ) {
      add({
        kind: evidence.stage === 'PREFLIGHT'
          ? 'PREFLIGHT_IDENTITY_INCIDENT'
          : 'RESOURCE_IDENTITY_INCIDENT',
        operation_id: evidence.evidence_id,
        request_sha256: hashObject(source.request),
        allowed_event_id: incident.event_id,
        allowed_event_sha256: hashObject(incident),
        allowed_evidence_id: null,
        expected_event_id: incident.event_id,
        marker_file: file,
      });
    }
  }

  return pending.sort((left, right) => (
    `${left.kind}:${left.operation_id}`
      .localeCompare(`${right.kind}:${right.operation_id}`)
  ));
}

function operationAllowed(operation, options) {
  const operationIdMatches = Boolean(
    options.allowOperationId
      && (
        operation.operation_id === options.allowOperationId
          || (
            operation.stable_id_unavailable === true
              && typeof operation.stable_id_sha256 === 'string'
              && sha256(options.allowOperationId) === hashDigest(
                operation.stable_id_sha256,
                `${operation.kind} pending stable_id_sha256`,
              )
          )
      ),
  );
  return Boolean(
    (
      options.allowEvidenceId
        && operation.allowed_evidence_id === options.allowEvidenceId
    )
      || (
        options.allowEventId
          && options.allowEventSha256
          && operation.allowed_event_id === options.allowEventId
          && operation.allowed_event_sha256 === options.allowEventSha256
      )
      || (
        options.allowOperationKind
          && options.allowRequestSha256
          && operation.kind === options.allowOperationKind
          && operationIdMatches
          && operation.request_sha256 === options.allowRequestSha256
      )
      || (
        options.allowOperationKind
          && options.allowUnboundOperationMarkerFile
          && operation.kind === options.allowOperationKind
          && operationIdMatches
          && operation.request_sha256 === null
          && typeof operation.marker_file === 'string'
          && path.resolve(operation.marker_file)
            === path.resolve(options.allowUnboundOperationMarkerFile)
      )
  );
}

function assertNoPending(pending, options, label) {
  const blocking = options.forArchive === true
    ? pending
    : pending.filter((operation) => !operationAllowed(operation, options));
  assertControl(
    blocking.length === 0,
    'TASK_OPERATION_PENDING',
    `${label} 有未 seal durable operation: ${blocking
      .map((item) => (
        `${item.kind}:${
          item.operation_id
            || item.stable_id_sha256
            || '<stable-id-unavailable>'
        }`
      ))
      .join(', ')}${
        options.allowUnboundOperationMarkerFile
          ? `; unbound-marker allowance=${
            options.allowUnboundOperationMarkerFile
          }; observed=${
            blocking.map((item) => item.marker_file || '<none>').join(',')
          }`
          : ''
      }`,
    {
      blocking: blocking.map((operation) => ({
        kind: operation.kind,
        operation_id: operation.operation_id || null,
        request_sha256: operation.request_sha256 ?? null,
        marker_file: operation.marker_file || null,
      })),
      allowance: {
        operation_kind: options.allowOperationKind || null,
        operation_id: options.allowOperationId || null,
        request_sha256: options.allowRequestSha256 || null,
        unbound_marker_file:
          options.allowUnboundOperationMarkerFile || null,
      },
    },
  );
  return pending;
}

function assertNoPendingTaskOperations(
  root,
  goalId,
  taskId,
  options = {},
) {
  return assertNoPending(
    listPendingTaskOperations(root, goalId, taskId, options),
    options,
    `task ${taskId}`,
  );
}

function assertNoPendingGoalOperations(root, goalId, options = {}) {
  return assertNoPending(
    listPendingGoalOperations(root, goalId),
    options,
    `Goal ${goalId}`,
  );
}

function assertNoPendingResourceOperations(root, options = {}) {
  return assertNoPending(
    listPendingResourceOperations(root),
    options,
    'resource ledger',
  );
}

module.exports = {
  assertNoPendingGoalOperations,
  assertNoPendingResourceOperations,
  assertNoPendingTaskOperations,
  listPendingGoalOperations,
  listPendingGoalRecoveryStagings,
  listPendingGoalRegistrationIntents,
  listPendingResourceOperations,
  listPendingSourceExportOperations,
  listPendingSourceImportOperations,
  listPendingTaskOperations,
};
