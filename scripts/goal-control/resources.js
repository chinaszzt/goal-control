'use strict';

const fs = require('fs');
const path = require('path');
const { fileURLToPath } = require('url');
const { assertControl, ControlError } = require('./errors');
const { actorSequenceKey } = require('./fsm');
const {
  authorizeGoalSession,
  authorizeSession,
  createCapabilityFile,
  hashesEqual,
  readCapabilityFile,
} = require('./auth');
const {
  inspectPreparedEvidenceBytesForRetryUnderLock,
  readExistingEvidenceForRetryUnderLock,
  recordEvidenceBytesUnderLock,
  semanticIngressPreparedFile,
} = require('./evidence');
const {
  acceptEventUnderLock,
  assertFrozenInputs,
  loadGoalStateReadOnly,
  loadGoalStateUnlocked,
} = require('./goal');
const {
  preparedIdentityIncidentAuthorization,
  sealIdentityIncidentEventAuthority,
} = require('./incident-authority');
const {
  atomicWriteJson,
  canonicalTransactionKey,
  ensureDir,
  isHistoricalTransactionRetry,
  isOddTransactionRetry,
  readJsonIfExists,
  sealChainedRecord,
  withLock,
  withStableRead,
} = require('./store');
const { fsyncDirectory } = require('./init-receipt');
const {
  controlRoot,
  assertIsolatedTestMode,
  hashFile,
  hashObject,
  normalizeHash,
  nowIso,
  optionalInteger,
  randomId,
  readJson,
  runtimeNowMilliseconds,
  safeId,
  sha256,
} = require('./util');
const { HARD_HOLDS, ROLES } = require('./validation');
const { assertOperationalScope } = require('./operational-scope');

const ACTIVE = 'ACTIVE';
const TERMINAL = new Set(['RELEASED', 'REAPED']);
const UNVERIFIED_REVOKE = 'UNVERIFIED_REVOKE';
const RESOURCE_KEY_RE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?::[A-Za-z0-9][A-Za-z0-9._-]*)+$/;
const MAX_RESOURCE_TTL_MS = 4 * 60 * 60 * 1000;
const RESOURCE_RENEWAL_MAX_LEAD_MS = MAX_RESOURCE_TTL_MS / 4;
const RESOURCE_RENEWAL_TERM_DIVISOR = 4;
const PRISTINE_ABORT_RETRY = 'STORE_PRISTINE_ABORT_RETRY';
const RESOURCE_KIND_PREFIX = Object.freeze({
  PORT: 'preview-port',
  BROWSER_PROFILE: 'browser-profile',
  ACCOUNT: 'account',
  TIM_SESSION: 'tim-session',
  WINDOW: 'window',
  EXECUTABLE: 'executable',
  TEST_DATA: 'test-data',
});
const WORKER_RESOURCE_ROLES = Object.freeze(['DEV', 'REVIEW', 'RECEIPT']);

function requirementAppliesToRole(requirement, role) {
  if (
    requirement.roles === undefined
      && process.env.GOAL_CONTROL_TEST_LEGACY_RESOURCE_ROLE_DEFAULT === '1'
  ) {
    assertIsolatedTestMode();
    return true;
  }
  const roles = requirement.roles === undefined
    ? WORKER_RESOURCE_ROLES
    : requirement.roles;
  return roles.includes(role);
}

function currentTimeMilliseconds() {
  return runtimeNowMilliseconds();
}

function maybeInjectResourceGenerationBoundaryFault(
  cwd,
  environmentName,
) {
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
    'TEST_FAULT_AFTER_RESOURCE_GENERATION',
    `injected resource generation boundary failure: ${environmentName}`,
  );
}

function resourceGenerationBoundaryFaultHook(cwd, environmentName) {
  const mode = process.env[environmentName];
  if (mode === undefined || mode === '') return undefined;
  assertIsolatedTestMode(cwd);
  return () => (
    maybeInjectResourceGenerationBoundaryFault(cwd, environmentName)
  );
}

function maybeAdvanceAcquireClockAfterBoundaryForTest() {
  const override = process.env.GOAL_CONTROL_TEST_ACQUIRE_NOW_AFTER_BOUNDARY;
  if (override === undefined || override === '') return;
  assertIsolatedTestMode();
  const numeric = Number(override);
  const parsed = Number.isFinite(numeric) ? numeric : Date.parse(override);
  assertControl(
    Number.isFinite(parsed),
    'INVALID_TEST_FAULT',
    'GOAL_CONTROL_TEST_ACQUIRE_NOW_AFTER_BOUNDARY 必须是 ISO 时间或毫秒时间戳',
  );
  process.env.GOAL_CONTROL_NOW = new Date(parsed).toISOString();
}

function resourcePaths(root) {
  const dir = path.join(root, 'resources');
  return {
    dir,
    events: path.join(dir, 'events'),
    head: path.join(dir, 'head.json'),
    projection: path.join(dir, 'resources.json'),
    capabilities: path.join(dir, 'capabilities'),
  };
}

function sealedHead(value) {
  const head = { ...value };
  head.head_sha256 = hashObject(head);
  return head;
}

function validateHead(head) {
  assertExactKeys(head, ['schema_version', 'event_count', 'last_event_sha256', 'fencing_tokens', 'updated_at', 'head_sha256'], 'resource head');
  assertControl(head && head.schema_version === 1, 'CORRUPT_STORE', 'resource head 格式非法');
  const unsigned = { ...head };
  delete unsigned.head_sha256;
  assertControl(hashObject(unsigned) === head.head_sha256, 'CORRUPT_STORE', 'resource head hash 不匹配');
  assertControl(Number.isSafeInteger(head.event_count) && head.event_count >= 0, 'CORRUPT_STORE', 'resource head event_count 非法');
  assertControl(head.last_event_sha256 === null || /^sha256:[0-9a-f]{64}$/.test(head.last_event_sha256), 'CORRUPT_STORE', 'resource head last hash 非法');
  assertControl(head.fencing_tokens && typeof head.fencing_tokens === 'object' && !Array.isArray(head.fencing_tokens), 'CORRUPT_STORE', 'resource head fencing_tokens 非法');
  for (const [resource, token] of Object.entries(head.fencing_tokens)) {
    assertControl(RESOURCE_KEY_RE.test(resource) && Number.isSafeInteger(token) && token > 0, 'CORRUPT_STORE', 'resource head fencing token 非法');
  }
  assertControl(typeof head.updated_at === 'string' && Number.isFinite(Date.parse(head.updated_at)), 'CORRUPT_STORE', 'resource head updated_at 非法');
}

function writeHead(paths, value) {
  atomicWriteJson(paths.head, sealedHead(value));
}

function eventFiles(paths) {
  if (!fs.existsSync(paths.events)) return [];
  return fs.readdirSync(paths.events)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => path.join(paths.events, name));
}

function resourceEventById(paths, eventId) {
  let match = null;
  for (const file of eventFiles(paths)) {
    const event = readResourceJson(file, `resource event ${path.basename(file)}`);
    if (event.event_id !== eventId) continue;
    assertControl(
      match === null,
      'CORRUPT_STORE',
      `resource event id ${eventId} 在 append-only ledger 中重复`,
    );
    match = event;
  }
  return match;
}

function readResourceJson(file, label) {
  try {
    return readJson(file, label);
  } catch (error) {
    assertControl(false, 'CORRUPT_STORE', `${label} 无法读取: ${error.message}`);
  }
}

function assertExactKeys(value, allowed, label) {
  assertControl(value && typeof value === 'object' && !Array.isArray(value), 'CORRUPT_STORE', `${label} 必须是对象`);
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  const missing = allowed.filter((key) => !(key in value));
  assertControl(unknown.length === 0 && missing.length === 0, 'CORRUPT_STORE', `${label} 字段不匹配 unknown=[${unknown.join(',')}] missing=[${missing.join(',')}]`);
}

function storedId(value, label) {
  assertControl(typeof value === 'string' && value.length <= 200 && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value), 'CORRUPT_STORE', `${label} 非法`);
}

function validateStoredOwner(owner, label) {
  assertExactKeys(owner, ['goal_id', 'task_id', 'role', 'thread_id', 'host_id'], label);
  storedId(owner.goal_id, `${label}.goal_id`);
  storedId(owner.task_id, `${label}.task_id`);
  assertControl(ROLES.includes(owner.role), 'CORRUPT_STORE', `${label}.role 非法`);
  storedId(owner.thread_id, `${label}.thread_id`);
  storedId(owner.host_id, `${label}.host_id`);
}

function validateStoredAuthority(authority, label) {
  assertExactKeys(authority, [
    'role',
    'thread_id',
    'host_id',
    'attempt',
    'capability_file',
    'capability_sha256',
  ], label);
  assertControl(ROLES.includes(authority.role), 'CORRUPT_STORE', `${label}.role 非法`);
  storedId(authority.thread_id, `${label}.thread_id`);
  storedId(authority.host_id, `${label}.host_id`);
  assertControl(Number.isSafeInteger(authority.attempt) && authority.attempt > 0, 'CORRUPT_STORE', `${label}.attempt 非法`);
  assertControl(typeof authority.capability_file === 'string' && path.isAbsolute(authority.capability_file), 'CORRUPT_STORE', `${label}.capability_file 非法`);
  assertControl(/^[0-9a-f]{64}$/.test(authority.capability_sha256), 'CORRUPT_STORE', `${label}.capability_sha256 非法`);
}

function validateStoredSessionBinding(binding, label) {
  assertExactKeys(binding, [
    'role',
    'thread_id',
    'host_id',
    'attempt',
    'launch_id',
  ], label);
  assertControl(ROLES.includes(binding.role), 'CORRUPT_STORE', `${label}.role 非法`);
  storedId(binding.thread_id, `${label}.thread_id`);
  storedId(binding.host_id, `${label}.host_id`);
  assertControl(Number.isSafeInteger(binding.attempt) && binding.attempt > 0, 'CORRUPT_STORE', `${label}.attempt 非法`);
  storedId(binding.launch_id, `${label}.launch_id`);
}

function validateStoredLease(lease) {
  assertExactKeys(lease, [
    'lease_id', 'resource', 'access', 'owner', 'owner_capability_sha256',
    'owner_capability_file', 'revision', 'fencing_token', 'status',
    'acquired_at', 'updated_at', 'expires_at',
  ], 'resource lease');
  storedId(lease.lease_id, 'resource lease_id');
  assertControl(typeof lease.resource === 'string' && RESOURCE_KEY_RE.test(lease.resource), 'CORRUPT_STORE', 'resource lease key 非法');
  assertControl(['EXCLUSIVE', 'SHARED_READ'].includes(lease.access), 'CORRUPT_STORE', 'resource lease access 非法');
  validateStoredOwner(lease.owner, 'resource lease owner');
  assertControl(typeof lease.owner_capability_sha256 === 'string' && /^[0-9a-f]{64}$/.test(lease.owner_capability_sha256), 'CORRUPT_STORE', 'owner capability verifier 非法');
  assertControl(typeof lease.owner_capability_file === 'string' && path.isAbsolute(lease.owner_capability_file), 'CORRUPT_STORE', 'owner capability file 非法');
  assertControl(lease.revision === 1 && Number.isSafeInteger(lease.fencing_token) && lease.fencing_token > 0, 'CORRUPT_STORE', 'resource lease revision/fencing 非法');
  assertControl(lease.status === ACTIVE, 'CORRUPT_STORE', 'acquired lease status 非法');
  for (const field of ['acquired_at', 'updated_at', 'expires_at']) {
    assertControl(typeof lease[field] === 'string' && Number.isFinite(Date.parse(lease[field])), 'CORRUPT_STORE', `resource lease ${field} 非法`);
  }
  assertControl(Date.parse(lease.expires_at) > Date.parse(lease.acquired_at), 'CORRUPT_STORE', 'resource lease expires_at 非法');
}

function validateStoredResourceEvent(event) {
  const common = ['schema_version', 'event_id', 'type', 'accepted_at', 'actor', 'log_sequence', 'previous_event_sha256', 'event_sha256'];
  const byType = {
    LEASE_ACQUIRED: [...common, 'lease'],
    LEASE_ACQUIRE_ABORTED: [
      ...common,
      'request_sha256',
      'resource',
      'access',
      'lease_id',
      'fencing_token',
      'ttl_ms',
      'reason',
    ],
    LEASE_RENEWED: [...common, 'lease_id', 'from_revision', 'to_revision', 'expires_at'],
    LEASE_RELEASED: [...common, 'lease_id', 'from_revision', 'to_revision'],
    LEASE_REAPED: [...common, 'lease_id', 'from_revision', 'to_revision', 'evidence_id'],
    LEASE_SET_REVOKED: [
      ...common,
      'leases',
      'lost_owner',
      'successor',
      'predecessor_launch_id',
      'predecessor_launch_sha256',
      'handoff_event_id',
      'authorized_by',
      'reason',
    ],
    ZERO_RUNTIME_REINITIALIZED: [
      ...common,
      'goal_id',
      'task_id',
      'handoff_event_id',
      'predecessor',
      'successor',
      'predecessor_launch_id',
      'predecessor_launch_sha256',
      'captain_authority',
      'foreman_authority',
      'leases',
    ],
  };
  assertControl(event && byType[event.type], 'CORRUPT_STORE', `未知 resource event type ${event && event.type}`);
  assertExactKeys(event, byType[event.type], `resource event ${event.event_id || '_unknown'}`);
  assertControl(event.schema_version === 1, 'CORRUPT_STORE', 'resource event schema_version 非法');
  storedId(event.event_id, 'resource event_id');
  assertControl(typeof event.accepted_at === 'string' && Number.isFinite(Date.parse(event.accepted_at)), 'CORRUPT_STORE', 'resource event accepted_at 非法');
  validateStoredOwner(event.actor, 'resource event actor');
  assertControl(Number.isSafeInteger(event.log_sequence) && event.log_sequence > 0, 'CORRUPT_STORE', 'resource event log_sequence 非法');
  assertControl(event.previous_event_sha256 === null || /^sha256:[0-9a-f]{64}$/.test(event.previous_event_sha256), 'CORRUPT_STORE', 'resource previous hash 非法');
  assertControl(/^sha256:[0-9a-f]{64}$/.test(event.event_sha256), 'CORRUPT_STORE', 'resource event hash 非法');
  if (event.type === 'LEASE_ACQUIRED') {
    validateStoredLease(event.lease);
    assertControl(hashObject(event.actor) === hashObject(event.lease.owner), 'CORRUPT_STORE', 'acquire actor 与 lease owner 不一致');
  } else if (event.type === 'LEASE_ACQUIRE_ABORTED') {
    assertControl(
      /^sha256:[0-9a-f]{64}$/.test(event.request_sha256),
      'CORRUPT_STORE',
      'aborted acquire request hash 非法',
    );
    assertControl(
      typeof event.resource === 'string'
        && RESOURCE_KEY_RE.test(event.resource)
        && ['EXCLUSIVE', 'SHARED_READ'].includes(event.access)
        && Number.isSafeInteger(event.fencing_token)
        && event.fencing_token > 0
        && Number.isSafeInteger(event.ttl_ms)
        && event.ttl_ms > 0
        && typeof event.reason === 'string'
        && event.reason.length > 0,
      'CORRUPT_STORE',
      'aborted acquire binding 非法',
    );
    storedId(event.lease_id, 'aborted acquire lease_id');
  } else if (event.type === 'ZERO_RUNTIME_REINITIALIZED') {
    storedId(event.goal_id, 'zero-runtime goal_id');
    storedId(event.task_id, 'zero-runtime task_id');
    storedId(event.handoff_event_id, 'zero-runtime handoff event');
    storedId(event.predecessor_launch_id, 'zero-runtime predecessor launch');
    assertControl(/^sha256:[0-9a-f]{64}$/.test(event.predecessor_launch_sha256), 'CORRUPT_STORE', 'zero-runtime launch digest 非法');
    validateStoredSessionBinding(event.predecessor, 'zero-runtime predecessor');
    validateStoredSessionBinding(event.successor, 'zero-runtime successor');
    validateStoredAuthority(event.captain_authority, 'zero-runtime captain authority');
    validateStoredAuthority(event.foreman_authority, 'zero-runtime foreman authority');
    assertControl(
      event.actor.goal_id === event.goal_id
        && event.actor.task_id === event.task_id
        && event.actor.role === 'CAPTAIN'
        && event.captain_authority.role === 'CAPTAIN'
        && event.foreman_authority.role === 'FOREMAN'
        && event.predecessor.role === 'DEV'
        && event.successor.role === 'DEV',
      'CORRUPT_STORE',
      'zero-runtime actor/authority/session roles 非法',
    );
    assertControl(
      event.actor.thread_id === event.captain_authority.thread_id
        && event.actor.host_id === event.captain_authority.host_id,
      'CORRUPT_STORE',
      'zero-runtime actor 与 CAPTAIN authority 不一致',
    );
    assertControl(
      Array.isArray(event.leases) && event.leases.length === 0,
      'CORRUPT_STORE',
      'zero-runtime receipt 必须绑定空 lease set',
    );
  } else if (event.type === 'LEASE_SET_REVOKED') {
    assertControl(Array.isArray(event.leases) && event.leases.length > 0, 'CORRUPT_STORE', 'revoked lease set 不能为空');
    validateStoredOwner(event.lost_owner, 'resource revoke lost owner');
    validateStoredOwner(event.successor, 'resource revoke successor');
    validateStoredOwner(event.authorized_by, 'resource revoke authorizer');
    assertControl(event.actor.role === 'CAPTAIN' && event.authorized_by.role === 'FOREMAN', 'CORRUPT_STORE', 'resource revoke 双授权角色非法');
    assertControl(event.actor.goal_id === event.lost_owner.goal_id && event.actor.task_id === event.lost_owner.task_id, 'CORRUPT_STORE', 'resource revoke actor task 非法');
    assertControl(event.successor.goal_id === event.lost_owner.goal_id && event.successor.task_id === event.lost_owner.task_id, 'CORRUPT_STORE', 'resource revoke successor task 非法');
    storedId(event.predecessor_launch_id, 'resource revoke predecessor launch');
    assertControl(/^sha256:[0-9a-f]{64}$/.test(event.predecessor_launch_sha256), 'CORRUPT_STORE', 'resource revoke launch digest 非法');
    storedId(event.handoff_event_id, 'resource revoke handoff event');
    assertControl(typeof event.reason === 'string' && event.reason.length > 0, 'CORRUPT_STORE', 'resource revoke reason 缺失');
    const leaseIds = new Set();
    for (const item of event.leases) {
      assertExactKeys(item, ['lease_id', 'resource', 'revision', 'fencing_token'], 'resource revoked lease');
      storedId(item.lease_id, 'resource revoked lease_id');
      assertControl(!leaseIds.has(item.lease_id), 'CORRUPT_STORE', 'resource revoke lease 重复');
      leaseIds.add(item.lease_id);
      assertControl(typeof item.resource === 'string' && RESOURCE_KEY_RE.test(item.resource), 'CORRUPT_STORE', 'resource revoke key 非法');
      assertControl(Number.isSafeInteger(item.revision) && item.revision > 0, 'CORRUPT_STORE', 'resource revoke revision 非法');
      assertControl(Number.isSafeInteger(item.fencing_token) && item.fencing_token > 0, 'CORRUPT_STORE', 'resource revoke fencing token 非法');
    }
  } else {
    storedId(event.lease_id, 'resource lease_id');
    assertControl(Number.isSafeInteger(event.from_revision) && event.from_revision > 0 && event.to_revision === event.from_revision + 1, 'CORRUPT_STORE', 'resource event revision 非法');
    if (event.expires_at !== undefined) assertControl(typeof event.expires_at === 'string' && Number.isFinite(Date.parse(event.expires_at)), 'CORRUPT_STORE', 'renew expires_at 非法');
    if (event.evidence_id !== undefined) storedId(event.evidence_id, 'resource evidence_id');
  }
}

function applyResourceEvent(state, event) {
  if (event.type === 'LEASE_ACQUIRED') {
    assertControl(!state.leases[event.lease.lease_id], 'CORRUPT_STORE', `重复 lease_id: ${event.lease.lease_id}`);
    state.leases[event.lease.lease_id] = { ...event.lease };
    state.fencing_tokens[event.lease.resource] = event.lease.fencing_token;
  } else if (event.type === 'LEASE_ACQUIRE_ABORTED') {
    assertControl(
      event.fencing_token === (state.fencing_tokens[event.resource] || 0) + 1,
      'CORRUPT_STORE',
      `aborted acquire ${event.event_id} fencing token 断裂`,
    );
    state.fencing_tokens[event.resource] = event.fencing_token;
  } else if (event.type === 'ZERO_RUNTIME_REINITIALIZED') {
    // This is a sealed safety receipt for a proven zero-runtime no-op. It
    // intentionally changes no lease projection.
  } else if (event.type === 'LEASE_SET_REVOKED') {
    for (const item of event.leases) {
      const lease = state.leases[item.lease_id];
      assertControl(lease, 'CORRUPT_STORE', `事件引用未知 lease: ${item.lease_id}`);
      assertControl(!TERMINAL.has(lease.status), 'CORRUPT_STORE', `lease ${item.lease_id} 已 terminal`);
      assertControl(
        lease.resource === item.resource
          && lease.revision === item.revision
          && lease.fencing_token === item.fencing_token,
        'CORRUPT_STORE',
        `lease ${item.lease_id} revoke binding 漂移`,
      );
      assertControl(hashObject(lease.owner) === hashObject(event.lost_owner), 'CORRUPT_STORE', `lease ${item.lease_id} lost owner 不一致`);
      lease.revision += 1;
      lease.updated_at = event.accepted_at;
      // Historical v1 decoders accepted LEASE_SET_REVOKED without a resource-
      // specific host fence. Preserve the append-only event for replay, but
      // quarantine its projection: it is not proof that the physical resource
      // became reusable.
      lease.status = UNVERIFIED_REVOKE;
      lease.unverified_revoke_at = event.accepted_at;
      lease.unverified_revoke = {
        event_id: event.event_id,
        actor: event.actor,
        authorized_by: event.authorized_by,
        successor: event.successor,
        predecessor_launch_id: event.predecessor_launch_id,
        predecessor_launch_sha256: event.predecessor_launch_sha256,
        handoff_event_id: event.handoff_event_id,
        reason: event.reason,
      };
    }
  } else {
    const lease = state.leases[event.lease_id];
    assertControl(lease, 'CORRUPT_STORE', `事件引用未知 lease: ${event.lease_id}`);
    assertControl(event.from_revision === lease.revision, 'CORRUPT_STORE', `lease ${event.lease_id} revision 断裂`);
    if (event.type === 'LEASE_REAPED') {
      assertControl(
        ['CAPTAIN', 'FOREMAN'].includes(event.actor.role)
          && event.actor.goal_id === lease.owner.goal_id
          && event.actor.task_id === lease.owner.task_id,
        'CORRUPT_STORE',
        `lease ${event.lease_id} reap actor 非法`
      );
    } else {
      assertControl(hashObject(event.actor) === hashObject(lease.owner), 'CORRUPT_STORE', `lease ${event.lease_id} actor 与 owner 不一致`);
    }
    lease.revision = event.to_revision;
    lease.updated_at = event.accepted_at;
    if (event.type === 'LEASE_RENEWED') {
      lease.expires_at = event.expires_at;
    } else if (event.type === 'LEASE_RELEASED') {
      lease.status = 'RELEASED';
      lease.released_at = event.accepted_at;
    } else if (event.type === 'LEASE_REAPED') {
      lease.status = 'REAPED';
      lease.reaped_at = event.accepted_at;
      lease.reap = {
        actor: event.actor,
        evidence_id: event.evidence_id,
      };
    } else {
      assertControl(false, 'CORRUPT_STORE', `未知资源事件 ${event.type}`);
    }
  }
  state.event_count += 1;
}

function rebuildUnlocked(root, options = {}) {
  const paths = resourcePaths(root);
  const state = {
    schema_version: 1,
    generated_at: nowIso(),
    event_count: 0,
    fencing_tokens: {},
    leases: {},
  };
  const files = eventFiles(paths);
  let previousEventHash = null;
  const seenEventIds = new Set();
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    const event = readResourceJson(file, `resource event ${path.basename(file)}`);
    const sequence = index + 1;
    assertControl(path.basename(file).startsWith(`${String(sequence).padStart(8, '0')}-`), 'CORRUPT_STORE', `resource event 序号缺口: ${path.basename(file)}`);
    assertControl(event.log_sequence === sequence, 'CORRUPT_STORE', `resource event log_sequence 应为 ${sequence}`);
    assertControl(event.previous_event_sha256 === previousEventHash, 'CORRUPT_STORE', 'resource event hash chain 断裂');
    const unsigned = { ...event };
    delete unsigned.event_sha256;
    assertControl(hashObject(unsigned) === event.event_sha256, 'CORRUPT_STORE', `resource event ${event.event_id} hash 不匹配`);
    validateStoredResourceEvent(event);
    assertControl(
      !seenEventIds.has(event.event_id),
      'CORRUPT_STORE',
      `resource event id ${event.event_id} 在 append-only ledger 中重复`,
    );
    seenEventIds.add(event.event_id);
    applyResourceEvent(state, event);
    previousEventHash = event.event_sha256;
  }
  const head = readJsonIfExists(paths.head, null);
  if (!head) {
    assertControl(files.length === 0, 'CORRUPT_STORE', 'resource head 缺失，无法证明 event tail 完整');
    if (options.repairHeads !== false) {
      writeHead(paths, {
        schema_version: 1,
        event_count: 0,
        last_event_sha256: null,
        fencing_tokens: {},
        updated_at: nowIso(),
      });
    }
  } else {
    validateHead(head);
    assertControl(Number.isSafeInteger(head.event_count) && head.event_count >= 0 && head.event_count <= files.length, 'CORRUPT_STORE', 'resource event tail 被删除');
    const anchoredHash = head.event_count === 0
      ? null
      : readResourceJson(files[head.event_count - 1], 'resource anchored event').event_sha256;
    assertControl(head.last_event_sha256 === anchoredHash, 'CORRUPT_STORE', 'resource event head hash 不匹配');
    if (head.event_count === files.length) {
      assertControl(hashObject(head.fencing_tokens || {}) === hashObject(state.fencing_tokens), 'CORRUPT_STORE', 'resource fencing token head 不匹配');
    }
  }
  if (!head || head.event_count < files.length) {
    if (options.repairHeads === false) {
      assertControl(
        options.allowLaggingHeads === true
          || (!head && files.length === 0),
        'STORE_REPAIR_REQUIRED',
        'resource head 落后 event tail；须由写权限控制角色运行 repair/rebuild',
      );
    } else {
      writeHead(paths, {
        schema_version: 1,
        event_count: files.length,
        last_event_sha256: previousEventHash,
        fencing_tokens: state.fencing_tokens,
        updated_at: files.length ? readResourceJson(files[files.length - 1], 'resource tail').accepted_at : nowIso(),
      });
    }
  }
  return { paths, state };
}

function rebuildResourcesReadOnlyUnlocked(root) {
  return rebuildUnlocked(root, { repairHeads: false });
}

function publicLease(lease, now = currentTimeMilliseconds()) {
  const {
    owner_capability_sha256: _secretVerifier,
    owner_capability_file: _capabilityFile,
    ...visible
  } = lease;
  if (visible.status === ACTIVE && Date.parse(visible.expires_at) <= now) visible.status = 'EXPIRED';
  return visible;
}

function writeProjection(paths, state) {
  const now = currentTimeMilliseconds();
  const projection = {
    schema_version: 1,
    generated_at: new Date(now).toISOString(),
    event_count: state.event_count,
    fencing_tokens: state.fencing_tokens,
    leases: Object.values(state.leases).map((lease) => publicLease(lease, now)),
  };
  atomicWriteJson(paths.projection, projection);
  return projection;
}

function appendEvent(paths, state, event) {
  ensureDir(paths.events);
  assertControl(
    !resourceEventById(paths, event.event_id),
    'RESOURCE_EVENT_ID_CONFLICT',
    `resource event id ${event.event_id} 已存在`,
  );
  const sequence = state.event_count + 1;
  const previousEventHash = state.event_count
    ? readResourceJson(eventFiles(paths)[state.event_count - 1], 'resource tail').event_sha256
    : null;
  const sealed = sealChainedRecord(event, sequence, previousEventHash);
  validateStoredResourceEvent(sealed);
  const filename = `${String(sequence).padStart(8, '0')}-${event.event_id.replace(/[^A-Za-z0-9._-]/g, '_')}.json`;
  const file = path.join(paths.events, filename);
  assertControl(!fs.existsSync(file), 'RESOURCE_EVENT_EXISTS', `资源事件文件已存在: ${filename}`);
  atomicWriteJson(file, sealed);
  if (process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_EVENT_INSTALL === '1') {
    assertIsolatedTestMode();
    throw new ControlError(
      'TEST_FAULT_AFTER_RESOURCE_EVENT_INSTALL',
      'injected failure after resource event install',
    );
  }
  applyResourceEvent(state, sealed);
  writeHead(paths, {
    schema_version: 1,
    event_count: sequence,
    last_event_sha256: sealed.event_sha256,
    fencing_tokens: state.fencing_tokens,
    updated_at: sealed.accepted_at,
  });
  return file;
}

function normalizeOwner(options) {
  const goalId = safeId(options.goalId, 'goal');
  const taskId = safeId(options.taskId, 'task');
  assertControl(ROLES.includes(options.role), 'INVALID_ROLE', `未知 role: ${options.role}`);
  const threadId = safeId(options.threadId, 'resource owner thread');
  const hostId = safeId(options.hostId || 'local', 'resource owner host');
  return {
    goal_id: goalId,
    task_id: taskId,
    role: options.role,
    thread_id: threadId,
    host_id: hostId,
  };
}

function actorIdentity(session, goalId, taskId) {
  return {
    goal_id: goalId,
    task_id: taskId,
    role: session.role,
    thread_id: session.thread_id,
    host_id: session.host_id,
  };
}

function authorizeResourceSession(
  loaded,
  state,
  capabilityFile,
  options = {},
) {
  let role = options.role || null;
  let supplied = null;
  if (!role && state.sessions && state.sessions.FOREMAN) {
    supplied = readCapabilityFile(capabilityFile);
    const foreman = state.sessions.FOREMAN;
    if (
      foreman.capability_file === supplied.file
        && hashesEqual(foreman.capability_sha256, supplied.sha256)
    ) {
      role = 'FOREMAN';
    }
  }
  if (role !== 'FOREMAN') {
    return authorizeSession(state, capabilityFile, options);
  }
  if (options.allowTerminal === true) {
    supplied = supplied || readCapabilityFile(capabilityFile);
    const current = state.sessions && state.sessions.FOREMAN;
    const targetsCurrentGoalForeman = current
      && current.capability_file === supplied.file
      && hashesEqual(current.capability_sha256, supplied.sha256);
    if (!targetsCurrentGoalForeman) {
      return authorizeSession(state, capabilityFile, options);
    }
  }
  return authorizeGoalSession(loaded.snapshot, capabilityFile, {
    role: 'FOREMAN',
    threadId: options.threadId || null,
  });
}

function authorityIdentity(session) {
  return {
    role: session.role,
    thread_id: session.thread_id,
    host_id: session.host_id,
    attempt: session.attempt,
    capability_file: session.capability_file,
    capability_sha256: session.capability_sha256,
  };
}

function authorityLiveness(session) {
  return {
    status: session.status,
    lease_until: session.lease_until,
  };
}

function acquireAuthorityUsableAt(liveness, now) {
  return liveness
    && ['active', 'idle'].includes(liveness.status)
    && Date.parse(liveness.lease_until) > now;
}

function sessionBinding(session) {
  return {
    role: session.role,
    thread_id: session.thread_id,
    host_id: session.host_id,
    attempt: session.attempt,
    launch_id: session.launch_id,
  };
}

function assertNoHardHold(state) {
  const hardHolds = state.holds.filter((hold) => hold.hard || HARD_HOLDS.includes(hold.kind));
  assertControl(hardHolds.length === 0, 'TASK_HARD_HELD', `task 存在 hard hold: ${hardHolds.map((hold) => hold.kind).join(', ')}`);
}

function assertRuntimeRotationLeaseMaintenanceHold(state, session, lease) {
  const phaseByRole = {
    DEV: 'DEV_ACTIVE',
    REVIEW: 'REVIEW_ACTIVE',
    RECEIPT: 'RECEIPT_ACTIVE',
  };
  assertControl(
    state.holds.length === 1
      && state.holds[0].hard === true
      && state.holds[0].kind === 'ENV_IDENTITY_INCIDENT'
      && session
      && phaseByRole[session.role] === state.phase
      && ['active', 'idle'].includes(session.status)
      && session.role === lease.owner.role
      && session.thread_id === lease.owner.thread_id
      && session.host_id === lease.owner.host_id
      && session.launch_id,
    'TASK_HARD_HELD',
    'hard hold 下只允许同一 active worker 保存 runtime-rotation predecessor/successor 的既有 lease',
  );
}

function runtimeRotationExpiredRenewalBoundary(
  state,
  session,
  resources,
  lease,
  now,
) {
  assertRuntimeRotationLeaseMaintenanceHold(state, session, lease);
  if (Date.parse(lease.expires_at) > now) return null;
  assertControl(
    lease.status === ACTIVE
      && acquireAuthorityUsableAt(authorityLiveness(session), now),
    lease.status === ACTIVE ? 'ACTOR_LEASE_EXPIRED' : 'LEASE_NOT_ACTIVE',
    lease.status === ACTIVE
      ? `runtime-rotation worker lease 已于 ${session.lease_until} 过期`
      : `lease 已是 ${lease.status}`,
  );
  const currentFencingToken =
    assertRuntimeRotationLeaseCurrent(resources, lease, now);
  return {
    schema_version: 1,
    goal_id: lease.owner.goal_id,
    task_id: lease.owner.task_id,
    state_revision: state.state_revision,
    phase: state.phase,
    hold_sha256: hashObject(state.holds[0]),
    session: {
      ...sessionBinding(session),
      capability_file: session.capability_file,
      capability_sha256: session.capability_sha256,
    },
    lease: {
      lease_id: lease.lease_id,
      resource: lease.resource,
      access: lease.access,
      owner: { ...lease.owner },
      owner_capability_file: lease.owner_capability_file,
      owner_capability_sha256: lease.owner_capability_sha256,
      revision: lease.revision,
      fencing_token: lease.fencing_token,
      status: lease.status,
      updated_at: lease.updated_at,
      expires_at: lease.expires_at,
    },
    resource_head: {
      event_count: resources.event_count,
      fencing_token: currentFencingToken,
    },
  };
}

function assertRuntimeRotationLeaseCurrent(resources, lease, now) {
  const currentFencingToken = resources.fencing_tokens[lease.resource] || 0;
  const competingLease = Object.values(resources.leases).find(
    (candidate) => (
      candidate.lease_id !== lease.lease_id
        && candidate.resource === lease.resource
        && candidate.status === ACTIVE
        && Date.parse(candidate.expires_at) > now
    ),
  );
  assertControl(
    currentFencingToken === lease.fencing_token && !competingLease,
    'RESOURCE_EXPIRY_RECOVERY_FENCED',
    `resource ${lease.resource} 已产生 newer fencing/owner，禁止复活旧 lease`,
  );
  return currentFencingToken;
}

function assertOwnerCapabilityDisclosureBoundary(
  state,
  resources,
  lease,
  now,
) {
  const hardHolds = state.holds.filter(
    (hold) => hold.hard || HARD_HOLDS.includes(hold.kind),
  );
  if (hardHolds.length === 0) return null;

  const session = state.sessions[lease.owner.role];
  assertRuntimeRotationLeaseMaintenanceHold(state, session, lease);
  assertControl(
    lease.status === ACTIVE,
    'LEASE_NOT_ACTIVE',
    `lease 已是 ${lease.status}`,
  );
  assertControl(
    acquireAuthorityUsableAt(authorityLiveness(session), now),
    ['active', 'idle'].includes(session.status)
      ? 'ACTOR_LEASE_EXPIRED'
      : 'ACTOR_UNUSABLE',
    ['active', 'idle'].includes(session.status)
      ? `runtime-rotation worker lease 已于 ${session.lease_until} 过期`
      : `runtime-rotation worker status=${session.status}`,
  );
  assertRuntimeRotationLeaseCurrent(resources, lease, now);

  const policy = resourceRenewalPolicy(lease);
  const remainingMilliseconds = Date.parse(lease.expires_at) - now;
  if (remainingMilliseconds > 0) {
    assertControl(
      remainingMilliseconds <= policy.leadMilliseconds,
      'RESOURCE_RENEW_NOT_DUE',
      `lease ${lease.lease_id} 尚未进入续租窗口；expires_at=${lease.expires_at}`,
    );
    return {
      expiry_state: 'RENEWAL_WINDOW',
      policy,
      expired_boundary: null,
    };
  }

  return {
    expiry_state: 'EXPIRED_PRESERVATION',
    policy,
    expired_boundary: runtimeRotationExpiredRenewalBoundary(
      state,
      session,
      resources,
      lease,
      now,
    ),
  };
}

function assertRuntimeRotationExpiredRenewalStillAuthorized(
  root,
  options,
  resources,
  lease,
  expectedBoundary,
  now,
) {
  assertControl(
    lease,
    'LEASE_NOT_FOUND',
    `找不到 lease: ${options.leaseId}`,
  );
  const loaded = loadGoalStateUnlocked(
    root,
    lease.owner.goal_id,
    {
      repairHeads: false,
      repairBootstrapConsumption: false,
    },
  );
  const state = loaded.snapshot.tasks[lease.owner.task_id];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${lease.owner.task_id}`);
  const session = authorizeResourceSession(
    loaded,
    state,
    options.actorCapabilityFile,
    {
      role: lease.owner.role,
      threadId: lease.owner.thread_id,
    },
  );
  assertControl(
    session.host_id === lease.owner.host_id,
    'CAPABILITY_INVALID',
    'capability host 不匹配',
  );
  const currentBoundary = runtimeRotationExpiredRenewalBoundary(
    state,
    session,
    resources,
    lease,
    now,
  );
  assertControl(
    currentBoundary
      && hashObject(currentBoundary) === hashObject(expectedBoundary),
    'RESOURCE_EXPIRY_RECOVERY_BOUNDARY_CHANGED',
    '过期 lease 的 ENV identity recovery 边界已变化；禁止续租',
  );
}

function assertResourceOperationalScope(state, role, operation) {
  if (role === 'FOREMAN') return 'FULL';
  return assertOperationalScope(state, role, operation);
}

function assertNoPendingTaskMutation(root, goalId, taskId, options = {}) {
  const {
    assertNoPendingResourceOperations,
    assertNoPendingTaskOperations,
  } = require('./pending-operations');
  assertNoPendingTaskOperations(root, goalId, taskId, options);
  assertNoPendingResourceOperations(root, options);
}

function actorContext(cwd, goalId, taskId, actorCapabilityFile, expected = {}, options = {}) {
  const loaded = loadGoalStateReadOnly(cwd, goalId);
  const { assertFrozenInputs } = require('./goal');
  assertFrozenInputs(cwd, loaded, taskId);
  const state = loaded.snapshot.tasks[taskId];
  assertControl(state, 'UNKNOWN_TASK', `Goal ${goalId} 没有 task ${taskId}`);
  assertControl(
    state.phase !== 'ARCHIVED',
    'TASK_TERMINAL',
    `task ${taskId} 已 ARCHIVED，禁止继续修改或使用 resource ledger`,
  );
  const session = authorizeResourceSession(loaded, state, actorCapabilityFile, {
    role: expected.role || null,
    threadId: expected.threadId || null,
    allowTerminal: options.allowTerminal === true,
  });
  if (expected.hostId) assertControl(session.host_id === expected.hostId, 'CAPABILITY_INVALID', 'capability host 不匹配');
  if (options.forbidHardHold) assertNoHardHold(state);
  return {
    actor: actorIdentity(session, goalId, taskId),
    authorized_session: {
      role: session.role,
      thread_id: session.thread_id,
      host_id: session.host_id,
      attempt: session.attempt,
      status: session.status,
      lease_until: session.lease_until,
      capability_file: session.capability_file,
      capability_sha256: session.capability_sha256,
      goal_wide: session.role === 'FOREMAN',
    },
    control_epoch: loaded.control.epoch,
    control_event_count: loaded.control.eventCount,
    control_event_sha256: loaded.control.lastEventHash,
    event_count: state.state_revision,
    last_event_sha256: loaded.lastEventHashes[taskId] || null,
    manifest_task: loaded.manifest.tasks.find((task) => task.id === taskId),
    mode: loaded.manifest.mode,
    state,
  };
}

function assertActorContextFresh(root, context, options = {}) {
  const head = readJsonIfExists(
    path.join(root, 'goals', context.actor.goal_id, 'event-heads', `${context.actor.task_id}.json`),
    null
  );
  assertControl(head && head.event_count === context.event_count, 'ACTOR_STATE_CHANGED', 'actor task state 在资源动作前已变化，请重试');
  assertControl(head.last_event_sha256 === context.last_event_sha256, 'ACTOR_STATE_CHANGED', 'actor task event head 在资源动作前已变化，请重试');
  const controlHead = readJsonIfExists(path.join(root, 'goals', context.actor.goal_id, 'control-head.json'), null);
  assertControl(
    controlHead
      && controlHead.control_epoch === context.control_epoch
      && controlHead.event_count === context.control_event_count
      && controlHead.last_event_sha256 === context.control_event_sha256,
    'ACTOR_STATE_CHANGED',
    'control epoch 在资源动作前已变化，请重试'
  );
  const usableStatuses = options.allowTerminal === true
    ? ['active', 'idle', 'terminal']
    : ['active', 'idle'];
  const authorized = context.authorized_session;
  if (authorized.goal_wide) {
    const loaded = loadGoalStateUnlocked(
      root,
      context.actor.goal_id,
      {
        repairHeads: false,
        repairBootstrapConsumption: false,
      },
    );
    const current = authorizeGoalSession(
      loaded.snapshot,
      authorized.capability_file,
      {
        role: 'FOREMAN',
        threadId: authorized.thread_id,
      },
    );
    assertControl(
      current.host_id === authorized.host_id
        && current.attempt === authorized.attempt
        && current.capability_file === authorized.capability_file
        && hashesEqual(
          current.capability_sha256,
          authorized.capability_sha256,
        ),
      'ACTOR_STATE_CHANGED',
      'Goal FOREMAN authority 在资源动作前已变化',
    );
    return;
  }
  const exact = [
    context.state.sessions[authorized.role],
    ...((context.state.session_history && context.state.session_history[authorized.role]) || []),
  ].find((candidate) => (
    candidate
      && candidate.role === authorized.role
      && candidate.thread_id === authorized.thread_id
      && candidate.host_id === authorized.host_id
      && candidate.attempt === authorized.attempt
      && candidate.capability_file === authorized.capability_file
      && hashesEqual(candidate.capability_sha256, authorized.capability_sha256)
  ));
  assertControl(exact, 'CAPABILITY_INVALID', 'authorized exact historical actor 已漂移');
  assertControl(usableStatuses.includes(exact.status), 'ACTOR_UNUSABLE', `actor status=${exact.status}`);
  if (!(options.allowTerminal === true && exact.status === 'terminal')) {
    assertControl(Date.parse(exact.lease_until) > currentTimeMilliseconds(), 'ACTOR_LEASE_EXPIRED', `actor lease 已于 ${exact.lease_until} 过期`);
  }
}

function assertOwnerCapability(lease, capabilityFile) {
  const supplied = readCapabilityFile(capabilityFile);
  assertControl(
    supplied.file === lease.owner_capability_file
      && hashesEqual(supplied.sha256, lease.owner_capability_sha256),
    'LEASE_OWNER_MISMATCH',
    'owner capability 不匹配'
  );
}

function historicalResourceSessions(state, actor, goalSnapshot = null) {
  const states = actor.role === 'FOREMAN' && goalSnapshot
    ? Object.values(goalSnapshot.tasks || {})
    : [state];
  return states.flatMap((candidateState) => [
    ...Object.values(candidateState.sessions || {}),
    ...Object.values(candidateState.session_history || {}).flat(),
  ]);
}

function exactHistoricalResourceActor(
  state,
  actor,
  actorCapabilityFile,
  goalSnapshot = null,
) {
  const supplied = readCapabilityFile(actorCapabilityFile);
  const sessions = historicalResourceSessions(state, actor, goalSnapshot);
  const session = sessions.find((candidate) => (
    candidate
      && candidate.role === actor.role
      && candidate.thread_id === actor.thread_id
      && candidate.host_id === actor.host_id
      && candidate.capability_file === supplied.file
      && hashesEqual(candidate.capability_sha256, supplied.sha256)
  ));
  assertControl(
    session,
    'CAPABILITY_INVALID',
    'capability 不属于 resource operation 的原始历史 actor',
  );
  return session;
}

function exactHistoricalResourceAuthority(
  state,
  authority,
  actorCapabilityFile,
  goalSnapshot = null,
) {
  const supplied = readCapabilityFile(actorCapabilityFile);
  const sessions = historicalResourceSessions(state, authority, goalSnapshot);
  const session = sessions.find((candidate) => (
    candidate
      && candidate.role === authority.role
      && candidate.thread_id === authority.thread_id
      && candidate.host_id === authority.host_id
      && candidate.attempt === authority.attempt
      && candidate.capability_file === authority.capability_file
      && candidate.capability_file === supplied.file
      && hashesEqual(candidate.capability_sha256, authority.capability_sha256)
      && hashesEqual(candidate.capability_sha256, supplied.sha256)
  ));
  assertControl(
    session,
    'CAPABILITY_INVALID',
    `capability 不属于原始历史 ${authority.role} authority`,
  );
  return session;
}

function assertHistoricalAuthorityUsableAt(
  session,
  transactionStartedAt,
  options = {},
) {
  const startedAt = Date.parse(transactionStartedAt);
  assertControl(
    Number.isFinite(startedAt),
    'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
    'pristine resource recovery 缺 transaction_started_at',
  );
  const usableStatuses = options.allowTerminal === true
    ? ['active', 'idle', 'terminal']
    : ['active', 'idle'];
  assertControl(
    usableStatuses.includes(session.status),
    'ACTOR_UNUSABLE',
    `actor status=${session.status}`,
  );
  if (session.status !== 'terminal') {
    assertControl(
      Date.parse(session.lease_until) > startedAt,
      'ACTOR_LEASE_EXPIRED',
      `actor lease 在 transaction_started_at=${transactionStartedAt} 前已过期`,
    );
  }
  return session;
}

function assertExactPristineBoundary(
  transaction,
  expectedTransaction,
) {
  assertControl(
    transaction
      && isOddTransactionRetry(transaction.mode)
      && transaction.active_transaction
      && transaction.active_transaction.key_sha256
        === expectedTransaction.key_sha256,
    'STORE_TRANSACTION_MISMATCH',
    'pristine resource recovery transaction key 不匹配',
  );
  assertControl(
    typeof transaction.pre_write_vector_sha256 === 'string',
    'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
    'pristine resource recovery 缺 v3 pre-write vector',
  );
  assertControl(
    transaction.pristine_payload_vector_sha256
      === transaction.pre_write_vector_sha256,
    'STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH',
    'pristine resource recovery payload 已漂移',
  );
}

function assertPristinePayloadUnchanged(transaction) {
  assertControl(
    transaction
      && isOddTransactionRetry(transaction.mode)
      && typeof transaction.pre_write_vector_sha256 === 'string',
    'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
    'pristine resource recovery 缺 v3 pre-write vector',
  );
  assertControl(
    transaction.pristine_payload_vector_sha256
      === transaction.pre_write_vector_sha256,
    'STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH',
    'pristine resource recovery payload 已漂移',
  );
}

function pristineAbortRetry(operation) {
  return new ControlError(
    PRISTINE_ABORT_RETRY,
    `${operation} 的旧 pristine transaction 已安全关闭；必须按当前授权重新执行`,
  );
}

function runWithOneFreshRetry(operation) {
  try {
    return operation(false);
  } catch (error) {
    if (!error || error.code !== PRISTINE_ABORT_RETRY) throw error;
    return operation(true);
  }
}

function assertOwnerCapabilityRequest(lease, capabilityFile, allowDeleted) {
  assertControl(
    typeof capabilityFile === 'string'
      && path.resolve(capabilityFile) === lease.owner_capability_file,
    'LEASE_OWNER_MISMATCH',
    'owner capability path 不匹配',
  );
  if (fs.existsSync(lease.owner_capability_file)) {
    assertOwnerCapability(lease, capabilityFile);
    return;
  }
  assertControl(
    allowDeleted && TERMINAL.has(lease.status),
    'LEASE_OWNER_MISMATCH',
    'owner capability 已缺失且 lease 尚未 durable terminal',
  );
}

function validateResourceMutationRetry(
  state,
  event,
  options,
  type,
  now,
) {
  const lease = state.leases[event.lease_id];
  const expectedRevision = optionalInteger(
    options.expectedRevision,
    'expected revision',
  );
  assertControl(expectedRevision !== null, 'ARG_REQUIRED', '缺少 expected revision');
  assertControl(
    event.type === type
      && event.lease_id === options.leaseId
      && event.from_revision === expectedRevision,
    'RESOURCE_EVENT_ID_CONFLICT',
    `resource event id ${options.eventId} 已绑定不同 ${type} request`,
  );
  assertControl(
    lease
      && hashObject(lease.owner) === hashObject(event.actor)
      && lease.revision >= event.to_revision,
    'CORRUPT_STORE',
    `resource event ${options.eventId} lease lineage 漂移`,
  );
  if (type === 'LEASE_RENEWED') {
    const ttlMilliseconds = validateTtl(options.ttlMilliseconds);
    assertControl(
      Date.parse(event.expires_at) - Date.parse(event.accepted_at)
        === ttlMilliseconds,
      'RESOURCE_EVENT_ID_CONFLICT',
      `resource event id ${options.eventId} 已绑定不同 renew TTL`,
    );
  }
  assertOwnerCapabilityRequest(lease, options.ownerCapabilityFile, true);
  return {
    ...publicLease(lease, now),
    idempotent: true,
    operation_event_id: event.event_id,
  };
}

function maybeFaultAfterResourceCommit(type) {
  const fault = process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_COMMIT;
  if (fault !== '1' && fault !== type) return;
  assertIsolatedTestMode();
  throw new ControlError(
    'TEST_FAULT_AFTER_RESOURCE_COMMIT',
    `injected response loss after durable ${type}`,
  );
}

function validateTtl(value) {
  const ttlMilliseconds = optionalInteger(value, 'ttl-ms', 3600000);
  assertControl(
    ttlMilliseconds > 0 && ttlMilliseconds <= MAX_RESOURCE_TTL_MS,
    'INVALID_TTL',
    `ttl-ms 必须在 1-${MAX_RESOURCE_TTL_MS}`
  );
  return ttlMilliseconds;
}

function resourceRenewalPolicy(lease) {
  const updatedAt = Date.parse(lease.updated_at);
  const expiresAt = Date.parse(lease.expires_at);
  const ttlMilliseconds = expiresAt - updatedAt;
  assertControl(
    Number.isSafeInteger(ttlMilliseconds)
      && ttlMilliseconds > 0
      && ttlMilliseconds <= MAX_RESOURCE_TTL_MS,
    'CORRUPT_STORE',
    `resource lease ${lease.lease_id} renewal term 非法`,
  );
  return {
    ttlMilliseconds,
    leadMilliseconds: Math.min(
      RESOURCE_RENEWAL_MAX_LEAD_MS,
      Math.max(1, Math.floor(
        ttlMilliseconds / RESOURCE_RENEWAL_TERM_DIVISOR,
      )),
    ),
  };
}

function resourceRenewalEventId(lease) {
  const stableDigest = sha256([
    lease.owner.goal_id,
    lease.owner.task_id,
    lease.lease_id,
    String(lease.revision),
  ].join('\0')).slice(0, 32);
  return `resource-renew-${stableDigest}-r${lease.revision}`;
}

function assertResourceRenewalRequest(
  lease,
  options,
  now,
  allowExpired = false,
) {
  const policy = resourceRenewalPolicy(lease);
  const requestedTtl = validateTtl(options.ttlMilliseconds);
  const remainingMilliseconds = Date.parse(lease.expires_at) - now;
  assertControl(
    (
      remainingMilliseconds > 0
        && remainingMilliseconds <= policy.leadMilliseconds
    )
      || (allowExpired && remainingMilliseconds <= 0),
    'RESOURCE_RENEW_NOT_DUE',
    `lease ${lease.lease_id} 尚未进入续租窗口；expires_at=${lease.expires_at}`,
  );
  assertControl(
    options.eventId === resourceRenewalEventId(lease),
    'RESOURCE_RENEW_EVENT_ID_MISMATCH',
    `renew event_id 必须使用 maintenance action 为 lease ${lease.lease_id} revision ${lease.revision} 生成的稳定值`,
  );
  assertControl(
    requestedTtl === policy.ttlMilliseconds,
    'RESOURCE_RENEW_TTL_MISMATCH',
    `renew ttl-ms 必须保持上一租期 ${policy.ttlMilliseconds}`,
  );
  return policy;
}

function declaredRequirement(task, resource, access, role) {
  const match = task.resource_requirements.find((requirement) => {
    const prefix = RESOURCE_KIND_PREFIX[requirement.kind];
    const declaredBase = `${prefix}:${requirement.id}`;
    return resource === declaredBase;
  });
  assertControl(match, 'RESOURCE_NOT_DECLARED', `resource ${resource} 未在 manifest task ${task.id} 声明`);
  assertControl(
    requirementAppliesToRole(match, role),
    'RESOURCE_ROLE_MISMATCH',
    `resource ${resource} 未声明给 ${role} 使用`,
  );
  assertControl(match.access === access, 'RESOURCE_ACCESS_MISMATCH', `resource ${resource} 必须使用 ${match.access}`);
  return match;
}

function lookupLease(cwd, leaseId) {
  const root = controlRoot(cwd);
  return withStableRead(root, () => {
    const { state } = rebuildUnlocked(root, { repairHeads: false });
    const lease = state.leases[leaseId];
    assertControl(lease, 'LEASE_NOT_FOUND', `找不到 lease: ${leaseId}`);
    return { ...lease, owner: { ...lease.owner } };
  });
}

function assertLeaseMutable(lease, options, now, allowExpired) {
  assertControl(lease, 'LEASE_NOT_FOUND', `找不到 lease: ${options.leaseId}`);
  assertControl(lease.status === ACTIVE, 'LEASE_NOT_ACTIVE', `lease 已是 ${lease.status}`);
  const expectedRevision = optionalInteger(options.expectedRevision, 'expected revision');
  assertControl(expectedRevision !== null, 'ARG_REQUIRED', '缺少 expected revision');
  assertControl(expectedRevision === lease.revision, 'STALE_LEASE_REVISION', `expected lease revision ${expectedRevision}，当前为 ${lease.revision}`);
  if (!allowExpired) assertControl(Date.parse(lease.expires_at) > now, 'LEASE_EXPIRED', `lease 已于 ${lease.expires_at} 过期，需显式 reap`);
}

function acquireRequest(owner, options) {
  const resource = safeId(options.resource, 'resource');
  assertControl(
    RESOURCE_KEY_RE.test(resource),
    'INVALID_RESOURCE_KEY',
    'resource 必须是 kind:id[:sub-id...] 形式，kind 使用小写 kebab-case',
  );
  const access = options.access || 'EXCLUSIVE';
  assertControl(
    ['EXCLUSIVE', 'SHARED_READ'].includes(access),
    'INVALID_RESOURCE_ACCESS',
    'access 必须是 EXCLUSIVE 或 SHARED_READ',
  );
  return {
    schema_version: 1,
    event_id: safeId(options.eventId, 'resource acquire event'),
    owner,
    resource,
    access,
    ttl_ms: validateTtl(options.ttlMilliseconds),
  };
}

function acquireTransactionKey(request, actorAuthority) {
  assertControl(
    actorAuthority,
    'TRANSACTION_KEY_INVALID',
    'resource acquire transaction 缺 actor authority anchor',
  );
  return canonicalTransactionKey(
    'RESOURCE_ACQUIRE',
    {
      goal_id: request.owner.goal_id,
      task_id: request.owner.task_id,
    },
    request.event_id,
    hashObject({
      ...request,
      actor_authority: actorAuthority,
    }),
  );
}

function deterministicAcquireLeaseId(request, actorAuthority) {
  const transaction = acquireTransactionKey(request, actorAuthority);
  const identitySha256 = hashObject({
    schema_version: 1,
    kind: 'RESOURCE_ACQUIRE_LEASE_ID',
    transaction_key_sha256: transaction.key_sha256,
    event_id: request.event_id,
    actor_authority_sha256: hashObject(actorAuthority),
  });
  return `lease-${identitySha256.slice('sha256:'.length, 31)}`;
}

function resolveAcquireTransactionAuthority(
  root,
  request,
  actorCapabilityFile,
) {
  const paths = resourcePaths(root);
  const existingEvent = resourceEventById(paths, request.event_id);
  const intentEntry = readAcquireIntent(paths, request);
  if (existingEvent || (intentEntry && intentEntry.intent !== null)) {
    assertControl(
      intentEntry
        && intentEntry.intent !== null
        && hashObject(intentEntry.intent.request) === hashObject(request),
      'RESOURCE_EVENT_ID_CONFLICT',
      `resource acquire ${request.event_id} 缺 exact intent authority`,
    );
    const loaded = loadGoalStateUnlocked(
      root,
      intentEntry.intent.actor.goal_id,
      {
        repairHeads: false,
        allowLaggingHeads: true,
        repairBootstrapConsumption: false,
        allowIncompleteRecoveryRead: true,
        allowIncompleteGoalOperationRead: true,
      },
    );
    const state = loaded.snapshot.tasks[intentEntry.intent.actor.task_id];
    assertControl(
      state,
      'UNKNOWN_TASK',
      `未知 task ${intentEntry.intent.actor.task_id}`,
    );
    exactHistoricalResourceAuthority(
      state,
      intentEntry.intent.actor_authority,
      actorCapabilityFile,
      loaded.snapshot,
    );
    return intentEntry.intent.actor_authority;
  }
  const owner = request.owner;
  const loaded = loadGoalStateUnlocked(
    root,
    owner.goal_id,
    {
      repairHeads: false,
      repairBootstrapConsumption: false,
    },
  );
  const state = loaded.snapshot.tasks[owner.task_id];
  assertControl(
    state,
    'UNKNOWN_TASK',
    `Goal ${owner.goal_id} 没有 task ${owner.task_id}`,
  );
  return authorityIdentity(exactHistoricalResourceActor(
    state,
    owner,
    actorCapabilityFile,
    loaded.snapshot,
  ));
}

function resourceMutationRequest(
  type,
  options,
  actor,
  actorAuthority,
) {
  const expectedRevision = optionalInteger(
    options.expectedRevision,
    'expected revision',
  );
  assertControl(
    expectedRevision !== null,
    'ARG_REQUIRED',
    '缺少 expected revision',
  );
  const request = {
    schema_version: 1,
    type,
    event_id: safeId(options.eventId, `resource ${type} event`),
    lease_id: safeId(options.leaseId, 'lease'),
    expected_revision: expectedRevision,
    actor,
    actor_authority: actorAuthority,
  };
  if (type === 'LEASE_RENEWED') {
    request.ttl_ms = validateTtl(options.ttlMilliseconds);
  }
  return request;
}

function resourceMutationTransactionKey(type, options, boundary) {
  assertControl(
    boundary && boundary.actorAuthority,
    'TRANSACTION_KEY_INVALID',
    `resource ${type} transaction boundary/authority 缺失`,
  );
  const actor = boundary.existingEvent
    ? boundary.existingEvent.actor
    : boundary.actor;
  const request = resourceMutationRequest(
    type,
    options,
    actor,
    boundary.actorAuthority,
  );
  const kind = type === 'LEASE_RENEWED'
    ? 'RESOURCE_RENEW'
    : 'RESOURCE_RELEASE';
  return canonicalTransactionKey(
    kind,
    {
      goal_id: actor.goal_id,
      task_id: actor.task_id,
    },
    request.event_id,
    hashObject(request),
  );
}

function resolveResourceMutationTransactionBoundary(
  root,
  type,
  options,
) {
  const paths = resourcePaths(root);
  const existingEvent = resourceEventById(paths, options.eventId);
  if (existingEvent) {
    assertControl(
      existingEvent.type === type
        && existingEvent.lease_id === options.leaseId,
      'RESOURCE_EVENT_ID_CONFLICT',
      `resource event id ${options.eventId} 已绑定不同 operation`,
    );
    const loaded = loadGoalStateUnlocked(
      root,
      existingEvent.actor.goal_id,
      {
        repairHeads: false,
        allowLaggingHeads: true,
        repairBootstrapConsumption: false,
        allowIncompleteRecoveryRead: true,
        allowIncompleteGoalOperationRead: true,
      },
    );
    const state = loaded.snapshot.tasks[existingEvent.actor.task_id];
    assertControl(
      state,
      'UNKNOWN_TASK',
      `未知 task ${existingEvent.actor.task_id}`,
    );
    const historical = exactHistoricalResourceActor(
      state,
      existingEvent.actor,
      options.actorCapabilityFile,
      loaded.snapshot,
    );
    return {
      existingEvent,
      actorAuthority: authorityIdentity(historical),
    };
  }
  const { state: resources } = rebuildUnlocked(root, {
    repairHeads: false,
    allowLaggingHeads: true,
  });
  const lease = resources.leases[options.leaseId];
  assertControl(
    lease,
    'LEASE_NOT_FOUND',
    `找不到 lease: ${options.leaseId}`,
  );
  const loaded = loadGoalStateUnlocked(
    root,
    lease.owner.goal_id,
    {
      repairHeads: false,
      repairBootstrapConsumption: false,
    },
  );
  const state = loaded.snapshot.tasks[lease.owner.task_id];
  assertControl(
    state,
    'UNKNOWN_TASK',
    `未知 task ${lease.owner.task_id}`,
  );
  const historical = exactHistoricalResourceActor(
    state,
    lease.owner,
    options.actorCapabilityFile,
    loaded.snapshot,
  );
  return {
    actor: actorIdentity(
      historical,
      lease.owner.goal_id,
      lease.owner.task_id,
    ),
    actorAuthority: authorityIdentity(historical),
  };
}

function assertTransactionAuthorityStable(expected, actual, label) {
  assertControl(
    expected
      && actual
      && hashObject(expected) === hashObject(actual),
    'STORE_TRANSACTION_PREFLIGHT_MUTATED',
    `${label} transaction authority 在 key resolution 与 authorization 间漂移`,
  );
}

function acquireIntentDirectory(paths, eventId) {
  return path.join(paths.dir, 'acquire-intents', safeId(eventId, 'acquire event'));
}

function acquireIntentStagingDirectory(paths, eventId) {
  return path.join(
    paths.dir,
    'acquire-intents',
    `.init-${safeId(eventId, 'acquire event')}`,
  );
}

function regexEscape(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function atomicWriteTemporaryPattern(fileName) {
  return new RegExp(
    `^\\.${regexEscape(fileName)}\\.[1-9][0-9]*\\.tmp-[0-9a-f]{24}$`,
  );
}

function ownerCapabilityPattern(leaseId) {
  return new RegExp(
    `^${regexEscape(leaseId)}-owner-[0-9a-f]{24}\\.cap$`,
  );
}

function ownerCapabilityAtomicTemporaryPattern(leaseId) {
  return new RegExp(
    `^\\.${regexEscape(leaseId)}-owner-[0-9a-f]{24}\\.cap\\.[1-9][0-9]*\\.tmp-[0-9a-f]{24}$`,
  );
}

function assertOwnedPrivateAtomicTemporary(file, label) {
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
    `${label} 不是当前 owner 的 0600 普通文件`,
  );
}

function sealAcquireRecord(value, sealKey) {
  return {
    ...value,
    [sealKey]: hashObject(value),
  };
}

function readAcquireRecord(file, sealKey, label) {
  const stat = fs.lstatSync(file);
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && (
        typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
      ),
    'CORRUPT_STORE',
    `${label} 非本进程用户普通文件`,
  );
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

function readAcquireIntent(paths, request) {
  const finalDirectory = acquireIntentDirectory(paths, request.event_id);
  const staging = acquireIntentStagingDirectory(paths, request.event_id);
  let directory = finalDirectory;
  if (!fs.existsSync(finalDirectory) && fs.existsSync(staging)) {
    const stagingStat = fs.lstatSync(staging);
    assertControl(
      stagingStat.isDirectory()
        && !stagingStat.isSymbolicLink()
        && (typeof process.getuid !== 'function'
          || stagingStat.uid === process.getuid()),
      'CORRUPT_STORE',
      `resource acquire staging ${path.basename(staging)} 非本进程用户普通目录`,
    );
    const entries = fs.readdirSync(staging).sort();
    const intentAtomicPattern = atomicWriteTemporaryPattern('intent.json');
    const atomicTemporaries = entries.filter((entry) => (
      intentAtomicPattern.test(entry)
    ));
    assertControl(
      entries.length <= 1
        && entries.every((entry) => (
          entry === 'intent.json' || atomicTemporaries.includes(entry)
        )),
      'CORRUPT_STORE',
      `resource acquire staging ${path.basename(staging)} 含未知文件: ${entries.join(', ')}`,
    );
    assertControl(
      !(entries.includes('intent.json') && atomicTemporaries.length > 0),
      'CORRUPT_STORE',
      `resource acquire staging ${path.basename(staging)} canonical intent/temp 并存`,
    );
    for (const name of atomicTemporaries) {
      assertOwnedPrivateAtomicTemporary(
        path.join(staging, name),
        `resource acquire intent atomic temp ${name}`,
      );
    }
    if (!entries.includes('intent.json')) {
      return {
        directory: staging,
        file: path.join(staging, 'intent.json'),
        finalDirectory,
        staged: true,
        emptyStaging: entries.length === 0,
        atomicTemporaries,
        intent: null,
      };
    }
    directory = staging;
  }
  assertControl(
    !(fs.existsSync(finalDirectory) && fs.existsSync(staging)),
    'CORRUPT_STORE',
    `resource acquire intent ${request.event_id} final/staging 并存`,
  );
  if (!fs.existsSync(directory)) return null;
  const directoryStat = fs.lstatSync(directory);
  assertControl(
    directoryStat.isDirectory()
      && !directoryStat.isSymbolicLink()
      && (
        typeof process.getuid !== 'function'
          || directoryStat.uid === process.getuid()
      ),
    'CORRUPT_STORE',
    `resource acquire intent ${request.event_id} 非本进程用户普通目录`,
  );
  const file = path.join(directory, 'intent.json');
  assertControl(
    fs.existsSync(file),
    'CORRUPT_STORE',
    `resource acquire intent ${request.event_id} 缺 intent.json`,
  );
  const intent = readAcquireRecord(
    file,
    'intent_sha256',
    `resource acquire intent ${request.event_id}`,
  );
  assertControl(
    intent.schema_version === 1
      && intent.type === 'LEASE_ACQUIRE_INTENT'
      && hashObject(intent.request) === hashObject(request)
      && intent.actor
      && intent.actor_authority
      && intent.actor_authority.role === intent.actor.role
      && intent.actor_authority.thread_id === intent.actor.thread_id
      && intent.actor_authority.host_id === intent.actor.host_id
      && intent.lease_template
      && intent.resource_head,
    'RESOURCE_EVENT_ID_CONFLICT',
    `resource event id ${request.event_id} 已绑定不同 acquire intent`,
  );
  return {
    directory,
    file,
    finalDirectory,
    staged: directory === staging,
    emptyStaging: false,
    atomicTemporaries: [],
    intent,
  };
}

function assertExactLeaseAcquisitionAuthority(paths, lease, session) {
  const acquisitions = eventFiles(paths)
    .map((file) => readResourceJson(
      file,
      `resource event ${path.basename(file)}`,
    ))
    .filter((event) => (
      event.type === 'LEASE_ACQUIRED'
        && event.lease
        && event.lease.lease_id === lease.lease_id
    ));
  assertControl(
    acquisitions.length === 1,
    'CORRUPT_STORE',
    `lease ${lease.lease_id} 缺唯一 acquisition authority witness`,
  );
  const acquisition = acquisitions[0];
  assertControl(
    acquisition.lease.resource === lease.resource
      && acquisition.lease.access === lease.access
      && acquisition.lease.fencing_token === lease.fencing_token
      && hashObject(acquisition.lease.owner) === hashObject(lease.owner)
      && acquisition.lease.owner_capability_file
        === lease.owner_capability_file
      && hashesEqual(
        acquisition.lease.owner_capability_sha256,
        lease.owner_capability_sha256,
      ),
    'CORRUPT_STORE',
    `lease ${lease.lease_id} acquisition witness 与 current lineage 不一致`,
  );
  const request = {
    schema_version: 1,
    event_id: acquisition.event_id,
    owner: acquisition.actor,
    resource: acquisition.lease.resource,
    access: acquisition.lease.access,
    ttl_ms: Date.parse(acquisition.lease.expires_at)
      - Date.parse(acquisition.accepted_at),
  };
  const intentEntry = readAcquireIntent(paths, request);
  assertControl(
    intentEntry
      && intentEntry.intent
      && intentEntry.intent.lease_template.lease_id === lease.lease_id
      && hashObject(intentEntry.intent.actor) === hashObject(acquisition.actor),
    'CORRUPT_STORE',
    `lease ${lease.lease_id} 缺 exact acquisition authority intent`,
  );
  assertControl(
    hashObject(intentEntry.intent.actor_authority)
      === hashObject(authorityIdentity(session)),
    'LEASE_OWNER_MISMATCH',
    'hard hold 下 owner capability 只能由 acquire 时的 exact session attempt 恢复',
  );
}

function promoteAcquireIntent(intentEntry) {
  if (!intentEntry.staged) return intentEntry;
  assertControl(
    fs.existsSync(intentEntry.directory)
      && !fs.existsSync(intentEntry.finalDirectory),
    'CORRUPT_STORE',
    `resource acquire staging ${intentEntry.intent.request.event_id} 无法 promote`,
  );
  fs.renameSync(intentEntry.directory, intentEntry.finalDirectory);
  fsyncDirectory(path.dirname(intentEntry.finalDirectory));
  return {
    ...intentEntry,
    directory: intentEntry.finalDirectory,
    file: path.join(intentEntry.finalDirectory, 'intent.json'),
    staged: false,
  };
}

function cleanupEmptyAcquireStaging(intentEntry) {
  assertControl(
    intentEntry
      && intentEntry.staged === true
      && intentEntry.intent === null
      && Array.isArray(intentEntry.atomicTemporaries),
    'CORRUPT_STORE',
    'resource acquire unpublished staging recovery context 非法',
  );
  const stat = fs.lstatSync(intentEntry.directory);
  assertControl(
    stat.isDirectory()
      && !stat.isSymbolicLink()
      && (
        typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
      ),
    'CORRUPT_STORE',
    `resource acquire unpublished staging ${path.basename(intentEntry.directory)} 已漂移`,
  );
  const currentEntries = fs.readdirSync(intentEntry.directory).sort();
  assertControl(
    hashObject(currentEntries) === hashObject(intentEntry.atomicTemporaries),
    'CORRUPT_STORE',
    `resource acquire unpublished staging ${path.basename(intentEntry.directory)} 内容已漂移`,
  );
  for (const name of currentEntries) {
    const file = path.join(intentEntry.directory, name);
    assertControl(
      atomicWriteTemporaryPattern('intent.json').test(name),
      'CORRUPT_STORE',
      `resource acquire unpublished staging ${name} 非协议 atomic temp`,
    );
    assertOwnedPrivateAtomicTemporary(
      file,
      `resource acquire intent atomic temp ${name}`,
    );
  }
  for (const name of currentEntries) {
    fs.rmSync(path.join(intentEntry.directory, name), { force: true });
  }
  if (currentEntries.length > 0) fsyncDirectory(intentEntry.directory);
  assertControl(
    fs.readdirSync(intentEntry.directory).length === 0,
    'CORRUPT_STORE',
    `resource acquire unpublished staging ${path.basename(intentEntry.directory)} 清理后非空`,
  );
  fs.rmdirSync(intentEntry.directory);
  fsyncDirectory(path.dirname(intentEntry.directory));
}

function writeAcquireIntent(
  paths,
  request,
  actor,
  actorAuthority,
  state,
  transactionStartedAt,
) {
  const directory = acquireIntentDirectory(paths, request.event_id);
  const parent = path.dirname(directory);
  assertControl(
    !fs.existsSync(directory),
    'RESOURCE_EVENT_ID_CONFLICT',
    `resource acquire intent ${request.event_id} 已存在`,
  );
  assertControl(
    typeof transactionStartedAt === 'string'
      && Number.isFinite(Date.parse(transactionStartedAt)),
    'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
    'resource acquire intent 缺 immutable transaction_started_at',
  );
  const leaseId = deterministicAcquireLeaseId(request, actorAuthority);
  const intent = sealAcquireRecord({
    schema_version: 1,
    type: 'LEASE_ACQUIRE_INTENT',
    request,
    actor,
    actor_authority: actorAuthority,
    lease_template: {
      lease_id: leaseId,
      resource: request.resource,
      access: request.access,
      owner: request.owner,
      revision: 1,
      fencing_token: (state.fencing_tokens[request.resource] || 0) + 1,
      status: ACTIVE,
    },
    resource_head: {
      event_count: state.event_count,
      fencing_token: state.fencing_tokens[request.resource] || 0,
    },
    created_at: transactionStartedAt,
  }, 'intent_sha256');
  const staging = acquireIntentStagingDirectory(paths, request.event_id);
  if (fs.existsSync(staging)) {
    const stat = fs.lstatSync(staging);
    assertControl(
      stat.isDirectory()
        && !stat.isSymbolicLink()
        && fs.readdirSync(staging).length === 0,
      'RESOURCE_EVENT_ID_CONFLICT',
      `resource acquire staging ${request.event_id} 不是 exact empty retry directory`,
    );
  }
  ensureDir(staging);
  if (
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGING_DIRECTORY === '1'
  ) {
    assertIsolatedTestMode();
    throw new ControlError(
      'TEST_FAULT_AFTER_ACQUIRE_STAGING_DIRECTORY',
      'injected failure after acquire staging directory publication',
    );
  }
  atomicWriteJson(path.join(staging, 'intent.json'), intent, {
    fault_namespace: 'RESOURCE_ACQUIRE_INTENT',
  });
  fsyncDirectory(staging);
  if (
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGED_INTENT === '1'
  ) {
    assertIsolatedTestMode();
    throw new ControlError(
      'TEST_FAULT_AFTER_ACQUIRE_STAGED_INTENT',
      'injected failure after sealed acquire staging intent publication',
    );
  }
  fs.renameSync(staging, directory);
  fsyncDirectory(parent);
  const file = path.join(directory, 'intent.json');
  if (process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT === '1') {
    assertIsolatedTestMode();
    throw new ControlError(
      'TEST_FAULT_AFTER_ACQUIRE_INTENT',
      'injected failure after durable acquire intent',
    );
  }
  return { directory, file, intent };
}

function cleanupAcquireAtomicTemporaries(intentEntry) {
  const leaseId = intentEntry.intent.lease_template.lease_id;
  const receiptPattern = atomicWriteTemporaryPattern(
    'capability-receipt.json',
  );
  const capabilityPattern = ownerCapabilityAtomicTemporaryPattern(leaseId);
  const finalizedCapabilityPattern = ownerCapabilityPattern(leaseId);
  const entries = fs.readdirSync(intentEntry.directory).sort();
  const receiptTemporaries = entries.filter((name) => receiptPattern.test(name));
  const capabilityTemporaries = entries.filter((name) => (
    capabilityPattern.test(name)
  ));
  const finalizedCapabilities = entries.filter((name) => (
    finalizedCapabilityPattern.test(name)
  ));
  const known = new Set([
    'intent.json',
    'capability-receipt.json',
    ...receiptTemporaries,
    ...capabilityTemporaries,
    ...finalizedCapabilities,
  ]);
  const unknown = entries.filter((name) => !known.has(name));
  assertControl(
    unknown.length === 0,
    'CORRUPT_STORE',
    `acquire intent ${intentEntry.intent.request.event_id} 含未知 staging 文件: ${unknown.join(', ')}`,
  );
  assertControl(
    receiptTemporaries.length <= 1
      && capabilityTemporaries.length <= 1
      && !(receiptTemporaries.length > 0 && capabilityTemporaries.length > 0),
    'CORRUPT_STORE',
    `acquire intent ${intentEntry.intent.request.event_id} atomic temp lineage 分叉`,
  );
  assertControl(
    !entries.includes('capability-receipt.json')
      || (
        receiptTemporaries.length === 0
          && capabilityTemporaries.length === 0
      ),
    'CORRUPT_STORE',
    `acquire intent ${intentEntry.intent.request.event_id} canonical receipt/temp 并存`,
  );
  assertControl(
    !entries.includes('capability-receipt.json')
      || finalizedCapabilities.length === 1,
    'CORRUPT_STORE',
    `acquire intent ${intentEntry.intent.request.event_id} canonical receipt 必须绑定唯一 finalized capability`,
  );
  assertControl(
    capabilityTemporaries.length === 0 || finalizedCapabilities.length === 0,
    'CORRUPT_STORE',
    `acquire intent ${intentEntry.intent.request.event_id} capability final/temp 并存`,
  );
  assertControl(
    receiptTemporaries.length === 0 || finalizedCapabilities.length === 1,
    'CORRUPT_STORE',
    `acquire intent ${intentEntry.intent.request.event_id} receipt temp 缺唯一 finalized capability`,
  );
  const temporaries = [...receiptTemporaries, ...capabilityTemporaries];
  for (const name of temporaries) {
    assertOwnedPrivateAtomicTemporary(
      path.join(intentEntry.directory, name),
      `acquire atomic temp ${name}`,
    );
  }
  for (const name of temporaries) {
    fs.rmSync(path.join(intentEntry.directory, name), { force: true });
  }
  if (temporaries.length > 0) fsyncDirectory(intentEntry.directory);
}

function acquireOwnerCapability(intentEntry) {
  const leaseId = intentEntry.intent.lease_template.lease_id;
  const expectedPrefix = `${leaseId}-owner-`;
  const finalizedCapabilityPattern = ownerCapabilityPattern(leaseId);
  const receiptFile = path.join(intentEntry.directory, 'capability-receipt.json');
  if (fs.existsSync(receiptFile)) {
    const receipt = readAcquireRecord(
      receiptFile,
      'receipt_sha256',
      `acquire capability receipt ${intentEntry.intent.request.event_id}`,
    );
    assertControl(
      receipt.schema_version === 1
        && receipt.type === 'LEASE_OWNER_CAPABILITY'
        && receipt.event_id === intentEntry.intent.request.event_id
        && receipt.lease_id === intentEntry.intent.lease_template.lease_id,
      'CORRUPT_STORE',
      `acquire capability receipt ${intentEntry.intent.request.event_id} binding 漂移`,
    );
    const finalizedCapabilities = fs.readdirSync(intentEntry.directory)
      .filter((name) => finalizedCapabilityPattern.test(name));
    assertControl(
      finalizedCapabilities.length === 1,
      'CORRUPT_STORE',
      `acquire capability receipt ${receipt.lease_id} 未绑定唯一 finalized capability`,
    );
    const capability = readCapabilityFile(
      receipt.capability_file,
      path.join(intentEntry.directory, finalizedCapabilities[0]),
    );
    assertControl(
      hashesEqual(capability.sha256, receipt.capability_sha256),
      'CORRUPT_STORE',
      `acquire capability ${receipt.lease_id} hash 漂移`,
    );
    return capability;
  }

  const staleCapabilities = fs.readdirSync(intentEntry.directory)
    .filter((name) => name !== 'intent.json')
    .filter((name) => finalizedCapabilityPattern.test(name));
  const unknown = fs.readdirSync(intentEntry.directory)
    .filter((name) => (
      name !== 'intent.json'
        && name !== 'capability-receipt.json'
        && !staleCapabilities.includes(name)
    ));
  assertControl(
    unknown.length === 0,
    'CORRUPT_STORE',
    `acquire intent ${intentEntry.intent.request.event_id} 含未知 staging 文件`,
  );
  for (const name of staleCapabilities) {
    const file = path.join(intentEntry.directory, name);
    const stat = fs.lstatSync(file);
    assertControl(
      stat.isFile() && !stat.isSymbolicLink(),
      'CORRUPT_STORE',
      `acquire staging capability ${name} 类型非法`,
    );
    fs.rmSync(file, { force: true });
  }
  if (staleCapabilities.length > 0) fsyncDirectory(intentEntry.directory);
  const capability = createCapabilityFile(
    intentEntry.directory,
    `${intentEntry.intent.lease_template.lease_id}-owner`,
  );
  if (
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT === '1'
  ) {
    assertIsolatedTestMode();
    throw new ControlError(
      'TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT',
      'injected failure after acquire owner capability mint',
    );
  }
  atomicWriteJson(receiptFile, sealAcquireRecord({
    schema_version: 1,
    type: 'LEASE_OWNER_CAPABILITY',
    event_id: intentEntry.intent.request.event_id,
    lease_id: intentEntry.intent.lease_template.lease_id,
    capability_file: capability.file,
    capability_sha256: capability.sha256,
  }, 'receipt_sha256'));
  return capability;
}

function cleanupAbortedAcquireIntent(intentEntry) {
  if (!intentEntry || !fs.existsSync(intentEntry.directory)) return;
  const finalizedCapabilityPattern = ownerCapabilityPattern(
    intentEntry.intent.lease_template.lease_id,
  );
  const removable = fs.readdirSync(intentEntry.directory)
    .filter((name) => name !== 'intent.json');
  for (const name of removable) {
    assertControl(
      name === 'capability-receipt.json'
        || finalizedCapabilityPattern.test(name),
      'CORRUPT_STORE',
      `aborted acquire intent ${intentEntry.intent.request.event_id} 含未知文件 ${name}`,
    );
    const file = path.join(intentEntry.directory, name);
    const stat = fs.lstatSync(file);
    assertControl(
      stat.isFile() && !stat.isSymbolicLink(),
      'CORRUPT_STORE',
      `aborted acquire staging ${name} 非普通文件`,
    );
  }
  for (const name of removable) {
    const file = path.join(intentEntry.directory, name);
    fs.rmSync(file, { force: true });
  }
  fsyncDirectory(intentEntry.directory);
}

function publicAbortedAcquire(event, idempotent) {
  return {
    status: 'ABORTED',
    resource: event.resource,
    access: event.access,
    operation_event_id: event.event_id,
    request_sha256: event.request_sha256,
    fencing_token: event.fencing_token,
    reason: event.reason,
    idempotent,
  };
}

function validateAcquireEventRetryState(state, event, request, owner) {
  if (event.type === 'LEASE_ACQUIRE_ABORTED') {
    assertControl(
      event.request_sha256 === hashObject(request)
        && hashObject(event.actor) === hashObject(owner)
        && event.resource === request.resource
        && event.access === request.access
        && event.ttl_ms === request.ttl_ms,
      'RESOURCE_EVENT_ID_CONFLICT',
      `resource event id ${request.event_id} 已绑定不同 aborted acquire request`,
    );
    return { aborted: true, current: null, capabilityFile: null };
  }
  assertControl(
    event.type === 'LEASE_ACQUIRED'
      && hashObject(event.actor) === hashObject(owner)
      && event.lease.resource === request.resource
      && event.lease.access === request.access
      && Date.parse(event.lease.expires_at)
        - Date.parse(event.accepted_at) === request.ttl_ms,
    'RESOURCE_EVENT_ID_CONFLICT',
    `resource event id ${request.event_id} 已绑定不同 acquire request`,
  );
  const current = state.leases[event.lease.lease_id];
  assertControl(
    current
      && current.lease_id === event.lease.lease_id
      && current.resource === event.lease.resource
      && current.access === event.lease.access
      && current.fencing_token === event.lease.fencing_token
      && hashObject(current.owner) === hashObject(event.lease.owner),
    'CORRUPT_STORE',
    `lease ${event.lease.lease_id} current lineage 与 acquire event 不一致`,
  );
  let capabilityFile = null;
  if (fs.existsSync(current.owner_capability_file)) {
    const capability = readCapabilityFile(
      current.owner_capability_file,
      current.owner_capability_file,
    );
    assertControl(
      hashesEqual(capability.sha256, current.owner_capability_sha256),
      'CORRUPT_STORE',
      `lease ${current.lease_id} owner capability 漂移`,
    );
    capabilityFile = capability.file;
  } else {
    assertControl(
      TERMINAL.has(current.status),
      'CORRUPT_STORE',
      `active lease ${current.lease_id} owner capability 缺失`,
    );
  }
  return { aborted: false, current, capabilityFile };
}

function abortAcquire(paths, state, intentEntry, request, acceptedAt) {
  const aborted = {
    schema_version: 1,
    event_id: request.event_id,
    type: 'LEASE_ACQUIRE_ABORTED',
    accepted_at: acceptedAt,
    actor: intentEntry.intent.actor,
    request_sha256: hashObject(request),
    resource: request.resource,
    access: request.access,
    lease_id: intentEntry.intent.lease_template.lease_id,
    fencing_token: intentEntry.intent.lease_template.fencing_token,
    ttl_ms: request.ttl_ms,
    reason: 'sealed acquire actor is no longer live at commit',
  };
  appendEvent(paths, state, aborted);
  writeProjection(paths, state);
  cleanupAbortedAcquireIntent(intentEntry);
  return publicAbortedAcquire(aborted, false);
}

function acquireLeaseOnce(cwd, options) {
  const root = controlRoot(cwd);
  const owner = normalizeOwner(options);
  const request = acquireRequest(owner, options);
  const eventId = request.event_id;
  let context = null;
  let transactionAuthority = null;
  let abortPristine = false;
  let transactionBoundaryStartedAt = null;
  return withLock(root, () => {
    if (abortPristine) throw pristineAbortRetry('resource acquire');
    const { paths, state } = rebuildUnlocked(root);
    const {
      resource,
      access,
      ttl_ms: ttlMilliseconds,
    } = request;
    const existingEvent = context.existingEvent;
    if (existingEvent) {
      const retry = validateAcquireEventRetryState(
        state,
        existingEvent,
        request,
        owner,
      );
      if (retry.aborted) {
        cleanupAcquireAtomicTemporaries(context.intentEntry);
        cleanupAbortedAcquireIntent(context.intentEntry);
        return publicAbortedAcquire(existingEvent, true);
      }
      assertOwnerCapabilityDisclosureBoundary(
        context.taskState,
        state,
        retry.current,
        currentTimeMilliseconds(),
      );
      return {
        ...publicLease(retry.current),
        owner_capability_file: retry.capabilityFile,
        idempotent: true,
      };
    }
    let intentEntry = context.intentEntry;
    if (context.unpublishedStaging) {
      if (
        process.env
          .GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_EMPTY_STAGING_CLEANUP === '1'
      ) {
        assertIsolatedTestMode();
        throw new ControlError(
          'TEST_FAULT_AFTER_ACQUIRE_EMPTY_STAGING_CLEANUP',
          'injected failure after acquire empty staging cleanup',
        );
      }
      intentEntry = context.unpublishedStaging;
    }
    assertNoPendingTaskMutation(root, owner.goal_id, owner.task_id, {
      allowOperationKind: 'RESOURCE_ACQUIRE',
      allowOperationId: eventId,
      allowRequestSha256: hashObject(request),
    });
    if (intentEntry && intentEntry.intent !== null) {
      intentEntry = promoteAcquireIntent(intentEntry);
      assertControl(
        state.event_count === intentEntry.intent.resource_head.event_count
          && (state.fencing_tokens[resource] || 0)
            === intentEntry.intent.resource_head.fencing_token,
        'RESOURCE_PENDING_OPERATION_CONFLICT',
        `acquire intent ${eventId} 后 resource ledger 已推进`,
      );
      cleanupAcquireAtomicTemporaries(intentEntry);
    }
    const boundaryNow = currentTimeMilliseconds();
    const actorUsableAtBoundary = acquireAuthorityUsableAt(
      context.authorityLiveness,
      boundaryNow,
    );
    if (
      !actorUsableAtBoundary
        && !(intentEntry && intentEntry.intent !== null)
    ) {
      assertControl(
        ['active', 'idle'].includes(context.authorityLiveness.status),
        'ACTOR_UNUSABLE',
        `actor status=${context.authorityLiveness.status}`,
      );
      assertControl(
        Date.parse(context.authorityLiveness.lease_until) > boundaryNow,
        'ACTOR_LEASE_EXPIRED',
        `actor lease 已于 ${context.authorityLiveness.lease_until} 过期`,
      );
    }
    if (!actorUsableAtBoundary) {
      assertControl(
        intentEntry && intentEntry.intent !== null,
        'CORRUPT_STORE',
        `aborted acquire ${eventId} 缺 durable intent`,
      );
      return abortAcquire(
        paths,
        state,
        intentEntry,
        request,
        new Date(boundaryNow).toISOString(),
      );
    }
    // A sealed intent already crossed the manifest/role boundary before it
    // became durable. Exact recovery must preserve that accepted authority,
    // including intents written by an older decoder whose omitted `roles`
    // semantics also admitted control-plane roles. Only a fresh request uses
    // the current worker-only default.
    if (!intentEntry) {
      declaredRequirement(
        context.manifest_task,
        resource,
        access,
        context.actor.role,
      );
    }
    const occupants = Object.values(state.leases).filter((lease) => lease.resource === resource && !TERMINAL.has(lease.status));
    const quarantined = occupants.find((lease) => lease.status === UNVERIFIED_REVOKE);
    if (quarantined) {
      assertControl(
        false,
        'RESOURCE_BROKER_REPAIR_REQUIRED',
        `资源 ${resource} 存在未经 host broker 隔离的历史 revoke ${quarantined.lease_id}；禁止复用`,
      );
    }
    const stale = occupants.find(
      (lease) => Date.parse(lease.expires_at) <= boundaryNow,
    );
    if (stale) {
      assertControl(false, 'RESOURCE_STALE_REQUIRES_REAP', `资源 ${resource} 存在过期 lease ${stale.lease_id}；必须先显式 reap`);
    }
    const conflict = occupants.find((lease) => access === 'EXCLUSIVE' || (lease.access || 'EXCLUSIVE') === 'EXCLUSIVE');
    if (conflict) {
      assertControl(false, 'RESOURCE_CONFLICT', `资源 ${resource} 已被 lease ${conflict.lease_id} 占用`);
    }
    if (!intentEntry || intentEntry.intent === null) {
      intentEntry = writeAcquireIntent(
        paths,
        request,
        context.actor,
        context.actorAuthority,
        state,
        transactionBoundaryStartedAt,
      );
    }
    assertControl(
      state.event_count === intentEntry.intent.resource_head.event_count
        && (state.fencing_tokens[resource] || 0)
          === intentEntry.intent.resource_head.fencing_token,
      'RESOURCE_PENDING_OPERATION_CONFLICT',
      `acquire intent ${eventId} 后 resource ledger 已推进`,
    );
    const ownerCapability = acquireOwnerCapability(intentEntry);
    maybeAdvanceAcquireClockAfterBoundaryForTest();
    const finalNow = currentTimeMilliseconds();
    const acceptedAt = new Date(finalNow).toISOString();
    if (!acquireAuthorityUsableAt(context.authorityLiveness, finalNow)) {
      return abortAcquire(paths, state, intentEntry, request, acceptedAt);
    }
    const lease = {
      ...intentEntry.intent.lease_template,
      owner_capability_sha256: ownerCapability.sha256,
      owner_capability_file: ownerCapability.file,
      acquired_at: acceptedAt,
      updated_at: acceptedAt,
      expires_at: new Date(finalNow + request.ttl_ms).toISOString(),
    };
    appendEvent(paths, state, {
      schema_version: 1,
      event_id: eventId,
      type: 'LEASE_ACQUIRED',
      accepted_at: acceptedAt,
      actor: intentEntry.intent.actor,
      lease,
    });
    writeProjection(paths, state);
    return {
      ...publicLease(lease, finalNow),
      owner_capability_file: ownerCapability.file,
      idempotent: false,
    };
  }, {
    beforeGeneration: (transaction) => {
      abortPristine = false;
      transactionBoundaryStartedAt = transaction.transaction_started_at;
      const paths = resourcePaths(root);
      const existingEvent = resourceEventById(paths, eventId);
      if (existingEvent) {
        const intentEntry = readAcquireIntent(paths, request);
        assertControl(
          ['LEASE_ACQUIRED', 'LEASE_ACQUIRE_ABORTED'].includes(
            existingEvent.type,
          )
            && hashObject(existingEvent.actor) === hashObject(owner)
            && intentEntry
            && intentEntry.intent !== null
            && hashObject(intentEntry.intent.request)
              === hashObject(request)
            && hashObject(intentEntry.intent.actor)
              === hashObject(existingEvent.actor),
          'RESOURCE_EVENT_ID_CONFLICT',
          `resource event id ${eventId} 缺 exact sealed acquire request witness`,
        );
        const loaded = loadGoalStateUnlocked(
          root,
          existingEvent.actor.goal_id,
          {
            repairHeads: false,
            allowLaggingHeads: true,
            repairBootstrapConsumption: false,
            allowIncompleteRecoveryRead: true,
            allowIncompleteGoalOperationRead: true,
          },
        );
        const state = loaded.snapshot.tasks[existingEvent.actor.task_id];
        assertControl(state, 'UNKNOWN_TASK', `未知 task ${existingEvent.actor.task_id}`);
        exactHistoricalResourceAuthority(
          state,
          intentEntry.intent.actor_authority,
          options.actorCapabilityFile,
          loaded.snapshot,
        );
        const { state: resources } = rebuildUnlocked(root, {
          repairHeads: false,
          allowLaggingHeads: true,
        });
        validateAcquireEventRetryState(
          resources,
          existingEvent,
          request,
          owner,
        );
        context = {
          existingEvent,
          intentEntry,
          actorAuthority: intentEntry.intent.actor_authority,
          taskState: state,
        };
        assertTransactionAuthorityStable(
          transactionAuthority,
          context.actorAuthority,
          'resource acquire',
        );
        return;
      }
      const intentEntry = readAcquireIntent(paths, request);
      if (intentEntry && intentEntry.intent !== null) {
        const loaded = loadGoalStateUnlocked(
          root,
          intentEntry.intent.actor.goal_id,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const state = loaded.snapshot.tasks[intentEntry.intent.actor.task_id];
        assertControl(
          state,
          'UNKNOWN_TASK',
          `未知 task ${intentEntry.intent.actor.task_id}`,
        );
        assertControl(
          state.phase !== 'ARCHIVED',
          'TASK_TERMINAL',
          `task ${state.task_id} 已 ARCHIVED，不得完成 pending resource acquire`,
        );
        // A legal Goal event cannot add a hard hold while this durable intent
        // is pending. Keep the local recovery path fail-closed as defense in
        // depth for migrated or repaired stores that violate that invariant.
        assertNoHardHold(state);
        const historicalAuthority = exactHistoricalResourceAuthority(
          state,
          intentEntry.intent.actor_authority,
          options.actorCapabilityFile,
          loaded.snapshot,
        );
        context = {
          actor: intentEntry.intent.actor,
          actorAuthority: intentEntry.intent.actor_authority,
          authorityLiveness: authorityLiveness(historicalAuthority),
          manifest_task: loaded.manifest.tasks.find(
            (task) => task.id === intentEntry.intent.actor.task_id,
          ),
          intentEntry,
          existingEvent: null,
        };
        assertTransactionAuthorityStable(
          transactionAuthority,
          context.actorAuthority,
          'resource acquire',
        );
        return;
      }
      const loaded = loadGoalStateUnlocked(
        root,
        owner.goal_id,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const state = loaded.snapshot.tasks[owner.task_id];
      assertControl(state, 'UNKNOWN_TASK', `Goal ${owner.goal_id} 没有 task ${owner.task_id}`);
      assertControl(
        state.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${owner.task_id} 已 ARCHIVED，禁止 acquire resource`,
      );
      const session = isHistoricalTransactionRetry(transaction.mode)
        ? assertHistoricalAuthorityUsableAt(
          exactHistoricalResourceActor(
            state,
            owner,
            options.actorCapabilityFile,
            loaded.snapshot,
          ),
          transaction.transaction_started_at,
        )
        : authorizeResourceSession(
          loaded,
          state,
          options.actorCapabilityFile,
          {
            role: owner.role,
            threadId: owner.thread_id,
          },
        );
      assertControl(session.host_id === owner.host_id, 'CAPABILITY_INVALID', 'capability host 不匹配');
      if (!isHistoricalTransactionRetry(transaction.mode)) {
        assertFrozenInputs(cwd, loaded, owner.task_id);
      }
      assertNoHardHold(state);
      assertResourceOperationalScope(state, owner.role, 'RESOURCE_ACQUIRE');
      context = {
        actor: actorIdentity(session, owner.goal_id, owner.task_id),
        actorAuthority: authorityIdentity(session),
        authorityLiveness: authorityLiveness(session),
        manifest_task: loaded.manifest.tasks.find((task) => task.id === owner.task_id),
        intentEntry: null,
        unpublishedStaging: intentEntry && intentEntry.intent === null
          ? intentEntry
          : null,
        existingEvent: null,
      };
      assertTransactionAuthorityStable(
        transactionAuthority,
        context.actorAuthority,
        'resource acquire',
      );
      if (isOddTransactionRetry(transaction.mode)) {
        const expectedTransaction = acquireTransactionKey(
          request,
          context.actorAuthority,
        );
        if (
          transaction.transport_transaction_key_sha256
            !== expectedTransaction.key_sha256
            || transaction.transport_has_non_generation_state !== true
        ) {
          assertExactPristineBoundary(transaction, expectedTransaction);
          abortPristine = true;
        }
      }
    },
    authorizeOddRecovery: () => Boolean(
      context
        && (
          context.existingEvent
          || (context.intentEntry && context.intentEntry.intent !== null)
        ),
    ),
    authorizePristineOddRecovery: () => Boolean(
      abortPristine,
    ),
    transactionKey: () => {
      transactionAuthority = resolveAcquireTransactionAuthority(
        root,
        request,
        options.actorCapabilityFile,
      );
      return acquireTransactionKey(request, transactionAuthority);
    },
    sameStableOperationMismatchCode: 'RESOURCE_EVENT_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      'resource acquire event id 已绑定不同 request',
    afterGenerationBeforeCallback: resourceGenerationBoundaryFaultHook(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_ACQUIRE_GENERATION',
    ),
  });
}

function acquireLease(cwd, options) {
  return runWithOneFreshRetry(() => acquireLeaseOnce(cwd, options));
}

function renewLeaseOnce(cwd, options) {
  const root = controlRoot(cwd);
  safeId(options.eventId, 'resource renew event');
  let boundary = null;
  let transactionBoundary = null;
  let abortPristine = false;
  return withLock(root, () => {
    if (abortPristine) throw pristineAbortRetry('resource renew');
    const { paths, state } = rebuildUnlocked(root);
    const now = currentTimeMilliseconds();
    if (boundary.existingEvent) {
      return validateResourceMutationRetry(
        state,
        boundary.existingEvent,
        options,
        'LEASE_RENEWED',
        now,
      );
    }
    assertNoPendingTaskMutation(
      root,
      boundary.actor.goal_id,
      boundary.actor.task_id,
    );
    assertControl(
      acquireAuthorityUsableAt(boundary.authorityLiveness, now),
      Date.parse(boundary.authorityLiveness.lease_until) <= now
        ? 'ACTOR_LEASE_EXPIRED'
        : 'ACTOR_UNUSABLE',
      `renew actor 在 commit 时不可用；lease_until=${boundary.authorityLiveness.lease_until}`,
    );
    const lease = state.leases[options.leaseId];
    const allowExpired = Boolean(boundary.expiredRenewalBoundary);
    if (allowExpired) {
      assertRuntimeRotationExpiredRenewalStillAuthorized(
        root,
        options,
        state,
        lease,
        boundary.expiredRenewalBoundary,
        now,
      );
    }
    assertLeaseMutable(lease, options, now, allowExpired);
    assertOwnerCapability(lease, options.ownerCapabilityFile);
    const { ttlMilliseconds } = assertResourceRenewalRequest(
      lease,
      options,
      now,
      allowExpired,
    );
    appendEvent(paths, state, {
      schema_version: 1,
      event_id: options.eventId,
      type: 'LEASE_RENEWED',
      accepted_at: new Date(now).toISOString(),
      actor: boundary.actor,
      lease_id: lease.lease_id,
      from_revision: lease.revision,
      to_revision: lease.revision + 1,
      expires_at: new Date(now + ttlMilliseconds).toISOString(),
    });
    writeProjection(paths, state);
    const renewed = {
      ...publicLease(state.leases[lease.lease_id], now),
      idempotent: false,
      operation_event_id: options.eventId,
    };
    maybeFaultAfterResourceCommit('LEASE_RENEWED');
    return renewed;
  }, {
    beforeGeneration: (transaction) => {
      abortPristine = false;
      const paths = resourcePaths(root);
      const existingEvent = resourceEventById(paths, options.eventId);
      if (existingEvent) {
        assertControl(
          existingEvent.type === 'LEASE_RENEWED'
            && existingEvent.lease_id === options.leaseId,
          'RESOURCE_EVENT_ID_CONFLICT',
          `resource event id ${options.eventId} 已绑定不同 operation`,
        );
        const loaded = loadGoalStateUnlocked(
          root,
          existingEvent.actor.goal_id,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const state = loaded.snapshot.tasks[existingEvent.actor.task_id];
        assertControl(state, 'UNKNOWN_TASK', `未知 task ${existingEvent.actor.task_id}`);
        const historical = exactHistoricalResourceActor(
          state,
          existingEvent.actor,
          options.actorCapabilityFile,
          loaded.snapshot,
        );
        const { state: resources } = rebuildUnlocked(root, {
          repairHeads: false,
          allowLaggingHeads: true,
        });
        validateResourceMutationRetry(
          resources,
          existingEvent,
          options,
          'LEASE_RENEWED',
          currentTimeMilliseconds(),
        );
        boundary = {
          existingEvent,
          actorAuthority: authorityIdentity(historical),
        };
        assertTransactionAuthorityStable(
          transactionBoundary.actorAuthority,
          boundary.actorAuthority,
          'resource renew',
        );
        return;
      }
      const { state: resources } = rebuildUnlocked(root, { repairHeads: false });
      const lease = resources.leases[options.leaseId];
      assertControl(lease, 'LEASE_NOT_FOUND', `找不到 lease: ${options.leaseId}`);
      const loaded = loadGoalStateUnlocked(
        root,
        lease.owner.goal_id,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const state = loaded.snapshot.tasks[lease.owner.task_id];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${lease.owner.task_id}`);
      assertControl(
        state.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${state.task_id} 已 ARCHIVED，禁止 renew resource`,
      );
      const session = isHistoricalTransactionRetry(transaction.mode)
        ? assertHistoricalAuthorityUsableAt(
          exactHistoricalResourceActor(
            state,
            lease.owner,
            options.actorCapabilityFile,
            loaded.snapshot,
          ),
          transaction.transaction_started_at,
        )
        : authorizeResourceSession(
          loaded,
          state,
          options.actorCapabilityFile,
          {
            role: lease.owner.role,
            threadId: lease.owner.thread_id,
          },
        );
      assertControl(session.host_id === lease.owner.host_id, 'CAPABILITY_INVALID', 'capability host 不匹配');
      if (!isHistoricalTransactionRetry(transaction.mode)) {
        assertFrozenInputs(cwd, loaded, lease.owner.task_id);
      }
      let expiredRenewalBoundary = null;
      if (state.holds.some(
        (hold) => hold.hard || HARD_HOLDS.includes(hold.kind),
      )) {
        expiredRenewalBoundary = runtimeRotationExpiredRenewalBoundary(
          state,
          session,
          resources,
          lease,
          currentTimeMilliseconds(),
        );
      }
      assertResourceOperationalScope(state, lease.owner.role, 'RESOURCE_USE');
      const boundaryNow = isHistoricalTransactionRetry(transaction.mode)
        ? Date.parse(transaction.transaction_started_at)
        : currentTimeMilliseconds();
      assertLeaseMutable(
        lease,
        options,
        boundaryNow,
        Boolean(expiredRenewalBoundary),
      );
      assertOwnerCapability(lease, options.ownerCapabilityFile);
      assertResourceRenewalRequest(
        lease,
        options,
        boundaryNow,
        Boolean(expiredRenewalBoundary),
      );
      boundary = {
        actor: actorIdentity(
          session,
          lease.owner.goal_id,
          lease.owner.task_id,
        ),
        actorAuthority: authorityIdentity(session),
        authorityLiveness: authorityLiveness(session),
        expiredRenewalBoundary,
      };
      assertTransactionAuthorityStable(
        transactionBoundary.actorAuthority,
        boundary.actorAuthority,
        'resource renew',
      );
      if (isOddTransactionRetry(transaction.mode)) {
        assertExactPristineBoundary(
          transaction,
          resourceMutationTransactionKey(
            'LEASE_RENEWED',
            options,
            boundary,
          ),
        );
        abortPristine = true;
      }
    },
    authorizeOddRecovery: () => Boolean(
      boundary && boundary.existingEvent,
    ),
    authorizePristineOddRecovery: () => Boolean(
      abortPristine,
    ),
    transactionKey: () => {
      transactionBoundary = resolveResourceMutationTransactionBoundary(
        root,
        'LEASE_RENEWED',
        options,
      );
      return resourceMutationTransactionKey(
        'LEASE_RENEWED',
        options,
        transactionBoundary,
      );
    },
    sameStableOperationMismatchCode: 'RESOURCE_EVENT_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      'resource renew event id 已绑定不同 request',
    afterGenerationBeforeCallback: resourceGenerationBoundaryFaultHook(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_RENEW_GENERATION',
    ),
  });
}

function renewLease(cwd, options) {
  return runWithOneFreshRetry(() => renewLeaseOnce(cwd, options));
}

function releaseLease(cwd, options) {
  const root = controlRoot(cwd);
  safeId(options.eventId, 'resource release event');
  let boundary = null;
  let transactionBoundary = null;
  return withLock(root, () => {
    const { paths, state } = rebuildUnlocked(root);
    const now = currentTimeMilliseconds();
    if (boundary.existingEvent) {
      return validateResourceMutationRetry(
        state,
        boundary.existingEvent,
        options,
        'LEASE_RELEASED',
        now,
      );
    }
    assertNoPendingTaskMutation(
      root,
      boundary.actor.goal_id,
      boundary.actor.task_id,
    );
    const lease = state.leases[options.leaseId];
    assertLeaseMutable(lease, options, now, true);
    assertOwnerCapability(lease, options.ownerCapabilityFile);
    appendEvent(paths, state, {
      schema_version: 1,
      event_id: options.eventId,
      type: 'LEASE_RELEASED',
      accepted_at: new Date(now).toISOString(),
      actor: boundary.actor,
      lease_id: lease.lease_id,
      from_revision: lease.revision,
      to_revision: lease.revision + 1,
    });
    writeProjection(paths, state);
    const released = publicLease(state.leases[lease.lease_id], now);
    try {
      if (process.env.GOAL_CONTROL_TEST_FAULT_RESOURCE_CAP_CLEANUP === '1') {
        assertIsolatedTestMode();
      } else {
        fs.rmSync(lease.owner_capability_file, { force: true });
      }
    } catch {
      // Lease 已 durable terminal；capability 清理失败不能把动作伪装成未提交。
    }
    const response = {
      ...released,
      idempotent: false,
      operation_event_id: options.eventId,
    };
    maybeFaultAfterResourceCommit('LEASE_RELEASED');
    return response;
  }, {
    beforeGeneration: (transaction) => {
      const paths = resourcePaths(root);
      const existingEvent = resourceEventById(paths, options.eventId);
      if (existingEvent) {
        assertControl(
          existingEvent.type === 'LEASE_RELEASED'
            && existingEvent.lease_id === options.leaseId,
          'RESOURCE_EVENT_ID_CONFLICT',
          `resource event id ${options.eventId} 已绑定不同 operation`,
        );
        const loaded = loadGoalStateUnlocked(
          root,
          existingEvent.actor.goal_id,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const state = loaded.snapshot.tasks[existingEvent.actor.task_id];
        assertControl(state, 'UNKNOWN_TASK', `未知 task ${existingEvent.actor.task_id}`);
        const historical = exactHistoricalResourceActor(
          state,
          existingEvent.actor,
          options.actorCapabilityFile,
          loaded.snapshot,
        );
        const { state: resources } = rebuildUnlocked(root, {
          repairHeads: false,
          allowLaggingHeads: true,
        });
        validateResourceMutationRetry(
          resources,
          existingEvent,
          options,
          'LEASE_RELEASED',
          currentTimeMilliseconds(),
        );
        boundary = {
          existingEvent,
          actorAuthority: authorityIdentity(historical),
          pristineResume: false,
        };
        assertTransactionAuthorityStable(
          transactionBoundary.actorAuthority,
          boundary.actorAuthority,
          'resource release',
        );
        return;
      }
      const { state: resources } = rebuildUnlocked(root, { repairHeads: false });
      const lease = resources.leases[options.leaseId];
      assertControl(lease, 'LEASE_NOT_FOUND', `找不到 lease: ${options.leaseId}`);
      const loaded = loadGoalStateUnlocked(
        root,
        lease.owner.goal_id,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const state = loaded.snapshot.tasks[lease.owner.task_id];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${lease.owner.task_id}`);
      assertControl(
        state.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${state.task_id} 已 ARCHIVED，禁止 release resource`,
      );
      assertNoHardHold(state);
      const session = isHistoricalTransactionRetry(transaction.mode)
        ? assertHistoricalAuthorityUsableAt(
          exactHistoricalResourceActor(
            state,
            lease.owner,
            options.actorCapabilityFile,
            loaded.snapshot,
          ),
          transaction.transaction_started_at,
          { allowTerminal: true },
        )
        : authorizeResourceSession(
          loaded,
          state,
          options.actorCapabilityFile,
          {
            role: lease.owner.role,
            threadId: lease.owner.thread_id,
            allowTerminal: true,
          },
        );
      assertControl(session.host_id === lease.owner.host_id, 'CAPABILITY_INVALID', 'capability host 不匹配');
      if (!isHistoricalTransactionRetry(transaction.mode)) {
        assertFrozenInputs(cwd, loaded, lease.owner.task_id);
      }
      assertResourceOperationalScope(state, lease.owner.role, 'CLEANUP');
      boundary = {
        actor: actorIdentity(
          session,
          lease.owner.goal_id,
          lease.owner.task_id,
        ),
        actorAuthority: authorityIdentity(session),
        pristineResume: isOddTransactionRetry(transaction.mode),
      };
      assertTransactionAuthorityStable(
        transactionBoundary.actorAuthority,
        boundary.actorAuthority,
        'resource release',
      );
      if (boundary.pristineResume) {
        assertExactPristineBoundary(
          transaction,
          resourceMutationTransactionKey(
            'LEASE_RELEASED',
            options,
            boundary,
          ),
        );
      }
    },
    authorizeOddRecovery: () => Boolean(
      boundary && boundary.existingEvent,
    ),
    authorizePristineOddRecovery: () => Boolean(
      boundary && boundary.pristineResume,
    ),
    transactionKey: () => {
      transactionBoundary = resolveResourceMutationTransactionBoundary(
        root,
        'LEASE_RELEASED',
        options,
      );
      return resourceMutationTransactionKey(
        'LEASE_RELEASED',
        options,
        transactionBoundary,
      );
    },
    sameStableOperationMismatchCode: 'RESOURCE_EVENT_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      'resource release event id 已绑定不同 request',
    afterGenerationBeforeCallback: resourceGenerationBoundaryFaultHook(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_RELEASE_GENERATION',
    ),
  });
}

function reapLease(cwd, options) {
  const root = controlRoot(cwd);
  const current = lookupLease(cwd, options.leaseId);
  const context = actorContext(
    cwd,
    current.owner.goal_id,
    current.owner.task_id,
    options.actorCapabilityFile
  );
  assertControl(['CAPTAIN', 'FOREMAN'].includes(context.actor.role), 'REAP_AUTHORITY_REQUIRED', '只有 active CAPTAIN/FOREMAN capability 可 reap');
  return withStableRead(root, () => {
    const { state } = rebuildUnlocked(root, { repairHeads: false });
    assertActorContextFresh(root, context);
    const lease = state.leases[options.leaseId];
    const now = currentTimeMilliseconds();
    assertLeaseMutable(lease, options, now, true);
    assertControl(Date.parse(lease.expires_at) <= now, 'LEASE_NOT_EXPIRED', `lease 在 ${lease.expires_at} 前仍有效`);
    assertControl(context.mode === 'enforce', 'REAP_DISABLED_IN_SHADOW', 'shadow 模式禁止转手过期资源；须先完成外部隔离并切 enforce');
    const recovery = context.state.recovery;
    assertControl(recovery, 'REAP_RECOVERY_REQUIRED', 'reap 前必须先登记对应 ROLE_LOST recovery');
    assertControl(recovery.role === lease.owner.role, 'REAP_OWNER_MISMATCH', 'ROLE_LOST role 与 lease owner 不一致');
    assertControl(recovery.lost_thread_id === lease.owner.thread_id, 'REAP_OWNER_MISMATCH', 'ROLE_LOST thread 与 lease owner 不一致');
    assertControl(recovery.evidence_id && recovery.evidence_id === options.evidenceId, 'REAP_EVIDENCE_MISMATCH', 'reap evidence 必须是当前 recovery 已验真的 ROLE_FAILURE evidence');
    const evidenceFile = path.join(root, 'goals', context.actor.goal_id, 'evidence', context.actor.task_id, `${safeId(options.evidenceId, 'evidence')}.json`);
    const evidence = readJson(evidenceFile, 'ROLE_FAILURE evidence');
    const unsignedEvidence = { ...evidence };
    delete unsignedEvidence.registry_sha256;
    assertControl(hashObject(unsignedEvidence) === evidence.registry_sha256, 'CORRUPT_STORE', 'ROLE_FAILURE evidence registry seal 不匹配');
    assertControl(evidence.registry_sha256 === recovery.evidence_registry_sha256, 'REAP_EVIDENCE_MISMATCH', 'ROLE_FAILURE evidence seal 与 recovery 不一致');
    assertControl(evidence.evidence_id === options.evidenceId && evidence.kind === 'ROLE_FAILURE' && evidence.status === 'FAIL', 'REAP_EVIDENCE_MISMATCH', 'reap 引用了错误 evidence');
    const binding = evidence.resource_lease;
    assertControl(binding && binding.isolated === true, 'RESOURCE_ISOLATION_REQUIRED', 'ROLE_FAILURE evidence 必须声明资源已外部隔离');
    assertControl(binding.lease_id === lease.lease_id, 'REAP_EVIDENCE_MISMATCH', 'ROLE_FAILURE evidence 绑定了不同 lease');
    assertControl(binding.resource === lease.resource, 'REAP_EVIDENCE_MISMATCH', 'ROLE_FAILURE evidence 绑定了不同 resource');
    assertControl(binding.revision === lease.revision, 'REAP_EVIDENCE_MISMATCH', 'ROLE_FAILURE evidence 绑定了不同 lease revision');
    assertControl(hashObject(binding.owner) === hashObject(lease.owner), 'REAP_EVIDENCE_MISMATCH', 'ROLE_FAILURE evidence 绑定了不同 owner');
    assertControl(typeof binding.isolation_ref === 'string' && binding.isolation_ref.length > 0, 'RESOURCE_ISOLATION_REQUIRED', '资源隔离缺少外部引用');
    assertControl(false, 'REAP_REQUIRES_BROKER', '语义 ROLE_FAILURE evidence 不能证明资源已停止使用；v1 必须有按资源类型机械验证 PID/profile/port/account 的 broker adapter 才允许 reap');
  });
}

function zeroRuntimeReceipt(event, idempotent) {
  return {
    reinitialized: true,
    idempotent,
    no_op: true,
    event_id: event.event_id,
    event_sha256: event.event_sha256,
    handoff_event_id: event.handoff_event_id,
    predecessor_launch_id: event.predecessor_launch_id,
    predecessor_launch_sha256: event.predecessor_launch_sha256,
    captain_authority: event.captain_authority,
    foreman_authority: event.foreman_authority,
    predecessor: event.predecessor,
    successor: event.successor,
    leases: event.leases,
  };
}

function assertZeroRuntimeRetryRequest(event, options) {
  assertControl(
    event.type === 'ZERO_RUNTIME_REINITIALIZED'
      && event.event_id === options.eventId
      && event.goal_id === options.goalId
      && event.task_id === options.taskId
      && event.handoff_event_id === options.handoffEventId
      && event.successor.thread_id === options.successorThreadId
      && (!options.captainThreadId
        || event.captain_authority.thread_id === options.captainThreadId)
      && (!options.foremanThreadId
        || event.foreman_authority.thread_id === options.foremanThreadId),
    'RESOURCE_EVENT_ID_CONFLICT',
    `resource event id ${options.eventId} 已绑定不同 zero-runtime request`,
  );
}

function zeroRuntimeTransactionRequest(options, boundary) {
  assertControl(
    boundary,
    'TRANSACTION_KEY_INVALID',
    'zero-runtime transaction boundary 缺失',
  );
  const durable = boundary.existingEvent || {
    predecessor: sessionBinding(boundary.predecessor),
    successor: sessionBinding(boundary.successor),
    predecessor_launch_id: boundary.launch.launch_id,
    predecessor_launch_sha256: boundary.launchSha256,
    captain_authority: authorityIdentity(boundary.captain),
    foreman_authority: authorityIdentity(boundary.foreman),
  };
  return {
    schema_version: 1,
    event_id: safeId(options.eventId, 'resource reinitialize event'),
    goal_id: safeId(options.goalId, 'goal'),
    task_id: safeId(options.taskId, 'task'),
    handoff_event_id: safeId(options.handoffEventId, 'handoff event'),
    successor_thread_id: safeId(
      options.successorThreadId,
      'successor thread',
    ),
    predecessor: durable.predecessor,
    successor: durable.successor,
    predecessor_launch_id: durable.predecessor_launch_id,
    predecessor_launch_sha256: durable.predecessor_launch_sha256,
    captain_authority: durable.captain_authority,
    foreman_authority: durable.foreman_authority,
  };
}

function resourceAuthorityFromCapability(
  state,
  goalSnapshot,
  capabilityFile,
  role,
  threadId = null,
) {
  const supplied = readCapabilityFile(capabilityFile);
  const matches = historicalResourceSessions(
    state,
    { role },
    goalSnapshot,
  ).filter((candidate) => (
    candidate
      && candidate.role === role
      && (!threadId || candidate.thread_id === threadId)
      && candidate.capability_file === supplied.file
      && hashesEqual(candidate.capability_sha256, supplied.sha256)
  ));
  assertControl(
    matches.length > 0,
    'CAPABILITY_INVALID',
    `capability 不属于 zero-runtime 的历史 ${role} authority`,
  );
  const authorities = new Map(
    matches.map((candidate) => {
      const authority = authorityIdentity(candidate);
      return [hashObject(authority), candidate];
    }),
  );
  assertControl(
    authorities.size === 1,
    'CAPABILITY_INVALID',
    `zero-runtime ${role} capability 匹配多个 authority`,
  );
  return [...authorities.values()][0];
}

function zeroRuntimeStructuralBoundary(root, options) {
  const paths = resourcePaths(root);
  const existingEvent = resourceEventById(paths, options.eventId);
  if (existingEvent) {
    assertControl(
      existingEvent.type === 'ZERO_RUNTIME_REINITIALIZED',
      'RESOURCE_EVENT_ID_CONFLICT',
      `resource event id ${options.eventId} 已绑定不同 operation`,
    );
    assertZeroRuntimeRetryRequest(existingEvent, options);
    const loaded = loadGoalStateUnlocked(
      root,
      existingEvent.goal_id,
      {
        repairHeads: false,
        allowLaggingHeads: true,
        repairBootstrapConsumption: false,
        allowIncompleteRecoveryRead: true,
        allowIncompleteGoalOperationRead: true,
      },
    );
    const taskState = loaded.snapshot.tasks[existingEvent.task_id];
    assertControl(
      taskState,
      'UNKNOWN_TASK',
      `未知 task ${existingEvent.task_id}`,
    );
    exactHistoricalResourceAuthority(
      taskState,
      existingEvent.captain_authority,
      options.captainCapabilityFile,
      loaded.snapshot,
    );
    exactHistoricalResourceAuthority(
      taskState,
      existingEvent.foreman_authority,
      options.foremanCapabilityFile,
      loaded.snapshot,
    );
    return { existingEvent };
  }

  const loaded = loadGoalStateUnlocked(
    root,
    options.goalId,
    {
      repairHeads: false,
      repairBootstrapConsumption: false,
      allowIncompleteRecoveryRead: true,
      allowIncompleteGoalOperationRead: true,
    },
  );
  const taskState = loaded.snapshot.tasks[options.taskId];
  assertControl(
    taskState,
    'UNKNOWN_TASK',
    `未知 task ${options.taskId}`,
  );
  const captain = resourceAuthorityFromCapability(
    taskState,
    loaded.snapshot,
    options.captainCapabilityFile,
    'CAPTAIN',
    options.captainThreadId || null,
  );
  const foreman = resourceAuthorityFromCapability(
    taskState,
    loaded.snapshot,
    options.foremanCapabilityFile,
    'FOREMAN',
    options.foremanThreadId || null,
  );
  const successor = taskState.sessions.DEV;
  assertControl(
    successor
      && successor.thread_id === options.successorThreadId
      && successor.recovered_from
      && successor.recovery_handoff
      && successor.recovery_handoff.event_id === options.handoffEventId,
    'RECOVERY_HANDOFF_MISMATCH',
    'zero-runtime transaction 无法解析 exact recovered DEV handoff',
  );
  const predecessor = [...(taskState.session_history.DEV || [])]
    .reverse()
    .find((candidate) => (
      candidate.thread_id === successor.recovered_from.thread_id
        && candidate.host_id === successor.recovered_from.host_id
        && candidate.attempt === successor.recovered_from.attempt
    ));
  assertControl(
    predecessor && predecessor.status === 'lost',
    'RECOVERY_PREDECESSOR_MISSING',
    'zero-runtime transaction 缺失 exact lost DEV predecessor',
  );
  const launchFile = path.join(
    loaded.paths.dir,
    'launches',
    options.taskId,
    `${successor.recovery_handoff.predecessor_launch_id}.json`,
  );
  const { validateLaunchManifest } = require('./validation');
  const launch = validateLaunchManifest(
    readJson(launchFile, 'predecessor launch'),
  );
  const launchSha256 = hashFile(launchFile);
  assertControl(
    launchSha256
      === normalizeHash(
        successor.recovery_handoff.predecessor_launch_sha256,
      ),
    'LAUNCH_HASH_MISMATCH',
    'predecessor launch digest 与 handoff 不一致',
  );
  return {
    captain,
    foreman,
    successor,
    predecessor,
    launch,
    launchSha256,
  };
}

function reinitializeZeroRuntimeLeases(cwd, options) {
  const root = controlRoot(cwd);
  safeId(options.goalId, 'goal');
  safeId(options.taskId, 'task');
  safeId(options.successorThreadId, 'successor thread');
  safeId(options.handoffEventId, 'handoff event');
  safeId(options.eventId, 'resource reinitialize event');
  let boundary = null;
  let transactionBoundary = null;
  return withLock(root, () => {
    const { paths, state } = rebuildUnlocked(root);
    if (boundary.existingEvent) {
      const existing = resourceEventById(paths, options.eventId);
      assertControl(existing, 'CORRUPT_STORE', `zero-runtime receipt ${options.eventId} 消失`);
      assertZeroRuntimeRetryRequest(existing, options);
      return zeroRuntimeReceipt(existing, true);
    }
    assertNoPendingTaskMutation(root, options.goalId, options.taskId);
    const lostOwner = actorIdentity(
      boundary.predecessor,
      options.goalId,
      options.taskId,
    );
    const nonTerminalOwned = Object.values(state.leases).filter((lease) => (
      !TERMINAL.has(lease.status)
        && hashObject(lease.owner) === hashObject(lostOwner)
    ));
    assertControl(
      nonTerminalOwned.length === 0,
      'REINITIALIZE_REQUIRES_BROKER',
      'lost actor 仍有非终态 lease；内建控制器不能证明对应运行时已停止，必须外部 broker',
    );
    const eventFile = appendEvent(paths, state, {
      schema_version: 1,
      event_id: options.eventId,
      type: 'ZERO_RUNTIME_REINITIALIZED',
      accepted_at: nowIso(),
      actor: actorIdentity(
        boundary.captain,
        options.goalId,
        options.taskId,
      ),
      goal_id: options.goalId,
      task_id: options.taskId,
      handoff_event_id: options.handoffEventId,
      predecessor: sessionBinding(boundary.predecessor),
      successor: sessionBinding(boundary.successor),
      predecessor_launch_id: boundary.launch.launch_id,
      predecessor_launch_sha256: boundary.launchSha256,
      captain_authority: authorityIdentity(boundary.captain),
      foreman_authority: authorityIdentity(boundary.foreman),
      leases: [],
    });
    writeProjection(paths, state);
    const sealed = readResourceJson(eventFile, 'zero-runtime receipt');
    const response = zeroRuntimeReceipt(sealed, false);
    maybeFaultAfterResourceCommit('ZERO_RUNTIME_REINITIALIZED');
    return response;
  }, {
    beforeGeneration: (transaction) => {
      const paths = resourcePaths(root);
      const existingEvent = resourceEventById(paths, options.eventId);
      if (existingEvent) {
        assertControl(
          existingEvent.type === 'ZERO_RUNTIME_REINITIALIZED',
          'RESOURCE_EVENT_ID_CONFLICT',
          `resource event id ${options.eventId} 已绑定不同 operation`,
        );
        assertZeroRuntimeRetryRequest(existingEvent, options);
        const loaded = loadGoalStateUnlocked(
          root,
          existingEvent.goal_id,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const taskState = loaded.snapshot.tasks[existingEvent.task_id];
        assertControl(taskState, 'UNKNOWN_TASK', `未知 task ${existingEvent.task_id}`);
        exactHistoricalResourceAuthority(
          taskState,
          existingEvent.captain_authority,
          options.captainCapabilityFile,
          loaded.snapshot,
        );
        exactHistoricalResourceAuthority(
          taskState,
          existingEvent.foreman_authority,
          options.foremanCapabilityFile,
          loaded.snapshot,
        );
        boundary = { existingEvent };
        return;
      }

      if (isOddTransactionRetry(transaction.mode)) {
        assertPristinePayloadUnchanged(transaction);
      }
      const loaded = loadGoalStateUnlocked(
        root,
        options.goalId,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const taskState = loaded.snapshot.tasks[options.taskId];
      assertControl(taskState, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
      assertControl(
        taskState.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${options.taskId} 已 ARCHIVED，禁止创建 zero-runtime receipt`,
      );
      const currentCaptain = taskState.sessions.CAPTAIN;
      const currentForeman = taskState.sessions.FOREMAN;
      if (isHistoricalTransactionRetry(transaction.mode)) {
        assertControl(
          currentCaptain && currentForeman,
          'CAPABILITY_INVALID',
          'zero-runtime pristine recovery 缺 current CAPTAIN/FOREMAN anchor',
        );
      }
      const captain = isHistoricalTransactionRetry(transaction.mode)
        ? assertHistoricalAuthorityUsableAt(
          exactHistoricalResourceAuthority(
            taskState,
            authorityIdentity(currentCaptain),
            options.captainCapabilityFile,
            loaded.snapshot,
          ),
          transaction.transaction_started_at,
        )
        : authorizeSession(
          taskState,
          options.captainCapabilityFile,
          {
            role: 'CAPTAIN',
            threadId: options.captainThreadId || null,
          },
        );
      const foreman = isHistoricalTransactionRetry(transaction.mode)
        ? assertHistoricalAuthorityUsableAt(
          exactHistoricalResourceAuthority(
            taskState,
            authorityIdentity(currentForeman),
            options.foremanCapabilityFile,
            loaded.snapshot,
          ),
          transaction.transaction_started_at,
        )
        : authorizeGoalSession(
          loaded.snapshot,
          options.foremanCapabilityFile,
          {
            role: 'FOREMAN',
            threadId: options.foremanThreadId || null,
          },
        );
      if (!isHistoricalTransactionRetry(transaction.mode)) {
        assertFrozenInputs(cwd, loaded, options.taskId);
      }
      const successor = taskState.sessions.DEV;
      assertControl(
        successor && ['active', 'idle'].includes(successor.status),
        'SUCCESSOR_NOT_REGISTERED',
        '当前没有 active DEV successor',
      );
      assertControl(
        successor.thread_id === options.successorThreadId,
        'SUCCESSOR_NOT_REGISTERED',
        'successor thread 与当前 DEV 不一致',
      );
      assertControl(
        successor.recovered_from && successor.recovery_handoff,
        'RECOVERY_HANDOFF_REQUIRED',
        'zero-runtime reinitialize 只适用于已绑定 handoff 的 recovered DEV',
      );
      assertControl(
        successor.operational_scope === 'PREFLIGHT_ONLY',
        'RECOVERY_SCOPE_VIOLATION',
        `DEV scope=${successor.operational_scope}`,
      );
      assertControl(
        successor.recovery_handoff.event_id === options.handoffEventId,
        'RECOVERY_HANDOFF_MISMATCH',
        'handoff event 不匹配',
      );
      assertControl(
        !taskState.recovery
          && (!taskState.recovery_backlog
            || taskState.recovery_backlog.length === 0),
        'RECOVERY_REQUIRED',
        'role recovery 尚未闭合',
      );
      const predecessor = [...(taskState.session_history.DEV || [])]
        .reverse()
        .find((candidate) => (
          candidate.thread_id === successor.recovered_from.thread_id
            && candidate.host_id === successor.recovered_from.host_id
            && candidate.attempt === successor.recovered_from.attempt
        ));
      assertControl(
        predecessor && predecessor.status === 'lost',
        'RECOVERY_PREDECESSOR_MISSING',
        '缺失 exact lost DEV predecessor',
      );
      const launchFile = path.join(
        loaded.paths.dir,
        'launches',
        options.taskId,
        `${successor.recovery_handoff.predecessor_launch_id}.json`,
      );
      const { validateLaunchManifest } = require('./validation');
      const launch = validateLaunchManifest(
        readJson(launchFile, 'predecessor launch'),
      );
      const launchSha256 = hashFile(launchFile);
      assertControl(
        launchSha256
          === normalizeHash(
            successor.recovery_handoff.predecessor_launch_sha256,
          ),
        'LAUNCH_HASH_MISMATCH',
        'predecessor launch digest 与 handoff 不一致',
      );
      assertControl(
        launch.goal_id === options.goalId
          && launch.task_id === options.taskId
          && launch.role === 'DEV'
          && launch.thread.id === predecessor.thread_id
          && launch.thread.host_id === predecessor.host_id
          && launch.launch_id === predecessor.launch_id,
        'LAUNCH_IDENTITY_MISMATCH',
        'predecessor launch identity 与 lost DEV 不一致',
      );
      assertControl(
        launch.execution.environment === 'none'
          && launch.execution.write_mode === 'NONE'
          && launch.execution.target.kind === 'NONE',
        'REINITIALIZE_REQUIRES_BROKER',
        '只有 sealed target=NONE/environment=none/write_mode=NONE 才可能走内建 no-op；其它资源必须外部 broker',
      );
      assertControl(
        launch.resource_leases.length === 0,
        'REINITIALIZE_REQUIRES_BROKER',
        'target=NONE 只是声明，不能证明旧 actor 未消费 lease；非空 lease set 必须由按资源类型机械隔离的外部 broker 处理',
      );
      const { state: resources } = rebuildUnlocked(
        root,
        { repairHeads: false },
      );
      const lostOwner = actorIdentity(
        predecessor,
        options.goalId,
        options.taskId,
      );
      const nonTerminalOwned = Object.values(resources.leases).filter(
        (lease) => (
          !TERMINAL.has(lease.status)
            && hashObject(lease.owner) === hashObject(lostOwner)
        ),
      );
      assertControl(
        nonTerminalOwned.length === 0,
        'REINITIALIZE_REQUIRES_BROKER',
        'lost actor 仍有非终态 lease；内建控制器不能证明对应运行时已停止，必须外部 broker',
      );
      boundary = {
        captain,
        foreman,
        successor,
        predecessor,
        launch,
        launchSha256,
        pristineResume: isOddTransactionRetry(transaction.mode),
      };
      assertControl(
        transactionBoundary
          && hashObject(
            zeroRuntimeTransactionRequest(options, transactionBoundary),
          ) === hashObject(
            zeroRuntimeTransactionRequest(options, boundary),
          ),
        'STORE_TRANSACTION_PREFLIGHT_MUTATED',
        'zero-runtime transaction boundary 在 key resolution 与 authorization 间漂移',
      );
      if (boundary.pristineResume) {
        const request = zeroRuntimeTransactionRequest(options, boundary);
        assertExactPristineBoundary(
          transaction,
          canonicalTransactionKey(
            'ZERO_RUNTIME',
            {
              goal_id: request.goal_id,
              task_id: request.task_id,
            },
            request.event_id,
            hashObject(request),
          ),
        );
      }
    },
    authorizeOddRecovery: () => Boolean(
      boundary && boundary.existingEvent,
    ),
    authorizePristineOddRecovery: () => Boolean(
      boundary && boundary.pristineResume,
    ),
    transactionKey: () => {
      transactionBoundary = zeroRuntimeStructuralBoundary(root, options);
      const request = zeroRuntimeTransactionRequest(
        options,
        transactionBoundary,
      );
      return canonicalTransactionKey(
        'ZERO_RUNTIME',
        {
          goal_id: request.goal_id,
          task_id: request.task_id,
        },
        request.event_id,
        hashObject(request),
      );
    },
    sameStableOperationMismatchCode: 'RESOURCE_EVENT_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      'zero-runtime resource event id 已绑定不同 request',
    afterGenerationBeforeCallback: resourceGenerationBoundaryFaultHook(
      cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_ZERO_RUNTIME_GENERATION',
    ),
  });
}

function resourceIncidentIds(operationId) {
  const stableOperationId = safeId(operationId, 'resource verify event');
  const operationDigest = sha256(stableOperationId).slice(0, 32);
  return {
    stableOperationId,
    evidenceId: `resource-identity-${operationDigest}`,
    incidentEventId: `resource-identity-hold-${operationDigest}`,
    holdId: `resource-hold-${operationDigest}`,
  };
}

function resourceVerifyRequest(options) {
  const eventId = safeId(options.eventId, 'resource verify event');
  const leaseId = safeId(options.leaseId, 'lease');
  const ownerCapability = readCapabilityFile(options.ownerCapabilityFile);
  return {
    schema_version: 1,
    operation_id: eventId,
    lease_id: leaseId,
    resource: options.resource || null,
    owner_capability_file: ownerCapability.file,
    owner_capability_sha256: ownerCapability.sha256,
  };
}

function resourceIdentitySource(registered, request, ids) {
  const source = registered.evidence.uri.startsWith('file:')
    ? readJson(
      fileURLToPath(registered.evidence.uri),
      'resource identity incident source',
    )
    : null;
  assertControl(
    registered.evidence.kind === 'HOLD_ASSERTION'
      && registered.evidence.stage === 'RESOURCE_VERIFY'
      && registered.evidence.status === 'BLOCKED'
      && source
      && source.kind === 'RESOURCE_IDENTITY_INCIDENT'
      && hashObject(source.request) === hashObject(request)
      && source.failure
      && typeof source.failure.code === 'string'
      && typeof source.failure.message === 'string'
      && source.incident_event
      && source.incident_event.event_id === ids.incidentEventId
      && source.incident_event.payload
      && source.incident_event.payload.hold_id === ids.holdId
      && source.incident_event.payload.evidence_id === ids.evidenceId
      && source.event_authority
      && source.event_authority.evidence_id === ids.evidenceId
      && source.event_authority.event_id === ids.incidentEventId
      && source.event_authority.event_input_sha256
        === hashObject(source.incident_event),
    'RESOURCE_EVENT_ID_CONFLICT',
    `resource verify event ${ids.stableOperationId} 已绑定不同 request`,
  );
  return source;
}

function assertResourceIncidentHold(accepted, ids) {
  const hold = accepted.task.holds.find((candidate) => (
    candidate.kind === 'ENV_IDENTITY_INCIDENT'
      && candidate.hold_id === ids.holdId
      && candidate.evidence
      && candidate.evidence.evidence_id === ids.evidenceId
      && candidate.evidence.kind === 'HOLD_ASSERTION'
      && candidate.evidence.stage === 'RESOURCE_VERIFY'
  ));
  assertControl(
    hold,
    'CORRUPT_STORE',
    `resource identity incident ${ids.incidentEventId} 未安装 exact hold`,
  );
  return hold;
}

function maybeFaultAfterResourceIncidentEvidence(dependencies) {
  if (typeof dependencies.afterIncidentEvidenceIngress === 'function') {
    assertIsolatedTestMode();
    dependencies.afterIncidentEvidenceIngress();
  }
  if (
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_INCIDENT_EVIDENCE !== '1'
  ) {
    return;
  }
  assertIsolatedTestMode();
  throw new ControlError(
    'TEST_FAULT_AFTER_RESOURCE_INCIDENT_EVIDENCE',
    'injected failure after durable resource incident evidence before ADD_HOLD',
  );
}

function recoverResourceIdentityIncident(
  cwd,
  request,
  actorCapabilityFile,
) {
  const root = controlRoot(cwd);
  const ids = resourceIncidentIds(request.operation_id);
  const goalsDirectory = path.join(root, 'goals');
  if (!fs.existsSync(goalsDirectory)) return null;
  let located = null;
  for (const goalId of fs.readdirSync(goalsDirectory).sort()) {
    const evidenceRoot = path.join(
      goalsDirectory,
      goalId,
      'evidence',
    );
    if (!fs.existsSync(evidenceRoot)) continue;
    for (const taskId of fs.readdirSync(evidenceRoot).sort()) {
      const candidate = path.join(evidenceRoot, taskId, `${ids.evidenceId}.json`);
      if (!fs.existsSync(candidate)) continue;
      assertControl(
        !located,
        'CORRUPT_STORE',
        `resource identity evidence ${ids.evidenceId} 在多个 task 出现`,
      );
      located = { goalId, taskId };
    }
  }
  if (!located) return null;
  let recoveryBoundary = null;
  return withLock(root, () => {
    const { registered, source } = recoveryBoundary;
    assertControl(
      source.goal_id === located.goalId
        && source.task_id === located.taskId,
      'CORRUPT_STORE',
      `resource identity evidence ${ids.evidenceId} task binding 漂移`,
    );
    const accepted = acceptEventUnderLock(
      cwd,
      source.incident_event,
      actorCapabilityFile,
      preparedIdentityIncidentAuthorization(
        ids.evidenceId,
        source.event_authority,
      ),
    );
    assertResourceIncidentHold(accepted, ids);
    return source.failure;
  }, {
    beforeGeneration: (transaction) => {
      const registered = readExistingEvidenceForRetryUnderLock(cwd, {
        goalId: located.goalId,
        taskId: located.taskId,
        evidenceId: ids.evidenceId,
        actorCapabilityFile,
      });
      const source = resourceIdentitySource(registered, request, ids);
      assertControl(
        source.goal_id === located.goalId
          && source.task_id === located.taskId,
        'CORRUPT_STORE',
        `resource identity evidence ${ids.evidenceId} task binding 漂移`,
      );
      recoveryBoundary = { registered, source };
    },
    authorizeOddRecovery: () => Boolean(recoveryBoundary),
    transactionKey: canonicalTransactionKey(
      'RESOURCE_IDENTITY_INCIDENT',
      {
        goal_id: located.goalId,
        task_id: located.taskId,
      },
      request.operation_id,
      hashObject(request),
    ),
    sameStableOperationMismatchCode: 'RESOURCE_EVENT_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      `resource verify event ${ids.stableOperationId} 已绑定不同 request`,
  });
}

function recordResourceIdentityIncident(
  cwd,
  context,
  lease,
  failure,
  actorCapabilityFile,
  request,
  dependencies = {},
) {
  const root = controlRoot(cwd);
  const ids = resourceIncidentIds(request.operation_id);
  const {
    evidenceId,
    incidentEventId,
    holdId,
  } = ids;
  const checks = [{
    name: 'resource-lease-binding',
    status: 'FAIL',
    detail: `${failure.code || 'RESOURCE_VERIFY_FAILED'}: ${failure.message}`,
  }];
  const incidentArtifacts = (
    task,
    session,
    incidentEvent,
    eventAuthority,
  ) => {
    const source = {
      schema_version: 1,
      kind: 'RESOURCE_IDENTITY_INCIDENT',
      goal_id: context.actor.goal_id,
      task_id: context.actor.task_id,
      evidence_id: evidenceId,
      request,
      failure: {
        code: failure.code || 'RESOURCE_VERIFY_FAILED',
        message: failure.message,
      },
      lease: {
        lease_id: lease.lease_id,
        resource: lease.resource,
        revision: lease.revision,
        status: lease.status,
        owner: lease.owner,
      },
      checks,
      incident_event: incidentEvent,
      event_authority: eventAuthority,
      recorded_at: eventAuthority.prepared_accepted_at,
    };
    const sourceBytes = Buffer.from(
      `${JSON.stringify(source, null, 2)}\n`,
      'utf8',
    );
    return {
      source,
      sourceBytes,
      evidence: {
        schema_version: 1,
        evidence_id: evidenceId,
        goal_id: context.actor.goal_id,
        task_id: context.actor.task_id,
        kind: 'HOLD_ASSERTION',
        stage: 'RESOURCE_VERIFY',
        status: 'BLOCKED',
        producer: {
          role: session.role,
          thread_id: session.thread_id,
          host_id: session.host_id,
        },
        state_revision: task.state_revision,
        packet: { revision: task.packet.revision, sha256: task.packet.sha256 },
        packet_sha256: task.packet.sha256,
        base_head: task.base_head,
        full_head: task.full_head,
        created_at: eventAuthority.prepared_accepted_at,
        source_sha256: `sha256:${sha256(sourceBytes)}`,
        checks,
      },
    };
  };
  let boundary = null;
  return withLock(root, () => {
    const {
      loaded,
      task,
      session,
      registered: existingRegistration,
      durableSource: existingSource,
      incidentEvent: preparedIncidentEvent,
      eventAuthority,
      artifacts,
    } = boundary;
    if (existingRegistration) {
      const accepted = acceptEventUnderLock(
        cwd,
        existingSource.incident_event,
        actorCapabilityFile,
        preparedIdentityIncidentAuthorization(
          evidenceId,
          existingSource.event_authority,
        ),
      );
      return assertResourceIncidentHold(accepted, ids);
    }
    const registered = recordEvidenceBytesUnderLock(
      cwd,
      artifacts.evidence,
      artifacts.sourceBytes,
      actorCapabilityFile,
      true,
      {
        allowEvidenceId: evidenceId,
        afterSemanticIngressPrepared:
          dependencies.afterIncidentIngressPrepared,
      },
    );
    if (!registered.idempotent) {
      maybeFaultAfterResourceIncidentEvidence(dependencies);
    }
    const accepted = acceptEventUnderLock(
      cwd,
      preparedIncidentEvent,
      actorCapabilityFile,
      preparedIdentityIncidentAuthorization(
        evidenceId,
        eventAuthority,
      ),
    );
    return assertResourceIncidentHold(accepted, ids);
  }, {
    beforeGeneration: (transaction) => {
      const loaded = loadGoalStateUnlocked(
        root,
        context.actor.goal_id,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const task = loaded.snapshot.tasks[context.actor.task_id];
      assertControl(task, 'UNKNOWN_TASK', `未知 task ${context.actor.task_id}`);
      const registryFile = path.join(
        root,
        'goals',
        context.actor.goal_id,
        'evidence',
        context.actor.task_id,
        `${evidenceId}.json`,
      );
      if (fs.existsSync(registryFile)) {
        const registered = readExistingEvidenceForRetryUnderLock(cwd, {
          goalId: context.actor.goal_id,
          taskId: context.actor.task_id,
          evidenceId,
          actorCapabilityFile,
        });
        const durableSource = resourceIdentitySource(
          registered,
          request,
          ids,
        );
        boundary = {
          loaded,
          task,
          session: registered.session,
          registered,
          durableSource,
          incidentEvent: durableSource.incident_event,
          eventAuthority: durableSource.event_authority,
        };
        return;
      }
      assertControl(
        task.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${task.task_id} 已 ARCHIVED，不得追加 resource identity incident`,
      );
      assertFrozenInputs(cwd, loaded, context.actor.task_id);
      const existing = task.holds.some(
        (hold) => (
          hold.kind === 'ENV_IDENTITY_INCIDENT'
            && hold.hold_id === holdId
            && hold.evidence
            && hold.evidence.evidence_id === evidenceId
            && hold.evidence.kind === 'HOLD_ASSERTION'
            && hold.evidence.stage === 'RESOURCE_VERIFY'
        ),
      );
      assertControl(
        !existing,
        'CORRUPT_STORE',
        `resource identity hold ${holdId} 引用了缺失 evidence registry`,
      );
      const session = authorizeResourceSession(
        loaded,
        task,
        actorCapabilityFile,
        {
        role: context.actor.role,
        threadId: context.actor.thread_id,
        },
      );
      const actorKey = actorSequenceKey(session);
      const incidentEvent = {
        schema_version: 1,
        event_id: incidentEventId,
        goal_id: context.actor.goal_id,
        task_id: context.actor.task_id,
        type: 'ADD_HOLD',
        actor: {
          role: session.role,
          thread_id: session.thread_id,
          host_id: session.host_id,
        },
        actor_sequence: (task.actor_sequences[actorKey] || 0) + 1,
        expected_state_revision: task.state_revision,
        control_epoch: loaded.control.epoch,
        packet: { revision: task.packet.revision, sha256: task.packet.sha256 },
        base_head: task.base_head,
        full_head: task.full_head,
        payload: {
          kind: 'ENV_IDENTITY_INCIDENT',
          hold_id: holdId,
          reason: `${failure.code || 'RESOURCE_VERIFY_FAILED'} on ${lease.resource}`,
          evidence_id: evidenceId,
        },
      };
      const eventAuthority = sealIdentityIncidentEventAuthority({
        event: incidentEvent,
        evidenceId,
        session,
        task,
        controlEpoch: loaded.control.epoch,
        preparedAcceptedAt: transaction.transaction_started_at,
      });
      const artifacts = incidentArtifacts(
        task,
        session,
        incidentEvent,
        eventAuthority,
      );
      const preparedFile = semanticIngressPreparedFile(
        root,
        context.actor.goal_id,
        context.actor.task_id,
        evidenceId,
      );
      let preparedRegistration = null;
      if (fs.existsSync(preparedFile)) {
        preparedRegistration = inspectPreparedEvidenceBytesForRetryUnderLock(
          cwd,
          artifacts.evidence,
          artifacts.sourceBytes,
          actorCapabilityFile,
          true,
        );
      }
      boundary = {
        loaded,
        task,
        session,
        registered: null,
        durableSource: null,
        incidentEvent,
        eventAuthority,
        artifacts,
        preparedRegistration,
      };
    },
    authorizeOddRecovery: () => Boolean(
      boundary
        && (boundary.registered || boundary.preparedRegistration),
    ),
    transactionKey: canonicalTransactionKey(
      'RESOURCE_IDENTITY_INCIDENT',
      {
        goal_id: context.actor.goal_id,
        task_id: context.actor.task_id,
      },
      request.operation_id,
      hashObject(request),
    ),
    sameStableOperationMismatchCode: 'RESOURCE_EVENT_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      `resource verify event ${ids.stableOperationId} 已绑定不同 request`,
  });
}

function verifyLease(cwd, options, dependencies = {}) {
  const request = resourceVerifyRequest(options);
  const recoveredFailure = recoverResourceIdentityIncident(
    cwd,
    request,
    options.actorCapabilityFile,
  );
  if (recoveredFailure) {
    throw new ControlError(recoveredFailure.code, recoveredFailure.message);
  }
  const root = controlRoot(cwd);
  const current = lookupLease(cwd, options.leaseId);
  let context;
  try {
    context = actorContext(
      cwd,
      current.owner.goal_id,
      current.owner.task_id,
      options.actorCapabilityFile,
      {
        role: current.owner.role,
        threadId: current.owner.thread_id,
        hostId: current.owner.host_id,
      },
      { forbidHardHold: true },
    );
  } catch (error) {
    const racedFailure = recoverResourceIdentityIncident(
      cwd,
      request,
      options.actorCapabilityFile,
    );
    if (racedFailure) {
      throw new ControlError(racedFailure.code, racedFailure.message);
    }
    throw error;
  }
  assertResourceOperationalScope(context.state, current.owner.role, 'RESOURCE_USE');
  if (typeof dependencies.beforeStableRead === 'function') {
    assertIsolatedTestMode();
    dependencies.beforeStableRead();
  }
  try {
    return withStableRead(root, () => {
      const { state } = rebuildUnlocked(root, { repairHeads: false });
      assertActorContextFresh(root, context);
      const lease = state.leases[options.leaseId];
      const now = currentTimeMilliseconds();
      assertControl(lease, 'LEASE_NOT_FOUND', `找不到 lease: ${options.leaseId}`);
      assertControl(lease.status === ACTIVE, 'LEASE_NOT_ACTIVE', `lease 已是 ${lease.status}`);
      assertControl(Date.parse(lease.expires_at) > now, 'LEASE_EXPIRED', `lease 已于 ${lease.expires_at} 过期`);
      assertOwnerCapability(lease, options.ownerCapabilityFile);
      if (options.resource) assertControl(lease.resource === options.resource, 'LEASE_RESOURCE_MISMATCH', `lease resource 不是 ${options.resource}`);
      return { ...publicLease(lease, now), valid: true };
    });
  } catch (error) {
    if (error.code === 'ACTOR_STATE_CHANGED') {
      // A concurrent verifier for the same stable operation may have installed
      // the identity-incident hold after this process captured actor context.
      // Recover that durable operation before surfacing the generic CAS race,
      // so every participant receives the original mechanical failure and no
      // caller is tempted to start a second incident with a new event id.
      const racedFailure = recoverResourceIdentityIncident(
        cwd,
        request,
        options.actorCapabilityFile,
      );
      if (racedFailure) {
        throw new ControlError(racedFailure.code, racedFailure.message);
      }
    }
    const incidentCodes = new Set(['LEASE_NOT_ACTIVE', 'LEASE_EXPIRED', 'LEASE_OWNER_MISMATCH', 'LEASE_RESOURCE_MISMATCH']);
    if (incidentCodes.has(error.code)) {
      if (typeof dependencies.beforeIncidentCommit === 'function') {
        assertIsolatedTestMode();
        dependencies.beforeIncidentCommit();
      }
      recordResourceIdentityIncident(
        cwd,
        context,
        current,
        error,
        options.actorCapabilityFile,
        request,
        dependencies,
      );
    }
    throw error;
  }
}

function recoverOwnerCapability(cwd, options) {
  const root = controlRoot(cwd);
  const lease = lookupLease(cwd, options.leaseId);
  const context = actorContext(
    cwd,
    lease.owner.goal_id,
    lease.owner.task_id,
    options.actorCapabilityFile,
    {
      role: lease.owner.role,
      threadId: lease.owner.thread_id,
      hostId: lease.owner.host_id,
    },
    {
      allowTerminal: true,
    },
  );
  assertResourceOperationalScope(context.state, lease.owner.role, 'CLEANUP');
  return withStableRead(root, () => {
    const { state } = rebuildUnlocked(root, { repairHeads: false });
    assertActorContextFresh(root, context, { allowTerminal: true });
    const current = state.leases[options.leaseId];
    assertControl(current, 'LEASE_NOT_FOUND', `找不到 lease: ${options.leaseId}`);
    assertControl(
      current.status === ACTIVE,
      'LEASE_NOT_ACTIVE',
      `lease 已是 ${current.status}`,
    );
    assertControl(
      hashObject(current.owner) === hashObject(context.actor),
      'LEASE_OWNER_MISMATCH',
      'actor 不是 active lease 的 exact owner',
    );
    const disclosureBoundary = assertOwnerCapabilityDisclosureBoundary(
      context.state,
      state,
      current,
      currentTimeMilliseconds(),
    );
    if (disclosureBoundary) {
      assertExactLeaseAcquisitionAuthority(
        resourcePaths(root),
        current,
        context.authorized_session,
      );
    }
    const capability = readCapabilityFile(
      current.owner_capability_file,
      current.owner_capability_file,
    );
    assertControl(
      hashesEqual(capability.sha256, current.owner_capability_sha256),
      'CORRUPT_STORE',
      'owner capability verifier 不匹配',
    );
    return {
      lease_id: current.lease_id,
      revision: current.revision,
      owner_capability_file: capability.file,
    };
  });
}

function verifyLeaseBinding(cwd, leaseId, expectedOwner) {
  const root = controlRoot(cwd);
  const loaded = loadGoalStateReadOnly(cwd, expectedOwner.goal_id);
  const taskState = loaded.snapshot.tasks[expectedOwner.task_id];
  assertControl(taskState, 'UNKNOWN_TASK', `未知 task ${expectedOwner.task_id}`);
  assertNoHardHold(taskState);
  const context = {
    actor: { goal_id: expectedOwner.goal_id, task_id: expectedOwner.task_id },
    control_epoch: loaded.control.epoch,
    control_event_count: loaded.control.eventCount,
    control_event_sha256: loaded.control.lastEventHash,
    event_count: taskState.state_revision,
    last_event_sha256: loaded.lastEventHashes[expectedOwner.task_id] || null,
    state: taskState,
  };
  return withStableRead(root, () => {
    const { state } = rebuildUnlocked(root, { repairHeads: false });
    const head = readJsonIfExists(
      path.join(root, 'goals', expectedOwner.goal_id, 'event-heads', `${expectedOwner.task_id}.json`),
      null
    );
    assertControl(head && head.event_count === context.event_count && head.last_event_sha256 === context.last_event_sha256, 'ACTOR_STATE_CHANGED', 'task state 在 lease binding 验证前已变化，请重试');
    const controlHead = readJsonIfExists(path.join(root, 'goals', expectedOwner.goal_id, 'control-head.json'), null);
    assertControl(
      controlHead
        && controlHead.control_epoch === context.control_epoch
        && controlHead.event_count === context.control_event_count
        && controlHead.last_event_sha256 === context.control_event_sha256,
      'ACTOR_STATE_CHANGED',
      'control epoch 在 lease binding 验证前已变化，请重试'
    );
    const lease = state.leases[leaseId];
    const now = currentTimeMilliseconds();
    assertControl(lease, 'LEASE_NOT_FOUND', `找不到 lease: ${leaseId}`);
    assertControl(lease.status === ACTIVE, 'LEASE_NOT_ACTIVE', `lease 已是 ${lease.status}`);
    assertControl(Date.parse(lease.expires_at) > now, 'LEASE_EXPIRED', `lease 已于 ${lease.expires_at} 过期`);
    for (const [field, value] of Object.entries(expectedOwner)) {
      assertControl(lease.owner[field] === value, 'LEASE_OWNER_MISMATCH', `lease owner.${field} 与 launch 不一致`);
    }
    return publicLease(lease, now);
  });
}

function verifyLeaseBindingUnlocked(root, leaseId, expectedOwner, taskState) {
  assertControl(taskState, 'UNKNOWN_TASK', `未知 task ${expectedOwner.task_id}`);
  assertNoHardHold(taskState);
  const { state } = rebuildUnlocked(root, { repairHeads: false });
  const lease = state.leases[leaseId];
  const now = currentTimeMilliseconds();
  assertControl(lease, 'LEASE_NOT_FOUND', `找不到 lease: ${leaseId}`);
  assertControl(lease.status === ACTIVE, 'LEASE_NOT_ACTIVE', `lease 已是 ${lease.status}`);
  assertControl(Date.parse(lease.expires_at) > now, 'LEASE_EXPIRED', `lease 已于 ${lease.expires_at} 过期`);
  for (const [field, value] of Object.entries(expectedOwner)) {
    assertControl(lease.owner[field] === value, 'LEASE_OWNER_MISMATCH', `lease owner.${field} 与 launch 不一致`);
  }
  return publicLease(lease, now);
}

function verifyLaunchResourceRequirementsUnlocked(root, manifestTask, launch, taskState, options = {}) {
  assertControl(manifestTask && manifestTask.id === launch.task_id, 'UNKNOWN_TASK', `未知 task ${launch.task_id}`);
  assertControl(taskState && taskState.task_id === launch.task_id, 'UNKNOWN_TASK', `未知 task ${launch.task_id}`);
  if (options.historical !== true) {
    if (options.allowRuntimeRotationHold === true) {
      const session = taskState.sessions
        && taskState.sessions[launch.role];
      assertControl(
        taskState.holds.length === 1
          && taskState.holds[0].kind === 'ENV_IDENTITY_INCIDENT'
          && taskState.holds[0].hard === true
          && session
          && session.last_runtime_rotation
          && session.last_runtime_rotation.hold_id
            === taskState.holds[0].hold_id
          && session.last_runtime_rotation.successor_launch_id
            === launch.launch_id
          && session.launch_id === launch.launch_id,
        'RUNTIME_ROTATION_HOLD_MISMATCH',
        '只允许 active runtime rotation successor 在精确 ENV identity hold 下验证既有 leases',
      );
    } else {
      assertNoHardHold(taskState);
    }
  }
  const { state } = rebuildUnlocked(root, options);
  const now = currentTimeMilliseconds();
  const expectedOwner = {
    goal_id: launch.goal_id,
    task_id: launch.task_id,
    role: launch.role,
    thread_id: launch.thread.id,
    host_id: launch.thread.host_id || 'local',
  };
  const expectedKey = (requirement) => `${RESOURCE_KIND_PREFIX[requirement.kind]}:${requirement.id}`;
  const requirements = (manifestTask.resource_requirements || [])
    .filter((requirement) => requirementAppliesToRole(requirement, launch.role));
  assertControl(
    launch.resource_leases.length === requirements.length,
    'RESOURCE_REQUIREMENT_MISSING',
    `launch lease 数量 ${launch.resource_leases.length} 与 manifest 要求 ${requirements.length} 不一致`,
  );
  const leases = launch.resource_leases.map((leaseId) => {
    const lease = state.leases[leaseId];
    assertControl(lease, 'LEASE_NOT_FOUND', `找不到 lease: ${leaseId}`);
    if (options.historical !== true) {
      assertControl(lease.status === ACTIVE, 'LEASE_NOT_ACTIVE', `lease 已是 ${lease.status}`);
      assertControl(Date.parse(lease.expires_at) > now, 'LEASE_EXPIRED', `lease 已于 ${lease.expires_at} 过期`);
    } else {
      assertControl(
        Number.isSafeInteger(lease.revision)
          && lease.revision > 0
          && typeof lease.acquired_at === 'string'
          && Number.isFinite(Date.parse(lease.acquired_at))
          && typeof lease.expires_at === 'string'
          && Number.isFinite(Date.parse(lease.expires_at))
          && typeof lease.resource === 'string'
          && ['EXCLUSIVE', 'SHARED_READ'].includes(lease.access),
        'CORRUPT_STORE',
        `historical lease ${leaseId} 结构非法`,
      );
    }
    for (const [field, value] of Object.entries(expectedOwner)) {
      assertControl(lease.owner[field] === value, 'LEASE_OWNER_MISMATCH', `lease owner.${field} 与 launch 不一致`);
    }
    return options.historical === true ? lease : publicLease(lease, now);
  });
  for (const requirement of requirements) {
    const matches = leases.filter((lease) => (
      lease.resource === expectedKey(requirement)
      && lease.access === requirement.access
    ));
    assertControl(
      matches.length === 1,
      'RESOURCE_REQUIREMENT_MISSING',
      `缺少唯一资源租约 ${requirement.kind}:${requirement.id}`,
    );
  }
  for (const lease of leases) {
    const declared = requirements.some((requirement) => (
      lease.resource === expectedKey(requirement)
      && lease.access === requirement.access
    ));
    assertControl(declared, 'RESOURCE_NOT_DECLARED', `launch 携带未声明 lease ${lease.resource}`);
  }
  return leases;
}

function verifyLaunchResourceRequirements(cwd, manifestTask, launch, taskState, options = {}) {
  const root = controlRoot(cwd);
  return withStableRead(root, () => verifyLaunchResourceRequirementsUnlocked(
    root,
    manifestTask,
    launch,
    taskState,
    { ...options, repairHeads: false },
  ));
}

function verifyLaunchResourceRequirementsReadOnly(cwd, manifestTask, launch, taskState, options = {}) {
  const root = controlRoot(cwd);
  return withStableRead(root, () => verifyLaunchResourceRequirementsUnlocked(
    root,
    manifestTask,
    launch,
    taskState,
    { ...options, repairHeads: false },
  ));
}

function listLeases(cwd, filters = {}) {
  const root = controlRoot(cwd);
  return withStableRead(root, () => {
    const { state } = rebuildUnlocked(root, { repairHeads: false });
    const now = currentTimeMilliseconds();
    const leases = Object.values(state.leases)
      .map((lease) => publicLease(lease, now))
      .filter((lease) => !filters.goalId || lease.owner.goal_id === filters.goalId)
      .filter((lease) => !filters.taskId || lease.owner.task_id === filters.taskId)
      .filter((lease) => !filters.resource || lease.resource === filters.resource);
    return { schema_version: 1, generated_at: new Date(now).toISOString(), leases };
  });
}

function doctorResources(cwd) {
  const listed = listLeases(cwd);
  const findings = listed.leases
    .filter((lease) => lease.status === 'EXPIRED')
    .map((lease) => ({ severity: 'ERROR', code: 'STALE_RESOURCE_LEASE', lease_id: lease.lease_id, resource: lease.resource, expires_at: lease.expires_at }));
  for (const lease of listed.leases.filter((candidate) => candidate.status === UNVERIFIED_REVOKE)) {
    findings.push({
      severity: 'ERROR',
      code: 'RESOURCE_BROKER_REPAIR_REQUIRED',
      lease_id: lease.lease_id,
      resource: lease.resource,
      detail: '历史 LEASE_SET_REVOKED 没有资源专用 host fence，资源保持隔离且不可复用',
    });
  }
  return { healthy: findings.length === 0, checked_at: listed.generated_at, findings };
}

function nonTerminalTaskLeasesUnlocked(root, goalId, taskId) {
  const { state } = rebuildUnlocked(root, { repairHeads: false });
  return Object.values(state.leases).filter((lease) => (
    !TERMINAL.has(lease.status)
      && lease.owner.goal_id === goalId
      && lease.owner.task_id === taskId
  ));
}

module.exports = {
  MAX_RESOURCE_TTL_MS,
  RESOURCE_RENEWAL_MAX_LEAD_MS,
  WORKER_RESOURCE_ROLES,
  acquireLease,
  currentTimeMilliseconds,
  doctorResources,
  listLeases,
  nonTerminalTaskLeasesUnlocked,
  rebuildResourcesReadOnlyUnlocked,
  reapLease,
  reinitializeZeroRuntimeLeases,
  recoverOwnerCapability,
  releaseLease,
  resourceRenewalEventId,
  resourceRenewalPolicy,
  assertOwnerCapabilityDisclosureBoundary,
  renewLease,
  verifyLease,
  verifyLeaseBinding,
  verifyLeaseBindingUnlocked,
  verifyLaunchResourceRequirements,
  verifyLaunchResourceRequirementsReadOnly,
  verifyLaunchResourceRequirementsUnlocked,
};
