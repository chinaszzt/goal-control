'use strict';

const { assertControl } = require('./errors');
const { MAX_ROLE_LEASE_MS } = require('./auth');
const { assertFullSha, hashObject, normalizeHash, nowIso } = require('./util');
const {
  HARD_HOLDS,
  HOLD_KINDS,
  ROLES,
  validateDevEvidence,
  validateSingleEvidence,
} = require('./validation');

const TRANSITIONS = Object.freeze({
  START_P1: { from: ['QUEUED'], to: 'P1_ACTIVE', roles: ['CAPTAIN'] },
  P1_READY: { from: ['P1_ACTIVE'], to: 'P1_READY', roles: ['CAPTAIN'] },
  P1_APPROVED: { from: ['P1_READY'], to: 'P1_APPROVED', roles: ['FOREMAN'] },
  P1_COMMITTED: { from: ['P1_APPROVED'], to: 'P1_COMMITTED', roles: ['CAPTAIN'], updatesHead: true },
  P1_RESTARTED: { from: ['P1_ACTIVE', 'P1_READY', 'P1_APPROVED'], to: 'QUEUED', roles: ['FOREMAN'] },
  LAUNCH_DEV: { from: ['P1_COMMITTED'], to: 'DEV_ACTIVE', roles: ['CAPTAIN'] },
  DEV_READY: { from: ['DEV_ACTIVE'], to: 'DEV_READY', roles: ['DEV'], updatesHead: true },
  LAUNCH_REVIEW: { from: ['DEV_READY'], to: 'REVIEW_ACTIVE', roles: ['CAPTAIN'] },
  REVIEW_REWORK: { from: ['REVIEW_ACTIVE'], to: 'DEV_ACTIVE', roles: ['REVIEW'] },
  REVIEW_PASS: { from: ['REVIEW_ACTIVE'], to: 'REVIEW_PASS', roles: ['REVIEW'] },
  LAUNCH_RECEIPT: { from: ['REVIEW_PASS'], to: 'RECEIPT_ACTIVE', roles: ['CAPTAIN'] },
  RECEIPT_FAIL: { from: ['RECEIPT_ACTIVE'], to: 'RECEIPT_FAILED', roles: ['RECEIPT'] },
  REOPEN_DEV: { from: ['RECEIPT_FAILED'], to: 'DEV_ACTIVE', roles: ['CAPTAIN'] },
  REOPEN_REVIEW: { from: ['RECEIPT_FAILED'], to: 'REVIEW_ACTIVE', roles: ['CAPTAIN'] },
  RECEIPT_PASS: { from: ['RECEIPT_ACTIVE'], to: 'RECEIPT_PASS', roles: ['RECEIPT'] },
  READY_FOR_MERGE: { from: ['RECEIPT_PASS'], to: 'ACCEPTED_PENDING_MERGE', roles: ['CAPTAIN'] },
  TASK_REOPEN: { from: ['ACCEPTED_PENDING_MERGE'], to: 'DEV_ACTIVE', roles: ['FOREMAN'] },
  MERGED: { from: ['ACCEPTED_PENDING_MERGE'], to: 'MERGED_TO_MAIN', roles: ['FOREMAN'] },
  ARCHIVED: { from: ['MERGED_TO_MAIN'], to: 'ARCHIVED', roles: ['FOREMAN'] },
});

const EXPECTED_ACTIVE_ROLE = Object.freeze({
  P1_ACTIVE: 'CAPTAIN',
  P1_READY: 'FOREMAN',
  P1_APPROVED: 'CAPTAIN',
  P1_COMMITTED: 'CAPTAIN',
  DEV_ACTIVE: 'DEV',
  DEV_READY: 'CAPTAIN',
  REVIEW_ACTIVE: 'REVIEW',
  REVIEW_PASS: 'CAPTAIN',
  RECEIPT_ACTIVE: 'RECEIPT',
  RECEIPT_FAILED: 'CAPTAIN',
  RECEIPT_PASS: 'CAPTAIN',
  ACCEPTED_PENDING_MERGE: 'FOREMAN',
  MERGED_TO_MAIN: 'FOREMAN',
});

const NON_TRANSITION_EVENTS = new Set([
  'REGISTER_ROLE',
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
  'RECOVER_EXPIRED_FOREMAN',
  'PACKET_UPDATED',
  'P1_COMMIT_ABANDONED',
  'GITHUB_MERGE_RESERVED',
  'PROBE_OBSERVATION_REFRESHED',
]);

function initialTaskState(task, manifest, options = {}) {
  return {
    task_id: task.id,
    probe_observation_required:
      Boolean(manifest.probe_observation_receipts),
    role_identity_protocol_version:
      options.roleIdentityProtocolVersion || 1,
    phase: 'QUEUED',
    state_revision: 0,
    control_epoch: 0,
    task_cycle: 1,
    packet: { ...task.packet },
    base_head: manifest.base_head,
    full_head: manifest.base_head,
    pr: null,
    holds: [],
    sessions: {},
    session_history: {},
    actor_sequences: {},
    last_reconciled_epoch: 0,
    reconcile_required: null,
    p1: task.p1 ? { policy: JSON.parse(JSON.stringify(task.p1)) } : {},
    evidence: {},
    recovery: null,
    recovery_backlog: [],
    merge: null,
    merge_reservation: null,
    last_event: null,
  };
}

function expectedRoleForPhase(phase) {
  return EXPECTED_ACTIVE_ROLE[phase] || null;
}

function actorSequenceKey(actor) {
  return JSON.stringify([actor.role, actor.host_id, actor.thread_id]);
}

function validateCommonBinding(state, event, goalControlEpoch, options = {}) {
  assertControl(event.expected_state_revision === state.state_revision, 'STALE_STATE_REVISION', `expected state revision ${event.expected_state_revision}，当前为 ${state.state_revision}`);
  assertControl(event.control_epoch === goalControlEpoch, 'STALE_CONTROL_EPOCH', `event control epoch ${event.control_epoch}，当前为 ${goalControlEpoch}`);
  assertControl(event.packet.revision === state.packet.revision, 'STALE_PACKET', `event packet revision ${event.packet.revision}，当前为 ${state.packet.revision}`);
  assertControl(normalizeHash(event.packet.sha256) === state.packet.sha256, 'STALE_PACKET', 'event packet hash 与当前 packet 不一致');
  assertControl(event.base_head === state.base_head, 'STALE_BASE_HEAD', 'event base HEAD 与当前任务不一致');
  if (!options.updatesHead) {
    assertControl(event.full_head === state.full_head, 'STALE_HEAD', `event HEAD ${event.full_head}，当前为 ${state.full_head}`);
  }
}

function validateRegisteredActor(state, event) {
  const registered = state.sessions[event.actor.role];
  assertControl(registered, 'UNREGISTERED_ACTOR', `${event.actor.role} 尚未登记 session`);
  assertControl(registered.thread_id === event.actor.thread_id, 'WRONG_ACTOR_THREAD', `${event.actor.role} thread 与登记值不一致`);
  assertControl(registered.host_id === event.actor.host_id, 'WRONG_ACTOR_HOST', `${event.actor.role} host 与登记值不一致`);
  const restoringGoalForemanReplica = (
    event.actor.role === 'FOREMAN'
      && event.type === 'HEARTBEAT'
      && registered.status === 'systemError'
      && event.goal_foreman_authority
      && ['active', 'idle'].includes(event.payload.status || 'active')
  );
  assertControl(
    restoringGoalForemanReplica
      || !['superseded', 'lost', 'systemError', 'terminal']
        .includes(registered.status),
    'ACTOR_UNUSABLE',
    `${event.actor.role} session status=${registered.status}`,
  );
  if (event.actor.role === 'FOREMAN' && event.goal_foreman_authority) {
    const authority = event.goal_foreman_authority;
    assertControl(
      typeof authority.source_task_id === 'string'
        && authority.thread_id === registered.thread_id
        && authority.host_id === registered.host_id
        && authority.attempt === registered.attempt
        && authority.capability_file === registered.capability_file
        && authority.capability_sha256 === registered.capability_sha256
        && typeof authority.lease_until === 'string'
        && Date.parse(authority.lease_until) > Date.parse(event.accepted_at),
      'GOAL_FOREMAN_AUTHORITY_INVALID',
      'accepted FOREMAN event 缺有效 Goal replica lease anchor',
    );
  } else {
    assertControl(Date.parse(registered.lease_until) > Date.parse(event.accepted_at), 'ACTOR_LEASE_EXPIRED', `${event.actor.role} lease 已于 ${registered.lease_until} 过期`);
  }
  const key = actorSequenceKey(event.actor);
  const previous = state.actor_sequences[key] || 0;
  assertControl(event.actor_sequence === previous + 1, 'ACTOR_SEQUENCE_MISMATCH', `actor sequence 应为 ${previous + 1}，收到 ${event.actor_sequence}`);
}

function validateRecoverySuccessorLease(session, event) {
  assertControl(
    Date.parse(session.lease_until) > Date.parse(event.accepted_at),
    'SUCCESSOR_LEASE_EXPIRED',
    `successor lease 已于 ${session.lease_until} 过期`,
  );
}

function applyRegistration(state, event) {
  const role = event.payload.role || event.actor.role;
  assertControl(ROLES.includes(role), 'INVALID_ROLE', `未知角色 ${role}`);
  assertControl(typeof event.payload.thread_id === 'string' && event.payload.thread_id.length > 0, 'INVALID_REGISTRATION', 'thread_id 缺失');
  const hostId = event.payload.host_id;
  assertControl(
    typeof hostId === 'string' && hostId.length > 0,
    'INVALID_REGISTRATION',
    'host_id 缺失',
  );
  assertControl(event.actor.role === role, 'REGISTRATION_ACTOR_MISMATCH', 'REGISTER_ROLE actor 必须是目标 role');
  assertControl(event.actor.thread_id === event.payload.thread_id && event.actor.host_id === hostId, 'REGISTRATION_ACTOR_MISMATCH', 'REGISTER_ROLE actor identity 与目标不一致');
  assertControl(typeof event.payload.capability_sha256 === 'string' && /^[0-9a-f]{64}$/.test(event.payload.capability_sha256), 'INVALID_REGISTRATION', 'capability hash 缺失');
  assertControl(typeof event.payload.capability_file === 'string' && event.payload.capability_file.length > 0, 'INVALID_REGISTRATION', 'capability file 缺失');
  assertControl(event.payload.authorized_by && typeof event.payload.authorized_by === 'object', 'REGISTRATION_AUTHORITY_REQUIRED', 'REGISTER_ROLE 缺授权者');
  if (state.probe_observation_required) {
    const identity = event.payload.role_identity;
    const protocolRequired =
      state.role_identity_protocol_version >= 2;
    assertControl(
      (!protocolRequired && identity === undefined)
        || (
          identity
          && (
            protocolRequired
              ? identity.protocol
                === 'goalctl-role-identity-intent-v2'
              : [
                'goalctl-role-identity-intent-v1',
                'goalctl-role-identity-intent-v2',
              ].includes(identity.protocol)
          )
        && identity.operation_id === event.event_id
        && identity.thread_id === event.payload.thread_id
        && identity.host_id === hostId
        && identity.attempt === Number(event.payload.attempt || 1)
        && identity.launch_id === (event.payload.launch_id || null)
        ),
      'ROLE_IDENTITY_INTENT_MISMATCH',
      'probe-enabled REGISTER_ROLE 必须绑定 exact upstream role identity intent',
    );
    if (
      identity
        && identity.protocol === 'goalctl-role-identity-intent-v2'
    ) {
      assertControl(
        hashObject(event.payload.authorized_by)
            === identity.registration_authorized_by_sha256
          && event.payload.probe_observation
          && event.payload.probe_observation.binding_sha256
            === identity.probe_observation_binding_sha256
          && (
            ['DEV', 'REVIEW', 'RECEIPT'].includes(role)
              ? (
                event.payload.worker_bootstrap
                  && event.payload.worker_bootstrap.binding_sha256
                    === identity.worker_bootstrap_binding_sha256
                  && event.payload.worker_bootstrap.thread
                    === identity.thread_id
                  && event.payload.worker_bootstrap.host
                    === identity.host_id
                  && event.payload.worker_bootstrap.operation_id
                    === identity.launch_id
                  && event.payload.worker_bootstrap.head
                    === identity.full_head
              )
              : (
                event.payload.worker_bootstrap === undefined
                  && identity.worker_bootstrap_binding_sha256 === null
              )
          ),
        'ROLE_IDENTITY_INTENT_MISMATCH',
        'REGISTER_ROLE issuer/probe/bootstrap sibling 与 v2 identity authority 不一致',
      );
    }
  }
  if (['DEV', 'REVIEW', 'RECEIPT'].includes(role)) {
    assertControl(typeof event.payload.launch_id === 'string' && event.payload.launch_id.length > 0, 'LAUNCH_ID_REQUIRED', `${role} registration 缺 launch_id`);
    assertControl(typeof event.payload.task_nonce === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(event.payload.task_nonce), 'TASK_NONCE_REQUIRED', `${role} registration 缺控制面 task_nonce`);
    const registrationPhases = {
      DEV: ['P1_COMMITTED', 'DEV_ACTIVE', 'RECEIPT_FAILED'],
      REVIEW: ['DEV_READY', 'RECEIPT_FAILED'],
      RECEIPT: ['REVIEW_PASS'],
    };
    const recoveryRegistration = role === 'DEV' && state.phase === 'DEV_ACTIVE' && state.recovery && state.recovery.role === 'DEV';
    assertControl(
      registrationPhases[role].includes(state.phase) && (state.phase !== 'DEV_ACTIVE' || recoveryRegistration),
      'PREMATURE_ROLE_REGISTRATION',
      `${role} 不能在 phase=${state.phase} 提前登记`,
    );
  } else {
    assertControl(
      event.payload.worker_bootstrap === undefined,
      'WORKER_BOOTSTRAP_ROLE_INVALID',
      'worker_bootstrap 只允许 DEV/REVIEW/RECEIPT registration',
    );
  }
  const attempt = Number(event.payload.attempt || 1);
  assertControl(Number.isSafeInteger(attempt) && attempt > 0, 'INVALID_REGISTRATION', 'attempt 必须是正整数');
  const existing = state.sessions[role];
  if (existing) {
    const replacingPendingSuccessor = Boolean(
      state.recovery
        && state.recovery.role === role
        && state.recovery.successor_thread_id === existing.thread_id
        && state.recovery.successor_host_id === existing.host_id
        && state.recovery.successor_attempt === existing.attempt,
    );
    assertControl(
      !(role === 'DEV' && existing.operational_scope === 'PREFLIGHT_ONLY' && existing.recovery_handoff),
      'RECOVERY_IDENTITY_FROZEN',
      'RECOVERY_HANDOFF_BOUND 后 successor identity 已冻结；不得迁移 receipt/checkpoint/launch/lease/evidence',
    );
    assertControl(attempt === existing.attempt + 1, 'STALE_ROLE_ATTEMPT', `${role} attempt 必须恰好从 ${existing.attempt} 增至 ${existing.attempt + 1}`);
    assertControl(
      existing.thread_id !== event.payload.thread_id || existing.host_id !== hostId,
      'ROLE_IDENTITY_REUSE',
      `${role} 新 attempt 必须使用不同 host/thread identity`,
    );
    assertControl(
      (state.recovery && state.recovery.role === role) || existing.status === 'terminal',
      'ROLE_REPLACEMENT_REQUIRES_RECOVERY',
      `${role} 仍活跃，必须先进入 recovery 或完成当前 attempt`
    );
    if (replacingPendingSuccessor) {
      assertControl(
        existing.status === 'systemError' || Date.parse(existing.lease_until) <= Date.parse(event.accepted_at),
        'RECOVERY_SUCCESSOR_STILL_ACTIVE',
        `未确认 successor ${existing.thread_id} lease 仍有效`,
      );
    }
    if (!state.session_history[role]) state.session_history[role] = [];
    const historical = JSON.parse(JSON.stringify(existing));
    if (replacingPendingSuccessor) {
      historical.status = 'lost';
      historical.lost_at = event.accepted_at;
      historical.terminal_reason = existing.status === 'systemError'
        ? 'RECOVERY_SUCCESSOR_SYSTEM_ERROR'
        : 'RECOVERY_SUCCESSOR_LEASE_EXPIRED';
    }
    state.session_history[role].push(historical);
    existing.status = 'superseded';
    existing.superseded_at = event.accepted_at;
  }
  const historicalIdentity = Object.values(state.session_history || {})
    .flat()
    .find((session) => session.thread_id === event.payload.thread_id);
  assertControl(
    !historicalIdentity,
    'ROLE_IDENTITY_REUSE',
    `thread ${event.payload.thread_id} 已在 task 历史中使用`,
  );
  for (const [otherRole, session] of Object.entries(state.sessions)) {
    if (otherRole !== role && session.thread_id === event.payload.thread_id && session.status !== 'superseded') {
      assertControl(false, 'THREAD_ROLE_COLLISION', `thread 已登记为 ${otherRole}`);
    }
  }
  const leaseMilliseconds = Number(event.payload.lease_ms || 3600000);
  assertControl(Number.isSafeInteger(leaseMilliseconds) && leaseMilliseconds > 0 && leaseMilliseconds <= MAX_ROLE_LEASE_MS, 'INVALID_REGISTRATION', `lease_ms 必须在 1-${MAX_ROLE_LEASE_MS}`);
  assertControl(['active', 'idle', 'systemError'].includes(event.payload.status || 'active'), 'INVALID_REGISTRATION', 'registration status 必须是 active/idle/systemError');
  if (event.payload.goal_foreman_projection === true) {
    assertControl(role === 'FOREMAN' && !existing, 'INVALID_REGISTRATION', 'Goal FOREMAN projection 只适用于空 task');
    assertControl(
      typeof event.payload.projected_lease_until === 'string'
        && Number.isFinite(Date.parse(event.payload.projected_lease_until))
        && Date.parse(event.payload.projected_lease_until) > Date.parse(event.accepted_at),
      'INVALID_REGISTRATION',
      'Goal FOREMAN projection lease 非法或已过期',
    );
  }
  state.sessions[role] = {
    role,
    thread_id: event.payload.thread_id,
    host_id: hostId,
    attempt,
    status: event.payload.status || 'active',
    registered_at: event.accepted_at,
    last_seen_at: event.accepted_at,
    lease_until: event.payload.goal_foreman_projection === true
      ? event.payload.projected_lease_until
      : new Date(Date.parse(event.accepted_at) + leaseMilliseconds).toISOString(),
    launch_id: event.payload.launch_id || null,
    task_nonce: event.payload.task_nonce || null,
    ...(event.payload.worker_bootstrap !== undefined
      ? {
        worker_bootstrap: JSON.parse(
          JSON.stringify(event.payload.worker_bootstrap),
        ),
      }
      : {}),
    ...(event.payload.probe_observation !== undefined
      ? {
        probe_observation: JSON.parse(
          JSON.stringify(event.payload.probe_observation),
        ),
        ...(event.payload.role_identity
          && event.payload.role_identity.protocol
            === 'goalctl-role-identity-intent-v2'
          ? {
            registration_probe_observation: JSON.parse(
              JSON.stringify(event.payload.probe_observation),
            ),
          }
          : {}),
      }
      : {}),
    ...(event.payload.role_identity !== undefined
      ? {
        role_identity: JSON.parse(
          JSON.stringify(event.payload.role_identity),
        ),
      }
      : {}),
    registered_state_revision: state.state_revision + 1,
    registered_control_epoch: event.control_epoch,
    registered_packet_revision: state.packet.revision,
    registered_packet_sha256: state.packet.sha256,
    registered_full_head: state.full_head,
    registered_task_cycle: state.task_cycle,
    capability_sha256: event.payload.capability_sha256,
    capability_file: event.payload.capability_file,
    authorized_by: event.payload.authorized_by,
    registration_event_id: event.event_id,
  };
  if (state.recovery && state.recovery.role === role) {
    state.recovery.successor_thread_id = event.payload.thread_id;
    state.recovery.successor_host_id = hostId;
    state.recovery.successor_attempt = attempt;
  }
}

function applyHeartbeat(state, event) {
  const session = state.sessions[event.actor.role];
  const leaseMilliseconds = Number(event.payload.lease_ms || 3600000);
  assertControl(Number.isSafeInteger(leaseMilliseconds) && leaseMilliseconds > 0 && leaseMilliseconds <= MAX_ROLE_LEASE_MS, 'INVALID_HEARTBEAT', `lease_ms 必须在 1-${MAX_ROLE_LEASE_MS}`);
  assertControl(['active', 'idle', 'systemError'].includes(event.payload.status || 'active'), 'INVALID_HEARTBEAT', 'heartbeat status 非法');
  session.status = event.payload.status || 'active';
  session.last_seen_at = event.accepted_at;
  session.lease_until = new Date(Date.parse(event.accepted_at) + leaseMilliseconds).toISOString();
}

function applyProbeObservationRefreshed(state, event) {
  const role = event.payload.role;
  const session = state.sessions[role];
  assertControl(
    session
      && session.thread_id === event.actor.thread_id
      && session.host_id === event.actor.host_id
      && session.attempt === event.payload.attempt,
    'CANARY_OBSERVATION_CROSS_IDENTITY',
    'probe observation refresh actor/session identity 漂移',
  );
  assertControl(
    session.probe_observation
      && session.probe_observation.binding_sha256
        === event.payload.previous_binding_sha256,
    'CANARY_OBSERVATION_REFRESH_CAS_MISMATCH',
    'probe observation refresh previous binding CAS 漂移',
  );
  assertControl(
    event.payload.probe_observation.thread_id === session.thread_id
      && event.payload.probe_observation.host_id === session.host_id
      && event.payload.probe_observation.attempt === session.attempt
      && event.payload.probe_observation.accepted_at === event.accepted_at,
    'CANARY_OBSERVATION_CROSS_IDENTITY',
    'refreshed probe observation 未绑定 exact session/accepted_at',
  );
  session.probe_observation = JSON.parse(
    JSON.stringify(event.payload.probe_observation),
  );
  session.probe_observation_refreshed_at = event.accepted_at;
}

function applyP1CommitAbandoned(state, event) {
  assertControl(
    state.p1.policy && state.phase === 'P1_APPROVED',
    'P1_COMMIT_ABANDON_INVALID',
    'P1_COMMIT_ABANDONED 只适用于 mechanical P1_APPROVED',
  );
  assertControl(
    !state.p1.commit_abandonment,
    'P1_COMMIT_ALREADY_ABANDONED',
    '当前 P1 cycle 已存在 append-only abandonment tombstone',
  );
  assertControl(
    event.actor.role === 'FOREMAN'
      && event.payload.task_cycle === state.task_cycle
      && event.payload.predecessor_event_sha256
        === (
          state.last_event
            ? state.last_event.event_sha256
            : null
        ),
    'P1_COMMIT_ABANDON_INVALID',
    'P1_COMMIT_ABANDONED cycle/predecessor/actor binding 漂移',
  );
  state.p1.commit_abandonment = {
    event_id: event.event_id,
    prepared_event_id: event.payload.prepared_event_id,
    task_cycle: event.payload.task_cycle,
    p1_intent_sha256: normalizeHash(
      event.payload.p1_intent_sha256,
      'P1 abandonment p1_intent_sha256',
    ),
    abandon_intent_sha256: normalizeHash(
      event.payload.abandon_intent_sha256,
      'P1 abandonment intent_sha256',
    ),
    abandon_request_sha256: normalizeHash(
      event.payload.abandon_request_sha256,
      'P1 abandonment request_sha256',
    ),
    abandon_receipt_sha256: normalizeHash(
      event.payload.abandon_receipt_sha256,
      'P1 abandonment receipt_sha256',
    ),
    commit_ref: event.payload.commit_ref,
    commit_sha: event.payload.commit_sha,
    predecessor_event_sha256: event.payload.predecessor_event_sha256,
    reason: event.payload.reason,
    incident_ref: event.payload.incident_ref,
    abandoned_at: event.accepted_at,
  };
}

function applyHold(state, event) {
  const kind = event.payload.kind;
  assertControl(HOLD_KINDS.includes(kind), 'INVALID_HOLD', `未知 hold kind: ${kind}`);
  const holdId = event.payload.hold_id || event.event_id;
  assertControl(!state.holds.some((hold) => hold.hold_id === holdId), 'DUPLICATE_HOLD', `hold 已存在: ${holdId}`);
  assertControl(event.payload.hold_evidence && event.payload.hold_evidence.evidence_id, 'HOLD_EVIDENCE_REQUIRED', 'hold 必须带可信 evidence');
  state.holds.push({
    hold_id: holdId,
    kind,
    hard: HARD_HOLDS.includes(kind),
    reason: event.payload.reason || '',
    evidence: event.payload.hold_evidence,
    raised_by: event.actor,
    raised_at: event.accepted_at,
    resume_phase: state.phase,
  });
}

function resolveHold(state, event) {
  const holdId = event.payload.hold_id;
  const index = state.holds.findIndex((hold) => hold.hold_id === holdId);
  assertControl(index !== -1, 'UNKNOWN_HOLD', `找不到 hold: ${holdId}`);
  const hold = state.holds[index];
  if (hold.hard) {
    assertControl(event.actor.role === 'FOREMAN', 'HARD_HOLD_AUTHORITY_REQUIRED', `${hold.kind} 只能由 FOREMAN 解除`);
    assertControl(typeof event.payload.authority === 'string' && event.payload.authority.length > 0, 'HARD_HOLD_AUTHORITY_REQUIRED', 'hard hold 缺 authority');
    assertControl(event.payload.resolution_evidence && event.payload.resolution_evidence.evidence_id, 'HARD_HOLD_EVIDENCE_REQUIRED', 'hard hold 缺可信 resolution evidence');
    assertControl(event.payload.disposition === 'FIXED' || event.payload.disposition === 'FALSE_POSITIVE', 'HARD_HOLD_NO_WAIVER', '安全 hold 只能以 FIXED 或 FALSE_POSITIVE 解除，不接受 waiver');
  } else {
    assertControl(['CAPTAIN', 'FOREMAN'].includes(event.actor.role), 'HOLD_AUTHORITY_REQUIRED', '普通 hold 只能由 CAPTAIN/FOREMAN 解除');
  }
  const rotatedSession = Object.values(state.sessions || {}).find(
    (session) => (
      session
        && session.last_runtime_rotation
        && session.last_runtime_rotation.hold_id === holdId
    ),
  );
  if (rotatedSession) {
    const evidence = event.payload.runtime_preflight_evidence;
    assertControl(
      evidence
        && evidence.kind === 'PREFLIGHT'
        && evidence.status === 'PASS'
        && evidence.launch_id === rotatedSession.launch_id
        && evidence.producer
        && evidence.producer.role === rotatedSession.role
        && evidence.producer.thread_id === rotatedSession.thread_id
        && (evidence.producer.host_id || 'local')
          === rotatedSession.host_id,
      'RUNTIME_PREFLIGHT_EVIDENCE_REQUIRED',
      'runtime rotation hold 只能由 exact successor PREFLIGHT PASS 解除',
    );
  }
  state.holds.splice(index, 1);
}

function applyRuntimeRotated(state, event) {
  assertControl(
    event.actor.role === 'CAPTAIN',
    'RUNTIME_ROTATION_AUTHORITY',
    'runtime rotation 只能由 CAPTAIN 执行',
  );
  assertControl(
    !state.recovery
      && (!Array.isArray(state.recovery_backlog)
        || state.recovery_backlog.length === 0)
      && !state.reconcile_required,
    'RUNTIME_ROTATION_CONTROL_BLOCKED',
    'recovery/reconcile 未闭合，禁止 runtime rotation',
  );
  assertControl(
    state.holds.length === 1
      && state.holds[0].kind === 'ENV_IDENTITY_INCIDENT'
      && state.holds[0].hard === true
      && state.holds[0].hold_id === event.payload.hold_id,
    'RUNTIME_ROTATION_HOLD_REQUIRED',
    'runtime rotation 只允许在唯一、精确匹配的 ENV_IDENTITY_INCIDENT hard hold 下执行',
  );
  const role = event.payload.role;
  const phaseByRole = {
    DEV: 'DEV_ACTIVE',
    REVIEW: 'REVIEW_ACTIVE',
    RECEIPT: 'RECEIPT_ACTIVE',
  };
  assertControl(
    phaseByRole[role] === state.phase,
    'RUNTIME_ROTATION_PHASE_MISMATCH',
    `${role} runtime 不能在 phase=${state.phase} 轮换`,
  );
  const session = state.sessions[role];
  assertControl(
    session
      && ['active', 'idle'].includes(session.status)
      && session.thread_id === event.payload.worker_thread_id
      && session.host_id === event.payload.worker_host_id
      && session.attempt === event.payload.worker_attempt,
    'RUNTIME_ROTATION_WORKER_MISMATCH',
    'runtime rotation worker identity 与 active session 不一致',
  );
  assertControl(
    Date.parse(session.lease_until) > Date.parse(event.accepted_at),
    'ACTOR_LEASE_EXPIRED',
    `${role} worker lease 已过期`,
  );
  assertControl(
    !session.recovered_from || session.operational_scope === 'FULL',
    'RECOVERY_PROMOTION_REQUIRED',
    'recovered worker 尚未恢复 FULL scope',
  );
  const currentIncarnation = session.runtime_incarnation === undefined
    ? 1
    : session.runtime_incarnation;
  assertControl(
    Number.isSafeInteger(currentIncarnation)
      && currentIncarnation > 0
      && event.payload.predecessor_incarnation === currentIncarnation
      && event.payload.successor_incarnation === currentIncarnation + 1,
    'RUNTIME_INCARNATION_CAS_MISMATCH',
    `runtime incarnation 应为 ${currentIncarnation}->${currentIncarnation + 1}`,
  );
  assertControl(
    session.launch_id === event.payload.predecessor_launch_id
      && event.payload.successor_launch_id
        !== event.payload.predecessor_launch_id,
    'RUNTIME_LAUNCH_CAS_MISMATCH',
    'runtime predecessor/successor launch CAS 不匹配',
  );
  const usedLaunchIds = [];
  for (const current of Object.values(state.sessions || {})) {
    if (current.launch_id) usedLaunchIds.push(current.launch_id);
    for (const runtime of current.runtime_history || []) {
      if (runtime.launch_id) usedLaunchIds.push(runtime.launch_id);
    }
  }
  for (const history of Object.values(state.session_history || {})) {
    for (const historical of history || []) {
      if (historical.launch_id) usedLaunchIds.push(historical.launch_id);
      for (const runtime of historical.runtime_history || []) {
        if (runtime.launch_id) usedLaunchIds.push(runtime.launch_id);
      }
    }
  }
  assertControl(
    !usedLaunchIds.includes(event.payload.successor_launch_id),
    'RUNTIME_SUCCESSOR_ID_REUSED',
    `successor launch_id ${event.payload.successor_launch_id} 已使用`,
  );
  if (!Array.isArray(session.runtime_history)) {
    session.runtime_history = [];
  }
  session.runtime_history.push({
    incarnation: currentIncarnation,
    launch_id: event.payload.predecessor_launch_id,
    launch_sha256: normalizeHash(
      event.payload.predecessor_launch_sha256,
      'runtime predecessor launch sha256',
    ),
    retirement_proof: JSON.parse(JSON.stringify(
      event.payload.retirement_proof,
    )),
    lease_set_sha256: normalizeHash(
      event.payload.lease_set_sha256,
      'runtime lease set sha256',
    ),
    retired_at: event.accepted_at,
    rotation_event_id: event.event_id,
  });
  session.runtime_incarnation = event.payload.successor_incarnation;
  session.runtime_nonce = event.payload.runtime_nonce;
  session.launch_id = event.payload.successor_launch_id;
  session.last_runtime_rotation = {
    event_id: event.event_id,
    predecessor_incarnation: currentIncarnation,
    successor_incarnation: event.payload.successor_incarnation,
    predecessor_launch_id: event.payload.predecessor_launch_id,
    predecessor_launch_sha256: normalizeHash(
      event.payload.predecessor_launch_sha256,
      'runtime predecessor launch sha256',
    ),
    successor_launch_id: event.payload.successor_launch_id,
    runtime_nonce: event.payload.runtime_nonce,
    hold_id: event.payload.hold_id,
    reason: event.payload.reason,
    incident_ref: event.payload.incident_ref,
    lease_set_sha256: normalizeHash(
      event.payload.lease_set_sha256,
      'runtime lease set sha256',
    ),
    retirement: {
      kind: event.payload.retirement_proof.kind,
      predecessor_pid: event.payload.retirement_proof.predecessor_pid,
      preview_port: event.payload.retirement_proof.preview_port,
      proxy_port: event.payload.retirement_proof.proxy_port,
      sample_count: event.payload.retirement_proof.sample_count,
    },
    rotated_at: event.accepted_at,
  };
}

function applyRoleLost(state, event) {
  assertControl(!state.recovery, 'RECOVERY_ALREADY_PENDING', `角色 ${state.recovery && state.recovery.role} 的 recovery 尚未闭合`);
  assertControl(['CAPTAIN', 'FOREMAN'].includes(event.actor.role), 'ROLE_LOST_AUTHORITY', '只有 CAPTAIN/FOREMAN 可登记失联');
  const lostRole = event.payload.role;
  assertControl(ROLES.includes(lostRole), 'INVALID_ROLE', `未知失联角色 ${lostRole}`);
  const session = state.sessions[lostRole];
  assertControl(session, 'UNREGISTERED_ACTOR', `${lostRole} 尚未登记`);
  const targetBindingKeys = [
    'expected_thread_id',
    'expected_host_id',
    'expected_attempt',
    'expected_lease_until',
  ];
  const hasTargetBinding = targetBindingKeys.some(
    (key) => event.payload[key] !== undefined,
  );
  if (hasTargetBinding) {
    assertControl(
      targetBindingKeys.every((key) => event.payload[key] !== undefined),
      'ROLE_LOST_TARGET_INVALID',
      'ROLE_LOST exact target binding 必须完整',
    );
    assertControl(
      ['active', 'idle', 'systemError'].includes(session.status)
        && session.thread_id === event.payload.expected_thread_id
        && session.host_id === event.payload.expected_host_id
        && session.attempt === event.payload.expected_attempt
        && session.lease_until === event.payload.expected_lease_until,
      'ROLE_LOST_TARGET_STALE',
      `ROLE_LOST exact target 已漂移；当前 ${lostRole}=${session.thread_id}@${session.host_id}/a${session.attempt}/${session.lease_until}`,
    );
  }
  assertControl(
    !(lostRole === 'DEV' && session.operational_scope === 'PREFLIGHT_ONLY' && session.recovery_handoff),
    'RECOVERY_IDENTITY_FROZEN',
    'RECOVERY_HANDOFF_BOUND 后 DEV identity 已冻结；PREFLIGHT_ONLY 不允许再次 ROLE_LOST/retarget',
  );
  if (lostRole === 'CAPTAIN') {
    assertControl(event.actor.role === 'FOREMAN', 'ROLE_LOST_AUTHORITY', 'CAPTAIN 失联只能由 FOREMAN 登记');
  } else {
    assertControl(event.actor.role === 'CAPTAIN', 'ROLE_LOST_AUTHORITY', '执行角色失联只能由 CAPTAIN 登记');
  }
  const dormantSourcePredecessor = lostRole === 'DEV'
    && state.phase === 'DEV_ACTIVE'
    && session.operational_scope === 'RECOVERY_BLOCKED'
    && session.recovered_from
    && !session.recovery_handoff
    ? JSON.parse(JSON.stringify(session.recovered_from))
    : null;
  session.status = 'lost';
  state.recovery = {
    role: lostRole,
    lost_thread_id: session.thread_id,
    lost_host_id: session.host_id,
    lost_attempt: session.attempt,
    recovery_event_id: event.event_id,
    resume_phase: state.phase,
    reason: event.payload.reason || 'terminal event missing',
    fingerprint: event.payload.fingerprint || null,
    attempts: Number(event.payload.attempts || 1),
    evidence_id: event.payload.role_failure_evidence
      ? event.payload.role_failure_evidence.evidence_id
      : null,
    evidence_registry_sha256: event.payload.role_failure_evidence
      ? event.payload.role_failure_evidence.registry_sha256
      : null,
    ...(dormantSourcePredecessor
      ? {
        source_predecessor: dormantSourcePredecessor,
        dormant_successor: {
          thread_id: session.thread_id,
          host_id: session.host_id,
          attempt: session.attempt,
          recovery_event_id: event.event_id,
        },
      }
      : {}),
    detected_at: event.accepted_at,
  };
}

function foremanRootRecoveryStatusEligible(state, foreman) {
  if (!state || !foreman) return false;
  const alreadyMarkedLost = foreman.status === 'lost'
    && state.recovery
    && state.recovery.role === 'FOREMAN'
    && state.recovery.lost_thread_id === foreman.thread_id;
  if (state.phase === 'ARCHIVED') {
    return [
      'active',
      'idle',
      'systemError',
      'lost',
      'terminal',
    ].includes(foreman.status);
  }
  return ['active', 'idle', 'systemError'].includes(foreman.status)
    || alreadyMarkedLost;
}

function applyExpiredForemanRecovery(state, event) {
  assertControl(event.actor.role === 'FOREMAN', 'RECOVERY_ACTOR_INVALID', '过期 FOREMAN replacement actor 必须是 successor FOREMAN');
  assertControl(
    event.payload.authorized_by
      && event.payload.authorized_by.role === 'GOAL_RECOVERY'
      && Object.keys(event.payload.authorized_by).length === 1,
    'RECOVERY_AUTHORITY',
    '过期 FOREMAN replacement 只接受独立 Goal recovery authority',
  );
  const previous = state.sessions.FOREMAN;
  const adoption = event.payload.adopt_without_local_foreman === true;
  assertControl(
    previous || adoption,
    'UNREGISTERED_ACTOR',
    'FOREMAN 尚未登记，且事件不是 Goal archived-lineage adoption',
  );
  assertControl(
    !previous || !adoption,
    'INVALID_RECOVERY_REQUEST',
    '已有本地 FOREMAN 时禁止使用 archived-lineage adoption',
  );
  const pendingRecovery = state.recovery
    ? JSON.parse(JSON.stringify(state.recovery))
    : null;
  if (previous) {
    assertControl(
      foremanRootRecoveryStatusEligible(state, previous),
      'FOREMAN_RECOVERY_NOT_ELIGIBLE',
      `FOREMAN status=${previous.status} 不适用过期原子恢复`,
    );
    assertControl(previous.thread_id === event.payload.expected_foreman_thread_id, 'STALE_FOREMAN_IDENTITY', 'expected FOREMAN thread 已漂移');
    assertControl(previous.host_id === event.payload.expected_foreman_host_id, 'STALE_FOREMAN_IDENTITY', 'expected FOREMAN host 已漂移');
    assertControl(previous.attempt === event.payload.expected_foreman_attempt, 'STALE_ROLE_ATTEMPT', 'expected FOREMAN attempt 已漂移');
    assertControl(previous.lease_until === event.payload.expected_foreman_lease_until, 'STALE_FOREMAN_LEASE', 'expected FOREMAN lease 已漂移');
    assertControl(
      Date.parse(previous.lease_until) <= Date.parse(event.accepted_at),
      'FOREMAN_LEASE_ACTIVE',
      `FOREMAN lease ${previous.lease_until} 尚未过期`,
    );
  } else {
    assertControl(
      event.payload.source_foreman
        && event.payload.source_foreman.task_id
        && event.payload.source_foreman.thread_id === event.payload.expected_foreman_thread_id
        && event.payload.source_foreman.host_id === event.payload.expected_foreman_host_id
        && event.payload.source_foreman.attempt === event.payload.expected_foreman_attempt
        && event.payload.source_foreman.lease_until === event.payload.expected_foreman_lease_until,
      'INVALID_RECOVERY_REQUEST',
      'archived-lineage adoption 缺 sealed source FOREMAN binding',
    );
  }
  assertControl(
    (state.last_event && state.last_event.event_sha256) === event.payload.expected_event_head,
    'STALE_EVENT_HEAD',
    'expected task event head 已漂移',
  );

  const attempt = Number(event.payload.attempt);
  const incumbentAttempt = previous
    ? previous.attempt
    : Number(event.payload.source_foreman.attempt);
  assertControl(attempt === incumbentAttempt + 1, 'STALE_ROLE_ATTEMPT', `FOREMAN attempt 必须恰好从 ${incumbentAttempt} 增至 ${incumbentAttempt + 1}`);
  if (state.probe_observation_required) {
    const identity = event.payload.role_identity;
    const protocolRequired =
      state.role_identity_protocol_version >= 2;
    assertControl(
      (!protocolRequired && identity === undefined)
        || (
          identity
          && (
            protocolRequired
              ? identity.protocol
                === 'goalctl-role-identity-intent-v2'
              : [
                'goalctl-role-identity-intent-v1',
                'goalctl-role-identity-intent-v2',
              ].includes(identity.protocol)
          )
        && identity.operation_id === event.payload.root_recovery_id
        && identity.thread_id === event.actor.thread_id
        && identity.host_id === event.actor.host_id
        && identity.attempt === attempt
        && identity.launch_id === null
        ),
      'ROLE_IDENTITY_INTENT_MISMATCH',
      'probe-enabled FOREMAN recovery 必须绑定 exact upstream role identity intent',
    );
  }
  assertControl(!previous || event.actor.thread_id !== previous.thread_id, 'ROLE_IDENTITY_REUSE', 'successor FOREMAN 必须使用全新的 thread identity');
  const allSessions = [
    ...Object.values(state.sessions || {}),
    ...Object.values(state.session_history || {}).flat(),
  ];
  assertControl(
    !allSessions.some((session) => session.thread_id === event.actor.thread_id),
    'ROLE_IDENTITY_REUSE',
    'successor FOREMAN thread identity 已在 task 历史中使用',
  );
  const leaseMilliseconds = Number(event.payload.lease_ms);
  assertControl(
    Number.isSafeInteger(leaseMilliseconds) && leaseMilliseconds > 0 && leaseMilliseconds <= MAX_ROLE_LEASE_MS,
    'INVALID_REGISTRATION',
    `lease_ms 必须在 1-${MAX_ROLE_LEASE_MS}`,
  );
  assertControl(event.payload.status === 'active', 'INVALID_REGISTRATION', 'recovered FOREMAN 必须以 active 状态登记');
  assertControl(typeof event.payload.capability_sha256 === 'string' && /^[0-9a-f]{64}$/.test(event.payload.capability_sha256), 'INVALID_REGISTRATION', 'capability hash 缺失');
  assertControl(typeof event.payload.capability_file === 'string' && event.payload.capability_file.length > 0, 'INVALID_REGISTRATION', 'capability file 缺失');
  assertControl(typeof event.payload.reason === 'string' && event.payload.reason.trim().length > 0, 'RECOVERY_REASON_REQUIRED', 'recovery reason 缺失');
  assertControl(typeof event.payload.incident_ref === 'string' && event.payload.incident_ref.trim().length > 0, 'RECOVERY_INCIDENT_REQUIRED', 'recovery incident_ref 缺失');
  assertControl(typeof event.payload.request_sha256 === 'string' && /^sha256:[0-9a-f]{64}$/.test(event.payload.request_sha256), 'INVALID_RECOVERY_REQUEST', 'recovery request hash 缺失');

  if (previous) {
    const historical = JSON.parse(JSON.stringify(previous));
    historical.status = 'lost';
    historical.lost_at = event.accepted_at;
    historical.terminal_reason = 'LEASE_EXPIRED_GOAL_RECOVERY';
    if (!state.session_history.FOREMAN) state.session_history.FOREMAN = [];
    state.session_history.FOREMAN.push(historical);
  }

  state.sessions.FOREMAN = {
    role: 'FOREMAN',
    thread_id: event.actor.thread_id,
    host_id: event.actor.host_id,
    attempt,
    status: 'active',
    registered_at: event.accepted_at,
    last_seen_at: event.accepted_at,
    lease_until: new Date(Date.parse(event.accepted_at) + leaseMilliseconds).toISOString(),
    launch_id: null,
    task_nonce: null,
    registered_state_revision: state.state_revision + 1,
    registered_control_epoch: event.control_epoch,
    registered_packet_revision: state.packet.revision,
    registered_packet_sha256: state.packet.sha256,
    registered_full_head: state.full_head,
    registered_task_cycle: state.task_cycle,
    capability_sha256: event.payload.capability_sha256,
    capability_file: event.payload.capability_file,
    authorized_by: { role: 'GOAL_RECOVERY' },
    recovery_event_id: event.payload.root_recovery_id || event.event_id,
    recovery_request_sha256: event.payload.request_sha256,
    recovery_incident_ref: event.payload.incident_ref,
    ...(event.payload.probe_observation !== undefined
      ? {
        probe_observation: JSON.parse(
          JSON.stringify(event.payload.probe_observation),
        ),
      }
      : {}),
    ...(event.payload.role_identity !== undefined
      ? {
        role_identity: JSON.parse(
          JSON.stringify(event.payload.role_identity),
        ),
      }
      : {}),
  };
  if (pendingRecovery && pendingRecovery.role === 'CAPTAIN') {
    state.recovery = pendingRecovery;
  } else if (pendingRecovery && pendingRecovery.role !== 'FOREMAN') {
    if (!Array.isArray(state.recovery_backlog)) state.recovery_backlog = [];
    state.recovery_backlog.push(pendingRecovery);
    state.recovery = null;
  } else {
    state.recovery = null;
  }
}

function applyRoleRecovered(state, event) {
  assertControl(state.recovery, 'NO_RECOVERY_PENDING', '当前没有待恢复角色');
  const recovery = JSON.parse(JSON.stringify(state.recovery));
  const role = recovery.role;
  if (role === 'CAPTAIN') {
    assertControl(event.actor.role === 'FOREMAN', 'RECOVERY_AUTHORITY', 'CAPTAIN 恢复只能由 FOREMAN 确认');
  } else {
    assertControl(event.actor.role === 'CAPTAIN', 'RECOVERY_AUTHORITY', '执行角色恢复只能由 CAPTAIN 确认');
  }
  const session = state.sessions[role];
  assertControl(session && session.thread_id === event.payload.successor_thread_id, 'SUCCESSOR_NOT_REGISTERED', 'successor 尚未登记为当前角色');
  assertControl(
    recovery.successor_thread_id === session.thread_id
      && recovery.successor_host_id === session.host_id
      && recovery.successor_attempt === session.attempt,
    'SUCCESSOR_NOT_REGISTERED',
    'successor identity 与 recovery registration 不一致',
  );
  assertControl(['active', 'idle'].includes(session.status), 'SUCCESSOR_NOT_REGISTERED', `successor status=${session.status}`);
  validateRecoverySuccessorLease(session, event);
  const predecessor = [...(state.session_history[role] || [])]
    .reverse()
    .find((candidate) => (
      candidate.thread_id === recovery.lost_thread_id
        && candidate.host_id === recovery.lost_host_id
        && candidate.attempt === recovery.lost_attempt
    ));
  assertControl(predecessor && predecessor.status === 'lost', 'RECOVERY_PREDECESSOR_MISSING', 'successor 缺失对应的 lost predecessor');
  assertControl(predecessor.attempt < session.attempt, 'STALE_ROLE_ATTEMPT', 'successor attempt 未晚于 lost predecessor');
  for (let attempt = predecessor.attempt + 1; attempt < session.attempt; attempt += 1) {
    const abandoned = (state.session_history[role] || []).find((candidate) => candidate.attempt === attempt);
    assertControl(
      abandoned && abandoned.status === 'lost',
      'RECOVERY_LINEAGE_GAP',
      `recovery successor attempt ${attempt} 缺失 lost lineage`,
    );
  }
  session.status = 'active';
  session.last_seen_at = event.accepted_at;
  session.activated_state_revision = state.state_revision + 1;
  session.activated_control_epoch = event.control_epoch;
  session.activated_packet_revision = state.packet.revision;
  session.activated_packet_sha256 = state.packet.sha256;
  session.activated_full_head = state.full_head;
  session.activated_task_cycle = state.task_cycle;
  const predecessorLaunchHead = predecessor.recovery_handoff
    ? predecessor.recovery_handoff.import_commit
    : predecessor.registered_full_head;
  if (predecessor.recovery_handoff) {
    assertControl(
      predecessor.operational_scope === 'FULL'
        && predecessor.recovery_promotion
        && predecessor.recovery_promotion.launch_id === predecessor.launch_id
        && typeof predecessorLaunchHead === 'string',
      'RECOVERY_LINEAGE_GAP',
      'recovered predecessor 缺已 promotion 的 canonical launch checkpoint',
    );
  }
  let recoveredFrom = {
    role,
    thread_id: recovery.lost_thread_id,
    host_id: predecessor.host_id,
    attempt: predecessor.attempt,
    recovery_event_id: recovery.recovery_event_id || null,
    predecessor_launch_id: predecessor.launch_id || null,
    predecessor_registered_head: predecessor.registered_full_head,
    predecessor_launch_head: predecessorLaunchHead,
    resume_phase: recovery.resume_phase,
    recovered_at: event.accepted_at,
  };
  if (role === 'DEV' && recovery.source_predecessor) {
    const sourcePredecessor = recovery.source_predecessor;
    const sourceHistory = (state.session_history.DEV || []).filter((candidate) => (
      candidate.thread_id === sourcePredecessor.thread_id
        && candidate.host_id === sourcePredecessor.host_id
        && candidate.attempt === sourcePredecessor.attempt
    ));
    assertControl(
      sourceHistory.length === 1 && sourceHistory[0].status === 'lost',
      'RECOVERY_PREDECESSOR_MISSING',
      'dormant successor retarget 缺 exact original source predecessor',
    );
    assertControl(
      sourcePredecessor.resume_phase === 'DEV_ACTIVE'
        && sourcePredecessor.predecessor_launch_id === sourceHistory[0].launch_id
        && sourcePredecessor.predecessor_registered_head === sourceHistory[0].registered_full_head
        && sourcePredecessor.predecessor_launch_head === (
          sourceHistory[0].recovery_handoff
            ? sourceHistory[0].recovery_handoff.import_commit
            : sourceHistory[0].registered_full_head
        ),
      'RECOVERY_LINEAGE_GAP',
      'dormant successor retarget 的 source lineage 已漂移',
    );
    recoveredFrom = {
      ...sourcePredecessor,
      recovered_at: event.accepted_at,
    };
    session.recovery_chain = [
      ...(Array.isArray(predecessor.recovery_chain)
        ? JSON.parse(JSON.stringify(predecessor.recovery_chain))
        : []),
      {
        thread_id: recovery.lost_thread_id,
        host_id: predecessor.host_id,
        attempt: predecessor.attempt,
        recovery_event_id: recovery.recovery_event_id || null,
        reason: recovery.reason,
      },
    ];
  }
  session.recovered_from = recoveredFrom;
  session.operational_scope = role === 'DEV' && recovery.resume_phase === 'DEV_ACTIVE'
    ? 'RECOVERY_BLOCKED'
    : 'FULL';
  state.recovery = null;
  if (role === 'CAPTAIN' && Array.isArray(state.recovery_backlog) && state.recovery_backlog.length > 0) {
    state.recovery = state.recovery_backlog.shift();
  }
}

function applyRecoveryHandoffBound(state, event) {
  assertControl(event.actor.role === 'CAPTAIN', 'RECOVERY_AUTHORITY', 'DEV source handoff 只能由 CAPTAIN 绑定');
  assertControl(state.phase === 'DEV_ACTIVE', 'RECOVERY_HANDOFF_NOT_APPLICABLE', `phase=${state.phase} 不适用 DEV source handoff`);
  const session = state.sessions.DEV;
  assertControl(session && session.thread_id === event.payload.successor_thread_id, 'SUCCESSOR_NOT_REGISTERED', 'handoff successor 不是当前 DEV');
  validateRecoverySuccessorLease(session, event);
  assertControl(session.recovered_from && session.recovered_from.role === 'DEV', 'RECOVERY_HANDOFF_NOT_APPLICABLE', '当前 DEV 不是 recovery successor');
  assertControl(session.operational_scope === 'RECOVERY_BLOCKED', 'RECOVERY_HANDOFF_ALREADY_BOUND', `DEV scope=${session.operational_scope}`);
  assertControl(
    !session.recovery_retarget_required,
    'RECOVERY_RETARGET_REQUIRED',
    '已废止 handoff 的 successor 必须先 ROLE_LOST 并登记 fresh attempt，不能原 identity 重绑',
  );
  assertControl(event.payload.predecessor_launch_id === session.recovered_from.predecessor_launch_id, 'RECOVERY_HANDOFF_MISMATCH', 'handoff predecessor launch 与 recovery lineage 不一致');
  session.recovery_handoff = {
    event_id: event.event_id,
    snapshot_id: event.payload.snapshot_id,
    snapshot_sha256: event.payload.snapshot_sha256,
    import_receipt_id: event.payload.import_receipt_id,
    import_receipt_sha256: event.payload.import_receipt_sha256,
    predecessor_launch_id: event.payload.predecessor_launch_id,
    predecessor_launch_sha256: event.payload.predecessor_launch_sha256,
    source_worktree: event.payload.source_worktree,
    source_branch: event.payload.source_branch,
    source_launch_head: event.payload.source_launch_head,
    source_observed_head: event.payload.source_observed_head,
    destination_worktree: event.payload.destination_worktree,
    destination_branch: event.payload.destination_branch,
    import_commit: event.payload.import_commit,
    bound_at: event.accepted_at,
  };
  session.operational_scope = 'PREFLIGHT_ONLY';
}

function applyRecoveryHandoffAbandoned(state, event) {
  assertControl(event.actor.role === 'CAPTAIN', 'RECOVERY_AUTHORITY', 'sealed handoff 放弃只能由 CAPTAIN 发起');
  assertControl(state.phase === 'DEV_ACTIVE', 'RECOVERY_HANDOFF_NOT_APPLICABLE', `phase=${state.phase} 不适用 handoff abandon`);
  const session = state.sessions.DEV;
  assertControl(
    session
      && session.thread_id === event.payload.successor_thread_id
      && session.operational_scope === 'PREFLIGHT_ONLY'
      && session.recovery_handoff,
    'RECOVERY_HANDOFF_NOT_APPLICABLE',
    'handoff abandon 只适用于当前 PREFLIGHT_ONLY DEV',
  );
  assertControl(
    session.recovery_handoff.event_id === event.payload.handoff_event_id,
    'RECOVERY_HANDOFF_MISMATCH',
    'handoff abandon 引用了不同 sealed handoff',
  );
  const foreman = state.sessions.FOREMAN;
  const coauthority = event.goal_foreman_coauthority || null;
  assertControl(foreman, 'RECOVERY_AUTHORITY', 'handoff abandon 缺 local FOREMAN projection');
  assertControl(
    foreman.thread_id === event.payload.foreman_thread_id
      && foreman.host_id === event.payload.foreman_host_id
      && foreman.attempt === event.payload.foreman_attempt,
    'RECOVERY_AUTHORITY',
    'handoff abandon 的 FOREMAN 联合授权 identity 不匹配',
  );
  if (coauthority) {
    assertControl(
      coauthority.thread_id === foreman.thread_id
        && coauthority.host_id === foreman.host_id
        && coauthority.attempt === foreman.attempt
        && coauthority.capability_file === foreman.capability_file
        && coauthority.capability_sha256 === foreman.capability_sha256,
      'RECOVERY_AUTHORITY',
      'handoff abandon 的 Goal FOREMAN coauthority anchor 与 local projection 不一致',
    );
    assertControl(
      Date.parse(coauthority.lease_until) > Date.parse(event.accepted_at),
      'ACTOR_LEASE_EXPIRED',
      `联合授权 Goal FOREMAN lease 已于 ${coauthority.lease_until} 过期`,
    );
  } else {
    assertControl(
      ['active', 'idle'].includes(foreman.status),
      'RECOVERY_AUTHORITY',
      `handoff abandon local FOREMAN status=${foreman.status}`,
    );
    assertControl(
      Date.parse(foreman.lease_until) > Date.parse(event.accepted_at),
      'ACTOR_LEASE_EXPIRED',
      `联合授权 FOREMAN lease 已于 ${foreman.lease_until} 过期`,
    );
  }
  const abandoned = {
    ...JSON.parse(JSON.stringify(session.recovery_handoff)),
    abandoned_at: event.accepted_at,
    abandoned_by: {
      captain: { ...event.actor },
      foreman: {
        role: 'FOREMAN',
        thread_id: foreman.thread_id,
        host_id: foreman.host_id,
        attempt: foreman.attempt,
      },
    },
    reason: event.payload.reason,
    incident_ref: event.payload.incident_ref,
  };
  if (!Array.isArray(session.abandoned_recovery_handoffs)) {
    session.abandoned_recovery_handoffs = [];
  }
  session.abandoned_recovery_handoffs.push(abandoned);
  delete session.recovery_handoff;
  delete session.recovery_promotion;
  session.recovery_retarget_required = {
    abandonment_event_id: event.event_id,
    abandoned_handoff_event_id: event.payload.handoff_event_id,
    required_next: 'ROLE_LOST',
  };
  session.operational_scope = 'RECOVERY_BLOCKED';
}

function applyRecoveryPromoted(state, event) {
  assertControl(event.actor.role === 'CAPTAIN', 'RECOVERY_AUTHORITY', 'DEV recovery promotion 只能由 CAPTAIN 确认');
  assertControl(state.phase === 'DEV_ACTIVE', 'RECOVERY_PROMOTION_NOT_APPLICABLE', `phase=${state.phase} 不适用 DEV recovery promotion`);
  const session = state.sessions.DEV;
  assertControl(session && session.thread_id === event.payload.successor_thread_id, 'SUCCESSOR_NOT_REGISTERED', 'promotion successor 不是当前 DEV');
  validateRecoverySuccessorLease(session, event);
  assertControl(session.recovery_handoff, 'RECOVERY_HANDOFF_REQUIRED', 'promotion 前必须先绑定 source handoff');
  assertControl(session.recovery_handoff.event_id === event.payload.handoff_event_id, 'RECOVERY_HANDOFF_MISMATCH', 'promotion 引用了不同 handoff');
  assertControl(session.operational_scope === 'PREFLIGHT_ONLY', 'RECOVERY_PROMOTION_NOT_APPLICABLE', `DEV scope=${session.operational_scope}`);
  assertControl(session.launch_id === event.payload.launch_id, 'LAUNCH_ID_MISMATCH', 'promotion launch_id 与 DEV session 不一致');
  assertControl(
    event.payload.preflight_evidence
      && event.payload.preflight_evidence.evidence_id === event.payload.preflight_evidence_id
      && event.payload.preflight_evidence.launch_id === event.payload.launch_id
      && event.payload.preflight_evidence.launch_sha256 === event.payload.launch_sha256,
    'PREFLIGHT_EVIDENCE_MISMATCH',
    'promotion 缺可重放且绑定 launch 的 sealed PREFLIGHT evidence',
  );
  session.operational_scope = 'FULL';
  session.recovery_promotion = {
    event_id: event.event_id,
    handoff_event_id: event.payload.handoff_event_id,
    launch_id: event.payload.launch_id,
    launch_sha256: event.payload.launch_sha256,
    preflight_evidence_id: event.payload.preflight_evidence_id,
    preflight_evidence: event.payload.preflight_evidence,
    promoted_at: event.accepted_at,
  };
  session.activated_state_revision = state.state_revision + 1;
  session.activated_control_epoch = event.control_epoch;
  session.activated_packet_revision = state.packet.revision;
  session.activated_packet_sha256 = state.packet.sha256;
  session.activated_full_head = state.full_head;
  session.activated_task_cycle = state.task_cycle;
}

function applyPacketUpdate(state, event) {
  assertControl(event.actor.role === 'FOREMAN', 'PACKET_UPDATE_AUTHORITY', '只有 FOREMAN 可更新 packet');
  assertControl(
    !state.p1.policy,
    'P1_PACKET_UPDATE_UNSUPPORTED',
    '机械 P1 v1 禁止 PACKET_UPDATED；须冻结新输入并初始化 fresh Goal',
  );
  assertControl(!['ACCEPTED_PENDING_MERGE', 'MERGED_TO_MAIN', 'ARCHIVED'].includes(state.phase), 'TASK_REOPEN_REQUIRED', `phase=${state.phase} 必须先显式 TASK_REOPEN，不能直接更新 packet`);
  const nextRevision = Number(event.payload.revision);
  const nextHash = normalizeHash(event.payload.sha256, 'new packet sha256');
  assertControl(Number.isSafeInteger(nextRevision) && nextRevision === state.packet.revision + 1, 'PACKET_REVISION_GAP', 'packet revision 必须恰好 +1');
  assertControl(typeof event.payload.path === 'string' && event.payload.path.length > 0, 'INVALID_PACKET_UPDATE', '新 packet path 缺失');
  const changeKind = event.payload.change_kind;
  assertControl(['CONTRACT', 'AC', 'SEAM', 'SCOPE', 'ENVIRONMENT', 'EXIT_CRITERIA', 'IMPLEMENTATION'].includes(changeKind), 'INVALID_PACKET_UPDATE', '未知 packet change_kind');
  state.packet = { revision: nextRevision, path: event.payload.path, sha256: nextHash };
  state.evidence = {};
  state.p1 = state.p1.policy ? { policy: state.p1.policy } : {};
  state.pr = null;
  state.recovery = null;
  state.recovery_backlog = [];
  state.full_head = event.full_head;
  state.task_cycle += 1;
  for (const role of ['CAPTAIN', 'DEV', 'REVIEW', 'RECEIPT']) {
    const session = state.sessions[role];
    if (!session) continue;
    session.status = 'terminal';
    session.completed_at = event.accepted_at;
    session.terminal_reason = 'PACKET_CHANGED';
  }
  state.phase = 'P1_ACTIVE';
}

function applyGithubMergeReserved(state, event) {
  assertControl(
    event.actor.role === 'FOREMAN',
    'GITHUB_MERGE_RESERVATION_AUTHORITY',
    'GitHub merge reservation 只能由 FOREMAN 建立',
  );
  assertControl(
    state.phase === 'ACCEPTED_PENDING_MERGE',
    'MERGE_PHASE_MISMATCH',
    `GitHub merge reservation 要求 ACCEPTED_PENDING_MERGE，当前 ${state.phase}`,
  );
  assertControl(
    !state.merge_reservation,
    'GITHUB_MERGE_RESERVATION_EXISTS',
    'task 已有 append-only GitHub merge reservation',
  );
  assertControl(
    event.payload.candidate_head === state.full_head
      && event.payload.pull_request_url === state.pr,
    'GITHUB_MERGE_RESERVATION_MISMATCH',
    'GitHub merge reservation 与 task PR/head 不一致',
  );
  state.merge_reservation = {
    status: 'ACTIVE',
    reservation_event_id: event.event_id,
    target_event_id: event.payload.target_event_id,
    request_sha256: event.payload.request_sha256,
    repository: event.payload.repository,
    pull_request_number: event.payload.pull_request_number,
    pull_request_url: event.payload.pull_request_url,
    base_branch: event.payload.base_branch,
    expected_main_head: event.payload.expected_main_head,
    candidate_head: event.payload.candidate_head,
    preflight_attestation: event.payload.preflight_attestation,
    pr_contract_sha256: event.payload.pr_contract_sha256,
    reserved_at: event.accepted_at,
  };
}

function applyControlReconciled(state, event, goalControlEpoch) {
  assertControl(event.actor.role === 'FOREMAN', 'CONTROL_RECONCILE_AUTHORITY', '只有 FOREMAN 可确认 control reconcile');
  assertControl(state.reconcile_required, 'CONTROL_RECONCILE_NOT_REQUIRED', '当前 task 不需要 control reconcile');
  assertControl(event.payload.control_event_id === state.reconcile_required.control_event_id, 'STALE_CONTROL_EPOCH', 'reconcile 未引用当前 control event');
  assertControl(typeof event.payload.instruction_ref === 'string' && event.payload.instruction_ref.length > 0, 'CONTROL_INSTRUCTION_REQUIRED', 'reconcile 缺 instruction_ref');
  state.last_reconciled_epoch = goalControlEpoch;
  state.reconcile_required = null;
  state.evidence = {};
  state.p1 = state.p1.policy ? { policy: state.p1.policy } : {};
  state.pr = null;
  state.recovery = null;
  state.recovery_backlog = [];
  state.merge = null;
  state.task_cycle += 1;
  for (const role of ['CAPTAIN', 'DEV', 'REVIEW', 'RECEIPT']) {
    const session = state.sessions[role];
    if (session && ['active', 'idle'].includes(session.status)) {
      session.status = 'terminal';
      session.completed_at = event.accepted_at;
      session.terminal_reason = 'CONTROL_EPOCH_CHANGED';
    }
  }
  if (state.p1.policy) {
    state.phase = 'QUEUED';
  } else if (state.phase !== 'QUEUED') {
    state.phase = 'P1_ACTIVE';
  }
}

const MECHANICAL_P1_RESTART_PHASES = Object.freeze([
  'P1_ACTIVE',
  'P1_READY',
  'P1_APPROVED',
]);

function mechanicalP1RestartEligible(state) {
  if (
    !state.p1.policy
      || !MECHANICAL_P1_RESTART_PHASES.includes(state.phase)
      || typeof state.p1.worktree !== 'string'
      || typeof state.p1.branch !== 'string'
  ) {
    return false;
  }
  const captain = state.sessions.CAPTAIN;
  const recoveredFrom = captain && captain.recovered_from;
  if (
    !captain
      || !['active', 'idle'].includes(captain.status)
      || captain.operational_scope !== 'FULL'
      || !recoveredFrom
      || recoveredFrom.role !== 'CAPTAIN'
      || !MECHANICAL_P1_RESTART_PHASES.includes(recoveredFrom.resume_phase)
      || !recoveredFrom.recovery_event_id
  ) {
    return false;
  }
  const resumeIndex = MECHANICAL_P1_RESTART_PHASES.indexOf(
    recoveredFrom.resume_phase,
  );
  const currentIndex = MECHANICAL_P1_RESTART_PHASES.indexOf(state.phase);
  if (currentIndex < resumeIndex) return false;
  return !captain.p1_restart
    || captain.p1_restart.recovery_event_id
      !== recoveredFrom.recovery_event_id;
}

function validateTransitionPayload(state, event, transition) {
  function requireLaunchSession(role) {
    const launchId = event.payload.launch_id;
    assertControl(typeof launchId === 'string' && launchId.length > 0, 'LAUNCH_ID_REQUIRED', `${event.type} 缺 launch_id`);
    const session = state.sessions[role];
    assertControl(session && ['active', 'idle'].includes(session.status), 'FRESH_SESSION_REQUIRED', `${event.type} 需要 active ${role} session`);
    assertControl(session.launch_id === launchId, 'LAUNCH_ID_MISMATCH', `${event.type} launch_id 与登记 session 不一致`);
    assertControl((session.activated_control_epoch ?? session.registered_control_epoch) === state.control_epoch, 'STALE_ROLE_REGISTRATION', `${role} registration control epoch 陈旧`);
    assertControl(
      (session.activated_packet_revision || session.registered_packet_revision) === state.packet.revision
        && (session.activated_packet_sha256 || session.registered_packet_sha256) === state.packet.sha256,
      'STALE_ROLE_REGISTRATION',
      `${role} registration packet 陈旧`,
    );
    assertControl((session.activated_full_head || session.registered_full_head) === state.full_head, 'STALE_ROLE_REGISTRATION', `${role} registration HEAD 陈旧`);
    assertControl((session.activated_task_cycle || session.registered_task_cycle) === state.task_cycle, 'STALE_ROLE_REGISTRATION', `${role} registration cycle 陈旧`);
    if (role === 'DEV' && session.recovered_from) {
      assertControl(session.operational_scope === 'FULL', 'RECOVERY_PROMOTION_REQUIRED', 'recovered DEV 尚未完成 handoff + fresh preflight promotion');
    }
  }
  switch (event.type) {
    case 'START_P1': {
      if (state.p1.policy) {
        assertControl(
          typeof event.payload.required_start_head === 'string',
          'P1_START_HEAD_REQUIRED',
          '机械 START_P1 缺 required_start_head',
        );
        assertFullSha(event.payload.required_start_head, 'required_start_head');
        state.p1.required_start_head = event.payload.required_start_head;
        assertControl(
          typeof event.payload.p1_worktree === 'string'
            && typeof event.payload.p1_branch === 'string',
          'P1_WORKTREE_BINDING_REQUIRED',
          '机械 START_P1 缺 worktree/branch binding',
        );
        state.p1.worktree = event.payload.p1_worktree;
        state.p1.branch = event.payload.p1_branch;
        state.base_head = event.payload.required_start_head;
        state.full_head = event.payload.required_start_head;
      } else {
        assertControl(
          event.payload.required_start_head === undefined
            && event.payload.p1_worktree === undefined
            && event.payload.p1_branch === undefined,
          'P1_POLICY_NOT_ENABLED',
          'legacy task 不接受 mechanical START_P1 binding',
        );
      }
      break;
    }
    case 'P1_READY': {
      state.p1.plan_path = event.payload.plan_path;
      state.p1.plan_sha256 = normalizeHash(event.payload.plan_sha256, 'plan_sha256');
      state.p1.context_path = event.payload.context_path;
      state.p1.context_sha256 = normalizeHash(event.payload.context_sha256, 'context_sha256');
      if (state.p1.policy) {
        assertControl(
          event.payload.artifact_manifest_sha256 !== undefined,
          'P1_ARTIFACT_MANIFEST_REQUIRED',
          '机械 P1_READY 缺 artifact_manifest_sha256',
        );
        state.p1.artifact_manifest_sha256 = normalizeHash(
          event.payload.artifact_manifest_sha256,
          'artifact_manifest_sha256',
        );
        assertControl(
          typeof event.payload.p1_worktree === 'string'
            && typeof event.payload.p1_branch === 'string',
          'P1_WORKTREE_BINDING_REQUIRED',
          '机械 P1_READY 缺 worktree/branch binding',
        );
        assertControl(
          event.payload.p1_worktree === state.p1.worktree
            && event.payload.p1_branch === state.p1.branch,
          'P1_WORKTREE_BINDING_MISMATCH',
          'P1_READY 必须来自 START_P1 绑定的同一 worktree/branch',
        );
        state.p1.approval_binding = {
          schema_version: 1,
          kind: 'SCOPED_DELEGATION_APPROVAL',
          task_id: state.task_id,
          authority: { ...state.p1.policy.authority },
          packet: {
            revision: state.packet.revision,
            sha256: state.packet.sha256,
          },
          artifacts: {
            plan_path: state.p1.plan_path,
            plan_sha256: state.p1.plan_sha256,
            context_path: state.p1.context_path,
            context_sha256: state.p1.context_sha256,
            artifact_manifest_sha256: state.p1.artifact_manifest_sha256,
          },
          source: {
            worktree: state.p1.worktree,
            branch: state.p1.branch,
            required_start_head: state.p1.required_start_head,
          },
        };
        state.p1.required_approval_ref = hashObject(state.p1.approval_binding);
      } else {
        assertControl(
          event.payload.artifact_manifest_sha256 === undefined
            && event.payload.p1_worktree === undefined
            && event.payload.p1_branch === undefined,
          'P1_POLICY_NOT_ENABLED',
          'legacy task 不接受 artifact_manifest_sha256',
        );
      }
      break;
    }
    case 'P1_APPROVED': {
      assertControl(typeof event.payload.approval_ref === 'string' && event.payload.approval_ref.trim().length > 0, 'P1_APPROVAL_REQUIRED', 'P1_APPROVED 缺用户批准引用');
      const approved = normalizeHash(event.payload.plan_sha256, 'approved plan_sha256');
      assertControl(approved === state.p1.plan_sha256, 'P1_APPROVAL_MISMATCH', '批准的 plan digest 与 P1_READY 不一致');
      assertControl(normalizeHash(event.payload.context_sha256, 'approved context_sha256') === state.p1.context_sha256, 'P1_APPROVAL_MISMATCH', '批准的 context digest 与 P1_READY 不一致');
      assertControl(event.payload.plan_path === state.p1.plan_path && event.payload.context_path === state.p1.context_path, 'P1_APPROVAL_MISMATCH', '批准的 plan/context path 与 P1_READY 不一致');
      if (state.p1.policy) {
        assertControl(
          normalizeHash(
            event.payload.artifact_manifest_sha256,
            'approved artifact_manifest_sha256',
          ) === state.p1.artifact_manifest_sha256,
          'P1_APPROVAL_MISMATCH',
          '批准的 artifact manifest digest 与 P1_READY 不一致',
        );
        assertControl(
          event.payload.approval_ref === state.p1.required_approval_ref,
          'P1_APPROVAL_AUTHORITY_MISMATCH',
          `approval_ref 必须机械绑定当前 authority/packet/artifacts: ${state.p1.required_approval_ref}`,
        );
        assertControl(
          event.payload.p1_worktree === state.p1.worktree
            && event.payload.p1_branch === state.p1.branch,
          'P1_APPROVAL_MISMATCH',
          '批准的 P1 worktree/branch binding 与 READY 不一致',
        );
      } else {
        assertControl(
          event.payload.artifact_manifest_sha256 === undefined
            && event.payload.p1_worktree === undefined
            && event.payload.p1_branch === undefined,
          'P1_POLICY_NOT_ENABLED',
          'legacy task 不接受 artifact_manifest_sha256',
        );
      }
      state.p1.approval_event_id = event.event_id;
      state.p1.approval_ref = event.payload.approval_ref;
      state.p1.approved_at = event.accepted_at;
      break;
    }
    case 'P1_COMMITTED': {
      assertControl(state.p1.approval_event_id, 'P1_APPROVAL_REQUIRED', 'P1 未批准，不能 commit');
      assertControl(normalizeHash(event.payload.plan_sha256, 'committed plan_sha256') === state.p1.plan_sha256, 'P1_COMMIT_MISMATCH', 'commit 的 plan digest 与批准版本不一致');
      assertControl(normalizeHash(event.payload.context_sha256, 'committed context_sha256') === state.p1.context_sha256, 'P1_COMMIT_MISMATCH', 'commit 的 context digest 与批准版本不一致');
      assertControl(event.payload.plan_path === state.p1.plan_path && event.payload.context_path === state.p1.context_path, 'P1_COMMIT_MISMATCH', 'commit 的 plan/context path 与批准版本不一致');
      assertControl(event.payload.approval_event_id === state.p1.approval_event_id, 'P1_APPROVAL_MISMATCH', 'P1 commit 未引用当前 approval event');
      if (state.p1.policy) {
        assertControl(
          normalizeHash(
            event.payload.artifact_manifest_sha256,
            'committed artifact_manifest_sha256',
          ) === state.p1.artifact_manifest_sha256,
          'P1_COMMIT_MISMATCH',
          'commit 的 artifact manifest digest 与批准版本不一致',
        );
        assertControl(
          event.payload.p1_worktree === state.p1.worktree
            && event.payload.p1_branch === state.p1.branch,
          'P1_COMMIT_MISMATCH',
          'commit 的 P1 worktree/branch binding 与 READY 不一致',
        );
      } else {
        assertControl(
          event.payload.artifact_manifest_sha256 === undefined
            && event.payload.p1_worktree === undefined
            && event.payload.p1_branch === undefined,
          'P1_POLICY_NOT_ENABLED',
          'legacy task 不接受 artifact_manifest_sha256',
        );
      }
      state.p1.commit_sha = event.full_head;
      if (state.p1.policy) {
        assertControl(
          typeof event.payload.p1_commit_ref === 'string'
            && event.payload.p1_commit_ref.startsWith('refs/heads/'),
          'P1_COMMIT_REF_REQUIRED',
          '机械 P1_COMMITTED 缺 controller-owned durable ref',
        );
        state.p1.commit_ref = event.payload.p1_commit_ref;
        state.p1.commit_branch = event.payload.p1_commit_ref.slice(
          'refs/heads/'.length,
        );
        if (event.p1_commit_transaction) {
          state.p1.commit_transaction = JSON.parse(JSON.stringify(
            event.p1_commit_transaction,
          ));
        }
      } else {
        assertControl(
          event.payload.p1_commit_ref === undefined,
          'P1_POLICY_NOT_ENABLED',
          'legacy task 不接受 p1_commit_ref',
        );
      }
      break;
    }
    case 'P1_RESTARTED': {
      assertControl(
        mechanicalP1RestartEligible(state),
        'P1_RESTART_NOT_ELIGIBLE',
        'P1_RESTARTED 仅适用于 lost CAPTAIN 的 active recovery successor',
      );
      const captain = state.sessions.CAPTAIN;
      const recoveredFrom = captain.recovered_from;
      assertControl(
        event.payload.captain_recovery_event_id
          === recoveredFrom.recovery_event_id
          && event.payload.predecessor_thread_id
            === recoveredFrom.thread_id
          && event.payload.predecessor_host_id === recoveredFrom.host_id
          && event.payload.predecessor_attempt === recoveredFrom.attempt
          && event.payload.successor_thread_id === captain.thread_id
          && event.payload.successor_host_id === captain.host_id
          && event.payload.successor_attempt === captain.attempt,
        'P1_RESTART_IDENTITY_MISMATCH',
        'P1_RESTARTED identity/recovery binding 与当前 CAPTAIN lineage 不一致',
      );
      assertControl(
        event.payload.abandoned_p1_worktree === state.p1.worktree
          && event.payload.abandoned_p1_branch === state.p1.branch,
        'P1_RESTART_BINDING_MISMATCH',
        'P1_RESTARTED 未精确引用被放弃的 P1 worktree/branch',
      );
      assertControl(
        typeof event.payload.reason === 'string'
          && event.payload.reason.trim().length > 0
          && typeof event.payload.incident_ref === 'string'
          && event.payload.incident_ref.trim().length > 0,
        'P1_RESTART_JUSTIFICATION_REQUIRED',
        'P1_RESTARTED 缺 reason/incident_ref',
      );
      captain.p1_restart = {
        event_id: event.event_id,
        recovery_event_id: recoveredFrom.recovery_event_id,
        abandoned_phase: state.phase,
        abandoned_worktree: state.p1.worktree,
        abandoned_branch: state.p1.branch,
        reason: event.payload.reason,
        incident_ref: event.payload.incident_ref,
        restarted_at: event.accepted_at,
      };
      state.p1 = { policy: state.p1.policy };
      state.evidence = {};
      state.pr = null;
      state.merge = null;
      state.task_cycle += 1;
      break;
    }
    case 'LAUNCH_DEV':
      requireLaunchSession('DEV');
      break;
    case 'DEV_READY': {
      state.evidence.dev = validateDevEvidence(event.payload.evidence, state.packet.sha256, event.full_head);
      assertControl(typeof event.payload.pr === 'string' && event.payload.pr.length > 0, 'PR_REQUIRED', 'DEV_READY 必须带 PR');
      state.pr = event.payload.pr;
      break;
    }
    case 'LAUNCH_REVIEW':
      assertControl(state.evidence.dev, 'EVIDENCE_REQUIRED', '缺 DEV deterministic evidence，不能启动 REVIEW');
      requireLaunchSession('REVIEW');
      break;
    case 'REVIEW_REWORK':
      assertControl(event.payload.review_evidence && event.payload.review_evidence.evidence_id, 'EVIDENCE_REQUIRED', 'REVIEW_REWORK 缺 review evidence');
      state.evidence.review = null;
      state.evidence.receipt = null;
      state.sessions.REVIEW.status = 'terminal';
      state.sessions.REVIEW.completed_at = event.accepted_at;
      break;
    case 'REVIEW_PASS':
      state.evidence.review = validateSingleEvidence(event.payload.evidence, 'review', state.packet.sha256, state.full_head);
      state.sessions.REVIEW.status = 'terminal';
      state.sessions.REVIEW.completed_at = event.accepted_at;
      break;
    case 'LAUNCH_RECEIPT':
      assertControl(state.evidence.review, 'EVIDENCE_REQUIRED', '缺当前 HEAD 的 REVIEW PASS');
      requireLaunchSession('RECEIPT');
      break;
    case 'RECEIPT_FAIL':
      assertControl(event.payload.receipt_evidence && event.payload.receipt_evidence.evidence_id, 'EVIDENCE_REQUIRED', 'RECEIPT_FAIL 缺 evidence');
      state.evidence.receipt = null;
      state.sessions.RECEIPT.status = 'terminal';
      state.sessions.RECEIPT.completed_at = event.accepted_at;
      break;
    case 'REOPEN_REVIEW':
      requireLaunchSession('REVIEW');
      break;
    case 'RECEIPT_PASS':
      state.evidence.receipt = validateSingleEvidence(event.payload.evidence, 'receipt', state.packet.sha256, state.full_head);
      state.sessions.RECEIPT.status = 'terminal';
      state.sessions.RECEIPT.completed_at = event.accepted_at;
      break;
    case 'READY_FOR_MERGE':
      assertControl(state.evidence.review && state.evidence.receipt, 'EVIDENCE_REQUIRED', '缺 review/receipt evidence');
      break;
    case 'TASK_REOPEN':
      assertControl(typeof event.payload.reason === 'string' && event.payload.reason.length > 0, 'REOPEN_REASON_REQUIRED', 'TASK_REOPEN 缺 reason');
      assertControl(event.payload.merge_boundary_evidence && event.payload.merge_boundary_evidence.evidence_id, 'EVIDENCE_REQUIRED', 'TASK_REOPEN 缺可信 evidence');
      state.evidence = {};
      break;
    case 'MERGED':
      assertFullSha(event.payload.main_merge_sha, 'main_merge_sha');
      assertFullSha(event.payload.expected_main_head, 'expected_main_head');
      if (event.payload.merge_receipt_sha256 !== undefined) {
        assertControl(
          /^sha256:[0-9a-f]{64}$/.test(event.payload.merge_receipt_sha256),
          'INVALID_EVENT',
          'merge_receipt_sha256 必须是 canonical SHA-256',
        );
      }
      if (state.merge_reservation) {
        assertControl(
          state.merge_reservation.status === 'ACTIVE'
            && state.merge_reservation.target_event_id === event.event_id
            && event.payload.merge_reservation_event_id
              === state.merge_reservation.reservation_event_id
            && event.payload.merge_request_sha256
              === state.merge_reservation.request_sha256,
          'GITHUB_MERGE_RESERVATION_MISMATCH',
          'MERGED 未消费 matching append-only GitHub merge reservation',
        );
        state.merge_reservation = {
          ...state.merge_reservation,
          status: 'CONSUMED',
          consumed_by_event_id: event.event_id,
          consumed_at: event.accepted_at,
        };
      }
      state.merge = {
        pr_head: state.full_head,
        expected_main_head: event.payload.expected_main_head,
        main_merge_sha: event.payload.main_merge_sha,
        ...(event.payload.merge_receipt_sha256
          ? { receipt_sha256: event.payload.merge_receipt_sha256 }
          : {}),
        ...(event.payload.merge_reservation_event_id
          ? {
            reservation_event_id:
              event.payload.merge_reservation_event_id,
          }
          : {}),
        merged_at: event.accepted_at,
      };
      if (
        state.sessions.DEV
          && ['active', 'idle'].includes(state.sessions.DEV.status)
      ) {
        state.sessions.DEV.status = 'terminal';
        state.sessions.DEV.completed_at = event.accepted_at;
        state.sessions.DEV.terminal_reason = 'TASK_MERGED';
      }
      break;
    case 'ARCHIVED':
      assertControl(
        state.merge
          && state.evidence.dev
          && state.evidence.review
          && state.evidence.receipt,
        'ARCHIVE_EVIDENCE_INCOMPLETE',
        'ARCHIVED 需要完整 DEV/REVIEW/RECEIPT/merge 证据链',
      );
      assertControl(
        event.payload.archive_evidence
          && event.payload.archive_evidence.evidence_id,
        'ARCHIVE_EVIDENCE_REQUIRED',
        'ARCHIVED 缺可信 archive evidence',
      );
      state.evidence.archive = event.payload.archive_evidence;
      for (const role of ['CAPTAIN', 'DEV', 'REVIEW', 'RECEIPT']) {
        const session = state.sessions[role];
        if (!session || !['active', 'idle'].includes(session.status)) continue;
        session.status = 'terminal';
        session.completed_at = event.accepted_at;
        session.terminal_reason = 'TASK_ARCHIVED';
      }
      break;
    default:
      break;
  }
  if (transition.updatesHead) state.full_head = event.full_head;
}

function applyEvent(previousState, event, goalControlEpoch) {
  const state = JSON.parse(JSON.stringify(previousState));
  const transition = TRANSITIONS[event.type];
  assertControl(transition || NON_TRANSITION_EVENTS.has(event.type), 'UNKNOWN_EVENT_TYPE', `未知事件类型 ${event.type}`);
  validateCommonBinding(state, event, goalControlEpoch, { updatesHead: Boolean(transition && transition.updatesHead) || event.type === 'PACKET_UPDATED' });

  event.accepted_at = event.accepted_at || nowIso();
  if (state.phase === 'ARCHIVED') {
    assertControl(
      event.type === 'HEARTBEAT' && event.actor.role === 'FOREMAN',
      'TASK_TERMINAL',
      'ARCHIVED task 只保留既有 Goal FOREMAN heartbeat；禁止 registration/recovery/hold/资源或业务迁移',
    );
  }
  if (event.type === 'REGISTER_ROLE') {
    applyRegistration(state, event);
  } else if (event.type === 'RECOVER_EXPIRED_FOREMAN') {
    applyExpiredForemanRecovery(state, event);
  } else {
    validateRegisteredActor(state, event);
    const actorKey = actorSequenceKey(event.actor);
    state.actor_sequences[actorKey] = event.actor_sequence;
    if (event.type === 'HEARTBEAT') applyHeartbeat(state, event);
    else if (event.type === 'PROBE_OBSERVATION_REFRESHED') {
      applyProbeObservationRefreshed(state, event);
    }
    else if (event.type === 'CONTROL_RECONCILED') applyControlReconciled(state, event, goalControlEpoch);
    else if (event.type === 'ADD_HOLD') applyHold(state, event);
    else if (event.type === 'RESOLVE_HOLD') resolveHold(state, event);
    else if (event.type === 'RUNTIME_ROTATED') applyRuntimeRotated(state, event);
    else if (event.type === 'ROLE_LOST') applyRoleLost(state, event);
    else if (event.type === 'ROLE_RECOVERED') applyRoleRecovered(state, event);
    else if (event.type === 'RECOVERY_HANDOFF_BOUND') applyRecoveryHandoffBound(state, event);
    else if (event.type === 'RECOVERY_HANDOFF_ABANDONED') applyRecoveryHandoffAbandoned(state, event);
    else if (event.type === 'RECOVERY_PROMOTED') applyRecoveryPromoted(state, event);
    else if (event.type === 'PACKET_UPDATED') applyPacketUpdate(state, event);
    else if (event.type === 'GITHUB_MERGE_RESERVED') {
      applyGithubMergeReserved(state, event);
    }
    else if (event.type === 'P1_COMMIT_ABANDONED') {
      applyP1CommitAbandoned(state, event);
    }
    else {
      assertControl(!state.recovery, 'RECOVERY_REQUIRED', `角色 ${state.recovery && state.recovery.role} 待恢复，不能推进状态`);
      assertControl(
        !Array.isArray(state.recovery_backlog) || state.recovery_backlog.length === 0,
        'RECOVERY_BACKLOG_REQUIRED',
        `角色 ${state.recovery_backlog && state.recovery_backlog.map((item) => item.role).join(',')} 待恢复，不能推进状态`,
      );
      assertControl(!state.reconcile_required, 'CONTROL_RECONCILE_REQUIRED', `task 尚未 reconcile control epoch ${state.reconcile_required && state.reconcile_required.to_epoch}`);
      assertControl(state.holds.length === 0, 'TASK_HELD', `任务存在 hold: ${state.holds.map((hold) => hold.kind).join(', ')}`);
      assertControl(transition.from.includes(state.phase), 'ILLEGAL_TRANSITION', `${event.type} 不能从 ${state.phase} 执行`);
      assertControl(transition.roles.includes(event.actor.role), 'WRONG_ACTOR_ROLE', `${event.type} 只能由 ${transition.roles.join('/')} 执行`);
      validateTransitionPayload(state, event, transition);
      state.phase = transition.to;
    }
  }

  state.state_revision += 1;
  state.control_epoch = goalControlEpoch;
  state.last_event = {
    event_id: event.event_id,
    type: event.type,
    actor_role: event.actor.role,
    accepted_at: event.accepted_at,
    control_epoch: event.control_epoch,
    event_sha256: event.event_sha256 || hashObject(event),
  };
  return state;
}

function allowedActions(state) {
  if (state.phase === 'ARCHIVED') return [];
  if (state.reconcile_required) return [{ type: 'CONTROL_RECONCILED', actor_role: 'FOREMAN', control_event_id: state.reconcile_required.control_event_id }];
  if (state.recovery) return [{ type: 'ROLE_RECOVERED', actor_role: state.recovery.role === 'CAPTAIN' ? 'FOREMAN' : 'CAPTAIN' }];
  if (Array.isArray(state.recovery_backlog) && state.recovery_backlog.length > 0) {
    return [{ type: 'ROLE_LOST', actor_role: 'FOREMAN', target_role: 'CAPTAIN' }];
  }
  if (state.holds.length > 0) {
    return [
      ...state.holds.map((hold) => ({
        type: 'RESOLVE_HOLD',
        actor_role: hold.hard ? 'FOREMAN' : 'CAPTAIN|FOREMAN',
        hold_id: hold.hold_id,
      })),
      {
        type: 'ROLE_LOST',
        actor_role: 'FOREMAN|CAPTAIN',
      },
    ];
  }
  const recoveredDev = state.sessions.DEV;
  if (
    state.phase === 'DEV_ACTIVE'
    && recoveredDev
    && recoveredDev.recovered_from
    && recoveredDev.operational_scope !== 'FULL'
  ) {
    return recoveredDev.operational_scope === 'RECOVERY_BLOCKED'
      ? [
        ...(!recoveredDev.recovery_retarget_required
          ? [{ type: 'RECOVERY_HANDOFF_BOUND', actor_role: 'CAPTAIN' }]
          : []),
        { type: 'ADD_HOLD', actor_role: ROLES.join('|') },
        { type: 'ROLE_LOST', actor_role: 'CAPTAIN', target_role: 'DEV' },
      ]
      : [
        { type: 'RECOVERY_PROMOTED', actor_role: 'CAPTAIN' },
        { type: 'RECOVERY_HANDOFF_ABANDONED', actor_role: 'CAPTAIN', joint_authorizer_role: 'FOREMAN' },
        { type: 'ADD_HOLD', actor_role: ROLES.join('|') },
      ];
  }
  const actions = [];
  for (const [type, transition] of Object.entries(TRANSITIONS)) {
    if (
      transition.from.includes(state.phase)
        && (type !== 'P1_RESTARTED' || mechanicalP1RestartEligible(state))
    ) {
      actions.push({ type, actor_role: transition.roles.join('|') });
    }
  }
  actions.push({ type: 'ADD_HOLD', actor_role: ROLES.join('|') });
  actions.push({ type: 'ROLE_LOST', actor_role: 'FOREMAN|CAPTAIN' });
  return actions;
}

module.exports = {
  EXPECTED_ACTIVE_ROLE,
  TRANSITIONS,
  actorSequenceKey,
  allowedActions,
  applyEvent,
  expectedRoleForPhase,
  foremanRootRecoveryStatusEligible,
  initialTaskState,
};
