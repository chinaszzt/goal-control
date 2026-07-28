'use strict';

const { assertControl } = require('./errors');
const { actorSequenceKey } = require('./fsm');
const { hashObject, nowIso, safeId } = require('./util');

const INCIDENT_AUTHORITY_KIND = 'IDENTITY_INCIDENT_EVENT_AUTHORITY';

function sealIdentityIncidentEventAuthority({
  event,
  evidenceId,
  session,
  task,
  controlEpoch,
  preparedAcceptedAt = nowIso(),
}) {
  safeId(evidenceId, 'identity incident evidence_id');
  assertControl(
    event
      && event.type === 'ADD_HOLD'
      && event.payload
      && event.payload.kind === 'ENV_IDENTITY_INCIDENT'
      && event.payload.evidence_id === evidenceId,
    'CORRUPT_STORE',
    'identity incident authority 只能封装 exact ENV_IDENTITY_INCIDENT ADD_HOLD',
  );
  assertControl(
    session
      && session.role === event.actor.role
      && session.thread_id === event.actor.thread_id
      && session.host_id === event.actor.host_id
      && Number.isSafeInteger(session.attempt)
      && typeof session.lease_until === 'string'
      && typeof session.capability_file === 'string'
      && typeof session.capability_sha256 === 'string',
    'CORRUPT_STORE',
    'identity incident authority producer binding 非法',
  );
  assertControl(
    Number.isFinite(Date.parse(preparedAcceptedAt))
      && Date.parse(preparedAcceptedAt) <= Date.parse(session.lease_until),
    'ACTOR_LEASE_EXPIRED',
    'identity incident authority 必须在 producer lease 内预封装',
  );
  const sequenceKey = actorSequenceKey(session);
  const priorActorSequence = task.actor_sequences[sequenceKey] || 0;
  assertControl(
    event.actor_sequence === priorActorSequence + 1
      && event.expected_state_revision === task.state_revision
      && event.control_epoch === controlEpoch
      && hashObject(event.packet) === hashObject({
        revision: task.packet.revision,
        sha256: task.packet.sha256,
      })
      && event.base_head === task.base_head
      && event.full_head === task.full_head,
    'CORRUPT_STORE',
    'identity incident authority task/event anchor 不一致',
  );
  const unsigned = {
    schema_version: 1,
    kind: INCIDENT_AUTHORITY_KIND,
    goal_id: event.goal_id,
    task_id: event.task_id,
    evidence_id: evidenceId,
    event_id: event.event_id,
    event_input_sha256: hashObject(event),
    prepared_accepted_at: preparedAcceptedAt,
    producer: {
      role: session.role,
      thread_id: session.thread_id,
      host_id: session.host_id,
      attempt: session.attempt,
      lease_until: session.lease_until,
      capability_file: session.capability_file,
      capability_sha256: session.capability_sha256,
    },
    task_anchor: {
      control_epoch: controlEpoch,
      state_revision: task.state_revision,
      packet: {
        revision: task.packet.revision,
        sha256: task.packet.sha256,
      },
      base_head: task.base_head,
      full_head: task.full_head,
      actor_sequence_key: sequenceKey,
      prior_actor_sequence: priorActorSequence,
    },
  };
  return {
    ...unsigned,
    authority_sha256: hashObject(unsigned),
  };
}

function preparedIdentityIncidentAuthorization(evidenceId, authority) {
  assertControl(
    authority
      && authority.kind === INCIDENT_AUTHORITY_KIND
      && authority.evidence_id === evidenceId
      && typeof authority.authority_sha256 === 'string',
    'CORRUPT_STORE',
    'identity incident event authority 缺失或绑定漂移',
  );
  return {
    preparedIdentityIncident: {
      evidenceId,
      authoritySha256: authority.authority_sha256,
    },
  };
}

module.exports = {
  INCIDENT_AUTHORITY_KIND,
  preparedIdentityIncidentAuthorization,
  sealIdentityIncidentEventAuthority,
};
