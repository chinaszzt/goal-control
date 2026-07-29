'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { assertControl } = require('./errors');
const {
  assertNoSensitiveStringLeaves,
} = require('./canary-observation-receipt');
const {
  canonicalJson,
  hashFile,
  hashObject,
  normalizeHash,
  safeId,
} = require('./util');

const OBSERVATION_KIND = 'GOALCTL_HOST_ROLE_IDENTITY_OBSERVATION_V1';
const INTENT_KIND = 'ROLE_IDENTITY_INTENT';
const ROLES = new Set(['FOREMAN', 'CAPTAIN', 'DEV', 'REVIEW', 'RECEIPT']);
const MAX_RECEIPT_BYTES = 64 * 1024;
const RFC3339_UTC_MILLIS_RE =
  /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/;

function exactKeys(value, keys, label, code) {
  assertControl(
    value
      && typeof value === 'object'
      && !Array.isArray(value)
      && Object.keys(value).length === keys.length
      && Object.keys(value).every((key) => keys.includes(key)),
    code,
    `${label} 字段非法`,
  );
}

function assertPrivateReceipt(file) {
  assertControl(
    typeof file === 'string' && path.isAbsolute(file),
    'ROLE_IDENTITY_OBSERVATION_INVALID',
    'role identity observation 必须使用 absolute receipt path',
  );
  let canonical;
  try {
    canonical = fs.realpathSync(file);
  } catch {
    assertControl(
      false,
      'ROLE_IDENTITY_OBSERVATION_INVALID',
      'role identity observation receipt 不存在',
    );
  }
  assertControl(
    canonical === path.normalize(file),
    'ROLE_IDENTITY_OBSERVATION_INVALID',
    'role identity observation receipt path 必须 canonical',
  );
  const stat = fs.lstatSync(canonical);
  const parent = fs.lstatSync(path.dirname(canonical));
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && stat.nlink === 1
      && stat.size > 0
      && stat.size <= MAX_RECEIPT_BYTES
      && (stat.mode & 0o077) === 0
      && parent.isDirectory()
      && !parent.isSymbolicLink()
      && (parent.mode & 0o077) === 0
      && (
        typeof process.getuid !== 'function'
          || (stat.uid === process.getuid() && parent.uid === process.getuid())
      ),
    'ROLE_IDENTITY_OBSERVATION_INVALID',
    'role identity observation receipt/parent 必须为当前 owner 私有普通对象',
  );
  return {
    file: canonical,
    identity_sha256: hashObject({
      canonical_path_sha256: `sha256:${
        crypto.createHash('sha256').update(canonical).digest('hex')
      }`,
      device: String(stat.dev),
      inode: String(stat.ino),
      size: stat.size,
      uid: stat.uid,
      mode: stat.mode & 0o777,
      nlink: stat.nlink,
    }),
  };
}

function publicKey(hostAttestation) {
  assertControl(
    hostAttestation
      && hostAttestation.algorithm === 'ED25519'
      && typeof hostAttestation.key_id === 'string'
      && typeof hostAttestation.public_key_sha256 === 'string'
      && typeof hostAttestation.public_key_spki_base64 === 'string',
    'ROLE_IDENTITY_OBSERVATION_INVALID',
    'manifest host attestation authority 非法',
  );
  const bytes = Buffer.from(
    hostAttestation.public_key_spki_base64,
    'base64',
  );
  assertControl(
    `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`
      === normalizeHash(
        hostAttestation.public_key_sha256,
        'host attestation public key sha256',
      ),
    'ROLE_IDENTITY_OBSERVATION_INVALID',
    'manifest host attestation public key hash 不匹配',
  );
  return crypto.createPublicKey({
    key: bytes,
    format: 'der',
    type: 'spki',
  });
}

function canonicalTimestamp(value, label, code) {
  const milliseconds = typeof value === 'string'
    && RFC3339_UTC_MILLIS_RE.test(value)
    ? Date.parse(value)
    : Number.NaN;
  assertControl(
    Number.isFinite(milliseconds)
      && RFC3339_UTC_MILLIS_RE.test(value),
    code,
    `${label} 必须是 exact RFC3339 UTC millisecond timestamp`,
  );
  return milliseconds;
}

function assertActualIdentityAliases(record) {
  assertControl(
    record.host_id.toLowerCase() !== 'local'
      && record.thread_id.toLowerCase() !== 'local'
      && !/^(foreman|captain|dev|review|receipt)(?:-1|-a-[1-9][0-9]*)$/i
        .test(record.thread_id),
    'ROLE_IDENTITY_SYNTHETIC_ALIAS_FORBIDDEN',
    'role identity 禁止 synthetic thread/host alias',
  );
}

function validateRoleIdentityObservationStructure(record) {
  assertNoSensitiveStringLeaves(record);
  exactKeys(record, [
    'schema_version',
    'kind',
    'operation_id',
    'goal_id',
    'task_id',
    'role',
    'thread_id',
    'host_id',
    'session_id',
    'launch_id',
    'repository_head',
    'worker_bootstrap_binding_sha256',
    'observed_at',
    'expires_at',
    'attestation',
    'record_sha256',
  ], 'role identity observation', 'ROLE_IDENTITY_OBSERVATION_INVALID');
  exactKeys(record.attestation, [
    'algorithm',
    'key_id',
    'public_key_sha256',
    'signature_base64url',
  ], 'role identity observation.attestation', 'ROLE_IDENTITY_OBSERVATION_INVALID');
  assertControl(
    record.schema_version === 1
      && record.kind === OBSERVATION_KIND
      && ROLES.has(record.role)
      && /^[0-9a-f]{40}$/.test(record.repository_head || '')
      && (
        record.launch_id === null
          || typeof record.launch_id === 'string'
      )
      && (
        record.worker_bootstrap_binding_sha256 === null
          || /^sha256:[0-9a-f]{64}$/.test(
            record.worker_bootstrap_binding_sha256,
          )
      )
      && record.attestation.algorithm === 'ED25519'
      && safeId(
        record.attestation.key_id,
        'role identity observation attestation key_id',
      )
      && /^sha256:[0-9a-f]{64}$/.test(
        record.attestation.public_key_sha256 || '',
      )
      && /^[A-Za-z0-9_-]{86}$/.test(
        record.attestation.signature_base64url || '',
      )
      && /^sha256:[0-9a-f]{64}$/.test(record.record_sha256 || ''),
    'ROLE_IDENTITY_OBSERVATION_INVALID',
    'role identity observation schema 非法',
  );
  for (const [value, label] of [
    [record.operation_id, 'operation_id'],
    [record.goal_id, 'goal_id'],
    [record.task_id, 'task_id'],
    [record.thread_id, 'thread_id'],
    [record.host_id, 'host_id'],
    [record.session_id, 'session_id'],
  ]) {
    safeId(value, `role identity observation ${label}`);
  }
  if (record.launch_id !== null) {
    safeId(record.launch_id, 'role identity observation launch_id');
  }
  assertActualIdentityAliases(record);
  canonicalTimestamp(
    record.observed_at,
    'role identity observation observed_at',
    'ROLE_IDENTITY_OBSERVATION_INVALID',
  );
  canonicalTimestamp(
    record.expires_at,
    'role identity observation expires_at',
    'ROLE_IDENTITY_OBSERVATION_INVALID',
  );
  return record;
}

function validateRoleIdentityObservation(options) {
  const trustedFile = assertPrivateReceipt(options.receiptFile);
  const file = trustedFile.file;
  assertControl(
    hashFile(file) === normalizeHash(
      options.receiptSha256,
      'role identity observation receipt sha256',
    ),
    'ROLE_IDENTITY_OBSERVATION_HASH_MISMATCH',
    'role identity observation receipt content hash 不匹配',
  );
  let record;
  try {
    record = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    assertControl(
      false,
      'ROLE_IDENTITY_OBSERVATION_INVALID',
      'role identity observation receipt 不是合法 JSON',
    );
  }
  validateRoleIdentityObservationStructure(record);
  assertControl(
    record.schema_version === 1
      && record.kind === OBSERVATION_KIND
      && record.operation_id === options.operationId
      && record.goal_id === options.goalId
      && record.task_id === options.taskId
      && record.role === options.role
      && ROLES.has(record.role)
      && /^[0-9a-f]{40}$/.test(record.repository_head || '')
      && record.repository_head === options.repositoryHead
      && (
        record.launch_id === null
          || typeof record.launch_id === 'string'
      )
      && (
        record.worker_bootstrap_binding_sha256 === null
          || /^sha256:[0-9a-f]{64}$/.test(
            record.worker_bootstrap_binding_sha256,
          )
      ),
    'ROLE_IDENTITY_OBSERVATION_BINDING_MISMATCH',
    'role identity observation Goal/task/role/operation/HEAD binding 不匹配',
  );
  const observedAt = canonicalTimestamp(
    record.observed_at,
    'role identity observation observed_at',
    'ROLE_IDENTITY_OBSERVATION_INVALID',
  );
  const expiresAt = canonicalTimestamp(
    record.expires_at,
    'role identity observation expires_at',
    'ROLE_IDENTITY_OBSERVATION_INVALID',
  );
  const now = options.acceptanceTime === undefined
    ? Date.now()
    : Date.parse(options.acceptanceTime);
  assertControl(
    Number.isFinite(observedAt)
      && Number.isFinite(expiresAt)
      && Number.isFinite(now)
      && observedAt <= now
      && now < expiresAt
      && expiresAt - observedAt > 0
      && expiresAt - observedAt <= options.maxTtlMs,
    'ROLE_IDENTITY_OBSERVATION_EXPIRED',
    'role identity observation 时间/TTL 非法、未来或已过期',
  );
  const attestation = options.hostAttestation;
  assertControl(
    record.attestation.algorithm === attestation.algorithm
      && record.attestation.key_id === attestation.key_id
      && record.attestation.public_key_sha256
        === attestation.public_key_sha256
      && /^[A-Za-z0-9_-]{86}$/.test(
        record.attestation.signature_base64url || '',
      ),
    'ROLE_IDENTITY_OBSERVATION_AUTHENTICATION_INVALID',
    'role identity observation attestation authority 不匹配',
  );
  const sealed = { ...record };
  delete sealed.record_sha256;
  assertControl(
    record.record_sha256 === hashObject(sealed),
    'ROLE_IDENTITY_OBSERVATION_AUTHENTICATION_INVALID',
    'role identity observation record seal 不匹配',
  );
  const signed = {
    ...sealed,
    attestation: {
      algorithm: sealed.attestation.algorithm,
      key_id: sealed.attestation.key_id,
      public_key_sha256: sealed.attestation.public_key_sha256,
    },
  };
  assertControl(
    crypto.verify(
      null,
      Buffer.from(canonicalJson(signed)),
      publicKey(attestation),
      Buffer.from(
        record.attestation.signature_base64url,
        'base64url',
      ),
    ),
    'ROLE_IDENTITY_OBSERVATION_AUTHENTICATION_INVALID',
    'role identity observation signature 非法',
  );
  return {
    record: JSON.parse(JSON.stringify(record)),
    receipt_file_identity_sha256: trustedFile.identity_sha256,
  };
}

function validateRoleIdentityIntent(value) {
  assertNoSensitiveStringLeaves(value);
  exactKeys(value, [
    'schema_version',
    'kind',
    'operation_id',
    'goal_id',
    'task_id',
    'role',
    'thread_id',
    'host_id',
    'attempt',
    'session_id',
    'launch_id',
    'state_revision',
    'control_epoch',
    'packet',
    'base_head',
    'full_head',
    'task_cycle',
    'identity_observation',
    'issuer_authority',
    'created_at',
    'intent_sha256',
  ], 'role identity intent', 'ROLE_IDENTITY_INTENT_INVALID');
  exactKeys(value.packet, [
    'revision',
    'sha256',
  ], 'role identity intent.packet', 'ROLE_IDENTITY_INTENT_INVALID');
  exactKeys(value.identity_observation, [
    'receipt_sha256',
    'receipt_file_identity_sha256',
    'record_sha256',
    'attestation_key_id',
    'observed_at',
    'expires_at',
    'worker_bootstrap_binding_sha256',
  ], 'role identity intent.identity_observation', 'ROLE_IDENTITY_INTENT_INVALID');
  exactKeys(value.issuer_authority, [
    'kind',
    'capability_sha256',
    'source_task_id',
    'role',
    'thread_id',
    'host_id',
    'attempt',
    'session_id',
    'lease_until',
    'registration_event_id',
    'bootstrap_init_receipt_sha256',
    'recovery_scope_sha256',
  ], 'role identity intent.issuer_authority', 'ROLE_IDENTITY_INTENT_INVALID');
  const unsigned = { ...value };
  delete unsigned.intent_sha256;
  assertControl(
    value.schema_version === 1
      && value.kind === INTENT_KIND
      && ROLES.has(value.role)
      && Number.isSafeInteger(value.attempt)
      && value.attempt > 0
      && Number.isSafeInteger(value.state_revision)
      && value.state_revision >= 0
      && Number.isSafeInteger(value.control_epoch)
      && value.control_epoch >= 0
      && Number.isSafeInteger(value.packet.revision)
      && value.packet.revision > 0
      && /^sha256:[0-9a-f]{64}$/.test(value.packet.sha256 || '')
      && /^[0-9a-f]{40}$/.test(value.base_head || '')
      && /^[0-9a-f]{40}$/.test(value.full_head || '')
      && Number.isSafeInteger(value.task_cycle)
      && value.task_cycle > 0
      && /^sha256:[0-9a-f]{64}$/.test(
        value.identity_observation.receipt_sha256 || '',
      )
      && /^sha256:[0-9a-f]{64}$/.test(
        value.identity_observation.receipt_file_identity_sha256 || '',
      )
      && /^sha256:[0-9a-f]{64}$/.test(
        value.identity_observation.record_sha256 || '',
      )
      && /^[0-9a-f]{64}$/.test(
        value.issuer_authority.capability_sha256 || '',
      )
      && [
        'BOOTSTRAP',
        'SESSION',
        'CURRENT_SESSION',
        'GOAL_RECOVERY',
      ].includes(value.issuer_authority.kind)
      && (
        value.issuer_authority.kind !== 'BOOTSTRAP'
          || (
            value.issuer_authority.source_task_id === null
              && value.issuer_authority.role === null
              && value.issuer_authority.thread_id === null
              && value.issuer_authority.host_id === null
              && value.issuer_authority.attempt === null
              && value.issuer_authority.session_id === null
              && value.issuer_authority.lease_until === null
              && value.issuer_authority.registration_event_id === null
              && /^sha256:[0-9a-f]{64}$/.test(
                value.issuer_authority
                  .bootstrap_init_receipt_sha256 || '',
              )
              && value.issuer_authority.recovery_scope_sha256 === null
          )
      )
      && (
        !['SESSION', 'CURRENT_SESSION'].includes(
          value.issuer_authority.kind,
        )
          || (
            value.issuer_authority.bootstrap_init_receipt_sha256 === null
              && value.issuer_authority.recovery_scope_sha256 === null
          )
      )
      && (
        value.issuer_authority.kind !== 'GOAL_RECOVERY'
          || (
            value.issuer_authority.bootstrap_init_receipt_sha256 === null
              && /^sha256:[0-9a-f]{64}$/.test(
                value.issuer_authority.recovery_scope_sha256 || '',
              )
          )
      )
      && value.intent_sha256 === hashObject(unsigned),
    'ROLE_IDENTITY_INTENT_INVALID',
    'role identity intent schema/hash/binding 非法',
  );
  for (const [candidate, label] of [
    [value.operation_id, 'operation_id'],
    [value.goal_id, 'goal_id'],
    [value.task_id, 'task_id'],
    [value.thread_id, 'thread_id'],
    [value.host_id, 'host_id'],
    [value.session_id, 'session_id'],
  ]) {
    safeId(candidate, `role identity intent ${label}`);
  }
  if (value.launch_id !== null) {
    safeId(value.launch_id, 'role identity intent launch_id');
  }
  safeId(
    value.identity_observation.attestation_key_id,
    'role identity intent attestation_key_id',
  );
  if (value.issuer_authority.kind !== 'BOOTSTRAP') {
    assertControl(
      ROLES.has(value.issuer_authority.role)
        && Number.isSafeInteger(value.issuer_authority.attempt)
        && value.issuer_authority.attempt > 0,
      'ROLE_IDENTITY_INTENT_INVALID',
      'role identity intent issuer session lineage 非法',
    );
    for (const [candidate, label] of [
      [value.issuer_authority.source_task_id, 'source_task_id'],
      [value.issuer_authority.thread_id, 'thread_id'],
      [value.issuer_authority.host_id, 'host_id'],
      [value.issuer_authority.session_id, 'session_id'],
      [
        value.issuer_authority.registration_event_id,
        'registration_event_id',
      ],
    ]) {
      safeId(candidate, `role identity intent issuer ${label}`);
    }
    canonicalTimestamp(
      value.issuer_authority.lease_until,
      'role identity intent issuer lease_until',
      'ROLE_IDENTITY_INTENT_INVALID',
    );
    assertActualIdentityAliases({
      thread_id: value.issuer_authority.thread_id,
      host_id: value.issuer_authority.host_id,
    });
  }
  assertActualIdentityAliases(value);
  canonicalTimestamp(
    value.created_at,
    'role identity intent created_at',
    'ROLE_IDENTITY_INTENT_INVALID',
  );
  canonicalTimestamp(
    value.identity_observation.observed_at,
    'role identity intent observed_at',
    'ROLE_IDENTITY_INTENT_INVALID',
  );
  canonicalTimestamp(
    value.identity_observation.expires_at,
    'role identity intent expires_at',
    'ROLE_IDENTITY_INTENT_INVALID',
  );
  return JSON.parse(JSON.stringify(value));
}

function publicRoleIdentityIntent(value) {
  const intent = validateRoleIdentityIntent(value);
  return {
    schema_version: 1,
    kind: intent.kind,
    operation_id: intent.operation_id,
    goal_id: intent.goal_id,
    task_id: intent.task_id,
    role: intent.role,
    thread_id: intent.thread_id,
    host_id: intent.host_id,
    attempt: intent.attempt,
    session_id: intent.session_id,
    launch_id: intent.launch_id,
    state_revision: intent.state_revision,
    control_epoch: intent.control_epoch,
    packet: intent.packet,
    base_head: intent.base_head,
    full_head: intent.full_head,
    task_cycle: intent.task_cycle,
    identity_observation: {
      receipt_sha256:
        intent.identity_observation.receipt_sha256,
      record_sha256:
        intent.identity_observation.record_sha256,
      attestation_key_id:
        intent.identity_observation.attestation_key_id,
      observed_at: intent.identity_observation.observed_at,
      expires_at: intent.identity_observation.expires_at,
      worker_bootstrap_binding_sha256:
        intent.identity_observation.worker_bootstrap_binding_sha256,
    },
    created_at: intent.created_at,
    intent_sha256: intent.intent_sha256,
  };
}

module.exports = {
  INTENT_KIND,
  OBSERVATION_KIND,
  publicRoleIdentityIntent,
  validateRoleIdentityIntent,
  validateRoleIdentityObservation,
  validateRoleIdentityObservationStructure,
};
