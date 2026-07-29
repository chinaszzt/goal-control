'use strict';

const path = require('path');
const { assertControl } = require('./errors');
const {
  assertFullSha,
  hashObject,
  normalizeHash,
  safeId,
} = require('./util');
const {
  CAPTAIN_CANARY_BOOTSTRAP_PROTOCOL,
} = require('./validation');

const CHALLENGE_RE = /^[0-9a-f]{64}$/;
const BINDING_KEYS = Object.freeze([
  'binding_sha256',
  'branch',
  'canary_policy',
  'challenge',
  'common_git_dir',
  'git_dir',
  'head',
  'host',
  'identity_observation_sha256',
  'identity_plan_sha256',
  'operation_id',
  'protocol',
  'receipt_file',
  'receipt_sha256',
  'schema_version',
  'thread',
  'worktree',
]);
const BINDING_UNSIGNED_KEYS = Object.freeze(
  BINDING_KEYS.filter((key) => key !== 'binding_sha256'),
);

function exactKeys(value, expected, label) {
  assertControl(
    value
      && typeof value === 'object'
      && !Array.isArray(value)
      && JSON.stringify(Object.keys(value).sort())
        === JSON.stringify([...expected].sort()),
    'CAPTAIN_BOOTSTRAP_BINDING_INVALID',
    `${label} 字段集合非法`,
  );
}

function canonicalAbsolutePath(value, label) {
  assertControl(
    typeof value === 'string'
      && path.isAbsolute(value)
      && path.normalize(value) === value,
    'CAPTAIN_BOOTSTRAP_BINDING_INVALID',
    `${label} 必须是 canonical absolute path`,
  );
  return value;
}

function validateCaptainBootstrapBinding(
  value,
  label = 'captain bootstrap binding',
) {
  exactKeys(value, BINDING_KEYS, label);
  assertControl(
    value.schema_version === 1
      && value.protocol === CAPTAIN_CANARY_BOOTSTRAP_PROTOCOL,
    'CAPTAIN_BOOTSTRAP_BINDING_INVALID',
    `${label} schema/protocol 非法`,
  );
  safeId(value.operation_id, `${label}.operation_id`);
  safeId(value.thread, `${label}.thread`);
  safeId(value.host, `${label}.host`);
  assertControl(
    CHALLENGE_RE.test(value.challenge),
    'CAPTAIN_BOOTSTRAP_BINDING_INVALID',
    `${label}.challenge 必须是 64 位小写 hex`,
  );
  for (const key of [
    'receipt_sha256',
    'identity_plan_sha256',
    'identity_observation_sha256',
    'binding_sha256',
  ]) {
    normalizeHash(value[key], `${label}.${key}`);
  }
  for (const key of [
    'receipt_file',
    'worktree',
    'git_dir',
    'common_git_dir',
  ]) {
    canonicalAbsolutePath(value[key], `${label}.${key}`);
  }
  assertFullSha(value.head, `${label}.head`);
  assertControl(
    typeof value.branch === 'string'
      && value.branch.startsWith('codex/')
      && value.branch.length <= 300,
    'CAPTAIN_BOOTSTRAP_BINDING_INVALID',
    `${label}.branch 必须是 codex/ 命名分支`,
  );
  exactKeys(
    value.canary_policy,
    ['path', 'sha256'],
    `${label}.canary_policy`,
  );
  assertControl(
    typeof value.canary_policy.path === 'string'
      && value.canary_policy.path.length > 0
      && !path.isAbsolute(value.canary_policy.path),
    'CAPTAIN_BOOTSTRAP_BINDING_INVALID',
    `${label}.canary_policy.path 必须是 repo-relative path`,
  );
  normalizeHash(
    value.canary_policy.sha256,
    `${label}.canary_policy.sha256`,
  );
  const unsigned = {};
  for (const key of BINDING_UNSIGNED_KEYS) unsigned[key] = value[key];
  assertControl(
    value.binding_sha256 === hashObject(unsigned),
    'CAPTAIN_BOOTSTRAP_BINDING_INVALID',
    `${label}.binding_sha256 不匹配`,
  );
  return JSON.parse(JSON.stringify(value));
}

function sealCaptainBootstrapBinding(receipt) {
  const unsigned = {
    schema_version: 1,
    protocol: CAPTAIN_CANARY_BOOTSTRAP_PROTOCOL,
    receipt_file: receipt.receipt_file,
    receipt_sha256: receipt.receipt_sha256,
    identity_plan_sha256: receipt.identity_plan_sha256,
    identity_observation_sha256:
      receipt.identity_observation_sha256,
    operation_id: receipt.operation_id,
    challenge: receipt.challenge,
    thread: receipt.thread,
    host: receipt.host,
    worktree: receipt.worktree,
    git_dir: receipt.git_dir,
    common_git_dir: receipt.common_git_dir,
    head: receipt.head,
    branch: receipt.branch,
    canary_policy: receipt.canary_policy,
  };
  return validateCaptainBootstrapBinding({
    ...unsigned,
    binding_sha256: hashObject(unsigned),
  });
}

function captainBootstrapOptions(options) {
  const values = [
    options.captainBootstrapReceipt,
    options.captainBootstrapReceiptSha256,
    options.captainBootstrapOperationId,
    options.captainBootstrapChallenge,
    options.captainBootstrapIdentityPlanSha256,
  ];
  const count = values.filter(
    (value) => value !== null && value !== undefined,
  ).length;
  assertControl(
    count === 0 || count === values.length,
    'CAPTAIN_BOOTSTRAP_REGISTRATION_ARGUMENT_MISMATCH',
    'captain bootstrap receipt/hash/operation/challenge/plan 必须同时提供或同时省略',
  );
  if (count === 0) return null;
  return {
    receipt_file: options.captainBootstrapReceipt,
    receipt_sha256: normalizeHash(
      options.captainBootstrapReceiptSha256,
      '--captain-bootstrap-receipt-sha256',
    ),
    operation_id: safeId(
      options.captainBootstrapOperationId,
      '--captain-bootstrap-operation-id',
    ),
    challenge: options.captainBootstrapChallenge,
    identity_plan_sha256: normalizeHash(
      options.captainBootstrapIdentityPlanSha256,
      '--captain-bootstrap-identity-plan-sha256',
    ),
    thread: options.threadId,
    host: options.hostId || 'local',
    invocation_cwd: canonicalAbsolutePath(
      options.invocationCwd,
      'register-role invocation cwd',
    ),
  };
}

function captainBootstrapRequestMatchesBinding(binding, options) {
  const request = captainBootstrapOptions(options);
  if (binding === null || binding === undefined) return request === null;
  if (request === null) return false;
  const validated = validateCaptainBootstrapBinding(binding);
  return validated.receipt_file === request.receipt_file
    && validated.receipt_sha256 === request.receipt_sha256
    && validated.operation_id === request.operation_id
    && validated.challenge === request.challenge
    && validated.identity_plan_sha256
      === request.identity_plan_sha256
    && validated.thread === request.thread
    && validated.host === request.host
    && validated.worktree === request.invocation_cwd;
}

function registrationRequiresCaptainBootstrap(manifest, role) {
  return Boolean(
    manifest
      && manifest.captain_canary_bootstrap
      && role === 'CAPTAIN',
  );
}

module.exports = {
  captainBootstrapOptions,
  captainBootstrapRequestMatchesBinding,
  registrationRequiresCaptainBootstrap,
  sealCaptainBootstrapBinding,
  validateCaptainBootstrapBinding,
};
