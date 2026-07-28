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
  WORKER_CANARY_BOOTSTRAP_PROTOCOL,
} = require('./validation');

const WORKER_ROLES = Object.freeze(['DEV', 'REVIEW', 'RECEIPT']);
const DEV_HEAD_ADVANCE_EVENTS = Object.freeze([
  'DEV_READY',
  'REOPEN_DEV',
]);
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
    'WORKER_BOOTSTRAP_BINDING_INVALID',
    `${label} 字段集合非法`,
  );
}

function canonicalAbsolutePath(value, label) {
  assertControl(
    typeof value === 'string'
      && path.isAbsolute(value)
      && path.normalize(value) === value,
    'WORKER_BOOTSTRAP_BINDING_INVALID',
    `${label} 必须是 canonical absolute path`,
  );
  return value;
}

function validateWorkerBootstrapBinding(value, label = 'worker bootstrap binding') {
  exactKeys(value, BINDING_KEYS, label);
  assertControl(
    value.schema_version === 1
      && value.protocol === WORKER_CANARY_BOOTSTRAP_PROTOCOL,
    'WORKER_BOOTSTRAP_BINDING_INVALID',
    `${label} schema/protocol 非法`,
  );
  safeId(value.operation_id, `${label}.operation_id`);
  safeId(value.thread, `${label}.thread`);
  safeId(value.host, `${label}.host`);
  assertControl(
    CHALLENGE_RE.test(value.challenge),
    'WORKER_BOOTSTRAP_BINDING_INVALID',
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
    'WORKER_BOOTSTRAP_BINDING_INVALID',
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
    'WORKER_BOOTSTRAP_BINDING_INVALID',
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
    'WORKER_BOOTSTRAP_BINDING_INVALID',
    `${label}.binding_sha256 不匹配`,
  );
  return JSON.parse(JSON.stringify(value));
}

function sealWorkerBootstrapBinding(receipt) {
  const unsigned = {
    schema_version: 1,
    protocol: WORKER_CANARY_BOOTSTRAP_PROTOCOL,
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
  return validateWorkerBootstrapBinding({
    ...unsigned,
    binding_sha256: hashObject(unsigned),
  });
}

function workerBootstrapOptions(options) {
  const values = [
    options.workerBootstrapReceipt,
    options.workerBootstrapReceiptSha256,
    options.workerBootstrapOperationId,
    options.workerBootstrapChallenge,
    options.workerBootstrapIdentityPlanSha256,
  ];
  const count = values.filter(
    (value) => value !== null && value !== undefined,
  ).length;
  assertControl(
    count === 0 || count === values.length,
    'WORKER_BOOTSTRAP_REGISTRATION_ARGUMENT_MISMATCH',
    'worker bootstrap receipt/hash/operation/challenge/plan 必须同时提供或同时省略',
  );
  if (count === 0) return null;
  return {
    receipt_file: options.workerBootstrapReceipt,
    receipt_sha256: normalizeHash(
      options.workerBootstrapReceiptSha256,
      '--worker-bootstrap-receipt-sha256',
    ),
    operation_id: safeId(
      options.workerBootstrapOperationId,
      '--worker-bootstrap-operation-id',
    ),
    challenge: options.workerBootstrapChallenge,
    identity_plan_sha256: normalizeHash(
      options.workerBootstrapIdentityPlanSha256,
      '--worker-bootstrap-identity-plan-sha256',
    ),
    thread: options.threadId,
    host: options.hostId || 'local',
    invocation_cwd: canonicalAbsolutePath(
      options.invocationCwd,
      'register-role invocation cwd',
    ),
  };
}

function workerBootstrapRequestMatchesBinding(binding, options) {
  const request = workerBootstrapOptions(options);
  if (binding === null || binding === undefined) return request === null;
  if (request === null) return false;
  const validated = validateWorkerBootstrapBinding(binding);
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

function registrationRequiresWorkerBootstrap(manifest, role) {
  return Boolean(
    manifest
      && manifest.worker_canary_bootstrap
      && WORKER_ROLES.includes(role),
  );
}

function workerBootstrapEventAllowsHeadAdvance(role, eventType) {
  return role === 'DEV'
    && DEV_HEAD_ADVANCE_EVENTS.includes(eventType);
}

function requiredWorkerBootstrapBinding(manifest, session, role) {
  const required = registrationRequiresWorkerBootstrap(manifest, role);
  const binding = session && session.worker_bootstrap;
  assertControl(
    !required || binding,
    'WORKER_BOOTSTRAP_REGISTRATION_REQUIRED',
    `manifest 启用 worker canary bootstrap 后，${role} session 必须携带 receipt-bound registration identity`,
  );
  assertControl(
    required || !binding,
    'WORKER_CANARY_BOOTSTRAP_PROTOCOL_UNSUPPORTED',
    `${role} session 在未启用 worker canary bootstrap 的 Goal 中携带 binding`,
  );
  return binding
    ? validateWorkerBootstrapBinding(
      binding,
      `${role} session.worker_bootstrap`,
    )
    : null;
}

function assertWorkerBootstrapLaunchBinding(
  session,
  launch,
  options = {},
) {
  const binding = session && session.worker_bootstrap;
  if (!binding) return false;
  const validated = validateWorkerBootstrapBinding(binding);
  assertControl(
    launch
      && launch.worker_bootstrap
      && hashObject(
        validateWorkerBootstrapBinding(
          launch.worker_bootstrap,
          'launch.worker_bootstrap',
        ),
      ) === hashObject(validated)
      && launch.thread
      && launch.thread.id === validated.thread
      && (launch.thread.host_id || 'local') === validated.host
      && launch.thread.cwd === validated.worktree
      && launch.repository
      && launch.repository.worktree === validated.worktree
      && launch.repository.branch === validated.branch
      && launch.repository.root === path.dirname(validated.common_git_dir)
      && (
        options.allowHeadAdvance === true
          || launch.repository.full_head === validated.head
      ),
    'WORKER_BOOTSTRAP_LAUNCH_MISMATCH',
    'launch/session 未绑定同一 worker bootstrap actual worktree identity',
  );
  return true;
}

function assertWorkerBootstrapCurrentWorktree(
  session,
  identity,
  options = {},
) {
  const binding = session && session.worker_bootstrap;
  if (!binding) return false;
  const validated = validateWorkerBootstrapBinding(binding);
  assertControl(
    identity
      && identity.worktree === validated.worktree
      && identity.git_dir === validated.git_dir
      && identity.common_git_dir === validated.common_git_dir
      && identity.branch === validated.branch
      && (
        options.allowHeadAdvance === true
          || identity.head === validated.head
      ),
    'WORKER_BOOTSTRAP_LAUNCH_MISMATCH',
    'launch-template/preflight checkout 不是 receipt-bound actual worker identity',
  );
  return true;
}

module.exports = {
  WORKER_ROLES,
  assertWorkerBootstrapCurrentWorktree,
  assertWorkerBootstrapLaunchBinding,
  registrationRequiresWorkerBootstrap,
  requiredWorkerBootstrapBinding,
  sealWorkerBootstrapBinding,
  validateWorkerBootstrapBinding,
  workerBootstrapEventAllowsHeadAdvance,
  workerBootstrapOptions,
  workerBootstrapRequestMatchesBinding,
};
