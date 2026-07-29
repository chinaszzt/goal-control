'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { assertControl } = require('./errors');
const {
  assertFullSha,
  hashFile,
  hashObject,
  normalizeHash,
  realpathWithin,
  safeId,
} = require('./util');

const ROLES = Object.freeze(['FOREMAN', 'CAPTAIN', 'DEV', 'REVIEW', 'RECEIPT']);
const HARD_HOLDS = Object.freeze(['BLOCKED_SECURITY', 'BLOCKED_EXTERNAL_FACT', 'ENV_IDENTITY_INCIDENT']);
const OTHER_HOLDS = Object.freeze(['TECH', 'CONTRACT', 'SPEC_CONFLICT', 'ENV', 'PERMISSION', 'TOOLING', 'RESOURCE']);
const HOLD_KINDS = Object.freeze([...HARD_HOLDS, ...OTHER_HOLDS]);
const ENTITY_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const REPO_PATH_RE = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const RESOURCE_KINDS = Object.freeze(['PORT', 'BROWSER_PROFILE', 'ACCOUNT', 'TIM_SESSION', 'WINDOW', 'EXECUTABLE', 'TEST_DATA']);
const RESOURCE_ACCESS = Object.freeze(['EXCLUSIVE', 'SHARED_READ']);
const RESOURCE_ROLES = Object.freeze(['DEV', 'REVIEW', 'RECEIPT']);
const WORKER_CANARY_BOOTSTRAP_PROTOCOL =
  'goalctl-worker-canary-bootstrap-v1';
const WORKER_CANARY_BOOTSTRAP_POLICY_MARKER =
  `Worker-Canary-Bootstrap-Protocol: ${WORKER_CANARY_BOOTSTRAP_PROTOCOL}`;
const PROBE_OBSERVATION_RECEIPT_PROTOCOL =
  'goalctl-sealed-probe-observation-v1';
const P1_COMMIT_REF_RE = /^refs\/heads\/codex\/goal-control\/p1\/[0-9a-f]{64}\/[0-9a-f]{64}\/cycle-[1-9][0-9]*$/;
const EVENT_PAYLOAD_KEYS = Object.freeze({
  START_P1: ['required_start_head', 'p1_worktree', 'p1_branch'],
  P1_READY: ['plan_path', 'plan_sha256', 'context_path', 'context_sha256', 'artifact_manifest_sha256', 'p1_worktree', 'p1_branch'],
  P1_APPROVED: ['plan_path', 'plan_sha256', 'context_path', 'context_sha256', 'artifact_manifest_sha256', 'p1_worktree', 'p1_branch', 'approval_ref'],
  P1_COMMITTED: ['plan_path', 'plan_sha256', 'context_path', 'context_sha256', 'artifact_manifest_sha256', 'p1_worktree', 'p1_branch', 'approval_event_id', 'p1_commit_ref'],
  P1_COMMIT_ABANDONED: [
    'prepared_event_id',
    'task_cycle',
    'p1_intent_sha256',
    'abandon_intent_sha256',
    'abandon_request_sha256',
    'abandon_receipt_sha256',
    'commit_ref',
    'commit_sha',
    'predecessor_event_sha256',
    'reason',
    'incident_ref',
  ],
  P1_RESTARTED: [
    'captain_recovery_event_id',
    'predecessor_thread_id',
    'predecessor_host_id',
    'predecessor_attempt',
    'successor_thread_id',
    'successor_host_id',
    'successor_attempt',
    'abandoned_p1_worktree',
    'abandoned_p1_branch',
    'reason',
    'incident_ref',
  ],
  LAUNCH_DEV: ['launch_id'],
  DEV_READY: ['pr', 'evidence'],
  LAUNCH_REVIEW: ['launch_id'],
  REVIEW_REWORK: ['review_evidence'],
  REVIEW_PASS: ['evidence'],
  LAUNCH_RECEIPT: ['launch_id'],
  RECEIPT_FAIL: ['evidence_id'],
  REOPEN_DEV: [],
  REOPEN_REVIEW: ['launch_id'],
  RECEIPT_PASS: ['evidence'],
  READY_FOR_MERGE: [],
  TASK_REOPEN: ['reason', 'evidence_id'],
  MERGED: [
    'main_merge_sha',
    'expected_main_head',
    'merge_receipt_sha256',
    'merge_reservation_event_id',
    'merge_request_sha256',
  ],
  GITHUB_MERGE_RESERVED: [
    'target_event_id',
    'request_sha256',
    'repository',
    'pull_request_number',
    'pull_request_url',
    'base_branch',
    'expected_main_head',
    'candidate_head',
    'task_cycle',
    'phase',
    'issue',
    'head_ref_name',
    'body_sha256',
    'preflight_attestation',
    'pr_contract_sha256',
  ],
  ARCHIVED: ['evidence_id'],
  REGISTER_ROLE: ['role', 'thread_id', 'host_id', 'attempt', 'lease_ms', 'status', 'launch_id', 'task_nonce', 'capability_sha256', 'capability_file', 'authorized_by', 'worker_bootstrap', 'probe_observation', 'goal_foreman_projection', 'projected_lease_until'],
  PROBE_OBSERVATION_REFRESHED: [
    'role',
    'attempt',
    'previous_binding_sha256',
    'probe_observation',
    'request_sha256',
  ],
  HEARTBEAT: ['lease_ms', 'status'],
  CONTROL_RECONCILED: ['control_event_id', 'instruction_ref'],
  ADD_HOLD: ['kind', 'hold_id', 'reason', 'evidence_id'],
  RESOLVE_HOLD: [
    'hold_id',
    'authority',
    'resolution_evidence_id',
    'runtime_preflight_evidence_id',
    'disposition',
  ],
  RUNTIME_ROTATED: [
    'role',
    'worker_thread_id',
    'worker_host_id',
    'worker_attempt',
    'predecessor_incarnation',
    'successor_incarnation',
    'predecessor_launch_id',
    'predecessor_launch_sha256',
    'successor_launch_id',
    'runtime_nonce',
    'hold_id',
    'reason',
    'incident_ref',
    'retirement_proof',
    'lease_set_sha256',
  ],
  ROLE_LOST: [
    'role',
    'reason',
    'fingerprint',
    'attempts',
    'evidence_id',
    'expected_thread_id',
    'expected_host_id',
    'expected_attempt',
    'expected_lease_until',
  ],
  ROLE_RECOVERED: ['successor_thread_id'],
  RECOVERY_HANDOFF_BOUND: [
    'successor_thread_id',
    'snapshot_id',
    'snapshot_sha256',
    'import_receipt_id',
    'import_receipt_sha256',
    'predecessor_launch_id',
    'predecessor_launch_sha256',
    'source_worktree',
    'source_branch',
    'source_launch_head',
    'source_observed_head',
    'destination_worktree',
    'destination_branch',
    'import_commit',
  ],
  RECOVERY_HANDOFF_ABANDONED: [
    'successor_thread_id',
    'handoff_event_id',
    'reason',
    'incident_ref',
    'foreman_thread_id',
    'foreman_host_id',
    'foreman_attempt',
  ],
  RECOVERY_PROMOTED: [
    'successor_thread_id',
    'handoff_event_id',
    'launch_id',
    'launch_sha256',
    'preflight_evidence_id',
  ],
  RECOVER_EXPIRED_FOREMAN: [
    'attempt',
    'lease_ms',
    'status',
    'capability_sha256',
    'capability_file',
    'reason',
    'incident_ref',
    'request_sha256',
    'probe_observation',
    'root_recovery_id',
    'goal_scope',
    'goal_scope_sha256',
    'scope_task_ids',
    'source_task_ids',
    'adoption_target_task_id',
    'adopt_without_local_foreman',
    'source_foreman',
    'expected_event_head',
    'expected_foreman_thread_id',
    'expected_foreman_host_id',
    'expected_foreman_attempt',
    'expected_foreman_lease_until',
    'authorized_by',
  ],
  PACKET_UPDATED: ['revision', 'sha256', 'path', 'change_kind'],
});

const EVENT_PAYLOAD_REQUIRED = Object.freeze({
  START_P1: [],
  P1_READY: ['plan_path', 'plan_sha256', 'context_path', 'context_sha256'],
  P1_APPROVED: ['plan_path', 'plan_sha256', 'context_path', 'context_sha256', 'approval_ref'],
  P1_COMMITTED: ['plan_path', 'plan_sha256', 'context_path', 'context_sha256', 'approval_event_id'],
  P1_COMMIT_ABANDONED: EVENT_PAYLOAD_KEYS.P1_COMMIT_ABANDONED,
  P1_RESTARTED: EVENT_PAYLOAD_KEYS.P1_RESTARTED,
  LAUNCH_DEV: ['launch_id'],
  DEV_READY: ['pr', 'evidence'],
  LAUNCH_REVIEW: ['launch_id'],
  REVIEW_REWORK: ['review_evidence'],
  REVIEW_PASS: ['evidence'],
  LAUNCH_RECEIPT: ['launch_id'],
  RECEIPT_FAIL: ['evidence_id'],
  REOPEN_DEV: [],
  REOPEN_REVIEW: ['launch_id'],
  RECEIPT_PASS: ['evidence'],
  READY_FOR_MERGE: [],
  TASK_REOPEN: ['reason', 'evidence_id'],
  MERGED: ['main_merge_sha', 'expected_main_head'],
  GITHUB_MERGE_RESERVED: [
    'target_event_id',
    'request_sha256',
    'repository',
    'pull_request_number',
    'pull_request_url',
    'base_branch',
    'expected_main_head',
    'candidate_head',
    'task_cycle',
    'phase',
    'issue',
    'head_ref_name',
    'body_sha256',
    'preflight_attestation',
    'pr_contract_sha256',
  ],
  ARCHIVED: ['evidence_id'],
  REGISTER_ROLE: [
    'role',
    'thread_id',
    'host_id',
    'attempt',
    'lease_ms',
    'status',
    'launch_id',
    'task_nonce',
    'capability_sha256',
    'capability_file',
    'authorized_by',
  ],
  PROBE_OBSERVATION_REFRESHED:
    EVENT_PAYLOAD_KEYS.PROBE_OBSERVATION_REFRESHED,
  HEARTBEAT: [],
  CONTROL_RECONCILED: EVENT_PAYLOAD_KEYS.CONTROL_RECONCILED,
  ADD_HOLD: ['kind', 'evidence_id'],
  RESOLVE_HOLD: ['hold_id'],
  RUNTIME_ROTATED: EVENT_PAYLOAD_KEYS.RUNTIME_ROTATED,
  ROLE_LOST: ['role'],
  ROLE_RECOVERED: ['successor_thread_id'],
  RECOVERY_HANDOFF_BOUND: EVENT_PAYLOAD_KEYS.RECOVERY_HANDOFF_BOUND,
  RECOVERY_HANDOFF_ABANDONED: EVENT_PAYLOAD_KEYS.RECOVERY_HANDOFF_ABANDONED,
  RECOVERY_PROMOTED: EVENT_PAYLOAD_KEYS.RECOVERY_PROMOTED,
  RECOVER_EXPIRED_FOREMAN: [
    'attempt',
    'lease_ms',
    'status',
    'capability_sha256',
    'capability_file',
    'reason',
    'incident_ref',
    'request_sha256',
    'expected_event_head',
    'expected_foreman_thread_id',
    'expected_foreman_host_id',
    'expected_foreman_attempt',
    'expected_foreman_lease_until',
    'authorized_by',
  ],
  PACKET_UPDATED: EVENT_PAYLOAD_KEYS.PACKET_UPDATED,
});

const ROLE_LOST_TARGET_BINDING_KEYS = Object.freeze([
  'expected_thread_id',
  'expected_host_id',
  'expected_attempt',
  'expected_lease_until',
]);

function assertLiveRoleLostTargetBinding(event) {
  if (!event || event.type !== 'ROLE_LOST') return event;
  const payload = event.payload || {};
  assertControl(
    ROLE_LOST_TARGET_BINDING_KEYS.every(
      (key) => Object.prototype.hasOwnProperty.call(payload, key),
    ),
    'ROLE_LOST_TARGET_REQUIRED',
    '新的 ROLE_LOST 必须完整绑定 exact thread/host/attempt/lease_until；'
      + '旧 accepted ledger 仅允许原 event exact replay',
  );
  entityId(
    payload.expected_thread_id,
    'ROLE_LOST expected_thread_id',
    'ROLE_LOST_TARGET_INVALID',
  );
  entityId(
    payload.expected_host_id,
    'ROLE_LOST expected_host_id',
    'ROLE_LOST_TARGET_INVALID',
  );
  assertControl(
    Number.isSafeInteger(payload.expected_attempt)
      && payload.expected_attempt > 0,
    'ROLE_LOST_TARGET_INVALID',
    'ROLE_LOST expected_attempt 必须是正整数',
  );
  validDateTime(
    payload.expected_lease_until,
    'ROLE_LOST expected_lease_until',
    'ROLE_LOST_TARGET_INVALID',
  );
  return event;
}

function assertPlainObject(value, code, label) {
  assertControl(value && typeof value === 'object' && !Array.isArray(value), code, `${label} 必须是对象`);
  return value;
}

function assertOnlyKeys(value, allowed, code, label) {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  assertControl(unknown.length === 0, code, `${label} 含未知字段: ${unknown.join(', ')}`);
}

function entityId(value, label, code = 'INVALID_ID') {
  assertControl(typeof value === 'string' && value.length <= 200 && ENTITY_ID_RE.test(value), code, `${label} 必须是安全 ID`);
  return value;
}

function nonEmptyString(value, label, code, maxLength = 2000) {
  assertControl(typeof value === 'string' && value.length > 0 && value.length <= maxLength, code, `${label} 必须是 1-${maxLength} 字符字符串`);
  return value;
}

function uniqueArray(value, label, code) {
  assertControl(Array.isArray(value), code, `${label} 必须是列表`);
  assertControl(new Set(value).size === value.length, code, `${label} 不能重复`);
  return value;
}

function repoPath(value, label, code = 'INVALID_MANIFEST') {
  assertControl(typeof value === 'string' && value.length <= 500 && REPO_PATH_RE.test(value), code, `${label} 必须是安全的仓库相对 POSIX 路径`);
  return value;
}

function mechanicalP1WritePattern(
  value,
  label = 'mechanical P1 expected_write_set item',
  code = 'INVALID_MANIFEST',
) {
  nonEmptyString(value, label, code, 500);
  assertControl(
    !value.startsWith('/')
      && !value.includes('\\')
      && !value.includes('\0'),
    code,
    `${label} 必须是仓库相对 POSIX pattern`,
  );
  const segments = value.split('/');
  assertControl(
    segments.every(
      (segment) => segment.length > 0 && segment !== '.' && segment !== '..',
    ),
    code,
    `${label} 禁止空、. 或 .. path segment`,
  );
  assertControl(
    !/[!?{}[\]]/.test(value) && !/[?*+@!]\(/.test(value),
    code,
    `${label} 只支持 literal、单 segment * 与完整 segment **`,
  );
  assertControl(
    segments.every(
      (segment) => !segment.includes('**') || segment === '**',
    ),
    code,
    `${label} 的 ** 必须是完整 path segment`,
  );
  return value;
}

function mechanicalP1WriteSegmentMatches(patternSegment, candidateSegment) {
  if (!patternSegment.includes('*')) return patternSegment === candidateSegment;
  const expression = patternSegment
    .split('*')
    .map((literal) => literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${expression}$`).test(candidateSegment);
}

function matchesMechanicalP1WritePattern(pattern, candidatePath) {
  mechanicalP1WritePattern(pattern);
  if (
    typeof candidatePath !== 'string'
      || candidatePath.length === 0
      || candidatePath.startsWith('/')
      || candidatePath.includes('\\')
      || candidatePath.includes('\0')
  ) {
    return false;
  }
  const candidateSegments = candidatePath.split('/');
  if (
    candidateSegments.some(
      (segment) => segment.length === 0 || segment === '.' || segment === '..',
    )
  ) {
    return false;
  }
  const patternSegments = pattern.split('/');
  const memo = new Map();
  const visit = (patternIndex, candidateIndex) => {
    const key = `${patternIndex}:${candidateIndex}`;
    if (memo.has(key)) return memo.get(key);
    let matched;
    if (patternIndex === patternSegments.length) {
      matched = candidateIndex === candidateSegments.length;
    } else if (patternSegments[patternIndex] === '**') {
      matched = visit(patternIndex + 1, candidateIndex)
        || (
          candidateIndex < candidateSegments.length
            && visit(patternIndex, candidateIndex + 1)
        );
    } else {
      matched = candidateIndex < candidateSegments.length
        && mechanicalP1WriteSegmentMatches(
          patternSegments[patternIndex],
          candidateSegments[candidateIndex],
        )
        && visit(patternIndex + 1, candidateIndex + 1);
    }
    memo.set(key, matched);
    return matched;
  };
  return visit(0, 0);
}

function validDateTime(value, label, code) {
  assertControl(typeof value === 'string' && Number.isFinite(Date.parse(value)), code, `${label} 必须是 ISO date-time`);
  return value;
}

function safeHttpUrl(value, label, options = {}) {
  nonEmptyString(value, label, 'INVALID_LAUNCH_MANIFEST', 1000);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    assertControl(false, 'INVALID_LAUNCH_MANIFEST', `${label} 必须是合法 URL`);
  }
  const protocols = options.httpsOnly ? ['https:'] : ['http:', 'https:'];
  assertControl(protocols.includes(parsed.protocol) && parsed.hostname, 'INVALID_LAUNCH_MANIFEST', `${label} 必须使用 ${protocols.join('/')} 且包含 host`);
  assertControl(!parsed.username && !parsed.password, 'SENSITIVE_URL_FORBIDDEN', `${label} 禁止 userinfo 凭证`);
  assertControl(!parsed.hash, 'SENSITIVE_URL_FORBIDDEN', `${label} 禁止 fragment`);
  if (options.noQuery) {
    assertControl(!parsed.search, 'SENSITIVE_URL_FORBIDDEN', `${label} 禁止 query`);
  } else {
    for (const key of parsed.searchParams.keys()) {
      assertControl(
        !/token|secret|password|authorization|cookie|credential|api[_-]?key|access[_-]?key/i.test(key),
        'SENSITIVE_URL_FORBIDDEN',
        `${label} 禁止敏感 query key: ${key}`,
      );
    }
  }
  return value;
}

function parsePullRequestUrl(value, expectedRepository = null) {
  nonEmptyString(value, 'pull request URL', 'INVALID_PULL_REQUEST', 2000);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    assertControl(false, 'INVALID_PULL_REQUEST', 'pull request 必须是 canonical GitHub URL');
  }
  assertControl(
    parsed.protocol === 'https:' && parsed.hostname === 'github.com' && !parsed.username && !parsed.password
      && !parsed.search && !parsed.hash,
    'INVALID_PULL_REQUEST',
    'pull request 必须是无凭证、无 query/fragment 的 https://github.com URL',
  );
  const match = parsed.pathname.match(/^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/pull\/([1-9][0-9]*)$/);
  assertControl(match, 'INVALID_PULL_REQUEST', 'pull request URL path 必须是 /owner/repo/pull/<number>');
  const repository = `${match[1]}/${match[2]}`;
  if (expectedRepository) {
    assertControl(repository.toLowerCase() === expectedRepository.toLowerCase(), 'PULL_REQUEST_REPOSITORY_MISMATCH', `PR repository=${repository}，期望 ${expectedRepository}`);
  }
  const canonicalRepository = expectedRepository || repository;
  const number = Number(match[3]);
  return {
    repository: canonicalRepository,
    number,
    url: `https://github.com/${canonicalRepository}/pull/${number}`,
    base: 'main',
  };
}

function assertNoSensitiveKeys(value, label, code) {
  if (Array.isArray(value)) {
    value.forEach((child, index) => assertNoSensitiveKeys(child, `${label}[${index}]`, code));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    assertControl(!/token|secret|password|authorization|cookie|credential/i.test(key), code, `${label} 禁止敏感字段 ${key}`);
    assertNoSensitiveKeys(child, `${label}.${key}`, code);
  }
}

function validateManifest(manifest, manifestFile, repositoryRoot) {
  assertPlainObject(manifest, 'INVALID_MANIFEST', 'manifest');
  assertOnlyKeys(manifest, ['schema_version', 'goal_id', 'title', 'mode', 'repository', 'base_head', 'protocol', 'preclaim', 'worker_canary_bootstrap', 'probe_observation_receipts', 'tasks'], 'INVALID_MANIFEST', 'manifest');
  assertControl(manifest.schema_version === 1, 'UNSUPPORTED_SCHEMA', 'manifest.schema_version 必须为 1');
  const goalId = entityId(manifest.goal_id, 'goal_id', 'INVALID_MANIFEST');
  if (manifest.title !== undefined) nonEmptyString(manifest.title, 'manifest.title', 'INVALID_MANIFEST', 200);
  const mode = manifest.mode || 'shadow';
  assertControl(['shadow', 'enforce'].includes(mode), 'INVALID_MANIFEST', 'manifest.mode 必须是 shadow 或 enforce');
  assertPlainObject(manifest.repository, 'INVALID_MANIFEST', 'manifest.repository');
  assertOnlyKeys(manifest.repository, ['name_with_owner', 'base_branch', 'merge_policy'], 'INVALID_MANIFEST', 'manifest.repository');
  assertControl(
    typeof manifest.repository.name_with_owner === 'string' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(manifest.repository.name_with_owner),
    'INVALID_MANIFEST',
    'repository.name_with_owner 必须是 owner/repo'
  );
  assertControl(manifest.repository.base_branch === 'main', 'INVALID_MANIFEST', 'repository.base_branch 必须为 main');
  assertControl(
    manifest.repository.merge_policy === undefined
      || manifest.repository.merge_policy === 'goalctl-github-squash-v1',
    'INVALID_MANIFEST',
    'repository.merge_policy 只能是 goalctl-github-squash-v1',
  );
  assertFullSha(manifest.base_head, 'manifest.base_head');
  realpathWithin(repositoryRoot, manifestFile, 'manifest path');
  assertControl(Array.isArray(manifest.tasks) && manifest.tasks.length > 0, 'INVALID_MANIFEST', 'manifest.tasks 必须是非空列表');

  let workerCanaryBootstrap;
  if (manifest.worker_canary_bootstrap !== undefined) {
    assertPlainObject(
      manifest.worker_canary_bootstrap,
      'INVALID_MANIFEST',
      'manifest.worker_canary_bootstrap',
    );
    assertOnlyKeys(
      manifest.worker_canary_bootstrap,
      ['protocol', 'policy'],
      'INVALID_MANIFEST',
      'manifest.worker_canary_bootstrap',
    );
    assertControl(
      manifest.worker_canary_bootstrap.protocol
        === WORKER_CANARY_BOOTSTRAP_PROTOCOL,
      'WORKER_CANARY_BOOTSTRAP_PROTOCOL_UNSUPPORTED',
      `worker canary bootstrap protocol 必须是 ${WORKER_CANARY_BOOTSTRAP_PROTOCOL}`,
    );
    assertPlainObject(
      manifest.worker_canary_bootstrap.policy,
      'INVALID_MANIFEST',
      'manifest.worker_canary_bootstrap.policy',
    );
    assertOnlyKeys(
      manifest.worker_canary_bootstrap.policy,
      ['path', 'sha256'],
      'INVALID_MANIFEST',
      'manifest.worker_canary_bootstrap.policy',
    );
    const policyPath = repoPath(
      manifest.worker_canary_bootstrap.policy.path,
      'manifest.worker_canary_bootstrap.policy.path',
    );
    const policyFile = path.resolve(repositoryRoot, policyPath);
    realpathWithin(
      repositoryRoot,
      policyFile,
      'manifest.worker_canary_bootstrap.policy.path',
    );
    const policyStat = fs.lstatSync(policyFile);
    assertControl(
      policyStat.isFile() && !policyStat.isSymbolicLink(),
      'WORKER_CANARY_BOOTSTRAP_POLICY_UNSUPPORTED',
      'worker canary bootstrap policy 必须是仓库内普通文件',
    );
    const declaredPolicySha256 = normalizeHash(
      manifest.worker_canary_bootstrap.policy.sha256,
      'manifest.worker_canary_bootstrap.policy.sha256',
    );
    const computedPolicySha256 = hashFile(policyFile);
    assertControl(
      declaredPolicySha256 === computedPolicySha256,
      'WORKER_CANARY_BOOTSTRAP_POLICY_UNSUPPORTED',
      'worker canary bootstrap policy hash 与文件不一致',
    );
    const policyLines = fs.readFileSync(policyFile, 'utf8').split(/\r?\n/);
    assertControl(
      policyLines.includes(WORKER_CANARY_BOOTSTRAP_POLICY_MARKER),
      'WORKER_CANARY_BOOTSTRAP_POLICY_UNSUPPORTED',
      `worker canary bootstrap policy 缺少 exact opt-in marker: ${WORKER_CANARY_BOOTSTRAP_POLICY_MARKER}`,
    );
    workerCanaryBootstrap = {
      protocol: WORKER_CANARY_BOOTSTRAP_PROTOCOL,
      policy: {
        path: policyPath,
        sha256: computedPolicySha256,
      },
    };
  }

  let probeObservationReceipts;
  if (manifest.probe_observation_receipts !== undefined) {
    assertPlainObject(
      manifest.probe_observation_receipts,
      'INVALID_MANIFEST',
      'manifest.probe_observation_receipts',
    );
    assertOnlyKeys(
      manifest.probe_observation_receipts,
      ['protocol', 'max_ttl_ms', 'host_attestation'],
      'INVALID_MANIFEST',
      'manifest.probe_observation_receipts',
    );
    assertControl(
      manifest.probe_observation_receipts.protocol
        === PROBE_OBSERVATION_RECEIPT_PROTOCOL,
      'PROBE_OBSERVATION_PROTOCOL_UNSUPPORTED',
      `probe observation protocol 必须是 ${
        PROBE_OBSERVATION_RECEIPT_PROTOCOL
      }`,
    );
    assertControl(
      Number.isSafeInteger(
        manifest.probe_observation_receipts.max_ttl_ms,
      )
        && manifest.probe_observation_receipts.max_ttl_ms >= 1000
        && manifest.probe_observation_receipts.max_ttl_ms <= 900000,
      'INVALID_MANIFEST',
      'probe_observation_receipts.max_ttl_ms 必须在 1000-900000',
    );
    assertPlainObject(
      manifest.probe_observation_receipts.host_attestation,
      'INVALID_MANIFEST',
      'manifest.probe_observation_receipts.host_attestation',
    );
    assertOnlyKeys(
      manifest.probe_observation_receipts.host_attestation,
      [
        'algorithm',
        'key_id',
        'public_key_sha256',
        'public_key_spki_base64',
      ],
      'INVALID_MANIFEST',
      'manifest.probe_observation_receipts.host_attestation',
    );
    const hostAttestation =
      manifest.probe_observation_receipts.host_attestation;
    assertControl(
      hostAttestation.algorithm === 'ED25519',
      'INVALID_MANIFEST',
      'probe observation host attestation algorithm 必须是 ED25519',
    );
    const attestationKeyId = safeId(
      hostAttestation.key_id,
      'probe_observation_receipts.host_attestation.key_id',
    );
    const publicKeySha256 = normalizeHash(
      hostAttestation.public_key_sha256,
      'probe_observation_receipts.host_attestation.public_key_sha256',
    );
    assertControl(
      typeof hostAttestation.public_key_spki_base64 === 'string'
        && /^[A-Za-z0-9+/]+={0,2}$/.test(
          hostAttestation.public_key_spki_base64,
        )
        && hostAttestation.public_key_spki_base64.length <= 256,
      'INVALID_MANIFEST',
      'probe observation host attestation public key 必须是有界 base64 SPKI',
    );
    let publicKeyDer;
    let publicKey;
    try {
      publicKeyDer = Buffer.from(
        hostAttestation.public_key_spki_base64,
        'base64',
      );
      publicKey = crypto.createPublicKey({
        key: publicKeyDer,
        format: 'der',
        type: 'spki',
      });
    } catch (error) {
      assertControl(
        false,
        'INVALID_MANIFEST',
        `probe observation host attestation public key 非法: ${error.message}`,
      );
    }
    assertControl(
      publicKey
        && publicKey.asymmetricKeyType === 'ed25519'
        && publicKey.export({ format: 'der', type: 'spki' })
          .equals(publicKeyDer)
        && `sha256:${crypto
          .createHash('sha256')
          .update(publicKeyDer)
          .digest('hex')}` === publicKeySha256,
      'INVALID_MANIFEST',
      'probe observation host attestation 必须是 canonical Ed25519 SPKI 且 hash 匹配',
    );
    probeObservationReceipts = {
      protocol: PROBE_OBSERVATION_RECEIPT_PROTOCOL,
      max_ttl_ms: manifest.probe_observation_receipts.max_ttl_ms,
      host_attestation: {
        algorithm: 'ED25519',
        key_id: attestationKeyId,
        public_key_sha256: publicKeySha256,
        public_key_spki_base64:
          hostAttestation.public_key_spki_base64,
      },
    };
  }

  let protocol;
  if (manifest.protocol !== undefined) {
    assertPlainObject(manifest.protocol, 'INVALID_MANIFEST', 'manifest.protocol');
    const protocolKeys = ['entry', 'shared', 'foreman', 'captain', 'role_kernel'];
    assertOnlyKeys(manifest.protocol, protocolKeys, 'INVALID_MANIFEST', 'manifest.protocol');
    protocol = {};
    for (const [key, value] of Object.entries(manifest.protocol)) {
      const relative = repoPath(value, `manifest.protocol.${key}`);
      const absolute = path.resolve(repositoryRoot, relative);
      realpathWithin(repositoryRoot, absolute, `manifest.protocol.${key}`);
      protocol[key] = { path: relative, sha256: hashFile(absolute) };
    }
  }

  let preclaim;
  if (manifest.preclaim !== undefined) {
    assertPlainObject(manifest.preclaim, 'INVALID_MANIFEST', 'manifest.preclaim');
    assertOnlyKeys(
      manifest.preclaim,
      ['policy', 'operation_id', 'requested_at', 'authorization', 'issues', 'expected_actor', 'expected_status'],
      'INVALID_MANIFEST',
      'manifest.preclaim',
    );
    assertControl(
      manifest.preclaim.policy === 'supervisor-exact-whitelist-v1',
      'INVALID_MANIFEST',
      'manifest.preclaim.policy 必须是 supervisor-exact-whitelist-v1',
    );
    const operationId = entityId(
      manifest.preclaim.operation_id,
      'manifest.preclaim.operation_id',
      'INVALID_MANIFEST',
    );
    assertControl(
      typeof manifest.preclaim.requested_at === 'string'
        && Number.isFinite(Date.parse(manifest.preclaim.requested_at))
        && new Date(manifest.preclaim.requested_at).toISOString()
          === manifest.preclaim.requested_at,
      'INVALID_MANIFEST',
      'manifest.preclaim.requested_at 必须是 canonical ISO 时间',
    );
    assertPlainObject(
      manifest.preclaim.authorization,
      'INVALID_MANIFEST',
      'manifest.preclaim.authorization',
    );
    assertOnlyKeys(
      manifest.preclaim.authorization,
      ['path', 'sha256'],
      'INVALID_MANIFEST',
      'manifest.preclaim.authorization',
    );
    const authorizationPath = repoPath(
      manifest.preclaim.authorization.path,
      'manifest.preclaim.authorization.path',
    );
    const authorizationFile = path.resolve(repositoryRoot, authorizationPath);
    realpathWithin(
      repositoryRoot,
      authorizationFile,
      'manifest.preclaim.authorization.path',
    );
    const authorizationStat = fs.lstatSync(authorizationFile);
    assertControl(
      authorizationStat.isFile() && !authorizationStat.isSymbolicLink(),
      'INVALID_MANIFEST',
      'manifest.preclaim.authorization 必须是仓库内普通文件',
    );
    const authorizationSha256 = hashFile(authorizationFile);
    assertControl(
      normalizeHash(
        manifest.preclaim.authorization.sha256,
        'manifest.preclaim.authorization.sha256',
      ) === authorizationSha256,
      'PRECLAIM_AUTHORITY_HASH_MISMATCH',
      'manifest.preclaim.authorization hash 与文件不一致',
    );
    const issues = uniqueArray(
      manifest.preclaim.issues,
      'manifest.preclaim.issues',
      'INVALID_MANIFEST',
    );
    assertControl(
      issues.length > 0
        && issues.every((issue) => Number.isSafeInteger(issue) && issue > 0),
      'INVALID_MANIFEST',
      'manifest.preclaim.issues 必须是非空正整数白名单',
    );
    const expectedActor = nonEmptyString(
      manifest.preclaim.expected_actor,
      'manifest.preclaim.expected_actor',
      'INVALID_MANIFEST',
      120,
    );
    assertControl(
      /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(expectedActor),
      'INVALID_MANIFEST',
      'manifest.preclaim.expected_actor 不是合法 GitHub login',
    );
    assertControl(
      manifest.preclaim.expected_status === 'status:doing',
      'INVALID_MANIFEST',
      'manifest.preclaim.expected_status 必须是 status:doing',
    );
    preclaim = {
      policy: 'supervisor-exact-whitelist-v1',
      operation_id: operationId,
      requested_at: manifest.preclaim.requested_at,
      authorization: {
        path: authorizationPath,
        sha256: authorizationSha256,
      },
      issues: [...issues].sort((left, right) => left - right),
      expected_actor: expectedActor,
      expected_status: 'status:doing',
    };
  }

  const taskIds = new Set();
  const orders = new Set();
  const tasks = manifest.tasks.map((task) => {
    assertPlainObject(task, 'INVALID_MANIFEST', 'task');
    assertOnlyKeys(task, ['id', 'title', 'issue', 'dependencies', 'integration_order', 'parallel_group', 'risk_class', 'packet', 'p1', 'expected_write_set', 'conflict_domains', 'resource_requirements'], 'INVALID_MANIFEST', 'task');
    const id = entityId(task.id, 'task.id', 'INVALID_MANIFEST');
    assertControl(!taskIds.has(id), 'INVALID_MANIFEST', `重复 task id: ${id}`);
    taskIds.add(id);
    if (task.title !== undefined) nonEmptyString(task.title, `${id}.title`, 'INVALID_MANIFEST', 200);
    assertControl(task.issue === undefined || task.issue === null || (Number.isSafeInteger(task.issue) && task.issue > 0), 'INVALID_MANIFEST', `${id}.issue 非法`);
    const dependencies = uniqueArray(task.dependencies, `${id}.dependencies`, 'INVALID_MANIFEST')
      .map((dependency) => entityId(dependency, `${id}.dependency`, 'INVALID_MANIFEST'));
    assertControl(!dependencies.includes(id), 'INVALID_MANIFEST', `${id} 不能依赖自身`);
    assertControl(Number.isSafeInteger(task.integration_order) && task.integration_order > 0, 'INVALID_MANIFEST', `${id}.integration_order 必须是正整数`);
    assertControl(!orders.has(task.integration_order), 'INVALID_MANIFEST', `重复 integration_order: ${task.integration_order}`);
    orders.add(task.integration_order);
    if (task.parallel_group !== undefined) entityId(task.parallel_group, `${id}.parallel_group`, 'INVALID_MANIFEST');
    const riskClass = task.risk_class || 'STANDARD';
    assertControl(typeof riskClass === 'string' && riskClass.length <= 80 && /^[A-Z][A-Z0-9_]*$/.test(riskClass), 'INVALID_MANIFEST', `${id}.risk_class 非法`);
    assertPlainObject(task.packet, 'INVALID_MANIFEST', `${id}.packet`);
    assertOnlyKeys(task.packet, ['revision', 'path', 'sha256'], 'INVALID_MANIFEST', `${id}.packet`);
    assertControl(Number.isSafeInteger(task.packet.revision) && task.packet.revision > 0, 'INVALID_MANIFEST', `${id}.packet.revision 非法`);
    repoPath(task.packet.path, `${id}.packet.path`);
    const declaredPacketHash = normalizeHash(task.packet.sha256, `${id}.packet.sha256`);
    const packetPath = path.resolve(repositoryRoot, task.packet.path);
    realpathWithin(repositoryRoot, packetPath, `${id}.packet.path`);
    const computedHash = hashFile(packetPath);
    assertControl(declaredPacketHash === computedHash, 'PACKET_HASH_MISMATCH', `${id} packet hash 与文件不一致`);

    let p1;
    if (task.p1 !== undefined) {
      assertPlainObject(task.p1, 'INVALID_MANIFEST', `${id}.p1`);
      assertOnlyKeys(
        task.p1,
        ['producer', 'artifact_root', 'authority', 'dependency_gate'],
        'INVALID_MANIFEST',
        `${id}.p1`,
      );
      assertControl(task.p1.producer === 'CAPTAIN', 'INVALID_MANIFEST', `${id}.p1.producer 必须是 CAPTAIN`);
      assertControl(
        Number.isSafeInteger(task.issue) && task.issue > 0,
        'INVALID_MANIFEST',
        `${id}.p1 需要 task.issue`,
      );
      const artifactRoot = repoPath(task.p1.artifact_root, `${id}.p1.artifact_root`);
      assertControl(
        artifactRoot === `docs/issues/${task.issue}`,
        'INVALID_MANIFEST',
        `${id}.p1.artifact_root 必须精确等于 docs/issues/${task.issue}`,
      );
      assertPlainObject(task.p1.authority, 'INVALID_MANIFEST', `${id}.p1.authority`);
      assertOnlyKeys(
        task.p1.authority,
        ['kind', 'path', 'sha256'],
        'INVALID_MANIFEST',
        `${id}.p1.authority`,
      );
      assertControl(
        task.p1.authority.kind === 'SCOPED_DELEGATION',
        'INVALID_MANIFEST',
        `${id}.p1.authority.kind 必须是 SCOPED_DELEGATION`,
      );
      const authorityPath = repoPath(task.p1.authority.path, `${id}.p1.authority.path`);
      assertControl(
        authorityPath !== artifactRoot && !authorityPath.startsWith(`${artifactRoot}/`),
        'INVALID_MANIFEST',
        `${id}.p1.authority 不得位于可写 artifact_root 内`,
      );
      const declaredAuthorityHash = normalizeHash(
        task.p1.authority.sha256,
        `${id}.p1.authority.sha256`,
      );
      const authorityFile = path.resolve(repositoryRoot, authorityPath);
      realpathWithin(repositoryRoot, authorityFile, `${id}.p1.authority.path`);
      const authorityStat = fs.lstatSync(authorityFile);
      assertControl(
        authorityStat.isFile() && !authorityStat.isSymbolicLink(),
        'INVALID_MANIFEST',
        `${id}.p1.authority 必须是仓库内普通文件`,
      );
      const computedAuthorityHash = hashFile(authorityFile);
      assertControl(
        declaredAuthorityHash === computedAuthorityHash,
        'P1_AUTHORITY_HASH_MISMATCH',
        `${id}.p1.authority hash 与文件不一致`,
      );
      assertControl(
        task.p1.dependency_gate === 'ARCHIVED',
        'INVALID_MANIFEST',
        `${id}.p1.dependency_gate 必须是 ARCHIVED`,
      );
      p1 = {
        producer: 'CAPTAIN',
        artifact_root: artifactRoot,
        authority: {
          kind: 'SCOPED_DELEGATION',
          path: authorityPath,
          sha256: computedAuthorityHash,
        },
        dependency_gate: 'ARCHIVED',
      };
    }

    const expectedWriteSet = uniqueArray(task.expected_write_set || [], `${id}.expected_write_set`, 'INVALID_MANIFEST');
    for (const pattern of expectedWriteSet) {
      if (p1) {
        mechanicalP1WritePattern(
          pattern,
          `${id}.expected_write_set item`,
          'INVALID_MANIFEST',
        );
      } else {
        nonEmptyString(
          pattern,
          `${id}.expected_write_set item`,
          'INVALID_MANIFEST',
          500,
        );
      }
    }
    const conflictDomains = uniqueArray(task.conflict_domains || [], `${id}.conflict_domains`, 'INVALID_MANIFEST')
      .map((domain) => entityId(domain, `${id}.conflict_domain`, 'INVALID_MANIFEST'));
    const resourceRequirements = uniqueArray(task.resource_requirements || [], `${id}.resource_requirements`, 'INVALID_MANIFEST').map((requirement) => {
      assertPlainObject(requirement, 'INVALID_MANIFEST', `${id}.resource requirement`);
      assertOnlyKeys(requirement, ['kind', 'id', 'access', 'roles'], 'INVALID_MANIFEST', `${id}.resource requirement`);
      assertControl(RESOURCE_KINDS.includes(requirement.kind), 'INVALID_MANIFEST', `${id} resource.kind 非法`);
      const requirementId = entityId(requirement.id, `${id}.resource.id`, 'INVALID_MANIFEST');
      assertControl(RESOURCE_ACCESS.includes(requirement.access), 'INVALID_MANIFEST', `${id} resource.access 非法`);
      let roles;
      if (requirement.roles !== undefined) {
        roles = uniqueArray(requirement.roles, `${id}.resource.roles`, 'INVALID_MANIFEST');
        assertControl(roles.length > 0, 'INVALID_MANIFEST', `${id}.resource.roles 不能为空`);
        for (const role of roles) {
          assertControl(RESOURCE_ROLES.includes(role), 'INVALID_MANIFEST', `${id}.resource.roles 包含非法 worker role: ${role}`);
        }
      }
      return {
        kind: requirement.kind,
        id: requirementId,
        access: requirement.access,
        ...(roles ? { roles: [...roles] } : {}),
      };
    });
    const resourceKeys = resourceRequirements.map((item) => `${item.kind}:${item.id}`);
    assertControl(new Set(resourceKeys).size === resourceKeys.length, 'INVALID_MANIFEST', `${id}.resource_requirements 存在重复 kind/id`);

    return {
      id,
      ...(task.title !== undefined ? { title: task.title } : {}),
      ...(task.issue !== undefined ? { issue: task.issue } : {}),
      dependencies,
      integration_order: task.integration_order,
      ...(task.parallel_group !== undefined ? { parallel_group: task.parallel_group } : {}),
      risk_class: riskClass,
      expected_write_set: expectedWriteSet,
      conflict_domains: conflictDomains,
      resource_requirements: resourceRequirements,
      packet: {
        revision: task.packet.revision,
        path: path.relative(repositoryRoot, packetPath).split(path.sep).join('/'),
        sha256: computedHash,
      },
      ...(p1 ? { p1 } : {}),
    };
  });

  for (const task of tasks) {
    for (const dependency of task.dependencies) {
      assertControl(taskIds.has(dependency), 'INVALID_MANIFEST', `${task.id} 依赖未知 task: ${dependency}`);
    }
  }
  detectDependencyCycle(tasks);
  const orderedTasks = [...tasks].sort(
    (left, right) => left.integration_order - right.integration_order,
  );
  if (orderedTasks.some((task) => task.p1)) {
    assertControl(
      orderedTasks.every((task) => task.p1),
      'INVALID_MANIFEST',
      'mechanical P1 v1 Goal 要求所有 task 都显式启用 p1，禁止 mixed mode',
    );
    assertControl(
      orderedTasks[0].dependencies.length === 0,
      'INVALID_MANIFEST',
      `mechanical P1 v1 首项 ${orderedTasks[0].id} 不得有 dependency`,
    );
    for (let index = 1; index < orderedTasks.length; index += 1) {
      const previous = orderedTasks[index - 1];
      const current = orderedTasks[index];
      assertControl(
        current.dependencies.includes(previous.id),
        'INVALID_MANIFEST',
        `mechanical P1 v1 要求 ${current.id} 直接依赖紧邻前项 ${previous.id}`,
      );
    }
  }
  if (preclaim) {
    const taskIssues = orderedTasks
      .map((task) => task.issue)
      .filter((issue) => Number.isSafeInteger(issue))
      .sort((left, right) => left - right);
    assertControl(
      hashObject(taskIssues) === hashObject(preclaim.issues),
      'INVALID_MANIFEST',
      'manifest.preclaim.issues 必须精确等于 task issue 白名单',
    );
    assertControl(
      orderedTasks.every(
        (task) => task.p1
          && task.p1.authority.path === preclaim.authorization.path
          && task.p1.authority.sha256 === preclaim.authorization.sha256,
      ),
      'INVALID_MANIFEST',
      'manifest.preclaim.authorization 必须与全部 task P1 authority 一致',
    );
  }

  const normalized = {
    schema_version: 1,
    goal_id: goalId,
    ...(manifest.title !== undefined ? { title: manifest.title } : {}),
    mode,
    repository: {
      name_with_owner: manifest.repository.name_with_owner,
      base_branch: 'main',
      ...(manifest.repository.merge_policy !== undefined
        ? { merge_policy: manifest.repository.merge_policy }
        : {}),
    },
    base_head: manifest.base_head,
    ...(protocol ? { protocol } : {}),
    ...(preclaim ? { preclaim } : {}),
    ...(workerCanaryBootstrap
      ? { worker_canary_bootstrap: workerCanaryBootstrap }
      : {}),
    ...(probeObservationReceipts
      ? { probe_observation_receipts: probeObservationReceipts }
      : {}),
    source_manifest: path.relative(fs.realpathSync(repositoryRoot), fs.realpathSync(manifestFile)).split(path.sep).join('/'),
    tasks: orderedTasks,
  };
  normalized.manifest_sha256 = hashObject(normalized);
  return normalized;
}

function detectDependencyCycle(tasks) {
  const byId = new Map(tasks.map((task) => [task.id, task]));
  const visiting = new Set();
  const visited = new Set();
  function visit(id) {
    if (visited.has(id)) return;
    assertControl(!visiting.has(id), 'INVALID_MANIFEST', `任务依赖存在环: ${[...visiting, id].join(' -> ')}`);
    visiting.add(id);
    for (const dependency of byId.get(id).dependencies) visit(dependency);
    visiting.delete(id);
    visited.add(id);
  }
  for (const task of tasks) visit(task.id);
}

function validateActor(actor) {
  assertPlainObject(actor, 'INVALID_EVENT', 'event.actor');
  assertOnlyKeys(actor, ['role', 'thread_id', 'host_id'], 'INVALID_EVENT', 'event.actor');
  assertControl(ROLES.includes(actor.role), 'INVALID_EVENT', `未知 actor role: ${actor.role}`);
  entityId(actor.thread_id, 'actor.thread_id', 'INVALID_EVENT');
  if (actor.host_id !== undefined) {
    entityId(actor.host_id, 'actor.host_id', 'INVALID_EVENT');
  }
  return {
    role: actor.role,
    thread_id: actor.thread_id,
    host_id: actor.host_id || 'local',
  };
}

function validateRuntimeRotationPayload(payload) {
  assertControl(
    ['DEV', 'REVIEW', 'RECEIPT'].includes(payload.role),
    'INVALID_EVENT',
    'RUNTIME_ROTATED.payload.role 必须是 worker role',
  );
  for (const key of [
    'worker_thread_id',
    'worker_host_id',
    'predecessor_launch_id',
    'successor_launch_id',
  ]) {
    entityId(
      payload[key],
      `RUNTIME_ROTATED.payload.${key}`,
      'INVALID_EVENT',
    );
  }
  safeId(payload.hold_id, 'RUNTIME_ROTATED.payload.hold_id');
  for (const key of ['worker_attempt', 'predecessor_incarnation']) {
    assertControl(
      Number.isSafeInteger(payload[key]) && payload[key] > 0,
      'INVALID_EVENT',
      `RUNTIME_ROTATED.payload.${key} 必须是正整数`,
    );
  }
  assertControl(
    payload.successor_incarnation === payload.predecessor_incarnation + 1,
    'INVALID_EVENT',
    'RUNTIME_ROTATED runtime incarnation 必须恰好 +1',
  );
  assertControl(
    payload.predecessor_launch_id !== payload.successor_launch_id,
    'INVALID_EVENT',
    'RUNTIME_ROTATED successor launch_id 必须 fresh',
  );
  normalizeHash(
    payload.predecessor_launch_sha256,
    'RUNTIME_ROTATED.payload.predecessor_launch_sha256',
  );
  normalizeHash(
    payload.lease_set_sha256,
    'RUNTIME_ROTATED.payload.lease_set_sha256',
  );
  assertControl(
    typeof payload.runtime_nonce === 'string'
      && /^[0-9a-f]{40}$/.test(payload.runtime_nonce),
    'INVALID_EVENT',
    'RUNTIME_ROTATED.payload.runtime_nonce 非法',
  );
  nonEmptyString(
    payload.reason,
    'RUNTIME_ROTATED.payload.reason',
    'INVALID_EVENT',
    4000,
  );
  nonEmptyString(
    payload.incident_ref,
    'RUNTIME_ROTATED.payload.incident_ref',
    'INVALID_EVENT',
    2000,
  );
  const proof = assertPlainObject(
    payload.retirement_proof,
    'INVALID_EVENT',
    'RUNTIME_ROTATED.payload.retirement_proof',
  );
  assertOnlyKeys(
    proof,
    [
      'schema_version',
      'kind',
      'predecessor_launch_id',
      'predecessor_pid',
      'preview_port',
      'proxy_port',
      'sample_count',
      'samples',
    ],
    'INVALID_EVENT',
    'RUNTIME_ROTATED.payload.retirement_proof',
  );
  assertControl(
    proof.schema_version === 1
      && proof.kind === 'LOCAL_PREVIEW_ZERO_WITNESS'
      && proof.predecessor_launch_id === payload.predecessor_launch_id
      && Number.isSafeInteger(proof.predecessor_pid)
      && proof.predecessor_pid > 0
      && Number.isSafeInteger(proof.preview_port)
      && proof.preview_port > 0
      && proof.preview_port <= 65535
      && Number.isSafeInteger(proof.proxy_port)
      && proof.proxy_port > 0
      && proof.proxy_port <= 65535
      && proof.proxy_port !== proof.preview_port
      && proof.sample_count === 3
      && Array.isArray(proof.samples)
      && proof.samples.length === 3,
    'INVALID_EVENT',
    'RUNTIME_ROTATED retirement proof binding/shape 非法',
  );
  for (const [index, sample] of proof.samples.entries()) {
    assertPlainObject(
      sample,
      'INVALID_EVENT',
      `RUNTIME_ROTATED retirement proof sample[${index}]`,
    );
    assertOnlyKeys(
      sample,
      [
        'observed_at',
        'predecessor_pid_absent',
        'preview_listener_absent',
        'proxy_listener_absent',
        'matching_process_count',
      ],
      'INVALID_EVENT',
      `RUNTIME_ROTATED retirement proof sample[${index}]`,
    );
    assertControl(
      typeof sample.observed_at === 'string'
        && Number.isFinite(Date.parse(sample.observed_at))
        && sample.predecessor_pid_absent === true
        && sample.preview_listener_absent === true
        && sample.proxy_listener_absent === true
        && sample.matching_process_count === 0,
      'INVALID_EVENT',
      `RUNTIME_ROTATED retirement proof sample[${index}] 非法`,
    );
  }
}

function validateEvent(event) {
  assertPlainObject(event, 'INVALID_EVENT', 'event');
  assertOnlyKeys(event, ['schema_version', 'event_id', 'goal_id', 'task_id', 'type', 'actor', 'actor_sequence', 'expected_state_revision', 'control_epoch', 'packet', 'base_head', 'full_head', 'payload'], 'INVALID_EVENT', 'event');
  assertControl(event.schema_version === 1, 'UNSUPPORTED_SCHEMA', 'event.schema_version 必须为 1');
  safeId(event.event_id, 'event_id');
  entityId(event.goal_id, 'goal_id', 'INVALID_EVENT');
  entityId(event.task_id, 'task_id', 'INVALID_EVENT');
  assertControl(typeof event.type === 'string' && /^[A-Z][A-Z0-9_]*$/.test(event.type), 'INVALID_EVENT', 'event.type 非法');
  const actor = validateActor(event.actor);
  assertControl(Number.isSafeInteger(event.actor_sequence) && event.actor_sequence > 0, 'INVALID_EVENT', 'actor_sequence 必须为正整数');
  assertControl(Number.isSafeInteger(event.expected_state_revision) && event.expected_state_revision >= 0, 'INVALID_EVENT', 'expected_state_revision 必须为非负整数');
  assertControl(Number.isSafeInteger(event.control_epoch) && event.control_epoch >= 0, 'INVALID_EVENT', 'control_epoch 必须为非负整数');
  assertPlainObject(event.packet, 'INVALID_EVENT', 'event.packet');
  assertOnlyKeys(event.packet, ['revision', 'sha256'], 'INVALID_EVENT', 'event.packet');
  assertControl(Number.isSafeInteger(event.packet.revision) && event.packet.revision > 0, 'INVALID_EVENT', 'packet.revision 非法');
  const packetHash = normalizeHash(event.packet.sha256, 'event.packet.sha256');
  assertFullSha(event.base_head, 'event.base_head');
  assertFullSha(event.full_head, 'event.full_head');
  assertControl(event.payload === undefined || (event.payload && typeof event.payload === 'object' && !Array.isArray(event.payload)), 'INVALID_EVENT', 'event.payload 必须是对象');
  assertControl(EVENT_PAYLOAD_KEYS[event.type], 'INVALID_EVENT', `未知 event.type: ${event.type}`);
  const payload = event.payload || {};
  assertOnlyKeys(payload, EVENT_PAYLOAD_KEYS[event.type], 'INVALID_EVENT', `${event.type}.payload`);
  const missingPayloadKeys = EVENT_PAYLOAD_REQUIRED[event.type].filter((key) => !Object.prototype.hasOwnProperty.call(payload, key));
  assertControl(missingPayloadKeys.length === 0, 'INVALID_EVENT', `${event.type}.payload 缺字段: ${missingPayloadKeys.join(', ')}`);
  assertNoSensitiveKeys(payload, `${event.type}.payload`, 'INVALID_EVENT');
  if (event.type === 'RUNTIME_ROTATED') {
    validateRuntimeRotationPayload(payload);
  }
  if (
    event.type === 'REGISTER_ROLE'
      && payload.worker_bootstrap !== undefined
  ) {
    const {
      validateWorkerBootstrapBinding,
    } = require('./worker-bootstrap-binding');
    validateWorkerBootstrapBinding(
      payload.worker_bootstrap,
      'REGISTER_ROLE.payload.worker_bootstrap',
    );
  }
  if (
    [
      'REGISTER_ROLE',
      'RECOVER_EXPIRED_FOREMAN',
      'PROBE_OBSERVATION_REFRESHED',
    ].includes(event.type)
      && payload.probe_observation !== undefined
  ) {
    const {
      validateBinding,
    } = require('./canary-observation-receipt');
    validateBinding(
      payload.probe_observation,
      `${event.type}.payload.probe_observation`,
    );
  }
  if (
    event.type === 'RESOLVE_HOLD'
      && payload.runtime_preflight_evidence_id !== undefined
  ) {
    safeId(
      payload.runtime_preflight_evidence_id,
      'RESOLVE_HOLD.payload.runtime_preflight_evidence_id',
    );
  }
  if (event.type === 'START_P1') {
    if (payload.required_start_head !== undefined) {
      assertFullSha(payload.required_start_head, 'START_P1.payload.required_start_head');
    }
    if (payload.p1_worktree !== undefined) {
      nonEmptyString(
        payload.p1_worktree,
        'START_P1.payload.p1_worktree',
        'INVALID_EVENT',
        2000,
      );
      assertControl(
        path.isAbsolute(payload.p1_worktree)
          && path.normalize(payload.p1_worktree) === payload.p1_worktree,
        'INVALID_EVENT',
        'START_P1.payload.p1_worktree 必须是规范绝对路径',
      );
    }
    if (payload.p1_branch !== undefined) {
      nonEmptyString(
        payload.p1_branch,
        'START_P1.payload.p1_branch',
        'INVALID_EVENT',
        500,
      );
    }
  }
  if (['P1_READY', 'P1_APPROVED', 'P1_COMMITTED'].includes(event.type)) {
    repoPath(payload.plan_path, `${event.type}.payload.plan_path`, 'INVALID_EVENT');
    repoPath(payload.context_path, `${event.type}.payload.context_path`, 'INVALID_EVENT');
    normalizeHash(payload.plan_sha256, `${event.type}.payload.plan_sha256`);
    normalizeHash(payload.context_sha256, `${event.type}.payload.context_sha256`);
    if (payload.artifact_manifest_sha256 !== undefined) {
      normalizeHash(
        payload.artifact_manifest_sha256,
        `${event.type}.payload.artifact_manifest_sha256`,
      );
    }
    if (payload.p1_worktree !== undefined) {
      nonEmptyString(
        payload.p1_worktree,
        `${event.type}.payload.p1_worktree`,
        'INVALID_EVENT',
        2000,
      );
      assertControl(
        path.isAbsolute(payload.p1_worktree)
          && path.normalize(payload.p1_worktree) === payload.p1_worktree,
        'INVALID_EVENT',
        `${event.type}.payload.p1_worktree 必须是规范绝对路径`,
      );
    }
    if (payload.p1_branch !== undefined) {
      nonEmptyString(
        payload.p1_branch,
        `${event.type}.payload.p1_branch`,
        'INVALID_EVENT',
        500,
      );
    }
    if (payload.p1_commit_ref !== undefined) {
      assertControl(
        P1_COMMIT_REF_RE.test(payload.p1_commit_ref),
        'INVALID_EVENT',
        `${event.type}.payload.p1_commit_ref 非法`,
      );
    }
  }
  if (event.type === 'P1_COMMIT_ABANDONED') {
    for (const key of [
      'prepared_event_id',
      'reason',
      'incident_ref',
    ]) {
      nonEmptyString(
        payload[key],
        `P1_COMMIT_ABANDONED.payload.${key}`,
        'INVALID_EVENT',
        2000,
      );
    }
    assertControl(
      Number.isSafeInteger(payload.task_cycle) && payload.task_cycle > 0,
      'INVALID_EVENT',
      'P1_COMMIT_ABANDONED.payload.task_cycle 必须是正整数',
    );
    for (const key of [
      'p1_intent_sha256',
      'abandon_intent_sha256',
      'abandon_request_sha256',
      'abandon_receipt_sha256',
      'predecessor_event_sha256',
    ]) {
      normalizeHash(
        payload[key],
        `P1_COMMIT_ABANDONED.payload.${key}`,
      );
    }
    assertControl(
      P1_COMMIT_REF_RE.test(payload.commit_ref),
      'INVALID_EVENT',
      'P1_COMMIT_ABANDONED.payload.commit_ref 非法',
    );
    assertFullSha(
      payload.commit_sha,
      'P1_COMMIT_ABANDONED.payload.commit_sha',
    );
  }
  if (event.type === 'P1_RESTARTED') {
    for (const key of [
      'captain_recovery_event_id',
      'predecessor_thread_id',
      'predecessor_host_id',
      'successor_thread_id',
      'successor_host_id',
      'abandoned_p1_branch',
      'reason',
      'incident_ref',
    ]) {
      nonEmptyString(
        payload[key],
        `P1_RESTARTED.payload.${key}`,
        'INVALID_EVENT',
        key === 'reason' ? 4000 : 2000,
      );
    }
    nonEmptyString(
      payload.abandoned_p1_worktree,
      'P1_RESTARTED.payload.abandoned_p1_worktree',
      'INVALID_EVENT',
      2000,
    );
    assertControl(
      path.isAbsolute(payload.abandoned_p1_worktree)
        && path.normalize(payload.abandoned_p1_worktree)
          === payload.abandoned_p1_worktree,
      'INVALID_EVENT',
      'P1_RESTARTED.payload.abandoned_p1_worktree 必须是规范绝对路径',
    );
    for (const key of ['predecessor_attempt', 'successor_attempt']) {
      assertControl(
        Number.isSafeInteger(payload[key]) && payload[key] > 0,
        'INVALID_EVENT',
        `P1_RESTARTED.payload.${key} 必须是正整数`,
      );
    }
  }
  if (event.type === 'RECOVERY_HANDOFF_ABANDONED') {
    for (const key of [
      'successor_thread_id',
      'handoff_event_id',
      'reason',
      'incident_ref',
      'foreman_thread_id',
      'foreman_host_id',
    ]) {
      nonEmptyString(payload[key], `RECOVERY_HANDOFF_ABANDONED.payload.${key}`, 'INVALID_EVENT', 2000);
    }
    assertControl(
      Number.isSafeInteger(payload.foreman_attempt) && payload.foreman_attempt > 0,
      'INVALID_EVENT',
      'RECOVERY_HANDOFF_ABANDONED.payload.foreman_attempt 必须是正整数',
    );
  }
  if (event.type === 'GITHUB_MERGE_RESERVED') {
    safeId(payload.target_event_id, 'GITHUB_MERGE_RESERVED target_event_id');
    normalizeHash(
      payload.request_sha256,
      'GITHUB_MERGE_RESERVED request_sha256',
    );
    assertControl(
      typeof payload.repository === 'string'
        && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(payload.repository),
      'INVALID_EVENT',
      'GITHUB_MERGE_RESERVED repository 非 canonical owner/repo',
    );
    assertControl(
      Number.isSafeInteger(payload.pull_request_number)
        && payload.pull_request_number > 0,
      'INVALID_EVENT',
      'GITHUB_MERGE_RESERVED pull_request_number 非法',
    );
    const parsed = parsePullRequestUrl(
      payload.pull_request_url,
      payload.repository,
    );
    assertControl(
      parsed.number === payload.pull_request_number,
      'INVALID_EVENT',
      'GITHUB_MERGE_RESERVED PR number/url 不一致',
    );
    nonEmptyString(
      payload.base_branch,
      'GITHUB_MERGE_RESERVED base_branch',
      'INVALID_EVENT',
      500,
    );
    assertFullSha(
      payload.expected_main_head,
      'GITHUB_MERGE_RESERVED expected_main_head',
    );
    assertFullSha(
      payload.candidate_head,
      'GITHUB_MERGE_RESERVED candidate_head',
    );
    assertControl(
      Number.isSafeInteger(payload.task_cycle) && payload.task_cycle > 0,
      'INVALID_EVENT',
      'GITHUB_MERGE_RESERVED task_cycle 非法',
    );
    assertControl(
      payload.phase === 'ACCEPTED_PENDING_MERGE',
      'INVALID_EVENT',
      'GITHUB_MERGE_RESERVED phase 非法',
    );
    assertControl(
      Number.isSafeInteger(payload.issue) && payload.issue > 0,
      'INVALID_EVENT',
      'GITHUB_MERGE_RESERVED issue 非法',
    );
    nonEmptyString(
      payload.head_ref_name,
      'GITHUB_MERGE_RESERVED head_ref_name',
      'INVALID_EVENT',
      500,
    );
    normalizeHash(
      payload.body_sha256,
      'GITHUB_MERGE_RESERVED body_sha256',
    );
    assertControl(
      payload.preflight_attestation
        && payload.preflight_attestation.schema_version === 1
        && payload.preflight_attestation.required_checks
        && payload.preflight_attestation.required_checks.status === 'PASS'
        && payload.preflight_attestation.gh_executable
        && typeof payload.preflight_attestation.gh_executable.path === 'string',
      'INVALID_EVENT',
      'GITHUB_MERGE_RESERVED preflight_attestation 非脱敏 PASS 摘要',
    );
    normalizeHash(
      payload.preflight_attestation.required_checks.output_sha256,
      'GITHUB_MERGE_RESERVED required checks hash',
    );
    normalizeHash(
      payload.preflight_attestation.gh_executable.sha256,
      'GITHUB_MERGE_RESERVED gh executable hash',
    );
    normalizeHash(
      payload.pr_contract_sha256,
      'GITHUB_MERGE_RESERVED pr_contract_sha256',
    );
  }
  if (event.type === 'MERGED') {
    if (payload.merge_reservation_event_id !== undefined) {
      safeId(
        payload.merge_reservation_event_id,
        'MERGED merge_reservation_event_id',
      );
    }
    if (payload.merge_request_sha256 !== undefined) {
      normalizeHash(
        payload.merge_request_sha256,
        'MERGED merge_request_sha256',
      );
    }
  }
  if (event.type === 'DEV_READY') parsePullRequestUrl(payload.pr);
  return {
    schema_version: 1,
    event_id: event.event_id,
    goal_id: event.goal_id,
    task_id: event.task_id,
    type: event.type,
    actor,
    actor_sequence: event.actor_sequence,
    expected_state_revision: event.expected_state_revision,
    control_epoch: event.control_epoch,
    packet: { revision: event.packet.revision, sha256: packetHash },
    base_head: event.base_head,
    full_head: event.full_head,
    payload,
  };
}

function validateEvidenceItem(item, label, packetHash, fullHead) {
  assertControl(item && typeof item === 'object', 'EVIDENCE_REQUIRED', `${label} evidence 缺失`);
  assertControl(item.status === 'PASS', 'EVIDENCE_REQUIRED', `${label} evidence 必须 PASS`);
  assertControl(normalizeHash(item.packet_sha256, `${label}.packet_sha256`) === packetHash, 'STALE_EVIDENCE', `${label} packet hash 陈旧`);
  assertFullSha(item.full_head, `${label}.full_head`);
  assertControl(item.full_head === fullHead, 'STALE_EVIDENCE', `${label} HEAD 陈旧`);
  assertControl(typeof item.uri === 'string' && item.uri.length > 0, 'EVIDENCE_REQUIRED', `${label} evidence.uri 缺失`);
  return item;
}

function validateDevEvidence(evidence, packetHash, fullHead) {
  assertControl(evidence && typeof evidence === 'object', 'EVIDENCE_REQUIRED', 'DEV_READY 缺 evidence');
  const required = ['preflight', 'fast', 'full_ci', 'ac_audit'];
  const output = {};
  for (const key of required) output[key] = validateEvidenceItem(evidence[key], key, packetHash, fullHead);
  return output;
}

function validateSingleEvidence(evidence, key, packetHash, fullHead) {
  assertControl(evidence && typeof evidence === 'object', 'EVIDENCE_REQUIRED', `${key} evidence 缺失`);
  return validateEvidenceItem(evidence[key] || evidence, key, packetHash, fullHead);
}

function validateLaunchManifest(manifest) {
  assertPlainObject(manifest, 'INVALID_LAUNCH_MANIFEST', 'launch manifest');
  assertOnlyKeys(manifest, ['schema_version', 'launch_id', 'goal_id', 'task_id', 'role', 'control_epoch', 'state_revision', 'thread', 'packet', 'repository', 'runtime', 'runtime_incarnation', 'worker_bootstrap', 'execution', 'pull_request', 'resource_leases', 'created_at'], 'INVALID_LAUNCH_MANIFEST', 'launch manifest');
  assertNoSensitiveKeys(manifest, 'launch manifest', 'INVALID_LAUNCH_MANIFEST');
  assertControl(manifest.schema_version === 1, 'UNSUPPORTED_SCHEMA', 'launch manifest schema_version 必须为 1');
  entityId(manifest.goal_id, 'launch.goal_id', 'INVALID_LAUNCH_MANIFEST');
  entityId(manifest.task_id, 'launch.task_id', 'INVALID_LAUNCH_MANIFEST');
  assertControl(ROLES.includes(manifest.role), 'INVALID_LAUNCH_MANIFEST', 'launch.role 非法');
  entityId(manifest.launch_id, 'launch.launch_id', 'INVALID_LAUNCH_MANIFEST');
  assertControl(Number.isSafeInteger(manifest.control_epoch) && manifest.control_epoch >= 0, 'INVALID_LAUNCH_MANIFEST', 'launch.control_epoch 非法');
  assertControl(Number.isSafeInteger(manifest.state_revision) && manifest.state_revision >= 0, 'INVALID_LAUNCH_MANIFEST', 'launch.state_revision 非法');

  assertPlainObject(manifest.thread, 'INVALID_LAUNCH_MANIFEST', 'launch.thread');
  assertOnlyKeys(manifest.thread, ['id', 'host_id', 'title', 'cwd'], 'INVALID_LAUNCH_MANIFEST', 'launch.thread');
  nonEmptyString(manifest.thread.id, 'launch.thread.id', 'INVALID_LAUNCH_MANIFEST', 200);
  nonEmptyString(manifest.thread.host_id, 'launch.thread.host_id', 'INVALID_LAUNCH_MANIFEST', 200);
  assertControl(path.isAbsolute(nonEmptyString(manifest.thread.cwd, 'launch.thread.cwd', 'INVALID_LAUNCH_MANIFEST', 1000)), 'INVALID_LAUNCH_MANIFEST', 'launch.thread.cwd 必须是绝对路径');
  if (manifest.thread.title !== undefined) nonEmptyString(manifest.thread.title, 'launch.thread.title', 'INVALID_LAUNCH_MANIFEST', 200);

  assertPlainObject(manifest.repository, 'INVALID_LAUNCH_MANIFEST', 'launch.repository');
  assertOnlyKeys(manifest.repository, ['name_with_owner', 'origin_url', 'base_branch', 'base_head', 'full_head', 'branch', 'root', 'worktree'], 'INVALID_LAUNCH_MANIFEST', 'launch.repository');
  assertControl(typeof manifest.repository.name_with_owner === 'string' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(manifest.repository.name_with_owner), 'INVALID_LAUNCH_MANIFEST', 'launch.repository.name_with_owner 非法');
  safeHttpUrl(manifest.repository.origin_url, 'launch.repository.origin_url', { httpsOnly: true, noQuery: true });
  assertControl(manifest.repository.base_branch === 'main', 'INVALID_LAUNCH_MANIFEST', 'launch.repository.base_branch 必须为 main');
  assertFullSha(manifest.repository.base_head, 'launch.repository.base_head');
  assertFullSha(manifest.repository.full_head, 'launch.repository.full_head');
  nonEmptyString(manifest.repository.branch, 'launch.repository.branch', 'INVALID_LAUNCH_MANIFEST', 300);
  assertControl(path.isAbsolute(nonEmptyString(manifest.repository.root, 'launch.repository.root', 'INVALID_LAUNCH_MANIFEST', 1000)), 'INVALID_LAUNCH_MANIFEST', 'launch.repository.root 必须是绝对路径');
  assertControl(path.isAbsolute(nonEmptyString(manifest.repository.worktree, 'launch.repository.worktree', 'INVALID_LAUNCH_MANIFEST', 1000)), 'INVALID_LAUNCH_MANIFEST', 'launch.repository.worktree 必须是绝对路径');

  assertPlainObject(manifest.packet, 'INVALID_LAUNCH_MANIFEST', 'launch.packet');
  assertOnlyKeys(manifest.packet, ['revision', 'path', 'sha256'], 'INVALID_LAUNCH_MANIFEST', 'launch.packet');
  normalizeHash(manifest.packet.sha256, 'launch.packet.sha256');
  assertControl(Number.isSafeInteger(manifest.packet.revision) && manifest.packet.revision > 0, 'INVALID_LAUNCH_MANIFEST', 'launch.packet.revision 非法');
  repoPath(manifest.packet.path, 'launch.packet.path', 'INVALID_LAUNCH_MANIFEST');

  assertPlainObject(manifest.runtime, 'INVALID_LAUNCH_MANIFEST', 'launch.runtime');
  assertOnlyKeys(manifest.runtime, ['node_version', 'pnpm_version', 'lockfile_sha256', 'model'], 'INVALID_LAUNCH_MANIFEST', 'launch.runtime');
  nonEmptyString(manifest.runtime.node_version, 'launch.runtime.node_version', 'INVALID_LAUNCH_MANIFEST', 100);
  nonEmptyString(manifest.runtime.pnpm_version, 'launch.runtime.pnpm_version', 'INVALID_LAUNCH_MANIFEST', 100);
  normalizeHash(manifest.runtime.lockfile_sha256, 'launch.runtime.lockfile_sha256');
  if (manifest.runtime.model !== undefined) {
    assertPlainObject(manifest.runtime.model, 'INVALID_LAUNCH_MANIFEST', 'launch.runtime.model');
    assertOnlyKeys(manifest.runtime.model, ['requested', 'actual', 'reasoning_effort'], 'INVALID_LAUNCH_MANIFEST', 'launch.runtime.model');
    if (manifest.runtime.model.requested !== undefined) nonEmptyString(manifest.runtime.model.requested, 'model.requested', 'INVALID_LAUNCH_MANIFEST', 200);
    if (manifest.runtime.model.actual !== undefined) nonEmptyString(manifest.runtime.model.actual, 'model.actual', 'INVALID_LAUNCH_MANIFEST', 200);
    if (manifest.runtime.model.reasoning_effort !== undefined) assertControl(['low', 'medium', 'high', 'xhigh', 'max', 'ultra'].includes(manifest.runtime.model.reasoning_effort), 'INVALID_LAUNCH_MANIFEST', 'model.reasoning_effort 非法');
  }
  if (manifest.runtime_incarnation !== undefined) {
    assertPlainObject(
      manifest.runtime_incarnation,
      'INVALID_LAUNCH_MANIFEST',
      'launch.runtime_incarnation',
    );
    assertOnlyKeys(
      manifest.runtime_incarnation,
      ['epoch', 'nonce', 'rotation_event_id'],
      'INVALID_LAUNCH_MANIFEST',
      'launch.runtime_incarnation',
    );
    assertControl(
      Number.isSafeInteger(manifest.runtime_incarnation.epoch)
        && manifest.runtime_incarnation.epoch >= 2,
      'INVALID_LAUNCH_MANIFEST',
      'launch.runtime_incarnation.epoch 必须 >= 2',
    );
    assertControl(
      typeof manifest.runtime_incarnation.nonce === 'string'
        && /^[0-9a-f]{40}$/.test(manifest.runtime_incarnation.nonce),
      'INVALID_LAUNCH_MANIFEST',
      'launch.runtime_incarnation.nonce 非法',
    );
    safeId(
      manifest.runtime_incarnation.rotation_event_id,
      'launch.runtime_incarnation.rotation_event_id',
    );
  }
  if (manifest.worker_bootstrap !== undefined) {
    const {
      validateWorkerBootstrapBinding,
    } = require('./worker-bootstrap-binding');
    validateWorkerBootstrapBinding(
      manifest.worker_bootstrap,
      'launch.worker_bootstrap',
    );
  }

  assertPlainObject(manifest.execution, 'INVALID_LAUNCH_MANIFEST', 'launch.execution');
  assertOnlyKeys(manifest.execution, ['environment', 'domain', 'account_alias', 'tim_alias', 'write_mode', 'task_nonce', 'identity_probe', 'target'], 'INVALID_LAUNCH_MANIFEST', 'launch.execution');
  const environment = nonEmptyString(manifest.execution.environment, 'launch.execution.environment', 'INVALID_LAUNCH_MANIFEST', 200);
  assertControl(['NONE', 'TESTING_WRITE', 'READ_ONLY'].includes(manifest.execution.write_mode), 'INVALID_LAUNCH_MANIFEST', 'launch.execution.write_mode 非法');
  if (manifest.execution.write_mode === 'TESTING_WRITE') assertControl(environment === 'testing', 'ENV_WRITE_POLICY_VIOLATION', 'TESTING_WRITE 只允许 testing 环境');
  assertControl(typeof manifest.execution.task_nonce === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(manifest.execution.task_nonce), 'INVALID_LAUNCH_MANIFEST', 'launch.execution.task_nonce 缺失或非法');
  for (const alias of ['account_alias', 'tim_alias']) {
    if (manifest.execution[alias] !== undefined) assertControl(/^[A-Za-z][A-Za-z0-9._-]{0,119}$/.test(manifest.execution[alias]), 'INVALID_LAUNCH_MANIFEST', `launch.execution.${alias} 非法`);
  }
  if (manifest.execution.domain !== undefined) nonEmptyString(manifest.execution.domain, 'launch.execution.domain', 'INVALID_LAUNCH_MANIFEST', 300);
  if (environment !== 'none' || manifest.execution.write_mode !== 'NONE') {
    assertPlainObject(manifest.execution.identity_probe, 'INVALID_LAUNCH_MANIFEST', 'launch.execution.identity_probe');
    assertOnlyKeys(manifest.execution.identity_probe, ['path', 'sha256'], 'INVALID_LAUNCH_MANIFEST', 'launch.execution.identity_probe');
    assertControl(path.isAbsolute(nonEmptyString(manifest.execution.identity_probe.path, 'identity_probe.path', 'INVALID_LAUNCH_MANIFEST', 1000)), 'INVALID_LAUNCH_MANIFEST', 'identity_probe.path 必须是绝对路径');
    normalizeHash(manifest.execution.identity_probe.sha256, 'identity_probe.sha256');
  }

  assertPlainObject(manifest.execution.target, 'INVALID_LAUNCH_MANIFEST', 'launch.execution.target');
  assertOnlyKeys(manifest.execution.target, ['kind', 'executable_path', 'pid', 'started_at', 'preview_url', 'build_head', 'user_data_dir', 'cdp_target_id', 'window_id'], 'INVALID_LAUNCH_MANIFEST', 'launch.execution.target');
  const target = manifest.execution.target;
  assertControl(['NONE', 'CLI', 'PREVIEW', 'ELECTRON', 'BROWSER'].includes(target.kind), 'INVALID_LAUNCH_MANIFEST', 'execution.target.kind 非法');
  if (target.kind !== 'NONE') assertControl(path.isAbsolute(nonEmptyString(target.executable_path, 'target.executable_path', 'INVALID_LAUNCH_MANIFEST', 1000)), 'INVALID_LAUNCH_MANIFEST', 'target.executable_path 必须是绝对路径');
  if (['PREVIEW', 'ELECTRON', 'BROWSER'].includes(target.kind)) {
    assertControl(Number.isSafeInteger(target.pid) && target.pid > 0, 'INVALID_LAUNCH_MANIFEST', `${target.kind} target.pid 必填`);
    validDateTime(target.started_at, 'target.started_at', 'INVALID_LAUNCH_MANIFEST');
  }
  if (['ELECTRON', 'BROWSER'].includes(target.kind)) {
    assertControl(path.isAbsolute(nonEmptyString(target.user_data_dir, 'target.user_data_dir', 'INVALID_LAUNCH_MANIFEST', 1000)), 'INVALID_LAUNCH_MANIFEST', `${target.kind} user_data_dir 必填`);
  }
  if (target.kind === 'PREVIEW') safeHttpUrl(target.preview_url, 'target.preview_url');
  if (target.pid !== undefined) {
    assertControl(Number.isSafeInteger(target.pid) && target.pid > 0, 'INVALID_LAUNCH_MANIFEST', 'target.pid 非法');
    validDateTime(target.started_at, 'target.started_at', 'INVALID_LAUNCH_MANIFEST');
  }
  if (target.build_head !== undefined) assertFullSha(target.build_head, 'target.build_head');
  if (target.user_data_dir !== undefined) assertControl(path.isAbsolute(nonEmptyString(target.user_data_dir, 'target.user_data_dir', 'INVALID_LAUNCH_MANIFEST', 1000)), 'INVALID_LAUNCH_MANIFEST', 'target.user_data_dir 必须是绝对路径');
  if (target.preview_url !== undefined) {
    assertControl(target.kind === 'PREVIEW', 'INVALID_LAUNCH_MANIFEST', 'preview_url 只允许 PREVIEW target');
  }
  for (const field of ['cdp_target_id', 'window_id']) if (target[field] !== undefined) nonEmptyString(target[field], `target.${field}`, 'INVALID_LAUNCH_MANIFEST', 1000);

  uniqueArray(manifest.resource_leases, 'launch.resource_leases', 'INVALID_LAUNCH_MANIFEST').forEach((leaseId) => safeId(leaseId, 'launch.resource lease'));
  validDateTime(manifest.created_at, 'launch.created_at', 'INVALID_LAUNCH_MANIFEST');
  if (manifest.pull_request !== undefined && manifest.pull_request !== null) {
    assertPlainObject(manifest.pull_request, 'INVALID_LAUNCH_MANIFEST', 'launch.pull_request');
    assertOnlyKeys(manifest.pull_request, ['repository', 'number', 'base', 'head'], 'INVALID_LAUNCH_MANIFEST', 'launch.pull_request');
    assertControl(manifest.pull_request.repository === manifest.repository.name_with_owner, 'INVALID_LAUNCH_MANIFEST', 'pull_request.repository 与 launch repository 不一致');
    assertControl(Number.isSafeInteger(manifest.pull_request.number) && manifest.pull_request.number > 0, 'INVALID_LAUNCH_MANIFEST', 'pull_request.number 非法');
    assertControl(manifest.pull_request.base === 'main', 'INVALID_LAUNCH_MANIFEST', 'pull_request.base 必须为 main');
    assertFullSha(manifest.pull_request.head, 'pull_request.head');
    assertControl(manifest.pull_request.head === manifest.repository.full_head, 'INVALID_LAUNCH_MANIFEST', 'pull_request.head 与 launch full_head 不一致');
  }
  return manifest;
}

module.exports = {
  EVENT_PAYLOAD_REQUIRED,
  EVENT_PAYLOAD_KEYS,
  HARD_HOLDS,
  HOLD_KINDS,
  ROLES,
  WORKER_CANARY_BOOTSTRAP_POLICY_MARKER,
  PROBE_OBSERVATION_RECEIPT_PROTOCOL,
  WORKER_CANARY_BOOTSTRAP_PROTOCOL,
  assertLiveRoleLostTargetBinding,
  matchesMechanicalP1WritePattern,
  mechanicalP1WritePattern,
  parsePullRequestUrl,
  validateDevEvidence,
  validateEvent,
  validateEvidenceItem,
  validateLaunchManifest,
  validateManifest,
  validateSingleEvidence,
};
