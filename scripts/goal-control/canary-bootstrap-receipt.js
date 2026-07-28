'use strict';

const fs = require('fs');
const path = require('path');
const {
  BOOTSTRAP_PLAN_KIND,
} = require('./canary-bootstrap-identity-plan');
const {
  parsePrivateJson,
} = require('./canary-bootstrap-artifacts');
const { assertControl } = require('./errors');
const {
  canonicalJson,
  hashObject,
  normalizeHash,
  safeId,
  sha256,
} = require('./util');

const BOOTSTRAP_INTENT_KIND = 'WORKER_CANARY_PREPARE_INTENT';
const BOOTSTRAP_OBSERVATION_KIND =
  'WORKER_CANARY_IDENTITY_OBSERVATION';
const BOOTSTRAP_RECEIPT_KIND = 'WORKER_CANARY_PREPARE_RECEIPT';
const WORKER_ROLES = Object.freeze(['DEV', 'REVIEW', 'RECEIPT']);
const ALLOWED_OBSERVATIONS = Object.freeze([
  'THREAD_HOST_FROM_PLATFORM',
  'CANONICAL_CWD',
  'GIT_DIR',
  'GIT_COMMON_DIR',
  'HEAD',
  'BRANCH_OR_DETACHED',
  'CLEAN_STATUS',
]);
const FORBIDDEN_ACTIONS = Object.freeze([
  'ROLE_REGISTRATION',
  'CAPABILITY_OR_LEASE',
  'GOAL_EVENT_OR_RESUME',
  'GITHUB_OR_PUSH',
  'BROWSER_OR_ENVIRONMENT',
  'SOURCE_OR_INDEX_WRITE',
]);
const CHALLENGE_RE = /^[0-9a-f]{64}$/;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const HEAD_TRANSACTION_PROTOCOLS = new Set([
  'git-update-ref-symref-v1',
  'git-files-backend-hardlink-head-v1',
]);

function canonicalDirectory(candidate, code, label) {
  let resolved;
  let stat;
  try {
    resolved = fs.realpathSync(candidate);
    stat = fs.lstatSync(candidate);
  } catch (error) {
    assertControl(false, code, `${label} 不可读取: ${error.message}`);
  }
  assertControl(
    typeof candidate === 'string'
      && path.isAbsolute(candidate)
      && path.normalize(candidate) === candidate
      && resolved === candidate
      && stat.isDirectory()
      && !stat.isSymbolicLink(),
    code,
    `${label} 必须是 canonical non-symlink directory`,
  );
  return resolved;
}

function safePathSegment(value, label) {
  safeId(value, label);
  assertControl(
    value !== '.' && value !== '..',
    'CANARY_BOOTSTRAP_RECEIPT_INVALID',
    `${label} 禁止 dot path segment`,
  );
  return value;
}

function receiptPath(commonGitDir, receipt) {
  return path.join(
    commonGitDir,
    'goal-control',
    'worker-canary-bootstrap-v1',
    'goals',
    safePathSegment(receipt.goal_id, 'receipt goal_id'),
    'tasks',
    safePathSegment(receipt.task_id, 'receipt task_id'),
    sha256(receipt.operation_id),
    'receipt.json',
  );
}

function workerFromObservation(observation, workerBranch) {
  return {
    cwd: observation.cwd,
    git_dir: observation.git_dir,
    common_git_dir: observation.common_git_dir,
    head: observation.head,
    branch: workerBranch,
    clean: observation.clean,
    tree: observation.tree,
    index: observation.index,
    filesystem_identity: observation.filesystem_identity,
    registry: {
      worktree: observation.cwd,
      head: observation.head,
      branch: workerBranch,
      detached: false,
    },
    status_sha256: observation.status_sha256,
  };
}

function expectedObservation(receipt, observation) {
  return {
    schema_version: 1,
    kind: BOOTSTRAP_OBSERVATION_KIND,
    identity_plan_sha256: receipt.identity_plan_sha256,
    goal_id: receipt.goal_id,
    task_id: receipt.task_id,
    role: receipt.role,
    operation_id: receipt.operation_id,
    challenge: receipt.challenge,
    thread: receipt.thread,
    host: receipt.host,
    cwd: observation.cwd,
    git_dir: observation.git_dir,
    common_git_dir: observation.common_git_dir,
    head: observation.head,
    branch: null,
    clean: true,
    tree: observation.tree,
    index: observation.index,
    filesystem_identity: observation.filesystem_identity,
    registry: {
      worktree: observation.cwd,
      head: observation.head,
      branch: null,
      detached: true,
    },
    status_sha256: observation.status_sha256,
  };
}

function assertExpectedAuthority(options, receipt) {
  safeId(options.expectedOperationId, '--worker-bootstrap-operation-id');
  assertControl(
    CHALLENGE_RE.test(options.expectedChallenge),
    'CANARY_BOOTSTRAP_RECEIPT_BINDING_MISMATCH',
    '--worker-bootstrap-challenge 必须是 64 位小写 hex',
  );
  const expectedPlanSha256 = normalizeHash(
    options.expectedIdentityPlanSha256,
    '--worker-bootstrap-identity-plan-sha256',
  );
  assertControl(
    receipt.operation_id === options.expectedOperationId
      && receipt.challenge === options.expectedChallenge
      && receipt.identity_plan_sha256 === expectedPlanSha256,
    'CANARY_BOOTSTRAP_RECEIPT_BINDING_MISMATCH',
    'worker bootstrap receipt 未绑定 supervisor 指定的 operation/challenge/plan',
  );
}

function assertReceiptShape(receipt) {
  assertControl(
    receipt
      && receipt.schema_version === 1
      && receipt.kind === BOOTSTRAP_RECEIPT_KIND
      && SHA256_RE.test(receipt.receipt_binding_sha256)
      && receipt.identity_plan
      && typeof receipt.identity_plan === 'object'
      && !Array.isArray(receipt.identity_plan)
      && SHA256_RE.test(receipt.identity_plan_sha256)
      && SHA256_RE.test(receipt.identity_observation_sha256)
      && SHA256_RE.test(receipt.intent_sha256)
      && typeof receipt.goal_id === 'string'
      && typeof receipt.task_id === 'string'
      && WORKER_ROLES.includes(receipt.role)
      && typeof receipt.operation_id === 'string'
      && CHALLENGE_RE.test(receipt.challenge)
      && typeof receipt.thread === 'string'
      && typeof receipt.host === 'string'
      && typeof receipt.worker_branch === 'string'
      && receipt.worker_branch.startsWith('codex/')
      && receipt.controller
      && typeof receipt.controller === 'object'
      && !Array.isArray(receipt.controller)
      && receipt.frozen_repository
      && typeof receipt.frozen_repository === 'object'
      && !Array.isArray(receipt.frozen_repository)
      && receipt.manifest
      && typeof receipt.manifest === 'object'
      && !Array.isArray(receipt.manifest)
      && receipt.canary_policy
      && typeof receipt.canary_policy === 'object'
      && !Array.isArray(receipt.canary_policy)
      && receipt.worker
      && typeof receipt.worker === 'object'
      && !Array.isArray(receipt.worker)
      && receipt.worker.filesystem_identity
      && SHA256_RE.test(
        receipt.worker.filesystem_identity.worktree_key_sha256,
      )
      && receipt.head_transaction
      && typeof receipt.head_transaction === 'object'
      && !Array.isArray(receipt.head_transaction)
      && typeof receipt.head_transaction.claim_file === 'string'
      && SHA256_RE.test(receipt.head_transaction.claim_sha256)
      && HEAD_TRANSACTION_PROTOCOLS.has(
        receipt.head_transaction.transaction_protocol,
      )
      && (
        receipt.head_transaction.transaction_protocol
          !== 'git-files-backend-hardlink-head-v1'
          || (
            typeof receipt.head_transaction.completion_file === 'string'
              && SHA256_RE.test(
                receipt.head_transaction.completion_sha256,
              )
          )
      ),
    'CANARY_BOOTSTRAP_RECEIPT_INVALID',
    'worker bootstrap receipt schema/kind/hash 非法',
  );
}

function assertIdentityPlanBinding(
  options,
  receipt,
  authorizedCommonGitDir,
) {
  let currentNodeExecutable;
  try {
    currentNodeExecutable = fs.realpathSync(process.execPath);
  } catch (error) {
    assertControl(
      false,
      'CANARY_BOOTSTRAP_RECEIPT_BINDING_MISMATCH',
      `无法解析 current Node executable: ${error.message}`,
    );
  }
  const plan = receipt.identity_plan;
  const {
    identity_binding_sha256: identityBindingSha256,
    identity_capture: identityCapture,
    ...planCore
  } = plan;
  const exactPlanCore = {
    schema_version: 1,
    kind: BOOTSTRAP_PLAN_KIND,
    phase: 'IDENTITY_ONLY',
    controller: options.controller,
    frozen_repository: {
      worktree: options.repositoryRoot,
      common_git_dir: authorizedCommonGitDir,
      head: options.repositoryHead,
      name_with_owner: options.repositoryNameWithOwner,
      base_branch: options.baseBranch,
    },
    manifest: {
      path: options.manifestPath,
      sha256: options.manifestSha256,
      validated_manifest_sha256:
        options.validatedManifestSha256,
    },
    canary_policy: options.canaryPolicy,
    goal_id: options.goalId,
    task_id: options.taskId,
    role: options.role,
    expected_head: receipt.worker.head,
    operation_id: options.expectedOperationId,
    challenge: options.expectedChallenge,
    worker_branch: receipt.worker_branch,
    allowed_observations: ALLOWED_OBSERVATIONS,
    forbidden_actions: FORBIDDEN_ACTIONS,
  };
  assertControl(
    identityCapture
      && typeof identityCapture === 'object'
      && !Array.isArray(identityCapture)
      && identityCapture.node_executable
        === currentNodeExecutable
      && canonicalJson(planCore) === canonicalJson(exactPlanCore)
      && identityBindingSha256 === hashObject(exactPlanCore)
      && receipt.identity_plan_sha256 === hashObject(plan)
      && receipt.identity_plan_sha256
        === normalizeHash(
          options.expectedIdentityPlanSha256,
          '--worker-bootstrap-identity-plan-sha256',
        ),
    'CANARY_BOOTSTRAP_RECEIPT_BINDING_MISMATCH',
    'worker bootstrap receipt 未携带 supervisor hash-bound exact identity plan',
  );
}

function validateWorkerBootstrapReceipt(options, dependencies) {
  assertControl(
    WORKER_ROLES.includes(options.role),
    'CANARY_BOOTSTRAP_ROLE_INVALID',
    'worker bootstrap receipt 只适用于 worker role',
  );
  safeId(options.workerThread, '--worker-thread');
  safeId(options.workerHost, '--worker-host');
  const record = parsePrivateJson(
    options.receiptFile,
    'worker canary bootstrap receipt',
  );
  assertControl(
    record.sha256 === normalizeHash(
      options.expectedReceiptSha256,
      '--worker-bootstrap-receipt-sha256',
    ),
    'CANARY_BOOTSTRAP_RECEIPT_BINDING_MISMATCH',
    'worker bootstrap receipt bytes 与 expected SHA-256 不匹配',
  );
  const receipt = record.value;
  assertReceiptShape(receipt);
  assertExpectedAuthority(options, receipt);
  safePathSegment(receipt.goal_id, 'receipt goal_id');
  safePathSegment(receipt.task_id, 'receipt task_id');
  safeId(receipt.operation_id, 'receipt operation_id');

  const authorizedCommonGitDir = dependencies.repositoryCommonGitDir(
    options.repositoryRoot,
  );
  assertControl(
    receipt.frozen_repository
      && receipt.frozen_repository.worktree === options.repositoryRoot
      && receipt.frozen_repository.common_git_dir
        === authorizedCommonGitDir
      && receipt.frozen_repository.head === options.repositoryHead
      && receipt.worker.cwd !== options.repositoryRoot
      && receipt.worker.common_git_dir === authorizedCommonGitDir
      && receipt.worker.filesystem_identity.common_git_dir
        === authorizedCommonGitDir
      && options.receiptFile === receiptPath(
        authorizedCommonGitDir,
        receipt,
      ),
    'CANARY_BOOTSTRAP_RECEIPT_BINDING_MISMATCH',
    'worker bootstrap receipt 未绑定 authorized repository/common gitdir',
  );
  assertIdentityPlanBinding(
    options,
    receipt,
    authorizedCommonGitDir,
  );

  const intentFile = path.join(
    path.dirname(options.receiptFile),
    'intent.json',
  );
  const intent = parsePrivateJson(
    intentFile,
    'worker canary bootstrap intent',
  );
  const {
    request_sha256: intentRequestSha256,
    ...intentUnsigned
  } = intent.value || {};
  const observation = intentUnsigned.worker_observation;
  assertControl(
    observation
      && typeof observation === 'object'
      && !Array.isArray(observation),
    'CANARY_BOOTSTRAP_RECEIPT_INVALID',
    'worker bootstrap intent 缺 identity observation',
  );
  const exactObservation = expectedObservation(receipt, observation);
  const finalWorker = workerFromObservation(
    exactObservation,
    receipt.worker_branch,
  );
  const exactIntentUnsigned = {
    schema_version: 1,
    kind: BOOTSTRAP_INTENT_KIND,
    identity_plan_sha256: receipt.identity_plan_sha256,
    identity_observation_sha256:
      receipt.identity_observation_sha256,
    goal_id: receipt.goal_id,
    task_id: receipt.task_id,
    role: receipt.role,
    operation_id: receipt.operation_id,
    challenge: receipt.challenge,
    thread: receipt.thread,
    host: receipt.host,
    worker_branch: receipt.worker_branch,
    worker_observation: exactObservation,
    controller: receipt.controller,
    canary_policy: receipt.canary_policy,
  };
  assertControl(
    intent.sha256 === receipt.intent_sha256
      && intentRequestSha256 === hashObject(exactIntentUnsigned)
      && canonicalJson(intentUnsigned)
        === canonicalJson(exactIntentUnsigned)
      && receipt.identity_observation_sha256
        === hashObject(exactObservation)
      && canonicalJson(receipt.worker) === canonicalJson(finalWorker)
      && receipt.worker_branch === receipt.worker.branch,
    'CANARY_BOOTSTRAP_RECEIPT_INVALID',
    'worker bootstrap intent/observation/attached-worker projection 不匹配',
  );

  const targetRef = `refs/heads/${receipt.worker_branch}`;
  const exactHeadTransaction =
    dependencies.verifyWorktreeBootstrapHead({
      cwd: receipt.worker.cwd,
      artifactRoot: path.join(
        authorizedCommonGitDir,
        'goal-control',
        'worker-canary-bootstrap-v1',
      ),
      branchFenceFile: path.join(
        path.dirname(options.receiptFile),
        'branch-ref-fence',
      ),
      operationId: receipt.operation_id,
      operationBindingSha256: intentRequestSha256,
      expectedWorktreeKeySha256:
        receipt.worker.filesystem_identity.worktree_key_sha256,
      expectedWorktreeIdentity:
        receipt.worker.filesystem_identity,
      expectedRegistry: exactObservation.registry,
      expectedIndex: receipt.worker.index,
      expectedDetachedOid: receipt.worker.head,
      targetRef,
      expectedClaimFile:
        receipt.head_transaction.claim_file,
      expectedClaimSha256:
        receipt.head_transaction.claim_sha256,
      expectedTransactionProtocol:
        receipt.head_transaction.transaction_protocol,
      expectedCompletionFile:
        receipt.head_transaction.completion_file,
      expectedCompletionSha256:
        receipt.head_transaction.completion_sha256,
    });
  assertControl(
    canonicalJson(receipt.head_transaction)
      === canonicalJson(exactHeadTransaction),
    'CANARY_BOOTSTRAP_RECEIPT_INVALID',
    'worker bootstrap HEAD claim/owner/lock/ref/transaction 非 exact durable projection',
  );

  const exactReceiptUnsigned = {
    schema_version: 1,
    kind: BOOTSTRAP_RECEIPT_KIND,
    identity_plan: receipt.identity_plan,
    identity_plan_sha256: receipt.identity_plan_sha256,
    identity_observation_sha256:
      receipt.identity_observation_sha256,
    intent_sha256: intent.sha256,
    goal_id: options.goalId,
    task_id: options.taskId,
    role: options.role,
    operation_id: options.expectedOperationId,
    challenge: options.expectedChallenge,
    thread: options.workerThread,
    host: options.workerHost,
    worker_branch: receipt.worker_branch,
    controller: options.controller,
    frozen_repository: {
      worktree: options.repositoryRoot,
      common_git_dir: authorizedCommonGitDir,
      head: options.repositoryHead,
    },
    manifest: {
      path: options.manifestPath,
      sha256: options.manifestSha256,
      validated_manifest_sha256:
        options.validatedManifestSha256,
    },
    canary_policy: options.canaryPolicy,
    worker: finalWorker,
    head_transaction: exactHeadTransaction,
    side_effects: {
      source_tree_changed: false,
      index_changed: false,
      remote_write_performed: false,
      goal_store_written: false,
      role_or_capability_created: false,
      resource_or_environment_touched: false,
    },
  };
  assertControl(
    receipt.receipt_binding_sha256 === hashObject(exactReceiptUnsigned)
      && canonicalJson((() => {
        const unsigned = { ...receipt };
        delete unsigned.receipt_binding_sha256;
        return unsigned;
      })()) === canonicalJson(exactReceiptUnsigned),
    'CANARY_BOOTSTRAP_RECEIPT_INVALID',
    'worker bootstrap receipt 不是 exact authorized projection',
  );

  const capture = {
    repositoryRoot: options.repositoryRoot,
    commonGitDir: authorizedCommonGitDir,
    expectedHead: receipt.worker.head,
    workerBranch: receipt.worker.branch,
    manifest: {
      repository: { base_branch: options.baseBranch },
    },
  };
  const live = dependencies.inspectWorkerWorktree(
    receipt.worker.cwd,
    capture,
    { checkLocks: true },
  );
  assertControl(
    canonicalJson(live) === canonicalJson(receipt.worker),
    'CANARY_BOOTSTRAP_RECEIPT_BINDING_MISMATCH',
    'worker bootstrap receipt 与 live worktree identity 漂移',
  );
  dependencies.assertBranchNotOccupiedElsewhere(
    capture,
    receipt.worker.cwd,
    receipt.worker.branch,
  );
  const invocationCwd = canonicalDirectory(
    options.invocationCwd,
    'CANARY_BOOTSTRAP_PROCESS_CWD_MISMATCH',
    'canary-plan process cwd',
  );
  assertControl(
    invocationCwd === receipt.worker.cwd,
    'CANARY_BOOTSTRAP_PROCESS_CWD_MISMATCH',
    'receipt-bound canary-plan 必须从 actual worker process cwd 执行',
  );
  return {
    receipt_file: options.receiptFile,
    receipt_sha256: record.sha256,
    identity_plan_sha256: receipt.identity_plan_sha256,
    identity_observation_sha256:
      receipt.identity_observation_sha256,
    operation_id: receipt.operation_id,
    challenge: receipt.challenge,
    thread: receipt.thread,
    host: receipt.host,
    worktree: receipt.worker.cwd,
    git_dir: receipt.worker.git_dir,
    common_git_dir: receipt.worker.common_git_dir,
    head: receipt.worker.head,
    branch: receipt.worker.branch,
    canary_policy: receipt.canary_policy,
  };
}

module.exports = {
  validateWorkerBootstrapReceipt,
};
