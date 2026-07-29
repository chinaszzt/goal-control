'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const {
  assertControllerProvenanceStable,
  assertSafeGeneratorNodeRuntime,
  controllerProvenanceCapture,
} = require('./canary-controller-attestation');
const {
  BOOTSTRAP_PLAN_KIND,
  CAPTAIN_BOOTSTRAP_PLAN_KIND,
  identityPlanOutput,
} = require('./canary-bootstrap-identity-plan');
const { ControlError, assertControl } = require('./errors');
const {
  ZERO_OID,
  executeLooseRefTransaction,
  inspectLooseRefFence,
} = require('./git-loose-ref-transaction');
const {
  assertPrivateDirectory,
  parsePrivateJson,
  publishPrivateJson,
  recoverPrivateJsonPublication,
} = require('./canary-bootstrap-artifacts');
const {
  validateBootstrapReceipt: validateBootstrapReceiptCore,
} = require('./canary-bootstrap-receipt');
const {
  assertFullSha,
  assertIsolatedTestMode,
  canonicalJson,
  controlRoot,
  hashObject,
  normalizeHash,
  readOnlyGitEnvironment,
  repoRoot,
  safeId,
  sha256,
  trustedGitExecutable,
} = require('./util');
const {
  CAPTAIN_CANARY_BOOTSTRAP_PROTOCOL,
  WORKER_CANARY_BOOTSTRAP_PROTOCOL,
  validateManifest,
} = require('./validation');
const {
  attachWorktreeBootstrapHead,
  captureWorktreeGitdirIdentity,
  verifyWorktreeBootstrapHead,
} = require('./worktree-bootstrap-head-router');

const WORKER_ROLES = Object.freeze(['DEV', 'REVIEW', 'RECEIPT']);
const BOOTSTRAP_OBSERVATION_KIND = 'WORKER_CANARY_IDENTITY_OBSERVATION';
const BOOTSTRAP_INTENT_KIND = 'WORKER_CANARY_PREPARE_INTENT';
const BOOTSTRAP_RECEIPT_KIND = 'WORKER_CANARY_PREPARE_RECEIPT';
const CAPTAIN_BOOTSTRAP_OBSERVATION_KIND =
  'CAPTAIN_CANARY_IDENTITY_OBSERVATION';
const CAPTAIN_BOOTSTRAP_INTENT_KIND =
  'CAPTAIN_CANARY_PREPARE_INTENT';
const CAPTAIN_BOOTSTRAP_RECEIPT_KIND =
  'CAPTAIN_CANARY_PREPARE_RECEIPT';
const WORKER_BOOTSTRAP_PROFILE = Object.freeze({
  roleLabel: 'worker',
  roles: WORKER_ROLES,
  manifestKey: 'worker_canary_bootstrap',
  protocol: WORKER_CANARY_BOOTSTRAP_PROTOCOL,
  planKind: BOOTSTRAP_PLAN_KIND,
  observationKind: BOOTSTRAP_OBSERVATION_KIND,
  intentKind: BOOTSTRAP_INTENT_KIND,
  receiptKind: BOOTSTRAP_RECEIPT_KIND,
  artifactDirectory: 'worker-canary-bootstrap-v1',
  outputPrefix: 'worker',
});
const CAPTAIN_BOOTSTRAP_PROFILE = Object.freeze({
  roleLabel: 'captain',
  roles: Object.freeze(['CAPTAIN']),
  manifestKey: 'captain_canary_bootstrap',
  protocol: CAPTAIN_CANARY_BOOTSTRAP_PROTOCOL,
  planKind: CAPTAIN_BOOTSTRAP_PLAN_KIND,
  observationKind: CAPTAIN_BOOTSTRAP_OBSERVATION_KIND,
  intentKind: CAPTAIN_BOOTSTRAP_INTENT_KIND,
  receiptKind: CAPTAIN_BOOTSTRAP_RECEIPT_KIND,
  artifactDirectory: 'captain-canary-bootstrap-v1',
  outputPrefix: 'captain',
});
const REPO_PATH_RE =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const CHALLENGE_RE = /^[0-9a-f]{64}$/;
const HIDDEN_GIT_OPERATION_SENTINELS = Object.freeze([
  'MERGE_HEAD',
  'CHERRY_PICK_HEAD',
  'REVERT_HEAD',
  'REBASE_HEAD',
  'rebase-apply',
  'rebase-merge',
  'sequencer',
  'BISECT_START',
  'BISECT_LOG',
  'BISECT_TERMS',
  'AUTO_MERGE',
  'MERGE_AUTOSTASH',
]);
const HEAD_TRANSACTION_CODES = Object.freeze({
  artifact: 'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
  claimConflict: 'CANARY_BOOTSTRAP_OPERATION_CONFLICT',
  headConflict: 'CANARY_BOOTSTRAP_HEAD_ATTACH_FAILED',
  identity: 'CANARY_BOOTSTRAP_WORKTREE_DRIFT',
  lockConflict: 'CANARY_BOOTSTRAP_GIT_LOCK_CONFLICT',
  targetRef: 'CANARY_BOOTSTRAP_BRANCH_CONFLICT',
});

function maybeCaptainBootstrapFault(
  capture,
  cwd,
  environmentName,
  code,
) {
  if (capture.bootstrapProfile !== CAPTAIN_BOOTSTRAP_PROFILE) return;
  const mode = process.env[environmentName];
  if (mode === undefined || mode === '') return;
  assertControl(
    ['1', 'throw', 'exit'].includes(mode),
    'INVALID_TEST_FAULT',
    `${environmentName} 只能是 1/throw/exit`,
  );
  assertIsolatedTestMode(cwd);
  if (mode === 'exit') process.exit(86);
  throw new ControlError(code, `injected ${environmentName} fault`);
}

function gitResult(cwd, args, options = {}) {
  try {
    return {
      status: 0,
      stdout: execFileSync(trustedGitExecutable(), args, {
        cwd,
        encoding: options.encoding === null ? null : 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...readOnlyGitEnvironment(),
          GIT_LITERAL_PATHSPECS: '1',
          GIT_NO_REPLACE_OBJECTS: '1',
        },
      }),
      stderr: '',
    };
  } catch (error) {
    return {
      status: Number.isInteger(error && error.status)
        ? error.status
        : -1,
      stdout: options.encoding === null
        ? Buffer.from(error && error.stdout || '')
        : String(error && error.stdout || ''),
      stderr: String(error && (error.stderr || error.message) || ''),
    };
  }
}

function gitText(cwd, args, code, label) {
  const result = gitResult(cwd, args);
  if (result.status !== 0) {
    const detail = result.stderr.trim();
    throw new ControlError(
      code,
      `${label} 失败${detail ? `: ${detail}` : ''}`,
    );
  }
  return result.stdout.trim();
}

function gitBytes(cwd, args, code, label) {
  const result = gitResult(cwd, args, { encoding: null });
  if (result.status !== 0) {
    const detail = result.stderr.trim();
    throw new ControlError(
      code,
      `${label} 失败${detail ? `: ${detail}` : ''}`,
    );
  }
  return result.stdout;
}

function assertCanonicalAbsoluteDirectory(candidate, code, label) {
  assertControl(
    typeof candidate === 'string'
      && path.isAbsolute(candidate)
      && path.normalize(candidate) === candidate,
    code,
    `${label} 必须是 canonical absolute path`,
  );
  let resolved;
  let stat;
  try {
    resolved = fs.realpathSync(candidate);
    stat = fs.lstatSync(candidate);
  } catch (error) {
    throw new ControlError(code, `${label} 不可读取: ${error.message}`);
  }
  assertControl(
    resolved === candidate
      && stat.isDirectory()
      && !stat.isSymbolicLink(),
    code,
    `${label} 必须是 canonical non-symlink directory`,
  );
  return resolved;
}

function assertRepoRelativePath(relative, label) {
  assertControl(
    typeof relative === 'string' && REPO_PATH_RE.test(relative),
    'CANARY_BOOTSTRAP_INPUT_INVALID',
    `${label} 必须是 canonical repo-relative path`,
  );
  return relative;
}

function assertArtifactPathSegment(value, label) {
  safeId(value, label);
  assertControl(
    value !== '.' && value !== '..',
    'CANARY_BOOTSTRAP_INPUT_INVALID',
    `${label} 禁止 dot path segment`,
  );
  return value;
}

function repositoryHead(repositoryRoot) {
  const head = gitText(
    repositoryRoot,
    ['rev-parse', '--verify', 'HEAD^{commit}'],
    'CANARY_BOOTSTRAP_REPOSITORY_INVALID',
    'repository HEAD',
  );
  assertFullSha(head, 'repository HEAD');
  return head;
}

function repositoryCommonGitDir(repositoryRoot) {
  return fs.realpathSync(path.resolve(gitText(
    repositoryRoot,
    ['rev-parse', '--path-format=absolute', '--git-common-dir'],
    'CANARY_BOOTSTRAP_REPOSITORY_INVALID',
    'repository common git dir',
  )));
}

function assertNoReplaceRefs(repositoryRoot) {
  const output = gitText(
    repositoryRoot,
    [
      'for-each-ref',
      '--count=1',
      '--format=%(refname)',
      'refs/replace',
    ],
    'CANARY_BOOTSTRAP_REPOSITORY_INVALID',
    'replace ref inventory',
  );
  assertControl(
    output.length === 0,
    'CANARY_BOOTSTRAP_REPLACE_REFS',
    `worker canary bootstrap 禁止 Git replace refs: ${output}`,
  );
}

function ordinaryFileIdentity(stat) {
  return {
    dev: stat.dev.toString(),
    ino: stat.ino.toString(),
    mode: stat.mode.toString(),
    uid: stat.uid.toString(),
    nlink: stat.nlink.toString(),
    size: stat.size.toString(),
    mtime_ns: stat.mtimeNs.toString(),
    ctime_ns: stat.ctimeNs.toString(),
  };
}

function sameIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function readOrdinaryFileStable(file, code, label, maxBytes = null) {
  let before;
  try {
    before = fs.lstatSync(file, { bigint: true });
  } catch (error) {
    throw new ControlError(code, `${label} 无法读取: ${error.message}`);
  }
  assertControl(
    before.isFile()
      && !before.isSymbolicLink()
      && (
        maxBytes === null
          || (
            before.size > 0n
              && before.size <= BigInt(maxBytes)
          )
      ),
    code,
    `${label} 必须是大小受限的 non-symlink ordinary file`,
  );
  const beforeIdentity = ordinaryFileIdentity(before);
  let descriptor;
  try {
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const openedBefore = fs.fstatSync(descriptor, { bigint: true });
    assertControl(
      openedBefore.isFile()
        && sameIdentity(
          beforeIdentity,
          ordinaryFileIdentity(openedBefore),
        ),
      code,
      `${label} 在 path/open 之间发生 identity 漂移`,
    );
    const bytes = fs.readFileSync(descriptor);
    const openedAfter = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(file, { bigint: true });
    assertControl(
      sameIdentity(
        ordinaryFileIdentity(openedBefore),
        ordinaryFileIdentity(openedAfter),
      )
        && sameIdentity(
          ordinaryFileIdentity(openedAfter),
          ordinaryFileIdentity(pathAfter),
        )
        && BigInt(bytes.length) === openedAfter.size,
      code,
      `${label} 在读取期间发生 identity/content 漂移`,
    );
    return {
      bytes,
      identity: ordinaryFileIdentity(openedAfter),
    };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function committedFileAt(repositoryRoot, head, relative, label) {
  assertRepoRelativePath(relative, label);
  const entry = gitBytes(
    repositoryRoot,
    ['ls-tree', '-z', head, '--', relative],
    'CANARY_BOOTSTRAP_INPUT_NOT_COMMITTED',
    `${label} tree entry`,
  ).toString('utf8');
  const match = /^(100644|100755) blob ([0-9a-f]{40})\t([^\0]+)\0$/.exec(
    entry,
  );
  assertControl(
    match && match[3] === relative,
    'CANARY_BOOTSTRAP_INPUT_NOT_COMMITTED',
    `${label} 必须是 ${head} 中的 ordinary committed blob: ${relative}`,
  );
  const bytes = gitBytes(
    repositoryRoot,
    ['cat-file', 'blob', `${head}:${relative}`],
    'CANARY_BOOTSTRAP_INPUT_NOT_COMMITTED',
    `${label} committed blob`,
  );
  return {
    bytes,
    sha256: `sha256:${sha256(bytes)}`,
  };
}

function committedCurrentFile(repositoryRoot, head, relative, label) {
  const committed = committedFileAt(repositoryRoot, head, relative, label);
  const absolute = path.join(repositoryRoot, relative);
  let resolved;
  try {
    resolved = fs.realpathSync(absolute);
  } catch (error) {
    throw new ControlError(
      'CANARY_BOOTSTRAP_INPUT_NOT_COMMITTED',
      `${label} current path 不存在: ${error.message}`,
    );
  }
  assertControl(
    resolved.startsWith(`${repositoryRoot}${path.sep}`),
    'CANARY_BOOTSTRAP_INPUT_NOT_COMMITTED',
    `${label} current path 逃逸 repository`,
  );
  const current = readOrdinaryFileStable(
    absolute,
    'CANARY_BOOTSTRAP_INPUT_RACE',
    label,
  );
  assertControl(
    `sha256:${sha256(current.bytes)}` === committed.sha256,
    'CANARY_BOOTSTRAP_INPUT_DIRTY',
    `${label} current bytes 与 ${head} committed blob 不一致`,
  );
  return {
    ...committed,
    absolute,
    identity: current.identity,
  };
}

function committedManifestInputs(manifest) {
  const inputs = new Map([[manifest.source_manifest, 'manifest']]);
  for (const [name, protocol] of Object.entries(manifest.protocol || {})) {
    inputs.set(protocol.path, `protocol.${name}`);
  }
  for (const task of manifest.tasks) {
    inputs.set(task.packet.path, `${task.id}.packet`);
    if (task.p1) {
      inputs.set(task.p1.authority.path, `${task.id}.p1.authority`);
    }
  }
  if (manifest.worker_canary_bootstrap) {
    inputs.set(
      manifest.worker_canary_bootstrap.policy.path,
      'worker_canary_bootstrap.policy',
    );
  }
  if (manifest.captain_canary_bootstrap) {
    inputs.set(
      manifest.captain_canary_bootstrap.policy.path,
      'captain_canary_bootstrap.policy',
    );
  }
  return inputs;
}

function bootstrapProfileForRole(role) {
  if (WORKER_ROLES.includes(role)) return WORKER_BOOTSTRAP_PROFILE;
  if (role === 'CAPTAIN') return CAPTAIN_BOOTSTRAP_PROFILE;
  assertControl(
    false,
    'CANARY_BOOTSTRAP_ROLE_INVALID',
    'canary bootstrap 只适用于 CAPTAIN/DEV/REVIEW/RECEIPT',
  );
}

function captainRequiredStartHeadFromGoal(
  loaded,
  selectedTask,
  deriveMechanicalP1Head,
) {
  const state = loaded.snapshot.tasks[selectedTask.id];
  assertControl(
    state,
    'CAPTAIN_BOOTSTRAP_GOAL_STATE_INVALID',
    `Goal state 缺 task ${selectedTask.id}`,
  );
  let source;
  let requiredStartHead;
  if (!selectedTask.p1) {
    requiredStartHead = state.full_head;
    source = {
      kind: 'TASK_FULL_HEAD',
      task_full_head: state.full_head,
    };
  } else if (selectedTask.dependencies.length === 0) {
    requiredStartHead = deriveMechanicalP1Head(loaded, selectedTask);
    source = {
      kind: 'GOAL_INPUT_HEAD',
      goal_input_head: loaded.meta.goal_input_head,
    };
  } else {
    const byId = new Map(
      loaded.manifest.tasks.map((task) => [task.id, task]),
    );
    const dependency = [...selectedTask.dependencies]
      .map((dependencyId) => byId.get(dependencyId))
      .sort(
        (left, right) =>
          left.integration_order - right.integration_order,
      )
      .at(-1);
    const dependencyState = dependency
      && loaded.snapshot.tasks[dependency.id];
    requiredStartHead = deriveMechanicalP1Head(loaded, selectedTask);
    source = {
      kind: 'DEPENDENCY_MAIN_MERGE',
      dependency_task_id: dependency && dependency.id,
      dependency_main_merge_sha:
        dependencyState
        && dependencyState.merge
        && dependencyState.merge.main_merge_sha,
    };
  }
  assertFullSha(
    requiredStartHead,
    `CAPTAIN ${selectedTask.id} required start HEAD`,
  );
  return {
    schema_version: 1,
    goal_id: loaded.manifest.goal_id,
    task_id: selectedTask.id,
    control_epoch: loaded.control.epoch,
    state_revision: state.state_revision,
    task_cycle: state.task_cycle,
    required_start_head: requiredStartHead,
    source,
  };
}

function loadCaptainRequiredStartHeadProof(
  repositoryRoot,
  manifest,
  selectedTask,
) {
  // Lazy loading avoids the goal -> canary-bootstrap module cycle during
  // controller startup; this path runs only after both modules are initialized.
  const {
    loadGoalStateReadOnly,
    mechanicalP1RequiredStartHead,
  } = require('./goal');
  const loaded = loadGoalStateReadOnly(
    repositoryRoot,
    manifest.goal_id,
    (goal) => goal,
  );
  assertControl(
    loaded.manifest.manifest_sha256 === manifest.manifest_sha256,
    'CAPTAIN_BOOTSTRAP_GOAL_STATE_INVALID',
    'Goal state sealed manifest 与 bootstrap manifest 不一致',
  );
  return captainRequiredStartHeadFromGoal(
    loaded,
    selectedTask,
    mechanicalP1RequiredStartHead,
  );
}

function deriveWorkerBranch(goalId, taskId, role, operationId) {
  const taskSlug = taskId
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'task';
  const digest = sha256(canonicalJson({
    schema_version: 1,
    goal_id: goalId,
    task_id: taskId,
    role,
    operation_id: operationId,
  })).slice(0, 16);
  return `codex/canary-${role.toLowerCase()}-${taskSlug}-${digest}`;
}

function captureBootstrapInputs(cwd, options) {
  assertSafeGeneratorNodeRuntime();
  const controller = controllerProvenanceCapture();
  const repositoryRoot = assertCanonicalAbsoluteDirectory(
    fs.realpathSync(repoRoot(cwd)),
    'CANARY_BOOTSTRAP_REPOSITORY_INVALID',
    'frozen Goal worktree',
  );
  assertNoReplaceRefs(repositoryRoot);
  const head = repositoryHead(repositoryRoot);
  const commonGitDir = repositoryCommonGitDir(repositoryRoot);
  const manifestRelative = assertRepoRelativePath(
    options.manifestFile,
    '--manifest',
  );
  const manifestCapture = committedCurrentFile(
    repositoryRoot,
    head,
    manifestRelative,
    'manifest',
  );
  let sourceManifest;
  try {
    sourceManifest = JSON.parse(manifestCapture.bytes.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'CANARY_BOOTSTRAP_INPUT_INVALID',
      `manifest 不是合法 JSON: ${error.message}`,
    );
  }
  const manifest = validateManifest(
    sourceManifest,
    manifestCapture.absolute,
    repositoryRoot,
  );
  assertControl(
    manifest.source_manifest === manifestRelative,
    'CANARY_BOOTSTRAP_INPUT_INVALID',
    'validated manifest path 与 --manifest 不一致',
  );
  const bootstrapProfile = bootstrapProfileForRole(options.role);
  const selectedTask = manifest.tasks.find(
    (task) => task.id === options.taskId,
  );
  assertControl(
    selectedTask,
    'CANARY_BOOTSTRAP_TASK_INVALID',
    `manifest 中不存在 task: ${options.taskId}`,
  );
  assertControl(
    manifest[bootstrapProfile.manifestKey]
      && manifest[bootstrapProfile.manifestKey].protocol
        === bootstrapProfile.protocol,
    bootstrapProfile === WORKER_BOOTSTRAP_PROFILE
      ? 'WORKER_CANARY_BOOTSTRAP_PROTOCOL_UNSUPPORTED'
      : 'CAPTAIN_CANARY_BOOTSTRAP_PROTOCOL_UNSUPPORTED',
    `manifest 未显式启用 ${bootstrapProfile.protocol}`,
  );
  const expectedHead = assertFullSha(
    options.expectedHead,
    '--expected-head',
  );
  const commitCheck = gitResult(
    repositoryRoot,
    ['cat-file', '-e', `${expectedHead}^{commit}`],
  );
  assertControl(
    commitCheck.status === 0,
    'CANARY_BOOTSTRAP_HEAD_INVALID',
    `expected worker HEAD 不存在: ${expectedHead}`,
  );
  let requiredStartHeadProof = null;
  if (bootstrapProfile === CAPTAIN_BOOTSTRAP_PROFILE) {
    requiredStartHeadProof = loadCaptainRequiredStartHeadProof(
      repositoryRoot,
      manifest,
      selectedTask,
    );
    assertControl(
      expectedHead === requiredStartHeadProof.required_start_head,
      'CAPTAIN_BOOTSTRAP_REQUIRED_HEAD_MISMATCH',
      `CAPTAIN bootstrap expected HEAD ${expectedHead} 与 Goal-state required start HEAD ${requiredStartHeadProof.required_start_head} 不一致`,
    );
  }
  safeId(options.operationId, '--operation-id');
  assertControl(
    CHALLENGE_RE.test(options.challenge),
    'CANARY_BOOTSTRAP_CHALLENGE_INVALID',
    '--challenge 必须是 64 位小写 hex 一次性 challenge',
  );

  const captures = new Map();
  for (const [relative, label] of committedManifestInputs(manifest)) {
    const current = committedCurrentFile(
      repositoryRoot,
      head,
      relative,
      label,
    );
    if (bootstrapProfile === WORKER_BOOTSTRAP_PROFILE) {
      const expected = committedFileAt(
        repositoryRoot,
        expectedHead,
        relative,
        `${label} at expected worker HEAD`,
      );
      assertControl(
        expected.sha256 === current.sha256,
        'CANARY_BOOTSTRAP_HEAD_INPUT_MISMATCH',
        `${label} 在 frozen HEAD 与 expected worker HEAD 的 bytes 不一致`,
      );
    }
    captures.set(relative, current);
  }
  assertControl(
    captures.get(manifestRelative).sha256 === manifestCapture.sha256,
    'CANARY_BOOTSTRAP_INPUT_RACE',
    'manifest 在 bootstrap plan 计算期间变化',
  );

  const policyPath = assertRepoRelativePath(
    options.canaryPolicy,
    '--canary-policy',
  );
  const policySha256 = normalizeHash(
    options.canaryPolicySha256,
    '--canary-policy-sha256',
  );
  assertControl(
    policyPath === manifest[bootstrapProfile.manifestKey].policy.path
      && policySha256
        === manifest[bootstrapProfile.manifestKey].policy.sha256,
    'CANARY_BOOTSTRAP_POLICY_MISMATCH',
    'canary policy path/hash 与 manifest worker bootstrap opt-in 不一致',
  );
  const policy = committedCurrentFile(
    repositoryRoot,
    head,
    policyPath,
    'canary policy',
  );
  const expectedPolicy = bootstrapProfile === WORKER_BOOTSTRAP_PROFILE
    ? committedFileAt(
      repositoryRoot,
      expectedHead,
      policyPath,
      'canary policy at expected worker HEAD',
    )
    : null;
  assertControl(
    policy.sha256 === policySha256
      && (
        expectedPolicy === null
          || expectedPolicy.sha256 === policySha256
      ),
    'CANARY_BOOTSTRAP_POLICY_MISMATCH',
    'canary policy path/hash 未同时绑定 frozen 与 expected worker HEAD',
  );
  assertControl(
    repositoryHead(repositoryRoot) === head,
    'CANARY_BOOTSTRAP_INPUT_RACE',
    'frozen Goal HEAD 在 bootstrap plan 计算期间变化',
  );
  assertNoReplaceRefs(repositoryRoot);

  const workerBranch = deriveWorkerBranch(
    manifest.goal_id,
    selectedTask.id,
    options.role,
    options.operationId,
  );
  const branchCheck = gitResult(
    repositoryRoot,
    ['check-ref-format', `refs/heads/${workerBranch}`],
  );
  assertControl(
    branchCheck.status === 0
      && workerBranch !== manifest.repository.base_branch,
    'CANARY_BOOTSTRAP_BRANCH_INVALID',
    'derived worker branch 非法或命中 base branch',
  );
  return {
    controller,
    repositoryRoot,
    commonGitDir,
    head,
    manifest,
    manifestCapture,
    selectedTask,
    expectedHead,
    policyPath,
    policySha256,
    workerBranch,
    bootstrapProfile,
    requiredStartHeadProof,
  };
}

function canaryBootstrapPlan(cwd, options) {
  const capture = captureBootstrapInputs(cwd, options);
  const output = identityPlanOutput(capture, options);
  assertControllerProvenanceStable(capture.controller);
  return output;
}

function parseWorktreeInventory(repositoryRoot) {
  const bytes = gitBytes(
    repositoryRoot,
    ['worktree', 'list', '--porcelain', '-z'],
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'git worktree inventory',
  );
  assertControl(
    bytes.length > 0 && bytes[bytes.length - 1] === 0,
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'git worktree inventory 缺 NUL terminator',
  );
  const tokens = bytes
    .subarray(0, bytes.length - 1)
    .toString('utf8')
    .split('\0');
  const records = [];
  let current = null;
  for (const token of tokens) {
    if (token === '') {
      if (current) records.push(current);
      current = null;
      continue;
    }
    const separator = token.indexOf(' ');
    const key = separator === -1 ? token : token.slice(0, separator);
    const value = separator === -1 ? true : token.slice(separator + 1);
    if (key === 'worktree') {
      assertControl(
        current === null,
        'CANARY_BOOTSTRAP_WORKTREE_INVALID',
        'worktree inventory record 未闭合',
      );
      current = { worktree: value };
    } else {
      assertControl(
        current !== null && current[key] === undefined,
        'CANARY_BOOTSTRAP_WORKTREE_INVALID',
        'worktree inventory 字段顺序或重复非法',
      );
      current[key] = value;
    }
  }
  if (current) records.push(current);
  return records;
}

function worktreeIndexIdentity(worktree, gitDir) {
  const indexPath = path.resolve(gitText(
    worktree,
    ['rev-parse', '--git-path', 'index'],
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker index path',
  ));
  assertControl(
    indexPath.startsWith(`${gitDir}${path.sep}`),
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker index 不在 worktree-specific git dir',
  );
  const capture = readOrdinaryFileStable(
    indexPath,
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker index',
  );
  return {
    path: indexPath,
    sha256: `sha256:${sha256(capture.bytes)}`,
    size: capture.bytes.length,
    identity: capture.identity,
  };
}

function pathEntryPresent(candidate, label) {
  try {
    fs.lstatSync(candidate);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw new ControlError(
      'CANARY_BOOTSTRAP_GIT_LOCK_CONFLICT',
      `${label} 无法安全 lstat: ${error.message}`,
    );
  }
}

function assertNoHiddenGitOperation(gitDir, commonGitDir) {
  const present = HIDDEN_GIT_OPERATION_SENTINELS.filter((relative) => (
    pathEntryPresent(
      path.join(gitDir, relative),
      `hidden Git operation ${relative}`,
    )
      || (
        commonGitDir !== gitDir
          && pathEntryPresent(
            path.join(commonGitDir, relative),
            `hidden common Git operation ${relative}`,
          )
      )
  ));
  assertControl(
    present.length === 0,
    'CANARY_BOOTSTRAP_GIT_OPERATION_ACTIVE',
    `worker worktree 存在 hidden Git operation: ${present.join(', ')}`,
  );
}

function assertNoForeignLocks(gitDir, commonGitDir, workerBranch) {
  const branchRef = path.join(
    commonGitDir,
    'refs',
    'heads',
    ...workerBranch.split('/'),
  );
  const locks = [
    path.join(gitDir, 'index.lock'),
    path.join(gitDir, 'HEAD.lock'),
    path.join(commonGitDir, 'packed-refs.lock'),
    `${branchRef}.lock`,
  ].filter((candidate) => pathEntryPresent(candidate, 'Git lock'));
  assertControl(
    locks.length === 0,
    'CANARY_BOOTSTRAP_GIT_LOCK_CONFLICT',
    `worker bootstrap 发现 foreign Git lock: ${locks.join(', ')}`,
  );
}

function assertNoWorktreeMutationLocks(
  gitDir,
  commonGitDir,
  options = {},
) {
  const locks = [
    path.join(gitDir, 'index.lock'),
    ...(
      options.includePacked === false
        ? []
        : [path.join(commonGitDir, 'packed-refs.lock')]
    ),
    ...(
      options.includeHead === false
        ? []
        : [path.join(gitDir, 'HEAD.lock')]
    ),
  ].filter((candidate) => pathEntryPresent(candidate, 'Git lock'));
  assertControl(
    locks.length === 0,
    'CANARY_BOOTSTRAP_GIT_LOCK_CONFLICT',
    `worker bootstrap 发现 foreign worktree Git lock: ${locks.join(', ')}`,
  );
}

function currentBranch(worktree) {
  const result = gitResult(
    worktree,
    ['symbolic-ref', '--quiet', '--short', 'HEAD'],
  );
  if (result.status === 1) return null;
  if (result.status !== 0) {
    throw new ControlError(
      'CANARY_BOOTSTRAP_WORKTREE_INVALID',
      `worker branch 无法解析: ${result.stderr.trim()}`,
    );
  }
  return result.stdout.trim();
}

function inspectWorkerWorktree(workerWorktree, capture, options = {}) {
  const worktree = assertCanonicalAbsoluteDirectory(
    workerWorktree,
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker worktree',
  );
  const filesystemIdentity = captureWorktreeGitdirIdentity(
    worktree,
    HEAD_TRANSACTION_CODES,
  );
  const gitDir = filesystemIdentity.git_dir;
  const commonGitDir = filesystemIdentity.common_git_dir;
  assertControl(
    commonGitDir === capture.commonGitDir,
    'CANARY_BOOTSTRAP_FOREIGN_REPOSITORY',
    'worker worktree 与 frozen Goal 不属于同一 Git common dir',
  );
  assertControl(
    gitDir !== commonGitDir
      && gitDir.startsWith(`${commonGitDir}${path.sep}worktrees${path.sep}`),
    'CANARY_BOOTSTRAP_PRIMARY_WORKTREE_FORBIDDEN',
    'worker 必须是拥有专属 gitdir 的 linked worktree，禁止 primary/main worktree',
  );
  assertNoReplaceRefs(worktree);
  assertNoHiddenGitOperation(gitDir, commonGitDir);
  const head = repositoryHead(worktree);
  assertControl(
    head === capture.expectedHead,
    'CANARY_BOOTSTRAP_HEAD_MISMATCH',
    `worker HEAD 必须精确等于 expected HEAD ${capture.expectedHead}`,
  );
  const branch = currentBranch(worktree);
  assertControl(
    branch === null || branch === capture.workerBranch,
    'CANARY_BOOTSTRAP_BRANCH_MISMATCH',
    'worker 必须是 detached HEAD 或 exact deterministic worker branch',
  );
  assertControl(
    branch !== capture.manifest.repository.base_branch,
    'CANARY_BOOTSTRAP_BASE_BRANCH_FORBIDDEN',
    'worker 禁止绑定 repository base branch',
  );
  const statusBytes = gitBytes(
    worktree,
    ['status', '--porcelain=v2', '-z', '--untracked-files=all'],
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker status',
  );
  assertControl(
    statusBytes.length === 0,
    'CANARY_BOOTSTRAP_DIRTY_WORKTREE',
    'worker worktree 必须 clean（tracked/staged/untracked 均为空）',
  );
  const index = worktreeIndexIdentity(worktree, gitDir);
  const tree = gitText(
    worktree,
    ['rev-parse', 'HEAD^{tree}'],
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker HEAD tree',
  );
  assertFullSha(tree, 'worker HEAD tree');
  const inventory = parseWorktreeInventory(capture.repositoryRoot);
  const matches = inventory.filter((record) => {
    try {
      return fs.realpathSync(record.worktree) === worktree;
    } catch {
      return false;
    }
  });
  const expectedRegistryKeys = branch === null
    ? ['HEAD', 'detached', 'worktree']
    : ['HEAD', 'branch', 'worktree'];
  assertControl(
    matches.length === 1
      && canonicalJson(Object.keys(matches[0]).sort())
        === canonicalJson(expectedRegistryKeys.sort())
      && matches[0].HEAD === head
      && (
        branch === null
          ? matches[0].detached === true
          : matches[0].branch === `refs/heads/${branch}`
      ),
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker worktree registry identity/HEAD/branch 不唯一或不匹配',
  );
  const finalFilesystemIdentity = captureWorktreeGitdirIdentity(
    worktree,
    HEAD_TRANSACTION_CODES,
  );
  assertControl(
    canonicalJson(finalFilesystemIdentity)
      === canonicalJson(filesystemIdentity),
    'CANARY_BOOTSTRAP_WORKTREE_DRIFT',
    'worker worktree/gitdir identity 在 inspect 期间漂移',
  );
  if (options.checkLocks === true) {
    assertNoForeignLocks(gitDir, commonGitDir, capture.workerBranch);
  }
  return {
    cwd: worktree,
    git_dir: gitDir,
    common_git_dir: commonGitDir,
    head,
    branch,
    clean: true,
    tree,
    index,
    filesystem_identity: filesystemIdentity,
    registry: {
      worktree,
      head,
      branch,
      detached: branch === null,
    },
    status_sha256: `sha256:${sha256(statusBytes)}`,
  };
}

function assertIdentityPlanHash(planOutput, expected) {
  const normalized = normalizeHash(
    expected,
    '--expected-identity-plan-sha256',
  );
  assertControl(
    planOutput.identity_plan_sha256 === normalized,
    'CANARY_BOOTSTRAP_PLAN_MISMATCH',
    'recomputed identity plan 与 expected hash 不匹配',
  );
}

function inspectWorkerIdentity(cwd, capture, options, planOutput) {
  safeId(options.workerThread, '--worker-thread');
  safeId(options.workerHost, '--worker-host');
  assertControl(
    options.expectedIdentityPlanSha256
      || options.expectedIdentityBindingSha256,
    'CANARY_BOOTSTRAP_PLAN_MISMATCH',
    'inspect 必须绑定 identity plan hash 或 identity binding hash',
  );
  if (options.expectedIdentityPlanSha256) {
    assertIdentityPlanHash(planOutput, options.expectedIdentityPlanSha256);
  }
  if (options.expectedIdentityBindingSha256) {
    assertControl(
      planOutput.identity_plan.identity_binding_sha256
        === normalizeHash(
          options.expectedIdentityBindingSha256,
          '--expected-identity-binding-sha256',
        ),
      'CANARY_BOOTSTRAP_PLAN_MISMATCH',
      'identity binding hash 不匹配',
    );
  }
  const identity = inspectWorkerWorktree(cwd, capture);
  const observation = {
    schema_version: 1,
    kind: capture.bootstrapProfile.observationKind,
    identity_plan_sha256: planOutput.identity_plan_sha256,
    goal_id: capture.manifest.goal_id,
    task_id: capture.selectedTask.id,
    role: options.role,
    operation_id: options.operationId,
    challenge: options.challenge,
    thread: options.workerThread,
    host: options.workerHost,
    ...identity,
  };
  return {
    identity_observation: observation,
    identity_observation_sha256: hashObject(observation),
  };
}

function canaryBootstrapInspect(cwd, options) {
  const goalWorktree = assertCanonicalAbsoluteDirectory(
    options.goalWorktree,
    'CANARY_BOOTSTRAP_REPOSITORY_INVALID',
    '--goal-worktree',
  );
  const workerWorktree = assertCanonicalAbsoluteDirectory(
    cwd,
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker process cwd',
  );
  assertControl(
    workerWorktree !== goalWorktree,
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker worktree 必须独立于 frozen Goal worktree',
  );
  const capture = captureBootstrapInputs(goalWorktree, options);
  const planOutput = identityPlanOutput(capture, options);
  const output = inspectWorkerIdentity(
    workerWorktree,
    capture,
    options,
    planOutput,
  );
  assertControllerProvenanceStable(capture.controller);
  return output;
}

function bootstrapArtifactPaths(capture, operationId) {
  assertArtifactPathSegment(capture.manifest.goal_id, 'goal_id');
  assertArtifactPathSegment(capture.selectedTask.id, 'task_id');
  safeId(operationId, 'operation_id');
  const root = path.join(
    capture.bootstrapProfile === CAPTAIN_BOOTSTRAP_PROFILE
      ? capture.commonGitDir
      : path.dirname(controlRoot(capture.repositoryRoot)),
    ...(capture.bootstrapProfile === CAPTAIN_BOOTSTRAP_PROFILE
      ? ['goal-control']
      : []),
    capture.bootstrapProfile.artifactDirectory,
  );
  const operationHash = sha256(operationId);
  const operationDirectory = path.join(
    root,
    'goals',
    capture.manifest.goal_id,
    'tasks',
    capture.selectedTask.id,
    operationHash,
  );
  return {
    root,
    operationDirectory,
    intent: path.join(operationDirectory, 'intent.json'),
    receipt: path.join(operationDirectory, 'receipt.json'),
    refFence: path.join(operationDirectory, 'branch-ref-fence'),
    headFence: path.join(operationDirectory, 'head-transaction.fence'),
    headCompletion: path.join(
      operationDirectory,
      'head-transaction-completion.json',
    ),
  };
}

function parseRef(worktree, ref) {
  const output = gitText(
    worktree,
    ['for-each-ref', '--format=%(refname)%00%(objectname)', ref],
    'CANARY_BOOTSTRAP_BRANCH_INVALID',
    'worker branch ref inventory',
  );
  if (output === '') return null;
  const separator = output.indexOf('\0');
  assertControl(
    separator > 0
      && output.slice(0, separator) === ref
      && output.indexOf('\0', separator + 1) === -1,
    'CANARY_BOOTSTRAP_BRANCH_INVALID',
    'worker branch ref inventory 非 exact single ref',
  );
  const oid = output.slice(separator + 1);
  assertFullSha(oid, 'worker branch ref');
  return oid;
}

function assertBranchNotOccupiedElsewhere(
  capture,
  worktree,
  branch,
) {
  const ref = `refs/heads/${branch}`;
  const occupied = parseWorktreeInventory(capture.repositoryRoot)
    .filter((record) => record.branch === ref)
    .map((record) => {
      try {
        return fs.realpathSync(record.worktree);
      } catch {
        return record.worktree;
      }
    })
    .filter((candidate) => candidate !== worktree);
  assertControl(
    occupied.length === 0,
    'CANARY_BOOTSTRAP_BRANCH_OCCUPIED',
    `deterministic worker branch 已被其它 worktree 占用: ${occupied.join(', ')}`,
  );
}

function attachWorkerBranch(capture, intent, paths) {
  let current = inspectWorkerWorktree(
    intent.worker_observation.cwd,
    capture,
    { checkLocks: false },
  );
  assertNoWorktreeMutationLocks(
    current.git_dir,
    current.common_git_dir,
    { includeHead: false, includePacked: false },
  );
  assertControl(
    current.tree === intent.worker_observation.tree
      && canonicalJson(current.index)
        === canonicalJson(intent.worker_observation.index)
      && canonicalJson(current.filesystem_identity)
        === canonicalJson(
          intent.worker_observation.filesystem_identity,
        )
      && current.status_sha256
        === intent.worker_observation.status_sha256,
    'CANARY_BOOTSTRAP_WORKTREE_DRIFT',
    'worker tree/index/status 在 durable intent 后漂移',
  );
  assertBranchNotOccupiedElsewhere(
    capture,
    current.cwd,
    capture.workerBranch,
  );
  const ref = `refs/heads/${capture.workerBranch}`;
  let refOid = parseRef(current.cwd, ref);
  if (current.branch === null) {
    assertControl(
      refOid === null || refOid === capture.expectedHead,
      'CANARY_BOOTSTRAP_BRANCH_CONFLICT',
      'deterministic worker branch 指向 unexpected commit',
    );
    const branchTransactionCodes = {
      refConflict: 'CANARY_BOOTSTRAP_BRANCH_CONFLICT',
      lockConflict: 'CANARY_BOOTSTRAP_GIT_LOCK_CONFLICT',
      fenceConflict: 'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
      invalidRef: 'CANARY_BOOTSTRAP_BRANCH_INVALID',
    };
    const fence = inspectLooseRefFence({
      fenceFile: paths.refFence,
      expectedNew: capture.expectedHead,
      codes: branchTransactionCodes,
      label: `worker canary branch ${ref}`,
    });
    executeLooseRefTransaction({
      cwd: current.cwd,
      commonGitDir: current.common_git_dir,
      ref,
      expectedOld: ZERO_OID,
      expectedNew: capture.expectedHead,
      fenceFile: paths.refFence,
      fenceInstalledAtEntry: Boolean(fence),
      reflogPolicy: 'absent',
      codes: branchTransactionCodes,
      label: `worker canary branch ${ref}`,
    });
    refOid = parseRef(current.cwd, ref);
    assertControl(
      refOid === capture.expectedHead,
      'CANARY_BOOTSTRAP_BRANCH_CONFLICT',
      'deterministic worker branch CAS 未收敛到 expected HEAD',
    );
    maybeCaptainBootstrapFault(
      capture,
      current.cwd,
      'GOAL_CONTROL_TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_REF',
      'TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_REF',
    );
  } else {
    assertControl(
      current.branch === capture.workerBranch
        && refOid === capture.expectedHead,
      'CANARY_BOOTSTRAP_BRANCH_CONFLICT',
      'prepared worker branch/ref 不匹配',
    );
  }
  const headTransaction = attachWorktreeBootstrapHead({
    cwd: current.cwd,
    artifactRoot: paths.root,
    branchFenceFile: paths.refFence,
    headFenceFile: paths.headFence,
    completionFile: paths.headCompletion,
    operationId: intent.operation_id,
    operationBindingSha256: intent.request_sha256,
    expectedWorktreeKeySha256:
      intent.worker_observation.filesystem_identity
        .worktree_key_sha256,
    expectedRegistry: intent.worker_observation.registry,
    expectedIndex: intent.worker_observation.index,
    expectedDetachedOid: capture.expectedHead,
    targetRef: ref,
    codes: HEAD_TRANSACTION_CODES,
  });
  maybeCaptainBootstrapFault(
    capture,
    current.cwd,
    'GOAL_CONTROL_TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_HEAD',
    'TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_HEAD',
  );
  current = inspectWorkerWorktree(
    intent.worker_observation.cwd,
    capture,
    { checkLocks: false },
  );
  assertNoWorktreeMutationLocks(
    current.git_dir,
    current.common_git_dir,
  );
  assertControl(
    current.branch === capture.workerBranch
      && current.head === capture.expectedHead
      && current.tree === intent.worker_observation.tree
      && canonicalJson(current.index)
        === canonicalJson(intent.worker_observation.index)
      && canonicalJson(current.filesystem_identity)
        === canonicalJson(
          intent.worker_observation.filesystem_identity,
        )
      && current.status_sha256
        === intent.worker_observation.status_sha256,
    'CANARY_BOOTSTRAP_WORKTREE_DRIFT',
    'branch attach 改变了 HEAD commit/tree/index/status 或未绑定 branch',
  );
  assertBranchNotOccupiedElsewhere(
    capture,
    current.cwd,
    capture.workerBranch,
  );
  return {
    worker: current,
    head_transaction: headTransaction,
  };
}

function assertIntentMatchesRequest(intent, request) {
  const {
    request_sha256: requestSha256,
    ...unsigned
  } = intent || {};
  assertControl(
    intent
      && intent.schema_version === 1
      && intent.kind === request.kind
      && requestSha256 === hashObject(unsigned)
      && requestSha256 === hashObject(request),
    'CANARY_BOOTSTRAP_OPERATION_CONFLICT',
    'bootstrap intent schema/request binding 非法',
  );
  const expected = {
    ...request,
    request_sha256: hashObject(request),
  };
  assertControl(
    canonicalJson(intent) === canonicalJson(expected),
    'CANARY_BOOTSTRAP_OPERATION_CONFLICT',
    '同一 bootstrap operation 已绑定不同 request/challenge',
  );
}

function durableHeadTransactionEvidence(transaction) {
  const evidence = { ...transaction };
  delete evidence.claim_created;
  delete evidence.idempotent;
  return evidence;
}

function canaryBootstrapPrepare(cwd, options) {
  safeId(options.workerThread, '--worker-thread');
  safeId(options.workerHost, '--worker-host');
  const workerWorktree = assertCanonicalAbsoluteDirectory(
    options.workerWorktree,
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    '--worker-worktree',
  );
  const capture = captureBootstrapInputs(cwd, options);
  assertControl(
    workerWorktree !== capture.repositoryRoot,
    'CANARY_BOOTSTRAP_WORKTREE_INVALID',
    'worker worktree 必须独立于 frozen Goal worktree',
  );
  const planOutput = identityPlanOutput(capture, options);
  assertIdentityPlanHash(planOutput, options.expectedIdentityPlanSha256);
  const paths = bootstrapArtifactPaths(capture, options.operationId);
  const expectedObservationSha256 = normalizeHash(
    options.expectedObservationSha256,
    '--expected-observation-sha256',
  );
  let captainFreshObservation = null;
  if (
    capture.bootstrapProfile === CAPTAIN_BOOTSTRAP_PROFILE
      && !pathEntryPresent(paths.intent, 'captain bootstrap intent')
  ) {
    const current = inspectWorkerIdentity(
      workerWorktree,
      capture,
      {
        ...options,
        expectedIdentityPlanSha256:
          planOutput.identity_plan_sha256,
        workerThread: options.workerThread,
        workerHost: options.workerHost,
      },
      planOutput,
    );
    assertControl(
      current.identity_observation_sha256
        === expectedObservationSha256,
      'CANARY_BOOTSTRAP_OBSERVATION_MISMATCH',
      'captain identity observation 与 expected hash 不匹配',
    );
    captainFreshObservation = current.identity_observation;
    const initialRef = parseRef(
      workerWorktree,
      `refs/heads/${capture.workerBranch}`,
    );
    assertBranchNotOccupiedElsewhere(
      capture,
      captainFreshObservation.cwd,
      capture.workerBranch,
    );
    assertControl(
      captainFreshObservation.branch === null
        && initialRef === null,
      'CANARY_BOOTSTRAP_BRANCH_CONFLICT',
      '首次 CAPTAIN prepare 只接受 detached HEAD + absent deterministic ref',
    );
    assertNoForeignLocks(
      captainFreshObservation.git_dir,
      captainFreshObservation.common_git_dir,
      capture.workerBranch,
    );
  }
  assertPrivateDirectory(
    paths.root,
    `${capture.bootstrapProfile.roleLabel} canary bootstrap root`,
    true,
  );
  assertPrivateDirectory(
    paths.operationDirectory,
    `${capture.bootstrapProfile.roleLabel} canary bootstrap operation`,
    true,
  );
  recoverPrivateJsonPublication(
    paths.intent,
    'worker canary bootstrap intent',
    'CANARY_BOOTSTRAP_OPERATION_CONFLICT',
  );
  let existingIntent = null;
  if (pathEntryPresent(paths.intent, 'worker bootstrap intent')) {
    existingIntent = parsePrivateJson(
      paths.intent,
      'worker canary bootstrap intent',
    );
  }

  let observation;
  if (existingIntent) {
    assertControl(
      existingIntent.value
        && existingIntent.value.worker_observation
        && existingIntent.value.worker_observation.cwd
          === workerWorktree,
      'CANARY_BOOTSTRAP_OPERATION_CONFLICT',
      'exact retry 的 --worker-worktree 与 durable intent 不一致',
    );
    observation = existingIntent.value.worker_observation;
  } else {
    if (captainFreshObservation) {
      observation = captainFreshObservation;
    } else {
      const current = inspectWorkerIdentity(
        workerWorktree,
        capture,
        {
          ...options,
          expectedIdentityPlanSha256:
            planOutput.identity_plan_sha256,
          workerThread: options.workerThread,
          workerHost: options.workerHost,
        },
        planOutput,
      );
      assertControl(
        current.identity_observation_sha256
          === expectedObservationSha256,
        'CANARY_BOOTSTRAP_OBSERVATION_MISMATCH',
        'worker identity observation 与 expected hash 不匹配',
      );
      observation = current.identity_observation;
    }
  }
  const request = {
    schema_version: 1,
    kind: capture.bootstrapProfile.intentKind,
    identity_plan_sha256: planOutput.identity_plan_sha256,
    identity_observation_sha256: expectedObservationSha256,
    goal_id: capture.manifest.goal_id,
    task_id: capture.selectedTask.id,
    role: options.role,
    operation_id: options.operationId,
    challenge: options.challenge,
    thread: options.workerThread,
    host: options.workerHost,
    worker_branch: capture.workerBranch,
    worker_observation: observation,
    controller: capture.controller.provenance,
    canary_policy: {
      path: capture.policyPath,
      sha256: capture.policySha256,
    },
  };
  const intent = {
    ...request,
    request_sha256: hashObject(request),
  };
  if (existingIntent) {
    assertIntentMatchesRequest(existingIntent.value, request);
  } else {
    const initialBranch = observation.branch;
    const ref = `refs/heads/${capture.workerBranch}`;
    const refOid = parseRef(workerWorktree, ref);
    assertBranchNotOccupiedElsewhere(
      capture,
      observation.cwd,
      capture.workerBranch,
    );
    assertControl(
      initialBranch === null
        && refOid === null,
      'CANARY_BOOTSTRAP_BRANCH_CONFLICT',
      '首次 prepare 只接受 detached HEAD + absent deterministic ref',
    );
    assertNoForeignLocks(
      observation.git_dir,
      observation.common_git_dir,
      capture.workerBranch,
    );
    publishPrivateJson(
      paths.intent,
      intent,
      'worker canary bootstrap intent',
      'CANARY_BOOTSTRAP_OPERATION_CONFLICT',
    );
    maybeCaptainBootstrapFault(
      capture,
      workerWorktree,
      'GOAL_CONTROL_TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_INTENT',
      'TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_INTENT',
    );
  }

  const intentRecord = parsePrivateJson(
    paths.intent,
    'worker canary bootstrap intent',
  );
  assertIntentMatchesRequest(intentRecord.value, request);
  const finalWorker = attachWorkerBranch(
    capture,
    intentRecord.value,
    paths,
  );
  const receiptUnsigned = {
    schema_version: 1,
    kind: capture.bootstrapProfile.receiptKind,
    identity_plan: planOutput.identity_plan,
    identity_plan_sha256: planOutput.identity_plan_sha256,
    identity_observation_sha256: expectedObservationSha256,
    intent_sha256: intentRecord.sha256,
    goal_id: capture.manifest.goal_id,
    task_id: capture.selectedTask.id,
    role: options.role,
    operation_id: options.operationId,
    challenge: options.challenge,
    thread: options.workerThread,
    host: options.workerHost,
    worker_branch: capture.workerBranch,
    controller: capture.controller.provenance,
    frozen_repository: {
      worktree: capture.repositoryRoot,
      common_git_dir: capture.commonGitDir,
      head: capture.head,
    },
    manifest: {
      path: capture.manifest.source_manifest,
      sha256: capture.manifestCapture.sha256,
      validated_manifest_sha256: capture.manifest.manifest_sha256,
    },
    canary_policy: {
      path: capture.policyPath,
      sha256: capture.policySha256,
    },
    worker: finalWorker.worker,
    head_transaction: durableHeadTransactionEvidence(
      finalWorker.head_transaction,
    ),
    side_effects: {
      source_tree_changed: false,
      index_changed: false,
      remote_write_performed: false,
      goal_store_written: false,
      role_or_capability_created: false,
      resource_or_environment_touched: false,
    },
  };
  const receipt = {
    ...receiptUnsigned,
    receipt_binding_sha256: hashObject(receiptUnsigned),
  };
  const publication = publishPrivateJson(
    paths.receipt,
    receipt,
    'worker canary bootstrap receipt',
    'CANARY_BOOTSTRAP_RECEIPT_CONFLICT',
  );
  maybeCaptainBootstrapFault(
    capture,
    workerWorktree,
    'GOAL_CONTROL_TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_RECEIPT',
    'TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_RECEIPT',
  );
  const sealed = parsePrivateJson(
    paths.receipt,
    'worker canary bootstrap receipt',
  );
  assertControl(
    sealed.value.receipt_binding_sha256
      === hashObject(receiptUnsigned),
    'CANARY_BOOTSTRAP_RECEIPT_CONFLICT',
    'worker bootstrap receipt binding hash 不匹配',
  );
  assertControllerProvenanceStable(capture.controller);
  return {
    [`${capture.bootstrapProfile.outputPrefix}_bootstrap_receipt_file`]:
      paths.receipt,
    [`${capture.bootstrapProfile.outputPrefix}_bootstrap_receipt_sha256`]:
      sealed.sha256,
    identity_plan_sha256: planOutput.identity_plan_sha256,
    identity_observation_sha256: expectedObservationSha256,
    intent_sha256: intentRecord.sha256,
    worker_branch: capture.workerBranch,
    idempotent: !publication.created,
  };
}

function validateWorkerBootstrapReceipt(options) {
  assertControl(
    WORKER_ROLES.includes(options.role),
    'CANARY_BOOTSTRAP_ROLE_INVALID',
    'worker bootstrap receipt 只适用于 worker role',
  );
  return validateBootstrapReceiptCore(options, {
    assertBranchNotOccupiedElsewhere,
    inspectWorkerWorktree,
    repositoryCommonGitDir,
    verifyWorktreeBootstrapHead,
  }, WORKER_BOOTSTRAP_PROFILE);
}

function validateCaptainBootstrapReceipt(options) {
  assertControl(
    options.role === 'CAPTAIN',
    'CANARY_BOOTSTRAP_ROLE_INVALID',
    'captain bootstrap receipt 只适用于 CAPTAIN',
  );
  return validateBootstrapReceiptCore(options, {
    assertBranchNotOccupiedElsewhere,
    inspectWorkerWorktree,
    repositoryCommonGitDir,
    verifyWorktreeBootstrapHead,
  }, CAPTAIN_BOOTSTRAP_PROFILE);
}

module.exports = {
  BOOTSTRAP_INTENT_KIND,
  BOOTSTRAP_PLAN_KIND,
  BOOTSTRAP_RECEIPT_KIND,
  CAPTAIN_BOOTSTRAP_INTENT_KIND,
  CAPTAIN_BOOTSTRAP_PLAN_KIND,
  CAPTAIN_BOOTSTRAP_RECEIPT_KIND,
  WORKER_ROLES,
  canaryBootstrapInspect,
  canaryBootstrapPlan,
  canaryBootstrapPrepare,
  validateCaptainBootstrapReceipt,
  validateWorkerBootstrapReceipt,
  captainRequiredStartHeadFromGoal,
  loadCaptainRequiredStartHeadProof,
};
