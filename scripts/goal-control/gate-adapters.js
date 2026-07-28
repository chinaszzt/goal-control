'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { fileURLToPath, pathToFileURL } = require('url');
const { assertControl, ControlError } = require('./errors');
const {
  authorizeSession,
  hashesEqual,
  readCapabilityFile,
} = require('./auth');
const { assertDevCandidateLineage } = require('./candidate-lineage');
const {
  evidenceAcceptanceAnchor,
  evidenceFile,
  readExistingEvidenceForRetryUnderLock,
} = require('./evidence');
const { assertOperationalScope } = require('./operational-scope');
const {
  atomicWriteJson,
  canonicalTransactionKey,
  ensureDir,
  isOddTransactionRetry,
  withLock,
} = require('./store');
const {
  assertFullSha,
  assertIsolatedTestMode,
  controlRoot,
  git,
  hashFile,
  hashObject,
  nowIso,
  readJson,
  repoRoot,
  safeId,
} = require('./util');

const MAX_CAPTURE_BYTES = 1024 * 1024;

function trustedHomeDirectory() {
  let home;
  try {
    home = os.userInfo().homedir;
  } catch (error) {
    throw new ControlError('TRUSTED_HOME_MISSING', `无法从 OS 账号解析 home: ${error.message}`);
  }
  assertControl(path.isAbsolute(home), 'TRUSTED_HOME_MISSING', 'OS 账号 home 不是绝对路径');
  try {
    return fs.realpathSync(home);
  } catch (error) {
    throw new ControlError('TRUSTED_HOME_MISSING', `OS 账号 home 不可用: ${error.message}`);
  }
}

function captured(value) {
  const body = String(value || '');
  if (Buffer.byteLength(body) <= MAX_CAPTURE_BYTES) return body;
  return `${body.slice(0, MAX_CAPTURE_BYTES)}\n[goalctl: output truncated]\n`;
}

function maybeFaultAfterGateGeneration(cwd, kind, dependencies) {
  if (
    typeof dependencies.afterGenerationBeforeCallback === 'function'
  ) {
    assertIsolatedTestMode(cwd);
    dependencies.afterGenerationBeforeCallback();
  }
  const environmentName =
    `GOAL_CONTROL_TEST_FAULT_AFTER_${kind}_GENERATION`;
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
    'TEST_FAULT_AFTER_GATE_GENERATION',
    `injected ${kind} generation boundary failure`,
  );
}

function gateGenerationBoundaryFaultHook(cwd, kind, dependencies) {
  const mode =
    process.env[`GOAL_CONTROL_TEST_FAULT_AFTER_${kind}_GENERATION`];
  if (
    typeof dependencies.afterGenerationBeforeCallback !== 'function'
      && (mode === undefined || mode === '')
  ) {
    return undefined;
  }
  assertIsolatedTestMode(cwd);
  return () => maybeFaultAfterGateGeneration(cwd, kind, dependencies);
}

function trustedExecutableCandidates(name, trustedHome = trustedHomeDirectory(), nodeExecutable = process.execPath) {
  return [
    name === 'node' ? nodeExecutable : null,
    path.join('/opt/homebrew/bin', name),
    path.join('/usr/local/bin', name),
    path.join('/usr/bin', name),
    path.join('/bin', name),
    name === 'pnpm'
      ? path.join(trustedHome, 'setup-pnpm', 'node_modules', '.bin', 'pnpm')
      : null,
    path.join(trustedHome, '.local', 'bin', name),
  ].filter(Boolean);
}

function trustedExecutable(name) {
  const candidates = trustedExecutableCandidates(name);
  for (const candidate of candidates) {
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) {
        return { executable: fs.realpathSync(candidate), path_dir: path.dirname(candidate) };
      }
    } catch {
      // Try the next fixed installation prefix. Caller PATH is deliberately ignored.
    }
  }
  throw new ControlError('TRUSTED_EXECUTABLE_MISSING', `固定路径中找不到 ${name}`);
}

function resolveExecutable(name, dependencies = {}) {
  if (typeof dependencies.resolveExecutable !== 'function') return trustedExecutable(name);
  assertControl(process.env.GOAL_CONTROL_TEST_MODE === '1', 'TEST_DEPENDENCY_FORBIDDEN', '可执行文件解析器只允许测试注入');
  const resolved = dependencies.resolveExecutable(name);
  assertControl(
    resolved && path.isAbsolute(resolved.executable) && path.isAbsolute(resolved.path_dir),
    'INVALID_TEST_DEPENDENCY',
    `测试解析器没有返回 ${name} 的绝对路径`,
  );
  return resolved;
}

function sanitizedEnvironment(requiredExecutables, dependencies = {}) {
  const resolved = requiredExecutables.map((name) => resolveExecutable(name, dependencies));
  const trustedHome = trustedHomeDirectory();
  const pathEntries = [
    ...resolved.map((item) => item.path_dir),
    path.dirname(process.execPath),
    '/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin',
  ];
  const env = {
    PATH: [...new Set(pathEntries)].join(path.delimiter),
    HOME: trustedHome,
    CI: '1',
    TZ: 'Asia/Shanghai',
    BASE_REF: 'origin/main',
    SKIP_TESTS: '0',
    GH_PROMPT_DISABLED: '1',
    GIT_TERMINAL_PROMPT: '0',
  };
  return { env, resolved };
}

function runFixed(executable, args, cwd, requiredExecutables, dependencies = {}) {
  const { env } = sanitizedEnvironment(requiredExecutables, dependencies);
  const runner = dependencies.runner || spawnSync;
  const result = runner(executable, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: MAX_CAPTURE_BYTES,
    env,
  });
  if (result.error) throw new ControlError('GATE_EXEC_FAILED', `${path.basename(executable)} 启动失败: ${result.error.message}`);
  return {
    exit_code: Number.isSafeInteger(result.status) ? result.status : 1,
    signal: result.signal || null,
    stdout: captured(result.stdout),
    stderr: captured(result.stderr),
  };
}

function prepare(cwd, options, role) {
  const { assertFrozenInputs, loadGoalStateReadOnly } = require('./goal');
  const loaded = loadGoalStateReadOnly(cwd, options.goalId);
  const task = loaded.snapshot.tasks[options.taskId];
  assertControl(task, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
  const session = authorizeSession(task, options.actorCapabilityFile, { role });
  assertFrozenInputs(cwd, loaded, options.taskId);
  assertControl(task.phase === 'DEV_ACTIVE', 'GATE_PHASE_MISMATCH', `${role} gate 只允许在 DEV_ACTIVE 生成候选 evidence`);
  assertOperationalScope(task, 'DEV', 'GATE_EVIDENCE');
  assertControl(task.holds.length === 0, 'TASK_HELD', `task 存在 hold: ${task.holds.map((hold) => hold.kind).join(',')}`);
  const worktree = repoRoot(cwd);
  const fullHead = git(worktree, ['rev-parse', 'HEAD']);
  assertFullSha(fullHead, 'candidate HEAD');
  assertDevCandidateLineage(worktree, task, task.sessions.DEV, fullHead);
  assertControl(git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '', 'DIRTY_WORKTREE', 'mechanical evidence 只允许审核 clean committed HEAD');
  return { loaded, task, session, worktree, fullHead };
}

function assertCandidateUnchanged(context) {
  assertControl(git(context.worktree, ['rev-parse', 'HEAD']) === context.fullHead, 'HEAD_CHANGED_DURING_GATE', 'gate 运行期间 HEAD 发生变化');
  assertControl(git(context.worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '', 'DIRTY_WORKTREE', 'gate 运行期间 worktree 变脏');
}

function gateRequest(options, kind) {
  return {
    schema_version: 1,
    evidence_id: safeId(options.evidenceId, `${kind} evidence`),
    goal_id: safeId(options.goalId, 'goal_id'),
    task_id: safeId(options.taskId, 'task_id'),
    kind,
    ...(kind === 'FULL_CI' || kind === 'AC_AUDIT'
      ? { pull_request: options.pullRequest }
      : {}),
    ...(kind === 'AC_AUDIT' ? { issue: options.issue } : {}),
  };
}

function gateProducerAuthority(session) {
  assertControl(
    session
      && typeof session.role === 'string'
      && typeof session.thread_id === 'string'
      && typeof session.host_id === 'string'
      && Number.isSafeInteger(session.attempt)
      && typeof session.capability_file === 'string'
      && typeof session.capability_sha256 === 'string',
    'TRANSACTION_KEY_INVALID',
    'gate transaction 缺 producer authority anchor',
  );
  return {
    role: session.role,
    thread_id: session.thread_id,
    host_id: session.host_id,
    attempt: session.attempt,
    capability_file: session.capability_file,
    capability_sha256: session.capability_sha256,
  };
}

function gateTransactionKey(options, kind, binding) {
  const request = gateRequest(options, kind);
  const transactionKind = {
    FAST: 'FAST_GATE',
    FULL_CI: 'FULL_GATE',
    AC_AUDIT: 'AC_AUDIT_GATE',
  }[kind];
  assertControl(
    transactionKind,
    'TRANSACTION_KIND_INVALID',
    `未知 gate transaction kind: ${kind}`,
  );
  assertControl(
    binding
      && binding.session
      && typeof binding.fullHead === 'string'
      && /^[0-9a-f]{40}$/.test(binding.fullHead),
    'TRANSACTION_KEY_INVALID',
    `${kind} gate transaction 缺 producer/candidate binding`,
  );
  const producer = gateProducerAuthority(binding.session);
  const transactionRequest = {
    ...request,
    producer_authority: producer,
    candidate_full_head: binding.fullHead,
  };
  return canonicalTransactionKey(
    transactionKind,
    {
      goal_id: request.goal_id,
      task_id: request.task_id,
      producer_role: producer.role,
      producer_thread_id: producer.thread_id,
      producer_host_id: producer.host_id,
      producer_attempt: String(producer.attempt),
      producer_capability_sha256: producer.capability_sha256,
      candidate_full_head: binding.fullHead,
    },
    request.evidence_id,
    hashObject(transactionRequest),
  );
}

function gateArtifactFile(root, options) {
  return path.join(
    root,
    'goals',
    options.goalId,
    'evidence-artifacts',
    options.taskId,
    `${options.evidenceId}-artifact.json`,
  );
}

function sealGateArtifact(artifact) {
  return {
    ...artifact,
    artifact_sha256: hashObject(artifact),
  };
}

function validateGateArtifact(cwd, options, kind, artifactFile = null) {
  const root = controlRoot(cwd);
  const file = artifactFile || gateArtifactFile(root, options);
  const artifact = readJson(file, `${kind} prepared artifact`);
  const unsigned = { ...artifact };
  delete unsigned.artifact_sha256;
  const expectedRequest = gateRequest(options, kind);
  const expectedRole = kind === 'FAST' ? 'DEV' : 'CAPTAIN';
  assertControl(
    path.resolve(file) === gateArtifactFile(root, options)
      && artifact.schema_version === 1
      && artifact.controller === 'goalctl'
      && artifact.adapter === kind
      && artifact.goal_id === options.goalId
      && artifact.task_id === options.taskId
      && artifact.producer
      && artifact.producer.role === expectedRole
      && artifact.acceptance_anchor
      && hashObject(artifact.request) === hashObject(expectedRequest)
      && artifact.artifact_sha256 === hashObject(unsigned),
    'EVIDENCE_ID_CONFLICT',
    `${kind} evidence id ${options.evidenceId} 已绑定不同或损坏的 prepared artifact`,
  );
  return artifact;
}

function exactHistoricalGateSession(state, artifact, actorCapabilityFile) {
  const supplied = readCapabilityFile(actorCapabilityFile);
  const anchor = artifact.acceptance_anchor;
  const sessions = [
    ...Object.values(state.sessions || {}),
    ...Object.values(state.session_history || {}).flat(),
  ];
  const session = sessions.find((candidate) => (
    candidate
      && candidate.role === artifact.producer.role
      && candidate.thread_id === artifact.producer.thread_id
      && candidate.host_id === artifact.producer.host_id
      && candidate.attempt === anchor.producer.attempt
      && (candidate.launch_id || null) === anchor.producer.launch_id
      && candidate.capability_file === supplied.file
      && hashesEqual(candidate.capability_sha256, supplied.sha256)
  ));
  assertControl(
    session,
    'CAPABILITY_INVALID',
    `capability 不属于 ${artifact.adapter} prepared artifact 的原始历史 producer`,
  );
  assertControl(
    hashObject(evidenceAcceptanceAnchor(
      {
        task_id: artifact.task_id,
        state_revision: artifact.state_revision,
        control_epoch: anchor.control_epoch,
        phase: anchor.phase,
        task_cycle: anchor.task_cycle,
      },
      session,
    )) === hashObject(anchor),
    'CORRUPT_STORE',
    `${artifact.adapter} prepared artifact acceptance anchor 漂移`,
  );
  return session;
}

function resolveGateTransactionBinding(
  cwd,
  options,
  kind,
  fallbackContext = null,
) {
  const root = controlRoot(cwd);
  const artifactFile = gateArtifactFile(root, options);
  if (fs.existsSync(artifactFile)) {
    const artifact = validateGateArtifact(
      cwd,
      options,
      kind,
      artifactFile,
    );
    const { loadGoalStateUnlocked } = require('./goal');
    const loaded = loadGoalStateUnlocked(
      root,
      options.goalId,
      {
        repairHeads: false,
        repairBootstrapConsumption: false,
      },
    );
    const state = loaded.snapshot.tasks[options.taskId];
    assertControl(
      state,
      'UNKNOWN_TASK',
      `未知 task ${options.taskId}`,
    );
    return {
      session: exactHistoricalGateSession(
        state,
        artifact,
        options.actorCapabilityFile,
      ),
      fullHead: artifact.full_head,
    };
  }
  assertControl(
    fallbackContext
      && fallbackContext.session
      && typeof fallbackContext.fullHead === 'string',
    'TRANSACTION_KEY_INVALID',
    `${kind} gate transaction 缺 prepared/fresh candidate binding`,
  );
  return {
    session: fallbackContext.session,
    fullHead: fallbackContext.fullHead,
  };
}

function assertGateTransactionBindingStable(expected, session, fullHead, kind) {
  assertControl(
    expected
      && hashObject(gateProducerAuthority(expected.session))
        === hashObject(gateProducerAuthority(session))
      && expected.fullHead === fullHead,
    'STORE_TRANSACTION_PREFLIGHT_MUTATED',
    `${kind} gate producer/candidate binding 在 key resolution 与 authorization 间漂移`,
  );
}

function exactPristineGateSessionAt(
  state,
  transaction,
  options,
  kind,
) {
  const supplied = readCapabilityFile(options.actorCapabilityFile);
  const scope = transaction.active_transaction.scope;
  const expectedRole = kind === 'FAST' ? 'DEV' : 'CAPTAIN';
  const startedAt = Date.parse(transaction.transaction_started_at);
  assertControl(
    Number.isFinite(startedAt),
    'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
    `${kind} pristine recovery 缺 transaction_started_at`,
  );
  const sessions = [
    ...Object.values(state.sessions || {}),
    ...Object.values(state.session_history || {}).flat(),
  ];
  const session = sessions.find((candidate) => (
    candidate
      && candidate.role === expectedRole
      && candidate.role === scope.producer_role
      && candidate.thread_id === scope.producer_thread_id
      && candidate.host_id === scope.producer_host_id
      && String(candidate.attempt) === scope.producer_attempt
      && candidate.capability_sha256
        === scope.producer_capability_sha256
      && candidate.capability_file === supplied.file
      && hashesEqual(candidate.capability_sha256, supplied.sha256)
  ));
  assertControl(
    session,
    'CAPABILITY_INVALID',
    `capability 不属于 ${kind} pristine transaction 的原始 producer`,
  );
  assertControl(
    ['active', 'idle'].includes(session.status),
    'ACTOR_UNUSABLE',
    `${kind} producer status=${session.status}`,
  );
  assertControl(
    Date.parse(session.lease_until) > startedAt,
    'ACTOR_LEASE_EXPIRED',
    `${kind} producer lease 在 transaction_started_at=${transaction.transaction_started_at} 前已过期`,
  );
  assertControl(
    typeof scope.candidate_full_head === 'string'
      && /^[0-9a-f]{40}$/.test(scope.candidate_full_head),
    'TRANSACTION_KEY_INVALID',
    `${kind} pristine transaction 缺 candidate HEAD`,
  );
  return {
    session,
    fullHead: scope.candidate_full_head,
  };
}

function assertPreparedGateMaterializable(root, loaded, task, artifact) {
  assertControl(
    task.phase !== 'ARCHIVED',
    'TASK_TERMINAL',
    `task ${task.task_id} 已 ARCHIVED，不得 materialize prepared ${artifact.adapter} evidence`,
  );
  const anchor = artifact.acceptance_anchor;
  assertControl(
    task.state_revision === artifact.state_revision
      && loaded.control.epoch === anchor.control_epoch
      && task.phase === anchor.phase
      && task.task_cycle === anchor.task_cycle
      && task.packet.revision === artifact.packet.revision
      && task.packet.sha256 === artifact.packet.sha256
      && task.base_head === artifact.base_head,
    'TASK_OPERATION_DIVERGED',
    `prepared ${artifact.adapter} evidence ${artifact.request.evidence_id} 的 task/control anchor 已漂移`,
  );
  const { assertNoPendingTaskOperations } = require('./pending-operations');
  assertNoPendingTaskOperations(
    root,
    artifact.goal_id,
    artifact.task_id,
    {
      allowOperationKind: artifact.adapter,
      allowOperationId: artifact.request.evidence_id,
      allowRequestSha256: hashObject(artifact.request),
    },
  );
}

function maybeFaultAfterEvidenceIngress(kind, dependencies) {
  if (typeof dependencies.afterEvidenceIngress === 'function') {
    assertControl(
      process.env.GOAL_CONTROL_TEST_MODE === '1',
      'TEST_DEPENDENCY_FORBIDDEN',
      'evidence ingress fault 只允许测试注入',
    );
    dependencies.afterEvidenceIngress();
  }
  const fault = process.env.GOAL_CONTROL_TEST_FAULT_AFTER_EVIDENCE_INGRESS;
  if (fault !== '1' && fault !== kind) return;
  assertControl(
    process.env.GOAL_CONTROL_TEST_MODE === '1',
    'TEST_DEPENDENCY_FORBIDDEN',
    'evidence ingress fault 只允许测试注入',
  );
  throw new ControlError(
    'TEST_FAULT_AFTER_EVIDENCE_INGRESS',
    `injected response loss after durable ${kind} evidence`,
  );
}

function maybeFaultAfterGateArtifact(kind, dependencies) {
  if (typeof dependencies.afterArtifactIngress === 'function') {
    assertControl(
      process.env.GOAL_CONTROL_TEST_MODE === '1',
      'TEST_DEPENDENCY_FORBIDDEN',
      'gate artifact fault 只允许测试注入',
    );
    dependencies.afterArtifactIngress();
  }
  const fault = process.env.GOAL_CONTROL_TEST_FAULT_AFTER_GATE_ARTIFACT;
  if (fault !== '1' && fault !== kind) return;
  assertControl(
    process.env.GOAL_CONTROL_TEST_MODE === '1',
    'TEST_DEPENDENCY_FORBIDDEN',
    'gate artifact fault 只允许测试注入',
  );
  throw new ControlError(
    'TEST_FAULT_AFTER_GATE_ARTIFACT',
    `injected failure after durable ${kind} prepared artifact`,
  );
}

function storeArtifactUnderLock(root, options, kind, artifact) {
  const dir = path.join(
    root,
    'goals',
    options.goalId,
    'evidence-artifacts',
    options.taskId,
  );
  ensureDir(dir);
  const file = path.join(dir, `${options.evidenceId}-artifact.json`);
  assertControl(
    !fs.existsSync(file),
    'EVIDENCE_ID_CONFLICT',
    `${kind} evidence id ${options.evidenceId} 已存在 prepared artifact`,
  );
  const sealed = sealGateArtifact(artifact);
  atomicWriteJson(file, sealed);
  return { file, artifact: sealed };
}

function gateEvidenceFromArtifact(root, options, artifact) {
  const artifactFile = gateArtifactFile(root, options);
  return {
    schema_version: 1,
    evidence_id: options.evidenceId,
    goal_id: options.goalId,
    task_id: options.taskId,
    kind: artifact.adapter,
    status: artifact.status,
    producer: artifact.producer,
    state_revision: artifact.state_revision,
    packet: artifact.packet,
    packet_sha256: artifact.packet_sha256,
    base_head: artifact.base_head,
    full_head: artifact.full_head,
    ...(artifact.pull_request ? { pull_request: artifact.pull_request } : {}),
    ...(artifact.launch_id ? { launch_id: artifact.launch_id } : {}),
    created_at: artifact.created_at,
    uri: pathToFileURL(artifactFile).href,
    source_sha256: hashFile(artifactFile),
    command: artifact.command,
    checks: artifact.checks,
    attestation: { controller: 'goalctl', adapter: artifact.adapter },
    acceptance_anchor: artifact.acceptance_anchor,
  };
}

function writeGateEvidenceUnderLock(root, options, artifact, idempotent) {
  const file = evidenceFile(
    root,
    options.goalId,
    options.taskId,
    options.evidenceId,
  );
  assertControl(
    !fs.existsSync(file),
    'EVIDENCE_ID_CONFLICT',
    `${artifact.adapter} evidence ${options.evidenceId} 已存在`,
  );
  const evidence = gateEvidenceFromArtifact(root, options, artifact);
  const sealed = {
    ...evidence,
    registry_sha256: hashObject(evidence),
  };
  ensureDir(path.dirname(file));
  atomicWriteJson(file, sealed);
  return {
    registered: true,
    idempotent,
    evidence: sealed,
    evidence_file: file,
  };
}

function validateGateRetry(cwd, options, kind, retried) {
  const root = controlRoot(cwd);
  const evidence = retried.evidence;
  let artifactFile;
  try {
    artifactFile = fileURLToPath(new URL(evidence.uri));
  } catch (error) {
    throw new ControlError(
      'MECHANICAL_ARTIFACT_INVALID',
      `${kind} artifact URI 无法解析: ${error.message}`,
    );
  }
  const artifact = validateGateArtifact(
    cwd,
    options,
    kind,
    artifactFile,
  );
  const expectedEvidence = gateEvidenceFromArtifact(root, options, artifact);
  const actualEvidence = { ...evidence };
  delete actualEvidence.registry_sha256;
  assertControl(
    hashObject(actualEvidence) === hashObject(expectedEvidence),
    'EVIDENCE_ID_CONFLICT',
    `${kind} evidence id ${options.evidenceId} registry 与 prepared artifact 不一致`,
  );
  return {
    response: {
      registered: true,
      idempotent: true,
      evidence,
      evidence_file: retried.evidence_file,
    },
    artifact,
  };
}

function recoverGateIngress(cwd, options, kind) {
  const root = controlRoot(cwd);
  const artifactFile = gateArtifactFile(root, options);
  const registryFile = evidenceFile(
    root,
    options.goalId,
    options.taskId,
    options.evidenceId,
  );
  if (!fs.existsSync(artifactFile) && !fs.existsSync(registryFile)) return null;
  let boundary = null;
  let transactionBinding = null;
  return withLock(root, () => {
    if (boundary.retry) return boundary.retry;
    return writeGateEvidenceUnderLock(
      root,
      options,
      boundary.artifact,
      true,
    );
  }, {
    beforeGeneration: () => {
      const retried = readExistingEvidenceForRetryUnderLock(cwd, {
        goalId: options.goalId,
        taskId: options.taskId,
        evidenceId: options.evidenceId,
        actorCapabilityFile: options.actorCapabilityFile,
      });
      if (retried) {
        const validated = validateGateRetry(
          cwd,
          options,
          kind,
          retried,
        );
        const { loadGoalStateUnlocked } = require('./goal');
        const loaded = loadGoalStateUnlocked(
          root,
          options.goalId,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const state = loaded.snapshot.tasks[options.taskId];
        assertControl(state, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
        const session = exactHistoricalGateSession(
          state,
          validated.artifact,
          options.actorCapabilityFile,
        );
        boundary = {
          retry: validated.response,
          artifact: validated.artifact,
          session,
        };
        assertGateTransactionBindingStable(
          transactionBinding,
          session,
          validated.artifact.full_head,
          kind,
        );
        return;
      }
      assertControl(
        fs.existsSync(artifactFile),
        'CORRUPT_STORE',
        `${kind} evidence registry 存在但 prepared artifact 缺失`,
      );
      const artifact = validateGateArtifact(cwd, options, kind, artifactFile);
      const { loadGoalStateUnlocked } = require('./goal');
      const loaded = loadGoalStateUnlocked(
        root,
        options.goalId,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const state = loaded.snapshot.tasks[options.taskId];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
      const session = exactHistoricalGateSession(
        state,
        artifact,
        options.actorCapabilityFile,
      );
      assertPreparedGateMaterializable(root, loaded, state, artifact);
      boundary = { artifact, session };
      assertGateTransactionBindingStable(
        transactionBinding,
        session,
        artifact.full_head,
        kind,
      );
    },
    authorizeOddRecovery: () => Boolean(
      boundary && (boundary.retry || boundary.artifact),
    ),
    transactionKey: () => {
      transactionBinding = resolveGateTransactionBinding(
        cwd,
        options,
        kind,
      );
      return gateTransactionKey(options, kind, transactionBinding);
    },
    sameStableOperationMismatchCode: 'EVIDENCE_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      `${kind} evidence id 已绑定不同 gate request`,
  });
}

function abortPristineGateIngress(cwd, options, kind) {
  const root = controlRoot(cwd);
  const artifactFile = gateArtifactFile(root, options);
  const registryFile = evidenceFile(
    root,
    options.goalId,
    options.taskId,
    options.evidenceId,
  );
  if (fs.existsSync(artifactFile) || fs.existsSync(registryFile)) return false;
  const generationFile = path.join(root, '.generation.json');
  if (!fs.existsSync(generationFile)) return false;
  const generation = readJson(
    generationFile,
    `${kind} pristine generation probe`,
  );
  const transactionKind = {
    FAST: 'FAST_GATE',
    FULL_CI: 'FULL_GATE',
    AC_AUDIT: 'AC_AUDIT_GATE',
  }[kind];
  if (
    !Number.isSafeInteger(generation.generation)
      || generation.generation % 2 === 0
      || !generation.active_transaction
      || generation.active_transaction.kind !== transactionKind
      || generation.active_transaction.scope.goal_id !== options.goalId
      || generation.active_transaction.scope.task_id !== options.taskId
  ) {
    return false;
  }
  let authorized = false;
  try {
    withLock(root, () => {
      throw new ControlError(
        'STORE_PRISTINE_ABORT_RETRY',
        `旧 ${kind} pristine transaction 已安全关闭；必须按当前输入重新执行`,
      );
    }, {
      beforeGeneration: (transaction) => {
        authorized = false;
        assertControl(
          isOddTransactionRetry(transaction.mode)
            && transaction.active_transaction
            && transaction.active_transaction.kind === transactionKind,
          'STORE_TRANSACTION_MISMATCH',
          `${kind} pristine transaction kind 不匹配`,
        );
        const { loadGoalStateUnlocked } = require('./goal');
        const loaded = loadGoalStateUnlocked(
          root,
          options.goalId,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const state = loaded.snapshot.tasks[options.taskId];
        assertControl(state, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
        const binding = exactPristineGateSessionAt(
          state,
          transaction,
          options,
          kind,
        );
        const expected = gateTransactionKey(
          options,
          kind,
          binding,
        );
        assertControl(
          transaction.active_transaction.key_sha256
            === expected.key_sha256,
          'STORE_TRANSACTION_MISMATCH',
          `${kind} pristine transaction key 不匹配`,
        );
        assertControl(
          typeof transaction.pre_write_vector_sha256 === 'string',
          'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
          `${kind} pristine recovery 缺 v3 pre-write vector`,
        );
        assertControl(
          transaction.pristine_payload_vector_sha256
            === transaction.pre_write_vector_sha256,
          'STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH',
          `${kind} pristine payload 已漂移`,
        );
        authorized = true;
      },
      authorizePristineOddRecovery: () => authorized,
      transactionKey: () => {
        const { loadGoalStateUnlocked } = require('./goal');
        const loaded = loadGoalStateUnlocked(
          root,
          options.goalId,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const state = loaded.snapshot.tasks[options.taskId];
        assertControl(
          state,
          'UNKNOWN_TASK',
          `未知 task ${options.taskId}`,
        );
        const binding = exactPristineGateSessionAt(
          state,
          {
            active_transaction: generation.active_transaction,
            transaction_started_at: generation.updated_at,
          },
          options,
          kind,
        );
        return gateTransactionKey(options, kind, binding);
      },
    });
  } catch (error) {
    if (error && error.code === 'STORE_PRISTINE_ABORT_RETRY') return true;
    throw error;
  }
  assertControl(
    false,
    'CORRUPT_STORE',
    `${kind} pristine abort 未返回预期边界错误`,
  );
}

function registerGate(
  cwd,
  options,
  context,
  kind,
  command,
  status,
  checks,
  execution,
  pullRequest = null,
  dependencies = {},
) {
  const root = controlRoot(cwd);
  let boundary = null;
  let transactionBinding = null;
  return withLock(root, () => {
    if (boundary.retry) return boundary.retry;
    if (boundary.artifact) {
      return writeGateEvidenceUnderLock(
        root,
        options,
        boundary.artifact,
        true,
      );
    }
    const { task, session } = boundary;

    const createdAt = nowIso();
    const request = gateRequest(options, kind);
    const stored = storeArtifactUnderLock(root, options, kind, {
      schema_version: 1,
      controller: 'goalctl',
      adapter: kind,
      request,
      goal_id: options.goalId,
      task_id: options.taskId,
      producer: {
        role: session.role,
        thread_id: session.thread_id,
        host_id: session.host_id,
      },
      state_revision: task.state_revision,
      packet: { revision: task.packet.revision, sha256: task.packet.sha256 },
      packet_sha256: task.packet.sha256,
      base_head: task.base_head,
      full_head: context.fullHead,
      ...(pullRequest ? { pull_request: pullRequest } : {}),
      ...(session.launch_id ? { launch_id: session.launch_id } : {}),
      command,
      status,
      checks,
      execution,
      created_at: createdAt,
      acceptance_anchor: evidenceAcceptanceAnchor(task, session),
    });
    maybeFaultAfterGateArtifact(kind, dependencies);
    return writeGateEvidenceUnderLock(
      root,
      options,
      stored.artifact,
      false,
    );
  }, {
    beforeGeneration: () => {
      const { assertFrozenInputs, loadGoalStateUnlocked } = require('./goal');
      const retried = readExistingEvidenceForRetryUnderLock(cwd, {
        goalId: options.goalId,
        taskId: options.taskId,
        evidenceId: options.evidenceId,
        actorCapabilityFile: options.actorCapabilityFile,
      });
      if (retried) {
        const validated = validateGateRetry(
          cwd,
          options,
          kind,
          retried,
        );
        const loaded = loadGoalStateUnlocked(
          root,
          options.goalId,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const task = loaded.snapshot.tasks[options.taskId];
        assertControl(task, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
        const session = exactHistoricalGateSession(
          task,
          validated.artifact,
          options.actorCapabilityFile,
        );
        boundary = {
          retry: validated.response,
          artifact: validated.artifact,
          session,
        };
        assertGateTransactionBindingStable(
          transactionBinding,
          session,
          validated.artifact.full_head,
          kind,
        );
        return;
      }
      const artifactFile = gateArtifactFile(root, options);
      if (fs.existsSync(artifactFile)) {
        const artifact = validateGateArtifact(
          cwd,
          options,
          kind,
          artifactFile,
        );
        const loaded = loadGoalStateUnlocked(
          root,
          options.goalId,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const task = loaded.snapshot.tasks[options.taskId];
        assertControl(task, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
        const session = exactHistoricalGateSession(
          task,
          artifact,
          options.actorCapabilityFile,
        );
        assertPreparedGateMaterializable(root, loaded, task, artifact);
        boundary = { artifact, session };
        assertGateTransactionBindingStable(
          transactionBinding,
          session,
          artifact.full_head,
          kind,
        );
        return;
      }
      const loaded = loadGoalStateUnlocked(
        root,
        options.goalId,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const task = loaded.snapshot.tasks[options.taskId];
      assertControl(task, 'UNKNOWN_TASK', `未知 task ${options.taskId}`);
      assertControl(
        task.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${task.task_id} 已 ARCHIVED，不得提交 ${kind} evidence`,
      );
      assertControl(
        loaded.control.eventCount === context.loaded.control.eventCount
          && loaded.control.lastEventHash === context.loaded.control.lastEventHash
          && loaded.control.epoch === context.loaded.control.epoch
          && task.state_revision === context.task.state_revision
          && loaded.lastEventHashes[options.taskId]
            === context.loaded.lastEventHashes[options.taskId],
        'STALE_STATE_REVISION',
        `${kind} 执行期间控制状态已漂移；必须基于 fresh state 重跑`,
      );
      const session = authorizeSession(task, options.actorCapabilityFile, {
        role: context.session.role,
        threadId: context.session.thread_id,
      });
      assertFrozenInputs(cwd, loaded, options.taskId);
      assertControl(
        task.phase === 'DEV_ACTIVE',
        'GATE_PHASE_MISMATCH',
        `${session.role} gate 只允许在 DEV_ACTIVE 生成候选 evidence`,
      );
      assertOperationalScope(task, 'DEV', 'GATE_EVIDENCE');
      assertControl(
        task.holds.length === 0,
        'TASK_HELD',
        `task 存在 hold: ${task.holds.map((hold) => hold.kind).join(',')}`,
      );
      assertCandidateUnchanged(context);
      assertDevCandidateLineage(
        context.worktree,
        task,
        task.sessions.DEV,
        context.fullHead,
      );
      boundary = { loaded, task, session };
      assertGateTransactionBindingStable(
        transactionBinding,
        session,
        context.fullHead,
        kind,
      );
    },
    authorizeOddRecovery: () => Boolean(
      boundary && (boundary.retry || boundary.artifact),
    ),
    transactionKey: () => {
      transactionBinding = resolveGateTransactionBinding(
        cwd,
        options,
        kind,
        context,
      );
      return gateTransactionKey(options, kind, transactionBinding);
    },
    sameStableOperationMismatchCode: 'EVIDENCE_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      `${kind} evidence id 已绑定不同 gate request`,
    afterGenerationBeforeCallback:
      gateGenerationBoundaryFaultHook(cwd, kind, dependencies),
  });
}

function runFastEvidence(cwd, options, dependencies = {}) {
  safeId(options.evidenceId, 'FAST evidence');
  abortPristineGateIngress(cwd, options, 'FAST');
  const retry = recoverGateIngress(cwd, options, 'FAST');
  if (retry) return retry;
  const { assertNoPendingTaskOperations } = require('./pending-operations');
  assertNoPendingTaskOperations(
    controlRoot(cwd),
    options.goalId,
    options.taskId,
  );
  const context = prepare(cwd, options, 'DEV');
  const command = ['bash', 'scripts/quality-gate-fast.sh'];
  const execution = runFixed('/bin/bash', ['scripts/quality-gate-fast.sh'], context.worktree, ['node', 'pnpm'], dependencies);
  assertCandidateUnchanged(context);
  const status = execution.exit_code === 0 ? 'PASS' : 'FAIL';
  const registered = registerGate(cwd, options, context, 'FAST', command, status, [
    { name: 'quality-gate-fast', status, detail: `exit=${execution.exit_code}` },
  ], execution, null, dependencies);
  if (!registered.idempotent) maybeFaultAfterEvidenceIngress('FAST', dependencies);
  return registered;
}

function parsePrView(execution) {
  assertControl(execution.exit_code === 0, 'FULL_CI_QUERY_FAILED', `gh pr view 失败: ${execution.stderr.trim() || `exit ${execution.exit_code}`}`);
  try {
    return JSON.parse(execution.stdout);
  } catch (error) {
    throw new ControlError('FULL_CI_QUERY_FAILED', `gh pr view 未返回合法 JSON: ${error.message}`);
  }
}

function runFullCiEvidence(cwd, options, dependencies = {}) {
  safeId(options.evidenceId, 'FULL_CI evidence');
  assertControl(Number.isSafeInteger(options.pullRequest) && options.pullRequest > 0, 'INVALID_ARGUMENT', 'pr 必须是正整数');
  abortPristineGateIngress(cwd, options, 'FULL_CI');
  const retry = recoverGateIngress(cwd, options, 'FULL_CI');
  if (retry) return retry;
  const { assertNoPendingTaskOperations } = require('./pending-operations');
  assertNoPendingTaskOperations(
    controlRoot(cwd),
    options.goalId,
    options.taskId,
  );
  const context = prepare(cwd, options, 'CAPTAIN');
  const repository = context.loaded.manifest.repository.name_with_owner;
  const gh = resolveExecutable('gh', dependencies);
  const command = [
    'gh', 'pr', 'view', String(options.pullRequest), '--repo', repository,
    '--json', 'number,url,state,isDraft,headRefOid,baseRefName,statusCheckRollup',
  ];
  const execution = runFixed(gh.executable, command.slice(1), context.worktree, ['gh'], dependencies);
  assertCandidateUnchanged(context);
  const pr = parsePrView(execution);
  const exactUrl = `https://github.com/${repository}/pull/${options.pullRequest}`;
  const rollup = Array.isArray(pr.statusCheckRollup) ? pr.statusCheckRollup : [];
  const matches = rollup.filter((check) => (check && (check.name || check.context)) === 'Quality Gate (Full)');
  const checks = [
    { name: 'repository', status: pr.url === exactUrl ? 'PASS' : 'FAIL', detail: String(pr.url || '') },
    { name: 'pull-request', status: pr.number === options.pullRequest && pr.state === 'OPEN' ? 'PASS' : 'FAIL', detail: `number=${pr.number},state=${pr.state}` },
    { name: 'ready-for-review', status: pr.isDraft === false ? 'PASS' : 'FAIL', detail: `isDraft=${pr.isDraft}` },
    { name: 'base-branch', status: pr.baseRefName === context.loaded.manifest.repository.base_branch ? 'PASS' : 'FAIL', detail: String(pr.baseRefName || '') },
    { name: 'head', status: pr.headRefOid === context.fullHead ? 'PASS' : 'FAIL', detail: String(pr.headRefOid || '') },
    {
      name: 'Quality Gate (Full)',
      status: matches.length === 1 && matches[0].conclusion === 'SUCCESS' ? 'PASS' : 'FAIL',
      detail: `matches=${matches.length},conclusion=${matches[0] && matches[0].conclusion}`,
    },
  ];
  const status = checks.every((check) => check.status === 'PASS') ? 'PASS' : 'FAIL';
  const pullRequest = {
    repository,
    number: options.pullRequest,
    url: exactUrl,
    base: context.loaded.manifest.repository.base_branch,
    head: context.fullHead,
  };
  const registered = registerGate(cwd, options, context, 'FULL_CI', command, status, checks, { ...execution, response: pr }, pullRequest, dependencies);
  if (!registered.idempotent) {
    maybeFaultAfterEvidenceIngress('FULL_CI', dependencies);
  }
  return registered;
}

function runAcAuditEvidence(cwd, options, dependencies = {}) {
  safeId(options.evidenceId, 'AC_AUDIT evidence');
  assertControl(Number.isSafeInteger(options.issue) && options.issue > 0, 'INVALID_ARGUMENT', 'issue 必须是正整数');
  assertControl(Number.isSafeInteger(options.pullRequest) && options.pullRequest > 0, 'INVALID_ARGUMENT', 'pr 必须是正整数');
  abortPristineGateIngress(cwd, options, 'AC_AUDIT');
  const retry = recoverGateIngress(cwd, options, 'AC_AUDIT');
  if (retry) return retry;
  const { assertNoPendingTaskOperations } = require('./pending-operations');
  assertNoPendingTaskOperations(
    controlRoot(cwd),
    options.goalId,
    options.taskId,
  );
  const context = prepare(cwd, options, 'CAPTAIN');
  const manifestTask = context.loaded.manifest.tasks.find((candidate) => candidate.id === options.taskId);
  assertControl(Number.isSafeInteger(manifestTask.issue) && manifestTask.issue > 0, 'ISSUE_BINDING_MISSING', 'AC audit 要求 Goal manifest task 固定 issue');
  assertControl(manifestTask.issue === options.issue, 'ISSUE_BINDING_MISMATCH', `task issue=${manifestTask.issue}，收到 ${options.issue}`);
  const base = context.loaded.manifest.repository.base_branch;
  const command = [
    'bash', 'scripts/ac-audit.sh', String(options.issue), '--expected-head', context.fullHead,
    '--pr', String(options.pullRequest), '--base', base,
  ];
  const execution = runFixed('/bin/bash', command.slice(1), context.worktree, ['node', 'pnpm', 'gh', 'codex'], dependencies);
  assertCandidateUnchanged(context);
  const status = execution.exit_code === 0 ? 'PASS' : 'FAIL';
  const pullRequest = {
    repository: context.loaded.manifest.repository.name_with_owner,
    number: options.pullRequest,
    url: `https://github.com/${context.loaded.manifest.repository.name_with_owner}/pull/${options.pullRequest}`,
    base,
    head: context.fullHead,
  };
  const registered = registerGate(cwd, options, context, 'AC_AUDIT', command, status, [
    { name: 'ac-audit', status, detail: `issue=${options.issue},pr=${options.pullRequest},head=${context.fullHead},exit=${execution.exit_code}` },
  ], execution, pullRequest, dependencies);
  if (!registered.idempotent) {
    maybeFaultAfterEvidenceIngress('AC_AUDIT', dependencies);
  }
  return registered;
}

module.exports = {
  runAcAuditEvidence,
  runFastEvidence,
  runFullCiEvidence,
  trustedExecutableCandidates,
};
