'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { assertControl } = require('./errors');
const {
  runtimeRotationHoldEligible,
} = require('./launch-source-checkpoint');
const {
  hashFile,
  hashObject,
  normalizeHash,
  readJson,
  runtimeNowMilliseconds,
  safeId,
  sha256,
  sleepSync,
} = require('./util');
const { validateLaunchManifest } = require('./validation');

const WORKER_PHASES = Object.freeze({
  DEV: 'DEV_ACTIVE',
  REVIEW: 'REVIEW_ACTIVE',
  RECEIPT: 'RECEIPT_ACTIVE',
});
const LOCAL_PREVIEW_ZERO_WITNESS = 'LOCAL_PREVIEW_ZERO_WITNESS';
const ZERO_WITNESS_SAMPLES = 3;
const ZERO_WITNESS_INTERVAL_MS = 150;
// `observed_at` remains only for schema compatibility. Per-sample wall-clock
// time would make the raw RUNTIME_ROTATED event differ on an exact retry.
// The accepted event's `accepted_at` is the durable witness time anchor.
const ZERO_WITNESS_UNTIMED_MARKER = '1970-01-01T00:00:00.000Z';

function currentRuntimeIncarnation(session) {
  if (session && session.runtime_incarnation !== undefined) {
    assertControl(
      Number.isSafeInteger(session.runtime_incarnation)
        && session.runtime_incarnation > 0,
      'CORRUPT_STORE',
      'session runtime_incarnation 非法',
    );
    return session.runtime_incarnation;
  }
  return session && session.launch_id ? 1 : 0;
}

function runtimeNonce(binding) {
  return sha256([
    binding.goal_id,
    binding.task_id,
    binding.role,
    binding.worker_thread_id,
    binding.worker_host_id,
    String(binding.worker_attempt),
    String(binding.predecessor_incarnation),
    String(binding.successor_incarnation),
    binding.predecessor_launch_id,
    binding.successor_launch_id,
    binding.event_id,
  ].join('\0')).slice(0, 40);
}

function runtimePreflightEvidenceId(launch) {
  assertControl(
    launch
      && launch.runtime_incarnation
      && typeof launch.runtime_incarnation.rotation_event_id === 'string',
    'PREFLIGHT_EVIDENCE_ID_REQUIRED',
    '非 runtime successor preflight 必须显式提供 evidence ID',
  );
  return `preflight-runtime-${sha256([
    'RUNTIME_PREFLIGHT_EVIDENCE_V1',
    launch.goal_id,
    launch.task_id,
    launch.runtime_incarnation.rotation_event_id,
    launch.launch_id,
    hashObject(launch),
  ].join('\0')).slice(0, 32)}`;
}

function deriveProxyPort(webPort) {
  return webPort < 8090 ? 3456 : 3460 + (webPort - 8090);
}

function localPreviewPorts(launch) {
  assertControl(
    launch.execution.environment === 'none'
      && launch.execution.write_mode === 'NONE',
    'RUNTIME_ROTATION_SCOPE_VIOLATION',
    'runtime rotation v1 只允许 environment=none/write_mode=NONE',
  );
  for (const field of [
    'domain',
    'account_alias',
    'tim_alias',
    'identity_probe',
  ]) {
    assertControl(
      launch.execution[field] === undefined,
      'RUNTIME_ROTATION_SCOPE_VIOLATION',
      `runtime rotation v1 禁止 execution.${field}`,
    );
  }
  const target = launch.execution.target;
  assertControl(
    target.kind === 'PREVIEW'
      && Number.isSafeInteger(target.pid)
      && target.pid > 0,
    'RUNTIME_ROTATION_SCOPE_VIOLATION',
    'runtime rotation v1 只允许 PID-bound PREVIEW',
  );
  for (const field of ['user_data_dir', 'cdp_target_id', 'window_id']) {
    assertControl(
      target[field] === undefined,
      'RUNTIME_ROTATION_SCOPE_VIOLATION',
      `runtime rotation v1 禁止 target.${field}`,
    );
  }
  let parsed;
  try {
    parsed = new URL(target.preview_url);
  } catch {
    assertControl(
      false,
      'RUNTIME_ROTATION_SCOPE_VIOLATION',
      'PREVIEW URL 非法',
    );
  }
  assertControl(
    parsed.protocol === 'http:'
      && parsed.hostname === '127.0.0.1'
      && parsed.port
      && !parsed.username
      && !parsed.password
      && !parsed.search
      && !parsed.hash,
    'RUNTIME_ROTATION_SCOPE_VIOLATION',
    'runtime rotation v1 只允许无凭证/query/fragment 的 http://127.0.0.1:<port>',
  );
  const previewPort = Number(parsed.port);
  assertControl(
    Number.isSafeInteger(previewPort)
      && previewPort > 0
      && previewPort <= 65535,
    'RUNTIME_ROTATION_SCOPE_VIOLATION',
    'PREVIEW port 非法',
  );
  const proxyPort = deriveProxyPort(previewPort);
  assertControl(
    proxyPort > 0 && proxyPort <= 65535 && proxyPort !== previewPort,
    'RUNTIME_ROTATION_SCOPE_VIOLATION',
    'PREVIEW proxy port 映射非法',
  );
  return { preview_port: previewPort, proxy_port: proxyPort };
}

function trustedExecutable(candidates, label) {
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    const resolved = fs.realpathSync(candidate);
    const stat = fs.statSync(resolved);
    if (stat.isFile() && (stat.mode & 0o111) !== 0) return resolved;
  }
  assertControl(
    false,
    'RUNTIME_ZERO_WITNESS_UNAVAILABLE',
    `缺可信 ${label} executable`,
  );
}

function runTrusted(command, args, label) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      LANG: 'C',
      LC_ALL: 'C',
    },
    timeout: 5000,
  });
  assertControl(
    !result.error && result.signal === null,
    'RUNTIME_ZERO_WITNESS_FAILED',
    `${label} 执行失败`,
  );
  return result;
}

function processPatternCount(output, previewPort, proxyPort) {
  const preview = String(previewPort);
  const proxy = String(proxyPort);
  const previewPortArgument = new RegExp(
    `(?:^|\\s)--port(?:=|\\s+)${preview}(?:\\s|$)`,
  );
  const proxyPortArgument = new RegExp(
    `scripts/dev-proxy\\.js(?:\\s+)${proxy}(?:\\s|$)`,
  );
  return String(output || '')
    .split(/\r?\n/)
    .filter((line) => {
      const normalized = line.trim().replace(/\s+/g, ' ');
      if (!normalized) return false;
      return (
        (
          normalized.includes('scripts/dev-preview.js')
            && previewPortArgument.test(normalized)
        )
          || (
            normalized.includes('expo')
              && previewPortArgument.test(normalized)
          )
          || (
            normalized.includes('scripts/dev-proxy.js')
              && proxyPortArgument.test(normalized)
          )
      );
    })
    .length;
}

function localPreviewZeroSample(launch) {
  const ports = localPreviewPorts(launch);
  const ps = trustedExecutable(['/bin/ps', '/usr/bin/ps'], 'ps');
  const lsof = trustedExecutable(
    ['/usr/sbin/lsof', '/usr/bin/lsof'],
    'lsof',
  );
  const pid = launch.execution.target.pid;
  const pidResult = runTrusted(ps, ['-p', String(pid), '-o', 'pid='], 'PID probe');
  assertControl(
    [0, 1].includes(pidResult.status),
    'RUNTIME_ZERO_WITNESS_FAILED',
    'PID probe 返回未知状态',
  );
  const pidAbsent = pidResult.status === 1
    || String(pidResult.stdout || '').trim() === '';
  const listenerAbsent = (port) => {
    const result = runTrusted(
      lsof,
      ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN'],
      `port ${port} probe`,
    );
    assertControl(
      [0, 1].includes(result.status),
      'RUNTIME_ZERO_WITNESS_FAILED',
      `port ${port} probe 返回未知状态`,
    );
    return result.status === 1
      || String(result.stdout || '').trim() === '';
  };
  const processResult = runTrusted(
    ps,
    ['-axo', 'pid=,command='],
    'process-tree residue probe',
  );
  assertControl(
    processResult.status === 0,
    'RUNTIME_ZERO_WITNESS_FAILED',
    'process-tree residue probe 失败',
  );
  const matchingProcessCount = processPatternCount(
    processResult.stdout,
    ports.preview_port,
    ports.proxy_port,
  );
  const previewListenerAbsent = listenerAbsent(ports.preview_port);
  const proxyListenerAbsent = listenerAbsent(ports.proxy_port);
  assertControl(
    pidAbsent
      && previewListenerAbsent
      && proxyListenerAbsent
      && matchingProcessCount === 0,
    'RUNTIME_PREDECESSOR_STILL_ACTIVE',
    '旧 PREVIEW PID/端口或已知子进程仍存活',
  );
  return {
    observed_at: ZERO_WITNESS_UNTIMED_MARKER,
    predecessor_pid_absent: true,
    preview_listener_absent: true,
    proxy_listener_absent: true,
    matching_process_count: 0,
  };
}

function buildLocalPreviewZeroWitness(launch, options = {}) {
  const ports = localPreviewPorts(launch);
  const sample = options.sample || localPreviewZeroSample;
  const sampleCount = options.sampleCount || ZERO_WITNESS_SAMPLES;
  const intervalMilliseconds = options.intervalMilliseconds
    ?? ZERO_WITNESS_INTERVAL_MS;
  assertControl(
    Number.isSafeInteger(sampleCount) && sampleCount >= 1,
    'RUNTIME_ZERO_WITNESS_FAILED',
    'zero witness sample count 非法',
  );
  const samples = [];
  for (let index = 0; index < sampleCount; index += 1) {
    samples.push(sample(launch));
    if (index + 1 < sampleCount && intervalMilliseconds > 0) {
      sleepSync(intervalMilliseconds);
    }
  }
  return {
    schema_version: 1,
    kind: LOCAL_PREVIEW_ZERO_WITNESS,
    predecessor_launch_id: launch.launch_id,
    predecessor_pid: launch.execution.target.pid,
    preview_port: ports.preview_port,
    proxy_port: ports.proxy_port,
    sample_count: samples.length,
    samples,
  };
}

function validateLocalPreviewZeroWitness(launch, proof) {
  const ports = localPreviewPorts(launch);
  assertControl(
    proof
      && typeof proof === 'object'
      && !Array.isArray(proof)
      && Object.keys(proof).every((key) => [
        'schema_version',
        'kind',
        'predecessor_launch_id',
        'predecessor_pid',
        'preview_port',
        'proxy_port',
        'sample_count',
        'samples',
      ].includes(key))
      && proof.schema_version === 1
      && proof.kind === LOCAL_PREVIEW_ZERO_WITNESS
      && proof.predecessor_launch_id === launch.launch_id
      && proof.predecessor_pid === launch.execution.target.pid
      && proof.preview_port === ports.preview_port
      && proof.proxy_port === ports.proxy_port
      && proof.sample_count === ZERO_WITNESS_SAMPLES
      && Array.isArray(proof.samples)
      && proof.samples.length === ZERO_WITNESS_SAMPLES,
    'RUNTIME_ZERO_WITNESS_INVALID',
    'LOCAL_PREVIEW_ZERO_WITNESS binding/shape 非法',
  );
  for (const sample of proof.samples) {
    assertControl(
      sample
        && typeof sample === 'object'
        && !Array.isArray(sample)
        && Object.keys(sample).length === 5
        && typeof sample.observed_at === 'string'
        && Number.isFinite(Date.parse(sample.observed_at))
        && sample.predecessor_pid_absent === true
        && sample.preview_listener_absent === true
        && sample.proxy_listener_absent === true
        && sample.matching_process_count === 0,
      'RUNTIME_ZERO_WITNESS_INVALID',
      'LOCAL_PREVIEW_ZERO_WITNESS sample 非法',
    );
  }
  return proof;
}

function runtimeLeaseSetBinding(root, manifestTask, state, launch) {
  const {
    rebuildResourcesReadOnlyUnlocked,
    verifyLaunchResourceRequirementsUnlocked,
  } = require('./resources');
  verifyLaunchResourceRequirementsUnlocked(
    root,
    manifestTask,
    launch,
    state,
    { historical: true, repairHeads: false },
  );
  const resources = rebuildResourcesReadOnlyUnlocked(root).state;
  const expectedOwner = {
    goal_id: launch.goal_id,
    task_id: launch.task_id,
    role: launch.role,
    thread_id: launch.thread.id,
    host_id: launch.thread.host_id || 'local',
  };
  const now = runtimeNowMilliseconds();
  const launchLeaseIds = [...launch.resource_leases].sort();
  const activeOwnerLeaseIds = Object.values(resources.leases)
    .filter((lease) => (
      lease.status === 'ACTIVE'
        && Object.entries(expectedOwner).every(
          ([field, value]) => lease.owner[field] === value,
        )
    ))
    .map((lease) => lease.lease_id)
    .sort();
  assertControl(
    hashObject(activeOwnerLeaseIds) === hashObject(launchLeaseIds),
    'RUNTIME_LEASE_SET_CHANGED',
    'runtime rotation 要求 predecessor launch 精确覆盖 worker 的完整 ACTIVE lease set',
  );
  const leases = launchLeaseIds
    .map((leaseId) => {
      const lease = resources.leases[leaseId];
      assertControl(lease, 'LEASE_NOT_FOUND', `找不到 lease: ${leaseId}`);
      assertControl(
        lease.status === 'ACTIVE'
          && Date.parse(lease.expires_at) > now,
        lease.status === 'ACTIVE' ? 'LEASE_EXPIRED' : 'LEASE_NOT_ACTIVE',
        `runtime rotation 要求 active、未过期 lease: ${leaseId}`,
      );
      for (const [field, value] of Object.entries(expectedOwner)) {
        assertControl(
          lease.owner[field] === value,
          'LEASE_OWNER_MISMATCH',
          `lease ${leaseId} owner.${field} 与 worker 不一致`,
        );
      }
      return {
        lease_id: lease.lease_id,
        resource: lease.resource,
        access: lease.access,
        revision: lease.revision,
        fencing_token: lease.fencing_token,
        owner: expectedOwner,
        expires_at: lease.expires_at,
      };
    });
  return {
    schema_version: 1,
    leases,
  };
}

function assertUnusedSuccessorLaunch(root, loaded, state, successorLaunchId) {
  safeId(successorLaunchId, 'successor launch_id');
  const used = [];
  for (const session of Object.values(state.sessions || {})) {
    if (session.launch_id) used.push(session.launch_id);
    for (const runtime of session.runtime_history || []) {
      if (runtime.launch_id) used.push(runtime.launch_id);
    }
  }
  for (const history of Object.values(state.session_history || {})) {
    for (const session of history || []) {
      if (session.launch_id) used.push(session.launch_id);
      for (const runtime of session.runtime_history || []) {
        if (runtime.launch_id) used.push(runtime.launch_id);
      }
    }
  }
  assertControl(
    !used.includes(successorLaunchId),
    'RUNTIME_SUCCESSOR_ID_REUSED',
    `successor launch_id ${successorLaunchId} 已使用`,
  );
  const launchFile = path.join(
    loaded.paths.dir,
    'launches',
    state.task_id,
    `${successorLaunchId}.json`,
  );
  assertControl(
    !fs.existsSync(launchFile),
    'RUNTIME_SUCCESSOR_ID_REUSED',
    `successor launch_id ${successorLaunchId} 已有持久化 manifest`,
  );
}

function runtimeRotationContext(root, loaded, state, manifestTask, binding) {
  assertControl(
    WORKER_PHASES[binding.role] === state.phase,
    'RUNTIME_ROTATION_PHASE_MISMATCH',
    `${binding.role} runtime 不能在 phase=${state.phase} 轮换`,
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
      && state.holds[0].hold_id === binding.hold_id,
    'RUNTIME_ROTATION_HOLD_REQUIRED',
    'runtime rotation 只允许在唯一、精确匹配的 ENV_IDENTITY_INCIDENT hard hold 下执行',
  );
  assertControl(
    runtimeRotationHoldEligible(
      root,
      state,
      loaded.manifest.goal_id,
    ),
    'RUNTIME_ROTATION_HOLD_NOT_ELIGIBLE',
    '该 ENV_IDENTITY_INCIDENT 不是可轮换的 runtime identity 故障；source checkpoint hold 禁止 runtime rotation',
  );
  const session = state.sessions[binding.role];
  assertControl(
    session
      && ['active', 'idle'].includes(session.status)
      && session.thread_id === binding.worker_thread_id
      && session.host_id === binding.worker_host_id
      && session.attempt === binding.worker_attempt,
    'RUNTIME_ROTATION_WORKER_MISMATCH',
    'runtime rotation worker identity 与 active session 不一致',
  );
  assertControl(
    Date.parse(session.lease_until) > runtimeNowMilliseconds(),
    'ACTOR_LEASE_EXPIRED',
    `${binding.role} worker lease 已过期`,
  );
  assertControl(
    !session.recovered_from || session.operational_scope === 'FULL',
    'RECOVERY_PROMOTION_REQUIRED',
    'recovered worker 尚未恢复 FULL scope',
  );
  const predecessorIncarnation = currentRuntimeIncarnation(session);
  assertControl(
    binding.predecessor_incarnation === predecessorIncarnation
      && binding.successor_incarnation === predecessorIncarnation + 1,
    'RUNTIME_INCARNATION_CAS_MISMATCH',
    `runtime incarnation 应为 ${predecessorIncarnation}->${predecessorIncarnation + 1}`,
  );
  assertControl(
    session.launch_id === binding.predecessor_launch_id
      && binding.successor_launch_id !== binding.predecessor_launch_id,
    'RUNTIME_LAUNCH_CAS_MISMATCH',
    'runtime predecessor/successor launch CAS 不匹配',
  );
  assertUnusedSuccessorLaunch(
    root,
    loaded,
    state,
    binding.successor_launch_id,
  );
  const predecessorFile = path.join(
    loaded.paths.dir,
    'launches',
    state.task_id,
    `${binding.predecessor_launch_id}.json`,
  );
  assertControl(
    fs.existsSync(predecessorFile),
    'RUNTIME_PREDECESSOR_LAUNCH_MISSING',
    `predecessor launch 不存在: ${binding.predecessor_launch_id}`,
  );
  const predecessor = validateLaunchManifest(
    readJson(predecessorFile, 'runtime rotation predecessor launch'),
  );
  const predecessorSha256 = hashFile(predecessorFile);
  assertControl(
    predecessorSha256 === normalizeHash(
      binding.predecessor_launch_sha256,
      'predecessor launch sha256',
    ),
    'RUNTIME_PREDECESSOR_LAUNCH_MISMATCH',
    'predecessor launch hash 与 CAS 不一致',
  );
  assertControl(
    predecessor.goal_id === loaded.manifest.goal_id
      && predecessor.task_id === state.task_id
      && predecessor.role === binding.role
      && predecessor.launch_id === session.launch_id
      && predecessor.thread.id === session.thread_id
      && predecessor.thread.host_id === session.host_id
      && predecessor.execution.task_nonce === session.task_nonce
      && predecessor.control_epoch === loaded.control.epoch
      && predecessor.state_revision === session.registered_state_revision
      && predecessor.packet.revision === state.packet.revision
      && normalizeHash(predecessor.packet.sha256) === state.packet.sha256,
    'RUNTIME_PREDECESSOR_LAUNCH_MISMATCH',
    'predecessor launch 与 Goal/session binding 不一致',
  );
  assertLaunchRuntimeIncarnation(session, predecessor);
  localPreviewPorts(predecessor);
  const leaseSet = runtimeLeaseSetBinding(
    root,
    manifestTask,
    state,
    predecessor,
  );
  return {
    session,
    predecessor,
    predecessorFile,
    predecessorSha256,
    leaseSet,
    leaseSetSha256: hashObject(leaseSet),
  };
}

function prepareRuntimeRotation(
  root,
  loaded,
  state,
  manifestTask,
  options,
) {
  const predecessorIncarnation = Number(options.predecessorIncarnation);
  const binding = {
    role: options.role,
    worker_thread_id: options.workerThreadId,
    worker_host_id: options.workerHostId,
    worker_attempt: Number(options.workerAttempt),
    predecessor_incarnation: predecessorIncarnation,
    successor_incarnation: predecessorIncarnation + 1,
    predecessor_launch_id: options.predecessorLaunchId,
    predecessor_launch_sha256: options.predecessorLaunchSha256,
    successor_launch_id: options.successorLaunchId,
    hold_id: options.holdId,
  };
  const context = runtimeRotationContext(
    root,
    loaded,
    state,
    manifestTask,
    binding,
  );
  const payload = {
    ...binding,
    runtime_nonce: runtimeNonce({
      goal_id: loaded.manifest.goal_id,
      task_id: state.task_id,
      event_id: options.eventId,
      ...binding,
    }),
    reason: options.reason,
    incident_ref: options.incidentRef,
    retirement_proof: buildLocalPreviewZeroWitness(context.predecessor),
    lease_set_sha256: context.leaseSetSha256,
  };
  return payload;
}

function validateRuntimeRotationBoundary(
  root,
  loaded,
  state,
  manifestTask,
  event,
) {
  const context = runtimeRotationContext(
    root,
    loaded,
    state,
    manifestTask,
    event.payload,
  );
  assertControl(
    event.actor.role === 'CAPTAIN',
    'RUNTIME_ROTATION_AUTHORITY',
    'runtime rotation 只能由 CAPTAIN 执行',
  );
  assertControl(
    event.payload.runtime_nonce === runtimeNonce({
      goal_id: event.goal_id,
      task_id: event.task_id,
      event_id: event.event_id,
      ...event.payload,
    }),
    'RUNTIME_NONCE_MISMATCH',
    'runtime nonce 与 event/worker/launch binding 不一致',
  );
  assertControl(
    normalizeHash(event.payload.lease_set_sha256)
      === context.leaseSetSha256,
    'RUNTIME_LEASE_SET_CHANGED',
    'runtime rotation lease owner/revision/fencing/expiry 已漂移',
  );
  validateLocalPreviewZeroWitness(
    context.predecessor,
    event.payload.retirement_proof,
  );
  buildLocalPreviewZeroWitness(context.predecessor, {
    sampleCount: 1,
    intervalMilliseconds: 0,
  });
  return context;
}

function assertLaunchRuntimeIncarnation(session, launch) {
  const incarnation = currentRuntimeIncarnation(session);
  if (!session || session.runtime_incarnation === undefined) {
    assertControl(
      launch.runtime_incarnation === undefined,
      'RUNTIME_INCARNATION_MISMATCH',
      'legacy session launch 禁止携带 runtime_incarnation',
    );
    return;
  }
  const expected = {
    epoch: incarnation,
    nonce: session.runtime_nonce,
    rotation_event_id: session.last_runtime_rotation
      && session.last_runtime_rotation.event_id,
  };
  assertControl(
    launch.runtime_incarnation
      && hashObject(launch.runtime_incarnation) === hashObject(expected),
    'RUNTIME_INCARNATION_MISMATCH',
    'launch runtime_incarnation 与 active session 不一致',
  );
}

function isRuntimeRotationHoldLane(state, session, launch = null) {
  if (
    !state
      || !session
      || !session.last_runtime_rotation
      || !Array.isArray(state.holds)
      || state.holds.length !== 1
  ) {
    return false;
  }
  const rotation = session.last_runtime_rotation;
  const hold = state.holds[0];
  if (
    hold.kind !== 'ENV_IDENTITY_INCIDENT'
      || hold.hard !== true
      || hold.hold_id !== rotation.hold_id
      || session.launch_id !== rotation.successor_launch_id
  ) {
    return false;
  }
  if (launch === null) return true;
  if (
    launch.launch_id !== rotation.successor_launch_id
      || !launch.runtime_incarnation
      || launch.runtime_incarnation.epoch
        !== rotation.successor_incarnation
      || launch.runtime_incarnation.nonce !== rotation.runtime_nonce
      || launch.runtime_incarnation.rotation_event_id
        !== rotation.event_id
  ) {
    return false;
  }
  return true;
}

function assertRotationSuccessorLaunch(
  predecessor,
  session,
  launch,
) {
  if (!session || !session.last_runtime_rotation) return;
  const rotation = session.last_runtime_rotation;
  assertControl(
    launch.launch_id === rotation.successor_launch_id
      && predecessor.launch_id === rotation.predecessor_launch_id
      && hashObject([...launch.resource_leases].sort())
        === hashObject([...predecessor.resource_leases].sort()),
    'RUNTIME_SUCCESSOR_BINDING_MISMATCH',
    'successor launch/lease set 与 rotation binding 不一致',
  );
  const oldPorts = localPreviewPorts(predecessor);
  const newPorts = localPreviewPorts(launch);
  assertControl(
    new Set([
      oldPorts.preview_port,
      oldPorts.proxy_port,
      newPorts.preview_port,
      newPorts.proxy_port,
    ]).size === 4,
    'RUNTIME_SUCCESSOR_PORT_REUSE',
    'successor PREVIEW 必须使用与 predecessor 完全不同的 web/proxy port group',
  );
  assertControl(
    launch.execution.target.pid !== predecessor.execution.target.pid
      && Date.parse(launch.execution.target.started_at)
        > Date.parse(predecessor.execution.target.started_at)
      && launch.execution.target.executable_path
        === predecessor.execution.target.executable_path
      && launch.runtime.node_version === predecessor.runtime.node_version
      && launch.runtime.pnpm_version === predecessor.runtime.pnpm_version,
    'RUNTIME_SUCCESSOR_IDENTITY_MISMATCH',
    'successor PREVIEW 必须是更新的 PID/start、同 executable/Node/pnpm runtime',
  );
  assertLaunchRuntimeIncarnation(session, launch);
}

function predecessorLaunchForRotation(loaded, state, session) {
  if (!session || !session.last_runtime_rotation) return null;
  const launchId = session.last_runtime_rotation.predecessor_launch_id;
  const file = path.join(
    loaded.paths.dir,
    'launches',
    state.task_id,
    `${launchId}.json`,
  );
  assertControl(
    fs.existsSync(file),
    'RUNTIME_PREDECESSOR_LAUNCH_MISSING',
    `rotation predecessor launch 不存在: ${launchId}`,
  );
  const launch = validateLaunchManifest(
    readJson(file, 'rotation predecessor launch'),
  );
  assertControl(
    hashFile(file) === session.last_runtime_rotation.predecessor_launch_sha256,
    'RUNTIME_PREDECESSOR_LAUNCH_MISMATCH',
    'rotation predecessor launch bytes 漂移',
  );
  return launch;
}

module.exports = {
  LOCAL_PREVIEW_ZERO_WITNESS,
  assertLaunchRuntimeIncarnation,
  assertRotationSuccessorLaunch,
  buildLocalPreviewZeroWitness,
  currentRuntimeIncarnation,
  deriveProxyPort,
  isRuntimeRotationHoldLane,
  localPreviewPorts,
  predecessorLaunchForRotation,
  prepareRuntimeRotation,
  runtimeNonce,
  runtimePreflightEvidenceId,
  validateLocalPreviewZeroWitness,
  validateRuntimeRotationBoundary,
};
