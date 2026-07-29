'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { fileURLToPath, pathToFileURL } = require('url');
const { execFileSync } = require('child_process');
const { ControlError, assertControl } = require('./errors');
const { actorSequenceKey } = require('./fsm');
const {
  authorizeSession,
  hashesEqual,
  readCapabilityFile,
} = require('./auth');
const { assertDevCandidateLineage } = require('./candidate-lineage');
const {
  evidenceAcceptanceAnchor,
  evidenceFile,
  inspectPreparedEvidenceBytesForRetryUnderLock,
  readExistingEvidenceForRetryUnderLock,
  readSemanticIngressPrepared,
  recordEvidenceBytesUnderLock,
  semanticIngressPreparedFile,
} = require('./evidence');
const {
  acceptEventUnderLock,
  assertFrozenInputs,
  loadGoalStateReadOnly,
  loadGoalStateUnlocked,
} = require('./goal');
const {
  preparedIdentityIncidentAuthorization,
  sealIdentityIncidentEventAuthority,
} = require('./incident-authority');
const { assertOperationalScope, sessionOperationalScope } = require('./operational-scope');
const {
  assertRequiredLiveBinding: assertRequiredLiveProbeObservationBinding,
} = require('./canary-observation-receipt');
const {
  assertLaunchRuntimeIncarnation,
  assertRotationSuccessorLaunch,
  isRuntimeRotationHoldLane,
  predecessorLaunchForRotation,
  runtimePreflightEvidenceId,
} = require('./runtime-incarnation');
const {
  assertSourceCheckpointAdvance,
  canonicalRuntimeLaunchFile,
} = require('./launch-source-checkpoint');
const {
  assertWorkerBootstrapCurrentWorktree,
  assertWorkerBootstrapLaunchBinding,
  requiredWorkerBootstrapBinding,
} = require('./worker-bootstrap-binding');
const {
  verifyLaunchResourceRequirements,
  verifyLaunchResourceRequirementsUnlocked,
} = require('./resources');
const {
  atomicCreate,
  atomicWriteJson,
  canonicalTransactionKey,
  ensureDir,
  isOddTransactionRetry,
  withLock,
} = require('./store');
const { trustedExecutableCandidates } = require('./gate-adapters');
const {
  controlRoot,
  assertIsolatedTestMode,
  git,
  hashFile,
  hashObject,
  normalizeHash,
  nowIso,
  readJson,
  repoRoot,
  safeId,
  sha256,
} = require('./util');
const { parsePullRequestUrl, validateLaunchManifest } = require('./validation');

const SYSTEM_EXECUTABLE_CANDIDATES = Object.freeze({
  ps: ['/bin/ps', '/usr/bin/ps'],
  lsof: ['/usr/sbin/lsof', '/usr/bin/lsof'],
});

function canonicalOrigin(value) {
  if (!value) return null;
  const normalized = String(value)
    .trim()
    .replace(/^git@([^:]+):/, 'https://$1/')
    .replace(/^ssh:\/\/git@([^/]+)\//, 'https://$1/')
    .replace(/\.git$/, '')
    .replace(/\/$/, '')
    .toLowerCase();
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new ControlError('ORIGIN_MISMATCH', 'origin URL 不是可规范化 URL');
  }
  assertControl(!parsed.username && !parsed.password, 'ORIGIN_CREDENTIAL_FORBIDDEN', 'origin URL 禁止内嵌凭证');
  return normalized;
}

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

function trustedPreflightExecutable(name) {
  const candidates = SYSTEM_EXECUTABLE_CANDIDATES[name]
    || trustedExecutableCandidates(name);
  for (const candidate of candidates) {
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) {
        return {
          executable: fs.realpathSync(candidate),
          pathDirectory: path.dirname(candidate),
        };
      }
    } catch {
      // Caller PATH is deliberately ignored; try the next fixed installation prefix.
    }
  }
  throw new ControlError('TRUSTED_EXECUTABLE_MISSING', `固定路径中找不到 ${name}`);
}

function trustedCommandOutput(name, args) {
  const resolved = trustedPreflightExecutable(name);
  const pathEntries = [
    resolved.pathDirectory,
    path.dirname(process.execPath),
    '/opt/homebrew/bin',
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
    '/usr/sbin',
    '/sbin',
  ];
  return execFileSync(resolved.executable, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: [...new Set(pathEntries)].join(path.delimiter),
      HOME: trustedHomeDirectory(),
      LANG: 'C',
      LC_ALL: 'C',
      TZ: 'UTC',
    },
  }).trim();
}

function commandVersion(command, args) {
  try {
    return trustedCommandOutput(command, args);
  } catch (error) {
    throw new ControlError('RUNTIME_VERSION_FAILED', `无法读取 ${command} 版本: ${String(error.stderr || error.message).trim()}`);
  }
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

function processIdentity(pid) {
  assertControl(processAlive(pid), 'TARGET_PROCESS_MISSING', `PID ${pid} 不存在`);
  let executable;
  if (process.platform === 'linux') {
    executable = fs.realpathSync(`/proc/${pid}/exe`);
  } else if (process.platform === 'darwin') {
    const output = trustedCommandOutput('lsof', ['-a', '-p', String(pid), '-d', 'txt', '-Fn']);
    const candidates = output.split('\n').filter((line) => line.startsWith('n/')).map((line) => line.slice(1));
    executable = candidates.find((candidate) => fs.existsSync(candidate));
  }
  if (!executable) {
    executable = trustedCommandOutput('ps', ['-p', String(pid), '-o', 'comm=']);
  }
  const startedRaw = trustedCommandOutput('ps', ['-p', String(pid), '-o', 'lstart=']);
  const command = trustedCommandOutput('ps', ['-p', String(pid), '-o', 'command=']);
  // trustedCommandOutput fixes TZ=UTC; ps lstart omits the zone, so make it explicit
  // instead of letting the caller process timezone reinterpret the timestamp.
  const startedAt = Date.parse(`${startedRaw} UTC`);
  assertControl(executable && Number.isFinite(startedAt), 'TARGET_PROCESS_IDENTITY_FAILED', `无法读取 PID ${pid} 的 executable/start time`);
  return { executable: fs.realpathSync(executable), startedAt, command };
}

function canonicalExisting(candidate, label) {
  assertControl(typeof candidate === 'string' && candidate.length > 0, 'PREFLIGHT_PATH_MISMATCH', `${label} 缺失`);
  try {
    return fs.realpathSync(candidate);
  } catch (error) {
    throw new ControlError('PREFLIGHT_PATH_MISMATCH', `${label} 不存在: ${error.message}`);
  }
}

function inspectLaunchRuntimeUnderLock(
  root,
  goalId,
  taskId,
  launch,
  {
    verifyAncestry = true,
    allowSourceCheckpoint = true,
  } = {},
) {
  const launchFile = canonicalRuntimeLaunchFile(
    root,
    goalId,
    taskId,
    launch.launch_id,
  );
  const launchBody = `${JSON.stringify(launch, null, 2)}\n`;
  const launchSha256 = `sha256:${sha256(launchBody)}`;
  if (fs.existsSync(launchFile)) {
    let existing;
    try {
      existing = validateLaunchManifest(
        readJson(launchFile, 'persisted launch manifest'),
      );
    } catch (error) {
      throw new ControlError(
        'LAUNCH_ID_CONFLICT',
        `launch_id ${launch.launch_id} canonical manifest 非法: ${error.code || error.message}`,
      );
    }
    const canonicalSha256 = hashFile(launchFile);
    const bytesMatch = canonicalSha256 === launchSha256;
    if (!bytesMatch) {
      assertControl(
        allowSourceCheckpoint,
        'LAUNCH_ID_CONFLICT',
        `launch_id ${launch.launch_id} legacy prepared request 不允许 source checkpoint`,
      );
      assertSourceCheckpointAdvance(existing, launch, { verifyAncestry });
    }
    return {
      launchFile,
      launchBody,
      launchSha256,
      canonicalSha256,
      exactRuntime: bytesMatch,
      created: false,
    };
  }
  return {
    launchFile,
    launchBody,
    launchSha256,
    canonicalSha256: null,
    exactRuntime: true,
    created: true,
  };
}

function persistLaunchRuntimeUnderLock(
  root,
  goalId,
  taskId,
  launch,
  options = {},
) {
  const inspected = inspectLaunchRuntimeUnderLock(
    root,
    goalId,
    taskId,
    launch,
    options,
  );
  if (!inspected.created) return inspected;
  ensureDir(path.dirname(inspected.launchFile));
  const created = atomicCreate(
    inspected.launchFile,
    inspected.launchBody,
  );
  if (!created) {
    return inspectLaunchRuntimeUnderLock(
      root,
      goalId,
      taskId,
      launch,
      options,
    );
  }
  return { ...inspected, created: true };
}

function preparedRuntimeLaunchAnchor(inspection) {
  if (inspection.created) {
    return {
      mode: 'CREATE_CANONICAL',
    };
  }
  return {
    mode: inspection.exactRuntime
      ? 'EXACT_CANONICAL'
      : 'SOURCE_CHECKPOINT',
    canonical_sha256: inspection.canonicalSha256,
  };
}

function materializeRuntimeLaunchUnderLock(
  root,
  launch,
  prepared,
) {
  const anchor = prepared.runtime_launch_anchor;
  if (anchor === undefined) {
    // Decoder versions before source-checkpoint refresh could only prepare a
    // first canonical launch or byte-exact retry. Preserve that recovery lane
    // without allowing a legacy artifact to acquire the new capability.
    return persistLaunchRuntimeUnderLock(
      root,
      launch.goal_id,
      launch.task_id,
      launch,
      {
        verifyAncestry: false,
        allowSourceCheckpoint: false,
      },
    );
  }
  assertControl(
    anchor
      && typeof anchor === 'object'
      && !Array.isArray(anchor)
      && ['CREATE_CANONICAL', 'EXACT_CANONICAL', 'SOURCE_CHECKPOINT']
        .includes(anchor.mode)
      && (
        anchor.mode === 'CREATE_CANONICAL'
          ? Object.keys(anchor).length === 1
          : Object.keys(anchor).length === 2
            && typeof anchor.canonical_sha256 === 'string'
            && /^sha256:[0-9a-f]{64}$/.test(anchor.canonical_sha256)
      ),
    'CORRUPT_STORE',
    `prepared preflight ${prepared.request.evidence_id} runtime launch anchor 非法`,
  );
  const launchFile = canonicalRuntimeLaunchFile(
    root,
    launch.goal_id,
    launch.task_id,
    launch.launch_id,
  );
  if (anchor.mode === 'CREATE_CANONICAL') {
    if (fs.existsSync(launchFile)) {
      assertControl(
        fs.statSync(launchFile).isFile()
          && !fs.lstatSync(launchFile).isSymbolicLink()
          && hashFile(launchFile)
            === `sha256:${sha256(`${JSON.stringify(launch, null, 2)}\n`)}`,
        'PREFLIGHT_RUNTIME_ANCHOR_DRIFT',
        `prepared preflight ${prepared.request.evidence_id} CREATE canonical residual 非 exact bytes`,
      );
    }
  } else {
    assertControl(
      fs.existsSync(launchFile)
        && fs.statSync(launchFile).isFile()
        && !fs.lstatSync(launchFile).isSymbolicLink()
        && hashFile(launchFile) === anchor.canonical_sha256,
      'PREFLIGHT_RUNTIME_ANCHOR_DRIFT',
      `prepared preflight ${prepared.request.evidence_id} canonical launch 已丢失或漂移`,
    );
  }
  const materialized = persistLaunchRuntimeUnderLock(
    root,
    launch.goal_id,
    launch.task_id,
    launch,
    {
      verifyAncestry: false,
      allowSourceCheckpoint: anchor.mode === 'SOURCE_CHECKPOINT',
    },
  );
  assertControl(
    (
      anchor.mode === 'CREATE_CANONICAL'
        && materialized.exactRuntime
    ) || (
      anchor.mode === 'EXACT_CANONICAL'
        && !materialized.created
        && materialized.exactRuntime
    ) || (
      anchor.mode === 'SOURCE_CHECKPOINT'
        && !materialized.created
        && !materialized.exactRuntime
    ),
    'PREFLIGHT_RUNTIME_ANCHOR_DRIFT',
    `prepared preflight ${prepared.request.evidence_id} runtime launch mode 漂移`,
  );
  return materialized;
}

function persistLaunchEvidenceUnderLock(root, goalId, taskId, evidenceId, launch) {
  const dir = path.join(root, 'goals', goalId, 'evidence-artifacts', taskId);
  ensureDir(dir);
  const file = path.join(dir, `${evidenceId}-launch.json`);
  if (fs.existsSync(file)) {
    assertControl(
      hashObject(readJson(file, 'persisted preflight launch artifact'))
        === hashObject(launch),
      'EVIDENCE_ID_CONFLICT',
      `preflight evidence id ${evidenceId} 已绑定不同 launch artifact`,
    );
    return { file, created: false };
  }
  atomicWriteJson(file, launch);
  return { file, created: true };
}

function preflightPreparedFile(root, goalId, taskId, evidenceId) {
  return path.join(
    root,
    'goals',
    goalId,
    'evidence-artifacts',
    taskId,
    `${evidenceId}-preflight-prepared.json`,
  );
}

function preflightRequest(launch, stage, evidenceId) {
  return {
    schema_version: 1,
    evidence_id: safeId(evidenceId, 'preflight evidence'),
    goal_id: launch.goal_id,
    task_id: launch.task_id,
    stage: stage || launch.role,
    launch_sha256: hashObject(launch),
  };
}

function sealPreparedPreflight(prepared) {
  return {
    ...prepared,
    prepared_sha256: hashObject(prepared),
  };
}

function validatePreparedPreflight(
  root,
  launch,
  stage,
  evidenceId,
) {
  const file = preflightPreparedFile(
    root,
    launch.goal_id,
    launch.task_id,
    evidenceId,
  );
  const prepared = readJson(file, 'prepared preflight artifact');
  const unsigned = { ...prepared };
  delete unsigned.prepared_sha256;
  assertControl(
    prepared.schema_version === 1
      && prepared.controller === 'goalctl'
      && prepared.adapter === 'PREFLIGHT_PREPARED'
      && hashObject(prepared.request)
        === hashObject(preflightRequest(launch, stage, evidenceId))
      && hashObject(prepared.launch) === hashObject(launch)
      && prepared.prepared_sha256 === hashObject(unsigned),
    'EVIDENCE_ID_CONFLICT',
    `preflight evidence id ${evidenceId} 已绑定不同或损坏的 prepared artifact`,
  );
  return { file, prepared };
}

function exactHistoricalPreflightSession(
  state,
  prepared,
  actorCapabilityFile,
) {
  const supplied = readCapabilityFile(actorCapabilityFile);
  const anchor = prepared.acceptance_anchor;
  const sessions = [
    ...Object.values(state.sessions || {}),
    ...Object.values(state.session_history || {}).flat(),
  ];
  const session = sessions.find((candidate) => (
    candidate
      && candidate.role === prepared.producer.role
      && candidate.thread_id === prepared.producer.thread_id
      && candidate.host_id === prepared.producer.host_id
      && candidate.attempt === anchor.producer.attempt
      && (candidate.launch_id || null) === anchor.producer.launch_id
      && candidate.capability_file === supplied.file
      && hashesEqual(candidate.capability_sha256, supplied.sha256)
  ));
  assertControl(
    session,
    'CAPABILITY_INVALID',
    'capability 不属于 prepared preflight 的原始历史 producer',
  );
  assertControl(
    hashObject(evidenceAcceptanceAnchor(
      {
        task_id: prepared.request.task_id,
        state_revision: prepared.state_revision,
        control_epoch: anchor.control_epoch,
        phase: anchor.phase,
        task_cycle: anchor.task_cycle,
      },
      session,
    )) === hashObject(anchor),
    'CORRUPT_STORE',
    'prepared preflight acceptance anchor 漂移',
  );
  return session;
}

function exactHistoricalLaunchSessionAt(
  state,
  launch,
  actorCapabilityFile,
  transactionStartedAt,
) {
  const supplied = readCapabilityFile(actorCapabilityFile);
  const startedAt = Date.parse(transactionStartedAt);
  assertControl(
    Number.isFinite(startedAt),
    'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
    'preflight pristine recovery 缺 transaction_started_at',
  );
  const sessions = [
    ...Object.values(state.sessions || {}),
    ...Object.values(state.session_history || {}).flat(),
  ];
  const session = sessions.find((candidate) => (
    candidate
      && candidate.role === launch.role
      && candidate.thread_id === launch.thread.id
      && candidate.host_id === (launch.thread.host_id || 'local')
      && candidate.launch_id === launch.launch_id
      && candidate.task_nonce === launch.execution.task_nonce
      && candidate.capability_file === supplied.file
      && hashesEqual(candidate.capability_sha256, supplied.sha256)
  ));
  assertControl(
    session,
    'CAPABILITY_INVALID',
    'capability 不属于 pristine preflight 的原始 launch session',
  );
  assertControl(
    ['active', 'idle'].includes(session.status),
    'ACTOR_UNUSABLE',
    `preflight actor status=${session.status}`,
  );
  assertControl(
    Date.parse(session.lease_until) > startedAt,
    'ACTOR_LEASE_EXPIRED',
    `preflight actor lease 在 transaction_started_at=${transactionStartedAt} 前已过期`,
  );
  return session;
}

function pristinePreflightAbortError() {
  return new ControlError(
    'STORE_PRISTINE_ABORT_RETRY',
    '旧 pristine preflight transaction 已安全关闭；必须按当前输入重新执行',
  );
}

function maybeFaultAfterPreflightGeneration(cwd, dependencies) {
  if (
    typeof dependencies.afterGenerationBeforeCallback === 'function'
  ) {
    assertIsolatedTestMode(cwd);
    dependencies.afterGenerationBeforeCallback();
  }
  const mode =
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_GENERATION;
  if (mode === undefined || mode === '') return;
  assertControl(
    ['1', 'throw', 'exit', 'sigkill'].includes(mode),
    'INVALID_TEST_FAULT',
    'GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_GENERATION '
      + '只能是 1/throw/exit/sigkill',
  );
  assertIsolatedTestMode(cwd);
  if (mode === 'sigkill') {
    process.kill(process.pid, 'SIGKILL');
    return;
  }
  if (mode === 'exit') process.exit(86);
  throw new ControlError(
    'TEST_FAULT_AFTER_PREFLIGHT_GENERATION',
    'injected preflight generation boundary failure',
  );
}

function preflightGenerationBoundaryFaultHook(cwd, dependencies) {
  const mode =
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_GENERATION;
  if (
    typeof dependencies.afterGenerationBeforeCallback !== 'function'
      && (mode === undefined || mode === '')
  ) {
    return undefined;
  }
  assertIsolatedTestMode(cwd);
  return () => maybeFaultAfterPreflightGeneration(cwd, dependencies);
}

function assertPreparedPreflightMaterializable(root, loaded, task, prepared) {
  assertControl(
    task.phase !== 'ARCHIVED',
    'TASK_TERMINAL',
    `task ${task.task_id} 已 ARCHIVED，不得 materialize prepared preflight evidence`,
  );
  const anchor = prepared.acceptance_anchor;
  assertControl(
    task.state_revision === prepared.state_revision
      && loaded.control.epoch === anchor.control_epoch
      && task.phase === anchor.phase
      && task.task_cycle === anchor.task_cycle
      && task.packet.revision === prepared.packet.revision
      && task.packet.sha256 === prepared.packet.sha256
      && task.base_head === prepared.base_head
      && (
        anchor.phase === 'DEV_ACTIVE'
          || task.full_head === prepared.full_head
      ),
    'TASK_OPERATION_DIVERGED',
    `prepared preflight ${prepared.request.evidence_id} 的 task/control anchor 已漂移`,
  );
  const { assertNoPendingTaskOperations } = require('./pending-operations');
  assertNoPendingTaskOperations(
    root,
    prepared.request.goal_id,
    prepared.request.task_id,
    {
      allowOperationKind: 'PREFLIGHT',
      allowOperationId: prepared.request.evidence_id,
      allowRequestSha256: hashObject(prepared.request),
    },
  );
}

function recordIdentityIncident(
  cwd,
  launch,
  failures,
  actorCapabilityFile,
  parentEvidenceId,
  dependencies = {},
) {
  const root = controlRoot(cwd);
  const stableEvidenceId = safeId(parentEvidenceId, 'preflight evidence');
  const incidentDigest = sha256(stableEvidenceId).slice(0, 32);
  const holdEvidenceId = `env-incident-${incidentDigest}`;
  const incidentEventId = `env-identity-hold-${incidentDigest}`;
  const holdId = `env-hold-${incidentDigest}`;
  const request = {
    schema_version: 1,
    goal_id: launch.goal_id,
    task_id: launch.task_id,
    parent_evidence_id: stableEvidenceId,
    launch_id: launch.launch_id,
    checks: failures,
  };
  const incidentArtifacts = (
    task,
    session,
    incidentEvent,
    eventAuthority,
  ) => {
    const source = {
      controller: 'goalctl',
      adapter: 'PREFLIGHT_IDENTITY_INCIDENT',
      request,
      incident_event: incidentEvent,
      event_authority: eventAuthority,
      created_at: eventAuthority.prepared_accepted_at,
    };
    const sourceBytes = Buffer.from(
      `${JSON.stringify(source, null, 2)}\n`,
      'utf8',
    );
    return {
      source,
      sourceBytes,
      holdEvidence: {
        schema_version: 1,
        evidence_id: holdEvidenceId,
        goal_id: launch.goal_id,
        task_id: launch.task_id,
        kind: 'HOLD_ASSERTION',
        stage: 'PREFLIGHT',
        status: 'BLOCKED',
        producer: {
          role: session.role,
          thread_id: session.thread_id,
          host_id: session.host_id,
        },
        state_revision: task.state_revision,
        packet: { revision: task.packet.revision, sha256: task.packet.sha256 },
        packet_sha256: task.packet.sha256,
        base_head: task.base_head,
        full_head: task.full_head,
        launch_id: launch.launch_id,
        created_at: eventAuthority.prepared_accepted_at,
        source_sha256: `sha256:${sha256(sourceBytes)}`,
        checks: failures,
      },
    };
  };
  let boundary = null;
  return withLock(root, () => {
    const {
      loaded,
      task,
      session,
      registered: existingRegistration,
      durableSource: existingSource,
      incidentEvent: preparedIncidentEvent,
      eventAuthority,
      artifacts,
    } = boundary;
    if (existingRegistration) {
      const accepted = acceptEventUnderLock(
        cwd,
        existingSource.incident_event,
        actorCapabilityFile,
        preparedIdentityIncidentAuthorization(
          holdEvidenceId,
          existingSource.event_authority,
        ),
      );
      return accepted.task.holds.find((hold) => (
        hold.kind === 'ENV_IDENTITY_INCIDENT'
          && hold.hold_id === holdId
          && hold.evidence
          && hold.evidence.evidence_id === holdEvidenceId
          && hold.evidence.kind === 'HOLD_ASSERTION'
          && hold.evidence.stage === 'PREFLIGHT'
      ));
    }
    const registered = recordEvidenceBytesUnderLock(
      cwd,
      artifacts.holdEvidence,
      artifacts.sourceBytes,
      actorCapabilityFile,
      true,
      {
        allowEvidenceId: holdEvidenceId,
        afterSemanticIngressPrepared:
          dependencies.afterIdentityIncidentIngressPrepared,
      },
    );
    if (!registered.idempotent) {
      maybeFaultAfterIdentityIncidentEvidenceIngress(dependencies);
    }
    const accepted = acceptEventUnderLock(
      cwd,
      preparedIncidentEvent,
      actorCapabilityFile,
      preparedIdentityIncidentAuthorization(
        holdEvidenceId,
        eventAuthority,
      ),
    );
    return accepted.task.holds.find((hold) => (
      hold.kind === 'ENV_IDENTITY_INCIDENT'
        && hold.hold_id === holdId
        && hold.evidence
        && hold.evidence.evidence_id === holdEvidenceId
        && hold.evidence.kind === 'HOLD_ASSERTION'
        && hold.evidence.stage === 'PREFLIGHT'
    ));
  }, {
    beforeGeneration: (transaction) => {
      const loaded = loadGoalStateUnlocked(
        root,
        launch.goal_id,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const task = loaded.snapshot.tasks[launch.task_id];
      assertControl(task, 'UNKNOWN_TASK', `未知 task ${launch.task_id}`);
      const registryFile = evidenceFile(
        root,
        launch.goal_id,
        launch.task_id,
        holdEvidenceId,
      );
      if (fs.existsSync(registryFile)) {
        const registered = readExistingEvidenceForRetryUnderLock(cwd, {
          goalId: launch.goal_id,
          taskId: launch.task_id,
          evidenceId: holdEvidenceId,
          actorCapabilityFile,
        });
        const durableSource = registered.evidence.uri.startsWith('file:')
          ? readJson(
            fileURLToPath(registered.evidence.uri),
            'preflight identity incident source',
          )
          : null;
        assertControl(
          registered.evidence.kind === 'HOLD_ASSERTION'
            && registered.evidence.stage === 'PREFLIGHT'
            && registered.evidence.status === 'BLOCKED'
            && registered.evidence.launch_id === launch.launch_id
            && hashObject(registered.evidence.checks) === hashObject(failures)
            && durableSource
            && durableSource.controller === 'goalctl'
            && durableSource.adapter === 'PREFLIGHT_IDENTITY_INCIDENT'
            && hashObject(durableSource.request) === hashObject(request)
            && durableSource.incident_event
            && durableSource.incident_event.event_id === incidentEventId
            && durableSource.incident_event.payload
            && durableSource.incident_event.payload.hold_id === holdId
            && durableSource.incident_event.payload.evidence_id === holdEvidenceId
            && durableSource.event_authority
            && durableSource.event_authority.evidence_id === holdEvidenceId
            && durableSource.event_authority.event_id === incidentEventId
            && durableSource.event_authority.event_input_sha256
              === hashObject(durableSource.incident_event),
          'EVIDENCE_ID_CONFLICT',
          `preflight evidence ${stableEvidenceId} 已绑定不同 identity incident`,
        );
        boundary = {
          loaded,
          task,
          session: registered.session,
          registered,
          durableSource,
          incidentEvent: durableSource.incident_event,
          eventAuthority: durableSource.event_authority,
        };
        return;
      }
      assertControl(
        task.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${task.task_id} 已 ARCHIVED，不得追加 identity incident`,
      );
      assertFrozenInputs(cwd, loaded, launch.task_id);
      const existing = task.holds.find(
        (hold) => (
          hold.kind === 'ENV_IDENTITY_INCIDENT'
            && hold.hold_id === holdId
            && hold.evidence
            && hold.evidence.evidence_id === holdEvidenceId
            && hold.evidence.kind === 'HOLD_ASSERTION'
            && hold.evidence.stage === 'PREFLIGHT'
        ),
      );
      assertControl(
        !existing,
        'CORRUPT_STORE',
        `identity hold ${holdId} 引用了缺失 evidence registry`,
      );
      const session = authorizeSession(task, actorCapabilityFile, {
        role: launch.role,
        threadId: launch.thread.id,
      });
      const actorKey = actorSequenceKey(session);
      const incidentEvent = {
        schema_version: 1,
        event_id: incidentEventId,
        goal_id: launch.goal_id,
        task_id: launch.task_id,
        type: 'ADD_HOLD',
        actor: {
          role: session.role,
          thread_id: session.thread_id,
          host_id: session.host_id,
        },
        actor_sequence: (task.actor_sequences[actorKey] || 0) + 1,
        expected_state_revision: task.state_revision,
        control_epoch: loaded.snapshot.control_epoch,
        packet: { revision: task.packet.revision, sha256: task.packet.sha256 },
        base_head: task.base_head,
        full_head: task.full_head,
        payload: {
          kind: 'ENV_IDENTITY_INCIDENT',
          hold_id: holdId,
          reason: failures
            .map((item) => `${item.name}:${item.detail}`)
            .join(' | ')
            .slice(0, 4000),
          evidence_id: holdEvidenceId,
        },
      };
      const eventAuthority = sealIdentityIncidentEventAuthority({
        event: incidentEvent,
        evidenceId: holdEvidenceId,
        session,
        task,
        controlEpoch: loaded.snapshot.control_epoch,
        preparedAcceptedAt: transaction.transaction_started_at,
      });
      const artifacts = incidentArtifacts(
        task,
        session,
        incidentEvent,
        eventAuthority,
      );
      const preparedFile = semanticIngressPreparedFile(
        root,
        launch.goal_id,
        launch.task_id,
        holdEvidenceId,
      );
      let preparedRegistration = null;
      if (fs.existsSync(preparedFile)) {
        preparedRegistration = inspectPreparedEvidenceBytesForRetryUnderLock(
          cwd,
          artifacts.holdEvidence,
          artifacts.sourceBytes,
          actorCapabilityFile,
          true,
        );
      }
      boundary = {
        loaded,
        task,
        session,
        registered: null,
        durableSource: null,
        incidentEvent,
        eventAuthority,
        artifacts,
        preparedRegistration,
      };
    },
    authorizeOddRecovery: () => Boolean(
      boundary
        && (boundary.registered || boundary.preparedRegistration),
    ),
    transactionKey: canonicalTransactionKey(
      'PREFLIGHT_IDENTITY',
      {
        goal_id: launch.goal_id,
        task_id: launch.task_id,
      },
      incidentEventId,
      hashObject(request),
    ),
    sameStableOperationMismatchCode: 'EVIDENCE_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      `preflight evidence ${stableEvidenceId} 已绑定不同 identity incident`,
  });
}

function recoverPendingIdentityIncident(
  cwd,
  launch,
  actorCapabilityFile,
  parentEvidenceId,
  dependencies,
) {
  const root = controlRoot(cwd);
  const generationFile = path.join(root, '.generation.json');
  if (!fs.existsSync(generationFile)) return null;
  const generation = readJson(
    generationFile,
    'preflight identity generation probe',
  );
  if (
    !Number.isSafeInteger(generation.generation)
      || generation.generation % 2 === 0
      || !generation.active_transaction
      || generation.active_transaction.kind !== 'PREFLIGHT_IDENTITY'
      || generation.active_transaction.scope.goal_id !== launch.goal_id
      || generation.active_transaction.scope.task_id !== launch.task_id
  ) {
    return null;
  }
  const stableEvidenceId = safeId(parentEvidenceId, 'preflight evidence');
  const incidentDigest = sha256(stableEvidenceId).slice(0, 32);
  const registryFile = evidenceFile(
    root,
    launch.goal_id,
    launch.task_id,
    `env-incident-${incidentDigest}`,
  );
  const preparedFile = semanticIngressPreparedFile(
    root,
    launch.goal_id,
    launch.task_id,
    `env-incident-${incidentDigest}`,
  );
  if (
    !fs.existsSync(registryFile)
      && !fs.existsSync(preparedFile)
  ) {
    throw new ControlError(
      'STORE_TRANSACTION_MISMATCH',
      `preflight evidence ${stableEvidenceId} 的 identity odd transaction 缺 durable registry/prepared witness`,
    );
  }
  const candidate = fs.existsSync(registryFile)
    ? readJson(
      registryFile,
      'pending preflight identity evidence',
    )
    : readSemanticIngressPrepared(preparedFile).evidence;
  assertControl(
    Array.isArray(candidate.checks)
      && candidate.checks.length > 0,
    'INVALID_EVIDENCE',
    `preflight evidence ${stableEvidenceId} identity incident 缺 checks`,
  );
  return recordIdentityIncident(
    cwd,
    launch,
    candidate.checks,
    actorCapabilityFile,
    stableEvidenceId,
    dependencies,
  );
}

function maybeFaultAfterIdentityIncidentEvidenceIngress(dependencies) {
  if (typeof dependencies.afterIdentityIncidentEvidenceIngress === 'function') {
    assertIsolatedTestMode();
    dependencies.afterIdentityIncidentEvidenceIngress();
  }
  if (
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_INCIDENT_EVIDENCE
      !== '1'
  ) {
    return;
  }
  assertIsolatedTestMode();
  throw new ControlError(
    'TEST_FAULT_AFTER_PREFLIGHT_INCIDENT_EVIDENCE',
    'injected failure after durable preflight incident evidence before ADD_HOLD',
  );
}

const IDENTITY_FAILURE_NAMES = new Set([
  'goal-task-binding',
  'packet-binding',
  'repository-identity',
  'origin-identity',
  'pull-request-binding',
  'registered-session',
  'environment-identity',
  'runtime-identity',
  'execution-target',
  'resource-leases',
  'launch-runtime-binding',
]);
const POLICY_FAILURE_CODES = new Set([
  'TASK_HELD',
  'CONTROL_RECONCILE_REQUIRED',
]);

function failureCodeFromCheck(check) {
  const match = typeof check.detail === 'string'
    ? /^([A-Z][A-Z0-9_]*):/.exec(check.detail)
    : null;
  return match ? match[1] : null;
}

function identityFailuresFromEvidence(evidence) {
  return (evidence.checks || []).filter((item) => (
    item.status === 'FAIL'
      && IDENTITY_FAILURE_NAMES.has(item.name)
      && !POLICY_FAILURE_CODES.has(failureCodeFromCheck(item))
  ));
}

function validatePreflightRetry(retried, launch, stage, evidenceId) {
  const evidence = retried.evidence;
  let persistedLaunch = null;
  try {
    persistedLaunch = validateLaunchManifest(
      readJson(
        fileURLToPath(new URL(evidence.launch_uri)),
        `preflight launch ${evidence.launch_id}`,
      ),
    );
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'MECHANICAL_ARTIFACT_INVALID',
      `preflight launch artifact 无法读取: ${error.message}`,
    );
  }
  assertControl(
    evidence.evidence_id === evidenceId
      && evidence.goal_id === launch.goal_id
      && evidence.task_id === launch.task_id
      && evidence.kind === 'PREFLIGHT'
      && evidence.stage === (stage || launch.role)
      && evidence.producer.role === launch.role
      && evidence.producer.thread_id === launch.thread.id
      && (evidence.producer.host_id || 'local')
        === (launch.thread.host_id || 'local')
      && evidence.launch_id === launch.launch_id
      && evidence.launch_sha256 === hashFile(fileURLToPath(new URL(evidence.launch_uri)))
      && hashObject(persistedLaunch) === hashObject(launch),
    'EVIDENCE_ID_CONFLICT',
    `preflight evidence id ${evidenceId} 已绑定不同 request`,
  );
  return evidence;
}

function maybeFaultAfterEvidenceIngress(kind, dependencies) {
  if (typeof dependencies.afterEvidenceIngress === 'function') {
    assertIsolatedTestMode();
    dependencies.afterEvidenceIngress();
  }
  const fault = process.env.GOAL_CONTROL_TEST_FAULT_AFTER_EVIDENCE_INGRESS;
  if (fault !== '1' && fault !== kind) return;
  assertIsolatedTestMode();
  throw new ControlError(
    'TEST_FAULT_AFTER_EVIDENCE_INGRESS',
    `injected response loss after durable ${kind} evidence`,
  );
}

function maybeFaultAfterPreparedPreflight(dependencies) {
  if (typeof dependencies.afterPreparedIngress === 'function') {
    assertIsolatedTestMode();
    dependencies.afterPreparedIngress();
  }
  const fault = process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED;
  if (fault !== '1') return;
  assertIsolatedTestMode();
  throw new ControlError(
    'TEST_FAULT_AFTER_PREFLIGHT_PREPARED',
    'injected failure after durable prepared preflight artifact',
  );
}

function maybeFaultAfterPreflightEvidenceBeforeIncident(dependencies) {
  if (typeof dependencies.afterPreflightEvidenceBeforeIncident === 'function') {
    assertIsolatedTestMode();
    dependencies.afterPreflightEvidenceBeforeIncident();
  }
  if (
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_EVIDENCE_BEFORE_INCIDENT
      !== '1'
  ) {
    return;
  }
  assertIsolatedTestMode();
  throw new ControlError(
    'TEST_FAULT_AFTER_PREFLIGHT_EVIDENCE_BEFORE_INCIDENT',
    'injected failure after durable preflight evidence before identity incident',
  );
}

function materializePreparedPreflightUnderLock(
  root,
  launch,
  evidenceId,
  prepared,
  idempotent,
) {
  let runtimeLaunch = null;
  if (prepared.status === 'PASS') {
    // The first commit attempt already checked lineage twice and sealed the
    // canonical runtime anchor. Exact materialization after response loss
    // must not depend on a still-present/live worktree or re-sample a
    // different canonical launch.
    runtimeLaunch = materializeRuntimeLaunchUnderLock(
      root,
      launch,
      prepared,
    );
  }
  const persistedLaunch = persistLaunchEvidenceUnderLock(
    root,
    launch.goal_id,
    launch.task_id,
    evidenceId,
    launch,
  );
  const boundLaunchFile = runtimeLaunch && runtimeLaunch.exactRuntime
    ? runtimeLaunch.launchFile
    : persistedLaunch.file;
  const registryFile = evidenceFile(
    root,
    launch.goal_id,
    launch.task_id,
    evidenceId,
  );
  assertControl(
    !fs.existsSync(registryFile),
    'EVIDENCE_ID_CONFLICT',
    `preflight evidence ${evidenceId} 已存在`,
  );
  const evidence = {
    schema_version: 1,
    evidence_id: evidenceId,
    goal_id: launch.goal_id,
    task_id: launch.task_id,
    kind: 'PREFLIGHT',
    stage: prepared.request.stage,
    status: prepared.status,
    producer: prepared.producer,
    state_revision: prepared.state_revision,
    packet: prepared.packet,
    packet_sha256: prepared.packet_sha256,
    base_head: prepared.base_head,
    full_head: prepared.full_head,
    launch_id: launch.launch_id,
    launch_sha256: hashFile(boundLaunchFile),
    attestation: { controller: 'goalctl', adapter: 'PREFLIGHT' },
    launch_uri: pathToFileURL(boundLaunchFile).href,
    ...(runtimeLaunch && !runtimeLaunch.exactRuntime
      ? {
        runtime_launch_sha256:
          prepared.runtime_launch_anchor.canonical_sha256,
        runtime_launch_uri: pathToFileURL(runtimeLaunch.launchFile).href,
      }
      : {}),
    created_at: prepared.created_at,
    uri: pathToFileURL(registryFile).href,
    checks: prepared.checks,
    acceptance_anchor: prepared.acceptance_anchor,
  };
  const sealed = {
    ...evidence,
    registry_sha256: hashObject(evidence),
  };
  ensureDir(path.dirname(registryFile));
  atomicWriteJson(registryFile, sealed);
  return { evidence: sealed, idempotent };
}

function recoverPreflightIngress(
  cwd,
  launch,
  stage,
  evidenceId,
  actorCapabilityFile,
) {
  const root = controlRoot(cwd);
  const registryFile = evidenceFile(
    root,
    launch.goal_id,
    launch.task_id,
    evidenceId,
  );
  const preparedFile = preflightPreparedFile(
    root,
    launch.goal_id,
    launch.task_id,
    evidenceId,
  );
  const launchArtifactFile = path.join(
    root,
    'goals',
    launch.goal_id,
    'evidence-artifacts',
    launch.task_id,
    `${evidenceId}-launch.json`,
  );
  if (
    !fs.existsSync(registryFile)
      && !fs.existsSync(preparedFile)
      && !fs.existsSync(launchArtifactFile)
  ) {
    return null;
  }
  let boundary = null;
  return withLock(root, () => {
    if (boundary.retry) {
      return {
        evidence: boundary.retry,
        idempotent: true,
      };
    }
    return materializePreparedPreflightUnderLock(
      root,
      launch,
      evidenceId,
      boundary.prepared,
      true,
    );
  }, {
    beforeGeneration: () => {
      const retried = readExistingEvidenceForRetryUnderLock(cwd, {
        goalId: launch.goal_id,
        taskId: launch.task_id,
        evidenceId,
        actorCapabilityFile,
      });
      if (retried) {
        boundary = {
          retry: validatePreflightRetry(
            retried,
            launch,
            stage,
            evidenceId,
          ),
        };
        return;
      }
      assertControl(
        fs.existsSync(preparedFile),
        'PREFLIGHT_PREPARED_ARTIFACT_MISSING',
        `preflight ${evidenceId} 有 launch artifact 但缺 prepared result；禁止重跑覆盖`,
      );
      const { prepared } = validatePreparedPreflight(
        root,
        launch,
        stage,
        evidenceId,
      );
      const loaded = loadGoalStateUnlocked(
        root,
        launch.goal_id,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const task = loaded.snapshot.tasks[launch.task_id];
      assertControl(task, 'UNKNOWN_TASK', `未知 task ${launch.task_id}`);
      exactHistoricalPreflightSession(
        task,
        prepared,
        actorCapabilityFile,
      );
      assertPreparedPreflightMaterializable(root, loaded, task, prepared);
      boundary = { prepared };
    },
    authorizeOddRecovery: () => Boolean(
      boundary && (boundary.retry || boundary.prepared),
    ),
    transactionKey: canonicalTransactionKey(
      'PREFLIGHT_INGRESS',
      {
        goal_id: launch.goal_id,
        task_id: launch.task_id,
      },
      evidenceId,
      hashObject(preflightRequest(launch, stage, evidenceId)),
    ),
    sameStableOperationMismatchCode: 'EVIDENCE_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      `preflight evidence ${evidenceId} 已绑定不同 request`,
  });
}

function abortPristinePreflightIngress(
  cwd,
  launch,
  stage,
  evidenceId,
  actorCapabilityFile,
) {
  const root = controlRoot(cwd);
  const preparedFile = preflightPreparedFile(
    root,
    launch.goal_id,
    launch.task_id,
    evidenceId,
  );
  const registryFile = evidenceFile(
    root,
    launch.goal_id,
    launch.task_id,
    evidenceId,
  );
  if (fs.existsSync(preparedFile) || fs.existsSync(registryFile)) return false;
  const generationFile = path.join(root, '.generation.json');
  if (!fs.existsSync(generationFile)) return false;
  const generation = readJson(
    generationFile,
    'preflight pristine generation probe',
  );
  if (
    !Number.isSafeInteger(generation.generation)
      || generation.generation % 2 === 0
      || !generation.active_transaction
      || generation.active_transaction.kind !== 'PREFLIGHT_INGRESS'
      || generation.active_transaction.scope.goal_id !== launch.goal_id
      || generation.active_transaction.scope.task_id !== launch.task_id
  ) {
    return false;
  }
  const transactionKey = canonicalTransactionKey(
    'PREFLIGHT_INGRESS',
    {
      goal_id: launch.goal_id,
      task_id: launch.task_id,
    },
    evidenceId,
    hashObject(preflightRequest(launch, stage, evidenceId)),
  );
  let authorized = false;
  try {
    withLock(root, () => {
      throw pristinePreflightAbortError();
    }, {
      beforeGeneration: (transaction) => {
        authorized = false;
        assertControl(
          isOddTransactionRetry(transaction.mode)
            && transaction.active_transaction
            && transaction.active_transaction.key_sha256
              === transactionKey.key_sha256,
          'STORE_TRANSACTION_MISMATCH',
          'pristine preflight transaction key 不匹配',
        );
        assertControl(
          typeof transaction.pre_write_vector_sha256 === 'string',
          'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
          'pristine preflight recovery 缺 v3 pre-write vector',
        );
        assertControl(
          transaction.pristine_payload_vector_sha256
            === transaction.pre_write_vector_sha256,
          'STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH',
          'pristine preflight payload 已漂移',
        );
        const loaded = loadGoalStateUnlocked(
          root,
          launch.goal_id,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const task = loaded.snapshot.tasks[launch.task_id];
        assertControl(task, 'UNKNOWN_TASK', `未知 task ${launch.task_id}`);
        exactHistoricalLaunchSessionAt(
          task,
          launch,
          actorCapabilityFile,
          transaction.transaction_started_at,
        );
        authorized = true;
      },
      authorizePristineOddRecovery: () => authorized,
      transactionKey,
      sameStableOperationMismatchCode: 'EVIDENCE_ID_CONFLICT',
      sameStableOperationMismatchMessage:
        `preflight evidence ${evidenceId} 已绑定不同 request`,
    });
  } catch (error) {
    if (error && error.code === 'STORE_PRISTINE_ABORT_RETRY') return true;
    throw error;
  }
  assertControl(
    false,
    'CORRUPT_STORE',
    'pristine preflight abort 未返回预期边界错误',
  );
}

function commitPreflightEvidence(
  cwd,
  {
    launchFile,
    launch,
    checkedLoaded,
    checkedTask,
    actorCapabilityFile,
    stage,
    status,
    evidenceId,
    checks,
    actualHead,
    dependencies,
  },
) {
  const root = controlRoot(cwd);
  let boundary = null;
  return withLock(root, () => {
    if (boundary.retry) {
      return {
        evidence: boundary.retry,
        idempotent: true,
      };
    }
    if (boundary.prepared) {
      return materializePreparedPreflightUnderLock(
        root,
        launch,
        evidenceId,
        boundary.prepared,
        true,
      );
    }
    const { loaded, task, session } = boundary;
    let committedStatus = status;
    let runtimeLaunchAnchor = null;
    const committedChecks = checks.map((check) => ({ ...check }));
    if (status === 'PASS') {
      try {
        const inspection = inspectLaunchRuntimeUnderLock(
          root,
          launch.goal_id,
          launch.task_id,
          launch,
        );
        runtimeLaunchAnchor = preparedRuntimeLaunchAnchor(inspection);
      } catch (error) {
        const failure = error instanceof ControlError
          ? error
          : new ControlError('LAUNCH_RUNTIME_PERSIST_FAILED', error.message);
        committedStatus = 'FAIL';
        committedChecks.push({
          name: 'launch-runtime-binding',
          status: 'FAIL',
          detail: `${failure.code}: ${failure.message}`,
        });
      }
    }
    const preparedDir = path.join(
      root,
      'goals',
      launch.goal_id,
      'evidence-artifacts',
      launch.task_id,
    );
    ensureDir(preparedDir);
    const preparedFile = preflightPreparedFile(
      root,
      launch.goal_id,
      launch.task_id,
      evidenceId,
    );
    assertControl(
      !fs.existsSync(preparedFile),
      'EVIDENCE_ID_CONFLICT',
      `preflight evidence ${evidenceId} prepared artifact 已存在`,
    );
    const prepared = sealPreparedPreflight({
      schema_version: 1,
      controller: 'goalctl',
      adapter: 'PREFLIGHT_PREPARED',
      request: preflightRequest(launch, stage, evidenceId),
      launch,
      producer: {
        role: launch.role,
        thread_id: launch.thread.id,
        host_id: launch.thread.host_id || 'local',
      },
      state_revision: task.state_revision,
      packet: { revision: task.packet.revision, sha256: task.packet.sha256 },
      packet_sha256: task.packet.sha256,
      base_head: task.base_head,
      full_head: actualHead,
      status: committedStatus,
      checks: committedChecks,
      created_at: boundary.acceptedAt,
      acceptance_anchor: evidenceAcceptanceAnchor(task, session),
      ...(committedStatus === 'PASS'
        ? { runtime_launch_anchor: runtimeLaunchAnchor }
        : {}),
    });
    atomicWriteJson(preparedFile, prepared);
    maybeFaultAfterPreparedPreflight(dependencies);
    return materializePreparedPreflightUnderLock(
      root,
      launch,
      evidenceId,
      prepared,
      false,
    );
  }, {
    beforeGeneration: () => {
      const retried = readExistingEvidenceForRetryUnderLock(cwd, {
        goalId: launch.goal_id,
        taskId: launch.task_id,
        evidenceId,
        actorCapabilityFile,
      });
      if (retried) {
        boundary = {
          retry: validatePreflightRetry(
            retried,
            launch,
            stage,
            evidenceId,
          ),
        };
        return;
      }
      const preparedFile = preflightPreparedFile(
        root,
        launch.goal_id,
        launch.task_id,
        evidenceId,
      );
      if (fs.existsSync(preparedFile)) {
        const { prepared } = validatePreparedPreflight(
          root,
          launch,
          stage,
          evidenceId,
        );
        const loaded = loadGoalStateUnlocked(
          root,
          launch.goal_id,
          {
            repairHeads: false,
            repairBootstrapConsumption: false,
          },
        );
        const task = loaded.snapshot.tasks[launch.task_id];
        assertControl(task, 'UNKNOWN_TASK', `未知 task ${launch.task_id}`);
        exactHistoricalPreflightSession(
          task,
          prepared,
          actorCapabilityFile,
        );
        assertPreparedPreflightMaterializable(
          root,
          loaded,
          task,
          prepared,
        );
        boundary = { prepared };
        return;
      }
      const loaded = loadGoalStateUnlocked(
        root,
        launch.goal_id,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      const task = loaded.snapshot.tasks[launch.task_id];
      assertControl(task, 'UNKNOWN_TASK', `未知 task ${launch.task_id}`);
      assertControl(
        task.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${task.task_id} 已 ARCHIVED，不得提交 preflight evidence`,
      );
      assertControl(
        loaded.control.eventCount === checkedLoaded.control.eventCount
          && loaded.control.lastEventHash === checkedLoaded.control.lastEventHash
          && loaded.control.epoch === checkedLoaded.control.epoch
          && task.state_revision === checkedTask.state_revision
          && loaded.lastEventHashes[launch.task_id]
            === checkedLoaded.lastEventHashes[launch.task_id],
        'STALE_STATE_REVISION',
        'preflight 检查期间控制状态已漂移；必须基于 fresh state 重跑',
      );
      const session = authorizeSession(task, actorCapabilityFile, {
        role: launch.role,
        threadId: launch.thread.id,
      });
      assertFrozenInputs(cwd, loaded, launch.task_id);
      const receiptAcceptedAt = nowIso();
      assertRequiredLiveProbeObservationBinding(
        loaded.manifest,
        session,
        'PREFLIGHT durable commit',
        Date.parse(receiptAcceptedAt),
        {
          repositoryHead: task.full_head,
          role: launch.role,
          taskId: launch.task_id,
        },
      );
      assertOperationalScope(task, launch.role, 'PREFLIGHT');
      assertControl(!task.recovery, 'RECOVERY_REQUIRED', 'preflight commit 前 recovery 状态已漂移');
      assertControl(
        !Array.isArray(task.recovery_backlog) || task.recovery_backlog.length === 0,
        'RECOVERY_BACKLOG_REQUIRED',
        'preflight commit 前 recovery backlog 已漂移',
      );

      const freshLaunch = validateLaunchManifest(
        readJson(launchFile, 'launch manifest'),
      );
      assertControl(
        hashObject(freshLaunch) === hashObject(launch),
        'LAUNCH_MANIFEST_DRIFT',
        'preflight 检查期间 launch manifest bytes 已漂移',
      );
      assertLaunchRuntimeIncarnation(session, freshLaunch);
      const rotationPredecessor = predecessorLaunchForRotation(
        loaded,
        task,
        session,
      );
      if (rotationPredecessor) {
        assertRotationSuccessorLaunch(
          rotationPredecessor,
          session,
          freshLaunch,
        );
      }

      if (status === 'PASS') {
        const worktree = repoRoot(cwd);
        const freshHead = git(worktree, ['rev-parse', 'HEAD']);
        const freshBranch = git(worktree, ['branch', '--show-current']);
        assertControl(
          freshHead === actualHead && freshHead === launch.repository.full_head,
          'STALE_HEAD',
          'preflight 检查期间 worktree HEAD 已漂移',
        );
        assertControl(
          freshBranch === launch.repository.branch,
          'BRANCH_MISMATCH',
          'preflight 检查期间 worktree branch 已漂移',
        );
        assertControl(
          git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '',
          'DIRTY_WORKTREE',
          'preflight 检查期间 worktree 已变脏',
        );
        if (task.phase === 'DEV_ACTIVE') {
          assertDevCandidateLineage(
            worktree,
            task,
            session,
            freshHead,
            { allowPreflightOnly: true },
          );
        } else {
          assertControl(
            task.full_head === freshHead,
            'STALE_HEAD',
            'preflight commit HEAD 与控制面不一致',
          );
        }
        const manifestTask = loaded.manifest.tasks.find(
          (candidate) => candidate.id === launch.task_id,
        );
        verifyLaunchResourceRequirementsUnlocked(
          root,
          manifestTask,
          launch,
          task,
          {
            repairHeads: false,
            allowRuntimeRotationHold: isRuntimeRotationHoldLane(
              task,
              session,
              freshLaunch,
            ),
          },
        );
      }
      boundary = {
        loaded,
        task,
        session,
        acceptedAt: receiptAcceptedAt,
      };
    },
    authorizeOddRecovery: () => Boolean(
      boundary && (boundary.retry || boundary.prepared),
    ),
    transactionKey: canonicalTransactionKey(
      'PREFLIGHT_INGRESS',
      {
        goal_id: launch.goal_id,
        task_id: launch.task_id,
      },
      evidenceId,
      hashObject(preflightRequest(launch, stage, evidenceId)),
    ),
    sameStableOperationMismatchCode: 'EVIDENCE_ID_CONFLICT',
    sameStableOperationMismatchMessage:
      `preflight evidence ${evidenceId} 已绑定不同 request`,
    afterGenerationBeforeCallback:
      preflightGenerationBoundaryFaultHook(cwd, dependencies),
  });
}

function runPreflight(cwd, options, dependencies = {}) {
  const launchFile = path.resolve(cwd, options.launchFile);
  const launch = validateLaunchManifest(readJson(launchFile, 'launch manifest'));
  const evidenceId = options.evidenceId
    ? safeId(options.evidenceId, 'preflight evidence')
    : runtimePreflightEvidenceId(launch);
  assertControl(!options.goalId || launch.goal_id === options.goalId, 'LAUNCH_GOAL_MISMATCH', 'launch goal 与 --goal 不一致');
  assertControl(!options.taskId || launch.task_id === options.taskId, 'LAUNCH_TASK_MISMATCH', 'launch task 与 --task 不一致');
  recoverPendingIdentityIncident(
    cwd,
    launch,
    options.actorCapabilityFile,
    evidenceId,
    dependencies,
  );
  abortPristinePreflightIngress(
    cwd,
    launch,
    options.stage,
    evidenceId,
    options.actorCapabilityFile,
  );
  const retried = recoverPreflightIngress(
    cwd,
    launch,
    options.stage,
    evidenceId,
    options.actorCapabilityFile,
  );
  if (retried) {
    const identityFailures = identityFailuresFromEvidence(retried.evidence);
    if (identityFailures.length > 0) {
      recordIdentityIncident(
        cwd,
        launch,
        identityFailures,
        options.actorCapabilityFile,
        evidenceId,
        dependencies,
      );
    }
    return retried.evidence;
  }

  const { assertNoPendingTaskOperations } = require('./pending-operations');
  assertNoPendingTaskOperations(
    controlRoot(cwd),
    launch.goal_id,
    launch.task_id,
  );
  const loaded = loadGoalStateReadOnly(cwd, launch.goal_id);
  const task = loaded.snapshot.tasks[launch.task_id];
  assertControl(task, 'UNKNOWN_TASK', `未知 task ${launch.task_id}`);
  const authorizedSession = authorizeSession(task, options.actorCapabilityFile, {
    role: launch.role,
    threadId: launch.thread.id,
  });
  const runtimeRotationHoldLane = isRuntimeRotationHoldLane(
    task,
    authorizedSession,
    launch,
  );
  assertFrozenInputs(cwd, loaded, launch.task_id);
  assertRequiredLiveProbeObservationBinding(
    loaded.manifest,
    authorizedSession,
    'PREFLIGHT',
    undefined,
    {
      repositoryHead: task.full_head,
      role: launch.role,
      taskId: launch.task_id,
    },
  );
  assertOperationalScope(task, launch.role, 'PREFLIGHT');
  assertControl(!task.recovery, 'RECOVERY_REQUIRED', `preflight 前必须先闭合 ${task.recovery && task.recovery.role} recovery`);
  assertControl(
    !Array.isArray(task.recovery_backlog) || task.recovery_backlog.length === 0,
    'RECOVERY_BACKLOG_REQUIRED',
    'preflight 前必须先清空 recovery backlog',
  );
  if (typeof dependencies.beforeLiveChecks === 'function') {
    assertIsolatedTestMode(cwd);
    dependencies.beforeLiveChecks();
  }
  const checks = [];

  function check(name, callback) {
    try {
      const detail = callback();
      checks.push({ name, status: 'PASS', ...(detail ? { detail: String(detail) } : {}) });
    } catch (error) {
      const failure = error instanceof ControlError ? error : new ControlError('PREFLIGHT_CHECK_FAILED', error.message);
      checks.push({ name, status: 'FAIL', detail: `${failure.code}: ${failure.message}` });
    }
  }

  const worktree = repoRoot(cwd);
  const actualHead = git(worktree, ['rev-parse', 'HEAD']);
  const actualBranch = git(worktree, ['branch', '--show-current']);
  const gitDir = fs.realpathSync(path.resolve(
    git(
      worktree,
      ['rev-parse', '--path-format=absolute', '--absolute-git-dir'],
    ),
  ));
  const commonGitDir = fs.realpathSync(path.resolve(
    git(
      worktree,
      ['rev-parse', '--path-format=absolute', '--git-common-dir'],
    ),
  ));
  const repositoryRoot = path.dirname(commonGitDir);
  const allowWorkerHeadAdvance =
    launch.role === 'DEV' && task.phase === 'DEV_ACTIVE';

  check('goal-task-binding', () => {
    assertControl(launch.control_epoch === loaded.snapshot.control_epoch, 'STALE_CONTROL_EPOCH', 'launch control_epoch 陈旧');
    assertControl(!task.reconcile_required, 'CONTROL_RECONCILE_REQUIRED', 'task 尚未 reconcile 当前 control epoch');
    assertControl(
      task.holds.length === 0 || runtimeRotationHoldLane,
      'TASK_HELD',
      `task 存在 hold: ${task.holds.map((hold) => hold.kind).join(',')}`,
    );
    assertControl(launch.repository.name_with_owner === loaded.manifest.repository.name_with_owner, 'REPOSITORY_MISMATCH', 'repository.name_with_owner 与 Goal manifest 不一致');
    assertControl(launch.repository.base_branch === loaded.manifest.repository.base_branch, 'BASE_BRANCH_MISMATCH', 'base branch 与 Goal manifest 不一致');
    assertControl(launch.repository.base_head === task.base_head, 'STALE_BASE_HEAD', 'launch base HEAD 与 task 不一致');
    return `${launch.goal_id}/${launch.task_id}`;
  });

  check('packet-binding', () => {
    assertControl(launch.packet.revision === task.packet.revision, 'STALE_PACKET', 'launch packet revision 陈旧');
    assertControl(normalizeHash(launch.packet.sha256) === task.packet.sha256, 'STALE_PACKET', 'launch packet hash 陈旧');
    assertControl(launch.packet.path === task.packet.path, 'STALE_PACKET', 'launch packet path 与当前 task 不一致');
    const packetFile = path.resolve(worktree, launch.packet.path);
    const canonicalPacket = canonicalExisting(packetFile, 'packet path');
    assertControl(canonicalPacket.startsWith(`${canonicalExisting(worktree, 'worktree')}${path.sep}`), 'PATH_OUTSIDE_REPO', 'packet path 逃逸 worktree');
    assertControl(hashFile(canonicalPacket) === task.packet.sha256, 'PACKET_HASH_MISMATCH', 'packet 文件内容与 hash 不一致');
    return task.packet.sha256;
  });

  check('repository-identity', () => {
    const canonicalRepositoryRoot = canonicalExisting(repositoryRoot, 'git common root');
    const canonicalWorktree = canonicalExisting(worktree, 'worktree');
    assertControl(
      launch.repository.root === canonicalRepositoryRoot
        && canonicalExisting(launch.repository.root, 'repository.root') === canonicalRepositoryRoot,
      'REPOSITORY_ROOT_MISMATCH',
      'launch repository.root 必须是当前 Git common root 的 canonical realpath',
    );
    assertControl(
      launch.repository.worktree === canonicalWorktree
        && canonicalExisting(launch.repository.worktree, 'repository.worktree') === canonicalWorktree,
      'WORKTREE_MISMATCH',
      'launch repository.worktree 必须是当前 worktree 的 canonical realpath',
    );
    assertControl(actualBranch === launch.repository.branch, 'BRANCH_MISMATCH', `当前 branch ${actualBranch} 与 launch 不一致`);
    assertControl(actualHead === launch.repository.full_head, 'STALE_HEAD', `当前 HEAD ${actualHead} 与 launch 不一致`);
    assertControl(task.phase === 'DEV_ACTIVE' || task.full_head === actualHead, 'STALE_HEAD', '控制面当前 HEAD 与 launch 不一致');
    if (task.phase === 'DEV_ACTIVE') {
      assertDevCandidateLineage(
        worktree,
        task,
        authorizedSession,
        actualHead,
        { allowPreflightOnly: true },
      );
    }
    if (launch.thread.cwd) {
      assertControl(
        launch.thread.cwd === canonicalWorktree
          && canonicalExisting(launch.thread.cwd, 'thread.cwd') === canonicalWorktree,
        'THREAD_CWD_MISMATCH',
        'thread cwd 必须是当前 worktree 的 canonical realpath',
      );
    }
    assertWorkerBootstrapCurrentWorktree(
      authorizedSession,
      {
        worktree: canonicalWorktree,
        git_dir: gitDir,
        common_git_dir: commonGitDir,
        head: actualHead,
        branch: actualBranch,
      },
      { allowHeadAdvance: allowWorkerHeadAdvance },
    );
    if (sessionOperationalScope(task, launch.role) === 'PREFLIGHT_ONLY') {
      const handoff = authorizedSession.recovery_handoff;
      assertControl(handoff, 'RECOVERY_HANDOFF_REQUIRED', 'recovery preflight 缺 source handoff');
      assertControl(canonicalExisting(handoff.destination_worktree, 'handoff destination') === canonicalExisting(worktree, 'worktree'), 'WORKTREE_MISMATCH', 'recovery preflight 未使用 sealed destination worktree');
      assertControl(handoff.destination_branch === actualBranch, 'BRANCH_MISMATCH', 'recovery preflight 未使用 sealed destination branch');
      assertControl(
        actualHead === handoff.import_commit,
        'STALE_HEAD',
        'PREFLIGHT_ONLY worktree HEAD 必须精确等于 sealed import checkpoint',
      );
    }
    return `${actualBranch}@${actualHead}`;
  });

  check('origin-identity', () => {
    const actualOrigin = git(worktree, ['remote', 'get-url', 'origin']);
    assertControl(canonicalOrigin(actualOrigin) === canonicalOrigin(launch.repository.origin_url), 'ORIGIN_MISMATCH', 'origin URL 与 launch 不一致');
    assertControl(canonicalOrigin(actualOrigin).endsWith(`/${loaded.manifest.repository.name_with_owner.toLowerCase()}`), 'ORIGIN_MISMATCH', 'origin URL 与 name_with_owner 不一致');
    return canonicalOrigin(actualOrigin);
  });

  check('pull-request-binding', () => {
    const requiresPullRequest = ['REVIEW', 'RECEIPT'].includes(launch.role);
    if (launch.role === 'DEV') {
      assertControl(
        !launch.pull_request,
        'PULL_REQUEST_UNEXPECTED',
        'DEV runtime launch 不绑定 PR；PR 由 DEV_READY 与 Full/AC evidence 绑定',
      );
      return task.pr ? 'DEV_READY_EVENT_BOUND' : 'N/A';
    }
    if (!task.pr && !launch.pull_request) {
      assertControl(!requiresPullRequest, 'PULL_REQUEST_REQUIRED', `${launch.role} launch 必须绑定当前 PR`);
      return 'N/A';
    }
    assertControl(task.pr && launch.pull_request, 'PULL_REQUEST_REQUIRED', 'launch 与控制面 PR binding 必须同时存在');
    const expected = parsePullRequestUrl(task.pr, loaded.manifest.repository.name_with_owner);
    assertControl(launch.pull_request.repository === expected.repository, 'PULL_REQUEST_MISMATCH', 'launch PR repository 不一致');
    assertControl(launch.pull_request.number === expected.number, 'PULL_REQUEST_MISMATCH', 'launch PR number 不一致');
    assertControl(launch.pull_request.base === expected.base, 'PULL_REQUEST_MISMATCH', 'launch PR base 不一致');
    assertControl(launch.pull_request.head === actualHead, 'PULL_REQUEST_MISMATCH', 'launch PR head 不是当前候选 HEAD');
    return expected.url;
  });

  check('registered-session', () => {
    const session = authorizedSession;
    requiredWorkerBootstrapBinding(
      loaded.manifest,
      session,
      launch.role,
    );
    assertControl(session.thread_id === launch.thread.id, 'WRONG_ACTOR_THREAD', 'launch thread 与登记 session 不一致');
    assertControl(session.host_id === (launch.thread.host_id || 'local'), 'WRONG_ACTOR_HOST', 'launch host 与登记 session 不一致');
    assertControl(!['lost', 'superseded', 'systemError'].includes(session.status), 'RECOVERY_REQUIRED', `session status=${session.status}`);
    assertControl(session.launch_id === launch.launch_id, 'LAUNCH_ID_MISMATCH', 'launch_id 与登记 session 不一致');
    assertControl(session.task_nonce === launch.execution.task_nonce, 'TASK_NONCE_MISMATCH', 'task_nonce 不是控制面签发值');
    assertControl(session.registered_control_epoch === launch.control_epoch, 'STALE_CONTROL_EPOCH', 'session 与 launch control epoch 不一致');
    assertControl(session.registered_state_revision === launch.state_revision, 'STALE_STATE_REVISION', 'launch state_revision 与 session registration 不一致');
    assertLaunchRuntimeIncarnation(session, launch);
    const rotationPredecessor = predecessorLaunchForRotation(
      loaded,
      task,
      session,
    );
    if (rotationPredecessor) {
      assertRotationSuccessorLaunch(
        rotationPredecessor,
        session,
        launch,
      );
    }
    assertWorkerBootstrapLaunchBinding(
      session,
      launch,
      { allowHeadAdvance: allowWorkerHeadAdvance },
    );
    return `${launch.role}:${session.host_id}:${session.thread_id}`;
  });

  check('environment-identity', () => {
    const declared = launch.execution;
    if (!declared.identity_probe) return 'N/A';
    const probeFile = canonicalExisting(declared.identity_probe.path, 'identity probe');
    assertControl(path.resolve(declared.identity_probe.path) === probeFile, 'IDENTITY_PROBE_PATH_NOT_CANONICAL', 'identity probe path 必须是 canonical realpath');
    assertControl(fs.statSync(probeFile).isFile(), 'IDENTITY_PROBE_INVALID', 'identity probe 必须是普通文件');
    assertControl(hashFile(probeFile) === normalizeHash(declared.identity_probe.sha256), 'IDENTITY_PROBE_HASH_MISMATCH', 'identity probe hash 不匹配');
    const probe = readJson(probeFile, 'identity probe');
    const allowedProbeKeys = ['schema_version', 'task_nonce', 'environment', 'domain', 'account_alias', 'tim_alias', 'write_mode', 'observed_at', 'source'];
    assertControl(probe && typeof probe === 'object' && !Array.isArray(probe), 'IDENTITY_PROBE_INVALID', 'identity probe 必须是对象');
    assertControl(Object.keys(probe).every((key) => allowedProbeKeys.includes(key)), 'IDENTITY_PROBE_INVALID', 'identity probe 含未知字段');
    assertControl(probe.schema_version === 1 && Number.isFinite(Date.parse(probe.observed_at)), 'IDENTITY_PROBE_INVALID', 'identity probe 版本或时间非法');
    for (const key of ['task_nonce', 'environment', 'domain', 'account_alias', 'tim_alias', 'write_mode']) {
      assertControl((probe[key] ?? null) === (declared[key] ?? null), 'ENV_IDENTITY_MISMATCH', `identity probe ${key} 与 launch 不一致`);
    }
    assertControl(
      typeof probe.source === 'string'
        && /^[a-z][a-z0-9-]{0,63}$/.test(probe.source),
      'IDENTITY_PROBE_INVALID',
      'identity probe source 非法',
    );
    if (probe.source === 'test-fixture') {
      assertIsolatedTestMode();
    } else {
      assertControl(
        false,
        'ENVIRONMENT_ATTESTATION_REQUIRES_BROKER',
        `${probe.source} JSON+hash 可由 launch actor 自签，不能证明 live environment/account/TIM；须由 controller/broker challenge-response adapter 生成 sealed attestation`,
      );
    }
    return `${probe.source}:${probe.environment}`;
  });

  check('runtime-identity', () => {
    assertControl(launch.runtime.node_version === process.version, 'NODE_VERSION_MISMATCH', `Node ${process.version} 与 launch ${launch.runtime.node_version} 不一致`);
    const pnpmVersion = commandVersion('pnpm', ['--version']);
    assertControl(launch.runtime.pnpm_version === pnpmVersion, 'PNPM_VERSION_MISMATCH', `pnpm ${pnpmVersion} 与 launch ${launch.runtime.pnpm_version} 不一致`);
    const lockfile = path.join(worktree, 'pnpm-lock.yaml');
    assertControl(hashFile(lockfile) === normalizeHash(launch.runtime.lockfile_sha256), 'LOCKFILE_MISMATCH', 'pnpm-lock.yaml hash 与 launch 不一致');
    return `node=${process.version}, pnpm=${pnpmVersion}`;
  });

  check('worktree-clean', () => {
    const status = git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']);
    assertControl(status === '', 'DIRTY_WORKTREE', `worktree 不干净: ${status.split('\n').slice(0, 5).join(', ')}`);
    git(worktree, ['diff', '--check', 'HEAD']);
    return 'clean';
  });

  check('execution-target', () => {
    const target = launch.execution.target;
    let canonicalExecutable = null;
    if (target.executable_path) {
      const executable = canonicalExisting(target.executable_path, 'execution target executable');
      assertControl(path.resolve(target.executable_path) === executable, 'EXECUTABLE_PATH_NOT_CANONICAL', 'executable_path 必须是 canonical realpath');
      assertControl(fs.statSync(executable).isFile(), 'TARGET_EXECUTABLE_INVALID', 'execution target executable 必须是普通文件');
      try {
        fs.accessSync(executable, fs.constants.X_OK);
      } catch {
        assertControl(false, 'TARGET_EXECUTABLE_INVALID', 'execution target executable 必须可执行');
      }
      canonicalExecutable = executable;
    }
    if (target.user_data_dir) {
      const userDataDirectory = canonicalExisting(target.user_data_dir, 'execution target user_data_dir');
      assertControl(path.resolve(target.user_data_dir) === userDataDirectory, 'TARGET_PROFILE_INVALID', 'execution target user_data_dir 必须是 canonical realpath');
      assertControl(fs.statSync(userDataDirectory).isDirectory(), 'TARGET_PROFILE_INVALID', 'execution target user_data_dir 必须是目录');
    }
    if (target.pid) {
      const observed = processIdentity(target.pid);
      assertControl(observed.executable === canonicalExecutable, 'TARGET_EXECUTABLE_MISMATCH', `PID ${target.pid} executable 与 launch 不一致`);
      assertControl(Math.abs(observed.startedAt - Date.parse(target.started_at)) < 2000, 'TARGET_START_TIME_MISMATCH', `PID ${target.pid} start time 与 launch 不一致`);
      if (target.user_data_dir) assertControl(observed.command.includes(target.user_data_dir), 'TARGET_PROFILE_MISMATCH', 'PID argv 未绑定 launch user_data_dir');
    }
    if (target.build_head) assertControl(target.build_head === actualHead, 'TARGET_BUILD_HEAD_MISMATCH', '候选 build HEAD 与当前 HEAD 不一致');
    return target.kind;
  });

  const leases = [];
  check('resource-leases', () => {
    const manifestTask = loaded.manifest.tasks.find((candidate) => candidate.id === launch.task_id);
    leases.push(...verifyLaunchResourceRequirements(
      cwd,
      manifestTask,
      launch,
      task,
      {
        allowRuntimeRotationHold: runtimeRotationHoldLane,
      },
    ));
    return leases.length ? leases.map((lease) => `${lease.resource}#${lease.fencing_token}`).join(', ') : 'N/A';
  });

  let status = checks.every((item) => item.status === 'PASS') ? 'PASS' : 'FAIL';
  if (typeof dependencies.beforeEvidenceCommit === 'function') {
    assertIsolatedTestMode();
    dependencies.beforeEvidenceCommit();
  }
  let committed;
  try {
    committed = commitPreflightEvidence(cwd, {
      launchFile,
      launch,
      checkedLoaded: loaded,
      checkedTask: task,
      actorCapabilityFile: options.actorCapabilityFile,
      stage: options.stage,
      status,
      evidenceId,
      checks,
      actualHead,
      dependencies,
    });
  } catch (error) {
    if (status === 'PASS' && ['LAUNCH_ID_CONFLICT', 'LAUNCH_RUNTIME_PERSIST_FAILED'].includes(error.code)) {
      const failure = error instanceof ControlError
        ? error
        : new ControlError('LAUNCH_RUNTIME_PERSIST_FAILED', error.message);
      recordIdentityIncident(cwd, launch, [{
        name: 'launch-runtime-binding',
        status: 'FAIL',
        detail: `${failure.code}: ${failure.message}`,
      }], options.actorCapabilityFile, evidenceId, dependencies);
    }
    throw error;
  }
  if (!committed.idempotent) {
    maybeFaultAfterPreflightEvidenceBeforeIncident(dependencies);
  }
  const identityFailures = identityFailuresFromEvidence(committed.evidence);
  if (identityFailures.length > 0) {
    recordIdentityIncident(
      cwd,
      launch,
      identityFailures,
      options.actorCapabilityFile,
      evidenceId,
      dependencies,
    );
  }
  if (!committed.idempotent) {
    maybeFaultAfterEvidenceIngress('PREFLIGHT', dependencies);
  }
  return committed.evidence;
}

module.exports = { runPreflight };
