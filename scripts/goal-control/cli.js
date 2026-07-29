'use strict';

const fs = require('fs');
const path = require('path');
const { authorizeSession } = require('./auth');
const { ControlError, assertControl } = require('./errors');
const {
  acceptEvent,
  actionsForTask,
  advanceControlEpoch,
  abandonMechanicalP1Commit,
  authorizeHistoricalActorCapability,
  doctor,
  initializeGoal,
  loadGoalState,
  loadGoalStateReadOnly,
  nextTasks,
  prepareProbeObservationChallenge,
  refreshProbeObservation,
  rebuildLedger,
  recoverExpiredForeman,
  registerRole,
  retryAcceptedCommandEvent,
  resumeCapsule,
} = require('./goal');
const { runPreflight } = require('./preflight');
const { publicEvidenceResult, recordEvidence } = require('./evidence');
const {
  runAcAuditEvidence,
  runFastEvidence,
  runFullCiEvidence,
} = require('./gate-adapters');
const {
  acquireLease,
  doctorResources,
  listLeases,
  reapLease,
  reinitializeZeroRuntimeLeases,
  recoverOwnerCapability,
  releaseLease,
  renewLease,
  verifyLease,
} = require('./resources');
const {
  optionalInteger,
  parseArgs,
  git,
  hashFile,
  normalizeHash,
  readJson,
  requireArg,
} = require('./util');
const {
  buildCodexShellAudit,
  buildRecoveryHandoffPayload,
  checkpointRecoverySource,
  exportRecoverySnapshot,
  exportRecoverySnapshotFromCodexRollout,
  importRecoverySnapshot,
  inspectCodexRolloutPatchEvents,
  publicRecoveryHandoffResult,
  writeCodexShellAuditOutput,
} = require('./source-handoff');
const {
  adoptStoreProtocol,
  rotateStoreProtocol,
} = require('./migration');
const { ROLES } = require('./validation');
const {
  createEventTemplate,
  createLaunchTemplate,
  helpDocument,
  revalidateSourceCheckpointHold,
  renderHelp,
  scaffoldGoal,
} = require('./usability');
const { mergePullRequest } = require('./github-merge');
const { preclaimIssues } = require('./preclaim-issues');
const { prepareRuntimeRotation } = require('./runtime-incarnation');
const { canaryPlan } = require('./canary-plan');
const {
  canaryBootstrapInspect,
  canaryBootstrapPlan,
  canaryBootstrapPrepare,
} = require('./canary-bootstrap');
const {
  assertNoSensitiveStringLeaves,
  containsSensitiveStringLeaves,
} = require('./canary-observation-receipt');

const ROLE_IDENTITY_COMMANDS = new Set([
  'prepare-probe-observation-challenge',
  'recover-expired-foreman',
  'refresh-probe-observation',
  'register-role',
]);
const ROLE_IDENTITY_CAPABILITY_OPTIONS = new Set([
  '--actor-capability-file',
  '--authorizer-capability-file',
  '--bootstrap-capability-file',
  '--foreman-recovery-capability-file',
  '--issuer-capability-file',
]);

function assertNoSensitiveRoleIdentityArguments(argv) {
  if (!ROLE_IDENTITY_COMMANDS.has(argv[0])) return;
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (
      index > 0
        && ROLE_IDENTITY_CAPABILITY_OPTIONS.has(argv[index - 1])
    ) {
      continue;
    }
    assertNoSensitiveStringLeaves(token);
  }
}

function readEvent(file) {
  if (file !== '-') return readJson(file, 'event file');
  const body = fs.readFileSync(0, 'utf8');
  try {
    return JSON.parse(body);
  } catch {
    throw new ControlError('INVALID_JSON', 'stdin event 不是合法 JSON');
  }
}

function validateRole(role) {
  assertControl(ROLES.includes(role), 'INVALID_ROLE', '未知 role');
  return role;
}

function assertStrictCommandArguments(command, args, argv, allowed) {
  const unknown = Object.keys(args).filter((key) => !allowed.has(key));
  const longOptions = argv
    .filter((token) => token.startsWith('--'))
    .map((token) => token.slice(2).replace(/-/g, '_'));
  const duplicates = longOptions.filter(
    (option, index) => longOptions.indexOf(option) !== index,
  );
  assertControl(
    args._.length === 1
      && unknown.length === 0
      && duplicates.length === 0,
    'INVALID_ARGUMENT',
    `${command} 拒绝未知、重复或非 canonical 参数`,
  );
}

function canaryBootstrapBindingOptions(args) {
  return {
    manifestFile: requireArg(args, 'manifest'),
    role: requireArg(args, 'role'),
    taskId: requireArg(args, 'task'),
    expectedHead: requireArg(args, 'expected_head'),
    operationId: requireArg(args, 'operation_id'),
    challenge: requireArg(args, 'challenge'),
    canaryPolicy: requireArg(args, 'canary_policy'),
    canaryPolicySha256: requireArg(args, 'canary_policy_sha256'),
  };
}

function goalCommand(
  argv,
  cwd = process.cwd(),
  invocationCwd = cwd,
) {
  assertNoSensitiveRoleIdentityArguments(argv);
  const args = parseArgs(argv);
  const command = args._[0];
  if (args.help || command === 'help') {
    const topic = command === 'help' ? (args._[1] || null) : (command || null);
    return { value: helpDocument('goal', topic), exitCode: 0, help: true };
  }
  assertControl(command, 'COMMAND_REQUIRED', '缺少 goalctl command');

  if (command === 'scaffold') {
    return {
      value: scaffoldGoal(cwd, {
        specFile: requireArg(args, 'spec'),
        outputDir: args.output_dir || null,
        allowEnforce: args.allow_enforce === true,
      }),
      exitCode: 0,
    };
  }
  if (command === 'init') {
    return { value: initializeGoal(cwd, requireArg(args, 'manifest')), exitCode: 0 };
  }
  if (command === 'prepare-probe-observation-challenge') {
    const allowed = new Set([
      '_',
      'json',
      'goal',
      'task',
      'role',
      'event_id',
      'canary_plan_sha256',
      'issuer_capability_file',
      'identity_receipt',
      'identity_receipt_sha256',
      'worker_bootstrap_receipt',
      'worker_bootstrap_receipt_sha256',
      'worker_bootstrap_operation_id',
      'worker_bootstrap_challenge',
      'worker_bootstrap_identity_plan_sha256',
      'worker_worktree',
    ]);
    const unknown = Object.keys(args).filter((key) => !allowed.has(key));
    assertControl(
      args._.length === 1 && unknown.length === 0,
      'INVALID_ARGUMENT',
      'prepare-probe-observation-challenge 拒绝 caller identity/未知参数',
    );
    return {
      value: prepareProbeObservationChallenge(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        role: validateRole(requireArg(args, 'role')),
        eventId: requireArg(args, 'event_id'),
        planSha256: requireArg(args, 'canary_plan_sha256'),
        issuerCapabilityFile:
          requireArg(args, 'issuer_capability_file'),
        identityReceipt: requireArg(
          args,
          'identity_receipt',
        ),
        identityReceiptSha256: requireArg(
          args,
          'identity_receipt_sha256',
        ),
        workerBootstrapReceipt:
          args.worker_bootstrap_receipt === undefined
            ? null
            : requireArg(args, 'worker_bootstrap_receipt'),
        workerBootstrapReceiptSha256:
          args.worker_bootstrap_receipt_sha256 === undefined
            ? null
            : requireArg(args, 'worker_bootstrap_receipt_sha256'),
        workerBootstrapOperationId:
          args.worker_bootstrap_operation_id === undefined
            ? null
            : requireArg(args, 'worker_bootstrap_operation_id'),
        workerBootstrapChallenge:
          args.worker_bootstrap_challenge === undefined
            ? null
            : requireArg(args, 'worker_bootstrap_challenge'),
        workerBootstrapIdentityPlanSha256:
          args.worker_bootstrap_identity_plan_sha256 === undefined
            ? null
            : requireArg(
              args,
              'worker_bootstrap_identity_plan_sha256',
            ),
        workerWorktree: args.worker_worktree === undefined
          ? null
          : requireArg(args, 'worker_worktree'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'canary-plan') {
    const allowed = new Set([
      '_',
      'json',
      'repository_worktree',
      'manifest',
      'role',
      'task',
      'browser_canary_receipt',
      'worker_bootstrap_receipt',
      'worker_bootstrap_receipt_sha256',
      'worker_bootstrap_operation_id',
      'worker_bootstrap_challenge',
      'worker_bootstrap_identity_plan_sha256',
      'worker_thread',
      'worker_host',
    ]);
    assertStrictCommandArguments(command, args, argv, allowed);
    return {
      value: canaryPlan(cwd, {
        manifestFile: requireArg(args, 'manifest'),
        role: requireArg(args, 'role'),
        taskId: args.task === undefined ? null : requireArg(args, 'task'),
        browserCanaryReceipt: args.browser_canary_receipt === undefined
          ? null
          : requireArg(args, 'browser_canary_receipt'),
        workerBootstrapReceipt:
          args.worker_bootstrap_receipt === undefined
            ? null
            : requireArg(args, 'worker_bootstrap_receipt'),
        workerBootstrapReceiptSha256:
          args.worker_bootstrap_receipt_sha256 === undefined
            ? null
            : requireArg(args, 'worker_bootstrap_receipt_sha256'),
        workerBootstrapOperationId:
          args.worker_bootstrap_operation_id === undefined
            ? null
            : requireArg(args, 'worker_bootstrap_operation_id'),
        workerBootstrapChallenge:
          args.worker_bootstrap_challenge === undefined
            ? null
            : requireArg(args, 'worker_bootstrap_challenge'),
        workerBootstrapIdentityPlanSha256:
          args.worker_bootstrap_identity_plan_sha256 === undefined
            ? null
            : requireArg(
              args,
              'worker_bootstrap_identity_plan_sha256',
            ),
        workerThread: args.worker_thread === undefined
          ? null
          : requireArg(args, 'worker_thread'),
        workerHost: args.worker_host === undefined
          ? null
          : requireArg(args, 'worker_host'),
      }, {}, invocationCwd),
      exitCode: 0,
    };
  }
  if (command === 'canary-bootstrap-plan') {
    const allowed = new Set([
      '_',
      'json',
      'repository_worktree',
      'manifest',
      'role',
      'task',
      'expected_head',
      'operation_id',
      'challenge',
      'canary_policy',
      'canary_policy_sha256',
    ]);
    assertStrictCommandArguments(command, args, argv, allowed);
    requireArg(args, 'repository_worktree');
    return {
      value: canaryBootstrapPlan(
        cwd,
        canaryBootstrapBindingOptions(args),
      ),
      exitCode: 0,
    };
  }
  if (command === 'canary-bootstrap-inspect') {
    const allowed = new Set([
      '_',
      'json',
      'goal_worktree',
      'manifest',
      'role',
      'task',
      'expected_head',
      'operation_id',
      'challenge',
      'canary_policy',
      'canary_policy_sha256',
      'expected_identity_plan_sha256',
      'expected_identity_binding_sha256',
      'worker_thread',
      'worker_host',
    ]);
    assertStrictCommandArguments(command, args, argv, allowed);
    return {
      value: canaryBootstrapInspect(cwd, {
        ...canaryBootstrapBindingOptions(args),
        goalWorktree: requireArg(args, 'goal_worktree'),
        expectedIdentityPlanSha256:
          args.expected_identity_plan_sha256 === undefined
            ? null
            : requireArg(args, 'expected_identity_plan_sha256'),
        expectedIdentityBindingSha256:
          args.expected_identity_binding_sha256 === undefined
            ? null
            : requireArg(args, 'expected_identity_binding_sha256'),
        workerThread: requireArg(args, 'worker_thread'),
        workerHost: requireArg(args, 'worker_host'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'canary-bootstrap-prepare') {
    const allowed = new Set([
      '_',
      'json',
      'repository_worktree',
      'manifest',
      'role',
      'task',
      'expected_head',
      'operation_id',
      'challenge',
      'canary_policy',
      'canary_policy_sha256',
      'expected_identity_plan_sha256',
      'expected_observation_sha256',
      'worker_thread',
      'worker_host',
      'worker_worktree',
    ]);
    assertStrictCommandArguments(command, args, argv, allowed);
    requireArg(args, 'repository_worktree');
    return {
      value: canaryBootstrapPrepare(cwd, {
        ...canaryBootstrapBindingOptions(args),
        expectedIdentityPlanSha256: requireArg(
          args,
          'expected_identity_plan_sha256',
        ),
        expectedObservationSha256: requireArg(
          args,
          'expected_observation_sha256',
        ),
        workerThread: requireArg(args, 'worker_thread'),
        workerHost: requireArg(args, 'worker_host'),
        workerWorktree: requireArg(args, 'worker_worktree'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'preclaim-issues') {
    return {
      value: preclaimIssues(cwd, {
        manifestFile: requireArg(args, 'manifest'),
        operationId: requireArg(args, 'operation_id'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'adopt-store-protocol') {
    return {
      value: adoptStoreProtocol(cwd, {
        incidentRef: args.incident_ref,
        oldControllerDrainAcknowledgment: args.acknowledge_old_controller_drained,
        goalWorktreesFile: args.goal_worktrees_file || null,
      }),
      exitCode: 0,
    };
  }
  if (command === 'rotate-store-protocol') {
    const allowed = new Set([
      '_',
      'json',
      'repository_worktree',
      'rotation_id',
      'predecessor_controller_worktree',
      'goal_worktrees_file',
      'expected_predecessor_seal_sha256',
      'incident_ref',
      'acknowledge_old_controller_drained',
    ]);
    const unknown = Object.keys(args).filter((key) => !allowed.has(key));
    const longOptions = argv
      .filter((token) => token.startsWith('--'))
      .map((token) => token.slice(2).replace(/-/g, '_'));
    const duplicates = longOptions.filter(
      (option, index) => longOptions.indexOf(option) !== index,
    );
    assertControl(
      args._.length === 1
        && unknown.length === 0
        && duplicates.length === 0,
      'INVALID_ARGUMENT',
      `rotate-store-protocol 拒绝未知、重复或非 canonical 参数${
        unknown.length > 0
          ? `: ${unknown.map((key) => `--${key.replace(/_/g, '-')}`).join(', ')}`
          : duplicates.length > 0
            ? `: duplicate --${duplicates[0].replace(/_/g, '-')}`
            : ''
      }`,
    );
    return {
      value: rotateStoreProtocol(cwd, {
        rotationId: requireArg(args, 'rotation_id'),
        predecessorControllerWorktree: requireArg(
          args,
          'predecessor_controller_worktree',
        ),
        goalWorktreesFile: args.goal_worktrees_file === undefined
          ? null
          : requireArg(args, 'goal_worktrees_file'),
        expectedPredecessorSealSha256: requireArg(
          args,
          'expected_predecessor_seal_sha256',
        ),
        incidentRef: requireArg(args, 'incident_ref'),
        oldControllerDrainAcknowledgment: requireArg(
          args,
          'acknowledge_old_controller_drained',
        ),
      }),
      exitCode: 0,
    };
  }
  if (command === 'event-template') {
    const role = validateRole(requireArg(args, 'role'));
    return {
      value: createEventTemplate(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        role,
        threadId: requireArg(args, 'thread'),
        type: requireArg(args, 'type'),
        actorCapabilityFile: requireArg(args, 'actor_capability_file'),
        payloadFile: args.payload_file || null,
        fullHead: args.full_head || null,
        eventId: args.event_id || null,
      }),
      exitCode: 0,
    };
  }
  if (command === 'event') {
    const event = readEvent(requireArg(args, 'file'));
    const goalId = requireArg(args, 'goal');
    assertControl(event.goal_id === goalId, 'EVENT_GOAL_MISMATCH', 'event.goal_id 与 --goal 不一致');
    return {
      value: acceptEvent(
        cwd,
        event,
        args.actor_capability_file || null,
        { foremanCapabilityFile: args.foreman_capability_file || null },
      ),
      exitCode: 0,
    };
  }
  if (command === 'p1-abandon-commit') {
    return {
      value: abandonMechanicalP1Commit(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        preparedEventId: requireArg(args, 'prepared_event_id'),
        eventId: requireArg(args, 'event_id'),
        expectedIntentSha256: requireArg(
          args,
          'expected_intent_sha256',
        ),
        expectedCommitRef: requireArg(args, 'expected_commit_ref'),
        expectedRefHead: requireArg(args, 'expected_ref_head'),
        threadId: requireArg(args, 'thread'),
        reason: requireArg(args, 'reason'),
        incidentRef: requireArg(args, 'incident_ref'),
        foremanCapabilityFile: requireArg(
          args,
          'foreman_capability_file',
        ),
      }),
      exitCode: 0,
    };
  }
  if (command === 'register-role') {
    const role = validateRole(requireArg(args, 'role'));
    const value = registerRole(cwd, {
      goalId: requireArg(args, 'goal'),
      taskId: requireArg(args, 'task'),
      role,
      threadId: requireArg(args, 'thread'),
      hostId: args.host || 'local',
      attempt: optionalInteger(args.attempt, 'attempt', 1),
      leaseMs: optionalInteger(args.lease_ms, 'lease-ms', 3600000),
      status: args.status || 'active',
      launchId: args.launch_id || null,
      eventId: args.event_id || null,
      actorCapabilityFile: args.actor_capability_file || null,
      bootstrapCapabilityFile: args.bootstrap_capability_file || null,
      foremanRecoveryCapabilityFile: args.foreman_recovery_capability_file || null,
      authorizerCapabilityFile: args.authorizer_capability_file || null,
      authorizerThreadId: args.authorizer_thread || null,
      workerBootstrapReceipt:
        args.worker_bootstrap_receipt || null,
      workerBootstrapReceiptSha256:
        args.worker_bootstrap_receipt_sha256 || null,
      workerBootstrapOperationId:
        args.worker_bootstrap_operation_id || null,
      workerBootstrapChallenge:
        args.worker_bootstrap_challenge || null,
      workerBootstrapIdentityPlanSha256:
        args.worker_bootstrap_identity_plan_sha256 || null,
      probeObservationReceipt:
        args.probe_observation_receipt || null,
      probeObservationReceiptSha256:
        args.probe_observation_receipt_sha256 || null,
      probeObservationPlan:
        args.probe_observation_plan || null,
      probeObservationPlanSha256:
        args.probe_observation_plan_sha256 || null,
      probeObservationStableId:
        args.probe_observation_stable_id || null,
      probeObservationChallenge:
        args.probe_observation_challenge || null,
      invocationCwd,
    });
    return { value, exitCode: 0 };
  }
  if (command === 'refresh-probe-observation') {
    const role = validateRole(requireArg(args, 'role'));
    return {
      value: refreshProbeObservation(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        role,
        threadId: requireArg(args, 'thread'),
        hostId: args.host || 'local',
        attempt: optionalInteger(
          requireArg(args, 'attempt'),
          'attempt',
        ),
        expectedStateRevision: optionalInteger(
          requireArg(args, 'expected_state_revision'),
          'expected-state-revision',
        ),
        expectedBindingSha256: requireArg(
          args,
          'expected_binding_sha256',
        ),
        eventId: requireArg(args, 'event_id'),
        actorCapabilityFile: requireArg(
          args,
          'actor_capability_file',
        ),
        probeObservationReceipt: requireArg(
          args,
          'probe_observation_receipt',
        ),
        probeObservationReceiptSha256: requireArg(
          args,
          'probe_observation_receipt_sha256',
        ),
        probeObservationPlan: requireArg(
          args,
          'probe_observation_plan',
        ),
        probeObservationPlanSha256: requireArg(
          args,
          'probe_observation_plan_sha256',
        ),
        probeObservationStableId: requireArg(
          args,
          'probe_observation_stable_id',
        ),
        probeObservationChallenge: requireArg(
          args,
          'probe_observation_challenge',
        ),
        invocationCwd,
      }),
      exitCode: 0,
    };
  }
  if (command === 'recover-expired-foreman') {
    const value = recoverExpiredForeman(cwd, {
      goalId: requireArg(args, 'goal'),
      taskId: requireArg(args, 'task'),
      threadId: requireArg(args, 'thread'),
      hostId: requireArg(args, 'host'),
      attempt: optionalInteger(requireArg(args, 'attempt'), 'attempt'),
      leaseMs: optionalInteger(requireArg(args, 'lease_ms'), 'lease-ms'),
      expectedGoalScopeSha256: requireArg(args, 'expected_goal_scope_sha256'),
      expectedControlEpoch: args.expected_control_epoch === undefined
        ? undefined
        : optionalInteger(args.expected_control_epoch, 'expected-control-epoch'),
      expectedStateRevision: args.expected_state_revision === undefined
        ? undefined
        : optionalInteger(args.expected_state_revision, 'expected-state-revision'),
      expectedEventHead: args.expected_event_head,
      expectedPacketRevision: args.expected_packet_revision === undefined
        ? undefined
        : optionalInteger(args.expected_packet_revision, 'expected-packet-revision'),
      expectedPacketSha256: args.expected_packet_sha256,
      expectedFullHead: args.expected_full_head,
      expectedForemanThreadId: args.expected_foreman_thread,
      expectedForemanHostId: args.expected_foreman_host,
      expectedForemanAttempt: args.expected_foreman_attempt === undefined
        ? undefined
        : optionalInteger(args.expected_foreman_attempt, 'expected-foreman-attempt'),
      expectedForemanLeaseUntil: args.expected_foreman_lease_until,
      reason: requireArg(args, 'reason'),
      incidentRef: requireArg(args, 'incident_ref'),
      foremanRecoveryCapabilityFile: requireArg(args, 'foreman_recovery_capability_file'),
      eventId: requireArg(args, 'event_id'),
      probeObservationReceipt:
        args.probe_observation_receipt || null,
      probeObservationReceiptSha256:
        args.probe_observation_receipt_sha256 || null,
      probeObservationPlan:
        args.probe_observation_plan || null,
      probeObservationPlanSha256:
        args.probe_observation_plan_sha256 || null,
      probeObservationStableId:
        args.probe_observation_stable_id || null,
      probeObservationChallenge:
        args.probe_observation_challenge || null,
      invocationCwd,
    });
    return { value, exitCode: 0 };
  }
  if (command === 'status') {
    const loaded = loadGoalStateReadOnly(
      cwd,
      requireArg(args, 'goal'),
      null,
      { allowIncompleteRecoveryRead: true },
    );
    const value = {
      ...loaded.public_snapshot,
      foreman_recovery_scope: loaded.foreman_recovery_scope,
      pending_foreman_recovery: loaded.pending_foreman_recovery,
      pending_operations: loaded.pending_operations,
      ...(loaded.control_store_read
        ? { control_store_read: loaded.control_store_read }
        : {}),
    };
    if (args.task) {
      assertControl(value.tasks[args.task], 'UNKNOWN_TASK', `未知 task ${args.task}`);
      return { value: { ...value, tasks: { [args.task]: value.tasks[args.task] } }, exitCode: 0 };
    }
    return { value, exitCode: 0 };
  }
  if (command === 'next') {
    return { value: nextTasks(cwd, requireArg(args, 'goal')), exitCode: 0 };
  }
  if (command === 'actions') {
    const role = args.role ? validateRole(args.role) : null;
    assertControl(
      role || !args.thread,
      'INVALID_ARGUMENT',
      'credentialless actions 不能单独指定 --thread',
    );
    return {
      value: actionsForTask(
        cwd,
        requireArg(args, 'goal'),
        requireArg(args, 'task'),
        role,
        role ? requireArg(args, 'thread') : null,
      ),
      exitCode: 0,
    };
  }
  if (command === 'resume') {
    const role = validateRole(requireArg(args, 'role'));
    return {
      value: resumeCapsule(cwd, requireArg(args, 'goal'), requireArg(args, 'task'), role, requireArg(args, 'thread')),
      exitCode: 0,
      resume: true,
    };
  }
  if (command === 'doctor') {
    const value = doctor(cwd, requireArg(args, 'goal'));
    return { value, exitCode: value.healthy ? 0 : 1 };
  }
  if (command === 'merge-pr') {
    const allowed = new Set([
      '_',
      'json',
      'repository_worktree',
      'goal',
      'task',
      'thread',
      'event_id',
      'expected_state_revision',
      'expected_control_epoch',
      'actor_capability_file',
    ]);
    const unknown = Object.keys(args).filter((key) => !allowed.has(key));
    assertControl(
      args._.length === 1 && unknown.length === 0,
      'INVALID_ARGUMENT',
      `merge-pr 拒绝未知/非 canonical 参数${
        unknown.length > 0 ? `: ${unknown.map((key) => `--${key.replace(/_/g, '-')}`).join(', ')}` : ''
      }`,
    );
    return {
      value: mergePullRequest(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        threadId: requireArg(args, 'thread'),
        eventId: requireArg(args, 'event_id'),
        expectedStateRevision: optionalInteger(
          requireArg(args, 'expected_state_revision'),
          'expected-state-revision',
        ),
        expectedControlEpoch: optionalInteger(
          requireArg(args, 'expected_control_epoch'),
          'expected-control-epoch',
        ),
        actorCapabilityFile: requireArg(
          args,
          'actor_capability_file',
        ),
      }),
      exitCode: 0,
    };
  }
  if (command === 'control') {
    return {
      value: advanceControlEpoch(cwd, {
        goalId: requireArg(args, 'goal'),
        expectedEpoch: optionalInteger(args.expected_epoch, 'expected-epoch'),
        reason: requireArg(args, 'reason'),
        instructionRef: requireArg(args, 'instruction_ref'),
        actorCapabilityFile: requireArg(args, 'actor_capability_file'),
        threadId: requireArg(args, 'thread'),
        eventId: requireArg(args, 'event_id'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'preflight') {
    const value = runPreflight(cwd, {
      goalId: requireArg(args, 'goal'),
      taskId: requireArg(args, 'task'),
      launchFile: requireArg(args, 'launch'),
      stage: args.stage || null,
      evidenceId: args.evidence_id || null,
      actorCapabilityFile: requireArg(args, 'actor_capability_file'),
    });
    return { value, exitCode: value.status === 'PASS' ? 0 : 1 };
  }
  if (command === 'launch-template') {
    const role = validateRole(requireArg(args, 'role'));
    return {
      value: createLaunchTemplate(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        role,
        threadId: requireArg(args, 'thread'),
        actorCapabilityFile: requireArg(args, 'actor_capability_file'),
        inputFile: args.input_file || null,
      }),
      exitCode: 0,
    };
  }
  if (command === 'revalidate-source-checkpoint-hold') {
    return {
      value: revalidateSourceCheckpointHold(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        threadId: requireArg(args, 'thread'),
        operationId: requireArg(args, 'operation_id'),
        holdId: requireArg(args, 'hold'),
        expectedHoldEventId: requireArg(
          args,
          'expected_hold_event_id',
        ),
        expectedCanonicalLaunchSha256: requireArg(
          args,
          'expected_canonical_launch_sha256',
        ),
        expectedCandidateHead: requireArg(
          args,
          'expected_candidate_head',
        ),
        actorCapabilityFile: requireArg(
          args,
          'actor_capability_file',
        ),
      }),
      exitCode: 0,
    };
  }
  if (command === 'rotate-runtime') {
    const goalId = requireArg(args, 'goal');
    const taskId = requireArg(args, 'task');
    const role = validateRole(requireArg(args, 'role'));
    assertControl(
      ['DEV', 'REVIEW', 'RECEIPT'].includes(role),
      'INVALID_ROLE',
      'rotate-runtime --role 只允许 DEV/REVIEW/RECEIPT',
    );
    const workerThreadId = requireArg(args, 'worker_thread');
    const predecessorIncarnation = optionalInteger(
      requireArg(args, 'predecessor_incarnation'),
      'predecessor-incarnation',
    );
    const predecessorLaunchId = requireArg(args, 'predecessor_launch');
    const predecessorLaunchSha256 = normalizeHash(
      requireArg(args, 'expected_predecessor_launch_sha256'),
      'expected predecessor launch sha256',
    );
    const successorLaunchId = requireArg(args, 'successor_launch');
    const holdId = requireArg(args, 'hold');
    const expectedStateRevision = optionalInteger(
      requireArg(args, 'expected_state_revision'),
      'expected-state-revision',
    );
    const expectedControlEpoch = optionalInteger(
      requireArg(args, 'expected_control_epoch'),
      'expected-control-epoch',
    );
    const reason = requireArg(args, 'reason');
    const incidentRef = requireArg(args, 'incident_ref');
    const captainThreadId = requireArg(args, 'captain_thread');
    const actorCapabilityFile = requireArg(
      args,
      'captain_capability_file',
    );
    const eventId = requireArg(args, 'event_id');
    const historicalRetry = retryAcceptedCommandEvent(cwd, {
      goalId,
      taskId,
      eventId,
      type: 'RUNTIME_ROTATED',
      actorCapabilityFile,
      assertRequest: (accepted) => {
        assertControl(
          accepted.actor.role === 'CAPTAIN'
            && accepted.actor.thread_id === captainThreadId
            && accepted.expected_state_revision === expectedStateRevision
            && accepted.control_epoch === expectedControlEpoch
            && accepted.payload.role === role
            && accepted.payload.worker_thread_id === workerThreadId
            && accepted.payload.predecessor_incarnation
              === predecessorIncarnation
            && accepted.payload.predecessor_launch_id
              === predecessorLaunchId
            && normalizeHash(
              accepted.payload.predecessor_launch_sha256,
            ) === predecessorLaunchSha256
            && accepted.payload.successor_launch_id
              === successorLaunchId
            && accepted.payload.hold_id === holdId
            && accepted.payload.reason === reason
            && accepted.payload.incident_ref === incidentRef,
          'EVENT_ID_CONFLICT',
          `rotate-runtime event id ${eventId} 已绑定不同请求`,
        );
      },
    });
    if (historicalRetry) {
      const value = { ...historicalRetry };
      delete value.accepted_event;
      return { value, exitCode: 0 };
    }
    const loaded = loadGoalStateReadOnly(cwd, goalId);
    const state = loaded.snapshot.tasks[taskId];
    const manifestTask = loaded.manifest.tasks.find(
      (candidate) => candidate.id === taskId,
    );
    assertControl(state && manifestTask, 'UNKNOWN_TASK', `未知 task ${taskId}`);
    assertControl(
      state.state_revision === expectedStateRevision,
      'STALE_STATE_REVISION',
      `expected state revision ${expectedStateRevision}，当前为 ${state.state_revision}`,
    );
    assertControl(
      loaded.control.epoch === expectedControlEpoch,
      'STALE_CONTROL_EPOCH',
      `expected control epoch ${expectedControlEpoch}，当前为 ${loaded.control.epoch}`,
    );
    const worker = state.sessions[role];
    assertControl(
      worker
        && worker.thread_id === workerThreadId,
      'RUNTIME_ROTATION_WORKER_MISMATCH',
      `${role} worker thread 与 active session 不一致`,
    );
    const root = path.dirname(path.dirname(loaded.paths.dir));
    const payload = prepareRuntimeRotation(
      root,
      loaded,
      state,
      manifestTask,
      {
        role,
        workerThreadId,
        workerHostId: worker.host_id,
        workerAttempt: worker.attempt,
        predecessorIncarnation,
        predecessorLaunchId,
        predecessorLaunchSha256,
        successorLaunchId,
        holdId,
        reason,
        incidentRef,
        eventId,
      },
    );
    const event = createEventTemplate(cwd, {
      goalId,
      taskId,
      role: 'CAPTAIN',
      threadId: captainThreadId,
      type: 'RUNTIME_ROTATED',
      actorCapabilityFile,
      payload,
      eventId,
      runtimeRotationOperation: true,
    });
    assertControl(
      event.expected_state_revision === expectedStateRevision
        && event.control_epoch === expectedControlEpoch,
      'ACTOR_STATE_CHANGED',
      'runtime rotation proof 期间 task/control CAS 已漂移',
    );
    return {
      value: acceptEvent(
        cwd,
        event,
        actorCapabilityFile,
        { runtimeRotationOperation: true },
      ),
      exitCode: 0,
    };
  }
  if (command === 'recovery-export-source') {
    return {
      value: publicRecoveryHandoffResult(exportRecoverySnapshot(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        snapshotId: requireArg(args, 'snapshot_id'),
        successorThreadId: requireArg(args, 'successor_thread'),
        captainCapabilityFile: requireArg(args, 'captain_capability_file'),
        repositoryWorktree: requireArg(args, 'repository_worktree'),
      })),
      exitCode: 0,
    };
  }
  if (command === 'recovery-export-codex-rollout') {
    return {
      value: publicRecoveryHandoffResult(exportRecoverySnapshotFromCodexRollout(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        snapshotId: requireArg(args, 'snapshot_id'),
        successorThreadId: requireArg(args, 'successor_thread'),
        predecessorLaunchId: requireArg(args, 'predecessor_launch'),
        predecessorThreadId: requireArg(args, 'predecessor_thread'),
        rolloutFile: requireArg(args, 'rollout_file'),
        captainCapabilityFile: requireArg(args, 'captain_capability_file'),
        repositoryWorktree: requireArg(args, 'repository_worktree'),
        shellAuditFile: args.shell_audit_file || null,
        foremanCapabilityFile: args.foreman_capability_file || null,
      })),
      exitCode: 0,
    };
  }
  if (command === 'recovery-inspect-codex-rollout') {
    return {
      value: inspectCodexRolloutPatchEvents(requireArg(args, 'rollout_file'), {
        historicalWorktree: requireArg(args, 'historical_worktree'),
        predecessorThreadId: requireArg(args, 'predecessor_thread'),
        allowShellAudit: args.allow_shell_audit === true,
      }),
      exitCode: 0,
    };
  }
  if (command === 'recovery-build-codex-shell-audit') {
    const audit = buildCodexShellAudit({
      goalId: requireArg(args, 'goal'),
      taskId: requireArg(args, 'task'),
      predecessorLaunchId: requireArg(args, 'predecessor_launch'),
      predecessorThreadId: requireArg(args, 'predecessor_thread'),
      historicalWorktree: requireArg(args, 'historical_worktree'),
      predecessorHead: requireArg(args, 'predecessor_head'),
      rolloutFile: requireArg(args, 'rollout_file'),
      captainThreadId: requireArg(args, 'captain_thread'),
      foremanThreadId: requireArg(args, 'foreman_thread'),
      incidentRef: requireArg(args, 'incident_ref'),
      dispositionsFile: requireArg(args, 'dispositions_file'),
    });
    return {
      value: args.output_file === undefined
        ? audit
        : writeCodexShellAuditOutput(audit, requireArg(args, 'output_file')),
      exitCode: 0,
    };
  }
  if (command === 'recovery-import-source') {
    const value = importRecoverySnapshot(cwd, {
      goalId: requireArg(args, 'goal'),
      taskId: requireArg(args, 'task'),
      importId: requireArg(args, 'import_id'),
      successorThreadId: requireArg(args, 'successor_thread'),
      snapshotId: requireArg(args, 'snapshot'),
      actorCapabilityFile: requireArg(args, 'actor_capability_file'),
    });
    return {
      value: publicRecoveryHandoffResult({
        ...value,
        next_step:
          'run recovery-checkpoint-source with this import_receipt_id, then pass checkpoint_sha to recovery-bind --import-commit',
      }),
      exitCode: 0,
    };
  }
  if (command === 'recovery-checkpoint-source') {
    return {
      value: checkpointRecoverySource(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        successorThreadId: requireArg(args, 'successor_thread'),
        snapshotId: requireArg(args, 'snapshot'),
        importReceiptId: requireArg(args, 'import_receipt'),
        actorCapabilityFile: requireArg(args, 'actor_capability_file'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'recovery-bind') {
    const goalId = requireArg(args, 'goal');
    const taskId = requireArg(args, 'task');
    const successorThreadId = requireArg(args, 'successor_thread');
    const snapshotId = requireArg(args, 'snapshot');
    const importReceiptId = requireArg(args, 'import_receipt');
    const actorCapabilityFile = requireArg(args, 'captain_capability_file');
    const eventId = requireArg(args, 'event_id');
    const requestedImportCommit = args.import_commit || 'HEAD';
    const explicitHistoricalCommit = /^[0-9a-f]{40}$/.test(requestedImportCommit)
      ? requestedImportCommit
      : null;
    const historicalRetry = retryAcceptedCommandEvent(cwd, {
      goalId,
      taskId,
      eventId,
      type: 'RECOVERY_HANDOFF_BOUND',
      actorCapabilityFile,
      assertRequest: (accepted) => {
        assertControl(
          explicitHistoricalCommit,
          'HISTORICAL_RETRY_REQUIRES_FULL_IMPORT_COMMIT',
          'recovery-bind 历史精确重试必须显式传入 accepted request 的完整 40 位 --import-commit；不能从当前 worktree 解析 HEAD/ref',
        );
        assertControl(
          accepted.payload.successor_thread_id === successorThreadId
            && accepted.payload.snapshot_id === snapshotId
            && accepted.payload.import_receipt_id === importReceiptId
            && accepted.payload.import_commit === explicitHistoricalCommit,
          'EVENT_ID_CONFLICT',
          `recovery-bind event id ${eventId} 已绑定不同请求`,
        );
      },
    });
    if (historicalRetry) {
      const accepted = historicalRetry.accepted_event;
      const value = { ...historicalRetry };
      delete value.accepted_event;
      return {
        value: {
          ...value,
          operational_scope: value.task.sessions.DEV
            ? value.task.sessions.DEV.operational_scope
            : null,
          handoff: {
            event_id: eventId,
            ...accepted.payload,
            bound_at: accepted.accepted_at,
          },
        },
        exitCode: 0,
      };
    }
    const importCommit = git(cwd, [
      'rev-parse',
      '--verify',
      `${requestedImportCommit}^{commit}`,
    ]);
    const loaded = loadGoalStateReadOnly(cwd, goalId);
    const state = loaded.snapshot.tasks[taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
    const captain = state.sessions.CAPTAIN;
    const successor = state.sessions.DEV;
    const captainThreadId = args.captain_thread || (captain && captain.thread_id);
    assertControl(captainThreadId, 'UNREGISTERED_ACTOR', '当前 task 缺 CAPTAIN session');
    authorizeSession(state, actorCapabilityFile, {
      role: 'CAPTAIN',
      threadId: captainThreadId,
    });
    assertControl(successor && successor.thread_id === successorThreadId, 'SUCCESSOR_NOT_REGISTERED', 'successor 不是当前 DEV');
    assertControl(
      !successor.recovery_retarget_required,
      'RECOVERY_RETARGET_REQUIRED',
      '已废止 handoff 的 successor 必须先 ROLE_LOST 并登记 fresh attempt',
    );
    if (successor.recovery_handoff) {
      const handoff = successor.recovery_handoff;
      assertControl(
        handoff.event_id === eventId
          && handoff.snapshot_id === snapshotId
          && handoff.import_receipt_id === importReceiptId
          && handoff.import_commit === importCommit,
        'RECOVERY_HANDOFF_ALREADY_BOUND',
        '当前 successor 已绑定不同 source handoff',
      );
      return {
        value: {
          accepted: true,
          idempotent: true,
          event_id: handoff.event_id,
          operational_scope: successor.operational_scope,
          handoff,
        },
        exitCode: 0,
      };
    }
    const payload = buildRecoveryHandoffPayload(cwd, {
      goalId,
      taskId,
      successorThreadId,
      snapshotId,
      importReceiptId,
      importCommit,
      captainThreadId,
      captainCapabilityFile: actorCapabilityFile,
    });
    const event = createEventTemplate(cwd, {
      goalId,
      taskId,
      role: 'CAPTAIN',
      threadId: captainThreadId,
      type: 'RECOVERY_HANDOFF_BOUND',
      actorCapabilityFile,
      payload,
      eventId,
    });
    return { value: acceptEvent(cwd, event, actorCapabilityFile), exitCode: 0 };
  }
  if (command === 'recovery-promote') {
    const goalId = requireArg(args, 'goal');
    const taskId = requireArg(args, 'task');
    const successorThreadId = requireArg(args, 'successor_thread');
    const preflightEvidenceId = requireArg(args, 'preflight_evidence');
    const actorCapabilityFile = requireArg(args, 'captain_capability_file');
    const eventId = requireArg(args, 'event_id');
    const historicalRetry = retryAcceptedCommandEvent(cwd, {
      goalId,
      taskId,
      eventId,
      type: 'RECOVERY_PROMOTED',
      actorCapabilityFile,
      assertRequest: (accepted) => {
        assertControl(
          accepted.payload.successor_thread_id === successorThreadId
            && accepted.payload.preflight_evidence_id === preflightEvidenceId,
          'EVENT_ID_CONFLICT',
          `recovery-promote event id ${eventId} 已绑定不同请求`,
        );
      },
    });
    if (historicalRetry) {
      const accepted = historicalRetry.accepted_event;
      const value = { ...historicalRetry };
      delete value.accepted_event;
      return {
        value: {
          ...value,
          operational_scope: value.task.sessions.DEV
            ? value.task.sessions.DEV.operational_scope
            : null,
          promotion: {
            event_id: eventId,
            ...accepted.payload,
            promoted_at: accepted.accepted_at,
          },
        },
        exitCode: 0,
      };
    }
    const loaded = loadGoalStateReadOnly(cwd, goalId);
    const state = loaded.snapshot.tasks[taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
    const captain = state.sessions.CAPTAIN;
    const successor = state.sessions.DEV;
    const captainThreadId = args.captain_thread || (captain && captain.thread_id);
    assertControl(captainThreadId, 'UNREGISTERED_ACTOR', '当前 task 缺 CAPTAIN session');
    authorizeSession(state, actorCapabilityFile, {
      role: 'CAPTAIN',
      threadId: captainThreadId,
    });
    assertControl(successor && successor.thread_id === successorThreadId, 'SUCCESSOR_NOT_REGISTERED', 'successor 不是当前 DEV');
    if (successor.recovery_promotion) {
      const promotion = successor.recovery_promotion;
      assertControl(
        promotion.event_id === eventId
          && promotion.preflight_evidence_id === preflightEvidenceId,
        'RECOVERY_PROMOTION_NOT_APPLICABLE',
        '当前 successor 已用不同 preflight evidence 完成 promotion',
      );
      return {
        value: {
          accepted: true,
          idempotent: true,
          event_id: promotion.event_id,
          operational_scope: successor.operational_scope,
          promotion,
        },
        exitCode: 0,
      };
    }
    assertControl(successor.recovery_handoff, 'RECOVERY_HANDOFF_REQUIRED', 'promotion 前缺 source handoff');
    assertControl(successor.launch_id, 'LAUNCH_ID_REQUIRED', 'successor 缺 launch_id');
    const launchFile = path.join(loaded.paths.dir, 'launches', taskId, `${successor.launch_id}.json`);
    assertControl(fs.existsSync(launchFile), 'PREFLIGHT_REQUIRED', `launch ${successor.launch_id} 尚未通过 preflight`);
    const payload = {
      successor_thread_id: successorThreadId,
      handoff_event_id: successor.recovery_handoff.event_id,
      launch_id: successor.launch_id,
      launch_sha256: hashFile(launchFile),
      preflight_evidence_id: preflightEvidenceId,
    };
    const event = createEventTemplate(cwd, {
      goalId,
      taskId,
      role: 'CAPTAIN',
      threadId: captainThreadId,
      type: 'RECOVERY_PROMOTED',
      actorCapabilityFile,
      payload,
      eventId,
    });
    return { value: acceptEvent(cwd, event, actorCapabilityFile), exitCode: 0 };
  }
  if (command === 'recovery-abandon-handoff') {
    const goalId = requireArg(args, 'goal');
    const taskId = requireArg(args, 'task');
    const successorThreadId = requireArg(args, 'successor_thread');
    const captainCapabilityFile = requireArg(args, 'captain_capability_file');
    const foremanCapabilityFile = requireArg(args, 'foreman_capability_file');
    const reason = requireArg(args, 'reason');
    const incidentRef = requireArg(args, 'incident_ref');
    const eventId = requireArg(args, 'event_id');
    const historicalRetry = retryAcceptedCommandEvent(cwd, {
      goalId,
      taskId,
      eventId,
      type: 'RECOVERY_HANDOFF_ABANDONED',
      actorCapabilityFile: captainCapabilityFile,
      assertRequest: (accepted, acceptedLoaded) => {
        assertControl(
          accepted.payload.successor_thread_id === successorThreadId
            && accepted.payload.reason === reason
            && accepted.payload.incident_ref === incidentRef
            && (!args.captain_thread || accepted.actor.thread_id === args.captain_thread)
            && (!args.foreman_thread || accepted.payload.foreman_thread_id === args.foreman_thread),
          'EVENT_ID_CONFLICT',
          `recovery-abandon-handoff event id ${eventId} 已绑定不同请求`,
        );
        authorizeHistoricalActorCapability(
          acceptedLoaded.snapshot,
          foremanCapabilityFile,
          {
            role: 'FOREMAN',
            thread_id: accepted.payload.foreman_thread_id,
            host_id: accepted.payload.foreman_host_id,
            attempt: accepted.payload.foreman_attempt,
          },
          { goalWide: true },
        );
      },
    });
    if (historicalRetry) {
      const accepted = historicalRetry.accepted_event;
      const value = { ...historicalRetry };
      delete value.accepted_event;
      return {
        value: {
          ...value,
          operational_scope: value.task.sessions.DEV
            ? value.task.sessions.DEV.operational_scope
            : null,
          abandoned_handoff_event_id: accepted.payload.handoff_event_id,
        },
        exitCode: 0,
      };
    }
    const loaded = loadGoalStateReadOnly(cwd, goalId);
    const state = loaded.snapshot.tasks[taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
    const captain = state.sessions.CAPTAIN;
    const foreman = state.sessions.FOREMAN;
    const successor = state.sessions.DEV;
    const captainThreadId = args.captain_thread || (captain && captain.thread_id);
    const foremanThreadId = args.foreman_thread || (foreman && foreman.thread_id);
    assertControl(captainThreadId && foremanThreadId, 'UNREGISTERED_ACTOR', 'handoff abandon 需要当前 CAPTAIN + FOREMAN');
    assertControl(
      successor
        && successor.thread_id === successorThreadId
        && successor.operational_scope === 'PREFLIGHT_ONLY'
        && successor.recovery_handoff,
      'RECOVERY_HANDOFF_NOT_APPLICABLE',
      'successor 不是当前 PREFLIGHT_ONLY DEV',
    );
    const payload = {
      successor_thread_id: successorThreadId,
      handoff_event_id: successor.recovery_handoff.event_id,
      reason,
      incident_ref: incidentRef,
      foreman_thread_id: foremanThreadId,
      foreman_host_id: foreman.host_id,
      foreman_attempt: foreman.attempt,
    };
    const event = createEventTemplate(cwd, {
      goalId,
      taskId,
      role: 'CAPTAIN',
      threadId: captainThreadId,
      type: 'RECOVERY_HANDOFF_ABANDONED',
      actorCapabilityFile: captainCapabilityFile,
      payload,
      eventId,
    });
    const value = acceptEvent(
      cwd,
      event,
      captainCapabilityFile,
      { foremanCapabilityFile },
    );
    return {
      value: {
        ...value,
        operational_scope: value.task.sessions.DEV.operational_scope,
        abandoned_handoff_event_id: payload.handoff_event_id,
      },
      exitCode: 0,
    };
  }
  if (command === 'evidence') {
    const evidence = readEvent(requireArg(args, 'file'));
    const goalId = requireArg(args, 'goal');
    assertControl(evidence.goal_id === goalId, 'EVIDENCE_GOAL_MISMATCH', 'evidence.goal_id 与 --goal 不一致');
    return { value: recordEvidence(cwd, evidence, requireArg(args, 'actor_capability_file')), exitCode: 0 };
  }
  if (command === 'gate-fast') {
    const value = runFastEvidence(cwd, {
      goalId: requireArg(args, 'goal'),
      taskId: requireArg(args, 'task'),
      evidenceId: requireArg(args, 'evidence_id'),
      actorCapabilityFile: requireArg(args, 'actor_capability_file'),
    });
    return {
      value: publicEvidenceResult(value),
      exitCode: value.evidence.status === 'PASS' ? 0 : 1,
    };
  }
  if (command === 'gate-full-ci') {
    const value = runFullCiEvidence(cwd, {
      goalId: requireArg(args, 'goal'),
      taskId: requireArg(args, 'task'),
      pullRequest: optionalInteger(requireArg(args, 'pr'), 'pr'),
      evidenceId: requireArg(args, 'evidence_id'),
      actorCapabilityFile: requireArg(args, 'actor_capability_file'),
    });
    return {
      value: publicEvidenceResult(value),
      exitCode: value.evidence.status === 'PASS' ? 0 : 1,
    };
  }
  if (command === 'gate-ac-audit') {
    const value = runAcAuditEvidence(cwd, {
      goalId: requireArg(args, 'goal'),
      taskId: requireArg(args, 'task'),
      issue: optionalInteger(requireArg(args, 'issue'), 'issue'),
      pullRequest: optionalInteger(requireArg(args, 'pr'), 'pr'),
      evidenceId: requireArg(args, 'evidence_id'),
      actorCapabilityFile: requireArg(args, 'actor_capability_file'),
    });
    return {
      value: publicEvidenceResult(value),
      exitCode: value.evidence.status === 'PASS' ? 0 : 1,
    };
  }
  if (command === 'rebuild-ledger') {
    return { value: rebuildLedger(cwd, requireArg(args, 'goal')), exitCode: 0 };
  }
  throw new ControlError('UNKNOWN_COMMAND', `未知 goalctl command: ${command}`);
}

function resourceCommand(argv, cwd = process.cwd()) {
  const args = parseArgs(argv);
  const command = args._[0];
  if (args.help || command === 'help') {
    const topic = command === 'help' ? (args._[1] || null) : (command || null);
    return { value: helpDocument('resource', topic), exitCode: 0, help: true };
  }
  assertControl(command, 'COMMAND_REQUIRED', '缺少 resourcectl command');

  if (command === 'acquire') {
    const value = acquireLease(cwd, {
      goalId: requireArg(args, 'goal'),
      taskId: requireArg(args, 'task'),
      role: validateRole(requireArg(args, 'role')),
      threadId: requireArg(args, 'thread'),
      hostId: args.host || 'local',
      resource: requireArg(args, 'resource'),
      access: args.access || 'EXCLUSIVE',
      ttlMilliseconds: optionalInteger(args.ttl_ms, 'ttl-ms', 3600000),
      actorCapabilityFile: requireArg(args, 'actor_capability_file'),
      eventId: requireArg(args, 'event_id'),
    });
    return { value, exitCode: 0 };
  }
  if (command === 'renew') {
    return {
      value: renewLease(cwd, {
        leaseId: requireArg(args, 'lease'),
        ownerCapabilityFile: requireArg(args, 'owner_capability_file'),
        actorCapabilityFile: requireArg(args, 'actor_capability_file'),
        expectedRevision: optionalInteger(args.expected_revision, 'expected-revision'),
        ttlMilliseconds: optionalInteger(args.ttl_ms, 'ttl-ms', 3600000),
        eventId: requireArg(args, 'event_id'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'release') {
    return {
      value: releaseLease(cwd, {
        leaseId: requireArg(args, 'lease'),
        ownerCapabilityFile: requireArg(args, 'owner_capability_file'),
        actorCapabilityFile: requireArg(args, 'actor_capability_file'),
        expectedRevision: optionalInteger(args.expected_revision, 'expected-revision'),
        eventId: requireArg(args, 'event_id'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'verify') {
    return {
      value: verifyLease(cwd, {
        leaseId: requireArg(args, 'lease'),
        ownerCapabilityFile: requireArg(args, 'owner_capability_file'),
        actorCapabilityFile: requireArg(args, 'actor_capability_file'),
        resource: args.resource || null,
        eventId: requireArg(args, 'event_id'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'owner-capability') {
    return {
      value: recoverOwnerCapability(cwd, {
        leaseId: requireArg(args, 'lease'),
        actorCapabilityFile: requireArg(args, 'actor_capability_file'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'reap') {
    return {
      value: reapLease(cwd, {
        leaseId: requireArg(args, 'lease'),
        expectedRevision: optionalInteger(args.expected_revision, 'expected-revision'),
        actorCapabilityFile: requireArg(args, 'actor_capability_file'),
        evidenceId: requireArg(args, 'evidence'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'reinitialize-zero-runtime') {
    return {
      value: reinitializeZeroRuntimeLeases(cwd, {
        goalId: requireArg(args, 'goal'),
        taskId: requireArg(args, 'task'),
        successorThreadId: requireArg(args, 'successor_thread'),
        handoffEventId: requireArg(args, 'handoff_event_id'),
        captainCapabilityFile: requireArg(args, 'captain_capability_file'),
        captainThreadId: args.captain_thread || null,
        foremanCapabilityFile: requireArg(args, 'foreman_capability_file'),
        foremanThreadId: args.foreman_thread || null,
        eventId: requireArg(args, 'event_id'),
      }),
      exitCode: 0,
    };
  }
  if (command === 'list') {
    return {
      value: listLeases(cwd, { goalId: args.goal || null, taskId: args.task || null, resource: args.resource || null }),
      exitCode: 0,
    };
  }
  if (command === 'doctor') {
    const value = doctorResources(cwd);
    return { value, exitCode: value.healthy ? 0 : 1 };
  }
  throw new ControlError('UNKNOWN_COMMAND', `未知 resourcectl command: ${command}`);
}

function renderResume(value) {
  const action = value.allowed_actions.length === 1
    ? value.allowed_actions[0].type
    : value.allowed_actions.map((item) => item.type).join(',') || 'NONE';
  const maintenance = (value.maintenance_actions || [])
    .map((item) => `${item.type}${item.lease_until ? `@${item.lease_until}` : ''}`)
    .join(',') || 'NONE';
  return [
    `ROLE ${value.role}`,
    `GOAL ${value.goal_id}`,
    `TASK ${value.task_id}`,
    `PHASE ${value.phase}`,
    `STATE_REVISION ${value.state_revision}`,
    `CONTROL_EPOCH ${value.control_epoch}`,
    `PACKET r${value.packet_revision} ${value.packet_sha256}`,
    `HEAD ${value.full_head}`,
    `WORKTREE_HEAD ${value.worktree_head}`,
    `LAUNCH ${value.launch_id || 'NONE'} ${value.launch_scope || 'FULL'}`,
    `LEASES ${value.resource_leases.join(',') || 'NONE'}`,
    `PROTOCOLS ${Object.values(value.protocols || {}).join(',') || 'NONE'}`,
    `HOLDS ${value.holds.join(',') || 'NONE'}`,
    `ALLOWED ${action}; MAINTENANCE ${maintenance}`,
    `FORBIDDEN ${value.forbidden}`,
  ].join('\n');
}

function printResult(result, argv) {
  const args = parseArgs(argv);
  if (result.help && !args.json) process.stdout.write(`${renderHelp(result.value)}\n`);
  else if (result.resume && !args.json) process.stdout.write(`${renderResume(result.value)}\n`);
  else process.stdout.write(`${JSON.stringify(result.value, null, args.json ? 2 : 0)}\n`);
  process.exitCode = result.exitCode;
}

function controlErrorCauseCodes(error) {
  const codes = [];
  const seen = new Set();
  let current = error && error.cause;
  while (
    current
      && typeof current === 'object'
      && !seen.has(current)
      && codes.length < 16
  ) {
    seen.add(current);
    if (
      typeof current.code === 'string'
        && current.code.length > 0
        && !codes.includes(current.code)
    ) {
      codes.push(current.code);
    }
    current = current.cause;
  }
  return codes;
}

function runMain(kind, argv) {
  try {
    assertNoSensitiveRoleIdentityArguments(argv);
    const args = parseArgs(argv);
    const invocationCwd = fs.realpathSync(process.cwd());
    let cwd = invocationCwd;
    if (args.repository_worktree !== undefined) {
      const requested = requireArg(args, 'repository_worktree');
      assertControl(path.isAbsolute(requested), 'INVALID_ARGUMENT', '--repository-worktree 必须是绝对路径');
      assertControl(path.normalize(requested) === requested, 'INVALID_ARGUMENT', '--repository-worktree 必须是规范绝对路径');
      const exportOperation = kind === 'goal'
        && ['recovery-export-source', 'recovery-export-codex-rollout'].includes(args._[0]);
      if (!exportOperation) {
        try {
          cwd = fs.realpathSync(requested);
        } catch (error) {
          throw new ControlError('INVALID_ARGUMENT', `--repository-worktree 不存在: ${error.message}`);
        }
        assertControl(fs.statSync(cwd).isDirectory(), 'INVALID_ARGUMENT', '--repository-worktree 必须是目录');
      }
    }
    const result = kind === 'goal'
      ? goalCommand(argv, cwd, invocationCwd)
      : resourceCommand(argv, cwd);
    printResult(result, argv);
  } catch (error) {
    const failure = error instanceof ControlError
      ? error
      : new ControlError('UNEXPECTED', '内部错误');
    const publicMessage = containsSensitiveStringLeaves(failure.message)
      ? '请求包含敏感数据，已拒绝'
      : failure.message;
    process.stderr.write(`${kind}ctl[${failure.code}]: ${publicMessage}\n`);
    if (
      failure.details
        && !containsSensitiveStringLeaves(failure.details)
    ) {
      process.stderr.write(`${JSON.stringify(failure.details)}\n`);
    }
    const causeCodes = controlErrorCauseCodes(failure);
    if (causeCodes.length > 0) {
      process.stderr.write(`${JSON.stringify({ caused_by_codes: causeCodes })}\n`);
    }
    process.exitCode = 2;
  }
}

module.exports = { goalCommand, resourceCommand, runMain };
