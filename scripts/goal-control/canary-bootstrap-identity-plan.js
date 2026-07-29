'use strict';

const fs = require('fs');
const {
  replayEnvironmentContract,
  replayShellCommand,
} = require('./canary-controller-attestation');
const { hashObject } = require('./util');

const BOOTSTRAP_PLAN_KIND = 'WORKER_CANARY_IDENTITY_PLAN';
const CAPTAIN_BOOTSTRAP_PLAN_KIND =
  'CAPTAIN_CANARY_IDENTITY_PLAN';

function identityPlanCore(capture, options) {
  return {
    schema_version: 1,
    kind: capture.bootstrapProfile.planKind,
    phase: 'IDENTITY_ONLY',
    controller: capture.controller.provenance,
    frozen_repository: {
      worktree: capture.repositoryRoot,
      common_git_dir: capture.commonGitDir,
      head: capture.head,
      name_with_owner: capture.manifest.repository.name_with_owner,
      base_branch: capture.manifest.repository.base_branch,
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
    goal_id: capture.manifest.goal_id,
    task_id: capture.selectedTask.id,
    role: options.role,
    expected_head: capture.expectedHead,
    ...(capture.requiredStartHeadProof
      ? {
        required_start_head_proof:
          capture.requiredStartHeadProof,
      }
      : {}),
    operation_id: options.operationId,
    challenge: options.challenge,
    worker_branch: capture.workerBranch,
    allowed_observations: [
      'THREAD_HOST_FROM_PLATFORM',
      'CANONICAL_CWD',
      'GIT_DIR',
      'GIT_COMMON_DIR',
      'HEAD',
      'BRANCH_OR_DETACHED',
      'CLEAN_STATUS',
    ],
    forbidden_actions: [
      'ROLE_REGISTRATION',
      'CAPABILITY_OR_LEASE',
      'GOAL_EVENT_OR_RESUME',
      'GITHUB_OR_PUSH',
      'BROWSER_OR_ENVIRONMENT',
      'SOURCE_OR_INDEX_WRITE',
    ],
  };
}

function identityPlanOutput(capture, options) {
  const core = identityPlanCore(capture, options);
  const bindingSha256 = hashObject(core);
  const replayEnvironment = replayEnvironmentContract();
  const inspectArgv = [
    capture.controller.provenance.entrypoint,
    'canary-bootstrap-inspect',
    '--goal-worktree',
    capture.repositoryRoot,
    '--manifest',
    capture.manifest.source_manifest,
    '--role',
    options.role,
    '--task',
    capture.selectedTask.id,
    '--expected-head',
    capture.expectedHead,
    '--operation-id',
    options.operationId,
    '--challenge',
    options.challenge,
    '--canary-policy',
    capture.policyPath,
    '--canary-policy-sha256',
    capture.policySha256,
    '--expected-identity-binding-sha256',
    bindingSha256,
    '--worker-thread',
    '<platform-thread-id>',
    '--worker-host',
    '<platform-host-id>',
    '--json',
  ];
  const nodeExecutable = fs.realpathSync(process.execPath);
  const plan = {
    ...core,
    identity_binding_sha256: bindingSha256,
    identity_capture: {
      node_executable: nodeExecutable,
      argv_template: inspectArgv,
      environment: replayEnvironment,
      shell_command_template: replayShellCommand(
        replayEnvironment,
        nodeExecutable,
        inspectArgv,
      ),
    },
  };
  return {
    identity_plan: plan,
    identity_plan_sha256: hashObject(plan),
  };
}

module.exports = {
  BOOTSTRAP_PLAN_KIND,
  CAPTAIN_BOOTSTRAP_PLAN_KIND,
  identityPlanOutput,
};
