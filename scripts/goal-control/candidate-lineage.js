'use strict';

const fs = require('fs');
const { ControlError, assertControl } = require('./errors');
const { sessionOperationalScope } = require('./operational-scope');
const { assertFullSha, git } = require('./util');

function assertAncestor(worktree, ancestor, descendant, code, detail) {
  assertFullSha(ancestor, 'candidate ancestor');
  assertFullSha(descendant, 'candidate HEAD');
  try {
    git(worktree, ['merge-base', '--is-ancestor', ancestor, descendant]);
  } catch {
    throw new ControlError(code, detail);
  }
}

function assertDevCandidateLineage(worktree, state, session, candidateHead, options = {}) {
  assertControl(state.phase === 'DEV_ACTIVE', 'CANDIDATE_PHASE_MISMATCH', `phase=${state.phase} 不是 DEV_ACTIVE`);
  assertControl(
    session
      && session.role === 'DEV'
      && state.sessions.DEV
      && session.thread_id === state.sessions.DEV.thread_id
      && session.host_id === state.sessions.DEV.host_id
      && session.attempt === state.sessions.DEV.attempt,
    'FRESH_SESSION_REQUIRED',
    'candidate 必须绑定当前 DEV session',
  );
  const candidateAncestor = session.activated_full_head || session.registered_full_head;
  assertControl(
    typeof candidateAncestor === 'string',
    'STALE_ROLE_REGISTRATION',
    'DEV session 缺 activated/registered candidate ancestor',
  );
  assertAncestor(
    worktree,
    candidateAncestor,
    candidateHead,
    'CANDIDATE_HEAD_NOT_DESCENDANT',
    `candidate HEAD ${candidateHead} 不是 session ancestor ${candidateAncestor} 的后代`,
  );

  if (session.recovered_from && session.recovered_from.resume_phase === 'DEV_ACTIVE') {
    const handoff = session.recovery_handoff;
    assertControl(handoff, 'RECOVERY_HANDOFF_REQUIRED', 'recovered DEV candidate 缺 sealed source handoff');
    const scope = sessionOperationalScope(state, 'DEV');
    const allowedScopes = options.allowPreflightOnly === true
      ? ['PREFLIGHT_ONLY', 'FULL']
      : ['FULL'];
    assertControl(
      allowedScopes.includes(scope),
      'RECOVERY_PROMOTION_REQUIRED',
      `recovered DEV operational_scope=${scope}`,
    );
    const canonicalWorktree = fs.realpathSync(worktree);
    assertControl(
      canonicalWorktree === fs.realpathSync(handoff.destination_worktree),
      'WORKTREE_MISMATCH',
      'recovered DEV candidate 未使用 sealed destination worktree',
    );
    assertControl(
      git(canonicalWorktree, ['branch', '--show-current']) === handoff.destination_branch,
      'BRANCH_MISMATCH',
      'recovered DEV candidate 未使用 sealed destination branch',
    );
    assertAncestor(
      canonicalWorktree,
      handoff.import_commit,
      candidateHead,
      'CANDIDATE_HEAD_NOT_DESCENDANT',
      `candidate HEAD ${candidateHead} 不是 recovery import ${handoff.import_commit} 的后代`,
    );
  } else if (session.recovered_from) {
    assertControl(
      sessionOperationalScope(state, 'DEV') === 'FULL',
      'RECOVERY_PROMOTION_REQUIRED',
      `non-source DEV recovery operational_scope=${sessionOperationalScope(state, 'DEV')}`,
    );
  }
  return candidateAncestor;
}

function assertDevCandidateReplayLineage(launch, state, session, candidateHead, options = {}) {
  assertControl(state.phase === 'DEV_ACTIVE', 'CANDIDATE_PHASE_MISMATCH', `phase=${state.phase} 不是 DEV_ACTIVE`);
  assertControl(
    launch
      && launch.role === 'DEV'
      && launch.goal_id
      && launch.task_id === state.task_id
      && launch.repository
      && launch.repository.full_head === candidateHead,
    'PREFLIGHT_LAUNCH_MISMATCH',
    'sealed PREFLIGHT launch 未绑定 replay candidate HEAD/task',
  );
  assertControl(
    session
      && session.role === 'DEV'
      && state.sessions.DEV
      && session.thread_id === state.sessions.DEV.thread_id
      && session.host_id === state.sessions.DEV.host_id
      && session.attempt === state.sessions.DEV.attempt
      && launch.thread.id === session.thread_id
      && (launch.thread.host_id || 'local') === session.host_id
      && launch.launch_id === session.launch_id
      && launch.execution.task_nonce === session.task_nonce,
    'FRESH_SESSION_REQUIRED',
    'sealed PREFLIGHT launch 必须绑定事件时的 DEV session',
  );
  const candidateAncestor = session.activated_full_head || session.registered_full_head;
  assertControl(
    typeof candidateAncestor === 'string',
    'STALE_ROLE_REGISTRATION',
    'DEV session 缺 activated/registered candidate ancestor',
  );
  if (session.recovered_from && session.recovered_from.resume_phase === 'DEV_ACTIVE') {
    const handoff = session.recovery_handoff;
    assertControl(handoff, 'RECOVERY_HANDOFF_REQUIRED', 'recovered DEV candidate 缺 sealed source handoff');
    const scope = sessionOperationalScope(state, 'DEV');
    const allowedScopes = options.allowPreflightOnly === true
      ? ['PREFLIGHT_ONLY', 'FULL']
      : ['FULL'];
    assertControl(
      allowedScopes.includes(scope),
      'RECOVERY_PROMOTION_REQUIRED',
      `recovered DEV operational_scope=${scope}`,
    );
    assertControl(
      launch.repository.worktree === handoff.destination_worktree
        && launch.repository.branch === handoff.destination_branch,
      'WORKTREE_MISMATCH',
      'sealed PREFLIGHT launch 未绑定 recovery handoff destination identity',
    );
    assertControl(
      candidateHead === handoff.import_commit || sessionOperationalScope(state, 'DEV') === 'FULL',
      'CANDIDATE_HEAD_NOT_DESCENDANT',
      'PREFLIGHT_ONLY candidate 必须精确绑定 recovery import checkpoint',
    );
  } else if (session.recovered_from) {
    assertControl(
      sessionOperationalScope(state, 'DEV') === 'FULL',
      'RECOVERY_PROMOTION_REQUIRED',
      `non-source DEV recovery operational_scope=${sessionOperationalScope(state, 'DEV')}`,
    );
  }
  return candidateAncestor;
}

module.exports = {
  assertDevCandidateLineage,
  assertDevCandidateReplayLineage,
};
