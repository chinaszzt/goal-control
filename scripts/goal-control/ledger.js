'use strict';

function taskLedgerRow(task, state, actions, launchScope = null) {
  const sessions = Object.values(state.sessions)
    .filter((session) => session.status !== 'superseded')
    .map((session) => `${session.role}:${session.thread_id}@${session.attempt}`)
    .join(', ');
  return {
    task_id: task.id,
    phase: state.phase,
    state_revision: state.state_revision,
    packet_revision: state.packet.revision,
    packet_sha256: state.packet.sha256,
    base_head: state.base_head,
    full_head: state.full_head,
    pr: state.pr,
    sessions,
    holds: state.holds.map((hold) => hold.kind),
    recovery: state.recovery ? state.recovery.role : null,
    recovery_backlog: (state.recovery_backlog || []).map((item) => item.role),
    operational_scope: launchScope,
    next_actions: actions.map((action) => action.type),
    last_event: state.last_event,
    integration_order: task.integration_order,
  };
}

function renderMarkdown(ledger) {
  const lines = [
    `# Goal ${ledger.goal_id} runtime ledger`,
    '',
    '> 由 `goalctl` 从 append-only event log 生成，禁止手改。',
    '',
    `- control epoch: ${ledger.control_epoch}`,
    `- manifest: ${ledger.manifest_sha256}`,
    `- generated: ${ledger.generated_at}`,
    '',
    '| task | phase/rev | packet | head | sessions | holds/recovery | next |',
    '|---|---|---|---|---|---|---|',
  ];
  for (const row of ledger.tasks) {
    const holds = [
      ...row.holds,
      row.recovery ? `RECOVERY:${row.recovery}` : null,
      row.recovery_backlog.length ? `RECOVERY_BACKLOG:${row.recovery_backlog.join('+')}` : null,
      row.operational_scope && row.operational_scope !== 'FULL' ? row.operational_scope : null,
    ].filter(Boolean).join(', ') || '—';
    lines.push(
      `| ${row.task_id} | ${row.phase} / ${row.state_revision} | r${row.packet_revision} / ${row.packet_sha256.slice(-12)} | ${row.full_head.slice(0, 12)} | ${row.sessions || '—'} | ${holds} | ${row.next_actions.join(', ') || '—'} |`
    );
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

module.exports = { renderMarkdown, taskLedgerRow };
