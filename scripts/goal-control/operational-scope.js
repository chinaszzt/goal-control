'use strict';

const { assertControl } = require('./errors');

const FULL = 'FULL';
const RECOVERY_BLOCKED = 'RECOVERY_BLOCKED';
const PREFLIGHT_ONLY = 'PREFLIGHT_ONLY';

function sessionOperationalScope(state, role) {
  const session = state && state.sessions && state.sessions[role];
  if (!session) return null;
  if (role === 'DEV' && session.recovered_from) {
    return session.operational_scope || RECOVERY_BLOCKED;
  }
  return FULL;
}

function assertOperationalScope(state, role, operation) {
  const scope = sessionOperationalScope(state, role);
  assertControl(scope, 'UNREGISTERED_ACTOR', `${role} 尚未登记 session`);
  if (scope === FULL) return scope;

  const preflightOnlyOperations = new Set([
    'RESOURCE_ACQUIRE',
    'LAUNCH_TEMPLATE',
    'PREFLIGHT',
    'PREFLIGHT_EVIDENCE',
    'CLEANUP',
  ]);
  const blockedRecoveryOperations = new Set(['CLEANUP']);
  const allowed = scope === PREFLIGHT_ONLY
    ? preflightOnlyOperations.has(operation)
    : scope === RECOVERY_BLOCKED && blockedRecoveryOperations.has(operation);
  assertControl(
    allowed,
    'RECOVERY_SCOPE_VIOLATION',
    `${role} operational_scope=${scope} 不允许 ${operation}`,
  );
  return scope;
}

module.exports = {
  FULL,
  PREFLIGHT_ONLY,
  RECOVERY_BLOCKED,
  assertOperationalScope,
  sessionOperationalScope,
};
