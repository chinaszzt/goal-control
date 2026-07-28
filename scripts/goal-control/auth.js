'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ControlError, assertControl } = require('./errors');
const { atomicWrite, ensureDir } = require('./store');
const { randomId, runtimeNowMilliseconds, sha256 } = require('./util');

const MAX_ROLE_LEASE_MS = 4 * 60 * 60 * 1000;

function createCapabilityFile(directory, prefix) {
  ensureDir(directory);
  const file = path.join(directory, `${randomId(prefix)}.cap`);
  const capability = crypto.randomBytes(32).toString('base64url');
  atomicWrite(file, `${capability}\n`);
  fs.chmodSync(file, 0o600);
  return { file: fs.realpathSync(file), sha256: sha256(capability) };
}

function readCapabilityFile(file, expectedFile = null) {
  assertControl(typeof file === 'string' && file.length > 0, 'CAPABILITY_REQUIRED', '缺少 capability file');
  let resolved;
  try {
    resolved = fs.realpathSync(path.resolve(file));
  } catch (error) {
    throw new ControlError('CAPABILITY_INVALID', `capability file 不存在: ${error.message}`);
  }
  if (expectedFile) {
    let expected;
    try {
      expected = fs.realpathSync(expectedFile);
    } catch {
      assertControl(false, 'CAPABILITY_INVALID', '登记的 capability file 不存在');
    }
    assertControl(resolved === expected, 'CAPABILITY_INVALID', 'capability file 不是登记值');
  }
  const stat = fs.statSync(resolved);
  assertControl(stat.isFile(), 'CAPABILITY_INVALID', 'capability 必须是普通文件');
  assertControl((stat.mode & 0o077) === 0, 'CAPABILITY_PERMISSIONS', 'capability file 权限必须为 0600');
  if (typeof process.getuid === 'function') assertControl(stat.uid === process.getuid(), 'CAPABILITY_PERMISSIONS', 'capability file owner 不匹配');
  const value = fs.readFileSync(resolved, 'utf8').trim();
  assertControl(/^[A-Za-z0-9_-]{40,128}$/.test(value), 'CAPABILITY_INVALID', 'capability 内容非法');
  return { file: resolved, sha256: sha256(value) };
}

function hashesEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const leftBuffer = Buffer.from(left, 'hex');
  const rightBuffer = Buffer.from(right, 'hex');
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function authorizeSession(state, capabilityFile, options = {}) {
  const historicalSessions = options.allowTerminal
    ? Object.values(state.session_history || {}).flat()
    : [];
  const sessions = [...Object.values(state.sessions), ...historicalSessions];
  const supplied = readCapabilityFile(capabilityFile);
  const session = sessions.find((candidate) => hashesEqual(candidate.capability_sha256, supplied.sha256));
  assertControl(session, 'CAPABILITY_INVALID', 'capability 不属于当前 task 的活动角色');
  assertControl(!options.role || session.role === options.role, 'CAPABILITY_INVALID', `capability role 不是 ${options.role}`);
  assertControl(!options.threadId || session.thread_id === options.threadId, 'CAPABILITY_INVALID', 'capability thread 不匹配');
  assertControl(session.capability_file === supplied.file, 'CAPABILITY_INVALID', 'capability file 与登记路径不一致');
  const usableStatuses = options.allowTerminal ? ['active', 'idle', 'terminal'] : ['active', 'idle'];
  assertControl(usableStatuses.includes(session.status), 'ACTOR_UNUSABLE', `actor status=${session.status}`);
  if (session.status !== 'terminal') {
    assertControl(Date.parse(session.lease_until) > runtimeNowMilliseconds(), 'ACTOR_LEASE_EXPIRED', `actor lease 已于 ${session.lease_until} 过期`);
  }
  return session;
}

function assertCoherentGoalForemanLineage(snapshot) {
  const foremen = Object.values(snapshot.tasks || {})
    .map((task) => task.sessions && task.sessions.FOREMAN)
    .filter(Boolean);
  const attempt = Math.max(
    0,
    ...foremen.map((session) => Number(session.attempt) || 0),
  );
  const replicas = foremen.filter((session) => session.attempt === attempt);
  if (replicas.length === 0) return { attempt, replicas };
  const anchor = replicas[0];
  assertControl(
    replicas.every((session) => (
      session.thread_id === anchor.thread_id
        && session.host_id === anchor.host_id
        && session.capability_file === anchor.capability_file
        && session.capability_sha256 === anchor.capability_sha256
    )),
    'GOAL_FOREMAN_LINEAGE_DIVERGED',
    `Goal max-attempt FOREMAN replicas attempt=${attempt} identity/capability 分叉`,
  );
  return { attempt, replicas, anchor };
}

function authorizeGoalSession(snapshot, capabilityFile, options = {}) {
  const supplied = readCapabilityFile(capabilityFile);
  const foremanLineage = options.role === 'FOREMAN'
    ? assertCoherentGoalForemanLineage(snapshot)
    : null;
  const currentGoalForemanAttempt = foremanLineage
    ? foremanLineage.attempt
    : null;
  if (options.role === 'FOREMAN') {
    assertControl(
      foremanLineage.replicas.length > 0,
      'GOAL_FOREMAN_LINEAGE_DIVERGED',
      'Goal 没有 current FOREMAN lineage',
    );
  }
  const matches = [];
  for (const task of Object.values(snapshot.tasks || {})) {
    for (const session of Object.values(task.sessions || {})) {
      if (hashesEqual(session.capability_sha256, supplied.sha256)) {
        matches.push({ ...session, task_id: task.task_id });
      }
    }
  }
  assertControl(matches.length > 0, 'CAPABILITY_INVALID', 'capability 不属于当前 Goal 的活动角色');
  assertControl(
    matches.every((session) => session.capability_file === supplied.file),
    'CAPABILITY_INVALID',
    'capability file 与 Goal registration replicas 不一致',
  );
  assertControl(
    matches.every((session) => !options.role || session.role === options.role),
    'CAPABILITY_INVALID',
    `capability role 不是 ${options.role}`,
  );
  assertControl(
    matches.every((session) => (
      options.role !== 'FOREMAN' || session.attempt === currentGoalForemanAttempt
    )),
    'CAPABILITY_SUPERSEDED',
    `FOREMAN capability 已被 Goal attempt=${currentGoalForemanAttempt} supersede`,
  );
  assertControl(
    matches.every((session) => !options.threadId || session.thread_id === options.threadId),
    'CAPABILITY_INVALID',
    'capability thread 不匹配',
  );
  assertControl(
    matches.every((session) => (
      session.role === matches[0].role
        && session.thread_id === matches[0].thread_id
        && session.host_id === matches[0].host_id
        && session.attempt === matches[0].attempt
    )),
    'CORRUPT_STORE',
    'Goal capability replicas identity 分叉',
  );
  const usable = matches
    .filter((session) => (
      ['active', 'idle'].includes(session.status)
        && Date.parse(session.lease_until) > runtimeNowMilliseconds()
    ))
    .sort((left, right) => Date.parse(right.lease_until) - Date.parse(left.lease_until));
  assertControl(
    usable.length > 0,
    matches.some((session) => ['active', 'idle'].includes(session.status))
      ? 'ACTOR_LEASE_EXPIRED'
      : 'ACTOR_UNUSABLE',
    matches.some((session) => ['active', 'idle'].includes(session.status))
      ? `actor replicas lease 均已过期: ${matches.map((session) => session.lease_until).join(',')}`
      : `actor replica statuses=${matches.map((session) => session.status).join(',')}`,
  );
  return usable[0];
}

module.exports = {
  MAX_ROLE_LEASE_MS,
  assertCoherentGoalForemanLineage,
  authorizeGoalSession,
  authorizeSession,
  createCapabilityFile,
  hashesEqual,
  readCapabilityFile,
};
