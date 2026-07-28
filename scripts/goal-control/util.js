'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { ControlError, assertControl } = require('./errors');

const FULL_SHA_RE = /^[0-9a-f]{40}$/;
const SHA256_RE = /^(?:sha256:)?[0-9a-f]{64}$/;
let verifiedTestOverride = null;
let trustedTemporaryRootCache = null;
let trustedGitExecutableCache = null;

const READ_ONLY_GIT_ENVIRONMENT = Object.freeze({
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  GIT_ASKPASS: '/usr/bin/false',
  SSH_ASKPASS: '/usr/bin/false',
  GCM_INTERACTIVE: 'Never',
});

function readOnlyGitEnvironment(overrides = {}) {
  let trustedHome;
  try {
    trustedHome = fs.realpathSync(os.userInfo().homedir);
  } catch (error) {
    throw new ControlError(
      'GIT_FAILED',
      `无法解析可信 OS home: ${error.message}`,
    );
  }
  const safeOverrides = Object.fromEntries(
    Object.entries(overrides).filter(([key]) => (
      !key.startsWith('GIT_')
        && ![
          'HOME',
          'PATH',
          'SSH_ASKPASS',
          'GCM_INTERACTIVE',
        ].includes(key)
    )),
  );
  return {
    PATH: [
      '/usr/bin',
      '/bin',
      '/usr/sbin',
      '/sbin',
      '/opt/homebrew/bin',
      '/usr/local/bin',
    ].join(path.delimiter),
    HOME: trustedHome,
    LANG: process.env.LANG || 'C',
    LC_ALL: 'C',
    ...safeOverrides,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_COUNT: '0',
    ...READ_ONLY_GIT_ENVIRONMENT,
  };
}

function trustedGitExecutable() {
  if (trustedGitExecutableCache) return trustedGitExecutableCache;
  for (const candidate of [
    '/usr/bin/git',
    '/bin/git',
    '/opt/homebrew/bin/git',
    '/usr/local/bin/git',
  ]) {
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) {
        trustedGitExecutableCache = fs.realpathSync(candidate);
        return trustedGitExecutableCache;
      }
    } catch {
      // Continue through fixed installation prefixes; caller PATH is ignored.
    }
  }
  throw new ControlError(
    'GIT_FAILED',
    '固定可信路径中找不到 git',
  );
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((out, key) => {
        out[key] = canonicalize(value[key]);
        return out;
      }, {});
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256(value) {
  const input = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
  return crypto.createHash('sha256').update(input).digest('hex');
}

function hashObject(value) {
  return `sha256:${sha256(canonicalJson(value))}`;
}

function hashFile(file) {
  return `sha256:${sha256(fs.readFileSync(file))}`;
}

function readJson(file, label = file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (error) {
    throw new ControlError('READ_FAILED', `无法读取 ${label}: ${error.message}`);
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new ControlError('INVALID_JSON', `${label} 不是合法 JSON: ${error.message}`);
  }
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) {
      args._.push(token);
      continue;
    }
    const key = token.slice(2).replace(/-/g, '_');
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      index += 1;
    }
  }
  return args;
}

function requireArg(args, key) {
  const value = args[key];
  assertControl(typeof value === 'string' && value.length > 0, 'ARG_REQUIRED', `缺少 --${key.replace(/_/g, '-')}`);
  return value;
}

function optionalInteger(value, label, fallback = null) {
  if (value === undefined || value === null) return fallback;
  const parsed = Number(value);
  assertControl(Number.isSafeInteger(parsed), 'INVALID_ARGUMENT', `${label} 必须是整数`);
  return parsed;
}

function git(cwd, args) {
  try {
    return execFileSync(trustedGitExecutable(), args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: readOnlyGitEnvironment(),
    }).trim();
  } catch (error) {
    const detail = String(error.stderr || error.message || '').trim();
    throw new ControlError('GIT_FAILED', `git ${args.join(' ')} 失败${detail ? `: ${detail}` : ''}`);
  }
}

function repoRoot(cwd) {
  return path.resolve(git(cwd, ['rev-parse', '--show-toplevel']));
}

function trustedTemporaryRoot() {
  if (trustedTemporaryRootCache) return trustedTemporaryRootCache;
  let candidate = '/tmp';
  if (process.platform === 'darwin') {
    try {
      candidate = execFileSync('/usr/bin/getconf', ['DARWIN_USER_TEMP_DIR'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        env: { PATH: '/usr/bin:/bin' },
      }).trim();
    } catch {
      candidate = '/tmp';
    }
  }
  trustedTemporaryRootCache = fs.realpathSync(candidate);
  return trustedTemporaryRootCache;
}

function assertIsolatedTestMode(cwd = null) {
  const override = process.env.GOAL_CONTROL_DIR;
  assertControl(
    process.env.GOAL_CONTROL_TEST_MODE === '1' && typeof override === 'string' && override.length > 0,
    'TEST_MODE_FORBIDDEN',
    '测试覆盖必须同时使用 GOAL_CONTROL_TEST_MODE=1 与隔离 GOAL_CONTROL_DIR'
  );
  const temporaryRoot = trustedTemporaryRoot();
  const resolvedOverride = fs.realpathSync(override);
  assertControl(
    resolvedOverride !== temporaryRoot && resolvedOverride.startsWith(`${temporaryRoot}${path.sep}`),
    'TEST_MODE_FORBIDDEN',
    'GOAL_CONTROL_DIR 测试覆盖必须位于系统临时目录内'
  );
  if (cwd) {
    const resolvedRepository = fs.realpathSync(repoRoot(cwd));
    assertControl(
      resolvedRepository !== temporaryRoot && resolvedRepository.startsWith(`${temporaryRoot}${path.sep}`),
      'TEST_MODE_FORBIDDEN',
      '测试覆盖只能作用于系统临时目录内的隔离 Git 仓库'
    );
    verifiedTestOverride = `${resolvedOverride}\n${resolvedRepository}`;
  } else {
    assertControl(
      typeof verifiedTestOverride === 'string' && verifiedTestOverride.startsWith(`${resolvedOverride}\n`),
      'TEST_MODE_FORBIDDEN',
      '测试时间或 fixture identity 覆盖必须先绑定隔离 Git 仓库'
    );
  }
  return resolvedOverride;
}

function controlRoot(cwd) {
  if (process.env.GOAL_CONTROL_DIR) {
    return assertIsolatedTestMode(cwd);
  }
  const common = git(cwd, ['rev-parse', '--path-format=absolute', '--git-common-dir']);
  return path.join(path.resolve(common), 'goal-control', 'v1');
}

function runtimeNowMilliseconds() {
  const override = process.env.GOAL_CONTROL_NOW;
  if (override === undefined || override === '') return Date.now();
  assertIsolatedTestMode();
  const numeric = Number(override);
  const parsed = Number.isFinite(numeric) ? numeric : Date.parse(override);
  assertControl(Number.isFinite(parsed), 'INVALID_NOW', 'GOAL_CONTROL_NOW 必须是 ISO 时间或毫秒时间戳');
  return parsed;
}

function normalizeHash(value, label = 'sha256') {
  assertControl(typeof value === 'string' && SHA256_RE.test(value), 'INVALID_HASH', `${label} 必须是 64 位 sha256`);
  return value.startsWith('sha256:') ? value : `sha256:${value}`;
}

function assertFullSha(value, label) {
  assertControl(typeof value === 'string' && FULL_SHA_RE.test(value), 'INVALID_FULL_SHA', `${label} 必须是完整 40 位小写 SHA`);
  return value;
}

function safeId(value, label) {
  assertControl(typeof value === 'string' && value.length <= 200 && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value), 'INVALID_ID', `${label} 必须不超过 200 字符，且只能含字母、数字、点、冒号、下划线和连字符`);
  return value;
}

function realpathWithin(root, candidate, label) {
  const resolvedRoot = fs.realpathSync(root);
  const resolved = fs.realpathSync(candidate);
  assertControl(
    resolved === resolvedRoot || resolved.startsWith(`${resolvedRoot}${path.sep}`),
    'PATH_OUTSIDE_REPO',
    `${label} 必须位于仓库内`
  );
  return resolved;
}

function nowIso() {
  return new Date(runtimeNowMilliseconds()).toISOString();
}

function sleepSync(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function randomId(prefix) {
  return `${prefix}-${crypto.randomBytes(12).toString('hex')}`;
}

module.exports = {
  FULL_SHA_RE,
  assertIsolatedTestMode,
  canonicalJson,
  controlRoot,
  git,
  hashFile,
  hashObject,
  normalizeHash,
  nowIso,
  optionalInteger,
  parseArgs,
  randomId,
  readOnlyGitEnvironment,
  readJson,
  realpathWithin,
  repoRoot,
  requireArg,
  safeId,
  sha256,
  sleepSync,
  trustedGitExecutable,
  trustedTemporaryRoot,
  runtimeNowMilliseconds,
  assertFullSha,
};
