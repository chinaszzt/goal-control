'use strict';

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ControlError, assertControl } = require('./errors');
const {
  hashObject,
  readOnlyGitEnvironment,
  repoRoot,
  sha256,
  trustedGitExecutable,
} = require('./util');

const CONTROL_PATHS = Object.freeze([
  'scripts/goalctl.js',
  'scripts/goal-control',
]);
const CANARY_CONTROLLER_MODULES = Object.freeze([
  'scripts/goalctl.js',
  'scripts/goal-control/browser-canary-probe.js',
  'scripts/goal-control/browser-canary-server.js',
  'scripts/goal-control/canary-controller-attestation.js',
  'scripts/goal-control/canary-plan.js',
  'scripts/goal-control/cli.js',
]);
const REPLAY_ENV_ASSIGNMENTS = Object.freeze([
  'GIT_CONFIG_GLOBAL=/dev/null',
  'GIT_CONFIG_NOSYSTEM=1',
  'GIT_NO_REPLACE_OBJECTS=1',
  'GIT_OPTIONAL_LOCKS=0',
  'GIT_TERMINAL_PROMPT=0',
  'LANG=C',
  'LC_ALL=C',
  'PATH=/usr/bin:/bin:/usr/sbin',
  'TZ=UTC',
]);
const DANGEROUS_NODE_ENV_KEYS = new Set([
  'NODE_OPTIONS',
  'NODE_PATH',
  'NODE_V8_COVERAGE',
  'LD_PRELOAD',
  'ELECTRON_RUN_AS_NODE',
]);
const REPO_PATH_RE =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;

function gitBytes(repositoryRoot, args, label) {
  try {
    return execFileSync(trustedGitExecutable(), args, {
      cwd: repositoryRoot,
      encoding: null,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...readOnlyGitEnvironment(),
        GIT_LITERAL_PATHSPECS: '1',
        GIT_NO_REPLACE_OBJECTS: '1',
      },
    });
  } catch (error) {
    const detail = String(error.stderr || error.message || '').trim();
    throw new ControlError(
      'CANARY_PLAN_CONTROLLER_ATTESTATION_FAILED',
      `${label} 失败${detail ? ` (${detail})` : ''}`,
    );
  }
}

function repositoryHead(repositoryRoot) {
  const head = gitBytes(
    repositoryRoot,
    ['rev-parse', '--verify', 'HEAD^{commit}'],
    'controller HEAD',
  ).toString('utf8').trim();
  assertControl(
    /^[0-9a-f]{40}$/.test(head),
    'CANARY_PLAN_CONTROLLER_CLOSURE_INVALID',
    'controller HEAD 必须是完整 SHA-1 commit ID',
  );
  return head;
}

function assertNoReplaceRefs(repositoryRoot) {
  const output = gitBytes(
    repositoryRoot,
    [
      'for-each-ref',
      '--count=1',
      '--format=%(refname)',
      'refs/replace',
    ],
    'controller replace ref inventory',
  ).toString('utf8').trim();
  assertControl(
    output.length === 0,
    'CANARY_PLAN_REPLACE_REFS',
    `controller attestation 禁止 Git replace refs: ${output}`,
  );
}

function assertControllerStatusClean(controllerRoot) {
  const status = gitBytes(
    controllerRoot,
    [
      'status',
      '--porcelain=v1',
      '-z',
      '--untracked-files=all',
      '--',
      ...CONTROL_PATHS,
    ],
    'controller worktree status',
  );
  assertControl(
    status.length === 0,
    'CANARY_PLAN_CONTROLLER_DIRTY',
    'controller scripts/goalctl.js 与 scripts/goal-control '
      + '必须全部来自当前 HEAD',
  );
}

function parseNulRecords(bytes, label) {
  if (bytes.length === 0) return [];
  assertControl(
    bytes[bytes.length - 1] === 0,
    'CANARY_PLAN_CONTROLLER_CLOSURE_INVALID',
    `${label} 缺少 NUL terminator`,
  );
  return bytes
    .subarray(0, bytes.length - 1)
    .toString('utf8')
    .split('\0');
}

function controllerTreeEntries(controllerRoot, head) {
  const records = parseNulRecords(
    gitBytes(
      controllerRoot,
      ['ls-tree', '-r', '-z', head, '--', ...CONTROL_PATHS],
      'controller HEAD closure',
    ),
    'controller HEAD closure',
  );
  const entries = records.map((record) => {
    const match =
      /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/.exec(record);
    assertControl(
      match !== null
        && REPO_PATH_RE.test(match[3])
        && (
          match[3] === 'scripts/goalctl.js'
            || match[3].startsWith('scripts/goal-control/')
        ),
      'CANARY_PLAN_CONTROLLER_CLOSURE_INVALID',
      'controller HEAD closure 只允许 scope 内 canonical ordinary blob',
    );
    return { mode: match[1], blob: match[2], path: match[3] };
  }).sort((left, right) => (
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0
  ));
  assertControl(
    entries.length > 0
      && new Set(entries.map((entry) => entry.path)).size === entries.length,
    'CANARY_PLAN_CONTROLLER_CLOSURE_INVALID',
    'controller HEAD closure 为空或含重复 path',
  );
  return entries;
}

function assertControllerIndexFlags(controllerRoot, expectedPaths) {
  const records = parseNulRecords(
    gitBytes(
      controllerRoot,
      ['ls-files', '-v', '-z', '--', ...CONTROL_PATHS],
      'controller index flags',
    ),
    'controller index flags',
  );
  const seen = new Set();
  for (const record of records) {
    const match = /^([^ ]) (.+)$/.exec(record);
    assertControl(
      match !== null
        && match[1] === 'H'
        && !seen.has(match[2]),
      'CANARY_PLAN_CONTROLLER_INDEX_FLAGS',
      'controller index 只允许普通 H flag；拒绝 assume-unchanged/'
        + 'skip-worktree/重复 stage',
    );
    seen.add(match[2]);
  }
  assertControl(
    seen.size === expectedPaths.length
      && expectedPaths.every((relative) => seen.has(relative)),
    'CANARY_PLAN_CONTROLLER_INDEX_FLAGS',
    'controller index path 集合必须与 HEAD closure 完全一致',
  );
}

function fileIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    nlink: stat.nlink,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  };
}

function sameIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function readOrdinaryFileStable(absolute, relative) {
  const before = fs.lstatSync(absolute, { bigint: true });
  assertControl(
    before.isFile() && !before.isSymbolicLink() && before.nlink === 1n,
    'CANARY_PLAN_CONTROLLER_CLOSURE_INVALID',
    `controller closure 必须是单链接 ordinary file: ${relative}`,
  );
  const beforeIdentity = fileIdentity(before);
  let descriptor;
  try {
    descriptor = fs.openSync(
      absolute,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const openedBefore = fs.fstatSync(descriptor, { bigint: true });
    assertControl(
      openedBefore.isFile()
        && sameIdentity(beforeIdentity, fileIdentity(openedBefore)),
      'CANARY_PLAN_CONTROLLER_CHANGED',
      `controller closure path/open identity 漂移: ${relative}`,
    );
    const bytes = fs.readFileSync(descriptor);
    const openedAfter = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(absolute, { bigint: true });
    assertControl(
      sameIdentity(
        fileIdentity(openedBefore),
        fileIdentity(openedAfter),
      )
        && sameIdentity(
          fileIdentity(openedAfter),
          fileIdentity(pathAfter),
        )
        && BigInt(bytes.length) === openedAfter.size,
      'CANARY_PLAN_CONTROLLER_CHANGED',
      `controller closure 在读取期间变化: ${relative}`,
    );
    return { bytes, identity: fileIdentity(openedAfter) };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function gitBlobObjectId(bytes) {
  return crypto
    .createHash('sha1')
    .update(Buffer.from(`blob ${bytes.length}\0`))
    .update(bytes)
    .digest('hex');
}

function assertControllerControlPathsCommitted(controllerRoot, head) {
  const canonicalRoot = fs.realpathSync(repoRoot(controllerRoot));
  assertControl(
    fs.realpathSync(controllerRoot) === canonicalRoot
      && repositoryHead(canonicalRoot) === head,
    'CANARY_PLAN_CONTROLLER_CLOSURE_INVALID',
    'controller root/HEAD 与 attestation target 不匹配',
  );
  assertNoReplaceRefs(canonicalRoot);
  assertControllerStatusClean(canonicalRoot);
  const entries = controllerTreeEntries(canonicalRoot, head);
  const expectedPaths = entries.map((entry) => entry.path);
  assertControllerIndexFlags(canonicalRoot, expectedPaths);
  const captures = new Map();
  const closureFiles = [];
  for (const entry of entries) {
    const capture = readOrdinaryFileStable(
      path.join(canonicalRoot, entry.path),
      entry.path,
    );
    const executable = (capture.identity.mode & 0o111n) !== 0n;
    assertControl(
      gitBlobObjectId(capture.bytes) === entry.blob
        && executable === (entry.mode === '100755'),
      'CANARY_PLAN_CONTROLLER_DIRTY',
      `controller closure bytes/mode 与 HEAD 不一致: ${entry.path}`,
    );
    const current = {
      absolute: path.join(canonicalRoot, entry.path),
      bytes: Buffer.from(capture.bytes),
      identity: capture.identity,
      sha256: `sha256:${sha256(capture.bytes)}`,
    };
    captures.set(entry.path, current);
    closureFiles.push({
      path: entry.path,
      mode: entry.mode,
      blob: entry.blob,
      sha256: current.sha256,
    });
  }
  assertControl(
    repositoryHead(canonicalRoot) === head,
    'CANARY_PLAN_CONTROLLER_CHANGED',
    'controller HEAD 在 closure capture 期间变化',
  );
  assertControllerIndexFlags(canonicalRoot, expectedPaths);
  assertControllerStatusClean(canonicalRoot);
  return {
    closureSha256: hashObject({
      schema_version: 1,
      files: closureFiles,
    }),
    captures,
  };
}

function assertSameControllerCapture(initial, current, label) {
  assertControl(
    current.closureSha256 === initial.closureSha256
      && current.captures.size === initial.captures.size
      && [...initial.captures].every(([relative, capture]) => {
        const next = current.captures.get(relative);
        return next
          && next.sha256 === capture.sha256
          && sameIdentity(next.identity, capture.identity);
      }),
    'CANARY_PLAN_CONTROLLER_CHANGED',
    `${label} controller execution closure 发生变化`,
  );
}

function isJestVmModuleIsolation() {
  return process.env.NODE_ENV === 'test'
    && /^[1-9][0-9]*$/.test(process.env.JEST_WORKER_ID || '')
    && process.env.NODE_OPTIONS === '--experimental-vm-modules';
}

function assertSafeGeneratorNodeRuntime() {
  const jestIsolation = isJestVmModuleIsolation();
  const dangerousEnvironment = Object.keys(process.env)
    .filter((key) => (
      DANGEROUS_NODE_ENV_KEYS.has(key)
        || key.startsWith('LD_')
        || key.startsWith('DYLD_')
    ))
    .filter((key) => !(key === 'NODE_OPTIONS' && jestIsolation));
  const unsafeExecArgv = process.execArgv.filter((argument) => !(
    jestIsolation && argument === '--experimental-vm-modules'
  ));
  assertControl(
    dangerousEnvironment.length === 0 && unsafeExecArgv.length === 0,
    'CANARY_PLAN_UNSAFE_NODE_RUNTIME',
    'canary-plan 拒绝继承 Node/preload/loader/inspect runtime 注入',
    {
      dangerous_environment_keys: dangerousEnvironment.sort(),
      unsafe_exec_argv: unsafeExecArgv,
    },
  );
}

function controllerProvenanceCapture() {
  const controllerRoot = fs.realpathSync(
    repoRoot(path.resolve(__dirname, '..', '..')),
  );
  assertNoReplaceRefs(controllerRoot);
  const head = repositoryHead(controllerRoot);
  const initialClosure = assertControllerControlPathsCommitted(
    controllerRoot,
    head,
  );
  const modules = {};
  for (const relative of CANARY_CONTROLLER_MODULES) {
    const capture = initialClosure.captures.get(relative);
    assertControl(
      capture,
      'CANARY_PLAN_CONTROLLER_CLOSURE_INVALID',
      `controller execution closure 缺少必需 module: ${relative}`,
    );
    modules[relative] = capture.sha256;
  }
  const { controllerDecoderFingerprint } = require('./store');
  const decoderSha256 = controllerDecoderFingerprint();
  const afterDecoderClosure = assertControllerControlPathsCommitted(
    controllerRoot,
    head,
  );
  assertSameControllerCapture(
    initialClosure,
    afterDecoderClosure,
    'decoder fingerprint 后',
  );
  assertNoReplaceRefs(controllerRoot);
  return {
    provenance: {
      root: controllerRoot,
      entrypoint:
        initialClosure.captures.get('scripts/goalctl.js').absolute,
      repository_head: head,
      decoder_sha256: decoderSha256,
      closure_sha256: initialClosure.closureSha256,
      modules,
    },
    controllerRoot,
    closure: initialClosure,
  };
}

function assertControllerProvenanceStable(initial) {
  assertControl(
    repositoryHead(initial.controllerRoot)
      === initial.provenance.repository_head,
    'CANARY_PLAN_CONTROLLER_CHANGED',
    'canary controller HEAD 在 plan 输出前变化',
  );
  const finalClosure = assertControllerControlPathsCommitted(
    initial.controllerRoot,
    initial.provenance.repository_head,
  );
  assertSameControllerCapture(initial.closure, finalClosure, 'plan 输出前');
  assertControl(
    finalClosure.closureSha256 === initial.provenance.closure_sha256,
    'CANARY_PLAN_CONTROLLER_CHANGED',
    'controller closure hash 在 plan 输出前变化',
  );
  const { controllerDecoderFingerprintAt } = require('./store');
  assertControl(
    controllerDecoderFingerprintAt(__dirname)
      === initial.provenance.decoder_sha256,
    'CANARY_PLAN_CONTROLLER_CHANGED',
    'canary controller decoder closure 在 plan 计算期间变化',
  );
  assertNoReplaceRefs(initial.controllerRoot);
}

function replayEnvironmentContract() {
  let executable;
  let stat;
  try {
    executable = fs.realpathSync('/usr/bin/env');
    stat = fs.lstatSync(executable);
  } catch (error) {
    throw new ControlError(
      'CANARY_PLAN_REPLAY_ENV_INVALID',
      `无法解析 canonical /usr/bin/env: ${error.message}`,
    );
  }
  assertControl(
    executable === '/usr/bin/env'
      && stat.isFile()
      && !stat.isSymbolicLink()
      && (stat.mode & 0o111) !== 0,
    'CANARY_PLAN_REPLAY_ENV_INVALID',
    'replay 必须使用 canonical executable /usr/bin/env',
  );
  const contract = {
    schema_version: 1,
    executable,
    clear_inherited: true,
    assignments: [...REPLAY_ENV_ASSIGNMENTS],
  };
  return { ...contract, sha256: hashObject(contract) };
}

function quotePosixShellArgument(value) {
  assertControl(
    typeof value === 'string' && !value.includes('\0'),
    'INVALID_ARGUMENT',
    'replay shell argument 必须是无 NUL 的字符串',
  );
  return `'${value.replace(/'/g, "'\"'\"'")}'`;
}

function replayShellCommand(environment, nodeExecutable, argv) {
  return [
    environment.executable,
    '-i',
    ...environment.assignments,
    nodeExecutable,
    ...argv,
  ].map(quotePosixShellArgument).join(' ');
}

module.exports = {
  assertControllerControlPathsCommitted,
  assertControllerProvenanceStable,
  assertSafeGeneratorNodeRuntime,
  assertSameControllerCapture,
  controllerProvenanceCapture,
  replayEnvironmentContract,
  replayShellCommand,
};
