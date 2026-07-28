'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { ControlError, assertControl } = require('./errors');
const { fsyncDirectory } = require('./init-receipt');
const {
  readOnlyGitEnvironment,
  sha256,
} = require('./util');

const ZERO_OID = '0'.repeat(40);
const SAFE_GIT_FILE_MODES = new Set([0o600, 0o644]);
const stageInterruptions = new WeakSet();

function transactionCodes(options = {}) {
  return {
    refConflict:
      options.refConflict || 'GIT_LOOSE_REF_TRANSACTION_CONFLICT',
    lockConflict:
      options.lockConflict || 'GIT_LOOSE_REF_LOCK_CONFLICT',
    fenceConflict:
      options.fenceConflict || 'GIT_LOOSE_REF_FENCE_CONFLICT',
    invalidRef:
      options.invalidRef || 'GIT_LOOSE_REF_INVALID',
  };
}

function lstatIfPresent(file, code, label) {
  try {
    return fs.lstatSync(file);
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw new ControlError(
      code,
      `${label} 无法安全 lstat: ${error.message}`,
    );
  }
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function currentUidMatches(stat) {
  return typeof process.getuid !== 'function'
    || stat.uid === process.getuid();
}

function assertOwnedRegular(
  stat,
  code,
  label,
  allowedModes = null,
) {
  assertControl(
    stat
      && stat.isFile()
      && !stat.isSymbolicLink()
      && currentUidMatches(stat)
      && (
        allowedModes === null
          || allowedModes.has(stat.mode & 0o7777)
      ),
    code,
    `${label} 不是当前 uid 的安全普通文件`,
  );
}

function gitResult(cwd, args) {
  try {
    return {
      status: 0,
      stdout: execFileSync('git', args, {
        cwd,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: readOnlyGitEnvironment(),
      }),
      stderr: '',
    };
  } catch (error) {
    return {
      status: Number.isInteger(error && error.status)
        ? error.status
        : -1,
      stdout: String(error && error.stdout || ''),
      stderr: String(error && (error.stderr || error.message) || ''),
    };
  }
}

function gitText(cwd, args, code, label) {
  const result = gitResult(cwd, args);
  if (result.status !== 0) {
    const detail = result.stderr.trim();
    throw new ControlError(
      code,
      `${label} 失败${detail ? `: ${detail}` : ''}`,
    );
  }
  return result.stdout.trim();
}

function assertFilesRefBackend(cwd, commonGitDir, codes, label) {
  assertControl(
    typeof commonGitDir === 'string'
      && path.isAbsolute(commonGitDir)
      && path.normalize(commonGitDir) === commonGitDir,
    codes.invalidRef,
    `${label} common git dir 非法`,
  );
  const stat = lstatIfPresent(
    commonGitDir,
    codes.lockConflict,
    `${label} common git dir`,
  );
  assertControl(
    stat
      && stat.isDirectory()
      && !stat.isSymbolicLink()
      && currentUidMatches(stat),
    codes.lockConflict,
    `${label} common git dir 不是当前 uid 的普通目录`,
  );
  const actual = path.resolve(gitText(
    cwd,
    [
      'rev-parse',
      '--path-format=absolute',
      '--git-common-dir',
    ],
    codes.invalidRef,
    `${label} resolve git-common-dir`,
  ));
  assertControl(
    actual === commonGitDir
      && fs.realpathSync(actual) === fs.realpathSync(commonGitDir),
    codes.invalidRef,
    `${label} cwd/commonGitDir binding 漂移`,
  );
  const storage = gitResult(
    cwd,
    ['config', '--get', 'extensions.refStorage'],
  );
  assertControl(
    (storage.status === 1 && storage.stdout.trim() === '')
      || (
        storage.status === 0
          && storage.stdout.trim().toLowerCase() === 'files'
      ),
    codes.invalidRef,
    `${label} 只支持 files refs backend`,
  );
}

function assertStrictRefName(cwd, ref, codes, label) {
  assertControl(
    typeof ref === 'string'
      && ref.startsWith('refs/')
      && !path.isAbsolute(ref)
      && path.normalize(ref) === ref
      && !ref.includes('\\')
      && !ref.includes('\u0000'),
    codes.invalidRef,
    `${label} ref name 非法`,
  );
  const checked = gitResult(cwd, ['check-ref-format', ref]);
  assertControl(
    checked.status === 0,
    codes.invalidRef,
    `${label} ref 未通过 git check-ref-format`,
  );
}

function looseRefLocation(commonGitDir, ref) {
  const refFile = path.join(commonGitDir, ...ref.split('/'));
  const relative = path.relative(commonGitDir, refFile);
  return {
    commonGitDir,
    ref,
    refFile,
    refParent: path.dirname(refFile),
    refLock: `${refFile}.lock`,
    packedRefs: path.join(commonGitDir, 'packed-refs'),
    packedLock: path.join(commonGitDir, 'packed-refs.lock'),
    logFile: path.join(commonGitDir, 'logs', ...ref.split('/')),
    logParent: path.join(
      commonGitDir,
      'logs',
      ...ref.split('/').slice(0, -1),
    ),
    safeRelative: (
      relative.length > 0
        && !path.isAbsolute(relative)
        && relative !== '..'
        && !relative.startsWith(`..${path.sep}`)
    ),
  };
}

function ordinaryParentExists(
  commonGitDir,
  target,
  codes,
  label,
) {
  const relative = path.relative(commonGitDir, target);
  assertControl(
    relative === ''
      || (
        !path.isAbsolute(relative)
          && relative !== '..'
          && !relative.startsWith(`..${path.sep}`)
      ),
    codes.invalidRef,
    `${label} path 逃逸 common git dir`,
  );
  let current = commonGitDir;
  for (const component of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    const stat = lstatIfPresent(
      current,
      codes.lockConflict,
      `${label} parent`,
    );
    if (!stat) return false;
    assertControl(
      stat.isDirectory()
        && !stat.isSymbolicLink()
        && currentUidMatches(stat),
      codes.lockConflict,
      `${label} parent 不是当前 uid 的普通目录`,
    );
  }
  return true;
}

function ensureRefParent(location, codes, label) {
  const relative = path.relative(
    location.commonGitDir,
    location.refParent,
  );
  let current = location.commonGitDir;
  for (const component of relative.split(path.sep).filter(Boolean)) {
    const parent = current;
    current = path.join(current, component);
    let stat = lstatIfPresent(
      current,
      codes.lockConflict,
      `${label} ref parent`,
    );
    if (!stat) {
      try {
        fs.mkdirSync(current, { mode: 0o700 });
        fsyncDirectory(parent);
      } catch (error) {
        if (!error || error.code !== 'EEXIST') {
          throw new ControlError(
            codes.lockConflict,
            `${label} 无法建立 deterministic ref parent: ${
              error.message
            }`,
          );
        }
      }
      stat = lstatIfPresent(
        current,
        codes.lockConflict,
        `${label} ref parent`,
      );
    }
    assertControl(
      stat
        && stat.isDirectory()
        && !stat.isSymbolicLink()
        && currentUidMatches(stat),
      codes.lockConflict,
      `${label} ref parent 不是当前 uid 的普通目录`,
    );
  }
}

function directoryEntries(directory, codes, label) {
  try {
    return fs.readdirSync(directory);
  } catch (error) {
    throw new ControlError(
      codes.lockConflict,
      `${label} 无法扫描 inventory: ${error.message}`,
    );
  }
}

function refLockCandidate(location, codes, label) {
  if (!ordinaryParentExists(
    location.commonGitDir,
    location.refParent,
    codes,
    label,
  )) {
    return null;
  }
  const lockName = path.basename(location.refLock);
  const lower = lockName.toLowerCase();
  const candidates = directoryEntries(
    location.refParent,
    codes,
    `${label} ref-lock`,
  ).filter((entry) => (
    entry === lockName
      || entry.startsWith(`${lockName}.`)
      || entry.toLowerCase() === lower
  ));
  assertControl(
    candidates.length <= 1,
    codes.lockConflict,
    `${label} multiple ref-lock candidates: ${
      candidates.sort().join(', ')
    }`,
  );
  if (candidates.length === 0) return null;
  assertControl(
    candidates[0] === lockName,
    codes.lockConflict,
    `${label} foreign ref-lock candidate: ${candidates[0]}`,
  );
  return location.refLock;
}

function packedLockCandidate(location, codes, label) {
  const lockName = path.basename(location.packedLock);
  const lower = lockName.toLowerCase();
  const candidates = directoryEntries(
    location.commonGitDir,
    codes,
    `${label} packed-lock`,
  ).filter((entry) => (
    entry === lockName
      || entry.startsWith(`${lockName}.`)
      || entry.toLowerCase() === lower
  ));
  assertControl(
    candidates.length <= 1,
    codes.lockConflict,
    `${label} multiple packed-refs.lock candidates: ${
      candidates.sort().join(', ')
    }`,
  );
  if (candidates.length === 0) return null;
  assertControl(
    candidates[0] === lockName,
    codes.lockConflict,
    `${label} foreign packed-refs.lock candidate: ${candidates[0]}`,
  );
  return location.packedLock;
}

function readExactRef(cwd, ref, codes, label) {
  const result = gitResult(
    cwd,
    ['rev-parse', '--verify', '--quiet', ref],
  );
  if (result.status === 1) return null;
  if (result.status !== 0) {
    throw new ControlError(
      codes.refConflict,
      `${label} 无法读取 canonical ref: ${result.stderr.trim()}`,
    );
  }
  return result.stdout.trim();
}

function actualRef(oid) {
  return oid === ZERO_OID ? null : oid;
}

function classifyRef(
  cwd,
  location,
  expectedOld,
  expectedNew,
  allowedFinalRefs,
  codes,
  label,
) {
  const current = readExactRef(cwd, location.ref, codes, label);
  if (
    current === actualRef(expectedNew)
      || allowedFinalRefs.includes(current)
  ) {
    return { kind: 'final', current };
  }
  if (current === actualRef(expectedOld)) {
    return { kind: 'old', current };
  }
  throw new ControlError(
    codes.refConflict,
    `${label} canonical ref ${current} 不是 expected old/new`,
  );
}

function readLooseRefStat(location, codes, label) {
  if (!ordinaryParentExists(
    location.commonGitDir,
    location.refParent,
    codes,
    label,
  )) {
    return null;
  }
  return lstatIfPresent(
    location.refFile,
    codes.lockConflict,
    `${label} canonical ref`,
  );
}

function readStableFile(file, stat, code, label) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const opened = fs.fstatSync(descriptor);
    assertControl(
      sameInode(stat, opened),
      code,
      `${label} open 后 inode 漂移`,
    );
    return {
      stat: opened,
      body: fs.readFileSync(descriptor),
    };
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      code,
      `${label} 无法 no-follow read: ${error.message}`,
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function assertCanonicalLooseOid(location, oid, codes, label) {
  const stat = readLooseRefStat(location, codes, label);
  if (oid === ZERO_OID) {
    assertControl(
      stat === null,
      codes.lockConflict,
      `${label} expected zero 但 loose canonical ref 已存在`,
    );
    return null;
  }
  assertOwnedRegular(
    stat,
    codes.lockConflict,
    `${label} loose canonical ref`,
    SAFE_GIT_FILE_MODES,
  );
  assertControl(
    stat.nlink === 1,
    codes.lockConflict,
    `${label} expected ref 不是 single-link loose ref`,
  );
  const opened = readStableFile(
    location.refFile,
    stat,
    codes.lockConflict,
    `${label} loose canonical ref`,
  );
  assertControl(
    opened.body.equals(Buffer.from(`${oid}\n`, 'ascii')),
    codes.lockConflict,
    `${label} loose canonical bytes 不是 exact OID`,
  );
  return opened.stat;
}

function assertExpectedOldStorage(
  options,
  location,
  packedOid,
  codes,
) {
  if (options.expectedOld === ZERO_OID) {
    return assertCanonicalLooseOid(
      location,
      ZERO_OID,
      codes,
      options.label,
    );
  }
  const loose = readLooseRefStat(
    location,
    codes,
    options.label,
  );
  if (loose) {
    return assertCanonicalLooseOid(
      location,
      options.expectedOld,
      codes,
      options.label,
    );
  }
  assertControl(
    options.expectedNew !== ZERO_OID
      && packedOid === options.expectedOld,
    codes.lockConflict,
    `${options.label} expected old 既非 exact loose 也非 exact packed update`,
  );
  return null;
}

function inspectLooseRefFence(options) {
  const codes = transactionCodes(options.codes);
  const {
    fenceFile,
    expectedNew,
    label = 'loose-ref fence',
  } = options;
  assertControl(
    typeof fenceFile === 'string'
      && path.isAbsolute(fenceFile)
      && /^[0-9a-f]{40}$/.test(expectedNew),
    codes.fenceConflict,
    `${label} path/expected-new 非法`,
  );
  const stat = lstatIfPresent(
    fenceFile,
    codes.fenceConflict,
    label,
  );
  if (!stat) return null;
  assertOwnedRegular(
    stat,
    codes.fenceConflict,
    label,
    new Set([0o600]),
  );
  const opened = readStableFile(
    fenceFile,
    stat,
    codes.fenceConflict,
    label,
  );
  const expected = Buffer.from(`${expectedNew}\n`, 'ascii');
  assertControl(
    opened.stat.nlink >= 1
      && opened.stat.nlink <= 3
      && opened.body.length <= expected.length
      && expected.subarray(0, opened.body.length).equals(opened.body)
      && (
        opened.stat.nlink === 1
          || opened.body.length === expected.length
      ),
    codes.fenceConflict,
    `${label} 必须是 expected-new prefix；linked fence 必须完整`,
  );
  return { stat: opened.stat, body: opened.body, expected };
}

function writeRange(descriptor, body, start, end, code, label) {
  let offset = start;
  while (offset < end) {
    const written = fs.writeSync(
      descriptor,
      body,
      offset,
      end - offset,
      offset,
    );
    assertControl(
      Number.isSafeInteger(written) && written > 0,
      code,
      `${label} write 没有取得进展`,
    );
    offset += written;
  }
}

function invokeStage(options, stage) {
  if (typeof options.onStage !== 'function') return;
  try {
    options.onStage(stage);
  } catch (error) {
    if (
      error
        && (
          typeof error === 'object'
            || typeof error === 'function'
        )
    ) {
      stageInterruptions.add(error);
    }
    throw error;
  }
}

function installFence(options, codes) {
  const expected = Buffer.from(`${options.expectedNew}\n`, 'ascii');
  const parent = path.dirname(options.fenceFile);
  const parentStat = lstatIfPresent(
    parent,
    codes.fenceConflict,
    `${options.label} fence parent`,
  );
  assertControl(
    parentStat
      && parentStat.isDirectory()
      && !parentStat.isSymbolicLink()
      && (parentStat.mode & 0o7777) === 0o700
      && currentUidMatches(parentStat),
    codes.fenceConflict,
    `${options.label} fence parent 必须是当前 uid 的 0700 普通目录`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      options.fenceFile,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.fchmodSync(descriptor, 0o600);
    const midpoint = Math.max(1, Math.floor(expected.length / 2));
    writeRange(
      descriptor,
      expected,
      0,
      midpoint,
      codes.fenceConflict,
      options.label,
    );
    fs.fsyncSync(descriptor);
    fsyncDirectory(parent);
    invokeStage(options, 'fence-partial');
    writeRange(
      descriptor,
      expected,
      midpoint,
      expected.length,
      codes.fenceConflict,
      options.label,
    );
    fs.fsyncSync(descriptor);
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      codes.fenceConflict,
      `${options.label} 无法 no-replace publish fence: ${
        error.message
      }`,
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  fsyncDirectory(parent);
  const installed = inspectLooseRefFence({
    fenceFile: options.fenceFile,
    expectedNew: options.expectedNew,
    codes,
    label: options.label,
  });
  assertControl(
    installed && installed.body.equals(installed.expected),
    codes.fenceConflict,
    `${options.label} durable fence bytes 不完整`,
  );
  invokeStage(options, 'fence-durable');
  return installed;
}

function repairFence(options, fence, codes) {
  if (fence.body.equals(fence.expected)) return fence;
  assertControl(
    fence.stat.nlink === 1,
    codes.fenceConflict,
    `${options.label} partial linked fence 禁止修复`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      options.fenceFile,
      fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0),
    );
    const opened = fs.fstatSync(descriptor);
    assertControl(
      sameInode(fence.stat, opened)
        && opened.nlink === 1
        && (opened.mode & 0o7777) === 0o600,
      codes.fenceConflict,
      `${options.label} partial fence inode/mode 漂移`,
    );
    writeRange(
      descriptor,
      fence.expected,
      fence.body.length,
      fence.expected.length,
      codes.fenceConflict,
      options.label,
    );
    fs.ftruncateSync(descriptor, fence.expected.length);
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(options.fenceFile));
  const repaired = inspectLooseRefFence({
    fenceFile: options.fenceFile,
    expectedNew: options.expectedNew,
    codes,
    label: options.label,
  });
  assertControl(
    repaired
      && sameInode(fence.stat, repaired.stat)
      && repaired.body.equals(repaired.expected),
    codes.fenceConflict,
    `${options.label} partial fence repair 未保留 exact inode`,
  );
  return repaired;
}

function describeReflogFile(location, codes, label) {
  if (!ordinaryParentExists(
    location.commonGitDir,
    location.logParent,
    codes,
    `${label} reflog`,
  )) {
    return { exists: false };
  }
  const stat = lstatIfPresent(
    location.logFile,
    codes.lockConflict,
    `${label} reflog`,
  );
  if (!stat) return { exists: false };
  assertOwnedRegular(
    stat,
    codes.lockConflict,
    `${label} reflog`,
    SAFE_GIT_FILE_MODES,
  );
  assertControl(
    stat.nlink === 1,
    codes.lockConflict,
    `${label} reflog 不是 single-link file`,
  );
  const opened = readStableFile(
    location.logFile,
    stat,
    codes.lockConflict,
    `${label} reflog`,
  );
  return {
    exists: true,
    dev: String(opened.stat.dev),
    ino: String(opened.stat.ino),
    mode: opened.stat.mode & 0o7777,
    uid: opened.stat.uid,
    nlink: opened.stat.nlink,
    size: opened.stat.size,
    sha256: `sha256:${sha256(opened.body)}`,
  };
}

function validateReflogDescriptor(value, codes, label) {
  assertControl(
    value
      && typeof value === 'object'
      && !Array.isArray(value)
      && (
        (
          value.exists === false
            && Object.keys(value).length === 1
        )
          || (
            value.exists === true
              && Object.keys(value).sort().join(',')
                === [
                  'dev',
                  'exists',
                  'ino',
                  'mode',
                  'nlink',
                  'sha256',
                  'size',
                  'uid',
                ].sort().join(',')
              && /^[0-9]+$/.test(value.dev)
              && /^[0-9]+$/.test(value.ino)
              && SAFE_GIT_FILE_MODES.has(value.mode)
              && Number.isSafeInteger(value.uid)
              && value.nlink === 1
              && Number.isSafeInteger(value.size)
              && value.size >= 0
              && /^sha256:[0-9a-f]{64}$/.test(value.sha256)
          )
      ),
    codes.invalidRef,
    `${label} durable expected reflog descriptor 非法`,
  );
}

function reflogLockCandidates(location, codes, label) {
  if (!ordinaryParentExists(
    location.commonGitDir,
    location.logParent,
    codes,
    `${label} reflog`,
  )) {
    return [];
  }
  const name = `${path.basename(location.logFile)}.lock`;
  const lower = name.toLowerCase();
  return directoryEntries(
    location.logParent,
    codes,
    `${label} reflog-lock`,
  ).filter((entry) => (
    entry === name
      || entry.startsWith(`${name}.`)
      || entry.toLowerCase() === lower
  ));
}

function assertReflogExpectation(
  location,
  options,
  codes,
) {
  const locks = reflogLockCandidates(
    location,
    codes,
    options.label,
  );
  assertControl(
    locks.length === 0,
    codes.lockConflict,
    `${options.label} 发现 reflog lock artifacts: ${
      locks.sort().join(', ')
    }`,
  );
  const actual = describeReflogFile(
    location,
    codes,
    options.label,
  );
  if (options.reflogPolicy === 'absent') {
    assertControl(
      actual.exists === false,
      codes.lockConflict,
      `${options.label} internal ref 已有 foreign reflog`,
    );
    return;
  }
  assertControl(
    options.reflogPolicy === 'preserve',
    codes.invalidRef,
    `${options.label} reflogPolicy 必须是 absent/preserve`,
  );
  validateReflogDescriptor(
    options.expectedReflog,
    codes,
    options.label,
  );
  const exactDescriptor = (
    Object.keys(actual).length
      === Object.keys(options.expectedReflog).length
        && Object.keys(actual).every((key) => (
          actual[key] === options.expectedReflog[key]
        ))
  );
  if (exactDescriptor) return;

  const extension = options.allowedReflogExtension;
  assertControl(
    extension
      && typeof extension === 'object'
      && !Array.isArray(extension)
      && Object.keys(extension).sort().join(',') === 'new,old'
      && /^[0-9a-f]{40}$/.test(extension.old)
      && /^[0-9a-f]{40}$/.test(extension.new)
      && extension.old !== extension.new
      && actual.exists === true,
    codes.lockConflict,
    `${options.label} reflog 与 durable expected descriptor 漂移`,
  );

  const stat = lstatIfPresent(
    location.logFile,
    codes.lockConflict,
    `${options.label} reflog extension`,
  );
  assertOwnedRegular(
    stat,
    codes.lockConflict,
    `${options.label} reflog extension`,
    SAFE_GIT_FILE_MODES,
  );
  assertControl(
    stat.nlink === 1,
    codes.lockConflict,
    `${options.label} reflog extension 不是 single-link file`,
  );
  const opened = readStableFile(
    location.logFile,
    stat,
    codes.lockConflict,
    `${options.label} reflog extension`,
  );
  const descriptor = {
    exists: true,
    dev: String(opened.stat.dev),
    ino: String(opened.stat.ino),
    mode: opened.stat.mode & 0o7777,
    uid: opened.stat.uid,
    nlink: opened.stat.nlink,
    size: opened.stat.size,
    sha256: `sha256:${sha256(opened.body)}`,
  };
  assertControl(
    Object.keys(actual).every((key) => actual[key] === descriptor[key]),
    codes.lockConflict,
    `${options.label} reflog extension read 期间 descriptor 漂移`,
  );

  let suffix = opened.body;
  if (options.expectedReflog.exists) {
    const expected = options.expectedReflog;
    assertControl(
      descriptor.dev === expected.dev
        && descriptor.ino === expected.ino
        && descriptor.mode === expected.mode
        && descriptor.uid === expected.uid
        && descriptor.nlink === expected.nlink
        && descriptor.size > expected.size,
      codes.lockConflict,
      `${options.label} reflog extension 未保留 sealed inode/metadata prefix`,
    );
    const prefix = opened.body.subarray(0, expected.size);
    assertControl(
      `sha256:${sha256(prefix)}` === expected.sha256
        && (
          prefix.length === 0
            || prefix[prefix.length - 1] === 0x0a
        ),
      codes.lockConflict,
      `${options.label} reflog extension 的 sealed prefix 漂移或未按行闭合`,
    );
    suffix = opened.body.subarray(expected.size);
  }
  assertControl(
    suffix.length > 0
      && suffix[suffix.length - 1] === 0x0a,
    codes.lockConflict,
    `${options.label} reflog extension 必须是非空完整行`,
  );
  const text = suffix.toString('utf8');
  assertControl(
    Buffer.from(text, 'utf8').equals(suffix),
    codes.lockConflict,
    `${options.label} reflog extension 不是 canonical UTF-8`,
  );
  const expectedPrefix = `${extension.old} ${extension.new} `;
  const lines = text.slice(0, -1).split('\n');
  const observedTransitions = lines.map((line) => {
    const match = /^([0-9a-f]{40}) ([0-9a-f]{40}) /.exec(line);
    return match ? `${match[1]}→${match[2]}` : '<malformed>';
  });
  assertControl(
    lines.length > 0
      && lines.every((line) => (
        line.startsWith(expectedPrefix)
          && line.length > expectedPrefix.length
          && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(line)
      )),
    codes.lockConflict,
    `${options.label} reflog extension 含非授权 old→new transition；expected=${
      extension.old
    }→${extension.new}；observed=${observedTransitions.join(',')}`,
  );
}

function describeLooseRefReflog(options) {
  const codes = transactionCodes(options.codes);
  const label = options.label || `loose-ref ${options.ref}`;
  assertFilesRefBackend(
    options.cwd,
    options.commonGitDir,
    codes,
    label,
  );
  assertStrictRefName(options.cwd, options.ref, codes, label);
  const location = looseRefLocation(options.commonGitDir, options.ref);
  assertControl(
    location.safeRelative,
    codes.invalidRef,
    `${label} ref 逃逸 common git dir`,
  );
  const locks = reflogLockCandidates(location, codes, label);
  assertControl(
    locks.length === 0,
    codes.lockConflict,
    `${label} 发现 reflog lock artifacts`,
  );
  return describeReflogFile(location, codes, label);
}

function packedRefOid(location, codes, label) {
  const stat = lstatIfPresent(
    location.packedRefs,
    codes.lockConflict,
    `${label} packed-refs`,
  );
  if (!stat) return null;
  assertOwnedRegular(
    stat,
    codes.lockConflict,
    `${label} packed-refs`,
    SAFE_GIT_FILE_MODES,
  );
  assertControl(
    stat.nlink === 1,
    codes.lockConflict,
    `${label} packed-refs 不是 single-link file`,
  );
  const opened = readStableFile(
    location.packedRefs,
    stat,
    codes.lockConflict,
    `${label} packed-refs`,
  );
  const lines = opened.body.toString('utf8').split('\n');
  let found = null;
  for (const line of lines) {
    if (
      line === ''
        || line.startsWith('#')
        || /^\^[0-9a-f]{40}$/.test(line)
    ) {
      continue;
    }
    const match = /^([0-9a-f]{40}) (.+)$/.exec(line);
    assertControl(
      match,
      codes.lockConflict,
      `${label} packed-refs 含 malformed line`,
    );
    if (match[2] !== location.ref) continue;
    assertControl(
      found === null,
      codes.lockConflict,
      `${label} packed-refs 含 duplicate 同名 ref`,
    );
    found = match[1];
  }
  return found;
}

function assertPackedRefPolicy(options, location, codes) {
  const oid = packedRefOid(location, codes, options.label);
  if (
    options.expectedOld === ZERO_OID
      || options.expectedNew === ZERO_OID
  ) {
    assertControl(
      oid === null,
      codes.lockConflict,
      `${options.label} create/delete 禁止 packed 同名 ref`,
    );
    return oid;
  }
  assertControl(
    oid === null || oid === options.expectedOld,
    codes.lockConflict,
    `${options.label} packed 同名 ref 不是 exact expected old`,
  );
  return oid;
}

function assertNoFenceExpectedNew(
  options,
  location,
  codes,
) {
  const assertNoLocks = (phase) => {
    assertControl(
      refLockCandidate(location, codes, options.label) === null
        && packedLockCandidate(location, codes, options.label) === null,
      codes.lockConflict,
      `${options.label} packed-final ${phase} 出现 lock artifacts`,
    );
  };
  assertNoLocks('validation 前');
  const loose = readLooseRefStat(
    location,
    codes,
    options.label,
  );
  if (loose) {
    assertCanonicalLooseOid(
      location,
      options.expectedNew,
      codes,
      options.label,
    );
  } else {
    assertControl(
      packedRefOid(location, codes, options.label)
        === options.expectedNew,
      codes.lockConflict,
      `${options.label} final ref 既非 exact loose 也非 exact packed`,
    );
  }
  assertReflogExpectation(location, options, codes);
  const stable = classifyRef(
    options.cwd,
    location,
    options.expectedOld,
    options.expectedNew,
    options.allowedFinalRefs,
    codes,
    options.label,
  );
  assertControl(
    stable.current === options.expectedNew,
    codes.refConflict,
    `${options.label} packed-final validation 后 canonical 漂移`,
  );
  assertNoLocks('validation 后');
  return stable.current;
}

function inspectOwnedTopology(
  location,
  fence,
  codes,
  label,
) {
  const freshFence = inspectLooseRefFence({
    fenceFile: fence.file,
    expectedNew: fence.expectedNew,
    codes,
    label,
  });
  const packedPath = packedLockCandidate(location, codes, label);
  const refLockPath = refLockCandidate(location, codes, label);
  const packed = packedPath
    ? lstatIfPresent(
      packedPath,
      codes.lockConflict,
      `${label} packed-refs.lock`,
    )
    : null;
  const refLock = refLockPath
    ? lstatIfPresent(
      refLockPath,
      codes.lockConflict,
      `${label} ref.lock`,
    )
    : null;
  const canonical = readLooseRefStat(location, codes, label);
  for (const [name, stat] of [
    ['packed-refs.lock', packed],
    ['ref.lock', refLock],
  ]) {
    if (!stat) continue;
    assertOwnedRegular(
      stat,
      codes.lockConflict,
      `${label} ${name}`,
      new Set([0o600]),
    );
    assertControl(
      sameInode(freshFence.stat, stat),
      codes.lockConflict,
      `${label} ${name} 不是 durable fence 的 hard-link`,
    );
  }
  const canonicalOwned = Boolean(
    canonical && sameInode(freshFence.stat, canonical),
  );
  if (canonicalOwned) {
    assertOwnedRegular(
      canonical,
      codes.lockConflict,
      `${label} owned canonical`,
      new Set([0o600]),
    );
  }
  const knownLinks = 1
    + (packed ? 1 : 0)
    + (refLock ? 1 : 0)
    + (canonicalOwned ? 1 : 0);
  assertControl(
    freshFence.stat.nlink === knownLinks,
    codes.fenceConflict,
    `${label} fence nlink=${freshFence.stat.nlink} 与 known topology=${knownLinks} 不符`,
  );
  return {
    fence: freshFence,
    packed,
    refLock,
    canonical,
    canonicalOwned,
  };
}

function linkFence(
  options,
  destination,
  directory,
  stage,
  codes,
) {
  try {
    fs.linkSync(options.fenceFile, destination);
  } catch (error) {
    throw new ControlError(
      codes.lockConflict,
      `${options.label} 无法 O_EXCL hard-link ${path.basename(
        destination,
      )}: ${error.message}`,
    );
  }
  fsyncDirectory(directory);
  invokeStage(options, stage);
}

function unlinkOwned(
  options,
  file,
  directory,
  stage,
  codes,
) {
  const fence = inspectLooseRefFence({
    fenceFile: options.fenceFile,
    expectedNew: options.expectedNew,
    codes,
    label: options.label,
  });
  const target = lstatIfPresent(
    file,
    codes.lockConflict,
    `${options.label} ${path.basename(file)}`,
  );
  assertControl(
    target && sameInode(fence.stat, target),
    codes.lockConflict,
    `${options.label} refusing to unlink non-owned ${path.basename(file)}`,
  );
  fs.unlinkSync(file);
  fsyncDirectory(directory);
  invokeStage(options, stage);
}

function cleanupFence(
  options,
  codes,
  expectedTopology = { ownedCanonical: null },
) {
  const fence = inspectLooseRefFence({
    fenceFile: options.fenceFile,
    expectedNew: options.expectedNew,
    codes,
    label: options.label,
  });
  assertControl(
    fence && fence.stat.nlink >= 1,
    codes.fenceConflict,
    `${options.label} cleanup fence 缺失`,
  );
  if (expectedTopology.ownedCanonical) {
    const canonical = readLooseRefStat(
      expectedTopology.location,
      codes,
      options.label,
    );
    assertOwnedRegular(
      canonical,
      codes.lockConflict,
      `${options.label} cleanup owned canonical`,
      new Set([0o600]),
    );
    assertControl(
      sameInode(fence.stat, canonical)
        && fence.stat.nlink === 2
        && canonical.nlink === 2,
      codes.fenceConflict,
      `${options.label} cleanup 前 fence/canonical 不再是 exact remaining hard-link topology`,
    );
  } else {
    assertControl(
      fence.stat.nlink === 1,
      codes.fenceConflict,
      `${options.label} cleanup 前 fence 仍有未解释 hard-link`,
    );
  }
  // This revalidation closes deterministic replacement windows at adapter
  // stage boundaries. Node/POSIX has no inode-conditional unlink primitive:
  // an actively hostile same-UID process can still exchange this pathname
  // after the check and before unlink. That threat requires a host broker or
  // an openat/unlinkat native adapter; do not claim this userspace check as
  // isolation from arbitrary same-UID metadata writes.
  fs.unlinkSync(options.fenceFile);
  fsyncDirectory(path.dirname(options.fenceFile));
  invokeStage(options, 'fence-cleaned');
}

function releasePackedOnlyForFreshValidation(
  options,
  location,
  topology,
  codes,
) {
  assertControl(
    topology.packed
      && !topology.refLock
      && !topology.canonicalOwned
      && topology.fence.stat.nlink === 2,
    codes.lockConflict,
    `${options.label} packed-only recovery topology 非法`,
  );
  unlinkOwned(
    options,
    location.packedLock,
    location.commonGitDir,
    'packed-lock-released',
    codes,
  );
}

function acquireBothLocks(options, location, codes) {
  let fence = inspectLooseRefFence({
    fenceFile: options.fenceFile,
    expectedNew: options.expectedNew,
    codes,
    label: options.label,
  });
  ensureRefParent(location, codes, options.label);
  const parentStat = fs.lstatSync(location.refParent);
  assertControl(
    parentStat.dev === fence.stat.dev,
    codes.lockConflict,
    `${options.label} fence/ref 不在同一 filesystem`,
  );
  let topology = inspectOwnedTopology(
    location,
    {
      file: options.fenceFile,
      expectedNew: options.expectedNew,
    },
    codes,
    options.label,
  );
  if (topology.packed && !topology.refLock) {
    releasePackedOnlyForFreshValidation(
      options,
      location,
      topology,
      codes,
    );
    topology = inspectOwnedTopology(
      location,
      {
        file: options.fenceFile,
        expectedNew: options.expectedNew,
      },
      codes,
      options.label,
    );
  }
  assertControl(
    !topology.packed
      && !topology.refLock
      && !topology.canonicalOwned
      && topology.fence.stat.nlink === 1,
    codes.lockConflict,
    `${options.label} fresh lock acquisition 前 topology 非法`,
  );
  linkFence(
    options,
    location.packedLock,
    location.commonGitDir,
    'packed-lock-linked',
    codes,
  );
  fence = inspectLooseRefFence({
    fenceFile: options.fenceFile,
    expectedNew: options.expectedNew,
    codes,
    label: options.label,
  });
  assertControl(
    fence.stat.nlink === 2,
    codes.fenceConflict,
    `${options.label} packed side-fence nlink 非 2`,
  );
  linkFence(
    options,
    location.refLock,
    location.refParent,
    'ref-lock-linked',
    codes,
  );
  topology = inspectOwnedTopology(
    location,
    {
      file: options.fenceFile,
      expectedNew: options.expectedNew,
    },
    codes,
    options.label,
  );
  assertControl(
    topology.packed
      && topology.refLock
      && !topology.canonicalOwned
      && topology.fence.stat.nlink === 3,
    codes.lockConflict,
    `${options.label} dual-lock topology 非法`,
  );
  return topology;
}

function assertPreimageWithBothLocks(
  options,
  location,
  codes,
) {
  const topology = inspectOwnedTopology(
    location,
    {
      file: options.fenceFile,
      expectedNew: options.expectedNew,
    },
    codes,
    options.label,
  );
  assertControl(
    topology.packed
      && topology.refLock
      && !topology.canonicalOwned
      && topology.fence.stat.nlink === 3,
    codes.lockConflict,
    `${options.label} preimage validation 缺 dual owned locks`,
  );
  const packedOid = assertPackedRefPolicy(
    options,
    location,
    codes,
  );
  assertReflogExpectation(location, options, codes);
  const state = classifyRef(
    options.cwd,
    location,
    options.expectedOld,
    options.expectedNew,
    options.allowedFinalRefs,
    codes,
    options.label,
  );
  assertControl(
    state.kind === 'old',
    codes.refConflict,
    `${options.label} dual-lock 后 canonical 已非 expected old`,
  );
  const oldStat = assertExpectedOldStorage(
    options,
    location,
    packedOid,
    codes,
  );
  return { topology, oldStat, packedOid };
}

function closeExpectedNew(options, location, codes) {
  let topology = inspectOwnedTopology(
    location,
    {
      file: options.fenceFile,
      expectedNew: options.expectedNew,
    },
    codes,
    options.label,
  );
  if (!topology.packed) {
    linkFence(
      options,
      location.packedLock,
      location.commonGitDir,
      'packed-lock-linked',
      codes,
    );
    topology = inspectOwnedTopology(
      location,
      {
        file: options.fenceFile,
        expectedNew: options.expectedNew,
      },
      codes,
      options.label,
    );
  }
  assertControl(
    topology.packed,
    codes.lockConflict,
    `${options.label} close 缺 transaction-owned packed side-fence`,
  );
  assertPackedRefPolicy(options, location, codes);
  assertReflogExpectation(location, options, codes);
  const state = classifyRef(
    options.cwd,
    location,
    options.expectedOld,
    options.expectedNew,
    options.allowedFinalRefs,
    codes,
    options.label,
  );
  assertControl(
    state.current === actualRef(options.expectedNew),
    codes.refConflict,
    `${options.label} close 时 canonical 不是 expected new`,
  );
  if (options.expectedNew === ZERO_OID) {
    assertControl(
      !topology.canonical,
      codes.lockConflict,
      `${options.label} delete close 仍有 loose canonical`,
    );
    if (topology.refLock) {
      unlinkOwned(
        options,
        location.refLock,
        location.refParent,
        'ref-lock-released',
        codes,
      );
    }
  } else {
    assertControl(
      topology.canonicalOwned
        && !topology.refLock,
      codes.lockConflict,
      `${options.label} published canonical 不是 owned fence inode`,
    );
  }
  topology = inspectOwnedTopology(
    location,
    {
      file: options.fenceFile,
      expectedNew: options.expectedNew,
    },
    codes,
    options.label,
  );
  if (topology.packed) {
    unlinkOwned(
      options,
      location.packedLock,
      location.commonGitDir,
      'packed-lock-released',
      codes,
    );
  }
  assertReflogExpectation(location, options, codes);
  cleanupFence(options, codes, {
    ownedCanonical: options.expectedNew !== ZERO_OID,
    location,
  });
  const finalStat = assertCanonicalLooseOid(
    location,
    options.expectedNew,
    codes,
    options.label,
  );
  if (finalStat) {
    assertControl(
      finalStat.nlink === 1,
      codes.lockConflict,
      `${options.label} final canonical 仍有额外 hard-link`,
    );
  }
  assertControl(
    refLockCandidate(location, codes, options.label) === null
      && packedLockCandidate(location, codes, options.label) === null,
    codes.lockConflict,
    `${options.label} close 后仍有 lock artifacts`,
  );
  assertReflogExpectation(location, options, codes);
  return state.current;
}

function cleanupUnmutatedFence(
  options,
  location,
  topology,
  codes,
) {
  assertControl(
    !topology.refLock && !topology.canonicalOwned,
    codes.lockConflict,
    `${options.label} unmutated cleanup topology 非法`,
  );
  if (topology.packed) {
    unlinkOwned(
      options,
      location.packedLock,
      location.commonGitDir,
      'packed-lock-released',
      codes,
    );
  }
  cleanupFence(options, codes, {
    ownedCanonical: false,
    location,
  });
}

function cleanupOwnedLocksBeforeMutation(
  options,
  location,
  codes,
) {
  const fence = inspectLooseRefFence({
    fenceFile: options.fenceFile,
    expectedNew: options.expectedNew,
    codes,
    label: options.label,
  });
  if (!fence) return;
  const canonical = readLooseRefStat(
    location,
    codes,
    options.label,
  );
  assertControl(
    !canonical || !sameInode(fence.stat, canonical),
    codes.lockConflict,
    `${options.label} canonical 已 mutation，禁止 error-path 清理 owned locks`,
  );
  for (const [file, directory] of [
    [location.refLock, location.refParent],
    [location.packedLock, location.commonGitDir],
  ]) {
    const stat = lstatIfPresent(
      file,
      codes.lockConflict,
      `${options.label} error cleanup ${path.basename(file)}`,
    );
    if (!stat || !sameInode(fence.stat, stat)) continue;
    fs.unlinkSync(file);
    fsyncDirectory(directory);
  }
  const retained = inspectLooseRefFence({
    fenceFile: options.fenceFile,
    expectedNew: options.expectedNew,
    codes,
    label: options.label,
  });
  assertControl(
    retained && retained.stat.nlink === 1,
    codes.fenceConflict,
    `${options.label} pre-mutation error cleanup 后 fence nlink 非 1`,
  );
}

function executeLooseRefTransaction(rawOptions) {
  const codes = transactionCodes(rawOptions.codes);
  const label = rawOptions.label || `loose-ref ${rawOptions.ref}`;
  const options = {
    ...rawOptions,
    allowedFinalRefs: rawOptions.allowedFinalRefs || [],
    reflogPolicy: rawOptions.reflogPolicy || 'preserve',
    label,
  };
  assertControl(
    typeof options.cwd === 'string'
      && /^[0-9a-f]{40}$/.test(options.expectedOld)
      && /^[0-9a-f]{40}$/.test(options.expectedNew)
      && options.expectedOld !== options.expectedNew
      && Array.isArray(options.allowedFinalRefs)
      && options.allowedFinalRefs.every((oid) => (
        oid === null || /^[0-9a-f]{40}$/.test(oid)
      ))
      && typeof options.fenceInstalledAtEntry === 'boolean',
    codes.invalidRef,
    `${label} old/new/fence binding 非法`,
  );
  assertFilesRefBackend(
    options.cwd,
    options.commonGitDir,
    codes,
    label,
  );
  assertStrictRefName(options.cwd, options.ref, codes, label);
  if (typeof options.assertRefPolicy === 'function') {
    options.assertRefPolicy(options.ref);
  }
  const location = looseRefLocation(
    options.commonGitDir,
    options.ref,
  );
  assertControl(
    location.safeRelative,
    codes.invalidRef,
    `${label} ref 逃逸 common git dir`,
  );

  let fence = inspectLooseRefFence({
    fenceFile: options.fenceFile,
    expectedNew: options.expectedNew,
    codes,
    label,
  });
  assertControl(
    Boolean(fence) === options.fenceInstalledAtEntry,
    codes.fenceConflict,
    `${label} fence inventory 与 caller sealed view 漂移`,
  );
  let state = classifyRef(
    options.cwd,
    location,
    options.expectedOld,
    options.expectedNew,
    options.allowedFinalRefs,
    codes,
    label,
  );
  if (!fence) {
    assertControl(
      !refLockCandidate(location, codes, label)
        && !packedLockCandidate(location, codes, label),
      codes.lockConflict,
      `${label} 首次 fence 前已有 foreign lock`,
    );
    if (
      state.kind === 'final'
        && state.current !== actualRef(options.expectedNew)
    ) {
      assertReflogExpectation(location, options, codes);
      return state.current;
    }
    if (
      state.kind === 'final'
        && options.expectedNew !== ZERO_OID
    ) {
      return assertNoFenceExpectedNew(
        options,
        location,
        codes,
      );
    }
    if (state.kind === 'old') {
      const loose = readLooseRefStat(location, codes, label);
      if (options.expectedOld === ZERO_OID || loose) {
        assertCanonicalLooseOid(
          location,
          options.expectedOld,
          codes,
          label,
        );
      }
    }
    fence = installFence(options, codes);
  } else {
    fence = repairFence(options, fence, codes);
  }

  let topology = inspectOwnedTopology(
    location,
    {
      file: options.fenceFile,
      expectedNew: options.expectedNew,
    },
    codes,
    label,
  );
  state = classifyRef(
    options.cwd,
    location,
    options.expectedOld,
    options.expectedNew,
    options.allowedFinalRefs,
    codes,
    label,
  );
  if (state.kind === 'final') {
    if (state.current === actualRef(options.expectedNew)) {
      try {
        return closeExpectedNew(options, location, codes);
      } catch (error) {
        if (stageInterruptions.has(error)) throw error;
        const failedTopology = inspectOwnedTopology(
          location,
          {
            file: options.fenceFile,
            expectedNew: options.expectedNew,
          },
          codes,
          label,
        );
        if (
          options.expectedNew !== ZERO_OID
            && !failedTopology.canonicalOwned
        ) {
          cleanupOwnedLocksBeforeMutation(
            options,
            location,
            codes,
          );
        }
        throw error;
      }
    }
    assertControl(
      !topology.refLock && !topology.canonicalOwned,
      codes.refConflict,
      `${label} dual-lock/mutated transaction 期间出现 foreign final ref`,
    );
    cleanupUnmutatedFence(options, location, topology, codes);
    assertReflogExpectation(location, options, codes);
    return state.current;
  }

  let preimage;
  let beforeMutation;
  try {
    if (topology.packed && !topology.refLock) {
      releasePackedOnlyForFreshValidation(
        options,
        location,
        topology,
        codes,
      );
      topology = inspectOwnedTopology(
        location,
        {
          file: options.fenceFile,
          expectedNew: options.expectedNew,
        },
        codes,
        label,
      );
    }
    if (!topology.packed && !topology.refLock) {
      acquireBothLocks(options, location, codes);
    }
    preimage = assertPreimageWithBothLocks(
      options,
      location,
      codes,
    );
    beforeMutation = assertExpectedOldStorage(
      options,
      location,
      preimage.packedOid,
      codes,
    );
    if (options.expectedOld !== ZERO_OID) {
      assertControl(
        (
          preimage.oldStat === null
            && beforeMutation === null
        )
          || (
            preimage.oldStat
              && beforeMutation
              && sameInode(preimage.oldStat, beforeMutation)
          ),
        codes.lockConflict,
        `${label} mutation 前 canonical inode 漂移`,
      );
    }
  } catch (error) {
    if (stageInterruptions.has(error)) throw error;
    cleanupOwnedLocksBeforeMutation(
      options,
      location,
      codes,
    );
    throw error;
  }
  if (options.expectedNew === ZERO_OID) {
    fs.unlinkSync(location.refFile);
  } else {
    fs.renameSync(location.refLock, location.refFile);
  }
  fsyncDirectory(location.refParent);
  invokeStage(options, 'canonical-mutated');
  return closeExpectedNew(options, location, codes);
}

module.exports = {
  ZERO_OID,
  describeLooseRefReflog,
  executeLooseRefTransaction,
  inspectLooseRefFence,
};
