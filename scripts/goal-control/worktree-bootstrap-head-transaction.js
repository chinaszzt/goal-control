'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const {
  assertPrivateDirectory,
  parsePrivateJson,
  publishPrivateJson,
} = require('./canary-bootstrap-artifacts');
const { ControlError, assertControl } = require('./errors');
const {
  describeLooseRefReflog,
} = require('./git-loose-ref-transaction');
const { fsyncDirectory } = require('./init-receipt');
const {
  canonicalJson,
  hashObject,
  normalizeHash,
  readOnlyGitEnvironment,
  safeId,
  sha256,
  trustedGitExecutable,
} = require('./util');

const CLAIM_KIND = 'WORKTREE_BOOTSTRAP_HEAD_CLAIM';
const CLAIM_ROOT_DIRECTORY = 'worktree-bootstrap-head-claims-v1';
const NATIVE_TRANSACTION_PROTOCOL = 'git-update-ref-symref-v1';
const FILES_TRANSACTION_PROTOCOL =
  'git-files-backend-hardlink-head-v1';
const TRANSACTION_PROTOCOLS = Object.freeze([
  NATIVE_TRANSACTION_PROTOCOL,
  FILES_TRANSACTION_PROTOCOL,
]);
const FULL_OID_RE = /^[0-9a-f]{40}$/;
const SAFE_GIT_FILE_MODES = new Set([0o600, 0o644]);
const MAX_GIT_POINTER_BYTES = 4096;
const MAX_PACKED_REFS_BYTES = 64 * 1024 * 1024;
const MINIMUM_GIT_MAJOR = 2;
const MINIMUM_GIT_MINOR = 50;
function transactionCodes(overrides = {}) {
  return {
    artifact:
      overrides.artifact || 'WORKTREE_BOOTSTRAP_HEAD_ARTIFACT_INVALID',
    claimConflict:
      overrides.claimConflict || 'WORKTREE_BOOTSTRAP_HEAD_CLAIM_CONFLICT',
    headConflict:
      overrides.headConflict || 'WORKTREE_BOOTSTRAP_HEAD_PREIMAGE_CONFLICT',
    identity:
      overrides.identity || 'WORKTREE_BOOTSTRAP_HEAD_IDENTITY_INVALID',
    lockConflict:
      overrides.lockConflict || 'WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT',
    targetRef:
      overrides.targetRef || 'WORKTREE_BOOTSTRAP_HEAD_TARGET_REF_INVALID',
  };
}

function currentUidMatches(stat) {
  return typeof process.getuid !== 'function'
    || stat.uid === BigInt(process.getuid());
}

function fileIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    uid: stat.uid,
    nlink: stat.nlink,
    size: stat.size,
    birthtimeNs: stat.birthtimeNs,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  };
}

function sameFileIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function lstatIfPresent(file, code, label) {
  try {
    return fs.lstatSync(file, { bigint: true });
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw new ControlError(
      code,
      `${label} 无法安全 lstat: ${error.message}`,
    );
  }
}

function readStableOrdinaryFile(file, code, label, maxBytes) {
  const before = lstatIfPresent(file, code, label);
  assertControl(
    before
      && before.isFile()
      && !before.isSymbolicLink()
      && currentUidMatches(before)
      && before.size <= BigInt(maxBytes),
    code,
    `${label} 必须是当前 uid 的大小受限 non-symlink ordinary file`,
  );
  const beforeIdentity = fileIdentity(before);
  let descriptor;
  try {
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const openedBefore = fs.fstatSync(descriptor, { bigint: true });
    assertControl(
      openedBefore.isFile()
        && sameFileIdentity(
          beforeIdentity,
          fileIdentity(openedBefore),
        ),
      code,
      `${label} path/open identity 漂移`,
    );
    const bytes = fs.readFileSync(descriptor);
    const openedAfter = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(file, { bigint: true });
    assertControl(
      sameFileIdentity(
        fileIdentity(openedBefore),
        fileIdentity(openedAfter),
      )
        && sameFileIdentity(
          fileIdentity(openedAfter),
          fileIdentity(pathAfter),
        )
        && BigInt(bytes.length) === openedAfter.size,
      code,
      `${label} 读取期间 identity/content 漂移`,
    );
    return { bytes, stat: openedAfter };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function gitEnvironment() {
  return {
    ...readOnlyGitEnvironment(),
    GIT_LITERAL_PATHSPECS: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
  };
}

function gitResult(cwd, args, options = {}) {
  try {
    return {
      status: 0,
      stdout: execFileSync(trustedGitExecutable(), args, {
        cwd,
        encoding: options.encoding === null ? null : 'utf8',
        input: options.input,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: gitEnvironment(),
      }),
      stderr: '',
    };
  } catch (error) {
    return {
      status: Number.isInteger(error && error.status)
        ? error.status
        : -1,
      stdout: options.encoding === null
        ? Buffer.from(error && error.stdout || '')
        : String(error && error.stdout || ''),
      stderr: String(error && (error.stderr || error.message) || ''),
      cause: error,
    };
  }
}

function gitText(cwd, args, code, label) {
  const result = gitResult(cwd, args);
  if (result.status !== 0) {
    throw new ControlError(
      code,
      `${label} 失败${result.stderr.trim()
        ? `: ${result.stderr.trim()}`
        : ''}`,
    );
  }
  return result.stdout.trim();
}

function gitBytes(cwd, args, code, label) {
  const result = gitResult(cwd, args, { encoding: null });
  if (result.status !== 0) {
    throw new ControlError(
      code,
      `${label} 失败${result.stderr.trim()
        ? `: ${result.stderr.trim()}`
        : ''}`,
    );
  }
  return result.stdout;
}

function gitVersion(cwd, codes) {
  const output = gitText(
    cwd,
    ['--version'],
    codes.identity,
    'Git version probe',
  );
  const match = /^git version ([0-9]+)\.([0-9]+)(?:\.|$)/.exec(output);
  assertControl(
    match,
    codes.identity,
    'Git version probe 返回无法识别的版本',
  );
  const major = Number(match[1]);
  const minor = Number(match[2]);
  return {
    output,
    major,
    minor,
    native_symref_transaction_supported:
      major > MINIMUM_GIT_MAJOR
        || (
          major === MINIMUM_GIT_MAJOR
            && minor >= MINIMUM_GIT_MINOR
        ),
  };
}

function canonicalDirectory(candidate, code, label) {
  assertControl(
    typeof candidate === 'string'
      && path.isAbsolute(candidate)
      && path.normalize(candidate) === candidate,
    code,
    `${label} 必须是 canonical absolute path`,
  );
  let resolved;
  let stat;
  try {
    resolved = fs.realpathSync(candidate);
    stat = fs.lstatSync(candidate, { bigint: true });
  } catch (error) {
    throw new ControlError(code, `${label} 不可读取: ${error.message}`);
  }
  assertControl(
    resolved === candidate
      && stat.isDirectory()
      && !stat.isSymbolicLink()
      && currentUidMatches(stat),
    code,
    `${label} 必须是当前 uid 的 canonical non-symlink directory`,
  );
  return { path: resolved, stat };
}

function directoryIdentity(stat) {
  return {
    dev: stat.dev.toString(),
    ino: stat.ino.toString(),
    birthtime_ns: stat.birthtimeNs.toString(),
    mode: Number(stat.mode & 0o7777n),
    uid: stat.uid.toString(),
  };
}

function reciprocalFileIdentity(capture) {
  return {
    dev: capture.stat.dev.toString(),
    ino: capture.stat.ino.toString(),
    birthtime_ns: capture.stat.birthtimeNs.toString(),
    mtime_ns: capture.stat.mtimeNs.toString(),
    ctime_ns: capture.stat.ctimeNs.toString(),
    mode: Number(capture.stat.mode & 0o7777n),
    uid: capture.stat.uid.toString(),
    nlink: capture.stat.nlink.toString(),
    size: capture.stat.size.toString(),
    sha256: `sha256:${sha256(capture.bytes)}`,
  };
}

function readReciprocalFile(file, code, label) {
  const capture = readStableOrdinaryFile(
    file,
    code,
    label,
    MAX_GIT_POINTER_BYTES,
  );
  assertControl(
    capture.stat.nlink === 1n
      && SAFE_GIT_FILE_MODES.has(Number(capture.stat.mode & 0o7777n))
      && capture.bytes.length > 0
      && capture.bytes[capture.bytes.length - 1] === 0x0a
      && !capture.bytes
        .subarray(0, capture.bytes.length - 1)
        .includes(0x0a)
      && !capture.bytes.includes(0x00),
    code,
    `${label} 必须是 single-link canonical one-line Git registry file`,
  );
  return {
    bytes: capture.bytes.toString('utf8'),
    identity: reciprocalFileIdentity(capture),
  };
}

function captureWorktreeGitdirIdentity(cwd, rawCodes = {}) {
  const codes = transactionCodes(rawCodes);
  const worktree = canonicalDirectory(cwd, codes.identity, 'worktree cwd');
  const topLevel = fs.realpathSync(gitText(
    worktree.path,
    ['rev-parse', '--show-toplevel'],
    codes.identity,
    'worktree top-level',
  ));
  assertControl(
    topLevel === worktree.path,
    codes.identity,
    'cwd 必须是 linked worktree top-level',
  );
  const gitDirPath = fs.realpathSync(path.resolve(gitText(
    worktree.path,
    ['rev-parse', '--path-format=absolute', '--absolute-git-dir'],
    codes.identity,
    'worktree git dir',
  )));
  const commonGitDirPath = fs.realpathSync(path.resolve(gitText(
    worktree.path,
    ['rev-parse', '--path-format=absolute', '--git-common-dir'],
    codes.identity,
    'worktree common git dir',
  )));
  const gitDir = canonicalDirectory(
    gitDirPath,
    codes.identity,
    'worktree git dir',
  );
  const commonGitDir = canonicalDirectory(
    commonGitDirPath,
    codes.identity,
    'worktree common git dir',
  );
  assertControl(
    gitDir.path !== commonGitDir.path
      && gitDir.path.startsWith(
        `${commonGitDir.path}${path.sep}worktrees${path.sep}`,
      ),
    codes.identity,
    'bootstrap HEAD transaction 只允许专属 gitdir 的 linked worktree',
  );
  const dotGitFile = path.join(worktree.path, '.git');
  const backPointerFile = path.join(gitDir.path, 'gitdir');
  const commondirFile = path.join(gitDir.path, 'commondir');
  const dotGit = readReciprocalFile(
    dotGitFile,
    codes.identity,
    'linked worktree .git registry',
  );
  const backPointer = readReciprocalFile(
    backPointerFile,
    codes.identity,
    'linked worktree gitdir back-pointer',
  );
  const commondir = readReciprocalFile(
    commondirFile,
    codes.identity,
    'linked worktree commondir pointer',
  );
  assertControl(
    dotGit.bytes === `gitdir: ${gitDir.path}\n`
      && backPointer.bytes === `${dotGitFile}\n`
      && fs.realpathSync(path.resolve(
        gitDir.path,
        commondir.bytes.trimEnd(),
      )) === commonGitDir.path,
    codes.identity,
    'linked worktree reciprocal .git/gitdir/commondir binding 不匹配',
  );
  const identity = {
    schema_version: 1,
    cwd: worktree.path,
    cwd_identity: directoryIdentity(worktree.stat),
    git_dir: gitDir.path,
    git_dir_identity: directoryIdentity(gitDir.stat),
    common_git_dir: commonGitDir.path,
    common_git_dir_identity: directoryIdentity(commonGitDir.stat),
    reciprocal_registry: {
      dot_git: { path: dotGitFile, ...dotGit },
      gitdir_back_pointer: {
        path: backPointerFile,
        ...backPointer,
      },
      commondir: { path: commondirFile, ...commondir },
    },
  };
  return {
    ...identity,
    worktree_key_sha256: hashObject(identity),
  };
}

function parseWorktreeInventory(cwd, codes) {
  const bytes = gitBytes(
    cwd,
    ['worktree', 'list', '--porcelain', '-z'],
    codes.identity,
    'git worktree registry',
  );
  assertControl(
    bytes.length > 0 && bytes[bytes.length - 1] === 0,
    codes.identity,
    'git worktree registry 缺 NUL terminator',
  );
  const records = [];
  let current = null;
  for (
    const token of bytes.subarray(0, bytes.length - 1)
      .toString('utf8').split('\0')
  ) {
    if (token === '') {
      if (current) records.push(current);
      current = null;
      continue;
    }
    const separator = token.indexOf(' ');
    const key = separator === -1 ? token : token.slice(0, separator);
    const value = separator === -1 ? true : token.slice(separator + 1);
    if (key === 'worktree') {
      assertControl(
        current === null,
        codes.identity,
        'git worktree registry record 未闭合',
      );
      current = { worktree: value };
    } else {
      assertControl(
        current && current[key] === undefined,
        codes.identity,
        'git worktree registry 字段顺序或重复非法',
      );
      current[key] = value;
    }
  }
  if (current) records.push(current);
  return records;
}

function currentWorktreeRegistry(identity, codes) {
  const matches = parseWorktreeInventory(identity.cwd, codes)
    .filter((record) => {
      try {
        return fs.realpathSync(record.worktree) === identity.cwd;
      } catch {
        return false;
      }
    });
  assertControl(
    matches.length === 1,
    codes.identity,
    'actual linked worktree registry record 不唯一',
  );
  const record = matches[0];
  const detached = record.detached === true;
  const branch = typeof record.branch === 'string'
    ? record.branch.replace(/^refs\/heads\//, '')
    : null;
  const expectedKeys = detached
    ? ['HEAD', 'detached', 'worktree']
    : ['HEAD', 'branch', 'worktree'];
  assertControl(
    canonicalJson(Object.keys(record).sort())
      === canonicalJson(expectedKeys.sort())
      && FULL_OID_RE.test(record.HEAD)
      && (
        detached
          ? branch === null
          : record.branch === `refs/heads/${branch}`
      ),
    codes.identity,
    'actual linked worktree registry record 非 canonical detached/branch',
  );
  return {
    worktree: identity.cwd,
    head: record.HEAD,
    branch,
    detached,
  };
}

function readHead(identity, expectedOid, targetRef, codes) {
  const capture = readStableOrdinaryFile(
    path.join(identity.git_dir, 'HEAD'),
    codes.headConflict,
    'worktree HEAD',
    512,
  );
  const mode = Number(capture.stat.mode & 0o7777n);
  assertControl(
    capture.stat.nlink === 1n && SAFE_GIT_FILE_MODES.has(mode),
    codes.headConflict,
    'worktree HEAD 必须是 current uid 的 single-link 0600/0644 file',
  );
  const body = capture.bytes.toString('ascii');
  if (body === `${expectedOid}\n`) return { state: 'DETACHED', mode };
  if (body === `ref: ${targetRef}\n`) return { state: 'ATTACHED', mode };
  throw new ControlError(
    codes.headConflict,
    'raw HEAD 不是 exact detached OID 或 exact target symref',
  );
}

function targetRefLocation(identity, targetRef, codes) {
  assertControl(
    typeof targetRef === 'string'
      && targetRef.startsWith('refs/heads/')
      && !targetRef.includes('\0')
      && !targetRef.includes('\\'),
    codes.targetRef,
    'target symref 必须是 refs/heads/ 下的 canonical ref',
  );
  const format = gitResult(identity.cwd, ['check-ref-format', targetRef]);
  assertControl(
    format.status === 0,
    codes.targetRef,
    'target symref 未通过 git check-ref-format',
  );
  const refFile = path.join(
    identity.common_git_dir,
    ...targetRef.split('/'),
  );
  const refParent = canonicalDirectory(
    path.dirname(refFile),
    codes.targetRef,
    'target ref parent',
  );
  assertControl(
    refParent.path.startsWith(`${identity.common_git_dir}${path.sep}`),
    codes.targetRef,
    'target ref parent 逃逸 common git dir',
  );
  return {
    refFile,
    refLock: `${refFile}.lock`,
    packedLock: path.join(identity.common_git_dir, 'packed-refs.lock'),
  };
}

function assertTargetRef(identity, targetRef, expectedOid, codes) {
  const location = targetRefLocation(identity, targetRef, codes);
  const capture = readStableOrdinaryFile(
    location.refFile,
    codes.targetRef,
    'target loose ref',
    64,
  );
  const semantic = gitText(
    identity.cwd,
    ['for-each-ref', '--format=%(refname)%00%(objectname)', targetRef],
    codes.targetRef,
    'target ref inventory',
  );
  assertControl(
    capture.bytes.toString('ascii') === `${expectedOid}\n`
      && capture.stat.nlink === 1n
      && SAFE_GIT_FILE_MODES.has(
        Number(capture.stat.mode & 0o7777n),
      )
      && semantic === `${targetRef}\0${expectedOid}`,
    codes.targetRef,
    'target branch 必须是 single-link exact loose expected OID ref',
  );
  return location;
}

function assertPackedTargetAbsent(identity, targetRef, codes) {
  const packedRefs = path.join(identity.common_git_dir, 'packed-refs');
  const stat = lstatIfPresent(
    packedRefs,
    codes.lockConflict,
    'packed-refs',
  );
  if (!stat) return;
  const capture = readStableOrdinaryFile(
    packedRefs,
    codes.lockConflict,
    'packed-refs',
    MAX_PACKED_REFS_BYTES,
  );
  assertControl(
    capture.stat.nlink === 1n
      && SAFE_GIT_FILE_MODES.has(
        Number(capture.stat.mode & 0o7777n),
      ),
    codes.lockConflict,
    'packed-refs 必须是 current uid 的 single-link safe-mode file',
  );
  const text = capture.bytes.toString('utf8');
  assertControl(
    Buffer.from(text, 'utf8').equals(capture.bytes)
      && !capture.bytes.includes(0),
    codes.lockConflict,
    'packed-refs 必须是 canonical UTF-8 text',
  );
  for (const line of text.split('\n')) {
    if (
      line === ''
        || line.startsWith('#')
        || /^\^[0-9a-f]{40}$/.test(line)
    ) {
      continue;
    }
    const match = /^([0-9a-f]{40}) (refs\/[^\s]+)$/.exec(line);
    assertControl(
      match,
      codes.lockConflict,
      'packed-refs 含 malformed line',
    );
    assertControl(
      match[2] !== targetRef,
      codes.lockConflict,
      'bootstrap target ref 禁止 packed shadow',
    );
  }
}

function assertFilesRefBackend(identity, codes) {
  const configured = gitResult(
    identity.cwd,
    ['config', '--local', '--get-all', 'extensions.refStorage'],
  );
  assertControl(
    (
      configured.status === 1
        && configured.stdout === ''
    )
      || (
        configured.status === 0
          && configured.stdout.trim() === 'files'
      ),
    codes.identity,
    'files-backend HEAD protocol 只允许 extensions.refStorage=files 或默认 files backend',
  );
  assertControl(
    lstatIfPresent(
      path.join(identity.common_git_dir, 'reftable'),
      codes.identity,
      'reftable storage',
    ) === null,
    codes.identity,
    'files-backend HEAD protocol 禁止 reftable storage',
  );
}

function fileWitness(capture) {
  return {
    dev: capture.stat.dev.toString(),
    ino: capture.stat.ino.toString(),
    mode: Number(capture.stat.mode & 0o7777n),
    uid: capture.stat.uid.toString(),
    nlink: capture.stat.nlink.toString(),
    size: capture.stat.size.toString(),
    birthtime_ns: capture.stat.birthtimeNs.toString(),
    mtime_ns: capture.stat.mtimeNs.toString(),
    ctime_ns: capture.stat.ctimeNs.toString(),
    sha256: `sha256:${sha256(capture.bytes)}`,
  };
}

function assertFileWitness(capture, expected, code, label) {
  assertControl(
    canonicalJson(fileWitness(capture)) === canonicalJson(expected),
    code,
    `${label} identity/content witness 漂移`,
  );
}

function lockFamily(parent, basename, codes, label) {
  const parentStat = lstatIfPresent(parent, codes.lockConflict, label);
  if (!parentStat) return [];
  assertControl(
    parentStat.isDirectory()
      && !parentStat.isSymbolicLink()
      && currentUidMatches(parentStat),
    codes.lockConflict,
    `${label} parent 必须是 current uid 的 non-symlink directory`,
  );
  let entries;
  try {
    entries = fs.readdirSync(parent);
  } catch (error) {
    throw new ControlError(
      codes.lockConflict,
      `${label} 无法读取: ${error.message}`,
    );
  }
  const lower = basename.toLowerCase();
  return entries.filter((entry) => (
    entry === basename
      || entry.startsWith(`${basename}.`)
      || entry.toLowerCase() === lower
  ));
}

function assertBootstrapBranchFinalState(
  identity,
  targetRef,
  expectedOid,
  artifactRoot,
  branchFenceFile,
  codes,
) {
  assertControl(
    typeof branchFenceFile === 'string'
      && path.isAbsolute(branchFenceFile)
      && path.normalize(branchFenceFile) === branchFenceFile,
    codes.artifact,
    'branch fence path 必须是 normalized absolute path',
  );
  const fenceParent = canonicalDirectory(
    path.dirname(branchFenceFile),
    codes.artifact,
    'branch fence parent',
  );
  assertControl(
    lstatIfPresent(
      branchFenceFile,
      codes.artifact,
      'branch fence',
    ) === null,
    codes.artifact,
    'bootstrap branch final state 禁止残留 transaction fence',
  );
  const location = assertTargetRef(
    identity,
    targetRef,
    expectedOid,
    codes,
  );
  assertNoGitLocks(identity, location, codes);
  assertPackedTargetAbsent(identity, targetRef, codes);
  const reflog = describeLooseRefReflog({
    cwd: identity.cwd,
    commonGitDir: identity.common_git_dir,
    ref: targetRef,
    codes: {
      refConflict: codes.targetRef,
      lockConflict: codes.lockConflict,
      fenceConflict: codes.artifact,
      invalidRef: codes.targetRef,
    },
    label: `worker bootstrap branch ${targetRef}`,
  });
  assertControl(
    reflog.exists === false,
    codes.lockConflict,
    'bootstrap target ref 禁止 foreign reflog',
  );
  const headReflogLocks = lockFamily(
    path.join(identity.git_dir, 'logs'),
    'HEAD.lock',
    codes,
    'worktree HEAD reflog lock',
  );
  assertControl(
    headReflogLocks.length === 0,
    codes.lockConflict,
    `worker bootstrap 发现 HEAD reflog lock: ${
      headReflogLocks.sort().join(', ')
    }`,
  );
  assertControl(
    fenceParent.path.startsWith(
      `${artifactRoot}${path.sep}`,
    ),
    codes.artifact,
    'branch fence parent 未绑定 bootstrap artifact root',
  );
  return location;
}

function assertNoGitLocks(identity, location, codes) {
  const locks = [
    path.join(identity.git_dir, 'HEAD.lock'),
    path.join(identity.git_dir, 'index.lock'),
    location.refLock,
    location.packedLock,
  ].filter((candidate) => lstatIfPresent(
    candidate,
    codes.lockConflict,
    `Git lock ${path.basename(candidate)}`,
  ));
  assertControl(
    locks.length === 0,
    codes.lockConflict,
    `worker bootstrap 发现 foreign/stale Git lock: ${locks.join(', ')}`,
  );
}

function assertPrivateEmptyAnchor(file, code, label) {
  const capture = readStableOrdinaryFile(file, code, label, 0);
  assertControl(
    capture.bytes.length === 0
      && (capture.stat.mode & 0o7777n) === 0o600n
      && capture.stat.nlink >= 1n,
    code,
    `${label} 必须是当前 uid 的 0600 empty anchor`,
  );
  return capture;
}

function createEmptyAnchor(file, code, label) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      file,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } catch (error) {
    if (!error || error.code !== 'EEXIST') {
      throw new ControlError(
        code,
        `${label} create 失败: ${error.message}`,
      );
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(file));
  return assertPrivateEmptyAnchor(file, code, label);
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}
function claimBasePaths(artifactRoot, identity) {
  const identityKey = identity.worktree_key_sha256.slice('sha256:'.length);
  const root = path.join(artifactRoot, CLAIM_ROOT_DIRECTORY);
  const claimDirectory = path.join(root, identityKey);
  return {
    root,
    claimDirectory,
    operationsDirectory: path.join(claimDirectory, 'operations'),
    owner: path.join(claimDirectory, 'owner'),
    claim: path.join(claimDirectory, 'claim.json'),
  };
}
function claimPaths(artifactRoot, identity, requestSha256) {
  const base = claimBasePaths(artifactRoot, identity);
  const requestKey = requestSha256.slice('sha256:'.length);
  return {
    ...base,
    operationAnchor: path.join(
      base.operationsDirectory,
      `${requestKey}.anchor`,
    ),
  };
}
function existingClaimRecord(artifactRoot, identity, codes) {
  const paths = claimBasePaths(artifactRoot, identity);
  const claim = lstatIfPresent(
    paths.claim,
    codes.claimConflict,
    'worktree bootstrap head claim',
  );
  if (!claim) return null;
  return {
    paths,
    record: parsePrivateJson(
      paths.claim,
      'worktree bootstrap head claim',
    ),
  };
}

function ownerAnchorRequestSha256(artifactRoot, identity, codes) {
  const base = claimBasePaths(artifactRoot, identity);
  const owner = lstatIfPresent(
    base.owner,
    codes.claimConflict,
    'worktree claim owner',
  );
  if (!owner) return null;
  assertPrivateDirectory(
    base.claimDirectory,
    'worktree head identity claim',
  );
  assertPrivateDirectory(
    base.operationsDirectory,
    'worktree head operation anchors',
  );
  const ownerCapture = assertPrivateEmptyAnchor(
    base.owner,
    codes.claimConflict,
    'worktree claim owner',
  );
  const names = fs.readdirSync(base.operationsDirectory);
  const matches = [];
  for (const name of names) {
    assertControl(
      /^[0-9a-f]{64}\.anchor$/.test(name),
      codes.claimConflict,
      `worktree operation anchor inventory 非法: ${name}`,
    );
    const candidate = path.join(base.operationsDirectory, name);
    const capture = assertPrivateEmptyAnchor(
      candidate,
      codes.claimConflict,
      'worktree operation anchor',
    );
    if (sameInode(ownerCapture.stat, capture.stat)) matches.push(name);
  }
  assertControl(
    matches.length === 1
      && ownerCapture.stat.nlink === 2n,
    codes.claimConflict,
    'worktree claim owner 缺唯一 exact operation anchor',
  );
  return `sha256:${matches[0].slice(0, -'.anchor'.length)}`;
}

function inspectClaimOwner(paths, codes) {
  const owner = lstatIfPresent(
    paths.owner,
    codes.claimConflict,
    'worktree claim owner',
  );
  const anchor = lstatIfPresent(
    paths.operationAnchor,
    codes.claimConflict,
    'worktree operation anchor',
  );
  if (!owner) {
    if (anchor) {
      const capture = assertPrivateEmptyAnchor(
        paths.operationAnchor,
        codes.claimConflict,
        'worktree operation anchor',
      );
      assertControl(
        capture.stat.nlink === 1n,
        codes.claimConflict,
        'unowned operation anchor nlink 必须为 1',
      );
    }
    return false;
  }
  assertControl(
    anchor,
    codes.claimConflict,
    'worktree identity 已被其它 bootstrap operation claim',
  );
  const ownerCapture = assertPrivateEmptyAnchor(
    paths.owner,
    codes.claimConflict,
    'worktree claim owner',
  );
  const anchorCapture = assertPrivateEmptyAnchor(
    paths.operationAnchor,
    codes.claimConflict,
    'worktree operation anchor',
  );
  assertControl(
    sameInode(ownerCapture.stat, anchorCapture.stat)
      && ownerCapture.stat.nlink === 2n
      && anchorCapture.stat.nlink === 2n,
    codes.claimConflict,
    'worktree claim owner 不是本 exact operation 的双链接 anchor',
  );
  return true;
}

function acquireDurableClaim(
  artifactRoot,
  identity,
  claimUnsigned,
  headState,
  codes,
  options = {},
) {
  const claim = {
    ...claimUnsigned,
    claim_request_sha256: hashObject(claimUnsigned),
  };
  const paths = claimPaths(
    artifactRoot,
    identity,
    claim.claim_request_sha256,
  );
  assertPrivateDirectory(paths.root, 'worktree head claim root', true);
  assertPrivateDirectory(
    paths.claimDirectory,
    'worktree head identity claim',
    true,
  );
  assertPrivateDirectory(
    paths.operationsDirectory,
    'worktree head operation anchors',
    true,
  );
  const owned = inspectClaimOwner(paths, codes);
  if (!owned) {
    assertControl(
      headState === 'DETACHED',
      codes.claimConflict,
      '缺 durable claim 时禁止为既有 target symref 补签 provenance',
    );
    createEmptyAnchor(
      paths.operationAnchor,
      codes.claimConflict,
      'worktree operation anchor',
    );
    try {
      fs.linkSync(paths.operationAnchor, paths.owner);
      fsyncDirectory(paths.claimDirectory);
    } catch (error) {
      if (!error || error.code !== 'EEXIST') {
        throw new ControlError(
          codes.claimConflict,
          `worktree owner claim 失败: ${error.message}`,
        );
      }
    }
    assertControl(
      inspectClaimOwner(paths, codes),
      codes.claimConflict,
      'worktree owner claim 未收敛到 exact operation',
    );
    if (typeof options.onStage === 'function') {
      options.onStage('claim-owner-acquired');
    }
  }
  const publication = publishPrivateJson(
    paths.claim,
    claim,
    'worktree bootstrap head claim',
    codes.claimConflict,
    { onStage: (stage) => options.onStage?.(`claim-record-${stage}`) },
  );
  if (typeof options.onStage === 'function') {
    options.onStage('claim-record-published');
  }
  const record = parsePrivateJson(
    paths.claim,
    'worktree bootstrap head claim',
  );
  assertControl(
    canonicalJson(record.value) === canonicalJson(claim),
    codes.claimConflict,
    'worktree bootstrap head claim bytes/request binding 不匹配',
  );
  return {
    claim,
    claimCreated: !owned && publication.created,
    claimSha256: record.sha256,
    paths,
  };
}

function assertStaticIdentity(expected, codes) {
  const current = captureWorktreeGitdirIdentity(expected.cwd, codes);
  assertControl(
    canonicalJson(current) === canonicalJson(expected),
    codes.identity,
    'worktree/gitdir/reciprocal registry identity 漂移',
  );
  return current;
}

function expectedAttachedRegistry(identity, targetRef, expectedOid) {
  return {
    worktree: identity.cwd,
    head: expectedOid,
    branch: targetRef.slice('refs/heads/'.length),
    detached: false,
  };
}

function assertRegistryState(
  identity,
  expectedDetachedRegistry,
  targetRef,
  expectedOid,
  headState,
  codes,
) {
  const current = currentWorktreeRegistry(identity, codes);
  const expected = headState === 'DETACHED'
    ? expectedDetachedRegistry
    : expectedAttachedRegistry(identity, targetRef, expectedOid);
  assertControl(
    canonicalJson(current) === canonicalJson(expected),
    codes.identity,
    `worktree registry 与 ${headState} HEAD 状态不匹配`,
  );
  return current;
}

function symrefTransactionInput(targetRef, expectedOid) {
  return Buffer.concat([
    Buffer.from('start\0'),
    Buffer.from(`verify ${targetRef}\0`),
    Buffer.from(`${expectedOid}\0`),
    Buffer.from('symref-update HEAD\0'),
    Buffer.from(`${targetRef}\0`),
    Buffer.from('oid\0'),
    Buffer.from(`${expectedOid}\0`),
    Buffer.from('prepare\0'),
    Buffer.from('commit\0'),
  ]);
}

function executeSymrefTransaction(
  identity,
  targetRef,
  expectedOid,
  codes,
) {
  const result = gitResult(
    identity.cwd,
    [
      '-c',
      'core.hooksPath=/dev/null',
      'update-ref',
      '--stdin',
      '-z',
    ],
    { input: symrefTransactionInput(targetRef, expectedOid) },
  );
  if (result.status !== 0) {
    throw new ControlError(
      codes.headConflict,
      `Git atomic symref transaction 失败${result.stderr.trim()
        ? `: ${result.stderr.trim()}`
        : ''}`,
      { cause: result.cause },
    );
  }
}

function invokeStage(options, stage) {
  if (typeof options.onStage === 'function') options.onStage(stage);
}

function attachWorktreeBootstrapHead(rawOptions) {
  const codes = transactionCodes(rawOptions.codes);
  assertControl(
    rawOptions
      && typeof rawOptions.cwd === 'string'
      && typeof rawOptions.artifactRoot === 'string'
      && typeof rawOptions.branchFenceFile === 'string'
      && typeof rawOptions.operationId === 'string'
      && typeof rawOptions.targetRef === 'string'
      && FULL_OID_RE.test(rawOptions.expectedDetachedOid)
      && rawOptions.expectedRegistry
      && typeof rawOptions.expectedRegistry === 'object'
      && !Array.isArray(rawOptions.expectedRegistry),
    codes.identity,
    'worktree bootstrap HEAD transaction 参数非法',
  );
  safeId(rawOptions.operationId, 'worktree bootstrap operation_id');
  const operationBindingSha256 = normalizeHash(
    rawOptions.operationBindingSha256,
    'worktree bootstrap operation binding',
  );
  const expectedWorktreeKeySha256 = normalizeHash(
    rawOptions.expectedWorktreeKeySha256,
    'expected worktree identity key',
  );
  const artifactRootInput = path.resolve(rawOptions.artifactRoot);
  assertControl(
    artifactRootInput === rawOptions.artifactRoot,
    codes.artifact,
    'artifact root 必须是 normalized absolute path',
  );
  assertPrivateDirectory(
    artifactRootInput,
    'worktree bootstrap artifact root',
    true,
  );
  assertControl(
    gitVersion(rawOptions.cwd, codes)
      .native_symref_transaction_supported,
    codes.identity,
    `native symref protocol 要求 Git >= ${MINIMUM_GIT_MAJOR}.${MINIMUM_GIT_MINOR}`,
  );
  const identity = captureWorktreeGitdirIdentity(
    rawOptions.cwd,
    codes,
  );
  assertControl(
    identity.worktree_key_sha256 === expectedWorktreeKeySha256,
    codes.identity,
    'actual worktree identity 与 durable observation key 不匹配',
  );
  const expectedDetachedRegistry = {
    worktree: identity.cwd,
    head: rawOptions.expectedDetachedOid,
    branch: null,
    detached: true,
  };
  assertControl(
    canonicalJson(rawOptions.expectedRegistry)
      === canonicalJson(expectedDetachedRegistry),
    codes.identity,
    'durable observation registry 必须是 exact detached worker record',
  );
  assertBootstrapBranchFinalState(
    identity,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    artifactRootInput,
    rawOptions.branchFenceFile,
    codes,
  );
  let head = readHead(
    identity,
    rawOptions.expectedDetachedOid,
    rawOptions.targetRef,
    codes,
  );
  assertRegistryState(
    identity,
    expectedDetachedRegistry,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    head.state,
    codes,
  );
  const claimUnsigned = {
    schema_version: 1,
    kind: CLAIM_KIND,
    transaction_protocol: NATIVE_TRANSACTION_PROTOCOL,
    worktree: identity,
    expected_registry: expectedDetachedRegistry,
    operation_id: rawOptions.operationId,
    operation_binding_sha256: operationBindingSha256,
    expected_worktree_key_sha256: expectedWorktreeKeySha256,
    expected_detached_oid: rawOptions.expectedDetachedOid,
    target_ref: rawOptions.targetRef,
  };
  const durable = acquireDurableClaim(
    artifactRootInput,
    identity,
    claimUnsigned,
    head.state,
    codes,
    { onStage: rawOptions.onStage },
  );
  invokeStage(rawOptions, 'claim-published');

  assertStaticIdentity(identity, codes);
  assertBootstrapBranchFinalState(
    identity,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    artifactRootInput,
    rawOptions.branchFenceFile,
    codes,
  );
  head = readHead(
    identity,
    rawOptions.expectedDetachedOid,
    rawOptions.targetRef,
    codes,
  );
  assertRegistryState(
    identity,
    expectedDetachedRegistry,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    head.state,
    codes,
  );
  const initiallyAttached = head.state === 'ATTACHED';
  if (!initiallyAttached) {
    invokeStage(rawOptions, 'before-git-transaction');
    executeSymrefTransaction(
      identity,
      rawOptions.targetRef,
      rawOptions.expectedDetachedOid,
      codes,
    );
    invokeStage(rawOptions, 'after-git-transaction');
  }

  assertStaticIdentity(identity, codes);
  assertBootstrapBranchFinalState(
    identity,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    artifactRootInput,
    rawOptions.branchFenceFile,
    codes,
  );
  head = readHead(
    identity,
    rawOptions.expectedDetachedOid,
    rawOptions.targetRef,
    codes,
  );
  assertControl(
    head.state === 'ATTACHED',
    codes.headConflict,
    'Git symref transaction 后 HEAD 未收敛到 target branch',
  );
  assertRegistryState(
    identity,
    expectedDetachedRegistry,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    head.state,
    codes,
  );
  return {
    schema_version: 1,
    transaction_protocol: NATIVE_TRANSACTION_PROTOCOL,
    git_minimum_version: `${MINIMUM_GIT_MAJOR}.${MINIMUM_GIT_MINOR}`,
    worktree_key_sha256: identity.worktree_key_sha256,
    claim_file: durable.paths.claim,
    claim_sha256: durable.claimSha256,
    claim_created: durable.claimCreated,
    operation_id: rawOptions.operationId,
    operation_binding_sha256: operationBindingSha256,
    expected_worktree_key_sha256: expectedWorktreeKeySha256,
    git_dir: identity.git_dir,
    expected_oid: rawOptions.expectedDetachedOid,
    target_ref: rawOptions.targetRef,
    head_state: 'ATTACHED',
    idempotent: initiallyAttached,
  };
}

function verifyWorktreeBootstrapHead(rawOptions) {
  const codes = transactionCodes(rawOptions.codes);
  assertControl(
    rawOptions
      && typeof rawOptions.cwd === 'string'
      && typeof rawOptions.artifactRoot === 'string'
      && typeof rawOptions.branchFenceFile === 'string'
      && typeof rawOptions.operationId === 'string'
      && typeof rawOptions.targetRef === 'string'
      && typeof rawOptions.expectedClaimFile === 'string'
      && FULL_OID_RE.test(rawOptions.expectedDetachedOid)
      && rawOptions.expectedRegistry
      && typeof rawOptions.expectedRegistry === 'object'
      && !Array.isArray(rawOptions.expectedRegistry)
      && rawOptions.expectedWorktreeIdentity
      && typeof rawOptions.expectedWorktreeIdentity === 'object'
      && !Array.isArray(rawOptions.expectedWorktreeIdentity),
    codes.identity,
    'worktree bootstrap HEAD verification 参数非法',
  );
  safeId(rawOptions.operationId, 'worktree bootstrap operation_id');
  const operationBindingSha256 = normalizeHash(
    rawOptions.operationBindingSha256,
    'worktree bootstrap operation binding',
  );
  const expectedWorktreeKeySha256 = normalizeHash(
    rawOptions.expectedWorktreeKeySha256,
    'expected worktree identity key',
  );
  const expectedClaimSha256 = normalizeHash(
    rawOptions.expectedClaimSha256,
    'expected worktree claim SHA-256',
  );
  const artifactRootInput = path.resolve(rawOptions.artifactRoot);
  assertControl(
    artifactRootInput === rawOptions.artifactRoot,
    codes.artifact,
    'artifact root 必须是 normalized absolute path',
  );
  assertPrivateDirectory(
    artifactRootInput,
    'worktree bootstrap artifact root',
  );
  assertControl(
    rawOptions.expectedTransactionProtocol
      === NATIVE_TRANSACTION_PROTOCOL,
    codes.claimConflict,
    'native HEAD verifier 缺 exact expected transaction protocol',
  );
  const identity = captureWorktreeGitdirIdentity(
    rawOptions.cwd,
    codes,
  );
  assertControl(
    identity.worktree_key_sha256 === expectedWorktreeKeySha256
      && canonicalJson(identity)
        === canonicalJson(rawOptions.expectedWorktreeIdentity),
    codes.identity,
    'actual worktree identity 与 durable observation 不匹配',
  );
  const expectedDetachedRegistry = {
    worktree: identity.cwd,
    head: rawOptions.expectedDetachedOid,
    branch: null,
    detached: true,
  };
  assertControl(
    canonicalJson(rawOptions.expectedRegistry)
      === canonicalJson(expectedDetachedRegistry),
    codes.identity,
    'durable observation registry 必须是 exact detached worker record',
  );
  assertBootstrapBranchFinalState(
    identity,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    artifactRootInput,
    rawOptions.branchFenceFile,
    codes,
  );
  let head = readHead(
    identity,
    rawOptions.expectedDetachedOid,
    rawOptions.targetRef,
    codes,
  );
  assertControl(
    head.state === 'ATTACHED',
    codes.headConflict,
    'verified worker HEAD 未绑定 target branch',
  );
  assertRegistryState(
    identity,
    expectedDetachedRegistry,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    head.state,
    codes,
  );
  const claimUnsigned = {
    schema_version: 1,
    kind: CLAIM_KIND,
    transaction_protocol: NATIVE_TRANSACTION_PROTOCOL,
    worktree: identity,
    expected_registry: expectedDetachedRegistry,
    operation_id: rawOptions.operationId,
    operation_binding_sha256: operationBindingSha256,
    expected_worktree_key_sha256: expectedWorktreeKeySha256,
    expected_detached_oid: rawOptions.expectedDetachedOid,
    target_ref: rawOptions.targetRef,
  };
  const claimRequestSha256 = hashObject(claimUnsigned);
  const paths = claimPaths(
    artifactRootInput,
    identity,
    claimRequestSha256,
  );
  assertControl(
    rawOptions.expectedClaimFile === paths.claim,
    codes.claimConflict,
    'worktree claim path 与 exact operation 不匹配',
  );
  assertPrivateDirectory(
    paths.claimDirectory,
    'worktree head identity claim',
  );
  assertPrivateDirectory(
    paths.operationsDirectory,
    'worktree head operation anchors',
  );
  assertControl(
    inspectClaimOwner(paths, codes),
    codes.claimConflict,
    'worktree claim owner/operation anchor 不存在',
  );
  const claimRecord = parsePrivateJson(
    paths.claim,
    'worktree bootstrap head claim',
  );
  const exactClaim = {
    ...claimUnsigned,
    claim_request_sha256: claimRequestSha256,
  };
  assertControl(
    claimRecord.sha256 === expectedClaimSha256
      && canonicalJson(claimRecord.value)
        === canonicalJson(exactClaim),
    codes.claimConflict,
    'worktree claim bytes/request binding 不匹配',
  );

  assertStaticIdentity(identity, codes);
  assertBootstrapBranchFinalState(
    identity,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    artifactRootInput,
    rawOptions.branchFenceFile,
    codes,
  );
  head = readHead(
    identity,
    rawOptions.expectedDetachedOid,
    rawOptions.targetRef,
    codes,
  );
  assertControl(
    head.state === 'ATTACHED',
    codes.headConflict,
    'verified worker HEAD 在复核期间漂移',
  );
  assertRegistryState(
    identity,
    expectedDetachedRegistry,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    head.state,
    codes,
  );
  assertControl(
    inspectClaimOwner(paths, codes),
    codes.claimConflict,
    'worktree claim owner/operation anchor 在复核期间漂移',
  );
  return {
    schema_version: 1,
    transaction_protocol: NATIVE_TRANSACTION_PROTOCOL,
    git_minimum_version: `${MINIMUM_GIT_MAJOR}.${MINIMUM_GIT_MINOR}`,
    worktree_key_sha256: identity.worktree_key_sha256,
    claim_file: paths.claim,
    claim_sha256: claimRecord.sha256,
    operation_id: rawOptions.operationId,
    operation_binding_sha256: operationBindingSha256,
    expected_worktree_key_sha256: expectedWorktreeKeySha256,
    git_dir: identity.git_dir,
    expected_oid: rawOptions.expectedDetachedOid,
    target_ref: rawOptions.targetRef,
    head_state: 'ATTACHED',
  };
}
module.exports = {
  CLAIM_KIND,
  FILES_TRANSACTION_PROTOCOL,
  NATIVE_TRANSACTION_PROTOCOL,
  TRANSACTION_PROTOCOLS,
  HEAD_TRANSACTION_SECURITY: Object.freeze({
    assertFileWitness,
    assertFilesRefBackend,
    assertPackedTargetAbsent,
    assertRegistryState,
    assertStaticIdentity,
    assertTargetRef,
    canonicalDirectory,
    currentUidMatches,
    fileWitness,
    lstatIfPresent,
    readStableOrdinaryFile,
    targetRefLocation,
  }),
  NATIVE_TRANSACTION_INTERNALS: Object.freeze({
    acquireDurableClaim,
    assertBootstrapBranchFinalState,
    claimBasePaths,
    claimPaths,
    currentWorktreeRegistry,
    executeSymrefTransaction,
    existingClaimRecord,
    gitVersion,
    inspectClaimOwner,
    ownerAnchorRequestSha256,
    readHead,
    transactionCodes,
  }),
  attachWorktreeBootstrapHead,
  captureWorktreeGitdirIdentity,
  verifyWorktreeBootstrapHead,
};
