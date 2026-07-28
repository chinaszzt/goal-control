'use strict';

const fs = require('fs');
const path = require('path');
const {
  assertPrivateDirectory,
  parsePrivateJson,
  publishPrivateJson,
  recoverPrivateJsonPublication,
} = require('./canary-bootstrap-artifacts');
const { ControlError, assertControl } = require('./errors');
const { fsyncDirectory } = require('./init-receipt');
const {
  canonicalJson,
  hashObject,
  normalizeHash,
  sha256,
} = require('./util');
const {
  FILES_TRANSACTION_PROTOCOL,
  HEAD_TRANSACTION_SECURITY,
} = require('./worktree-bootstrap-head-transaction');

const COMPLETION_KIND =
  'WORKTREE_BOOTSTRAP_FILES_HEAD_COMPLETION';
const SAFE_MODES = new Set([0o600, 0o644]);
const MAX_HEAD_BYTES = 512;
const MAX_REF_BYTES = 64;
const MAX_PACKED_REFS_BYTES = 64 * 1024 * 1024;
const MAX_INDEX_BYTES = 512 * 1024 * 1024;

function invokeStage(options, stage) {
  if (typeof options.onStage === 'function') options.onStage(stage);
}

function normalizedAbsolute(file, code, label) {
  assertControl(
    typeof file === 'string'
      && path.isAbsolute(file)
      && path.normalize(file) === file,
    code,
    `${label} 必须是 normalized absolute path`,
  );
  return file;
}

function stableInodeWitness(capture) {
  return {
    dev: capture.stat.dev.toString(),
    ino: capture.stat.ino.toString(),
    birthtime_ns: capture.stat.birthtimeNs.toString(),
    mode: Number(capture.stat.mode & 0o7777n),
    uid: capture.stat.uid.toString(),
    size: capture.stat.size.toString(),
    sha256: `sha256:${sha256(capture.bytes)}`,
  };
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertSafeOrdinaryCapture(
  capture,
  expectedBytes,
  expectedMode,
  code,
  label,
) {
  assertControl(
    capture.stat.isFile()
      && !capture.stat.isSymbolicLink()
      && HEAD_TRANSACTION_SECURITY.currentUidMatches(capture.stat)
      && Number(capture.stat.mode & 0o7777n) === expectedMode
      && capture.bytes.equals(expectedBytes),
    code,
    `${label} 必须是 exact current-uid ${expectedMode
      .toString(8)} ordinary file`,
  );
}

function captureExactFile(file, expectedBytes, maxBytes, code, label) {
  const capture = HEAD_TRANSACTION_SECURITY.readStableOrdinaryFile(
    file,
    code,
    label,
    maxBytes,
  );
  assertControl(
    capture.bytes.equals(expectedBytes)
      && capture.stat.nlink === 1n
      && SAFE_MODES.has(Number(capture.stat.mode & 0o7777n)),
    code,
    `${label} exact content/single-link/mode 不匹配`,
  );
  return capture;
}

function capturePackedRefs(identity, targetRef, codes) {
  HEAD_TRANSACTION_SECURITY.assertPackedTargetAbsent(
    identity,
    targetRef,
    codes,
  );
  const file = path.join(identity.common_git_dir, 'packed-refs');
  const stat = HEAD_TRANSACTION_SECURITY.lstatIfPresent(
    file,
    codes.lockConflict,
    'packed-refs',
  );
  if (!stat) return { state: 'ABSENT' };
  const capture = HEAD_TRANSACTION_SECURITY.readStableOrdinaryFile(
    file,
    codes.lockConflict,
    'packed-refs',
    MAX_PACKED_REFS_BYTES,
  );
  assertControl(
    capture.stat.nlink === 1n
      && SAFE_MODES.has(Number(capture.stat.mode & 0o7777n)),
    codes.lockConflict,
    'packed-refs preimage 必须是 single-link safe-mode file',
  );
  return {
    state: 'PRESENT',
    witness: HEAD_TRANSACTION_SECURITY.fileWitness(capture),
  };
}

function indexObservation(identity, codes) {
  const file = path.join(identity.git_dir, 'index');
  const capture = HEAD_TRANSACTION_SECURITY.readStableOrdinaryFile(
    file,
    codes.identity,
    'worker index',
    MAX_INDEX_BYTES,
  );
  assertControl(
    capture.stat.nlink === 1n
      && SAFE_MODES.has(Number(capture.stat.mode & 0o7777n)),
    codes.identity,
    'worker index 必须是 current-uid single-link safe-mode file',
  );
  return {
    path: file,
    sha256: `sha256:${sha256(capture.bytes)}`,
    size: capture.bytes.length,
    identity: {
      dev: capture.stat.dev.toString(),
      ino: capture.stat.ino.toString(),
      mode: capture.stat.mode.toString(),
      uid: capture.stat.uid.toString(),
      nlink: capture.stat.nlink.toString(),
      size: capture.stat.size.toString(),
      mtime_ns: capture.stat.mtimeNs.toString(),
      ctime_ns: capture.stat.ctimeNs.toString(),
    },
  };
}

function assertIndexObservation(options, expected) {
  assertControl(
    expected
      && canonicalJson(indexObservation(
        options.identity,
        options.codes,
      )) === canonicalJson(expected),
    options.codes.identity,
    'worker index 与 durable observation 漂移',
  );
}

function protocolPaths(options, identity, codes, createArtifacts = false) {
  const artifactRoot = normalizedAbsolute(
    options.artifactRoot,
    codes.artifact,
    'files HEAD artifact root',
  );
  const branchFenceFile = normalizedAbsolute(
    options.branchFenceFile,
    codes.artifact,
    'branch transaction fence',
  );
  const headFenceFile = normalizedAbsolute(
    options.headFenceFile,
    codes.artifact,
    'HEAD transaction fence',
  );
  const completionFile = normalizedAbsolute(
    options.completionFile,
    codes.artifact,
    'HEAD transaction completion',
  );
  assertControl(
    new Set([
      branchFenceFile,
      headFenceFile,
      completionFile,
    ]).size === 3,
    codes.artifact,
    'branch fence、HEAD fence 与 completion 必须是三个独立 path',
  );
  assertPrivateDirectory(
    path.dirname(headFenceFile),
    'files HEAD transaction artifact directory',
    createArtifacts,
  );
  assertControl(
    path.dirname(headFenceFile) === path.dirname(completionFile)
      && headFenceFile.startsWith(`${artifactRoot}${path.sep}`)
      && branchFenceFile.startsWith(`${artifactRoot}${path.sep}`)
      && completionFile.startsWith(`${artifactRoot}${path.sep}`),
    codes.artifact,
    'files HEAD transaction artifacts 未绑定 private artifact root',
  );
  const location = HEAD_TRANSACTION_SECURITY.targetRefLocation(
    identity,
    options.targetRef,
    codes,
  );
  const headFile = path.join(identity.git_dir, 'HEAD');
  const indexLock = path.join(identity.git_dir, 'index.lock');
  const headLock = path.join(identity.git_dir, 'HEAD.lock');
  const directories = [
    path.dirname(headFenceFile),
    identity.git_dir,
    identity.common_git_dir,
    path.dirname(location.refFile),
  ].map((directory) => (
    HEAD_TRANSACTION_SECURITY.canonicalDirectory(
      directory,
      codes.identity,
      'files HEAD transaction filesystem boundary',
    )
  ));
  assertControl(
    directories.every(
      (directory) => directory.stat.dev === directories[0].stat.dev,
    ),
    codes.identity,
    'files HEAD hardlink/rename protocol 要求 artifacts 与 Git metadata 位于同一 filesystem',
  );
  return {
    artifactRoot,
    branchFenceFile,
    headFenceFile,
    completionFile,
    headFile,
    locks: {
      packed: location.packedLock,
      ref: location.refLock,
      index: indexLock,
      head: headLock,
    },
    location,
    filesystemDevice: directories[0].stat.dev.toString(),
  };
}

function prepareFilesHeadProtocolBinding(options) {
  const { identity, codes } = options;
  assertControl(
    process.platform !== 'win32',
    codes.identity,
    'files HEAD fallback 只支持 POSIX hardlink/rename semantics',
  );
  HEAD_TRANSACTION_SECURITY.assertFilesRefBackend(identity, codes);
  const paths = protocolPaths(options, identity, codes, true);
  const expectedHeadBytes = Buffer.from(`${options.expectedOid}\n`);
  const expectedRefBytes = Buffer.from(`${options.expectedOid}\n`);
  const head = captureExactFile(
    paths.headFile,
    expectedHeadBytes,
    MAX_HEAD_BYTES,
    codes.headConflict,
    'detached worktree HEAD preimage',
  );
  const target = captureExactFile(
    paths.location.refFile,
    expectedRefBytes,
    MAX_REF_BYTES,
    codes.targetRef,
    'target loose ref preimage',
  );
  const packed = capturePackedRefs(
    identity,
    options.targetRef,
    codes,
  );
  assertIndexObservation(options, options.expectedIndex);
  const rawLockStats = {};
  for (const [name, file] of Object.entries(paths.locks)) {
    rawLockStats[name] = HEAD_TRANSACTION_SECURITY.lstatIfPresent(
      file,
      codes.lockConflict,
      `${name} lock`,
    );
    assertControl(
      rawLockStats[name] === null,
      codes.lockConflict,
      `fresh files HEAD protocol 发现 foreign ${name} lock`,
    );
  }
  assertCollisionInventory(options, paths, rawLockStats);
  assertControl(
    HEAD_TRANSACTION_SECURITY.lstatIfPresent(
      paths.headFenceFile,
      codes.artifact,
      'HEAD transaction fence',
    ) === null
      && HEAD_TRANSACTION_SECURITY.lstatIfPresent(
        paths.completionFile,
        codes.artifact,
        'HEAD transaction completion',
      ) === null,
    codes.artifact,
    'fresh files HEAD protocol 禁止既有 fence/completion',
  );
  return {
    schema_version: 1,
    transaction_protocol: FILES_TRANSACTION_PROTOCOL,
    git_minimum_version: '2.43',
    ref_backend: 'files',
    filesystem_semantics: 'posix-hardlink-rename',
    filesystem_device: paths.filesystemDevice,
    branch_fence_file: paths.branchFenceFile,
    head_fence_file: paths.headFenceFile,
    completion_file: paths.completionFile,
    head_preimage: HEAD_TRANSACTION_SECURITY.fileWitness(head),
    target_ref_preimage: HEAD_TRANSACTION_SECURITY.fileWitness(target),
    packed_refs_preimage: packed,
    index_preimage: options.expectedIndex,
  };
}

function assertProtocolBinding(options, binding) {
  const paths = protocolPaths(options, options.identity, options.codes);
  assertControl(
    process.platform !== 'win32'
      && binding
      && binding.schema_version === 1
      && binding.transaction_protocol === FILES_TRANSACTION_PROTOCOL
      && binding.git_minimum_version === '2.43'
      && binding.ref_backend === 'files'
      && binding.filesystem_semantics === 'posix-hardlink-rename'
      && binding.filesystem_device === paths.filesystemDevice
      && binding.branch_fence_file === paths.branchFenceFile
      && binding.head_fence_file === paths.headFenceFile
      && binding.completion_file === paths.completionFile
      && binding.head_preimage
      && binding.target_ref_preimage
      && binding.packed_refs_preimage
      && binding.index_preimage
      && canonicalJson(binding.index_preimage)
        === canonicalJson(options.expectedIndex)
      && ['ABSENT', 'PRESENT'].includes(
        binding.packed_refs_preimage.state,
      ),
    options.codes.claimConflict,
    'files HEAD protocol durable binding 非法或 path/backend 漂移',
  );
  assertControl(
    HEAD_TRANSACTION_SECURITY.lstatIfPresent(
      paths.branchFenceFile,
      options.codes.artifact,
      'branch transaction fence',
    ) === null,
    options.codes.artifact,
    'files HEAD protocol 禁止残留 branch transaction fence',
  );
  return paths;
}

function assertPackedPreimage(options, binding) {
  const current = capturePackedRefs(
    options.identity,
    options.targetRef,
    options.codes,
  );
  assertControl(
    canonicalJson(current)
      === canonicalJson(binding.packed_refs_preimage),
    options.codes.lockConflict,
    'packed-refs preimage identity/content 漂移',
  );
}

function assertDetachedPreimages(options, binding, paths) {
  assertControl(
    HEAD_TRANSACTION_SECURITY.lstatIfPresent(
      paths.branchFenceFile,
      options.codes.artifact,
      'branch transaction fence',
    ) === null,
    options.codes.artifact,
    '锁内重验发现 branch transaction fence',
  );
  const head = captureExactFile(
    paths.headFile,
    Buffer.from(`${options.expectedOid}\n`),
    MAX_HEAD_BYTES,
    options.codes.headConflict,
    'detached worktree HEAD',
  );
  HEAD_TRANSACTION_SECURITY.assertFileWitness(
    head,
    binding.head_preimage,
    options.codes.headConflict,
    'detached worktree HEAD',
  );
  const target = captureExactFile(
    paths.location.refFile,
    Buffer.from(`${options.expectedOid}\n`),
    MAX_REF_BYTES,
    options.codes.targetRef,
    'target loose ref',
  );
  HEAD_TRANSACTION_SECURITY.assertFileWitness(
    target,
    binding.target_ref_preimage,
    options.codes.targetRef,
    'target loose ref',
  );
  assertPackedPreimage(options, binding);
  assertIndexObservation(options, binding.index_preimage);
  HEAD_TRANSACTION_SECURITY.assertStaticIdentity(
    options.identity,
    options.codes,
  );
  HEAD_TRANSACTION_SECURITY.assertRegistryState(
    options.identity,
    options.expectedDetachedRegistry,
    options.targetRef,
    options.expectedOid,
    'DETACHED',
    options.codes,
  );
}

function lstatKnown(file, codes, label) {
  return HEAD_TRANSACTION_SECURITY.lstatIfPresent(
    file,
    codes.lockConflict,
    label,
  );
}

function lockFamily(file, options, label) {
  const parent = path.dirname(file);
  const parentStat = HEAD_TRANSACTION_SECURITY.lstatIfPresent(
    parent,
    options.codes.lockConflict,
    `${label} parent`,
  );
  if (!parentStat) return [];
  HEAD_TRANSACTION_SECURITY.canonicalDirectory(
    parent,
    options.codes.lockConflict,
    `${label} parent`,
  );
  const basename = path.basename(file);
  const lower = basename.toLowerCase();
  return fs.readdirSync(parent).filter((entry) => (
    entry === basename
      || entry.startsWith(`${basename}.`)
      || entry.toLowerCase() === lower
      || entry.toLowerCase().startsWith(`${lower}.`)
  ));
}

function assertCollisionInventory(options, paths, rawLockStats) {
  for (const [name, file] of Object.entries(paths.locks)) {
    const family = lockFamily(file, options, `${name} lock family`);
    const expected = rawLockStats[name] ? [path.basename(file)] : [];
    assertControl(
      canonicalJson(family.sort())
        === canonicalJson(expected.sort()),
      options.codes.lockConflict,
      `${name} lock family 含 case/dot collision: ${family.join(', ')}`,
    );
  }
  const branchLog = path.join(
    options.identity.common_git_dir,
    'logs',
    ...options.targetRef.split('/'),
  );
  assertControl(
    HEAD_TRANSACTION_SECURITY.lstatIfPresent(
      branchLog,
      options.codes.lockConflict,
      'target branch reflog',
    ) === null
      && lockFamily(
        `${branchLog}.lock`,
        options,
        'target branch reflog lock',
      ).length === 0
      && lockFamily(
        path.join(options.identity.git_dir, 'logs', 'HEAD.lock'),
        options,
        'worktree HEAD reflog lock',
      ).length === 0,
    options.codes.lockConflict,
    'files HEAD protocol 禁止 branch reflog 或 HEAD/branch reflog lock family',
  );
}

function readFenceLink(file, expectedBytes, codes, label) {
  const capture = HEAD_TRANSACTION_SECURITY.readStableOrdinaryFile(
    file,
    codes.lockConflict,
    label,
    MAX_HEAD_BYTES,
  );
  assertSafeOrdinaryCapture(
    capture,
    expectedBytes,
    0o600,
    codes.lockConflict,
    label,
  );
  return capture;
}

function readRawHead(paths, options) {
  const capture = HEAD_TRANSACTION_SECURITY.readStableOrdinaryFile(
    paths.headFile,
    options.codes.headConflict,
    'worktree HEAD',
    MAX_HEAD_BYTES,
  );
  const body = capture.bytes.toString('ascii');
  if (body === `${options.expectedOid}\n`) {
    return { capture, state: 'DETACHED' };
  }
  if (body === `ref: ${options.targetRef}\n`) {
    return { capture, state: 'ATTACHED' };
  }
  throw new ControlError(
    options.codes.headConflict,
    'raw HEAD 不是 exact detached OID 或 exact target symref',
  );
}

function booleanPrefix(values) {
  let missing = false;
  for (const value of values) {
    if (!value) missing = true;
    else if (missing) return false;
  }
  return true;
}

function inspectTopology(options, paths) {
  const expectedFenceBytes = Buffer.from(
    `ref: ${options.targetRef}\n`,
  );
  const fenceStat = lstatKnown(
    paths.headFenceFile,
    options.codes,
    'HEAD transaction fence',
  );
  const rawLockStats = Object.fromEntries(
    Object.entries(paths.locks).map(([name, file]) => [
      name,
      lstatKnown(file, options.codes, `${name} lock`),
    ]),
  );
  assertCollisionInventory(options, paths, rawLockStats);
  const head = readRawHead(paths, options);
  if (!fenceStat) {
    const foreign = Object.entries(rawLockStats)
      .filter(([, stat]) => Boolean(stat))
      .map(([name]) => name);
    assertControl(
      foreign.length === 0,
      options.codes.lockConflict,
      `缺 HEAD fence 时发现 foreign Git locks: ${foreign.join(', ')}`,
    );
    assertControl(
      head.capture.stat.nlink === 1n
        && SAFE_MODES.has(
          Number(head.capture.stat.mode & 0o7777n),
        ),
      options.codes.headConflict,
      '无 HEAD fence 的 final/detached HEAD 必须是 single-link safe-mode file',
    );
    return {
      state: head.state,
      fence: null,
      head: head.capture,
      locks: {
        packed: null,
        ref: null,
        index: null,
        head: null,
      },
    };
  }
  const fence = readFenceLink(
    paths.headFenceFile,
    expectedFenceBytes,
    options.codes,
    'HEAD transaction fence',
  );
  const locks = {};
  for (const [name, file] of Object.entries(paths.locks)) {
    locks[name] = rawLockStats[name]
      ? readFenceLink(
        file,
        expectedFenceBytes,
        options.codes,
        `${name} lock`,
      )
      : null;
    assertControl(
      !locks[name] || sameInode(fence.stat, locks[name].stat),
      options.codes.lockConflict,
      `${name} lock 不是 transaction-owned fence hardlink`,
    );
  }
  if (head.state === 'ATTACHED') {
    assertSafeOrdinaryCapture(
      head.capture,
      expectedFenceBytes,
      0o600,
      options.codes.headConflict,
      'attached worktree HEAD',
    );
    assertControl(
      sameInode(fence.stat, head.capture.stat)
        && locks.head === null
        && booleanPrefix([
          Boolean(locks.packed),
          Boolean(locks.ref),
          Boolean(locks.index),
        ]),
      options.codes.lockConflict,
      'attached files HEAD topology 不是合法 cleanup suffix',
    );
  } else {
    assertControl(
      booleanPrefix([
        Boolean(locks.packed),
        Boolean(locks.ref),
        Boolean(locks.index),
        Boolean(locks.head),
      ]),
      options.codes.lockConflict,
      'detached files HEAD topology 不是合法 lock prefix',
    );
  }
  const ownedLinkCount = 1
    + Object.values(locks).filter(Boolean).length
    + (head.state === 'ATTACHED' ? 1 : 0);
  assertControl(
    fence.stat.nlink === BigInt(ownedLinkCount)
      && Object.values(locks).filter(Boolean).every(
        (capture) => capture.stat.nlink === BigInt(ownedLinkCount),
      )
      && (
        head.state !== 'ATTACHED'
          || head.capture.stat.nlink === BigInt(ownedLinkCount)
      ),
    options.codes.lockConflict,
    'files HEAD fence inode nlink 暴露 foreign hardlink 或非法 crash topology',
  );
  return {
    state: head.state,
    fence,
    head: head.capture,
    locks,
  };
}

function writeWithProgress(descriptor, bytes, offset, length, options) {
  let written = 0;
  while (written < length) {
    const progress = fs.writeSync(
      descriptor,
      bytes,
      offset + written,
      length - written,
      offset + written,
    );
    assertControl(
      progress > 0,
      options.codes.lockConflict,
      'HEAD transaction fence write 未取得进展',
    );
    written += progress;
  }
}

function completeFencePrefix(options, binding, paths, fresh) {
  const bytes = Buffer.from(`ref: ${options.targetRef}\n`);
  const capture = HEAD_TRANSACTION_SECURITY.readStableOrdinaryFile(
    paths.headFenceFile,
    options.codes.lockConflict,
    'HEAD transaction fence prefix',
    MAX_HEAD_BYTES,
  );
  assertControl(
    Number(capture.stat.mode & 0o7777n) === 0o600
      && bytes.subarray(0, capture.bytes.length)
        .equals(capture.bytes),
    options.codes.lockConflict,
    'HEAD transaction fence partial bytes/mode/nlink 非 exact prefix',
  );
  if (capture.bytes.length === bytes.length) {
    let descriptor;
    try {
      descriptor = fs.openSync(
        paths.headFenceFile,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
      );
      const opened = fs.fstatSync(descriptor, { bigint: true });
      assertControl(
        sameInode(opened, capture.stat),
        options.codes.lockConflict,
        'full HEAD fence fsync 前 path/open identity 漂移',
      );
      fs.fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    fsyncDirectory(path.dirname(paths.headFenceFile));
    return;
  }
  assertControl(
    capture.stat.nlink === 1n,
    options.codes.lockConflict,
    'partial HEAD fence 禁止既有 hardlink',
  );
  const rawLockStats = Object.fromEntries(
    Object.entries(paths.locks).map(([name, file]) => [
      name,
      lstatKnown(file, options.codes, `${name} lock`),
    ]),
  );
  assertCollisionInventory(options, paths, rawLockStats);
  assertControl(
    Object.values(rawLockStats).every((stat) => stat === null)
      && HEAD_TRANSACTION_SECURITY.lstatIfPresent(
        paths.completionFile,
        options.codes.claimConflict,
        'files HEAD completion',
      ) === null,
    options.codes.lockConflict,
    'partial HEAD fence 只允许在 mutation 前 exact recovery',
  );
  assertDetachedPreimages(options, binding, paths);
  let descriptor;
  try {
    descriptor = fs.openSync(
      paths.headFenceFile,
      fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0),
    );
    const opened = fs.fstatSync(descriptor, { bigint: true });
    assertControl(
      sameInode(opened, capture.stat)
        && opened.size === capture.stat.size
        && opened.nlink === 1n,
      options.codes.lockConflict,
      'HEAD fence prefix path/open identity 漂移',
    );
    const offset = capture.bytes.length;
    const remaining = bytes.length - offset;
    if (fresh && offset === 0 && remaining > 1) {
      const prefixLength = Math.max(1, Math.floor(remaining / 2));
      writeWithProgress(
        descriptor,
        bytes,
        0,
        prefixLength,
        options,
      );
      fs.fsyncSync(descriptor);
      invokeStage(options, 'files-fence-prefix-written');
      writeWithProgress(
        descriptor,
        bytes,
        prefixLength,
        remaining - prefixLength,
        options,
      );
    } else {
      writeWithProgress(
        descriptor,
        bytes,
        offset,
        remaining,
        options,
      );
    }
    fs.fsyncSync(descriptor);
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      options.codes.lockConflict,
      `HEAD transaction fence prefix recovery 失败: ${error.message}`,
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(paths.headFenceFile));
  invokeStage(options, 'files-fence-created');
}

function createFence(options, binding, paths) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      paths.headFenceFile,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } catch (error) {
    throw new ControlError(
      options.codes.lockConflict,
      `HEAD transaction fence O_EXCL create 失败: ${error.message}`,
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(paths.headFenceFile));
  invokeStage(options, 'files-fence-opened');
  completeFencePrefix(options, binding, paths, true);
}

function acquireOwnedLock(options, paths, name, stage) {
  const target = paths.locks[name];
  try {
    fs.linkSync(paths.headFenceFile, target);
  } catch (error) {
    if (!error || error.code !== 'EEXIST') {
      throw new ControlError(
        options.codes.lockConflict,
        `${name} lock hardlink acquire 失败: ${error.message}`,
      );
    }
  }
  fsyncDirectory(path.dirname(target));
  const topology = inspectTopology(options, paths);
  assertControl(
    topology.locks[name],
    options.codes.lockConflict,
    `${name} lock 未收敛到 transaction-owned hardlink`,
  );
  invokeStage(options, stage);
}

function completionUnsigned(options, binding, paths, topology) {
  return {
    schema_version: 1,
    kind: COMPLETION_KIND,
    transaction_protocol: FILES_TRANSACTION_PROTOCOL,
    operation_id: options.operationId,
    operation_binding_sha256: normalizeHash(
      options.operationBindingSha256,
      'files HEAD operation binding',
    ),
    expected_worktree_key_sha256: normalizeHash(
      options.expectedWorktreeKeySha256,
      'files HEAD worktree key',
    ),
    expected_oid: options.expectedOid,
    target_ref: options.targetRef,
    claim_file: options.claimFile,
    claim_sha256: normalizeHash(
      options.claimSha256,
      'files HEAD claim SHA-256',
    ),
    transaction_binding_sha256: hashObject(binding),
    head_fence_file: paths.headFenceFile,
    committed_fence_identity: stableInodeWitness(topology.fence),
    committed_topology: 'F_P_R_I_HEAD',
  };
}

function exactCompletion(options, binding, paths, topology) {
  const unsigned = completionUnsigned(
    options,
    binding,
    paths,
    topology,
  );
  return {
    ...unsigned,
    completion_binding_sha256: hashObject(unsigned),
  };
}

function validateCompletion(
  options,
  binding,
  paths,
  expectedFile,
  expectedSha256,
) {
  assertControl(
    expectedFile === paths.completionFile,
    options.codes.claimConflict,
    'files HEAD completion path 与 durable binding 不匹配',
  );
  const record = parsePrivateJson(
    paths.completionFile,
    'files HEAD transaction completion',
  );
  if (expectedSha256 !== undefined) {
    assertControl(
      record.sha256 === normalizeHash(
        expectedSha256,
        'files HEAD completion SHA-256',
      ),
      options.codes.claimConflict,
      'files HEAD completion bytes SHA-256 不匹配',
    );
  }
  const completion = record.value;
  const {
    completion_binding_sha256: bindingSha256,
    ...unsigned
  } = completion || {};
  assertControl(
    completion
      && completion.schema_version === 1
      && completion.kind === COMPLETION_KIND
      && bindingSha256 === hashObject(unsigned)
      && completion.transaction_protocol
        === FILES_TRANSACTION_PROTOCOL
      && completion.operation_id === options.operationId
      && completion.operation_binding_sha256
        === normalizeHash(
          options.operationBindingSha256,
          'files HEAD operation binding',
        )
      && completion.expected_worktree_key_sha256
        === normalizeHash(
          options.expectedWorktreeKeySha256,
          'files HEAD worktree key',
        )
      && completion.expected_oid === options.expectedOid
      && completion.target_ref === options.targetRef
      && completion.claim_file === options.claimFile
      && completion.claim_sha256
        === normalizeHash(
          options.claimSha256,
          'files HEAD claim SHA-256',
        )
      && completion.transaction_binding_sha256
        === hashObject(binding)
      && completion.head_fence_file === paths.headFenceFile
      && completion.committed_topology === 'F_P_R_I_HEAD'
      && completion.committed_fence_identity,
    options.codes.claimConflict,
    'files HEAD completion schema/protocol/claim/operation binding 非法',
  );
  return { record, completion };
}

function sealCompletion(options, binding, paths, topology) {
  assertControl(
    topology.state === 'ATTACHED'
      && topology.fence
      && topology.locks.packed
      && topology.locks.ref
      && topology.locks.index
      && topology.locks.head === null
      && topology.fence.stat.nlink === 5n,
    options.codes.lockConflict,
    '缺 exact post-rename owned topology 时禁止 seal completion',
  );
  const completion = exactCompletion(
    options,
    binding,
    paths,
    topology,
  );
  publishPrivateJson(
    paths.completionFile,
    completion,
    'files HEAD transaction completion',
    options.codes.claimConflict,
    {
      onStage(stage) {
        invokeStage(options, `files-completion-${stage}`);
      },
    },
  );
  return validateCompletion(
    options,
    binding,
    paths,
    paths.completionFile,
  );
}

function removeOwnedLock(options, paths, name, stage) {
  const topology = inspectTopology(options, paths);
  const capture = topology.locks[name];
  if (!capture) {
    fsyncDirectory(path.dirname(paths.locks[name]));
    return;
  }
  assertControl(
    topology.state === 'ATTACHED'
      && topology.fence
      && sameInode(topology.fence.stat, capture.stat),
    options.codes.lockConflict,
    `拒绝清理非 transaction-owned ${name} lock`,
  );
  const before = fs.lstatSync(paths.locks[name], { bigint: true });
  assertControl(
    sameInode(before, capture.stat)
      && before.nlink === topology.fence.stat.nlink,
    options.codes.lockConflict,
    `${name} lock cleanup 前 inode/nlink 漂移`,
  );
  fs.unlinkSync(paths.locks[name]);
  fsyncDirectory(path.dirname(paths.locks[name]));
  invokeStage(options, stage);
}

function removeFence(options, paths) {
  const topology = inspectTopology(options, paths);
  assertControl(
    topology.state === 'ATTACHED'
      && topology.fence
      && !topology.locks.packed
      && !topology.locks.ref
      && !topology.locks.index
      && !topology.locks.head
      && topology.fence.stat.nlink === 2n
      && sameInode(topology.fence.stat, topology.head.stat),
    options.codes.lockConflict,
    'HEAD fence cleanup 只允许 final owned two-link topology',
  );
  const before = fs.lstatSync(paths.headFenceFile, { bigint: true });
  assertControl(
    sameInode(before, topology.fence.stat)
      && before.nlink === 2n,
    options.codes.lockConflict,
    'HEAD fence cleanup 前 inode/nlink 漂移',
  );
  fs.unlinkSync(paths.headFenceFile);
  fsyncDirectory(path.dirname(paths.headFenceFile));
  invokeStage(options, 'files-fence-released');
}

function assertAttachedState(options, binding, paths) {
  assertControl(
    HEAD_TRANSACTION_SECURITY.lstatIfPresent(
      paths.branchFenceFile,
      options.codes.artifact,
      'branch transaction fence',
    ) === null,
    options.codes.artifact,
    'attached HEAD 禁止残留 branch transaction fence',
  );
  HEAD_TRANSACTION_SECURITY.assertStaticIdentity(
    options.identity,
    options.codes,
  );
  HEAD_TRANSACTION_SECURITY.assertTargetRef(
    options.identity,
    options.targetRef,
    options.expectedOid,
    options.codes,
  );
  const target = captureExactFile(
    paths.location.refFile,
    Buffer.from(`${options.expectedOid}\n`),
    MAX_REF_BYTES,
    options.codes.targetRef,
    'attached target loose ref',
  );
  HEAD_TRANSACTION_SECURITY.assertFileWitness(
    target,
    binding.target_ref_preimage,
    options.codes.targetRef,
    'attached target loose ref',
  );
  assertPackedPreimage(options, binding);
  assertIndexObservation(options, binding.index_preimage);
  HEAD_TRANSACTION_SECURITY.assertRegistryState(
    options.identity,
    options.expectedDetachedRegistry,
    options.targetRef,
    options.expectedOid,
    'ATTACHED',
    options.codes,
  );
}

function attachFilesHeadTransaction(options) {
  const binding = options.protocolBinding;
  HEAD_TRANSACTION_SECURITY.assertFilesRefBackend(
    options.identity,
    options.codes,
  );
  const paths = assertProtocolBinding(options, binding);
  recoverPrivateJsonPublication(
    paths.completionFile,
    'files HEAD transaction completion',
    options.codes.claimConflict,
  );
  if (HEAD_TRANSACTION_SECURITY.lstatIfPresent(
    paths.headFenceFile,
    options.codes.lockConflict,
    'HEAD transaction fence',
  )) {
    completeFencePrefix(options, binding, paths, false);
  }
  let topology = inspectTopology(options, paths);
  const completionStat = HEAD_TRANSACTION_SECURITY.lstatIfPresent(
    paths.completionFile,
    options.codes.claimConflict,
    'files HEAD transaction completion',
  );
  const initiallyFinal = (
    topology.state === 'ATTACHED'
      && topology.fence === null
      && completionStat !== null
  );
  if (topology.state === 'DETACHED') {
    assertControl(
      completionStat === null,
      options.codes.claimConflict,
      'detached HEAD 禁止既有 completion',
    );
    assertDetachedPreimages(options, binding, paths);
    if (!topology.fence) {
      createFence(options, binding, paths);
      topology = inspectTopology(options, paths);
    }
    acquireOwnedLock(
      options,
      paths,
      'packed',
      'files-packed-lock-acquired',
    );
    acquireOwnedLock(
      options,
      paths,
      'ref',
      'files-ref-lock-acquired',
    );
    acquireOwnedLock(
      options,
      paths,
      'index',
      'files-index-lock-acquired',
    );
    acquireOwnedLock(
      options,
      paths,
      'head',
      'files-head-lock-acquired',
    );
    topology = inspectTopology(options, paths);
    assertControl(
      topology.state === 'DETACHED'
        && topology.fence
        && topology.locks.packed
        && topology.locks.ref
        && topology.locks.index
        && topology.locks.head
        && topology.fence.stat.nlink === 5n,
      options.codes.lockConflict,
      'files HEAD protocol 未收敛到 F_P_R_I_H prefix',
    );
    assertDetachedPreimages(options, binding, paths);
    invokeStage(options, 'before-files-head-rename');
    try {
      fs.renameSync(paths.locks.head, paths.headFile);
      fsyncDirectory(path.dirname(paths.headFile));
    } catch (error) {
      throw new ControlError(
        options.codes.headConflict,
        `HEAD.lock -> HEAD atomic rename 失败: ${error.message}`,
      );
    }
    invokeStage(options, 'after-files-head-rename');
    topology = inspectTopology(options, paths);
  }
  assertControl(
    topology.state === 'ATTACHED',
    options.codes.headConflict,
    'files HEAD protocol 未收敛到 attached HEAD',
  );
  fsyncDirectory(options.identity.git_dir);
  assertAttachedState(options, binding, paths);
  let completion;
  if (!completionStat) {
    completion = sealCompletion(options, binding, paths, topology);
  } else {
    completion = validateCompletion(
      options,
      binding,
      paths,
      paths.completionFile,
    );
    if (topology.fence) {
      assertControl(
        canonicalJson(
          completion.completion.committed_fence_identity,
        ) === canonicalJson(stableInodeWitness(topology.fence)),
        options.codes.claimConflict,
        'completion 与 live owned fence inode 不匹配',
      );
    }
  }
  removeOwnedLock(
    options,
    paths,
    'index',
    'files-index-lock-released',
  );
  removeOwnedLock(
    options,
    paths,
    'ref',
    'files-ref-lock-released',
  );
  removeOwnedLock(
    options,
    paths,
    'packed',
    'files-packed-lock-released',
  );
  topology = inspectTopology(options, paths);
  if (topology.fence) removeFence(options, paths);
  const finalTopology = inspectTopology(options, paths);
  fsyncDirectory(path.dirname(paths.headFenceFile));
  assertControl(
    finalTopology.state === 'ATTACHED'
      && finalTopology.fence === null
      && canonicalJson(
        completion.completion.committed_fence_identity,
      ) === canonicalJson(stableInodeWitness(finalTopology.head)),
    options.codes.headConflict,
    'files HEAD final inode/content 与 durable completion 不匹配',
  );
  assertAttachedState(options, binding, paths);
  return {
    transaction_binding_sha256: hashObject(binding),
    head_fence_file: paths.headFenceFile,
    completion_file: paths.completionFile,
    completion_sha256: completion.record.sha256,
    idempotent: initiallyFinal,
  };
}

function verifyFilesHeadTransaction(options) {
  const binding = options.protocolBinding;
  HEAD_TRANSACTION_SECURITY.assertFilesRefBackend(
    options.identity,
    options.codes,
  );
  const paths = assertProtocolBinding(options, binding);
  const topology = inspectTopology(options, paths);
  assertControl(
    topology.state === 'ATTACHED'
      && topology.fence === null,
    options.codes.headConflict,
    'verified files HEAD transaction 不是 final attached topology',
  );
  const completion = validateCompletion(
    options,
    binding,
    paths,
    options.expectedCompletionFile,
    options.expectedCompletionSha256,
  );
  assertControl(
    canonicalJson(
      completion.completion.committed_fence_identity,
    ) === canonicalJson(stableInodeWitness(topology.head)),
    options.codes.claimConflict,
    'verified HEAD inode/content 未绑定 durable completion',
  );
  assertAttachedState(options, binding, paths);
  return {
    transaction_binding_sha256: hashObject(binding),
    head_fence_file: paths.headFenceFile,
    completion_file: paths.completionFile,
    completion_sha256: completion.record.sha256,
  };
}

module.exports = {
  COMPLETION_KIND,
  attachFilesHeadTransaction,
  prepareFilesHeadProtocolBinding,
  verifyFilesHeadTransaction,
};
