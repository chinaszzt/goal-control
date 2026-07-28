'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const RECEIPT_TTL_MILLISECONDS = 15 * 60 * 1000;
const MAX_RECEIPT_BYTES = 128 * 1024;
const SAFE_SERVE_ENVIRONMENT_BASE = Object.freeze({
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin:/usr/sbin',
  TZ: 'UTC',
});

function sha256(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function validateTestTtl(raw) {
  if (
    typeof raw !== 'string'
      || !/^[1-9][0-9]{1,5}$/.test(raw)
      || Number(raw) < 50
      || Number(raw) > RECEIPT_TTL_MILLISECONDS
  ) {
    throw new Error('BROWSER_CANARY_TEST_TTL_MILLISECONDS 非法');
  }
  return raw;
}

function deriveServeEnvironment(source = process.env) {
  const environment = { ...SAFE_SERVE_ENVIRONMENT_BASE };
  if (
    source.NODE_ENV === 'test'
      && source.BROWSER_CANARY_TEST_TTL_MILLISECONDS !== undefined
  ) {
    environment.NODE_ENV = 'test';
    environment.BROWSER_CANARY_TEST_TTL_MILLISECONDS = validateTestTtl(
      source.BROWSER_CANARY_TEST_TTL_MILLISECONDS,
    );
  }
  return Object.freeze(environment);
}

function assertCanonicalServeEnvironment(environment) {
  if (
    !environment
      || typeof environment !== 'object'
      || Array.isArray(environment)
  ) {
    throw new Error('serve environment contract 非法');
  }
  const source = (
    environment.NODE_ENV === 'test'
      || environment.BROWSER_CANARY_TEST_TTL_MILLISECONDS !== undefined
  )
    ? environment
    : {};
  const expected = deriveServeEnvironment(source);
  if (JSON.stringify(environment) !== JSON.stringify(expected)) {
    throw new Error('serve environment 必须是 canonical minimal allowlist');
  }
  return expected;
}

function dangerousRuntimeEnvironmentKeys(environment) {
  return Object.keys(environment).filter((key) => (
    [
      'NODE_OPTIONS',
      'NODE_PATH',
      'NODE_V8_COVERAGE',
      'ELECTRON_RUN_AS_NODE',
    ].includes(key)
      || key.startsWith('LD_')
      || key.startsWith('DYLD_')
  ) && environment[key] !== '');
}

function assertSafeLauncherRuntime() {
  const dangerous = dangerousRuntimeEnvironmentKeys(process.env);
  const exactJestException = process.env.NODE_ENV === 'test'
    && /^[1-9][0-9]*$/.test(process.env.JEST_WORKER_ID || '')
    && process.execArgv.length === 0
    && (
      dangerous.length === 0
        || (
          dangerous.length === 1
          && dangerous[0] === 'NODE_OPTIONS'
          && process.env.NODE_OPTIONS === '--experimental-vm-modules'
        )
    );
  if (exactJestException) return;
  if (process.execArgv.length !== 0 || dangerous.length !== 0) {
    throw new Error(
      'launcher 拒绝未绑定的 Node execArgv/runtime environment: '
        + [...process.execArgv, ...dangerous].join(','),
    );
  }
}

function assertCurrentServeEnvironment() {
  const expected = deriveServeEnvironment(process.env);
  const actualEnvironment = { ...process.env };
  if (
    typeof actualEnvironment.__CF_USER_TEXT_ENCODING === 'string'
      && /^0x[0-9A-F]+:0x[0-9A-F]+:0x[0-9A-F]+$/i
        .test(actualEnvironment.__CF_USER_TEXT_ENCODING)
  ) {
    delete actualEnvironment.__CF_USER_TEXT_ENCODING;
  }
  const sort = (value) => Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  );
  if (
    JSON.stringify(sort(actualEnvironment)) !== JSON.stringify(sort(expected))
      || process.execArgv.length !== 0
  ) {
    throw new Error(
      'serve process 必须由 launch 以 minimal allowlist 且无 Node execArgv 启动',
    );
  }
}

function privateParentIdentity(receiptFile, expected = null) {
  if (!path.isAbsolute(receiptFile) || path.resolve(receiptFile) !== receiptFile) {
    throw new Error('receipt-file 必须是 canonical absolute path');
  }
  const parent = path.dirname(receiptFile);
  const stat = fs.lstatSync(parent);
  const identity = {
    path: parent,
    dev: stat.dev,
    ino: stat.ino,
    uid: stat.uid,
    mode: stat.mode & 0o777,
  };
  if (
    !stat.isDirectory()
      || stat.isSymbolicLink()
      || fs.realpathSync(parent) !== parent
      || (typeof process.getuid === 'function' && stat.uid !== process.getuid())
      || identity.mode !== 0o700
      || (
        expected !== null
          && JSON.stringify(identity) !== JSON.stringify(expected)
      )
  ) {
    throw new Error('receipt parent identity/owner/exact 0700 mode 非法或漂移');
  }
  return identity;
}

function fileIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    uid: stat.uid,
    mode: stat.mode,
    nlink: stat.nlink,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
  };
}

function assertPrivateFile(stat) {
  if (
    !stat.isFile()
      || stat.isSymbolicLink()
      || stat.nlink !== 1
      || (stat.mode & 0o777) !== 0o600
      || stat.size <= 0
      || stat.size > MAX_RECEIPT_BYTES
      || (typeof process.getuid === 'function' && stat.uid !== process.getuid())
  ) {
    throw new Error('receipt 必须是当前用户 0600 单链接受限大小 ordinary file');
  }
}

function readDescriptorBytes(descriptor, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = fs.readSync(
      descriptor,
      bytes,
      offset,
      size - offset,
      offset,
    );
    if (count === 0) throw new Error('receipt descriptor 提前 EOF');
    offset += count;
  }
  if (fs.readSync(descriptor, Buffer.alloc(1), 0, 1, size) !== 0) {
    throw new Error('receipt descriptor size 与 bytes 不一致');
  }
  return bytes;
}

function assertCaptureStillInstalled(receiptFile, capture) {
  if (!capture || !Number.isInteger(capture.descriptor)) {
    throw new Error('receipt capture 已关闭或非法');
  }
  const parent = privateParentIdentity(receiptFile, capture.parent_identity);
  const heldBefore = fs.fstatSync(capture.descriptor);
  assertPrivateFile(heldBefore);
  if (
    JSON.stringify(fileIdentity(heldBefore))
      !== JSON.stringify(capture.file_identity)
      || heldBefore.dev !== parent.dev
  ) {
    throw new Error('held receipt fd identity 在 lifecycle 期间变化');
  }
  const pathname = fs.lstatSync(receiptFile);
  assertPrivateFile(pathname);
  if (
    fs.realpathSync(receiptFile) !== receiptFile
      || pathname.dev !== heldBefore.dev
      || pathname.ino !== heldBefore.ino
  ) {
    throw new Error('receipt pathname 不再指向 held fd inode');
  }
  const bytes = readDescriptorBytes(capture.descriptor, heldBefore.size);
  const heldAfter = fs.fstatSync(capture.descriptor);
  if (
    JSON.stringify(fileIdentity(heldAfter))
      !== JSON.stringify(capture.file_identity)
      || !bytes.equals(capture.bytes)
      || sha256(bytes) !== capture.sha256
  ) {
    throw new Error('held receipt bytes/identity 在 lifecycle 期间变化');
  }
  privateParentIdentity(receiptFile, capture.parent_identity);
}

function closeReceiptCapture(capture) {
  if (capture && capture.descriptor !== null) {
    fs.closeSync(capture.descriptor);
    capture.descriptor = null;
  }
}

function openPrivateJsonReceiptCapture(receiptFile) {
  const parentIdentity = privateParentIdentity(receiptFile);
  let descriptor;
  try {
    const before = fs.lstatSync(receiptFile);
    assertPrivateFile(before);
    descriptor = fs.openSync(
      receiptFile,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const opened = fs.fstatSync(descriptor);
    assertPrivateFile(opened);
    if (
      before.dev !== opened.dev
        || before.ino !== opened.ino
        || opened.dev !== parentIdentity.dev
    ) {
      throw new Error('receipt lstat/open/parent identity 不一致');
    }
    const bytes = readDescriptorBytes(descriptor, opened.size);
    const after = fs.fstatSync(descriptor);
    if (
      JSON.stringify(fileIdentity(opened)) !== JSON.stringify(fileIdentity(after))
    ) {
      throw new Error('receipt 在读取期间变化');
    }
    const capture = {
      receipt: JSON.parse(bytes.toString('utf8')),
      bytes,
      sha256: sha256(bytes),
      descriptor,
      file_identity: fileIdentity(after),
      parent_identity: parentIdentity,
    };
    descriptor = undefined;
    assertCaptureStillInstalled(receiptFile, capture);
    return capture;
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    privateParentIdentity(receiptFile, parentIdentity);
    throw error;
  }
}

module.exports = {
  RECEIPT_TTL_MILLISECONDS,
  assertCanonicalServeEnvironment,
  assertCaptureStillInstalled,
  assertCurrentServeEnvironment,
  assertSafeLauncherRuntime,
  closeReceiptCapture,
  deriveServeEnvironment,
  openPrivateJsonReceiptCapture,
  validateTestTtl,
};
