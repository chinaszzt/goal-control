'use strict';

const fs = require('fs');
const path = require('path');
const { ControlError, assertControl } = require('./errors');
const { fsyncDirectory } = require('./init-receipt');
const { sha256 } = require('./util');

const MAX_PRIVATE_ARTIFACT_BYTES = 256 * 1024;
const MAX_PRIVATE_JSON_DEPTH = 64;
const DANGEROUS_JSON_KEYS = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

function fileIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    uid: stat.uid,
    nlink: stat.nlink,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
  };
}

function sameIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function readStable(file, label) {
  let before;
  try {
    before = fs.lstatSync(file);
  } catch (error) {
    throw new ControlError(
      'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
      `${label} 无法读取: ${error.message}`,
    );
  }
  assertControl(
    before.isFile()
      && !before.isSymbolicLink()
      && before.size > 0
      && before.size <= MAX_PRIVATE_ARTIFACT_BYTES,
    'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
    `${label} 必须是大小受限的 non-symlink ordinary file`,
  );
  const beforeIdentity = fileIdentity(before);
  let descriptor;
  try {
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const openedBefore = fs.fstatSync(descriptor);
    assertControl(
      openedBefore.isFile()
        && sameIdentity(beforeIdentity, fileIdentity(openedBefore)),
      'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
      `${label} path/open identity 漂移`,
    );
    const bytes = fs.readFileSync(descriptor);
    const openedAfter = fs.fstatSync(descriptor);
    const pathAfter = fs.lstatSync(file);
    assertControl(
      sameIdentity(fileIdentity(openedBefore), fileIdentity(openedAfter))
        && sameIdentity(fileIdentity(openedAfter), fileIdentity(pathAfter))
        && bytes.length === openedAfter.size,
      'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
      `${label} 读取期间 identity/content 漂移`,
    );
    return { bytes, identity: fileIdentity(openedAfter) };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function assertPrivateDirectory(directory, label, create = false) {
  if (create && !fs.existsSync(directory)) {
    const parent = path.dirname(directory);
    if (parent !== directory && !fs.existsSync(parent)) {
      assertPrivateDirectory(parent, `${label} parent`, true);
    }
    try {
      fs.mkdirSync(directory, { mode: 0o700 });
      fsyncDirectory(parent);
    } catch (error) {
      if (!error || error.code !== 'EEXIST') throw error;
    }
  }
  let stat;
  let resolved;
  try {
    stat = fs.lstatSync(directory);
    resolved = fs.realpathSync(directory);
  } catch (error) {
    throw new ControlError(
      'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
      `${label} 无法读取: ${error.message}`,
    );
  }
  assertControl(
    resolved === directory
      && stat.isDirectory()
      && !stat.isSymbolicLink()
      && (stat.mode & 0o777) === 0o700
      && (
        typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
    ),
    'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
    `${label} 必须是当前 uid 的 canonical 0700 non-symlink directory`,
  );
}

function assertPrivateFile(capture, label, links = 1) {
  const stat = capture.identity;
  assertControl(
    (stat.mode & 0o777) === 0o600
      && stat.nlink === links
      && (
        typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
      ),
    'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
    `${label} 必须是当前 uid 的 0600 private file`,
  );
}

function readPrivateArtifact(file, label) {
  assertControl(
    typeof file === 'string'
      && path.isAbsolute(file)
      && path.normalize(file) === file,
    'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
    `${label} path 必须是 canonical absolute path`,
  );
  assertPrivateDirectory(path.dirname(file), `${label} parent`);
  let resolved;
  try {
    resolved = fs.realpathSync(file);
  } catch (error) {
    throw new ControlError(
      'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
      `${label} 无法 canonicalize: ${error.message}`,
    );
  }
  assertControl(
    resolved === file,
    'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
    `${label} 禁止 symlink/path alias`,
  );
  const capture = readStable(file, label);
  assertPrivateFile(capture, label);
  return capture;
}

function assertSafeJsonValue(value, label, depth = 0) {
  assertControl(
    depth <= MAX_PRIVATE_JSON_DEPTH,
    'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
    `${label} JSON nesting 过深`,
  );
  if (typeof value === 'number') {
    assertControl(
      Number.isSafeInteger(value) && !Object.is(value, -0),
      'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
      `${label} 包含非 canonical safe integer`,
    );
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      assertSafeJsonValue(item, label, depth + 1);
    }
    return;
  }
  if (value === null || typeof value !== 'object') return;
  for (const key of Object.keys(value)) {
    assertControl(
      !DANGEROUS_JSON_KEYS.has(key),
      'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
      `${label} 包含 canonical JSON 禁止字段: ${key}`,
    );
    assertSafeJsonValue(value[key], label, depth + 1);
  }
}

function parsePrivateJsonBytes(bytes, label) {
  assertControl(
    Buffer.isBuffer(bytes)
      && bytes.length > 0
      && bytes.length <= MAX_PRIVATE_ARTIFACT_BYTES,
    'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
    `${label} bytes 必须是大小受限的 non-empty Buffer`,
  );
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
      `${label} 不是合法 JSON: ${error.message}`,
    );
  }
  assertSafeJsonValue(value, label);
  return {
    value,
    bytes,
    sha256: `sha256:${sha256(bytes)}`,
  };
}

function parsePrivateJson(file, label) {
  return parsePrivateJsonBytes(
    readPrivateArtifact(file, label).bytes,
    label,
  );
}

function publicationTemporary(target, bytes) {
  return path.join(
    path.dirname(target),
    `.${path.basename(target)}.${sha256(bytes)}.tmp`,
  );
}

function publicationTemporaryFiles(target) {
  const directory = path.dirname(target);
  const prefix = `.${path.basename(target)}.`;
  return fs.readdirSync(directory)
    .filter((name) => (
      name.startsWith(prefix)
        && name.endsWith('.tmp')
    ))
    .map((name) => path.join(directory, name));
}

function inspectPrivateJsonPublication(
  target,
  label,
  conflictCode = 'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
) {
  assertControl(
    typeof target === 'string'
      && path.isAbsolute(target)
      && path.normalize(target) === target,
    'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
    `${label} path 必须是 canonical absolute path`,
  );
  const directory = path.dirname(target);
  assertPrivateDirectory(directory, `${label} parent`);
  const temporaryFiles = publicationTemporaryFiles(target);
  if (!fs.existsSync(target)) {
    if (temporaryFiles.length === 0) {
      return {
        state: 'ABSENT',
        target,
        temporary: null,
        parse_ready: false,
        recoverable: false,
      };
    }
    assertControl(
      temporaryFiles.length === 1,
      conflictCode,
      `${label} 存在多个 staging artifact`,
    );
    const staged = readStable(
      temporaryFiles[0],
      `${label} staging`,
    );
    const expectedTemporary = publicationTemporary(target, staged.bytes);
    assertControl(
      temporaryFiles[0] === expectedTemporary,
      conflictCode,
      `${label} 存在异文 staging artifact`,
    );
    assertPrivateFile(staged, `${label} staging`);
    return {
      state: 'STAGING_ONLY',
      target,
      temporary: expectedTemporary,
      parse_ready: false,
      recoverable: false,
      bytes: staged.bytes,
    };
  }

  const published = readStable(target, label);
  const expectedTemporary = publicationTemporary(target, published.bytes);
  const foreign = temporaryFiles.filter(
    (temporary) => temporary !== expectedTemporary,
  );
  assertControl(
    foreign.length === 0,
    conflictCode,
    `${label} 存在异文 staging artifact`,
  );
  if (!fs.existsSync(expectedTemporary)) {
    assertPrivateFile(published, label);
    return {
      state: 'STABLE',
      target,
      temporary: null,
      parse_ready: true,
      recoverable: false,
      bytes: published.bytes,
    };
  }

  const staged = readStable(
    expectedTemporary,
    `${label} staging`,
  );
  const sameInode = published.identity.dev === staged.identity.dev
    && published.identity.ino === staged.identity.ino;
  assertControl(
    published.bytes.equals(staged.bytes)
      && sameInode,
    conflictCode,
    `${label} publication hardlink lineage 不匹配`,
  );
  assertPrivateFile(published, label, 2);
  assertPrivateFile(staged, `${label} staging`, 2);
  return {
    state: 'PUBLISHED_TEMP_PENDING_UNLINK',
    target,
    temporary: expectedTemporary,
    parse_ready: false,
    recoverable: true,
    bytes: published.bytes,
    target_identity: published.identity,
    temporary_identity: staged.identity,
  };
}

function recoverPrivateJsonPublication(
  target,
  label,
  conflictCode = 'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
) {
  const inspected = inspectPrivateJsonPublication(
    target,
    label,
    conflictCode,
  );
  if (inspected.state !== 'PUBLISHED_TEMP_PENDING_UNLINK') {
    return {
      ...inspected,
      recovered: false,
    };
  }

  const publishedBefore = readStable(target, label);
  const stagedBefore = readStable(
    inspected.temporary,
    `${label} staging`,
  );
  assertControl(
    sameIdentity(
      publishedBefore.identity,
      inspected.target_identity,
    )
      && sameIdentity(
        stagedBefore.identity,
        inspected.temporary_identity,
      )
      && publishedBefore.bytes.equals(inspected.bytes)
      && stagedBefore.bytes.equals(inspected.bytes)
      && publishedBefore.identity.dev === stagedBefore.identity.dev
      && publishedBefore.identity.ino === stagedBefore.identity.ino,
    conflictCode,
    `${label} publication recovery 前 identity/content 漂移`,
  );
  assertPrivateFile(publishedBefore, label, 2);
  assertPrivateFile(stagedBefore, `${label} staging`, 2);
  fs.unlinkSync(inspected.temporary);
  fsyncDirectory(path.dirname(target));

  const recovered = readPrivateArtifact(target, label);
  assertControl(
    recovered.bytes.equals(inspected.bytes),
    conflictCode,
    `${label} recovered bytes 不匹配`,
  );
  return {
    state: 'STABLE',
    target,
    temporary: null,
    parse_ready: true,
    recoverable: false,
    recovered: true,
    bytes: recovered.bytes,
  };
}

function createTemporary(file, bytes, label) {
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
    let offset = 0;
    while (offset < bytes.length) {
      offset += fs.writeSync(
        descriptor,
        bytes,
        offset,
        bytes.length - offset,
      );
    }
    fs.fsyncSync(descriptor);
  } catch (error) {
    if (!error || error.code !== 'EEXIST') {
      throw new ControlError(
        'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
        `${label} staging create 失败: ${error.message}`,
      );
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function publishPrivateJson(
  target,
  value,
  label,
  conflictCode,
  options = {},
) {
  const invokeStage = (stage) => {
    if (typeof options.onStage === 'function') options.onStage(stage);
  };
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  assertControl(
    bytes.length <= MAX_PRIVATE_ARTIFACT_BYTES,
    'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
    `${label} 超过大小上限`,
  );
  const directory = path.dirname(target);
  assertPrivateDirectory(directory, `${label} parent`, true);
  const temporary = publicationTemporary(target, bytes);
  const foreign = publicationTemporaryFiles(target).filter(
    (candidate) => candidate !== temporary,
  );
  assertControl(
    foreign.length === 0,
    conflictCode,
    `${label} 存在异文 staging artifact`,
  );
  if (fs.existsSync(target)) {
    const existing = readStable(target, label);
    assertControl(
      existing.bytes.equals(bytes),
      conflictCode,
      `${label} stable ID 已绑定不同 request/bytes`,
    );
    if (fs.existsSync(temporary)) {
      const staged = readStable(temporary, `${label} staging`);
      assertControl(
        staged.bytes.equals(bytes),
        conflictCode,
        `${label} staging bytes 不匹配`,
      );
      const sameInode = existing.identity.dev === staged.identity.dev
        && existing.identity.ino === staged.identity.ino;
      assertControl(
        sameInode,
        conflictCode,
        `${label} publication hardlink lineage 不匹配`,
      );
      assertPrivateFile(existing, label, 2);
      assertPrivateFile(staged, `${label} staging`, 2);
      fs.unlinkSync(temporary);
      fsyncDirectory(directory);
    } else {
      assertPrivateFile(existing, label);
    }
    const recovered = readPrivateArtifact(target, label);
    assertControl(
      recovered.bytes.equals(bytes),
      conflictCode,
      `${label} recovered bytes 不匹配`,
    );
    return { created: false, bytes: recovered.bytes };
  }
  createTemporary(temporary, bytes, label);
  invokeStage('staging-created');
  const staged = readStable(temporary, `${label} staging`);
  assertPrivateFile(staged, `${label} staging`);
  assertControl(
    staged.bytes.equals(bytes),
    conflictCode,
    `${label} staging bytes 不匹配`,
  );
  try {
    fs.linkSync(temporary, target);
    fsyncDirectory(directory);
  } catch (error) {
    if (!error || error.code !== 'EEXIST') {
      throw new ControlError(
        'CANARY_BOOTSTRAP_ARTIFACT_INVALID',
        `${label} publish 失败: ${error.message}`,
      );
    }
  }
  invokeStage('target-published');
  const published = readStable(target, label);
  const stagedAfter = readStable(temporary, `${label} staging`);
  assertPrivateFile(published, label, 2);
  assertPrivateFile(stagedAfter, `${label} staging`, 2);
  assertControl(
    published.bytes.equals(bytes)
      && stagedAfter.bytes.equals(bytes)
      && published.identity.dev === stagedAfter.identity.dev
      && published.identity.ino === stagedAfter.identity.ino,
    conflictCode,
    `${label} publication hardlink lineage 不匹配`,
  );
  fs.unlinkSync(temporary);
  fsyncDirectory(directory);
  invokeStage('staging-unlinked');
  const finalCapture = readPrivateArtifact(target, label);
  assertControl(
    finalCapture.bytes.equals(bytes),
    conflictCode,
    `${label} final bytes 不匹配`,
  );
  return { created: true, bytes: finalCapture.bytes };
}

module.exports = {
  assertPrivateDirectory,
  inspectPrivateJsonPublication,
  parsePrivateJson,
  parsePrivateJsonBytes,
  publishPrivateJson,
  recoverPrivateJsonPublication,
};
