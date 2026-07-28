'use strict';

const { createHash } = require('crypto');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  readOnlyGitEnvironment,
  trustedGitExecutable,
} = require('./goal-control/util');

const PORTABLE_DELTA_ALLOWLIST = new Set([
  'scripts/goal-control/migration.js',
  'scripts/goal-control/preflight.js',
  'scripts/goal-control/schemas/event.schema.json',
  'scripts/goal-control/schemas/evidence.schema.json',
  'scripts/goal-control/schemas/goal-manifest.schema.json',
  'scripts/goal-control/schemas/launch-manifest.schema.json',
  'scripts/goal-control/schemas/resource-event.schema.json',
]);

function git(cwd, args) {
  return execFileSync(trustedGitExecutable(), args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...readOnlyGitEnvironment(),
      GIT_NO_REPLACE_OBJECTS: '1',
    },
  }).trim();
}

function gitBytes(cwd, args) {
  return execFileSync(trustedGitExecutable(), args, {
    cwd,
    encoding: null,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...readOnlyGitEnvironment(),
      GIT_NO_REPLACE_OBJECTS: '1',
    },
  });
}

function sha256Bytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function sha256(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${file} must be an ordinary file`);
  }
  return sha256Bytes(fs.readFileSync(file));
}

function walkFiles(root, relative) {
  const absolute = path.join(root, relative);
  const stat = fs.lstatSync(absolute);
  if (stat.isSymbolicLink()) {
    throw new Error(`${relative} must not be a symlink`);
  }
  if (stat.isFile()) return [relative];
  if (!stat.isDirectory()) {
    throw new Error(`${relative} must be a regular file or directory`);
  }
  return fs.readdirSync(absolute)
    .sort()
    .flatMap((entry) => walkFiles(root, path.join(relative, entry)));
}

function importedFiles(root) {
  return [
    ...walkFiles(root, 'scripts/goal-control'),
    'scripts/goalctl.js',
    'scripts/resourcectl.js',
  ].sort();
}

function portableDeltaSha256(files) {
  const deltas = files
    .filter((entry) => entry.status === 'PORTABLE_DELTA')
    .map((entry) => ({
      path: entry.path,
      source_mode: entry.source_mode,
      target_mode: entry.target_mode,
      source_sha256: entry.source_sha256,
      target_sha256: entry.target_sha256,
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  return `sha256:${createHash('sha256')
    .update(JSON.stringify(deltas))
    .digest('hex')}`;
}

function productionTreeSha256(entries) {
  const tree = entries
    .map((entry) => ({
      path: entry.path,
      mode: entry.mode || entry.target_mode,
      sha256: entry.sha256 || entry.target_sha256,
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  return `sha256:${createHash('sha256')
    .update(JSON.stringify(tree))
    .digest('hex')}`;
}

function extractionStatus(entry) {
  return entry.source_sha256 === entry.target_sha256
      && entry.source_mode === entry.target_mode
    ? 'IDENTICAL'
    : 'PORTABLE_DELTA';
}

function snapshotImportedEntries(root, requestedCommit) {
  if (
    typeof requestedCommit !== 'string'
      || !/^[0-9a-f]{40,64}$/.test(requestedCommit)
  ) {
    throw new Error('target snapshot must be a full canonical commit ID');
  }
  const commit = git(root, [
    'rev-parse',
    '--verify',
    `${requestedCommit}^{commit}`,
  ]);
  if (commit !== requestedCommit || !/^[0-9a-f]{40,64}$/.test(commit)) {
    throw new Error('target snapshot must be a full canonical commit ID');
  }
  const tree = gitBytes(root, [
    'ls-tree',
    '-r',
    '-z',
    commit,
    '--',
    'scripts/goal-control',
    'scripts/goalctl.js',
    'scripts/resourcectl.js',
  ]);
  if (tree.length === 0 || tree[tree.length - 1] !== 0) {
    throw new Error('target snapshot production tree is empty or malformed');
  }
  const records = tree
    .subarray(0, tree.length - 1)
    .toString('utf8')
    .split('\0');
  const entries = records.map((record) => {
    const match = /^(100644|100755) blob ([0-9a-f]{40,64})\t(.+)$/
      .exec(record);
    if (
      match === null
        || !/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/
          .test(match[3])
        || !(
          match[3] === 'scripts/goalctl.js'
            || match[3] === 'scripts/resourcectl.js'
            || match[3].startsWith('scripts/goal-control/')
        )
    ) {
      throw new Error('target snapshot contains a non-canonical production entry');
    }
    const bytes = gitBytes(root, ['cat-file', 'blob', match[2]]);
    return {
      path: match[3],
      mode: match[1],
      blob: match[2],
      sha256: sha256Bytes(bytes),
      bytes,
    };
  }).sort((left, right) => left.path.localeCompare(right.path));
  if (
    entries.length === 0
      || new Set(entries.map((entry) => entry.path)).size !== entries.length
  ) {
    throw new Error('target snapshot production inventory is empty or duplicated');
  }
  return entries;
}

function snapshotControllerIdentity(root, commit, entries) {
  const sandbox = fs.mkdtempSync(
    path.join(os.tmpdir(), 'goal-control-snapshot-'),
  );
  try {
    for (const entry of entries) {
      const absolute = path.join(sandbox, entry.path);
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      fs.writeFileSync(absolute, entry.bytes, {
        mode: entry.mode === '100755' ? 0o755 : 0o644,
      });
    }
    const decoderDirectory = path.join(
      sandbox,
      'scripts',
      'goal-control',
    );
    const {
      controllerDecoderFingerprintAt,
    } = require(path.join(decoderDirectory, 'store.js'));
    const { hashObject } = require(path.join(decoderDirectory, 'util.js'));
    const closureFiles = entries
      .filter((entry) => (
        entry.path === 'scripts/goalctl.js'
          || entry.path.startsWith('scripts/goal-control/')
      ))
      .map((entry) => ({
        path: entry.path,
        mode: entry.mode,
        blob: entry.blob,
        sha256: entry.sha256,
      }));
    return {
      head: commit,
      decoder_sha256:
        controllerDecoderFingerprintAt(decoderDirectory),
      controller_closure_sha256: hashObject({
        schema_version: 1,
        files: closureFiles,
      }),
    };
  } finally {
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
}

function trackedMode(root, relative) {
  const record = git(root, ['ls-files', '-s', '--', relative]);
  if (record === '') throw new Error(`${relative} is not tracked`);
  const lines = record.split('\n');
  if (lines.length !== 1) throw new Error(`${relative} has ambiguous index entries`);
  const match = /^(\d{6}) [0-9a-f]{40,64} 0\t/.exec(lines[0]);
  if (!match) throw new Error(`${relative} has an invalid index record`);
  return match[1];
}

function assertTrackedEntriesMatchSnapshot(root, entries) {
  const canonicalRoot = fs.realpathSync(root);
  for (const entry of entries) {
    const absolute = path.join(canonicalRoot, entry.path);
    let stat;
    let canonical;
    try {
      stat = fs.lstatSync(absolute);
      canonical = fs.realpathSync(absolute);
    } catch (error) {
      throw new Error(
        `${entry.path} is missing from the worktree: ${error.message}`,
      );
    }
    if (
      !stat.isFile()
        || stat.isSymbolicLink()
        || stat.nlink !== 1
        || canonical !== absolute
    ) {
      throw new Error(`${entry.path} must be a canonical single-link file`);
    }
    const worktreeMode = (stat.mode & 0o111) === 0
      ? '100644'
      : '100755';
    const worktreeSha256 = sha256(absolute);
    if (
      worktreeMode !== entry.mode
        || worktreeSha256 !== entry.sha256
    ) {
      throw new Error(
        `${entry.path} worktree bytes/mode differ from the pinned commit`,
      );
    }
    const index = git(root, ['ls-files', '-s', '--', entry.path]);
    const indexMatch =
      /^(\d{6}) ([0-9a-f]{40,64}) 0\t(.+)$/.exec(index);
    if (
      indexMatch === null
        || indexMatch[1] !== entry.mode
        || indexMatch[2] !== entry.blob
        || indexMatch[3] !== entry.path
    ) {
      throw new Error(
        `${entry.path} index stage/blob/mode differ from the pinned commit`,
      );
    }
    const flag = gitBytes(root, [
      'ls-files',
      '-v',
      '-z',
      '--',
      entry.path,
    ]).toString('utf8');
    if (flag !== `H ${entry.path}\0`) {
      throw new Error(
        `${entry.path} has an unsafe assume-unchanged/skip-worktree/index flag`,
      );
    }
  }
}

function snapshotTrackedEntry(root, commit, relative) {
  const tree = gitBytes(root, [
    'ls-tree',
    '-z',
    commit,
    '--',
    relative,
  ]);
  if (tree.length === 0 || tree[tree.length - 1] !== 0) {
    throw new Error(`${relative} is missing from commit ${commit}`);
  }
  const records = tree
    .subarray(0, tree.length - 1)
    .toString('utf8')
    .split('\0');
  if (records.length !== 1) {
    throw new Error(`${relative} has an ambiguous commit tree entry`);
  }
  const match = /^(100644|100755) blob ([0-9a-f]{40,64})\t(.+)$/
    .exec(records[0]);
  if (match === null || match[3] !== relative) {
    throw new Error(`${relative} has an invalid commit tree entry`);
  }
  const bytes = gitBytes(root, ['cat-file', 'blob', match[2]]);
  return {
    path: relative,
    mode: match[1],
    blob: match[2],
    sha256: sha256Bytes(bytes),
    bytes,
  };
}

function assertTrackedFileClean(root, relative, expectedMode) {
  const head = git(root, ['rev-parse', '--verify', 'HEAD^{commit}']);
  const entry = snapshotTrackedEntry(root, head, relative);
  if (expectedMode !== undefined && entry.mode !== expectedMode) {
    throw new Error(`${relative} must have Git mode ${expectedMode}`);
  }
  assertTrackedEntriesMatchSnapshot(root, [entry]);
  return entry;
}

function assertImportedPathsClean(root, files) {
  const head = git(root, ['rev-parse', '--verify', 'HEAD^{commit}']);
  const entries = snapshotImportedEntries(root, head);
  const snapshotFiles = entries.map((entry) => entry.path);
  if (JSON.stringify(files) !== JSON.stringify(snapshotFiles)) {
    throw new Error('worktree and pinned-commit imported inventories differ');
  }
  assertTrackedEntriesMatchSnapshot(root, entries);
}

function controllerIdentity(root) {
  const head = git(root, ['rev-parse', 'HEAD']);
  const decoderDirectory = path.join(root, 'scripts', 'goal-control');
  const {
    controllerDecoderFingerprintAt,
  } = require(path.join(decoderDirectory, 'store.js'));
  const {
    assertControllerControlPathsCommitted,
  } = require(path.join(
    decoderDirectory,
    'canary-controller-attestation.js',
  ));
  const closure = assertControllerControlPathsCommitted(root, head);
  return {
    head,
    decoder_sha256: controllerDecoderFingerprintAt(decoderDirectory),
    controller_closure_sha256: closure.closureSha256,
  };
}

module.exports = {
  PORTABLE_DELTA_ALLOWLIST,
  assertImportedPathsClean,
  assertTrackedFileClean,
  controllerIdentity,
  extractionStatus,
  git,
  importedFiles,
  portableDeltaSha256,
  productionTreeSha256,
  sha256,
  snapshotControllerIdentity,
  snapshotImportedEntries,
  snapshotTrackedEntry,
  trackedMode,
};
