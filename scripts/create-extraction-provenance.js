#!/usr/bin/env node
'use strict';

const { randomBytes } = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  PORTABLE_DELTA_ALLOWLIST,
  assertImportedPathsClean,
  extractionStatus,
  git,
  importedFiles,
  portableDeltaSha256,
  productionTreeSha256,
  snapshotControllerIdentity,
  snapshotImportedEntries,
} = require('./extraction-provenance-lib');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'extraction', 'provenance.json');

function fail(message) {
  process.stderr.write(`create-extraction-provenance: ${message}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--') {
      continue;
    }
    if (argv[index] === '--source-worktree') {
      options.sourceWorktree = argv[index + 1];
      index += 1;
    } else {
      fail(`unknown argument ${argv[index]}`);
    }
  }
  if (!options.sourceWorktree) fail('--source-worktree is required');
  return options;
}

function assertCanonicalOutputParent() {
  const parent = path.dirname(OUTPUT);
  if (!fs.existsSync(parent)) {
    fs.mkdirSync(parent, { mode: 0o755 });
  }
  const stat = fs.lstatSync(parent);
  if (
    !stat.isDirectory()
      || stat.isSymbolicLink()
      || fs.realpathSync(parent) !== parent
      || path.dirname(parent) !== fs.realpathSync(ROOT)
  ) {
    throw new Error(
      'extraction output directory must be a canonical in-repository directory',
    );
  }
  return parent;
}

function writeProvenance(body) {
  const parent = assertCanonicalOutputParent();
  if (fs.existsSync(OUTPUT)) {
    const stat = fs.lstatSync(OUTPUT);
    if (
      !stat.isFile()
        || stat.isSymbolicLink()
        || fs.realpathSync(OUTPUT) !== OUTPUT
    ) {
      throw new Error(
        'existing extraction/provenance.json is not a canonical ordinary file',
      );
    }
    if (fs.readFileSync(OUTPUT, 'utf8') === body) return false;
    throw new Error(
      'existing extraction/provenance.json differs; the historical baseline is immutable',
    );
  }
  const temporary = path.join(
    parent,
    `.provenance.${process.pid}.${randomBytes(8).toString('hex')}.tmp`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_WRONLY,
      0o600,
    );
    fs.writeFileSync(descriptor, body, 'utf8');
    fs.fsyncSync(descriptor);
    fs.fchmodSync(descriptor, 0o644);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, OUTPUT);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(temporary, { force: true });
  }
  return true;
}

function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    const source = fs.realpathSync(options.sourceWorktree);
    const sourceFiles = importedFiles(source);
    const targetFiles = importedFiles(ROOT);
    if (JSON.stringify(sourceFiles) !== JSON.stringify(targetFiles)) {
      fail('source and target imported-file inventories differ');
    }
    assertImportedPathsClean(source, sourceFiles);
    assertImportedPathsClean(ROOT, targetFiles);

    const sourceCommit = git(source, [
      'rev-parse',
      '--verify',
      'HEAD^{commit}',
    ]);
    const targetSnapshotCommit = git(ROOT, [
      'rev-parse',
      '--verify',
      'HEAD^{commit}',
    ]);
    const sourceEntries = snapshotImportedEntries(
      source,
      sourceCommit,
    );
    const targetEntries = snapshotImportedEntries(
      ROOT,
      targetSnapshotCommit,
    );
    const files = sourceEntries.map((sourceEntry, index) => {
      const targetEntry = targetEntries[index];
      const relative = sourceEntry.path;
      const sourceSha256 = sourceEntry.sha256;
      const targetSha256 = targetEntry.sha256;
      const sourceMode = sourceEntry.mode;
      const targetMode = targetEntry.mode;
      const status = extractionStatus({
        source_sha256: sourceSha256,
        target_sha256: targetSha256,
        source_mode: sourceMode,
        target_mode: targetMode,
      });
      if (
        status === 'PORTABLE_DELTA'
          && !PORTABLE_DELTA_ALLOWLIST.has(relative)
      ) {
        fail(`unexpected portable delta: ${relative}`);
      }
      return {
        path: relative,
        status,
        source_mode: sourceMode,
        target_mode: targetMode,
        source_sha256: sourceSha256,
        target_sha256: targetSha256,
      };
    });
    const observedDeltas = new Set(
      files
        .filter((entry) => entry.status === 'PORTABLE_DELTA')
        .map((entry) => entry.path),
    );
    for (const allowed of PORTABLE_DELTA_ALLOWLIST) {
      if (!observedDeltas.has(allowed)) {
        fail(`expected portable delta is absent: ${allowed}`);
      }
    }

    const sourceIdentity = snapshotControllerIdentity(
      source,
      sourceCommit,
      sourceEntries,
    );
    const targetIdentity = snapshotControllerIdentity(
      ROOT,
      targetSnapshotCommit,
      targetEntries,
    );
    const manifest = {
      schema_version: 3,
      source_label: 'private-production-integration',
      target_snapshot_basis: 'PROVENANCE_FIRST_ADD_COMMIT',
      source_production_tree_sha256:
        productionTreeSha256(sourceEntries),
      target_production_tree_sha256:
        productionTreeSha256(targetEntries),
      imported_file_count: files.length,
      portable_delta_allowlist: [...PORTABLE_DELTA_ALLOWLIST].sort(),
      portable_delta_sha256: portableDeltaSha256(files),
      source_controller: {
        decoder_sha256: sourceIdentity.decoder_sha256,
        controller_closure_sha256:
          sourceIdentity.controller_closure_sha256,
      },
      target_controller: {
        decoder_sha256: targetIdentity.decoder_sha256,
        controller_closure_sha256:
          targetIdentity.controller_closure_sha256,
      },
      files,
    };
    const created = writeProvenance(
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
    process.stdout.write(
      `extraction provenance ${created ? 'written' : 'already exact'}: ${files.length} files, ${observedDeltas.size} portable deltas\n`,
    );
  } catch (error) {
    fail(error.message);
  }
}

main();
