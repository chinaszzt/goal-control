#!/usr/bin/env node
'use strict';

const fs = require('fs');
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
const {
  verifyTargetProvenance,
} = require('./verify-extraction-provenance');

function fail(message) {
  process.stderr.write(`verify-source-equivalence: ${message}\n`);
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

function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    const provenance = verifyTargetProvenance();
    const source = fs.realpathSync(options.sourceWorktree);
    const sourceHead = git(source, [
      'rev-parse',
      '--verify',
      'HEAD^{commit}',
    ]);
    const sourceFiles = importedFiles(source);
    const manifestFiles = provenance.files.map((entry) => entry.path);
    for (const [label, files] of [
      ['source', sourceFiles],
      ['manifest', manifestFiles],
    ]) {
      if (new Set(files).size !== files.length) {
        fail(`${label} inventory contains duplicates`);
      }
    }
    if (
      JSON.stringify(sourceFiles) !== JSON.stringify(manifestFiles)
    ) {
      fail('source/manifest imported-file inventories differ');
    }
    if (
      JSON.stringify([...PORTABLE_DELTA_ALLOWLIST].sort())
        !== JSON.stringify(provenance.portable_delta_allowlist)
    ) {
      fail('portable delta allowlist drifted');
    }
    assertImportedPathsClean(source, sourceFiles);
    const sourceEntries = snapshotImportedEntries(source, sourceHead);

    const mismatches = [];
    const observedSourceTreeSha256 =
      productionTreeSha256(sourceEntries);
    if (
      observedSourceTreeSha256
        !== provenance.source_production_tree_sha256
    ) {
      mismatches.push(
        `source_production_tree_sha256 expected=${provenance.source_production_tree_sha256} observed=${observedSourceTreeSha256}`,
      );
    }
    for (let index = 0; index < provenance.files.length; index += 1) {
      const entry = provenance.files[index];
      const sourceEntry = sourceEntries[index];
      const observed = {
        source_mode: sourceEntry.mode,
        target_mode: entry.target_mode,
        source_sha256: sourceEntry.sha256,
        target_sha256: entry.target_sha256,
      };
      for (const [key, value] of Object.entries(observed)) {
        if (key.startsWith('target_')) continue;
        if (value !== entry[key]) {
          mismatches.push(
            `${entry.path}: ${key} expected=${entry[key]} observed=${value}`,
          );
        }
      }
      const expectedStatus = extractionStatus(observed);
      if (entry.status !== expectedStatus) {
        mismatches.push(
          `${entry.path}: status expected=${entry.status} observed=${expectedStatus}`,
        );
      }
      if (
        expectedStatus === 'PORTABLE_DELTA'
          && !PORTABLE_DELTA_ALLOWLIST.has(entry.path)
      ) {
        mismatches.push(`${entry.path}: unapproved portable delta`);
      }
    }
    if (
      portableDeltaSha256(provenance.files)
        !== provenance.portable_delta_sha256
    ) {
      mismatches.push('portable delta aggregate hash drifted');
    }

    for (const [label, observed, expected] of [
      [
        'source_controller',
        snapshotControllerIdentity(source, sourceHead, sourceEntries),
        provenance.source_controller,
      ],
    ]) {
      for (const key of [
        'decoder_sha256',
        'controller_closure_sha256',
      ]) {
        if (observed[key] !== expected[key]) {
          mismatches.push(
            `${label}.${key}: expected=${expected[key]} observed=${observed[key]}`,
          );
        }
      }
    }
    if (mismatches.length > 0) fail(mismatches.join('\n'));
    process.stdout.write(
      `source-equivalence: PASS (${provenance.files.length} files; ${provenance.portable_delta_allowlist.length} audited portable deltas)\n`,
    );
  } catch (error) {
    fail(error.message);
  }
}

main();
