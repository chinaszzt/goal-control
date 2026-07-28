#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const {
  PORTABLE_DELTA_ALLOWLIST,
  assertTrackedFileClean,
  extractionStatus,
  git,
  portableDeltaSha256,
  productionTreeSha256,
  sha256,
  snapshotControllerIdentity,
  snapshotImportedEntries,
  snapshotTrackedEntry,
} = require('./extraction-provenance-lib');

const ROOT = path.resolve(__dirname, '..');

function fail(message) {
  process.stderr.write(`verify-extraction-provenance: ${message}\n`);
  process.exit(1);
}

function assertUniqueInventory(label, files) {
  if (new Set(files).size !== files.length) {
    throw new Error(`${label} inventory contains duplicates`);
  }
}

function loadProvenance(provenanceFile) {
  let stat;
  try {
    stat = fs.lstatSync(provenanceFile);
  } catch {
    throw new Error('extraction/provenance.json is missing');
  }
  if (
    !stat.isFile()
      || stat.isSymbolicLink()
  ) {
    throw new Error(
      'extraction/provenance.json must be a canonical ordinary file',
    );
  }
  const provenance = JSON.parse(fs.readFileSync(provenanceFile, 'utf8'));
  if (
    provenance === null
      || typeof provenance !== 'object'
      || Array.isArray(provenance)
      || provenance.schema_version !== 3
      || provenance.source_label !== 'private-production-integration'
      || provenance.target_snapshot_basis
        !== 'PROVENANCE_FIRST_ADD_COMMIT'
      || !Array.isArray(provenance.files)
      || !Array.isArray(provenance.portable_delta_allowlist)
      || !/^sha256:[0-9a-f]{64}$/.test(
        provenance.source_production_tree_sha256 || '',
      )
      || !/^sha256:[0-9a-f]{64}$/.test(
        provenance.target_production_tree_sha256 || '',
      )
      || !/^sha256:[0-9a-f]{64}$/.test(
        provenance.source_controller?.decoder_sha256 || '',
      )
      || !/^sha256:[0-9a-f]{64}$/.test(
        provenance.source_controller?.controller_closure_sha256 || '',
      )
      || !/^sha256:[0-9a-f]{64}$/.test(
        provenance.target_controller?.decoder_sha256 || '',
      )
      || !/^sha256:[0-9a-f]{64}$/.test(
        provenance.target_controller?.controller_closure_sha256 || '',
      )
      || !/^sha256:[0-9a-f]{64}$/.test(
        provenance.portable_delta_sha256 || '',
      )
      || !provenance.files.every((entry) => (
        entry !== null
          && typeof entry === 'object'
          && typeof entry.path === 'string'
          && ['IDENTICAL', 'PORTABLE_DELTA'].includes(entry.status)
          && ['100644', '100755'].includes(entry.source_mode)
          && ['100644', '100755'].includes(entry.target_mode)
          && /^sha256:[0-9a-f]{64}$/.test(entry.source_sha256 || '')
          && /^sha256:[0-9a-f]{64}$/.test(entry.target_sha256 || '')
      ))
  ) {
    throw new Error('extraction/provenance.json has an unsupported shape');
  }
  return provenance;
}

function verifyTargetProvenance(
  root = ROOT,
  provenanceFile = path.join(root, 'extraction', 'provenance.json'),
) {
  const provenance = loadProvenance(provenanceFile);
  const canonicalRoot = fs.realpathSync(root);
  const expectedProvenanceFile = path.join(
    canonicalRoot,
    'extraction',
    'provenance.json',
  );
  if (
    fs.realpathSync(provenanceFile) !== expectedProvenanceFile
  ) {
    throw new Error(
      'extraction/provenance.json must be a clean tracked repository file',
    );
  }
  assertTrackedFileClean(
    root,
    'extraction/provenance.json',
    '100644',
  );
  if (
    git(root, ['rev-parse', '--is-shallow-repository']) !== 'false'
  ) {
    throw new Error(
      'extraction provenance verification requires complete Git history; shallow repositories are unsupported',
    );
  }
  const additions = git(root, [
    'log',
    '--format=%H',
    '--diff-filter=A',
    '--full-history',
    'HEAD',
    '--',
    'extraction/provenance.json',
  ]).split('\n').filter(Boolean);
  if (additions.length !== 1 || !/^[0-9a-f]{40}$/.test(additions[0])) {
    throw new Error(
      'extraction/provenance.json must have exactly one first-add commit',
    );
  }
  const baselineCommit = additions[0];
  const baselineManifest = snapshotTrackedEntry(
    root,
    baselineCommit,
    'extraction/provenance.json',
  );
  if (
    baselineManifest.mode !== '100644'
      || baselineManifest.sha256 !== sha256(provenanceFile)
  ) {
    throw new Error(
      'extraction/provenance.json differs from its immutable first-add blob',
    );
  }
  const snapshotEntries = snapshotImportedEntries(
    root,
    baselineCommit,
  );
  const targetFiles = snapshotEntries.map((entry) => entry.path);
  const manifestFiles = provenance.files.map((entry) => entry.path);
  assertUniqueInventory('target snapshot', targetFiles);
  assertUniqueInventory('manifest', manifestFiles);
  if (JSON.stringify(targetFiles) !== JSON.stringify(manifestFiles)) {
    throw new Error('target/manifest imported-file inventories differ');
  }
  if (provenance.imported_file_count !== manifestFiles.length) {
    throw new Error('imported_file_count does not match the manifest inventory');
  }
  const observedSourceTreeSha256 = productionTreeSha256(
    provenance.files.map((entry) => ({
      path: entry.path,
      mode: entry.source_mode,
      sha256: entry.source_sha256,
    })),
  );
  if (
    observedSourceTreeSha256
      !== provenance.source_production_tree_sha256
  ) {
    throw new Error(
      `source_production_tree_sha256 expected=${provenance.source_production_tree_sha256} observed=${observedSourceTreeSha256}`,
    );
  }
  const observedTargetTreeSha256 =
    productionTreeSha256(snapshotEntries);
  if (
    observedTargetTreeSha256
      !== provenance.target_production_tree_sha256
  ) {
    throw new Error(
      `target_production_tree_sha256 expected=${provenance.target_production_tree_sha256} observed=${observedTargetTreeSha256}`,
    );
  }

  const expectedAllowlist = [...PORTABLE_DELTA_ALLOWLIST].sort();
  if (
    JSON.stringify(expectedAllowlist)
      !== JSON.stringify(provenance.portable_delta_allowlist)
  ) {
    throw new Error('portable delta allowlist drifted');
  }
  const mismatches = [];
  const observedDeltas = new Set();
  for (let index = 0; index < provenance.files.length; index += 1) {
    const entry = provenance.files[index];
    const snapshot = snapshotEntries[index];
    if (
      entry === null
        || typeof entry !== 'object'
        || typeof entry.path !== 'string'
        || typeof entry.source_sha256 !== 'string'
        || typeof entry.target_sha256 !== 'string'
        || typeof entry.source_mode !== 'string'
        || typeof entry.target_mode !== 'string'
    ) {
      mismatches.push('manifest contains an invalid file record');
      continue;
    }
    if (snapshot.mode !== entry.target_mode) {
      mismatches.push(
        `${entry.path}: target_mode expected=${entry.target_mode} snapshot=${snapshot.mode}`,
      );
    }
    if (snapshot.sha256 !== entry.target_sha256) {
      mismatches.push(
        `${entry.path}: target_sha256 expected=${entry.target_sha256} snapshot=${snapshot.sha256}`,
      );
    }
    const expectedStatus = extractionStatus(entry);
    if (entry.status !== expectedStatus) {
      mismatches.push(
        `${entry.path}: status expected=${entry.status} observed=${expectedStatus}`,
      );
    }
    if (expectedStatus === 'PORTABLE_DELTA') {
      observedDeltas.add(entry.path);
      if (!PORTABLE_DELTA_ALLOWLIST.has(entry.path)) {
        mismatches.push(`${entry.path}: unapproved portable delta`);
      }
    }
  }
  for (const allowed of PORTABLE_DELTA_ALLOWLIST) {
    if (!observedDeltas.has(allowed)) {
      mismatches.push(`expected portable delta is absent: ${allowed}`);
    }
  }
  const observedDeltaSha256 = portableDeltaSha256(provenance.files);
  if (observedDeltaSha256 !== provenance.portable_delta_sha256) {
    mismatches.push(
      `portable_delta_sha256 expected=${provenance.portable_delta_sha256} observed=${observedDeltaSha256}`,
    );
  }

  const targetIdentity = snapshotControllerIdentity(
    root,
    baselineCommit,
    snapshotEntries,
  );
  for (const key of [
    'decoder_sha256',
    'controller_closure_sha256',
  ]) {
    if (targetIdentity[key] !== provenance.target_controller?.[key]) {
      mismatches.push(
        `target_controller.${key}: expected=${provenance.target_controller?.[key]} observed=${targetIdentity[key]}`,
      );
    }
  }
  if (mismatches.length > 0) {
    throw new Error(mismatches.join('\n'));
  }
  return provenance;
}

if (require.main === module) {
  try {
    const provenance = verifyTargetProvenance();
    process.stdout.write(
      `extraction-provenance: PASS (${provenance.files.length} production files; ${provenance.portable_delta_allowlist.length} audited portable deltas)\n`,
    );
  } catch (error) {
    fail(error.message);
  }
}

module.exports = {
  verifyTargetProvenance,
};
