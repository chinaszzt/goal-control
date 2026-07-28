'use strict';

const fs = require('fs');
const path = require('path');
const { readCapabilityFile } = require('./auth');
const { ControlError, assertControl } = require('./errors');
const { atomicWriteJson } = require('./store');
const {
  hashObject,
  readJson,
  trustedTemporaryRoot,
} = require('./util');

const INIT_RECEIPT_SCHEMA_VERSION = 1;
const INIT_RECEIPT_FILE = 'init-receipt.json';
const INIT_RECEIPT_KEYS = Object.freeze([
  'schema_version',
  'goal_id',
  'manifest_sha256',
  'source_manifest_sha256',
  'repository_root',
  'initialized_at',
  'bootstrap_capability_file',
  'bootstrap_capability_sha256',
  'foreman_recovery_capability_file',
  'foreman_recovery_capability_sha256',
  'publication_kind',
  'publication_recorded_at',
  'legacy_source_sha256',
  'receipt_sha256',
  'goal_input_head',
  'goal_input_source',
]);

function fsyncDirectory(directory) {
  let fd;
  try {
    fd = fs.openSync(directory, 'r');
    fs.fsyncSync(fd);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code)) throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function ensurePrivateDirectory(directory, options = {}) {
  if (options.create === true) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  let stat;
  try {
    stat = fs.lstatSync(directory);
  } catch (error) {
    throw new ControlError(
      'INIT_PERMISSION_INVALID',
      `init private directory 无法读取: ${directory}: ${error.message}`,
    );
  }
  assertControl(
    stat.isDirectory() && !stat.isSymbolicLink(),
    'INIT_PERMISSION_INVALID',
    `init private directory 必须是非 symlink 目录: ${directory}`,
  );
  if (typeof process.getuid === 'function') {
    assertControl(
      stat.uid === process.getuid(),
      'INIT_PERMISSION_INVALID',
      `init private directory owner 不匹配: ${directory}`,
    );
  }
  if (options.repair === true) fs.chmodSync(directory, 0o700);
  const verified = fs.lstatSync(directory);
  assertControl(
    (verified.mode & 0o777) === 0o700,
    'INIT_PERMISSION_INVALID',
    `init private directory 权限必须为 0700: ${directory}`,
  );
}

function assertPrivateFile(file, label) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    throw new ControlError('INIT_PERMISSION_INVALID', `${label} 无法读取: ${error.message}`);
  }
  assertControl(
    stat.isFile() && !stat.isSymbolicLink(),
    'INIT_PERMISSION_INVALID',
    `${label} 必须是非 symlink 普通文件`,
  );
  assertControl(
    (stat.mode & 0o777) === 0o600,
    'INIT_PERMISSION_INVALID',
    `${label} 权限必须为 0600`,
  );
  if (typeof process.getuid === 'function') {
    assertControl(stat.uid === process.getuid(), 'INIT_PERMISSION_INVALID', `${label} owner 不匹配`);
  }
}

function sealInitReceipt(unsigned) {
  return {
    ...unsigned,
    receipt_sha256: hashObject(unsigned),
  };
}

function writeInitReceipt(temporaryGoalDir, unsigned) {
  const receipt = sealInitReceipt(unsigned);
  const file = path.join(temporaryGoalDir, INIT_RECEIPT_FILE);
  atomicWriteJson(file, receipt);
  assertPrivateFile(file, 'init receipt');
  return { file, receipt };
}

function capabilityMaterial(
  materialDirectory,
  metadata,
  publishedGoalDirectory = materialDirectory,
) {
  const expectedBootstrapFile = path.join(
    publishedGoalDirectory,
    'capabilities',
    'bootstrap.cap',
  );
  const expectedForemanRecoveryFile = path.join(
    publishedGoalDirectory,
    'capabilities',
    'foreman-recovery.cap',
  );
  const materialBootstrapFile = path.join(
    materialDirectory,
    'capabilities',
    'bootstrap.cap',
  );
  const materialForemanRecoveryFile = path.join(
    materialDirectory,
    'capabilities',
    'foreman-recovery.cap',
  );
  assertControl(
    metadata.bootstrap_capability_file === expectedBootstrapFile
      && metadata.foreman_recovery_capability_file === expectedForemanRecoveryFile
      && /^[0-9a-f]{64}$/.test(metadata.bootstrap_capability_sha256)
      && /^[0-9a-f]{64}$/.test(metadata.foreman_recovery_capability_sha256),
    'INIT_CAPABILITY_TAMPERED',
    'Goal metadata 的 init capability identity 非法',
  );
  const bootstrapConsumed = !fs.existsSync(materialBootstrapFile);
  assertControl(
    !bootstrapConsumed
      || (
        typeof metadata.bootstrap_consumed_at === 'string'
        && Number.isFinite(Date.parse(metadata.bootstrap_consumed_at))
      ),
    'INIT_CAPABILITY_TAMPERED',
    'bootstrap capability 缺失，但 metadata 未记录已消费',
  );
  if (!bootstrapConsumed) {
    assertPrivateFile(materialBootstrapFile, 'bootstrap capability');
  }
  assertPrivateFile(
    materialForemanRecoveryFile,
    'FOREMAN recovery capability',
  );
  let bootstrap = null;
  let foremanRecovery;
  try {
    if (!bootstrapConsumed) {
      bootstrap = readCapabilityFile(
        materialBootstrapFile,
        materialBootstrapFile,
      );
    }
    foremanRecovery = readCapabilityFile(
      materialForemanRecoveryFile,
      materialForemanRecoveryFile,
    );
  } catch (error) {
    if (error instanceof ControlError && error.code === 'CAPABILITY_PERMISSIONS') {
      throw new ControlError('INIT_PERMISSION_INVALID', error.message);
    }
    throw new ControlError('INIT_CAPABILITY_TAMPERED', `init capability 无法验证: ${error.message}`);
  }
  assertControl(
    (bootstrapConsumed || bootstrap.sha256 === metadata.bootstrap_capability_sha256)
      && foremanRecovery.sha256 === metadata.foreman_recovery_capability_sha256,
    'INIT_CAPABILITY_TAMPERED',
    'init capability bytes 与 sealed Goal metadata 不一致',
  );
  return {
    bootstrapConsumed,
    bootstrapFile: expectedBootstrapFile,
    foremanRecoveryFile: expectedForemanRecoveryFile,
  };
}

function adoptLegacyInitReceipt(goalDirectory, expected) {
  ensurePrivateDirectory(goalDirectory, { repair: true });
  const capabilitiesDirectory = path.join(goalDirectory, 'capabilities');
  ensurePrivateDirectory(capabilitiesDirectory, { repair: true });
  const manifestFile = path.join(goalDirectory, 'manifest.json');
  const metadataFile = path.join(goalDirectory, 'goal.json');
  assertPrivateFile(manifestFile, 'control manifest');
  assertPrivateFile(metadataFile, 'Goal metadata');
  const manifest = readJson(manifestFile, 'control manifest');
  const metadata = readJson(metadataFile, 'Goal metadata');
  const unsignedManifest = { ...manifest };
  delete unsignedManifest.manifest_sha256;
  const unsignedMetadata = { ...metadata };
  delete unsignedMetadata.meta_sha256;
  assertControl(
    manifest.manifest_sha256 === expected.manifestSha256
      && hashObject(unsignedManifest) === manifest.manifest_sha256
      && metadata.goal_id === expected.goalId
      && metadata.repository_root === expected.repositoryRoot
      && hashObject(unsignedMetadata) === metadata.meta_sha256,
    'INIT_LEGACY_ADOPTION_REJECTED',
    'legacy Goal manifest/metadata seal 或 identity 不匹配',
  );
  const material = capabilityMaterial(goalDirectory, metadata);
  assertControl(
    material.bootstrapConsumed === expected.bootstrapConsumed
      && (!material.bootstrapConsumed || expected.bootstrapLineageSha256),
    'INIT_LEGACY_ADOPTION_REJECTED',
    'legacy bootstrap 消费状态缺少 append-only lineage 证明',
  );
  const recordedAt = expected.recordedAt;
  const legacySourceSha256 = hashObject({
    schema_version: 1,
    goal_id: expected.goalId,
    manifest_sha256: manifest.manifest_sha256,
    source_manifest_sha256: expected.sourceManifestSha256,
    metadata_sha256: metadata.meta_sha256,
    bootstrap_capability_sha256: metadata.bootstrap_capability_sha256,
    bootstrap_consumed: material.bootstrapConsumed,
    bootstrap_lineage_sha256: expected.bootstrapLineageSha256 || null,
    foreman_recovery_capability_sha256: metadata.foreman_recovery_capability_sha256,
  });
  const written = writeInitReceipt(goalDirectory, {
    schema_version: INIT_RECEIPT_SCHEMA_VERSION,
    goal_id: expected.goalId,
    manifest_sha256: manifest.manifest_sha256,
    source_manifest_sha256: expected.sourceManifestSha256,
    repository_root: metadata.repository_root,
    initialized_at: metadata.initialized_at,
    bootstrap_capability_file: material.bootstrapFile,
    bootstrap_capability_sha256: metadata.bootstrap_capability_sha256,
    foreman_recovery_capability_file: material.foremanRecoveryFile,
    foreman_recovery_capability_sha256: metadata.foreman_recovery_capability_sha256,
    publication_kind: 'LOCKED_LEGACY_ADOPTION',
    publication_recorded_at: recordedAt,
    legacy_source_sha256: legacySourceSha256,
  });
  fsyncDirectory(goalDirectory);
  finalizeLegacyInitReceiptMetadata(goalDirectory, {
    receiptSha256: written.receipt.receipt_sha256,
    recordedAt,
    legacySourceSha256,
  });
  return legacySourceSha256;
}

function finalizeLegacyInitReceiptMetadata(goalDirectory, receipt) {
  const metadataFile = path.join(goalDirectory, 'goal.json');
  const metadata = readJson(metadataFile, 'Goal metadata');
  if (metadata.init_receipt_schema_version !== undefined) {
    assertControl(
      metadata.init_receipt_schema_version === INIT_RECEIPT_SCHEMA_VERSION
        && metadata.init_receipt_sha256 === receipt.receiptSha256
        && metadata.init_receipt_adopted_at === receipt.recordedAt
        && metadata.init_receipt_legacy_source_sha256 === receipt.legacySourceSha256,
      'INIT_RECEIPT_TAMPERED',
      'legacy init receipt metadata marker 与 receipt 不一致',
    );
    return;
  }
  const unsigned = { ...metadata };
  delete unsigned.meta_sha256;
  unsigned.init_receipt_schema_version = INIT_RECEIPT_SCHEMA_VERSION;
  unsigned.init_receipt_sha256 = receipt.receiptSha256;
  unsigned.init_receipt_adopted_at = receipt.recordedAt;
  unsigned.init_receipt_legacy_source_sha256 = receipt.legacySourceSha256;
  atomicWriteJson(metadataFile, {
    ...unsigned,
    meta_sha256: hashObject(unsigned),
  });
}

function readAndVerifyInitReceipt(goalDirectory, expected) {
  ensurePrivateDirectory(goalDirectory);
  const capabilitiesDirectory = path.join(goalDirectory, 'capabilities');
  ensurePrivateDirectory(capabilitiesDirectory);
  const receiptFile = path.join(goalDirectory, INIT_RECEIPT_FILE);
  assertControl(
    fs.existsSync(receiptFile),
    'INIT_RECEIPT_MISSING',
    `Goal ${expected.goalId} 缺少随目录原子发布的 init receipt`,
  );
  assertPrivateFile(receiptFile, 'init receipt');

  let receipt;
  try {
    receipt = readJson(receiptFile, 'init receipt');
  } catch (error) {
    throw new ControlError('INIT_RECEIPT_TAMPERED', `init receipt 无法解析: ${error.message}`);
  }
  const expectedReceiptKeys = expected.goalInputHead
    ? INIT_RECEIPT_KEYS
    : INIT_RECEIPT_KEYS.filter(
      (key) => !['goal_input_head', 'goal_input_source'].includes(key),
    );
  assertControl(
    receipt
      && typeof receipt === 'object'
      && !Array.isArray(receipt)
      && Object.keys(receipt).length === expectedReceiptKeys.length
      && Object.keys(receipt).every((key) => expectedReceiptKeys.includes(key)),
    'INIT_RECEIPT_TAMPERED',
    'init receipt 字段非法',
  );
  const unsigned = { ...receipt };
  delete unsigned.receipt_sha256;
  assertControl(
    typeof receipt.receipt_sha256 === 'string'
      && hashObject(unsigned) === receipt.receipt_sha256,
    'INIT_RECEIPT_TAMPERED',
    'init receipt seal 不匹配',
  );

  const publishedGoalDirectory = expected.publishedGoalDirectory
    || goalDirectory;
  const expectedBootstrapFile = path.join(
    publishedGoalDirectory,
    'capabilities',
    'bootstrap.cap',
  );
  const expectedForemanRecoveryFile = path.join(
    publishedGoalDirectory,
    'capabilities',
    'foreman-recovery.cap',
  );
  assertControl(
    receipt.source_manifest_sha256 === expected.sourceManifestSha256,
    'INIT_REQUEST_MISMATCH',
    '当前 committed manifest bytes 与 init receipt 不一致',
  );
  assertControl(
    receipt.schema_version === INIT_RECEIPT_SCHEMA_VERSION
      && receipt.goal_id === expected.goalId
      && receipt.manifest_sha256 === expected.manifestSha256
      && path.resolve(receipt.repository_root) === path.resolve(expected.repositoryRoot)
      && (
        expected.goalInputHead
          ? receipt.goal_input_head === expected.goalInputHead
            && receipt.goal_input_source === expected.goalInputSource
          : receipt.goal_input_head === undefined
            && receipt.goal_input_source === undefined
      )
      && typeof receipt.initialized_at === 'string'
      && Number.isFinite(Date.parse(receipt.initialized_at))
      && receipt.bootstrap_capability_file === expectedBootstrapFile
      && receipt.foreman_recovery_capability_file === expectedForemanRecoveryFile
      && /^[0-9a-f]{64}$/.test(receipt.bootstrap_capability_sha256)
      && /^[0-9a-f]{64}$/.test(receipt.foreman_recovery_capability_sha256)
      && ['ATOMIC_DIRECTORY_RENAME', 'LOCKED_LEGACY_ADOPTION'].includes(receipt.publication_kind)
      && typeof receipt.publication_recorded_at === 'string'
      && Number.isFinite(Date.parse(receipt.publication_recorded_at))
      && (
        (
          receipt.publication_kind === 'ATOMIC_DIRECTORY_RENAME'
          && receipt.publication_recorded_at === receipt.initialized_at
          && receipt.legacy_source_sha256 === null
        )
        || (
          receipt.publication_kind === 'LOCKED_LEGACY_ADOPTION'
          && /^sha256:[0-9a-f]{64}$/.test(receipt.legacy_source_sha256)
        )
      ),
    'INIT_RECEIPT_TAMPERED',
    'init receipt identity 与 committed Goal 不一致',
  );

  const manifestFile = path.join(goalDirectory, 'manifest.json');
  const metadataFile = path.join(goalDirectory, 'goal.json');
  assertPrivateFile(manifestFile, 'control manifest');
  assertPrivateFile(metadataFile, 'Goal metadata');
  const manifest = readJson(manifestFile, 'control manifest');
  const unsignedManifest = { ...manifest };
  delete unsignedManifest.manifest_sha256;
  assertControl(
    manifest.manifest_sha256 === expected.manifestSha256
      && hashObject(unsignedManifest) === manifest.manifest_sha256,
    'INIT_RECEIPT_TAMPERED',
    'init receipt 对应的 control manifest seal 不匹配',
  );
  const metadata = readJson(metadataFile, 'Goal metadata');
  const unsignedMetadata = { ...metadata };
  delete unsignedMetadata.meta_sha256;
  assertControl(
    hashObject(unsignedMetadata) === metadata.meta_sha256
      && metadata.goal_id === receipt.goal_id
      && metadata.repository_root === receipt.repository_root
      && metadata.goal_input_head === receipt.goal_input_head
      && metadata.goal_input_source === receipt.goal_input_source
      && metadata.initialized_at === receipt.initialized_at
      && metadata.bootstrap_capability_file === receipt.bootstrap_capability_file
      && metadata.bootstrap_capability_sha256 === receipt.bootstrap_capability_sha256
      && metadata.foreman_recovery_capability_file === receipt.foreman_recovery_capability_file
      && metadata.foreman_recovery_capability_sha256 === receipt.foreman_recovery_capability_sha256,
    'INIT_RECEIPT_TAMPERED',
    'init receipt 与 sealed Goal metadata 不一致',
  );
  if (metadata.init_receipt_schema_version === undefined) {
    assertControl(
      receipt.publication_kind === 'LOCKED_LEGACY_ADOPTION',
      'INIT_RECEIPT_TAMPERED',
      'atomic init metadata 缺少 receipt-required marker',
    );
  } else {
    assertControl(
      metadata.init_receipt_schema_version === INIT_RECEIPT_SCHEMA_VERSION
        && metadata.init_receipt_sha256 === receipt.receipt_sha256
        && (
          (
            receipt.publication_kind === 'ATOMIC_DIRECTORY_RENAME'
            && metadata.init_receipt_adopted_at === undefined
            && metadata.init_receipt_legacy_source_sha256 === undefined
          )
          || (
            receipt.publication_kind === 'LOCKED_LEGACY_ADOPTION'
            && metadata.init_receipt_adopted_at === receipt.publication_recorded_at
            && metadata.init_receipt_legacy_source_sha256 === receipt.legacy_source_sha256
          )
        ),
      'INIT_RECEIPT_TAMPERED',
      'init receipt-required metadata marker 与 receipt 不一致',
    );
  }

  const material = capabilityMaterial(
    goalDirectory,
    metadata,
    publishedGoalDirectory,
  );
  assertControl(
    metadata.bootstrap_capability_sha256 === receipt.bootstrap_capability_sha256
      && metadata.foreman_recovery_capability_sha256 === receipt.foreman_recovery_capability_sha256,
    'INIT_CAPABILITY_TAMPERED',
    'init capability identity 与 receipt 不一致',
  );

  return {
    init_receipt_file: receiptFile,
    bootstrap_capability_file: expectedBootstrapFile,
    bootstrap_capability_consumed: material.bootstrapConsumed,
    foreman_recovery_capability_file: expectedForemanRecoveryFile,
    receipt_sha256: receipt.receipt_sha256,
    receipt_publication: receipt.publication_kind,
    receipt_publication_recorded_at: receipt.publication_recorded_at,
    legacy_source_sha256: receipt.legacy_source_sha256,
    ...(receipt.goal_input_head ? { goal_input_head: receipt.goal_input_head } : {}),
    ...(receipt.goal_input_source
      ? { goal_input_source: receipt.goal_input_source }
      : {}),
  };
}

function validatedPostPublishFaultMode(root) {
  const mode = process.env.GOAL_CONTROL_TEST_FAULT_AFTER_INIT_PUBLISH;
  if (mode === undefined || mode === '') return null;
  const temporaryRoot = trustedTemporaryRoot();
  let resolvedRoot;
  try {
    resolvedRoot = fs.realpathSync(root);
  } catch (error) {
    throw new ControlError('TEST_MODE_FORBIDDEN', `init fault root 无法验证: ${error.message}`);
  }
  assertControl(
    process.env.GOAL_CONTROL_TEST_MODE === '1'
      && resolvedRoot !== temporaryRoot
      && resolvedRoot.startsWith(`${temporaryRoot}${path.sep}`),
    'TEST_MODE_FORBIDDEN',
    'init post-publish fault injection 只允许隔离测试目录',
  );
  assertControl(
    mode === 'exit' || mode === 'throw' || mode === '1',
    'INVALID_TEST_FAULT',
    'GOAL_CONTROL_TEST_FAULT_AFTER_INIT_PUBLISH 只能是 exit/throw/1',
  );
  return mode;
}

function maybeInjectPostPublishFault(root) {
  const mode = validatedPostPublishFaultMode(root);
  if (mode === null || mode === 'exit') return;
  throw new ControlError(
    'TEST_FAULT_AFTER_INIT_PUBLISH',
    'injected failure after Goal directory publication',
  );
}

function maybeExitAfterInitCommit(root) {
  if (validatedPostPublishFaultMode(root) === 'exit') process.exit(86);
}

module.exports = {
  INIT_RECEIPT_FILE,
  adoptLegacyInitReceipt,
  ensurePrivateDirectory,
  finalizeLegacyInitReceiptMetadata,
  fsyncDirectory,
  maybeExitAfterInitCommit,
  maybeInjectPostPublishFault,
  readAndVerifyInitReceipt,
  writeInitReceipt,
};
