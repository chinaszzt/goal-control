'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { fileURLToPath, pathToFileURL } = require('url');
const { ControlError, assertControl } = require('./errors');
const {
  EXPECTED_PRODUCER,
  LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
  MECHANICAL_EVIDENCE_KINDS,
  collectLegacySemanticEvidenceSources,
  createLegacyEvidenceMigrationCollector,
  readLegacyEvidenceAnchorIndex,
  sealLegacyEvidenceAnchorIndex,
} = require('./evidence');
const {
  assertControllerControlPathsCommitted,
} = require('./canary-controller-attestation');
const {
  assertFrozenInputs,
  loadGoalStateUnlocked,
} = require('./goal');
const {
  rebuildResourcesReadOnlyUnlocked,
} = require('./resources');
const {
  LEGACY_IDENTITY_INCIDENT_RECEIPT_RELATIVE_PATH,
  assertSourceCheckpointAdvance,
  canonicalRuntimeLaunchFile,
  createLegacyIdentityIncidentCollector,
  readProtocolSealedIdentityIncidentEvidenceSource,
  sealLegacyIdentityIncidentReceipt,
  validateLegacyIdentityIncidentReceipt,
  validateProtocolSealedLegacyIdentityIncidentReceipts,
} = require('./launch-source-checkpoint');
const {
  acceptedEventFiles,
  adoptRootProtocol,
  controllerDecoderFingerprintAt,
  readRootProtocolSealForRotation,
  rotateRootProtocol,
} = require('./store');
const {
  assertIsolatedTestMode,
  canonicalJson,
  controlRoot,
  git,
  hashFile,
  hashObject,
  normalizeHash,
  readJson,
  repoRoot,
  safeId,
  sha256,
} = require('./util');
const { validateLaunchManifest } = require('./validation');

const OLD_CONTROLLER_DRAIN_ACK = 'ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED';
const PREDECESSOR_STRICT_PROBE_TIMEOUT_MILLISECONDS = 60 * 1000;
const PREDECESSOR_REPLAY_TIMEOUT_MILLISECONDS = 5 * 60 * 1000;
const PREDECESSOR_PREFLIGHT_OVERLAY_MAX_RECORDS = 256;
const HISTORICAL_PREFLIGHT_OVERWRITE_FIELDS = Object.freeze([
  'created_at',
  'repository.full_head',
  'execution.target.pid',
  'execution.target.started_at',
  'execution.target.build_head',
]);
const EVIDENCE_STATUSES = new Set(['PASS', 'FAIL', 'BLOCKED', 'STALE']);
const EVIDENCE_REGISTRY_KEYS = new Set([
  'schema_version',
  'evidence_id',
  'goal_id',
  'task_id',
  'kind',
  'stage',
  'status',
  'producer',
  'state_revision',
  'packet',
  'packet_sha256',
  'base_head',
  'full_head',
  'launch_id',
  'created_at',
  'uri',
  'source_sha256',
  'command',
  'checks',
  'attestation',
  'launch_sha256',
  'launch_uri',
  'runtime_launch_sha256',
  'runtime_launch_uri',
  'pull_request',
  'resource_lease',
  'ingress_sha256',
  'acceptance_anchor',
  'registry_sha256',
]);

function assertPlainDirectory(file, label) {
  const stat = fs.lstatSync(file);
  assertControl(
    stat.isDirectory() && !stat.isSymbolicLink(),
    'CORRUPT_STORE',
    `${label} 必须是非 symlink 目录`,
  );
}

function assertNoSymlinks(root, label) {
  if (!fs.existsSync(root)) return;
  const visit = (directory) => {
    assertPlainDirectory(directory, label);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      const stat = fs.lstatSync(file);
      assertControl(
        !stat.isSymbolicLink(),
        'CORRUPT_STORE',
        `${label} 禁止 symlink: ${path.relative(root, file)}`,
      );
      assertControl(
        stat.isDirectory() || stat.isFile(),
        'CORRUPT_STORE',
        `${label} 只允许普通文件/目录: ${path.relative(root, file)}`,
      );
      if (stat.isDirectory()) visit(file);
    }
  };
  visit(root);
}

function isRejectionOnlyGoalDirectory(directory) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  if (
    entries.length !== 1
    || entries[0].name !== 'rejections'
    || !entries[0].isDirectory()
    || entries[0].isSymbolicLink()
  ) {
    return false;
  }
  const rejections = path.join(directory, 'rejections');
  for (const taskEntry of fs.readdirSync(rejections, { withFileTypes: true })) {
    assertControl(
      taskEntry.isDirectory() && !taskEntry.isSymbolicLink(),
      'CORRUPT_STORE',
      `rejection-only store ${path.basename(directory)} 只允许 task 目录`,
    );
    const taskDir = path.join(rejections, taskEntry.name);
    for (const rejection of fs.readdirSync(taskDir, { withFileTypes: true })) {
      assertControl(
        rejection.isFile()
          && !rejection.isSymbolicLink()
          && rejection.name.endsWith('.json'),
        'CORRUPT_STORE',
        `rejection-only store ${path.basename(directory)} 只允许 .json rejection 文件`,
      );
      readJson(
        path.join(taskDir, rejection.name),
        `rejection ${path.basename(directory)}/${taskEntry.name}/${rejection.name}`,
      );
    }
  }
  return true;
}

function goalIds(root, rejectionOnlyRoots = []) {
  const goalsDir = path.join(root, 'goals');
  if (!fs.existsSync(goalsDir)) return [];
  assertPlainDirectory(goalsDir, 'control goals');
  return fs.readdirSync(goalsDir, { withFileTypes: true })
    .flatMap((entry) => {
      assertControl(
        entry.isDirectory() && !entry.isSymbolicLink(),
        'CORRUPT_STORE',
        `goals/${entry.name} 必须是非 symlink 目录`,
      );
      const directory = path.join(goalsDir, entry.name);
      const hasManifest = fs.existsSync(path.join(directory, 'manifest.json'));
      if (!hasManifest && isRejectionOnlyGoalDirectory(directory)) {
        rejectionOnlyRoots.push(entry.name);
        return [];
      }
      safeId(entry.name, 'goal_id');
      return [entry.name];
    })
    .sort();
}

function readEvidenceArtifact(record, field, hashField, label, options = {}) {
  assertControl(
    typeof record[field] === 'string' && record[field].length > 0,
    'CORRUPT_STORE',
    `${label} 缺 ${field}`,
  );
  let uri;
  try {
    uri = new URL(record[field]);
  } catch {
    throw new ControlError('CORRUPT_STORE', `${label} ${field} 不是绝对 URL`);
  }
  assertControl(
    uri.protocol === 'file:',
    'CORRUPT_STORE',
    `${label} ${field} 必须是可离线重放的 file URI`,
  );
  const file = fileURLToPath(uri);
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (options.allowMissing === true && error.code === 'ENOENT') return false;
    throw new ControlError('CORRUPT_STORE', `${label} artifact 不存在: ${error.message}`);
  }
  assertControl(
    stat.isFile() && !stat.isSymbolicLink(),
    'CORRUPT_STORE',
    `${label} artifact 必须是非 symlink 普通文件`,
  );
  assertControl(
    hashFile(file) === normalizeHash(record[hashField], `${label}.${hashField}`),
    'CORRUPT_STORE',
    `${label} artifact hash 不匹配`,
  );
  return true;
}

function stableRegularFileSnapshot(file, label) {
  let before;
  let body;
  let after;
  try {
    before = fs.lstatSync(file);
    body = fs.readFileSync(file);
    after = fs.lstatSync(file);
  } catch (error) {
    throw new ControlError(
      'CORRUPT_STORE',
      `${label} 无法稳定读取: ${error.message}`,
    );
  }
  assertControl(
    before.isFile()
      && !before.isSymbolicLink()
      && after.isFile()
      && !after.isSymbolicLink()
      && String(before.dev) === String(after.dev)
      && String(before.ino) === String(after.ino)
      && before.size === after.size
      && before.mtimeMs === after.mtimeMs
      && before.ctimeMs === after.ctimeMs,
    'CORRUPT_STORE',
    `${label} 必须是读取期间 identity/bytes 不变的非 symlink 普通文件`,
  );
  return {
    body,
    file_sha256: `sha256:${sha256(body)}`,
    dev: String(before.dev),
    ino: String(before.ino),
    size: before.size,
    mtime_ms: before.mtimeMs,
    ctime_ms: before.ctimeMs,
  };
}

function parseJsonArtifact(snapshot, label) {
  try {
    const value = JSON.parse(snapshot.body.toString('utf8'));
    assertControl(
      value && typeof value === 'object' && !Array.isArray(value),
      'CORRUPT_STORE',
      `${label} 必须是 JSON object`,
    );
    return value;
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'CORRUPT_STORE',
      `${label} 不是合法 JSON: ${error.message}`,
    );
  }
}

function acceptedEventReferencesPreflight(event, evidenceId) {
  if (!event || !event.payload) return false;
  if (event.type === 'DEV_READY') {
    return event.payload.evidence
      && event.payload.evidence.preflight === evidenceId;
  }
  if (event.type === 'RESOLVE_HOLD') {
    return event.payload.runtime_preflight_evidence_id === evidenceId;
  }
  if (event.type === 'RECOVERY_PROMOTED') {
    return event.payload.preflight_evidence_id === evidenceId;
  }
  return false;
}

function acceptedGoalEventReferencesEvidence(root, loaded, evidenceId) {
  return loaded.manifest.tasks.some((task) => {
    const index = loaded.eventIndexes[task.id];
    return acceptedEventFiles(
      root,
      loaded.manifest.goal_id,
      task.id,
    ).some((file) => {
      const event = readJson(
        file,
        `accepted event evidence reference ${task.id}`,
      );
      return index
        && index.get(event.event_id) === event.input_sha256
        && acceptedEventReferencesPreflight(event, evidenceId);
    });
  });
}

function assertPreflightLaunchIdentity(record, launch, label, options = {}) {
  assertControl(
    launch
      && typeof launch === 'object'
      && !Array.isArray(launch)
      && launch.goal_id === record.goal_id
      && launch.task_id === record.task_id
      && launch.launch_id === record.launch_id
      && launch.role === record.producer.role
      && launch.thread
      && launch.thread.id === record.producer.thread_id
      && (launch.thread.host_id || 'local')
        === (record.producer.host_id || 'local')
      && record.packet
      && launch.packet
      && launch.packet.revision === record.packet.revision
      && normalizeHash(
        launch.packet.sha256,
        `${label} packet sha256`,
      ) === normalizeHash(
        record.packet.sha256,
        `${label} registry packet sha256`,
      )
      && launch.repository
      && launch.repository.base_head === record.base_head
      && typeof launch.repository.full_head === 'string'
      && /^[0-9a-f]{40}$/.test(launch.repository.full_head)
      && (
        options.allowFullHeadDrift === true
          || launch.repository.full_head === record.full_head
      ),
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REJECTED',
    `${label} 与 sealed PREFLIGHT registry identity 不匹配`,
  );
}

function historicalLaunchOverwriteProjection(launch) {
  const projected = JSON.parse(JSON.stringify(launch));
  delete projected.created_at;
  if (
    projected.repository
      && typeof projected.repository === 'object'
      && !Array.isArray(projected.repository)
  ) {
    delete projected.repository.full_head;
  }
  if (
    projected.execution
      && typeof projected.execution === 'object'
      && !Array.isArray(projected.execution)
      && projected.execution.target
      && typeof projected.execution.target === 'object'
      && !Array.isArray(projected.execution.target)
  ) {
    delete projected.execution.target.pid;
    delete projected.execution.target.started_at;
    delete projected.execution.target.build_head;
  }
  return projected;
}

function nestedValue(value, dottedPath) {
  return dottedPath.split('.').reduce(
    (current, key) => (
      current && typeof current === 'object'
        ? current[key]
        : undefined
    ),
    value,
  );
}

function assertHistoricalOverwriteFieldTypes(launch, label) {
  assertControl(
    typeof launch.created_at === 'string'
      && Number.isFinite(Date.parse(launch.created_at))
      && launch.repository
      && typeof launch.repository.full_head === 'string'
      && /^[0-9a-f]{40}$/.test(launch.repository.full_head),
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REJECTED',
    `${label} historical overwrite timestamp/full HEAD 非法`,
  );
  const target = launch.execution && launch.execution.target;
  if (target === undefined) return;
  assertControl(
    target
      && typeof target === 'object'
      && !Array.isArray(target)
      && (
        target.pid === undefined
          || (Number.isSafeInteger(target.pid) && target.pid > 0)
      )
      && (
        target.started_at === undefined
          || (
            typeof target.started_at === 'string'
              && Number.isFinite(Date.parse(target.started_at))
          )
      )
      && (
        target.build_head === undefined
          || (
            typeof target.build_head === 'string'
              && /^[0-9a-f]{40}$/.test(target.build_head)
          )
      ),
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REJECTED',
    `${label} historical execution target overwrite 字段非法`,
  );
}

function assertHistoricalLaunchOverwriteEquivalent(
  immutableLaunch,
  canonicalLaunch,
  evidenceId,
) {
  assertHistoricalOverwriteFieldTypes(
    immutableLaunch,
    `historical PREFLIGHT ${evidenceId} immutable launch`,
  );
  assertHistoricalOverwriteFieldTypes(
    canonicalLaunch,
    `historical PREFLIGHT ${evidenceId} overwritten canonical launch`,
  );
  const immutableProjection =
    historicalLaunchOverwriteProjection(immutableLaunch);
  const canonicalProjection =
    historicalLaunchOverwriteProjection(canonicalLaunch);
  assertControl(
    canonicalJson(immutableProjection)
      === canonicalJson(canonicalProjection),
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REJECTED',
    `historical PREFLIGHT ${evidenceId} canonical/immutable launch 除 allowlist overwrite 字段外不等价`,
  );
  const observedFields = HISTORICAL_PREFLIGHT_OVERWRITE_FIELDS.filter(
    (field) => (
      canonicalJson({ value: nestedValue(immutableLaunch, field) })
        !== canonicalJson({ value: nestedValue(canonicalLaunch, field) })
    ),
  );
  assertControl(
    observedFields.length > 0,
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REJECTED',
    `historical PREFLIGHT ${evidenceId} 没有 allowlist historical overwrite`,
  );
  return {
    observed_fields: observedFields,
    stable_structure_sha256: hashObject(immutableProjection),
  };
}

function preflightCompatibilityOverlayCandidate(
  root,
  loaded,
  record,
  registryFile,
  canonicalSnapshot,
  options = {},
) {
  safeId(record.launch_id, 'historical PREFLIGHT launch_id');
  const expectedCanonical = path.join(
    root,
    'goals',
    record.goal_id,
    'launches',
    record.task_id,
    `${record.launch_id}.json`,
  );
  const expectedImmutable = path.join(
    root,
    'goals',
    record.goal_id,
    'evidence-artifacts',
    record.task_id,
    `${record.evidence_id}-launch.json`,
  );
  const expectedRegistryUri = pathToFileURL(registryFile).href;
  const expectedCanonicalUri = pathToFileURL(expectedCanonical).href;
  assertControl(
    record.uri === expectedRegistryUri
      && record.launch_uri === expectedCanonicalUri,
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REJECTED',
    `historical PREFLIGHT ${record.evidence_id} 不是 exact canonical registry/launch URI`,
  );
  assertControl(
    canonicalSnapshot.file_sha256
      !== normalizeHash(record.launch_sha256, 'launch_sha256'),
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REJECTED',
    `historical PREFLIGHT ${record.evidence_id} canonical launch 未发生 bytes 覆写`,
  );
  const acceptedEventReplay = acceptedGoalEventReferencesEvidence(
    root,
    loaded,
    record.evidence_id,
  );
  assertControl(
    !acceptedEventReplay
      || typeof options.predecessorProtocolSealSha256 === 'string',
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REFERENCED',
    `historical PREFLIGHT ${record.evidence_id} 已被 accepted event 引用，且缺 sealed predecessor compatibility context`,
  );

  const immutableSnapshot = stableRegularFileSnapshot(
    expectedImmutable,
    `historical PREFLIGHT ${record.evidence_id} immutable launch`,
  );
  assertControl(
    immutableSnapshot.file_sha256
      === normalizeHash(record.launch_sha256, 'launch_sha256'),
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REJECTED',
    `historical PREFLIGHT ${record.evidence_id} immutable launch 与 sealed launch_sha256 不匹配`,
  );
  const canonicalLaunch = parseJsonArtifact(
    canonicalSnapshot,
    `historical PREFLIGHT ${record.evidence_id} overwritten canonical launch`,
  );
  const immutableLaunch = parseJsonArtifact(
    immutableSnapshot,
    `historical PREFLIGHT ${record.evidence_id} immutable launch`,
  );
  assertPreflightLaunchIdentity(
    record,
    canonicalLaunch,
    `historical PREFLIGHT ${record.evidence_id} overwritten canonical launch`,
    { allowFullHeadDrift: true },
  );
  assertPreflightLaunchIdentity(
    record,
    immutableLaunch,
    `historical PREFLIGHT ${record.evidence_id} immutable launch`,
  );
  const overwriteEquivalence =
    assertHistoricalLaunchOverwriteEquivalent(
      immutableLaunch,
      canonicalLaunch,
      record.evidence_id,
    );

  const overlaidUnsigned = acceptedEventReplay
    ? { ...record }
    : {
      ...record,
      launch_uri: pathToFileURL(expectedImmutable).href,
    };
  delete overlaidUnsigned.registry_sha256;
  const overlaidRecord = {
    ...overlaidUnsigned,
    registry_sha256: hashObject(overlaidUnsigned),
  };
  const registrySnapshot = stableRegularFileSnapshot(
    registryFile,
    `historical PREFLIGHT ${record.evidence_id} registry`,
  );
  const registryRelativePath = path.relative(root, registryFile)
    .split(path.sep).join('/');
  const canonicalRelativePath = path.relative(root, expectedCanonical)
    .split(path.sep).join('/');
  const immutableRelativePath = path.relative(root, expectedImmutable)
    .split(path.sep).join('/');
  return {
    registry_file: registryFile,
    registry_relative_path: registryRelativePath,
    registry_snapshot: registrySnapshot,
    source_registry_file_sha256: registrySnapshot.file_sha256,
    source_registry_sha256:
      normalizeHash(record.registry_sha256, 'registry_sha256'),
    canonical_launch_file: expectedCanonical,
    canonical_launch_snapshot: canonicalSnapshot,
    canonical_launch_file_sha256: canonicalSnapshot.file_sha256,
    immutable_launch_file: expectedImmutable,
    immutable_launch_snapshot: immutableSnapshot,
    immutable_launch_file_sha256: immutableSnapshot.file_sha256,
    overlaid_record: overlaidRecord,
    audit: {
      goal_id: record.goal_id,
      task_id: record.task_id,
      evidence_id: record.evidence_id,
      registry_relative_path: registryRelativePath,
      source_registry_file_sha256: registrySnapshot.file_sha256,
      source_registry_sha256:
        normalizeHash(record.registry_sha256, 'registry_sha256'),
      source_launch_uri: record.launch_uri,
      overwritten_canonical_launch_relative_path: canonicalRelativePath,
      overwritten_canonical_launch_sha256:
        canonicalSnapshot.file_sha256,
      sealed_launch_sha256:
        normalizeHash(record.launch_sha256, 'launch_sha256'),
      immutable_launch_relative_path: immutableRelativePath,
      allowed_overwrite_fields:
        HISTORICAL_PREFLIGHT_OVERWRITE_FIELDS,
      observed_overwrite_fields:
        overwriteEquivalence.observed_fields,
      stable_launch_structure_sha256:
        overwriteEquivalence.stable_structure_sha256,
      accepted_event_replay: acceptedEventReplay,
      predecessor_protocol_seal_sha256:
        options.predecessorProtocolSealSha256 || null,
      read_overlay_kind: acceptedEventReplay
        ? 'SEALED_ACCEPTED_REPLAY_NO_OVERLAY'
        : 'REGISTRY_LAUNCH_URI',
      read_overlay_relative_path: acceptedEventReplay
        ? null
        : registryRelativePath,
      overlay_launch_uri: overlaidRecord.launch_uri,
      overlay_registry_sha256: overlaidRecord.registry_sha256,
    },
  };
}

function validatePreflightLaunchArtifact(
  root,
  loaded,
  record,
  registryFile,
  options = {},
) {
  let uri;
  try {
    uri = new URL(record.launch_uri);
  } catch {
    throw new ControlError(
      'CORRUPT_STORE',
      `evidence ${record.evidence_id} launch launch_uri 不是绝对 URL`,
    );
  }
  assertControl(
    uri.protocol === 'file:',
    'CORRUPT_STORE',
    `evidence ${record.evidence_id} launch launch_uri 必须是可离线重放的 file URI`,
  );
  const canonicalFile = fileURLToPath(uri);
  const canonicalSnapshot = stableRegularFileSnapshot(
    canonicalFile,
    `evidence ${record.evidence_id} launch artifact`,
  );
  const hasRuntimeSha = record.runtime_launch_sha256 !== undefined;
  const hasRuntimeUri = record.runtime_launch_uri !== undefined;
  const expectedRuntimeFile = canonicalRuntimeLaunchFile(
    root,
    record.goal_id,
    record.task_id,
    record.launch_id,
  );
  assertControl(
    hasRuntimeSha === hasRuntimeUri,
    'CORRUPT_STORE',
    `evidence ${record.evidence_id} runtime launch binding 必须成对`,
  );
  assertControl(
    record.status !== 'PASS'
      || path.resolve(canonicalFile) === path.resolve(expectedRuntimeFile)
      || hasRuntimeSha,
    'CORRUPT_STORE',
    `evidence ${record.evidence_id} PASS candidate 缺 canonical runtime 双绑定`,
  );
  if (hasRuntimeSha) {
    const expectedCandidateFile = path.join(
      loaded.paths.dir,
      'evidence-artifacts',
      record.task_id,
      `${record.evidence_id}-launch.json`,
    );
    assertControl(
      path.resolve(canonicalFile) === path.resolve(expectedCandidateFile)
        && canonicalSnapshot.file_sha256
          === normalizeHash(record.launch_sha256, 'launch_sha256'),
      'CORRUPT_STORE',
      `evidence ${record.evidence_id} source checkpoint candidate 路径/hash 非法`,
    );
    let runtimeUri;
    try {
      runtimeUri = new URL(record.runtime_launch_uri);
    } catch {
      throw new ControlError(
        'CORRUPT_STORE',
        `evidence ${record.evidence_id} runtime_launch_uri 不是绝对 URL`,
      );
    }
    assertControl(
      runtimeUri.protocol === 'file:'
        && path.resolve(fileURLToPath(runtimeUri))
          === path.resolve(expectedRuntimeFile),
      'CORRUPT_STORE',
      `evidence ${record.evidence_id} runtime launch 路径不是 canonical`,
    );
    const runtimeSnapshot = stableRegularFileSnapshot(
      expectedRuntimeFile,
      `evidence ${record.evidence_id} canonical runtime launch`,
    );
    assertControl(
      runtimeSnapshot.file_sha256
        === normalizeHash(
          record.runtime_launch_sha256,
          'runtime_launch_sha256',
        ),
      'CORRUPT_STORE',
      `evidence ${record.evidence_id} canonical runtime launch hash 不匹配`,
    );
    let runtimeLaunch;
    let candidateLaunch;
    try {
      runtimeLaunch = validateLaunchManifest(
        parseJsonArtifact(
          runtimeSnapshot,
          `evidence ${record.evidence_id} canonical runtime launch`,
        ),
      );
      candidateLaunch = validateLaunchManifest(
        parseJsonArtifact(
          canonicalSnapshot,
          `evidence ${record.evidence_id} source checkpoint candidate`,
        ),
      );
    } catch (error) {
      if (error instanceof ControlError) throw error;
      throw new ControlError(
        'CORRUPT_STORE',
        `evidence ${record.evidence_id} source checkpoint launch 非法: ${error.message}`,
      );
    }
    assertSourceCheckpointAdvance(runtimeLaunch, candidateLaunch, {
      ancestryWorktree: options.repositoryWorktree,
    });
  }
  if (
    canonicalSnapshot.file_sha256
      === normalizeHash(record.launch_sha256, 'launch_sha256')
  ) {
    return;
  }
  assertControl(
    options.predecessorCompatibilityCollector instanceof Map,
    'CORRUPT_STORE',
    `evidence ${record.evidence_id} launch artifact hash 不匹配`,
  );
  const candidate = preflightCompatibilityOverlayCandidate(
    root,
    loaded,
    record,
    registryFile,
    canonicalSnapshot,
    {
      predecessorProtocolSealSha256:
        options.predecessorCompatibilityCollector
          .predecessorProtocolSealSha256,
    },
  );
  const key = `${record.goal_id}/${record.task_id}/${record.evidence_id}`;
  assertControl(
    options.predecessorCompatibilityCollector.size
      < PREDECESSOR_PREFLIGHT_OVERLAY_MAX_RECORDS
      && !options.predecessorCompatibilityCollector.has(key),
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_LIMIT',
    `predecessor PREFLIGHT compatibility overlay 超限或重复: ${key}`,
  );
  options.predecessorCompatibilityCollector.set(key, candidate);
}

function sealPredecessorCompatibilityOverlay(collector) {
  const changes = collector instanceof Map
    ? [...collector.values()].sort((left, right) => (
      left.registry_relative_path.localeCompare(right.registry_relative_path)
    ))
    : [];
  const records = changes.map((change) => change.audit);
  const readOverlayRecordCount = changes.filter(
    (change) => change.audit.accepted_event_replay !== true,
  ).length;
  const unsigned = {
    schema_version: 1,
    kind: 'PREFLIGHT_LAUNCH_URI_COMPATIBILITY_OVERLAY',
    scope: 'PREDECESSOR_SEMANTIC_REPLAY_IN_MEMORY_READ_ONLY',
    live_root_mutated: false,
    predecessor_protocol_seal_sha256:
      collector && collector.predecessorProtocolSealSha256
        ? collector.predecessorProtocolSealSha256
        : null,
    record_count: records.length,
    read_overlay_record_count: readOverlayRecordCount,
    records,
    records_sha256: hashObject(records),
  };
  return {
    changes,
    audit: {
      ...unsigned,
      overlay_sha256: hashObject(unsigned),
    },
  };
}

function validateLegacySemanticSource(root, record, legacyIndex) {
  if (!legacyIndex) return false;
  const key = `${record.goal_id}/${record.task_id}/${record.evidence_id}`;
  const binding = legacyIndex.semantic_sources[key];
  if (binding === undefined) return false;
  const digest = normalizeHash(record.source_sha256, 'source_sha256');
  const expectedPath = `.legacy-evidence-sources.v1/${digest.slice('sha256:'.length)}.artifact`;
  assertControl(
    binding
      && binding.goal_id === record.goal_id
      && binding.task_id === record.task_id
      && binding.evidence_id === record.evidence_id
      && normalizeHash(binding.registry_sha256, 'legacy registry sha256')
        === normalizeHash(record.registry_sha256, 'registry_sha256')
      && normalizeHash(binding.source_sha256, 'legacy source sha256') === digest
      && binding.artifact_path === expectedPath,
    'LEGACY_EVIDENCE_SOURCE_MISMATCH',
    `legacy semantic evidence ${record.evidence_id} 缺 protocol-sealed source binding`,
  );
  const artifact = path.join(root, expectedPath);
  let stat;
  try {
    stat = fs.lstatSync(artifact);
  } catch (error) {
    throw new ControlError(
      'CORRUPT_STORE_PROTOCOL',
      `legacy semantic evidence ${record.evidence_id} sealed source 不存在: ${error.message}`,
    );
  }
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && hashFile(artifact) === digest,
    'CORRUPT_STORE_PROTOCOL',
    `legacy semantic evidence ${record.evidence_id} sealed source hash 不匹配`,
  );
  return true;
}

function validateEvidenceRegistries(root, loaded, options = {}) {
  const evidenceRoot = path.join(loaded.paths.dir, 'evidence');
  if (!fs.existsSync(evidenceRoot)) {
    return { registry_count: 0, registry_set_sha256: hashObject([]) };
  }
  assertPlainDirectory(evidenceRoot, `Goal ${loaded.manifest.goal_id} evidence`);
  const knownTasks = new Set(loaded.manifest.tasks.map((task) => task.id));
  const bindings = [];
  for (const taskEntry of fs.readdirSync(evidenceRoot, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))) {
    assertControl(
      taskEntry.isDirectory() && !taskEntry.isSymbolicLink(),
      'CORRUPT_STORE',
      `evidence/${taskEntry.name} 必须是非 symlink 目录`,
    );
    safeId(taskEntry.name, 'evidence task_id');
    assertControl(
      knownTasks.has(taskEntry.name),
      'CORRUPT_STORE',
      `evidence 引用了 manifest 外 task: ${taskEntry.name}`,
    );
    const taskDir = path.join(evidenceRoot, taskEntry.name);
    for (const entry of fs.readdirSync(taskDir, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))) {
      assertControl(
        entry.isFile() && !entry.isSymbolicLink() && entry.name.endsWith('.json'),
        'CORRUPT_STORE',
        `evidence registry 必须是 .json 普通文件: ${taskEntry.name}/${entry.name}`,
      );
      const file = path.join(taskDir, entry.name);
      const record = readJson(file, `evidence registry ${entry.name}`);
      assertControl(
        record
          && typeof record === 'object'
          && !Array.isArray(record)
          && Object.keys(record).every((key) => EVIDENCE_REGISTRY_KEYS.has(key)),
        'CORRUPT_STORE',
        `evidence registry ${entry.name} 含当前 decoder 未知字段`,
      );
      assertControl(
        record.schema_version === 1
          && record.goal_id === loaded.manifest.goal_id
          && record.task_id === taskEntry.name,
        'CORRUPT_STORE',
        `evidence registry ${entry.name} 身份非法`,
      );
      safeId(record.evidence_id, 'evidence_id');
      assertControl(
        entry.name === `${record.evidence_id}.json`,
        'CORRUPT_STORE',
        `evidence registry 文件名与 evidence_id 不一致: ${entry.name}`,
      );
      const unsigned = { ...record };
      delete unsigned.registry_sha256;
      assertControl(
        typeof record.registry_sha256 === 'string'
          && hashObject(unsigned) === normalizeHash(record.registry_sha256, 'registry_sha256'),
        'CORRUPT_STORE',
        `evidence registry ${record.evidence_id} seal 不匹配`,
      );
      assertControl(
        Object.prototype.hasOwnProperty.call(EXPECTED_PRODUCER, record.kind),
        'CORRUPT_STORE',
        `evidence registry ${record.evidence_id} kind 未知: ${record.kind}`,
      );
      assertControl(
        EVIDENCE_STATUSES.has(record.status)
          && record.producer
          && EXPECTED_PRODUCER[record.kind].includes(record.producer.role),
        'CORRUPT_STORE',
        `evidence registry ${record.evidence_id} status/producer 非法`,
      );
      if (record.kind === 'PREFLIGHT') {
        validatePreflightLaunchArtifact(
          root,
          loaded,
          record,
          file,
          options,
        );
      } else {
        assertControl(
          record.runtime_launch_sha256 === undefined
            && record.runtime_launch_uri === undefined,
          'CORRUPT_STORE',
          `evidence ${record.evidence_id} 非 PREFLIGHT 禁止 runtime launch binding`,
        );
        const sourcePresent = readEvidenceArtifact(
          record,
          'uri',
          'source_sha256',
          `evidence ${record.evidence_id}`,
          {
            allowMissing:
              !MECHANICAL_EVIDENCE_KINDS.has(record.kind)
              && Boolean(
                options.legacyIndex
                  || options.allowProtocolSealedIdentityIncidentSources,
              ),
          },
        );
        if (!sourcePresent) {
          let identitySourcePresent = false;
          if (
            options.allowProtocolSealedIdentityIncidentSources === true
              && record.kind === 'HOLD_ASSERTION'
              && record.stage === 'PREFLIGHT'
              && record.status === 'BLOCKED'
          ) {
            identitySourcePresent = (
              readProtocolSealedIdentityIncidentEvidenceSource(
                root,
                record,
                { allowNoBinding: true },
              ) !== null
            );
          }
          const legacySourcePresent = options.legacyIndex
            ? validateLegacySemanticSource(
              root,
              record,
              options.legacyIndex,
            )
            : false;
          assertControl(
            identitySourcePresent || legacySourcePresent,
            'CORRUPT_STORE',
            `evidence ${record.evidence_id} source 缺 protocol-sealed binding`,
          );
        }
      }
      bindings.push([
        taskEntry.name,
        record.evidence_id,
        normalizeHash(record.registry_sha256, 'registry_sha256'),
      ]);
    }
  }
  return {
    registry_count: bindings.length,
    registry_set_sha256: hashObject(bindings),
  };
}

function assertSuccessorCompatibleActiveDevLaunches(root, loaded) {
  for (const task of loaded.manifest.tasks) {
    const state = loaded.snapshot.tasks[task.id];
    const session = state && state.sessions && state.sessions.DEV;
    if (
      !session
        || !['active', 'idle'].includes(session.status)
        || !session.launch_id
    ) {
      continue;
    }
    const launchFile = canonicalRuntimeLaunchFile(
      root,
      loaded.manifest.goal_id,
      task.id,
      session.launch_id,
    );
    if (!fs.existsSync(launchFile)) continue;
    const snapshot = stableRegularFileSnapshot(
      launchFile,
      `active DEV canonical launch ${session.launch_id}`,
    );
    const launch = parseJsonArtifact(
      snapshot,
      `active DEV canonical launch ${session.launch_id}`,
    );
    assertControl(
      launch
        && launch.goal_id === loaded.manifest.goal_id
        && launch.task_id === task.id
        && launch.launch_id === session.launch_id
        && launch.role === 'DEV'
        && launch.thread
        && launch.thread.id === session.thread_id
        && (launch.thread.host_id || 'local')
          === (session.host_id || 'local'),
      'CORRUPT_STORE',
      `active DEV canonical launch ${session.launch_id} 与当前 session identity 不匹配`,
    );
    assertControl(
      launch.pull_request === null
        || launch.pull_request === undefined,
      'STORE_MIGRATION_ACTIVE_DEV_PR_LAUNCH_UNSUPPORTED',
      `Goal ${loaded.manifest.goal_id} task ${task.id} 的 active DEV canonical launch ${session.launch_id} 不是 successor-compatible PR-free launch（只允许 pull_request:null 或 legacy omitted）；`
        + '继续 adoption/rotation 会令 DEV preflight/source-checkpoint 永久不可执行。'
        + '请保持 predecessor seal，先用 predecessor decoder 将该 DEV session/task 正常推进到 terminal，'
        + '或走可审计 recovery/repair 生成 pull_request:null 的 fresh DEV launch 并终结旧 session；'
        + '禁止直接删除/覆盖 canonical launch 或 append-only ledger，修复后再重试 protocol adoption/rotation',
    );
  }
}

function taskSummary(loaded, task) {
  const state = loaded.snapshot.tasks[task.id];
  return {
    task_id: task.id,
    phase: state.phase,
    state_revision: state.state_revision,
    event_count: loaded.eventIndexes[task.id].size,
    event_head_sha256: loaded.lastEventHashes[task.id] || null,
    packet_revision: state.packet.revision,
    packet_sha256: state.packet.sha256,
    full_head: state.full_head,
  };
}

function validateRepositoryWorktree(cwd) {
  const worktree = fs.realpathSync(repoRoot(cwd));
  assertControl(
    git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '',
    'FROZEN_WORKTREE_DIRTY',
    'protocol adoption 只接受 clean frozen repository worktree',
  );
  return {
    repository_worktree: worktree,
    repository_common_dir: fs.realpathSync(
      git(worktree, ['rev-parse', '--path-format=absolute', '--git-common-dir']),
    ),
    repository_head: git(worktree, ['rev-parse', 'HEAD']),
  };
}

function validateMappedRepositoryWorktree(requested, expectedCommonDir) {
  assertControl(
    typeof requested === 'string' && path.isAbsolute(requested),
    'STORE_MIGRATION_WORKTREE_MAP_INVALID',
    'goal worktree mapping 必须使用绝对路径',
  );
  const normalized = path.resolve(requested);
  let requestedStat;
  let worktree;
  try {
    requestedStat = fs.lstatSync(normalized);
    worktree = fs.realpathSync(normalized);
  } catch (error) {
    throw new ControlError(
      'STORE_MIGRATION_WORKTREE_MAP_INVALID',
      `goal worktree mapping 路径无法读取: ${requested}: ${error.message}`,
    );
  }
  assertControl(
    requestedStat.isDirectory() && !requestedStat.isSymbolicLink(),
    'STORE_MIGRATION_WORKTREE_SYMLINK',
    `goal worktree mapping 禁止 symlink/非目录: ${requested}`,
  );
  assertControl(
    normalized === worktree,
    'STORE_MIGRATION_WORKTREE_SYMLINK',
    `goal worktree mapping 必须是 canonical realpath: ${requested}`,
  );
  const repositoryRoot = fs.realpathSync(repoRoot(worktree));
  assertControl(
    repositoryRoot === worktree,
    'STORE_MIGRATION_WORKTREE_MAP_INVALID',
    `goal worktree mapping 必须指向 Git worktree 根目录: ${requested}`,
  );
  const identity = validateRepositoryWorktree(worktree);
  assertControl(
    identity.repository_common_dir === expectedCommonDir,
    'STORE_MIGRATION_WORKTREE_REPOSITORY_MISMATCH',
    `goal worktree ${worktree} 不属于 control root 的同一 Git common dir`,
  );
  return identity;
}

function readGoalWorktreeMapFile(file) {
  assertControl(
    typeof file === 'string' && path.isAbsolute(file),
    'STORE_MIGRATION_WORKTREE_MAP_INVALID',
    '--goal-worktrees-file 必须是绝对路径',
  );
  const normalized = path.resolve(file);
  let before;
  let body;
  let canonicalFile;
  try {
    before = fs.lstatSync(normalized);
    canonicalFile = fs.realpathSync(normalized);
    body = fs.readFileSync(normalized);
  } catch (error) {
    throw new ControlError(
      'STORE_MIGRATION_WORKTREE_MAP_INVALID',
      `goal worktree map 无法读取: ${error.message}`,
    );
  }
  assertControl(
    before.isFile()
      && !before.isSymbolicLink()
      && canonicalFile === normalized,
    'STORE_MIGRATION_WORKTREE_SYMLINK',
    'goal worktree map 必须是 canonical、非 symlink 普通文件',
  );
  const after = fs.lstatSync(normalized);
  assertControl(
    String(before.dev) === String(after.dev)
      && String(before.ino) === String(after.ino)
      && before.size === after.size,
    'STORE_MIGRATION_WORKTREE_MAP_CHANGED',
    'goal worktree map 在读取期间被替换',
  );
  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'STORE_MIGRATION_WORKTREE_MAP_INVALID',
      `goal worktree map 不是合法 JSON: ${error.message}`,
    );
  }
  assertControl(
    parsed
      && typeof parsed === 'object'
      && !Array.isArray(parsed)
      && Object.keys(parsed).length === 2
      && Object.keys(parsed).every((key) => (
        ['schema_version', 'goal_worktrees'].includes(key)
      ))
      && parsed.schema_version === 1
      && Array.isArray(parsed.goal_worktrees),
    'STORE_MIGRATION_WORKTREE_MAP_INVALID',
    'goal worktree map 必须是 {schema_version:1,goal_worktrees:[...]}',
  );
  const entries = [];
  const seen = new Set();
  for (const entry of parsed.goal_worktrees) {
    assertControl(
      entry
        && typeof entry === 'object'
        && !Array.isArray(entry)
        && Object.keys(entry).length === 2
        && Object.keys(entry).every((key) => (
          ['goal_id', 'repository_worktree'].includes(key)
        ))
        && typeof entry.goal_id === 'string'
        && typeof entry.repository_worktree === 'string'
        && !seen.has(entry.goal_id),
      'STORE_MIGRATION_WORKTREE_MAP_INVALID',
      'goal worktree map entry 字段非法或 goal_id 重复',
    );
    safeId(entry.goal_id, 'goal worktree map goal_id');
    seen.add(entry.goal_id);
    entries.push({
      goal_id: entry.goal_id,
      repository_worktree: entry.repository_worktree,
    });
  }
  const sorted = [...entries].sort((left, right) => left.goal_id.localeCompare(right.goal_id));
  assertControl(
    canonicalJson(entries) === canonicalJson(sorted),
    'STORE_MIGRATION_WORKTREE_MAP_INVALID',
    'goal worktree map 必须按 goal_id 排序',
  );
  return {
    file: canonicalFile,
    file_sha256: `sha256:${sha256(body)}`,
    file_dev: String(before.dev),
    file_ino: String(before.ino),
    entries,
  };
}

function assertGoalWorktreeMapFileUnchanged(snapshot) {
  if (!snapshot) return;
  let stat;
  let body;
  try {
    stat = fs.lstatSync(snapshot.file);
    body = fs.readFileSync(snapshot.file);
  } catch (error) {
    throw new ControlError(
      'STORE_MIGRATION_WORKTREE_MAP_CHANGED',
      `goal worktree map 在 replay 期间消失: ${error.message}`,
    );
  }
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && String(stat.dev) === snapshot.file_dev
      && String(stat.ino) === snapshot.file_ino
      && `sha256:${sha256(body)}` === snapshot.file_sha256,
    'STORE_MIGRATION_WORKTREE_MAP_CHANGED',
    'goal worktree map 在 replay 期间发生 bytes/identity 漂移',
  );
}

function selectGoalWorktrees(cwd, ids, mapFile) {
  const defaultRepository = validateRepositoryWorktree(cwd);
  const snapshot = mapFile ? readGoalWorktreeMapFile(mapFile) : null;
  const entries = snapshot
    ? snapshot.entries
    : ids.map((goalId) => ({
      goal_id: goalId,
      repository_worktree: defaultRepository.repository_worktree,
    }));
  assertControl(
    canonicalJson(entries.map((entry) => entry.goal_id)) === canonicalJson(ids),
    'STORE_MIGRATION_WORKTREE_MAP_INCOMPLETE',
    'goal worktree map 必须精确覆盖 control root 中全部非 rejection-only Goal，且不得有额外项',
  );
  const byGoal = new Map();
  for (const entry of entries) {
    const repository = snapshot
      ? validateMappedRepositoryWorktree(
        entry.repository_worktree,
        defaultRepository.repository_common_dir,
      )
      : defaultRepository;
    byGoal.set(entry.goal_id, repository);
  }
  return {
    defaultRepository,
    snapshot,
    byGoal,
    mode: snapshot ? 'EXPLICIT_MAP' : 'SINGLE_DEFAULT',
  };
}

function frozenInputBinding(loaded, repository) {
  const frozenInputs = [
    ...Object.entries(loaded.manifest.protocol || {})
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, value]) => ({
        kind: 'PROTOCOL',
        name,
        path: value.path,
        sha256: normalizeHash(value.sha256, `${name} protocol sha256`),
      })),
    ...loaded.manifest.tasks
      .map((task) => {
        const state = loaded.snapshot.tasks[task.id];
        return {
          kind: 'PACKET',
          task_id: task.id,
          path: state.packet.path,
          revision: state.packet.revision,
          sha256: normalizeHash(state.packet.sha256, `${task.id} packet sha256`),
        };
      })
      .sort((left, right) => left.task_id.localeCompare(right.task_id)),
  ];
  const unsigned = {
    goal_id: loaded.manifest.goal_id,
    repository_worktree: repository.repository_worktree,
    repository_common_dir: repository.repository_common_dir,
    repository_head: repository.repository_head,
    manifest_sha256: normalizeHash(
      loaded.manifest.manifest_sha256,
      `${loaded.manifest.goal_id} manifest sha256`,
    ),
    frozen_inputs_sha256: hashObject(frozenInputs),
  };
  return {
    ...unsigned,
    worktree_identity_sha256: hashObject(unsigned),
  };
}

function goalWorktreeMapReceipt(selection, bindings) {
  const goalWorktrees = [...bindings]
    .sort((left, right) => left.goal_id.localeCompare(right.goal_id));
  return {
    schema_version: 1,
    mode: selection.mode,
    mapping_file: selection.snapshot ? selection.snapshot.file : null,
    mapping_file_sha256: selection.snapshot
      ? selection.snapshot.file_sha256
      : null,
    goal_worktrees: goalWorktrees,
    goal_worktrees_sha256: hashObject(goalWorktrees),
  };
}

function assertHistoricalGoalWorktreeMapSubset(
  historicalMap,
  currentMap,
) {
  assertControl(
    historicalMap
      && Array.isArray(historicalMap.goal_worktrees)
      && currentMap
      && Array.isArray(currentMap.goal_worktrees),
    'STORE_MIGRATION_WORKTREE_MAP_MISMATCH',
    'historical/current Goal worktree map 结构非法',
  );
  const currentByGoal = new Map(
    currentMap.goal_worktrees.map((binding) => [
      binding.goal_id,
      binding,
    ]),
  );
  for (const historical of historicalMap.goal_worktrees) {
    const current = currentByGoal.get(historical.goal_id);
    assertControl(
      current
        && canonicalJson(current) === canonicalJson(historical),
      'STORE_MIGRATION_WORKTREE_MAP_MISMATCH',
      `historical Goal ${historical.goal_id} frozen mapping/identity 漂移`,
    );
  }
}

function assertGoalWorktreeSelectionUnchanged(selection, receipt, loadedByGoal) {
  assertGoalWorktreeMapFileUnchanged(selection.snapshot);
  for (const binding of receipt.goal_worktrees) {
    const current = selection.snapshot
      ? validateMappedRepositoryWorktree(
        binding.repository_worktree,
        selection.defaultRepository.repository_common_dir,
      )
      : validateRepositoryWorktree(binding.repository_worktree);
    assertControl(
      current.repository_worktree === binding.repository_worktree
        && current.repository_common_dir === binding.repository_common_dir
        && current.repository_head === binding.repository_head,
      'STORE_MIGRATION_WORKTREE_CHANGED',
      `Goal ${binding.goal_id} frozen worktree 在 replay 期间发生 identity/HEAD 漂移`,
    );
    const loaded = loadedByGoal.get(binding.goal_id);
    assertControl(
      loaded,
      'STORE_MIGRATION_WORKTREE_MAP_INCOMPLETE',
      `Goal ${binding.goal_id} 缺 replay snapshot，拒绝 seal`,
    );
    assertFrozenInputs(current.repository_worktree, loaded);
    assertControl(
      canonicalJson(frozenInputBinding(loaded, current))
        === canonicalJson(binding),
      'STORE_MIGRATION_WORKTREE_CHANGED',
      `Goal ${binding.goal_id} frozen inputs 在 replay 期间发生漂移`,
    );
  }
}

function existingMigrationArtifacts(root, protocol) {
  const descriptors = protocol && Array.isArray(protocol.migration_artifacts)
    ? protocol.migration_artifacts
    : [];
  return descriptors.map((descriptor) => {
    const file = path.join(root, descriptor.relative_path);
    const body = fs.readFileSync(file);
    assertControl(
      `sha256:${sha256(body)}` === normalizeHash(descriptor.sha256),
      'CORRUPT_STORE_PROTOCOL',
      `migration artifact bytes 与 root protocol seal 不匹配: ${descriptor.relative_path}`,
    );
    return {
      relative_path: descriptor.relative_path,
      sha256: normalizeHash(descriptor.sha256),
      body,
    };
  });
}

function createPredecessorCompatibilityCollector(protocol) {
  assertControl(
    protocol
      && typeof protocol === 'object'
      && !Array.isArray(protocol)
      && typeof protocol.seal_sha256 === 'string',
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation compatibility 缺 sealed predecessor protocol',
  );
  const unsigned = { ...protocol };
  delete unsigned.seal_sha256;
  const seal = normalizeHash(
    protocol.seal_sha256,
    'predecessor protocol seal sha256',
  );
  assertControl(
    hashObject(unsigned) === seal,
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation compatibility predecessor seal 不匹配',
  );
  const collector = new Map();
  collector.predecessorProtocolSealSha256 = seal;
  return collector;
}

function migrationValidation(cwd, context, options, hooks = {}) {
  assertNoSymlinks(path.join(context.root, 'goals'), 'control goals');
  assertNoSymlinks(path.join(context.root, 'resources'), 'control resources');

  const adopting = context.adopting === true;
  const rotating = options.rotationMode === true;
  const predecessorCompatibilityCollector = rotating
    ? createPredecessorCompatibilityCollector(context.existing_protocol)
    : null;
  const collector = adopting ? createLegacyEvidenceMigrationCollector() : null;
  const legacyIdentityIncidentCollector = adopting || rotating
    ? createLegacyIdentityIncidentCollector()
    : null;
  const legacyRecoveryHandoffCollector = adopting ? new Map() : null;
  let migrationArtifacts = adopting
    ? []
    : existingMigrationArtifacts(context.root, context.existing_protocol);
  let legacyIndex = null;
  if (migrationArtifacts.some(
    (artifact) => artifact.relative_path === LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
  )) {
    legacyIndex = readLegacyEvidenceAnchorIndex(context.root);
    if (!rotating) {
      assertControl(
        legacyIndex.migration_receipt.incident_ref === options.incidentRef
          && legacyIndex.migration_receipt.old_controller_drain_ack
            === options.oldControllerDrainAcknowledgment,
        'STORE_MIGRATION_INCIDENT_MISMATCH',
        'idempotent protocol adoption 必须使用首次 seal 的 incident-ref 与 drain acknowledgement',
      );
    }
  }
  validateProtocolSealedLegacyIdentityIncidentReceipts(context.root);
  const goals = [];
  const rejectionOnlyRoots = [];
  const ids = goalIds(context.root, rejectionOnlyRoots);
  const worktreeSelection = selectGoalWorktrees(
    cwd,
    ids,
    options.goalWorktreesFile,
  );
  const goalWorktreeBindings = [];
  const loadedByGoal = new Map();
  let totalEvidenceRegistries = 0;
  for (const goalId of ids) {
    const repository = worktreeSelection.byGoal.get(goalId);
    assertControl(
      repository,
      'STORE_MIGRATION_WORKTREE_MAP_INCOMPLETE',
      `Goal ${goalId} 缺 frozen worktree mapping`,
    );
    const loaded = loadGoalStateUnlocked(context.root, goalId, {
      repairHeads: false,
      repairBootstrapConsumption: false,
      requireBootstrapConsumptionReconciled: true,
      ...(collector ? { legacyEvidenceBindingCollector: collector } : {}),
      ...(legacyIdentityIncidentCollector
        ? { legacyIdentityIncidentCollector }
        : {}),
      ...(legacyRecoveryHandoffCollector
        ? {
          legacyRecoveryHandoffBindingCollector:
            legacyRecoveryHandoffCollector,
          legacyRecoveryHandoffRepositoryWorktree:
            repository.repository_worktree,
        }
        : {}),
    });
    loadedByGoal.set(goalId, loaded);
    assertFrozenInputs(repository.repository_worktree, loaded);
    assertSuccessorCompatibleActiveDevLaunches(context.root, loaded);
    const worktreeBinding = frozenInputBinding(loaded, repository);
    goalWorktreeBindings.push(worktreeBinding);
    const evidence = validateEvidenceRegistries(
      context.root,
      loaded,
      {
        legacyIndex,
        allowProtocolSealedIdentityIncidentSources: rotating,
        predecessorCompatibilityCollector,
        repositoryWorktree: repository.repository_worktree,
      },
    );
    totalEvidenceRegistries += evidence.registry_count;
    goals.push({
      goal_id: goalId,
      manifest_sha256: loaded.manifest.manifest_sha256,
      control_epoch: loaded.snapshot.control_epoch,
      control_event_count: loaded.control.eventCount,
      frozen_worktree: worktreeBinding,
      evidence,
      tasks: loaded.manifest.tasks.map((task) => taskSummary(loaded, task)),
    });
  }
  if (collector) collectLegacySemanticEvidenceSources(context.root, collector);
  const worktreeMapReceipt = goalWorktreeMapReceipt(
    worktreeSelection,
    goalWorktreeBindings,
  );
  assertGoalWorktreeSelectionUnchanged(
    worktreeSelection,
    worktreeMapReceipt,
    loadedByGoal,
  );
  if (legacyIndex) {
    if (rotating) {
      assertHistoricalGoalWorktreeMapSubset(
        legacyIndex.migration_receipt.goal_worktree_map,
        worktreeMapReceipt,
      );
    } else {
      assertControl(
        canonicalJson(legacyIndex.migration_receipt.goal_worktree_map)
          === canonicalJson(worktreeMapReceipt),
        'STORE_MIGRATION_WORKTREE_MAP_MISMATCH',
        'idempotent protocol adoption 必须使用首次 seal 的 exact Goal worktree mapping 与 identities',
      );
    }
  }

  const { state: resourceState } = rebuildResourcesReadOnlyUnlocked(context.root);
  const report = {
    schema_version: 1,
    decoder_sha256: normalizeHash(context.decoder_sha256, 'decoder sha256'),
    source_state_vector_sha256: normalizeHash(
      context.state_vector_sha256,
      'source state vector sha256',
    ),
    ...worktreeSelection.defaultRepository,
    goal_worktree_map: worktreeMapReceipt,
    goals,
    goal_count: goals.length,
    ignored_rejection_only_roots: rejectionOnlyRoots.sort(),
    evidence_registry_count: totalEvidenceRegistries,
    resources: {
      event_count: resourceState.event_count,
      lease_count: Object.keys(resourceState.leases).length,
      fencing_tokens_sha256: hashObject(resourceState.fencing_tokens),
    },
  };

  let legacyEvidenceEventCount = 0;
  let legacySemanticSourceCount = 0;
  let legacySemanticSourceBytes = 0;
  let legacyRecoveryHandoffCount = 0;
  if (adopting) {
    const sealed = sealLegacyEvidenceAnchorIndex(collector, {
      controllerDecoderSha256: context.decoder_sha256,
      sourceStateVectorSha256: context.state_vector_sha256,
      incidentRef: options.incidentRef,
      oldControllerDrainAck: options.oldControllerDrainAcknowledgment,
      goalWorktreeMap: worktreeMapReceipt,
      recoveryHandoffs: legacyRecoveryHandoffCollector,
    });
    migrationArtifacts = sealed.migration_artifacts;
    legacyEvidenceEventCount = sealed.event_count;
    legacySemanticSourceCount = sealed.semantic_source_count;
    legacySemanticSourceBytes = sealed.unique_semantic_source_bytes;
    legacyRecoveryHandoffCount = sealed.recovery_handoff_count;
  } else {
    if (legacyIndex) {
      legacyEvidenceEventCount = Object.keys(legacyIndex.events).length;
      legacySemanticSourceCount = Object.keys(legacyIndex.semantic_sources).length;
      legacyRecoveryHandoffCount = Object.keys(
        legacyIndex.recovery_handoffs,
      ).length;
      legacySemanticSourceBytes = migrationArtifacts
        .filter((artifact) => ![
          LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
          LEGACY_IDENTITY_INCIDENT_RECEIPT_RELATIVE_PATH,
        ].includes(artifact.relative_path))
        .reduce((sum, artifact) => sum + artifact.body.length, 0);
    }
  }
  report.legacy_evidence_event_count = legacyEvidenceEventCount;
  report.legacy_semantic_source_count = legacySemanticSourceCount;
  report.legacy_semantic_source_bytes = legacySemanticSourceBytes;
  report.legacy_recovery_handoff_count = legacyRecoveryHandoffCount;
  let legacyIdentityIncidentCount = 0;
  let legacyIdentityIncidentSkippedSemanticCount = 0;
  let legacyIdentityIncidentSkippedSemanticHolds = [];
  if (adopting || rotating) {
    const sealedIdentityIncidents = sealLegacyIdentityIncidentReceipt(
      legacyIdentityIncidentCollector,
      {
        controllerDecoderSha256: context.decoder_sha256,
        sourceStateVectorSha256: context.state_vector_sha256,
        predecessorProtocolSealSha256:
          context.existing_protocol
            && context.existing_protocol.seal_sha256,
        incidentRef: options.incidentRef,
        oldControllerDrainAck:
          options.oldControllerDrainAcknowledgment,
      },
    );
    legacyIdentityIncidentCount =
      sealedIdentityIncidents.incident_count;
    legacyIdentityIncidentSkippedSemanticCount =
      sealedIdentityIncidents.skipped_semantic_count;
    legacyIdentityIncidentSkippedSemanticHolds =
      sealedIdentityIncidents.skipped_semantic_holds;
    if (adopting) {
      migrationArtifacts = [
        ...migrationArtifacts.filter((artifact) => (
          artifact.relative_path
            !== LEGACY_IDENTITY_INCIDENT_RECEIPT_RELATIVE_PATH
        )),
        sealedIdentityIncidents.migration_artifact,
      ].sort((left, right) => (
        left.relative_path.localeCompare(right.relative_path)
      ));
    } else {
      report.legacy_identity_incident_receipt =
        sealedIdentityIncidents.receipt;
    }
  } else {
    const identityArtifact = migrationArtifacts.find((artifact) => (
      artifact.relative_path
        === LEGACY_IDENTITY_INCIDENT_RECEIPT_RELATIVE_PATH
    ));
    if (identityArtifact) {
      const existingIdentityReceipt =
        validateLegacyIdentityIncidentReceipt(JSON.parse(
          identityArtifact.body.toString('utf8'),
        ), { root: context.root });
      legacyIdentityIncidentCount = Object.keys(
        existingIdentityReceipt.incidents,
      ).length;
    }
  }
  report.legacy_identity_incident_count =
    legacyIdentityIncidentCount;
  report.legacy_identity_incident_skipped_semantic_count =
    legacyIdentityIncidentSkippedSemanticCount;
  report.legacy_identity_incident_skipped_semantic_holds =
    legacyIdentityIncidentSkippedSemanticHolds;

  if (typeof hooks.afterReplay === 'function') {
    hooks.afterReplay({ root: context.root, report });
  }
  assertGoalWorktreeSelectionUnchanged(
    worktreeSelection,
    worktreeMapReceipt,
    loadedByGoal,
  );
  return {
    report,
    migration_artifacts: migrationArtifacts,
    predecessor_compatibility_overlay:
      sealPredecessorCompatibilityOverlay(
        predecessorCompatibilityCollector,
      ),
  };
}

function adoptStoreProtocol(cwd, options, hooks = {}) {
  assertControl(
    options
      && typeof options.incidentRef === 'string'
      && options.incidentRef.trim().length > 0
      && options.incidentRef.length <= 2000,
    'STORE_MIGRATION_INCIDENT_REQUIRED',
    'adopt-store-protocol 必须提供 durable --incident-ref',
  );
  assertControl(
    options.oldControllerDrainAcknowledgment === OLD_CONTROLLER_DRAIN_ACK,
    'STORE_MIGRATION_DRAIN_ACK_REQUIRED',
    `必须精确确认 --acknowledge-old-controller-drained ${OLD_CONTROLLER_DRAIN_ACK}`,
  );
  const migrationOptions = {
    incidentRef: options.incidentRef.trim(),
    oldControllerDrainAcknowledgment: options.oldControllerDrainAcknowledgment,
    goalWorktreesFile: options.goalWorktreesFile || null,
  };
  const root = controlRoot(cwd);
  const adopted = adoptRootProtocol(
    root,
    (context) => {
      const {
        report,
        migration_artifacts: migrationArtifacts,
        predecessor_compatibility_overlay: predecessorCompatibilityOverlay,
      } = migrationValidation(cwd, context, migrationOptions, hooks);
      assertControl(
        predecessorCompatibilityOverlay
          && Array.isArray(predecessorCompatibilityOverlay.changes)
          && predecessorCompatibilityOverlay.changes.length === 0,
        'STORE_MIGRATION_RESULT_INVALID',
        'adoption 不得携带 rotation-only predecessor compatibility overlay',
      );
      return {
        report,
        migration_artifacts: migrationArtifacts,
      };
    },
  );
  const validation = adopted.validation;
  assertControl(
    validation && validation.schema_version === 1,
    'STORE_MIGRATION_RESULT_INCOMPLETE',
    'store protocol adoption 未返回完整 replay report',
  );
  return {
    schema_version: 1,
    operation: 'STORE_PROTOCOL_ADOPTION',
    incident_ref: migrationOptions.incidentRef,
    old_controllers_drained_and_isolated: true,
    adopted: adopted.adopted,
    idempotent: adopted.idempotent,
    control_root: root,
    protocol: adopted.protocol,
    source_state_vector_sha256: adopted.source_state_vector_sha256
      || adopted.state_vector_sha256,
    sealed_state_vector_sha256: adopted.sealed_state_vector_sha256
      || adopted.state_vector_sha256,
    migration_artifacts: adopted.migration_artifacts || [],
    validation,
    residual_security_boundary: '同一 OS UID 的旧 controller binary 会忽略新 seal；只能依赖运行前 drain/isolate，不能由同一 root 双向 fence。',
  };
}

function validateControllerWorktree(requested, role) {
  const label = role === 'PREDECESSOR' ? 'predecessor' : 'successor';
  const worktreeError =
    `STORE_PROTOCOL_ROTATION_${role}_WORKTREE_INVALID`;
  const decoderError =
    `STORE_PROTOCOL_ROTATION_${role}_DECODER_INVALID`;
  assertControl(
    typeof requested === 'string' && path.isAbsolute(requested),
    worktreeError,
    `${label} controller worktree 必须是绝对路径`,
  );
  const normalized = path.resolve(requested);
  let requestedStat;
  let worktree;
  try {
    requestedStat = fs.lstatSync(normalized);
    worktree = fs.realpathSync(normalized);
  } catch (error) {
    throw new ControlError(
      worktreeError,
      `${label} controller worktree 无法读取: ${error.message}`,
    );
  }
  assertControl(
    requestedStat.isDirectory()
      && !requestedStat.isSymbolicLink()
      && normalized === worktree,
    worktreeError,
    `${label} controller worktree 必须是 canonical、非 symlink 目录`,
  );
  const repositoryRoot = fs.realpathSync(repoRoot(worktree));
  assertControl(
    repositoryRoot === worktree,
    worktreeError,
    `${label} controller worktree 必须指向 Git worktree 根目录`,
  );
  const identity = validateRepositoryWorktree(worktree);
  assertControl(
    identity.repository_worktree === worktree,
    worktreeError,
    `${label} controller Git identity 与 requested worktree 不匹配`,
  );
  const decoderDirectory = path.join(
    identity.repository_worktree,
    'scripts',
    'goal-control',
  );
  let decoderStat;
  let canonicalDecoderDirectory;
  try {
    decoderStat = fs.lstatSync(decoderDirectory);
    canonicalDecoderDirectory = fs.realpathSync(decoderDirectory);
  } catch (error) {
    throw new ControlError(
      decoderError,
      `${label} decoder directory 无法读取: ${error.message}`,
    );
  }
  assertControl(
    decoderStat.isDirectory()
      && !decoderStat.isSymbolicLink()
      && canonicalDecoderDirectory === decoderDirectory
      && canonicalDecoderDirectory === path.join(
        identity.repository_worktree,
        'scripts',
        'goal-control',
      )
      && fs.existsSync(path.join(decoderDirectory, 'store.js'))
      && fs.existsSync(path.join(decoderDirectory, 'goal.js'))
      && fs.existsSync(path.join(decoderDirectory, 'resources.js')),
    decoderError,
    `${label} controller worktree 缺 canonical goal-control decoder closure`,
  );
  const committedClosure = assertControllerControlPathsCommitted(
    identity.repository_worktree,
    identity.repository_head,
  );
  return {
    ...identity,
    decoder_directory: canonicalDecoderDirectory,
    decoder_sha256: controllerDecoderFingerprintAt(decoderDirectory),
    controller_closure_sha256: committedClosure.closureSha256,
  };
}

function validatePredecessorControllerWorktree(requested) {
  return validateControllerWorktree(requested, 'PREDECESSOR');
}

function validateSuccessorControllerWorktree() {
  return validateControllerWorktree(
    path.resolve(__dirname, '..', '..'),
    'SUCCESSOR',
  );
}

function predecessorSubprocessTimeout(
  cwd,
  hooks,
  optionName,
  testEnvironmentName,
  fallback,
) {
  const hookValue = hooks && hooks[optionName];
  const environmentValue = process.env[testEnvironmentName];
  const requested = hookValue !== undefined
    ? hookValue
    : environmentValue === undefined
      ? undefined
      : Number(environmentValue);
  if (requested === undefined) return fallback;
  assertIsolatedTestMode(cwd);
  assertControl(
    Number.isSafeInteger(requested)
      && requested > 0
      && requested <= fallback,
    'TEST_MODE_FORBIDDEN',
    `${optionName} 只允许隔离测试缩短，且必须是 1..${fallback}ms 的整数`,
  );
  return requested;
}

function predecessorSubprocessFailure(
  code,
  label,
  error,
  timeoutMilliseconds,
) {
  const timedOut = error
    && (
      error.code === 'ETIMEDOUT'
        || (
          error.signal === 'SIGKILL'
            && error.killed === true
        )
    );
  const rawDetail = error && error.stderr
    ? String(error.stderr).trim()
    : error && error.message
      ? String(error.message).trim()
      : '';
  const detail = timedOut
    ? `超过 ${timeoutMilliseconds}ms，子进程已由 SIGKILL 终止`
    : rawDetail || '未知子进程错误';
  return new ControlError(code, `${label} 失败: ${detail}`);
}

function strictPredecessorProtocolProbe(
  controller,
  root,
  protocol,
  options = {},
) {
  const timeoutMilliseconds = options.timeoutMilliseconds
    ?? PREDECESSOR_STRICT_PROBE_TIMEOUT_MILLISECONDS;
  const probeRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), 'goal-protocol-predecessor-probe-'),
  );
  fs.chmodSync(probeRoot, 0o700);
  const copyRelative = (relativePath) => {
    const source = path.join(root, relativePath);
    const destination = path.join(probeRoot, relativePath);
    assertControl(
      destination.startsWith(`${probeRoot}${path.sep}`),
      'STORE_PROTOCOL_ROTATION_PREDECESSOR_PROBE_FAILED',
      `predecessor probe artifact path 越界: ${relativePath}`,
    );
    fs.mkdirSync(path.dirname(destination), {
      recursive: true,
      mode: 0o700,
    });
    fs.copyFileSync(source, destination);
    fs.chmodSync(destination, 0o600);
  };
  const script = [
    "'use strict';",
    "const path = require('path');",
    'const decoder = process.argv[1];',
    'const root = process.argv[2];',
    "const store = require(path.join(decoder, 'store.js'));",
    'const value = store.withStableRead(root, () => ({ pass: true }));',
    'process.stdout.write(`${JSON.stringify(value)}\\n`);',
  ].join('\n');
  let stdout;
  try {
    copyRelative('.store-protocol.json');
    for (const descriptor of protocol.migration_artifacts || []) {
      copyRelative(descriptor.relative_path);
    }
    for (const descriptor of protocol.protocol_rotations || []) {
      copyRelative(descriptor.relative_path);
    }
    stdout = execFileSync(
      process.execPath,
      ['-e', script, controller.decoder_directory, probeRoot],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: undefined,
        },
        maxBuffer: 4 * 1024 * 1024,
        timeout: timeoutMilliseconds,
        killSignal: 'SIGKILL',
      },
    );
  } catch (error) {
    throw predecessorSubprocessFailure(
      'STORE_PROTOCOL_ROTATION_PREDECESSOR_PROBE_FAILED',
      'predecessor decoder strict protocol probe',
      error,
      timeoutMilliseconds,
    );
  } finally {
    fs.rmSync(probeRoot, { recursive: true, force: true });
  }
  assertControl(
    stdout.trim() === '{"pass":true}',
    'STORE_PROTOCOL_ROTATION_PREDECESSOR_PROBE_FAILED',
    'predecessor decoder strict protocol probe 输出异常',
  );
  return {
    status: 'PASS',
    stdout_sha256: `sha256:${sha256(Buffer.from(stdout))}`,
  };
}

function predecessorUnlockedReplay(
  controller,
  root,
  ids,
  options = {},
) {
  const timeoutMilliseconds = options.timeoutMilliseconds
    ?? PREDECESSOR_REPLAY_TIMEOUT_MILLISECONDS;
  const compatibilityOverlay = options.compatibilityOverlay;
  const overlayInput = predecessorCompatibilityReadOverlay(
    compatibilityOverlay,
  );
  const script = [
    "'use strict';",
    "const fs = require('fs');",
    "const path = require('path');",
    'const decoder = process.argv[1];',
    'const root = process.argv[2];',
    'const ids = JSON.parse(process.argv[3]);',
    "const overlay = JSON.parse(fs.readFileSync(0, 'utf8'));",
    'if (',
    '  !overlay',
    "    || overlay.schema_version !== 1",
    '    || !Array.isArray(overlay.records)',
    ') throw new Error("invalid predecessor read overlay");',
    'const overlayReads = new Map();',
    'for (const record of overlay.records) {',
    '  if (',
    '    !record',
    "      || typeof record.path !== 'string'",
    '      || !path.isAbsolute(record.path)',
    "      || typeof record.body_base64 !== 'string'",
    '      || overlayReads.has(record.path)',
    '  ) throw new Error("invalid predecessor read overlay record");',
    "  const body = Buffer.from(record.body_base64, 'base64');",
    '  if (body.toString("base64") !== record.body_base64) {',
    '    throw new Error("non-canonical predecessor overlay bytes");',
    '  }',
    '  overlayReads.set(record.path, body);',
    '}',
    'const originalReadFileSync = fs.readFileSync.bind(fs);',
    'fs.readFileSync = function exactPredecessorOverlayRead(file, options) {',
    "  const body = typeof file === 'string'",
    '    ? overlayReads.get(file)',
    '    : undefined;',
    '  if (body === undefined) return originalReadFileSync(file, options);',
    "  const encoding = typeof options === 'string'",
    '    ? options',
    '    : options && options.encoding;',
    '  return encoding ? body.toString(encoding) : Buffer.from(body);',
    '};',
    "const goal = require(path.join(decoder, 'goal.js'));",
    "const resources = require(path.join(decoder, 'resources.js'));",
    "const util = require(path.join(decoder, 'util.js'));",
    'const mapEntries = (value) => [...value.entries()]',
    '  .sort(([left], [right]) => String(left).localeCompare(String(right)));',
    'const withoutGeneratedAt = (value) => {',
    '  const stable = { ...value };',
    '  delete stable.generated_at;',
    '  return stable;',
    '};',
    'const goals = ids.map((goalId) => {',
    '  const loaded = goal.loadGoalStateUnlocked(root, goalId, {',
    '    repairHeads: false,',
    '    repairBootstrapConsumption: false,',
    '    requireBootstrapConsumptionReconciled: true,',
    '  });',
    '  return {',
    '    goal_id: goalId,',
    '    manifest: loaded.manifest,',
    '    meta: loaded.meta,',
    '    control: loaded.control,',
    '    snapshot: withoutGeneratedAt(loaded.snapshot),',
    '    task_events: Object.fromEntries(',
    '      Object.keys(loaded.eventIndexes).sort().map((taskId) => [',
    '        taskId,',
    '        mapEntries(loaded.eventIndexes[taskId]),',
    '      ]),',
    '    ),',
    '    last_event_hashes: loaded.lastEventHashes,',
    '    pending_foreman_recovery_batches:',
    '      loaded.pendingForemanRecoveryBatches,',
    '    pending_goal_operations: loaded.pendingGoalOperations,',
    '  };',
    '});',
    'const rebuilt = resources.rebuildResourcesReadOnlyUnlocked(root).state;',
    'const report = {',
    '  goals,',
    '  resources: withoutGeneratedAt(rebuilt),',
    '};',
    'process.stdout.write(`${util.canonicalJson(report)}\\n`);',
  ].join('\n');
  let stdout;
  let replayError = null;
  try {
    stdout = execFileSync(
      process.execPath,
      [
        '-e',
        script,
        controller.decoder_directory,
        root,
        JSON.stringify(ids),
      ],
      {
        input: `${canonicalJson(overlayInput)}\n`,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: undefined,
        },
        maxBuffer: 64 * 1024 * 1024,
        timeout: timeoutMilliseconds,
        killSignal: 'SIGKILL',
      },
    );
  } catch (error) {
    replayError = error;
  }
  for (const change of compatibilityOverlay.changes) {
    assertCompatibilityOverlaySourcesUnchanged(change);
  }
  if (replayError) {
    throw predecessorSubprocessFailure(
      'STORE_PROTOCOL_ROTATION_PREDECESSOR_REPLAY_FAILED',
      'predecessor decoder unlocked replay',
      replayError,
      timeoutMilliseconds,
    );
  }
  try {
    const report = JSON.parse(stdout);
    assertControl(
      `${canonicalJson(report)}\n` === stdout,
      'STORE_PROTOCOL_ROTATION_PREDECESSOR_REPLAY_FAILED',
      'predecessor decoder replay 不是 canonical JSON',
    );
    return report;
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'STORE_PROTOCOL_ROTATION_PREDECESSOR_REPLAY_FAILED',
      `predecessor decoder replay 输出非法: ${error.message}`,
    );
  }
}

function atomicSnapshotIdentityMatches(left, right) {
  return left.file_sha256 === right.file_sha256
    && left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtime_ms === right.mtime_ms
    && left.ctime_ms === right.ctime_ms;
}

function assertCompatibilityOverlaySourcesUnchanged(change) {
  const registry = stableRegularFileSnapshot(
    change.registry_file,
    `predecessor overlay source registry ${change.registry_relative_path}`,
  );
  const canonical = stableRegularFileSnapshot(
    change.canonical_launch_file,
    `predecessor overlay overwritten canonical launch ${change.registry_relative_path}`,
  );
  const immutable = stableRegularFileSnapshot(
    change.immutable_launch_file,
    `predecessor overlay immutable launch ${change.registry_relative_path}`,
  );
  assertControl(
    atomicSnapshotIdentityMatches(registry, change.registry_snapshot)
      && atomicSnapshotIdentityMatches(
        canonical,
        change.canonical_launch_snapshot,
      )
      && atomicSnapshotIdentityMatches(
        immutable,
        change.immutable_launch_snapshot,
      ),
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_CHANGED',
    `predecessor PREFLIGHT compatibility source 在 replay 期间漂移: ${change.registry_relative_path}`,
  );
}

function predecessorCompatibilityReadOverlay(overlay) {
  assertControl(
    overlay
      && Array.isArray(overlay.changes)
      && overlay.audit
      && overlay.audit.record_count === overlay.changes.length,
    'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_INVALID',
    'predecessor compatibility overlay plan 非法',
  );
  const records = [];
  for (const change of overlay.changes) {
    assertCompatibilityOverlaySourcesUnchanged(change);
    const unsigned = { ...change.overlaid_record };
    delete unsigned.registry_sha256;
    const acceptedEventReplay =
      change.audit.accepted_event_replay === true;
    assertControl(
      path.isAbsolute(change.registry_file)
        && hashObject(unsigned)
          === change.overlaid_record.registry_sha256
        && (
          acceptedEventReplay
            ? (
              change.audit.read_overlay_kind
                === 'SEALED_ACCEPTED_REPLAY_NO_OVERLAY'
                && change.audit.overlay_registry_sha256
                  === change.source_registry_sha256
                && change.audit.read_overlay_relative_path === null
            )
            : change.audit.read_overlay_kind
              === 'REGISTRY_LAUNCH_URI'
        ),
      'STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_INVALID',
      `predecessor in-memory overlay registry seal 非法: ${change.registry_relative_path}`,
    );
    if (acceptedEventReplay) continue;
    records.push({
      path: change.registry_file,
      body_base64: Buffer.from(
        `${JSON.stringify(change.overlaid_record, null, 2)}\n`,
      ).toString('base64'),
    });
  }
  return {
    schema_version: 1,
    records,
  };
}

function canonicalLoadedGoalReplay(loaded, goalId) {
  const snapshot = { ...loaded.snapshot };
  delete snapshot.generated_at;
  return {
    goal_id: goalId,
    manifest: loaded.manifest,
    meta: loaded.meta,
    control: loaded.control,
    snapshot,
    task_events: Object.fromEntries(
      Object.keys(loaded.eventIndexes).sort().map((taskId) => [
        taskId,
        [...loaded.eventIndexes[taskId].entries()]
          .sort(([left], [right]) => (
            String(left).localeCompare(String(right))
          )),
      ]),
    ),
    last_event_hashes: loaded.lastEventHashes,
    pending_foreman_recovery_batches:
      loaded.pendingForemanRecoveryBatches,
    pending_goal_operations: loaded.pendingGoalOperations,
  };
}

function successorUnlockedReplay(root, ids) {
  const resources = {
    ...rebuildResourcesReadOnlyUnlocked(root).state,
  };
  delete resources.generated_at;
  return {
    goals: ids.map((goalId) => canonicalLoadedGoalReplay(
      loadGoalStateUnlocked(root, goalId, {
        repairHeads: false,
        repairBootstrapConsumption: false,
        requireBootstrapConsumptionReconciled: true,
      }),
      goalId,
    )),
    resources,
  };
}

function rotateStoreProtocol(cwd, options, hooks = {}) {
  assertControl(
    options
      && typeof options.rotationId === 'string'
      && options.rotationId.length > 0,
    'STORE_PROTOCOL_ROTATION_ID_REQUIRED',
    'rotate-store-protocol 必须提供稳定 --rotation-id',
  );
  const rotationId = safeId(options.rotationId, 'rotation_id');
  assertControl(
    typeof options.incidentRef === 'string'
      && options.incidentRef.trim().length > 0
      && options.incidentRef.trim().length <= 2000,
    'STORE_MIGRATION_INCIDENT_REQUIRED',
    'rotate-store-protocol 必须提供 durable --incident-ref',
  );
  assertControl(
    options.oldControllerDrainAcknowledgment === OLD_CONTROLLER_DRAIN_ACK,
    'STORE_MIGRATION_DRAIN_ACK_REQUIRED',
    `必须精确确认 --acknowledge-old-controller-drained ${OLD_CONTROLLER_DRAIN_ACK}`,
  );
  assertControl(
    typeof options.predecessorControllerWorktree === 'string'
      && path.isAbsolute(options.predecessorControllerWorktree),
    'STORE_PROTOCOL_ROTATION_PREDECESSOR_WORKTREE_REQUIRED',
    '--predecessor-controller-worktree 必须是绝对路径',
  );
  const expectedPredecessorSealSha256 = normalizeHash(
    options.expectedPredecessorSealSha256,
    'expected predecessor seal sha256',
  );
  const incidentRef = options.incidentRef.trim();
  const predecessorControllerWorktree = path.resolve(
    options.predecessorControllerWorktree,
  );
  assertControl(
    options.goalWorktreesFile === null
      || options.goalWorktreesFile === undefined
      || (
        typeof options.goalWorktreesFile === 'string'
          && path.isAbsolute(options.goalWorktreesFile)
          && path.normalize(options.goalWorktreesFile)
            === options.goalWorktreesFile
      ),
    'INVALID_ARGUMENT',
    '--goal-worktrees-file 必须是规范绝对路径',
  );
  const goalWorktreesFile = options.goalWorktreesFile || null;
  const predecessorProbeTimeoutMilliseconds =
    predecessorSubprocessTimeout(
      cwd,
      hooks,
      'predecessorProbeTimeoutMilliseconds',
      'GOAL_CONTROL_TEST_PREDECESSOR_PROBE_TIMEOUT_MILLISECONDS',
      PREDECESSOR_STRICT_PROBE_TIMEOUT_MILLISECONDS,
    );
  const predecessorReplayTimeoutMilliseconds =
    predecessorSubprocessTimeout(
      cwd,
      hooks,
      'predecessorReplayTimeoutMilliseconds',
      'GOAL_CONTROL_TEST_PREDECESSOR_REPLAY_TIMEOUT_MILLISECONDS',
      PREDECESSOR_REPLAY_TIMEOUT_MILLISECONDS,
    );
  const operatorRequest = {
    schema_version: 1,
    rotation_id: rotationId,
    predecessor_controller_worktree:
      predecessorControllerWorktree,
    goal_worktrees_file: goalWorktreesFile,
    expected_predecessor_seal_sha256:
      expectedPredecessorSealSha256,
    incident_ref: incidentRef,
    old_controller_drain_ack:
      options.oldControllerDrainAcknowledgment,
  };
  const rotationRequest = {
    rotationId,
    incidentRef,
    oldControllerDrainAcknowledgment:
      options.oldControllerDrainAcknowledgment,
    expectedPredecessorSealSha256,
    operatorRequestSha256: hashObject(operatorRequest),
  };
  const root = controlRoot(cwd);
  validateRepositoryWorktree(cwd);
  const successorController =
    validateSuccessorControllerWorktree();
  let controller = null;
  let strictProbe = null;
  const initialSnapshot = readRootProtocolSealForRotation(
    root,
    rotationRequest,
  );
  const initialProtocol = initialSnapshot.protocol;
  assertControl(
    initialProtocol !== null,
    'STORE_PROTOCOL_ROTATION_PREDECESSOR_REQUIRED',
    '未 seal v1 root 必须走 adopt-store-protocol',
  );
  if (
    initialSnapshot.pending_rotation === null
      && initialProtocol.seal_sha256
        === expectedPredecessorSealSha256
  ) {
    controller = validatePredecessorControllerWorktree(
      predecessorControllerWorktree,
    );
    assertControl(
      controller.decoder_sha256
        === initialProtocol.controller_decoder_sha256,
      'STORE_PROTOCOL_ROTATION_PREDECESSOR_DECODER_MISMATCH',
      'predecessor controller closure fingerprint 与 sealed decoder 不匹配',
    );
    strictProbe = strictPredecessorProtocolProbe(
      controller,
      root,
      initialProtocol,
      {
        timeoutMilliseconds:
          predecessorProbeTimeoutMilliseconds,
      },
    );
  }
  const rotated = rotateRootProtocol(
    root,
    (context) => {
      const beforeSuccessorController =
        validateSuccessorControllerWorktree();
      assertControl(
        canonicalJson(beforeSuccessorController)
          === canonicalJson(successorController)
          && beforeSuccessorController.decoder_sha256
            === context.target_decoder_sha256,
        'STORE_PROTOCOL_ROTATION_SUCCESSOR_DECODER_CHANGED',
        'successor controller worktree/HEAD/fingerprint 在 rotation 前漂移',
      );
      const beforeController =
        validatePredecessorControllerWorktree(
          predecessorControllerWorktree,
        );
      assertControl(
        controller !== null
          && canonicalJson(beforeController)
            === canonicalJson(controller),
        'STORE_PROTOCOL_ROTATION_PREDECESSOR_DECODER_CHANGED',
        'predecessor controller worktree/common-dir/HEAD/fingerprint 在 rotation 前漂移',
      );
      assertControl(
        beforeController.decoder_sha256
          === context.predecessor_protocol.controller_decoder_sha256,
        'STORE_PROTOCOL_ROTATION_PREDECESSOR_DECODER_MISMATCH',
        'rotation lock 内 predecessor decoder fingerprint 漂移',
      );
      assertControl(
        strictProbe !== null,
        'STORE_PROTOCOL_ROTATION_PREDECESSOR_PROBE_FAILED',
        'fresh/receipt-only rotation 缺 predecessor strict probe',
      );
      const migrationOptions = {
        incidentRef,
        oldControllerDrainAcknowledgment:
          options.oldControllerDrainAcknowledgment,
        goalWorktreesFile,
        rotationMode: true,
      };
      const validated = migrationValidation(
        cwd,
        {
          root: context.root,
          state_vector_sha256:
            context.source_state_vector_sha256,
          decoder_sha256: context.target_decoder_sha256,
          existing_protocol: context.predecessor_protocol,
          adopting: false,
        },
        migrationOptions,
        hooks,
      );
      const ids = validated.report.goals.map((goal) => goal.goal_id);
      const predecessorReport = predecessorUnlockedReplay(
        beforeController,
        root,
        ids,
        {
          timeoutMilliseconds:
            predecessorReplayTimeoutMilliseconds,
          compatibilityOverlay:
            validated.predecessor_compatibility_overlay,
        },
      );
      const successorReport = successorUnlockedReplay(root, ids);
      assertControl(
        canonicalJson(predecessorReport)
          === canonicalJson(successorReport),
        'STORE_PROTOCOL_ROTATION_DECODER_REPLAY_MISMATCH',
        'predecessor/successor decoder 对 sealed control bytes 的语义重放不一致',
      );
      const afterController =
        validatePredecessorControllerWorktree(
          predecessorControllerWorktree,
        );
      assertControl(
        canonicalJson(beforeController)
          === canonicalJson(afterController),
        'STORE_PROTOCOL_ROTATION_PREDECESSOR_DECODER_CHANGED',
        'predecessor controller worktree 在 replay 期间发生 identity/HEAD/fingerprint 漂移',
      );
      const afterSuccessorController =
        validateSuccessorControllerWorktree();
      assertControl(
        canonicalJson(beforeSuccessorController)
          === canonicalJson(afterSuccessorController),
        'STORE_PROTOCOL_ROTATION_SUCCESSOR_DECODER_CHANGED',
        'successor controller worktree 在 replay 期间发生 identity/HEAD/fingerprint 漂移',
      );
      return {
        report: {
          ...validated.report,
          protocol_rotation: {
            schema_version: 1,
            predecessor_controller: beforeController,
            successor_controller: beforeSuccessorController,
            predecessor_strict_probe: strictProbe,
            predecessor_compatibility_overlay:
              validated.predecessor_compatibility_overlay.audit,
            predecessor_semantic_replay_sha256:
              hashObject(predecessorReport),
            successor_semantic_replay_sha256:
              hashObject(successorReport),
            semantic_replay_match: true,
          },
        },
      };
    },
    rotationRequest,
    hooks,
  );
  return {
    schema_version: 1,
    operation: 'STORE_PROTOCOL_ROTATION',
    rotation_id: rotationId,
    incident_ref: incidentRef,
    old_controllers_drained_and_isolated: true,
    control_root: root,
    ...rotated,
  };
}

module.exports = {
  OLD_CONTROLLER_DRAIN_ACK,
  adoptStoreProtocol,
  assertSuccessorCompatibleActiveDevLaunches,
  migrationValidation,
  rotateStoreProtocol,
};
