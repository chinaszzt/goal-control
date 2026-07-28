'use strict';

const fs = require('fs');
const path = require('path');
const { fileURLToPath, pathToFileURL } = require('url');
const { ControlError, assertControl } = require('./errors');
const {
  authorizeGoalSession,
  authorizeSession,
  hashesEqual,
  readCapabilityFile,
} = require('./auth');
const {
  assertDevCandidateLineage,
  assertDevCandidateReplayLineage,
} = require('./candidate-lineage');
const {
  acceptedEventFiles,
  atomicWrite,
  atomicWriteJson,
  canonicalTransactionKey,
  ensureDir,
  readProtocolSealedMigrationArtifact,
  withLock,
  withStableRead,
} = require('./store');
const {
  git,
  hashFile,
  hashObject,
  canonicalJson,
  controlRoot,
  normalizeHash,
  readJson,
  safeId,
  sha256,
} = require('./util');
const { assertOperationalScope, sessionOperationalScope } = require('./operational-scope');
const {
  assertLaunchRuntimeIncarnation,
  isRuntimeRotationHoldLane,
} = require('./runtime-incarnation');
const {
  assertSourceCheckpointAdvance,
  canonicalRuntimeLaunchFile,
  collectLegacyIdentityIncident,
  readProtocolSealedIdentityIncidentEvidenceSource,
} = require('./launch-source-checkpoint');

const EXPECTED_PRODUCER = Object.freeze({
  PREFLIGHT: ['DEV', 'REVIEW', 'RECEIPT', 'CAPTAIN'],
  FAST: ['DEV'],
  FULL_CI: ['CAPTAIN'],
  AC_AUDIT: ['CAPTAIN'],
  DEV_SELF_REVIEW: ['DEV'],
  REVIEW: ['REVIEW'],
  RECEIPT: ['RECEIPT'],
  PREVIEW: ['DEV', 'CAPTAIN', 'RECEIPT'],
  SEAM: ['DEV', 'REVIEW', 'RECEIPT'],
  ENVIRONMENT: ['DEV', 'CAPTAIN', 'RECEIPT'],
  APPROVAL: ['FOREMAN'],
  HOLD_ASSERTION: ['DEV', 'REVIEW', 'RECEIPT', 'CAPTAIN', 'FOREMAN'],
  HOLD_RESOLUTION: ['FOREMAN'],
  MERGE_BOUNDARY: ['FOREMAN'],
  ROLE_FAILURE: ['CAPTAIN', 'FOREMAN'],
  CONTROL: ['FOREMAN'],
});

const MECHANICAL_EVIDENCE_KINDS = new Set(['PREFLIGHT', 'FAST', 'FULL_CI', 'AC_AUDIT']);

function publicEvidenceResult(result) {
  const value = JSON.parse(JSON.stringify(result));
  const redact = (candidate) => {
    if (Array.isArray(candidate)) {
      for (const item of candidate) redact(item);
      return;
    }
    if (!candidate || typeof candidate !== 'object') return;
    delete candidate.capability_file;
    delete candidate.capability_sha256;
    for (const nested of Object.values(candidate)) redact(nested);
  };
  redact(value);
  return value;
}

const LEGACY_SEMANTIC_SOURCE_MAX_BYTES = 16 * 1024 * 1024;
const LEGACY_SEMANTIC_SOURCE_TOTAL_MAX_BYTES = 64 * 1024 * 1024;
const LEGACY_SEMANTIC_SOURCE_MAX_COUNT = 4096;
const SEMANTIC_SOURCE_MAX_BYTES = 16 * 1024 * 1024;

const EVIDENCE_STATUSES = new Set(['PASS', 'FAIL', 'BLOCKED', 'STALE']);
const EVIDENCE_KEYS = new Set([
  'schema_version', 'evidence_id', 'goal_id', 'task_id', 'kind', 'stage', 'status', 'producer',
  'state_revision', 'packet', 'packet_sha256', 'base_head', 'full_head', 'launch_id', 'created_at',
  'uri', 'source_sha256', 'command', 'checks', 'attestation', 'launch_sha256', 'launch_uri',
  'runtime_launch_sha256', 'runtime_launch_uri',
  'pull_request',
  'resource_lease',
]);

function validateResourceLeaseBinding(value) {
  assertControl(value && typeof value === 'object' && !Array.isArray(value), 'INVALID_EVIDENCE', 'resource_lease 必须是对象');
  const keys = ['lease_id', 'resource', 'revision', 'owner', 'isolated', 'isolation_ref'];
  assertControl(Object.keys(value).length === keys.length && Object.keys(value).every((key) => keys.includes(key)), 'INVALID_EVIDENCE', 'resource_lease 字段非法');
  safeId(value.lease_id, 'resource_lease.lease_id');
  assertControl(typeof value.resource === 'string' && value.resource.length > 0, 'INVALID_EVIDENCE', 'resource_lease.resource 非法');
  assertControl(Number.isSafeInteger(value.revision) && value.revision > 0, 'INVALID_EVIDENCE', 'resource_lease.revision 非法');
  assertControl(value.isolated === true, 'RESOURCE_ISOLATION_REQUIRED', 'ROLE_FAILURE 资源证据必须明确 isolated=true');
  assertControl(typeof value.isolation_ref === 'string' && value.isolation_ref.length > 0 && value.isolation_ref.length <= 1000, 'RESOURCE_ISOLATION_REQUIRED', 'resource_lease.isolation_ref 非法');
  const ownerKeys = ['goal_id', 'task_id', 'role', 'thread_id', 'host_id'];
  assertControl(value.owner && Object.keys(value.owner).length === ownerKeys.length && Object.keys(value.owner).every((key) => ownerKeys.includes(key)), 'INVALID_EVIDENCE', 'resource_lease.owner 字段非法');
  for (const key of ownerKeys) assertControl(typeof value.owner[key] === 'string' && value.owner[key].length > 0, 'INVALID_EVIDENCE', `resource_lease.owner.${key} 非法`);
}

function validatePullRequestBinding(value, expected = null) {
  assertControl(value && typeof value === 'object' && !Array.isArray(value), 'PULL_REQUEST_EVIDENCE_MISMATCH', 'evidence 缺结构化 PR binding');
  const keys = ['repository', 'number', 'url', 'base', 'head'];
  assertControl(Object.keys(value).length === keys.length && Object.keys(value).every((key) => keys.includes(key)), 'PULL_REQUEST_EVIDENCE_MISMATCH', 'evidence PR binding 字段非法');
  assertControl(Number.isSafeInteger(value.number) && value.number > 0 && value.base === 'main', 'PULL_REQUEST_EVIDENCE_MISMATCH', 'evidence PR number/base 非法');
  const { parsePullRequestUrl } = require('./validation');
  const parsed = parsePullRequestUrl(value.url, value.repository);
  assertControl(parsed.number === value.number && parsed.url === value.url, 'PULL_REQUEST_EVIDENCE_MISMATCH', 'evidence PR URL/number 不一致');
  assertControl(/^[0-9a-f]{40}$/.test(value.head), 'PULL_REQUEST_EVIDENCE_MISMATCH', 'evidence PR head 非完整 SHA');
  if (expected) assertControl(hashObject(value) === hashObject(expected), 'PULL_REQUEST_EVIDENCE_MISMATCH', 'evidence 绑定了不同 PR');
  return value;
}

function preflightLaunchArtifactFile(root, record) {
  if (!root) return null;
  return path.join(
    root,
    'goals',
    safeId(record.goal_id, 'evidence goal_id'),
    'evidence-artifacts',
    safeId(record.task_id, 'evidence task_id'),
    `${safeId(record.evidence_id, 'evidence_id')}-launch.json`,
  );
}

function controllerAttestedPreflightLaunchFile(record, root = null) {
  let launchSource;
  try {
    launchSource = new URL(record.launch_uri);
  } catch {
    assertControl(false, 'MECHANICAL_ARTIFACT_INVALID', 'PREFLIGHT launch_uri 不是绝对 URL');
  }
  assertControl(launchSource.protocol === 'file:', 'MECHANICAL_ARTIFACT_INVALID', 'PREFLIGHT launch artifact 必须是本地 sealed file');
  const canonicalLaunchFile = fileURLToPath(launchSource);
  const expected = normalizeHash(record.launch_sha256);
  if (
    fs.existsSync(canonicalLaunchFile)
      && fs.statSync(canonicalLaunchFile).isFile()
      && hashFile(canonicalLaunchFile) === expected
  ) {
    return canonicalLaunchFile;
  }
  const immutableArtifact = preflightLaunchArtifactFile(root, record);
  assertControl(
    immutableArtifact
      && fs.existsSync(immutableArtifact)
      && fs.statSync(immutableArtifact).isFile()
      && !fs.lstatSync(immutableArtifact).isSymbolicLink()
      && hashFile(immutableArtifact) === expected,
    'MECHANICAL_ARTIFACT_HASH_MISMATCH',
    'PREFLIGHT launch artifact hash 不匹配，且无 exact immutable evidence artifact',
  );
  return immutableArtifact;
}

function controllerAttestedRuntimeLaunchFile(
  record,
  root = null,
  attestedLaunchFile = null,
  options = {},
) {
  const hasSha = record.runtime_launch_sha256 !== undefined;
  const hasUri = record.runtime_launch_uri !== undefined;
  assertControl(
    hasSha === hasUri,
    'MECHANICAL_ATTESTATION_REQUIRED',
    'PREFLIGHT source checkpoint 必须同时绑定 runtime launch URI 与 SHA',
  );
  assertControl(root, 'MECHANICAL_ARTIFACT_INVALID', 'PREFLIGHT runtime launch 缺 control root');
  const expected = canonicalRuntimeLaunchFile(
    root,
    record.goal_id,
    record.task_id,
    record.launch_id,
  );
  const effectiveLaunchFile = attestedLaunchFile
    || controllerAttestedPreflightLaunchFile(record, root);
  let legacyCanonicalLaunchFile = null;
  try {
    const legacySource = new URL(record.launch_uri);
    if (legacySource.protocol === 'file:') {
      legacyCanonicalLaunchFile = fileURLToPath(legacySource);
    }
  } catch {
    // controllerAttestedPreflightLaunchFile reports the canonical URI error.
  }
  const acceptedLegacyCanonicalReplay =
    options.acceptedReplay === true
      && record.status === 'PASS'
      && !hasSha
      && !hasUri
      && legacyCanonicalLaunchFile
      && path.resolve(legacyCanonicalLaunchFile) === path.resolve(expected)
      && path.resolve(effectiveLaunchFile) === path.resolve(
        preflightLaunchArtifactFile(root, record),
      );
  assertControl(
    record.status !== 'PASS'
      || path.resolve(effectiveLaunchFile) === path.resolve(expected)
      || hasSha
      || acceptedLegacyCanonicalReplay,
    'MECHANICAL_ATTESTATION_REQUIRED',
    'PREFLIGHT PASS source checkpoint 缺 canonical runtime 双绑定',
  );
  if (!hasSha) return null;
  let source;
  try {
    source = new URL(record.runtime_launch_uri);
  } catch {
    assertControl(false, 'MECHANICAL_ARTIFACT_INVALID', 'PREFLIGHT runtime_launch_uri 不是绝对 URL');
  }
  assertControl(
    source.protocol === 'file:',
    'MECHANICAL_ARTIFACT_INVALID',
    'PREFLIGHT runtime launch 必须是本地 sealed file',
  );
  const file = fileURLToPath(source);
  assertControl(
    path.resolve(file) === path.resolve(expected)
      && fs.existsSync(file)
      && fs.statSync(file).isFile()
      && !fs.lstatSync(file).isSymbolicLink()
      && hashFile(file) === normalizeHash(record.runtime_launch_sha256),
    'MECHANICAL_ARTIFACT_HASH_MISMATCH',
    'PREFLIGHT canonical runtime launch 路径或 hash 不匹配',
  );
  return file;
}

function validateControllerAttestation(record, root = null, options = {}) {
  if (!MECHANICAL_EVIDENCE_KINDS.has(record.kind)) return record;
  assertControl(
    record.attestation
      && Object.keys(record.attestation).length === 2
      && record.attestation.controller === 'goalctl'
      && record.attestation.adapter === record.kind,
    'MECHANICAL_ATTESTATION_REQUIRED',
    `${record.kind} evidence 必须由对应 goalctl adapter attested`,
  );
  if (record.kind === 'PREFLIGHT') {
    assertControl(typeof record.launch_sha256 === 'string', 'MECHANICAL_ATTESTATION_REQUIRED', 'PREFLIGHT evidence 缺 launch_sha256');
    normalizeHash(record.launch_sha256, 'launch_sha256');
    assertControl(typeof record.launch_uri === 'string', 'MECHANICAL_ATTESTATION_REQUIRED', 'PREFLIGHT evidence 缺 launch_uri');
    const launchFile = controllerAttestedPreflightLaunchFile(record, root);
    controllerAttestedRuntimeLaunchFile(
      record,
      root,
      launchFile,
      options,
    );
  } else {
    assertControl(typeof record.source_sha256 === 'string', 'MECHANICAL_ATTESTATION_REQUIRED', `${record.kind} evidence 缺 artifact digest`);
    normalizeHash(record.source_sha256, 'source_sha256');
    let artifactSource;
    try {
      artifactSource = new URL(record.uri);
    } catch {
      assertControl(false, 'MECHANICAL_ARTIFACT_INVALID', `${record.kind} artifact URI 非法`);
    }
    assertControl(artifactSource.protocol === 'file:', 'MECHANICAL_ARTIFACT_INVALID', `${record.kind} artifact 必须是本地 sealed file`);
    const artifactFile = fileURLToPath(artifactSource);
    assertControl(fs.existsSync(artifactFile) && fs.statSync(artifactFile).isFile(), 'MECHANICAL_ARTIFACT_MISSING', `${record.kind} artifact 不存在`);
    const { hashFile } = require('./util');
    assertControl(hashFile(artifactFile) === normalizeHash(record.source_sha256), 'MECHANICAL_ARTIFACT_HASH_MISMATCH', `${record.kind} artifact hash 不匹配`);
  }
  return record;
}

function verifySemanticEvidenceSource(record) {
  if (MECHANICAL_EVIDENCE_KINDS.has(record.kind)) return record;
  assertControl(typeof record.source_sha256 === 'string', 'EVIDENCE_SOURCE_HASH_MISSING', `evidence ${record.evidence_id} 缺 source_sha256`);
  const expectedHash = normalizeHash(record.source_sha256, 'source_sha256');
  let source;
  try {
    source = new URL(record.uri);
  } catch {
    assertControl(false, 'EVIDENCE_SOURCE_INVALID', `evidence ${record.evidence_id} source URI 非法`);
  }
  assertControl(
    source.protocol === 'file:',
    'EVIDENCE_HTTPS_REQUIRES_ADAPTER',
    'HTTPS semantic evidence 无法在 replay 时重新取回并验 hash；v1 只接受本地 sealed file',
  );
  const sourceFile = fileURLToPath(source);
  stableSemanticSourceBytes(
    sourceFile,
    expectedHash,
    `evidence ${record.evidence_id} source`,
  );
  return record;
}

function legacySemanticSourceKey(record) {
  return `${record.goal_id}/${record.task_id}/${record.evidence_id}`;
}

function createLegacyEvidenceMigrationCollector() {
  return {
    eventBindings: new Map(),
    semanticSources: new Map(),
  };
}

function eventBindingCollector(collector) {
  if (collector instanceof Map) return collector;
  assertControl(
    collector
      && collector.eventBindings instanceof Map
      && collector.semanticSources instanceof Map,
    'INVALID_LEGACY_EVIDENCE_ANCHORS',
    'legacy evidence migration collector 格式非法',
  );
  return collector.eventBindings;
}

function collectLegacySemanticSource(collector, record, sourceBytes) {
  assertControl(
    collector && collector.semanticSources instanceof Map,
    'INVALID_LEGACY_EVIDENCE_ANCHORS',
    'legacy semantic source collector 缺失',
  );
  assertControl(
    sourceBytes.length <= LEGACY_SEMANTIC_SOURCE_MAX_BYTES,
    'LEGACY_EVIDENCE_SOURCE_TOO_LARGE',
    `legacy semantic evidence ${record.evidence_id} 超过 16MiB`,
  );
  const key = legacySemanticSourceKey(record);
  const entry = {
    goal_id: record.goal_id,
    task_id: record.task_id,
    evidence_id: record.evidence_id,
    registry_sha256: normalizeHash(record.registry_sha256, 'registry_sha256'),
    source_sha256: normalizeHash(record.source_sha256, 'source_sha256'),
    source_bytes: Buffer.from(sourceBytes),
  };
  const existing = collector.semanticSources.get(key);
  assertControl(
    !existing
      || (
        existing.registry_sha256 === entry.registry_sha256
        && existing.source_sha256 === entry.source_sha256
        && existing.source_bytes.equals(entry.source_bytes)
      ),
    'EVIDENCE_ID_CONFLICT',
    `legacy semantic evidence ${record.evidence_id} source collector 冲突`,
  );
  collector.semanticSources.set(key, entry);
  assertControl(
    collector.semanticSources.size <= LEGACY_SEMANTIC_SOURCE_MAX_COUNT,
    'LEGACY_EVIDENCE_SOURCE_LIMIT',
    `legacy semantic evidence 数量超过 ${LEGACY_SEMANTIC_SOURCE_MAX_COUNT}`,
  );
}

function collectLegacySemanticEvidenceSources(root, collector) {
  eventBindingCollector(collector);
  const goalsDir = path.join(root, 'goals');
  if (!fs.existsSync(goalsDir)) return collector;
  for (const goalId of fs.readdirSync(goalsDir).sort()) {
    const evidenceDir = path.join(goalsDir, goalId, 'evidence');
    if (!fs.existsSync(evidenceDir) || !fs.statSync(evidenceDir).isDirectory()) continue;
    for (const taskId of fs.readdirSync(evidenceDir).sort()) {
      const taskDir = path.join(evidenceDir, taskId);
      if (!fs.statSync(taskDir).isDirectory()) continue;
      for (const name of fs.readdirSync(taskDir).filter((candidate) => candidate.endsWith('.json')).sort()) {
        const file = path.join(taskDir, name);
        const record = sealOrVerifyRecord(file, readJson(file, `legacy evidence ${goalId}/${taskId}/${name}`));
        if (MECHANICAL_EVIDENCE_KINDS.has(record.kind)) continue;
        verifySemanticEvidenceSource(record);
        collectLegacySemanticSource(
          collector,
          record,
          fs.readFileSync(fileURLToPath(new URL(record.uri))),
        );
      }
    }
  }
  return collector;
}

function durableSemanticEvidenceTarget(root, record) {
  const expectedHash = normalizeHash(record.source_sha256, 'source_sha256');
  const digest = expectedHash.slice('sha256:'.length);
  const targetDir = path.join(
    root,
    'goals',
    safeId(record.goal_id, 'goal_id'),
    'evidence-sources',
    safeId(record.task_id, 'task_id'),
  );
  return path.join(
    targetDir,
    `${safeId(record.evidence_id, 'evidence_id')}-${digest}.artifact`,
  );
}

function stableSemanticSourceBytes(sourceFile, expectedHash, label) {
  let before;
  try {
    before = fs.lstatSync(sourceFile);
  } catch (error) {
    throw new ControlError(
      'EVIDENCE_SOURCE_MISSING',
      `${label} 不存在: ${error.message}`,
    );
  }
  assertControl(
    before.isFile() && !before.isSymbolicLink(),
    'EVIDENCE_SOURCE_TYPE_INVALID',
    `${label} 必须是非 symlink 普通文件`,
  );
  assertControl(
    before.size <= SEMANTIC_SOURCE_MAX_BYTES,
    'EVIDENCE_SOURCE_TOO_LARGE',
    `${label} 超过 ${SEMANTIC_SOURCE_MAX_BYTES} bytes`,
  );
  const bytes = fs.readFileSync(sourceFile);
  const after = fs.lstatSync(sourceFile);
  assertControl(
    after.isFile()
      && !after.isSymbolicLink()
      && before.dev === after.dev
      && before.ino === after.ino
      && before.size === after.size
      && before.mtimeMs === after.mtimeMs
      && bytes.length === before.size,
    'EVIDENCE_SOURCE_CHANGED',
    `${label} 在读取期间发生变化`,
  );
  assertControl(
    `sha256:${sha256(bytes)}` === expectedHash,
    'EVIDENCE_SOURCE_HASH_MISMATCH',
    `${label} hash 不匹配`,
  );
  return bytes;
}

function validatedSemanticSourceBytes(sourceBytes, expectedHash, label) {
  assertControl(
    Buffer.isBuffer(sourceBytes),
    'INVALID_EVIDENCE',
    `${label} 必须是 Buffer`,
  );
  assertControl(
    sourceBytes.length <= SEMANTIC_SOURCE_MAX_BYTES,
    'EVIDENCE_SOURCE_TOO_LARGE',
    `${label} 超过 ${SEMANTIC_SOURCE_MAX_BYTES} bytes`,
  );
  assertControl(
    `sha256:${sha256(sourceBytes)}` === expectedHash,
    'EVIDENCE_SOURCE_HASH_MISMATCH',
    `${label} hash 不匹配`,
  );
  return sourceBytes;
}

function durableSemanticEvidenceSource(root, record) {
  if (MECHANICAL_EVIDENCE_KINDS.has(record.kind)) return record;
  verifySemanticEvidenceSource(record);
  const sourceFile = fileURLToPath(new URL(record.uri));
  const expectedHash = normalizeHash(record.source_sha256, 'source_sha256');
  const targetFile = durableSemanticEvidenceTarget(root, record);
  const targetDir = path.dirname(targetFile);
  ensureDir(targetDir);
  if (fs.existsSync(targetFile)) {
    const targetStat = fs.lstatSync(targetFile);
    assertControl(
      targetStat.isFile() && !targetStat.isSymbolicLink(),
      'CORRUPT_STORE',
      `durable evidence source ${record.evidence_id} 不是普通文件`,
    );
    stableSemanticSourceBytes(
      targetFile,
      expectedHash,
      `durable evidence source ${record.evidence_id}`,
    );
  } else {
    const bytes = stableSemanticSourceBytes(
      sourceFile,
      expectedHash,
      `evidence source ${record.evidence_id}`,
    );
    atomicWrite(targetFile, bytes);
    assertControl(
      hashFile(targetFile) === expectedHash,
      'CORRUPT_STORE',
      `durable evidence source ${record.evidence_id} 持久化后 hash 不匹配`,
    );
  }
  return {
    ...record,
    uri: pathToFileURL(targetFile).href,
  };
}

function durableSemanticEvidenceSourceBytes(root, record, sourceBytes) {
  assertControl(
    !MECHANICAL_EVIDENCE_KINDS.has(record.kind),
    'INVALID_EVIDENCE',
    'mechanical evidence 不接受 in-memory semantic source',
  );
  const expectedHash = normalizeHash(record.source_sha256, 'source_sha256');
  const bytes = validatedSemanticSourceBytes(
    sourceBytes,
    expectedHash,
    `evidence source ${record.evidence_id}`,
  );
  const targetFile = durableSemanticEvidenceTarget(root, record);
  assertControl(
    record.uri === pathToFileURL(targetFile).href,
    'CORRUPT_STORE',
    `evidence ${record.evidence_id} in-memory source 未绑定 durable target`,
  );
  ensureDir(path.dirname(targetFile));
  if (fs.existsSync(targetFile)) {
    stableSemanticSourceBytes(
      targetFile,
      expectedHash,
      `durable evidence source ${record.evidence_id}`,
    );
  } else {
    atomicWrite(targetFile, bytes);
    assertControl(
      hashFile(targetFile) === expectedHash,
      'CORRUPT_STORE',
      `durable evidence source ${record.evidence_id} 持久化后 hash 不匹配`,
    );
  }
  return record;
}

function bindSemanticEvidenceSourceBytes(root, raw, sourceBytes) {
  assertControl(
    raw && typeof raw === 'object' && !Array.isArray(raw),
    'INVALID_EVIDENCE',
    'in-memory evidence 必须是对象',
  );
  const expectedHash = normalizeHash(raw.source_sha256, 'source_sha256');
  const bytes = validatedSemanticSourceBytes(
    sourceBytes,
    expectedHash,
    `evidence source ${raw.evidence_id || 'unknown'}`,
  );
  const targetFile = durableSemanticEvidenceTarget(root, raw);
  return {
    evidence: {
      ...raw,
      uri: pathToFileURL(targetFile).href,
    },
    sourceBytes: bytes,
    targetFile,
  };
}

function semanticIngressPreparedFile(root, goalId, taskId, evidenceId) {
  return path.join(
    root,
    'goals',
    safeId(goalId, 'goal_id'),
    'evidence-ingress',
    safeId(taskId, 'task_id'),
    `${safeId(evidenceId, 'evidence_id')}.json`,
  );
}

function sealSemanticIngressPrepared(value) {
  return {
    ...value,
    prepared_sha256: hashObject(value),
  };
}

function readSemanticIngressPrepared(file) {
  const prepared = readJson(file, `prepared evidence ingress ${path.basename(file)}`);
  const unsigned = { ...prepared };
  delete unsigned.prepared_sha256;
  assertControl(
    prepared
      && prepared.schema_version === 1
      && prepared.prepared_sha256 === hashObject(unsigned)
      && prepared.evidence
      && prepared.producer_authority
      && prepared.source,
    'CORRUPT_STORE',
    `prepared evidence ingress ${path.basename(file)} seal 非法`,
  );
  return prepared;
}

function validatePreparedSemanticIngress(
  root,
  prepared,
  raw,
  actorCapabilityFile,
  controller,
) {
  assertControl(
    prepared.goal_id === raw.goal_id
      && prepared.task_id === raw.task_id
      && prepared.evidence_id === raw.evidence_id
      && prepared.controller === controller
      && prepared.ingress_sha256 === hashObject(raw),
    'EVIDENCE_ID_CONFLICT',
    `evidence id ${raw.evidence_id} 已绑定不同 prepared ingress`,
    {
      prepared_goal_id: prepared.goal_id,
      requested_goal_id: raw.goal_id,
      prepared_task_id: prepared.task_id,
      requested_task_id: raw.task_id,
      prepared_evidence_id: prepared.evidence_id,
      requested_evidence_id: raw.evidence_id,
      prepared_controller: prepared.controller,
      requested_controller: controller,
      prepared_ingress_sha256: prepared.ingress_sha256,
      requested_ingress_sha256: hashObject(raw),
      differing_evidence_fields: [...new Set([
        ...Object.keys(prepared.evidence || {}),
        ...Object.keys(raw || {}),
      ])].sort().filter((key) => (
        hashObject(prepared.evidence && prepared.evidence[key])
          !== hashObject(raw && raw[key])
      )),
    },
  );
  const { loadGoalStateUnlocked } = require('./goal');
  const loaded = loadGoalStateUnlocked(
    root,
    prepared.goal_id,
    {
      repairHeads: false,
      repairBootstrapConsumption: false,
    },
  );
  const state = loaded.snapshot.tasks[prepared.task_id];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${prepared.task_id}`);
  const session = exactHistoricalEvidenceSession(
    state,
    prepared.evidence,
    actorCapabilityFile,
    loaded.snapshot,
  );
  const authority = prepared.producer_authority;
  assertControl(
    authority.role === session.role
      && authority.thread_id === session.thread_id
      && authority.host_id === session.host_id
      && authority.attempt === session.attempt
      && authority.capability_file === session.capability_file
      && hashesEqual(authority.capability_sha256, session.capability_sha256),
    'CORRUPT_STORE',
    `prepared evidence ${prepared.evidence_id} producer authority 漂移`,
  );
  validateAcceptanceAnchor(prepared.evidence, state, session);
  assertControl(
    prepared.evidence.state_revision === state.state_revision
      && prepared.evidence.packet
      && prepared.evidence.packet.revision === state.packet.revision
      && normalizeHash(prepared.evidence.packet.sha256) === state.packet.sha256
      && normalizeHash(prepared.evidence.packet_sha256) === state.packet.sha256
      && prepared.evidence.base_head === state.base_head
      && prepared.evidence.full_head === state.full_head,
    'STALE_EVIDENCE',
    `prepared evidence ${prepared.evidence_id} task/packet/HEAD anchor 已漂移`,
  );
  const expectedTarget = durableSemanticEvidenceTarget(root, prepared.evidence);
  assertControl(
    prepared.source.sha256 === normalizeHash(prepared.evidence.source_sha256)
      && prepared.source.target_file === expectedTarget
      && prepared.evidence.uri === pathToFileURL(expectedTarget).href,
    'CORRUPT_STORE',
    `prepared evidence ${prepared.evidence_id} source binding 漂移`,
  );
  return { loaded, state, session, targetFile: expectedTarget };
}

function maybeFaultAfterSemanticSourcePublish(cwd) {
  if (
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_SOURCE_PUBLISH !== '1'
  ) {
    return;
  }
  const { assertIsolatedTestMode } = require('./util');
  assertIsolatedTestMode(cwd);
  throw new ControlError(
    'TEST_FAULT_AFTER_SEMANTIC_SOURCE_PUBLISH',
    'injected failure after durable semantic source before evidence registry',
  );
}

function maybeFaultAfterSemanticIngressPrepared(
  cwd,
  pendingAuthorization,
) {
  if (
    typeof pendingAuthorization.afterSemanticIngressPrepared === 'function'
  ) {
    const { assertIsolatedTestMode } = require('./util');
    assertIsolatedTestMode(cwd);
    pendingAuthorization.afterSemanticIngressPrepared();
  }
  const mode =
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_INGRESS_PREPARED;
  if (mode === undefined || mode === '') return;
  assertControl(
    ['1', 'throw', 'exit', 'sigkill'].includes(mode),
    'INVALID_TEST_FAULT',
    'GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_INGRESS_PREPARED '
      + '只能是 1/throw/exit/sigkill',
  );
  const { assertIsolatedTestMode } = require('./util');
  assertIsolatedTestMode(cwd);
  if (mode === 'sigkill') {
    process.kill(process.pid, 'SIGKILL');
    return;
  }
  if (mode === 'exit') process.exit(110);
  throw new ControlError(
    'TEST_FAULT_AFTER_SEMANTIC_INGRESS_PREPARED',
    'injected failure after prepared semantic ingress before source publish',
  );
}

function evidenceAcceptanceAnchor(state, session) {
  return {
    schema_version: 1,
    state_revision: state.state_revision,
    control_epoch: state.control_epoch,
    phase: state.phase,
    task_cycle: state.task_cycle,
    producer: {
      role: session.role,
      thread_id: session.thread_id,
      host_id: session.host_id,
      attempt: session.attempt,
      launch_id: session.launch_id || null,
      source_task_id: session.task_id || state.task_id,
      capability_file: session.capability_file,
      capability_sha256: session.capability_sha256,
    },
  };
}

function validateAcceptanceAnchor(record, state, session) {
  const anchor = record.acceptance_anchor;
  if (!anchor) return false;
  const allowedAnchorKeys = [
    'schema_version',
    'state_revision',
    'control_epoch',
    'phase',
    'task_cycle',
    'producer',
  ];
  assertControl(
    anchor
      && typeof anchor === 'object'
      && !Array.isArray(anchor)
      && Object.keys(anchor).length === allowedAnchorKeys.length
      && Object.keys(anchor).every((key) => allowedAnchorKeys.includes(key)),
    'CORRUPT_STORE',
    `evidence ${record.evidence_id} acceptance_anchor 字段非法`,
  );
  const expected = evidenceAcceptanceAnchor(
    {
      state_revision: record.state_revision,
      control_epoch: anchor.control_epoch,
      phase: anchor.phase,
      task_cycle: anchor.task_cycle,
    },
    {
      role: record.producer.role,
      thread_id: record.producer.thread_id,
      host_id: record.producer.host_id || 'local',
      attempt: anchor.producer && anchor.producer.attempt,
      launch_id: anchor.producer && anchor.producer.launch_id,
      task_id: anchor.producer && anchor.producer.source_task_id,
      capability_file: anchor.producer && anchor.producer.capability_file,
      capability_sha256: anchor.producer && anchor.producer.capability_sha256,
    },
  );
  assertControl(
    hashObject(anchor) === hashObject(expected),
    'CORRUPT_STORE',
    `evidence ${record.evidence_id} acceptance_anchor 与 registry 身份不一致`,
  );
  assertControl(
    anchor.control_epoch === state.control_epoch
      && anchor.phase === state.phase
      && anchor.task_cycle === state.task_cycle,
    'STALE_EVIDENCE',
    `evidence ${record.evidence_id} material state 已变化`,
  );
  assertControl(
    anchor.producer.role === session.role
      && anchor.producer.thread_id === session.thread_id
      && anchor.producer.host_id === session.host_id
      && anchor.producer.attempt === session.attempt
      && anchor.producer.launch_id === (session.launch_id || null)
      && (
        anchor.producer.source_task_id === undefined
          || anchor.producer.source_task_id === (session.task_id || state.task_id)
      )
      && (
        anchor.producer.capability_file === undefined
          || anchor.producer.capability_file === session.capability_file
      )
      && (
        anchor.producer.capability_sha256 === undefined
          || hashesEqual(
            anchor.producer.capability_sha256,
            session.capability_sha256,
          )
      ),
    'STALE_EVIDENCE',
    `evidence ${record.evidence_id} producer session 已变化`,
  );
  return true;
}

function assertOnlyBenignHeartbeatsSince(root, record, state) {
  assertControl(
    Number.isSafeInteger(record.state_revision)
      && record.state_revision >= 0
      && record.state_revision <= state.state_revision,
    'STALE_EVIDENCE',
    `evidence ${record.evidence_id} state revision 非法`,
  );
  if (record.state_revision === state.state_revision) return;
  const files = acceptedEventFiles(root, record.goal_id, record.task_id);
  assertControl(
    files.length >= state.state_revision,
    'CORRUPT_STORE',
    `task ${record.task_id} event tail 短于 state revision`,
  );
  for (let revision = record.state_revision + 1; revision <= state.state_revision; revision += 1) {
    const accepted = readJson(files[revision - 1], `event revision ${revision}`);
    assertControl(
      accepted.log_sequence === revision
        && accepted.type === 'HEARTBEAT'
        && (!accepted.payload.status || ['active', 'idle'].includes(accepted.payload.status)),
      'STALE_EVIDENCE',
      `evidence ${record.evidence_id} 后存在非 benign HEARTBEAT 的 state revision ${revision}`,
    );
  }
}

function evidenceFile(root, goalId, taskId, evidenceId) {
  safeId(evidenceId, 'evidence_id');
  return path.join(root, 'goals', goalId, 'evidence', taskId, `${evidenceId}.json`);
}

function sealOrVerifyRecord(file, record) {
  const unsigned = { ...record };
  delete unsigned.registry_sha256;
  const digest = hashObject(unsigned);
  assertControl(typeof record.registry_sha256 === 'string', 'EVIDENCE_NOT_REGISTERED', `evidence ${record.evidence_id} 未由控制面 seal`);
  assertControl(record.registry_sha256 === digest, 'CORRUPT_STORE', `evidence ${record.evidence_id} registry hash 不匹配`);
  return record;
}

function exactHistoricalEvidenceSession(
  state,
  record,
  actorCapabilityFile,
  snapshot = null,
) {
  const anchor = record.acceptance_anchor;
  const allowedAnchorKeys = [
    'schema_version',
    'state_revision',
    'control_epoch',
    'phase',
    'task_cycle',
    'producer',
  ];
  assertControl(
    anchor
      && typeof anchor === 'object'
      && !Array.isArray(anchor)
      && Object.keys(anchor).length === allowedAnchorKeys.length
      && Object.keys(anchor).every((key) => allowedAnchorKeys.includes(key))
      && anchor.schema_version === 1
      && anchor.producer
      && typeof anchor.producer === 'object',
    'CORRUPT_STORE',
    `evidence ${record.evidence_id} acceptance_anchor 字段非法`,
  );
  const expectedAnchor = evidenceAcceptanceAnchor(
    {
      state_revision: record.state_revision,
      control_epoch: anchor.control_epoch,
      phase: anchor.phase,
      task_cycle: anchor.task_cycle,
    },
    {
      role: record.producer.role,
      thread_id: record.producer.thread_id,
      host_id: record.producer.host_id || 'local',
      attempt: anchor.producer.attempt,
      launch_id: anchor.producer.launch_id,
      task_id: anchor.producer.source_task_id,
      capability_file: anchor.producer.capability_file,
      capability_sha256: anchor.producer.capability_sha256,
    },
  );
  assertControl(
    hashObject(anchor) === hashObject(expectedAnchor),
    'CORRUPT_STORE',
    `evidence ${record.evidence_id} acceptance_anchor 与 registry 身份不一致`,
  );
  const supplied = readCapabilityFile(actorCapabilityFile);
  const states = record.producer.role === 'FOREMAN' && snapshot
    ? Object.values(snapshot.tasks || {})
    : [state];
  const sessions = states.flatMap((candidateState) => [
    ...Object.values(candidateState.sessions || {}).map((session) => ({
      ...session,
      task_id: candidateState.task_id,
    })),
    ...Object.values(candidateState.session_history || {})
      .flat()
      .map((session) => ({
        ...session,
        task_id: candidateState.task_id,
      })),
  ]);
  const session = sessions.find((candidate) => (
    candidate
      && candidate.role === record.producer.role
      && candidate.thread_id === record.producer.thread_id
      && candidate.host_id === (record.producer.host_id || 'local')
      && candidate.attempt === anchor.producer.attempt
      && (candidate.launch_id || null) === anchor.producer.launch_id
      && (
        anchor.producer.source_task_id === undefined
          || candidate.task_id === anchor.producer.source_task_id
      )
      && (
        anchor.producer.capability_file === undefined
          || candidate.capability_file === anchor.producer.capability_file
      )
      && (
        anchor.producer.capability_sha256 === undefined
          || hashesEqual(
            candidate.capability_sha256,
            anchor.producer.capability_sha256,
          )
      )
      && candidate.capability_file === supplied.file
      && hashesEqual(candidate.capability_sha256, supplied.sha256)
  ));
  assertControl(
    session,
    'CAPABILITY_INVALID',
    `capability 不属于 evidence ${record.evidence_id} 的原始历史 producer`,
  );
  return session;
}

function readExistingEvidenceForRetryUnderLock(cwd, options) {
  const { loadGoalStateUnlocked } = require('./goal');
  const { controlRoot } = require('./util');
  const root = controlRoot(cwd);
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const evidenceId = safeId(options.evidenceId, 'evidence_id');
  const file = evidenceFile(root, goalId, taskId, evidenceId);
  if (!fs.existsSync(file)) return null;
  const record = sealOrVerifyRecord(
    file,
    readJson(file, `evidence ${evidenceId}`),
  );
  assertControl(
    record
      && record.schema_version === 1
      && record.evidence_id === evidenceId
      && record.goal_id === goalId
      && record.task_id === taskId,
    'CORRUPT_STORE',
    `evidence ${evidenceId} registry 身份非法`,
  );
  const loaded = loadGoalStateUnlocked(root, goalId, {
    repairHeads: false,
    repairBootstrapConsumption: false,
  });
  const state = loaded.snapshot.tasks[taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
  const session = exactHistoricalEvidenceSession(
    state,
    record,
    options.actorCapabilityFile,
    loaded.snapshot,
  );
  validateControllerAttestation(record, root);
  verifyReplaySemanticEvidenceSource(root, record);
  return {
    evidence: record,
    evidence_file: file,
    session,
    state,
    loaded,
  };
}

function readExistingEvidenceForRetry(cwd, options) {
  const { controlRoot } = require('./util');
  const root = controlRoot(cwd);
  return withStableRead(root, () => readExistingEvidenceForRetryUnderLock(
    cwd,
    options,
  ));
}

function resolveTrustedEvidence(root, state, reference, expected) {
  assertControl(typeof reference === 'string', 'EVIDENCE_NOT_REGISTERED', 'evidence 必须引用 registry ID，不能内联 PASS 对象');
  const file = evidenceFile(root, expected.goalId, state.task_id, reference);
  assertControl(fs.existsSync(file), 'EVIDENCE_NOT_REGISTERED', `evidence ${reference} 未登记`);
  const record = sealOrVerifyRecord(file, readJson(file, `evidence ${reference}`));
  assertControl(record && typeof record === 'object' && record.schema_version === 1, 'EVIDENCE_NOT_REGISTERED', `evidence ${reference} 格式非法`);
  assertControl(record.evidence_id === reference && record.goal_id === expected.goalId && record.task_id === state.task_id, 'EVIDENCE_NOT_REGISTERED', `evidence ${reference} 身份不匹配`);
  assertControl(record.kind === expected.kind, 'EVIDENCE_KIND_MISMATCH', `evidence ${reference} kind=${record.kind}，期望 ${expected.kind}`);
  validateControllerAttestation(record, root, {
    acceptedReplay: expected.acceptedReplay === true,
  });
  verifyReplaySemanticEvidenceSource(root, record, {
    allowIdentityIncidentRotationReceipt:
      expected.acceptedReplay === true
        && expected.kind === 'HOLD_ASSERTION',
  });
  assertControl(record.status === (expected.status || 'PASS'), 'EVIDENCE_STATUS_MISMATCH', `evidence ${reference} status=${record.status}`);
  const allowedProducers = EXPECTED_PRODUCER[record.kind] || [];
  assertControl(record.producer && allowedProducers.includes(record.producer.role), 'EVIDENCE_PRODUCER_MISMATCH', `evidence ${reference} producer=${record.producer && record.producer.role}`);
  if (expected.producerRole) assertControl(record.producer.role === expected.producerRole, 'EVIDENCE_PRODUCER_MISMATCH', `evidence ${reference} producer role 不匹配`);
  const session = state.sessions[record.producer.role];
  assertControl(session && session.thread_id === record.producer.thread_id && session.host_id === (record.producer.host_id || 'local'), 'EVIDENCE_PRODUCER_MISMATCH', `evidence ${reference} producer session 不匹配`);
  if (record.state_revision !== state.state_revision) {
    assertControl(
      validateAcceptanceAnchor(record, state, session),
      'STALE_EVIDENCE',
      `evidence ${reference} state revision 陈旧且缺 acceptance anchor`,
    );
    assertOnlyBenignHeartbeatsSince(root, record, state);
  } else if (record.acceptance_anchor) {
    validateAcceptanceAnchor(record, state, session);
  }
  assertControl(record.packet && record.packet.revision === state.packet.revision, 'STALE_EVIDENCE', `evidence ${reference} packet revision 陈旧`);
  assertControl(normalizeHash(record.packet.sha256) === state.packet.sha256, 'STALE_EVIDENCE', `evidence ${reference} packet hash 陈旧`);
  assertControl(normalizeHash(record.packet_sha256) === state.packet.sha256, 'STALE_EVIDENCE', `evidence ${reference} direct packet hash 陈旧`);
  assertControl(record.base_head === state.base_head, 'STALE_EVIDENCE', `evidence ${reference} base HEAD 陈旧`);
  assertControl(record.full_head === expected.fullHead, 'STALE_EVIDENCE', `evidence ${reference} full HEAD 陈旧`);
  if (expected.pullRequest) validatePullRequestBinding(record.pull_request, expected.pullRequest);
  if (record.kind === 'PREFLIGHT') {
    const launchFile = controllerAttestedPreflightLaunchFile(record, root);
    const { validateLaunchManifest } = require('./validation');
    const launch = validateLaunchManifest(readJson(launchFile, `preflight launch ${record.launch_id}`));
    const runtimeLaunchFile = controllerAttestedRuntimeLaunchFile(
      record,
      root,
      launchFile,
      {
        acceptedReplay: expected.acceptedReplay === true,
      },
    );
    if (
      expected.requireSourceCheckpointRuntimeBinding === true
        && expected.acceptedReplay !== true
        && path.resolve(launchFile) !== path.resolve(
          canonicalRuntimeLaunchFile(
            root,
            record.goal_id,
            record.task_id,
            record.launch_id,
          ),
        )
    ) {
      assertControl(
        runtimeLaunchFile,
        'MECHANICAL_ATTESTATION_REQUIRED',
        '当前 source checkpoint PREFLIGHT 必须双绑定 canonical runtime launch',
      );
    }
    if (runtimeLaunchFile) {
      const runtimeLaunch = validateLaunchManifest(
        readJson(runtimeLaunchFile, `runtime launch ${record.launch_id}`),
      );
      assertSourceCheckpointAdvance(runtimeLaunch, launch, {
        verifyAncestry: false,
      });
      assertControl(
        path.resolve(launchFile)
          === path.resolve(preflightLaunchArtifactFile(root, record)),
        'MECHANICAL_ARTIFACT_INVALID',
        'PREFLIGHT source checkpoint candidate 必须使用 deterministic evidence artifact',
      );
    }
    assertControl(launch.goal_id === record.goal_id && launch.task_id === record.task_id, 'PREFLIGHT_LAUNCH_MISMATCH', 'PREFLIGHT launch goal/task 不匹配');
    assertControl(launch.role === record.producer.role && launch.thread.id === record.producer.thread_id, 'PREFLIGHT_LAUNCH_MISMATCH', 'PREFLIGHT launch producer 不匹配');
    assertControl((launch.thread.host_id || 'local') === (record.producer.host_id || 'local'), 'PREFLIGHT_LAUNCH_MISMATCH', 'PREFLIGHT launch host 不匹配');
    assertControl(launch.launch_id === record.launch_id, 'PREFLIGHT_LAUNCH_MISMATCH', 'PREFLIGHT launch_id 不匹配');
    assertControl(launch.packet.revision === state.packet.revision && normalizeHash(launch.packet.sha256) === state.packet.sha256, 'STALE_EVIDENCE', 'PREFLIGHT launch packet 陈旧');
    assertControl(launch.repository.base_head === state.base_head && launch.repository.full_head === record.full_head, 'STALE_EVIDENCE', 'PREFLIGHT launch HEAD 陈旧');
    assertControl(session.launch_id === launch.launch_id && session.task_nonce === launch.execution.task_nonce, 'PREFLIGHT_LAUNCH_MISMATCH', 'PREFLIGHT launch 未绑定当前 session');
    assertLaunchRuntimeIncarnation(session, launch);
    if (expected.allowRuntimeRotationHold === true) {
      assertControl(
        isRuntimeRotationHoldLane(state, session, launch),
        'RUNTIME_PREFLIGHT_BINDING_MISMATCH',
        'PREFLIGHT evidence 未绑定当前 runtime rotation hold/successor',
      );
    }
    if (record.producer.role === 'DEV') {
      if (expected.readOnly === true) {
        assertDevCandidateReplayLineage(
          launch,
          state,
          state.sessions.DEV,
          record.full_head,
          { allowPreflightOnly: expected.allowPreflightOnly === true },
        );
      } else {
        assertDevCandidateLineage(
          launch.repository.worktree,
          state,
          state.sessions.DEV,
          record.full_head,
          { allowPreflightOnly: expected.allowPreflightOnly === true },
        );
      }
    } else if (['REVIEW', 'RECEIPT'].includes(record.producer.role)) {
      const expectedPhase = `${record.producer.role}_ACTIVE`;
      assertControl(
        state.phase === expectedPhase
          && record.full_head === state.full_head
          && launch.repository.full_head === state.full_head,
        'STALE_EVIDENCE',
        `${record.producer.role} PREFLIGHT 必须精确绑定当前 task full HEAD`,
      );
      if (expected.readOnly !== true) {
        assertControl(
          git(
            launch.repository.worktree,
            ['rev-parse', 'HEAD'],
          ) === state.full_head,
          'STALE_EVIDENCE',
          `${record.producer.role} PREFLIGHT worktree HEAD 与 task full HEAD 不一致`,
        );
      }
    } else {
      assertControl(
        false,
        'EVIDENCE_PRODUCER_MISMATCH',
        `${record.producer.role} PREFLIGHT 无 worker HEAD 校验策略`,
      );
    }
    assertControl(expected.manifestTask, 'UNKNOWN_TASK', `PREFLIGHT evidence 缺 manifest task ${launch.task_id}`);
    const { verifyLaunchResourceRequirementsUnlocked } = require('./resources');
    verifyLaunchResourceRequirementsUnlocked(
      root,
      expected.manifestTask,
      launch,
      state,
      {
        repairHeads: expected.readOnly !== true,
        historical: expected.readOnly === true || expected.acceptedReplay === true,
        allowRuntimeRotationHold: expected.allowRuntimeRotationHold === true,
      },
    );
  }
  assertControl(typeof record.uri === 'string' && record.uri.length > 0, 'EVIDENCE_NOT_REGISTERED', `evidence ${reference} source URI 缺失`);
  return record;
}

function eventEvidenceRegistryDigest(preparedEvent) {
  const bindings = {};
  const visit = (value) => {
    if (Array.isArray(value)) {
      for (const child of value) visit(child);
      return;
    }
    if (!value || typeof value !== 'object') return;
    if (
      typeof value.evidence_id === 'string'
        && typeof value.registry_sha256 === 'string'
    ) {
      const digest = normalizeHash(value.registry_sha256, 'registry_sha256');
      assertControl(
        !bindings[value.evidence_id] || bindings[value.evidence_id] === digest,
        'CORRUPT_STORE',
        `event 同一 evidence ${value.evidence_id} 出现不同 registry digest`,
      );
      bindings[value.evidence_id] = digest;
      return;
    }
    for (const child of Object.values(value)) visit(child);
  };
  visit(preparedEvent.payload);
  return Object.keys(bindings).length > 0 ? hashObject(bindings) : null;
}

function bindAcceptedEventEvidence(event, preparedEvent) {
  const digest = eventEvidenceRegistryDigest(preparedEvent);
  if (digest) event.evidence_registry_sha256 = digest;
  return digest;
}

const LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH = '.legacy-evidence-anchors.v1.json';

function legacyEvidenceAnchorFile(root) {
  return path.join(root, LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH);
}

function legacyEventAnchorKey(event) {
  return `${event.goal_id}/${event.task_id}/${event.event_id}`;
}

function legacyEventAnchorEntry(event, digest) {
  return {
    goal_id: event.goal_id,
    task_id: event.task_id,
    event_id: event.event_id,
    input_sha256: normalizeHash(event.input_sha256, 'event.input_sha256'),
    event_sha256: normalizeHash(event.event_sha256, 'event.event_sha256'),
    evidence_registry_sha256: normalizeHash(digest, 'event evidence registry digest'),
  };
}

function validateGoalWorktreeMapReceipt(receipt) {
  const keys = [
    'schema_version',
    'mode',
    'mapping_file',
    'mapping_file_sha256',
    'goal_worktrees',
    'goal_worktrees_sha256',
  ];
  assertControl(
    receipt
      && typeof receipt === 'object'
      && !Array.isArray(receipt)
      && Object.keys(receipt).length === keys.length
      && Object.keys(receipt).every((key) => keys.includes(key))
      && receipt.schema_version === 1
      && ['SINGLE_DEFAULT', 'EXPLICIT_MAP'].includes(receipt.mode)
      && Array.isArray(receipt.goal_worktrees),
    'CORRUPT_STORE',
    'legacy migration goal worktree map receipt 格式非法',
  );
  if (receipt.mode === 'EXPLICIT_MAP') {
    assertControl(
      typeof receipt.mapping_file === 'string'
        && path.isAbsolute(receipt.mapping_file)
        && path.resolve(receipt.mapping_file) === receipt.mapping_file
        && typeof receipt.mapping_file_sha256 === 'string',
      'CORRUPT_STORE',
      'explicit Goal worktree map receipt 缺 canonical mapping file identity',
    );
    normalizeHash(receipt.mapping_file_sha256, 'goal worktree mapping file sha256');
  } else {
    assertControl(
      receipt.mapping_file === null && receipt.mapping_file_sha256 === null,
      'CORRUPT_STORE',
      'single-default Goal worktree receipt 不得携带 mapping file',
    );
  }
  const seen = new Set();
  let previousGoalId = null;
  for (const binding of receipt.goal_worktrees) {
    const bindingKeys = [
      'goal_id',
      'repository_worktree',
      'repository_common_dir',
      'repository_head',
      'manifest_sha256',
      'frozen_inputs_sha256',
      'worktree_identity_sha256',
    ];
    assertControl(
      binding
        && typeof binding === 'object'
        && !Array.isArray(binding)
        && Object.keys(binding).length === bindingKeys.length
        && Object.keys(binding).every((key) => bindingKeys.includes(key))
        && typeof binding.goal_id === 'string'
        && !seen.has(binding.goal_id)
        && typeof binding.repository_worktree === 'string'
        && path.isAbsolute(binding.repository_worktree)
        && path.resolve(binding.repository_worktree) === binding.repository_worktree
        && typeof binding.repository_common_dir === 'string'
        && path.isAbsolute(binding.repository_common_dir)
        && path.resolve(binding.repository_common_dir) === binding.repository_common_dir
        && typeof binding.repository_head === 'string'
        && /^[0-9a-f]{40}$/.test(binding.repository_head),
      'CORRUPT_STORE',
      'legacy migration Goal worktree binding 格式非法',
    );
    safeId(binding.goal_id, 'legacy migration goal_id');
    assertControl(
      previousGoalId === null || previousGoalId.localeCompare(binding.goal_id) < 0,
      'CORRUPT_STORE',
      'legacy migration Goal worktree bindings 必须按 goal_id 排序且唯一',
    );
    normalizeHash(binding.manifest_sha256, 'legacy migration manifest sha256');
    normalizeHash(binding.frozen_inputs_sha256, 'legacy migration frozen inputs sha256');
    normalizeHash(binding.worktree_identity_sha256, 'legacy migration worktree identity sha256');
    const unsignedBinding = { ...binding };
    delete unsignedBinding.worktree_identity_sha256;
    assertControl(
      hashObject(unsignedBinding) === binding.worktree_identity_sha256,
      'CORRUPT_STORE',
      `legacy migration Goal ${binding.goal_id} worktree identity seal 不匹配`,
    );
    seen.add(binding.goal_id);
    previousGoalId = binding.goal_id;
  }
  assertControl(
    hashObject(receipt.goal_worktrees) === receipt.goal_worktrees_sha256,
    'CORRUPT_STORE',
    'legacy migration Goal worktree map digest 不匹配',
  );
  return receipt;
}

function sealLegacyEvidenceAnchorIndex(entries, options) {
  const bindings = eventBindingCollector(entries);
  const events = {};
  for (const [key, entry] of [...bindings.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    assertControl(key === legacyEventAnchorKey(entry), 'INVALID_LEGACY_EVIDENCE_ANCHORS', `legacy evidence anchor key 非法: ${key}`);
    events[key] = legacyEventAnchorEntry(entry, entry.evidence_registry_sha256);
  }
  const semanticSources = {};
  const migrationArtifactsByPath = new Map();
  let uniqueSourceBytes = 0;
  if (!(entries instanceof Map)) {
    for (const [key, entry] of [...entries.semanticSources.entries()].sort(([left], [right]) => left.localeCompare(right))) {
      assertControl(key === `${entry.goal_id}/${entry.task_id}/${entry.evidence_id}`, 'INVALID_LEGACY_EVIDENCE_ANCHORS', `legacy semantic source key 非法: ${key}`);
      const digest = normalizeHash(entry.source_sha256, 'legacy semantic source sha256');
      assertControl(
        `sha256:${sha256(entry.source_bytes)}` === digest,
        'EVIDENCE_SOURCE_HASH_MISMATCH',
        `legacy semantic source ${entry.evidence_id} bytes/hash 不匹配`,
      );
      const relativePath = `.legacy-evidence-sources.v1/${digest.slice('sha256:'.length)}.artifact`;
      semanticSources[key] = {
        goal_id: entry.goal_id,
        task_id: entry.task_id,
        evidence_id: entry.evidence_id,
        registry_sha256: normalizeHash(entry.registry_sha256, 'legacy semantic registry sha256'),
        source_sha256: digest,
        artifact_path: relativePath,
      };
      const existing = migrationArtifactsByPath.get(relativePath);
      if (existing) {
        assertControl(
          existing.sha256 === digest && existing.body.equals(entry.source_bytes),
          'CORRUPT_STORE',
          `legacy semantic source digest collision: ${digest}`,
        );
      } else {
        const body = Buffer.from(entry.source_bytes);
        uniqueSourceBytes += body.length;
        assertControl(
          uniqueSourceBytes <= LEGACY_SEMANTIC_SOURCE_TOTAL_MAX_BYTES,
          'LEGACY_EVIDENCE_SOURCE_LIMIT',
          'legacy semantic evidence 去重后总量超过 64MiB',
        );
        migrationArtifactsByPath.set(relativePath, {
          relative_path: relativePath,
          sha256: digest,
          body,
        });
      }
    }
  }
  const {
    prepareLegacyRecoveryHandoffBindings,
  } = require('./source-handoff');
  const recoveryHandoffs = prepareLegacyRecoveryHandoffBindings(
    options.recoveryHandoffs || new Map(),
  );
  assertControl(
    typeof options.incidentRef === 'string'
      && options.incidentRef.length > 0
      && options.incidentRef.length <= 2000,
    'STORE_MIGRATION_INCIDENT_REQUIRED',
    'legacy evidence migration 缺 incident_ref',
  );
  assertControl(
    options.oldControllerDrainAck === 'ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED',
    'STORE_MIGRATION_DRAIN_ACK_REQUIRED',
    'legacy evidence migration 缺 old controller drain/isolation acknowledgement',
  );
  const goalWorktreeMap = validateGoalWorktreeMapReceipt(options.goalWorktreeMap);
  const goalWorktreesById = new Map(
    goalWorktreeMap.goal_worktrees.map((binding) => [binding.goal_id, binding]),
  );
  for (const handoff of Object.values(recoveryHandoffs.handoffs)) {
    const goalWorktree = goalWorktreesById.get(handoff.goal_id);
    assertControl(
      goalWorktree,
      'LEGACY_HANDOFF_ANCHOR_MISMATCH',
      `legacy recovery handoff ${handoff.goal_id}/${handoff.task_id}/${handoff.event_id} 缺 Goal worktree migration binding`,
    );
    assertControl(
      handoff.migration_repository_worktree === goalWorktree.repository_worktree
        && handoff.migration_repository_common_dir === goalWorktree.repository_common_dir
        && handoff.migration_repository_head === goalWorktree.repository_head,
      'STORE_MIGRATION_WORKTREE_CHANGED',
      `Goal ${handoff.goal_id} legacy recovery handoff witness 与 frozen worktree identity/HEAD 不一致`,
    );
  }
  const unsigned = {
    schema_version: 1,
    kind: 'LEGACY_EVIDENCE_EVENT_BINDINGS',
    controller_decoder_sha256: normalizeHash(options.controllerDecoderSha256, 'controller decoder sha256'),
    source_state_vector_sha256: normalizeHash(options.sourceStateVectorSha256, 'source state vector sha256'),
    migration_receipt: {
      incident_ref: options.incidentRef,
      old_controller_drain_ack: options.oldControllerDrainAck,
      goal_worktree_map: goalWorktreeMap,
    },
    events,
    semantic_sources: semanticSources,
    recovery_handoffs: recoveryHandoffs.handoffs,
  };
  const index = { ...unsigned, index_sha256: hashObject(unsigned) };
  const body = `${canonicalJson(index)}\n`;
  const indexArtifact = {
    relative_path: LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
    sha256: `sha256:${sha256(body)}`,
    body,
  };
  return {
    index,
    migration_artifact: indexArtifact,
    migration_artifacts: [
      ...[...migrationArtifactsByPath.values()].sort((left, right) => left.relative_path.localeCompare(right.relative_path)),
      indexArtifact,
    ],
    event_count: Object.keys(events).length,
    semantic_source_count: Object.keys(semanticSources).length,
    unique_semantic_source_bytes: uniqueSourceBytes,
    recovery_handoff_count: recoveryHandoffs.count,
  };
}

function readLegacyEvidenceAnchorIndex(root) {
  const sealedArtifact = readProtocolSealedMigrationArtifact(
    root,
    LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
  );
  assertControl(
    sealedArtifact,
    'LEGACY_EVIDENCE_ANCHOR_REQUIRED',
    'legacy accepted evidence event 缺 protocol-sealed migration anchor index',
  );
  let index;
  try {
    index = JSON.parse(sealedArtifact.body.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'CORRUPT_STORE',
      `legacy evidence anchor index 无法解析: ${error.message}`,
    );
  }
  const requiredKeys = [
    'schema_version',
    'kind',
    'controller_decoder_sha256',
    'source_state_vector_sha256',
    'migration_receipt',
    'events',
    'semantic_sources',
    'index_sha256',
  ];
  const allowedKeys = [...requiredKeys, 'recovery_handoffs'];
  assertControl(
    index
      && typeof index === 'object'
      && !Array.isArray(index)
      && requiredKeys.every((key) => Object.hasOwn(index, key))
      && Object.keys(index).every((key) => allowedKeys.includes(key))
      && (
        Object.keys(index).length === requiredKeys.length
          || Object.keys(index).length === allowedKeys.length
      )
      && index.schema_version === 1
      && index.kind === 'LEGACY_EVIDENCE_EVENT_BINDINGS'
      && index.events
      && typeof index.events === 'object'
      && !Array.isArray(index.events)
      && index.semantic_sources
      && typeof index.semantic_sources === 'object'
      && !Array.isArray(index.semantic_sources)
      && index.migration_receipt
      && typeof index.migration_receipt === 'object'
      && !Array.isArray(index.migration_receipt)
      && Object.keys(index.migration_receipt).length === 3
      && typeof index.migration_receipt.incident_ref === 'string'
      && index.migration_receipt.incident_ref.length > 0
      && index.migration_receipt.old_controller_drain_ack === 'ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED',
    'CORRUPT_STORE',
    'legacy evidence anchor index 格式非法',
  );
  normalizeHash(index.controller_decoder_sha256, 'legacy anchor decoder sha256');
  normalizeHash(index.source_state_vector_sha256, 'legacy anchor source vector sha256');
  validateGoalWorktreeMapReceipt(index.migration_receipt.goal_worktree_map);
  const unsigned = { ...index };
  delete unsigned.index_sha256;
  assertControl(
    hashObject(unsigned) === index.index_sha256,
    'CORRUPT_STORE',
    'legacy evidence anchor index seal 不匹配',
  );
  // Pre-handoff indexes did not have this optional field. Verify their exact
  // original seal first, then expose an empty map to the current decoder.
  const {
    prepareLegacyRecoveryHandoffBindings,
  } = require('./source-handoff');
  const recoveryHandoffs = prepareLegacyRecoveryHandoffBindings(
    index.recovery_handoffs || {},
  );
  return {
    ...index,
    recovery_handoffs: recoveryHandoffs.handoffs,
  };
}

function verifyLegacySemanticEvidenceSource(root, record) {
  const sealedArtifact = readProtocolSealedMigrationArtifact(
    root,
    LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
  );
  if (!sealedArtifact) return null;
  const index = readLegacyEvidenceAnchorIndex(root);
  const binding = index.semantic_sources[legacySemanticSourceKey(record)];
  if (binding === undefined) return null;
  const allowedKeys = [
    'goal_id',
    'task_id',
    'evidence_id',
    'registry_sha256',
    'source_sha256',
    'artifact_path',
  ];
  assertControl(
    binding
      && Object.keys(binding).length === allowedKeys.length
      && Object.keys(binding).every((key) => allowedKeys.includes(key))
      && binding.goal_id === record.goal_id
      && binding.task_id === record.task_id
      && binding.evidence_id === record.evidence_id
      && normalizeHash(binding.registry_sha256, 'legacy registry sha256') === record.registry_sha256
      && normalizeHash(binding.source_sha256, 'legacy source sha256') === normalizeHash(record.source_sha256),
    'LEGACY_EVIDENCE_SOURCE_MISMATCH',
    `legacy semantic evidence ${record.evidence_id} 缺 protocol-sealed source binding`,
  );
  const digest = normalizeHash(record.source_sha256);
  const expectedRelative = `.legacy-evidence-sources.v1/${digest.slice('sha256:'.length)}.artifact`;
  assertControl(
    binding.artifact_path === expectedRelative,
    'LEGACY_EVIDENCE_SOURCE_MISMATCH',
    `legacy semantic evidence ${record.evidence_id} artifact path 非确定性`,
  );
  const artifact = readProtocolSealedMigrationArtifact(
    root,
    binding.artifact_path,
  );
  assertControl(
    artifact,
    'EVIDENCE_SOURCE_MISSING',
    `legacy semantic evidence ${record.evidence_id} protocol-sealed artifact 不存在`,
  );
  assertControl(
    artifact.descriptor.sha256 === digest,
    'EVIDENCE_SOURCE_HASH_MISMATCH',
    `legacy semantic evidence ${record.evidence_id} sealed artifact hash 漂移`,
  );
  return record;
}

function verifyReplaySemanticEvidenceSource(root, record, options = {}) {
  try {
    return verifySemanticEvidenceSource(record);
  } catch (error) {
    if (error && error.code === 'EVIDENCE_SOURCE_MISSING') {
      const legacyBinding = verifyLegacySemanticEvidenceSource(
        root,
        record,
      );
      let identityBinding = null;
      if (
        options.allowIdentityIncidentRotationReceipt === true
          && record.kind === 'HOLD_ASSERTION'
          && record.stage === 'PREFLIGHT'
          && record.status === 'BLOCKED'
      ) {
        identityBinding = readProtocolSealedIdentityIncidentEvidenceSource(
          root,
          record,
          { allowNoBinding: true },
        );
      }
      assertControl(
        legacyBinding !== null || identityBinding !== null,
        'EVIDENCE_SOURCE_MISSING',
        `evidence ${record.evidence_id} 缺 protocol-sealed source binding`,
      );
      return record;
    }
    throw error;
  }
}

function assertLegacyEvidenceAnchor(root, event, digest) {
  const index = readLegacyEvidenceAnchorIndex(root);
  const key = legacyEventAnchorKey(event);
  const actual = index.events[key];
  assertControl(
    actual
      && Object.keys(actual).length === 6
      && hashObject(actual) === hashObject(legacyEventAnchorEntry(event, digest)),
    'EVIDENCE_REGISTRY_BINDING_MISMATCH',
    `legacy accepted event ${event.event_id} evidence registry anchor 不匹配`,
  );
}

function collectLegacyEvidenceAnchor(collector, event, digest) {
  const bindings = eventBindingCollector(collector);
  const key = legacyEventAnchorKey(event);
  const entry = legacyEventAnchorEntry(event, digest);
  const existing = bindings.get(key);
  assertControl(
    !existing || hashObject(existing) === hashObject(entry),
    'EVIDENCE_REGISTRY_BINDING_MISMATCH',
    `legacy accepted event ${event.event_id} collector binding 冲突`,
  );
  bindings.set(key, entry);
}

function verifyAcceptedEventEvidenceBinding(root, event, preparedEvent, options = {}) {
  const digest = eventEvidenceRegistryDigest(preparedEvent);
  if (digest) {
    if (typeof event.evidence_registry_sha256 === 'string') {
      assertControl(
        normalizeHash(event.evidence_registry_sha256, 'event.evidence_registry_sha256') === digest,
        'EVIDENCE_REGISTRY_BINDING_MISMATCH',
        `accepted event ${event.event_id} trusted evidence registry digest 漂移`,
      );
    } else if (options.legacyEvidenceBindingCollector) {
      collectLegacyEvidenceAnchor(options.legacyEvidenceBindingCollector, event, digest);
    } else {
      assertLegacyEvidenceAnchor(root, event, digest);
    }
  } else {
    assertControl(
      event.evidence_registry_sha256 === undefined,
      'CORRUPT_STORE',
      `accepted event ${event.event_id} 含无对应 evidence 的 registry digest`,
    );
  }
}

function resolveEventEvidence(root, goalId, state, event, manifestTask = null, options = {}) {
  const prepared = JSON.parse(JSON.stringify(event));
  const acceptedReplay =
    options.acceptedReplay === true
      && options.verifyAcceptedBinding === true
      && typeof event.input_sha256 === 'string'
      && typeof event.event_sha256 === 'string'
      && typeof event.accepted_at === 'string'
      && Number.isFinite(Date.parse(event.accepted_at))
      && Number.isSafeInteger(event.log_sequence)
      && event.log_sequence > 0;
  if (event.type === 'DEV_READY') {
    const references = event.payload.evidence;
    assertControl(references && typeof references === 'object' && !Array.isArray(references), 'EVIDENCE_NOT_REGISTERED', 'DEV_READY evidence 必须是 registry ID map');
    const { parsePullRequestUrl } = require('./validation');
    const parsedPr = parsePullRequestUrl(event.payload.pr);
    const pullRequest = { ...parsedPr, head: event.full_head };
    const expected = {
      preflight: ['PREFLIGHT', null],
      fast: ['FAST', 'DEV'],
      full_ci: ['FULL_CI', 'CAPTAIN'],
      ac_audit: ['AC_AUDIT', 'CAPTAIN'],
    };
    prepared.payload.evidence = {};
    for (const [key, [kind, producerRole]] of Object.entries(expected)) {
      prepared.payload.evidence[key] = resolveTrustedEvidence(root, state, references[key], {
        goalId,
        kind,
        producerRole,
        fullHead: event.full_head,
        ...(kind === 'PREFLIGHT' ? { manifestTask } : {}),
        ...(kind === 'PREFLIGHT' ? { readOnly: options.readOnly === true } : {}),
        ...(kind === 'PREFLIGHT' ? { acceptedReplay } : {}),
        ...(kind === 'PREFLIGHT'
          ? { requireSourceCheckpointRuntimeBinding: true }
          : {}),
        ...(['FULL_CI', 'AC_AUDIT'].includes(kind) ? { pullRequest } : {}),
      });
    }
  } else if (event.type === 'REVIEW_PASS') {
    const reference = typeof event.payload.evidence === 'string' ? event.payload.evidence : event.payload.evidence && event.payload.evidence.review;
    prepared.payload.evidence = resolveTrustedEvidence(root, state, reference, { goalId, kind: 'REVIEW', producerRole: 'REVIEW', fullHead: event.full_head });
  } else if (event.type === 'RECEIPT_PASS') {
    const reference = typeof event.payload.evidence === 'string' ? event.payload.evidence : event.payload.evidence && event.payload.evidence.receipt;
    prepared.payload.evidence = resolveTrustedEvidence(root, state, reference, { goalId, kind: 'RECEIPT', producerRole: 'RECEIPT', fullHead: event.full_head });
  } else if (event.type === 'REVIEW_REWORK') {
    prepared.payload.review_evidence = resolveTrustedEvidence(root, state, event.payload.review_evidence, { goalId, kind: 'REVIEW', producerRole: 'REVIEW', status: 'FAIL', fullHead: event.full_head });
  } else if (event.type === 'RECEIPT_FAIL') {
    prepared.payload.receipt_evidence = resolveTrustedEvidence(root, state, event.payload.evidence_id, { goalId, kind: 'RECEIPT', producerRole: 'RECEIPT', status: 'FAIL', fullHead: event.full_head });
  } else if (event.type === 'ADD_HOLD') {
    prepared.payload.hold_evidence = resolveTrustedEvidence(
      root,
      state,
      event.payload.evidence_id,
      {
        goalId,
        kind: 'HOLD_ASSERTION',
        fullHead: event.full_head,
        status: 'BLOCKED',
        acceptedReplay,
      },
    );
    if (
      acceptedReplay
        && options.legacyIdentityIncidentCollector
    ) {
      collectLegacyIdentityIncident(
        root,
        options.legacyIdentityIncidentCollector,
        state,
        goalId,
        event,
        prepared.payload.hold_evidence,
      );
    }
  } else if (event.type === 'RESOLVE_HOLD') {
    prepared.payload.resolution_evidence = resolveTrustedEvidence(root, state, event.payload.resolution_evidence_id, { goalId, kind: 'HOLD_RESOLUTION', producerRole: 'FOREMAN', fullHead: event.full_head });
    const rotatedSession = Object.values(state.sessions || {}).find(
      (session) => (
        session
          && session.last_runtime_rotation
          && session.last_runtime_rotation.hold_id
            === event.payload.hold_id
      ),
    );
    if (rotatedSession) {
      assertControl(
        typeof event.payload.runtime_preflight_evidence_id === 'string',
        'RUNTIME_PREFLIGHT_EVIDENCE_REQUIRED',
        'runtime rotation hold 只能在 exact successor PREFLIGHT PASS 后解除',
      );
      const launchFile = path.join(
        root,
        'goals',
        goalId,
        'launches',
        state.task_id,
        `${rotatedSession.launch_id}.json`,
      );
      assertControl(
        fs.existsSync(launchFile),
        'RUNTIME_PREFLIGHT_EVIDENCE_REQUIRED',
        'runtime rotation successor launch 尚未持久化',
      );
      const { validateLaunchManifest } = require('./validation');
      const successorLaunch = validateLaunchManifest(
        readJson(launchFile, 'runtime rotation successor launch'),
      );
      prepared.payload.runtime_preflight_evidence = resolveTrustedEvidence(
        root,
        state,
        event.payload.runtime_preflight_evidence_id,
        {
          goalId,
          kind: 'PREFLIGHT',
          producerRole: rotatedSession.role,
          fullHead: successorLaunch.repository.full_head,
          manifestTask,
          allowPreflightOnly: true,
          allowRuntimeRotationHold: true,
          readOnly: options.readOnly === true,
          acceptedReplay,
        },
      );
    } else {
      assertControl(
        event.payload.runtime_preflight_evidence_id === undefined,
        'RUNTIME_PREFLIGHT_EVIDENCE_UNEXPECTED',
        '非 runtime rotation hold 禁止附带 runtime preflight evidence',
      );
    }
  } else if (event.type === 'TASK_REOPEN') {
    prepared.payload.merge_boundary_evidence = resolveTrustedEvidence(root, state, event.payload.evidence_id, { goalId, kind: 'MERGE_BOUNDARY', producerRole: 'FOREMAN', status: 'FAIL', fullHead: event.full_head });
  } else if (event.type === 'RECOVERY_PROMOTED') {
    const recoverySession = state.sessions.DEV;
    assertControl(
      recoverySession && recoverySession.recovery_handoff,
      'RECOVERY_HANDOFF_REQUIRED',
      'promotion evidence 缺当前 recovered DEV handoff',
    );
    prepared.payload.preflight_evidence = resolveTrustedEvidence(
      root,
      state,
      event.payload.preflight_evidence_id,
      {
        goalId,
        kind: 'PREFLIGHT',
        producerRole: 'DEV',
        fullHead: recoverySession.recovery_handoff.import_commit,
        manifestTask,
        allowPreflightOnly: true,
        readOnly: options.readOnly === true,
        acceptedReplay,
      },
    );
  } else if (event.type === 'ARCHIVED') {
    prepared.payload.archive_evidence = resolveTrustedEvidence(root, state, event.payload.evidence_id, { goalId, kind: 'MERGE_BOUNDARY', producerRole: 'FOREMAN', status: 'PASS', fullHead: event.full_head });
  } else if (event.type === 'ROLE_LOST' && event.payload.evidence_id) {
    prepared.payload.role_failure_evidence = resolveTrustedEvidence(root, state, event.payload.evidence_id, { goalId, kind: 'ROLE_FAILURE', fullHead: event.full_head, status: 'FAIL' });
  }
  if (options.verifyAcceptedBinding === true) {
    verifyAcceptedEventEvidenceBinding(root, event, prepared, options);
  }
  return prepared;
}

function validateEvidenceIngress(cwd, raw, state, session, options = {}) {
  assertControl(raw && typeof raw === 'object' && !Array.isArray(raw), 'INVALID_EVIDENCE', 'evidence 必须是对象');
  assertControl(Object.keys(raw).every((key) => EVIDENCE_KEYS.has(key)), 'INVALID_EVIDENCE', 'evidence 含未知字段');
  assertControl(raw.schema_version === 1, 'INVALID_EVIDENCE', 'evidence schema_version 必须为 1');
  safeId(raw.evidence_id, 'evidence_id');
  safeId(raw.goal_id, 'evidence goal_id');
  safeId(raw.task_id, 'evidence task_id');
  assertControl(raw.goal_id && raw.task_id === state.task_id, 'INVALID_EVIDENCE', 'evidence task 身份不匹配');
  assertControl(EXPECTED_PRODUCER[raw.kind], 'INVALID_EVIDENCE', `未知 evidence kind ${raw.kind}`);
  if (MECHANICAL_EVIDENCE_KINDS.has(raw.kind)) {
    assertControl(options.controller === true, 'MECHANICAL_EVIDENCE_REQUIRED', `${raw.kind} 只能由 goalctl 固定 adapter 生成，通用 evidence ingress 禁止登记`);
    validateControllerAttestation(raw, controlRoot(cwd));
    if (['FULL_CI', 'AC_AUDIT'].includes(raw.kind)) validatePullRequestBinding(raw.pull_request);
  } else {
    assertControl(
      raw.attestation === undefined
        && raw.launch_sha256 === undefined
        && raw.runtime_launch_sha256 === undefined
        && raw.runtime_launch_uri === undefined,
      'INVALID_EVIDENCE',
      '语义 evidence 禁止伪造 controller/runtime launch attestation',
    );
  }
  if (raw.resource_lease !== undefined) {
    assertControl(raw.kind === 'ROLE_FAILURE', 'INVALID_EVIDENCE', 'resource_lease 只允许用于 ROLE_FAILURE evidence');
    validateResourceLeaseBinding(raw.resource_lease);
  }
  assertControl(EVIDENCE_STATUSES.has(raw.status), 'INVALID_EVIDENCE', `非法 evidence status ${raw.status}`);
  assertControl(raw.producer && Object.keys(raw.producer).every((key) => ['role', 'thread_id', 'host_id'].includes(key)), 'INVALID_EVIDENCE', 'producer 含未知字段');
  safeId(raw.producer.thread_id, 'evidence producer.thread_id');
  safeId(raw.producer.host_id || 'local', 'evidence producer.host_id');
  assertControl(raw.producer.role === session.role && raw.producer.thread_id === session.thread_id && (raw.producer.host_id || 'local') === session.host_id, 'EVIDENCE_PRODUCER_MISMATCH', 'evidence producer 与 capability session 不一致');
  assertControl(EXPECTED_PRODUCER[raw.kind].includes(session.role), 'EVIDENCE_PRODUCER_MISMATCH', `${session.role} 不能生成 ${raw.kind}`);
  const recoveredDevScope = sessionOperationalScope(state, 'DEV');
  if (session.role === 'DEV' && state.phase === 'DEV_ACTIVE' && recoveredDevScope && recoveredDevScope !== 'FULL') {
    if (raw.kind === 'PREFLIGHT') {
      assertOperationalScope(state, 'DEV', 'PREFLIGHT_EVIDENCE');
    } else if (!['HOLD_ASSERTION', 'ROLE_FAILURE'].includes(raw.kind)) {
      assertControl(false, 'RECOVERY_SCOPE_VIOLATION', `DEV operational_scope=${recoveredDevScope} 不允许登记 ${raw.kind} evidence`);
    }
  }
  assertControl(raw.state_revision === state.state_revision, 'STALE_EVIDENCE', 'evidence state_revision 陈旧');
  assertControl(raw.packet && raw.packet.revision === state.packet.revision, 'STALE_EVIDENCE', 'evidence packet revision 陈旧');
  assertControl(normalizeHash(raw.packet.sha256) === state.packet.sha256 && normalizeHash(raw.packet_sha256) === state.packet.sha256, 'STALE_EVIDENCE', 'evidence packet hash 陈旧');
  assertControl(raw.base_head === state.base_head, 'STALE_EVIDENCE', 'evidence base HEAD 陈旧');
  const candidateKinds = new Set(['PREFLIGHT', 'FAST', 'FULL_CI', 'AC_AUDIT']);
  const semanticVerdictKinds = new Set(['REVIEW', 'RECEIPT']);
  if (semanticVerdictKinds.has(raw.kind)) {
    const { git, repoRoot } = require('./util');
    const worktree = repoRoot(cwd);
    assertControl(git(worktree, ['rev-parse', 'HEAD']) === raw.full_head && raw.full_head === state.full_head, 'STALE_EVIDENCE', `${raw.kind} evidence 不是当前控制面/worktree HEAD`);
    assertControl(git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '', 'DIRTY_WORKTREE', `${raw.kind} verdict 只允许绑定 clean committed HEAD`);
  } else if (state.phase === 'DEV_ACTIVE' && candidateKinds.has(raw.kind)) {
    const { git, repoRoot } = require('./util');
    const worktree = repoRoot(cwd);
    assertControl(git(worktree, ['rev-parse', 'HEAD']) === raw.full_head, 'STALE_EVIDENCE', 'candidate evidence full HEAD 不是当前 worktree HEAD');
    assertDevCandidateLineage(
      worktree,
      state,
      state.sessions.DEV,
      raw.full_head,
      { allowPreflightOnly: raw.kind === 'PREFLIGHT' },
    );
    if (options.controller === true) {
      assertControl(git(worktree, ['status', '--porcelain=v1', '--untracked-files=all']) === '', 'DIRTY_WORKTREE', 'mechanical evidence 只允许绑定 clean committed HEAD');
    }
  } else {
    assertControl(raw.full_head === state.full_head, 'STALE_EVIDENCE', 'evidence full HEAD 陈旧');
  }
  assertControl(typeof raw.created_at === 'string' && Number.isFinite(Date.parse(raw.created_at)), 'INVALID_EVIDENCE', 'evidence created_at 非法');
  assertControl(typeof raw.uri === 'string' && raw.uri.length > 0 && raw.uri.length <= 2000, 'INVALID_EVIDENCE', 'evidence uri 非法');
  let source;
  try {
    source = new URL(raw.uri);
  } catch {
    assertControl(false, 'INVALID_EVIDENCE', 'evidence uri 必须是绝对 URL');
  }
  assertControl(!source.username && !source.password, 'INVALID_EVIDENCE', 'evidence uri 禁止内嵌凭证');
  assertControl(['file:', 'https:'].includes(source.protocol), 'INVALID_EVIDENCE', 'evidence uri 只允许 file/https');
  if (!MECHANICAL_EVIDENCE_KINDS.has(raw.kind)) {
    assertControl(
      source.protocol === 'file:',
      'EVIDENCE_HTTPS_REQUIRES_ADAPTER',
      'HTTPS semantic evidence 缺 replay-time fetch/hash adapter；v1 只接受本地 sealed file',
    );
  }
  assertControl(typeof raw.source_sha256 === 'string', 'INVALID_EVIDENCE', 'evidence 缺 source_sha256');
  normalizeHash(raw.source_sha256, 'source_sha256');
  if (source.protocol === 'file:') {
    if (options.semanticSourceBytes !== undefined) {
      validatedSemanticSourceBytes(
        options.semanticSourceBytes,
        normalizeHash(raw.source_sha256),
        `evidence ${raw.evidence_id} source`,
      );
    } else {
      const sourceFile = decodeURIComponent(source.pathname);
      stableSemanticSourceBytes(
        sourceFile,
        normalizeHash(raw.source_sha256),
        `evidence ${raw.evidence_id} source`,
      );
    }
  }
  if (raw.launch_id !== undefined) assertControl(raw.launch_id === session.launch_id, 'LAUNCH_ID_MISMATCH', 'evidence launch_id 与 session 不一致');
  return JSON.parse(JSON.stringify(raw));
}

function recordEvidence(cwd, raw, actorCapabilityFile) {
  return publicEvidenceResult(
    recordEvidenceInternal(cwd, raw, actorCapabilityFile, false),
  );
}

function recordControllerEvidence(cwd, raw, actorCapabilityFile) {
  return recordEvidenceInternal(cwd, raw, actorCapabilityFile, true);
}

function inspectPreparedEvidenceBytesForRetryUnderLock(
  cwd,
  raw,
  sourceBytes,
  actorCapabilityFile,
  controller = false,
) {
  const { controlRoot } = require('./util');
  const root = controlRoot(cwd);
  const bound = bindSemanticEvidenceSourceBytes(root, raw, sourceBytes);
  const preparedFile = semanticIngressPreparedFile(
    root,
    bound.evidence.goal_id,
    bound.evidence.task_id,
    bound.evidence.evidence_id,
  );
  assertControl(
    fs.existsSync(preparedFile),
    'EVIDENCE_SOURCE_MISSING',
    `prepared evidence ${bound.evidence.evidence_id} 不存在`,
  );
  const prepared = readSemanticIngressPrepared(preparedFile);
  const validated = validatePreparedSemanticIngress(
    root,
    prepared,
    bound.evidence,
    actorCapabilityFile,
    controller,
  );
  assertControl(
    prepared.source.sha256
      === normalizeHash(bound.evidence.source_sha256)
      && prepared.source.size === bound.sourceBytes.length
      && prepared.source.target_file === bound.targetFile,
    'CORRUPT_STORE',
    `prepared evidence ${bound.evidence.evidence_id} source bytes binding 漂移`,
  );
  return {
    ...validated,
    evidence: bound.evidence,
    prepared,
    preparedFile,
    sourceBytes: bound.sourceBytes,
  };
}

function recordEvidenceBytesUnderLock(
  cwd,
  raw,
  sourceBytes,
  actorCapabilityFile,
  controller = false,
  pendingAuthorization = {},
) {
  const { controlRoot } = require('./util');
  const root = controlRoot(cwd);
  const bound = bindSemanticEvidenceSourceBytes(root, raw, sourceBytes);
  return recordEvidenceUnderLock(
    cwd,
    bound.evidence,
    actorCapabilityFile,
    controller,
    {
      ...pendingAuthorization,
      semanticSourceBytes: bound.sourceBytes,
    },
  );
}

function recordEvidenceUnderLock(
  cwd,
  raw,
  actorCapabilityFile,
  controller = false,
  pendingAuthorization = {},
) {
  const { assertFrozenInputs, loadGoalStateUnlocked } = require('./goal');
  const { controlRoot } = require('./util');
  const root = controlRoot(cwd);
  const suppliedSourceBytes = pendingAuthorization.semanticSourceBytes;
  assertControl(
    raw
      && typeof raw === 'object'
      && !Array.isArray(raw)
      && typeof raw.goal_id === 'string'
      && typeof raw.task_id === 'string'
      && typeof raw.evidence_id === 'string',
    'INVALID_EVIDENCE',
    'evidence retry 身份非法',
  );
  safeId(raw.goal_id, 'evidence goal_id');
  safeId(raw.task_id, 'evidence task_id');
  safeId(raw.evidence_id, 'evidence_id');
  const file = evidenceFile(root, raw.goal_id, raw.task_id, raw.evidence_id);
  if (fs.existsSync(file)) {
    const retried = readExistingEvidenceForRetryUnderLock(cwd, {
      goalId: raw.goal_id,
      taskId: raw.task_id,
      evidenceId: raw.evidence_id,
      actorCapabilityFile,
    });
    assertControl(
      typeof retried.evidence.ingress_sha256 === 'string'
        && retried.evidence.ingress_sha256 === hashObject(raw),
      'EVIDENCE_ID_CONFLICT',
      `evidence id ${raw.evidence_id} 已绑定不同 ingress bytes`,
    );
    return {
      registered: true,
      idempotent: true,
      evidence: retried.evidence,
      evidence_file: retried.evidence_file,
    };
  }
  const preparedFile = semanticIngressPreparedFile(
    root,
    raw.goal_id,
    raw.task_id,
    raw.evidence_id,
  );
  if (fs.existsSync(preparedFile)) {
    const prepared = readSemanticIngressPrepared(preparedFile);
    const { state: preparedTask, targetFile } = validatePreparedSemanticIngress(
      root,
      prepared,
      raw,
      actorCapabilityFile,
      controller,
    );
    assertControl(
      preparedTask && preparedTask.phase !== 'ARCHIVED',
      'TASK_TERMINAL',
      `task ${prepared.task_id} 已 ARCHIVED，不得 materialize prepared evidence`,
    );
    const { assertNoPendingTaskOperations } = require('./pending-operations');
    assertNoPendingTaskOperations(
      root,
      prepared.goal_id,
      prepared.task_id,
      {
        allowOperationKind: 'GENERIC_EVIDENCE',
        allowOperationId: prepared.evidence_id,
        allowRequestSha256: prepared.ingress_sha256,
        allowEvidenceId: pendingAuthorization.allowEvidenceId || null,
      },
    );
    if (!fs.existsSync(targetFile)) {
      if (suppliedSourceBytes !== undefined) {
        durableSemanticEvidenceSourceBytes(
          root,
          prepared.evidence,
          suppliedSourceBytes,
        );
      } else {
        durableSemanticEvidenceSource(root, {
          ...prepared.evidence,
          uri: raw.uri,
        });
      }
    }
    const sourceBytes = stableSemanticSourceBytes(
      targetFile,
      prepared.source.sha256,
      `prepared evidence source ${prepared.evidence_id}`,
    );
    assertControl(
      sourceBytes.length === prepared.source.size,
      'CORRUPT_STORE',
      `prepared evidence ${prepared.evidence_id} source size 漂移`,
    );
    const sealed = {
      ...prepared.evidence,
      registry_sha256: hashObject(prepared.evidence),
    };
    ensureDir(path.dirname(file));
    atomicWriteJson(file, sealed);
    return {
      registered: true,
      idempotent: true,
      evidence: sealed,
      evidence_file: file,
    };
  }
  const { assertNoPendingTaskOperations } = require('./pending-operations');
  assertNoPendingTaskOperations(root, raw.goal_id, raw.task_id, {
    allowEvidenceId: pendingAuthorization.allowEvidenceId || null,
  });
  const loaded = loadGoalStateUnlocked(root, raw && raw.goal_id);
  const state = loaded.snapshot.tasks[raw && raw.task_id];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${raw && raw.task_id}`);
  assertControl(
    state.phase !== 'ARCHIVED',
    'TASK_TERMINAL',
    `task ${state.task_id} 已 ARCHIVED，仅允许既有 FOREMAN HEARTBEAT`,
  );
  assertFrozenInputs(cwd, loaded, raw.task_id);
  const expectedRole = raw && raw.producer && raw.producer.role;
  const expectedThread = raw && raw.producer && raw.producer.thread_id;
  const session = expectedRole === 'FOREMAN'
    ? authorizeGoalSession(loaded.snapshot, actorCapabilityFile, {
      role: 'FOREMAN',
      threadId: expectedThread,
    })
    : authorizeSession(state, actorCapabilityFile, {
      role: expectedRole,
      threadId: expectedThread,
    });
  assertControl(
    raw.goal_id === loaded.manifest.goal_id
      && raw.task_id === state.task_id,
    'INVALID_EVIDENCE',
    'evidence retry 身份非法',
  );
  const validated = validateEvidenceIngress(
    cwd,
    raw,
    state,
    session,
    {
      controller,
      semanticSourceBytes: suppliedSourceBytes,
    },
  );
  const anchored = {
    ...validated,
    ingress_sha256: hashObject(validated),
    acceptance_anchor: evidenceAcceptanceAnchor(state, session),
  };
  let evidence = anchored;
  if (!MECHANICAL_EVIDENCE_KINDS.has(anchored.kind)) {
    const durableTarget = durableSemanticEvidenceTarget(root, anchored);
    assertControl(
      !fs.existsSync(durableTarget),
      'EVIDENCE_SOURCE_ORPHAN',
      `evidence ${anchored.evidence_id} 有未绑定 prepared ingress 的 orphan source`,
    );
    const sourceStat = suppliedSourceBytes === undefined
      ? fs.lstatSync(fileURLToPath(new URL(anchored.uri)))
      : null;
    const preparedEvidence = {
      ...anchored,
      uri: pathToFileURL(durableTarget).href,
    };
    const prepared = sealSemanticIngressPrepared({
      schema_version: 1,
      goal_id: anchored.goal_id,
      task_id: anchored.task_id,
      evidence_id: anchored.evidence_id,
      controller,
      ingress_sha256: anchored.ingress_sha256,
      producer_authority: {
        role: session.role,
        thread_id: session.thread_id,
        host_id: session.host_id,
        attempt: session.attempt,
        capability_file: session.capability_file,
        capability_sha256: session.capability_sha256,
      },
      source: {
        sha256: normalizeHash(anchored.source_sha256),
        size: suppliedSourceBytes === undefined
          ? sourceStat.size
          : suppliedSourceBytes.length,
        target_file: durableTarget,
      },
      evidence: preparedEvidence,
    });
    ensureDir(path.dirname(preparedFile));
    atomicWriteJson(preparedFile, prepared);
    maybeFaultAfterSemanticIngressPrepared(cwd, pendingAuthorization);
    evidence = suppliedSourceBytes === undefined
      ? durableSemanticEvidenceSource(root, anchored)
      : durableSemanticEvidenceSourceBytes(
        root,
        preparedEvidence,
        suppliedSourceBytes,
      );
    assertControl(
      hashObject(evidence) === hashObject(preparedEvidence),
      'CORRUPT_STORE',
      `evidence ${anchored.evidence_id} prepared/source binding 漂移`,
    );
    maybeFaultAfterSemanticSourcePublish(cwd);
  }
  const sealed = { ...evidence, registry_sha256: hashObject(evidence) };
  ensureDir(path.dirname(file));
  atomicWriteJson(file, sealed);
  return {
    registered: true,
    idempotent: false,
    evidence: sealed,
    evidence_file: file,
  };
}

function recordEvidenceInternal(cwd, raw, actorCapabilityFile, controller) {
  const { loadGoalStateUnlocked } = require('./goal');
  const { controlRoot } = require('./util');
  const root = controlRoot(cwd);
  let retryFile = null;
  let preparedRetryFile = null;
  if (
    raw
      && typeof raw === 'object'
      && !Array.isArray(raw)
      && typeof raw.goal_id === 'string'
      && typeof raw.task_id === 'string'
      && typeof raw.evidence_id === 'string'
  ) {
    retryFile = evidenceFile(
      root,
      raw.goal_id,
      raw.task_id,
      raw.evidence_id,
    );
    preparedRetryFile = semanticIngressPreparedFile(
      root,
      raw.goal_id,
      raw.task_id,
      raw.evidence_id,
    );
  }
  if (
    (retryFile && fs.existsSync(retryFile))
      || (preparedRetryFile && fs.existsSync(preparedRetryFile))
  ) {
    let oddRecoveryAuthorized = false;
    return withLock(root, () => recordEvidenceUnderLock(
      cwd,
      raw,
      actorCapabilityFile,
      controller,
    ), {
      beforeGeneration: () => {
        if (retryFile && fs.existsSync(retryFile)) {
          const retried = readExistingEvidenceForRetryUnderLock(cwd, {
            goalId: raw.goal_id,
            taskId: raw.task_id,
            evidenceId: raw.evidence_id,
            actorCapabilityFile,
          });
          assertControl(
            typeof retried.evidence.ingress_sha256 === 'string'
              && retried.evidence.ingress_sha256 === hashObject(raw),
            'EVIDENCE_ID_CONFLICT',
            `evidence id ${raw.evidence_id} 已绑定不同 ingress bytes`,
          );
          oddRecoveryAuthorized = true;
          return;
        }
        const prepared = readSemanticIngressPrepared(preparedRetryFile);
        const { state, targetFile } = validatePreparedSemanticIngress(
          root,
          prepared,
          raw,
          actorCapabilityFile,
          controller,
        );
        assertControl(
          state && state.phase !== 'ARCHIVED',
          'TASK_TERMINAL',
          `task ${prepared.task_id} 已 ARCHIVED，不得 materialize prepared evidence`,
        );
        const { assertNoPendingTaskOperations } = require('./pending-operations');
        assertNoPendingTaskOperations(
          root,
          prepared.goal_id,
          prepared.task_id,
          {
            allowOperationKind: 'GENERIC_EVIDENCE',
            allowOperationId: prepared.evidence_id,
            allowRequestSha256: prepared.ingress_sha256,
          },
        );
        const sourceBytes = stableSemanticSourceBytes(
          targetFile,
          prepared.source.sha256,
          `prepared evidence source ${prepared.evidence_id}`,
        );
        assertControl(
          sourceBytes.length === prepared.source.size,
          'CORRUPT_STORE',
          `prepared evidence ${prepared.evidence_id} source size 漂移`,
        );
        oddRecoveryAuthorized = true;
      },
      authorizeOddRecovery: () => oddRecoveryAuthorized,
      transactionKey: () => canonicalTransactionKey(
        'EVIDENCE_INGRESS',
        {
          goal_id: raw.goal_id,
          task_id: raw.task_id,
        },
        raw.evidence_id,
        hashObject(raw),
      ),
    });
  }
  withStableRead(root, () => {
    const loaded = loadGoalStateUnlocked(root, raw && raw.goal_id, {
      repairHeads: false,
      repairBootstrapConsumption: false,
    });
    const state = loaded.snapshot.tasks[raw && raw.task_id];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${raw && raw.task_id}`);
    assertControl(
      state.phase !== 'ARCHIVED',
      'TASK_TERMINAL',
      `task ${state.task_id} 已 ARCHIVED，仅允许既有 FOREMAN HEARTBEAT`,
    );
  });
  return withLock(root, () => recordEvidenceUnderLock(
    cwd,
    raw,
    actorCapabilityFile,
    controller,
  ), {
    transactionKey: () => canonicalTransactionKey(
      'EVIDENCE_INGRESS',
      {
        goal_id: raw.goal_id,
        task_id: raw.task_id,
      },
      raw.evidence_id,
      hashObject(raw),
    ),
  });
}

module.exports = {
  EXPECTED_PRODUCER,
  LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
  MECHANICAL_EVIDENCE_KINDS,
  bindAcceptedEventEvidence,
  collectLegacySemanticEvidenceSources,
  createLegacyEvidenceMigrationCollector,
  evidenceFile,
  evidenceAcceptanceAnchor,
  legacyEvidenceAnchorFile,
  readLegacyEvidenceAnchorIndex,
  readExistingEvidenceForRetry,
  readExistingEvidenceForRetryUnderLock,
  readSemanticIngressPrepared,
  inspectPreparedEvidenceBytesForRetryUnderLock,
  recordEvidence,
  recordEvidenceBytesUnderLock,
  recordControllerEvidence,
  recordEvidenceUnderLock,
  semanticIngressPreparedFile,
  publicEvidenceResult,
  resolveEventEvidence,
  resolveTrustedEvidence,
  sealLegacyEvidenceAnchorIndex,
};
