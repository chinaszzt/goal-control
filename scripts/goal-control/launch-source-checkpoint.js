'use strict';

const fs = require('fs');
const path = require('path');
const { fileURLToPath } = require('url');
const { ControlError, assertControl } = require('./errors');
const {
  canonicalJson,
  git,
  hashFile,
  hashObject,
  normalizeHash,
  readJson,
  safeId,
  sha256,
} = require('./util');
const {
  acceptedEventFiles,
  readProtocolSealedMigrationArtifact,
  readProtocolSealedRotationReceipts,
} = require('./store');
const { actorSequenceKey } = require('./fsm');

const LAUNCH_HOLD_CLASSIFICATION = Object.freeze({
  SOURCE_ONLY: 'SOURCE_ONLY',
  RUNTIME_IDENTITY: 'RUNTIME_IDENTITY',
  UNKNOWN: 'UNKNOWN',
});

const ROTATABLE_EXECUTION_TARGET_FAILURE_CODES = new Set([
  'TARGET_PROCESS_MISSING',
  'TARGET_PROCESS_IDENTITY_FAILED',
  'TARGET_EXECUTABLE_MISMATCH',
  'TARGET_START_TIME_MISMATCH',
]);
const LEGACY_IDENTITY_INCIDENT_RECEIPT_RELATIVE_PATH =
  '.legacy-identity-incidents.v1.json';
const LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH =
  '.legacy-evidence-anchors.v1.json';
const LEGACY_EVIDENCE_SOURCE_DIRECTORY =
  '.legacy-evidence-sources.v1';
// The source bytes are base64-embedded inside a rotation receipt whose entire
// canonical JSON is capped at 16 MiB. Keep ample room for the 4/3 expansion,
// the validation report, Goal summaries, and receipt metadata.
const IDENTITY_INCIDENT_SOURCE_MAX_BYTES = 4 * 1024 * 1024;
const LEGACY_IDENTITY_INCIDENT_ENTRY_KEYS = Object.freeze([
  'schema_version',
  'goal_id',
  'task_id',
  'hold_id',
  'evidence_id',
  'source_sha256',
  'registry_sha256',
  'event_id',
  'event_input_sha256',
  'event_sha256',
  'event_evidence_registry_sha256',
  'accepted_at',
  'actor_sha256',
  'launch_id',
  'parent_evidence_id',
  'parent_registry_sha256',
  'candidate_launch_sha256',
  'authority_sha256',
  'entry_sha256',
]);
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;

function hasExactKeys(value, keys) {
  return value
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && Object.keys(value).every((key) => keys.includes(key));
}

function sourceCheckpointInvariant(launch) {
  const invariant = JSON.parse(JSON.stringify(launch));
  delete invariant.repository.full_head;
  if (invariant.execution && invariant.execution.target) {
    delete invariant.execution.target.build_head;
  }
  return invariant;
}

function canonicalRuntimeLaunchFile(root, goalId, taskId, launchId) {
  return path.join(
    root,
    'goals',
    goalId,
    'launches',
    taskId,
    `${launchId}.json`,
  );
}

function validBuildHeadBinding(launch) {
  const target = launch.execution && launch.execution.target;
  if (!target) return false;
  return target.kind === 'NONE'
    ? target.build_head === undefined
    : target.build_head === launch.repository.full_head;
}

function parentCandidateHeadBinding(
  parent,
  candidate,
  failed,
  canonical,
) {
  const observedHead = parent && parent.full_head;
  const candidateHead = candidate
    && candidate.repository
    && candidate.repository.full_head;
  const repositoryFailures = Array.isArray(failed)
    ? failed.filter((check) => (
      check
        && check.name === 'repository-identity'
        && check.status === 'FAIL'
    ))
    : [];
  const exactStaleHeadFailure = (
    typeof observedHead === 'string'
      && /^[0-9a-f]{40}$/.test(observedHead)
      && repositoryFailures.length === 1
      && repositoryFailures[0].detail
        === `STALE_HEAD: 当前 HEAD ${observedHead} 与 launch 不一致`
  );
  if (candidateHead === observedHead) {
    return !exactStaleHeadFailure;
  }
  // A legacy STALE_HEAD proves only that the sealed canonical launch was
  // checked from a different worktree HEAD. It does not authorize inferring a
  // later same-ID source checkpoint, so migration deliberately requires the
  // candidate and canonical launch objects to remain exact.
  return exactStaleHeadFailure
    && canonical
    && hashObject(candidate) === hashObject(canonical)
    && validBuildHeadBinding(candidate)
    && validBuildHeadBinding(canonical);
}

function supportedLocalPreviewRuntime(launch) {
  const execution = launch.execution;
  const target = execution && execution.target;
  if (
    !execution
      || execution.environment !== 'none'
      || execution.write_mode !== 'NONE'
      || execution.domain !== undefined
      || execution.account_alias !== undefined
      || execution.tim_alias !== undefined
      || execution.identity_probe !== undefined
      || !target
      || target.kind !== 'PREVIEW'
      || !Number.isSafeInteger(target.pid)
      || target.pid <= 0
      || typeof target.started_at !== 'string'
      || !Number.isFinite(Date.parse(target.started_at))
      || typeof target.executable_path !== 'string'
      || target.user_data_dir !== undefined
      || target.cdp_target_id !== undefined
      || target.window_id !== undefined
      || !validBuildHeadBinding(launch)
  ) {
    return false;
  }
  try {
    const preview = new URL(target.preview_url);
    return preview.protocol === 'http:'
      && preview.hostname === '127.0.0.1'
      && Boolean(preview.port)
      && !preview.username
      && !preview.password
      && !preview.search
      && !preview.hash;
  } catch {
    return false;
  }
}

function runtimeIdentityInvariant(launch) {
  const invariant = JSON.parse(JSON.stringify(launch));
  delete invariant.created_at;
  delete invariant.execution.target.pid;
  delete invariant.execution.target.started_at;
  delete invariant.execution.target.preview_url;
  return invariant;
}

function classifySupportedRuntimeIdentity(
  canonical,
  candidate,
  { requireRuntimeIdentityDelta = false } = {},
) {
  const canonicalTarget = canonical.execution.target;
  const candidateTarget = candidate.execution.target;
  const hasRuntimeIdentityDelta = [
    'pid',
    'started_at',
    'preview_url',
  ].some((field) => canonicalTarget[field] !== candidateTarget[field]);
  return supportedLocalPreviewRuntime(canonical)
    && supportedLocalPreviewRuntime(candidate)
    && canonical.repository.full_head === candidate.repository.full_head
    && hashObject(runtimeIdentityInvariant(canonical))
      === hashObject(runtimeIdentityInvariant(candidate))
    && (!requireRuntimeIdentityDelta || hasRuntimeIdentityDelta)
    ? LAUNCH_HOLD_CLASSIFICATION.RUNTIME_IDENTITY
    : LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
}

function launchMatchesActiveWorker(
  launch,
  state,
  goalId,
  session,
) {
  return launch
    && launch.role === session.role
    && launch.goal_id === goalId
    && launch.task_id === state.task_id
    && launch.launch_id === session.launch_id
    && launch.thread.id === session.thread_id
    && (launch.thread.host_id || 'local') === session.host_id
    && launch.execution.task_nonce === session.task_nonce
    && launch.control_epoch === state.control_epoch
    && session.registered_control_epoch === state.control_epoch
    && launch.state_revision === session.registered_state_revision
    && launch.packet.revision === state.packet.revision
    && normalizeHash(launch.packet.sha256) === state.packet.sha256
    && launch.repository.base_head === state.base_head;
}

function readCanonicalLaunch(root, state, goalId, session) {
  const file = canonicalRuntimeLaunchFile(
    root,
    goalId,
    state.task_id,
    session.launch_id,
  );
  assertControl(
    fs.existsSync(file)
      && fs.statSync(file).isFile()
      && !fs.lstatSync(file).isSymbolicLink(),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `canonical launch ${session.launch_id} 不存在或不是普通文件`,
  );
  const { validateLaunchManifest } = require('./validation');
  const launch = validateLaunchManifest(
    readJson(file, `launch hold canonical ${session.launch_id}`),
  );
  assertControl(
    launchMatchesActiveWorker(launch, state, goalId, session),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'canonical launch 与 active worker/session/frozen source 不匹配',
  );
  return launch;
}

function validateLegacyIdentityIncidentEntrySource(entry, body) {
  let source;
  try {
    source = JSON.parse(body.toString('utf8'));
  } catch (error) {
    assertControl(
      false,
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      `legacy identity incident ${entry.evidence_id} source 无法解析: ${error.message}`,
    );
  }
  const incidentEvent = source && source.incident_event;
  const authority = source && source.event_authority;
  const unsignedAuthority = authority && { ...authority };
  if (unsignedAuthority) delete unsignedAuthority.authority_sha256;
  const producer = authority && authority.producer;
  const anchor = authority && authority.task_anchor;
  assertControl(
    source
      && source.controller === 'goalctl'
      && source.adapter === 'PREFLIGHT_IDENTITY_INCIDENT'
      && source.request
      && source.request.schema_version === 1
      && source.request.goal_id === entry.goal_id
      && source.request.task_id === entry.task_id
      && source.request.parent_evidence_id === entry.parent_evidence_id
      && source.request.launch_id === entry.launch_id
      && Array.isArray(source.request.checks)
      && source.request.checks.length > 0
      && source.request.checks.every((check) => (
        check
          && typeof check === 'object'
          && !Array.isArray(check)
          && check.status === 'FAIL'
      ))
      && incidentEvent
      && incidentEvent.goal_id === entry.goal_id
      && incidentEvent.task_id === entry.task_id
      && incidentEvent.event_id === entry.event_id
      && incidentEvent.type === 'ADD_HOLD'
      && incidentEvent.payload
      && incidentEvent.payload.kind === 'ENV_IDENTITY_INCIDENT'
      && incidentEvent.payload.hold_id === entry.hold_id
      && incidentEvent.payload.evidence_id === entry.evidence_id
      && hashObject(incidentEvent) === entry.event_input_sha256
      && hashObject(incidentEvent.actor) === entry.actor_sha256
      && authority
      && authority.schema_version === 1
      && authority.kind === 'IDENTITY_INCIDENT_EVENT_AUTHORITY'
      && authority.authority_sha256 === hashObject(unsignedAuthority)
      && authority.authority_sha256 === entry.authority_sha256
      && authority.goal_id === entry.goal_id
      && authority.task_id === entry.task_id
      && authority.evidence_id === entry.evidence_id
      && authority.event_id === entry.event_id
      && authority.event_input_sha256 === entry.event_input_sha256
      && authority.prepared_accepted_at === entry.accepted_at
      && source.created_at === entry.accepted_at
      && producer
      && producer.role === incidentEvent.actor.role
      && producer.thread_id === incidentEvent.actor.thread_id
      && producer.host_id === incidentEvent.actor.host_id
      && Number.isSafeInteger(producer.attempt)
      && typeof producer.lease_until === 'string'
      && Number.isFinite(Date.parse(producer.lease_until))
      && Date.parse(entry.accepted_at) <= Date.parse(producer.lease_until)
      && typeof producer.capability_file === 'string'
      && /^[0-9a-f]{64}$/.test(producer.capability_sha256)
      && anchor
      && anchor.control_epoch === incidentEvent.control_epoch
      && anchor.state_revision === incidentEvent.expected_state_revision
      && hashObject(anchor.packet) === hashObject(incidentEvent.packet)
      && anchor.base_head === incidentEvent.base_head
      && anchor.full_head === incidentEvent.full_head
      && anchor.actor_sequence_key === actorSequenceKey(
        incidentEvent.actor,
      )
      && incidentEvent.actor_sequence === anchor.prior_actor_sequence + 1,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `legacy identity incident ${entry.evidence_id} source context binding 非法`,
  );
  return source;
}

function readLegacyIdentityContextJson(file, label) {
  assertControl(
    fs.existsSync(file)
      && fs.statSync(file).isFile()
      && !fs.lstatSync(file).isSymbolicLink(),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `${label} 不存在或不是普通文件`,
  );
  return readJson(file, label);
}

function validateLegacyIdentityIncidentEntryContext(
  root,
  entry,
  source,
) {
  const goalId = safeId(entry.goal_id, 'legacy identity goal_id');
  const taskId = safeId(entry.task_id, 'legacy identity task_id');
  const evidenceId = safeId(
    entry.evidence_id,
    'legacy identity evidence_id',
  );
  const parentEvidenceId = safeId(
    entry.parent_evidence_id,
    'legacy identity parent evidence_id',
  );
  const event = acceptedEventFiles(root, goalId, taskId)
    .map((file) => readJson(
      file,
      `legacy identity accepted event ${path.basename(file)}`,
    ))
    .filter((candidate) => candidate.event_id === entry.event_id);
  assertControl(
    event.length === 1,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `legacy identity accepted event ${entry.event_id} 缺失或重复`,
  );
  const stored = event[0];
  const unsignedStored = { ...stored };
  delete unsignedStored.event_sha256;
  const incidentEvent = source.incident_event;
  const evidence = readLegacyIdentityContextJson(
    path.join(
      root,
      'goals',
      goalId,
      'evidence',
      taskId,
      `${evidenceId}.json`,
    ),
    `legacy identity evidence ${evidenceId}`,
  );
  const unsignedEvidence = { ...evidence };
  delete unsignedEvidence.registry_sha256;
  const failed = Array.isArray(evidence.checks)
    ? evidence.checks.filter((check) => check.status === 'FAIL')
    : [];
  const eventEvidenceRegistrySha256 = hashObject({
    [evidenceId]: entry.registry_sha256,
  });
  assertControl(
    stored.event_sha256 === hashObject(unsignedStored)
      && normalizeHash(stored.input_sha256) === entry.event_input_sha256
      && normalizeHash(stored.event_sha256) === entry.event_sha256
      && stored.accepted_at === entry.accepted_at
      && hashObject(stored.actor) === entry.actor_sha256
      && hashObject(stored.actor) === hashObject(incidentEvent.actor)
      && hashObject(stored.payload) === hashObject(incidentEvent.payload)
      && (
        stored.evidence_registry_sha256 === undefined
          || normalizeHash(stored.evidence_registry_sha256)
            === entry.event_evidence_registry_sha256
      )
      && entry.event_evidence_registry_sha256
        === eventEvidenceRegistrySha256
      && evidence.registry_sha256 === hashObject(unsignedEvidence)
      && normalizeHash(evidence.registry_sha256) === entry.registry_sha256
      && normalizeHash(evidence.source_sha256) === entry.source_sha256
      && evidence.goal_id === goalId
      && evidence.task_id === taskId
      && evidence.evidence_id === evidenceId
      && evidence.kind === 'HOLD_ASSERTION'
      && evidence.stage === 'PREFLIGHT'
      && evidence.status === 'BLOCKED'
      && evidence.launch_id === entry.launch_id
      && evidence.producer
      && evidence.producer.role === stored.actor.role
      && evidence.producer.thread_id === stored.actor.thread_id
      && evidence.producer.host_id === stored.actor.host_id
      && evidence.created_at === entry.accepted_at
      && evidence.state_revision === incidentEvent.expected_state_revision
      && hashObject(evidence.packet) === hashObject(incidentEvent.packet)
      && normalizeHash(evidence.packet_sha256)
        === normalizeHash(incidentEvent.packet.sha256)
      && evidence.base_head === incidentEvent.base_head
      && evidence.full_head === incidentEvent.full_head
      && failed.length > 0
      && hashObject(failed) === hashObject(source.request.checks),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `legacy identity incident ${entry.evidence_id} event/evidence binding 非法`,
  );
  const parent = readLegacyIdentityContextJson(
    path.join(
      root,
      'goals',
      goalId,
      'evidence',
      taskId,
      `${parentEvidenceId}.json`,
    ),
    `legacy identity parent PREFLIGHT ${parentEvidenceId}`,
  );
  const unsignedParent = { ...parent };
  delete unsignedParent.registry_sha256;
  const parentFailures = Array.isArray(parent.checks)
    ? parent.checks.filter((check) => check.status === 'FAIL')
    : [];
  assertControl(
    parent.registry_sha256 === hashObject(unsignedParent)
      && normalizeHash(parent.registry_sha256)
        === entry.parent_registry_sha256
      && parent.schema_version === 1
      && parent.goal_id === goalId
      && parent.task_id === taskId
      && parent.evidence_id === parentEvidenceId
      && parent.kind === 'PREFLIGHT'
      && parent.status === 'FAIL'
      && parent.launch_id === entry.launch_id
      && parent.producer
      && parent.producer.role === stored.actor.role
      && parent.producer.thread_id === stored.actor.thread_id
      && parent.producer.host_id === stored.actor.host_id
      && parent.attestation
      && parent.attestation.controller === 'goalctl'
      && parent.attestation.adapter === 'PREFLIGHT'
      && parent.state_revision === incidentEvent.expected_state_revision
      && hashObject(parent.packet) === hashObject(incidentEvent.packet)
      && normalizeHash(parent.packet_sha256)
        === normalizeHash(incidentEvent.packet.sha256)
      && parent.base_head === incidentEvent.base_head
      && hashObject(parentFailures) === hashObject(source.request.checks)
      && normalizeHash(parent.launch_sha256)
        === entry.candidate_launch_sha256,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `legacy identity incident ${entry.evidence_id} parent PREFLIGHT binding 非法`,
  );
  let candidateFile;
  try {
    const candidateUrl = new URL(parent.launch_uri);
    assertControl(
      candidateUrl.protocol === 'file:',
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      'legacy identity candidate launch 必须是 sealed file',
    );
    candidateFile = fileURLToPath(candidateUrl);
  } catch (error) {
    if (error instanceof ControlError) throw error;
    assertControl(
      false,
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      `legacy identity candidate launch URI 非法: ${error.message}`,
    );
  }
  const expectedCandidateFile = path.join(
    root,
    'goals',
    goalId,
    'evidence-artifacts',
    taskId,
    `${parentEvidenceId}-launch.json`,
  );
  assertControl(
    fs.existsSync(candidateFile)
      && fs.existsSync(expectedCandidateFile)
      && fs.statSync(candidateFile).isFile()
      && !fs.lstatSync(candidateFile).isSymbolicLink()
      && fs.statSync(expectedCandidateFile).isFile()
      && !fs.lstatSync(expectedCandidateFile).isSymbolicLink()
      && fs.realpathSync(candidateFile)
        === fs.realpathSync(expectedCandidateFile)
      && hashFile(candidateFile) === entry.candidate_launch_sha256,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `legacy identity incident ${entry.evidence_id} candidate artifact binding 非法`,
  );
  const { validateLaunchManifest } = require('./validation');
  const candidate = validateLaunchManifest(
    readJson(
      candidateFile,
      `legacy identity candidate ${parentEvidenceId}`,
    ),
  );
  const canonicalFile = canonicalRuntimeLaunchFile(
    root,
    goalId,
    taskId,
    entry.launch_id,
  );
  const canonical = validateLaunchManifest(
    readLegacyIdentityContextJson(
      canonicalFile,
      `legacy identity canonical launch ${entry.launch_id}`,
    ),
  );
  assertControl(
    candidate.goal_id === goalId
      && candidate.task_id === taskId
      && candidate.launch_id === entry.launch_id
      && candidate.role === stored.actor.role
      && candidate.thread.id === stored.actor.thread_id
      && (candidate.thread.host_id || 'local') === stored.actor.host_id
      && canonical.goal_id === candidate.goal_id
      && canonical.task_id === candidate.task_id
      && canonical.launch_id === candidate.launch_id
      && canonical.role === candidate.role
      && canonical.thread.id === candidate.thread.id
      && (canonical.thread.host_id || 'local')
        === (candidate.thread.host_id || 'local')
      && canonical.control_epoch === candidate.control_epoch
      && canonical.state_revision === candidate.state_revision
      && hashObject(canonical.packet) === hashObject(candidate.packet)
      && canonical.repository.base_head === candidate.repository.base_head
      && canonical.execution.task_nonce
        === candidate.execution.task_nonce
      && parentCandidateHeadBinding(
        parent,
        candidate,
        parentFailures,
        canonical,
      ),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `legacy identity incident ${entry.evidence_id} candidate launch context 非法`,
  );
}

function validateLegacyIdentityIncidentReceipt(
  receipt,
  { root = null } = {},
) {
  const allowedKeys = [
    'schema_version',
    'kind',
    'controller_decoder_sha256',
    'source_state_vector_sha256',
    'predecessor_protocol_seal_sha256',
    'migration_receipt',
    'incidents',
    'incidents_sha256',
    'sources',
    'sources_sha256',
    'receipt_sha256',
  ];
  const unsignedReceipt = receipt && { ...receipt };
  if (unsignedReceipt) delete unsignedReceipt.receipt_sha256;
  assertControl(
    receipt
      && typeof receipt === 'object'
      && !Array.isArray(receipt)
      && Object.keys(receipt).length === allowedKeys.length
      && Object.keys(receipt).every((key) => allowedKeys.includes(key))
      && receipt.schema_version === 1
      && receipt.kind === 'LEGACY_IDENTITY_INCIDENT_BINDINGS'
      && receipt.receipt_sha256 === hashObject(unsignedReceipt)
      && receipt.incidents
      && typeof receipt.incidents === 'object'
      && !Array.isArray(receipt.incidents)
      && receipt.incidents_sha256 === hashObject(receipt.incidents)
      && receipt.sources
      && typeof receipt.sources === 'object'
      && !Array.isArray(receipt.sources)
      && receipt.sources_sha256 === hashObject(receipt.sources)
      && receipt.migration_receipt
      && typeof receipt.migration_receipt === 'object'
      && !Array.isArray(receipt.migration_receipt)
      && Object.keys(receipt.migration_receipt).length === 2
      && typeof receipt.migration_receipt.incident_ref === 'string'
      && receipt.migration_receipt.incident_ref.length > 0
      && receipt.migration_receipt.old_controller_drain_ack
        === 'ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED'
      && SHA256_PATTERN.test(
        receipt.controller_decoder_sha256,
      )
      && SHA256_PATTERN.test(
        receipt.source_state_vector_sha256,
      )
      && (
        receipt.predecessor_protocol_seal_sha256 === null
          || SHA256_PATTERN.test(
            receipt.predecessor_protocol_seal_sha256,
          )
      ),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'legacy identity incident receipt seal 非法',
  );
  let sourceBytes = 0;
  const referencedSources = new Set();
  const evidenceKeys = new Set();
  const eventKeys = new Set();
  for (const [key, entry] of Object.entries(receipt.incidents)) {
    const unsignedEntry = entry && { ...entry };
    if (unsignedEntry) delete unsignedEntry.entry_sha256;
    const stringFields = [
      'goal_id',
      'task_id',
      'hold_id',
      'evidence_id',
      'event_id',
      'launch_id',
      'parent_evidence_id',
    ];
    const hashFields = [
      'source_sha256',
      'registry_sha256',
      'event_input_sha256',
      'event_sha256',
      'event_evidence_registry_sha256',
      'actor_sha256',
      'parent_registry_sha256',
      'candidate_launch_sha256',
      'authority_sha256',
      'entry_sha256',
    ];
    const evidenceKey = entry
      && `${entry.goal_id}/${entry.task_id}/${entry.evidence_id}`;
    const eventKey = entry
      && `${entry.goal_id}/${entry.task_id}/${entry.event_id}`;
    assertControl(
      hasExactKeys(entry, LEGACY_IDENTITY_INCIDENT_ENTRY_KEYS)
        && entry.schema_version === 1
        && stringFields.every((field) => (
          typeof entry[field] === 'string' && entry[field].length > 0
        ))
        && hashFields.every((field) => SHA256_PATTERN.test(entry[field]))
        && typeof entry.accepted_at === 'string'
        && Number.isFinite(Date.parse(entry.accepted_at))
        && key === `${entry.goal_id}/${entry.task_id}/${entry.hold_id}`
        && entry.entry_sha256 === hashObject(unsignedEntry)
        && !evidenceKeys.has(evidenceKey)
        && !eventKeys.has(eventKey)
        && Object.prototype.hasOwnProperty.call(
          receipt.sources,
          entry.source_sha256,
        ),
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      `legacy identity incident entry ${key} binding 非法`,
    );
    const sourceBody = Buffer.from(
      receipt.sources[entry.source_sha256],
      'base64',
    );
    assertControl(
      sourceBody.toString('base64')
          === receipt.sources[entry.source_sha256]
        && `sha256:${sha256(sourceBody)}` === entry.source_sha256,
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      `legacy identity incident entry ${key} source hash 非法`,
    );
    const source = validateLegacyIdentityIncidentEntrySource(
      entry,
      sourceBody,
    );
    if (root !== null) {
      validateLegacyIdentityIncidentEntryContext(root, entry, source);
    }
    evidenceKeys.add(evidenceKey);
    eventKeys.add(eventKey);
    referencedSources.add(entry.source_sha256);
  }
  for (const [digest, bodyBase64] of Object.entries(receipt.sources)) {
    const body = typeof bodyBase64 === 'string'
      ? Buffer.from(bodyBase64, 'base64')
      : Buffer.alloc(0);
    assertControl(
      SHA256_PATTERN.test(digest)
        && typeof bodyBase64 === 'string'
        && body.toString('base64') === bodyBase64
        && `sha256:${sha256(body)}` === digest
        && referencedSources.has(digest),
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      'legacy identity incident source binding 非法',
    );
    sourceBytes += body.length;
  }
  assertControl(
    sourceBytes <= IDENTITY_INCIDENT_SOURCE_MAX_BYTES,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'legacy identity incident source 闭集超过大小上限',
  );
  return receipt;
}

function protocolSealedLegacyIdentityIncidentReceipts(root) {
  const receipts = [];
  const sealedRotations = readProtocolSealedRotationReceipts(root);
  const migrationArtifact = readProtocolSealedMigrationArtifact(
    root,
    LEGACY_IDENTITY_INCIDENT_RECEIPT_RELATIVE_PATH,
  );
  if (migrationArtifact) {
    try {
      const receipt = validateLegacyIdentityIncidentReceipt(
        JSON.parse(migrationArtifact.body.toString('utf8')),
        { root },
      );
      const anchorArtifact = readProtocolSealedMigrationArtifact(
        root,
        LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
      );
      const anchor = anchorArtifact
        ? JSON.parse(anchorArtifact.body.toString('utf8'))
        : null;
      const originControllerDecoderSha256 = sealedRotations.length > 0
        ? sealedRotations[0].receipt.predecessor_protocol
          .controller_decoder_sha256
        : migrationArtifact.protocol.controller_decoder_sha256;
      assertControl(
        receipt.controller_decoder_sha256
            === originControllerDecoderSha256
          && receipt.source_state_vector_sha256
            === migrationArtifact.protocol
              .migration_source_state_vector_sha256
          && receipt.predecessor_protocol_seal_sha256 === null
          && anchor
          && anchor.source_state_vector_sha256
            === receipt.source_state_vector_sha256
          && anchor.migration_receipt
          && anchor.migration_receipt.incident_ref
            === receipt.migration_receipt.incident_ref
          && anchor.migration_receipt.old_controller_drain_ack
            === receipt.migration_receipt.old_controller_drain_ack,
        'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
        'adoption identity receipt 与 root protocol/evidence anchor 上下文不匹配',
      );
      receipts.push(receipt);
    } catch (error) {
      if (error && error.code === 'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN') {
        throw error;
      }
      assertControl(
        false,
        'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
        `protocol-sealed legacy identity receipt 无法解析: ${error.message}`,
      );
    }
  }
  for (const { receipt: outer } of sealedRotations) {
    const candidate = outer
      && outer.validation_report
      && outer.validation_report.legacy_identity_incident_receipt;
    if (candidate) {
      const receipt = validateLegacyIdentityIncidentReceipt(
        candidate,
        { root },
      );
      assertControl(
        receipt.source_state_vector_sha256
            === outer.source_state_vector_sha256
          && receipt.controller_decoder_sha256
            === outer.successor_protocol.controller_decoder_sha256
          && receipt.predecessor_protocol_seal_sha256
            === outer.predecessor_protocol.seal_sha256
          && receipt.migration_receipt.incident_ref
            === outer.incident_ref
          && receipt.migration_receipt.old_controller_drain_ack
            === outer.old_controller_drain_ack,
        'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
        'rotation identity receipt 与 outer protocol rotation 上下文不匹配',
      );
      receipts.push(receipt);
    }
  }
  const deduplicated = new Map();
  for (const receipt of receipts) {
    deduplicated.set(receipt.receipt_sha256, receipt);
  }
  return [...deduplicated.values()];
}

function identityIncidentCoreMatches(
  entry,
  state,
  goalId,
  hold,
) {
  return entry
    && entry.goal_id === goalId
    && entry.task_id === state.task_id
    && entry.hold_id === hold.hold_id
    && entry.evidence_id === hold.evidence.evidence_id
    && normalizeHash(entry.source_sha256)
      === normalizeHash(hold.evidence.source_sha256)
    && normalizeHash(entry.registry_sha256)
      === normalizeHash(hold.evidence.registry_sha256);
}

function readProtocolSealedLegacyEvidenceSource(
  root,
  state,
  goalId,
  hold,
) {
  const anchorArtifact = readProtocolSealedMigrationArtifact(
    root,
    LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
  );
  if (!anchorArtifact) return null;
  let index;
  try {
    index = JSON.parse(anchorArtifact.body.toString('utf8'));
  } catch (error) {
    assertControl(
      false,
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      `protocol-sealed legacy evidence index 无法解析: ${error.message}`,
    );
  }
  const unsignedIndex = { ...index };
  delete unsignedIndex.index_sha256;
  const evidenceKey =
    `${goalId}/${state.task_id}/${hold.evidence.evidence_id}`;
  const semantic = index.semantic_sources
    && index.semantic_sources[evidenceKey];
  if (semantic === undefined) return null;
  const sourceSha256 = normalizeHash(hold.evidence.source_sha256);
  const registrySha256 = normalizeHash(hold.evidence.registry_sha256);
  const expectedArtifact =
    `${LEGACY_EVIDENCE_SOURCE_DIRECTORY}/${sourceSha256.slice('sha256:'.length)}.artifact`;
  assertControl(
    index
      && index.schema_version === 1
      && index.kind === 'LEGACY_EVIDENCE_EVENT_BINDINGS'
      && index.index_sha256 === hashObject(unsignedIndex)
      && index.migration_receipt
      && index.migration_receipt.old_controller_drain_ack
        === 'ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED'
      && semantic
      && semantic.goal_id === goalId
      && semantic.task_id === state.task_id
      && semantic.evidence_id === hold.evidence.evidence_id
      && normalizeHash(semantic.registry_sha256) === registrySha256
      && normalizeHash(semantic.source_sha256) === sourceSha256
      && semantic.artifact_path === expectedArtifact,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'legacy identity incident evidence 不在 protocol-sealed migration 闭集',
  );
  const sourceArtifact = readProtocolSealedMigrationArtifact(
    root,
    expectedArtifact,
  );
  assertControl(
    sourceArtifact
      && sourceArtifact.descriptor.sha256 === sourceSha256,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'legacy identity incident source artifact 未被 root protocol seal',
  );
  return sourceArtifact.body;
}

function readIdentityIncidentSourceBytes(
  root,
  state,
  goalId,
  hold,
) {
  let directSourceMissing = false;
  try {
    const source = new URL(hold.evidence.uri);
    assertControl(
      source.protocol === 'file:',
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      'launch identity incident source 必须是 sealed file',
    );
    const sourceFile = fileURLToPath(source);
    let before;
    try {
      before = fs.lstatSync(sourceFile);
    } catch (error) {
      if (error && ['ENOENT', 'ENOTDIR'].includes(error.code)) {
        directSourceMissing = true;
      } else {
        throw error;
      }
    }
    if (directSourceMissing) throw new ControlError(
      'IDENTITY_INCIDENT_SOURCE_MISSING',
      `launch identity incident source 不存在: ${sourceFile}`,
    );
    assertControl(
      before.isFile()
        && !before.isSymbolicLink()
        && before.size <= IDENTITY_INCIDENT_SOURCE_MAX_BYTES,
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      'launch identity incident source 必须是有界非 symlink 普通文件',
    );
    const body = fs.readFileSync(sourceFile);
    const after = fs.lstatSync(sourceFile);
    assertControl(
      after.isFile()
        && !after.isSymbolicLink()
        && before.dev === after.dev
        && before.ino === after.ino
        && before.size === after.size
        && before.mtimeMs === after.mtimeMs
        && body.length === before.size
        && `sha256:${sha256(body)}`
          === normalizeHash(hold.evidence.source_sha256),
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      'launch identity incident source 在读取期间变化或 hash 漂移',
    );
    return body;
  } catch (error) {
    if (
      !directSourceMissing
        || !error
        || error.code !== 'IDENTITY_INCIDENT_SOURCE_MISSING'
    ) {
      if (error instanceof ControlError) throw error;
      throw new ControlError(
        'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
        `launch identity incident source 无法读取: ${error.message}`,
      );
    }
    // A drained legacy controller may no longer retain the original URI.
  }
  const legacyBody = readProtocolSealedLegacyEvidenceSource(
    root,
    state,
    goalId,
    hold,
  );
  if (legacyBody) return legacyBody;
  const key = `${goalId}/${state.task_id}/${hold.hold_id}`;
  const sourceSha256 = normalizeHash(hold.evidence.source_sha256);
  for (const receipt of protocolSealedLegacyIdentityIncidentReceipts(root)) {
    const entry = receipt.incidents[key];
    const bodyBase64 = receipt.sources[sourceSha256];
    if (
      identityIncidentCoreMatches(entry, state, goalId, hold)
        && typeof bodyBase64 === 'string'
    ) {
      return Buffer.from(bodyBase64, 'base64');
    }
  }
  assertControl(
    false,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'launch identity incident source 不在 URI 或 protocol-sealed legacy 闭集',
  );
}

function readProtocolSealedIdentityIncidentEvidenceSource(
  root,
  record,
  { allowNoBinding = false } = {},
) {
  const matches = [];
  for (const receipt of protocolSealedLegacyIdentityIncidentReceipts(root)) {
    for (const entry of Object.values(receipt.incidents)) {
      if (
        entry
          && entry.goal_id === record.goal_id
          && entry.task_id === record.task_id
          && entry.evidence_id === record.evidence_id
          && normalizeHash(entry.registry_sha256)
            === normalizeHash(record.registry_sha256)
          && normalizeHash(entry.source_sha256)
            === normalizeHash(record.source_sha256)
      ) {
        const bodyBase64 = receipt.sources[entry.source_sha256];
        assertControl(
          typeof bodyBase64 === 'string',
          'LEGACY_EVIDENCE_SOURCE_MISMATCH',
          `identity incident ${record.evidence_id} receipt 缺 source bytes`,
        );
        matches.push({
          entry,
          body: Buffer.from(bodyBase64, 'base64'),
        });
      }
    }
  }
  if (matches.length === 0 && allowNoBinding) return null;
  assertControl(
    matches.length > 0,
    'LEGACY_EVIDENCE_SOURCE_MISMATCH',
    `identity incident ${record.evidence_id} 缺 protocol-rotation source binding`,
  );
  const first = matches[0];
  assertControl(
    matches.every((match) => (
      match.entry.entry_sha256 === first.entry.entry_sha256
        && match.body.equals(first.body)
    ))
      && `sha256:${sha256(first.body)}`
        === normalizeHash(record.source_sha256),
    'LEGACY_EVIDENCE_SOURCE_MISMATCH',
    `identity incident ${record.evidence_id} rotation receipts 冲突`,
  );
  return first.body;
}

function validateProtocolSealedLegacyIdentityIncidentReceipts(root) {
  protocolSealedLegacyIdentityIncidentReceipts(root);
}

function legacyIdentityIncidentReceiptAllows(
  root,
  state,
  goalId,
  hold,
  sealed,
  stored,
) {
  try {
    const parentEvidenceId = safeId(
      sealed.request.parent_evidence_id,
      'legacy identity parent evidence',
    );
    const parentFile = path.join(
      root,
      'goals',
      goalId,
      'evidence',
      state.task_id,
      `${parentEvidenceId}.json`,
    );
    const parent = readJson(
      parentFile,
      `legacy identity parent PREFLIGHT ${parentEvidenceId}`,
    );
    const evidenceRegistryDigest = hashObject({
      [hold.evidence.evidence_id]:
        normalizeHash(hold.evidence.registry_sha256),
    });
    const unsignedEntry = {
      schema_version: 1,
      goal_id: goalId,
      task_id: state.task_id,
      hold_id: hold.hold_id,
      evidence_id: hold.evidence.evidence_id,
      source_sha256: normalizeHash(hold.evidence.source_sha256),
      registry_sha256: normalizeHash(hold.evidence.registry_sha256),
      event_id: stored.event_id,
      event_input_sha256: normalizeHash(stored.input_sha256),
      event_sha256: normalizeHash(stored.event_sha256),
      event_evidence_registry_sha256: evidenceRegistryDigest,
      accepted_at: stored.accepted_at,
      actor_sha256: hashObject(hold.raised_by),
      launch_id: sealed.request.launch_id,
      parent_evidence_id: parentEvidenceId,
      parent_registry_sha256: normalizeHash(parent.registry_sha256),
      candidate_launch_sha256: normalizeHash(parent.launch_sha256),
      authority_sha256: normalizeHash(
        sealed.event_authority.authority_sha256,
      ),
    };
    const expectedEntry = {
      ...unsignedEntry,
      entry_sha256: hashObject(unsignedEntry),
    };
    const key = `${goalId}/${state.task_id}/${hold.hold_id}`;
    return protocolSealedLegacyIdentityIncidentReceipts(root)
      .some((receipt) => (
        canonicalJson(receipt.incidents[key])
          === canonicalJson(expectedEntry)
      ));
  } catch {
    return false;
  }
}

function legacyPreparedIdentityIncidentAllowed(
  root,
  state,
  goalId,
  hold,
  sealed,
  stored,
) {
  if (
    legacyIdentityIncidentReceiptAllows(
      root,
      state,
      goalId,
      hold,
      sealed,
      stored,
    )
  ) {
    return true;
  }
  const parentEvidenceId = sealed
    && sealed.request
    && sealed.request.parent_evidence_id;
  if (typeof parentEvidenceId !== 'string') return false;
  const incidentDigest = sha256(parentEvidenceId).slice(0, 32);
  if (
    hold.evidence.evidence_id !== `env-incident-${incidentDigest}`
      || hold.hold_id !== `env-hold-${incidentDigest}`
      || stored.event_id !== `env-identity-hold-${incidentDigest}`
  ) {
    return false;
  }
  try {
    const anchorArtifact = readProtocolSealedMigrationArtifact(
      root,
      LEGACY_EVIDENCE_ANCHOR_RELATIVE_PATH,
    );
    if (!anchorArtifact) return false;
    const index = JSON.parse(anchorArtifact.body.toString('utf8'));
    const unsignedIndex = { ...index };
    delete unsignedIndex.index_sha256;
    assertControl(
      index
        && index.schema_version === 1
        && index.kind === 'LEGACY_EVIDENCE_EVENT_BINDINGS'
        && index.index_sha256 === hashObject(unsignedIndex)
        && index.migration_receipt
        && index.migration_receipt.old_controller_drain_ack
          === 'ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED'
        && /^sha256:[0-9a-f]{64}$/.test(
          index.source_state_vector_sha256,
        )
        && index.semantic_sources
        && typeof index.semantic_sources === 'object',
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      'legacy identity incident anchor index 非法',
    );
    const evidenceKey =
      `${goalId}/${state.task_id}/${hold.evidence.evidence_id}`;
    const semantic = index.semantic_sources[evidenceKey];
    const sourceSha256 = normalizeHash(hold.evidence.source_sha256);
    const registrySha256 = normalizeHash(hold.evidence.registry_sha256);
    const expectedArtifact =
      `${LEGACY_EVIDENCE_SOURCE_DIRECTORY}/${sourceSha256.slice('sha256:'.length)}.artifact`;
    const sourceArtifact = readProtocolSealedMigrationArtifact(
      root,
      expectedArtifact,
    );
    assertControl(
      semantic
        && semantic.goal_id === goalId
        && semantic.task_id === state.task_id
        && semantic.evidence_id === hold.evidence.evidence_id
        && normalizeHash(semantic.registry_sha256) === registrySha256
        && normalizeHash(semantic.source_sha256) === sourceSha256
        && semantic.artifact_path === expectedArtifact
        && sourceArtifact
        && sourceArtifact.descriptor.sha256 === sourceSha256,
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      'legacy identity incident evidence 不在 drained controller 闭集',
    );
    const evidenceRegistryDigest = hashObject({
      [hold.evidence.evidence_id]: registrySha256,
    });
    const eventKey =
      `${goalId}/${state.task_id}/${stored.event_id}`;
    const eventAnchor = index.events && index.events[eventKey];
    if (eventAnchor) {
      assertControl(
        eventAnchor.goal_id === goalId
          && eventAnchor.task_id === state.task_id
          && eventAnchor.event_id === stored.event_id
          && normalizeHash(eventAnchor.input_sha256)
            === stored.input_sha256
          && normalizeHash(eventAnchor.event_sha256)
            === stored.event_sha256
          && normalizeHash(eventAnchor.evidence_registry_sha256)
            === evidenceRegistryDigest,
        'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
        'legacy identity incident accepted event anchor 漂移',
      );
    } else {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function readAcceptedIdentityIncidentEvent(
  root,
  state,
  goalId,
  session,
  hold,
  sealed,
  {
    requireProvenance = true,
    acceptedEvent = null,
  } = {},
) {
  const incidentEvent = sealed.incident_event;
  const authority = sealed.event_authority;
  const unsignedAuthority = authority && { ...authority };
  if (unsignedAuthority) delete unsignedAuthority.authority_sha256;
  const producer = authority && authority.producer;
  const anchor = authority && authority.task_anchor;
  assertControl(
    incidentEvent
      && authority
      && authority.kind === 'IDENTITY_INCIDENT_EVENT_AUTHORITY'
      && authority.authority_sha256 === hashObject(unsignedAuthority)
      && authority.goal_id === goalId
      && authority.task_id === state.task_id
      && authority.evidence_id === hold.evidence.evidence_id
      && authority.event_id === incidentEvent.event_id
      && authority.event_input_sha256 === hashObject(incidentEvent)
      && authority.prepared_accepted_at === sealed.created_at
      && incidentEvent.goal_id === goalId
      && incidentEvent.task_id === state.task_id
      && incidentEvent.type === 'ADD_HOLD'
      && incidentEvent.payload
      && incidentEvent.payload.kind === 'ENV_IDENTITY_INCIDENT'
      && incidentEvent.payload.hold_id === hold.hold_id
      && incidentEvent.payload.evidence_id === hold.evidence.evidence_id
      && hashObject(incidentEvent.actor) === hashObject(hold.raised_by)
      && producer
      && producer.role === incidentEvent.actor.role
      && producer.thread_id === incidentEvent.actor.thread_id
      && producer.host_id === incidentEvent.actor.host_id
      && producer.role === session.role
      && producer.thread_id === session.thread_id
      && producer.host_id === session.host_id
      && producer.attempt === session.attempt
      && typeof producer.lease_until === 'string'
      && Number.isFinite(Date.parse(producer.lease_until))
      && Date.parse(authority.prepared_accepted_at)
        <= Date.parse(producer.lease_until)
      && typeof producer.capability_file === 'string'
      && /^[0-9a-f]{64}$/.test(producer.capability_sha256)
      && (
        session.capability_file === undefined
          || session.capability_file === producer.capability_file
      )
      && (
        session.capability_sha256 === undefined
          || session.capability_sha256 === producer.capability_sha256
      )
      && anchor
      && anchor.control_epoch === incidentEvent.control_epoch
      && anchor.state_revision === incidentEvent.expected_state_revision
      && hashObject(anchor.packet) === hashObject(incidentEvent.packet)
      && anchor.base_head === incidentEvent.base_head
      && anchor.full_head === incidentEvent.full_head
      && anchor.actor_sequence_key === actorSequenceKey(incidentEvent.actor)
      && incidentEvent.actor_sequence === anchor.prior_actor_sequence + 1,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'launch identity incident 缺完整 controller event authority binding',
  );
  const accepted = acceptedEvent
    ? [acceptedEvent]
    : acceptedEventFiles(
      root,
      goalId,
      state.task_id,
    ).map((file) => readJson(
      file,
      `launch identity accepted event ${path.basename(file)}`,
    )).filter((candidate) => (
      candidate.event_id === incidentEvent.event_id
    ));
  assertControl(
    accepted.length === 1,
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `identity incident accepted event ${incidentEvent.event_id} 缺失或重复`,
  );
  const stored = accepted[0];
  const unsignedStored = { ...stored };
  delete unsignedStored.event_sha256;
  const preparedMarker = stored.prepared_identity_incident_authority;
  assertControl(
    stored.event_sha256 === hashObject(unsignedStored)
      && stored.input_sha256 === authority.event_input_sha256
      && stored.accepted_at === authority.prepared_accepted_at
      && hold.raised_at === stored.accepted_at
      && hashObject(stored.actor) === hashObject(incidentEvent.actor)
      && hashObject(stored.payload) === hashObject(incidentEvent.payload),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `identity incident accepted event ${incidentEvent.event_id} authority 漂移`,
  );
  const preparedMarkerMatches = preparedMarker
    && preparedMarker.schema_version === 1
    && preparedMarker.evidence_id === hold.evidence.evidence_id
    && preparedMarker.authority_sha256 === authority.authority_sha256;
  if (requireProvenance) {
    assertControl(
      preparedMarkerMatches
        || legacyPreparedIdentityIncidentAllowed(
          root,
          state,
          goalId,
          hold,
          sealed,
          stored,
        ),
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      `identity incident accepted event ${incidentEvent.event_id} 缺 prepared marker 或 drained legacy receipt`,
    );
  }
  return {
    stored,
    preparedMarker,
    preparedMarkerMatches: Boolean(preparedMarkerMatches),
  };
}

function readControllerIncidentCandidate(
  root,
  state,
  goalId,
  session,
  hold,
  failed,
  {
    requireProvenance = true,
    acceptedEvent = null,
  } = {},
) {
  let sealed;
  try {
    sealed = JSON.parse(
      readIdentityIncidentSourceBytes(
        root,
        state,
        goalId,
        hold,
      ).toString('utf8'),
    );
  } catch (error) {
    if (
      error
        && error.code === 'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN'
    ) {
      throw error;
    }
    assertControl(
      false,
      'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
      `launch identity incident source 无法解析: ${error.message}`,
    );
  }
  assertControl(
    sealed
      && sealed.controller === 'goalctl'
      && sealed.adapter === 'PREFLIGHT_IDENTITY_INCIDENT'
      && hold.evidence.kind === 'HOLD_ASSERTION'
      && hold.evidence.stage === 'PREFLIGHT'
      && hold.evidence.status === 'BLOCKED'
      && sealed.request
      && sealed.request.goal_id === goalId
      && sealed.request.task_id === state.task_id
      && sealed.request.launch_id === session.launch_id
      && hashObject(sealed.request.checks) === hashObject(failed),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'launch identity incident 缺 exact controller request binding',
  );
  readAcceptedIdentityIncidentEvent(
    root,
    state,
    goalId,
    session,
    hold,
    sealed,
    { requireProvenance, acceptedEvent },
  );

  const parentEvidenceId = safeId(
    sealed.request.parent_evidence_id,
    'parent preflight evidence',
  );
  const parentFile = path.join(
    root,
    'goals',
    safeId(goalId, 'goal_id'),
    'evidence',
    safeId(state.task_id, 'task_id'),
    `${parentEvidenceId}.json`,
  );
  assertControl(
    fs.existsSync(parentFile)
      && fs.statSync(parentFile).isFile()
      && !fs.lstatSync(parentFile).isSymbolicLink(),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `parent PREFLIGHT ${parentEvidenceId} 不存在`,
  );
  const parent = readJson(
    parentFile,
    `launch identity parent PREFLIGHT ${parentEvidenceId}`,
  );
  const unsignedParent = { ...parent };
  delete unsignedParent.registry_sha256;
  const parentFailures = Array.isArray(parent.checks)
    ? parent.checks.filter((check) => check.status === 'FAIL')
    : [];
  assertControl(
    parent.registry_sha256 === hashObject(unsignedParent)
      && parent.schema_version === 1
      && parent.evidence_id === parentEvidenceId
      && parent.goal_id === goalId
      && parent.task_id === state.task_id
      && parent.kind === 'PREFLIGHT'
      && parent.status === 'FAIL'
      && parent.launch_id === session.launch_id
      && parent.producer
      && parent.producer.role === session.role
      && parent.producer.thread_id === session.thread_id
      && (parent.producer.host_id || 'local') === session.host_id
      && parent.attestation
      && parent.attestation.controller === 'goalctl'
      && parent.attestation.adapter === 'PREFLIGHT'
      && parent.packet
      && parent.packet.revision === state.packet.revision
      && normalizeHash(parent.packet.sha256) === state.packet.sha256
      && normalizeHash(parent.packet_sha256) === state.packet.sha256
      && parent.base_head === state.base_head
      && hashObject(parentFailures) === hashObject(failed),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    `parent PREFLIGHT ${parentEvidenceId} registry/binding 非法`,
  );
  const candidateUrl = new URL(parent.launch_uri);
  assertControl(
    candidateUrl.protocol === 'file:',
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'candidate launch artifact 必须是 sealed file',
  );
  const candidateFile = fileURLToPath(candidateUrl);
  const expectedCandidateFile = path.join(
    root,
    'goals',
    goalId,
    'evidence-artifacts',
    state.task_id,
    `${parentEvidenceId}-launch.json`,
  );
  assertControl(
    fs.existsSync(candidateFile)
      && fs.existsSync(expectedCandidateFile)
      && fs.statSync(candidateFile).isFile()
      && !fs.lstatSync(candidateFile).isSymbolicLink()
      && fs.statSync(expectedCandidateFile).isFile()
      && !fs.lstatSync(expectedCandidateFile).isSymbolicLink()
      && fs.realpathSync(candidateFile)
        === fs.realpathSync(expectedCandidateFile)
      && hashFile(candidateFile) === normalizeHash(parent.launch_sha256),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'candidate launch 不是 exact deterministic PREFLIGHT artifact',
  );
  const { validateLaunchManifest } = require('./validation');
  const candidate = validateLaunchManifest(
    readJson(candidateFile, `launch identity candidate ${parentEvidenceId}`),
  );
  const canonical = readCanonicalLaunch(root, state, goalId, session);
  assertControl(
    launchMatchesActiveWorker(candidate, state, goalId, session)
      && parentCandidateHeadBinding(
        parent,
        candidate,
        parentFailures,
        canonical,
      ),
    'LAUNCH_HOLD_CLASSIFICATION_UNKNOWN',
    'candidate launch 与 parent evidence/active worker 不匹配',
  );
  return candidate;
}

function createLegacyIdentityIncidentCollector() {
  return {
    incidents: new Map(),
    sources: new Map(),
    skippedSemanticHolds: new Set(),
  };
}

function collectLegacyIdentityIncident(
  root,
  collector,
  state,
  goalId,
  event,
  evidence,
) {
  if (
    event.type !== 'ADD_HOLD'
      || !event.payload
      || event.payload.kind !== 'ENV_IDENTITY_INCIDENT'
  ) {
    return;
  }
  assertControl(
    collector
      && collector.incidents instanceof Map
      && collector.sources instanceof Map
      && collector.skippedSemanticHolds instanceof Set
      && evidence
      && evidence.kind === 'HOLD_ASSERTION',
    'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
    'legacy identity incident collector 非法',
  );
  const hold = {
    hold_id: event.payload.hold_id || event.event_id,
    kind: event.payload.kind,
    hard: true,
    reason: event.payload.reason || '',
    evidence,
    raised_by: event.actor,
    raised_at: event.accepted_at,
    resume_phase: state.phase,
  };
  const failed = Array.isArray(evidence.checks)
    ? evidence.checks.filter((check) => check.status === 'FAIL')
    : [];
  const evidenceDigestMatch =
    /^env-incident-([0-9a-f]{32})$/.exec(
      evidence.evidence_id || '',
    );
  const deterministicControllerShape = Boolean(
    evidenceDigestMatch
      && hold.hold_id === `env-hold-${evidenceDigestMatch[1]}`,
  );
  const preflightIdentityShape =
    evidence.kind === 'HOLD_ASSERTION'
    && evidence.stage === 'PREFLIGHT'
    && failed.some((check) => (
      check.name === 'launch-runtime-binding'
        && typeof check.detail === 'string'
        && check.detail.startsWith('LAUNCH_ID_CONFLICT:')
    ));
  let controllerShaped =
    deterministicControllerShape || preflightIdentityShape;
  const key = `${goalId}/${state.task_id}/${hold.hold_id}`;
  try {
    const sourceBody = readIdentityIncidentSourceBytes(
      root,
      state,
      goalId,
      hold,
    );
    const sealed = JSON.parse(sourceBody.toString('utf8'));
    controllerShaped = controllerShaped || Boolean(
      sealed
        && sealed.controller === 'goalctl'
        && sealed.adapter === 'PREFLIGHT_IDENTITY_INCIDENT',
    );
    const sourceSha256 = normalizeHash(evidence.source_sha256);
    assertControl(
      `sha256:${sha256(sourceBody)}` === sourceSha256,
      'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
      `legacy identity source ${hold.hold_id} hash 漂移`,
    );
    const session = state.sessions
      && state.sessions[event.actor.role];
    assertControl(
      session,
      'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
      `legacy identity event ${event.event_id} 缺 incident-time producer session`,
    );
    const accepted = readAcceptedIdentityIncidentEvent(
      root,
      state,
      goalId,
      session,
      hold,
      sealed,
      {
        requireProvenance: false,
        acceptedEvent: event,
      },
    );
    if (accepted.preparedMarkerMatches) return;
    assertControl(
      accepted.preparedMarker === undefined,
      'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
      `identity incident accepted event ${event.event_id} prepared marker 与 controller authority 不匹配`,
    );
    if (
      legacyIdentityIncidentReceiptAllows(
        root,
        state,
        goalId,
        hold,
        sealed,
        accepted.stored,
      )
    ) {
      return;
    }
    assertControl(
      failed.length > 0,
      'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
      `controller identity incident ${hold.hold_id} 缺 FAIL checks`,
    );
    readControllerIncidentCandidate(
      root,
      state,
      goalId,
      session,
      hold,
      failed,
      {
        requireProvenance: false,
        acceptedEvent: event,
      },
    );
    const parentEvidenceId = safeId(
      sealed.request.parent_evidence_id,
      'legacy identity parent evidence',
    );
    const parent = readJson(
      path.join(
        root,
        'goals',
        goalId,
        'evidence',
        state.task_id,
        `${parentEvidenceId}.json`,
      ),
      `legacy identity parent ${parentEvidenceId}`,
    );
    const eventEvidenceRegistrySha256 = hashObject({
      [evidence.evidence_id]:
        normalizeHash(evidence.registry_sha256),
    });
    if (accepted.stored.evidence_registry_sha256 !== undefined) {
      assertControl(
        normalizeHash(accepted.stored.evidence_registry_sha256)
          === eventEvidenceRegistrySha256,
        'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
        `legacy identity event ${accepted.stored.event_id} evidence digest 漂移`,
      );
    }
    const unsignedEntry = {
      schema_version: 1,
      goal_id: goalId,
      task_id: state.task_id,
      hold_id: hold.hold_id,
      evidence_id: evidence.evidence_id,
      source_sha256: normalizeHash(evidence.source_sha256),
      registry_sha256: normalizeHash(evidence.registry_sha256),
      event_id: accepted.stored.event_id,
      event_input_sha256: normalizeHash(accepted.stored.input_sha256),
      event_sha256: normalizeHash(accepted.stored.event_sha256),
      event_evidence_registry_sha256:
        eventEvidenceRegistrySha256,
      accepted_at: accepted.stored.accepted_at,
      actor_sha256: hashObject(hold.raised_by),
      launch_id: sealed.request.launch_id,
      parent_evidence_id: parentEvidenceId,
      parent_registry_sha256:
        normalizeHash(parent.registry_sha256),
      candidate_launch_sha256:
        normalizeHash(parent.launch_sha256),
      authority_sha256: normalizeHash(
        sealed.event_authority.authority_sha256,
      ),
    };
    const entry = {
      ...unsignedEntry,
      entry_sha256: hashObject(unsignedEntry),
    };
    const existingEntry = collector.incidents.get(key);
    assertControl(
      existingEntry === undefined
        || canonicalJson(existingEntry) === canonicalJson(entry),
      'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
      `duplicate legacy identity incident ${key}`,
    );
    const sourceBase64 = sourceBody.toString('base64');
    const existingSource = collector.sources.get(sourceSha256);
    assertControl(
      existingSource === undefined || existingSource === sourceBase64,
      'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
      `legacy identity source ${sourceSha256} bytes 冲突`,
    );
    collector.incidents.set(key, entry);
    collector.sources.set(sourceSha256, sourceBase64);
  } catch (error) {
    if (controllerShaped) {
      const failure = new ControlError(
        'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
        `controller identity incident ${key} 无法生成 drained receipt: ${error.message}`,
      );
      failure.cause = error;
      throw failure;
    }
    collector.skippedSemanticHolds.add(key);
    // Non-controller or unverifiable semantic holds remain fail-closed.
  }
}

function sealLegacyIdentityIncidentReceipt(
  collector,
  options,
) {
  assertControl(
    collector
      && collector.incidents instanceof Map
      && collector.sources instanceof Map
      && collector.skippedSemanticHolds instanceof Set
      && options
      && typeof options.incidentRef === 'string'
      && options.incidentRef.length > 0
      && options.oldControllerDrainAck
        === 'ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED',
    'INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT',
    'legacy identity incident receipt 缺 migration/drain authority',
  );
  const incidents = Object.fromEntries(
    [...collector.incidents.entries()].sort(
      ([left], [right]) => left.localeCompare(right),
    ),
  );
  const sources = Object.fromEntries(
    [...collector.sources.entries()].sort(
      ([left], [right]) => left.localeCompare(right),
    ),
  );
  const skippedSemanticHolds =
    [...collector.skippedSemanticHolds].sort();
  const unsigned = {
    schema_version: 1,
    kind: 'LEGACY_IDENTITY_INCIDENT_BINDINGS',
    controller_decoder_sha256: normalizeHash(
      options.controllerDecoderSha256,
    ),
    source_state_vector_sha256: normalizeHash(
      options.sourceStateVectorSha256,
    ),
    predecessor_protocol_seal_sha256:
      options.predecessorProtocolSealSha256
        ? normalizeHash(options.predecessorProtocolSealSha256)
        : null,
    migration_receipt: {
      incident_ref: options.incidentRef,
      old_controller_drain_ack: options.oldControllerDrainAck,
    },
    incidents,
    incidents_sha256: hashObject(incidents),
    sources,
    sources_sha256: hashObject(sources),
  };
  const receipt = {
    ...unsigned,
    receipt_sha256: hashObject(unsigned),
  };
  validateLegacyIdentityIncidentReceipt(receipt);
  const body = `${canonicalJson(receipt)}\n`;
  return {
    receipt,
    incident_count: Object.keys(incidents).length,
    skipped_semantic_count: skippedSemanticHolds.length,
    skipped_semantic_holds: skippedSemanticHolds,
    migration_artifact: {
      relative_path: LEGACY_IDENTITY_INCIDENT_RECEIPT_RELATIVE_PATH,
      sha256: `sha256:${sha256(body)}`,
      body: Buffer.from(body, 'utf8'),
    },
  };
}

function classifyCandidateLaunchConflict(
  canonical,
  candidate,
  state,
  goalId,
  session,
) {
  if (
    !launchMatchesActiveWorker(canonical, state, goalId, session)
      || !launchMatchesActiveWorker(candidate, state, goalId, session)
  ) {
    return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
  }
  if (
    hashObject(sourceCheckpointInvariant(canonical))
      === hashObject(sourceCheckpointInvariant(candidate))
  ) {
    try {
      assertSourceCheckpointAdvance(canonical, candidate);
      return session.role === 'DEV'
        ? LAUNCH_HOLD_CLASSIFICATION.SOURCE_ONLY
        : LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
    } catch {
      return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
    }
  }
  if (
    canonical.repository.full_head === candidate.repository.full_head
      && validBuildHeadBinding(canonical)
      && validBuildHeadBinding(candidate)
  ) {
    return classifySupportedRuntimeIdentity(
      canonical,
      candidate,
      { requireRuntimeIdentityDelta: true },
    );
  }
  return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
}

function classifyLaunchIdentityHold(root, state, goalId) {
  const workerRoleByPhase = {
    DEV_ACTIVE: 'DEV',
    REVIEW_ACTIVE: 'REVIEW',
    RECEIPT_ACTIVE: 'RECEIPT',
  };
  const workerRole = workerRoleByPhase[state.phase];
  if (
    !workerRole
      || !Array.isArray(state.holds)
      || state.holds.length !== 1
      || state.holds[0].kind !== 'ENV_IDENTITY_INCIDENT'
      || state.holds[0].hard !== true
  ) {
    return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
  }
  const hold = state.holds[0];
  const session = state.sessions && state.sessions[workerRole];
  if (
    !session
      || !['active', 'idle'].includes(session.status)
      || !session.launch_id
  ) {
    return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
  }
  const checks = hold.evidence && Array.isArray(hold.evidence.checks)
    ? hold.evidence.checks
    : [];
  const failed = checks.filter((check) => check.status === 'FAIL');
  if (
    workerRole === 'DEV'
      &&
    failed.length > 0
      && failed.every((check) => (
        check.name === 'launch-invalid-stale-head'
          || check.name === 'source-checkpoint-stale'
      ))
  ) {
    try {
      const canonical = readCanonicalLaunch(
        root,
        state,
        goalId,
        session,
      );
      const candidate = JSON.parse(JSON.stringify(canonical));
      const candidateHead = git(
        fs.realpathSync(canonical.repository.worktree),
        ['rev-parse', 'HEAD'],
      );
      candidate.repository.full_head = candidateHead;
      if (candidate.execution.target.kind === 'NONE') {
        delete candidate.execution.target.build_head;
      } else {
        candidate.execution.target.build_head = candidateHead;
      }
      assertSourceCheckpointAdvance(canonical, candidate);
      return LAUNCH_HOLD_CLASSIFICATION.SOURCE_ONLY;
    } catch {
      return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
    }
  }
  if (failed.length === 0) {
    return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
  }
  const launchIdConflicts = failed.filter((check) => (
    check.name === 'launch-runtime-binding'
      && typeof check.detail === 'string'
      && check.detail.startsWith('LAUNCH_ID_CONFLICT:')
  ));
  if (launchIdConflicts.length > 0) {
    if (launchIdConflicts.length !== failed.length) {
      return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
    }
    try {
      const canonical = readCanonicalLaunch(
        root,
        state,
        goalId,
        session,
      );
      const candidate = readControllerIncidentCandidate(
        root,
        state,
        goalId,
        session,
        hold,
        failed,
      );
      return classifyCandidateLaunchConflict(
        canonical,
        candidate,
        state,
        goalId,
        session,
      );
    } catch {
      return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
    }
  }
  if (!failed.every((check) => {
    const failureCode = typeof check.detail === 'string'
      ? /^([A-Z][A-Z0-9_]*):/.exec(check.detail)?.[1]
      : null;
    return check.name === 'execution-target'
      && ROTATABLE_EXECUTION_TARGET_FAILURE_CODES.has(failureCode);
  })) {
    return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
  }
  try {
    const canonical = readCanonicalLaunch(
      root,
      state,
      goalId,
      session,
    );
    const candidate = readControllerIncidentCandidate(
      root,
      state,
      goalId,
      session,
      hold,
      failed,
    );
    return classifySupportedRuntimeIdentity(canonical, candidate);
  } catch {
    return LAUNCH_HOLD_CLASSIFICATION.UNKNOWN;
  }
}

function isSourceCheckpointHoldIntent(root, state, goalId) {
  return classifyLaunchIdentityHold(root, state, goalId)
    === LAUNCH_HOLD_CLASSIFICATION.SOURCE_ONLY;
}

function runtimeRotationHoldEligible(root, state, goalId) {
  return classifyLaunchIdentityHold(root, state, goalId)
    === LAUNCH_HOLD_CLASSIFICATION.RUNTIME_IDENTITY;
}

function assertSourceCheckpointAdvance(
  canonical,
  candidate,
  {
    verifyAncestry = true,
    ancestryWorktree = null,
  } = {},
) {
  assertControl(
    canonical.role === 'DEV' && candidate.role === 'DEV',
    'LAUNCH_ID_CONFLICT',
    '同一 runtime 的 source checkpoint 刷新只适用于 DEV',
  );
  assertControl(
    ['NONE', 'CLI', 'PREVIEW'].includes(canonical.execution.target.kind),
    'LAUNCH_ID_CONFLICT',
    `target.kind=${canonical.execution.target.kind} 不支持同一 runtime source checkpoint 刷新`,
  );
  assertControl(
    hashObject(sourceCheckpointInvariant(canonical))
      === hashObject(sourceCheckpointInvariant(candidate)),
    'LAUNCH_ID_CONFLICT',
    `launch_id ${candidate.launch_id} source checkpoint 改动超出 full_head/build_head 白名单`,
  );
  const canonicalHead = canonical.repository.full_head;
  const candidateHead = candidate.repository.full_head;
  const canonicalBuildHead = canonical.execution.target.build_head;
  const candidateBuildHead = candidate.execution.target.build_head;
  const targetKind = canonical.execution.target.kind;
  assertControl(
    targetKind === 'NONE'
      ? (
      canonicalBuildHead === undefined
        && candidateBuildHead === undefined
      )
      : (
        canonicalBuildHead === canonicalHead
        && candidateBuildHead === candidateHead
      ),
    'LAUNCH_ID_CONFLICT',
    targetKind === 'NONE'
      ? 'NONE source checkpoint 禁止 target.build_head'
      : `${targetKind} source checkpoint 的 target.build_head 必须分别等于对应 repository.full_head`,
  );
  assertControl(
    candidateHead !== canonicalHead,
    'LAUNCH_ID_CONFLICT',
    `launch_id ${candidate.launch_id} candidate bytes 不同但 source HEAD 未前进`,
  );
  if (verifyAncestry) {
    const worktree = fs.realpathSync(
      ancestryWorktree || candidate.repository.worktree,
    );
    try {
      git(worktree, [
        'merge-base',
        '--is-ancestor',
        canonicalHead,
        candidateHead,
      ]);
    } catch {
      assertControl(
        false,
        'CANDIDATE_HEAD_NOT_DESCENDANT',
        `candidate HEAD ${candidateHead} 不是 canonical runtime checkpoint ${canonicalHead} 的后代`,
      );
    }
  }
  return {
    canonical_head: canonicalHead,
    candidate_head: candidateHead,
  };
}

module.exports = {
  IDENTITY_INCIDENT_SOURCE_MAX_BYTES,
  LAUNCH_HOLD_CLASSIFICATION,
  LEGACY_IDENTITY_INCIDENT_RECEIPT_RELATIVE_PATH,
  assertSourceCheckpointAdvance,
  canonicalRuntimeLaunchFile,
  classifyLaunchIdentityHold,
  classifySupportedRuntimeIdentity,
  collectLegacyIdentityIncident,
  createLegacyIdentityIncidentCollector,
  isSourceCheckpointHoldIntent,
  parentCandidateHeadBinding,
  readControllerIncidentCandidate,
  readIdentityIncidentSourceBytes,
  runtimeRotationHoldEligible,
  readProtocolSealedIdentityIncidentEvidenceSource,
  sealLegacyIdentityIncidentReceipt,
  validateLegacyIdentityIncidentReceipt,
  validateProtocolSealedLegacyIdentityIncidentReceipts,
};
