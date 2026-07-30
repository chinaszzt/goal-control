'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ControlError, assertControl } = require('./errors');
const { atomicCreate, ensureDir } = require('./store');
const {
  hashObject,
  assertIsolatedTestMode,
  canonicalJson,
  normalizeHash,
  runtimeNowMilliseconds,
  safeId,
  sha256,
} = require('./util');

const PROTOCOL = 'goalctl-sealed-probe-observation-v1';
const RECEIPT_KIND = 'SEALED_PROBE_OBSERVATION_RECEIPT';
const MAX_RECEIPT_BYTES = 256 * 1024;
const MAX_PLAN_BYTES = 1024 * 1024;
const DEFAULT_MAX_TTL_MS = 15 * 60 * 1000;
const CHALLENGE_RE = /^[0-9a-f]{64}$/;
const CONTROLLER_EVIDENCE_ID_RE =
  /^controller-evidence-v1-[0-9a-f]{64}$/;
const CAPABILITY_VALUE_RE =
  /(?:^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?:$|[^A-Za-z0-9_-])/;
const GITHUB_TOKEN_VALUE_RE =
  /(?:gh[pousr][_-][A-Za-z0-9_-]{8,}|github[_-]pat[_-][A-Za-z0-9_-]{8,}|xox[baprs][_-][A-Za-z0-9_-]{8,})/i;
const GENERIC_CREDENTIAL_VALUE_RE =
  /(?:^|[^A-Za-z0-9])(?:(?:(?:sk|pk|rk|api|auth|token|secret|bearer|credential|access[_-]key)[_-](?:live|test|prod|proj|key)?[_-]?)[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{16,}|glpat-[A-Za-z0-9_-]{8,}|hf_[A-Za-z0-9_-]{8,}|xai-[A-Za-z0-9_-]{8,}|SK[0-9a-f]{32}|SG\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|npm_[A-Za-z0-9]{16,}|pypi-[A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?:$|[^A-Za-z0-9])/i;
const PRIVATE_KEY_TEXT_RE =
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/i;
const CREDENTIAL_ASSIGNMENT_RE =
  /(?:api[_-]?key|password|passwd|client[_-]?secret|private[_-]?key|access[_-]?token|access[_-]?key|token|authorization|credential)\s*[:=]\s*[^\s"'&]{4,}/i;
const AUTHORIZATION_HEADER_RE =
  /(?:^|[\s,;])(?:authorization\s*:\s*)?(?:basic|bearer)\s+[A-Za-z0-9._~+/-]+=*(?:$|[\s,;])/i;
const CREDENTIAL_URL_RE =
  /https?:\/\/(?:[^/\s@]+@|[^\s"']+[?&](?:access[_-]?token|api[_-]?key|password|passwd|client[_-]?secret|private[_-]?key|token|key|secret|auth(?:orization)?|credential)=)/i;
const CRYPTOGRAPHIC_CAPABILITY_EXEMPT_FIELDS = new Set([
  'attestation_public_key_spki_base64',
  'attestation_signature_base64url',
  'public_key_spki_base64',
  'signature_base64url',
]);
const VALIDATED_ENUM_STRING_FIELDS = new Set([
  'adapter',
  'aggregate_disposition',
  'aggregate_dispositions',
  'disposition',
  'kind',
  'probe',
  'producer_namespace',
  'protocol',
  'registration_gate',
  'required_probes',
  'role',
  'schema',
]);
const DERIVED_CANONICAL_STRING_FIELDS = new Set([
  'shell_command',
]);
const DISPOSITIONS = Object.freeze([
  'PASS',
  'PROVISIONAL_KNOWN_LIMITATION',
  'KNOWN_LIMITATION',
  'FAIL',
]);
const ADAPTERS = Object.freeze([
  'GITHUB_CLI',
  'GIT_TRANSPORT',
  'GITHUB_APP',
  'BROWSER',
  'TASK_BROKER',
  'CONTROLLER_CLI',
]);

const RECEIPT_KEYS = Object.freeze([
  'aggregate_disposition',
  'canary_plan_sha256',
  'challenge',
  'expires_at',
  'goal_id',
  'kind',
  'observed_at',
  'probe_results',
  'producer',
  'replay_result',
  'receipt_binding_sha256',
  'receipt_attestation',
  'role',
  'schema_version',
  'stable_id',
  'target_fingerprint_sha256',
  'target_identity_sha256',
  'task_id',
  'ttl_ms',
]);
const PROBE_RESULT_KEYS = Object.freeze([
  'adapter',
  'disposition',
  'evidence_refs',
  'interactive',
  'limitation',
  'probe',
  'result_fingerprint_sha256',
  'sequence',
  'target_identity_sha256',
]);
const BINDING_KEYS = Object.freeze([
  'aggregate_disposition',
  'accepted_at',
  'attestation_algorithm',
  'attestation_key_id',
  'attestation_public_key_sha256',
  'attestation_public_key_spki_base64',
  'attestation_signature_base64url',
  'binding_sha256',
  'canary_plan_sha256',
  'challenge',
  'expires_at',
  'host_id',
  'observed_at',
  'plan_file',
  'plan_file_sha256',
  'protocol',
  'receipt_file',
  'receipt_sha256',
  'schema_version',
  'stable_id',
  'target_fingerprint_sha256',
  'target_identity_sha256',
  'thread_id',
  'attempt',
  'probe_results_sha256',
  'receipt_binding_sha256',
  'request_sha256',
]);

function exactKeys(value, expected, label, code = 'CANARY_OBSERVATION_INVALID') {
  assertControl(
    value
      && typeof value === 'object'
      && !Array.isArray(value)
      && JSON.stringify(Object.keys(value).sort())
        === JSON.stringify([...expected].sort()),
    code,
    `${label} 字段集合非法`,
  );
}

function canonicalAbsolutePath(value, label) {
  assertControl(
    typeof value === 'string'
      && path.isAbsolute(value)
      && path.normalize(value) === value,
    'CANARY_OBSERVATION_FILE_INVALID',
    `${label} 必须是 canonical absolute path`,
  );
  return value;
}

function statIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    nlink: stat.nlink,
    uid: stat.uid,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  };
}

function sameIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function readStableFile(file, options) {
  canonicalAbsolutePath(file, options.label);
  const parent = path.dirname(file);
  const components = file.split(path.sep).filter(Boolean);
  const ancestorIdentities = [];
  let cursor = path.parse(file).root;
  for (const component of components.slice(0, -1)) {
    cursor = path.join(cursor, component);
    const ancestor = fs.lstatSync(cursor, { bigint: true });
    assertControl(
      ancestor.isDirectory()
        && !ancestor.isSymbolicLink()
        && (
          typeof process.getuid !== 'function'
            || Number(ancestor.uid) === process.getuid()
            || Number(ancestor.uid) === 0
        )
        && (
          Number(ancestor.mode & 0o022n) === 0
            || (
              Number(ancestor.uid) === 0
                && Number(ancestor.mode & 0o1000n) === 0o1000
            )
        ),
      'CANARY_OBSERVATION_FILE_PERMISSIONS',
      `${options.label} ancestor 必须 no-symlink 且非 group/world writable`,
    );
    ancestorIdentities.push({
      path: cursor,
      identity: statIdentity(ancestor),
    });
  }
  const parentStat = fs.lstatSync(parent, { bigint: true });
  assertControl(
    parentStat.isDirectory()
      && !parentStat.isSymbolicLink()
      && Number(parentStat.mode & 0o7777n) === options.parentMode
      && (
        typeof process.getuid !== 'function'
          || Number(parentStat.uid) === process.getuid()
      ),
    'CANARY_OBSERVATION_FILE_PERMISSIONS',
    `${options.label} parent 必须由当前用户持有且 exact ${
      options.parentMode.toString(8)
    }`,
  );
  const before = fs.lstatSync(file, { bigint: true });
  const allowedNlinks = Array.isArray(options.allowedNlinks)
    ? options.allowedNlinks
    : [1];
  assertControl(
    before.isFile()
      && !before.isSymbolicLink()
      && allowedNlinks.includes(Number(before.nlink))
      && Number(before.mode & 0o7777n) === options.mode
      && Number(before.size) > 0
      && Number(before.size) <= options.maxBytes
      && (
        typeof process.getuid !== 'function'
          || Number(before.uid) === process.getuid()
      ),
    'CANARY_OBSERVATION_FILE_PERMISSIONS',
    `${options.label} 必须是当前用户 ${
      options.mode.toString(8)
    } 单链接受限大小 ordinary file`,
  );
  const beforeIdentity = statIdentity(before);
  const noFollow = typeof fs.constants.O_NOFOLLOW === 'number'
    ? fs.constants.O_NOFOLLOW
    : 0;
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | noFollow);
  } catch (error) {
    throw new ControlError(
      'CANARY_OBSERVATION_FILE_INVALID',
      `${options.label} 无法 no-follow 打开: ${error.message}`,
    );
  }
  try {
    const openedBefore = fs.fstatSync(descriptor, { bigint: true });
    assertControl(
      openedBefore.isFile()
        && sameIdentity(beforeIdentity, statIdentity(openedBefore)),
      'CANARY_OBSERVATION_FILE_RACE',
      `${options.label} lstat/open identity 漂移`,
    );
    const bytes = Buffer.alloc(Number(openedBefore.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(
        descriptor,
        bytes,
        offset,
        bytes.length - offset,
        null,
      );
      assertControl(
        count > 0,
        'CANARY_OBSERVATION_FILE_RACE',
        `${options.label} descriptor 提前 EOF`,
      );
      offset += count;
    }
    const openedAfter = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(file, { bigint: true });
    const ancestorsStable = ancestorIdentities.every((entry) => (
      sameIdentity(
        entry.identity,
        statIdentity(fs.lstatSync(entry.path, { bigint: true })),
      )
    ));
    assertControl(
      sameIdentity(statIdentity(openedBefore), statIdentity(openedAfter))
        && sameIdentity(statIdentity(openedAfter), statIdentity(pathAfter))
        && ancestorsStable,
      'CANARY_OBSERVATION_FILE_RACE',
      `${options.label} 读取期间 identity/content 漂移`,
    );
    return {
      bytes,
      sha256: `sha256:${sha256(bytes)}`,
      file_identity_sha256: hashObject({
        canonical_path_sha256: `sha256:${sha256(file)}`,
        dev: openedAfter.dev.toString(),
        ino: openedAfter.ino.toString(),
        mode: Number(openedAfter.mode & 0o7777n),
        uid: Number(openedAfter.uid),
        size: Number(openedAfter.size),
        mtime_ns: openedAfter.mtimeNs.toString(),
        ...(options.stableInodeIdentity === true
          ? {}
          : {
            nlink: Number(openedAfter.nlink),
            ctime_ns: openedAfter.ctimeNs.toString(),
          }),
      }),
    };
  } finally {
    fs.closeSync(descriptor);
  }
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new ControlError(
      'CANARY_OBSERVATION_INVALID',
      `${label} 不是合法 JSON`,
    );
  }
}

function assertNoSensitiveReceiptText(bytes) {
  const text = bytes.toString('utf8');
  assertControl(
    !/(?:token|cookie|credential(?:[_ -]?url)?|capability(?:[_ -]?(?:text|bytes|url))?|authorization)\s*["':=]/i
      .test(text)
      && !/https?:\/\/[^/\s@]+@/i.test(text)
      && !/https?:\/\/[^\s"']+[?&](?:access_token|token|key|credential)=/i
        .test(text),
    'CANARY_OBSERVATION_SENSITIVE_DATA',
    'probe observation receipt 禁止 token/cookie/credential URL/capability 原文',
  );
}

function sensitiveStringFinding(value, options = {}) {
  let finding = null;
  const visit = (current, field = null) => {
    if (finding) return;
    if (typeof current === 'string') {
      if (
        field === 'stable_id'
          && typeof options.allowedDerivedStableId === 'string'
          && current === options.allowedDerivedStableId
      ) {
        return;
      }
      if (
        options.allowedExactFieldValues
          && Object.prototype.hasOwnProperty.call(
            options.allowedExactFieldValues,
            field,
          )
          && (
            current === options.allowedExactFieldValues[field]
              || (
                Array.isArray(options.allowedExactFieldValues[field])
                  && options.allowedExactFieldValues[field]
                    .includes(current)
              )
          )
      ) {
        return;
      }
      if (
        VALIDATED_ENUM_STRING_FIELDS.has(field)
          || DERIVED_CANONICAL_STRING_FIELDS.has(field)
      ) {
        return;
      }
      if (
        !CRYPTOGRAPHIC_CAPABILITY_EXEMPT_FIELDS.has(field)
          && CAPABILITY_VALUE_RE.test(current)
      ) {
        finding = { category: 'capability', field };
      } else if (GITHUB_TOKEN_VALUE_RE.test(current)) {
        finding = { category: 'provider_token', field };
      } else if (GENERIC_CREDENTIAL_VALUE_RE.test(current)) {
        finding = { category: 'generic_credential', field };
      } else if (PRIVATE_KEY_TEXT_RE.test(current)) {
        finding = { category: 'private_key', field };
      } else if (CREDENTIAL_ASSIGNMENT_RE.test(current)) {
        finding = { category: 'credential_assignment', field };
      } else if (AUTHORIZATION_HEADER_RE.test(current)) {
        finding = { category: 'authorization_header', field };
      } else if (CREDENTIAL_URL_RE.test(current)) {
        finding = { category: 'credential_url', field };
      }
      return;
    }
    if (Array.isArray(current)) {
      current.forEach((entry) => visit(entry, field));
      return;
    }
    if (current && typeof current === 'object') {
      Object.entries(current).forEach(([key, entry]) => {
        visit(entry, key);
      });
    }
  };
  visit(value);
  return finding;
}

function containsSensitiveStringLeaves(value) {
  return sensitiveStringFinding(value) !== null;
}

function assertNoSensitiveStringLeaves(value, options = {}) {
  const finding = sensitiveStringFinding(value, options);
  assertControl(
    finding === null,
    'CANARY_OBSERVATION_SENSITIVE_DATA',
    `controller boundary 禁止 token/credential URL/private key/auth header/capability 原文 (${finding ? `${finding.category}/${finding.field || 'value'}` : 'unknown'})`,
  );
}

function attestationPayload(receipt) {
  const value = JSON.parse(JSON.stringify(receipt));
  delete value.receipt_binding_sha256;
  if (
    value.receipt_attestation
      && typeof value.receipt_attestation === 'object'
  ) {
    delete value.receipt_attestation.signature_base64url;
  }
  return value;
}

function canonicalHostAttestation(value, label) {
  assertControl(
    value
      && typeof value === 'object'
      && !Array.isArray(value),
    'CANARY_OBSERVATION_AUTHENTICATION_INVALID',
    `${label} 缺 host attestation`,
  );
  exactKeys(
    value,
    [
      'algorithm',
      'key_id',
      'public_key_sha256',
      'public_key_spki_base64',
    ],
    label,
    'CANARY_OBSERVATION_AUTHENTICATION_INVALID',
  );
  assertControl(
    value.algorithm === 'ED25519',
    'CANARY_OBSERVATION_AUTHENTICATION_INVALID',
    `${label}.algorithm 必须是 ED25519`,
  );
  safeId(value.key_id, `${label}.key_id`);
  const publicKeySha256 = normalizeHash(
    value.public_key_sha256,
    `${label}.public_key_sha256`,
  );
  assertControl(
    typeof value.public_key_spki_base64 === 'string'
      && /^[A-Za-z0-9+/]+={0,2}$/.test(value.public_key_spki_base64)
      && value.public_key_spki_base64.length <= 256,
    'CANARY_OBSERVATION_AUTHENTICATION_INVALID',
    `${label}.public_key_spki_base64 非法`,
  );
  let der;
  let publicKey;
  try {
    der = Buffer.from(value.public_key_spki_base64, 'base64');
    publicKey = crypto.createPublicKey({
      key: der,
      format: 'der',
      type: 'spki',
    });
  } catch (error) {
    throw new ControlError(
      'CANARY_OBSERVATION_AUTHENTICATION_INVALID',
      `${label} 不是合法 Ed25519 SPKI: ${error.message}`,
    );
  }
  assertControl(
    publicKey.asymmetricKeyType === 'ed25519'
      && publicKey.export({ format: 'der', type: 'spki' }).equals(der)
      && `sha256:${sha256(der)}` === publicKeySha256,
    'CANARY_OBSERVATION_AUTHENTICATION_INVALID',
    `${label} 必须是 canonical Ed25519 SPKI 且 hash 匹配`,
  );
  return {
    algorithm: value.algorithm,
    key_id: value.key_id,
    public_key_sha256: publicKeySha256,
    public_key_spki_base64: value.public_key_spki_base64,
    publicKey,
  };
}

function assertReceiptAttestation(receipt, hostAttestation) {
  exactKeys(
    receipt.receipt_attestation,
    [
      'algorithm',
      'key_id',
      'public_key_sha256',
      'signature_base64url',
    ],
    'probe observation receipt.receipt_attestation',
    'CANARY_OBSERVATION_AUTHENTICATION_INVALID',
  );
  const attestation = receipt.receipt_attestation;
  assertControl(
    attestation.algorithm === hostAttestation.algorithm
      && attestation.key_id === hostAttestation.key_id
      && normalizeHash(
        attestation.public_key_sha256,
        'receipt_attestation.public_key_sha256',
      ) === hostAttestation.public_key_sha256
      && typeof attestation.signature_base64url === 'string'
      && /^[A-Za-z0-9_-]{86}$/.test(
        attestation.signature_base64url,
      ),
    'CANARY_OBSERVATION_AUTHENTICATION_INVALID',
    'probe observation receipt attestation key binding 非法',
  );
  const signature = Buffer.from(
    attestation.signature_base64url,
    'base64url',
  );
  assertControl(
    signature.length === 64
      && crypto.verify(
        null,
        Buffer.from(canonicalJson(attestationPayload(receipt))),
        hostAttestation.publicKey,
        signature,
      ),
    'CANARY_OBSERVATION_AUTHENTICATION_INVALID',
    'probe observation receipt 缺 host-integration-only Ed25519 attestation',
  );
}

function aggregateProbeResults(results) {
  if (results.some((result) => (
    result.disposition === 'FAIL'
      || result.interactive.allow_prompt
      || result.interactive.auth_prompt
  ))) return 'FAIL';
  if (results.some(
    (result) => result.disposition === 'PROVISIONAL_KNOWN_LIMITATION',
  )) return 'PROVISIONAL_KNOWN_LIMITATION';
  if (results.some(
    (result) => result.disposition === 'KNOWN_LIMITATION',
  )) return 'KNOWN_LIMITATION';
  return 'PASS';
}

function expectedAdapter(probe) {
  if (probe.startsWith('GH_')) return 'GITHUB_CLI';
  if (probe.startsWith('GIT_')) return 'GIT_TRANSPORT';
  if (probe.startsWith('GITHUB_APP_')) return 'GITHUB_APP';
  if (probe.startsWith('BROWSER_')) return 'BROWSER';
  if (probe.startsWith('TASK_')) return 'TASK_BROKER';
  return 'CONTROLLER_CLI';
}

function controllerEvidenceReference(context, result, evidenceSha256, index) {
  const normalizedEvidenceSha256 = normalizeHash(
    evidenceSha256,
    'controller evidence sha256',
  );
  assertControl(
    Number.isSafeInteger(index) && index >= 0 && index < 16,
    'CANARY_OBSERVATION_INVALID',
    'controller evidence reference index 非法',
  );
  const referenceBinding = {
    protocol: 'goalctl-controller-evidence-reference-v1',
    stable_id: context.stableId,
    challenge: context.challenge,
    canary_plan_sha256: context.canaryPlanSha256,
    goal_id: context.goalId,
    task_id: context.taskId,
    role: context.role,
    thread_id: context.threadId,
    host_id: context.hostId,
    attempt: context.attempt,
    target_identity_sha256: context.targetIdentitySha256,
    target_fingerprint_sha256: context.targetFingerprintSha256,
    sequence: result.sequence,
    probe: result.probe,
    adapter: result.adapter,
    disposition: result.disposition,
    result_fingerprint_sha256: result.result_fingerprint_sha256,
    interactive: result.interactive,
    limitation: result.limitation,
    evidence_index: index,
    evidence_sha256: normalizedEvidenceSha256,
  };
  return {
    kind: 'HOST_ADAPTER_EVIDENCE',
    id: `controller-evidence-v1-${hashObject(referenceBinding).slice(7)}`,
    sha256: normalizedEvidenceSha256,
  };
}

function validateEvidenceRef(value, label, context, result, index) {
  exactKeys(value, ['id', 'kind', 'sha256'], label);
  assertControl(
    value.kind === 'HOST_ADAPTER_EVIDENCE'
      && CONTROLLER_EVIDENCE_ID_RE.test(value.id),
    'CANARY_OBSERVATION_EVIDENCE_REFERENCE_MISMATCH',
    `${label} 不是 controller-issued evidence reference`,
  );
  const expected = controllerEvidenceReference(
    context,
    result,
    value.sha256,
    index,
  );
  assertControl(
    hashObject(value) === hashObject(expected),
    'CANARY_OBSERVATION_EVIDENCE_REFERENCE_MISMATCH',
    `${label} 未精确绑定 challenge/plan/session/target/result/evidence`,
  );
}

function validateProbeResult(
  result,
  probe,
  index,
  targetIdentitySha256,
  sequence = index + 1,
  evidenceContext,
) {
  exactKeys(result, PROBE_RESULT_KEYS, `probe_results[${index}]`);
  assertControl(
    result.sequence === sequence
      && result.probe === probe
      && ADAPTERS.includes(result.adapter)
      && result.adapter === expectedAdapter(probe)
      && DISPOSITIONS.includes(result.disposition)
      && result.target_identity_sha256 === targetIdentitySha256,
    'CANARY_OBSERVATION_PROBE_MISMATCH',
    `probe_results[${index}] 缺项、乱序、重复或 adapter/target binding 非法`,
  );
  normalizeHash(
    result.result_fingerprint_sha256,
    `probe_results[${index}].result_fingerprint_sha256`,
  );
  exactKeys(
    result.interactive,
    ['allow_prompt', 'auth_prompt'],
    `probe_results[${index}].interactive`,
  );
  assertControl(
    typeof result.interactive.allow_prompt === 'boolean'
      && typeof result.interactive.auth_prompt === 'boolean',
    'CANARY_OBSERVATION_INVALID',
    `probe_results[${index}].interactive 必须是 boolean`,
  );
  assertControl(
    Array.isArray(result.evidence_refs)
      && result.evidence_refs.length > 0
      && result.evidence_refs.length <= 16,
    'CANARY_OBSERVATION_INVALID',
    `probe_results[${index}].evidence_refs 必须非空且有界`,
  );
  assertControl(
    result.limitation === null
      || (
        result.limitation
          && typeof result.limitation === 'object'
          && !Array.isArray(result.limitation)
      ),
    'CANARY_OBSERVATION_INVALID',
    `probe_results[${index}].limitation 非法`,
  );
  if (result.limitation !== null) {
    exactKeys(
      result.limitation,
      ['exact_match', 'id'],
      `probe_results[${index}].limitation`,
    );
    safeId(
      result.limitation.id,
      `probe_results[${index}].limitation.id`,
    );
    exactKeys(
      result.limitation.exact_match,
      [
        'allow_dialog',
        'authentication_prompt',
        'repository',
        'result_fingerprint',
        'semantic_operation',
        'target_kind',
      ],
      `probe_results[${index}].limitation.exact_match`,
    );
    assertControl(
      result.limitation.exact_match.semantic_operation
        === 'REPOSITORY_METADATA_READ'
        && result.limitation.exact_match.target_kind === 'REPOSITORY'
        && typeof result.limitation.exact_match.repository === 'string'
        && result.limitation.exact_match.repository.length > 0
        && result.limitation.exact_match.repository.length <= 300
        && result.limitation.exact_match.result_fingerprint
          === '404/repo_not_found'
        && result.limitation.exact_match.allow_dialog === false
        && result.limitation.exact_match.authentication_prompt === false,
      'CANARY_OBSERVATION_LIMITATION_MISMATCH',
      `probe_results[${index}].limitation 只允许 exact committed 404 claim`,
    );
  }
  result.evidence_refs.forEach((reference, referenceIndex) => {
    validateEvidenceRef(
      reference,
      `probe_results[${index}].evidence_refs[${referenceIndex}]`,
      evidenceContext,
      result,
      referenceIndex,
    );
  });
  const evidenceIds = result.evidence_refs.map((reference) => reference.id);
  assertControl(
    new Set(evidenceIds).size === evidenceIds.length,
    'CANARY_OBSERVATION_INVALID',
    `probe_results[${index}].evidence_refs 重复`,
  );
}

function validateReplayResult(
  result,
  targetIdentitySha256,
  evidenceContext,
) {
  validateProbeResult(
    result,
    'CANARY_PLAN_REPLAY',
    0,
    targetIdentitySha256,
    0,
    evidenceContext,
  );
  assertControl(
    result.adapter === 'CONTROLLER_CLI'
      && result.disposition === 'PASS'
      && result.limitation === null
      && result.interactive.allow_prompt === false
      && result.interactive.auth_prompt === false,
    'CANARY_OBSERVATION_REPLAY_FAILED',
    'canonical plan replay 必须作为 sequence=0 的显式 PASS 结果',
  );
}

function validateKnownLimitation(result, plan, results) {
  if (![
    'PROVISIONAL_KNOWN_LIMITATION',
    'KNOWN_LIMITATION',
  ].includes(result.disposition)) {
    assertControl(
      result.limitation === null,
      'CANARY_OBSERVATION_LIMITATION_MISMATCH',
      '非 limitation 结果不得携带 limitation claim',
    );
    return;
  }
  exactKeys(
    result.limitation,
    ['exact_match', 'id'],
    'known limitation claim',
    'CANARY_OBSERVATION_LIMITATION_MISMATCH',
  );
  exactKeys(
    result.limitation.exact_match,
    [
      'allow_dialog',
      'authentication_prompt',
      'repository',
      'result_fingerprint',
      'semantic_operation',
      'target_kind',
    ],
    'known limitation exact_match',
    'CANARY_OBSERVATION_LIMITATION_MISMATCH',
  );
  const limitations = (
    plan.probe_evaluation
      && Array.isArray(plan.probe_evaluation.known_limitations)
  ) ? plan.probe_evaluation.known_limitations : [];
  const policy = limitations.find((candidate) => (
    result.limitation
      && candidate.id === result.limitation.id
      && candidate.probe === result.probe
  ));
  assertControl(
    policy
      && hashObject(result.limitation.exact_match)
        === hashObject(policy.exact_match)
      && result.limitation.id === policy.id,
    'CANARY_OBSERVATION_LIMITATION_MISMATCH',
    'known limitation 必须精确匹配 committed canary policy',
  );
  if (result.disposition === 'KNOWN_LIMITATION') {
    assertControl(
      policy.final_disposition === 'KNOWN_LIMITATION'
        && policy.compensation_probes.every((probe) => {
          const compensation = results.find(
            (candidate) => candidate.probe === probe,
          );
          return compensation && compensation.disposition === 'PASS';
        }),
      'CANARY_OBSERVATION_LIMITATION_MISMATCH',
      '404 known limitation 只有全部同-session compensation PASS 才能 finalize',
    );
  }
}

function validatePlan(planEnvelope, expectedPlanSha256, expected) {
  exactKeys(
    planEnvelope,
    ['canary_plan', 'canary_plan_sha256'],
    'canary plan envelope',
  );
  const planSha256 = normalizeHash(
    expectedPlanSha256,
    '--canary-plan-sha256',
  );
  assertControl(
    planEnvelope.canary_plan_sha256 === planSha256
      && hashObject(planEnvelope.canary_plan) === planSha256,
    'CANARY_OBSERVATION_STALE_PLAN',
    'canary plan content hash 与 expected/current plan 不一致',
  );
  const plan = planEnvelope.canary_plan;
  const { canaryPlan } = require('./canary-plan');
  const workerBootstrap = plan && plan.worker_bootstrap;
  const browserReceipt = (
    plan
      && plan.browser
      && plan.browser.target
      && plan.browser.target.receipt
  ) ? plan.browser.target.receipt.path : null;
  const canonicalEnvelope = canaryPlan(
    expected.repositoryWorktree,
    {
      manifestFile: expected.manifest.source_manifest,
      role: expected.role,
      taskId: expected.role === 'FOREMAN' ? null : expected.taskId,
      browserCanaryReceipt: browserReceipt,
      ...(workerBootstrap
        ? {
          workerBootstrapReceipt: workerBootstrap.receipt_file,
          workerBootstrapReceiptSha256: workerBootstrap.receipt_sha256,
          workerBootstrapOperationId: workerBootstrap.operation_id,
          workerBootstrapChallenge: workerBootstrap.challenge,
          workerBootstrapIdentityPlanSha256:
            workerBootstrap.identity_plan_sha256,
          workerThread: workerBootstrap.thread,
          workerHost: workerBootstrap.host,
        }
        : {}),
    },
    {},
    expected.invocationCwd || expected.repositoryWorktree,
  );
  assertControl(
    canonicalEnvelope.canary_plan_sha256 === planSha256
      && hashObject(canonicalEnvelope.canary_plan) === planSha256
      && hashObject(canonicalEnvelope.canary_plan) === hashObject(plan),
    'CANARY_OBSERVATION_STALE_PLAN',
    'canary plan 不等于当前 controller 对 live repository/manifest 机械生成的 canonical plan',
  );
  const expectedPlanTaskId = expected.role === 'FOREMAN'
    ? null
    : expected.taskId;
  assertControl(
    plan
      && plan.schema_version === 1
      && plan.goal_id === expected.goalId
      && plan.task_id === expectedPlanTaskId
      && plan.role === expected.role
      && plan.repository_head === expected.repositoryHead
      && plan.manifest
      && plan.manifest.validated_manifest_sha256
        === expected.validatedManifestSha256
      && plan.observation_receipt
      && plan.observation_receipt.protocol === PROTOCOL
      && plan.observation_receipt.max_ttl_ms
        === expected.manifest.probe_observation_receipts.max_ttl_ms
      && hashObject(plan.observation_receipt.host_attestation)
        === hashObject((() => {
          const attestation =
            expected.manifest.probe_observation_receipts.host_attestation;
          return {
            algorithm: attestation.algorithm,
            key_id: attestation.key_id,
            public_key_sha256: attestation.public_key_sha256,
          };
        })())
      && plan.observation_receipt.registration_gate
        === 'PASS_OR_POLICY_FINALIZED_KNOWN_LIMITATION'
      && plan.observation_receipt.launch_gate
        === 'PASS_OR_POLICY_FINALIZED_KNOWN_LIMITATION'
      && plan.observation_receipt.full_scope_gate
        === 'PASS_OR_POLICY_FINALIZED_KNOWN_LIMITATION'
      && plan.observation_receipt.interactive_allow_or_auth === 'FAIL'
      && plan.observation_receipt.executor_boundary
        === 'HOST_ADAPTER_EXECUTES_CORE_VALIDATES_ONLY'
      && Array.isArray(plan.required_probes)
      && plan.required_probes.length > 0
      && new Set(plan.required_probes).size === plan.required_probes.length,
    'CANARY_OBSERVATION_STALE_PLAN',
    'canary plan 与当前 Goal/task/role/HEAD/manifest 不一致',
  );
  return { plan, planSha256 };
}

function targetHashes(plan, expected) {
  const identity = {
    goal_id: expected.goalId,
    task_id: expected.taskId,
    role: expected.role,
    thread_id: expected.threadId,
    host_id: expected.hostId,
    attempt: expected.attempt,
  };
  const fingerprint = {
    repository_head: plan.repository_head,
    repository: plan.repository,
    controller_decoder_sha256:
      plan.controller && plan.controller.decoder_sha256,
    controller_closure_sha256:
      plan.controller && plan.controller.closure_sha256,
  };
  return {
    targetIdentitySha256: hashObject(identity),
    targetFingerprintSha256: hashObject(fingerprint),
  };
}

function receiptOptions(options) {
  const values = [
    options.probeObservationReceipt,
    options.probeObservationReceiptSha256,
    options.probeObservationPlan,
    options.probeObservationPlanSha256,
    options.probeObservationStableId,
    options.probeObservationChallenge,
  ];
  const count = values.filter(
    (value) => value !== null && value !== undefined,
  ).length;
  assertControl(
    count === 0 || count === values.length,
    'CANARY_OBSERVATION_ARGUMENT_MISMATCH',
    'probe observation receipt/hash/plan/plan-hash/stable-id/challenge 必须同时提供或同时省略',
  );
  if (count === 0) return null;
  assertControl(
    CHALLENGE_RE.test(options.probeObservationChallenge),
    'CANARY_OBSERVATION_ARGUMENT_MISMATCH',
    'probe observation challenge 必须是 64 位小写 hex',
  );
  return {
    receipt_file: canonicalAbsolutePath(
      options.probeObservationReceipt,
      '--probe-observation-receipt',
    ),
    receipt_sha256: normalizeHash(
      options.probeObservationReceiptSha256,
      '--probe-observation-receipt-sha256',
    ),
    plan_file: canonicalAbsolutePath(
      options.probeObservationPlan,
      '--probe-observation-plan',
    ),
    canary_plan_sha256: normalizeHash(
      options.probeObservationPlanSha256,
      '--probe-observation-plan-sha256',
    ),
    stable_id: safeId(
      options.probeObservationStableId,
      '--probe-observation-stable-id',
    ),
    challenge: options.probeObservationChallenge,
  };
}

function protocolRequired(manifest) {
  return Boolean(manifest && manifest.probe_observation_receipts);
}

function validateReceipt(options) {
  const request = receiptOptions(options);
  assertControl(
    request,
    'CANARY_OBSERVATION_REQUIRED',
    'probe observation receipt protocol 已启用；registration 必须携带 sealed receipt',
  );
  const expectedStableId = `canary-observation-${options.registrationEventId}`;
  assertControl(
    request.stable_id === expectedStableId,
    'CANARY_OBSERVATION_STABLE_ID_MISMATCH',
    `probe observation stable ID 必须精确等于 ${expectedStableId}`,
  );
  // stable_id is now controller-derived from the separately validated event
  // ID. The recursive scan may exempt this exact derived field without
  // allowing a caller-authored 43-character capability-shaped identity.
  const planCapture = readStableFile(request.plan_file, {
    label: 'canary plan',
    parentMode: 0o700,
    mode: 0o600,
    maxBytes: MAX_PLAN_BYTES,
  });
  const planEnvelope = parseJson(planCapture.bytes, 'canary plan');
  const { plan, planSha256 } = validatePlan(
    planEnvelope,
    request.canary_plan_sha256,
    options,
  );
  // shell_command is an exact controller-regenerated serialization of the
  // separately scanned argv/environment leaves. Scan only after that
  // canonical equality closes so the derived string cannot hide caller data.
  assertNoSensitiveStringLeaves(planEnvelope, {
    allowedExactFieldValues: {
      repository_worktree: options.repositoryWorktree,
      argv: [
        options.repositoryWorktree,
        options.invocationCwd || options.repositoryWorktree,
      ],
    },
  });
  const {
    targetIdentitySha256,
    targetFingerprintSha256,
  } = targetHashes(plan, options);
  const hostAttestation = canonicalHostAttestation(
    options.manifest.probe_observation_receipts.host_attestation,
    'manifest.probe_observation_receipts.host_attestation',
  );
  exactKeys(
    options.challengeRecord,
    [
      'attestation_algorithm',
      'attestation_key_id',
      'attestation_public_key_sha256',
      'attempt',
      'canary_plan_sha256',
      'challenge',
      'expires_at',
      'goal_id',
      'host_id',
      'issued_at',
      'issuer_capability_sha256',
      'kind',
      'producer_namespace',
      'record_sha256',
      'registration_event_id',
      'role',
      'schema_version',
      'task_id',
      'thread_id',
    ],
    'probe observation challenge',
    'CANARY_OBSERVATION_CHALLENGE_INVALID',
  );
  assertControl(
    options.challengeRecord
      && options.challengeRecord.schema_version === 1
      && options.challengeRecord.kind
        === 'PROBE_OBSERVATION_CHALLENGE'
      && options.challengeRecord.goal_id === options.goalId
      && options.challengeRecord.task_id === options.taskId
      && options.challengeRecord.role === options.role
      && options.challengeRecord.thread_id === options.threadId
      && options.challengeRecord.host_id === options.hostId
      && options.challengeRecord.attempt === options.attempt
      && options.challengeRecord.registration_event_id
        === options.registrationEventId
      && options.challengeRecord.canary_plan_sha256 === planSha256
      && options.challengeRecord.challenge === request.challenge
      && options.challengeRecord.attestation_algorithm
        === hostAttestation.algorithm
      && options.challengeRecord.attestation_key_id
        === hostAttestation.key_id
      && options.challengeRecord.attestation_public_key_sha256
        === hostAttestation.public_key_sha256
      && Date.parse(options.challengeRecord.issued_at)
        <= Date.parse(options.challengeRecord.expires_at)
      && options.challengeRecord.record_sha256 === hashObject((() => {
        const value = { ...options.challengeRecord };
        delete value.record_sha256;
        return value;
      })()),
    'CANARY_OBSERVATION_CHALLENGE_INVALID',
    'probe observation challenge 必须来自 controller durable issuer 且精确绑定 event/identity/plan',
  );
  assertNoSensitiveStringLeaves(options.challengeRecord);
  const receiptCapture = readStableFile(request.receipt_file, {
    label: 'probe observation receipt',
    parentMode: 0o700,
    mode: 0o600,
    maxBytes: MAX_RECEIPT_BYTES,
  });
  assertControl(
    receiptCapture.sha256 === request.receipt_sha256,
    'CANARY_OBSERVATION_CONTENT_HASH_MISMATCH',
    'probe observation receipt content hash 不匹配',
  );
  assertNoSensitiveReceiptText(receiptCapture.bytes);
  const receipt = parseJson(
    receiptCapture.bytes,
    'probe observation receipt',
  );
  exactKeys(receipt, RECEIPT_KEYS, 'probe observation receipt');
  assertControl(
    receipt.stable_id === request.stable_id,
    'CANARY_OBSERVATION_BINDING_MISMATCH',
    'probe observation receipt stable ID binding 非法',
  );
  assertNoSensitiveStringLeaves(receipt, {
    allowedDerivedStableId: request.stable_id,
  });
  const unsigned = { ...receipt };
  delete unsigned.receipt_binding_sha256;
  assertControl(
    receipt.schema_version === 1
      && receipt.kind === RECEIPT_KIND
      && receipt.receipt_binding_sha256 === hashObject(unsigned)
      && receipt.stable_id === request.stable_id
      && receipt.challenge === request.challenge
      && receipt.canary_plan_sha256 === planSha256
      && receipt.goal_id === options.goalId
      && receipt.task_id === options.taskId
      && receipt.role === options.role
      && receipt.target_identity_sha256 === targetIdentitySha256
      && receipt.target_fingerprint_sha256 === targetFingerprintSha256,
    'CANARY_OBSERVATION_BINDING_MISMATCH',
    'probe observation receipt plan/challenge/Goal/task/role/target binding 非法',
  );
  assertReceiptAttestation(receipt, hostAttestation);
  exactKeys(
    receipt.producer,
    ['attempt', 'host_id', 'namespace', 'thread_id'],
    'probe observation receipt.producer',
  );
  assertControl(
    receipt.producer.thread_id === options.threadId
      && receipt.producer.host_id === options.hostId
      && receipt.producer.attempt === options.attempt,
    'CANARY_OBSERVATION_CROSS_IDENTITY',
    'probe observation receipt cross-thread/host/attempt',
  );
  assertControl(
    ['HOST_ADAPTER', 'ISOLATED_TEST_FAKE'].includes(
      receipt.producer.namespace,
    )
      && options.challengeRecord.producer_namespace
        === receipt.producer.namespace,
    'CANARY_OBSERVATION_PRODUCER_INVALID',
    'probe observation producer namespace 非法',
  );
  if (receipt.producer.namespace === 'ISOLATED_TEST_FAKE') {
    assertIsolatedTestMode(options.repositoryWorktree);
  }
  const observedAt = Date.parse(receipt.observed_at);
  const expiresAt = Date.parse(receipt.expires_at);
  const challengeIssuedAt = Date.parse(options.challengeRecord.issued_at);
  const challengeExpiresAt = Date.parse(options.challengeRecord.expires_at);
  const maxTtl = (
    options.manifest.probe_observation_receipts.max_ttl_ms
      || DEFAULT_MAX_TTL_MS
  );
  const now = options.acceptanceTime === undefined
    ? runtimeNowMilliseconds()
    : Date.parse(options.acceptanceTime);
  assertControl(
    Number.isFinite(now)
      && Number.isFinite(observedAt)
      && Number.isFinite(expiresAt)
      && Number.isSafeInteger(receipt.ttl_ms)
      && receipt.ttl_ms > 0
      && receipt.ttl_ms <= maxTtl
      && expiresAt - observedAt === receipt.ttl_ms
      && observedAt <= now
      && now < expiresAt
      && challengeIssuedAt <= observedAt
      && expiresAt <= challengeExpiresAt,
    'CANARY_OBSERVATION_EXPIRED',
    'probe observation receipt 时间/TTL 非法、未来或已过期',
  );
  assertControl(
    Array.isArray(receipt.probe_results)
      && receipt.probe_results.length === plan.required_probes.length,
    'CANARY_OBSERVATION_PROBE_MISMATCH',
    'probe observation receipt 缺项或多余 probe',
  );
  const evidenceContext = {
    stableId: request.stable_id,
    challenge: request.challenge,
    canaryPlanSha256: planSha256,
    goalId: options.goalId,
    taskId: options.taskId,
    role: options.role,
    threadId: options.threadId,
    hostId: options.hostId,
    attempt: options.attempt,
    targetIdentitySha256,
    targetFingerprintSha256,
  };
  validateReplayResult(
    receipt.replay_result,
    targetIdentitySha256,
    evidenceContext,
  );
  receipt.probe_results.forEach((result, index) => {
    validateProbeResult(
      result,
      plan.required_probes[index],
      index,
      targetIdentitySha256,
      index + 1,
      evidenceContext,
    );
    validateKnownLimitation(result, plan, receipt.probe_results);
  });
  const aggregate = aggregateProbeResults(receipt.probe_results);
  assertControl(
    receipt.aggregate_disposition === aggregate,
    'CANARY_OBSERVATION_AGGREGATE_MISMATCH',
    'probe observation receipt aggregate disposition 非机械聚合结果',
  );
  if (aggregate === 'FAIL' && receipt.probe_results.some((result) => (
    result.interactive.allow_prompt || result.interactive.auth_prompt
  ))) {
    throw new ControlError(
      'INTERACTIVE_APPROVAL_REQUIRED',
      '交互式 Allow/auth prompt 确定性归类为 FAIL',
    );
  }
  assertControl(
    ['PASS', 'KNOWN_LIMITATION'].includes(aggregate),
    'CANARY_OBSERVATION_NOT_PASS',
    `probe observation receipt aggregate=${aggregate}；registration/launch/FULL fail closed`,
  );
  assertControl(
    typeof options.evidenceDirectory === 'string'
      && path.isAbsolute(options.evidenceDirectory),
    'CANARY_OBSERVATION_EVIDENCE_REQUIRED',
    'controller durable evidence directory 缺失',
  );
  const durablePlanFile = path.join(options.evidenceDirectory, 'plan.json');
  const durableReceiptFile = path.join(
    options.evidenceDirectory,
    'receipt.json',
  );
  if (options.persistEvidence !== false) {
    if (!fs.existsSync(options.evidenceDirectory)) {
      ensureDir(options.evidenceDirectory);
    }
    fs.chmodSync(options.evidenceDirectory, 0o700);
    for (const [file, bytes] of [
      [durablePlanFile, planCapture.bytes],
      [durableReceiptFile, receiptCapture.bytes],
    ]) {
      if (fs.existsSync(file)) {
        assertControl(
          `sha256:${sha256(fs.readFileSync(file))}`
            === `sha256:${sha256(bytes)}`,
          'CANARY_OBSERVATION_REPLAY_CONFLICT',
          'controller durable evidence 已绑定不同 bytes',
        );
      } else {
        atomicCreate(file, bytes);
      }
      fs.chmodSync(file, 0o600);
    }
  }
  const bindingUnsigned = {
    schema_version: 1,
    protocol: PROTOCOL,
    accepted_at: new Date(now).toISOString(),
    attestation_algorithm: hostAttestation.algorithm,
    attestation_key_id: hostAttestation.key_id,
    attestation_public_key_sha256:
      hostAttestation.public_key_sha256,
    attestation_public_key_spki_base64:
      hostAttestation.public_key_spki_base64,
    attestation_signature_base64url:
      receipt.receipt_attestation.signature_base64url,
    plan_file: durablePlanFile,
    plan_file_sha256: planCapture.sha256,
    receipt_file: durableReceiptFile,
    receipt_sha256: request.receipt_sha256,
    canary_plan_sha256: planSha256,
    stable_id: request.stable_id,
    challenge: request.challenge,
    thread_id: options.threadId,
    host_id: options.hostId,
    attempt: options.attempt,
    target_identity_sha256: targetIdentitySha256,
    target_fingerprint_sha256: targetFingerprintSha256,
    aggregate_disposition: aggregate,
    observed_at: receipt.observed_at,
    expires_at: receipt.expires_at,
    probe_results_sha256: hashObject({
      replay_result: receipt.replay_result,
      probe_results: receipt.probe_results,
    }),
    receipt_binding_sha256: receipt.receipt_binding_sha256,
    request_sha256: hashObject(request),
  };
  const binding = validateBinding({
    ...bindingUnsigned,
    binding_sha256: hashObject(bindingUnsigned),
  });
  assertNoSensitiveStringLeaves(binding, {
    allowedDerivedStableId: request.stable_id,
  });
  return binding;
}

function validateBinding(value, label = 'probe observation binding') {
  exactKeys(value, BINDING_KEYS, label, 'CANARY_OBSERVATION_BINDING_INVALID');
  const unsigned = { ...value };
  delete unsigned.binding_sha256;
  assertControl(
    value.schema_version === 1
      && value.protocol === PROTOCOL
      && ['PASS', 'KNOWN_LIMITATION'].includes(
        value.aggregate_disposition,
      )
      && value.binding_sha256 === hashObject(unsigned)
      && CHALLENGE_RE.test(value.challenge)
      && Number.isSafeInteger(value.attempt)
      && value.attempt > 0
      && Number.isFinite(Date.parse(value.accepted_at))
      && Number.isFinite(Date.parse(value.observed_at))
      && Number.isFinite(Date.parse(value.expires_at)),
    'CANARY_OBSERVATION_BINDING_INVALID',
    `${label} schema/protocol/PASS/hash/time 非法`,
  );
  canonicalAbsolutePath(value.receipt_file, `${label}.receipt_file`);
  canonicalAbsolutePath(value.plan_file, `${label}.plan_file`);
  const hostAttestation = canonicalHostAttestation(
    {
      algorithm: value.attestation_algorithm,
      key_id: value.attestation_key_id,
      public_key_sha256: value.attestation_public_key_sha256,
      public_key_spki_base64:
        value.attestation_public_key_spki_base64,
    },
    `${label}.host_attestation`,
  );
  assertControl(
    typeof value.attestation_signature_base64url === 'string'
      && /^[A-Za-z0-9_-]{86}$/.test(
        value.attestation_signature_base64url,
      ),
    'CANARY_OBSERVATION_BINDING_INVALID',
    `${label}.attestation_signature_base64url 非法`,
  );
  normalizeHash(value.receipt_sha256, `${label}.receipt_sha256`);
  normalizeHash(value.plan_file_sha256, `${label}.plan_file_sha256`);
  normalizeHash(
    value.canary_plan_sha256,
    `${label}.canary_plan_sha256`,
  );
  normalizeHash(
    value.target_identity_sha256,
    `${label}.target_identity_sha256`,
  );
  normalizeHash(
    value.target_fingerprint_sha256,
    `${label}.target_fingerprint_sha256`,
  );
  normalizeHash(value.probe_results_sha256, `${label}.probe_results_sha256`);
  normalizeHash(
    value.receipt_binding_sha256,
    `${label}.receipt_binding_sha256`,
  );
  normalizeHash(value.request_sha256, `${label}.request_sha256`);
  safeId(value.stable_id, `${label}.stable_id`);
  safeId(value.thread_id, `${label}.thread_id`);
  safeId(value.host_id, `${label}.host_id`);
  assertControl(
    hostAttestation.public_key_sha256
      === value.attestation_public_key_sha256,
    'CANARY_OBSERVATION_BINDING_INVALID',
    `${label} attestation public key 漂移`,
  );
  return JSON.parse(JSON.stringify(value));
}

function requestMatchesBinding(binding, options) {
  const request = receiptOptions(options);
  if (binding === null || binding === undefined) return request === null;
  if (request === null) return false;
  const validated = validateBinding(binding);
  return validated.request_sha256 === hashObject(request)
    && validated.stable_id === request.stable_id
    && validated.challenge === request.challenge
    && validated.thread_id === options.threadId
    && validated.host_id === (options.hostId || 'local')
    && validated.attempt === Number(options.attempt || 1);
}

function assertLivePassBinding(
  binding,
  now = runtimeNowMilliseconds(),
  expected = {},
) {
  const validated = validateBinding(binding);
  const planCapture = readStableFile(validated.plan_file, {
    label: 'controller canary plan evidence',
    parentMode: 0o700,
    mode: 0o600,
    maxBytes: MAX_PLAN_BYTES,
  });
  assertControl(
    planCapture.sha256 === validated.plan_file_sha256,
    'CANARY_OBSERVATION_CONTENT_HASH_MISMATCH',
    'controller-held plan bytes/hash 漂移',
  );
  const receiptCapture = readStableFile(validated.receipt_file, {
    label: 'controller probe observation evidence',
    parentMode: 0o700,
    mode: 0o600,
    maxBytes: MAX_RECEIPT_BYTES,
  });
  assertControl(
    receiptCapture.sha256 === validated.receipt_sha256,
    'CANARY_OBSERVATION_CONTENT_HASH_MISMATCH',
    'controller-held receipt bytes/hash 漂移',
  );
  const receipt = parseJson(
    receiptCapture.bytes,
    'controller probe observation evidence',
  );
  assertNoSensitiveReceiptText(receiptCapture.bytes);
  assertControl(
    receipt.stable_id === validated.stable_id,
    'CANARY_OBSERVATION_BINDING_INVALID',
    'controller-held receipt stable ID 漂移',
  );
  assertNoSensitiveStringLeaves(receipt, {
    allowedDerivedStableId: validated.stable_id,
  });
  const receiptUnsigned = { ...receipt };
  delete receiptUnsigned.receipt_binding_sha256;
  const hostAttestation = canonicalHostAttestation(
    {
      algorithm: validated.attestation_algorithm,
      key_id: validated.attestation_key_id,
      public_key_sha256: validated.attestation_public_key_sha256,
      public_key_spki_base64:
        validated.attestation_public_key_spki_base64,
    },
    'controller-held host attestation',
  );
  assertReceiptAttestation(receipt, hostAttestation);
  const planEnvelope = parseJson(
    planCapture.bytes,
    'controller canary plan evidence',
  );
  const plan = planEnvelope.canary_plan;
  const {
    controllerProvenanceCapture,
  } = require('./canary-controller-attestation');
  const controller = controllerProvenanceCapture().provenance;
  assertControl(
    receipt.receipt_binding_sha256
        === validated.receipt_binding_sha256
      && receipt.receipt_binding_sha256 === hashObject(receiptUnsigned)
      && receipt.receipt_attestation.signature_base64url
        === validated.attestation_signature_base64url
      && receipt.receipt_attestation.algorithm
        === validated.attestation_algorithm
      && receipt.receipt_attestation.key_id
        === validated.attestation_key_id
      && receipt.receipt_attestation.public_key_sha256
        === validated.attestation_public_key_sha256
      && receipt.challenge === validated.challenge
      && receipt.target_identity_sha256
        === validated.target_identity_sha256
      && receipt.target_fingerprint_sha256
        === validated.target_fingerprint_sha256
      && hashObject({
        replay_result: receipt.replay_result,
        probe_results: receipt.probe_results,
      }) === validated.probe_results_sha256
      && plan
      && hashObject(plan.observation_receipt.host_attestation)
        === hashObject({
          algorithm: validated.attestation_algorithm,
          key_id: validated.attestation_key_id,
          public_key_sha256: validated.attestation_public_key_sha256,
        })
      && hashObject(plan.controller) === hashObject(controller),
    'CANARY_OBSERVATION_BINDING_INVALID',
    'controller-held receipt identity/results/controller seal 漂移',
  );
  if (expected.repositoryHead !== undefined) {
    assertControl(
      plan
        && plan.repository_head === expected.repositoryHead
        && (
          expected.role === undefined
            || plan.role === expected.role
        )
        && (
          expected.taskId === undefined
            || plan.task_id === (
              expected.role === 'FOREMAN' ? null : expected.taskId
            )
        ),
      'CANARY_OBSERVATION_STALE_PLAN',
      'controller-held receipt 不再绑定 live canonical task/role/HEAD',
    );
  }
  const observedAt = Date.parse(validated.observed_at);
  const expiresAt = Date.parse(validated.expires_at);
  assertControl(
    ['PASS', 'KNOWN_LIMITATION'].includes(
      validated.aggregate_disposition,
    )
      && observedAt <= now
      && now < expiresAt,
    'CANARY_OBSERVATION_EXPIRED',
    'launch/FULL 前 probe observation PASS receipt 已过期',
  );
  return validated;
}

function assertRequiredLiveBinding(
  manifest,
  session,
  operation,
  now = runtimeNowMilliseconds(),
  expected = {},
) {
  if (!protocolRequired(manifest)) return null;
  assertControl(
    session && session.probe_observation,
    'CANARY_OBSERVATION_REQUIRED',
    `${operation} 前缺 sealed probe observation PASS binding`,
  );
  return assertLivePassBinding(
    session.probe_observation,
    now,
    expected,
  );
}

module.exports = {
  ADAPTERS,
  DEFAULT_MAX_TTL_MS,
  DISPOSITIONS,
  MAX_RECEIPT_BYTES,
  PROTOCOL,
  RECEIPT_KIND,
  aggregateProbeResults,
  assertNoSensitiveStringLeaves,
  containsSensitiveStringLeaves,
  assertLivePassBinding,
  assertRequiredLiveBinding,
  controllerEvidenceReference,
  expectedAdapter,
  protocolRequired,
  receiptOptions,
  requestMatchesBinding,
  readStableFile,
  targetHashes,
  validateBinding,
  validateKnownLimitation,
  validateReceipt,
};
