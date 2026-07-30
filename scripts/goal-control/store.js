'use strict';

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ControlError, assertControl } = require('./errors');
const {
  canonicalJson,
  hashObject,
  nowIso,
  randomId,
  readJson,
  sha256,
  sleepSync,
  trustedTemporaryRoot,
} = require('./util');

const LEGACY_ROOT_GENERATION_SCHEMA_VERSION = 1;
const TRANSACTION_ROOT_GENERATION_SCHEMA_VERSION = 2;
const ROOT_GENERATION_SCHEMA_VERSION = 3;
const PRISTINE_PAYLOAD_VECTOR_SCHEMA_VERSION = 1;
const ROOT_GENERATION_FILE = '.generation.json';
const ATOMIC_TRANSPORT_DIRECTORY = '.atomic-transactions';
const ATOMIC_TRANSPORT_SCHEMA_VERSION = 2;
const ATOMIC_RESIDUAL_WRITE = 'WRITE';
const ATOMIC_RESIDUAL_CREATE = 'CREATE';
const ATOMIC_RESIDUAL_MKDIR = 'MKDIR';
const ATOMIC_MKDIR_LINEAGE = 'MKDIR_LINEAGE';
const ATOMIC_PUBLICATION_LINEAGE = 'PUBLISH_LINEAGE';
const ATOMIC_PUBLICATION_LINEAGE_SUFFIX = '.published';
const ATOMIC_MKDIR_CLAIM_PATTERN =
  /^\.mkdir-claim-([0-9a-f]{64})\.json$/;
const ATOMIC_PAYLOAD_PATTERN =
  /^\.payload-(WRITE|CREATE)-([0-9a-f]{64})-([0-9a-f]{64})-miss-([0-9]{1,4})(?:-time-([0-9]{13}))?\.tmp$/;
const ATOMIC_PUBLICATION_SUFFIX = '.publish';
const ATOMIC_RESERVATION_SUFFIX = '.reservation.json';
const ATOMIC_CLEANUP_MANIFEST_PATTERN =
  /^\.cleanup-manifest-([0-9a-f]{64})\.json$/;
const ATOMIC_CLEANUP_CLAIM_PATTERN =
  /^cleanup-(EVEN|PROTOCOL_ROTATION)-tx-([0-9a-f]{64})-gen-([0-9]+)-manifest-([0-9a-f]{64})-bind-([0-9a-f]{64})$/;
const MAX_ATOMIC_MKDIR_LINEAGE_CLAIMS = 16 * 1024;
const MAX_ATOMIC_PUBLICATION_LINEAGE_CLAIMS = 16 * 1024;
const MAX_ATOMIC_CLEANUP_MANIFEST_BYTES = 64 * 1024 * 1024;
const MAX_ATOMIC_TRANSPORT_DIRECTORIES = 64 * 1024;
const MAX_ATOMIC_TRANSPORT_DEPTH = 256;
const MAX_ATOMIC_TRANSPORT_RELATIVE_PATH_BYTES = 64 * 1024 * 1024;
const MAX_ATOMIC_INSPECTION_ARTIFACT_BYTES = 128 * 1024 * 1024;
const MAX_ATOMIC_INSPECTION_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_ATOMIC_RELOCATION_ENTRIES = 256 * 1024;
const MAX_ROOT_GENERATION_BYTES = 64 * 1024;
const LEGACY_ROOT_PROTOCOL_SCHEMA_VERSION = 2;
const ROOT_PROTOCOL_SCHEMA_VERSION = 3;
const ROOT_PROTOCOL_FILE = '.store-protocol.json';
const ROOT_PROTOCOL_ROTATION_DIRECTORY = '.protocol-rotations.v1';
const ROOT_PROTOCOL_ROTATION_SCHEMA_VERSION = 1;
const MAX_ROOT_PROTOCOL_ROTATIONS = 1024;
const MAX_ROOT_PROTOCOL_SEAL_BYTES = 16 * 1024 * 1024;
const MAX_ROOT_PROTOCOL_ROTATION_RECEIPT_BYTES = 16 * 1024 * 1024;
const MAX_PROTOCOL_AUTHORITY_SNAPSHOT_RETRIES = 16;
const PROTOCOL_AUTHORITY_SNAPSHOT_RETRY_MILLISECONDS = 5;
const DEFAULT_CONTROL_CONTENTION_TIMEOUT_MILLISECONDS = 5000;
const DEFAULT_LIVE_V2_CONTENTION_TIMEOUT_MILLISECONDS = 30000;
const ROOT_PROTOCOL_ROTATION_DRAIN_ACK =
  'ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED';
const CONTROLLER_DECODER_VERSION = 3;
const LOCK_OWNER_SCHEMA_VERSION = 1;
const LOCK_PROTOCOL_VERSION = 2;
const LOCK_OWNER_FILE = 'owner.json';
const WRITER_LOCK_KIND = 'WRITER';
const REAPER_LOCK_KIND = 'REAPER';
const CONTROLLER_DECODER_SEEDS = Object.freeze([
  'store.js',
  'validation.js',
  'fsm.js',
  'goal.js',
  'p1-commit-transaction.js',
  'preclaim-issues.js',
  'github-merge.js',
  'evidence.js',
  'resources.js',
  'preflight.js',
  'migration.js',
]);
const CONTROLLER_SCHEMA_DIRECTORY = 'schemas';
const LEGACY_EVIDENCE_ANCHOR_FILE = '.legacy-evidence-anchors.v1.json';
const LEGACY_IDENTITY_INCIDENT_RECEIPT_FILE =
  '.legacy-identity-incidents.v1.json';
const LEGACY_EVIDENCE_SOURCE_DIRECTORY = '.legacy-evidence-sources.v1';
const MAX_MIGRATION_SOURCE_ARTIFACTS = 4096;
const MAX_MIGRATION_SOURCE_ARTIFACT_BYTES = 16 * 1024 * 1024;
const MAX_MIGRATION_SOURCE_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_MIGRATION_INDEX_BYTES = 16 * 1024 * 1024;
let controllerDecoderFingerprintCache = null;

const TRANSACTION_KINDS = new Set([
  'AUDITED_REPAIR_ONLY',
  'GOAL_INIT',
  'GOAL_EVENT',
  'GOAL_EVENT_REJECTION',
  'P1_COMMIT',
  'P1_COMMIT_ABANDON',
  'PRECLAIM_ISSUES',
  'REGISTRATION',
  'FOREMAN_RECOVERY',
  'PROBE_OBSERVATION_CHALLENGE',
  'PROBE_OBSERVATION_REFRESH',
  'GOAL_CONTROL_EVENT',
  'SOURCE_EXPORT',
  'SOURCE_IMPORT',
  'SOURCE_CHECKPOINT',
  'SOURCE_CHECKPOINT_HOLD_REVALIDATION',
  'GITHUB_MERGE',
  'RESOURCE_ACQUIRE',
  'RESOURCE_RENEW',
  'RESOURCE_RELEASE',
  'ZERO_RUNTIME',
  'RESOURCE_IDENTITY_INCIDENT',
  'EVIDENCE_INGRESS',
  'PREFLIGHT_IDENTITY',
  'PREFLIGHT_INGRESS',
  'FAST_GATE',
  'FULL_GATE',
  'AC_AUDIT_GATE',
  'LEDGER_REBUILD',
  'PROTOCOL_ROTATION',
]);

function canonicalTransactionKey(kind, scope, stableId, requestHash) {
  assertControl(
    TRANSACTION_KINDS.has(kind),
    'TRANSACTION_KIND_INVALID',
    `未知 transaction kind: ${kind}`,
  );
  assertControl(
    scope
      && typeof scope === 'object'
      && !Array.isArray(scope)
      && Object.keys(scope).length > 0
      && Object.keys(scope).length <= 16,
    'TRANSACTION_SCOPE_INVALID',
    'transaction scope 必须是非空 string map',
  );
  const canonicalScope = {};
  for (const key of Object.keys(scope).sort()) {
    const value = scope[key];
    assertControl(
      /^[a-z][a-z0-9_]{0,63}$/.test(key)
        && typeof value === 'string'
        && value.length > 0
        && value.length <= 512
        && !/[\u0000-\u001f\u007f]/.test(value),
      'TRANSACTION_SCOPE_INVALID',
      `transaction scope ${key} 非法`,
    );
    canonicalScope[key] = value;
  }
  assertControl(
    typeof stableId === 'string'
      && stableId.length > 0
      && stableId.length <= 1024
      && !/[\u0000-\u001f\u007f]/.test(stableId),
    'TRANSACTION_STABLE_ID_INVALID',
    'transaction stable operation id 非法',
  );
  assertControl(
    typeof requestHash === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(requestHash),
    'TRANSACTION_REQUEST_HASH_INVALID',
    'transaction request hash 非法',
  );
  const unsigned = {
    schema_version: 1,
    kind,
    scope: canonicalScope,
    stable_operation_id_sha256: `sha256:${sha256(stableId)}`,
    request_sha256: requestHash,
  };
  return {
    ...unsigned,
    key_sha256: hashObject(unsigned),
  };
}

function validateTransactionKey(value) {
  assertControl(
    value
      && typeof value === 'object'
      && !Array.isArray(value)
      && Object.keys(value).length === 6
      && Object.keys(value).every((key) => [
        'schema_version',
        'kind',
        'scope',
        'stable_operation_id_sha256',
        'request_sha256',
        'key_sha256',
      ].includes(key)),
    'TRANSACTION_KEY_INVALID',
    'transaction key 字段非法',
  );
  assertControl(
    value.schema_version === 1
      && TRANSACTION_KINDS.has(value.kind)
      && value.scope
      && typeof value.scope === 'object'
      && !Array.isArray(value.scope)
      && Object.keys(value.scope).length > 0
      && Object.keys(value.scope).length <= 16
      && /^sha256:[0-9a-f]{64}$/.test(
        value.stable_operation_id_sha256 || '',
      )
      && /^sha256:[0-9a-f]{64}$/.test(value.request_sha256 || '')
      && /^sha256:[0-9a-f]{64}$/.test(value.key_sha256 || ''),
    'TRANSACTION_KEY_INVALID',
    'transaction key 格式非法',
  );
  const canonicalScope = {};
  for (const key of Object.keys(value.scope).sort()) {
    const scopeValue = value.scope[key];
    assertControl(
      /^[a-z][a-z0-9_]{0,63}$/.test(key)
        && typeof scopeValue === 'string'
        && scopeValue.length > 0
        && scopeValue.length <= 512
        && !/[\u0000-\u001f\u007f]/.test(scopeValue),
      'TRANSACTION_KEY_INVALID',
      `transaction scope ${key} 非法`,
    );
    canonicalScope[key] = scopeValue;
  }
  const unsigned = {
    schema_version: 1,
    kind: value.kind,
    scope: canonicalScope,
    stable_operation_id_sha256: value.stable_operation_id_sha256,
    request_sha256: value.request_sha256,
  };
  assertControl(
    hashObject(unsigned) === value.key_sha256
      && hashObject(value.scope) === hashObject(canonicalScope),
    'TRANSACTION_KEY_INVALID',
    'transaction key seal/canonical scope 不匹配',
  );
  return {
    ...unsigned,
    key_sha256: value.key_sha256,
  };
}

function ensureDirRaw(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function ensureDir(dir) {
  if (!activeAtomicTransaction) {
    ensureDirRaw(dir);
    return;
  }
  ensureTransactionDirectory(dir);
}

function fsyncDirectory(dir) {
  let directoryFd;
  try {
    directoryFd = fs.openSync(dir, 'r');
    fs.fsyncSync(directoryFd);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code)) throw error;
  } finally {
    if (directoryFd !== undefined) fs.closeSync(directoryFd);
  }
}

function atomicBody(body) {
  assertControl(
    typeof body === 'string'
      || Buffer.isBuffer(body)
      || ArrayBuffer.isView(body),
    'STORE_ATOMIC_BODY_INVALID',
    'atomic write body 必须是 string/Buffer/TypedArray',
  );
  return Buffer.isBuffer(body)
    ? Buffer.from(body)
    : Buffer.from(body);
}

function atomicResidualDescriptor(operation, file, body) {
  assertControl(
    [ATOMIC_RESIDUAL_WRITE, ATOMIC_RESIDUAL_CREATE].includes(operation),
    'STORE_ATOMIC_PLAN_INVALID',
    `未知 atomic residual operation: ${operation}`,
  );
  assertControl(
    typeof file === 'string' && file.length > 0,
    'STORE_ATOMIC_PLAN_INVALID',
    'atomic residual target 必须是非空路径',
  );
  const bytes = atomicBody(body);
  return Object.freeze({
    schema_version: ATOMIC_TRANSPORT_SCHEMA_VERSION,
    operation,
    file: path.resolve(file),
    body: bytes,
    payload_sha256: `sha256:${sha256(bytes)}`,
  });
}

function atomicResidualWrite(file, body) {
  return atomicResidualDescriptor(ATOMIC_RESIDUAL_WRITE, file, body);
}

function atomicResidualCreate(file, body) {
  return atomicResidualDescriptor(ATOMIC_RESIDUAL_CREATE, file, body);
}

let activeAtomicTransaction = null;

function isOddTransactionRetry(mode) {
  return mode === 'ODD_RETRY';
}

function isPreWitnessTransactionRetry(mode) {
  return mode === 'PRE_WITNESS_RETRY';
}

function isHistoricalTransactionRetry(mode) {
  return isOddTransactionRetry(mode)
    || isPreWitnessTransactionRetry(mode);
}

function historicalTransactionKeySha256(transaction) {
  if (!transaction || typeof transaction !== 'object') return null;
  if (isOddTransactionRetry(transaction.mode)) {
    return transaction.active_transaction
      && transaction.active_transaction.key_sha256;
  }
  if (isPreWitnessTransactionRetry(transaction.mode)) {
    return transaction.transport_transaction_key_sha256;
  }
  return null;
}

function atomicTransportRoot(root) {
  return path.join(root, ATOMIC_TRANSPORT_DIRECTORY);
}

function atomicTransactionHex(transactionKey) {
  const validated = validateTransactionKey(transactionKey);
  return validated.key_sha256.slice('sha256:'.length);
}

function assertPrivateOwnedDirectory(directory, label) {
  let stat;
  try {
    stat = fs.lstatSync(directory);
  } catch (error) {
    throw new ControlError(
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `${label} 无法读取: ${error.message}`,
    );
  }
  assertControl(
    stat.isDirectory()
      && !stat.isSymbolicLink()
      && stat.uid === process.getuid()
      && (stat.mode & 0o777) === 0o700,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `${label} 必须是当前 uid 持有的 0700 non-symlink directory`,
  );
  return stat;
}

function ensurePrivateOwnedDirectory(directory, label) {
  try {
    fs.mkdirSync(directory, { mode: 0o700 });
    fsyncDirectory(path.dirname(directory));
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  return assertPrivateOwnedDirectory(directory, label);
}

function assertPrivateOwnedAtomicFile(file, label) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    throw new ControlError(
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `${label} 无法读取: ${error.message}`,
    );
  }
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && stat.uid === process.getuid()
      && (stat.mode & 0o777) === 0o600
      && (stat.nlink === 1 || stat.nlink === 2),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `${label} 必须是当前 uid 持有、0600、link-count 1/2 的 regular file`,
  );
  return stat;
}

function assertPrivateOwnedPublicationMarker(file, label) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    throw new ControlError(
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `${label} 无法读取: ${error.message}`,
    );
  }
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && stat.uid === process.getuid()
      && (stat.mode & 0o777) === 0o600
      && stat.nlink >= 1
      && stat.nlink <= 3,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `${label} 必须是当前 uid 持有、0600、link-count 1/2/3 的 regular file`,
  );
  return stat;
}

function createAtomicInspectionBudget(
  maxArtifactBytes,
  maxTotalBytes,
  errorCode = 'STORE_ATOMIC_ARTIFACT_INVALID',
) {
  assertControl(
    Number.isSafeInteger(maxArtifactBytes)
      && maxArtifactBytes > 0
      && Number.isSafeInteger(maxTotalBytes)
      && maxTotalBytes >= maxArtifactBytes
      && [
        'STORE_ATOMIC_ARTIFACT_INVALID',
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
      ].includes(errorCode),
    'STORE_ATOMIC_ARTIFACT_INVALID',
    'atomic inspection byte budget 非法',
  );
  return {
    max_artifact_bytes: maxArtifactBytes,
    max_total_bytes: maxTotalBytes,
    consumed_bytes: 0,
    error_code: errorCode,
  };
}

function atomicInspectionErrorCode(budget) {
  return budget === null
    ? 'STORE_ATOMIC_RESIDUAL_CONFLICT'
    : budget.error_code;
}

function sameAtomicFileBinding(left, right) {
  return sameFileIdentity(left, right)
    && left.uid === right.uid
    && (left.mode & 0o777) === (right.mode & 0o777)
    && left.size === right.size
    && left.nlink === right.nlink;
}

function readBoundedOpenDescriptor(
  file,
  descriptor,
  expected,
  maxBytes,
  errorCode,
  label,
) {
  assertControl(
    Number.isSafeInteger(maxBytes)
      && maxBytes >= 0
      && Number.isSafeInteger(expected.size)
      && expected.size >= 0
      && expected.size <= maxBytes,
    errorCode,
    `${label} 超出 bounded FD read 上限`,
  );
  let pathnameBefore;
  try {
    pathnameBefore = fs.lstatSync(file);
  } catch (error) {
    throw new ControlError(
      errorCode,
      `${label} bounded FD read 前 pathname 无法读取: ${error.message}`,
    );
  }
  const opened = fs.fstatSync(descriptor);
  assertControl(
    opened.isFile()
      && pathnameBefore.isFile()
      && !pathnameBefore.isSymbolicLink()
      && sameAtomicFileBinding(expected, opened)
      && sameAtomicFileBinding(opened, pathnameBefore)
      && opened.size <= maxBytes,
    errorCode,
    `${label} bounded FD read 前 identity/mode/size/link 漂移`,
  );
  const bytes = Buffer.alloc(opened.size);
  let offset = 0;
  while (offset < bytes.length) {
    const count = fs.readSync(
      descriptor,
      bytes,
      offset,
      bytes.length - offset,
      offset,
    );
    assertControl(
      count > 0,
      errorCode,
      `${label} bounded FD read 截断`,
    );
    offset += count;
  }
  const after = fs.fstatSync(descriptor);
  let pathnameAfter;
  try {
    pathnameAfter = fs.lstatSync(file);
  } catch (error) {
    throw new ControlError(
      errorCode,
      `${label} bounded FD read 后 pathname 无法读取: ${error.message}`,
    );
  }
  assertControl(
    sameAtomicFileBinding(opened, after)
      && pathnameAfter.isFile()
      && !pathnameAfter.isSymbolicLink()
      && sameAtomicFileBinding(opened, pathnameAfter),
    errorCode,
    `${label} bounded FD read 期间 identity/mode/size/link 漂移`,
  );
  return bytes;
}

function assertAtomicPathBinding(file, expected, errorCode, label) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
  } catch (error) {
    throw new ControlError(
      errorCode,
      `${label} pathname 无法安全打开: ${error.message}`,
    );
  }
  try {
    const opened = fs.fstatSync(descriptor);
    const pathname = fs.lstatSync(file);
    assertControl(
      opened.isFile()
        && pathname.isFile()
        && !pathname.isSymbolicLink()
        && sameAtomicFileBinding(expected, opened)
        && sameAtomicFileBinding(opened, pathname),
      errorCode,
      `${label} pathname/inode/mode/size/link 漂移`,
    );
  } finally {
    fs.closeSync(descriptor);
  }
}

function readAtomicInspectionFile(
  file,
  stat,
  budget,
  label,
  maxBytesOverride = null,
) {
  const maxBytes = maxBytesOverride === null
    ? (
      budget === null
        ? MAX_ATOMIC_INSPECTION_ARTIFACT_BYTES
        : budget.max_artifact_bytes
    )
    : maxBytesOverride;
  const errorCode = atomicInspectionErrorCode(budget);
  assertControl(
    Number.isSafeInteger(stat.size)
      && stat.size >= 0
      && stat.size <= maxBytes
      && (
        budget === null
          || budget.consumed_bytes <= budget.max_total_bytes - stat.size
      ),
    errorCode,
    `${label} 超出 atomic inspection byte budget`,
  );
  const descriptor = fs.openSync(
    file,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const opened = fs.fstatSync(descriptor);
    assertControl(
      opened.isFile()
        && sameFileIdentity(stat, opened)
        && opened.uid === stat.uid
        && (opened.mode & 0o777) === (stat.mode & 0o777)
        && opened.size === stat.size
        && opened.nlink === stat.nlink
        && opened.size <= maxBytes
        && (
          budget === null
            || budget.consumed_bytes
              <= budget.max_total_bytes - opened.size
        ),
      errorCode,
      `${label} open identity/mode/size/link 超出 inspection binding`,
    );
    if (budget !== null) budget.consumed_bytes += opened.size;
    return readBoundedOpenDescriptor(
      file,
      descriptor,
      opened,
      maxBytes,
      errorCode,
      label,
    );
  } finally {
    fs.closeSync(descriptor);
  }
}

function inspectAtomicFileDigest(file, stat, label, maxBytes) {
  assertControl(
    Number.isSafeInteger(maxBytes)
      && maxBytes >= 0
      && stat.size <= maxBytes,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `${label} 超出 sealed size 上限`,
  );
  const descriptor = fs.openSync(
    file,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const opened = fs.fstatSync(descriptor);
    assertControl(
      opened.isFile()
        && sameFileIdentity(stat, opened)
        && opened.uid === stat.uid
        && (opened.mode & 0o777) === (stat.mode & 0o777)
        && opened.size === stat.size
        && opened.size <= maxBytes
        && opened.nlink === stat.nlink,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `${label} digest open identity/mode/size/link 漂移`,
    );
    const digest = crypto.createHash('sha256');
    const chunk = Buffer.alloc(Math.min(64 * 1024, opened.size || 1));
    let offset = 0;
    while (offset < opened.size) {
      const count = fs.readSync(
        descriptor,
        chunk,
        0,
        Math.min(chunk.length, opened.size - offset),
        offset,
      );
      assertControl(
        count > 0,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `${label} digest read 截断`,
      );
      digest.update(chunk.subarray(0, count));
      offset += count;
    }
    const after = fs.fstatSync(descriptor);
    const pathnameAfter = fs.lstatSync(file);
    assertControl(
      sameFileIdentity(opened, after)
        && after.uid === opened.uid
        && (after.mode & 0o777) === (opened.mode & 0o777)
        && after.size === opened.size
        && after.nlink === opened.nlink
        && sameFileIdentity(opened, pathnameAfter)
        && pathnameAfter.uid === opened.uid
        && (pathnameAfter.mode & 0o777) === (opened.mode & 0o777)
        && pathnameAfter.size === opened.size
        && pathnameAfter.nlink === opened.nlink,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `${label} digest read 期间 identity/mode/size/link 漂移`,
    );
    return `sha256:${digest.digest('hex')}`;
  } finally {
    fs.closeSync(descriptor);
  }
}

function inspectAtomicCanonical(
  file,
  budget = null,
  maxBytesOverride = null,
  expectedStat = null,
  reusable = null,
) {
  const errorCode = atomicInspectionErrorCode(budget);
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return {
        kind: 'MISSING',
        descriptor_sha256: hashObject({
          schema_version: ATOMIC_TRANSPORT_SCHEMA_VERSION,
          kind: 'MISSING',
        }),
      };
    }
    throw error;
  }
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && stat.uid === process.getuid()
      && (
        expectedStat === null
          || sameAtomicFileBinding(expectedStat, stat)
      ),
    errorCode,
    `atomic canonical ${file} 必须是当前 uid 持有的 non-symlink regular file`,
  );
  let bytes;
  if (
    reusable !== null
      && Buffer.isBuffer(reusable.bytes)
      && sameAtomicFileBinding(reusable.stat, stat)
      && reusable.bytes.length === stat.size
  ) {
    assertAtomicPathBinding(
      file,
      stat,
      errorCode,
      `atomic canonical ${file} reusable payload`,
    );
    bytes = reusable.bytes;
  } else {
    bytes = readAtomicInspectionFile(
      file,
      stat,
      budget,
      `atomic canonical ${file}`,
      maxBytesOverride,
    );
  }
  const descriptor = {
    schema_version: ATOMIC_TRANSPORT_SCHEMA_VERSION,
    kind: 'FILE',
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: stat.mode & 0o777,
    uid: stat.uid,
    size: stat.size,
    payload_sha256: `sha256:${sha256(bytes)}`,
  };
  return {
    ...descriptor,
    bytes,
    stat,
    descriptor_sha256: hashObject(descriptor),
  };
}

function sameFileIdentity(left, right) {
  return left
    && right
    && left.dev === right.dev
    && left.ino === right.ino;
}

function atomicPayloadName(
  operation,
  payloadSha256,
  preimageSha256,
  missingDirectoryCount,
  stableTime,
) {
  const timestamp = stableTime === null || stableTime === undefined
    ? ''
    : `-time-${String(stableTime)}`;
  return `.payload-${operation}-${
    payloadSha256.slice('sha256:'.length)
  }-${preimageSha256.slice('sha256:'.length)}-miss-${
    missingDirectoryCount
  }${timestamp}.tmp`;
}

function sealedAtomicOperationReservation(
  transactionHex,
  operation,
  targetRelative,
  payloadSha256,
  preimageSha256,
  missingRelativeDirectories,
  pristineMissingRelativeDirectories,
  stableTime,
) {
  const unsigned = {
    schema_version: ATOMIC_TRANSPORT_SCHEMA_VERSION,
    kind: 'ATOMIC_OPERATION_RESERVATION',
    transaction_key_sha256: `sha256:${transactionHex}`,
    operation,
    target_relative: targetRelative.split(path.sep).join('/'),
    payload_sha256: payloadSha256,
    preimage_sha256: preimageSha256,
    missing_relative_directories: missingRelativeDirectories.map(
      (relative) => relative.split(path.sep).join('/'),
    ),
    pristine_missing_relative_directories:
      pristineMissingRelativeDirectories.map(
        (relative) => relative.split(path.sep).join('/'),
      ),
    stable_time_milliseconds: stableTime,
  };
  return {
    ...unsigned,
    reservation_sha256: hashObject(unsigned),
  };
}

function atomicOperationReservationBody(reservation) {
  return Buffer.from(`${JSON.stringify(reservation, null, 2)}\n`);
}

function validateAtomicOperationReservation(
  transactionHex,
  operation,
  targetRelative,
  payloadSha256,
  preimageSha256,
  missingRelativeDirectories,
  pristineMissingRelativeDirectories,
  stableTime,
  reservation,
) {
  const expected = sealedAtomicOperationReservation(
    transactionHex,
    operation,
    targetRelative,
    payloadSha256,
    preimageSha256,
    missingRelativeDirectories,
    pristineMissingRelativeDirectories,
    stableTime,
  );
  assertControl(
    reservation
      && typeof reservation === 'object'
      && !Array.isArray(reservation)
      && Object.keys(reservation).length === 11
      && Object.keys(reservation).every((key) => [
        'schema_version',
        'kind',
        'transaction_key_sha256',
        'operation',
        'target_relative',
        'payload_sha256',
        'preimage_sha256',
        'missing_relative_directories',
        'pristine_missing_relative_directories',
        'stable_time_milliseconds',
        'reservation_sha256',
      ].includes(key))
      && canonicalJson(reservation) === canonicalJson(expected),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic operation reservation seal/binding 非法: ${targetRelative}`,
  );
  return expected;
}

function atomicTargetRelative(root, file) {
  const resolvedRoot = path.resolve(root);
  const resolvedFile = path.resolve(file);
  const relative = path.relative(resolvedRoot, resolvedFile);
  assertControl(
    relative
      && relative !== '..'
      && !relative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relative),
    'STORE_ATOMIC_PATH_INVALID',
    `transaction-bound atomic target 越出 control root: ${resolvedFile}`,
  );
  return relative;
}

function atomicMirrorDirectory(transactionDirectory, operation, targetRelative) {
  return path.join(
    transactionDirectory,
    operation,
    ...targetRelative.split(path.sep),
  );
}

function atomicTransactionDirectory(root, transactionHex) {
  return path.join(atomicTransportRoot(root), `tx-${transactionHex}`);
}

function missingAtomicDirectories(root, targetRelative) {
  const components = targetRelative.split(path.sep);
  const missing = [];
  let current = path.resolve(root);
  let foundMissing = false;
  for (let index = 0; index < components.length; index += 1) {
    current = path.join(current, components[index]);
    const relative = path.join(...components.slice(0, index + 1));
    if (foundMissing || !fs.existsSync(current)) {
      foundMissing = true;
      missing.push(relative);
      continue;
    }
    const stat = fs.lstatSync(current);
    assertControl(
      stat.isDirectory()
        && !stat.isSymbolicLink()
        && stat.uid === process.getuid(),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic mkdir ancestor 不是当前 uid 的 directory: ${relative}`,
    );
  }
  return missing;
}

function sealedAtomicMkdirClaim(
  transactionHex,
  targetRelative,
  missingRelativeDirectories,
) {
  const unsigned = {
    schema_version: ATOMIC_TRANSPORT_SCHEMA_VERSION,
    kind: 'ATOMIC_MKDIR_CLAIM',
    transaction_key_sha256: `sha256:${transactionHex}`,
    target_relative: targetRelative.split(path.sep).join('/'),
    missing_relative_directories: missingRelativeDirectories.map(
      (relative) => relative.split(path.sep).join('/'),
    ),
  };
  return {
    ...unsigned,
    claim_sha256: hashObject(unsigned),
  };
}

function atomicMkdirClaimBody(claim) {
  return Buffer.from(`${JSON.stringify(claim, null, 2)}\n`);
}

function validateAtomicMkdirClaim(
  root,
  transactionHex,
  targetRelative,
  claim,
) {
  assertControl(
    claim
      && typeof claim === 'object'
      && !Array.isArray(claim)
      && Object.keys(claim).length === 6
      && Object.keys(claim).every((key) => [
        'schema_version',
        'kind',
        'transaction_key_sha256',
        'target_relative',
        'missing_relative_directories',
        'claim_sha256',
      ].includes(key)),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic mkdir claim 字段非法',
  );
  const unsigned = { ...claim };
  delete unsigned.claim_sha256;
  const normalizedTarget = targetRelative.split(path.sep).join('/');
  assertControl(
    claim.schema_version === ATOMIC_TRANSPORT_SCHEMA_VERSION
      && claim.kind === 'ATOMIC_MKDIR_CLAIM'
      && claim.transaction_key_sha256 === `sha256:${transactionHex}`
      && claim.target_relative === normalizedTarget
      && Array.isArray(claim.missing_relative_directories)
      && claim.missing_relative_directories.length > 0
      && claim.missing_relative_directories.every(
        (relative) => typeof relative === 'string' && relative.length > 0,
      )
      && hashObject(unsigned) === claim.claim_sha256,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic mkdir claim seal/transaction/target 非法',
  );
  const targetComponents = targetRelative.split(path.sep);
  const expectedSuffixes = targetComponents.map(
    (_component, index) => path.join(...targetComponents.slice(0, index + 1)),
  );
  const normalizedMissing = claim.missing_relative_directories.map(
    (relative) => relative.split('/').join(path.sep),
  );
  const suffixStart = expectedSuffixes.length - normalizedMissing.length;
  assertControl(
    suffixStart >= 0
      && canonicalJson(normalizedMissing)
        === canonicalJson(expectedSuffixes.slice(suffixStart)),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic mkdir claim missing directories 不是 exact continuous suffix',
  );
  for (const relative of normalizedMissing) {
    const candidate = path.join(root, relative);
    let stat;
    try {
      stat = fs.lstatSync(candidate);
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic mkdir claimed path 无法验证: ${relative}: ${error.message}`,
      );
    }
    assertControl(
      stat.isDirectory()
        && !stat.isSymbolicLink()
        && stat.uid === process.getuid()
        && (stat.mode & 0o777) === 0o700,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic mkdir claimed path 不是当前 uid 的 0700 directory: ${relative}`,
    );
  }
  return {
    ...claim,
    missing_relative_directories: normalizedMissing,
  };
}

function walkAtomicTransport(
  directory,
  relative,
  output,
  traversal = null,
) {
  const rootCall = traversal === null;
  const state = traversal || {
    directory_count: 0,
    file_count: 0,
    entry_count: 0,
    relative_path_bytes: 0,
  };
  const handle = fs.opendirSync(directory);
  try {
    for (;;) {
      const entry = handle.readSync();
      if (entry === null) break;
      state.entry_count += 1;
      assertControl(
        state.entry_count
          <= MAX_ATOMIC_TRANSPORT_DIRECTORIES
            + MAX_ATOMIC_MKDIR_LINEAGE_CLAIMS
            + MAX_ATOMIC_PUBLICATION_LINEAGE_CLAIMS
            + 3,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        'atomic transport entry 数量超出上限',
      );
      const childRelative = relative
        ? path.join(relative, entry.name)
        : entry.name;
      const depth = childRelative.split(path.sep).length;
      state.relative_path_bytes += Buffer.byteLength(childRelative);
      assertControl(
        depth <= MAX_ATOMIC_TRANSPORT_DEPTH
          && state.relative_path_bytes
            <= MAX_ATOMIC_TRANSPORT_RELATIVE_PATH_BYTES,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        'atomic transport path depth/total bytes 超出上限',
      );
      const child = path.join(directory, entry.name);
      const stat = fs.lstatSync(child);
      assertControl(
        !stat.isSymbolicLink(),
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic transport 含 symlink: ${childRelative}`,
      );
      if (stat.isDirectory()) {
        state.directory_count += 1;
        assertControl(
          state.directory_count <= MAX_ATOMIC_TRANSPORT_DIRECTORIES,
          'STORE_ATOMIC_RESIDUAL_CONFLICT',
          'atomic transport directory 数量超出上限',
        );
        assertPrivateOwnedDirectory(
          child,
          `atomic transport directory ${childRelative}`,
        );
        output.directories.push(childRelative);
        walkAtomicTransport(child, childRelative, output, state);
        continue;
      }
      state.file_count += 1;
      assertControl(
        stat.isFile()
          && state.file_count
            <= MAX_ATOMIC_MKDIR_LINEAGE_CLAIMS
              + MAX_ATOMIC_PUBLICATION_LINEAGE_CLAIMS
              + 3,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic transport 含非 regular/过量 file: ${childRelative}`,
      );
      output.files.push(childRelative);
    }
  } finally {
    handle.closeSync();
  }
  if (rootCall) {
    output.directories.sort();
    output.files.sort();
  }
}

function boundedAtomicDirectoryEntries(directory, maximum, label) {
  const entries = [];
  const handle = fs.opendirSync(directory);
  try {
    for (;;) {
      const entry = handle.readSync();
      if (entry === null) break;
      assertControl(
        entries.length < maximum,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `${label} entry 数量超出上限`,
      );
      entries.push(entry.name);
    }
  } finally {
    handle.closeSync();
  }
  return entries.sort();
}

function inspectAtomicMkdirClaim(
  root,
  transactionHex,
  transactionDirectory,
  relativeClaim,
  budget = null,
) {
  const parts = relativeClaim.split(path.sep);
  const match = ATOMIC_MKDIR_CLAIM_PATTERN.exec(parts[parts.length - 1]);
  const lineage = parts[0] === ATOMIC_MKDIR_LINEAGE;
  assertControl(
    (
      (lineage && parts.length === 2)
        || (
          !lineage
            && parts.length >= 3
            && parts[0] === ATOMIC_RESIDUAL_MKDIR
        )
    )
      && match,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic mkdir claim path 非法: ${relativeClaim}`,
  );
  const file = path.join(transactionDirectory, relativeClaim);
  const stat = assertPrivateOwnedAtomicFile(
    file,
    `atomic mkdir claim ${relativeClaim}`,
  );
  assertControl(
    stat.nlink === 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic mkdir claim 必须是 single-link file: ${relativeClaim}`,
  );
  const raw = readAtomicInspectionFile(
    file,
    stat,
    budget,
    `atomic mkdir claim ${relativeClaim}`,
  );
  let parsedLineage = null;
  if (lineage) {
    try {
      parsedLineage = JSON.parse(raw.toString('utf8'));
    } catch (error) {
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic mkdir lineage claim 未完整: ${error.message}`,
      );
    }
  }
  const targetRelative = lineage
    ? String(parsedLineage.target_relative || '')
      .split('/').join(path.sep)
    : parts.slice(1, -1).join(path.sep);
  assertControl(
    targetRelative
      && targetRelative !== '..'
      && !targetRelative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(targetRelative),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic mkdir mirrored target 非法: ${targetRelative}`,
  );
  const currentMissing = missingAtomicDirectories(root, targetRelative);
  let claim;
  let complete = false;
  try {
    claim = validateAtomicMkdirClaim(
      root,
      transactionHex,
      targetRelative,
      parsedLineage || JSON.parse(raw.toString('utf8')),
    );
    complete = true;
  } catch (error) {
    if (lineage) throw error;
    const expected = sealedAtomicMkdirClaim(
      transactionHex,
      targetRelative,
      currentMissing,
    );
    const expectedBody = atomicMkdirClaimBody(expected);
    assertControl(
      currentMissing.length > 0
        && raw.length < expectedBody.length
        && expectedBody.subarray(0, raw.length).equals(raw)
        && match[1] === expected.claim_sha256.slice('sha256:'.length),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic mkdir partial claim 不是 exact expected prefix: ${targetRelative}`,
    );
    claim = expected;
  }
  assertControl(
    complete || currentMissing.length > 0,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic mkdir partial claim 与已创建 canonical directories 并存: ${targetRelative}`,
  );
  return {
    operation: ATOMIC_RESIDUAL_MKDIR,
    payload_sha256: null,
    preimage_sha256: null,
    stable_time_milliseconds: null,
    target: path.join(root, targetRelative),
    target_relative: targetRelative,
    file,
    stat,
    complete,
    lineage,
    transport_kind: lineage
      ? ATOMIC_MKDIR_LINEAGE
      : ATOMIC_RESIDUAL_MKDIR,
    body: atomicMkdirClaimBody(claim),
    claim_record: claim,
    missing_relative_directories: claim.missing_relative_directories,
    canonical: null,
    canonical_is_payload: false,
  };
}

function relocatedAtomicPublicationLinks(root, markerStat) {
  const links = [];
  const traversal = {
    entries: 0,
    relative_path_bytes: 0,
  };
  const visit = (directory, relativeDirectory) => {
    const handle = fs.opendirSync(directory);
    try {
      for (;;) {
        const entry = handle.readSync();
        if (entry === null) break;
        const relative = relativeDirectory
          ? path.join(relativeDirectory, entry.name)
          : entry.name;
        if (
          !relativeDirectory
            && (
              relative === ATOMIC_TRANSPORT_DIRECTORY
                || relative === '.lock'
                || relative.startsWith('.lock.')
            )
        ) {
          continue;
        }
        traversal.entries += 1;
        traversal.relative_path_bytes += Buffer.byteLength(relative);
        assertControl(
          traversal.entries <= MAX_ATOMIC_RELOCATION_ENTRIES
            && relative.split(path.sep).length
              <= MAX_ATOMIC_TRANSPORT_DEPTH
            && traversal.relative_path_bytes
              <= MAX_ATOMIC_TRANSPORT_RELATIVE_PATH_BYTES,
          'STORE_ATOMIC_RESIDUAL_CONFLICT',
          'relocated publication scan entry/depth/path bytes 超出上限',
        );
        const absolute = path.join(directory, entry.name);
        const stat = fs.lstatSync(absolute);
        if (stat.isDirectory() && !stat.isSymbolicLink()) {
          visit(absolute, relative);
        } else if (
          stat.isFile()
            && !stat.isSymbolicLink()
            && sameFileIdentity(stat, markerStat)
        ) {
          assertControl(
            stat.uid === process.getuid()
              && (stat.mode & 0o777) === 0o600,
            'STORE_ATOMIC_RESIDUAL_CONFLICT',
            `relocated publication link mode/uid 非法: ${relative}`,
          );
          links.push(absolute);
        }
      }
    } finally {
      handle.closeSync();
    }
  };
  visit(root, '');
  return links;
}

function parseAtomicPublicationLineage(root, relativeMarker) {
  const parts = relativeMarker.split(path.sep);
  const markerName = parts[parts.length - 1];
  const payloadName = markerName.endsWith(
    ATOMIC_PUBLICATION_LINEAGE_SUFFIX,
  )
    ? markerName.slice(
      0,
      -ATOMIC_PUBLICATION_LINEAGE_SUFFIX.length,
    )
    : '';
  const match = ATOMIC_PAYLOAD_PATTERN.exec(payloadName);
  const operation = parts[1];
  const targetRelative = parts.slice(2, -1).join(path.sep);
  assertControl(
    parts.length >= 4
      && parts[0] === ATOMIC_PUBLICATION_LINEAGE
      && [ATOMIC_RESIDUAL_WRITE, ATOMIC_RESIDUAL_CREATE]
        .includes(operation)
      && match
      && match[1] === operation
      && targetRelative
      && targetRelative !== '..'
      && !targetRelative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(targetRelative),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic publication lineage path 非法: ${relativeMarker}`,
  );
  const payloadSha256 = `sha256:${match[2]}`;
  const target = path.join(root, targetRelative);
  const targetParentRelative = path.dirname(targetRelative);
  const parentComponents = targetParentRelative === '.'
    ? []
    : targetParentRelative.split(path.sep);
  const missingDirectoryCount = Number(match[4]);
  assertControl(
    Number.isSafeInteger(missingDirectoryCount)
      && missingDirectoryCount >= 0
      && missingDirectoryCount <= parentComponents.length,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic publication lineage missing-directory count 非法: ${relativeMarker}`,
  );
  const stableTime = match[5] ? Number(match[5]) : null;
  assertControl(
    stableTime === null
      || (
        Number.isSafeInteger(stableTime)
          && stableTime >= 0
          && String(stableTime).length === 13
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic publication lineage stable timestamp 非法: ${relativeMarker}`,
  );
  return {
    operation,
    target,
    target_relative: targetRelative,
    payload_sha256: payloadSha256,
    preimage_sha256: `sha256:${match[3]}`,
    missing_relative_directories: parentComponents
      .map((_component, index) => (
        path.join(...parentComponents.slice(0, index + 1))
      ))
      .slice(parentComponents.length - missingDirectoryCount),
    stable_time_milliseconds: stableTime,
    relative_file: relativeMarker,
    payload_name: payloadName,
  };
}

function inspectAtomicPublicationLineage(
  root,
  transactionDirectory,
  relativeMarker,
  budget = null,
) {
  const parsed = parseAtomicPublicationLineage(root, relativeMarker);
  const marker = path.join(transactionDirectory, relativeMarker);
  const stat = assertPrivateOwnedPublicationMarker(
    marker,
    `atomic publication lineage ${relativeMarker}`,
  );
  assertControl(
    stat.nlink >= 1 && stat.nlink <= 3,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic publication lineage link-count 非法: ${relativeMarker}`,
  );
  const bytes = readAtomicInspectionFile(
    marker,
    stat,
    budget,
    `atomic publication lineage ${relativeMarker}`,
  );
  assertControl(
    `sha256:${sha256(bytes)}` === parsed.payload_sha256,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic publication lineage payload hash 非法: ${relativeMarker}`,
  );
  const target = parsed.target;
  const canonical = inspectAtomicCanonical(
    target,
    budget,
    null,
    null,
    { stat, bytes },
  );
  const canonicalIsPayload =
    canonical.kind === 'FILE'
      && sameFileIdentity(stat, canonical.stat);
  const relocatedLinks = !canonicalIsPayload && stat.nlink === 2
    ? relocatedAtomicPublicationLinks(root, stat)
    : [];
  return {
    ...parsed,
    file: marker,
    stat,
    bytes,
    canonical,
    canonical_is_payload: canonicalIsPayload,
    relocated_canonical_links: relocatedLinks,
  };
}

function inspectAtomicCleanupManifestStaging(
  transactionDirectory,
  relativeManifest,
  budget = null,
) {
  const match = ATOMIC_CLEANUP_MANIFEST_PATTERN.exec(relativeManifest);
  assertControl(
    match && !relativeManifest.includes(path.sep),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic cleanup manifest path 非法: ${relativeManifest}`,
  );
  const file = path.join(transactionDirectory, relativeManifest);
  const stat = assertPrivateOwnedAtomicFile(
    file,
    'atomic cleanup manifest',
  );
  assertControl(
    stat.nlink === 1 && stat.size <= MAX_ATOMIC_CLEANUP_MANIFEST_BYTES,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup manifest 必须是 bounded single-link file',
  );
  const raw = readAtomicInspectionFile(
    file,
    stat,
    budget,
    'atomic cleanup manifest',
    MAX_ATOMIC_CLEANUP_MANIFEST_BYTES,
  );
  const expectedSha256 = `sha256:${match[1]}`;
  let record = null;
  let complete = false;
  if (`sha256:${sha256(raw)}` === expectedSha256) {
    try {
      record = JSON.parse(raw.toString('utf8'));
      complete = `${canonicalJson(record)}\n` === raw.toString('utf8');
    } catch {
      complete = false;
    }
  }
  return {
    file,
    relative_file: relativeManifest,
    stat,
    raw,
    expected_sha256: expectedSha256,
    complete,
    record,
  };
}

function inspectAtomicTransport(
  root,
  expectedTransactionHex = null,
  options = {},
) {
  const budget = options.inspectionBudget || createAtomicInspectionBudget(
    MAX_ATOMIC_INSPECTION_ARTIFACT_BYTES,
    MAX_ATOMIC_INSPECTION_TOTAL_BYTES,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
  );
  const transport = atomicTransportRoot(root);
  const empty = () => ({
    transport,
    transactionHex: null,
    transactionDirectory: null,
    directories: [],
    mkdir_lineage_claims: [],
    publication_lineage_claims: [],
    lineage_missing_relative_directories: [],
    cleanup_manifest: null,
    residual: null,
  });
  if (!fs.existsSync(transport)) return empty();
  assertPrivateOwnedDirectory(transport, 'atomic transport root');
  const entries = boundedAtomicDirectoryEntries(
    transport,
    2,
    'atomic transport root',
  );
  assertControl(
    entries.length <= 1
      && entries.every((entry) => /^tx-[0-9a-f]{64}$/.test(entry)),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic transport root 含 foreign/lookalike/multiple transaction staging',
  );
  if (entries.length === 0) return empty();
  const transactionHex = entries[0].slice('tx-'.length);
  assertControl(
    expectedTransactionHex === null
      || transactionHex === expectedTransactionHex,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic transport 绑定了不同 transaction',
  );
  const transactionDirectory = path.join(transport, entries[0]);
  assertPrivateOwnedDirectory(
    transactionDirectory,
    `atomic transaction ${transactionHex}`,
  );
  const walked = { directories: [], files: [] };
  walkAtomicTransport(transactionDirectory, '', walked);
  assertControl(
    walked.files.length
      <= MAX_ATOMIC_MKDIR_LINEAGE_CLAIMS
        + MAX_ATOMIC_PUBLICATION_LINEAGE_CLAIMS
        + 3,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic transaction 含 multiple/foreign staging',
  );
  if (walked.files.length === 0) {
    return {
      transport,
      transactionHex,
      transactionDirectory,
      directories: walked.directories,
      mkdir_lineage_claims: [],
      publication_lineage_claims: [],
      lineage_missing_relative_directories: [],
      cleanup_manifest: null,
      residual: null,
    };
  }

  const reservationFiles = walked.files.filter(
    (relative) => relative.endsWith(ATOMIC_RESERVATION_SUFFIX),
  );
  const publicationFiles = walked.files.filter(
    (relative) => relative.endsWith(ATOMIC_PUBLICATION_SUFFIX),
  );
  assertControl(
    reservationFiles.length <= 1 && publicationFiles.length <= 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic transaction 含 multiple reservation/publication staging',
  );
  const ordinaryFiles = walked.files.filter(
    (relative) => !relative.endsWith(ATOMIC_RESERVATION_SUFFIX)
      && !relative.endsWith(ATOMIC_PUBLICATION_SUFFIX),
  );
  const cleanupManifestFiles = ordinaryFiles.filter(
    (relative) => ATOMIC_CLEANUP_MANIFEST_PATTERN.test(relative),
  );
  assertControl(
    cleanupManifestFiles.length <= 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic transaction 含 multiple cleanup manifests',
  );
  const cleanupManifest = cleanupManifestFiles.length === 1
    ? inspectAtomicCleanupManifestStaging(
      transactionDirectory,
      cleanupManifestFiles[0],
      budget,
    )
    : null;
  const lineageAndPayloadFiles = ordinaryFiles.filter(
    (relative) => !cleanupManifestFiles.includes(relative),
  );
  const mkdirFiles = lineageAndPayloadFiles.filter((relative) => {
    const parts = relative.split(path.sep);
    return [
      ATOMIC_RESIDUAL_MKDIR,
      ATOMIC_MKDIR_LINEAGE,
    ].includes(parts[0])
      && ATOMIC_MKDIR_CLAIM_PATTERN.test(parts[parts.length - 1]);
  });
  const publicationLineageFiles = lineageAndPayloadFiles.filter((relative) => {
    const parts = relative.split(path.sep);
    return parts[0] === ATOMIC_PUBLICATION_LINEAGE
      && relative.endsWith(ATOMIC_PUBLICATION_LINEAGE_SUFFIX);
  });
  assertControl(
    mkdirFiles.length <= MAX_ATOMIC_MKDIR_LINEAGE_CLAIMS,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic transaction mkdir lineage claims 超出上限',
  );
  assertControl(
    publicationLineageFiles.length
      <= MAX_ATOMIC_PUBLICATION_LINEAGE_CLAIMS,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic transaction publication lineage claims 超出上限',
  );
  const mkdirClaims = mkdirFiles.map((relative) => (
    inspectAtomicMkdirClaim(
      root,
      transactionHex,
      transactionDirectory,
      relative,
      budget,
    )
  ));
  const activeMkdirClaims = mkdirClaims.filter(
    (claim) => claim.lineage !== true,
  );
  const publicationLineageClaims = publicationLineageFiles.map(
    (relative) => inspectAtomicPublicationLineage(
      root,
      transactionDirectory,
      relative,
      budget,
    ),
  );
  assertControl(
    activeMkdirClaims.length <= 1
      && mkdirClaims
        .filter((claim) => claim.lineage === true)
        .every((claim) => claim.complete),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic transaction 含多个 active 或无效 historical mkdir claims',
  );
  const lineageMissingRelativeDirectories = [
    ...new Set(mkdirClaims.flatMap(
      (claim) => claim.missing_relative_directories,
    )),
  ].sort();

  if (reservationFiles.length === 0) {
    assertControl(
      publicationLineageClaims.every(
        (claim) => claim.canonical_is_payload
          ? claim.stat.nlink === 2
          : (
            claim.stat.nlink === 1
              || (
                claim.stat.nlink === 2
                  && claim.relocated_canonical_links.length === 1
              )
          ),
      ),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'historical publication lineage link-count/canonical identity 非法',
    );
    assertControl(
      publicationFiles.length === 0
        && ordinaryFiles.length
          === mkdirFiles.length
            + publicationLineageFiles.length
            + cleanupManifestFiles.length,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic WRITE/CREATE payload 缺 durable sealed reservation',
    );
    const pendingMkdir = activeMkdirClaims[0] || null;
    assertControl(
      cleanupManifest === null
        || (
          pendingMkdir === null
            && publicationLineageClaims.length > 0
        ),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic cleanup manifest 只允许 lineage-only transaction',
    );
    return {
      transport,
      transactionHex,
      transactionDirectory,
      directories: walked.directories,
      mkdir_lineage_claims: mkdirClaims,
      publication_lineage_claims: publicationLineageClaims,
      lineage_missing_relative_directories:
        lineageMissingRelativeDirectories,
      cleanup_manifest: cleanupManifest,
      residual: pendingMkdir,
    };
  }

  const reservationRelative = reservationFiles[0];
  const expectedPayloadRelative = reservationRelative.slice(
    0,
    -ATOMIC_RESERVATION_SUFFIX.length,
  );
  const parts = expectedPayloadRelative.split(path.sep);
  const match = parts.length >= 3
    ? ATOMIC_PAYLOAD_PATTERN.exec(parts[parts.length - 1])
    : null;
  assertControl(
    match
      && [ATOMIC_RESIDUAL_WRITE, ATOMIC_RESIDUAL_CREATE].includes(parts[0])
      && match[1] === parts[0],
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic reservation path 非法: ${reservationRelative}`,
  );
  const operation = match[1];
  const targetRelative = parts.slice(1, -1).join(path.sep);
  assertControl(
    targetRelative
      && targetRelative !== '..'
      && !targetRelative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(targetRelative),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic reservation mirrored target 非法: ${targetRelative}`,
  );
  const payloadFiles = lineageAndPayloadFiles.filter(
    (relative) => !mkdirFiles.includes(relative)
      && !publicationLineageFiles.includes(relative),
  );
  const matchingPublicationLineages = publicationLineageClaims.filter(
    (claim) => (
      claim.operation === operation
        && claim.target_relative === targetRelative
        && claim.payload_sha256 === `sha256:${match[2]}`
        && claim.preimage_sha256 === `sha256:${match[3]}`
        && claim.missing_relative_directories.length === Number(match[4])
        && claim.stable_time_milliseconds
          === (match[5] ? Number(match[5]) : null)
    ),
  );
  assertControl(
    publicationLineageClaims
      .filter((claim) => !matchingPublicationLineages.includes(claim))
      .every(
        (claim) => claim.canonical_is_payload
          ? claim.stat.nlink === 2
          : (
            claim.stat.nlink === 1
              || (
                claim.stat.nlink === 2
                  && claim.relocated_canonical_links.length === 1
              )
          ),
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'non-active publication lineage link-count/canonical identity 非法',
  );
  assertControl(
    activeMkdirClaims.every((claim) => (
      claim.complete && fs.existsSync(claim.target)
    ))
      && payloadFiles.length <= 1
      && cleanupManifest === null
      && matchingPublicationLineages.length <= 1
      && (
        payloadFiles.length === 0
          || payloadFiles[0] === expectedPayloadRelative
      )
      && (
        publicationFiles.length === 0
          || (
            payloadFiles.length === 1
              && publicationFiles[0]
                === `${expectedPayloadRelative}${ATOMIC_PUBLICATION_SUFFIX}`
          )
      )
      && lineageAndPayloadFiles.length
        === mkdirFiles.length
          + publicationLineageFiles.length
          + payloadFiles.length,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic reservation/payload/publication chain 非 exact single operation',
  );

  const canonical = path.join(root, targetRelative);
  const missingDirectoryCount = Number(match[4]);
  const targetParentRelative = path.dirname(targetRelative);
  const parentComponents = targetParentRelative === '.'
    ? []
    : targetParentRelative.split(path.sep);
  assertControl(
    Number.isSafeInteger(missingDirectoryCount)
      && missingDirectoryCount >= 0
      && missingDirectoryCount <= parentComponents.length,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic reservation missing-directory count 非法: ${targetRelative}`,
  );
  const targetSuffixMissingRelativeDirectories = parentComponents
    .map((_component, index) => path.join(...parentComponents.slice(0, index + 1)))
    .slice(parentComponents.length - missingDirectoryCount);
  const payloadSha256 = `sha256:${match[2]}`;
  const preimageSha256 = `sha256:${match[3]}`;
  const stableTime = match[5] ? Number(match[5]) : null;
  const reservationFile = path.join(
    transactionDirectory,
    reservationRelative,
  );
  const reservationStat = assertPrivateOwnedAtomicFile(
    reservationFile,
    `atomic operation reservation ${reservationRelative}`,
  );
  assertControl(
    reservationStat.nlink === 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic operation reservation 必须 single-link: ${targetRelative}`,
  );
  const rawReservation = readAtomicInspectionFile(
    reservationFile,
    reservationStat,
    budget,
    `atomic operation reservation ${reservationRelative}`,
  );
  const targetParent = path.dirname(canonical);
  const targetMkdirCandidates = mkdirClaims.filter(
    (claim) => (
      claim.missing_relative_directories.length
          === missingDirectoryCount
        && (
          claim.target === targetParent
            || targetParent.startsWith(`${claim.target}${path.sep}`)
        )
    ),
  ).sort((left, right) => (
    right.target_relative.length - left.target_relative.length
  ));
  const targetMkdirClaims = targetMkdirCandidates.length === 0
    ? []
    : targetMkdirCandidates.filter(
      (claim) => claim.target_relative.length
        === targetMkdirCandidates[0].target_relative.length,
    );
  assertControl(
    activeMkdirClaims.length
        <= (missingDirectoryCount === 0 ? 0 : 1)
      && targetMkdirClaims.length <= 1
      && (
        missingDirectoryCount === 0
          || (
            targetMkdirClaims.length === 1
              && (
                activeMkdirClaims.length === 0
                  || activeMkdirClaims[0] === targetMkdirClaims[0]
              )
          )
    ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic reservation 缺 exact operation-local mkdir claim: target=${
      targetRelative
    } missing=${missingDirectoryCount} active=${
      activeMkdirClaims.map((claim) => claim.target_relative).join(',')
    } candidates=${
      mkdirClaims.map((claim) => (
        `${claim.target_relative}:${claim.missing_relative_directories.length}:${
          claim.lineage ? 'lineage' : 'active'
        }`
      )).join(',')
    }`,
  );
  const mkdirClaim = missingDirectoryCount === 0
    ? null
    : targetMkdirClaims[0];
  let parsedReservation;
  try {
    parsedReservation = JSON.parse(rawReservation.toString('utf8'));
  } catch {
    const missingRelativeDirectories = mkdirClaim
      ? mkdirClaim.missing_relative_directories
      : targetSuffixMissingRelativeDirectories;
    if (mkdirClaim) {
      const targetParent = path.dirname(canonical);
      assertControl(
        mkdirClaim.complete
          && (
            targetParent === mkdirClaim.target
              || targetParent.startsWith(
                `${mkdirClaim.target}${path.sep}`,
              )
          ),
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        'partial atomic reservation 的 mkdir lineage 与 target 不匹配',
      );
    }
    assertControl(
      payloadFiles.length === 0
        && publicationFiles.length === 0
        && matchingPublicationLineages.length === 0,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      '未 seal atomic reservation 不得携带 payload/publication',
    );
    const current = inspectAtomicCanonical(canonical, budget);
    assertControl(
      current.descriptor_sha256 === preimageSha256,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `partial atomic reservation canonical/preimage 漂移: ${targetRelative}`,
    );
    return {
      transport,
      transactionHex,
      transactionDirectory,
      directories: walked.directories,
      mkdir_lineage_claims: mkdirClaims,
      publication_lineage_claims: publicationLineageClaims,
      lineage_missing_relative_directories:
        lineageMissingRelativeDirectories,
      cleanup_manifest: null,
      residual: {
        operation,
        payload_sha256: payloadSha256,
        preimage_sha256: preimageSha256,
        stable_time_milliseconds: stableTime,
        missing_relative_directories: missingRelativeDirectories,
        pristine_missing_relative_directories:
          lineageMissingRelativeDirectories,
        promoted_mkdir_claim: mkdirClaim
          ? mkdirClaim.claim_record
          : null,
        mkdir_claim_file: mkdirClaim ? mkdirClaim.file : null,
        target: canonical,
        target_relative: targetRelative,
        reservation_file: reservationFile,
        reservation_stat: reservationStat,
        reservation_body: null,
        reservation_prefix: rawReservation,
        reservation_complete: false,
        file: null,
        stat: null,
        payload_file: null,
        payload_stat: null,
        publication_lineage_file: null,
        publication_lineage: null,
        publication_file: null,
        publication_stat: null,
        canonical: current,
        canonical_is_payload: false,
      },
    };
  }
  const missingRelativeDirectories = Array.isArray(
    parsedReservation.missing_relative_directories,
  )
    ? parsedReservation.missing_relative_directories.map(
      (relative) => String(relative).split('/').join(path.sep),
    )
    : [];
  assertControl(
    missingRelativeDirectories.length === missingDirectoryCount
      && missingRelativeDirectories.every(
        (relative, index) => (
          relative
            && relative !== '..'
            && !relative.startsWith(`..${path.sep}`)
            && !path.isAbsolute(relative)
            && path.normalize(relative) === relative
            && missingRelativeDirectories.indexOf(relative) === index
        ),
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic reservation current mkdir lineage 非法: ${targetRelative}`,
  );
  const pristineMissingRelativeDirectories = Array.isArray(
    parsedReservation.pristine_missing_relative_directories,
  )
    ? parsedReservation.pristine_missing_relative_directories.map(
      (relative) => String(relative).split('/').join(path.sep),
    )
    : [];
  const normalizedPristineMissing = [
    ...new Set(pristineMissingRelativeDirectories),
  ].sort();
  const invalidPristineMissing = normalizedPristineMissing.filter(
    (relative) => {
      if (
        !relative
          || relative === '..'
          || relative.startsWith(`..${path.sep}`)
          || path.isAbsolute(relative)
          || path.normalize(relative) !== relative
      ) {
        return true;
      }
      try {
        const stat = fs.lstatSync(path.join(root, relative));
        return !stat.isDirectory()
          || stat.isSymbolicLink()
          || stat.uid !== process.getuid()
          || (stat.mode & 0o777) !== 0o700;
      } catch (error) {
        // A transaction may atomically publish into a temporary directory and
        // then rename that directory as part of the same durable operation.
        // The sealed lineage still proves that the original path was absent
        // at the pre-write boundary; its later absence is therefore valid.
        return error.code !== 'ENOENT';
      }
    },
  );
  assertControl(
    canonicalJson(pristineMissingRelativeDirectories)
        === canonicalJson(normalizedPristineMissing)
      && canonicalJson(normalizedPristineMissing)
        === canonicalJson(lineageMissingRelativeDirectories)
      && invalidPristineMissing.length === 0,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic reservation pristine mkdir lineage 非法: ${targetRelative}; invalid=${
      invalidPristineMissing.join(',')
    }; current=${missingRelativeDirectories.join(',')}; sealed=${
      pristineMissingRelativeDirectories.join(',')
    }`,
  );
  const reservation = sealedAtomicOperationReservation(
    transactionHex,
    operation,
    targetRelative,
    payloadSha256,
    preimageSha256,
    missingRelativeDirectories,
    normalizedPristineMissing,
    stableTime,
  );
  const reservationBody = atomicOperationReservationBody(reservation);
  validateAtomicOperationReservation(
    transactionHex,
    operation,
    targetRelative,
    payloadSha256,
    preimageSha256,
    missingRelativeDirectories,
    normalizedPristineMissing,
    stableTime,
    parsedReservation,
  );

  if (mkdirClaim) {
    const targetParent = path.dirname(canonical);
    assertControl(
      mkdirClaim.complete
        && (
          targetParent === mkdirClaim.target
            || targetParent.startsWith(`${mkdirClaim.target}${path.sep}`)
        )
        && canonicalJson(mkdirClaim.missing_relative_directories)
          === canonicalJson(missingRelativeDirectories),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic operation reservation 的 mkdir lineage 不匹配',
    );
  } else {
    assertControl(
      canonicalJson(missingRelativeDirectories)
        === canonicalJson(targetSuffixMissingRelativeDirectories),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic operation reservation 缺 MKDIR claim 且 current lineage 非 target suffix',
    );
  }

  const payloadFile = payloadFiles.length === 1
    ? path.join(transactionDirectory, payloadFiles[0])
    : null;
  const payloadStat = payloadFile === null
    ? null
    : assertPrivateOwnedPublicationMarker(
      payloadFile,
      `atomic payload ${targetRelative}`,
    );
  const publicationLineage = matchingPublicationLineages[0] || null;
  const file = payloadFile || (
    publicationLineage ? publicationLineage.file : null
  );
  const stat = payloadStat || (
    publicationLineage ? publicationLineage.stat : null
  );
  const publicationFile = publicationFiles.length === 1
    ? path.join(transactionDirectory, publicationFiles[0])
    : null;
  const publicationStat = publicationFile === null
    ? null
    : assertPrivateOwnedAtomicFile(
      publicationFile,
      `atomic publication ${targetRelative}`,
    );
  assertControl(
    publicationStat === null
      || (
        operation === ATOMIC_RESIDUAL_WRITE
          && publicationLineage === null
          && sameFileIdentity(payloadStat, publicationStat)
          && payloadStat.nlink === 2
          && publicationStat.nlink === 2
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic publication hardlink/inode/link-count 非法: ${targetRelative}`,
  );
  const current = inspectAtomicCanonical(canonical, budget);
  const canonicalIsPayload = stat !== null
    && current.kind === 'FILE'
    && sameFileIdentity(stat, current.stat);
  assertControl(
    publicationLineage === null
      || (
        publicationStat === null
          && canonicalIsPayload
          && publicationLineage.canonical_is_payload
          && (
            payloadStat === null
              ? stat.nlink === 2
              : (
                sameFileIdentity(payloadStat, publicationLineage.stat)
                  && payloadStat.nlink === 3
                  && publicationLineage.stat.nlink === 3
              )
          )
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic publication lineage active chain 非 exact same inode: ${targetRelative}`,
  );
  const missingPreimageSha256 = hashObject({
    schema_version: ATOMIC_TRANSPORT_SCHEMA_VERSION,
    kind: 'MISSING',
  });
  assertControl(
    canonicalIsPayload
      ? (
        operation === ATOMIC_RESIDUAL_WRITE
          || preimageSha256 === missingPreimageSha256
      )
      : current.descriptor_sha256 === preimageSha256,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic canonical/preimage binding 漂移: ${targetRelative}`,
  );
  assertControl(
    stat === null
      || (
        publicationLineage !== null
          ? canonicalIsPayload
          : canonicalIsPayload
            ? stat.nlink === 2 && publicationStat === null
          : stat.nlink === (publicationStat === null ? 1 : 2)
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic payload link-count 非法: ${targetRelative}`,
  );
  if (publicationStat !== null) {
    const payload = readAtomicInspectionFile(
      payloadFile,
      payloadStat,
      budget,
      `atomic publication payload ${targetRelative}`,
    );
    assertControl(
      `sha256:${sha256(payload)}` === payloadSha256,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic publication payload bytes/hash 非法: ${targetRelative}`,
    );
  }
  return {
    transport,
    transactionHex,
    transactionDirectory,
    directories: walked.directories,
    mkdir_lineage_claims: mkdirClaims,
    publication_lineage_claims: publicationLineageClaims,
    lineage_missing_relative_directories:
      lineageMissingRelativeDirectories,
    cleanup_manifest: null,
    residual: {
      operation,
      payload_sha256: payloadSha256,
      preimage_sha256: preimageSha256,
      stable_time_milliseconds: stableTime,
      missing_relative_directories: missingRelativeDirectories,
      pristine_missing_relative_directories: normalizedPristineMissing,
      promoted_mkdir_claim: mkdirClaim
        ? mkdirClaim.claim_record
        : null,
      mkdir_claim_file: mkdirClaim ? mkdirClaim.file : null,
      target: canonical,
      target_relative: targetRelative,
      reservation_file: reservationFile,
      reservation_stat: reservationStat,
      reservation_body: reservationBody,
      reservation_complete: true,
      file,
      stat,
      payload_file: payloadFile,
      payload_stat: payloadStat,
      publication_lineage_file:
        publicationLineage ? publicationLineage.file : null,
      publication_lineage:
        publicationLineage,
      publication_file: publicationFile,
      publication_stat: publicationStat,
      canonical: current,
      canonical_is_payload: canonicalIsPayload,
    },
  };
}

function atomicExpectedDirectories(operation, targetRelative) {
  const parts = [operation, ...targetRelative.split(path.sep)];
  const expected = [];
  for (let index = 1; index <= parts.length; index += 1) {
    expected.push(path.join(...parts.slice(0, index)));
  }
  return expected;
}

function atomicPublicationLineageDirectories(claim) {
  const parts = [
    ATOMIC_PUBLICATION_LINEAGE,
    claim.operation,
    ...claim.target_relative.split(path.sep),
  ];
  return parts.map(
    (_part, index) => path.join(...parts.slice(0, index + 1)),
  );
}

function assertAtomicDirectoryShape(inspection, operation, targetRelative) {
  const expected = new Set(atomicExpectedDirectories(operation, targetRelative));
  assertControl(
    inspection.transactionDirectory !== null
      && inspection.residual === null
      && inspection.directories.length === expected.size
      && inspection.directories.every((relative) => expected.has(relative)),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic transaction empty/mirrored directory 与 exact target 不匹配',
  );
}

function atomicDirectoryShapeMatches(
  inspection,
  operation,
  targetRelative,
) {
  const expected = new Set(
    atomicExpectedDirectories(operation, targetRelative),
  );
  return inspection.transactionDirectory !== null
    && inspection.residual === null
    && inspection.directories.length === expected.size
    && inspection.directories.every((relative) => expected.has(relative));
}

function cleanupExactEmptyAtomicTransport(
  inspection,
  operation,
  targetRelative,
) {
  assertControl(
    atomicDirectoryShapeMatches(inspection, operation, targetRelative),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic empty transport 不是 exact target mirror',
  );
  for (const relative of [...inspection.directories]
    .sort((left, right) => right.length - left.length)) {
    const directory = path.join(inspection.transactionDirectory, relative);
    try {
      fs.rmdirSync(directory);
      fsyncDirectory(path.dirname(directory));
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic empty transport cleanup 发现 foreign directory: ${relative}`,
      );
    }
  }
  fs.rmdirSync(inspection.transactionDirectory);
  fsyncDirectory(inspection.transport);
}

function assertAtomicPayloadDirectoryShape(
  inspection,
  operation,
  targetRelative,
) {
  const payloadDirectories = new Set(
    atomicExpectedDirectories(operation, targetRelative),
  );
  const mkdirDirectories = inspection.directories.filter(
    (relative) => relative === ATOMIC_RESIDUAL_MKDIR
      || relative.startsWith(`${ATOMIC_RESIDUAL_MKDIR}${path.sep}`)
      || relative === ATOMIC_MKDIR_LINEAGE
  );
  const expectedMkdir = new Set(
    (inspection.mkdir_lineage_claims || []).flatMap(
      (claim) => (
        claim.lineage === true
          ? [ATOMIC_MKDIR_LINEAGE]
          : atomicExpectedDirectories(
            ATOMIC_RESIDUAL_MKDIR,
            claim.target_relative,
          )
      ),
    ),
  );
  if (mkdirDirectories.includes(ATOMIC_MKDIR_LINEAGE)) {
    expectedMkdir.add(ATOMIC_MKDIR_LINEAGE);
  }
  const publicationDirectories = inspection.directories.filter(
    (relative) => relative === ATOMIC_PUBLICATION_LINEAGE
      || relative.startsWith(
        `${ATOMIC_PUBLICATION_LINEAGE}${path.sep}`,
      ),
  );
  const expectedPublication = new Set(
    (inspection.publication_lineage_claims || []).flatMap(
      atomicPublicationLineageDirectories,
    ),
  );
  assertControl(
    mkdirDirectories.every((relative) => expectedMkdir.has(relative))
      && [...expectedMkdir].every(
        (relative) => mkdirDirectories.includes(relative),
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic payload 携带的 mkdir lineage directories 与 sealed claims 不匹配',
  );
  assertControl(
    publicationDirectories.every(
      (relative) => expectedPublication.has(relative),
    )
      && [...expectedPublication].every(
        (relative) => publicationDirectories.includes(relative),
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic payload 携带的 publication lineage directories 与 markers 不匹配',
  );
  assertControl(
    inspection.directories.every(
      (relative) => payloadDirectories.has(relative)
        || mkdirDirectories.includes(relative)
        || publicationDirectories.includes(relative),
    ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic payload transport 含 foreign/lookalike directory',
  );
  return [...mkdirDirectories, ...publicationDirectories];
}

function promoteActiveAtomicMkdirClaim(root, inspection) {
  const activeClaims = (inspection.mkdir_lineage_claims || [])
    .filter((claim) => claim.lineage !== true);
  if (activeClaims.length === 0) return inspection;
  assertControl(
    activeClaims.length === 1
      && activeClaims[0].complete
      && fs.existsSync(activeClaims[0].target),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic mkdir lineage promotion 只接受单个已安装 claim',
  );
  const active = activeClaims[0];
  const lineageDirectory = path.join(
    inspection.transactionDirectory,
    ATOMIC_MKDIR_LINEAGE,
  );
  ensurePrivateOwnedDirectory(
    lineageDirectory,
    'atomic mkdir lineage directory',
  );
  const destination = path.join(
    lineageDirectory,
    path.basename(active.file),
  );
  assertControl(
    !fs.existsSync(destination),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic mkdir lineage destination 已存在',
  );
  fs.renameSync(active.file, destination);
  fsyncDirectory(path.dirname(active.file));
  fsyncDirectory(lineageDirectory);
  return inspectAtomicTransport(
    root,
    inspection.transactionHex,
  );
}

function promotePublishedAtomicPayload(root, inspection) {
  let residual = inspection.residual;
  assertControl(
    residual
      && [ATOMIC_RESIDUAL_WRITE, ATOMIC_RESIDUAL_CREATE]
        .includes(residual.operation)
      && residual.reservation_complete
      && residual.canonical_is_payload
      && residual.publication_file === null,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic publication lineage promotion 缺 exact published residual',
  );
  const payloadName = residual.payload_file
    ? path.basename(residual.payload_file)
    : residual.publication_lineage
      ? residual.publication_lineage.payload_name
      : null;
  assertControl(
    payloadName && ATOMIC_PAYLOAD_PATTERN.test(payloadName),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic publication lineage promotion 缺 payload binding',
  );
  const lineageDirectory = path.join(
    inspection.transactionDirectory,
    ATOMIC_PUBLICATION_LINEAGE,
    residual.operation,
    ...residual.target_relative.split(path.sep),
  );
  let current = inspection.transactionDirectory;
  for (const component of [
    ATOMIC_PUBLICATION_LINEAGE,
    residual.operation,
    ...residual.target_relative.split(path.sep),
  ]) {
    current = path.join(current, component);
    ensurePrivateOwnedDirectory(
      current,
      `atomic publication lineage mirror ${component}`,
    );
  }
  const marker = path.join(
    lineageDirectory,
    `${payloadName}${ATOMIC_PUBLICATION_LINEAGE_SUFFIX}`,
  );
  const existingMarker = residual.publication_lineage_file;
  assertControl(
    existingMarker === null || existingMarker === marker,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic publication lineage destination 含非 exact marker',
  );
  if (existingMarker === null) {
    const isCleanEvenCompletion = atomicPayloadCompletesRootTransaction(
      root,
      residual.target,
      residual.canonical.bytes,
    );
    const markerLimit = isCleanEvenCompletion
      ? MAX_ATOMIC_PUBLICATION_LINEAGE_CLAIMS
      : MAX_ATOMIC_PUBLICATION_LINEAGE_CLAIMS - 1;
    assertControl(
      inspection.publication_lineage_claims.length
        < markerLimit,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic publication lineage claims 已达上限或未给 generation completion 预留槽位',
    );
    assertControl(
      residual.payload_file !== null,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic publication lineage marker 缺 source payload',
    );
    try {
      fs.linkSync(residual.payload_file, marker);
    } catch (error) {
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic publication lineage no-clobber link 失败: ${error.message}`,
      );
    }
    fsyncDirectory(lineageDirectory);
    maybeInjectAtomicFault(
      marker,
      'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_PUBLISH_LINEAGE',
      'atomic cleanup publication lineage',
    );
    inspection = inspectAtomicTransport(
      root,
      inspection.transactionHex,
    );
    residual = inspection.residual;
  }
  assertControl(
    residual
      && residual.publication_lineage_file === marker
      && residual.canonical_is_payload
      && (
        residual.payload_file === null
          || sameFileIdentity(
            residual.payload_stat,
            residual.publication_lineage.stat,
          )
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic publication lineage marker 未绑定 exact canonical payload',
  );
  if (residual.payload_file !== null) {
    fs.unlinkSync(residual.payload_file);
    fsyncDirectory(path.dirname(residual.payload_file));
    maybeInjectAtomicFault(
      marker,
      'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_PAYLOAD_UNLINK',
      'atomic cleanup active payload unlink',
    );
    inspection = inspectAtomicTransport(
      root,
      inspection.transactionHex,
    );
    residual = inspection.residual;
  }
  assertControl(
    residual
      && residual.payload_file === null
      && residual.publication_lineage_file === marker
      && residual.canonical_is_payload
      && residual.stat.nlink === 2,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic publication lineage promotion 未收敛到 canonical+marker',
  );
  return inspection;
}

function atomicPayloadCompletesRootTransaction(root, target, body) {
  if (path.resolve(target) !== rootGenerationFile(root)) return false;
  let value;
  try {
    value = JSON.parse(Buffer.from(body).toString('utf8'));
  } catch {
    return false;
  }
  return value
    && Number.isSafeInteger(value.generation)
    && value.generation % 2 === 0
    && value.active_transaction === null
    && value.pre_write_vector_sha256 === null;
}

function removeExactUnpublishedAtomicResidual(root, inspection) {
  const residual = inspection.residual;
  assertControl(
    residual
      && (
        residual.operation === ATOMIC_RESIDUAL_MKDIR
          || (
            [
              ATOMIC_RESIDUAL_WRITE,
              ATOMIC_RESIDUAL_CREATE,
            ].includes(residual.operation)
              && residual.reservation_complete
              && residual.file === null
              && residual.publication_file === null
              && !residual.canonical_is_payload
          )
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic unpublished cleanup 缺 exact residual',
  );
  const files = residual.operation === ATOMIC_RESIDUAL_MKDIR
    ? [residual.file]
    : [
      residual.reservation_file,
      residual.mkdir_claim_file,
    ].filter((file) => file !== null);
  for (const file of files) {
    const stat = assertPrivateOwnedAtomicFile(
      file,
      'atomic unpublished cleanup file',
    );
    assertControl(
      stat.nlink === 1,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic unpublished cleanup file 必须 single-link',
    );
  }
  const lineageDirectories = atomicLineageDirectorySet(inspection);
  const activeDirectories = new Set(
    atomicExpectedDirectories(
      residual.operation,
      residual.target_relative,
    ),
  );
  if (
    residual.operation !== ATOMIC_RESIDUAL_MKDIR
      && residual.promoted_mkdir_claim
  ) {
    for (const relative of atomicExpectedDirectories(
      ATOMIC_RESIDUAL_MKDIR,
      residual.promoted_mkdir_claim.target_relative,
    )) {
      activeDirectories.add(relative);
    }
  }
  assertControl(
    inspection.directories.every(
      (relative) => lineageDirectories.has(relative)
        || activeDirectories.has(relative),
    ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic unpublished cleanup 含 foreign directory',
  );
  for (const file of files) {
    fs.unlinkSync(file);
    fsyncDirectory(path.dirname(file));
  }
  for (const relative of [...inspection.directories]
    .filter((relative) => activeDirectories.has(relative))
    .sort((left, right) => right.length - left.length)) {
    const directory = path.join(inspection.transactionDirectory, relative);
    try {
      fs.rmdirSync(directory);
      fsyncDirectory(path.dirname(directory));
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic unpublished cleanup 发现 foreign/non-empty directory: ${relative}`,
      );
    }
  }
  const retained = inspectAtomicTransport(root, inspection.transactionHex);
  assertControl(
    retained.residual === null
      && retained.mkdir_lineage_claims.every(
        (claim) => claim.lineage === true && claim.complete,
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic unpublished cleanup 未收敛到 historical lineage',
  );
  if (
    retained.mkdir_lineage_claims.length === 0
      && retained.publication_lineage_claims.length === 0
  ) {
    assertControl(
      retained.directories.length === 0,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic unpublished cleanup 留下 foreign empty directory',
    );
    fs.rmdirSync(retained.transactionDirectory);
    fsyncDirectory(retained.transport);
  } else {
    assertAtomicLineageOnlyDirectoryShape(retained);
  }
}

function isExactEmptyOwnedDirectory(directory) {
  try {
    const stat = fs.lstatSync(directory);
    return stat.isDirectory()
      && !stat.isSymbolicLink()
      && stat.uid === process.getuid()
      && (stat.mode & 0o777) === 0o700
      && fs.readdirSync(directory).length === 0;
  } catch {
    return false;
  }
}

function cleanupExactUnpublishedCallbackTransport(root, transactionKey) {
  const transactionHex = atomicTransactionHex(transactionKey);
  const inspection = inspectAtomicTransport(root, transactionHex);
  if (inspection.transactionDirectory === null) return true;
  const residual = inspection.residual;
  if (!residual) return false;
  if (residual.operation === ATOMIC_RESIDUAL_MKDIR) {
    if (
      !residual.complete
        || !isExactEmptyOwnedDirectory(residual.target)
    ) {
      return false;
    }
    removeExactUnpublishedAtomicResidual(root, inspection);
    return true;
  }
  if (
    ![ATOMIC_RESIDUAL_WRITE, ATOMIC_RESIDUAL_CREATE]
      .includes(residual.operation)
      || !residual.reservation_complete
      || residual.file !== null
      || residual.publication_file !== null
      || residual.canonical_is_payload
  ) {
    return false;
  }
  if (residual.missing_relative_directories.length > 0) {
    if (
      !residual.mkdir_claim_file
        || !residual.promoted_mkdir_claim
        || !isExactEmptyOwnedDirectory(path.join(
          root,
          residual.promoted_mkdir_claim.target_relative,
        ))
    ) {
      return false;
    }
  } else if (residual.mkdir_claim_file !== null) {
    return false;
  }
  assertAtomicPayloadDirectoryShape(
    inspection,
    residual.operation,
    residual.target_relative,
  );
  removeExactUnpublishedAtomicResidual(root, inspection);
  return true;
}

function cleanupExactPublishedAtomicResidual(inspection) {
  assertControl(
    inspection.residual
      && inspection.residual.canonical_is_payload,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic published cleanup 缺 exact same-inode residual',
  );
  let residual = inspection.residual;
  const retainedStat = assertPrivateOwnedPublicationMarker(
    residual.file,
    'atomic published cleanup payload',
  );
  const canonical = inspectAtomicCanonical(residual.target);
  assertControl(
    canonical.kind === 'FILE'
      && sameFileIdentity(retainedStat, canonical.stat)
      && (
        (
          residual.payload_file !== null
            && residual.publication_lineage_file !== null
            && retainedStat.nlink === 3
        )
          || (
            [
              residual.payload_file,
              residual.publication_lineage_file,
            ].filter((file) => file !== null).length === 1
              && retainedStat.nlink === 2
          )
      )
      && `sha256:${sha256(canonical.bytes)}`
        === residual.payload_sha256,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic published cleanup canonical/payload bytes/inode/link 不匹配',
  );
  const root = path.dirname(inspection.transport);
  const completesTransaction = atomicPayloadCompletesRootTransaction(
    root,
    residual.target,
    canonical.bytes,
  );
  inspection = promoteActiveAtomicMkdirClaim(root, inspection);
  residual = inspection.residual;
  assertControl(
    residual && residual.canonical_is_payload,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic mkdir lineage promotion 后 published residual 丢失',
  );
  inspection = promotePublishedAtomicPayload(root, inspection);
  residual = inspection.residual;
  const completionMarker = residual.publication_lineage_file;
  fs.unlinkSync(residual.reservation_file);
  fsyncDirectory(path.dirname(residual.reservation_file));
  maybeInjectAtomicFault(
    completionMarker,
    'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_RESERVATION_UNLINK',
    'atomic cleanup reservation unlink',
  );
  inspection = inspectAtomicTransport(root, inspection.transactionHex);
  assertControl(
    inspection.residual === null
      && inspection.publication_lineage_claims.some(
        (claim) => claim.file === completionMarker,
      )
      && inspection.mkdir_lineage_claims.every(
        (claim) => claim.lineage === true && claim.complete,
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic published cleanup reservation 后未收敛到 lineage-only transport',
  );
  const activeDirectories = new Set(
    atomicExpectedDirectories(
      residual.operation,
      residual.target_relative,
    ),
  );
  for (const claim of inspection.mkdir_lineage_claims) {
    for (const relative of atomicExpectedDirectories(
      ATOMIC_RESIDUAL_MKDIR,
      claim.target_relative,
    )) {
      activeDirectories.add(relative);
    }
  }
  for (const relative of [...inspection.directories]
    .filter((relative) => activeDirectories.has(relative))
    .sort((left, right) => right.length - left.length)) {
    const directory = path.join(inspection.transactionDirectory, relative);
    try {
      fs.rmdirSync(directory);
      fsyncDirectory(path.dirname(directory));
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic published cleanup 发现 foreign/non-empty active directory: ${relative}`,
      );
    }
  }
  maybeInjectAtomicFault(
    completionMarker,
    'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_ACTIVE_DIRECTORIES',
    'atomic cleanup active directories',
  );
  inspection = inspectAtomicTransport(root, inspection.transactionHex);
  if (!completesTransaction) {
    assertControl(
      inspection.residual === null
        && inspection.publication_lineage_claims.some(
          (claim) => claim.file === completionMarker,
        )
        && inspection.directories.every(
          (relative) => (
            relative === ATOMIC_MKDIR_LINEAGE
              || relative.startsWith(
                `${ATOMIC_MKDIR_LINEAGE}${path.sep}`,
              )
              || relative === ATOMIC_PUBLICATION_LINEAGE
              || relative.startsWith(
                `${ATOMIC_PUBLICATION_LINEAGE}${path.sep}`,
              )
          )
        ),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic published cleanup 未只保留 sealed lineage',
    );
    return;
  }
  finalizeCompletedEvenAtomicTransport(
    root,
    inspection,
    completionMarker,
  );
}

function atomicLineageDirectorySet(inspection) {
  const expected = new Set();
  if (inspection.mkdir_lineage_claims.some(
    (claim) => claim.lineage === true,
  )) {
    expected.add(ATOMIC_MKDIR_LINEAGE);
  }
  for (const claim of inspection.publication_lineage_claims) {
    for (const relative of atomicPublicationLineageDirectories(claim)) {
      expected.add(relative);
    }
  }
  return expected;
}

function atomicDurableDirectorySet(inspection) {
  const expected = atomicLineageDirectorySet(inspection);
  for (const claim of inspection.mkdir_lineage_claims) {
    if (claim.lineage === true) continue;
    for (const relative of atomicExpectedDirectories(
      ATOMIC_RESIDUAL_MKDIR,
      claim.target_relative,
    )) {
      expected.add(relative);
    }
  }
  return expected;
}

function assertAtomicPendingOperationDirectoryShape(
  inspection,
  operation,
  targetRelative,
) {
  const durable = atomicDurableDirectorySet(inspection);
  const pending = atomicExpectedDirectories(operation, targetRelative);
  assertControl(
    inspection.transactionDirectory !== null
      && inspection.cleanup_manifest === null
      && [...durable].every(
        (relative) => inspection.directories.includes(relative),
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic pending mirror 缺 durable lineage directory',
  );
  const extras = inspection.directories.filter(
    (relative) => !durable.has(relative),
  );
  assertControl(
    extras.length <= pending.length
      && extras.every((relative, index) => relative === pending[index]),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic pending mirror 不是 exact ${operation}/${targetRelative} prefix`,
  );
}

function assertAtomicLineageOnlyDirectoryShape(inspection) {
  const expected = atomicLineageDirectorySet(inspection);
  assertControl(
    inspection.transactionDirectory !== null
      && inspection.residual === null
      && inspection.mkdir_lineage_claims.every(
        (claim) => claim.lineage === true && claim.complete,
      )
      && inspection.directories.length === expected.size
      && inspection.directories.every(
        (relative) => expected.has(relative),
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic lineage cleanup 只接受 exact sealed lineage directory shape',
  );
}

function exactAtomicLineageOnlyDirectoryShape(inspection) {
  const expected = atomicLineageDirectorySet(inspection);
  return inspection.transactionDirectory !== null
    && inspection.residual === null
    && inspection.mkdir_lineage_claims.every(
      (claim) => claim.lineage === true && claim.complete,
    )
    && inspection.directories.length === expected.size
    && inspection.directories.every((relative) => expected.has(relative));
}

function restoreExactPublishedAtomicLineage(
  root,
  target,
  body,
  operation,
  options = {},
) {
  const inspection = inspectAtomicTransport(
    root,
    atomicTransactionHex(activeAtomicTransaction.transaction_key),
  );
  if (
    inspection.transactionDirectory === null
      || inspection.residual !== null
      || inspection.cleanup_manifest
      || !exactAtomicLineageOnlyDirectoryShape(inspection)
  ) {
    return false;
  }
  const canonical = inspectAtomicCanonical(target);
  if (canonical.kind !== 'MISSING') return false;
  const requestedStableTime = options.stable_time_milliseconds ?? null;
  const payloadSha256 = `sha256:${sha256(body)}`;
  const candidates = inspection.publication_lineage_claims.filter(
    (claim) => (
      claim.operation === operation
        && claim.target === target
        && claim.payload_sha256 === payloadSha256
        && claim.preimage_sha256 === canonical.descriptor_sha256
        && claim.stable_time_milliseconds === requestedStableTime
        && claim.bytes.equals(body)
        && !claim.canonical_is_payload
        && claim.relocated_canonical_links.length === 0
        && claim.stat.nlink === 1
    ),
  );
  assertControl(
    candidates.length <= 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic historical publication lineage 对 ${target} 不唯一`,
  );
  if (candidates.length === 0) return false;
  try {
    fs.linkSync(candidates[0].file, target);
  } catch (error) {
    throw new ControlError(
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic historical publication lineage no-clobber restore 失败: ${error.message}`,
    );
  }
  fsyncDirectory(path.dirname(target));
  const restored = inspectAtomicCanonical(target);
  const marker = assertPrivateOwnedPublicationMarker(
    candidates[0].file,
    'restored atomic historical publication lineage',
  );
  assertControl(
    restored.kind === 'FILE'
      && restored.bytes.equals(body)
      && sameFileIdentity(restored.stat, marker)
      && marker.nlink === 2,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic historical publication lineage restore 后 inode/bytes/link 不匹配',
  );
  return true;
}

function normalizeAtomicLineageActiveDirectoryTails(
  root,
  inspection,
  options = {},
) {
  if (
    inspection.transactionDirectory === null
      || inspection.residual !== null
      || inspection.publication_lineage_claims.length === 0
  ) {
    return inspection;
  }
  const lineageDirectories = atomicLineageDirectorySet(inspection);
  const allowedActiveDirectories = new Set();
  for (const claim of inspection.publication_lineage_claims) {
    for (const relative of atomicExpectedDirectories(
      claim.operation,
      claim.target_relative,
    )) {
      allowedActiveDirectories.add(relative);
    }
  }
  for (const claim of inspection.mkdir_lineage_claims) {
    for (const relative of atomicExpectedDirectories(
      ATOMIC_RESIDUAL_MKDIR,
      claim.target_relative,
    )) {
      allowedActiveDirectories.add(relative);
    }
  }
  if (options.preserveUnboundPendingMirror !== true) {
    assertControl(
      inspection.directories.every(
        (relative) => lineageDirectories.has(relative)
          || allowedActiveDirectories.has(relative),
      ),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic cleanup tail 含无法绑定 publication/mkdir lineage 的 directory',
    );
  }
  for (const relative of [...inspection.directories]
    .filter((relative) => (
      !lineageDirectories.has(relative)
        && allowedActiveDirectories.has(relative)
    ))
    .sort((left, right) => right.length - left.length)) {
    const directory = path.join(inspection.transactionDirectory, relative);
    try {
      fs.rmdirSync(directory);
      fsyncDirectory(path.dirname(directory));
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      if (
        options.preserveUnboundPendingMirror === true
          && ['ENOTEMPTY', 'EEXIST'].includes(error.code)
      ) {
        continue;
      }
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic cleanup tail 发现 foreign/non-empty directory: ${relative}`,
      );
    }
  }
  return inspectAtomicTransport(root, inspection.transactionHex);
}

function atomicCleanupBinding(kind, root, transactionHex, extra = {}) {
  const generation = readRootGenerationRecord(root);
  return {
    schema_version: 1,
    kind,
    transaction_key_sha256: `sha256:${transactionHex}`,
    generation: generation.generation,
    generation_record_sha256: hashObject(generation),
    ...extra,
  };
}

function atomicCleanupManifestEntry(
  root,
  transactionDirectory,
  relative,
  expectedClaim,
  publication,
) {
  const file = path.join(transactionDirectory, relative);
  const stat = assertPrivateOwnedPublicationMarker(
    file,
    `atomic cleanup manifest source ${relative}`,
  );
  assertControl(
    expectedClaim
      && sameAtomicFileBinding(expectedClaim.stat, stat)
      && stat.size <= MAX_ATOMIC_INSPECTION_ARTIFACT_BYTES,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `atomic cleanup manifest source ${relative} 与 final inspection descriptor 漂移`,
  );
  const payloadSha256 = inspectAtomicFileDigest(
    file,
    stat,
    `atomic cleanup manifest source ${relative}`,
    MAX_ATOMIC_INSPECTION_ARTIFACT_BYTES,
  );
  let publicationOperation = null;
  let publicationTargetRelative = null;
  let counterpartRelativePath = null;
  if (publication) {
    const publicationClaim = expectedClaim;
    const parsed = parseAtomicPublicationLineage(root, relative);
    assertControl(
      Buffer.isBuffer(publicationClaim.bytes)
        && publicationClaim.bytes.length === stat.size
        && `sha256:${sha256(publicationClaim.bytes)}` === payloadSha256
        && parsed.operation === publicationClaim.operation
        && parsed.target_relative === publicationClaim.target_relative
        && parsed.payload_sha256 === payloadSha256,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic cleanup publication descriptor 漂移: ${relative}`,
    );
    publicationOperation = parsed.operation;
    publicationTargetRelative = parsed.target_relative;
    if (publicationClaim.stat.nlink === 2) {
      const counterpart = publicationClaim.canonical_is_payload
        ? publicationClaim.target
        : (
          publicationClaim.relocated_canonical_links.length === 1
            ? publicationClaim.relocated_canonical_links[0]
            : null
        );
      assertControl(
        counterpart !== null,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic cleanup publication 缺 exact counterpart: ${relative}`,
      );
      const normalized = path.relative(root, counterpart);
      assertControl(
        normalized
          && normalized !== '..'
          && !normalized.startsWith(`..${path.sep}`)
          && !path.isAbsolute(normalized)
          && normalized.split(path.sep)[0] !== ATOMIC_TRANSPORT_DIRECTORY,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic cleanup publication counterpart 越界: ${relative}`,
      );
      let counterpartStat;
      try {
        counterpartStat = fs.lstatSync(counterpart);
      } catch (error) {
        throw new ControlError(
          'STORE_ATOMIC_RESIDUAL_CONFLICT',
          `atomic cleanup publication counterpart 无法读取: ${error.message}`,
        );
      }
      assertControl(
        counterpartStat.isFile()
          && !counterpartStat.isSymbolicLink()
          && sameAtomicFileBinding(stat, counterpartStat)
          && (
            publicationClaim.canonical_is_payload
              ? (
                publicationClaim.canonical.kind === 'FILE'
                  && sameAtomicFileBinding(
                    publicationClaim.canonical.stat,
                    counterpartStat,
                  )
              )
              : (
                publicationClaim.relocated_canonical_links.length === 1
                  && publicationClaim.relocated_canonical_links[0]
                    === counterpart
              )
          ),
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic cleanup publication counterpart descriptor 漂移: ${relative}`,
      );
      assertAtomicPathBinding(
        counterpart,
        counterpartStat,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic cleanup publication counterpart ${relative}`,
      );
      counterpartRelativePath = normalized.split(path.sep).join('/');
    } else {
      assertControl(
        publicationClaim.stat.nlink === 1
          && !publicationClaim.canonical_is_payload
          && publicationClaim.relocated_canonical_links.length === 0,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic cleanup publication single-link descriptor 非法: ${relative}`,
      );
    }
  } else {
    assertControl(
      expectedClaim.lineage === true
        && expectedClaim.complete === true
        && Buffer.isBuffer(expectedClaim.body)
        && expectedClaim.body.length === stat.size
        && `sha256:${sha256(expectedClaim.body)}` === payloadSha256,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic cleanup mkdir lineage 与 final inspection bytes 漂移: ${relative}`,
    );
  }
  return {
    relative_path: relative.split(path.sep).join('/'),
    payload_sha256: payloadSha256,
    size: stat.size,
    device: String(stat.dev),
    inode: String(stat.ino),
    link_count: stat.nlink,
    mode: stat.mode & 0o777,
    uid: stat.uid,
    publication_operation: publicationOperation,
    publication_target_relative: publicationTargetRelative === null
      ? null
      : publicationTargetRelative.split(path.sep).join('/'),
    counterpart_relative_path: counterpartRelativePath,
  };
}

function encodeAtomicCleanupManifest(record) {
  const body = Buffer.from(`${canonicalJson(record)}\n`);
  assertControl(
    body.length <= MAX_ATOMIC_CLEANUP_MANIFEST_BYTES,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup manifest 超出大小上限',
  );
  return body;
}

function sealedAtomicCleanupManifest(inspection, binding) {
  assertAtomicLineageOnlyDirectoryShape(inspection);
  const root = path.dirname(inspection.transport);
  const files = [
    ...inspection.mkdir_lineage_claims.map((claim) => ({
      file: claim.file,
      claim,
      publication: false,
    })),
    ...inspection.publication_lineage_claims.map((claim) => ({
      file: claim.file,
      claim,
      publication: true,
    })),
  ].map((item) => ({
    ...item,
    relative: path.relative(inspection.transactionDirectory, item.file),
  })).sort((left, right) => left.relative.localeCompare(right.relative))
    .map((item) => (
      atomicCleanupManifestEntry(
        root,
        inspection.transactionDirectory,
        item.relative,
        item.claim,
        item.publication,
      )
    ));
  const record = {
    schema_version: 1,
    base_binding: binding,
    transaction_key_sha256: `sha256:${inspection.transactionHex}`,
    directories: [...inspection.directories]
      .sort()
      .map((relative) => relative.split(path.sep).join('/')),
    files,
  };
  const body = encodeAtomicCleanupManifest(record);
  const manifestSha256 = `sha256:${sha256(body)}`;
  return {
    record,
    body,
    manifest_sha256: manifestSha256,
    file: path.join(
      inspection.transactionDirectory,
      `.cleanup-manifest-${
        manifestSha256.slice('sha256:'.length)
      }.json`,
    ),
  };
}

function ensureAtomicCleanupManifest(inspection, binding) {
  const sealed = sealedAtomicCleanupManifest(inspection, binding);
  const existing = inspection.cleanup_manifest || null;
  assertControl(
    existing === null || existing.file === sealed.file,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup manifest 与 exact lineage snapshot 不匹配',
  );
  if (existing === null) {
    const descriptor = fs.openSync(
      sealed.file,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.closeSync(descriptor);
    fsyncDirectory(inspection.transactionDirectory);
  }
  const before = assertPrivateOwnedAtomicFile(
    sealed.file,
    'atomic cleanup manifest staging',
  );
  assertControl(
    before.nlink === 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup manifest staging 必须 single-link',
  );
  const descriptor = fs.openSync(
    sealed.file,
    fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
  );
  try {
    const prefix = readBoundedOpenDescriptor(
      sealed.file,
      descriptor,
      before,
      sealed.body.length,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic cleanup manifest prefix',
    );
    assertControl(
      prefix.length <= sealed.body.length
        && sealed.body.subarray(0, prefix.length).equals(prefix),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic cleanup manifest 不是 expected bytes 的 exact prefix',
    );
    writeAtomicRange(
      descriptor,
      sealed.body,
      prefix.length,
      sealed.body.length,
    );
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fsyncDirectory(inspection.transactionDirectory);
  const sealedStat = assertPrivateOwnedAtomicFile(
    sealed.file,
    'atomic cleanup manifest sealed bytes',
  );
  assertControl(
    readAtomicInspectionFile(
      sealed.file,
      sealedStat,
      null,
      'atomic cleanup manifest sealed bytes',
      sealed.body.length,
    ).equals(sealed.body),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup manifest seal 后 bytes 不匹配',
  );
  return {
    ...sealed,
    claim_binding: {
      ...binding,
      cleanup_manifest_sha256: sealed.manifest_sha256,
    },
  };
}

function atomicCleanupClaimName(binding) {
  return `cleanup-${binding.kind}-tx-${
    binding.transaction_key_sha256.slice('sha256:'.length)
  }-gen-${binding.generation}-manifest-${
    binding.cleanup_manifest_sha256.slice('sha256:'.length)
  }-bind-${hashObject(binding).slice('sha256:'.length)
  }`;
}

function atomicCleanupClaimAt(root) {
  const transport = atomicTransportRoot(root);
  if (!fs.existsSync(transport)) return null;
  assertPrivateOwnedDirectory(transport, 'atomic transport root');
  const entries = boundedAtomicDirectoryEntries(
    transport,
    2,
    'atomic cleanup transport root',
  );
  const claims = entries.map((entry) => ({
    entry,
    match: ATOMIC_CLEANUP_CLAIM_PATTERN.exec(entry),
  })).filter(({ match }) => match !== null);
  if (claims.length === 0) return null;
  assertControl(
    claims.length === 1 && entries.length === 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup claim 与 active/foreign transport 并存',
  );
  const [{ entry, match }] = claims;
  return {
    transport,
    directory: path.join(transport, entry),
    entry,
    kind: match[1],
    transaction_hex: match[2],
    generation: Number(match[3]),
    manifest_sha256: `sha256:${match[4]}`,
    binding_sha256: `sha256:${match[5]}`,
  };
}

function inspectClaimedAtomicTransport(
  root,
  claim,
  binding,
  options = {},
) {
  const budget = options.inspectionBudget || createAtomicInspectionBudget(
    MAX_ATOMIC_INSPECTION_ARTIFACT_BYTES,
    MAX_ATOMIC_INSPECTION_TOTAL_BYTES,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
  );
  const claimBinding = claim
    ? {
      ...binding,
      cleanup_manifest_sha256: claim.manifest_sha256,
    }
    : null;
  assertControl(
    claim
      && claim.kind === binding.kind
      && claim.transaction_hex
        === binding.transaction_key_sha256.slice('sha256:'.length)
      && claim.generation === binding.generation
      && claim.binding_sha256 === hashObject(claimBinding)
      && claim.entry === atomicCleanupClaimName(claimBinding),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup claim name/binding 不匹配',
  );
  assertPrivateOwnedDirectory(
    claim.directory,
    'atomic claimed cleanup directory',
  );
  const walked = { directories: [], files: [] };
  walkAtomicTransport(claim.directory, '', walked);
  assertControl(
    walked.files.length
      <= MAX_ATOMIC_MKDIR_LINEAGE_CLAIMS
        + MAX_ATOMIC_PUBLICATION_LINEAGE_CLAIMS
        + 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup claim file 数量超出上限',
  );
  if (walked.files.length === 0) {
    assertControl(
      walked.directories.length === 0,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic cleanup terminal claim 缺 manifest 但仍含 directories',
    );
    return {
      terminal: true,
      claim,
      claim_binding: claimBinding,
      walked,
      manifest_relative: null,
      manifest_file: null,
      manifest_stat: null,
      manifest_bytes: null,
      manifest: null,
      manifest_files: new Map(),
      current_data_files: [],
      current_files: new Map(),
    };
  }
  const manifestRelative = `.cleanup-manifest-${
    claim.manifest_sha256.slice('sha256:'.length)
  }.json`;
  assertControl(
    walked.files.includes(manifestRelative),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup claim 缺 exact sealed manifest',
  );
  const manifestFile = path.join(claim.directory, manifestRelative);
  const manifestStat = assertPrivateOwnedAtomicFile(
    manifestFile,
    'atomic claimed cleanup manifest',
  );
  assertControl(
    manifestStat.nlink === 1
      && manifestStat.size <= MAX_ATOMIC_CLEANUP_MANIFEST_BYTES,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup manifest 必须是 bounded single-link file',
  );
  const manifestBytes = readAtomicInspectionFile(
    manifestFile,
    manifestStat,
    budget,
    'atomic claimed cleanup manifest',
    MAX_ATOMIC_CLEANUP_MANIFEST_BYTES,
  );
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic cleanup manifest 无法解析: ${error.message}`,
    );
  }
  assertControl(
    manifestBytes.length <= MAX_ATOMIC_CLEANUP_MANIFEST_BYTES
      && `sha256:${sha256(manifestBytes)}` === claim.manifest_sha256
      && `${canonicalJson(manifest)}\n` === manifestBytes.toString('utf8')
      && manifest
      && manifest.schema_version === 1
      && Object.keys(manifest).length === 5
      && Object.keys(manifest).every((key) => [
        'schema_version',
        'base_binding',
        'transaction_key_sha256',
        'directories',
        'files',
      ].includes(key))
      && canonicalJson(manifest.base_binding) === canonicalJson(binding)
      && manifest.transaction_key_sha256
        === binding.transaction_key_sha256
      && Array.isArray(manifest.directories)
      && manifest.directories.length <= MAX_ATOMIC_TRANSPORT_DIRECTORIES
      && Array.isArray(manifest.files)
      && manifest.files.length
        <= MAX_ATOMIC_MKDIR_LINEAGE_CLAIMS
          + MAX_ATOMIC_PUBLICATION_LINEAGE_CLAIMS,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup manifest hash/schema/binding 非法',
  );
  const normalizedManifestDirectories = manifest.directories.map(
    (value) => String(value).split('/').join(path.sep),
  );
  const manifestDirectories = new Set(normalizedManifestDirectories);
  assertControl(
    manifestDirectories.size === manifest.directories.length
      && normalizedManifestDirectories.every(
        (relative) => (
          relative
            && relative !== '.'
            && relative !== '..'
            && !relative.startsWith(`..${path.sep}`)
            && !path.isAbsolute(relative)
            && path.normalize(relative) === relative
        ),
      )
      && walked.directories.every(
        (relative) => manifestDirectories.has(relative),
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup claim 含 manifest 外 directory',
  );
  const manifestFiles = new Map();
  const publicationDescriptors = new Map();
  for (const entry of manifest.files) {
    const relative = String(entry.relative_path || '')
      .split('/').join(path.sep);
    const publication = relative.split(path.sep)[0]
      === ATOMIC_PUBLICATION_LINEAGE;
    const publicationTargetRelative =
      entry.publication_target_relative === null
        ? null
        : String(entry.publication_target_relative || '')
          .split('/').join(path.sep);
    const counterpartRelative =
      entry.counterpart_relative_path === null
        ? null
        : String(entry.counterpart_relative_path || '')
          .split('/').join(path.sep);
    assertControl(
      relative
        && relative !== '..'
        && !relative.startsWith(`..${path.sep}`)
        && !path.isAbsolute(relative)
        && path.normalize(relative) === relative
        && !manifestFiles.has(relative)
        && Object.keys(entry).length === 11
        && Object.keys(entry).every((key) => [
          'relative_path',
          'payload_sha256',
          'size',
          'device',
          'inode',
          'link_count',
          'mode',
          'uid',
          'publication_operation',
          'publication_target_relative',
          'counterpart_relative_path',
        ].includes(key))
        && /^sha256:[0-9a-f]{64}$/.test(entry.payload_sha256)
        && Number.isSafeInteger(entry.size)
        && entry.size >= 0
        && entry.size <= MAX_ATOMIC_INSPECTION_ARTIFACT_BYTES
        && /^[0-9]+$/.test(entry.device)
        && /^[0-9]+$/.test(entry.inode)
        && Number.isSafeInteger(entry.link_count)
        && entry.link_count >= 1
        && entry.link_count <= 2
        && entry.mode === 0o600
        && entry.uid === process.getuid()
        && (
          publication
            ? (
              [ATOMIC_RESIDUAL_WRITE, ATOMIC_RESIDUAL_CREATE]
                .includes(entry.publication_operation)
                && publicationTargetRelative
                && publicationTargetRelative !== '..'
                && !publicationTargetRelative.startsWith(`..${path.sep}`)
                && !path.isAbsolute(publicationTargetRelative)
                && path.normalize(publicationTargetRelative)
                  === publicationTargetRelative
                && (
                  entry.link_count === 1
                    ? counterpartRelative === null
                    : (
                      counterpartRelative
                        && counterpartRelative !== '..'
                        && !counterpartRelative
                          .startsWith(`..${path.sep}`)
                        && !path.isAbsolute(counterpartRelative)
                        && path.normalize(counterpartRelative)
                          === counterpartRelative
                        && counterpartRelative.split(path.sep)[0]
                          !== ATOMIC_TRANSPORT_DIRECTORY
                    )
                )
            )
            : (
              entry.publication_operation === null
                && publicationTargetRelative === null
                && counterpartRelative === null
                && entry.link_count === 1
            )
        ),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic cleanup manifest file entry 非法',
    );
    if (publication) {
      const parsed = parseAtomicPublicationLineage(root, relative);
      assertControl(
        parsed.operation === entry.publication_operation
          && parsed.target_relative === publicationTargetRelative
          && parsed.payload_sha256 === entry.payload_sha256,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic cleanup manifest publication binding 非法: ${relative}`,
      );
      publicationDescriptors.set(relative, {
        parsed,
        counterpart_relative: counterpartRelative,
      });
    }
    manifestFiles.set(relative, entry);
  }
  const currentDataFiles = walked.files.filter(
    (relative) => relative !== manifestRelative,
  );
  assertControl(
    currentDataFiles.every((relative) => manifestFiles.has(relative)),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup claim 含 manifest 外 file',
  );
  const validateCurrentFile = (relative) => {
    const entry = manifestFiles.get(relative);
    const file = path.join(claim.directory, relative);
    const stat = assertPrivateOwnedPublicationMarker(
      file,
      `atomic claimed cleanup file ${relative}`,
    );
    assertControl(
      String(stat.dev) === entry.device
        && String(stat.ino) === entry.inode
        && stat.nlink === entry.link_count
        && stat.size === entry.size
        && (stat.mode & 0o777) === entry.mode
        && stat.uid === entry.uid,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic cleanup claim file 漂移: ${relative}`,
    );
    const payloadSha256 = inspectAtomicFileDigest(
      file,
      stat,
      `atomic claimed cleanup file ${relative}`,
      entry.size,
    );
    assertControl(
      payloadSha256 === entry.payload_sha256,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic cleanup claim file payload 漂移: ${relative}`,
    );
    return { file, stat, payload_sha256: payloadSha256, entry };
  };
  const currentFiles = new Map();
  for (const relative of currentDataFiles) {
    currentFiles.set(relative, validateCurrentFile(relative));
  }
  const counterpartFiles = new Map();
  for (const [relative, descriptor] of publicationDescriptors) {
    const entry = manifestFiles.get(relative);
    if (entry.link_count === 1) continue;
    const counterpartFile = path.join(
      root,
      descriptor.counterpart_relative,
    );
    const counterpartStat = assertPrivateOwnedPublicationMarker(
      counterpartFile,
      `atomic cleanup counterpart ${descriptor.counterpart_relative}`,
    );
    const markerPresent = currentFiles.has(relative);
    assertControl(
      String(counterpartStat.dev) === entry.device
        && String(counterpartStat.ino) === entry.inode
        && counterpartStat.nlink === (markerPresent ? 2 : 1)
        && counterpartStat.size === entry.size
        && (counterpartStat.mode & 0o777) === entry.mode
        && counterpartStat.uid === entry.uid
        && (
          !markerPresent
            || sameFileIdentity(
              currentFiles.get(relative).stat,
              counterpartStat,
            )
        ),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic cleanup counterpart identity/link 漂移: ${relative}`,
    );
    const payloadSha256 = inspectAtomicFileDigest(
      counterpartFile,
      counterpartStat,
      `atomic cleanup counterpart ${descriptor.counterpart_relative}`,
      entry.size,
    );
    assertControl(
      payloadSha256 === entry.payload_sha256,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `atomic cleanup counterpart payload 漂移: ${relative}`,
    );
    counterpartFiles.set(relative, {
      file: counterpartFile,
      stat: counterpartStat,
      payload_sha256: payloadSha256,
    });
  }
  return {
    terminal: false,
    claim,
    claim_binding: claimBinding,
    walked,
    manifest_relative: manifestRelative,
    manifest_file: manifestFile,
    manifest_stat: manifestStat,
    manifest_bytes: manifestBytes,
    manifest,
    manifest_files: manifestFiles,
    publication_descriptors: publicationDescriptors,
    current_data_files: currentDataFiles,
    current_files: currentFiles,
    counterpart_files: counterpartFiles,
  };
}

function removeClaimedAtomicTransport(root, claim, binding) {
  const inspection = inspectClaimedAtomicTransport(root, claim, binding);
  if (inspection.terminal) {
    fs.rmdirSync(claim.directory);
    fsyncDirectory(claim.transport);
    return;
  }
  for (const relative of inspection.current_data_files) {
    const { file } = inspection.current_files.get(relative);
    fs.unlinkSync(file);
    fsyncDirectory(path.dirname(file));
    maybeInjectAtomicFault(
      file,
      'GOAL_CONTROL_TEST_FAULT_DURING_ATOMIC_CLEANUP_LINEAGE_UNLINK',
      'atomic cleanup lineage unlink',
    );
  }
  const postUnlinkInspection = inspectClaimedAtomicTransport(
    root,
    claim,
    binding,
  );
  assertControl(
    postUnlinkInspection.current_data_files.length === 0,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup unlink 后仍有 data file',
  );
  for (const relative of [...postUnlinkInspection.walked.directories]
    .sort((left, right) => right.length - left.length)) {
    const directory = path.join(claim.directory, relative);
    fs.rmdirSync(directory);
    fsyncDirectory(path.dirname(directory));
  }
  const remaining = fs.readdirSync(claim.directory).sort();
  assertControl(
    remaining.length === 1
      && remaining[0] === inspection.manifest_relative,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup data 删除后出现 foreign entry',
  );
  const finalManifestStat = assertPrivateOwnedAtomicFile(
    postUnlinkInspection.manifest_file,
    'atomic cleanup final manifest',
  );
  assertControl(
    sameFileIdentity(postUnlinkInspection.manifest_stat, finalManifestStat)
      && finalManifestStat.nlink === 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup final manifest inode/link 漂移',
  );
  fs.unlinkSync(postUnlinkInspection.manifest_file);
  fsyncDirectory(claim.directory);
  maybeInjectAtomicFault(
    claim.directory,
    'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_MANIFEST_UNLINK',
    'atomic cleanup manifest unlink',
  );
  fs.rmdirSync(claim.directory);
  fsyncDirectory(claim.transport);
  maybeInjectAtomicFault(
    path.join(claim.transport, '.cleanup-complete'),
    'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_FINAL_DIRECTORIES',
    'atomic cleanup final directories',
  );
}

function claimAndRemoveAtomicTransport(inspection, binding) {
  assertAtomicLineageOnlyDirectoryShape(inspection);
  const sealedManifest = ensureAtomicCleanupManifest(
    inspection,
    binding,
  );
  const destination = path.join(
    inspection.transport,
    atomicCleanupClaimName(sealedManifest.claim_binding),
  );
  assertControl(
    !fs.existsSync(destination),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup claim destination 已存在',
  );
  fs.renameSync(inspection.transactionDirectory, destination);
  fsyncDirectory(inspection.transport);
  maybeInjectAtomicFault(
    destination,
    'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_CLAIM',
    'atomic cleanup claim rename',
  );
  const claim = atomicCleanupClaimAt(path.dirname(inspection.transport));
  removeClaimedAtomicTransport(
    path.dirname(inspection.transport),
    claim,
    binding,
  );
}

function cleanEvenGenerationRecord(root) {
  const generation = readRootGenerationRecord(root);
  assertControl(
    !generation.legacy
      && generation.schema_version === ROOT_GENERATION_SCHEMA_VERSION
      && generation.generation % 2 === 0
      && generation.active_transaction === null
      && generation.pre_write_vector_sha256 === null,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic completion cleanup 缺 clean even generation authority',
  );
  return generation;
}

function evenCompletionMarker(root, inspection, expectedMarker = null) {
  const generation = cleanEvenGenerationRecord(root);
  const generationBytes = readBoundedRootGenerationBytes(root);
  const candidates = inspection.publication_lineage_claims.filter(
    (claim) => (
      claim.target === rootGenerationFile(root)
        && claim.canonical_is_payload
        && claim.bytes.equals(generationBytes)
        && atomicPayloadCompletesRootTransaction(
          root,
          claim.target,
          claim.bytes,
        )
    ),
  );
  assertControl(
    candidates.length === 1
      && (
        expectedMarker === null
          || candidates[0].file === expectedMarker
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic lineage cleanup 缺 unique exact clean-even completion marker',
  );
  return { generation, marker: candidates[0] };
}

function finalizeCompletedEvenAtomicTransport(
  root,
  inspection,
  expectedMarker = null,
) {
  const { generation } = evenCompletionMarker(
    root,
    inspection,
    expectedMarker,
  );
  const binding = atomicCleanupBinding(
    'EVEN',
    root,
    inspection.transactionHex,
    { completed_generation: generation.generation },
  );
  claimAndRemoveAtomicTransport(inspection, binding);
}

function cleanupCompletedEvenAtomicClaim(root) {
  const claim = atomicCleanupClaimAt(root);
  if (claim === null || claim.kind !== 'EVEN') return false;
  const generation = cleanEvenGenerationRecord(root);
  const binding = atomicCleanupBinding(
    'EVEN',
    root,
    claim.transaction_hex,
    { completed_generation: generation.generation },
  );
  removeClaimedAtomicTransport(root, claim, binding);
  return true;
}

function cleanupCompletedEvenAtomicTransport(
  root,
  initialInspection = null,
) {
  let inspection = initialInspection || inspectAtomicTransport(root);
  if (inspection.transactionDirectory === null) return inspection;
  if (inspection.residual !== null) {
    const residual = inspection.residual;
    if (
      residual.operation === ATOMIC_RESIDUAL_WRITE
        && residual.target === rootGenerationFile(root)
        && residual.canonical_is_payload
        && atomicPayloadCompletesRootTransaction(
          root,
          residual.target,
          residual.canonical.bytes,
        )
    ) {
      cleanEvenGenerationRecord(root);
      cleanupExactPublishedAtomicResidual(inspection);
      return inspectAtomicTransport(root);
    }
    return inspection;
  }
  if (inspection.publication_lineage_claims.length === 0) {
    return inspection;
  }
  inspection = normalizeAtomicLineageActiveDirectoryTails(
    root,
    inspection,
  );
  finalizeCompletedEvenAtomicTransport(root, inspection);
  return inspectAtomicTransport(root);
}

function ensureTransactionDirectory(dir) {
  const context = activeAtomicTransaction;
  const root = path.resolve(context.root);
  const target = path.resolve(dir);
  const transactionHex = atomicTransactionHex(context.transaction_key);
  let inspection = inspectAtomicTransport(root, transactionHex);
  if (target === root) {
    if (inspection.residual) {
      assertControl(
        inspection.residual.operation !== ATOMIC_RESIDUAL_MKDIR
          && path.dirname(inspection.residual.target) === root,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        'control root ensureDir 与 current atomic residual 不匹配',
      );
    }
    const rootStat = fs.lstatSync(root);
    assertControl(
      rootStat.isDirectory()
        && !rootStat.isSymbolicLink()
        && rootStat.uid === process.getuid(),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'control root 不是当前 uid 的 non-symlink directory',
    );
    return;
  }
  const targetRelative = atomicTargetRelative(root, target);
  if (fs.existsSync(target)) {
    const stat = fs.lstatSync(target);
    assertControl(
      stat.isDirectory()
        && !stat.isSymbolicLink()
        && stat.uid === process.getuid(),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `ensureDir target 不是当前 uid 的 non-symlink directory: ${target}`,
    );
    return;
  }

  if (inspection.residual) {
    if (inspection.residual.operation === ATOMIC_RESIDUAL_MKDIR) {
      assertControl(
        inspection.residual.target === target,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `callback ensureDir 未命中 exact current-transaction mkdir claim: claimed=${
          inspection.residual.target
        } requested=${target}`,
      );
      if (!inspection.residual.complete) {
        const before = fs.lstatSync(inspection.residual.file);
        const descriptor = fs.openSync(
          inspection.residual.file,
          fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
        );
        try {
          const opened = fs.fstatSync(descriptor);
          assertControl(
            sameFileIdentity(before, opened)
              && opened.nlink === 1
              && opened.uid === process.getuid()
              && (opened.mode & 0o777) === 0o600,
            'STORE_ATOMIC_RESIDUAL_CONFLICT',
            'atomic mkdir partial claim inode/mode/uid/link 漂移',
          );
          writeAtomicRange(
            descriptor,
            inspection.residual.body,
            opened.size,
            inspection.residual.body.length,
          );
          fs.fsyncSync(descriptor);
        } finally {
          fs.closeSync(descriptor);
        }
        fsyncDirectory(path.dirname(inspection.residual.file));
        inspection = inspectAtomicTransport(root, transactionHex);
        assertControl(
          inspection.residual
            && inspection.residual.operation === ATOMIC_RESIDUAL_MKDIR
            && inspection.residual.complete,
          'STORE_ATOMIC_RESIDUAL_CONFLICT',
          'atomic mkdir partial claim repair 后仍不完整',
        );
      }
    } else {
      const expectedParent = path.dirname(inspection.residual.target);
      assertControl(
        target === expectedParent,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        'callback ensureDir 先于 matching atomic 消费了不同 target',
      );
    }
  }
  if (inspection.transactionDirectory && !inspection.residual) {
    assertAtomicPendingOperationDirectoryShape(
      inspection,
      ATOMIC_RESIDUAL_MKDIR,
      targetRelative,
    );
  }

  if (!inspection.residual) {
    const missing = missingAtomicDirectories(root, targetRelative);
    assertControl(
      missing.length > 0,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic mkdir claim 仅允许绑定当前缺失目录 suffix',
    );
    const claimRecord = sealedAtomicMkdirClaim(
      transactionHex,
      targetRelative,
      missing,
    );
    const claimBody = atomicMkdirClaimBody(claimRecord);
    const transport = atomicTransportRoot(root);
    const transactionDirectory = atomicTransactionDirectory(
      root,
      transactionHex,
    );
    ensurePrivateOwnedDirectory(transport, 'atomic transport root');
    ensurePrivateOwnedDirectory(
      transactionDirectory,
      'atomic mkdir transaction',
    );
    let mirror = transactionDirectory;
    for (const component of [
      ATOMIC_RESIDUAL_MKDIR,
      ...targetRelative.split(path.sep),
    ]) {
      mirror = path.join(mirror, component);
      ensurePrivateOwnedDirectory(mirror, `atomic mkdir mirror ${component}`);
    }
    const claim = path.join(
      mirror,
      `.mkdir-claim-${
        claimRecord.claim_sha256.slice('sha256:'.length)
      }.json`,
    );
    const descriptor = fs.openSync(
      claim,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      const midpoint = Math.max(1, Math.floor(claimBody.length / 2));
      writeAtomicRange(descriptor, claimBody, 0, midpoint);
      maybeInjectAtomicFault(
        claim,
        'GOAL_CONTROL_TEST_FAULT_DURING_ATOMIC_MKDIR_CLAIM',
        'atomic mkdir claim mid-write',
      );
      writeAtomicRange(descriptor, claimBody, midpoint, claimBody.length);
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    fsyncDirectory(mirror);
    maybeInjectAtomicFault(
      claim,
      'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_MKDIR_CLAIM',
      'atomic mkdir claim',
    );
    inspection = inspectAtomicTransport(root, transactionHex);
    assertControl(
      inspection.residual
        && inspection.residual.operation === ATOMIC_RESIDUAL_MKDIR
        && inspection.residual.complete
        && inspection.residual.target === target,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic mkdir claim publish 后 exact binding 缺失',
    );
  }

  fs.mkdirSync(target, { recursive: true, mode: 0o700 });
  const installed = fs.lstatSync(target);
  assertControl(
    installed.isDirectory()
      && !installed.isSymbolicLink()
      && installed.uid === process.getuid(),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `ensureDir target publish 后属性非法: ${target}`,
  );
  for (const relative of inspection.residual.missing_relative_directories) {
    const created = fs.lstatSync(path.join(root, relative));
    assertControl(
      created.isDirectory()
        && !created.isSymbolicLink()
        && created.uid === process.getuid()
        && (created.mode & 0o777) === 0o700,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      `ensureDir claimed directory mode/uid 漂移: ${relative}`,
    );
  }
  fsyncDirectory(path.dirname(target));
  maybeInjectAtomicFault(
    inspection.residual.file,
    'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_MKDIR_INSTALL',
    'atomic mkdir install',
  );
  maybeInjectAtomicFault(
    inspection.residual.file,
    'GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_ENSURE_DIR',
    'atomic ensureDir',
  );
}

function writeAtomicRange(fd, body, start, end) {
  let offset = start;
  while (offset < end) {
    const written = fs.writeSync(
      fd,
      body,
      offset,
      end - offset,
      offset,
    );
    assertControl(
      Number.isSafeInteger(written) && written > 0,
      'STORE_ATOMIC_WRITE_FAILED',
      'atomic payload write 没有取得进展',
    );
    offset += written;
  }
}

const atomicFaultOccurrences = new Map();

function maybeInjectAtomicFault(file, variable, label) {
  const mode = process.env[variable];
  if (!mode) return;
  const occurrenceVariable = `${variable}_OCCURRENCE`;
  const requestedOccurrence = process.env[occurrenceVariable] === undefined
    ? 1
    : Number(process.env[occurrenceVariable]);
  assertControl(
    Number.isSafeInteger(requestedOccurrence) && requestedOccurrence > 0,
    'TEST_MODE_FORBIDDEN',
    `${occurrenceVariable} 必须是正整数`,
  );
  const occurrence = (atomicFaultOccurrences.get(variable) || 0) + 1;
  atomicFaultOccurrences.set(variable, occurrence);
  if (occurrence !== requestedOccurrence) return;
  const temporaryRoot = trustedTemporaryRoot();
  const resolved = fs.realpathSync(path.dirname(file));
  assertControl(
    process.env.GOAL_CONTROL_TEST_MODE === '1'
      && resolved !== temporaryRoot
      && resolved.startsWith(`${temporaryRoot}${path.sep}`),
    'TEST_MODE_FORBIDDEN',
    `${label} fault injection 只允许隔离测试目录`,
  );
  if (mode === 'sigkill') {
    process.kill(process.pid, 'SIGKILL');
    return;
  }
  if (mode === 'exit') {
    process.exit(86);
  }
  throw new ControlError('TEST_ATOMIC_FAULT', `injected ${label} fault`);
}

function atomicFaultVariables(options, suffix) {
  const variables = [`GOAL_CONTROL_TEST_FAULT_${suffix}`];
  if (options && options.fault_namespace) {
    variables.unshift(
      `GOAL_CONTROL_TEST_FAULT_${options.fault_namespace}_${suffix}`,
    );
  }
  return variables;
}

function injectAtomicFaults(file, options, suffix, label) {
  for (const variable of atomicFaultVariables(options, suffix)) {
    maybeInjectAtomicFault(file, variable, label);
  }
}

function ensureAtomicMirror(prepared) {
  ensurePrivateOwnedDirectory(
    prepared.transport,
    'atomic transport root',
  );
  ensurePrivateOwnedDirectory(
    prepared.transactionDirectory,
    'atomic transaction directory',
  );
  let current = prepared.transactionDirectory;
  for (const component of [
    prepared.operation,
    ...prepared.targetRelative.split(path.sep),
  ]) {
    current = path.join(current, component);
    ensurePrivateOwnedDirectory(current, `atomic mirror ${component}`);
  }
}

function createOrRepairAtomicReservation(prepared, options) {
  ensureAtomicMirror(prepared);
  if (!fs.existsSync(prepared.reservation)) {
    const descriptor = fs.openSync(
      prepared.reservation,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.closeSync(descriptor);
    fsyncDirectory(path.dirname(prepared.reservation));
  }
  const before = assertPrivateOwnedAtomicFile(
    prepared.reservation,
    'atomic operation reservation',
  );
  assertControl(
    before.nlink === 1,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic operation reservation 必须 single-link',
  );
  const descriptor = fs.openSync(
    prepared.reservation,
    fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
  );
  try {
    const existing = readBoundedOpenDescriptor(
      prepared.reservation,
      descriptor,
      before,
      prepared.reservationBody.length,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic operation reservation',
    );
    assertControl(
      existing.length <= prepared.reservationBody.length
        && prepared.reservationBody.subarray(0, existing.length)
          .equals(existing),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic operation reservation 不是 expected bytes 的 exact prefix',
    );
    if (existing.length < prepared.reservationBody.length) {
      const midpoint = existing.length + Math.max(
        1,
        Math.floor(
          (prepared.reservationBody.length - existing.length) / 2,
        ),
      );
      writeAtomicRange(
        descriptor,
        prepared.reservationBody,
        existing.length,
        midpoint,
      );
      injectAtomicFaults(
        prepared.reservation,
        options,
        'DURING_ATOMIC_RESERVATION_WRITE',
        'atomic reservation mid-write',
      );
      writeAtomicRange(
        descriptor,
        prepared.reservationBody,
        midpoint,
        prepared.reservationBody.length,
      );
    }
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(prepared.reservation));
  injectAtomicFaults(
    prepared.reservation,
    options,
    'AFTER_ATOMIC_RESERVATION',
    'atomic reservation',
  );
  const inspection = inspectAtomicTransport(
    prepared.root,
    prepared.transactionHex,
  );
  assertControl(
    inspection.residual
      && inspection.residual.operation === prepared.operation
      && inspection.residual.target === prepared.file
      && inspection.residual.payload_sha256 === prepared.payloadSha256
      && inspection.residual.preimage_sha256 === prepared.preimageSha256
      && inspection.residual.reservation_file === prepared.reservation
      && inspection.residual.reservation_complete,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic operation reservation publish 后 exact binding 缺失',
  );
}

function createOrRepairAtomicPayload(prepared, options) {
  createOrRepairAtomicReservation(prepared, options);
  if (!fs.existsSync(prepared.temporary)) {
    const descriptor = fs.openSync(
      prepared.temporary,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      const stat = fs.fstatSync(descriptor);
      assertControl(
        stat.isFile()
          && stat.uid === process.getuid()
          && (stat.mode & 0o777) === 0o600
          && stat.nlink === 1,
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        'new atomic payload inode 属性非法',
      );
    } finally {
      fs.closeSync(descriptor);
    }
    fsyncDirectory(path.dirname(prepared.temporary));
    injectAtomicFaults(
      prepared.temporary,
      options,
      'AFTER_ATOMIC_TEMP_CREATE',
      'atomic temp create',
    );
  }

  const before = fs.lstatSync(prepared.temporary);
  const publicationBefore = fs.existsSync(prepared.publication)
    ? assertPrivateOwnedAtomicFile(
      prepared.publication,
      'atomic publication link',
    )
    : null;
  const canonicalBefore = inspectAtomicCanonical(prepared.file);
  const canonicalIsRetainedPayload = canonicalBefore.kind === 'FILE'
    && sameFileIdentity(before, canonicalBefore.stat);
  const descriptor = fs.openSync(
    prepared.temporary,
    fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
  );
  try {
    const opened = fs.fstatSync(descriptor);
    assertControl(
      sameFileIdentity(before, opened)
        && opened.isFile()
        && opened.uid === process.getuid()
        && (opened.mode & 0o777) === 0o600
        && (
          (
            publicationBefore === null
              && opened.nlink === 1
          )
            || (
              publicationBefore !== null
                && sameFileIdentity(before, publicationBefore)
                && sameFileIdentity(opened, publicationBefore)
                && opened.nlink === 2
            )
            || (
              publicationBefore === null
                && canonicalIsRetainedPayload
                && sameFileIdentity(opened, canonicalBefore.stat)
                && opened.nlink === 2
            )
        ),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic payload open 发生 pathname/inode/mode/uid/link 漂移',
    );
    const existing = readBoundedOpenDescriptor(
      prepared.temporary,
      descriptor,
      opened,
      prepared.body.length,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic payload prefix',
    );
    assertControl(
      existing.length <= prepared.body.length
        && prepared.body.subarray(0, existing.length).equals(existing),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic payload 不是 expected bytes 的 exact prefix',
    );
    if (existing.length < prepared.body.length) {
      const midpoint = existing.length + Math.max(
        1,
        Math.floor((prepared.body.length - existing.length) / 2),
      );
      writeAtomicRange(
        descriptor,
        prepared.body,
        existing.length,
        midpoint,
      );
      injectAtomicFaults(
        prepared.temporary,
        options,
        'DURING_ATOMIC_TEMP_WRITE',
        'atomic temp mid-write',
      );
      writeAtomicRange(
        descriptor,
        prepared.body,
        midpoint,
        prepared.body.length,
      );
    }
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  injectAtomicFaults(
    prepared.temporary,
    options,
    'AFTER_ATOMIC_TEMP_FSYNC',
    'atomic temp fsync',
  );
  const completeStat = assertPrivateOwnedAtomicFile(
    prepared.temporary,
    'complete atomic payload bytes',
  );
  const complete = readAtomicInspectionFile(
    prepared.temporary,
    completeStat,
    null,
    'complete atomic payload bytes',
    prepared.body.length,
  );
  assertControl(
    complete.equals(prepared.body)
      && `sha256:${sha256(complete)}` === prepared.payloadSha256,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic payload complete bytes/hash 不匹配',
  );
  return assertPrivateOwnedAtomicFile(
    prepared.temporary,
    'complete atomic payload',
  );
}

function removeAtomicTransactionTree(prepared) {
  const inspection = inspectAtomicTransport(
    prepared.root,
    prepared.transactionHex,
  );
  assertControl(
    inspection.residual
      && inspection.residual.operation === prepared.operation
      && inspection.residual.target === prepared.file
      && inspection.residual.payload_sha256 === prepared.payloadSha256
      && inspection.residual.preimage_sha256 === prepared.preimageSha256
      && inspection.residual.reservation_file === prepared.reservation
      && inspection.residual.reservation_complete
      && inspection.residual.canonical_is_payload,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic cleanup 前 residual/canonical 不是 exact promoted inode',
  );
  cleanupExactPublishedAtomicResidual(inspection);
}

function prepareTransactionAtomic(file, body, operation, options = {}) {
  const context = activeAtomicTransaction;
  assertControl(
    context
      && context.root
      && context.transaction_key,
    'STORE_ATOMIC_TRANSACTION_REQUIRED',
    'transaction-bound atomic write 缺 active store transaction',
  );
  const root = path.resolve(context.root);
  const target = path.resolve(file);
  const transactionHex = atomicTransactionHex(context.transaction_key);
  const targetRelative = atomicTargetRelative(root, target);
  const payloadSha256 = `sha256:${sha256(body)}`;
  let inspection = inspectAtomicTransport(root, transactionHex);
  let mkdirClaim = null;
  if (
    inspection.residual
      && inspection.residual.operation === ATOMIC_RESIDUAL_MKDIR
  ) {
    const expectedParent = path.dirname(target);
    const claimedDirectory = inspection.residual.target;
    assertControl(
      expectedParent === claimedDirectory
        || expectedParent.startsWith(`${claimedDirectory}${path.sep}`),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic write target 不在 exact mkdir claim 下',
    );
    mkdirClaim = inspection.residual;
  }
  if (
    inspection.transactionDirectory
      && (inspection.residual === null || mkdirClaim !== null)
  ) {
    assertAtomicPendingOperationDirectoryShape(
      inspection,
      operation,
      targetRelative,
    );
  }
  let preimage = inspectAtomicCanonical(target);
  let preimageSha256 = preimage.descriptor_sha256;
  const requestedStableTime =
    options.stable_time_milliseconds ?? null;
  let stableTime = requestedStableTime;
  let missingRelativeDirectories = mkdirClaim
    ? mkdirClaim.missing_relative_directories
    : [];
  // v2 reconstructs cumulative pristine lineage exclusively from retained,
  // sealed MKDIR claims; no process-local context affects durable bytes.
  let pristineMissingRelativeDirectories = [
    ...(inspection.lineage_missing_relative_directories || []),
    ...missingRelativeDirectories,
  ];
  let carriedMkdirDirectories = [];
  if (inspection.residual && !mkdirClaim) {
    assertControl(
      inspection.residual.operation === operation
        && inspection.residual.target === target
        && inspection.residual.payload_sha256 === payloadSha256,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'callback 第一笔 atomic write 未消费 exact current-transaction residual',
    );
    preimageSha256 = inspection.residual.preimage_sha256;
    assertControl(
      inspection.residual.stable_time_milliseconds
        === requestedStableTime,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic residual stable timestamp 与 exact retry request 不匹配',
    );
    stableTime = inspection.residual.stable_time_milliseconds;
    missingRelativeDirectories =
      inspection.residual.missing_relative_directories;
    pristineMissingRelativeDirectories =
      inspection.residual.pristine_missing_relative_directories;
    carriedMkdirDirectories = assertAtomicPayloadDirectoryShape(
      inspection,
      operation,
      targetRelative,
    );
    preimage = inspection.residual.canonical_is_payload
      ? {
        kind: 'MISSING',
        descriptor_sha256: preimageSha256,
      }
      : inspection.residual.canonical;
  }
  pristineMissingRelativeDirectories = [
    ...new Set(pristineMissingRelativeDirectories),
  ].sort();
  if (stableTime !== null) {
    assertControl(
      Number.isSafeInteger(stableTime)
        && stableTime >= 0
        && String(stableTime).length === 13,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic stable timestamp 非法',
    );
  }
  const transactionDirectory = atomicTransactionDirectory(root, transactionHex);
  const mirror = atomicMirrorDirectory(
    transactionDirectory,
    operation,
    targetRelative,
  );
  const temporary = path.join(
    mirror,
    atomicPayloadName(
      operation,
      payloadSha256,
      preimageSha256,
      missingRelativeDirectories.length,
      stableTime,
    ),
  );
  const publication = `${temporary}${ATOMIC_PUBLICATION_SUFFIX}`;
  const reservation = `${temporary}${ATOMIC_RESERVATION_SUFFIX}`;
  const reservationRecord = sealedAtomicOperationReservation(
    transactionHex,
    operation,
    targetRelative,
    payloadSha256,
    preimageSha256,
    missingRelativeDirectories,
    pristineMissingRelativeDirectories,
    stableTime,
  );
  const reservationBody = atomicOperationReservationBody(reservationRecord);
  if (inspection.residual && !mkdirClaim) {
    const expectedPublicationMarker = path.join(
      transactionDirectory,
      ATOMIC_PUBLICATION_LINEAGE,
      operation,
      ...targetRelative.split(path.sep),
      `${path.basename(temporary)}${ATOMIC_PUBLICATION_LINEAGE_SUFFIX}`,
    );
    assertControl(
      inspection.residual.reservation_file === reservation
        && (
          inspection.residual.payload_file === null
            || inspection.residual.payload_file === temporary
        )
        && (
          inspection.residual.publication_lineage_file === null
            || inspection.residual.publication_lineage_file
              === expectedPublicationMarker
        )
        && (
          inspection.residual.file === null
            || [
              temporary,
              expectedPublicationMarker,
            ].includes(inspection.residual.file)
        ),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic residual exact path/binding 不匹配',
    );
  }
  return {
    root,
    file: target,
    body,
    operation,
    payloadSha256,
    preimage,
    preimageSha256,
    transport: atomicTransportRoot(root),
    transactionHex,
    transactionDirectory,
    targetRelative,
    temporary,
    publication,
    reservation,
    reservationBody,
    stableTime,
    missingRelativeDirectories,
    pristineMissingRelativeDirectories,
    mkdirClaim,
    mkdirInspection: mkdirClaim ? inspection : null,
    promotedMkdirClaim: inspection.residual
      ? inspection.residual.promoted_mkdir_claim
      : null,
    carriedMkdirDirectories,
  };
}

function publishTransactionAtomic(prepared, options = {}) {
  const existing = inspectAtomicCanonical(prepared.file);
  const entryInspection = inspectAtomicTransport(
    prepared.root,
    prepared.transactionHex,
  );
  if (
    entryInspection.residual
      && entryInspection.residual.canonical_is_payload
  ) {
    assertControl(
      entryInspection.residual.operation === prepared.operation
        && entryInspection.residual.target === prepared.file
        && entryInspection.residual.payload_sha256
          === prepared.payloadSha256
        && entryInspection.residual.preimage_sha256
          === prepared.preimageSha256
        && entryInspection.residual.stable_time_milliseconds
          === prepared.stableTime
        && existing.kind === 'FILE'
        && existing.bytes.equals(prepared.body),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic published retry 未命中 exact operation/payload binding',
    );
    cleanupExactPublishedAtomicResidual(entryInspection);
    return { created: true, idempotent: true };
  }
  if (
    existing.kind === 'FILE'
      && existing.bytes.equals(prepared.body)
      && !fs.existsSync(prepared.temporary)
  ) {
    const inspection = inspectAtomicTransport(
      prepared.root,
      prepared.transactionHex,
    );
    if (inspection.residual === null) {
      return { created: false, idempotent: true };
    }
  }
  if (
    prepared.operation === ATOMIC_RESIDUAL_CREATE
      && existing.kind === 'FILE'
      && !fs.existsSync(prepared.temporary)
  ) {
    const inspection = inspectAtomicTransport(
      prepared.root,
      prepared.transactionHex,
    );
    assertControl(
      inspection.residual === null,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic create canonical 已存在但 transaction staging 未闭合',
    );
    return { created: false, idempotent: true };
  }

  const temporaryStat = createOrRepairAtomicPayload(prepared, options);
  ensureDirRaw(path.dirname(prepared.file));
  injectAtomicFaults(
    prepared.temporary,
    options,
    'AFTER_ATOMIC_ENSURE_DIR',
    'atomic target ensureDir',
  );

  const current = inspectAtomicCanonical(prepared.file);
  if (current.kind === 'FILE' && sameFileIdentity(current.stat, temporaryStat)) {
    assertControl(
      current.bytes.equals(prepared.body),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic canonical 与 payload 同 inode 但 bytes 不匹配',
    );
  } else if (prepared.operation === ATOMIC_RESIDUAL_CREATE) {
    assertControl(
      current.kind === 'MISSING',
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic create no-clobber publication 遇到 foreign canonical',
    );
    try {
      fs.linkSync(prepared.temporary, prepared.file);
    } catch (error) {
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic create no-clobber link 失败: ${error.message}`,
      );
    }
  } else if (prepared.preimage.kind === 'MISSING') {
    assertControl(
      current.kind === 'MISSING',
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic write missing-target publication 遇到 foreign canonical',
    );
    try {
      fs.linkSync(prepared.temporary, prepared.file);
    } catch (error) {
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `atomic write no-clobber link 失败: ${error.message}`,
      );
    }
  } else {
    assertControl(
      current.kind === 'FILE'
        && current.descriptor_sha256 === prepared.preimageSha256,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic replace canonical preimage/path/inode/mode/uid/hash 漂移',
    );
    if (!fs.existsSync(prepared.publication)) {
      fs.linkSync(prepared.temporary, prepared.publication);
      fsyncDirectory(path.dirname(prepared.publication));
      injectAtomicFaults(
        prepared.publication,
        options,
        'AFTER_ATOMIC_PUBLICATION_LINK',
        'atomic publication retained hardlink',
      );
    }
    const retained = assertPrivateOwnedAtomicFile(
      prepared.temporary,
      'atomic retained payload before replace',
    );
    const publication = assertPrivateOwnedAtomicFile(
      prepared.publication,
      'atomic publication before replace',
    );
    assertControl(
      sameFileIdentity(retained, publication)
        && retained.nlink === 2
        && publication.nlink === 2,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic replace publication/retained payload 不是 exact same inode',
    );
    fs.renameSync(prepared.publication, prepared.file);
  }
  fsyncDirectory(path.dirname(prepared.file));
  injectAtomicFaults(
    prepared.file,
    options,
    'AFTER_ATOMIC_PUBLISH',
    'atomic publish',
  );
  const installed = inspectAtomicCanonical(prepared.file);
  assertControl(
    installed.kind === 'FILE'
      && installed.bytes.equals(prepared.body)
      && sameFileIdentity(installed.stat, temporaryStat),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'atomic publish 后 canonical bytes/inode 不匹配',
  );
  removeAtomicTransactionTree(prepared);
  return { created: true, idempotent: false };
}

function legacyAtomicWrite(file, body, createOnly) {
  ensureDir(path.dirname(file));
  const binding = hashObject({
    schema_version: ATOMIC_TRANSPORT_SCHEMA_VERSION,
    operation: createOnly ? ATOMIC_RESIDUAL_CREATE : ATOMIC_RESIDUAL_WRITE,
    target_sha256: `sha256:${sha256(path.resolve(file))}`,
    payload_sha256: `sha256:${sha256(body)}`,
  }).slice('sha256:'.length);
  const temporary = path.join(
    path.dirname(file),
    `.${path.basename(file)}.atomic-${binding}.tmp`,
  );
  const candidates = fs.readdirSync(path.dirname(file))
    .filter((name) => name.startsWith(`.${path.basename(file)}.atomic-`));
  assertControl(
    candidates.length <= 1
      && candidates.every((name) => name === path.basename(temporary)),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    `standalone atomic ${file} 含 foreign/lookalike/multiple staging`,
  );
  if (createOnly && fs.existsSync(file) && !fs.existsSync(temporary)) {
    return false;
  }
  if (!fs.existsSync(temporary)) {
    const fd = fs.openSync(
      temporary,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.closeSync(fd);
    fsyncDirectory(path.dirname(file));
  }
  const stat = assertPrivateOwnedAtomicFile(temporary, 'standalone atomic temp');
  const fd = fs.openSync(
    temporary,
    fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
  );
  try {
    const prefix = readBoundedOpenDescriptor(
      temporary,
      fd,
      stat,
      body.length,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'standalone atomic temp',
    );
    assertControl(
      prefix.length <= body.length
        && body.subarray(0, prefix.length).equals(prefix),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'standalone atomic temp 不是 expected prefix',
    );
    writeAtomicRange(fd, body, prefix.length, body.length);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  if (createOnly) {
    try {
      fs.linkSync(temporary, file);
    } catch (error) {
      if (error.code === 'EEXIST') {
        const temporaryStat = assertPrivateOwnedAtomicFile(
          temporary,
          'standalone atomic create temp',
        );
        const canonical = inspectAtomicCanonical(file);
        assertControl(
          canonical.kind === 'FILE'
            && canonical.bytes.equals(body)
            && sameFileIdentity(temporaryStat, canonical.stat)
            && temporaryStat.nlink === 2,
          'STORE_ATOMIC_RESIDUAL_CONFLICT',
          'standalone atomic create EEXIST 不是 exact same-inode publication',
        );
        fs.unlinkSync(temporary);
        fsyncDirectory(path.dirname(file));
        return true;
      }
      throw error;
    }
    fs.unlinkSync(temporary);
  } else {
    fs.renameSync(temporary, file);
  }
  fsyncDirectory(path.dirname(file));
  return true;
}

function isCompletedAtomicPrefix(
  file,
  body,
  operation = null,
  options = {},
) {
  if (!activeAtomicTransaction) return false;
  const root = path.resolve(activeAtomicTransaction.root);
  const target = path.resolve(file);
  const inspection = inspectAtomicTransport(
    root,
    atomicTransactionHex(activeAtomicTransaction.transaction_key),
  );
  const canonical = inspectAtomicCanonical(target);
  if (canonical.kind !== 'FILE' || !canonical.bytes.equals(body)) {
    return false;
  }
  if (inspection.residual) {
    return inspection.residual.target !== target;
  }
  const requestedStableTime = options.stable_time_milliseconds ?? null;
  return inspection.publication_lineage_claims.some((claim) => (
    claim.target === target
      && claim.canonical_is_payload
      && claim.payload_sha256 === `sha256:${sha256(body)}`
      && (operation === null || claim.operation === operation)
      && claim.stable_time_milliseconds === requestedStableTime
      && claim.bytes.equals(body)
  ));
}

function atomicTransportHasNonGenerationState(root, inspection) {
  if (inspection.transactionDirectory === null) return false;
  if (
    inspection.cleanup_manifest !== null
      || inspection.mkdir_lineage_claims.length > 0
      || inspection.publication_lineage_claims.some(
        (claim) => claim.target !== rootGenerationFile(root),
      )
  ) {
    return true;
  }
  const allowed = new Set();
  for (const claim of inspection.publication_lineage_claims) {
    for (const relative of atomicPublicationLineageDirectories(claim)) {
      allowed.add(relative);
    }
  }
  if (inspection.residual !== null) {
    if (
      inspection.residual.operation === ATOMIC_RESIDUAL_MKDIR
        || inspection.residual.target !== rootGenerationFile(root)
    ) {
      return true;
    }
    for (const relative of atomicExpectedDirectories(
      inspection.residual.operation,
      inspection.residual.target_relative,
    )) {
      allowed.add(relative);
    }
  }
  return inspection.directories.some((relative) => !allowed.has(relative));
}

function completedEvenCleanupBinding(claim, generation) {
  assertControl(
    claim.kind === 'EVEN'
      && !generation.legacy
      && generation.schema_version === ROOT_GENERATION_SCHEMA_VERSION
      && generation.generation % 2 === 0
      && generation.active_transaction === null
      && generation.pre_write_vector_sha256 === null,
    'STORE_ATOMIC_ARTIFACT_INVALID',
    'private atomic artifact cleanup claim 缺 clean-even authority',
  );
  return {
    schema_version: 1,
    kind: 'EVEN',
    transaction_key_sha256: `sha256:${claim.transaction_hex}`,
    generation: generation.generation,
    generation_record_sha256: hashObject(generation),
    completed_generation: generation.generation,
  };
}

function cleanupClaimStateSha256(inspection) {
  return hashObject({
    claim: {
      entry: inspection.claim.entry,
      kind: inspection.claim.kind,
      transaction_hex: inspection.claim.transaction_hex,
      generation: inspection.claim.generation,
      manifest_sha256: inspection.claim.manifest_sha256,
      binding_sha256: inspection.claim.binding_sha256,
    },
    terminal: inspection.terminal,
    manifest_sha256: inspection.terminal
      ? null
      : `sha256:${sha256(inspection.manifest_bytes)}`,
    directories: inspection.walked.directories,
    current_files: inspection.current_data_files.map((relative) => {
      const current = inspection.current_files.get(relative);
      return {
        relative,
        device: String(current.stat.dev),
        inode: String(current.stat.ino),
        link_count: current.stat.nlink,
        size: current.stat.size,
        payload_sha256: current.payload_sha256,
      };
    }),
    counterparts: inspection.terminal
      ? []
      : [...inspection.counterpart_files.entries()]
        .map(([relative, counterpart]) => ({
          relative,
          file: path.relative(
            path.dirname(inspection.claim.transport),
            counterpart.file,
          ).split(path.sep).join('/'),
          device: String(counterpart.stat.dev),
          inode: String(counterpart.stat.ino),
          link_count: counterpart.stat.nlink,
          size: counterpart.stat.size,
          payload_sha256: counterpart.payload_sha256,
        }))
        .sort((left, right) => left.relative.localeCompare(right.relative)),
  });
}

function assertCleanupManifestCanonicalBinding(
  label,
  entry,
  current,
  canonical,
) {
  assertControl(
    entry.link_count === 2
      && entry.mode === 0o600
      && entry.uid === process.getuid()
      && canonical.kind === 'FILE'
      && String(canonical.stat.dev) === entry.device
      && String(canonical.stat.ino) === entry.inode
      && canonical.stat.size === entry.size
      && (canonical.stat.mode & 0o777) === entry.mode
      && canonical.stat.uid === entry.uid
      && `sha256:${sha256(canonical.bytes)}` === entry.payload_sha256
      && (
        current
          ? (
            sameFileIdentity(current.stat, canonical.stat)
              && current.stat.nlink === entry.link_count
              && canonical.stat.nlink === entry.link_count
              && current.payload_sha256
                === `sha256:${sha256(canonical.bytes)}`
          )
          : canonical.stat.nlink === entry.link_count - 1
      ),
    'STORE_ATOMIC_ARTIFACT_INVALID',
    `${label} 与 sealed cleanup manifest/canonical identity 不匹配`,
  );
}

function atomicCleanupArtifactOwnershipSnapshot(
  root,
  target,
  operation,
  generation,
  canonical,
  claim,
  budget,
) {
  const binding = completedEvenCleanupBinding(claim, generation);
  const inspection = inspectClaimedAtomicTransport(
    root,
    claim,
    binding,
    { inspectionBudget: budget },
  );
  const generationCanonical = inspectAtomicCanonical(
    rootGenerationFile(root),
    budget,
    MAX_ROOT_GENERATION_BYTES,
  );
  assertControl(
    generationCanonical.kind === 'FILE',
    'STORE_ATOMIC_ARTIFACT_INVALID',
    'private atomic artifact cleanup claim 缺 generation canonical',
  );
  const publicationEntries = inspection.terminal
    ? []
    : [...inspection.manifest_files.entries()]
      .filter(([relative]) => (
        relative.split(path.sep)[0] === ATOMIC_PUBLICATION_LINEAGE
      ))
      .map(([relative, entry]) => ({
        relative,
        entry,
        parsed: inspection.publication_descriptors.get(relative).parsed,
        counterpart_relative:
          inspection.publication_descriptors
            .get(relative).counterpart_relative,
        current: inspection.current_files.get(relative) || null,
      }));
  const generationEntries = publicationEntries.filter(
    ({ parsed, entry, counterpart_relative: counterpartRelative }) => (
      parsed.operation === ATOMIC_RESIDUAL_WRITE
        && parsed.target === rootGenerationFile(root)
        && counterpartRelative !== null
        && path.join(root, counterpartRelative)
          === rootGenerationFile(root)
        && parsed.payload_sha256
          === `sha256:${sha256(generationCanonical.bytes)}`
        && entry.payload_sha256 === parsed.payload_sha256
        && entry.link_count === 2
        && entry.device === String(generationCanonical.stat.dev)
        && entry.inode === String(generationCanonical.stat.ino)
    ),
  );
  if (!inspection.terminal) {
    assertControl(
      generationEntries.length === 1,
      'STORE_ATOMIC_ARTIFACT_INVALID',
      'private atomic artifact cleanup claim 缺 unique generation completion marker',
    );
    const generationEntry = generationEntries[0];
    assertCleanupManifestCanonicalBinding(
      'generation completion marker',
      generationEntry.entry,
      generationEntry.current,
      generationCanonical,
    );
    assertControl(
      generationEntry.parsed.payload_sha256
        === `sha256:${sha256(generationCanonical.bytes)}`
        && atomicPayloadCompletesRootTransaction(
          root,
          rootGenerationFile(root),
          generationCanonical.bytes,
        ),
      'STORE_ATOMIC_ARTIFACT_INVALID',
      'private atomic artifact cleanup generation marker 未绑定 clean-even bytes',
    );
  } else {
    assertControl(
      generationCanonical.stat.nlink === 1,
      'STORE_ATOMIC_ARTIFACT_INVALID',
      'terminal cleanup claim 的 generation canonical 仍有未知 hardlink',
    );
  }
  const sameTargetEntries = publicationEntries.filter(
    ({ parsed }) => parsed.target === target,
  );
  const targetEntries = sameTargetEntries.filter(
    ({ entry, counterpart_relative: counterpartRelative }) => (
      entry.link_count === 2
        && counterpartRelative !== null
        && path.join(root, counterpartRelative) === target
        && entry.device === String(canonical.stat.dev)
        && entry.inode === String(canonical.stat.ino)
        && entry.payload_sha256
          === `sha256:${sha256(canonical.bytes)}`
    ),
  );
  assertControl(
    sameTargetEntries.length === 0
      || (
        targetEntries.length === 1
          && targetEntries[0].parsed.operation === operation
      ),
    'STORE_ATOMIC_ARTIFACT_INVALID',
    `private atomic artifact ${target} cleanup manifest operation/counterpart 不匹配`,
  );
  let kind;
  let transactionKeySha256 = null;
  let lineageRelativePath = null;
  let markerPresent = false;
  if (targetEntries.length === 1) {
    const targetEntry = targetEntries[0];
    assertCleanupManifestCanonicalBinding(
      `private atomic artifact ${target}`,
      targetEntry.entry,
      targetEntry.current,
      canonical,
    );
    assertControl(
      targetEntry.parsed.payload_sha256
        === `sha256:${sha256(canonical.bytes)}`,
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `private atomic artifact ${target} cleanup lineage payload hash 不匹配`,
    );
    kind = 'COMPLETED_EVEN_CLEANUP';
    transactionKeySha256 = binding.transaction_key_sha256;
    lineageRelativePath = targetEntry.relative.split(path.sep).join('/');
    markerPresent = targetEntry.current !== null;
  } else {
    assertControl(
      canonical.stat.nlink === 1,
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `private atomic artifact ${target} 与 cleanup claim 间存在未知 hardlink`,
    );
    kind = inspection.terminal
      ? 'SINGLE_LINK_EVEN_CLEANUP_TERMINAL'
      : 'SINGLE_LINK_EVEN_CLEANUP';
  }
  const unsigned = {
    kind,
    generation_record_sha256: hashObject(generation),
    transaction_key_sha256: transactionKeySha256,
    operation,
    target,
    payload_sha256: `sha256:${sha256(canonical.bytes)}`,
    dev: String(canonical.stat.dev),
    ino: String(canonical.stat.ino),
    nlink: canonical.stat.nlink,
    transport_transaction_key_sha256: binding.transaction_key_sha256,
    lineage_relative_path: lineageRelativePath,
    residual_reservation_relative_path: null,
    cleanup_claim_state_sha256: cleanupClaimStateSha256(inspection),
    cleanup_marker_present: markerPresent,
  };
  return {
    ...unsigned,
    ownership_sha256: hashObject(unsigned),
  };
}

function atomicArtifactOwnershipSnapshot(
  root,
  file,
  options,
  expectedStat = null,
) {
  const resolvedRoot = path.resolve(root);
  const target = path.resolve(file);
  atomicTargetRelative(resolvedRoot, target);
  const operation = options.operation;
  assertControl(
    [ATOMIC_RESIDUAL_WRITE, ATOMIC_RESIDUAL_CREATE].includes(operation),
    'STORE_ATOMIC_ARTIFACT_INVALID',
    'private atomic artifact operation 必须是 WRITE/CREATE',
  );
  const budget = createAtomicInspectionBudget(
    MAX_ATOMIC_INSPECTION_ARTIFACT_BYTES,
    Math.max(
      MAX_ATOMIC_INSPECTION_TOTAL_BYTES,
      MAX_ATOMIC_CLEANUP_MANIFEST_BYTES,
      options.maxBytes,
    ),
  );
  const generation = readRootGenerationRecord(resolvedRoot);
  const generationSha256 = hashObject(generation);
  const cleanupClaim = atomicCleanupClaimAt(resolvedRoot);
  const canonical = inspectAtomicCanonical(
    target,
    budget,
    options.maxBytes,
    expectedStat,
  );
  assertControl(
    canonical.kind === 'FILE'
      && canonical.stat.uid === process.getuid()
      && (canonical.stat.mode & 0o777) === 0o600,
    'STORE_ATOMIC_ARTIFACT_INVALID',
    `private atomic artifact ${target} 必须是当前 uid 的 0600 ordinary file`,
  );
  if (cleanupClaim !== null) {
    return atomicCleanupArtifactOwnershipSnapshot(
      resolvedRoot,
      target,
      operation,
      generation,
      canonical,
      cleanupClaim,
      budget,
    );
  }
  const inspection = inspectAtomicTransport(
    resolvedRoot,
    null,
    { inspectionBudget: budget },
  );
  const targetClaims = inspection.publication_lineage_claims.filter(
    (claim) => claim.target === target,
  );
  const targetResidual = inspection.residual
      && inspection.residual.target === target
    ? inspection.residual
    : null;
  if (canonical.stat.nlink === 1) {
    assertControl(
      targetClaims.length === 0 && targetResidual === null,
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `single-link private atomic artifact ${target} 仍有同 target transport binding`,
    );
    const unsigned = {
      kind: 'SINGLE_LINK',
      generation_record_sha256: generationSha256,
      transaction_key_sha256: null,
      operation,
      target,
      payload_sha256: `sha256:${sha256(canonical.bytes)}`,
      dev: String(canonical.stat.dev),
      ino: String(canonical.stat.ino),
      nlink: canonical.stat.nlink,
      transport_transaction_key_sha256: inspection.transactionHex
        ? `sha256:${inspection.transactionHex}`
        : null,
      lineage_relative_path: null,
      residual_reservation_relative_path: null,
    };
    return {
      ...unsigned,
      ownership_sha256: hashObject(unsigned),
    };
  }
  assertControl(
    canonical.stat.nlink >= 2
      && canonical.stat.nlink <= 3
      && inspection.transactionDirectory !== null
      && inspection.cleanup_manifest === null,
    'STORE_ATOMIC_ARTIFACT_INVALID',
    `multi-link private atomic artifact ${target} 缺 active exact transport`,
  );
  let kind;
  let transactionKeySha256;
  if (generation.generation % 2 === 1) {
    assertControl(
      !generation.legacy
        && generation.active_transaction
        && inspection.transactionHex
          === atomicTransactionHex(generation.active_transaction),
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `private atomic artifact ${target} transport 未绑定 active odd transaction`,
    );
    kind = targetResidual === null
      ? 'ACTIVE_ODD'
      : 'ACTIVE_ODD_RESIDUAL';
    transactionKeySha256 = generation.active_transaction.key_sha256;
  } else {
    assertControl(
      targetResidual === null,
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `completed-even private atomic artifact ${target} 不得含 active residual`,
    );
    evenCompletionMarker(resolvedRoot, inspection);
    kind = 'COMPLETED_EVEN';
    transactionKeySha256 = `sha256:${inspection.transactionHex}`;
  }
  let lineageRelativePath = null;
  let residualReservationRelativePath = null;
  if (targetResidual !== null) {
    assertControl(
      targetResidual.operation === operation
        && targetResidual.canonical_is_payload
        && targetResidual.canonical.bytes.equals(canonical.bytes)
        && sameFileIdentity(targetResidual.canonical.stat, canonical.stat)
        && (
          targetResidual.publication_lineage === null
            ? targetClaims.length === 0
            : (
              targetClaims.length === 1
                && targetClaims[0].file
                  === targetResidual.publication_lineage.file
            )
        ),
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `private atomic artifact ${target} residual/lineage binding 非法`,
    );
    residualReservationRelativePath = path.relative(
      inspection.transactionDirectory,
      targetResidual.reservation_file,
    ).split(path.sep).join('/');
    if (targetResidual.publication_lineage !== null) {
      lineageRelativePath = targetResidual.publication_lineage.relative_file
        .split(path.sep).join('/');
    }
  } else {
    assertControl(
      targetClaims.length === 1
        && targetClaims[0].operation === operation
        && targetClaims[0].canonical_is_payload
        && targetClaims[0].relocated_canonical_links.length === 0
        && targetClaims[0].stat.nlink === 2
        && canonical.stat.nlink === 2
        && sameFileIdentity(targetClaims[0].stat, canonical.stat)
        && targetClaims[0].bytes.equals(canonical.bytes),
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `private atomic artifact ${target} 缺 unique exact publication lineage`,
    );
    lineageRelativePath = targetClaims[0].relative_file
      .split(path.sep).join('/');
  }
  const unsigned = {
    kind,
    generation_record_sha256: generationSha256,
    transaction_key_sha256: transactionKeySha256,
    operation,
    target,
    payload_sha256: `sha256:${sha256(canonical.bytes)}`,
    dev: String(canonical.stat.dev),
    ino: String(canonical.stat.ino),
    nlink: canonical.stat.nlink,
    transport_transaction_key_sha256:
      `sha256:${inspection.transactionHex}`,
    lineage_relative_path: lineageRelativePath,
    residual_reservation_relative_path: residualReservationRelativePath,
  };
  return {
    ...unsigned,
    ownership_sha256: hashObject(unsigned),
  };
}

function readPrivateAtomicArtifact(root, file, options = {}) {
  const maxBytes = options.maxBytes;
  assertControl(
    Number.isSafeInteger(maxBytes)
      && maxBytes > 0
      && maxBytes <= MAX_ATOMIC_INSPECTION_ARTIFACT_BYTES,
    'STORE_ATOMIC_ARTIFACT_INVALID',
    'private atomic artifact maxBytes 必须是正安全整数',
  );
  const target = path.resolve(file);
  const before = fs.lstatSync(target);
  assertControl(
    before.isFile()
      && !before.isSymbolicLink()
      && before.uid === process.getuid()
      && (before.mode & 0o777) === 0o600
      && before.size <= maxBytes
      && before.nlink >= 1
      && before.nlink <= 3,
    'STORE_ATOMIC_ARTIFACT_INVALID',
    `private atomic artifact ${target} preflight mode/size/link 非法`,
  );
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  const probe = fs.openSync(
    target,
    fs.constants.O_RDONLY | noFollow,
  );
  try {
    const opened = fs.fstatSync(probe);
    assertControl(
      sameFileIdentity(before, opened)
        && opened.uid === before.uid
        && (opened.mode & 0o777) === (before.mode & 0o777)
        && opened.size === before.size
        && opened.size <= maxBytes
        && opened.nlink === before.nlink,
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `private atomic artifact ${target} preflight identity/size/link 漂移`,
    );
  } finally {
    fs.closeSync(probe);
  }
  const beforeOwnership = atomicArtifactOwnershipSnapshot(
    root,
    target,
    options,
    before,
  );
  const descriptor = fs.openSync(
    target,
    fs.constants.O_RDONLY | noFollow,
  );
  let body;
  try {
    const opened = fs.fstatSync(descriptor);
    assertControl(
      opened.isFile()
        && !opened.isSymbolicLink()
        && opened.dev === before.dev
        && opened.ino === before.ino
        && opened.uid === before.uid
        && (opened.mode & 0o777) === (before.mode & 0o777)
        && opened.size === before.size
        && opened.nlink === before.nlink
        && opened.size <= maxBytes
        && String(opened.dev) === beforeOwnership.dev
        && String(opened.ino) === beforeOwnership.ino
        && opened.nlink === beforeOwnership.nlink,
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `private atomic artifact ${target} open identity/mode/size/link 漂移`,
    );
    body = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < body.length) {
      const count = fs.readSync(
        descriptor,
        body,
        offset,
        body.length - offset,
        offset,
      );
      assertControl(
        count > 0,
        'STORE_ATOMIC_ARTIFACT_INVALID',
        `private atomic artifact ${target} 读取截断`,
      );
      offset += count;
    }
    const after = fs.fstatSync(descriptor);
    const pathnameAfter = fs.lstatSync(target);
    assertControl(
      after.dev === opened.dev
        && after.ino === opened.ino
        && after.uid === opened.uid
        && (after.mode & 0o777) === (opened.mode & 0o777)
        && after.size === opened.size
        && after.nlink === opened.nlink
        && pathnameAfter.dev === opened.dev
        && pathnameAfter.ino === opened.ino
        && pathnameAfter.uid === opened.uid
        && (pathnameAfter.mode & 0o777) === (opened.mode & 0o777)
        && pathnameAfter.size === opened.size
        && pathnameAfter.nlink === opened.nlink,
      'STORE_ATOMIC_ARTIFACT_INVALID',
      `private atomic artifact ${target} 读取期间 identity/mode/size/link 漂移`,
    );
  } finally {
    fs.closeSync(descriptor);
  }
  const afterOwnership = atomicArtifactOwnershipSnapshot(
    root,
    target,
    options,
    before,
  );
  assertControl(
    afterOwnership.ownership_sha256
      === beforeOwnership.ownership_sha256
      && `sha256:${sha256(body)}`
        === beforeOwnership.payload_sha256,
    'STORE_ATOMIC_ARTIFACT_INVALID',
    `private atomic artifact ${target} ownership/payload 在读取期间漂移`,
  );
  return {
    bytes: body,
    ownership: beforeOwnership,
  };
}

function sourceImportIntentPublicationBinding(file, body) {
  const context = activeAtomicTransaction;
  assertControl(
    context
      && context.transaction_key
      && context.transaction_key.kind === 'SOURCE_IMPORT',
    'STORE_ATOMIC_ADOPTION_FORBIDDEN',
    'source import intent publication adoption 只允许 active SOURCE_IMPORT transaction',
  );
  const root = path.resolve(context.root);
  const target = path.resolve(file);
  const targetRelative = atomicTargetRelative(root, target);
  const parts = targetRelative.split(path.sep);
  assertControl(
    parts.length === 7
      && parts[0] === 'goals'
      && parts[2] === 'recovery-handoffs'
      && parts[4] === 'import-intents'
      && parts[6] === 'intent.json',
    'STORE_ATOMIC_ADOPTION_FORBIDDEN',
    'source import intent publication adoption target path 非法',
  );
  const [
    ,
    goalId,
    ,
    taskId,
    ,
    importId,
  ] = parts;
  const safeIdentifier = (value) => (
    typeof value === 'string'
      && value.length <= 200
      && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  );
  assertControl(
    [goalId, taskId, importId].every(safeIdentifier)
      && context.transaction_key.scope.goal_id === goalId
      && context.transaction_key.scope.task_id === taskId
      && context.transaction_key.stable_operation_id_sha256
        === `sha256:${sha256(importId)}`,
    'STORE_ATOMIC_ADOPTION_FORBIDDEN',
    'source import intent publication adoption identity 与 transaction key 不匹配',
  );
  const bytes = atomicBody(body);
  let intent;
  try {
    intent = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'STORE_ATOMIC_ADOPTION_FORBIDDEN',
      `source import intent publication adoption body 不是合法 JSON: ${error.message}`,
    );
  }
  const unsigned = intent
    && typeof intent === 'object'
    && !Array.isArray(intent)
    ? { ...intent }
    : null;
  const intentSha256 = unsigned && unsigned.intent_sha256;
  if (unsigned) delete unsigned.intent_sha256;
  assertControl(
    unsigned
      && intent.schema_version === 1
      && intent.kind === 'RECOVERY_IMPORT_INTENT'
      && intent.goal_id === goalId
      && intent.task_id === taskId
      && intent.import_id === importId
      && intent.request
      && typeof intent.request === 'object'
      && !Array.isArray(intent.request)
      && intent.request_sha256
        === context.transaction_key.request_sha256
      && hashObject(intent.request) === intent.request_sha256
      && intentSha256 === hashObject(unsigned),
    'STORE_ATOMIC_ADOPTION_FORBIDDEN',
    'source import intent publication adoption body/seal 与 transaction key 不匹配',
  );
  return { root, target, bytes };
}

function sourceImportAdoptionDirectoryChain(targetRelative) {
  return atomicPublicationLineageDirectories({
    operation: ATOMIC_RESIDUAL_CREATE,
    target_relative: targetRelative,
  });
}

function cleanupSourceImportAdoptionDirectoryTail(
  root,
  inspection,
  targetRelative,
) {
  if (inspection.transactionDirectory === null) return inspection;
  const durable = atomicLineageDirectorySet(inspection);
  const availableTail = sourceImportAdoptionDirectoryChain(
    targetRelative,
  ).filter((relative) => !durable.has(relative));
  const actualTail = inspection.directories.filter(
    (relative) => !durable.has(relative),
  );
  assertControl(
    actualTail.length <= availableTail.length
      && actualTail.every(
        (relative, index) => relative === availableTail[index],
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'source import intent publication adoption 遇到 foreign/non-prefix directory tail',
  );
  for (const relative of [...actualTail].sort(
    (left, right) => (
      right.split(path.sep).length - left.split(path.sep).length
    ),
  )) {
    const directory = path.join(inspection.transactionDirectory, relative);
    try {
      fs.rmdirSync(directory);
      fsyncDirectory(path.dirname(directory));
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw new ControlError(
        'STORE_ATOMIC_RESIDUAL_CONFLICT',
        `source import intent publication adoption 无法清理 exact empty lineage directory ${relative}: ${error.message}`,
      );
    }
    maybeInjectAtomicFault(
      path.join(
        inspection.transactionDirectory,
        '.source-import-adoption-fault',
      ),
      'GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_IMPORT_ADOPTION_DIRECTORY_RMDIR',
      'source import intent adoption directory cleanup',
    );
  }
  const retained = inspectAtomicTransport(
    root,
    inspection.transactionHex,
  );
  assertControl(
    retained.residual === null
      && retained.cleanup_manifest === null,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'source import intent publication adoption directory cleanup 后出现 active residual',
  );
  if (
    retained.mkdir_lineage_claims.length === 0
      && retained.publication_lineage_claims.length === 0
  ) {
    assertControl(
      retained.directories.length === 0,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'source import intent publication adoption 留下 foreign transport directory',
    );
    fs.rmdirSync(retained.transactionDirectory);
    fsyncDirectory(retained.transport);
    return inspectAtomicTransport(root);
  }
  assertAtomicLineageOnlyDirectoryShape(retained);
  return retained;
}

function adoptSourceImportIntentPublication(file, body) {
  const binding = sourceImportIntentPublicationBinding(file, body);
  const targetRelative = atomicTargetRelative(
    binding.root,
    binding.target,
  );
  const transactionHex = atomicTransactionHex(
    activeAtomicTransaction.transaction_key,
  );
  let inspection = inspectAtomicTransport(
    binding.root,
    transactionHex,
  );
  assertControl(
    inspection.residual === null
      && inspection.cleanup_manifest === null,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'source import intent publication adoption 遇到 active residual/cleanup',
  );
  const targetClaims = inspection.publication_lineage_claims.filter(
    (claim) => claim.target === binding.target,
  );
  assertControl(
    targetClaims.length <= 1
      && targetClaims.every((claim) => (
        claim.operation === ATOMIC_RESIDUAL_CREATE
          && claim.payload_sha256
            === `sha256:${sha256(binding.bytes)}`
          && claim.bytes.equals(binding.bytes)
      )),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'source import intent publication adoption 未命中 unique exact CREATE lineage',
  );
  const canonical = inspectAtomicCanonical(binding.target);
  assertControl(
    canonical.kind === 'FILE'
      && canonical.bytes.equals(binding.bytes),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'source import intent publication adoption canonical bytes 不匹配',
  );
  if (targetClaims.length === 0) {
    cleanupSourceImportAdoptionDirectoryTail(
      binding.root,
      inspection,
      targetRelative,
    );
    return { adopted: false, idempotent: true };
  }
  assertAtomicLineageOnlyDirectoryShape(inspection);
  const claim = targetClaims[0];
  const markerBefore = assertPrivateOwnedPublicationMarker(
    claim.file,
    'source import intent publication marker',
  );
  const canonicalBefore = fs.lstatSync(binding.target);
  assertControl(
    claim.canonical_is_payload
      && claim.relocated_canonical_links.length === 0
      && sameFileIdentity(markerBefore, claim.stat)
      && sameFileIdentity(canonicalBefore, claim.canonical.stat)
      && sameFileIdentity(markerBefore, canonicalBefore)
      && markerBefore.nlink === 2
      && canonicalBefore.nlink === 2,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'source import intent publication adoption 只接受 canonical+marker exact hardlink',
  );
  fs.unlinkSync(claim.file);
  fsyncDirectory(path.dirname(claim.file));
  maybeInjectAtomicFault(
    path.join(
      inspection.transactionDirectory,
      '.source-import-adoption-fault',
    ),
    'GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_IMPORT_ADOPTION_MARKER_UNLINK',
    'source import intent adoption marker unlink',
  );
  const canonicalAfter = fs.lstatSync(binding.target);
  assertControl(
    sameFileIdentity(canonicalBefore, canonicalAfter)
      && canonicalAfter.nlink === 1
      && fs.readFileSync(binding.target).equals(binding.bytes),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'source import intent publication adoption 未收敛到 single-link canonical witness',
  );
  inspection = inspectAtomicTransport(binding.root, transactionHex);
  assertControl(
    inspection.publication_lineage_claims.every(
      (candidate) => candidate.target !== binding.target,
    ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'source import intent publication adoption 后仍残留 target lineage',
  );
  cleanupSourceImportAdoptionDirectoryTail(
    binding.root,
    inspection,
    targetRelative,
  );
  return { adopted: true, idempotent: false };
}

function atomicWrite(file, body, options = {}) {
  const bytes = atomicBody(body);
  if (!activeAtomicTransaction) {
    legacyAtomicWrite(file, bytes, false);
    return;
  }
  if (isCompletedAtomicPrefix(
    file,
    bytes,
    ATOMIC_RESIDUAL_WRITE,
    options,
  )) return;
  const target = path.resolve(file);
  ensureDir(path.dirname(target));
  if (restoreExactPublishedAtomicLineage(
    path.resolve(activeAtomicTransaction.root),
    target,
    bytes,
    ATOMIC_RESIDUAL_WRITE,
    options,
  )) {
    return;
  }
  const prepared = prepareTransactionAtomic(
    file,
    bytes,
    ATOMIC_RESIDUAL_WRITE,
    options,
  );
  publishTransactionAtomic(prepared, options);
}

function atomicWriteJson(file, value, options = {}) {
  atomicWrite(file, `${JSON.stringify(value, null, 2)}\n`, options);
}

function atomicCreate(file, body, options = {}) {
  const bytes = atomicBody(body);
  if (!activeAtomicTransaction) {
    return legacyAtomicWrite(file, bytes, true);
  }
  if (isCompletedAtomicPrefix(
    file,
    bytes,
    ATOMIC_RESIDUAL_CREATE,
    options,
  )) return false;
  const target = path.resolve(file);
  ensureDir(path.dirname(target));
  if (restoreExactPublishedAtomicLineage(
    path.resolve(activeAtomicTransaction.root),
    target,
    bytes,
    ATOMIC_RESIDUAL_CREATE,
    options,
  )) {
    return true;
  }
  const prepared = prepareTransactionAtomic(
    file,
    bytes,
    ATOMIC_RESIDUAL_CREATE,
    options,
  );
  return publishTransactionAtomic(prepared, options).created;
}

function withAtomicTransaction(root, transactionKey, callback) {
  const validated = validateTransactionKey(transactionKey);
  const resolvedRoot = path.resolve(root);
  const previous = activeAtomicTransaction;
  assertControl(
    previous === null
      || (
        previous.root === resolvedRoot
          && previous.transaction_key.key_sha256 === validated.key_sha256
      ),
    'STORE_ATOMIC_TRANSACTION_CONFLICT',
    'nested atomic transaction 与 active transaction 不一致',
  );
  activeAtomicTransaction = {
    root: resolvedRoot,
    transaction_key: validated,
  };
  try {
    return callback();
  } finally {
    activeAtomicTransaction = previous;
  }
}

function atomicGenerationResidual(root, expectedTransaction = null) {
  const expectedHex = expectedTransaction === null
    ? null
    : atomicTransactionHex(expectedTransaction);
  let inspection = inspectAtomicTransport(root, expectedHex);
  const generationRelative = atomicTargetRelative(
    root,
    rootGenerationFile(root),
  );
  assertControl(
    inspection.transactionDirectory === null
      || expectedTransaction !== null,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'generation atomic residual 尚未绑定 requested transaction',
  );
  if (
    inspection.residual
      && inspection.residual.target === rootGenerationFile(root)
      && inspection.residual.canonical_is_payload
  ) {
    cleanupExactPublishedAtomicResidual(inspection);
    inspection = inspectAtomicTransport(root, expectedHex);
  }
  if (
    !inspection.residual
      && inspection.transactionDirectory !== null
      && inspection.mkdir_lineage_claims.length === 0
      && inspection.publication_lineage_claims.length === 0
      && atomicDirectoryShapeMatches(
        inspection,
        ATOMIC_RESIDUAL_WRITE,
        generationRelative,
      )
  ) {
    cleanupExactEmptyAtomicTransport(
      inspection,
      ATOMIC_RESIDUAL_WRITE,
      generationRelative,
    );
    inspection = inspectAtomicTransport(root, expectedHex);
  }
  if (
    !inspection.residual
      && inspection.transactionDirectory !== null
      && readRootGeneration(root) % 2 === 0
  ) {
    inspection = cleanupCompletedEvenAtomicTransport(root, inspection);
  }
  if (!inspection.residual) {
    return {
      inspection,
      timestamp: null,
    };
  }
  assertControl(
    inspection.residual.operation === ATOMIC_RESIDUAL_WRITE
      && inspection.residual.target === rootGenerationFile(root)
      && Number.isSafeInteger(
        inspection.residual.stable_time_milliseconds,
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'generation boundary 发现非 generation 或缺 timestamp 的 atomic residual',
  );
  const timestamp = new Date(
    inspection.residual.stable_time_milliseconds,
  ).toISOString();
  assertControl(
    Number.isFinite(Date.parse(timestamp)),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'generation atomic residual timestamp 非法',
  );
  return { inspection, timestamp };
}

function assertAtomicTransactionClean(root, transactionKey) {
  const inspection = inspectAtomicTransport(
    root,
    atomicTransactionHex(transactionKey),
  );
  assertControl(
    inspection.transactionDirectory === null
      || (
        inspection.residual === null
          && (
            inspection.mkdir_lineage_claims.length
              + inspection.publication_lineage_claims.length
          ) > 0
          && inspection.mkdir_lineage_claims.every(
            (claim) => claim.lineage === true,
          )
      ),
    'STORE_ATOMIC_RESIDUAL_UNCONSUMED',
    'callback/transaction completion 前仍有未消费 atomic payload transport',
  );
}

function processAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

function processStartToken(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const started = execFileSync('/bin/ps', ['-p', String(pid), '-o', 'lstart='], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      env: { PATH: '/usr/bin:/bin' },
    }).trim();
    return started ? `sha256:${sha256(`${pid}\n${started}`)}` : null;
  } catch {
    return null;
  }
}

const CURRENT_PROCESS_START_TOKEN = processStartToken(process.pid)
  || `sha256:${sha256(`${process.pid}\n${Math.floor(Date.now() - (process.uptime() * 1000))}`)}`;

function controllerDecoderFingerprintAt(decoderDirectory) {
  const files = {};
  const root = fs.realpathSync(decoderDirectory);
  const pending = [...CONTROLLER_DECODER_SEEDS];
  const schemaDir = path.join(root, CONTROLLER_SCHEMA_DIRECTORY);
  for (const name of fs.readdirSync(schemaDir).sort()) {
    if (name.endsWith('.json')) {
      pending.push(`${CONTROLLER_SCHEMA_DIRECTORY}/${name}`);
    }
  }
  const visited = new Set();
  while (pending.length > 0) {
    const relative = pending.shift().split(path.sep).join('/');
    if (visited.has(relative)) continue;
    const absolute = path.resolve(root, relative);
    let dependencyStat;
    let canonicalAbsolute;
    try {
      dependencyStat = fs.lstatSync(absolute);
      canonicalAbsolute = fs.realpathSync(absolute);
    } catch (error) {
      throw new ControlError(
        'DECODER_DEPENDENCY_INVALID',
        `decoder dependency 无法读取: ${relative}: ${error.message}`,
      );
    }
    assertControl(
      absolute.startsWith(`${root}${path.sep}`)
        && dependencyStat.isFile()
        && !dependencyStat.isSymbolicLink()
        && canonicalAbsolute === absolute,
      'DECODER_DEPENDENCY_INVALID',
      `decoder dependency 越界、symlink 或不是 canonical file: ${relative}`,
    );
    visited.add(relative);
    const body = fs.readFileSync(absolute);
    files[relative] = `sha256:${sha256(body)}`;
    if (!relative.endsWith('.js')) continue;

    const source = body.toString('utf8');
    const localRequire = /\brequire\s*\(\s*(['"])(\.[^'"]+)\1\s*\)/g;
    let match;
    while ((match = localRequire.exec(source)) !== null) {
      const requested = path.resolve(path.dirname(absolute), match[2]);
      const candidates = path.extname(requested)
        ? [requested]
        : [
          requested,
          `${requested}.js`,
          `${requested}.json`,
          path.join(requested, 'index.js'),
          path.join(requested, 'index.json'),
        ];
      const dependency = candidates.find((candidate) => {
        try {
          return fs.statSync(candidate).isFile();
        } catch {
          return false;
        }
      });
      assertControl(
        dependency
          && dependency.startsWith(`${root}${path.sep}`),
        'DECODER_DEPENDENCY_INVALID',
        `无法解析 decoder 本地依赖 ${match[2]}（from ${relative}）`,
      );
      pending.push(path.relative(root, dependency));
    }
  }
  return hashObject({
    schema_version: 1,
    files,
  });
}

function controllerDecoderFingerprint() {
  if (controllerDecoderFingerprintCache) return controllerDecoderFingerprintCache;
  controllerDecoderFingerprintCache = controllerDecoderFingerprintAt(__dirname);
  return controllerDecoderFingerprintCache;
}

function assertCurrentControllerDecoderFingerprint(expectedSha256) {
  const fresh = controllerDecoderFingerprintAt(__dirname);
  assertControl(
    fresh === expectedSha256
      && controllerDecoderFingerprint() === expectedSha256,
    'STORE_PROTOCOL_ROTATION_SUCCESSOR_DECODER_CHANGED',
    'successor decoder closure 在 rotation 期间发生 bytes/fingerprint 漂移',
  );
  return fresh;
}

function rootProtocolCompatibility() {
  return {
    schema_version: ROOT_PROTOCOL_SCHEMA_VERSION,
    controller_decoder_version: CONTROLLER_DECODER_VERSION,
    controller_decoder_sha256: controllerDecoderFingerprint(),
    lock_protocol_version: LOCK_PROTOCOL_VERSION,
  };
}

function rootProtocolCompatibilitySha256() {
  return hashObject(rootProtocolCompatibility());
}

function expectedRootProtocol(options = {}) {
  const unsigned = {
    ...rootProtocolCompatibility(),
    migration_source_state_vector_sha256:
      options.migrationSourceStateVectorSha256 ?? null,
    migration_artifacts: options.migrationArtifacts ?? [],
    protocol_rotations: options.protocolRotations ?? [],
  };
  return {
    ...unsigned,
    seal_sha256: hashObject(unsigned),
  };
}

function rootProtocolFile(root) {
  return path.join(root, ROOT_PROTOCOL_FILE);
}

function migrationArtifactKind(relativePath) {
  if (relativePath === LEGACY_EVIDENCE_ANCHOR_FILE) return 'INDEX';
  if (relativePath === LEGACY_IDENTITY_INCIDENT_RECEIPT_FILE) {
    return 'IDENTITY_INDEX';
  }
  if (
    typeof relativePath === 'string'
    && /^\.legacy-evidence-sources\.v1\/[0-9a-f]{64}\.artifact$/.test(relativePath)
  ) {
    return 'SOURCE';
  }
  return null;
}

function assertMigrationArtifactPath(relativePath, sha) {
  const kind = migrationArtifactKind(relativePath);
  assertControl(
    kind !== null
      && path.posix.normalize(relativePath) === relativePath
      && !path.isAbsolute(relativePath)
      && !relativePath.split('/').includes('..'),
    'STORE_MIGRATION_ARTIFACT_PATH_INVALID',
    `migration artifact path 不在白名单: ${relativePath}`,
  );
  if (kind === 'SOURCE') {
    assertControl(
      path.posix.basename(relativePath) === `${sha.slice('sha256:'.length)}.artifact`,
      'STORE_MIGRATION_ARTIFACT_DIGEST_MISMATCH',
      `legacy source artifact 文件名未绑定 body digest: ${relativePath}`,
    );
  }
  return kind;
}

function validateMigrationArtifactDescriptors(root, descriptors) {
  assertControl(
    Array.isArray(descriptors)
      && descriptors.length <= MAX_MIGRATION_SOURCE_ARTIFACTS + 2,
    'CORRUPT_STORE_PROTOCOL',
    'root protocol migration_artifacts 必须是受限数组',
  );
  const normalized = [];
  const seen = new Set();
  let indexCount = 0;
  let identityIndexCount = 0;
  let sourceCount = 0;
  let sourceBytes = 0;
  for (const descriptor of descriptors) {
    assertControl(
      descriptor
        && typeof descriptor === 'object'
        && !Array.isArray(descriptor)
        && Object.keys(descriptor).length === 2
        && Object.keys(descriptor).every((key) => (
          ['relative_path', 'sha256'].includes(key)
        ))
        && typeof descriptor.sha256 === 'string'
        && /^sha256:[0-9a-f]{64}$/.test(descriptor.sha256)
        && !seen.has(descriptor.relative_path),
      'CORRUPT_STORE_PROTOCOL',
      'root protocol migration artifact descriptor 非法、重复或越界',
    );
    const kind = assertMigrationArtifactPath(
      descriptor.relative_path,
      descriptor.sha256,
    );
    seen.add(descriptor.relative_path);
    ensureMigrationArtifactParent(root, descriptor.relative_path, false);
    const file = path.join(root, descriptor.relative_path);
    let stat;
    let body;
    try {
      stat = fs.lstatSync(file);
      body = fs.readFileSync(file);
    } catch (error) {
      throw new ControlError(
        'CORRUPT_STORE_PROTOCOL',
        `root protocol migration artifact 无法读取: ${descriptor.relative_path}: ${error.message}`,
      );
    }
    assertControl(
      stat.isFile()
        && `sha256:${sha256(body)}` === descriptor.sha256,
      'CORRUPT_STORE_PROTOCOL',
      `root protocol migration artifact bytes 不匹配: ${descriptor.relative_path}`,
    );
    if (kind === 'INDEX' || kind === 'IDENTITY_INDEX') {
      if (kind === 'INDEX') indexCount += 1;
      else identityIndexCount += 1;
      assertControl(
        body.length <= MAX_MIGRATION_INDEX_BYTES,
        'CORRUPT_STORE_PROTOCOL',
        'legacy evidence anchor index 超过大小上限',
      );
    } else {
      sourceCount += 1;
      sourceBytes += body.length;
      assertControl(
        body.length <= MAX_MIGRATION_SOURCE_ARTIFACT_BYTES
          && sourceBytes <= MAX_MIGRATION_SOURCE_TOTAL_BYTES,
        'CORRUPT_STORE_PROTOCOL',
        'legacy evidence source artifact 超过单文件或总大小上限',
      );
    }
    normalized.push({
      relative_path: descriptor.relative_path,
      sha256: descriptor.sha256,
    });
  }
  normalized.sort((left, right) => left.relative_path.localeCompare(right.relative_path));
  assertControl(
    canonicalJson(descriptors) === canonicalJson(normalized),
    'CORRUPT_STORE_PROTOCOL',
    'root protocol migration_artifacts 必须按 relative_path 排序',
  );
  assertControl(
    (normalized.length === 0 && indexCount === 0 && sourceCount === 0)
      || (
        indexCount === 1
          && identityIndexCount <= 1
          && sourceCount <= MAX_MIGRATION_SOURCE_ARTIFACTS
      ),
    'CORRUPT_STORE_PROTOCOL',
    'root protocol migration artifacts 必须包含且仅包含一个 legacy anchor index',
  );
  return normalized;
}

function protocolCompatibilityFromSeal(seal) {
  return {
    schema_version: seal.schema_version,
    controller_decoder_version: seal.controller_decoder_version,
    controller_decoder_sha256: seal.controller_decoder_sha256,
    lock_protocol_version: seal.lock_protocol_version,
  };
}

function validateProtocolCompatibilityRecord(record, label, options = {}) {
  assertControl(
    record
      && typeof record === 'object'
      && !Array.isArray(record)
      && Object.keys(record).length === 4
      && Object.keys(record).every((key) => (
        [
          'schema_version',
          'controller_decoder_version',
          'controller_decoder_sha256',
          'lock_protocol_version',
        ].includes(key)
      ))
      && Number.isSafeInteger(record.schema_version)
      && (
        options.allowLegacySchema === true
          ? [
            LEGACY_ROOT_PROTOCOL_SCHEMA_VERSION,
            ROOT_PROTOCOL_SCHEMA_VERSION,
          ].includes(record.schema_version)
          : record.schema_version === ROOT_PROTOCOL_SCHEMA_VERSION
      )
      && Number.isSafeInteger(record.controller_decoder_version)
      && record.controller_decoder_version > 0
      && typeof record.controller_decoder_sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(record.controller_decoder_sha256)
      && record.lock_protocol_version === LOCK_PROTOCOL_VERSION,
    'CORRUPT_STORE_PROTOCOL',
    `${label} protocol compatibility 非法`,
  );
  return record;
}

function protocolAuthoritySingleLinkRetryCandidate(file, maxBytes) {
  try {
    const stat = fs.lstatSync(file);
    return stat.isFile()
      && !stat.isSymbolicLink()
      && stat.uid === process.getuid()
      && (stat.mode & 0o777) === 0o600
      && stat.nlink === 1
      && stat.size <= maxBytes;
  } catch {
    return false;
  }
}

function rootGenerationSnapshotSha256(root) {
  try {
    return hashObject(readRootGenerationRecord(root));
  } catch {
    return null;
  }
}

function protocolAuthorityHasRetryWitness(root, generationBeforeSha256) {
  const contention = observeOwnedDirectoryContention(
    path.join(root, '.lock'),
    WRITER_LOCK_KIND,
  );
  if (
    contention.kind === 'LIVE_V2'
      && contention.observation.owner.pid !== process.pid
  ) {
    return true;
  }
  if (contention.kind === 'TRANSITION') return true;
  const generationAfterSha256 = rootGenerationSnapshotSha256(root);
  return generationBeforeSha256 !== null
    && generationAfterSha256 !== null
    && generationBeforeSha256 !== generationAfterSha256;
}

function readProtocolAuthorityFile(
  root,
  file,
  maxBytes,
  label,
  operations,
) {
  let failures = [];
  for (
    let attempt = 0;
    attempt <= MAX_PROTOCOL_AUTHORITY_SNAPSHOT_RETRIES;
    attempt += 1
  ) {
    const generationBeforeSha256 = rootGenerationSnapshotSha256(root);
    failures = [];
    for (const operation of operations) {
      try {
        return readPrivateAtomicArtifact(root, file, {
          operation,
          maxBytes,
        }).bytes;
      } catch (error) {
        failures.push(
          `${error && error.code ? error.code : 'ERROR'}:${
            error && error.message ? error.message : String(error)
          }`,
        );
      }
    }
    if (
      attempt >= MAX_PROTOCOL_AUTHORITY_SNAPSHOT_RETRIES
        || !protocolAuthoritySingleLinkRetryCandidate(file, maxBytes)
        || !protocolAuthorityHasRetryWitness(
          root,
          generationBeforeSha256,
        )
    ) break;
    sleepSync(PROTOCOL_AUTHORITY_SNAPSHOT_RETRY_MILLISECONDS);
  }
  let before;
  let descriptor;
  let candidate;
  try {
    before = fs.lstatSync(file);
    assertControl(
      before.isFile()
        && !before.isSymbolicLink()
        && before.uid === process.getuid()
        && (before.mode & 0o777) === 0o600
        && (before.nlink === 1 || before.nlink === 2)
        && before.size <= maxBytes,
      'CORRUPT_STORE_PROTOCOL',
      `${label} partial-write preimage 属性非法`,
    );
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    candidate = readBoundedOpenDescriptor(
      file,
      descriptor,
      before,
      maxBytes,
      'CORRUPT_STORE_PROTOCOL',
      `${label} partial-write preimage`,
    );
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'CORRUPT_STORE_PROTOCOL',
      `${label} 无法安全读取 partial-write preimage: ${error.message}`,
    );
  }
  fs.closeSync(descriptor);
  const generation = readRootGenerationRecord(root);
  const inspection = inspectAtomicTransport(root);
  const residual = inspection.residual;
  const activePreimage = (
    before.nlink === 1
      && !generation.legacy
      && generation.generation % 2 === 1
      && generation.active_transaction
      && inspection.transactionHex
        === generation.active_transaction.key_sha256.slice('sha256:'.length)
      && residual
      && residual.target === path.resolve(file)
      && operations.includes(residual.operation)
      && residual.canonical
      && residual.canonical.kind === 'FILE'
      && !residual.canonical_is_payload
      && residual.preimage_sha256
        === residual.canonical.descriptor_sha256
      && sameAtomicFileBinding(before, residual.canonical.stat)
      && residual.canonical.bytes.equals(candidate)
  );
  const authorityClaims = inspection.publication_lineage_claims.filter(
    (claim) => (
      claim.target === path.resolve(file)
        && operations.includes(claim.operation)
        && claim.canonical_is_payload
        && sameAtomicFileBinding(before, claim.stat)
        && claim.bytes.equals(candidate)
    ),
  );
  const publishedGenerationCompletion = (
    before.nlink === 2
      && !generation.legacy
      && generation.schema_version === ROOT_GENERATION_SCHEMA_VERSION
      && generation.generation % 2 === 0
      && generation.active_transaction === null
      && generation.pre_write_vector_sha256 === null
      && residual
      && residual.operation === ATOMIC_RESIDUAL_WRITE
      && residual.target === rootGenerationFile(root)
      && residual.canonical_is_payload
      && residual.canonical
      && residual.canonical.kind === 'FILE'
      && residual.payload_sha256
        === `sha256:${sha256(residual.canonical.bytes)}`
      && atomicPayloadCompletesRootTransaction(
        root,
        residual.target,
        residual.canonical.bytes,
      )
      && residual.canonical.bytes.equals(
        readBoundedRootGenerationBytes(root),
      )
      && authorityClaims.length === 1
  );
  assertControl(
    activePreimage || publishedGenerationCompletion,
    'CORRUPT_STORE_PROTOCOL',
    `${label} 不是 exact active atomic authority: ${failures.join(',')}`,
  );
  const after = fs.lstatSync(file);
  assertControl(
    sameAtomicFileBinding(before, after),
    'CORRUPT_STORE_PROTOCOL',
    `${label} active atomic preimage validation 后 pathname 漂移`,
  );
  const finalDescriptor = fs.openSync(
    file,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  let finalBytes;
  try {
    finalBytes = readBoundedOpenDescriptor(
      file,
      finalDescriptor,
      after,
      maxBytes,
      'CORRUPT_STORE_PROTOCOL',
      `${label} active atomic authority final read`,
    );
  } finally {
    fs.closeSync(finalDescriptor);
  }
  assertControl(
    finalBytes.equals(candidate),
    'CORRUPT_STORE_PROTOCOL',
    `${label} active atomic authority bytes 在 validation 期间漂移`,
  );
  return candidate;
}

function protocolRotationDirectoryInventory(root) {
  const directory = path.join(root, ROOT_PROTOCOL_ROTATION_DIRECTORY);
  let before;
  try {
    before = fs.lstatSync(directory);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return {
        kind: 'MISSING',
        directory,
        names: [],
        stat: null,
      };
    }
    throw new ControlError(
      'CORRUPT_STORE_PROTOCOL',
      `protocol rotation directory 无法读取: ${error.message}`,
    );
  }
  assertControl(
    before.isDirectory()
      && !before.isSymbolicLink()
      && before.uid === process.getuid()
      && (before.mode & 0o777) === 0o700,
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation directory 必须是 current-uid 0700 ordinary directory',
  );
  const names = [];
  let handle;
  try {
    handle = fs.opendirSync(directory);
    for (;;) {
      const entry = handle.readSync();
      if (entry === null) break;
      assertControl(
        names.length < MAX_ROOT_PROTOCOL_ROTATIONS,
        'CORRUPT_STORE_PROTOCOL',
        `protocol rotation directory 超出 ${MAX_ROOT_PROTOCOL_ROTATIONS} entries`,
      );
      names.push(entry.name);
    }
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'CORRUPT_STORE_PROTOCOL',
      `protocol rotation directory 无法枚举: ${error.message}`,
    );
  } finally {
    if (handle) handle.closeSync();
  }
  const after = fs.lstatSync(directory);
  assertControl(
    sameFileIdentity(before, after)
      && after.isDirectory()
      && !after.isSymbolicLink()
      && after.uid === before.uid
      && (after.mode & 0o777) === (before.mode & 0o777),
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation directory 在 inventory 期间 identity/mode 漂移',
  );
  return {
    kind: 'DIRECTORY',
    directory,
    names: names.sort(),
    stat: after,
  };
}

function assertProtocolRotationInventory(
  inventory,
  expectedNames,
  expectedDirectoryStat = null,
) {
  const expectedKind = expectedNames.length === 0
    ? inventory.kind
    : 'DIRECTORY';
  assertControl(
    inventory.kind === expectedKind
      && (
        expectedDirectoryStat === null
          || (
            inventory.stat !== null
              && sameFileIdentity(expectedDirectoryStat, inventory.stat)
              && inventory.stat.uid === expectedDirectoryStat.uid
              && (inventory.stat.mode & 0o777)
                === (expectedDirectoryStat.mode & 0o777)
          )
      )
      && canonicalJson(inventory.names)
        === canonicalJson([...expectedNames].sort()),
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation directory inventory 与 seal descriptors 不一致',
  );
}

function validateProtocolRotationReceipt(root, descriptor) {
  assertControl(
    descriptor
      && typeof descriptor === 'object'
      && !Array.isArray(descriptor)
      && Object.keys(descriptor).length === 2
      && Object.keys(descriptor).every((key) => (
        ['relative_path', 'sha256'].includes(key)
      ))
      && typeof descriptor.relative_path === 'string'
      && /^\.protocol-rotations\.v1\/[0-9a-f]{64}\.json$/.test(
        descriptor.relative_path,
      )
      && typeof descriptor.sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(descriptor.sha256)
      && path.posix.basename(descriptor.relative_path)
        === `${descriptor.sha256.slice('sha256:'.length)}.json`,
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation descriptor 非法',
  );
  const parent = path.join(root, ROOT_PROTOCOL_ROTATION_DIRECTORY);
  const file = path.join(root, descriptor.relative_path);
  let parentStat;
  let body;
  try {
    parentStat = fs.lstatSync(parent);
    body = readProtocolAuthorityFile(
      root,
      file,
      MAX_ROOT_PROTOCOL_ROTATION_RECEIPT_BYTES,
      `protocol rotation receipt ${descriptor.relative_path}`,
      [ATOMIC_RESIDUAL_CREATE],
    );
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'CORRUPT_STORE_PROTOCOL',
      `protocol rotation receipt 无法读取: ${descriptor.relative_path}: ${error.message}`,
    );
  }
  assertControl(
    parentStat.isDirectory()
      && !parentStat.isSymbolicLink()
      && parentStat.uid === process.getuid()
      && (parentStat.mode & 0o777) === 0o700
      && body.length <= MAX_ROOT_PROTOCOL_ROTATION_RECEIPT_BYTES
      && `sha256:${sha256(body)}` === descriptor.sha256,
    'CORRUPT_STORE_PROTOCOL',
    `protocol rotation receipt identity/bytes 非法: ${descriptor.relative_path}`,
  );
  let receipt;
  try {
    receipt = JSON.parse(body.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'CORRUPT_STORE_PROTOCOL',
      `protocol rotation receipt 不是合法 JSON: ${error.message}`,
    );
  }
  assertControl(
    Buffer.from(`${canonicalJson(receipt)}\n`).equals(body)
      && receipt
      && typeof receipt === 'object'
      && !Array.isArray(receipt)
      && Object.keys(receipt).length === 18
      && Object.keys(receipt).every((key) => (
        [
          'schema_version',
          'rotation_id',
          'requested_at',
          'incident_ref',
          'old_controller_drain_ack',
          'predecessor_protocol',
          'successor_protocol',
          'migration_artifacts_sha256',
          'source_state_vector_sha256',
          'validation_report',
          'validation_report_sha256',
          'goal_worktree_map',
          'goal_worktree_map_sha256',
          'entry_generation',
          'exit_generation',
          'operator_request_sha256',
          'request_sha256',
          'receipt_sha256',
        ].includes(key)
      )),
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation receipt 字段或 canonical encoding 非法',
  );
  assertControl(
    receipt.schema_version === ROOT_PROTOCOL_ROTATION_SCHEMA_VERSION
      && typeof receipt.rotation_id === 'string'
      && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(receipt.rotation_id)
      && typeof receipt.requested_at === 'string'
      && Number.isFinite(Date.parse(receipt.requested_at))
      && typeof receipt.incident_ref === 'string'
      && receipt.incident_ref.trim() === receipt.incident_ref
      && receipt.incident_ref.length > 0
      && receipt.incident_ref.length <= 2000
      && receipt.old_controller_drain_ack
        === ROOT_PROTOCOL_ROTATION_DRAIN_ACK
      && typeof receipt.migration_artifacts_sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(
        receipt.migration_artifacts_sha256,
      )
      && typeof receipt.source_state_vector_sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(
        receipt.source_state_vector_sha256,
      )
      && typeof receipt.validation_report_sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(
        receipt.validation_report_sha256,
      )
      && typeof receipt.goal_worktree_map_sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(
        receipt.goal_worktree_map_sha256,
      )
      && Number.isSafeInteger(receipt.entry_generation)
      && receipt.entry_generation >= 0
      && receipt.entry_generation % 2 === 0
      && receipt.exit_generation === receipt.entry_generation + 2
      && typeof receipt.operator_request_sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(
        receipt.operator_request_sha256,
      )
      && typeof receipt.request_sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(receipt.request_sha256)
      && typeof receipt.receipt_sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(receipt.receipt_sha256),
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation receipt scalar binding 非法',
  );
  validateProtocolCompatibilityRecord(
    {
      schema_version: receipt.predecessor_protocol.schema_version,
      controller_decoder_version:
        receipt.predecessor_protocol.controller_decoder_version,
      controller_decoder_sha256:
        receipt.predecessor_protocol.controller_decoder_sha256,
      lock_protocol_version:
        receipt.predecessor_protocol.lock_protocol_version,
    },
    'predecessor',
    { allowLegacySchema: true },
  );
  assertControl(
    Object.keys(receipt.predecessor_protocol).length === 5
      && typeof receipt.predecessor_protocol.seal_sha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(
        receipt.predecessor_protocol.seal_sha256,
      ),
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation predecessor seal binding 非法',
  );
  validateProtocolCompatibilityRecord(
    receipt.successor_protocol,
    'successor',
  );
  let reportJson;
  let worktreeMapJson;
  try {
    reportJson = canonicalJson(receipt.validation_report);
    worktreeMapJson = canonicalJson(receipt.goal_worktree_map);
  } catch (error) {
    throw new ControlError(
      'CORRUPT_STORE_PROTOCOL',
      `protocol rotation receipt JSON binding 非法: ${error.message}`,
    );
  }
  assertControl(
    hashObject(receipt.validation_report)
      === receipt.validation_report_sha256
      && hashObject(receipt.goal_worktree_map)
        === receipt.goal_worktree_map_sha256
      && typeof reportJson === 'string'
      && typeof worktreeMapJson === 'string',
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation validation/worktree map hash 不匹配',
  );
  const request = {
    schema_version: 1,
    rotation_id: receipt.rotation_id,
    incident_ref: receipt.incident_ref,
    old_controller_drain_ack: receipt.old_controller_drain_ack,
    expected_predecessor_seal_sha256:
      receipt.predecessor_protocol.seal_sha256,
    operator_request_sha256: receipt.operator_request_sha256,
    predecessor_protocol: receipt.predecessor_protocol,
    successor_protocol: receipt.successor_protocol,
    migration_artifacts_sha256: receipt.migration_artifacts_sha256,
    source_state_vector_sha256: receipt.source_state_vector_sha256,
    validation_report_sha256: receipt.validation_report_sha256,
    goal_worktree_map_sha256: receipt.goal_worktree_map_sha256,
  };
  assertControl(
    hashObject(request) === receipt.request_sha256,
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation request hash 不匹配',
  );
  const unsigned = { ...receipt };
  delete unsigned.receipt_sha256;
  assertControl(
    hashObject(unsigned) === receipt.receipt_sha256,
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation receipt self hash 不匹配',
  );
  return receipt;
}

function exactPendingProtocolRotationInventory(
  root,
  seal,
  inventory,
  sealedNames,
  requestOptions,
) {
  const sealed = new Set(sealedNames);
  const extras = inventory.names.filter((name) => !sealed.has(name));
  if (extras.length === 0) return null;
  assertControl(
    inventory.kind === 'DIRECTORY'
      && extras.length === 1
      && inventory.names.length === sealedNames.length + 1
      && /^[0-9a-f]{64}\.json$/.test(extras[0]),
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation directory 含非 sealed/active receipt entry',
  );
  const pendingName = extras[0];
  const descriptor = {
    relative_path:
      `${ROOT_PROTOCOL_ROTATION_DIRECTORY}/${pendingName}`,
    sha256:
      `sha256:${pendingName.slice(0, -'.json'.length)}`,
  };
  const receipt = validateProtocolRotationReceipt(root, descriptor);
  const generation = readRootGenerationRecord(root);
  const validation = normalizeProtocolRotationValidationResult({
    report: receipt.validation_report,
  });
  const targetCompatibility = receipt.successor_protocol;
  const request = rootProtocolRotationRequest({
    rotationId: requestOptions.rotationId,
    incidentRef: requestOptions.incidentRef,
    oldControllerDrainAcknowledgment:
      requestOptions.oldControllerDrainAcknowledgment,
    operatorRequestSha256: requestOptions.operatorRequestSha256,
    predecessorProtocol: seal,
    successorProtocol: targetCompatibility,
    sourceStateVectorSha256: receipt.source_state_vector_sha256,
    validation,
  });
  const expectedTransaction = rootProtocolRotationTransaction(
    root,
    receipt.rotation_id,
    request,
  );
  assertControl(
    !generation.legacy
      && generation.generation % 2 === 1
      && canonicalJson(generation.active_transaction)
        === canonicalJson(expectedTransaction)
      && generation.generation === receipt.entry_generation + 1
      && receipt.exit_generation === generation.generation + 1
      && seal.seal_sha256
        === requestOptions.expectedPredecessorSealSha256
      && receipt.rotation_id === requestOptions.rotationId
      && receipt.incident_ref === requestOptions.incidentRef
      && receipt.old_controller_drain_ack
        === requestOptions.oldControllerDrainAcknowledgment
      && receipt.predecessor_protocol.seal_sha256
        === requestOptions.expectedPredecessorSealSha256
      && receipt.operator_request_sha256
        === requestOptions.operatorRequestSha256
      && canonicalJson(receipt.predecessor_protocol)
        === canonicalJson(protocolWithSealSummary(seal))
      && receipt.migration_artifacts_sha256
        === hashObject(seal.migration_artifacts)
      && canonicalJson(validation.goal_worktree_map)
        === canonicalJson(receipt.goal_worktree_map)
      && validation.goal_worktree_map_sha256
        === receipt.goal_worktree_map_sha256
      && hashObject(request) === receipt.request_sha256,
    'CORRUPT_STORE_PROTOCOL',
    'unsealed protocol rotation receipt 缺 exact predecessor/odd transaction binding',
  );
  const inspection = inspectAtomicTransport(
    root,
    atomicTransactionHex(expectedTransaction),
  );
  const receiptFile = path.join(root, descriptor.relative_path);
  const receiptClaims = inspection.publication_lineage_claims.filter(
    (claim) => (
      claim.operation === ATOMIC_RESIDUAL_CREATE
        && claim.target === receiptFile
        && claim.payload_sha256 === descriptor.sha256
        && claim.canonical_is_payload
        && claim.bytes.equals(protocolRotationReceiptBody(receipt))
    ),
  );
  assertControl(
    receiptClaims.length === 1,
    'CORRUPT_STORE_PROTOCOL',
    'unsealed protocol rotation receipt 缺 exact atomic CREATE lineage',
  );
  assertControl(
    readMigrationSourceStateVector(root, inspection)
      === receipt.source_state_vector_sha256,
    'STORE_PROTOCOL_ROTATION_SOURCE_CHANGED',
    'unsealed protocol rotation receipt 的 source vector 已漂移',
  );
  assertControl(
    receipt.requested_at === generation.updated_at
      && inspection.transactionDirectory !== null,
    'CORRUPT_STORE_PROTOCOL',
    'unsealed protocol rotation receipt 缺 exact generation timestamp/transaction transport',
  );
  return {
    descriptor,
    receipt,
    generation,
    validation,
    request,
    transaction: expectedTransaction,
  };
}

function validateProtocolRotationDescriptors(root, seal, options = {}) {
  const descriptors = seal.protocol_rotations;
  assertControl(
    Array.isArray(descriptors)
      && descriptors.length <= MAX_ROOT_PROTOCOL_ROTATIONS,
    'CORRUPT_STORE_PROTOCOL',
    'root protocol protocol_rotations 必须是受限数组',
  );
  const inventoryBefore = protocolRotationDirectoryInventory(root);
  const seen = new Set();
  const normalized = [];
  const receipts = [];
  for (const descriptor of descriptors) {
    assertControl(
      !seen.has(descriptor && descriptor.relative_path),
      'CORRUPT_STORE_PROTOCOL',
      'protocol rotation descriptor 重复',
    );
    const receipt = validateProtocolRotationReceipt(root, descriptor);
    seen.add(descriptor.relative_path);
    normalized.push({
      relative_path: descriptor.relative_path,
      sha256: descriptor.sha256,
    });
    receipts.push(receipt);
  }
  assertControl(
    canonicalJson(descriptors) === canonicalJson(normalized),
    'CORRUPT_STORE_PROTOCOL',
    'protocol_rotations 必须保持 append-only receipt 顺序',
  );
  const expectedNames = normalized.map(
    (descriptor) => path.posix.basename(descriptor.relative_path),
  );
  const pendingRequest =
    options.pendingProtocolRotationRequest || null;
  const pendingBefore = pendingRequest === null
    ? null
    : exactPendingProtocolRotationInventory(
      root,
      seal,
      inventoryBefore,
      expectedNames,
      pendingRequest,
    );
  const permittedNames = pendingBefore === null
    ? expectedNames
    : [
      ...expectedNames,
      path.posix.basename(pendingBefore.descriptor.relative_path),
    ];
  assertProtocolRotationInventory(inventoryBefore, permittedNames);
  const inventoryAfter = protocolRotationDirectoryInventory(root);
  assertControl(
    inventoryAfter.kind === inventoryBefore.kind,
    'CORRUPT_STORE_PROTOCOL',
    'protocol rotation directory 在 receipt validation 期间出现/消失',
  );
  const pendingAfter = pendingRequest === null
    ? null
    : exactPendingProtocolRotationInventory(
      root,
      seal,
      inventoryAfter,
      expectedNames,
      pendingRequest,
    );
  assertControl(
    canonicalJson(pendingAfter) === canonicalJson(pendingBefore),
    'CORRUPT_STORE_PROTOCOL',
    'unsealed protocol rotation receipt 在 validation 期间漂移',
  );
  assertProtocolRotationInventory(
    inventoryAfter,
    permittedNames,
    inventoryBefore.stat,
  );
  const migrationArtifactsSha256 = hashObject(seal.migration_artifacts);
  for (let index = 0; index < receipts.length; index += 1) {
    const receipt = receipts[index];
    const prefix = normalized.slice(0, index);
    const predecessor = receipt.predecessor_protocol;
    const predecessorUnsigned = {
      schema_version: predecessor.schema_version,
      controller_decoder_version:
        predecessor.controller_decoder_version,
      controller_decoder_sha256:
        predecessor.controller_decoder_sha256,
      lock_protocol_version: predecessor.lock_protocol_version,
      migration_source_state_vector_sha256:
        seal.migration_source_state_vector_sha256,
      migration_artifacts: seal.migration_artifacts,
      ...(predecessor.schema_version === ROOT_PROTOCOL_SCHEMA_VERSION
        ? { protocol_rotations: prefix }
        : {}),
    };
    assertControl(
      receipt.migration_artifacts_sha256 === migrationArtifactsSha256
        && hashObject(predecessorUnsigned)
          === predecessor.seal_sha256,
      'CORRUPT_STORE_PROTOCOL',
      `protocol rotation chain predecessor 不匹配: ${receipt.rotation_id}`,
    );
    if (index > 0) {
      assertControl(
        canonicalJson(receipts[index - 1].successor_protocol)
          === canonicalJson({
            schema_version: predecessor.schema_version,
            controller_decoder_version:
              predecessor.controller_decoder_version,
            controller_decoder_sha256:
              predecessor.controller_decoder_sha256,
            lock_protocol_version: predecessor.lock_protocol_version,
          }),
        'CORRUPT_STORE_PROTOCOL',
        `protocol rotation chain compatibility 断裂: ${receipt.rotation_id}`,
      );
    } else {
      assertControl(
        [
          LEGACY_ROOT_PROTOCOL_SCHEMA_VERSION,
          ROOT_PROTOCOL_SCHEMA_VERSION,
        ].includes(predecessor.schema_version),
        'CORRUPT_STORE_PROTOCOL',
        '首个 protocol rotation predecessor schema 非法',
      );
    }
  }
  if (receipts.length > 0) {
    assertControl(
      canonicalJson(receipts[receipts.length - 1].successor_protocol)
        === canonicalJson(protocolCompatibilityFromSeal(seal)),
      'CORRUPT_STORE_PROTOCOL',
      'root protocol compatibility 未绑定最后一个 rotation receipt',
    );
  }
  return {
    descriptors: normalized,
    receipts,
    pending_rotation: pendingBefore,
  };
}

function readRootProtocolSealSnapshot(root, options = {}) {
  const file = rootProtocolFile(root);
  try {
    fs.lstatSync(file);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return {
        protocol: null,
        pending_rotation: null,
      };
    }
    throw new ControlError(
      'CORRUPT_STORE_PROTOCOL',
      `root protocol seal pathname 无法读取: ${error.message}`,
    );
  }
  let seal;
  try {
    seal = JSON.parse(readProtocolAuthorityFile(
      root,
      file,
      MAX_ROOT_PROTOCOL_SEAL_BYTES,
      'root protocol seal',
      [ATOMIC_RESIDUAL_WRITE, ATOMIC_RESIDUAL_CREATE],
    ).toString('utf8'));
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError('CORRUPT_STORE_PROTOCOL', `root protocol seal 无法读取: ${error.message}`);
  }
  const legacy = seal
    && seal.schema_version === LEGACY_ROOT_PROTOCOL_SCHEMA_VERSION;
  const allowedKeys = [
    'schema_version',
    'controller_decoder_version',
    'controller_decoder_sha256',
    'lock_protocol_version',
    'migration_source_state_vector_sha256',
    'migration_artifacts',
    ...(legacy ? [] : ['protocol_rotations']),
    'seal_sha256',
  ];
  assertControl(
    seal
      && typeof seal === 'object'
      && !Array.isArray(seal)
      && [
        LEGACY_ROOT_PROTOCOL_SCHEMA_VERSION,
        ROOT_PROTOCOL_SCHEMA_VERSION,
      ].includes(seal.schema_version)
      && Object.keys(seal).length === allowedKeys.length
      && Object.keys(seal).every((key) => allowedKeys.includes(key)),
    'CORRUPT_STORE_PROTOCOL',
    'root protocol seal 字段非法',
  );
  const unsigned = { ...seal };
  delete unsigned.seal_sha256;
  assertControl(
    typeof seal.seal_sha256 === 'string'
      && hashObject(unsigned) === seal.seal_sha256,
    'CORRUPT_STORE_PROTOCOL',
    'root protocol seal hash 不匹配',
  );
  validateProtocolCompatibilityRecord(
    protocolCompatibilityFromSeal(seal),
    'root',
    { allowLegacySchema: true },
  );
  const migrationArtifacts = validateMigrationArtifactDescriptors(
    root,
    seal.migration_artifacts,
  );
  assertControl(
    (
      migrationArtifacts.length === 0
      && seal.migration_source_state_vector_sha256 === null
    )
      || (
        migrationArtifacts.length > 0
        && typeof seal.migration_source_state_vector_sha256 === 'string'
        && /^sha256:[0-9a-f]{64}$/.test(seal.migration_source_state_vector_sha256)
      ),
    'CORRUPT_STORE_PROTOCOL',
    'root protocol migration source vector 与 artifacts 不一致',
  );
  const rotations = legacy
    ? (
      options.pendingProtocolRotationRequest
        ? validateProtocolRotationDescriptors(
          root,
          { ...seal, protocol_rotations: [] },
          options,
        )
        : null
    )
    : validateProtocolRotationDescriptors(root, seal, options);
  return {
    protocol: seal,
    pending_rotation:
      rotations === null ? null : rotations.pending_rotation,
  };
}

function readRootProtocolSealWithOptions(root, options = {}) {
  return readRootProtocolSealSnapshot(root, options).protocol;
}

function readRootProtocolSealForRotation(root, requestOptions) {
  const snapshot = readRootProtocolSealSnapshot(root, {
    pendingProtocolRotationRequest: requestOptions,
  });
  return {
    ...snapshot,
    sealed_rotation:
      snapshot.protocol !== null && snapshot.pending_rotation === null
        ? exactSealedProtocolRotationRecovery(
          root,
          snapshot.protocol,
          requestOptions,
        )
        : null,
  };
}

function readRootProtocolSeal(root) {
  return readRootProtocolSealWithOptions(root);
}

function readProtocolSealedMigrationArtifact(root, relativePath) {
  const protocol = readRootProtocolSeal(root);
  if (protocol === null) return null;
  const descriptor = protocol.migration_artifacts.find(
    (candidate) => candidate.relative_path === relativePath,
  );
  if (!descriptor) return null;
  const file = path.join(root, relativePath);
  let stat;
  let body;
  try {
    stat = fs.lstatSync(file);
    body = fs.readFileSync(file);
  } catch (error) {
    throw new ControlError(
      'CORRUPT_STORE_PROTOCOL',
      `protocol-sealed migration artifact 无法读取: ${relativePath}: ${error.message}`,
    );
  }
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && `sha256:${sha256(body)}` === descriptor.sha256,
    'CORRUPT_STORE_PROTOCOL',
    `protocol-sealed migration artifact bytes 漂移: ${relativePath}`,
  );
  return {
    protocol: JSON.parse(JSON.stringify(protocol)),
    descriptor: { ...descriptor },
    body,
  };
}

function readProtocolSealedRotationReceipts(root) {
  const protocol = readRootProtocolSeal(root);
  if (
    protocol === null
      || protocol.schema_version !== ROOT_PROTOCOL_SCHEMA_VERSION
  ) {
    return [];
  }
  return protocol.protocol_rotations.map((descriptor) => ({
    descriptor: { ...descriptor },
    receipt: validateProtocolRotationReceipt(root, descriptor),
  }));
}

function readRootProtocol(root) {
  const seal = readRootProtocolSeal(root);
  if (seal === null) return null;
  const expectedCompatibility = rootProtocolCompatibility();
  assertControl(
    canonicalJson(protocolCompatibilityFromSeal(seal))
      === canonicalJson(expectedCompatibility),
    'STORE_PROTOCOL_UNSUPPORTED',
    `控制器 decoder/lock protocol 不兼容: 需要 decoder=${expectedCompatibility.controller_decoder_version}, lock=${expectedCompatibility.lock_protocol_version}`,
  );
  return seal;
}

function ensureRootProtocol(root, options = {}) {
  const existing = readRootProtocol(root);
  if (existing) {
    if (activeAtomicTransaction) {
      atomicCreate(
        rootProtocolFile(root),
        `${JSON.stringify(existing, null, 2)}\n`,
        options.atomicOptions || {},
      );
    }
    return readRootProtocol(root);
  }
  const expected = expectedRootProtocol(options);
  atomicCreate(
    rootProtocolFile(root),
    `${JSON.stringify(expected, null, 2)}\n`,
    options.atomicOptions || {},
  );
  const published = readRootProtocol(root);
  assertControl(
    canonicalJson(published) === canonicalJson(expected),
    'STORE_PROTOCOL_CONFLICT',
    'root protocol seal 在 no-replace publication 期间被不兼容 writer 抢占',
  );
  return published;
}

function rootGenerationFile(root) {
  return path.join(root, ROOT_GENERATION_FILE);
}

function readBoundedRootGenerationBytes(root) {
  const file = rootGenerationFile(root);
  const before = fs.lstatSync(file);
  assertControl(
    before.isFile()
      && !before.isSymbolicLink()
      && before.uid === process.getuid()
      && before.size <= MAX_ROOT_GENERATION_BYTES,
    'CORRUPT_STORE',
    'root generation seal 必须是 bounded current-uid regular file',
  );
  const descriptor = fs.openSync(
    file,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    return readBoundedOpenDescriptor(
      file,
      descriptor,
      before,
      MAX_ROOT_GENERATION_BYTES,
      'CORRUPT_STORE',
      'root generation seal',
    );
  } finally {
    fs.closeSync(descriptor);
  }
}

function readRootGenerationRecord(root) {
  const file = rootGenerationFile(root);
  if (!fs.existsSync(file)) {
    return {
      schema_version: LEGACY_ROOT_GENERATION_SCHEMA_VERSION,
      generation: 0,
      active_transaction: null,
      pre_write_vector_sha256: null,
      legacy: true,
    };
  }
  let seal;
  try {
    seal = JSON.parse(readBoundedRootGenerationBytes(root).toString('utf8'));
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError('CORRUPT_STORE', `root generation seal 无法读取: ${error.message}`);
  }
  const legacy = seal && seal.schema_version
    === LEGACY_ROOT_GENERATION_SCHEMA_VERSION;
  const transactionOnly = seal && seal.schema_version
    === TRANSACTION_ROOT_GENERATION_SCHEMA_VERSION;
  const allowedKeys = legacy
    ? ['schema_version', 'generation', 'updated_at', 'seal_sha256']
    : transactionOnly
      ? [
        'schema_version',
        'generation',
        'active_transaction',
        'updated_at',
        'seal_sha256',
      ]
      : [
      'schema_version',
      'generation',
      'active_transaction',
      'pre_write_vector_sha256',
      'updated_at',
      'seal_sha256',
      ];
  assertControl(
    seal
      && typeof seal === 'object'
      && !Array.isArray(seal)
      && Object.keys(seal).length === allowedKeys.length
      && Object.keys(seal).every((key) => allowedKeys.includes(key))
      && (
        legacy
          || transactionOnly
          || seal.schema_version === ROOT_GENERATION_SCHEMA_VERSION
      )
      && Number.isSafeInteger(seal.generation)
      && seal.generation >= 0
      && typeof seal.updated_at === 'string'
      && Number.isFinite(Date.parse(seal.updated_at))
      && typeof seal.seal_sha256 === 'string',
    'CORRUPT_STORE',
    'root generation seal 格式非法',
  );
  const unsigned = { ...seal };
  delete unsigned.seal_sha256;
  assertControl(
    hashObject(unsigned) === seal.seal_sha256,
    'CORRUPT_STORE',
    'root generation seal hash 不匹配',
  );
  if (legacy) {
    return {
      ...seal,
      active_transaction: null,
      pre_write_vector_sha256: null,
      legacy: true,
    };
  }
  assertControl(
    seal.generation % 2 === 0
      ? seal.active_transaction === null
      : seal.active_transaction !== null,
    'CORRUPT_STORE',
    'generation v2 even/odd active_transaction 不变量破坏',
  );
  if (!transactionOnly) {
    assertControl(
      seal.generation % 2 === 0
        ? seal.pre_write_vector_sha256 === null
        : (
          typeof seal.pre_write_vector_sha256 === 'string'
            && /^sha256:[0-9a-f]{64}$/.test(
              seal.pre_write_vector_sha256,
            )
        ),
      'CORRUPT_STORE',
      'generation v3 even/odd pre_write_vector 不变量破坏',
    );
  }
  return {
    ...seal,
    active_transaction: seal.active_transaction === null
      ? null
      : validateTransactionKey(seal.active_transaction),
    pre_write_vector_sha256: transactionOnly
      ? null
      : seal.pre_write_vector_sha256,
    legacy: false,
  };
}

function readRootGeneration(root) {
  return readRootGenerationRecord(root).generation;
}

function sealedRootGenerationValue(
  generation,
  activeTransaction,
  preWriteVectorSha256,
  schemaVersion,
  updatedAt,
) {
  const unsigned = {
    schema_version: schemaVersion,
    generation,
    active_transaction: activeTransaction,
    ...(schemaVersion === ROOT_GENERATION_SCHEMA_VERSION
      ? { pre_write_vector_sha256: preWriteVectorSha256 }
      : {}),
    updated_at: updatedAt,
  };
  return {
    ...unsigned,
    seal_sha256: hashObject(unsigned),
  };
}

function writeRootGeneration(
  root,
  generation,
  activeTransaction,
  preWriteVectorSha256 = null,
  schemaVersion = ROOT_GENERATION_SCHEMA_VERSION,
  updatedAt = nowIso(),
  atomicOptions = {},
) {
  assertControl(
    Number.isSafeInteger(generation) && generation >= 0,
    'STORE_GENERATION_EXHAUSTED',
    'root generation 超出安全整数范围',
  );
  const transaction = activeTransaction === null
    ? null
    : validateTransactionKey(activeTransaction);
  assertControl(
    generation % 2 === 0
      ? transaction === null
      : transaction !== null,
    'CORRUPT_STORE',
    '写 generation 时 even 必须清空、odd 必须绑定 transaction',
  );
  assertControl(
    [
      TRANSACTION_ROOT_GENERATION_SCHEMA_VERSION,
      ROOT_GENERATION_SCHEMA_VERSION,
    ].includes(schemaVersion),
    'CORRUPT_STORE',
    `不支持写 generation schema v${schemaVersion}`,
  );
  assertControl(
    schemaVersion === TRANSACTION_ROOT_GENERATION_SCHEMA_VERSION
      ? preWriteVectorSha256 === null
      : (
        generation % 2 === 0
          ? preWriteVectorSha256 === null
          : (
            typeof preWriteVectorSha256 === 'string'
              && /^sha256:[0-9a-f]{64}$/.test(preWriteVectorSha256)
          )
      ),
    'CORRUPT_STORE',
    'generation v3 odd 必须绑定 pristine pre-write vector，even 必须清空',
  );
  assertControl(
    typeof updatedAt === 'string' && Number.isFinite(Date.parse(updatedAt)),
    'CORRUPT_STORE',
    'generation updated_at 必须是合法时间',
  );
  atomicWriteJson(
    rootGenerationFile(root),
    sealedRootGenerationValue(
      generation,
      transaction,
      preWriteVectorSha256,
      schemaVersion,
      updatedAt,
    ),
    atomicOptions,
  );
}

function beginRootWrite(
  root,
  transactionKey = null,
  preWriteVectorSha256 = null,
  transactionStartedAt = null,
) {
  const current = readRootGenerationRecord(root);
  assertControl(
    current.generation % 2 === 0 || !current.legacy,
    'AUDITED_REPAIR_ONLY',
    'legacy v1 odd generation 没有 transaction binding；只能走 audited repair',
  );
  assertControl(
    current.generation <= Number.MAX_SAFE_INTEGER - 3,
    'STORE_GENERATION_EXHAUSTED',
    'root generation 已耗尽',
  );
  let activeTransaction;
  let activePreWriteVector = null;
  let schemaVersion = ROOT_GENERATION_SCHEMA_VERSION;
  if (current.generation % 2 === 0) {
    activeTransaction = validateTransactionKey(transactionKey);
    assertControl(
      typeof preWriteVectorSha256 === 'string'
        && /^sha256:[0-9a-f]{64}$/.test(preWriteVectorSha256),
      'PRISTINE_VECTOR_REQUIRED',
      'fresh writer 必须绑定 strict pre-write payload vector',
    );
    activePreWriteVector = preWriteVectorSha256;
    transactionStartedAt = transactionStartedAt || nowIso();
    assertControl(
      typeof transactionStartedAt === 'string'
        && Number.isFinite(Date.parse(transactionStartedAt)),
      'CORRUPT_STORE',
      'fresh writer transaction_started_at 非法',
    );
  } else {
    assertControl(current.active_transaction, 'CORRUPT_STORE', 'odd generation 缺 transaction binding');
    activeTransaction = current.active_transaction;
    activePreWriteVector = current.pre_write_vector_sha256;
    schemaVersion = current.schema_version;
    transactionStartedAt = current.updated_at;
    if (transactionKey !== null) {
      const requested = validateTransactionKey(transactionKey);
      assertControl(
        requested.key_sha256 === activeTransaction.key_sha256,
        'STORE_TRANSACTION_MISMATCH',
        'odd generation transaction key 不匹配',
      );
    }
  }
  const generation = current.generation % 2 === 0
    ? current.generation + 1
    : current.generation + 2;
  withAtomicTransaction(root, activeTransaction, () => {
    writeRootGeneration(
      root,
      generation,
      activeTransaction,
      activePreWriteVector,
      schemaVersion,
      transactionStartedAt,
      {
        fault_namespace: 'GENERATION_BEGIN',
        stable_time_milliseconds: Date.parse(transactionStartedAt),
      },
    );
  });
  return {
    schema_version: schemaVersion,
    generation,
    active_transaction: activeTransaction,
    pre_write_vector_sha256: activePreWriteVector,
    transaction_started_at: transactionStartedAt,
  };
}

function completeRootWrite(root, started) {
  assertControl(
    started
      && Number.isSafeInteger(started.generation)
      && started.generation % 2 === 1
      && started.generation < Number.MAX_SAFE_INTEGER
      && started.active_transaction
      && [
        TRANSACTION_ROOT_GENERATION_SCHEMA_VERSION,
        ROOT_GENERATION_SCHEMA_VERSION,
      ].includes(started.schema_version),
    'CORRUPT_STORE',
    'writer generation 必须是奇数',
  );
  const current = readRootGenerationRecord(root);
  assertControl(
    !current.legacy
      && current.generation === started.generation
      && current.active_transaction
      && current.active_transaction.key_sha256
        === started.active_transaction.key_sha256
      && current.schema_version === started.schema_version
      && current.pre_write_vector_sha256
        === started.pre_write_vector_sha256
      && typeof started.transaction_started_at === 'string'
      && current.updated_at === started.transaction_started_at,
    'STORE_GENERATION_CHANGED',
    `writer generation/transaction 从 ${started.generation} 漂移到 ${current.generation}`,
  );
  withAtomicTransaction(root, started.active_transaction, () => {
    const generationResidual = atomicGenerationResidual(
      root,
      started.active_transaction,
    );
    const completedAt = generationResidual.timestamp || nowIso();
    writeRootGeneration(
      root,
      started.generation + 1,
      null,
      null,
      ROOT_GENERATION_SCHEMA_VERSION,
      completedAt,
      {
        fault_namespace: 'GENERATION_COMPLETE',
        stable_time_milliseconds: Date.parse(completedAt),
      },
    );
  });
}

function normalizeOddGenerationAtomicTransport(
  root,
  current,
  requestedTransaction = null,
) {
  if (current.generation % 2 === 0) return current;
  assertControl(
    requestedTransaction === null
      || validateTransactionKey(requestedTransaction).key_sha256
        === current.active_transaction.key_sha256,
    'STORE_TRANSACTION_MISMATCH',
    'odd generation 绑定了不同 transaction；requested transaction key 不匹配',
  );
  let inspection = inspectAtomicTransport(
    root,
    atomicTransactionHex(current.active_transaction),
  );
  const generationRelative = atomicTargetRelative(
    root,
    rootGenerationFile(root),
  );
  assertControl(
    inspection.transactionDirectory === null
      || requestedTransaction !== null,
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'odd generation atomic residual 尚未绑定 requested transaction',
  );
  if (
    inspection.residual === null
      && inspection.publication_lineage_claims.length > 0
  ) {
    inspection = normalizeAtomicLineageActiveDirectoryTails(
      root,
      inspection,
      { preserveUnboundPendingMirror: true },
    );
  }
  if (
    !inspection.residual
      || inspection.residual.target !== rootGenerationFile(root)
  ) {
    return current;
  }
  const residual = inspection.residual;
  assertControl(
    residual.operation === ATOMIC_RESIDUAL_WRITE
      && Number.isSafeInteger(residual.stable_time_milliseconds),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'odd generation transport 缺 exact WRITE/timestamp binding',
  );
  if (residual.canonical_is_payload) {
    cleanupExactPublishedAtomicResidual(inspection);
    return current;
  }
  const stableAt = new Date(
    residual.stable_time_milliseconds,
  ).toISOString();
  const fenceValue = sealedRootGenerationValue(
    current.generation + 2,
    current.active_transaction,
    current.pre_write_vector_sha256,
    current.schema_version,
    current.updated_at,
  );
  const completeValue = sealedRootGenerationValue(
    current.generation + 1,
    null,
    null,
    ROOT_GENERATION_SCHEMA_VERSION,
    stableAt,
  );
  const fenceBody = Buffer.from(`${JSON.stringify(fenceValue, null, 2)}\n`);
  const completeBody = Buffer.from(
    `${JSON.stringify(completeValue, null, 2)}\n`,
  );
  let value;
  let namespace;
  let timestamp;
  if (`sha256:${sha256(fenceBody)}` === residual.payload_sha256) {
    assertControl(
      stableAt === current.updated_at,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'generation fence residual 改写了 immutable transaction_started_at',
    );
    value = fenceValue;
    namespace = 'GENERATION_BEGIN';
    timestamp = Date.parse(current.updated_at);
  } else {
    assertControl(
      `sha256:${sha256(completeBody)}` === residual.payload_sha256,
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'odd generation temp 既不是 exact fence 也不是 exact completion',
    );
    value = completeValue;
    namespace = 'GENERATION_COMPLETE';
    timestamp = residual.stable_time_milliseconds;
  }
  withAtomicTransaction(root, current.active_transaction, () => {
    atomicWriteJson(rootGenerationFile(root), value, {
      fault_namespace: namespace,
      stable_time_milliseconds: timestamp,
    });
  });
  return readRootGenerationRecord(root);
}

function runLockTestHook(lockDir, hook, label) {
  if (typeof hook !== 'function') return;
  const temporaryRoot = trustedTemporaryRoot();
  const root = fs.realpathSync(path.dirname(lockDir));
  assertControl(
    process.env.GOAL_CONTROL_TEST_MODE === '1'
      && root !== temporaryRoot
      && root.startsWith(`${temporaryRoot}${path.sep}`),
    'TEST_MODE_FORBIDDEN',
    `${label} hook 只允许隔离测试目录`,
  );
  hook();
}

function ownedDirectoryProtocolCompatibility(protocolBinding = {}) {
  return protocolBinding.protocolCompatibility || rootProtocolCompatibility();
}

function ownedDirectoryProtocolReader(protocolBinding = {}) {
  return protocolBinding.readProtocol || readRootProtocol;
}

function createOwnedDirectoryRecord(kind, protocolBinding = {}) {
  const nonce = typeof protocolBinding.nonceForKind === 'function'
    ? protocolBinding.nonceForKind(kind)
    : randomId(kind === WRITER_LOCK_KIND ? 'writer' : 'reaper');
  assertControl(
    typeof nonce === 'string'
      && /^[A-Za-z0-9-]{10,100}$/.test(nonce),
    'LOCK_OWNER_NONCE_INVALID',
    `${kind} owner nonce 非法`,
  );
  const unsigned = {
    schema_version: LOCK_OWNER_SCHEMA_VERSION,
    lock_protocol_version: LOCK_PROTOCOL_VERSION,
    kind,
    pid: process.pid,
    process_start_token: CURRENT_PROCESS_START_TOKEN,
    nonce,
    acquired_at: nowIso(),
    root_protocol_compatibility_sha256: hashObject(
      ownedDirectoryProtocolCompatibility(protocolBinding),
    ),
  };
  return {
    ...unsigned,
    owner_sha256: hashObject(unsigned),
  };
}

function validateOwnedDirectoryRecord(
  owner,
  expectedKind,
  protocolBinding = {},
) {
  assertControl(
    owner
      && typeof owner === 'object'
      && !Array.isArray(owner)
      && Object.keys(owner).length === 9
      && Object.keys(owner).every((key) => (
        [
          'schema_version',
          'lock_protocol_version',
          'kind',
          'pid',
          'process_start_token',
          'nonce',
          'acquired_at',
          'root_protocol_compatibility_sha256',
          'owner_sha256',
        ].includes(key)
      )),
    'CORRUPT_LOCK_OWNER',
    `${expectedKind} owner 字段非法`,
  );
  assertControl(
    owner.schema_version === LOCK_OWNER_SCHEMA_VERSION
      && owner.lock_protocol_version === LOCK_PROTOCOL_VERSION
      && owner.kind === expectedKind
      && Number.isSafeInteger(owner.pid)
      && owner.pid > 0
      && typeof owner.process_start_token === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(owner.process_start_token)
      && typeof owner.nonce === 'string'
      && /^[A-Za-z0-9-]{10,100}$/.test(owner.nonce)
      && typeof owner.acquired_at === 'string'
      && Number.isFinite(Date.parse(owner.acquired_at))
      && owner.root_protocol_compatibility_sha256 === hashObject(
        ownedDirectoryProtocolCompatibility(protocolBinding),
      )
      && typeof owner.owner_sha256 === 'string',
    'LOCK_PROTOCOL_MISMATCH',
    `${expectedKind} owner 与当前 decoder/lock protocol 不兼容`,
  );
  const unsigned = { ...owner };
  delete unsigned.owner_sha256;
  assertControl(
    hashObject(unsigned) === owner.owner_sha256,
    'CORRUPT_LOCK_OWNER',
    `${expectedKind} owner seal hash 不匹配`,
  );
  return owner;
}

function observeOwnedDirectory(
  lockDir,
  expectedKind,
  rootProtocol = null,
  protocolBinding = {},
) {
  let entryStat;
  try {
    entryStat = fs.lstatSync(lockDir);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  let backingPath = null;
  if (entryStat.isSymbolicLink()) {
    const target = fs.readlinkSync(lockDir);
    const expectedPrefix = expectedKind === WRITER_LOCK_KIND
      ? '.lock.owner.'
      : '.lock.reap.owner.';
    const resolved = path.resolve(path.dirname(lockDir), target);
    assertControl(
      !path.isAbsolute(target)
        && path.dirname(target) === '.'
        && path.dirname(resolved) === path.dirname(lockDir)
        && path.basename(target).startsWith(expectedPrefix),
      'CORRUPT_LOCK_OWNER',
      `${lockDir} backing symlink 越界或命名非法`,
    );
    backingPath = resolved;
  }
  let stat;
  try {
    stat = fs.statSync(lockDir);
  } catch (error) {
    throw new ControlError('CORRUPT_LOCK_OWNER', `${lockDir} backing 无法读取: ${error.message}`);
  }
  assertControl(stat.isDirectory(), 'CORRUPT_LOCK_OWNER', `${lockDir} 不是目录`);

  const ownerFile = path.join(lockDir, LOCK_OWNER_FILE);
  let raw = null;
  try {
    raw = fs.readFileSync(ownerFile, 'utf8');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  let owner = null;
  if (raw !== null) {
    try {
      owner = JSON.parse(raw);
    } catch {
      owner = null;
    }
  }

  const looksVersioned = owner
    && typeof owner === 'object'
    && !Array.isArray(owner)
    && (
      Object.prototype.hasOwnProperty.call(owner, 'schema_version')
      || Object.prototype.hasOwnProperty.call(owner, 'lock_protocol_version')
      || Object.prototype.hasOwnProperty.call(owner, 'owner_sha256')
      || Object.prototype.hasOwnProperty.call(owner, 'nonce')
    );
  if (looksVersioned) {
    return {
      format: 'v2',
      owner: validateOwnedDirectoryRecord(
        owner,
        expectedKind,
        protocolBinding,
      ),
      entry_dev: String(entryStat.dev),
      entry_ino: String(entryStat.ino),
      target_dev: String(stat.dev),
      target_ino: String(stat.ino),
      backing_path: backingPath,
    };
  }

  assertControl(
    rootProtocol === null,
    'LOCK_PROTOCOL_MISMATCH',
    `${lockDir} 使用无版本 owner；root 已 seal，禁止按旧 stale-lock 规则回收`,
  );
  return {
    format: 'legacy',
    owner,
    raw_sha256: raw === null ? null : `sha256:${sha256(raw)}`,
    entry_dev: String(entryStat.dev),
    entry_ino: String(entryStat.ino),
    target_dev: String(stat.dev),
    target_ino: String(stat.ino),
    backing_path: backingPath,
    mtime_ms: stat.mtimeMs,
  };
}

function sameOwnedDirectory(left, right) {
  if (!left || !right || left.format !== right.format) return false;
  if (left.format === 'v2') {
    return left.owner.nonce === right.owner.nonce
      && left.owner.owner_sha256 === right.owner.owner_sha256
      && left.entry_dev === right.entry_dev
      && left.entry_ino === right.entry_ino
      && left.target_dev === right.target_dev
      && left.target_ino === right.target_ino
      && left.backing_path === right.backing_path;
  }
  return left.raw_sha256 === right.raw_sha256
    && left.entry_dev === right.entry_dev
    && left.entry_ino === right.entry_ino
    && left.target_dev === right.target_dev
    && left.target_ino === right.target_ino
    && left.backing_path === right.backing_path;
}

function sameOwnedTarget(left, right) {
  if (!left || !right || left.format !== right.format) return false;
  const sameOwner = left.format === 'v2'
    ? left.owner.nonce === right.owner.nonce
      && left.owner.owner_sha256 === right.owner.owner_sha256
    : left.raw_sha256 === right.raw_sha256;
  return sameOwner
    && left.target_dev === right.target_dev
    && left.target_ino === right.target_ino;
}

function ownedDirectoryIsStale(observation, staleMilliseconds) {
  if (!observation) return false;
  if (observation.format === 'v2') {
    const age = Date.now() - Date.parse(observation.owner.acquired_at);
    const pidAlive = processAlive(observation.owner.pid);
    const currentStartToken = pidAlive
      ? processStartToken(observation.owner.pid)
      : null;
    const sameProcessStillOwnsPid = pidAlive
      && (
        currentStartToken === null
        || currentStartToken === observation.owner.process_start_token
      );
    // A v2 owner is bound to both PID and process-start token. Once that
    // exact process is gone (or the PID has been reused), waiting for a stale
    // TTL only turns a recoverable child exit into a multi-second deadlock.
    return Number.isFinite(age) && !sameProcessStillOwnsPid;
  }
  if (
    observation.owner
    && typeof observation.owner === 'object'
    && !Array.isArray(observation.owner)
  ) {
    const age = Date.now() - Date.parse(observation.owner.acquired_at || '');
    if (
      Number.isFinite(age)
      && Number.isSafeInteger(observation.owner.pid)
      && observation.owner.pid > 0
    ) {
      return age >= staleMilliseconds && !processAlive(observation.owner.pid);
    }
  }
  // An empty/partial legacy lock is indistinguishable from an old writer
  // paused between mkdir(".lock") and owner.json. Never guess from directory
  // mtime: require manual repair rather than overlap a possibly live writer.
  return false;
}

function observeOwnedDirectoryContention(
  lockDir,
  expectedKind,
  protocolBinding = {},
) {
  let before;
  try {
    before = fs.lstatSync(lockDir);
  } catch (error) {
    if (error.code === 'ENOENT') return { kind: 'ABSENT' };
    return { kind: 'INVALID', error };
  }
  let observation;
  try {
    observation = observeOwnedDirectory(
      lockDir,
      expectedKind,
      null,
      protocolBinding,
    );
  } catch (error) {
    let after;
    try {
      after = fs.lstatSync(lockDir);
    } catch (afterError) {
      if (afterError.code === 'ENOENT') return { kind: 'TRANSITION' };
      return { kind: 'INVALID', error };
    }
    if (!sameFileIdentity(before, after)) {
      return { kind: 'TRANSITION' };
    }
    return { kind: 'INVALID', error };
  }
  let after;
  try {
    after = fs.lstatSync(lockDir);
  } catch (error) {
    if (error.code === 'ENOENT') return { kind: 'TRANSITION' };
    return { kind: 'INVALID', error };
  }
  if (
    observation === null
      || !sameFileIdentity(before, after)
  ) {
    return { kind: 'TRANSITION' };
  }
  if (observation.format !== 'v2') {
    return { kind: 'LEGACY', observation };
  }
  return ownedDirectoryIsStale(observation, 0)
    ? { kind: 'DEAD_V2', observation }
    : { kind: 'LIVE_V2', observation };
}

function publishOwnedDirectory(
  root,
  lockDir,
  kind,
  afterOwnerSealed,
  afterBackingPublished = null,
  afterLockPublished = null,
  protocolBinding = {},
) {
  const owner = createOwnedDirectoryRecord(kind, protocolBinding);
  const pending = path.join(
    root,
    `${path.basename(lockDir)}.pending.${process.pid}.${owner.nonce}`,
  );
  const backing = `${lockDir}.owner.${owner.nonce}`;
  let backingPublished = false;
  let lockPublished = false;
  fs.mkdirSync(pending, { mode: 0o700 });
  try {
    atomicWriteJson(path.join(pending, LOCK_OWNER_FILE), owner);
    runLockTestHook(lockDir, afterOwnerSealed, `${kind} publish-window`);
    fs.renameSync(pending, backing);
    backingPublished = true;
    fsyncDirectory(root);
    runLockTestHook(lockDir, afterBackingPublished, `${kind} backing-window`);
    try {
      // rename(2) may replace an existing empty directory on macOS. Publishing
      // a relative directory symlink is a single no-replace syscall instead,
      // while legacy code can still read ".lock/owner.json".
      fs.symlinkSync(path.basename(backing), lockDir, 'dir');
      lockPublished = true;
      fsyncDirectory(root);
      runLockTestHook(lockDir, afterLockPublished, `${kind} lock-published`);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      return null;
    }
  } finally {
    fs.rmSync(pending, { recursive: true, force: true });
    if (backingPublished && !lockPublished) {
      fs.rmSync(backing, { recursive: true, force: true });
    }
  }
  const published = observeOwnedDirectory(
    lockDir,
    kind,
    ownedDirectoryProtocolReader(protocolBinding)(root),
    protocolBinding,
  );
  assertControl(
    published
      && published.format === 'v2'
      && published.owner.nonce === owner.nonce
      && published.owner.owner_sha256 === owner.owner_sha256,
    'LOCK_OWNERSHIP_LOST',
    `${kind} owner 在原子发布后已被替换`,
  );
  return owner;
}

function assertOwnedDirectory(
  lockDir,
  kind,
  owner,
  protocolBinding = {},
) {
  const observed = observeOwnedDirectory(
    lockDir,
    kind,
    ownedDirectoryProtocolReader(protocolBinding)(path.dirname(lockDir)),
    protocolBinding,
  );
  assertControl(
    observed
      && observed.format === 'v2'
      && observed.owner.nonce === owner.nonce
      && observed.owner.owner_sha256 === owner.owner_sha256,
    'LOCK_OWNERSHIP_LOST',
    `${kind} owner nonce 已变化，拒绝操作同名路径`,
  );
  return observed;
}

function restoreClaimedDirectory(lockDir, quarantine) {
  if (fs.existsSync(lockDir)) return;
  try {
    fs.renameSync(quarantine, lockDir);
  } catch {
    // Preserve the mismatched owner in quarantine rather than deleting it.
  }
}

function validateClaimedBacking(
  quarantine,
  kind,
  moved,
  protocolBinding = {},
) {
  if (moved.backing_path === null) return;
  const direct = observeOwnedDirectory(
    moved.backing_path,
    kind,
    moved.format === 'legacy'
      ? null
      : ownedDirectoryProtocolReader(protocolBinding)(
        path.dirname(quarantine),
      ),
    protocolBinding,
  );
  assertControl(
    direct && direct.backing_path === null && sameOwnedTarget(moved, direct),
    'LOCK_OWNERSHIP_LOST',
    `${kind} backing owner nonce 已变化，拒绝删除`,
  );
}

function deleteClaimedDirectory(quarantine, moved) {
  if (moved.backing_path === null) {
    fs.rmSync(quarantine, { recursive: true, force: true });
    return;
  }
  fs.rmSync(quarantine, { force: true });
  fs.rmSync(moved.backing_path, { recursive: true, force: true });
}

function releaseOwnedDirectory(
  lockDir,
  kind,
  owner,
  afterClaimed = null,
  protocolBinding = {},
) {
  const observed = assertOwnedDirectory(
    lockDir,
    kind,
    owner,
    protocolBinding,
  );
  const quarantine = `${lockDir}.release.${owner.nonce}`;
  try {
    fs.renameSync(lockDir, quarantine);
  } catch (error) {
    throw new ControlError('LOCK_OWNERSHIP_LOST', `${kind} release 无法 claim owner: ${error.message}`);
  }
  runLockTestHook(lockDir, afterClaimed, `${kind} release-claim`);
  let moved;
  try {
    moved = observeOwnedDirectory(
      quarantine,
      kind,
      ownedDirectoryProtocolReader(protocolBinding)(path.dirname(lockDir)),
      protocolBinding,
    );
  } catch (error) {
    restoreClaimedDirectory(lockDir, quarantine);
    throw error;
  }
  if (!sameOwnedDirectory(observed, moved)) {
    restoreClaimedDirectory(lockDir, quarantine);
    throw new ControlError('LOCK_OWNERSHIP_LOST', `${kind} release 发生 pathname ABA，拒绝删除`);
  }
  try {
    validateClaimedBacking(quarantine, kind, moved, protocolBinding);
  } catch (error) {
    restoreClaimedDirectory(lockDir, quarantine);
    throw error;
  }
  deleteClaimedDirectory(quarantine, moved);
  fsyncDirectory(path.dirname(lockDir));
}

function claimAndDeleteObservedDirectory(
  lockDir,
  kind,
  observed,
  suffix,
  protocolBinding = {},
) {
  const quarantine = `${lockDir}.${suffix}.${process.pid}.${randomId('claim')}`;
  try {
    fs.renameSync(lockDir, quarantine);
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
  let moved;
  try {
    moved = observeOwnedDirectory(
      quarantine,
      kind,
      observed.format === 'legacy'
        ? null
        : ownedDirectoryProtocolReader(protocolBinding)(
          path.dirname(lockDir),
        ),
      protocolBinding,
    );
  } catch (error) {
    restoreClaimedDirectory(lockDir, quarantine);
    throw error;
  }
  if (!sameOwnedDirectory(observed, moved)) {
    restoreClaimedDirectory(lockDir, quarantine);
    throw new ControlError('LOCK_OWNERSHIP_LOST', `${kind} stale claim 发生 pathname ABA，拒绝删除`);
  }
  try {
    validateClaimedBacking(quarantine, kind, moved, protocolBinding);
  } catch (error) {
    restoreClaimedDirectory(lockDir, quarantine);
    throw error;
  }
  deleteClaimedDirectory(quarantine, moved);
  fsyncDirectory(path.dirname(lockDir));
  return true;
}

function tryRecoverStaleReaper(
  root,
  reaperMutex,
  staleMilliseconds,
  protocolBinding = {},
) {
  const observed = observeOwnedDirectory(
    reaperMutex,
    REAPER_LOCK_KIND,
    ownedDirectoryProtocolReader(protocolBinding)(root),
    protocolBinding,
  );
  if (!observed || !ownedDirectoryIsStale(observed, staleMilliseconds)) return false;
  if (
    typeof protocolBinding.canReapObserved === 'function'
      && !protocolBinding.canReapObserved(observed, REAPER_LOCK_KIND)
  ) {
    return false;
  }
  return claimAndDeleteObservedDirectory(
    reaperMutex,
    REAPER_LOCK_KIND,
    observed,
    'stale-reaper',
    protocolBinding,
  );
}

function tryReapStaleLock(root, lockDir, staleMilliseconds, options = {}) {
  const protocolBinding = options.protocolBinding || {};
  const reaperMutex = `${lockDir}.reap`;
  const reaperOwner = publishOwnedDirectory(
    root,
    reaperMutex,
    REAPER_LOCK_KIND,
    options.afterOwnerSealed,
    options.afterBackingPublished,
    null,
    protocolBinding,
  );
  if (!reaperOwner) return false;
  try {
    runLockTestHook(lockDir, options.afterMutexAcquired, 'stale-lock reaper');
    assertOwnedDirectory(
      reaperMutex,
      REAPER_LOCK_KIND,
      reaperOwner,
      protocolBinding,
    );

    const observed = observeOwnedDirectory(
      lockDir,
      WRITER_LOCK_KIND,
      ownedDirectoryProtocolReader(protocolBinding)(root),
      protocolBinding,
    );
    if (!observed || !ownedDirectoryIsStale(observed, staleMilliseconds)) return false;
    if (
      typeof protocolBinding.canReapObserved === 'function'
        && !protocolBinding.canReapObserved(
          observed,
          WRITER_LOCK_KIND,
        )
    ) {
      return false;
    }

    // A legacy owner observed before a concurrent root migration is not
    // authority to delete it after the decoder/lock protocol becomes sealed.
    const currentProtocol = ownedDirectoryProtocolReader(protocolBinding)(root);
    if (observed.format === 'legacy' && currentProtocol !== null) {
      throw new ControlError(
        'LOCK_PROTOCOL_MISMATCH',
        '旧 writer owner 与已 seal 的 root protocol 并存，拒绝自动回收',
      );
    }
    const entryGenerationRecord = readRootGenerationRecord(root);
    const entryGeneration = entryGenerationRecord.generation;
    const reaped = claimAndDeleteObservedDirectory(
      lockDir,
      WRITER_LOCK_KIND,
      observed,
      'stale-writer',
      protocolBinding,
    );
    if (!reaped) return false;
    assertControl(
      readRootGeneration(root) === entryGeneration,
      'STORE_GENERATION_CHANGED',
      `stale-lock reaper 期间 generation 从 ${entryGeneration} 漂移`,
    );
    // Reaping proves only that the lock owner died. It is not authority to
    // classify, consume, or fence any transaction residual. Preserve the
    // generation and strict transport byte-for-byte until a caller binds the
    // exact requested transaction inside withLock/adoption.
    return true;
  } finally {
    // If writer claim validation failed, our reaper mutex is still ours and
    // must be released. If the reaper itself was replaced, nonce validation
    // fails closed without deleting that replacement.
    releaseOwnedDirectory(
      reaperMutex,
      REAPER_LOCK_KIND,
      reaperOwner,
      null,
      protocolBinding,
    );
  }
}

function legacyRootHasControlState(root) {
  for (const name of ['goals', 'resources']) {
    const dir = path.join(root, name);
    try {
      if (fs.readdirSync(dir).length > 0) return true;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return false;
}

function lockArtifactKind(name) {
  if (name.startsWith('.lock.reap.')) return REAPER_LOCK_KIND;
  if (name.startsWith('.lock.')) return WRITER_LOCK_KIND;
  return null;
}

function referencedLockBackings(root) {
  const referenced = new Set();
  for (const name of fs.readdirSync(root)) {
    const candidate = path.join(root, name);
    try {
      if (!fs.lstatSync(candidate).isSymbolicLink()) continue;
      const resolved = path.resolve(root, fs.readlinkSync(candidate));
      if (path.dirname(resolved) === root) referenced.add(resolved);
    } catch {
      // A concurrent pathname change is re-evaluated on the next writer.
    }
  }
  return referenced;
}

function cleanupStaleLockArtifacts(
  root,
  staleMilliseconds,
  protocolBinding = {},
) {
  const cleanupPass = (symlinksOnly) => {
    const referenced = referencedLockBackings(root);
    for (const name of fs.readdirSync(root).sort()) {
      if (name === '.lock' || name === '.lock.reap') continue;
      const kind = lockArtifactKind(name);
      if (!kind) continue;
      const candidate = path.join(root, name);
      try {
        const stat = fs.lstatSync(candidate);
        if (stat.isSymbolicLink() !== symlinksOnly) continue;
        if (!stat.isSymbolicLink() && referenced.has(candidate)) continue;
        const observed = observeOwnedDirectory(
          candidate,
          kind,
          ownedDirectoryProtocolReader(protocolBinding)(root),
          protocolBinding,
        );
        if (
          !observed
          || observed.format !== 'v2'
          || !ownedDirectoryIsStale(observed, staleMilliseconds)
          || (
            typeof protocolBinding.canReapObserved === 'function'
              && !protocolBinding.canReapObserved(observed, kind)
          )
        ) {
          continue;
        }
        claimAndDeleteObservedDirectory(
          candidate,
          kind,
          observed,
          'orphan-gc',
          protocolBinding,
        );
      } catch {
        // Orphan cleanup is conservative and best-effort. Unknown protocol,
        // live owner, or a concurrent replacement is preserved for audit.
      }
    }
  };
  // Claim dangling release/stale symlinks first; deleting one may make its
  // unique backing eligible during the directory pass.
  cleanupPass(true);
  cleanupPass(false);
}

function acquireRootWriterLock(root, options = {}) {
  const protocolBinding = options.protocolBinding || {};
  const readProtocol = ownedDirectoryProtocolReader(protocolBinding);
  const lockDir = path.join(root, '.lock');
  const reaperMutex = `${lockDir}.reap`;
  const timeoutMilliseconds = options.timeoutMilliseconds
    ?? DEFAULT_CONTROL_CONTENTION_TIMEOUT_MILLISECONDS;
  const liveOwnerTimeoutMilliseconds = options.timeoutMilliseconds
    ?? DEFAULT_LIVE_V2_CONTENTION_TIMEOUT_MILLISECONDS;
  const staleMilliseconds = options.staleMilliseconds ?? 30000;
  ensureDir(root);
  cleanupStaleLockArtifacts(root, staleMilliseconds, protocolBinding);
  const started = Date.now();
  const liveOwnerSlots = new Set();
  let lockOwner;
  const hasLiveOwnerBudget = (slot, contention) => {
    if (contention.kind === 'LIVE_V2') {
      liveOwnerSlots.add(slot);
      return true;
    }
    return contention.kind === 'TRANSITION' && liveOwnerSlots.has(slot);
  };
  const waitForContention = (message, useLiveOwnerBudget = false) => {
    const waitTimeoutMilliseconds = useLiveOwnerBudget
      ? liveOwnerTimeoutMilliseconds
      : timeoutMilliseconds;
    if (Date.now() - started >= waitTimeoutMilliseconds) {
      throw new ControlError(
        'LOCK_TIMEOUT',
        `${message}超过 ${waitTimeoutMilliseconds}ms`,
      );
    }
    sleepSync(25);
  };
  while (true) {
    const reaperContention = observeOwnedDirectoryContention(
      reaperMutex,
      REAPER_LOCK_KIND,
      protocolBinding,
    );
    if (reaperContention.kind === 'INVALID') {
      throw reaperContention.error;
    }
    if (reaperContention.kind !== 'ABSENT') {
      if (
        !['LIVE_V2', 'TRANSITION'].includes(reaperContention.kind)
          && protocolBinding.allowStaleReaperRecovery !== false
          && tryRecoverStaleReaper(
            root,
            reaperMutex,
            staleMilliseconds,
            protocolBinding,
          )
      ) continue;
      waitForContention(
        '控制面 stale-lock reaper 等待',
        hasLiveOwnerBudget(reaperMutex, reaperContention),
      );
      continue;
    }
    const writerContention = observeOwnedDirectoryContention(
      lockDir,
      WRITER_LOCK_KIND,
      protocolBinding,
    );
    if (writerContention.kind === 'INVALID') {
      throw writerContention.error;
    }
    if (writerContention.kind !== 'ABSENT') {
      if (!['LIVE_V2', 'TRANSITION'].includes(writerContention.kind)) {
        readProtocol(root);
        if (tryReapStaleLock(root, lockDir, staleMilliseconds, {
            afterMutexAcquired: options.afterReaperMutexAcquired,
            afterOwnerSealed: options.afterReaperOwnerSealed,
            afterBackingPublished: options.afterReaperBackingPublished,
            protocolBinding,
          })) continue;
      }
      waitForContention(
        '控制面锁等待',
        hasLiveOwnerBudget(lockDir, writerContention),
      );
      continue;
    }
    readProtocol(root);
    const reaperAfterProtocol = observeOwnedDirectoryContention(
      reaperMutex,
      REAPER_LOCK_KIND,
      protocolBinding,
    );
    const writerAfterProtocol = observeOwnedDirectoryContention(
      lockDir,
      WRITER_LOCK_KIND,
      protocolBinding,
    );
    for (const contention of [
      reaperAfterProtocol,
      writerAfterProtocol,
    ]) {
      if (contention.kind === 'INVALID') throw contention.error;
    }
    if (
      reaperAfterProtocol.kind !== 'ABSENT'
        || writerAfterProtocol.kind !== 'ABSENT'
    ) {
      const reaperHasLiveOwnerBudget = hasLiveOwnerBudget(
        reaperMutex,
        reaperAfterProtocol,
      );
      const writerHasLiveOwnerBudget = hasLiveOwnerBudget(
        lockDir,
        writerAfterProtocol,
      );
      waitForContention(
        '控制面锁等待',
        reaperHasLiveOwnerBudget || writerHasLiveOwnerBudget,
      );
      continue;
    }
    lockOwner = publishOwnedDirectory(
      root,
      lockDir,
      WRITER_LOCK_KIND,
      options.afterLockOwnerSealed,
      options.afterLockBackingPublished,
      options.afterLockPublished,
      protocolBinding,
    );
    if (lockOwner) break;
    waitForContention('控制面锁等待');
  }
  cleanupStaleLockArtifacts(root, staleMilliseconds, protocolBinding);
  return { lockDir, lockOwner, protocolBinding };
}

/*
 * Odd recovery has two deliberately separate caller-specific authorities:
 *
 * - `authorizeOddRecovery` proves an exact durable witness (accepted event,
 *   sealed intent, receipt, etc.) and may resume a partially written payload.
 * - `authorizePristineOddRecovery` proves the exact caller/request is still
 *   authorized, but is accepted only when a v3 odd seal's pre-write payload
 *   vector still matches byte-for-byte. That proves the callback never made a
 *   control write; it does not prove anything about external side effects.
 * - For a v3 odd seal, `updated_at` is the immutable
 *   `transaction_started_at`. It is chosen before `beforeGeneration`, passed
 *   to the caller, preserved by stale fencing, and checked again at commit.
 *   Callers may use it only to prove authority at the original boundary; they
 *   must still revalidate time-aged resources and external inputs according to
 *   the operation-specific policy.
 *
 * Both default to false, require an exact transaction key, and are mechanically
 * checked for zero control mutation. Callers must never enable pristine
 * recovery when a callback can make an external semantic mutation before its
 * first durable control witness.
 */
function assertRequestedTransactionMatches(
  activeTransaction,
  requestedTransaction,
  options = {},
) {
  if (requestedTransaction === null) {
    throw new ControlError(
      'TRANSACTION_KEY_REQUIRED',
      'odd recovery 必须声明 recoverable transactionKey',
    );
  }
  if (
    requestedTransaction.key_sha256
      === activeTransaction.key_sha256
  ) {
    return;
  }
  const sameStableOperation = Boolean(
    requestedTransaction.kind === activeTransaction.kind
      && requestedTransaction.stable_operation_id_sha256
        === activeTransaction.stable_operation_id_sha256
      && hashObject(requestedTransaction.scope)
        === hashObject(activeTransaction.scope),
  );
  const code = sameStableOperation
      && typeof options.sameStableOperationMismatchCode === 'string'
    ? options.sameStableOperationMismatchCode
    : 'STORE_TRANSACTION_MISMATCH';
  const message = sameStableOperation
      && typeof options.sameStableOperationMismatchMessage === 'string'
    ? options.sameStableOperationMismatchMessage
    : '控制面 odd generation 绑定了不同 transaction';
  throw new ControlError(code, message, {
    active_transaction: {
      kind: activeTransaction.kind,
      scope: activeTransaction.scope,
      stable_operation_id_sha256:
        activeTransaction.stable_operation_id_sha256,
      request_sha256: activeTransaction.request_sha256,
    },
    active_transaction_key_sha256:
      activeTransaction.key_sha256,
    requested_transaction: {
      kind: requestedTransaction.kind,
      scope: requestedTransaction.scope,
      stable_operation_id_sha256:
        requestedTransaction.stable_operation_id_sha256,
      request_sha256: requestedTransaction.request_sha256,
    },
    requested_transaction_key_sha256:
      requestedTransaction.key_sha256,
  });
}

function withLock(root, callback, options = {}) {
  const { lockDir, lockOwner } = acquireRootWriterLock(root, options);

  let entryGeneration = null;
  let entryGenerationRecord = null;
  let entryGenerationRecordSha256 = null;
  let entryStateVector = null;
  let entryPristinePayloadVector = null;
  let entryAtomicTransport = null;
  let preWitnessGenerationRetry = false;
  let transactionStartedAt = null;
  let startedGeneration = null;
  let callbackStartVector = null;
  let recoveringOddGeneration = false;
  let oddRecoveryKind = null;
  let completedEvenTransportRetry = false;
  let completedEvenTransportTimestamp = null;
  try {
    assertOwnedDirectory(lockDir, WRITER_LOCK_KIND, lockOwner);
    const rootProtocol = readRootProtocol(root);
    entryGenerationRecord = readRootGenerationRecord(root);
    entryGeneration = entryGenerationRecord.generation;
    if (entryGeneration % 2 === 0) {
      cleanupCompletedEvenAtomicClaim(root);
      entryGenerationRecord = readRootGenerationRecord(root);
      entryGeneration = entryGenerationRecord.generation;
    }
    entryAtomicTransport = inspectAtomicTransport(root);
    if (
      entryGeneration % 2 === 0
        && entryAtomicTransport.transactionDirectory !== null
    ) {
      const rawCompletionResidual = entryAtomicTransport.residual;
      completedEvenTransportRetry = Boolean(
        rawCompletionResidual
          && rawCompletionResidual.operation === ATOMIC_RESIDUAL_WRITE
          && rawCompletionResidual.target === rootGenerationFile(root)
          && rawCompletionResidual.canonical_is_payload,
      );
      completedEvenTransportTimestamp = completedEvenTransportRetry
          && Number.isSafeInteger(
            rawCompletionResidual.stable_time_milliseconds,
          )
        ? new Date(
          rawCompletionResidual.stable_time_milliseconds,
        ).toISOString()
        : null;
      entryAtomicTransport = cleanupCompletedEvenAtomicTransport(
        root,
        entryAtomicTransport,
      );
      entryGenerationRecord = readRootGenerationRecord(root);
      entryGeneration = entryGenerationRecord.generation;
    }
    if (entryGeneration % 2 === 1) {
      transactionStartedAt = entryGenerationRecord.updated_at;
    } else {
      const rawGenerationResidual = entryAtomicTransport.residual;
      transactionStartedAt = rawGenerationResidual
          && rawGenerationResidual.operation === ATOMIC_RESIDUAL_WRITE
          && rawGenerationResidual.target === rootGenerationFile(root)
          && Number.isSafeInteger(
            rawGenerationResidual.stable_time_milliseconds,
          )
        ? new Date(
          rawGenerationResidual.stable_time_milliseconds,
        ).toISOString()
        : completedEvenTransportTimestamp || nowIso();
      preWitnessGenerationRetry = Boolean(
        completedEvenTransportRetry
          || entryAtomicTransport.transactionDirectory,
      );
    }
    entryGenerationRecordSha256 = hashObject(entryGenerationRecord);
    entryStateVector = readOddRecoveryStateVector(root);
    entryPristinePayloadVector = readPristinePayloadVector(root, {
      atomicTransportInspection: entryAtomicTransport,
    });
    const unsealedFirstTransaction = rootProtocol === null
      && entryGeneration === 1
      && entryGenerationRecord.legacy === false
      && entryGenerationRecord.active_transaction !== null;
    assertControl(
      rootProtocol !== null
        || !legacyRootHasControlState(root)
        || unsealedFirstTransaction,
      'STORE_PROTOCOL_MIGRATION_REQUIRED',
      '现存 v1 control root 尚未 seal；须由能完整重放该 root 的 audited migration 安装 decoder seal',
    );
    let requestedTransaction = null;
    if (options.transactionKey !== undefined && options.transactionKey !== null) {
      const rawTransaction = typeof options.transactionKey === 'function'
        ? options.transactionKey()
        : options.transactionKey;
      requestedTransaction = validateTransactionKey(rawTransaction);
    }
    if (
      entryGeneration % 2 === 1
        && entryGenerationRecord.legacy === false
    ) {
      assertRequestedTransactionMatches(
        entryGenerationRecord.active_transaction,
        requestedTransaction,
        options,
      );
    }
    assertControl(
      !unsealedFirstTransaction
        || (
          requestedTransaction
            && requestedTransaction.key_sha256
              === entryGenerationRecord.active_transaction.key_sha256
        ),
      'STORE_PROTOCOL_MIGRATION_REQUIRED',
      '未 seal control root 只允许 exact first transaction 完成 protocol publication',
    );
    assertControl(
      !entryAtomicTransport.transactionHex
        || (
          requestedTransaction
            && entryAtomicTransport.transactionHex
              === atomicTransactionHex(requestedTransaction)
        ),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'atomic transport 与 requested transaction 不匹配',
    );
    assertControl(
      readRootGeneration(root) === entryGeneration
        && hashObject(readRootGenerationRecord(root))
          === entryGenerationRecordSha256
        && readOddRecoveryStateVector(root) === entryStateVector
        && readPristinePayloadVector(root, {
          atomicTransportInspection: entryAtomicTransport,
        })
          === entryPristinePayloadVector,
      entryGeneration % 2 === 1
        ? 'STORE_ODD_RECOVERY_PREFLIGHT_MUTATED'
        : 'STORE_TRANSACTION_PREFLIGHT_MUTATED',
      'transaction preflight/key resolver 改写了 control root',
    );
    if (entryGeneration % 2 === 1) {
      assertControl(
        !entryGenerationRecord.legacy,
        'AUDITED_REPAIR_ONLY',
        'legacy v1 odd generation 没有 transaction binding；只能走 audited repair',
      );
      assertControl(
        entryGenerationRecord.active_transaction.kind
          !== 'AUDITED_REPAIR_ONLY',
        'AUDITED_REPAIR_ONLY',
        '该 odd generation 来自未声明 transaction 的普通 writer；禁止自动恢复',
      );
      assertRequestedTransactionMatches(
        entryGenerationRecord.active_transaction,
        requestedTransaction,
        options,
      );
    }
    if (typeof options.beforeGeneration === 'function') {
      options.beforeGeneration(Object.freeze({
        mode: entryGeneration % 2 === 1
          ? 'ODD_RETRY'
          : preWitnessGenerationRetry
            ? 'PRE_WITNESS_RETRY'
            : 'FRESH',
        generation: entryGeneration,
        transaction_started_at: transactionStartedAt,
        active_transaction: entryGeneration % 2 === 1
          ? entryGenerationRecord.active_transaction
          : null,
        transport_transaction_key_sha256:
          entryAtomicTransport.transactionHex
            ? `sha256:${entryAtomicTransport.transactionHex}`
            : null,
        transport_has_non_generation_state:
          atomicTransportHasNonGenerationState(
            root,
            entryAtomicTransport,
          ),
        pristine_payload_vector_sha256: entryPristinePayloadVector,
        pre_write_vector_sha256:
          entryGenerationRecord.pre_write_vector_sha256,
      }));
      assertOwnedDirectory(lockDir, WRITER_LOCK_KIND, lockOwner);
      assertControl(
        readRootGeneration(root) === entryGeneration
          && hashObject(readRootGenerationRecord(root))
            === entryGenerationRecordSha256
          && readOddRecoveryStateVector(root) === entryStateVector
          && readPristinePayloadVector(root, {
            atomicTransportInspection: entryAtomicTransport,
          }) === entryPristinePayloadVector,
        entryGeneration % 2 === 1
          ? 'STORE_ODD_RECOVERY_PREFLIGHT_MUTATED'
          : 'STORE_TRANSACTION_PREFLIGHT_MUTATED',
        entryGeneration % 2 === 1
          ? 'odd-generation recovery preflight 改写了 control root'
          : 'transaction preflight 改写了 control root',
      );
    }
    if (
      entryGeneration % 2 === 0
        && typeof options.readOnlyResultBeforeGeneration === 'function'
    ) {
      const readOnlyResult =
        options.readOnlyResultBeforeGeneration();
      if (
        readOnlyResult
          && readOnlyResult.completed === true
      ) {
        assertOwnedDirectory(
          lockDir,
          WRITER_LOCK_KIND,
          lockOwner,
        );
        assertControl(
          readRootGeneration(root) === entryGeneration
            && hashObject(readRootGenerationRecord(root))
              === entryGenerationRecordSha256
            && readOddRecoveryStateVector(root) === entryStateVector
            && readPristinePayloadVector(root, {
              atomicTransportInspection: entryAtomicTransport,
            }) === entryPristinePayloadVector,
          'STORE_TRANSACTION_PREFLIGHT_MUTATED',
          'read-only transaction completion 改写了 control root',
        );
        releaseOwnedDirectory(
          lockDir,
          WRITER_LOCK_KIND,
          lockOwner,
        );
        return readOnlyResult.value;
      }
    }
    if (entryGeneration % 2 === 1 && !entryGenerationRecord.legacy) {
      entryGenerationRecord = normalizeOddGenerationAtomicTransport(
        root,
        entryGenerationRecord,
        requestedTransaction,
      );
    }
    entryGenerationRecord = readRootGenerationRecord(root);
    entryGeneration = entryGenerationRecord.generation;
    if (entryGeneration % 2 === 1) {
      entryAtomicTransport = inspectAtomicTransport(
        root,
        atomicTransactionHex(
          requestedTransaction
            || entryGenerationRecord.active_transaction,
        ),
      );
      transactionStartedAt = entryGenerationRecord.updated_at;
      preWitnessGenerationRetry = false;
    } else {
      const generationTransport = atomicGenerationResidual(
        root,
        requestedTransaction,
      );
      entryAtomicTransport = generationTransport.inspection;
      // `beforeGeneration` may seal request artifacts with this timestamp.
      // Never pick a second wall-clock value after that authorization boundary;
      // a retry must reconstruct byte-identical artifacts from the timestamp
      // ultimately sealed into the odd generation.
      transactionStartedAt =
        generationTransport.timestamp || transactionStartedAt;
      preWitnessGenerationRetry = Boolean(
        completedEvenTransportRetry
          || entryAtomicTransport.transactionDirectory,
      );
      entryGenerationRecord = readRootGenerationRecord(root);
      entryGeneration = entryGenerationRecord.generation;
    }
    entryGenerationRecordSha256 = hashObject(entryGenerationRecord);
    entryStateVector = readOddRecoveryStateVector(root);
    entryPristinePayloadVector = readPristinePayloadVector(root, {
      atomicTransportInspection: entryAtomicTransport,
    });
    assertControl(
      !(
        (
          typeof options.authorizeOddRecovery === 'function'
            || typeof options.authorizePristineOddRecovery === 'function'
        )
        && requestedTransaction === null),
      'TRANSACTION_KEY_REQUIRED',
      '提供 odd recovery authority 时必须声明 recoverable transactionKey',
    );
    if (entryGeneration % 2 === 1) {
      assertControl(
        !entryGenerationRecord.legacy,
        'AUDITED_REPAIR_ONLY',
        'legacy v1 odd generation 没有 transaction binding；只能走 audited repair',
      );
      assertControl(
        entryGeneration < Number.MAX_SAFE_INTEGER,
        'STORE_GENERATION_EXHAUSTED',
        'root generation 已耗尽，无法安全完成 odd-generation recovery',
      );
      assertControl(
        entryGenerationRecord.active_transaction.kind
          !== 'AUDITED_REPAIR_ONLY',
        'AUDITED_REPAIR_ONLY',
        '该 odd generation 来自未声明 transaction 的普通 writer；禁止自动恢复',
      );
      assertRequestedTransactionMatches(
        entryGenerationRecord.active_transaction,
        requestedTransaction,
        options,
      );
      const recoveryContext = {
        generation: entryGeneration,
        state_vector_sha256: entryStateVector,
        pristine_payload_vector_sha256: entryPristinePayloadVector,
        pre_write_vector_sha256:
          entryGenerationRecord.pre_write_vector_sha256,
        transaction_started_at: transactionStartedAt,
        active_transaction: entryGenerationRecord.active_transaction,
      };
      const witnessAuthorized =
        typeof options.authorizeOddRecovery === 'function'
        && options.authorizeOddRecovery({
          ...recoveryContext,
        }) === true;
      const publishedTransportAuthorized = Boolean(
        entryAtomicTransport
          && entryAtomicTransport.transactionDirectory
          && (
            entryAtomicTransport.publication_lineage_claims.some(
              (claim) => claim.target !== rootGenerationFile(root),
            )
              || (
                entryAtomicTransport.residual
                  && entryAtomicTransport.residual.canonical_is_payload
                  && [
                    ATOMIC_RESIDUAL_WRITE,
                    ATOMIC_RESIDUAL_CREATE,
                  ].includes(entryAtomicTransport.residual.operation)
                  && entryAtomicTransport.residual.target
                    !== rootGenerationFile(root)
              )
          )
      );
      const pristineTransportAuthorized = Boolean(
        entryAtomicTransport
          && entryAtomicTransport.transactionDirectory
          && entryAtomicTransport.residual
          && (
            (
              entryAtomicTransport.residual.operation
                === ATOMIC_RESIDUAL_MKDIR
                && entryAtomicTransport.residual.complete === true
            )
              || (
                [
                  ATOMIC_RESIDUAL_WRITE,
                  ATOMIC_RESIDUAL_CREATE,
                ].includes(entryAtomicTransport.residual.operation)
                  && entryAtomicTransport.residual
                    .reservation_complete === true
              )
          )
          && entryPristinePayloadVector
            === entryGenerationRecord.pre_write_vector_sha256,
      );
      const transportAuthorized =
        publishedTransportAuthorized || pristineTransportAuthorized;
      let pristineAuthorized = false;
      if (
        !witnessAuthorized
          && typeof options.authorizePristineOddRecovery === 'function'
      ) {
        assertControl(
          entryGenerationRecord.schema_version
            === ROOT_GENERATION_SCHEMA_VERSION
            && typeof entryGenerationRecord
              .pre_write_vector_sha256 === 'string',
          'STORE_PRISTINE_RECOVERY_UNAVAILABLE',
          `控制面 generation=${entryGeneration} 没有 v3 pristine pre-write binding；只能走 durable witness 或 audited repair`,
        );
        assertControl(
          entryPristinePayloadVector
            === entryGenerationRecord.pre_write_vector_sha256,
          'STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH',
          `控制面 generation=${entryGeneration} payload 已偏离 sealed pre-write vector；禁止按 pristine retry`,
          {
            generation: entryGeneration,
            writer_crash_marker: true,
            state_verified: false,
            sealed_pre_write_vector_sha256:
              entryGenerationRecord.pre_write_vector_sha256,
            current_payload_vector_sha256:
              entryPristinePayloadVector,
          },
        );
        pristineAuthorized = options.authorizePristineOddRecovery({
          ...recoveryContext,
        }) === true;
      }
      assertControl(
        witnessAuthorized || pristineAuthorized || transportAuthorized,
        'STORE_REPAIR_REQUIRED',
        `控制面 generation=${entryGeneration} 是 writer crash marker；仅允许 exact durable witness，或已认证且 payload 仍 pristine 的原 stable operation ID 修复`,
        {
          generation: entryGeneration,
          writer_crash_marker: true,
          state_verified: false,
          required_action: 'retry the exact operation with explicit witness/pristine authorization, or use an audited repair path',
        },
      );
      assertControl(
        readRootGeneration(root) === entryGeneration
          && readOddRecoveryStateVector(root) === entryStateVector
          && readPristinePayloadVector(root, {
            atomicTransportInspection: entryAtomicTransport,
          })
            === entryPristinePayloadVector,
        'STORE_ODD_RECOVERY_PREFLIGHT_MUTATED',
        'odd-generation recovery authorization 改写了 control root；拒绝继续并保留 crash marker',
      );
      recoveringOddGeneration = true;
      oddRecoveryKind = witnessAuthorized
        ? 'WITNESS'
        : transportAuthorized
          ? 'TRANSPORT'
          : 'PRISTINE';
      startedGeneration = {
        schema_version: entryGenerationRecord.schema_version,
        generation: entryGeneration,
        active_transaction: entryGenerationRecord.active_transaction,
        pre_write_vector_sha256:
          entryGenerationRecord.pre_write_vector_sha256,
        transaction_started_at: transactionStartedAt,
      };
      callbackStartVector = ['PRISTINE', 'TRANSPORT'].includes(oddRecoveryKind)
        ? entryPristinePayloadVector
        : entryStateVector;
    } else {
      if (requestedTransaction === null) {
        const nonce = randomId('unrecoverable');
        requestedTransaction = canonicalTransactionKey(
          'AUDITED_REPAIR_ONLY',
          { control_root: path.resolve(root) },
          nonce,
          hashObject({
            schema_version: 1,
            kind: 'UNDECLARED_TRANSACTION',
            nonce,
          }),
        );
      }
      startedGeneration = beginRootWrite(
        root,
        requestedTransaction,
        entryPristinePayloadVector,
        transactionStartedAt,
      );
      callbackStartVector = readTransactionMutationVector(
        root,
        inspectAtomicTransport(
          root,
          atomicTransactionHex(startedGeneration.active_transaction),
        ),
      );
      runLockTestHook(
        lockDir,
        options.afterGenerationBeforeCallback,
        'writer generation-to-callback boundary',
      );
      assertControl(
        readPristinePayloadVector(root, {
          atomicTransportInspection: inspectAtomicTransport(
            root,
            atomicTransactionHex(startedGeneration.active_transaction),
          ),
        }) === entryPristinePayloadVector,
        'STORE_TRANSACTION_PREFLIGHT_MUTATED',
        'generation-to-callback test hook 改写了 control payload',
      );
    }
  } catch (error) {
    let preflightUnchanged = false;
    try {
      preflightUnchanged = entryGeneration !== null
        && readRootGeneration(root) === entryGeneration
        && hashObject(readRootGenerationRecord(root))
          === entryGenerationRecordSha256
        && readOddRecoveryStateVector(root) === entryStateVector;
    } catch {
      preflightUnchanged = false;
    }
    if (preflightUnchanged) {
      try {
        releaseOwnedDirectory(lockDir, WRITER_LOCK_KIND, lockOwner);
      } catch (releaseError) {
        if (releaseError.cause === undefined) releaseError.cause = error;
        throw releaseError;
      }
    }
    throw error;
  }

  let value;
  let callbackError = null;
  try {
    value = withAtomicTransaction(
      root,
      startedGeneration.active_transaction,
      callback,
    );
  } catch (error) {
    callbackError = error;
  }

  if (callbackError) {
    if (
      recoveringOddGeneration
        && ['WITNESS', 'TRANSPORT'].includes(oddRecoveryKind)
    ) {
      // An exact retry may still reject after its read-only authorization.
      // Never reinterpret that rejection as proof that the pre-existing
      // partial transaction is complete: keep the original odd marker.
      try {
        releaseOwnedDirectory(lockDir, WRITER_LOCK_KIND, lockOwner);
      } catch (releaseError) {
        if (releaseError.cause === undefined) releaseError.cause = callbackError;
        throw releaseError;
      }
      throw callbackError;
    }
    let callbackTransportPresent = false;
    let callbackTransportCleaned = false;
    try {
      const callbackTransport = inspectAtomicTransport(
        root,
        atomicTransactionHex(startedGeneration.active_transaction),
      );
      // LINEAGE_ONLY is durable pre-write evidence, not an unpublished
      // operation. If the callback already installed a semantic witness and
      // then failed, keep the odd generation for exact witness recovery.
      callbackTransportPresent =
        callbackTransport.residual !== null;
      const callbackPayloadUnchanged =
        callbackStartVector === readTransactionMutationVector(
          root,
          callbackTransport,
        );
      if (callbackTransportPresent && callbackPayloadUnchanged) {
        callbackTransportCleaned =
          cleanupExactUnpublishedCallbackTransport(
            root,
            startedGeneration.active_transaction,
          );
      }
    } catch {
      callbackTransportPresent = true;
      callbackTransportCleaned = false;
    }
    let callbackMutatedStore = true;
    try {
      callbackMutatedStore = recoveringOddGeneration
        ? callbackStartVector !== readPristinePayloadVector(root, {
          atomicTransportInspection: inspectAtomicTransport(
            root,
            atomicTransactionHex(startedGeneration.active_transaction),
          ),
        })
        : callbackStartVector !== readTransactionMutationVector(
          root,
          inspectAtomicTransport(
            root,
            atomicTransactionHex(startedGeneration.active_transaction),
          ),
        );
    } catch {
      callbackMutatedStore = true;
    }
    if (
      callbackMutatedStore
        && !(callbackTransportPresent && !callbackTransportCleaned)
    ) {
      // Keep the odd generation as the durable crash marker, but release the
      // nonce-checked writer lock so an exact idempotent retry can repair it
      // immediately instead of waiting for the stale TTL.
      try {
        releaseOwnedDirectory(lockDir, WRITER_LOCK_KIND, lockOwner);
      } catch (releaseError) {
        if (releaseError.cause === undefined) releaseError.cause = callbackError;
        throw releaseError;
      }
      throw callbackError;
    }
  }

  let generationError = null;
  try {
    assertOwnedDirectory(lockDir, WRITER_LOCK_KIND, lockOwner);
    withAtomicTransaction(
      root,
      startedGeneration.active_transaction,
      () => {
        assertAtomicTransactionClean(
          root,
          startedGeneration.active_transaction,
        );
        if (!callbackError) ensureRootProtocol(root);
        assertAtomicTransactionClean(
          root,
          startedGeneration.active_transaction,
        );
        completeRootWrite(root, startedGeneration);
      },
    );
  } catch (error) {
    generationError = error;
  }
  if (!generationError) {
    try {
      runLockTestHook(lockDir, options.beforeLockRelease, 'writer release');
      releaseOwnedDirectory(
        lockDir,
        WRITER_LOCK_KIND,
        lockOwner,
        options.afterLockReleaseClaimed,
      );
    } catch (error) {
      generationError = error;
    }
  }
  if (generationError) {
    if (callbackError && generationError.cause === undefined) {
      generationError.cause = callbackError;
    }
    throw generationError;
  }
  if (callbackError) throw callbackError;
  return value;
}

function readControlStateVector(root, options = {}) {
  if (!fs.existsSync(root)) return hashObject([]);
  const entries = [];
  const visit = (dir, relativeDir) => {
    const children = fs.readdirSync(dir, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      const relative = relativeDir
        ? `${relativeDir}/${child.name}`
        : child.name;
      // Lock publication/backing/quarantine entries are transport state. The
      // explicit lock checks bracket this vector; hashing them would make an
      // otherwise stable snapshot depend on orphan cleanup.
      if (!relativeDir && (relative === '.lock' || relative.startsWith('.lock.'))) {
        continue;
      }
      if (
        options.excludeMigrationMetadata === true
        && !relativeDir
        && [
          ROOT_GENERATION_FILE,
          ROOT_PROTOCOL_FILE,
          LEGACY_EVIDENCE_ANCHOR_FILE,
          LEGACY_IDENTITY_INCIDENT_RECEIPT_FILE,
          LEGACY_EVIDENCE_SOURCE_DIRECTORY,
          ROOT_PROTOCOL_ROTATION_DIRECTORY,
        ].includes(relative)
      ) {
        continue;
      }
      if (
        !relativeDir
        && relative === ATOMIC_TRANSPORT_DIRECTORY
        && options.atomicTransportInspection
      ) {
        continue;
      }
      if (
        options.includeRejections !== true
        && /^goals\/[^/]+\/rejections(?:\/|$)/.test(relative)
      ) {
        continue;
      }
      if (
        options.excludeRepairableHeads === true
        && (
          relative === 'resources/head.json'
          || /^goals\/[^/]+\/control-head\.json$/.test(relative)
          || /^goals\/[^/]+\/event-heads(?:\/|$)/.test(relative)
        )
      ) {
        continue;
      }
      if (
        options.includeDerived !== true
        && (
          /^goals\/[^/]+\/(?:state\.json|ledger\.json|ledger\.md)$/.test(relative)
          || relative === 'resources/resources.json'
        )
      ) {
        continue;
      }
      if (
        options.includeTransient !== true
        && (
          (child.name.startsWith('.') && child.name.includes('.tmp-'))
          || child.name.startsWith('.init-')
        )
      ) {
        continue;
      }
      const absolute = path.join(dir, child.name);
      const stat = fs.lstatSync(absolute);
      const mode = stat.mode & 0o7777;
      if (stat.isDirectory()) {
        if (options.includeDirectories === true) {
          entries.push(['directory', relative, mode]);
        }
        visit(absolute, relative);
      } else if (stat.isSymbolicLink()) {
        entries.push(['symlink', relative, mode, fs.readlinkSync(absolute)]);
      } else if (stat.isFile()) {
        entries.push([
          'file',
          relative,
          mode,
          stat.size,
          `sha256:${sha256(fs.readFileSync(absolute))}`,
        ]);
      } else {
        entries.push(['other', relative, mode, String(stat.dev), String(stat.ino)]);
      }
    }
  };
  try {
    visit(root, '');
  } catch (error) {
    if (['ENOENT', 'ENOTDIR'].includes(error.code)) {
      throw new ControlError(
        'STORE_VECTOR_CHANGED',
        `控制面 head-vector 扫描期间发生路径变化: ${error.message}`,
      );
    }
    if (error instanceof ControlError) throw error;
    throw new ControlError('CORRUPT_STORE', `控制面 head-vector 无法读取: ${error.message}`);
  }
  return hashObject(entries);
}

function readPristinePayloadVector(root, options = {}) {
  if (!fs.existsSync(root)) {
    return hashObject({
      schema_version: PRISTINE_PAYLOAD_VECTOR_SCHEMA_VERSION,
      entries: [['missing', '.', 0]],
    });
  }
  const entries = [];
  const repairableAncestorDirectories = new Set();
  if (options.atomicTransportInspection) {
    const inspection = options.atomicTransportInspection;
    const residual = inspection.residual;
    for (const relative of (
      (residual && (
        residual.pristine_missing_relative_directories
          || residual.missing_relative_directories
      ))
        || inspection.lineage_missing_relative_directories
        || []
    )) {
      repairableAncestorDirectories.add(relative);
    }
  }
  const visit = (dir, relativeDir) => {
    const children = fs.readdirSync(dir, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      const relative = relativeDir
        ? `${relativeDir}/${child.name}`
        : child.name;
      if (
        !relativeDir
          && (
            relative === ROOT_GENERATION_FILE
              || relative === ROOT_PROTOCOL_FILE
              || (
                relative === ATOMIC_TRANSPORT_DIRECTORY
                  && options.atomicTransportInspection
              )
              || relative === '.lock'
              || relative.startsWith('.lock.')
          )
      ) {
        continue;
      }
      if (
        relative === 'resources/head.json'
          || relative === 'resources/resources.json'
          || /^goals\/[^/]+\/control-head\.json$/.test(relative)
          || /^goals\/[^/]+\/event-heads(?:\/|$)/.test(relative)
          || /^goals\/[^/]+\/(?:state\.json|ledger\.json|ledger\.md)$/.test(
            relative,
          )
      ) {
        continue;
      }
      const absolute = path.join(dir, child.name);
      const stat = fs.lstatSync(absolute);
      const mode = stat.mode & 0o7777;
      if (stat.isDirectory()) {
        if (!repairableAncestorDirectories.has(relative)) {
          entries.push(['directory', relative, mode]);
        }
        visit(absolute, relative);
      } else if (stat.isSymbolicLink()) {
        entries.push([
          'symlink',
          relative,
          mode,
          fs.readlinkSync(absolute),
        ]);
      } else if (stat.isFile()) {
        entries.push([
          'file',
          relative,
          mode,
          stat.size,
          `sha256:${sha256(fs.readFileSync(absolute))}`,
        ]);
      } else {
        entries.push([
          'other',
          relative,
          mode,
          String(stat.dev),
          String(stat.ino),
          stat.size,
        ]);
      }
    }
  };
  try {
    const rootStat = fs.lstatSync(root);
    assertControl(
      rootStat.isDirectory() && !rootStat.isSymbolicLink(),
      'CORRUPT_STORE',
      'control root 必须是非 symlink directory',
    );
    entries.push(['directory', '.', rootStat.mode & 0o7777]);
    visit(root, '');
  } catch (error) {
    if (error instanceof ControlError) throw error;
    if (['ENOENT', 'ENOTDIR'].includes(error.code)) {
      throw new ControlError(
        'STORE_VECTOR_CHANGED',
        `控制面 pristine payload vector 扫描期间发生路径变化: ${error.message}`,
      );
    }
    throw new ControlError(
      'CORRUPT_STORE',
      `控制面 pristine payload vector 无法读取: ${error.message}`,
    );
  }
  return hashObject({
    schema_version: PRISTINE_PAYLOAD_VECTOR_SCHEMA_VERSION,
    entries,
  });
}

function readTransactionMutationVector(
  root,
  atomicTransportInspection = null,
) {
  return readControlStateVector(root, {
    excludeRepairableHeads: true,
    atomicTransportInspection,
  });
}

function readOddRecoveryStateVector(root) {
  return readControlStateVector(root, {
    includeDerived: true,
    includeRejections: true,
    includeTransient: true,
    includeDirectories: true,
  });
}

function readMigrationSourceStateVector(
  root,
  atomicTransportInspection = null,
) {
  return readControlStateVector(root, {
    excludeMigrationMetadata: true,
    atomicTransportInspection,
  });
}

function readMigrationValidationVector(
  root,
  atomicTransportInspection = null,
) {
  return readControlStateVector(root, {
    includeDerived: true,
    includeRejections: true,
    atomicTransportInspection,
  });
}

function normalizeMigrationValidationResult(result, adopting, existingProtocol) {
  assertControl(
    result
      && typeof result === 'object'
      && !Array.isArray(result)
      && Object.keys(result).length === 2
      && Object.keys(result).every((key) => (
        ['report', 'migration_artifacts'].includes(key)
      ))
      && Array.isArray(result.migration_artifacts),
    'STORE_MIGRATION_RESULT_INVALID',
    'migration validator 必须返回 {report,migration_artifacts}',
  );
  try {
    const reportJson = canonicalJson(result.report);
    assertControl(
      typeof reportJson === 'string'
        && canonicalJson(JSON.parse(reportJson)) === reportJson,
      'STORE_MIGRATION_RESULT_INVALID',
      'migration validator report 必须是 JSON-safe value',
    );
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'STORE_MIGRATION_RESULT_INVALID',
      `migration validator report 无法 canonicalize: ${error.message}`,
    );
  }

  const artifacts = [];
  const seen = new Set();
  let indexCount = 0;
  let identityIndexCount = 0;
  let sourceCount = 0;
  let sourceBytes = 0;
  for (const artifact of result.migration_artifacts) {
    assertControl(
      artifact
        && typeof artifact === 'object'
        && !Array.isArray(artifact)
        && Object.keys(artifact).length === 3
        && Object.keys(artifact).every((key) => (
          ['relative_path', 'body', 'sha256'].includes(key)
        ))
        && typeof artifact.relative_path === 'string'
        && typeof artifact.sha256 === 'string'
        && /^sha256:[0-9a-f]{64}$/.test(artifact.sha256)
        && (typeof artifact.body === 'string' || Buffer.isBuffer(artifact.body))
        && !seen.has(artifact.relative_path),
      'STORE_MIGRATION_ARTIFACT_INVALID',
      'migration artifact request 字段非法或重复',
    );
    const kind = assertMigrationArtifactPath(
      artifact.relative_path,
      artifact.sha256,
    );
    const body = Buffer.isBuffer(artifact.body)
      ? Buffer.from(artifact.body)
      : Buffer.from(artifact.body, 'utf8');
    assertControl(
      `sha256:${sha256(body)}` === artifact.sha256,
      'STORE_MIGRATION_ARTIFACT_DIGEST_MISMATCH',
      `migration artifact body hash 不匹配: ${artifact.relative_path}`,
    );
    if (kind === 'INDEX' || kind === 'IDENTITY_INDEX') {
      if (kind === 'INDEX') indexCount += 1;
      else identityIndexCount += 1;
      assertControl(
        body.length <= MAX_MIGRATION_INDEX_BYTES,
        'STORE_MIGRATION_ARTIFACT_LIMIT',
        'legacy migration index 超过大小上限',
      );
      let parsed;
      try {
        parsed = JSON.parse(body.toString('utf8'));
      } catch (error) {
        throw new ControlError(
          'STORE_MIGRATION_ARTIFACT_INVALID',
          `legacy migration index 不是合法 JSON: ${error.message}`,
        );
      }
      assertControl(
        Buffer.from(`${canonicalJson(parsed)}\n`).equals(body),
        'STORE_MIGRATION_ARTIFACT_INVALID',
        'legacy migration index 必须是 canonical JSON + newline',
      );
    } else {
      sourceCount += 1;
      sourceBytes += body.length;
      assertControl(
        body.length <= MAX_MIGRATION_SOURCE_ARTIFACT_BYTES
          && sourceCount <= MAX_MIGRATION_SOURCE_ARTIFACTS
          && sourceBytes <= MAX_MIGRATION_SOURCE_TOTAL_BYTES,
        'STORE_MIGRATION_ARTIFACT_LIMIT',
        'legacy evidence source artifact 超过数量、单文件或总大小上限',
      );
    }
    seen.add(artifact.relative_path);
    artifacts.push({
      relative_path: artifact.relative_path,
      sha256: artifact.sha256,
      body,
      kind,
    });
  }
  artifacts.sort((left, right) => left.relative_path.localeCompare(right.relative_path));
  assertControl(
    adopting
      ? indexCount === 1 && identityIndexCount <= 1
      : indexCount <= 1 && identityIndexCount <= 1,
    'STORE_MIGRATION_ARTIFACT_REQUIRED',
    'legacy root adoption 必须提供 evidence anchor；identity incident receipt 至多一个',
  );

  const descriptors = artifacts.map(({ relative_path: relativePath, sha256: digest }) => ({
    relative_path: relativePath,
    sha256: digest,
  }));
  if (existingProtocol) {
    assertControl(
      canonicalJson(descriptors) === canonicalJson(existingProtocol.migration_artifacts),
      'STORE_MIGRATION_ARTIFACT_CONFLICT',
      'idempotent migration validator 返回的 artifacts 与 protocol seal 不一致',
    );
  }
  return {
    report: result.report,
    artifacts,
    descriptors,
  };
}

function ensureMigrationArtifactParent(root, relativePath, create = true) {
  const parentRelative = path.posix.dirname(relativePath);
  if (parentRelative === '.') return;
  const parent = path.join(root, parentRelative);
  if (create) {
    ensureDir(parent);
  }
  let stat;
  try {
    stat = fs.lstatSync(parent);
  } catch (error) {
    throw new ControlError(
      'STORE_MIGRATION_ARTIFACT_PATH_INVALID',
      `migration artifact ancestor 无法读取: ${parentRelative}: ${error.message}`,
    );
  }
  assertControl(
    stat.isDirectory() && !stat.isSymbolicLink(),
    'STORE_MIGRATION_ARTIFACT_PATH_INVALID',
    `migration artifact ancestor 不是可信目录: ${parentRelative}`,
  );
}

function installMigrationArtifacts(root, artifacts) {
  // Source blobs are installed before the index that references them. The
  // protocol seal is published last and is the transaction's commit record.
  const installationOrder = [...artifacts].sort((left, right) => (
    left.kind === right.kind
      ? left.relative_path.localeCompare(right.relative_path)
      : left.kind === 'SOURCE' ? -1 : 1
  ));
  const outcomes = new Map();
  for (const artifact of installationOrder) {
    ensureMigrationArtifactParent(root, artifact.relative_path);
    const file = path.join(root, artifact.relative_path);
    const created = atomicCreate(file, artifact.body, {
      fault_namespace: 'MIGRATION_ARTIFACT',
    });
    if (!created) {
      let stat;
      let existing;
      try {
        stat = fs.lstatSync(file);
        existing = fs.readFileSync(file);
      } catch (error) {
        throw new ControlError(
          'STORE_MIGRATION_ARTIFACT_CONFLICT',
          `migration artifact 既有 bytes 无法验证: ${artifact.relative_path}: ${error.message}`,
        );
      }
      assertControl(
        stat.isFile()
          && !stat.isSymbolicLink()
          && existing.equals(artifact.body),
        'STORE_MIGRATION_ARTIFACT_CONFLICT',
        `migration artifact 既有 bytes 与 replay 结果冲突: ${artifact.relative_path}`,
      );
    }
    outcomes.set(artifact.relative_path, {
      relative_path: artifact.relative_path,
      sha256: artifact.sha256,
      created,
      idempotent: !created,
    });
  }
  return artifacts.map((artifact) => outcomes.get(artifact.relative_path));
}

function rootProtocolAdoptionTransaction(
  root,
  sourceStateVector,
  descriptors,
) {
  const request = {
    schema_version: 1,
    source_state_vector_sha256: sourceStateVector,
    migration_artifacts: descriptors,
    protocol_compatibility: rootProtocolCompatibility(),
  };
  return canonicalTransactionKey(
    'AUDITED_REPAIR_ONLY',
    { control_root: path.resolve(root) },
    'root-protocol-adoption',
    hashObject(request),
  );
}

function normalizeProtocolRotationValidationResult(result) {
  assertControl(
    result
      && typeof result === 'object'
      && !Array.isArray(result)
      && Object.keys(result).length === 1
      && Object.keys(result)[0] === 'report',
    'STORE_PROTOCOL_ROTATION_RESULT_INVALID',
    'protocol rotation validator 必须返回 {report}',
  );
  let reportJson;
  try {
    reportJson = canonicalJson(result.report);
  } catch (error) {
    throw new ControlError(
      'STORE_PROTOCOL_ROTATION_RESULT_INVALID',
      `protocol rotation report 无法 canonicalize: ${error.message}`,
    );
  }
  assertControl(
    typeof reportJson === 'string'
      && canonicalJson(JSON.parse(reportJson)) === reportJson
      && result.report
      && typeof result.report === 'object'
      && !Array.isArray(result.report)
      && result.report.goal_worktree_map
      && typeof result.report.goal_worktree_map === 'object'
      && !Array.isArray(result.report.goal_worktree_map),
    'STORE_PROTOCOL_ROTATION_RESULT_INVALID',
    'protocol rotation report 必须是 JSON-safe object 且含 goal_worktree_map',
  );
  return {
    report: result.report,
    report_sha256: hashObject(result.report),
    goal_worktree_map: result.report.goal_worktree_map,
    goal_worktree_map_sha256:
      hashObject(result.report.goal_worktree_map),
  };
}

function protocolWithSealSummary(protocol) {
  return {
    ...protocolCompatibilityFromSeal(protocol),
    seal_sha256: protocol.seal_sha256,
  };
}

function rootProtocolRotationRequest(options) {
  return {
    schema_version: 1,
    rotation_id: options.rotationId,
    incident_ref: options.incidentRef,
    old_controller_drain_ack:
      options.oldControllerDrainAcknowledgment,
    expected_predecessor_seal_sha256:
      options.predecessorProtocol.seal_sha256,
    operator_request_sha256: options.operatorRequestSha256,
    predecessor_protocol:
      protocolWithSealSummary(options.predecessorProtocol),
    successor_protocol: options.successorProtocol,
    migration_artifacts_sha256:
      hashObject(options.predecessorProtocol.migration_artifacts),
    source_state_vector_sha256: options.sourceStateVectorSha256,
    validation_report_sha256: options.validation.report_sha256,
    goal_worktree_map_sha256:
      options.validation.goal_worktree_map_sha256,
  };
}

function rootProtocolRotationTransaction(root, rotationId, request) {
  return canonicalTransactionKey(
    'PROTOCOL_ROTATION',
    { control_root: path.resolve(root) },
    rotationId,
    hashObject(request),
  );
}

function protocolRotationReceiptBody(receipt) {
  return Buffer.from(`${canonicalJson(receipt)}\n`);
}

function protocolRotationDescriptor(receipt) {
  const body = protocolRotationReceiptBody(receipt);
  const digest = `sha256:${sha256(body)}`;
  return {
    descriptor: {
      relative_path:
        `${ROOT_PROTOCOL_ROTATION_DIRECTORY}/${digest.slice('sha256:'.length)}.json`,
      sha256: digest,
    },
    body,
  };
}

function assertProspectiveProtocolRotationCandidate(
  predecessorProtocol,
  receipt,
  receiptArtifact,
  successorProtocol,
) {
  const predecessorRotations =
    predecessorProtocol.schema_version === ROOT_PROTOCOL_SCHEMA_VERSION
      ? predecessorProtocol.protocol_rotations
      : [];
  assertControl(
    Array.isArray(predecessorRotations)
      && predecessorRotations.length < MAX_ROOT_PROTOCOL_ROTATIONS,
    'STORE_PROTOCOL_ROTATION_CAPACITY_EXHAUSTED',
    `protocol rotation receipt 已达到上限 ${MAX_ROOT_PROTOCOL_ROTATIONS}`,
  );
  assertControl(
    receiptArtifact.body.length
      <= MAX_ROOT_PROTOCOL_ROTATION_RECEIPT_BYTES,
    'STORE_PROTOCOL_ROTATION_RECEIPT_LIMIT',
    `protocol rotation receipt 超过 ${MAX_ROOT_PROTOCOL_ROTATION_RECEIPT_BYTES} bytes`,
  );
  const receiptUnsigned = { ...receipt };
  delete receiptUnsigned.receipt_sha256;
  const request = {
    schema_version: 1,
    rotation_id: receipt.rotation_id,
    incident_ref: receipt.incident_ref,
    old_controller_drain_ack: receipt.old_controller_drain_ack,
    expected_predecessor_seal_sha256:
      receipt.predecessor_protocol.seal_sha256,
    operator_request_sha256: receipt.operator_request_sha256,
    predecessor_protocol: receipt.predecessor_protocol,
    successor_protocol: receipt.successor_protocol,
    migration_artifacts_sha256: receipt.migration_artifacts_sha256,
    source_state_vector_sha256: receipt.source_state_vector_sha256,
    validation_report_sha256: receipt.validation_report_sha256,
    goal_worktree_map_sha256: receipt.goal_worktree_map_sha256,
  };
  assertControl(
    receipt.receipt_sha256 === hashObject(receiptUnsigned)
      && receipt.request_sha256 === hashObject(request)
      && receipt.migration_artifacts_sha256
        === hashObject(predecessorProtocol.migration_artifacts)
      && canonicalJson(receipt.predecessor_protocol)
        === canonicalJson(protocolWithSealSummary(predecessorProtocol))
      && canonicalJson(receipt.successor_protocol)
        === canonicalJson(protocolCompatibilityFromSeal(successorProtocol))
      && receipt.validation_report_sha256
        === hashObject(receipt.validation_report)
      && receipt.goal_worktree_map_sha256
        === hashObject(receipt.goal_worktree_map)
      && receiptArtifact.descriptor.sha256
        === `sha256:${sha256(receiptArtifact.body)}`
      && successorProtocol.protocol_rotations.length
        === predecessorRotations.length + 1
      && canonicalJson(
        successorProtocol.protocol_rotations.slice(0, -1),
      ) === canonicalJson(predecessorRotations)
      && canonicalJson(
        successorProtocol.protocol_rotations[
          successorProtocol.protocol_rotations.length - 1
        ],
      ) === canonicalJson(receiptArtifact.descriptor),
    'STORE_PROTOCOL_ROTATION_CANDIDATE_INVALID',
    'prospective rotation receipt/protocol chain binding 非法',
  );
  const successorUnsigned = { ...successorProtocol };
  delete successorUnsigned.seal_sha256;
  assertControl(
    successorProtocol.seal_sha256 === hashObject(successorUnsigned),
    'STORE_PROTOCOL_ROTATION_CANDIDATE_INVALID',
    'prospective successor protocol self hash 非法',
  );
}

function exactProtocolRotationReceipt(protocol, options) {
  if (
    protocol.schema_version !== ROOT_PROTOCOL_SCHEMA_VERSION
      || !Array.isArray(protocol.protocol_rotations)
      || protocol.protocol_rotations.length === 0
  ) {
    return null;
  }
  const descriptor =
    protocol.protocol_rotations[protocol.protocol_rotations.length - 1];
  const receipt = validateProtocolRotationReceipt(
    options.root,
    descriptor,
  );
  const exact = receipt.rotation_id === options.rotationId
    && receipt.incident_ref === options.incidentRef
    && receipt.old_controller_drain_ack
      === options.oldControllerDrainAcknowledgment
    && receipt.predecessor_protocol.seal_sha256
      === options.expectedPredecessorSealSha256
    && receipt.operator_request_sha256
      === options.operatorRequestSha256
    && canonicalJson(receipt.successor_protocol)
      === canonicalJson(protocolCompatibilityFromSeal(protocol));
  return exact ? { descriptor, receipt } : null;
}

function predecessorProtocolFromRotationReceipt(protocol, receipt) {
  const predecessor = receipt.predecessor_protocol;
  return {
    ...predecessor,
    migration_source_state_vector_sha256:
      protocol.migration_source_state_vector_sha256,
    migration_artifacts: protocol.migration_artifacts,
    ...(predecessor.schema_version === ROOT_PROTOCOL_SCHEMA_VERSION
      ? {
        protocol_rotations:
          protocol.protocol_rotations.slice(0, -1),
      }
      : {}),
  };
}

function exactSealedProtocolRotationRecovery(
  root,
  protocol,
  requestOptions,
) {
  const exact = exactProtocolRotationReceipt(protocol, {
    root,
    ...requestOptions,
  });
  if (exact === null) return null;
  const { descriptor, receipt } = exact;
  const predecessorProtocol =
    predecessorProtocolFromRotationReceipt(protocol, receipt);
  const validation = normalizeProtocolRotationValidationResult({
    report: receipt.validation_report,
  });
  const targetCompatibility =
    protocolCompatibilityFromSeal(protocol);
  const request = rootProtocolRotationRequest({
    rotationId: requestOptions.rotationId,
    incidentRef: requestOptions.incidentRef,
    oldControllerDrainAcknowledgment:
      requestOptions.oldControllerDrainAcknowledgment,
    operatorRequestSha256: requestOptions.operatorRequestSha256,
    predecessorProtocol,
    successorProtocol: targetCompatibility,
    sourceStateVectorSha256: receipt.source_state_vector_sha256,
    validation,
  });
  const transaction = rootProtocolRotationTransaction(
    root,
    requestOptions.rotationId,
    request,
  );
  assertControl(
    canonicalJson(receipt.predecessor_protocol)
      === canonicalJson(protocolWithSealSummary(predecessorProtocol))
      && canonicalJson(receipt.successor_protocol)
        === canonicalJson(targetCompatibility)
      && canonicalJson(validation.goal_worktree_map)
        === canonicalJson(receipt.goal_worktree_map)
      && validation.goal_worktree_map_sha256
        === receipt.goal_worktree_map_sha256
      && hashObject(request) === receipt.request_sha256,
    'CORRUPT_STORE_PROTOCOL',
    'sealed protocol rotation receipt 缺 exact predecessor/request binding',
  );
  const generation = readRootGenerationRecord(root);
  if (generation.generation % 2 === 1) {
    assertControl(
      !generation.legacy
        && generation.active_transaction
        && canonicalJson(generation.active_transaction)
          === canonicalJson(transaction)
        && generation.generation === receipt.entry_generation + 1
        && receipt.exit_generation === generation.generation + 1
        && receipt.requested_at === generation.updated_at,
      'CORRUPT_STORE_PROTOCOL',
      'sealed successor odd recovery 缺 exact generation/transaction binding',
    );
    const inspection = inspectAtomicTransport(
      root,
      atomicTransactionHex(transaction),
    );
    assertControl(
      readMigrationSourceStateVector(root, inspection)
        === receipt.source_state_vector_sha256,
      'STORE_PROTOCOL_ROTATION_SOURCE_CHANGED',
      'sealed successor odd recovery 的 source vector 已漂移',
    );
  }
  return {
    descriptor,
    receipt,
    predecessor_protocol: predecessorProtocol,
    validation,
    request,
    transaction,
    generation,
  };
}

function readRootProtocolForRotationTarget(root, targetCompatibility) {
  const protocol = readRootProtocolSeal(root);
  assertControl(
    protocol !== null
      && canonicalJson(protocolCompatibilityFromSeal(protocol))
        === canonicalJson(targetCompatibility),
    'STORE_PROTOCOL_ROTATION_PUBLICATION_MISMATCH',
    'completed rotation protocol 与 sealed successor target 不匹配',
  );
  return protocol;
}

function completedProtocolRotationResult(
  root,
  exactRotation,
  generationRecord,
  options = {},
) {
  const { descriptor, receipt } = exactRotation;
  assertControl(
    generationRecord.generation >= receipt.exit_generation
      && generationRecord.generation % 2 === 0
      && generationRecord.active_transaction === null
      && generationRecord.pre_write_vector_sha256 === null
      && (
        options.requireExactExitGeneration !== true
          || generationRecord.generation === receipt.exit_generation
      ),
    'STORE_PROTOCOL_ROTATION_GENERATION_MISMATCH',
    options.requireExactExitGeneration === true
      ? 'recovered protocol rotation completion generation 必须等于 sealed receipt exit_generation'
      : 'successor protocol 的 clean even generation 不得早于 sealed receipt exit_generation',
  );
  const strictProtocol = readRootProtocolForRotationTarget(
    root,
    receipt.successor_protocol,
  );
  return {
    rotated: false,
    idempotent: true,
    predecessor_protocol: receipt.predecessor_protocol,
    protocol: strictProtocol,
    entry_generation: receipt.entry_generation,
    exit_generation: receipt.exit_generation,
    source_state_vector_sha256:
      receipt.source_state_vector_sha256,
    sealed_state_vector_sha256: readControlStateVector(root),
    rotation_receipt: descriptor,
    validation: receipt.validation_report,
  };
}

function cleanupExactProtocolRotationMkdirLineage(
  root,
  rotationTransaction,
  successorProtocol,
  receiptArtifact,
  expectedReceipt,
) {
  const generation = readRootGenerationRecord(root);
  const currentProtocol = readRootProtocolSeal(root);
  const lastDescriptor = currentProtocol
    && currentProtocol.schema_version === ROOT_PROTOCOL_SCHEMA_VERSION
    && Array.isArray(currentProtocol.protocol_rotations)
    ? currentProtocol.protocol_rotations[
      currentProtocol.protocol_rotations.length - 1
    ]
    : null;
  const durableReceipt = lastDescriptor
    ? validateProtocolRotationReceipt(root, lastDescriptor)
    : null;
  assertControl(
    !generation.legacy
      && generation.generation % 2 === 1
      && generation.active_transaction
      && generation.active_transaction.kind === 'PROTOCOL_ROTATION'
      && generation.active_transaction.key_sha256
        === rotationTransaction.key_sha256
      && generation.active_transaction.request_sha256
        === expectedReceipt.request_sha256
      && canonicalJson(currentProtocol)
        === canonicalJson(successorProtocol)
      && canonicalJson(lastDescriptor)
        === canonicalJson(receiptArtifact.descriptor)
      && canonicalJson(durableReceipt)
        === canonicalJson(expectedReceipt)
      && durableReceipt.entry_generation + 1
        === generation.generation
      && durableReceipt.exit_generation
        === generation.generation + 1
      && canonicalJson(durableReceipt.successor_protocol)
        === canonicalJson(protocolCompatibilityFromSeal(currentProtocol)),
    'STORE_PROTOCOL_ROTATION_PUBLICATION_MISMATCH',
    'protocol lineage cleanup 缺 exact successor protocol/receipt/odd transaction witness',
  );
  const inspection = inspectAtomicTransport(
    root,
    atomicTransactionHex(rotationTransaction),
  );
  if (inspection.transactionDirectory === null) return;
  assertControl(
    inspection.residual === null
      && inspection.mkdir_lineage_claims.every(
        (claim) => claim.lineage === true && claim.complete,
      ),
    'STORE_ATOMIC_RESIDUAL_CONFLICT',
    'protocol rotation witness cleanup 只接受 sealed lineage/cleanup tail',
  );
  const binding = atomicCleanupBinding(
    'PROTOCOL_ROTATION',
    root,
    inspection.transactionHex,
    {
      successor_protocol_seal_sha256: currentProtocol.seal_sha256,
      rotation_receipt_sha256: durableReceipt.receipt_sha256,
    },
  );
  claimAndRemoveAtomicTransport(inspection, binding);
}

function cleanupExactProtocolRotationAtomicClaim(root, requestOptions) {
  const claim = atomicCleanupClaimAt(root);
  if (claim === null || claim.kind !== 'PROTOCOL_ROTATION') return false;
  const generation = readRootGenerationRecord(root);
  const currentProtocol = readRootProtocolSeal(root);
  const exactRotation = currentProtocol
    ? exactProtocolRotationReceipt(currentProtocol, {
      root,
      ...requestOptions,
    })
    : null;
  assertControl(
    !generation.legacy
      && generation.generation % 2 === 1
      && generation.active_transaction
      && generation.active_transaction.kind === 'PROTOCOL_ROTATION'
      && atomicTransactionHex(generation.active_transaction)
        === claim.transaction_hex
      && exactRotation
      && exactRotation.receipt.entry_generation + 1
        === generation.generation
      && exactRotation.receipt.exit_generation
        === generation.generation + 1,
    'STORE_PROTOCOL_ROTATION_PUBLICATION_MISMATCH',
    'protocol cleanup claim 缺 exact successor receipt/odd transaction authority',
  );
  const binding = atomicCleanupBinding(
    'PROTOCOL_ROTATION',
    root,
    claim.transaction_hex,
    {
      successor_protocol_seal_sha256: currentProtocol.seal_sha256,
      rotation_receipt_sha256:
        exactRotation.receipt.receipt_sha256,
    },
  );
  removeClaimedAtomicTransport(root, claim, binding);
  return true;
}

function rotateRootProtocol(
  root,
  validationCallback,
  requestOptions,
  options = {},
) {
  assertControl(
    typeof validationCallback === 'function',
    'STORE_PROTOCOL_ROTATION_VALIDATOR_REQUIRED',
    'store protocol rotation 必须提供完整 replay validator',
  );
  assertControl(
    requestOptions
      && typeof requestOptions === 'object'
      && !Array.isArray(requestOptions)
      && typeof requestOptions.rotationId === 'string'
      && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(
        requestOptions.rotationId,
      )
      && typeof requestOptions.incidentRef === 'string'
      && requestOptions.incidentRef.trim()
        === requestOptions.incidentRef
      && requestOptions.incidentRef.length > 0
      && requestOptions.incidentRef.length <= 2000
      && requestOptions.oldControllerDrainAcknowledgment
        === ROOT_PROTOCOL_ROTATION_DRAIN_ACK
      && typeof requestOptions.expectedPredecessorSealSha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(
        requestOptions.expectedPredecessorSealSha256,
      )
      && typeof requestOptions.operatorRequestSha256 === 'string'
      && /^sha256:[0-9a-f]{64}$/.test(
        requestOptions.operatorRequestSha256,
      ),
    'STORE_PROTOCOL_ROTATION_REQUEST_INVALID',
    'store protocol rotation request 缺稳定 ID、incident、drain ack 或 exact predecessor/operator binding',
  );
  const rotationProtocolSnapshot = (candidateRoot) => (
    readRootProtocolSealForRotation(candidateRoot, requestOptions)
  );
  const rotationProtocolReader = (candidateRoot) => (
    rotationProtocolSnapshot(candidateRoot).protocol
  );
  const initialSnapshot = rotationProtocolSnapshot(root);
  const initialProtocol = initialSnapshot.protocol;
  let pendingRotation = initialSnapshot.pending_rotation;
  let sealedRotation = initialSnapshot.sealed_rotation;
  assertControl(
    initialProtocol !== null,
    'STORE_PROTOCOL_ROTATION_PREDECESSOR_REQUIRED',
    '未 seal v1 root 必须走 adopt-store-protocol，不能走 rotation',
  );
  let predecessorProtocol = initialProtocol;
  let alreadyRotated = sealedRotation === null
    ? null
    : {
      descriptor: sealedRotation.descriptor,
      receipt: sealedRotation.receipt,
    };
  if (alreadyRotated) {
    predecessorProtocol = sealedRotation.predecessor_protocol;
  }
  const initialSealedSuccessor = pendingRotation
    ? pendingRotation.receipt.successor_protocol
    : alreadyRotated
      ? alreadyRotated.receipt.successor_protocol
      : null;
  assertControl(
    predecessorProtocol.seal_sha256
      === requestOptions.expectedPredecessorSealSha256,
    'STORE_PROTOCOL_ROTATION_PREDECESSOR_MISMATCH',
    '当前/receipt predecessor protocol seal 与 expected CAS 不匹配',
  );
  const predecessorCompatibility =
    protocolCompatibilityFromSeal(predecessorProtocol);
  validateProtocolCompatibilityRecord(
    predecessorCompatibility,
    'rotation predecessor',
    { allowLegacySchema: true },
  );
  const recoveryBrokerCompatibility = rootProtocolCompatibility();
  const targetCompatibility = initialSealedSuccessor
    ? protocolCompatibilityFromSeal(initialSealedSuccessor)
    : recoveryBrokerCompatibility;
  assertCurrentControllerDecoderFingerprint(
    recoveryBrokerCompatibility.controller_decoder_sha256,
  );
  if (!alreadyRotated) {
    assertControl(
      canonicalJson(predecessorCompatibility)
        !== canonicalJson(targetCompatibility),
      'STORE_PROTOCOL_ROTATION_NOT_REQUIRED',
      'predecessor 已与当前 decoder/schema 兼容；拒绝制造空 rotation',
    );
  }
  const lockBindingSha256 = hashObject({
    schema_version: 1,
    rotation_id: requestOptions.rotationId,
    incident_ref: requestOptions.incidentRef,
    expected_predecessor_seal_sha256:
      requestOptions.expectedPredecessorSealSha256,
    operator_request_sha256: requestOptions.operatorRequestSha256,
    target_protocol: targetCompatibility,
  });
  const lockNoncePrefix =
    `rotation-${lockBindingSha256.slice(-20)}-`;
  const protocolBinding = {
    protocolCompatibility: predecessorCompatibility,
    readProtocol: rotationProtocolReader,
    nonceForKind: (kind) => (
      `${kind === WRITER_LOCK_KIND ? 'writer' : 'reaper'}-${lockNoncePrefix}${randomId('attempt')}`
    ),
    allowStaleReaperRecovery: true,
    canReapObserved: (observed, kind) => (
      observed
        && observed.format === 'v2'
        && observed.owner.nonce.startsWith(
          `${kind === WRITER_LOCK_KIND ? 'writer' : 'reaper'}-${lockNoncePrefix}`,
        )
    ),
  };
  const {
    lockDir,
    lockOwner,
  } = acquireRootWriterLock(root, {
    ...options,
    protocolBinding,
  });
  let safeToRelease = true;
  try {
    assertOwnedDirectory(
      lockDir,
      WRITER_LOCK_KIND,
      lockOwner,
      protocolBinding,
    );
    let currentSnapshot = rotationProtocolSnapshot(root);
    let currentProtocol = currentSnapshot.protocol;
    pendingRotation = currentSnapshot.pending_rotation;
    sealedRotation = currentSnapshot.sealed_rotation;
    assertControl(
      currentProtocol !== null,
      'STORE_PROTOCOL_ROTATION_PREDECESSOR_REQUIRED',
      'rotation lock 内 root protocol seal 消失',
    );
    alreadyRotated = sealedRotation === null
      ? null
      : {
        descriptor: sealedRotation.descriptor,
        receipt: sealedRotation.receipt,
      };
    assertControl(
      !(alreadyRotated && pendingRotation),
      'STORE_PROTOCOL_ROTATION_PUBLICATION_MISMATCH',
      'protocol rotation receipt 不得同时处于 sealed 与 pending 状态',
    );
    const lockedSealedSuccessor = pendingRotation
      ? pendingRotation.receipt.successor_protocol
      : alreadyRotated
        ? alreadyRotated.receipt.successor_protocol
        : null;
    assertControl(
      (
        initialSealedSuccessor === null
          || lockedSealedSuccessor !== null
      )
        && (
          lockedSealedSuccessor === null
            || canonicalJson(lockedSealedSuccessor)
              === canonicalJson(targetCompatibility)
        ),
      'STORE_PROTOCOL_ROTATION_PUBLICATION_MISMATCH',
      'rotation lock 内 sealed successor target 消失或漂移',
    );
    let generationRecord = readRootGenerationRecord(root);
    if (generationRecord.generation % 2 === 0) {
      cleanupCompletedEvenAtomicClaim(root);
    } else {
      cleanupExactProtocolRotationAtomicClaim(root, requestOptions);
    }
    generationRecord = readRootGenerationRecord(root);
    let transport = inspectAtomicTransport(root);
    if (
      alreadyRotated
        && generationRecord.generation % 2 === 0
        && generationRecord.active_transaction === null
        && transport.transactionDirectory === null
    ) {
      return completedProtocolRotationResult(
        root,
        alreadyRotated,
        generationRecord,
      );
    }
    assertControl(
      currentProtocol.seal_sha256
        === requestOptions.expectedPredecessorSealSha256
        || alreadyRotated !== null,
      'STORE_PROTOCOL_ROTATION_PREDECESSOR_MISMATCH',
      'rotation lock 内 protocol seal 不是 exact predecessor/successor',
    );
    assertControl(
      generationRecord.generation % 2 === 0
        || (
          !generationRecord.legacy
            && generationRecord.active_transaction
            && generationRecord.active_transaction.kind
              === 'PROTOCOL_ROTATION'
        ),
      'STORE_PROTOCOL_ROTATION_EVEN_REQUIRED',
      'protocol rotation 只接受 even root 或 exact PROTOCOL_ROTATION odd crash marker',
    );
    if (
      alreadyRotated
        && generationRecord.generation % 2 === 1
    ) {
      assertControl(
        generationRecord.generation
          === alreadyRotated.receipt.entry_generation + 1
          && alreadyRotated.receipt.exit_generation
            === generationRecord.generation + 1,
        'STORE_PROTOCOL_ROTATION_GENERATION_MISMATCH',
        'successor protocol 的 odd recovery generation 必须匹配 sealed receipt entry/exit',
      );
    }
    const sourceStateVector = readMigrationSourceStateVector(
      root,
      transport,
    );
    const beforeValidationVector = readMigrationValidationVector(
      root,
      transport,
    );
    const beforeValidationStrictVector = readOddRecoveryStateVector(root);
    let validation;
    if (pendingRotation) {
      const pendingValidation =
        normalizeProtocolRotationValidationResult({
          report: pendingRotation.receipt.validation_report,
        });
      const pendingRequest = rootProtocolRotationRequest({
        rotationId: requestOptions.rotationId,
        incidentRef: requestOptions.incidentRef,
        oldControllerDrainAcknowledgment:
          requestOptions.oldControllerDrainAcknowledgment,
        operatorRequestSha256: requestOptions.operatorRequestSha256,
        predecessorProtocol,
        successorProtocol: targetCompatibility,
        sourceStateVectorSha256: sourceStateVector,
        validation: pendingValidation,
      });
      const pendingTransaction = rootProtocolRotationTransaction(
        root,
        requestOptions.rotationId,
        pendingRequest,
      );
      assertControl(
        generationRecord.generation % 2 === 1
          && sourceStateVector
            === pendingRotation.receipt.source_state_vector_sha256
          && hashObject(pendingRequest)
            === pendingRotation.receipt.request_sha256
          && canonicalJson(pendingTransaction)
            === canonicalJson(pendingRotation.transaction)
          && canonicalJson(generationRecord.active_transaction)
            === canonicalJson(pendingTransaction),
        'STORE_PROTOCOL_ROTATION_SOURCE_CHANGED',
        'pending rotation receipt 的 source/request/odd transaction 已漂移',
      );
      validation = pendingValidation;
    } else if (alreadyRotated) {
      assertControl(
        sourceStateVector
          === alreadyRotated.receipt.source_state_vector_sha256,
        'STORE_PROTOCOL_ROTATION_SOURCE_CHANGED',
        'successor odd recovery 的 source vector 已偏离 sealed receipt',
      );
      validation = normalizeProtocolRotationValidationResult({
        report: alreadyRotated.receipt.validation_report,
      });
    } else {
      try {
        const result = validationCallback({
          root,
          source_state_vector_sha256: sourceStateVector,
          target_decoder_sha256: controllerDecoderFingerprint(),
          predecessor_protocol:
            JSON.parse(JSON.stringify(predecessorProtocol)),
          current_protocol:
            JSON.parse(JSON.stringify(currentProtocol)),
        });
        assertControl(
          !result
            || (
              typeof result !== 'object'
                && typeof result !== 'function'
            )
            || typeof result.then !== 'function',
          'STORE_PROTOCOL_ROTATION_VALIDATOR_ASYNC',
          'protocol rotation validator 必须同步完成',
        );
        validation = normalizeProtocolRotationValidationResult(result);
      } catch (error) {
        let unchanged = false;
        try {
          unchanged = beforeValidationVector
              === readMigrationValidationVector(root, transport)
            && beforeValidationStrictVector
              === readOddRecoveryStateVector(root);
        } catch {
          unchanged = false;
        }
        safeToRelease = unchanged;
        if (!unchanged) {
          const mutationError = new ControlError(
            'STORE_PROTOCOL_ROTATION_VALIDATOR_MUTATED',
            'protocol rotation validator 改写了 control root；保留锁证据',
          );
          mutationError.cause = error;
          throw mutationError;
        }
        throw error;
      }
    }
    if (
      beforeValidationVector
        !== readMigrationValidationVector(root, transport)
        || beforeValidationStrictVector
          !== readOddRecoveryStateVector(root)
    ) {
      safeToRelease = false;
      throw new ControlError(
        'STORE_PROTOCOL_ROTATION_VALIDATOR_MUTATED',
        'protocol rotation validator 改写了 control root；拒绝切换',
      );
    }
    const request = rootProtocolRotationRequest({
      rotationId: requestOptions.rotationId,
      incidentRef: requestOptions.incidentRef,
      oldControllerDrainAcknowledgment:
        requestOptions.oldControllerDrainAcknowledgment,
      operatorRequestSha256: requestOptions.operatorRequestSha256,
      predecessorProtocol,
      successorProtocol: targetCompatibility,
      sourceStateVectorSha256: sourceStateVector,
      validation,
    });
    const rotationTransaction = rootProtocolRotationTransaction(
      root,
      requestOptions.rotationId,
      request,
    );
    if (pendingRotation) {
      assertControl(
        hashObject(request) === pendingRotation.receipt.request_sha256
          && canonicalJson(rotationTransaction)
            === canonicalJson(pendingRotation.transaction),
        'STORE_TRANSACTION_MISMATCH',
        'pending rotation exact retry 重建了不同 request/transaction',
      );
    }
    assertCurrentControllerDecoderFingerprint(
      recoveryBrokerCompatibility.controller_decoder_sha256,
    );
    assertControl(
      transport.transactionHex === null
        || transport.transactionHex
          === atomicTransactionHex(rotationTransaction),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'protocol rotation atomic transport 绑定了不同 transaction',
    );
    let recoveredTimestamp = null;
    if (generationRecord.generation % 2 === 1) {
      assertControl(
        generationRecord.active_transaction
          && generationRecord.active_transaction.key_sha256
            === rotationTransaction.key_sha256,
        'STORE_TRANSACTION_MISMATCH',
        'odd protocol rotation 只能由 exact request 恢复',
      );
      generationRecord = normalizeOddGenerationAtomicTransport(
        root,
        generationRecord,
        rotationTransaction,
      );
      transport = inspectAtomicTransport(
        root,
        atomicTransactionHex(rotationTransaction),
      );
    } else {
      const residual = atomicGenerationResidual(
        root,
        rotationTransaction,
      );
      transport = residual.inspection;
      recoveredTimestamp = residual.timestamp;
      generationRecord = readRootGenerationRecord(root);
    }
    if (
      recoveredTimestamp === null
        && transport.residual
        && Number.isSafeInteger(
          transport.residual.stable_time_milliseconds,
        )
    ) {
      recoveredTimestamp = new Date(
        transport.residual.stable_time_milliseconds,
      ).toISOString();
    }
    if (
      alreadyRotated
        && generationRecord.generation % 2 === 0
    ) {
      assertControl(
        transport.transactionDirectory === null,
        'STORE_ATOMIC_RESIDUAL_UNCONSUMED',
        'completed protocol rotation exact retry 后仍有 atomic transport',
      );
      return completedProtocolRotationResult(
        root,
        alreadyRotated,
        generationRecord,
        { requireExactExitGeneration: true },
      );
    }
    const prospectiveStartedGeneration =
      generationRecord.generation % 2 === 1
      ? {
        schema_version: generationRecord.schema_version,
        generation: generationRecord.generation,
        active_transaction: generationRecord.active_transaction,
        pre_write_vector_sha256:
          generationRecord.pre_write_vector_sha256,
        transaction_started_at: generationRecord.updated_at,
      }
      : {
        schema_version: ROOT_GENERATION_SCHEMA_VERSION,
        generation: generationRecord.generation + 1,
        active_transaction: rotationTransaction,
        pre_write_vector_sha256: readPristinePayloadVector(root, {
          atomicTransportInspection: transport,
        }),
        transaction_started_at: recoveredTimestamp || nowIso(),
      };
    const receiptUnsigned = {
      schema_version: ROOT_PROTOCOL_ROTATION_SCHEMA_VERSION,
      rotation_id: requestOptions.rotationId,
      requested_at:
        prospectiveStartedGeneration.transaction_started_at,
      incident_ref: requestOptions.incidentRef,
      old_controller_drain_ack:
        requestOptions.oldControllerDrainAcknowledgment,
      predecessor_protocol: protocolWithSealSummary(
        predecessorProtocol,
      ),
      successor_protocol: targetCompatibility,
      migration_artifacts_sha256:
        hashObject(predecessorProtocol.migration_artifacts),
      source_state_vector_sha256: sourceStateVector,
      validation_report: validation.report,
      validation_report_sha256: validation.report_sha256,
      goal_worktree_map: validation.goal_worktree_map,
      goal_worktree_map_sha256:
        validation.goal_worktree_map_sha256,
      entry_generation:
        prospectiveStartedGeneration.generation - 1,
      exit_generation:
        prospectiveStartedGeneration.generation + 1,
      operator_request_sha256:
        requestOptions.operatorRequestSha256,
      request_sha256: hashObject(request),
    };
    const receipt = {
      ...receiptUnsigned,
      receipt_sha256: hashObject(receiptUnsigned),
    };
    const receiptArtifact = protocolRotationDescriptor(receipt);
    const predecessorRotations =
      predecessorProtocol.schema_version === ROOT_PROTOCOL_SCHEMA_VERSION
        ? predecessorProtocol.protocol_rotations
        : [];
    const successorUnsigned = {
      ...targetCompatibility,
      migration_source_state_vector_sha256:
        predecessorProtocol.migration_source_state_vector_sha256,
      migration_artifacts: predecessorProtocol.migration_artifacts,
      protocol_rotations: [
        ...predecessorRotations,
        receiptArtifact.descriptor,
      ],
    };
    const successorProtocol = {
      ...successorUnsigned,
      seal_sha256: hashObject(successorUnsigned),
    };
    assertProspectiveProtocolRotationCandidate(
      predecessorProtocol,
      receipt,
      receiptArtifact,
      successorProtocol,
    );
    if (pendingRotation) {
      assertControl(
        canonicalJson(receipt)
            === canonicalJson(pendingRotation.receipt)
          && canonicalJson(receiptArtifact.descriptor)
            === canonicalJson(pendingRotation.descriptor),
        'STORE_PROTOCOL_ROTATION_RECEIPT_CONFLICT',
        'pending rotation exact retry 重建了不同 receipt bytes/descriptor',
      );
    }
    const startedGeneration = generationRecord.generation % 2 === 1
      ? prospectiveStartedGeneration
      : beginRootWrite(
        root,
        rotationTransaction,
        prospectiveStartedGeneration.pre_write_vector_sha256,
        prospectiveStartedGeneration.transaction_started_at,
      );
    assertControl(
      canonicalJson(startedGeneration)
        === canonicalJson(prospectiveStartedGeneration),
      'STORE_PROTOCOL_ROTATION_GENERATION_MISMATCH',
      'rotation generation begin 未使用预验证的 exact candidate timestamp/vector',
    );
    runLockTestHook(
      lockDir,
      options.afterRotationGenerationStarted,
      'protocol rotation generation-started',
    );
    safeToRelease = true;
    withAtomicTransaction(root, rotationTransaction, () => {
      assertCurrentControllerDecoderFingerprint(
        recoveryBrokerCompatibility.controller_decoder_sha256,
      );
      ensureDir(path.join(root, ROOT_PROTOCOL_ROTATION_DIRECTORY));
      atomicCreate(
        path.join(root, receiptArtifact.descriptor.relative_path),
        receiptArtifact.body,
        { fault_namespace: 'PROTOCOL_ROTATION_RECEIPT' },
      );
      const receiptFile = path.join(
        root,
        receiptArtifact.descriptor.relative_path,
      );
      const receiptStat = fs.lstatSync(receiptFile);
      assertControl(
        receiptStat.isFile()
          && !receiptStat.isSymbolicLink()
          && (receiptStat.mode & 0o777) === 0o600
          && fs.readFileSync(receiptFile).equals(receiptArtifact.body),
        'STORE_PROTOCOL_ROTATION_RECEIPT_CONFLICT',
        'protocol rotation receipt 既有 identity/mode/bytes 不匹配',
      );
      runLockTestHook(
        lockDir,
        options.afterRotationReceiptInstalled,
        'protocol rotation receipt-installed',
      );
      currentSnapshot = rotationProtocolSnapshot(root);
      currentProtocol = currentSnapshot.protocol;
      const protocolTransport = inspectAtomicTransport(
        root,
        atomicTransactionHex(rotationTransaction),
      );
      const protocolTransportRequiresCompletion =
        protocolTransport.residual
          && protocolTransport.residual.target
            === rootProtocolFile(root);
      if (
        canonicalJson(currentProtocol)
          !== canonicalJson(successorProtocol)
          || protocolTransportRequiresCompletion
      ) {
        assertControl(
          currentProtocol.seal_sha256
            === predecessorProtocol.seal_sha256
            || (
              protocolTransportRequiresCompletion
                && canonicalJson(currentProtocol)
                  === canonicalJson(successorProtocol)
            ),
          'STORE_PROTOCOL_ROTATION_PREDECESSOR_MISMATCH',
          'protocol publication/recovery 前 canonical seal 漂移',
        );
        atomicWriteJson(
          rootProtocolFile(root),
          successorProtocol,
          { fault_namespace: 'PROTOCOL_ROTATION_PROTOCOL' },
        );
      }
      cleanupExactProtocolRotationMkdirLineage(
        root,
        rotationTransaction,
        successorProtocol,
        receiptArtifact,
        receipt,
      );
      runLockTestHook(
        lockDir,
        options.afterRotationProtocolInstalled,
        'protocol rotation protocol-installed',
      );
      assertControl(
        canonicalJson(readRootProtocolSeal(root))
          === canonicalJson(successorProtocol),
        'STORE_PROTOCOL_ROTATION_PUBLICATION_MISMATCH',
        'successor protocol publication bytes 不匹配',
      );
      assertCurrentControllerDecoderFingerprint(
        recoveryBrokerCompatibility.controller_decoder_sha256,
      );
      assertOwnedDirectory(
        lockDir,
        WRITER_LOCK_KIND,
        lockOwner,
        protocolBinding,
      );
      assertAtomicTransactionClean(root, rotationTransaction);
      runLockTestHook(
        lockDir,
        options.beforeRotationGenerationComplete,
        'protocol rotation before-generation-complete',
      );
      completeRootWrite(root, startedGeneration);
    });
    const strictProtocol = readRootProtocolForRotationTarget(
      root,
      targetCompatibility,
    );
    return {
      rotated: true,
      idempotent: false,
      predecessor_protocol: protocolWithSealSummary(
        predecessorProtocol,
      ),
      protocol: strictProtocol,
      entry_generation: receipt.entry_generation,
      exit_generation: receipt.exit_generation,
      source_state_vector_sha256: sourceStateVector,
      sealed_state_vector_sha256: readControlStateVector(root),
      rotation_receipt: receiptArtifact.descriptor,
      validation: validation.report,
    };
  } finally {
    if (safeToRelease) {
      releaseOwnedDirectory(
        lockDir,
        WRITER_LOCK_KIND,
        lockOwner,
        null,
        protocolBinding,
      );
    }
  }
}

function adoptRootProtocol(root, validationCallback, options = {}) {
  assertControl(
    typeof validationCallback === 'function',
    'STORE_MIGRATION_VALIDATOR_REQUIRED',
    'root protocol migration 必须提供完整 replay/decoder validation callback',
  );
  const { lockDir, lockOwner } = acquireRootWriterLock(root, options);
  let safeToRelease = true;
  try {
    assertOwnedDirectory(lockDir, WRITER_LOCK_KIND, lockOwner);
    let generationRecord = readRootGenerationRecord(root);
    if (generationRecord.generation % 2 === 0) {
      cleanupCompletedEvenAtomicClaim(root);
      generationRecord = readRootGenerationRecord(root);
    }
    let transport = inspectAtomicTransport(root);
    let recoveredGenerationTimestamp = null;
    const existing = readRootProtocol(root);
    const adopting = existing === null;
    const sourceStateVector = readMigrationSourceStateVector(
      root,
      transport,
    );
    const beforeValidationVector = readMigrationValidationVector(
      root,
      transport,
    );
    const beforeValidationStrictVector = readOddRecoveryStateVector(root);
    let normalizedResult;
    try {
      const validationResult = validationCallback({
        root,
        state_vector_sha256: sourceStateVector,
        decoder_sha256: controllerDecoderFingerprint(),
        existing_protocol: existing === null
          ? null
          : JSON.parse(JSON.stringify(existing)),
        adopting,
      });
      assertControl(
        !validationResult
          || (typeof validationResult !== 'object' && typeof validationResult !== 'function')
          || typeof validationResult.then !== 'function',
        'STORE_MIGRATION_VALIDATOR_ASYNC',
        'decoder migration validator 必须同步完成；异步 validator 不得在 replay 完成前安装 seal',
      );
      normalizedResult = normalizeMigrationValidationResult(
        validationResult,
        adopting,
        existing,
      );
    } catch (error) {
      let unchanged = false;
      try {
        unchanged = beforeValidationVector
            === readMigrationValidationVector(root, transport)
          && beforeValidationStrictVector
            === readOddRecoveryStateVector(root);
      } catch {
        unchanged = false;
      }
      safeToRelease = unchanged;
      if (!unchanged) {
        const mutationError = new ControlError(
          'STORE_MIGRATION_VALIDATOR_MUTATED',
          'decoder migration validator 改写了 control root bytes；拒绝 seal 并保留锁证据',
        );
        mutationError.cause = error;
        throw mutationError;
      }
      throw error;
    }
    const afterValidationVector = readMigrationValidationVector(
      root,
      transport,
    );
    if (
      beforeValidationVector !== afterValidationVector
        || beforeValidationStrictVector !== readOddRecoveryStateVector(root)
    ) {
      safeToRelease = false;
      throw new ControlError(
        'STORE_MIGRATION_VALIDATOR_MUTATED',
        'decoder migration validator 改写了 control root bytes；拒绝 seal 并保留锁证据',
      );
    }
    const adoptionTransaction = rootProtocolAdoptionTransaction(
      root,
      sourceStateVector,
      normalizedResult.descriptors,
    );
    assertControl(
      transport.transactionHex === null
        || transport.transactionHex
          === atomicTransactionHex(adoptionTransaction),
      'STORE_ATOMIC_RESIDUAL_CONFLICT',
      'root protocol adoption transport 绑定了不同 transaction',
    );
    const interruptedGeneration = generationRecord.generation % 2 === 1;
    if (generationRecord.generation % 2 === 1) {
      assertControl(
        !generationRecord.legacy
          && generationRecord.active_transaction
          && generationRecord.active_transaction.kind
            === 'AUDITED_REPAIR_ONLY'
          && generationRecord.active_transaction.key_sha256
            === adoptionTransaction.key_sha256,
        'AUDITED_REPAIR_ONLY',
        'odd audited repair 只能由 exact root protocol adoption transaction 恢复',
      );
    }

    const interrupted = generationRecord.generation % 2 === 1
      || transport.transactionDirectory !== null;
    if (existing && !interrupted) {
      const sealedStateVector = readControlStateVector(root);
      return {
        adopted: false,
        idempotent: true,
        repaired_interrupted_generation: false,
        protocol: existing,
        state_vector_sha256: sourceStateVector,
        source_state_vector_sha256: sourceStateVector,
        sealed_state_vector_sha256: sealedStateVector,
        migration_artifacts: normalizedResult.artifacts.map((artifact) => ({
          relative_path: artifact.relative_path,
          sha256: artifact.sha256,
          created: false,
          idempotent: true,
        })),
        validation: normalizedResult.report,
      };
    }

    safeToRelease = false;
    if (generationRecord.generation % 2 === 1) {
      generationRecord = normalizeOddGenerationAtomicTransport(
        root,
        generationRecord,
        adoptionTransaction,
      );
    }
    generationRecord = readRootGenerationRecord(root);
    if (generationRecord.generation % 2 === 1) {
      transport = inspectAtomicTransport(
        root,
        atomicTransactionHex(adoptionTransaction),
      );
    } else {
      const generationResidual = atomicGenerationResidual(
        root,
        adoptionTransaction,
      );
      transport = generationResidual.inspection;
      recoveredGenerationTimestamp = generationResidual.timestamp;
      generationRecord = readRootGenerationRecord(root);
    }
    let artifactOutcomes;
    let protocol;
    withAtomicTransaction(root, adoptionTransaction, () => {
      const startedGeneration = generationRecord.generation % 2 === 1
        ? {
          schema_version: generationRecord.schema_version,
          generation: generationRecord.generation,
          active_transaction: generationRecord.active_transaction,
          pre_write_vector_sha256:
            generationRecord.pre_write_vector_sha256,
          transaction_started_at: generationRecord.updated_at,
        }
        : beginRootWrite(
          root,
          adoptionTransaction,
          readPristinePayloadVector(root, {
            atomicTransportInspection: transport,
          }),
          recoveredGenerationTimestamp,
        );
      artifactOutcomes = installMigrationArtifacts(
        root,
        normalizedResult.artifacts,
      );
      runLockTestHook(
        lockDir,
        options.afterMigrationArtifactsInstalled,
        'migration artifact publication',
      );
      protocol = ensureRootProtocol(root, {
        migrationSourceStateVectorSha256: sourceStateVector,
        migrationArtifacts: normalizedResult.descriptors,
        atomicOptions: {
          fault_namespace: 'MIGRATION_PROTOCOL',
        },
      });
      assertOwnedDirectory(lockDir, WRITER_LOCK_KIND, lockOwner);
      assertAtomicTransactionClean(root, adoptionTransaction);
      completeRootWrite(root, startedGeneration);
    });
    const sealedStateVector = readControlStateVector(root);
    safeToRelease = true;
    return {
      adopted: adopting,
      idempotent: !adopting,
      repaired_interrupted_generation:
        interruptedGeneration,
      protocol,
      state_vector_sha256: sourceStateVector,
      source_state_vector_sha256: sourceStateVector,
      sealed_state_vector_sha256: sealedStateVector,
      migration_artifacts: artifactOutcomes,
      validation: normalizedResult.report,
    };
  } finally {
    if (safeToRelease) {
      releaseOwnedDirectory(lockDir, WRITER_LOCK_KIND, lockOwner);
    }
  }
}

function withStableRead(root, callback, options = {}) {
  const lockDir = path.join(root, '.lock');
  const reaperMutex = `${lockDir}.reap`;
  const timeoutMilliseconds = options.timeoutMilliseconds
    ?? DEFAULT_CONTROL_CONTENTION_TIMEOUT_MILLISECONDS;
  const liveOwnerTimeoutMilliseconds = options.timeoutMilliseconds
    ?? DEFAULT_LIVE_V2_CONTENTION_TIMEOUT_MILLISECONDS;
  const retryMilliseconds = options.retryMilliseconds ?? 25;
  const maxTransientRetries = options.maxTransientRetries ?? 3;
  const started = Date.now();
  const liveOwnerSlots = new Set();
  let transientRetries = 0;
  const hasLiveOwnerBudget = (slot, contention) => {
    if (contention.kind === 'LIVE_V2') {
      liveOwnerSlots.add(slot);
      return true;
    }
    return contention.kind === 'TRANSITION' && liveOwnerSlots.has(slot);
  };
  const waitForStableSnapshot = (useLiveOwnerBudget = false) => {
    const waitTimeoutMilliseconds = useLiveOwnerBudget
      ? liveOwnerTimeoutMilliseconds
      : timeoutMilliseconds;
    if (Date.now() - started >= waitTimeoutMilliseconds) {
      throw new ControlError(
        'LOCK_TIMEOUT',
        `控制面只读快照等待超过 ${waitTimeoutMilliseconds}ms`,
      );
    }
    sleepSync(retryMilliseconds);
  };
  while (true) {
    let crashedWriter = null;
    const reaperContention = observeOwnedDirectoryContention(
      reaperMutex,
      REAPER_LOCK_KIND,
    );
    if (reaperContention.kind === 'INVALID') {
      throw reaperContention.error;
    }
    if (reaperContention.kind !== 'ABSENT') {
      waitForStableSnapshot(
        hasLiveOwnerBudget(reaperMutex, reaperContention),
      );
      continue;
    }
    const writerContention = observeOwnedDirectoryContention(
      lockDir,
      WRITER_LOCK_KIND,
    );
    if (writerContention.kind === 'INVALID') {
      throw writerContention.error;
    }
    if (writerContention.kind !== 'ABSENT') {
      if (
        ['LIVE_V2', 'TRANSITION'].includes(writerContention.kind)
      ) {
        waitForStableSnapshot(
          hasLiveOwnerBudget(lockDir, writerContention),
        );
        continue;
      }
      const observed = observeOwnedDirectory(
        lockDir,
        WRITER_LOCK_KIND,
        readRootProtocol(root),
      );
      if (
        observed
          && observed.format === 'v2'
          && ownedDirectoryIsStale(observed, 0)
      ) {
        if (options.allowOddCrashInspection === true) {
          crashedWriter = observed;
        } else {
          const generation = readRootGeneration(root);
          throw new ControlError(
            'STORE_REPAIR_REQUIRED',
            `控制面 writer pid=${observed.owner.pid} 已退出，generation=${generation} 为未完成写入提示；须用原 stable operation ID 精确写重试，不能等待或读取为完整 state`,
            {
              generation,
              writer_crash_marker: generation % 2 === 1,
              stale_writer_pid: observed.owner.pid,
              state_verified: false,
              required_action: 'retry the original write with the same stable operation ID, or use an audited repair path',
            },
          );
        }
      } else {
        waitForStableSnapshot();
        continue;
      }
    }
    const beforeProtocol = readRootProtocol(root);
    const beforeGenerationRecord = readRootGenerationRecord(root);
    const beforeGeneration = beforeGenerationRecord.generation;
    if (
      beforeGeneration % 2 === 1
        && options.allowOddCrashInspection !== true
    ) {
      throw new ControlError(
        'STORE_REPAIR_REQUIRED',
        `控制面 generation=${beforeGeneration} 是 writer crash marker，且当前无 writer lock；不要等待或猜测完整 state，须用原 stable operation ID 精确写重试，或走审计 repair`,
        {
          generation: beforeGeneration,
          writer_crash_marker: true,
          state_verified: false,
          required_action: 'retry the original write with the same stable operation ID, or use an audited repair path',
        },
      );
    }
    const beforeStateVector = readControlStateVector(root);
    try {
      const value = callback();
      const afterStateVector = readControlStateVector(root);
      const afterGenerationRecord = readRootGenerationRecord(root);
      const afterGeneration = afterGenerationRecord.generation;
      const afterProtocol = readRootProtocol(root);
      const crashedWriterStillSame = crashedWriter
        ? (
          fs.existsSync(lockDir)
            && sameOwnedDirectory(
              crashedWriter,
              observeOwnedDirectory(
                lockDir,
                WRITER_LOCK_KIND,
                afterProtocol,
              ),
            )
            && ownedDirectoryIsStale(crashedWriter, 0)
        )
        : !fs.existsSync(lockDir);
      if (
        crashedWriterStillSame
        && !fs.existsSync(reaperMutex)
        && canonicalJson(beforeProtocol) === canonicalJson(afterProtocol)
        && beforeGeneration === afterGeneration
        && hashObject(beforeGenerationRecord)
          === hashObject(afterGenerationRecord)
        && beforeStateVector === afterStateVector
        && (
          afterGeneration % 2 === 0
            || options.allowOddCrashInspection === true
        )
      ) {
        if (
          (afterGeneration % 2 === 1 || crashedWriter)
            && value
            && typeof value === 'object'
            && !Array.isArray(value)
        ) {
          return {
            ...value,
            control_store_read: {
              complete: afterGeneration % 2 === 0,
              generation: afterGeneration,
              writer_crash_marker: afterGeneration % 2 === 1,
              stale_writer: Boolean(crashedWriter),
              transaction_kind:
                afterGenerationRecord.active_transaction
                  ? afterGenerationRecord.active_transaction.kind
                  : null,
              required_action: afterGeneration % 2 === 1
                ? 'retry the original write with the same stable operation ID'
                : 'none',
            },
          };
        }
        return value;
      }
    } catch (error) {
      const transient = error instanceof ControlError
        && ['CORRUPT_STORE', 'STORE_REPAIR_REQUIRED', 'STORE_VECTOR_CHANGED'].includes(error.code);
      if (!transient || transientRetries >= maxTransientRetries) throw error;
      transientRetries += 1;
    }
    waitForStableSnapshot();
  }
}

function goalDir(root, goalId) {
  return path.join(root, 'goals', goalId);
}

function eventDir(root, goalId, taskId) {
  return path.join(goalDir(root, goalId), 'events', taskId);
}

function rejectionDir(root, goalId, taskId) {
  return path.join(goalDir(root, goalId), 'rejections', taskId);
}

function acceptedEventFiles(root, goalId, taskId) {
  const dir = eventDir(root, goalId, taskId);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((name) => name.endsWith('.json')).sort().map((name) => path.join(dir, name));
}

function goalMergeTargetReservations(root, goalId, targetEventId = null) {
  const eventsRoot = path.join(goalDir(root, goalId), 'events');
  if (!fs.existsSync(eventsRoot)) return [];
  const reservations = [];
  for (const taskId of fs.readdirSync(eventsRoot).sort()) {
    const taskDir = path.join(eventsRoot, taskId);
    let stat;
    try {
      stat = fs.lstatSync(taskDir);
    } catch (error) {
      throw new ControlError(
        'CORRUPT_STORE',
        `无法读取 task event directory ${taskId}: ${error.message}`,
      );
    }
    assertControl(
      stat.isDirectory() && !stat.isSymbolicLink(),
      'CORRUPT_STORE',
      `task event path ${taskId} 不是普通目录`,
    );
    for (const file of acceptedEventFiles(root, goalId, taskId)) {
      const event = readJson(file, `accepted event ${path.basename(file)}`);
      if (event.type !== 'GITHUB_MERGE_RESERVED') continue;
      assertControl(
        event.goal_id === goalId
          && event.task_id === taskId
          && event.payload
          && typeof event.payload.target_event_id === 'string'
          && /^sha256:[0-9a-f]{64}$/.test(event.payload.request_sha256),
        'CORRUPT_STORE',
        `GitHub merge reservation ${event.event_id} binding 非法`,
      );
      if (
        targetEventId === null
          || event.payload.target_event_id === targetEventId
      ) {
        reservations.push(event);
      }
    }
  }
  if (targetEventId !== null) {
    assertControl(
      reservations.length <= 1,
      'CORRUPT_STORE',
      `target event ${targetEventId} 有多个 GitHub merge reservations`,
    );
  }
  return reservations;
}

function assertTaskEventNotReserved(root, goalId, event) {
  const reservations = goalMergeTargetReservations(
    root,
    goalId,
    event.event_id,
  );
  if (reservations.length === 0) return;
  const reservation = reservations[0];
  assertControl(
    event.type === 'MERGED'
      && event.task_id === reservation.task_id
      && event.payload
      && event.payload.merge_reservation_event_id === reservation.event_id
      && event.payload.merge_request_sha256
        === reservation.payload.request_sha256,
    'EVENT_ID_RESERVED',
    `event id ${event.event_id} 已由 append-only GitHub merge reservation ${reservation.event_id} 占用`,
  );
}

function eventHeadFile(root, goalId, taskId) {
  return path.join(goalDir(root, goalId), 'event-heads', `${taskId}.json`);
}

function sealedEventHead(value) {
  const head = { ...value };
  head.head_sha256 = hashObject(head);
  return head;
}

function sealChainedRecord(record, sequence, previousEventHash) {
  const sealed = {
    ...record,
    log_sequence: sequence,
    previous_event_sha256: previousEventHash,
  };
  sealed.event_sha256 = hashObject(sealed);
  return sealed;
}

function writeAcceptedEvent(root, goalId, taskId, revision, event, previousEventHash) {
  assertTaskEventNotReserved(root, goalId, event);
  const sealed = sealChainedRecord(event, revision, previousEventHash);
  const safeEventId = event.event_id.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
  const file = path.join(eventDir(root, goalId, taskId), `${String(revision).padStart(8, '0')}-${safeEventId}.json`);
  assertControl(!fs.existsSync(file), 'EVENT_FILE_EXISTS', `事件文件已存在: ${file}`);
  const injectPostInstallFault = process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL === '1';
  if (injectPostInstallFault) {
    const temporaryRoot = trustedTemporaryRoot();
    const resolvedRoot = fs.realpathSync(root);
    assertControl(
      process.env.GOAL_CONTROL_TEST_MODE === '1'
        && resolvedRoot !== temporaryRoot
        && resolvedRoot.startsWith(`${temporaryRoot}${path.sep}`),
      'TEST_MODE_FORBIDDEN',
      'accepted-event fault injection 只允许隔离测试目录',
    );
  }
  atomicWriteJson(file, sealed);
  if (injectPostInstallFault) {
    throw new ControlError('TEST_FAULT_AFTER_EVENT_INSTALL', 'injected failure after accepted event install');
  }
  let headError = null;
  try {
    atomicWriteJson(eventHeadFile(root, goalId, taskId), sealedEventHead({
      schema_version: 1,
      task_id: taskId,
      event_count: revision,
      state_revision: revision,
      last_event_sha256: sealed.event_sha256,
      updated_at: sealed.accepted_at,
    }));
  } catch (error) {
    headError = error;
  }
  return { file, event: sealed, headError };
}

function readJsonIfExists(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new ControlError('CORRUPT_STORE', `${file} 不是合法 JSON: ${error.message}`);
  }
}

module.exports = {
  acceptedEventFiles,
  adoptSourceImportIntentPublication,
  goalMergeTargetReservations,
  adoptRootProtocol,
  atomicCreate,
  atomicResidualCreate,
  atomicResidualWrite,
  atomicWrite,
  atomicWriteJson,
  canonicalJson,
  canonicalTransactionKey,
  controllerDecoderFingerprint,
  controllerDecoderFingerprintAt,
  encodeAtomicCleanupManifest,
  ensureDir,
  ensureRootProtocol,
  eventHeadFile,
  eventDir,
  goalDir,
  historicalTransactionKeySha256,
  isHistoricalTransactionRetry,
  isOddTransactionRetry,
  isPreWitnessTransactionRetry,
  readProtocolSealedMigrationArtifact,
  readProtocolSealedRotationReceipts,
  readPrivateAtomicArtifact,
  readJsonIfExists,
  readRootProtocolSeal,
  readRootProtocolSealForRotation,
  rejectionDir,
  sealChainedRecord,
  sealedEventHead,
  rotateRootProtocol,
  withLock,
  withAtomicTransaction,
  withStableRead,
  writeAcceptedEvent,
};
