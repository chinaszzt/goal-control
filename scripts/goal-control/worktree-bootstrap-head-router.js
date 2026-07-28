'use strict';

const path = require('path');
const {
  assertPrivateDirectory,
  inspectPrivateJsonPublication,
  parsePrivateJson,
  parsePrivateJsonBytes,
  recoverPrivateJsonPublication,
} = require('./canary-bootstrap-artifacts');
const { assertControl } = require('./errors');
const {
  attachFilesHeadTransaction,
  prepareFilesHeadProtocolBinding,
  verifyFilesHeadTransaction,
} = require('./worktree-bootstrap-files-head-transaction');
const {
  CLAIM_KIND,
  FILES_TRANSACTION_PROTOCOL,
  HEAD_TRANSACTION_SECURITY,
  NATIVE_TRANSACTION_INTERNALS,
  NATIVE_TRANSACTION_PROTOCOL,
  TRANSACTION_PROTOCOLS,
  attachWorktreeBootstrapHead: attachNativeHead,
  captureWorktreeGitdirIdentity,
  verifyWorktreeBootstrapHead: verifyNativeHead,
} = require('./worktree-bootstrap-head-transaction');
const {
  canonicalJson,
  hashObject,
  normalizeHash,
  safeId,
} = require('./util');

const FULL_OID_RE = /^[0-9a-f]{40}$/;
const FILES_MINIMUM_GIT_MAJOR = 2;
const FILES_MINIMUM_GIT_MINOR = 43;

function assertFilesGitVersion(rawOptions, context) {
  const version = NATIVE_TRANSACTION_INTERNALS.gitVersion(
    rawOptions.cwd,
    context.codes,
  );
  assertControl(
    version.major > FILES_MINIMUM_GIT_MAJOR
      || (
        version.major === FILES_MINIMUM_GIT_MAJOR
          && version.minor >= FILES_MINIMUM_GIT_MINOR
      ),
    context.codes.identity,
    `files-backend HEAD protocol 要求 Git >= ${
      FILES_MINIMUM_GIT_MAJOR
    }.${FILES_MINIMUM_GIT_MINOR}`,
  );
  return version;
}

function protocolPaths(rawOptions) {
  return {
    headFenceFile: rawOptions.headFenceFile || path.join(
      path.dirname(rawOptions.branchFenceFile),
      'head-transaction.fence',
    ),
    completionFile: rawOptions.completionFile || path.join(
      path.dirname(rawOptions.branchFenceFile),
      'head-transaction-completion.json',
    ),
  };
}

function normalizedInputs(rawOptions, codes, createArtifacts) {
  assertControl(
    rawOptions
      && typeof rawOptions.cwd === 'string'
      && typeof rawOptions.artifactRoot === 'string'
      && typeof rawOptions.branchFenceFile === 'string'
      && typeof rawOptions.operationId === 'string'
      && typeof rawOptions.targetRef === 'string'
      && FULL_OID_RE.test(rawOptions.expectedDetachedOid)
      && rawOptions.expectedRegistry
      && typeof rawOptions.expectedRegistry === 'object'
      && !Array.isArray(rawOptions.expectedRegistry),
    codes.identity,
    'worktree bootstrap HEAD router 参数非法',
  );
  safeId(rawOptions.operationId, 'worktree bootstrap operation_id');
  const artifactRoot = path.resolve(rawOptions.artifactRoot);
  assertControl(
    artifactRoot === rawOptions.artifactRoot,
    codes.artifact,
    'artifact root 必须是 normalized absolute path',
  );
  assertPrivateDirectory(
    artifactRoot,
    'worktree bootstrap artifact root',
    createArtifacts,
  );
  const identity = captureWorktreeGitdirIdentity(
    rawOptions.cwd,
    codes,
  );
  const expectedWorktreeKeySha256 = normalizeHash(
    rawOptions.expectedWorktreeKeySha256,
    'expected worktree identity key',
  );
  assertControl(
    identity.worktree_key_sha256 === expectedWorktreeKeySha256,
    codes.identity,
    'actual worktree identity 与 durable observation key 不匹配',
  );
  const expectedDetachedRegistry = {
    worktree: identity.cwd,
    head: rawOptions.expectedDetachedOid,
    branch: null,
    detached: true,
  };
  assertControl(
    canonicalJson(rawOptions.expectedRegistry)
      === canonicalJson(expectedDetachedRegistry),
    codes.identity,
    'durable observation registry 必须是 exact detached worker record',
  );
  return {
    artifactRoot,
    codes,
    expectedDetachedRegistry,
    expectedWorktreeKeySha256,
    identity,
    operationBindingSha256: normalizeHash(
      rawOptions.operationBindingSha256,
      'worktree bootstrap operation binding',
    ),
    ...protocolPaths(rawOptions),
  };
}

function commonClaimUnsigned(rawOptions, context, protocol) {
  return {
    schema_version: 1,
    kind: CLAIM_KIND,
    transaction_protocol: protocol,
    worktree: context.identity,
    expected_registry: context.expectedDetachedRegistry,
    operation_id: rawOptions.operationId,
    operation_binding_sha256: context.operationBindingSha256,
    expected_worktree_key_sha256:
      context.expectedWorktreeKeySha256,
    expected_detached_oid: rawOptions.expectedDetachedOid,
    target_ref: rawOptions.targetRef,
  };
}

function legacyNativeClaimUnsigned(rawOptions, context) {
  const claim = commonClaimUnsigned(
    rawOptions,
    context,
    NATIVE_TRANSACTION_PROTOCOL,
  );
  delete claim.transaction_protocol;
  return claim;
}

function filesOptions(rawOptions, context, protocolBinding) {
  return {
    identity: context.identity,
    artifactRoot: context.artifactRoot,
    branchFenceFile: rawOptions.branchFenceFile,
    headFenceFile: context.headFenceFile,
    completionFile: context.completionFile,
    operationId: rawOptions.operationId,
    operationBindingSha256: context.operationBindingSha256,
    expectedWorktreeKeySha256:
      context.expectedWorktreeKeySha256,
    expectedDetachedRegistry: context.expectedDetachedRegistry,
    expectedIndex: rawOptions.expectedIndex,
    expectedOid: rawOptions.expectedDetachedOid,
    targetRef: rawOptions.targetRef,
    protocolBinding,
    codes: context.codes,
    onStage: rawOptions.onStage,
  };
}

function filesClaimUnsigned(rawOptions, context, binding) {
  return {
    ...commonClaimUnsigned(
      rawOptions,
      context,
      FILES_TRANSACTION_PROTOCOL,
    ),
    files_transaction_binding: binding,
  };
}

function exactStoredClaim(record, rawOptions, context) {
  const {
    claim_request_sha256: requestSha256,
    ...unsigned
  } = record.value || {};
  const legacyNative = record.value
    && record.value.transaction_protocol === undefined;
  assertControl(
    record.value
      && (
        legacyNative
          || TRANSACTION_PROTOCOLS.includes(
            record.value.transaction_protocol,
          )
      )
      && requestSha256 === hashObject(unsigned),
    context.codes.claimConflict,
    'stored worktree HEAD claim protocol/request hash 非法',
  );
  const expected = legacyNative
    ? legacyNativeClaimUnsigned(rawOptions, context)
    : record.value.transaction_protocol === NATIVE_TRANSACTION_PROTOCOL
      ? commonClaimUnsigned(
        rawOptions,
        context,
        NATIVE_TRANSACTION_PROTOCOL,
      )
      : filesClaimUnsigned(
        rawOptions,
        context,
        record.value.files_transaction_binding,
      );
  assertControl(
    canonicalJson(unsigned) === canonicalJson(expected),
    context.codes.claimConflict,
    'stored worktree HEAD claim 与 exact operation/protocol 不匹配',
  );
  return {
    claimUnsigned: expected,
    legacyNative,
    protocol: legacyNative
      ? NATIVE_TRANSACTION_PROTOCOL
      : record.value.transaction_protocol,
  };
}

function requestedProtocol(rawOptions, codes) {
  if (rawOptions.transactionProtocol === undefined) return null;
  assertControl(
    TRANSACTION_PROTOCOLS.includes(rawOptions.transactionProtocol),
    codes.identity,
    `未知 worktree HEAD transaction protocol: ${
      rawOptions.transactionProtocol
    }`,
  );
  return rawOptions.transactionProtocol;
}

function freshFilesClaim(rawOptions, context) {
  assertFilesGitVersion(rawOptions, context);
  const binding = prepareFilesHeadProtocolBinding(
    filesOptions(rawOptions, context, null),
  );
  return {
    claimUnsigned: filesClaimUnsigned(
      rawOptions,
      context,
      binding,
    ),
    protocol: FILES_TRANSACTION_PROTOCOL,
  };
}

function recoverClaimPublicationBeforeProtocol(rawOptions, context) {
  const paths = NATIVE_TRANSACTION_INTERNALS.claimBasePaths(
    context.artifactRoot,
    context.identity,
  );
  if (!HEAD_TRANSACTION_SECURITY.lstatIfPresent(
    paths.claimDirectory,
    context.codes.claimConflict,
    'worktree claim directory',
  )) return;
  const inspected = inspectPrivateJsonPublication(
    paths.claim,
    'worktree bootstrap head claim',
    context.codes.claimConflict,
  );
  if (inspected.state !== 'PUBLISHED_TEMP_PENDING_UNLINK') return;
  const ownerRequestSha256 =
    NATIVE_TRANSACTION_INTERNALS.ownerAnchorRequestSha256(
      context.artifactRoot,
      context.identity,
      context.codes,
    );
  const record = parsePrivateJsonBytes(
    inspected.bytes,
    'worktree bootstrap head claim',
  );
  const selected = exactStoredClaim(
    record,
    rawOptions,
    context,
  );
  const requested = requestedProtocol(rawOptions, context.codes);
  assertControl(
    ownerRequestSha256 === hashObject(selected.claimUnsigned)
      && (
        requested === null
          || requested === selected.protocol
      ),
    context.codes.claimConflict,
    'pending claim publication 与 exact owner/protocol 不匹配',
  );
  recoverPrivateJsonPublication(
    paths.claim,
    'worktree bootstrap head claim',
    context.codes.claimConflict,
  );
}

function resolveClaimProtocol(rawOptions, context) {
  const requested = requestedProtocol(rawOptions, context.codes);
  const existing = NATIVE_TRANSACTION_INTERNALS.existingClaimRecord(
    context.artifactRoot,
    context.identity,
    context.codes,
  );
  if (existing) {
    const resolved = exactStoredClaim(
      existing.record,
      rawOptions,
      context,
    );
    assertControl(
      requested === null || requested === resolved.protocol,
      context.codes.claimConflict,
      'explicit protocol 与 durable claim protocol 不匹配',
    );
    return resolved;
  }

  const ownedRequestSha256 =
    NATIVE_TRANSACTION_INTERNALS.ownerAnchorRequestSha256(
      context.artifactRoot,
      context.identity,
      context.codes,
    );
  const native = {
    claimUnsigned: commonClaimUnsigned(
      rawOptions,
      context,
      NATIVE_TRANSACTION_PROTOCOL,
    ),
    protocol: NATIVE_TRANSACTION_PROTOCOL,
  };
  if (ownedRequestSha256) {
    const legacyNative = {
      claimUnsigned: legacyNativeClaimUnsigned(
        rawOptions,
        context,
      ),
      legacyNative: true,
      protocol: NATIVE_TRANSACTION_PROTOCOL,
    };
    if (
      hashObject(legacyNative.claimUnsigned)
        === ownedRequestSha256
    ) {
      assertControl(
        requested === null
          || requested === NATIVE_TRANSACTION_PROTOCOL,
        context.codes.claimConflict,
        'legacy owner anchor 只能解释为 native protocol',
      );
      return legacyNative;
    }
    if (hashObject(native.claimUnsigned) === ownedRequestSha256) {
      assertControl(
        requested === null
          || requested === NATIVE_TRANSACTION_PROTOCOL,
        context.codes.claimConflict,
        'explicit protocol 与 durable owner anchor 不匹配',
      );
      return native;
    }
    const files = freshFilesClaim(rawOptions, context);
    assertControl(
      hashObject(files.claimUnsigned) === ownedRequestSha256
        && (
          requested === null
            || requested === FILES_TRANSACTION_PROTOCOL
        ),
      context.codes.claimConflict,
      'durable owner anchor 无法解析为 exact supported protocol',
    );
    return files;
  }

  if (requested === NATIVE_TRANSACTION_PROTOCOL) return native;
  if (requested === FILES_TRANSACTION_PROTOCOL) {
    return freshFilesClaim(rawOptions, context);
  }
  return NATIVE_TRANSACTION_INTERNALS.gitVersion(
    rawOptions.cwd,
    context.codes,
  ).native_symref_transaction_supported
    ? native
    : freshFilesClaim(rawOptions, context);
}

function legacyNativeEvidence(rawOptions, context, durable, idempotent) {
  return {
    schema_version: 1,
    transaction_protocol: NATIVE_TRANSACTION_PROTOCOL,
    git_minimum_version: '2.50',
    worktree_key_sha256: context.identity.worktree_key_sha256,
    claim_file: durable.paths.claim,
    claim_sha256: durable.claimSha256,
    claim_created: durable.claimCreated,
    operation_id: rawOptions.operationId,
    operation_binding_sha256: context.operationBindingSha256,
    expected_worktree_key_sha256:
      context.expectedWorktreeKeySha256,
    git_dir: context.identity.git_dir,
    expected_oid: rawOptions.expectedDetachedOid,
    target_ref: rawOptions.targetRef,
    head_state: 'ATTACHED',
    idempotent,
  };
}

function attachLegacyNativeHead(rawOptions, context, selected) {
  NATIVE_TRANSACTION_INTERNALS.assertBootstrapBranchFinalState(
    context.identity,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    context.artifactRoot,
    rawOptions.branchFenceFile,
    context.codes,
  );
  let head = NATIVE_TRANSACTION_INTERNALS.readHead(
    context.identity,
    rawOptions.expectedDetachedOid,
    rawOptions.targetRef,
    context.codes,
  );
  HEAD_TRANSACTION_SECURITY.assertRegistryState(
    context.identity,
    context.expectedDetachedRegistry,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    head.state,
    context.codes,
  );
  const durable = NATIVE_TRANSACTION_INTERNALS.acquireDurableClaim(
    context.artifactRoot,
    context.identity,
    selected.claimUnsigned,
    head.state,
    context.codes,
    { onStage: rawOptions.onStage },
  );
  if (typeof rawOptions.onStage === 'function') {
    rawOptions.onStage('claim-published');
  }
  HEAD_TRANSACTION_SECURITY.assertStaticIdentity(
    context.identity,
    context.codes,
  );
  NATIVE_TRANSACTION_INTERNALS.assertBootstrapBranchFinalState(
    context.identity,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    context.artifactRoot,
    rawOptions.branchFenceFile,
    context.codes,
  );
  head = NATIVE_TRANSACTION_INTERNALS.readHead(
    context.identity,
    rawOptions.expectedDetachedOid,
    rawOptions.targetRef,
    context.codes,
  );
  HEAD_TRANSACTION_SECURITY.assertRegistryState(
    context.identity,
    context.expectedDetachedRegistry,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    head.state,
    context.codes,
  );
  const initiallyAttached = head.state === 'ATTACHED';
  if (!initiallyAttached) {
    const version = NATIVE_TRANSACTION_INTERNALS.gitVersion(
      rawOptions.cwd,
      context.codes,
    );
    assertControl(
      version.native_symref_transaction_supported,
      context.codes.identity,
      'legacy native claim exact retry 要求 Git >= 2.50',
    );
    if (typeof rawOptions.onStage === 'function') {
      rawOptions.onStage('before-git-transaction');
    }
    NATIVE_TRANSACTION_INTERNALS.executeSymrefTransaction(
      context.identity,
      rawOptions.targetRef,
      rawOptions.expectedDetachedOid,
      context.codes,
    );
    if (typeof rawOptions.onStage === 'function') {
      rawOptions.onStage('after-git-transaction');
    }
  }
  HEAD_TRANSACTION_SECURITY.assertStaticIdentity(
    context.identity,
    context.codes,
  );
  NATIVE_TRANSACTION_INTERNALS.assertBootstrapBranchFinalState(
    context.identity,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    context.artifactRoot,
    rawOptions.branchFenceFile,
    context.codes,
  );
  head = NATIVE_TRANSACTION_INTERNALS.readHead(
    context.identity,
    rawOptions.expectedDetachedOid,
    rawOptions.targetRef,
    context.codes,
  );
  assertControl(
    head.state === 'ATTACHED',
    context.codes.headConflict,
    'legacy native transaction 未收敛到 attached HEAD',
  );
  HEAD_TRANSACTION_SECURITY.assertRegistryState(
    context.identity,
    context.expectedDetachedRegistry,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    'ATTACHED',
    context.codes,
  );
  return legacyNativeEvidence(
    rawOptions,
    context,
    durable,
    initiallyAttached,
  );
}

function attachWorktreeBootstrapHead(rawOptions) {
  const codes = NATIVE_TRANSACTION_INTERNALS.transactionCodes(
    rawOptions.codes,
  );
  const context = normalizedInputs(rawOptions, codes, true);
  recoverClaimPublicationBeforeProtocol(rawOptions, context);
  const selected = resolveClaimProtocol(rawOptions, context);
  if (selected.protocol === NATIVE_TRANSACTION_PROTOCOL) {
    if (selected.legacyNative) {
      return attachLegacyNativeHead(rawOptions, context, selected);
    }
    return attachNativeHead(rawOptions);
  }
  assertFilesGitVersion(rawOptions, context);

  const paths = NATIVE_TRANSACTION_INTERNALS.claimPaths(
    context.artifactRoot,
    context.identity,
    hashObject(selected.claimUnsigned),
  );
  const existingClaim =
    NATIVE_TRANSACTION_INTERNALS.existingClaimRecord(
      context.artifactRoot,
      context.identity,
      context.codes,
    );
  let headState = 'ATTACHED';
  if (!existingClaim) {
    headState = NATIVE_TRANSACTION_INTERNALS.readHead(
      context.identity,
      rawOptions.expectedDetachedOid,
      rawOptions.targetRef,
      context.codes,
    ).state;
  }
  const durable = NATIVE_TRANSACTION_INTERNALS.acquireDurableClaim(
    context.artifactRoot,
    context.identity,
    selected.claimUnsigned,
    headState,
    context.codes,
    { onStage: rawOptions.onStage },
  );
  if (typeof rawOptions.onStage === 'function') {
    rawOptions.onStage('claim-published');
  }
  const transaction = attachFilesHeadTransaction({
    ...filesOptions(
      rawOptions,
      context,
      selected.claimUnsigned.files_transaction_binding,
    ),
    claimFile: paths.claim,
    claimSha256: durable.claimSha256,
  });
  return {
    schema_version: 1,
    transaction_protocol: FILES_TRANSACTION_PROTOCOL,
    git_minimum_version: '2.43',
    git_ref_backend: 'files',
    worktree_key_sha256: context.identity.worktree_key_sha256,
    claim_file: paths.claim,
    claim_sha256: durable.claimSha256,
    claim_created: durable.claimCreated,
    operation_id: rawOptions.operationId,
    operation_binding_sha256: context.operationBindingSha256,
    expected_worktree_key_sha256:
      context.expectedWorktreeKeySha256,
    git_dir: context.identity.git_dir,
    expected_oid: rawOptions.expectedDetachedOid,
    target_ref: rawOptions.targetRef,
    head_state: 'ATTACHED',
    ...transaction,
  };
}

function verifyContext(rawOptions, codes) {
  const context = normalizedInputs(rawOptions, codes, false);
  assertControl(
    rawOptions.expectedWorktreeIdentity
      && canonicalJson(context.identity)
        === canonicalJson(rawOptions.expectedWorktreeIdentity),
    codes.identity,
    'actual worktree identity 与 receipt observation 不匹配',
  );
  assertControl(
    typeof rawOptions.expectedClaimFile === 'string',
    codes.claimConflict,
    'HEAD verifier 缺 expected claim path',
  );
  assertPrivateDirectory(
    NATIVE_TRANSACTION_INTERNALS.claimBasePaths(
      context.artifactRoot,
      context.identity,
    ).claimDirectory,
    'worktree head identity claim',
  );
  const existing = NATIVE_TRANSACTION_INTERNALS.existingClaimRecord(
    context.artifactRoot,
    context.identity,
    codes,
  );
  assertControl(
    existing,
    codes.claimConflict,
    'HEAD verifier 缺 durable claim',
  );
  const selected = exactStoredClaim(
    existing.record,
    rawOptions,
    context,
  );
  assertControl(
    selected.protocol === rawOptions.expectedTransactionProtocol,
    codes.claimConflict,
    'receipt expected protocol 与 durable claim 不匹配',
  );
  const claimRequestSha256 = hashObject(selected.claimUnsigned);
  const paths = NATIVE_TRANSACTION_INTERNALS.claimPaths(
    context.artifactRoot,
    context.identity,
    claimRequestSha256,
  );
  assertControl(
    rawOptions.expectedClaimFile === paths.claim
      && existing.record.sha256 === normalizeHash(
        rawOptions.expectedClaimSha256,
        'expected worktree claim SHA-256',
      )
      && NATIVE_TRANSACTION_INTERNALS.inspectClaimOwner(
        paths,
        codes,
      ),
    codes.claimConflict,
    'HEAD verifier claim bytes/path/owner lineage 不匹配',
  );
  return { context, paths, selected };
}

function verifyLegacyNativeHead(rawOptions, verified) {
  const { context, paths } = verified;
  HEAD_TRANSACTION_SECURITY.assertStaticIdentity(
    context.identity,
    context.codes,
  );
  NATIVE_TRANSACTION_INTERNALS.assertBootstrapBranchFinalState(
    context.identity,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    context.artifactRoot,
    rawOptions.branchFenceFile,
    context.codes,
  );
  const head = NATIVE_TRANSACTION_INTERNALS.readHead(
    context.identity,
    rawOptions.expectedDetachedOid,
    rawOptions.targetRef,
    context.codes,
  );
  assertControl(
    head.state === 'ATTACHED',
    context.codes.headConflict,
    'legacy native verifier 要求 final attached HEAD',
  );
  HEAD_TRANSACTION_SECURITY.assertRegistryState(
    context.identity,
    context.expectedDetachedRegistry,
    rawOptions.targetRef,
    rawOptions.expectedDetachedOid,
    'ATTACHED',
    context.codes,
  );
  const evidence = legacyNativeEvidence(
    rawOptions,
    context,
    {
      paths,
      claimSha256: normalizeHash(
        rawOptions.expectedClaimSha256,
        'expected worktree claim SHA-256',
      ),
      claimCreated: false,
    },
    true,
  );
  delete evidence.claim_created;
  delete evidence.idempotent;
  return evidence;
}

function verifyWorktreeBootstrapHead(rawOptions) {
  const codes = NATIVE_TRANSACTION_INTERNALS.transactionCodes(
    rawOptions.codes,
  );
  assertControl(
    TRANSACTION_PROTOCOLS.includes(
      rawOptions.expectedTransactionProtocol,
    ),
    codes.claimConflict,
    'HEAD verifier 必须由 receipt 指定 exact transaction protocol',
  );
  if (
    rawOptions.expectedTransactionProtocol
      === NATIVE_TRANSACTION_PROTOCOL
  ) {
    const verified = verifyContext(rawOptions, codes);
    if (verified.selected.legacyNative) {
      return verifyLegacyNativeHead(rawOptions, verified);
    }
    return verifyNativeHead(rawOptions);
  }
  const { context, selected } = verifyContext(rawOptions, codes);
  assertFilesGitVersion(rawOptions, context);
  const transaction = verifyFilesHeadTransaction({
    ...filesOptions(
      rawOptions,
      context,
      selected.claimUnsigned.files_transaction_binding,
    ),
    claimFile: rawOptions.expectedClaimFile,
    claimSha256: rawOptions.expectedClaimSha256,
    expectedCompletionFile: rawOptions.expectedCompletionFile,
    expectedCompletionSha256:
      rawOptions.expectedCompletionSha256,
  });
  assertControl(
    NATIVE_TRANSACTION_INTERNALS.inspectClaimOwner(
      NATIVE_TRANSACTION_INTERNALS.claimPaths(
        context.artifactRoot,
        context.identity,
        hashObject(selected.claimUnsigned),
      ),
      codes,
    ),
    codes.claimConflict,
    'HEAD verifier 复核期间 owner lineage 漂移',
  );
  return {
    schema_version: 1,
    transaction_protocol: FILES_TRANSACTION_PROTOCOL,
    git_minimum_version: '2.43',
    git_ref_backend: 'files',
    worktree_key_sha256: context.identity.worktree_key_sha256,
    claim_file: rawOptions.expectedClaimFile,
    claim_sha256: normalizeHash(
      rawOptions.expectedClaimSha256,
      'expected worktree claim SHA-256',
    ),
    operation_id: rawOptions.operationId,
    operation_binding_sha256: context.operationBindingSha256,
    expected_worktree_key_sha256:
      context.expectedWorktreeKeySha256,
    git_dir: context.identity.git_dir,
    expected_oid: rawOptions.expectedDetachedOid,
    target_ref: rawOptions.targetRef,
    head_state: 'ATTACHED',
    ...transaction,
  };
}

module.exports = {
  FILES_TRANSACTION_PROTOCOL,
  NATIVE_TRANSACTION_PROTOCOL,
  attachWorktreeBootstrapHead,
  captureWorktreeGitdirIdentity,
  verifyWorktreeBootstrapHead,
};
