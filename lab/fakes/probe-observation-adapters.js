'use strict';

const crypto = require('crypto');
const { assertControl } = require('../../scripts/goal-control/errors');
const {
  controllerEvidenceReference,
  expectedAdapter,
  targetHashes,
} = require('../../scripts/goal-control/canary-observation-receipt');
const {
  canonicalJson,
  hashObject,
} = require('../../scripts/goal-control/util');

const FAKE_ADAPTERS = Object.freeze({
  GITHUB_CLI: 'fake-github-cli-v1',
  GIT_TRANSPORT: 'fake-git-transport-v1',
  GITHUB_APP: 'fake-github-app-v1',
  BROWSER: 'fake-browser-v1',
  TASK_BROKER: 'fake-task-broker-v1',
  CONTROLLER_CLI: 'fake-controller-cli-v1',
});

function assertIsolatedFakeNamespace() {
  assertControl(
    process.env.GOAL_CONTROL_TEST_MODE === '1',
    'TEST_DEPENDENCY_FORBIDDEN',
    'fake probe adapters 只允许隔离 GOAL_CONTROL_TEST_MODE namespace',
  );
}

function sealFakeReceipt(receipt, options) {
  assertIsolatedFakeNamespace();
  const hostAttestation =
    options.manifest.probe_observation_receipts.host_attestation;
  assertControl(
    options.hostAttestationPrivateKey,
    'TEST_DEPENDENCY_FORBIDDEN',
    'isolated fake signer 缺 test-owned in-memory private key',
  );
  const value = JSON.parse(JSON.stringify(receipt));
  delete value.receipt_binding_sha256;
  value.receipt_attestation = {
    algorithm: hostAttestation.algorithm,
    key_id: hostAttestation.key_id,
    public_key_sha256: hostAttestation.public_key_sha256,
  };
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalJson(value)),
    options.hostAttestationPrivateKey,
  );
  value.receipt_attestation.signature_base64url =
    signature.toString('base64url');
  value.receipt_binding_sha256 = hashObject(value);
  return value;
}

function fakeProbeResult(
  probe,
  sequence,
  targetIdentitySha256,
  evidenceContext,
  override = {},
) {
  const adapter = expectedAdapter(probe);
  assertControl(
    Object.prototype.hasOwnProperty.call(FAKE_ADAPTERS, adapter),
    'INVALID_TEST_DEPENDENCY',
    `fake adapter 不支持 ${adapter}`,
  );
  const disposition = override.disposition || 'PASS';
  const interactive = {
    allow_prompt: override.allowPrompt === true,
    auth_prompt: override.authPrompt === true,
  };
  const result = {
    sequence,
    probe,
    adapter,
    disposition,
    target_identity_sha256: targetIdentitySha256,
    result_fingerprint_sha256: hashObject({
      namespace: 'GOAL_CONTROL_TEST_MODE',
      implementation: FAKE_ADAPTERS[adapter],
      probe,
      disposition,
      interactive,
    }),
    evidence_refs: [],
    interactive,
    limitation: override.limitation || null,
  };
  const evidenceSha256 = hashObject({
    namespace: 'GOAL_CONTROL_TEST_MODE',
    adapter,
    probe,
    sequence,
  });
  result.evidence_refs = [
    controllerEvidenceReference(
      evidenceContext,
      result,
      evidenceSha256,
      0,
    ),
  ];
  return result;
}

function fakeReceipt(options) {
  assertIsolatedFakeNamespace();
  const plan = options.planEnvelope.canary_plan;
  const {
    targetIdentitySha256,
    targetFingerprintSha256,
  } = targetHashes(plan, options);
  const overrides = options.overrides || {};
  const evidenceContext = {
    stableId: options.stableId,
    challenge: options.challenge,
    canaryPlanSha256: options.planEnvelope.canary_plan_sha256,
    goalId: options.goalId,
    taskId: options.taskId,
    role: options.role,
    threadId: options.threadId,
    hostId: options.hostId,
    attempt: options.attempt,
    targetIdentitySha256,
    targetFingerprintSha256,
  };
  const probeResults = plan.required_probes.map((probe, index) => (
    fakeProbeResult(
      probe,
      index + 1,
      targetIdentitySha256,
      evidenceContext,
      overrides[probe],
    )
  ));
  const replayResult = fakeProbeResult(
    'CANARY_PLAN_REPLAY',
    0,
    targetIdentitySha256,
    evidenceContext,
    overrides.CANARY_PLAN_REPLAY,
  );
  const aggregateDisposition = probeResults.some((result) => (
    result.disposition === 'FAIL'
      || result.interactive.allow_prompt
      || result.interactive.auth_prompt
  ))
    ? 'FAIL'
    : probeResults.some((result) => (
      result.disposition === 'PROVISIONAL_KNOWN_LIMITATION'
    ))
      ? 'PROVISIONAL_KNOWN_LIMITATION'
      : probeResults.some((result) => (
      result.disposition === 'KNOWN_LIMITATION'
    ))
        ? 'KNOWN_LIMITATION'
        : 'PASS';
  const observedAt = options.observedAt || new Date().toISOString();
  const ttlMs = options.ttlMs || 60_000;
  const unsigned = {
    schema_version: 1,
    kind: 'SEALED_PROBE_OBSERVATION_RECEIPT',
    stable_id: options.stableId,
    challenge: options.challenge,
    canary_plan_sha256: options.planEnvelope.canary_plan_sha256,
    goal_id: options.goalId,
    task_id: options.taskId,
    role: options.role,
    producer: {
      thread_id: options.threadId,
      host_id: options.hostId,
      attempt: options.attempt,
      namespace: 'ISOLATED_TEST_FAKE',
    },
    target_identity_sha256: targetIdentitySha256,
    target_fingerprint_sha256: targetFingerprintSha256,
    replay_result: replayResult,
    probe_results: probeResults,
    aggregate_disposition: aggregateDisposition,
    observed_at: observedAt,
    expires_at: new Date(Date.parse(observedAt) + ttlMs).toISOString(),
    ttl_ms: ttlMs,
  };
  return sealFakeReceipt(unsigned, options);
}

module.exports = {
  FAKE_ADAPTERS,
  fakeProbeResult,
  fakeReceipt,
  sealFakeReceipt,
};
