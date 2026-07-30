import { createRequire } from "module";
import { createHash } from "crypto";
import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const nodeRequire = createRequire(import.meta.url);
const validation = nodeRequire(path.join(ROOT, "scripts", "goal-control", "validation.js")) as {
  EVENT_PAYLOAD_KEYS: Record<string, readonly string[]>;
  EVENT_PAYLOAD_REQUIRED: Record<string, readonly string[]>;
  WORKER_CANARY_BOOTSTRAP_PROTOCOL: string;
  validateEvent: (value: unknown) => unknown;
  validateLaunchManifest: (value: unknown) => unknown;
};
const evidence = nodeRequire(path.join(ROOT, "scripts", "goal-control", "evidence.js")) as {
  EXPECTED_PRODUCER: Record<string, readonly string[]>;
  MECHANICAL_EVIDENCE_KINDS: Set<string>;
};
const Ajv2020 = nodeRequire("ajv/dist/2020").default as new (
  options: Record<string, unknown>,
) => {
  addFormat: (
    name: string,
    definition: Record<string, unknown>,
  ) => void;
  addSchema: (schema: Record<string, any>) => void;
  compile: (
    schema: Record<string, any>,
  ) => (value: unknown) => boolean;
};
const {
  validateLegacyRoleIdentityIntent,
  validateRoleIdentityIntent,
  validateRoleIdentityObservationStructure,
} = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "role-identity-intent.js",
  ),
) as {
  validateRoleIdentityIntent: (
    value: Record<string, any>,
  ) => Record<string, any>;
  validateLegacyRoleIdentityIntent: (
    value: Record<string, any>,
  ) => Record<string, any>;
  validateRoleIdentityObservationStructure: (
    value: Record<string, any>,
  ) => Record<string, any>;
};
const { hashObject } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "util.js"),
) as {
  hashObject: (value: unknown) => string;
};
const { validateWorkerBootstrapBinding } = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "worker-bootstrap-binding.js",
  ),
) as {
  validateWorkerBootstrapBinding: (
    value: Record<string, any>,
  ) => Record<string, any>;
};
const { applyEvent, initialTaskState } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "fsm.js"),
) as {
  applyEvent: (
    state: Record<string, any>,
    event: Record<string, any>,
    epoch: number,
  ) => Record<string, any>;
  initialTaskState: (
    task: Record<string, any>,
    manifest: Record<string, any>,
    options?: Record<string, any>,
  ) => Record<string, any>;
};
const { validateRoleIdentityBundle } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "goal.js"),
) as {
  validateRoleIdentityBundle: (
    value: Record<string, any>,
  ) => Record<string, any>;
};

function readJson(relative: string): Record<string, any> {
  return JSON.parse(readFileSync(path.join(ROOT, relative), "utf8")) as Record<string, any>;
}

function compileDraft202012(
  schema: Record<string, any>,
  options: Record<string, unknown> = {},
  referencedSchemas: Record<string, any>[] = [],
): (value: unknown) => boolean {
  const ajv = new Ajv2020({
    strict: true,
    strictTypes: false,
    allErrors: true,
    validateFormats: true,
    ...options,
  });
  ajv.addFormat("date-time", {
    type: "string",
    validate: (value: unknown) => (
      typeof value === "string"
        && Number.isFinite(Date.parse(value))
        && new Date(Date.parse(value)).toISOString() === value
    ),
  });
  referencedSchemas.forEach((referenced) => ajv.addSchema(referenced));
  return ajv.compile(schema);
}

const PLATFORM_THREAD = "019fabbe-3b38-7a23-8d8f-8c392bced038";
const PLATFORM_HOST = "019fabbe-3b38-7a23-8d8f-8c392bced039";
const PLATFORM_SESSION = "019fabbe-3b38-7a23-8d8f-8c392bced03a";
const GENERIC_PROVIDER_TOKEN_CASES = [
  ["glpat", `GlPaT-${"A".repeat(12)}`],
  ["hugging-face", `Hf_${"B".repeat(12)}`],
  ["xai", `XaI-${"C".repeat(12)}`],
  ["sendgrid-key", `sK${"aB".repeat(16)}`],
  ["sendgrid-token", `sG.${"D".repeat(12)}.${"E".repeat(12)}`],
  ["aws-akia", `aKiA${"F".repeat(16)}`],
  ["aws-asia", `aSiA${"G".repeat(16)}`],
  ["google", `aIzA${"H".repeat(20)}`],
  ["npm", `NpM_${"I".repeat(16)}`],
  ["pypi", `PyPi-${"J".repeat(16)}`],
  ["jwt", `EyJ${"K".repeat(8)}.${"L".repeat(8)}.${"M".repeat(8)}`],
] as const;

describe("goal-control machine contract schemas", () => {
  it("keeps embedded worker bootstrap paths in three-way parity", () => {
    const intentSchema = readJson(
      "scripts/goal-control/schemas/role-identity-intent.schema.json",
    );
    const eventSchema = readJson(
      "scripts/goal-control/schemas/event.schema.json",
    );
    const intentWorker = compileDraft202012({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      $ref: "#/$defs/workerBootstrapBinding",
      $defs: intentSchema.$defs,
    });
    const eventWorker = compileDraft202012({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      $ref: "#/$defs/workerBootstrap",
      $defs: eventSchema.$defs,
    });
    const unsigned = {
      schema_version: 1,
      protocol: "goalctl-worker-canary-bootstrap-v1",
      receipt_file: "/private/receipt.json",
      receipt_sha256: `sha256:${"1".repeat(64)}`,
      identity_plan_sha256: `sha256:${"2".repeat(64)}`,
      identity_observation_sha256: `sha256:${"3".repeat(64)}`,
      operation_id: "worker-bootstrap-parity-1",
      challenge: "4".repeat(64),
      thread: PLATFORM_THREAD,
      host: PLATFORM_HOST,
      worktree: "/private/worktree",
      git_dir: "/private/worktree/.git",
      common_git_dir: "/private/git",
      head: "a".repeat(40),
      branch: "codex/worker-bootstrap-parity",
      canary_policy: {
        path: "a".repeat(500),
        sha256: `sha256:${"5".repeat(64)}`,
      },
    };
    const seal = (
      mutate: (value: Record<string, any>) => void,
    ): Record<string, any> => {
      const value = structuredClone(unsigned);
      mutate(value);
      return {
        ...value,
        binding_sha256: hashObject(value),
      };
    };
    const parity = (
      value: Record<string, any>,
      expected: boolean,
    ): void => {
      expect(intentWorker(value)).toBe(expected);
      expect(eventWorker(value)).toBe(expected);
      let runtime = true;
      try {
        validateWorkerBootstrapBinding(value);
      } catch {
        runtime = false;
      }
      expect(runtime).toBe(expected);
    };
    parity(seal(() => {}), true);
    parity(seal((value) => {
      value.canary_policy.path = "a".repeat(501);
    }), false);
    parity(seal((value) => {
      value.canary_policy.path = "a/../b";
    }), false);
    parity(seal((value) => {
      value.receipt_file = "relative/receipt.json";
    }), false);
    parity(seal((value) => {
      value.worktree = "/tmp/x/../w";
    }), false);
    parity(seal((value) => {
      value.git_dir = `/${"a".repeat(1999)}`;
    }), true);
    parity(seal((value) => {
      value.common_git_dir = `/${"a".repeat(2000)}`;
    }), false);
  });

  it("requires v2 identity only across the durable new-goal protocol boundary", () => {
    const packet = {
      revision: 1,
      path: "packet.md",
      sha256: `sha256:${"a".repeat(64)}`,
    };
    const manifest = {
      base_head: "b".repeat(40),
      probe_observation_receipts: {},
    };
    const legacy = initialTaskState(
      { id: "TASK-A", packet },
      manifest,
    );
    const current = initialTaskState(
      { id: "TASK-A", packet },
      manifest,
      { roleIdentityProtocolVersion: 2 },
    );
    const event = {
      schema_version: 1,
      event_id: "legacy-register-foreman",
      goal_id: "goal-schema-parity",
      task_id: "TASK-A",
      type: "REGISTER_ROLE",
      actor: {
        role: "FOREMAN",
        thread_id: "legacy-foreman-thread",
        host_id: "legacy-host",
      },
      actor_sequence: 1,
      expected_state_revision: 0,
      control_epoch: 0,
      packet,
      base_head: manifest.base_head,
      full_head: manifest.base_head,
      accepted_at: "2026-07-29T01:02:03.004Z",
      payload: {
        role: "FOREMAN",
        thread_id: "legacy-foreman-thread",
        host_id: "legacy-host",
        attempt: 1,
        lease_ms: 60_000,
        status: "active",
        launch_id: null,
        capability_sha256: "c".repeat(64),
        capability_file: "/legacy/capability",
        authorized_by: {
          role: "BOOTSTRAP",
          capability_file: "/private/controller-capability",
        },
        probe_observation: {
          thread_id: "legacy-foreman-thread",
          host_id: "legacy-host",
          attempt: 1,
          accepted_at: "2026-07-29T01:02:03.004Z",
          binding_sha256: `sha256:${"d".repeat(64)}`,
        },
      },
    };
    const legacyRegistered = applyEvent(
      legacy,
      structuredClone(event),
      0,
    );
    expect(legacyRegistered)
      .toMatchObject({
        sessions: {
          FOREMAN: {
            thread_id: "legacy-foreman-thread",
          },
        },
      });
    const refreshedProbe = {
      ...legacyRegistered.sessions.FOREMAN.probe_observation,
      accepted_at: "2026-07-29T01:02:04.005Z",
      binding_sha256: `sha256:${"e".repeat(64)}`,
    };
    const legacyRotated = applyEvent(
      legacyRegistered,
      {
        ...structuredClone(event),
        event_id: "legacy-refresh-foreman",
        type: "PROBE_OBSERVATION_REFRESHED",
        actor_sequence: 1,
        expected_state_revision: 1,
        accepted_at: refreshedProbe.accepted_at,
        payload: {
          role: "FOREMAN",
          attempt: 1,
          previous_binding_sha256: `sha256:${"d".repeat(64)}`,
          probe_observation: refreshedProbe,
          request_sha256: `sha256:${"f".repeat(64)}`,
        },
      },
      0,
    );
    expect(
      legacyRotated.sessions.FOREMAN.probe_observation.binding_sha256,
    ).toBe(refreshedProbe.binding_sha256);
    expect(() => applyEvent(current, structuredClone(event), 0))
      .toThrow(expect.objectContaining({
        code: "ROLE_IDENTITY_INTENT_MISMATCH",
      }));
  });

  it("defines strict host observation and controller identity intent contracts", () => {
    const observation = readJson(
      "scripts/goal-control/schemas/role-identity-observation.schema.json",
    );
    const intent = readJson(
      "scripts/goal-control/schemas/role-identity-intent.schema.json",
    );
    expect(observation).toMatchObject({
      type: "object",
      additionalProperties: false,
      properties: {
        kind: {
          const: "GOALCTL_HOST_ROLE_IDENTITY_OBSERVATION_V1",
        },
        attestation: {
          type: "object",
          additionalProperties: false,
          properties: {
            algorithm: { const: "ED25519" },
          },
        },
      },
    });
    expect(observation.required).toEqual(expect.arrayContaining([
      "thread_id",
      "host_id",
      "session_id",
      "launch_id",
      "repository_head",
      "attestation",
      "record_sha256",
    ]));
    expect(intent).toMatchObject({
      type: "object",
      additionalProperties: false,
      properties: {
        kind: { const: "ROLE_IDENTITY_INTENT" },
        attempt: { type: "integer", minimum: 1 },
        state_revision: { type: "integer", minimum: 0 },
        control_epoch: { type: "integer", minimum: 0 },
        packet: {
          type: "object",
          additionalProperties: false,
        },
        issuer_authority: {
          type: "object",
          additionalProperties: false,
        },
      },
    });
    expect(intent.required).toEqual(expect.arrayContaining([
      "protocol",
      "operation_id",
      "goal_id",
      "task_id",
      "role",
      "thread_id",
      "host_id",
      "attempt",
      "session_id",
      "launch_id",
      "state_revision",
      "control_epoch",
      "packet",
      "base_head",
      "full_head",
      "task_cycle",
      "identity_observation",
      "issuer_authority",
      "intent_sha256",
    ]));
  });

  it("executes Draft 2020-12 identity schemas in parity with runtime boundaries", () => {
    const observationSchema = readJson(
      "scripts/goal-control/schemas/role-identity-observation.schema.json",
    );
    const intentSchema = readJson(
      "scripts/goal-control/schemas/role-identity-intent.schema.json",
    );
    const schemaObservation = compileDraft202012(observationSchema);
    const schemaIntent = compileDraft202012(
      intentSchema,
      {},
      [observationSchema],
    );
    const runtimeObservation = (value: Record<string, any>): boolean => {
      try {
        validateRoleIdentityObservationStructure(value);
        return true;
      } catch {
        return false;
      }
    };
    const runtimeIntent = (value: Record<string, any>): boolean => {
      try {
        validateRoleIdentityIntent(value);
        return true;
      } catch {
        return false;
      }
    };
    const observation = {
      schema_version: 1,
      kind: "GOALCTL_HOST_ROLE_IDENTITY_OBSERVATION_V1",
      operation_id: "register-foreman-actual-1",
      goal_id: "goal-schema-parity",
      task_id: "TASK-A",
      role: "FOREMAN",
      thread_id: PLATFORM_THREAD,
      host_id: PLATFORM_HOST,
      session_id: PLATFORM_SESSION,
      launch_id: null,
      repository_head: "a".repeat(40),
      worker_bootstrap_binding_sha256: null,
      observed_at: "2026-07-29T01:02:03.004Z",
      expires_at: "2026-07-29T01:03:03.004Z",
      attestation: {
        algorithm: "ED25519",
        key_id: "host-attestation-schema-v1",
        public_key_sha256: `sha256:${"b".repeat(64)}`,
        signature_base64url: "C".repeat(86),
      },
      record_sha256: `sha256:${"d".repeat(64)}`,
    };
    const intentCore = {
      schema_version: 1,
      kind: "ROLE_IDENTITY_INTENT",
      protocol: "goalctl-role-identity-intent-v2",
      operation_id: observation.operation_id,
      semantic_slot_sha256: `sha256:${"0".repeat(64)}`,
      goal_id: observation.goal_id,
      task_id: observation.task_id,
      role: observation.role,
      thread_id: observation.thread_id,
      host_id: observation.host_id,
      attempt: 1,
      session_id: observation.session_id,
      launch_id: null,
      state_revision: 0,
      control_epoch: 0,
      packet: {
        revision: 1,
        sha256: `sha256:${"e".repeat(64)}`,
      },
      base_head: "a".repeat(40),
      full_head: "a".repeat(40),
      task_cycle: 1,
      worker_bootstrap: null,
      worker_bootstrap_authority: null,
      identity_observation: {
        receipt_sha256: `sha256:${"f".repeat(64)}`,
        receipt_file_identity_sha256: `sha256:${"2".repeat(64)}`,
        record_sha256: observation.record_sha256,
        attestation_key_id: observation.attestation.key_id,
        observed_at: observation.observed_at,
        expires_at: observation.expires_at,
        worker_bootstrap_binding_sha256: null,
        signed_record: observation,
      },
      issuer_authority: {
        kind: "BOOTSTRAP",
        capability_sha256: "1".repeat(64),
        capability_file_identity_sha256:
          `sha256:${"4".repeat(64)}`,
        source_task_id: null,
        source_state_revision: null,
        source_event_head_sha256: null,
        role: null,
        thread_id: null,
        host_id: null,
        attempt: null,
        session_id: null,
        lease_until: null,
        registration_event_id: null,
        bootstrap_init_receipt_sha256:
          `sha256:${"3".repeat(64)}`,
        recovery_scope_sha256: null,
      },
      created_at: "2026-07-29T01:02:04.005Z",
    };
    const sealIntent = (
      value: Record<string, any>,
    ): Record<string, any> => {
      const unsigned = structuredClone(value);
      delete unsigned.intent_sha256;
      if (unsigned.identity_observation?.signed_record) {
        const signedRecord = unsigned.identity_observation.signed_record;
        Object.assign(signedRecord, {
          operation_id: unsigned.operation_id,
          goal_id: unsigned.goal_id,
          task_id: unsigned.task_id,
          role: unsigned.role,
          thread_id: unsigned.thread_id,
          host_id: unsigned.host_id,
          session_id: unsigned.session_id,
          launch_id: unsigned.launch_id,
          repository_head: unsigned.full_head,
          worker_bootstrap_binding_sha256:
            unsigned.identity_observation
              .worker_bootstrap_binding_sha256,
          observed_at: unsigned.identity_observation.observed_at,
          expires_at: unsigned.identity_observation.expires_at,
        });
        delete signedRecord.record_sha256;
        signedRecord.record_sha256 = hashObject(signedRecord);
        unsigned.identity_observation.record_sha256 =
          signedRecord.record_sha256;
      }
      unsigned.semantic_slot_sha256 = hashObject({
        schema_version: 1,
        kind: "ROLE_IDENTITY_SEMANTIC_SLOT",
        goal_id: unsigned.goal_id,
        task_id: unsigned.task_id,
        role: unsigned.role,
        attempt: unsigned.attempt,
        state_revision: unsigned.state_revision,
        control_epoch: unsigned.control_epoch,
        packet: unsigned.packet,
        base_head: unsigned.base_head,
        full_head: unsigned.full_head,
        task_cycle: unsigned.task_cycle,
      });
      return {
        ...unsigned,
        intent_sha256: hashObject(unsigned),
      };
    };
    const parity = (
      schemaValidator: (value: unknown) => boolean,
      runtimeValidator: (value: Record<string, any>) => boolean,
      value: Record<string, any>,
      expected: boolean,
    ): void => {
      expect(schemaValidator(value)).toBe(expected);
      expect(runtimeValidator(value)).toBe(expected);
    };

    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, operation_id: "A".repeat(200) },
      true,
    );
    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, operation_id: "A".repeat(201) },
      false,
    );
    parity(schemaObservation, runtimeObservation, observation, true);
    parity(
      schemaObservation,
      runtimeObservation,
      {
        ...observation,
        thread_id: PLATFORM_THREAD,
      },
      true,
    );
    const omittedObservationLaunch = structuredClone(observation);
    delete omittedObservationLaunch.launch_id;
    parity(
      schemaObservation,
      runtimeObservation,
      omittedObservationLaunch,
      false,
    );
    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, observed_at: "2026-13-29 01:02:03" },
      false,
    );
    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, observed_at: "2025-02-29T01:02:03.004Z" },
      false,
    );
    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, thread_id: `GhP_${"Z".repeat(36)}` },
      false,
    );
    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, thread_id: `sk_live_${"Z".repeat(32)}` },
      false,
    );
    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, operation_id: "colon:intent" },
      false,
    );
    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, thread_id: "review-a-2" },
      false,
    );
    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, host_id: "LoCaL" },
      false,
    );
    parity(
      schemaObservation,
      runtimeObservation,
      { ...observation, unexpected: "field" },
      false,
    );
    const missingObservation = structuredClone(observation);
    delete missingObservation.session_id;
    parity(
      schemaObservation,
      runtimeObservation,
      missingObservation,
      false,
    );
    for (const [, token] of GENERIC_PROVIDER_TOKEN_CASES) {
      const wrapped = `prefix.${token}.suffix`;
      const embedded = `prefixx${token}suffix`;
      parity(
        schemaObservation,
        runtimeObservation,
        { ...observation, operation_id: wrapped },
        false,
      );
      parity(
        schemaObservation,
        runtimeObservation,
        { ...observation, operation_id: embedded },
        true,
      );
    }

    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent(intentCore),
      true,
    );
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent({
        ...intentCore,
        operation_id: "A".repeat(200),
      }),
      true,
    );
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent({
        ...intentCore,
        operation_id: "A".repeat(201),
      }),
      false,
    );
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent({
        ...intentCore,
        attempt: Number.MAX_SAFE_INTEGER,
      }),
      true,
    );
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent({
        ...intentCore,
        attempt: Number.MAX_SAFE_INTEGER + 1,
      }),
      false,
    );
    const omittedIntentLaunch = structuredClone(intentCore);
    delete omittedIntentLaunch.launch_id;
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent(omittedIntentLaunch),
      false,
    );
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent({
        ...intentCore,
        created_at: "29 July 2026",
      }),
      false,
    );
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent({
        ...intentCore,
        session_id: `prefix:XoXb-${"Q".repeat(30)}:suffix`,
      }),
      false,
    );
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent({
        ...intentCore,
        operation_id: `receipt.${"R".repeat(43)}.json`,
      }),
      false,
    );
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent({
        ...intentCore,
        thread_id: "captain-1",
      }),
      false,
    );
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent({
        ...intentCore,
        unexpected: "field",
      }),
      false,
    );
    const missingIntent = structuredClone(intentCore);
    delete missingIntent.identity_observation;
    parity(
      schemaIntent,
      runtimeIntent,
      sealIntent(missingIntent),
      false,
    );
    const legacyIntent = sealIntent(intentCore);
    delete legacyIntent.protocol;
    delete legacyIntent.semantic_slot_sha256;
    delete legacyIntent.worker_bootstrap;
    delete legacyIntent.worker_bootstrap_authority;
    delete legacyIntent.identity_observation.signed_record;
    delete legacyIntent.issuer_authority
      .capability_file_identity_sha256;
    delete legacyIntent.issuer_authority.source_capability_sha256;
    delete legacyIntent.issuer_authority
      .source_capability_file_identity_sha256;
    delete legacyIntent.issuer_authority.source_state_revision;
    delete legacyIntent.issuer_authority.source_event_head_sha256;
    delete legacyIntent.intent_sha256;
    legacyIntent.intent_sha256 = hashObject(legacyIntent);
    expect(schemaIntent(legacyIntent)).toBe(false);
    expect(runtimeIntent(legacyIntent)).toBe(false);
    expect(() => validateLegacyRoleIdentityIntent(legacyIntent))
      .not.toThrow();

    const bundleSchema = readJson(
      "scripts/goal-control/schemas/role-identity-bundle.schema.json",
    );
    const schemaBundle = compileDraft202012(
      bundleSchema,
      {},
      [observationSchema, intentSchema],
    );
    const runtimeBundle = (value: Record<string, any>): boolean => {
      try {
        validateRoleIdentityBundle(value);
        return true;
      } catch (error) {
        return false;
      }
    };
    const compositeBundle = (
      value: Record<string, any>,
    ): boolean => schemaBundle(value) && runtimeBundle(value);
    const bundleIntent = sealIntent(intentCore);
    const challengeUnsigned = {
      schema_version: 1,
      kind: "PROBE_OBSERVATION_CHALLENGE",
      goal_id: bundleIntent.goal_id,
      task_id: bundleIntent.task_id,
      role: bundleIntent.role,
      thread_id: bundleIntent.thread_id,
      host_id: bundleIntent.host_id,
      attempt: bundleIntent.attempt,
      registration_event_id: bundleIntent.operation_id,
      canary_plan_sha256: `sha256:${"c".repeat(64)}`,
      producer_namespace: "HOST_ADAPTER",
      issuer_capability_sha256:
        bundleIntent.issuer_authority.capability_sha256,
      attestation_algorithm: "ED25519",
      attestation_key_id:
        bundleIntent.identity_observation.attestation_key_id,
      attestation_public_key_sha256:
        bundleIntent.identity_observation.signed_record
          .attestation.public_key_sha256,
      challenge: "d".repeat(64),
      issued_at: "2026-07-29T01:02:04.005Z",
      expires_at: "2026-07-29T01:03:04.005Z",
    };
    const challenge = {
      ...challengeUnsigned,
      record_sha256: hashObject(challengeUnsigned),
    };
    const bundleUnsigned = {
      schema_version: 2,
      kind: "ROLE_IDENTITY_CHALLENGE_BUNDLE",
      operation_id: bundleIntent.operation_id,
      semantic_slot_sha256: bundleIntent.semantic_slot_sha256,
      intent: bundleIntent,
      challenge,
    };
    const bundle = {
      ...bundleUnsigned,
      bundle_sha256: hashObject(bundleUnsigned),
    };
    expect(compositeBundle(bundle)).toBe(true);
    const bundleForOperationId = (
      operationId: string,
    ): Record<string, any> => {
      const candidateIntent = sealIntent({
        ...intentCore,
        operation_id: operationId,
      });
      const candidateChallengeUnsigned = {
        ...challengeUnsigned,
        registration_event_id: operationId,
      };
      const candidateChallenge = {
        ...candidateChallengeUnsigned,
        record_sha256: hashObject(candidateChallengeUnsigned),
      };
      const candidateUnsigned = {
        schema_version: 2,
        kind: "ROLE_IDENTITY_CHALLENGE_BUNDLE",
        operation_id: operationId,
        semantic_slot_sha256:
          candidateIntent.semantic_slot_sha256,
        intent: candidateIntent,
        challenge: candidateChallenge,
      };
      return {
        ...candidateUnsigned,
        bundle_sha256: hashObject(candidateUnsigned),
      };
    };
    for (const [, token] of GENERIC_PROVIDER_TOKEN_CASES) {
      const wrapped = `prefix.${token}.suffix`;
      const embedded = `prefixx${token}suffix`;
      parity(
        schemaIntent,
        runtimeIntent,
        sealIntent({ ...intentCore, operation_id: wrapped }),
        false,
      );
      parity(
        schemaIntent,
        runtimeIntent,
        sealIntent({ ...intentCore, operation_id: embedded }),
        true,
      );
      expect(compositeBundle(bundleForOperationId(wrapped)))
        .toBe(false);
      expect(compositeBundle(bundleForOperationId(embedded)))
        .toBe(true);
    }
    const bundleExtra = {
      ...structuredClone(bundle),
      nested_extra: { arbitrary: "rejected" },
    };
    expect(schemaBundle(bundleExtra)).toBe(false);
    expect(runtimeBundle(bundleExtra)).toBe(false);
    const bundleBadTimestamp = structuredClone(bundle);
    bundleBadTimestamp.challenge.issued_at =
      "2025-02-29T01:02:04.005Z";
    expect(schemaBundle(bundleBadTimestamp)).toBe(false);
    expect(runtimeBundle(bundleBadTimestamp)).toBe(false);
    const bundleSecretId = structuredClone(bundle);
    bundleSecretId.operation_id = `credential_prod_${"x".repeat(20)}`;
    expect(schemaBundle(bundleSecretId)).toBe(false);
    expect(runtimeBundle(bundleSecretId)).toBe(false);
    const bundleCrossField = structuredClone(bundle);
    bundleCrossField.challenge.host_id =
      "019fabbe-3b38-7a23-8d8f-8c392bced03b";
    expect(schemaBundle(bundleCrossField)).toBe(true);
    expect(runtimeBundle(bundleCrossField)).toBe(false);
    expect(compositeBundle(bundleCrossField)).toBe(false);
    const bundleBadSeal = structuredClone(bundle);
    bundleBadSeal.bundle_sha256 = `sha256:${"f".repeat(64)}`;
    expect(schemaBundle(bundleBadSeal)).toBe(true);
    expect(runtimeBundle(bundleBadSeal)).toBe(false);
    expect(compositeBundle(bundleBadSeal)).toBe(false);
    const bundleBadIntentSeal = structuredClone(bundle);
    bundleBadIntentSeal.intent.intent_sha256 =
      `sha256:${"e".repeat(64)}`;
    expect(schemaBundle(bundleBadIntentSeal)).toBe(true);
    expect(runtimeBundle(bundleBadIntentSeal)).toBe(false);
    expect(compositeBundle(bundleBadIntentSeal)).toBe(false);
  });

  it("executes the checked-in event role identity binding in Ajv/runtime parity", () => {
    const eventSchema = readJson(
      "scripts/goal-control/schemas/event.schema.json",
    );
    // Historical P1 conditional branches put `required` beside properties
    // declared in the shared payload schema. Keep every other strict check
    // enabled while exercising the exact checked-in event contract.
    const schemaEvent = compileDraft202012(eventSchema, {
      strictRequired: false,
    });
    const runtimeEvent = (value: Record<string, any>): boolean => {
      try {
        validation.validateEvent(value);
        return true;
      } catch {
        return false;
      }
    };
    const identityV1 = {
      protocol: "goalctl-role-identity-intent-v1",
      operation_id: "register-foreman-parity-1",
      intent_sha256: `sha256:${"1".repeat(64)}`,
      session_id: "foreman-session-parity-1",
      thread_id: "foreman-thread-parity-1",
      host_id: "foreman-host-parity-1",
      attempt: 1,
      launch_id: null,
      identity_observation_receipt_sha256:
        `sha256:${"2".repeat(64)}`,
    };
    const identityV2 = {
      ...identityV1,
      protocol: "goalctl-role-identity-intent-v2",
      session_id: PLATFORM_SESSION,
      thread_id: PLATFORM_THREAD,
      host_id: PLATFORM_HOST,
      semantic_slot_sha256: `sha256:${"3".repeat(64)}`,
      bundle_sha256: `sha256:${"4".repeat(64)}`,
      bundle_file_identity_sha256: `sha256:${"5".repeat(64)}`,
      issuer_authority_sha256: `sha256:${"6".repeat(64)}`,
      identity_observation_record_sha256:
        `sha256:${"7".repeat(64)}`,
      identity_observation_receipt_file_identity_sha256:
        `sha256:${"8".repeat(64)}`,
      worker_bootstrap_binding_sha256: null,
      worker_bootstrap_authority_sha256: null,
      state_revision: 0,
      control_epoch: 0,
      packet_revision: 1,
      packet_sha256: `sha256:${"9".repeat(64)}`,
      base_head: "a".repeat(40),
      full_head: "a".repeat(40),
      task_cycle: 1,
      challenge_record_sha256: `sha256:${"a".repeat(64)}`,
      probe_observation_binding_sha256:
        `sha256:${"b".repeat(64)}`,
      registration_authorized_by_sha256: hashObject({
        role: "BOOTSTRAP",
        capability_file: "/private/controller-capability",
      }),
    };
    const event = {
      schema_version: 1,
      event_id: "register-foreman-parity-event-1",
      goal_id: "goal-schema-parity",
      task_id: "TASK-A",
      type: "REGISTER_ROLE",
      actor: {
        role: "FOREMAN",
        thread_id: identityV1.thread_id,
        host_id: identityV1.host_id,
      },
      actor_sequence: 1,
      expected_state_revision: 0,
      control_epoch: 0,
      packet: {
        revision: 1,
        sha256: `sha256:${"9".repeat(64)}`,
      },
      base_head: "a".repeat(40),
      full_head: "a".repeat(40),
      payload: {
        role: "FOREMAN",
        thread_id: identityV1.thread_id,
        host_id: identityV1.host_id,
        attempt: 1,
        lease_ms: 60_000,
        status: "active",
        launch_id: null,
        task_nonce: null,
        capability_sha256: "b".repeat(64),
        capability_file: "/private/controller-capability",
        authorized_by: {
          role: "BOOTSTRAP",
          capability_file: "/private/controller-capability",
        },
        role_identity: identityV1,
      },
    };
    const parity = (
      value: Record<string, any>,
      expected: boolean,
    ): void => {
      expect(schemaEvent(value)).toBe(expected);
      expect(runtimeEvent(value)).toBe(expected);
    };
    const probeObservationFor = (
      identity: Record<string, any>,
    ): Record<string, any> => {
      const publicKeySpki = Buffer.from(
        `302a300506032b6570032100${"01".repeat(32)}`,
        "hex",
      );
      const unsigned = {
        schema_version: 1,
        protocol: "goalctl-sealed-probe-observation-v1",
        accepted_at: "2026-07-29T01:02:05.006Z",
        attestation_algorithm: "ED25519",
        attestation_key_id: "host-attestation-schema-v1",
        attestation_public_key_sha256:
          `sha256:${createHash("sha256")
            .update(publicKeySpki).digest("hex")}`,
        attestation_public_key_spki_base64:
          publicKeySpki.toString("base64"),
        attestation_signature_base64url: "C".repeat(86),
        plan_file: "/private/plan.json",
        plan_file_sha256: `sha256:${"1".repeat(64)}`,
        receipt_file: "/private/receipt.json",
        receipt_sha256: `sha256:${"2".repeat(64)}`,
        canary_plan_sha256: `sha256:${"3".repeat(64)}`,
        stable_id: `canary-observation-${event.event_id}`,
        challenge: "4".repeat(64),
        thread_id: identity.thread_id,
        host_id: identity.host_id,
        attempt: identity.attempt,
        target_identity_sha256: `sha256:${"5".repeat(64)}`,
        target_fingerprint_sha256: `sha256:${"6".repeat(64)}`,
        aggregate_disposition: "PASS",
        observed_at: "2026-07-29T01:02:03.004Z",
        expires_at: "2026-07-29T01:03:03.004Z",
        probe_results_sha256: `sha256:${"7".repeat(64)}`,
        receipt_binding_sha256: `sha256:${"8".repeat(64)}`,
        request_sha256: `sha256:${"9".repeat(64)}`,
      };
      return {
        ...unsigned,
        binding_sha256: hashObject(unsigned),
      };
    };
    const withIdentity = (
      identity: Record<string, any>,
    ): Record<string, any> => {
      const sealedIdentity = structuredClone(identity);
      const probeObservation =
        sealedIdentity.protocol === "goalctl-role-identity-intent-v2"
          ? probeObservationFor(sealedIdentity)
          : null;
      if (probeObservation) {
        sealedIdentity.probe_observation_binding_sha256 =
          probeObservation.binding_sha256;
      }
      return {
        ...structuredClone(event),
        actor: {
          ...structuredClone(event.actor),
          thread_id: sealedIdentity.thread_id,
          host_id: sealedIdentity.host_id,
        },
        payload: {
          ...structuredClone(event.payload),
          thread_id: sealedIdentity.thread_id,
          host_id: sealedIdentity.host_id,
          attempt: sealedIdentity.attempt,
          launch_id: sealedIdentity.launch_id,
          role_identity: sealedIdentity,
          ...(probeObservation
            ? {
              probe_observation: probeObservation,
              capability_file_identity_sha256:
                `sha256:${"c".repeat(64)}`,
            }
            : {}),
        },
      };
    };
    const resealEventProbeObservation = (
      value: Record<string, any>,
    ): Record<string, any> => {
      const probeObservation =
        value.payload.probe_observation;
      delete probeObservation.binding_sha256;
      probeObservation.binding_sha256 =
        hashObject(probeObservation);
      value.payload.role_identity
        .probe_observation_binding_sha256 =
        probeObservation.binding_sha256;
      return value;
    };

    parity(withIdentity(identityV1), true);
    const v1ValidCapabilityFileIdentity =
      withIdentity(identityV1);
    v1ValidCapabilityFileIdentity.payload
      .capability_file_identity_sha256 =
        `sha256:${"c".repeat(64)}`;
    parity(v1ValidCapabilityFileIdentity, true);
    const v1NullCapabilityFileIdentity =
      withIdentity(identityV1);
    v1NullCapabilityFileIdentity.payload
      .capability_file_identity_sha256 = null;
    parity(v1NullCapabilityFileIdentity, false);
    const v1MalformedCapabilityFileIdentity =
      withIdentity(identityV1);
    v1MalformedCapabilityFileIdentity.payload
      .capability_file_identity_sha256 = "not-a-sha256";
    parity(v1MalformedCapabilityFileIdentity, false);
    parity(withIdentity(identityV2), true);
    const v2MissingCapabilityFileIdentity =
      withIdentity(identityV2);
    delete v2MissingCapabilityFileIdentity.payload
      .capability_file_identity_sha256;
    parity(v2MissingCapabilityFileIdentity, false);
    const v2NullCapabilityFileIdentity =
      withIdentity(identityV2);
    v2NullCapabilityFileIdentity.payload
      .capability_file_identity_sha256 = null;
    parity(v2NullCapabilityFileIdentity, false);
    const v2MalformedCapabilityFileIdentity =
      withIdentity(identityV2);
    v2MalformedCapabilityFileIdentity.payload
      .capability_file_identity_sha256 = "not-a-sha256";
    parity(v2MalformedCapabilityFileIdentity, false);
    parity(withIdentity({
      ...identityV2,
      operation_id: "A".repeat(200),
    }), true);
    parity(withIdentity({
      ...identityV2,
      operation_id: "A".repeat(201),
    }), false);
    parity(withIdentity({
      ...identityV2,
      operation_id: "colon:intent",
    }), false);
    parity(withIdentity({
      ...identityV2,
      attempt: Number.MAX_SAFE_INTEGER,
    }), true);
    parity(withIdentity({
      ...identityV2,
      attempt: Number.MAX_SAFE_INTEGER + 1,
    }), false);

    const missingV1Launch = structuredClone(identityV1);
    delete missingV1Launch.launch_id;
    parity(withIdentity(missingV1Launch), false);
    parity(withIdentity({
      ...identityV1,
      launch_id: "launch-not-null",
    }), false);
    parity(withIdentity({
      ...identityV1,
      semantic_slot_sha256: `sha256:${"3".repeat(64)}`,
    }), false);
    parity(withIdentity({
      ...identityV1,
      unexpected: "field",
    }), false);

    const missingV2Bundle = structuredClone(identityV2);
    delete missingV2Bundle.bundle_sha256;
    parity(withIdentity(missingV2Bundle), false);
    const missingV2Probe = withIdentity(identityV2);
    delete missingV2Probe.payload.probe_observation;
    parity(missingV2Probe, false);
    const missingV2Bootstrap = structuredClone(identityV2);
    delete missingV2Bootstrap.worker_bootstrap_binding_sha256;
    parity(withIdentity(missingV2Bootstrap), false);
    parity(withIdentity({
      ...identityV2,
      worker_bootstrap_binding_sha256:
        `sha256:${"c".repeat(64)}`,
    }), false);
    parity(withIdentity({
      ...identityV2,
      worker_bootstrap_authority_sha256:
        `sha256:${"d".repeat(64)}`,
    }), false);
    parity(withIdentity({
      ...identityV2,
      worker_bootstrap_binding_sha256: undefined,
    }), false);
    parity(withIdentity({
      ...identityV2,
      extra_authority: `sha256:${"d".repeat(64)}`,
    }), false);

    const unsafeStateRevision = withIdentity(identityV2);
    unsafeStateRevision.expected_state_revision =
      Number.MAX_SAFE_INTEGER + 1;
    parity(unsafeStateRevision, false);
    const unsafeControlEpoch = withIdentity(identityV2);
    unsafeControlEpoch.control_epoch = Number.MAX_SAFE_INTEGER + 1;
    parity(unsafeControlEpoch, false);
    const unsafePacketRevision = withIdentity(identityV2);
    unsafePacketRevision.packet.revision =
      Number.MAX_SAFE_INTEGER + 1;
    parity(unsafePacketRevision, false);
    const maximumProbeAttempt = withIdentity(identityV2);
    maximumProbeAttempt.payload.probe_observation.attempt =
      Number.MAX_SAFE_INTEGER;
    parity(resealEventProbeObservation(maximumProbeAttempt), true);
    const unsafeProbeAttempt = withIdentity(identityV2);
    unsafeProbeAttempt.payload.probe_observation.attempt =
      Number.MAX_SAFE_INTEGER + 1;
    parity(resealEventProbeObservation(unsafeProbeAttempt), false);
    for (const attempt of [null, 0, 1, Number.MAX_SAFE_INTEGER]) {
      const attemptBoundary = withIdentity(identityV2);
      attemptBoundary.payload.probe_observation.attempt = attempt;
      parity(
        resealEventProbeObservation(attemptBoundary),
        attempt === 1 || attempt === Number.MAX_SAFE_INTEGER,
      );
    }

    const exactDerived43 = withIdentity(identityV2);
    exactDerived43.event_id = "x".repeat(24);
    exactDerived43.payload.probe_observation.stable_id =
      `canary-observation-${exactDerived43.event_id}`;
    parity(resealEventProbeObservation(exactDerived43), true);
    const providerStableMismatch = withIdentity(identityV2);
    providerStableMismatch.payload.probe_observation.stable_id =
      `prefix.AKIA${"F".repeat(16)}.suffix`;
    parity(
      resealEventProbeObservation(providerStableMismatch),
      false,
    );
    const embeddedNearMiss = withIdentity(identityV2);
    embeddedNearMiss.event_id =
      `prefixxglpat-${"A".repeat(8)}suffix`;
    embeddedNearMiss.payload.probe_observation.stable_id =
      `canary-observation-${embeddedNearMiss.event_id}`;
    parity(resealEventProbeObservation(embeddedNearMiss), true);

    const sessionAuthority = withIdentity(identityV2);
    sessionAuthority.payload.authorized_by = {
      role: "FOREMAN",
      thread_id: PLATFORM_THREAD,
      host_id: PLATFORM_HOST,
      attempt: 1,
    };
    sessionAuthority.payload.role_identity
      .registration_authorized_by_sha256 = hashObject(
        sessionAuthority.payload.authorized_by,
      );
    parity(sessionAuthority, true);
    const invalidSessionAuthority = structuredClone(sessionAuthority);
    invalidSessionAuthority.payload.authorized_by.thread_id =
      "foreman-thread-not-platform-attested";
    invalidSessionAuthority.payload.role_identity
      .registration_authorized_by_sha256 = hashObject(
        invalidSessionAuthority.payload.authorized_by,
      );
    parity(invalidSessionAuthority, false);

    const sensitiveControllerId = withIdentity({
      ...identityV2,
      operation_id: `receipt.${"C".repeat(43)}.json`,
    });
    parity(sensitiveControllerId, false);
    const sensitiveReceiptPath = withIdentity(identityV2);
    sensitiveReceiptPath.payload.probe_observation.receipt_file =
      `/private/tmp/${"D".repeat(43)}.cap`;
    parity(sensitiveReceiptPath, false);
    const credentialPlanUrl = withIdentity(identityV2);
    credentialPlanUrl.payload.probe_observation.plan_file =
      `https://example.invalid/plan?api_key=${"E".repeat(24)}`;
    parity(credentialPlanUrl, false);
    for (const [, token] of GENERIC_PROVIDER_TOKEN_CASES) {
      const wrapped = `prefix.${token}.suffix`;
      const embedded = `prefixx${token}suffix`;
      parity(withIdentity({
        ...identityV2,
        operation_id: wrapped,
      }), false);
      parity(withIdentity({
        ...identityV2,
        operation_id: embedded,
      }), true);
      const wrappedPath = withIdentity(identityV2);
      wrappedPath.payload.probe_observation.receipt_file =
        `/private/${wrapped}`;
      parity(resealEventProbeObservation(wrappedPath), false);
      const embeddedPath = withIdentity(identityV2);
      embeddedPath.payload.probe_observation.receipt_file =
        `/private/${embedded}`;
      parity(resealEventProbeObservation(embeddedPath), true);
    }

    const recoveryIdentity = {
      ...structuredClone(identityV2),
      operation_id: "recover-foreman-schema-root-2",
      attempt: 2,
      registration_authorized_by_sha256: hashObject({
        role: "GOAL_RECOVERY",
        capability_file: "/private/recovery-capability",
      }),
    };
    const sourceForeman = {
      role: "FOREMAN",
      thread_id: PLATFORM_THREAD,
      host_id: PLATFORM_HOST,
      attempt: 1,
      status: "lost",
      lease_until: "2026-07-29T01:02:04.005Z",
      registration_event_id: "register-foreman-schema-source-1",
      recovery_event_id: null,
    };
    const recoveryScopeCore = {
      schema_version: 1,
      goal_id: event.goal_id,
      control_epoch: event.control_epoch,
      control_event_head: null,
      tasks: [{
        task_id: event.task_id,
        phase: "DEV_ACTIVE",
        state_revision: event.expected_state_revision,
        event_head: `sha256:${"d".repeat(64)}`,
        control_epoch: event.control_epoch,
        packet: structuredClone(event.packet),
        base_head: event.base_head,
        full_head: event.full_head,
        foreman: sourceForeman,
        captain: null,
        recovery_sha256: null,
        recovery_backlog_sha256: `sha256:${"e".repeat(64)}`,
      }],
    };
    const recoveryScope = {
      ...recoveryScopeCore,
      scope_sha256: hashObject(recoveryScopeCore),
      recoverable_task_ids: [event.task_id],
      archived_source_task_ids: [],
      adoption_candidate_task_ids: [],
    };
    const recoveryProbe = probeObservationFor(recoveryIdentity);
    recoveryProbe.stable_id =
      `canary-observation-${recoveryIdentity.operation_id}`;
    delete recoveryProbe.binding_sha256;
    recoveryProbe.binding_sha256 = hashObject(recoveryProbe);
    recoveryIdentity.probe_observation_binding_sha256 =
      recoveryProbe.binding_sha256;
    const recoveryEvent = {
      ...structuredClone(event),
      event_id: recoveryIdentity.operation_id,
      type: "RECOVER_EXPIRED_FOREMAN",
      actor: {
        role: "FOREMAN",
        thread_id: recoveryIdentity.thread_id,
        host_id: recoveryIdentity.host_id,
      },
      payload: {
        attempt: 2,
        lease_ms: 60_000,
        status: "active",
        capability_sha256: "c".repeat(64),
        capability_file: "/private/recovery-successor-capability",
        capability_file_identity_sha256:
          `sha256:${"c".repeat(64)}`,
        reason: "schema recovery parity",
        incident_ref: "test://schema/recovery",
        request_sha256: `sha256:${"d".repeat(64)}`,
        probe_observation: recoveryProbe,
        role_identity: recoveryIdentity,
        root_recovery_id: recoveryIdentity.operation_id,
        goal_scope: recoveryScope,
        goal_scope_sha256: recoveryScope.scope_sha256,
        scope_task_ids: [event.task_id],
        source_task_ids: [event.task_id],
        adoption_target_task_id: null,
        adopt_without_local_foreman: false,
        source_foreman: {
          task_id: event.task_id,
          ...sourceForeman,
        },
        expected_event_head: `sha256:${"d".repeat(64)}`,
        expected_foreman_thread_id: sourceForeman.thread_id,
        expected_foreman_host_id: sourceForeman.host_id,
        expected_foreman_attempt: sourceForeman.attempt,
        expected_foreman_lease_until: sourceForeman.lease_until,
        authorized_by: { role: "GOAL_RECOVERY" },
      },
    };
    parity(recoveryEvent, true);
    const emptyRecoveryScope = structuredClone(recoveryEvent);
    emptyRecoveryScope.payload.goal_scope = {};
    parity(emptyRecoveryScope, false);
    for (const field of [
      "capability_file_identity_sha256",
      "probe_observation",
      "role_identity",
      "root_recovery_id",
      "goal_scope",
      "goal_scope_sha256",
      "scope_task_ids",
      "source_task_ids",
      "adoption_target_task_id",
      "adopt_without_local_foreman",
      "source_foreman",
    ]) {
      const omitted = structuredClone(recoveryEvent);
      delete omitted.payload[field];
      expect(schemaEvent(omitted)).toBe(false);
      if (runtimeEvent(omitted)) {
        throw new Error(
          `runtime accepted omitted v2 recovery field ${field}`,
        );
      }
      const nullValue = structuredClone(recoveryEvent);
      nullValue.payload[field] = null;
      const nullAccepted = field === "adoption_target_task_id";
      expect(schemaEvent(nullValue)).toBe(nullAccepted);
      if (runtimeEvent(nullValue) !== nullAccepted) {
        throw new Error(
          `runtime/schema null boundary diverged for v2 recovery field ${field}`,
        );
      }
    }
  });

  it("defines the canonical sealed probe observation receipt contract", () => {
    const schema = readJson(
      "scripts/goal-control/schemas/canary-observation-receipt.schema.json",
    );
    expect(schema).toMatchObject({
      type: "object",
      additionalProperties: false,
      properties: {
        schema_version: { const: 1 },
        kind: { const: "SEALED_PROBE_OBSERVATION_RECEIPT" },
        aggregate_disposition: {
          $ref: "#/$defs/disposition",
        },
        receipt_attestation: {
          type: "object",
          additionalProperties: false,
        },
      },
      $defs: {
        disposition: {
          enum: [
            "PASS",
            "PROVISIONAL_KNOWN_LIMITATION",
            "KNOWN_LIMITATION",
            "FAIL",
          ],
        },
      },
    });
    expect(schema.required).toEqual(expect.arrayContaining([
      "canary_plan_sha256",
      "goal_id",
      "task_id",
      "role",
      "producer",
      "target_identity_sha256",
      "target_fingerprint_sha256",
      "probe_results",
      "observed_at",
      "expires_at",
      "ttl_ms",
      "receipt_attestation",
      "receipt_binding_sha256",
    ]));
    const limitation = schema.$defs.probeResult.properties.limitation
      .oneOf[1];
    expect(limitation).toMatchObject({
      type: "object",
      additionalProperties: false,
      required: ["id", "exact_match"],
      properties: {
        exact_match: {
          type: "object",
          additionalProperties: false,
        },
      },
    });
  });

  it("keeps worker canary bootstrap manifest schema aligned with runtime validation", () => {
    const schema = readJson(
      "scripts/goal-control/schemas/goal-manifest.schema.json",
    );
    const bootstrap = schema.properties.worker_canary_bootstrap;
    expect(schema.additionalProperties).toBe(false);
    expect(schema.required).not.toContain("worker_canary_bootstrap");
    expect(bootstrap).toMatchObject({
      type: "object",
      additionalProperties: false,
      required: ["protocol", "policy"],
      properties: {
        protocol: {
          const: validation.WORKER_CANARY_BOOTSTRAP_PROTOCOL,
        },
        policy: {
          type: "object",
          additionalProperties: false,
          required: ["path", "sha256"],
          properties: {
            path: { $ref: "#/$defs/repoPath" },
            sha256: { $ref: "#/$defs/sha256" },
          },
        },
      },
    });
  });

  it("keeps the event enum and payload allowlist synchronized with runtime validation", () => {
    const schema = readJson("scripts/goal-control/schemas/event.schema.json");
    expect(new Set(schema.properties.type.enum)).toEqual(
      new Set(Object.keys(validation.EVENT_PAYLOAD_KEYS))
    );
    const schemaPayloadKeys = Object.keys(schema.properties.payload.properties);
    const runtimePayloadKeys = [...new Set(Object.values(validation.EVENT_PAYLOAD_KEYS).flat())];
    expect(new Set(schemaPayloadKeys)).toEqual(new Set(runtimePayloadKeys));
    expect(schema.properties.payload.additionalProperties).toBe(false);

    const conditionalContracts = Object.fromEntries(schema.allOf
      .filter((entry: any) => (
        entry.then?.properties?.payload?.propertyNames
          || entry.then?.properties?.payload?.maxProperties === 0
      ))
      .map((entry: any) => {
      const type = entry.if.properties.type.const as string;
      const payload = entry.then.properties.payload;
      return [type, {
        allowed: payload.maxProperties === 0 ? [] : payload.propertyNames.enum,
        required: payload.required ?? [],
      }];
    })) as Record<string, { allowed: string[]; required: string[] }>;
    expect(new Set(Object.keys(conditionalContracts))).toEqual(new Set(Object.keys(validation.EVENT_PAYLOAD_KEYS)));
    for (const [type, keys] of Object.entries(validation.EVENT_PAYLOAD_KEYS)) {
      expect(new Set(conditionalContracts[type].allowed)).toEqual(new Set(keys));
      expect(new Set(conditionalContracts[type].required)).toEqual(
        new Set(validation.EVENT_PAYLOAD_REQUIRED[type])
      );
    }
  });

  it("keeps evidence kinds and the persisted registry seal synchronized", () => {
    const schema = readJson("scripts/goal-control/schemas/evidence.schema.json");
    expect(new Set(schema.properties.kind.enum)).toEqual(
      new Set(Object.keys(evidence.EXPECTED_PRODUCER))
    );
    expect(schema.required).toContain("registry_sha256");
    expect(schema.additionalProperties).toBe(false);
    expect(evidence.MECHANICAL_EVIDENCE_KINDS).toEqual(
      new Set(["PREFLIGHT", "FAST", "FULL_CI", "AC_AUDIT"])
    );
    expect(schema.properties.attestation.properties.controller.const).toBe("goalctl");
    expect(new Set(schema.properties.attestation.properties.adapter.enum)).toEqual(
      evidence.MECHANICAL_EVIDENCE_KINDS
    );
    expect(JSON.stringify(schema.allOf)).toContain("launch_sha256");
  });

  it("validates the checked-in launch example through the same strict runtime ingress", () => {
    const example = readJson("docs/planning/goals/example/launch-manifest.example.json");
    expect(validation.validateLaunchManifest(example)).toEqual(example);
  });

  it("keeps the runtime incarnation launch schema and runtime validator strict", () => {
    const schema = readJson(
      "scripts/goal-control/schemas/launch-manifest.schema.json"
    );
    expect(schema.properties.runtime_incarnation).toMatchObject({
      type: "object",
      additionalProperties: false,
      required: ["epoch", "nonce", "rotation_event_id"],
      properties: {
        epoch: { type: "integer", minimum: 2 },
        nonce: { type: "string", pattern: "^[0-9a-f]{40}$" },
        rotation_event_id: {
          type: "string",
          pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        },
      },
    });

    const launch = readJson(
      "docs/planning/goals/example/launch-manifest.example.json"
    );
    launch.runtime_incarnation = {
      epoch: 2,
      nonce: "a".repeat(40),
      rotation_event_id: "runtime-rotated-example-dev-1-to-2",
    };
    expect(validation.validateLaunchManifest(launch)).toEqual(launch);

    const forgedEpoch = structuredClone(launch);
    forgedEpoch.runtime_incarnation.epoch = 1;
    expect(() => validation.validateLaunchManifest(forgedEpoch)).toThrow();

    const forgedNonce = structuredClone(launch);
    forgedNonce.runtime_incarnation.nonce = "not-a-runtime-nonce";
    expect(() => validation.validateLaunchManifest(forgedNonce)).toThrow();

    const forgedEvent = structuredClone(launch);
    forgedEvent.runtime_incarnation.rotation_event_id = "../forged";
    expect(() => validation.validateLaunchManifest(forgedEvent)).toThrow();

    const injectedField = structuredClone(launch);
    injectedField.runtime_incarnation.worker_token = "forbidden";
    expect(() => validation.validateLaunchManifest(injectedField)).toThrow();
  });

  it("does not expose raw owner tokens in the resource persistence contract", () => {
    const schemaText = readFileSync(
      path.join(ROOT, "scripts", "goal-control", "schemas", "resource-event.schema.json"),
      "utf8"
    );
    expect(schemaText).not.toMatch(/owner_token|owner-token/);
    expect(schemaText).toContain("owner_capability_file");
  });
});
