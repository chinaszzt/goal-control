import { createRequire } from "module";
import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const nodeRequire = createRequire(import.meta.url);
const validation = nodeRequire(path.join(ROOT, "scripts", "goal-control", "validation.js")) as {
  EVENT_PAYLOAD_KEYS: Record<string, readonly string[]>;
  EVENT_PAYLOAD_REQUIRED: Record<string, readonly string[]>;
  WORKER_CANARY_BOOTSTRAP_PROTOCOL: string;
  validateLaunchManifest: (value: unknown) => unknown;
};
const evidence = nodeRequire(path.join(ROOT, "scripts", "goal-control", "evidence.js")) as {
  EXPECTED_PRODUCER: Record<string, readonly string[]>;
  MECHANICAL_EVIDENCE_KINDS: Set<string>;
};
const { compileDraft202012 } = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "json-schema-2020-runtime.js",
  ),
) as {
  compileDraft202012: (
    schema: Record<string, any>,
  ) => (value: unknown) => boolean;
};
const {
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
  validateRoleIdentityObservationStructure: (
    value: Record<string, any>,
  ) => Record<string, any>;
};
const { hashObject } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "util.js"),
) as {
  hashObject: (value: unknown) => string;
};

function readJson(relative: string): Record<string, any> {
  return JSON.parse(readFileSync(path.join(ROOT, relative), "utf8")) as Record<string, any>;
}

describe("goal-control machine contract schemas", () => {
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
    const schemaIntent = compileDraft202012(intentSchema);
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
      thread_id: "codex-thread-actual-schema-1",
      host_id: "codex-host-actual-schema-1",
      session_id: "codex-session-actual-schema-1",
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
      operation_id: observation.operation_id,
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
      identity_observation: {
        receipt_sha256: `sha256:${"f".repeat(64)}`,
        receipt_file_identity_sha256: `sha256:${"2".repeat(64)}`,
        record_sha256: observation.record_sha256,
        attestation_key_id: observation.attestation.key_id,
        observed_at: observation.observed_at,
        expires_at: observation.expires_at,
        worker_bootstrap_binding_sha256: null,
      },
      issuer_authority: {
        kind: "BOOTSTRAP",
        capability_sha256: "1".repeat(64),
        source_task_id: null,
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
      { ...observation, thread_id: `GhP_${"Z".repeat(36)}` },
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

    const conditionalContracts = Object.fromEntries(schema.allOf.map((entry: any) => {
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
