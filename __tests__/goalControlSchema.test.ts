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

function readJson(relative: string): Record<string, any> {
  return JSON.parse(readFileSync(path.join(ROOT, relative), "utf8")) as Record<string, any>;
}

describe("goal-control machine contract schemas", () => {
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
