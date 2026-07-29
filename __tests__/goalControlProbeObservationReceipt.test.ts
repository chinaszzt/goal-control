import { execFileSync } from "child_process";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import path from "path";
import { createRequire } from "module";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const nodeRequire = createRequire(import.meta.url);
const observation = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "canary-observation-receipt.js",
  ),
) as Record<string, (...args: any[]) => any>;
const { canonicalJson, hashObject } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "util.js"),
) as {
  canonicalJson: (value: unknown) => string;
  hashObject: (value: unknown) => string;
};
const { goalCommand } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "cli.js"),
) as {
  goalCommand: (
    args: string[],
    cwd: string,
  ) => { value: Record<string, any>; exitCode: number };
};
const {
  loadGoalStateReadOnly,
  recoveryIntentMatchesOptions,
  taskActionProjection,
  validateRoleLaunchBoundary,
} = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "goal.js"),
) as {
  loadGoalStateReadOnly: (
    cwd: string,
    goalId: string,
    consume: (loaded: Record<string, any>) => unknown,
  ) => any;
  taskActionProjection: (
    paths: Record<string, string>,
    state: Record<string, any>,
    goalId: string,
    manifestTask: Record<string, any>,
    options: Record<string, any>,
  ) => Record<string, any>;
  validateRoleLaunchBoundary: (
    cwd: string,
    root: string,
    loaded: Record<string, any>,
    state: Record<string, any>,
    event: Record<string, any>,
  ) => void;
  recoveryIntentMatchesOptions: (
    intent: Record<string, any>,
    eventId: string,
    options: Record<string, any>,
  ) => boolean;
};
const { sessionOperationalScope } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "operational-scope.js"),
) as {
  sessionOperationalScope: (
    state: Record<string, any>,
    role: string,
  ) => string | null;
};
const { validateManifest } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "validation.js"),
) as {
  validateManifest: (
    manifest: Record<string, unknown>,
    manifestFile: string,
    repositoryRoot: string,
  ) => Record<string, any>;
};
const { canaryPlan } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "canary-plan.js"),
) as {
  canaryPlan: (
    cwd: string,
    options: Record<string, unknown>,
  ) => Record<string, any>;
};
const {
  FAKE_ADAPTERS,
  fakeReceipt,
  sealFakeReceipt,
} = nodeRequire(
  path.join(ROOT, "lab", "fakes", "probe-observation-adapters.js"),
) as {
  FAKE_ADAPTERS: Record<string, string>;
  fakeReceipt: (options: Record<string, unknown>) => Record<string, any>;
  sealFakeReceipt: (
    receipt: Record<string, unknown>,
    options: Record<string, unknown>,
  ) => Record<string, any>;
};

const roots: string[] = [];

type Fixture = {
  root: string;
  planFile: string;
  receiptFile: string;
  planEnvelope: Record<string, any>;
  receipt: Record<string, any>;
  options: Record<string, any>;
  repository: ReturnType<typeof integrationRepository>;
  initialized: Record<string, any>;
};

function fileSha256(file: string): string {
  return `sha256:${createHash("sha256")
    .update(readFileSync(file))
    .digest("hex")}`;
}

function writePrivateJson(file: string, value: unknown): void {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o600,
  });
  chmodSync(file, 0o600);
}

function ordinaryFileBytesUnder(root: string): Buffer[] {
  const bytes: Buffer[] = [];
  if (!existsSync(root)) return bytes;
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory)) {
      const entry = path.join(directory, name);
      const stat = statSync(entry);
      if (stat.isDirectory()) {
        visit(entry);
      } else if (stat.isFile()) {
        bytes.push(readFileSync(entry));
      }
    }
  };
  visit(root);
  return bytes;
}

function expectSecretAbsent(
  secret: string,
  surfaces: Array<string | Buffer>,
): void {
  expect(surfaces.some((surface) => (
    Buffer.isBuffer(surface)
      ? surface.includes(Buffer.from(secret))
      : surface.includes(secret)
  ))).toBe(false);
}

function sealReceipt(current: Fixture): void {
  const authenticated = sealFakeReceipt(
    current.receipt,
    current.options,
  );
  Object.keys(current.receipt).forEach((key) => {
    delete current.receipt[key];
  });
  Object.assign(current.receipt, authenticated);
}

function sealHostAdapterReceipt(
  receipt: Record<string, any>,
  repository: ReturnType<typeof integrationRepository>,
): Record<string, any> {
  const value = JSON.parse(JSON.stringify(receipt));
  delete value.receipt_binding_sha256;
  const hostAttestation =
    repository.manifest.probe_observation_receipts.host_attestation;
  value.receipt_attestation = {
    algorithm: hostAttestation.algorithm,
    key_id: hostAttestation.key_id,
    public_key_sha256: hostAttestation.public_key_sha256,
  };
  value.receipt_attestation.signature_base64url = sign(
    null,
    Buffer.from(canonicalJson(value)),
    repository.hostAttestationPrivateKey,
  ).toString("base64url");
  value.receipt_binding_sha256 = hashObject(value);
  return value;
}

function fixture(
  overrides: {
    role?: string;
    taskId?: string;
    receiptOverrides?: Record<string, unknown>;
    repository?: ReturnType<typeof integrationRepository>;
    initialized?: Record<string, any>;
    productionHost?: boolean;
    eventTag?: string;
  } = {},
): Fixture {
  delete process.env.GOAL_CONTROL_DIR;
  delete process.env.GOAL_CONTROL_TEST_MODE;
  const repository = overrides.repository || integrationRepository();
  if (!overrides.productionHost) {
    process.env.GOAL_CONTROL_DIR = repository.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
  }
  const initialized = overrides.initialized || goalCommand([
      "init",
      "--manifest",
      repository.manifestFile,
      "--json",
    ], repository.root).value;
  const root = realpathSync(mkdtempSync(
    path.join(tmpdir(), "goal-probe-observation-"),
  ));
  roots.push(root);
  chmodSync(root, 0o700);
  const role = overrides.role || "DEV";
  const taskId = overrides.taskId || "TASK-A";
  const goalId = "goal-receipt-integration";
  const planEnvelope = canaryPlan(repository.root, {
    manifestFile: path.relative(
      repository.root,
      repository.manifestFile,
    ),
    role,
    taskId: role === "FOREMAN" ? null : taskId,
    browserCanaryReceipt: null,
  });
  const eventId = [
    `register-${role.toLowerCase()}-receipt`,
    overrides.eventTag || "1",
  ].join("-");
  const challengeRecord = goalCommand([
    "prepare-probe-observation-challenge",
    "--goal", goalId,
    "--task", taskId,
    "--role", role,
    "--thread", `${role.toLowerCase()}-thread-1`,
    "--host", "host-1",
    "--attempt", "1",
    "--event-id", eventId,
    "--canary-plan-sha256", planEnvelope.canary_plan_sha256,
    "--issuer-capability-file",
    String(initialized.bootstrap_capability_file),
    "--json",
  ], repository.root).value;
  const options: Record<string, any> = {
    registrationEventId: eventId,
    goalId,
    taskId,
    role,
    threadId: `${role.toLowerCase()}-thread-1`,
    hostId: "host-1",
    attempt: 1,
    repositoryHead: repository.fullHead,
    repositoryWorktree: repository.root,
    invocationCwd: repository.root,
    validatedManifestSha256: repository.manifest.manifest_sha256,
    manifest: repository.manifest,
    hostAttestationPrivateKey: repository.hostAttestationPrivateKey,
    stableId: `canary-observation-${eventId}`,
    challenge: challengeRecord.challenge,
    challengeRecord,
    planEnvelope,
    evidenceDirectory: path.join(
      repository.controlDir,
      `direct-evidence-${role.toLowerCase()}-${eventId}`,
    ),
    ...(overrides.receiptOverrides || {}),
  };
  const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
  const previousControlDir = process.env.GOAL_CONTROL_DIR;
  process.env.GOAL_CONTROL_TEST_MODE = "1";
  process.env.GOAL_CONTROL_DIR = repository.controlDir;
  if (
    options.overrides
      && options.overrides.FIRST_PROBE
  ) {
    options.overrides[
      planEnvelope.canary_plan.required_probes[0]
    ] = options.overrides.FIRST_PROBE;
    delete options.overrides.FIRST_PROBE;
  }
  let receipt = fakeReceipt(options);
  if (overrides.productionHost) {
    receipt.producer.namespace = "HOST_ADAPTER";
    receipt = sealHostAdapterReceipt(receipt, repository);
  }
  options.acceptanceTime = receipt.observed_at;
  if (previousTestMode === undefined) {
    delete process.env.GOAL_CONTROL_TEST_MODE;
  } else {
    process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
  }
  if (previousControlDir === undefined) {
    delete process.env.GOAL_CONTROL_DIR;
  } else {
    process.env.GOAL_CONTROL_DIR = previousControlDir;
  }
  const planFile = path.join(root, "plan.json");
  const receiptFile = path.join(root, "receipt.json");
  writePrivateJson(planFile, planEnvelope);
  writePrivateJson(receiptFile, receipt);
  Object.assign(options, {
    probeObservationReceipt: receiptFile,
    probeObservationReceiptSha256: fileSha256(receiptFile),
    probeObservationPlan: planFile,
    probeObservationPlanSha256: planEnvelope.canary_plan_sha256,
    probeObservationStableId: options.stableId,
    probeObservationChallenge: challengeRecord.challenge,
  });
  return {
    root,
    planFile,
    receiptFile,
    planEnvelope,
    receipt,
    options,
    repository,
    initialized,
  };
}

function rewriteReceipt(current: Fixture): void {
  sealReceipt(current);
  writePrivateJson(current.receiptFile, current.receipt);
  current.options.probeObservationReceiptSha256 =
    fileSha256(current.receiptFile);
}

function rewriteHostAdapterReceipt(current: Fixture): void {
  const authenticated = sealHostAdapterReceipt(
    current.receipt,
    current.repository,
  );
  Object.keys(current.receipt).forEach((key) => {
    delete current.receipt[key];
  });
  Object.assign(current.receipt, authenticated);
  writePrivateJson(current.receiptFile, current.receipt);
  current.options.probeObservationReceiptSha256 =
    fileSha256(current.receiptFile);
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

function integrationRepository(): {
  root: string;
  controlDir: string;
  manifestFile: string;
  manifestSha: string;
  fullHead: string;
  manifest: Record<string, any>;
  hostAttestationPrivateKey: any;
} {
  const trustedTestRoot = realpathSync(tmpdir());
  const root = realpathSync(
    mkdtempSync(
      path.join(trustedTestRoot, "goal-probe-registration-repo-"),
    ),
  );
  const controlDir = realpathSync(
    mkdtempSync(
      path.join(trustedTestRoot, "goal-probe-registration-state-"),
    ),
  );
  roots.push(root, controlDir);
  chmodSync(controlDir, 0o700);
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.name", "Probe Receipt Test");
  git(root, "config", "user.email", "probe@example.invalid");
  writeFileSync(path.join(root, "README.md"), "# receipt fixture\n");
  writeFileSync(
    path.join(root, "pnpm-lock.yaml"),
    "lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n",
  );
  git(root, "add", ".");
  git(root, "commit", "-qm", "base");
  const baseHead = git(root, "rev-parse", "HEAD");
  const hostAttestation = generateKeyPairSync("ed25519");
  const hostAttestationPublicKey = hostAttestation.publicKey.export({
    format: "der",
    type: "spki",
  });
  const packetRelative =
    "docs/planning/goals/receipt/packets/TASK-A-r1.md";
  const packetFile = path.join(root, packetRelative);
  mkdirSync(path.dirname(packetFile), { recursive: true });
  const packetBody = "# TASK-A\n\nReceipt registration fixture.\n";
  writeFileSync(packetFile, packetBody);
  const manifestRelative =
    "docs/planning/goals/receipt/manifest.json";
  const manifestFile = path.join(root, manifestRelative);
  const manifest = {
    schema_version: 1,
    goal_id: "goal-receipt-integration",
    mode: "shadow",
    repository: {
      name_with_owner: "example/receipt",
      base_branch: "main",
    },
    base_head: baseHead,
    probe_observation_receipts: {
      protocol: "goalctl-sealed-probe-observation-v1",
      max_ttl_ms: 120_000,
      host_attestation: {
        algorithm: "ED25519",
        key_id: "host-attestation-test-v1",
        public_key_sha256: `sha256:${createHash("sha256")
          .update(hostAttestationPublicKey)
          .digest("hex")}`,
        public_key_spki_base64:
          hostAttestationPublicKey.toString("base64"),
      },
    },
    tasks: [{
      id: "TASK-A",
      dependencies: [],
      integration_order: 1,
      resource_requirements: [],
      packet: {
        revision: 1,
        path: packetRelative,
        sha256: `sha256:${createHash("sha256")
          .update(packetBody)
          .digest("hex")}`,
      },
    }],
  };
  writePrivateJson(manifestFile, manifest);
  chmodSync(manifestFile, 0o644);
  git(root, "add", ".");
  git(root, "commit", "-qm", "goal");
  git(
    root,
    "remote",
    "add",
    "origin",
    "https://github.com/example/receipt.git",
  );
  const validated = validateManifest(manifest, manifestFile, root);
  return {
    root,
    controlDir,
    manifestFile,
    manifestSha: validated.manifest_sha256,
    fullHead: git(root, "rev-parse", "HEAD"),
    manifest: validated,
    hostAttestationPrivateKey: hostAttestation.privateKey,
  };
}

afterEach(() => {
  delete process.env.GOAL_CONTROL_DIR;
  delete process.env.GOAL_CONTROL_TEST_MODE;
  delete process.env.GOAL_CONTROL_NOW;
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("sealed probe observation receipt", () => {
  test("validates a PASS receipt across every fake adapter family", () => {
    const current = fixture();
    expect(Object.keys(FAKE_ADAPTERS)).toEqual([
      "GITHUB_CLI",
      "GIT_TRANSPORT",
      "GITHUB_APP",
      "BROWSER",
      "TASK_BROKER",
      "CONTROLLER_CLI",
    ]);
    const binding = observation.validateReceipt(current.options);
    const roleCapability = readFileSync(
      String(current.initialized.bootstrap_capability_file),
      "utf8",
    ).trim();
    expectSecretAbsent(roleCapability, [
      JSON.stringify(current.receipt),
      JSON.stringify(current.planEnvelope),
      JSON.stringify(current.options.challengeRecord),
      JSON.stringify(binding),
      ...ordinaryFileBytesUnder(current.options.evidenceDirectory),
    ]);
    expect(binding).toMatchObject({
      aggregate_disposition: "PASS",
      stable_id: current.options.probeObservationStableId,
      challenge: current.options.probeObservationChallenge,
      thread_id: "dev-thread-1",
      host_id: "host-1",
      attempt: 1,
      plan_file: expect.stringContaining("direct-evidence-dev"),
      receipt_file: expect.stringContaining("direct-evidence-dev"),
    });
    unlinkSync(current.planFile);
    unlinkSync(current.receiptFile);
    expect(observation.assertRequiredLiveBinding(
      current.options.manifest,
      { probe_observation: binding },
      "launch",
    )).toEqual(binding);
  });

  test("accepts a goal-wide FOREMAN plan while binding its task projection", () => {
    const current = fixture({
      role: "FOREMAN",
      taskId: "TASK-A",
    });
    expect(observation.validateReceipt(current.options)).toMatchObject({
      thread_id: "foreman-thread-1",
      aggregate_disposition: "PASS",
    });
  });

  test("mechanically aggregates the complete disposition vocabulary", () => {
    const result = (disposition: string, interactive = false) => ({
      disposition,
      interactive: {
        allow_prompt: interactive,
        auth_prompt: false,
      },
    });
    expect(observation.aggregateProbeResults([result("PASS")]))
      .toBe("PASS");
    expect(observation.aggregateProbeResults([
      result("KNOWN_LIMITATION"),
    ])).toBe("KNOWN_LIMITATION");
    expect(observation.aggregateProbeResults([
      result("KNOWN_LIMITATION"),
      result("PROVISIONAL_KNOWN_LIMITATION"),
    ])).toBe("PROVISIONAL_KNOWN_LIMITATION");
    expect(observation.aggregateProbeResults([
      result("PASS", true),
    ])).toBe("FAIL");
    const exactMatch = {
      semantic_operation: "REPOSITORY_METADATA_READ",
      target_kind: "REPOSITORY",
      repository: "example/receipt",
      result_fingerprint: "404/repo_not_found",
      allow_dialog: false,
      authentication_prompt: false,
    };
    const policy = {
      probe_evaluation: {
        known_limitations: [{
          id: "github_app_private_repo_404-v1",
          probe: "GITHUB_APP_REPOSITORY_READ",
          exact_match: exactMatch,
          compensation_probes: ["GIT_REMOTE_READ"],
          final_disposition: "KNOWN_LIMITATION",
        }],
      },
    };
    const limited = {
      probe: "GITHUB_APP_REPOSITORY_READ",
      disposition: "KNOWN_LIMITATION",
      limitation: {
        id: "github_app_private_repo_404-v1",
        exact_match: exactMatch,
      },
    };
    expect(() => observation.validateKnownLimitation(
      limited,
      policy,
      [
        limited,
        { probe: "GIT_REMOTE_READ", disposition: "PASS" },
      ],
    )).not.toThrow();
    expect(() => observation.validateKnownLimitation(
      {
        ...limited,
        limitation: {
          ...limited.limitation,
          exact_match: {
            ...exactMatch,
            result_fingerprint: "403/forbidden",
          },
        },
      },
      policy,
      [
        limited,
        { probe: "GIT_REMOTE_READ", disposition: "PASS" },
      ],
    )).toThrow(expect.objectContaining({
      code: "CANARY_OBSERVATION_LIMITATION_MISMATCH",
    }));
  });

  test.each([
    ["missing replay", (current: Fixture) => {
      delete current.receipt.replay_result;
    }],
    ["failed replay", (current: Fixture) => {
      current.receipt.replay_result.disposition = "FAIL";
    }],
    ["out-of-order replay", (current: Fixture) => {
      current.receipt.replay_result.sequence = 1;
    }],
    ["duplicate replay", (current: Fixture) => {
      current.receipt.probe_results.push({
        ...current.receipt.replay_result,
        sequence: current.receipt.probe_results.length + 1,
      });
    }],
  ])("rejects %s", (_label, mutate) => {
    const current = fixture();
    mutate(current);
    rewriteReceipt(current);
    expect(() => observation.validateReceipt(current.options))
      .toThrow();
  });

  test.each([
    ["repository", (current: Fixture) => {
      current.planEnvelope.canary_plan.repository.name_with_owner =
        "other/repository";
    }],
    ["controller", (current: Fixture) => {
      current.planEnvelope.canary_plan.controller.closure_sha256 =
        `sha256:${"9".repeat(64)}`;
    }],
    ["probe order", (current: Fixture) => {
      current.planEnvelope.canary_plan.required_probes.reverse();
    }],
  ])("rejects self-hashed non-canonical %s truth", (_label, mutate) => {
    const current = fixture();
    mutate(current);
    current.planEnvelope.canary_plan_sha256 =
      hashObject(current.planEnvelope.canary_plan);
    writePrivateJson(current.planFile, current.planEnvelope);
    current.options.probeObservationPlanSha256 =
      current.planEnvelope.canary_plan_sha256;
    expect(() => observation.validateReceipt(current.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_STALE_PLAN",
      }));
  });

  test("rejects a resealed mismatched current target identity", () => {
    const current = fixture();
    const forged = `sha256:${"8".repeat(64)}`;
    current.receipt.target_identity_sha256 = forged;
    current.receipt.replay_result.target_identity_sha256 = forged;
    for (const result of current.receipt.probe_results) {
      result.target_identity_sha256 = forged;
    }
    rewriteReceipt(current);
    expect(() => observation.validateReceipt(current.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_BINDING_MISMATCH",
      }));
  });

  test.each([
    ["missing probe", (current: Fixture) => {
      current.receipt.probe_results.pop();
    }, "CANARY_OBSERVATION_PROBE_MISMATCH"],
    ["out-of-order probe", (current: Fixture) => {
      [
        current.receipt.probe_results[0],
        current.receipt.probe_results[1],
      ] = [
        current.receipt.probe_results[1],
        current.receipt.probe_results[0],
      ];
    }, "CANARY_OBSERVATION_PROBE_MISMATCH"],
    ["duplicate probe", (current: Fixture) => {
      current.receipt.probe_results[1] = {
        ...current.receipt.probe_results[0],
        sequence: 2,
      };
    }, "CANARY_OBSERVATION_PROBE_MISMATCH"],
    ["cross-thread", (current: Fixture) => {
      current.receipt.producer.thread_id = "other-thread";
    }, "CANARY_OBSERVATION_CROSS_IDENTITY"],
    ["cross-host", (current: Fixture) => {
      current.receipt.producer.host_id = "other-host";
    }, "CANARY_OBSERVATION_CROSS_IDENTITY"],
    ["cross-attempt", (current: Fixture) => {
      current.receipt.producer.attempt = 2;
    }, "CANARY_OBSERVATION_CROSS_IDENTITY"],
    ["old challenge", (current: Fixture) => {
      current.receipt.challenge = "cd".repeat(32);
    }, "CANARY_OBSERVATION_BINDING_MISMATCH"],
  ])("rejects %s", (_label, mutate, code) => {
    const current = fixture();
    mutate(current);
    rewriteReceipt(current);
    expect(() => observation.validateReceipt(current.options))
      .toThrow(expect.objectContaining({ code }));
  });

  test("rejects a stale plan even when the caller recomputes its hashes", () => {
    const current = fixture();
    current.planEnvelope.canary_plan.repository_head = "9".repeat(40);
    current.planEnvelope.canary_plan_sha256 =
      hashObject(current.planEnvelope.canary_plan);
    writePrivateJson(current.planFile, current.planEnvelope);
    current.options.probeObservationPlanSha256 =
      current.planEnvelope.canary_plan_sha256;
    current.receipt.canary_plan_sha256 =
      current.planEnvelope.canary_plan_sha256;
    rewriteReceipt(current);
    expect(() => observation.validateReceipt(current.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_STALE_PLAN",
      }));
  });

  test("rejects variant stable IDs and exact-retry request variants", () => {
    const current = fixture();
    current.options.probeObservationStableId =
      "canary-observation-different-registration";
    expect(() => observation.validateReceipt(current.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_STABLE_ID_MISMATCH",
      }));
    current.options.probeObservationStableId =
      current.receipt.stable_id;
    const binding = observation.validateReceipt(current.options);
    expect(observation.requestMatchesBinding(binding, current.options))
      .toBe(true);
    const copiedPlan = path.join(current.root, "plan-copy.json");
    copyFileSync(current.planFile, copiedPlan);
    chmodSync(copiedPlan, 0o600);
    expect(observation.requestMatchesBinding(binding, {
      ...current.options,
      probeObservationPlan: copiedPlan,
    })).toBe(false);
    expect(observation.requestMatchesBinding(binding, {
      ...current.options,
      probeObservationChallenge: "ef".repeat(32),
    })).toBe(false);
  });

  test("rejects expired and non-PASS receipts before registration", () => {
    const expired = fixture({
      receiptOverrides: {
        observedAt: new Date(Date.now() - 180_000).toISOString(),
        ttlMs: 60_000,
      },
    });
    expect(() => observation.validateReceipt(expired.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_EXPIRED",
      }));

    const limited = fixture({
      receiptOverrides: {
        overrides: {
          FIRST_PROBE: {
            disposition: "FAIL",
          },
        },
      },
    });
    expect(() => observation.validateReceipt(limited.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_NOT_PASS",
      }));
  });

  test("uses the locked accepted_at boundary for near-expiry TTL", () => {
    const near = fixture();
    near.options.acceptanceTime = new Date(
      Date.parse(near.receipt.expires_at) - 1,
    ).toISOString();
    expect(() => observation.validateReceipt(near.options)).not.toThrow();

    const expired = fixture();
    expired.options.acceptanceTime = expired.receipt.expires_at;
    expect(existsSync(expired.options.evidenceDirectory)).toBe(false);
    expect(() => observation.validateReceipt(expired.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_EXPIRED",
      }));
    expect(existsSync(expired.options.evidenceDirectory)).toBe(false);
  });

  test("missing recovery binding cannot silently regain FULL", () => {
    expect(sessionOperationalScope({
      probe_observation_required: true,
      sessions: {
        FOREMAN: {
          status: "active",
        },
      },
    }, "FOREMAN")).toBe("PREFLIGHT_ONLY");
  });

  test("recovery receipt request exact-retries and conflicts mechanically", () => {
    const current = fixture({ role: "FOREMAN" });
    const binding = observation.validateReceipt(current.options);
    const recoveryOptions: Record<string, any> = {
      ...current.options,
      eventId: current.options.registrationEventId,
      expectedGoalScopeSha256: `sha256:${"6".repeat(64)}`,
      leaseMs: 60_000,
      reason: "expired foreman",
      incidentRef: "incident:foreman-expired",
    };
    const intent = {
      request: {
        root_recovery_id: recoveryOptions.eventId,
        goal_id: recoveryOptions.goalId,
        anchor_task_id: recoveryOptions.taskId,
        successor: {
          role: "FOREMAN",
          thread_id: recoveryOptions.threadId,
          host_id: recoveryOptions.hostId,
          attempt: recoveryOptions.attempt,
          lease_ms: recoveryOptions.leaseMs,
        },
        expected_goal_scope_sha256:
          recoveryOptions.expectedGoalScopeSha256,
        reason: recoveryOptions.reason,
        incident_ref: recoveryOptions.incidentRef,
        probe_observation: binding,
      },
    };
    expect(recoveryIntentMatchesOptions(
      intent,
      recoveryOptions.eventId,
      recoveryOptions,
    )).toBe(true);
    expect(recoveryIntentMatchesOptions(
      intent,
      recoveryOptions.eventId,
      {
        ...recoveryOptions,
        probeObservationChallenge: "ef".repeat(32),
      },
    )).toBe(false);
  });

  test("durable launch checks reject expired or tampered evidence", () => {
    const expired = fixture();
    const binding = observation.validateReceipt(expired.options);
    expect(() => observation.assertRequiredLiveBinding(
      expired.options.manifest,
      { probe_observation: binding },
      "LAUNCH_DEV durable boundary",
      Date.parse(binding.expires_at),
    )).toThrow(expect.objectContaining({
      code: "CANARY_OBSERVATION_EXPIRED",
    }));

    const tampered = fixture();
    const tamperedBinding =
      observation.validateReceipt(tampered.options);
    writeFileSync(
      tamperedBinding.receipt_file,
      `${readFileSync(tamperedBinding.receipt_file, "utf8")} `,
    );
    chmodSync(tamperedBinding.receipt_file, 0o600);
    expect(() => observation.assertRequiredLiveBinding(
      tampered.options.manifest,
      { probe_observation: tamperedBinding },
      "REVIEW_PASS durable boundary",
    )).toThrow(expect.objectContaining({
      code: "CANARY_OBSERVATION_CONTENT_HASH_MISMATCH",
    }));
  });

  test("projects zero verdicts and dual-gates LAUNCH actor and target", () => {
    const captainReceipt = fixture({
      role: "CAPTAIN",
      receiptOverrides: { ttlMs: 20_000 },
    });
    const devReceipt = fixture({
      role: "DEV",
      repository: captainReceipt.repository,
      initialized: captainReceipt.initialized,
      receiptOverrides: { ttlMs: 100_000 },
    });
    const captainBinding =
      observation.validateReceipt(captainReceipt.options);
    const devBinding = observation.validateReceipt(devReceipt.options);
    const loaded = loadGoalStateReadOnly(
      captainReceipt.repository.root,
      captainReceipt.options.goalId,
      (value) => value,
    );
    const state = JSON.parse(JSON.stringify(
      loaded.snapshot.tasks["TASK-A"],
    ));
    state.phase = "DEV_ACTIVE";
    state.full_head = captainReceipt.repository.fullHead;
    state.sessions = {
      CAPTAIN: {
        role: "CAPTAIN",
        thread_id: "captain-thread-1",
        host_id: "host-1",
        attempt: 1,
        status: "active",
        probe_observation: captainBinding,
      },
      DEV: {
        role: "DEV",
        thread_id: "dev-thread-1",
        host_id: "host-1",
        attempt: 1,
        status: "active",
        launch_id: "launch-dev-receipt-gate",
        probe_observation: devBinding,
      },
    };
    const expiredProjectionState =
      JSON.parse(JSON.stringify(state));
    expiredProjectionState.sessions.DEV.probe_observation.expires_at =
      new Date(Date.now() - 1).toISOString();
    const expiredProjection = taskActionProjection(
      loaded.paths,
      expiredProjectionState,
      captainReceipt.options.goalId,
      loaded.manifest.tasks[0],
      {
        manifest: loaded.manifest,
        goalSnapshot: {
          ...loaded.snapshot,
          tasks: {
            ...loaded.snapshot.tasks,
            "TASK-A": expiredProjectionState,
          },
        },
        readOnly: true,
      },
    );
    expect(expiredProjection.launch_scope).toBe("PREFLIGHT_ONLY");
    expect(expiredProjection.actions.map(
      (action: Record<string, any>) => action.type,
    )).not.toContain("DEV_READY");

    const wrongActor = {
      type: "LAUNCH_DEV",
      actor: {
        role: "DEV",
        thread_id: "dev-thread-1",
        host_id: "host-1",
      },
      accepted_at: new Date().toISOString(),
      payload: { launch_id: "launch-dev-receipt-gate" },
    };
    expect(() => validateRoleLaunchBoundary(
      captainReceipt.repository.root,
      captainReceipt.repository.controlDir,
      loaded,
      state,
      wrongActor,
    )).toThrow(expect.objectContaining({
      code: "CAPTAIN_ACTOR_REQUIRED",
    }));

    const expiredCaptain = {
      ...wrongActor,
      actor: {
        role: "CAPTAIN",
        thread_id: "captain-thread-1",
        host_id: "host-1",
      },
      accepted_at: captainBinding.expires_at,
    };
    expect(() => validateRoleLaunchBoundary(
      captainReceipt.repository.root,
      captainReceipt.repository.controlDir,
      loaded,
      state,
      expiredCaptain,
    )).toThrow(expect.objectContaining({
      code: "CANARY_OBSERVATION_EXPIRED",
    }));

    writeFileSync(
      devBinding.receipt_file,
      `${readFileSync(devBinding.receipt_file, "utf8")} `,
    );
    chmodSync(devBinding.receipt_file, 0o600);
    const tamperedProjection = taskActionProjection(
      loaded.paths,
      state,
      captainReceipt.options.goalId,
      loaded.manifest.tasks[0],
      {
        manifest: loaded.manifest,
        goalSnapshot: {
          ...loaded.snapshot,
          tasks: {
            ...loaded.snapshot.tasks,
            "TASK-A": state,
          },
        },
        readOnly: true,
      },
    );
    expect(tamperedProjection.launch_scope).toBe("PREFLIGHT_ONLY");
    expect(tamperedProjection.launch_error_code)
      .toBe("CANARY_OBSERVATION_CONTENT_HASH_MISMATCH");
    expect(tamperedProjection.actions.map(
      (action: Record<string, any>) => action.type,
    )).not.toContain("DEV_READY");
    expect(() => validateRoleLaunchBoundary(
      captainReceipt.repository.root,
      captainReceipt.repository.controlDir,
      loaded,
      state,
      {
        ...expiredCaptain,
        accepted_at: new Date().toISOString(),
      },
    )).toThrow(expect.objectContaining({
      code: "CANARY_OBSERVATION_CONTENT_HASH_MISMATCH",
    }));
  });

  test.each([
    ["P1_COMMITTED", "DEV", "LAUNCH_DEV"],
    ["DEV_READY", "REVIEW", "LAUNCH_REVIEW"],
    ["REVIEW_PASS", "RECEIPT", "LAUNCH_RECEIPT"],
  ])(
    "public projection dual-gates %s %s across missing, expired, and tampered receipts",
    (phase, targetRole, launchAction) => {
      const captainShort = fixture({
        role: "CAPTAIN",
        eventTag: "projection-short",
        receiptOverrides: { ttlMs: 30_000 },
      });
      const targetShort = fixture({
        role: targetRole,
        eventTag: "projection-short",
        repository: captainShort.repository,
        initialized: captainShort.initialized,
        receiptOverrides: { ttlMs: 30_000 },
      });
      const captainLong = fixture({
        role: "CAPTAIN",
        eventTag: "projection-long",
        repository: captainShort.repository,
        initialized: captainShort.initialized,
        receiptOverrides: { ttlMs: 90_000 },
      });
      const targetLong = fixture({
        role: targetRole,
        eventTag: "projection-long",
        repository: captainShort.repository,
        initialized: captainShort.initialized,
        receiptOverrides: { ttlMs: 90_000 },
      });
      const bindings = {
        captainShort: observation.validateReceipt(
          captainShort.options,
        ),
        targetLong: observation.validateReceipt(targetLong.options),
        captainLong: observation.validateReceipt(captainLong.options),
        targetShort: observation.validateReceipt(targetShort.options),
      };
      const loaded = loadGoalStateReadOnly(
        captainShort.repository.root,
        captainShort.options.goalId,
        (value) => value,
      );
      const makeState = (
        captainBinding: Record<string, any> | null,
        targetBinding: Record<string, any> | null,
      ) => {
        const state = JSON.parse(JSON.stringify(
          loaded.snapshot.tasks["TASK-A"],
        ));
        state.phase = phase;
        state.full_head = captainShort.repository.fullHead;
        state.sessions = {
          CAPTAIN: {
            role: "CAPTAIN",
            thread_id: "captain-thread-1",
            host_id: "host-1",
            attempt: 1,
            status: "active",
            ...(captainBinding
              ? { probe_observation: captainBinding }
              : {}),
          },
          [targetRole]: {
            role: targetRole,
            thread_id: `${targetRole.toLowerCase()}-thread-1`,
            host_id: "host-1",
            attempt: 1,
            status: "idle",
            ...(targetBinding
              ? { probe_observation: targetBinding }
              : {}),
          },
        };
        return state;
      };
      const project = (state: Record<string, any>) =>
        taskActionProjection(
          loaded.paths,
          state,
          captainShort.options.goalId,
          loaded.manifest.tasks[0],
          {
            manifest: loaded.manifest,
            goalSnapshot: {
              ...loaded.snapshot,
              tasks: {
                ...loaded.snapshot.tasks,
                "TASK-A": state,
              },
            },
            readOnly: true,
          },
        );
      const actionTypes = (projection: Record<string, any>) =>
        projection.actions.map(
          (action: Record<string, any>) => action.type,
        );

      expect(actionTypes(project(makeState(
        bindings.captainLong,
        bindings.targetLong,
      )))).toContain(launchAction);
      expect(actionTypes(project(makeState(
        null,
        bindings.targetLong,
      )))).not.toContain(launchAction);
      expect(actionTypes(project(makeState(
        bindings.captainLong,
        null,
      )))).not.toContain(launchAction);

      const tamperedCaptain = JSON.parse(JSON.stringify(
        bindings.captainLong,
      ));
      tamperedCaptain.attestation_signature_base64url =
        "A".repeat(86);
      expect(actionTypes(project(makeState(
        tamperedCaptain,
        bindings.targetLong,
      )))).not.toContain(launchAction);
      const tamperedTarget = JSON.parse(JSON.stringify(
        bindings.targetLong,
      ));
      tamperedTarget.attestation_signature_base64url =
        "A".repeat(86);
      expect(actionTypes(project(makeState(
        bindings.captainLong,
        tamperedTarget,
      )))).not.toContain(launchAction);

      process.env.GOAL_CONTROL_NOW = new Date(Math.max(
        Date.parse(bindings.captainShort.expires_at),
        Date.parse(bindings.targetShort.expires_at),
      )).toISOString();
      expect(actionTypes(project(makeState(
        bindings.captainShort,
        bindings.targetLong,
      )))).not.toContain(launchAction);
      expect(actionTypes(project(makeState(
        bindings.captainLong,
        bindings.targetShort,
      )))).not.toContain(launchAction);
      delete process.env.GOAL_CONTROL_NOW;
    },
  );

  test("classifies interactive Allow/auth deterministically as FAIL", () => {
    const current = fixture({
      receiptOverrides: {
        overrides: {
          FIRST_PROBE: {
            allowPrompt: true,
          },
        },
      },
    });
    expect(() => observation.validateReceipt(current.options))
      .toThrow(expect.objectContaining({
        code: "INTERACTIVE_APPROVAL_REQUIRED",
      }));
  });

  test("rejects forged aggregate, sensitive text, and content hash drift", () => {
    const aggregate = fixture({
      receiptOverrides: {
        overrides: {
          FIRST_PROBE: {
            disposition: "FAIL",
          },
        },
      },
    });
    aggregate.receipt.aggregate_disposition = "PASS";
    rewriteReceipt(aggregate);
    expect(() => observation.validateReceipt(aggregate.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_AGGREGATE_MISMATCH",
      }));

    const sensitive = fixture();
    const unsafe = JSON.parse(JSON.stringify(sensitive.receipt));
    unsafe.token = "forbidden";
    writePrivateJson(sensitive.receiptFile, unsafe);
    sensitive.options.probeObservationReceiptSha256 =
      fileSha256(sensitive.receiptFile);
    expect(() => observation.validateReceipt(sensitive.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_SENSITIVE_DATA",
      }));

    const drift = fixture();
    drift.options.probeObservationReceiptSha256 =
      `sha256:${"0".repeat(64)}`;
    expect(() => observation.validateReceipt(drift.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_CONTENT_HASH_MISMATCH",
      }));
  });

  test("accepts only controller-bound evidence references", () => {
    const current = fixture();
    const results = [
      current.receipt.replay_result,
      ...current.receipt.probe_results,
    ];
    for (const result of results) {
      for (const reference of result.evidence_refs) {
        expect(reference).toMatchObject({
          kind: "HOST_ADAPTER_EVIDENCE",
          id: expect.stringMatching(
            /^controller-evidence-v1-[0-9a-f]{64}$/,
          ),
          sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        });
      }
    }
    expect(() => observation.validateReceipt(current.options))
      .not.toThrow();
  });

  test("rejects valid-host-signed capability and token evidence IDs without echoing them", () => {
    const capabilityReceipt = fixture({ productionHost: true });
    const roleCapability = readFileSync(
      String(capabilityReceipt.initialized.bootstrap_capability_file),
      "utf8",
    ).trim();
    expect(roleCapability).toHaveLength(43);
    capabilityReceipt.receipt.probe_results[0].evidence_refs[0].id =
      roleCapability;
    rewriteHostAdapterReceipt(capabilityReceipt);
    let capabilityError: any = null;
    try {
      observation.validateReceipt(capabilityReceipt.options);
    } catch (error) {
      capabilityError = error;
    }
    expect(capabilityError).toMatchObject({
      code: "CANARY_OBSERVATION_SENSITIVE_DATA",
    });
    expect(String(capabilityError?.message)).not.toContain(roleCapability);

    const tokenReceipt = fixture({ productionHost: true });
    const tokenCanary = `ghp_${"Z".repeat(36)}`;
    tokenReceipt.receipt.probe_results[0].evidence_refs[0].id =
      tokenCanary;
    rewriteHostAdapterReceipt(tokenReceipt);
    let tokenError: any = null;
    try {
      observation.validateReceipt(tokenReceipt.options);
    } catch (error) {
      tokenError = error;
    }
    expect(tokenError).toMatchObject({
      code: "CANARY_OBSERVATION_SENSITIVE_DATA",
    });
    expect(String(tokenError?.message)).not.toContain(tokenCanary);
  });

  test("rejects evidence reference mismatch, result replay, and cross-session reuse", () => {
    const mismatch = fixture();
    const mismatchId =
      mismatch.receipt.probe_results[0].evidence_refs[0].id;
    mismatch.receipt.probe_results[0].evidence_refs[0].id =
      `${mismatchId.slice(0, -1)}${mismatchId.endsWith("0") ? "1" : "0"}`;
    rewriteReceipt(mismatch);
    expect(() => observation.validateReceipt(mismatch.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_EVIDENCE_REFERENCE_MISMATCH",
      }));

    const replay = fixture();
    const replayReference = JSON.parse(JSON.stringify(
      replay.receipt.replay_result.evidence_refs[0],
    ));
    replay.receipt.replay_result.evidence_refs[0] =
      replay.receipt.probe_results[0].evidence_refs[0];
    replay.receipt.probe_results[0].evidence_refs[0] =
      replayReference;
    rewriteReceipt(replay);
    expect(() => observation.validateReceipt(replay.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_EVIDENCE_REFERENCE_MISMATCH",
      }));

    const source = fixture({ eventTag: "evidence-source" });
    const target = fixture({ eventTag: "evidence-target" });
    target.receipt.probe_results[0].evidence_refs[0] =
      JSON.parse(JSON.stringify(
        source.receipt.probe_results[0].evidence_refs[0],
      ));
    rewriteReceipt(target);
    expect(() => observation.validateReceipt(target.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_EVIDENCE_REFERENCE_MISMATCH",
      }));
  });

  test("closes authenticated limitation claims to the exact 404 schema", () => {
    const nested = fixture();
    nested.receipt.probe_results[0].disposition =
      "PROVISIONAL_KNOWN_LIMITATION";
    nested.receipt.probe_results[0].limitation = {
      id: "github_app_private_repo_404-v1",
      exact_match: {
        semantic_operation: "REPOSITORY_METADATA_READ",
        target_kind: "REPOSITORY",
        repository: "example/receipt",
        result_fingerprint: "404/repo_not_found",
        allow_dialog: false,
        authentication_prompt: false,
      },
      capability_bytes: {
        unlabeled: "never-serialize-this-secret",
      },
    };
    rewriteReceipt(nested);
    expect(() => observation.validateReceipt(nested.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_SENSITIVE_DATA",
      }));

    const additional = fixture();
    additional.receipt.probe_results[0].limitation = {
      id: "github_app_private_repo_404-v1",
      exact_match: {
        semantic_operation: "REPOSITORY_METADATA_READ",
        target_kind: "REPOSITORY",
        repository: "example/receipt",
        result_fingerprint: "404/repo_not_found",
        allow_dialog: false,
        authentication_prompt: false,
      },
      nested: { opaque: "not-allowed" },
    };
    rewriteReceipt(additional);
    expect(() => observation.validateReceipt(additional.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_INVALID",
      }));
  });

  test("requires private ordinary no-follow single-link files", () => {
    const permissive = fixture();
    chmodSync(permissive.receiptFile, 0o644);
    expect(() => observation.validateReceipt(permissive.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_FILE_PERMISSIONS",
      }));

    const specialBits = fixture();
    chmodSync(specialBits.receiptFile, 0o1600);
    expect(() => observation.validateReceipt(specialBits.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_FILE_PERMISSIONS",
      }));

    const hardLinked = fixture();
    linkSync(
      hardLinked.receiptFile,
      path.join(hardLinked.root, "receipt-hard-link.json"),
    );
    expect(() => observation.validateReceipt(hardLinked.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_FILE_PERMISSIONS",
      }));

    const symbolic = fixture();
    const link = path.join(symbolic.root, "receipt-symbolic.json");
    symlinkSync(symbolic.receiptFile, link);
    expect(() => observation.validateReceipt({
      ...symbolic.options,
      probeObservationReceipt: link,
    })).toThrow(expect.objectContaining({
      code: "CANARY_OBSERVATION_FILE_PERMISSIONS",
    }));

    const ancestor = fixture();
    const alias = path.join(
      path.dirname(ancestor.root),
      `${path.basename(ancestor.root)}-alias`,
    );
    symlinkSync(ancestor.root, alias);
    roots.push(alias);
    expect(() => observation.validateReceipt({
      ...ancestor.options,
      probeObservationReceipt: path.join(alias, "receipt.json"),
    })).toThrow(expect.objectContaining({
      code: "CANARY_OBSERVATION_FILE_PERMISSIONS",
    }));
  });

  test("keeps fake adapters inaccessible outside the isolated namespace", () => {
    const current = fixture();
    const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
    delete process.env.GOAL_CONTROL_TEST_MODE;
    try {
      expect(() => fakeReceipt(current.options))
        .toThrow(expect.objectContaining({
          code: "TEST_DEPENDENCY_FORBIDDEN",
        }));
    } finally {
      if (previousTestMode !== undefined) {
        process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
      }
    }
  });

  test("rejects caller-resealed synthetic bytes renamed HOST_ADAPTER", () => {
    const current = fixture();
    current.options.challengeRecord.producer_namespace = "HOST_ADAPTER";
    const unsignedChallenge = {
      ...current.options.challengeRecord,
    };
    delete unsignedChallenge.record_sha256;
    current.options.challengeRecord.record_sha256 =
      hashObject(unsignedChallenge);
    current.receipt.producer.namespace = "HOST_ADAPTER";
    delete current.receipt.receipt_binding_sha256;
    current.receipt.receipt_binding_sha256 =
      hashObject(current.receipt);
    writePrivateJson(current.receiptFile, current.receipt);
    current.options.probeObservationReceiptSha256 =
      fileSha256(current.receiptFile);
    expect(() => observation.validateReceipt(current.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_AUTHENTICATION_INVALID",
      }));
  });

  test("same-UID roles cannot discover a signer or forge HOST_ADAPTER receipts", () => {
    const current = fixture({ productionHost: true });
    const binding = observation.validateReceipt(current.options);
    const loaded = loadGoalStateReadOnly(
      current.repository.root,
      current.options.goalId,
      (value) => value,
    );
    const privateDer = current.repository.hostAttestationPrivateKey
      .export({ format: "der", type: "pkcs8" })
      .toString("base64");
    const serialized = JSON.stringify({
      challenge: current.options.challengeRecord,
      receipt: current.receipt,
      binding,
      snapshot: loaded.snapshot,
    });
    expect(serialized).not.toContain(privateDer);
    expect(serialized).not.toContain("authenticator_file");
    expect(serialized).not.toContain("probe-observation-authenticators");
    expect(serialized).not.toContain("capability_bytes");
    const persistedBytes = ordinaryFileBytesUnder(
      current.repository.controlDir,
    );
    expect(persistedBytes.some((bytes) => (
      bytes.includes(Buffer.from(privateDer, "base64"))
        || bytes.toString("utf8").includes(privateDer)
    ))).toBe(false);
    const persistedText = Buffer.concat(persistedBytes).toString("utf8");
    expect(persistedText).not.toContain("authenticator_file");
    expect(persistedText).not.toContain("probe-observation-authenticators");

    const attacker = generateKeyPairSync("ed25519");
    const forged = JSON.parse(JSON.stringify(current.receipt));
    forged.probe_results[0].result_fingerprint_sha256 =
      `sha256:${"6".repeat(64)}`;
    delete forged.receipt_binding_sha256;
    forged.receipt_attestation = {
      algorithm: "ED25519",
      key_id: current.repository.manifest
        .probe_observation_receipts.host_attestation.key_id,
      public_key_sha256: current.repository.manifest
        .probe_observation_receipts.host_attestation.public_key_sha256,
    };
    forged.receipt_attestation.signature_base64url = sign(
      null,
      Buffer.from(canonicalJson(forged)),
      attacker.privateKey,
    ).toString("base64url");
    forged.receipt_binding_sha256 = hashObject(forged);
    writePrivateJson(current.receiptFile, forged);
    current.options.probeObservationReceiptSha256 =
      fileSha256(current.receiptFile);
    expect(() => observation.validateReceipt(current.options))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_AUTHENTICATION_INVALID",
      }));
  });

  test("controller challenge exact-retries and rejects conflicting input", () => {
    const current = fixture({ role: "FOREMAN" });
    const args = [
      "prepare-probe-observation-challenge",
      "--goal", current.options.goalId,
      "--task", current.options.taskId,
      "--role", current.options.role,
      "--thread", current.options.threadId,
      "--host", current.options.hostId,
      "--attempt", String(current.options.attempt),
      "--event-id", current.options.registrationEventId,
      "--canary-plan-sha256",
      current.options.probeObservationPlanSha256,
      "--issuer-capability-file",
      String(current.initialized.bootstrap_capability_file),
      "--json",
    ];
    expect(goalCommand(args, current.repository.root).value.challenge)
      .toBe(current.options.probeObservationChallenge);
    const conflicting = [...args];
    conflicting[
      conflicting.indexOf("--canary-plan-sha256") + 1
    ] = `sha256:${"7".repeat(64)}`;
    expect(() => goalCommand(conflicting, current.repository.root))
      .toThrow();
  });

  test("gates registration and exact-retries response loss mechanically", () => {
    const receipt = fixture({
      role: "FOREMAN",
      taskId: "TASK-A",
    });
    const repository = receipt.repository;
    const previous = {
      controlDir: process.env.GOAL_CONTROL_DIR,
      testMode: process.env.GOAL_CONTROL_TEST_MODE,
    };
    process.env.GOAL_CONTROL_DIR = repository.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    try {
      const initialized = receipt.initialized;
      const bootstrapCapability = readFileSync(
        String(initialized.bootstrap_capability_file),
        "utf8",
      ).trim();
      const eventId = receipt.options.registrationEventId;
      const common = [
        "register-role",
        "--goal", "goal-receipt-integration",
        "--task", "TASK-A",
        "--role", "FOREMAN",
        "--thread", "foreman-thread-1",
        "--host", "host-1",
        "--attempt", "1",
        "--event-id", eventId,
        "--bootstrap-capability-file",
        String(initialized.bootstrap_capability_file),
        "--json",
      ];
      expect(() => goalCommand(common, repository.root))
        .toThrow(expect.objectContaining({
          code: "CANARY_OBSERVATION_REQUIRED",
        }));
      const exact = [
        ...common.slice(0, -1),
        "--probe-observation-receipt", receipt.receiptFile,
        "--probe-observation-receipt-sha256",
        receipt.options.probeObservationReceiptSha256,
        "--probe-observation-plan", receipt.planFile,
        "--probe-observation-plan-sha256",
        receipt.options.probeObservationPlanSha256,
        "--probe-observation-stable-id",
        receipt.options.probeObservationStableId,
        "--probe-observation-challenge",
        receipt.options.probeObservationChallenge,
        "--json",
      ];
      const registered = goalCommand(exact, repository.root).value;
      expect(registered).toMatchObject({
        registered: true,
        idempotent: false,
        session: {
          probe_observation: {
            aggregate_disposition: "PASS",
            plan_file: expect.stringContaining(
              "probe-observation-evidence",
            ),
            receipt_file: expect.stringContaining(
              "probe-observation-evidence",
            ),
          },
        },
      });
      expect(goalCommand(exact, repository.root).value).toMatchObject({
        registered: true,
        idempotent: true,
      });
      const planCopy = path.join(receipt.root, "variant-plan.json");
      copyFileSync(receipt.planFile, planCopy);
      chmodSync(planCopy, 0o600);
      const variant = [...exact];
      variant[variant.indexOf("--probe-observation-plan") + 1] =
        planCopy;
      expect(() => goalCommand(variant, repository.root))
        .toThrow(expect.objectContaining({
          code: "EVENT_ID_CONFLICT",
        }));

      const loaded = loadGoalStateReadOnly(
        repository.root,
        "goal-receipt-integration",
        (value) => value,
      );
      const privateDer = repository.hostAttestationPrivateKey
        .export({ format: "der", type: "pkcs8" });
      const durableBytes = ordinaryFileBytesUnder(repository.controlDir);
      const durableSerialized = JSON.stringify({
        output: registered,
        snapshot: loaded.snapshot,
      });
      expectSecretAbsent(bootstrapCapability, [
        durableSerialized,
        readFileSync(loaded.paths.state),
        ...(existsSync(loaded.paths.ledgerJson)
          ? [readFileSync(loaded.paths.ledgerJson)]
          : []),
        ...(existsSync(loaded.paths.ledgerMarkdown)
          ? [readFileSync(loaded.paths.ledgerMarkdown)]
          : []),
        ...ordinaryFileBytesUnder(loaded.paths.controlEvents),
        ...ordinaryFileBytesUnder(
          loaded.paths.probeObservationChallenges,
        ),
        ...ordinaryFileBytesUnder(
          loaded.paths.probeObservationEvidence,
        ),
      ]);
      expect(durableSerialized).not.toContain("capability_bytes");
      expect(durableBytes.some((bytes) => bytes.includes(privateDer)))
        .toBe(false);
      expect(Buffer.concat(durableBytes).toString("utf8"))
        .not.toContain("capability_bytes");
      const registeredSession =
        loaded.snapshot.tasks["TASK-A"].sessions.FOREMAN;
      const refreshEventId = "refresh-foreman-receipt-1";
      const refreshChallenge = goalCommand([
        "prepare-probe-observation-challenge",
        "--goal", "goal-receipt-integration",
        "--task", "TASK-A",
        "--role", "FOREMAN",
        "--thread", "foreman-thread-1",
        "--host", "host-1",
        "--attempt", "1",
        "--event-id", refreshEventId,
        "--canary-plan-sha256",
        receipt.planEnvelope.canary_plan_sha256,
        "--issuer-capability-file",
        registeredSession.capability_file,
        "--json",
      ], repository.root).value;
      const refreshOptions = {
        ...receipt.options,
        registrationEventId: refreshEventId,
        stableId: `canary-observation-${refreshEventId}`,
        challenge: refreshChallenge.challenge,
        challengeRecord: refreshChallenge,
      };
      const refreshReceipt = fakeReceipt(refreshOptions);
      const refreshReceiptFile = path.join(
        receipt.root,
        "refresh-receipt.json",
      );
      writePrivateJson(refreshReceiptFile, refreshReceipt);
      const refresh = [
        "refresh-probe-observation",
        "--goal", "goal-receipt-integration",
        "--task", "TASK-A",
        "--role", "FOREMAN",
        "--thread", "foreman-thread-1",
        "--host", "host-1",
        "--attempt", "1",
        "--expected-state-revision",
        String(loaded.snapshot.tasks["TASK-A"].state_revision),
        "--expected-binding-sha256",
        registeredSession.probe_observation.binding_sha256,
        "--event-id", refreshEventId,
        "--actor-capability-file",
        registeredSession.capability_file,
        "--probe-observation-receipt", refreshReceiptFile,
        "--probe-observation-receipt-sha256",
        fileSha256(refreshReceiptFile),
        "--probe-observation-plan", receipt.planFile,
        "--probe-observation-plan-sha256",
        receipt.planEnvelope.canary_plan_sha256,
        "--probe-observation-stable-id",
        refreshOptions.stableId,
        "--probe-observation-challenge",
        refreshChallenge.challenge,
        "--json",
      ];
      const refreshed = goalCommand(refresh, repository.root).value;
      expect(refreshed).toMatchObject({
        refreshed: true,
        idempotent: false,
        session: {
          probe_observation: {
            binding_sha256: expect.not.stringMatching(
              registeredSession.probe_observation.binding_sha256,
            ),
          },
        },
      });
      expect(goalCommand(refresh, repository.root).value).toMatchObject({
        refreshed: true,
        idempotent: true,
      });
      const afterRefresh = loadGoalStateReadOnly(
        repository.root,
        "goal-receipt-integration",
        (value) => value,
      );
      const refreshedSession =
        afterRefresh.snapshot.tasks["TASK-A"].sessions.FOREMAN;
      const refreshVariant = [...refresh];
      refreshVariant[
        refreshVariant.indexOf("--expected-binding-sha256") + 1
      ] = `sha256:${"8".repeat(64)}`;
      expect(() => goalCommand(refreshVariant, repository.root))
        .toThrow(expect.objectContaining({
          code: "EVENT_ID_CONFLICT",
        }));
      const staleCas = [...refresh];
      staleCas[staleCas.indexOf("--event-id") + 1] =
        "refresh-foreman-receipt-stale-cas";
      staleCas[
        staleCas.indexOf("--expected-state-revision") + 1
      ] = String(
        afterRefresh.snapshot.tasks["TASK-A"].state_revision,
      );
      staleCas[
        staleCas.indexOf("--expected-binding-sha256") + 1
      ] = `sha256:${"7".repeat(64)}`;
      expect(() => goalCommand(staleCas, repository.root))
        .toThrow(expect.objectContaining({
          code: "CANARY_OBSERVATION_REFRESH_CAS_MISMATCH",
        }));
      expect(loadGoalStateReadOnly(
        repository.root,
        "goal-receipt-integration",
        (value) => value.snapshot.tasks["TASK-A"].state_revision,
      )).toBe(afterRefresh.snapshot.tasks["TASK-A"].state_revision);

      process.env.GOAL_CONTROL_NOW =
        refreshedSession.probe_observation.expires_at;
      const expiredOld = [...refresh];
      expiredOld[expiredOld.indexOf("--event-id") + 1] =
        "refresh-foreman-receipt-expired-old";
      expiredOld[
        expiredOld.indexOf("--expected-state-revision") + 1
      ] = String(
        afterRefresh.snapshot.tasks["TASK-A"].state_revision,
      );
      expiredOld[
        expiredOld.indexOf("--expected-binding-sha256") + 1
      ] = refreshedSession.probe_observation.binding_sha256;
      expect(() => goalCommand(expiredOld, repository.root))
        .toThrow(expect.objectContaining({
          code: "CANARY_OBSERVATION_EXPIRED",
        }));
      delete process.env.GOAL_CONTROL_NOW;
      expect(loadGoalStateReadOnly(
        repository.root,
        "goal-receipt-integration",
        (value) => value.snapshot.tasks["TASK-A"].state_revision,
      )).toBe(afterRefresh.snapshot.tasks["TASK-A"].state_revision);

      const recoveryBoundary = loadGoalStateReadOnly(
        repository.root,
        "goal-receipt-integration",
        (value) => value.snapshot.tasks["TASK-A"],
      );
      process.env.GOAL_CONTROL_NOW = new Date(Math.max(
        Date.parse(recoveryBoundary.sessions.FOREMAN.lease_until),
        Date.parse(
          recoveryBoundary.sessions.FOREMAN
            .probe_observation.expires_at,
        ),
      ) + 1).toISOString();
      const recoveryScope = goalCommand([
        "status",
        "--goal", "goal-receipt-integration",
        "--json",
      ], repository.root).value.foreman_recovery_scope;
      const beforeRecoveryRevision =
        recoveryBoundary.state_revision;
      expect(() => goalCommand([
        "recover-expired-foreman",
        "--goal", "goal-receipt-integration",
        "--task", "TASK-A",
        "--thread", "foreman-thread-recovered",
        "--host", "host-2",
        "--attempt", "2",
        "--lease-ms", "60000",
        "--expected-goal-scope-sha256",
        recoveryScope.scope_sha256,
        "--reason", "receipt-gated recovery test",
        "--incident-ref", "test:expired-foreman",
        "--foreman-recovery-capability-file",
        String(initialized.foreman_recovery_capability_file),
        "--event-id", "recover-foreman-without-receipt",
        "--json",
      ], repository.root)).toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_REQUIRED",
      }));
      delete process.env.GOAL_CONTROL_NOW;
      expect(loadGoalStateReadOnly(
        repository.root,
        "goal-receipt-integration",
        (value) => value.snapshot.tasks["TASK-A"].state_revision,
      )).toBe(beforeRecoveryRevision);
    } finally {
      if (previous.controlDir === undefined) {
        delete process.env.GOAL_CONTROL_DIR;
      } else {
        process.env.GOAL_CONTROL_DIR = previous.controlDir;
      }
      if (previous.testMode === undefined) {
        delete process.env.GOAL_CONTROL_TEST_MODE;
      } else {
        process.env.GOAL_CONTROL_TEST_MODE = previous.testMode;
      }
    }
  });
});
