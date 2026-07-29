import { execFileSync, spawnSync } from "child_process";
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
const { sealWorkerBootstrapBinding } = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "worker-bootstrap-binding.js",
  ),
) as {
  sealWorkerBootstrapBinding: (
    receipt: Record<string, unknown>,
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
  identityFile: string;
  identityObservation: Record<string, any>;
  issuerCapabilityFile: string;
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

function ordinaryFileSnapshot(root: string): Record<string, string> {
  const snapshot: Record<string, string> = {};
  if (!existsSync(root)) return snapshot;
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const entry = path.join(directory, name);
      const stat = statSync(entry);
      if (stat.isDirectory()) {
        visit(entry);
      } else if (stat.isFile()) {
        snapshot[path.relative(root, entry)] = createHash("sha256")
          .update(readFileSync(entry))
          .digest("hex");
      }
    }
  };
  visit(root);
  return snapshot;
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

function withoutGoalControlDirectory<T>(operation: () => T): T {
  const previous = process.env.GOAL_CONTROL_DIR;
  delete process.env.GOAL_CONTROL_DIR;
  try {
    return operation();
  } finally {
    if (previous === undefined) {
      delete process.env.GOAL_CONTROL_DIR;
    } else {
      process.env.GOAL_CONTROL_DIR = previous;
    }
  }
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

function roleIdentityObservation(
  repository: ReturnType<typeof integrationRepository>,
  values: {
    operationId: string;
    taskId: string;
    role: string;
    threadId: string;
    hostId: string;
    sessionId: string;
    launchId: string | null;
    workerBootstrapBindingSha256?: string | null;
    repositoryHead?: string;
  },
): Record<string, any> {
  const hostAttestation =
    repository.manifest.probe_observation_receipts.host_attestation;
  const observedAt = new Date(Date.now() - 1000).toISOString();
  const unsigned = {
    schema_version: 1,
    kind: "GOALCTL_HOST_ROLE_IDENTITY_OBSERVATION_V1",
    operation_id: values.operationId,
    goal_id: "goal-receipt-integration",
    task_id: values.taskId,
    role: values.role,
    thread_id: values.threadId,
    host_id: values.hostId,
    session_id: values.sessionId,
    launch_id: values.launchId,
    repository_head:
      values.repositoryHead || repository.manifest.base_head,
    worker_bootstrap_binding_sha256:
      values.workerBootstrapBindingSha256 || null,
    observed_at: observedAt,
    expires_at: new Date(
      Date.parse(observedAt)
        + repository.manifest.probe_observation_receipts.max_ttl_ms,
    ).toISOString(),
    attestation: {
      algorithm: hostAttestation.algorithm,
      key_id: hostAttestation.key_id,
      public_key_sha256: hostAttestation.public_key_sha256,
    },
  };
  const signature = sign(
    null,
    Buffer.from(canonicalJson(unsigned)),
    repository.hostAttestationPrivateKey,
  ).toString("base64url");
  const sealed = {
    ...unsigned,
    attestation: {
      ...unsigned.attestation,
      signature_base64url: signature,
    },
  };
  return {
    ...sealed,
    record_sha256: hashObject(sealed),
  };
}

function resealRoleIdentityObservation(
  repository: ReturnType<typeof integrationRepository>,
  record: Record<string, any>,
): Record<string, any> {
  const unsigned = JSON.parse(JSON.stringify(record));
  delete unsigned.record_sha256;
  unsigned.attestation = {
    algorithm: unsigned.attestation.algorithm,
    key_id: unsigned.attestation.key_id,
    public_key_sha256: unsigned.attestation.public_key_sha256,
  };
  const sealed = {
    ...unsigned,
    attestation: {
      ...unsigned.attestation,
      signature_base64url: sign(
        null,
        Buffer.from(canonicalJson(unsigned)),
        repository.hostAttestationPrivateKey,
      ).toString("base64url"),
    },
  };
  return {
    ...sealed,
    record_sha256: hashObject(sealed),
  };
}

function runGoalctlProcess(
  cwd: string,
  args: string[],
): {
  status: number | null;
  stdout: string;
  stderr: string;
} {
  const result = spawnSync(
    process.execPath,
    [path.join(ROOT, "scripts", "goalctl.js"), ...args],
    {
      cwd,
      encoding: "utf8",
      env: { ...process.env },
    },
  );
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function registerControlAuthority(
  repository: ReturnType<typeof integrationRepository>,
  initialized: Record<string, any>,
  artifactRoot: string,
  role: "FOREMAN" | "CAPTAIN",
  authorizerCapabilityFile: string | null,
): Record<string, any> {
  const taskId = "TASK-A";
  const existing = loadGoalStateReadOnly(
    repository.root,
    "goal-receipt-integration",
    (loaded) => loaded.snapshot.tasks[taskId].sessions[role] || null,
  );
  if (existing) {
    return {
      registered: true,
      idempotent: true,
      session: existing,
      actor_capability_file: existing.capability_file,
    };
  }
  const eventId = `authority-${role.toLowerCase()}-registration-1`;
  const planEnvelope = canaryPlan(repository.root, {
    manifestFile: path.relative(
      repository.root,
      repository.manifestFile,
    ),
    role,
    taskId: role === "FOREMAN" ? null : taskId,
    browserCanaryReceipt: null,
  });
  const threadId = `codex-thread-${role.toLowerCase()}-real-1`;
  const hostId = "codex-host-real-1";
  const identity = roleIdentityObservation(repository, {
    operationId: eventId,
    taskId,
    role,
    threadId,
    hostId,
    sessionId: `codex-session-${role.toLowerCase()}-real-1`,
    launchId: null,
  });
  const identityFile = path.join(
    artifactRoot,
    `${eventId}-identity.json`,
  );
  writePrivateJson(identityFile, identity);
  const issuerCapabilityFile = role === "FOREMAN"
    ? String(initialized.bootstrap_capability_file)
    : String(authorizerCapabilityFile);
  const challenge = goalCommand([
    "prepare-probe-observation-challenge",
    "--goal", "goal-receipt-integration",
    "--task", taskId,
    "--role", role,
    "--event-id", eventId,
    "--canary-plan-sha256", planEnvelope.canary_plan_sha256,
    "--issuer-capability-file", issuerCapabilityFile,
    "--identity-receipt", identityFile,
    "--identity-receipt-sha256", fileSha256(identityFile),
    "--json",
  ], repository.root).value;
  const receiptOptions = {
    registrationEventId: eventId,
    goalId: "goal-receipt-integration",
    taskId,
    role,
    threadId,
    hostId,
    attempt: 1,
    repositoryHead: repository.fullHead,
    repositoryWorktree: repository.root,
    invocationCwd: repository.root,
    validatedManifestSha256: repository.manifest.manifest_sha256,
    manifest: repository.manifest,
    hostAttestationPrivateKey: repository.hostAttestationPrivateKey,
    stableId: `canary-observation-${eventId}`,
    challenge: challenge.challenge,
    challengeRecord: challenge,
    planEnvelope,
    evidenceDirectory: path.join(
      repository.controlDir,
      `authority-evidence-${role.toLowerCase()}`,
    ),
  };
  const originalTestMode = process.env.GOAL_CONTROL_TEST_MODE;
  const originalControlDir = process.env.GOAL_CONTROL_DIR;
  process.env.GOAL_CONTROL_TEST_MODE = "1";
  process.env.GOAL_CONTROL_DIR = repository.controlDir;
  let receipt = fakeReceipt(receiptOptions);
  if (originalTestMode !== "1") {
    receipt.producer.namespace = "HOST_ADAPTER";
    receipt = sealHostAdapterReceipt(receipt, repository);
  }
  if (originalTestMode === undefined) {
    delete process.env.GOAL_CONTROL_TEST_MODE;
  } else {
    process.env.GOAL_CONTROL_TEST_MODE = originalTestMode;
  }
  if (originalControlDir === undefined) {
    delete process.env.GOAL_CONTROL_DIR;
  } else {
    process.env.GOAL_CONTROL_DIR = originalControlDir;
  }
  const planFile = path.join(artifactRoot, `${eventId}-plan.json`);
  const receiptFile = path.join(
    artifactRoot,
    `${eventId}-receipt.json`,
  );
  writePrivateJson(planFile, planEnvelope);
  writePrivateJson(receiptFile, receipt);
  const authArgs = role === "FOREMAN"
    ? [
      "--bootstrap-capability-file",
      String(initialized.bootstrap_capability_file),
    ]
    : [
      "--authorizer-capability-file",
      String(authorizerCapabilityFile),
    ];
  return goalCommand([
    "register-role",
    "--goal", "goal-receipt-integration",
    "--task", taskId,
    "--role", role,
    "--thread", threadId,
    "--host", hostId,
    "--attempt", "1",
    "--event-id", eventId,
    ...authArgs,
    "--probe-observation-receipt", receiptFile,
    "--probe-observation-receipt-sha256", fileSha256(receiptFile),
    "--probe-observation-plan", planFile,
    "--probe-observation-plan-sha256",
    planEnvelope.canary_plan_sha256,
    "--probe-observation-stable-id",
    `canary-observation-${eventId}`,
    "--probe-observation-challenge", challenge.challenge,
    "--json",
  ], repository.root).value;
}

function prepareRoleIdentityChallenge(
  repository: ReturnType<typeof integrationRepository>,
  artifactRoot: string,
  values: {
    operationId: string;
    taskId: string;
    role: "FOREMAN" | "CAPTAIN" | "DEV" | "REVIEW" | "RECEIPT";
    threadId: string;
    hostId: string;
    sessionId: string;
    launchId: string | null;
    issuerCapabilityFile: string;
    workerBootstrapBindingSha256?: string | null;
  },
): {
  challenge: Record<string, any>;
  identity: Record<string, any>;
  identityFile: string;
  planEnvelope: Record<string, any>;
} {
  const planEnvelope = canaryPlan(repository.root, {
    manifestFile: path.relative(
      repository.root,
      repository.manifestFile,
    ),
    role: values.role,
    taskId: values.role === "FOREMAN" ? null : values.taskId,
    browserCanaryReceipt: null,
  });
  const identity = roleIdentityObservation(repository, {
    operationId: values.operationId,
    taskId: values.taskId,
    role: values.role,
    threadId: values.threadId,
    hostId: values.hostId,
    sessionId: values.sessionId,
    launchId: values.launchId,
    workerBootstrapBindingSha256:
      values.workerBootstrapBindingSha256,
  });
  const identityFile = path.join(
    artifactRoot,
    `${values.operationId}-identity.json`,
  );
  writePrivateJson(identityFile, identity);
  const challenge = goalCommand([
    "prepare-probe-observation-challenge",
    "--goal", "goal-receipt-integration",
    "--task", values.taskId,
    "--role", values.role,
    "--event-id", values.operationId,
    "--canary-plan-sha256", planEnvelope.canary_plan_sha256,
    "--issuer-capability-file", values.issuerCapabilityFile,
    "--identity-receipt", identityFile,
    "--identity-receipt-sha256", fileSha256(identityFile),
    "--json",
  ], repository.root).value;
  return {
    challenge,
    identity,
    identityFile,
    planEnvelope,
  };
}

function prepareWorkerBootstrap(
  repository: ReturnType<typeof integrationRepository>,
  frozenRepositoryWorktree: string,
  worker: string,
  values: {
    operationId: string;
    challenge: string;
    threadId: string;
    hostId: string;
    role?: "DEV" | "REVIEW" | "RECEIPT";
  },
): {
  receiptFile: string;
  receiptSha256: string;
  identityPlanSha256: string;
  binding: Record<string, any>;
  planEnvelope: Record<string, any>;
} {
  const role = values.role || "DEV";
  const expectedHead = loadGoalStateReadOnly(
    repository.root,
    "goal-receipt-integration",
    (loaded) => loaded.snapshot.tasks["TASK-A"].full_head,
  );
  const bindingArgs = [
    "--manifest", path.relative(
      repository.root,
      repository.manifestFile,
    ),
    "--role", role,
    "--task", "TASK-A",
    "--expected-head", expectedHead,
    "--operation-id", values.operationId,
    "--challenge", values.challenge,
    "--canary-policy",
    String(repository.workerBootstrapPolicy),
    "--canary-policy-sha256",
    repository.manifest.worker_canary_bootstrap.policy.sha256,
  ];
  const identityPlan = withoutGoalControlDirectory(() => goalCommand([
    "canary-bootstrap-plan",
    "--repository-worktree", frozenRepositoryWorktree,
    ...bindingArgs,
    "--json",
  ], frozenRepositoryWorktree).value);
  const identityObservation = withoutGoalControlDirectory(() => goalCommand([
    "canary-bootstrap-inspect",
    "--goal-worktree", frozenRepositoryWorktree,
    ...bindingArgs,
    "--expected-identity-plan-sha256",
    identityPlan.identity_plan_sha256,
    "--worker-thread", values.threadId,
    "--worker-host", values.hostId,
    "--json",
  ], worker).value);
  const prepared = withoutGoalControlDirectory(() => goalCommand([
    "canary-bootstrap-prepare",
    "--repository-worktree", frozenRepositoryWorktree,
    ...bindingArgs,
    "--expected-identity-plan-sha256",
    identityPlan.identity_plan_sha256,
    "--expected-observation-sha256",
    identityObservation.identity_observation_sha256,
    "--worker-thread", values.threadId,
    "--worker-host", values.hostId,
    "--worker-worktree", worker,
    "--json",
  ], frozenRepositoryWorktree).value);
  const planEnvelope = withoutGoalControlDirectory(() => goalCommand([
    "canary-plan",
    "--repository-worktree", frozenRepositoryWorktree,
    "--manifest", path.relative(
      repository.root,
      repository.manifestFile,
    ),
    "--role", role,
    "--task", "TASK-A",
    "--worker-bootstrap-receipt",
    prepared.worker_bootstrap_receipt_file,
    "--worker-bootstrap-receipt-sha256",
    prepared.worker_bootstrap_receipt_sha256,
    "--worker-bootstrap-operation-id", values.operationId,
    "--worker-bootstrap-challenge", values.challenge,
    "--worker-bootstrap-identity-plan-sha256",
    identityPlan.identity_plan_sha256,
    "--worker-thread", values.threadId,
    "--worker-host", values.hostId,
    "--json",
  ], frozenRepositoryWorktree, worker).value);
  return {
    receiptFile: prepared.worker_bootstrap_receipt_file,
    receiptSha256: prepared.worker_bootstrap_receipt_sha256,
    identityPlanSha256: identityPlan.identity_plan_sha256,
    binding: sealWorkerBootstrapBinding(
      planEnvelope.canary_plan.worker_bootstrap,
    ),
    planEnvelope,
  };
}

function createDetachedWorker(
  repository: ReturnType<typeof integrationRepository>,
  head = repository.manifest.base_head,
): string {
  const parent = realpathSync(mkdtempSync(
    path.join(tmpdir(), "goal-probe-registration-worker-extra-"),
  ));
  roots.push(parent);
  const worker = path.join(parent, "worker");
  git(
    repository.root,
    "worktree",
    "add",
    "--detach",
    "-q",
    worker,
    head,
  );
  return realpathSync(worker);
}

function registerWorkerIdentity(
  repository: ReturnType<typeof integrationRepository>,
  frozenRepositoryWorktree: string,
  artifacts: string,
  captain: Record<string, any>,
  worker: string,
  bootstrap: ReturnType<typeof prepareWorkerBootstrap>,
  values: {
    eventId: string;
    threadId: string;
    hostId: string;
    attempt: number;
    launchId: string;
    registrationLaunchId?: string;
    observedBootstrapBindingSha256?: string;
    beforeRegister?: () => void;
  },
): Record<string, any> {
  const identity = roleIdentityObservation(repository, {
    operationId: values.eventId,
    taskId: "TASK-A",
    role: "DEV",
    threadId: values.threadId,
    hostId: values.hostId,
    sessionId: `actual-session-dev-${values.attempt}`,
    launchId: values.launchId,
    workerBootstrapBindingSha256:
      values.observedBootstrapBindingSha256
        || bootstrap.binding.binding_sha256,
    repositoryHead: bootstrap.binding.head,
  });
  const identityFile = path.join(
    artifacts,
    `${values.eventId}-identity.json`,
  );
  writePrivateJson(identityFile, identity);
  const challenge = goalCommand([
    "prepare-probe-observation-challenge",
    "--goal", "goal-receipt-integration",
    "--task", "TASK-A",
    "--role", "DEV",
    "--event-id", values.eventId,
    "--canary-plan-sha256",
    bootstrap.planEnvelope.canary_plan_sha256,
    "--issuer-capability-file",
    String(captain.actor_capability_file),
    "--identity-receipt", identityFile,
    "--identity-receipt-sha256", fileSha256(identityFile),
    "--json",
  ], frozenRepositoryWorktree).value;
  const receiptOptions = {
    registrationEventId: values.eventId,
    goalId: "goal-receipt-integration",
    taskId: "TASK-A",
    role: "DEV",
    threadId: values.threadId,
    hostId: values.hostId,
    attempt: values.attempt,
    repositoryHead: bootstrap.binding.head,
    repositoryWorktree: frozenRepositoryWorktree,
    invocationCwd: worker,
    validatedManifestSha256: repository.manifest.manifest_sha256,
    manifest: repository.manifest,
    hostAttestationPrivateKey: repository.hostAttestationPrivateKey,
    stableId: `canary-observation-${values.eventId}`,
    challenge: challenge.challenge,
    challengeRecord: challenge,
    planEnvelope: bootstrap.planEnvelope,
    evidenceDirectory: path.join(
      repository.controlDir,
      `worker-evidence-${values.eventId}`,
    ),
  };
  const receipt = fakeReceipt(receiptOptions);
  const planFile = path.join(
    artifacts,
    `${values.eventId}-plan.json`,
  );
  const receiptFile = path.join(
    artifacts,
    `${values.eventId}-receipt.json`,
  );
  writePrivateJson(planFile, bootstrap.planEnvelope);
  writePrivateJson(receiptFile, receipt);
  values.beforeRegister?.();
  return goalCommand([
    "register-role",
    "--goal", "goal-receipt-integration",
    "--task", "TASK-A",
    "--role", "DEV",
    "--thread", values.threadId,
    "--host", values.hostId,
    "--attempt", String(values.attempt),
    "--launch-id", values.registrationLaunchId || values.launchId,
    "--event-id", values.eventId,
    "--authorizer-capability-file",
    String(captain.actor_capability_file),
    "--worker-bootstrap-receipt", bootstrap.receiptFile,
    "--worker-bootstrap-receipt-sha256",
    bootstrap.receiptSha256,
    "--worker-bootstrap-operation-id",
    bootstrap.binding.operation_id,
    "--worker-bootstrap-challenge",
    bootstrap.binding.challenge,
    "--worker-bootstrap-identity-plan-sha256",
    bootstrap.identityPlanSha256,
    "--probe-observation-receipt", receiptFile,
    "--probe-observation-receipt-sha256",
    fileSha256(receiptFile),
    "--probe-observation-plan", planFile,
    "--probe-observation-plan-sha256",
    bootstrap.planEnvelope.canary_plan_sha256,
    "--probe-observation-stable-id",
    `canary-observation-${values.eventId}`,
    "--probe-observation-challenge", challenge.challenge,
    "--json",
  ], frozenRepositoryWorktree, worker).value;
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
  let issuerCapabilityFile =
    String(initialized.bootstrap_capability_file);
  if (role !== "FOREMAN") {
    const foreman = registerControlAuthority(
      repository,
      initialized,
      root,
      "FOREMAN",
      null,
    );
    issuerCapabilityFile = String(foreman.actor_capability_file);
    if (role !== "CAPTAIN") {
      const captain = registerControlAuthority(
        repository,
        initialized,
        root,
        "CAPTAIN",
        issuerCapabilityFile,
      );
      issuerCapabilityFile = String(captain.actor_capability_file);
    }
  }
  const identityObservation = roleIdentityObservation(repository, {
    operationId: eventId,
    taskId,
    role,
    threadId: `${role.toLowerCase()}-thread-1`,
    hostId: "host-1",
    sessionId: `codex-session-${role.toLowerCase()}-1`,
    launchId: ["DEV", "REVIEW", "RECEIPT"].includes(role)
      ? `launch-${role.toLowerCase()}-1`
      : null,
  });
  const identityFile = path.join(root, "role-identity.json");
  writePrivateJson(identityFile, identityObservation);
  const challengeRecord = goalCommand([
    "prepare-probe-observation-challenge",
    "--goal", goalId,
    "--task", taskId,
    "--role", role,
    "--event-id", eventId,
    "--canary-plan-sha256", planEnvelope.canary_plan_sha256,
    "--issuer-capability-file",
    issuerCapabilityFile,
    "--identity-receipt", identityFile,
    "--identity-receipt-sha256", fileSha256(identityFile),
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
    identityFile,
    identityObservation,
    issuerCapabilityFile,
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

function submitPublicGoalEvent(
  repository: ReturnType<typeof integrationRepository>,
  artifactRoot: string,
  values: {
    eventId: string;
    type: string;
    actorRole: "FOREMAN" | "CAPTAIN" | "DEV" | "REVIEW" | "RECEIPT";
    actorCapabilityFile: string;
    payload: Record<string, unknown>;
    cwd?: string;
    fullHead?: string;
  },
): Record<string, any> {
  const loaded = loadGoalStateReadOnly(
    repository.root,
    "goal-receipt-integration",
    (current) => current,
  );
  const state = loaded.snapshot.tasks["TASK-A"];
  const actor = state.sessions[values.actorRole];
  const sequenceKey = JSON.stringify([
    actor.role,
    actor.host_id,
    actor.thread_id,
  ]);
  const event = {
    schema_version: 1,
    event_id: values.eventId,
    goal_id: "goal-receipt-integration",
    task_id: "TASK-A",
    type: values.type,
    actor: {
      role: actor.role,
      thread_id: actor.thread_id,
      host_id: actor.host_id,
    },
    actor_sequence: (state.actor_sequences[sequenceKey] || 0) + 1,
    expected_state_revision: state.state_revision,
    control_epoch: loaded.control.epoch,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    base_head: state.base_head,
    full_head: values.fullHead || state.full_head,
    payload: values.payload,
  };
  const file = path.join(artifactRoot, `${values.eventId}.json`);
  writePrivateJson(file, event);
  return goalCommand([
    "event",
    "--goal", "goal-receipt-integration",
    "--file", file,
    "--actor-capability-file", values.actorCapabilityFile,
    "--json",
  ], values.cwd || repository.root).value;
}

function advanceLegacyP1(
  repository: ReturnType<typeof integrationRepository>,
  artifacts: string,
  foreman: Record<string, any>,
  captain: Record<string, any>,
): {
  worktree: string;
  fullHead: string;
} {
  const worktree = createDetachedWorker(
    repository,
    repository.manifest.base_head,
  );
  const planPath =
    "docs/planning/goals/receipt/p1/plan.md";
  const contextPath =
    "docs/planning/goals/receipt/p1/context.md";
  const planBody = "# P1 plan\n\nIssue 22 lifecycle fixture.\n";
  const contextBody =
    "# P1 context\n\nController-owned identity intent.\n";
  const planSha = `sha256:${createHash("sha256")
    .update(planBody)
    .digest("hex")}`;
  const contextSha = `sha256:${createHash("sha256")
    .update(contextBody)
    .digest("hex")}`;
  for (const relative of [
    path.relative(repository.root, repository.manifestFile),
    ...(repository.workerBootstrapPolicy
      ? [repository.workerBootstrapPolicy]
      : []),
  ]) {
    const source = path.join(repository.root, relative);
    const target = path.join(worktree, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(source, target);
    chmodSync(target, 0o644);
  }
  submitPublicGoalEvent(repository, artifacts, {
    eventId: "issue-22-start-p1",
    type: "START_P1",
    actorRole: "CAPTAIN",
    actorCapabilityFile: String(captain.actor_capability_file),
    payload: {},
    cwd: worktree,
  });
  mkdirSync(path.dirname(path.join(worktree, planPath)), {
    recursive: true,
  });
  writeFileSync(path.join(worktree, planPath), planBody);
  writeFileSync(path.join(worktree, contextPath), contextBody);
  submitPublicGoalEvent(repository, artifacts, {
    eventId: "issue-22-p1-ready",
    type: "P1_READY",
    actorRole: "CAPTAIN",
    actorCapabilityFile: String(captain.actor_capability_file),
    payload: {
      plan_path: planPath,
      plan_sha256: planSha,
      context_path: contextPath,
      context_sha256: contextSha,
    },
    cwd: worktree,
  });
  submitPublicGoalEvent(repository, artifacts, {
    eventId: "issue-22-p1-approved",
    type: "P1_APPROVED",
    actorRole: "FOREMAN",
    actorCapabilityFile: String(foreman.actor_capability_file),
    payload: {
      plan_path: planPath,
      plan_sha256: planSha,
      context_path: contextPath,
      context_sha256: contextSha,
      approval_ref: "test://issue-22/p1-approved",
    },
    cwd: worktree,
  });
  for (const relative of [
    repository.manifest.tasks.find(
      (task: Record<string, any>) => task.id === "TASK-A",
    ).packet.path,
  ]) {
    const source = path.join(repository.root, relative);
    const target = path.join(worktree, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(source, target);
    chmodSync(target, 0o644);
  }
  git(worktree, "add", ".");
  git(worktree, "commit", "-qm", "issue 22 P1 fixture");
  const fullHead = git(worktree, "rev-parse", "HEAD");
  submitPublicGoalEvent(repository, artifacts, {
    eventId: "issue-22-p1-committed",
    type: "P1_COMMITTED",
    actorRole: "CAPTAIN",
    actorCapabilityFile: String(captain.actor_capability_file),
    payload: {
      plan_path: planPath,
      plan_sha256: planSha,
      context_path: contextPath,
      context_sha256: contextSha,
      approval_event_id: "issue-22-p1-approved",
    },
    cwd: worktree,
    fullHead,
  });
  return { worktree, fullHead };
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

function integrationRepository(
  options: {
    twoTasks?: boolean;
    workerBootstrap?: boolean;
  } = {},
): {
  root: string;
  controlDir: string;
  manifestFile: string;
  manifestSha: string;
  fullHead: string;
  manifest: Record<string, any>;
  hostAttestationPrivateKey: any;
  worker: string | null;
  workerBootstrapPolicy: string | null;
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
  const packetRelative =
    "docs/planning/goals/receipt/packets/TASK-A-r1.md";
  const packetBody = "# TASK-A\n\nReceipt registration fixture.\n";
  const packetFile = path.join(root, packetRelative);
  mkdirSync(path.dirname(packetFile), { recursive: true });
  writeFileSync(packetFile, packetBody);
  const secondPacketRelative =
    "docs/planning/goals/receipt/packets/TASK-B-r1.md";
  const secondPacketBody =
    "# TASK-B\n\nGoal-wide FOREMAN projection fixture.\n";
  if (options.twoTasks) {
    const secondPacketFile = path.join(root, secondPacketRelative);
    writeFileSync(secondPacketFile, secondPacketBody);
  }
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
  const workerBootstrapPolicy =
    "docs/planning/goals/receipt/worker-canary-policy.md";
  const workerBootstrapPolicyBody = [
    "# Worker canary bootstrap policy",
    "",
    "Worker-Canary-Bootstrap-Protocol: goalctl-worker-canary-bootstrap-v1",
    "",
    "IDENTITY_ONLY -> PREPARE_ACTUAL_WORKTREE -> CANARY_EXECUTE",
    "",
  ].join("\n");
  if (options.workerBootstrap) {
    const policyFile = path.join(root, workerBootstrapPolicy);
    writeFileSync(policyFile, workerBootstrapPolicyBody);
  }
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
    ...(options.workerBootstrap ? {
      worker_canary_bootstrap: {
        protocol: "goalctl-worker-canary-bootstrap-v1",
        policy: {
          path: workerBootstrapPolicy,
          sha256: `sha256:${createHash("sha256")
            .update(workerBootstrapPolicyBody)
            .digest("hex")}`,
        },
      },
    } : {}),
    tasks: [
      {
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
      },
      ...(options.twoTasks ? [{
        id: "TASK-B",
        dependencies: ["TASK-A"],
        integration_order: 2,
        resource_requirements: [],
        packet: {
          revision: 1,
          path: secondPacketRelative,
          sha256: `sha256:${createHash("sha256")
            .update(secondPacketBody)
            .digest("hex")}`,
        },
      }] : []),
    ],
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
    worker: null,
    workerBootstrapPolicy:
      options.workerBootstrap ? workerBootstrapPolicy : null,
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
      current.issuerCapabilityFile,
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
      const captainLong = fixture({
        role: "CAPTAIN",
        eventTag: "projection-long",
        repository: captainShort.repository,
        initialized: captainShort.initialized,
        receiptOverrides: { ttlMs: 90_000 },
      });
      const targetShort = fixture({
        role: targetRole,
        eventTag: "projection-short",
        repository: captainShort.repository,
        initialized: captainShort.initialized,
        receiptOverrides: { ttlMs: 30_000 },
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
      capabilityReceipt.issuerCapabilityFile,
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
      "--event-id", current.options.registrationEventId,
      "--canary-plan-sha256",
      current.options.probeObservationPlanSha256,
      "--issuer-capability-file",
      String(current.initialized.bootstrap_capability_file),
      "--identity-receipt", current.identityFile,
      "--identity-receipt-sha256", fileSha256(current.identityFile),
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
    const originalIdentityBytes = readFileSync(current.identityFile);
    unlinkSync(current.identityFile);
    writeFileSync(current.identityFile, originalIdentityBytes, {
      mode: 0o600,
    });
    chmodSync(current.identityFile, 0o600);
    const beforeReplacementRetry = ordinaryFileSnapshot(
      current.repository.controlDir,
    );
    expect(() => goalCommand(args, current.repository.root))
      .toThrow(expect.objectContaining({
        code: "CANARY_OBSERVATION_REPLAY_CONFLICT",
      }));
    expect(ordinaryFileSnapshot(current.repository.controlDir))
      .toEqual(beforeReplacementRetry);
  });

  test("seals only pre-attested identity and projects it with zero public writes", () => {
    const current = fixture({ role: "FOREMAN" });
    const beforeReads = ordinaryFileSnapshot(
      current.repository.controlDir,
    );
    const status = goalCommand([
      "status",
      "--goal", current.options.goalId,
      "--json",
    ], current.repository.root).value;
    const actions = goalCommand([
      "actions",
      "--goal", current.options.goalId,
      "--task", current.options.taskId,
      "--json",
    ], current.repository.root).value;
    expect(ordinaryFileSnapshot(current.repository.controlDir))
      .toEqual(beforeReads);
    const expectedIntent = {
      kind: "ROLE_IDENTITY_INTENT",
      operation_id: current.options.registrationEventId,
      goal_id: current.options.goalId,
      task_id: current.options.taskId,
      role: "FOREMAN",
      thread_id: current.options.threadId,
      host_id: current.options.hostId,
      attempt: 1,
      session_id: current.identityObservation.session_id,
      launch_id: null,
      state_revision: 0,
      control_epoch: 0,
      full_head: current.repository.manifest.base_head,
      intent_sha256: expect.stringMatching(
        /^sha256:[0-9a-f]{64}$/,
      ),
    };
    expect(
      status.tasks["TASK-A"].role_identity_intent,
    ).toMatchObject(expectedIntent);
    expect(actions.role_identity_intent).toMatchObject(expectedIntent);
    const serialized = JSON.stringify({ status, actions });
    expect(serialized).not.toContain("issuer_authority");
    expect(serialized).not.toContain("capability_sha256");
    expect(serialized).not.toContain("signature_base64url");
    expect(serialized).not.toContain("public_key_spki_base64");
  });

  test("preserves the canonical source task for a two-task Goal-wide FOREMAN intent", () => {
    const repository = integrationRepository({ twoTasks: true });
    process.env.GOAL_CONTROL_DIR = repository.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    const initialized = goalCommand([
      "init",
      "--manifest", repository.manifestFile,
      "--json",
    ], repository.root).value;
    const artifacts = realpathSync(mkdtempSync(
      path.join(tmpdir(), "goal-role-identity-two-task-"),
    ));
    roots.push(artifacts);
    chmodSync(artifacts, 0o700);
    const foreman = registerControlAuthority(
      repository,
      initialized,
      artifacts,
      "FOREMAN",
      null,
    );
    const operationId = "project-foreman-task-b-1";
    const projected = prepareRoleIdentityChallenge(
      repository,
      artifacts,
      {
        operationId,
        taskId: "TASK-B",
        role: "FOREMAN",
        threadId: foreman.session.thread_id,
        hostId: foreman.session.host_id,
        sessionId: foreman.session.role_identity.session_id,
        launchId: null,
        issuerCapabilityFile: String(
          foreman.actor_capability_file,
        ),
      },
    );
    expect(projected.challenge).toMatchObject({
      goal_id: "goal-receipt-integration",
      task_id: "TASK-B",
      role: "FOREMAN",
      thread_id: foreman.session.thread_id,
      host_id: foreman.session.host_id,
    });
    const loaded = loadGoalStateReadOnly(
      repository.root,
      "goal-receipt-integration",
      (current) => current,
    );
    const intent = readdirSync(
      loaded.paths.roleIdentityIntents,
    )
      .filter((name) => (
        name.endsWith(".role-identity-intent.json")
      ))
      .map((name) => JSON.parse(readFileSync(
        path.join(loaded.paths.roleIdentityIntents, name),
        "utf8",
      )))
      .find((candidate) => candidate.operation_id === operationId);
    expect(intent).toMatchObject({
      task_id: "TASK-B",
      issuer_authority: {
        kind: "SESSION",
        source_task_id: "TASK-A",
        role: "FOREMAN",
        thread_id: foreman.session.thread_id,
        host_id: foreman.session.host_id,
        attempt: 1,
        session_id: foreman.session.role_identity.session_id,
        lease_until: foreman.session.lease_until,
        registration_event_id:
          foreman.session.registration_event_id,
      },
    });
    const beforeRead = ordinaryFileSnapshot(repository.controlDir);
    expect(goalCommand([
      "actions",
      "--goal", "goal-receipt-integration",
      "--task", "TASK-B",
      "--json",
    ], repository.root).value.role_identity_intent).toMatchObject({
      operation_id: operationId,
      role: "FOREMAN",
      attempt: 1,
    });
    expect(ordinaryFileSnapshot(repository.controlDir))
      .toEqual(beforeRead);
  });

  test("rejects active takeover but admits ROLE_LOST and terminal higher-attempt successors", () => {
    const setup = (): {
      repository: ReturnType<typeof integrationRepository>;
      initialized: Record<string, any>;
      artifacts: string;
      foreman: Record<string, any>;
      captain: Record<string, any>;
    } => {
      const repository = integrationRepository();
      process.env.GOAL_CONTROL_DIR = repository.controlDir;
      process.env.GOAL_CONTROL_TEST_MODE = "1";
      const initialized = goalCommand([
        "init",
        "--manifest", repository.manifestFile,
        "--json",
      ], repository.root).value;
      const artifacts = realpathSync(mkdtempSync(
        path.join(tmpdir(), "goal-role-identity-successor-"),
      ));
      roots.push(artifacts);
      chmodSync(artifacts, 0o700);
      const foreman = registerControlAuthority(
        repository,
        initialized,
        artifacts,
        "FOREMAN",
        null,
      );
      const captain = registerControlAuthority(
        repository,
        initialized,
        artifacts,
        "CAPTAIN",
        String(foreman.actor_capability_file),
      );
      return {
        repository,
        initialized,
        artifacts,
        foreman,
        captain,
      };
    };
    const prepareCaptain = (
      current: ReturnType<typeof setup>,
      operationId: string,
      tag: string,
    ): ReturnType<typeof prepareRoleIdentityChallenge> => (
      prepareRoleIdentityChallenge(
        current.repository,
        current.artifacts,
        {
          operationId,
          taskId: "TASK-A",
          role: "CAPTAIN",
          threadId: `actual-captain-${tag}-2`,
          hostId: `actual-host-${tag}-2`,
          sessionId: `actual-session-${tag}-2`,
          launchId: null,
          issuerCapabilityFile: String(
            current.foreman.actor_capability_file,
          ),
        },
      )
    );

    const lostCase = setup();
    const beforeActiveTakeover = ordinaryFileSnapshot(
      lostCase.repository.controlDir,
    );
    expect(() => prepareCaptain(
      lostCase,
      "active-captain-takeover-2",
      "active",
    )).toThrow(expect.objectContaining({
      code: "ROLE_REPLACEMENT_REQUIRES_RECOVERY",
    }));
    expect(ordinaryFileSnapshot(lostCase.repository.controlDir))
      .toEqual(beforeActiveTakeover);
    const currentCaptain = loadGoalStateReadOnly(
      lostCase.repository.root,
      "goal-receipt-integration",
      (loaded) => loaded.snapshot.tasks["TASK-A"].sessions.CAPTAIN,
    );
    submitPublicGoalEvent(
      lostCase.repository,
      lostCase.artifacts,
      {
        eventId: "captain-role-lost-1",
        type: "ROLE_LOST",
        actorRole: "FOREMAN",
        actorCapabilityFile: String(
          lostCase.foreman.actor_capability_file,
        ),
        payload: {
          role: "CAPTAIN",
          reason: "black-box successor identity test",
          expected_thread_id: currentCaptain.thread_id,
          expected_host_id: currentCaptain.host_id,
          expected_attempt: currentCaptain.attempt,
          expected_lease_until: currentCaptain.lease_until,
        },
      },
    );
    prepareCaptain(
      lostCase,
      "lost-captain-successor-2",
      "lost",
    );
    expect(goalCommand([
      "actions",
      "--goal", "goal-receipt-integration",
      "--task", "TASK-A",
      "--json",
    ], lostCase.repository.root).value.role_identity_intent)
      .toMatchObject({
        operation_id: "lost-captain-successor-2",
        role: "CAPTAIN",
        attempt: 2,
        thread_id: "actual-captain-lost-2",
      });

    const terminalCase = setup();
    const controlEventId = "terminal-captain-control-1";
    goalCommand([
      "control",
      "--goal", "goal-receipt-integration",
      "--expected-epoch", "0",
      "--reason", "terminal predecessor successor test",
      "--instruction-ref", "test://issue-22/terminal-predecessor",
      "--thread", terminalCase.foreman.session.thread_id,
      "--actor-capability-file",
      String(terminalCase.foreman.actor_capability_file),
      "--event-id", controlEventId,
      "--json",
    ], terminalCase.repository.root);
    submitPublicGoalEvent(
      terminalCase.repository,
      terminalCase.artifacts,
      {
        eventId: "terminal-captain-reconcile-1",
        type: "CONTROL_RECONCILED",
        actorRole: "FOREMAN",
        actorCapabilityFile: String(
          terminalCase.foreman.actor_capability_file,
        ),
        payload: {
          control_event_id: controlEventId,
          instruction_ref:
            "test://issue-22/terminal-predecessor",
        },
      },
    );
    expect(loadGoalStateReadOnly(
      terminalCase.repository.root,
      "goal-receipt-integration",
      (loaded) => (
        loaded.snapshot.tasks["TASK-A"].sessions.CAPTAIN.status
      ),
    )).toBe("terminal");
    prepareCaptain(
      terminalCase,
      "terminal-captain-successor-2",
      "terminal",
    );
    expect(goalCommand([
      "actions",
      "--goal", "goal-receipt-integration",
      "--task", "TASK-A",
      "--json",
    ], terminalCase.repository.root).value.role_identity_intent)
      .toMatchObject({
        operation_id: "terminal-captain-successor-2",
        role: "CAPTAIN",
        attempt: 2,
        thread_id: "actual-captain-terminal-2",
      });
  });

  test("runs signed identity prepare and repeated zero-write reads through the real goalctl process", () => {
    const repository = integrationRepository();
    process.env.GOAL_CONTROL_DIR = repository.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    const initialized = goalCommand([
      "init",
      "--manifest", repository.manifestFile,
      "--json",
    ], repository.root).value;
    const artifacts = realpathSync(mkdtempSync(
      path.join(tmpdir(), "goal-role-identity-process-"),
    ));
    roots.push(artifacts);
    chmodSync(artifacts, 0o700);
    const plan = canaryPlan(repository.root, {
      manifestFile: path.relative(
        repository.root,
        repository.manifestFile,
      ),
      role: "FOREMAN",
      taskId: null,
      browserCanaryReceipt: null,
    });
    const operationId = "process-foreman-identity-1";
    const identity = roleIdentityObservation(repository, {
      operationId,
      taskId: "TASK-A",
      role: "FOREMAN",
      threadId: "actual-process-foreman-thread-1",
      hostId: "actual-process-host-1",
      sessionId: "actual-process-session-1",
      launchId: null,
    });
    const identityFile = path.join(artifacts, "identity.json");
    writePrivateJson(identityFile, identity);
    const prepare = runGoalctlProcess(repository.root, [
      "prepare-probe-observation-challenge",
      "--goal", "goal-receipt-integration",
      "--task", "TASK-A",
      "--role", "FOREMAN",
      "--event-id", operationId,
      "--canary-plan-sha256", plan.canary_plan_sha256,
      "--issuer-capability-file",
      String(initialized.bootstrap_capability_file),
      "--identity-receipt", identityFile,
      "--identity-receipt-sha256", fileSha256(identityFile),
      "--json",
    ]);
    expect({ status: prepare.status, stderr: prepare.stderr })
      .toEqual({ status: 0, stderr: "" });
    expect(JSON.parse(prepare.stdout)).toMatchObject({
      goal_id: "goal-receipt-integration",
      task_id: "TASK-A",
      role: "FOREMAN",
      thread_id: "actual-process-foreman-thread-1",
      host_id: "actual-process-host-1",
    });
    const beforeReads = ordinaryFileSnapshot(repository.controlDir);
    for (let index = 0; index < 2; index += 1) {
      const status = runGoalctlProcess(repository.root, [
        "status",
        "--goal", "goal-receipt-integration",
        "--json",
      ]);
      const actions = runGoalctlProcess(repository.root, [
        "actions",
        "--goal", "goal-receipt-integration",
        "--task", "TASK-A",
        "--json",
      ]);
      expect(status.status).toBe(0);
      expect(actions.status).toBe(0);
      expect(
        JSON.parse(status.stdout).tasks["TASK-A"]
          .role_identity_intent.operation_id,
      ).toBe(operationId);
      expect(
        JSON.parse(actions.stdout).role_identity_intent.operation_id,
      ).toBe(operationId);
      expect(ordinaryFileSnapshot(repository.controlDir))
        .toEqual(beforeReads);
    }

    const secret =
      `prefix-GhP_${"Ab7-".repeat(12)}-suffix`;
    const secretOperation = "process-secret-identity-1";
    const secretIdentity = roleIdentityObservation(repository, {
      operationId: secretOperation,
      taskId: "TASK-A",
      role: "FOREMAN",
      threadId: secret,
      hostId: "actual-process-host-secret",
      sessionId: "actual-process-session-secret",
      launchId: null,
    });
    const secretFile = path.join(artifacts, "secret-identity.json");
    writePrivateJson(secretFile, secretIdentity);
    const beforeSecret = ordinaryFileSnapshot(repository.controlDir);
    const rejected = runGoalctlProcess(repository.root, [
      "prepare-probe-observation-challenge",
      "--goal", "goal-receipt-integration",
      "--task", "TASK-A",
      "--role", "FOREMAN",
      "--event-id", secretOperation,
      "--canary-plan-sha256", plan.canary_plan_sha256,
      "--issuer-capability-file",
      String(initialized.bootstrap_capability_file),
      "--identity-receipt", secretFile,
      "--identity-receipt-sha256", fileSha256(secretFile),
      "--json",
    ]);
    expect(rejected.status).toBe(2);
    expect(rejected.stdout).toBe("");
    expect(rejected.stderr).toMatch(
      /^goalctl\[CANARY_OBSERVATION_SENSITIVE_DATA\]:/,
    );
    expect(rejected.stderr).not.toContain(secret);
    expect(ordinaryFileSnapshot(repository.controlDir))
      .toEqual(beforeSecret);
  });

  test("rejects signed-observation binding, authentication, TTL, and replay variants with zero writes", () => {
    const repository = integrationRepository();
    process.env.GOAL_CONTROL_DIR = repository.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    const initialized = goalCommand([
      "init",
      "--manifest", repository.manifestFile,
      "--json",
    ], repository.root).value;
    const artifacts = realpathSync(mkdtempSync(
      path.join(tmpdir(), "goal-role-identity-a7-"),
    ));
    roots.push(artifacts);
    chmodSync(artifacts, 0o700);
    const plan = canaryPlan(repository.root, {
      manifestFile: path.relative(
        repository.root,
        repository.manifestFile,
      ),
      role: "FOREMAN",
      taskId: null,
      browserCanaryReceipt: null,
    });
    const cases: Array<{
      name: string;
      mutate: (
        record: Record<string, any>,
      ) => Record<string, any>;
      eventId?: string;
      receiptSha256?: string;
    }> = [
      {
        name: "missing-signature",
        mutate: (record) => {
          const value = JSON.parse(JSON.stringify(record));
          delete value.attestation.signature_base64url;
          return value;
        },
      },
      {
        name: "tampered-signature",
        mutate: (record) => {
          const value = JSON.parse(JSON.stringify(record));
          value.attestation.signature_base64url = "A".repeat(86);
          const unsigned = { ...value };
          delete unsigned.record_sha256;
          value.record_sha256 = hashObject(unsigned);
          return value;
        },
      },
      {
        name: "tampered-record-hash",
        mutate: (record) => ({
          ...record,
          record_sha256: `sha256:${"9".repeat(64)}`,
        }),
      },
      {
        name: "expired",
        mutate: (record) => resealRoleIdentityObservation(
          repository,
          {
            ...record,
            observed_at: new Date(Date.now() - 240_000)
              .toISOString(),
            expires_at: new Date(Date.now() - 120_000)
              .toISOString(),
          },
        ),
      },
      {
        name: "future",
        mutate: (record) => resealRoleIdentityObservation(
          repository,
          {
            ...record,
            observed_at: new Date(Date.now() + 60_000)
              .toISOString(),
            expires_at: new Date(Date.now() + 120_000)
              .toISOString(),
          },
        ),
      },
      ...([
        ["goal_id", "goal-cross-binding"],
        ["task_id", "TASK-CROSS"],
        ["role", "CAPTAIN"],
        ["repository_head", "f".repeat(40)],
      ] as Array<[string, string]>).map(([field, value]) => ({
        name: `wrong-${field}`,
        mutate: (record: Record<string, any>) => (
          resealRoleIdentityObservation(repository, {
            ...record,
            [field]: value,
          })
        ),
      })),
      {
        name: "wrong-control-launch",
        mutate: (record) => resealRoleIdentityObservation(
          repository,
          {
            ...record,
            launch_id: "launch-must-not-bind-control-role",
          },
        ),
      },
      {
        name: "replay-another-event",
        eventId: "a7-replay-target-event",
        mutate: (record) => record,
      },
      {
        name: "content-hash",
        receiptSha256: `sha256:${"8".repeat(64)}`,
        mutate: (record) => record,
      },
    ];
    for (const [index, variant] of cases.entries()) {
      const sourceEventId = `a7-${variant.name}-${index + 1}`;
      const eventId = variant.eventId || sourceEventId;
      const record = variant.mutate(roleIdentityObservation(
        repository,
        {
          operationId: sourceEventId,
          taskId: "TASK-A",
          role: "FOREMAN",
          threadId: `actual-a7-thread-${index + 1}`,
          hostId: "actual-a7-host-1",
          sessionId: `actual-a7-session-${index + 1}`,
          launchId: null,
        },
      ));
      const receiptFile = path.join(
        artifacts,
        `${variant.name}.json`,
      );
      writePrivateJson(receiptFile, record);
      const before = ordinaryFileSnapshot(repository.controlDir);
      expect(() => goalCommand([
        "prepare-probe-observation-challenge",
        "--goal", "goal-receipt-integration",
        "--task", "TASK-A",
        "--role", "FOREMAN",
        "--event-id", eventId,
        "--canary-plan-sha256", plan.canary_plan_sha256,
        "--issuer-capability-file",
        String(initialized.bootstrap_capability_file),
        "--identity-receipt", receiptFile,
        "--identity-receipt-sha256",
        variant.receiptSha256 || fileSha256(receiptFile),
        "--json",
      ], repository.root)).toThrow();
      expect(ordinaryFileSnapshot(repository.controlDir))
        .toEqual(before);
    }
  });

  test("hides pending intents after revision, control epoch, or packet drift without read repair", () => {
    const assertHiddenWithoutWrites = (
      current: Fixture,
      cwd = current.repository.root,
    ): void => {
      const before = ordinaryFileSnapshot(
        current.repository.controlDir,
      );
      for (let index = 0; index < 2; index += 1) {
        const status = goalCommand([
          "status",
          "--goal", "goal-receipt-integration",
          "--json",
        ], cwd).value;
        const actions = goalCommand([
          "actions",
          "--goal", "goal-receipt-integration",
          "--task", "TASK-A",
          "--json",
        ], cwd).value;
        expect(status.tasks["TASK-A"])
          .not.toHaveProperty("role_identity_intent");
        expect(actions).not.toHaveProperty("role_identity_intent");
        expect(ordinaryFileSnapshot(
          current.repository.controlDir,
        )).toEqual(before);
      }
    };

    const revision = fixture({
      role: "CAPTAIN",
      eventTag: "stale-revision",
    });
    const revisionForeman = loadGoalStateReadOnly(
      revision.repository.root,
      "goal-receipt-integration",
      (loaded) => loaded.snapshot.tasks["TASK-A"].sessions.FOREMAN,
    );
    submitPublicGoalEvent(
      revision.repository,
      revision.root,
      {
        eventId: "stale-intent-heartbeat-1",
        type: "HEARTBEAT",
        actorRole: "FOREMAN",
        actorCapabilityFile:
          revisionForeman.capability_file,
        payload: {
          lease_ms: 60_000,
          status: "active",
        },
      },
    );
    assertHiddenWithoutWrites(revision);

    const epoch = fixture({
      role: "CAPTAIN",
      eventTag: "stale-epoch",
    });
    const epochForeman = loadGoalStateReadOnly(
      epoch.repository.root,
      "goal-receipt-integration",
      (loaded) => loaded.snapshot.tasks["TASK-A"].sessions.FOREMAN,
    );
    goalCommand([
      "control",
      "--goal", "goal-receipt-integration",
      "--expected-epoch", "0",
      "--reason", "invalidate pending intent epoch",
      "--instruction-ref", "test://issue-22/stale-epoch",
      "--thread", epochForeman.thread_id,
      "--actor-capability-file", epochForeman.capability_file,
      "--event-id", "stale-intent-control-1",
      "--json",
    ], epoch.repository.root);
    assertHiddenWithoutWrites(epoch);

    const packet = fixture({
      role: "CAPTAIN",
      eventTag: "stale-packet",
    });
    const packetForeman = loadGoalStateReadOnly(
      packet.repository.root,
      "goal-receipt-integration",
      (loaded) => loaded.snapshot.tasks["TASK-A"].sessions.FOREMAN,
    );
    const packetWorktree = createDetachedWorker(
      packet.repository,
      packet.repository.manifest.base_head,
    );
    const manifestRelative = path.relative(
      packet.repository.root,
      packet.repository.manifestFile,
    );
    const manifestTarget = path.join(
      packetWorktree,
      manifestRelative,
    );
    mkdirSync(path.dirname(manifestTarget), { recursive: true });
    copyFileSync(packet.repository.manifestFile, manifestTarget);
    chmodSync(manifestTarget, 0o644);
    const packetPath =
      "docs/planning/goals/receipt/packets/TASK-A-r2.md";
    const packetBody =
      "# TASK-A r2\n\nInvalidate stale identity intent.\n";
    const packetTarget = path.join(packetWorktree, packetPath);
    mkdirSync(path.dirname(packetTarget), { recursive: true });
    writeFileSync(packetTarget, packetBody);
    git(packetWorktree, "add", ".");
    git(packetWorktree, "commit", "-qm", "packet revision 2");
    const packetHead = git(packetWorktree, "rev-parse", "HEAD");
    submitPublicGoalEvent(
      packet.repository,
      packet.root,
      {
        eventId: "stale-intent-packet-update-1",
        type: "PACKET_UPDATED",
        actorRole: "FOREMAN",
        actorCapabilityFile: packetForeman.capability_file,
        payload: {
          revision: 2,
          sha256: `sha256:${createHash("sha256")
            .update(packetBody)
            .digest("hex")}`,
          path: packetPath,
          change_kind: "CONTRACT",
        },
        cwd: packetWorktree,
        fullHead: packetHead,
      },
    );
    assertHiddenWithoutWrites(packet, packetWorktree);
  });

  test("binds worker observations to the exact bootstrap and launch across a higher attempt", () => {
    const setup = (): {
      repository: ReturnType<typeof integrationRepository>;
      initialized: Record<string, any>;
      artifacts: string;
      foreman: Record<string, any>;
      captain: Record<string, any>;
      p1: ReturnType<typeof advanceLegacyP1>;
    } => {
      const repository = integrationRepository({
        workerBootstrap: true,
      });
      process.env.GOAL_CONTROL_DIR = repository.controlDir;
      process.env.GOAL_CONTROL_TEST_MODE = "1";
      const initialized = goalCommand([
        "init",
        "--manifest", repository.manifestFile,
        "--json",
      ], repository.root).value;
      const artifacts = realpathSync(mkdtempSync(
        path.join(tmpdir(), "goal-worker-role-identity-"),
      ));
      roots.push(artifacts);
      chmodSync(artifacts, 0o700);
      const foreman = registerControlAuthority(
        repository,
        initialized,
        artifacts,
        "FOREMAN",
        null,
      );
      const captain = registerControlAuthority(
        repository,
        initialized,
        artifacts,
        "CAPTAIN",
        String(foreman.actor_capability_file),
      );
      const p1 = advanceLegacyP1(
        repository,
        artifacts,
        foreman,
        captain,
      );
      return {
        repository,
        initialized,
        artifacts,
        foreman,
        captain,
        p1,
      };
    };

    const mismatch = setup();
    const mismatchWorkerA = createDetachedWorker(
      mismatch.repository,
      mismatch.p1.fullHead,
    );
    const mismatchBootstrapA = prepareWorkerBootstrap(
      mismatch.repository,
      mismatch.p1.worktree,
      mismatchWorkerA,
      {
        operationId: "bootstrap-dev-mismatch-a",
        challenge: "a1".repeat(32),
        threadId: "actual-dev-mismatch-thread-a",
        hostId: "actual-dev-mismatch-host-a",
      },
    );
    const mismatchWorkerB = createDetachedWorker(
      mismatch.repository,
      mismatch.p1.fullHead,
    );
    const mismatchBootstrapB = prepareWorkerBootstrap(
      mismatch.repository,
      mismatch.p1.worktree,
      mismatchWorkerB,
      {
        operationId: "bootstrap-dev-mismatch-b",
        challenge: "b2".repeat(32),
        threadId: "actual-dev-mismatch-thread-b",
        hostId: "actual-dev-mismatch-host-b",
      },
    );
    let beforeCrossBinding: Record<string, string> = {};
    expect(() => registerWorkerIdentity(
      mismatch.repository,
      mismatch.p1.worktree,
      mismatch.artifacts,
      mismatch.captain,
      mismatchWorkerA,
      mismatchBootstrapA,
      {
        eventId: "register-dev-cross-bootstrap-1",
        threadId: "actual-dev-mismatch-thread-a",
        hostId: "actual-dev-mismatch-host-a",
        attempt: 1,
        launchId: "launch-dev-cross-bootstrap-a",
        observedBootstrapBindingSha256:
          mismatchBootstrapB.binding.binding_sha256,
        beforeRegister: () => {
          beforeCrossBinding = ordinaryFileSnapshot(
            mismatch.repository.controlDir,
          );
        },
      },
    )).toThrow(expect.objectContaining({
      code: "ROLE_IDENTITY_WORKER_BOOTSTRAP_MISMATCH",
    }));
    expect(ordinaryFileSnapshot(mismatch.repository.controlDir))
      .toEqual(beforeCrossBinding);

    let beforeCrossLaunch: Record<string, string> = {};
    expect(() => registerWorkerIdentity(
      mismatch.repository,
      mismatch.p1.worktree,
      mismatch.artifacts,
      mismatch.captain,
      mismatchWorkerA,
      mismatchBootstrapA,
      {
        eventId: "register-dev-cross-launch-1",
        threadId: "actual-dev-mismatch-thread-a",
        hostId: "actual-dev-mismatch-host-a",
        attempt: 1,
        launchId: "launch-dev-observed-a",
        registrationLaunchId: "launch-dev-supplied-b",
        beforeRegister: () => {
          beforeCrossLaunch = ordinaryFileSnapshot(
            mismatch.repository.controlDir,
          );
        },
      },
    )).toThrow(expect.objectContaining({
      code: "ROLE_IDENTITY_INTENT_MISMATCH",
    }));
    expect(ordinaryFileSnapshot(mismatch.repository.controlDir))
      .toEqual(beforeCrossLaunch);

    const positive = setup();
    const workerAttempt1 = createDetachedWorker(
      positive.repository,
      positive.p1.fullHead,
    );
    const bootstrapAttempt1 = prepareWorkerBootstrap(
      positive.repository,
      positive.p1.worktree,
      workerAttempt1,
      {
        operationId: "bootstrap-dev-positive-1",
        challenge: "c3".repeat(32),
        threadId: "actual-dev-positive-thread-1",
        hostId: "actual-dev-positive-host-1",
      },
    );
    const registeredAttempt1 = registerWorkerIdentity(
      positive.repository,
      positive.p1.worktree,
      positive.artifacts,
      positive.captain,
      workerAttempt1,
      bootstrapAttempt1,
      {
        eventId: "register-dev-positive-1",
        threadId: "actual-dev-positive-thread-1",
        hostId: "actual-dev-positive-host-1",
        attempt: 1,
        launchId: "launch-dev-positive-1",
      },
    );
    submitPublicGoalEvent(
      positive.repository,
      positive.artifacts,
      {
        eventId: "dev-positive-role-lost-1",
        type: "ROLE_LOST",
        actorRole: "CAPTAIN",
        actorCapabilityFile: String(
          positive.captain.actor_capability_file,
        ),
        payload: {
          role: "DEV",
          reason: "higher-attempt worker binding test",
          expected_thread_id:
            registeredAttempt1.session.thread_id,
          expected_host_id:
            registeredAttempt1.session.host_id,
          expected_attempt:
            registeredAttempt1.session.attempt,
          expected_lease_until:
            registeredAttempt1.session.lease_until,
        },
      },
    );
    const workerAttempt2 = createDetachedWorker(
      positive.repository,
      positive.p1.fullHead,
    );
    const bootstrapAttempt2 = prepareWorkerBootstrap(
      positive.repository,
      positive.p1.worktree,
      workerAttempt2,
      {
        operationId: "bootstrap-dev-positive-2",
        challenge: "d4".repeat(32),
        threadId: "actual-dev-positive-thread-2",
        hostId: "actual-dev-positive-host-2",
      },
    );
    const registeredAttempt2 = registerWorkerIdentity(
      positive.repository,
      positive.p1.worktree,
      positive.artifacts,
      positive.captain,
      workerAttempt2,
      bootstrapAttempt2,
      {
        eventId: "register-dev-positive-2",
        threadId: "actual-dev-positive-thread-2",
        hostId: "actual-dev-positive-host-2",
        attempt: 2,
        launchId: "launch-dev-positive-2",
      },
    );
    expect(registeredAttempt2).toMatchObject({
      registered: true,
      idempotent: false,
      session: {
        role: "DEV",
        thread_id: "actual-dev-positive-thread-2",
        host_id: "actual-dev-positive-host-2",
        attempt: 2,
        launch_id: "launch-dev-positive-2",
        worker_bootstrap: {
          binding_sha256:
            bootstrapAttempt2.binding.binding_sha256,
        },
        role_identity: {
          operation_id: "register-dev-positive-2",
          launch_id: "launch-dev-positive-2",
          attempt: 2,
        },
      },
    });
    const positiveLoaded = loadGoalStateReadOnly(
      positive.p1.worktree,
      "goal-receipt-integration",
      (loaded) => loaded,
    );
    const positiveIntent = readdirSync(
      positiveLoaded.paths.roleIdentityIntents,
    )
      .filter((name) => (
        name.endsWith(".role-identity-intent.json")
      ))
      .map((name) => JSON.parse(readFileSync(
        path.join(
          positiveLoaded.paths.roleIdentityIntents,
          name,
        ),
        "utf8",
      )))
      .find((candidate) => (
        candidate.operation_id === "register-dev-positive-2"
      ));
    expect(positiveIntent.identity_observation)
      .toMatchObject({
        worker_bootstrap_binding_sha256:
          bootstrapAttempt2.binding.binding_sha256,
      });
  });

  test("rejects unattested claims, aliases, and credential-shaped identity leaves before generation without echo", () => {
    delete process.env.GOAL_CONTROL_DIR;
    delete process.env.GOAL_CONTROL_TEST_MODE;
    const repository = integrationRepository();
    process.env.GOAL_CONTROL_DIR = repository.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    const initialized = goalCommand([
      "init",
      "--manifest", repository.manifestFile,
      "--json",
    ], repository.root).value;
    const artifacts = realpathSync(mkdtempSync(
      path.join(tmpdir(), "goal-role-identity-adversarial-"),
    ));
    roots.push(artifacts);
    chmodSync(artifacts, 0o700);
    const plan = canaryPlan(repository.root, {
      manifestFile: path.relative(
        repository.root,
        repository.manifestFile,
      ),
      role: "FOREMAN",
      taskId: null,
      browserCanaryReceipt: null,
    });
    const challengeArgs = (
      operationId: string,
      identityFile: string,
    ): string[] => [
      "prepare-probe-observation-challenge",
      "--goal", "goal-receipt-integration",
      "--task", "TASK-A",
      "--role", "FOREMAN",
      "--event-id", operationId,
      "--canary-plan-sha256", plan.canary_plan_sha256,
      "--issuer-capability-file",
      String(initialized.bootstrap_capability_file),
      "--identity-receipt", identityFile,
      "--identity-receipt-sha256", fileSha256(identityFile),
      "--json",
    ];

    const forgedOperation = "forged-host-identity-1";
    const forged = roleIdentityObservation(repository, {
      operationId: forgedOperation,
      taskId: "TASK-A",
      role: "FOREMAN",
      threadId: "actual-foreman-thread-forged",
      hostId: "actual-host-forged",
      sessionId: "actual-session-forged",
      launchId: null,
    });
    forged.attestation.signature_base64url = "A".repeat(86);
    const forgedSeal = { ...forged };
    delete forgedSeal.record_sha256;
    forged.record_sha256 = hashObject(forgedSeal);
    const forgedFile = path.join(artifacts, "forged.json");
    writePrivateJson(forgedFile, forged);
    const beforeForged = ordinaryFileSnapshot(repository.controlDir);
    expect(() => goalCommand(
      challengeArgs(forgedOperation, forgedFile),
      repository.root,
    )).toThrow(expect.objectContaining({
      code: "ROLE_IDENTITY_OBSERVATION_AUTHENTICATION_INVALID",
    }));
    expect(ordinaryFileSnapshot(repository.controlDir))
      .toEqual(beforeForged);
    const afterForgedStatus = goalCommand([
      "status",
      "--goal", "goal-receipt-integration",
      "--json",
    ], repository.root).value;
    expect(
      afterForgedStatus.tasks["TASK-A"],
    ).not.toHaveProperty("role_identity_intent");
    expect(ordinaryFileSnapshot(repository.controlDir))
      .toEqual(beforeForged);

    const rejectedValues = [
      "local",
      "FOREMAN-A-1",
      `Ghp-${"Ab9_".repeat(9)}`,
      `prefix:XoXb_${"Q7-".repeat(10)}:suffix`,
      "A".repeat(43),
    ];
    for (const [index, rejected] of rejectedValues.entries()) {
      const operationId = `sensitive-role-identity-${index + 1}`;
      const observationRecord = roleIdentityObservation(repository, {
        operationId,
        taskId: "TASK-A",
        role: "FOREMAN",
        threadId: rejected,
        hostId: "actual-platform-host-1",
        sessionId: `actual-session-sensitive-${index + 1}`,
        launchId: null,
      });
      const receiptFile = path.join(
        artifacts,
        `sensitive-${index + 1}.json`,
      );
      writePrivateJson(receiptFile, observationRecord);
      const before = ordinaryFileSnapshot(repository.controlDir);
      let rejectedError: any = null;
      try {
        goalCommand(
          challengeArgs(operationId, receiptFile),
          repository.root,
        );
      } catch (error) {
        rejectedError = error;
      }
      expect(rejectedError).toBeTruthy();
      expect([
        "CANARY_OBSERVATION_SENSITIVE_DATA",
        "ROLE_IDENTITY_SYNTHETIC_ALIAS_FORBIDDEN",
      ]).toContain(rejectedError.code);
      expect(String(rejectedError.message)).not.toContain(rejected);
      expect(ordinaryFileSnapshot(repository.controlDir)).toEqual(before);
    }

    const localHostOperation = "synthetic-local-host-1";
    const localHost = roleIdentityObservation(repository, {
      operationId: localHostOperation,
      taskId: "TASK-A",
      role: "FOREMAN",
      threadId: "actual-foreman-thread-local-host",
      hostId: "LoCaL",
      sessionId: "actual-session-local-host",
      launchId: null,
    });
    const localHostFile = path.join(artifacts, "local-host.json");
    writePrivateJson(localHostFile, localHost);
    const beforeLocalHost = ordinaryFileSnapshot(
      repository.controlDir,
    );
    expect(() => goalCommand(
      challengeArgs(localHostOperation, localHostFile),
      repository.root,
    )).toThrow(expect.objectContaining({
      code: "ROLE_IDENTITY_SYNTHETIC_ALIAS_FORBIDDEN",
    }));
    expect(ordinaryFileSnapshot(repository.controlDir))
      .toEqual(beforeLocalHost);

    const trustCases: Array<{
      name: string;
      prepare: (
        sourceFile: string,
        operationId: string,
      ) => string;
      cleanup?: () => void;
    }> = [];
    trustCases.push({
      name: "symlink",
      prepare: (sourceFile) => {
        const linked = path.join(artifacts, "identity-symlink.json");
        symlinkSync(sourceFile, linked);
        return linked;
      },
    });
    trustCases.push({
      name: "hardlink",
      prepare: (sourceFile) => {
        const linked = path.join(artifacts, "identity-hardlink.json");
        linkSync(sourceFile, linked);
        return linked;
      },
    });
    trustCases.push({
      name: "permissive-file",
      prepare: (sourceFile) => {
        chmodSync(sourceFile, 0o644);
        return sourceFile;
      },
    });
    trustCases.push({
      name: "permissive-parent",
      prepare: (sourceFile) => {
        chmodSync(artifacts, 0o755);
        return sourceFile;
      },
      cleanup: () => chmodSync(artifacts, 0o700),
    });
    for (const [index, trustCase] of trustCases.entries()) {
      const operationId = `identity-file-trust-${index + 1}`;
      const trustedObservation = roleIdentityObservation(repository, {
        operationId,
        taskId: "TASK-A",
        role: "FOREMAN",
        threadId: `actual-file-trust-thread-${index + 1}`,
        hostId: "actual-file-trust-host",
        sessionId: `actual-file-trust-session-${index + 1}`,
        launchId: null,
      });
      const sourceFile = path.join(
        artifacts,
        `identity-file-trust-source-${index + 1}.json`,
      );
      writePrivateJson(sourceFile, trustedObservation);
      const candidateFile = trustCase.prepare(sourceFile, operationId);
      const before = ordinaryFileSnapshot(repository.controlDir);
      expect(() => goalCommand(
        challengeArgs(operationId, candidateFile),
        repository.root,
      )).toThrow(expect.objectContaining({
        code: "ROLE_IDENTITY_OBSERVATION_INVALID",
      }));
      expect(ordinaryFileSnapshot(repository.controlDir)).toEqual(before);
      trustCase.cleanup?.();
    }

    expect(() => goalCommand([
      ...challengeArgs(forgedOperation, forgedFile).slice(0, -1),
      "--thread", "caller-authored-thread",
      "--json",
    ], repository.root)).toThrow(expect.objectContaining({
      code: "INVALID_ARGUMENT",
    }));
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
          role_identity: {
            protocol: "goalctl-role-identity-intent-v1",
            thread_id: "foreman-thread-1",
            host_id: "host-1",
            attempt: 1,
            session_id: receipt.identityObservation.session_id,
            launch_id: null,
          },
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
      expect(goalCommand([
        "actions",
        "--goal", "goal-receipt-integration",
        "--task", "TASK-A",
        "--role", "FOREMAN",
        "--thread", "foreman-thread-1",
        "--json",
      ], repository.root).value).toMatchObject({
        goal_id: "goal-receipt-integration",
        task_id: "TASK-A",
      });
      expect(() => goalCommand([
        "actions",
        "--goal", "goal-receipt-integration",
        "--task", "TASK-A",
        "--role", "FOREMAN",
        "--thread", "foreman-1",
        "--json",
      ], repository.root)).toThrow(expect.objectContaining({
        code: "WRONG_ACTOR_THREAD",
      }));
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
      const currentIdentityVariants = [
        {
          name: "thread",
          values: {
            threadId: "actual-cross-current-thread",
            hostId: registeredSession.host_id,
            sessionId: registeredSession.role_identity.session_id,
          },
        },
        {
          name: "host",
          values: {
            threadId: registeredSession.thread_id,
            hostId: "actual-cross-current-host",
            sessionId: registeredSession.role_identity.session_id,
          },
        },
        {
          name: "session",
          values: {
            threadId: registeredSession.thread_id,
            hostId: registeredSession.host_id,
            sessionId: "actual-cross-current-session",
          },
        },
      ];
      for (const variant of currentIdentityVariants) {
        const variantEventId =
          `refresh-foreman-cross-${variant.name}`;
        const variantIdentity = roleIdentityObservation(repository, {
          operationId: variantEventId,
          taskId: "TASK-A",
          role: "FOREMAN",
          ...variant.values,
          launchId: null,
        });
        const variantIdentityFile = path.join(
          receipt.root,
          `${variantEventId}.json`,
        );
        writePrivateJson(variantIdentityFile, variantIdentity);
        const beforeVariant = ordinaryFileSnapshot(
          repository.controlDir,
        );
        expect(() => goalCommand([
          "prepare-probe-observation-challenge",
          "--goal", "goal-receipt-integration",
          "--task", "TASK-A",
          "--role", "FOREMAN",
          "--event-id", variantEventId,
          "--canary-plan-sha256",
          receipt.planEnvelope.canary_plan_sha256,
          "--issuer-capability-file",
          registeredSession.capability_file,
          "--identity-receipt", variantIdentityFile,
          "--identity-receipt-sha256",
          fileSha256(variantIdentityFile),
          "--json",
        ], repository.root)).toThrow(expect.objectContaining({
          code: "ROLE_IDENTITY_OBSERVATION_BINDING_MISMATCH",
        }));
        expect(ordinaryFileSnapshot(repository.controlDir))
          .toEqual(beforeVariant);
      }
      const refreshEventId = "refresh-foreman-receipt-1";
      const refreshIdentity = roleIdentityObservation(repository, {
        operationId: refreshEventId,
        taskId: "TASK-A",
        role: "FOREMAN",
        threadId: "foreman-thread-1",
        hostId: "host-1",
        sessionId: receipt.identityObservation.session_id,
        launchId: null,
      });
      const refreshIdentityFile = path.join(
        receipt.root,
        "refresh-identity.json",
      );
      writePrivateJson(refreshIdentityFile, refreshIdentity);
      const refreshChallenge = goalCommand([
        "prepare-probe-observation-challenge",
        "--goal", "goal-receipt-integration",
        "--task", "TASK-A",
        "--role", "FOREMAN",
        "--event-id", refreshEventId,
        "--canary-plan-sha256",
        receipt.planEnvelope.canary_plan_sha256,
        "--issuer-capability-file",
        registeredSession.capability_file,
        "--identity-receipt", refreshIdentityFile,
        "--identity-receipt-sha256",
        fileSha256(refreshIdentityFile),
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
