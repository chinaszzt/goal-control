import { execFileSync, spawnSync } from "child_process";
import { createHash, randomUUID } from "crypto";
import { createRequire } from "module";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir, userInfo } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const nodeRequire = createRequire(import.meta.url);
const gateAdapters = nodeRequire(path.join(ROOT, "scripts", "goal-control", "gate-adapters.js")) as {
  runFastEvidence: (cwd: string, options: Record<string, unknown>, dependencies?: Record<string, unknown>) => Record<string, any>;
  runFullCiEvidence: (cwd: string, options: Record<string, unknown>, dependencies?: Record<string, unknown>) => Record<string, any>;
  runAcAuditEvidence: (cwd: string, options: Record<string, unknown>, dependencies?: Record<string, unknown>) => Record<string, any>;
  trustedExecutableCandidates: (name: string, trustedHome?: string, nodeExecutable?: string) => string[];
};
type TransactionKey = {
  schema_version: 1;
  kind: string;
  scope: Record<string, string>;
  stable_operation_id_sha256: string;
  request_sha256: string;
  key_sha256: string;
};
const { canonicalTransactionKey } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "store.js"),
) as {
  canonicalTransactionKey: (
    kind: string,
    scope: Record<string, string>,
    stableId: string,
    requestHash: string,
  ) => TransactionKey;
};
const { hashObject } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "util.js"),
) as {
  hashObject: (value: unknown) => string;
};

type CliResult = { code: number; stdout: string; stderr: string };
type Role = "FOREMAN" | "CAPTAIN" | "DEV" | "REVIEW" | "RECEIPT";
type Capabilities = Partial<Record<Role, string>> & { bootstrap: string };

type Fixture = {
  sandbox: string;
  root: string;
  controlDir: string;
  productionRoot?: boolean;
  manifest: string;
  packetPath: string;
  packetHash: string;
  planHash: string;
  contextHash: string;
  baseHead: string;
  fullHead: string;
  bootstrapCapabilityFile?: string;
  bootstrapCapabilityBytes?: string;
  consumedGoalMetadataBytes?: string;
};

const THREADS: Record<Role, string> = {
  FOREMAN: "foreman-security-1",
  CAPTAIN: "captain-security-1",
  DEV: "dev-security-1",
  REVIEW: "review-security-1",
  RECEIPT: "receipt-security-1",
};

function runCli(
  fixture: Fixture,
  args: string[],
  options: { env?: Record<string, string> } = {},
): CliResult {
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    ...options.env,
  };
  if (fixture.productionRoot) {
    delete environment.GOAL_CONTROL_DIR;
    delete environment.GOAL_CONTROL_NOW;
    for (const key of Object.keys(environment)) {
      if (key.startsWith("GOAL_CONTROL_TEST_")) delete environment[key];
    }
  } else {
    environment.GOAL_CONTROL_DIR = fixture.controlDir;
    environment.GOAL_CONTROL_TEST_MODE = "1";
  }
  try {
    const stdout = execFileSync("node", [GOALCTL, ...args], {
      cwd: fixture.root,
      encoding: "utf8",
      stdio: "pipe",
      env: environment,
    });
    return { code: 0, stdout, stderr: "" };
  } catch (error: unknown) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return {
      code: failure.status ?? 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? "",
    };
  }
}

function expectCliSigkill(
  fixture: Fixture,
  args: string[],
  env: Record<string, string>,
): void {
  const interrupted = spawnSync(process.execPath, [GOALCTL, ...args], {
    cwd: fixture.root,
    encoding: "utf8",
    stdio: "pipe",
    timeout: 10_000,
    env: {
      ...process.env,
      GOAL_CONTROL_DIR: fixture.controlDir,
      GOAL_CONTROL_TEST_MODE: "1",
      ...env,
    },
  });
  expect(interrupted.error).toBeUndefined();
  expect(interrupted.status).toBeNull();
  expect(interrupted.signal).toBe("SIGKILL");
}

function parse(result: CliResult): Record<string, unknown> {
  expect(result.stdout).not.toBe("");
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

function expectError(result: CliResult, code: string): void {
  expect(result.code).not.toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toContain(code);
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" }).trim();
}

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function generationSeal(fixture: Fixture): {
  generation: number;
  active_transaction: TransactionKey | null;
  pre_write_vector_sha256: string | null;
  updated_at: string;
} {
  return JSON.parse(readFileSync(
    path.join(fixture.controlDir, ".generation.json"),
    "utf8",
  )) as {
    generation: number;
    active_transaction: TransactionKey | null;
    pre_write_vector_sha256: string | null;
    updated_at: string;
  };
}

function gitIndexSnapshot(repository: string): {
  path: string;
  dev: string;
  ino: string;
  size: string;
  mtime_ns: string;
  sha256: string;
} {
  const index = realpathSync(path.resolve(
    repository,
    git(
      repository,
      "rev-parse",
      "--path-format=absolute",
      "--git-path",
      "index",
    ),
  ));
  const stat = lstatSync(index, { bigint: true });
  return {
    path: index,
    dev: String(stat.dev),
    ino: String(stat.ino),
    size: String(stat.size),
    mtime_ns: String(stat.mtimeNs),
    sha256: sha256(readFileSync(index)),
  };
}

function writeGenerationSeal(
  controlDir: string,
  generation: number,
  activeTransaction: TransactionKey | null,
): void {
  const unsigned = {
    schema_version: 2,
    generation,
    active_transaction: activeTransaction,
    updated_at: "2026-07-24T00:00:00.000Z",
  };
  writeFileSync(
    path.join(controlDir, ".generation.json"),
    `${JSON.stringify({
      ...unsigned,
      seal_sha256: hashObject(unsigned),
    }, null, 2)}\n`,
  );
}

function exactControlTree(root: string): Array<[string, string, string]> {
  const entries: Array<[string, string, string]> = [];
  const visit = (directory: string, relativeDirectory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const relative = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      if (!relativeDirectory && (
        relative === ".lock"
          || relative.startsWith(".lock.")
      )) {
        continue;
      }
      const absolute = path.join(directory, name);
      const stat = lstatSync(absolute);
      const mode = (stat.mode & 0o7777).toString(8);
      if (stat.isDirectory()) {
        entries.push(["directory", relative, mode]);
        visit(absolute, relative);
      } else if (stat.isSymbolicLink()) {
        entries.push(["symlink", relative, `${mode}:${readlinkSync(absolute)}`]);
      } else {
        entries.push([
          "file",
          relative,
          `${mode}:${readFileSync(absolute).toString("base64")}`,
        ]);
      }
    }
  };
  visit(root, "");
  return entries;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.keys(value as Record<string, unknown>)
      .sort()
      .reduce<Record<string, unknown>>((output, key) => {
        output[key] = canonicalize((value as Record<string, unknown>)[key]);
        return output;
      }, {});
  }
  return value;
}

function registrySeal(record: Record<string, unknown>): Record<string, unknown> {
  const digest = sha256(JSON.stringify(canonicalize(record)));
  return { ...record, registry_sha256: digest };
}

function installPendingBootstrapConsumption(fixture: Fixture): string {
  expect(fixture.bootstrapCapabilityFile).toBeDefined();
  expect(fixture.bootstrapCapabilityBytes).toBeDefined();
  const metadataFile = path.join(
    fixture.controlDir,
    "goals",
    "demo",
    "goal.json",
  );
  fixture.consumedGoalMetadataBytes = readFileSync(metadataFile, "utf8");
  const metadata = JSON.parse(readFileSync(metadataFile, "utf8")) as Record<string, unknown>;
  delete metadata.bootstrap_consumed_at;
  delete metadata.meta_sha256;
  const sealed = {
    ...metadata,
    meta_sha256: sha256(JSON.stringify(canonicalize(metadata))),
  };
  writeFileSync(metadataFile, `${JSON.stringify(sealed, null, 2)}\n`);
  writeFileSync(
    fixture.bootstrapCapabilityFile as string,
    fixture.bootstrapCapabilityBytes as string,
  );
  chmodSync(fixture.bootstrapCapabilityFile as string, 0o600);
  return fixture.bootstrapCapabilityFile as string;
}

function restoreConsumedBootstrapState(fixture: Fixture): void {
  expect(fixture.consumedGoalMetadataBytes).toBeDefined();
  const metadataFile = path.join(
    fixture.controlDir,
    "goals",
    "demo",
    "goal.json",
  );
  writeFileSync(metadataFile, fixture.consumedGoalMetadataBytes as string);
  rmSync(fixture.bootstrapCapabilityFile as string, { force: true });
}

function makeFixture(): Fixture {
  const sandbox = mkdtempSync(path.join(tmpdir(), "goal-control-goal-security-"));
  const root = path.join(sandbox, "repo");
  const controlDir = path.join(sandbox, "control", "state");
  mkdirSync(root, { recursive: true });
  mkdirSync(controlDir, { recursive: true });
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.email", "security@example.test");
  git(root, "config", "user.name", "Goal Security Test");
  writeFileSync(path.join(root, "README.md"), "# security fixture\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "base");
  const baseHead = git(root, "rev-parse", "HEAD");

  const packetPath = "docs/planning/goals/demo/packets/TASK-A-r1.md";
  const absolutePacket = path.join(root, packetPath);
  mkdirSync(path.dirname(absolutePacket), { recursive: true });
  const packetBody = "# TASK-A r1\n\nImmutable security packet.\n";
  writeFileSync(absolutePacket, packetBody);
  const packetHash = sha256(packetBody);
  const issueDir = path.join(root, "docs", "issues", "4242");
  mkdirSync(issueDir, { recursive: true });
  const planBody = "# Security fixture plan\n";
  const contextBody = "# Security fixture context\n";
  writeFileSync(path.join(issueDir, "plan.md"), planBody);
  writeFileSync(path.join(issueDir, "context.md"), contextBody);
  const manifest = path.join(root, "docs", "planning", "goals", "demo", "manifest.json");
  writeFileSync(
    manifest,
    `${JSON.stringify(
      {
        schema_version: 1,
        goal_id: "demo",
        mode: "shadow",
        repository: { name_with_owner: "example-org/example-repo", base_branch: "main" },
        base_head: baseHead,
        tasks: [
          {
            id: "TASK-A",
            issue: 4242,
            dependencies: [],
            integration_order: 1,
            packet: { revision: 1, path: packetPath, sha256: packetHash },
          },
        ],
      },
      null,
      2
    )}\n`
  );
  git(root, "add", ".");
  git(root, "commit", "-qm", "goal manifest");
  return {
    sandbox,
    root,
    controlDir,
    manifest,
    packetPath,
    packetHash,
    planHash: sha256(planBody),
    contextHash: sha256(contextBody),
    baseHead,
    fullHead: git(root, "rev-parse", "HEAD"),
  };
}

function initialize(fixture: Fixture): CliResult {
  return runCli(fixture, ["init", "--manifest", fixture.manifest, "--json"]);
}

function rejectionRequest(
  fixture: Fixture,
  suffix: string,
): {
  args: string[];
  capability: string;
  wrongCapability: string;
  eventFile: string;
  raw: Record<string, unknown>;
} {
  expect(initialize(fixture).code).toBe(0);
  const capability = path.join(
    fixture.sandbox,
    `rejection-caller-${suffix}.cap`,
  );
  const wrongCapability = path.join(
    fixture.sandbox,
    `wrong-rejection-caller-${suffix}.cap`,
  );
  writeFileSync(capability, "rejection-caller\n", { mode: 0o600 });
  writeFileSync(wrongCapability, "wrong-rejection-caller\n", { mode: 0o600 });
  const raw = {
    schema_version: 1,
    event_id: `rejection-${suffix}`,
    goal_id: "demo",
    task_id: "TASK-A",
    type: "START_P1",
    actor: {
      role: "CAPTAIN",
      thread_id: "missing-captain",
      host_id: "local",
    },
    actor_sequence: 1,
    expected_state_revision: 0,
    control_epoch: 0,
    packet: { revision: 1, sha256: fixture.packetHash },
    base_head: fixture.baseHead,
    full_head: fixture.baseHead,
    payload: {},
  };
  const eventFile = path.join(
    fixture.sandbox,
    `rejection-${suffix}.json`,
  );
  writeFileSync(eventFile, `${JSON.stringify(raw, null, 2)}\n`);
  return {
    args: [
      "event",
      "--goal",
      "demo",
      "--file",
      eventFile,
      "--actor-capability-file",
      capability,
      "--json",
    ],
    capability,
    wrongCapability,
    eventFile,
    raw,
  };
}

function rejectionReceiptArtifacts(fixture: Fixture): {
  canonical: string[];
  temporary: string[];
} {
  const names = readdirSync(fixture.controlDir)
    .filter((name) => name.startsWith(".goal-event-rejection-"))
    .sort();
  return {
    canonical: names
      .filter((name) => name.endsWith(".json"))
      .map((name) => path.join(fixture.controlDir, name)),
    temporary: names
      .filter((name) => name.includes(".json.tmp"))
      .map((name) => path.join(fixture.controlDir, name)),
  };
}

function capabilityPath(result: CliResult, field: string): string {
  if (result.code !== 0) throw new Error(JSON.stringify(result));
  const value = parse(result)[field];
  expect(typeof value).toBe("string");
  const file = String(value);
  expect(existsSync(file)).toBe(true);
  expect(statSync(file).mode & 0o777).toBe(0o600);
  return file;
}

function registerRole(
  fixture: Fixture,
  role: Role,
  authorizerFlag: "bootstrap-capability-file" | "authorizer-capability-file",
  authorizerFile: string,
  options: { attempt?: number; status?: string; leaseMs?: number; thread?: string } = {}
): CliResult {
  const args = [
    "register-role",
    "--goal",
    "demo",
    "--task",
    "TASK-A",
    "--role",
    role,
    "--thread",
    options.thread ?? THREADS[role],
    "--host",
    "local",
    "--attempt",
    String(options.attempt ?? 1),
    `--${authorizerFlag}`,
    authorizerFile,
    "--json",
  ];
  if (options.status) args.push("--status", options.status);
  if (options.leaseMs !== undefined) args.push("--lease-ms", String(options.leaseMs));
  if (["DEV", "REVIEW", "RECEIPT"].includes(role)) {
    args.push("--launch-id", `launch-${role.toLowerCase()}-${options.attempt ?? 1}`);
  }
  return runCli(fixture, args);
}

function establishChain(
  fixture: Fixture,
  workers: Role[] = ["DEV"],
  workerOptions: Partial<Record<Role, { status?: string; leaseMs?: number }>> = {}
): Capabilities {
  const bootstrap = capabilityPath(initialize(fixture), "bootstrap_capability_file");
  fixture.bootstrapCapabilityFile = bootstrap;
  fixture.bootstrapCapabilityBytes = readFileSync(bootstrap, "utf8");
  const foreman = capabilityPath(
    registerRole(fixture, "FOREMAN", "bootstrap-capability-file", bootstrap),
    "actor_capability_file"
  );
  const captain = capabilityPath(
    registerRole(fixture, "CAPTAIN", "authorizer-capability-file", foreman),
    "actor_capability_file"
  );
  const capabilities: Capabilities = { bootstrap, FOREMAN: foreman, CAPTAIN: captain };
  for (const role of workers) {
    capabilities[role] = capabilityPath(
      registerRole(
        fixture,
        role,
        "authorizer-capability-file",
        captain,
        workerOptions[role]
      ),
      "actor_capability_file"
    );
  }
  return capabilities;
}

type TaskState = {
  phase: string;
  state_revision: number;
  control_epoch: number;
  task_cycle: number;
  base_head: string;
  full_head: string;
  packet: { revision: number; sha256: string };
  sessions: Record<Role, {
    role: Role;
    thread_id: string;
    host_id: string;
    attempt: number;
    launch_id: string | null;
    lease_until: string;
  }>;
};

function taskState(fixture: Fixture): TaskState {
  const result = runCli(fixture, ["status", "--goal", "demo", "--task", "TASK-A", "--json"]);
  expect(result.code).toBe(0);
  return (JSON.parse(result.stdout) as { tasks: { "TASK-A": TaskState } }).tasks["TASK-A"];
}

function eventInput(
  fixture: Fixture,
  type: string,
  role: Role,
  sequence: number,
  payload: Record<string, unknown> = {},
  fullHead?: string,
  threadId = THREADS[role]
): { event: Record<string, unknown>; file: string } {
  const state = taskState(fixture);
  const event = {
    schema_version: 1,
    event_id: randomUUID(),
    goal_id: "demo",
    task_id: "TASK-A",
    type,
    actor: { role, thread_id: threadId, host_id: "local" },
    actor_sequence: sequence,
    expected_state_revision: state.state_revision,
    control_epoch: state.control_epoch,
    packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
    base_head: state.base_head,
    full_head: fullHead ?? state.full_head,
    payload,
  };
  const inputDir = path.join(fixture.controlDir, "inputs");
  mkdirSync(inputDir, { recursive: true });
  const file = path.join(inputDir, `${event.event_id}.json`);
  writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);
  return { event, file };
}

function submitEvent(
  fixture: Fixture,
  input: { file: string },
  capabilityFile?: string
): CliResult {
  const args = ["event", "--goal", "demo", "--file", input.file];
  if (capabilityFile) args.push("--actor-capability-file", capabilityFile);
  args.push("--json");
  return runCli(fixture, args);
}

function applyEvent(
  fixture: Fixture,
  capabilities: Capabilities,
  type: string,
  role: Role,
  sequence: number,
  payload: Record<string, unknown> = {},
  fullHead?: string
): { eventId: string; result: CliResult } {
  const input = eventInput(fixture, type, role, sequence, payload, fullHead);
  const cap = capabilities[role];
  expect(cap).toBeDefined();
  const result = submitEvent(fixture, input, cap);
  if (result.code !== 0) throw new Error(JSON.stringify(result));
  return { eventId: String(input.event.event_id), result };
}

function enterDevActive(
  fixture: Fixture,
  devOptions: { status?: string; leaseMs?: number } = {}
): Capabilities {
  const capabilities = establishChain(fixture, []);
  applyEvent(fixture, capabilities, "START_P1", "CAPTAIN", 1);
  applyEvent(fixture, capabilities, "P1_READY", "CAPTAIN", 2, {
    plan_path: "docs/issues/4242/plan.md",
    plan_sha256: fixture.planHash,
    context_path: "docs/issues/4242/context.md",
    context_sha256: fixture.contextHash,
  });
  const approval = applyEvent(fixture, capabilities, "P1_APPROVED", "FOREMAN", 1, {
    plan_path: "docs/issues/4242/plan.md",
    plan_sha256: fixture.planHash,
    context_path: "docs/issues/4242/context.md",
    context_sha256: fixture.contextHash,
    approval_ref: "user://issue-4242/approved",
  });
  applyEvent(
    fixture,
    capabilities,
    "P1_COMMITTED",
    "CAPTAIN",
    3,
    {
      plan_path: "docs/issues/4242/plan.md",
      plan_sha256: fixture.planHash,
      context_path: "docs/issues/4242/context.md",
      context_sha256: fixture.contextHash,
      approval_event_id: approval.eventId,
    },
    fixture.fullHead
  );
  const devRegistration = registerRole(
    fixture,
    "DEV",
    "authorizer-capability-file",
    capabilities.CAPTAIN as string,
    devOptions
  );
  capabilities.DEV = capabilityPath(devRegistration, "actor_capability_file");
  if (devOptions.status !== "systemError") {
    seedDevLaunch(fixture, parse(devRegistration));
    applyEvent(fixture, capabilities, "LAUNCH_DEV", "CAPTAIN", 4, {
      launch_id: "launch-dev-1",
    });
  }
  return capabilities;
}

function seedWorkerLaunch(
  fixture: Fixture,
  registration: Record<string, unknown>,
  role: "DEV" | "REVIEW" | "RECEIPT",
): void {
  const state = taskState(fixture);
  const repositoryRoot = realpathSync(fixture.root);
  const session = registration.session as {
    launch_id: string;
    task_nonce: string;
    thread_id: string;
    host_id: string;
    registered_state_revision: number;
  };
  const dir = path.join(fixture.controlDir, "goals", "demo", "launches", "TASK-A");
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, `${session.launch_id}.json`), `${JSON.stringify({
    schema_version: 1,
    launch_id: session.launch_id,
    goal_id: "demo",
    task_id: "TASK-A",
    role,
    control_epoch: state.control_epoch,
    state_revision: session.registered_state_revision,
    thread: { id: session.thread_id, host_id: session.host_id, cwd: repositoryRoot },
    packet: { revision: state.packet.revision, path: fixture.packetPath, sha256: state.packet.sha256 },
    repository: {
      name_with_owner: "example-org/example-repo",
      origin_url: "https://github.com/example-org/example-repo.git",
      base_branch: "main",
      base_head: state.base_head,
      full_head: state.full_head,
      branch: "main",
      root: repositoryRoot,
      worktree: repositoryRoot,
    },
    ...(["REVIEW", "RECEIPT"].includes(role)
      ? {
        pull_request: {
          repository: "example-org/example-repo",
          number: 999,
          base: "main",
          head: fixture.fullHead,
        },
      }
      : {}),
    runtime: { node_version: process.version, pnpm_version: "10.0.0-test", lockfile_sha256: sha256("fixture lock") },
    execution: { environment: "none", write_mode: "NONE", task_nonce: session.task_nonce, target: { kind: "NONE" } },
    resource_leases: [],
    created_at: "2026-07-22T00:00:00.000Z",
  }, null, 2)}\n`);
}

function seedDevLaunch(fixture: Fixture, registration: Record<string, unknown>): void {
  seedWorkerLaunch(fixture, registration, "DEV");
}

type EvidenceKind = "PREFLIGHT" | "FAST" | "FULL_CI" | "AC_AUDIT";

function evidenceRecord(
  fixture: Fixture,
  id: string,
  kind: EvidenceKind,
  producer: Role,
  overrides: {
    producerRole?: Role;
    packetHash?: string;
    fullHead?: string;
  } = {}
): Record<string, unknown> {
  const state = taskState(fixture);
  const actualProducer = overrides.producerRole ?? producer;
  const artifactFile = path.join(fixture.controlDir, "test-artifacts", `${id}-${kind.toLowerCase()}.json`);
  const artifactBody = `${JSON.stringify({ kind, evidence_id: id, launch_id: "launch-dev-1" })}\n`;
  mkdirSync(path.dirname(artifactFile), { recursive: true });
  writeFileSync(artifactFile, artifactBody);
  return {
    schema_version: 1,
    evidence_id: id,
    goal_id: "demo",
    task_id: "TASK-A",
    kind,
    status: "PASS",
    producer: {
      role: actualProducer,
      thread_id: THREADS[actualProducer],
      host_id: "local",
    },
    state_revision: state.state_revision,
    packet: { revision: 1, sha256: overrides.packetHash ?? fixture.packetHash },
    packet_sha256: overrides.packetHash ?? fixture.packetHash,
    base_head: fixture.baseHead,
    full_head: overrides.fullHead ?? fixture.fullHead,
    created_at: "2026-07-22T00:00:00.000Z",
    uri: kind === "PREFLIGHT" ? `artifact://demo/TASK-A/${id}` : pathToFileURL(artifactFile).href,
    attestation: { controller: "goalctl", adapter: kind },
    ...(kind === "PREFLIGHT"
      ? { launch_id: "launch-dev-1", launch_sha256: sha256(artifactBody), launch_uri: pathToFileURL(artifactFile).href }
      : {
        source_sha256: sha256(artifactBody),
        ...(["FULL_CI", "AC_AUDIT"].includes(kind) ? {
          pull_request: {
            repository: "example-org/example-repo",
            number: 999,
            url: "https://github.com/example-org/example-repo/pull/999",
            base: "main",
            head: overrides.fullHead ?? fixture.fullHead,
          },
        } : {}),
      }),
  };
}

function seedEvidenceRegistry(
  fixture: Fixture,
  mutation?: (records: Record<string, Record<string, unknown>>) => void
): Record<string, string> {
  const ids = {
    preflight: `preflight-${randomUUID()}`,
    fast: `fast-${randomUUID()}`,
    full_ci: `full-ci-${randomUUID()}`,
    ac_audit: `ac-audit-${randomUUID()}`,
  };
  const records = {
    preflight: evidenceRecord(fixture, ids.preflight, "PREFLIGHT", "DEV"),
    fast: evidenceRecord(fixture, ids.fast, "FAST", "DEV"),
    full_ci: evidenceRecord(fixture, ids.full_ci, "FULL_CI", "CAPTAIN"),
    ac_audit: evidenceRecord(fixture, ids.ac_audit, "AC_AUDIT", "CAPTAIN"),
  };
  mutation?.(records);
  const dir = path.join(fixture.controlDir, "goals", "demo", "evidence", "TASK-A");
  const artifactDir = path.join(
    fixture.controlDir,
    "test-artifacts",
    "seeded-registry",
    "TASK-A"
  );
  mkdirSync(dir, { recursive: true });
  mkdirSync(artifactDir, { recursive: true });
  for (const [key, record] of Object.entries(records)) {
    if (record.kind === "PREFLIGHT") {
      const activeLaunch = path.join(fixture.controlDir, "goals", "demo", "launches", "TASK-A", "launch-dev-1.json");
      record.launch_uri = pathToFileURL(realpathSync(activeLaunch)).href;
      record.launch_sha256 = sha256(readFileSync(activeLaunch, "utf8"));
    } else {
      const artifactFile = path.join(
        artifactDir,
        `${ids[key as keyof typeof ids]}-artifact.json`
      );
      writeFileSync(artifactFile, `${JSON.stringify({ kind: record.kind, status: record.status }, null, 2)}\n`);
      record.uri = pathToFileURL(artifactFile).href;
      record.source_sha256 = sha256(readFileSync(artifactFile, "utf8"));
    }
    writeFileSync(path.join(dir, `${ids[key as keyof typeof ids]}.json`), `${JSON.stringify(registrySeal(record), null, 2)}\n`);
  }
  return ids;
}

function seedWorkflowEvidence(
  fixture: Fixture,
  kind: "REVIEW" | "RECEIPT" | "MERGE_BOUNDARY",
  producer: "REVIEW" | "RECEIPT" | "FOREMAN",
): string {
  const state = taskState(fixture);
  const evidenceId = `${kind.toLowerCase()}-${randomUUID()}`;
  const directory = path.join(
    fixture.controlDir,
    "goals",
    "demo",
    "evidence",
    "TASK-A",
  );
  const artifact = path.join(
    fixture.controlDir,
    "test-artifacts",
    `${evidenceId}.json`,
  );
  mkdirSync(directory, { recursive: true });
  mkdirSync(path.dirname(artifact), { recursive: true });
  writeFileSync(artifact, `${JSON.stringify({ kind, status: "PASS" })}\n`);
  const record = registrySeal({
    schema_version: 1,
    evidence_id: evidenceId,
    goal_id: "demo",
    task_id: "TASK-A",
    kind,
    status: "PASS",
    producer: {
      role: producer,
      thread_id: THREADS[producer],
      host_id: "local",
    },
    state_revision: state.state_revision,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    packet_sha256: state.packet.sha256,
    base_head: state.base_head,
    full_head: state.full_head,
    created_at: "2026-07-22T00:00:00.000Z",
    uri: pathToFileURL(artifact).href,
    source_sha256: sha256(readFileSync(artifact, "utf8")),
  });
  writeFileSync(
    path.join(directory, `${evidenceId}.json`),
    `${JSON.stringify(record, null, 2)}\n`,
  );
  return evidenceId;
}

function addAcceptanceAnchors(
  fixture: Fixture,
  records: Record<string, Record<string, unknown>>
): void {
  const state = taskState(fixture);
  for (const record of Object.values(records)) {
    const producer = record.producer as { role: Role };
    const session = state.sessions[producer.role];
    record.acceptance_anchor = {
      schema_version: 1,
      state_revision: record.state_revision,
      control_epoch: state.control_epoch,
      phase: state.phase,
      task_cycle: state.task_cycle,
      producer: {
        role: session.role,
        thread_id: session.thread_id,
        host_id: session.host_id,
        attempt: session.attempt,
        launch_id: session.launch_id,
      },
    };
  }
}

function devReadyInput(
  fixture: Fixture,
  evidence: Record<string, unknown>
): { file: string; event: Record<string, unknown> } {
  return eventInput(
    fixture,
    "DEV_READY",
    "DEV",
    1,
    { pr: "https://github.com/example-org/example-repo/pull/999", evidence },
    fixture.fullHead
  );
}

function allFiles(root: string): string[] {
  if (!existsSync(root)) return [];
  const files: string[] = [];
  function walk(dir: string): void {
    for (const name of readdirSync(dir)) {
      const candidate = path.join(dir, name);
      if (statSync(candidate).isDirectory()) walk(candidate);
      else files.push(candidate);
    }
  }
  walk(root);
  return files;
}

describe("goal control capability chain", () => {
  let fixture: Fixture;

  beforeEach(() => {
    fixture = makeFixture();
  });

  afterEach(() => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  it("returns stable 0600 capability paths on exact init retry without exposing raw capabilities", () => {
    const first = initialize(fixture);
    const bootstrapFile = capabilityPath(first, "bootstrap_capability_file");
    const recoveryFile = capabilityPath(first, "foreman_recovery_capability_file");
    const rawCapability = readFileSync(bootstrapFile, "utf8").trim();
    const rawRecovery = readFileSync(recoveryFile, "utf8").trim();
    expect(rawCapability.length).toBeGreaterThanOrEqual(32);
    expect(first.stdout).not.toContain(rawCapability);
    expect(first.stdout).not.toContain(rawRecovery);

    const second = initialize(fixture);
    expect(second.code).toBe(0);
    expect(parse(second)).toMatchObject({
      initialized: false,
      idempotent: true,
      bootstrap_capability_file: bootstrapFile,
      bootstrap_capability_consumed: false,
      foreman_recovery_capability_file: recoveryFile,
      receipt_publication: "ATOMIC_DIRECTORY_RENAME",
    });
    expect(typeof parse(second).init_receipt_file).toBe("string");
    expect(typeof parse(second).receipt_sha256).toBe("string");
    expect(second.stdout).not.toContain(rawCapability);
    expect(second.stdout).not.toContain(rawRecovery);
  });

  it("runs normal Goal writers on the repository control root without arming a test hook", () => {
    const productionFixture: Fixture = {
      ...fixture,
      controlDir: path.join(fixture.root, ".git", "goal-control", "v1"),
      productionRoot: true,
    };
    const capabilities = establishChain(productionFixture, []);
    const started = applyEvent(
      productionFixture,
      capabilities,
      "START_P1",
      "CAPTAIN",
      1,
    );
    expect(started.result.code).toBe(0);
    const state = taskState(productionFixture);
    expect(state.phase).toBe("P1_ACTIVE");
    expect(state.state_revision).toBeGreaterThan(0);
    const generation = JSON.parse(readFileSync(
      path.join(productionFixture.controlDir, ".generation.json"),
      "utf8",
    )) as { generation: number; active_transaction: unknown };
    expect(generation.generation % 2).toBe(0);
    expect(generation.active_transaction).toBeNull();
  });

  it("rejects a production generation fault before creating a lock or generation", () => {
    const productionControlDir = path.join(
      fixture.root,
      ".git",
      "goal-control",
      "v1",
    );
    const environment: NodeJS.ProcessEnv = { ...process.env };
    delete environment.GOAL_CONTROL_DIR;
    delete environment.GOAL_CONTROL_NOW;
    for (const key of Object.keys(environment)) {
      if (key.startsWith("GOAL_CONTROL_TEST_")) delete environment[key];
    }
    environment.GOAL_CONTROL_TEST_FAULT_AFTER_INIT_GENERATION = "throw";
    let result: CliResult;
    try {
      const stdout = execFileSync(
        "node",
        [GOALCTL, "init", "--manifest", fixture.manifest, "--json"],
        {
          cwd: fixture.root,
          encoding: "utf8",
          stdio: "pipe",
          env: environment,
        },
      );
      result = { code: 0, stdout, stderr: "" };
    } catch (error: unknown) {
      const failure = error as {
        status?: number;
        stdout?: string;
        stderr?: string;
      };
      result = {
        code: failure.status ?? 1,
        stdout: failure.stdout ?? "",
        stderr: failure.stderr ?? "",
      };
    }
    expectError(result, "TEST_MODE_FORBIDDEN");
    expect(existsSync(productionControlDir)).toBe(false);
  });

  it("rejects GOAL_CONTROL_TEST_MODE when the repository itself is not isolated under the system temp directory", () => {
    const controlDir = path.join(fixture.sandbox, "real-repo-control");
    mkdirSync(controlDir, { recursive: true });
    try {
      execFileSync("node", [GOALCTL, "status", "--goal", "demo", "--json"], {
        cwd: ROOT,
        encoding: "utf8",
        stdio: "pipe",
        env: { ...process.env, GOAL_CONTROL_DIR: controlDir, GOAL_CONTROL_TEST_MODE: "1" },
      });
      throw new Error("expected TEST_MODE_FORBIDDEN");
    } catch (error: unknown) {
      const failure = error as { stderr?: string };
      expect(failure.stderr).toContain("TEST_MODE_FORBIDDEN");
    }
  });

  it("does not trust caller TMPDIR when authorizing test-only overrides", () => {
    const fakeTempRoot = mkdtempSync(path.join(path.dirname(ROOT), "goalctl-tmpdir-poison-"));
    const fakeRepository = path.join(fakeTempRoot, "repo");
    const fakeControl = path.join(fakeTempRoot, "control");
    mkdirSync(fakeRepository, { recursive: true });
    mkdirSync(fakeControl, { recursive: true });
    git(fakeRepository, "init", "-q", "-b", "main");
    try {
      execFileSync("node", [GOALCTL, "status", "--goal", "not-initialized", "--json"], {
        cwd: fakeRepository,
        encoding: "utf8",
        stdio: "pipe",
        env: {
          ...process.env,
          TMPDIR: fakeTempRoot,
          GOAL_CONTROL_DIR: fakeControl,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      });
      throw new Error("expected TEST_MODE_FORBIDDEN");
    } catch (error: unknown) {
      const failure = error as { stderr?: string };
      expect(failure.stderr).toContain("TEST_MODE_FORBIDDEN");
    } finally {
      rmSync(fakeTempRoot, { recursive: true, force: true });
    }
  });

  it("rejects FOREMAN registration with no bootstrap capability", () => {
    expect(initialize(fixture).code).toBe(0);
    const result = runCli(fixture, [
      "register-role",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "FOREMAN",
      "--thread",
      THREADS.FOREMAN,
      "--host",
      "local",
      "--attempt",
      "1",
      "--json",
    ]);

    expectError(result, "CAPABILITY_REQUIRED");
  });

  it("rejects FOREMAN registration with the wrong bootstrap capability", () => {
    expect(initialize(fixture).code).toBe(0);
    const wrong = path.join(fixture.sandbox, "wrong-bootstrap.cap");
    writeFileSync(wrong, "not-the-bootstrap-capability\n", { mode: 0o600 });
    chmodSync(wrong, 0o600);

    expectError(
      registerRole(fixture, "FOREMAN", "bootstrap-capability-file", wrong),
      "CAPABILITY_INVALID"
    );
  });

  it("enforces FOREMAN → CAPTAIN → worker delegation and consumes bootstrap", () => {
    const capabilities = enterDevActive(fixture);
    const uniqueFiles = new Set(
      ["FOREMAN", "CAPTAIN", "DEV"].map(
        (role) => capabilities[role as Role]
      )
    );
    expect(uniqueFiles.size).toBe(3);

    const wrongParent = registerRole(
      fixture,
      "DEV",
      "authorizer-capability-file",
      capabilities.FOREMAN as string,
      { attempt: 2, thread: "dev-wrong-parent" }
    );
    expectError(wrongParent, "CAPABILITY_INVALID");

    const bootstrapReuse = registerRole(
      fixture,
      "FOREMAN",
      "bootstrap-capability-file",
      capabilities.bootstrap,
      { attempt: 2, thread: "foreman-reused-bootstrap" }
    );
    expectError(bootstrapReuse, "CAPABILITY_CONSUMED");
  });

  it("allows exact registration response recovery by its original authorizer or actor and redacts capability metadata from status", () => {
    const capabilities = establishChain(fixture, []);
    const registration = [
      "register-role",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "CAPTAIN",
      "--thread",
      THREADS.CAPTAIN,
      "--host",
      "local",
      "--attempt",
      "1",
    ];

    const recoveredByAuthorizer = runCli(fixture, [
      ...registration,
      "--authorizer-capability-file",
      capabilities.FOREMAN as string,
      "--json",
    ]);
    expect(recoveredByAuthorizer.code).toBe(0);
    expect(parse(recoveredByAuthorizer)).toMatchObject({
      registered: true,
      idempotent: true,
    });

    const repeated = runCli(fixture, [
      ...registration,
      "--actor-capability-file",
      capabilities.CAPTAIN as string,
      "--json",
    ]);
    expect(repeated.code).toBe(0);
    expect(parse(repeated)).toMatchObject({ registered: true, idempotent: true });

    const publicReads = [
      runCli(fixture, ["status", "--goal", "demo", "--json"]),
      runCli(fixture, ["rebuild-ledger", "--goal", "demo", "--json"]),
    ];
    for (const result of publicReads) {
      if (result.code !== 0) throw new Error(JSON.stringify(result));
      expect(result.code).toBe(0);
      expect(result.stdout).not.toContain("capability_file");
      expect(result.stdout).not.toContain("capability_sha256");
    }
  });

  it("recovers an exact ledger rebuild after a generation-boundary crash", () => {
    establishChain(fixture, []);
    expectCliSigkill(
      fixture,
      ["rebuild-ledger", "--goal", "demo", "--json"],
      {
        GOAL_CONTROL_TEST_FAULT_AFTER_LEDGER_REBUILD_GENERATION: "sigkill",
      },
    );
    const interrupted = generationSeal(fixture);
    expect(interrupted.generation % 2).toBe(1);
    expect(interrupted.active_transaction?.kind).toBe("LEDGER_REBUILD");

    const retried = runCli(
      fixture,
      ["rebuild-ledger", "--goal", "demo", "--json"],
    );
    expect(retried.code).toBe(0);
    expect(generationSeal(fixture).generation % 2).toBe(0);
    expect(retried.stdout).toContain("TASK-A");
  });

  it("requires the registered actor capability on every event", () => {
    const capabilities = establishChain(fixture, []);
    const input = eventInput(fixture, "START_P1", "CAPTAIN", 1);
    expectError(submitEvent(fixture, input), "CAPABILITY_REQUIRED");

    const wrong = path.join(fixture.sandbox, "wrong-actor.cap");
    writeFileSync(wrong, "wrong-actor-capability\n", { mode: 0o600 });
    expectError(submitEvent(fixture, input, wrong), "CAPABILITY_INVALID");

    expect(submitEvent(fixture, input, capabilities.CAPTAIN).code).toBe(0);
    expect(taskState(fixture).phase).toBe("P1_ACTIVE");
  });

  it("does not replace an active role with a higher attempt before ROLE_LOST recovery", () => {
    const capabilities = enterDevActive(fixture);
    const replacement = registerRole(
      fixture,
      "DEV",
      "authorizer-capability-file",
      capabilities.CAPTAIN as string,
      { attempt: 2, thread: "dev-security-2" }
    );

    expectError(replacement, "ROLE_REPLACEMENT_REQUIRES_RECOVERY");
  });

  it("requires every fresh ROLE_LOST path to bind one valid exact target", () => {
    const capabilities = establishChain(fixture, []);
    const target = taskState(fixture).sessions.CAPTAIN;
    const exactBinding = {
      expected_thread_id: target.thread_id,
      expected_host_id: target.host_id,
      expected_attempt: target.attempt,
      expected_lease_until: target.lease_until,
    };
    const bindingEntries = Object.entries(exactBinding);
    const before = taskState(fixture);
    const eventHead = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "event-heads",
      "TASK-A.json",
    );
    const eventHeadBefore = existsSync(eventHead)
      ? readFileSync(eventHead)
      : null;
    const assertRejectedStateIsUnchanged = (): void => {
      expect(taskState(fixture)).toEqual(before);
      expect(existsSync(eventHead)).toBe(eventHeadBefore !== null);
      if (eventHeadBefore) {
        expect(readFileSync(eventHead)).toEqual(eventHeadBefore);
      }
    };
    const writePayload = (
      name: string,
      payload: Record<string, unknown>,
    ): string => {
      const file = path.join(
        fixture.controlDir,
        "inputs",
        `${name}-${randomUUID()}.json`,
      );
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`);
      return file;
    };
    const template = (
      payload: Record<string, unknown>,
      name: string,
    ): CliResult => runCli(fixture, [
      "event-template",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "FOREMAN",
      "--thread",
      THREADS.FOREMAN,
      "--type",
      "ROLE_LOST",
      "--event-id",
      `${name}-${randomUUID()}`,
      "--payload-file",
      writePayload(name, payload),
      "--actor-capability-file",
      capabilities.FOREMAN as string,
      "--json",
    ]);

    for (let presentCount = 0; presentCount <= 3; presentCount += 1) {
      const payload = {
        role: "CAPTAIN",
        ...Object.fromEntries(bindingEntries.slice(0, presentCount)),
      };
      expectError(
        template(payload, `role-lost-template-partial-${presentCount}`),
        "ROLE_LOST_TARGET_REQUIRED",
      );
      expectError(
        submitEvent(
          fixture,
          eventInput(fixture, "ROLE_LOST", "FOREMAN", 1, payload),
          capabilities.FOREMAN,
        ),
        "ROLE_LOST_TARGET_REQUIRED",
      );
      assertRejectedStateIsUnchanged();
    }

    const malformedBindings = [
      { ...exactBinding, expected_thread_id: "invalid/thread" },
      { ...exactBinding, expected_host_id: "invalid/host" },
      { ...exactBinding, expected_attempt: Number.MAX_SAFE_INTEGER + 1 },
    ];
    for (const [index, binding] of malformedBindings.entries()) {
      const payload = { role: "CAPTAIN", ...binding };
      expectError(
        template(payload, `role-lost-template-invalid-${index}`),
        "ROLE_LOST_TARGET_INVALID",
      );
      expectError(
        submitEvent(
          fixture,
          eventInput(fixture, "ROLE_LOST", "FOREMAN", 1, payload),
          capabilities.FOREMAN,
        ),
        "ROLE_LOST_TARGET_INVALID",
      );
      assertRejectedStateIsUnchanged();
    }

    const acceptedTemplate = template(
      {
        role: "CAPTAIN",
        reason: "exact target security policy test",
        ...exactBinding,
      },
      "role-lost-template-exact",
    );
    expect(acceptedTemplate.code).toBe(0);
    const acceptedEvent = parse(acceptedTemplate);
    expect(acceptedEvent).toMatchObject({
      type: "ROLE_LOST",
      actor: {
        role: "FOREMAN",
        thread_id: THREADS.FOREMAN,
        host_id: "local",
      },
      payload: {
        role: "CAPTAIN",
        ...exactBinding,
      },
    });
    const acceptedInput = writePayload(
      "role-lost-exact-event",
      acceptedEvent,
    );
    expect(submitEvent(
      fixture,
      { file: acceptedInput },
      capabilities.FOREMAN,
    ).code).toBe(0);
    expect(taskState(fixture)).toMatchObject({
      sessions: {
        CAPTAIN: {
          status: "lost",
          thread_id: target.thread_id,
          host_id: target.host_id,
          attempt: target.attempt,
        },
      },
      recovery: {
        role: "CAPTAIN",
        lost_thread_id: target.thread_id,
        lost_host_id: target.host_id,
        lost_attempt: target.attempt,
      },
    });
  });

  it("rejects events from expired actor sessions", () => {
    const expiredCaps = enterDevActive(fixture);
    applyEvent(fixture, expiredCaps, "HEARTBEAT", "DEV", 1, {
      status: "active",
      lease_ms: 100,
    });
    const expiredEvent = eventInput(fixture, "ADD_HOLD", "DEV", 2, {
      kind: "TOOLING",
      evidence_id: "expired-evidence",
    });
    const leaseUntil = taskState(fixture).sessions.DEV?.lease_until;
    expect(leaseUntil).toBeDefined();
    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(leaseUntil as string) + 1
    ).toISOString();
    try {
      expectError(
        submitEvent(fixture, expiredEvent, expiredCaps.DEV),
        "ACTOR_LEASE_EXPIRED"
      );
    } finally {
      delete process.env.GOAL_CONTROL_NOW;
    }
  });

  it("rejects events from systemError actor sessions", () => {
    const errorCaps = enterDevActive(fixture);
    applyEvent(fixture, errorCaps, "HEARTBEAT", "DEV", 1, {
      status: "systemError",
      lease_ms: 3600000,
    });
    const errorEvent = eventInput(fixture, "ADD_HOLD", "DEV", 2, {
      kind: "TOOLING",
      evidence_id: "system-error-evidence",
    });
    expectError(submitEvent(fixture, errorEvent, errorCaps.DEV), "ACTOR_UNUSABLE");
  });

  it("advances control epoch only through FOREMAN capability + CAS and requires explicit reconcile", () => {
    const capabilities = establishChain(fixture, []);
    const eventId = `control-${randomUUID()}`;
    const missingCapability = runCli(fixture, [
      "control", "--goal", "demo", "--expected-epoch", "0", "--reason", "new user instruction",
      "--instruction-ref", "user://issue-4242/comment-1", "--thread", THREADS.FOREMAN, "--event-id", eventId, "--json",
    ]);
    expectError(missingCapability, "ARG_REQUIRED");

    const advanced = runCli(fixture, [
      "control", "--goal", "demo", "--expected-epoch", "0", "--reason", "new user instruction",
      "--instruction-ref", "user://issue-4242/comment-1", "--thread", THREADS.FOREMAN,
      "--actor-capability-file", capabilities.FOREMAN as string, "--event-id", eventId, "--json",
    ]);
    expect(advanced.code).toBe(0);
    expect(parse(advanced)).toMatchObject({ control_epoch: 1, event_id: eventId, idempotent: false });
    expect(taskState(fixture)).toMatchObject({ control_epoch: 1, reconcile_required: { control_event_id: eventId } });

    const blocked = eventInput(fixture, "START_P1", "CAPTAIN", 1);
    expectError(submitEvent(fixture, blocked, capabilities.CAPTAIN), "CONTROL_RECONCILE_REQUIRED");
    const reconcile = eventInput(fixture, "CONTROL_RECONCILED", "FOREMAN", 1, {
      control_event_id: eventId,
      instruction_ref: "user://issue-4242/comment-1",
    });
    expect(submitEvent(fixture, reconcile, capabilities.FOREMAN).code).toBe(0);
    expect(taskState(fixture)).toMatchObject({
      sessions: { CAPTAIN: { status: "terminal", terminal_reason: "CONTROL_EPOCH_CHANGED" } },
    });
    capabilities.CAPTAIN = capabilityPath(
      registerRole(
        fixture,
        "CAPTAIN",
        "authorizer-capability-file",
        capabilities.FOREMAN as string,
        { attempt: 2, thread: "captain-security-2" }
      ),
      "actor_capability_file"
    );
    expect(
      submitEvent(
        fixture,
        eventInput(fixture, "START_P1", "CAPTAIN", 1, {}, undefined, "captain-security-2"),
        capabilities.CAPTAIN
      ).code
    ).toBe(0);

    const stale = runCli(fixture, [
      "control", "--goal", "demo", "--expected-epoch", "0", "--reason", "stale",
      "--instruction-ref", "user://issue-4242/comment-2", "--thread", THREADS.FOREMAN,
      "--actor-capability-file", capabilities.FOREMAN as string,
      "--event-id", `control-stale-${randomUUID()}`, "--json",
    ]);
    expectError(stale, "STALE_CONTROL_EPOCH");
  });
});

describe("goal control trusted evidence registry", () => {
  let fixture: Fixture;
  let capabilities: Capabilities;

  beforeEach(() => {
    fixture = makeFixture();
    capabilities = enterDevActive(fixture);
  });

  it("registers semantic evidence only through an active producer capability and source digest", () => {
    const source = path.join(fixture.sandbox, "self-review.json");
    const sourceBody = `${JSON.stringify({ kind: "dev-self-review", status: "PASS" })}\n`;
    writeFileSync(source, sourceBody);
    const state = taskState(fixture);
    const evidence = {
      schema_version: 1,
      evidence_id: `self-review-registered-${randomUUID()}`,
      goal_id: "demo",
      task_id: "TASK-A",
      kind: "DEV_SELF_REVIEW",
      status: "PASS",
      producer: { role: "DEV", thread_id: THREADS.DEV, host_id: "local" },
      state_revision: state.state_revision,
      packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
      packet_sha256: state.packet.sha256,
      base_head: state.base_head,
      full_head: state.full_head,
      created_at: "2026-07-22T00:00:00.000Z",
      uri: pathToFileURL(source).href,
      source_sha256: sha256(sourceBody),
    };
    const input = path.join(fixture.controlDir, "inputs", `${evidence.evidence_id}.json`);
    mkdirSync(path.dirname(input), { recursive: true });
    writeFileSync(input, `${JSON.stringify(evidence, null, 2)}\n`);

    expectError(runCli(fixture, ["evidence", "--goal", "demo", "--file", input, "--json"]), "ARG_REQUIRED");
    const registered = runCli(fixture, [
      "evidence", "--goal", "demo", "--file", input,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]);
    expect(registered.code).toBe(0);
    const stored = (parse(registered).evidence as Record<string, unknown>);
    expect(stored.registry_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fileURLToPath(String(stored.uri))).toContain(
      path.join("goals", "demo", "evidence-sources", "TASK-A")
    );
    expect(fileURLToPath(String(stored.uri))).not.toBe(source);
    expect(readFileSync(fileURLToPath(String(stored.uri)), "utf8")).toBe(sourceBody);
    expect(registered.stdout).not.toContain(readFileSync(capabilities.DEV as string, "utf8").trim());
    expect(registered.stdout).not.toContain("capability_file");
    expect(registered.stdout).not.toContain("capability_sha256");
    const durableEvidence = readFileSync(
      String(parse(registered).evidence_file),
      "utf8"
    );
    expect(durableEvidence).toContain("capability_file");
    expect(durableEvidence).toContain("capability_sha256");

    const wrongDigest = { ...evidence, evidence_id: `fast-wrong-${randomUUID()}`, source_sha256: `sha256:${"0".repeat(64)}` };
    const wrongInput = path.join(fixture.controlDir, "inputs", `${wrongDigest.evidence_id}.json`);
    writeFileSync(wrongInput, `${JSON.stringify(wrongDigest, null, 2)}\n`);
    expectError(runCli(fixture, [
      "evidence", "--goal", "demo", "--file", wrongInput,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]), "EVIDENCE_SOURCE_HASH_MISMATCH");

    applyEvent(fixture, capabilities, "HEARTBEAT", "DEV", 1, {
      lease_ms: 3600000,
      status: "idle",
    });
    const retried = runCli(fixture, [
      "evidence", "--goal", "demo", "--file", input,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]);
    if (retried.code !== 0) {
      throw new Error(`semantic exact retry failed: ${retried.stderr || retried.stdout}`);
    }
    expect(retried.code).toBe(0);
    expect(parse(retried)).toMatchObject({ idempotent: true });
    expect(retried.stdout).not.toContain("capability_file");
    expect(retried.stdout).not.toContain("capability_sha256");

    const controlEventId = `control-after-evidence-${randomUUID()}`;
    const controlled = runCli(fixture, [
      "control",
      "--goal", "demo",
      "--expected-epoch", "0",
      "--reason", "terminalize original evidence producer",
      "--instruction-ref", "user://issue-4242/evidence-retry",
      "--thread", THREADS.FOREMAN,
      "--actor-capability-file", capabilities.FOREMAN as string,
      "--event-id", controlEventId,
      "--json",
    ]);
    expect(controlled.code).toBe(0);
    applyEvent(fixture, capabilities, "CONTROL_RECONCILED", "FOREMAN", 2, {
      control_event_id: controlEventId,
      instruction_ref: "user://issue-4242/evidence-retry",
    });
    expect(taskState(fixture).sessions.DEV).toMatchObject({
      thread_id: THREADS.DEV,
      status: "terminal",
      terminal_reason: "CONTROL_EPOCH_CHANGED",
    });
    const historicalRetry = runCli(fixture, [
      "evidence", "--goal", "demo", "--file", input,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]);
    expect(historicalRetry.code).toBe(0);
    expect(parse(historicalRetry)).toMatchObject({ idempotent: true });
    expect(historicalRetry.stdout).not.toContain("capability_file");
    expect(historicalRetry.stdout).not.toContain("capability_sha256");

    const conflictingEvidence = {
      ...evidence,
      created_at: "2026-07-22T00:00:01.000Z",
    };
    const conflictingInput = path.join(
      fixture.controlDir,
      "inputs",
      `conflict-${evidence.evidence_id}.json`,
    );
    writeFileSync(
      conflictingInput,
      `${JSON.stringify(conflictingEvidence, null, 2)}\n`,
    );
    expectError(runCli(fixture, [
      "evidence", "--goal", "demo", "--file", conflictingInput,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]), "EVIDENCE_ID_CONFLICT");
  });

  it("replays semantic evidence from the durable copy and pins the accepted registry digest", () => {
    const source = path.join(fixture.sandbox, "hold-assertion.json");
    const sourceBody = `${JSON.stringify({ kind: "blocked", status: "BLOCKED" })}\n`;
    writeFileSync(source, sourceBody);
    const state = taskState(fixture);
    const evidenceId = `hold-durable-${randomUUID()}`;
    const evidence = {
      schema_version: 1,
      evidence_id: evidenceId,
      goal_id: "demo",
      task_id: "TASK-A",
      kind: "HOLD_ASSERTION",
      status: "BLOCKED",
      producer: { role: "DEV", thread_id: THREADS.DEV, host_id: "local" },
      state_revision: state.state_revision,
      packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
      packet_sha256: state.packet.sha256,
      base_head: state.base_head,
      full_head: state.full_head,
      created_at: "2026-07-22T00:00:00.000Z",
      uri: pathToFileURL(source).href,
      source_sha256: sha256(sourceBody),
    };
    const input = path.join(fixture.controlDir, "inputs", `${evidenceId}.json`);
    writeFileSync(input, `${JSON.stringify(evidence, null, 2)}\n`);
    const registered = runCli(fixture, [
      "evidence", "--goal", "demo", "--file", input,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]);
    expect(registered.code).toBe(0);
    const stored = parse(registered).evidence as Record<string, unknown>;
    const durableSource = fileURLToPath(String(stored.uri));
    rmSync(source);

    const held = submitEvent(
      fixture,
      eventInput(fixture, "ADD_HOLD", "DEV", 1, {
        kind: "TOOLING",
        evidence_id: evidenceId,
        reason: "durable evidence replay",
      }),
      capabilities.DEV
    );
    expect(held.code).toBe(0);
    expect(taskState(fixture).phase).toBe("DEV_ACTIVE");

    const registryFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence",
      "TASK-A",
      `${evidenceId}.json`
    );
    const originalRegistry = readFileSync(registryFile, "utf8");
    const replaced = JSON.parse(readFileSync(registryFile, "utf8")) as Record<string, unknown>;
    delete replaced.registry_sha256;
    replaced.created_at = "2026-07-22T00:00:01.000Z";
    writeFileSync(registryFile, `${JSON.stringify(registrySeal(replaced), null, 2)}\n`);
    expectError(
      runCli(fixture, ["status", "--goal", "demo", "--task", "TASK-A", "--json"]),
      "EVIDENCE_REGISTRY_BINDING_MISMATCH"
    );

    writeFileSync(registryFile, originalRegistry);
    writeFileSync(durableSource, "tampered durable bytes\n");
    expectError(
      runCli(fixture, ["status", "--goal", "demo", "--task", "TASK-A", "--json"]),
      "EVIDENCE_SOURCE_HASH_MISMATCH"
    );
  });

  it("exact-retries semantic source publication and rejects unsafe source files", () => {
    const state = taskState(fixture);
    const evidenceId = `semantic-source-loss-${randomUUID()}`;
    const source = path.join(fixture.sandbox, `${evidenceId}.json`);
    const sourceBody = `${JSON.stringify({ incident: "sealed source" })}\n`;
    writeFileSync(source, sourceBody);
    const evidence = {
      schema_version: 1,
      evidence_id: evidenceId,
      goal_id: "demo",
      task_id: "TASK-A",
      kind: "HOLD_ASSERTION",
      status: "BLOCKED",
      producer: { role: "DEV", thread_id: THREADS.DEV, host_id: "local" },
      state_revision: state.state_revision,
      packet: state.packet,
      packet_sha256: state.packet.sha256,
      base_head: state.base_head,
      full_head: state.full_head,
      created_at: "2026-07-22T00:00:00.000Z",
      uri: pathToFileURL(source).href,
      source_sha256: sha256(sourceBody),
    };
    const input = path.join(fixture.controlDir, "inputs", `${evidenceId}.json`);
    writeFileSync(input, `${JSON.stringify(evidence, null, 2)}\n`);
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_SOURCE_PUBLISH = "1";
    expectError(runCli(fixture, [
      "evidence", "--goal", "demo", "--file", input,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]), "TEST_FAULT_AFTER_SEMANTIC_SOURCE_PUBLISH");
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_SOURCE_PUBLISH;

    const pendingBootstrap = installPendingBootstrapConsumption(fixture);
    const oddWrongCapabilityTree = exactControlTree(fixture.controlDir);
    expectError(runCli(fixture, [
      "evidence", "--goal", "demo", "--file", input,
      "--actor-capability-file", capabilities.CAPTAIN as string, "--json",
    ]), "CAPABILITY_INVALID");
    expect(exactControlTree(fixture.controlDir)).toEqual(oddWrongCapabilityTree);
    expect(readFileSync(pendingBootstrap, "utf8"))
      .toBe(fixture.bootstrapCapabilityBytes);

    const retried = runCli(fixture, [
      "evidence", "--goal", "demo", "--file", input,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]);
    if (retried.code !== 0) {
      throw new Error(`semantic source retry failed: ${retried.stderr || retried.stdout}`);
    }
    expect(retried.code).toBe(0);
    expect(parse(retried)).toMatchObject({
      idempotent: true,
      evidence: { evidence_id: evidenceId },
    });
    restoreConsumedBootstrapState(fixture);

    const realSource = path.join(fixture.sandbox, "semantic-real.json");
    writeFileSync(realSource, "{}\n");
    const linkedSource = path.join(fixture.sandbox, "semantic-link.json");
    symlinkSync(realSource, linkedSource);
    const linkedEvidence = {
      ...evidence,
      evidence_id: `semantic-symlink-${randomUUID()}`,
      uri: pathToFileURL(linkedSource).href,
      source_sha256: sha256("{}\n"),
    };
    const linkedInput = path.join(
      fixture.controlDir,
      "inputs",
      `${linkedEvidence.evidence_id}.json`,
    );
    writeFileSync(linkedInput, `${JSON.stringify(linkedEvidence, null, 2)}\n`);
    expectError(runCli(fixture, [
      "evidence", "--goal", "demo", "--file", linkedInput,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]), "EVIDENCE_SOURCE_TYPE_INVALID");

    const oversizedSource = path.join(fixture.sandbox, "semantic-oversized.bin");
    const oversizedBytes = Buffer.alloc((16 * 1024 * 1024) + 1, 0x61);
    writeFileSync(oversizedSource, oversizedBytes);
    const oversizedEvidence = {
      ...evidence,
      evidence_id: `semantic-oversized-${randomUUID()}`,
      uri: pathToFileURL(oversizedSource).href,
      source_sha256: sha256(oversizedBytes),
    };
    const oversizedInput = path.join(
      fixture.controlDir,
      "inputs",
      `${oversizedEvidence.evidence_id}.json`,
    );
    writeFileSync(
      oversizedInput,
      `${JSON.stringify(oversizedEvidence, null, 2)}\n`,
    );
    expectError(runCli(fixture, [
      "evidence", "--goal", "demo", "--file", oversizedInput,
      "--actor-capability-file", capabilities.DEV as string, "--json",
    ]), "EVIDENCE_SOURCE_TOO_LARGE");
  });

  it.each([
    ["PREFLIGHT", "DEV"],
    ["FAST", "DEV"],
    ["FULL_CI", "CAPTAIN"],
    ["AC_AUDIT", "CAPTAIN"],
  ] as const)("rejects caller-authored %s through the generic evidence ingress", (kind, role) => {
    const source = path.join(fixture.sandbox, `${kind.toLowerCase()}.json`);
    const sourceBody = `${JSON.stringify({ forged: kind, status: "PASS" })}\n`;
    writeFileSync(source, sourceBody);
    const state = taskState(fixture);
    const raw = {
      schema_version: 1,
      evidence_id: `forged-${kind.toLowerCase()}-${randomUUID()}`,
      goal_id: "demo",
      task_id: "TASK-A",
      kind,
      status: "PASS",
      producer: { role, thread_id: THREADS[role], host_id: "local" },
      state_revision: state.state_revision,
      packet: state.packet,
      packet_sha256: state.packet.sha256,
      base_head: state.base_head,
      full_head: fixture.fullHead,
      created_at: "2026-07-22T00:00:00.000Z",
      uri: pathToFileURL(source).href,
      source_sha256: sha256(sourceBody),
      attestation: { controller: "goalctl", adapter: kind },
      ...(kind === "PREFLIGHT" ? { launch_sha256: `sha256:${"c".repeat(64)}` } : {}),
    };
    const input = path.join(fixture.controlDir, "inputs", `${raw.evidence_id}.json`);
    writeFileSync(input, `${JSON.stringify(raw, null, 2)}\n`);

    expectError(runCli(fixture, [
      "evidence", "--goal", "demo", "--file", input,
      "--actor-capability-file", capabilities[role] as string, "--json",
    ]), "MECHANICAL_EVIDENCE_REQUIRED");
  });

  it("derives runner tool candidates only from fixed roots and the trusted OS home", () => {
    const trustedHome = path.join(path.sep, "trusted", "runner");
    const runningNode = path.join(path.sep, "trusted", "node", "bin", "node");
    const attackerBin = path.join(path.sep, "tmp", "attacker-bin");
    const pnpmCandidates = gateAdapters.trustedExecutableCandidates("pnpm", trustedHome, runningNode);
    const nodeCandidates = gateAdapters.trustedExecutableCandidates("node", trustedHome, runningNode);

    expect(pnpmCandidates).toContain(
      path.join(trustedHome, "setup-pnpm", "node_modules", ".bin", "pnpm")
    );
    expect(pnpmCandidates).not.toContain(path.join(attackerBin, "pnpm"));
    expect(nodeCandidates[0]).toBe(runningNode);
  });

  it("rejects executable resolver injection outside isolated test mode", () => {
    const previousControlDir = process.env.GOAL_CONTROL_DIR;
    const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    delete process.env.GOAL_CONTROL_TEST_MODE;
    try {
      expect(() => gateAdapters.runFastEvidence(fixture.root, {
        goalId: "demo",
        taskId: "TASK-A",
        evidenceId: `fast-resolver-${randomUUID()}`,
        actorCapabilityFile: capabilities.DEV as string,
      }, {
        runner: () => ({ status: 0, signal: null, stdout: "PASS\n", stderr: "" }),
        resolveExecutable: (name: string) => ({
          executable: path.join(fixture.sandbox, name),
          path_dir: fixture.sandbox,
        }),
      })).toThrow("测试覆盖必须同时使用 GOAL_CONTROL_TEST_MODE=1");
    } finally {
      if (previousControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
      else process.env.GOAL_CONTROL_DIR = previousControlDir;
      if (previousTestMode === undefined) delete process.env.GOAL_CONTROL_TEST_MODE;
      else process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
    }
  });

  it("runs mechanical gates through fixed controller commands and seals their artifacts", () => {
    const forbiddenEnvironment = [
      "BASH_ENV",
      "ENV",
      "CDPATH",
      "NODE_OPTIONS",
      "NODE_PATH",
      "PNPM_HOME",
      "GH_CONFIG_DIR",
      "GH_HOST",
      "GH_TOKEN",
      "GH_ENTERPRISE_TOKEN",
      "GITHUB_TOKEN",
      "GIT_CONFIG_COUNT",
      "GIT_CONFIG_KEY_0",
      "GIT_CONFIG_VALUE_0",
      "GIT_EXEC_PATH",
      "CODEX_HOME",
    ];
    const calls: Array<{
      executable: string;
      args: string[];
      environment: NodeJS.ProcessEnv;
      dangerousEnv: string[];
    }> = [];
    const runner = (executable: string, args: string[], options: { env: NodeJS.ProcessEnv }) => {
      const dangerousEnv = Object.keys(options.env).filter((key) => (
        forbiddenEnvironment.includes(key)
        || /^npm_config_/i.test(key)
      ));
      calls.push({ executable, args, environment: { ...options.env }, dangerousEnv });
      if (path.basename(executable) === "gh") {
        return {
          status: 0,
          signal: null,
          stderr: "",
          stdout: JSON.stringify({
            number: 999,
            url: "https://github.com/example-org/example-repo/pull/999",
            state: "OPEN",
            isDraft: false,
            headRefOid: fixture.fullHead,
            baseRefName: "main",
            statusCheckRollup: [{ name: "Quality Gate (Full)", conclusion: "SUCCESS" }],
          }),
        };
      }
      return { status: 0, signal: null, stdout: "PASS\n", stderr: "" };
    };
    const trustedBin = path.join(fixture.sandbox, "trusted-bin");
    mkdirSync(trustedBin);
    for (const name of ["node", "pnpm", "gh", "codex"]) {
      const executable = path.join(trustedBin, name);
      writeFileSync(executable, "#!/bin/sh\nexit 0\n");
      chmodSync(executable, 0o755);
    }
    const resolveExecutable = (name: string) => ({
      executable: path.join(trustedBin, name),
      path_dir: trustedBin,
    });
    const common = { goalId: "demo", taskId: "TASK-A", injectedCommand: ["sh", "-c", "true"] };
    const previousControlDir = process.env.GOAL_CONTROL_DIR;
    const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
    const previousPath = process.env.PATH;
    const attackerBin = path.join(fixture.sandbox, "attacker-bin");
    mkdirSync(attackerBin);
    const attackerPnpm = path.join(attackerBin, "pnpm");
    writeFileSync(attackerPnpm, "#!/bin/sh\nexit 0\n");
    chmodSync(attackerPnpm, 0o755);
    const poison = {
      SKIP_TESTS: "1",
      BASE_REF: "HEAD",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.hooksPath",
      GIT_CONFIG_VALUE_0: "/tmp/attacker-hooks",
      GIT_EXEC_PATH: "/tmp/attacker-git-exec",
      HOME: "/tmp/attacker-home",
      PNPM_HOME: attackerBin,
      CODEX_HOME: "/tmp/attacker-codex-home",
      BASH_ENV: "/tmp/attacker-bash-env",
      GH_TOKEN: "attacker-token",
      npm_config_userconfig: "/tmp/attacker-npmrc",
    };
    const previousPoison = new Map(
      Object.keys(poison).map((key) => [key, process.env[key]])
    );
    process.env.PATH = attackerBin;
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    Object.assign(process.env, poison);
    let fast = {} as Record<string, any>;
    let full = {} as Record<string, any>;
    let audit = {} as Record<string, any>;
    const fastOptions = {
      ...common,
      evidenceId: `fast-adapter-${randomUUID()}`,
      actorCapabilityFile: capabilities.DEV as string,
    };
    const fullOptions = {
      ...common,
      pullRequest: 999,
      evidenceId: `full-ci-adapter-${randomUUID()}`,
      actorCapabilityFile: capabilities.CAPTAIN as string,
    };
    const auditOptions = {
      ...common,
      issue: 4242,
      pullRequest: 999,
      evidenceId: `ac-audit-adapter-${randomUUID()}`,
      actorCapabilityFile: capabilities.CAPTAIN as string,
    };
    try {
      fast = gateAdapters.runFastEvidence(
        fixture.root,
        fastOptions,
        { runner, resolveExecutable },
      );
      full = gateAdapters.runFullCiEvidence(
        fixture.root,
        fullOptions,
        { runner, resolveExecutable },
      );
      audit = gateAdapters.runAcAuditEvidence(
        fixture.root,
        auditOptions,
        { runner, resolveExecutable },
      );
      expect(gateAdapters.runFullCiEvidence(
        fixture.root,
        fullOptions,
        { runner, resolveExecutable },
      )).toMatchObject({ idempotent: true });
      expect(gateAdapters.runAcAuditEvidence(
        fixture.root,
        auditOptions,
        { runner, resolveExecutable },
      )).toMatchObject({ idempotent: true });
      expect(() => gateAdapters.runFullCiEvidence(
        fixture.root,
        { ...fullOptions, pullRequest: 998 },
        { runner, resolveExecutable },
      )).toThrow("已绑定不同");
      expect(() => gateAdapters.runAcAuditEvidence(
        fixture.root,
        { ...auditOptions, issue: 4243 },
        { runner, resolveExecutable },
      )).toThrow("已绑定不同");
    } finally {
      if (previousControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
      else process.env.GOAL_CONTROL_DIR = previousControlDir;
      if (previousTestMode === undefined) delete process.env.GOAL_CONTROL_TEST_MODE;
      else process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
      process.env.PATH = previousPath;
      for (const [key, value] of previousPoison) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }

    expect(calls[0]).toMatchObject({ executable: "/bin/bash", args: ["scripts/quality-gate-fast.sh"] });
    expect(path.basename(calls[1].executable)).toBe("gh");
    expect(calls[1].args).toEqual(["pr", "view", "999", "--repo", "example-org/example-repo", "--json", "number,url,state,isDraft,headRefOid,baseRefName,statusCheckRollup"]);
    expect(calls[2]).toMatchObject({
      executable: "/bin/bash",
      args: ["scripts/ac-audit.sh", "4242", "--expected-head", fixture.fullHead, "--pr", "999", "--base", "main"],
    });
    for (const call of calls) {
      expect(String(call.environment.PATH)).not.toContain(attackerBin);
      expect(call.environment).toMatchObject({
        HOME: userInfo().homedir,
        SKIP_TESTS: "0",
        BASE_REF: "origin/main",
      });
      expect(call.environment.HOME).not.toBe(poison.HOME);
      expect(call.dangerousEnv).toEqual([]);
    }
    for (const result of [fast, full, audit]) {
      expect(result.evidence).toMatchObject({
        status: "PASS",
        attestation: { controller: "goalctl", adapter: result.evidence.kind },
      });
      const artifactFile = fileURLToPath(result.evidence.uri);
      expect(sha256(readFileSync(artifactFile, "utf8"))).toBe(result.evidence.source_sha256);
      expect(result.evidence.registry_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
  });

  it("aborts pristine FAST before one fresh current-authority runner", () => {
    const marker = path.join(fixture.sandbox, "fast-pristine-runs.txt");
    const scriptDirectory = path.join(fixture.root, "scripts");
    mkdirSync(scriptDirectory, { recursive: true });
    writeFileSync(
      path.join(scriptDirectory, "quality-gate-fast.sh"),
      `#!/bin/sh\nprintf 'run\\n' >> '${marker}'\nexit 0\n`,
    );
    git(fixture.root, "add", "scripts/quality-gate-fast.sh");
    git(fixture.root, "commit", "-qm", "test: add fast gate counter");
    fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");
    const evidenceId = `fast-pristine-current-${randomUUID()}`;
    const args = [
      "gate-fast",
      "--goal", "demo",
      "--task", "TASK-A",
      "--evidence-id", evidenceId,
      "--actor-capability-file", capabilities.DEV as string,
      "--json",
    ];
    const interrupted = runCli(fixture, args, {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_FAST_GENERATION: "sigkill",
      },
    });
    expect(interrupted.code).not.toBe(0);
    const runCount = () => (
      existsSync(marker)
        ? readFileSync(marker, "utf8").trim().split("\n").filter(Boolean).length
        : 0
    );
    expect(runCount()).toBe(1);
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const odd = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as {
      generation: number;
      active_transaction: { kind: string };
    };
    expect(odd.generation % 2).toBe(1);
    expect(odd.active_transaction.kind).toBe("FAST_GATE");

    const wrongCapabilityArgs = [...args];
    wrongCapabilityArgs[
      wrongCapabilityArgs.indexOf("--actor-capability-file") + 1
    ] = capabilities.CAPTAIN as string;
    expectError(
      runCli(fixture, wrongCapabilityArgs),
      "CAPABILITY_INVALID",
    );
    expect(runCount()).toBe(1);
    expect(JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )).generation % 2).toBe(1);

    const recovered = runCli(fixture, args);
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      evidence: { evidence_id: evidenceId, status: "PASS" },
    });
    expect(runCount()).toBe(2);
    const even = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: null };
    expect(even.generation % 2).toBe(0);
    expect(even.active_transaction).toBeNull();
  });

  it("runs zero fresh FAST runners when current producer has expired", () => {
    const devLeaseUntil = taskState(fixture).sessions.DEV.lease_until;
    const marker = path.join(fixture.sandbox, "fast-expired-runs.txt");
    const scriptDirectory = path.join(fixture.root, "scripts");
    mkdirSync(scriptDirectory, { recursive: true });
    writeFileSync(
      path.join(scriptDirectory, "quality-gate-fast.sh"),
      `#!/bin/sh\nprintf 'run\\n' >> '${marker}'\nexit 0\n`,
    );
    git(fixture.root, "add", "scripts/quality-gate-fast.sh");
    git(fixture.root, "commit", "-qm", "test: add expired fast counter");
    fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");
    const evidenceId = `fast-pristine-expired-${randomUUID()}`;
    const args = [
      "gate-fast",
      "--goal", "demo",
      "--task", "TASK-A",
      "--evidence-id", evidenceId,
      "--actor-capability-file", capabilities.DEV as string,
      "--json",
    ];
    expect(runCli(fixture, args, {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_FAST_GENERATION: "sigkill",
      },
    }).code).not.toBe(0);
    expect(readFileSync(marker, "utf8").trim().split("\n")).toHaveLength(1);

    expectError(
      runCli(fixture, args, {
        env: {
          GOAL_CONTROL_NOW: new Date(
            Date.parse(devLeaseUntil) + 1,
          ).toISOString(),
        },
      }),
      "ACTOR_LEASE_EXPIRED",
    );
    expect(readFileSync(marker, "utf8").trim().split("\n")).toHaveLength(1);
    const even = JSON.parse(readFileSync(
      path.join(fixture.controlDir, ".generation.json"),
      "utf8",
    )) as { generation: number; active_transaction: null };
    expect(even.generation % 2).toBe(0);
    expect(even.active_transaction).toBeNull();
  });

  it("recovers FAST from prepared-artifact and evidence response loss without rerunning the gate", () => {
    const previousControlDir = process.env.GOAL_CONTROL_DIR;
    const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    const trustedBin = path.join(fixture.sandbox, "gate-retry-bin");
    mkdirSync(trustedBin);
    for (const name of ["node", "pnpm"]) {
      const executable = path.join(trustedBin, name);
      writeFileSync(executable, "#!/bin/sh\nexit 0\n");
      chmodSync(executable, 0o755);
    }
    const resolveExecutable = (name: string) => ({
      executable: path.join(trustedBin, name),
      path_dir: trustedBin,
    });
    let runnerCalls = 0;
    const runner = () => {
      runnerCalls += 1;
      return { status: 0, signal: null, stdout: "PASS\n", stderr: "" };
    };
    try {
      const artifactOptions = {
        goalId: "demo",
        taskId: "TASK-A",
        evidenceId: `fast-artifact-loss-${randomUUID()}`,
        actorCapabilityFile: capabilities.DEV as string,
      };
      const archiveAttempt = eventInput(
        fixture,
        "ARCHIVED",
        "FOREMAN",
        2,
        { evidence_id: "archive-must-wait-for-fast-retry" },
      );
      expect(() => gateAdapters.runFastEvidence(
        fixture.root,
        artifactOptions,
        {
          runner,
          resolveExecutable,
          afterArtifactIngress: () => {
            throw new Error("lost after prepared artifact");
          },
        },
      )).toThrow("lost after prepared artifact");
      expect(runnerCalls).toBe(1);
      const pendingBootstrap = installPendingBootstrapConsumption(fixture);
      const oddWrongCapabilityTree = exactControlTree(fixture.controlDir);
      let wrongCapabilityError: unknown = null;
      try {
        gateAdapters.runFastEvidence(
          fixture.root,
          {
            ...artifactOptions,
            actorCapabilityFile: capabilities.CAPTAIN as string,
          },
          { runner, resolveExecutable },
        );
      } catch (error) {
        wrongCapabilityError = error;
      }
      expect(wrongCapabilityError).toMatchObject({
        code: "CAPABILITY_INVALID",
      });
      expect(runnerCalls).toBe(1);
      expect(exactControlTree(fixture.controlDir))
        .toEqual(oddWrongCapabilityTree);
      expect(readFileSync(pendingBootstrap, "utf8"))
        .toBe(fixture.bootstrapCapabilityBytes);
      const oddArtifactTree = exactControlTree(fixture.controlDir);
      expectError(
        submitEvent(
          fixture,
          archiveAttempt,
          capabilities.FOREMAN as string,
        ),
        "STORE_TRANSACTION_MISMATCH",
      );
      expect(exactControlTree(fixture.controlDir)).toEqual(oddArtifactTree);
      const dirty = path.join(fixture.root, "dirty-after-gate-artifact.txt");
      writeFileSync(dirty, "dirty\n");
      const recovered = gateAdapters.runFastEvidence(
        fixture.root,
        artifactOptions,
        { runner, resolveExecutable },
      );
      expect(recovered).toMatchObject({
        idempotent: true,
        evidence: {
          evidence_id: artifactOptions.evidenceId,
          status: "PASS",
        },
      });
      expect(runnerCalls).toBe(1);
      rmSync(dirty);

      const evidenceOptions = {
        ...artifactOptions,
        evidenceId: `fast-evidence-loss-${randomUUID()}`,
      };
      expect(() => gateAdapters.runFastEvidence(
        fixture.root,
        evidenceOptions,
        {
          runner,
          resolveExecutable,
          afterEvidenceIngress: () => {
            throw new Error("lost after evidence ingress");
          },
        },
      )).toThrow("lost after evidence ingress");
      expect(runnerCalls).toBe(2);
      expect(gateAdapters.runFastEvidence(
        fixture.root,
        evidenceOptions,
        { runner, resolveExecutable },
      )).toMatchObject({
        idempotent: true,
        evidence: { evidence_id: evidenceOptions.evidenceId },
      });
      expect(runnerCalls).toBe(2);
    } finally {
      if (previousControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
      else process.env.GOAL_CONTROL_DIR = previousControlDir;
      if (previousTestMode === undefined) delete process.env.GOAL_CONTROL_TEST_MODE;
      else process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
    }
  });

  it("refuses mechanical attestation before or after a candidate worktree becomes dirty", () => {
    const previousControlDir = process.env.GOAL_CONTROL_DIR;
    const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    const options = {
      goalId: "demo",
      taskId: "TASK-A",
      evidenceId: `fast-dirty-${randomUUID()}`,
      actorCapabilityFile: capabilities.DEV as string,
    };
    try {
      const dirtyBefore = path.join(fixture.root, "dirty-before.txt");
      writeFileSync(dirtyBefore, "uncommitted\n");
      let called = false;
      expect(() => gateAdapters.runFastEvidence(fixture.root, options, {
        runner: () => {
          called = true;
          return { status: 0, signal: null, stdout: "PASS\n", stderr: "" };
        },
      })).toThrow("clean committed HEAD");
      expect(called).toBe(false);
      rmSync(dirtyBefore);

      expect(() => gateAdapters.runFastEvidence(fixture.root, options, {
        runner: () => {
          writeFileSync(path.join(fixture.root, "dirty-during.txt"), "changed during gate\n");
          return { status: 0, signal: null, stdout: "PASS\n", stderr: "" };
        },
      })).toThrow("gate 运行期间 worktree 变脏");
    } finally {
      rmSync(path.join(fixture.root, "dirty-during.txt"), { force: true });
      if (previousControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
      else process.env.GOAL_CONTROL_DIR = previousControlDir;
      if (previousTestMode === undefined) delete process.env.GOAL_CONTROL_TEST_MODE;
      else process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
    }
  });

  afterEach(() => {
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_SOURCE_PUBLISH;
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  it("rejects inline PASS-shaped artifacts that were never registered", () => {
    const fake = {
      preflight: {
        status: "PASS",
        packet_sha256: fixture.packetHash,
        full_head: fixture.fullHead,
        uri: "artifact://invented/preflight",
      },
      fast: {
        status: "PASS",
        packet_sha256: fixture.packetHash,
        full_head: fixture.fullHead,
        uri: "artifact://invented/fast",
      },
      full_ci: {
        status: "PASS",
        packet_sha256: fixture.packetHash,
        full_head: fixture.fullHead,
        uri: "artifact://invented/full-ci",
      },
      ac_audit: {
        status: "PASS",
        packet_sha256: fixture.packetHash,
        full_head: fixture.fullHead,
        uri: "artifact://invented/ac-audit",
      },
    };

    expectError(
      submitEvent(fixture, devReadyInput(fixture, fake), capabilities.DEV),
      "EVIDENCE_NOT_REGISTERED"
    );
  });

  it("accepts DEV_READY only when every evidence ID resolves with the expected trust binding", () => {
    const ids = seedEvidenceRegistry(fixture);
    const result = submitEvent(fixture, devReadyInput(fixture, ids), capabilities.DEV);

    expect(result.code).toBe(0);
    expect(taskState(fixture).phase).toBe("DEV_READY");
  });

  it("recursively redacts capability metadata from every public task projection", () => {
    const state = taskState(fixture);
    const durableTask = (
      JSON.parse(
        readFileSync(
          path.join(fixture.controlDir, "goals", "demo", "state.json"),
          "utf8"
        )
      ) as { tasks: Record<string, TaskState> }
    ).tasks["TASK-A"];
    const ids = seedEvidenceRegistry(fixture, (records) => {
      for (const record of Object.values(records)) {
        const producer = record.producer as { role: Role };
        const session = durableTask.sessions[producer.role] as TaskState["sessions"][Role] & {
          capability_file: string;
          capability_sha256: string;
        };
        record.acceptance_anchor = {
          schema_version: 1,
          state_revision: record.state_revision,
          control_epoch: state.control_epoch,
          phase: state.phase,
          task_cycle: state.task_cycle,
          producer: {
            role: session.role,
            thread_id: session.thread_id,
            host_id: session.host_id,
            attempt: session.attempt,
            launch_id: session.launch_id ?? null,
            source_task_id: "TASK-A",
            capability_file: session.capability_file,
            capability_sha256: session.capability_sha256,
          },
        };
      }
    });
    const ready = submitEvent(
      fixture,
      devReadyInput(fixture, ids),
      capabilities.DEV
    );
    expect(ready.code).toBe(0);

    const durableState = readFileSync(
      path.join(fixture.controlDir, "goals", "demo", "state.json"),
      "utf8"
    );
    expect(durableState).toContain("capability_file");
    expect(durableState).toContain("capability_sha256");

    const publicReads = [
      runCli(fixture, ["status", "--goal", "demo", "--task", "TASK-A", "--json"]),
      runCli(fixture, ["next", "--goal", "demo", "--json"]),
      runCli(fixture, [
        "actions", "--goal", "demo", "--task", "TASK-A",
        "--role", "CAPTAIN", "--thread", THREADS.CAPTAIN, "--json",
      ]),
      runCli(fixture, [
        "resume", "--goal", "demo", "--task", "TASK-A",
        "--role", "CAPTAIN", "--thread", THREADS.CAPTAIN, "--json",
      ]),
    ];
    for (const result of publicReads) {
      expect(result.code).toBe(0);
      expect(result.stdout).not.toContain("capability_file");
      expect(result.stdout).not.toContain("capability_sha256");
    }
    expect(publicReads[0].stdout).toContain(THREADS.DEV);
    expect(publicReads[0].stdout).toContain(ids.fast);
  });

  it("allows only benign HEARTBEAT revisions between evidence acceptance and DEV_READY", () => {
    const ids = seedEvidenceRegistry(fixture, (records) => {
      addAcceptanceAnchors(fixture, records);
    });
    applyEvent(fixture, capabilities, "HEARTBEAT", "CAPTAIN", 5, {
      lease_ms: 3600000,
      status: "idle",
    });

    expect(submitEvent(fixture, devReadyInput(fixture, ids), capabilities.DEV).code).toBe(0);
    expect(taskState(fixture).phase).toBe("DEV_READY");
  });

  it("invalidates evidence when an intervening HEARTBEAT reports systemError", () => {
    const ids = seedEvidenceRegistry(fixture, (records) => {
      addAcceptanceAnchors(fixture, records);
    });
    applyEvent(fixture, capabilities, "HEARTBEAT", "CAPTAIN", 5, {
      lease_ms: 3600000,
      status: "systemError",
    });

    expectError(
      submitEvent(fixture, devReadyInput(fixture, ids), capabilities.DEV),
      "STALE_EVIDENCE"
    );
    expect(taskState(fixture).phase).toBe("DEV_ACTIVE");
  });

  it("replays accepted PREFLIGHT evidence after its DEV worktree is deleted", () => {
    const devWorktree = path.join(fixture.sandbox, "disposable-dev-worktree");
    git(
      fixture.root,
      "worktree",
      "add",
      "-q",
      "-b",
      `test/disposable-dev-${randomUUID()}`,
      devWorktree,
      fixture.fullHead
    );
    const activeLaunchFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      "launch-dev-1.json"
    );
    const activeLaunch = JSON.parse(readFileSync(activeLaunchFile, "utf8")) as Record<string, any>;
    activeLaunch.thread.cwd = devWorktree;
    activeLaunch.repository.worktree = devWorktree;
    activeLaunch.repository.branch = git(devWorktree, "branch", "--show-current");
    writeFileSync(activeLaunchFile, `${JSON.stringify(activeLaunch, null, 2)}\n`);

    const ids = seedEvidenceRegistry(fixture);
    const devReady = devReadyInput(fixture, ids);
    const accepted = (() => {
      try {
        const stdout = execFileSync("node", [
          GOALCTL,
          "event",
          "--goal",
          "demo",
          "--file",
          devReady.file,
          "--actor-capability-file",
          capabilities.DEV as string,
          "--json",
        ], {
          cwd: devWorktree,
          encoding: "utf8",
          stdio: "pipe",
          env: {
            ...process.env,
            GOAL_CONTROL_DIR: fixture.controlDir,
            GOAL_CONTROL_TEST_MODE: "1",
          },
        });
        return { code: 0, stdout, stderr: "" };
      } catch (error: unknown) {
        const failure = error as { status?: number; stdout?: string; stderr?: string };
        return {
          code: failure.status ?? 1,
          stdout: failure.stdout ?? "",
          stderr: failure.stderr ?? "",
        };
      }
    })();
    if (accepted.code !== 0) {
      throw new Error(`DEV_READY failed: ${accepted.stderr || accepted.stdout}`);
    }
    const preflightRegistry = JSON.parse(readFileSync(
      path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "evidence",
        "TASK-A",
        `${ids.preflight}.json`
      ),
      "utf8"
    )) as { launch_uri: string };
    const sealedLaunch = fileURLToPath(preflightRegistry.launch_uri);
    git(fixture.root, "worktree", "remove", "--force", devWorktree);
    expect(existsSync(devWorktree)).toBe(false);

    const replay = (args: string[]) => {
      return runCli(fixture, [...args, "--json"]);
    };
    const status = replay(["status", "--goal", "demo", "--task", "TASK-A"]);
    if (status.code !== 0) {
      throw new Error(`status replay failed: ${status.stderr || status.stdout}`);
    }
    expect(status.code).toBe(0);
    expect(JSON.parse(status.stdout)).toMatchObject({
      tasks: { "TASK-A": { phase: "DEV_READY" } },
    });
    for (const args of [
      ["next", "--goal", "demo"],
      [
        "actions", "--goal", "demo", "--task", "TASK-A",
        "--role", "CAPTAIN", "--thread", THREADS.CAPTAIN,
      ],
    ]) {
      const result = replay(args);
      expect(result.code).toBe(0);
      expect(result.stdout).toContain("TASK-A");
    }

    writeFileSync(sealedLaunch, "tampered sealed launch\n");
    expectError(
      replay(["status", "--goal", "demo", "--task", "TASK-A"]),
      "MECHANICAL_ARTIFACT_HASH_MISMATCH"
    );
  });

  it.each([
    ["preflight", "launch_uri"],
    ["fast", "uri"],
  ] as const)("rejects %s after its sealed artifact bytes are changed", (key, uriField) => {
    const ids = seedEvidenceRegistry(fixture);
    const id = ids[key];
    const registryFile = path.join(fixture.controlDir, "goals", "demo", "evidence", "TASK-A", `${id}.json`);
    const record = JSON.parse(readFileSync(registryFile, "utf8")) as Record<string, string>;
    writeFileSync(fileURLToPath(record[uriField]), "tampered after registration\n");

    expectError(
      submitEvent(fixture, devReadyInput(fixture, ids), capabilities.DEV),
      "MECHANICAL_ARTIFACT_HASH_MISMATCH"
    );
  });

  it.each([
    {
      name: "kind",
      code: "EVIDENCE_KIND_MISMATCH",
      mutate: (records: Record<string, Record<string, unknown>>) => {
        records.fast.kind = "FULL_CI";
      },
    },
    {
      name: "producer",
      code: "EVIDENCE_PRODUCER_MISMATCH",
      mutate: (records: Record<string, Record<string, unknown>>) => {
        records.fast.producer = {
          role: "CAPTAIN",
          thread_id: THREADS.CAPTAIN,
          host_id: "local",
        };
      },
    },
    {
      name: "packet",
      code: "STALE_EVIDENCE",
      mutate: (records: Record<string, Record<string, unknown>>) => {
        records.fast.packet = { revision: 1, sha256: `sha256:${"0".repeat(64)}` };
        records.fast.packet_sha256 = `sha256:${"0".repeat(64)}`;
      },
    },
    {
      name: "HEAD",
      code: "STALE_EVIDENCE",
      mutate: (records: Record<string, Record<string, unknown>>) => {
        records.fast.full_head = fixture.baseHead;
      },
    },
    {
      name: "PR",
      code: "PULL_REQUEST_EVIDENCE_MISMATCH",
      mutate: (records: Record<string, Record<string, unknown>>) => {
        records.full_ci.pull_request = {
          repository: "example-org/example-repo",
          number: 998,
          url: "https://github.com/example-org/example-repo/pull/998",
          base: "main",
          head: fixture.fullHead,
        };
      },
    },
  ])("rejects registry evidence with mismatched $name", ({ code, mutate }) => {
    const ids = seedEvidenceRegistry(fixture, mutate);

    expectError(
      submitEvent(fixture, devReadyInput(fixture, ids), capabilities.DEV),
      code
    );
    expect(taskState(fixture).phase).toBe("DEV_ACTIVE");
  });
});

describe("goal control rejection containment", () => {
  let fixture: Fixture;

  beforeEach(() => {
    fixture = makeFixture();
  });

  afterEach(() => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  it("contains raw invalid goal/task rejection logs and recursively redacts secrets", () => {
    const wrongCapability = path.join(fixture.sandbox, "wrong-event.cap");
    writeFileSync(wrongCapability, "wrong-event-capability\n", { mode: 0o600 });
    const secretValues = [
      "token-super-secret-4242",
      "password-super-secret-4242",
      "capability-super-secret-4242",
    ];
    const maliciousGoal = "../../../escaped-goal-4242";
    const maliciousTask = "../../../../escaped-task-4242";
    const rawEvents = [
      {
        schema_version: 1,
        event_id: "malicious-goal",
        goal_id: maliciousGoal,
        task_id: "TASK-A",
      },
      {
        schema_version: 1,
        event_id: "malicious-task",
        goal_id: "demo",
        task_id: maliciousTask,
      },
    ].map((event) => ({
      ...event,
      type: "START_P1",
      actor: { role: "CAPTAIN", thread_id: "attacker", host_id: "local" },
      actor_sequence: 1,
      expected_state_revision: 0,
      control_epoch: 0,
      packet: { revision: 1, sha256: fixture.packetHash },
      base_head: fixture.baseHead,
      full_head: fixture.baseHead,
      payload: {
        api_token: secretValues[0],
        nested: { password: secretValues[1] },
        values: [{ actor_capability: secretValues[2] }],
      },
    }));

    for (const raw of rawEvents) {
      const file = path.join(fixture.sandbox, `${raw.event_id}.json`);
      writeFileSync(file, `${JSON.stringify(raw, null, 2)}\n`);
      const result = runCli(fixture, [
        "event",
        "--goal",
        raw.goal_id,
        "--file",
        file,
        "--actor-capability-file",
        wrongCapability,
        "--json",
      ]);
      expect(result.code).not.toBe(0);
    }

    const escapedGoalPath = path.resolve(
      fixture.controlDir,
      "goals",
      maliciousGoal,
      "rejections",
      "TASK-A"
    );
    const escapedTaskPath = path.resolve(
      fixture.controlDir,
      "goals",
      "demo",
      "rejections",
      maliciousTask
    );
    expect(escapedGoalPath.startsWith(`${fixture.controlDir}${path.sep}`)).toBe(false);
    expect(escapedTaskPath.startsWith(`${fixture.controlDir}${path.sep}`)).toBe(false);
    expect(existsSync(escapedGoalPath)).toBe(false);
    expect(existsSync(escapedTaskPath)).toBe(false);

    const rejectionFiles = allFiles(fixture.controlDir).filter((file) => file.endsWith(".json"));
    expect(rejectionFiles.length).toBeGreaterThan(0);
    const rejectionText = rejectionFiles.map((file) => readFileSync(file, "utf8")).join("\n");
    for (const secret of secretValues) expect(rejectionText).not.toContain(secret);
    expect(rejectionText).toContain("INVALID_EVENT");
    expect(rejectionText).toContain("REDACTED");

    const generation = JSON.parse(readFileSync(
      path.join(fixture.controlDir, ".generation.json"),
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey | null;
    };
    expect(generation.generation % 2).toBe(0);
    expect(generation.active_transaction).toBeNull();
  });

  it("exact-retries a SIGKILLed deterministic rejection receipt and fences wrong caller/request", () => {
    expect(initialize(fixture).code).toBe(0);
    const capability = path.join(fixture.sandbox, "rejection-caller.cap");
    const wrongCapability = path.join(fixture.sandbox, "wrong-rejection-caller.cap");
    writeFileSync(capability, "rejection-caller\n", { mode: 0o600 });
    writeFileSync(wrongCapability, "wrong-rejection-caller\n", { mode: 0o600 });
    const raw = {
      schema_version: 1,
      event_id: "sigkill-rejection",
      goal_id: "demo",
      task_id: "TASK-A",
      type: "START_P1",
      actor: { role: "CAPTAIN", thread_id: "missing-captain", host_id: "local" },
      actor_sequence: 1,
      expected_state_revision: 0,
      control_epoch: 0,
      packet: { revision: 1, sha256: fixture.packetHash },
      base_head: fixture.baseHead,
      full_head: fixture.baseHead,
      payload: {},
    };
    const eventFile = path.join(fixture.sandbox, "sigkill-rejection.json");
    writeFileSync(eventFile, `${JSON.stringify(raw, null, 2)}\n`);
    const args = [
      "event",
      "--goal",
      "demo",
      "--file",
      eventFile,
      "--actor-capability-file",
      capability,
      "--json",
    ];
    expectCliSigkill(fixture, args, {
      GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_RECEIPT: "sigkill",
    });
    const receipt = readdirSync(fixture.controlDir)
      .find((name) => name.startsWith(".goal-event-rejection-"));
    expect(receipt).toBeDefined();
    const receiptFile = path.join(fixture.controlDir, receipt as string);
    const receiptBytes = readFileSync(receiptFile, "utf8");
    const odd = JSON.parse(readFileSync(
      path.join(fixture.controlDir, ".generation.json"),
      "utf8",
    )) as { generation: number; active_transaction: TransactionKey };
    expect(odd.generation % 2).toBe(1);
    expect(odd.active_transaction.kind).toBe("GOAL_EVENT_REJECTION");

    const rejectionPayload = () => exactControlTree(fixture.controlDir)
      .filter(([, relative]) => relative !== ".generation.json");
    const wrongCallerBefore = rejectionPayload();
    const wrongCallerArgs = args.map((value) => (
      value === capability ? wrongCapability : value
    ));
    expectError(runCli(fixture, wrongCallerArgs), "STORE_TRANSACTION_MISMATCH");
    expect(rejectionPayload()).toEqual(wrongCallerBefore);
    const afterWrongCaller = JSON.parse(readFileSync(
      path.join(fixture.controlDir, ".generation.json"),
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey;
      pre_write_vector_sha256: string;
    };
    expect(afterWrongCaller.generation % 2).toBe(1);
    expect(afterWrongCaller.active_transaction.key_sha256)
      .toBe(odd.active_transaction.key_sha256);

    const changedRaw = { ...raw, event_id: "changed-sigkill-rejection" };
    const changedFile = path.join(fixture.sandbox, "changed-sigkill-rejection.json");
    writeFileSync(changedFile, `${JSON.stringify(changedRaw, null, 2)}\n`);
    const wrongRequestArgs = args.map((value) => (
      value === eventFile ? changedFile : value
    ));
    expectError(runCli(fixture, wrongRequestArgs), "STORE_TRANSACTION_MISMATCH");
    expect(rejectionPayload()).toEqual(wrongCallerBefore);
    const afterWrongRequest = JSON.parse(readFileSync(
      path.join(fixture.controlDir, ".generation.json"),
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey;
      pre_write_vector_sha256: string;
    };
    expect(afterWrongRequest.generation % 2).toBe(1);
    expect(afterWrongRequest.active_transaction.key_sha256)
      .toBe(odd.active_transaction.key_sha256);
    expect(afterWrongRequest.pre_write_vector_sha256)
      .toBe(afterWrongCaller.pre_write_vector_sha256);

    expectError(runCli(fixture, args), "CAPABILITY_INVALID");
    expect(readFileSync(receiptFile, "utf8")).toBe(receiptBytes);
    const even = JSON.parse(readFileSync(
      path.join(fixture.controlDir, ".generation.json"),
      "utf8",
    )) as { generation: number; active_transaction: TransactionKey | null };
    expect(even.generation % 2).toBe(0);
    expect(even.active_transaction).toBeNull();
  });

  it.each([
    {
      stage: "temp-create",
      fault: "GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_CREATE",
      temporaryState: "EMPTY",
      linked: false,
    },
    {
      stage: "mid-write",
      fault: "GOAL_CONTROL_TEST_FAULT_DURING_REJECTION_TEMP_WRITE",
      temporaryState: "PARTIAL",
      linked: false,
    },
    {
      stage: "post-fsync",
      fault: "GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_FSYNC",
      temporaryState: "COMPLETE",
      linked: false,
    },
    {
      stage: "post-link",
      fault: "GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_LINK",
      temporaryState: "COMPLETE",
      linked: true,
    },
  ])(
    "repairs the original rejection temp inode after a real SIGKILL at $stage",
    ({ stage, fault, temporaryState, linked }) => {
      const request = rejectionRequest(fixture, stage);
      expectCliSigkill(fixture, request.args, { [fault]: "sigkill" });

      const interruptedArtifacts = rejectionReceiptArtifacts(fixture);
      expect(interruptedArtifacts.temporary).toHaveLength(1);
      expect(interruptedArtifacts.canonical)
        .toHaveLength(linked ? 1 : 0);
      const temporary = interruptedArtifacts.temporary[0];
      const temporaryStat = lstatSync(temporary);
      const temporaryBytes = readFileSync(temporary);
      if (temporaryState === "EMPTY") {
        expect(temporaryBytes).toHaveLength(0);
      } else if (temporaryState === "PARTIAL") {
        expect(temporaryBytes.length).toBeGreaterThan(0);
        expect(() => JSON.parse(temporaryBytes.toString("utf8")))
          .toThrow();
      } else {
        expect(JSON.parse(temporaryBytes.toString("utf8")))
          .toMatchObject({ kind: "GOAL_EVENT_REJECTION_RECEIPT" });
      }
      if (linked) {
        const canonicalStat = lstatSync(interruptedArtifacts.canonical[0]);
        expect({
          dev: String(canonicalStat.dev),
          ino: String(canonicalStat.ino),
        }).toEqual({
          dev: String(temporaryStat.dev),
          ino: String(temporaryStat.ino),
        });
      }
      const odd = generationSeal(fixture);
      expect(odd.generation % 2).toBe(1);
      expect(odd.active_transaction?.kind)
        .toBe("GOAL_EVENT_REJECTION");

      const rejectionPayload = () => exactControlTree(fixture.controlDir)
        .filter(([, relative]) => relative !== ".generation.json");
      const beforeWrongCaller = rejectionPayload();
      expectError(
        runCli(fixture, request.args.map((value) => (
          value === request.capability ? request.wrongCapability : value
        ))),
        "STORE_TRANSACTION_MISMATCH",
      );
      expect(rejectionPayload()).toEqual(beforeWrongCaller);

      const changedRaw = {
        ...request.raw,
        event_id: `${String(request.raw.event_id)}-changed`,
      };
      const changedFile = path.join(
        fixture.sandbox,
        `${String(changedRaw.event_id)}.json`,
      );
      writeFileSync(changedFile, `${JSON.stringify(changedRaw, null, 2)}\n`);
      const beforeWrongRequest = rejectionPayload();
      expectError(
        runCli(fixture, request.args.map((value) => (
          value === request.eventFile ? changedFile : value
        ))),
        "STORE_TRANSACTION_MISMATCH",
      );
      expect(rejectionPayload()).toEqual(beforeWrongRequest);

      expectError(runCli(fixture, request.args), "CAPABILITY_INVALID");
      const even = generationSeal(fixture);
      expect(even.generation % 2).toBe(0);
      expect(even.active_transaction).toBeNull();
      const recoveredArtifacts = rejectionReceiptArtifacts(fixture);
      expect(recoveredArtifacts.temporary).toEqual([]);
      expect(recoveredArtifacts.canonical).toHaveLength(1);
      const recoveredStat = lstatSync(recoveredArtifacts.canonical[0]);
      expect({
        dev: String(recoveredStat.dev),
        ino: String(recoveredStat.ino),
      }).toEqual({
        dev: String(temporaryStat.dev),
        ino: String(temporaryStat.ino),
      });
      const recoveredReceipt = JSON.parse(readFileSync(
        recoveredArtifacts.canonical[0],
        "utf8",
      )) as Record<string, unknown>;
      const unsignedReceipt = { ...recoveredReceipt };
      delete unsignedReceipt.receipt_sha256;
      expect(recoveredReceipt.receipt_sha256)
        .toBe(hashObject(unsignedReceipt));
    },
  );

  it.each([
    {
      scenario: "foreign canonical",
      fault: "GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_CREATE",
      mutate: (canonical: string, temporary: string): void => {
        expect(existsSync(canonical)).toBe(false);
        expect(existsSync(temporary)).toBe(true);
        writeFileSync(canonical, "foreign canonical\n", { mode: 0o600 });
      },
    },
    {
      scenario: "lookalike temporary",
      fault: "GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_CREATE",
      mutate: (canonical: string, temporary: string): void => {
        const body = readFileSync(temporary);
        rmSync(temporary);
        writeFileSync(`${canonical}.tmp-lookalike`, body, { mode: 0o600 });
      },
    },
    {
      scenario: "multiple temporaries",
      fault: "GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_CREATE",
      mutate: (_canonical: string, temporary: string): void => {
        writeFileSync(`${temporary}.extra`, "foreign\n", { mode: 0o600 });
      },
    },
    {
      scenario: "divergent exact temporary",
      fault: "GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_CREATE",
      mutate: (_canonical: string, temporary: string): void => {
        writeFileSync(temporary, "{\"foreign\":true}\n", { mode: 0o600 });
      },
    },
    {
      scenario: "separate canonical and temporary inodes",
      fault: "GOAL_CONTROL_TEST_FAULT_AFTER_REJECTION_TEMP_LINK",
      mutate: (canonical: string, temporary: string): void => {
        const body = readFileSync(temporary);
        const canonicalStat = lstatSync(canonical);
        rmSync(temporary);
        writeFileSync(temporary, body, { mode: 0o600 });
        const temporaryStat = lstatSync(temporary);
        expect({
          dev: String(temporaryStat.dev),
          ino: String(temporaryStat.ino),
        }).not.toEqual({
          dev: String(canonicalStat.dev),
          ino: String(canonicalStat.ino),
        });
      },
    },
  ])(
    "fails closed and preserves a $scenario rejection artifact",
    ({ scenario, fault, mutate }) => {
      const suffix = scenario.replace(/[^a-z]+/g, "-");
      const request = rejectionRequest(fixture, suffix);
      expectCliSigkill(fixture, request.args, { [fault]: "sigkill" });
      const artifacts = rejectionReceiptArtifacts(fixture);
      expect(artifacts.temporary).toHaveLength(1);
      const temporary = artifacts.temporary[0];
      const canonical = temporary.slice(0, temporary.indexOf(".tmp-"));
      mutate(canonical, temporary);

      const rejectionPayload = () => exactControlTree(fixture.controlDir)
        .filter(([, relative]) => relative !== ".generation.json");
      const before = rejectionPayload();
      expectError(
        runCli(fixture, request.args),
        "REJECTION_RECEIPT_CONFLICT",
      );
      expect(rejectionPayload()).toEqual(before);
      const odd = generationSeal(fixture);
      expect(odd.generation % 2).toBe(1);
      expect(odd.active_transaction?.kind)
        .toBe("GOAL_EVENT_REJECTION");
    },
  );

  it("cannot use an invalid-event rejection request to clear any odd transaction", () => {
    const wrongCapability = path.join(fixture.sandbox, "wrong-event.cap");
    writeFileSync(wrongCapability, "wrong-event-capability\n", { mode: 0o600 });
    const raw = {
      schema_version: 1,
      event_id: "malicious-odd-rejection",
      goal_id: "../../../escaped-goal-odd",
      task_id: "TASK-A",
      type: "START_P1",
      actor: { role: "CAPTAIN", thread_id: "attacker", host_id: "local" },
      actor_sequence: 1,
      expected_state_revision: 0,
      control_epoch: 0,
      packet: { revision: 1, sha256: fixture.packetHash },
      base_head: fixture.baseHead,
      full_head: fixture.baseHead,
      payload: { api_token: "must-never-be-written" },
    };
    const file = path.join(fixture.sandbox, "malicious-odd-rejection.json");
    writeFileSync(file, `${JSON.stringify(raw, null, 2)}\n`);

    const unrelatedRequest = { resource_id: "unrelated-resource-operation" };
    const unrelatedKey = canonicalTransactionKey(
      "RESOURCE_ACQUIRE",
      { resource_id: "unrelated-resource-operation" },
      "unrelated-resource-operation",
      hashObject(unrelatedRequest),
    );
    writeGenerationSeal(fixture.controlDir, 1, unrelatedKey);
    const unrelatedBefore = exactControlTree(fixture.controlDir);
    expectError(runCli(fixture, [
      "event",
      "--goal",
      raw.goal_id,
      "--file",
      file,
      "--actor-capability-file",
      wrongCapability,
      "--json",
    ]), "STORE_TRANSACTION_MISMATCH");
    expect(exactControlTree(fixture.controlDir)).toEqual(unrelatedBefore);

    const rawRequestHash = hashObject(raw);
    const exactRejectionKey = canonicalTransactionKey(
      "GOAL_EVENT_REJECTION",
      { lane: "invalid_event_v1" },
      rawRequestHash,
      rawRequestHash,
    );
    writeGenerationSeal(fixture.controlDir, 3, exactRejectionKey);
    const exactBefore = exactControlTree(fixture.controlDir);
    expectError(runCli(fixture, [
      "event",
      "--goal",
      raw.goal_id,
      "--file",
      file,
      "--actor-capability-file",
      wrongCapability,
      "--json",
    ]), "STORE_TRANSACTION_MISMATCH");
    expect(exactControlTree(fixture.controlDir)).toEqual(exactBefore);
  });
});

describe("goal event pristine odd recovery", () => {
  let fixture: Fixture;

  beforeEach(() => {
    fixture = makeFixture();
  });

  afterEach(() => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  it("recovers a generation-before-callback SIGKILL with the expired historical capability only", () => {
    const bootstrap = capabilityPath(
      initialize(fixture),
      "bootstrap_capability_file",
    );
    const foreman = capabilityPath(
      registerRole(
        fixture,
        "FOREMAN",
        "bootstrap-capability-file",
        bootstrap,
      ),
      "actor_capability_file",
    );
    const captainRegistration = registerRole(
      fixture,
      "CAPTAIN",
      "authorizer-capability-file",
      foreman,
      { leaseMs: 2000 },
    );
    const captain = capabilityPath(
      captainRegistration,
      "actor_capability_file",
    );
    const captainSession = parse(captainRegistration).session as {
      registered_at: string;
      lease_until: string;
    };
    const boundary = new Date(
      Date.parse(captainSession.registered_at) + 1,
    ).toISOString();
    const afterExpiry = new Date(
      Date.parse(captainSession.lease_until) + 1,
    ).toISOString();
    expect(Date.parse(boundary))
      .toBeLessThan(Date.parse(captainSession.lease_until));
    const input = eventInput(fixture, "START_P1", "CAPTAIN", 1);
    const args = [
      "event",
      "--goal",
      "demo",
      "--file",
      input.file,
      "--actor-capability-file",
      captain,
      "--json",
    ];
    expectCliSigkill(fixture, args, {
      GOAL_CONTROL_NOW: boundary,
      GOAL_CONTROL_TEST_FAULT_AFTER_EVENT_GENERATION: "sigkill",
    });
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const originalOdd = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey;
      pre_write_vector_sha256: string;
      updated_at: string;
    };
    expect(originalOdd.generation % 2).toBe(1);
    expect(originalOdd.active_transaction.kind).toBe("GOAL_EVENT");
    expect(originalOdd.updated_at).toBe(boundary);

    const payloadTree = () => exactControlTree(fixture.controlDir)
      .filter(([, relative]) => relative !== ".generation.json");
    const pristinePayload = payloadTree();
    expectError(runCli(
      fixture,
      args.map((value) => value === captain ? foreman : value),
      { env: { GOAL_CONTROL_NOW: afterExpiry } },
    ), "CAPABILITY_INVALID");
    expect(payloadTree()).toEqual(pristinePayload);
    const fencedOdd = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey;
      pre_write_vector_sha256: string;
    };
    expect(fencedOdd.generation % 2).toBe(1);
    expect(fencedOdd.active_transaction.key_sha256)
      .toBe(originalOdd.active_transaction.key_sha256);
    expect(fencedOdd.pre_write_vector_sha256)
      .toBe(originalOdd.pre_write_vector_sha256);

    const changed = {
      ...input.event,
      event_id: "different-pristine-event",
    };
    const changedFile = path.join(fixture.sandbox, "different-pristine-event.json");
    writeFileSync(changedFile, `${JSON.stringify(changed, null, 2)}\n`);
    expectError(runCli(
      fixture,
      args.map((value) => value === input.file ? changedFile : value),
      { env: { GOAL_CONTROL_NOW: afterExpiry } },
    ), "STORE_TRANSACTION_MISMATCH");
    expect(payloadTree()).toEqual(pristinePayload);

    const recovered = runCli(fixture, args, {
      env: { GOAL_CONTROL_NOW: afterExpiry },
    });
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      accepted: true,
      idempotent: false,
      event_id: input.event.event_id,
    });
    const even = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: TransactionKey | null };
    expect(even.generation % 2).toBe(0);
    expect(even.active_transaction).toBeNull();
  });
});

describe("goal command pristine generation recovery", () => {
  let fixture: Fixture;

  beforeEach(() => {
    fixture = makeFixture();
  });

  afterEach(() => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  it("exact-retries an INIT SIGKILL only after the pristine vector is restored", () => {
    const args = ["init", "--manifest", fixture.manifest, "--json"];
    expectCliSigkill(fixture, args, {
      GOAL_CONTROL_TEST_FAULT_AFTER_INIT_GENERATION: "sigkill",
    });

    const odd = generationSeal(fixture);
    expect(odd.generation % 2).toBe(1);
    expect(odd.active_transaction?.kind).toBe("GOAL_INIT");
    expect(existsSync(path.join(fixture.controlDir, "goals", "demo"))).toBe(false);

    const drift = path.join(fixture.controlDir, "init-pristine-vector-drift.txt");
    writeFileSync(drift, "must be fenced until removed\n");
    expectError(
      runCli(fixture, args),
      "STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH",
    );
    const vectorFenced = generationSeal(fixture);
    expect(vectorFenced.generation % 2).toBe(1);
    expect(vectorFenced.generation).toBe(odd.generation);
    expect(vectorFenced).toMatchObject({
      active_transaction: odd.active_transaction,
      pre_write_vector_sha256: odd.pre_write_vector_sha256,
      updated_at: odd.updated_at,
    });

    rmSync(drift);
    const recovered = runCli(fixture, args);
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      goal_id: "demo",
      initialized: true,
      idempotent: false,
    });
    expect(generationSeal(fixture)).toMatchObject({
      active_transaction: null,
    });
    expect(generationSeal(fixture).generation % 2).toBe(0);
  });

  it("uses the sealed REGISTRATION boundary for exact retry after authorizer expiry", () => {
    const bootstrap = capabilityPath(
      initialize(fixture),
      "bootstrap_capability_file",
    );
    const foremanRegistration = registerRole(
      fixture,
      "FOREMAN",
      "bootstrap-capability-file",
      bootstrap,
      { leaseMs: 60_000 },
    );
    const foreman = capabilityPath(
      foremanRegistration,
      "actor_capability_file",
    );
    const foremanSession = parse(foremanRegistration).session as {
      registered_at: string;
      lease_until: string;
    };
    const boundary = new Date(
      Date.parse(foremanSession.registered_at) + 1,
    ).toISOString();
    const afterExpiry = new Date(
      Date.parse(foremanSession.lease_until) + 1,
    ).toISOString();
    expect(Date.parse(boundary))
      .toBeLessThan(Date.parse(foremanSession.lease_until));

    const args = [
      "register-role",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "CAPTAIN",
      "--thread",
      THREADS.CAPTAIN,
      "--host",
      "local",
      "--attempt",
      "1",
      "--lease-ms",
      "3600000",
      "--authorizer-capability-file",
      foreman,
      "--event-id",
      "registration-generation-sigkill",
      "--json",
    ];
    expectCliSigkill(fixture, args, {
      GOAL_CONTROL_NOW: boundary,
      GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_GENERATION: "sigkill",
    });
    const odd = generationSeal(fixture);
    expect(odd.generation % 2).toBe(1);
    expect(odd.active_transaction?.kind).toBe("REGISTRATION");
    expect(odd.updated_at).toBe(boundary);
    expect(existsSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "registrations",
      "registration-generation-sigkill",
    ))).toBe(false);

    const wrongCapability = path.join(
      fixture.sandbox,
      "wrong-registration-authorizer.cap",
    );
    writeFileSync(wrongCapability, `${"x".repeat(48)}\n`, { mode: 0o600 });
    const wrongCapabilityArgs = args.map((value) => (
      value === foreman ? wrongCapability : value
    ));
    expectError(
      runCli(fixture, wrongCapabilityArgs, {
        env: { GOAL_CONTROL_NOW: afterExpiry },
      }),
      "CAPABILITY_INVALID",
    );
    const capabilityFenced = generationSeal(fixture);
    expect(capabilityFenced.generation % 2).toBe(1);
    expect(capabilityFenced.generation).toBe(odd.generation);
    expect(capabilityFenced).toMatchObject({
      active_transaction: odd.active_transaction,
      pre_write_vector_sha256: odd.pre_write_vector_sha256,
      updated_at: odd.updated_at,
    });

    const recovered = runCli(fixture, args, {
      env: { GOAL_CONTROL_NOW: afterExpiry },
    });
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      registered: true,
      idempotent: false,
      session: {
        role: "CAPTAIN",
        registered_at: boundary,
      },
    });
    expect(generationSeal(fixture).generation % 2).toBe(0);
    expect(generationSeal(fixture).active_transaction).toBeNull();
  });

  it("exact-retries a FOREMAN_RECOVERY SIGKILL only with the recovery capability", () => {
    const initialized = initialize(fixture);
    const bootstrap = capabilityPath(
      initialized,
      "bootstrap_capability_file",
    );
    const recoveryCapability = capabilityPath(
      initialized,
      "foreman_recovery_capability_file",
    );
    const foremanRegistration = registerRole(
      fixture,
      "FOREMAN",
      "bootstrap-capability-file",
      bootstrap,
      { leaseMs: 2_000 },
    );
    const foremanSession = parse(foremanRegistration).session as {
      lease_until: string;
    };
    const status = parse(runCli(fixture, [
      "status",
      "--goal",
      "demo",
      "--json",
    ]));
    const recoveryScope = (
      status.foreman_recovery_scope as { scope_sha256: string }
    ).scope_sha256;
    const afterExpiry = new Date(
      Date.parse(foremanSession.lease_until) + 1,
    ).toISOString();
    const args = [
      "recover-expired-foreman",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--thread",
      "foreman-security-2",
      "--host",
      "recovery-host",
      "--attempt",
      "2",
      "--lease-ms",
      "3600000",
      "--expected-goal-scope-sha256",
      recoveryScope,
      "--reason",
      "mechanical pristine recovery test",
      "--incident-ref",
      "incident://goal-control/pristine-generation",
      "--foreman-recovery-capability-file",
      recoveryCapability,
      "--event-id",
      "foreman-recovery-generation-sigkill",
      "--json",
    ];
    expectCliSigkill(fixture, args, {
      GOAL_CONTROL_NOW: afterExpiry,
      GOAL_CONTROL_TEST_FAULT_AFTER_FOREMAN_RECOVERY_GENERATION: "sigkill",
    });
    const odd = generationSeal(fixture);
    expect(odd.generation % 2).toBe(1);
    expect(odd.active_transaction?.kind).toBe("FOREMAN_RECOVERY");
    expect(existsSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "foreman-recovery-batches",
      "foreman-recovery-generation-sigkill",
    ))).toBe(false);

    const wrongCapability = path.join(
      fixture.sandbox,
      "wrong-foreman-recovery.cap",
    );
    writeFileSync(wrongCapability, `${"y".repeat(48)}\n`, { mode: 0o600 });
    expectError(
      runCli(fixture, args.map((value) => (
        value === recoveryCapability ? wrongCapability : value
      )), {
        env: { GOAL_CONTROL_NOW: afterExpiry },
      }),
      "CAPABILITY_INVALID",
    );
    const recoveryCapabilityFenced = generationSeal(fixture);
    expect(recoveryCapabilityFenced.generation % 2).toBe(1);
    expect(recoveryCapabilityFenced.generation).toBe(odd.generation);
    expect(recoveryCapabilityFenced).toMatchObject({
      active_transaction: odd.active_transaction,
      pre_write_vector_sha256: odd.pre_write_vector_sha256,
      updated_at: odd.updated_at,
    });

    const recovered = runCli(fixture, args, {
      env: { GOAL_CONTROL_NOW: afterExpiry },
    });
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      recovered: true,
      idempotent: false,
      event_id: "foreman-recovery-generation-sigkill",
    });
    expect(generationSeal(fixture).generation % 2).toBe(0);
    expect(generationSeal(fixture).active_transaction).toBeNull();
  });

  it("uses the sealed CONTROL boundary for exact retry after actor expiry", () => {
    const bootstrap = capabilityPath(
      initialize(fixture),
      "bootstrap_capability_file",
    );
    const foremanRegistration = registerRole(
      fixture,
      "FOREMAN",
      "bootstrap-capability-file",
      bootstrap,
      { leaseMs: 60_000 },
    );
    const foreman = capabilityPath(
      foremanRegistration,
      "actor_capability_file",
    );
    const foremanSession = parse(foremanRegistration).session as {
      registered_at: string;
      lease_until: string;
    };
    const boundary = new Date(
      Date.parse(foremanSession.registered_at) + 1,
    ).toISOString();
    const afterExpiry = new Date(
      Date.parse(foremanSession.lease_until) + 1,
    ).toISOString();
    const args = [
      "control",
      "--goal",
      "demo",
      "--expected-epoch",
      "0",
      "--reason",
      "mechanical control recovery test",
      "--instruction-ref",
      "user://goal-control/pristine-generation",
      "--actor-capability-file",
      foreman,
      "--thread",
      THREADS.FOREMAN,
      "--event-id",
      "control-generation-sigkill",
      "--json",
    ];
    expectCliSigkill(fixture, args, {
      GOAL_CONTROL_NOW: boundary,
      GOAL_CONTROL_TEST_FAULT_AFTER_CONTROL_GENERATION: "sigkill",
    });
    const odd = generationSeal(fixture);
    expect(odd.generation % 2).toBe(1);
    expect(odd.active_transaction?.kind).toBe("GOAL_CONTROL_EVENT");
    expect(odd.updated_at).toBe(boundary);

    const wrongRequest = [...args];
    wrongRequest[wrongRequest.indexOf("mechanical control recovery test")] =
      "different valid control request";
    expectError(
      runCli(fixture, wrongRequest, {
        env: { GOAL_CONTROL_NOW: afterExpiry },
      }),
      "STORE_TRANSACTION_MISMATCH",
    );
    const requestFenced = generationSeal(fixture);
    expect(requestFenced.generation % 2).toBe(1);
    expect(requestFenced.generation).toBe(odd.generation);
    expect(requestFenced).toMatchObject({
      active_transaction: odd.active_transaction,
      pre_write_vector_sha256: odd.pre_write_vector_sha256,
      updated_at: odd.updated_at,
    });

    const recovered = runCli(fixture, args, {
      env: { GOAL_CONTROL_NOW: afterExpiry },
    });
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      control_epoch: 1,
      event_id: "control-generation-sigkill",
      idempotent: false,
    });
    expect(generationSeal(fixture).generation % 2).toBe(0);
    expect(generationSeal(fixture).active_transaction).toBeNull();
  });

  it("rejects a pristine CONTROL retry when the actor was already expired at the sealed boundary", () => {
    const bootstrap = capabilityPath(
      initialize(fixture),
      "bootstrap_capability_file",
    );
    const foremanRegistration = registerRole(
      fixture,
      "FOREMAN",
      "bootstrap-capability-file",
      bootstrap,
      { leaseMs: 2_000 },
    );
    const foreman = capabilityPath(
      foremanRegistration,
      "actor_capability_file",
    );
    const foremanLeaseUntil = String(
      (parse(foremanRegistration).session as { lease_until: string })
        .lease_until,
    );
    const afterExpiry = new Date(
      Date.parse(foremanLeaseUntil) + 1,
    ).toISOString();
    const args = [
      "control",
      "--goal",
      "demo",
      "--expected-epoch",
      "0",
      "--reason",
      "must not launder an expired actor",
      "--instruction-ref",
      "incident://goal-control/expired-boundary",
      "--actor-capability-file",
      foreman,
      "--thread",
      THREADS.FOREMAN,
      "--event-id",
      "control-expired-generation-sigkill",
      "--json",
    ];
    expectCliSigkill(fixture, args, {
      GOAL_CONTROL_NOW: afterExpiry,
      GOAL_CONTROL_TEST_FAULT_AFTER_CONTROL_GENERATION: "sigkill",
    });
    const odd = generationSeal(fixture);
    expect(odd.generation % 2).toBe(1);
    expect(Date.parse(odd.updated_at))
      .toBeGreaterThanOrEqual(Date.parse(foremanLeaseUntil));

    expectError(
      runCli(fixture, args, {
        env: { GOAL_CONTROL_NOW: afterExpiry },
      }),
      "ACTOR_LEASE_EXPIRED",
    );
    const expiredFenced = generationSeal(fixture);
    expect(expiredFenced.generation % 2).toBe(1);
    expect(expiredFenced.generation).toBe(odd.generation);
    expect(expiredFenced).toMatchObject({
      active_transaction: odd.active_transaction,
      pre_write_vector_sha256: odd.pre_write_vector_sha256,
      updated_at: odd.updated_at,
    });
  });

  it("keeps the canonical Git index byte- and metadata-identical across DEV_READY pristine preflight", () => {
    const capabilities = enterDevActive(fixture);
    const evidence = seedEvidenceRegistry(fixture);
    const input = devReadyInput(fixture, evidence);
    const args = [
      "event",
      "--goal",
      "demo",
      "--file",
      input.file,
      "--actor-capability-file",
      capabilities.DEV as string,
      "--json",
    ];
    expectCliSigkill(fixture, args, {
      GOAL_CONTROL_TEST_FAULT_AFTER_EVENT_GENERATION: "sigkill",
    });
    expect(generationSeal(fixture).active_transaction?.kind)
      .toBe("GOAL_EVENT");
    const indexBefore = gitIndexSnapshot(fixture.root);

    const recovered = runCli(fixture, args, {
      env: {
        GIT_OPTIONAL_LOCKS: "1",
        GIT_TERMINAL_PROMPT: "1",
        GCM_INTERACTIVE: "Always",
      },
    });
    if (recovered.code !== 0) {
      throw new Error(recovered.stderr || recovered.stdout);
    }
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      accepted: true,
      idempotent: false,
      event_id: input.event.event_id,
    });
    expect(gitIndexSnapshot(fixture.root)).toEqual(indexBefore);
    expect(generationSeal(fixture).generation % 2).toBe(0);
  });

  it("keeps the canonical Git index byte- and metadata-identical across ARCHIVED pristine preflight", () => {
    const capabilities = enterDevActive(fixture);
    const devReady = devReadyInput(fixture, seedEvidenceRegistry(fixture));
    expect(submitEvent(
      fixture,
      devReady,
      capabilities.DEV,
    ).code).toBe(0);

    const reviewRegistration = registerRole(
      fixture,
      "REVIEW",
      "authorizer-capability-file",
      capabilities.CAPTAIN as string,
    );
    capabilities.REVIEW = capabilityPath(
      reviewRegistration,
      "actor_capability_file",
    );
    seedWorkerLaunch(fixture, parse(reviewRegistration), "REVIEW");
    applyEvent(fixture, capabilities, "LAUNCH_REVIEW", "CAPTAIN", 5, {
      launch_id: "launch-review-1",
    });
    applyEvent(fixture, capabilities, "REVIEW_PASS", "REVIEW", 1, {
      evidence: seedWorkflowEvidence(fixture, "REVIEW", "REVIEW"),
    });

    const receiptRegistration = registerRole(
      fixture,
      "RECEIPT",
      "authorizer-capability-file",
      capabilities.CAPTAIN as string,
    );
    capabilities.RECEIPT = capabilityPath(
      receiptRegistration,
      "actor_capability_file",
    );
    seedWorkerLaunch(fixture, parse(receiptRegistration), "RECEIPT");
    applyEvent(fixture, capabilities, "LAUNCH_RECEIPT", "CAPTAIN", 6, {
      launch_id: "launch-receipt-1",
    });
    applyEvent(fixture, capabilities, "RECEIPT_PASS", "RECEIPT", 1, {
      evidence: seedWorkflowEvidence(fixture, "RECEIPT", "RECEIPT"),
    });
    applyEvent(fixture, capabilities, "READY_FOR_MERGE", "CAPTAIN", 7);
    applyEvent(fixture, capabilities, "MERGED", "FOREMAN", 2, {
      expected_main_head: fixture.baseHead,
      main_merge_sha: fixture.fullHead,
    });

    const archiveInput = eventInput(
      fixture,
      "ARCHIVED",
      "FOREMAN",
      3,
      {
        evidence_id: seedWorkflowEvidence(
          fixture,
          "MERGE_BOUNDARY",
          "FOREMAN",
        ),
      },
    );
    const args = [
      "event",
      "--goal",
      "demo",
      "--file",
      archiveInput.file,
      "--actor-capability-file",
      capabilities.FOREMAN as string,
      "--json",
    ];
    expectCliSigkill(fixture, args, {
      GOAL_CONTROL_TEST_FAULT_AFTER_EVENT_GENERATION: "sigkill",
    });
    expect(generationSeal(fixture).active_transaction?.kind)
      .toBe("GOAL_EVENT");
    const indexBefore = gitIndexSnapshot(fixture.root);

    const recovered = runCli(fixture, args, {
      env: {
        GIT_OPTIONAL_LOCKS: "1",
        GIT_TERMINAL_PROMPT: "1",
        GCM_INTERACTIVE: "Always",
      },
    });
    if (recovered.code !== 0) {
      throw new Error(recovered.stderr || recovered.stdout);
    }
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      accepted: true,
      idempotent: false,
      event_id: archiveInput.event.event_id,
      task: { phase: "ARCHIVED" },
    });
    expect(gitIndexSnapshot(fixture.root)).toEqual(indexBefore);
    expect(generationSeal(fixture).generation % 2).toBe(0);
  });
});
