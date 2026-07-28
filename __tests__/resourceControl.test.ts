import { execFileSync, spawn } from "child_process";
import { createHash, randomUUID } from "crypto";
import {
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
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { createRequire } from "module";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const RESOURCECTL = path.join(ROOT, "scripts", "resourcectl.js");
const nodeRequire = createRequire(import.meta.url);
const {
  assertOwnerCapabilityDisclosureBoundary,
  verifyLease,
} = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "resources.js"),
) as {
  assertOwnerCapabilityDisclosureBoundary: (
    state: Record<string, unknown>,
    resources: Record<string, unknown>,
    lease: Record<string, unknown>,
    now: number,
  ) => unknown;
  verifyLease: (
    cwd: string,
    options: {
      leaseId: string;
      ownerCapabilityFile: string;
      actorCapabilityFile: string;
      resource: string | null;
      eventId: string;
    },
    dependencies?: {
      beforeStableRead?: () => void;
    },
  ) => Record<string, unknown>;
};

type CliResult = { code: number; stdout: string; stderr: string };
type ResourceFixture = {
  root: string;
  controlDir: string;
  productionRoot?: boolean;
  manifest: string;
  packetHash: string;
  planHash: string;
  contextHash: string;
  baseHead: string;
  fullHead: string;
  capabilities: { foreman: string; captain: string; dev: string };
};

function commandEnvironment(
  fixture: ResourceFixture,
  now: string,
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = { ...process.env };
  if (fixture.productionRoot) {
    delete environment.GOAL_CONTROL_DIR;
    delete environment.GOAL_CONTROL_NOW;
    for (const key of Object.keys(environment)) {
      if (key.startsWith("GOAL_CONTROL_TEST_")) delete environment[key];
    }
  } else {
    environment.GOAL_CONTROL_DIR = fixture.controlDir;
    environment.GOAL_CONTROL_NOW = now;
    environment.GOAL_CONTROL_TEST_MODE = "1";
  }
  return environment;
}

function run(
  executable: string,
  args: string[],
  fixture: ResourceFixture,
  now = "2026-07-22T00:00:00.000Z"
): CliResult {
  try {
    const stdout = execFileSync("node", [executable, ...args], {
      cwd: fixture.root,
      encoding: "utf8",
      stdio: "pipe",
      env: commandEnvironment(fixture, now),
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

function runAsync(
  executable: string,
  args: string[],
  fixture: ResourceFixture,
  now = "2026-07-22T00:00:00.000Z"
): Promise<CliResult> {
  return new Promise((resolve) => {
    const child = spawn("node", [executable, ...args], {
      cwd: fixture.root,
      stdio: ["ignore", "pipe", "pipe"],
      env: commandEnvironment(fixture, now),
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const watchdog = setTimeout(() => {
      stderr += "\nTEST_CHILD_TIMEOUT_AFTER_35000MS\n";
      child.kill("SIGKILL");
    }, 35_000);
    watchdog.unref();
    child.on("close", (code) => {
      clearTimeout(watchdog);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" }).trim();
}

function digest(body: string): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function semanticEvidenceSource(
  fixture: ResourceFixture,
  evidenceId: string,
  body: Record<string, unknown>
): { uri: string; source_sha256: string } {
  const directory = path.join(fixture.controlDir, "test-evidence-sources");
  mkdirSync(directory, { recursive: true });
  const file = path.join(directory, `${evidenceId}.json`);
  const serialized = `${JSON.stringify(body, null, 2)}\n`;
  writeFileSync(file, serialized);
  return {
    uri: pathToFileURL(file).href,
    source_sha256: digest(serialized),
  };
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.keys(value as Record<string, unknown>)
      .sort()
      .reduce<Record<string, unknown>>((out, key) => {
        out[key] = canonicalize((value as Record<string, unknown>)[key]);
        return out;
      }, {});
  }
  return value;
}

function objectDigest(value: unknown): string {
  return digest(JSON.stringify(canonicalize(value)));
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

function makeFixture(
  mode: "shadow" | "enforce" = "shadow",
  resourceRoles?: string[],
  productionRoot = false,
): ResourceFixture {
  const root = mkdtempSync(path.join(tmpdir(), "goal-control-resourcectl-test-"));
  const controlDir = productionRoot
    ? path.join(root, ".git", "goal-control", "v1")
    : mkdtempSync(path.join(tmpdir(), "goal-control-resourcectl-state-"));
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.email", "resourcectl@example.test");
  git(root, "config", "user.name", "Resource Control Test");
  writeFileSync(path.join(root, "README.md"), "# resource control fixture\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "base");
  const baseHead = git(root, "rev-parse", "HEAD");

  const goalDir = path.join(root, "docs", "planning", "goals", "demo");
  const packetDir = path.join(goalDir, "packets");
  mkdirSync(packetDir, { recursive: true });
  const aBody = "# TASK-A r1\n";
  const bBody = "# TASK-B r1\n";
  writeFileSync(path.join(packetDir, "TASK-A-r1.md"), aBody);
  writeFileSync(path.join(packetDir, "TASK-B-r1.md"), bBody);
  const issueDir = path.join(root, "docs", "issues", "4242");
  mkdirSync(issueDir, { recursive: true });
  const planBody = "# Resource fixture plan\n";
  const contextBody = "# Resource fixture context\n";
  writeFileSync(path.join(issueDir, "plan.md"), planBody);
  writeFileSync(path.join(issueDir, "context.md"), contextBody);
  const manifest = path.join(goalDir, "manifest.json");
  writeFileSync(
    manifest,
    `${JSON.stringify(
      {
        schema_version: 1,
        goal_id: "demo",
        mode,
        repository: { name_with_owner: "example-org/example-repo", base_branch: "main" },
        base_head: baseHead,
        tasks: [
          {
            id: "TASK-A",
            dependencies: [],
            integration_order: 1,
            packet: {
              revision: 1,
              path: "docs/planning/goals/demo/packets/TASK-A-r1.md",
              sha256: digest(aBody),
            },
            resource_requirements: [
              {
                kind: "PORT",
                id: "8123",
                access: "EXCLUSIVE",
                ...(resourceRoles ? { roles: resourceRoles } : {}),
              },
              {
                kind: "TEST_DATA",
                id: "readonly-fixture",
                access: "SHARED_READ",
                ...(resourceRoles ? { roles: resourceRoles } : {}),
              },
            ],
          },
          {
            id: "TASK-B",
            dependencies: [],
            integration_order: 2,
            packet: {
              revision: 1,
              path: "docs/planning/goals/demo/packets/TASK-B-r1.md",
              sha256: digest(bBody),
            },
            resource_requirements: [
              { kind: "TEST_DATA", id: "task-b-readonly", access: "SHARED_READ" },
            ],
          },
        ],
      },
      null,
      2
    )}\n`
  );
  git(root, "add", ".");
  git(root, "commit", "-qm", "seed goal");

  return {
    root,
    controlDir,
    productionRoot,
    manifest,
    packetHash: digest(aBody),
    planHash: digest(planBody),
    contextHash: digest(contextBody),
    baseHead,
    fullHead: git(root, "rev-parse", "HEAD"),
    capabilities: { foreman: "", captain: "", dev: "" },
  };
}

function resource(
  fixture: ResourceFixture,
  args: string[],
  now?: string
): CliResult {
  const stableOperationCommands = new Set(["renew", "release", "verify"]);
  const withOperationId = stableOperationCommands.has(args[0])
    && !args.includes("--event-id")
    ? [
      ...args,
      "--event-id",
      `test-${args[0]}-${createHash("sha256").update(JSON.stringify(args)).digest("hex").slice(0, 24)}`,
    ]
    : args;
  return run(RESOURCECTL, [...withOperationId, "--json"], fixture, now);
}

function parse(result: CliResult): Record<string, unknown> {
  expect(result.stdout).not.toBe("");
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

function expectError(result: CliResult, code: string): void {
  expect(result.code).not.toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toContain(code);
}

function capabilityFile(result: CliResult, field: string): string {
  if (result.code !== 0) {
    throw new Error(`capability command failed (${result.code}): ${result.stderr || result.stdout}`);
  }
  const file = String(parse(result)[field]);
  expect(file).not.toBe("undefined");
  expect(existsSync(file)).toBe(true);
  expect(statSync(file).mode & 0o777).toBe(0o600);
  return file;
}

function registerRole(
  fixture: ResourceFixture,
  role: "FOREMAN" | "CAPTAIN" | "DEV",
  capabilityFlag: "bootstrap-capability-file" | "authorizer-capability-file",
  capability: string
): string {
  const thread = `${role.toLowerCase()}-task-a`;
  const launchArgs = role === "DEV" ? ["--launch-id", "launch-dev-resource-1"] : [];
  const result = run(
    GOALCTL,
    [
      "register-role",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      role,
      "--thread",
      thread,
      "--host",
      "local",
      "--attempt",
      "1",
      ...launchArgs,
      `--${capabilityFlag}`,
      capability,
      "--json",
    ],
    fixture
  );
  return capabilityFile(result, "actor_capability_file");
}

function initializeRoles(fixture: ResourceFixture): void {
  const initialized = run(
    GOALCTL,
    ["init", "--manifest", fixture.manifest, "--json"],
    fixture
  );
  const bootstrap = capabilityFile(initialized, "bootstrap_capability_file");
  const foreman = registerRole(fixture, "FOREMAN", "bootstrap-capability-file", bootstrap);
  const captain = registerRole(fixture, "CAPTAIN", "authorizer-capability-file", foreman);
  const sequences = { CAPTAIN: 0, FOREMAN: 0 };
  let approvalEventId = "";
  const p1Payload = () => ({
    plan_path: "docs/issues/4242/plan.md",
    plan_sha256: fixture.planHash,
    context_path: "docs/issues/4242/context.md",
    context_sha256: fixture.contextHash,
  });
  const submit = (type: string, role: "CAPTAIN" | "FOREMAN", payload: Record<string, unknown>, fullHead?: string): string => {
    const state = taskState(fixture);
    sequences[role] += 1;
    const eventId = `${type.toLowerCase()}-${randomUUID()}`;
    const event = {
      schema_version: 1,
      event_id: eventId,
      goal_id: "demo",
      task_id: "TASK-A",
      type,
      actor: { role, thread_id: `${role.toLowerCase()}-task-a`, host_id: "local" },
      actor_sequence: sequences[role],
      expected_state_revision: state.state_revision,
      control_epoch: state.control_epoch,
      packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
      base_head: state.base_head,
      full_head: fullHead ?? state.full_head,
      payload,
    };
    const file = path.join(fixture.controlDir, `${eventId}.json`);
    writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);
    const accepted = run(GOALCTL, [
      "event", "--goal", "demo", "--file", file,
      "--actor-capability-file", role === "CAPTAIN" ? captain : foreman, "--json",
    ], fixture);
    if (accepted.code !== 0) throw new Error(`${type} failed: ${accepted.stderr || accepted.stdout}`);
    return eventId;
  };
  submit("START_P1", "CAPTAIN", {});
  submit("P1_READY", "CAPTAIN", p1Payload());
  approvalEventId = submit("P1_APPROVED", "FOREMAN", {
    ...p1Payload(),
    approval_ref: "user://issue-4242/approved",
  });
  submit("P1_COMMITTED", "CAPTAIN", {
    ...p1Payload(),
    approval_event_id: approvalEventId,
  }, fixture.fullHead);
  const dev = registerRole(fixture, "DEV", "authorizer-capability-file", captain);
  fixture.capabilities = { foreman, captain, dev };
}

function launchDev(
  fixture: ResourceFixture,
  resourceLeaseIds: string[],
): string {
  const state = taskState(fixture);
  const launchDir = path.join(
    fixture.controlDir,
    "goals",
    "demo",
    "launches",
    "TASK-A",
  );
  mkdirSync(launchDir, { recursive: true });
  const launchFile = path.join(launchDir, "launch-dev-resource-1.json");
  writeFileSync(launchFile, `${JSON.stringify({
    schema_version: 1,
    launch_id: "launch-dev-resource-1",
    goal_id: "demo",
    task_id: "TASK-A",
    role: "DEV",
    control_epoch: state.control_epoch,
    state_revision: state.sessions.DEV.registered_state_revision,
    thread: { id: "dev-task-a", host_id: "local", cwd: fixture.root },
    packet: {
      revision: state.packet.revision,
      path: "docs/planning/goals/demo/packets/TASK-A-r1.md",
      sha256: state.packet.sha256,
    },
    repository: {
      name_with_owner: "example-org/example-repo",
      origin_url: "https://github.com/example-org/example-repo.git",
      base_branch: "main",
      base_head: state.base_head,
      full_head: state.full_head,
      branch: "main",
      root: fixture.root,
      worktree: fixture.root,
    },
    runtime: {
      node_version: process.version,
      pnpm_version: "10.0.0-test",
      lockfile_sha256: `sha256:${"c".repeat(64)}`,
    },
    execution: {
      environment: "none",
      write_mode: "NONE",
      task_nonce: state.sessions.DEV.task_nonce,
      target: { kind: "NONE" },
    },
    resource_leases: resourceLeaseIds,
    created_at: "2026-07-22T00:00:00.000Z",
  }, null, 2)}\n`);

  const eventId = `launch_dev-${randomUUID()}`;
  const eventFile = path.join(fixture.controlDir, `${eventId}.json`);
  writeFileSync(eventFile, `${JSON.stringify({
    schema_version: 1,
    event_id: eventId,
    goal_id: "demo",
    task_id: "TASK-A",
    type: "LAUNCH_DEV",
    actor: {
      role: "CAPTAIN",
      thread_id: "captain-task-a",
      host_id: "local",
    },
    actor_sequence: 4,
    expected_state_revision: state.state_revision,
    control_epoch: state.control_epoch,
    packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
    base_head: state.base_head,
    full_head: state.full_head,
    payload: { launch_id: "launch-dev-resource-1" },
  }, null, 2)}\n`);
  const launched = run(GOALCTL, [
    "event",
    "--goal", "demo",
    "--file", eventFile,
    "--actor-capability-file", fixture.capabilities.captain,
    "--json",
  ], fixture);
  if (launched.code !== 0) {
    throw new Error(`LAUNCH_DEV failed: ${launched.stderr || launched.stdout}`);
  }
  expect(taskState(fixture).phase).toBe("DEV_ACTIVE");
  return launchFile;
}

function seedRoleFailureEvidence(
  fixture: ResourceFixture,
  lease: { lease_id: string; resource: string; revision: number }
): string {
  const evidenceId = `resource-role-failure-${randomUUID()}`;
  const state = taskState(fixture);
  const dir = path.join(fixture.controlDir, "goals", "demo", "evidence", "TASK-A");
  mkdirSync(dir, { recursive: true });
  const source = semanticEvidenceSource(fixture, evidenceId, {
    kind: "ROLE_FAILURE",
    lease_id: lease.lease_id,
    resource: lease.resource,
    isolated: true,
  });
  const record: Record<string, unknown> = {
    schema_version: 1,
    evidence_id: evidenceId,
    goal_id: "demo",
    task_id: "TASK-A",
    kind: "ROLE_FAILURE",
    status: "FAIL",
    producer: { role: "CAPTAIN", thread_id: "captain-task-a", host_id: "local" },
    state_revision: state.state_revision,
    packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
    packet_sha256: state.packet.sha256,
    base_head: state.base_head,
    full_head: state.full_head,
    created_at: "2026-07-22T00:00:02.000Z",
    ...source,
    resource_lease: {
      lease_id: lease.lease_id,
      resource: lease.resource,
      revision: lease.revision,
      owner: {
        goal_id: "demo",
        task_id: "TASK-A",
        role: "DEV",
        thread_id: "dev-task-a",
        host_id: "local",
      },
      isolated: true,
      isolation_ref: `test://isolated/${lease.lease_id}`,
    },
  };
  record.registry_sha256 = objectDigest(record);
  writeFileSync(path.join(dir, `${evidenceId}.json`), `${JSON.stringify(record, null, 2)}\n`);
  return evidenceId;
}

function reportDevLost(fixture: ResourceFixture, evidenceId: string): void {
  const state = taskState(fixture);
  const dev = state.sessions.DEV;
  const event = {
    schema_version: 1,
    event_id: `role-lost-${randomUUID()}`,
    goal_id: "demo",
    task_id: "TASK-A",
    type: "ROLE_LOST",
    actor: { role: "CAPTAIN", thread_id: "captain-task-a", host_id: "local" },
    actor_sequence: 4,
    expected_state_revision: state.state_revision,
    control_epoch: state.control_epoch,
    packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
    base_head: state.base_head,
    full_head: state.full_head,
    payload: {
      role: "DEV",
      reason: "worker process disappeared",
      attempts: 1,
      evidence_id: evidenceId,
      expected_thread_id: dev.thread_id,
      expected_host_id: dev.host_id,
      expected_attempt: dev.attempt,
      expected_lease_until: dev.lease_until,
    },
  };
  const file = path.join(fixture.controlDir, `role-lost-${randomUUID()}.json`);
  writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);
  const accepted = run(GOALCTL, [
    "event", "--goal", "demo", "--file", file,
    "--actor-capability-file", fixture.capabilities.captain, "--json",
  ], fixture);
  if (accepted.code !== 0) throw new Error(`ROLE_LOST failed: ${accepted.stderr || accepted.stdout}`);
}

type TaskState = {
  phase: string;
  state_revision: number;
  control_epoch: number;
  packet: { revision: number; sha256: string };
  base_head: string;
  full_head: string;
  holds: Array<{ kind: string; hard: boolean }>;
  sessions: {
    DEV: {
      thread_id: string;
      host_id: string;
      attempt: number;
      task_nonce: string;
      registered_state_revision: number;
      lease_until: string;
    };
  };
};

function taskState(fixture: ResourceFixture): TaskState {
  const result = run(
    GOALCTL,
    ["status", "--goal", "demo", "--task", "TASK-A", "--json"],
    fixture
  );
  expect(result.code).toBe(0);
  return (JSON.parse(result.stdout) as { tasks: { "TASK-A": TaskState } }).tasks["TASK-A"];
}

type ResourceRenewRequest = {
  type: "REQUEST_RESOURCE_RENEW";
  actor_role: "CAPTAIN";
  requested_action: "RENEW_RESOURCE";
  dispatch: {
    coordinator_role: "CAPTAIN";
    executor_binding: "EXACT_RESOURCE_OWNER";
    executor: {
      role: "DEV" | "REVIEW" | "RECEIPT";
      thread_id: string;
      host_id: string;
    };
    capability_mode: "EXACT_OWNER_DUAL_CAPABILITY";
  };
  event_id: string;
  lease_id: string;
  resource: string;
  expected_revision: number;
  ttl_ms: number;
  expires_at: string;
  renewal_window_ms: number;
  owner: {
    role: "DEV" | "REVIEW" | "RECEIPT";
    thread_id: string;
    host_id: string;
  };
};

function resourceRenewRequests(
  fixture: ResourceFixture,
  now: string
): ResourceRenewRequest[] {
  const result = run(
    GOALCTL,
    ["status", "--goal", "demo", "--task", "TASK-A", "--json"],
    fixture,
    now
  );
  expect(result.code).toBe(0);
  const task = (
    JSON.parse(result.stdout) as {
      tasks: {
        "TASK-A": { maintenance_actions: Array<Record<string, unknown>> };
      };
    }
  ).tasks["TASK-A"];
  return task.maintenance_actions.filter(
    (action) => action.type === "REQUEST_RESOURCE_RENEW"
  ) as ResourceRenewRequest[];
}

function addHardHold(fixture: ResourceFixture): void {
  const state = taskState(fixture);
  const evidenceId = `resource-hard-hold-${randomUUID()}`;
  const evidenceDir = path.join(fixture.controlDir, "goals", "demo", "evidence", "TASK-A");
  mkdirSync(evidenceDir, { recursive: true });
  const source = semanticEvidenceSource(fixture, evidenceId, {
    kind: "HOLD_ASSERTION",
    reason: "resource containment test",
  });
  const record: Record<string, unknown> = {
    schema_version: 1,
    evidence_id: evidenceId,
    goal_id: "demo",
    task_id: "TASK-A",
    kind: "HOLD_ASSERTION",
    status: "BLOCKED",
    producer: { role: "CAPTAIN", thread_id: "captain-task-a", host_id: "local" },
    state_revision: state.state_revision,
    packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
    packet_sha256: state.packet.sha256,
    base_head: state.base_head,
    full_head: state.full_head,
    created_at: "2026-07-22T00:00:00.000Z",
    ...source,
  };
  record.registry_sha256 = objectDigest(record);
  writeFileSync(path.join(evidenceDir, `${evidenceId}.json`), `${JSON.stringify(record, null, 2)}\n`);
  const event = {
    schema_version: 1,
    event_id: `hard-hold-${randomUUID()}`,
    goal_id: "demo",
    task_id: "TASK-A",
    type: "ADD_HOLD",
    actor: { role: "CAPTAIN", thread_id: "captain-task-a", host_id: "local" },
    actor_sequence: 4,
    expected_state_revision: state.state_revision,
    control_epoch: state.control_epoch,
    packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
    base_head: state.base_head,
    full_head: state.full_head,
    payload: {
      kind: "BLOCKED_SECURITY",
      hold_id: "resource-security-hold",
      reason: "resource containment test",
      evidence_id: evidenceId,
    },
  };
  const file = path.join(fixture.controlDir, `hard-hold-${randomUUID()}.json`);
  writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);
  const accepted = run(
    GOALCTL,
    [
      "event",
      "--goal",
      "demo",
      "--file",
      file,
      "--actor-capability-file",
      fixture.capabilities.captain,
      "--json",
    ],
    fixture
  );
  if (accepted.code !== 0) throw new Error(`hard hold failed: ${accepted.stderr || accepted.stdout}`);
}

function addIdentityIncidentHardHold(
  fixture: ResourceFixture,
  lease: { lease_id: string },
  now = "2026-07-22T00:00:00.000Z",
): void {
  expectError(
    resource(fixture, [
      "verify",
      "--lease", lease.lease_id,
      "--owner-capability-file", fixture.capabilities.captain,
      "--actor-capability-file", fixture.capabilities.dev,
      "--event-id", `resource-identity-incident-${randomUUID()}`,
    ], now),
    "LEASE_OWNER_MISMATCH",
  );
  expect(taskState(fixture).holds).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ kind: "ENV_IDENTITY_INCIDENT", hard: true }),
    ]),
  );
}

function acquire(
  fixture: ResourceFixture,
  task: "TASK-A" = "TASK-A",
  now = "2026-07-22T00:00:00.000Z",
  ttl = 60_000,
  resourceKey = "preview-port:8123",
  access = "EXCLUSIVE"
): CliResult {
  return resource(
    fixture,
    [
      "acquire",
      "--goal",
      "demo",
      "--task",
      task,
      "--role",
      "DEV",
      "--thread",
      "dev-task-a",
      "--host",
      "local",
      "--resource",
      resourceKey,
      "--access",
      access,
      "--ttl-ms",
      String(ttl),
      "--event-id",
      `resource-acquire-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities.dev,
    ],
    now
  );
}

describe("owner capability hard-hold disclosure boundary", () => {
  const makeBoundary = (
    access: "EXCLUSIVE" | "SHARED_READ" = "EXCLUSIVE",
  ) => {
    const owner = {
      goal_id: "demo",
      task_id: "TASK-A",
      role: "DEV",
      thread_id: "dev-task-a",
      host_id: "local",
    };
    const lease = {
      lease_id: "lease-current",
      resource: access === "SHARED_READ"
        ? "test-data:readonly-fixture"
        : "preview-port:8123",
      access,
      owner,
      owner_capability_file: "/tmp/owner-current.cap",
      owner_capability_sha256: "a".repeat(64),
      revision: 1,
      fencing_token: 1,
      status: "ACTIVE",
      updated_at: "2026-07-22T00:00:00.000Z",
      expires_at: "2026-07-22T01:00:00.000Z",
    };
    const state = {
      task_id: "TASK-A",
      state_revision: 10,
      phase: "DEV_ACTIVE",
      holds: [{
        hold_id: "env-hold-runtime",
        kind: "ENV_IDENTITY_INCIDENT",
        hard: true,
      }],
      sessions: {
        DEV: {
          role: "DEV",
          thread_id: "dev-task-a",
          host_id: "local",
          attempt: 1,
          launch_id: "launch-dev-runtime",
          status: "active",
          lease_until: "2026-07-22T04:00:00.000Z",
          capability_file: "/tmp/dev.cap",
          capability_sha256: "b".repeat(64),
        },
      },
    };
    const resources = {
      event_count: 1,
      fencing_tokens: { [lease.resource]: 1 },
      leases: { [lease.lease_id]: lease },
    };
    return { state, resources, lease };
  };

  it("rejects disclosure before the exact renewal window", () => {
    const { state, resources, lease } = makeBoundary();
    expect(() => assertOwnerCapabilityDisclosureBoundary(
      state,
      resources,
      lease,
      Date.parse("2026-07-22T00:44:59.999Z"),
    )).toThrow(expect.objectContaining({
      code: "RESOURCE_RENEW_NOT_DUE",
    }));
  });

  it("rejects a lease whose fencing token was superseded inside the window", () => {
    const { state, resources, lease } = makeBoundary();
    (resources.fencing_tokens as Record<string, number>)[lease.resource] = 2;
    expect(() => assertOwnerCapabilityDisclosureBoundary(
      state,
      resources,
      lease,
      Date.parse("2026-07-22T00:45:00.000Z"),
    )).toThrow(expect.objectContaining({
      code: "RESOURCE_EXPIRY_RECOVERY_FENCED",
    }));
  });

  it("rejects current shared fencing while another owner is still active", () => {
    const { state, resources, lease } = makeBoundary("SHARED_READ");
    const competing = {
      ...lease,
      lease_id: "lease-competing",
      owner: {
        ...lease.owner,
        task_id: "TASK-B",
        thread_id: "dev-task-b",
      },
    };
    (resources.leases as Record<string, unknown>)[
      competing.lease_id
    ] = competing;
    expect(() => assertOwnerCapabilityDisclosureBoundary(
      state,
      resources,
      lease,
      Date.parse("2026-07-22T00:45:00.000Z"),
    )).toThrow(expect.objectContaining({
      code: "RESOURCE_EXPIRY_RECOVERY_FENCED",
    }));
  });
});

describe("scripts/resourcectl.js", () => {
  let fixture: ResourceFixture;

  beforeEach(() => {
    fixture = makeFixture();
    initializeRoles(fixture);
  });

  afterEach(() => {
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGING_DIRECTORY;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGED_INTENT;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_EMPTY_STAGING_CLEANUP;
    delete process.env.GOAL_CONTROL_TEST_ACQUIRE_NOW_AFTER_BOUNDARY;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_INCIDENT_EVIDENCE;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_INGRESS_PREPARED;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_EVENT_INSTALL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_COMMIT;
    delete process.env.GOAL_CONTROL_TEST_FAULT_RESOURCE_CAP_CLEANUP;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_ACQUIRE_GENERATION;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_RENEW_GENERATION;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_RELEASE_GENERATION;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ZERO_RUNTIME_GENERATION;
    delete process.env
      .GOAL_CONTROL_TEST_FAULT_RESOURCE_ACQUIRE_INTENT_AFTER_ATOMIC_TEMP_CREATE;
    delete process.env.GOAL_CONTROL_TEST_LEGACY_RESOURCE_ROLE_DEFAULT;
    rmSync(fixture.root, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
  });

  it("grants one exclusive lease through 0600 capabilities and rejects a conflict", () => {
    const first = acquire(fixture, "TASK-A");
    expect(first.code).toBe(0);
    const lease = parse(first) as {
      lease_id: string;
      owner_capability_file: string;
      revision: number;
      fencing_token: number;
      status: string;
      expires_at: string;
    };
    expect(lease).toMatchObject({ revision: 1, fencing_token: 1, status: "ACTIVE" });
    expect(lease.lease_id).toBeTruthy();
    expect(existsSync(lease.owner_capability_file)).toBe(true);
    expect(statSync(lease.owner_capability_file).mode & 0o777).toBe(0o600);
    const rawCapability = readFileSync(lease.owner_capability_file, "utf8").trim();
    expect(first.stdout).not.toContain(rawCapability);
    const ledgerText = readdirSync(path.join(fixture.controlDir, "resources", "events"))
      .map((name) => readFileSync(path.join(fixture.controlDir, "resources", "events", name), "utf8"))
      .join("\n");
    expect(ledgerText).not.toContain(rawCapability);

    expectError(acquire(fixture, "TASK-A"), "RESOURCE_CONFLICT");

    const verified = resource(fixture, [
      "verify",
      "--lease",
      lease.lease_id,
      "--owner-capability-file",
      lease.owner_capability_file,
      "--actor-capability-file",
      fixture.capabilities.dev,
      "--resource",
      "preview-port:8123",
    ]);
    expect(verified.code).toBe(0);
    expect(parse(verified)).toMatchObject({ status: "ACTIVE", revision: 1, fencing_token: 1 });

    expectError(
      resource(fixture, [
        "verify",
        "--lease",
        lease.lease_id,
        "--owner-capability-file",
        fixture.capabilities.captain,
        "--actor-capability-file",
        fixture.capabilities.dev,
      ]),
      "LEASE_OWNER_MISMATCH"
    );
    expect(taskState(fixture).holds).toEqual(
      expect.arrayContaining([expect.objectContaining({ kind: "ENV_IDENTITY_INCIDENT", hard: true })])
    );
  });

  it("runs resource writers on the repository control root without test hooks", () => {
    const productionFixture = makeFixture("shadow", undefined, true);
    try {
      initializeRoles(productionFixture);
      const acquiredResult = acquire(
        productionFixture,
        "TASK-A",
        undefined,
        60 * 60 * 1000,
      );
      expect(acquiredResult.code).toBe(0);
      const acquired = parse(acquiredResult) as {
        lease_id: string;
        owner_capability_file: string;
        revision: number;
        status: string;
      };
      expect(acquired).toMatchObject({ revision: 1, status: "ACTIVE" });
      expect(path.relative(
        realpathSync(productionFixture.controlDir),
        realpathSync(acquired.owner_capability_file),
      ).startsWith("..")).toBe(false);

      const verified = resource(productionFixture, [
        "verify",
        "--lease", acquired.lease_id,
        "--owner-capability-file", acquired.owner_capability_file,
        "--actor-capability-file", productionFixture.capabilities.dev,
      ]);
      expect(verified.code).toBe(0);
      expect(parse(verified)).toMatchObject({
        lease_id: acquired.lease_id,
        revision: 1,
        status: "ACTIVE",
      });

      const released = resource(productionFixture, [
        "release",
        "--lease", acquired.lease_id,
        "--owner-capability-file", acquired.owner_capability_file,
        "--actor-capability-file", productionFixture.capabilities.dev,
        "--expected-revision", "1",
      ]);
      expect(released.code).toBe(0);
      expect(parse(released)).toMatchObject({
        lease_id: acquired.lease_id,
        revision: 2,
        status: "RELEASED",
      });
      const generation = JSON.parse(readFileSync(
        path.join(productionFixture.controlDir, ".generation.json"),
        "utf8",
      )) as { generation: number; active_transaction: unknown };
      expect(generation.generation % 2).toBe(0);
      expect(generation.active_transaction).toBeNull();
    } finally {
      rmSync(productionFixture.root, { recursive: true, force: true });
    }
  });

  it("reuses the deterministic acquire identity after first-witness SIGKILL", () => {
    const eventId = `resource-acquire-first-witness-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env
      .GOAL_CONTROL_TEST_FAULT_RESOURCE_ACQUIRE_INTENT_AFTER_ATOMIC_TEMP_CREATE =
      "sigkill";
    expect(resource(fixture, args).code).not.toBe(0);
    delete process.env
      .GOAL_CONTROL_TEST_FAULT_RESOURCE_ACQUIRE_INTENT_AFTER_ATOMIC_TEMP_CREATE;

    const recoveredResult = resource(fixture, args);
    const recovered = parse(recoveredResult) as {
      lease_id: string;
      idempotent: boolean;
    };
    expect(recovered.lease_id).toMatch(/^lease-[0-9a-f]{24}$/);
    expect(recovered.idempotent).toBe(false);
    const intent = JSON.parse(readFileSync(path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      eventId,
      "intent.json",
    ), "utf8")) as {
      created_at: string;
      lease_template: { lease_id: string };
    };
    expect(intent.created_at).toBe("2026-07-22T00:00:00.000Z");
    expect(intent.lease_template.lease_id).toBe(recovered.lease_id);

    expect(parse(resource(fixture, args))).toMatchObject({
      lease_id: recovered.lease_id,
      idempotent: true,
    });
  });

  it("aborts pristine acquire and renew transactions before one fresh retry", () => {
    const acquireEventId = `resource-acquire-pristine-${randomUUID()}`;
    const acquireArgs = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", String(60 * 60 * 1000),
      "--event-id", acquireEventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_ACQUIRE_GENERATION =
      "throw";
    expectError(
      resource(fixture, acquireArgs),
      "TEST_FAULT_AFTER_RESOURCE_GENERATION",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_ACQUIRE_GENERATION;
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const acquireOdd = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: { kind: string } };
    expect(acquireOdd.generation % 2).toBe(1);
    expect(acquireOdd.active_transaction.kind).toBe("RESOURCE_ACQUIRE");

    const acquired = resource(fixture, acquireArgs);
    expect(acquired.code).toBe(0);
    const lease = parse(acquired) as {
      lease_id: string;
      owner_capability_file: string;
      revision: number;
      idempotent: boolean;
    };
    expect(lease).toMatchObject({ revision: 1, idempotent: false });
    const acquireEven = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: null };
    // +1 directly closes the exact old odd and +2 is the deterministic
    // resource projection/cache transaction.
    expect(acquireEven.generation).toBe(acquireOdd.generation + 3);
    expect(acquireEven.active_transaction).toBeNull();

    const renewal = resourceRenewRequests(
      fixture,
      "2026-07-22T00:45:00.000Z",
    )[0];
    const renewArgs = [
      "renew",
      "--lease", lease.lease_id,
      "--owner-capability-file", lease.owner_capability_file,
      "--actor-capability-file", fixture.capabilities.dev,
      "--expected-revision", "1",
      "--ttl-ms", String(renewal.ttl_ms),
      "--event-id", renewal.event_id,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_RENEW_GENERATION =
      "throw";
    expectError(
      resource(fixture, renewArgs, "2026-07-22T00:45:00.000Z"),
      "TEST_FAULT_AFTER_RESOURCE_GENERATION",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_RENEW_GENERATION;
    const renewOdd = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: { kind: string } };
    expect(renewOdd.generation % 2).toBe(1);
    expect(renewOdd.active_transaction.kind).toBe("RESOURCE_RENEW");

    expect(parse(resource(
      fixture,
      renewArgs,
      "2026-07-22T00:45:00.000Z",
    ))).toMatchObject({
      lease_id: lease.lease_id,
      revision: 2,
      idempotent: false,
    });
    const renewEven = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: null };
    expect(renewEven.generation).toBe(renewOdd.generation + 3);
    expect(renewEven.active_transaction).toBeNull();
  });

  it("resumes pristine release at its sealed start time after actor expiry", () => {
    const acquired = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60_000,
    )) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const releaseEventId = `resource-release-pristine-${randomUUID()}`;
    const releaseArgs = [
      "release",
      "--lease", acquired.lease_id,
      "--owner-capability-file", acquired.owner_capability_file,
      "--actor-capability-file", fixture.capabilities.dev,
      "--expected-revision", "1",
      "--event-id", releaseEventId,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_RELEASE_GENERATION =
      "throw";
    expectError(
      resource(fixture, releaseArgs, "2026-07-22T00:00:00.000Z"),
      "TEST_FAULT_AFTER_RESOURCE_GENERATION",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_RELEASE_GENERATION;
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const odd = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as {
      generation: number;
      active_transaction: { kind: string };
      updated_at: string;
    };
    expect(odd.generation % 2).toBe(1);
    expect(odd.active_transaction.kind).toBe("RESOURCE_RELEASE");
    expect(odd.updated_at).toBe("2026-07-22T00:00:00.000Z");

    expect(parse(resource(
      fixture,
      releaseArgs,
      "2026-07-22T02:00:00.000Z",
    ))).toMatchObject({
      lease_id: acquired.lease_id,
      status: "RELEASED",
      revision: 2,
      idempotent: false,
    });
    const even = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: null };
    // Exact release resumes and closes the old odd in one step.
    expect(even.generation).toBe(odd.generation + 1);
    expect(even.active_transaction).toBeNull();
  });

  it("projects a deterministic renewal request only inside the lease renewal window and exact-retries it", () => {
    const acquired = acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60 * 60 * 1000,
    );
    expect(acquired.code).toBe(0);
    const lease = parse(acquired) as {
      lease_id: string;
      owner_capability_file: string;
      revision: number;
      expires_at: string;
    };
    expect(resourceRenewRequests(
      fixture,
      "2026-07-22T00:44:59.999Z",
    )).toEqual([]);

    const requests = resourceRenewRequests(
      fixture,
      "2026-07-22T00:45:00.000Z",
    );
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({
      type: "REQUEST_RESOURCE_RENEW",
      actor_role: "CAPTAIN",
      requested_action: "RENEW_RESOURCE",
      dispatch: {
        coordinator_role: "CAPTAIN",
        executor_binding: "EXACT_RESOURCE_OWNER",
        executor: {
          role: "DEV",
          thread_id: "dev-task-a",
          host_id: "local",
        },
        capability_mode: "EXACT_OWNER_DUAL_CAPABILITY",
      },
      event_id: expect.stringMatching(
        /^resource-renew-[0-9a-f]{32}-r1$/,
      ),
      lease_id: lease.lease_id,
      resource: "preview-port:8123",
      expected_revision: 1,
      ttl_ms: 60 * 60 * 1000,
      expires_at: "2026-07-22T01:00:00.000Z",
      renewal_window_ms: 15 * 60 * 1000,
      owner: {
        role: "DEV",
        thread_id: "dev-task-a",
        host_id: "local",
      },
    });
    expect(resourceRenewRequests(
      fixture,
      "2026-07-22T00:45:00.000Z",
    )).toEqual(requests);

    const renewalArgs = [
      "renew",
      "--lease", lease.lease_id,
      "--owner-capability-file", lease.owner_capability_file,
      "--actor-capability-file", fixture.capabilities.dev,
      "--expected-revision", String(requests[0].expected_revision),
      "--ttl-ms", String(requests[0].ttl_ms),
      "--event-id", requests[0].event_id,
    ];
    const beforeRejectedCoordinatorExecution = exactControlTree(
      fixture.controlDir,
    );
    expectError(
      resource(
        fixture,
        [
          ...renewalArgs.slice(
            0,
            renewalArgs.indexOf("--actor-capability-file") + 1,
          ),
          fixture.capabilities.captain,
          ...renewalArgs.slice(
            renewalArgs.indexOf("--actor-capability-file") + 2,
          ),
        ],
        "2026-07-22T00:45:00.000Z",
      ),
      "CAPABILITY_INVALID",
    );
    expect(exactControlTree(fixture.controlDir)).toEqual(
      beforeRejectedCoordinatorExecution,
    );
    expectError(
      resource(
        fixture,
        renewalArgs,
        "2026-07-22T00:44:59.999Z",
      ),
      "RESOURCE_RENEW_NOT_DUE",
    );
    expectError(
      resource(
        fixture,
        [
          ...renewalArgs.slice(0, renewalArgs.indexOf("--event-id")),
          "--event-id", `resource-renew-unprojected-${randomUUID()}`,
        ],
        "2026-07-22T00:45:00.000Z",
      ),
      "RESOURCE_RENEW_EVENT_ID_MISMATCH",
    );
    for (const invalidTtl of [
      String(requests[0].ttl_ms - 1),
      String(requests[0].ttl_ms + 1),
    ]) {
      const mismatchedTtl = [...renewalArgs];
      mismatchedTtl[mismatchedTtl.indexOf("--ttl-ms") + 1] = invalidTtl;
      expectError(
        resource(
          fixture,
          mismatchedTtl,
          "2026-07-22T00:45:00.000Z",
        ),
        "RESOURCE_RENEW_TTL_MISMATCH",
      );
    }
    const renewed = resource(
      fixture,
      renewalArgs,
      "2026-07-22T00:45:00.000Z",
    );
    expect(renewed.code).toBe(0);
    expect(parse(renewed)).toMatchObject({
      lease_id: lease.lease_id,
      revision: 2,
      expires_at: "2026-07-22T01:45:00.000Z",
      idempotent: false,
    });
    expect(parse(resource(
      fixture,
      renewalArgs,
      "2026-07-22T00:45:00.000Z",
    ))).toMatchObject({
      lease_id: lease.lease_id,
      revision: 2,
      expires_at: "2026-07-22T01:45:00.000Z",
      idempotent: true,
    });
    expectError(
      resource(
        fixture,
        [
          "renew",
          "--lease", lease.lease_id,
          "--owner-capability-file", lease.owner_capability_file,
          "--actor-capability-file", fixture.capabilities.dev,
          "--expected-revision", "2",
          "--ttl-ms", String(requests[0].ttl_ms),
          "--event-id", `resource-renew-repeat-${randomUUID()}`,
        ],
        "2026-07-22T00:45:00.000Z",
      ),
      "RESOURCE_RENEW_NOT_DUE",
    );
    expect(resourceRenewRequests(
      fixture,
      "2026-07-22T00:45:00.000Z",
    )).toEqual([]);

    const released = resource(
      fixture,
      [
        "release",
        "--lease", lease.lease_id,
        "--owner-capability-file", lease.owner_capability_file,
        "--actor-capability-file", fixture.capabilities.dev,
        "--expected-revision", "2",
        "--event-id", `resource-release-${randomUUID()}`,
      ],
      "2026-07-22T00:45:00.000Z",
    );
    expect(released.code).toBe(0);
    expect(resourceRenewRequests(
      fixture,
      "2026-07-22T01:30:00.000Z",
    )).toEqual([]);
  });

  it("does not project renewal while the task is hard-held", () => {
    const hardHeld = acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60 * 60 * 1000,
    );
    expect(hardHeld.code).toBe(0);
    addHardHold(fixture);
    expect(resourceRenewRequests(
      fixture,
      "2026-07-22T00:45:00.000Z",
    )).toEqual([]);
  });

  it("does not project renewal for a lost owner or after its lease expires", () => {
    const lost = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60 * 60 * 1000,
    )) as {
      lease_id: string;
      resource: string;
      revision: number;
    };
    reportDevLost(fixture, seedRoleFailureEvidence(fixture, lost));
    expect(resourceRenewRequests(
      fixture,
      "2026-07-22T00:45:00.000Z",
    )).toEqual([]);
    expect(resourceRenewRequests(
      fixture,
      "2026-07-22T01:00:00.000Z",
    )).toEqual([]);
  });

  it("preserves the owner capability and exact-retries after the resource event installs before its head", () => {
    const eventId = `resource-acquire-fault-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_EVENT_INSTALL = "1";
    const interrupted = resource(fixture, args);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_EVENT_INSTALL;
    expectError(interrupted, "TEST_FAULT_AFTER_RESOURCE_EVENT_INSTALL");

    const resourceEvents = readdirSync(
      path.join(fixture.controlDir, "resources", "events"),
    ).map((name) => JSON.parse(readFileSync(
      path.join(fixture.controlDir, "resources", "events", name),
      "utf8",
    )));
    const installed = resourceEvents.find((event) => event.event_id === eventId);
    expect(installed).toBeDefined();
    expect(existsSync(installed.lease.owner_capability_file)).toBe(true);
    const oddAcquireTree = exactControlTree(fixture.controlDir);
    const wrongAcquire = [...args];
    wrongAcquire[wrongAcquire.indexOf("--ttl-ms") + 1] = "120000";
    expectError(resource(fixture, wrongAcquire), "RESOURCE_EVENT_ID_CONFLICT");
    expect(exactControlTree(fixture.controlDir)).toEqual(oddAcquireTree);
    const wrongAcquireCapability = [...args];
    wrongAcquireCapability[
      wrongAcquireCapability.indexOf("--actor-capability-file") + 1
    ] = fixture.capabilities.captain;
    expectError(
      resource(fixture, wrongAcquireCapability),
      "CAPABILITY_INVALID",
    );
    expect(exactControlTree(fixture.controlDir)).toEqual(oddAcquireTree);

    const retried = resource(fixture, args);
    if (retried.code !== 0) {
      throw new Error(`exact acquire retry failed: ${retried.stderr || retried.stdout}`);
    }
    expect(retried.code).toBe(0);
    const lease = parse(retried) as {
      lease_id: string;
      owner_capability_file: string;
      idempotent: boolean;
    };
    expect(lease).toMatchObject({
      lease_id: installed.lease.lease_id,
      owner_capability_file: installed.lease.owner_capability_file,
      idempotent: true,
    });
    const renewalRequest = resourceRenewRequests(
      fixture,
      "2026-07-22T00:00:45.000Z",
    )[0];
    const renewed = resource(fixture, [
      "renew",
      "--lease", lease.lease_id,
      "--owner-capability-file", lease.owner_capability_file,
      "--actor-capability-file", fixture.capabilities.dev,
      "--expected-revision", "1",
      "--ttl-ms", String(renewalRequest.ttl_ms),
      "--event-id", renewalRequest.event_id,
    ], "2026-07-22T00:00:45.000Z");
    expect(renewed.code).toBe(0);
    expect(parse(resource(fixture, args))).toMatchObject({
      lease_id: lease.lease_id,
      status: "ACTIVE",
      revision: 2,
      idempotent: true,
    });
    process.env.GOAL_CONTROL_TEST_FAULT_RESOURCE_CAP_CLEANUP = "1";
    const released = resource(fixture, [
      "release",
      "--lease", lease.lease_id,
      "--owner-capability-file", lease.owner_capability_file,
      "--actor-capability-file", fixture.capabilities.dev,
      "--expected-revision", "2",
    ]);
    delete process.env.GOAL_CONTROL_TEST_FAULT_RESOURCE_CAP_CLEANUP;
    expect(released.code).toBe(0);
    expect(existsSync(lease.owner_capability_file)).toBe(true);
    expect(parse(resource(fixture, args))).toMatchObject({
      lease_id: lease.lease_id,
      status: "RELEASED",
      revision: 3,
      owner_capability_file: lease.owner_capability_file,
      idempotent: true,
    });
  });

  it("exact-retries one sealed acquire intent after response loss without minting a second lease", () => {
    const eventId = `resource-acquire-intent-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT = "1";
    expectError(
      resource(fixture, args),
      "TEST_FAULT_AFTER_ACQUIRE_INTENT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT;

    const intentDirectory = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      eventId,
    );
    expect(readdirSync(intentDirectory)).toEqual(["intent.json"]);

    const taskBAcquire = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-B",
      "--role", "FOREMAN",
      "--thread", "foreman-task-a",
      "--host", "local",
      "--resource", "test-data:task-b-readonly",
      "--access", "SHARED_READ",
      "--ttl-ms", "60000",
      "--event-id", `resource-acquire-task-b-${randomUUID()}`,
      "--actor-capability-file", fixture.capabilities.foreman,
    ];
    const oddIntentTree = exactControlTree(fixture.controlDir);
    expectError(
      resource(fixture, taskBAcquire),
      "STORE_TRANSACTION_MISMATCH",
    );
    expect(exactControlTree(fixture.controlDir)).toEqual(oddIntentTree);

    const retried = resource(fixture, args);
    expect(retried.code).toBe(0);
    const lease = parse(retried) as {
      lease_id: string;
      owner_capability_file: string;
    };
    expect(lease.lease_id).toBeTruthy();
    expect(readdirSync(intentDirectory).sort()).toEqual(
      expect.arrayContaining(["capability-receipt.json", "intent.json"]),
    );
    const accepted = readdirSync(
      path.join(fixture.controlDir, "resources", "events"),
    ).map((name) => JSON.parse(readFileSync(
      path.join(fixture.controlDir, "resources", "events", name),
      "utf8",
    ))).filter((event) => event.event_id === eventId);
    expect(accepted).toHaveLength(1);
    expect(accepted[0].lease.lease_id).toBe(lease.lease_id);
    expectError(
      resource(fixture, taskBAcquire),
      "RESOURCE_ROLE_MISMATCH",
    );

    const conflict = [...args];
    conflict[conflict.indexOf("--ttl-ms") + 1] = "120000";
    expectError(resource(fixture, conflict), "RESOURCE_EVENT_ID_CONFLICT");
  });

  it("aborts a sealed acquire intent when recovery outlives the actor lease", () => {
    const eventId = `resource-acquire-late-intent-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGED_INTENT = "1";
    expectError(
      resource(fixture, args, "2026-07-22T00:00:00.000Z"),
      "TEST_FAULT_AFTER_ACQUIRE_STAGED_INTENT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGED_INTENT;

    const recovered = resource(
      fixture,
      args,
      "2026-07-22T02:00:00.000Z",
    );
    expect(recovered.code).toBe(0);
    const aborted = parse(recovered) as {
      status: string;
      operation_event_id: string;
      fencing_token: number;
      idempotent: boolean;
    };
    expect(aborted).toMatchObject({
      status: "ABORTED",
      operation_event_id: eventId,
      fencing_token: 1,
      idempotent: false,
    });
    expect(parse(resource(
      fixture,
      args,
      "2026-07-22T02:00:00.000Z",
    ))).toMatchObject({
      status: "ABORTED",
      operation_event_id: eventId,
      fencing_token: 1,
      idempotent: true,
    });
    const listed = parse(resource(
      fixture,
      ["list"],
      "2026-07-22T02:00:00.000Z",
    )) as { leases: unknown[] };
    expect(listed.leases).toEqual([]);
  });

  it("revalidates the acquire authority at accepted_at across the lease boundary", () => {
    const eventId = `resource-acquire-lease-boundary-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    const leaseUntil = Date.parse(taskState(fixture).sessions.DEV.lease_until);
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT = "1";
    expectError(
      resource(fixture, args),
      "TEST_FAULT_AFTER_ACQUIRE_INTENT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT;

    process.env.GOAL_CONTROL_TEST_ACQUIRE_NOW_AFTER_BOUNDARY =
      new Date(leaseUntil + 1).toISOString();
    const recovered = resource(
      fixture,
      args,
      new Date(leaseUntil - 1).toISOString(),
    );
    delete process.env.GOAL_CONTROL_TEST_ACQUIRE_NOW_AFTER_BOUNDARY;

    if (recovered.code !== 0) {
      throw new Error(
        `lease-boundary acquire recovery failed: ${recovered.stderr || recovered.stdout}`,
      );
    }
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      status: "ABORTED",
      operation_event_id: eventId,
      idempotent: false,
    });
    const events = readdirSync(
      path.join(fixture.controlDir, "resources", "events"),
    ).map((name) => JSON.parse(readFileSync(
      path.join(fixture.controlDir, "resources", "events", name),
      "utf8",
    ))).filter((event) => event.event_id === eventId);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      type: "LEASE_ACQUIRE_ABORTED",
      accepted_at: new Date(leaseUntil + 1).toISOString(),
    });
    expect(parse(resource(
      fixture,
      ["list"],
      new Date(leaseUntil + 1).toISOString(),
    ))).toMatchObject({ leases: [] });
  });

  it("aborts a fresh acquire that crosses the actor lease while minting its capability", () => {
    const eventId = `resource-acquire-fresh-boundary-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    const leaseUntil = Date.parse(taskState(fixture).sessions.DEV.lease_until);
    process.env.GOAL_CONTROL_TEST_ACQUIRE_NOW_AFTER_BOUNDARY =
      new Date(leaseUntil + 1).toISOString();
    const result = resource(
      fixture,
      args,
      new Date(leaseUntil - 1).toISOString(),
    );
    delete process.env.GOAL_CONTROL_TEST_ACQUIRE_NOW_AFTER_BOUNDARY;

    if (result.code !== 0) {
      throw new Error(
        `fresh lease-boundary acquire failed: ${result.stderr || result.stdout}`,
      );
    }
    expect(parse(result)).toMatchObject({
      status: "ABORTED",
      operation_event_id: eventId,
      idempotent: false,
    });
    const intentDirectory = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      eventId,
    );
    expect(readdirSync(intentDirectory)).toEqual(["intent.json"]);
    const events = readdirSync(
      path.join(fixture.controlDir, "resources", "events"),
    ).map((name) => JSON.parse(readFileSync(
      path.join(fixture.controlDir, "resources", "events", name),
      "utf8",
    ))).filter((event) => event.event_id === eventId);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      type: "LEASE_ACQUIRE_ABORTED",
      accepted_at: new Date(leaseUntil + 1).toISOString(),
    });
  });

  it("aborts an expired sealed acquire before rechecking time-aged shared occupants", () => {
    const now = "2026-07-22T00:00:00.000Z";
    const existing = acquire(
      fixture,
      "TASK-A",
      now,
      60_000,
      "test-data:readonly-fixture",
      "SHARED_READ",
    );
    expect(existing.code).toBe(0);

    const eventId = `resource-acquire-aged-occupant-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "test-data:readonly-fixture",
      "--access", "SHARED_READ",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT = "1";
    expectError(
      resource(fixture, args, now),
      "TEST_FAULT_AFTER_ACQUIRE_INTENT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT;

    expect(parse(resource(
      fixture,
      args,
      "2026-07-22T02:00:00.000Z",
    ))).toMatchObject({
      status: "ABORTED",
      operation_event_id: eventId,
      idempotent: false,
    });
  });

  it("safely cleans an empty acquire staging directory on exact retry", () => {
    const eventId = `resource-acquire-empty-staging-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGING_DIRECTORY = "1";
    expectError(
      resource(fixture, args),
      "TEST_FAULT_AFTER_ACQUIRE_STAGING_DIRECTORY",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGING_DIRECTORY;
    const staging = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      `.init-${eventId}`,
    );
    expect(readdirSync(staging)).toEqual([]);

    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const generationBeforeCleanup = JSON.parse(
      readFileSync(generationFile, "utf8"),
    ).generation as number;
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_EMPTY_STAGING_CLEANUP =
      "1";
    expectError(
      resource(fixture, args),
      "TEST_FAULT_AFTER_ACQUIRE_EMPTY_STAGING_CLEANUP",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_EMPTY_STAGING_CLEANUP;
    const generationAfterCleanup = JSON.parse(
      readFileSync(generationFile, "utf8"),
    ).generation as number;
    expect(generationAfterCleanup).toBe(generationBeforeCleanup + 2);
    expect(parse(resource(fixture, ["list"]))).toMatchObject({ leases: [] });

    const retried = resource(fixture, args);
    expect(retried.code).toBe(0);
    expect(existsSync(staging)).toBe(false);
    expect(parse(retried)).toMatchObject({ status: "ACTIVE" });
  });

  it("preserves and rejects an anonymous legacy intent temp without a request-bound seal", () => {
    const eventId = `resource-acquire-intent-temp-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGING_DIRECTORY = "1";
    expectError(
      resource(fixture, args),
      "TEST_FAULT_AFTER_ACQUIRE_STAGING_DIRECTORY",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_STAGING_DIRECTORY;

    const staging = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      `.init-${eventId}`,
    );
    const atomicTemp = path.join(
      staging,
      `.intent.json.4242.tmp-${"a".repeat(24)}`,
    );
    writeFileSync(atomicTemp, "{\"attacker\":\"partial", { mode: 0o600 });

    const before = readFileSync(atomicTemp);
    expectError(resource(fixture, args), "CORRUPT_STORE");
    expect(readFileSync(atomicTemp)).toEqual(before);
    expect(readdirSync(staging)).toEqual([path.basename(atomicTemp)]);
  });

  it("discards a strict atomic capability temp left by SIGKILL", () => {
    const eventId = `resource-acquire-cap-temp-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT = "1";
    expectError(
      resource(fixture, args),
      "TEST_FAULT_AFTER_ACQUIRE_INTENT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT;

    const intentDirectory = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      eventId,
    );
    const intent = JSON.parse(readFileSync(
      path.join(intentDirectory, "intent.json"),
      "utf8",
    ));
    const leaseId = intent.lease_template.lease_id as string;
    const atomicTemp = path.join(
      intentDirectory,
      `.${leaseId}-owner-${"b".repeat(24)}.cap.4242.tmp-${"c".repeat(24)}`,
    );
    writeFileSync(atomicTemp, "partial-capability", { mode: 0o600 });

    const recovered = resource(fixture, args);
    if (recovered.code !== 0) {
      throw new Error(
        `capability-temp acquire recovery failed: ${recovered.stderr || recovered.stdout}`,
      );
    }
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({ status: "ACTIVE" });
    expect(existsSync(atomicTemp)).toBe(false);
    const entries = readdirSync(intentDirectory);
    expect(entries.filter((name) => name.endsWith(".cap"))).toHaveLength(1);
    expect(entries).toContain("capability-receipt.json");
    expect(entries.some((name) => name.includes(".tmp-"))).toBe(false);
  });

  it("fails closed without deleting a lookalike capability temp", () => {
    const eventId = `resource-acquire-cap-lookalike-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT = "1";
    expectError(
      resource(fixture, args),
      "TEST_FAULT_AFTER_ACQUIRE_INTENT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT;

    const intentDirectory = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      eventId,
    );
    const intent = JSON.parse(readFileSync(
      path.join(intentDirectory, "intent.json"),
      "utf8",
    ));
    const leaseId = intent.lease_template.lease_id as string;
    const lookalike = path.join(
      intentDirectory,
      `.${leaseId}-owner-${"b".repeat(24)}.cap.0.tmp-${"c".repeat(24)}`,
    );
    writeFileSync(lookalike, "must-not-delete", { mode: 0o600 });

    expectError(resource(fixture, args), "CORRUPT_STORE");
    expect(existsSync(lookalike)).toBe(true);
    expect(readFileSync(lookalike, "utf8")).toBe("must-not-delete");
  });

  it("fails closed when one canonical receipt has multiple finalized capabilities", () => {
    const eventId = `resource-acquire-cap-fork-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT = "1";
    expectError(
      resource(fixture, args),
      "TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT;

    const intentDirectory = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      eventId,
    );
    const intent = JSON.parse(readFileSync(
      path.join(intentDirectory, "intent.json"),
      "utf8",
    ));
    const leaseId = intent.lease_template.lease_id as string;
    const firstCapabilityName = readdirSync(intentDirectory)
      .find((name) => name.endsWith(".cap"));
    expect(firstCapabilityName).toBeDefined();
    const firstCapabilityFile = path.join(
      intentDirectory,
      firstCapabilityName!,
    );
    const capabilityValue = readFileSync(firstCapabilityFile, "utf8").trim();
    const receiptBody = {
      schema_version: 1,
      type: "LEASE_OWNER_CAPABILITY",
      event_id: eventId,
      lease_id: leaseId,
      capability_file: firstCapabilityFile,
      capability_sha256: digest(capabilityValue),
    };
    const receipt = {
      ...receiptBody,
      receipt_sha256: objectDigest(receiptBody),
    };
    const receiptFile = path.join(
      intentDirectory,
      "capability-receipt.json",
    );
    writeFileSync(
      receiptFile,
      `${JSON.stringify(receipt, null, 2)}\n`,
      { mode: 0o600 },
    );
    const extraCapability = path.join(
      intentDirectory,
      `${leaseId}-owner-${"e".repeat(24)}.cap`,
    );
    writeFileSync(extraCapability, "must-not-delete", { mode: 0o600 });

    expectError(resource(fixture, args), "CORRUPT_STORE");
    expect(existsSync(firstCapabilityFile)).toBe(true);
    expect(existsSync(extraCapability)).toBe(true);
    expect(existsSync(receiptFile)).toBe(true);
  });

  it("discards a strict atomic receipt temp left by SIGKILL and remints from durable intent", () => {
    const eventId = `resource-acquire-receipt-temp-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT = "1";
    expectError(
      resource(fixture, args),
      "TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT;

    const intentDirectory = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      eventId,
    );
    const staleCapability = readdirSync(intentDirectory)
      .find((name) => name.endsWith(".cap"));
    expect(staleCapability).toBeDefined();
    const staleCapabilityFile = path.join(intentDirectory, staleCapability!);
    const atomicTemp = path.join(
      intentDirectory,
      `.capability-receipt.json.4242.tmp-${"d".repeat(24)}`,
    );
    writeFileSync(atomicTemp, "{\"receipt\":\"partial", { mode: 0o600 });

    const recovered = resource(fixture, args);
    if (recovered.code !== 0) {
      throw new Error(
        `receipt-temp acquire recovery failed: ${recovered.stderr || recovered.stdout}`,
      );
    }
    expect(recovered.code).toBe(0);
    const lease = parse(recovered) as {
      status: string;
      owner_capability_file: string;
    };
    expect(lease.status).toBe("ACTIVE");
    expect(existsSync(atomicTemp)).toBe(false);
    expect(existsSync(staleCapabilityFile)).toBe(false);
    expect(lease.owner_capability_file).not.toBe(staleCapabilityFile);
    const entries = readdirSync(intentDirectory);
    expect(entries.filter((name) => name.endsWith(".cap"))).toHaveLength(1);
    expect(entries).toContain("capability-receipt.json");
    expect(entries.some((name) => name.includes(".tmp-"))).toBe(false);
  });

  it("removes an uncommitted owner capability when an expired acquire aborts", () => {
    const eventId = `resource-acquire-cap-abort-${randomUUID()}`;
    const args = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", eventId,
      "--actor-capability-file", fixture.capabilities.dev,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT = "1";
    expectError(
      resource(fixture, args, "2026-07-22T00:00:00.000Z"),
      "TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_CAPABILITY_MINT;
    const intentDirectory = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      eventId,
    );
    expect(readdirSync(intentDirectory).some((name) => name.endsWith(".cap")))
      .toBe(true);

    expect(parse(resource(
      fixture,
      args,
      "2026-07-22T02:00:00.000Z",
    ))).toMatchObject({ status: "ABORTED", idempotent: false });
    expect(readdirSync(intentDirectory)).toEqual(["intent.json"]);
  });

  it("finishes an exact resource identity incident after its actor lease expires", () => {
    const lease = parse(acquire(fixture, "TASK-A")) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const eventId = `resource-verify-expired-retry-${randomUUID()}`;
    const args = [
      "verify",
      "--lease", lease.lease_id,
      "--owner-capability-file", fixture.capabilities.captain,
      "--actor-capability-file", fixture.capabilities.dev,
      "--event-id", eventId,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_INCIDENT_EVIDENCE = "1";
    expectError(
      resource(fixture, args, "2026-07-22T00:00:00.000Z"),
      "TEST_FAULT_AFTER_RESOURCE_INCIDENT_EVIDENCE",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_INCIDENT_EVIDENCE;

    const oddIncidentTree = exactControlTree(fixture.controlDir);
    expectError(
      resource(
        fixture,
        [...args, "--resource", "preview-port:different"],
        "2026-07-22T02:00:00.000Z",
      ),
      "RESOURCE_EVENT_ID_CONFLICT",
    );
    expect(exactControlTree(fixture.controlDir)).toEqual(oddIncidentTree);
    expectError(
      resource(fixture, args, "2026-07-22T02:00:00.000Z"),
      "LEASE_OWNER_MISMATCH",
    );
    expectError(
      resource(fixture, args, "2026-07-22T02:00:00.000Z"),
      "LEASE_OWNER_MISMATCH",
    );

    const goalRoot = path.join(fixture.controlDir, "goals", "demo");
    const incidentEvents = readdirSync(path.join(goalRoot, "events", "TASK-A"))
      .map((name) => JSON.parse(readFileSync(
        path.join(goalRoot, "events", "TASK-A", name),
        "utf8",
      )))
      .filter((event) => (
        event.type === "ADD_HOLD"
          && event.payload?.kind === "ENV_IDENTITY_INCIDENT"
      ));
    expect(incidentEvents).toHaveLength(1);
    expect(taskState(fixture).holds).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "ENV_IDENTITY_INCIDENT",
          hard: true,
        }),
      ]),
    );

    expectError(
      resource(
        fixture,
        [...args, "--resource", "preview-port:different"],
        "2026-07-22T02:00:00.000Z",
      ),
      "RESOURCE_EVENT_ID_CONFLICT",
    );
  });

  it("preserves a prepared-first identity incident for its exact transaction after SIGKILL", () => {
    const lease = parse(acquire(fixture, "TASK-A")) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const eventId = `resource-verify-prepared-${randomUUID()}`;
    const args = [
      "verify",
      "--lease", lease.lease_id,
      "--owner-capability-file", fixture.capabilities.captain,
      "--actor-capability-file", fixture.capabilities.dev,
      "--event-id", eventId,
    ];
    const beforeTemps = readdirSync(tmpdir())
      .filter((name) => name.startsWith("goalctl-resource-incident-"))
      .sort();

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_INGRESS_PREPARED =
      "sigkill";
    const interrupted = resource(
      fixture,
      args,
      "2026-07-22T00:00:00.000Z",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_INGRESS_PREPARED;
    expect(interrupted.code).not.toBe(0);

    const incidentDigest = createHash("sha256")
      .update(eventId)
      .digest("hex")
      .slice(0, 32);
    const incidentEvidenceId = `resource-identity-${incidentDigest}`;
    const goalRoot = path.join(fixture.controlDir, "goals", "demo");
    expect(existsSync(path.join(
      goalRoot,
      "evidence-ingress",
      "TASK-A",
      `${incidentEvidenceId}.json`,
    ))).toBe(true);
    expect(existsSync(path.join(
      goalRoot,
      "evidence",
      "TASK-A",
      `${incidentEvidenceId}.json`,
    ))).toBe(false);
    expect(
      readdirSync(tmpdir())
        .filter((name) => name.startsWith("goalctl-resource-incident-"))
        .sort()
    ).toEqual(beforeTemps);

    expectError(
      resource(fixture, args, "2026-07-22T00:00:00.000Z"),
      "STORE_REPAIR_REQUIRED",
    );
    expect(existsSync(path.join(
      goalRoot,
      "evidence",
      "TASK-A",
      `${incidentEvidenceId}.json`,
    ))).toBe(false);
    const incidents = readdirSync(path.join(goalRoot, "events", "TASK-A"))
      .map((name) => JSON.parse(readFileSync(
        path.join(goalRoot, "events", "TASK-A", name),
        "utf8",
      )))
      .filter((event) => (
        event.type === "ADD_HOLD"
          && event.payload?.evidence_id === incidentEvidenceId
      ));
    expect(incidents).toHaveLength(0);
  });

  it("exact-retries renew and release after durable commit response loss", () => {
    const lease = parse(acquire(fixture, "TASK-A")) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const renewalRequest = resourceRenewRequests(
      fixture,
      "2026-07-22T00:00:45.000Z",
    )[0];
    const renewEventId = renewalRequest.event_id;
    const renewArgs = [
      "renew",
      "--lease", lease.lease_id,
      "--owner-capability-file", lease.owner_capability_file,
      "--actor-capability-file", fixture.capabilities.dev,
      "--expected-revision", "1",
      "--ttl-ms", String(renewalRequest.ttl_ms),
      "--event-id", renewEventId,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_COMMIT = "LEASE_RENEWED";
    expectError(
      resource(fixture, renewArgs, "2026-07-22T00:00:45.000Z"),
      "TEST_FAULT_AFTER_RESOURCE_COMMIT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_COMMIT;

    const oddRenewTree = exactControlTree(fixture.controlDir);
    const conflictingRenew = [...renewArgs];
    conflictingRenew[conflictingRenew.indexOf("--ttl-ms") + 1] = "30000";
    expectError(
      resource(
        fixture,
        conflictingRenew,
        "2026-07-22T00:00:45.000Z",
      ),
      "RESOURCE_EVENT_ID_CONFLICT",
    );
    expect(exactControlTree(fixture.controlDir)).toEqual(oddRenewTree);
    const wrongRenewCapability = [...renewArgs];
    wrongRenewCapability[
      wrongRenewCapability.indexOf("--actor-capability-file") + 1
    ] = fixture.capabilities.captain;
    expectError(
      resource(
        fixture,
        wrongRenewCapability,
        "2026-07-22T00:00:45.000Z",
      ),
      "CAPABILITY_INVALID",
    );
    expect(exactControlTree(fixture.controlDir)).toEqual(oddRenewTree);
    expect(parse(resource(
      fixture,
      renewArgs,
      "2026-07-22T00:00:45.000Z",
    ))).toMatchObject({
      lease_id: lease.lease_id,
      revision: 2,
      operation_event_id: renewEventId,
      idempotent: true,
    });
    const secondRenew = resource(fixture, [
      "renew",
      "--lease", lease.lease_id,
      "--owner-capability-file", lease.owner_capability_file,
      "--actor-capability-file", fixture.capabilities.dev,
      "--expected-revision", "2",
      "--ttl-ms", String(renewalRequest.ttl_ms),
      "--event-id", `resource-renew-second-${randomUUID()}`,
    ], "2026-07-22T00:00:45.000Z");
    expectError(secondRenew, "RESOURCE_RENEW_NOT_DUE");
    expect(parse(resource(
      fixture,
      renewArgs,
      "2026-07-22T00:00:45.000Z",
    ))).toMatchObject({
      revision: 2,
      operation_event_id: renewEventId,
      idempotent: true,
    });

    const releaseEventId = `resource-release-response-loss-${randomUUID()}`;
    const releaseArgs = [
      "release",
      "--lease", lease.lease_id,
      "--owner-capability-file", lease.owner_capability_file,
      "--actor-capability-file", fixture.capabilities.dev,
      "--expected-revision", "2",
      "--event-id", releaseEventId,
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_COMMIT = "LEASE_RELEASED";
    expectError(
      resource(fixture, releaseArgs, "2026-07-22T00:00:45.000Z"),
      "TEST_FAULT_AFTER_RESOURCE_COMMIT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_COMMIT;
    expect(existsSync(lease.owner_capability_file)).toBe(false);
    expect(parse(resource(
      fixture,
      releaseArgs,
      "2026-07-22T00:00:45.000Z",
    ))).toMatchObject({
      lease_id: lease.lease_id,
      status: "RELEASED",
      revision: 3,
      operation_event_id: releaseEventId,
      idempotent: true,
    });
  });

  it("serializes concurrent resource identity incidents without orphan evidence", async () => {
    const lease = parse(acquire(fixture, "TASK-A")) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const args = [
      "verify",
      "--lease",
      lease.lease_id,
      "--owner-capability-file",
      fixture.capabilities.captain,
      "--actor-capability-file",
      fixture.capabilities.dev,
      "--event-id",
      `resource-verify-incident-${randomUUID()}`,
    ];

    const results = await Promise.all([
      runAsync(RESOURCECTL, args, fixture),
      runAsync(RESOURCECTL, args, fixture),
    ]);
    for (const result of results) {
      const output = `${result.stdout}\n${result.stderr}`;
      expect(result.code).not.toBe(0);
      expect(output).toContain("LEASE_OWNER_MISMATCH");
      expect(output).not.toContain("LOCK_TIMEOUT");
      expect(output).not.toContain("TEST_CHILD_TIMEOUT_AFTER_35000MS");
    }

    const goalRoot = path.join(fixture.controlDir, "goals", "demo");
    const evidenceDir = path.join(goalRoot, "evidence", "TASK-A");
    const sourceDir = path.join(goalRoot, "evidence-sources", "TASK-A");
    if (!existsSync(evidenceDir)) {
      throw new Error(`identity incident was not recorded: ${JSON.stringify(results)}`);
    }
    const incidentEvidence = readdirSync(evidenceDir)
      .filter((name) => name.endsWith(".json"))
      .map((name) => JSON.parse(readFileSync(path.join(evidenceDir, name), "utf8")))
      .filter((record) => (
        record.kind === "HOLD_ASSERTION"
        && record.stage === "RESOURCE_VERIFY"
      ));
    const acceptedEvents = readdirSync(path.join(goalRoot, "events", "TASK-A"))
      .filter((name) => name.endsWith(".json"))
      .map((name) => JSON.parse(
        readFileSync(path.join(goalRoot, "events", "TASK-A", name), "utf8")
      ));
    const incidentEvents = acceptedEvents.filter((event) => (
      event.type === "ADD_HOLD"
      && event.payload?.kind === "ENV_IDENTITY_INCIDENT"
    ));

    expect(incidentEvidence).toHaveLength(1);
    expect(incidentEvents).toHaveLength(1);
    expect(incidentEvents[0].payload.evidence_id).toBe(
      incidentEvidence[0].evidence_id
    );
    expect(readdirSync(sourceDir).filter((name) => name.endsWith(".artifact")))
      .toHaveLength(1);
  }, 45_000);

  it("exact-recovers a durable identity incident after actor context becomes stale", () => {
    const lease = parse(acquire(fixture, "TASK-A")) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const eventId = `resource-verify-stale-context-${randomUUID()}`;
    let failure: unknown = null;
    const priorEnvironment = {
      controlDir: process.env.GOAL_CONTROL_DIR,
      now: process.env.GOAL_CONTROL_NOW,
      testMode: process.env.GOAL_CONTROL_TEST_MODE,
    };
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    process.env.GOAL_CONTROL_NOW = "2026-07-22T00:00:00.000Z";
    process.env.GOAL_CONTROL_TEST_MODE = "1";

    try {
      verifyLease(
        fixture.root,
        {
          leaseId: lease.lease_id,
          ownerCapabilityFile: fixture.capabilities.captain,
          actorCapabilityFile: fixture.capabilities.dev,
          resource: null,
          eventId,
        },
        {
          beforeStableRead: () => {
            expectError(
              resource(fixture, [
                "verify",
                "--lease",
                lease.lease_id,
                "--owner-capability-file",
                fixture.capabilities.captain,
                "--actor-capability-file",
                fixture.capabilities.dev,
                "--event-id",
                eventId,
              ]),
              "LEASE_OWNER_MISMATCH",
            );
          },
        },
      );
    } catch (error) {
      failure = error;
    } finally {
      if (priorEnvironment.controlDir === undefined) {
        delete process.env.GOAL_CONTROL_DIR;
      } else {
        process.env.GOAL_CONTROL_DIR = priorEnvironment.controlDir;
      }
      if (priorEnvironment.now === undefined) {
        delete process.env.GOAL_CONTROL_NOW;
      } else {
        process.env.GOAL_CONTROL_NOW = priorEnvironment.now;
      }
      if (priorEnvironment.testMode === undefined) {
        delete process.env.GOAL_CONTROL_TEST_MODE;
      } else {
        process.env.GOAL_CONTROL_TEST_MODE = priorEnvironment.testMode;
      }
    }

    expect(failure).toMatchObject({ code: "LEASE_OWNER_MISMATCH" });
    const goalRoot = path.join(fixture.controlDir, "goals", "demo");
    const evidenceDir = path.join(goalRoot, "evidence", "TASK-A");
    const sourceDir = path.join(goalRoot, "evidence-sources", "TASK-A");
    const incidentEvidence = readdirSync(evidenceDir)
      .filter((name) => name.endsWith(".json"))
      .map((name) => JSON.parse(
        readFileSync(path.join(evidenceDir, name), "utf8"),
      ))
      .filter((record) => (
        record.kind === "HOLD_ASSERTION"
        && record.stage === "RESOURCE_VERIFY"
      ));
    const incidentEvents = readdirSync(
      path.join(goalRoot, "events", "TASK-A"),
    )
      .filter((name) => name.endsWith(".json"))
      .map((name) => JSON.parse(
        readFileSync(
          path.join(goalRoot, "events", "TASK-A", name),
          "utf8",
        ),
      ))
      .filter((event) => (
        event.type === "ADD_HOLD"
        && event.payload?.kind === "ENV_IDENTITY_INCIDENT"
      ));

    expect(incidentEvidence).toHaveLength(1);
    expect(incidentEvents).toHaveLength(1);
    expect(incidentEvents[0].payload.evidence_id).toBe(
      incidentEvidence[0].evidence_id,
    );
    expect(readdirSync(sourceDir).filter((name) => name.endsWith(".artifact")))
      .toHaveLength(1);
  });

  it("uses CAS and owner proof for renewal/release, then advances the fencing token on reacquire", () => {
    const lease = parse(acquire(fixture, "TASK-A")) as {
      lease_id: string;
      owner_capability_file: string;
    };
    expectError(
      resource(fixture, [
        "renew",
        "--lease",
        lease.lease_id,
        "--owner-capability-file",
        lease.owner_capability_file,
        "--actor-capability-file",
        fixture.capabilities.dev,
        "--expected-revision",
        "0",
        "--ttl-ms",
        "60000",
      ]),
      "STALE_LEASE_REVISION"
    );
    expectError(
      resource(fixture, [
        "release",
        "--lease",
        lease.lease_id,
        "--owner-capability-file",
        fixture.capabilities.captain,
        "--actor-capability-file",
        fixture.capabilities.dev,
        "--expected-revision",
        "1",
      ]),
      "LEASE_OWNER_MISMATCH"
    );

    const renewalRequest = resourceRenewRequests(
      fixture,
      "2026-07-22T00:00:45.000Z",
    )[0];
    const renewed = resource(fixture, [
      "renew",
      "--lease",
      lease.lease_id,
      "--owner-capability-file",
      lease.owner_capability_file,
      "--actor-capability-file",
      fixture.capabilities.dev,
      "--expected-revision",
      "1",
      "--ttl-ms",
      String(renewalRequest.ttl_ms),
      "--event-id",
      renewalRequest.event_id,
    ], "2026-07-22T00:00:45.000Z");
    expect(renewed.code).toBe(0);
    expect(parse(renewed)).toMatchObject({ status: "ACTIVE", revision: 2, fencing_token: 1 });

    const released = resource(fixture, [
      "release",
      "--lease",
      lease.lease_id,
      "--owner-capability-file",
      lease.owner_capability_file,
      "--actor-capability-file",
      fixture.capabilities.dev,
      "--expected-revision",
      "2",
    ]);
    expect(released.code).toBe(0);
    expect(parse(released)).toMatchObject({ status: "RELEASED", revision: 3, fencing_token: 1 });

    const second = acquire(fixture, "TASK-A");
    expect(second.code).toBe(0);
    expect(parse(second)).toMatchObject({ status: "ACTIVE", revision: 1, fencing_token: 2 });
  });

  it("replays DEV_READY after its declared resource leases are normally released", () => {
    const portLease = parse(acquire(fixture, "TASK-A")) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const dataLease = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60_000,
      "test-data:readonly-fixture",
      "SHARED_READ"
    )) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const launchFile = launchDev(
      fixture,
      [portLease.lease_id, dataLease.lease_id],
    );

    const submit = (
      type: string,
      role: "CAPTAIN" | "DEV",
      sequence: number,
      payload: Record<string, unknown>
    ): CliResult => {
      const state = taskState(fixture);
      const eventId = `${type.toLowerCase()}-${randomUUID()}`;
      const input = path.join(fixture.controlDir, `${eventId}.json`);
      writeFileSync(input, `${JSON.stringify({
        schema_version: 1,
        event_id: eventId,
        goal_id: "demo",
        task_id: "TASK-A",
        type,
        actor: {
          role,
          thread_id: role === "CAPTAIN" ? "captain-task-a" : "dev-task-a",
          host_id: "local",
        },
        actor_sequence: sequence,
        expected_state_revision: state.state_revision,
        control_epoch: state.control_epoch,
        packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
        base_head: state.base_head,
        full_head: state.full_head,
        payload,
      }, null, 2)}\n`);
      return run(GOALCTL, [
        "event", "--goal", "demo", "--file", input,
        "--actor-capability-file",
        role === "CAPTAIN" ? fixture.capabilities.captain : fixture.capabilities.dev,
        "--json",
      ], fixture);
    };
    const evidenceState = taskState(fixture);
    const evidenceDir = path.join(fixture.controlDir, "goals", "demo", "evidence", "TASK-A");
    mkdirSync(evidenceDir, { recursive: true });
    const evidenceIds = {
      preflight: `preflight-${randomUUID()}`,
      fast: `fast-${randomUUID()}`,
      full_ci: `full-ci-${randomUUID()}`,
      ac_audit: `ac-audit-${randomUUID()}`,
    };
    const kinds = {
      preflight: ["PREFLIGHT", "DEV"],
      fast: ["FAST", "DEV"],
      full_ci: ["FULL_CI", "CAPTAIN"],
      ac_audit: ["AC_AUDIT", "CAPTAIN"],
    } as const;
    for (const [key, [kind, role]] of Object.entries(kinds)) {
      const id = evidenceIds[key as keyof typeof evidenceIds];
      const registryFile = path.join(evidenceDir, `${id}.json`);
      const artifactFile = path.join(evidenceDir, `${id}.artifact`);
      writeFileSync(artifactFile, `${kind} PASS\n`);
      const record: Record<string, unknown> = {
        schema_version: 1,
        evidence_id: id,
        goal_id: "demo",
        task_id: "TASK-A",
        kind,
        status: "PASS",
        producer: {
          role,
          thread_id: role === "DEV" ? "dev-task-a" : "captain-task-a",
          host_id: "local",
        },
        state_revision: evidenceState.state_revision,
        packet: evidenceState.packet,
        packet_sha256: evidenceState.packet.sha256,
        base_head: evidenceState.base_head,
        full_head: evidenceState.full_head,
        created_at: "2026-07-22T00:00:00.000Z",
        uri: pathToFileURL(kind === "PREFLIGHT" ? registryFile : artifactFile).href,
        attestation: { controller: "goalctl", adapter: kind },
        ...(kind === "PREFLIGHT"
          ? {
            launch_id: "launch-dev-resource-1",
            launch_sha256: digest(readFileSync(launchFile, "utf8")),
            launch_uri: pathToFileURL(realpathSync(launchFile)).href,
          }
          : { source_sha256: digest(readFileSync(artifactFile, "utf8")) }),
        ...(["FULL_CI", "AC_AUDIT"].includes(kind)
          ? {
            pull_request: {
              repository: "example-org/example-repo",
              number: 999,
              url: "https://github.com/example-org/example-repo/pull/999",
              base: "main",
              head: evidenceState.full_head,
            },
          }
          : {}),
      };
      record.registry_sha256 = objectDigest(record);
      writeFileSync(registryFile, `${JSON.stringify(record, null, 2)}\n`);
    }
    const devReady = submit("DEV_READY", "DEV", 1, {
      pr: "https://github.com/example-org/example-repo/pull/999",
      evidence: evidenceIds,
    });
    if (devReady.code !== 0) {
      throw new Error(`DEV_READY failed: ${devReady.stderr || devReady.stdout}`);
    }

    for (const lease of [portLease, dataLease]) {
      const released = resource(fixture, [
        "release",
        "--lease", lease.lease_id,
        "--owner-capability-file", lease.owner_capability_file,
        "--actor-capability-file", fixture.capabilities.dev,
        "--expected-revision", "1",
      ]);
      expect(released.code).toBe(0);
      expect(parse(released)).toMatchObject({ status: "RELEASED" });
    }

    for (const args of [
      ["status", "--goal", "demo", "--task", "TASK-A"],
      ["next", "--goal", "demo"],
      [
        "actions", "--goal", "demo", "--task", "TASK-A",
        "--role", "CAPTAIN", "--thread", "captain-task-a",
      ],
    ]) {
      const replayed = run(GOALCTL, [...args, "--json"], fixture);
      if (replayed.code !== 0) {
        throw new Error(`${args[0]} replay failed: ${replayed.stderr || replayed.stdout}`);
      }
      expect(replayed.code).toBe(0);
      expect(replayed.stdout).toContain("TASK-A");
    }
  });

  it("never auto-steals an expired lease and requires an authorized evidence-backed reap", () => {
    const started = "2026-07-22T00:00:00.000Z";
    const expired = "2026-07-22T00:00:02.000Z";
    const lease = parse(acquire(fixture, "TASK-A", started, 1_000)) as {
      lease_id: string;
      owner_capability_file: string;
    };

    expectError(acquire(fixture, "TASK-A", expired), "RESOURCE_STALE_REQUIRES_REAP");
    expectError(
      resource(
        fixture,
        [
          "renew",
          "--lease",
          lease.lease_id,
          "--owner-capability-file",
          lease.owner_capability_file,
          "--actor-capability-file",
          fixture.capabilities.dev,
          "--expected-revision",
          "1",
          "--ttl-ms",
          "60000",
        ],
        expired
      ),
      "LEASE_EXPIRED"
    );

    const doctor = resource(fixture, ["doctor"], expired);
    expect(doctor.code).not.toBe(0);
    expect(doctor.stdout).toContain("STALE_RESOURCE_LEASE");

    const evidenceId = seedRoleFailureEvidence(fixture, {
      lease_id: lease.lease_id,
      resource: "preview-port:8123",
      revision: 1,
    });
    expectError(
      resource(
        fixture,
        [
          "reap",
          "--lease",
          lease.lease_id,
          "--expected-revision",
          "1",
          "--actor-capability-file",
          fixture.capabilities.dev,
          "--evidence",
          evidenceId,
        ],
        expired
      ),
      "REAP_AUTHORITY_REQUIRED"
    );

    const reaped = resource(
      fixture,
      [
        "reap",
        "--lease",
        lease.lease_id,
        "--expected-revision",
        "1",
        "--actor-capability-file",
        fixture.capabilities.captain,
        "--evidence",
        evidenceId,
      ],
      expired
    );
    expectError(reaped, "REAP_DISABLED_IN_SHADOW");
  });

  it("still refuses enforce reap when only semantic isolation evidence exists and no mechanical broker is installed", () => {
    rmSync(fixture.root, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
    fixture = makeFixture("enforce", ["DEV"]);
    initializeRoles(fixture);
    const started = "2026-07-22T00:00:00.000Z";
    const expired = "2026-07-22T00:00:02.000Z";
    const lease = parse(acquire(fixture, "TASK-A", started, 1_000)) as {
      lease_id: string;
      resource: string;
      revision: number;
    };
    const evidenceId = seedRoleFailureEvidence(fixture, lease);
    reportDevLost(fixture, evidenceId);

    const evidenceFile = path.join(fixture.controlDir, "goals", "demo", "evidence", "TASK-A", `${evidenceId}.json`);
    const sealedEvidence = readFileSync(evidenceFile, "utf8");
    const tampered = JSON.parse(sealedEvidence) as { resource_lease: { isolation_ref: string } };
    tampered.resource_lease.isolation_ref = "test://tampered";
    writeFileSync(evidenceFile, `${JSON.stringify(tampered, null, 2)}\n`);
    expectError(resource(fixture, [
      "reap", "--lease", lease.lease_id, "--expected-revision", "1",
      "--actor-capability-file", fixture.capabilities.captain, "--evidence", evidenceId,
    ], expired), "CORRUPT_STORE");
    writeFileSync(evidenceFile, sealedEvidence);

    const reaped = resource(fixture, [
      "reap", "--lease", lease.lease_id, "--expected-revision", "1",
      "--actor-capability-file", fixture.capabilities.captain, "--evidence", evidenceId,
    ], expired);
    expectError(reaped, "REAP_REQUIRES_BROKER");
    const listed = parse(resource(fixture, ["list"], expired)) as {
      leases: Array<{ lease_id: string; status: string; revision: number }>;
    };
    expect(listed.leases).toEqual(
      expect.arrayContaining([expect.objectContaining({ lease_id: lease.lease_id, status: "EXPIRED", revision: 1 })])
    );
  });

  it("refuses to reap a still-live lease even with an authorized actor and trusted evidence", () => {
    const lease = parse(acquire(fixture, "TASK-A")) as { lease_id: string; resource: string; revision: number };
    const evidenceId = seedRoleFailureEvidence(fixture, lease);
    const result = resource(fixture, [
      "reap",
      "--lease",
      lease.lease_id,
      "--expected-revision",
      "1",
      "--actor-capability-file",
      fixture.capabilities.foreman,
      "--evidence",
      evidenceId,
    ]);

    expectError(result, "LEASE_NOT_EXPIRED");
  });

  it("binds every resource action to the active actor capability", () => {
    const missingEventId = resource(fixture, [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--actor-capability-file", fixture.capabilities.dev,
    ]);
    expectError(missingEventId, "ARG_REQUIRED");
    expect(`${missingEventId.stdout}\n${missingEventId.stderr}`)
      .toContain("--event-id");

    const stableIdCommands = [
      [
        "renew",
        "--lease", "missing-lease",
        "--owner-capability-file", fixture.capabilities.dev,
        "--actor-capability-file", fixture.capabilities.dev,
        "--expected-revision", "1",
        "--ttl-ms", "60000",
      ],
      [
        "release",
        "--lease", "missing-lease",
        "--owner-capability-file", fixture.capabilities.dev,
        "--actor-capability-file", fixture.capabilities.dev,
        "--expected-revision", "1",
      ],
      [
        "verify",
        "--lease", "missing-lease",
        "--owner-capability-file", fixture.capabilities.dev,
        "--actor-capability-file", fixture.capabilities.dev,
      ],
    ];
    for (const command of stableIdCommands) {
      const missingStableId = run(
        RESOURCECTL,
        [...command, "--json"],
        fixture,
      );
      expectError(missingStableId, "ARG_REQUIRED");
      expect(`${missingStableId.stdout}\n${missingStableId.stderr}`)
        .toContain("--event-id");
    }

    expectError(
      resource(fixture, [
        "acquire",
        "--goal",
        "demo",
        "--task",
        "TASK-A",
        "--role",
        "DEV",
        "--thread",
        "dev-task-a",
        "--resource",
        "preview-port:8123",
      ]),
      "ARG_REQUIRED"
    );
    expectError(
      resource(fixture, [
        "acquire",
        "--goal",
        "demo",
        "--task",
        "TASK-A",
        "--role",
        "DEV",
        "--thread",
        "dev-task-a",
        "--resource",
        "preview-port:8123",
        "--event-id",
        `resource-acquire-${randomUUID()}`,
        "--actor-capability-file",
        fixture.capabilities.captain,
      ]),
      "CAPABILITY_INVALID"
    );

    const lease = parse(acquire(fixture)) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const wrongActorActions = [
      ["verify", "--lease", lease.lease_id],
      [
        "renew",
        "--lease",
        lease.lease_id,
        "--expected-revision",
        "1",
        "--ttl-ms",
        "60000",
      ],
      [
        "release",
        "--lease",
        lease.lease_id,
        "--expected-revision",
        "1",
      ],
    ];
    for (const action of wrongActorActions) {
      expectError(
        resource(fixture, [
          ...action,
          "--owner-capability-file",
          lease.owner_capability_file,
          "--actor-capability-file",
          fixture.capabilities.captain,
        ]),
        "CAPABILITY_INVALID"
      );
    }

    const actorExpiredAt = new Date(Date.now() + 5 * 60 * 60 * 1000).toISOString();
    expectError(acquire(fixture, "TASK-A", actorExpiredAt), "ACTOR_LEASE_EXPIRED");
  });

  it("allows only the exact manifest requirement and access mode", () => {
    expectError(
      acquire(fixture, "TASK-A", undefined, 60_000, "account:8123"),
      "RESOURCE_NOT_DECLARED"
    );
    expectError(
      acquire(fixture, "TASK-A", undefined, 60_000, "preview-port:any:8123"),
      "RESOURCE_NOT_DECLARED"
    );
    expectError(
      acquire(fixture, "TASK-A", undefined, 60_000, "preview-port:8123", "SHARED_READ"),
      "RESOURCE_ACCESS_MISMATCH"
    );
    expectError(
      acquire(fixture, "TASK-A", undefined, 60_000, "preview-port:8123:allocated-8123"),
      "RESOURCE_NOT_DECLARED"
    );
    const declared = acquire(fixture, "TASK-A", undefined, 60_000, "preview-port:8123");
    expect(declared.code).toBe(0);
  });

  it("rejects a requirement that does not opt in the acquiring worker role", () => {
    rmSync(fixture.root, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
    fixture = makeFixture("shadow", ["REVIEW"]);
    initializeRoles(fixture);

    expectError(acquire(fixture), "RESOURCE_ROLE_MISMATCH");
  });

  it("defaults omitted roles to workers while preserving exact legacy control-role replay", () => {
    const legacyEventId = `resource-acquire-legacy-captain-${randomUUID()}`;
    const legacyCaptainAcquire = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", "captain-task-a",
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", legacyEventId,
      "--actor-capability-file", fixture.capabilities.captain,
    ];
    process.env.GOAL_CONTROL_TEST_LEGACY_RESOURCE_ROLE_DEFAULT = "1";
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT = "1";
    expectError(
      resource(fixture, legacyCaptainAcquire),
      "TEST_FAULT_AFTER_ACQUIRE_INTENT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACQUIRE_INTENT;
    delete process.env.GOAL_CONTROL_TEST_LEGACY_RESOURCE_ROLE_DEFAULT;

    const completed = resource(fixture, legacyCaptainAcquire);
    expect(completed.code).toBe(0);
    expect(parse(completed)).toMatchObject({
      status: "ACTIVE",
      idempotent: false,
    });
    expect(parse(resource(fixture, legacyCaptainAcquire))).toMatchObject({
      status: "ACTIVE",
      idempotent: true,
    });

    for (const [role, thread, capability] of [
      ["CAPTAIN", "captain-task-a", fixture.capabilities.captain],
      ["FOREMAN", "foreman-task-a", fixture.capabilities.foreman],
    ] as const) {
      expectError(resource(fixture, [
        "acquire",
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", role,
        "--thread", thread,
        "--host", "local",
        "--resource", "test-data:readonly-fixture",
        "--access", "SHARED_READ",
        "--ttl-ms", "60000",
        "--event-id", `resource-acquire-control-${randomUUID()}`,
        "--actor-capability-file", capability,
      ]), "RESOURCE_ROLE_MISMATCH");
    }
  });

  it.each([
    { label: "empty", roles: [] },
    { label: "duplicate", roles: ["DEV", "DEV"] },
    { label: "control-plane", roles: ["CAPTAIN"] },
  ])("rejects $label resource role declarations", ({ roles }) => {
    rmSync(fixture.root, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
    fixture = makeFixture("shadow", roles);

    expectError(
      run(GOALCTL, ["init", "--manifest", fixture.manifest, "--json"], fixture),
      "INVALID_MANIFEST"
    );
  });

  it("caps acquire and renew TTL at four hours", () => {
    const maximum = 4 * 60 * 60 * 1000;
    expectError(acquire(fixture, "TASK-A", undefined, maximum + 1), "INVALID_TTL");
    const lease = parse(acquire(fixture, "TASK-A", undefined, maximum)) as {
      lease_id: string;
      owner_capability_file: string;
    };
    expectError(
      resource(fixture, [
        "renew",
        "--lease",
        lease.lease_id,
        "--owner-capability-file",
        lease.owner_capability_file,
        "--actor-capability-file",
        fixture.capabilities.dev,
        "--expected-revision",
        "1",
        "--ttl-ms",
        String(maximum + 1),
      ]),
      "INVALID_TTL"
    );
  });

  it("quarantines acquire, use, owner-capability, and release under a hard hold", () => {
    const lease = parse(acquire(fixture, "TASK-A")) as {
      lease_id: string;
      owner_capability_file: string;
    };
    addHardHold(fixture);

    expectError(
      acquire(fixture, "TASK-A", undefined, 60_000, "test-data:readonly-fixture", "SHARED_READ"),
      "TASK_HARD_HELD"
    );
    expectError(
      resource(fixture, [
        "renew",
        "--lease",
        lease.lease_id,
        "--owner-capability-file",
        lease.owner_capability_file,
        "--actor-capability-file",
        fixture.capabilities.dev,
        "--expected-revision",
        "1",
        "--ttl-ms",
        "60000",
      ]),
      "TASK_HARD_HELD"
    );
    expectError(
      resource(fixture, [
        "verify",
        "--lease",
        lease.lease_id,
        "--owner-capability-file",
        lease.owner_capability_file,
        "--actor-capability-file",
        fixture.capabilities.dev,
      ]),
      "TASK_HARD_HELD"
    );
    expectError(
      resource(fixture, [
        "owner-capability",
        "--lease", lease.lease_id,
        "--actor-capability-file", fixture.capabilities.dev,
      ]),
      "TASK_HARD_HELD",
    );
    expectError(
      resource(fixture, [
        "release",
        "--lease",
        lease.lease_id,
        "--owner-capability-file",
        lease.owner_capability_file,
        "--actor-capability-file",
        fixture.capabilities.dev,
        "--expected-revision",
        "1",
      ]),
      "TASK_HARD_HELD",
    );
  });

  it("discloses an owner capability under an identity hard hold only at the projected renewal boundary", () => {
    const lease = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60_000,
    )) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const dataLease = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60_000,
      "test-data:readonly-fixture",
      "SHARED_READ",
    )) as { lease_id: string };
    launchDev(fixture, [lease.lease_id, dataLease.lease_id]);
    addIdentityIncidentHardHold(fixture, lease);

    expectError(
      resource(fixture, [
        "owner-capability",
        "--lease", lease.lease_id,
        "--actor-capability-file", fixture.capabilities.dev,
      ], "2026-07-22T00:00:44.999Z"),
      "RESOURCE_RENEW_NOT_DUE",
    );

    const recovered = resource(fixture, [
      "owner-capability",
      "--lease", lease.lease_id,
      "--actor-capability-file", fixture.capabilities.dev,
    ], "2026-07-22T00:00:45.000Z");
    expect(recovered.code).toBe(0);
    expect(parse(recovered)).toMatchObject({
      lease_id: lease.lease_id,
      revision: 1,
      owner_capability_file: lease.owner_capability_file,
    });
  });

  it("rejects a fresh acquisition attempt from recovering an old owner capability under a hard hold", () => {
    const lease = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60_000,
    )) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const dataLease = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60_000,
      "test-data:readonly-fixture",
      "SHARED_READ",
    )) as { lease_id: string };
    launchDev(fixture, [lease.lease_id, dataLease.lease_id]);
    addIdentityIncidentHardHold(fixture, lease);

    const acquisition = readdirSync(
      path.join(fixture.controlDir, "resources", "events"),
    ).map((name) => JSON.parse(readFileSync(
      path.join(fixture.controlDir, "resources", "events", name),
      "utf8",
    ))).find((event) => (
      event.type === "LEASE_ACQUIRED"
        && event.lease?.lease_id === lease.lease_id
    ));
    expect(acquisition).toBeDefined();
    const intentFile = path.join(
      fixture.controlDir,
      "resources",
      "acquire-intents",
      acquisition.event_id,
      "intent.json",
    );
    const intent = JSON.parse(readFileSync(intentFile, "utf8")) as {
      actor_authority: { attempt: number };
      intent_sha256: string;
    };
    expect(intent.actor_authority.attempt).toBe(1);
    intent.actor_authority.attempt += 1;
    const unsignedIntent = { ...intent } as Record<string, unknown>;
    delete unsignedIntent.intent_sha256;
    intent.intent_sha256 = objectDigest(unsignedIntent);
    writeFileSync(intentFile, `${JSON.stringify(intent, null, 2)}\n`);

    const beforeRejectedRecovery = exactControlTree(fixture.controlDir);
    const ownerCapabilityBytes = readFileSync(
      lease.owner_capability_file,
      "utf8",
    );
    expectError(
      resource(fixture, [
        "owner-capability",
        "--lease", lease.lease_id,
        "--actor-capability-file", fixture.capabilities.dev,
      ], "2026-07-22T00:00:45.000Z"),
      "LEASE_OWNER_MISMATCH",
    );
    expect(exactControlTree(fixture.controlDir)).toEqual(
      beforeRejectedRecovery,
    );
    expect(readFileSync(lease.owner_capability_file, "utf8")).toBe(
      ownerCapabilityBytes,
    );
  });

  it("keeps owner capability disclosure fail-closed before the worker phase is active", () => {
    const lease = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60_000,
    )) as { lease_id: string };
    addIdentityIncidentHardHold(fixture, lease);
    expect(taskState(fixture).phase).toBe("P1_COMMITTED");

    expectError(
      resource(fixture, [
        "owner-capability",
        "--lease", lease.lease_id,
        "--actor-capability-file", fixture.capabilities.dev,
      ], "2026-07-22T00:00:45.000Z"),
      "TASK_HARD_HELD",
    );
  });

  it("refuses a superseded shared lease capability under an identity hard hold", () => {
    const portLease = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      5 * 60_000,
    )) as { lease_id: string };
    const superseded = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      60_000,
      "test-data:readonly-fixture",
      "SHARED_READ",
    )) as { lease_id: string };
    const current = parse(acquire(
      fixture,
      "TASK-A",
      "2026-07-22T00:00:00.000Z",
      5 * 60_000,
      "test-data:readonly-fixture",
      "SHARED_READ",
    )) as { lease_id: string };
    launchDev(fixture, [portLease.lease_id, current.lease_id]);
    addIdentityIncidentHardHold(fixture, superseded);

    expectError(
      resource(fixture, [
        "owner-capability",
        "--lease", superseded.lease_id,
        "--actor-capability-file", fixture.capabilities.dev,
      ], "2026-07-22T00:01:00.000Z"),
      "RESOURCE_EXPIRY_RECOVERY_FENCED",
    );
  });
});
