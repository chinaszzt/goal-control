import { execFileSync, spawn, spawnSync } from "child_process";
import { createHash, randomUUID } from "crypto";
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath, pathToFileURL } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const RESOURCECTL = path.join(ROOT, "scripts", "resourcectl.js");
const nodeRequire = createRequire(import.meta.url);
const { goalCommand } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "cli.js"),
) as {
  goalCommand: (
    args: string[],
    cwd: string,
  ) => { value: unknown; exitCode: number };
};
const goalFsm = nodeRequire(path.join(ROOT, "scripts", "goal-control", "fsm.js")) as {
  applyEvent: (
    state: Record<string, unknown>,
    event: Record<string, unknown>,
    controlEpoch: number
  ) => Record<string, unknown>;
};
const { runPreflight } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "preflight.js")
) as {
  runPreflight: (
    cwd: string,
    options: Record<string, unknown>,
    dependencies?: { beforeEvidenceCommit?: () => void }
  ) => Record<string, unknown>;
};
const { runFastEvidence } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "gate-adapters.js")
) as {
  runFastEvidence: (
    cwd: string,
    options: Record<string, unknown>,
    dependencies?: Record<string, unknown>
  ) => Record<string, unknown>;
};
const { verifyLease } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "resources.js")
) as {
  verifyLease: (
    cwd: string,
    options: Record<string, unknown>,
    dependencies?: { beforeIncidentCommit?: () => void }
  ) => Record<string, unknown>;
};
const { mergePullRequest } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "github-merge.js")
) as {
  mergePullRequest: (
    cwd: string,
    options: Record<string, unknown>,
    dependencies?: Record<string, unknown>
  ) => Record<string, unknown>;
};
type CliResult = { code: number; stdout: string; stderr: string };
type Role = "FOREMAN" | "CAPTAIN" | "DEV" | "REVIEW" | "RECEIPT";

type GoalFixture = {
  root: string;
  controlDir: string;
  manifest: string;
  baseHead: string;
  fullHead: string;
  packetHashes: Record<"TASK-A" | "TASK-B", string>;
  bootstrapCapability?: string;
  foremanRecoveryCapability?: string;
  capabilities: Record<string, Partial<Record<Role, string>>>;
};

type GoalRepoTemplate = Pick<
  GoalFixture,
  "root" | "baseHead" | "fullHead" | "packetHashes"
>;

const THREADS: Record<Role, string> = {
  FOREMAN: "foreman-1",
  CAPTAIN: "captain-a-1",
  DEV: "dev-a-1",
  REVIEW: "review-a-1",
  RECEIPT: "receipt-a-1",
};

const PLAN_PATH = "docs/issues/4242/plan.md";
const CONTEXT_PATH = "docs/issues/4242/context.md";
const PLAN_BODY = "# Plan\n\nApproved implementation plan.\n";
const CONTEXT_BODY = "# Context\n\nFrozen issue context.\n";

let inProcessGoalCliFixtureSetup = false;
let goalRepoTemplate: GoalRepoTemplate | undefined;

function runGoalCommandInProcess(
  args: string[],
  cwd: string,
  controlDir: string,
): CliResult {
  if (!args.includes("--json")) {
    throw new Error("in-process Goal fixture setup requires --json");
  }
  if (args.includes("--repository-worktree")) {
    throw new Error(
      "in-process Goal fixture setup cannot emulate --repository-worktree",
    );
  }
  const previousControlDir = process.env.GOAL_CONTROL_DIR;
  const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
  process.env.GOAL_CONTROL_DIR = controlDir;
  process.env.GOAL_CONTROL_TEST_MODE = "1";
  try {
    const result = goalCommand(args, cwd);
    if (result.exitCode !== 0) {
      throw new Error(
        `in-process Goal fixture setup returned exitCode=${result.exitCode}: `
          + JSON.stringify(result.value),
      );
    }
    return {
      code: 0,
      stdout: `${JSON.stringify(result.value, null, 2)}\n`,
      stderr: "",
    };
  } finally {
    if (previousControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
    else process.env.GOAL_CONTROL_DIR = previousControlDir;
    if (previousTestMode === undefined) {
      delete process.env.GOAL_CONTROL_TEST_MODE;
    } else {
      process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
    }
  }
}

type SyncOnly<T> = T extends PromiseLike<unknown> ? never : T;

function withInProcessGoalCliFixtureSetup<T>(
  callback: () => SyncOnly<T>,
): SyncOnly<T> {
  const previous = inProcessGoalCliFixtureSetup;
  inProcessGoalCliFixtureSetup = true;
  try {
    const result = callback();
    if (
      result !== null
        && typeof result === "object"
        && typeof (result as { then?: unknown }).then === "function"
    ) {
      throw new Error("in-process Goal fixture setup must be synchronous");
    }
    return result;
  } finally {
    inProcessGoalCliFixtureSetup = previous;
  }
}

function runCli(args: string[], cwd: string, controlDir: string): CliResult {
  if (inProcessGoalCliFixtureSetup) {
    return runGoalCommandInProcess(args, cwd, controlDir);
  }
  try {
    const stdout = execFileSync("node", [GOALCTL, ...args], {
      cwd,
      encoding: "utf8",
      stdio: "pipe",
      env: { ...process.env, GOAL_CONTROL_DIR: controlDir, GOAL_CONTROL_TEST_MODE: "1" },
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

function runResourceCli(args: string[], cwd: string, controlDir: string): CliResult {
  const stableOperationCommands = new Set(["renew", "release", "verify"]);
  const withOperationId = stableOperationCommands.has(args[0])
    && !args.includes("--event-id")
    ? [
      ...args,
      "--event-id",
      `test-${args[0]}-${createHash("sha256").update(JSON.stringify(args)).digest("hex").slice(0, 24)}`,
    ]
    : args;
  try {
    const stdout = execFileSync("node", [RESOURCECTL, ...withOperationId], {
      cwd,
      encoding: "utf8",
      stdio: "pipe",
      env: { ...process.env, GOAL_CONTROL_DIR: controlDir, GOAL_CONTROL_TEST_MODE: "1" },
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

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function controlTreeSnapshot(root: string): Array<[string, string]> {
  const entries: Array<[string, string]> = [];
  const visit = (directory: string, relativeDirectory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const relative = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      const stat = lstatSync(absolute);
      if (stat.isDirectory()) {
        entries.push([`${relative}/`, String(stat.mode & 0o7777)]);
        visit(absolute, relative);
      } else if (stat.isSymbolicLink()) {
        entries.push([relative, `symlink:${readlinkSync(absolute)}`]);
      } else {
        entries.push([
          relative,
          `${stat.mode & 0o7777}:${sha256(readFileSync(absolute))}`,
        ]);
      }
    }
  };
  visit(root, "");
  return entries;
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" }).trim();
}

function createGoalRepoTemplate(): GoalRepoTemplate {
  const root = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-control-goalctl-test-"))
  );
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.email", "goalctl@example.test");
  git(root, "config", "user.name", "Goal Control Test");
  writeFileSync(path.join(root, "README.md"), "# isolated goal control fixture\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "base");
  const baseHead = git(root, "rev-parse", "HEAD");

  const packetDir = path.join(root, "docs", "planning", "goals", "demo", "packets");
  mkdirSync(packetDir, { recursive: true });
  const packetBodies = {
    "TASK-A": "# TASK-A r1\n\nImmutable packet A.\n",
    "TASK-B": "# TASK-B r1\n\nImmutable packet B.\n",
  } as const;
  const packetHashes = {
    "TASK-A": sha256(packetBodies["TASK-A"]),
    "TASK-B": sha256(packetBodies["TASK-B"]),
  };
  for (const [task, body] of Object.entries(packetBodies)) {
    writeFileSync(path.join(packetDir, `${task}-r1.md`), body);
  }
  const protocolDir = path.join(root, "docs", "protocol");
  mkdirSync(protocolDir, { recursive: true });
  const protocolFiles = {
    entry: "entry.md",
    shared: "shared.md",
    foreman: "foreman.md",
    captain: "captain.md",
    role_kernel: "role-kernel.md",
  };
  for (const [name, file] of Object.entries(protocolFiles)) {
    writeFileSync(path.join(protocolDir, file), `# ${name}\n`);
  }
  mkdirSync(path.join(root, "docs", "issues", "4242"), { recursive: true });
  writeFileSync(path.join(root, PLAN_PATH), PLAN_BODY);
  writeFileSync(path.join(root, CONTEXT_PATH), CONTEXT_BODY);
  const manifest = path.join(root, "docs", "planning", "goals", "demo", "manifest.json");
  writeFileSync(
    manifest,
    JSON.stringify(
      {
        schema_version: 1,
        goal_id: "demo",
        mode: "shadow",
        repository: { name_with_owner: "example-org/example-repo", base_branch: "main" },
        base_head: baseHead,
        protocol: Object.fromEntries(
          Object.entries(protocolFiles).map(([name, file]) => [name, `docs/protocol/${file}`])
        ),
        tasks: [
          {
            id: "TASK-A",
            dependencies: [],
            integration_order: 1,
            packet: {
              revision: 1,
              path: path.relative(root, path.join(packetDir, "TASK-A-r1.md")),
              sha256: packetHashes["TASK-A"],
            },
          },
          {
            id: "TASK-B",
            dependencies: ["TASK-A"],
            integration_order: 2,
            packet: {
              revision: 1,
              path: path.relative(root, path.join(packetDir, "TASK-B-r1.md")),
              sha256: packetHashes["TASK-B"],
            },
          },
        ],
      },
      null,
      2
    ) + "\n"
  );
  git(root, "add", ".");
  git(root, "commit", "-qm", "seed goal manifest");
  const fullHead = git(root, "rev-parse", "HEAD");
  return { root, baseHead, fullHead, packetHashes };
}

function makeGoalRepo(): GoalFixture {
  if (goalRepoTemplate === undefined) {
    goalRepoTemplate = createGoalRepoTemplate();
  }
  const root = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-control-goalctl-test-"))
  );
  cpSync(goalRepoTemplate.root, root, { recursive: true });
  const controlDir = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-control-goalctl-state-"))
  );
  return {
    root,
    controlDir,
    manifest: path.join(
      root,
      "docs",
      "planning",
      "goals",
      "demo",
      "manifest.json",
    ),
    baseHead: goalRepoTemplate.baseHead,
    fullHead: goalRepoTemplate.fullHead,
    packetHashes: { ...goalRepoTemplate.packetHashes },
    capabilities: { "TASK-A": {}, "TASK-B": {} },
  };
}

function json(result: CliResult): Record<string, unknown> {
  expect(result.stdout).not.toBe("");
  return JSON.parse(result.stdout) as Record<string, unknown>;
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

function initGoal(fixture: GoalFixture): void {
  withInProcessGoalCliFixtureSetup(() => {
    const result = runCli(["init", "--manifest", fixture.manifest, "--json"], fixture.root, fixture.controlDir);
    expect(result.code).toBe(0);
    fixture.bootstrapCapability = String(json(result).bootstrap_capability_file);
    fixture.foremanRecoveryCapability = String(json(result).foreman_recovery_capability_file);
  });
}

type RegisterRoleOptions = {
  task?: string;
  thread?: string;
  attempt?: number;
  seedLaunch?: boolean;
  leaseMs?: number;
};

function registerRole(
  fixture: GoalFixture,
  role: Role,
  options: RegisterRoleOptions = {},
): Record<string, unknown> {
  return withInProcessGoalCliFixtureSetup(
    () => registerRoleInProcess(fixture, role, options),
  );
}

function registerRoleInProcess(
  fixture: GoalFixture,
  role: Role,
  options: RegisterRoleOptions,
): Record<string, unknown> {
  const task = options.task ?? "TASK-A";
  const attempt = options.attempt ?? 1;
  const parent = role === "FOREMAN"
    ? (attempt === 1 ? fixture.bootstrapCapability : fixture.foremanRecoveryCapability)
    : role === "CAPTAIN"
      ? fixture.capabilities[task].FOREMAN
      : fixture.capabilities[task].CAPTAIN;
  const capabilityFlag = role === "FOREMAN"
    ? (attempt === 1 ? "--bootstrap-capability-file" : "--foreman-recovery-capability-file")
    : "--authorizer-capability-file";
  const launchArgs = ["DEV", "REVIEW", "RECEIPT"].includes(role)
    ? ["--launch-id", `launch-${role.toLowerCase()}-${attempt}`]
    : [];
  const result = runCli(
    [
      "register-role",
      "--goal",
      "demo",
      "--task",
      task,
      "--role",
      role,
      "--thread",
      options.thread ?? THREADS[role],
      "--host",
      "local",
      "--attempt",
      String(attempt),
      ...(options.leaseMs ? ["--lease-ms", String(options.leaseMs)] : []),
      ...launchArgs,
      capabilityFlag,
      parent as string,
      "--json",
    ],
    fixture.root,
    fixture.controlDir
  );
  if (result.code !== 0) {
    throw new Error(`expected ${role} registration to succeed: ${result.stderr || result.stdout}`);
  }
  expect(result.code).toBe(0);
  const value = json(result);
  fixture.capabilities[task][role] = String(value.actor_capability_file);
  if (["DEV", "REVIEW", "RECEIPT"].includes(role) && options.seedLaunch !== false) {
    seedLaunchRuntime(fixture, task, role, value);
  }
  return value;
}

function seedLaunchRuntime(
  fixture: GoalFixture,
  taskId: string,
  role: Role,
  registration: Record<string, unknown>,
  launchHead?: string
): void {
  const state = taskStatus(fixture, taskId);
  const session = registration.session as {
    launch_id: string;
    task_nonce: string;
    thread_id: string;
    host_id: string;
    registered_state_revision: number;
    activated_state_revision?: number;
  };
  const runtimeHead = launchHead ?? state.full_head;
  const launch: Record<string, unknown> = {
    schema_version: 1,
    launch_id: session.launch_id,
    goal_id: "demo",
    task_id: taskId,
    role,
    control_epoch: state.control_epoch,
    state_revision: session.registered_state_revision,
    thread: { id: session.thread_id, host_id: session.host_id, cwd: fixture.root },
    packet: {
      revision: state.packet.revision,
      path: `docs/planning/goals/demo/packets/${taskId}-r${state.packet.revision}.md`,
      sha256: state.packet.sha256,
    },
    repository: {
      name_with_owner: "example-org/example-repo",
      origin_url: "https://github.com/example-org/example-repo.git",
      base_branch: "main",
      base_head: state.base_head,
      full_head: runtimeHead,
      branch: git(fixture.root, "branch", "--show-current"),
      root: fixture.root,
      worktree: fixture.root,
    },
    runtime: {
      node_version: process.version,
      pnpm_version: "10.0.0-test",
      lockfile_sha256: sha256("fixture lockfile"),
    },
    execution: {
      environment: "none",
      write_mode: "NONE",
      task_nonce: session.task_nonce,
      target: { kind: "NONE" },
    },
    ...(role === "REVIEW" || role === "RECEIPT" ? {
      pull_request: {
        repository: "example-org/example-repo",
        number: 999,
        base: "main",
        head: runtimeHead,
      },
    } : {}),
    resource_leases: [],
    created_at: "2026-07-22T00:00:00.000Z",
  };
  const dir = path.join(fixture.controlDir, "goals", "demo", "launches", taskId);
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, `${session.launch_id}.json`), `${JSON.stringify(launch, null, 2)}\n`);
}

function initAndRegister(fixture: GoalFixture): void {
  initGoal(fixture);
  registerRole(fixture, "FOREMAN");
  registerRole(fixture, "CAPTAIN");
}

type TaskStatus = {
  task_id: string;
  phase: string;
  state_revision: number;
  control_epoch: number;
  base_head: string;
  full_head: string;
  packet: { revision: number; sha256: string };
  task_cycle?: number;
  p1?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
  pr?: string | null;
  holds?: Array<{ hold_id: string; kind: string }>;
  merge?: Record<string, unknown> | null;
  last_event?: {
    event_id: string;
    type: string;
    event_sha256: string;
  } | null;
  recovery?: { role: Role; successor_thread_id?: string } | null;
  recovery_backlog?: Array<{ role: Role; successor_thread_id?: string }>;
  reconcile_required?: Record<string, unknown> | null;
  operational_scope?: string | null;
  next_actions?: Array<{ type: string; actor_role: string }>;
  maintenance_actions?: Array<Record<string, unknown>>;
  sessions?: Partial<Record<Role, {
    thread_id: string;
    host_id: string;
    attempt: number;
    status: string;
    lease_until: string;
    launch_id?: string | null;
    task_nonce?: string | null;
    registered_state_revision?: number;
    registered_full_head?: string;
    activated_state_revision?: number;
    terminal_reason?: string;
    recovered_from?: {
      role: Role;
      thread_id: string;
      host_id: string;
      attempt: number;
      resume_phase: string;
      recovered_at: string;
    };
  }>>;
  session_history?: Partial<Record<Role, Array<{
    thread_id: string;
    host_id: string;
    attempt: number;
    status: string;
    lease_until: string;
  }>>>;
};

const recoveryScopeByTaskStatus = new WeakMap<object, string>();

function taskStatus(fixture: GoalFixture, taskId = "TASK-A"): TaskStatus {
  return withInProcessGoalCliFixtureSetup(() => {
    const result = runCli(["status", "--goal", "demo", "--json"], fixture.root, fixture.controlDir);
    if (result.code !== 0) {
      throw new Error(`status failed: ${result.stderr || result.stdout}`);
    }
    const body = json(result) as {
      tasks?: TaskStatus[] | Record<string, TaskStatus>;
      task?: TaskStatus;
      foreman_recovery_scope?: { scope_sha256?: string };
    };
    const task = Array.isArray(body.tasks)
      ? body.tasks.find((candidate) => candidate.task_id === taskId)
      : body.tasks?.[taskId] ?? body.task;
    expect(task).toBeDefined();
    if (body.foreman_recovery_scope?.scope_sha256) {
      recoveryScopeByTaskStatus.set(
        task as object,
        body.foreman_recovery_scope.scope_sha256,
      );
    }
    return task as TaskStatus;
  });
}

type EventOverrides = {
  eventId?: string;
  taskId?: "TASK-A" | "TASK-B";
  actorSequence?: number;
  expectedStateRevision?: number;
  controlEpoch?: number;
  packetRevision?: number;
  packetHash?: string;
  baseHead?: string;
  fullHead?: string;
  threadId?: string;
  hostId?: string;
  payload?: Record<string, unknown>;
};

function buildEvent(
  fixture: GoalFixture,
  type: string,
  role: Role,
  actorSequence: number,
  overrides: EventOverrides = {}
): Record<string, unknown> {
  const taskId = overrides.taskId ?? "TASK-A";
  const state = taskStatus(fixture, taskId);
  const requestedPayload = overrides.payload ?? {};
  const targetRole = type === "ROLE_LOST"
    ? requestedPayload.role as Role | undefined
    : undefined;
  const hasExplicitRoleLostTarget = [
    "expected_thread_id",
    "expected_host_id",
    "expected_attempt",
    "expected_lease_until",
  ].some((field) => Object.prototype.hasOwnProperty.call(
    requestedPayload,
    field,
  ));
  const targetSession = targetRole
    ? state.sessions?.[targetRole]
    : undefined;
  const payload = type === "ROLE_LOST"
    && targetSession
    && !hasExplicitRoleLostTarget
    ? {
      ...requestedPayload,
      expected_thread_id: targetSession.thread_id,
      expected_host_id: targetSession.host_id,
      expected_attempt: targetSession.attempt,
      expected_lease_until: targetSession.lease_until,
    }
    : requestedPayload;
  return {
    schema_version: 1,
    event_id: overrides.eventId ?? randomUUID(),
    goal_id: "demo",
    task_id: taskId,
    type,
    actor: {
      role,
      thread_id: overrides.threadId ?? THREADS[role],
      host_id: overrides.hostId ?? "local",
    },
    actor_sequence: overrides.actorSequence ?? actorSequence,
    expected_state_revision: overrides.expectedStateRevision ?? state.state_revision,
    control_epoch: overrides.controlEpoch ?? state.control_epoch,
    packet: {
      revision: overrides.packetRevision ?? state.packet.revision,
      sha256: overrides.packetHash ?? state.packet.sha256,
    },
    base_head: overrides.baseHead ?? state.base_head,
    full_head: overrides.fullHead ?? state.full_head,
    payload,
  };
}

function submitEvent(
  fixture: GoalFixture,
  event: Record<string, unknown>,
  actorCapabilityFile?: string,
): CliResult {
  const inputDir = path.join(fixture.controlDir, "inputs");
  mkdirSync(inputDir, { recursive: true });
  const file = path.join(inputDir, `${randomUUID()}.json`);
  writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);
  const actor = event.actor as { role: Role };
  const taskId = String(event.task_id);
  return runCli([
    "event", "--goal", "demo", "--file", file,
    "--actor-capability-file",
    actorCapabilityFile ?? fixture.capabilities[taskId][actor.role] as string,
    "--json",
  ], fixture.root, fixture.controlDir);
}

function expectControlError(result: CliResult, code: string): void {
  expect(result.code).not.toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toContain(code);
}

function expectExactCliControlErrorNoEcho(
  result: CliResult,
  code: string,
  message: string,
  forbiddenValues: string[],
): void {
  expect(message.trim()).not.toHaveLength(0);
  expect(result).toEqual({
    code: 2,
    stdout: "",
    stderr: `goalctl[${code}]: ${message}\n`,
  });
  const serialized = JSON.stringify(result);
  for (const forbidden of forbiddenValues) {
    expect(forbidden).not.toHaveLength(0);
    expect(serialized).not.toContain(forbidden);
  }
}

function expectSerializedSurfaceNoEcho(
  value: unknown,
  forbiddenValues: string[],
): void {
  const serialized = JSON.stringify(value);
  for (const forbidden of forbiddenValues) {
    expect(forbidden).not.toHaveLength(0);
    expect(serialized).not.toContain(forbidden);
  }
}

type RecoverForemanOverrides = {
  snapshot?: TaskStatus;
  taskId?: "TASK-A" | "TASK-B";
  eventId?: string;
  controllerCwd?: string;
  repositoryWorktree?: string;
  capabilityFile?: string;
  expectedControlEpoch?: number;
  expectedStateRevision?: number;
  expectedEventHead?: string;
  expectedPacketRevision?: number;
  expectedPacketSha256?: string;
  expectedFullHead?: string;
  expectedForemanThread?: string;
  expectedForemanHost?: string;
  expectedForemanAttempt?: number;
  expectedForemanLeaseUntil?: string;
  expectedGoalScopeSha256?: string;
  thread?: string;
  host?: string;
  attempt?: number;
};

function recoverExpiredForeman(
  fixture: GoalFixture,
  overrides: RecoverForemanOverrides = {}
): CliResult {
  const taskId = overrides.taskId ?? "TASK-A";
  const state = overrides.snapshot ?? taskStatus(fixture, taskId);
  const foreman = state.sessions?.FOREMAN;
  return runCli([
    "recover-expired-foreman",
    ...(overrides.repositoryWorktree
      ? ["--repository-worktree", overrides.repositoryWorktree]
      : []),
    "--goal", "demo",
    "--task", taskId,
    "--thread", overrides.thread ?? "foreman-a-2",
    "--host", overrides.host ?? "recovery-host",
    "--attempt", String(overrides.attempt ?? 2),
    "--lease-ms", "3600000",
    "--expected-goal-scope-sha256",
    overrides.expectedGoalScopeSha256
      ?? recoveryScopeByTaskStatus.get(state as object)
      ?? (() => {
        const status = json(runCli(
          ["status", "--goal", "demo", "--json"],
          fixture.root,
          fixture.controlDir,
        )) as { foreman_recovery_scope?: { scope_sha256?: string } };
        return status.foreman_recovery_scope?.scope_sha256 as string;
      })(),
    "--expected-control-epoch", String(overrides.expectedControlEpoch ?? state.control_epoch),
    "--expected-state-revision", String(overrides.expectedStateRevision ?? state.state_revision),
    ...(state.last_event?.event_sha256 || overrides.expectedEventHead
      ? ["--expected-event-head", overrides.expectedEventHead ?? state.last_event?.event_sha256 as string]
      : []),
    "--expected-packet-revision", String(overrides.expectedPacketRevision ?? state.packet.revision),
    "--expected-packet-sha256", overrides.expectedPacketSha256 ?? state.packet.sha256,
    "--expected-full-head", overrides.expectedFullHead ?? state.full_head,
    ...(foreman || overrides.expectedForemanThread
      ? [
        "--expected-foreman-thread", overrides.expectedForemanThread ?? foreman?.thread_id as string,
        "--expected-foreman-host", overrides.expectedForemanHost ?? foreman?.host_id as string,
        "--expected-foreman-attempt", String(overrides.expectedForemanAttempt ?? foreman?.attempt),
        "--expected-foreman-lease-until",
        overrides.expectedForemanLeaseUntil ?? foreman?.lease_until as string,
      ]
      : []),
    "--reason", "all control-plane role leases expired",
    "--incident-ref", "incident://goal-control/simultaneous-expiry",
    "--foreman-recovery-capability-file",
    overrides.capabilityFile ?? fixture.foremanRecoveryCapability as string,
    "--event-id", overrides.eventId ?? `recover-${randomUUID()}`,
    "--json",
  ], overrides.controllerCwd ?? fixture.root, fixture.controlDir);
}

function expireRegisteredRoles(fixture: GoalFixture): void {
  const leases = Object.values(taskStatus(fixture).sessions ?? {})
    .map((session) => Date.parse(session.lease_until));
  expect(leases.length).toBeGreaterThan(0);
  expect(leases.every(Number.isFinite)).toBe(true);
  process.env.GOAL_CONTROL_NOW = new Date(Math.max(...leases) + 1).toISOString();
}

function workflowState(state: TaskStatus): Record<string, unknown> {
  return {
    phase: state.phase,
    control_epoch: state.control_epoch,
    task_cycle: state.task_cycle,
    base_head: state.base_head,
    full_head: state.full_head,
    packet: state.packet,
    p1: state.p1,
    evidence: state.evidence,
    pr: state.pr,
    holds: state.holds,
    merge: state.merge,
    reconcile_required: state.reconcile_required,
  };
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.keys(value as Record<string, unknown>).sort().reduce<Record<string, unknown>>((output, key) => {
      output[key] = canonicalize((value as Record<string, unknown>)[key]);
      return output;
    }, {});
  }
  return value;
}

function seedEvidence(
  fixture: GoalFixture,
  kind: string,
  producer: Role,
  status = "PASS",
  fullHead = fixture.fullHead,
  producerThread = THREADS[producer]
): string {
  const state = taskStatus(fixture);
  const evidenceId = `${kind.toLowerCase()}-${randomUUID()}`;
  const dir = path.join(fixture.controlDir, "goals", "demo", "evidence", "TASK-A");
  mkdirSync(dir, { recursive: true });
  const record: Record<string, unknown> = {
    schema_version: 1,
    evidence_id: evidenceId,
    goal_id: "demo",
    task_id: "TASK-A",
    kind,
    status,
    producer: { role: producer, thread_id: producerThread, host_id: "local" },
    state_revision: state.state_revision,
    packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
    packet_sha256: state.packet.sha256,
    base_head: state.base_head,
    full_head: fullHead,
    created_at: "2026-07-22T00:00:00.000Z",
    uri: `https://github.com/example-org/example-repo/actions/runs/${evidenceId}`,
  };
  if (["PREFLIGHT", "FAST", "FULL_CI", "AC_AUDIT"].includes(kind)) {
    record.attestation = { controller: "goalctl", adapter: kind };
    if (kind === "PREFLIGHT") {
      const activeLaunchId = state.sessions?.[producer]?.launch_id;
      if (!activeLaunchId) throw new Error(`active ${producer} launch missing`);
      const activeLaunch = path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "launches",
        "TASK-A",
        `${activeLaunchId}.json`
      );
      const artifactDir = path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "evidence-artifacts",
        "TASK-A",
      );
      mkdirSync(artifactDir, { recursive: true });
      const launchFile = path.join(artifactDir, `${evidenceId}-launch.json`);
      writeFileSync(launchFile, readFileSync(activeLaunch));
      record.launch_id = activeLaunchId;
      record.launch_uri = pathToFileURL(activeLaunch).href;
      record.launch_sha256 = sha256(readFileSync(activeLaunch, "utf8"));
    } else {
      const artifactFile = path.join(dir, `${evidenceId}-artifact.json`);
      writeFileSync(artifactFile, `${JSON.stringify({ kind, status }, null, 2)}\n`);
      record.uri = pathToFileURL(artifactFile).href;
      record.source_sha256 = sha256(readFileSync(artifactFile, "utf8"));
      if (["FULL_CI", "AC_AUDIT"].includes(kind)) {
        record.pull_request = {
          repository: "example-org/example-repo",
          number: 999,
          url: "https://github.com/example-org/example-repo/pull/999",
          base: "main",
          head: fullHead,
        };
      }
    }
  } else {
    const artifactFile = path.join(dir, `${evidenceId}-artifact.json`);
    writeFileSync(artifactFile, `${JSON.stringify({ kind, status }, null, 2)}\n`);
    record.uri = pathToFileURL(artifactFile).href;
    record.source_sha256 = sha256(readFileSync(artifactFile, "utf8"));
  }
  record.registry_sha256 = sha256(JSON.stringify(canonicalize(record)));
  writeFileSync(path.join(dir, `${evidenceId}.json`), `${JSON.stringify(record, null, 2)}\n`);
  return evidenceId;
}

function devEvidence(
  fixture: GoalFixture,
  preflightHead = fixture.fullHead,
  producerThread = THREADS.DEV
) {
  return {
    preflight: seedEvidence(fixture, "PREFLIGHT", "DEV", "PASS", preflightHead, producerThread),
    fast: seedEvidence(fixture, "FAST", "DEV", "PASS", fixture.fullHead, producerThread),
    full_ci: seedEvidence(fixture, "FULL_CI", "CAPTAIN"),
    ac_audit: seedEvidence(fixture, "AC_AUDIT", "CAPTAIN"),
  };
}

type SequenceBook = Record<Role, number>;

function sequences(): SequenceBook {
  return { FOREMAN: 0, CAPTAIN: 0, DEV: 0, REVIEW: 0, RECEIPT: 0 };
}

function apply(
  fixture: GoalFixture,
  book: SequenceBook,
  type: string,
  role: Role,
  overrides: EventOverrides = {}
): { event: Record<string, unknown>; result: CliResult } {
  return withInProcessGoalCliFixtureSetup(() => {
    book[role] += 1;
    const event = buildEvent(fixture, type, role, book[role], overrides);
    const result = submitEvent(fixture, event);
    if (result.code !== 0) throw new Error(`expected ${type} to succeed: ${result.stderr || result.stdout}`);
    expect(result.code).toBe(0);
    return { event, result };
  });
}

const PLAN_HASH = sha256(PLAN_BODY);
const CONTEXT_HASH = sha256(CONTEXT_BODY);

function p1Payload(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    plan_path: PLAN_PATH,
    plan_sha256: PLAN_HASH,
    context_path: CONTEXT_PATH,
    context_sha256: CONTEXT_HASH,
    ...extra,
  };
}

function advanceToDevActive(fixture: GoalFixture, book: SequenceBook): string {
  apply(fixture, book, "START_P1", "CAPTAIN");
  apply(fixture, book, "P1_READY", "CAPTAIN", {
    payload: p1Payload(),
  });
  const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
    payload: p1Payload({ approval_ref: "user://issue-4242/approved" }),
  });
  const approvalId = String(approval.event.event_id);
  apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
    fullHead: fixture.fullHead,
    payload: p1Payload({ approval_event_id: approvalId }),
  });
  registerRole(fixture, "DEV");
  apply(fixture, book, "LAUNCH_DEV", "CAPTAIN", { payload: { launch_id: "launch-dev-1" } });
  return approvalId;
}

function prepareRuntimePreflightRepository(fixture: GoalFixture): void {
  writeFileSync(
    path.join(fixture.root, "pnpm-lock.yaml"),
    "lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n",
  );
  git(fixture.root, "add", "pnpm-lock.yaml");
  git(fixture.root, "commit", "-qm", "add runtime preflight lockfile");
  git(
    fixture.root,
    "remote",
    "add",
    "origin",
    "https://github.com/example-org/example-repo.git",
  );
  fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");
}

function processStartedAt(pid: number): string {
  const ps = existsSync("/bin/ps") ? "/bin/ps" : "/usr/bin/ps";
  const started = execFileSync(
    ps,
    ["-p", String(pid), "-o", "lstart="],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        TZ: "UTC",
        NODE_ENV: "test",
      },
    },
  ).trim();
  return new Date(Date.parse(`${started} UTC`)).toISOString();
}

async function stopChild(child: ReturnType<typeof spawn>): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const force = setTimeout(() => child.kill("SIGKILL"), 2000);
    child.once("exit", () => {
      clearTimeout(force);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

function rolePreviewLaunch(
  fixture: GoalFixture,
  role: "REVIEW" | "RECEIPT",
  registration: Record<string, unknown>,
  runtime: {
    pid: number;
    startedAt: string;
    previewPort: number;
  },
): Record<string, unknown> {
  const state = taskStatus(fixture);
  const session = registration.session as {
    launch_id: string;
    task_nonce: string;
    thread_id: string;
    host_id: string;
    registered_state_revision: number;
  };
  return {
    schema_version: 1,
    launch_id: session.launch_id,
    goal_id: "demo",
    task_id: "TASK-A",
    role,
    control_epoch: state.control_epoch,
    state_revision: session.registered_state_revision,
    thread: {
      id: session.thread_id,
      host_id: session.host_id,
      cwd: fixture.root,
    },
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
      branch: git(fixture.root, "branch", "--show-current"),
      root: fixture.root,
      worktree: fixture.root,
    },
    runtime: {
      node_version: process.version,
      pnpm_version: execFileSync("pnpm", ["--version"], {
        encoding: "utf8",
      }).trim(),
      lockfile_sha256: sha256(
        readFileSync(path.join(fixture.root, "pnpm-lock.yaml")),
      ),
    },
    execution: {
      environment: "none",
      write_mode: "NONE",
      task_nonce: session.task_nonce,
      target: {
        kind: "PREVIEW",
        executable_path: realpathSync(process.execPath),
        pid: runtime.pid,
        started_at: runtime.startedAt,
        preview_url: `http://127.0.0.1:${runtime.previewPort}`,
        build_head: state.full_head,
      },
    },
    pull_request: {
      repository: "example-org/example-repo",
      number: 999,
      base: "main",
      head: state.full_head,
    },
    resource_leases: [],
    created_at: runtime.startedAt,
  };
}

function enterRuntimeWorkerPhase(
  fixture: GoalFixture,
  book: SequenceBook,
  role: "REVIEW" | "RECEIPT",
): Record<string, unknown> {
  advanceToDevActive(fixture, book);
  apply(fixture, book, "DEV_READY", "DEV", {
    fullHead: fixture.fullHead,
    payload: {
      pr: "https://github.com/example-org/example-repo/pull/999",
      evidence: devEvidence(fixture),
    },
  });
  if (role === "REVIEW") {
    return registerRole(fixture, "REVIEW", { seedLaunch: false });
  }
  registerRole(fixture, "REVIEW");
  apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", {
    payload: { launch_id: "launch-review-1" },
  });
  apply(fixture, book, "REVIEW_PASS", "REVIEW", {
    payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW") },
  });
  return registerRole(fixture, "RECEIPT", { seedLaunch: false });
}

function advanceDevActiveToArchived(
  fixture: GoalFixture,
  book: SequenceBook,
  beforeArchive?: () => void,
): void {
  apply(fixture, book, "DEV_READY", "DEV", {
    fullHead: fixture.fullHead,
    payload: {
      pr: "https://github.com/example-org/example-repo/pull/999",
      evidence: devEvidence(fixture),
    },
  });
  registerRole(fixture, "REVIEW");
  apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", {
    payload: { launch_id: "launch-review-1" },
  });
  apply(fixture, book, "REVIEW_PASS", "REVIEW", {
    payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW") },
  });
  registerRole(fixture, "RECEIPT");
  apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", {
    payload: { launch_id: "launch-receipt-1" },
  });
  apply(fixture, book, "RECEIPT_PASS", "RECEIPT", {
    payload: { evidence: seedEvidence(fixture, "RECEIPT", "RECEIPT") },
  });
  apply(fixture, book, "READY_FOR_MERGE", "CAPTAIN");
  apply(fixture, book, "MERGED", "FOREMAN", {
    payload: {
      expected_main_head: fixture.baseHead,
      main_merge_sha: fixture.fullHead,
    },
  });
  if (beforeArchive) beforeArchive();
  const archiveEvidence = seedEvidence(
    fixture,
    "MERGE_BOUNDARY",
    "FOREMAN",
  );
  apply(fixture, book, "ARCHIVED", "FOREMAN", {
    payload: { evidence_id: archiveEvidence },
  });
  expect(taskStatus(fixture).phase).toBe("ARCHIVED");
}

function expectDirectControlError(callback: () => unknown, code: string): void {
  try {
    callback();
    throw new Error(`expected ${code}`);
  } catch (error: unknown) {
    if ((error as { code?: string }).code !== code) throw error;
    expect((error as { code?: string }).code).toBe(code);
  }
}

function withDirectControl<T>(fixture: GoalFixture, callback: () => T): T {
  const previousControlDir = process.env.GOAL_CONTROL_DIR;
  const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
  process.env.GOAL_CONTROL_DIR = fixture.controlDir;
  process.env.GOAL_CONTROL_TEST_MODE = "1";
  try {
    return callback();
  } finally {
    if (previousControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
    else process.env.GOAL_CONTROL_DIR = previousControlDir;
    if (previousTestMode === undefined) delete process.env.GOAL_CONTROL_TEST_MODE;
    else process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
  }
}

function enableGithubMergePolicy(fixture: GoalFixture): void {
  const manifest = JSON.parse(readFileSync(fixture.manifest, "utf8"));
  manifest.repository.merge_policy = "goalctl-github-squash-v1";
  manifest.tasks[0].issue = 4242;
  writeFileSync(fixture.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
  git(fixture.root, "add", fixture.manifest);
  git(fixture.root, "commit", "-qm", "enable canonical github merge");
  fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");
}

function advanceToReadyForCanonicalMerge(
  fixture: GoalFixture,
  book: SequenceBook,
): void {
  advanceToDevActive(fixture, book);
  apply(fixture, book, "DEV_READY", "DEV", {
    fullHead: fixture.fullHead,
    payload: {
      pr: "https://github.com/example-org/example-repo/pull/999",
      evidence: devEvidence(fixture),
    },
  });
  registerRole(fixture, "REVIEW");
  apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", {
    payload: { launch_id: "launch-review-1" },
  });
  apply(fixture, book, "REVIEW_PASS", "REVIEW", {
    payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW") },
  });
  registerRole(fixture, "RECEIPT");
  apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", {
    payload: { launch_id: "launch-receipt-1" },
  });
  apply(fixture, book, "RECEIPT_PASS", "RECEIPT", {
    payload: { evidence: seedEvidence(fixture, "RECEIPT", "RECEIPT") },
  });
  apply(fixture, book, "READY_FOR_MERGE", "CAPTAIN");
}

function prepareReadyForCanonicalMerge(fixture: GoalFixture): SequenceBook {
  enableGithubMergePolicy(fixture);
  return withInProcessGoalCliFixtureSetup(() => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToReadyForCanonicalMerge(fixture, book);
    return book;
  });
}

type FakeGithub = {
  dependencies: Record<string, unknown>;
  remote: string;
  mergeCalls: () => number;
  argv: () => string[][];
};

function fakeGithub(
  fixture: GoalFixture,
  options: {
    permission?: string;
    body?: string;
    head?: string;
    base?: string;
    draft?: boolean;
    crossRepository?: boolean;
    closingIssue?: number;
    closingRepository?: string;
    checksExit?: number;
    squashMergeAllowed?: boolean;
    remoteOnlyMergeCommit?: boolean;
  } = {},
): FakeGithub {
  const remote = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-control-goalctl-remote-")),
  );
  execFileSync("git", ["init", "--bare", "-q", remote]);
  git(fixture.root, "remote", "add", "origin", remote);
  git(
    fixture.root,
    "push",
    "-q",
    "origin",
    `${fixture.baseHead}:refs/heads/main`,
  );
  if (options.remoteOnlyMergeCommit) {
    git(
      fixture.root,
      "push",
      "-q",
      "origin",
      `${fixture.fullHead}:refs/heads/codex/task-a`,
    );
  }
  let state = "OPEN";
  let mergeSha: string | null = null;
  let mergeCount = 0;
  const calls: string[][] = [];
  const expectedHead = options.head ?? fixture.fullHead;
  const pr = (): Record<string, unknown> => ({
    number: 999,
    url: "https://github.com/example-org/example-repo/pull/999",
    state,
    isDraft: options.draft ?? false,
    baseRefName: "main",
    baseRefOid: options.base ?? fixture.baseHead,
    headRefName: "codex/task-a",
    headRefOid: expectedHead,
    headRepository: {
      nameWithOwner: "example-org/example-repo",
    },
    headRepositoryOwner: { login: "example-org" },
    isCrossRepository: options.crossRepository ?? false,
    mergeCommit: mergeSha ? { oid: mergeSha } : null,
    mergedAt: mergeSha ? "2026-07-24T00:00:00Z" : null,
    mergedBy: mergeSha ? { login: "goalctl-test" } : null,
    mergeable: state === "OPEN" ? "MERGEABLE" : "UNKNOWN",
    mergeStateStatus: state === "OPEN" ? "CLEAN" : "UNKNOWN",
    statusCheckRollup: [{
      __typename: "CheckRun",
      name: "Quality Gate (Full)",
      status: "COMPLETED",
      conclusion: "SUCCESS",
    }],
    closingIssuesReferences: [{
      number: options.closingIssue ?? 4242,
      repository: {
        nameWithOwner: options.closingRepository ?? "example-org/example-repo",
      },
    }],
    body: options.body ?? "Implements the accepted plan.\n\nCloses #4242\n",
  });
  const runner = (
    _executable: string,
    args: string[],
  ): Record<string, unknown> => {
    calls.push([...args]);
    if (args[0] === "auth" && args[1] === "status") {
      return { status: 0, stdout: "authenticated\n", stderr: "", signal: null };
    }
    if (args[0] === "repo" && args[1] === "view") {
      return {
        status: 0,
        stdout: JSON.stringify({
          nameWithOwner: "example-org/example-repo",
          defaultBranchRef: { name: "main" },
          viewerPermission: options.permission ?? "WRITE",
          squashMergeAllowed: options.squashMergeAllowed ?? true,
          isArchived: false,
        }),
        stderr: "",
        signal: null,
      };
    }
    if (args[0] === "pr" && args[1] === "checks") {
      return {
        status: options.checksExit ?? 0,
        stdout: options.checksExit ? "" : "required checks pass\n",
        stderr: options.checksExit ? "sensitive provider failure" : "",
        signal: null,
      };
    }
    if (args[0] === "pr" && args[1] === "view") {
      return { status: 0, stdout: JSON.stringify(pr()), stderr: "", signal: null };
    }
    if (args[0] === "pr" && args[1] === "merge") {
      mergeCount += 1;
      expect(args).toEqual([
        "pr", "merge", "999",
        "--repo", "example-org/example-repo",
        "--squash",
        "--match-head-commit", fixture.fullHead,
      ]);
      expect(args).not.toEqual(expect.arrayContaining(["--admin", "--auto", "--delete-branch"]));
      if (!mergeSha) {
        if (options.remoteOnlyMergeCommit) {
          const tree = execFileSync(
            "git",
            [`--git-dir=${remote}`, "rev-parse", `${fixture.fullHead}^{tree}`],
            { encoding: "utf8" },
          ).trim();
          mergeSha = execFileSync(
            "git",
            [
              `--git-dir=${remote}`,
              "commit-tree",
              tree,
              "-p",
              fixture.baseHead,
              "-m",
              "squash task A",
            ],
            {
              encoding: "utf8",
              env: {
                ...process.env,
                GIT_AUTHOR_NAME: "goalctl test",
                GIT_AUTHOR_EMAIL: "goalctl@example.test",
                GIT_COMMITTER_NAME: "goalctl test",
                GIT_COMMITTER_EMAIL: "goalctl@example.test",
              },
            },
          ).trim();
          execFileSync(
            "git",
            [
              `--git-dir=${remote}`,
              "update-ref",
              "refs/heads/main",
              mergeSha,
              fixture.baseHead,
            ],
          );
        } else {
          const tree = git(fixture.root, "rev-parse", `${fixture.fullHead}^{tree}`);
          mergeSha = git(
            fixture.root,
            "commit-tree",
            tree,
            "-p",
            fixture.baseHead,
            "-m",
            "squash task A",
          );
          git(
            fixture.root,
            "push",
            "-q",
            "origin",
            `${mergeSha}:refs/heads/main`,
          );
        }
      }
      state = "MERGED";
      return { status: 0, stdout: "merged\n", stderr: "", signal: null };
    }
    return { status: 1, stdout: "", stderr: "unexpected fake gh call", signal: null };
  };
  return {
    remote,
    mergeCalls: () => mergeCount,
    argv: () => calls,
    dependencies: {
      resolveExecutable: () => ({
        executable: process.execPath,
        path_dir: path.dirname(process.execPath),
      }),
      originRepository: "example-org/example-repo",
      runner,
    },
  };
}

function canonicalMergeOptions(fixture: GoalFixture): Record<string, unknown> {
  const state = taskStatus(fixture);
  return {
    goalId: "demo",
    taskId: "TASK-A",
    threadId: THREADS.FOREMAN,
    eventId: "merge-task-a-stable",
    expectedStateRevision: state.state_revision,
    expectedControlEpoch: state.control_epoch,
    actorCapabilityFile: fixture.capabilities["TASK-A"].FOREMAN,
  };
}

function mergeIntentFile(
  fixture: GoalFixture,
  eventId = "merge-task-a-stable",
): string {
  return path.join(
    fixture.controlDir,
    "goals",
    "demo",
    "github-merge-intents",
    "TASK-A",
    `${eventId}.json`,
  );
}

function mergeArtifactFile(
  fixture: GoalFixture,
  stage: "intent" | "invocation" | "receipt" | "completion",
  eventId = "merge-task-a-stable",
): string {
  const directories = {
    intent: "github-merge-intents",
    invocation: "github-merge-invocations",
    receipt: "github-merge-receipts",
    completion: "github-merge-completions",
  };
  return path.join(
    fixture.controlDir,
    "goals",
    "demo",
    directories[stage],
    "TASK-A",
    `${eventId}.json`,
  );
}

function resealRecord(
  record: Record<string, unknown>,
  sealKey: string,
): Record<string, unknown> {
  const unsigned = { ...record };
  delete unsigned[sealKey];
  return {
    ...unsigned,
    [sealKey]: sha256(JSON.stringify(canonicalize(unsigned))),
  };
}

function removeMergeSidebands(fixture: GoalFixture): void {
  for (const stage of ["intent", "invocation", "receipt", "completion"] as const) {
    rmSync(path.dirname(mergeArtifactFile(fixture, stage)), {
      recursive: true,
      force: true,
    });
  }
}

function mergeAtomicTemp(file: string, suffix = "a".repeat(24)): string {
  return path.join(
    path.dirname(file),
    `.${path.basename(file)}.${process.pid}.tmp-${suffix}`,
  );
}

function sigkillMergeTransactionAfterGeneration(
  fixture: GoalFixture,
  options: Record<string, unknown>,
): void {
  const program = [
    `const { canonicalTransactionKey, withLock } = require(${JSON.stringify(
      path.join(ROOT, "scripts", "goal-control", "store.js"),
    )});`,
    `const { hashObject } = require(${JSON.stringify(
      path.join(ROOT, "scripts", "goal-control", "util.js"),
    )});`,
    `const options = ${JSON.stringify(options)};`,
    `const request = {
      schema_version: 1,
      kind: "GITHUB_MERGE_REQUEST",
      goal_id: options.goalId,
      task_id: options.taskId,
      event_id: options.eventId,
      foreman_thread_id: options.threadId,
      expected_state_revision: Number(options.expectedStateRevision),
      expected_control_epoch: Number(options.expectedControlEpoch),
    };`,
    `const key = canonicalTransactionKey(
      "GITHUB_MERGE",
      { goal_id: String(options.goalId), task_id: String(options.taskId) },
      String(options.eventId),
      hashObject(request),
    );`,
    `withLock(
      ${JSON.stringify(fixture.controlDir)},
      () => process.exit(91),
      {
        transactionKey: key,
        afterGenerationBeforeCallback: () =>
          process.kill(process.pid, "SIGKILL"),
      },
    );`,
    `process.exit(92);`,
  ].join("\n");
  const result = spawnSync(process.execPath, ["-e", program], {
    cwd: fixture.root,
    encoding: "utf8",
    stdio: "pipe",
    timeout: 10_000,
    env: {
      ...process.env,
      GOAL_CONTROL_DIR: fixture.controlDir,
      GOAL_CONTROL_TEST_MODE: "1",
    },
  });
  expect(result.status).toBeNull();
  expect(result.signal).toBe("SIGKILL");
}

function sigkillFreshMergeAfterGeneration(
  fixture: GoalFixture,
  options: Record<string, unknown>,
): void {
  const pullRequest = {
    number: 999,
    url: "https://github.com/example-org/example-repo/pull/999",
    state: "OPEN",
    isDraft: false,
    baseRefName: "main",
    baseRefOid: fixture.baseHead,
    headRefName: "codex/task-a",
    headRefOid: fixture.fullHead,
    headRepository: { nameWithOwner: "example-org/example-repo" },
    headRepositoryOwner: { login: "example-org" },
    isCrossRepository: false,
    mergeCommit: null,
    mergedAt: null,
    mergedBy: null,
    mergeable: "MERGEABLE",
    mergeStateStatus: "CLEAN",
    statusCheckRollup: [{
      __typename: "CheckRun",
      name: "Quality Gate (Full)",
      status: "COMPLETED",
      conclusion: "SUCCESS",
    }],
    closingIssuesReferences: [{
      number: 4242,
      repository: { nameWithOwner: "example-org/example-repo" },
    }],
    body: "Implements the accepted plan.\n\nCloses #4242\n",
  };
  const program = [
    `const path = require("path");`,
    `const { mergePullRequest } = require(${JSON.stringify(
      path.join(ROOT, "scripts", "goal-control", "github-merge.js"),
    )});`,
    `const pullRequest = ${JSON.stringify(pullRequest)};`,
    `const runner = (_executable, args) => {
      if (args[0] === "auth" && args[1] === "status") {
        return { status: 0, stdout: "authenticated\\n", stderr: "", signal: null };
      }
      if (args[0] === "repo" && args[1] === "view") {
        return {
          status: 0,
          stdout: JSON.stringify({
            nameWithOwner: "example-org/example-repo",
            defaultBranchRef: { name: "main" },
            viewerPermission: "WRITE",
            squashMergeAllowed: true,
            isArchived: false,
          }),
          stderr: "",
          signal: null,
        };
      }
      if (args[0] === "pr" && args[1] === "checks") {
        return { status: 0, stdout: "required checks pass\\n", stderr: "", signal: null };
      }
      if (args[0] === "pr" && args[1] === "view") {
        return {
          status: 0,
          stdout: JSON.stringify(pullRequest),
          stderr: "",
          signal: null,
        };
      }
      if (args[0] === "pr" && args[1] === "merge") process.exit(94);
      return { status: 1, stdout: "", stderr: "unexpected command", signal: null };
    };`,
    `mergePullRequest(
      ${JSON.stringify(fixture.root)},
      ${JSON.stringify(options)},
      {
        resolveExecutable: () => ({
          executable: process.execPath,
          path_dir: path.dirname(process.execPath),
        }),
        originRepository: "example-org/example-repo",
        runner,
        afterGenerationBeforeCallback: () =>
          process.kill(process.pid, "SIGKILL"),
      },
    );`,
    `process.exit(95);`,
  ].join("\n");
  const result = spawnSync(process.execPath, ["-e", program], {
    cwd: fixture.root,
    encoding: "utf8",
    stdio: "pipe",
    timeout: 20_000,
    env: {
      ...process.env,
      GOAL_CONTROL_DIR: fixture.controlDir,
      GOAL_CONTROL_TEST_MODE: "1",
    },
  });
  expect(result.status).toBeNull();
  expect(result.signal).toBe("SIGKILL");
}

function downgradeOddGenerationToV2(fixture: GoalFixture): void {
  const generationFile = path.join(
    fixture.controlDir,
    ".generation.json",
  );
  const current = JSON.parse(
    readFileSync(generationFile, "utf8"),
  ) as Record<string, unknown>;
  expect(current.schema_version).toBe(3);
  expect(Number(current.generation) % 2).toBe(1);
  const unsigned = {
    schema_version: 2,
    generation: current.generation,
    active_transaction: current.active_transaction,
    updated_at: current.updated_at,
  };
  // The v3 generation file may be hard-linked to its durable publication
  // marker. A legacy decoder would publish a replacement inode; truncating the
  // canonical path in place would corrupt that marker too and construct an
  // impossible crash state.
  const replacement = path.join(
    fixture.controlDir,
    `.generation-v2-${randomUUID()}.json`,
  );
  writeFileSync(
    replacement,
    `${JSON.stringify({
      ...unsigned,
      seal_sha256: sha256(JSON.stringify(canonicalize(unsigned))),
    }, null, 2)}\n`,
    { mode: 0o600 },
  );
  renameSync(replacement, generationFile);
}

describe("scripts/goalctl.js", () => {
  let fixture: GoalFixture;
  let nodeCompileCache: string;
  let previousNodeCompileCache: string | undefined;
  let previousNodeDisableCompileCache: string | undefined;

  beforeAll(() => {
    previousNodeCompileCache = process.env.NODE_COMPILE_CACHE;
    previousNodeDisableCompileCache =
      process.env.NODE_DISABLE_COMPILE_CACHE;
    nodeCompileCache = mkdtempSync(
      path.join(tmpdir(), "goal-control-goalctl-node-compile-cache-"),
    );
    process.env.NODE_COMPILE_CACHE = nodeCompileCache;
    delete process.env.NODE_DISABLE_COMPILE_CACHE;
  });

  afterAll(() => {
    if (previousNodeCompileCache === undefined) {
      delete process.env.NODE_COMPILE_CACHE;
    } else {
      process.env.NODE_COMPILE_CACHE = previousNodeCompileCache;
    }
    if (previousNodeDisableCompileCache === undefined) {
      delete process.env.NODE_DISABLE_COMPILE_CACHE;
    } else {
      process.env.NODE_DISABLE_COMPILE_CACHE =
        previousNodeDisableCompileCache;
    }
    rmSync(nodeCompileCache, { recursive: true, force: true });
    if (goalRepoTemplate !== undefined) {
      rmSync(goalRepoTemplate.root, { recursive: true, force: true });
      goalRepoTemplate = undefined;
    }
  });

  beforeEach(() => {
    delete process.env.GOAL_CONTROL_NOW;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_INTENT_INSTALL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_TASK_EVENT_INSTALL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_INTENT_INSTALL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_STAGING_SEAL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_STAGING_SEAL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_BEFORE_BOOTSTRAP_CONSUMPTION_MARKER;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_BOOTSTRAP_CONSUMPTION_MARKER;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_BOOTSTRAP_CAPABILITY_DELETE;
    fixture = makeGoalRepo();
  });

  afterEach(() => {
    delete process.env.GOAL_CONTROL_NOW;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_INTENT_INSTALL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_TASK_EVENT_INSTALL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_INTENT_INSTALL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_STAGING_SEAL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_STAGING_SEAL;
    delete process.env.GOAL_CONTROL_TEST_FAULT_BEFORE_BOOTSTRAP_CONSUMPTION_MARKER;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_BOOTSTRAP_CONSUMPTION_MARKER;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_BOOTSTRAP_CAPABILITY_DELETE;
    rmSync(fixture.root, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
  });

  it("bootstrap-v1 initializes a machine-readable goal in the isolated control directory", () => {
    const result = runCli(["init", "--manifest", fixture.manifest, "--json"], fixture.root, fixture.controlDir);

    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ goal_id: "demo", initialized: true });
    expect(taskStatus(fixture)).toMatchObject({ phase: "QUEUED", state_revision: 0 });
  });

  it("keeps legacy non-mechanical P1_COMMITTED writable on an even generation", () => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      payload: p1Payload(),
    });
    const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({ approval_ref: "user://legacy-p1/approved" }),
    });
    const committed = apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      fullHead: fixture.fullHead,
      payload: p1Payload({
        approval_event_id: approval.event.event_id,
      }),
    });

    expect(committed.result.code).toBe(0);
    expect(taskStatus(fixture).phase).toBe("P1_COMMITTED");
  });

  it.each([
    {
      hook: "GOAL_CONTROL_TEST_FAULT_BEFORE_BOOTSTRAP_CONSUMPTION_MARKER",
      code: "TEST_FAULT_BEFORE_BOOTSTRAP_CONSUMPTION_MARKER",
      marker: false,
      capability: true,
    },
    {
      hook: "GOAL_CONTROL_TEST_FAULT_AFTER_BOOTSTRAP_CONSUMPTION_MARKER",
      code: "TEST_FAULT_AFTER_BOOTSTRAP_CONSUMPTION_MARKER",
      marker: true,
      capability: true,
    },
    {
      hook: "GOAL_CONTROL_TEST_FAULT_AFTER_BOOTSTRAP_CAPABILITY_DELETE",
      code: "TEST_FAULT_AFTER_BOOTSTRAP_CAPABILITY_DELETE",
      marker: true,
      capability: false,
    },
  ])(
    "recovers BOOTSTRAP consumption response loss at $code",
    ({ hook, code, marker, capability }) => {
      initGoal(fixture);
      const eventId = `register-bootstrap-recovery-${randomUUID()}`;
      const registration = [
        "register-role",
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", "FOREMAN",
        "--thread", THREADS.FOREMAN,
        "--host", "local",
        "--attempt", "1",
        "--event-id", eventId,
        "--bootstrap-capability-file", fixture.bootstrapCapability as string,
        "--json",
      ];
      process.env[hook] = "throw";
      expectControlError(
        runCli(registration, fixture.root, fixture.controlDir),
        code,
      );
      delete process.env[hook];

      const metadataFile = path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "goal.json",
      );
      const interruptedMetadata = JSON.parse(
        readFileSync(metadataFile, "utf8"),
      ) as { bootstrap_consumed_at?: string };
      expect(typeof interruptedMetadata.bootstrap_consumed_at === "string")
        .toBe(marker);
      expect(existsSync(fixture.bootstrapCapability as string))
        .toBe(capability);

      // The failed writer deliberately leaves an odd generation crash marker.
      // Read-only commands must remain fail-closed until the original stable
      // operation is retried and reconciles the durable event/marker/capability
      // sequence.
      const retried = runCli(registration, fixture.root, fixture.controlDir);
      expect(retried.code).toBe(0);
      expect(json(retried)).toMatchObject({
        registered: true,
        idempotent: true,
        session: { thread_id: THREADS.FOREMAN, attempt: 1 },
      });
      expect(taskStatus(fixture)).toMatchObject({
        state_revision: 1,
        last_event: { event_id: eventId, type: "REGISTER_ROLE" },
        sessions: {
          FOREMAN: { thread_id: THREADS.FOREMAN, attempt: 1 },
        },
      });
      const repairedMetadata = JSON.parse(
        readFileSync(metadataFile, "utf8"),
      ) as { bootstrap_consumed_at?: string };
      expect(typeof repairedMetadata.bootstrap_consumed_at).toBe("string");
      expect(existsSync(fixture.bootstrapCapability as string)).toBe(false);

      expectControlError(
        runCli([
          "register-role",
          "--goal", "demo",
          "--task", "TASK-B",
          "--role", "FOREMAN",
          "--thread", "foreman-bootstrap-reuse",
          "--host", "local",
          "--attempt", "1",
          "--event-id", `register-bootstrap-reuse-${randomUUID()}`,
          "--bootstrap-capability-file", fixture.bootstrapCapability as string,
          "--json",
        ], fixture.root, fixture.controlDir),
        "CAPABILITY_CONSUMED",
      );
    },
  );

  it("re-materializes frozen protocol paths and digests after context compaction", () => {
    initAndRegister(fixture);
    const resumed = runCli([
      "resume", "--goal", "demo", "--task", "TASK-A", "--role", "CAPTAIN", "--thread", THREADS.CAPTAIN, "--json",
    ], fixture.root, fixture.controlDir);
    expect(resumed.code).toBe(0);
    const protocols = json(resumed).protocols as Record<string, string>;
    expect(Object.keys(protocols).sort()).toEqual(["captain", "entry", "foreman", "role_kernel", "shared"]);
    expect(protocols.role_kernel).toMatch(/^docs\/protocol\/role-kernel\.md@sha256:[0-9a-f]{64}$/);

    const plain = runCli([
      "resume", "--goal", "demo", "--task", "TASK-A", "--role", "CAPTAIN", "--thread", THREADS.CAPTAIN,
    ], fixture.root, fixture.controlDir);
    expect(plain.code).toBe(0);
    expect(plain.stdout.trim().split("\n")).toHaveLength(15);
    expect(plain.stdout).toContain(`WORKTREE_HEAD ${fixture.fullHead}`);
  });

  it("projects the one Goal FOREMAN authority into a second task before CAPTAIN delegation", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    const taskAForeman = fixture.capabilities["TASK-A"].FOREMAN as string;
    const taskBForeman = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", taskAForeman, "--json",
    ], fixture.root, fixture.controlDir);
    expect(taskBForeman.code).toBe(0);
    const taskBForemanCapability = String(json(taskBForeman).actor_capability_file);
    expect(taskBForemanCapability).toBe(taskAForeman);
    const taskBCaptain = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "CAPTAIN",
      "--thread", "captain-task-b-1", "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", taskBForemanCapability, "--json",
    ], fixture.root, fixture.controlDir);
    expect(taskBCaptain.code).toBe(0);
    expect(taskStatus(fixture, "TASK-B").sessions).toMatchObject({
      FOREMAN: { thread_id: THREADS.FOREMAN },
      CAPTAIN: { thread_id: "captain-task-b-1" },
    });
  });

  it("recovers a bootstrap FOREMAN registration response loss without reopening bootstrap", () => {
    initGoal(fixture);
    const eventId = `register-bootstrap-response-loss-${randomUUID()}`;
    const registration = [
      "register-role", "--goal", "demo", "--task", "TASK-A", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--event-id", eventId,
      "--bootstrap-capability-file", fixture.bootstrapCapability as string,
      "--json",
    ];

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL = "1";
    expectControlError(
      runCli(registration, fixture.root, fixture.controlDir),
      "TEST_FAULT_AFTER_EVENT_INSTALL",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL;

    const generationFile = path.join(
      fixture.controlDir,
      ".generation.json",
    );
    const metadataFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "goal.json",
    );
    const generationBeforeUnrelatedRetry = readFileSync(
      generationFile,
      "utf8",
    );
    const metadataBeforeUnrelatedRetry = readFileSync(metadataFile, "utf8");
    const bootstrapBeforeUnrelatedRetry = readFileSync(
      fixture.bootstrapCapability as string,
      "utf8",
    );
    const secondBootstrap = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", "foreman-illegal-second", "--host", "local", "--attempt", "1",
      "--event-id", `register-illegal-second-bootstrap-${randomUUID()}`,
      "--bootstrap-capability-file", fixture.bootstrapCapability as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(secondBootstrap, "STORE_TRANSACTION_MISMATCH");
    expect(readFileSync(generationFile, "utf8"))
      .toBe(generationBeforeUnrelatedRetry);
    expect(readFileSync(metadataFile, "utf8"))
      .toBe(metadataBeforeUnrelatedRetry);
    expect(readFileSync(fixture.bootstrapCapability as string, "utf8"))
      .toBe(bootstrapBeforeUnrelatedRetry);

    const repeated = runCli(registration, fixture.root, fixture.controlDir);
    expect(repeated.code).toBe(0);
    const body = json(repeated);
    expect(body).toMatchObject({
      registered: true,
      idempotent: true,
      task: {
        sessions: {
          FOREMAN: {
            thread_id: THREADS.FOREMAN,
            attempt: 1,
          },
        },
      },
      session: {
        thread_id: THREADS.FOREMAN,
        attempt: 1,
      },
    });
    expect(existsSync(String(body.actor_capability_file))).toBe(true);
  });

  it("exact-retries a historical worker registration after successor takeover and frozen inputs disappear", () => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      payload: p1Payload(),
    });
    const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({ approval_ref: "user://issue-4242/register-retry" }),
    });
    apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      fullHead: fixture.fullHead,
      payload: p1Payload({
        approval_event_id: String(approval.event.event_id),
      }),
    });

    const eventId = `register-dev-response-loss-${randomUUID()}`;
    const originalRegistration = [
      "register-role", "--goal", "demo", "--task", "TASK-A", "--role", "DEV",
      "--thread", THREADS.DEV, "--host", "local", "--attempt", "1",
      "--launch-id", "launch-dev-response-loss",
      "--event-id", eventId,
      "--authorizer-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      "--json",
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL = "1";
    expectControlError(
      runCli(originalRegistration, fixture.root, fixture.controlDir),
      "TEST_FAULT_AFTER_EVENT_INSTALL",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL;
    const firstRetry = runCli(
      originalRegistration,
      fixture.root,
      fixture.controlDir,
    );
    expect(firstRetry.code).toBe(0);
    const firstRetryBody = json(firstRetry);
    const rawActorCapability = readFileSync(
      String(firstRetryBody.actor_capability_file),
      "utf8",
    ).trim();
    const rawCaptainCapability = readFileSync(
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      "utf8",
    ).trim();
    expectSerializedSurfaceNoEcho(firstRetryBody, [
      rawActorCapability,
      rawCaptainCapability,
    ]);

    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: {
        role: "DEV",
        reason: "response was lost and the original worker later disappeared",
        fingerprint: "system-error:dev-response-loss",
        attempts: 1,
      },
    });
    registerRole(fixture, "DEV", {
      thread: "dev-a-2",
      attempt: 2,
      seedLaunch: false,
    });
    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      payload: { successor_thread_id: "dev-a-2" },
    });

    unlinkSync(path.join(fixture.root, "docs", "protocol", "shared.md"));
    const beforeHistoricalRetry =
      ordinaryFileSnapshot(fixture.controlDir);
    const repeated = runCli(originalRegistration, fixture.root, fixture.controlDir);
    expect(repeated.code).toBe(0);
    const body = json(repeated);
    expect(body).toMatchObject({
      registered: true,
      idempotent: true,
      task: {
        sessions: {
          DEV: {
            thread_id: "dev-a-2",
            attempt: 2,
          },
        },
      },
      session: {
        thread_id: THREADS.DEV,
        attempt: 1,
      },
    });
    expect(typeof body.task_nonce).toBe("string");
    expect(String(body.task_nonce)).not.toHaveLength(0);
    expect(body.task_nonce).toBe(firstRetryBody.task_nonce);
    expect(body.actor_capability_file).toBe(firstRetryBody.actor_capability_file);
    expect(existsSync(String(body.actor_capability_file))).toBe(true);
    expectSerializedSurfaceNoEcho(body, [
      rawActorCapability,
      rawCaptainCapability,
    ]);
    expect(ordinaryFileSnapshot(fixture.controlDir))
      .toEqual(beforeHistoricalRetry);

    const variantLaunchId = "launch-dev-response-loss-variant";
    const variantLaunch = [...originalRegistration];
    variantLaunch[variantLaunch.indexOf("--launch-id") + 1] =
      variantLaunchId;
    const beforeVariantLaunch =
      ordinaryFileSnapshot(fixture.controlDir);
    expectExactCliControlErrorNoEcho(
      runCli(
        variantLaunch,
        fixture.root,
        fixture.controlDir,
      ),
      "EVENT_ID_CONFLICT",
      `registration event id ${eventId} 已被不同请求使用`,
      [
        rawActorCapability,
        rawCaptainCapability,
        variantLaunchId,
      ],
    );
    expect(ordinaryFileSnapshot(fixture.controlDir))
      .toEqual(beforeVariantLaunch);

    const syntheticReceipt = path.join(
      fixture.root,
      "synthetic-v2-receipt.json",
    );
    const syntheticPlan = path.join(
      fixture.root,
      "synthetic-v2-plan.json",
    );
    const syntheticReceiptBody =
      "{\"rejected_sensitive_receipt\":\"ao01-receipt-secret-value\"}\n";
    const syntheticPlanBody =
      "{\"rejected_sensitive_plan\":\"ao01-plan-secret-value\"}\n";
    writeFileSync(syntheticReceipt, syntheticReceiptBody);
    writeFileSync(syntheticPlan, syntheticPlanBody);
    const syntheticReceiptSha = createHash("sha256")
      .update(readFileSync(syntheticReceipt))
      .digest("hex");
    const syntheticPlanSha = createHash("sha256")
      .update(readFileSync(syntheticPlan))
      .digest("hex");
    const mixedRetry = [
      ...originalRegistration,
      "--probe-observation-receipt", syntheticReceipt,
      "--probe-observation-receipt-sha256", syntheticReceiptSha,
      "--probe-observation-plan", syntheticPlan,
      "--probe-observation-plan-sha256", syntheticPlanSha,
      "--probe-observation-stable-id",
      "canary-observation-synthetic-legacy-retry",
      "--probe-observation-challenge", "ab".repeat(32),
    ];
    const beforeMixedRetry =
      ordinaryFileSnapshot(fixture.controlDir);
    expectExactCliControlErrorNoEcho(
      runCli(
        mixedRetry,
        fixture.root,
        fixture.controlDir,
      ),
      "EVENT_ID_CONFLICT",
      `registration event id ${eventId} 已被不同请求使用`,
      [
        rawActorCapability,
        rawCaptainCapability,
        syntheticReceiptBody.trim(),
        syntheticPlanBody.trim(),
        "ao01-receipt-secret-value",
        "ao01-plan-secret-value",
        "canary-observation-synthetic-legacy-retry",
        "ab".repeat(32),
      ],
    );
    expect(ordinaryFileSnapshot(fixture.controlDir))
      .toEqual(beforeMixedRetry);
  });

  it("recovers one sealed registration capability and nonce after child exit and authorizer lease expiry", () => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      payload: p1Payload(),
    });
    const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({
        approval_ref: "user://issue-4242/registration-intent",
      }),
    });
    apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      fullHead: fixture.fullHead,
      payload: p1Payload({
        approval_event_id: String(approval.event.event_id),
      }),
    });

    const eventId = `register-dev-intent-${randomUUID()}`;
    const registration = [
      "register-role", "--goal", "demo", "--task", "TASK-A", "--role", "DEV",
      "--thread", "dev-registration-intent-1", "--host", "local",
      "--attempt", "1", "--launch-id", "launch-registration-intent-1",
      "--event-id", eventId,
      "--authorizer-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      "--json",
    ];
    const blockedHeartbeat = buildEvent(
      fixture,
      "HEARTBEAT",
      "FOREMAN",
      book.FOREMAN + 1,
      {
        eventId: `heartbeat-during-prepared-registration-${randomUUID()}`,
        payload: { lease_ms: 60000, status: "active" },
      },
    );
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_STAGING_SEAL = "exit";
    const interrupted = runCli(registration, fixture.root, fixture.controlDir);
    expect(interrupted.code).toBe(86);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_STAGING_SEAL;

    const intentParent = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "registration-intents",
    );
    const intentDir = path.join(
      intentParent,
      eventId,
    );
    const stagingName = readdirSync(intentParent).find((name) =>
      name.startsWith(".init-registration-")
    );
    expect(stagingName).toBeDefined();
    const stagingDir = path.join(intentParent, stagingName as string);
    expect(existsSync(intentDir)).toBe(false);
    const stagedIntentBytes = readFileSync(
      path.join(stagingDir, "intent.json"),
      "utf8",
    );
    const intent = JSON.parse(
      stagedIntentBytes,
    ) as {
      accepted_at: string;
      capability_file: string;
      capability_sha256: string;
      task_nonce: string;
    };
    const stagedCapabilityName = readdirSync(stagingDir).find((name) =>
      name.endsWith(".cap")
    );
    expect(stagedCapabilityName).toBeDefined();
    const stagedCapabilityBytes = readFileSync(
      path.join(stagingDir, stagedCapabilityName as string),
      "utf8",
    );
    expect(readdirSync(stagingDir).filter((name) => name.endsWith(".cap")))
      .toHaveLength(1);

    const divergent = [...registration];
    divergent[divergent.indexOf("launch-registration-intent-1")]
      = "launch-registration-intent-divergent";
    const generationFile = path.join(
      fixture.controlDir,
      ".generation.json",
    );
    const interruptedGenerationBytes = readFileSync(generationFile, "utf8");
    const interruptedGeneration = JSON.parse(
      interruptedGenerationBytes,
    ) as { generation: number };
    expectControlError(
      runCli(divergent, fixture.root, fixture.controlDir),
      "PREPARED_REQUEST_MISMATCH",
    );
    const reapedGenerationBytes = readFileSync(generationFile, "utf8");
    const reapedGeneration = JSON.parse(
      reapedGenerationBytes,
    ) as { generation: number };
    expect(reapedGeneration.generation)
      .toBe(interruptedGeneration.generation);
    expect(reapedGeneration.generation % 2).toBe(1);
    expect(existsSync(stagingDir)).toBe(true);
    expect(existsSync(intentDir)).toBe(false);
    expect(readFileSync(path.join(stagingDir, "intent.json"), "utf8"))
      .toBe(stagedIntentBytes);

    const unrelatedResults = [
      runCli([
        "status", "--goal", "demo", "--json",
      ], fixture.root, fixture.controlDir),
      runCli([
        "next", "--goal", "demo", "--json",
      ], fixture.root, fixture.controlDir),
      runCli([
        "actions",
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", "CAPTAIN",
        "--thread", THREADS.CAPTAIN,
        "--json",
      ], fixture.root, fixture.controlDir),
      runCli([
        "resume",
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", "CAPTAIN",
        "--thread", THREADS.CAPTAIN,
        "--json",
      ], fixture.root, fixture.controlDir),
      submitEvent(
        fixture,
        blockedHeartbeat,
        fixture.capabilities["TASK-A"].FOREMAN as string,
      ),
      runCli([
        "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "DEV",
        "--thread", "dev-registration-intent-1", "--host", "local",
        "--attempt", "1", "--launch-id", "launch-task-b-conflict",
        "--event-id", `register-task-b-conflict-${randomUUID()}`,
        "--authorizer-capability-file",
        fixture.capabilities["TASK-A"].CAPTAIN as string,
        "--json",
      ], fixture.root, fixture.controlDir),
    ];
    for (const readOnly of unrelatedResults.slice(0, 4)) {
      expect(readOnly.code).toBe(0);
      expect(json(readOnly)).toMatchObject({
        control_store_read: {
          complete: false,
          writer_crash_marker: true,
          transaction_kind: "REGISTRATION",
          required_action:
            "retry the original write with the same stable operation ID",
        },
      });
    }
    for (const differentWriter of unrelatedResults.slice(4)) {
      expectControlError(
        differentWriter,
        "STORE_TRANSACTION_MISMATCH",
      );
    }
    const blockedResource = runResourceCli([
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", THREADS.CAPTAIN,
      "--resource", "preview-port:prepared-registration",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", `resource-during-prepared-registration-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(blockedResource, "TASK_OPERATION_PENDING");
    expect(readFileSync(generationFile, "utf8"))
      .toBe(reapedGenerationBytes);
    expect(readFileSync(path.join(stagingDir, "intent.json"), "utf8"))
      .toBe(stagedIntentBytes);
    expect(readFileSync(
      path.join(stagingDir, stagedCapabilityName as string),
      "utf8",
    )).toBe(stagedCapabilityBytes);

    const stateProjection = JSON.parse(readFileSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "state.json",
    ), "utf8")) as {
      tasks: Record<string, {
        sessions: Record<string, { lease_until: string }>;
      }>;
    };
    const captainLease =
      stateProjection.tasks["TASK-A"].sessions.CAPTAIN.lease_until;
    expect(typeof captainLease).toBe("string");
    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(captainLease as string) + 1,
    ).toISOString();
    const recovered = runCli(registration, fixture.root, fixture.controlDir);
    expect(recovered.code).toBe(0);
    expect(json(recovered)).toMatchObject({
      registered: true,
      idempotent: false,
      recovered_from_intent: true,
      actor_capability_file: intent.capability_file,
      task_nonce: intent.task_nonce,
      session: {
        thread_id: "dev-registration-intent-1",
        attempt: 1,
      },
    });
    expect(existsSync(stagingDir)).toBe(false);
    expect(readFileSync(path.join(intentDir, "intent.json"), "utf8"))
      .toBe(stagedIntentBytes);
    expect(readFileSync(
      path.join(intentDir, stagedCapabilityName as string),
      "utf8",
    )).toBe(stagedCapabilityBytes);
    const accepted = readdirSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "events",
      "TASK-A",
    )).map((name) => JSON.parse(readFileSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "events",
      "TASK-A",
      name,
    ), "utf8")) as { event_id: string; accepted_at: string });
    expect(accepted.filter((event) => event.event_id === eventId)).toHaveLength(1);
    expect(accepted.find((event) => event.event_id === eventId)?.accepted_at)
      .toBe(intent.accepted_at);
    expect(readdirSync(intentDir).filter((name) => name.endsWith(".cap")))
      .toHaveLength(1);
  });

  it("cleans only an exact unsealed registration staging before retrying", () => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      payload: p1Payload(),
    });
    const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({
        approval_ref: "user://issue-4242/unsealed-registration",
      }),
    });
    apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      fullHead: fixture.fullHead,
      payload: p1Payload({
        approval_event_id: String(approval.event.event_id),
      }),
    });

    const eventId = `register-dev-unsealed-${randomUUID()}`;
    const registration = [
      "register-role", "--goal", "demo", "--task", "TASK-A", "--role", "DEV",
      "--thread", "dev-registration-unsealed-1", "--host", "local",
      "--attempt", "1", "--launch-id", "launch-registration-unsealed-1",
      "--event-id", eventId,
      "--authorizer-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      "--json",
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_STAGING_SEAL = "exit";
    expect(runCli(registration, fixture.root, fixture.controlDir).code).toBe(86);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_STAGING_SEAL;

    const intentParent = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "registration-intents",
    );
    const stagingName = readdirSync(intentParent).find((name) =>
      name.startsWith(".init-registration-")
    );
    expect(stagingName).toBeDefined();
    const stagingDir = path.join(intentParent, stagingName as string);
    for (const entry of readdirSync(stagingDir)) {
      rmSync(path.join(stagingDir, entry), { recursive: true, force: true });
    }
    const partialIntent = path.join(
      stagingDir,
      `.intent.json.4242.tmp-${"b".repeat(24)}`,
    );
    writeFileSync(partialIntent, "{\"partial\":", { mode: 0o600 });

    const divergent = [...registration];
    divergent[divergent.indexOf("launch-registration-unsealed-1")]
      = "launch-registration-unsealed-divergent";
    expectControlError(
      runCli(divergent, fixture.root, fixture.controlDir),
      "PREPARED_REQUEST_MISMATCH",
    );
    expect(readFileSync(partialIntent, "utf8")).toBe("{\"partial\":");

    const retried = runCli(registration, fixture.root, fixture.controlDir);
    expect(retried.code).toBe(0);
    expect(existsSync(stagingDir)).toBe(false);
    const finalDir = path.join(intentParent, eventId);
    expect(readdirSync(finalDir).filter((name) => name.endsWith(".cap")))
      .toHaveLength(1);
    expect(readFileSync(path.join(finalDir, "intent.json"), "utf8"))
      .not.toContain("\"partial\"");
  });

  it("projects exact normal FOREMAN recovery to a live CAPTAIN before permitting root recovery", () => {
    process.env.GOAL_CONTROL_NOW = "2026-07-24T00:00:00.000Z";
    initGoal(fixture);
    registerRole(fixture, "FOREMAN", { leaseMs: 1000 });
    registerRole(fixture, "CAPTAIN", { leaseMs: 4 * 60 * 60 * 1000 });
    const beforeExpiry = taskStatus(fixture);
    const foreman = beforeExpiry.sessions?.FOREMAN;
    expect(foreman).toBeDefined();
    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(foreman?.lease_until as string) + 1,
    ).toISOString();

    type ExactRoleLostAction = {
      type: "ROLE_LOST";
      actor_role: "CAPTAIN";
      target_role: "FOREMAN";
      target: {
        thread_id: string;
        host_id: string;
        attempt: number;
        lease_until: string;
      };
      event_id: string;
      payload: {
        role: "FOREMAN";
        reason: string;
        fingerprint: string;
        attempts: number;
        expected_thread_id: string;
        expected_host_id: string;
        expected_attempt: number;
        expected_lease_until: string;
      };
      requested_action: string;
    };
    const actionsResult = runCli([
      "actions",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", THREADS.CAPTAIN,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(actionsResult.code).toBe(0);
    const exactAction = (
      json(actionsResult).actions as ExactRoleLostAction[]
    ).find((action) => (
      action.type === "ROLE_LOST"
        && action.target_role === "FOREMAN"
    ));
    expect(exactAction).toMatchObject({
      type: "ROLE_LOST",
      actor_role: "CAPTAIN",
      target_role: "FOREMAN",
      target: {
        thread_id: THREADS.FOREMAN,
        host_id: "local",
        attempt: 1,
        lease_until: foreman?.lease_until,
      },
      event_id: expect.stringMatching(
        /^role-lost-foreman-task-a-a1-[0-9a-f]{16}$/,
      ),
      payload: {
        role: "FOREMAN",
        reason: `registered FOREMAN lease expired at ${foreman?.lease_until}`,
        fingerprint: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        attempts: 1,
        expected_thread_id: THREADS.FOREMAN,
        expected_host_id: "local",
        expected_attempt: 1,
        expected_lease_until: foreman?.lease_until,
      },
      requested_action: "EVENT_TEMPLATE_AND_ACCEPT",
    });
    expect((json(actionsResult).actions as ExactRoleLostAction[]).filter(
      (action) => action.type === "ROLE_LOST",
    )).toHaveLength(1);

    const resumed = runCli([
      "resume",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", THREADS.CAPTAIN,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(resumed.code).toBe(0);
    expect(json(resumed).allowed_actions).toEqual(
      expect.arrayContaining([exactAction]),
    );

    const doctorResult = runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    );
    const doctor = json(doctorResult) as {
      findings: Array<{ code: string; task_id?: string }>;
    };
    expect(doctor.findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: "FOREMAN_RECOVERY_DEADLOCK",
        task_id: "TASK-A",
      }),
    ]));

    const beforeRejectedRootRecovery = taskStatus(fixture);
    expectControlError(
      recoverExpiredForeman(fixture, {
        snapshot: beforeRejectedRootRecovery,
      }),
      "CAPTAIN_RECOVERY_PATH_AVAILABLE",
    );
    expect(taskStatus(fixture)).toEqual(beforeRejectedRootRecovery);

    const payloadDir = path.join(fixture.controlDir, "inputs");
    mkdirSync(payloadDir, { recursive: true });
    const payloadFile = path.join(
      payloadDir,
      `role-lost-foreman-${randomUUID()}.json`,
    );
    writeFileSync(
      payloadFile,
      `${JSON.stringify(exactAction?.payload, null, 2)}\n`,
    );
    const templateResult = runCli([
      "event-template",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", THREADS.CAPTAIN,
      "--type", "ROLE_LOST",
      "--event-id", exactAction?.event_id as string,
      "--payload-file", payloadFile,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(templateResult.code).toBe(0);
    const roleLostEvent = json(templateResult);
    expect(roleLostEvent).toMatchObject({
      event_id: exactAction?.event_id,
      type: "ROLE_LOST",
      actor: {
        role: "CAPTAIN",
        thread_id: THREADS.CAPTAIN,
        host_id: "local",
      },
      payload: exactAction?.payload,
    });
    expect(submitEvent(
      fixture,
      roleLostEvent,
      fixture.capabilities["TASK-A"].CAPTAIN,
    ).code).toBe(0);
    const normalRecovery = taskStatus(fixture);
    expect(normalRecovery).toMatchObject({
      recovery: {
        role: "FOREMAN",
        lost_thread_id: THREADS.FOREMAN,
        lost_host_id: "local",
        lost_attempt: 1,
        recovery_event_id: exactAction?.event_id,
        fingerprint: exactAction?.payload.fingerprint,
      },
      sessions: {
        FOREMAN: {
          thread_id: THREADS.FOREMAN,
          attempt: 1,
          status: "lost",
        },
        CAPTAIN: {
          thread_id: THREADS.CAPTAIN,
          attempt: 1,
          status: "active",
        },
      },
    });

    const recovered = recoverExpiredForeman(fixture, {
      snapshot: normalRecovery,
    });
    expect(recovered.code).toBe(0);
    expect(taskStatus(fixture)).toMatchObject({
      recovery: null,
      last_event: { type: "RECOVER_EXPIRED_FOREMAN" },
      sessions: {
        FOREMAN: {
          thread_id: "foreman-a-2",
          host_id: "recovery-host",
          attempt: 2,
          status: "active",
        },
        CAPTAIN: {
          thread_id: THREADS.CAPTAIN,
          attempt: 1,
          status: "active",
        },
      },
    });

    const beforeStaleReplay = taskStatus(fixture);
    const staleTemplate = runCli([
      "event-template",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", THREADS.CAPTAIN,
      "--type", "ROLE_LOST",
      "--event-id", `role-lost-foreman-stale-${randomUUID()}`,
      "--payload-file", payloadFile,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(staleTemplate.code).toBe(0);
    expectControlError(
      submitEvent(
        fixture,
        json(staleTemplate),
        fixture.capabilities["TASK-A"].CAPTAIN,
      ),
      "ROLE_LOST_TARGET_STALE",
    );
    expect(taskStatus(fixture)).toEqual(beforeStaleReplay);
  });

  it("projects durable worker systemError as one exact recovery action", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "HEARTBEAT", "DEV", {
      payload: { status: "systemError", lease_ms: 3600000 },
    });
    const state = taskStatus(fixture);
    const dev = state.sessions?.DEV;
    const projected = json(runCli([
      "actions",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", THREADS.CAPTAIN,
      "--json",
    ], fixture.root, fixture.controlDir)) as {
      actions: Array<Record<string, unknown>>;
    };
    const roleLost = projected.actions.filter(
      (action) => action.type === "ROLE_LOST",
    );
    expect(roleLost.length).toBeGreaterThan(0);
    expect(roleLost.every((action) => (
      typeof action.target_role === "string"
        && action.payload !== undefined
        && action.event_id !== undefined
    ))).toBe(true);
    expect(roleLost).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor_role: "CAPTAIN",
          target_role: "DEV",
          target: {
            thread_id: dev?.thread_id,
            host_id: dev?.host_id,
            attempt: dev?.attempt,
            lease_until: dev?.lease_until,
          },
          payload: expect.objectContaining({
            role: "DEV",
            expected_thread_id: dev?.thread_id,
            expected_host_id: dev?.host_id,
            expected_attempt: dev?.attempt,
            expected_lease_until: dev?.lease_until,
          }),
          execution_condition: "ACTOR_SYSTEM_ERROR",
          requested_action: "EVENT_TEMPLATE_AND_ACCEPT",
        }),
      ]),
    );
    const exactDev = roleLost.find((action) => action.target_role === "DEV");
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      eventId: String(exactDev?.event_id),
      payload: exactDev?.payload as Record<string, unknown>,
    });
    expect(taskStatus(fixture)).toMatchObject({
      recovery: { role: "DEV" },
      sessions: { DEV: { status: "lost" } },
    });
  });

  it("diagnoses normal FOREMAN recovery Goal-wide when one source CAPTAIN can close it", () => {
    process.env.GOAL_CONTROL_NOW = "2026-07-24T00:00:00.000Z";
    initGoal(fixture);
    registerRole(fixture, "FOREMAN", { leaseMs: 1000 });
    const foremanCapability =
      fixture.capabilities["TASK-A"].FOREMAN as string;
    const taskBProjection = runCli([
      "register-role",
      "--goal", "demo",
      "--task", "TASK-B",
      "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN,
      "--host", "local",
      "--attempt", "1",
      "--lease-ms", "1000",
      "--authorizer-capability-file", foremanCapability,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(taskBProjection.code).toBe(0);
    fixture.capabilities["TASK-B"].FOREMAN = foremanCapability;
    registerRole(fixture, "CAPTAIN", {
      task: "TASK-A",
      leaseMs: 4 * 60 * 60 * 1000,
    });
    const taskA = taskStatus(fixture, "TASK-A");
    const taskB = taskStatus(fixture, "TASK-B");
    process.env.GOAL_CONTROL_NOW = new Date(
      Math.max(
        Date.parse(taskA.sessions?.FOREMAN?.lease_until as string),
        Date.parse(taskB.sessions?.FOREMAN?.lease_until as string),
      ) + 1,
    ).toISOString();

    const beforeNormalRecovery = json(runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    )) as {
      findings: Array<{ code: string; task_id?: string }>;
    };
    expect(beforeNormalRecovery.findings.filter(
      (finding) => finding.code === "FOREMAN_RECOVERY_DEADLOCK",
    )).toEqual([]);
    expectControlError(
      recoverExpiredForeman(fixture, { snapshot: taskStatus(fixture) }),
      "CAPTAIN_RECOVERY_PATH_AVAILABLE",
    );

    const book = sequences();
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: {
        role: "FOREMAN",
        reason: "normal Goal-wide FOREMAN recovery started on TASK-A",
        attempts: 1,
      },
    });
    const afterNormalRecoveryStarted = json(runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    )) as {
      findings: Array<{ code: string; task_id?: string }>;
    };
    expect(afterNormalRecoveryStarted.findings.filter(
      (finding) => finding.code === "FOREMAN_RECOVERY_DEADLOCK",
    )).toEqual([]);

    const recovered = recoverExpiredForeman(fixture, {
      snapshot: taskStatus(fixture),
    });
    expect(recovered.code).toBe(0);
    expect(taskStatus(fixture, "TASK-B")).toMatchObject({
      sessions: {
        FOREMAN: {
          thread_id: "foreman-a-2",
          attempt: 2,
          status: "active",
        },
      },
    });
  });

  it("permits root FOREMAN recovery when reconciliation makes the live CAPTAIN path illegal", () => {
    process.env.GOAL_CONTROL_NOW = "2026-07-24T00:00:00.000Z";
    initGoal(fixture);
    registerRole(fixture, "FOREMAN", { leaseMs: 1000 });
    registerRole(fixture, "CAPTAIN", {
      leaseMs: 4 * 60 * 60 * 1000,
    });
    const controlEventId = `control-reconcile-${randomUUID()}`;
    const advanced = runCli([
      "control",
      "--goal", "demo",
      "--expected-epoch", "0",
      "--reason", "force reconciliation before FOREMAN expiry",
      "--instruction-ref", "user://goal-control/reconcile-recovery",
      "--thread", THREADS.FOREMAN,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].FOREMAN as string,
      "--event-id", controlEventId,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(advanced.code).toBe(0);
    const beforeExpiry = taskStatus(fixture);
    expect(beforeExpiry.reconcile_required).toMatchObject({
      control_event_id: controlEventId,
    });
    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(
        beforeExpiry.sessions?.FOREMAN?.lease_until as string,
      ) + 1,
    ).toISOString();

    for (const command of ["actions", "resume"]) {
      const projection = runCli([
        command,
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", "CAPTAIN",
        "--thread", THREADS.CAPTAIN,
        "--json",
      ], fixture.root, fixture.controlDir);
      expect(projection.code).toBe(0);
      const body = json(projection) as {
        actions?: Array<{ type: string; target_role?: string }>;
        allowed_actions?: Array<{ type: string; target_role?: string }>;
      };
      expect(
        (body.actions ?? body.allowed_actions ?? []).filter(
          (action) => (
            action.type === "ROLE_LOST"
              && action.target_role === "FOREMAN"
          ),
        ),
      ).toEqual([]);
    }

    const diagnosis = json(runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    )) as {
      findings: Array<{ code: string; task_id?: string }>;
    };
    expect(diagnosis.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: "FOREMAN_RECOVERY_DEADLOCK",
        task_id: "TASK-A",
      }),
    ]));

    const recovered = recoverExpiredForeman(fixture, {
      snapshot: taskStatus(fixture),
    });
    expect(recovered.code).toBe(0);
    expect(taskStatus(fixture)).toMatchObject({
      reconcile_required: {
        control_event_id: controlEventId,
      },
      sessions: {
        FOREMAN: {
          thread_id: "foreman-a-2",
          host_id: "recovery-host",
          attempt: 2,
          status: "active",
        },
        CAPTAIN: {
          thread_id: THREADS.CAPTAIN,
          attempt: 1,
          status: "active",
        },
      },
    });
  });

  it("uses a live identical Goal FOREMAN replica to refresh an expired task projection", () => {
    process.env.GOAL_CONTROL_NOW = "2026-07-24T00:00:00.000Z";
    initGoal(fixture);
    registerRole(fixture, "FOREMAN", { leaseMs: 1000 });
    const foremanCapability = fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--lease-ms", "1000",
      "--authorizer-capability-file", foremanCapability, "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    fixture.capabilities["TASK-B"].FOREMAN = foremanCapability;
    registerRole(fixture, "CAPTAIN", {
      task: "TASK-B",
      thread: "captain-b-1",
      leaseMs: 4 * 60 * 60 * 1000,
    });
    const originalLease = Date.parse(
      taskStatus(fixture, "TASK-B").sessions?.FOREMAN?.lease_until as string,
    );

    process.env.GOAL_CONTROL_NOW = new Date(originalLease - 1).toISOString();
    const heartbeatA = buildEvent(fixture, "HEARTBEAT", "FOREMAN", 1, {
      payload: { lease_ms: 3600000, status: "active" },
    });
    expect(submitEvent(fixture, heartbeatA).code).toBe(0);

    process.env.GOAL_CONTROL_NOW = new Date(originalLease + 1).toISOString();
    for (const command of ["actions", "resume"]) {
      const projection = runCli([
        command,
        "--goal", "demo",
        "--task", "TASK-B",
        "--role", "CAPTAIN",
        "--thread", "captain-b-1",
        "--json",
      ], fixture.root, fixture.controlDir);
      expect(projection.code).toBe(0);
      const body = json(projection) as {
        actions?: Array<{ type: string; target_role?: string }>;
        allowed_actions?: Array<{ type: string; target_role?: string }>;
      };
      const roleLost = (body.actions ?? body.allowed_actions ?? []).filter(
        (action) => (
          action.type === "ROLE_LOST"
            && action.target_role === "FOREMAN"
        ),
      );
      expect(roleLost).toEqual([]);
    }
    const heartbeatB = buildEvent(fixture, "HEARTBEAT", "FOREMAN", 1, {
      taskId: "TASK-B",
      payload: { lease_ms: 3600000, status: "active" },
    });
    expect(submitEvent(fixture, heartbeatB).code).toBe(0);
    expect(taskStatus(fixture, "TASK-B").sessions?.FOREMAN).toMatchObject({
      thread_id: THREADS.FOREMAN,
      status: "active",
    });
    const doctorResult = runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    );
    const findings = json(doctorResult).findings as Array<{ code: string; task_id?: string }>;
    expect(findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: "FOREMAN_RECOVERY_DEADLOCK",
        task_id: "TASK-B",
      }),
    ]));
  });

  it("uses a live Goal FOREMAN replica to repair one systemError projection", () => {
    process.env.GOAL_CONTROL_NOW = "2026-07-24T00:00:00.000Z";
    initGoal(fixture);
    registerRole(fixture, "FOREMAN", {
      leaseMs: 4 * 60 * 60 * 1000,
    });
    const foremanCapability =
      fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B",
      "--role", "FOREMAN", "--thread", THREADS.FOREMAN,
      "--host", "local", "--attempt", "1",
      "--lease-ms", String(4 * 60 * 60 * 1000),
      "--authorizer-capability-file", foremanCapability, "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    fixture.capabilities["TASK-B"].FOREMAN = foremanCapability;

    const failedReplica = buildEvent(
      fixture,
      "HEARTBEAT",
      "FOREMAN",
      1,
      {
        taskId: "TASK-B",
        payload: { lease_ms: 3600000, status: "systemError" },
      },
    );
    expect(submitEvent(
      fixture,
      failedReplica,
      foremanCapability,
    ).code).toBe(0);
    expect(taskStatus(fixture, "TASK-B").sessions?.FOREMAN)
      .toMatchObject({ status: "systemError" });

    const repairProjection = runCli([
      "actions",
      "--goal", "demo",
      "--task", "TASK-B",
      "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(repairProjection.code).toBe(0);
    const repair = (
      json(repairProjection).maintenance_actions as Array<
        Record<string, unknown>
      >
    ).find((action) => (
      action.type === "HEARTBEAT"
        && action.execution_condition
          === "GOAL_FOREMAN_REPLICA_REPAIR"
    ));
    expect(repair).toMatchObject({
      actor_role: "FOREMAN",
      event_id: expect.stringMatching(
        /^heartbeat-foreman-replica-restore-[0-9a-f]{32}$/,
      ),
      payload: { status: "active", lease_ms: 3600000 },
      dispatch: {
        executor_binding: "EXACT_USABLE_GOAL_FOREMAN_REPLICA",
        capability_mode: "GOAL_FOREMAN_CAPABILITY",
      },
    });

    const restored = buildEvent(
      fixture,
      "HEARTBEAT",
      "FOREMAN",
      2,
      {
        taskId: "TASK-B",
        eventId: String(repair?.event_id),
        payload: repair?.payload as Record<string, unknown>,
      },
    );
    expect(submitEvent(
      fixture,
      restored,
      foremanCapability,
    ).code).toBe(0);
    expect(taskStatus(fixture, "TASK-B").sessions?.FOREMAN)
      .toMatchObject({ status: "active" });
  });

  it("root-recovers a lone expired systemError FOREMAN when no CAPTAIN path exists", () => {
    process.env.GOAL_CONTROL_NOW = "2026-07-24T00:00:00.000Z";
    initGoal(fixture);
    registerRole(fixture, "FOREMAN", { leaseMs: 1000 });
    const failed = buildEvent(
      fixture,
      "HEARTBEAT",
      "FOREMAN",
      1,
      {
        payload: { lease_ms: 1000, status: "systemError" },
      },
    );
    expect(submitEvent(fixture, failed).code).toBe(0);
    const failedState = taskStatus(fixture);
    expect(failedState.sessions?.FOREMAN).toMatchObject({
      status: "systemError",
    });
    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(failedState.sessions?.FOREMAN?.lease_until as string) + 1,
    ).toISOString();

    const before = taskStatus(fixture);
    const diagnosis = json(runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    )) as { findings: Array<{ code: string; task_id?: string }> };
    expect(diagnosis.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: "FOREMAN_RECOVERY_DEADLOCK",
        task_id: "TASK-A",
      }),
    ]));

    const recovered = recoverExpiredForeman(fixture, { snapshot: before });
    expect(recovered.code).toBe(0);
    expect(taskStatus(fixture)).toMatchObject({
      sessions: {
        FOREMAN: {
          thread_id: "foreman-a-2",
          attempt: 2,
          status: "active",
        },
      },
      session_history: {
        FOREMAN: [
          expect.objectContaining({
            thread_id: THREADS.FOREMAN,
            attempt: 1,
            status: "lost",
            terminal_reason: "LEASE_EXPIRED_GOAL_RECOVERY",
          }),
        ],
      },
    });
  });

  it("does not root-recover one systemError FOREMAN projection while an exact live replica remains", () => {
    process.env.GOAL_CONTROL_NOW = "2026-07-24T00:00:00.000Z";
    initGoal(fixture);
    registerRole(fixture, "FOREMAN", { leaseMs: 1000 });
    const foremanCapability =
      fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B",
      "--role", "FOREMAN", "--thread", THREADS.FOREMAN,
      "--host", "local", "--attempt", "1",
      "--lease-ms", String(4 * 60 * 60 * 1000),
      "--authorizer-capability-file", foremanCapability,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    fixture.capabilities["TASK-B"].FOREMAN = foremanCapability;

    const failed = buildEvent(
      fixture,
      "HEARTBEAT",
      "FOREMAN",
      1,
      {
        payload: { lease_ms: 1000, status: "systemError" },
      },
    );
    expect(submitEvent(fixture, failed, foremanCapability).code).toBe(0);
    const liveReplica = buildEvent(
      fixture,
      "HEARTBEAT",
      "FOREMAN",
      1,
      {
        taskId: "TASK-B",
        payload: {
          lease_ms: 4 * 60 * 60 * 1000,
          status: "active",
        },
      },
    );
    expect(submitEvent(
      fixture,
      liveReplica,
      foremanCapability,
    ).code).toBe(0);
    const failedState = taskStatus(fixture);
    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(failedState.sessions?.FOREMAN?.lease_until as string) + 1,
    ).toISOString();

    const before = taskStatus(fixture);
    const diagnosis = json(runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    )) as { findings: Array<{ code: string }> };
    expect(diagnosis.findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "FOREMAN_RECOVERY_DEADLOCK" }),
    ]));
    expectControlError(
      recoverExpiredForeman(fixture, { snapshot: before }),
      "FOREMAN_LEASE_ACTIVE",
    );
    expect(taskStatus(fixture)).toEqual(before);
  });

  it("exact-retries one Goal-wide recovery after every FOREMAN replica expired in systemError", () => {
    process.env.GOAL_CONTROL_NOW = "2026-07-24T00:00:00.000Z";
    initGoal(fixture);
    registerRole(fixture, "FOREMAN", { leaseMs: 1000 });
    const foremanCapability =
      fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B",
      "--role", "FOREMAN", "--thread", THREADS.FOREMAN,
      "--host", "local", "--attempt", "1", "--lease-ms", "1000",
      "--authorizer-capability-file", foremanCapability,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    fixture.capabilities["TASK-B"].FOREMAN = foremanCapability;
    for (const taskId of ["TASK-A", "TASK-B"] as const) {
      const failed = buildEvent(
        fixture,
        "HEARTBEAT",
        "FOREMAN",
        1,
        {
          taskId,
          payload: { lease_ms: 1000, status: "systemError" },
        },
      );
      expect(submitEvent(fixture, failed, foremanCapability).code).toBe(0);
    }
    const leases = (["TASK-A", "TASK-B"] as const).map((taskId) => (
      Date.parse(
        taskStatus(fixture, taskId).sessions?.FOREMAN?.lease_until as string,
      )
    ));
    process.env.GOAL_CONTROL_NOW =
      new Date(Math.max(...leases) + 1).toISOString();
    const before = taskStatus(fixture);
    const eventId = `recover-system-error-${randomUUID()}`;

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL = "1";
    expectControlError(
      recoverExpiredForeman(fixture, { snapshot: before, eventId }),
      "TEST_FAULT_AFTER_EVENT_INSTALL",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL;

    const recovered = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    });
    expect(recovered.code).toBe(0);
    expect(json(recovered)).toMatchObject({
      recovered_task_ids: ["TASK-A", "TASK-B"],
      tasks: {
        "TASK-A": {
          sessions: { FOREMAN: { attempt: 2, status: "active" } },
        },
        "TASK-B": {
          sessions: { FOREMAN: { attempt: 2, status: "active" } },
        },
      },
    });
    const batchDirectory = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "foreman-recovery-batches",
      eventId,
    );
    expect(
      readdirSync(batchDirectory).filter((name) => name.endsWith(".cap")),
    ).toHaveLength(1);
  });

  it("allows FOREMAN replacement only through the independent Goal recovery capability", () => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: { role: "FOREMAN", reason: "foreman session terminated", attempts: 1 },
    });

    const wrongAuthority = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-A", "--role", "FOREMAN",
      "--thread", "foreman-2", "--host", "local", "--attempt", "2",
      "--authorizer-capability-file", fixture.capabilities["TASK-A"].CAPTAIN as string, "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(wrongAuthority, "CAPABILITY_REQUIRED");

    registerRole(fixture, "FOREMAN", { thread: "foreman-2", attempt: 2 });
    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      payload: { successor_thread_id: "foreman-2" },
    });
    expect(taskStatus(fixture)).toMatchObject({
      recovery: null,
      sessions: { FOREMAN: { thread_id: "foreman-2", attempt: 2, status: "active" } },
    });
  });

  it("lets a newer controller binary drive the frozen worktree of an already initialized Goal", () => {
    initAndRegister(fixture);
    const externalController = runCli([
      "status",
      "--repository-worktree",
      fixture.root,
      "--goal",
      "demo",
      "--json",
    ], ROOT, fixture.controlDir);

    expect(externalController.code).toBe(0);
    expect(json(externalController)).toMatchObject({
      goal_id: "demo",
      tasks: {
        "TASK-A": {
          sessions: {
            FOREMAN: { thread_id: THREADS.FOREMAN },
            CAPTAIN: { thread_id: THREADS.CAPTAIN },
          },
        },
      },
    });
  });

  it("atomically recovers an expired FOREMAN and then restores F2 → C2 → D2 through the normal authority chain", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    const before = taskStatus(fixture);
    expect(before.sessions).toMatchObject({
      FOREMAN: { thread_id: THREADS.FOREMAN, attempt: 1, status: "active" },
      CAPTAIN: { thread_id: THREADS.CAPTAIN, attempt: 1, status: "active" },
      DEV: { thread_id: THREADS.DEV, attempt: 1, status: "active" },
    });

    expireRegisteredRoles(fixture);
    const blockedDoctorResult = runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir
    );
    expect(blockedDoctorResult.code).toBe(1);
    expect(blockedDoctorResult.stderr).toBe("");
    const blockedDoctor = json(blockedDoctorResult) as { findings: Array<{ code: string }> };
    expect(blockedDoctor.findings).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "FOREMAN_RECOVERY_DEADLOCK" })])
    );
    const recovered = recoverExpiredForeman(fixture, {
      snapshot: before,
      controllerCwd: ROOT,
      repositoryWorktree: fixture.root,
    });
    expect(recovered.code).toBe(0);
    const recoveredBody = json(recovered);
    expect(recoveredBody).toMatchObject({ recovered: true, idempotent: false });
    fixture.capabilities["TASK-A"].FOREMAN = String(recoveredBody.actor_capability_file);

    const afterForeman = taskStatus(fixture);
    expect(afterForeman.state_revision).toBe(before.state_revision + 1);
    expect(workflowState(afterForeman)).toEqual(workflowState(before));
    expect(afterForeman).toMatchObject({
      recovery: null,
      last_event: { type: "RECOVER_EXPIRED_FOREMAN" },
      sessions: {
        FOREMAN: {
          thread_id: "foreman-a-2",
          host_id: "recovery-host",
          attempt: 2,
          status: "active",
        },
        CAPTAIN: { thread_id: THREADS.CAPTAIN, attempt: 1 },
        DEV: { thread_id: THREADS.DEV, attempt: 1 },
      },
      session_history: {
        FOREMAN: [{ thread_id: THREADS.FOREMAN, attempt: 1 }],
      },
    });

    book.FOREMAN = 0;
    apply(fixture, book, "ROLE_LOST", "FOREMAN", {
      threadId: "foreman-a-2",
      hostId: "recovery-host",
      payload: { role: "CAPTAIN", reason: "captain lease expired", attempts: 1 },
    });
    registerRole(fixture, "CAPTAIN", { thread: "captain-a-2", attempt: 2 });
    apply(fixture, book, "ROLE_RECOVERED", "FOREMAN", {
      threadId: "foreman-a-2",
      hostId: "recovery-host",
      payload: { successor_thread_id: "captain-a-2" },
    });

    book.CAPTAIN = 0;
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      threadId: "captain-a-2",
      payload: { role: "DEV", reason: "dev lease expired", attempts: 1 },
    });
    registerRole(fixture, "DEV", { thread: "dev-a-2", attempt: 2 });
    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      threadId: "captain-a-2",
      payload: { successor_thread_id: "dev-a-2" },
    });

    expect(taskStatus(fixture)).toMatchObject({
      phase: "DEV_ACTIVE",
      recovery: null,
      sessions: {
        FOREMAN: { thread_id: "foreman-a-2", attempt: 2, status: "active" },
        CAPTAIN: { thread_id: "captain-a-2", attempt: 2, status: "active" },
        DEV: { thread_id: "dev-a-2", attempt: 2, status: "active" },
      },
      session_history: {
        FOREMAN: [{ thread_id: THREADS.FOREMAN, attempt: 1 }],
        CAPTAIN: [{ thread_id: THREADS.CAPTAIN, attempt: 1 }],
        DEV: [{ thread_id: THREADS.DEV, attempt: 1 }],
      },
    });
  });

  it("rejects expired FOREMAN recovery while its lease is still active", () => {
    initAndRegister(fixture);
    const before = taskStatus(fixture);

    expectControlError(recoverExpiredForeman(fixture), "FOREMAN_LEASE_ACTIVE");
    expect(taskStatus(fixture)).toEqual(before);
  });

  it("rejects expired FOREMAN recovery with the wrong Goal recovery capability", () => {
    initAndRegister(fixture);
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const wrongCapability = path.join(fixture.root, "wrong-foreman-recovery.cap");
    writeFileSync(wrongCapability, "a".repeat(48) + "\n", { mode: 0o600 });

    expectControlError(
      recoverExpiredForeman(fixture, { capabilityFile: wrongCapability }),
      "CAPABILITY_INVALID"
    );
    expect(taskStatus(fixture)).toEqual(before);
  });

  it("preserves a pending worker recovery until fresh FOREMAN and CAPTAIN are active", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: { role: "DEV", reason: "dev session terminated", attempts: 1 },
    });
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const recovered = recoverExpiredForeman(fixture, { snapshot: before });
    expect(recovered.code).toBe(0);
    const recoveredBody = json(recovered);
    fixture.capabilities["TASK-A"].FOREMAN = String(recoveredBody.actor_capability_file);
    expect(taskStatus(fixture)).toMatchObject({
      recovery: null,
      recovery_backlog: [{ role: "DEV" }],
      sessions: { FOREMAN: { thread_id: "foreman-a-2", attempt: 2 } },
    });

    const projected = runCli([
      "actions",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "FOREMAN",
      "--thread", "foreman-a-2",
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    const exactCaptainLoss = (
      json(projected).actions as Array<{
        type: string;
        actor_role: string;
        target_role?: string;
        event_id?: string;
        payload?: Record<string, unknown>;
      }>
    ).filter((action) => action.type === "ROLE_LOST");
    expect(exactCaptainLoss).toHaveLength(1);
    expect(exactCaptainLoss[0]).toMatchObject({
      actor_role: "FOREMAN",
      target_role: "CAPTAIN",
      event_id: expect.stringMatching(
        /^role-lost-captain-task-a-a1-[0-9a-f]{16}$/,
      ),
      payload: {
        role: "CAPTAIN",
        expected_thread_id: THREADS.CAPTAIN,
        expected_host_id: "local",
        expected_attempt: 1,
        expected_lease_until:
          before.sessions?.CAPTAIN?.lease_until,
      },
    });
    const staleCaptainPayload =
      exactCaptainLoss[0].payload as Record<string, unknown>;

    book.FOREMAN = 0;
    apply(fixture, book, "ROLE_LOST", "FOREMAN", {
      eventId: exactCaptainLoss[0].event_id,
      threadId: "foreman-a-2",
      hostId: "recovery-host",
      payload: staleCaptainPayload,
    });
    registerRole(fixture, "CAPTAIN", { thread: "captain-a-2", attempt: 2 });
    apply(fixture, book, "ROLE_RECOVERED", "FOREMAN", {
      threadId: "foreman-a-2",
      hostId: "recovery-host",
      payload: { successor_thread_id: "captain-a-2" },
    });
    expect(taskStatus(fixture)).toMatchObject({
      recovery: { role: "DEV" },
      recovery_backlog: [],
    });

    book.CAPTAIN = 0;
    registerRole(fixture, "DEV", { thread: "dev-a-2", attempt: 2 });
    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      threadId: "captain-a-2",
      payload: { successor_thread_id: "dev-a-2" },
    });
    expect(taskStatus(fixture)).toMatchObject({
      phase: "DEV_ACTIVE",
      recovery: null,
      recovery_backlog: [],
      sessions: {
        FOREMAN: { thread_id: "foreman-a-2", status: "active" },
        CAPTAIN: { thread_id: "captain-a-2", status: "active" },
        DEV: { thread_id: "dev-a-2", status: "active" },
      },
    });

    const beforeStaleReplay = taskStatus(fixture);
    const staleReplay = buildEvent(
      fixture,
      "ROLE_LOST",
      "FOREMAN",
      book.FOREMAN + 1,
      {
        eventId: `stale-${exactCaptainLoss[0].event_id}`,
        threadId: "foreman-a-2",
        hostId: "recovery-host",
        payload: staleCaptainPayload,
      },
    );
    expectControlError(
      submitEvent(
        fixture,
        staleReplay,
        fixture.capabilities["TASK-A"].FOREMAN,
      ),
      "ROLE_LOST_TARGET_STALE",
    );
    expect(taskStatus(fixture)).toEqual(beforeStaleReplay);
  });

  it("atomically closes a pending FOREMAN recovery after the CAPTAIN also expires", () => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: { role: "FOREMAN", reason: "foreman session stopped", attempts: 1 },
    });
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);

    const recovered = recoverExpiredForeman(fixture, { snapshot: before });
    expect(recovered.code).toBe(0);
    expect(taskStatus(fixture)).toMatchObject({
      recovery: null,
      recovery_backlog: [],
      sessions: {
        FOREMAN: { thread_id: "foreman-a-2", attempt: 2, status: "active" },
        CAPTAIN: { thread_id: THREADS.CAPTAIN, attempt: 1 },
      },
      session_history: {
        FOREMAN: [{ thread_id: THREADS.FOREMAN, attempt: 1, status: "lost" }],
      },
    });
  });

  it("recovers an expired FOREMAN while a live successor CAPTAIN is awaiting FOREMAN confirmation", () => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "ROLE_LOST", "FOREMAN", {
      payload: { role: "CAPTAIN", reason: "captain-1 stopped", attempts: 1 },
    });
    registerRole(fixture, "CAPTAIN", {
      thread: "captain-a-2",
      attempt: 2,
      leaseMs: 4 * 60 * 60 * 1000,
    });
    const pending = taskStatus(fixture);
    const foremanLease = Date.parse(pending.sessions?.FOREMAN?.lease_until as string);
    const successorCaptainLease = Date.parse(pending.sessions?.CAPTAIN?.lease_until as string);
    expect(successorCaptainLease).toBeGreaterThan(foremanLease);
    process.env.GOAL_CONTROL_NOW = new Date(foremanLease + 1).toISOString();

    const doctorResult = runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir
    );
    expect(doctorResult.code).toBe(1);
    expect(json(doctorResult)).toMatchObject({
      findings: expect.arrayContaining([
        expect.objectContaining({ code: "FOREMAN_RECOVERY_DEADLOCK", role: "GOAL_RECOVERY" }),
      ]),
    });

    const recovered = recoverExpiredForeman(fixture, { snapshot: pending });
    expect(recovered.code).toBe(0);
    const recoveredBody = json(recovered);
    fixture.capabilities["TASK-A"].FOREMAN = String(recoveredBody.actor_capability_file);
    expect(taskStatus(fixture)).toMatchObject({
      recovery: { role: "CAPTAIN", successor_thread_id: "captain-a-2" },
      sessions: {
        FOREMAN: { thread_id: "foreman-a-2", status: "active" },
        CAPTAIN: { thread_id: "captain-a-2", status: "active" },
      },
    });

    book.FOREMAN = 0;
    apply(fixture, book, "ROLE_RECOVERED", "FOREMAN", {
      threadId: "foreman-a-2",
      hostId: "recovery-host",
      payload: { successor_thread_id: "captain-a-2" },
    });
    expect(taskStatus(fixture)).toMatchObject({
      recovery: null,
      sessions: {
        FOREMAN: { thread_id: "foreman-a-2", status: "active" },
        CAPTAIN: { thread_id: "captain-a-2", status: "active" },
      },
    });
  });

  it("blocks a live worker verdict while its recovery is parked behind control-role restoration", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: { role: "DEV", reason: "dev-1 stopped", attempts: 1 },
    });
    registerRole(fixture, "DEV", {
      thread: "dev-a-2",
      attempt: 2,
      leaseMs: 4 * 60 * 60 * 1000,
    });
    const pending = taskStatus(fixture);
    const foremanLease = Date.parse(pending.sessions?.FOREMAN?.lease_until as string);
    const captainLease = Date.parse(pending.sessions?.CAPTAIN?.lease_until as string);
    const successorDevLease = Date.parse(pending.sessions?.DEV?.lease_until as string);
    const controlLease = Math.max(foremanLease, captainLease);
    expect(successorDevLease).toBeGreaterThan(controlLease);
    process.env.GOAL_CONTROL_NOW = new Date(controlLease + 1).toISOString();

    const recovered = recoverExpiredForeman(fixture, { snapshot: pending });
    expect(recovered.code).toBe(0);
    const parked = taskStatus(fixture) as unknown as Record<string, unknown>;
    expect(parked).toMatchObject({
      recovery: null,
      recovery_backlog: [{ role: "DEV", successor_thread_id: "dev-a-2" }],
    });
    const verdict = buildEvent(fixture, "DEV_READY", "DEV", 1, {
      threadId: "dev-a-2",
      payload: {},
    });
    verdict.accepted_at = new Date(controlLease + 2).toISOString();

    expect(() => goalFsm.applyEvent(parked, verdict, Number(parked.control_epoch))).toThrow(
      expect.objectContaining({ code: "RECOVERY_BACKLOG_REQUIRED" })
    );
  });

  it("rejects expired FOREMAN recovery that reuses the old identity", () => {
    initAndRegister(fixture);
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);

    expectControlError(
      recoverExpiredForeman(fixture, {
        thread: THREADS.FOREMAN,
        host: "local",
      }),
      "ROLE_IDENTITY_REUSE"
    );
    expect(taskStatus(fixture)).toEqual(before);
  });

  it("rejects expired FOREMAN recovery with a stale state-revision CAS", () => {
    initAndRegister(fixture);
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);

    expectControlError(
      recoverExpiredForeman(fixture, {
        expectedStateRevision: before.state_revision - 1,
      }),
      "STALE_STATE_REVISION"
    );
    expect(taskStatus(fixture)).toEqual(before);
  });

  it("retries the exact recovery request idempotently without appending or minting a second capability", () => {
    initAndRegister(fixture);
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const eventId = `recover-${randomUUID()}`;

    const first = recoverExpiredForeman(fixture, { snapshot: before, eventId });
    expect(first.code).toBe(0);
    const firstBody = json(first);
    fixture.capabilities["TASK-A"].FOREMAN = String(
      firstBody.actor_capability_file,
    );
    const progress = buildEvent(fixture, "HEARTBEAT", "FOREMAN", 1, {
      threadId: "foreman-a-2",
      hostId: "recovery-host",
      payload: { lease_ms: 3600000, status: "active" },
    });
    expect(submitEvent(fixture, progress).code).toBe(0);
    const afterProgress = taskStatus(fixture);
    unlinkSync(path.join(fixture.root, "docs", "protocol", "shared.md"));

    const repeated = recoverExpiredForeman(fixture, { snapshot: before, eventId });
    expect(repeated.code).toBe(0);
    expect(json(repeated)).toMatchObject({
      recovered: true,
      idempotent: true,
      event_id: eventId,
      actor_capability_file: firstBody.actor_capability_file,
    });
    expect(taskStatus(fixture)).toEqual(afterProgress);
  });

  it("preserves the successor capability when failure happens after the recovery event is durably installed", () => {
    initAndRegister(fixture);
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const eventId = `recover-fault-${randomUUID()}`;
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL = "1";

    const interrupted = recoverExpiredForeman(fixture, { snapshot: before, eventId });
    expectControlError(interrupted, "TEST_FAULT_AFTER_EVENT_INSTALL");
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL;

    const repeated = recoverExpiredForeman(fixture, { snapshot: before, eventId });
    expect(repeated.code).toBe(0);
    const body = json(repeated);
    expect(body).toMatchObject({
      recovered: true,
      idempotent: true,
      cache_degraded: false,
      event_id: eventId,
    });
    expect(existsSync(String(body.actor_capability_file))).toBe(true);

    const goalDir = path.join(fixture.controlDir, "goals", "demo");
    const projectedState = JSON.parse(
      readFileSync(path.join(goalDir, "state.json"), "utf8")
    ) as { tasks: Record<string, TaskStatus> };
    expect(projectedState.tasks["TASK-A"]).toMatchObject({
      state_revision: before.state_revision + 1,
      last_event: { event_id: eventId, type: "RECOVER_EXPIRED_FOREMAN" },
      sessions: { FOREMAN: { thread_id: "foreman-a-2", attempt: 2 } },
    });
    const projectedLedger = JSON.parse(
      readFileSync(path.join(goalDir, "ledger.json"), "utf8")
    ) as { tasks: Array<{ task_id: string; sessions: string }> };
    expect(projectedLedger.tasks.find((task) => task.task_id === "TASK-A")).toMatchObject({
      sessions: expect.stringContaining("FOREMAN:foreman-a-2@2"),
    });
    expect(readFileSync(path.join(goalDir, "ledger.md"), "utf8")).toContain(
      "FOREMAN:foreman-a-2@2"
    );

    expect(taskStatus(fixture)).toMatchObject({
      state_revision: before.state_revision + 1,
      last_event: { event_id: eventId, type: "RECOVER_EXPIRED_FOREMAN" },
      sessions: { FOREMAN: { thread_id: "foreman-a-2", attempt: 2 } },
    });
  });

  it("recovers every non-ARCHIVED FOREMAN projection in one Goal-scope batch", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    const taskAForeman = fixture.capabilities["TASK-A"].FOREMAN as string;
    const taskBForeman = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", taskAForeman, "--json",
    ], fixture.root, fixture.controlDir);
    expect(taskBForeman.code).toBe(0);
    expect(json(taskBForeman).actor_capability_file).toBe(taskAForeman);
    registerRole(fixture, "CAPTAIN");
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);

    const doctorResult = runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir
    );
    expect(doctorResult.code).toBe(1);
    expect(json(doctorResult)).toMatchObject({
      findings: expect.arrayContaining([
        expect.objectContaining({ code: "FOREMAN_RECOVERY_DEADLOCK", role: "GOAL_RECOVERY" }),
      ]),
    });

    const recovered = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId: `recover-multi-${randomUUID()}`,
    });
    expect(recovered.code).toBe(0);
    expect(json(recovered)).toMatchObject({
      recovered_task_ids: ["TASK-A", "TASK-B"],
      tasks: {
        "TASK-A": { sessions: { FOREMAN: { thread_id: "foreman-a-2", attempt: 2 } } },
        "TASK-B": { sessions: { FOREMAN: { thread_id: "foreman-a-2", attempt: 2 } } },
      },
    });
    expect(taskStatus(fixture, "TASK-B")).toMatchObject({
      sessions: { FOREMAN: { thread_id: "foreman-a-2", attempt: 2 } },
    });

    const oldAuthority = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "CAPTAIN",
      "--thread", "captain-b-old-authority", "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", taskAForeman, "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(oldAuthority, "CAPABILITY_INVALID");
  });

  it("promotes one sealed root-recovery staging with identical time and capability bytes", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    const oldForemanCapability =
      fixture.capabilities["TASK-A"].FOREMAN as string;
    registerRole(fixture, "CAPTAIN");
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const eventId = `recover-prepared-${randomUUID()}`;

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_STAGING_SEAL = "throw";
    const interrupted = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    });
    expectControlError(
      interrupted,
      "TEST_FAULT_AFTER_RECOVERY_STAGING_SEAL",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_STAGING_SEAL;

    const batchParent = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "foreman-recovery-batches",
    );
    const stagingName = readdirSync(batchParent).find((name) =>
      name.startsWith(".init-foreman-recovery-")
    );
    expect(stagingName).toBeDefined();
    const stagingDir = path.join(batchParent, stagingName as string);
    const batchDir = path.join(batchParent, eventId);
    expect(existsSync(batchDir)).toBe(false);
    const stagedIntentBytes = readFileSync(
      path.join(stagingDir, "intent.json"),
      "utf8",
    );
    const stagedIntent = JSON.parse(stagedIntentBytes) as {
      accepted_at: string;
      capability_file: string;
    };
    const capabilityName = readdirSync(stagingDir).find((name) =>
      name.endsWith(".cap")
    );
    expect(capabilityName).toBeDefined();
    const stagedCapabilityBytes = readFileSync(
      path.join(stagingDir, capabilityName as string),
      "utf8",
    );

    const divergent = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
      thread: "foreman-divergent-2",
    });
    expectControlError(divergent, "PREPARED_REQUEST_MISMATCH");
    expect(existsSync(stagingDir)).toBe(true);
    expect(existsSync(batchDir)).toBe(false);

    const unrelated = runCli([
      "register-role",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", "captain-during-prepared-root",
      "--host", "local",
      "--attempt", "2",
      "--event-id", `register-during-prepared-root-${randomUUID()}`,
      "--authorizer-capability-file", oldForemanCapability,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(unrelated, "RECOVERY_BATCH_INCOMPLETE");
    expect(existsSync(stagingDir)).toBe(true);

    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(stagedIntent.accepted_at) + 60 * 60 * 1000,
    ).toISOString();
    const recovered = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    });
    expect(recovered.code).toBe(0);
    expect(existsSync(stagingDir)).toBe(false);
    expect(readFileSync(path.join(batchDir, "intent.json"), "utf8"))
      .toBe(stagedIntentBytes);
    expect(readFileSync(
      path.join(batchDir, capabilityName as string),
      "utf8",
    )).toBe(stagedCapabilityBytes);
    expect(json(recovered)).toMatchObject({
      recovered: true,
      event_id: eventId,
      actor_capability_file: stagedIntent.capability_file,
    });
    const accepted = readdirSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "events",
      "TASK-A",
    )).map((name) => JSON.parse(readFileSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "events",
      "TASK-A",
      name,
    ), "utf8")) as { event_id: string; accepted_at: string });
    expect(accepted.find((event) => event.event_id === eventId)?.accepted_at)
      .toBe(stagedIntent.accepted_at);
  });

  it("cleans only an exact unsealed root-recovery staging before retrying", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    registerRole(fixture, "CAPTAIN");
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const eventId = `recover-unsealed-${randomUUID()}`;

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_STAGING_SEAL = "exit";
    expect(recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    }).code).toBe(86);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_STAGING_SEAL;

    const batchParent = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "foreman-recovery-batches",
    );
    const stagingName = readdirSync(batchParent).find((name) =>
      name.startsWith(".init-foreman-recovery-")
    );
    expect(stagingName).toBeDefined();
    const stagingDir = path.join(batchParent, stagingName as string);
    for (const entry of readdirSync(stagingDir)) {
      rmSync(path.join(stagingDir, entry), { recursive: true, force: true });
    }
    const partialIntent = path.join(
      stagingDir,
      `.intent.json.4242.tmp-${"c".repeat(24)}`,
    );
    writeFileSync(partialIntent, "{\"partial\":", { mode: 0o600 });

    const divergent = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
      thread: "foreman-unsealed-divergent-2",
    });
    expectControlError(divergent, "PREPARED_REQUEST_MISMATCH");
    expect(readFileSync(partialIntent, "utf8")).toBe("{\"partial\":");

    const retried = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    });
    expect(retried.code).toBe(0);
    expect(existsSync(stagingDir)).toBe(false);
    const finalDir = path.join(batchParent, eventId);
    expect(readdirSync(finalDir).filter((name) => name.endsWith(".cap")))
      .toHaveLength(1);
    expect(readFileSync(path.join(finalDir, "intent.json"), "utf8"))
      .not.toContain("\"partial\"");
  });

  it("rejects a derived event-id collision before publishing a recovery intent and remains recoverable", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    const foremanCapability = fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", foremanCapability, "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    fixture.capabilities["TASK-B"].FOREMAN = foremanCapability;

    const rootRecoveryId = `recover-collision-${randomUUID()}`;
    const derivedTaskBEventId = `${rootRecoveryId}.task.${
      createHash("sha256").update("TASK-B").digest("hex").slice(0, 16)
    }`;
    const collision = buildEvent(fixture, "HEARTBEAT", "FOREMAN", 1, {
      taskId: "TASK-B",
      eventId: derivedTaskBEventId,
      payload: { lease_ms: 1, status: "active" },
    });
    expect(submitEvent(fixture, collision, foremanCapability).code).toBe(0);
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);

    const rejected = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId: rootRecoveryId,
    });
    expectControlError(rejected, "EVENT_ID_CONFLICT");
    expect(existsSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "foreman-recovery-batches",
      rootRecoveryId,
    ))).toBe(false);
    const generation = JSON.parse(readFileSync(
      path.join(fixture.controlDir, ".generation.json"),
      "utf8",
    )) as { generation: number };
    expect(generation.generation % 2).toBe(0);

    const recovered = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId: `recover-after-collision-${randomUUID()}`,
    });
    expect(recovered.code).toBe(0);
    expect(json(recovered)).toMatchObject({
      recovered_task_ids: ["TASK-A", "TASK-B"],
    });
  });

  it("forbids task-local FOREMAN replacement across multiple projections and permits one Goal batch despite a live CAPTAIN", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    const oldForemanCapability = fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", oldForemanCapability, "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    fixture.capabilities["TASK-B"].FOREMAN = oldForemanCapability;
    registerRole(fixture, "CAPTAIN", { leaseMs: 4 * 60 * 60 * 1000 });
    const book = sequences();
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: {
        role: "FOREMAN",
        reason: "Goal FOREMAN session terminated",
        attempts: 1,
      },
    });

    const localReplacementId = `register-local-foreman-${randomUUID()}`;
    const localReplacement = runCli([
      "register-role",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "FOREMAN",
      "--thread", "foreman-local-2",
      "--host", "local",
      "--attempt", "2",
      "--event-id", localReplacementId,
      "--foreman-recovery-capability-file",
      fixture.foremanRecoveryCapability as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(localReplacement, "GOAL_FOREMAN_BATCH_REQUIRED");
    expect(existsSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "registration-intents",
      localReplacementId,
    ))).toBe(false);
    expect(taskStatus(fixture, "TASK-B")).toMatchObject({
      sessions: { FOREMAN: { thread_id: THREADS.FOREMAN, attempt: 1 } },
    });

    const foremanLeaseUntil = Math.max(
      Date.parse(taskStatus(fixture).sessions?.FOREMAN?.lease_until as string),
      Date.parse(
        taskStatus(fixture, "TASK-B").sessions?.FOREMAN?.lease_until as string,
      ),
    );
    const captainLeaseUntil = Date.parse(
      taskStatus(fixture).sessions?.CAPTAIN?.lease_until as string,
    );
    expect(captainLeaseUntil).toBeGreaterThan(foremanLeaseUntil);
    process.env.GOAL_CONTROL_NOW = new Date(foremanLeaseUntil + 1).toISOString();
    const before = taskStatus(fixture);
    const recovered = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId: `recover-goal-foreman-${randomUUID()}`,
    });
    expect(recovered.code).toBe(0);
    const recovery = json(recovered);
    expect(recovery).toMatchObject({
      recovered_task_ids: ["TASK-A", "TASK-B"],
      tasks: {
        "TASK-A": {
          sessions: {
            FOREMAN: { thread_id: "foreman-a-2", attempt: 2 },
          },
        },
        "TASK-B": {
          sessions: {
            FOREMAN: { thread_id: "foreman-a-2", attempt: 2 },
          },
        },
      },
    });
    const successorCapability = String(recovery.actor_capability_file);
    const heartbeatB = buildEvent(fixture, "HEARTBEAT", "FOREMAN", 1, {
      taskId: "TASK-B",
      threadId: "foreman-a-2",
      hostId: "recovery-host",
      payload: { lease_ms: 3600000, status: "active" },
    });
    expect(submitEvent(fixture, heartbeatB, successorCapability).code).toBe(0);
  });

  it("fails closed before recovery intent when max-attempt FOREMAN replicas have different capabilities", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    const taskAForeman = fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", taskAForeman, "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    registerRole(fixture, "CAPTAIN");

    const goalDir = path.join(fixture.controlDir, "goals", "demo");
    const divergentCapabilityDir = path.join(
      goalDir,
      "capabilities",
      "TASK-B",
      "foreman",
    );
    mkdirSync(divergentCapabilityDir, { recursive: true });
    const divergentCapabilityFile = path.join(
      divergentCapabilityDir,
      `foreman-divergent-${randomUUID()}.cap`,
    );
    const divergentCapability = createHash("sha256")
      .update(randomUUID())
      .digest("base64url");
    writeFileSync(
      divergentCapabilityFile,
      `${divergentCapability}\n`,
      { mode: 0o600 },
    );
    const eventDir = path.join(goalDir, "events", "TASK-B");
    const eventFile = path.join(
      eventDir,
      readdirSync(eventDir).find((name) => name.endsWith(".json")) as string,
    );
    const accepted = JSON.parse(
      readFileSync(eventFile, "utf8"),
    ) as Record<string, unknown> & {
      payload: Record<string, unknown>;
      event_sha256?: string;
    };
    accepted.payload.capability_file = realpathSync(divergentCapabilityFile);
    accepted.payload.capability_sha256 = createHash("sha256")
      .update(divergentCapability)
      .digest("hex");
    const input = { ...accepted };
    for (const key of [
      "input_sha256",
      "accepted_at",
      "log_sequence",
      "previous_event_sha256",
      "event_sha256",
    ]) {
      delete input[key];
    }
    accepted.input_sha256 = sha256(
      JSON.stringify(canonicalize(input)),
    );
    delete accepted.event_sha256;
    accepted.event_sha256 = sha256(
      JSON.stringify(canonicalize(accepted)),
    );
    writeFileSync(eventFile, `${JSON.stringify(accepted, null, 2)}\n`);

    const headFile = path.join(goalDir, "event-heads", "TASK-B.json");
    const head = JSON.parse(readFileSync(headFile, "utf8")) as Record<string, unknown>;
    head.last_event_sha256 = accepted.event_sha256;
    delete head.head_sha256;
    head.head_sha256 = sha256(JSON.stringify(canonicalize(head)));
    writeFileSync(headFile, `${JSON.stringify(head, null, 2)}\n`);

    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const eventId = `recover-divergent-${randomUUID()}`;
    const recovery = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    });
    expectControlError(recovery, "GOAL_FOREMAN_LINEAGE_DIVERGED");
    expect(existsSync(path.join(
      goalDir,
      "foreman-recovery-batches",
      eventId,
    ))).toBe(false);
  });

  it("blocks unrelated writers after a partial Goal recovery and exact-retries the batch", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    const oldForeman = fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", oldForeman, "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    registerRole(fixture, "CAPTAIN");
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const eventId = `recover-partial-${randomUUID()}`;

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL = "1";
    const interrupted = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    });
    expectControlError(interrupted, "TEST_FAULT_AFTER_EVENT_INSTALL");
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ACCEPTED_EVENT_INSTALL;

    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const interruptedGenerationBytes = readFileSync(generationFile, "utf8");
    const goalDirectory = path.join(
      fixture.controlDir,
      "goals",
      "demo",
    );
    const interruptedGoalTree = controlTreeSnapshot(goalDirectory);
    const unrelated = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "CAPTAIN",
      "--thread", "captain-b-during-partial", "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", oldForeman, "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(unrelated, "STORE_TRANSACTION_MISMATCH");
    expectControlError(runCli(
      ["status", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    ), "STORE_REPAIR_REQUIRED");
    expectControlError(runCli(
      ["next", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    ), "STORE_REPAIR_REQUIRED");
    expect(readFileSync(generationFile, "utf8"))
      .toBe(interruptedGenerationBytes);
    expect(controlTreeSnapshot(goalDirectory)).toEqual(interruptedGoalTree);

    const completed = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    });
    expect(completed.code).toBe(0);
    expect(json(completed)).toMatchObject({
      recovered_task_ids: ["TASK-A", "TASK-B"],
      tasks: {
        "TASK-A": { sessions: { FOREMAN: { attempt: 2 } } },
        "TASK-B": { sessions: { FOREMAN: { attempt: 2 } } },
      },
    });
    const finalStatus = json(runCli(
      ["status", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    )) as { pending_foreman_recovery?: unknown };
    expect(finalStatus.pending_foreman_recovery).toBeNull();
  });

  it("reaps a process-exited recovery writer and exact-retries its durable partial batch", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    const oldForeman = fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", oldForeman, "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    registerRole(fixture, "CAPTAIN");
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const eventId = `recover-process-exit-${randomUUID()}`;

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_TASK_EVENT_INSTALL = "exit";
    const interrupted = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    });
    expect(interrupted.code).not.toBe(0);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECOVERY_TASK_EVENT_INSTALL;

    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const interruptedGeneration = JSON.parse(
      readFileSync(generationFile, "utf8"),
    ) as { generation: number };
    expect(interruptedGeneration.generation % 2).toBe(1);
    const lockOwnerFile = path.join(fixture.controlDir, ".lock", "owner.json");
    const owner = JSON.parse(
      readFileSync(lockOwnerFile, "utf8"),
    ) as Record<string, unknown>;
    const staleOwner: Record<string, unknown> & {
      acquired_at: string;
      owner_sha256?: string;
    } = {
      ...owner,
      acquired_at: "2000-01-01T00:00:00.000Z",
    };
    delete staleOwner.owner_sha256;
    staleOwner.owner_sha256 = sha256(
      JSON.stringify(canonicalize(staleOwner)),
    );
    writeFileSync(lockOwnerFile, `${JSON.stringify(staleOwner, null, 2)}\n`);

    const batchRoot = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "foreman-recovery-batches",
    );
    const batchDir = path.join(batchRoot, eventId);
    expect(existsSync(path.join(batchDir, "intent.json"))).toBe(true);
    expect(existsSync(path.join(batchDir, "commit.json"))).toBe(false);
    expect(
      readdirSync(batchDir).filter((name) => name.endsWith(".cap")),
    ).toHaveLength(1);
    expect(
      readdirSync(batchRoot).some((name) => name.startsWith(".init-")),
    ).toBe(false);
    expect(
      readdirSync(path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "events",
        "TASK-A",
      )).some((name) => name.includes(eventId)),
    ).toBe(true);
    expect(
      readdirSync(path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "events",
        "TASK-B",
      )).some((name) => name.includes(eventId)),
    ).toBe(false);

    const interruptedGoalTree = controlTreeSnapshot(path.join(
      fixture.controlDir,
      "goals",
      "demo",
    ));
    const unrelated = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "CAPTAIN",
      "--thread", "captain-b-during-process-exit", "--host", "local", "--attempt", "1",
      "--event-id", `register-during-process-exit-${randomUUID()}`,
      "--authorizer-capability-file", oldForeman, "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(unrelated, "STORE_TRANSACTION_MISMATCH");
    expect(() => lstatSync(path.join(fixture.controlDir, ".lock"))).toThrow();
    const repairedGeneration = JSON.parse(
      readFileSync(generationFile, "utf8"),
    ) as { generation: number };
    expect(repairedGeneration.generation)
      .toBe(interruptedGeneration.generation);
    expect(repairedGeneration.generation % 2).toBe(1);
    expect(controlTreeSnapshot(path.join(
      fixture.controlDir,
      "goals",
      "demo",
    ))).toEqual(interruptedGoalTree);
    const reapedGenerationBytes = readFileSync(generationFile, "utf8");
    const crashSnapshot = runCli(
      ["status", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    );
    expect(crashSnapshot.code).toBe(0);
    expect(json(crashSnapshot)).toMatchObject({
      control_store_read: {
        complete: false,
        writer_crash_marker: true,
        transaction_kind: "FOREMAN_RECOVERY",
        required_action:
          "retry the original write with the same stable operation ID",
      },
    });
    expect(readFileSync(generationFile, "utf8"))
      .toBe(reapedGenerationBytes);

    const completed = recoverExpiredForeman(fixture, {
      snapshot: before,
      eventId,
    });
    expect(completed.code).toBe(0);
    expect(json(completed)).toMatchObject({
      recovered: true,
      recovered_task_ids: ["TASK-A", "TASK-B"],
    });
    expect(existsSync(path.join(batchDir, "commit.json"))).toBe(true);
    expect(
      readdirSync(batchDir).filter((name) => name.endsWith(".cap")),
    ).toHaveLength(1);
    expect(
      readdirSync(batchRoot).some((name) => name.startsWith(".init-")),
    ).toBe(false);
  });

  it("detaches an expired FOREMAN from an ARCHIVED task by adopting F2 on the next task", () => {
    initAndRegister(fixture);
    const oldForemanCapability = fixture.capabilities["TASK-A"].FOREMAN as string;
    const book = sequences();
    advanceToDevActive(fixture, book);
    advanceDevActiveToArchived(fixture, book);
    const archivedBefore = taskStatus(fixture, "TASK-A");
    const archivedEventDir = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "events",
      "TASK-A",
    );
    const archivedEventBytes = readdirSync(archivedEventDir)
      .sort()
      .map((file) => readFileSync(path.join(archivedEventDir, file), "utf8"));
    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(archivedBefore.sessions?.FOREMAN?.lease_until as string) + 1,
    ).toISOString();
    const queuedBefore = taskStatus(fixture, "TASK-B");

    const recovered = recoverExpiredForeman(fixture, {
      taskId: "TASK-B",
      snapshot: queuedBefore,
      eventId: `recover-archived-${randomUUID()}`,
    });
    expect(recovered.code).toBe(0);
    expect(json(recovered)).toMatchObject({
      recovered_task_ids: ["TASK-B"],
      source_task_ids: ["TASK-A"],
      tasks: {
        "TASK-B": {
          sessions: {
            FOREMAN: { thread_id: "foreman-a-2", attempt: 2 },
          },
        },
      },
    });
    const archivedAfter = taskStatus(fixture, "TASK-A");
    const stripDerivedActions = (value: TaskStatus) => {
      const stable = { ...(value as Record<string, unknown>) };
      delete stable.maintenance_actions;
      delete stable.next_actions;
      delete stable.operational_scope;
      return stable;
    };
    expect(stripDerivedActions(archivedAfter)).toEqual(
      stripDerivedActions(archivedBefore),
    );
    expect(readdirSync(archivedEventDir).sort().map(
      (file) => readFileSync(path.join(archivedEventDir, file), "utf8"),
    )).toEqual(archivedEventBytes);

    const oldAuthority = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "CAPTAIN",
      "--thread", "captain-after-archived", "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", oldForemanCapability, "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(oldAuthority, "CAPABILITY_INVALID");
  });

  it("rejects every stale control, ledger, packet, HEAD, and incumbent-FOREMAN CAS binding", () => {
    initAndRegister(fixture);
    expireRegisteredRoles(fixture);
    const before = taskStatus(fixture);
    const foreman = before.sessions?.FOREMAN;
    const staleHash = `sha256:${"0".repeat(64)}`;
    const staleHead = "f".repeat(40);
    const staleLease = new Date(Date.parse(foreman?.lease_until as string) + 1).toISOString();
    const cases: Array<[RecoverForemanOverrides, string]> = [
      [{ expectedControlEpoch: before.control_epoch + 1 }, "STALE_CONTROL_EPOCH"],
      [{ expectedEventHead: staleHash }, "STALE_EVENT_HEAD"],
      [{ expectedPacketRevision: before.packet.revision + 1 }, "STALE_PACKET"],
      [{ expectedPacketSha256: staleHash }, "STALE_PACKET"],
      [{ expectedFullHead: staleHead }, "STALE_HEAD"],
      [{ expectedForemanThread: "stale-foreman-thread" }, "STALE_FOREMAN_IDENTITY"],
      [{ expectedForemanHost: "stale-foreman-host" }, "STALE_FOREMAN_IDENTITY"],
      [{ expectedForemanAttempt: (foreman?.attempt as number) + 1 }, "STALE_ROLE_ATTEMPT"],
      [{ expectedForemanLeaseUntil: staleLease }, "STALE_FOREMAN_LEASE"],
    ];

    for (const [overrides, code] of cases) {
      expectControlError(recoverExpiredForeman(fixture, overrides), code);
      expect(taskStatus(fixture)).toEqual(before);
    }
  });

  it("rejects a stale full Goal-scope CAS when a different task changes", () => {
    initGoal(fixture);
    registerRole(fixture, "FOREMAN");
    const foremanCapability = fixture.capabilities["TASK-A"].FOREMAN as string;
    const projected = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-B", "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN, "--host", "local", "--attempt", "1",
      "--authorizer-capability-file", foremanCapability, "--json",
    ], fixture.root, fixture.controlDir);
    expect(projected.code).toBe(0);
    fixture.capabilities["TASK-B"].FOREMAN = foremanCapability;
    registerRole(fixture, "CAPTAIN");
    const staleAnchor = taskStatus(fixture, "TASK-A");

    const heartbeatB = buildEvent(fixture, "HEARTBEAT", "FOREMAN", 1, {
      taskId: "TASK-B",
      payload: { lease_ms: 1000, status: "active" },
    });
    expect(submitEvent(fixture, heartbeatB).code).toBe(0);
    expireRegisteredRoles(fixture);

    expectControlError(
      recoverExpiredForeman(fixture, {
        snapshot: staleAnchor,
        eventId: `recover-stale-scope-${randomUUID()}`,
      }),
      "STALE_FOREMAN_SCOPE",
    );
  });

  it("computes a deterministic non-conflicting next batch and blocks a conflicting active task", () => {
    const manifest = JSON.parse(readFileSync(fixture.manifest, "utf8"));
    manifest.tasks[0].conflict_domains = ["shared-generated-surface"];
    manifest.tasks[1].dependencies = [];
    manifest.tasks[1].conflict_domains = ["shared-generated-surface"];
    writeFileSync(fixture.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
    git(fixture.root, "add", fixture.manifest);
    git(fixture.root, "commit", "-qm", "declare parallel conflict");
    fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");

    initGoal(fixture);
    const initial = json(runCli(["next", "--goal", "demo", "--json"], fixture.root, fixture.controlDir)) as {
      batch: Array<{ task_id: string }>;
      eligible: Array<{ task_id: string; deferred_by_conflict?: string }>;
    };
    expect(initial.batch.map((item) => item.task_id)).toEqual(["TASK-A"]);
    expect(initial.eligible.find((item) => item.task_id === "TASK-B")).toMatchObject({ deferred_by_conflict: "TASK-A" });

    registerRole(fixture, "FOREMAN");
    registerRole(fixture, "CAPTAIN");
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    const afterStart = json(runCli(["next", "--goal", "demo", "--json"], fixture.root, fixture.controlDir)) as {
      tasks: Array<{ task_id: string; eligible: boolean; reasons: string[] }>;
    };
    expect(afterStart.tasks.find((item) => item.task_id === "TASK-B")).toMatchObject({ eligible: false });
    expect(afterStart.tasks.find((item) => item.task_id === "TASK-B")?.reasons.join(" ")).toContain("active-conflicts=TASK-A");
  });

  it("requires every durable pending operation to be exact-retried before ARCHIVED", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    advanceDevActiveToArchived(fixture, book, () => {
      const evidenceId = `archive-pending-${randomUUID()}`;
      const unsignedPrepared = {
        schema_version: 1,
        goal_id: "demo",
        task_id: "TASK-A",
        evidence_id: evidenceId,
        ingress_sha256: sha256("archive pending ingress"),
      };
      const preparedFile = path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "evidence-ingress",
        "TASK-A",
        `${evidenceId}.json`,
      );
      mkdirSync(path.dirname(preparedFile), { recursive: true });
      writeFileSync(preparedFile, `${JSON.stringify({
        ...unsignedPrepared,
        prepared_sha256: sha256(
          JSON.stringify(canonicalize(unsignedPrepared)),
        ),
      }, null, 2)}\n`);
      const archiveEvidence = seedEvidence(
        fixture,
        "MERGE_BOUNDARY",
        "FOREMAN",
      );
      const archive = buildEvent(
        fixture,
        "ARCHIVED",
        "FOREMAN",
        book.FOREMAN + 1,
        { payload: { evidence_id: archiveEvidence } },
      );
      expectControlError(
        submitEvent(fixture, archive),
        "TASK_OPERATION_PENDING",
      );
      unlinkSync(preparedFile);
    });
    expect(taskStatus(fixture).phase).toBe("ARCHIVED");
  });

  it("leaves the archived control tree byte-identical when preflight is archived between checks and commit", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    const launchFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      "launch-dev-1.json",
    );
    let archivedSnapshot: Array<[string, string]> = [];

    withDirectControl(fixture, () => {
      expectDirectControlError(() => runPreflight(fixture.root, {
        goalId: "demo",
        taskId: "TASK-A",
        launchFile,
        stage: "DEV",
        evidenceId: `preflight-archive-race-${randomUUID()}`,
        actorCapabilityFile: fixture.capabilities["TASK-A"].DEV as string,
      }, {
        beforeEvidenceCommit: () => {
          advanceDevActiveToArchived(fixture, book);
          archivedSnapshot = controlTreeSnapshot(fixture.controlDir);
        },
      }), "TASK_TERMINAL");
    });

    expect(archivedSnapshot.length).toBeGreaterThan(0);
    expect(controlTreeSnapshot(fixture.controlDir)).toEqual(archivedSnapshot);
  });

  it("leaves the archived control tree byte-identical when resource incident commit loses the archive race", () => {
    const manifest = JSON.parse(readFileSync(fixture.manifest, "utf8"));
    manifest.tasks[0].resource_requirements = [
      { kind: "TEST_DATA", id: "archive-race", access: "SHARED_READ" },
    ];
    writeFileSync(fixture.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
    git(fixture.root, "add", fixture.manifest);
    git(fixture.root, "commit", "-qm", "declare archive race resource");
    fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");

    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      payload: p1Payload(),
    });
    const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({ approval_ref: "user://issue-4242/approved" }),
    });
    apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      fullHead: fixture.fullHead,
      payload: p1Payload({
        approval_event_id: String(approval.event.event_id),
      }),
    });
    registerRole(fixture, "DEV");
    const acquired = runResourceCli([
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--resource", "test-data:archive-race",
      "--access", "SHARED_READ",
      "--ttl-ms", "60000",
      "--event-id", `resource-acquire-${randomUUID()}`,
      "--actor-capability-file", fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(acquired.code).toBe(0);
    const lease = json(acquired) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const launchFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      "launch-dev-1.json",
    );
    const launch = JSON.parse(readFileSync(launchFile, "utf8"));
    launch.resource_leases = [lease.lease_id];
    writeFileSync(launchFile, `${JSON.stringify(launch, null, 2)}\n`);
    apply(fixture, book, "LAUNCH_DEV", "CAPTAIN", {
      payload: { launch_id: "launch-dev-1" },
    });
    let archivedSnapshot: Array<[string, string]> = [];

    withDirectControl(fixture, () => {
      expectDirectControlError(() => verifyLease(fixture.root, {
        leaseId: lease.lease_id,
        ownerCapabilityFile: fixture.capabilities["TASK-A"].CAPTAIN as string,
        actorCapabilityFile: fixture.capabilities["TASK-A"].DEV as string,
        eventId: `resource-verify-archive-race-${randomUUID()}`,
      }, {
        beforeIncidentCommit: () => {
          const activeLeases: Array<{
            lease_id: string;
            owner_capability_file: string;
            role: Role;
          }> = [{ ...lease, role: "DEV" }];
          apply(fixture, book, "DEV_READY", "DEV", {
            fullHead: fixture.fullHead,
            payload: {
              pr: "https://github.com/example-org/example-repo/pull/999",
              evidence: devEvidence(fixture),
            },
          });

          const registerWorkerWithLease = (
            role: "REVIEW" | "RECEIPT",
          ): void => {
            registerRole(fixture, role);
            const acquiredWorker = runResourceCli([
              "acquire",
              "--goal", "demo",
              "--task", "TASK-A",
              "--role", role,
              "--thread", THREADS[role],
              "--resource", "test-data:archive-race",
              "--access", "SHARED_READ",
              "--ttl-ms", "60000",
              "--event-id", `resource-acquire-${randomUUID()}`,
              "--actor-capability-file",
              fixture.capabilities["TASK-A"][role] as string,
              "--json",
            ], fixture.root, fixture.controlDir);
            expect(acquiredWorker.code).toBe(0);
            const workerLease = json(acquiredWorker) as {
              lease_id: string;
              owner_capability_file: string;
            };
            activeLeases.push({ ...workerLease, role });
            const workerLaunchFile = path.join(
              fixture.controlDir,
              "goals",
              "demo",
              "launches",
              "TASK-A",
              `launch-${role.toLowerCase()}-1.json`,
            );
            const workerLaunch = JSON.parse(
              readFileSync(workerLaunchFile, "utf8"),
            );
            workerLaunch.resource_leases = [workerLease.lease_id];
            writeFileSync(
              workerLaunchFile,
              `${JSON.stringify(workerLaunch, null, 2)}\n`,
            );
          };

          registerWorkerWithLease("REVIEW");
          apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", {
            payload: { launch_id: "launch-review-1" },
          });
          apply(fixture, book, "REVIEW_PASS", "REVIEW", {
            payload: {
              evidence: seedEvidence(fixture, "REVIEW", "REVIEW"),
            },
          });
          registerWorkerWithLease("RECEIPT");
          apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", {
            payload: { launch_id: "launch-receipt-1" },
          });
          apply(fixture, book, "RECEIPT_PASS", "RECEIPT", {
            payload: {
              evidence: seedEvidence(fixture, "RECEIPT", "RECEIPT"),
            },
          });
          apply(fixture, book, "READY_FOR_MERGE", "CAPTAIN");
          apply(fixture, book, "MERGED", "FOREMAN", {
            payload: {
              expected_main_head: fixture.baseHead,
              main_merge_sha: fixture.fullHead,
            },
          });
          for (const active of activeLeases) {
            const released = runResourceCli([
              "release",
              "--lease", active.lease_id,
              "--owner-capability-file", active.owner_capability_file,
              "--actor-capability-file",
              fixture.capabilities["TASK-A"][active.role] as string,
              "--expected-revision", "1",
              "--json",
            ], fixture.root, fixture.controlDir);
            if (released.code !== 0) {
              throw new Error(
                `expected ${active.role} lease release to succeed: ${released.stderr || released.stdout}`,
              );
            }
            expect(released.code).toBe(0);
          }
          const archiveEvidence = seedEvidence(
            fixture,
            "MERGE_BOUNDARY",
            "FOREMAN",
          );
          apply(fixture, book, "ARCHIVED", "FOREMAN", {
            payload: { evidence_id: archiveEvidence },
          });
          expect(taskStatus(fixture).phase).toBe("ARCHIVED");
          archivedSnapshot = controlTreeSnapshot(fixture.controlDir);
        },
      }), "TASK_TERMINAL");
    });

    expect(archivedSnapshot.length).toBeGreaterThan(0);
    expect(controlTreeSnapshot(fixture.controlDir)).toEqual(archivedSnapshot);
  });

  it("leaves the archived control tree byte-identical when a blocked gate runner resumes after archive", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    let archivedSnapshot: Array<[string, string]> = [];
    let runnerCalled = 0;

    withDirectControl(fixture, () => {
      expectDirectControlError(() => runFastEvidence(fixture.root, {
        goalId: "demo",
        taskId: "TASK-A",
        evidenceId: `fast-archive-race-${randomUUID()}`,
        actorCapabilityFile: fixture.capabilities["TASK-A"].DEV as string,
      }, {
        resolveExecutable: () => ({
          executable: process.execPath,
          path_dir: path.dirname(process.execPath),
        }),
        runner: () => {
          runnerCalled += 1;
          advanceDevActiveToArchived(fixture, book);
          archivedSnapshot = controlTreeSnapshot(fixture.controlDir);
          return {
            status: 0,
            signal: null,
            stdout: "PASS\n",
            stderr: "",
          };
        },
      }), "TASK_TERMINAL");
    });

    expect(runnerCalled).toBe(1);
    expect(archivedSnapshot.length).toBeGreaterThan(0);
    expect(controlTreeSnapshot(fixture.controlDir)).toEqual(archivedSnapshot);
  });

  it("runs the complete P1 → DEV → REVIEW → RECEIPT → merge path and derives next + ledger", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    registerRole(fixture, "REVIEW");
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", { payload: { launch_id: "launch-review-1" } });
    apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW") },
    });
    registerRole(fixture, "RECEIPT");
    apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", { payload: { launch_id: "launch-receipt-1" } });
    apply(fixture, book, "RECEIPT_PASS", "RECEIPT", {
      payload: { evidence: seedEvidence(fixture, "RECEIPT", "RECEIPT") },
    });
    apply(fixture, book, "READY_FOR_MERGE", "CAPTAIN");
    expect(taskStatus(fixture).phase).toBe("ACCEPTED_PENDING_MERGE");
    apply(fixture, book, "MERGED", "FOREMAN", {
      payload: { expected_main_head: fixture.baseHead, main_merge_sha: fixture.fullHead },
    });
    const archiveWithoutEvidence = buildEvent(
      fixture,
      "ARCHIVED",
      "FOREMAN",
      book.FOREMAN + 1,
    );
    expectControlError(submitEvent(fixture, archiveWithoutEvidence), "INVALID_EVENT");

    const archiveEvidence = seedEvidence(fixture, "MERGE_BOUNDARY", "FOREMAN");
    const archiveBlocker = path.join(fixture.root, "archive-blocker.txt");
    writeFileSync(archiveBlocker, "uncommitted archive state\n");
    const archiveWithDirtyWorktree = buildEvent(
      fixture,
      "ARCHIVED",
      "FOREMAN",
      book.FOREMAN + 1,
      { payload: { evidence_id: archiveEvidence } },
    );
    expectControlError(
      submitEvent(fixture, archiveWithDirtyWorktree),
      "ARCHIVE_WORKTREE_DIRTY",
    );
    unlinkSync(archiveBlocker);

    apply(fixture, book, "ARCHIVED", "FOREMAN", {
      payload: { evidence_id: archiveEvidence },
    });

    expect(taskStatus(fixture)).toMatchObject({ phase: "ARCHIVED", full_head: fixture.fullHead });
    const archivedState = taskStatus(fixture);
    const archivedSource = path.join(fixture.root, "archived-evidence-source.json");
    const archivedSourceBody = "{\"status\":\"PASS\"}\n";
    writeFileSync(archivedSource, archivedSourceBody);
    const archivedEvidenceInput = path.join(fixture.root, "archived-evidence-input.json");
    writeFileSync(archivedEvidenceInput, `${JSON.stringify({
      schema_version: 1,
      evidence_id: `archived-evidence-${randomUUID()}`,
      goal_id: "demo",
      task_id: "TASK-A",
      kind: "CONTROL",
      status: "PASS",
      producer: {
        role: "FOREMAN",
        thread_id: THREADS.FOREMAN,
        host_id: "local",
      },
      state_revision: archivedState.state_revision,
      packet: {
        revision: archivedState.packet.revision,
        sha256: archivedState.packet.sha256,
      },
      packet_sha256: archivedState.packet.sha256,
      base_head: archivedState.base_head,
      full_head: archivedState.full_head,
      created_at: "2026-07-24T00:00:00.000Z",
      uri: pathToFileURL(archivedSource).href,
      source_sha256: sha256(archivedSourceBody),
    }, null, 2)}\n`);
    const controlBeforeArchivedEvidence = controlTreeSnapshot(fixture.controlDir);
    const archivedEvidenceAttempt = runCli([
      "evidence",
      "--goal", "demo",
      "--file", archivedEvidenceInput,
      "--actor-capability-file", fixture.capabilities["TASK-A"].FOREMAN as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(archivedEvidenceAttempt, "TASK_TERMINAL");
    expect(controlTreeSnapshot(fixture.controlDir)).toEqual(controlBeforeArchivedEvidence);
    unlinkSync(archivedEvidenceInput);
    unlinkSync(archivedSource);

    const controlTreeBeforeRejectedAcquire = controlTreeSnapshot(fixture.controlDir);
    const postArchiveAcquire = runResourceCli([
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "FOREMAN",
      "--thread", THREADS.FOREMAN,
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", `resource-acquire-${randomUUID()}`,
      "--actor-capability-file", fixture.capabilities["TASK-A"].FOREMAN as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(postArchiveAcquire, "TASK_TERMINAL");
    expect(controlTreeSnapshot(fixture.controlDir)).toEqual(
      controlTreeBeforeRejectedAcquire
    );

    const durableFinalitySnapshot = controlTreeSnapshot(fixture.controlDir).filter(([relative]) => (
      relative.includes("/events/")
        || relative.includes("/capabilities/")
        || relative.startsWith("resources/")
    ));
    const reviveCaptain = runCli([
      "register-role",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", "captain-after-archive",
      "--host", "local",
      "--attempt", "2",
      "--authorizer-capability-file", fixture.capabilities["TASK-A"].FOREMAN as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(reviveCaptain, "TASK_TERMINAL");
    expect(controlTreeSnapshot(fixture.controlDir).filter(([relative]) => (
      relative.includes("/events/")
        || relative.includes("/capabilities/")
        || relative.startsWith("resources/")
    ))).toEqual(durableFinalitySnapshot);

    const next = runCli(["next", "--goal", "demo", "--json"], fixture.root, fixture.controlDir);
    expect(next.code).toBe(0);
    expect(next.stdout).toContain("TASK-B");
    expect(next.stdout).toContain("START_P1");

    const ledgerPath = path.join(fixture.controlDir, "goals", "demo", "ledger.md");
    if (existsSync(ledgerPath)) unlinkSync(ledgerPath);
    const rebuild = runCli(["rebuild-ledger", "--goal", "demo", "--json"], fixture.root, fixture.controlDir);
    expect(rebuild.code).toBe(0);
    expect(existsSync(ledgerPath)).toBe(true);
    const ledger = readFileSync(ledgerPath, "utf8");
    expect(ledger).toContain("TASK-A");
    expect(ledger).toContain("ARCHIVED");
    expect(ledger).toContain("TASK-B");

    const control = runCli([
      "control", "--goal", "demo", "--expected-epoch", "0", "--reason", "later Goal instruction",
      "--instruction-ref", "user://issue-4242/later", "--thread", THREADS.FOREMAN,
      "--actor-capability-file", fixture.capabilities["TASK-A"].FOREMAN as string,
      "--event-id", `control-later-${randomUUID()}`, "--json",
    ], fixture.root, fixture.controlDir);
    expect(control.code).toBe(0);
    expect(taskStatus(fixture)).toMatchObject({ phase: "ARCHIVED", reconcile_required: null });
  });

  it("keeps task event IDs disjoint from the Goal control-event namespace", () => {
    initAndRegister(fixture);
    const eventId = `control-namespace-${randomUUID()}`;
    const advanced = runCli([
      "control",
      "--goal", "demo",
      "--expected-epoch", "0",
      "--reason", "exercise the Goal-wide event namespace",
      "--instruction-ref", "user://issue-4242/event-namespace",
      "--thread", THREADS.FOREMAN,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].FOREMAN as string,
      "--event-id", eventId,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(advanced.code).toBe(0);

    const collidingHeartbeat = buildEvent(
      fixture,
      "HEARTBEAT",
      "FOREMAN",
      1,
      {
        eventId,
        payload: { lease_ms: 3600000, status: "active" },
      },
    );
    expectControlError(
      submitEvent(fixture, collidingHeartbeat),
      "EVENT_ID_CONFLICT",
    );
  });

  it("reopens a merge candidate through FOREMAN and invalidates downstream evidence", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    registerRole(fixture, "REVIEW");
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", { payload: { launch_id: "launch-review-1" } });
    apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW") },
    });
    registerRole(fixture, "RECEIPT");
    apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", { payload: { launch_id: "launch-receipt-1" } });
    apply(fixture, book, "RECEIPT_PASS", "RECEIPT", {
      payload: { evidence: seedEvidence(fixture, "RECEIPT", "RECEIPT") },
    });
    apply(fixture, book, "READY_FOR_MERGE", "CAPTAIN");
    apply(fixture, book, "TASK_REOPEN", "FOREMAN", {
      payload: {
        reason: "main advanced; candidate must rebase and regenerate evidence",
        evidence_id: seedEvidence(fixture, "MERGE_BOUNDARY", "FOREMAN", "FAIL"),
      },
    });

    expect(taskStatus(fixture)).toMatchObject({ phase: "DEV_ACTIVE" });
    const state = json(runCli(["status", "--goal", "demo", "--json"], fixture.root, fixture.controlDir)) as {
      tasks: Record<string, { evidence: Record<string, unknown> }>;
    };
    expect(state.tasks["TASK-A"].evidence).toEqual({});
  });

  it("invalidates an accepted candidate and returns to P1 after a new user control epoch", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    registerRole(fixture, "REVIEW");
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", { payload: { launch_id: "launch-review-1" } });
    apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW") },
    });
    registerRole(fixture, "RECEIPT");
    apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", { payload: { launch_id: "launch-receipt-1" } });
    apply(fixture, book, "RECEIPT_PASS", "RECEIPT", {
      payload: { evidence: seedEvidence(fixture, "RECEIPT", "RECEIPT") },
    });
    apply(fixture, book, "READY_FOR_MERGE", "CAPTAIN");

    const controlEventId = `control-${randomUUID()}`;
    const advanced = runCli([
      "control", "--goal", "demo", "--expected-epoch", "0",
      "--reason", "user changed the accepted contract",
      "--instruction-ref", "user://issue-4242/change-1", "--thread", THREADS.FOREMAN,
      "--actor-capability-file", fixture.capabilities["TASK-A"].FOREMAN as string,
      "--event-id", controlEventId, "--json",
    ], fixture.root, fixture.controlDir);
    expect(advanced.code).toBe(0);
    apply(fixture, book, "CONTROL_RECONCILED", "FOREMAN", {
      payload: { control_event_id: controlEventId, instruction_ref: "user://issue-4242/change-1" },
    });
    expect(taskStatus(fixture)).toMatchObject({
      phase: "P1_ACTIVE",
      task_cycle: 2,
      p1: {},
      evidence: {},
      pr: null,
      sessions: {
        CAPTAIN: { status: "terminal", terminal_reason: "CONTROL_EPOCH_CHANGED" },
      },
    });

    const staleMerge = buildEvent(fixture, "MERGED", "FOREMAN", book.FOREMAN + 1, {
      payload: { expected_main_head: fixture.baseHead, main_merge_sha: fixture.fullHead },
    });
    expectControlError(submitEvent(fixture, staleMerge), "ILLEGAL_TRANSITION");
  });

  it("exact-retries a historical control command after FOREMAN recovery and frozen-input loss", () => {
    initAndRegister(fixture);
    const oldForemanCapability = fixture.capabilities["TASK-A"].FOREMAN as string;
    const eventId = `control-response-loss-${randomUUID()}`;
    const command = [
      "control", "--goal", "demo", "--expected-epoch", "0",
      "--reason", "replace a lost response without reapplying control",
      "--instruction-ref", "user://issue-4242/control-response-loss",
      "--thread", THREADS.FOREMAN,
      "--actor-capability-file", oldForemanCapability,
      "--event-id", eventId,
      "--json",
    ];
    const first = runCli(command, fixture.root, fixture.controlDir);
    expect(first.code).toBe(0);

    expireRegisteredRoles(fixture);
    const beforeRecovery = taskStatus(fixture);
    const recovered = recoverExpiredForeman(fixture, {
      snapshot: beforeRecovery,
      eventId: `recover-after-control-${randomUUID()}`,
    });
    expect(recovered.code).toBe(0);
    unlinkSync(path.join(fixture.root, "docs", "protocol", "shared.md"));

    const repeated = runCli(command, fixture.root, fixture.controlDir);
    expect(repeated.code).toBe(0);
    expect(json(repeated)).toMatchObject({
      control_epoch: 1,
      current_control_epoch: 1,
      event_id: eventId,
      idempotent: true,
      state: {
        tasks: {
          "TASK-A": {
            sessions: {
              FOREMAN: {
                thread_id: "foreman-a-2",
                attempt: 2,
              },
            },
          },
        },
      },
    });
  });

  it("forces packet changes through an immutable r+1 boundary and restarts P1 with fresh attempts", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: { role: "DEV", reason: "worker vanished before packet revision", attempts: 1 },
    });
    const packetPath = "docs/planning/goals/demo/packets/TASK-A-r2.md";
    const packetBody = "# TASK-A r2\n\nContract changed after implementation started.\n";
    writeFileSync(path.join(fixture.root, packetPath), packetBody);

    const uncommitted = buildEvent(fixture, "PACKET_UPDATED", "FOREMAN", book.FOREMAN + 1, {
      fullHead: fixture.fullHead,
      payload: {
        revision: 2,
        path: packetPath,
        sha256: sha256(packetBody),
        change_kind: "CONTRACT",
      },
    });
    expectControlError(submitEvent(fixture, uncommitted), "DIRTY_WORKTREE");

    git(fixture.root, "add", packetPath);
    git(fixture.root, "commit", "-qm", "revise task packet");
    fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");

    const invalid = buildEvent(fixture, "PACKET_UPDATED", "FOREMAN", book.FOREMAN + 1, {
      fullHead: fixture.fullHead,
      payload: {
        revision: 2,
        path: packetPath,
        sha256: `sha256:${"0".repeat(64)}`,
        change_kind: "CONTRACT",
      },
    });
    expectControlError(submitEvent(fixture, invalid), "PACKET_HASH_MISMATCH");

    apply(fixture, book, "PACKET_UPDATED", "FOREMAN", {
      fullHead: fixture.fullHead,
      payload: {
        revision: 2,
        path: packetPath,
        sha256: sha256(packetBody),
        change_kind: "CONTRACT",
      },
    });
    expect(taskStatus(fixture)).toMatchObject({
      phase: "P1_ACTIVE",
      full_head: fixture.fullHead,
      packet: { revision: 2, sha256: sha256(packetBody) },
      task_cycle: 2,
      p1: {},
      evidence: {},
      pr: null,
      recovery: null,
      sessions: {
        CAPTAIN: { attempt: 1, status: "terminal", terminal_reason: "PACKET_CHANGED" },
        DEV: { attempt: 1, status: "terminal", terminal_reason: "PACKET_CHANGED" },
      },
    });

    registerRole(fixture, "CAPTAIN", { thread: "captain-a-2", attempt: 2 });
    book.CAPTAIN = 0;
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      threadId: "captain-a-2",
      payload: p1Payload(),
    });
    const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({ approval_ref: "user://issue-4242/reapproved-r2" }),
    });
    apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      threadId: "captain-a-2",
      fullHead: fixture.fullHead,
      payload: p1Payload({ approval_event_id: approval.event.event_id }),
    });

    const staleAttempt = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-A", "--role", "DEV",
      "--thread", "dev-stale", "--host", "local", "--attempt", "1",
      "--launch-id", "launch-dev-stale", "--authorizer-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string, "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(staleAttempt, "STALE_ROLE_ATTEMPT");

    registerRole(fixture, "DEV", { thread: "dev-a-2", attempt: 2 });
    expect(taskStatus(fixture).sessions).toMatchObject({
      DEV: { thread_id: "dev-a-2", attempt: 2, status: "active" },
    });
  });

  it("lets an expired exact terminal historical actor release its lease after a fresh attempt takes over", () => {
    const manifest = JSON.parse(readFileSync(fixture.manifest, "utf8"));
    manifest.tasks[0].resource_requirements = [
      { kind: "PORT", id: "8123", access: "EXCLUSIVE" },
    ];
    writeFileSync(fixture.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
    git(fixture.root, "add", fixture.manifest);
    git(fixture.root, "commit", "-qm", "declare terminal cleanup resource");
    fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");

    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      payload: p1Payload(),
    });
    const initialApproval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({ approval_ref: "user://issue-4242/approved" }),
    });
    apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      fullHead: fixture.fullHead,
      payload: p1Payload({
        approval_event_id: String(initialApproval.event.event_id),
      }),
    });
    registerRole(fixture, "DEV");
    const oldDevCapability = fixture.capabilities["TASK-A"].DEV as string;
    const acquireEventId = `resource-acquire-${randomUUID()}`;
    const acquireArgs = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", acquireEventId,
      "--actor-capability-file", oldDevCapability,
      "--json",
    ];
    const acquired = runResourceCli(
      acquireArgs,
      fixture.root,
      fixture.controlDir,
    );
    expect(acquired.code).toBe(0);
    const oldLease = json(acquired) as {
      lease_id: string;
      owner_capability_file: string;
    };
    const launchFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      "launch-dev-1.json",
    );
    const launch = JSON.parse(readFileSync(launchFile, "utf8"));
    launch.resource_leases = [oldLease.lease_id];
    writeFileSync(launchFile, `${JSON.stringify(launch, null, 2)}\n`);
    apply(fixture, book, "LAUNCH_DEV", "CAPTAIN", {
      payload: { launch_id: "launch-dev-1" },
    });

    const controlEventId = `control-${randomUUID()}`;
    const advanced = runCli([
      "control", "--goal", "demo", "--expected-epoch", "0",
      "--reason", "replace the execution identity",
      "--instruction-ref", "user://issue-4242/terminal-cleanup",
      "--thread", THREADS.FOREMAN,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].FOREMAN as string,
      "--event-id", controlEventId,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(advanced.code).toBe(0);
    apply(fixture, book, "CONTROL_RECONCILED", "FOREMAN", {
      payload: {
        control_event_id: controlEventId,
        instruction_ref: "user://issue-4242/terminal-cleanup",
      },
    });
    registerRole(fixture, "CAPTAIN", {
      thread: "captain-a-2",
      attempt: 2,
    });
    book.CAPTAIN = 0;
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      threadId: "captain-a-2",
      payload: p1Payload(),
    });
    const reapproval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({
        approval_ref: "user://issue-4242/terminal-cleanup-reapproved",
      }),
    });
    apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      threadId: "captain-a-2",
      fullHead: fixture.fullHead,
      payload: p1Payload({
        approval_event_id: String(reapproval.event.event_id),
      }),
    });
    registerRole(fixture, "DEV", {
      thread: "dev-a-2",
      attempt: 2,
    });

    const historicalDev = taskStatus(fixture).session_history?.DEV?.find(
      (session) => session.thread_id === THREADS.DEV,
    );
    expect(historicalDev).toMatchObject({
      thread_id: THREADS.DEV,
      attempt: 1,
      status: "terminal",
    });
    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(historicalDev?.lease_until as string) + 1,
    ).toISOString();
    const historicalAcquireRetry = runResourceCli(
      acquireArgs,
      fixture.root,
      fixture.controlDir,
    );
    expect(historicalAcquireRetry.code).toBe(0);
    expect(json(historicalAcquireRetry)).toMatchObject({
      lease_id: oldLease.lease_id,
      status: "EXPIRED",
      idempotent: true,
    });
    for (const command of ["verify", "renew"]) {
      const useAttempt = runResourceCli([
        command,
        "--lease", oldLease.lease_id,
        "--owner-capability-file", oldLease.owner_capability_file,
        "--actor-capability-file", oldDevCapability,
        ...(command === "renew"
          ? ["--expected-revision", "1", "--ttl-ms", "60000"]
          : []),
        "--json",
      ], fixture.root, fixture.controlDir);
      expectControlError(useAttempt, "CAPABILITY_INVALID");
    }
    const releaseEventId = `resource-release-${randomUUID()}`;
    const releaseArgs = [
      "release",
      "--lease", oldLease.lease_id,
      "--owner-capability-file", oldLease.owner_capability_file,
      "--actor-capability-file", oldDevCapability,
      "--expected-revision", "1",
      "--event-id", releaseEventId,
      "--json",
    ];
    const released = runResourceCli(
      releaseArgs,
      fixture.root,
      fixture.controlDir,
    );
    expect(released.code).toBe(0);
    expect(json(released)).toMatchObject({
      lease_id: oldLease.lease_id,
      status: "RELEASED",
      revision: 2,
    });
    expect(existsSync(oldLease.owner_capability_file)).toBe(false);
    const releaseRetry = runResourceCli(
      releaseArgs,
      fixture.root,
      fixture.controlDir,
    );
    expect(releaseRetry.code).toBe(0);
    expect(json(releaseRetry)).toMatchObject({
      lease_id: oldLease.lease_id,
      status: "RELEASED",
      revision: 2,
      operation_event_id: releaseEventId,
      idempotent: true,
    });
    const conflictingReleaseArgs = [...releaseArgs];
    conflictingReleaseArgs[
      conflictingReleaseArgs.indexOf("--expected-revision") + 1
    ] = "2";
    expectControlError(
      runResourceCli(
        conflictingReleaseArgs,
        fixture.root,
        fixture.controlDir,
      ),
      "RESOURCE_EVENT_ID_CONFLICT",
    );
  });

  describe.each(["REVIEW", "RECEIPT"] as const)(
    "%s stopped-preview runtime recovery",
    (role) => {
      let runtimeSetup: {
        book: SequenceBook;
        registration: Record<string, unknown>;
      };

      beforeEach(() => {
        prepareRuntimePreflightRepository(fixture);
        const book = sequences();
        const registration = withInProcessGoalCliFixtureSetup(() => {
          initAndRegister(fixture);
          return enterRuntimeWorkerPhase(fixture, book, role);
        });
        runtimeSetup = { book, registration };
      });

      it("rotates, passes fresh preflight, and resolves the exact hold", async () => {
        const { book, registration } = runtimeSetup;
        const predecessorPort = role === "REVIEW" ? 48737 : 49737;
        const successorPort = predecessorPort + 100;
        const predecessor = spawn(
          process.execPath,
          ["-e", "setInterval(() => {}, 1000)"],
          { stdio: "ignore" },
        );
        let successor: ReturnType<typeof spawn> | null = null;
        try {
          if (!predecessor.pid) throw new Error("missing predecessor PID");
          const predecessorLaunch = withInProcessGoalCliFixtureSetup(
            () => rolePreviewLaunch(
              fixture,
              role,
              registration,
              {
                pid: predecessor.pid as number,
                startedAt: processStartedAt(predecessor.pid as number),
                previewPort: predecessorPort,
              },
            ),
          );
          const predecessorInput = path.join(
            fixture.controlDir,
            `predecessor-${role.toLowerCase()}.json`,
          );
          writeFileSync(
            predecessorInput,
            `${JSON.stringify(predecessorLaunch, null, 2)}\n`,
          );
          const initialPreflight = withInProcessGoalCliFixtureSetup(
            () => runCli([
              "preflight",
              "--goal", "demo",
              "--task", "TASK-A",
              "--launch", predecessorInput,
              "--stage", role,
              "--evidence-id",
              `preflight-${role.toLowerCase()}-runtime-predecessor`,
              "--actor-capability-file",
              fixture.capabilities["TASK-A"][role] as string,
              "--json",
            ], fixture.root, fixture.controlDir),
          );
          if (initialPreflight.code !== 0) {
            throw new Error(
              initialPreflight.stderr || initialPreflight.stdout,
            );
          }
          withInProcessGoalCliFixtureSetup(() => {
            apply(fixture, book, `LAUNCH_${role}`, "CAPTAIN", {
              payload: {
                launch_id: `launch-${role.toLowerCase()}-1`,
              },
            });
          });

          await new Promise((resolve) => setTimeout(resolve, 1100));
          successor = spawn(
            process.execPath,
            ["-e", "setInterval(() => {}, 1000)"],
            { stdio: "ignore" },
          );
          if (!successor.pid) throw new Error("missing successor PID");
          const candidateLaunch = JSON.parse(
            JSON.stringify(predecessorLaunch),
          ) as {
            execution: {
              task_nonce: string;
              target: {
                pid: number;
                started_at: string;
                preview_url: string;
              };
            };
            created_at: string;
          };
          candidateLaunch.execution.target.pid = successor.pid;
          candidateLaunch.execution.target.started_at =
            processStartedAt(successor.pid);
          candidateLaunch.execution.target.preview_url =
            `http://127.0.0.1:${successorPort}`;
          candidateLaunch.created_at =
            candidateLaunch.execution.target.started_at;
          const candidateInput = path.join(
            fixture.controlDir,
            `candidate-${role.toLowerCase()}.json`,
          );
          writeFileSync(
            candidateInput,
            `${JSON.stringify(candidateLaunch, null, 2)}\n`,
          );
          const conflict = runCli([
            "preflight",
            "--goal", "demo",
            "--task", "TASK-A",
            "--launch", candidateInput,
            "--stage", role,
            "--evidence-id",
            `preflight-${role.toLowerCase()}-runtime-conflict`,
            "--actor-capability-file",
            fixture.capabilities["TASK-A"][role] as string,
            "--json",
          ], fixture.root, fixture.controlDir);
          expect(conflict.code).toBe(1);
          expect(`${conflict.stdout}\n${conflict.stderr}`)
            .toContain("LAUNCH_ID_CONFLICT");

          const held = withInProcessGoalCliFixtureSetup(
            () => taskStatus(fixture),
          ) as TaskStatus & {
            holds: Array<{ hold_id: string; kind: string }>;
            maintenance_actions: Array<{
              type: string;
              predecessor_incarnation?: number;
              predecessor_launch_id?: string;
              predecessor_launch_sha256?: string;
            }>;
          };
          const rotation = held.maintenance_actions.find(
            (action) => action.type === "REQUEST_RUNTIME_ROTATION",
          ) as {
            predecessor_incarnation?: number;
            predecessor_launch_id?: string;
            predecessor_launch_sha256?: string;
          } | undefined;
          expect(rotation).toMatchObject({
            predecessor_incarnation: 1,
            predecessor_launch_id: `launch-${role.toLowerCase()}-1`,
          });
          if (
            !rotation?.predecessor_launch_id
              || !rotation.predecessor_launch_sha256
          ) {
            throw new Error("missing projected runtime rotation");
          }
          const hold = held.holds.find(
            (candidate) => candidate.kind === "ENV_IDENTITY_INCIDENT",
          );
          if (!hold) throw new Error("missing runtime identity hold");

          await stopChild(predecessor);
          const successorLaunchId =
            `launch-${role.toLowerCase()}-runtime-2`;
          const rotated = runCli([
            "rotate-runtime",
            "--goal", "demo",
            "--task", "TASK-A",
            "--role", role,
            "--worker-thread", THREADS[role],
            "--predecessor-incarnation",
            String(rotation.predecessor_incarnation),
            "--predecessor-launch", rotation.predecessor_launch_id,
            "--expected-predecessor-launch-sha256",
            rotation.predecessor_launch_sha256,
            "--successor-launch", successorLaunchId,
            "--hold", hold.hold_id,
            "--expected-state-revision", String(held.state_revision),
            "--expected-control-epoch", String(held.control_epoch),
            "--reason", `replace stopped ${role} preview`,
            "--incident-ref",
            `incident://runtime-rotation/${role.toLowerCase()}`,
            "--captain-thread", THREADS.CAPTAIN,
            "--captain-capability-file",
            fixture.capabilities["TASK-A"].CAPTAIN as string,
            "--event-id",
            `runtime-rotated-${role.toLowerCase()}-1-to-2`,
            "--json",
          ], fixture.root, fixture.controlDir);
          if (rotated.code !== 0) {
            throw new Error(rotated.stderr || rotated.stdout);
          }
          expect(withInProcessGoalCliFixtureSetup(
            () => taskStatus(fixture),
          ).maintenance_actions).toEqual(
            expect.arrayContaining([
              expect.objectContaining({
                type: "REQUEST_RUNTIME_PREFLIGHT",
                role,
                successor_launch_id: successorLaunchId,
              }),
            ]),
          );

          const successorExecution = {
            ...(candidateLaunch.execution as Record<string, unknown>),
          };
          delete successorExecution.task_nonce;
          const successorTemplateInput = path.join(
            fixture.controlDir,
            `successor-${role.toLowerCase()}-input.json`,
          );
          writeFileSync(
            successorTemplateInput,
            `${JSON.stringify({
              execution: successorExecution,
              resource_leases: [],
            }, null, 2)}\n`,
          );
          const successorTemplate = withInProcessGoalCliFixtureSetup(
            () => runCli([
              "launch-template",
              "--goal", "demo",
              "--task", "TASK-A",
              "--role", role,
              "--thread", THREADS[role],
              "--actor-capability-file",
              fixture.capabilities["TASK-A"][role] as string,
              "--input-file", successorTemplateInput,
              "--json",
            ], fixture.root, fixture.controlDir),
          );
          if (successorTemplate.code !== 0) {
            throw new Error(
              successorTemplate.stderr || successorTemplate.stdout,
            );
          }
          expect(json(successorTemplate)).toMatchObject({
            launch_id: successorLaunchId,
            role,
            runtime_incarnation: {
              epoch: 2,
              rotation_event_id:
                `runtime-rotated-${role.toLowerCase()}-1-to-2`,
            },
          });
          const successorLaunchFile = path.join(
            fixture.controlDir,
            `successor-${role.toLowerCase()}-launch.json`,
          );
          writeFileSync(successorLaunchFile, successorTemplate.stdout);
          const successorPreflightId =
            `preflight-${role.toLowerCase()}-runtime-successor`;
          const successorPreflight = runCli([
            "preflight",
            "--goal", "demo",
            "--task", "TASK-A",
            "--launch", successorLaunchFile,
            "--stage", role,
            "--evidence-id", successorPreflightId,
            "--actor-capability-file",
            fixture.capabilities["TASK-A"][role] as string,
            "--json",
          ], fixture.root, fixture.controlDir);
          if (successorPreflight.code !== 0) {
            throw new Error(
              successorPreflight.stderr || successorPreflight.stdout,
            );
          }
          expect(json(successorPreflight)).toMatchObject({
            evidence_id: successorPreflightId,
            kind: "PREFLIGHT",
            status: "PASS",
            producer: {
              role,
              thread_id: THREADS[role],
            },
            launch_id: successorLaunchId,
            full_head: fixture.fullHead,
          });

          const resolutionEvidence = withInProcessGoalCliFixtureSetup(
            () => seedEvidence(
              fixture,
              "HOLD_RESOLUTION",
              "FOREMAN",
            ),
          );
          apply(fixture, book, "RESOLVE_HOLD", "FOREMAN", {
            payload: {
              hold_id: hold.hold_id,
              authority: `fresh ${role} runtime preflight passed`,
              resolution_evidence_id: resolutionEvidence,
              runtime_preflight_evidence_id: successorPreflightId,
              disposition: "FIXED",
            },
          });
          expect(withInProcessGoalCliFixtureSetup(
            () => taskStatus(fixture),
          )).toMatchObject({
            phase: `${role}_ACTIVE`,
            holds: [],
            sessions: {
              [role]: {
                thread_id: THREADS[role],
                launch_id: successorLaunchId,
                runtime_incarnation: 2,
              },
            },
          });
        } finally {
          await stopChild(predecessor);
          if (successor) await stopChild(successor);
        }
      }, 45_000);
    },
  );

  it("keeps only exact-owner renewal alive under the runtime-rotation hard hold", () => {
    const manifest = JSON.parse(readFileSync(fixture.manifest, "utf8"));
    manifest.tasks[0].resource_requirements = [
      { kind: "PORT", id: "8123", access: "EXCLUSIVE" },
      { kind: "TEST_DATA", id: "rotation-shared", access: "SHARED_READ" },
    ];
    writeFileSync(fixture.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
    git(fixture.root, "add", fixture.manifest);
    git(fixture.root, "commit", "-qm", "declare runtime rotation resource");
    fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");

    process.env.GOAL_CONTROL_NOW = "2026-07-22T00:00:00.000Z";
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      payload: p1Payload(),
    });
    const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({
        approval_ref: "user://issue-4242/runtime-rotation-approved",
      }),
    });
    apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      fullHead: fixture.fullHead,
      payload: p1Payload({
        approval_event_id: String(approval.event.event_id),
      }),
    });
    registerRole(fixture, "DEV");

    const acquiredArgs = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", `resource-acquire-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ];
    const acquiredResult = runResourceCli(
      acquiredArgs,
      fixture.root,
      fixture.controlDir,
    );
    expect(acquiredResult.code).toBe(0);
    const acquired = json(acquiredResult) as {
      lease_id: string;
      resource: string;
      revision: number;
      fencing_token: number;
      expires_at: string;
      owner: {
        goal_id: string;
        task_id: string;
        role: string;
        thread_id: string;
        host_id: string;
      };
      owner_capability_file: string;
    };
    expect(acquired).toMatchObject({
      resource: "preview-port:8123",
      revision: 1,
    });

    const supersededSharedArgs = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--host", "local",
      "--resource", "test-data:rotation-shared",
      "--access", "SHARED_READ",
      "--ttl-ms", "60000",
      "--event-id", `resource-acquire-shared-old-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ];
    const supersededSharedResult = runResourceCli(
      supersededSharedArgs,
      fixture.root,
      fixture.controlDir,
    );
    if (supersededSharedResult.code !== 0) {
      throw new Error(
        `old shared acquire failed: ${supersededSharedResult.stderr}`,
      );
    }
    const supersededShared = json(supersededSharedResult) as {
      lease_id: string;
      revision: number;
      fencing_token: number;
      owner_capability_file: string;
    };

    const currentSharedArgs = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--host", "local",
      "--resource", "test-data:rotation-shared",
      "--access", "SHARED_READ",
      "--ttl-ms", "600000",
      "--event-id", `resource-acquire-shared-new-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ];
    const currentSharedResult = runResourceCli(
      currentSharedArgs,
      fixture.root,
      fixture.controlDir,
    );
    if (currentSharedResult.code !== 0) {
      throw new Error(
        `new shared acquire failed: ${currentSharedResult.stderr}`,
      );
    }
    const currentShared = json(currentSharedResult) as {
      lease_id: string;
      revision: number;
      fencing_token: number;
      owner_capability_file: string;
    };
    expect(currentShared.fencing_token).toBe(
      supersededShared.fencing_token + 1,
    );

    const latestShortSharedArgs = [
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--host", "local",
      "--resource", "test-data:rotation-shared",
      "--access", "SHARED_READ",
      "--ttl-ms", "60000",
      "--event-id", `resource-acquire-shared-latest-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ];
    const latestShortSharedResult = runResourceCli(
      latestShortSharedArgs,
      fixture.root,
      fixture.controlDir,
    );
    if (latestShortSharedResult.code !== 0) {
      throw new Error(
        `latest shared acquire failed: ${latestShortSharedResult.stderr}`,
      );
    }
    const latestShortShared = json(latestShortSharedResult) as {
      lease_id: string;
      revision: number;
      fencing_token: number;
      owner_capability_file: string;
    };
    expect(latestShortShared.fencing_token).toBe(
      currentShared.fencing_token + 1,
    );

    const launchFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      "launch-dev-1.json",
    );
    const launch = JSON.parse(readFileSync(launchFile, "utf8"));
    launch.resource_leases = [acquired.lease_id, currentShared.lease_id];
    writeFileSync(launchFile, `${JSON.stringify(launch, null, 2)}\n`);
    apply(fixture, book, "LAUNCH_DEV", "CAPTAIN", {
      payload: { launch_id: "launch-dev-1" },
    });

    const runtimeHoldId = `runtime-identity-${randomUUID()}`;
    apply(fixture, book, "ADD_HOLD", "CAPTAIN", {
      payload: {
        hold_id: runtimeHoldId,
        kind: "ENV_IDENTITY_INCIDENT",
        reason: "retired preview must be replaced with a fresh incarnation",
        evidence_id: seedEvidence(
          fixture,
          "HOLD_ASSERTION",
          "CAPTAIN",
          "BLOCKED",
        ),
      },
    });

    process.env.GOAL_CONTROL_NOW = "2026-07-22T00:00:45.000Z";
    expect(
      (taskStatus(fixture).maintenance_actions || []).find(
        (action) => (
          action.type === "REQUEST_RESOURCE_RENEW"
            && action.lease_id === acquired.lease_id
        ),
      ),
    ).toMatchObject({
      lease_id: acquired.lease_id,
      expiry_state: "RENEWAL_WINDOW",
    });
    expect(
      (taskStatus(fixture).maintenance_actions || []).find(
        (action) => (
          action.type === "REQUEST_RESOURCE_RENEW"
            && action.lease_id === currentShared.lease_id
        ),
      ),
    ).toBeUndefined();
    expect(runResourceCli([
      "owner-capability",
      "--lease", acquired.lease_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir).code).toBe(0);
    expect(runResourceCli(
      acquiredArgs,
      fixture.root,
      fixture.controlDir,
    ).code).toBe(0);
    expectControlError(runResourceCli([
      "owner-capability",
      "--lease", currentShared.lease_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir), "RESOURCE_EXPIRY_RECOVERY_FENCED");
    expectControlError(
      runResourceCli(
        currentSharedArgs,
        fixture.root,
        fixture.controlDir,
      ),
      "RESOURCE_EXPIRY_RECOVERY_FENCED",
    );

    process.env.GOAL_CONTROL_NOW = "2026-07-22T00:01:15.000Z";
    const heldStatus = taskStatus(fixture);
    const renewal = (heldStatus.maintenance_actions || []).find(
      (action) => (
        action.type === "REQUEST_RESOURCE_RENEW"
          && action.lease_id === acquired.lease_id
      ),
    ) as {
      type: string;
      actor_role: string;
      requested_action: string;
      event_id: string;
      lease_id: string;
      resource: string;
      expected_revision: number;
      ttl_ms: number;
      expires_at: string;
      expiry_state: string;
      hold_id: string;
      dispatch: {
        coordinator_role: string;
        executor_binding: string;
        executor: {
          role: string;
          thread_id: string;
          host_id: string;
        };
        capability_mode: string;
      };
      owner: {
        role: string;
        thread_id: string;
        host_id: string;
      };
    } | undefined;
    expect(renewal).toMatchObject({
      type: "REQUEST_RESOURCE_RENEW",
      actor_role: "CAPTAIN",
      requested_action: "RENEW_RESOURCE",
      lease_id: acquired.lease_id,
      resource: "preview-port:8123",
      expected_revision: 1,
      expires_at: acquired.expires_at,
      expiry_state: "EXPIRED_PRESERVATION",
      hold_id: runtimeHoldId,
      dispatch: {
        coordinator_role: "CAPTAIN",
        executor_binding: "EXACT_RESOURCE_OWNER",
        executor: {
          role: "DEV",
          thread_id: THREADS.DEV,
          host_id: "local",
        },
        capability_mode: "EXACT_OWNER_DUAL_CAPABILITY",
      },
      owner: {
        role: "DEV",
        thread_id: THREADS.DEV,
        host_id: "local",
      },
    });
    if (!renewal) throw new Error("missing runtime-hold renewal request");

    const fencedRenewal = (heldStatus.maintenance_actions || []).find(
      (action) => (
        action.type === "REQUEST_RESOURCE_RENEW"
          && action.lease_id === supersededShared.lease_id
      ),
    ) as typeof renewal;
    expect(fencedRenewal).toBeUndefined();
    expect(
      (heldStatus.maintenance_actions || []).find(
        (action) => (
          action.type === "REQUEST_RESOURCE_RENEW"
            && action.lease_id === latestShortShared.lease_id
        ),
      ),
    ).toBeUndefined();
    expectControlError(runResourceCli([
      "renew",
      "--lease", supersededShared.lease_id,
      "--owner-capability-file", supersededShared.owner_capability_file,
      "--expected-revision", "1",
      "--ttl-ms", "60000",
      "--event-id", `resource-renew-fenced-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir), "RESOURCE_EXPIRY_RECOVERY_FENCED");

    const controlBeforeCapabilityRecovery = controlTreeSnapshot(
      fixture.controlDir,
    );
    expectControlError(runResourceCli([
      "owner-capability",
      "--lease", supersededShared.lease_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir), "RESOURCE_EXPIRY_RECOVERY_FENCED");
    expectControlError(runResourceCli([
      "owner-capability",
      "--lease", latestShortShared.lease_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir), "RESOURCE_EXPIRY_RECOVERY_FENCED");
    expect(controlTreeSnapshot(fixture.controlDir)).toEqual(
      controlBeforeCapabilityRecovery,
    );
    expectControlError(
      runResourceCli(
        supersededSharedArgs,
        fixture.root,
        fixture.controlDir,
      ),
      "RESOURCE_EXPIRY_RECOVERY_FENCED",
    );
    expectControlError(
      runResourceCli(
        latestShortSharedArgs,
        fixture.root,
        fixture.controlDir,
      ),
      "RESOURCE_EXPIRY_RECOVERY_FENCED",
    );
    expect(runResourceCli(
      acquiredArgs,
      fixture.root,
      fixture.controlDir,
    ).code).toBe(0);
    const controlBeforeExactOwnerRecovery = controlTreeSnapshot(
      fixture.controlDir,
    );
    for (const capability of [
      fixture.capabilities["TASK-A"].CAPTAIN,
      fixture.capabilities["TASK-A"].FOREMAN,
    ]) {
      expectControlError(runResourceCli([
        "owner-capability",
        "--lease", acquired.lease_id,
        "--actor-capability-file", capability as string,
        "--json",
      ], fixture.root, fixture.controlDir), "CAPABILITY_INVALID");
    }
    const recoveredOwner = runResourceCli([
      "owner-capability",
      "--lease", acquired.lease_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(recoveredOwner.code).toBe(0);
    expect(json(recoveredOwner)).toMatchObject({
      lease_id: acquired.lease_id,
      revision: acquired.revision,
      owner_capability_file: acquired.owner_capability_file,
    });
    expect(controlTreeSnapshot(fixture.controlDir)).toEqual(
      controlBeforeExactOwnerRecovery,
    );

    expectControlError(runResourceCli([
      "renew",
      "--lease", acquired.lease_id,
      "--owner-capability-file", acquired.owner_capability_file,
      "--expected-revision", String(renewal.expected_revision),
      "--ttl-ms", String(renewal.ttl_ms),
      "--event-id", renewal.event_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      "--json",
    ], fixture.root, fixture.controlDir), "CAPABILITY_INVALID");

    const renewedResult = runResourceCli([
      "renew",
      "--lease", acquired.lease_id,
      "--owner-capability-file",
      String(json(recoveredOwner).owner_capability_file),
      "--expected-revision", String(renewal.expected_revision),
      "--ttl-ms", String(renewal.ttl_ms),
      "--event-id", renewal.event_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(renewedResult.code).toBe(0);
    expect(json(renewedResult)).toMatchObject({
      lease_id: acquired.lease_id,
      status: "ACTIVE",
      revision: 2,
      fencing_token: acquired.fencing_token,
      expires_at: "2026-07-22T00:02:15.000Z",
      owner: acquired.owner,
    });

    const deniedAcquire = runResourceCli([
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--host", "local",
      "--resource", "preview-port:8123",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "60000",
      "--event-id", `resource-acquire-held-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(deniedAcquire, "TASK_HARD_HELD");

    const deniedRelease = runResourceCli([
      "release",
      "--lease", acquired.lease_id,
      "--owner-capability-file", acquired.owner_capability_file,
      "--expected-revision", "2",
      "--event-id", `resource-release-held-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(deniedRelease, "TASK_HARD_HELD");

    const deniedUse = runResourceCli([
      "verify",
      "--lease", acquired.lease_id,
      "--owner-capability-file", acquired.owner_capability_file,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(deniedUse, "TASK_HARD_HELD");

    process.env.GOAL_CONTROL_NOW = "2026-07-22T00:02:30.000Z";
    const nextRenewal = (taskStatus(fixture).maintenance_actions || []).find(
      (action) => (
        action.type === "REQUEST_RESOURCE_RENEW"
          && action.lease_id === acquired.lease_id
      ),
    ) as typeof renewal;
    expect(nextRenewal).toMatchObject({
      lease_id: acquired.lease_id,
      expected_revision: 2,
      expires_at: "2026-07-22T00:02:15.000Z",
      expiry_state: "EXPIRED_PRESERVATION",
      hold_id: runtimeHoldId,
      owner: renewal.owner,
    });
    if (!nextRenewal) throw new Error("missing second runtime-hold renewal request");

    apply(fixture, book, "RESOLVE_HOLD", "FOREMAN", {
      payload: {
        hold_id: runtimeHoldId,
        authority: "runtime-rotation-supervisor",
        resolution_evidence_id: seedEvidence(
          fixture,
          "HOLD_RESOLUTION",
          "FOREMAN",
        ),
        disposition: "FIXED",
      },
    });
    expectControlError(runResourceCli([
      "renew",
      "--lease", acquired.lease_id,
      "--owner-capability-file", acquired.owner_capability_file,
      "--expected-revision", String(nextRenewal.expected_revision),
      "--ttl-ms", String(nextRenewal.ttl_ms),
      "--event-id", nextRenewal.event_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir), "LEASE_EXPIRED");

    const securityHoldId = `security-${randomUUID()}`;
    apply(fixture, book, "ADD_HOLD", "CAPTAIN", {
      payload: {
        hold_id: securityHoldId,
        kind: "BLOCKED_SECURITY",
        reason: "a non-runtime hard hold must freeze every resource action",
        evidence_id: seedEvidence(
          fixture,
          "HOLD_ASSERTION",
          "CAPTAIN",
          "BLOCKED",
        ),
      },
    });

    expect(
      (taskStatus(fixture).maintenance_actions || [])
        .filter((action) => action.type === "REQUEST_RESOURCE_RENEW"),
    ).toEqual([]);
    expectControlError(runResourceCli([
      "renew",
      "--lease", acquired.lease_id,
      "--owner-capability-file", acquired.owner_capability_file,
      "--expected-revision", String(nextRenewal.expected_revision),
      "--ttl-ms", String(nextRenewal.ttl_ms),
      "--event-id", nextRenewal.event_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir), "TASK_HARD_HELD");
    expectControlError(
      runResourceCli(
        acquiredArgs,
        fixture.root,
        fixture.controlDir,
      ),
      "TASK_HARD_HELD",
    );

    apply(fixture, book, "RESOLVE_HOLD", "FOREMAN", {
      payload: {
        hold_id: securityHoldId,
        authority: "security-supervisor",
        resolution_evidence_id: seedEvidence(
          fixture,
          "HOLD_RESOLUTION",
          "FOREMAN",
        ),
        disposition: "FIXED",
      },
    });
    apply(fixture, book, "ADD_HOLD", "CAPTAIN", {
      payload: {
        hold_id: `runtime-expired-actor-${randomUUID()}`,
        kind: "ENV_IDENTITY_INCIDENT",
        reason: "capability disclosure must use one actor/resource clock",
        evidence_id: seedEvidence(
          fixture,
          "HOLD_ASSERTION",
          "CAPTAIN",
          "BLOCKED",
        ),
      },
    });
    const devLeaseUntil = taskStatus(fixture).sessions?.DEV?.lease_until;
    if (!devLeaseUntil) throw new Error("missing DEV lease_until");
    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(devLeaseUntil) + 1,
    ).toISOString();
    expect(
      (taskStatus(fixture).maintenance_actions || [])
        .filter((action) => action.type === "REQUEST_RESOURCE_RENEW"),
    ).toEqual([]);
    expectControlError(runResourceCli([
      "owner-capability",
      "--lease", acquired.lease_id,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir), "ACTOR_LEASE_EXPIRED");
    expectControlError(
      runResourceCli(
        acquiredArgs,
        fixture.root,
        fixture.controlDir,
      ),
      "ACTOR_LEASE_EXPIRED",
    );
  });

  it("rejects a committed packet update that rewrites away the audited task lineage", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: {
        role: "DEV",
        reason: "packet contract must change",
        fingerprint: "contract-change:divergent-packet",
        attempts: 1,
      },
    });
    const previousHead = fixture.fullHead;
    const packetPath = "docs/planning/goals/demo/packets/TASK-A-r2.md";
    const packetBody = "# TASK-A r2\n\nDivergent packet bytes.\n";
    writeFileSync(path.join(fixture.root, packetPath), packetBody);
    git(fixture.root, "add", packetPath);
    const tree = git(fixture.root, "write-tree");
    const sibling = git(
      fixture.root,
      "commit-tree",
      tree,
      "-p",
      fixture.baseHead,
      "-m",
      "rewrite packet outside audited lineage"
    );
    git(fixture.root, "reset", "--hard", sibling);
    fixture.fullHead = sibling;

    const update = buildEvent(
      fixture,
      "PACKET_UPDATED",
      "FOREMAN",
      book.FOREMAN + 1,
      {
        fullHead: sibling,
        payload: {
          revision: 2,
          path: packetPath,
          sha256: sha256(packetBody),
          change_kind: "CONTRACT",
        },
      }
    );
    expectControlError(
      submitEvent(fixture, update),
      "PACKET_HEAD_NOT_DESCENDANT"
    );
    expect(taskStatus(fixture)).toMatchObject({
      phase: "DEV_ACTIVE",
      full_head: previousHead,
      packet: { revision: 1 },
    });
  });

  it("requires a fresh REVIEW session after rework instead of reviving the terminal attempt", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    registerRole(fixture, "REVIEW");
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", { payload: { launch_id: "launch-review-1" } });
    apply(fixture, book, "REVIEW_REWORK", "REVIEW", {
      payload: { review_evidence: seedEvidence(fixture, "REVIEW", "REVIEW", "FAIL") },
    });
    expect((taskStatus(fixture).maintenance_actions || [])
      .filter((action) => action.type === "REQUEST_RESOURCE_RELEASE"))
      .toEqual([]);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });

    const staleLaunch = buildEvent(fixture, "LAUNCH_REVIEW", "CAPTAIN", book.CAPTAIN + 1, {
      payload: { launch_id: "launch-review-1" },
    });
    expectControlError(submitEvent(fixture, staleLaunch), "FRESH_SESSION_REQUIRED");

    const reusedIdentity = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-A", "--role", "REVIEW",
      "--thread", THREADS.REVIEW, "--host", "local", "--attempt", "2",
      "--launch-id", "launch-review-2", "--authorizer-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string, "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(reusedIdentity, "ROLE_IDENTITY_REUSE");

    registerRole(fixture, "REVIEW", { thread: "review-a-2", attempt: 2 });
    book.REVIEW = 0;
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", {
      payload: { launch_id: "launch-review-2" },
    });
    apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      threadId: "review-a-2",
      payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW", "PASS", fixture.fullHead, "review-a-2") },
    });
    expect(taskStatus(fixture)).toMatchObject({
      phase: "REVIEW_PASS",
      sessions: { REVIEW: { thread_id: "review-a-2", attempt: 2, status: "terminal" } },
    });
  });

  it("keeps role-scoped worker resources independent across DEV, REVIEW rework, and RECEIPT", () => {
    const manifest = JSON.parse(readFileSync(fixture.manifest, "utf8"));
    manifest.tasks[0].resource_requirements = [
      {
        kind: "PORT",
        id: "dev-preview",
        access: "EXCLUSIVE",
        roles: ["DEV"],
      },
      {
        kind: "PORT",
        id: "review-preview",
        access: "EXCLUSIVE",
        roles: ["REVIEW"],
      },
      {
        kind: "PORT",
        id: "receipt-preview",
        access: "EXCLUSIVE",
        roles: ["RECEIPT"],
      },
      {
        kind: "TEST_DATA",
        id: "role-shared",
        access: "SHARED_READ",
      },
    ];
    writeFileSync(fixture.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
    git(fixture.root, "add", fixture.manifest);
    git(fixture.root, "commit", "-qm", "declare role-scoped worker resources");
    fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");

    type WorkerLease = {
      lease_id: string;
      owner_capability_file: string;
      fencing_token: number;
      resource: string;
      revision: number;
      status: string;
    };
    const acquireWorker = (
      role: "DEV" | "REVIEW" | "RECEIPT",
      thread: string,
      resource: string,
      access: "EXCLUSIVE" | "SHARED_READ",
    ): WorkerLease => {
      const acquired = runResourceCli([
        "acquire",
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", role,
        "--thread", thread,
        "--host", "local",
        "--resource", resource,
        "--access", access,
        "--ttl-ms", "3600000",
        "--event-id", `resource-acquire-${randomUUID()}`,
        "--actor-capability-file",
        fixture.capabilities["TASK-A"][role] as string,
        "--json",
      ], fixture.root, fixture.controlDir);
      if (acquired.code !== 0) {
        throw new Error(`expected ${role} acquire ${resource} to succeed: ${acquired.stderr || acquired.stdout}`);
      }
      return json(acquired) as WorkerLease;
    };
    const bindLaunch = (
      role: "DEV" | "REVIEW" | "RECEIPT",
      attempt: number,
      leases: WorkerLease[],
    ): void => {
      const launchFile = path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "launches",
        "TASK-A",
        `launch-${role.toLowerCase()}-${attempt}.json`,
      );
      const launch = JSON.parse(readFileSync(launchFile, "utf8"));
      launch.resource_leases = leases.map((lease) => lease.lease_id);
      writeFileSync(launchFile, `${JSON.stringify(launch, null, 2)}\n`);
    };
    const releaseWorker = (
      role: "DEV" | "REVIEW" | "RECEIPT",
      capability: string,
      lease: WorkerLease,
    ): void => {
      const recovered = runResourceCli([
        "owner-capability",
        "--lease", lease.lease_id,
        "--actor-capability-file", capability,
        "--json",
      ], fixture.root, fixture.controlDir);
      if (recovered.code !== 0) {
        throw new Error(`expected ${role} owner-capability ${lease.lease_id} to succeed: ${recovered.stderr || recovered.stdout}`);
      }
      const recoveredOwner = json(recovered) as {
        lease_id: string;
        revision: number;
        owner_capability_file: string;
      };
      expect(recoveredOwner).toMatchObject({
        lease_id: lease.lease_id,
        revision: lease.revision,
        owner_capability_file: lease.owner_capability_file,
      });
      const released = runResourceCli([
        "release",
        "--lease", lease.lease_id,
        "--owner-capability-file", recoveredOwner.owner_capability_file,
        "--actor-capability-file", capability,
        "--expected-revision", String(lease.revision),
        "--json",
      ], fixture.root, fixture.controlDir);
      if (released.code !== 0) {
        throw new Error(`expected ${role} release ${lease.lease_id} to succeed: ${released.stderr || released.stdout}`);
      }
      expect(json(released)).toMatchObject({ status: "RELEASED" });
    };
    const rejectOwnerCapability = (
      capability: string,
      lease: WorkerLease,
      code: string,
    ): void => {
      expectControlError(runResourceCli([
        "owner-capability",
        "--lease", lease.lease_id,
        "--actor-capability-file", capability,
        "--json",
      ], fixture.root, fixture.controlDir), code);
    };
    type ReleaseRequest = {
      type: "REQUEST_RESOURCE_RELEASE";
      actor_role: "CAPTAIN";
      requested_action: "RELEASE_RESOURCE";
      lease_id: string;
      resource: string;
      expected_revision: number;
      owner: {
        role: "DEV" | "REVIEW" | "RECEIPT";
        thread_id: string;
        host_id: string;
      };
    };
    const releaseRequests = (
      rows: Array<Record<string, unknown>> | undefined,
    ): ReleaseRequest[] => (rows || [])
      .filter((row) => row.type === "REQUEST_RESOURCE_RELEASE") as ReleaseRequest[];
    const captainReleaseRequests = (): ReleaseRequest[] => {
      const result = runCli([
        "actions",
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", "CAPTAIN",
        "--thread", THREADS.CAPTAIN,
        "--json",
      ], fixture.root, fixture.controlDir);
      expect(result.code).toBe(0);
      return releaseRequests(
        (json(result) as { maintenance_actions: Array<Record<string, unknown>> })
          .maintenance_actions,
      );
    };
    const nextReleaseRequests = (): ReleaseRequest[] => {
      const result = runCli([
        "next",
        "--goal", "demo",
        "--json",
      ], fixture.root, fixture.controlDir);
      expect(result.code).toBe(0);
      const task = (
        json(result) as {
          tasks: Array<{
            task_id: string;
            maintenance_actions: Array<Record<string, unknown>>;
          }>;
        }
      ).tasks.find((candidate) => candidate.task_id === "TASK-A");
      expect(task).toBeDefined();
      return releaseRequests(task?.maintenance_actions);
    };
    const expectReleaseRequests = (
      rows: ReleaseRequest[],
      leases: WorkerLease[],
      role: "DEV" | "REVIEW" | "RECEIPT",
      thread: string,
    ): void => {
      expect(rows).toHaveLength(leases.length);
      for (const lease of leases) {
        expect(rows).toEqual(expect.arrayContaining([
          expect.objectContaining({
            type: "REQUEST_RESOURCE_RELEASE",
            actor_role: "CAPTAIN",
            requested_action: "RELEASE_RESOURCE",
            lease_id: lease.lease_id,
            resource: lease.resource,
            expected_revision: lease.revision,
            owner: {
              role,
              thread_id: thread,
              host_id: "local",
            },
          }),
        ]));
      }
      expect(JSON.stringify(rows)).not.toContain("capability");
    };

    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      payload: p1Payload(),
    });
    const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({ approval_ref: "user://issue-4242/approved" }),
    });
    apply(fixture, book, "P1_COMMITTED", "CAPTAIN", {
      fullHead: fixture.fullHead,
      payload: p1Payload({
        approval_event_id: String(approval.event.event_id),
      }),
    });

    registerRole(fixture, "DEV");
    const wrongRole = runResourceCli([
      "acquire",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--host", "local",
      "--resource", "preview-port:review-preview",
      "--access", "EXCLUSIVE",
      "--ttl-ms", "3600000",
      "--event-id", `resource-acquire-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities["TASK-A"].DEV as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(wrongRole, "RESOURCE_ROLE_MISMATCH");

    const devLeases = [
      acquireWorker("DEV", THREADS.DEV, "preview-port:dev-preview", "EXCLUSIVE"),
      acquireWorker("DEV", THREADS.DEV, "test-data:role-shared", "SHARED_READ"),
    ];
    bindLaunch("DEV", 1, devLeases);
    apply(fixture, book, "LAUNCH_DEV", "CAPTAIN", {
      payload: { launch_id: "launch-dev-1" },
    });
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: {
        pr: "https://github.com/example-org/example-repo/pull/999",
        evidence: devEvidence(fixture),
      },
    });

    registerRole(fixture, "REVIEW");
    const firstReviewCapability = fixture.capabilities["TASK-A"].REVIEW as string;
    const firstReviewLeases = [
      acquireWorker("REVIEW", THREADS.REVIEW, "preview-port:review-preview", "EXCLUSIVE"),
      acquireWorker("REVIEW", THREADS.REVIEW, "test-data:role-shared", "SHARED_READ"),
    ];
    bindLaunch("REVIEW", 1, firstReviewLeases);
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", {
      payload: { launch_id: "launch-review-1" },
    });
    apply(fixture, book, "REVIEW_REWORK", "REVIEW", {
      payload: {
        review_evidence: seedEvidence(fixture, "REVIEW", "REVIEW", "FAIL"),
      },
    });
    expectReleaseRequests(
      releaseRequests(taskStatus(fixture).maintenance_actions),
      firstReviewLeases,
      "REVIEW",
      THREADS.REVIEW,
    );
    const devActions = runCli([
      "actions",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--json",
    ], fixture.root, fixture.controlDir);
    expect(devActions.code).toBe(0);
    expect(releaseRequests(
      (json(devActions) as {
        maintenance_actions: Array<Record<string, unknown>>;
      }).maintenance_actions,
    )).toEqual([]);

    // REVIEW never consumes or invalidates the still-active DEV leases. The
    // original immutable DEV launch therefore remains valid for rework.
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: {
        pr: "https://github.com/example-org/example-repo/pull/999",
        evidence: devEvidence(fixture),
      },
    });
    for (const lease of firstReviewLeases) {
      releaseWorker("REVIEW", firstReviewCapability, lease);
    }
    expect(captainReleaseRequests()).toEqual([]);

    registerRole(fixture, "REVIEW", {
      thread: "review-a-2",
      attempt: 2,
    });
    book.REVIEW = 0;
    const secondReviewLeases = [
      acquireWorker("REVIEW", "review-a-2", "preview-port:review-preview", "EXCLUSIVE"),
      acquireWorker("REVIEW", "review-a-2", "test-data:role-shared", "SHARED_READ"),
    ];
    expect(secondReviewLeases[0].fencing_token)
      .toBeGreaterThan(firstReviewLeases[0].fencing_token);
    bindLaunch("REVIEW", 2, secondReviewLeases);
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", {
      payload: { launch_id: "launch-review-2" },
    });
    apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      threadId: "review-a-2",
      payload: {
        evidence: seedEvidence(
          fixture,
          "REVIEW",
          "REVIEW",
          "PASS",
          fixture.fullHead,
          "review-a-2",
        ),
      },
    });
    const secondReviewCapability = fixture.capabilities["TASK-A"].REVIEW as string;
    expectReleaseRequests(
      releaseRequests(taskStatus(fixture).maintenance_actions),
      secondReviewLeases,
      "REVIEW",
      "review-a-2",
    );

    registerRole(fixture, "RECEIPT");
    const firstReceiptCapability = fixture.capabilities["TASK-A"].RECEIPT as string;
    const firstReceiptLeases = [
      acquireWorker("RECEIPT", THREADS.RECEIPT, "preview-port:receipt-preview", "EXCLUSIVE"),
      acquireWorker("RECEIPT", THREADS.RECEIPT, "test-data:role-shared", "SHARED_READ"),
    ];
    bindLaunch("RECEIPT", 1, firstReceiptLeases);
    apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", {
      payload: { launch_id: "launch-receipt-1" },
    });
    apply(fixture, book, "RECEIPT_FAIL", "RECEIPT", {
      payload: {
        evidence_id: seedEvidence(fixture, "RECEIPT", "RECEIPT", "FAIL"),
      },
    });

    const retryActions = json(runCli([
      "actions",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "CAPTAIN",
      "--thread", THREADS.CAPTAIN,
      "--json",
    ], fixture.root, fixture.controlDir)) as {
      actions: Array<{ type: string }>;
      maintenance_actions: Array<Record<string, unknown>>;
    };
    expect(retryActions.actions).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: "REOPEN_REVIEW" }),
    ]));
    const failureReleaseRequests = releaseRequests(
      retryActions.maintenance_actions,
    );
    expectReleaseRequests(
      failureReleaseRequests.filter((row) => row.owner.role === "REVIEW"),
      secondReviewLeases,
      "REVIEW",
      "review-a-2",
    );
    expectReleaseRequests(
      failureReleaseRequests.filter((row) => row.owner.role === "RECEIPT"),
      firstReceiptLeases,
      "RECEIPT",
      THREADS.RECEIPT,
    );

    const toolingHoldId = `tooling-cleanup-${randomUUID()}`;
    apply(fixture, book, "ADD_HOLD", "CAPTAIN", {
      payload: {
        hold_id: toolingHoldId,
        kind: "TOOLING",
        reason: "ordinary hold must not hide exact-owner cleanup",
        evidence_id: seedEvidence(
          fixture,
          "HOLD_ASSERTION",
          "CAPTAIN",
          "BLOCKED",
        ),
      },
    });
    expectReleaseRequests(
      releaseRequests(taskStatus(fixture).maintenance_actions)
        .filter((row) => row.owner.role === "REVIEW"),
      secondReviewLeases,
      "REVIEW",
      "review-a-2",
    );
    expectReleaseRequests(
      releaseRequests(taskStatus(fixture).maintenance_actions)
        .filter((row) => row.owner.role === "RECEIPT"),
      firstReceiptLeases,
      "RECEIPT",
      THREADS.RECEIPT,
    );

    rejectOwnerCapability(
      firstReceiptCapability,
      secondReviewLeases[0],
      "CAPABILITY_INVALID",
    );
    rejectOwnerCapability(
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      secondReviewLeases[0],
      "CAPABILITY_INVALID",
    );
    registerRole(fixture, "REVIEW", {
      thread: "review-a-3",
      attempt: 3,
    });
    const thirdReviewCapability = fixture.capabilities["TASK-A"].REVIEW as string;
    rejectOwnerCapability(
      thirdReviewCapability,
      secondReviewLeases[0],
      "CAPABILITY_INVALID",
    );

    // Both verdict actors are terminal after RECEIPT_FAIL, but their exact
    // capabilities can recover only their own active owner capability for
    // cleanup. REVIEW a2 is now historical, while RECEIPT a1 remains the
    // current terminal attempt; both still require actor + owner capability
    // for release.
    for (const lease of secondReviewLeases) {
      releaseWorker("REVIEW", secondReviewCapability, lease);
    }
    for (const lease of firstReceiptLeases) {
      releaseWorker("RECEIPT", firstReceiptCapability, lease);
    }
    expect(releaseRequests(taskStatus(fixture).maintenance_actions)).toEqual([]);
    apply(fixture, book, "RESOLVE_HOLD", "CAPTAIN", {
      payload: {
        hold_id: toolingHoldId,
        resolution_evidence_id: seedEvidence(
          fixture,
          "HOLD_RESOLUTION",
          "FOREMAN",
        ),
      },
    });

    book.REVIEW = 0;
    const thirdReviewLeases = [
      acquireWorker("REVIEW", "review-a-3", "preview-port:review-preview", "EXCLUSIVE"),
      acquireWorker("REVIEW", "review-a-3", "test-data:role-shared", "SHARED_READ"),
    ];
    expect(thirdReviewLeases[0].fencing_token)
      .toBeGreaterThan(secondReviewLeases[0].fencing_token);
    expect(thirdReviewLeases[1].fencing_token)
      .toBeGreaterThan(secondReviewLeases[1].fencing_token);
    bindLaunch("REVIEW", 3, thirdReviewLeases);
    apply(fixture, book, "REOPEN_REVIEW", "CAPTAIN", {
      payload: { launch_id: "launch-review-3" },
    });
    apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      threadId: "review-a-3",
      payload: {
        evidence: seedEvidence(
          fixture,
          "REVIEW",
          "REVIEW",
          "PASS",
          fixture.fullHead,
          "review-a-3",
        ),
      },
    });
    expectReleaseRequests(
      nextReleaseRequests(),
      thirdReviewLeases,
      "REVIEW",
      "review-a-3",
    );

    registerRole(fixture, "RECEIPT", {
      thread: "receipt-a-2",
      attempt: 2,
    });
    book.RECEIPT = 0;
    const secondReceiptLeases = [
      acquireWorker("RECEIPT", "receipt-a-2", "preview-port:receipt-preview", "EXCLUSIVE"),
      acquireWorker("RECEIPT", "receipt-a-2", "test-data:role-shared", "SHARED_READ"),
    ];
    expect(secondReceiptLeases[0].fencing_token)
      .toBeGreaterThan(firstReceiptLeases[0].fencing_token);
    expect(secondReceiptLeases[1].fencing_token)
      .toBeGreaterThan(firstReceiptLeases[1].fencing_token);
    bindLaunch("RECEIPT", 2, secondReceiptLeases);
    apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", {
      payload: { launch_id: "launch-receipt-2" },
    });
    apply(fixture, book, "RECEIPT_PASS", "RECEIPT", {
      threadId: "receipt-a-2",
      payload: {
        evidence: seedEvidence(
          fixture,
          "RECEIPT",
          "RECEIPT",
          "PASS",
          fixture.fullHead,
          "receipt-a-2",
        ),
      },
    });
    const secondReceiptCapability = fixture.capabilities["TASK-A"].RECEIPT as string;
    const passReleaseRequests = releaseRequests(
      taskStatus(fixture).maintenance_actions,
    );
    expectReleaseRequests(
      passReleaseRequests.filter((row) => row.owner.role === "REVIEW"),
      thirdReviewLeases,
      "REVIEW",
      "review-a-3",
    );
    expectReleaseRequests(
      passReleaseRequests.filter((row) => row.owner.role === "RECEIPT"),
      secondReceiptLeases,
      "RECEIPT",
      "receipt-a-2",
    );

    const listed = json(runResourceCli([
      "list",
      "--goal", "demo",
      "--task", "TASK-A",
      "--json",
    ], fixture.root, fixture.controlDir)) as {
      leases: Array<{
        lease_id: string;
        status: string;
        owner: { role: Role };
      }>;
    };
    for (const lease of [...devLeases, ...thirdReviewLeases, ...secondReceiptLeases]) {
      expect(listed.leases).toEqual(expect.arrayContaining([
        expect.objectContaining({
          lease_id: lease.lease_id,
          status: "ACTIVE",
        }),
      ]));
    }
    expect(listed.leases.filter((lease) => lease.status === "ACTIVE")
      .map((lease) => lease.owner.role)).toEqual(
      expect.arrayContaining(["DEV", "REVIEW", "RECEIPT"]),
    );

    const securityHoldId = `security-cleanup-${randomUUID()}`;
    apply(fixture, book, "ADD_HOLD", "CAPTAIN", {
      payload: {
        hold_id: securityHoldId,
        kind: "BLOCKED_SECURITY",
        reason: "resource identity must remain quarantined",
        evidence_id: seedEvidence(
          fixture,
          "HOLD_ASSERTION",
          "CAPTAIN",
          "BLOCKED",
        ),
      },
    });
    expect(releaseRequests(taskStatus(fixture).maintenance_actions)).toEqual([]);
    rejectOwnerCapability(
      thirdReviewCapability,
      thirdReviewLeases[0],
      "TASK_HARD_HELD",
    );
    expectControlError(runResourceCli([
      "release",
      "--lease", thirdReviewLeases[0].lease_id,
      "--owner-capability-file",
      thirdReviewLeases[0].owner_capability_file,
      "--actor-capability-file", thirdReviewCapability,
      "--expected-revision", String(thirdReviewLeases[0].revision),
      "--event-id", `resource-release-${randomUUID()}`,
      "--json",
    ], fixture.root, fixture.controlDir), "TASK_HARD_HELD");
    apply(fixture, book, "RESOLVE_HOLD", "FOREMAN", {
      payload: {
        hold_id: securityHoldId,
        authority: "security-owner",
        resolution_evidence_id: seedEvidence(
          fixture,
          "HOLD_RESOLUTION",
          "FOREMAN",
        ),
        disposition: "FIXED",
      },
    });
    expectReleaseRequests(
      releaseRequests(taskStatus(fixture).maintenance_actions)
        .filter((row) => row.owner.role === "REVIEW"),
      thirdReviewLeases,
      "REVIEW",
      "review-a-3",
    );
    expectReleaseRequests(
      releaseRequests(taskStatus(fixture).maintenance_actions)
        .filter((row) => row.owner.role === "RECEIPT"),
      secondReceiptLeases,
      "RECEIPT",
      "receipt-a-2",
    );

    for (const lease of thirdReviewLeases) {
      releaseWorker("REVIEW", thirdReviewCapability, lease);
    }
    rejectOwnerCapability(
      thirdReviewCapability,
      thirdReviewLeases[0],
      "LEASE_NOT_ACTIVE",
    );
    for (const lease of secondReceiptLeases) {
      releaseWorker("RECEIPT", secondReceiptCapability, lease);
    }
    expect(releaseRequests(taskStatus(fixture).maintenance_actions)).toEqual([]);
    expect(captainReleaseRequests()).toEqual([]);
    expect(nextReleaseRequests()).toEqual([]);

    apply(fixture, book, "READY_FOR_MERGE", "CAPTAIN");
    apply(fixture, book, "MERGED", "FOREMAN", {
      payload: {
        expected_main_head: fixture.baseHead,
        main_merge_sha: fixture.fullHead,
      },
    });
    expect(taskStatus(fixture).sessions?.DEV).toMatchObject({
      status: "terminal",
      terminal_reason: "TASK_MERGED",
    });
    expectReleaseRequests(
      captainReleaseRequests(),
      devLeases,
      "DEV",
      THREADS.DEV,
    );
    expectReleaseRequests(
      nextReleaseRequests(),
      devLeases,
      "DEV",
      THREADS.DEV,
    );
    for (const lease of devLeases) {
      releaseWorker(
        "DEV",
        fixture.capabilities["TASK-A"].DEV as string,
        lease,
      );
    }
    expect(captainReleaseRequests()).toEqual([]);
    const healthyDoctor = runCli(
      ["doctor", "--goal", "demo", "--json"],
      fixture.root,
      fixture.controlDir,
    );
    expect(healthyDoctor.code).toBe(0);
    expect(json(healthyDoctor)).toMatchObject({
      healthy: true,
      findings: [],
    });
    const archiveEvidence = seedEvidence(
      fixture,
      "MERGE_BOUNDARY",
      "FOREMAN",
    );
    apply(fixture, book, "ARCHIVED", "FOREMAN", {
      payload: { evidence_id: archiveEvidence },
    });
    rejectOwnerCapability(
      secondReceiptCapability,
      secondReceiptLeases[0],
      "TASK_TERMINAL",
    );
  });

  it("rechecks semantic evidence source bytes when the verdict is consumed", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    registerRole(fixture, "REVIEW");
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", { payload: { launch_id: "launch-review-1" } });
    const evidenceId = seedEvidence(fixture, "REVIEW", "REVIEW");
    const artifact = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence",
      "TASK-A",
      `${evidenceId}-artifact.json`
    );
    writeFileSync(artifact, "{\"tampered\":true}\n");
    const verdict = buildEvent(fixture, "REVIEW_PASS", "REVIEW", book.REVIEW + 1, {
      payload: { evidence: evidenceId },
    });
    expectControlError(submitEvent(fixture, verdict), "EVIDENCE_SOURCE_HASH_MISMATCH");
  });

  it("requires fresh REVIEW and RECEIPT sessions after receipt failure", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    registerRole(fixture, "REVIEW");
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", { payload: { launch_id: "launch-review-1" } });
    const originalReviewPass = apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW") },
    });
    const originalReviewCapability = fixture.capabilities["TASK-A"].REVIEW;
    registerRole(fixture, "RECEIPT");
    apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", { payload: { launch_id: "launch-receipt-1" } });
    apply(fixture, book, "RECEIPT_FAIL", "RECEIPT", {
      payload: { evidence_id: seedEvidence(fixture, "RECEIPT", "RECEIPT", "FAIL") },
    });

    registerRole(fixture, "REVIEW", { thread: "review-a-2", attempt: 2 });
    const replacementReviewCapability = fixture.capabilities["TASK-A"].REVIEW;
    fixture.capabilities["TASK-A"].REVIEW = originalReviewCapability;
    const delayedReplay = submitEvent(fixture, originalReviewPass.event);
    expect(delayedReplay.code).toBe(0);
    expect(delayedReplay.stdout).toContain("idempotent");
    fixture.capabilities["TASK-A"].REVIEW = replacementReviewCapability;
    book.REVIEW = 0;
    apply(fixture, book, "REOPEN_REVIEW", "CAPTAIN", {
      payload: { launch_id: "launch-review-2" },
    });
    apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      threadId: "review-a-2",
      payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW", "PASS", fixture.fullHead, "review-a-2") },
    });

    const staleReceipt = buildEvent(fixture, "LAUNCH_RECEIPT", "CAPTAIN", book.CAPTAIN + 1, {
      payload: { launch_id: "launch-receipt-1" },
    });
    expectControlError(submitEvent(fixture, staleReceipt), "FRESH_SESSION_REQUIRED");

    registerRole(fixture, "RECEIPT", { thread: "receipt-a-2", attempt: 2 });
    book.RECEIPT = 0;
    apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", {
      payload: { launch_id: "launch-receipt-2" },
    });
    apply(fixture, book, "RECEIPT_PASS", "RECEIPT", {
      threadId: "receipt-a-2",
      payload: { evidence: seedEvidence(fixture, "RECEIPT", "RECEIPT", "PASS", fixture.fullHead, "receipt-a-2") },
    });
    expect(taskStatus(fixture)).toMatchObject({
      phase: "RECEIPT_PASS",
      sessions: { RECEIPT: { thread_id: "receipt-a-2", attempt: 2, status: "terminal" } },
    });
  });

  it("recovers a lost DEV after receipt failure and reopens development with a fresh launch", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    registerRole(fixture, "REVIEW");
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", { payload: { launch_id: "launch-review-1" } });
    apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW") },
    });
    registerRole(fixture, "RECEIPT");
    apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", { payload: { launch_id: "launch-receipt-1" } });
    apply(fixture, book, "RECEIPT_FAIL", "RECEIPT", {
      payload: { evidence_id: seedEvidence(fixture, "RECEIPT", "RECEIPT", "FAIL") },
    });

    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: { role: "DEV", reason: "original DEV session ended after receipt feedback", attempts: 1 },
    });
    registerRole(fixture, "DEV", { thread: "dev-a-2", attempt: 2, seedLaunch: false });
    book.DEV = 0;
    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      payload: { successor_thread_id: "dev-a-2" },
    });
    const recoveredDev = taskStatus(fixture).sessions?.DEV;
    expect(recoveredDev).toBeDefined();
    seedLaunchRuntime(fixture, "TASK-A", "DEV", { session: recoveredDev });
    apply(fixture, book, "REOPEN_DEV", "CAPTAIN");
    expect(taskStatus(fixture)).toMatchObject({
      phase: "DEV_ACTIVE",
      sessions: { DEV: { thread_id: "dev-a-2", attempt: 2, status: "active" } },
    });

    apply(fixture, book, "DEV_READY", "DEV", {
      threadId: "dev-a-2",
      fullHead: fixture.fullHead,
      payload: {
        pr: "https://github.com/example-org/example-repo/pull/999",
        evidence: devEvidence(fixture, fixture.fullHead, "dev-a-2"),
      },
    });
    expect(taskStatus(fixture).phase).toBe("DEV_READY");
  });

  it("accepts exact terminal REVIEW/RECEIPT event replays only with the original actor capability", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    registerRole(fixture, "REVIEW");
    apply(fixture, book, "LAUNCH_REVIEW", "CAPTAIN", { payload: { launch_id: "launch-review-1" } });
    const reviewPass = apply(fixture, book, "REVIEW_PASS", "REVIEW", {
      payload: { evidence: seedEvidence(fixture, "REVIEW", "REVIEW") },
    });
    const reviewRevision = taskStatus(fixture).state_revision;
    const reviewReplay = submitEvent(fixture, reviewPass.event);
    expect(reviewReplay.code).toBe(0);
    expect(reviewReplay.stdout).toContain("idempotent");
    expect(taskStatus(fixture).state_revision).toBe(reviewRevision);

    const reviewCapability = fixture.capabilities["TASK-A"].REVIEW;
    fixture.capabilities["TASK-A"].REVIEW = fixture.capabilities["TASK-A"].DEV;
    expectControlError(submitEvent(fixture, reviewPass.event), "CAPABILITY_INVALID");
    fixture.capabilities["TASK-A"].REVIEW = reviewCapability;

    registerRole(fixture, "RECEIPT");
    apply(fixture, book, "LAUNCH_RECEIPT", "CAPTAIN", { payload: { launch_id: "launch-receipt-1" } });
    const receiptPass = apply(fixture, book, "RECEIPT_PASS", "RECEIPT", {
      payload: { evidence: seedEvidence(fixture, "RECEIPT", "RECEIPT") },
    });
    const receiptRevision = taskStatus(fixture).state_revision;
    const receiptReplay = submitEvent(fixture, receiptPass.event);
    expect(receiptReplay.code).toBe(0);
    expect(receiptReplay.stdout).toContain("idempotent");
    expect(taskStatus(fixture).state_revision).toBe(receiptRevision);
  });

  it("rejects premature worker registration without invalidating a launch on unrelated heartbeats", () => {
    initAndRegister(fixture);
    const premature = runCli([
      "register-role", "--goal", "demo", "--task", "TASK-A", "--role", "DEV",
      "--thread", THREADS.DEV, "--host", "local", "--attempt", "1",
      "--launch-id", "launch-dev-1", "--authorizer-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string, "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(premature, "PREMATURE_ROLE_REGISTRATION");

    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "DEV_READY", "DEV", {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    registerRole(fixture, "REVIEW");
    apply(fixture, book, "HEARTBEAT", "CAPTAIN", { payload: { status: "active", lease_ms: 3600000 } });
    const staleLaunch = buildEvent(fixture, "LAUNCH_REVIEW", "CAPTAIN", book.CAPTAIN + 1, {
      payload: { launch_id: "launch-review-1" },
    });
    expect(submitEvent(fixture, staleLaunch).code).toBe(0);
    expect(taskStatus(fixture).phase).toBe("REVIEW_ACTIVE");
  });

  it("binds P1 approval to actual plan/context files and committed HEAD blobs", () => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    writeFileSync(path.join(fixture.root, PLAN_PATH), "# tampered before ready\n");
    const tamperedReady = buildEvent(fixture, "P1_READY", "CAPTAIN", 2, { payload: p1Payload() });
    expectControlError(submitEvent(fixture, tamperedReady), "P1_ARTIFACT_MISMATCH");

    writeFileSync(path.join(fixture.root, PLAN_PATH), PLAN_BODY);
    apply(fixture, book, "P1_READY", "CAPTAIN", { payload: p1Payload() });
    const approval = apply(fixture, book, "P1_APPROVED", "FOREMAN", {
      payload: p1Payload({ approval_ref: "user://issue-4242/approved" }),
    });
    writeFileSync(path.join(fixture.root, PLAN_PATH), "# changed after approval\n");
    git(fixture.root, "add", PLAN_PATH);
    git(fixture.root, "commit", "-qm", "mutate approved plan");
    fixture.fullHead = git(fixture.root, "rev-parse", "HEAD");
    const mismatchedCommit = buildEvent(fixture, "P1_COMMITTED", "CAPTAIN", book.CAPTAIN + 1, {
      fullHead: fixture.fullHead,
      payload: p1Payload({ approval_event_id: approval.event.event_id }),
    });
    expectControlError(submitEvent(fixture, mismatchedCommit), "P1_ARTIFACT_MISMATCH");
    expect(taskStatus(fixture).phase).toBe("P1_APPROVED");
  });

  it("rejects P1 commit before an explicit approval event", () => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    apply(fixture, book, "P1_READY", "CAPTAIN", {
      payload: p1Payload(),
    });

    const event = buildEvent(fixture, "P1_COMMITTED", "CAPTAIN", 3, {
      fullHead: fixture.fullHead,
      payload: p1Payload({ approval_event_id: randomUUID() }),
    });
    expectControlError(submitEvent(fixture, event), "ILLEGAL_TRANSITION");
    expect(taskStatus(fixture).phase).toBe("P1_READY");
  });

  it("rejects an event emitted by a registered but unauthorized role", () => {
    initAndRegister(fixture);
    const event = buildEvent(fixture, "START_P1", "FOREMAN", 1);

    expectControlError(submitEvent(fixture, event), "WRONG_ACTOR_ROLE");
    expect(taskStatus(fixture).phase).toBe("QUEUED");
  });

  it("treats an exact duplicate event as idempotent but rejects the same id with different content", () => {
    initAndRegister(fixture);
    const event = buildEvent(fixture, "START_P1", "CAPTAIN", 1);
    const first = submitEvent(fixture, event);
    expect(first.code).toBe(0);
    const revision = taskStatus(fixture).state_revision;

    const duplicate = submitEvent(fixture, event);
    expect(duplicate.code).toBe(0);
    expect(duplicate.stdout).toContain("idempotent");
    expect(taskStatus(fixture).state_revision).toBe(revision);

    const altered = { ...event, actor_sequence: 2 };
    expectControlError(submitEvent(fixture, altered), "EVENT_ID_CONFLICT");
    expect(taskStatus(fixture).state_revision).toBe(revision);
  });

  it("exact-retries an accepted event with its historical actor after takeover and frozen-input loss", () => {
    initAndRegister(fixture);
    const oldCaptainCapability = fixture.capabilities["TASK-A"].CAPTAIN as string;
    const heartbeat = buildEvent(fixture, "HEARTBEAT", "CAPTAIN", 1, {
      payload: { lease_ms: 3600000, status: "active" },
    });
    expect(submitEvent(fixture, heartbeat).code).toBe(0);

    const book = sequences();
    apply(fixture, book, "ROLE_LOST", "FOREMAN", {
      payload: {
        role: "CAPTAIN",
        reason: "original captain later disappeared",
        fingerprint: "system-error:captain-a-1",
        attempts: 1,
      },
    });
    registerRole(fixture, "CAPTAIN", {
      thread: "captain-a-2",
      attempt: 2,
    });
    apply(fixture, book, "ROLE_RECOVERED", "FOREMAN", {
      payload: { successor_thread_id: "captain-a-2" },
    });

    unlinkSync(path.join(fixture.root, "docs", "protocol", "shared.md"));
    const duplicate = submitEvent(fixture, heartbeat, oldCaptainCapability);
    expect(duplicate.code).toBe(0);
    expect(json(duplicate)).toMatchObject({
      accepted: true,
      idempotent: true,
      task: {
        sessions: {
          CAPTAIN: {
            thread_id: "captain-a-2",
            attempt: 2,
          },
        },
      },
    });
  });

  it.each([
    {
      name: "CAS revision",
      code: "STALE_STATE_REVISION",
      overrides: (state: TaskStatus) => ({ expectedStateRevision: state.state_revision - 1 }),
    },
    {
      name: "actor sequence",
      code: "ACTOR_SEQUENCE_MISMATCH",
      overrides: () => ({ actorSequence: 1 }),
    },
    {
      name: "packet digest",
      code: "STALE_PACKET",
      overrides: () => ({ packetHash: `sha256:${"0".repeat(64)}` }),
    },
    {
      name: "full HEAD",
      code: "STALE_HEAD",
      overrides: () => ({ fullHead: "f".repeat(40) }),
    },
  ])("rejects a stale $name without advancing durable state", ({ code, overrides }) => {
    initAndRegister(fixture);
    const book = sequences();
    apply(fixture, book, "START_P1", "CAPTAIN");
    const before = taskStatus(fixture);
    const event = buildEvent(fixture, "P1_READY", "CAPTAIN", 2, {
      payload: p1Payload(),
      ...overrides(before),
    });

    expectControlError(submitEvent(fixture, event), code);
    expect(taskStatus(fixture).state_revision).toBe(before.state_revision);
  });

  it("makes security holds sticky and forbids CAPTAIN waiver or normal progress", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    const holdId = randomUUID();
    apply(fixture, book, "ADD_HOLD", "DEV", {
      payload: {
        hold_id: holdId,
        kind: "BLOCKED_SECURITY",
        reason: "possible cross-tenant read",
        evidence_id: seedEvidence(fixture, "HOLD_ASSERTION", "DEV", "BLOCKED"),
      },
    });
    expect(taskStatus(fixture).holds).toEqual([
      expect.objectContaining({ hold_id: holdId, kind: "BLOCKED_SECURITY" }),
    ]);

    const readyWhileHeld = buildEvent(fixture, "DEV_READY", "DEV", 2, {
      fullHead: fixture.fullHead,
      payload: { pr: "https://github.com/example-org/example-repo/pull/999", evidence: devEvidence(fixture) },
    });
    expectControlError(submitEvent(fixture, readyWhileHeld), "TASK_HELD");

    const captainWaiver = buildEvent(fixture, "RESOLVE_HOLD", "CAPTAIN", book.CAPTAIN + 1, {
      payload: {
        hold_id: holdId,
        authority: "captain",
        resolution_evidence_id: seedEvidence(fixture, "HOLD_RESOLUTION", "FOREMAN"),
        disposition: "WAIVED",
      },
    });
    expectControlError(submitEvent(fixture, captainWaiver), "HARD_HOLD_AUTHORITY_REQUIRED");

    apply(fixture, book, "RESOLVE_HOLD", "FOREMAN", {
      payload: {
        hold_id: holdId,
        authority: "backend-security-owner",
        resolution_evidence_id: seedEvidence(fixture, "HOLD_RESOLUTION", "FOREMAN"),
        disposition: "FIXED",
      },
    });
    expect(taskStatus(fixture)).toMatchObject({ phase: "DEV_ACTIVE", holds: [] });
  });

  it("fails closed when DEV_READY omits deterministic preflight evidence or binds it to an old HEAD", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    const missingPreflight = devEvidence(fixture);
    delete (missingPreflight as Partial<typeof missingPreflight>).preflight;
    const missingEvent = buildEvent(fixture, "DEV_READY", "DEV", 1, {
      fullHead: fixture.fullHead,
      payload: {
        pr: "https://github.com/example-org/example-repo/pull/999",
        evidence: missingPreflight,
      },
    });
    expectControlError(submitEvent(fixture, missingEvent), "EVIDENCE_NOT_REGISTERED");
    expect(taskStatus(fixture).phase).toBe("DEV_ACTIVE");

    const staleEvidence = devEvidence(fixture, "e".repeat(40));
    const staleEvent = buildEvent(fixture, "DEV_READY", "DEV", 1, {
      fullHead: fixture.fullHead,
      payload: {
        pr: "https://github.com/example-org/example-repo/pull/999",
        evidence: staleEvidence,
      },
    });
    expectControlError(submitEvent(fixture, staleEvent), "STALE_EVIDENCE");
    expect(taskStatus(fixture).phase).toBe("DEV_ACTIVE");
  });

  it("rejects DEV_READY from a clean sibling that drops the registered DEV lineage", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    const registeredHead = fixture.fullHead;
    const tree = git(fixture.root, "rev-parse", `${registeredHead}^{tree}`);
    const sibling = git(
      fixture.root,
      "commit-tree",
      tree,
      "-p",
      fixture.baseHead,
      "-m",
      "divergent candidate with identical frozen bytes"
    );
    git(fixture.root, "reset", "--hard", sibling);
    fixture.fullHead = sibling;

    const event = buildEvent(fixture, "DEV_READY", "DEV", 1, {
      fullHead: sibling,
      payload: {
        pr: "https://github.com/example-org/example-repo/pull/999",
        evidence: devEvidence(fixture),
      },
    });
    expectControlError(
      submitEvent(fixture, event),
      "CANDIDATE_HEAD_NOT_DESCENDANT"
    );
    expect(taskStatus(fixture)).toMatchObject({
      phase: "DEV_ACTIVE",
      full_head: registeredHead,
    });
  });

  it("doctor reports a lost role and a registered successor restores the exact stage", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: {
        role: "DEV",
        reason: "systemError before terminal event",
        fingerprint: "system-error:worker-lost",
        attempts: 1,
      },
    });
    expect(taskStatus(fixture)).toMatchObject({
      phase: "DEV_ACTIVE",
      recovery: { role: "DEV" },
    });

    const unhealthy = runCli(["doctor", "--goal", "demo", "--json"], fixture.root, fixture.controlDir);
    expect(unhealthy.code).not.toBe(0);
    expect(unhealthy.stdout).toContain("RECOVERY_REQUIRED");

    const successor = registerRole(fixture, "DEV", { thread: "dev-a-2", attempt: 2, seedLaunch: false });
    const prematureLaunchInput = path.join(fixture.controlDir, "premature-recovery-launch.json");
    writeFileSync(prematureLaunchInput, `${JSON.stringify({
      execution: {
        environment: "none",
        write_mode: "NONE",
        target: { kind: "NONE" },
      },
      resource_leases: [],
    }, null, 2)}\n`);
    const preflightBeforeRecoveryClosed = runCli([
      "launch-template",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-a-2",
      "--actor-capability-file", String(successor.actor_capability_file),
      "--input-file", prematureLaunchInput,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(preflightBeforeRecoveryClosed, "RECOVERY_REQUIRED");

    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      payload: { successor_thread_id: "dev-a-2" },
    });
    const recovered = taskStatus(fixture);
    expect(recovered).toMatchObject({
      phase: "DEV_ACTIVE",
      recovery: null,
      sessions: {
        DEV: {
          thread_id: "dev-a-2",
          attempt: 2,
          status: "active",
          activated_state_revision: recovered.state_revision,
          recovered_from: {
            thread_id: THREADS.DEV,
            attempt: 1,
            resume_phase: "DEV_ACTIVE",
          },
        },
      },
    });

    apply(fixture, book, "HEARTBEAT", "CAPTAIN", {
      payload: { status: "active", lease_ms: 3600000 },
    });

    const projected = taskStatus(fixture);
    expect(projected.operational_scope).toBe("RECOVERY_BLOCKED");
    expect(projected.next_actions?.map((item) => item.type)).not.toContain("DEV_READY");
    const runtimeLedger = JSON.parse(readFileSync(
      path.join(fixture.controlDir, "goals", "demo", "ledger.json"),
      "utf8"
    )) as { tasks: Array<{ task_id: string; operational_scope: string; next_actions: string[] }> };
    expect(runtimeLedger.tasks.find((task) => task.task_id === "TASK-A")).toMatchObject({
      operational_scope: "RECOVERY_BLOCKED",
      next_actions: expect.not.arrayContaining(["DEV_READY"]),
    });
    const nextProjection = runCli(["next", "--goal", "demo", "--json"], fixture.root, fixture.controlDir);
    expect(nextProjection.code).toBe(0);
    const projectedRow = (json(nextProjection).tasks as Array<{
      task_id: string;
      operational_scope: string;
      next_actions: Array<{ type: string }>;
    }>).find((task) => task.task_id === "TASK-A");
    expect(projectedRow).toMatchObject({ operational_scope: "RECOVERY_BLOCKED" });
    expect(projectedRow?.next_actions.map((item) => item.type)).not.toContain("DEV_READY");

    const restrictedDoctor = runCli(["doctor", "--goal", "demo", "--json"], fixture.root, fixture.controlDir);
    expect(restrictedDoctor.code).not.toBe(0);
    expect(json(restrictedDoctor)).toMatchObject({
      healthy: false,
      findings: [
        expect.objectContaining({
          code: "RECOVERY_HANDOFF_REQUIRED",
          role: "DEV",
        }),
      ],
    });

    const restrictedResume = runCli([
      "resume", "--goal", "demo", "--task", "TASK-A", "--role", "DEV", "--thread", "dev-a-2", "--json",
    ], fixture.root, fixture.controlDir);
    expect(restrictedResume.code).toBe(0);
    expect(json(restrictedResume)).toMatchObject({
      launch_id: "launch-dev-2",
      launch_file: null,
      launch_scope: "RECOVERY_BLOCKED",
      resource_leases: [],
    });
    expect((json(restrictedResume).allowed_actions as Array<{ type: string }>).map((item) => item.type))
      .not.toContain("DEV_READY");

    const restrictedActions = runCli([
      "actions", "--goal", "demo", "--task", "TASK-A", "--role", "DEV", "--thread", "dev-a-2", "--json",
    ], fixture.root, fixture.controlDir);
    expect(restrictedActions.code).toBe(0);
    expect(json(restrictedActions)).toMatchObject({ launch_scope: "RECOVERY_BLOCKED" });
    expect((json(restrictedActions).actions as Array<{ type: string }>).map((item) => item.type))
      .not.toContain("DEV_READY");

    const prematureReady = buildEvent(fixture, "DEV_READY", "DEV", 1, {
      threadId: "dev-a-2",
      fullHead: fixture.fullHead,
      payload: {
        pr: "https://github.com/example-org/example-repo/pull/999",
        evidence: {
          preflight: "missing-preflight",
          fast: "missing-fast",
          full_ci: "missing-full-ci",
          ac_audit: "missing-ac-audit",
        },
      },
    });
    expectControlError(
      submitEvent(fixture, prematureReady),
      "RECOVERY_HANDOFF_REQUIRED"
    );

  });

  it("retargets an expired unconfirmed recovery successor without losing the original DEV handoff", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: {
        role: "DEV",
        reason: "original DEV lost",
        fingerprint: "system-error:dev-1",
        attempts: 1,
      },
    });
    registerRole(fixture, "DEV", {
      thread: "dev-a-2",
      attempt: 2,
      seedLaunch: false,
      leaseMs: 60000,
    });

    const stillActiveReplacement = runCli([
      "register-role",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", "dev-a-3",
      "--host", "local",
      "--attempt", "3",
      "--launch-id", "launch-dev-3",
      "--authorizer-capability-file", fixture.capabilities["TASK-A"].CAPTAIN as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(stillActiveReplacement, "RECOVERY_SUCCESSOR_STILL_ACTIVE");

    const secondLease = taskStatus(fixture).sessions?.DEV?.lease_until;
    expect(secondLease).toBeDefined();
    process.env.GOAL_CONTROL_NOW = new Date(Date.parse(secondLease as string) + 1).toISOString();
    registerRole(fixture, "DEV", {
      thread: "dev-a-3",
      attempt: 3,
      seedLaunch: false,
    });
    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      payload: { successor_thread_id: "dev-a-3" },
    });

    expect(taskStatus(fixture)).toMatchObject({
      phase: "DEV_ACTIVE",
      sessions: {
        DEV: {
          thread_id: "dev-a-3",
          attempt: 3,
          recovered_from: {
            thread_id: THREADS.DEV,
            attempt: 1,
          },
        },
      },
      session_history: {
        DEV: expect.arrayContaining([
          expect.objectContaining({
            thread_id: "dev-a-2",
            attempt: 2,
            status: "lost",
            terminal_reason: "RECOVERY_SUCCESSOR_LEASE_EXPIRED",
          }),
        ]),
      },
    });
    const resumed = runCli([
      "resume", "--goal", "demo", "--task", "TASK-A", "--role", "DEV", "--thread", "dev-a-3", "--json",
    ], fixture.root, fixture.controlDir);
    expect(resumed.code).toBe(0);
    expect(json(resumed)).toMatchObject({
      launch_scope: "RECOVERY_BLOCKED",
    });
  });

  it("never reuses a thread identity that already appears in task session history", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: {
        role: "DEV",
        reason: "first DEV lost",
        fingerprint: "system-error:dev-a1",
        attempts: 1,
      },
    });
    registerRole(fixture, "DEV", {
      thread: "dev-a-2",
      attempt: 2,
      seedLaunch: false,
    });
    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      payload: { successor_thread_id: "dev-a-2" },
    });
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: {
        role: "DEV",
        reason: "second DEV lost",
        fingerprint: "system-error:dev-a2",
        attempts: 1,
      },
    });

    const reused = runCli([
      "register-role",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--host", "new-host",
      "--attempt", "3",
      "--launch-id", "launch-dev-3",
      "--authorizer-capability-file",
      fixture.capabilities["TASK-A"].CAPTAIN as string,
      "--json",
    ], fixture.root, fixture.controlDir);
    expectControlError(reused, "ROLE_IDENTITY_REUSE");
    expect(taskStatus(fixture)).toMatchObject({
      recovery: { role: "DEV" },
      sessions: {
        DEV: { thread_id: "dev-a-2", attempt: 2, status: "lost" },
      },
    });
  });

  it("retargets a recovered-but-dormant DEV after thread handoff without losing the original source predecessor", () => {
    initAndRegister(fixture);
    const book = sequences();
    advanceToDevActive(fixture, book);
    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      payload: {
        role: "DEV",
        reason: "original DEV lost with dirty source",
        fingerprint: "system-error:dev-a1",
        attempts: 1,
      },
    });
    registerRole(fixture, "DEV", {
      thread: "dev-a-2",
      attempt: 2,
      seedLaunch: false,
    });
    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      payload: { successor_thread_id: "dev-a-2" },
    });
    expect(taskStatus(fixture).sessions?.DEV).toMatchObject({
      thread_id: "dev-a-2",
      operational_scope: "RECOVERY_BLOCKED",
      recovered_from: {
        thread_id: THREADS.DEV,
        attempt: 1,
      },
    });

    apply(fixture, book, "ROLE_LOST", "CAPTAIN", {
      threadId: THREADS.CAPTAIN,
      payload: {
        role: "DEV",
        reason: "Codex handoff created a fresh thread identity before activation",
        fingerprint: "thread-handoff:dev-a2",
        attempts: 1,
      },
    });
    registerRole(fixture, "DEV", {
      thread: "dev-a-3",
      attempt: 3,
      seedLaunch: false,
    });
    apply(fixture, book, "ROLE_RECOVERED", "CAPTAIN", {
      payload: { successor_thread_id: "dev-a-3" },
    });

    expect(taskStatus(fixture).sessions?.DEV).toMatchObject({
      thread_id: "dev-a-3",
      attempt: 3,
      operational_scope: "RECOVERY_BLOCKED",
      recovered_from: {
        thread_id: THREADS.DEV,
        attempt: 1,
        predecessor_launch_id: "launch-dev-1",
      },
      recovery_chain: [
        expect.objectContaining({
          thread_id: "dev-a-2",
          attempt: 2,
        }),
      ],
    });
    const resumed = runCli([
      "resume", "--goal", "demo", "--task", "TASK-A", "--role", "DEV", "--thread", "dev-a-3", "--json",
    ], fixture.root, fixture.controlDir);
    expect(resumed.code).toBe(0);
    expect(json(resumed)).toMatchObject({
      launch_scope: "RECOVERY_BLOCKED",
      launch_file: null,
    });
  });

  it("runs the policy-gated canonical GitHub squash merge and seals its receipt", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture, { remoteOnlyMergeCommit: true });
    try {
      const result = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        canonicalMergeOptions(fixture),
        github.dependencies,
      ));
      expect(result).toMatchObject({
        accepted: true,
        idempotent: false,
        event_id: "merge-task-a-stable",
      });
      expect(github.mergeCalls()).toBe(1);
      expect(taskStatus(fixture)).toMatchObject({
        phase: "MERGED_TO_MAIN",
        merge: {
          receipt_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        },
        sessions: {
          DEV: {
            status: "terminal",
            terminal_reason: "TASK_MERGED",
          },
        },
      });
      const doctor = runCli(
        ["doctor", "--goal", "demo", "--json"],
        fixture.root,
        fixture.controlDir,
      );
      expect(doctor.code).toBe(0);
      expect(json(doctor)).toMatchObject({ healthy: true, findings: [] });
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("hard-rejects raw MERGED for a Goal that requires the canonical wrapper", () => {
    const book = prepareReadyForCanonicalMerge(fixture);
    const raw = buildEvent(
      fixture,
      "MERGED",
      "FOREMAN",
      book.FOREMAN + 1,
      {
        eventId: "raw-merge-bypass",
        payload: {
          expected_main_head: fixture.baseHead,
          main_merge_sha: fixture.fullHead,
          merge_receipt_sha256: sha256("fabricated"),
        },
      },
    );
    expectControlError(
      submitEvent(fixture, raw),
      "GITHUB_MERGE_WRAPPER_REQUIRED",
    );
    expect(taskStatus(fixture).phase).toBe("ACCEPTED_PENDING_MERGE");
  });

  it("recovers response loss after GitHub merged without invoking merge twice", () => {
    prepareReadyForCanonicalMerge(fixture);
    const provider = {
      permission: "WRITE",
      squashMergeAllowed: true,
      checksExit: 0,
    };
    const github = fakeGithub(fixture, provider);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterMerge: () => {
            throw Object.assign(new Error("lost merge response"), {
              code: "TEST_AFTER_MERGE",
            });
          },
        },
      )), "TEST_AFTER_MERGE");
      expect(github.mergeCalls()).toBe(1);
      const checksBeforeRetry = github.argv().filter(
        (args) => args[0] === "pr" && args[1] === "checks",
      ).length;
      provider.permission = "READ";
      provider.squashMergeAllowed = false;
      provider.checksExit = 1;
      const pending = json(runCli(
        ["status", "--goal", "demo", "--task", "TASK-A", "--json"],
        fixture.root,
        fixture.controlDir,
      )) as { pending_operations?: Array<Record<string, unknown>> };
      expect(pending.pending_operations).toEqual([
        expect.objectContaining({
          kind: "GITHUB_MERGE",
          operation_id: "merge-task-a-stable",
          retry: expect.objectContaining({
            command: "merge-pr",
            request: "EXACT_WITH_ORIGINAL_FOREMAN_CAPABILITY",
          }),
        }),
      ]);
      const doctor = runCli(
        ["doctor", "--goal", "demo", "--json"],
        fixture.root,
        fixture.controlDir,
      );
      expect(doctor.code).toBe(1);
      expect(JSON.stringify(json(doctor))).toContain("GITHUB_MERGE");
      const recovered = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      ));
      expect(recovered).toMatchObject({ accepted: true });
      expect(github.mergeCalls()).toBe(1);
      expect(github.argv().filter(
        (args) => args[0] === "pr" && args[1] === "checks",
      )).toHaveLength(checksBeforeRetry);
      expect(taskStatus(fixture).phase).toBe("MERGED_TO_MAIN");
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("exact-retries a transaction-owned isolated merge object fetch and removes its stable owner", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture, { remoteOnlyMergeCommit: true });
    const options = canonicalMergeOptions(fixture);
    const fetchRoot = path.join(
      fixture.controlDir,
      "github-merge-object-fetch",
    );
    try {
      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          {
            ...github.dependencies,
            afterMergeFetchOwner: () => {
              throw Object.assign(new Error("lost after stable fetch owner"), {
                code: "TEST_AFTER_MERGE_FETCH_OWNER",
              });
            },
          },
        )),
        "TEST_AFTER_MERGE_FETCH_OWNER",
      );
      expect(readdirSync(fetchRoot).sort()).toEqual([
        expect.stringMatching(/^[0-9a-f]{64}\.objects$/),
        expect.stringMatching(/^[0-9a-f]{64}\.owner\.json$/),
      ]);

      const recovered = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      ));

      expect(recovered).toMatchObject({ accepted: true });
      expect(github.mergeCalls()).toBe(1);
      expect(readdirSync(fetchRoot)).toEqual([]);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("preserves a foreign directory substituted for a stale merge fetch directory", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture, { remoteOnlyMergeCommit: true });
    const options = canonicalMergeOptions(fixture);
    const fetchRoot = path.join(
      fixture.controlDir,
      "github-merge-object-fetch",
    );
    try {
      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          {
            ...github.dependencies,
            afterMergeFetchOwner: () => {
              throw Object.assign(new Error("lost after stable fetch owner"), {
                code: "TEST_AFTER_MERGE_FETCH_OWNER",
              });
            },
          },
        )),
        "TEST_AFTER_MERGE_FETCH_OWNER",
      );
      const objectsName = readdirSync(fetchRoot).find(
        (name) => name.endsWith(".objects"),
      );
      expect(objectsName).toBeDefined();
      const objects = path.join(fetchRoot, objectsName!);
      renameSync(objects, `${objects}.retained`);
      const foreign = path.join(fixture.root, "foreign-fetch-tree");
      mkdirSync(foreign);
      writeFileSync(path.join(foreign, "must-survive.txt"), "foreign\n");
      renameSync(foreign, objects);

      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        )),
        "MERGE_GIT_EVIDENCE_OWNER_INVALID",
      );
      expect(readFileSync(
        path.join(objects, "must-survive.txt"),
        "utf8",
      )).toBe("foreign\n");
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("recovers an exact merge fetch cleanup quarantine after interruption", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture, { remoteOnlyMergeCommit: true });
    const options = canonicalMergeOptions(fixture);
    const fetchRoot = path.join(
      fixture.controlDir,
      "github-merge-object-fetch",
    );
    try {
      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          {
            ...github.dependencies,
            afterMergeFetchOwner: () => {
              throw Object.assign(new Error("lost after stable fetch owner"), {
                code: "TEST_AFTER_MERGE_FETCH_OWNER",
              });
            },
          },
        )),
        "TEST_AFTER_MERGE_FETCH_OWNER",
      );
      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          {
            ...github.dependencies,
            afterMergeFetchCleanupRename: () => {
              throw Object.assign(new Error("lost after cleanup rename"), {
                code: "TEST_AFTER_MERGE_FETCH_CLEANUP_RENAME",
              });
            },
          },
        )),
        "TEST_AFTER_MERGE_FETCH_CLEANUP_RENAME",
      );
      expect(readdirSync(fetchRoot)).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/^[0-9a-f]{64}\.cleanup$/),
          expect.stringMatching(/^[0-9a-f]{64}\.owner\.json$/),
        ]),
      );

      const recovered = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      ));
      expect(recovered).toMatchObject({ accepted: true });
      expect(readdirSync(fetchRoot)).toEqual([]);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it.each([
    "beforeMergeObjectPromotion",
    "afterMergeObjectPromotionFetch",
    "afterMergeObjectPromotion",
  ])(
    "replays exact shared merge-object promotion after %s",
    (faultName) => {
      prepareReadyForCanonicalMerge(fixture);
      const github = fakeGithub(
        fixture,
        { remoteOnlyMergeCommit: true },
      );
      const options = canonicalMergeOptions(fixture);
      try {
        expectDirectControlError(
          () => withDirectControl(fixture, () => mergePullRequest(
            fixture.root,
            options,
            {
              ...github.dependencies,
              [faultName]: () => {
                throw Object.assign(
                  new Error(`lost at ${faultName}`),
                  { code: `TEST_${faultName.toUpperCase()}` },
                );
              },
            },
          )),
          `TEST_${faultName.toUpperCase()}`,
        );
        const recovered = withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        ));
        expect(recovered).toMatchObject({ accepted: true });
        expect(github.mergeCalls()).toBe(1);
      } finally {
        rmSync(github.remote, { recursive: true, force: true });
      }
    },
  );

  it.each(["afterIntent", "afterInvocation", "afterReceipt", "afterEvent"])(
    "exact-retries the canonical merge after the %s crash boundary",
    (faultName) => {
      prepareReadyForCanonicalMerge(fixture);
      const github = fakeGithub(fixture);
      const options = canonicalMergeOptions(fixture);
      try {
        expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          {
            ...github.dependencies,
            [faultName]: () => {
              throw Object.assign(new Error(`fault ${faultName}`), {
                code: `TEST_${faultName.toUpperCase()}`,
              });
            },
          },
        )), `TEST_${faultName.toUpperCase()}`);
        const recovered = withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        ));
        expect(recovered).toMatchObject({
          accepted: true,
          idempotent: faultName === "afterEvent",
        });
        expect(github.mergeCalls()).toBe(1);
        expect(taskStatus(fixture).phase).toBe("MERGED_TO_MAIN");
      } finally {
        rmSync(github.remote, { recursive: true, force: true });
      }
    },
  );

  it("fails GitHub permission and PR contract preflight before any merge invocation", () => {
    prepareReadyForCanonicalMerge(fixture);
    const denied = fakeGithub(fixture, { permission: "READ" });
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        canonicalMergeOptions(fixture),
        denied.dependencies,
      )), "GH_REPOSITORY_ACCESS_DENIED");
      expect(denied.mergeCalls()).toBe(0);
      const status = json(runCli(
        ["status", "--goal", "demo", "--json"],
        fixture.root,
        fixture.controlDir,
      )) as { pending_operations?: unknown[] };
      expect(status.pending_operations).toEqual([]);
    } finally {
      rmSync(denied.remote, { recursive: true, force: true });
    }
  });

  it("repairs an odd writer generation and promotes the one exact 0600 atomic temp", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterIntent: () => {
            throw Object.assign(new Error("intent response lost"), {
              code: "TEST_AFTER_INTENT",
            });
          },
        },
      )), "TEST_AFTER_INTENT");
      const intent = mergeIntentFile(fixture);
      const temporary = mergeAtomicTemp(intent);
      renameSync(intent, temporary);
      const pending = json(runCli(
        ["status", "--goal", "demo", "--task", "TASK-A", "--json"],
        fixture.root,
        fixture.controlDir,
      )) as { pending_operations?: Array<Record<string, unknown>> };
      expect(pending.pending_operations).toEqual([
        expect.objectContaining({
          operation_id: "merge-task-a-stable",
          retry: expect.objectContaining({
            stage: "RECOVERY_CHECKPOINT_REQUIRED",
          }),
        }),
      ]);
      sigkillMergeTransactionAfterGeneration(fixture, options);

      const recovered = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      ));
      expect(recovered).toMatchObject({ accepted: true });
      expect(existsSync(temporary)).toBe(false);
      expect(existsSync(intent)).toBe(true);
      const generation = JSON.parse(readFileSync(
        path.join(fixture.controlDir, ".generation.json"),
        "utf8",
      )) as { generation: number };
      expect(generation.generation % 2).toBe(0);
      expect(github.mergeCalls()).toBe(1);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it.each([
    ["foreign", "MERGE_RECOVERY_SCOPE_CONFLICT"],
    ["multiple", "CORRUPT_STORE"],
    ["weak-mode", "CORRUPT_STORE"],
  ])("fails closed on %s merge atomic temp state", (shape, expectedCode) => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterIntent: () => {
            throw Object.assign(new Error("intent response lost"), {
              code: "TEST_AFTER_INTENT",
            });
          },
        },
      )), "TEST_AFTER_INTENT");
      const intent = mergeIntentFile(fixture);
      const body = readFileSync(intent);
      if (shape === "foreign") {
        const foreign = mergeIntentFile(fixture, "foreign-event");
        const temporary = mergeAtomicTemp(foreign, "b".repeat(24));
        writeFileSync(temporary, body, { mode: 0o600 });
        chmodSync(temporary, 0o600);
      } else {
        const first = mergeAtomicTemp(intent, "c".repeat(24));
        writeFileSync(first, body, { mode: shape === "weak-mode" ? 0o644 : 0o600 });
        chmodSync(first, shape === "weak-mode" ? 0o644 : 0o600);
        if (shape === "multiple") {
          const second = mergeAtomicTemp(intent, "d".repeat(24));
          writeFileSync(second, body, { mode: 0o600 });
          chmodSync(second, 0o600);
        }
      }
      const generationFile = path.join(fixture.controlDir, ".generation.json");
      const generationBefore = readFileSync(generationFile, "utf8");
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      )), expectedCode);
      expect(readFileSync(generationFile, "utf8")).toBe(generationBefore);
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("does not unlink a canonical temp before exact FOREMAN authorization", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterIntent: () => {
            throw Object.assign(new Error("intent response lost"), {
              code: "TEST_AFTER_INTENT",
            });
          },
        },
      )), "TEST_AFTER_INTENT");
      const intent = mergeIntentFile(fixture);
      const temporary = mergeAtomicTemp(intent, "e".repeat(24));
      writeFileSync(temporary, readFileSync(intent), { mode: 0o600 });
      chmodSync(temporary, 0o600);
      const wrongOptions = {
        ...options,
        actorCapabilityFile: fixture.capabilities["TASK-A"].CAPTAIN,
      };
      const generationFile = path.join(fixture.controlDir, ".generation.json");
      const generationBefore = readFileSync(generationFile, "utf8");
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        wrongOptions,
        github.dependencies,
      )), "CAPABILITY_INVALID");
      expect(readFileSync(generationFile, "utf8")).toBe(generationBefore);
      expect(existsSync(temporary)).toBe(true);
      expect(existsSync(intent)).toBe(true);
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("rejects a Goal-wide event-id conflict before GitHub mutation", () => {
    enableGithubMergePolicy(fixture);
    withInProcessGoalCliFixtureSetup(() => {
      initAndRegister(fixture);
      const conflict = runCli([
        "register-role",
        "--goal", "demo",
        "--task", "TASK-B",
        "--role", "FOREMAN",
        "--thread", THREADS.FOREMAN,
        "--host", "local",
        "--attempt", "1",
        "--event-id", "merge-task-a-stable",
        "--authorizer-capability-file",
        fixture.capabilities["TASK-A"].FOREMAN as string,
        "--json",
      ], fixture.root, fixture.controlDir);
      expect(conflict.code).toBe(0);
      const book = sequences();
      advanceToReadyForCanonicalMerge(fixture, book);
    });
    const github = fakeGithub(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        canonicalMergeOptions(fixture),
        github.dependencies,
      )), "EVENT_ID_CONFLICT");
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("rejects non-descendant candidates and a moved base before GitHub mutation", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      const replacement = git(
        fixture.root,
        "commit-tree",
        `${fixture.fullHead}^{tree}`,
        "-m",
        "unrelated replacement",
      );
      git(fixture.root, "replace", fixture.fullHead, replacement);
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      )), "CANDIDATE_LINEAGE_MISMATCH");
      expect(github.mergeCalls()).toBe(0);
      git(fixture.root, "replace", "-d", fixture.fullHead);

      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterIntent: () => {
            throw Object.assign(new Error("intent response lost"), {
              code: "TEST_AFTER_INTENT",
            });
          },
        },
      )), "TEST_AFTER_INTENT");
      const movedBase = git(
        fixture.root,
        "commit-tree",
        `${fixture.baseHead}^{tree}`,
        "-p",
        fixture.baseHead,
        "-m",
        "concurrent base update",
      );
      git(
        fixture.root,
        "push",
        "-q",
        github.remote,
        `${movedBase}:refs/heads/main`,
      );
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      )), "BASE_HEAD_CHANGED");
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("preserves a valid sealed atomic temp that belongs to another request", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterIntent: () => {
            throw Object.assign(new Error("intent response lost"), {
              code: "TEST_AFTER_INTENT",
            });
          },
        },
      )), "TEST_AFTER_INTENT");
      const intentFile = mergeIntentFile(fixture);
      const intent = JSON.parse(readFileSync(intentFile, "utf8")) as Record<string, unknown>;
      const foreignRequest = {
        ...(intent.request as Record<string, unknown>),
        expected_state_revision:
          Number((intent.request as Record<string, unknown>).expected_state_revision) + 99,
      };
      const foreign = resealRecord({
        ...intent,
        request: foreignRequest,
        request_sha256: sha256(JSON.stringify(canonicalize(foreignRequest))),
      }, "intent_sha256");
      const temporary = mergeAtomicTemp(intentFile, "f".repeat(24));
      const body = `${JSON.stringify(foreign, null, 2)}\n`;
      writeFileSync(temporary, body, { mode: 0o600 });
      chmodSync(temporary, 0o600);
      sigkillMergeTransactionAfterGeneration(fixture, options);
      const generationFile = path.join(fixture.controlDir, ".generation.json");
      const generationBefore = readFileSync(generationFile, "utf8");

      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      )), "PREPARED_REQUEST_MISMATCH");
      expect(readFileSync(temporary, "utf8")).toBe(body);
      expect(readFileSync(generationFile, "utf8")).toBe(generationBefore);
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("cleans a zero-byte unpublished temp only after exact authorization", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterIntent: () => {
            throw Object.assign(new Error("intent response lost"), {
              code: "TEST_AFTER_INTENT",
            });
          },
        },
      )), "TEST_AFTER_INTENT");
      const invocation = mergeArtifactFile(fixture, "invocation");
      mkdirSync(path.dirname(invocation), { recursive: true, mode: 0o700 });
      chmodSync(path.dirname(invocation), 0o700);
      const temporary = mergeAtomicTemp(invocation, "0".repeat(24));
      writeFileSync(temporary, "", { mode: 0o600 });
      chmodSync(temporary, 0o600);

      const recovered = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      ));
      expect(recovered).toMatchObject({ accepted: true });
      expect(existsSync(temporary)).toBe(false);
      expect(github.mergeCalls()).toBe(1);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("pristine-recovers a real SIGKILL after generation and creates the reservation exactly once", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      sigkillFreshMergeAfterGeneration(fixture, options);
      expect(existsSync(mergeIntentFile(fixture))).toBe(false);

      const recovered = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      ));

      expect(recovered).toMatchObject({
        accepted: true,
        idempotent: false,
      });
      const reservationEvents = readdirSync(path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "events",
        "TASK-A",
      ))
        .map((name) => JSON.parse(readFileSync(path.join(
          fixture.controlDir,
          "goals",
          "demo",
          "events",
          "TASK-A",
          name,
        ), "utf8")))
        .filter((event) => event.type === "GITHUB_MERGE_RESERVED");
      expect(reservationEvents).toHaveLength(1);
      expect(github.mergeCalls()).toBe(1);
      expect(taskStatus(fixture).phase).toBe("MERGED_TO_MAIN");
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it.each([
    ["wrong request", "request", "STALE_STATE_REVISION"],
    ["wrong transaction key", "key", "STORE_TRANSACTION_MISMATCH"],
    ["wrong FOREMAN capability", "capability", "CAPABILITY_INVALID"],
  ] as const)(
    "keeps pristine-odd control byte-zero for %s",
    (_label, shape, expectedCode) => {
      prepareReadyForCanonicalMerge(fixture);
      const github = fakeGithub(fixture);
      const options = canonicalMergeOptions(fixture);
      const wrong = {
        ...options,
        ...(shape === "request"
          ? {
            expectedStateRevision:
              Number(options.expectedStateRevision) + 1,
          }
          : {}),
        ...(shape === "key"
          ? { eventId: "merge-task-a-other" }
          : {}),
        ...(shape === "capability"
          ? {
            actorCapabilityFile:
              fixture.capabilities["TASK-A"].CAPTAIN,
          }
          : {}),
      };
      try {
        sigkillFreshMergeAfterGeneration(fixture, options);

        // The first rejected caller may reap the dead writer lock. Once that
        // transport normalization is complete, the same invalid retry must be
        // byte-zero across the entire control root.
        expectDirectControlError(
          () => withDirectControl(fixture, () => mergePullRequest(
            fixture.root,
            wrong,
            github.dependencies,
          )),
          expectedCode,
        );
        const before = controlTreeSnapshot(fixture.controlDir);
        expectDirectControlError(
          () => withDirectControl(fixture, () => mergePullRequest(
            fixture.root,
            wrong,
            github.dependencies,
          )),
          expectedCode,
        );
        expect(controlTreeSnapshot(fixture.controlDir)).toEqual(before);
        expect(github.mergeCalls()).toBe(0);

        const recovered = withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        ));
        expect(recovered).toMatchObject({ accepted: true });
        expect(github.mergeCalls()).toBe(1);
      } finally {
        rmSync(github.remote, { recursive: true, force: true });
      }
    },
  );

  it("rejects pristine recovery after payload-vector drift without changing another byte", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      sigkillFreshMergeAfterGeneration(fixture, options);
      writeFileSync(
        path.join(fixture.controlDir, "vector-drift-marker"),
        "foreign control payload\n",
        { mode: 0o600 },
      );
      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        )),
        "STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH",
      );
      const before = controlTreeSnapshot(fixture.controlDir);
      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        )),
        "STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH",
      );
      expect(controlTreeSnapshot(fixture.controlDir)).toEqual(before);
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("keeps a fresh v2 odd generation witness-only", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      sigkillFreshMergeAfterGeneration(fixture, options);
      downgradeOddGenerationToV2(fixture);
      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        )),
        "STORE_PRISTINE_RECOVERY_UNAVAILABLE",
      );
      const before = controlTreeSnapshot(fixture.controlDir);
      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        )),
        "STORE_PRISTINE_RECOVERY_UNAVAILABLE",
      );
      expect(controlTreeSnapshot(fixture.controlDir)).toEqual(before);
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("still recovers a v2 odd generation from a durable merge witness", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          {
            ...github.dependencies,
            afterIntent: () => {
              throw Object.assign(new Error("intent response lost"), {
                code: "TEST_AFTER_INTENT",
              });
            },
          },
        )),
        "TEST_AFTER_INTENT",
      );
      sigkillMergeTransactionAfterGeneration(fixture, options);
      downgradeOddGenerationToV2(fixture);

      const recovered = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      ));

      expect(recovered).toMatchObject({ accepted: true });
      expect(github.mergeCalls()).toBe(1);
      expect(taskStatus(fixture).phase).toBe("MERGED_TO_MAIN");
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("routes an unbound zero-byte initial intent temp through strict fresh retry", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      const intent = mergeArtifactFile(fixture, "intent");
      mkdirSync(path.dirname(intent), { recursive: true, mode: 0o700 });
      chmodSync(path.dirname(intent), 0o700);
      const temporary = mergeAtomicTemp(intent, "1".repeat(24));
      writeFileSync(temporary, "", { mode: 0o600 });
      chmodSync(temporary, 0o600);
      const recovered = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      ));

      expect(recovered).toMatchObject({ accepted: true });
      expect(existsSync(temporary)).toBe(false);
      expect(github.mergeCalls()).toBe(1);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("pristine-recovers an exact request-bound partial initial intent temp after SIGKILL", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      const request = {
        schema_version: 1,
        kind: "GITHUB_MERGE_REQUEST",
        goal_id: options.goalId,
        task_id: options.taskId,
        event_id: options.eventId,
        foreman_thread_id: options.threadId,
        expected_state_revision: Number(options.expectedStateRevision),
        expected_control_epoch: Number(options.expectedControlEpoch),
      };
      const header = JSON.stringify({
        schema_version: 1,
        kind: "GITHUB_MERGE_INTENT",
        goal_id: request.goal_id,
        task_id: request.task_id,
        event_id: request.event_id,
        request,
        request_sha256: sha256(JSON.stringify(canonicalize(request))),
      }, null, 2);
      const partial = `${header.slice(0, -2)},\n  "task_anchor": {`;
      const intent = mergeArtifactFile(fixture, "intent");
      mkdirSync(path.dirname(intent), { recursive: true, mode: 0o700 });
      chmodSync(path.dirname(intent), 0o700);
      const temporary = mergeAtomicTemp(intent, "2".repeat(24));
      writeFileSync(temporary, partial, { mode: 0o600 });
      chmodSync(temporary, 0o600);
      sigkillMergeTransactionAfterGeneration(fixture, options);

      const recovered = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      ));

      expect(recovered).toMatchObject({ accepted: true });
      expect(existsSync(temporary)).toBe(false);
      expect(github.mergeCalls()).toBe(1);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("preserves a non-prefix initial intent temp and fails closed", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      const intent = mergeArtifactFile(fixture, "intent");
      mkdirSync(path.dirname(intent), { recursive: true, mode: 0o700 });
      chmodSync(path.dirname(intent), 0o700);
      const temporary = mergeAtomicTemp(intent, "3".repeat(24));
      const body = "{\"foreign\":true";
      writeFileSync(temporary, body, { mode: 0o600 });
      chmodSync(temporary, 0o600);
      const before = controlTreeSnapshot(fixture.controlDir);

      expectDirectControlError(
        () => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        )),
        "MERGE_RECOVERY_WITNESS_REQUIRED",
      );

      expect(readFileSync(temporary, "utf8")).toBe(body);
      expect(controlTreeSnapshot(fixture.controlDir)).toEqual(before);
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("recovers OPEN and MERGED states from the append-only reservation after all sidebands are lost", () => {
    for (const providerState of ["OPEN", "MERGED"] as const) {
      if (providerState === "MERGED") {
        rmSync(fixture.root, { recursive: true, force: true });
        rmSync(fixture.controlDir, { recursive: true, force: true });
        fixture = makeGoalRepo();
      }
      prepareReadyForCanonicalMerge(fixture);
      const github = fakeGithub(fixture);
      const options = canonicalMergeOptions(fixture);
      try {
        const faultName = providerState === "OPEN" ? "afterIntent" : "afterMerge";
        expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          {
            ...github.dependencies,
            [faultName]: () => {
              throw Object.assign(new Error(`lost at ${faultName}`), {
                code: `TEST_${faultName.toUpperCase()}`,
              });
            },
          },
        )), `TEST_${faultName.toUpperCase()}`);
        removeMergeSidebands(fixture);

        const recovered = withDirectControl(fixture, () => mergePullRequest(
          fixture.root,
          options,
          github.dependencies,
        ));
        expect(recovered).toMatchObject({ accepted: true });
        expect(github.mergeCalls()).toBe(1);
        expect(taskStatus(fixture).phase).toBe("MERGED_TO_MAIN");
      } finally {
        rmSync(github.remote, { recursive: true, force: true });
      }
    }
  });

  it("blocks raw reservation replay and cross-task reuse of its reserved target id", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterIntent: () => {
            throw Object.assign(new Error("intent response lost"), {
              code: "TEST_AFTER_INTENT",
            });
          },
        },
      )), "TEST_AFTER_INTENT");
      const eventDirectory = path.join(
        fixture.controlDir,
        "goals",
        "demo",
        "events",
        "TASK-A",
      );
      const acceptedReservation = readdirSync(eventDirectory)
        .map((name) => JSON.parse(readFileSync(path.join(eventDirectory, name), "utf8")))
        .find((event) => event.type === "GITHUB_MERGE_RESERVED") as Record<string, unknown>;
      const rawReservation = Object.fromEntries(
        [
          "schema_version", "event_id", "goal_id", "task_id", "type",
          "actor", "actor_sequence", "expected_state_revision",
          "control_epoch", "packet", "base_head", "full_head", "payload",
        ].map((key) => [key, acceptedReservation[key]]),
      );
      expectControlError(
        submitEvent(fixture, rawReservation),
        "GITHUB_MERGE_WRAPPER_REQUIRED",
      );
      const conflict = runCli([
        "register-role",
        "--goal", "demo",
        "--task", "TASK-B",
        "--role", "FOREMAN",
        "--thread", THREADS.FOREMAN,
        "--host", "local",
        "--attempt", "1",
        "--event-id", "merge-task-a-stable",
        "--authorizer-capability-file",
        fixture.capabilities["TASK-A"].FOREMAN as string,
        "--json",
      ], fixture.root, fixture.controlDir);
      expect(conflict.code).not.toBe(0);
      expect(`${conflict.stdout}\n${conflict.stderr}`).toContain("EVENT_ID_RESERVED");
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("rejects a dirty exact retry before any GitHub merge dispatch", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterIntent: () => {
            throw Object.assign(new Error("intent response lost"), {
              code: "TEST_AFTER_INTENT",
            });
          },
        },
      )), "TEST_AFTER_INTENT");
      writeFileSync(path.join(fixture.root, "dirty-after-intent.txt"), "dirty\n");
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      )), "DIRTY_WORKTREE");
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it.each([
    ["invocation", "afterInvocation"],
    ["receipt", "afterReceipt"],
  ] as const)("rejects recomputed seals when %s cross-bindings are tampered", (
    stage,
    faultName,
  ) => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          [faultName]: () => {
            throw Object.assign(new Error(`fault ${faultName}`), {
              code: `TEST_${faultName.toUpperCase()}`,
            });
          },
        },
      )), `TEST_${faultName.toUpperCase()}`);
      const file = mergeArtifactFile(fixture, stage);
      const record = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
      const sealKey = stage === "invocation" ? "invocation_sha256" : "receipt_sha256";
      const tampered = stage === "invocation"
        ? {
          ...record,
          command: {
            ...(record.command as Record<string, unknown>),
            argv: ["pr", "merge", "999", "--admin"],
            argv_sha256: sha256(JSON.stringify(canonicalize(
              ["pr", "merge", "999", "--admin"],
            ))),
          },
        }
        : {
          ...record,
          result: {
            ...(record.result as Record<string, unknown>),
            parent_sha: fixture.fullHead,
          },
        };
      writeFileSync(
        file,
        `${JSON.stringify(resealRecord(tampered, sealKey), null, 2)}\n`,
      );
      chmodSync(file, 0o600);

      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      )), "CORRUPT_STORE");
      expect(github.mergeCalls()).toBe(stage === "receipt" ? 1 : 0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });

  it("revalidates the sealed gh executable identity before an OPEN retry dispatch", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    const alternateDirectory = mkdtempSync(path.join(tmpdir(), "goalctl-fake-gh-"));
    const alternateGh = path.join(alternateDirectory, "gh");
    writeFileSync(alternateGh, "#!/bin/sh\nexit 99\n", { mode: 0o755 });
    chmodSync(alternateGh, 0o755);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterInvocation: () => {
            throw Object.assign(new Error("invocation response lost"), {
              code: "TEST_AFTER_INVOCATION",
            });
          },
        },
      )), "TEST_AFTER_INVOCATION");
      expect(github.mergeCalls()).toBe(0);

      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          resolveExecutable: () => ({
            executable: alternateGh,
            path_dir: alternateDirectory,
          }),
        },
      )), "GH_EXECUTABLE_CHANGED");
      expect(github.mergeCalls()).toBe(0);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
      rmSync(alternateDirectory, { recursive: true, force: true });
    }
  });

  it("uses a fixed trusted git executable for all merge evidence despite a PATH spoof", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    const spoofDirectory = mkdtempSync(path.join(tmpdir(), "goalctl-path-git-"));
    const spoofGit = path.join(spoofDirectory, "git");
    writeFileSync(
      spoofGit,
      "#!/bin/sh\nexec /usr/bin/git \"$@\"\n",
      { mode: 0o755 },
    );
    chmodSync(spoofGit, 0o755);
    const wrapperGitExecutables: string[] = [];
    const wrapperGitArgv: string[][] = [];
    const previousPath = process.env.PATH;
    process.env.PATH = `${spoofDirectory}:${previousPath ?? ""}`;
    try {
      const result = withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          gitRunner: (
            executable: string,
            args: string[],
            runnerOptions: Parameters<typeof spawnSync>[2],
          ) => {
            wrapperGitExecutables.push(executable);
            wrapperGitArgv.push([...args]);
            return spawnSync(executable, args, runnerOptions);
          },
        },
      ));
      expect(result).toMatchObject({ accepted: true });
      expect(wrapperGitExecutables.length).toBeGreaterThan(0);
      expect(wrapperGitExecutables.every((executable) => (
        path.isAbsolute(executable) && executable !== spoofGit
      ))).toBe(true);
      expect(wrapperGitArgv.some((args) => args[0] === "rev-list")).toBe(true);
      expect(wrapperGitArgv.some((args) => args[0] === "diff")).toBe(true);
      expect(wrapperGitArgv.some((args) => (
        args.some((arg) => arg.includes("refs/remotes/"))
          && args.includes("fetch")
      ))).toBe(false);
      expect(github.mergeCalls()).toBe(1);
    } finally {
      if (previousPath === undefined) delete process.env.PATH;
      else process.env.PATH = previousPath;
      rmSync(github.remote, { recursive: true, force: true });
      rmSync(spoofDirectory, { recursive: true, force: true });
    }
  });

  it("rejects sealed receipt provider metadata that differs from the current observation", () => {
    prepareReadyForCanonicalMerge(fixture);
    const github = fakeGithub(fixture);
    const options = canonicalMergeOptions(fixture);
    try {
      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        {
          ...github.dependencies,
          afterReceipt: () => {
            throw Object.assign(new Error("receipt response lost"), {
              code: "TEST_AFTER_RECEIPT",
            });
          },
        },
      )), "TEST_AFTER_RECEIPT");
      const file = mergeArtifactFile(fixture, "receipt");
      const receipt = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
      const tampered = resealRecord({
        ...receipt,
        pull_request: {
          ...(receipt.pull_request as Record<string, unknown>),
          merged_by: "different-provider-actor",
        },
      }, "receipt_sha256");
      writeFileSync(file, `${JSON.stringify(tampered, null, 2)}\n`);
      chmodSync(file, 0o600);

      expectDirectControlError(() => withDirectControl(fixture, () => mergePullRequest(
        fixture.root,
        options,
        github.dependencies,
      )), "MERGE_RECEIPT_MISMATCH");
      expect(github.mergeCalls()).toBe(1);
    } finally {
      rmSync(github.remote, { recursive: true, force: true });
    }
  });
});
