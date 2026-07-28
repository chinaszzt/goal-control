import { execFileSync, spawn } from "child_process";
import { createHash, randomUUID } from "crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";
import { createRequire } from "module";
import { once } from "events";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const RESOURCECTL = path.join(ROOT, "scripts", "resourcectl.js");
const nodeRequire = createRequire(import.meta.url);
const { hashObject } = nodeRequire("../scripts/goal-control/util.js") as {
  hashObject: (value: unknown) => string;
};
const {
  classifyLaunchIdentityHold,
  collectLegacyIdentityIncident,
  createLegacyIdentityIncidentCollector,
  sealLegacyIdentityIncidentReceipt,
} = nodeRequire(
  "../scripts/goal-control/launch-source-checkpoint.js",
) as {
  classifyLaunchIdentityHold: (
    root: string,
    state: Record<string, unknown>,
    goalId: string,
  ) => "SOURCE_ONLY" | "RUNTIME_IDENTITY" | "UNKNOWN";
  createLegacyIdentityIncidentCollector: () => {
    incidents: Map<string, unknown>;
    sources: Map<string, string>;
    skippedSemanticHolds: Set<string>;
  };
  collectLegacyIdentityIncident: (
    root: string,
    collector: {
      incidents: Map<string, unknown>;
      sources: Map<string, string>;
      skippedSemanticHolds: Set<string>;
    },
    state: Record<string, unknown>,
    goalId: string,
    event: Record<string, unknown>,
    evidence: Record<string, unknown>,
  ) => void;
  sealLegacyIdentityIncidentReceipt: (
    collector: {
      incidents: Map<string, unknown>;
      sources: Map<string, string>;
      skippedSemanticHolds: Set<string>;
    },
    options: {
      controllerDecoderSha256: string;
      sourceStateVectorSha256: string;
      predecessorProtocolSealSha256: string | null;
      incidentRef: string;
      oldControllerDrainAck: string;
    },
  ) => {
    incident_count: number;
    migration_artifact: {
      relative_path: string;
      body: Buffer;
    };
  };
};
const { adoptStoreProtocol } = nodeRequire("../scripts/goal-control/migration.js") as {
  adoptStoreProtocol: (
    cwd: string,
    options: {
      incidentRef?: string;
      oldControllerDrainAcknowledgment?: string;
      goalWorktreesFile?: string | null;
    },
    hooks?: { afterReplay?: (context: { root: string }) => void },
  ) => Record<string, unknown>;
};
const { revalidateSourceCheckpointHold } = nodeRequire(
  "../scripts/goal-control/usability.js",
) as {
  revalidateSourceCheckpointHold: (
    cwd: string,
    options: {
      goalId: string;
      taskId: string;
      threadId: string;
      operationId: string;
      holdId: string;
      expectedHoldEventId: string;
      expectedCanonicalLaunchSha256: string;
      expectedCandidateHead: string;
      actorCapabilityFile: string;
    },
    dependencies?: {
      beforeFinalInspection?: () => void;
      inspectSourceCheckpointHold?: (...args: unknown[]) => Record<string, unknown>;
    },
  ) => Record<string, unknown>;
};
const { acceptEvent, inspectSourceCheckpointHold } = nodeRequire(
  "../scripts/goal-control/goal.js",
) as {
  acceptEvent: (
    cwd: string,
    event: Record<string, unknown>,
    actorCapabilityFile: string,
    authorization?: {
      runtimeRotationOperation?: boolean;
      pristineEventAcceptedAt?: string;
    },
  ) => Record<string, unknown>;
  inspectSourceCheckpointHold: (
    ...args: unknown[]
  ) => Record<string, unknown>;
};
const { loadGoalStateUnlocked } = nodeRequire(
  "../scripts/goal-control/goal.js",
) as {
  loadGoalStateUnlocked: (
    root: string,
    goalId: string,
    options?: Record<string, unknown>,
  ) => {
    snapshot: { tasks: Record<string, unknown> };
  };
};

type CliResult = { code: number; stdout: string; stderr: string };
type Role = "FOREMAN" | "CAPTAIN" | "DEV";

type Fixture = {
  root: string;
  controlDir: string;
  baseHead: string;
  outputDir: string;
  manifest: string;
  planPath: string;
  contextPath: string;
  planHash: string;
  contextHash: string;
  capabilities: Partial<Record<Role, string>>;
  bootstrapCapability?: string;
  taskNonce?: string;
};

const THREADS: Record<Role, string> = {
  FOREMAN: "foreman-usability-1",
  CAPTAIN: "captain-usability-1",
  DEV: "dev-usability-1",
};

const fixtures: Fixture[] = [];

function runCli(args: string[], cwd: string, controlDir: string): CliResult {
  return runProgram(GOALCTL, args, cwd, controlDir);
}

function runProgram(program: string, args: string[], cwd: string, controlDir: string): CliResult {
  try {
    const stdout = execFileSync("node", [program, ...args], {
      cwd,
      encoding: "utf8",
      stdio: "pipe",
      env: {
        ...process.env,
        GOAL_CONTROL_DIR: controlDir,
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
}

function chmodTree(root: string, directoryMode: number, fileMode: number): void {
  const stat = lstatSync(root);
  const pathSegments = root.split(path.sep);
  const privateAuthorityTree = [
    ".atomic-transactions",
    ".protocol-rotations.v1",
  ].some((segment) => pathSegments.includes(segment));
  if (!stat.isDirectory()) {
    if (!stat.isSymbolicLink()) {
      const privateAuthority = root.endsWith(".cap")
        || path.basename(root) === ".store-protocol.json"
        || privateAuthorityTree;
      chmodSync(root, privateAuthority ? 0o600 : fileMode);
    }
    return;
  }
  const effectiveDirectoryMode = privateAuthorityTree
    ? 0o700
    : directoryMode;
  if ((effectiveDirectoryMode & 0o200) !== 0) {
    chmodSync(root, effectiveDirectoryMode);
  }
  for (const entry of readdirSync(root)) {
    chmodTree(path.join(root, entry), directoryMode, fileMode);
  }
  chmodSync(root, effectiveDirectoryMode);
}

function snapshotTree(root: string): string {
  const entries: Array<Record<string, unknown>> = [];
  const walk = (current: string, relative: string): void => {
    const stat = lstatSync(current);
    const descriptor: Record<string, unknown> = {
      relative,
      mode: stat.mode & 0o777,
      kind: stat.isDirectory()
        ? "directory"
        : stat.isSymbolicLink()
          ? "symlink"
          : "file",
    };
    if (stat.isDirectory()) {
      entries.push(descriptor);
      for (const entry of readdirSync(current).sort()) {
        walk(path.join(current, entry), path.posix.join(relative, entry));
      }
      return;
    }
    descriptor.sha256 = sha256(readFileSync(current));
    entries.push(descriptor);
  };
  walk(root, ".");
  return JSON.stringify(entries);
}

function run(fixture: Fixture, args: string[]): CliResult {
  return runCli(args, fixture.root, fixture.controlDir);
}

function parse<T = Record<string, unknown>>(result: CliResult): T {
  expect(result.stdout).not.toBe("");
  return JSON.parse(result.stdout) as T;
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function writeJson(file: string, value: unknown): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function makeFixture(options: { incompletePacket?: boolean; mode?: "shadow" | "enforce" } = {}): Fixture {
  const root = mkdtempSync(path.join(tmpdir(), "goalctl-usability-repo-"));
  const controlDir = mkdtempSync(path.join(tmpdir(), "goalctl-usability-state-"));
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.email", "goalctl-usability@example.test");
  git(root, "config", "user.name", "Goal Control Usability Test");

  const protocolFiles = [
    "docs/planning/session-role-protocol.md",
    "docs/planning/session-protocol/shared.md",
    "docs/planning/session-protocol/foreman.md",
    "docs/planning/session-protocol/captain.md",
    "docs/planning/session-protocol/role-kernel.md",
  ];
  for (const file of protocolFiles) {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    writeFileSync(path.join(root, file), `# ${path.basename(file)}\n`);
  }
  const planPath = "docs/issues/4242/plan.md";
  const contextPath = "docs/issues/4242/context.md";
  const planBody = "# Plan\n\nApproved usability fixture.\n";
  const contextBody = "# Context\n\nFrozen usability fixture.\n";
  mkdirSync(path.join(root, "docs", "issues", "4242"), { recursive: true });
  writeFileSync(path.join(root, planPath), planBody);
  writeFileSync(path.join(root, contextPath), contextBody);
  writeFileSync(path.join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n");
  writeFileSync(path.join(root, "README.md"), "# usability fixture\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "base inputs");
  const baseHead = git(root, "rev-parse", "HEAD");
  git(root, "remote", "add", "origin", "https://github.com/example-org/example-repo.git");

  const sourceDir = path.join(root, "goal-inputs");
  mkdirSync(sourceDir, { recursive: true });
  writeFileSync(
    path.join(sourceDir, "TASK-A.md"),
    options.incompletePacket
      ? "# TASK-A\n\nGOALCTL:SCAFFOLD_INCOMPLETE\n"
      : "# TASK-A\n\nComplete immutable packet A.\n"
  );
  writeFileSync(path.join(sourceDir, "TASK-B.md"), "# TASK-B\n\nComplete immutable packet B.\n");
  writeJson(path.join(sourceDir, "spec.json"), {
    schema_version: 1,
    goal_id: "usability",
    title: "Goal control usability fixture",
    mode: options.mode ?? "shadow",
    repository: { name_with_owner: "example-org/example-repo", base_branch: "main" },
    base_head: baseHead,
    tasks: [
      {
        id: "TASK-A",
        title: "First task",
        issue: 4242,
        dependencies: [],
        integration_order: 1,
        parallel_group: "batch-1",
        risk_class: "STANDARD",
        packet_source: "goal-inputs/TASK-A.md",
        packet_revision: 1,
        expected_write_set: ["scripts/goal-control/**"],
        conflict_domains: ["goal-control"],
        resource_requirements: [],
      },
      {
        id: "TASK-B",
        title: "Second task",
        dependencies: ["TASK-A"],
        integration_order: 2,
        parallel_group: "batch-2",
        risk_class: "STANDARD",
        packet_source: "goal-inputs/TASK-B.md",
        packet_revision: 2,
        expected_write_set: ["docs/planning/**"],
        conflict_domains: ["goal-docs"],
        resource_requirements: [],
      },
    ],
  });

  const outputDir = "docs/planning/goals/usability";
  const fixture: Fixture = {
    root,
    controlDir,
    baseHead,
    outputDir,
    manifest: path.join(root, outputDir, "manifest.json"),
    planPath,
    contextPath,
    planHash: sha256(planBody),
    contextHash: sha256(contextBody),
    capabilities: {},
  };
  fixtures.push(fixture);
  return fixture;
}

function scaffold(fixture: Fixture, extra: string[] = []): CliResult {
  return run(fixture, [
    "scaffold",
    "--spec",
    "goal-inputs/spec.json",
    "--output-dir",
    fixture.outputDir,
    ...extra,
    "--json",
  ]);
}

function commitScaffold(fixture: Fixture): void {
  git(fixture.root, "add", "goal-inputs", fixture.outputDir);
  git(fixture.root, "commit", "-qm", "commit generated goal inputs");
}

function initialize(fixture: Fixture): Record<string, unknown> {
  const result = run(fixture, ["init", "--manifest", fixture.manifest, "--json"]);
  expect(result.code).toBe(0);
  const value = parse(result);
  fixture.bootstrapCapability = String(value.bootstrap_capability_file);
  return value;
}

function register(
  fixture: Fixture,
  role: Role,
  authorizerCapability?: string
): Record<string, unknown> {
  const authorization = role === "FOREMAN"
    ? ["--bootstrap-capability-file", fixture.bootstrapCapability as string]
    : ["--authorizer-capability-file", authorizerCapability as string];
  const launch = role === "DEV" ? ["--launch-id", "launch-dev-usability-1"] : [];
  const result = run(fixture, [
    "register-role",
    "--goal",
    "usability",
    "--task",
    "TASK-A",
    "--role",
    role,
    "--thread",
    THREADS[role],
    "--host",
    "local",
    "--attempt",
    "1",
    ...launch,
    ...authorization,
    "--json",
  ]);
  expect(result.code).toBe(0);
  const value = parse(result);
  fixture.capabilities[role] = String(value.actor_capability_file);
  if (role === "DEV") fixture.taskNonce = String(value.task_nonce);
  return value;
}

type TaskState = {
  state_revision: number;
  phase: string;
  control_epoch: number;
  base_head: string;
  full_head: string;
  packet: { revision: number; path: string; sha256: string };
};

function taskState(fixture: Fixture): TaskState {
  const result = run(fixture, [
    "status",
    "--goal",
    "usability",
    "--task",
    "TASK-A",
    "--json",
  ]);
  expect(result.code).toBe(0);
  return (parse(result) as { tasks: { "TASK-A": TaskState } }).tasks["TASK-A"];
}

function eventTemplate(
  fixture: Fixture,
  role: Role,
  type: string,
  options: { payload?: Record<string, unknown>; fullHead?: string; thread?: string; capability?: string } = {}
): CliResult {
  const args = [
    "event-template",
    "--goal",
    "usability",
    "--task",
    "TASK-A",
    "--role",
    role,
    "--thread",
    options.thread ?? THREADS[role],
    "--type",
    type,
    "--actor-capability-file",
    options.capability ?? (fixture.capabilities[role] as string),
  ];
  if (options.payload) {
    const payloadFile = path.join(fixture.controlDir, `payload-${type}-${Date.now()}.json`);
    writeJson(payloadFile, options.payload);
    args.push("--payload-file", payloadFile);
  }
  if (options.fullHead) args.push("--full-head", options.fullHead);
  args.push("--json");
  return run(fixture, args);
}

function acceptTemplate(fixture: Fixture, template: Record<string, unknown>, role: Role): CliResult {
  const file = path.join(fixture.controlDir, `event-${String(template.event_id)}.json`);
  writeJson(file, template);
  return run(fixture, [
    "event",
    "--goal",
    "usability",
    "--file",
    file,
    "--actor-capability-file",
    fixture.capabilities[role] as string,
    "--json",
  ]);
}

function enterP1Committed(fixture: Fixture): void {
  const start = parse(eventTemplate(fixture, "CAPTAIN", "START_P1"));
  expect(acceptTemplate(fixture, start, "CAPTAIN").code).toBe(0);
  const p1Payload = {
    plan_path: fixture.planPath,
    plan_sha256: fixture.planHash,
    context_path: fixture.contextPath,
    context_sha256: fixture.contextHash,
  };
  const ready = parse(eventTemplate(fixture, "CAPTAIN", "P1_READY", { payload: p1Payload }));
  expect(acceptTemplate(fixture, ready, "CAPTAIN").code).toBe(0);
  const approved = parse(eventTemplate(fixture, "FOREMAN", "P1_APPROVED", {
    payload: { ...p1Payload, approval_ref: "user://goal-usability/approved" },
  }));
  expect(acceptTemplate(fixture, approved, "FOREMAN").code).toBe(0);
  const committed = parse(eventTemplate(fixture, "CAPTAIN", "P1_COMMITTED", {
    payload: { ...p1Payload, approval_event_id: String(approved.event_id) },
    fullHead: git(fixture.root, "rev-parse", "HEAD"),
  }));
  expect(acceptTemplate(fixture, committed, "CAPTAIN").code).toBe(0);
}

afterEach(() => {
  delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_GENERATION;
  delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_EVIDENCE;
  while (fixtures.length > 0) {
    const fixture = fixtures.pop() as Fixture;
    rmSync(fixture.root, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
  }
});

describe("goalctl usability layer", () => {
  test("help forms work without a Git repository or control store", () => {
    const cwd = mkdtempSync(path.join(tmpdir(), "goalctl-help-outside-repo-"));
    const controlDir = path.join(cwd, "missing-control-store");
    try {
      const overview = runCli(["help"], cwd, controlDir);
      expect(overview.code).toBe(0);
      expect(overview.stdout).toContain("goalctl");
      expect(overview.stdout).toContain("scaffold --spec <json>");
      expect(existsSync(controlDir)).toBe(false);

      const jsonHelp = runCli(["--help", "--json"], cwd, controlDir);
      expect(jsonHelp.code).toBe(0);
      expect(parse<{ program: string; commands: Array<{ name: string }> }>(jsonHelp)).toEqual(
        expect.objectContaining({
          program: "goalctl",
          commands: expect.arrayContaining([
            expect.objectContaining({ name: "adopt-store-protocol ..." }),
            expect.objectContaining({ name: "canary-bootstrap-inspect ..." }),
            expect.objectContaining({ name: "canary-bootstrap-plan ..." }),
            expect.objectContaining({ name: "canary-bootstrap-prepare ..." }),
            expect.objectContaining({ name: "rotate-store-protocol ..." }),
            expect.objectContaining({ name: "event-template ..." }),
            expect.objectContaining({ name: "launch-template ..." }),
            expect.objectContaining({ name: "recovery-checkpoint-source ..." }),
          ]),
        })
      );

      const commandHelp = runCli(["scaffold", "--help"], cwd, controlDir);
      expect(commandHelp.code).toBe(0);
      expect(commandHelp.stdout).toContain("goalctl scaffold --spec");
      const rotationHelp = runCli(
        ["help", "rotate-store-protocol"],
        cwd,
        controlDir,
      );
      expect(rotationHelp.code).toBe(0);
      expect(rotationHelp.stdout).toContain("--rotation-id <stable-id>");
      expect(rotationHelp.stdout).toContain(
        "--predecessor-controller-worktree",
      );
      expect(rotationHelp.stdout).toContain(
        "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
      );
      const acquireHelp = runProgram(
        RESOURCECTL,
        ["help", "acquire"],
        cwd,
        controlDir,
      );
      expect(acquireHelp.code).toBe(0);
      expect(acquireHelp.stdout).toContain("--event-id <stable-id>");
      expect(acquireHelp.stdout).toContain("响应丢失");
      for (const command of [
        "preflight",
        "gate-fast",
        "gate-full-ci",
        "gate-ac-audit",
      ]) {
        const help = runCli(["help", command], cwd, controlDir);
        expect(help.code).toBe(0);
        expect(help.stdout).toContain("--evidence-id <stable-id>");
      }
      for (const command of ["renew", "release", "verify"]) {
        const help = runProgram(
          RESOURCECTL,
          ["help", command],
          cwd,
          controlDir,
        );
        expect(help.code).toBe(0);
        expect(help.stdout).toContain("--event-id <stable-id>");
      }
      expect(runCli(["help", "not-a-command"], cwd, controlDir).stderr).toContain(
        "UNKNOWN_HELP_TOPIC"
      );
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });

  test("help explains Goal-wide FOREMAN projection, recovery, and pending-operation output", () => {
    const cwd = mkdtempSync(path.join(tmpdir(), "goalctl-help-contract-"));
    const controlDir = path.join(cwd, "missing-control-store");
    type HelpDocument = {
      usage: string;
      summary: string;
      safety: string;
    };
    const help = (topic: string): HelpDocument => {
      const result = runCli(["help", topic, "--json"], cwd, controlDir);
      expect(result.code).toBe(0);
      return parse<HelpDocument>(result);
    };

    try {
      const registration = help("register-role");
      expect(registration.usage).toContain("[--event-id <stable-id>]");
      expect(registration.summary).toContain("首次 bootstrap");
      expect(registration.summary).toContain("同一 Goal authority");
      expect(registration.summary).toContain("replacement");
      expect(registration.safety).toContain("exact retry");

      const rootRecovery = help("recover-expired-foreman");
      expect(rootRecovery.usage).toContain("[--expected-control-epoch <n>]");
      expect(rootRecovery.summary).toContain(
        "非 ARCHIVED 的 current FOREMAN projections",
      );
      expect(rootRecovery.safety).toContain("pending root transaction");

      const recoveryImport = help("recovery-import-source");
      expect(recoveryImport.safety).toContain("recovery-checkpoint-source");
      expect(recoveryImport.safety).toContain("不自动 commit");

      const checkpoint = help("recovery-checkpoint-source");
      expect(checkpoint.usage).toContain("--import-receipt <id>");
      expect(checkpoint.summary).toContain("commit-tree + update-ref CAS");
      expect(checkpoint.summary).toContain("checkpoint_sha");
      expect(checkpoint.safety).toContain("响应丢失");
      expect(checkpoint.safety).toContain("不 reset、不覆盖");

      const bootstrapPlan = help("canary-bootstrap-plan");
      expect(bootstrapPlan.summary).toContain("IDENTITY_ONLY");
      expect(bootstrapPlan.safety).toContain("worker_canary_bootstrap.protocol");

      const bootstrapInspect = help("canary-bootstrap-inspect");
      expect(bootstrapInspect.usage).toContain(
        "identity_plan.identity_capture.shell_command_template",
      );
      expect(bootstrapInspect.usage).toContain("只替换 thread/host");
      expect(bootstrapInspect.safety).toContain("禁止人工重建 inspect argv");
      expect(bootstrapInspect.safety).toContain("outer plan-hash ingress");

      const bootstrapPrepare = help("canary-bootstrap-prepare");
      expect(bootstrapPrepare.summary).toContain("Git common-dir");
      expect(bootstrapPrepare.summary).toContain("fenced loose-ref CAS");
      expect(bootstrapPrepare.safety).toContain("完整 exact argv");
      expect(bootstrapPrepare.safety).toContain(
        "deterministic rejection 不得循环",
      );

      for (const topic of ["status", "next", "actions", "doctor"]) {
        const document = help(topic);
        expect(`${document.summary} ${document.safety}`).toContain(
          "pending_operations",
        );
        expect(`${document.summary} ${document.safety}`).toContain(
          "launch_scope",
        );
        expect(`${document.summary} ${document.safety}`).toContain(
          "operational_scope",
        );
      }

      for (const topic of ["event", "register-role", "evidence", "rebuild-ledger"]) {
        expect(help(topic).safety).not.toContain("模板命令不提交事件");
      }
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });

  test("portable planning docs preserve Goal-wide FOREMAN and archive recovery invariants", () => {
    const planning = (relativePath: string): string => readFileSync(
      path.join(ROOT, "docs", "planning", relativePath),
      "utf8",
    );
    const quickstart = planning("goal-control-quickstart.md");
    const canonical = planning("goal-control.md");
    const shared = planning("session-protocol/shared.md");
    const foreman = planning("session-protocol/foreman.md");
    const captain = planning("session-protocol/captain.md");
    const dev = planning("session-protocol/dev.md");
    const review = planning("session-protocol/review.md");
    const receipt = planning("session-protocol/receipt.md");
    const roleKernel = planning("session-protocol/role-kernel.md");
    const roleProtocol = planning("session-role-protocol.md");
    const runGoal = planning("goal-control-run-goal.md");

    for (const document of [quickstart, canonical, shared, foreman]) {
      expect(document).toContain(
        "非 `ARCHIVED` 且已有 current FOREMAN projection",
      );
    }
    for (const document of [quickstart, canonical, foreman, captain]) {
      expect(document).toContain(
        "已有 pending recovery 就复用；只有没有 pending recovery 才提交 `ROLE_LOST`",
      );
    }
    for (const document of [
      quickstart,
      canonical,
      shared,
      foreman,
      captain,
      roleKernel,
    ]) {
      expect(document).toContain("pending_operations");
      expect(document).toContain("doctor");
    }
    expect(roleKernel).toContain("不得另发 HEARTBEAT");
    for (const document of [
      quickstart,
      runGoal,
      shared,
      foreman,
      captain,
      dev,
      review,
      receipt,
      roleKernel,
      roleProtocol,
    ]) {
      expect(document).toContain("goalctl-worker-canary-bootstrap-v1");
    }
    for (const document of [
      quickstart,
      runGoal,
      shared,
      captain,
      roleKernel,
      roleProtocol,
    ]) {
      expect(document).toContain("IDENTITY_ONLY");
      expect(document).toContain("CANARY_EXECUTE");
    }
    for (const document of [dev, review, receipt]) {
      expect(document).toContain("identity_plan");
      expect(document).toContain("CANARY_EXECUTE");
      expect(document).toMatch(
        /--worker-thread[\s\S]*--worker-host|actual thread\/host/,
      );
    }
    for (const document of [quickstart, runGoal, shared]) {
      for (const binding of [
        "--worker-bootstrap-receipt",
        "--worker-bootstrap-receipt-sha256",
        "--worker-bootstrap-operation-id",
        "--worker-bootstrap-challenge",
        "--worker-bootstrap-identity-plan-sha256",
        "--worker-thread",
        "--worker-host",
      ]) {
        expect(document).toContain(binding);
      }
    }
  });

  test("audited store protocol adoption requires drain acknowledgement and is idempotent", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    rmSync(path.join(fixture.controlDir, ".store-protocol.json"), { force: true });
    rmSync(path.join(fixture.controlDir, ".generation.json"), { force: true });
    writeJson(path.join(
      fixture.controlDir,
      "goals",
      "_unknown",
      "rejections",
      "_unknown",
      "rejected.json",
    ), {
      rejected_at: "2026-07-24T00:00:00.000Z",
      code: "INVALID_EVENT",
      message: "legacy rejection-only audit record",
      event: null,
    });

    const baseArgs = [
      "adopt-store-protocol",
      "--repository-worktree",
      fixture.root,
      "--json",
    ];
    const missingIncident = run(fixture, [
      ...baseArgs,
      "--acknowledge-old-controller-drained",
      "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
    ]);
    expect(missingIncident.code).toBe(2);
    expect(missingIncident.stderr).toContain("STORE_MIGRATION_INCIDENT_REQUIRED");
    expect(existsSync(path.join(fixture.controlDir, ".store-protocol.json"))).toBe(false);

    const missingAcknowledgement = run(fixture, [
      ...baseArgs,
      "--incident-ref",
      "incident://goal-control/store-adoption-1",
    ]);
    expect(missingAcknowledgement.code).toBe(2);
    expect(missingAcknowledgement.stderr).toContain("STORE_MIGRATION_DRAIN_ACK_REQUIRED");
    expect(existsSync(path.join(fixture.controlDir, ".store-protocol.json"))).toBe(false);

    const wrongAcknowledgement = run(fixture, [
      ...baseArgs,
      "--incident-ref",
      "incident://goal-control/store-adoption-1",
      "--acknowledge-old-controller-drained",
      "yes",
    ]);
    expect(wrongAcknowledgement.code).toBe(2);
    expect(wrongAcknowledgement.stderr).toContain("STORE_MIGRATION_DRAIN_ACK_REQUIRED");

    const adoptionArgs = [
      ...baseArgs,
      "--incident-ref",
      "incident://goal-control/store-adoption-1",
      "--acknowledge-old-controller-drained",
      "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
    ];
    const first = run(fixture, adoptionArgs);
    expect(first).toEqual(expect.objectContaining({ code: 0, stderr: "" }));
    const adopted = parse<{
      adopted: boolean;
      idempotent: boolean;
      source_state_vector_sha256: string;
      sealed_state_vector_sha256: string;
      protocol: {
        controller_decoder_sha256: string;
        lock_protocol_version: number;
        migration_artifacts: Array<{ relative_path: string; sha256: string }>;
      };
      validation: {
        goal_count: number;
        ignored_rejection_only_roots: string[];
        goals: Array<{ goal_id: string; tasks: Array<{ task_id: string }> }>;
        resources: { event_count: number };
      };
    }>(first);
    expect(adopted).toEqual(expect.objectContaining({
      adopted: true,
      idempotent: false,
      source_state_vector_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      sealed_state_vector_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      validation: expect.objectContaining({
        goal_count: 1,
        ignored_rejection_only_roots: ["_unknown"],
        resources: expect.objectContaining({ event_count: 0 }),
      }),
    }));
    expect(adopted.validation.goals).toEqual([
      expect.objectContaining({
        goal_id: "usability",
        tasks: [
          expect.objectContaining({ task_id: "TASK-A" }),
          expect.objectContaining({ task_id: "TASK-B" }),
        ],
      }),
    ]);
    expect(adopted.protocol.migration_artifacts).toEqual([
      expect.objectContaining({
        relative_path: ".legacy-evidence-anchors.v1.json",
        sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      }),
      expect.objectContaining({
        relative_path: ".legacy-identity-incidents.v1.json",
        sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      }),
    ]);
    expect(existsSync(path.join(
      fixture.controlDir,
      ".legacy-evidence-anchors.v1.json",
    ))).toBe(true);

    const second = run(fixture, adoptionArgs);
    expect(second.code).toBe(0);
    expect(parse(second)).toEqual(expect.objectContaining({
      adopted: false,
      idempotent: true,
      validation: expect.objectContaining({ goal_count: 1 }),
    }));
    const changedIncident = run(fixture, adoptionArgs.map((value) => (
      value === "incident://goal-control/store-adoption-1"
        ? "incident://goal-control/store-adoption-2"
        : value
    )));
    expect(changedIncident.code).toBe(2);
    expect(changedIncident.stderr).toContain("STORE_MIGRATION_INCIDENT_MISMATCH");
    expect(run(fixture, ["status", "--goal", "usability", "--json"]).code).toBe(0);
  });

  test("store protocol adoption rejects unknown event, evidence, and resource bytes", () => {
    const prepareLegacy = (): Fixture => {
      const fixture = makeFixture();
      expect(scaffold(fixture).code).toBe(0);
      commitScaffold(fixture);
      initialize(fixture);
      rmSync(path.join(fixture.controlDir, ".store-protocol.json"), { force: true });
      rmSync(path.join(fixture.controlDir, ".generation.json"), { force: true });
      return fixture;
    };
    const adopt = (fixture: Fixture): CliResult => run(fixture, [
      "adopt-store-protocol",
      "--repository-worktree",
      fixture.root,
      "--incident-ref",
      "incident://goal-control/corrupt-store",
      "--acknowledge-old-controller-drained",
      "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
      "--json",
    ]);

    const unknownEvent = prepareLegacy();
    const eventDir = path.join(
      unknownEvent.controlDir,
      "goals",
      "usability",
      "events",
      "TASK-A",
    );
    mkdirSync(eventDir, { recursive: true });
    const eventUnsigned = {
      schema_version: 1,
      event_id: "unknown-event-1",
      goal_id: "usability",
      task_id: "TASK-A",
      type: "UNKNOWN_EVENT",
      actor: { role: "CAPTAIN", thread_id: "captain-corrupt", host_id: "local" },
      actor_sequence: 1,
      expected_state_revision: 0,
      control_epoch: 0,
      packet: {
        revision: 1,
        sha256: sha256(readFileSync(path.join(
          unknownEvent.root,
          unknownEvent.outputDir,
          "packets",
          "TASK-A-r1.md",
        ))),
      },
      base_head: unknownEvent.baseHead,
      full_head: git(unknownEvent.root, "rev-parse", "HEAD"),
      payload: {},
      input_sha256: `sha256:${"0".repeat(64)}`,
      accepted_at: "2026-07-24T00:00:00.000Z",
      log_sequence: 1,
      previous_event_sha256: null,
    };
    writeJson(path.join(eventDir, "00000001-unknown-event-1.json"), {
      ...eventUnsigned,
      event_sha256: hashObject(eventUnsigned),
    });
    const eventFailure = adopt(unknownEvent);
    expect(eventFailure.code).toBe(2);
    expect(eventFailure.stderr).toContain("未知 event.type");
    expect(existsSync(path.join(
      unknownEvent.controlDir,
      ".store-protocol.json",
    ))).toBe(false);

    const unknownEvidence = prepareLegacy();
    const evidenceDir = path.join(
      unknownEvidence.controlDir,
      "goals",
      "usability",
      "evidence",
      "TASK-A",
    );
    mkdirSync(evidenceDir, { recursive: true });
    const evidenceUnsigned = {
      schema_version: 1,
      evidence_id: "unknown-evidence-1",
      goal_id: "usability",
      task_id: "TASK-A",
      kind: "UNKNOWN_KIND",
      status: "PASS",
      producer: { role: "CAPTAIN", thread_id: "captain-corrupt", host_id: "local" },
      state_revision: 0,
      packet: { revision: 1, sha256: `sha256:${"0".repeat(64)}` },
      packet_sha256: `sha256:${"0".repeat(64)}`,
      base_head: unknownEvidence.baseHead,
      full_head: git(unknownEvidence.root, "rev-parse", "HEAD"),
      created_at: "2026-07-24T00:00:00.000Z",
      uri: "file:///does/not-matter-for-unknown-kind",
      source_sha256: `sha256:${"0".repeat(64)}`,
    };
    writeJson(path.join(evidenceDir, "unknown-evidence-1.json"), {
      ...evidenceUnsigned,
      registry_sha256: hashObject(evidenceUnsigned),
    });
    const evidenceFailure = adopt(unknownEvidence);
    expect(evidenceFailure.code).toBe(2);
    expect(evidenceFailure.stderr).toContain("kind 未知");
    expect(existsSync(path.join(
      unknownEvidence.controlDir,
      ".store-protocol.json",
    ))).toBe(false);

    const semanticRuntimeBinding = prepareLegacy();
    const semanticSourceFile = path.join(
      semanticRuntimeBinding.controlDir,
      "semantic-runtime-source.json",
    );
    const semanticSourceBody = "{\"blocked\":\"legacy semantic fact\"}\n";
    writeFileSync(semanticSourceFile, semanticSourceBody);
    const fakeRuntimeLaunchFile = path.join(
      semanticRuntimeBinding.controlDir,
      "fake-runtime-launch.json",
    );
    const fakeRuntimeLaunchBody = "{}\n";
    writeFileSync(fakeRuntimeLaunchFile, fakeRuntimeLaunchBody);
    const semanticPacketFile = path.join(
      semanticRuntimeBinding.root,
      semanticRuntimeBinding.outputDir,
      "packets",
      "TASK-A-r1.md",
    );
    const semanticEvidenceUnsigned = {
      schema_version: 1,
      evidence_id: "semantic-runtime-binding-1",
      goal_id: "usability",
      task_id: "TASK-A",
      kind: "HOLD_ASSERTION",
      status: "BLOCKED",
      producer: {
        role: "FOREMAN",
        thread_id: "foreman-corrupt",
        host_id: "local",
      },
      state_revision: 0,
      packet: {
        revision: 1,
        sha256: sha256(readFileSync(semanticPacketFile)),
      },
      packet_sha256: sha256(readFileSync(semanticPacketFile)),
      base_head: semanticRuntimeBinding.baseHead,
      full_head: git(semanticRuntimeBinding.root, "rev-parse", "HEAD"),
      created_at: "2026-07-24T00:00:00.000Z",
      uri: pathToFileURL(semanticSourceFile).href,
      source_sha256: sha256(semanticSourceBody),
      runtime_launch_sha256: sha256(fakeRuntimeLaunchBody),
      runtime_launch_uri: pathToFileURL(fakeRuntimeLaunchFile).href,
    };
    const semanticEvidenceDir = path.join(
      semanticRuntimeBinding.controlDir,
      "goals",
      "usability",
      "evidence",
      "TASK-A",
    );
    writeJson(
      path.join(
        semanticEvidenceDir,
        "semantic-runtime-binding-1.json",
      ),
      {
        ...semanticEvidenceUnsigned,
        registry_sha256: hashObject(semanticEvidenceUnsigned),
      },
    );
    const semanticBindingFailure = adopt(semanticRuntimeBinding);
    expect(semanticBindingFailure.code).toBe(2);
    expect(
      `${semanticBindingFailure.stdout}\n${semanticBindingFailure.stderr}`,
    ).toContain("非 PREFLIGHT 禁止 runtime launch binding");
    expect(existsSync(path.join(
      semanticRuntimeBinding.controlDir,
      ".store-protocol.json",
    ))).toBe(false);

    const corruptResource = prepareLegacy();
    const resourceEvents = path.join(corruptResource.controlDir, "resources", "events");
    mkdirSync(resourceEvents, { recursive: true });
    const resourceUnsigned = {
      schema_version: 1,
      event_id: "unknown-resource-1",
      type: "UNKNOWN_RESOURCE_EVENT",
      accepted_at: "2026-07-24T00:00:00.000Z",
      actor: {
        goal_id: "usability",
        task_id: "TASK-A",
        role: "CAPTAIN",
        thread_id: "captain-corrupt",
        host_id: "local",
      },
      log_sequence: 1,
      previous_event_sha256: null,
    };
    writeJson(path.join(resourceEvents, "00000001-unknown-resource-1.json"), {
      ...resourceUnsigned,
      event_sha256: hashObject(resourceUnsigned),
    });
    const resourceFailure = adopt(corruptResource);
    expect(resourceFailure.code).toBe(2);
    expect(resourceFailure.stderr).toContain("未知 resource event type");
    expect(existsSync(path.join(
      corruptResource.controlDir,
      ".store-protocol.json",
    ))).toBe(false);
  });

  test("store protocol adoption seals legacy semantic source bytes for replay fallback", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    register(fixture, "FOREMAN");

    const sourceFile = path.join(fixture.controlDir, "lost-worker", "hold.json");
    const sourceBody = `${JSON.stringify({ blocked: "legacy semantic fact" })}\n`;
    mkdirSync(path.dirname(sourceFile), { recursive: true });
    writeFileSync(sourceFile, sourceBody);
    const beforeHold = taskState(fixture);
    const evidenceUnsigned = {
      schema_version: 1,
      evidence_id: "legacy-semantic-hold-1",
      goal_id: "usability",
      task_id: "TASK-A",
      kind: "HOLD_ASSERTION",
      status: "BLOCKED",
      producer: {
        role: "FOREMAN",
        thread_id: THREADS.FOREMAN,
        host_id: "local",
      },
      state_revision: beforeHold.state_revision,
      packet: {
        revision: beforeHold.packet.revision,
        sha256: beforeHold.packet.sha256,
      },
      packet_sha256: beforeHold.packet.sha256,
      base_head: beforeHold.base_head,
      full_head: beforeHold.full_head,
      created_at: "2026-07-24T00:00:00.000Z",
      uri: pathToFileURL(sourceFile).href,
      source_sha256: sha256(sourceBody),
    };
    const registryDir = path.join(
      fixture.controlDir,
      "goals",
      "usability",
      "evidence",
      "TASK-A",
    );
    writeJson(path.join(registryDir, "legacy-semantic-hold-1.json"), {
      ...evidenceUnsigned,
      registry_sha256: hashObject(evidenceUnsigned),
    });
    const hold = parse<{ event_id: string }>(eventTemplate(
      fixture,
      "FOREMAN",
      "ADD_HOLD",
      {
        payload: {
          kind: "TOOLING",
          hold_id: "legacy-source-hold",
          reason: "exercise legacy semantic source migration",
          evidence_id: evidenceUnsigned.evidence_id,
        },
      },
    ));
    expect(acceptTemplate(
      fixture,
      hold as unknown as Record<string, unknown>,
      "FOREMAN",
    ).code).toBe(0);

    const taskEvents = path.join(
      fixture.controlDir,
      "goals",
      "usability",
      "events",
      "TASK-A",
    );
    const holdEventFile = path.join(
      taskEvents,
      readdirSync(taskEvents).find((name) => name.includes(hold.event_id)) as string,
    );
    const storedHold = JSON.parse(readFileSync(holdEventFile, "utf8")) as Record<string, unknown>;
    expect(storedHold.evidence_registry_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    delete storedHold.evidence_registry_sha256;
    delete storedHold.event_sha256;
    storedHold.event_sha256 = hashObject(storedHold);
    writeJson(holdEventFile, storedHold);
    const taskHeadFile = path.join(
      fixture.controlDir,
      "goals",
      "usability",
      "event-heads",
      "TASK-A.json",
    );
    const taskHead = JSON.parse(readFileSync(taskHeadFile, "utf8")) as Record<string, unknown>;
    taskHead.last_event_sha256 = storedHold.event_sha256;
    delete taskHead.head_sha256;
    taskHead.head_sha256 = hashObject(taskHead);
    writeJson(taskHeadFile, taskHead);

    rmSync(path.join(fixture.controlDir, ".store-protocol.json"), { force: true });
    rmSync(path.join(fixture.controlDir, ".generation.json"), { force: true });
    const args = [
      "adopt-store-protocol",
      "--repository-worktree",
      fixture.root,
      "--incident-ref",
      "incident://goal-control/legacy-semantic-source",
      "--acknowledge-old-controller-drained",
      "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
      "--json",
    ];

    const first = run(fixture, args);
    expect(first.code).toBe(0);
    const adopted = parse<{
      protocol: {
        migration_artifacts: Array<{ relative_path: string; sha256: string }>;
      };
      validation: {
        legacy_semantic_source_count: number;
        legacy_semantic_source_bytes: number;
      };
    }>(first);
    const sealedSource = adopted.protocol.migration_artifacts.find(
      (artifact) => artifact.relative_path.startsWith(
        ".legacy-evidence-sources.v1/",
      ),
    );
    expect(sealedSource).toEqual(expect.objectContaining({
      relative_path: `.legacy-evidence-sources.v1/${sha256(sourceBody).slice("sha256:".length)}.artifact`,
      sha256: sha256(sourceBody),
    }));
    expect(adopted.validation).toEqual(expect.objectContaining({
      legacy_semantic_source_count: 1,
      legacy_semantic_source_bytes: Buffer.byteLength(sourceBody),
    }));

    const current = taskState(fixture);
    const postAdoptionSource = path.join(
      fixture.controlDir,
      "post-adoption-inputs",
      "post-adoption-control.json",
    );
    const postAdoptionSourceBody = "{\"control\":\"PASS\"}\n";
    mkdirSync(path.dirname(postAdoptionSource), { recursive: true });
    writeFileSync(postAdoptionSource, postAdoptionSourceBody);
    const postAdoptionEvidence = path.join(
      fixture.controlDir,
      "post-adoption-inputs",
      "post-adoption-evidence.json",
    );
    writeJson(postAdoptionEvidence, {
      schema_version: 1,
      evidence_id: "post-adoption-control-1",
      goal_id: "usability",
      task_id: "TASK-A",
      kind: "CONTROL",
      status: "PASS",
      producer: {
        role: "FOREMAN",
        thread_id: THREADS.FOREMAN,
        host_id: "local",
      },
      state_revision: current.state_revision,
      packet: {
        revision: current.packet.revision,
        sha256: current.packet.sha256,
      },
      packet_sha256: current.packet.sha256,
      base_head: current.base_head,
      full_head: current.full_head,
      created_at: "2026-07-24T00:00:01.000Z",
      uri: pathToFileURL(postAdoptionSource).href,
      source_sha256: sha256(postAdoptionSourceBody),
    });
    const registeredAfterAdoption = run(fixture, [
      "evidence",
      "--goal",
      "usability",
      "--file",
      postAdoptionEvidence,
      "--actor-capability-file",
      fixture.capabilities.FOREMAN as string,
      "--json",
    ]);
    expect(registeredAfterAdoption.code).toBe(0);
    expect(parse(registeredAfterAdoption)).toEqual(expect.objectContaining({
      registered: true,
      idempotent: false,
    }));

    rmSync(sourceFile);
    const replayFromBundle = run(fixture, args);
    if (replayFromBundle.code !== 0) {
      throw new Error(`idempotent adoption failed: ${replayFromBundle.stderr || replayFromBundle.stdout}`);
    }
    expect(replayFromBundle.code).toBe(0);
    expect(parse(replayFromBundle)).toEqual(expect.objectContaining({
      idempotent: true,
      validation: expect.objectContaining({ legacy_semantic_source_count: 1 }),
    }));
    const replayedStatus = run(fixture, [
      "status",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--json",
    ]);
    expect(replayedStatus.code).toBe(0);
    expect(parse<{ tasks: { "TASK-A": { holds: Array<{ hold_id: string }> } } }>(
      replayedStatus,
    ).tasks["TASK-A"].holds).toEqual([
      expect.objectContaining({ hold_id: "legacy-source-hold" }),
    ]);

    writeFileSync(sourceFile, "tampered original source\n");
    const originalTamper = run(fixture, [
      "status",
      "--goal",
      "usability",
      "--json",
    ]);
    expect(originalTamper.code).toBe(2);
    expect(originalTamper.stderr).toContain("EVIDENCE_SOURCE_HASH_MISMATCH");
    rmSync(sourceFile);

    const sealedSourceFile = path.join(
      fixture.controlDir,
      (sealedSource as { relative_path: string }).relative_path,
    );
    writeFileSync(sealedSourceFile, "tampered sealed source\n");
    const sealedTamper = run(fixture, ["status", "--goal", "usability", "--json"]);
    expect(sealedTamper.code).toBe(2);
    expect(sealedTamper.stderr).toContain("CORRUPT_STORE_PROTOCOL");
  });

  test("store protocol adoption detects a validator write and leaves no seal", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    rmSync(path.join(fixture.controlDir, ".store-protocol.json"), { force: true });
    rmSync(path.join(fixture.controlDir, ".generation.json"), { force: true });
    const manifest = path.join(
      fixture.controlDir,
      "goals",
      "usability",
      "manifest.json",
    );
    const previousControlDir = process.env.GOAL_CONTROL_DIR;
    const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    let thrown: unknown = null;
    try {
      adoptStoreProtocol(
        fixture.root,
        {
          incidentRef: "incident://goal-control/mutating-validator",
          oldControllerDrainAcknowledgment:
            "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
        },
        {
          afterReplay: () => {
            writeFileSync(manifest, `${readFileSync(manifest, "utf8")} `);
          },
        },
      );
    } catch (error) {
      thrown = error;
    } finally {
      if (previousControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
      else process.env.GOAL_CONTROL_DIR = previousControlDir;
      if (previousTestMode === undefined) delete process.env.GOAL_CONTROL_TEST_MODE;
      else process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
    }
    expect(thrown).toMatchObject({ code: "STORE_MIGRATION_VALIDATOR_MUTATED" });
    expect(existsSync(path.join(fixture.controlDir, ".store-protocol.json"))).toBe(false);
    expect(existsSync(path.join(fixture.controlDir, ".lock"))).toBe(true);
  });

  test("scaffold copies multi-task packets with hashes and reruns idempotently", () => {
    const fixture = makeFixture();
    const first = scaffold(fixture);
    expect(first.code).toBe(0);
    expect(parse(first)).toEqual(
      expect.objectContaining({
        goal_id: "usability",
        mode: "shadow",
        idempotent: false,
        initialized: false,
      })
    );
    const manifest = JSON.parse(readFileSync(fixture.manifest, "utf8")) as {
      tasks: Array<{ id: string; dependencies: string[]; packet: { path: string; sha256: string } }>;
    };
    expect(manifest.tasks.map((task) => task.id)).toEqual(["TASK-A", "TASK-B"]);
    expect(manifest.tasks[1].dependencies).toEqual(["TASK-A"]);
    for (const task of manifest.tasks) {
      const copied = readFileSync(path.join(fixture.root, task.packet.path));
      expect(task.packet.sha256).toBe(sha256(copied));
      expect(copied.equals(readFileSync(path.join(fixture.root, `goal-inputs/${task.id}.md`)))).toBe(true);
    }

    const second = scaffold(fixture);
    expect(second.code).toBe(0);
    expect(parse(second)).toEqual(expect.objectContaining({ idempotent: true }));

    const copiedA = path.join(fixture.root, fixture.outputDir, "packets", "TASK-A-r1.md");
    writeFileSync(copiedA, "tampered but recoverable\n");
    const conflict = scaffold(fixture);
    expect(conflict.code).toBe(2);
    expect(conflict.stderr).toContain("SCAFFOLD_CONFLICT");
    expect(readFileSync(copiedA, "utf8")).toBe("tampered but recoverable\n");
  });

  test("scaffold preserves the worker bootstrap opt-in and reruns idempotently (bootstrap-v2)", () => {
    const fixture = makeFixture();
    const policyPath = "goal-inputs/canary-policy.md";
    const policyBody = [
      "# Fresh Goal canary policy",
      "",
      "Worker-Canary-Bootstrap-Protocol: goalctl-worker-canary-bootstrap-v1",
      "",
    ].join("\n");
    writeFileSync(path.join(fixture.root, policyPath), policyBody);
    const specFile = path.join(fixture.root, "goal-inputs", "spec.json");
    const spec = JSON.parse(readFileSync(specFile, "utf8")) as Record<string, unknown>;
    spec.worker_canary_bootstrap = {
      protocol: "goalctl-worker-canary-bootstrap-v1",
      policy: {
        path: policyPath,
        sha256: sha256(policyBody),
      },
    };
    writeJson(specFile, spec);

    const first = scaffold(fixture);

    expect(first.code).toBe(0);
    const manifest = JSON.parse(readFileSync(fixture.manifest, "utf8")) as {
      worker_canary_bootstrap?: unknown;
    };
    expect(manifest.worker_canary_bootstrap).toEqual(
      spec.worker_canary_bootstrap,
    );
    const firstManifestBytes = readFileSync(fixture.manifest);

    const second = scaffold(fixture);

    expect(second.code).toBe(0);
    expect(parse(second)).toEqual(expect.objectContaining({ idempotent: true }));
    expect(readFileSync(fixture.manifest)).toEqual(firstManifestBytes);

    writeFileSync(
      path.join(fixture.root, policyPath),
      `${policyBody}tampered after generation\n`,
    );
    const driftedPolicy = scaffold(fixture);
    expect(driftedPolicy.code).toBe(2);
    expect(driftedPolicy.stderr).toContain(
      "WORKER_CANARY_BOOTSTRAP_POLICY_UNSUPPORTED",
    );
    expect(readFileSync(fixture.manifest)).toEqual(firstManifestBytes);
  });

  test("scaffold revalidates byte-identical existing output with the current manifest decoder", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    const specFile = path.join(fixture.root, "goal-inputs", "spec.json");
    const spec = JSON.parse(readFileSync(specFile, "utf8")) as {
      title: string;
    };
    const manifest = JSON.parse(readFileSync(fixture.manifest, "utf8")) as {
      title: string;
    };
    spec.title = "";
    manifest.title = "";
    writeJson(specFile, spec);
    writeJson(fixture.manifest, manifest);
    const invalidManifestBytes = readFileSync(fixture.manifest);

    const rerun = scaffold(fixture);

    expect(rerun.code).toBe(2);
    expect(rerun.stderr).toContain("INVALID_MANIFEST");
    expect(readFileSync(fixture.manifest)).toEqual(invalidManifestBytes);
  });

  test("scaffold fails closed for incomplete, enforce, and out-of-repo output", () => {
    const incomplete = makeFixture({ incompletePacket: true });
    const incompleteResult = scaffold(incomplete);
    expect(incompleteResult.code).toBe(2);
    expect(incompleteResult.stderr).toContain("INCOMPLETE_TASK_PACKET");
    expect(existsSync(path.join(incomplete.root, incomplete.outputDir))).toBe(false);

    const enforce = makeFixture({ mode: "enforce" });
    const denied = scaffold(enforce);
    expect(denied.code).toBe(2);
    expect(denied.stderr).toContain("ENFORCE_CONFIRMATION_REQUIRED");
    expect(scaffold(enforce, ["--allow-enforce"]).code).toBe(0);

    const outside = makeFixture();
    const escapedRelative = `../${path.basename(outside.root)}-escaped`;
    const escaped = run(outside, [
      "scaffold",
      "--spec",
      "goal-inputs/spec.json",
      "--output-dir",
      escapedRelative,
      "--json",
    ]);
    expect(escaped.code).toBe(2);
    expect(escaped.stderr).toContain("PATH_OUTSIDE_REPO");
    expect(existsSync(path.resolve(outside.root, escapedRelative))).toBe(false);

    const gitInternal = run(outside, [
      "scaffold",
      "--spec",
      "goal-inputs/spec.json",
      "--output-dir",
      ".git/generated-goal",
      "--json",
    ]);
    expect(gitInternal.code).toBe(2);
    expect(gitInternal.stderr).toContain("PATH_OUTSIDE_REPO");
    expect(existsSync(path.join(outside.root, ".git", "generated-goal"))).toBe(false);

    const caseFoldedGitInternal = run(outside, [
      "scaffold",
      "--spec",
      "goal-inputs/spec.json",
      "--output-dir",
      ".GIT/generated-goal",
      "--json",
    ]);
    expect(caseFoldedGitInternal.code).toBe(2);
    expect(caseFoldedGitInternal.stderr).toContain("PATH_OUTSIDE_REPO");
    expect(existsSync(path.join(outside.root, ".git", "generated-goal"))).toBe(false);

    const nestedRepo = path.join(outside.root, "vendor");
    mkdirSync(nestedRepo, { recursive: true });
    git(nestedRepo, "init", "-q");
    const nestedGitInternal = run(outside, [
      "scaffold",
      "--spec",
      "goal-inputs/spec.json",
      "--output-dir",
      "vendor/.git/generated-goal",
      "--json",
    ]);
    expect(nestedGitInternal.code).toBe(2);
    expect(nestedGitInternal.stderr).toContain("PATH_OUTSIDE_REPO");
    expect(existsSync(path.join(nestedRepo, ".git", "generated-goal"))).toBe(false);

    mkdirSync(path.join(outside.root, "redirected"), { recursive: true });
    symlinkSync("redirected", path.join(outside.root, "alias"), "dir");
    const symlinkAncestor = run(outside, [
      "scaffold",
      "--spec",
      "goal-inputs/spec.json",
      "--output-dir",
      "alias/generated-goal",
      "--json",
    ]);
    expect(symlinkAncestor.code).toBe(2);
    expect(symlinkAncestor.stderr).toContain("SCAFFOLD_PATH_SYMLINK");
    expect(existsSync(path.join(outside.root, "redirected", "generated-goal"))).toBe(false);
  });

  test("init rejects uncommitted generated inputs and succeeds after commit", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    const uncommitted = run(fixture, ["init", "--manifest", fixture.manifest, "--json"]);
    expect(uncommitted.code).toBe(2);
    expect(uncommitted.stderr).toContain("GOAL_INPUT_NOT_COMMITTED");
    expect(existsSync(path.join(fixture.controlDir, "goals", "usability"))).toBe(false);

    commitScaffold(fixture);
    const committedManifest = readFileSync(fixture.manifest, "utf8");
    writeFileSync(fixture.manifest, `${committedManifest}\n`);
    const dirty = run(fixture, ["init", "--manifest", fixture.manifest, "--json"]);
    expect(dirty.code).toBe(2);
    expect(dirty.stderr).toContain("GOAL_INPUT_DIRTY");
    writeFileSync(fixture.manifest, committedManifest);

    const initialized = initialize(fixture);
    expect(initialized).toEqual(expect.objectContaining({ goal_id: "usability", initialized: true }));
  });

  test("init rejects a committed symlink whose untracked target mimics the Git blob", () => {
    const fixture = makeFixture();
    const packet = path.join(fixture.root, fixture.outputDir, "packets", "TASK-A-r1.md");
    const untrackedTarget = path.join(fixture.root, "untracked-packet");
    const linkTarget = path.relative(path.dirname(packet), untrackedTarget);
    writeFileSync(path.join(fixture.root, "goal-inputs", "TASK-A.md"), linkTarget);
    expect(scaffold(fixture).code).toBe(0);
    unlinkSync(packet);
    writeFileSync(untrackedTarget, linkTarget);
    symlinkSync(linkTarget, packet);
    commitScaffold(fixture);

    const result = run(fixture, ["init", "--manifest", fixture.manifest, "--json"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("GOAL_INPUT_SYMLINK");
    expect(existsSync(path.join(fixture.controlDir, "goals", "usability"))).toBe(false);
  });

  test("read commands need no control-store write permission", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    const foreman = register(fixture, "FOREMAN");
    register(fixture, "CAPTAIN", String(foreman.actor_capability_file));

    chmodTree(fixture.controlDir, 0o555, 0o444);
    const readOnlySnapshot = snapshotTree(fixture.controlDir);
    try {
      const commands = [
        ["status", "--goal", "usability", "--json"],
        ["next", "--goal", "usability", "--json"],
        ["actions", "--goal", "usability", "--task", "TASK-A", "--role", "CAPTAIN", "--thread", THREADS.CAPTAIN, "--json"],
        ["resume", "--goal", "usability", "--task", "TASK-A", "--role", "CAPTAIN", "--thread", THREADS.CAPTAIN, "--json"],
        ["doctor", "--goal", "usability", "--json"],
        [
          "event-template", "--goal", "usability", "--task", "TASK-A",
          "--role", "CAPTAIN", "--thread", THREADS.CAPTAIN, "--type", "START_P1",
          "--actor-capability-file", fixture.capabilities.CAPTAIN as string, "--json",
        ],
      ];
      for (const command of commands) {
        const result = run(fixture, command);
        expect({
          command: command.join(" "),
          code: result.code,
          stderr: result.stderr,
        }).toEqual({
          command: command.join(" "),
          code: 0,
          stderr: "",
        });
        expect(result.stderr).toBe("");
      }
      for (const command of [["list", "--json"], ["doctor", "--json"]]) {
        const result = runProgram(RESOURCECTL, command, fixture.root, fixture.controlDir);
        expect(result.code).toBe(0);
        expect(result.stderr).toBe("");
      }
      const plainResume = run(fixture, [
        "resume", "--goal", "usability", "--task", "TASK-A",
        "--role", "CAPTAIN", "--thread", THREADS.CAPTAIN,
      ]);
      expect(plainResume.code).toBe(0);
      expect(plainResume.stdout).toContain("MAINTENANCE HEARTBEAT@");
      expect(plainResume.stdout.trim().split("\n").length).toBeLessThanOrEqual(15);
      expect(existsSync(path.join(fixture.controlDir, ".lock"))).toBe(false);
      expect(snapshotTree(fixture.controlDir)).toBe(readOnlySnapshot);
    } finally {
      chmodTree(fixture.controlDir, 0o700, 0o600);
    }
  });

  test("next and doctor expose pending durable operations and fail closed on a damaged marker", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    const preparedUnsigned = {
      schema_version: 1,
      goal_id: "usability",
      task_id: "TASK-A",
      evidence_id: "pending-usability-evidence",
      ingress_sha256: sha256("pending ingress"),
    };
    const preparedFile = path.join(
      fixture.controlDir,
      "goals",
      "usability",
      "evidence-ingress",
      "TASK-A",
      "pending-usability-evidence.json"
    );
    writeJson(preparedFile, {
      ...preparedUnsigned,
      prepared_sha256: hashObject(preparedUnsigned),
    });

    const next = parse<{
      batch: Array<{ task_id: string }>;
      tasks: Array<{
        task_id: string;
        eligible: boolean;
        reasons: string[];
      }>;
    }>(run(fixture, ["next", "--goal", "usability", "--json"]));
    expect(next.tasks.find((task) => task.task_id === "TASK-A")).toEqual(
      expect.objectContaining({
        eligible: false,
        reasons: expect.arrayContaining([
          "pending=GENERIC_EVIDENCE:pending-usability-evidence",
        ]),
      })
    );
    expect(next.batch.map((task) => task.task_id)).not.toContain("TASK-A");

    const diagnosis = parse<{
      healthy: boolean;
      findings: Array<{
        task_id?: string;
        code: string;
        detail: string;
      }>;
    }>(run(fixture, ["doctor", "--goal", "usability", "--json"]));
    expect(diagnosis.healthy).toBe(false);
    expect(diagnosis.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          task_id: "TASK-A",
          code: "TASK_OPERATION_PENDING",
          detail:
            "GENERIC_EVIDENCE:pending-usability-evidence; 使用同一 stable ID exact retry 完成该 durable operation",
        }),
      ])
    );

    writeJson(preparedFile, {
      ...preparedUnsigned,
      prepared_sha256: sha256("tampered seal"),
    });
    const damagedNext = run(fixture, [
      "next",
      "--goal",
      "usability",
      "--json",
    ]);
    expect(damagedNext.code).toBe(2);
    expect(damagedNext.stderr).toContain("CORRUPT_STORE");
    const damagedDoctor = run(fixture, [
      "doctor",
      "--goal",
      "usability",
      "--json",
    ]);
    expect(damagedDoctor.code).toBe(2);
    expect(damagedDoctor.stderr).toContain("CORRUPT_STORE");
  });

  test("doctor never repairs a missing resource head while validating an active launch", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    const foreman = register(fixture, "FOREMAN");
    const captain = register(
      fixture,
      "CAPTAIN",
      String(foreman.actor_capability_file)
    );
    enterP1Committed(fixture);
    register(fixture, "DEV", String(captain.actor_capability_file));

    const inputFile = path.join(fixture.controlDir, "launch-input.json");
    writeJson(inputFile, {
      execution: {
        environment: "none",
        write_mode: "NONE",
        target: { kind: "NONE" },
      },
      resource_leases: [],
    });
    const template = run(fixture, [
      "launch-template",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      THREADS.DEV,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--input-file",
      inputFile,
      "--json",
    ]);
    expect(template.code).toBe(0);
    const launchFile = path.join(fixture.controlDir, "launch.json");
    writeJson(launchFile, parse(template));
    const preflight = run(fixture, [
      "preflight",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--launch",
      launchFile,
      "--stage",
      "LAUNCH_DEV",
      "--evidence-id",
      `preflight-usability-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--json",
    ]);
    expect(preflight.code).toBe(0);

    const launched = parse(
      eventTemplate(fixture, "CAPTAIN", "LAUNCH_DEV", {
        payload: { launch_id: "launch-dev-usability-1" },
      })
    );
    expect(acceptTemplate(fixture, launched, "CAPTAIN").code).toBe(0);

    const resourceHead = path.join(
      fixture.controlDir,
      "resources",
      "head.json"
    );
    rmSync(resourceHead);
    expect(existsSync(resourceHead)).toBe(false);
    chmodTree(fixture.controlDir, 0o555, 0o444);
    const readOnlySnapshot = snapshotTree(fixture.controlDir);
    try {
      const result = run(fixture, [
        "doctor",
        "--goal",
        "usability",
        "--json",
      ]);
      expect(result.code).toBe(0);
      expect(result.stderr).toBe("");
      expect(existsSync(resourceHead)).toBe(false);
      expect(existsSync(path.join(fixture.controlDir, ".lock"))).toBe(false);
      expect(snapshotTree(fixture.controlDir)).toBe(readOnlySnapshot);
    } finally {
      chmodTree(fixture.controlDir, 0o700, 0o600);
    }
  });

  test("event-template binds the current envelope, is side-effect free, and advances sequence after accept", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    const foreman = register(fixture, "FOREMAN");
    register(fixture, "CAPTAIN", String(foreman.actor_capability_file));

    const before = taskState(fixture);
    const startResult = eventTemplate(fixture, "CAPTAIN", "START_P1");
    expect(startResult).toEqual(expect.objectContaining({ code: 0, stderr: "" }));
    const start = parse<{
      type: string;
      actor_sequence: number;
      expected_state_revision: number;
      control_epoch: number;
      packet: { revision: number; sha256: string };
      full_head: string;
      payload: Record<string, unknown>;
    }>(startResult);
    expect(start).toEqual(
      expect.objectContaining({
        type: "START_P1",
        actor_sequence: 1,
        expected_state_revision: before.state_revision,
        control_epoch: before.control_epoch,
        packet: {
          revision: before.packet.revision,
          sha256: before.packet.sha256,
        },
        full_head: before.full_head,
        payload: {},
      })
    );
    expect(taskState(fixture)).toEqual(before);

    expect(
      eventTemplate(fixture, "CAPTAIN", "P1_READY").stderr
    ).toContain("EVENT_NOT_ALLOWED");
    expect(
      eventTemplate(fixture, "CAPTAIN", "START_P1", {
        thread: "captain-wrong-thread",
      }).stderr
    ).toContain("CAPABILITY");
    expect(
      eventTemplate(fixture, "CAPTAIN", "START_P1", {
        capability: fixture.capabilities.FOREMAN,
      }).stderr
    ).toContain("CAPABILITY");

    expect(acceptTemplate(fixture, start as unknown as Record<string, unknown>, "CAPTAIN").code).toBe(0);
    const missingPayload = eventTemplate(fixture, "CAPTAIN", "P1_READY");
    expect(missingPayload.code).toBe(2);
    expect(missingPayload.stderr).toContain("PAYLOAD_FILE_REQUIRED");
    const next = eventTemplate(fixture, "CAPTAIN", "P1_READY", {
      payload: {
        plan_path: fixture.planPath,
        plan_sha256: fixture.planHash,
        context_path: fixture.contextPath,
        context_sha256: fixture.contextHash,
      },
    });
    expect(next.code).toBe(0);
    expect(parse<{ actor_sequence: number }>(next).actor_sequence).toBe(2);
    const ready = parse(next);
    expect(acceptTemplate(fixture, ready, "CAPTAIN").code).toBe(0);
    const p1Payload = {
      plan_path: fixture.planPath,
      plan_sha256: fixture.planHash,
      context_path: fixture.contextPath,
      context_sha256: fixture.contextHash,
    };
    const approved = parse(eventTemplate(fixture, "FOREMAN", "P1_APPROVED", {
      payload: { ...p1Payload, approval_ref: "user://goal-usability/approved" },
    }));
    expect(acceptTemplate(fixture, approved, "FOREMAN").code).toBe(0);
    const committedPayload = { ...p1Payload, approval_event_id: String(approved.event_id) };
    expect(eventTemplate(fixture, "CAPTAIN", "P1_COMMITTED", {
      payload: committedPayload,
    }).stderr).toContain("FULL_HEAD_REQUIRED");
    expect(eventTemplate(fixture, "CAPTAIN", "P1_COMMITTED", {
      payload: committedPayload,
      fullHead: fixture.baseHead,
    }).stderr).toContain("STALE_HEAD");
  });

  test("launch-template derives worker identity and runtime without mutating state", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    const foreman = register(fixture, "FOREMAN");
    const captain = register(fixture, "CAPTAIN", String(foreman.actor_capability_file));
    enterP1Committed(fixture);
    const dev = register(fixture, "DEV", String(captain.actor_capability_file));

    const inputFile = path.join(fixture.controlDir, "launch-input.json");
    writeJson(inputFile, {
      thread_title: "DEV TASK-A",
      runtime_model: {
        requested: "gpt-5",
        actual: "gpt-5",
        reasoning_effort: "high",
      },
      execution: {
        environment: "none",
        write_mode: "NONE",
        target: { kind: "NONE" },
      },
      resource_leases: [],
    });
    const before = taskState(fixture);
    const result = run(fixture, [
      "launch-template",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      THREADS.DEV,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--input-file",
      inputFile,
      "--json",
    ]);
    expect(result.code).toBe(0);
    const launch = parse<{
      launch_id: string;
      state_revision: number;
      thread: { id: string; cwd: string };
      repository: { root: string; worktree: string; branch: string; full_head: string };
      runtime: { node_version: string; pnpm_version: string; lockfile_sha256: string };
      execution: { task_nonce: string; environment: string; write_mode: string };
    }>(result);
    expect(launch).toEqual(
      expect.objectContaining({
        launch_id: "launch-dev-usability-1",
        state_revision: (dev.session as { registered_state_revision: number }).registered_state_revision,
        thread: expect.objectContaining({ id: THREADS.DEV, cwd: realpathSync(fixture.root) }),
        repository: expect.objectContaining({
          root: realpathSync(fixture.root),
          worktree: realpathSync(fixture.root),
          branch: "main",
          full_head: git(fixture.root, "rev-parse", "HEAD"),
        }),
        runtime: expect.objectContaining({
          node_version: process.version,
          pnpm_version: expect.any(String),
          lockfile_sha256: sha256(readFileSync(path.join(fixture.root, "pnpm-lock.yaml"))),
        }),
        execution: expect.objectContaining({
          task_nonce: fixture.taskNonce,
          environment: "none",
          write_mode: "NONE",
        }),
      })
    );
    expect(taskState(fixture)).toEqual(before);

    const launchFile = path.join(fixture.controlDir, "launch.json");
    writeJson(launchFile, launch);
    const preflight = run(fixture, [
      "preflight",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--launch",
      launchFile,
      "--stage",
      "LAUNCH_DEV",
      "--evidence-id",
      `preflight-usability-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--json",
    ]);
    expect(preflight.code).toBe(0);
    expect(parse<{ status: string }>(preflight).status).toBe("PASS");
    const launched = parse(eventTemplate(
      fixture,
      "CAPTAIN",
      "LAUNCH_DEV",
      { payload: { launch_id: "launch-dev-usability-1" } },
    ));
    expect(acceptTemplate(fixture, launched, "CAPTAIN").code).toBe(0);

    const canonicalLaunchFile = path.join(
      fixture.controlDir,
      "goals",
      "usability",
      "launches",
      "TASK-A",
      "launch-dev-usability-1.json",
    );
    const canonicalLaunchBefore = readFileSync(canonicalLaunchFile, "utf8");
    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate checkpoint");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const candidateTemplate = run(fixture, [
      "launch-template",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      THREADS.DEV,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--input-file",
      inputFile,
      "--json",
    ]);
    if (candidateTemplate.code !== 0) {
      throw new Error(candidateTemplate.stderr || candidateTemplate.stdout);
    }
    const candidateLaunch = parse<{
      created_at: string;
      repository: { full_head: string };
      execution: { target: { kind: string; build_head?: string } };
    }>(candidateTemplate);
    expect(candidateLaunch).toMatchObject({
      created_at: (launch as unknown as { created_at: string }).created_at,
      repository: { full_head: candidateHead },
      execution: { target: { kind: "NONE" } },
    });
    expect(candidateLaunch.execution.target.build_head).toBeUndefined();
    const candidateLaunchFile = path.join(
      fixture.controlDir,
      "candidate-launch.json",
    );
    writeJson(candidateLaunchFile, candidateLaunch);
    const candidatePreflight = run(fixture, [
      "preflight",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--launch",
      candidateLaunchFile,
      "--stage",
      "LAUNCH_DEV",
      "--evidence-id",
      `preflight-usability-candidate-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--json",
    ]);
    expect(candidatePreflight.code).toBe(0);
    expect(parse(candidatePreflight)).toMatchObject({
      status: "PASS",
      full_head: candidateHead,
      runtime_launch_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    });
    expect(readFileSync(canonicalLaunchFile, "utf8")).toBe(
      canonicalLaunchBefore,
    );

    const wrongCapability = run(fixture, [
      "launch-template",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      THREADS.DEV,
      "--actor-capability-file",
      fixture.capabilities.CAPTAIN as string,
      "--input-file",
      inputFile,
      "--json",
    ]);
    expect(wrongCapability.code).toBe(2);
    expect(wrongCapability.stderr).toContain("CAPABILITY");

    writeJson(inputFile, {
      execution: {
        environment: "none",
        write_mode: "NONE",
        target: { kind: "CLI", executable_path: tmpdir() },
      },
      resource_leases: [],
    });
    const directoryExecutable = run(fixture, [
      "launch-template",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      THREADS.DEV,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--input-file",
      inputFile,
      "--json",
    ]);
    expect(directoryExecutable.code).toBe(2);
    expect(directoryExecutable.stderr).toContain("INVALID_LAUNCH_INPUT");

    writeJson(inputFile, {
      execution: {
        environment: "none",
        write_mode: "NONE",
        target: {
          kind: "PREVIEW",
          executable_path: realpathSync(process.execPath),
          pid: process.pid,
          started_at: new Date().toISOString(),
          preview_url: "https://user:password@example.invalid/?access_token=SECRET",
        },
      },
      resource_leases: [],
    });
    const sensitiveUrl = run(fixture, [
      "launch-template",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      THREADS.DEV,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--input-file",
      inputFile,
      "--json",
    ]);
    expect(sensitiveUrl.code).toBe(2);
    expect(sensitiveUrl.stderr).toContain("SENSITIVE_URL_FORBIDDEN");

    writeJson(inputFile, {
      execution: {
        environment: "none",
        write_mode: "NONE",
        target: { kind: "NONE" },
      },
      resource_leases: [],
      unexpected: true,
    });
    const unknownInput = run(fixture, [
      "launch-template",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      THREADS.DEV,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--input-file",
      inputFile,
      "--json",
    ]);
    expect(unknownInput.code).toBe(2);
    expect(unknownInput.stderr).toContain("INVALID_LAUNCH_INPUT");

    const unsafeLaunch = JSON.parse(result.stdout) as Record<string, unknown> & {
      execution: Record<string, unknown>;
    };
    unsafeLaunch.execution = {
      ...unsafeLaunch.execution,
      target: { kind: "CLI", executable_path: realpathSync(tmpdir()) },
    };
    const unsafeLaunchFile = path.join(fixture.controlDir, "unsafe-launch.json");
    writeJson(unsafeLaunchFile, unsafeLaunch);
    const unsafePreflight = run(fixture, [
      "preflight",
      "--goal",
      "usability",
      "--task",
      "TASK-A",
      "--launch",
      unsafeLaunchFile,
      "--stage",
      "LAUNCH_DEV",
      "--evidence-id",
      `preflight-usability-${randomUUID()}`,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--json",
    ]);
    expect(unsafePreflight.code).toBe(1);
    expect(parse<{ checks: Array<{ name: string; status: string; detail?: string }> }>(unsafePreflight).checks)
      .toEqual(expect.arrayContaining([
        expect.objectContaining({
          name: "execution-target",
          status: "FAIL",
          detail: expect.stringContaining("TARGET_EXECUTABLE_INVALID"),
        }),
      ]));
  });

  test("projects candidate preflight instead of invalidating a source advance", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    const foreman = register(fixture, "FOREMAN");
    const captain = register(
      fixture,
      "CAPTAIN",
      String(foreman.actor_capability_file),
    );
    enterP1Committed(fixture);
    register(fixture, "DEV", String(captain.actor_capability_file));
    const initialHead = git(fixture.root, "rev-parse", "HEAD");
    const ps = existsSync("/bin/ps") ? "/bin/ps" : "/usr/bin/ps";
    const started = execFileSync(
      ps,
      ["-p", String(process.pid), "-o", "lstart="],
      {
        encoding: "utf8",
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C",
          LC_ALL: "C",
          TZ: "UTC",
          NODE_ENV: "test",
        },
      },
    ).trim();
    const inputFile = path.join(fixture.controlDir, "launch-input.json");
    writeJson(inputFile, {
      execution: {
        environment: "none",
        write_mode: "NONE",
        target: {
          kind: "PREVIEW",
          executable_path: realpathSync(process.execPath),
          pid: process.pid,
          started_at: new Date(Date.parse(`${started} UTC`)).toISOString(),
          preview_url: "http://127.0.0.1:8123",
          build_head: initialHead,
        },
      },
      resource_leases: [],
    });
    const launchArgs = [
      "launch-template",
      "--goal", "usability",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--input-file", inputFile,
      "--json",
    ];

    const h0 = git(fixture.root, "rev-parse", "HEAD");
    const initialLaunch = run(fixture, launchArgs);
    expect(initialLaunch.code).toBe(0);
    const initialLaunchFile = path.join(fixture.controlDir, "h1-launch.json");
    writeFileSync(initialLaunchFile, initialLaunch.stdout);
    const initialPreflight = run(fixture, [
      "preflight",
      "--goal", "usability",
      "--task", "TASK-A",
      "--launch", initialLaunchFile,
      "--stage", "DEV",
      "--evidence-id", `preflight-h1-${randomUUID()}`,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]);
    if (initialPreflight.code !== 0) {
      throw new Error(initialPreflight.stderr || initialPreflight.stdout);
    }
    expect(parse(initialPreflight)).toMatchObject({ full_head: h0 });
    const launched = parse(eventTemplate(
      fixture,
      "CAPTAIN",
      "LAUNCH_DEV",
      { payload: { launch_id: "launch-dev-usability-1" } },
    ));
    expect(acceptTemplate(fixture, launched, "CAPTAIN").code).toBe(0);

    writeFileSync(path.join(fixture.root, "h1.txt"), "h1\n");
    git(fixture.root, "add", "h1.txt");
    git(fixture.root, "commit", "-qm", "current candidate");
    const h1 = git(fixture.root, "rev-parse", "HEAD");
    const status = run(fixture, [
      "status",
      "--goal", "usability",
      "--task", "TASK-A",
      "--json",
    ]);
    expect(status.code).toBe(0);
    const projected = parse<{
      tasks: {
        "TASK-A": {
          launch_scope: string;
          launch_error_code?: string;
          next_actions: Array<{ type: string }>;
          maintenance_actions: Array<Record<string, unknown>>;
        };
      };
    }>(status).tasks["TASK-A"];
    expect(projected.launch_scope).toBe(
      "SOURCE_CHECKPOINT_PREFLIGHT_REQUIRED",
    );
    expect(projected.launch_error_code).toBeUndefined();
    expect(projected.maintenance_actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "REQUEST_CANDIDATE_PREFLIGHT",
          actor_role: "CAPTAIN",
          launch_id: "launch-dev-usability-1",
          canonical_head: h0,
          candidate_head: h1,
          mutable_fields: [
            "repository.full_head",
            "execution.target.build_head",
          ],
          forbidden_action: "ROTATE_RUNTIME",
        }),
      ]),
    );
    expect(projected.next_actions).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "DEV_READY" }),
      ]),
    );
    const candidateAction = projected.maintenance_actions.find(
      (action) => action.type === "REQUEST_CANDIDATE_PREFLIGHT",
    ) as { evidence_id: string };
    const candidateLaunch = run(fixture, [
      "launch-template",
      "--goal", "usability",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]);
    expect(candidateLaunch.code).toBe(0);
    const initialTarget = parse<{
      execution: { target: Record<string, unknown> };
    }>(initialLaunch).execution.target;
    const candidateTarget = parse<{
      execution: { target: Record<string, unknown> };
    }>(candidateLaunch).execution.target;
    expect(candidateTarget).toEqual({
      ...initialTarget,
      build_head: h1,
    });
    const candidateLaunchFile = path.join(
      fixture.controlDir,
      "candidate-launch.json",
    );
    writeFileSync(candidateLaunchFile, candidateLaunch.stdout);
    const candidatePreflight = run(fixture, [
      "preflight",
      "--goal", "usability",
      "--task", "TASK-A",
      "--launch", candidateLaunchFile,
      "--stage", "DEV",
      "--evidence-id", candidateAction.evidence_id,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]);
    expect(candidatePreflight.code).toBe(0);

    const after = parse<{
      tasks: {
        "TASK-A": {
          launch_scope: string;
          next_actions: Array<{ type: string }>;
          maintenance_actions: Array<Record<string, unknown>>;
        };
      };
    }>(run(fixture, [
      "status",
      "--goal", "usability",
      "--task", "TASK-A",
      "--json",
    ])).tasks["TASK-A"];
    expect(after.launch_scope).toBe("FULL");
    expect(after.next_actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "DEV_READY" }),
      ]),
    );
    expect(after.maintenance_actions).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "REQUEST_CANDIDATE_PREFLIGHT" }),
      ]),
    );
    const doctor = run(fixture, [
      "doctor",
      "--goal", "usability",
      "--json",
    ]);
    expect(`${doctor.stdout}\n${doctor.stderr}`).not.toContain("STALE_HEAD");
    expect(`${doctor.stdout}\n${doctor.stderr}`).not.toContain("LAUNCH_INVALID");
  });

  test.each(["NONE", "CLI", "PREVIEW"] as const)(
    "%s source advance with a changed lockfile requires exact fresh DEV recovery",
    (targetKind) => {
      const fixture = makeFixture();
      expect(scaffold(fixture).code).toBe(0);
      commitScaffold(fixture);
      initialize(fixture);
      const foreman = register(fixture, "FOREMAN");
      const captain = register(
        fixture,
        "CAPTAIN",
        String(foreman.actor_capability_file),
      );
      enterP1Committed(fixture);
      register(
        fixture,
        "DEV",
        String(captain.actor_capability_file),
      );
      const initialHead = git(fixture.root, "rev-parse", "HEAD");
      const target: Record<string, unknown> = targetKind === "NONE"
        ? { kind: "NONE" }
        : {
          kind: targetKind,
          executable_path: realpathSync(process.execPath),
          build_head: initialHead,
        };
      if (targetKind === "PREVIEW") {
        const ps = existsSync("/bin/ps") ? "/bin/ps" : "/usr/bin/ps";
        const started = execFileSync(
          ps,
          ["-p", String(process.pid), "-o", "lstart="],
          {
            encoding: "utf8",
            env: {
              PATH: "/usr/bin:/bin",
              LANG: "C",
              LC_ALL: "C",
              TZ: "UTC",
              NODE_ENV: "test",
            },
          },
        ).trim();
        target.pid = process.pid;
        target.started_at =
          new Date(Date.parse(`${started} UTC`)).toISOString();
        target.preview_url = "http://127.0.0.1:8124";
      }
      const inputFile = path.join(
        fixture.controlDir,
        `lock-drift-${targetKind.toLowerCase()}-input.json`,
      );
      writeJson(inputFile, {
        execution: {
          environment: "none",
          write_mode: "NONE",
          target,
        },
        resource_leases: [],
      });
      const launch = run(fixture, [
        "launch-template",
        "--goal", "usability",
        "--task", "TASK-A",
        "--role", "DEV",
        "--thread", THREADS.DEV,
        "--actor-capability-file",
        fixture.capabilities.DEV as string,
        "--input-file", inputFile,
        "--json",
      ]);
      expect(launch.code).toBe(0);
      const launchFile = path.join(
        fixture.controlDir,
        `lock-drift-${targetKind.toLowerCase()}-launch.json`,
      );
      writeFileSync(launchFile, launch.stdout);
      const preflight = run(fixture, [
        "preflight",
        "--goal", "usability",
        "--task", "TASK-A",
        "--launch", launchFile,
        "--stage", "DEV",
        "--evidence-id",
        `preflight-lock-drift-${targetKind.toLowerCase()}-${randomUUID()}`,
        "--actor-capability-file",
        fixture.capabilities.DEV as string,
        "--json",
      ]);
      if (preflight.code !== 0) {
        throw new Error(preflight.stderr || preflight.stdout);
      }
      const launched = parse(eventTemplate(
        fixture,
        "CAPTAIN",
        "LAUNCH_DEV",
        { payload: { launch_id: "launch-dev-usability-1" } },
      ));
      expect(acceptTemplate(
        fixture,
        launched,
        "CAPTAIN",
      ).code).toBe(0);

      const lockfile = path.join(fixture.root, "pnpm-lock.yaml");
      writeFileSync(
        lockfile,
        `${readFileSync(lockfile, "utf8")}# dependency update\n`,
      );
      writeFileSync(
        path.join(
          fixture.root,
          `lock-drift-${targetKind.toLowerCase()}.txt`,
        ),
        "candidate\n",
      );
      git(fixture.root, "add", ".");
      git(fixture.root, "commit", "-qm", `${targetKind} lock drift`);

      const projected = taskState(fixture) as TaskState & {
        launch_scope: string;
        next_actions: Array<Record<string, unknown>>;
        maintenance_actions: Array<Record<string, unknown>>;
      };
      expect(projected.launch_scope).toBe(
        "FRESH_RUNTIME_RECOVERY_REQUIRED",
      );
      expect(projected.maintenance_actions).not.toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: "REQUEST_CANDIDATE_PREFLIGHT",
          }),
        ]),
      );
      expect(projected.next_actions).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: "ROLE_LOST",
            actor_role: "CAPTAIN",
            target_role: "DEV",
            trigger: "SOURCE_RUNTIME_BINDING_CHANGED",
            target: expect.objectContaining({
              thread_id: THREADS.DEV,
              host_id: "local",
              attempt: 1,
              lease_until: expect.any(String),
            }),
            payload: expect.objectContaining({
              role: "DEV",
              fingerprint:
                expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
              expected_thread_id: THREADS.DEV,
              expected_host_id: "local",
              expected_attempt: 1,
              expected_lease_until: expect.any(String),
            }),
            requested_action:
              "EVENT_TEMPLATE_AND_ACCEPT_THEN_STANDARD_SOURCE_RECOVERY",
            forbidden_action: "SOURCE_CHECKPOINT_PREFLIGHT",
          }),
        ]),
      );
      const diagnosis = parse<{
        healthy: boolean;
        findings: Array<{
          task_id?: string;
          code: string;
          role?: string;
          detail: string;
        }>;
      }>(run(fixture, [
        "doctor",
        "--goal", "usability",
        "--json",
      ]));
      expect(diagnosis.findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            task_id: "TASK-A",
            code: "FRESH_RUNTIME_RECOVERY_REQUIRED",
            role: "DEV",
            detail: expect.stringContaining("lockfile binding"),
          }),
        ]),
      );
    },
  );

  test("projects runtime rotation for a controller-sealed same-source fresh preview identity", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    const foreman = register(fixture, "FOREMAN");
    const captain = register(
      fixture,
      "CAPTAIN",
      String(foreman.actor_capability_file),
    );
    enterP1Committed(fixture);
    register(fixture, "DEV", String(captain.actor_capability_file));
    const head = git(fixture.root, "rev-parse", "HEAD");
    const ps = existsSync("/bin/ps") ? "/bin/ps" : "/usr/bin/ps";
    const started = execFileSync(
      ps,
      ["-p", String(process.pid), "-o", "lstart="],
      {
        encoding: "utf8",
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C",
          LC_ALL: "C",
          TZ: "UTC",
          NODE_ENV: "test",
        },
      },
    ).trim();
    const inputFile = path.join(
      fixture.controlDir,
      "runtime-conflict-input.json",
    );
    writeJson(inputFile, {
      execution: {
        environment: "none",
        write_mode: "NONE",
        target: {
          kind: "PREVIEW",
          executable_path: realpathSync(process.execPath),
          pid: process.pid,
          started_at: new Date(
            Date.parse(`${started} UTC`),
          ).toISOString(),
          preview_url: "http://127.0.0.1:8123",
          build_head: head,
        },
      },
      resource_leases: [],
    });
    const initialLaunch = run(fixture, [
      "launch-template",
      "--goal", "usability",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--input-file", inputFile,
      "--json",
    ]);
    expect(initialLaunch.code).toBe(0);
    const initialLaunchFile = path.join(
      fixture.controlDir,
      "runtime-conflict-initial-launch.json",
    );
    writeFileSync(initialLaunchFile, initialLaunch.stdout);
    expect(run(fixture, [
      "preflight",
      "--goal", "usability",
      "--task", "TASK-A",
      "--launch", initialLaunchFile,
      "--stage", "DEV",
      "--evidence-id", `preflight-runtime-initial-${randomUUID()}`,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]).code).toBe(0);
    const launched = parse(eventTemplate(
      fixture,
      "CAPTAIN",
      "LAUNCH_DEV",
      { payload: { launch_id: "launch-dev-usability-1" } },
    ));
    expect(acceptTemplate(fixture, launched, "CAPTAIN").code).toBe(0);

    const freshRuntime = spawn(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)"],
      { stdio: "ignore" },
    );
    try {
      if (!freshRuntime.pid) throw new Error("fresh runtime missing PID");
      const freshStarted = execFileSync(
        ps,
        ["-p", String(freshRuntime.pid), "-o", "lstart="],
        {
          encoding: "utf8",
          env: {
            PATH: "/usr/bin:/bin",
            LANG: "C",
            LC_ALL: "C",
            TZ: "UTC",
            NODE_ENV: "test",
          },
        },
      ).trim();
      const candidate = JSON.parse(initialLaunch.stdout) as {
        execution: {
          target: {
            pid: number;
            started_at: string;
            preview_url: string;
          };
        };
        created_at: string;
      };
      candidate.execution.target.pid = freshRuntime.pid;
      candidate.execution.target.started_at = new Date(
        Date.parse(`${freshStarted} UTC`),
      ).toISOString();
      candidate.execution.target.preview_url =
        "http://127.0.0.1:8124";
      candidate.created_at = "2026-07-26T00:00:01.000Z";
      const candidateFile = path.join(
        fixture.controlDir,
        "runtime-conflict-candidate-launch.json",
      );
      writeJson(candidateFile, candidate);
      const rejected = run(fixture, [
        "preflight",
        "--goal", "usability",
        "--task", "TASK-A",
        "--launch", candidateFile,
        "--stage", "DEV",
        "--evidence-id", `preflight-runtime-conflict-${randomUUID()}`,
        "--actor-capability-file", fixture.capabilities.DEV as string,
        "--json",
      ]);
      expect(rejected.code).toBe(1);
      expect(`${rejected.stdout}\n${rejected.stderr}`).toContain(
        "LAUNCH_ID_CONFLICT",
      );
      const held = taskState(fixture) as TaskState & {
        holds: Array<{
          kind: string;
          evidence?: Record<string, unknown>;
        }>;
        maintenance_actions: Array<Record<string, unknown>>;
      };
      const incidentEvents = readdirSync(path.join(
        fixture.controlDir,
        "goals",
        "usability",
        "events",
        "TASK-A",
      )).filter((name) => name.endsWith(".json")).map((name) => (
        JSON.parse(readFileSync(path.join(
          fixture.controlDir,
          "goals",
          "usability",
          "events",
          "TASK-A",
          name,
        ), "utf8")
      ) as {
        type: string;
        payload?: { kind?: string; evidence_id?: string };
        prepared_identity_incident_authority?: {
          schema_version: number;
          evidence_id: string;
          authority_sha256: string;
        };
      })).filter((event) => (
        event.type === "ADD_HOLD"
          && event.payload?.kind === "ENV_IDENTITY_INCIDENT"
      ));
      expect(incidentEvents).toHaveLength(1);
      expect(incidentEvents[0].prepared_identity_incident_authority)
        .toMatchObject({
          schema_version: 1,
          evidence_id: incidentEvents[0].payload?.evidence_id,
          authority_sha256: expect.stringMatching(
            /^sha256:[0-9a-f]{64}$/,
          ),
        });
      expect(held.maintenance_actions).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: "REQUEST_RUNTIME_ROTATION",
            predecessor_launch_id: "launch-dev-usability-1",
          }),
        ]),
      );
      expect(held.maintenance_actions).not.toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: "REQUEST_CANDIDATE_HOLD_REVALIDATION",
          }),
        ]),
      );
      const staleEpoch = JSON.parse(JSON.stringify(held)) as {
        control_epoch: number;
      };
      staleEpoch.control_epoch += 1;
      expect(classifyLaunchIdentityHold(
        fixture.controlDir,
        staleEpoch as unknown as Record<string, unknown>,
        "usability",
      )).toBe("UNKNOWN");
      const staleRegistration = JSON.parse(JSON.stringify(held)) as {
        sessions: { DEV: { registered_state_revision: number } };
      };
      staleRegistration.sessions.DEV.registered_state_revision += 1;
      expect(classifyLaunchIdentityHold(
        fixture.controlDir,
        staleRegistration as unknown as Record<string, unknown>,
        "usability",
      )).toBe("UNKNOWN");

      const acceptedIncidentFile = readdirSync(path.join(
        fixture.controlDir,
        "goals",
        "usability",
        "events",
        "TASK-A",
      )).map((name) => path.join(
        fixture.controlDir,
        "goals",
        "usability",
        "events",
        "TASK-A",
        name,
      )).find((file) => {
        const event = JSON.parse(readFileSync(file, "utf8")) as {
          type?: string;
          payload?: { kind?: string };
        };
        return event.type === "ADD_HOLD"
          && event.payload?.kind === "ENV_IDENTITY_INCIDENT";
      });
      if (!acceptedIncidentFile) {
        throw new Error("missing accepted identity incident event");
      }
      const loadedBeforeMarkerRemoval = loadGoalStateUnlocked(
        fixture.controlDir,
        "usability",
      );
      const markerless = JSON.parse(
        readFileSync(acceptedIncidentFile, "utf8"),
      ) as Record<string, unknown>;
      delete markerless.prepared_identity_incident_authority;
      delete markerless.event_sha256;
      markerless.event_sha256 = hashObject(markerless);
      writeJson(acceptedIncidentFile, markerless);
      const identityHold = held.holds.find((hold) => (
        hold.kind === "ENV_IDENTITY_INCIDENT"
      ));
      if (!identityHold?.evidence) {
        throw new Error("missing identity hold evidence");
      }
      const identityCollector =
        createLegacyIdentityIncidentCollector();
      const markerlessTaskState = loadedBeforeMarkerRemoval
        .snapshot.tasks["TASK-A"] as unknown as Record<string, unknown>;
      collectLegacyIdentityIncident(
        fixture.controlDir,
        identityCollector,
        markerlessTaskState,
        "usability",
        markerless,
        identityHold.evidence as unknown as Record<string, unknown>,
      );
      const unsealed = sealLegacyIdentityIncidentReceipt(
        identityCollector,
        {
          controllerDecoderSha256: hashObject("unsealed-decoder"),
          sourceStateVectorSha256: hashObject("unsealed-source"),
          predecessorProtocolSealSha256: null,
          incidentRef: "incident://unsealed-self-signed-receipt",
          oldControllerDrainAck:
            "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
        },
      );
      expect(unsealed.incident_count).toBe(1);
      writeFileSync(
        path.join(
          fixture.controlDir,
          unsealed.migration_artifact.relative_path,
        ),
        unsealed.migration_artifact.body,
      );
      expect(classifyLaunchIdentityHold(
        fixture.controlDir,
        held as unknown as Record<string, unknown>,
        "usability",
      )).toBe("UNKNOWN");
    } finally {
      freshRuntime.kill("SIGTERM");
    }
  });

  test("projects replayable runtime rotation and exact successor preflight machine actions", async () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    const foreman = register(fixture, "FOREMAN");
    const captain = register(
      fixture,
      "CAPTAIN",
      String(foreman.actor_capability_file),
    );
    enterP1Committed(fixture);
    register(fixture, "DEV", String(captain.actor_capability_file));

    const ps = existsSync("/bin/ps") ? "/bin/ps" : "/usr/bin/ps";
    const processStartedAt = (pid: number): string => {
      const started = execFileSync(
        ps,
        ["-p", String(pid), "-o", "lstart="],
        {
          encoding: "utf8",
          env: {
            PATH: "/usr/bin:/bin",
            LANG: "C",
            LC_ALL: "C",
            TZ: "UTC",
            NODE_ENV: "test",
          },
        },
      ).trim();
      return new Date(Date.parse(`${started} UTC`)).toISOString();
    };
    const stopRuntime = async (
      runtime: ReturnType<typeof spawn>,
    ): Promise<void> => {
      if (runtime.exitCode !== null || runtime.signalCode !== null) return;
      const exited = once(runtime, "exit");
      runtime.kill("SIGTERM");
      await exited;
    };

    const predecessor = spawn(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)"],
      { stdio: "ignore" },
    );
    const conflictingCandidate = spawn(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)"],
      { stdio: "ignore" },
    );
    let successorRuntime: ReturnType<typeof spawn> | null = null;
    try {
      if (!predecessor.pid || !conflictingCandidate.pid) {
        throw new Error("runtime action fixture missing PID");
      }
      const predecessorStartedAt = processStartedAt(predecessor.pid);
      const predecessorPreviewPort = 8123;
      const predecessorProxyPort = 3493;
      const head = git(fixture.root, "rev-parse", "HEAD");
      const initialInputFile = path.join(
        fixture.controlDir,
        "machine-action-runtime-input.json",
      );
      writeJson(initialInputFile, {
        execution: {
          environment: "none",
          write_mode: "NONE",
          target: {
            kind: "PREVIEW",
            executable_path: realpathSync(process.execPath),
            pid: predecessor.pid,
            started_at: predecessorStartedAt,
            preview_url:
              `http://127.0.0.1:${predecessorPreviewPort}`,
            build_head: head,
          },
        },
        resource_leases: [],
      });
      const initialLaunch = run(fixture, [
        "launch-template",
        "--goal", "usability",
        "--task", "TASK-A",
        "--role", "DEV",
        "--thread", THREADS.DEV,
        "--actor-capability-file",
        fixture.capabilities.DEV as string,
        "--input-file", initialInputFile,
        "--json",
      ]);
      expect(initialLaunch.code).toBe(0);
      const initialLaunchFile = path.join(
        fixture.controlDir,
        "machine-action-runtime-launch.json",
      );
      writeFileSync(initialLaunchFile, initialLaunch.stdout);
      expect(run(fixture, [
        "preflight",
        "--goal", "usability",
        "--task", "TASK-A",
        "--launch", initialLaunchFile,
        "--stage", "DEV",
        "--evidence-id",
        `preflight-machine-action-initial-${randomUUID()}`,
        "--actor-capability-file",
        fixture.capabilities.DEV as string,
        "--json",
      ]).code).toBe(0);
      const launched = parse(eventTemplate(
        fixture,
        "CAPTAIN",
        "LAUNCH_DEV",
        { payload: { launch_id: "launch-dev-usability-1" } },
      ));
      expect(acceptTemplate(fixture, launched, "CAPTAIN").code).toBe(0);

      const conflictingLaunch = JSON.parse(initialLaunch.stdout) as {
        execution: {
          target: {
            pid: number;
            started_at: string;
            preview_url: string;
          };
        };
        created_at: string;
      };
      conflictingLaunch.execution.target.pid = conflictingCandidate.pid;
      conflictingLaunch.execution.target.started_at =
        processStartedAt(conflictingCandidate.pid);
      conflictingLaunch.execution.target.preview_url =
        "http://127.0.0.1:8124";
      conflictingLaunch.created_at = "2026-07-26T00:00:01.000Z";
      const conflictingLaunchFile = path.join(
        fixture.controlDir,
        "machine-action-runtime-conflict.json",
      );
      writeJson(conflictingLaunchFile, conflictingLaunch);
      const rejected = run(fixture, [
        "preflight",
        "--goal", "usability",
        "--task", "TASK-A",
        "--launch", conflictingLaunchFile,
        "--stage", "DEV",
        "--evidence-id",
        `preflight-machine-action-conflict-${randomUUID()}`,
        "--actor-capability-file",
        fixture.capabilities.DEV as string,
        "--json",
      ]);
      expect(rejected.code).toBe(1);
      expect(`${rejected.stdout}\n${rejected.stderr}`).toContain(
        "LAUNCH_ID_CONFLICT",
      );

      type RotationAction = {
        type: "REQUEST_RUNTIME_ROTATION";
        operation_id: string;
        event_id: string;
        successor_launch_id: string;
        expected_state_revision: number;
        expected_control_epoch: number;
        hold_id: string;
        hold_event_id: string;
        predecessor_incarnation: number;
        predecessor_launch_id: string;
        predecessor_launch_sha256: string;
        successor_incarnation: number;
        reason: string;
        incident_ref: string;
        dispatch: {
          coordinator_role: string;
          executor_binding: string;
          executor: {
            role: string;
            thread_id: string;
            host_id: string;
            attempt: number;
          };
          capability_mode: string;
        };
        execution_plan: {
          schema_version: number;
          command: string;
          arguments: Record<string, string | number | boolean>;
          capability: {
            argument: string;
            source: string;
          };
        };
      };
      const rotationActionFrom = (
        state: TaskState & {
          maintenance_actions: Array<Record<string, unknown>>;
        },
      ): RotationAction => {
        const action = state.maintenance_actions.find(
          (candidate) => (
            candidate.type === "REQUEST_RUNTIME_ROTATION"
          ),
        );
        if (!action) throw new Error("missing runtime rotation action");
        return action as unknown as RotationAction;
      };

      const held = taskState(fixture) as TaskState & {
        maintenance_actions: Array<Record<string, unknown>>;
      };
      const rotationAction = rotationActionFrom(held);
      const operationMatch =
        /^runtime-rotation-([0-9a-f]{32})$/.exec(
          rotationAction.operation_id,
        );
      expect(operationMatch).not.toBeNull();
      const operationDigest = operationMatch?.[1] as string;
      expect(rotationAction).toMatchObject({
        type: "REQUEST_RUNTIME_ROTATION",
        goal_id: "usability",
        task_id: "TASK-A",
        repository_worktree: realpathSync(fixture.root),
        event_id: `runtime-rotated-${operationDigest}`,
        successor_launch_id:
          `launch-dev-runtime-i2-${operationDigest}`,
        expected_state_revision: held.state_revision,
        expected_control_epoch: held.control_epoch,
        predecessor_incarnation: 1,
        predecessor_launch_id: "launch-dev-usability-1",
        predecessor_launch_sha256:
          expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        successor_incarnation: 2,
        dispatch: {
          coordinator_role: "CAPTAIN",
          executor_binding: "EXACT_ACTIVE_CAPTAIN",
          executor: {
            role: "CAPTAIN",
            thread_id: THREADS.CAPTAIN,
            host_id: "local",
            attempt: 1,
          },
          capability_mode: "EXACT_CAPTAIN_CAPABILITY",
        },
        execution_plan: {
          schema_version: 1,
          command: "rotate-runtime",
          arguments: expect.objectContaining({
            repository_worktree: realpathSync(fixture.root),
            goal: "usability",
            task: "TASK-A",
            role: "DEV",
            worker_thread: THREADS.DEV,
            predecessor_incarnation: 1,
            predecessor_launch: "launch-dev-usability-1",
            expected_predecessor_launch_sha256:
              rotationAction.predecessor_launch_sha256,
            successor_launch: rotationAction.successor_launch_id,
            hold: rotationAction.hold_id,
            expected_state_revision: held.state_revision,
            expected_control_epoch: held.control_epoch,
            reason: rotationAction.reason,
            incident_ref: rotationAction.incident_ref,
            captain_thread: THREADS.CAPTAIN,
            event_id: rotationAction.event_id,
            json: true,
          }),
          capability: {
            argument: "--captain-capability-file",
            source: "EXACT_CAPTAIN_CAPABILITY",
          },
        },
      });
      expect(rotationAction.hold_event_id).toMatch(
        /^[A-Za-z0-9][A-Za-z0-9._:-]*$/,
      );
      expect(rotationAction.incident_ref).toContain(
        rotationAction.hold_event_id,
      );
      expect(JSON.stringify(rotationAction)).not.toContain(
        String(fixture.capabilities.CAPTAIN),
      );

      const identicalRead = rotationActionFrom(
        taskState(fixture) as TaskState & {
          maintenance_actions: Array<Record<string, unknown>>;
        },
      );
      expect(identicalRead).toEqual(rotationAction);

      const heartbeat = parse(eventTemplate(
        fixture,
        "CAPTAIN",
        "HEARTBEAT",
        {
          payload: {
            status: "active",
            lease_ms: 3600000,
          },
        },
      ));
      expect(acceptTemplate(fixture, heartbeat, "CAPTAIN").code).toBe(0);
      const afterHeartbeat = taskState(fixture) as TaskState & {
        maintenance_actions: Array<Record<string, unknown>>;
      };
      const refreshedAction = rotationActionFrom(afterHeartbeat);
      expect(afterHeartbeat.state_revision).toBe(held.state_revision + 1);
      expect(refreshedAction).toMatchObject({
        operation_id: rotationAction.operation_id,
        event_id: rotationAction.event_id,
        successor_launch_id: rotationAction.successor_launch_id,
        expected_state_revision: afterHeartbeat.state_revision,
        expected_control_epoch: held.control_epoch,
        predecessor_launch_sha256:
          rotationAction.predecessor_launch_sha256,
        execution_plan: {
          arguments: expect.objectContaining({
            expected_state_revision: afterHeartbeat.state_revision,
            expected_control_epoch: held.control_epoch,
          }),
        },
      });

      await stopRuntime(predecessor);
      const argumentsMap = refreshedAction.execution_plan.arguments;
      const rotated = run(fixture, [
        refreshedAction.execution_plan.command,
        "--repository-worktree",
        String(argumentsMap.repository_worktree),
        "--goal", String(argumentsMap.goal),
        "--task", String(argumentsMap.task),
        "--role", String(argumentsMap.role),
        "--worker-thread", String(argumentsMap.worker_thread),
        "--predecessor-incarnation",
        String(argumentsMap.predecessor_incarnation),
        "--predecessor-launch",
        String(argumentsMap.predecessor_launch),
        "--expected-predecessor-launch-sha256",
        String(argumentsMap.expected_predecessor_launch_sha256),
        "--successor-launch",
        String(argumentsMap.successor_launch),
        "--hold", String(argumentsMap.hold),
        "--expected-state-revision",
        String(argumentsMap.expected_state_revision),
        "--expected-control-epoch",
        String(argumentsMap.expected_control_epoch),
        "--reason", String(argumentsMap.reason),
        "--incident-ref", String(argumentsMap.incident_ref),
        "--captain-thread", String(argumentsMap.captain_thread),
        "--captain-capability-file",
        fixture.capabilities.CAPTAIN as string,
        "--event-id", String(argumentsMap.event_id),
        "--json",
      ]);
      if (rotated.code !== 0) {
        throw new Error(rotated.stderr || rotated.stdout);
      }

      const rotatedState = taskState(fixture) as TaskState & {
        maintenance_actions: Array<Record<string, unknown>>;
      };
      const preflightAction = rotatedState.maintenance_actions.find(
        (candidate) => (
          candidate.type === "REQUEST_RUNTIME_PREFLIGHT"
        ),
      );
      expect(preflightAction).toMatchObject({
        type: "REQUEST_RUNTIME_PREFLIGHT",
        actor_role: "CAPTAIN",
        requested_action: "LAUNCH_TEMPLATE_AND_PREFLIGHT",
        operation_id:
          expect.stringMatching(/^runtime-preflight-[0-9a-f]{32}$/),
        rotation_event_id: rotationAction.event_id,
        hold_id: rotationAction.hold_id,
        successor_incarnation: 2,
        successor_launch_id: rotationAction.successor_launch_id,
        expected_state_revision: rotatedState.state_revision,
        expected_control_epoch: rotatedState.control_epoch,
        dispatch: {
          coordinator_role: "CAPTAIN",
          executor_binding: "EXACT_ACTIVE_DEV",
          executor: {
            role: "DEV",
            thread_id: THREADS.DEV,
            host_id: "local",
            attempt: 1,
          },
          capability_mode: "EXACT_WORKER_CAPABILITY",
        },
        resource_leases: [],
        freshness_contract: {
          predecessor: {
            pid: predecessor.pid,
            started_at: predecessorStartedAt,
            preview_port: predecessorPreviewPort,
            proxy_port: predecessorProxyPort,
          },
          successor: {
            pid: "FRESH",
            started_at: "AFTER_PREDECESSOR",
            preview_port: "FRESH",
            proxy_port: "FRESH_DERIVED_GROUP",
            same_executable: true,
            same_node_version: true,
            same_pnpm_version: true,
          },
        },
        evidence_id_mode: {
          kind: "AUTO_FROM_EXACT_LAUNCH",
          algorithm: "RUNTIME_PREFLIGHT_EVIDENCE_V1",
          prefix: "preflight-runtime-",
        },
        execution_plan: {
          schema_version: 1,
          runtime_broker: expect.objectContaining({
            required_runtime:
              "FRESH_PREVIEW_PID_AND_FRESH_WEB_PROXY_PORT_GROUP",
          }),
          launch_template: expect.objectContaining({
            command: "launch-template",
            role: "DEV",
            thread: THREADS.DEV,
            capability: {
              argument: "--actor-capability-file",
              source: "EXACT_WORKER_CAPABILITY",
            },
          }),
          preflight: expect.objectContaining({
            command: "preflight",
            stage: "DEV",
            evidence_id_mode: "AUTO_FROM_EXACT_LAUNCH",
            capability: {
              argument: "--actor-capability-file",
              source: "EXACT_WORKER_CAPABILITY",
            },
          }),
        },
      });
      expect(JSON.stringify(preflightAction)).not.toContain(
        String(fixture.capabilities.DEV),
      );
      const successorExecutionPlan = (preflightAction as unknown as {
        execution_plan: {
          launch_template: { repository_worktree: string };
          preflight: { repository_worktree: string };
        };
      }).execution_plan;

      await new Promise((resolve) => setTimeout(resolve, 1100));
      successorRuntime = spawn(
        process.execPath,
        ["-e", "setInterval(() => {}, 1000)"],
        { stdio: "ignore" },
      );
      if (!successorRuntime.pid) {
        throw new Error("runtime action fixture missing successor PID");
      }
      const successorInputFile = path.join(
        fixture.controlDir,
        "machine-action-runtime-successor-input.json",
      );
      writeJson(successorInputFile, {
        execution: {
          environment: "none",
          write_mode: "NONE",
          target: {
            kind: "PREVIEW",
            executable_path: realpathSync(process.execPath),
            pid: successorRuntime.pid,
            started_at: processStartedAt(successorRuntime.pid),
            preview_url: "http://127.0.0.1:8125",
            build_head: head,
          },
        },
        resource_leases: [],
      });
      const successorLaunch = run(fixture, [
        "launch-template",
        "--repository-worktree",
        successorExecutionPlan.launch_template.repository_worktree,
        "--goal", "usability",
        "--task", "TASK-A",
        "--role", "DEV",
        "--thread", THREADS.DEV,
        "--actor-capability-file",
        fixture.capabilities.DEV as string,
        "--input-file", successorInputFile,
        "--json",
      ]);
      expect(successorLaunch.code).toBe(0);
      const successorLaunchFile = path.join(
        fixture.controlDir,
        "machine-action-runtime-successor-launch.json",
      );
      writeFileSync(successorLaunchFile, successorLaunch.stdout);
      const successorPreflight = run(fixture, [
        "preflight",
        "--repository-worktree",
        successorExecutionPlan.preflight.repository_worktree,
        "--goal", "usability",
        "--task", "TASK-A",
        "--launch", successorLaunchFile,
        "--stage", "DEV",
        "--actor-capability-file",
        fixture.capabilities.DEV as string,
        "--json",
      ]);
      expect(successorPreflight.code).toBe(0);
      expect(parse<{ evidence_id: string }>(successorPreflight).evidence_id)
        .toMatch(/^preflight-runtime-[0-9a-f]{32}$/);
      const afterPreflight = taskState(fixture) as TaskState & {
        maintenance_actions: Array<Record<string, unknown>>;
      };
      expect(afterPreflight.maintenance_actions).not.toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: "REQUEST_RUNTIME_PREFLIGHT",
          }),
        ]),
      );
    } finally {
      await stopRuntime(predecessor);
      await stopRuntime(conflictingCandidate);
      if (successorRuntime) await stopRuntime(successorRuntime);
    }
  }, 180000);

  test.each(["BROWSER", "ELECTRON"] as const)(
    "%s source advance projects exact fresh DEV recovery, not candidate preflight",
    (targetKind) => {
      const fixture = makeFixture();
      expect(scaffold(fixture).code).toBe(0);
      commitScaffold(fixture);
      initialize(fixture);
      const foreman = register(fixture, "FOREMAN");
      const captain = register(
        fixture,
        "CAPTAIN",
        String(foreman.actor_capability_file),
      );
      enterP1Committed(fixture);
      register(fixture, "DEV", String(captain.actor_capability_file));

      const profileDir = realpathSync(mkdtempSync(path.join(
        tmpdir(),
        `goalctl-${targetKind.toLowerCase()}-profile-`,
      )));
      const runtime = spawn(
        process.execPath,
        [
          "-e",
          "setInterval(() => {}, 1000)",
          profileDir,
        ],
        { stdio: "ignore" },
      );
      expect(runtime.pid).toBeDefined();
      try {
        const ps = existsSync("/bin/ps") ? "/bin/ps" : "/usr/bin/ps";
        const started = execFileSync(
          ps,
          ["-p", String(runtime.pid), "-o", "lstart="],
          {
            encoding: "utf8",
            env: {
              PATH: "/usr/bin:/bin",
              LANG: "C",
              LC_ALL: "C",
              TZ: "UTC",
              NODE_ENV: "test",
            },
          },
        ).trim();
        const initialHead = git(fixture.root, "rev-parse", "HEAD");
        const inputFile = path.join(
          fixture.controlDir,
          `${targetKind.toLowerCase()}-launch-input.json`,
        );
        writeJson(inputFile, {
          execution: {
            environment: "none",
            write_mode: "NONE",
            target: {
              kind: targetKind,
              executable_path: realpathSync(process.execPath),
              pid: runtime.pid,
              started_at:
                new Date(Date.parse(`${started} UTC`)).toISOString(),
              user_data_dir: profileDir,
              build_head: initialHead,
            },
          },
          resource_leases: [],
        });
        const initialLaunch = run(fixture, [
          "launch-template",
          "--goal", "usability",
          "--task", "TASK-A",
          "--role", "DEV",
          "--thread", THREADS.DEV,
          "--actor-capability-file",
          fixture.capabilities.DEV as string,
          "--input-file", inputFile,
          "--json",
        ]);
        expect(initialLaunch.code).toBe(0);
        const initialLaunchFile = path.join(
          fixture.controlDir,
          `${targetKind.toLowerCase()}-launch.json`,
        );
        writeFileSync(initialLaunchFile, initialLaunch.stdout);
        const initialPreflight = run(fixture, [
          "preflight",
          "--goal", "usability",
          "--task", "TASK-A",
          "--launch", initialLaunchFile,
          "--stage", "DEV",
          "--evidence-id",
          `preflight-${targetKind.toLowerCase()}-${randomUUID()}`,
          "--actor-capability-file",
          fixture.capabilities.DEV as string,
          "--json",
        ]);
        if (initialPreflight.code !== 0) {
          throw new Error(
            initialPreflight.stderr || initialPreflight.stdout,
          );
        }
        const launched = parse(eventTemplate(
          fixture,
          "CAPTAIN",
          "LAUNCH_DEV",
          { payload: { launch_id: "launch-dev-usability-1" } },
        ));
        expect(acceptTemplate(
          fixture,
          launched,
          "CAPTAIN",
        ).code).toBe(0);

        writeFileSync(
          path.join(fixture.root, `${targetKind.toLowerCase()}-candidate.txt`),
          "candidate\n",
        );
        git(fixture.root, "add", ".");
        git(fixture.root, "commit", "-qm", `${targetKind} candidate`);
        const projected = taskState(fixture) as TaskState & {
          launch_scope: string;
          next_actions: Array<Record<string, unknown>>;
          maintenance_actions: Array<Record<string, unknown>>;
        };
        expect(projected.launch_scope).toBe(
          "FRESH_RUNTIME_RECOVERY_REQUIRED",
        );
        expect(projected.maintenance_actions).not.toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              type: "REQUEST_CANDIDATE_PREFLIGHT",
            }),
          ]),
        );
        expect(projected.next_actions).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              type: "ROLE_LOST",
              actor_role: "CAPTAIN",
              target_role: "DEV",
              trigger: "SOURCE_HEAD_REQUIRES_FRESH_RUNTIME",
              target: expect.objectContaining({
                thread_id: THREADS.DEV,
                host_id: "local",
                attempt: 1,
                lease_until: expect.any(String),
              }),
              event_id: expect.stringMatching(
                /^role-lost-dev-task-a-a1-[0-9a-f]{16}$/,
              ),
              payload: expect.objectContaining({
                role: "DEV",
                fingerprint:
                  expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
                attempts: 1,
                expected_thread_id: THREADS.DEV,
                expected_host_id: "local",
                expected_attempt: 1,
                expected_lease_until: expect.any(String),
              }),
              requested_action:
                "EVENT_TEMPLATE_AND_ACCEPT_THEN_STANDARD_SOURCE_RECOVERY",
              forbidden_action: "SOURCE_CHECKPOINT_PREFLIGHT",
            }),
          ]),
        );
        expect(projected.next_actions).not.toEqual(
          expect.arrayContaining([
            expect.objectContaining({ type: "DEV_READY" }),
          ]),
        );
        const recoveryAction = projected.next_actions.find(
          (action) => (
            action.type === "ROLE_LOST"
              && action.target_role === "DEV"
          ),
        ) as {
          target: { lease_until: string };
          payload: { expected_lease_until: string };
        };
        expect(recoveryAction.payload.expected_lease_until).toBe(
          recoveryAction.target.lease_until,
        );

        const diagnosis = parse<{
          healthy: boolean;
          findings: Array<{
            task_id?: string;
            code: string;
            detail: string;
          }>;
        }>(run(fixture, [
          "doctor",
          "--goal", "usability",
          "--json",
        ]));
        expect(diagnosis.healthy).toBe(false);
        expect(diagnosis.findings).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              task_id: "TASK-A",
              code: "FRESH_RUNTIME_RECOVERY_REQUIRED",
              role: "DEV",
              detail: expect.stringContaining(targetKind),
            }),
          ]),
        );
      } finally {
        runtime.kill("SIGTERM");
        rmSync(profileDir, { recursive: true, force: true });
      }
    },
  );

  test("mechanically revalidates a source checkpoint hold without rotating the runtime", () => {
    const fixture = makeFixture();
    expect(scaffold(fixture).code).toBe(0);
    commitScaffold(fixture);
    initialize(fixture);
    const foreman = register(fixture, "FOREMAN");
    const captain = register(
      fixture,
      "CAPTAIN",
      String(foreman.actor_capability_file),
    );
    enterP1Committed(fixture);
    register(fixture, "DEV", String(captain.actor_capability_file));
    const inputFile = path.join(fixture.controlDir, "launch-input.json");
    writeJson(inputFile, {
      execution: {
        environment: "none",
        write_mode: "NONE",
        target: { kind: "NONE" },
      },
      resource_leases: [],
    });
    const initialLaunch = run(fixture, [
      "launch-template",
      "--goal", "usability",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--input-file", inputFile,
      "--json",
    ]);
    expect(initialLaunch.code).toBe(0);
    const initialLaunchValue = parse<{
      repository: { full_head: string };
    }>(initialLaunch);
    const initialLaunchFile = path.join(
      fixture.controlDir,
      "initial-launch.json",
    );
    writeFileSync(initialLaunchFile, initialLaunch.stdout);
    expect(run(fixture, [
      "preflight",
      "--goal", "usability",
      "--task", "TASK-A",
      "--launch", initialLaunchFile,
      "--stage", "DEV",
      "--evidence-id", `preflight-initial-${randomUUID()}`,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]).code).toBe(0);
    const launched = parse(eventTemplate(
      fixture,
      "CAPTAIN",
      "LAUNCH_DEV",
      { payload: { launch_id: "launch-dev-usability-1" } },
    ));
    expect(acceptTemplate(fixture, launched, "CAPTAIN").code).toBe(0);

    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const beforeHold = taskState(fixture);
    const holdSourceFile = path.join(
      fixture.controlDir,
      "source-checkpoint-hold.json",
    );
    const holdSourceBody = `${JSON.stringify({
      incident: "old decoder rejected a source-only checkpoint",
    })}\n`;
    writeFileSync(holdSourceFile, holdSourceBody);
    const holdEvidenceFile = path.join(
      fixture.controlDir,
      "source-checkpoint-hold-evidence.json",
    );
    const holdEvidenceId = `hold-source-checkpoint-${randomUUID()}`;
    writeJson(holdEvidenceFile, {
      schema_version: 1,
      evidence_id: holdEvidenceId,
      goal_id: "usability",
      task_id: "TASK-A",
      kind: "HOLD_ASSERTION",
      stage: "RUNTIME_PREFLIGHT",
      status: "BLOCKED",
      producer: {
        role: "DEV",
        thread_id: THREADS.DEV,
        host_id: "local",
      },
      state_revision: beforeHold.state_revision,
      packet: {
        revision: beforeHold.packet.revision,
        sha256: beforeHold.packet.sha256,
      },
      packet_sha256: beforeHold.packet.sha256,
      base_head: beforeHold.base_head,
      full_head: beforeHold.full_head,
      launch_id: "launch-dev-usability-1",
      created_at: "2026-07-26T00:00:00.000Z",
      uri: pathToFileURL(holdSourceFile).href,
      source_sha256: sha256(holdSourceBody),
      checks: [{
        name: "launch-invalid-stale-head",
        status: "FAIL",
        detail:
          `immutable head=${initialLaunchValue.repository.full_head}; candidate head=${candidateHead}`,
      }],
    });
    expect(run(fixture, [
      "evidence",
      "--goal", "usability",
      "--file", holdEvidenceFile,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]).code).toBe(0);
    const addHold = parse(eventTemplate(
      fixture,
      "DEV",
      "ADD_HOLD",
      {
        payload: {
          kind: "ENV_IDENTITY_INCIDENT",
          hold_id: "hold-source-checkpoint",
          reason: "old decoder stale-head false positive",
          evidence_id: holdEvidenceId,
        },
      },
    ));
    expect(acceptTemplate(fixture, addHold, "DEV").code).toBe(0);

    const held = taskState(fixture) as TaskState & {
      maintenance_actions: Array<Record<string, unknown>>;
    };
    const action = held.maintenance_actions.find(
      (candidate) => (
        candidate.type === "REQUEST_CANDIDATE_HOLD_REVALIDATION"
      ),
    ) as {
      operation_id: string;
      hold_id: string;
      hold_event_id: string;
      canonical_launch_sha256: string;
      candidate_head: string;
      resolution_evidence_id: string;
      resolve_event_id: string;
    };
    expect(action).toMatchObject({
      hold_id: "hold-source-checkpoint",
      candidate_head: candidateHead,
    });
    expect(held.maintenance_actions).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "REQUEST_RUNTIME_ROTATION" }),
      ]),
    );
    const forbiddenSuccessorLaunch =
      `launch-source-hold-rotation-${randomUUID()}`;
    const forbiddenRotation = run(fixture, [
      "rotate-runtime",
      "--goal", "usability",
      "--task", "TASK-A",
      "--role", "DEV",
      "--worker-thread", THREADS.DEV,
      "--predecessor-incarnation", "1",
      "--predecessor-launch", "launch-dev-usability-1",
      "--expected-predecessor-launch-sha256",
      action.canonical_launch_sha256,
      "--successor-launch", forbiddenSuccessorLaunch,
      "--hold", action.hold_id,
      "--expected-state-revision", String(held.state_revision),
      "--expected-control-epoch", String(held.control_epoch),
      "--reason", "attempt to bypass source checkpoint recovery",
      "--incident-ref", "incident://source-checkpoint/rotation-bypass",
      "--captain-thread", THREADS.CAPTAIN,
      "--captain-capability-file",
      fixture.capabilities.CAPTAIN as string,
      "--event-id", `rotate-source-hold-${randomUUID()}`,
      "--json",
    ]);
    expect(forbiddenRotation.code).toBe(2);
    expect(
      `${forbiddenRotation.stdout}\n${forbiddenRotation.stderr}`,
    ).toContain("RUNTIME_ROTATION_HOLD_NOT_ELIGIBLE");

    const rotationEnvelope = parse(eventTemplate(
      fixture,
      "CAPTAIN",
      "HEARTBEAT",
      {
        payload: {
          status: "active",
          lease_ms: 3600000,
        },
      },
    ));
    rotationEnvelope.event_id =
      `forged-source-hold-rotation-${randomUUID()}`;
    rotationEnvelope.type = "RUNTIME_ROTATED";
    rotationEnvelope.payload = {
      role: "DEV",
      worker_thread_id: THREADS.DEV,
      worker_host_id: "local",
      worker_attempt: 1,
      predecessor_incarnation: 1,
      successor_incarnation: 2,
      predecessor_launch_id: "launch-dev-usability-1",
      predecessor_launch_sha256:
        action.canonical_launch_sha256,
      successor_launch_id: forbiddenSuccessorLaunch,
      runtime_nonce: "a".repeat(40),
      hold_id: action.hold_id,
      reason: "handcrafted source hold rotation bypass",
      incident_ref: "incident://source-checkpoint/forged-rotation",
      retirement_proof: {
        schema_version: 1,
        kind: "LOCAL_PREVIEW_ZERO_WITNESS",
        predecessor_launch_id: "launch-dev-usability-1",
        predecessor_pid: 4242,
        preview_port: 8737,
        proxy_port: 4117,
        sample_count: 3,
        samples: [0, 1, 2].map((index) => ({
          observed_at: `2026-07-26T00:00:0${index}.000Z`,
          predecessor_pid_absent: true,
          preview_listener_absent: true,
          proxy_listener_absent: true,
          matching_process_count: 0,
        })),
      },
      lease_set_sha256: sha256("empty source hold lease set"),
    };
    const stateBeforeForgedRotation = taskState(fixture);
    const rotationPreviousControlDir = process.env.GOAL_CONTROL_DIR;
    const rotationPreviousTestMode =
      process.env.GOAL_CONTROL_TEST_MODE;
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    let forgedRotationFailure: unknown = null;
    try {
      let acceptedAtInjectionFailure: unknown = null;
      try {
        acceptEvent(
          fixture.root,
          rotationEnvelope,
          fixture.capabilities.CAPTAIN as string,
          {
            runtimeRotationOperation: true,
            pristineEventAcceptedAt: "2026-07-26T00:00:00.000Z",
          },
        );
      } catch (error) {
        acceptedAtInjectionFailure = error;
      }
      expect(acceptedAtInjectionFailure).toMatchObject({
        code: "INTERNAL_AUTHORIZATION_FORBIDDEN",
      });
      acceptEvent(
        fixture.root,
        rotationEnvelope,
        fixture.capabilities.CAPTAIN as string,
        { runtimeRotationOperation: true },
      );
    } catch (error) {
      forgedRotationFailure = error;
    } finally {
      if (rotationPreviousControlDir === undefined) {
        delete process.env.GOAL_CONTROL_DIR;
      } else {
        process.env.GOAL_CONTROL_DIR =
          rotationPreviousControlDir;
      }
      if (rotationPreviousTestMode === undefined) {
        delete process.env.GOAL_CONTROL_TEST_MODE;
      } else {
        process.env.GOAL_CONTROL_TEST_MODE =
          rotationPreviousTestMode;
      }
    }
    expect(forgedRotationFailure).toMatchObject({
      code: "RUNTIME_ROTATION_HOLD_NOT_ELIGIBLE",
    });
    expect(taskState(fixture)).toEqual(stateBeforeForgedRotation);
    expect(existsSync(path.join(
      fixture.controlDir,
      "goals",
      "usability",
      "launches",
      "TASK-A",
      `${forbiddenSuccessorLaunch}.json`,
    ))).toBe(false);

    writeFileSync(
      path.join(fixture.root, "stale-parent.txt"),
      "advance beyond sealed parent\n",
    );
    git(fixture.root, "add", "stale-parent.txt");
    git(fixture.root, "commit", "-qm", "advance beyond sealed parent");
    const advancedHead = git(fixture.root, "rev-parse", "HEAD");
    const blocked = taskState(fixture) as TaskState & {
      maintenance_actions: Array<Record<string, unknown>>;
    };
    for (const type of [
      "REQUEST_CANDIDATE_HOLD_REVALIDATION",
      "REQUEST_RUNTIME_ROTATION",
      "REQUEST_CANDIDATE_PREFLIGHT",
    ]) {
      expect(blocked.maintenance_actions).not.toEqual(
        expect.arrayContaining([
          expect.objectContaining({ type }),
        ]),
      );
    }
    const blockedDiagnosis = parse<{
      healthy: boolean;
      findings: Array<{
        task_id?: string;
        code: string;
        role?: string;
        detail: string;
      }>;
    }>(run(fixture, [
      "doctor",
      "--goal", "usability",
      "--json",
    ]));
    expect(blockedDiagnosis.healthy).toBe(false);
    expect(blockedDiagnosis.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          task_id: "TASK-A",
          code: "SOURCE_CHECKPOINT_HOLD_REVALIDATION_BLOCKED",
          role: "FOREMAN",
        }),
      ]),
    );
    const revalidationOptions = {
      goalId: "usability",
      taskId: "TASK-A",
      threadId: THREADS.FOREMAN,
      operationId: action.operation_id,
      holdId: action.hold_id,
      expectedHoldEventId: action.hold_event_id,
      expectedCanonicalLaunchSha256:
        action.canonical_launch_sha256,
      expectedCandidateHead: action.candidate_head,
      actorCapabilityFile:
        fixture.capabilities.FOREMAN as string,
    };
    const previousControlDir = process.env.GOAL_CONTROL_DIR;
    const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    let inspectionCount = 0;
    let driftFailure: unknown = null;
    try {
      revalidateSourceCheckpointHold(
        fixture.root,
        revalidationOptions,
        {
          inspectSourceCheckpointHold: (...args: unknown[]) => {
            const inspection = inspectSourceCheckpointHold(...args);
            inspectionCount += 1;
            return inspectionCount === 2
              ? {
                ...inspection,
                candidate_head: "0".repeat(40),
              }
              : inspection;
          },
        },
      );
    } catch (error) {
      driftFailure = error;
    } finally {
      if (previousControlDir === undefined) {
        delete process.env.GOAL_CONTROL_DIR;
      } else {
        process.env.GOAL_CONTROL_DIR = previousControlDir;
      }
      if (previousTestMode === undefined) {
        delete process.env.GOAL_CONTROL_TEST_MODE;
      } else {
        process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
      }
    }
    expect(driftFailure).toMatchObject({
      code: "SOURCE_CHECKPOINT_HOLD_CHANGED",
    });
    expect(inspectionCount).toBe(2);
    const command = [
      "revalidate-source-checkpoint-hold",
      "--goal", "usability",
      "--task", "TASK-A",
      "--thread", THREADS.FOREMAN,
      "--operation-id", action.operation_id,
      "--hold", action.hold_id,
      "--expected-hold-event-id", action.hold_event_id,
      "--expected-canonical-launch-sha256",
      action.canonical_launch_sha256,
      "--expected-candidate-head", action.candidate_head,
      "--actor-capability-file", fixture.capabilities.FOREMAN as string,
      "--json",
    ];
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_GENERATION =
      "throw";
    const generationInterrupted = run(fixture, command);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_GENERATION;
    expect(generationInterrupted.code).toBe(2);
    expect(
      `${generationInterrupted.stdout}\n${generationInterrupted.stderr}`,
    ).toContain("TEST_FAULT_AFTER_SOURCE_HOLD_GENERATION");
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_EVIDENCE = "1";
    const interrupted = run(fixture, command);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_HOLD_EVIDENCE;
    expect(interrupted.code).toBe(2);
    expect(`${interrupted.stdout}\n${interrupted.stderr}`).toContain(
      "TEST_FAULT_AFTER_SOURCE_HOLD_EVIDENCE",
    );
    const interveningHeartbeat = parse(eventTemplate(
      fixture,
      "FOREMAN",
      "HEARTBEAT",
      {
        payload: {
          status: "active",
          lease_ms: 3600000,
        },
      },
    ));
    const blockedHeartbeat = acceptTemplate(
      fixture,
      interveningHeartbeat,
      "FOREMAN",
    );
    expect(blockedHeartbeat.code).toBe(2);
    expect(
      `${blockedHeartbeat.stdout}\n${blockedHeartbeat.stderr}`,
    ).toContain("STORE_TRANSACTION_MISMATCH");
    const resolved = run(fixture, command);
    expect(resolved.code).toBe(0);
    expect(parse(resolved)).toMatchObject({
      operation: "SOURCE_CHECKPOINT_HOLD_REVALIDATION",
      idempotent: true,
      resolution_evidence_id: action.resolution_evidence_id,
      resolve_event_id: action.resolve_event_id,
    });
    const after = taskState(fixture) as TaskState & {
      holds: unknown[];
      launch_scope: string;
      maintenance_actions: Array<Record<string, unknown>>;
    };
    expect(after.holds).toEqual([]);
    expect(after.launch_scope).toBe(
      "SOURCE_CHECKPOINT_PREFLIGHT_REQUIRED",
    );
    expect(after.maintenance_actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "REQUEST_CANDIDATE_PREFLIGHT",
          candidate_head: advancedHead,
        }),
      ]),
    );
    const retry = run(fixture, command);
    expect(retry.code).toBe(0);
    expect(parse(retry)).toMatchObject({
      operation: "SOURCE_CHECKPOINT_HOLD_REVALIDATION",
      idempotent: true,
      resolution_evidence_id: action.resolution_evidence_id,
      resolve_event_id: action.resolve_event_id,
    });

    const beforeReusedHold = taskState(fixture);
    const reusedSourceFile = path.join(
      fixture.controlDir,
      "source-checkpoint-hold-reused.json",
    );
    const reusedSourceBody = `${JSON.stringify({
      incident: "a later source-only checkpoint reused the human hold label",
    })}\n`;
    writeFileSync(reusedSourceFile, reusedSourceBody);
    const reusedEvidenceId =
      `hold-source-checkpoint-reused-${randomUUID()}`;
    const reusedEvidenceFile = path.join(
      fixture.controlDir,
      "source-checkpoint-hold-reused-evidence.json",
    );
    writeJson(reusedEvidenceFile, {
      schema_version: 1,
      evidence_id: reusedEvidenceId,
      goal_id: "usability",
      task_id: "TASK-A",
      kind: "HOLD_ASSERTION",
      stage: "RUNTIME_PREFLIGHT",
      status: "BLOCKED",
      producer: {
        role: "DEV",
        thread_id: THREADS.DEV,
        host_id: "local",
      },
      state_revision: beforeReusedHold.state_revision,
      packet: {
        revision: beforeReusedHold.packet.revision,
        sha256: beforeReusedHold.packet.sha256,
      },
      packet_sha256: beforeReusedHold.packet.sha256,
      base_head: beforeReusedHold.base_head,
      full_head: beforeReusedHold.full_head,
      launch_id: "launch-dev-usability-1",
      created_at: "2026-07-26T00:01:00.000Z",
      uri: pathToFileURL(reusedSourceFile).href,
      source_sha256: sha256(reusedSourceBody),
      checks: [{
        name: "launch-invalid-stale-head",
        status: "FAIL",
        detail:
          `immutable head=${initialLaunchValue.repository.full_head}; candidate head=${advancedHead}`,
      }],
    });
    expect(run(fixture, [
      "evidence",
      "--goal", "usability",
      "--file", reusedEvidenceFile,
      "--actor-capability-file",
      fixture.capabilities.DEV as string,
      "--json",
    ]).code).toBe(0);
    const reusedAddHold = parse(eventTemplate(
      fixture,
      "DEV",
      "ADD_HOLD",
      {
        payload: {
          kind: "ENV_IDENTITY_INCIDENT",
          hold_id: action.hold_id,
          reason: "later source checkpoint incident",
          evidence_id: reusedEvidenceId,
        },
      },
    ));
    expect(acceptTemplate(
      fixture,
      reusedAddHold,
      "DEV",
    ).code).toBe(0);
    const reusedState = taskState(fixture) as TaskState & {
      holds: Array<{ hold_id: string }>;
      maintenance_actions: Array<Record<string, unknown>>;
    };
    const reusedAction = reusedState.maintenance_actions.find(
      (candidate) => (
        candidate.type === "REQUEST_CANDIDATE_HOLD_REVALIDATION"
      ),
    ) as {
      operation_id: string;
      hold_event_id: string;
      candidate_head: string;
    };
    expect(reusedAction).toMatchObject({
      candidate_head: advancedHead,
    });
    expect(reusedAction.operation_id).not.toBe(action.operation_id);
    expect(reusedAction.hold_event_id).not.toBe(action.hold_event_id);

    const staleAcceptedRetry = run(fixture, command);
    expect(staleAcceptedRetry.code).toBe(2);
    expect(
      `${staleAcceptedRetry.stdout}\n${staleAcceptedRetry.stderr}`,
    ).toContain("SOURCE_CHECKPOINT_HOLD_CHANGED");
    const afterStaleRetry = taskState(fixture) as TaskState & {
      holds: Array<{ hold_id: string }>;
    };
    expect(afterStaleRetry.holds).toHaveLength(1);
    expect(afterStaleRetry.holds[0]).toMatchObject({
      hold_id: action.hold_id,
    });
  });
});
