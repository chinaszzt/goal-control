import { execFileSync } from "child_process";
import { createHash, randomUUID } from "crypto";
import { createRequire } from "module";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const nodeRequire = createRequire(import.meta.url);
type TransactionKey = {
  schema_version: 1;
  kind: string;
  scope: Record<string, string>;
  stable_operation_id_sha256: string;
  request_sha256: string;
  key_sha256: string;
};
const {
  canonicalTransactionKey,
} = nodeRequire(path.join(ROOT, "scripts", "goal-control", "store.js")) as {
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
const {
  registrationRequiresWorkerBootstrap,
  workerBootstrapEventAllowsHeadAdvance,
} = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "worker-bootstrap-binding.js",
  ),
) as {
  registrationRequiresWorkerBootstrap: (
    manifest: Record<string, unknown>,
    role: string,
  ) => boolean;
  workerBootstrapEventAllowsHeadAdvance: (
    role: string,
    eventType: string,
  ) => boolean;
};
const {
  classifyLaunchIdentityHold,
  classifySupportedRuntimeIdentity,
} = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "launch-source-checkpoint.js",
  ),
) as {
  classifyLaunchIdentityHold: (
    root: string,
    state: Record<string, unknown>,
    goalId: string,
  ) => "SOURCE_ONLY" | "RUNTIME_IDENTITY" | "UNKNOWN";
  classifySupportedRuntimeIdentity: (
    canonical: Record<string, unknown>,
    candidate: Record<string, unknown>,
    options?: { requireRuntimeIdentityDelta?: boolean },
  ) => "RUNTIME_IDENTITY" | "UNKNOWN";
};
const { runtimePreflightEvidenceId } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "runtime-incarnation.js"),
) as {
  runtimePreflightEvidenceId: (launch: Record<string, unknown>) => string;
};
const { runPreflight } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "preflight.js"),
) as {
  runPreflight: (
    cwd: string,
    options: Record<string, unknown>,
    dependencies?: {
      beforeLiveChecks?: () => void;
      afterGenerationBeforeCallback?: () => void;
    },
  ) => Record<string, unknown>;
};
const { assertDevLaunchHead } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "goal.js"),
) as {
  assertDevLaunchHead: (
    worktree: string,
    state: Record<string, unknown>,
    session: Record<string, unknown>,
    launch: LaunchManifest,
    expectedHead: string,
  ) => boolean;
};

type CliResult = { code: number; stdout: string; stderr: string };
type Role = "FOREMAN" | "CAPTAIN" | "DEV";

type Fixture = {
  root: string;
  worker?: string;
  controlDir: string;
  manifest: string;
  manifestRelative: string;
  bootstrapPolicy?: string;
  bootstrapPolicyHash?: string;
  packetPath: string;
  packetHash: string;
  planHash: string;
  contextHash: string;
  baseHead: string;
  fullHead: string;
  lockfileHash: string;
  capabilities: Partial<Record<Role, string>>;
  taskNonce: string;
  registeredStateRevision: number;
  launch?: LaunchManifest;
  bootstrapCapabilityFile?: string;
  bootstrapCapabilityBytes?: string;
};

type FixtureOptions = {
  workerBootstrap?: boolean;
};

const THREADS: Record<Role, string> = {
  FOREMAN: "foreman-preflight-1",
  CAPTAIN: "captain-preflight-1",
  DEV: "dev-preflight-1",
};

function runCliFrom(
  fixture: Fixture,
  cwd: string,
  args: string[],
): CliResult {
  try {
    const stdout = execFileSync("node", [GOALCTL, ...args], {
      cwd,
      encoding: "utf8",
      stdio: "pipe",
      env: { ...process.env, GOAL_CONTROL_DIR: fixture.controlDir, GOAL_CONTROL_TEST_MODE: "1" },
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

function runCli(fixture: Fixture, args: string[]): CliResult {
  return runCliFrom(fixture, fixture.root, args);
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" }).trim();
}

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
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

function writeV2OddGeneration(
  fixture: Fixture,
  transactionKey: TransactionKey,
): void {
  const generationFile = path.join(fixture.controlDir, ".generation.json");
  const current = JSON.parse(readFileSync(
    generationFile,
    "utf8",
  )) as { generation: number };
  expect(current.generation % 2).toBe(0);
  const unsigned = {
    schema_version: 2,
    generation: current.generation + 1,
    active_transaction: transactionKey,
    updated_at: "2026-07-24T00:00:00.000Z",
  };
  writeFileSync(
    generationFile,
    `${JSON.stringify({
      ...unsigned,
      seal_sha256: hashObject(unsigned),
    }, null, 2)}\n`,
  );
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

function installPendingBootstrapConsumption(fixture: Fixture): string {
  expect(fixture.bootstrapCapabilityFile).toBeDefined();
  expect(fixture.bootstrapCapabilityBytes).toBeDefined();
  const metadataFile = path.join(
    fixture.controlDir,
    "goals",
    "demo",
    "goal.json",
  );
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

function makeFixture(options: FixtureOptions = {}): Fixture {
  const root = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-control-preflight-repo-"))
  );
  let controlDir = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-control-preflight-state-"))
  );
  git(root, "init", "-q", "-b", "main");
  if (options.workerBootstrap) {
    rmSync(controlDir, { recursive: true, force: true });
    controlDir = path.join(
      realpathSync(git(
        root,
        "rev-parse",
        "--path-format=absolute",
        "--git-common-dir",
      )),
      "goal-control",
      "v1",
    );
    mkdirSync(controlDir, { recursive: true });
    controlDir = realpathSync(controlDir);
  }
  git(root, "config", "user.email", "preflight@example.test");
  git(root, "config", "user.name", "Goal Preflight Test");

  const lockfileBody = "lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n";
  writeFileSync(path.join(root, "pnpm-lock.yaml"), lockfileBody);
  writeFileSync(path.join(root, "README.md"), "# preflight fixture\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "base");
  const baseHead = git(root, "rev-parse", "HEAD");

  const packetPath = "docs/planning/goals/demo/packets/TASK-A-r1.md";
  const absolutePacket = path.join(root, packetPath);
  mkdirSync(path.dirname(absolutePacket), { recursive: true });
  const packetBody = "# TASK-A r1\n\nImmutable preflight packet.\n";
  writeFileSync(absolutePacket, packetBody);
  const packetHash = sha256(packetBody);
  const issueDir = path.join(root, "docs", "issues", "4242");
  mkdirSync(issueDir, { recursive: true });
  const planBody = "# Preflight fixture plan\n";
  const contextBody = "# Preflight fixture context\n";
  writeFileSync(path.join(issueDir, "plan.md"), planBody);
  writeFileSync(path.join(issueDir, "context.md"), contextBody);
  const protocol = options.workerBootstrap
    ? {
      entry: "docs/planning/session-role-protocol.md",
      shared: "docs/planning/session-protocol/shared.md",
      foreman: "docs/planning/session-protocol/foreman.md",
      captain: "docs/planning/session-protocol/captain.md",
      role_kernel: "docs/planning/session-protocol/role-kernel.md",
    }
    : undefined;
  if (protocol) {
    for (const [name, relative] of Object.entries(protocol)) {
      const absolute = path.join(root, relative);
      mkdirSync(path.dirname(absolute), { recursive: true });
      writeFileSync(absolute, `# ${name}\n`);
    }
  }
  const bootstrapProtocol = "goalctl-worker-canary-bootstrap-v1";
  const bootstrapPolicyBody = [
    "# Worker canary bootstrap policy",
    "",
    `Worker-Canary-Bootstrap-Protocol: ${bootstrapProtocol}`,
    "",
  ].join("\n");
  const bootstrapPolicyRelative =
    "docs/planning/goals/demo/worker.canary-policy.md";
  if (options.workerBootstrap) {
    const absolute = path.join(root, bootstrapPolicyRelative);
    mkdirSync(path.dirname(absolute), { recursive: true });
    writeFileSync(absolute, bootstrapPolicyBody);
  }
  const manifestRelative =
    "docs/planning/goals/demo/manifest.json";
  const manifest = path.join(root, manifestRelative);
  writeFileSync(
    manifest,
    `${JSON.stringify(
      {
        schema_version: 1,
        goal_id: "demo",
        mode: "shadow",
        repository: { name_with_owner: "example-org/example-repo", base_branch: "main" },
        base_head: baseHead,
        ...(protocol ? { protocol } : {}),
        ...(options.workerBootstrap
          ? {
            worker_canary_bootstrap: {
              protocol: bootstrapProtocol,
              policy: {
                path: bootstrapPolicyRelative,
                sha256: sha256(bootstrapPolicyBody),
              },
            },
          }
          : {}),
        tasks: [
          {
            id: "TASK-A",
            dependencies: [],
            integration_order: 1,
            resource_requirements: [],
            packet: { revision: 1, path: packetPath, sha256: packetHash },
          },
        ],
      },
      null,
      2
    )}\n`
  );
  git(root, "add", ".");
  git(root, "commit", "-qm", "goal manifest and packet");
  git(root, "remote", "add", "origin", "https://github.com/example-org/example-repo.git");
  const fullHead = git(root, "rev-parse", "HEAD");
  let worker: string | undefined;
  if (options.workerBootstrap) {
    worker = `${root}-worker`;
    git(root, "worktree", "add", "--detach", "-q", worker, fullHead);
    worker = realpathSync(worker);
  }

  return {
    root,
    worker,
    controlDir,
    manifest,
    manifestRelative,
    bootstrapPolicy: options.workerBootstrap
      ? bootstrapPolicyRelative
      : undefined,
    bootstrapPolicyHash: options.workerBootstrap
      ? sha256(bootstrapPolicyBody)
      : undefined,
    packetPath,
    packetHash,
    planHash: sha256(planBody),
    contextHash: sha256(contextBody),
    baseHead,
    fullHead,
    lockfileHash: sha256(lockfileBody),
    capabilities: {},
    taskNonce: "",
    registeredStateRevision: 0,
  };
}

function parse(result: CliResult): Record<string, unknown> {
  expect(result.stdout).not.toBe("");
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

function initialize(fixture: Fixture): string {
  const result = runCli(fixture, ["init", "--manifest", fixture.manifest, "--json"]);
  expect(result.code).toBe(0);
  return String(parse(result).bootstrap_capability_file);
}

function register(fixture: Fixture, role: Role, authorizer: string): Record<string, unknown> {
  const args = [
    "register-role",
    "--goal",
    "demo",
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
    role === "FOREMAN" ? "--bootstrap-capability-file" : "--authorizer-capability-file",
    authorizer,
    "--json",
  ];
  if (role === "DEV") args.splice(args.length - 1, 0, "--launch-id", "launch-dev-preflight-1");
  const result = runCli(fixture, args);
  expect(result.code).toBe(0);
  const value = parse(result);
  fixture.capabilities[role] = String(value.actor_capability_file);
  return value;
}

type TaskState = {
  state_revision: number;
  control_epoch: number;
  base_head: string;
  full_head: string;
  packet: { revision: number; sha256: string };
  holds: Array<{
    hold_id: string;
    kind: string;
    hard: boolean;
    evidence?: { uri?: string };
  }>;
  maintenance_actions?: Array<Record<string, unknown>>;
};

function taskState(fixture: Fixture): TaskState {
  const result = runCli(fixture, ["status", "--goal", "demo", "--task", "TASK-A", "--json"]);
  if (result.code !== 0) {
    throw new Error(`status failed: ${result.stderr || result.stdout}`);
  }
  const body = parse(result) as { tasks: { "TASK-A": TaskState } };
  return body.tasks["TASK-A"];
}

function sendEventFrom(
  fixture: Fixture,
  cwd: string,
  type: string,
  role: Role,
  sequence: number,
  payload: Record<string, unknown> = {},
  fullHead?: string,
  stableEventId?: string,
): { eventId: string; result: CliResult } {
  const state = taskState(fixture);
  const eventId = stableEventId ?? randomUUID();
  const event = {
    schema_version: 1,
    event_id: eventId,
    goal_id: "demo",
    task_id: "TASK-A",
    type,
    actor: { role, thread_id: THREADS[role], host_id: "local" },
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
  const eventFile = path.join(inputDir, `${eventId}.json`);
  writeFileSync(eventFile, `${JSON.stringify(event, null, 2)}\n`);
  return {
    eventId,
    result: runCliFrom(fixture, cwd, ["event", "--goal", "demo", "--file", eventFile, "--actor-capability-file", fixture.capabilities[role] as string, "--json"]),
  };
}

function sendEvent(
  fixture: Fixture,
  type: string,
  role: Role,
  sequence: number,
  payload: Record<string, unknown> = {},
  fullHead?: string,
  stableEventId?: string,
): { eventId: string; result: CliResult } {
  return sendEventFrom(
    fixture,
    fixture.root,
    type,
    role,
    sequence,
    payload,
    fullHead,
    stableEventId,
  );
}

function enterP1Committed(
  fixture: Fixture,
): Record<string, unknown> {
  const bootstrap = initialize(fixture);
  fixture.bootstrapCapabilityFile = bootstrap;
  fixture.bootstrapCapabilityBytes = readFileSync(bootstrap, "utf8");
  const foreman = register(fixture, "FOREMAN", bootstrap);
  const captain = register(fixture, "CAPTAIN", String(foreman.actor_capability_file));
  expect(sendEvent(fixture, "START_P1", "CAPTAIN", 1).result.code).toBe(0);
  expect(
    sendEvent(fixture, "P1_READY", "CAPTAIN", 2, {
      plan_path: "docs/issues/4242/plan.md",
      plan_sha256: fixture.planHash,
      context_path: "docs/issues/4242/context.md",
      context_sha256: fixture.contextHash,
    }).result.code
  ).toBe(0);
  const approval = sendEvent(fixture, "P1_APPROVED", "FOREMAN", 1, {
    plan_path: "docs/issues/4242/plan.md",
    plan_sha256: fixture.planHash,
    context_path: "docs/issues/4242/context.md",
    context_sha256: fixture.contextHash,
    approval_ref: "user://issue-4242/approved",
  });
  expect(approval.result.code).toBe(0);
  expect(
    sendEvent(
      fixture,
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
    ).result.code
  ).toBe(0);
  return captain;
}

function enterDevActive(fixture: Fixture): void {
  const captain = enterP1Committed(fixture);
  const dev = register(fixture, "DEV", String(captain.actor_capability_file));
  fixture.taskNonce = String(dev.task_nonce);
  fixture.registeredStateRevision = Number((dev.session as { registered_state_revision: number }).registered_state_revision);
  const initialPreflight = preflight(fixture, launchManifest(fixture));
  expect(initialPreflight.code).toBe(0);
  expect(
    sendEvent(
      fixture,
      "LAUNCH_DEV",
      "CAPTAIN",
      4,
      { launch_id: "launch-dev-preflight-1" }
    ).result
  ).toMatchObject({ code: 0, stderr: "" });
}

type LaunchManifest = {
  schema_version: number;
  launch_id: string;
  goal_id: string;
  task_id: string;
  role: string;
  control_epoch: number;
  state_revision: number;
  thread: { id: string; host_id: string; cwd: string; title?: string };
  packet: { revision: number; path: string; sha256: string };
  repository: {
    name_with_owner: string;
    origin_url: string;
    base_branch: string;
    base_head: string;
    full_head: string;
    branch: string;
    root: string;
    worktree: string;
  };
  runtime: { node_version: string; pnpm_version: string; lockfile_sha256: string };
  runtime_incarnation?: {
    epoch: number;
    nonce: string;
    rotation_event_id: string;
  };
  execution: {
    environment: string;
    write_mode: string;
    task_nonce: string;
    identity_probe?: { path: string; sha256: string };
    target: {
      kind: string;
      executable_path: string;
      build_head?: string;
      pid?: number;
      started_at?: string;
      preview_url?: string;
      user_data_dir?: string;
    };
  };
  resource_leases: string[];
  created_at: string;
};

function launchManifest(fixture: Fixture): LaunchManifest {
  if (fixture.launch) return JSON.parse(JSON.stringify(fixture.launch)) as LaunchManifest;
  const probeFile = path.join(fixture.controlDir, `identity-${randomUUID()}.json`);
  const probe = {
    schema_version: 1,
    task_nonce: fixture.taskNonce,
    environment: "testing",
    write_mode: "TESTING_WRITE",
    observed_at: "2026-07-22T00:00:00.000Z",
    source: "test-fixture",
  };
  const probeBody = `${JSON.stringify(probe, null, 2)}\n`;
  writeFileSync(probeFile, probeBody);
  fixture.launch = {
    schema_version: 1,
    launch_id: "launch-dev-preflight-1",
    goal_id: "demo",
    task_id: "TASK-A",
    role: "DEV",
    control_epoch: 0,
    state_revision: fixture.registeredStateRevision,
    thread: { id: THREADS.DEV, host_id: "local", cwd: fixture.root },
    packet: { revision: 1, path: fixture.packetPath, sha256: fixture.packetHash },
    repository: {
      name_with_owner: "example-org/example-repo",
      origin_url: "https://github.com/example-org/example-repo.git",
      base_branch: "main",
      base_head: fixture.baseHead,
      full_head: fixture.fullHead,
      branch: "main",
      root: fixture.root,
      worktree: fixture.root,
    },
    runtime: {
      node_version: process.version,
      pnpm_version: execFileSync("pnpm", ["--version"], { encoding: "utf8" }).trim(),
      lockfile_sha256: fixture.lockfileHash,
    },
    execution: {
      environment: "testing",
      write_mode: "TESTING_WRITE",
      task_nonce: fixture.taskNonce,
      identity_probe: { path: realpathSync(probeFile), sha256: sha256(probeBody) },
      target: {
        kind: "CLI",
        executable_path: realpathSync(process.execPath),
        build_head: fixture.fullHead,
      },
    },
    resource_leases: [],
    created_at: "2026-07-22T00:00:00.000Z",
  };
  return JSON.parse(JSON.stringify(fixture.launch)) as LaunchManifest;
}

function writeLaunch(fixture: Fixture, launch: LaunchManifest): string {
  const file = path.join(fixture.controlDir, `launch-${randomUUID()}.json`);
  writeFileSync(file, `${JSON.stringify(launch, null, 2)}\n`);
  return file;
}

function preflight(
  fixture: Fixture,
  launch: LaunchManifest,
  evidenceId = `preflight-${randomUUID()}`
): CliResult {
  return preflightFrom(fixture, fixture.root, launch, evidenceId);
}

function preflightFrom(
  fixture: Fixture,
  cwd: string,
  launch: LaunchManifest,
  evidenceId = `preflight-${randomUUID()}`
): CliResult {
  return runCliFrom(fixture, cwd, [
    "preflight",
    "--goal",
    "demo",
    "--task",
    "TASK-A",
    "--launch",
    writeLaunch(fixture, launch),
    "--stage",
    "DEV",
    "--evidence-id",
    evidenceId,
    "--actor-capability-file",
    fixture.capabilities.DEV as string,
    "--json",
  ]);
}

function expectFailedCheck(result: CliResult, code: string): void {
  expect(result.code).not.toBe(0);
  if (!result.stdout) {
    throw new Error(
      `preflight failed without JSON evidence: ${result.stderr || "<empty stderr>"}`,
    );
  }
  const evidence = parse(result) as { status: string; checks: Array<{ status: string; detail?: string }> };
  expect(evidence.status).toBe("FAIL");
  expect(JSON.stringify(evidence.checks)).toContain(code);
}

type WorkerBootstrap = {
  receiptFile: string;
  receiptSha256: string;
  planSha256: string;
  operationId: string;
  challenge: string;
  workerBranch: string;
};

function bootstrapDynamicDev(fixture: Fixture): WorkerBootstrap {
  expect(fixture.worker).toBeDefined();
  expect(fixture.bootstrapPolicy).toBeDefined();
  expect(fixture.bootstrapPolicyHash).toBeDefined();
  const operationId = `bootstrap-demo-task-a-dev-${
    createHash("sha256").update(fixture.root).digest("hex").slice(0, 16)
  }`;
  const challenge = "cd".repeat(32);
  const binding = [
    "--manifest", fixture.manifestRelative,
    "--role", "DEV",
    "--task", "TASK-A",
    "--expected-head", fixture.fullHead,
    "--operation-id", operationId,
    "--challenge", challenge,
    "--canary-policy", fixture.bootstrapPolicy as string,
    "--canary-policy-sha256", fixture.bootstrapPolicyHash as string,
  ];
  const planResult = runCli(fixture, [
    "canary-bootstrap-plan",
    "--repository-worktree", fixture.root,
    ...binding,
    "--json",
  ]);
  expect(planResult).toMatchObject({ code: 0, stderr: "" });
  const planOutput = parse(planResult);
  const planSha256 = String(planOutput.identity_plan_sha256);
  const plan = planOutput.identity_plan as Record<string, unknown>;
  const workerBranch = String(plan.worker_branch);

  const inspectResult = runCliFrom(
    fixture,
    fixture.worker as string,
    [
      "canary-bootstrap-inspect",
      "--goal-worktree", fixture.root,
      ...binding,
      "--expected-identity-plan-sha256", planSha256,
      "--worker-thread", THREADS.DEV,
      "--worker-host", "local",
      "--json",
    ],
  );
  expect(inspectResult).toMatchObject({ code: 0, stderr: "" });
  const observation = parse(inspectResult);

  const prepareResult = runCli(fixture, [
    "canary-bootstrap-prepare",
    "--repository-worktree", fixture.root,
    ...binding,
    "--expected-identity-plan-sha256", planSha256,
    "--expected-observation-sha256",
    String(observation.identity_observation_sha256),
    "--worker-thread", THREADS.DEV,
    "--worker-host", "local",
    "--worker-worktree", fixture.worker as string,
    "--json",
  ]);
  expect(prepareResult).toMatchObject({ code: 0, stderr: "" });
  const prepared = parse(prepareResult);
  const receiptFile = String(prepared.worker_bootstrap_receipt_file);
  const receiptSha256 =
    String(prepared.worker_bootstrap_receipt_sha256);

  const canaryResult = runCliFrom(
    fixture,
    fixture.worker as string,
    [
      "canary-plan",
      "--repository-worktree", fixture.root,
      "--manifest", fixture.manifestRelative,
      "--role", "DEV",
      "--task", "TASK-A",
      "--worker-bootstrap-receipt", receiptFile,
      "--worker-bootstrap-receipt-sha256", receiptSha256,
      "--worker-bootstrap-operation-id", operationId,
      "--worker-bootstrap-challenge", challenge,
      "--worker-bootstrap-identity-plan-sha256", planSha256,
      "--worker-thread", THREADS.DEV,
      "--worker-host", "local",
      "--json",
    ],
  );
  expect(canaryResult).toMatchObject({ code: 0, stderr: "" });

  return {
    receiptFile,
    receiptSha256,
    planSha256,
    operationId,
    challenge,
    workerBranch,
  };
}

function dynamicRegistrationArgs(
  fixture: Fixture,
  bootstrap: WorkerBootstrap,
): string[] {
  return [
    "register-role",
    "--repository-worktree", fixture.root,
    "--goal", "demo",
    "--task", "TASK-A",
    "--role", "DEV",
    "--thread", THREADS.DEV,
    "--host", "local",
    "--attempt", "1",
    "--launch-id", "launch-dev-preflight-1",
    "--authorizer-capability-file",
    fixture.capabilities.CAPTAIN as string,
    "--worker-bootstrap-receipt", bootstrap.receiptFile,
    "--worker-bootstrap-receipt-sha256", bootstrap.receiptSha256,
    "--worker-bootstrap-operation-id", bootstrap.operationId,
    "--worker-bootstrap-challenge", bootstrap.challenge,
    "--worker-bootstrap-identity-plan-sha256",
    bootstrap.planSha256,
    "--json",
  ];
}

function launchTemplateInput(fixture: Fixture): string {
  const file = path.join(fixture.controlDir, "launch-template-input.json");
  writeFileSync(file, `${JSON.stringify({
    thread_title: "dynamic DEV",
    execution: {
      environment: "none",
      write_mode: "NONE",
      target: { kind: "NONE" },
    },
    resource_leases: [],
  }, null, 2)}\n`);
  return file;
}

function seedWorkerGateEvidence(
  fixture: Fixture,
  kind: "FAST" | "FULL_CI" | "AC_AUDIT",
  producer: "DEV" | "CAPTAIN",
  fullHead: string,
): string {
  const state = taskState(fixture);
  const evidenceId = `${kind.toLowerCase()}-${randomUUID()}`;
  const evidenceDir = path.join(
    fixture.controlDir,
    "goals",
    "demo",
    "evidence",
    "TASK-A",
  );
  mkdirSync(evidenceDir, { recursive: true });
  const artifactFile = path.join(
    evidenceDir,
    `${evidenceId}-artifact.json`,
  );
  writeFileSync(
    artifactFile,
    `${JSON.stringify({ kind, status: "PASS" }, null, 2)}\n`,
  );
  const record: Record<string, unknown> = {
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
    full_head: fullHead,
    created_at: "2026-07-22T00:00:00.000Z",
    uri: pathToFileURL(artifactFile).href,
    source_sha256: sha256(readFileSync(artifactFile)),
    attestation: { controller: "goalctl", adapter: kind },
    ...(["FULL_CI", "AC_AUDIT"].includes(kind)
      ? {
        pull_request: {
          repository: "example-org/example-repo",
          number: 999,
          url: "https://github.com/example-org/example-repo/pull/999",
          base: "main",
          head: fullHead,
        },
      }
      : {}),
  };
  record.registry_sha256 = sha256(
    JSON.stringify(canonicalize(record)),
  );
  writeFileSync(
    path.join(evidenceDir, `${evidenceId}.json`),
    `${JSON.stringify(record, null, 2)}\n`,
  );
  return evidenceId;
}

function cleanupFixture(fixture: Fixture): void {
  if (fixture.worker && existsSync(fixture.worker)) {
    rmSync(fixture.worker, { recursive: true, force: true });
  }
  if (existsSync(fixture.root)) {
    rmSync(fixture.root, { recursive: true, force: true });
  }
  if (existsSync(fixture.controlDir)) {
    rmSync(fixture.controlDir, { recursive: true, force: true });
  }
}

describe("worker bootstrap registration/launch binding (worker-binding-v1)", () => {
  let fixture: Fixture;

  beforeEach(() => {
    fixture = makeFixture({ workerBootstrap: true });
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    enterP1Committed(fixture);
  });

  afterEach(() => {
    delete process.env.GOAL_CONTROL_DIR;
    delete process.env.GOAL_CONTROL_TEST_MODE;
    cleanupFixture(fixture);
  });

  it("rejects opt-in worker registration without the sealed bootstrap binding", () => {
    const bootstrap = bootstrapDynamicDev(fixture);
    const before = exactControlTree(fixture.controlDir);
    const args = dynamicRegistrationArgs(fixture, bootstrap);
    const firstBindingFlag = args.indexOf("--worker-bootstrap-receipt");
    args.splice(firstBindingFlag, 10);

    const result = runCliFrom(
      fixture,
      fixture.worker as string,
      args,
    );

    expect(result.code).toBe(2);
    expect(`${result.stdout}\n${result.stderr}`)
      .toContain("WORKER_BOOTSTRAP_REGISTRATION_REQUIRED");
    expect(exactControlTree(fixture.controlDir)).toEqual(before);
  });

  it("rejects registration from a sibling checkout even when HEAD matches", () => {
    const bootstrap = bootstrapDynamicDev(fixture);
    const before = exactControlTree(fixture.controlDir);

    const result = runCliFrom(
      fixture,
      fixture.root,
      dynamicRegistrationArgs(fixture, bootstrap),
    );

    expect(result.code).toBe(2);
    expect(`${result.stdout}\n${result.stderr}`)
      .toContain("CANARY_BOOTSTRAP_PROCESS_CWD_MISMATCH");
    expect(exactControlTree(fixture.controlDir)).toEqual(before);
  });

  it("seals the receipt binding and rejects CAPTAIN checkout launch/preflight", () => {
    const bootstrap = bootstrapDynamicDev(fixture);
    const registrationResult = runCliFrom(
      fixture,
      fixture.worker as string,
      dynamicRegistrationArgs(fixture, bootstrap),
    );
    expect(registrationResult).toMatchObject({ code: 0, stderr: "" });
    const registration = parse(registrationResult);
    const session = registration.session as Record<string, unknown>;
    expect(session.worker_bootstrap).toMatchObject({
      receipt_sha256: bootstrap.receiptSha256,
      operation_id: bootstrap.operationId,
      thread: THREADS.DEV,
      host: "local",
      worktree: fixture.worker,
      head: fixture.fullHead,
      branch: bootstrap.workerBranch,
    });
    fixture.capabilities.DEV =
      String(registration.actor_capability_file);
    fixture.taskNonce = String(registration.task_nonce);
    fixture.registeredStateRevision =
      Number(session.registered_state_revision);

    const inputFile = launchTemplateInput(fixture);
    const wrongTemplate = runCliFrom(fixture, fixture.root, [
      "launch-template",
      "--repository-worktree", fixture.root,
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--actor-capability-file", fixture.capabilities.DEV,
      "--input-file", inputFile,
      "--json",
    ]);
    expect(wrongTemplate.code).toBe(2);
    expect(`${wrongTemplate.stdout}\n${wrongTemplate.stderr}`)
      .toContain("WORKER_BOOTSTRAP_LAUNCH_MISMATCH");

    const correctTemplate = runCliFrom(
      fixture,
      fixture.worker as string,
      [
        "launch-template",
        "--repository-worktree", fixture.worker as string,
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", "DEV",
        "--thread", THREADS.DEV,
        "--actor-capability-file", fixture.capabilities.DEV,
        "--input-file", inputFile,
        "--json",
      ],
    );
    expect(correctTemplate).toMatchObject({ code: 0, stderr: "" });
    const validLaunch = parse(correctTemplate) as unknown as LaunchManifest;
    expect((validLaunch as unknown as Record<string, unknown>)
      .worker_bootstrap).toEqual(session.worker_bootstrap);
    const correctPreflight = preflightFrom(
      fixture,
      fixture.worker as string,
      validLaunch,
      "preflight-dynamic-dev-initial",
    );
    expect(correctPreflight).toMatchObject({ code: 0, stderr: "" });
    expect(
      sendEventFrom(
        fixture,
        fixture.worker as string,
        "LAUNCH_DEV",
        "CAPTAIN",
        4,
        { launch_id: "launch-dev-preflight-1" },
      ).result,
    ).toMatchObject({ code: 0, stderr: "" });
    const sourceFile = path.join(
      fixture.worker as string,
      "src",
      "worker-bootstrap-head-advance.ts",
    );
    mkdirSync(path.dirname(sourceFile), { recursive: true });
    writeFileSync(sourceFile, "export const workerBootstrapAdvance = true;\n");
    git(fixture.worker as string, "add", sourceFile);
    git(
      fixture.worker as string,
      "commit",
      "-qm",
      "test worker bootstrap source checkpoint",
    );
    const advancedHead = git(
      fixture.worker as string,
      "rev-parse",
      "HEAD",
    );
    const sourceCheckpoint = runCliFrom(
      fixture,
      fixture.worker as string,
      [
        "launch-template",
        "--repository-worktree", fixture.worker as string,
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", "DEV",
        "--thread", THREADS.DEV,
        "--actor-capability-file", fixture.capabilities.DEV,
        "--json",
      ],
    );
    expect(sourceCheckpoint).toMatchObject({ code: 0, stderr: "" });
    const advancedLaunch = parse(sourceCheckpoint) as unknown as
      LaunchManifest;
    expect(advancedLaunch.repository.full_head).toBe(advancedHead);
    expect((advancedLaunch as unknown as Record<string, unknown>)
      .worker_bootstrap).toEqual(session.worker_bootstrap);

    const advancedPreflight = preflightFrom(
      fixture,
      fixture.worker as string,
      advancedLaunch,
      "preflight-dynamic-dev-advanced",
    );
    if (advancedPreflight.code !== 0) {
      throw new Error(
        advancedPreflight.stdout || advancedPreflight.stderr,
      );
    }
    expect(advancedPreflight).toMatchObject({ code: 0, stderr: "" });
    const preflightEvidence = parse(advancedPreflight);
    const ready = sendEventFrom(
      fixture,
      fixture.worker as string,
      "DEV_READY",
      "DEV",
      1,
      {
        pr: "https://github.com/example-org/example-repo/pull/999",
        evidence: {
          preflight: String(preflightEvidence.evidence_id),
          fast: seedWorkerGateEvidence(
            fixture,
            "FAST",
            "DEV",
            advancedHead,
          ),
          full_ci: seedWorkerGateEvidence(
            fixture,
            "FULL_CI",
            "CAPTAIN",
            advancedHead,
          ),
          ac_audit: seedWorkerGateEvidence(
            fixture,
            "AC_AUDIT",
            "CAPTAIN",
            advancedHead,
          ),
        },
      },
      advancedHead,
    );
    expect(ready.result).toMatchObject({ code: 0, stderr: "" });

    const projectedStatus = runCli(fixture, [
      "status",
      "--goal", "demo",
      "--task", "TASK-A",
      "--json",
    ]);
    expect(projectedStatus).toMatchObject({ code: 0, stderr: "" });
    const projectedTask = (
      parse(projectedStatus) as {
        tasks: { "TASK-A": Record<string, unknown> };
      }
    ).tasks["TASK-A"];
    if (projectedTask.launch_scope !== null) {
      throw new Error(JSON.stringify(projectedTask, null, 2));
    }
    expect(projectedTask).toMatchObject({
      phase: "DEV_READY",
      launch_scope: null,
    });
    expect(projectedTask.launch_error_code).toBeUndefined();

    const wrongLaunch = JSON.parse(
      JSON.stringify(validLaunch),
    ) as LaunchManifest;
    wrongLaunch.thread.cwd = fixture.root;
    wrongLaunch.repository.worktree = fixture.root;
    wrongLaunch.repository.branch = "main";
    const wrongPreflight = preflight(fixture, wrongLaunch);
    expectFailedCheck(
      wrongPreflight,
      "WORKER_BOOTSTRAP_LAUNCH_MISMATCH",
    );
  });

  it("projects persisted launch binding drift through status/actions/resume/doctor", () => {
    const bootstrap = bootstrapDynamicDev(fixture);
    const registrationResult = runCliFrom(
      fixture,
      fixture.worker as string,
      dynamicRegistrationArgs(fixture, bootstrap),
    );
    expect(registrationResult).toMatchObject({ code: 0, stderr: "" });
    const registration = parse(registrationResult);
    const session = registration.session as Record<string, unknown>;
    fixture.capabilities.DEV =
      String(registration.actor_capability_file);
    fixture.taskNonce = String(registration.task_nonce);
    fixture.registeredStateRevision =
      Number(session.registered_state_revision);

    const template = runCliFrom(
      fixture,
      fixture.worker as string,
      [
        "launch-template",
        "--repository-worktree", fixture.worker as string,
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", "DEV",
        "--thread", THREADS.DEV,
        "--actor-capability-file", fixture.capabilities.DEV,
        "--input-file", launchTemplateInput(fixture),
        "--json",
      ],
    );
    expect(template).toMatchObject({ code: 0, stderr: "" });
    const launch = parse(template) as unknown as LaunchManifest;
    const preflightResult = preflightFrom(
      fixture,
      fixture.worker as string,
      launch,
      "preflight-dynamic-dev-drift-projection",
    );
    expect(preflightResult).toMatchObject({ code: 0, stderr: "" });
    const evidence = parse(preflightResult) as {
      launch_uri: string;
    };
    const canonicalLaunchFile = fileURLToPath(evidence.launch_uri);
    const tampered = JSON.parse(
      readFileSync(canonicalLaunchFile, "utf8"),
    ) as Record<string, unknown>;
    delete tampered.worker_bootstrap;
    writeFileSync(
      canonicalLaunchFile,
      `${JSON.stringify(tampered, null, 2)}\n`,
    );

    const statusResult = runCli(fixture, [
      "status",
      "--goal", "demo",
      "--task", "TASK-A",
      "--json",
    ]);
    expect(statusResult).toMatchObject({ code: 0, stderr: "" });
    expect(JSON.stringify(parse(statusResult)))
      .toContain("WORKER_BOOTSTRAP_LAUNCH_MISMATCH");

    const actionsResult = runCli(fixture, [
      "actions",
      "--goal", "demo",
      "--task", "TASK-A",
      "--role", "DEV",
      "--thread", THREADS.DEV,
      "--json",
    ]);
    expect(actionsResult).toMatchObject({ code: 0, stderr: "" });
    expect(JSON.stringify(parse(actionsResult)))
      .toContain("WORKER_BOOTSTRAP_LAUNCH_MISMATCH");

    const resumeResult = runCliFrom(
      fixture,
      fixture.worker as string,
      [
        "resume",
        "--goal", "demo",
        "--task", "TASK-A",
        "--role", "DEV",
        "--thread", THREADS.DEV,
        "--json",
      ],
    );
    expect(resumeResult.code).toBe(2);
    expect(`${resumeResult.stdout}\n${resumeResult.stderr}`)
      .toContain("WORKER_BOOTSTRAP_LAUNCH_MISMATCH");

    const doctorResult = runCli(fixture, [
      "doctor",
      "--goal", "demo",
      "--json",
    ]);
    expect(doctorResult.code).not.toBe(0);
    expect(`${doctorResult.stdout}\n${doctorResult.stderr}`)
      .toContain("WORKER_BOOTSTRAP_LAUNCH_MISMATCH");
  });
});

describe("worker bootstrap role scope (worker-binding-v1)", () => {
  const optedInManifest = {
    worker_canary_bootstrap: {
      protocol: "goalctl-worker-canary-bootstrap-v1",
    },
  };

  it.each(["DEV", "REVIEW", "RECEIPT"])(
    "requires the registration binding for %s",
    (role) => {
      expect(
        registrationRequiresWorkerBootstrap(optedInManifest, role),
      ).toBe(true);
    },
  );

  it.each(["FOREMAN", "CAPTAIN"])(
    "does not extend the worker binding to %s",
    (role) => {
      expect(
        registrationRequiresWorkerBootstrap(optedInManifest, role),
      ).toBe(false);
    },
  );

  it.each(["DEV_READY", "REOPEN_DEV"])(
    "allows the same bound DEV checkout to advance HEAD at %s",
    (eventType) => {
      expect(
        workerBootstrapEventAllowsHeadAdvance("DEV", eventType),
      ).toBe(true);
    },
  );

  it.each([
    ["DEV", "LAUNCH_DEV"],
    ["REVIEW", "REVIEW_REWORK"],
    ["RECEIPT", "RECEIPT_FAIL"],
  ])(
    "does not relax bootstrap HEAD for %s/%s",
    (role, eventType) => {
      expect(
        workerBootstrapEventAllowsHeadAdvance(role, eventType),
      ).toBe(false);
    },
  );
});

describe("goalctl preflight", () => {
  let fixture: Fixture;

  beforeEach(() => {
    fixture = makeFixture();
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    enterDevActive(fixture);
  });

  afterEach(() => {
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_EVIDENCE_BEFORE_INCIDENT;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_INCIDENT_EVIDENCE;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_INGRESS_PREPARED;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_EVIDENCE_INGRESS;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_GENERATION;
    delete process.env.GOAL_CONTROL_NOW;
    delete process.env.GOAL_CONTROL_DIR;
    delete process.env.GOAL_CONTROL_TEST_MODE;
    rmSync(fixture.root, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
  });

  it("derives runtime successor evidence IDs from exact launch bytes only", () => {
    const ordinary = launchManifest(fixture);
    expect(() => runtimePreflightEvidenceId(
      ordinary as unknown as Record<string, unknown>,
    )).toThrow("非 runtime successor preflight 必须显式提供 evidence ID");

    const successor: LaunchManifest = {
      ...ordinary,
      launch_id: "launch-dev-preflight-runtime-i2",
      runtime_incarnation: {
        epoch: 2,
        nonce: "a".repeat(40),
        rotation_event_id: "runtime-rotated-preflight-test",
      },
    };
    const first = runtimePreflightEvidenceId(
      successor as unknown as Record<string, unknown>,
    );
    expect(first).toMatch(/^preflight-runtime-[0-9a-f]{32}$/);
    expect(runtimePreflightEvidenceId(
      JSON.parse(JSON.stringify(successor)) as Record<string, unknown>,
    )).toBe(first);
    expect(runtimePreflightEvidenceId({
      ...successor,
      created_at: "2026-07-22T00:00:01.000Z",
    } as unknown as Record<string, unknown>)).not.toBe(first);
  });

  it("rejects an omitted evidence ID for ordinary launches without writes", () => {
    const launchFile = writeLaunch(fixture, launchManifest(fixture));
    const before = exactControlTree(fixture.controlDir);
    const result = runCli(fixture, [
      "preflight",
      "--goal", "demo",
      "--task", "TASK-A",
      "--launch", launchFile,
      "--stage", "DEV",
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]);
    expect(result.code).toBe(2);
    expect(`${result.stdout}\n${result.stderr}`).toContain(
      "PREFLIGHT_EVIDENCE_ID_REQUIRED",
    );
    expect(exactControlTree(fixture.controlDir)).toEqual(before);
  });

  it("writes durable PASS evidence bound to the current packet, HEAD, runtime and launch", () => {
    const result = preflight(fixture, launchManifest(fixture));

    expect(result.code).toBe(0);
    const evidence = parse(result) as {
      status: string;
      packet_sha256: string;
      full_head: string;
      launch_id: string;
      launch_sha256: string;
      attestation: { controller: string; adapter: string };
      launch_uri: string;
      uri: string;
      checks: Array<{ status: string }>;
    };
    expect(evidence).toMatchObject({
      status: "PASS",
      packet_sha256: fixture.packetHash,
      full_head: fixture.fullHead,
      launch_id: "launch-dev-preflight-1",
      launch_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      attestation: { controller: "goalctl", adapter: "PREFLIGHT" },
    });
    expect(evidence.checks.every((check) => check.status === "PASS")).toBe(true);
    const evidenceFile = fileURLToPath(evidence.uri);
    expect(existsSync(evidenceFile)).toBe(true);
    expect(JSON.parse(readFileSync(evidenceFile, "utf8"))).toMatchObject({
      status: "PASS",
      packet_sha256: fixture.packetHash,
      full_head: fixture.fullHead,
    });
    const launchRuntimeFile = fileURLToPath(evidence.launch_uri);
    expect(existsSync(launchRuntimeFile)).toBe(true);
    const resumed = runCli(fixture, [
      "resume",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      THREADS.DEV,
      "--json",
    ]);
    expect(resumed.code).toBe(0);
    expect(parse(resumed)).toMatchObject({
      launch_id: "launch-dev-preflight-1",
      launch_file: launchRuntimeFile,
      resource_leases: [],
    });
  });

  it("rejects runtime launch bindings on live semantic evidence ingress", () => {
    const state = taskState(fixture);
    const sourceFile = path.join(
      fixture.controlDir,
      "semantic-evidence-source.json",
    );
    const sourceBody = "{\"blocked\":\"semantic fact\"}\n";
    writeFileSync(sourceFile, sourceBody);
    const canonicalLaunchFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      "launch-dev-preflight-1.json",
    );
    const evidenceId = `semantic-runtime-binding-${randomUUID()}`;
    const evidenceFile = path.join(
      fixture.controlDir,
      `${evidenceId}.json`,
    );
    writeFileSync(evidenceFile, `${JSON.stringify({
      schema_version: 1,
      evidence_id: evidenceId,
      goal_id: "demo",
      task_id: "TASK-A",
      kind: "HOLD_ASSERTION",
      stage: "DEV",
      status: "BLOCKED",
      producer: {
        role: "DEV",
        thread_id: THREADS.DEV,
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
      launch_id: "launch-dev-preflight-1",
      created_at: "2026-07-26T00:00:00.000Z",
      uri: pathToFileURL(sourceFile).href,
      source_sha256: sha256(sourceBody),
      runtime_launch_sha256: sha256(
        readFileSync(canonicalLaunchFile),
      ),
      runtime_launch_uri: pathToFileURL(canonicalLaunchFile).href,
    }, null, 2)}\n`);

    const rejected = runCli(fixture, [
      "evidence",
      "--goal", "demo",
      "--file", evidenceFile,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]);
    expect(rejected.code).toBe(2);
    expect(`${rejected.stdout}\n${rejected.stderr}`).toContain(
      "语义 evidence 禁止伪造 controller/runtime launch attestation",
    );
    expect(existsSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence",
      "TASK-A",
      `${evidenceId}.json`,
    ))).toBe(false);
  });

  it("keeps a semantic runtime check UNKNOWN instead of authorizing rotation", () => {
    const state = taskState(fixture);
    const evidenceId = `semantic-runtime-check-${randomUUID()}`;
    const sourceFile = path.join(
      fixture.controlDir,
      `${evidenceId}-source.json`,
    );
    const sourceBody = '{"claim":"runtime-identity"}\n';
    writeFileSync(sourceFile, sourceBody);
    const evidenceFile = path.join(
      fixture.controlDir,
      `${evidenceId}.json`,
    );
    writeFileSync(evidenceFile, `${JSON.stringify({
      schema_version: 1,
      evidence_id: evidenceId,
      goal_id: "demo",
      task_id: "TASK-A",
      kind: "HOLD_ASSERTION",
      stage: "DEV",
      status: "BLOCKED",
      producer: {
        role: "DEV",
        thread_id: THREADS.DEV,
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
      launch_id: "launch-dev-preflight-1",
      created_at: "2026-07-26T00:00:00.000Z",
      uri: pathToFileURL(sourceFile).href,
      source_sha256: sha256(sourceBody),
      checks: [{
        name: "runtime-identity",
        status: "FAIL",
        detail: "semantic labels are not runtime authority",
      }],
    }, null, 2)}\n`);
    expect(runCli(fixture, [
      "evidence",
      "--goal", "demo",
      "--file", evidenceFile,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]).code).toBe(0);
    expect(sendEvent(
      fixture,
      "ADD_HOLD",
      "DEV",
      1,
      {
        kind: "ENV_IDENTITY_INCIDENT",
        hold_id: `semantic-runtime-hold-${randomUUID()}`,
        reason: "semantic runtime label must remain unclassified",
        evidence_id: evidenceId,
      },
    ).result.code).toBe(0);

    const held = taskState(fixture);
    expect(classifyLaunchIdentityHold(
      fixture.controlDir,
      held as unknown as Record<string, unknown>,
      "demo",
    )).toBe("UNKNOWN");
    for (const type of [
      "REQUEST_RUNTIME_ROTATION",
      "REQUEST_CANDIDATE_HOLD_REVALIDATION",
    ]) {
      expect(held.maintenance_actions).not.toEqual(
        expect.arrayContaining([
          expect.objectContaining({ type }),
        ]),
      );
    }
    const diagnosis = parse(runCli(fixture, [
      "doctor",
      "--goal", "demo",
      "--json",
    ])) as {
      findings: Array<{ code: string; task_id?: string }>;
    };
    expect(diagnosis.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "LAUNCH_IDENTITY_HOLD_UNCLASSIFIED",
          task_id: "TASK-A",
        }),
      ]),
    );
  });

  it("closes a pristine preflight before fresh live checks", () => {
    const evidenceId = `preflight-pristine-${randomUUID()}`;
    const launch = launchManifest(fixture);
    const launchFile = writeLaunch(fixture, launch);
    const options = {
      goalId: "demo",
      taskId: "TASK-A",
      launchFile,
      stage: "DEV",
      evidenceId,
      actorCapabilityFile: fixture.capabilities.DEV as string,
    };
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_GENERATION =
      "throw";
    const interrupted = runCli(fixture, [
      "preflight",
      "--goal", "demo",
      "--task", "TASK-A",
      "--launch", launchFile,
      "--stage", "DEV",
      "--evidence-id", evidenceId,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_GENERATION;
    expect(interrupted.code).toBe(2);
    expect(interrupted.stderr)
      .toContain("TEST_FAULT_AFTER_PREFLIGHT_GENERATION");
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const odd = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: { kind: string } };
    expect(odd.generation % 2).toBe(1);
    expect(odd.active_transaction.kind).toBe("PREFLIGHT_INGRESS");

    const liveCheckParities: number[] = [];
    const evidence = runPreflight(
      fixture.root,
      options,
      {
        beforeLiveChecks: () => {
          const current = JSON.parse(readFileSync(
            generationFile,
            "utf8",
          )) as { generation: number };
          liveCheckParities.push(current.generation % 2);
        },
      },
    );
    expect(evidence).toMatchObject({ evidence_id: evidenceId, status: "PASS" });
    expect(liveCheckParities).toEqual([0]);
    const even = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: null };
    expect(even.generation % 2).toBe(0);
    expect(even.active_transaction).toBeNull();
  });

  it("fences wrong capability and runs zero live checks after current actor expiry", () => {
    const status = parse(runCli(fixture, [
      "status",
      "--goal", "demo",
      "--task", "TASK-A",
      "--json",
    ])) as {
      tasks: { "TASK-A": { sessions: { DEV: { lease_until: string } } } };
    };
    const evidenceId = `preflight-expired-pristine-${randomUUID()}`;
    const launchFile = writeLaunch(fixture, launchManifest(fixture));
    const baseOptions = {
      goalId: "demo",
      taskId: "TASK-A",
      launchFile,
      stage: "DEV",
      evidenceId,
    };
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_GENERATION =
      "throw";
    const interrupted = runCli(fixture, [
      "preflight",
      "--goal", "demo",
      "--task", "TASK-A",
      "--launch", launchFile,
      "--stage", "DEV",
      "--evidence-id", evidenceId,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_GENERATION;
    expect(interrupted.code).toBe(2);
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const oddGeneration = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey;
      pre_write_vector_sha256: string;
      updated_at: string;
    };
    const payloadTree = () => exactControlTree(fixture.controlDir)
      .filter(([, relative]) => relative !== ".generation.json");
    const oddPayload = payloadTree();
    let liveChecks = 0;
    expect(() => runPreflight(
      fixture.root,
      {
        ...baseOptions,
        actorCapabilityFile: fixture.capabilities.CAPTAIN as string,
      },
      { beforeLiveChecks: () => { liveChecks += 1; } },
    )).toThrow(expect.objectContaining({ code: "CAPABILITY_INVALID" }));
    expect(liveChecks).toBe(0);
    expect(payloadTree()).toEqual(oddPayload);
    const fencedGeneration = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey;
      pre_write_vector_sha256: string;
      updated_at: string;
    };
    expect(fencedGeneration.generation % 2).toBe(1);
    expect(fencedGeneration.active_transaction)
      .toEqual(oddGeneration.active_transaction);
    expect(fencedGeneration.pre_write_vector_sha256)
      .toBe(oddGeneration.pre_write_vector_sha256);
    expect(fencedGeneration.updated_at).toBe(oddGeneration.updated_at);

    process.env.GOAL_CONTROL_NOW = new Date(
      Date.parse(status.tasks["TASK-A"].sessions.DEV.lease_until) + 1,
    ).toISOString();
    expect(() => runPreflight(
      fixture.root,
      {
        ...baseOptions,
        actorCapabilityFile: fixture.capabilities.DEV as string,
      },
      { beforeLiveChecks: () => { liveChecks += 1; } },
    )).toThrow(expect.objectContaining({ code: "ACTOR_LEASE_EXPIRED" }));
    expect(liveChecks).toBe(0);
    const even = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as { generation: number; active_transaction: null };
    expect(even.generation % 2).toBe(0);
    expect(even.active_transaction).toBeNull();
  });

  it("completes a sealed prepared preflight after response loss without rerunning live checks", () => {
    const evidenceId = `preflight-prepared-loss-${randomUUID()}`;
    const launch = launchManifest(fixture);
    const archiveState = taskState(fixture);
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED = "1";
    const interrupted = preflight(fixture, launch, evidenceId);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED;
    expect(interrupted.code).toBe(2);
    expect(interrupted.stderr).toContain(
      "TEST_FAULT_AFTER_PREFLIGHT_PREPARED",
    );

    const preparedFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence-artifacts",
      "TASK-A",
      `${evidenceId}-preflight-prepared.json`,
    );
    expect(existsSync(preparedFile)).toBe(true);
    const wrongCapabilityLaunch = writeLaunch(fixture, launch);
    const pendingBootstrap = installPendingBootstrapConsumption(fixture);
    const oddWrongCapabilityTree = exactControlTree(fixture.controlDir);
    const wrongCapability = runCli(fixture, [
      "preflight",
      "--goal", "demo",
      "--task", "TASK-A",
      "--launch", wrongCapabilityLaunch,
      "--stage", "DEV",
      "--evidence-id", evidenceId,
      "--actor-capability-file", fixture.capabilities.CAPTAIN as string,
      "--json",
    ]);
    expect(wrongCapability.code).toBe(2);
    expect(wrongCapability.stderr).toContain("CAPABILITY_INVALID");
    expect(exactControlTree(fixture.controlDir)).toEqual(oddWrongCapabilityTree);
    expect(readFileSync(pendingBootstrap, "utf8"))
      .toBe(fixture.bootstrapCapabilityBytes);
    const archiveEvent = {
      schema_version: 1,
      event_id: `archive-blocked-${randomUUID()}`,
      goal_id: "demo",
      task_id: "TASK-A",
      type: "ARCHIVED",
      actor: {
        role: "FOREMAN",
        thread_id: THREADS.FOREMAN,
        host_id: "local",
      },
      actor_sequence: 2,
      expected_state_revision: archiveState.state_revision,
      control_epoch: archiveState.control_epoch,
      packet: {
        revision: archiveState.packet.revision,
        sha256: archiveState.packet.sha256,
      },
      base_head: archiveState.base_head,
      full_head: archiveState.full_head,
      payload: {
        evidence_id: "archive-must-wait-for-preflight-retry",
      },
    };
    const archiveFile = path.join(
      fixture.controlDir,
      "inputs",
      `${archiveEvent.event_id}.json`,
    );
    writeFileSync(archiveFile, `${JSON.stringify(archiveEvent, null, 2)}\n`);
    const oddPreparedTree = exactControlTree(fixture.controlDir);
    const archiveAttempt = runCli(fixture, [
      "event",
      "--goal",
      "demo",
      "--file",
      archiveFile,
      "--actor-capability-file",
      fixture.capabilities.FOREMAN as string,
      "--json",
    ]);
    expect(archiveAttempt.code).toBe(2);
    expect(archiveAttempt.stderr).toContain("STORE_TRANSACTION_MISMATCH");
    expect(exactControlTree(fixture.controlDir)).toEqual(oddPreparedTree);
    writeFileSync(path.join(fixture.root, "dirty-after-prepared.txt"), "dirty\n");

    const retried = preflight(fixture, launch, evidenceId);
    expect(retried.code).toBe(0);
    expect(parse(retried)).toMatchObject({
      evidence_id: evidenceId,
      status: "PASS",
    });
    expect(existsSync(path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence",
      "TASK-A",
      `${evidenceId}.json`,
    ))).toBe(true);

    const conflicting = preflight(
      fixture,
      { ...launch, created_at: "2026-07-22T00:00:01.000Z" },
      evidenceId,
    );
    expect(conflicting.code).toBe(2);
    expect(conflicting.stderr).toContain("EVIDENCE_ID_CONFLICT");
  });

  it("fails closed on a launch-only orphan without a sealed prepared result", () => {
    const evidenceId = `preflight-launch-orphan-${randomUUID()}`;
    const launch = launchManifest(fixture);
    const artifactDir = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence-artifacts",
      "TASK-A",
    );
    mkdirSync(artifactDir, { recursive: true });
    writeFileSync(
      path.join(artifactDir, `${evidenceId}-launch.json`),
      `${JSON.stringify(launch, null, 2)}\n`,
    );
    const result = preflight(fixture, launch, evidenceId);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("PREFLIGHT_PREPARED_ARTIFACT_MISSING");
  });

  it("exact-retries after the preflight evidence commit response is lost", () => {
    const evidenceId = `preflight-evidence-loss-${randomUUID()}`;
    const launch = launchManifest(fixture);
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_EVIDENCE_INGRESS = "PREFLIGHT";
    const interrupted = preflight(fixture, launch, evidenceId);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_EVIDENCE_INGRESS;
    expect(interrupted.code).toBe(2);
    expect(interrupted.stderr).toContain(
      "TEST_FAULT_AFTER_EVIDENCE_INGRESS",
    );
    writeFileSync(path.join(fixture.root, "dirty-after-evidence.txt"), "dirty\n");
    const retried = preflight(fixture, launch, evidenceId);
    expect(retried.code).toBe(0);
    expect(parse(retried)).toMatchObject({
      evidence_id: evidenceId,
      status: "PASS",
    });
  });

  it("adopts a legacy root containing controller-generated PREFLIGHT evidence", () => {
    rmSync(path.join(fixture.controlDir, ".store-protocol.json"), { force: true });
    rmSync(path.join(fixture.controlDir, ".generation.json"), { force: true });

    const adopted = runCli(fixture, [
      "adopt-store-protocol",
      "--repository-worktree",
      fixture.root,
      "--incident-ref",
      "incident://goal-control/legacy-preflight-registry",
      "--acknowledge-old-controller-drained",
      "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
      "--json",
    ]);
    if (adopted.code !== 0) {
      throw new Error(`PREFLIGHT root adoption failed: ${adopted.stderr || adopted.stdout}`);
    }
    expect(parse(adopted)).toMatchObject({
      adopted: true,
      idempotent: false,
      validation: { evidence_registry_count: expect.any(Number) },
    });
  });

  it.each(["app-diagnostics", "host-example-mcp", "legacy-adapter"])(
    "rejects caller-signed %s identity JSON until a broker attestation adapter exists",
    (source) => {
      const launch = launchManifest(fixture);
      const identityProbe = launch.execution.identity_probe;
      if (!identityProbe) throw new Error("fixture launch missing identity probe");
      const probe = JSON.parse(readFileSync(identityProbe.path, "utf8")) as Record<string, unknown>;
      probe.source = source;
      const body = `${JSON.stringify(probe, null, 2)}\n`;
      writeFileSync(identityProbe.path, body);
      identityProbe.sha256 = sha256(body);

      expectFailedCheck(
        preflight(fixture, launch),
        "ENVIRONMENT_ATTESTATION_REQUIRES_BROKER"
      );
    },
  );

  it("rejects an undeclared identity probe source", () => {
    const launch = launchManifest(fixture);
    const identityProbe = launch.execution.identity_probe;
    if (!identityProbe) throw new Error("fixture launch missing identity probe");
    const probe = JSON.parse(readFileSync(identityProbe.path, "utf8")) as Record<string, unknown>;
    probe.source = "INVALID/source";
    const body = `${JSON.stringify(probe, null, 2)}\n`;
    writeFileSync(identityProbe.path, body);
    identityProbe.sha256 = sha256(body);

    expectFailedCheck(
      preflight(fixture, launch),
      "IDENTITY_PROBE_INVALID"
    );
  });

  it("re-runs preflight for a new clean candidate HEAD without replacing the registered launch identity", () => {
    const canonicalFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      "launch-dev-preflight-1.json",
    );
    const canonicalBefore = readFileSync(canonicalFile, "utf8");
    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate bytes\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const launch = launchManifest(fixture);
    launch.repository.full_head = candidateHead;
    launch.execution.target.build_head = candidateHead;

    const result = preflight(fixture, launch);
    expect(result.code).toBe(0);
    const evidence = parse(result) as {
      status: string;
      full_head: string;
      launch_uri: string;
      runtime_launch_uri: string;
      runtime_launch_sha256: string;
    };
    expect(evidence).toMatchObject({ status: "PASS", full_head: candidateHead });
    expect(fileURLToPath(evidence.launch_uri)).not.toBe(
      canonicalFile
    );
    expect(fileURLToPath(evidence.runtime_launch_uri)).toBe(canonicalFile);
    expect(evidence.runtime_launch_sha256).toBe(sha256(canonicalBefore));
    expect(readFileSync(canonicalFile, "utf8")).toBe(canonicalBefore);
  });

  it("adopts a legacy root containing a runtime-bound source checkpoint PREFLIGHT", () => {
    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate bytes\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const launch = launchManifest(fixture);
    launch.repository.full_head = candidateHead;
    launch.execution.target.build_head = candidateHead;
    const evidenceId = `preflight-source-adoption-${randomUUID()}`;
    expect(preflight(fixture, launch, evidenceId).code).toBe(0);

    rmSync(path.join(fixture.controlDir, ".store-protocol.json"), { force: true });
    rmSync(path.join(fixture.controlDir, ".generation.json"), { force: true });
    const adopted = runCli(fixture, [
      "adopt-store-protocol",
      "--repository-worktree",
      fixture.root,
      "--incident-ref",
      "incident://goal-control/source-checkpoint-preflight",
      "--acknowledge-old-controller-drained",
      "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
      "--json",
    ]);
    expect(adopted.code).toBe(0);
    expect(parse(adopted)).toMatchObject({
      adopted: true,
      validation: { evidence_registry_count: expect.any(Number) },
    });
  });

  it("rejects source checkpoint adoption when the canonical runtime binding is incomplete", () => {
    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate bytes\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const launch = launchManifest(fixture);
    launch.repository.full_head = candidateHead;
    launch.execution.target.build_head = candidateHead;
    const evidenceId = `preflight-source-incomplete-${randomUUID()}`;
    expect(preflight(fixture, launch, evidenceId).code).toBe(0);

    const registryFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence",
      "TASK-A",
      `${evidenceId}.json`,
    );
    const record = JSON.parse(readFileSync(registryFile, "utf8")) as
      Record<string, unknown>;
    delete record.runtime_launch_uri;
    delete record.registry_sha256;
    record.registry_sha256 = hashObject(record);
    writeFileSync(registryFile, `${JSON.stringify(record, null, 2)}\n`);
    rmSync(path.join(fixture.controlDir, ".store-protocol.json"), { force: true });
    rmSync(path.join(fixture.controlDir, ".generation.json"), { force: true });

    const adopted = runCli(fixture, [
      "adopt-store-protocol",
      "--repository-worktree",
      fixture.root,
      "--incident-ref",
      "incident://goal-control/source-checkpoint-incomplete",
      "--acknowledge-old-controller-drained",
      "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
      "--json",
    ]);
    expect(adopted.code).toBe(2);
    expect(`${adopted.stdout}\n${adopted.stderr}`)
      .toContain("runtime launch binding 必须成对");
    expect(existsSync(path.join(
      fixture.controlDir,
      ".store-protocol.json",
    ))).toBe(false);
  });

  it("rejects a live retry of an unbound source checkpoint even when both legacy runtime fields are absent", () => {
    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate bytes\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const launch = launchManifest(fixture);
    launch.repository.full_head = candidateHead;
    launch.execution.target.build_head = candidateHead;
    const evidenceId =
      `preflight-source-live-unbound-${randomUUID()}`;
    expect(preflight(fixture, launch, evidenceId).code).toBe(0);

    const registryFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence",
      "TASK-A",
      `${evidenceId}.json`,
    );
    const record = JSON.parse(readFileSync(
      registryFile,
      "utf8",
    )) as Record<string, unknown>;
    delete record.runtime_launch_uri;
    delete record.runtime_launch_sha256;
    delete record.registry_sha256;
    record.registry_sha256 = hashObject(record);
    writeFileSync(
      registryFile,
      `${JSON.stringify(record, null, 2)}\n`,
    );

    const rejected = preflight(fixture, launch, evidenceId);
    expect(rejected.code).toBe(2);
    expect(`${rejected.stdout}\n${rejected.stderr}`).toContain(
      "PREFLIGHT PASS source checkpoint 缺 canonical runtime 双绑定",
    );
  });

  it("rejects a non-NONE source checkpoint that drops the build HEAD binding", () => {
    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate bytes\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const launch = launchManifest(fixture);
    launch.repository.full_head = candidateHead;
    delete launch.execution.target.build_head;

    expectFailedCheck(
      preflight(fixture, launch),
      "LAUNCH_ID_CONFLICT",
    );
  });

  it("accepts a canonical runtime checkpoint between registration and the current DEV HEAD", () => {
    writeFileSync(path.join(fixture.root, "h1.txt"), "h1\n");
    git(fixture.root, "add", "h1.txt");
    git(fixture.root, "commit", "-qm", "runtime checkpoint h1");
    const h1 = git(fixture.root, "rev-parse", "HEAD");
    writeFileSync(path.join(fixture.root, "h2.txt"), "h2\n");
    git(fixture.root, "add", "h2.txt");
    git(fixture.root, "commit", "-qm", "candidate h2");
    const h2 = git(fixture.root, "rev-parse", "HEAD");
    const state = taskState(fixture) as unknown as Record<string, unknown> & {
      sessions: { DEV: Record<string, unknown> };
    };
    const launch = launchManifest(fixture);
    launch.repository.full_head = h1;
    launch.execution.target.build_head = h1;

    expect(assertDevLaunchHead(
      fixture.root,
      state,
      state.sessions.DEV,
      launch,
      h2,
    )).toBe(false);

    const sibling = git(
      fixture.root,
      "commit-tree",
      git(fixture.root, "rev-parse", `${h1}^{tree}`),
      "-p",
      String(state.full_head),
      "-m",
      "sibling runtime checkpoint",
    );
    launch.repository.full_head = sibling;
    launch.execution.target.build_head = sibling;
    let siblingFailure: unknown = null;
    try {
      assertDevLaunchHead(
        fixture.root,
        state,
        state.sessions.DEV,
        launch,
        h2,
      );
    } catch (error) {
      siblingFailure = error;
    }
    expect(siblingFailure).toMatchObject({
      code: "CANDIDATE_HEAD_NOT_DESCENDANT",
    });
  });

  it("exact-completes a prepared source checkpoint without re-reading a now-dirty worktree", () => {
    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate bytes\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const launch = launchManifest(fixture);
    launch.repository.full_head = candidateHead;
    launch.execution.target.build_head = candidateHead;
    const evidenceId = `preflight-source-prepared-${randomUUID()}`;

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED = "1";
    const interrupted = preflight(fixture, launch, evidenceId);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED;
    expect(interrupted.code).not.toBe(0);
    expect(`${interrupted.stdout}\n${interrupted.stderr}`)
      .toContain("TEST_FAULT_AFTER_PREFLIGHT_PREPARED");

    writeFileSync(path.join(fixture.root, "dirty-after-prepared.txt"), "dirty\n");
    const retried = preflight(fixture, launch, evidenceId);
    expect(retried.code).toBe(0);
    expect(parse(retried)).toMatchObject({
      evidence_id: evidenceId,
      status: "PASS",
      full_head: candidateHead,
      runtime_launch_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      runtime_launch_uri: expect.stringMatching(/^file:/),
    });
  });

  it("does not recreate a deleted canonical runtime launch from a prepared source checkpoint", () => {
    const canonicalFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      "launch-dev-preflight-1.json",
    );
    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate bytes\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const launch = launchManifest(fixture);
    launch.repository.full_head = candidateHead;
    launch.execution.target.build_head = candidateHead;
    const evidenceId = `preflight-source-delete-${randomUUID()}`;

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED = "1";
    const interrupted = preflight(fixture, launch, evidenceId);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED;
    expect(interrupted.code).not.toBe(0);
    rmSync(canonicalFile);

    const retried = preflight(fixture, launch, evidenceId);
    expect(retried.code).toBe(2);
    expect(`${retried.stdout}\n${retried.stderr}`)
      .toContain("PREFLIGHT_RUNTIME_ANCHOR_DRIFT");
    expect(existsSync(canonicalFile)).toBe(false);
  });

  it("rejects canonical runtime launch replacement after a source checkpoint is prepared", () => {
    const canonicalFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      "launch-dev-preflight-1.json",
    );
    writeFileSync(path.join(fixture.root, "candidate.txt"), "candidate bytes\n");
    git(fixture.root, "add", "candidate.txt");
    git(fixture.root, "commit", "-qm", "candidate");
    const candidateHead = git(fixture.root, "rev-parse", "HEAD");
    const launch = launchManifest(fixture);
    launch.repository.full_head = candidateHead;
    launch.execution.target.build_head = candidateHead;
    const evidenceId = `preflight-source-replace-${randomUUID()}`;

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED = "1";
    const interrupted = preflight(fixture, launch, evidenceId);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_PREPARED;
    expect(interrupted.code).not.toBe(0);
    writeFileSync(canonicalFile, `${JSON.stringify(launch, null, 2)}\n`);

    const retried = preflight(fixture, launch, evidenceId);
    expect(retried.code).toBe(2);
    expect(`${retried.stdout}\n${retried.stderr}`)
      .toContain("PREFLIGHT_RUNTIME_ANCHOR_DRIFT");
  });

  it("rejects a clean divergent sibling candidate that drops the registered DEV lineage", () => {
    const tree = git(fixture.root, "rev-parse", `${fixture.fullHead}^{tree}`);
    const sibling = git(
      fixture.root,
      "commit-tree",
      tree,
      "-p",
      fixture.baseHead,
      "-m",
      "divergent sibling with identical frozen bytes"
    );
    git(fixture.root, "reset", "--hard", sibling);
    const launch = launchManifest(fixture);
    launch.repository.full_head = sibling;
    launch.execution.target.build_head = sibling;

    expectFailedCheck(
      preflight(fixture, launch),
      "CANDIDATE_HEAD_NOT_DESCENDANT"
    );
  });

  it("fails closed when launch HEAD is stale", () => {
    const launch = launchManifest(fixture);
    launch.repository.full_head = fixture.baseHead;

    expectFailedCheck(preflight(fixture, launch), "STALE_HEAD");
    expect(taskState(fixture).holds).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "ENV_IDENTITY_INCIDENT",
          hard: true,
        }),
      ])
    );
  });

  it("exact-completes one identity hold after response loss following primary preflight evidence", () => {
    const launch = launchManifest(fixture);
    launch.repository.full_head = fixture.baseHead;
    const evidenceId = `preflight-primary-cut-${randomUUID()}`;
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_EVIDENCE_BEFORE_INCIDENT = "1";
    const interrupted = preflight(fixture, launch, evidenceId);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_EVIDENCE_BEFORE_INCIDENT;
    expect(interrupted.code).not.toBe(0);
    expect(`${interrupted.stdout}\n${interrupted.stderr}`)
      .toContain("TEST_FAULT_AFTER_PREFLIGHT_EVIDENCE_BEFORE_INCIDENT");

    expectFailedCheck(preflight(fixture, launch, evidenceId), "STALE_HEAD");
    expectFailedCheck(preflight(fixture, launch, evidenceId), "STALE_HEAD");
    const goalRoot = path.join(fixture.controlDir, "goals", "demo");
    const incidents = readdirSync(path.join(goalRoot, "events", "TASK-A"))
      .map((name) => JSON.parse(readFileSync(
        path.join(goalRoot, "events", "TASK-A", name),
        "utf8",
      )))
      .filter((event) => (
        event.type === "ADD_HOLD"
          && event.payload?.kind === "ENV_IDENTITY_INCIDENT"
      ));
    expect(incidents).toHaveLength(1);
  });

  it("exact-completes one identity hold after its incident evidence is durable", () => {
    const launch = launchManifest(fixture);
    launch.repository.full_head = fixture.baseHead;
    const evidenceId = `preflight-incident-cut-${randomUUID()}`;
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_INCIDENT_EVIDENCE = "1";
    const interrupted = preflight(fixture, launch, evidenceId);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_PREFLIGHT_INCIDENT_EVIDENCE;
    expect(interrupted.code).not.toBe(0);
    expect(`${interrupted.stdout}\n${interrupted.stderr}`)
      .toContain("TEST_FAULT_AFTER_PREFLIGHT_INCIDENT_EVIDENCE");

    const digest = sha256(evidenceId).replace(/^sha256:/, "").slice(0, 32);
    const incidentRegistryFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence",
      "TASK-A",
      `env-incident-${digest}.json`,
    );
    const incidentRegistryBytes = readFileSync(
      incidentRegistryFile,
      "utf8",
    );
    const incidentPreparedFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence-ingress",
      "TASK-A",
      `env-incident-${digest}.json`,
    );
    const incidentPreparedBytes = readFileSync(
      incidentPreparedFile,
      "utf8",
    );
    const incidentRegistry = JSON.parse(incidentRegistryBytes);
    const incidentSource = JSON.parse(readFileSync(
      fileURLToPath(incidentRegistry.uri),
      "utf8",
    ));
    const retryLaunchFile = writeLaunch(fixture, launch);
    const retryWithCapability = (capabilityFile: string): CliResult => runCli(
      fixture,
      [
        "preflight",
        "--goal", "demo",
        "--task", "TASK-A",
        "--launch", retryLaunchFile,
        "--stage", "DEV",
        "--evidence-id", evidenceId,
        "--actor-capability-file", capabilityFile,
        "--json",
      ],
    );

    const wrongCapabilityTree = exactControlTree(fixture.controlDir);
    const wrongCapability = retryWithCapability(
      fixture.capabilities.CAPTAIN as string,
    );
    expect(wrongCapability.code).not.toBe(0);
    expect(`${wrongCapability.stdout}\n${wrongCapability.stderr}`)
      .toContain("CAPABILITY_INVALID");
    expect(exactControlTree(fixture.controlDir)).toEqual(wrongCapabilityTree);

    const driftedRegistry = JSON.parse(incidentRegistryBytes) as Record<string, unknown>;
    driftedRegistry.checks = [{
      name: "repository-identity",
      status: "FAIL",
      detail: "STALE_HEAD: drifted registry",
    }];
    delete driftedRegistry.registry_sha256;
    driftedRegistry.registry_sha256 = hashObject(driftedRegistry);
    writeFileSync(
      incidentRegistryFile,
      `${JSON.stringify(driftedRegistry, null, 2)}\n`,
    );
    const driftedRegistryTree = exactControlTree(fixture.controlDir);
    const registryDrift = retryWithCapability(
      fixture.capabilities.DEV as string,
    );
    expect(registryDrift.code).not.toBe(0);
    expect(`${registryDrift.stdout}\n${registryDrift.stderr}`)
      .toMatch(
        /EVIDENCE_ID_CONFLICT|EVIDENCE_SOURCE_HASH_MISMATCH|STORE_ATOMIC_RESIDUAL_CONFLICT/,
      );
    expect(exactControlTree(fixture.controlDir)).toEqual(driftedRegistryTree);
    writeFileSync(incidentRegistryFile, incidentRegistryBytes);

    const maliciousEvent = {
      ...incidentSource.incident_event,
      payload: {
        ...incidentSource.incident_event.payload,
        hold_id: `malicious-hold-${digest}`,
        reason: "same id, divergent payload",
      },
    };
    const maliciousFile = path.join(
      fixture.controlDir,
      "inputs",
      `malicious-${digest}.json`,
    );
    writeFileSync(maliciousFile, `${JSON.stringify(maliciousEvent, null, 2)}\n`);
    const oddIncidentTree = exactControlTree(fixture.controlDir);
    const malicious = runCli(fixture, [
      "event",
      "--goal", "demo",
      "--file", maliciousFile,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]);
    expect(malicious.code).not.toBe(0);
    expect(`${malicious.stdout}\n${malicious.stderr}`)
      .toContain("STORE_TRANSACTION_MISMATCH");
    expect(exactControlTree(fixture.controlDir)).toEqual(oddIncidentTree);

    rmSync(incidentRegistryFile);
    rmSync(incidentPreparedFile);
    const missingWitnessTree = exactControlTree(fixture.controlDir);
    const missingWitness = retryWithCapability(
      fixture.capabilities.DEV as string,
    );
    expect(missingWitness.code).not.toBe(0);
    expect(`${missingWitness.stdout}\n${missingWitness.stderr}`)
      .toContain("STORE_TRANSACTION_MISMATCH");
    expect(exactControlTree(fixture.controlDir)).toEqual(missingWitnessTree);

    writeFileSync(incidentPreparedFile, incidentPreparedBytes, {
      mode: 0o600,
    });
    expectFailedCheck(
      retryWithCapability(fixture.capabilities.DEV as string),
      "STALE_HEAD",
    );
    expect(readFileSync(incidentRegistryFile, "utf8"))
      .toBe(incidentRegistryBytes);

    expectFailedCheck(preflight(fixture, launch, evidenceId), "STALE_HEAD");
    const goalRoot = path.join(fixture.controlDir, "goals", "demo");
    const incidentEvidence = readdirSync(
      path.join(goalRoot, "evidence", "TASK-A"),
    ).map((name) => JSON.parse(readFileSync(
      path.join(goalRoot, "evidence", "TASK-A", name),
      "utf8",
    ))).filter((record) => (
      record.kind === "HOLD_ASSERTION"
        && record.stage === "PREFLIGHT"
    ));
    const incidents = readdirSync(path.join(goalRoot, "events", "TASK-A"))
      .map((name) => JSON.parse(readFileSync(
        path.join(goalRoot, "events", "TASK-A", name),
        "utf8",
      )))
      .filter((event) => (
        event.type === "ADD_HOLD"
          && event.payload?.kind === "ENV_IDENTITY_INCIDENT"
      ));
    expect(incidentEvidence).toHaveLength(1);
    expect(incidents).toHaveLength(1);
  });

  it("recovers a prepared-first identity incident after SIGKILL without an anonymous temp source", () => {
    const launch = launchManifest(fixture);
    launch.repository.full_head = fixture.baseHead;
    const evidenceId = `preflight-incident-prepared-${randomUUID()}`;
    const beforeTemps = readdirSync(tmpdir())
      .filter((name) => name.startsWith("goalctl-preflight-incident-"))
      .sort();

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_INGRESS_PREPARED =
      "sigkill";
    const interrupted = preflight(fixture, launch, evidenceId);
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SEMANTIC_INGRESS_PREPARED;
    expect(interrupted.code).not.toBe(0);

    const incidentDigest = sha256(evidenceId)
      .replace(/^sha256:/, "")
      .slice(0, 32);
    const incidentEvidenceId = `env-incident-${incidentDigest}`;
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
        .filter((name) => name.startsWith("goalctl-preflight-incident-"))
        .sort()
    ).toEqual(beforeTemps);

    expectFailedCheck(preflight(fixture, launch, evidenceId), "STALE_HEAD");
    expect(existsSync(path.join(
      goalRoot,
      "evidence",
      "TASK-A",
      `${incidentEvidenceId}.json`,
    ))).toBe(true);
    const incidents = readdirSync(path.join(goalRoot, "events", "TASK-A"))
      .map((name) => JSON.parse(readFileSync(
        path.join(goalRoot, "events", "TASK-A", name),
        "utf8",
      )))
      .filter((event) => (
        event.type === "ADD_HOLD"
          && event.payload?.evidence_id === incidentEvidenceId
      ));
    expect(incidents).toHaveLength(1);
  });

  it("does not route a foreign PREFLIGHT_INGRESS odd key through identity recovery", () => {
    const launch = launchManifest(fixture);
    const evidenceId = `preflight-primary-${randomUUID()}`;
    expect(preflight(fixture, launch, evidenceId).code).toBe(0);
    const retryLaunchFile = writeLaunch(fixture, launch);
    const foreignEvidenceId = `preflight-foreign-${randomUUID()}`;
    const foreignRequest = {
      schema_version: 1,
      evidence_id: foreignEvidenceId,
      goal_id: launch.goal_id,
      task_id: launch.task_id,
      stage: "DEV",
      launch_sha256: hashObject(launch),
    };
    writeV2OddGeneration(
      fixture,
      canonicalTransactionKey(
        "PREFLIGHT_INGRESS",
        {
          goal_id: launch.goal_id,
          task_id: launch.task_id,
        },
        foreignEvidenceId,
        hashObject(foreignRequest),
      ),
    );
    const before = exactControlTree(fixture.controlDir);
    const foreign = runCli(fixture, [
      "preflight",
      "--goal", "demo",
      "--task", "TASK-A",
      "--launch", retryLaunchFile,
      "--stage", "DEV",
      "--evidence-id", evidenceId,
      "--actor-capability-file", fixture.capabilities.DEV as string,
      "--json",
    ]);

    expect(foreign.code).not.toBe(0);
    expect(`${foreign.stdout}\n${foreign.stderr}`)
      .toContain("STORE_TRANSACTION_MISMATCH");
    expect(exactControlTree(fixture.controlDir)).toEqual(before);
  });

  it("turns a stale Goal base binding into the same sticky identity incident", () => {
    const launch = launchManifest(fixture);
    launch.repository.base_head = "f".repeat(40);

    expectFailedCheck(preflight(fixture, launch), "STALE_BASE_HEAD");
    expect(taskState(fixture).holds).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "ENV_IDENTITY_INCIDENT", hard: true }),
      ])
    );
  });

  it("keeps an unsupported non-PREVIEW launch conflict out of the runtime lane", () => {
    const first = launchManifest(fixture);
    expect(preflight(fixture, first).code).toBe(0);
    const second = { ...first, thread: { ...first.thread, title: "different runtime" } };

    const rejected = preflight(fixture, second);
    expectFailedCheck(rejected, "LAUNCH_ID_CONFLICT");
    const held = taskState(fixture);
    expect(held.holds).toEqual(
      expect.arrayContaining([expect.objectContaining({ kind: "ENV_IDENTITY_INCIDENT", hard: true })])
    );
    expect(classifyLaunchIdentityHold(
      fixture.controlDir,
      held as unknown as Record<string, unknown>,
      "demo",
    )).toBe("UNKNOWN");
    expect(held.maintenance_actions).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "REQUEST_CANDIDATE_HOLD_REVALIDATION",
        }),
      ]),
    );
    expect(held.maintenance_actions).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "REQUEST_RUNTIME_ROTATION",
        }),
      ]),
    );

    const sourceUri = held.holds[0].evidence?.uri;
    if (!sourceUri) throw new Error("missing sealed incident source URI");
    writeFileSync(
      fileURLToPath(new URL(sourceUri)),
      '{"corrupt":true}\n',
    );
    expect(classifyLaunchIdentityHold(
      fixture.controlDir,
      held as unknown as Record<string, unknown>,
      "demo",
    )).toBe("UNKNOWN");
    const corruptStatus = runCli(
      fixture,
      ["status", "--goal", "demo", "--task", "TASK-A", "--json"],
    );
    expect(corruptStatus.code).toBe(2);
    expect(`${corruptStatus.stdout}\n${corruptStatus.stderr}`).toContain(
      "EVIDENCE_SOURCE_HASH_MISMATCH",
    );
  });

  it("requires a real PREVIEW identity delta for the launch-conflict runtime lane", () => {
    const canonical = launchManifest(fixture);
    canonical.execution = {
      environment: "none",
      write_mode: "NONE",
      task_nonce: canonical.execution.task_nonce,
      target: {
        kind: "PREVIEW",
        executable_path: realpathSync(process.execPath),
        pid: 101,
        started_at: "2026-07-26T00:00:00.000Z",
        preview_url: "http://127.0.0.1:8123",
        build_head: canonical.repository.full_head,
      },
    };
    const timestampOnly = JSON.parse(
      JSON.stringify(canonical),
    ) as LaunchManifest;
    timestampOnly.created_at = "2026-07-26T00:00:01.000Z";
    expect(classifySupportedRuntimeIdentity(
      canonical as unknown as Record<string, unknown>,
      timestampOnly as unknown as Record<string, unknown>,
      { requireRuntimeIdentityDelta: true },
    )).toBe("UNKNOWN");

    const freshIdentity = JSON.parse(
      JSON.stringify(timestampOnly),
    ) as LaunchManifest;
    freshIdentity.execution.target.pid = 102;
    expect(classifySupportedRuntimeIdentity(
      canonical as unknown as Record<string, unknown>,
      freshIdentity as unknown as Record<string, unknown>,
      { requireRuntimeIdentityDelta: true },
    )).toBe("RUNTIME_IDENTITY");
  });

  it("keeps canonical launch bytes immutable and retains a conflicting candidate artifact", () => {
    const first = launchManifest(fixture);
    expect(preflight(fixture, first).code).toBe(0);
    const canonicalFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "launches",
      "TASK-A",
      `${first.launch_id}.json`,
    );
    const canonicalBefore = readFileSync(canonicalFile, "utf8");
    const second = {
      ...first,
      // This field was intentionally excluded from immutableLaunchIdentity.
      // Reusing a launch id must nevertheless require byte-exact equality.
      created_at: "2026-07-22T00:00:01.000Z",
    };
    const evidenceId = `preflight-launch-conflict-${randomUUID()}`;

    const rejected = preflight(fixture, second, evidenceId);

    expectFailedCheck(rejected, "LAUNCH_ID_CONFLICT");
    expect(readFileSync(canonicalFile, "utf8")).toBe(canonicalBefore);
    const candidateFile = path.join(
      fixture.controlDir,
      "goals",
      "demo",
      "evidence-artifacts",
      "TASK-A",
      `${evidenceId}-launch.json`,
    );
    expect(readFileSync(candidateFile, "utf8")).toBe(
      `${JSON.stringify(second, null, 2)}\n`,
    );
    expect(parse(rejected)).toMatchObject({
      evidence_id: evidenceId,
      status: "FAIL",
      launch_id: first.launch_id,
    });
  });

  it("fails closed when launch packet digest is stale", () => {
    const launch = launchManifest(fixture);
    launch.packet.sha256 = `sha256:${"0".repeat(64)}`;

    expectFailedCheck(preflight(fixture, launch), "STALE_PACKET");
  });

  it("fails closed when the declared runtime does not match the executing runtime", () => {
    const launch = launchManifest(fixture);
    launch.runtime.node_version = "v0.0.0-stale";

    expectFailedCheck(preflight(fixture, launch), "NODE_VERSION_MISMATCH");
  });

  it("binds a live PID to the declared executable instead of accepting two unrelated facts", () => {
    const launch = launchManifest(fixture);
    const started = execFileSync("ps", ["-p", String(process.pid), "-o", "lstart="], { encoding: "utf8" }).trim();
    launch.execution.target = {
      kind: "PREVIEW",
      executable_path: realpathSync("/bin/sh"),
      pid: process.pid,
      started_at: new Date(Date.parse(started)).toISOString(),
      preview_url: "http://127.0.0.1:8123",
      build_head: fixture.fullHead,
    };

    expectFailedCheck(preflight(fixture, launch), "TARGET_EXECUTABLE_MISMATCH");
  });

  it("parses the fixed UTC process probe without caller-timezone drift", () => {
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
      }
    ).trim();
    const launch = launchManifest(fixture);
    launch.execution.target = {
      kind: "CLI",
      executable_path: realpathSync(process.execPath),
      pid: process.pid,
      started_at: new Date(Date.parse(`${started} UTC`)).toISOString(),
      build_head: fixture.fullHead,
    };

    const result = preflight(fixture, launch);
    expectFailedCheck(result, "LAUNCH_ID_CONFLICT");
    const evidence = parse(result) as {
      checks: Array<{ name: string; status: string; detail?: string }>;
    };
    expect(
      evidence.checks.find((check) => check.name === "execution-target")
    ).toMatchObject({ status: "PASS", detail: "CLI" });
  });

  it("ignores PATH-shadowed pnpm, ps and lsof when checking runtime identity", () => {
    const attackerBin = path.join(fixture.controlDir, `attacker-bin-${randomUUID()}`);
    mkdirSync(attackerBin);
    const fakePnpm = path.join(attackerBin, "pnpm");
    const fakePs = path.join(attackerBin, "ps");
    const fakeLsof = path.join(attackerBin, "lsof");
    writeFileSync(fakePnpm, "#!/bin/sh\nprintf '%s\\n' '0.0.0-shadow'\n");
    writeFileSync(
      fakePs,
      [
        "#!/bin/sh",
        "case \"$*\" in",
        "  *lstart=*) printf '%s\\n' 'Mon Jan  1 00:00:00 2001' ;;",
        "  *command=*) printf '%s\\n' \"$GOALCTL_FAKE_EXECUTABLE --forged\" ;;",
        "  *comm=*) printf '%s\\n' \"$GOALCTL_FAKE_EXECUTABLE\" ;;",
        "  *) exit 1 ;;",
        "esac",
        "",
      ].join("\n")
    );
    writeFileSync(
      fakeLsof,
      "#!/bin/sh\nprintf 'p1\\nn%s\\n' \"$GOALCTL_FAKE_EXECUTABLE\"\n"
    );
    for (const file of [fakePnpm, fakePs, fakeLsof]) chmodSync(file, 0o755);

    const launch = launchManifest(fixture);
    launch.runtime.pnpm_version = "0.0.0-shadow";
    launch.execution.target = {
      kind: "PREVIEW",
      executable_path: realpathSync(process.execPath),
      pid: process.pid,
      started_at: "2001-01-01T00:00:00.000Z",
      preview_url: "http://127.0.0.1:8123",
      build_head: fixture.fullHead,
    };
    const previousPath = process.env.PATH;
    const previousFakeExecutable = process.env.GOALCTL_FAKE_EXECUTABLE;
    process.env.PATH = `${attackerBin}${path.delimiter}${previousPath || ""}`;
    process.env.GOALCTL_FAKE_EXECUTABLE = realpathSync(process.execPath);
    try {
      const result = preflight(fixture, launch);
      expectFailedCheck(result, "PNPM_VERSION_MISMATCH");
      expect(JSON.stringify(parse(result).checks)).toContain(
        "TARGET_START_TIME_MISMATCH"
      );
    } finally {
      if (previousPath === undefined) delete process.env.PATH;
      else process.env.PATH = previousPath;
      if (previousFakeExecutable === undefined) {
        delete process.env.GOALCTL_FAKE_EXECUTABLE;
      } else {
        process.env.GOALCTL_FAKE_EXECUTABLE = previousFakeExecutable;
      }
    }
  });

  it("fails closed when the worktree becomes dirty after launch was frozen", () => {
    const launch = launchManifest(fixture);
    writeFileSync(path.join(fixture.root, "dirty-after-launch.txt"), "uncommitted\n");

    expectFailedCheck(preflight(fixture, launch), "DIRTY_WORKTREE");
  });
});
