import { execFileSync } from "child_process";
import { createHash } from "crypto";
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
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const nodeRequire = createRequire(import.meta.url);
const {
  assertMechanicalP1DependenciesArchived,
  mechanicalP1RequiredStartHead,
  mergeExpectedMainHead,
  validateCandidateBoundary,
} = nodeRequire("../scripts/goal-control/goal.js") as {
  assertMechanicalP1DependenciesArchived: (
    loaded: Record<string, unknown>,
    task: Record<string, unknown>,
  ) => void;
  mechanicalP1RequiredStartHead: (
    loaded: Record<string, unknown>,
    task: Record<string, unknown>,
  ) => string | null;
  mergeExpectedMainHead: (
    loaded: Record<string, unknown>,
    task: Record<string, unknown>,
  ) => string;
  validateCandidateBoundary: (
    cwd: string,
    loaded: Record<string, unknown>,
    state: Record<string, unknown>,
    event: Record<string, unknown>,
  ) => void;
};
const { hashObject } = nodeRequire("../scripts/goal-control/util.js") as {
  hashObject: (value: unknown) => string;
};
const { applyEvent } = nodeRequire("../scripts/goal-control/fsm.js") as {
  applyEvent: (
    state: Record<string, unknown>,
    event: Record<string, unknown>,
    controlEpoch: number,
  ) => Record<string, unknown>;
};
const {
  inspectExactUnsealedAbandonmentStaging,
  inspectP1CommitPreparation,
} = nodeRequire("../scripts/goal-control/p1-commit-transaction.js") as {
  inspectExactUnsealedAbandonmentStaging: (
    root: string,
    goalId: string,
    taskId: string,
    preparedEventId: string,
    requestSha256: string,
    foremanAuthoritySha256?: string,
  ) => Record<string, unknown> | null;
  inspectP1CommitPreparation: (
    root: string,
    goalId: string,
    taskId: string,
    eventId: string,
    requestSha256: string,
    acceptanceAuthoritySha256?: string,
  ) => Record<string, unknown> | null;
};

type CliResult = { code: number; stdout: string; stderr: string };
type Fixture = {
  root: string;
  controlDir: string;
  manifest: string;
  baseHead: string;
  goalInputHead: string;
  p1Worktree?: string;
  worktrees: string[];
  authorityPath: string;
  capabilities: Partial<Record<"FOREMAN" | "CAPTAIN", string>>;
  threads: Record<"FOREMAN" | "CAPTAIN", string>;
  bootstrapCapability?: string;
};

const fixtures: Fixture[] = [];
const GOAL = "mechanical-p1";
const TASK = "TASK-P1-A";
const PLAN = "docs/issues/4242/plan.md";
const CONTEXT = "docs/issues/4242/context.md";

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

function controlTreeFingerprint(root: string): Array<[string, string]> {
  const fingerprint: Array<[string, string]> = [];
  if (!existsSync(root)) return fingerprint;
  const visit = (directory: string, relativeDirectory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const entry = path.join(directory, name);
      const relative = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      const stat = lstatSync(entry);
      const mode = (stat.mode & 0o7777).toString(8);
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        fingerprint.push([relative, `directory:${mode}`]);
        visit(entry, relative);
      } else if (stat.isSymbolicLink()) {
        fingerprint.push([
          relative,
          `symlink:${mode}:${readlinkSync(entry)}`,
        ]);
      } else if (stat.isFile()) {
        fingerprint.push([
          relative,
          `file:${mode}:${readFileSync(entry).toString("base64")}`,
        ]);
      } else {
        fingerprint.push([relative, `other:${mode}`]);
      }
    }
  };
  visit(root, "");
  return fingerprint;
}

function writeJson(file: string, value: unknown): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function writePrivateFile(file: string, body: string | Buffer): void {
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, body, { mode: 0o600 });
  chmodSync(file, 0o600);
}

function atomicTemporary(base: string): string {
  return `.${base}.123.tmp-${"a".repeat(24)}`;
}

function acceptedEventFile(
  fixture: Fixture,
  eventId: string,
): string {
  const directory = path.join(
    fixture.controlDir,
    "goals",
    GOAL,
    "events",
    TASK,
  );
  const match = readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .map((name) => path.join(directory, name))
    .find((file) => (
      JSON.parse(readFileSync(file, "utf8")).event_id === eventId
    ));
  if (!match) throw new Error(`accepted event not found: ${eventId}`);
  return match;
}

function run(
  fixture: Fixture,
  args: string[],
  options: { cwd?: string; env?: Record<string, string> } = {},
): CliResult {
  try {
    const stdout = execFileSync("node", [GOALCTL, ...args], {
      cwd: options.cwd ?? fixture.root,
      encoding: "utf8",
      stdio: "pipe",
      env: {
        ...process.env,
        GOAL_CONTROL_DIR: fixture.controlDir,
        GOAL_CONTROL_TEST_MODE: "1",
        ...options.env,
      },
    });
    return { code: 0, stdout, stderr: "" };
  } catch (error: unknown) {
    const failure = error as {
      status?: number;
      stdout?: string;
      stderr?: string;
    };
    return {
      code: failure.status ?? 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? "",
    };
  }
}

function createP1Worktree(
  fixture: Fixture,
  branch = "codex/mechanical-p1",
  options: { createBranch?: boolean } = {},
): string {
  const worktree = realpathSync(mkdtempSync(
    path.join(tmpdir(), "goal-mechanical-p1-worktree-"),
  ));
  rmSync(worktree, { recursive: true });
  git(
    fixture.root,
    "worktree",
    "add",
    "-q",
    ...(options.createBranch === false ? [] : ["-b", branch]),
    worktree,
    ...(options.createBranch === false
      ? [branch]
      : [fixture.goalInputHead]),
  );
  fixture.p1Worktree = realpathSync(worktree);
  fixture.worktrees.push(fixture.p1Worktree);
  return fixture.p1Worktree;
}

function advanceRemoteMain(fixture: Fixture): string {
  const tree = git(fixture.root, "rev-parse", `${fixture.goalInputHead}^{tree}`);
  const advanced = execFileSync(
    "git",
    ["commit-tree", tree, "-p", fixture.goalInputHead],
    {
      cwd: fixture.root,
      encoding: "utf8",
      input: "advance origin/main after init\n",
      stdio: ["pipe", "pipe", "pipe"],
    },
  ).trim();
  git(
    fixture.root,
    "update-ref",
    "refs/remotes/origin/main",
    advanced,
  );
  return advanced;
}

function p1Checkout(fixture: Fixture): string {
  if (!fixture.p1Worktree) throw new Error("P1 worktree not created");
  return fixture.p1Worktree;
}

function parse<T>(result: CliResult): T {
  if (result.code !== 0) {
    throw new Error(
      `unexpected CLI exit ${result.code}: ${result.stderr}`,
    );
  }
  expect(result.code).toBe(0);
  expect(result.stdout).not.toBe("");
  return JSON.parse(result.stdout) as T;
}

function makeFixture(): Fixture {
  const root = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-mechanical-p1-repo-")),
  );
  const controlDir = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-mechanical-p1-store-")),
  );
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.email", "mechanical-p1@example.test");
  git(root, "config", "user.name", "Mechanical P1 Test");
  writeFileSync(path.join(root, "README.md"), "# mechanical P1 fixture\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "code baseline");
  const baseHead = git(root, "rev-parse", "HEAD");

  for (const file of [
    "docs/planning/session-role-protocol.md",
    "docs/planning/session-protocol/shared.md",
    "docs/planning/session-protocol/foreman.md",
    "docs/planning/session-protocol/captain.md",
    "docs/planning/session-protocol/role-kernel.md",
  ]) {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    writeFileSync(path.join(root, file), `# ${path.basename(file)}\n`);
  }
  const authorityPath =
    "docs/planning/goals/mechanical-p1.authorization.md";
  const authorityBody = [
    "# Scoped delegation",
    "",
    "- Goal: mechanical-p1",
    "- Tasks: TASK-P1-A, TASK-P1-B",
    "- Scope: normalize frozen sources only",
    "",
  ].join("\n");
  mkdirSync(path.dirname(path.join(root, authorityPath)), { recursive: true });
  writeFileSync(path.join(root, authorityPath), authorityBody);
  mkdirSync(path.join(root, "goal-inputs"), { recursive: true });
  writeFileSync(
    path.join(root, "goal-inputs", "TASK-P1-A.md"),
    "# TASK-P1-A\n\nFrozen packet A.\n",
  );
  writeFileSync(
    path.join(root, "goal-inputs", "TASK-P1-B.md"),
    "# TASK-P1-B\n\nFrozen packet B.\n",
  );
  const policy = (issue: number) => ({
    producer: "CAPTAIN",
    artifact_root: `docs/issues/${issue}`,
    authority: {
      kind: "SCOPED_DELEGATION",
      path: authorityPath,
      sha256: sha256(authorityBody),
    },
    dependency_gate: "ARCHIVED",
  });
  writeJson(path.join(root, "goal-inputs", "spec.json"), {
    schema_version: 1,
    goal_id: GOAL,
    mode: "shadow",
    repository: {
      name_with_owner: "example-org/example-repo",
      base_branch: "main",
    },
    base_head: baseHead,
    tasks: [
      {
        id: TASK,
        issue: 4242,
        dependencies: [],
        integration_order: 1,
        packet_source: "goal-inputs/TASK-P1-A.md",
        packet_revision: 1,
        p1: policy(4242),
        expected_write_set: [],
        conflict_domains: [],
        resource_requirements: [],
      },
      {
        id: "TASK-P1-B",
        issue: 4243,
        dependencies: [TASK],
        integration_order: 2,
        packet_source: "goal-inputs/TASK-P1-B.md",
        packet_revision: 1,
        p1: policy(4243),
        expected_write_set: [],
        conflict_domains: [],
        resource_requirements: [],
      },
    ],
  });
  const fixture: Fixture = {
    root,
    controlDir,
    manifest: "docs/planning/goals/mechanical-p1/manifest.json",
    baseHead,
    goalInputHead: "",
    worktrees: [],
    authorityPath,
    capabilities: {},
    threads: {
      FOREMAN: "foreman-mechanical-p1",
      CAPTAIN: "captain-mechanical-p1",
    },
  };
  fixtures.push(fixture);
  const scaffold = run(fixture, [
    "scaffold",
    "--spec",
    "goal-inputs/spec.json",
    "--output-dir",
    "docs/planning/goals/mechanical-p1",
    "--json",
  ]);
  expect(scaffold.code).toBe(0);
  git(root, "add", ".");
  git(root, "commit", "-qm", "freeze mechanical goal inputs");
  fixture.goalInputHead = git(root, "rev-parse", "HEAD");
  git(
    root,
    "update-ref",
    "refs/remotes/origin/main",
    fixture.goalInputHead,
  );
  return fixture;
}

function initializeAndRegister(
  fixture: Fixture,
  options: { createWorktree?: boolean } = {},
): void {
  const initialized = parse<{
    goal_input_head: string;
    bootstrap_capability_file: string;
  }>(run(fixture, [
    "init",
    "--manifest",
    fixture.manifest,
    "--json",
  ]));
  expect(initialized.goal_input_head).toBe(fixture.goalInputHead);
  fixture.bootstrapCapability = initialized.bootstrap_capability_file;
  if (options.createWorktree !== false) createP1Worktree(fixture);
  const foreman = parse<{ actor_capability_file: string }>(run(fixture, [
    "register-role",
    "--goal",
    GOAL,
    "--task",
    TASK,
    "--role",
    "FOREMAN",
    "--thread",
    fixture.threads.FOREMAN,
    "--host",
    "local",
    "--attempt",
    "1",
    "--bootstrap-capability-file",
    fixture.bootstrapCapability,
    "--json",
  ]));
  fixture.capabilities.FOREMAN = foreman.actor_capability_file;
  const captain = parse<{ actor_capability_file: string }>(run(fixture, [
    "register-role",
    "--goal",
    GOAL,
    "--task",
    TASK,
    "--role",
    "CAPTAIN",
    "--thread",
    fixture.threads.CAPTAIN,
    "--host",
    "local",
    "--attempt",
    "1",
    "--authorizer-capability-file",
    fixture.capabilities.FOREMAN,
    "--json",
  ]));
  fixture.capabilities.CAPTAIN = captain.actor_capability_file;
}

function eventTemplateResult(
  fixture: Fixture,
  role: "FOREMAN" | "CAPTAIN",
  type: string,
  fullHead?: string,
  options: {
    cwd?: string;
    payload?: Record<string, unknown>;
    threadId?: string;
    capability?: string;
  } = {},
): CliResult {
  const requestedPayload = options.payload;
  const targetRole = type === "ROLE_LOST"
    ? requestedPayload?.role
    : undefined;
  const hasExplicitRoleLostTarget = [
    "expected_thread_id",
    "expected_host_id",
    "expected_attempt",
    "expected_lease_until",
  ].some((field) => (
    requestedPayload
      && Object.prototype.hasOwnProperty.call(requestedPayload, field)
  ));
  const target = type === "ROLE_LOST"
    && (targetRole === "FOREMAN" || targetRole === "CAPTAIN")
    && !hasExplicitRoleLostTarget
    ? currentMechanicalAuthority(fixture, targetRole)
    : null;
  const payload = target
    ? {
      ...requestedPayload,
      expected_thread_id: target.thread_id,
      expected_host_id: target.host_id,
      expected_attempt: target.attempt,
      expected_lease_until: target.lease_until,
    }
    : requestedPayload;
  const payloadFile = payload
    ? path.join(
      fixture.controlDir,
      `payload-${type.toLowerCase()}-${Date.now()}-${Math.random()}.json`,
    )
    : null;
  if (payloadFile) writeJson(payloadFile, payload);
  return run(fixture, [
    "event-template",
    "--goal",
    GOAL,
    "--task",
    TASK,
    "--role",
    role,
    "--thread",
    options.threadId ?? fixture.threads[role],
    "--type",
    type,
    "--actor-capability-file",
    options.capability ?? fixture.capabilities[role] as string,
    ...(payloadFile ? ["--payload-file", payloadFile] : []),
    ...(fullHead ? ["--full-head", fullHead] : []),
    "--json",
  ], { cwd: options.cwd ?? fixture.p1Worktree ?? fixture.root });
}

function eventTemplate(
  fixture: Fixture,
  role: "FOREMAN" | "CAPTAIN",
  type: string,
  fullHead?: string,
  options: {
    cwd?: string;
    payload?: Record<string, unknown>;
    threadId?: string;
    capability?: string;
  } = {},
): Record<string, unknown> {
  return parse(eventTemplateResult(
    fixture,
    role,
    type,
    fullHead,
    options,
  ));
}

function accept(
  fixture: Fixture,
  event: Record<string, unknown>,
  role: "FOREMAN" | "CAPTAIN",
  options: {
    cwd?: string;
    capability?: string;
    env?: Record<string, string>;
  } = {},
): CliResult {
  const eventFile = path.join(
    fixture.controlDir,
    `${String(event.event_id)}-${Date.now()}.json`,
  );
  writeJson(eventFile, event);
  const result = run(fixture, [
    "event",
    "--goal",
    GOAL,
    "--file",
    eventFile,
    "--actor-capability-file",
    options.capability ?? fixture.capabilities[role] as string,
    "--json",
  ], {
    cwd: options.cwd ?? fixture.p1Worktree ?? fixture.root,
    env: options.env,
  });
  return result;
}

function writeArtifacts(fixture: Fixture): void {
  const worktree = fixture.p1Worktree ?? fixture.root;
  mkdirSync(path.join(worktree, "docs", "issues", "4242", "_ref"), {
    recursive: true,
  });
  writeFileSync(
    path.join(worktree, PLAN),
    "# Plan\n\nPure normalization of frozen packet A.\n",
  );
  writeFileSync(
    path.join(worktree, CONTEXT),
    "# Context\n\nNo open questions.\n",
  );
  writeFileSync(
    path.join(worktree, "docs", "issues", "4242", "_ref", "source.md"),
    "# Frozen source\n",
  );
}

function enterReady(fixture: Fixture): Record<string, unknown> {
  const start = eventTemplate(fixture, "CAPTAIN", "START_P1");
  expect(start.payload).toEqual({
    required_start_head: fixture.goalInputHead,
    p1_worktree: fixture.p1Worktree,
    p1_branch: "codex/mechanical-p1",
  });
  expect(accept(fixture, start, "CAPTAIN").code).toBe(0);
  writeArtifacts(fixture);
  const ready = eventTemplate(fixture, "CAPTAIN", "P1_READY");
  expect(ready.payload).toEqual(expect.objectContaining({
    plan_path: PLAN,
    context_path: CONTEXT,
    artifact_manifest_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    p1_worktree: fixture.p1Worktree,
    p1_branch: "codex/mechanical-p1",
  }));
  expect(accept(fixture, ready, "CAPTAIN").code).toBe(0);
  return ready;
}

function enterApproved(fixture: Fixture): Record<string, unknown> {
  enterReady(fixture);
  const approval = eventTemplate(fixture, "FOREMAN", "P1_APPROVED");
  expect(approval.payload).toEqual(expect.objectContaining({
    approval_ref: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    artifact_manifest_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
  }));
  expect(accept(fixture, approval, "FOREMAN").code).toBe(0);
  return approval;
}

function commitApprovedP1(fixture: Fixture): string {
  enterApproved(fixture);
  const worktree = p1Checkout(fixture);
  git(worktree, "add", "docs/issues/4242");
  git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
  const head = git(worktree, "rev-parse", "HEAD");
  const committed = eventTemplate(
    fixture,
    "CAPTAIN",
    "P1_COMMITTED",
    head,
  );
  expect(accept(fixture, committed, "CAPTAIN").code).toBe(0);
  return head;
}

function enterMechanicalP1Phase(
  fixture: Fixture,
  phase: "P1_ACTIVE" | "P1_READY" | "P1_APPROVED",
): void {
  if (phase === "P1_APPROVED") {
    enterApproved(fixture);
    return;
  }
  if (phase === "P1_READY") {
    enterReady(fixture);
    return;
  }
  const start = eventTemplate(fixture, "CAPTAIN", "START_P1");
  expect(accept(fixture, start, "CAPTAIN").code).toBe(0);
}

function removeLinkedWorktree(fixture: Fixture, worktree: string): void {
  git(fixture.root, "worktree", "remove", "--force", worktree);
  if (existsSync(worktree)) {
    rmSync(worktree, { recursive: true, force: true });
  }
  if (fixture.p1Worktree === worktree) fixture.p1Worktree = undefined;
}

function currentMechanicalAuthority(
  fixture: Fixture,
  role: "FOREMAN" | "CAPTAIN",
): {
  role: string;
  thread_id: string;
  host_id: string;
  attempt: number;
  capability_file: string;
  capability_sha256: string;
  lease_until: string;
} {
  const snapshot = JSON.parse(readFileSync(path.join(
    fixture.controlDir,
    "goals",
    GOAL,
    "state.json",
  ), "utf8")) as {
    tasks: Record<string, {
      sessions: Record<string, {
        role: string;
        thread_id: string;
        host_id: string;
        attempt: number;
        capability_file: string;
        capability_sha256: string;
        lease_until: string;
      }>;
    }>;
  };
  const session = snapshot.tasks[TASK].sessions[role];
  return {
    role: session.role,
    thread_id: session.thread_id,
    host_id: session.host_id,
    attempt: session.attempt,
    capability_file: session.capability_file,
    capability_sha256: session.capability_sha256,
    lease_until: session.lease_until,
  };
}

function currentMechanicalAuthoritySha(
  fixture: Fixture,
  role: "FOREMAN" | "CAPTAIN",
): string {
  return hashObject(currentMechanicalAuthority(fixture, role));
}

function p1CommitStaging(
  fixture: Fixture,
  event: Record<string, unknown>,
): string {
  const requestSha = hashObject(event);
  const authoritySha = currentMechanicalAuthoritySha(fixture, "CAPTAIN");
  return path.join(
    fixture.controlDir,
    "goals",
    GOAL,
    "p1-commit-intents",
    TASK,
    `.init-p1-commit-${
      sha256(String(event.event_id)).slice("sha256:".length)
    }-${requestSha.slice("sha256:".length)}-${
      authoritySha.slice("sha256:".length)
    }`,
  );
}

function removeP1WorktreeAndPrune(
  fixture: Fixture,
  worktree: string,
  branch: string,
): void {
  removeLinkedWorktree(fixture, worktree);
  git(fixture.root, "branch", "-D", branch);
  git(fixture.root, "reflog", "expire", "--expire=now", "--all");
  git(fixture.root, "gc", "--prune=now");
}

function privateDirectoryFingerprint(directory: string): unknown {
  const directoryStat = statSync(directory);
  return {
    directory_mtime_ms: directoryStat.mtimeMs,
    entries: readdirSync(directory).sort().map((name) => {
    const body = readFileSync(path.join(directory, name));
    const stat = statSync(path.join(directory, name));
    return {
      name,
      size: body.length,
      sha256: sha256(body),
      mtime_ms: stat.mtimeMs,
    };
    }),
  };
}

function recoverAndRestartMechanicalP1(
  fixture: Fixture,
  phase: "P1_ACTIVE" | "P1_READY" | "P1_APPROVED",
): {
  abandonedWorktree: string;
  abandonedBranch: string;
  freshWorktree: string;
  freshBranch: string;
  oldCaptainCapability: string;
  oldCaptainHeartbeat: Record<string, unknown>;
  restart: Record<string, unknown>;
} {
  enterMechanicalP1Phase(fixture, phase);
  const abandonedWorktree = p1Checkout(fixture);
  const abandonedBranch = git(abandonedWorktree, "branch", "--show-current");
  const oldCaptainCapability = fixture.capabilities.CAPTAIN as string;
  const oldCaptainHeartbeat = eventTemplate(
    fixture,
    "CAPTAIN",
    "HEARTBEAT",
  );
  const lost = eventTemplate(
    fixture,
    "FOREMAN",
    "ROLE_LOST",
    undefined,
    {
      payload: {
        role: "CAPTAIN",
        reason: `simulated CAPTAIN crash in ${phase}`,
      },
    },
  );
  expect(accept(fixture, lost, "FOREMAN").code).toBe(0);

  removeLinkedWorktree(fixture, abandonedWorktree);
  const freshBranch = `codex/mechanical-p1-recovered-${phase.toLowerCase()}`;
  const freshWorktree = createP1Worktree(fixture, freshBranch);
  const successorThread = `captain-mechanical-p1-${phase.toLowerCase()}-2`;
  const registered = parse<{ actor_capability_file: string }>(run(fixture, [
    "register-role",
    "--goal",
    GOAL,
    "--task",
    TASK,
    "--role",
    "CAPTAIN",
    "--thread",
    successorThread,
    "--host",
    "local",
    "--attempt",
    "2",
    "--authorizer-capability-file",
    fixture.capabilities.FOREMAN as string,
    "--json",
  ], { cwd: freshWorktree }));
  fixture.capabilities.CAPTAIN = registered.actor_capability_file;
  fixture.threads.CAPTAIN = successorThread;

  const recovered = eventTemplate(
    fixture,
    "FOREMAN",
    "ROLE_RECOVERED",
    undefined,
    {
      cwd: freshWorktree,
      payload: { successor_thread_id: successorThread },
    },
  );
  expect(accept(
    fixture,
    recovered,
    "FOREMAN",
    { cwd: freshWorktree },
  ).code).toBe(0);

  const restart = eventTemplate(
    fixture,
    "FOREMAN",
    "P1_RESTARTED",
    undefined,
    {
      cwd: freshWorktree,
      payload: {
        reason: `sealed worktree disappeared in ${phase}`,
        incident_ref: `incident:${phase.toLowerCase()}:worktree-removed`,
      },
    },
  );
  expect(restart.payload).toEqual(expect.objectContaining({
    predecessor_thread_id: "captain-mechanical-p1",
    predecessor_host_id: "local",
    predecessor_attempt: 1,
    successor_thread_id: successorThread,
    successor_host_id: "local",
    successor_attempt: 2,
    abandoned_p1_worktree: abandonedWorktree,
    abandoned_p1_branch: abandonedBranch,
  }));
  expect(accept(
    fixture,
    restart,
    "FOREMAN",
    { cwd: freshWorktree },
  ).code).toBe(0);
  return {
    abandonedWorktree,
    abandonedBranch,
    freshWorktree,
    freshBranch,
    oldCaptainCapability,
    oldCaptainHeartbeat,
    restart,
  };
}

function mechanicalControlState(
  phase: "QUEUED" | "P1_ACTIVE",
): Record<string, unknown> {
  const fullHead = "1".repeat(40);
  const policy = {
    producer: "CAPTAIN",
    artifact_root: "docs/issues/4242",
    authority: {
      kind: "SCOPED_DELEGATION",
      path: "docs/planning/goals/mechanical-p1.authorization.md",
      sha256: `sha256:${"a".repeat(64)}`,
    },
    dependency_gate: "ARCHIVED",
  };
  return {
    task_id: TASK,
    phase,
    state_revision: 4,
    control_epoch: 1,
    task_cycle: 1,
    packet: {
      revision: 1,
      path: "goal-inputs/TASK-P1-A.md",
      sha256: `sha256:${"b".repeat(64)}`,
    },
    base_head: fullHead,
    full_head: fullHead,
    pr: null,
    holds: [],
    sessions: {
      FOREMAN: {
        role: "FOREMAN",
        thread_id: "foreman-control",
        host_id: "local",
        attempt: 1,
        status: "active",
        lease_until: "2099-01-01T00:00:00.000Z",
      },
      CAPTAIN: {
        role: "CAPTAIN",
        thread_id: "captain-control",
        host_id: "local",
        attempt: 1,
        status: "active",
        lease_until: "2099-01-01T00:00:00.000Z",
      },
    },
    session_history: {},
    actor_sequences: {},
    last_reconciled_epoch: 1,
    reconcile_required: null,
    p1: phase === "QUEUED"
      ? { policy }
      : {
        policy,
        required_start_head: fullHead,
        worktree: "/tmp/abandoned-mechanical-p1",
        branch: "codex/abandoned-mechanical-p1",
      },
    evidence: {},
    recovery: null,
    recovery_backlog: [],
    merge: null,
    last_event: null,
  };
}

function foremanControlEvent(
  state: Record<string, unknown>,
  type: string,
  payload: Record<string, unknown>,
  controlEpoch = 1,
): Record<string, unknown> {
  return {
    schema_version: 1,
    event_id: `${type.toLowerCase()}-${String(state.phase).toLowerCase()}`,
    goal_id: GOAL,
    task_id: TASK,
    type,
    actor: {
      role: "FOREMAN",
      thread_id: "foreman-control",
      host_id: "local",
    },
    actor_sequence: 1,
    expected_state_revision: state.state_revision,
    control_epoch: controlEpoch,
    packet: state.packet,
    base_head: state.base_head,
    full_head: state.full_head,
    payload,
  };
}

afterEach(() => {
  while (fixtures.length > 0) {
    const fixture = fixtures.pop();
    if (!fixture) continue;
    for (const worktree of fixture.worktrees) {
      rmSync(worktree, { recursive: true, force: true });
    }
    rmSync(fixture.root, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
  }
});

describe("mechanically scoped fresh-Goal P1", () => {
  it("recovers a published mechanical init witness after response loss", () => {
    const fixture = makeFixture();
    const interrupted = run(fixture, [
      "init",
      "--manifest",
      fixture.manifest,
      "--json",
    ], {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_INIT_PUBLISH: "throw",
      },
    });
    expect(interrupted.code).toBe(2);
    expect(interrupted.stderr).toContain("TEST_FAULT_AFTER_INIT_PUBLISH");
    const goalDirectory = path.join(fixture.controlDir, "goals", GOAL);
    writePrivateFile(
      path.join(goalDirectory, "state.json"),
      "{\"interrupted_projection\":true}\n",
    );
    writePrivateFile(
      path.join(goalDirectory, "event-heads", `${TASK}.json`),
      "{\"interrupted_head\":true}\n",
    );
    const generationFile = path.join(
      fixture.controlDir,
      ".generation.json",
    );
    expect(JSON.parse(readFileSync(generationFile, "utf8")).generation % 2)
      .toBe(1);

    const retriedResult = run(fixture, [
      "init",
      "--manifest",
      fixture.manifest,
      "--json",
    ]);
    expect({
      code: retriedResult.code,
      stderr: retriedResult.stderr,
    }).toEqual({ code: 0, stderr: "" });
    const retried = parse<{
      initialized: boolean;
      idempotent: boolean;
      goal_input_head: string;
      cache_degraded: boolean;
    }>(retriedResult);
    expect(retried).toMatchObject({
      initialized: false,
      idempotent: true,
      goal_input_head: fixture.goalInputHead,
      cache_degraded: false,
    });
    expect(JSON.parse(readFileSync(generationFile, "utf8")).generation % 2)
      .toBe(0);
    for (const name of ["state.json", "ledger.json", "ledger.md"]) {
      expect(existsSync(path.join(goalDirectory, name))).toBe(true);
    }
    expect(readFileSync(path.join(goalDirectory, "state.json"), "utf8"))
      .not.toContain("interrupted_projection");
  });

  it("keeps a published mechanical init odd when its inventory has foreign bytes", () => {
    const fixture = makeFixture();
    const interrupted = run(fixture, [
      "init",
      "--manifest",
      fixture.manifest,
      "--json",
    ], {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_INIT_PUBLISH: "throw",
      },
    });
    expect(interrupted.code).toBe(2);
    const foreignFile = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "foreign.bin",
    );
    writePrivateFile(foreignFile, "do-not-delete\n");

    const retried = run(fixture, [
      "init",
      "--manifest",
      fixture.manifest,
      "--json",
    ]);
    expect(retried.code).toBe(2);
    expect(retried.stderr).toContain("PREPARED_STAGING_INVALID");
    expect(readFileSync(foreignFile, "utf8")).toBe("do-not-delete\n");
    expect(JSON.parse(readFileSync(
      path.join(fixture.controlDir, ".generation.json"),
      "utf8",
    )).generation % 2).toBe(1);
  });

  it("scaffolds, seals goal_input_head, derives payloads, and commits exact artifacts", () => {
    const fixture = makeFixture();
    const generatedManifest = JSON.parse(
      readFileSync(path.join(fixture.root, fixture.manifest), "utf8"),
    ) as { tasks: Array<{ p1?: Record<string, unknown> }> };
    expect(generatedManifest.tasks.every((task) => task.p1)).toBe(true);

    initializeAndRegister(fixture);
    const receipt = JSON.parse(readFileSync(path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "init-receipt.json",
    ), "utf8")) as Record<string, unknown>;
    const receiptSha = receipt.receipt_sha256;
    delete receipt.receipt_sha256;
    expect(receipt.goal_input_head).toBe(fixture.goalInputHead);
    expect(receipt.goal_input_source).toBe("refs/remotes/origin/main");
    expect(receiptSha).toBe(hashObject(receipt));
    const metadata = JSON.parse(readFileSync(path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "goal.json",
    ), "utf8")) as {
      goal_input_head: string;
      goal_input_source: string;
    };
    expect(metadata.goal_input_head).toBe(fixture.goalInputHead);
    expect(metadata.goal_input_source).toBe("refs/remotes/origin/main");

    const initialStatus = parse<{
      goal_input_head: string;
      tasks: Record<string, {
        required_start_head: string | null;
        base_head: string;
      }>;
    }>(run(fixture, ["status", "--goal", GOAL, "--json"]));
    expect(initialStatus.goal_input_head).toBe(fixture.goalInputHead);
    expect(initialStatus.tasks[TASK]).toMatchObject({
      required_start_head: fixture.goalInputHead,
      base_head: fixture.baseHead,
    });
    expect(initialStatus.tasks["TASK-P1-B"].required_start_head).toBeNull();
    const next = parse<{
      goal_input_head: string;
      batch: Array<{ task_id: string; required_start_head: string }>;
      tasks: Array<{ task_id: string; reasons: string[] }>;
    }>(run(fixture, ["next", "--goal", GOAL, "--json"]));
    expect(next.goal_input_head).toBe(fixture.goalInputHead);
    expect(next.batch.map((row) => row.task_id)).toEqual([TASK]);
    expect(next.batch[0].required_start_head).toBe(fixture.goalInputHead);
    expect(
      next.tasks.find((row) => row.task_id === "TASK-P1-B")?.reasons,
    ).toContain(`dependencies=${TASK}:QUEUED`);

    enterApproved(fixture);
    const worktree = p1Checkout(fixture);
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
    const p1Commit = git(worktree, "rev-parse", "HEAD");
    expect(git(worktree, "rev-parse", `${p1Commit}^`)).toBe(
      fixture.goalInputHead,
    );
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      p1Commit,
    );
    expect(accept(fixture, committed, "CAPTAIN").code).toBe(0);
    const finalStatus = parse<{
      tasks: Record<string, {
        phase: string;
        base_head: string;
        full_head: string;
        p1: {
          artifact_manifest_sha256: string;
          required_approval_ref: string;
        };
      }>;
    }>(run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]));
    expect(finalStatus.tasks[TASK]).toMatchObject({
      phase: "P1_COMMITTED",
      base_head: fixture.goalInputHead,
      full_head: p1Commit,
    });
    expect(finalStatus.tasks[TASK].p1.artifact_manifest_sha256).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    expect(finalStatus.tasks[TASK].p1.required_approval_ref).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    expect(finalStatus.tasks[TASK].p1).toMatchObject({
      commit_sha: p1Commit,
      commit_ref: committed.payload
        && (committed.payload as Record<string, unknown>).p1_commit_ref,
      commit_branch: String(
        (committed.payload as Record<string, unknown>).p1_commit_ref,
      ).slice("refs/heads/".length),
    });
  });

  it.each([
    "P1_ACTIVE",
    "P1_READY",
    "P1_APPROVED",
  ] as const)(
    "recovers a lost CAPTAIN and mechanically restarts %s on a fresh worktree",
    (phase) => {
      const fixture = makeFixture();
      initializeAndRegister(fixture);
      const recovered = recoverAndRestartMechanicalP1(fixture, phase);
      expect(existsSync(recovered.abandonedWorktree)).toBe(false);

      const afterRestart = parse<{
        tasks: Record<string, {
          phase: string;
          task_cycle: number;
          p1: Record<string, unknown>;
          sessions: {
            CAPTAIN: {
              thread_id: string;
              p1_restart: {
                event_id: string;
                abandoned_phase: string;
              };
            };
          };
        }>;
      }>(run(fixture, [
        "status",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--json",
      ], { cwd: recovered.freshWorktree }));
      expect(afterRestart.tasks[TASK]).toMatchObject({
        phase: "QUEUED",
        task_cycle: 2,
        p1: { policy: expect.any(Object) },
        sessions: {
          CAPTAIN: {
            thread_id: fixture.threads.CAPTAIN,
            p1_restart: {
              event_id: recovered.restart.event_id,
              abandoned_phase: phase,
            },
          },
        },
      });
      expect(afterRestart.tasks[TASK].p1).not.toHaveProperty("worktree");
      expect(afterRestart.tasks[TASK].p1).not.toHaveProperty(
        "approval_event_id",
      );

      if (phase === "P1_ACTIVE") {
        const duplicate = parse<{ idempotent: boolean }>(accept(
          fixture,
          recovered.restart,
          "FOREMAN",
          { cwd: recovered.freshWorktree },
        ));
        expect(duplicate.idempotent).toBe(true);
        const secondRestart = eventTemplateResult(
          fixture,
          "FOREMAN",
          "P1_RESTARTED",
          undefined,
          {
            cwd: recovered.freshWorktree,
            payload: {
              reason: "must not reuse one recovery lineage",
              incident_ref: "incident:duplicate-restart",
            },
          },
        );
        expect(secondRestart.code).toBe(2);
        expect(secondRestart.stderr).toContain("EVENT_NOT_ALLOWED");

        const oldIdentity = accept(
          fixture,
          recovered.oldCaptainHeartbeat,
          "CAPTAIN",
          {
            cwd: recovered.freshWorktree,
            capability: recovered.oldCaptainCapability,
          },
        );
        expect(oldIdentity.code).toBe(2);
        expect(oldIdentity.stderr).toContain("CAPABILITY_INVALID");
      }

      const freshStart = eventTemplate(
        fixture,
        "CAPTAIN",
        "START_P1",
        undefined,
        { cwd: recovered.freshWorktree },
      );
      expect(freshStart.payload).toEqual({
        required_start_head: fixture.goalInputHead,
        p1_worktree: recovered.freshWorktree,
        p1_branch: recovered.freshBranch,
      });
      expect(accept(
        fixture,
        freshStart,
        "CAPTAIN",
        { cwd: recovered.freshWorktree },
      ).code).toBe(0);
    },
  );

  it("seals an exact CAPTAIN ABANDON_HANDOFF for a foreign ref before FOREMAN tombstones it", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterApproved(fixture);
    const worktree = p1Checkout(fixture);
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
    const head = git(worktree, "rev-parse", "HEAD");
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      head,
    );
    const interrupted = accept(fixture, committed, "CAPTAIN", {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL: "1",
      },
    });
    expect(interrupted.stderr).toContain(
      "TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL",
    );
    const generationFile = path.join(
      fixture.controlDir,
      ".generation.json",
    );
    const oddGenerationBody = readFileSync(generationFile);
    expect(
      (JSON.parse(oddGenerationBody.toString("utf8")) as {
        generation: number;
      }).generation % 2,
    ).toBe(1);
    const intentDirectory = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "p1-commit-intents",
      TASK,
      String(committed.event_id),
    );
    const intentBeforeHandoff =
      privateDirectoryFingerprint(intentDirectory);

    const changed = JSON.parse(JSON.stringify(committed)) as Record<
      string,
      unknown
    >;
    changed.payload = {
      ...(changed.payload as Record<string, unknown>),
      plan_path: "docs/issues/4242/different-plan.md",
    };
    const mismatched = accept(fixture, changed, "CAPTAIN");
    expect(mismatched.code).toBe(2);
    expect(mismatched.stderr).toContain("STORE_TRANSACTION_MISMATCH");
    expect(readFileSync(generationFile)).toEqual(oddGenerationBody);
    expect(privateDirectoryFingerprint(intentDirectory)).toEqual(
      intentBeforeHandoff,
    );

    const wrongCapability = accept(
      fixture,
      committed,
      "CAPTAIN",
      { capability: fixture.capabilities.FOREMAN },
    );
    expect(wrongCapability.code).toBe(2);
    expect(wrongCapability.stderr).toContain("CAPABILITY_INVALID");
    expect(readFileSync(generationFile)).toEqual(oddGenerationBody);
    expect(privateDirectoryFingerprint(intentDirectory)).toEqual(
      intentBeforeHandoff,
    );

    const commitRef = String(
      (committed.payload as Record<string, unknown>).p1_commit_ref,
    );
    git(
      fixture.root,
      "update-ref",
      commitRef,
      fixture.goalInputHead,
      "0000000000000000000000000000000000000000",
    );
    const handedOff = parse<{
      accepted: boolean;
      idempotent: boolean;
      abandonment_required: boolean;
      intent_sha256: string;
      abandon_handoff_sha256: string;
      reason_code: string;
    }>(accept(fixture, committed, "CAPTAIN"));
    expect(handedOff).toMatchObject({
      accepted: false,
      idempotent: false,
      abandonment_required: true,
      reason_code: "FOREIGN_REF_CONFLICT",
    });
    expect(
      (JSON.parse(readFileSync(generationFile, "utf8")) as {
        generation: number;
      }).generation % 2,
    ).toBe(0);
    const handoffFile = path.join(
      intentDirectory,
      "abandon-handoff.json",
    );
    const handoffBody = readFileSync(handoffFile);
    const handoff = JSON.parse(handoffBody.toString("utf8")) as {
      handoff_sha256: string;
      intent_sha256: string;
      request_sha256: string;
      acceptance_authority_sha256: string;
      task_anchor_sha256: string;
      reason_code: string;
      ref_binding: {
        commit_ref: string;
        expected_ref_head: string;
        observed_actual_ref: string;
      };
    };
    expect(handoff).toMatchObject({
      handoff_sha256: handedOff.abandon_handoff_sha256,
      intent_sha256: handedOff.intent_sha256,
      request_sha256: hashObject(committed),
      acceptance_authority_sha256:
        currentMechanicalAuthoritySha(fixture, "CAPTAIN"),
      reason_code: "FOREIGN_REF_CONFLICT",
      ref_binding: {
        commit_ref: commitRef,
        expected_ref_head: head,
        observed_actual_ref: fixture.goalInputHead,
      },
    });
    expect(handoff.task_anchor_sha256).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    expect(() => acceptedEventFile(
      fixture,
      String(committed.event_id),
    )).toThrow();

    git(
      fixture.root,
      "update-ref",
      commitRef,
      head,
      fixture.goalInputHead,
    );
    const lateExactRetry = parse<{
      accepted: boolean;
      idempotent: boolean;
      abandonment_required: boolean;
    }>(accept(
      fixture,
      committed,
      "CAPTAIN",
    ));
    expect(lateExactRetry).toMatchObject({
      accepted: false,
      idempotent: true,
      abandonment_required: true,
    });
    expect(readFileSync(handoffFile)).toEqual(handoffBody);
    expect(git(fixture.root, "rev-parse", commitRef)).toBe(head);
    git(
      fixture.root,
      "update-ref",
      commitRef,
      fixture.goalInputHead,
      head,
    );

    const abandoned = parse<{
      abandoned: boolean;
      prepared_event_id: string;
    }>(run(fixture, [
      "p1-abandon-commit",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--prepared-event-id",
      String(committed.event_id),
      "--event-id",
      "abandon-foreign-ref-handoff-a1",
      "--expected-intent-sha256",
      handedOff.intent_sha256,
      "--expected-commit-ref",
      commitRef,
      "--expected-ref-head",
      head,
      "--thread",
      fixture.threads.FOREMAN,
      "--reason",
      "create-only P1 ref was already occupied by a foreign commit",
      "--incident-ref",
      "incident:p1-foreign-ref-handoff",
      "--foreman-capability-file",
      fixture.capabilities.FOREMAN as string,
      "--json",
    ]));
    expect(abandoned).toMatchObject({
      abandoned: true,
      prepared_event_id: committed.event_id,
    });
    expect(git(fixture.root, "rev-parse", commitRef)).toBe(
      fixture.goalInputHead,
    );
    expect(readFileSync(handoffFile)).toEqual(handoffBody);
    const oldRetry = accept(
      fixture,
      committed,
      "CAPTAIN",
    );
    expect(oldRetry.code).toBe(2);
    expect(oldRetry.stderr).toContain("P1_COMMIT_ABANDONED");
  });

  it.each([
    [
      "temporary create",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_TEMP_CREATE",
      false,
      false,
    ],
    [
      "temporary write",
      "GOAL_CONTROL_TEST_FAULT_DURING_P1_HANDOFF_TEMP_WRITE",
      false,
      false,
    ],
    [
      "complete temporary write",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_TEMP_WRITE",
      true,
      false,
    ],
    [
      "temporary fsync",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_TEMP_FSYNC",
      true,
      false,
    ],
    [
      "no-clobber link",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_LINK",
      true,
      true,
    ],
    [
      "durable promotion",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_PROMOTION",
      true,
      true,
    ],
  ] as const)(
    "exact-retries an odd P1 handoff after process exit around %s",
    (
      _stage,
      faultVariable,
      expectedComplete,
      expectedCanonical,
    ) => {
      const fixture = makeFixture();
      initializeAndRegister(fixture);
      enterApproved(fixture);
      const worktree = p1Checkout(fixture);
      git(worktree, "add", "docs/issues/4242");
      git(
        worktree,
        "commit",
        "-qm",
        "docs(issue-4242): P1 plan + context",
      );
      const head = git(worktree, "rev-parse", "HEAD");
      const committed = eventTemplate(
        fixture,
        "CAPTAIN",
        "P1_COMMITTED",
        head,
      );
      const initialFault = accept(fixture, committed, "CAPTAIN", {
        env: {
          GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL: "1",
        },
      });
      expect(initialFault.stderr).toContain(
        "TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL",
      );
      const generationFile = path.join(
        fixture.controlDir,
        ".generation.json",
      );
      expect(
        (JSON.parse(readFileSync(generationFile, "utf8")) as {
          generation: number;
        }).generation % 2,
      ).toBe(1);
      const commitRef = String(
        (committed.payload as Record<string, unknown>).p1_commit_ref,
      );
      git(
        fixture.root,
        "update-ref",
        commitRef,
        fixture.goalInputHead,
        "0000000000000000000000000000000000000000",
      );

      const crashed = accept(fixture, committed, "CAPTAIN", {
        env: { [faultVariable]: "exit" },
      });
      expect(crashed.code).toBe(86);
      const intentDirectory = path.join(
        fixture.controlDir,
        "goals",
        GOAL,
        "p1-commit-intents",
        TASK,
        String(committed.event_id),
      );
      const temporaryName = readdirSync(intentDirectory).find(
        (name) => name.startsWith(".abandon-handoff-"),
      );
      expect(temporaryName).toBeDefined();
      const temporaryFile = path.join(
        intentDirectory,
        temporaryName as string,
      );
      const canonicalFile = path.join(
        intentDirectory,
        "abandon-handoff.json",
      );
      const preparation = inspectP1CommitPreparation(
        fixture.controlDir,
        GOAL,
        TASK,
        String(committed.event_id),
        hashObject(committed),
      ) as {
        abandonHandoff?: Record<string, unknown>;
        abandonHandoffTemporary?: {
          complete: boolean;
          observedActualRef: string;
        };
      };
      expect(preparation.abandonHandoffTemporary).toMatchObject({
        complete: expectedComplete,
        observedActualRef: fixture.goalInputHead,
      });
      expect(Boolean(preparation.abandonHandoff)).toBe(
        expectedCanonical,
      );
      expect(existsSync(canonicalFile)).toBe(expectedCanonical);
      if (expectedCanonical) {
        expect(statSync(canonicalFile).ino).toBe(
          statSync(temporaryFile).ino,
        );
      }
      const oddGenerationBody = readFileSync(generationFile);
      const crashedGeneration = JSON.parse(
        oddGenerationBody.toString("utf8"),
      ) as {
        generation: number;
        active_transaction: { key_sha256: string };
        pre_write_vector_sha256: string;
      };
      const beforeRejectedRetries =
        privateDirectoryFingerprint(intentDirectory);

      const changed = JSON.parse(JSON.stringify(committed)) as Record<
        string,
        unknown
      >;
      changed.payload = {
        ...(changed.payload as Record<string, unknown>),
        plan_path: "docs/issues/4242/wrong-after-handoff-temp.md",
      };
      const wrongRequest = accept(
        fixture,
        changed,
        "CAPTAIN",
      );
      expect(wrongRequest.code).toBe(2);
      expect(wrongRequest.stderr).toContain(
        "STORE_TRANSACTION_MISMATCH",
      );
      const mismatchedGenerationBody = readFileSync(generationFile);
      const mismatchedGeneration = JSON.parse(
        mismatchedGenerationBody.toString("utf8"),
      ) as {
        generation: number;
        active_transaction: { key_sha256: string };
        pre_write_vector_sha256: string;
      };
      expect(mismatchedGeneration).toMatchObject({
        active_transaction: {
          key_sha256:
            crashedGeneration.active_transaction.key_sha256,
        },
        pre_write_vector_sha256:
          crashedGeneration.pre_write_vector_sha256,
      });
      expect(mismatchedGeneration.generation % 2).toBe(1);
      expect(privateDirectoryFingerprint(intentDirectory)).toEqual(
        beforeRejectedRetries,
      );

      const wrongCapability = accept(
        fixture,
        committed,
        "CAPTAIN",
        { capability: fixture.capabilities.FOREMAN },
      );
      expect(wrongCapability.code).toBe(2);
      expect(wrongCapability.stderr).toContain("CAPABILITY_INVALID");
      expect(readFileSync(generationFile)).toEqual(
        mismatchedGenerationBody,
      );
      expect(privateDirectoryFingerprint(intentDirectory)).toEqual(
        beforeRejectedRetries,
      );

      const recovered = parse<{
        accepted: boolean;
        idempotent: boolean;
        abandonment_required: boolean;
        abandon_handoff_sha256: string;
      }>(accept(fixture, committed, "CAPTAIN"));
      expect(recovered).toMatchObject({
        accepted: false,
        idempotent: false,
        abandonment_required: true,
      });
      expect(existsSync(temporaryFile)).toBe(false);
      expect(existsSync(canonicalFile)).toBe(true);
      const canonical = JSON.parse(
        readFileSync(canonicalFile, "utf8"),
      ) as {
        handoff_sha256: string;
        ref_binding: { observed_actual_ref: string };
      };
      expect(canonical).toMatchObject({
        handoff_sha256: recovered.abandon_handoff_sha256,
        ref_binding: {
          observed_actual_ref: fixture.goalInputHead,
        },
      });
      expect(
        (JSON.parse(readFileSync(generationFile, "utf8")) as {
          generation: number;
        }).generation % 2,
      ).toBe(0);
    },
  );

  it("fails closed without clearing foreign handoff canonical/temporary inodes", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterApproved(fixture);
    const worktree = p1Checkout(fixture);
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
    const head = git(worktree, "rev-parse", "HEAD");
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      head,
    );
    expect(accept(fixture, committed, "CAPTAIN", {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL: "1",
      },
    }).stderr).toContain(
      "TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL",
    );
    const commitRef = String(
      (committed.payload as Record<string, unknown>).p1_commit_ref,
    );
    git(
      fixture.root,
      "update-ref",
      commitRef,
      fixture.goalInputHead,
      "0000000000000000000000000000000000000000",
    );
    const intentDirectory = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "p1-commit-intents",
      TASK,
      String(committed.event_id),
    );
    const canonicalFile = path.join(
      intentDirectory,
      "abandon-handoff.json",
    );

    writePrivateFile(canonicalFile, "{\"foreign\":");
    const foreignCanonicalBody = readFileSync(canonicalFile);
    const foreignCanonicalInode = statSync(canonicalFile).ino;
    const rejectedCanonical = accept(
      fixture,
      committed,
      "CAPTAIN",
    );
    expect(rejectedCanonical.code).toBe(2);
    expect(rejectedCanonical.stderr).toContain("CORRUPT_STORE");
    expect(readFileSync(canonicalFile)).toEqual(foreignCanonicalBody);
    expect(statSync(canonicalFile).ino).toBe(foreignCanonicalInode);
    unlinkSync(canonicalFile);

    const foreignTemporary = path.join(
      intentDirectory,
      `.abandon-handoff-${fixture.goalInputHead}-${
        "f".repeat(64)
      }.tmp`,
    );
    writePrivateFile(foreignTemporary, "foreign temporary");
    const foreignTemporaryBody = readFileSync(foreignTemporary);
    const foreignTemporaryInode = statSync(foreignTemporary).ino;
    const rejectedTemporary = accept(
      fixture,
      committed,
      "CAPTAIN",
    );
    expect(rejectedTemporary.code).toBe(2);
    expect(rejectedTemporary.stderr).toContain(
      "STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH",
    );
    expect(readFileSync(foreignTemporary)).toEqual(
      foreignTemporaryBody,
    );
    expect(statSync(foreignTemporary).ino).toBe(
      foreignTemporaryInode,
    );
    unlinkSync(foreignTemporary);

    const afterFsync = accept(fixture, committed, "CAPTAIN", {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_P1_HANDOFF_TEMP_FSYNC: "exit",
      },
    });
    expect(afterFsync.code).toBe(86);
    const exactTemporaryName = readdirSync(intentDirectory).find(
      (name) => name.startsWith(".abandon-handoff-"),
    );
    expect(exactTemporaryName).toBeDefined();
    const exactTemporary = path.join(
      intentDirectory,
      exactTemporaryName as string,
    );
    const exactBody = readFileSync(exactTemporary);
    writePrivateFile(canonicalFile, exactBody);
    expect(statSync(canonicalFile).ino).not.toBe(
      statSync(exactTemporary).ino,
    );
    const racedCanonicalBody = readFileSync(canonicalFile);
    const racedTemporaryBody = readFileSync(exactTemporary);
    const racedCanonicalInode = statSync(canonicalFile).ino;
    const racedTemporaryInode = statSync(exactTemporary).ino;
    const rejectedRace = accept(fixture, committed, "CAPTAIN");
    expect(rejectedRace.code).toBe(2);
    expect(rejectedRace.stderr).toContain("CORRUPT_STORE");
    expect(readFileSync(canonicalFile)).toEqual(racedCanonicalBody);
    expect(readFileSync(exactTemporary)).toEqual(racedTemporaryBody);
    expect(statSync(canonicalFile).ino).toBe(racedCanonicalInode);
    expect(statSync(exactTemporary).ino).toBe(
      racedTemporaryInode,
    );

    unlinkSync(canonicalFile);
    const recovered = parse<{
      accepted: boolean;
      idempotent: boolean;
      abandonment_required: boolean;
    }>(accept(fixture, committed, "CAPTAIN"));
    expect(recovered).toMatchObject({
      accepted: false,
      idempotent: false,
      abandonment_required: true,
    });
    expect(existsSync(exactTemporary)).toBe(false);
    expect(existsSync(canonicalFile)).toBe(true);
  });

  it.each([
    ["empty staging", "EMPTY_STAGING"],
    ["bundle temporary", "BUNDLE_TEMP"],
    ["intent atomic temporary", "INTENT_TEMP"],
    ["wrong canonical unsealed bundle", "BUNDLE_ONLY"],
  ] as const)(
    "projects and exact-retries a real pre-seal %s residue",
    (residue, expectedStage) => {
      const fixture = makeFixture();
      initializeAndRegister(fixture);
      enterApproved(fixture);
      const worktree = p1Checkout(fixture);
      git(worktree, "add", "docs/issues/4242");
      git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
      const head = git(worktree, "rev-parse", "HEAD");
      const committed = eventTemplate(
        fixture,
        "CAPTAIN",
        "P1_COMMITTED",
        head,
      );
      const staging = p1CommitStaging(fixture, committed);
      mkdirSync(staging, { recursive: true, mode: 0o700 });
      chmodSync(staging, 0o700);
      if (residue === "empty staging") {
        const originalAuthority = currentMechanicalAuthority(
          fixture,
          "CAPTAIN",
        );
        const replacementAuthoritySha = hashObject({
          ...originalAuthority,
          attempt: originalAuthority.attempt + 1,
          capability_file: `${originalAuthority.capability_file}.replacement`,
          capability_sha256: `sha256:${"d".repeat(64)}`,
        });
        const beforeWrongAuthority =
          privateDirectoryFingerprint(staging);
        expect(() => inspectP1CommitPreparation(
          fixture.controlDir,
          GOAL,
          TASK,
          String(committed.event_id),
          hashObject(committed),
          replacementAuthoritySha,
        )).toThrow(expect.objectContaining({
          code: "PREPARED_REQUEST_MISMATCH",
        }));
        expect(privateDirectoryFingerprint(staging)).toEqual(
          beforeWrongAuthority,
        );
        expect(inspectP1CommitPreparation(
          fixture.controlDir,
          GOAL,
          TASK,
          String(committed.event_id),
          hashObject(committed),
          hashObject(originalAuthority),
        )).toMatchObject({
          acceptance_authority_sha256: hashObject(originalAuthority),
          stage: "EMPTY_STAGING",
        });
      }
      if (residue === "bundle temporary") {
        writePrivateFile(
          path.join(staging, ".commit.bundle.tmp"),
          "interrupted bundle bytes",
        );
      } else if (residue === "intent atomic temporary") {
        git(
          worktree,
          "bundle",
          "create",
          path.join(staging, "commit.bundle"),
          "HEAD",
          `^${fixture.goalInputHead}`,
        );
        chmodSync(path.join(staging, "commit.bundle"), 0o600);
        writePrivateFile(
          path.join(staging, atomicTemporary("intent.json")),
          "{\"partial\":",
        );
      } else if (residue === "wrong canonical unsealed bundle") {
        writePrivateFile(
          path.join(staging, "commit.bundle"),
          "not the requested commit bundle",
        );
      }

      const pending = parse<{
        tasks: Record<string, {
          pending_operations: Array<{
            kind: string;
            prepared_stage: string;
          }>;
        }>;
      }>(run(fixture, [
        "status",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--json",
      ]));
      expect(pending.tasks[TASK].pending_operations).toEqual([
        expect.objectContaining({
          kind: "P1_COMMIT_REF",
          prepared_stage: expectedStage,
        }),
      ]);

      expect(accept(fixture, committed, "CAPTAIN").code).toBe(0);
      expect(existsSync(staging)).toBe(false);
      expect(git(
        fixture.root,
        "rev-parse",
        "--verify",
        String(
          (committed.payload as Record<string, unknown>).p1_commit_ref,
        ),
      )).toBe(head);
    },
  );

  it("projects a missing completion receipt as an exact-retry-only pending operation", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterApproved(fixture);
    const worktree = p1Checkout(fixture);
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
    const head = git(worktree, "rev-parse", "HEAD");
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      head,
    );
    expect(accept(fixture, committed, "CAPTAIN").code).toBe(0);
    const receipt = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "p1-commit-receipts",
      TASK,
      `${String(committed.event_id)}.json`,
    );
    rmSync(receipt);

    const status = parse<{
      tasks: Record<string, {
        launch_scope: string;
        pending_operations: Array<{
          kind: string;
          operation_id: string;
          retry: { command: string; request: string };
        }>;
      }>;
    }>(run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]));
    expect(status.tasks[TASK]).toMatchObject({
      launch_scope: "OPERATION_PENDING",
      pending_operations: [{
        kind: "P1_COMMIT_REF",
        operation_id: committed.event_id,
        retry: {
          command: "event",
          request: "EXACT_WITH_ORIGINAL_EVENT_AND_CAPABILITY",
        },
      }],
    });

    const repairedResult = accept(
      fixture,
      committed,
      "CAPTAIN",
      { cwd: fixture.root },
    );
    expect(repairedResult.stderr).toBe("");
    const repaired = parse<{ idempotent: boolean }>(repairedResult);
    expect(repaired.idempotent).toBe(true);
    expect(existsSync(receipt)).toBe(true);

    rmSync(receipt);
    const receiptTemporary = path.join(
      path.dirname(receipt),
      atomicTemporary(path.basename(receipt)),
    );
    writePrivateFile(receiptTemporary, "{\"partial\":");
    const temporaryStatus = parse<{
      tasks: Record<string, {
        pending_operations: Array<{ prepared_stage: string }>;
      }>;
    }>(run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]));
    expect(temporaryStatus.tasks[TASK].pending_operations).toEqual([
      expect.objectContaining({ prepared_stage: "COMPLETION_TEMP" }),
    ]);
    const temporaryRepair = accept(
      fixture,
      committed,
      "CAPTAIN",
      { cwd: fixture.root },
    );
    expect(temporaryRepair.stderr).toBe("");
    expect(temporaryRepair.code).toBe(0);
    expect(existsSync(receiptTemporary)).toBe(false);
    expect(existsSync(receipt)).toBe(true);

    const exactReceiptBody = readFileSync(receipt);
    const wrongRequestReceipt = JSON.parse(
      exactReceiptBody.toString("utf8"),
    ) as Record<string, unknown>;
    wrongRequestReceipt.request_sha256 = `sha256:${"b".repeat(64)}`;
    delete wrongRequestReceipt.receipt_sha256;
    wrongRequestReceipt.receipt_sha256 = hashObject(wrongRequestReceipt);
    rmSync(receipt);
    writePrivateFile(
      receiptTemporary,
      `${JSON.stringify(wrongRequestReceipt, null, 2)}\n`,
    );
    const wrongRequestReceiptBody = readFileSync(receiptTemporary);
    const wrongRequestRepair = accept(
      fixture,
      committed,
      "CAPTAIN",
      { cwd: fixture.root },
    );
    expect(wrongRequestRepair.code).toBe(2);
    expect(wrongRequestRepair.stderr).toContain(
      "PREPARED_REQUEST_MISMATCH",
    );
    expect(existsSync(receipt)).toBe(false);
    expect(readFileSync(receiptTemporary)).toEqual(
      wrongRequestReceiptBody,
    );
    rmSync(receiptTemporary);
    writePrivateFile(receipt, exactReceiptBody);

    const tamperedReceipt = JSON.parse(readFileSync(
      receipt,
      "utf8",
    )) as Record<string, unknown>;
    tamperedReceipt.commit_sha = fixture.goalInputHead;
    delete tamperedReceipt.receipt_sha256;
    tamperedReceipt.receipt_sha256 = hashObject(tamperedReceipt);
    writeJson(receipt, tamperedReceipt);
    const rejectedRead = run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]);
    expect(rejectedRead.code).toBe(2);
    expect(rejectedRead.stderr).toContain("CORRUPT_STORE");
  });

  it.each([false, true])(
    "keeps accepted P1 transaction identity after retained intent deletion (receipt deleted=%s)",
    (deleteReceipt) => {
      const fixture = makeFixture();
      initializeAndRegister(fixture);
      enterApproved(fixture);
      const worktree = p1Checkout(fixture);
      git(worktree, "add", "docs/issues/4242");
      git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
      const committed = eventTemplate(
        fixture,
        "CAPTAIN",
        "P1_COMMITTED",
        git(worktree, "rev-parse", "HEAD"),
      );
      expect(accept(fixture, committed, "CAPTAIN").code).toBe(0);

      const accepted = JSON.parse(readFileSync(
        acceptedEventFile(fixture, String(committed.event_id)),
        "utf8",
      )) as {
        p1_commit_transaction?: {
          kind: string;
          event_id: string;
          request_sha256: string;
          intent_sha256: string;
        };
      };
      expect(accepted.p1_commit_transaction).toMatchObject({
        kind: "P1_COMMIT_REF_TRANSACTION",
        event_id: committed.event_id,
        request_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        intent_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      });

      rmSync(path.join(
        fixture.controlDir,
        "goals",
        GOAL,
        "p1-commit-intents",
        TASK,
        String(committed.event_id),
      ), { recursive: true });
      if (deleteReceipt) {
        rmSync(path.join(
          fixture.controlDir,
          "goals",
          GOAL,
          "p1-commit-receipts",
          TASK,
          `${String(committed.event_id)}.json`,
        ));
      }
      const rawCapabilityBytes = [
        fixture.capabilities.FOREMAN,
        fixture.capabilities.CAPTAIN,
      ].map((file) => readFileSync(file as string, "utf8").trim());
      const beforeRead = controlTreeFingerprint(fixture.controlDir);
      const status = run(fixture, [
        "status",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--json",
      ]);
      expect(status.code).toBe(2);
      expect(status.stdout).toBe("");
      expect(status.stderr).toBe(
        deleteReceipt
          ? "goalctl[CORRUPT_STORE]: accepted P1 transaction 缺 retained intent/bundle\n"
          : "goalctl[CORRUPT_STORE]: P1 commit receipt 缺 retained intent\n",
      );
      expect(String(committed.event_id)).toHaveLength(43);
      expect(status.stderr).not.toContain(String(committed.event_id));
      for (const secret of rawCapabilityBytes) {
        expect(status.stderr).not.toContain(secret);
      }
      expect(controlTreeFingerprint(fixture.controlDir)).toEqual(beforeRead);
    },
  );

  it("rejects foreign and orphan commit/abandon receipt inventory", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterApproved(fixture);
    const worktree = p1Checkout(fixture);
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      git(worktree, "rev-parse", "HEAD"),
    );
    expect(accept(fixture, committed, "CAPTAIN").code).toBe(0);

    for (const directoryName of [
      "p1-commit-receipts",
      "p1-commit-abandonment-receipts",
    ]) {
      const directory = path.join(
        fixture.controlDir,
        "goals",
        GOAL,
        directoryName,
        TASK,
      );
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      chmodSync(directory, 0o700);
      const foreign = path.join(directory, "foreign.txt");
      writePrivateFile(foreign, "foreign");
      const foreignRead = run(fixture, [
        "status",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--json",
      ]);
      expect(foreignRead.code).toBe(2);
      expect(foreignRead.stderr).toContain("CORRUPT_STORE");
      rmSync(foreign);

      const orphan = path.join(
        directory,
        atomicTemporary("orphan.json"),
      );
      writePrivateFile(orphan, "{\"partial\":");
      const orphanRead = run(fixture, [
        "status",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--json",
      ]);
      expect(orphanRead.code).toBe(2);
      expect(orphanRead.stderr).toContain("CORRUPT_STORE");
      rmSync(orphan);
    }
  });

  it("uses an exact P1 ABANDON_ONLY handoff and retains the prepared ref as an append-only audit root", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterApproved(fixture);
    const worktree = p1Checkout(fixture);
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
    const head = git(worktree, "rev-parse", "HEAD");
    const branch = git(worktree, "branch", "--show-current");
    const rescueBundle = path.join(
      fixture.root,
      ".git",
      "abandon-handoff-p1.bundle",
    );
    git(
      worktree,
      "bundle",
      "create",
      rescueBundle,
      "HEAD",
      `^${fixture.goalInputHead}`,
    );
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      head,
    );
    const interrupted = accept(fixture, committed, "CAPTAIN", {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY: "1",
      },
    });
    expect(interrupted.stderr).toContain(
      "TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY",
    );

    const commitRef = String(
      (committed.payload as Record<string, unknown>).p1_commit_ref,
    );
    removeP1WorktreeAndPrune(fixture, worktree, branch);
    const handoff = parse<{
      accepted: boolean;
      abandonment_required: boolean;
    }>(accept(fixture, committed, "CAPTAIN", { cwd: fixture.root }));
    expect(handoff).toMatchObject({
      accepted: false,
      abandonment_required: true,
    });
    git(fixture.root, "bundle", "unbundle", rescueBundle);
    const intentFile = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "p1-commit-intents",
      TASK,
      String(committed.event_id),
      "intent.json",
    );
    const intent = JSON.parse(readFileSync(intentFile, "utf8")) as {
      intent_sha256: string;
    };
    const abandonArgs = [
      "p1-abandon-commit",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--prepared-event-id",
      String(committed.event_id),
      "--event-id",
      "abandon-p1-commit-a1",
      "--expected-intent-sha256",
      intent.intent_sha256,
      "--expected-commit-ref",
      commitRef,
      "--expected-ref-head",
      head,
      "--thread",
      fixture.threads.FOREMAN,
      "--reason",
      "prepared P1 cannot be completed",
      "--incident-ref",
      "incident:p1-prepared-abandon",
      "--foreman-capability-file",
      fixture.capabilities.FOREMAN as string,
      "--json",
    ];
    const abandonRequestSha = hashObject({
      goal_id: GOAL,
      task_id: TASK,
      prepared_event_id: String(committed.event_id),
      abandon_event_id: "abandon-p1-commit-a1",
      expected_intent_sha256: intent.intent_sha256,
      expected_commit_ref: commitRef,
      expected_ref_head: head,
      p1_abandon_handoff_sha256: intent.intent_sha256,
      foreman_thread_id: fixture.threads.FOREMAN,
      reason: "prepared P1 cannot be completed",
      incident_ref: "incident:p1-prepared-abandon",
    });
    const emptyAbandonmentStaging = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "p1-commit-abandonments",
      TASK,
      `.init-abandon-${
        sha256(String(committed.event_id)).slice("sha256:".length)
      }-${abandonRequestSha.slice("sha256:".length)}-${
        currentMechanicalAuthoritySha(fixture, "FOREMAN")
          .slice("sha256:".length)
      }`,
    );
    mkdirSync(
      emptyAbandonmentStaging,
      { recursive: true, mode: 0o700 },
    );
    chmodSync(emptyAbandonmentStaging, 0o700);
    const originalForemanAuthority = currentMechanicalAuthority(
      fixture,
      "FOREMAN",
    );
    const replacementForemanAuthoritySha = hashObject({
      ...originalForemanAuthority,
      attempt: originalForemanAuthority.attempt + 1,
      capability_file:
        `${originalForemanAuthority.capability_file}.replacement`,
      capability_sha256: `sha256:${"e".repeat(64)}`,
    });
    const beforeWrongAuthority =
      privateDirectoryFingerprint(emptyAbandonmentStaging);
    expect(() => inspectExactUnsealedAbandonmentStaging(
      fixture.controlDir,
      GOAL,
      TASK,
      String(committed.event_id),
      abandonRequestSha,
      replacementForemanAuthoritySha,
    )).toThrow(expect.objectContaining({
      code: "PREPARED_REQUEST_MISMATCH",
    }));
    expect(privateDirectoryFingerprint(emptyAbandonmentStaging)).toEqual(
      beforeWrongAuthority,
    );
    expect(inspectExactUnsealedAbandonmentStaging(
      fixture.controlDir,
      GOAL,
      TASK,
      String(committed.event_id),
      abandonRequestSha,
      hashObject(originalForemanAuthority),
    )).toMatchObject({
      foreman_authority_sha256: hashObject(originalForemanAuthority),
      stage: "EMPTY_STAGING",
    });
    const emptyStagingBeforeStatus =
      privateDirectoryFingerprint(emptyAbandonmentStaging);
    const emptyStagingResult = parse<{
      tasks: Record<string, {
        pending_operations: Array<{
          kind: string;
          prepared_stage: string;
        }>;
      }>;
    }>(run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]));
    expect(emptyStagingResult.tasks[TASK].pending_operations).toEqual([
      expect.objectContaining({
        kind: "P1_COMMIT_REF_ABANDON",
        prepared_stage: "EMPTY_STAGING",
      }),
    ]);
    expect(privateDirectoryFingerprint(emptyAbandonmentStaging)).toEqual(
      emptyStagingBeforeStatus,
    );
    expect(existsSync(emptyAbandonmentStaging)).toBe(true);
    const abandonDirectoryFault = run(
      fixture,
      abandonArgs,
      {
        env: {
          GOAL_CONTROL_TEST_FAULT_AFTER_P1_ABANDON_STAGING_DIRECTORY: "1",
        },
      },
    );
    expect(abandonDirectoryFault.code).toBe(2);
    expect(abandonDirectoryFault.stderr).toContain(
      "TEST_FAULT_AFTER_P1_ABANDON_STAGING_DIRECTORY",
    );
    expect(existsSync(emptyAbandonmentStaging)).toBe(true);
    const abandonInterrupted = run(
      fixture,
      abandonArgs,
      {
        env: {
          GOAL_CONTROL_TEST_FAULT_AFTER_P1_ABANDON_INTENT_SEAL: "1",
        },
      },
    );
    expect(abandonInterrupted.code).toBe(2);
    expect(abandonInterrupted.stderr).toContain(
      "TEST_FAULT_AFTER_P1_ABANDON_INTENT_SEAL",
    );
    expect(existsSync(emptyAbandonmentStaging)).toBe(true);
    const abandoned = parse<{ abandoned: boolean }>(run(
      fixture,
      abandonArgs,
    ));
    expect(abandoned.abandoned).toBe(true);

    const abandonmentReceipt = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "p1-commit-abandonment-receipts",
      TASK,
      `${String(committed.event_id)}.json`,
    );
    expect(existsSync(abandonmentReceipt)).toBe(true);

    git(
      fixture.root,
      "update-ref",
      commitRef,
      head,
      "0000000000000000000000000000000000000000",
    );
    const restoredRefStatus = parse<{
      tasks: Record<string, {
        pending_operations: Array<{ prepared_stage: string }>;
      }>;
    }>(run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]));
    expect(restoredRefStatus.tasks[TASK].pending_operations).toEqual([]);
    expect(run(fixture, abandonArgs).code).toBe(0);
    expect(git(
      fixture.root,
      "rev-parse",
      "--verify",
      "--quiet",
      commitRef,
    )).toBe(head);

    const abandonmentCompletion = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "p1-commit-abandonments",
      TASK,
      String(committed.event_id),
      "completion.json",
    );
    const completionBody = readFileSync(abandonmentCompletion);
    const receiptBody = readFileSync(abandonmentReceipt);
    rmSync(abandonmentReceipt);
    rmSync(abandonmentCompletion);
    const completionTemporary = path.join(
      path.dirname(abandonmentCompletion),
      atomicTemporary("completion.json"),
    );
    writePrivateFile(completionTemporary, "{\"partial\":");
    const completionTempStatus = run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]);
    expect(completionTempStatus.code).toBe(2);
    expect(completionTempStatus.stderr).toContain("CORRUPT_STORE");
    const repairedCompletion = run(fixture, abandonArgs);
    expect(repairedCompletion.code).toBe(0);
    expect(existsSync(completionTemporary)).toBe(false);
    expect(readFileSync(abandonmentCompletion)).toEqual(completionBody);
    expect(readFileSync(abandonmentReceipt)).toEqual(receiptBody);

    const wrongRequestCompletion = JSON.parse(
      completionBody.toString("utf8"),
    ) as Record<string, unknown>;
    wrongRequestCompletion.request_sha256 = `sha256:${"c".repeat(64)}`;
    delete wrongRequestCompletion.completion_sha256;
    wrongRequestCompletion.completion_sha256 = hashObject(
      wrongRequestCompletion,
    );
    rmSync(abandonmentReceipt);
    rmSync(abandonmentCompletion);
    writePrivateFile(
      completionTemporary,
      `${JSON.stringify(wrongRequestCompletion, null, 2)}\n`,
    );
    const wrongRequestCompletionBody = readFileSync(completionTemporary);
    const rejectedCompletionRecovery = run(fixture, abandonArgs);
    expect(rejectedCompletionRecovery.code).toBe(2);
    expect(rejectedCompletionRecovery.stderr).toContain(
      "PREPARED_REQUEST_MISMATCH",
    );
    expect(existsSync(abandonmentCompletion)).toBe(false);
    expect(existsSync(abandonmentReceipt)).toBe(false);
    expect(readFileSync(completionTemporary)).toEqual(
      wrongRequestCompletionBody,
    );
    rmSync(completionTemporary);
    writePrivateFile(abandonmentCompletion, completionBody);
    writePrivateFile(abandonmentReceipt, receiptBody);

    rmSync(abandonmentReceipt);
    const abandonmentReceiptTemporary = path.join(
      path.dirname(abandonmentReceipt),
      atomicTemporary(path.basename(abandonmentReceipt)),
    );
    writePrivateFile(abandonmentReceiptTemporary, "");
    const interruptedStatus = run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]);
    expect(interruptedStatus.code).toBe(2);
    expect(interruptedStatus.stderr).toContain("CORRUPT_STORE");
    const repairedReceipt = run(fixture, abandonArgs);
    expect(repairedReceipt.code).toBe(0);
    expect(existsSync(abandonmentReceiptTemporary)).toBe(false);
    expect(readFileSync(abandonmentReceipt)).toEqual(receiptBody);

    const wrongRequestReceipt = JSON.parse(
      receiptBody.toString("utf8"),
    ) as Record<string, unknown>;
    wrongRequestReceipt.request_sha256 = `sha256:${"d".repeat(64)}`;
    delete wrongRequestReceipt.receipt_sha256;
    wrongRequestReceipt.receipt_sha256 = hashObject(wrongRequestReceipt);
    rmSync(abandonmentReceipt);
    writePrivateFile(
      abandonmentReceiptTemporary,
      `${JSON.stringify(wrongRequestReceipt, null, 2)}\n`,
    );
    const wrongRequestReceiptBody = readFileSync(
      abandonmentReceiptTemporary,
    );
    const rejectedReceiptRecovery = run(fixture, abandonArgs);
    expect(rejectedReceiptRecovery.code).toBe(2);
    expect(rejectedReceiptRecovery.stderr).toContain(
      "PREPARED_REQUEST_MISMATCH",
    );
    expect(existsSync(abandonmentReceipt)).toBe(false);
    expect(readFileSync(abandonmentReceiptTemporary)).toEqual(
      wrongRequestReceiptBody,
    );
    rmSync(abandonmentReceiptTemporary);
    writePrivateFile(abandonmentReceipt, receiptBody);

    const oldRetry = accept(fixture, committed, "CAPTAIN");
    expect(oldRetry.code).toBe(2);
    expect(oldRetry.stderr).toContain("P1_COMMIT_ABANDONED");
    const status = parse<{
      tasks: Record<string, {
        phase: string;
        p1: {
          commit_abandonment: {
            event_id: string;
            prepared_event_id: string;
          };
        };
        pending_operations: unknown[];
      }>;
    }>(run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]));
    expect(status.tasks[TASK]).toMatchObject({
      phase: "P1_APPROVED",
      p1: {
        commit_abandonment: {
          event_id: "abandon-p1-commit-a1",
          prepared_event_id: committed.event_id,
        },
      },
      pending_operations: [],
    });

    const storedAbandonment = JSON.parse(readFileSync(
      acceptedEventFile(fixture, "abandon-p1-commit-a1"),
      "utf8",
    )) as Record<string, unknown>;
    const rawAbandonment = Object.fromEntries(
      [
        "schema_version",
        "goal_id",
        "task_id",
        "type",
        "actor",
        "actor_sequence",
        "expected_state_revision",
        "control_epoch",
        "packet",
        "base_head",
        "full_head",
        "payload",
      ].map((key) => [key, storedAbandonment[key]]),
    );
    rawAbandonment.event_id = "raw-p1-abandonment-forbidden";
    const forbiddenRawAppend = accept(
      fixture,
      rawAbandonment,
      "FOREMAN",
      { cwd: fixture.root },
    );
    expect(forbiddenRawAppend.code).toBe(2);
    expect(forbiddenRawAppend.stderr).toContain(
      "P1_ABANDON_COMMAND_REQUIRED",
    );

    const abandonmentIntentFile = path.join(
      path.dirname(abandonmentCompletion),
      "intent.json",
    );
    const tamperedIntent = JSON.parse(readFileSync(
      abandonmentIntentFile,
      "utf8",
    )) as {
      request: Record<string, unknown> & { reason: string };
      request_sha256: string;
      prepared_request_sha256: string;
      task_anchor: unknown;
      foreman_authority: unknown;
      p1_intent_sha256: string;
      intent_sha256?: string;
    };
    tamperedIntent.request.reason =
      "self-consistent sideband rewrite outside the ledger";
    tamperedIntent.request_sha256 = hashObject(tamperedIntent.request);
    tamperedIntent.prepared_request_sha256 = hashObject({
      request: tamperedIntent.request,
      task_anchor: tamperedIntent.task_anchor,
      foreman_authority: tamperedIntent.foreman_authority,
      p1_intent_sha256: tamperedIntent.p1_intent_sha256,
    });
    delete tamperedIntent.intent_sha256;
    tamperedIntent.intent_sha256 = hashObject(tamperedIntent);
    writeJson(abandonmentIntentFile, tamperedIntent);

    const tamperedCompletion = JSON.parse(readFileSync(
      abandonmentCompletion,
      "utf8",
    )) as Record<string, unknown>;
    tamperedCompletion.reason = tamperedIntent.request.reason;
    tamperedCompletion.request_sha256 = tamperedIntent.request_sha256;
    tamperedCompletion.intent_sha256 = tamperedIntent.intent_sha256;
    delete tamperedCompletion.completion_sha256;
    tamperedCompletion.completion_sha256 = hashObject(tamperedCompletion);
    writeJson(abandonmentCompletion, tamperedCompletion);

    const tamperedReceipt = JSON.parse(readFileSync(
      abandonmentReceipt,
      "utf8",
    )) as Record<string, unknown>;
    tamperedReceipt.reason = tamperedIntent.request.reason;
    tamperedReceipt.request_sha256 = tamperedIntent.request_sha256;
    tamperedReceipt.intent_sha256 = tamperedIntent.intent_sha256;
    delete tamperedReceipt.receipt_sha256;
    tamperedReceipt.receipt_sha256 = hashObject(tamperedReceipt);
    writeJson(abandonmentReceipt, tamperedReceipt);
    const rejectedTamper = run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]);
    expect(rejectedTamper.code).toBe(2);
    expect(rejectedTamper.stderr).toContain("CORRUPT_STORE");
  });

  it("rejects P1_RESTARTED while the original CAPTAIN is not lost", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterMechanicalP1Phase(fixture, "P1_ACTIVE");
    const result = eventTemplateResult(
      fixture,
      "FOREMAN",
      "P1_RESTARTED",
      undefined,
      {
        payload: {
          reason: "no lost CAPTAIN",
          incident_ref: "incident:not-lost",
        },
      },
    );
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("EVENT_NOT_ALLOWED");
  });

  it.each(["QUEUED", "P1_ACTIVE"] as const)(
    "rejects mechanical PACKET_UPDATED before mutating %s state",
    (phase) => {
      const state = mechanicalControlState(phase);
      const before = JSON.parse(JSON.stringify(state));
      expect(() => applyEvent(
        state,
        foremanControlEvent(state, "PACKET_UPDATED", {
          revision: 2,
          sha256: `sha256:${"2".repeat(64)}`,
          path: "goal-inputs/TASK-P1-A-v2.md",
          change_kind: "AC",
        }),
        1,
      )).toThrow(expect.objectContaining({
        code: "P1_PACKET_UPDATE_UNSUPPORTED",
      }));
      expect(state).toEqual(before);
    },
  );

  it.each(["QUEUED", "P1_ACTIVE"] as const)(
    "reconciles mechanical %s back to a legal fresh START state",
    (phase) => {
      const state = mechanicalControlState(phase);
      state.reconcile_required = {
        control_event_id: "control-update-2",
        from_epoch: 1,
        to_epoch: 2,
      };
      const next = applyEvent(
        state,
        foremanControlEvent(
          state,
          "CONTROL_RECONCILED",
          {
            control_event_id: "control-update-2",
            instruction_ref: "docs/incidents/control-update-2.md",
          },
          2,
        ),
        2,
      ) as {
        phase: string;
        task_cycle: number;
        p1: Record<string, unknown>;
        sessions: Record<string, Record<string, unknown>>;
      };
      expect(next).toMatchObject({
        phase: "QUEUED",
        task_cycle: 2,
        p1: { policy: expect.any(Object) },
        sessions: {
          CAPTAIN: {
            status: "terminal",
            terminal_reason: "CONTROL_EPOCH_CHANGED",
          },
        },
      });
      expect(next.p1).not.toHaveProperty("worktree");
    },
  );

  it.each([
    [
      "empty staging directory",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY",
      "TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY",
    ],
    [
      "bundle temporary fsync",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_BUNDLE_TEMP",
      "TEST_FAULT_AFTER_P1_COMMIT_BUNDLE_TEMP",
    ],
  ] as const)(
    "exact-retries P1 after real pre-seal %s fault",
    (_stage, faultVariable, faultCode) => {
      const fixture = makeFixture();
      initializeAndRegister(fixture);
      enterApproved(fixture);
      const worktree = p1Checkout(fixture);
      git(worktree, "add", "docs/issues/4242");
      git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
      const committed = eventTemplate(
        fixture,
        "CAPTAIN",
        "P1_COMMITTED",
        git(worktree, "rev-parse", "HEAD"),
      );
      const interrupted = accept(
        fixture,
        committed,
        "CAPTAIN",
        { env: { [faultVariable]: "1" } },
      );
      expect(interrupted.code).toBe(2);
      expect(interrupted.stderr).toContain(faultCode);
      expect(accept(fixture, committed, "CAPTAIN").code).toBe(0);
    },
  );

  it.each([
    [
      "bundle",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_BUNDLE",
      "TEST_FAULT_AFTER_P1_COMMIT_BUNDLE",
    ],
    [
      "intent",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL",
      "TEST_FAULT_AFTER_P1_COMMIT_INTENT_INSTALL",
    ],
    [
      "ref",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_REF",
      "TEST_FAULT_AFTER_P1_COMMIT_REF",
    ],
    [
      "append",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_APPEND",
      "TEST_FAULT_AFTER_P1_COMMIT_APPEND",
    ],
  ] as const)(
    "exact-retries P1 after %s fault, worktree/branch removal, reflog expiry, and prune-now GC",
    (_stage, faultVariable, faultCode) => {
      const fixture = makeFixture();
      initializeAndRegister(fixture);
      enterApproved(fixture);
      const worktree = p1Checkout(fixture);
      const branch = git(worktree, "branch", "--show-current");
      git(worktree, "add", "docs/issues/4242");
      git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
      const head = git(worktree, "rev-parse", "HEAD");
      const committed = eventTemplate(
        fixture,
        "CAPTAIN",
        "P1_COMMITTED",
        head,
      );
      const commitRef = String(
        (committed.payload as Record<string, unknown>).p1_commit_ref,
      );
      const interrupted = accept(
        fixture,
        committed,
        "CAPTAIN",
        { env: { [faultVariable]: "1" } },
      );
      expect(interrupted.code).toBe(2);
      expect(interrupted.stderr).toContain(faultCode);

      removeLinkedWorktree(fixture, worktree);
      git(fixture.root, "branch", "-D", branch);
      git(fixture.root, "reflog", "expire", "--expire=now", "--all");
      git(fixture.root, "gc", "--prune=now");
      expect(git(fixture.root, "branch", "--list", branch)).toBe("");

      const pendingResult = run(fixture, [
        "status",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--json",
      ]);
      if (pendingResult.code === 0) {
        const pending = parse<{
          tasks: Record<string, {
            pending_operations: Array<{
              kind: string;
              request_sha256: string;
            }>;
          }>;
        }>(pendingResult);
        expect(pending.tasks[TASK].pending_operations).toEqual([
          expect.objectContaining({
            kind: "P1_COMMIT_REF",
            request_sha256: expect.stringMatching(
              /^sha256:[0-9a-f]{64}$/,
            ),
          }),
        ]);
      } else {
        expect(pendingResult.stderr).toContain(
          "STORE_REPAIR_REQUIRED",
        );
      }

      const repaired = parse<{ idempotent: boolean }>(accept(
        fixture,
        committed,
        "CAPTAIN",
        { cwd: fixture.root },
      ));
      expect(git(fixture.root, "rev-parse", "--verify", commitRef)).toBe(head);
      expect([true, false]).toContain(repaired.idempotent);
      const status = parse<{
        tasks: Record<string, {
          phase: string;
          pending_operations: unknown[];
          p1: {
            commit_sha: string;
            commit_ref: string;
            commit_branch: string;
          };
        }>;
      }>(run(fixture, [
        "status",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--json",
      ]));
      expect(status.tasks[TASK]).toMatchObject({
        phase: "P1_COMMITTED",
        pending_operations: [],
        p1: {
          commit_sha: head,
          commit_ref: commitRef,
          commit_branch: commitRef.slice("refs/heads/".length),
        },
      });
    },
  );

  it.each([
    [
      "EMPTY_STAGING",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY",
      "TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY",
      "ABANDON_ONLY",
    ],
    [
      "BUNDLE_TEMP",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_BUNDLE_TEMP",
      "TEST_FAULT_AFTER_P1_COMMIT_BUNDLE_TEMP",
      "RECOVER",
    ],
    [
      "INTENT_TEMP",
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_BUNDLE",
      "TEST_FAULT_AFTER_P1_COMMIT_BUNDLE",
      "RECOVER",
    ],
  ] as const)(
    "survives %s, worktree/branch deletion, reflog expiry, and prune-now GC",
    (stage, faultVariable, faultCode, expectedOutcome) => {
      const fixture = makeFixture();
      initializeAndRegister(fixture);
      enterApproved(fixture);
      const worktree = p1Checkout(fixture);
      const branch = git(worktree, "branch", "--show-current");
      git(worktree, "add", "docs/issues/4242");
      git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
      const head = git(worktree, "rev-parse", "HEAD");
      const committed = eventTemplate(
        fixture,
        "CAPTAIN",
        "P1_COMMITTED",
        head,
      );
      const interrupted = accept(
        fixture,
        committed,
        "CAPTAIN",
        { env: { [faultVariable]: "1" } },
      );
      expect(interrupted.code).toBe(2);
      expect(interrupted.stderr).toContain(faultCode);
      if (stage === "INTENT_TEMP") {
        writePrivateFile(
          path.join(p1CommitStaging(fixture, committed), atomicTemporary(
            "intent.json",
          )),
          "{\"partial\":",
        );
      }

      removeP1WorktreeAndPrune(fixture, worktree, branch);
      expect(() => git(fixture.root, "cat-file", "-e", `${head}^{commit}`))
        .toThrow();

      const retried = parse<{
        accepted: boolean;
        abandonment_required?: boolean;
      }>(accept(
        fixture,
        committed,
        "CAPTAIN",
        { cwd: fixture.root },
      ));
      const status = parse<{
        tasks: Record<string, {
          phase: string;
          pending_operations: Array<{
            prepared_stage: string;
            abandonment_required?: boolean;
            retry: { command: string };
          }>;
          p1: { commit_sha?: string; commit_ref?: string };
        }>;
      }>(run(fixture, [
        "status",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--json",
      ]));
      if (expectedOutcome === "ABANDON_ONLY") {
        expect(retried).toMatchObject({
          accepted: false,
          abandonment_required: true,
        });
        expect(status.tasks[TASK]).toMatchObject({
          phase: "P1_APPROVED",
          pending_operations: [
            {
              prepared_stage: "ABANDON_ONLY",
              abandonment_required: true,
              retry: { command: "p1-abandon-commit" },
            },
          ],
        });
        expect(() => git(fixture.root, "cat-file", "-e", `${head}^{commit}`))
          .toThrow();
      } else {
        expect(retried.accepted).toBe(true);
        expect(status.tasks[TASK]).toMatchObject({
          phase: "P1_COMMITTED",
          pending_operations: [],
          p1: { commit_sha: head },
        });
        expect(git(fixture.root, "cat-file", "-e", `${head}^{commit}`)).toBe(
          "",
        );
      }
    },
  );

  it.each([
    [".commit.bundle.tmp", "", 0, "BUNDLE_TEMP"],
    [
      atomicTemporary("intent.json"),
      "{\"partial\":",
      Buffer.byteLength("{\"partial\":"),
      "INTENT_TEMP",
    ],
  ] as const)(
    "preserves partial/empty %s residue while read-only and unauthorized callers stay zero-write",
    (residueName, residueBody, residueSize, expectedStage) => {
      const fixture = makeFixture();
      initializeAndRegister(fixture);
      enterApproved(fixture);
      const worktree = p1Checkout(fixture);
      const branch = git(worktree, "branch", "--show-current");
      git(worktree, "add", "docs/issues/4242");
      git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
      const head = git(worktree, "rev-parse", "HEAD");
      const committed = eventTemplate(
        fixture,
        "CAPTAIN",
        "P1_COMMITTED",
        head,
      );
      const interrupted = accept(fixture, committed, "CAPTAIN", {
        env: {
          GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY: "1",
        },
      });
      expect(interrupted.stderr).toContain(
        "TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY",
      );
      const staging = p1CommitStaging(fixture, committed);
      writePrivateFile(path.join(staging, residueName), residueBody);
      const noCapabilityEvent = path.join(
        fixture.controlDir,
        `no-cap-${String(committed.event_id)}.json`,
      );
      writeJson(noCapabilityEvent, committed);
      const before = privateDirectoryFingerprint(staging);

      const status = parse<{
        control_store_read: {
          complete: boolean;
          writer_crash_marker: boolean;
          transaction_kind: string;
        };
        tasks: Record<string, {
          pending_operations: Array<{ prepared_stage: string }>;
        }>;
      }>(run(fixture, [
        "status",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--json",
      ]));
      expect(status.control_store_read).toMatchObject({
        complete: false,
        writer_crash_marker: true,
        transaction_kind: "P1_COMMIT",
      });
      expect(status.tasks[TASK].pending_operations).toEqual([
        expect.objectContaining({ prepared_stage: expectedStage }),
      ]);
      run(fixture, ["doctor", "--goal", GOAL, "--json"]);
      const wrongCapability = accept(fixture, committed, "CAPTAIN", {
        capability: fixture.capabilities.FOREMAN,
      });
      expect(wrongCapability.code).toBe(2);
      expect(wrongCapability.stderr).toMatch(/CAPABILITY/);
      const noCapability = run(fixture, [
        "event",
        "--goal",
        GOAL,
        "--file",
        noCapabilityEvent,
        "--json",
      ]);
      expect(noCapability.code).not.toBe(0);
      expect(privateDirectoryFingerprint(staging)).toEqual(before);

      removeP1WorktreeAndPrune(fixture, worktree, branch);
      const converted = parse<{
        accepted: boolean;
        abandonment_required: boolean;
        intent_sha256: string;
      }>(accept(
        fixture,
        committed,
        "CAPTAIN",
        { cwd: fixture.root },
      ));
      expect(converted).toMatchObject({
        accepted: false,
        abandonment_required: true,
      });
      const intentDirectory = path.join(
        fixture.controlDir,
        "goals",
        GOAL,
        "p1-commit-intents",
        TASK,
        String(committed.event_id),
      );
      const intent = JSON.parse(readFileSync(
        path.join(intentDirectory, "intent.json"),
        "utf8",
      )) as {
        abort_only: boolean;
        abort_binding: {
          reason_code: string;
          residue_inventory: Array<{
            file: string;
            size: number;
            sha256: string;
          }>;
          residue_inventory_sha256: string;
        };
      };
      const marker = JSON.parse(readFileSync(
        path.join(intentDirectory, "carrier-unavailable.json"),
        "utf8",
      )) as {
        reason_code: string;
        residue_inventory: unknown;
        residue_inventory_sha256: string;
      };
      const expectedResidue = [{
        file: residueName,
        size: residueSize,
        sha256: sha256(residueBody),
      }];
      expect(intent).toMatchObject({
        abort_only: true,
        abort_binding: {
          reason_code: "PRE_SEAL_COMMIT_CARRIER_UNAVAILABLE",
          residue_inventory: expectedResidue,
          residue_inventory_sha256: hashObject(expectedResidue),
        },
      });
      expect(marker).toMatchObject({
        reason_code: "PRE_SEAL_COMMIT_CARRIER_UNAVAILABLE",
        residue_inventory: expectedResidue,
        residue_inventory_sha256: hashObject(expectedResidue),
      });
      expect(readFileSync(
        path.join(intentDirectory, residueName),
        "utf8",
      )).toBe(residueBody);
    },
  );

  it("keeps a fsynced unavailable-carrier marker one-way when the carrier reappears before abort intent seal", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterApproved(fixture);
    const worktree = p1Checkout(fixture);
    const branch = git(worktree, "branch", "--show-current");
    const originalCaptainCapability = fixture.capabilities.CAPTAIN as string;
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
    const head = git(worktree, "rev-parse", "HEAD");
    const rescueBundle = path.join(
      fixture.root,
      ".git",
      "late-pre-abort-intent-p1.bundle",
    );
    git(
      worktree,
      "bundle",
      "create",
      rescueBundle,
      "HEAD",
      `^${fixture.goalInputHead}`,
    );
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      head,
    );
    const commitRef = String(
      (committed.payload as Record<string, unknown>).p1_commit_ref,
    );
    const interrupted = accept(fixture, committed, "CAPTAIN", {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY: "1",
      },
    });
    expect(interrupted.stderr).toContain(
      "TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY",
    );
    const staging = p1CommitStaging(fixture, committed);
    removeP1WorktreeAndPrune(fixture, worktree, branch);
    const markerInterrupted = accept(
      fixture,
      committed,
      "CAPTAIN",
      {
        cwd: fixture.root,
        env: {
          GOAL_CONTROL_TEST_FAULT_AFTER_P1_ABORT_ONLY_MARKER: "1",
        },
      },
    );
    expect(markerInterrupted.code).toBe(2);
    expect(markerInterrupted.stderr).toContain(
      "TEST_FAULT_AFTER_P1_ABORT_ONLY_MARKER",
    );
    const unavailableCarrier = path.join(
      staging,
      "carrier-unavailable.json",
    );
    const unavailableCarrierBody = readFileSync(unavailableCarrier);
    expect(existsSync(path.join(staging, "intent.json"))).toBe(false);

    git(fixture.root, "bundle", "unbundle", rescueBundle);
    git(fixture.root, "update-ref", `refs/heads/${branch}`, head);
    const restoredWorktree = createP1Worktree(
      fixture,
      branch,
      { createBranch: false },
    );
    expect(git(restoredWorktree, "rev-parse", "HEAD")).toBe(head);

    const converted = parse<{
      accepted: boolean;
      abandonment_required: boolean;
    }>(accept(
      fixture,
      committed,
      "CAPTAIN",
      {
        cwd: restoredWorktree,
        capability: originalCaptainCapability,
      },
    ));
    expect(converted).toMatchObject({
      accepted: false,
      abandonment_required: true,
    });
    const intentDirectory = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
      "p1-commit-intents",
      TASK,
      String(committed.event_id),
    );
    const installedIntent = JSON.parse(readFileSync(
      path.join(intentDirectory, "intent.json"),
      "utf8",
    )) as { abort_only: boolean };
    expect(installedIntent.abort_only).toBe(true);
    expect(readFileSync(
      path.join(intentDirectory, "carrier-unavailable.json"),
    )).toEqual(unavailableCarrierBody);
    expect(() => git(
      fixture.root,
      "rev-parse",
      "--verify",
      commitRef,
    )).toThrow();
  });

  it("keeps ABANDON_ONLY one-way after a carrier reappears, then supports FOREMAN abandon and P1 restart", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterApproved(fixture);
    const worktree = p1Checkout(fixture);
    const branch = git(worktree, "branch", "--show-current");
    const originalCaptainCapability = fixture.capabilities.CAPTAIN as string;
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "docs(issue-4242): P1 plan + context");
    const head = git(worktree, "rev-parse", "HEAD");
    const rescueBundle = path.join(fixture.root, ".git", "late-p1.bundle");
    git(
      worktree,
      "bundle",
      "create",
      rescueBundle,
      "HEAD",
      `^${fixture.goalInputHead}`,
    );
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      head,
    );
    const commitRef = String(
      (committed.payload as Record<string, unknown>).p1_commit_ref,
    );
    const interrupted = accept(fixture, committed, "CAPTAIN", {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY: "1",
      },
    });
    expect(interrupted.stderr).toContain(
      "TEST_FAULT_AFTER_P1_COMMIT_STAGING_DIRECTORY",
    );
    removeP1WorktreeAndPrune(fixture, worktree, branch);
    const converted = parse<{
      accepted: boolean;
      abandonment_required: boolean;
      intent_sha256: string;
    }>(accept(
      fixture,
      committed,
      "CAPTAIN",
      { cwd: fixture.root },
    ));
    expect(converted).toMatchObject({
      accepted: false,
      abandonment_required: true,
    });

    git(fixture.root, "bundle", "unbundle", rescueBundle);
    git(fixture.root, "update-ref", `refs/heads/${branch}`, head);
    const restoredWorktree = createP1Worktree(
      fixture,
      branch,
      { createBranch: false },
    );
    expect(git(restoredWorktree, "rev-parse", "HEAD")).toBe(head);
    const stillAbandonOnly = parse<{
      accepted: boolean;
      idempotent: boolean;
      abandonment_required: boolean;
    }>(accept(
      fixture,
      committed,
      "CAPTAIN",
      {
        cwd: restoredWorktree,
        capability: originalCaptainCapability,
      },
    ));
    expect(stillAbandonOnly).toMatchObject({
      accepted: false,
      idempotent: true,
      abandonment_required: true,
    });
    expect(() => git(
      fixture.root,
      "rev-parse",
      "--verify",
      commitRef,
    )).toThrow();

    const abandonEventId = "abandon-pre-seal-carrier-a1";
    const abandoned = parse<{
      abandoned: boolean;
      prepared_event_id: string;
      abandon_event_id: string;
    }>(run(fixture, [
      "p1-abandon-commit",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--prepared-event-id",
      String(committed.event_id),
      "--event-id",
      abandonEventId,
      "--expected-intent-sha256",
      converted.intent_sha256,
      "--expected-commit-ref",
      commitRef,
      "--expected-ref-head",
      head,
      "--thread",
      fixture.threads.FOREMAN,
      "--reason",
      "pre-seal commit carrier was irrecoverable after prune-now GC",
      "--incident-ref",
      "incident:p1-pre-seal-carrier-unavailable",
      "--foreman-capability-file",
      fixture.capabilities.FOREMAN as string,
      "--json",
    ], { cwd: restoredWorktree }));
    expect(abandoned).toMatchObject({
      abandoned: true,
      prepared_event_id: committed.event_id,
      abandon_event_id: abandonEventId,
    });
    const oldEvent = accept(
      fixture,
      committed,
      "CAPTAIN",
      {
        cwd: restoredWorktree,
        capability: originalCaptainCapability,
      },
    );
    expect(oldEvent.code).toBe(2);
    expect(oldEvent.stderr).toContain("P1_COMMIT_ABANDONED");

    const lost = eventTemplate(
      fixture,
      "FOREMAN",
      "ROLE_LOST",
      undefined,
      {
        cwd: restoredWorktree,
        payload: {
          role: "CAPTAIN",
          reason: "old P1 worktree carrier was permanently abandoned",
        },
      },
    );
    expect(accept(
      fixture,
      lost,
      "FOREMAN",
      { cwd: restoredWorktree },
    ).code).toBe(0);
    removeLinkedWorktree(fixture, restoredWorktree);
    git(fixture.root, "branch", "-D", branch);
    const freshBranch = "codex/mechanical-p1-after-abandon";
    const freshWorktree = createP1Worktree(fixture, freshBranch);
    const successorThread = "captain-mechanical-p1-after-abandon-2";
    const registered = parse<{ actor_capability_file: string }>(run(
      fixture,
      [
        "register-role",
        "--goal",
        GOAL,
        "--task",
        TASK,
        "--role",
        "CAPTAIN",
        "--thread",
        successorThread,
        "--host",
        "local",
        "--attempt",
        "2",
        "--authorizer-capability-file",
        fixture.capabilities.FOREMAN as string,
        "--json",
      ],
      { cwd: freshWorktree },
    ));
    fixture.capabilities.CAPTAIN = registered.actor_capability_file;
    fixture.threads.CAPTAIN = successorThread;
    const recovered = eventTemplate(
      fixture,
      "FOREMAN",
      "ROLE_RECOVERED",
      undefined,
      {
        cwd: freshWorktree,
        payload: { successor_thread_id: successorThread },
      },
    );
    expect(accept(
      fixture,
      recovered,
      "FOREMAN",
      { cwd: freshWorktree },
    ).code).toBe(0);
    const restart = eventTemplate(
      fixture,
      "FOREMAN",
      "P1_RESTARTED",
      undefined,
      {
        cwd: freshWorktree,
        payload: {
          reason: "restart after audited pre-seal carrier abandonment",
          incident_ref: "incident:p1-pre-seal-carrier-restart",
        },
      },
    );
    expect(accept(
      fixture,
      restart,
      "FOREMAN",
      { cwd: freshWorktree },
    ).code).toBe(0);
    const restarted = parse<{
      tasks: Record<string, {
        phase: string;
        task_cycle: number;
        pending_operations: unknown[];
      }>;
    }>(run(fixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ], { cwd: freshWorktree }));
    expect(restarted.tasks[TASK]).toMatchObject({
      phase: "QUEUED",
      task_cycle: 2,
      pending_operations: [],
    });
  });

  it("keeps an exact published init retry bound to the sealed head after origin/main advances", () => {
    const fixture = makeFixture();
    const first = parse<{
      receipt_sha256: string;
      goal_input_head: string;
      initialized: boolean;
      idempotent: boolean;
    }>(run(fixture, [
      "init",
      "--manifest",
      fixture.manifest,
      "--json",
    ]));
    expect(first).toMatchObject({
      goal_input_head: fixture.goalInputHead,
      initialized: true,
      idempotent: false,
    });
    const advanced = advanceRemoteMain(fixture);
    expect(advanced).not.toBe(fixture.goalInputHead);

    const retry = parse<{
      receipt_sha256: string;
      goal_input_head: string;
      initialized: boolean;
      idempotent: boolean;
    }>(run(fixture, [
      "init",
      "--manifest",
      fixture.manifest,
      "--json",
    ]));
    expect(retry).toMatchObject({
      receipt_sha256: first.receipt_sha256,
      goal_input_head: fixture.goalInputHead,
      initialized: false,
      idempotent: true,
    });
  });

  it("promotes an exact sealed prepared init with its original head after origin/main advances", () => {
    const fixture = makeFixture();
    const faulted = run(fixture, [
      "init",
      "--manifest",
      fixture.manifest,
      "--json",
    ], {
      env: {
        GOAL_CONTROL_TEST_FAULT_AFTER_INIT_STAGING: "throw",
      },
    });
    expect(faulted.code).toBe(2);
    expect(faulted.stderr).toContain("TEST_FAULT_AFTER_INIT_STAGING");
    const goalsDirectory = path.join(fixture.controlDir, "goals");
    const stagingName = readdirSync(goalsDirectory).find(
      (name) => name.startsWith(".init-goal-"),
    );
    expect(stagingName).toBeDefined();
    const stagedReceipt = JSON.parse(readFileSync(path.join(
      goalsDirectory,
      stagingName as string,
      "init-receipt.json",
    ), "utf8")) as {
      receipt_sha256: string;
      goal_input_head: string;
    };
    expect(stagedReceipt.goal_input_head).toBe(fixture.goalInputHead);
    advanceRemoteMain(fixture);

    const retry = parse<{
      receipt_sha256: string;
      goal_input_head: string;
      initialized: boolean;
      idempotent: boolean;
    }>(run(fixture, [
      "init",
      "--manifest",
      fixture.manifest,
      "--json",
    ]));
    expect(retry).toMatchObject({
      receipt_sha256: stagedReceipt.receipt_sha256,
      goal_input_head: fixture.goalInputHead,
      initialized: false,
      idempotent: true,
    });
    expect(readdirSync(goalsDirectory).some(
      (name) => name.startsWith(".init-goal-"),
    )).toBe(false);
  });

  it("rejects mechanical START_P1 from the main root and from a linked base-branch checkout", () => {
    const mainRoot = makeFixture();
    initializeAndRegister(mainRoot, { createWorktree: false });
    const rootStart = eventTemplateResult(
      mainRoot,
      "CAPTAIN",
      "START_P1",
    );
    expect(rootStart.code).toBe(2);
    expect(rootStart.stderr).toContain("P1_LINKED_WORKTREE_REQUIRED");

    const linkedMain = makeFixture();
    initializeAndRegister(linkedMain, { createWorktree: false });
    git(linkedMain.root, "switch", "--detach", linkedMain.goalInputHead);
    createP1Worktree(
      linkedMain,
      "main",
      { createBranch: false },
    );
    const linkedMainStart = eventTemplateResult(
      linkedMain,
      "CAPTAIN",
      "START_P1",
    );
    expect(linkedMainStart.code).toBe(2);
    expect(linkedMainStart.stderr).toContain("P1_BASE_BRANCH_FORBIDDEN");
  });

  it("requires a clean required-head checkout at mechanical START_P1", () => {
    const dirty = makeFixture();
    initializeAndRegister(dirty);
    writeFileSync(path.join(p1Checkout(dirty), "untracked.txt"), "dirty\n");
    const dirtyStart = eventTemplateResult(dirty, "CAPTAIN", "START_P1");
    expect(dirtyStart.code).toBe(2);
    expect(dirtyStart.stderr).toContain("P1_START_WORKTREE_DIRTY");

    const advanced = makeFixture();
    initializeAndRegister(advanced);
    writeFileSync(path.join(p1Checkout(advanced), "extra.txt"), "advance\n");
    git(p1Checkout(advanced), "add", "extra.txt");
    git(p1Checkout(advanced), "commit", "-qm", "advance before P1 start");
    const advancedStart = eventTemplateResult(
      advanced,
      "CAPTAIN",
      "START_P1",
    );
    expect(advancedStart.code).toBe(2);
    expect(advancedStart.stderr).toContain("P1_START_HEAD_MISMATCH");
  });

  it("rejects an authority whose current bytes no longer match the committed declaration", () => {
    const fixture = makeFixture();
    writeFileSync(
      path.join(fixture.root, fixture.authorityPath),
      "# silently broadened delegation\n",
    );
    const result = run(fixture, [
      "init",
      "--manifest",
      fixture.manifest,
      "--json",
    ]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("P1_AUTHORITY_HASH_MISMATCH");
    expect(existsSync(path.join(
      fixture.controlDir,
      "goals",
      GOAL,
    ))).toBe(false);
  });

  it("reports P1 authority and durable ref drift through doctor", () => {
    const authorityFixture = makeFixture();
    initializeAndRegister(authorityFixture);
    writeFileSync(
      path.join(authorityFixture.root, authorityFixture.authorityPath),
      "# silently broadened delegation after init\n",
    );
    const authorityDoctor = run(authorityFixture, [
      "doctor",
      "--goal",
      GOAL,
      "--json",
    ]);
    expect(authorityDoctor.code).toBe(1);
    expect((JSON.parse(authorityDoctor.stdout) as {
      findings: Array<{ code: string }>;
    }).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "P1_AUTHORITY_DRIFT" }),
    ]));

    const refFixture = makeFixture();
    initializeAndRegister(refFixture);
    commitApprovedP1(refFixture);
    const status = parse<{
      tasks: Record<string, {
        p1: { commit_ref: string };
      }>;
    }>(run(refFixture, [
      "status",
      "--goal",
      GOAL,
      "--task",
      TASK,
      "--json",
    ]));
    git(refFixture.root, "update-ref", "-d", status.tasks[TASK].p1.commit_ref);
    const refDoctor = run(refFixture, [
      "doctor",
      "--goal",
      GOAL,
      "--json",
    ]);
    expect(refDoctor.code).toBe(1);
    expect((JSON.parse(refDoctor.stdout) as {
      findings: Array<{ code: string }>;
    }).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "P1_COMMIT_REF_MISSING" }),
    ]));
  });

  it("initializes only from a clean main checkout equal to origin/main", () => {
    const dirty = makeFixture();
    writeFileSync(path.join(dirty.root, "untracked.txt"), "dirty\n");
    const dirtyResult = run(dirty, [
      "init",
      "--manifest",
      dirty.manifest,
      "--json",
    ]);
    expect(dirtyResult.code).toBe(2);
    expect(dirtyResult.stderr).toContain("P1_INIT_WORKTREE_DIRTY");

    const branch = makeFixture();
    git(branch.root, "switch", "-qc", "feature-init");
    const branchResult = run(branch, [
      "init",
      "--manifest",
      branch.manifest,
      "--json",
    ]);
    expect(branchResult.code).toBe(2);
    expect(branchResult.stderr).toContain("P1_INIT_BRANCH_MISMATCH");

    const staleMain = makeFixture();
    git(
      staleMain.root,
      "update-ref",
      "refs/remotes/origin/main",
      staleMain.baseHead,
    );
    const staleResult = run(staleMain, [
      "init",
      "--manifest",
      staleMain.manifest,
      "--json",
    ]);
    expect(staleResult.code).toBe(2);
    expect(staleResult.stderr).toContain("P1_INIT_REMOTE_MAIN_MISMATCH");
  });

  it("rejects root siblings and mixed-mode manifests for mechanical P1 v1", () => {
    const fixture = makeFixture();
    const sourceSpec = JSON.parse(readFileSync(
      path.join(fixture.root, "goal-inputs", "spec.json"),
      "utf8",
    )) as {
      goal_id: string;
      tasks: Array<{
        dependencies: string[];
        p1?: Record<string, unknown>;
      }>;
    };
    const rootSiblingSpec = {
      ...sourceSpec,
      goal_id: "mechanical-p1-root-sibling",
      tasks: sourceSpec.tasks.map((task, index) => ({
        ...task,
        dependencies: index === 1 ? [] : task.dependencies,
      })),
    };
    writeJson(
      path.join(fixture.root, "goal-inputs", "root-sibling.json"),
      rootSiblingSpec,
    );
    const rootSibling = run(fixture, [
      "scaffold",
      "--spec",
      "goal-inputs/root-sibling.json",
      "--output-dir",
      "docs/planning/goals/mechanical-p1-root-sibling",
      "--json",
    ]);
    expect(rootSibling.code).toBe(2);
    expect(rootSibling.stderr).toContain("INVALID_MANIFEST");
    expect(rootSibling.stderr).toContain("直接依赖紧邻前项");

    const mixedSpec = {
      ...sourceSpec,
      goal_id: "mechanical-p1-mixed",
      tasks: sourceSpec.tasks.map((task, index) => (
        index === 1
          ? {
            ...task,
            p1: undefined,
          }
          : task
      )),
    };
    writeJson(
      path.join(fixture.root, "goal-inputs", "mixed.json"),
      mixedSpec,
    );
    const mixed = run(fixture, [
      "scaffold",
      "--spec",
      "goal-inputs/mixed.json",
      "--output-dir",
      "docs/planning/goals/mechanical-p1-mixed",
      "--json",
    ]);
    expect(mixed.code).toBe(2);
    expect(mixed.stderr).toContain("INVALID_MANIFEST");
    expect(mixed.stderr).toContain("禁止 mixed mode");
  });

  it("rejects READY when the CAPTAIN dirties anything outside plan/context/_ref", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    const start = eventTemplate(fixture, "CAPTAIN", "START_P1");
    expect(accept(fixture, start, "CAPTAIN").code).toBe(0);
    writeArtifacts(fixture);
    writeFileSync(
      path.join(p1Checkout(fixture), "README.md"),
      "# unauthorized CAPTAIN edit\n",
    );
    const ready = eventTemplateResult(fixture, "CAPTAIN", "P1_READY");
    expect(ready.code).toBe(2);
    expect(ready.stderr).toContain("P1_DIRTY_SCOPE_VIOLATION");
  });

  it("keeps READY on the linked worktree branch bound by START_P1", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    const start = eventTemplate(fixture, "CAPTAIN", "START_P1");
    expect(accept(fixture, start, "CAPTAIN").code).toBe(0);
    git(p1Checkout(fixture), "switch", "-qc", "codex/p1-other-branch");
    writeArtifacts(fixture);
    const ready = eventTemplateResult(fixture, "CAPTAIN", "P1_READY");
    expect(ready.code).toBe(2);
    expect(ready.stderr).toContain("P1_WORKTREE_BINDING_MISMATCH");
  });

  it("rejects an approval_ref that is not the canonical authority/packet/artifact binding", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterReady(fixture);
    const approval = eventTemplate(fixture, "FOREMAN", "P1_APPROVED");
    approval.payload = {
      ...(approval.payload as Record<string, unknown>),
      approval_ref: `sha256:${"0".repeat(64)}`,
    };
    const rejected = accept(fixture, approval, "FOREMAN");
    expect(rejected.code).toBe(2);
    expect(rejected.stderr).toContain("P1_APPROVAL_AUTHORITY_MISMATCH");
  });

  it("keeps the READY canonical worktree and branch binding through approval and commit", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterReady(fixture);
    const approval = eventTemplate(fixture, "FOREMAN", "P1_APPROVED");
    approval.payload = {
      ...(approval.payload as Record<string, unknown>),
      p1_branch: "other-branch",
    };
    const approvalRejected = accept(fixture, approval, "FOREMAN");
    expect(approvalRejected.code).toBe(2);
    expect(approvalRejected.stderr).toContain("P1_APPROVAL_MISMATCH");

    const validApproval = eventTemplate(fixture, "FOREMAN", "P1_APPROVED");
    expect(accept(fixture, validApproval, "FOREMAN").code).toBe(0);
    const worktree = p1Checkout(fixture);
    git(worktree, "switch", "-qc", "p1-wrong-branch");
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "commit from wrong branch");
    const head = git(worktree, "rev-parse", "HEAD");
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      head,
    );
    const commitRejected = accept(fixture, committed, "CAPTAIN");
    expect(commitRejected.code).toBe(2);
    expect(commitRejected.stderr).toContain("P1_WORKTREE_BINDING_MISMATCH");
  });

  it("rejects a single P1 commit that also changes an out-of-scope path", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterApproved(fixture);
    writeFileSync(
      path.join(p1Checkout(fixture), "README.md"),
      "# smuggled business edit\n",
    );
    const worktree = p1Checkout(fixture);
    git(worktree, "add", ".");
    git(worktree, "commit", "-qm", "smuggle unrelated change");
    const head = git(worktree, "rev-parse", "HEAD");
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      head,
    );
    const rejected = accept(fixture, committed, "CAPTAIN");
    expect(rejected.code).toBe(2);
    expect(rejected.stderr).toContain("P1_COMMIT_SCOPE_VIOLATION");
  });

  it("rejects allowed-path bytes that changed after READY approval", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    enterApproved(fixture);
    writeFileSync(
      path.join(p1Checkout(fixture), PLAN),
      "# Plan\n\nChanged after approval.\n",
    );
    const worktree = p1Checkout(fixture);
    git(worktree, "add", "docs/issues/4242");
    git(worktree, "commit", "-qm", "mutate approved P1");
    const head = git(worktree, "rev-parse", "HEAD");
    const committed = eventTemplate(
      fixture,
      "CAPTAIN",
      "P1_COMMITTED",
      head,
    );
    const rejected = accept(fixture, committed, "CAPTAIN");
    expect(rejected.code).toBe(2);
    expect(rejected.stderr).toContain("P1_ARTIFACT_MISMATCH");
  });

  it("keeps DEV_READY bound to frozen inputs, approved P1 inventory, and the declared write set", () => {
    const fixture = makeFixture();
    initializeAndRegister(fixture);
    const p1Commit = commitApprovedP1(fixture);
    const worktree = p1Checkout(fixture);
    const status = parse<{
      tasks: Record<string, Record<string, unknown>>;
    }>(run(fixture, ["status", "--goal", GOAL, "--json"]));
    const goalDirectory = path.join(
      fixture.controlDir,
      "goals",
      GOAL,
    );
    const controlManifest = JSON.parse(readFileSync(path.join(
      goalDirectory,
      "manifest.json",
    ), "utf8")) as {
      source_manifest: string;
      tasks: Array<{
        id: string;
        packet: { path: string };
      }>;
    };
    const metadata = JSON.parse(readFileSync(path.join(
      goalDirectory,
      "goal.json",
    ), "utf8")) as Record<string, unknown>;
    const loaded = {
      manifest: controlManifest,
      meta: metadata,
      snapshot: { tasks: status.tasks },
    };
    const candidateState = JSON.parse(JSON.stringify(
      status.tasks[TASK],
    )) as Record<string, unknown>;
    candidateState.phase = "DEV_ACTIVE";
    const sessions = candidateState.sessions as Record<
      string,
      Record<string, unknown>
    >;
    sessions.DEV = {
      role: "DEV",
      thread_id: "dev-mechanical-p1",
      host_id: "local",
      attempt: 1,
      registered_full_head: p1Commit,
    };
    const validateHead = (head: string): void => validateCandidateBoundary(
      worktree,
      loaded as unknown as Record<string, unknown>,
      candidateState,
      { type: "DEV_READY", full_head: head },
    );

    mkdirSync(path.join(worktree, "docs", "issues", "4242"), {
      recursive: true,
    });
    writeFileSync(
      path.join(worktree, "docs", "issues", "4242", "notes.md"),
      "# DEV notes remain outside the approved P1 inventory\n",
    );
    git(worktree, "add", "docs/issues/4242/notes.md");
    git(worktree, "commit", "-qm", "docs(issue-4242): add dev notes");
    expect(() => validateHead(git(worktree, "rev-parse", "HEAD"))).toThrow(
      expect.objectContaining({ code: "P1_WRITE_SET_VIOLATION" }),
    );

    const futureTask = controlManifest.tasks.find(
      (task) => task.id === "TASK-P1-B",
    );
    expect(futureTask).toBeDefined();
    const futurePacket = path.join(
      worktree,
      (futureTask as { packet: { path: string } }).packet.path,
    );
    const originalPacket = readFileSync(futurePacket);
    writeFileSync(futurePacket, "# tampered future packet\n");
    git(worktree, "add", futureTask?.packet.path as string);
    git(worktree, "commit", "-qm", "tamper future packet");
    expect(() => validateHead(git(worktree, "rev-parse", "HEAD"))).toThrow(
      expect.objectContaining({ code: "PACKET_DRIFT" }),
    );
    writeFileSync(futurePacket, originalPacket);
    git(worktree, "add", futureTask?.packet.path as string);
    git(worktree, "commit", "-qm", "restore future packet");

    const sourceManifest = path.join(
      worktree,
      controlManifest.source_manifest,
    );
    const originalSourceManifest = readFileSync(sourceManifest);
    const changedSourceManifest = JSON.parse(
      originalSourceManifest.toString("utf8"),
    ) as Record<string, unknown>;
    changedSourceManifest.title = "silently changed Goal";
    writeJson(sourceManifest, changedSourceManifest);
    git(worktree, "add", controlManifest.source_manifest);
    git(worktree, "commit", "-qm", "tamper source manifest");
    expect(() => validateHead(git(worktree, "rev-parse", "HEAD"))).toThrow(
      expect.objectContaining({ code: "SOURCE_MANIFEST_DRIFT" }),
    );
    writeFileSync(sourceManifest, originalSourceManifest);
    git(worktree, "add", controlManifest.source_manifest);
    git(worktree, "commit", "-qm", "restore source manifest");

    const sameBytesTarget = path.join(
      worktree,
      "goal-inputs",
      "future-packet-same-bytes.md",
    );
    writeFileSync(sameBytesTarget, originalPacket);
    rmSync(futurePacket);
    symlinkSync(sameBytesTarget, futurePacket);
    git(worktree, "add", "-A");
    git(worktree, "commit", "-qm", "replace future packet with symlink");
    expect(() => validateHead(git(worktree, "rev-parse", "HEAD"))).toThrow(
      expect.objectContaining({ code: "PACKET_DRIFT" }),
    );
    rmSync(futurePacket);
    writeFileSync(futurePacket, originalPacket);
    rmSync(sameBytesTarget);
    git(worktree, "add", "-A");
    git(worktree, "commit", "-qm", "restore ordinary future packet");

    writeFileSync(
      path.join(worktree, PLAN),
      "# Plan\n\nDEV silently changed the approved plan.\n",
    );
    git(worktree, "add", PLAN);
    git(worktree, "commit", "-qm", "tamper approved P1 inventory");
    expect(() => validateHead(git(worktree, "rev-parse", "HEAD"))).toThrow(
      expect.objectContaining({ code: "P1_ARTIFACT_DRIFT" }),
    );
  });

  it("derives dependency start from the highest dependency merge but gates on ARCHIVED", () => {
    const goalInputHead = "1".repeat(40);
    const firstMerge = "2".repeat(40);
    const secondMerge = "3".repeat(40);
    const task = {
      id: "TASK-C",
      p1: { dependency_gate: "ARCHIVED" },
      dependencies: ["TASK-A", "TASK-B"],
      integration_order: 3,
    };
    const loaded = {
      manifest: {
        tasks: [
          { id: "TASK-A", integration_order: 1 },
          { id: "TASK-B", integration_order: 2 },
          task,
        ],
      },
      meta: { goal_input_head: goalInputHead },
      snapshot: {
        tasks: {
          "TASK-A": {
            phase: "ARCHIVED",
            merge: { main_merge_sha: firstMerge },
          },
          "TASK-B": {
            phase: "MERGED_TO_MAIN",
            merge: { main_merge_sha: secondMerge },
          },
        },
      },
    };
    expect(
      mechanicalP1RequiredStartHead(
        loaded as unknown as Record<string, unknown>,
        task,
      ),
    ).toBe(secondMerge);
    expect(() => assertMechanicalP1DependenciesArchived(
      loaded as unknown as Record<string, unknown>,
      task,
    )).toThrow(expect.objectContaining({
      code: "P1_DEPENDENCY_NOT_ARCHIVED",
    }));
    loaded.snapshot.tasks["TASK-B"].phase = "ARCHIVED";
    expect(() => assertMechanicalP1DependenciesArchived(
      loaded as unknown as Record<string, unknown>,
      task,
    )).not.toThrow();
  });

  it("uses the immediately preceding archived merge for both serial P1 start and merge", () => {
    const goalInputHead = "1".repeat(40);
    const firstMerge = "2".repeat(40);
    const secondMerge = "3".repeat(40);
    const task = {
      id: "TASK-C",
      p1: { dependency_gate: "ARCHIVED" },
      dependencies: ["TASK-B"],
      integration_order: 3,
    };
    const loaded = {
      manifest: {
        base_head: "0".repeat(40),
        tasks: [
          { id: "TASK-A", integration_order: 1 },
          { id: "TASK-B", integration_order: 2 },
          task,
        ],
      },
      meta: { goal_input_head: goalInputHead },
      snapshot: {
        tasks: {
          "TASK-A": {
            phase: "ARCHIVED",
            merge: { main_merge_sha: firstMerge },
          },
          "TASK-B": {
            phase: "ARCHIVED",
            merge: { main_merge_sha: secondMerge },
          },
        },
      },
    };
    expect(mechanicalP1RequiredStartHead(
      loaded as unknown as Record<string, unknown>,
      task,
    )).toBe(secondMerge);
    expect(mergeExpectedMainHead(
      loaded as unknown as Record<string, unknown>,
      task,
    )).toBe(secondMerge);

    loaded.snapshot.tasks["TASK-B"].phase = "READY_FOR_MERGE";
    expect(() => mergeExpectedMainHead(
      loaded as unknown as Record<string, unknown>,
      task,
    )).toThrow(expect.objectContaining({
      code: "INTEGRATION_ORDER_BLOCKED",
    }));
  });
});
