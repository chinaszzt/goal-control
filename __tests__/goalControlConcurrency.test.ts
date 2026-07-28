import { execFileSync, spawn } from "child_process";
import { createHash, randomUUID } from "crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");

type Fixture = {
  root: string;
  controlDir: string;
  manifest: string;
  baseHead: string;
  packetHash: string;
  captainCapability?: string;
};

type ProcessResult = { code: number; stdout: string; stderr: string };
type TaskState = {
  state_revision: number;
  control_epoch: number;
  packet: { revision: number; sha256: string };
  base_head: string;
  full_head: string;
  phase: string;
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" }).trim();
}

function hash(body: string): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function makeFixture(): Fixture {
  const root = mkdtempSync(path.join(tmpdir(), "goal-control-goal-race-repo-"));
  const controlDir = mkdtempSync(path.join(tmpdir(), "goal-control-goal-race-state-"));
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.email", "race@example.test");
  git(root, "config", "user.name", "Goal CAS Race Test");
  writeFileSync(path.join(root, "README.md"), "# race fixture\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "base");
  const baseHead = git(root, "rev-parse", "HEAD");

  const packetBody = "# TASK-A r1\n";
  const packetPath = "docs/planning/goals/demo/packets/TASK-A-r1.md";
  const absolutePacket = path.join(root, packetPath);
  mkdirSync(path.dirname(absolutePacket), { recursive: true });
  writeFileSync(absolutePacket, packetBody);
  const packetHash = hash(packetBody);
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
  return { root, controlDir, manifest, baseHead, packetHash };
}

function syncCli(fixture: Fixture, args: string[]): ProcessResult {
  try {
    const stdout = execFileSync("node", [GOALCTL, ...args], {
      cwd: fixture.root,
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

function asyncCli(fixture: Fixture, args: string[]): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const child = spawn("node", [GOALCTL, ...args], {
      cwd: fixture.root,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, GOAL_CONTROL_DIR: fixture.controlDir, GOAL_CONTROL_TEST_MODE: "1" },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
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

function initialize(fixture: Fixture): void {
  const initialized = syncCli(fixture, ["init", "--manifest", fixture.manifest, "--json"]);
  expect(initialized.code).toBe(0);
  const bootstrap = JSON.parse(initialized.stdout).bootstrap_capability_file;
  const foreman = syncCli(fixture, [
    "register-role", "--goal", "demo", "--task", "TASK-A", "--role", "FOREMAN",
    "--thread", "foreman-race-1", "--host", "local", "--attempt", "1",
    "--bootstrap-capability-file", bootstrap, "--json",
  ]);
  expect(foreman.code).toBe(0);
  const captain = syncCli(fixture, [
      "register-role",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "CAPTAIN",
      "--thread",
      "captain-race-1",
      "--host",
      "local",
      "--attempt",
      "1",
      "--authorizer-capability-file",
      JSON.parse(foreman.stdout).actor_capability_file,
      "--json",
    ]);
  expect(captain.code).toBe(0);
  fixture.captainCapability = JSON.parse(captain.stdout).actor_capability_file;
}

function currentState(fixture: Fixture): TaskState {
  const result = syncCli(fixture, ["status", "--goal", "demo", "--task", "TASK-A", "--json"]);
  expect(result.code).toBe(0);
  return JSON.parse(result.stdout).tasks["TASK-A"];
}

function eventFile(
  fixture: Fixture,
  eventId: string,
  state: TaskState,
): string {
  const event = {
    schema_version: 1,
    event_id: eventId,
    goal_id: "demo",
    task_id: "TASK-A",
    type: "START_P1",
    actor: { role: "CAPTAIN", thread_id: "captain-race-1", host_id: "local" },
    actor_sequence: 1,
    expected_state_revision: state.state_revision,
    control_epoch: state.control_epoch,
    packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
    base_head: state.base_head,
    full_head: state.full_head,
    payload: {},
  };
  const inputDir = path.join(fixture.controlDir, "inputs");
  mkdirSync(inputDir, { recursive: true });
  const file = path.join(inputDir, `${eventId}.json`);
  writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);
  return file;
}

describe("goalctl event CAS concurrency", () => {
  let fixture: Fixture;

  beforeEach(() => {
    fixture = makeFixture();
    initialize(fixture);
  });

  afterEach(() => {
    rmSync(fixture.root, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
  });

  it("accepts exactly one of two processes submitting against the same state revision", async () => {
    const before = currentState(fixture);
    const firstFile = eventFile(fixture, randomUUID(), before);
    const secondFile = eventFile(fixture, randomUUID(), before);

    const results = await Promise.all([
      asyncCli(fixture, ["event", "--goal", "demo", "--file", firstFile, "--actor-capability-file", fixture.captainCapability as string, "--json"]),
      asyncCli(fixture, ["event", "--goal", "demo", "--file", secondFile, "--actor-capability-file", fixture.captainCapability as string, "--json"]),
    ]);

    expect(results.filter((result) => result.code === 0)).toHaveLength(1);
    const rejected = results.filter((result) => result.code !== 0);
    expect(rejected).toHaveLength(1);
    expect(`${rejected[0].stdout}\n${rejected[0].stderr}`).toContain("STALE_STATE_REVISION");

    const after = currentState(fixture);
    expect(after).toMatchObject({
      phase: "P1_ACTIVE",
      state_revision: before.state_revision + 1,
    });
  }, 45_000);
});
