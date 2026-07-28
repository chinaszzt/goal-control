import { execFileSync } from "child_process";
import { createHash, randomUUID } from "crypto";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const RESOURCECTL = path.join(ROOT, "scripts", "resourcectl.js");

type CliResult = { code: number; stdout: string; stderr: string };
type Executable = typeof GOALCTL | typeof RESOURCECTL;

type Fixture = {
  sandbox: string;
  root: string;
  controlDir: string;
  manifest: string;
  packetHash: string;
  planHash: string;
  contextHash: string;
  baseHead: string;
};

type Chain = {
  foremanCapabilityFile: string;
  captainCapabilityFile: string;
  devCapabilityFile: string;
};

function run(
  fixture: Fixture,
  executable: Executable,
  args: string[],
  now = "2026-07-22T00:00:00.000Z",
): CliResult {
  try {
    const stdout = execFileSync("node", [executable, ...args], {
      cwd: fixture.root,
      encoding: "utf8",
      stdio: "pipe",
      env: {
        ...process.env,
        GOAL_CONTROL_DIR: fixture.controlDir,
        GOAL_CONTROL_TEST_MODE: "1",
        GOAL_CONTROL_NOW: now,
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

function parse(result: CliResult): Record<string, unknown> {
  expect(result.stdout).not.toBe("");
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

function expectCorrupt(result: CliResult): void {
  expect(result.code).not.toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toContain("CORRUPT_STORE");
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" }).trim();
}

function hash(body: string): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
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

function objectHash(value: unknown): string {
  return hash(JSON.stringify(canonicalize(value)));
}

function makeFixture(): Fixture {
  const sandbox = mkdtempSync(path.join(tmpdir(), "goal-control-goal-integrity-"));
  const root = path.join(sandbox, "repo");
  const controlDir = path.join(sandbox, "control");
  mkdirSync(root, { recursive: true });
  mkdirSync(controlDir, { recursive: true });
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.email", "integrity@example.test");
  git(root, "config", "user.name", "Goal Integrity Test");
  writeFileSync(path.join(root, "README.md"), "# integrity fixture\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "base");
  const baseHead = git(root, "rev-parse", "HEAD");

  const packetBody = "# TASK-A r1\n";
  const packetPath = "docs/planning/goals/demo/packets/TASK-A-r1.md";
  const absolutePacket = path.join(root, packetPath);
  mkdirSync(path.dirname(absolutePacket), { recursive: true });
  writeFileSync(absolutePacket, packetBody);
  const packetHash = hash(packetBody);
  const issueDir = path.join(root, "docs", "issues", "4242");
  mkdirSync(issueDir, { recursive: true });
  const planBody = "# Integrity fixture plan\n";
  const contextBody = "# Integrity fixture context\n";
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
            dependencies: [],
            integration_order: 1,
            packet: { revision: 1, path: packetPath, sha256: packetHash },
            resource_requirements: [
              { kind: "PORT", id: "8123", access: "EXCLUSIVE" },
            ],
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
    packetHash,
    planHash: hash(planBody),
    contextHash: hash(contextBody),
    baseHead,
  };
}

function capabilityFile(result: CliResult, field: string): string {
  if (result.code !== 0) throw new Error(JSON.stringify(result));
  const value = parse(result)[field];
  expect(typeof value).toBe("string");
  return String(value);
}

function initializeChain(fixture: Fixture): Chain {
  const initialized = run(fixture, GOALCTL, ["init", "--manifest", fixture.manifest, "--json"]);
  const bootstrap = capabilityFile(initialized, "bootstrap_capability_file");
  const foreman = capabilityFile(
    run(fixture, GOALCTL, [
      "register-role",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "FOREMAN",
      "--thread",
      "foreman-integrity-1",
      "--host",
      "local",
      "--attempt",
      "1",
      "--bootstrap-capability-file",
      bootstrap,
      "--json",
    ]),
    "actor_capability_file"
  );
  const captain = capabilityFile(
    run(fixture, GOALCTL, [
      "register-role",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "CAPTAIN",
      "--thread",
      "captain-integrity-1",
      "--host",
      "local",
      "--attempt",
      "1",
      "--authorizer-capability-file",
      foreman,
      "--json",
    ]),
    "actor_capability_file"
  );
  return {
    foremanCapabilityFile: foreman,
    captainCapabilityFile: captain,
    devCapabilityFile: "",
  };
}

type TaskState = {
  state_revision: number;
  control_epoch: number;
  packet: { revision: number; sha256: string };
  base_head: string;
  full_head: string;
};

function taskState(fixture: Fixture): TaskState {
  const result = run(fixture, GOALCTL, [
    "status",
    "--goal",
    "demo",
    "--task",
    "TASK-A",
    "--json",
  ]);
  expect(result.code).toBe(0);
  return (JSON.parse(result.stdout) as { tasks: { "TASK-A": TaskState } }).tasks["TASK-A"];
}

function submitCaptainEvent(
  fixture: Fixture,
  captainCapabilityFile: string,
  type: "START_P1" | "P1_READY",
  sequence: number,
  payload: Record<string, unknown> = {}
): void {
  const state = taskState(fixture);
  const eventId = randomUUID();
  const event = {
    schema_version: 1,
    event_id: eventId,
    goal_id: "demo",
    task_id: "TASK-A",
    type,
    actor: { role: "CAPTAIN", thread_id: "captain-integrity-1", host_id: "local" },
    actor_sequence: sequence,
    expected_state_revision: state.state_revision,
    control_epoch: state.control_epoch,
    packet: { revision: state.packet.revision, sha256: state.packet.sha256 },
    base_head: state.base_head,
    full_head: state.full_head,
    payload,
  };
  const inputDir = path.join(fixture.controlDir, "inputs");
  mkdirSync(inputDir, { recursive: true });
  const file = path.join(inputDir, `${eventId}.json`);
  writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);
  const result = run(fixture, GOALCTL, [
    "event",
    "--goal",
    "demo",
    "--file",
    file,
    "--actor-capability-file",
    captainCapabilityFile,
    "--json",
  ]);
  expect(result.code).toBe(0);
}

function submitRoleEvent(
  fixture: Fixture,
  capabilityFile: string,
  role: "CAPTAIN" | "FOREMAN",
  threadId: string,
  type: "START_P1" | "P1_READY" | "P1_APPROVED" | "P1_COMMITTED",
  sequence: number,
  payload: Record<string, unknown>,
  fullHead?: string,
): string {
  const state = taskState(fixture);
  const eventId = `${type.toLowerCase()}-${randomUUID()}`;
  const event = {
    schema_version: 1,
    event_id: eventId,
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
  const file = path.join(inputDir, `${eventId}.json`);
  writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);
  const result = run(fixture, GOALCTL, [
    "event",
    "--goal",
    "demo",
    "--file",
    file,
    "--actor-capability-file",
    capabilityFile,
    "--json",
  ]);
  if (result.code !== 0) {
    throw new Error(`${type} failed: ${result.stderr || result.stdout}`);
  }
  return eventId;
}

function initializeResourceChain(fixture: Fixture): Chain {
  const chain = initializeChain(fixture);
  const p1 = {
    plan_path: "docs/issues/4242/plan.md",
    plan_sha256: fixture.planHash,
    context_path: "docs/issues/4242/context.md",
    context_sha256: fixture.contextHash,
  };
  submitRoleEvent(
    fixture,
    chain.captainCapabilityFile,
    "CAPTAIN",
    "captain-integrity-1",
    "START_P1",
    1,
    {},
  );
  submitRoleEvent(
    fixture,
    chain.captainCapabilityFile,
    "CAPTAIN",
    "captain-integrity-1",
    "P1_READY",
    2,
    p1,
  );
  const approvalEventId = submitRoleEvent(
    fixture,
    chain.foremanCapabilityFile,
    "FOREMAN",
    "foreman-integrity-1",
    "P1_APPROVED",
    1,
    { ...p1, approval_ref: "user://issue-4242/approved" },
  );
  submitRoleEvent(
    fixture,
    chain.captainCapabilityFile,
    "CAPTAIN",
    "captain-integrity-1",
    "P1_COMMITTED",
    3,
    { ...p1, approval_event_id: approvalEventId },
    git(fixture.root, "rev-parse", "HEAD"),
  );
  const dev = capabilityFile(
    run(fixture, GOALCTL, [
      "register-role",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      "dev-integrity-1",
      "--host",
      "local",
      "--attempt",
      "1",
      "--launch-id",
      "launch-dev-integrity-1",
      "--authorizer-capability-file",
      chain.captainCapabilityFile,
      "--json",
    ]),
    "actor_capability_file",
  );
  return { ...chain, devCapabilityFile: dev };
}

function goalEventFiles(fixture: Fixture): string[] {
  const dir = path.join(fixture.controlDir, "goals", "demo", "events", "TASK-A");
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => path.join(dir, name));
}

function resourceEventFiles(fixture: Fixture): string[] {
  const dir = path.join(fixture.controlDir, "resources", "events");
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => path.join(dir, name));
}

function advanceControl(fixture: Fixture, foremanCapabilityFile: string, expectedEpoch: number): CliResult {
  return run(fixture, GOALCTL, [
    "control", "--goal", "demo", "--expected-epoch", String(expectedEpoch),
    "--reason", `instruction-${expectedEpoch + 1}`,
    "--instruction-ref", `user://issue-4242/control-${expectedEpoch + 1}`,
    "--thread", "foreman-integrity-1",
    "--actor-capability-file", foremanCapabilityFile,
    "--event-id", `control-integrity-${expectedEpoch + 1}`,
    "--json",
  ]);
}

function controlEventFiles(fixture: Fixture): string[] {
  const dir = path.join(fixture.controlDir, "goals", "demo", "control-events");
  return readdirSync(dir).filter((name) => name.endsWith(".json")).sort().map((name) => path.join(dir, name));
}

function acquireResource(fixture: Fixture, devCapabilityFile: string): {
  lease_id: string;
  owner_capability_file: string;
} {
  const result = run(fixture, RESOURCECTL, [
    "acquire",
    "--goal",
    "demo",
    "--task",
    "TASK-A",
    "--role",
    "DEV",
    "--thread",
    "dev-integrity-1",
    "--host",
    "local",
    "--resource",
    "preview-port:8123",
    "--ttl-ms",
    "60000",
    "--event-id",
    `resource-acquire-${randomUUID()}`,
    "--actor-capability-file",
    devCapabilityFile,
    "--json",
  ]);
  if (result.code !== 0) {
    throw new Error(
      `resource acquire failed (${result.code}): ${result.stderr || result.stdout}`,
    );
  }
  expect(result.code).toBe(0);
  return parse(result) as { lease_id: string; owner_capability_file: string };
}

describe("accepted goal event integrity", () => {
  let fixture: Fixture;
  let chain: Chain;

  beforeEach(() => {
    fixture = makeFixture();
    chain = initializeChain(fixture);
  });

  afterEach(() => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  it("detects byte-valid tampering of an accepted event", () => {
    submitCaptainEvent(fixture, chain.captainCapabilityFile, "START_P1", 1);
    const files = goalEventFiles(fixture);
    const tail = files.at(-1) as string;
    const event = JSON.parse(readFileSync(tail, "utf8")) as Record<string, unknown>;
    event.accepted_at = "2099-01-01T00:00:00.000Z";
    writeFileSync(tail, `${JSON.stringify(event, null, 2)}\n`);

    expectCorrupt(run(fixture, GOALCTL, ["status", "--goal", "demo", "--json"]));
  });

  it("detects deletion of the accepted event-log tail instead of silently rolling state back", () => {
    submitCaptainEvent(fixture, chain.captainCapabilityFile, "START_P1", 1);
    submitCaptainEvent(fixture, chain.captainCapabilityFile, "P1_READY", 2, {
      plan_path: "docs/issues/4242/plan.md",
      plan_sha256: fixture.planHash,
      context_path: "docs/issues/4242/context.md",
      context_sha256: fixture.contextHash,
    });
    const files = goalEventFiles(fixture);
    rmSync(files.at(-1) as string);

    expectCorrupt(run(fixture, GOALCTL, ["status", "--goal", "demo", "--json"]));
  });
});

describe("resource event integrity", () => {
  let fixture: Fixture;
  let chain: Chain;

  beforeEach(() => {
    fixture = makeFixture();
    chain = initializeResourceChain(fixture);
  });

  afterEach(() => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  it("detects byte-valid tampering of an accepted resource event", () => {
    acquireResource(fixture, chain.devCapabilityFile);
    const file = resourceEventFiles(fixture)[0];
    const event = JSON.parse(readFileSync(file, "utf8")) as {
      lease: { expires_at: string };
    };
    event.lease.expires_at = "2099-01-01T00:00:00.000Z";
    writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);

    expectCorrupt(run(fixture, RESOURCECTL, ["list", "--json"]));
  });

  it("detects deletion of the resource event-log tail instead of resurrecting an old lease revision", () => {
    const lease = acquireResource(fixture, chain.devCapabilityFile);
    const status = run(
      fixture,
      GOALCTL,
      ["status", "--goal", "demo", "--task", "TASK-A", "--json"],
      "2026-07-22T00:00:45.000Z",
    );
    expect(status.code).toBe(0);
    const renewal = (
      JSON.parse(status.stdout) as {
        tasks: {
          "TASK-A": {
            maintenance_actions: Array<{
              type: string;
              event_id: string;
              ttl_ms: number;
              expected_revision: number;
            }>;
          };
        };
      }
    ).tasks["TASK-A"].maintenance_actions.find(
      (action) => action.type === "REQUEST_RESOURCE_RENEW",
    );
    if (!renewal) throw new Error("missing deterministic resource renewal action");
    const renewed = run(fixture, RESOURCECTL, [
      "renew",
      "--lease",
      lease.lease_id,
      "--owner-capability-file",
      lease.owner_capability_file,
      "--expected-revision",
      String(renewal.expected_revision),
      "--ttl-ms",
      String(renewal.ttl_ms),
      "--event-id",
      renewal.event_id,
      "--actor-capability-file",
      chain.devCapabilityFile,
      "--json",
    ], "2026-07-22T00:00:45.000Z");
    expect(renewed.code).toBe(0);
    const files = resourceEventFiles(fixture);
    rmSync(files.at(-1) as string);

    expectCorrupt(run(fixture, RESOURCECTL, ["list", "--json"]));
  });

  it("fails closed when the durable resource head anchor is missing", () => {
    acquireResource(fixture, chain.devCapabilityFile);
    rmSync(path.join(fixture.controlDir, "resources", "head.json"));

    expectCorrupt(run(fixture, RESOURCECTL, ["list", "--json"]));
  });

  it("rejects semantic corruption even when event and head hashes are recomputed", () => {
    acquireResource(fixture, chain.devCapabilityFile);
    const eventFile = resourceEventFiles(fixture)[0];
    const event = JSON.parse(readFileSync(eventFile, "utf8")) as Record<string, unknown> & {
      actor: { role: string };
      event_sha256: string;
    };
    event.actor.role = "FOREMAN";
    const { event_sha256: _oldEventHash, ...unsignedEvent } = event;
    event.event_sha256 = objectHash(unsignedEvent);
    writeFileSync(eventFile, `${JSON.stringify(event, null, 2)}\n`);

    const headFile = path.join(fixture.controlDir, "resources", "head.json");
    const head = JSON.parse(readFileSync(headFile, "utf8")) as Record<string, unknown> & {
      last_event_sha256: string;
      head_sha256: string;
    };
    head.last_event_sha256 = event.event_sha256;
    const { head_sha256: _oldHeadHash, ...unsignedHead } = head;
    head.head_sha256 = objectHash(unsignedHead);
    writeFileSync(headFile, `${JSON.stringify(head, null, 2)}\n`);

    expectCorrupt(run(fixture, RESOURCECTL, ["list", "--json"]));
  });

  it("quarantines legacy lease-set revocations until a host resource broker repairs them", () => {
    acquireResource(fixture, chain.devCapabilityFile);
    const acquiredFile = resourceEventFiles(fixture)[0];
    const acquired = JSON.parse(readFileSync(acquiredFile, "utf8")) as {
      event_sha256: string;
      lease: {
        lease_id: string;
        resource: string;
        revision: number;
        fencing_token: number;
        owner: {
          goal_id: string;
          task_id: string;
          role: string;
          thread_id: string;
          host_id: string;
        };
      };
    };
    const lostOwner = acquired.lease.owner;
    const actor = {
      goal_id: "demo",
      task_id: "TASK-A",
      role: "CAPTAIN",
      thread_id: "captain-integrity-1",
      host_id: "local",
    };
    const legacyUnsigned = {
      schema_version: 1,
      event_id: "legacy-revoke-without-host-fence",
      type: "LEASE_SET_REVOKED",
      accepted_at: "2026-07-22T00:00:01.000Z",
      actor,
      leases: [{
        lease_id: acquired.lease.lease_id,
        resource: acquired.lease.resource,
        revision: acquired.lease.revision,
        fencing_token: acquired.lease.fencing_token,
      }],
      lost_owner: lostOwner,
      successor: {
        goal_id: "demo",
        task_id: "TASK-A",
        role: "DEV",
        thread_id: "dev-integrity-2",
        host_id: "local",
      },
      predecessor_launch_id: "launch-dev-integrity-1",
      predecessor_launch_sha256: `sha256:${"a".repeat(64)}`,
      handoff_event_id: "recovery-handoff-integrity-1",
      authorized_by: {
        goal_id: "demo",
        task_id: "TASK-A",
        role: "FOREMAN",
        thread_id: "foreman-integrity-1",
        host_id: "local",
      },
      reason: "historical decoder accepted an identity-only revoke",
      log_sequence: 2,
      previous_event_sha256: acquired.event_sha256,
    };
    const legacy = {
      ...legacyUnsigned,
      event_sha256: objectHash(legacyUnsigned),
    };
    const eventsDir = path.dirname(acquiredFile);
    writeFileSync(
      path.join(eventsDir, "00000002-legacy-revoke-without-host-fence.json"),
      `${JSON.stringify(legacy, null, 2)}\n`
    );

    const headFile = path.join(fixture.controlDir, "resources", "head.json");
    const oldHead = JSON.parse(readFileSync(headFile, "utf8")) as {
      schema_version: number;
      fencing_tokens: Record<string, number>;
    };
    const unsignedHead = {
      schema_version: oldHead.schema_version,
      event_count: 2,
      last_event_sha256: legacy.event_sha256,
      fencing_tokens: oldHead.fencing_tokens,
      updated_at: legacy.accepted_at,
    };
    writeFileSync(
      headFile,
      `${JSON.stringify({
        ...unsignedHead,
        head_sha256: objectHash(unsignedHead),
      }, null, 2)}\n`
    );

    const listed = run(fixture, RESOURCECTL, ["list", "--json"]);
    if (listed.code !== 0) {
      throw new Error(
        `resource list failed (${listed.code}): ${listed.stderr || listed.stdout}`,
      );
    }
    expect(listed.code).toBe(0);
    expect(
      (
        parse(listed) as {
          leases: Array<{ lease_id: string; status: string }>;
        }
      ).leases
    ).toEqual([
      expect.objectContaining({
        lease_id: acquired.lease.lease_id,
        status: "UNVERIFIED_REVOKE",
      }),
    ]);

    const reacquire = run(fixture, RESOURCECTL, [
      "acquire",
      "--goal",
      "demo",
      "--task",
      "TASK-A",
      "--role",
      "DEV",
      "--thread",
      "dev-integrity-1",
      "--host",
      "local",
      "--resource",
      "preview-port:8123",
      "--ttl-ms",
      "60000",
      "--event-id",
      `resource-reacquire-${randomUUID()}`,
      "--actor-capability-file",
      chain.devCapabilityFile,
      "--json",
    ]);
    expect(reacquire.code).toBe(2);
    expect(reacquire.stderr).toContain("RESOURCE_BROKER_REPAIR_REQUIRED");

    const doctor = run(fixture, RESOURCECTL, ["doctor", "--json"]);
    expect(doctor.code).toBe(1);
    expect(parse(doctor)).toEqual(expect.objectContaining({
      healthy: false,
      findings: [
        expect.objectContaining({
          code: "RESOURCE_BROKER_REPAIR_REQUIRED",
          lease_id: acquired.lease.lease_id,
        }),
      ],
    }));
  });
});

describe("control epoch event integrity", () => {
  let fixture: Fixture;
  let chain: Chain;

  beforeEach(() => {
    fixture = makeFixture();
    chain = initializeChain(fixture);
  });

  afterEach(() => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  it("detects tampering of a Goal-level control instruction", () => {
    expect(advanceControl(fixture, chain.foremanCapabilityFile, 0).code).toBe(0);
    const file = controlEventFiles(fixture)[0];
    const event = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
    event.reason = "silently replaced instruction";
    writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`);

    expectCorrupt(run(fixture, GOALCTL, ["status", "--goal", "demo", "--json"]));
  });

  it("detects a deleted control-event tail through the sealed head", () => {
    expect(advanceControl(fixture, chain.foremanCapabilityFile, 0).code).toBe(0);
    expect(advanceControl(fixture, chain.foremanCapabilityFile, 1).code).toBe(0);
    rmSync(controlEventFiles(fixture).at(-1) as string);

    expectCorrupt(run(fixture, GOALCTL, ["status", "--goal", "demo", "--json"]));
  });
});
