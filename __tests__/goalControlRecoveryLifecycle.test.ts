import { execFileSync } from "child_process";
import { randomUUID } from "crypto";
import {
  appendFileSync,
  chmodSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { createRequire } from "module";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

const nodeRequire = createRequire(import.meta.url);
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const RESOURCECTL = path.join(ROOT, "scripts", "resourcectl.js");

type Role = "FOREMAN" | "CAPTAIN" | "DEV";

type Session = {
  role: Role;
  thread_id: string;
  host_id: string;
  attempt: number;
  status: string;
  lease_until: string;
  launch_id: string | null;
  task_nonce: string | null;
  registered_state_revision: number;
  registered_full_head: string;
  operational_scope?: "RECOVERY_BLOCKED" | "PREFLIGHT_ONLY" | "FULL";
  recovered_from?: {
    role: "DEV";
    thread_id: string;
    attempt: number;
    predecessor_launch_id: string;
    predecessor_registered_head: string;
    predecessor_launch_head: string;
  };
  recovery_handoff?: {
    event_id: string;
    import_commit: string;
  };
};

type TaskState = {
  task_id: string;
  phase: string;
  state_revision: number;
  control_epoch: number;
  base_head: string;
  full_head: string;
  packet: {
    revision: number;
    path: string;
    sha256: string;
  };
  holds: Array<{
    hold_id: string;
    kind: string;
    hard: boolean;
  }>;
  actor_sequences: Record<string, number>;
  sessions: Partial<Record<Role, Session>>;
};

type LoadedGoal = {
  control: { epoch: number };
  manifest: {
    goal_id: string;
    tasks: Array<{
      id: string;
      resource_requirements: Array<{
        kind: string;
        id: string;
        access: string;
      }>;
    }>;
  };
  paths: { dir: string };
  snapshot: {
    tasks: Record<string, TaskState>;
  };
};

type Registration = {
  actor_capability_file: string;
  task_nonce?: string;
  session: Session;
};

type Lease = {
  lease_id: string;
  resource: string;
  access: string;
  revision: number;
  fencing_token: number;
  status: string;
  owner_capability_file: string;
};

type Snapshot = {
  snapshot_id: string;
  snapshot_sha256: string;
  snapshot_file: string;
  predecessor_launch_id: string;
  predecessor_launch_sha256: string;
  source_worktree: string;
  source_branch: string;
  source_launch_head: string;
  source_observed_head: string;
  tracked_patch: { file: string };
};

type Receipt = {
  import_receipt_id: string;
  import_receipt_sha256: string;
  import_receipt_file: string;
  destination_worktree: string;
  destination_branch: string;
};

type PreflightEvidence = {
  evidence_id: string;
  status: string;
  launch_sha256: string;
};

type Fixture = {
  sandbox: string;
  repository: string;
  source: string;
  destination: string;
  controlDir: string;
  manifest: string;
  baseHead: string;
  fullHead: string;
  observedHead: string | null;
  bootstrapCapability: string | null;
  bootstrapCapabilityBytes: string | null;
  foremanCapability: string | null;
  captainCapability: string | null;
  d1Capability: string | null;
  d2Capability: string | null;
  d1Lease: Lease | null;
  withResource: boolean;
};

const {
  acceptEvent,
  actionsForTask,
  initializeGoal,
  loadGoalState,
  registerRole,
  resumeCapsule,
} = nodeRequire("../scripts/goal-control/goal.js") as {
  acceptEvent: (
    cwd: string,
    event: Record<string, unknown>,
    actorCapabilityFile: string
  ) => Record<string, unknown>;
  actionsForTask: (
    cwd: string,
    goalId: string,
    taskId: string,
    role: Role,
    threadId: string
  ) => Record<string, unknown>;
  initializeGoal: (
    cwd: string,
    manifestFile: string
  ) => {
    bootstrap_capability_file: string;
  };
  loadGoalState: (cwd: string, goalId: string) => LoadedGoal;
  registerRole: (
    cwd: string,
    options: Record<string, unknown>
  ) => Registration;
  resumeCapsule: (
    cwd: string,
    goalId: string,
    taskId: string,
    role: Role,
    threadId: string
  ) => Record<string, unknown>;
};

const {
  acquireLease,
  listLeases,
  reinitializeZeroRuntimeLeases,
  releaseLease,
} = nodeRequire("../scripts/goal-control/resources.js") as {
  acquireLease: (
    cwd: string,
    options: Record<string, unknown>
  ) => Lease;
  listLeases: (
    cwd: string,
    filters: Record<string, unknown>
  ) => { leases: Lease[] };
  reinitializeZeroRuntimeLeases: (
    cwd: string,
    options: Record<string, unknown>
  ) => Record<string, unknown>;
  releaseLease: (
    cwd: string,
    options: Record<string, unknown>
  ) => Lease;
};
const { actorSequenceKey } = nodeRequire(
  "../scripts/goal-control/fsm.js"
) as {
  actorSequenceKey: (actor: {
    role: string;
    host_id: string;
    thread_id: string;
  }) => string;
};

const {
  buildRecoveryHandoffPayload,
  exportRecoverySnapshot,
  importRecoverySnapshot,
} = nodeRequire("../scripts/goal-control/source-handoff.js") as {
  buildRecoveryHandoffPayload: (
    cwd: string,
    options: Record<string, unknown>
  ) => Record<string, string>;
  exportRecoverySnapshot: (
    cwd: string,
    options: Record<string, unknown>
  ) => Snapshot;
  importRecoverySnapshot: (
    cwd: string,
    options: Record<string, unknown>
  ) => Receipt;
};

const { createLaunchTemplate } = nodeRequire(
  "../scripts/goal-control/usability.js"
) as {
  createLaunchTemplate: (
    cwd: string,
    options: Record<string, unknown>
  ) => Record<string, unknown>;
};

const { runPreflight } = nodeRequire(
  "../scripts/goal-control/preflight.js"
) as {
  runPreflight: (
    cwd: string,
    options: Record<string, unknown>
  ) => PreflightEvidence;
};

const {
  recordEvidence,
  recordControllerEvidence,
} = nodeRequire("../scripts/goal-control/evidence.js") as {
  recordEvidence: (
    cwd: string,
    evidence: Record<string, unknown>,
    actorCapabilityFile: string
  ) => {
    evidence: { evidence_id: string };
  };
  recordControllerEvidence: (
    cwd: string,
    evidence: Record<string, unknown>,
    actorCapabilityFile: string
  ) => {
    evidence: { evidence_id: string };
  };
};

const {
  goalCommand,
  resourceCommand,
} = nodeRequire("../scripts/goal-control/cli.js") as {
  goalCommand: (
    argv: string[],
    cwd: string
  ) => { value: Record<string, unknown>; exitCode: number };
  resourceCommand: (
    argv: string[],
    cwd: string
  ) => { value: Record<string, unknown>; exitCode: number };
};

const {
  hashFile,
  hashObject,
} = nodeRequire("../scripts/goal-control/util.js") as {
  hashFile: (file: string) => string;
  hashObject: (value: unknown) => string;
};

const GOAL_ID = "goal-recovery-e2e";
const TASK_ID = "TASK-RECOVERY";
const RESOURCE = "preview-port:recovery-preview";
const PLAN_PATH = "docs/issues/4242/plan.md";
const CONTEXT_PATH = "docs/issues/4242/context.md";
const FOREMAN_THREAD = "foreman-recovery-e2e";
const CAPTAIN_THREAD = "captain-recovery-e2e";
const D1_THREAD = "dev-recovery-a1";
const D2_THREAD = "dev-recovery-a2";

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

function expectResourceCliSigkill(
  fixture: Fixture,
  cwd: string,
  args: string[],
): void {
  try {
    execFileSync(process.execPath, [RESOURCECTL, ...args], {
      cwd,
      encoding: "utf8",
      stdio: "pipe",
      env: {
        ...process.env,
        GOAL_CONTROL_DIR: fixture.controlDir,
        GOAL_CONTROL_TEST_MODE: "1",
        GOAL_CONTROL_TEST_FAULT_AFTER_ZERO_RUNTIME_GENERATION: "sigkill",
      },
    });
    throw new Error("expected resourcectl SIGKILL");
  } catch (error: unknown) {
    expect((error as { signal?: string }).signal).toBe("SIGKILL");
  }
}

function writeJson(file: string, value: unknown): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function expectControlCode(operation: () => unknown, code: string): void {
  try {
    operation();
    throw new Error(`expected ${code}`);
  } catch (error: unknown) {
    expect((error as { code?: string }).code).toBe(code);
  }
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

function installPendingBootstrapConsumption(fixture: Fixture): string {
  expect(fixture.bootstrapCapability).not.toBeNull();
  expect(fixture.bootstrapCapabilityBytes).not.toBeNull();
  const metadataFile = path.join(
    fixture.controlDir,
    "goals",
    GOAL_ID,
    "goal.json",
  );
  const metadata = JSON.parse(readFileSync(metadataFile, "utf8")) as Record<string, unknown>;
  delete metadata.bootstrap_consumed_at;
  delete metadata.meta_sha256;
  writeJson(metadataFile, {
    ...metadata,
    meta_sha256: hashObject(metadata),
  });
  writeFileSync(
    fixture.bootstrapCapability as string,
    fixture.bootstrapCapabilityBytes as string,
  );
  chmodSync(fixture.bootstrapCapability as string, 0o600);
  return fixture.bootstrapCapability as string;
}

function installDuplicateResourceEvent(
  fixture: Fixture,
  eventId: string,
): string {
  const eventsDirectory = path.join(
    fixture.controlDir,
    "resources",
    "events",
  );
  const files = readdirSync(eventsDirectory).sort();
  const tail = JSON.parse(readFileSync(
    path.join(eventsDirectory, files[files.length - 1]),
    "utf8",
  )) as Record<string, any>;
  const sequence = files.length + 1;
  const unsigned = {
    schema_version: 1,
    event_id: eventId,
    type: "LEASE_ACQUIRE_ABORTED",
    accepted_at: new Date().toISOString(),
    actor: tail.actor,
    log_sequence: sequence,
    previous_event_sha256: tail.event_sha256,
    request_sha256: hashObject({ duplicate: "different-request" }),
    lease_id: `lease-duplicate-${randomUUID()}`,
    resource: "preview-port:duplicate-probe",
    access: "EXCLUSIVE",
    fencing_token: 1,
    ttl_ms: 60_000,
    reason: "duplicate event id audit probe",
  };
  const file = path.join(
    eventsDirectory,
    `${String(sequence).padStart(8, "0")}-${eventId}.json`,
  );
  writeJson(file, {
    ...unsigned,
    event_sha256: hashObject(unsigned),
  });
  return file;
}

function makeFixture(options: { withResource?: boolean } = {}): Fixture {
  const withResource = options.withResource === true;
  const sandbox = mkdtempSync(path.join(tmpdir(), "goal-control-recovery-e2e-"));
  const repository = path.join(sandbox, "repository");
  const source = path.join(sandbox, "source");
  const destination = path.join(sandbox, "destination");
  const controlDir = path.join(sandbox, "control");
  mkdirSync(repository, { recursive: true });
  mkdirSync(controlDir, { recursive: true });

  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.email", "recovery-e2e@example.test");
  git(repository, "config", "user.name", "Recovery E2E Test");
  git(
    repository,
    "remote",
    "add",
    "origin",
    "https://github.com/example-org/example-repo.git"
  );
  writeFileSync(path.join(repository, "README.md"), "# recovery fixture\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "base");
  const baseHead = git(repository, "rev-parse", "HEAD");

  writeFileSync(
    path.join(repository, "pnpm-lock.yaml"),
    "lockfileVersion: '9.0'\n"
  );
  const packetPath = path.join(
    repository,
    "docs",
    "planning",
    "goals",
    "recovery-e2e",
    "packet.md"
  );
  mkdirSync(path.dirname(packetPath), { recursive: true });
  writeFileSync(packetPath, "# Recovery task packet\n");
  const protocolDir = path.join(repository, "docs", "protocol");
  mkdirSync(protocolDir, { recursive: true });
  const protocols = {
    entry: "entry.md",
    shared: "shared.md",
    foreman: "foreman.md",
    captain: "captain.md",
    role_kernel: "role-kernel.md",
  };
  for (const [name, file] of Object.entries(protocols)) {
    writeFileSync(path.join(protocolDir, file), `# ${name}\n`);
  }
  const issueDir = path.join(repository, "docs", "issues", "4242");
  mkdirSync(issueDir, { recursive: true });
  writeFileSync(path.join(repository, PLAN_PATH), "# Approved recovery plan\n");
  writeFileSync(path.join(repository, CONTEXT_PATH), "# Frozen recovery context\n");

  const manifest = path.join(
    repository,
    "docs",
    "planning",
    "goals",
    "recovery-e2e",
    "manifest.json"
  );
  writeJson(manifest, {
    schema_version: 1,
    goal_id: GOAL_ID,
    mode: "shadow",
    repository: {
      name_with_owner: "example-org/example-repo",
      base_branch: "main",
    },
    base_head: baseHead,
    protocol: Object.fromEntries(
      Object.entries(protocols).map(([name, file]) => [
        name,
        `docs/protocol/${file}`,
      ])
    ),
    tasks: [
      {
        id: TASK_ID,
        dependencies: [],
        integration_order: 1,
        packet: {
          revision: 1,
          path: path
            .relative(repository, packetPath)
            .split(path.sep)
            .join("/"),
          sha256: hashFile(packetPath),
        },
        resource_requirements: withResource
          ? [
              {
                kind: "PORT",
                id: "recovery-preview",
                access: "EXCLUSIVE",
              },
            ]
          : [],
      },
    ],
  });
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "seed frozen goal inputs");
  const fullHead = git(repository, "rev-parse", "HEAD");
  git(
    repository,
    "worktree",
    "add",
    "-q",
    "-b",
    "task/recovery-source",
    source,
    fullHead
  );
  return {
    sandbox,
    repository,
    source,
    destination,
    controlDir,
    manifest: path.join(
      source,
      path.relative(repository, manifest)
    ),
    baseHead,
    fullHead,
    observedHead: null,
    bootstrapCapability: null,
    bootstrapCapabilityBytes: null,
    foremanCapability: null,
    captainCapability: null,
    d1Capability: null,
    d2Capability: null,
    d1Lease: null,
    withResource,
  };
}

function taskState(fixture: Fixture, cwd = fixture.source): TaskState {
  return loadGoalState(cwd, GOAL_ID).snapshot.tasks[TASK_ID];
}

function capabilityFor(fixture: Fixture, role: Role, threadId: string): string {
  if (role === "FOREMAN") return fixture.foremanCapability as string;
  if (role === "CAPTAIN") return fixture.captainCapability as string;
  if (threadId === D1_THREAD) return fixture.d1Capability as string;
  return fixture.d2Capability as string;
}

function submit(
  fixture: Fixture,
  cwd: string,
  type: string,
  role: Role,
  threadId: string,
  payload: Record<string, unknown> = {},
  fullHead?: string
): {
  event: Record<string, unknown>;
  result: Record<string, unknown>;
} {
  const loaded = loadGoalState(cwd, GOAL_ID);
  const state = loaded.snapshot.tasks[TASK_ID];
  const session = state.sessions[role];
  if (!session) throw new Error(`missing ${role} session`);
  const targetRole = type === "ROLE_LOST"
    ? payload.role as Role | undefined
    : undefined;
  const hasExplicitRoleLostTarget = [
    "expected_thread_id",
    "expected_host_id",
    "expected_attempt",
    "expected_lease_until",
  ].some((field) => Object.prototype.hasOwnProperty.call(payload, field));
  const targetSession = targetRole
    ? state.sessions[targetRole]
    : undefined;
  const boundPayload = type === "ROLE_LOST"
    && targetSession
    && !hasExplicitRoleLostTarget
    ? {
      ...payload,
      expected_thread_id: targetSession.thread_id,
      expected_host_id: targetSession.host_id,
      expected_attempt: targetSession.attempt,
      expected_lease_until: targetSession.lease_until,
    }
    : payload;
  const actorKey = actorSequenceKey({
    role,
    host_id: session.host_id,
    thread_id: threadId,
  });
  const event = {
    schema_version: 1,
    event_id: `event-${type.toLowerCase()}-${randomUUID()}`,
    goal_id: GOAL_ID,
    task_id: TASK_ID,
    type,
    actor: {
      role,
      thread_id: threadId,
      host_id: session.host_id,
    },
    actor_sequence: (state.actor_sequences[actorKey] || 0) + 1,
    expected_state_revision: state.state_revision,
    control_epoch: loaded.control.epoch,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    base_head: state.base_head,
    full_head: fullHead || state.full_head,
    payload: boundPayload,
  };
  return {
    event,
    result: acceptEvent(
      cwd,
      event,
      capabilityFor(fixture, role, threadId)
    ),
  };
}

function registerInitialRoles(fixture: Fixture): void {
  const initialized = initializeGoal(
    fixture.source,
    path.relative(fixture.source, fixture.manifest)
  );
  fixture.bootstrapCapability = initialized.bootstrap_capability_file;
  fixture.bootstrapCapabilityBytes = readFileSync(
    fixture.bootstrapCapability,
    "utf8",
  );
  const foreman = registerRole(fixture.source, {
    goalId: GOAL_ID,
    taskId: TASK_ID,
    role: "FOREMAN",
    threadId: FOREMAN_THREAD,
    hostId: "host-control",
    attempt: 1,
    leaseMs: 3_600_000,
    status: "active",
    bootstrapCapabilityFile: fixture.bootstrapCapability,
  });
  fixture.foremanCapability = foreman.actor_capability_file;
  const captain = registerRole(fixture.source, {
    goalId: GOAL_ID,
    taskId: TASK_ID,
    role: "CAPTAIN",
    threadId: CAPTAIN_THREAD,
    hostId: "host-control",
    attempt: 1,
    leaseMs: 3_600_000,
    status: "active",
    authorizerCapabilityFile: fixture.foremanCapability,
  });
  fixture.captainCapability = captain.actor_capability_file;
}

function advanceP1(fixture: Fixture): void {
  const planSha = hashFile(path.join(fixture.source, PLAN_PATH));
  const contextSha = hashFile(path.join(fixture.source, CONTEXT_PATH));
  const artifacts = {
    plan_path: PLAN_PATH,
    plan_sha256: planSha,
    context_path: CONTEXT_PATH,
    context_sha256: contextSha,
  };
  submit(fixture, fixture.source, "START_P1", "CAPTAIN", CAPTAIN_THREAD);
  submit(
    fixture,
    fixture.source,
    "P1_READY",
    "CAPTAIN",
    CAPTAIN_THREAD,
    artifacts
  );
  const approval = submit(
    fixture,
    fixture.source,
    "P1_APPROVED",
    "FOREMAN",
    FOREMAN_THREAD,
    {
      ...artifacts,
      approval_ref: "user://recovery-e2e/approved",
    }
  );
  submit(
    fixture,
    fixture.source,
    "P1_COMMITTED",
    "CAPTAIN",
    CAPTAIN_THREAD,
    {
      ...artifacts,
      approval_event_id: String(approval.event.event_id),
    },
    fixture.fullHead
  );
}

function registerDev(
  fixture: Fixture,
  threadId: string,
  attempt: number,
  launchId: string
): Registration {
  return registerRole(fixture.source, {
    goalId: GOAL_ID,
    taskId: TASK_ID,
    role: "DEV",
    threadId,
    hostId: attempt === 1 ? "host-d1" : "host-d2",
    attempt,
    leaseMs: 3_600_000,
    status: "active",
    launchId,
    authorizerCapabilityFile: fixture.captainCapability,
  });
}

function createLaunch(
  fixture: Fixture,
  cwd: string,
  threadId: string,
  capability: string,
  leaseIds: string[],
  targetKind: "NONE" | "CLI"
): {
  launch: Record<string, unknown>;
  launchFile: string;
  preflight: PreflightEvidence;
} {
  const inputFile = path.join(
    fixture.controlDir,
    `launch-input-${threadId}-${randomUUID()}.json`
  );
  writeJson(inputFile, {
    execution: {
      environment: "none",
      write_mode: "NONE",
      target:
        targetKind === "NONE"
          ? { kind: "NONE" }
          : { kind: "CLI", executable_path: process.execPath },
    },
    resource_leases: leaseIds,
  });
  const launch = createLaunchTemplate(cwd, {
    goalId: GOAL_ID,
    taskId: TASK_ID,
    role: "DEV",
    threadId,
    actorCapabilityFile: capability,
    inputFile,
  });
  const launchFile = path.join(
    fixture.controlDir,
    `launch-${threadId}-${randomUUID()}.json`
  );
  writeJson(launchFile, launch);
  const preflight = runPreflight(cwd, {
    goalId: GOAL_ID,
    taskId: TASK_ID,
    launchFile,
    stage: "DEV",
    evidenceId: `preflight-recovery-${randomUUID()}`,
    actorCapabilityFile: capability,
  });
  expect(preflight.status).toBe("PASS");
  return { launch, launchFile, preflight };
}

function prepareRecovered(
  fixture: Fixture,
  options: {
    predecessorTarget?: "NONE" | "CLI";
    releaseOldLease?: boolean;
  } = {}
): void {
  registerInitialRoles(fixture);
  advanceP1(fixture);
  const d1 = registerDev(fixture, D1_THREAD, 1, "launch-dev-recovery-a1");
  fixture.d1Capability = d1.actor_capability_file;
  if (fixture.withResource) {
    fixture.d1Lease = acquireLease(fixture.source, {
      goalId: GOAL_ID,
      taskId: TASK_ID,
      eventId: "acquire-d1-recovery-source",
      role: "DEV",
      threadId: D1_THREAD,
      hostId: "host-d1",
      resource: RESOURCE,
      access: "EXCLUSIVE",
      ttlMilliseconds: 3_600_000,
      actorCapabilityFile: fixture.d1Capability,
    });
  }
  createLaunch(
    fixture,
    fixture.source,
    D1_THREAD,
    fixture.d1Capability,
    fixture.d1Lease ? [fixture.d1Lease.lease_id] : [],
    options.predecessorTarget || "NONE"
  );
  submit(
    fixture,
    fixture.source,
    "LAUNCH_DEV",
    "CAPTAIN",
    CAPTAIN_THREAD,
    { launch_id: "launch-dev-recovery-a1" }
  );

  writeFileSync(
    path.join(fixture.source, "README.md"),
    "# committed D1 recovery checkpoint\n"
  );
  git(fixture.source, "add", "README.md");
  git(fixture.source, "commit", "-qm", "D1 committed checkpoint");
  fixture.observedHead = git(fixture.source, "rev-parse", "HEAD");
  writeFileSync(
    path.join(fixture.source, "README.md"),
    "# dirty tracked D1 source\n"
  );
  writeFileSync(
    path.join(fixture.source, "untracked-recovery.txt"),
    "dirty untracked D1 source\n"
  );

  if (options.releaseOldLease && fixture.d1Lease) {
    releaseLease(fixture.source, {
      leaseId: fixture.d1Lease.lease_id,
      ownerCapabilityFile: fixture.d1Lease.owner_capability_file,
      actorCapabilityFile: fixture.d1Capability,
      expectedRevision: fixture.d1Lease.revision,
      eventId: `resource-release-recovery-${randomUUID()}`,
    });
  }

  submit(
    fixture,
    fixture.source,
    "ROLE_LOST",
    "CAPTAIN",
    CAPTAIN_THREAD,
    {
      role: "DEV",
      reason: "D1 session terminated during candidate work",
      fingerprint: "system-error:recovery-e2e-d1",
      attempts: 1,
    }
  );
  const d2 = registerDev(fixture, D2_THREAD, 2, "launch-dev-recovery-a2");
  fixture.d2Capability = d2.actor_capability_file;
  submit(
    fixture,
    fixture.source,
    "ROLE_RECOVERED",
    "CAPTAIN",
    CAPTAIN_THREAD,
    { successor_thread_id: D2_THREAD }
  );

  expect(taskState(fixture).sessions.DEV).toMatchObject({
    thread_id: D2_THREAD,
    operational_scope: "RECOVERY_BLOCKED",
  });
  git(
    fixture.repository,
    "worktree",
    "add",
    "-q",
    "-b",
    "task/recovery-destination",
    fixture.destination,
    fixture.observedHead as string
  );
}

function exportSnapshot(fixture: Fixture): Snapshot {
  return exportRecoverySnapshot(fixture.repository, {
    goalId: GOAL_ID,
    taskId: TASK_ID,
    snapshotId: "snapshot-recovery-lifecycle",
    successorThreadId: D2_THREAD,
    captainCapabilityFile: fixture.captainCapability,
    repositoryWorktree: realpathSync(fixture.source),
  });
}

function importSnapshot(fixture: Fixture, snapshot: Snapshot): Receipt {
  return importRecoverySnapshot(fixture.destination, {
    goalId: GOAL_ID,
    taskId: TASK_ID,
    importId: "import-recovery-lifecycle",
    snapshotId: snapshot.snapshot_id,
    successorThreadId: D2_THREAD,
    actorCapabilityFile: fixture.d2Capability,
  });
}

function commitImport(
  fixture: Fixture,
  snapshot: Snapshot,
  receipt: Receipt
): string {
  const checkpoint = goalCommand([
    "recovery-checkpoint-source",
    "--goal", GOAL_ID,
    "--task", TASK_ID,
    "--successor-thread", D2_THREAD,
    "--snapshot", snapshot.snapshot_id,
    "--import-receipt", receipt.import_receipt_id,
    "--actor-capability-file", fixture.d2Capability as string,
    "--json",
  ], fixture.destination);
  expect(checkpoint.exitCode).toBe(0);
  return String(
    (checkpoint.value as Record<string, unknown>).checkpoint_sha
  );
}

function bindHandoff(
  fixture: Fixture,
  snapshot: Snapshot,
  receipt: Receipt,
  importCommit: string
): string {
  const accepted = goalCommand([
    "recovery-bind",
    "--goal", GOAL_ID,
    "--task", TASK_ID,
    "--successor-thread", D2_THREAD,
    "--snapshot", snapshot.snapshot_id,
    "--import-receipt", receipt.import_receipt_id,
    "--import-commit", importCommit,
    "--captain-thread", CAPTAIN_THREAD,
    "--captain-capability-file", fixture.captainCapability as string,
    "--event-id", `handoff-${randomUUID()}`,
    "--json",
  ], fixture.destination);
  expect(accepted.exitCode).toBe(0);
  return String(accepted.value.event_id);
}

function writeBlockedFastEvidence(fixture: Fixture): Record<string, unknown> {
  const artifact = path.join(fixture.controlDir, "blocked-fast.json");
  writeJson(artifact, { status: "PASS", command: "test" });
  const state = taskState(fixture);
  return {
    schema_version: 1,
    evidence_id: `fast-blocked-${randomUUID()}`,
    goal_id: GOAL_ID,
    task_id: TASK_ID,
    kind: "FAST",
    status: "PASS",
    producer: {
      role: "DEV",
      thread_id: D2_THREAD,
      host_id: "host-d2",
    },
    state_revision: state.state_revision,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    packet_sha256: state.packet.sha256,
    base_head: state.base_head,
    full_head: fixture.observedHead,
    created_at: new Date().toISOString(),
    uri: pathToFileURL(artifact).href,
    source_sha256: hashFile(artifact),
    command: "pnpm test",
    attestation: { controller: "goalctl", adapter: "FAST" },
  };
}

function recordForemanHoldEvidence(
  fixture: Fixture,
  cwd: string,
  kind: "HOLD_ASSERTION" | "HOLD_RESOLUTION",
  status: "BLOCKED" | "PASS"
): string {
  const artifact = path.join(
    fixture.controlDir,
    `${kind.toLowerCase()}-${randomUUID()}.json`
  );
  writeJson(artifact, { kind, status });
  const state = taskState(fixture, cwd);
  const foreman = state.sessions.FOREMAN;
  if (!foreman) throw new Error("missing FOREMAN session");
  const registered = recordEvidence(
    cwd,
    {
      schema_version: 1,
      evidence_id: `${kind.toLowerCase()}-${randomUUID()}`,
      goal_id: GOAL_ID,
      task_id: TASK_ID,
      kind,
      status,
      producer: {
        role: "FOREMAN",
        thread_id: FOREMAN_THREAD,
        host_id: foreman.host_id,
      },
      state_revision: state.state_revision,
      packet: {
        revision: state.packet.revision,
        sha256: state.packet.sha256,
      },
      packet_sha256: state.packet.sha256,
      base_head: state.base_head,
      full_head: state.full_head,
      created_at: new Date().toISOString(),
      uri: pathToFileURL(artifact).href,
      source_sha256: hashFile(artifact),
    },
    fixture.foremanCapability as string
  );
  return registered.evidence.evidence_id;
}

function raiseRecoveryHardHold(fixture: Fixture, cwd: string): string {
  const holdId = `hold-${randomUUID()}`;
  submit(fixture, cwd, "ADD_HOLD", "FOREMAN", FOREMAN_THREAD, {
    hold_id: holdId,
    kind: "BLOCKED_SECURITY",
    reason: "recovery identity incident under investigation",
    evidence_id: recordForemanHoldEvidence(
      fixture,
      cwd,
      "HOLD_ASSERTION",
      "BLOCKED"
    ),
  });
  return holdId;
}

function resolveRecoveryHardHold(
  fixture: Fixture,
  cwd: string,
  holdId: string
): void {
  submit(fixture, cwd, "RESOLVE_HOLD", "FOREMAN", FOREMAN_THREAD, {
    hold_id: holdId,
    authority: "foreman-recovery-controller",
    resolution_evidence_id: recordForemanHoldEvidence(
      fixture,
      cwd,
      "HOLD_RESOLUTION",
      "PASS"
    ),
    disposition: "FIXED",
  });
}

function recordMechanicalEvidence(
  fixture: Fixture,
  kind: "FAST" | "FULL_CI" | "AC_AUDIT",
  producer: "DEV" | "CAPTAIN",
  fullHead: string
): string {
  const artifact = path.join(
    fixture.controlDir,
    `${kind.toLowerCase()}-${randomUUID()}.json`
  );
  writeJson(artifact, { kind, status: "PASS" });
  const state = taskState(fixture, fixture.destination);
  const threadId = producer === "DEV" ? D2_THREAD : CAPTAIN_THREAD;
  const hostId = producer === "DEV" ? "host-d2" : "host-control";
  const pullRequest = {
    repository: "example-org/example-repo",
    number: 999,
    url: "https://github.com/example-org/example-repo/pull/999",
    base: "main",
    head: fullHead,
  };
  const evidence: Record<string, unknown> = {
    schema_version: 1,
    evidence_id: `${kind.toLowerCase()}-${randomUUID()}`,
    goal_id: GOAL_ID,
    task_id: TASK_ID,
    kind,
    status: "PASS",
    producer: {
      role: producer,
      thread_id: threadId,
      host_id: hostId,
    },
    state_revision: state.state_revision,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    packet_sha256: state.packet.sha256,
    base_head: state.base_head,
    full_head: fullHead,
    created_at: new Date().toISOString(),
    uri: pathToFileURL(artifact).href,
    source_sha256: hashFile(artifact),
    command: `fixture:${kind}`,
    attestation: { controller: "goalctl", adapter: kind },
    ...(["FULL_CI", "AC_AUDIT"].includes(kind)
      ? { pull_request: pullRequest }
      : {}),
  };
  const registered = recordControllerEvidence(
    fixture.destination,
    evidence,
    producer === "DEV"
      ? (fixture.d2Capability as string)
      : (fixture.captainCapability as string)
  );
  return registered.evidence.evidence_id;
}

describe("recovered DEV isolated handoff lifecycle", () => {
  let fixture: Fixture;

  beforeEach(() => {
    fixture = makeFixture();
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
  });

  afterEach(() => {
    delete process.env.GOAL_CONTROL_TEST_MODE;
    delete process.env.GOAL_CONTROL_DIR;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_ZERO_RUNTIME_GENERATION;
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  it("allows FOREMAN to resolve a hard hold while recovered DEV is RECOVERY_BLOCKED", () => {
    prepareRecovered(fixture);
    expect(taskState(fixture).sessions.DEV).toMatchObject({
      operational_scope: "RECOVERY_BLOCKED",
    });

    const holdId = raiseRecoveryHardHold(fixture, fixture.source);
    expect(taskState(fixture).holds).toEqual([
      expect.objectContaining({ hold_id: holdId, hard: true }),
    ]);

    resolveRecoveryHardHold(fixture, fixture.source, holdId);
    expect(taskState(fixture)).toMatchObject({
      holds: [],
      sessions: {
        DEV: { operational_scope: "RECOVERY_BLOCKED" },
      },
    });
  });

  it("allows FOREMAN to resolve a hard hold while recovered DEV is PREFLIGHT_ONLY", () => {
    prepareRecovered(fixture);
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const importCommit = commitImport(fixture, snapshot, receipt);
    bindHandoff(fixture, snapshot, receipt, importCommit);
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      operational_scope: "PREFLIGHT_ONLY",
    });

    const holdId = raiseRecoveryHardHold(fixture, fixture.destination);
    expect(taskState(fixture, fixture.destination).holds).toEqual([
      expect.objectContaining({ hold_id: holdId, hard: true }),
    ]);

    resolveRecoveryHardHold(fixture, fixture.destination, holdId);
    expect(taskState(fixture, fixture.destination)).toMatchObject({
      holds: [],
      sessions: {
        DEV: { operational_scope: "PREFLIGHT_ONLY" },
      },
    });
  });

  it("moves dirty zero-resource D1 source into a distinct worktree, proves the built-in no-op, preflights D2, promotes FULL, and accepts DEV_READY", () => {
    prepareRecovered(fixture);

    const blockedResume = resumeCapsule(
      fixture.source,
      GOAL_ID,
      TASK_ID,
      "DEV",
      D2_THREAD
    );
    expect(blockedResume).toMatchObject({
      launch_scope: "RECOVERY_BLOCKED",
      resource_leases: [],
    });
    expect(String(blockedResume.forbidden)).toContain("源码修改/测试");
    expect(blockedResume.maintenance_actions).toEqual([
      expect.objectContaining({ type: "HEARTBEAT", actor_role: "DEV" }),
    ]);
    expect(
      (
        blockedResume.allowed_actions as Array<{ type: string }>
      ).map((action) => action.type)
    ).not.toContain("DEV_READY");
    expectControlCode(
      () =>
        recordControllerEvidence(
          fixture.source,
          writeBlockedFastEvidence(fixture),
          fixture.d2Capability as string
        ),
      "RECOVERY_SCOPE_VIOLATION"
    );
    expectControlCode(
      () =>
        acquireLease(fixture.source, {
          goalId: GOAL_ID,
          taskId: TASK_ID,
          eventId: "acquire-d2-recovery-blocked",
          role: "DEV",
          threadId: D2_THREAD,
          hostId: "host-d2",
          resource: RESOURCE,
          access: "EXCLUSIVE",
          ttlMilliseconds: 3_600_000,
          actorCapabilityFile: fixture.d2Capability,
        }),
      "RECOVERY_SCOPE_VIOLATION"
    );

    const snapshot = exportSnapshot(fixture);
    expect(snapshot.source_launch_head).toBe(fixture.fullHead);
    expect(snapshot.source_observed_head).toBe(fixture.observedHead);
    const receipt = importSnapshot(fixture, snapshot);
    expect(
      git(fixture.destination, "diff", "--cached", "--name-only")
        .split("\n")
        .sort()
    ).toEqual(["README.md", "untracked-recovery.txt"]);
    const importCommit = commitImport(fixture, snapshot, receipt);
    expect(git(fixture.destination, "rev-parse", `${importCommit}^`)).toBe(
      fixture.observedHead
    );
    expect(
      git(
        fixture.destination,
        "rev-list",
        "--parents",
        "-n",
        "1",
        importCommit
      ).split(" ")
    ).toHaveLength(2);
    const handoffEventId = bindHandoff(
      fixture,
      snapshot,
      receipt,
      importCommit
    );
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      operational_scope: "PREFLIGHT_ONLY",
      recovery_handoff: {
        event_id: handoffEventId,
        import_commit: importCommit,
      },
    });
    expect(goalCommand([
      "recovery-bind",
      "--goal", GOAL_ID,
      "--task", TASK_ID,
      "--successor-thread", D2_THREAD,
      "--snapshot", snapshot.snapshot_id,
      "--import-receipt", receipt.import_receipt_id,
      "--import-commit", importCommit,
      "--captain-thread", CAPTAIN_THREAD,
      "--captain-capability-file", fixture.captainCapability as string,
      "--event-id", handoffEventId,
      "--json",
    ], fixture.destination).value).toMatchObject({
      accepted: true,
      idempotent: true,
      event_id: handoffEventId,
      operational_scope: "PREFLIGHT_ONLY",
    });
    expectControlCode(
      () =>
        goalCommand([
          "recovery-bind",
          "--goal", GOAL_ID,
          "--task", TASK_ID,
          "--successor-thread", D2_THREAD,
          "--snapshot", snapshot.snapshot_id,
          "--import-receipt", receipt.import_receipt_id,
          "--import-commit", importCommit,
          "--captain-thread", CAPTAIN_THREAD,
          "--captain-capability-file", path.join(fixture.sandbox, "bogus-captain.cap"),
          "--event-id", handoffEventId,
          "--json",
        ], fixture.destination),
      "CAPABILITY_INVALID"
    );

    const trackedPatchFile = path.join(
      path.dirname(snapshot.snapshot_file),
      snapshot.tracked_patch.file
    );
    const trackedPatchBytes = readFileSync(trackedPatchFile);
    unlinkSync(trackedPatchFile);
    expectControlCode(
      () => taskState(fixture, fixture.destination),
      "HANDOFF_ARTIFACT_MISSING"
    );
    writeFileSync(trackedPatchFile, trackedPatchBytes);
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      operational_scope: "PREFLIGHT_ONLY",
    });

    const receiptBytes = readFileSync(receipt.import_receipt_file);
    const tamperedReceipt = JSON.parse(receiptBytes.toString("utf8")) as Record<
      string,
      unknown
    >;
    tamperedReceipt.destination_branch = "tampered-replay-branch";
    writeJson(receipt.import_receipt_file, tamperedReceipt);
    expectControlCode(
      () => taskState(fixture, fixture.destination),
      "HANDOFF_RECEIPT_TAMPERED"
    );
    writeFileSync(receipt.import_receipt_file, receiptBytes);
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      operational_scope: "PREFLIGHT_ONLY",
    });

    const reinitializeEventId = `reinitialize-${randomUUID()}`;
    const reinitializeArgs = [
      "reinitialize-zero-runtime",
      "--goal", GOAL_ID,
      "--task", TASK_ID,
      "--successor-thread", D2_THREAD,
      "--handoff-event-id", handoffEventId,
      "--captain-capability-file", fixture.captainCapability as string,
      "--captain-thread", CAPTAIN_THREAD,
      "--foreman-capability-file", fixture.foremanCapability as string,
      "--foreman-thread", FOREMAN_THREAD,
      "--event-id", reinitializeEventId,
      "--json",
    ];
    expectResourceCliSigkill(
      fixture,
      fixture.destination,
      reinitializeArgs,
    );
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const pristineOdd = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as {
      generation: number;
      active_transaction: { kind: string };
      pre_write_vector_sha256: string;
      updated_at: string;
    };
    expect(pristineOdd.generation % 2).toBe(1);
    expect(pristineOdd.active_transaction.kind).toBe("ZERO_RUNTIME");

    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_COMMIT =
      "ZERO_RUNTIME_REINITIALIZED";
    expectControlCode(
      () => resourceCommand(reinitializeArgs, fixture.destination),
      "TEST_FAULT_AFTER_RESOURCE_COMMIT",
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RESOURCE_COMMIT;
    const committedOdd = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )) as {
      generation: number;
      active_transaction: { kind: string };
      pre_write_vector_sha256: string;
      updated_at: string;
    };
    expect(committedOdd.generation % 2).toBe(1);
    expect(committedOdd.generation).toBe(pristineOdd.generation);
    expect(committedOdd.active_transaction)
      .toEqual(pristineOdd.active_transaction);
    expect(committedOdd.pre_write_vector_sha256)
      .toBe(pristineOdd.pre_write_vector_sha256);
    expect(committedOdd.updated_at).toBe(pristineOdd.updated_at);
    const pendingBootstrap = installPendingBootstrapConsumption(fixture);
    const wrongCapabilityArgs = [...reinitializeArgs];
    wrongCapabilityArgs[
      wrongCapabilityArgs.indexOf("--captain-capability-file") + 1
    ] = fixture.foremanCapability as string;
    const oddWrongCapabilityTree = exactControlTree(fixture.controlDir);
    expectControlCode(
      () => resourceCommand(wrongCapabilityArgs, fixture.destination),
      "CAPABILITY_INVALID",
    );
    expect(exactControlTree(fixture.controlDir))
      .toEqual(oddWrongCapabilityTree);
    expect(readFileSync(pendingBootstrap, "utf8"))
      .toBe(fixture.bootstrapCapabilityBytes);

    const duplicateResourceEvent = installDuplicateResourceEvent(
      fixture,
      reinitializeEventId,
    );
    const oddDuplicateTree = exactControlTree(fixture.controlDir);
    expectControlCode(
      () => resourceCommand(reinitializeArgs, fixture.destination),
      "CORRUPT_STORE",
    );
    expect(exactControlTree(fixture.controlDir)).toEqual(oddDuplicateTree);
    expect(
      JSON.parse(readFileSync(
        path.join(fixture.controlDir, ".generation.json"),
        "utf8",
      )).generation % 2,
    ).toBe(1);
    unlinkSync(duplicateResourceEvent);

    const reinitialized = resourceCommand(
      reinitializeArgs,
      fixture.destination,
    );
    expect(reinitialized.value).toMatchObject({
      reinitialized: true,
      idempotent: true,
      no_op: true,
      event_id: reinitializeEventId,
      event_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      leases: [],
    });
    expect(resourceCommand(
      reinitializeArgs,
      fixture.destination,
    ).value).toMatchObject({
      reinitialized: true,
      idempotent: true,
      no_op: true,
      event_id: reinitializeEventId,
    });
    const resourceEvents = readdirSync(path.join(
      fixture.controlDir,
      "resources",
      "events",
    )).map((name) => JSON.parse(readFileSync(path.join(
      fixture.controlDir,
      "resources",
      "events",
      name,
    ), "utf8")) as { type: string; event_id: string });
    expect(resourceEvents.filter(
      (event) => event.event_id === reinitializeEventId,
    )).toHaveLength(1);
    expect(resourceEvents.map((event) => event.type)).toContain(
      "ZERO_RUNTIME_REINITIALIZED",
    );
    expect(resourceEvents.map((event) => event.type)).not.toContain(
      "LEASE_SET_REVOKED",
    );
    expect(listLeases(fixture.destination, {
      goalId: GOAL_ID,
      taskId: TASK_ID,
    }).leases).toEqual([]);
    const d2Launch = createLaunch(
      fixture,
      fixture.destination,
      D2_THREAD,
      fixture.d2Capability as string,
      [],
      "NONE"
    );
    const promotionEventId = `promotion-${randomUUID()}`;
    const promoted = goalCommand([
      "recovery-promote",
      "--goal", GOAL_ID,
      "--task", TASK_ID,
      "--successor-thread", D2_THREAD,
      "--preflight-evidence", d2Launch.preflight.evidence_id,
      "--captain-thread", CAPTAIN_THREAD,
      "--captain-capability-file", fixture.captainCapability as string,
      "--event-id", promotionEventId,
      "--json",
    ], fixture.destination);
    expect(promoted.exitCode).toBe(0);
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      operational_scope: "FULL",
    });
    const promotionEvidenceFile = path.join(
      fixture.controlDir,
      "goals",
      GOAL_ID,
      "evidence",
      TASK_ID,
      `${d2Launch.preflight.evidence_id}.json`
    );
    const promotionEvidenceBytes = readFileSync(promotionEvidenceFile);
    unlinkSync(promotionEvidenceFile);
    expectControlCode(
      () => taskState(fixture, fixture.destination),
      "EVIDENCE_NOT_REGISTERED"
    );
    writeFileSync(promotionEvidenceFile, promotionEvidenceBytes);
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      operational_scope: "FULL",
      recovery_promotion: {
        preflight_evidence: {
          evidence_id: d2Launch.preflight.evidence_id,
        },
      },
    });
    expect(goalCommand([
      "recovery-promote",
      "--goal", GOAL_ID,
      "--task", TASK_ID,
      "--successor-thread", D2_THREAD,
      "--preflight-evidence", d2Launch.preflight.evidence_id,
      "--captain-thread", CAPTAIN_THREAD,
      "--captain-capability-file", fixture.captainCapability as string,
      "--event-id", promotionEventId,
      "--json",
    ], fixture.destination).value).toMatchObject({
      accepted: true,
      idempotent: true,
      operational_scope: "FULL",
    });
    expectControlCode(
      () =>
        goalCommand([
          "recovery-promote",
          "--goal", GOAL_ID,
          "--task", TASK_ID,
          "--successor-thread", D2_THREAD,
          "--preflight-evidence", d2Launch.preflight.evidence_id,
          "--captain-thread", CAPTAIN_THREAD,
          "--captain-capability-file", path.join(fixture.sandbox, "bogus-captain.cap"),
          "--event-id", promotionEventId,
          "--json",
        ], fixture.destination),
      "CAPABILITY_INVALID"
    );

    writeFileSync(
      path.join(fixture.destination, "post-promotion-fix.txt"),
      "candidate work after recovery promotion\n"
    );
    git(fixture.destination, "add", "post-promotion-fix.txt");
    git(fixture.destination, "commit", "-qm", "candidate fix after promotion");
    const candidateHead = git(fixture.destination, "rev-parse", "HEAD");
    expect(git(fixture.destination, "rev-parse", `${candidateHead}^`)).toBe(
      importCommit
    );

    const resumed = resumeCapsule(
      fixture.destination,
      GOAL_ID,
      TASK_ID,
      "DEV",
      D2_THREAD
    );
    expect(resumed).toMatchObject({
      launch_scope: "SOURCE_CHECKPOINT_PREFLIGHT_REQUIRED",
      launch_id: "launch-dev-recovery-a2",
      resource_leases: [],
    });
    expect(
      (resumed.allowed_actions as Array<{ type: string }>).map(
        (action) => action.type
      )
    ).not.toContain("DEV_READY");
    const projected = actionsForTask(
      fixture.destination,
      GOAL_ID,
      TASK_ID,
      "DEV",
      D2_THREAD
    );
    expect(
      (projected.actions as Array<{ type: string }>).map(
        (action) => action.type
      )
    ).not.toContain("DEV_READY");
    expect(projected.maintenance_actions).toEqual([
      expect.objectContaining({ type: "HEARTBEAT", actor_role: "DEV" }),
    ]);
    const captainProjected = actionsForTask(
      fixture.destination,
      GOAL_ID,
      TASK_ID,
      "CAPTAIN",
      CAPTAIN_THREAD
    );
    expect(captainProjected.maintenance_actions).toEqual([
      expect.objectContaining({
        type: "REQUEST_CANDIDATE_PREFLIGHT",
        actor_role: "CAPTAIN",
        dispatch: {
          coordinator_role: "CAPTAIN",
          executor_binding: "EXACT_ACTIVE_DEV",
          executor: {
            role: "DEV",
            thread_id: D2_THREAD,
            host_id: "host-d2",
          },
          capability_mode: "EXACT_DEV_CAPABILITY",
        },
        forbidden_action: "ROTATE_RUNTIME",
      }),
      expect.objectContaining({ type: "HEARTBEAT", actor_role: "CAPTAIN" }),
    ]);

    const candidateLaunch = createLaunch(
      fixture,
      fixture.destination,
      D2_THREAD,
      fixture.d2Capability as string,
      [],
      "NONE"
    );
    const currentPreflight = candidateLaunch.preflight;
    expect(currentPreflight.status).toBe("PASS");
    const candidateResumed = resumeCapsule(
      fixture.destination,
      GOAL_ID,
      TASK_ID,
      "DEV",
      D2_THREAD
    );
    expect(candidateResumed).toMatchObject({
      launch_scope: "FULL",
      launch_id: "launch-dev-recovery-a2",
      resource_leases: [],
    });
    expect(
      (candidateResumed.allowed_actions as Array<{ type: string }>).map(
        (action) => action.type
      )
    ).toContain("DEV_READY");
    const fast = recordMechanicalEvidence(
      fixture,
      "FAST",
      "DEV",
      candidateHead
    );
    const fullCi = recordMechanicalEvidence(
      fixture,
      "FULL_CI",
      "CAPTAIN",
      candidateHead
    );
    const acAudit = recordMechanicalEvidence(
      fixture,
      "AC_AUDIT",
      "CAPTAIN",
      candidateHead
    );
    submit(
      fixture,
      fixture.destination,
      "DEV_READY",
      "DEV",
      D2_THREAD,
      {
        pr: "https://github.com/example-org/example-repo/pull/999",
        evidence: {
          preflight: currentPreflight.evidence_id,
          fast,
          full_ci: fullCi,
          ac_audit: acAudit,
        },
      },
      candidateHead
    );
    expect(taskState(fixture, fixture.destination)).toMatchObject({
      phase: "DEV_READY",
      full_head: candidateHead,
    });
  });

  it("projects the promoted predecessor launch checkpoint into the next recovery epoch", () => {
    prepareRecovered(fixture);
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const importCommit = commitImport(fixture, snapshot, receipt);
    const handoffEventId = bindHandoff(
      fixture,
      snapshot,
      receipt,
      importCommit
    );

    const preflightOnlyActions = actionsForTask(
      fixture.destination,
      GOAL_ID,
      TASK_ID,
      "CAPTAIN",
      CAPTAIN_THREAD
    );
    expect(
      (preflightOnlyActions.actions as Array<{ type: string }>).map(
        (action) => action.type
      )
    ).toEqual(expect.arrayContaining(["RECOVERY_PROMOTED", "ADD_HOLD"]));
    expect(
      (preflightOnlyActions.actions as Array<{ type: string }>).map(
        (action) => action.type
      )
    ).not.toContain("ROLE_LOST");

    resourceCommand([
      "reinitialize-zero-runtime",
      "--goal", GOAL_ID,
      "--task", TASK_ID,
      "--successor-thread", D2_THREAD,
      "--handoff-event-id", handoffEventId,
      "--captain-capability-file", fixture.captainCapability as string,
      "--captain-thread", CAPTAIN_THREAD,
      "--foreman-capability-file", fixture.foremanCapability as string,
      "--foreman-thread", FOREMAN_THREAD,
      "--event-id", `reinitialize-${randomUUID()}`,
      "--json",
    ], fixture.destination);
    const d2Launch = createLaunch(
      fixture,
      fixture.destination,
      D2_THREAD,
      fixture.d2Capability as string,
      [],
      "NONE"
    );
    goalCommand([
      "recovery-promote",
      "--goal", GOAL_ID,
      "--task", TASK_ID,
      "--successor-thread", D2_THREAD,
      "--preflight-evidence", d2Launch.preflight.evidence_id,
      "--captain-thread", CAPTAIN_THREAD,
      "--captain-capability-file", fixture.captainCapability as string,
      "--event-id", `promotion-${randomUUID()}`,
      "--json",
    ], fixture.destination);

    submit(
      fixture,
      fixture.destination,
      "ROLE_LOST",
      "CAPTAIN",
      CAPTAIN_THREAD,
      {
        role: "DEV",
        reason: "promoted recovered predecessor lost",
        fingerprint: "system-error:recovered-predecessor",
        attempts: 1,
      }
    );
    const d3Thread = "dev-recovery-3";
    registerDev(fixture, d3Thread, 3, "launch-dev-recovery-a3");
    submit(
      fixture,
      fixture.destination,
      "ROLE_RECOVERED",
      "CAPTAIN",
      CAPTAIN_THREAD,
      { successor_thread_id: d3Thread }
    );

    const recovered = taskState(fixture, fixture.destination).sessions.DEV;
    expect(recovered).toMatchObject({
      thread_id: d3Thread,
      operational_scope: "RECOVERY_BLOCKED",
      recovered_from: {
        thread_id: D2_THREAD,
        predecessor_launch_id: "launch-dev-recovery-a2",
        predecessor_registered_head: fixture.fullHead,
        predecessor_launch_head: importCommit,
      },
    });
    expect(taskState(fixture, fixture.destination).sessions.DEV?.recovered_from)
      .toEqual(recovered?.recovered_from);
  });

  it("rejects any source commit between recovery bind and preflight launch", () => {
    prepareRecovered(fixture);
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const importCommit = commitImport(fixture, snapshot, receipt);
    bindHandoff(fixture, snapshot, receipt, importCommit);
    writeFileSync(
      path.join(fixture.destination, "forbidden-preflight-edit.txt"),
      "must not enter a PREFLIGHT_ONLY launch\n"
    );
    git(fixture.destination, "add", "forbidden-preflight-edit.txt");
    git(fixture.destination, "commit", "-qm", "forbidden descendant");

    expectControlCode(
      () => createLaunch(
        fixture,
        fixture.destination,
        D2_THREAD,
        fixture.d2Capability as string,
        [],
        "NONE"
      ),
      "STALE_HEAD"
    );
  });

  it("rejects importing the sealed snapshot into the predecessor worktree", () => {
    prepareRecovered(fixture);
    const snapshot = exportSnapshot(fixture);
    expectControlCode(
      () =>
        importRecoverySnapshot(fixture.source, {
          goalId: GOAL_ID,
          taskId: TASK_ID,
          importId: "import-recovery-lifecycle-wrong-destination",
          snapshotId: snapshot.snapshot_id,
          successorThreadId: D2_THREAD,
          actorCapabilityFile: fixture.d2Capability,
        }),
      "HANDOFF_SAME_WORKTREE"
    );
  });

  it("rejects a tampered snapshot before destination mutation", () => {
    prepareRecovered(fixture);
    const snapshot = exportSnapshot(fixture);
    appendFileSync(
      path.join(path.dirname(snapshot.snapshot_file), snapshot.tracked_patch.file),
      "tampered snapshot"
    );
    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_ARTIFACT_TAMPERED"
    );
    expect(git(fixture.destination, "status", "--porcelain=v1")).toBe("");
  });

  it("rejects a tampered import receipt before handoff binding", () => {
    prepareRecovered(fixture);
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const importCommit = commitImport(fixture, snapshot, receipt);
    const tampered = JSON.parse(
      readFileSync(receipt.import_receipt_file, "utf8")
    ) as Record<string, unknown>;
    tampered.materialized_patch_sha256 = hashObject("tampered receipt");
    writeJson(receipt.import_receipt_file, tampered);
    expectControlCode(
      () =>
        buildRecoveryHandoffPayload(fixture.destination, {
          goalId: GOAL_ID,
          taskId: TASK_ID,
          successorThreadId: D2_THREAD,
          snapshotId: snapshot.snapshot_id,
          importReceiptId: receipt.import_receipt_id,
          importCommit,
          captainCapabilityFile: fixture.captainCapability,
          captainThreadId: CAPTAIN_THREAD,
        }),
      "HANDOFF_RECEIPT_TAMPERED"
    );
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      operational_scope: "RECOVERY_BLOCKED",
    });
  });

  it("keeps bound identity frozen until CAPTAIN+FOREMAN abandon it, then permits a fresh successor without migrating runtime", () => {
    prepareRecovered(fixture);
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const importCommit = commitImport(fixture, snapshot, receipt);
    bindHandoff(fixture, snapshot, receipt, importCommit);
    const before = taskState(fixture, fixture.destination);

    expectControlCode(
      () =>
        submit(
          fixture,
          fixture.destination,
          "ROLE_LOST",
          "CAPTAIN",
          CAPTAIN_THREAD,
          {
            role: "DEV",
            reason: "attempted retarget after sealed handoff",
            fingerprint: "system-error:must-not-retarget",
            attempts: 1,
          }
        ),
      "RECOVERY_IDENTITY_FROZEN"
    );

    expect(taskState(fixture, fixture.destination)).toMatchObject({
      state_revision: before.state_revision,
      sessions: {
        DEV: {
          thread_id: D2_THREAD,
          attempt: 2,
          operational_scope: "PREFLIGHT_ONLY",
          recovery_handoff: {
            import_commit: importCommit,
          },
        },
      },
    });

    const abandoned = goalCommand([
      "recovery-abandon-handoff",
      "--goal", GOAL_ID,
      "--task", TASK_ID,
      "--successor-thread", D2_THREAD,
      "--captain-thread", CAPTAIN_THREAD,
      "--captain-capability-file", fixture.captainCapability as string,
      "--foreman-thread", FOREMAN_THREAD,
      "--foreman-capability-file", fixture.foremanCapability as string,
      "--reason", "bound successor task disappeared before promotion",
      "--incident-ref", "test://recovery/preflight-only-successor-loss",
      "--event-id", `abandon-${randomUUID()}`,
      "--json",
    ], fixture.destination);
    expect(abandoned.exitCode).toBe(0);
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      thread_id: D2_THREAD,
      operational_scope: "RECOVERY_BLOCKED",
      abandoned_recovery_handoffs: [
        expect.objectContaining({
          event_id: expect.any(String),
          import_commit: importCommit,
          incident_ref: "test://recovery/preflight-only-successor-loss",
        }),
      ],
    });
    expect(taskState(fixture, fixture.destination).sessions.DEV?.recovery_handoff)
      .toBeUndefined();
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      recovery_retarget_required: {
        abandoned_handoff_event_id: expect.any(String),
        required_next: "ROLE_LOST",
      },
    });
    expectControlCode(
      () => bindHandoff(fixture, snapshot, receipt, importCommit),
      "RECOVERY_RETARGET_REQUIRED"
    );

    submit(
      fixture,
      fixture.destination,
      "ROLE_LOST",
      "CAPTAIN",
      CAPTAIN_THREAD,
      {
        role: "DEV",
        reason: "abandoned bound successor is gone",
        fingerprint: "system-error:preflight-only-successor-loss",
        attempts: 1,
      }
    );
    const d3Thread = "dev-recovery-after-abandon";
    registerDev(fixture, d3Thread, 3, "launch-dev-recovery-a3");
    submit(
      fixture,
      fixture.destination,
      "ROLE_RECOVERED",
      "CAPTAIN",
      CAPTAIN_THREAD,
      { successor_thread_id: d3Thread }
    );
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      thread_id: d3Thread,
      attempt: 3,
      operational_scope: "RECOVERY_BLOCKED",
      recovered_from: {
        thread_id: D1_THREAD,
        predecessor_launch_id: "launch-dev-recovery-a1",
      },
    });
  });

  it("does not terminate a task cycle while the lost worker still owns a nonterminal lease", () => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
    fixture = makeFixture({ withResource: true });
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    registerInitialRoles(fixture);
    advanceP1(fixture);
    const d1 = registerDev(
      fixture,
      D1_THREAD,
      1,
      "launch-dev-recovery-a1"
    );
    fixture.d1Capability = d1.actor_capability_file;
    fixture.d1Lease = acquireLease(fixture.source, {
      goalId: GOAL_ID,
      taskId: TASK_ID,
      eventId: "acquire-d1-nonterminal-cycle",
      role: "DEV",
      threadId: D1_THREAD,
      hostId: "host-d1",
      resource: RESOURCE,
      access: "EXCLUSIVE",
      ttlMilliseconds: 3_600_000,
      actorCapabilityFile: fixture.d1Capability,
    });
    createLaunch(
      fixture,
      fixture.source,
      D1_THREAD,
      fixture.d1Capability,
      [fixture.d1Lease.lease_id],
      "NONE"
    );
    submit(
      fixture,
      fixture.source,
      "LAUNCH_DEV",
      "CAPTAIN",
      CAPTAIN_THREAD,
      { launch_id: "launch-dev-recovery-a1" }
    );
    submit(
      fixture,
      fixture.source,
      "ROLE_LOST",
      "CAPTAIN",
      CAPTAIN_THREAD,
      {
        role: "DEV",
        reason: "packet change after worker loss",
        fingerprint: "system-error:packet-lease-boundary",
        attempts: 1,
      }
    );
    const packetPath =
      "docs/planning/goals/recovery-e2e/packet-r2.md";
    writeFileSync(
      path.join(fixture.source, packetPath),
      "# Recovery task packet r2\n"
    );
    git(fixture.source, "add", packetPath);
    git(fixture.source, "commit", "-qm", "revise recovery packet");
    const packetHead = git(fixture.source, "rev-parse", "HEAD");

    expectControlCode(
      () =>
        submit(
          fixture,
          fixture.source,
          "PACKET_UPDATED",
          "FOREMAN",
          FOREMAN_THREAD,
          {
            revision: 2,
            path: packetPath,
            sha256: hashFile(path.join(fixture.source, packetPath)),
            change_kind: "CONTRACT",
          },
          packetHead
        ),
      "PACKET_UPDATE_RESOURCE_LEASES_ACTIVE"
    );
    expect(taskState(fixture)).toMatchObject({
      phase: "DEV_ACTIVE",
      full_head: fixture.fullHead,
      packet: { revision: 1 },
    });
  });

  it("requires an external broker for a non-NONE predecessor launch", () => {
    prepareRecovered(fixture, { predecessorTarget: "CLI" });
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const importCommit = commitImport(fixture, snapshot, receipt);
    const handoffEventId = bindHandoff(
      fixture,
      snapshot,
      receipt,
      importCommit
    );
    expectControlCode(
      () =>
        reinitializeZeroRuntimeLeases(fixture.destination, {
          goalId: GOAL_ID,
          taskId: TASK_ID,
          successorThreadId: D2_THREAD,
          handoffEventId,
          captainCapabilityFile: fixture.captainCapability,
          captainThreadId: CAPTAIN_THREAD,
          foremanCapabilityFile: fixture.foremanCapability,
          foremanThreadId: FOREMAN_THREAD,
          eventId: `reinitialize-${randomUUID()}`,
        }),
      "REINITIALIZE_REQUIRES_BROKER"
    );
    expect(taskState(fixture, fixture.destination).sessions.DEV).toMatchObject({
      operational_scope: "PREFLIGHT_ONLY",
    });
  });

  it("requires an external broker when a target=NONE predecessor launch contains any lease", () => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
    fixture = makeFixture({ withResource: true });
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    prepareRecovered(fixture);
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const importCommit = commitImport(fixture, snapshot, receipt);
    const handoffEventId = bindHandoff(
      fixture,
      snapshot,
      receipt,
      importCommit
    );
    expectControlCode(
      () =>
        reinitializeZeroRuntimeLeases(fixture.destination, {
          goalId: GOAL_ID,
          taskId: TASK_ID,
          successorThreadId: D2_THREAD,
          handoffEventId,
          captainCapabilityFile: fixture.captainCapability,
          captainThreadId: CAPTAIN_THREAD,
          foremanCapabilityFile: fixture.foremanCapability,
          foremanThreadId: FOREMAN_THREAD,
          eventId: `reinitialize-${randomUUID()}`,
        }),
      "REINITIALIZE_REQUIRES_BROKER"
    );
    const oldLease = listLeases(fixture.destination, {
      goalId: GOAL_ID,
      taskId: TASK_ID,
    }).leases.find(
      (lease) => lease.lease_id === fixture.d1Lease?.lease_id
    );
    expect(oldLease?.status).toBe("ACTIVE");
  });

  it("does not reinterpret a released predecessor lease as proof that its runtime is isolated", () => {
    rmSync(fixture.sandbox, { recursive: true, force: true });
    fixture = makeFixture({ withResource: true });
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    prepareRecovered(fixture, { releaseOldLease: true });
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const importCommit = commitImport(fixture, snapshot, receipt);
    const handoffEventId = bindHandoff(
      fixture,
      snapshot,
      receipt,
      importCommit
    );
    expectControlCode(
      () =>
        reinitializeZeroRuntimeLeases(fixture.destination, {
          goalId: GOAL_ID,
          taskId: TASK_ID,
          successorThreadId: D2_THREAD,
          handoffEventId,
          captainCapabilityFile: fixture.captainCapability,
          captainThreadId: CAPTAIN_THREAD,
          foremanCapabilityFile: fixture.foremanCapability,
          foremanThreadId: FOREMAN_THREAD,
          eventId: `reinitialize-${randomUUID()}`,
        }),
      "REINITIALIZE_REQUIRES_BROKER"
    );
    const oldLease = listLeases(fixture.destination, {
      goalId: GOAL_ID,
      taskId: TASK_ID,
    }).leases.find(
      (lease) => lease.lease_id === fixture.d1Lease?.lease_id
    );
    expect(oldLease?.status).toBe("RELEASED");
  });
});
