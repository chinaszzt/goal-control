import { execFileSync } from "child_process";
import { createHash, randomBytes } from "crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "fs";
import { createRequire } from "module";
import path from "path";

const nodeRequire = createRequire(import.meta.url);
const goalModule = nodeRequire("../scripts/goal-control/goal.js") as {
  loadGoalStateUnlocked: (root: string, goalId: string) => LoadedGoal;
};
const {
  hashObject,
  trustedTemporaryRoot,
} = nodeRequire("../scripts/goal-control/util.js") as {
  hashObject: (value: unknown) => string;
  trustedTemporaryRoot: () => string;
};
const { withLock } = nodeRequire("../scripts/goal-control/store.js") as {
  withLock: <T>(root: string, callback: () => T) => T;
};
const originalLoadGoalStateUnlocked = goalModule.loadGoalStateUnlocked;
const {
  buildCodexShellAudit,
  exportRecoverySnapshot,
  exportRecoverySnapshotFromCodexRollout,
  importRecoverySnapshot,
  inspectCodexRolloutPatchEvents,
} = nodeRequire("../scripts/goal-control/source-handoff.js") as {
  buildCodexShellAudit: (options: {
    goalId: string;
    taskId: string;
    predecessorLaunchId: string;
    predecessorThreadId: string;
    historicalWorktree: string;
    predecessorHead: string;
    rolloutFile: string;
    captainThreadId: string;
    foremanThreadId: string;
    incidentRef: string;
    dispositionsFile: string;
  }) => Record<string, unknown>;
  exportRecoverySnapshot: (
    cwd: string,
    options: {
      goalId: string;
      taskId: string;
      snapshotId: string;
      successorThreadId: string;
      captainCapabilityFile: string;
      repositoryWorktree: string;
    }
  ) => RecoverySnapshot;
  exportRecoverySnapshotFromCodexRollout: (
    cwd: string,
    options: {
      goalId: string;
      taskId: string;
      snapshotId: string;
      successorThreadId: string;
      predecessorLaunchId: string;
      predecessorThreadId: string;
      rolloutFile: string;
      captainCapabilityFile: string;
      repositoryWorktree: string;
      shellAuditFile?: string;
      foremanCapabilityFile?: string;
    }
  ) => RecoverySnapshot;
  importRecoverySnapshot: (
    cwd: string,
    options: {
      goalId: string;
      taskId: string;
      importId: string;
      snapshotId: string;
      successorThreadId: string;
      actorCapabilityFile: string;
    }
  ) => ImportReceipt;
  inspectCodexRolloutPatchEvents: (
    rolloutFile: string,
    options: {
      historicalWorktree: string;
      predecessorThreadId: string;
      allowShellAudit?: boolean;
    }
  ) => {
    shell_call_count: number;
    shell_calls: Array<{
      call_id: string;
      name: string;
      required_disposition?: string;
    }>;
  };
};
const {
  eventTemplateActionAllowed,
  helpDocument,
} = nodeRequire("../scripts/goal-control/usability.js") as {
  helpDocument: (binary: "goal", topic?: string) => {
    usage?: string;
    commands?: Array<{ name: string }>;
  };
  eventTemplateActionAllowed: (
    state: Record<string, unknown>,
    session: { role: string; status: string },
    role: string,
    type: string
  ) => boolean;
};
const { goalCommand } = nodeRequire("../scripts/goal-control/cli.js") as {
  goalCommand: (
    argv: string[],
    cwd: string
  ) => { value: RecoverySnapshot; exitCode: number };
};

type LoadedGoal = {
  paths: { dir: string };
  manifest: { goal_id: string };
  meta: { repository_root: string };
  control: { epoch: number };
  snapshot: {
    tasks: Record<string, {
      task_id: string;
      phase: string;
      packet: { revision: number; path: string; sha256: string };
      full_head: string;
      sessions: {
        FOREMAN: {
          role: "FOREMAN";
          thread_id: string;
          host_id: string;
          attempt: number;
          status: "active" | "terminal";
          lease_until: string;
          capability_file: string;
          capability_sha256: string;
        };
        CAPTAIN: {
          role: "CAPTAIN";
          thread_id: string;
          host_id: string;
          attempt: number;
          status: "active" | "terminal";
          lease_until: string;
          capability_file: string;
          capability_sha256: string;
        };
        DEV: {
          role: "DEV";
          thread_id: string;
          host_id: string;
          attempt: number;
          status: "active" | "terminal";
          lease_until: string;
          capability_file: string;
          capability_sha256: string;
          operational_scope: "RECOVERY_BLOCKED";
          recovered_from: {
            role: "DEV";
            thread_id: string;
            host_id: string;
            attempt: number;
            predecessor_launch_id: string;
            predecessor_registered_head: string;
            predecessor_launch_head?: string;
          };
        };
      };
      session_history: {
        FOREMAN?: Array<Record<string, unknown>>;
        CAPTAIN?: Array<Record<string, unknown>>;
        DEV: Array<{
          role: "DEV";
          thread_id: string;
          host_id: string;
          attempt: number;
          status: "lost";
          launch_id: string;
          task_nonce: string;
          registered_full_head?: string;
          operational_scope?: "FULL";
          recovery_handoff?: { import_commit: string };
          recovery_promotion?: {
            launch_id: string;
            launch_sha256: string;
            promoted_at?: string;
          };
        }>;
      };
    }>;
  };
};

type RecoverySnapshot = {
  snapshot_id: string;
  snapshot_sha256: string;
  snapshot_file: string;
  source_worktree: string;
  source_launch_head: string;
  expected_paths: string[];
  tracked_patch: { file: string; sha256: string };
  source_capture: {
    artifact: string;
    rollout_file_sha256: string;
    session_id: string;
    event_count: number;
    excluded_patch_count: number;
    events: Array<{
      call_id: string;
      call_record_sha256: string;
      event_record_sha256: string;
      result_record_sha256: string;
    }>;
    shell_audit?: {
      call_count: number;
      incident_ref: string;
      records_artifact: string;
    };
  };
  acceptance_authority: {
    captain: {
      thread_id: string;
      attempt: number;
      capability_file: string;
    };
    foreman?: {
      thread_id: string;
      attempt: number;
      capability_file: string;
    };
  };
  idempotent?: boolean;
};

type ImportReceipt = {
  snapshot_id: string;
  destination_worktree: string;
  materialized_patch_bytes: number;
};

type Fixture = {
  sandbox: string;
  repository: string;
  lostSource: string;
  destination: string;
  controlDir: string;
  rolloutFile: string;
  registeredHead: string;
  baseHead: string;
  captainCapabilityFile: string;
  foremanCapabilityFile: string;
  devCapabilityFile: string;
  loaded: LoadedGoal;
};

type PatchSpec = {
  callId: string;
  absolutePath: string;
  unifiedDiff: string;
  changeType?: string;
  includeEvent?: boolean;
};

type ProvenanceRecord = {
  payload: {
    input?: string;
    output?: string;
  };
  [key: string]: unknown;
};

type SnapshotManifest = {
  snapshot_sha256?: string;
  source_capture: {
    size: number;
    sha256: string;
    events: Array<{
      call_record_sha256: string;
      event_record_sha256: string;
      result_record_sha256: string;
    }>;
  };
  [key: string]: unknown;
};

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

function resealProvenance(
  snapshot: RecoverySnapshot,
  mutate: (records: ProvenanceRecord[]) => void
): void {
  const manifest = JSON.parse(
    readFileSync(snapshot.snapshot_file, "utf8")
  ) as SnapshotManifest;
  const artifact = path.join(
    path.dirname(snapshot.snapshot_file),
    snapshot.source_capture.artifact
  );
  const records = readFileSync(artifact, "utf8")
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line) as ProvenanceRecord);
  mutate(records);
  const rawRecords = records.map((record) => JSON.stringify(record));
  const body = `${rawRecords.join("\n")}\n`;
  writeFileSync(artifact, body);

  const event = manifest.source_capture.events[0];
  event.call_record_sha256 = sha256(rawRecords[1]);
  event.event_record_sha256 = sha256(rawRecords[2]);
  event.result_record_sha256 = sha256(rawRecords[3]);
  manifest.source_capture.size = Buffer.byteLength(body);
  manifest.source_capture.sha256 = sha256(body);
  delete manifest.snapshot_sha256;
  manifest.snapshot_sha256 = hashObject(manifest);
  writeFileSync(snapshot.snapshot_file, `${JSON.stringify(manifest, null, 2)}\n`);
}

function createCapability(directory: string, name: string): {
  file: string;
  verifier: string;
} {
  mkdirSync(directory, { recursive: true });
  const file = path.join(directory, `${name}.cap`);
  const value = randomBytes(32).toString("base64url");
  writeFileSync(file, `${value}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  return {
    file: realpathSync(file),
    verifier: createHash("sha256").update(value).digest("hex"),
  };
}

function makeLaunch(repository: string, lostSource: string, baseHead: string): Record<string, unknown> {
  return {
    schema_version: 1,
    launch_id: "launch-lost-dev-a1",
    goal_id: "goal-codex-rollout",
    task_id: "TASK-A",
    role: "DEV",
    control_epoch: 0,
    state_revision: 4,
    thread: {
      id: "dev-lost",
      host_id: "host-a",
      cwd: lostSource,
    },
    packet: {
      revision: 1,
      path: "docs/packet.md",
      sha256: sha256("packet"),
    },
    repository: {
      name_with_owner: "example-org/example-repo",
      origin_url: "https://github.com/example-org/example-repo.git",
      base_branch: "main",
      base_head: baseHead,
      full_head: baseHead,
      branch: "task/lost",
      root: realpathSync(repository),
      worktree: lostSource,
    },
    runtime: {
      node_version: process.version,
      pnpm_version: "10.0.0",
      lockfile_sha256: sha256("lockfileVersion: '9.0'\n"),
    },
    execution: {
      environment: "none",
      write_mode: "NONE",
      task_nonce: "codex_rollout_test_nonce_123456",
      target: { kind: "NONE" },
    },
    resource_leases: [],
    created_at: "2026-07-23T00:00:00.000Z",
  };
}

function rolloutRecords(lostSource: string, patches: PatchSpec[]): Array<Record<string, unknown>> {
  const records: Array<Record<string, unknown>> = [{
    timestamp: "2026-07-23T00:00:00.000Z",
    type: "session_meta",
    payload: {
      session_id: "dev-lost",
      id: "dev-lost",
      cwd: lostSource,
    },
  }, {
    timestamp: "2026-07-23T00:00:00.000Z",
    type: "session_meta",
    payload: {
      session_id: "fork-parent",
      id: "fork-parent",
      cwd: path.dirname(lostSource),
    },
  }];
  patches.forEach((patchSpec, index) => {
    records.push({
      timestamp: `2026-07-23T00:00:0${index + 1}.000Z`,
      type: "response_item",
      payload: {
        type: "custom_tool_call",
        status: "completed",
        call_id: patchSpec.callId,
        name: "apply_patch",
        input: [
          "*** Begin Patch",
          `*** Update File: ${patchSpec.absolutePath}`,
          patchSpec.unifiedDiff,
          "*** End Patch",
          "",
        ].join("\n"),
      },
    });
    if (patchSpec.includeEvent !== false) {
      records.push({
        timestamp: `2026-07-23T00:00:0${index + 1}.100Z`,
        type: "event_msg",
        payload: {
          type: "patch_apply_end",
          call_id: patchSpec.callId,
          turn_id: `turn-${index + 1}`,
          stdout: "Success. Updated the following files:\n",
          stderr: "",
          success: true,
          status: "completed",
          changes: {
            [patchSpec.absolutePath]: {
              type: patchSpec.changeType ?? "update",
              unified_diff: patchSpec.unifiedDiff,
              move_path: null,
            },
          },
        },
      });
    }
    records.push({
      timestamp: `2026-07-23T00:00:0${index + 1}.200Z`,
      type: "response_item",
      payload: {
        type: "custom_tool_call_output",
        call_id: patchSpec.callId,
        output: "Exit code: 0\nOutput:\nSuccess. Updated the following files:\n",
      },
    });
  });
  return records;
}

function writeRollout(fixture: Fixture, patches: PatchSpec[]): void {
  const body = `${rolloutRecords(fixture.lostSource, patches)
    .map((record) => JSON.stringify(record))
    .join("\n")}\n`;
  writeFileSync(fixture.rolloutFile, body);
}

function appendRolloutRecords(
  fixture: Fixture,
  records: Array<Record<string, unknown>>
): void {
  appendFileSync(
    fixture.rolloutFile,
    `${records.map((record) => JSON.stringify(record)).join("\n")}\n`
  );
}

function makeFixture(): Fixture {
  const sandbox = mkdtempSync(
    path.join(trustedTemporaryRoot(), "goal-control-codex-rollout-")
  );
  const repository = path.join(sandbox, "repo");
  const lostSourceCandidate = path.join(sandbox, "lost-source");
  const destination = path.join(sandbox, "destination");
  const controlCandidate = path.join(sandbox, "control");
  mkdirSync(repository, { recursive: true });
  mkdirSync(controlCandidate, { recursive: true });
  const controlDir = realpathSync(controlCandidate);
  withLock(controlDir, () => undefined);
  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.email", "rollout@example.test");
  git(repository, "config", "user.name", "Codex Rollout Test");
  git(repository, "remote", "add", "origin", "https://github.com/example-org/example-repo.git");
  writeFileSync(path.join(repository, "tracked.txt"), "base\n");
  writeFileSync(
    path.join(repository, "duplicates.txt"),
    [
      "function a() {",
      "  return 1;",
      "}",
      "function b() {",
      "  return 1;",
      "}",
      "",
    ].join("\n")
  );
  writeFileSync(path.join(repository, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "base");
  const registeredHead = git(repository, "rev-parse", "HEAD");
  git(repository, "commit", "--allow-empty", "-qm", "promoted import checkpoint");
  const baseHead = git(repository, "rev-parse", "HEAD");
  git(repository, "worktree", "add", "-q", "-b", "task/lost", lostSourceCandidate, baseHead);
  const lostSource = realpathSync(lostSourceCandidate);
  git(repository, "worktree", "add", "-q", "-b", "task/destination", destination, baseHead);

  const capabilityDir = path.join(controlDir, "goals", "goal-codex-rollout", "capabilities");
  const captain = createCapability(capabilityDir, "captain");
  const foreman = createCapability(capabilityDir, "foreman");
  const dev = createCapability(capabilityDir, "dev-successor");
  const launchDir = path.join(
    controlDir,
    "goals",
    "goal-codex-rollout",
    "launches",
    "TASK-A"
  );
  mkdirSync(launchDir, { recursive: true });
  writeFileSync(
    path.join(launchDir, "launch-lost-dev-a1.json"),
    `${JSON.stringify(makeLaunch(repository, lostSource, baseHead), null, 2)}\n`
  );
  const loaded: LoadedGoal = {
    paths: { dir: path.join(controlDir, "goals", "goal-codex-rollout") },
    manifest: { goal_id: "goal-codex-rollout" },
    meta: { repository_root: realpathSync(repository) },
    control: { epoch: 0 },
    snapshot: {
      tasks: {
        "TASK-A": {
          task_id: "TASK-A",
          phase: "DEV_ACTIVE",
          packet: {
            revision: 1,
            path: "docs/packet.md",
            sha256: sha256("packet"),
          },
          full_head: baseHead,
          sessions: {
            FOREMAN: {
              role: "FOREMAN",
              thread_id: "foreman-current",
              host_id: "host-a",
              attempt: 1,
              status: "active",
              lease_until: "2099-01-01T00:00:00.000Z",
              capability_file: foreman.file,
              capability_sha256: foreman.verifier,
            },
            CAPTAIN: {
              role: "CAPTAIN",
              thread_id: "captain-current",
              host_id: "host-a",
              attempt: 1,
              status: "active",
              lease_until: "2099-01-01T00:00:00.000Z",
              capability_file: captain.file,
              capability_sha256: captain.verifier,
            },
            DEV: {
              role: "DEV",
              thread_id: "dev-successor",
              host_id: "host-b",
              attempt: 2,
              status: "active",
              lease_until: "2099-01-01T00:00:00.000Z",
              capability_file: dev.file,
              capability_sha256: dev.verifier,
              operational_scope: "RECOVERY_BLOCKED",
              recovered_from: {
                role: "DEV",
                thread_id: "dev-lost",
                host_id: "host-a",
                attempt: 1,
                predecessor_launch_id: "launch-lost-dev-a1",
                predecessor_registered_head: baseHead,
              },
            },
          },
          session_history: {
            DEV: [{
              role: "DEV",
              thread_id: "dev-lost",
              host_id: "host-a",
              attempt: 1,
              status: "lost",
              launch_id: "launch-lost-dev-a1",
              task_nonce: "codex_rollout_test_nonce_123456",
            }],
          },
        },
      },
    },
  };
  const rolloutFile = path.join(sandbox, "rollout.jsonl");
  git(repository, "worktree", "remove", "--force", lostSource);
  expect(existsSync(lostSource)).toBe(false);
  return {
    sandbox,
    repository,
    lostSource,
    destination,
    controlDir,
    rolloutFile,
    registeredHead,
    baseHead,
    captainCapabilityFile: captain.file,
    foremanCapabilityFile: foreman.file,
    devCapabilityFile: dev.file,
    loaded,
  };
}

function configurePromotedPredecessor(
  fixture: Fixture,
  promotedAt = "2026-07-22T23:59:59.000Z"
): void {
  const task = fixture.loaded.snapshot.tasks["TASK-A"];
  const recovered = task.sessions.DEV.recovered_from;
  const predecessor = task.session_history.DEV[0];
  const launchFile = path.join(
    fixture.controlDir,
    "goals",
    "goal-codex-rollout",
    "launches",
    "TASK-A",
    "launch-lost-dev-a1.json"
  );
  recovered.predecessor_registered_head = fixture.registeredHead;
  recovered.predecessor_launch_head = fixture.baseHead;
  predecessor.registered_full_head = fixture.registeredHead;
  predecessor.operational_scope = "FULL";
  predecessor.recovery_handoff = { import_commit: fixture.baseHead };
  predecessor.recovery_promotion = {
    launch_id: "launch-lost-dev-a1",
    launch_sha256: sha256(readFileSync(launchFile)),
    promoted_at: promotedAt,
  };
}

function defaultPatch(fixture: Fixture): PatchSpec {
  return {
    callId: "call-update-tracked",
    absolutePath: path.join(fixture.lostSource, "tracked.txt"),
    unifiedDiff: "@@ -1 +1 @@\n-base\n+recovered from rollout\n",
  };
}

function createShellAudit(
  fixture: Fixture,
  options: {
    omitLast?: boolean;
    reverse?: boolean;
    invalidDisposition?: string;
    outsideWrongDisposition?: boolean;
  } = {}
): { file: string } {
  const rawLines = readFileSync(fixture.rolloutFile, "utf8").trimEnd().split("\n");
  const records = rawLines.map((line) => JSON.parse(line) as {
    type: string;
    payload: {
      type: string;
      name?: string;
      call_id?: string;
    };
  });
  const calls = records.flatMap((record, index) => {
    const regularShell = (
      record.type !== "response_item"
      || record.payload.type !== "function_call"
      || ![
        "exec_command",
        "read_thread_terminal",
        "send_message_to_thread",
        "update_plan",
        "write_stdin",
      ].includes(record.payload.name ?? "")
    ) ? false : true;
    const unpairedOutsidePatch = (
      record.type === "response_item"
      && record.payload.type === "custom_tool_call"
      && record.payload.name === "apply_patch"
      && record.payload.call_id
      && !records.some((candidate) =>
        candidate.type === "event_msg"
        && candidate.payload.type === "patch_apply_end"
        && candidate.payload.call_id === record.payload.call_id
      )
    );
    if ((!regularShell && !unpairedOutsidePatch) || !record.payload.call_id) return [];
    const resultIndex = records.findIndex((candidate) =>
      candidate.type === "response_item"
      && candidate.payload.type === (
        unpairedOutsidePatch ? "custom_tool_call_output" : "function_call_output"
      )
      && candidate.payload.call_id === record.payload.call_id
    );
    if (resultIndex < 0) throw new Error(`missing result ${record.payload.call_id}`);
    return [{
      call_id: record.payload.call_id,
      name: record.payload.name,
      line: index + 1,
      record_sha256: sha256(rawLines[index]),
      result_line: resultIndex + 1,
      result_record_sha256: sha256(rawLines[resultIndex]),
      disposition: unpairedOutsidePatch ? "IGNORED_PATH_ONLY" : "TEST_NO_UPDATE",
    }];
  });
  if (options.omitLast) calls.pop();
  if (options.reverse) calls.reverse();
  if (options.invalidDisposition && calls[0]) {
    calls[0].disposition = options.invalidDisposition;
  }
  if (options.outsideWrongDisposition) {
    const outside = calls.find((call) => call.name === "apply_patch");
    if (!outside) throw new Error("outside apply_patch call missing");
    outside.disposition = "TEST_NO_UPDATE";
  }
  const dispositionsFile = path.join(fixture.sandbox, "shell-dispositions.json");
  writeFileSync(dispositionsFile, `${JSON.stringify({
    asserted_untracked_empty: true,
    calls: calls.map((call) => ({
      call_id: call.call_id,
      disposition: call.disposition,
    })),
  }, null, 2)}\n`);
  const audit = buildCodexShellAudit({
    goalId: "goal-codex-rollout",
    taskId: "TASK-A",
    predecessorLaunchId: "launch-lost-dev-a1",
    predecessorThreadId: "dev-lost",
    historicalWorktree: fixture.lostSource,
    predecessorHead: fixture.baseHead,
    rolloutFile: fixture.rolloutFile,
    captainThreadId: "captain-current",
    foremanThreadId: "foreman-current",
    incidentRef: "test:lost-worktree-shell-audit",
    dispositionsFile,
  });
  const file = path.join(fixture.sandbox, "shell-audit.json");
  writeFileSync(file, `${JSON.stringify(audit, null, 2)}\n`);
  return { file };
}

function exportRollout(
  fixture: Fixture,
  audit: { file: string } | null = null,
  overrides: Partial<{
    snapshotId: string;
    repositoryWorktree: string;
    predecessorThreadId: string;
  }> = {}
): RecoverySnapshot {
  return exportRecoverySnapshotFromCodexRollout(fixture.repository, {
    goalId: "goal-codex-rollout",
    taskId: "TASK-A",
    snapshotId: overrides.snapshotId ?? "snapshot-codex-operation",
    successorThreadId: "dev-successor",
    predecessorLaunchId: "launch-lost-dev-a1",
    predecessorThreadId: overrides.predecessorThreadId ?? "dev-lost",
    rolloutFile: fixture.rolloutFile,
    captainCapabilityFile: fixture.captainCapabilityFile,
    repositoryWorktree:
      overrides.repositoryWorktree ?? fixture.repository,
    ...(audit ? {
      shellAuditFile: audit.file,
      foremanCapabilityFile: fixture.foremanCapabilityFile,
    } : {}),
  });
}

function runPreparedExportChild(
  fixture: Fixture,
  audit: { file: string },
  broker: string,
  fault:
    | "GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING" =
      "GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH"
): number {
  const loadedFile = path.join(fixture.sandbox, "prepared-export-loaded.json");
  writeFileSync(loadedFile, `${JSON.stringify(fixture.loaded)}\n`);
  const options = {
    goalId: "goal-codex-rollout",
    taskId: "TASK-A",
    snapshotId: "snapshot-codex-operation",
    successorThreadId: "dev-successor",
    predecessorLaunchId: "launch-lost-dev-a1",
    predecessorThreadId: "dev-lost",
    rolloutFile: fixture.rolloutFile,
    captainCapabilityFile: fixture.captainCapabilityFile,
    repositoryWorktree: broker,
    shellAuditFile: audit.file,
    foremanCapabilityFile: fixture.foremanCapabilityFile,
  };
  const program = [
    `const goal = require(${JSON.stringify(
      path.resolve("scripts/goal-control/goal.js")
    )});`,
    `goal.loadGoalStateUnlocked = () => JSON.parse(require("fs").readFileSync(${JSON.stringify(
      loadedFile
    )}, "utf8"));`,
    `require(${JSON.stringify(
      path.resolve("scripts/goal-control/source-handoff.js")
    )}).exportRecoverySnapshotFromCodexRollout(${JSON.stringify(
      fixture.repository
    )}, ${JSON.stringify(options)});`,
  ].join("\n");
  try {
    execFileSync(process.execPath, ["-e", program], {
      cwd: fixture.repository,
      env: {
        ...process.env,
        GOAL_CONTROL_TEST_MODE: "1",
        GOAL_CONTROL_DIR: fixture.controlDir,
        [fault]: "exit",
      },
      stdio: "pipe",
    });
    throw new Error("expected abrupt child exit");
  } catch (error: unknown) {
    const failure = error as {
      status?: number;
      stderr?: string | Buffer;
      stdout?: string | Buffer;
    };
    const expectedStatus =
      fault === "GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH" ? 85 : 91;
    if (failure.status !== expectedStatus) {
      throw new Error(
        `prepared export child failed: ${String(
          failure.stderr || failure.stdout || failure.status
        )}`
      );
    }
    return Number(failure.status);
  }
}

function expectControlCode(operation: () => unknown, code: string): void {
  try {
    operation();
    throw new Error(`expected ${code}`);
  } catch (error: unknown) {
    const actual = error as { code?: string; message?: string };
    if (actual.code !== code) {
      throw new Error(
        `expected ${code}, received ${String(actual.code)}: ${String(
          actual.message
        )}`
      );
    }
  }
}

describe("Codex rollout recovery broker", () => {
  let fixture: Fixture;

  beforeEach(() => {
    fixture = makeFixture();
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    process.env.GOAL_CONTROL_DIR = fixture.controlDir;
    goalModule.loadGoalStateUnlocked = () => fixture.loaded;
  });

  afterEach(() => {
    delete process.env.GOAL_CONTROL_TEST_MODE;
    delete process.env.GOAL_CONTROL_DIR;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PUBLISH;
    delete process.env.GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING;
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  afterAll(() => {
    goalModule.loadGoalStateUnlocked = originalLoadGoalStateUnlocked;
  });

  it("exports every successful patch event after the historical worktree disappears and imports it at the exact launch HEAD", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    const rolloutBody = readFileSync(fixture.rolloutFile);
    const snapshot = exportRollout(fixture);

    expect(snapshot.source_worktree).toBe(fixture.lostSource);
    expect(snapshot.source_capture).toMatchObject({
      session_id: "dev-lost",
      event_count: 1,
      rollout_file_sha256: sha256(rolloutBody),
    });
    expect(snapshot.source_capture.events[0]).toMatchObject({
      call_id: "call-update-tracked",
      call_record_sha256: expect.stringMatching(/^sha256:/),
      event_record_sha256: expect.stringMatching(/^sha256:/),
      result_record_sha256: expect.stringMatching(/^sha256:/),
    });

    const receipt = importRecoverySnapshot(fixture.destination, {
      goalId: "goal-codex-rollout",
      taskId: "TASK-A",
      importId: "import-codex-operation",
      snapshotId: snapshot.snapshot_id,
      successorThreadId: "dev-successor",
      actorCapabilityFile: fixture.devCapabilityFile,
    });
    expect(receipt).toMatchObject({
      snapshot_id: snapshot.snapshot_id,
      destination_worktree: realpathSync(fixture.destination),
    });
    expect(receipt.materialized_patch_bytes).toBeGreaterThan(0);
    expect(readFileSync(path.join(fixture.destination, "tracked.txt"), "utf8")).toBe(
      "recovered from rollout\n"
    );
    expect(git(fixture.destination, "diff", "--cached", "--name-only")).toBe(
      "tracked.txt"
    );
  });

  it("replays an audited Codex export after response loss without rereading a changed rollout or vanished broker worktree", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    appendRolloutRecords(fixture, [{
      timestamp: "2026-07-23T00:00:09.000Z",
      type: "response_item",
      payload: {
        type: "function_call",
        name: "exec_command",
        call_id: "call-read-only-pwd",
        arguments: JSON.stringify({
          cmd: "pwd",
          workdir: fixture.lostSource,
          shell: "/bin/zsh",
          login: false,
        }),
      },
    }, {
      timestamp: "2026-07-23T00:00:09.100Z",
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-read-only-pwd",
        output: `${fixture.lostSource}\n`,
      },
    }]);
    const audit = createShellAudit(fixture);
    const broker = path.join(fixture.sandbox, "codex-export-broker");
    git(
      fixture.repository,
      "worktree",
      "add",
      "-q",
      "-b",
      "task/codex-export-broker",
      broker,
      fixture.baseHead
    );
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PUBLISH = "1";
    expectControlCode(
      () => exportRollout(fixture, audit, { repositoryWorktree: broker }),
      "TEST_FAULT_AFTER_SNAPSHOT_PUBLISH"
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PUBLISH;

    writeFileSync(fixture.rolloutFile, "{\"changed\":\"after publish\"}\n");
    const task = fixture.loaded.snapshot.tasks["TASK-A"];
    task.sessions.CAPTAIN.status = "terminal";
    task.sessions.FOREMAN.status = "terminal";
    git(fixture.repository, "worktree", "remove", "--force", broker);

    const retried = exportRollout(fixture, audit, {
      repositoryWorktree: broker,
    });
    expect(retried).toMatchObject({
      snapshot_id: "snapshot-codex-operation",
      idempotent: true,
      acceptance_authority: {
        captain: {
          thread_id: "captain-current",
          attempt: 1,
        },
        foreman: {
          thread_id: "foreman-current",
          attempt: 1,
        },
      },
    });

    expectControlCode(
      () =>
        exportRollout(fixture, audit, {
          repositoryWorktree: broker,
          predecessorThreadId: "dev-other",
        }),
      "HANDOFF_OPERATION_CONFLICT"
    );
    task.sessions.CAPTAIN.status = "active";
    task.sessions.FOREMAN.status = "active";
    expectControlCode(
      () =>
        exportRollout(fixture, audit, {
          snapshotId: "snapshot-codex-other-operation",
          repositoryWorktree: broker,
        }),
      "HANDOFF_PATH_INVALID"
    );
  });

  it("discards unsealed Codex staging before rebuilding the exact export", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    appendRolloutRecords(fixture, [{
      timestamp: "2026-07-23T00:00:09.000Z",
      type: "response_item",
      payload: {
        type: "function_call",
        name: "exec_command",
        call_id: "call-partial-read-only-pwd",
        arguments: JSON.stringify({
          cmd: "pwd",
          workdir: fixture.lostSource,
          shell: "/bin/zsh",
          login: false,
        }),
      },
    }, {
      timestamp: "2026-07-23T00:00:09.100Z",
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-partial-read-only-pwd",
        output: `${fixture.lostSource}\n`,
      },
    }]);
    const audit = createShellAudit(fixture);
    const broker = path.join(fixture.sandbox, "codex-partial-broker");
    git(
      fixture.repository,
      "worktree",
      "add",
      "-q",
      "-b",
      "task/codex-partial-broker",
      broker,
      fixture.baseHead
    );

    expect(
      runPreparedExportChild(
        fixture,
        audit,
        broker,
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING"
      )
    ).toBe(91);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-codex-rollout",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const staging = readdirSync(snapshotsDir).filter((name) =>
      name.startsWith(".init-source-")
    );
    expect(staging).toHaveLength(1);
    const stagingDirectory = path.join(snapshotsDir, staging[0]);
    expect(readdirSync(stagingDirectory).sort()).toEqual([
      "operation-binding.json",
      "tracked.patch",
    ]);
    const bindingBefore = readFileSync(
      path.join(stagingDirectory, "operation-binding.json")
    );
    const patchBefore = readFileSync(
      path.join(stagingDirectory, "tracked.patch")
    );

    expectControlCode(
      () =>
        exportRecoverySnapshot(fixture.repository, {
          goalId: "goal-codex-rollout",
          taskId: "TASK-A",
          snapshotId: "snapshot-codex-operation",
          successorThreadId: "dev-successor",
          captainCapabilityFile: fixture.captainCapabilityFile,
          repositoryWorktree: broker,
        }),
      "HANDOFF_OPERATION_CONFLICT"
    );
    expectControlCode(
      () =>
        exportRollout(fixture, audit, {
          repositoryWorktree: broker,
          predecessorThreadId: "dev-other",
        }),
      "HANDOFF_OPERATION_CONFLICT"
    );
    expect(readFileSync(
      path.join(stagingDirectory, "operation-binding.json")
    )).toEqual(bindingBefore);
    expect(readFileSync(path.join(stagingDirectory, "tracked.patch"))).toEqual(
      patchBefore
    );

    const recovered = exportRollout(fixture, audit, {
      repositoryWorktree: broker,
    });

    expect(recovered).toMatchObject({
      snapshot_id: "snapshot-codex-operation",
      idempotent: false,
    });
    expect(existsSync(recovered.snapshot_file)).toBe(true);
    expect(
      readdirSync(snapshotsDir).some((name) =>
        name.startsWith(".init-source-")
      )
    ).toBe(false);
  });

  it("promotes sealed Codex staging after process exit without rereading vanished inputs or live authorities", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    appendRolloutRecords(fixture, [{
      timestamp: "2026-07-23T00:00:09.000Z",
      type: "response_item",
      payload: {
        type: "function_call",
        name: "exec_command",
        call_id: "call-prepared-read-only-pwd",
        arguments: JSON.stringify({
          cmd: "pwd",
          workdir: fixture.lostSource,
          shell: "/bin/zsh",
          login: false,
        }),
      },
    }, {
      timestamp: "2026-07-23T00:00:09.100Z",
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-prepared-read-only-pwd",
        output: `${fixture.lostSource}\n`,
      },
    }]);
    const audit = createShellAudit(fixture);
    const broker = path.join(fixture.sandbox, "codex-prepared-broker");
    git(
      fixture.repository,
      "worktree",
      "add",
      "-q",
      "-b",
      "task/codex-prepared-broker",
      broker,
      fixture.baseHead
    );

    expect(runPreparedExportChild(fixture, audit, broker)).toBe(85);

    writeFileSync(fixture.rolloutFile, "{\"changed\":\"after staging\"}\n");
    rmSync(audit.file);
    git(fixture.repository, "worktree", "remove", "--force", broker);
    const task = fixture.loaded.snapshot.tasks["TASK-A"];
    const history = task.session_history as Record<string, unknown[]>;
    history.CAPTAIN = [{
      ...task.sessions.CAPTAIN,
      status: "terminal",
    }];
    history.FOREMAN = [{
      ...task.sessions.FOREMAN,
      status: "terminal",
    }];
    delete (task.sessions as Partial<typeof task.sessions>).CAPTAIN;
    delete (task.sessions as Partial<typeof task.sessions>).FOREMAN;

    const recovered = exportRollout(fixture, audit, {
      repositoryWorktree: broker,
    });

    expect(recovered).toMatchObject({
      snapshot_id: "snapshot-codex-operation",
      idempotent: true,
      acceptance_authority: {
        captain: { thread_id: "captain-current", attempt: 1 },
        foreman: { thread_id: "foreman-current", attempt: 1 },
      },
    });
    expect(existsSync(recovered.snapshot_file)).toBe(true);
  });

  it("uses a promoted recovered predecessor launch checkpoint instead of its older registration HEAD", () => {
    configurePromotedPredecessor(fixture);
    writeRollout(fixture, [defaultPatch(fixture)]);

    const snapshot = exportRollout(fixture);

    expect(fixture.registeredHead).not.toBe(fixture.baseHead);
    expect(snapshot.source_launch_head).toBe(fixture.baseHead);
    expect(snapshot.tracked_patch.sha256).toMatch(/^sha256:/);
  });

  it("rejects target patches that predate a recovered predecessor promotion", () => {
    configurePromotedPredecessor(fixture, "2026-07-23T00:00:02.000Z");
    writeRollout(fixture, [defaultPatch(fixture)]);

    expectControlCode(
      () => exportRollout(fixture),
      "CODEX_ROLLOUT_PRE_PROMOTION_PATCH"
    );
  });

  it("rejects drift in the canonical launch sealed by predecessor promotion", () => {
    configurePromotedPredecessor(fixture);
    writeRollout(fixture, [defaultPatch(fixture)]);
    const launchFile = path.join(
      fixture.controlDir,
      "goals",
      "goal-codex-rollout",
      "launches",
      "TASK-A",
      "launch-lost-dev-a1.json"
    );
    const launch = JSON.parse(readFileSync(launchFile, "utf8")) as {
      created_at: string;
    };
    launch.created_at = "2026-07-23T00:00:01.000Z";
    writeFileSync(launchFile, `${JSON.stringify(launch, null, 2)}\n`);

    expectControlCode(
      () => exportRollout(fixture),
      "RECOVERY_HANDOFF_MISMATCH"
    );
  });

  it("replays an old receipt after its disposable destination worktree is gone", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    const snapshot = exportRollout(fixture);
    importRecoverySnapshot(fixture.destination, {
      goalId: "goal-codex-rollout",
      taskId: "TASK-A",
      importId: "import-codex-operation",
      snapshotId: snapshot.snapshot_id,
      successorThreadId: "dev-successor",
      actorCapabilityFile: fixture.devCapabilityFile,
    });
    git(fixture.repository, "worktree", "remove", "--force", fixture.destination);
    const replacement = path.join(fixture.sandbox, "replacement-destination");
    git(
      fixture.repository,
      "worktree",
      "add",
      "-q",
      "-b",
      "task/replacement-destination",
      replacement,
      fixture.baseHead
    );

    expectControlCode(
      () => importRecoverySnapshot(replacement, {
        goalId: "goal-codex-rollout",
        taskId: "TASK-A",
        importId: "import-codex-operation",
        snapshotId: snapshot.snapshot_id,
        successorThreadId: "dev-successor",
        actorCapabilityFile: fixture.devCapabilityFile,
      }),
      "HANDOFF_SNAPSHOT_ALREADY_IMPORTED"
    );
    expect(git(replacement, "status", "--porcelain=v1")).toBe("");
  });

  it("rejects provenance tampering before mutating destination", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    const snapshot = exportRollout(fixture);
    appendFileSync(
      path.join(path.dirname(snapshot.snapshot_file), snapshot.source_capture.artifact),
      "{}\n"
    );

    expectControlCode(
      () => importRecoverySnapshot(fixture.destination, {
        goalId: "goal-codex-rollout",
        taskId: "TASK-A",
        importId: "import-codex-operation",
        snapshotId: snapshot.snapshot_id,
        successorThreadId: "dev-successor",
        actorCapabilityFile: fixture.devCapabilityFile,
      }),
      "HANDOFF_ARTIFACT_TAMPERED"
    );
    expect(git(fixture.destination, "status", "--porcelain=v1")).toBe("");
  });

  it("rejects a patch event whose mutation differs from its successful apply_patch call", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    const records = readFileSync(fixture.rolloutFile, "utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as {
        type: string;
        payload?: {
          type?: string;
          changes?: Record<string, { unified_diff: string }>;
        };
      });
    const patchEvent = records.find((record) =>
      record.type === "event_msg"
      && record.payload?.type === "patch_apply_end"
    );
    const change = patchEvent?.payload?.changes?.[
      path.join(fixture.lostSource, "tracked.txt")
    ];
    if (!change) throw new Error("patch event change missing");
    change.unified_diff = change.unified_diff.replace(
      "+recovered from rollout",
      "+forged event mutation"
    );
    writeFileSync(
      fixture.rolloutFile,
      `${records.map((record) => JSON.stringify(record)).join("\n")}\n`
    );

    expectControlCode(
      () => exportRollout(fixture),
      "CODEX_ROLLOUT_PATCH_EVENT_MISMATCH"
    );
  });

  it("rejects an event that keeps mutation lines but retargets their hunk context", () => {
    writeRollout(fixture, [{
      callId: "call-context-bound",
      absolutePath: path.join(fixture.lostSource, "duplicates.txt"),
      unifiedDiff: [
        "@@ -1,3 +1,3 @@",
        " function a() {",
        "-  return 1;",
        "+  return 2;",
        " }",
        "",
      ].join("\n"),
    }]);
    const records = readFileSync(fixture.rolloutFile, "utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as {
        type: string;
        payload?: {
          type?: string;
          changes?: Record<string, { unified_diff: string }>;
        };
      });
    const patchEvent = records.find((record) =>
      record.type === "event_msg"
      && record.payload?.type === "patch_apply_end"
    );
    const change = patchEvent?.payload?.changes?.[
      path.join(fixture.lostSource, "duplicates.txt")
    ];
    if (!change) throw new Error("context-bound patch event missing");
    change.unified_diff = [
      "@@ -4,3 +4,3 @@",
      " function b() {",
      "-  return 1;",
      "+  return 2;",
      " }",
      "",
    ].join("\n");
    writeFileSync(
      fixture.rolloutFile,
      `${records.map((record) => JSON.stringify(record)).join("\n")}\n`
    );

    expectControlCode(
      () => exportRollout(fixture),
      "CODEX_ROLLOUT_PATCH_EVENT_MISMATCH"
    );
  });

  it("resolves apply_patch selector blocks against the launch HEAD before trusting numeric event hunks", () => {
    writeRollout(fixture, [{
      callId: "call-selector-bound",
      absolutePath: path.join(fixture.lostSource, "duplicates.txt"),
      unifiedDiff: [
        "@@ -4,3 +4,3 @@",
        " function b() {",
        "-  return 1;",
        "+  return 2;",
        " }",
        "",
      ].join("\n"),
    }]);
    const records = readFileSync(fixture.rolloutFile, "utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as {
        type: string;
        payload?: {
          type?: string;
          input?: string;
        };
      });
    const patchCall = records.find((record) =>
      record.type === "response_item"
      && record.payload?.type === "custom_tool_call"
    );
    if (!patchCall?.payload) throw new Error("selector patch call missing");
    patchCall.payload.input = [
      "*** Begin Patch",
      `*** Update File: ${path.join(fixture.lostSource, "duplicates.txt")}`,
      "@@ function b() {",
      "-  return 1;",
      "+  return 2;",
      " }",
      "*** End Patch",
      "",
    ].join("\n");
    writeFileSync(
      fixture.rolloutFile,
      `${records.map((record) => JSON.stringify(record)).join("\n")}\n`
    );

    const snapshot = exportRollout(fixture);
    expect(snapshot.expected_paths).toEqual(["duplicates.txt"]);
  });

  it("rejects a forged event that contradicts a nonempty apply_patch section selector", () => {
    writeRollout(fixture, [{
      callId: "call-selector-forged",
      absolutePath: path.join(fixture.lostSource, "duplicates.txt"),
      unifiedDiff: [
        "@@ -1,3 +1,3 @@",
        " function a() {",
        "-  return 1;",
        "+  return 2;",
        " }",
        "",
      ].join("\n"),
    }]);
    const records = readFileSync(fixture.rolloutFile, "utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as {
        type: string;
        payload?: {
          type?: string;
          input?: string;
        };
      });
    const patchCall = records.find((record) =>
      record.type === "response_item"
      && record.payload?.type === "custom_tool_call"
    );
    if (!patchCall?.payload) throw new Error("selector patch call missing");
    patchCall.payload.input = [
      "*** Begin Patch",
      `*** Update File: ${path.join(fixture.lostSource, "duplicates.txt")}`,
      "@@ function b() {",
      "-  return 1;",
      "+  return 2;",
      " }",
      "*** End Patch",
      "",
    ].join("\n");
    writeFileSync(
      fixture.rolloutFile,
      `${records.map((record) => JSON.stringify(record)).join("\n")}\n`
    );

    expectControlCode(
      () => exportRollout(fixture),
      "CODEX_ROLLOUT_PATCH_EVENT_MISMATCH"
    );
  });

  it.each([
    ["call", "CODEX_ROLLOUT_PATCH_EVENT_MISMATCH"],
    ["result", "CODEX_ROLLOUT_PATCH_RESULT_INVALID"],
  ] as const)(
    "independently rejects semantically tampered sealed %s records after hashes are recomputed",
    (kind, expectedCode) => {
      writeRollout(fixture, [defaultPatch(fixture)]);
      const snapshot = exportRollout(fixture);
      resealProvenance(snapshot, (records) => {
        if (kind === "call") {
          const input = records[1].payload.input;
          if (!input) throw new Error("sealed apply_patch call input missing");
          records[1].payload.input = input.replace(
            path.join(fixture.lostSource, "tracked.txt"),
            path.join(fixture.lostSource, "other.txt")
          );
        } else {
          records[3].payload.output = "Exit code: 1\nOutput:\nFailed.\n";
        }
      });

      expectControlCode(
        () => importRecoverySnapshot(fixture.destination, {
          goalId: "goal-codex-rollout",
          taskId: "TASK-A",
          importId: "import-codex-operation",
          snapshotId: snapshot.snapshot_id,
          successorThreadId: "dev-successor",
          actorCapabilityFile: fixture.devCapabilityFile,
        }),
        expectedCode
      );
      expect(git(fixture.destination, "status", "--porcelain=v1")).toBe("");
    }
  );

  it("rejects a successful apply_patch call when its patch_apply_end was omitted", () => {
    writeRollout(fixture, [
      defaultPatch(fixture),
      {
        callId: "call-omitted-event",
        absolutePath: path.join(fixture.lostSource, "tracked.txt"),
        unifiedDiff: "@@ -1 +1 @@\n-base\n+omitted\n",
        includeEvent: false,
      },
    ]);
    expectControlCode(
      () => exportRollout(fixture),
      "CODEX_ROLLOUT_PATCH_EVENT_MISSING"
    );
  });

  it("pairs but excludes a pure outside-worktree patch event", () => {
    writeRollout(fixture, [
      defaultPatch(fixture),
      {
        callId: "call-outside-patch",
        absolutePath: path.join(fixture.sandbox, "outside.txt"),
        unifiedDiff: "@@ -1 +1 @@\n-old\n+outside\n",
      },
    ]);

    const snapshot = exportRollout(fixture);
    expect(snapshot.source_capture.event_count).toBe(1);
    expect(snapshot.source_capture.excluded_patch_count).toBe(1);
    expect(snapshot.source_capture.events.map((event) => event.call_id)).toEqual([
      "call-update-tracked",
    ]);
  });

  it("never silently drops an aborted outside-worktree apply_patch", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    appendRolloutRecords(fixture, [{
      timestamp: "2026-07-23T00:00:08.000Z",
      type: "response_item",
      payload: {
        type: "custom_tool_call",
        status: "completed",
        call_id: "call-outside-aborted",
        name: "apply_patch",
        input: [
          "*** Begin Patch",
          `*** Add File: ${path.join(fixture.sandbox, "outside-aborted.txt")}`,
          "+outside",
          "*** End Patch",
          "",
        ].join("\n"),
      },
    }, {
      timestamp: "2026-07-23T00:00:08.100Z",
      type: "response_item",
      payload: {
        type: "custom_tool_call_output",
        call_id: "call-outside-aborted",
        output: "aborted by user after 745.7s",
      },
    }]);

    expectControlCode(
      () => exportRollout(fixture),
      "CODEX_ROLLOUT_SHELL_UNVERIFIED"
    );
    const inspected = inspectCodexRolloutPatchEvents(fixture.rolloutFile, {
      historicalWorktree: fixture.lostSource,
      predecessorThreadId: "dev-lost",
      allowShellAudit: true,
    });
    expect(inspected.shell_call_count).toBe(1);
    expect(inspected.shell_calls).toEqual([
      expect.objectContaining({
        call_id: "call-outside-aborted",
        name: "apply_patch",
        required_disposition: "IGNORED_PATH_ONLY",
      }),
    ]);
    expectControlCode(
      () => createShellAudit(fixture, { outsideWrongDisposition: true }),
      "CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH"
    );

    const snapshot = exportRollout(fixture, createShellAudit(fixture));
    expect(snapshot.source_capture.shell_audit?.call_count).toBe(1);
  });

  it("rejects a change path that escapes the historical predecessor worktree", () => {
    writeRollout(fixture, [{
      ...defaultPatch(fixture),
      absolutePath: `${fixture.lostSource}/../escape.ts`,
    }]);
    expectControlCode(() => exportRollout(fixture), "HANDOFF_PATH_INVALID");
  });

  it("requires exact dual-authorized broker audit for unverified shell calls", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    appendRolloutRecords(fixture, [{
      timestamp: "2026-07-23T00:00:09.000Z",
      type: "response_item",
      payload: {
        type: "function_call",
        name: "exec_command",
        call_id: "call-shell-write",
        arguments: JSON.stringify({
          cmd: "sed -i.bak 's/base/tampered/' tracked.txt",
          workdir: fixture.lostSource,
          shell: "/bin/zsh",
          login: false,
        }),
      },
    }, {
      timestamp: "2026-07-23T00:00:09.100Z",
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-shell-write",
        output: "Process exited with code 0\n",
      },
    }]);

    expectControlCode(
      () => exportRollout(fixture),
      "CODEX_ROLLOUT_SHELL_UNVERIFIED"
    );
    expectControlCode(
      () => exportRollout(fixture, createShellAudit(fixture, { omitLast: true })),
      "CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH"
    );
    expectControlCode(
      () => createShellAudit(fixture, { invalidDisposition: "TRUST_ME" }),
      "CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH"
    );

    const snapshot = exportRollout(fixture, createShellAudit(fixture));
    expect(snapshot.source_capture.shell_audit).toMatchObject({
      call_count: 1,
      incident_ref: "test:lost-worktree-shell-audit",
    });
    const receipt = importRecoverySnapshot(fixture.destination, {
      goalId: "goal-codex-rollout",
      taskId: "TASK-A",
      importId: "import-codex-operation",
      snapshotId: snapshot.snapshot_id,
      successorThreadId: "dev-successor",
      actorCapabilityFile: fixture.devCapabilityFile,
    });
    expect(receipt.materialized_patch_bytes).toBeGreaterThan(0);
  });

  it("accepts an identical live Goal-wide FOREMAN replica when the task-local projection is terminal", () => {
    const task = fixture.loaded.snapshot.tasks["TASK-A"];
    const replica = JSON.parse(JSON.stringify(task)) as typeof task;
    task.sessions.FOREMAN.status = "terminal";
    task.sessions.FOREMAN.lease_until = "2020-01-01T00:00:00.000Z";
    replica.task_id = "TASK-B";
    replica.sessions.FOREMAN.status = "active";
    replica.sessions.FOREMAN.lease_until = "2099-01-01T00:00:00.000Z";
    fixture.loaded.snapshot.tasks["TASK-B"] = replica;
    writeRollout(fixture, [defaultPatch(fixture)]);
    appendRolloutRecords(fixture, [{
      timestamp: "2026-07-23T00:00:09.000Z",
      type: "response_item",
      payload: {
        type: "function_call",
        name: "exec_command",
        call_id: "call-goal-wide-foreman",
        arguments: JSON.stringify({
          cmd: "pwd",
          workdir: fixture.lostSource,
          shell: "/bin/zsh",
          login: false,
        }),
      },
    }, {
      timestamp: "2026-07-23T00:00:09.100Z",
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-goal-wide-foreman",
        output: `${fixture.lostSource}\n`,
      },
    }]);

    const snapshot = exportRollout(fixture, createShellAudit(fixture));
    expect(snapshot.acceptance_authority.foreman).toMatchObject({
      thread_id: "foreman-current",
      attempt: 1,
    });
  });

  it("rejects divergent max-attempt Goal-wide FOREMAN replicas for audited export", () => {
    const task = fixture.loaded.snapshot.tasks["TASK-A"];
    const left = JSON.parse(JSON.stringify(task)) as typeof task;
    const right = JSON.parse(JSON.stringify(task)) as typeof task;
    left.task_id = "TASK-B";
    left.sessions.FOREMAN.attempt = 2;
    left.sessions.FOREMAN.thread_id = "foreman-attempt-2-left";
    right.task_id = "TASK-C";
    right.sessions.FOREMAN.attempt = 2;
    right.sessions.FOREMAN.thread_id = "foreman-attempt-2-right";
    fixture.loaded.snapshot.tasks["TASK-B"] = left;
    fixture.loaded.snapshot.tasks["TASK-C"] = right;
    writeRollout(fixture, [defaultPatch(fixture)]);
    appendRolloutRecords(fixture, [{
      timestamp: "2026-07-23T00:00:09.000Z",
      type: "response_item",
      payload: {
        type: "function_call",
        name: "exec_command",
        call_id: "call-diverged-foreman",
        arguments: JSON.stringify({
          cmd: "pwd",
          workdir: fixture.lostSource,
          shell: "/bin/zsh",
          login: false,
        }),
      },
    }, {
      timestamp: "2026-07-23T00:00:09.100Z",
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-diverged-foreman",
        output: `${fixture.lostSource}\n`,
      },
    }]);

    expectControlCode(
      () => exportRollout(fixture, createShellAudit(fixture)),
      "GOAL_FOREMAN_LINEAGE_DIVERGED"
    );
  });

  it("rejects write_stdin chains even when the initial target command is read-only", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    appendRolloutRecords(fixture, [{
      timestamp: "2026-07-23T00:00:09.000Z",
      type: "response_item",
      payload: {
        type: "function_call",
        name: "exec_command",
        call_id: "call-shell-session",
        arguments: JSON.stringify({
          cmd: "pwd",
          workdir: fixture.lostSource,
          shell: "/bin/zsh",
          login: false,
        }),
      },
    }, {
      timestamp: "2026-07-23T00:00:09.100Z",
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-shell-session",
        output: "Process running with session ID 4242\n",
      },
    }, {
      timestamp: "2026-07-23T00:00:09.200Z",
      type: "response_item",
      payload: {
        type: "function_call",
        name: "write_stdin",
        call_id: "call-shell-poll",
        arguments: JSON.stringify({
          session_id: 4242,
          chars: "",
        }),
      },
    }, {
      timestamp: "2026-07-23T00:00:09.300Z",
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-shell-poll",
        output: "Process exited with code 0\n",
      },
    }]);

    expectControlCode(
      () => exportRollout(fixture),
      "CODEX_ROLLOUT_SHELL_UNVERIFIED"
    );
    expectControlCode(
      () => createShellAudit(fixture, { reverse: true }),
      "CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH"
    );
  });

  it("includes cross-session sends in the exact jointly authorized tool-call set", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    appendRolloutRecords(fixture, [{
      timestamp: "2026-07-23T00:00:09.000Z",
      type: "response_item",
      payload: {
        type: "function_call",
        name: "send_message_to_thread",
        call_id: "call-send-captain",
        arguments: JSON.stringify({
          threadId: "captain-current",
          prompt: "[ROLE_BLOCKED] event_id=blocked-1",
        }),
      },
    }, {
      timestamp: "2026-07-23T00:00:09.100Z",
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-send-captain",
        output: "{\"queued\":true}",
      },
    }]);

    expectControlCode(
      () => exportRollout(fixture),
      "CODEX_ROLLOUT_SHELL_UNVERIFIED"
    );
    const inspected = inspectCodexRolloutPatchEvents(fixture.rolloutFile, {
      historicalWorktree: fixture.lostSource,
      predecessorThreadId: "dev-lost",
      allowShellAudit: true,
    });
    expect(inspected.shell_calls).toEqual([
      expect.objectContaining({
        call_id: "call-send-captain",
        name: "send_message_to_thread",
      }),
    ]);

    const snapshot = exportRollout(fixture, createShellAudit(fixture));
    expect(snapshot.source_capture.shell_audit).toMatchObject({ call_count: 1 });
  });

  it.each([
    ["function_call", "filesystem_write"],
    ["custom_tool_call", "workspace_mutate"],
  ] as const)(
    "rejects an unmodelled %s %s even when a joint shell audit was requested",
    (callType, name) => {
      writeRollout(fixture, [defaultPatch(fixture)]);
      appendRolloutRecords(fixture, [{
        timestamp: "2026-07-23T00:00:09.000Z",
        type: "response_item",
        payload: {
          type: callType,
          status: callType === "custom_tool_call" ? "completed" : undefined,
          name,
          call_id: `call-${name}`,
          ...(callType === "function_call"
            ? { arguments: JSON.stringify({ path: fixture.lostSource }) }
            : { input: fixture.lostSource }),
        },
      }, {
        timestamp: "2026-07-23T00:00:09.100Z",
        type: "response_item",
        payload: {
          type: callType === "function_call"
            ? "function_call_output"
            : "custom_tool_call_output",
          call_id: `call-${name}`,
          output: "ok",
        },
      }]);

      expectControlCode(
        () => inspectCodexRolloutPatchEvents(fixture.rolloutFile, {
          historicalWorktree: fixture.lostSource,
          predecessorThreadId: "dev-lost",
          allowShellAudit: true,
        }),
        "CODEX_ROLLOUT_TOOL_UNVERIFIED"
      );
    }
  );

  it.each(["shell", "add", "delete", "unknown"])(
    "rejects non-replayable %s changes fail-closed",
    (changeType) => {
      writeRollout(fixture, [{
        ...defaultPatch(fixture),
        changeType,
      }]);
      expectControlCode(
        () => exportRollout(fixture),
        "CODEX_ROLLOUT_CHANGE_UNSUPPORTED"
      );
    }
  );

  it("requires explicit predecessor launch and thread to match the lost lineage", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    expectControlCode(
      () => exportRecoverySnapshotFromCodexRollout(fixture.repository, {
        goalId: "goal-codex-rollout",
        taskId: "TASK-A",
        snapshotId: "snapshot-codex-operation",
        successorThreadId: "dev-successor",
        predecessorLaunchId: "launch-lost-dev-a1",
        predecessorThreadId: "different-thread",
        rolloutFile: fixture.rolloutFile,
        captainCapabilityFile: fixture.captainCapabilityFile,
        repositoryWorktree: fixture.repository,
      }),
      "RECOVERY_HANDOFF_MISMATCH"
    );
  });

  it("documents the dedicated goalctl command", () => {
    const overview = helpDocument("goal");
    const command = helpDocument("goal", "recovery-export-codex-rollout");
    expect(overview.commands?.some((entry) =>
      entry.name.startsWith("recovery-export-codex-rollout")
    )).toBe(true);
    expect(command.usage).toContain("--rollout-file");
    expect(command.usage).toContain("--snapshot-id");
    expect(command.usage).toContain("--predecessor-thread");
    expect(command.usage).toContain("--shell-audit-file");
    expect(command.usage).toContain("--foreman-capability-file");
    const builder = helpDocument("goal", "recovery-build-codex-shell-audit");
    expect(builder.usage).toContain("--dispositions-file");
    expect(builder.usage).toContain("--incident-ref");
    expect(builder.usage).toContain("--output-file <absolute-json>");
  });

  it("allows active FOREMAN and CAPTAIN heartbeat templates outside phase actions", () => {
    const stateWithoutHeartbeatAction = { phase: "DEV_ACTIVE" };
    expect(eventTemplateActionAllowed(
      stateWithoutHeartbeatAction,
      { role: "FOREMAN", status: "active" },
      "FOREMAN",
      "HEARTBEAT"
    )).toBe(true);
    expect(eventTemplateActionAllowed(
      stateWithoutHeartbeatAction,
      { role: "CAPTAIN", status: "idle" },
      "CAPTAIN",
      "HEARTBEAT"
    )).toBe(true);
    expect(eventTemplateActionAllowed(
      stateWithoutHeartbeatAction,
      { role: "FOREMAN", status: "lost" },
      "FOREMAN",
      "HEARTBEAT"
    )).toBe(false);
  });

  it("builds deterministic final audit JSON through the read-only CLI", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    const dispositionsFile = path.join(fixture.sandbox, "empty-dispositions.json");
    writeFileSync(dispositionsFile, `${JSON.stringify({
      asserted_untracked_empty: true,
      calls: [],
    })}\n`);
    const args = [
      path.resolve("scripts/goalctl.js"),
      "recovery-build-codex-shell-audit",
      "--goal", "goal-codex-rollout",
      "--task", "TASK-A",
      "--predecessor-launch", "launch-lost-dev-a1",
      "--predecessor-thread", "dev-lost",
      "--historical-worktree", fixture.lostSource,
      "--predecessor-head", fixture.baseHead,
      "--rollout-file", fixture.rolloutFile,
      "--captain-thread", "captain-current",
      "--foreman-thread", "foreman-current",
      "--incident-ref", "test:deterministic-builder",
      "--dispositions-file", dispositionsFile,
      "--json",
    ];
    const first = execFileSync(process.execPath, args, { encoding: "utf8" });
    const second = execFileSync(process.execPath, args, { encoding: "utf8" });
    expect(second).toBe(first);
    expect(JSON.parse(first)).toMatchObject({
      kind: "codex-rollout-shell-audit-v1",
      incident_ref: "test:deterministic-builder",
      asserted_untracked_empty: true,
      calls: [],
    });
  });

  it("atomically creates an explicit audit artifact and only accepts exact-byte idempotency", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    const dispositionsFile = path.join(fixture.sandbox, "output-dispositions.json");
    writeFileSync(dispositionsFile, `${JSON.stringify({
      asserted_untracked_empty: true,
      calls: [],
    })}\n`);
    const args = [
      path.resolve("scripts/goalctl.js"),
      "recovery-build-codex-shell-audit",
      "--goal", "goal-codex-rollout",
      "--task", "TASK-A",
      "--predecessor-launch", "launch-lost-dev-a1",
      "--predecessor-thread", "dev-lost",
      "--historical-worktree", fixture.lostSource,
      "--predecessor-head", fixture.baseHead,
      "--rollout-file", fixture.rolloutFile,
      "--captain-thread", "captain-current",
      "--foreman-thread", "foreman-current",
      "--incident-ref", "test:output-builder",
      "--dispositions-file", dispositionsFile,
      "--json",
    ];
    const expectedAuditBytes = execFileSync(process.execPath, args, { encoding: "utf8" });
    const outputFile = path.join(fixture.sandbox, "generated-audit.json");
    const outputArgs = [
      ...args.slice(0, -1),
      "--output-file", outputFile,
      "--json",
    ];
    const first = JSON.parse(execFileSync(process.execPath, outputArgs, { encoding: "utf8" }));
    expect(first).toEqual({
      output_file: outputFile,
      audit_sha256: JSON.parse(expectedAuditBytes).audit_sha256,
      call_count: 0,
    });
    expect(readFileSync(outputFile, "utf8")).toBe(expectedAuditBytes);
    const firstStat = statSync(outputFile);

    const second = JSON.parse(execFileSync(process.execPath, outputArgs, { encoding: "utf8" }));
    expect(second).toEqual(first);
    expect(statSync(outputFile).ino).toBe(firstStat.ino);
    expect(readdirSync(fixture.sandbox).some((entry) =>
      entry.startsWith(".generated-audit.json.")
    )).toBe(false);

    writeFileSync(outputFile, "different bytes\n");
    expect(() =>
      execFileSync(process.execPath, outputArgs, { encoding: "utf8", stdio: "pipe" })
    ).toThrow(/AUDIT_OUTPUT_CONFLICT/);
    expect(readFileSync(outputFile, "utf8")).toBe("different bytes\n");
  });

  it("rejects relative, symlinked, and directory audit output targets", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    const dispositionsFile = path.join(fixture.sandbox, "invalid-output-dispositions.json");
    writeFileSync(dispositionsFile, `${JSON.stringify({
      asserted_untracked_empty: true,
      calls: [],
    })}\n`);
    const baseArgs = [
      "recovery-build-codex-shell-audit",
      "--goal", "goal-codex-rollout",
      "--task", "TASK-A",
      "--predecessor-launch", "launch-lost-dev-a1",
      "--predecessor-thread", "dev-lost",
      "--historical-worktree", fixture.lostSource,
      "--predecessor-head", fixture.baseHead,
      "--rollout-file", fixture.rolloutFile,
      "--captain-thread", "captain-current",
      "--foreman-thread", "foreman-current",
      "--incident-ref", "test:invalid-output-builder",
      "--dispositions-file", dispositionsFile,
    ];
    const rejectOutput = (outputFile: string) => expectControlCode(
      () => goalCommand([...baseArgs, "--output-file", outputFile], fixture.repository),
      "AUDIT_OUTPUT_INVALID"
    );

    rejectOutput("relative-audit.json");
    const directoryOutput = path.join(fixture.sandbox, "audit-directory");
    mkdirSync(directoryOutput);
    rejectOutput(directoryOutput);
    const actualFile = path.join(fixture.sandbox, "actual-audit.json");
    writeFileSync(actualFile, "not an audit\n");
    const symlinkOutput = path.join(fixture.sandbox, "symlink-audit.json");
    symlinkSync(actualFile, symlinkOutput);
    rejectOutput(symlinkOutput);
    const actualParent = path.join(fixture.sandbox, "actual-parent");
    mkdirSync(actualParent);
    const symlinkParent = path.join(fixture.sandbox, "symlink-parent");
    symlinkSync(actualParent, symlinkParent);
    rejectOutput(path.join(symlinkParent, "audit.json"));
  });

  it("dispatches the dedicated goalctl command with explicit predecessor identity", () => {
    writeRollout(fixture, [defaultPatch(fixture)]);
    const result = goalCommand([
      "recovery-export-codex-rollout",
      "--repository-worktree", fixture.repository,
      "--goal", "goal-codex-rollout",
      "--task", "TASK-A",
      "--snapshot-id", "snapshot-codex-cli-operation",
      "--successor-thread", "dev-successor",
      "--predecessor-launch", "launch-lost-dev-a1",
      "--predecessor-thread", "dev-lost",
      "--rollout-file", fixture.rolloutFile,
      "--captain-capability-file", fixture.captainCapabilityFile,
      "--json",
    ], fixture.repository);

    expect(result.exitCode).toBe(0);
    expect(result.value.source_capture).toMatchObject({
      session_id: "dev-lost",
      event_count: 1,
    });
  });
});
