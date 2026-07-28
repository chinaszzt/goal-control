import { execFileSync, spawnSync } from "child_process";
import { createHash, randomBytes } from "crypto";
import {
  appendFileSync,
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "fs";
import { createRequire } from "module";
import { tmpdir } from "os";
import path from "path";

const nodeRequire = createRequire(import.meta.url);
type GoalLoadOptions = {
  repairHeads?: boolean;
  repairBootstrapConsumption?: boolean;
  [key: string]: unknown;
};
const goalModule = nodeRequire("../scripts/goal-control/goal.js") as {
  loadGoalStateUnlocked: (
    root: string,
    goalId: string,
    options?: GoalLoadOptions
  ) => LoadedGoal;
};
const { hashObject } = nodeRequire("../scripts/goal-control/util.js") as {
  hashObject: (value: unknown) => string;
};
const {
  createLegacyEvidenceMigrationCollector,
  sealLegacyEvidenceAnchorIndex,
} = nodeRequire("../scripts/goal-control/evidence.js") as {
  createLegacyEvidenceMigrationCollector: () => {
    eventBindings: Map<string, Record<string, unknown>>;
    semanticSources: Map<string, Record<string, unknown>>;
  };
  sealLegacyEvidenceAnchorIndex: (
    entries: {
      eventBindings: Map<string, Record<string, unknown>>;
      semanticSources: Map<string, Record<string, unknown>>;
    },
    options: Record<string, unknown>
  ) => {
    migration_artifact: {
      relative_path: string;
      sha256: string;
      body: string | Buffer;
    };
    recovery_handoff_count: number;
  };
};
const {
  adoptRootProtocol,
  canonicalTransactionKey,
  withLock,
} = nodeRequire(
  "../scripts/goal-control/store.js"
) as {
  adoptRootProtocol: (
    root: string,
    validationCallback: (context: {
      state_vector_sha256: string;
      decoder_sha256: string;
    }) => {
      report: Record<string, unknown>;
      migration_artifacts: Array<{
        relative_path: string;
        sha256: string;
        body: string | Buffer;
      }>;
    }
  ) => Record<string, unknown>;
  canonicalTransactionKey: (
    kind: string,
    scope: Record<string, string>,
    stableId: string,
    requestHash: string
  ) => Record<string, unknown>;
  withLock: <T>(
    root: string,
    callback: () => T,
    options?: { transactionKey?: Record<string, unknown> }
  ) => T;
};
const { listPendingTaskOperations } = nodeRequire(
  "../scripts/goal-control/pending-operations.js"
) as {
  listPendingTaskOperations: (
    root: string,
    goalId: string,
    taskId: string
  ) => Array<{ kind: string }>;
};
const { goalCommand } = nodeRequire("../scripts/goal-control/cli.js") as {
  goalCommand: (
    argv: string[],
    cwd?: string
  ) => { value: Record<string, unknown>; exitCode: number };
};
const originalLoadGoalStateUnlocked = goalModule.loadGoalStateUnlocked;
const {
  buildRecoveryHandoffPayload,
  checkpointRecoverySource,
  exportRecoverySnapshot,
  importRecoverySnapshot,
  publicRecoveryHandoffResult,
  verifyAcceptedRecoveryHandoffArtifacts,
  verifyRecoveryHandoff,
} = nodeRequire("../scripts/goal-control/source-handoff.js") as {
  buildRecoveryHandoffPayload: (
    cwd: string,
    options: {
      goalId: string;
      taskId: string;
      successorThreadId: string;
      snapshotId: string;
      importReceiptId: string;
      importCommit: string;
      captainCapabilityFile: string;
    }
  ) => Record<string, unknown>;
  checkpointRecoverySource: (
    cwd: string,
    options: {
      goalId: string;
      taskId: string;
      successorThreadId: string;
      snapshotId: string;
      importReceiptId: string;
      actorCapabilityFile: string;
    }
  ) => RecoveryCheckpoint;
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
  ) => RecoverySnapshot & { snapshot_file: string };
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
  ) => ImportReceipt & { import_receipt_file: string };
  verifyRecoveryHandoff: (
    cwd: string,
    options: Record<string, unknown>
  ) => { verified: boolean; import_commit: string };
  publicRecoveryHandoffResult: <T>(value: T) => T;
  verifyAcceptedRecoveryHandoffArtifacts: (
    root: string,
    options: Record<string, unknown>
  ) => {
    verified: boolean;
    materialized_tree: string;
  };
};

type Session<Role extends "CAPTAIN" | "DEV"> = {
  role: Role;
  thread_id: string;
  host_id: string;
  attempt: number;
  status: "active" | "terminal";
  lease_until: string;
  capability_file: string;
  capability_sha256: string;
  operational_scope?: "RECOVERY_BLOCKED";
  recovered_from?: {
    role: "DEV";
    thread_id: string;
    host_id: string;
    attempt: number;
    predecessor_launch_id: string;
    predecessor_registered_head: string;
  };
};

type HistoricalDevSession = {
  role: "DEV";
  thread_id: string;
  host_id: string;
  attempt: number;
  status: "lost" | "terminal";
  launch_id?: string;
  task_nonce?: string;
  capability_file?: string;
  capability_sha256?: string;
};

type LoadedGoal = {
  paths: { dir: string };
  manifest: { goal_id: string };
  meta: { repository_root: string };
  control: { epoch: number };
  snapshot: {
    tasks: Record<
      string,
      {
        task_id: string;
        phase: string;
        state_revision: number;
        packet: { revision: number; path: string; sha256: string };
        full_head: string;
        sessions: {
          CAPTAIN: Session<"CAPTAIN">;
          DEV: Session<"DEV">;
        };
        session_history: {
          CAPTAIN?: Session<"CAPTAIN">[];
          DEV: HistoricalDevSession[];
        };
      }
    >;
  };
};

type RecoverySnapshot = {
  snapshot_id: string;
  snapshot_sha256: string;
  predecessor_launch_id: string;
  predecessor_launch_sha256: string;
  source_worktree: string;
  source_branch: string;
  source_launch_head: string;
  source_observed_head: string;
  expected_tree: string;
  expected_paths: string[];
  tracked_patch: { file: string };
  total_bytes: number;
  acceptance_authority: {
    captain: {
      role: "CAPTAIN";
      thread_id: string;
      host_id: string;
      attempt: number;
      capability_file: string;
      capability_sha256: string;
    };
  };
  idempotent?: boolean;
};

type ImportReceipt = {
  import_receipt_id: string;
  import_receipt_sha256: string;
  destination_worktree: string;
  destination_branch: string;
  expected_tree: string;
  materialized_tree: string;
  materialized_patch_bytes: number;
  acceptance_authority: {
    dev: {
      role: "DEV";
      thread_id: string;
      host_id: string;
      attempt: number;
      capability_file: string;
      capability_sha256: string;
    };
  };
  idempotent?: boolean;
};

type RecoveryCheckpoint = {
  checkpoint_sha: string;
  parent_sha: string;
  tree_sha: string;
  idempotent: boolean;
};

type Fixture = {
  sandbox: string;
  repository: string;
  source: string;
  destination: string;
  controlDir: string;
  baseHead: string;
  observedHead: string;
  captainCapabilityFile: string;
  devCapabilityFile: string;
  loaded: LoadedGoal;
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

function gitPath(cwd: string, name: string): string {
  return git(
    cwd,
    "rev-parse",
    "--path-format=absolute",
    "--git-path",
    name
  );
}

function writeMergeHeadSentinel(cwd: string, head: string): string {
  const file = gitPath(cwd, "MERGE_HEAD");
  writeFileSync(file, `${head}\n`);
  return file;
}

function canonicalPatch(cwd: string, base: string, target: string): Buffer {
  return execFileSync(
    "git",
    [
      "diff",
      "--binary",
      "--full-index",
      "--no-ext-diff",
      "--no-textconv",
      "--no-renames",
      "--diff-algorithm=myers",
      "--no-indent-heuristic",
      "--unified=3",
      "--src-prefix=a/",
      "--dst-prefix=b/",
      base,
      target,
      "--",
    ],
    { cwd, encoding: null, stdio: "pipe" }
  );
}

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function directorySnapshot(root: string): Array<[string, string]> {
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

function gitObjectDatabaseSnapshot(root: string): Array<[string, string]> {
  const entries: Array<[string, string]> = [];
  const visit = (absolute: string, relative: string): void => {
    const stat = lstatSync(absolute, { bigint: true });
    const identity = [
      String(stat.mode & 0o7777n),
      String(stat.size),
      String(stat.mtimeNs),
    ].join(":");
    if (stat.isDirectory()) {
      entries.push([relative || ".", `directory:${identity}`]);
      for (const name of readdirSync(absolute).sort()) {
        visit(
          path.join(absolute, name),
          relative ? `${relative}/${name}` : name
        );
      }
      return;
    }
    if (stat.isSymbolicLink()) {
      entries.push([relative, `symlink:${identity}:${readlinkSync(absolute)}`]);
      return;
    }
    entries.push([
      relative,
      `file:${identity}:${sha256(readFileSync(absolute))}`,
    ]);
  };
  visit(root, "");
  return entries;
}

function findFilesWithBasePrefix(root: string, prefix: string): string[] {
  const matches: string[] = [];
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const stat = lstatSync(absolute);
      if (stat.isDirectory()) {
        visit(absolute);
      } else if (name.startsWith(prefix)) {
        matches.push(absolute);
      }
    }
  };
  visit(root);
  return matches;
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

function installPendingBootstrapReadOnlyProbe(fixture: Fixture): {
  goalDirectory: string;
  goalFile: string;
  bootstrapFile: string;
  bootstrapBytes: Buffer;
  calls: GoalLoadOptions[];
} {
  const goalDirectory = path.join(
    fixture.controlDir,
    "goals",
    "goal-handoff"
  );
  const goalFile = path.join(goalDirectory, "goal.json");
  const bootstrap = createCapability(
    path.join(goalDirectory, "capabilities"),
    "bootstrap-pending-reconciliation"
  );
  writeFileSync(
    goalFile,
    `${JSON.stringify(
      {
        goal_id: "goal-handoff",
        bootstrap_capability_file: bootstrap.file,
        bootstrap_capability_sha256: bootstrap.verifier,
        bootstrap_consumption: "PENDING_APPEND_ONLY_RECONCILIATION",
      },
      null,
      2
    )}\n`
  );
  const bootstrapBytes = readFileSync(bootstrap.file);
  const calls: GoalLoadOptions[] = [];
  goalModule.loadGoalStateUnlocked = (
    _root: string,
    _goalId: string,
    options: GoalLoadOptions = {}
  ) => {
    calls.push({ ...options });
    if (options.repairHeads !== false) {
      writeFileSync(goalFile, '{"reconciled":true}\n');
    }
    if (
      options.repairBootstrapConsumption !== false
      && existsSync(bootstrap.file)
    ) {
      rmSync(bootstrap.file);
    }
    return fixture.loaded;
  };
  return {
    goalDirectory,
    goalFile,
    bootstrapFile: bootstrap.file,
    bootstrapBytes,
    calls,
  };
}

function makeLaunch(fixture: {
  repository: string;
  source: string;
  baseHead: string;
  observedHead: string;
}): Record<string, unknown> {
  return {
    schema_version: 1,
    launch_id: "launch-dev-a1",
    goal_id: "goal-handoff",
    task_id: "TASK-A",
    role: "DEV",
    control_epoch: 0,
    state_revision: 11,
    thread: {
      id: "dev-predecessor",
      host_id: "host-a",
      cwd: realpathSync(fixture.source),
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
      base_head: fixture.baseHead,
      full_head: fixture.baseHead,
      branch: "task/source",
      root: realpathSync(fixture.repository),
      worktree: realpathSync(fixture.source),
    },
    runtime: {
      node_version: process.version,
      pnpm_version: "10.0.0",
      lockfile_sha256: sha256("lockfileVersion: '9.0'\n"),
    },
    execution: {
      environment: "none",
      write_mode: "NONE",
      task_nonce: "handoff_test_nonce_123456",
      target: { kind: "NONE" },
    },
    resource_leases: [],
    created_at: "2026-07-23T00:00:00.000Z",
  };
}

function makeFixture(): Fixture {
  const sandbox = mkdtempSync(path.join(tmpdir(), "goal-control-source-handoff-"));
  const repository = path.join(sandbox, "repo");
  const source = path.join(sandbox, "source");
  const destination = path.join(sandbox, "destination");
  const controlDirCandidate = path.join(sandbox, "control");
  mkdirSync(repository, { recursive: true });
  mkdirSync(controlDirCandidate, { recursive: true });
  const controlDir = realpathSync(controlDirCandidate);
  withLock(controlDir, () => undefined);
  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.email", "handoff@example.test");
  git(repository, "config", "user.name", "Source Handoff Test");
  git(repository, "remote", "add", "origin", "https://github.com/example-org/example-repo.git");
  writeFileSync(path.join(repository, "tracked.txt"), "base\n");
  writeFileSync(path.join(repository, "binary.bin"), Buffer.from([0, 1, 2, 3]));
  writeFileSync(path.join(repository, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "base");
  const baseHead = git(repository, "rev-parse", "HEAD");
  git(repository, "worktree", "add", "-q", "-b", "task/source", source, baseHead);

  writeFileSync(path.join(source, "tracked.txt"), "candidate\n");
  writeFileSync(path.join(source, "binary.bin"), Buffer.from([0, 255, 2, 3, 4]));
  git(source, "add", "tracked.txt", "binary.bin");
  git(source, "commit", "-qm", "candidate checkpoint");
  const observedHead = git(source, "rev-parse", "HEAD");
  git(
    repository,
    "worktree",
    "add",
    "-q",
    "-b",
    "task/destination",
    destination,
    observedHead
  );
  writeFileSync(path.join(source, "tracked.txt"), "candidate plus dirty\n");
  writeFileSync(path.join(source, "binary.bin"), Buffer.from([9, 8, 7, 0, 255]));
  mkdirSync(path.join(source, "notes"), { recursive: true });
  writeFileSync(path.join(source, "notes", "local.txt"), "untracked recovery note\n");
  const executable = path.join(source, "recover.sh");
  writeFileSync(executable, "#!/bin/sh\nexit 0\n");
  chmodSync(executable, 0o755);
  symlinkSync("notes/local.txt", path.join(source, "note-link"));

  const capabilityDir = path.join(controlDir, "goals", "goal-handoff", "capabilities");
  const captain = createCapability(capabilityDir, "captain");
  const dev = createCapability(capabilityDir, "dev-successor");
  const launchDir = path.join(controlDir, "goals", "goal-handoff", "launches", "TASK-A");
  mkdirSync(launchDir, { recursive: true });
  writeFileSync(
    path.join(launchDir, "launch-dev-a1.json"),
    `${JSON.stringify(makeLaunch({ repository, source, baseHead, observedHead }), null, 2)}\n`
  );
  const loaded: LoadedGoal = {
    paths: { dir: path.join(controlDir, "goals", "goal-handoff") },
    manifest: { goal_id: "goal-handoff" },
    meta: { repository_root: realpathSync(repository) },
    control: { epoch: 0 },
    snapshot: {
      tasks: {
        "TASK-A": {
          task_id: "TASK-A",
          phase: "DEV_ACTIVE",
          state_revision: 11,
          packet: {
            revision: 1,
            path: "docs/packet.md",
            sha256: sha256("packet"),
          },
          full_head: baseHead,
          sessions: {
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
                thread_id: "dev-predecessor",
                host_id: "host-a",
                attempt: 1,
                predecessor_launch_id: "launch-dev-a1",
                predecessor_registered_head: baseHead,
              },
            },
          },
          session_history: {
            DEV: [
              {
                role: "DEV",
                thread_id: "dev-predecessor",
                host_id: "host-a",
                attempt: 1,
                status: "lost",
                launch_id: "launch-dev-a1",
                task_nonce: "handoff_test_nonce_123456",
              },
            ],
          },
        },
      },
    },
  };
  return {
    sandbox: realpathSync(sandbox),
    repository: realpathSync(repository),
    source: realpathSync(source),
    destination: realpathSync(destination),
    controlDir,
    baseHead,
    observedHead,
    captainCapabilityFile: captain.file,
    devCapabilityFile: dev.file,
    loaded,
  };
}

function exportSnapshot(
  fixture: Fixture,
  snapshotId = "snapshot-source-operation",
  overrides: Partial<{
    successorThreadId: string;
    captainCapabilityFile: string;
    repositoryWorktree: string;
  }> = {}
): RecoverySnapshot & {
  snapshot_file: string;
} {
  return exportRecoverySnapshot(fixture.repository, {
    goalId: "goal-handoff",
    taskId: "TASK-A",
    snapshotId,
    successorThreadId: overrides.successorThreadId ?? "dev-successor",
    captainCapabilityFile:
      overrides.captainCapabilityFile ?? fixture.captainCapabilityFile,
    repositoryWorktree: overrides.repositoryWorktree ?? fixture.source,
  });
}

function importSnapshot(
  fixture: Fixture,
  snapshot: RecoverySnapshot,
  cwd = fixture.destination,
  importId = "import-source-operation",
  actorCapabilityFile = fixture.devCapabilityFile
): ImportReceipt & { import_receipt_file: string } {
  return importRecoverySnapshot(cwd, {
    goalId: "goal-handoff",
    taskId: "TASK-A",
    importId,
    snapshotId: snapshot.snapshot_id,
    successorThreadId: "dev-successor",
    actorCapabilityFile,
  });
}

function installLegacyImportIntentStaging(
  fixture: Fixture,
  snapshot: RecoverySnapshot,
  options: {
    importId?: string;
    state: "empty" | "canonical" | "atomic-temp";
  }
): {
  intentParent: string;
  stagingDirectory: string;
  intent: Record<string, unknown>;
  intentBytes: Buffer;
} {
  const importId = options.importId ?? "import-source-operation";
  const task = fixture.loaded.snapshot.tasks["TASK-A"];
  const dev = task.sessions.DEV;
  const commonGitDir = realpathSync(
    git(
      fixture.destination,
      "rev-parse",
      "--path-format=absolute",
      "--git-common-dir"
    )
  );
  const request = {
    schema_version: 1,
    import_id: importId,
    goal_id: "goal-handoff",
    task_id: "TASK-A",
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    successor_thread_id: "dev-successor",
    destination: {
      worktree: realpathSync(fixture.destination),
      branch: git(fixture.destination, "branch", "--show-current"),
      head: git(fixture.destination, "rev-parse", "--verify", "HEAD^{commit}"),
      repository_root: realpathSync(path.dirname(commonGitDir)),
      common_git_dir: commonGitDir,
    },
  };
  const taskAnchor = {
    control_epoch: fixture.loaded.control.epoch,
    state_revision: task.state_revision,
    packet_revision: task.packet.revision,
    packet_sha256: task.packet.sha256,
    full_head: task.full_head,
  };
  const devAuthority = {
    role: dev.role,
    thread_id: dev.thread_id,
    host_id: dev.host_id,
    attempt: dev.attempt,
    capability_file: dev.capability_file,
    capability_sha256: dev.capability_sha256.startsWith("sha256:")
      ? dev.capability_sha256
      : `sha256:${dev.capability_sha256}`,
  };
  const acceptanceAuthority = { dev: devAuthority };
  const requestSha256 = hashObject(request);
  const preparedRequestSha256 = hashObject({
    request,
    task_anchor: taskAnchor,
    acceptance_authority: acceptanceAuthority,
  });
  const unsigned = {
    schema_version: 1,
    kind: "RECOVERY_IMPORT_INTENT",
    import_id: importId,
    goal_id: "goal-handoff",
    task_id: "TASK-A",
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    successor_thread_id: "dev-successor",
    request,
    request_sha256: requestSha256,
    prepared_request_sha256: preparedRequestSha256,
    task_anchor: taskAnchor,
    acceptance_authority: acceptanceAuthority,
    accepted_at: "2026-07-23T00:00:00.000Z",
  };
  const intent = {
    ...unsigned,
    intent_sha256: hashObject(unsigned),
  };
  const intentBytes = Buffer.from(
    `${JSON.stringify(intent, null, 2)}\n`,
    "utf8"
  );
  const importDigest = sha256(importId).slice("sha256:".length);
  const stagingName = [
    ".init-import",
    importDigest,
    requestSha256.slice("sha256:".length),
    preparedRequestSha256.slice("sha256:".length),
  ].join("-");
  const intentParent = path.join(
    fixture.controlDir,
    "goals",
    "goal-handoff",
    "recovery-handoffs",
    "TASK-A",
    "import-intents"
  );
  mkdirSync(intentParent, { recursive: true });
  const stagingDirectory = path.join(intentParent, stagingName);
  mkdirSync(stagingDirectory, { mode: 0o700 });
  chmodSync(stagingDirectory, 0o700);
  if (options.state !== "empty") {
    const name = options.state === "canonical"
      ? "intent.json"
      : `.intent.json.999.tmp-${"a".repeat(24)}`;
    writeFileSync(path.join(stagingDirectory, name), intentBytes, {
      mode: 0o600,
    });
    chmodSync(path.join(stagingDirectory, name), 0o600);
  }
  return {
    intentParent,
    stagingDirectory,
    intent,
    intentBytes,
  };
}

function checkpointSnapshot(
  fixture: Fixture,
  snapshot: RecoverySnapshot,
  receipt: ImportReceipt,
  actorCapabilityFile = fixture.devCapabilityFile
): RecoveryCheckpoint {
  return checkpointRecoverySource(fixture.destination, {
    goalId: "goal-handoff",
    taskId: "TASK-A",
    successorThreadId: "dev-successor",
    snapshotId: snapshot.snapshot_id,
    importReceiptId: receipt.import_receipt_id,
    actorCapabilityFile,
  });
}

function forbiddenCapabilityKeys(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => forbiddenCapabilityKeys(entry));
  }
  if (!value || typeof value !== "object" || Buffer.isBuffer(value)) return [];
  return Object.entries(value as Record<string, unknown>).flatMap(
    ([key, entry]) => [
      ...(key === "capability_file" || key === "capability_sha256"
        ? [key]
        : []),
      ...forbiddenCapabilityKeys(entry),
    ]
  );
}

function verificationPayload(
  snapshot: RecoverySnapshot,
  receipt: ImportReceipt,
  importCommit: string
): Record<string, string> {
  return {
    successor_thread_id: "dev-successor",
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    import_receipt_id: receipt.import_receipt_id,
    import_receipt_sha256: receipt.import_receipt_sha256,
    predecessor_launch_id: snapshot.predecessor_launch_id,
    predecessor_launch_sha256: snapshot.predecessor_launch_sha256,
    source_worktree: snapshot.source_worktree,
    source_branch: snapshot.source_branch,
    source_launch_head: snapshot.source_launch_head,
    source_observed_head: snapshot.source_observed_head,
    destination_worktree: receipt.destination_worktree,
    destination_branch: receipt.destination_branch,
    import_commit: importCommit,
  };
}

function expectControlCode(operation: () => unknown, code: string): void {
  try {
    operation();
    throw new Error(`expected ${code}`);
  } catch (error: unknown) {
    expect((error as { code?: string }).code).toBe(code);
  }
}

function runExportChild(
  fixture: Fixture,
  snapshotId: string,
  fault: "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PUBLISH"
    | "GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_DISCARD_CLAIM"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_DISCARD_PAYLOAD_CLEANUP"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_STAGING_MKDIR"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_TEMP_FSYNC"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_PUBLISH"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_MANIFEST_TEMP_FSYNC"
): number {
  const loadedFile = path.join(fixture.sandbox, `${fault}.json`);
  writeFileSync(loadedFile, `${JSON.stringify(fixture.loaded)}\n`);
  const program = [
    `const goal = require(${JSON.stringify(
      path.resolve("scripts/goal-control/goal.js")
    )});`,
    `goal.loadGoalStateUnlocked = () => JSON.parse(require("fs").readFileSync(${JSON.stringify(
      loadedFile
    )}, "utf8"));`,
    `require(${JSON.stringify(
      path.resolve("scripts/goal-control/source-handoff.js")
    )}).exportRecoverySnapshot(${JSON.stringify(fixture.repository)}, ${JSON.stringify(
      {
        goalId: "goal-handoff",
        taskId: "TASK-A",
        successorThreadId: "dev-successor",
        captainCapabilityFile: fixture.captainCapabilityFile,
        repositoryWorktree: fixture.source,
        snapshotId,
      }
    )});`,
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
    return Number((error as { status?: number }).status);
  }
}

function runImportChild(
  fixture: Fixture,
  snapshotId: string,
  fault: "GOAL_CONTROL_TEST_FAULT_AFTER_RECEIPT_PUBLISH"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_IMPORT_MATERIALIZATION"
    | "GOAL_CONTROL_TEST_FAULT_SOURCE_IMPORT_INTENT_AFTER_ATOMIC_RESERVATION"
    | "GOAL_CONTROL_TEST_FAULT_SOURCE_IMPORT_INTENT_DURING_ATOMIC_TEMP_WRITE"
    | "GOAL_CONTROL_TEST_FAULT_SOURCE_IMPORT_INTENT_AFTER_ATOMIC_TEMP_FSYNC"
    | "GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_IMPORT_ADOPTION_MARKER_UNLINK"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE"
    | "GOAL_CONTROL_TEST_EXIT_DURING_IMPORT_ENTRY_WRITE"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_FSYNC"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_PROMOTE"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_TRACKED_IMPORT_PROMOTE"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_INDEX_LOCK_PUBLISH",
  importId = "import-source-operation",
  faultMode: "exit" | "sigkill" = "exit"
): number | string {
  const loadedFile = path.join(fixture.sandbox, `${fault}.json`);
  writeFileSync(loadedFile, `${JSON.stringify(fixture.loaded)}\n`);
  const program = [
    `const goal = require(${JSON.stringify(
      path.resolve("scripts/goal-control/goal.js")
    )});`,
    `goal.loadGoalStateUnlocked = () => JSON.parse(require("fs").readFileSync(${JSON.stringify(
      loadedFile
    )}, "utf8"));`,
    `require(${JSON.stringify(
      path.resolve("scripts/goal-control/source-handoff.js")
    )}).importRecoverySnapshot(${JSON.stringify(fixture.destination)}, ${JSON.stringify(
      {
        goalId: "goal-handoff",
        taskId: "TASK-A",
        importId,
        snapshotId,
        successorThreadId: "dev-successor",
        actorCapabilityFile: fixture.devCapabilityFile,
      }
    )});`,
  ].join("\n");
  try {
    execFileSync(process.execPath, ["-e", program], {
      cwd: fixture.repository,
      env: {
        ...process.env,
        GOAL_CONTROL_TEST_MODE: "1",
        GOAL_CONTROL_DIR: fixture.controlDir,
        [fault]: faultMode,
      },
      stdio: "pipe",
    });
    throw new Error("expected abrupt child exit");
  } catch (error: unknown) {
    const failure = error as { status?: number; signal?: string };
    return faultMode === "sigkill"
      ? String(failure.signal)
      : Number(failure.status);
  }
}

function runCheckpointChild(
  fixture: Fixture,
  snapshotId: string,
  importReceiptId: string,
  fault:
    | "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_GIT_FENCE"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_PUBLISH"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_FENCE_COMPLETION"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_CREATE"
    | "GOAL_CONTROL_TEST_EXIT_DURING_CHECKPOINT_INDEX_LOCK_WRITE"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_FSYNC"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_PUBLISH"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_FENCE"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_LOCK"
    | "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_MUTATION"
): number {
  const loadedFile = path.join(fixture.sandbox, `${fault}.json`);
  writeFileSync(loadedFile, `${JSON.stringify(fixture.loaded)}\n`);
  const program = [
    `const goal = require(${JSON.stringify(
      path.resolve("scripts/goal-control/goal.js")
    )});`,
    `goal.loadGoalStateUnlocked = () => JSON.parse(require("fs").readFileSync(${JSON.stringify(
      loadedFile
    )}, "utf8"));`,
    `require(${JSON.stringify(
      path.resolve("scripts/goal-control/source-handoff.js")
    )}).checkpointRecoverySource(${JSON.stringify(fixture.destination)}, ${JSON.stringify(
      {
        goalId: "goal-handoff",
        taskId: "TASK-A",
        successorThreadId: "dev-successor",
        snapshotId,
        importReceiptId,
        actorCapabilityFile: fixture.devCapabilityFile,
      }
    )});`,
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
    const child = error as {
      status?: number;
      signal?: string;
      stderr?: Buffer | string;
    };
    if (child.status === undefined) {
      throw new Error(
        `checkpoint child did not return an exit status; signal=${
          child.signal ?? "none"
        }; stderr=${String(child.stderr ?? "")}`
      );
    }
    return Number(child.status);
  }
}

describe("dirty DEV source handoff", () => {
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
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_DISCARD_CLAIM;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_DISCARD_PAYLOAD_CLEANUP;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_STAGING_MKDIR;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_TEMP_FSYNC;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_PUBLISH;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_MANIFEST_TEMP_FSYNC;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECEIPT_PUBLISH;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_IMPORT_MATERIALIZATION;
    delete process.env
      .GOAL_CONTROL_TEST_FAULT_SOURCE_IMPORT_INTENT_AFTER_ATOMIC_RESERVATION;
    delete process.env
      .GOAL_CONTROL_TEST_FAULT_SOURCE_IMPORT_INTENT_DURING_ATOMIC_TEMP_WRITE;
    delete process.env
      .GOAL_CONTROL_TEST_FAULT_SOURCE_IMPORT_INTENT_AFTER_ATOMIC_TEMP_FSYNC;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE;
    delete process.env.GOAL_CONTROL_TEST_EXIT_DURING_IMPORT_ENTRY_WRITE;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_FSYNC;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_PROMOTE;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_TRACKED_IMPORT_PROMOTE;
    delete process.env
      .GOAL_CONTROL_TEST_REPLACE_TRACKED_TARGET_AFTER_CAS;
    delete process.env
      .GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_INDEX_LOCK_PUBLISH;
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_CHECKPOINT_PUBLISH;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_GIT_FENCE;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_PUBLISH;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_FENCE_COMPLETION;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_CREATE;
    delete process.env.GOAL_CONTROL_TEST_EXIT_DURING_CHECKPOINT_INDEX_LOCK_WRITE;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_FSYNC;
    delete process.env.GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_PUBLISH;
    delete process.env.GOAL_CONTROL_NOW;
    rmSync(fixture.sandbox, { recursive: true, force: true });
  });

  afterAll(() => {
    goalModule.loadGoalStateUnlocked = originalLoadGoalStateUnlocked;
  });

  it("computes and seals an export without writing the shared Git object database", () => {
    const objectDirectory = realpathSync(gitPath(fixture.source, "objects"));
    const before = gitObjectDatabaseSnapshot(objectDirectory);

    const snapshot = exportSnapshot(fixture);

    expect(gitObjectDatabaseSnapshot(objectDirectory)).toEqual(before);
    const receipt = importSnapshot(fixture, snapshot);
    expect(receipt).toMatchObject({
      expected_tree: snapshot.expected_tree,
      materialized_tree: snapshot.expected_tree,
    });
  });

  it("does not write the shared Git object database before the checkpoint fence witness", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const objectDirectory = realpathSync(
      gitPath(fixture.destination, "objects")
    );
    const before = gitObjectDatabaseSnapshot(objectDirectory);

    expect(
      runCheckpointChild(
        fixture,
        snapshot.snapshot_id,
        receipt.import_receipt_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_GIT_FENCE"
      )
    ).toBe(99);

    expect(gitObjectDatabaseSnapshot(objectDirectory)).toEqual(before);
    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    expect(checkpoint).toMatchObject({
      parent_sha: fixture.observedHead,
      tree_sha: snapshot.expected_tree,
    });
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      checkpoint.checkpoint_sha
    );
  });

  it("preserves a same-prefix ref lock without a transaction fence", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    expect(
      runCheckpointChild(
        fixture,
        snapshot.snapshot_id,
        receipt.import_receipt_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_GIT_FENCE"
      )
    ).toBe(99);
    const fenceRoot = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "checkpoint-fences"
    );
    const [fenceDirectory] = readdirSync(fenceRoot);
    const marker = JSON.parse(readFileSync(
      path.join(fenceRoot, fenceDirectory, "prepared.json"),
      "utf8"
    )) as { request: { branch_ref: string; checkpoint_sha: string } };
    const refLock = gitPath(
      fixture.destination,
      `${marker.request.branch_ref}.lock`
    );
    writeFileSync(
      refLock,
      marker.request.checkpoint_sha.slice(0, 17),
      { mode: 0o644 }
    );

    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "HANDOFF_CHECKPOINT_REF_LOCK_INVALID"
    );

    expect(existsSync(refLock)).toBe(true);
    expect(readFileSync(refLock, "utf8")).toBe(
      marker.request.checkpoint_sha.slice(0, 17)
    );
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      fixture.observedHead
    );
  });

  it("exports committed+dirty+binary+untracked state, imports into a fresh branch, and verifies the exact squash commit", () => {
    const snapshot = exportSnapshot(fixture);
    expect(snapshot.acceptance_authority.captain).toMatchObject({
      role: "CAPTAIN",
      thread_id: "captain-current",
      host_id: "host-a",
      attempt: 1,
      capability_file: fixture.captainCapabilityFile,
    });
    expect(snapshot.source_launch_head).toBe(fixture.baseHead);
    expect(snapshot.source_observed_head).toBe(fixture.observedHead);
    expect(snapshot.expected_paths).toEqual([
      "binary.bin",
      "note-link",
      "notes/local.txt",
      "recover.sh",
      "tracked.txt",
    ]);

    const receipt = importSnapshot(fixture, snapshot);
    expect(receipt.acceptance_authority.dev).toMatchObject({
      role: "DEV",
      thread_id: "dev-successor",
      host_id: "host-b",
      attempt: 2,
      capability_file: fixture.devCapabilityFile,
    });
    expect(receipt.expected_tree).toBe(snapshot.expected_tree);
    expect(receipt.materialized_tree).toBe(snapshot.expected_tree);
    expect(git(fixture.destination, "diff", "--cached", "--name-only").split("\n").sort()).toEqual([
      "binary.bin",
      "note-link",
      "notes/local.txt",
      "recover.sh",
      "tracked.txt",
    ]);
    expect(readFileSync(path.join(fixture.destination, "tracked.txt"), "utf8")).toBe(
      "candidate plus dirty\n"
    );
    expect(readFileSync(path.join(fixture.destination, "binary.bin"))).toEqual(
      Buffer.from([9, 8, 7, 0, 255])
    );
    expect(readFileSync(path.join(fixture.destination, "notes", "local.txt"), "utf8")).toBe(
      "untracked recovery note\n"
    );
    expect(lstatSync(path.join(fixture.destination, "recover.sh")).mode & 0o111).not.toBe(0);
    expect(readlinkSync(path.join(fixture.destination, "note-link"))).toBe("notes/local.txt");

    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    const importCommit = checkpoint.checkpoint_sha;
    expect(checkpoint).toMatchObject({
      parent_sha: fixture.observedHead,
      tree_sha: snapshot.expected_tree,
      idempotent: false,
    });
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(importCommit);
    const bootstrapProbe = installPendingBootstrapReadOnlyProbe(fixture);
    const laggingGoalBytes = readFileSync(bootstrapProbe.goalFile);
    const bootstrapCapabilityBytes = readFileSync(
      bootstrapProbe.bootstrapFile
    );
    const goalTreeBeforeReadOnlyOperations = directorySnapshot(
      bootstrapProbe.goalDirectory
    );
    const indexFile = gitPath(fixture.destination, "index");
    const indexBytesBeforeReadOnlyOperations = readFileSync(indexFile);
    const indexMtimeBeforeReadOnlyOperations = lstatSync(
      indexFile,
      { bigint: true }
    ).mtimeNs;
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const generationBeforeReadOnlyOperations = readFileSync(generationFile);
    const verified = verifyRecoveryHandoff(fixture.destination, {
      goalId: "goal-handoff",
      taskId: "TASK-A",
      payload: verificationPayload(snapshot, receipt, importCommit),
    });
    expect(verified).toMatchObject({
      verified: true,
      import_commit: importCommit,
    });
    expect(readFileSync(generationFile)).toEqual(
      generationBeforeReadOnlyOperations
    );
    expect(bootstrapProbe.calls).toHaveLength(1);
    expect(bootstrapProbe.calls[0]).toMatchObject({
      repairHeads: false,
      repairBootstrapConsumption: false,
    });
    expect(readFileSync(bootstrapProbe.goalFile)).toEqual(laggingGoalBytes);
    expect(readFileSync(bootstrapProbe.bootstrapFile)).toEqual(
      bootstrapCapabilityBytes
    );
    expect(directorySnapshot(bootstrapProbe.goalDirectory)).toEqual(
      goalTreeBeforeReadOnlyOperations
    );
    expect(readFileSync(indexFile)).toEqual(
      indexBytesBeforeReadOnlyOperations
    );
    expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
      indexMtimeBeforeReadOnlyOperations
    );
    expect(
      buildRecoveryHandoffPayload(fixture.destination, {
        goalId: "goal-handoff",
        taskId: "TASK-A",
        successorThreadId: "dev-successor",
        snapshotId: snapshot.snapshot_id,
        importReceiptId: receipt.import_receipt_id,
        importCommit,
        captainCapabilityFile: fixture.captainCapabilityFile,
      })
    ).toMatchObject({
      successor_thread_id: "dev-successor",
      snapshot_id: snapshot.snapshot_id,
      import_receipt_id: receipt.import_receipt_id,
      import_commit: importCommit,
    });
    expect(readFileSync(generationFile)).toEqual(
      generationBeforeReadOnlyOperations
    );
    expect(bootstrapProbe.calls).toHaveLength(2);
    expect(bootstrapProbe.calls[1]).toMatchObject({
      repairHeads: false,
      repairBootstrapConsumption: false,
    });
    expect(readFileSync(bootstrapProbe.goalFile)).toEqual(laggingGoalBytes);
    expect(readFileSync(bootstrapProbe.bootstrapFile)).toEqual(
      bootstrapCapabilityBytes
    );
    expect(directorySnapshot(bootstrapProbe.goalDirectory)).toEqual(
      goalTreeBeforeReadOnlyOperations
    );
    expect(readFileSync(indexFile)).toEqual(
      indexBytesBeforeReadOnlyOperations
    );
    expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
      indexMtimeBeforeReadOnlyOperations
    );
    expect(git(fixture.destination, "rev-parse", `${importCommit}^`)).toBe(
      fixture.observedHead
    );
    expect(git(fixture.destination, "rev-parse", `${importCommit}^{tree}`)).toBe(
      snapshot.expected_tree
    );
    expect(git(fixture.destination, "status", "--porcelain=v1")).toBe("");
  });

  it("creates the precomputed UTF-8 checkpoint even when repository commitEncoding is non-default", () => {
    git(fixture.repository, "config", "i18n.commitEncoding", "ISO-8859-1");
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);

    expect(checkpoint.idempotent).toBe(false);
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      checkpoint.checkpoint_sha
    );
    expect(
      git(fixture.destination, "cat-file", "-p", checkpoint.checkpoint_sha)
    ).not.toContain("\nencoding ");
    expect(
      verifyRecoveryHandoff(fixture.destination, {
        goalId: "goal-handoff",
        taskId: "TASK-A",
        payload: verificationPayload(
          snapshot,
          receipt,
          checkpoint.checkpoint_sha
        ),
      })
    ).toMatchObject({
      verified: true,
      import_commit: checkpoint.checkpoint_sha,
    });
  });

  it("recursively redacts capability locator fields from a public return without mutating the source", () => {
    const durable = {
      capability_file: "/secret/root.cap",
      nested: {
        capability_sha256: "sha256:secret",
        keep: "visible",
        values: [{ capability_file: "/secret/nested.cap", ok: true }],
      },
    };
    const publicValue = publicRecoveryHandoffResult(durable);

    expect(publicValue).toEqual({
      nested: {
        keep: "visible",
        values: [{ ok: true }],
      },
    });
    expect(forbiddenCapabilityKeys(publicValue)).toEqual([]);
    expect(forbiddenCapabilityKeys(durable)).toEqual([
      "capability_file",
      "capability_sha256",
      "capability_file",
    ]);
  });

  it("redacts capability locators from recovery-export-source CLI output but retains them in the sealed snapshot", () => {
    const result = goalCommand(
      [
        "recovery-export-source",
        "--goal",
        "goal-handoff",
        "--task",
        "TASK-A",
        "--snapshot-id",
        "snapshot-public-export",
        "--successor-thread",
        "dev-successor",
        "--captain-capability-file",
        fixture.captainCapabilityFile,
        "--repository-worktree",
        fixture.source,
      ],
      fixture.repository
    );
    expect(result.exitCode).toBe(0);
    expect(forbiddenCapabilityKeys(result.value)).toEqual([]);

    const snapshotFile = String(result.value.snapshot_file);
    const durable = JSON.parse(readFileSync(snapshotFile, "utf8")) as unknown;
    expect(forbiddenCapabilityKeys(durable)).toEqual([
      "capability_file",
      "capability_sha256",
    ]);
  });

  it("redacts capability locators from recovery-import-source CLI output but retains them in the sealed receipt", () => {
    const snapshot = exportSnapshot(fixture, "snapshot-public-import");
    const result = goalCommand(
      [
        "recovery-import-source",
        "--goal",
        "goal-handoff",
        "--task",
        "TASK-A",
        "--import-id",
        "import-public-output",
        "--successor-thread",
        "dev-successor",
        "--snapshot",
        snapshot.snapshot_id,
        "--actor-capability-file",
        fixture.devCapabilityFile,
      ],
      fixture.destination
    );
    expect(result.exitCode).toBe(0);
    expect(forbiddenCapabilityKeys(result.value)).toEqual([]);
    expect(result.value.next_step).toContain("recovery-checkpoint-source");

    const receiptFile = String(result.value.import_receipt_file);
    const durable = JSON.parse(readFileSync(receiptFile, "utf8")) as unknown;
    expect(forbiddenCapabilityKeys(durable)).toEqual([
      "capability_file",
      "capability_sha256",
    ]);
  });

  it("rejects importing a snapshot back into the predecessor worktree", () => {
    const snapshot = exportSnapshot(fixture);
    expectControlCode(
      () => importSnapshot(fixture, snapshot, fixture.source),
      "HANDOFF_SAME_WORKTREE"
    );
  });

  it("rejects import when a worktree-specific MERGE_HEAD is hidden behind a clean index", () => {
    const snapshot = exportSnapshot(fixture);
    const sentinel = writeMergeHeadSentinel(
      fixture.destination,
      fixture.observedHead
    );
    const sentinelBefore = readFileSync(sentinel);
    const destinationBefore = directorySnapshot(fixture.destination);
    const headBefore = git(fixture.destination, "rev-parse", "HEAD");
    expect(git(fixture.destination, "status", "--porcelain=v1")).toBe("");

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_GIT_OPERATION_IN_PROGRESS"
    );

    expect(readFileSync(sentinel)).toEqual(sentinelBefore);
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(headBefore);
    expect(directorySnapshot(fixture.destination)).toEqual(destinationBefore);
    expect(
      existsSync(
        path.join(
          fixture.controlDir,
          "goals",
          "goal-handoff",
          "recovery-handoffs",
          "TASK-A",
          "import-receipts",
          "import-source-operation.json"
        )
      )
    ).toBe(false);
  });

  it("replays the sealed export after publish-before-response even when source and original CAPTAIN are historical", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PUBLISH"
      )
    ).toBe(86);

    writeFileSync(path.join(fixture.source, "tracked.txt"), "changed after publish\n");
    const task = fixture.loaded.snapshot.tasks["TASK-A"];
    const originalCaptain = task.sessions.CAPTAIN;
    task.session_history.CAPTAIN = [{
      ...originalCaptain,
      status: "terminal",
    }];
    const replacement = createCapability(
      path.dirname(fixture.captainCapabilityFile),
      "captain-replacement"
    );
    task.sessions.CAPTAIN = {
      role: "CAPTAIN",
      thread_id: "captain-replacement",
      host_id: "host-c",
      attempt: 2,
      status: "active",
      lease_until: "2099-01-01T00:00:00.000Z",
      capability_file: replacement.file,
      capability_sha256: replacement.verifier,
    };
    task.phase = "ARCHIVED";
    git(fixture.repository, "worktree", "remove", "--force", fixture.source);

    const retried = exportSnapshot(fixture);
    expect(retried).toMatchObject({
      snapshot_id: "snapshot-source-operation",
      idempotent: true,
      source_worktree: fixture.source,
    });
    expect(retried.acceptance_authority.captain.thread_id).toBe(
      "captain-current"
    );
  });

  it("discards an unsealed same-operation export staging orphan before an exact retry", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING"
      )
    ).toBe(91);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
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
        exportSnapshot(fixture, "snapshot-source-operation", {
          successorThreadId: "dev-other",
        }),
      "HANDOFF_OPERATION_CONFLICT"
    );
    expect(readFileSync(
      path.join(stagingDirectory, "operation-binding.json")
    )).toEqual(bindingBefore);
    expect(readFileSync(path.join(stagingDirectory, "tracked.patch"))).toEqual(
      patchBefore
    );

    const retried = exportSnapshot(fixture);

    expect(retried).toMatchObject({
      snapshot_id: "snapshot-source-operation",
      idempotent: false,
    });
    expect(existsSync(retried.snapshot_file)).toBe(true);
    expect(
      readdirSync(snapshotsDir).some((name) =>
        name.startsWith(".init-source-")
      )
    ).toBe(false);
  });

  it("keeps an empty v2 export staging fail-closed because no complete execution authority was sealed", () => {
    const snapshotId = `s${"x".repeat(199)}`;
    expect(snapshotId).toHaveLength(200);
    expect(
      runExportChild(
        fixture,
        snapshotId,
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_STAGING_MKDIR"
      )
    ).toBe(93);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const staging = readdirSync(snapshotsDir).filter((name) =>
      name.startsWith(".init-source-")
    );
    expect(staging).toHaveLength(1);
    expect(Buffer.byteLength(staging[0])).toBeLessThanOrEqual(255);
    expect(readdirSync(path.join(snapshotsDir, staging[0]))).toEqual([]);
    const requestedOperation = {
      kind: "SOURCE_WORKTREE",
      repository_worktree: realpathSync(fixture.source),
      successor_thread_id: "dev-successor",
    };
    const transactionKey = canonicalTransactionKey(
      "SOURCE_EXPORT",
      { goal_id: "goal-handoff", task_id: "TASK-A" },
      snapshotId,
      hashObject(requestedOperation)
    );
    try {
      withLock(
        fixture.controlDir,
        () => {
          writeFileSync(
            path.join(fixture.controlDir, ".test-empty-export-odd-witness"),
            "exact transaction crashed before publishing its witness\n"
          );
          throw new Error("leave an exact SOURCE_EXPORT odd generation");
        },
        { transactionKey }
      );
    } catch {
      // The exact persisted transaction key is necessary but not sufficient:
      // the empty staging still has no complete execution/authority witness.
    }
    const stagingBefore = directorySnapshot(snapshotsDir);
    const generationFile = path.join(fixture.controlDir, ".generation.json");

    expectControlCode(
      () =>
        exportSnapshot(fixture, snapshotId, {
          successorThreadId: "dev-other",
        }),
      "HANDOFF_OPERATION_CONFLICT"
    );
    expect(directorySnapshot(snapshotsDir)).toEqual(stagingBefore);

    expectControlCode(
      () =>
        exportSnapshot(fixture, snapshotId, {
          captainCapabilityFile: fixture.devCapabilityFile,
        }),
      "STORE_REPAIR_REQUIRED"
    );
    expect(directorySnapshot(snapshotsDir)).toEqual(stagingBefore);

    expectControlCode(
      () => exportSnapshot(fixture, snapshotId),
      "STORE_REPAIR_REQUIRED"
    );
    expect(directorySnapshot(snapshotsDir)).toEqual(stagingBefore);
    const generation = JSON.parse(
      readFileSync(generationFile, "utf8")
    ).generation as number;
    expect(generation % 2).toBe(1);
  });

  it.each([
    [
      "binding atomic temp",
      "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_TEMP_FSYNC",
      94,
      (entries: string[]) =>
        entries.some((name) =>
          /^\.operation-binding\.json\.[1-9][0-9]*\.tmp-[0-9a-f]{24}$/.test(
            name
          )
        ),
    ],
    [
      "canonical binding only",
      "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_PUBLISH",
      96,
      (entries: string[]) =>
        entries.length === 1 && entries[0] === "operation-binding.json",
    ],
  ] as const)(
    "recovers the %s crash boundary by exact retry",
    (_label, fault, status, inventoryMatches) => {
      expect(
        runExportChild(
          fixture,
          "snapshot-source-operation",
          fault
        )
      ).toBe(status);
      const snapshotsDir = path.join(
        fixture.controlDir,
        "goals",
        "goal-handoff",
        "recovery-handoffs",
        "TASK-A",
        "snapshots"
      );
      const staging = readdirSync(snapshotsDir).find((name) =>
        name.startsWith(".init-source-")
      );
      expect(staging).toBeDefined();
      expect(
        inventoryMatches(
          readdirSync(path.join(snapshotsDir, staging as string)).sort()
        )
      ).toBe(true);

      const retried = exportSnapshot(fixture);

      expect(retried).toMatchObject({
        snapshot_id: "snapshot-source-operation",
        idempotent: false,
      });
    }
  );

  it("fails closed on multiple export binding atomic temporaries and preserves both", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_TEMP_FSYNC"
      )
    ).toBe(94);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const staging = readdirSync(snapshotsDir).find((name) =>
      name.startsWith(".init-source-")
    );
    expect(staging).toBeDefined();
    const stagingDirectory = path.join(snapshotsDir, staging as string);
    const existingTemporary = readdirSync(stagingDirectory).find((name) =>
      /^\.operation-binding\.json\.[1-9][0-9]*\.tmp-[0-9a-f]{24}$/.test(
        name
      )
    );
    expect(existingTemporary).toBeDefined();
    writeFileSync(
      path.join(
        stagingDirectory,
        `.operation-binding.json.999.tmp-${"c".repeat(24)}`
      ),
      readFileSync(
        path.join(stagingDirectory, existingTemporary as string)
      ),
      { mode: 0o600 }
    );
    const before = directorySnapshot(stagingDirectory);

    expectControlCode(
      () => exportSnapshot(fixture),
      "HANDOFF_STAGING_INVALID"
    );
    expect(directorySnapshot(stagingDirectory)).toEqual(before);
  });

  it("promotes a complete snapshot atomic temp after source loss and authority replacement", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_MANIFEST_TEMP_FSYNC"
      )
    ).toBe(95);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const staging = readdirSync(snapshotsDir).find((name) =>
      name.startsWith(".init-source-")
    );
    expect(staging).toBeDefined();
    const stagingDirectory = path.join(snapshotsDir, staging as string);
    expect(
      readdirSync(stagingDirectory).some((name) =>
        /^\.snapshot\.json\.[1-9][0-9]*\.tmp-[0-9a-f]{24}$/.test(name)
      )
    ).toBe(true);

    const task = fixture.loaded.snapshot.tasks["TASK-A"];
    const originalCaptain = task.sessions.CAPTAIN;
    task.session_history.CAPTAIN = [{
      ...originalCaptain,
      status: "terminal",
    }];
    const replacement = createCapability(
      path.dirname(fixture.captainCapabilityFile),
      "captain-after-manifest-temp"
    );
    task.sessions.CAPTAIN = {
      role: "CAPTAIN",
      thread_id: "captain-after-manifest-temp",
      host_id: "host-c",
      attempt: 2,
      status: "active",
      lease_until: "2099-01-01T00:00:00.000Z",
      capability_file: replacement.file,
      capability_sha256: replacement.verifier,
    };
    git(fixture.repository, "worktree", "remove", "--force", fixture.source);

    const retried = exportSnapshot(fixture);

    expect(retried).toMatchObject({
      snapshot_id: "snapshot-source-operation",
      idempotent: true,
      acceptance_authority: {
        captain: { thread_id: "captain-current", attempt: 1 },
      },
    });
    expect(existsSync(retried.snapshot_file)).toBe(true);
  });

  it("preserves a partial export when the same CLI request now resolves to different source bytes", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING"
      )
    ).toBe(91);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const staging = readdirSync(snapshotsDir).find((name) =>
      name.startsWith(".init-source-")
    );
    expect(staging).toBeDefined();
    const stagingDirectory = path.join(snapshotsDir, staging as string);
    const bindingBefore = readFileSync(
      path.join(stagingDirectory, "operation-binding.json")
    );
    const patchBefore = readFileSync(
      path.join(stagingDirectory, "tracked.patch")
    );

    writeFileSync(
      path.join(fixture.source, "tracked.txt"),
      "different source after partial crash\n"
    );

    expectControlCode(
      () => exportSnapshot(fixture),
      "HANDOFF_OPERATION_CONFLICT"
    );
    expect(readFileSync(
      path.join(stagingDirectory, "operation-binding.json")
    )).toEqual(bindingBefore);
    expect(readFileSync(path.join(stagingDirectory, "tracked.patch"))).toEqual(
      patchBefore
    );
  });

  it("rejects non-private partial staging directories and files without deleting them", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING"
      )
    ).toBe(91);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const staging = readdirSync(snapshotsDir).find((name) =>
      name.startsWith(".init-source-")
    );
    expect(staging).toBeDefined();
    const stagingDirectory = path.join(snapshotsDir, staging as string);
    const patchFile = path.join(stagingDirectory, "tracked.patch");

    chmodSync(stagingDirectory, 0o755);
    expectControlCode(
      () => exportSnapshot(fixture),
      "HANDOFF_STAGING_INVALID"
    );
    expect(existsSync(stagingDirectory)).toBe(true);

    chmodSync(stagingDirectory, 0o700);
    chmodSync(patchFile, 0o644);
    expectControlCode(
      () => exportSnapshot(fixture),
      "HANDOFF_STAGING_INVALID"
    );
    expect(existsSync(stagingDirectory)).toBe(true);
    expect(existsSync(patchFile)).toBe(true);
  });

  it("recovers an exact discard claim left by abrupt cleanup without leaking a permanent residue", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING"
      )
    ).toBe(91);
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_DISCARD_CLAIM"
      )
    ).toBe(92);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const discarded = readdirSync(snapshotsDir).filter((name) =>
      name.startsWith(".discard-source-")
    );
    expect(discarded).toHaveLength(1);
    expect(
      readdirSync(path.join(snapshotsDir, discarded[0])).sort()
    ).toEqual(["operation-binding.json", "tracked.patch"]);
    const bootstrapProbe = installPendingBootstrapReadOnlyProbe(fixture);
    const goalBeforeWrongRequest = directorySnapshot(
      bootstrapProbe.goalDirectory
    );
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const generationBeforeWrongRequest = JSON.parse(
      readFileSync(generationFile, "utf8")
    ).generation as number;

    expectControlCode(
      () =>
        exportSnapshot(fixture, "snapshot-source-operation", {
          successorThreadId: "dev-other",
        }),
      "HANDOFF_OPERATION_CONFLICT"
    );
    expect(bootstrapProbe.calls).toHaveLength(0);
    expect(directorySnapshot(bootstrapProbe.goalDirectory)).toEqual(
      goalBeforeWrongRequest
    );
    expect(readFileSync(bootstrapProbe.bootstrapFile)).toEqual(
      bootstrapProbe.bootstrapBytes
    );
    const generationAfterWrongRequest = JSON.parse(
      readFileSync(generationFile, "utf8")
    ).generation as number;
    expect(generationAfterWrongRequest).toBeGreaterThanOrEqual(
      generationBeforeWrongRequest
    );
    expect(generationAfterWrongRequest % 2).toBe(1);

    const retried = exportSnapshot(fixture);

    expect(retried).toMatchObject({
      snapshot_id: "snapshot-source-operation",
      idempotent: false,
    });
    expect(
      readdirSync(snapshotsDir).some((name) =>
        name.startsWith(".discard-source-")
      )
    ).toBe(false);
  });

  it("finishes a discard whose payload was durably removed before a cleanup crash", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING"
      )
    ).toBe(91);
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_DISCARD_PAYLOAD_CLEANUP"
      )
    ).toBe(97);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const discarded = readdirSync(snapshotsDir).filter((name) =>
      name.startsWith(".discard-source-")
    );
    expect(discarded).toHaveLength(1);
    expect(
      readdirSync(path.join(snapshotsDir, discarded[0]))
    ).toEqual(["operation-binding.json"]);

    const retried = exportSnapshot(fixture);

    expect(retried.snapshot_id).toBe("snapshot-source-operation");
    expect(
      readdirSync(snapshotsDir).some((name) =>
        name.startsWith(".discard-source-")
      )
    ).toBe(false);
  });

  it("keeps a tampered partial operation binding fail-closed and byte-identical", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING"
      )
    ).toBe(91);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const staging = readdirSync(snapshotsDir).find((name) =>
      name.startsWith(".init-source-")
    );
    expect(staging).toBeDefined();
    const stagingDirectory = path.join(snapshotsDir, staging as string);
    const bindingFile = path.join(
      stagingDirectory,
      "operation-binding.json"
    );
    const binding = JSON.parse(readFileSync(bindingFile, "utf8")) as {
      execution_sha256: string;
      binding_sha256: string;
    };
    binding.execution_sha256 = hashObject({ tampered: true });
    writeFileSync(bindingFile, `${JSON.stringify(binding, null, 2)}\n`);
    const tamperedBinding = readFileSync(bindingFile);
    const patchBefore = readFileSync(
      path.join(stagingDirectory, "tracked.patch")
    );

    expectControlCode(
      () => exportSnapshot(fixture),
      "HANDOFF_STAGING_TAMPERED"
    );
    expect(readFileSync(bindingFile)).toEqual(tamperedBinding);
    expect(readFileSync(path.join(stagingDirectory, "tracked.patch"))).toEqual(
      patchBefore
    );
  });

  it("keeps a sealed prepared export fail-closed when its artifact no longer matches the manifest", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH"
      )
    ).toBe(85);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    const staging = readdirSync(snapshotsDir).filter((name) =>
      name.startsWith(".init-source-")
    );
    expect(staging).toHaveLength(1);
    const stagingDirectory = path.join(snapshotsDir, staging[0]);
    appendFileSync(path.join(stagingDirectory, "tracked.patch"), "tampered");

    expectControlCode(
      () => exportSnapshot(fixture),
      "HANDOFF_ARTIFACT_TAMPERED"
    );
    expect(existsSync(path.join(stagingDirectory, "snapshot.json"))).toBe(true);
    expect(existsSync(stagingDirectory)).toBe(true);
  });

  it("recovers only the exact stable-ID staging and fails closed on an unrelated malformed marker", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH"
      )
    ).toBe(85);
    const snapshotsDir = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "snapshots"
    );
    expect(
      readdirSync(snapshotsDir).some((name) =>
        name.startsWith(".init-source-")
      )
    ).toBe(true);
    const otherOperation = path.join(
      snapshotsDir,
      ".snapshot-other-operation.999.tmp-000000000000000000000000"
    );
    mkdirSync(otherOperation);

    expectControlCode(
      () => exportSnapshot(fixture),
      "CORRUPT_STORE"
    );
    expect(existsSync(otherOperation)).toBe(true);
    rmSync(otherOperation, { recursive: true, force: true });

    const task = fixture.loaded.snapshot.tasks["TASK-A"];
    const originalCaptain = task.sessions.CAPTAIN;
    task.session_history.CAPTAIN = [{
      ...originalCaptain,
      status: "terminal",
    }];
    const replacement = createCapability(
      path.dirname(fixture.captainCapabilityFile),
      "captain-after-staging-crash"
    );
    task.sessions.CAPTAIN = {
      role: "CAPTAIN",
      thread_id: "captain-after-staging-crash",
      host_id: "host-c",
      attempt: 2,
      status: "active",
      lease_until: "2099-01-01T00:00:00.000Z",
      capability_file: replacement.file,
      capability_sha256: replacement.verifier,
    };
    git(fixture.repository, "worktree", "remove", "--force", fixture.source);

    const snapshot = exportSnapshot(fixture);
    expect(snapshot.snapshot_id).toBe("snapshot-source-operation");
    expect(snapshot.idempotent).toBe(true);
    expect(snapshot.acceptance_authority.captain.thread_id).toBe(
      "captain-current"
    );
    expect(
      readdirSync(snapshotsDir).some((name) =>
        name.startsWith(".init-source-")
      )
    ).toBe(false);
  });

  it("leaves a legacy prepared export byte-identical instead of publishing it after ARCHIVED", () => {
    expect(
      runExportChild(
        fixture,
        "snapshot-source-operation",
        "GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH"
      )
    ).toBe(85);
    const handoffRoot = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A"
    );
    const before = directorySnapshot(handoffRoot);
    fixture.loaded.snapshot.tasks["TASK-A"].phase = "ARCHIVED";

    expectControlCode(
      () => exportSnapshot(fixture),
      "TASK_TERMINAL"
    );

    expect(directorySnapshot(handoffRoot)).toEqual(before);
    expect(
      existsSync(
        path.join(
          handoffRoot,
          "snapshots",
          "snapshot-source-operation"
        )
      )
    ).toBe(false);
  });

  it("rejects a different export request that reuses an operation ID and never aliases another ID", () => {
    const snapshot = exportSnapshot(fixture);
    expectControlCode(
      () =>
        exportSnapshot(fixture, snapshot.snapshot_id, {
          successorThreadId: "dev-other",
        }),
      "HANDOFF_OPERATION_CONFLICT"
    );

    git(fixture.repository, "worktree", "remove", "--force", fixture.source);
    expectControlCode(
      () => exportSnapshot(fixture, "snapshot-different-operation"),
      "HANDOFF_PATH_INVALID"
    );
  });

  it("returns the sealed receipt when import succeeded but its response was lost", () => {
    const snapshot = exportSnapshot(fixture);
    const first = importSnapshot(fixture, snapshot);
    const receiptBytes = readFileSync(first.import_receipt_file);

    const retried = importSnapshot(fixture, snapshot);

    expect(retried).toMatchObject({
      import_receipt_id: first.import_receipt_id,
      import_receipt_sha256: first.import_receipt_sha256,
      import_receipt_file: first.import_receipt_file,
      idempotent: true,
      expected_tree: snapshot.expected_tree,
      materialized_tree: snapshot.expected_tree,
    });
    expect(readFileSync(first.import_receipt_file)).toEqual(receiptBytes);
  });

  it("replays the sealed receipt after publish-before-response despite commit, phase, and DEV replacement progress", () => {
    const snapshot = exportSnapshot(fixture);
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECEIPT_PUBLISH = "1";
    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "TEST_FAULT_AFTER_RECEIPT_PUBLISH"
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_RECEIPT_PUBLISH;

    git(fixture.destination, "commit", "-qm", "advance after lost import response");
    const task = fixture.loaded.snapshot.tasks["TASK-A"];
    const originalDev = task.sessions.DEV;
    task.session_history.DEV.push({
      ...originalDev,
      status: "terminal",
    });
    const replacement = createCapability(
      path.dirname(fixture.devCapabilityFile),
      "dev-replacement"
    );
    task.sessions.DEV = {
      role: "DEV",
      thread_id: "dev-replacement",
      host_id: "host-c",
      attempt: 3,
      status: "active",
      lease_until: "2099-01-01T00:00:00.000Z",
      capability_file: replacement.file,
      capability_sha256: replacement.verifier,
    };
    task.phase = "DEV_COMPLETE";

    const retried = importSnapshot(fixture, snapshot);
    expect(retried).toMatchObject({
      snapshot_id: snapshot.snapshot_id,
      idempotent: true,
      destination_worktree: fixture.destination,
      destination_branch: "task/destination",
    });
    expect(retried.acceptance_authority.dev.thread_id).toBe("dev-successor");
    expect(git(fixture.destination, "rev-parse", "HEAD")).not.toBe(
      fixture.observedHead
    );
  });

  it("seals an exact fully materialized import after a pre-receipt crash without applying twice", () => {
    const snapshot = exportSnapshot(fixture);
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_IMPORT_MATERIALIZATION = "1";
    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "TEST_FAULT_AFTER_IMPORT_MATERIALIZATION"
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_IMPORT_MATERIALIZATION;
    const stagedBeforeRetry = git(
      fixture.destination,
      "diff",
      "--cached",
      "--binary"
    );

    const receipt = importSnapshot(fixture, snapshot);
    expect(receipt).toMatchObject({
      import_receipt_id: "import-source-operation",
      idempotent: false,
      expected_tree: snapshot.expected_tree,
      materialized_tree: snapshot.expected_tree,
    });
    expect(git(fixture.destination, "diff", "--cached", "--binary")).toBe(
      stagedBeforeRetry
    );
  });

  it("abruptly exits after full materialization and seals the exact staged tree on retry", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_FAULT_AFTER_IMPORT_MATERIALIZATION"
      )
    ).toBe(88);
    const stagedBeforeRetry = git(
      fixture.destination,
      "diff",
      "--cached",
      "--binary"
    );

    const receipt = importSnapshot(fixture, snapshot);
    expect(receipt).toMatchObject({
      import_receipt_id: "import-source-operation",
      idempotent: false,
      expected_tree: snapshot.expected_tree,
      materialized_tree: snapshot.expected_tree,
    });
    expect(git(fixture.destination, "diff", "--cached", "--binary")).toBe(
      stagedBeforeRetry
    );
  });

  it.each([
    [
      "empty exact entry temp",
      "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE",
      102,
    ],
    [
      "partial exact entry temp",
      "GOAL_CONTROL_TEST_EXIT_DURING_IMPORT_ENTRY_WRITE",
      103,
    ],
    [
      "fsynced exact entry temp",
      "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_FSYNC",
      104,
    ],
    [
      "no-clobber promoted entry",
      "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_PROMOTE",
      105,
    ],
  ] as const)(
    "exact-retries source import after abrupt %s",
    (_label, fault, exitCode) => {
      const snapshot = exportSnapshot(fixture);
      expect(runImportChild(fixture, snapshot.snapshot_id, fault)).toBe(
        exitCode
      );
      const destinationBeforeLockRecovery = directorySnapshot(
        fixture.destination
      );
      const indexFile = gitPath(fixture.destination, "index");
      const indexBytesBeforeLockRecovery = readFileSync(indexFile);
      const indexMtimeBeforeLockRecovery = lstatSync(
        indexFile,
        { bigint: true }
      ).mtimeNs;

      // The killed writer intentionally leaves the store lock owned by a dead
      // process. The first caller may reap that transport lock and reseal the
      // store generation, but it still must not touch source materialization.
      expectControlCode(
        () =>
          importSnapshot(
            fixture,
            snapshot,
            fixture.destination,
            "import-other-operation"
          ),
        "STORE_TRANSACTION_MISMATCH"
      );
      expect(directorySnapshot(fixture.destination)).toEqual(
        destinationBeforeLockRecovery
      );
      expect(readFileSync(indexFile)).toEqual(indexBytesBeforeLockRecovery);
      expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
        indexMtimeBeforeLockRecovery
      );

      const controlBeforeRejectedRetries = directorySnapshot(
        fixture.controlDir
      );
      const destinationBeforeRejectedRetries = directorySnapshot(
        fixture.destination
      );
      const indexBytesBeforeRejectedRetries = readFileSync(indexFile);
      const indexMtimeBeforeRejectedRetries = lstatSync(
        indexFile,
        { bigint: true }
      ).mtimeNs;

      expectControlCode(
        () =>
          importSnapshot(
            fixture,
            snapshot,
            fixture.destination,
            "import-other-operation"
          ),
        "STORE_TRANSACTION_MISMATCH"
      );
      expectControlCode(
        () =>
          importSnapshot(
            fixture,
            snapshot,
            fixture.destination,
            "import-source-operation",
            fixture.captainCapabilityFile
          ),
        "CAPABILITY_INVALID"
      );
      expect(directorySnapshot(fixture.controlDir)).toEqual(
        controlBeforeRejectedRetries
      );
      expect(directorySnapshot(fixture.destination)).toEqual(
        destinationBeforeRejectedRetries
      );
      expect(readFileSync(indexFile)).toEqual(
        indexBytesBeforeRejectedRetries
      );
      expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
        indexMtimeBeforeRejectedRetries
      );

      const receipt = importSnapshot(fixture, snapshot);
      expect(receipt).toMatchObject({
        import_receipt_id: "import-source-operation",
        expected_tree: snapshot.expected_tree,
        materialized_tree: snapshot.expected_tree,
        idempotent: false,
      });
      expect(
        git(
          fixture.destination,
          "ls-files",
          "--others",
          "--exclude-standard"
        )
      ).toBe("");
    }
  );

  it.each([
    [
      "one tracked path promotion",
      "GOAL_CONTROL_TEST_EXIT_AFTER_TRACKED_IMPORT_PROMOTE",
      110,
    ],
    [
      "transaction-owned canonical index lock publication",
      "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_INDEX_LOCK_PUBLISH",
      111,
    ],
  ] as const)(
    "exact-retries source import after abrupt %s without git apply --index residue",
    (_label, fault, exitCode) => {
      const snapshot = exportSnapshot(fixture);
      expect(runImportChild(fixture, snapshot.snapshot_id, fault)).toBe(
        exitCode
      );
      const indexFile = gitPath(fixture.destination, "index");
      if (fault === "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_INDEX_LOCK_PUBLISH") {
        expect(existsSync(`${indexFile}.lock`)).toBe(true);
      }

      const receipt = importSnapshot(fixture, snapshot);

      expect(receipt).toMatchObject({
        import_receipt_id: "import-source-operation",
        expected_tree: snapshot.expected_tree,
        materialized_tree: snapshot.expected_tree,
        idempotent: false,
      });
      expect(existsSync(`${indexFile}.lock`)).toBe(false);
      expect(
        findFilesWithBasePrefix(
          fixture.destination,
          ".goalctl-source-import-tracked-"
        )
      ).toEqual([]);
      expect(
        git(fixture.destination, "diff", "--name-only")
      ).toBe("");
      expect(
        git(fixture.destination, "ls-files", "--others", "--exclude-standard")
      ).toBe("");
    }
  );

  it("holds index.lock across canonical worktree materialization", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE"
      )
    ).toBe(102);
    const indexFile = gitPath(fixture.destination, "index");
    expect(existsSync(`${indexFile}.lock`)).toBe(true);
    const competing = spawnSync(
      "git",
      ["add", "tracked.txt"],
      {
        cwd: fixture.destination,
        encoding: "utf8",
        stdio: "pipe",
      }
    );
    expect(competing.status).not.toBe(0);
    expect(`${competing.stdout}${competing.stderr}`).toContain("index.lock");

    const receipt = importSnapshot(fixture, snapshot);
    expect(receipt.materialized_tree).toBe(snapshot.expected_tree);
    expect(existsSync(`${indexFile}.lock`)).toBe(false);
  });

  it("exact-retries crash-residual parent markers only through same-inode control anchors", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE"
      )
    ).toBe(102);
    const markers = findFilesWithBasePrefix(
      fixture.destination,
      ".goalctl-source-import-parent-"
    );
    const anchor = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "import-intents",
      "import-source-operation",
      "intent.json"
    );
    expect(markers.length).toBeGreaterThan(0);
    const anchorStat = lstatSync(anchor);
    expect(anchorStat.nlink).toBe(markers.length + 1);
    for (const marker of markers) {
      const markerStat = lstatSync(marker);
      expect([markerStat.dev, markerStat.ino, markerStat.nlink]).toEqual([
        anchorStat.dev,
        anchorStat.ino,
        markers.length + 1,
      ]);
      expect(readFileSync(marker)).toEqual(readFileSync(anchor));
    }

    const receipt = importSnapshot(fixture, snapshot);

    expect(receipt.materialized_tree).toBe(snapshot.expected_tree);
    expect(
      findFilesWithBasePrefix(
        fixture.destination,
        ".goalctl-source-import-parent-"
      )
    ).toEqual([]);
    expect(lstatSync(anchor).nlink).toBe(1);
  });

  it("rejects parent rename plus copied sealed marker because it is not the control anchor inode", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE"
      )
    ).toBe(102);
    const marker = findFilesWithBasePrefix(
      path.join(fixture.destination, "notes"),
      ".goalctl-source-import-parent-"
    )[0];
    expect(marker).toBeDefined();
    const markerBody = readFileSync(marker);
    const displacedParent = path.join(fixture.sandbox, "displaced-notes");
    renameSync(path.dirname(marker), displacedParent);
    mkdirSync(path.dirname(marker), { mode: 0o755 });
    writeFileSync(marker, markerBody, { mode: 0o600 });
    const foreignMarkerBefore = directorySnapshot(path.dirname(marker));

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_PATH_COLLISION"
    );

    expect(directorySnapshot(path.dirname(marker))).toEqual(
      foreignMarkerBefore
    );
    expect(readFileSync(marker)).toEqual(markerBody);
    expect(existsSync(displacedParent)).toBe(true);
  });

  it("preserves a foreign same-name parent marker even when its sealed bytes were copied", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE"
      )
    ).toBe(102);
    const marker = findFilesWithBasePrefix(
      fixture.destination,
      ".goalctl-source-import-parent-"
    )[0];
    expect(marker).toBeDefined();
    const markerBody = readFileSync(marker);
    rmSync(marker);
    writeFileSync(marker, markerBody, { mode: 0o600 });
    const foreignMarkerStat = lstatSync(marker);

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_PATH_COLLISION"
    );

    const preserved = lstatSync(marker);
    expect([preserved.dev, preserved.ino]).toEqual([
      foreignMarkerStat.dev,
      foreignMarkerStat.ino,
    ]);
    expect(readFileSync(marker)).toEqual(markerBody);
  });

  it("fails closed and preserves a same-uid atomic save injected after the tracked target CAS", () => {
    const snapshot = exportSnapshot(fixture);
    process.env.GOAL_CONTROL_TEST_REPLACE_TRACKED_TARGET_AFTER_CAS = "1";

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_DESTINATION_DIRTY"
    );

    expect(
      readFileSync(
        path.join(fixture.destination, "tracked.txt"),
        "utf8"
      )
    ).toBe("foreign same-uid atomic save\n");
    expect(
      findFilesWithBasePrefix(
        fixture.destination,
        ".goalctl-source-import-tracked-"
      ).length
    ).toBeGreaterThan(0);
  });

  it("fails closed without deleting a divergent exact import entry temp", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE"
      )
    ).toBe(102);
    const temporaries = findFilesWithBasePrefix(
      fixture.destination,
      ".goalctl-source-import-entry-"
    );
    expect(temporaries).toHaveLength(1);
    writeFileSync(temporaries[0], "divergent import bytes\n");
    const destinationBefore = directorySnapshot(fixture.destination);
    const indexFile = gitPath(fixture.destination, "index");
    const indexBytesBefore = readFileSync(indexFile);
    const indexMtimeBefore = lstatSync(indexFile, { bigint: true }).mtimeNs;

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_IMPORT_TEMP_CONFLICT"
    );

    expect(directorySnapshot(fixture.destination)).toEqual(destinationBefore);
    expect(readFileSync(indexFile)).toEqual(indexBytesBefore);
    expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
      indexMtimeBefore
    );
  });

  it("fails closed without deleting an import temp from a foreign binding", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE"
      )
    ).toBe(102);
    const [exactTemporary] = findFilesWithBasePrefix(
      fixture.destination,
      ".goalctl-source-import-entry-"
    );
    expect(exactTemporary).toBeDefined();
    const foreignTemporary = path.join(
      path.dirname(exactTemporary),
      `.goalctl-source-import-entry-${"f".repeat(64)}.tmp`
    );
    writeFileSync(foreignTemporary, "foreign binding\n", { mode: 0o600 });
    const destinationBefore = directorySnapshot(fixture.destination);
    const indexFile = gitPath(fixture.destination, "index");
    const indexBytesBefore = readFileSync(indexFile);
    const indexMtimeBefore = lstatSync(indexFile, { bigint: true }).mtimeNs;

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_IMPORT_TEMP_CONFLICT"
    );

    expect(directorySnapshot(fixture.destination)).toEqual(destinationBefore);
    expect(readFileSync(indexFile)).toEqual(indexBytesBefore);
    expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
      indexMtimeBefore
    );
  });

  it("rejects foreign untracked import content without consuming it", () => {
    const snapshot = exportSnapshot(fixture);
    const foreign = path.join(fixture.destination, "foreign-untracked.txt");
    writeFileSync(foreign, "must survive rejected import\n");
    const destinationBefore = directorySnapshot(fixture.destination);
    const indexFile = gitPath(fixture.destination, "index");
    const indexBytesBefore = readFileSync(indexFile);
    const indexMtimeBefore = lstatSync(indexFile, { bigint: true }).mtimeNs;

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_DESTINATION_DIRTY"
    );

    expect(directorySnapshot(fixture.destination)).toEqual(destinationBefore);
    expect(readFileSync(foreign, "utf8")).toBe(
      "must survive rejected import\n"
    );
    expect(readFileSync(indexFile)).toEqual(indexBytesBefore);
    expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
      indexMtimeBefore
    );
  });

  it("recovers the sealed import intent after process exit even when the DEV lease later expires", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_FAULT_AFTER_IMPORT_MATERIALIZATION"
      )
    ).toBe(88);
    const intentFile = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "import-intents",
      "import-source-operation",
      "intent.json"
    );
    const intentBytes = readFileSync(intentFile);
    const stagedBeforeRetry = git(
      fixture.destination,
      "diff",
      "--cached",
      "--binary"
    );

    process.env.GOAL_CONTROL_NOW = "2100-01-01T00:00:00.000Z";
    const receipt = importSnapshot(fixture, snapshot);

    expect(receipt).toMatchObject({
      import_receipt_id: "import-source-operation",
      idempotent: false,
      expected_tree: snapshot.expected_tree,
      materialized_tree: snapshot.expected_tree,
    });
    expect(readFileSync(intentFile)).toEqual(intentBytes);
    expect(git(fixture.destination, "diff", "--cached", "--binary")).toBe(
      stagedBeforeRetry
    );
  });

  it.each([
    [
      "reservation",
      "GOAL_CONTROL_TEST_FAULT_SOURCE_IMPORT_INTENT_AFTER_ATOMIC_RESERVATION",
    ],
    [
      "partial payload",
      "GOAL_CONTROL_TEST_FAULT_SOURCE_IMPORT_INTENT_DURING_ATOMIC_TEMP_WRITE",
    ],
    [
      "fsynced payload",
      "GOAL_CONTROL_TEST_FAULT_SOURCE_IMPORT_INTENT_AFTER_ATOMIC_TEMP_FSYNC",
    ],
  ] as const)(
    "exact-retries a SOURCE_IMPORT after %s transport SIGKILL",
    (_stage, fault) => {
      const snapshot = exportSnapshot(fixture);
      expect(
        runImportChild(fixture, snapshot.snapshot_id, fault)
      ).toBe(86);
      const generationFile = path.join(
        fixture.controlDir,
        ".generation.json"
      );
      const odd = JSON.parse(
        readFileSync(generationFile, "utf8")
      ) as {
        generation: number;
        active_transaction: { kind: string };
      };
      expect(odd.generation % 2).toBe(1);
      expect(odd.active_transaction.kind).toBe("SOURCE_IMPORT");

      const receipt = importSnapshot(fixture, snapshot);

      expect(receipt).toMatchObject({
        import_receipt_id: "import-source-operation",
        expected_tree: snapshot.expected_tree,
        materialized_tree: snapshot.expected_tree,
      });
      expect(
        (
          JSON.parse(readFileSync(generationFile, "utf8")) as {
            generation: number;
          }
        ).generation % 2
      ).toBe(0);
    }
  );

  it("exact-retries a real SOURCE_IMPORT after adoption-marker SIGKILL", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_IMPORT_ADOPTION_MARKER_UNLINK",
        "import-source-operation",
        "sigkill"
      )
    ).toBe("SIGKILL");

    const receipt = importSnapshot(fixture, snapshot);

    expect(receipt).toMatchObject({
      import_receipt_id: "import-source-operation",
      expected_tree: snapshot.expected_tree,
      materialized_tree: snapshot.expected_tree,
    });
  });

  it("rejects an unknown import-intent hardlink even for an empty snapshot", () => {
    writeFileSync(path.join(fixture.source, "tracked.txt"), "candidate\n");
    writeFileSync(
      path.join(fixture.source, "binary.bin"),
      Buffer.from([0, 255, 2, 3, 4])
    );
    rmSync(path.join(fixture.source, "notes"), {
      recursive: true,
      force: true,
    });
    rmSync(path.join(fixture.source, "recover.sh"), { force: true });
    rmSync(path.join(fixture.source, "note-link"), { force: true });
    expect(git(fixture.source, "status", "--porcelain")).toBe("");
    const snapshot = exportSnapshot(fixture);
    expect(snapshot.expected_paths).toEqual([]);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_IMPORT_ADOPTION_MARKER_UNLINK",
        "import-source-operation",
        "sigkill"
      )
    ).toBe("SIGKILL");
    const intentFile = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "import-intents",
      "import-source-operation",
      "intent.json"
    );
    const foreignLink = path.join(
      fixture.controlDir,
      "foreign-import-intent-link"
    );
    linkSync(intentFile, foreignLink);
    const intentBytes = readFileSync(intentFile);

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_PATH_COLLISION"
    );
    expect(readFileSync(intentFile)).toEqual(intentBytes);
    expect(readFileSync(foreignLink)).toEqual(intentBytes);
    expect(lstatSync(intentFile).nlink).toBe(2);
  });

  it("cleans an empty import-intent staging orphan and retries without a permanent control-store deadlock", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "empty" }
    );
    expect(
      readdirSync(intentParent).some((name) =>
        name.startsWith(".init-import-")
      )
    ).toBe(true);

    const receipt = importSnapshot(fixture, snapshot);

    expect(receipt.import_receipt_id).toBe("import-source-operation");
    expect(
      readdirSync(intentParent).some((name) =>
        name.startsWith(".init-import-")
      )
    ).toBe(false);
  });

  it("recovers an empty request-bound import staging with a max-length import ID", () => {
    const snapshot = exportSnapshot(fixture);
    const importId = `i${"x".repeat(199)}`;
    expect(importId).toHaveLength(200);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      {
        importId,
        state: "empty",
      }
    );
    const staging = readdirSync(intentParent).filter((name) =>
      name.startsWith(".init-import-")
    );
    expect(staging).toHaveLength(1);
    expect(Buffer.byteLength(staging[0])).toBeLessThanOrEqual(255);
    expect(readdirSync(path.join(intentParent, staging[0]))).toEqual([]);

    const receipt = importSnapshot(
      fixture,
      snapshot,
      fixture.destination,
      importId
    );

    expect(receipt.import_receipt_id).toBe(importId);
    expect(existsSync(path.join(intentParent, importId, "intent.json"))).toBe(
      true
    );
  });

  it("preserves empty import staging when the same ID resolves to a different destination request", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "empty" }
    );
    const before = directorySnapshot(intentParent);
    git(fixture.destination, "branch", "-m", "task/destination-renamed");

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_OPERATION_CONFLICT"
    );
    expect(directorySnapshot(intentParent)).toEqual(before);
  });

  it("preserves empty import staging when the same request resolves under replacement DEV authority", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "empty" }
    );
    const before = directorySnapshot(intentParent);
    const task = fixture.loaded.snapshot.tasks["TASK-A"];
    const originalDev = task.sessions.DEV;
    task.session_history.DEV.push({
      ...originalDev,
      status: "terminal",
    });
    const replacement = createCapability(
      path.dirname(fixture.devCapabilityFile),
      "dev-successor-replacement"
    );
    task.sessions.DEV = {
      ...originalDev,
      host_id: "host-replacement",
      attempt: 3,
      capability_file: replacement.file,
      capability_sha256: replacement.verifier,
    };

    expectControlCode(
      () =>
        importSnapshot(
          fixture,
          snapshot,
          fixture.destination,
          "import-source-operation",
          replacement.file
        ),
      "HANDOFF_OPERATION_CONFLICT"
    );
    expect(directorySnapshot(intentParent)).toEqual(before);
  });

  it("rejects non-private empty import staging without deleting it", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "empty" }
    );
    const staging = readdirSync(intentParent).find((name) =>
      name.startsWith(".init-import-")
    );
    expect(staging).toBeDefined();
    const stagingDirectory = path.join(intentParent, staging as string);
    chmodSync(stagingDirectory, 0o755);

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_STAGING_INVALID"
    );
    expect(existsSync(stagingDirectory)).toBe(true);
    expect(lstatSync(stagingDirectory).mode & 0o777).toBe(0o755);
  });

  it("fails closed and preserves multiple import staging candidates", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "empty" }
    );
    const legacy = path.join(
      intentParent,
      `.init-import-source-operation.999.tmp-${"a".repeat(24)}`
    );
    mkdirSync(legacy, { mode: 0o700 });
    const before = directorySnapshot(intentParent);

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_STAGING_AMBIGUOUS"
    );
    expect(directorySnapshot(intentParent)).toEqual(before);
  });

  it("fails closed and preserves a malformed import staging lookalike", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "empty" }
    );
    const staging = readdirSync(intentParent).find((name) =>
      name.startsWith(".init-import-")
    );
    expect(staging).toBeDefined();
    mkdirSync(path.join(intentParent, `${staging as string}-lookalike`), {
      mode: 0o700,
    });
    const before = directorySnapshot(intentParent);

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_STAGING_INVALID"
    );
    expect(directorySnapshot(intentParent)).toEqual(before);
  });

  it("promotes a sealed import-intent atomic temp and completes the exact retry", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "atomic-temp" }
    );
    const staging = readdirSync(intentParent).filter((name) =>
      name.startsWith(".init-import-")
    );
    expect(staging).toHaveLength(1);
    const stagedEntries = readdirSync(
      path.join(intentParent, staging[0])
    );
    expect(stagedEntries).toHaveLength(1);
    expect(stagedEntries[0]).toMatch(
      /^\.intent\.json\.[1-9][0-9]*\.tmp-[0-9a-f]{24}$/
    );

    const receipt = importSnapshot(fixture, snapshot);

    expect(receipt.import_receipt_id).toBe("import-source-operation");
    expect(
      existsSync(
        path.join(
          intentParent,
          "import-source-operation",
          "intent.json"
        )
      )
    ).toBe(true);
    expect(
      readdirSync(intentParent).some((name) =>
        name.startsWith(".init-import-")
      )
    ).toBe(false);
  });

  it("fails closed on canonical-plus-atomic import intent inventory and preserves both", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "canonical" }
    );
    const staging = readdirSync(intentParent).find((name) =>
      name.startsWith(".init-import-")
    );
    expect(staging).toBeDefined();
    const stagingDirectory = path.join(intentParent, staging as string);
    const canonical = readFileSync(
      path.join(stagingDirectory, "intent.json")
    );
    writeFileSync(
      path.join(
        stagingDirectory,
        `.intent.json.999.tmp-${"b".repeat(24)}`
      ),
      canonical,
      { mode: 0o600 }
    );
    const before = directorySnapshot(stagingDirectory);

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_STAGING_INVALID"
    );
    expect(directorySnapshot(stagingDirectory)).toEqual(before);
  });

  it("promotes a sealed import-intent staging record after process exit and DEV lease expiry", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "canonical" }
    );
    const staging = readdirSync(intentParent).filter((name) =>
      name.startsWith(".init-import-")
    );
    expect(staging).toHaveLength(1);
    const stagedBytes = readFileSync(
      path.join(intentParent, staging[0], "intent.json")
    );

    process.env.GOAL_CONTROL_NOW = "2100-01-01T00:00:00.000Z";
    const receipt = importSnapshot(fixture, snapshot);
    const stableIntent = path.join(
      intentParent,
      "import-source-operation",
      "intent.json"
    );

    expect(receipt.import_receipt_id).toBe("import-source-operation");
    expect(readFileSync(stableIntent)).toEqual(stagedBytes);
    expect(
      readdirSync(intentParent).some((name) =>
        name.startsWith(".init-import-")
      )
    ).toBe(false);
  });

  it("preserves a sealed import intent when the retry supplies the wrong DEV capability", () => {
    const snapshot = exportSnapshot(fixture);
    const { intentParent } = installLegacyImportIntentStaging(
      fixture,
      snapshot,
      { state: "canonical" }
    );
    const staging = readdirSync(intentParent).find((name) =>
      name.startsWith(".init-import-")
    );
    expect(staging).toBeDefined();
    const sealedBytes = readFileSync(
      path.join(intentParent, staging as string, "intent.json")
    );
    const bootstrapProbe = installPendingBootstrapReadOnlyProbe(fixture);
    const goalBefore = directorySnapshot(bootstrapProbe.goalDirectory);
    const intentBefore = directorySnapshot(intentParent);
    const generationFile = path.join(
      fixture.controlDir,
      ".generation.json"
    );
    const generationBefore = readFileSync(generationFile);

    expectControlCode(
      () =>
        importSnapshot(
          fixture,
          snapshot,
          fixture.destination,
          "import-source-operation",
          fixture.captainCapabilityFile
        ),
      "CAPABILITY_INVALID"
    );
    expect(directorySnapshot(intentParent)).toEqual(intentBefore);
    expect(directorySnapshot(bootstrapProbe.goalDirectory)).toEqual(
      goalBefore
    );
    expect(readFileSync(generationFile)).toEqual(generationBefore);
    expect(bootstrapProbe.calls).toHaveLength(1);
    expect(bootstrapProbe.calls[0]).toMatchObject({
      repairHeads: false,
      repairBootstrapConsumption: false,
    });
    expect(readFileSync(bootstrapProbe.bootstrapFile)).toEqual(
      bootstrapProbe.bootstrapBytes
    );
    expect(
      readFileSync(path.join(intentParent, staging as string, "intent.json"))
    ).toEqual(sealedBytes);
    expect(
      existsSync(
        path.join(intentParent, "import-source-operation", "intent.json")
      )
    ).toBe(false);
  });

  it("abruptly exits after durable receipt publication and returns the sealed receipt on retry", () => {
    const snapshot = exportSnapshot(fixture);
    expect(
      runImportChild(
        fixture,
        snapshot.snapshot_id,
        "GOAL_CONTROL_TEST_FAULT_AFTER_RECEIPT_PUBLISH"
      )
    ).toBe(87);

    const receipt = importSnapshot(fixture, snapshot);
    expect(receipt).toMatchObject({
      import_receipt_id: "import-source-operation",
      snapshot_id: snapshot.snapshot_id,
      idempotent: true,
      expected_tree: snapshot.expected_tree,
      materialized_tree: snapshot.expected_tree,
    });
  });

  it("rejects a different import ID after the snapshot already has a sealed receipt", () => {
    const snapshot = exportSnapshot(fixture);
    importSnapshot(fixture, snapshot);
    expectControlCode(
      () =>
        importSnapshot(
          fixture,
          snapshot,
          fixture.destination,
          "import-different-operation"
        ),
      "HANDOFF_SNAPSHOT_ALREADY_IMPORTED"
    );
  });

  it("creates and verifies the same deterministic checkpoint path for an empty snapshot", () => {
    git(fixture.source, "restore", "tracked.txt", "binary.bin");
    rmSync(path.join(fixture.source, "notes"), { recursive: true, force: true });
    rmSync(path.join(fixture.source, "recover.sh"), { force: true });
    rmSync(path.join(fixture.source, "note-link"), { force: true });

    const snapshot = exportSnapshot(fixture);
    expect(snapshot.total_bytes).toBe(0);
    expect(snapshot.expected_paths).toEqual([]);
    const receipt = importSnapshot(fixture, snapshot);
    expect(receipt.expected_tree).toBe(snapshot.expected_tree);
    expect(receipt.materialized_tree).toBe(snapshot.expected_tree);
    expect(receipt.materialized_patch_bytes).toBe(0);
    expect(git(fixture.destination, "status", "--porcelain=v1")).toBe("");

    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    const importCommit = checkpoint.checkpoint_sha;
    expect(checkpoint).toMatchObject({
      parent_sha: fixture.observedHead,
      tree_sha: snapshot.expected_tree,
      idempotent: false,
    });
    expect(
      verifyRecoveryHandoff(fixture.destination, {
        goalId: "goal-handoff",
        taskId: "TASK-A",
        payload: verificationPayload(snapshot, receipt, importCommit),
      })
    ).toMatchObject({ verified: true, import_commit: importCommit });
    expect(git(fixture.destination, "rev-parse", `${importCommit}^`)).toBe(
      fixture.observedHead
    );
    expect(git(fixture.destination, "rev-parse", `${importCommit}^{tree}`)).toBe(
      snapshot.expected_tree
    );
  });

  it("returns the same deterministic checkpoint after publish-before-response loss and repeat", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_CHECKPOINT_PUBLISH = "1";
    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "TEST_FAULT_AFTER_SOURCE_CHECKPOINT_PUBLISH"
    );
    delete process.env.GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_CHECKPOINT_PUBLISH;

    const publishedHead = git(fixture.destination, "rev-parse", "HEAD");
    const replay = checkpointSnapshot(fixture, snapshot, receipt);
    expect(replay).toMatchObject({
      checkpoint_sha: publishedHead,
      parent_sha: fixture.observedHead,
      tree_sha: snapshot.expected_tree,
      idempotent: true,
    });
    expect(checkpointSnapshot(fixture, snapshot, receipt)).toEqual(replay);
    expect(git(fixture.destination, "rev-list", "--count", fixture.observedHead + "..HEAD")).toBe(
      "1"
    );
  });

  it("republishes the same checkpoint when a completed branch was moved back to the sealed base", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    const branchRef = git(fixture.destination, "symbolic-ref", "HEAD");
    const fenceRoot = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "checkpoint-fences"
    );
    const fenceDirectory = path.join(fenceRoot, readdirSync(fenceRoot)[0]);
    const preparedFile = path.join(fenceDirectory, "prepared.json");
    const completedFile = path.join(fenceDirectory, "completed.json");
    const preparedBefore = readFileSync(preparedFile);
    const completedBefore = readFileSync(completedFile);

    git(
      fixture.repository,
      "update-ref",
      branchRef,
      fixture.observedHead,
      checkpoint.checkpoint_sha
    );
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      fixture.observedHead
    );

    const replay = checkpointSnapshot(fixture, snapshot, receipt);
    expect(replay).toMatchObject({
      checkpoint_sha: checkpoint.checkpoint_sha,
      parent_sha: fixture.observedHead,
      tree_sha: snapshot.expected_tree,
      idempotent: false,
    });
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      checkpoint.checkpoint_sha
    );
    expect(readFileSync(preparedFile)).toEqual(preparedBefore);
    expect(readFileSync(completedFile)).toEqual(completedBefore);
    expect(
      listPendingTaskOperations(
        fixture.controlDir,
        "goal-handoff",
        "TASK-A"
      )
    ).toEqual([]);
    expect(existsSync(`${gitPath(fixture.destination, "index")}.lock`)).toBe(
      false
    );
  });

  it("rejects a completed checkpoint replay when reflog history contains a foreign transition", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    const branchRef = git(fixture.destination, "symbolic-ref", "HEAD");
    const branchReflog = gitPath(
      fixture.destination,
      `logs/${branchRef}`
    );

    git(
      fixture.repository,
      "update-ref",
      branchRef,
      fixture.observedHead,
      checkpoint.checkpoint_sha
    );
    git(
      fixture.repository,
      "update-ref",
      branchRef,
      checkpoint.checkpoint_sha,
      fixture.observedHead
    );
    git(
      fixture.repository,
      "update-ref",
      branchRef,
      fixture.observedHead,
      checkpoint.checkpoint_sha
    );
    const reflogBefore = readFileSync(branchReflog);

    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "HANDOFF_CHECKPOINT_REF_LOCK_INVALID"
    );

    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      fixture.observedHead
    );
    expect(readFileSync(branchReflog)).toEqual(reflogBefore);
    expect(existsSync(`${gitPath(fixture.destination, "index")}.lock`)).toBe(
      false
    );
  });

  it("does not overwrite a third-party branch move after checkpoint completion", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    const branchRef = git(fixture.destination, "symbolic-ref", "HEAD");
    const fenceRoot = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "checkpoint-fences"
    );
    const fenceDirectory = path.join(fenceRoot, readdirSync(fenceRoot)[0]);
    const preparedFile = path.join(fenceDirectory, "prepared.json");
    const completedFile = path.join(fenceDirectory, "completed.json");
    const preparedBefore = readFileSync(preparedFile);
    const completedBefore = readFileSync(completedFile);

    git(
      fixture.repository,
      "update-ref",
      branchRef,
      fixture.baseHead,
      checkpoint.checkpoint_sha
    );
    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "HANDOFF_CHECKPOINT_HEAD_MISMATCH"
    );

    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      fixture.baseHead
    );
    expect(readFileSync(preparedFile)).toEqual(preparedBefore);
    expect(readFileSync(completedFile)).toEqual(completedBefore);
    expect(existsSync(`${gitPath(fixture.destination, "index")}.lock`)).toBe(
      false
    );
  });

  it("preserves an absent branch reflog while publishing the checkpoint", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const branchRef = git(fixture.destination, "symbolic-ref", "HEAD");
    const branchReflog = gitPath(
      fixture.destination,
      `logs/${branchRef}`
    );
    rmSync(branchReflog, { force: true });
    expect(existsSync(branchReflog)).toBe(false);

    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    expect(existsSync(branchReflog)).toBe(false);
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      checkpoint.checkpoint_sha
    );
  });

  it("rejects an otherwise exact human-authored commit instead of treating it as the fixed checkpoint", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    git(fixture.destination, "commit", "-qm", "manual recovery checkpoint");
    const divergentHead = git(fixture.destination, "rev-parse", "HEAD");

    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "HANDOFF_CHECKPOINT_HEAD_MISMATCH"
    );
    expectControlCode(
      () =>
        verifyRecoveryHandoff(fixture.destination, {
          goalId: "goal-handoff",
          taskId: "TASK-A",
          payload: verificationPayload(snapshot, receipt, divergentHead),
        }),
      "HANDOFF_CHECKPOINT_COMMIT_MISMATCH"
    );
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(divergentHead);
  });

  it("rejects extra dirty state without resetting or consuming it", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const extra = path.join(fixture.destination, "unexpected.txt");
    writeFileSync(extra, "must be preserved\n");

    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "HANDOFF_CHECKPOINT_DIRTY"
    );
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      fixture.observedHead
    );
    expect(readFileSync(extra, "utf8")).toBe("must be preserved\n");
    expect(
      git(fixture.destination, "diff", "--cached", "--name-only")
        .split("\n")
        .filter(Boolean)
        .sort()
    ).toEqual(snapshot.expected_paths);
  });

  it("rejects checkpoint while MERGE_HEAD exists and preserves the staged import exactly", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const sentinel = writeMergeHeadSentinel(
      fixture.destination,
      fixture.observedHead
    );
    const sentinelBefore = readFileSync(sentinel);
    const receiptBefore = readFileSync(receipt.import_receipt_file);
    const destinationBefore = directorySnapshot(fixture.destination);
    const headBefore = git(fixture.destination, "rev-parse", "HEAD");
    const indexTreeBefore = git(fixture.destination, "write-tree");

    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "HANDOFF_GIT_OPERATION_IN_PROGRESS"
    );

    expect(readFileSync(sentinel)).toEqual(sentinelBefore);
    expect(readFileSync(receipt.import_receipt_file)).toEqual(receiptBefore);
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(headBefore);
    expect(git(fixture.destination, "write-tree")).toBe(indexTreeBefore);
    expect(directorySnapshot(fixture.destination)).toEqual(destinationBefore);
  });

  it("refuses checkpoint before ref publication when another Git writer already holds index.lock", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const indexLock = `${gitPath(fixture.destination, "index")}.lock`;
    const receiptBefore = readFileSync(receipt.import_receipt_file);
    const headBefore = git(fixture.destination, "rev-parse", "HEAD");
    const indexTreeBefore = git(fixture.destination, "write-tree");
    const descriptor = openSync(indexLock, "wx", 0o600);

    try {
      expectControlCode(
        () => checkpointSnapshot(fixture, snapshot, receipt),
        "HANDOFF_GIT_INDEX_LOCKED"
      );
      expect(existsSync(indexLock)).toBe(true);
    } finally {
      closeSync(descriptor);
      rmSync(indexLock, { force: true });
    }

    expect(readFileSync(receipt.import_receipt_file)).toEqual(receiptBefore);
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(headBefore);
    expect(git(fixture.destination, "write-tree")).toBe(indexTreeBefore);
    expect(
      git(fixture.destination, "diff", "--cached", "--name-only")
        .split("\n")
        .filter(Boolean)
        .sort()
    ).toEqual(snapshot.expected_paths);
  });

  it("holds index.lock across checkpoint validation and ref publication so a competing Git writer cannot enter", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const fsModule = nodeRequire("fs") as { openSync: typeof openSync };
    const originalOpenSync = fsModule.openSync;
    const indexLock = `${gitPath(fixture.destination, "index")}.lock`;
    let attempted = false;
    let blockedByIndexLock = false;
    const openSpy = jest
      .spyOn(fsModule, "openSync")
      .mockImplementation((file, flags, mode) => {
        const descriptor = originalOpenSync(file, flags, mode);
        if (!attempted && String(file) === indexLock) {
          attempted = true;
          try {
            execFileSync(
              "git",
              ["add", "--refresh", "--", "."],
              {
                cwd: fixture.destination,
                encoding: "utf8",
                stdio: "pipe",
              }
            );
          } catch (error) {
            const stderr = String(
              (error as { stderr?: string | Buffer }).stderr || ""
            );
            blockedByIndexLock = stderr.includes("index.lock");
          }
        }
        return descriptor;
      });

    let checkpoint!: RecoveryCheckpoint;
    try {
      checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    } finally {
      openSpy.mockRestore();
    }

    expect(attempted).toBe(true);
    expect(blockedByIndexLock).toBe(true);
    expect(checkpoint).toMatchObject({
      parent_sha: fixture.observedHead,
      tree_sha: snapshot.expected_tree,
      idempotent: false,
    });
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      checkpoint.checkpoint_sha
    );
    expect(existsSync(indexLock)).toBe(false);
  });

  it("blocks an ordinary-user bisect during ref publication and fails closed if a privileged process bypasses the permission fence", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const fsModule = nodeRequire("fs") as { chmodSync: typeof chmodSync };
    const originalChmodSync = fsModule.chmodSync;
    const gitDir = realpathSync(
      git(
        fixture.destination,
        "rev-parse",
        "--path-format=absolute",
        "--absolute-git-dir"
      )
    );
    const originalMode = lstatSync(gitDir).mode & 0o7777;
    const fencedMode = originalMode & ~0o222;
    const bisectStart = gitPath(fixture.destination, "BISECT_START");
    const bisectLog = gitPath(fixture.destination, "BISECT_LOG");
    let attempted = false;
    let bisectBlocked = false;
    const chmodSpy = jest
      .spyOn(fsModule, "chmodSync")
      .mockImplementation((target, mode) => {
        originalChmodSync(target, mode);
        if (
          !attempted &&
          String(target) === gitDir &&
          Number(mode) === fencedMode
        ) {
          attempted = true;
          try {
            execFileSync("git", ["bisect", "start"], {
              cwd: fixture.destination,
              encoding: "utf8",
              stdio: "pipe",
            });
          } catch {
            bisectBlocked = !existsSync(bisectStart);
          }
        }
      });

    let checkpoint: RecoveryCheckpoint | undefined;
    let checkpointError: unknown;
    try {
      checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    } catch (error: unknown) {
      checkpointError = error;
    } finally {
      chmodSpy.mockRestore();
    }

    expect(attempted).toBe(true);
    const isPrivileged =
      typeof process.geteuid === "function"
        ? process.geteuid() === 0
        : typeof process.getuid === "function" && process.getuid() === 0;
    if (isPrivileged) {
      expect(bisectBlocked).toBe(false);
      expect((checkpointError as { code?: string }).code).toBe(
        "HANDOFF_GIT_OPERATION_IN_PROGRESS"
      );
      expect(checkpoint).toBeUndefined();
      expect(existsSync(bisectStart)).toBe(true);
      expect(existsSync(bisectLog)).toBe(true);
      expect(lstatSync(gitDir).mode & 0o7777).toBe(originalMode);
      expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
        fixture.observedHead
      );
      return;
    }

    if (checkpointError !== undefined) throw checkpointError;
    expect(bisectBlocked).toBe(true);
    expect(existsSync(bisectStart)).toBe(false);
    expect(lstatSync(gitDir).mode & 0o7777).toBe(originalMode);
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      checkpoint!.checkpoint_sha
    );
  });

  it("treats a sentinel created after the fence release point as later drift and bind rejects it", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const fsModule = nodeRequire("fs") as { chmodSync: typeof chmodSync };
    const originalChmodSync = fsModule.chmodSync;
    const gitDir = realpathSync(
      git(
        fixture.destination,
        "rev-parse",
        "--path-format=absolute",
        "--absolute-git-dir"
      )
    );
    const originalMode = lstatSync(gitDir).mode & 0o7777;
    const bisectStart = gitPath(fixture.destination, "BISECT_START");
    let attempted = false;
    const chmodSpy = jest
      .spyOn(fsModule, "chmodSync")
      .mockImplementation((target, mode) => {
        originalChmodSync(target, mode);
        if (
          !attempted &&
          String(target) === gitDir &&
          Number(mode) === originalMode
        ) {
          attempted = true;
          execFileSync("git", ["bisect", "start"], {
            cwd: fixture.destination,
            encoding: "utf8",
            stdio: "pipe",
          });
        }
      });

    let checkpoint!: RecoveryCheckpoint;
    try {
      checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    } finally {
      chmodSpy.mockRestore();
    }

    expect(attempted).toBe(true);
    expect(existsSync(bisectStart)).toBe(true);
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      checkpoint.checkpoint_sha
    );
    expectControlCode(
      () =>
        verifyRecoveryHandoff(fixture.destination, {
          goalId: "goal-handoff",
          taskId: "TASK-A",
          payload: verificationPayload(
            snapshot,
            receipt,
            checkpoint.checkpoint_sha
          ),
        }),
      "HANDOFF_GIT_OPERATION_IN_PROGRESS"
    );
  });

  it.each([
    [
      "empty exact index-lock temp",
      "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_CREATE",
      106,
    ],
    [
      "partial exact index-lock temp",
      "GOAL_CONTROL_TEST_EXIT_DURING_CHECKPOINT_INDEX_LOCK_WRITE",
      107,
    ],
    [
      "fsynced exact index-lock temp",
      "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_FSYNC",
      108,
    ],
    [
      "no-clobber published index lock",
      "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_PUBLISH",
      109,
    ],
  ] as const)(
    "exact-retries checkpoint after abrupt %s",
    (_label, fault, exitCode) => {
      const snapshot = exportSnapshot(fixture);
      const receipt = importSnapshot(fixture, snapshot);
      const gitDir = realpathSync(
        git(
          fixture.destination,
          "rev-parse",
          "--path-format=absolute",
          "--absolute-git-dir"
        )
      );
      const indexFile = gitPath(fixture.destination, "index");
      const indexLock = `${indexFile}.lock`;
      const originalMode = lstatSync(gitDir).mode & 0o7777;
      const indexBytesBefore = readFileSync(indexFile);
      const indexMtimeBefore = lstatSync(indexFile, { bigint: true }).mtimeNs;

      expect(
        runCheckpointChild(
          fixture,
          snapshot.snapshot_id,
          receipt.import_receipt_id,
          fault
        )
      ).toBe(exitCode);
      expect(lstatSync(gitDir).mode & 0o7777).toBe(originalMode);
      expect(readFileSync(indexFile)).toEqual(indexBytesBefore);
      expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
        indexMtimeBefore
      );

      const gitDirBeforeLockRecovery = directorySnapshot(gitDir);
      const destinationBeforeLockRecovery = directorySnapshot(
        fixture.destination
      );
      // As with import recovery, the first caller may reap the killed store
      // writer. That transport repair must remain source-zero-write.
      expectControlCode(
        () =>
          checkpointSnapshot(
            fixture,
            snapshot,
            receipt,
            fixture.captainCapabilityFile
          ),
        "CAPABILITY_INVALID"
      );
      expect(directorySnapshot(gitDir)).toEqual(
        gitDirBeforeLockRecovery
      );
      expect(directorySnapshot(fixture.destination)).toEqual(
        destinationBeforeLockRecovery
      );
      expect(readFileSync(indexFile)).toEqual(indexBytesBefore);
      expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
        indexMtimeBefore
      );

      const controlBeforeRejectedCapability = directorySnapshot(
        fixture.controlDir
      );
      const gitDirBeforeRejectedCapability = directorySnapshot(gitDir);
      const destinationBeforeRejectedCapability = directorySnapshot(
        fixture.destination
      );
      expectControlCode(
        () =>
          checkpointSnapshot(
            fixture,
            snapshot,
            receipt,
            fixture.captainCapabilityFile
          ),
        "CAPABILITY_INVALID"
      );
      expect(directorySnapshot(fixture.controlDir)).toEqual(
        controlBeforeRejectedCapability
      );
      expect(directorySnapshot(gitDir)).toEqual(
        gitDirBeforeRejectedCapability
      );
      expect(directorySnapshot(fixture.destination)).toEqual(
        destinationBeforeRejectedCapability
      );
      expect(readFileSync(indexFile)).toEqual(indexBytesBefore);
      expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
        indexMtimeBefore
      );

      const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
      expect(checkpoint).toMatchObject({
        parent_sha: fixture.observedHead,
        tree_sha: snapshot.expected_tree,
      });
      expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
        checkpoint.checkpoint_sha
      );
      expect(lstatSync(gitDir).mode & 0o7777).toBe(originalMode);
      expect(existsSync(indexLock)).toBe(false);
      expect(
        readdirSync(gitDir).filter((name) =>
          name.startsWith(".goalctl-checkpoint-index-lock-")
        )
      ).toEqual([]);
      expect(readFileSync(indexFile)).toEqual(indexBytesBefore);
      expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
        indexMtimeBefore
      );
    }
  );

  it("fails closed without deleting a divergent exact checkpoint index-lock temp", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const gitDir = realpathSync(
      git(
        fixture.destination,
        "rev-parse",
        "--path-format=absolute",
        "--absolute-git-dir"
      )
    );
    expect(
      runCheckpointChild(
        fixture,
        snapshot.snapshot_id,
        receipt.import_receipt_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_CREATE"
      )
    ).toBe(106);
    const temporaries = readdirSync(gitDir)
      .filter((name) =>
        name.startsWith(".goalctl-checkpoint-index-lock-")
      )
      .map((name) => path.join(gitDir, name));
    expect(temporaries).toHaveLength(1);
    writeFileSync(temporaries[0], "divergent checkpoint token\n");
    const gitDirBefore = directorySnapshot(gitDir);
    const destinationBefore = directorySnapshot(fixture.destination);
    const indexFile = gitPath(fixture.destination, "index");
    const indexBytesBefore = readFileSync(indexFile);
    const indexMtimeBefore = lstatSync(indexFile, { bigint: true }).mtimeNs;

    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "HANDOFF_GIT_INDEX_LOCKED"
    );

    expect(directorySnapshot(gitDir)).toEqual(gitDirBefore);
    expect(directorySnapshot(fixture.destination)).toEqual(destinationBefore);
    expect(readFileSync(indexFile)).toEqual(indexBytesBefore);
    expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
      indexMtimeBefore
    );
  });

  it("fails closed without deleting a checkpoint temp from a foreign request", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const gitDir = realpathSync(
      git(
        fixture.destination,
        "rev-parse",
        "--path-format=absolute",
        "--absolute-git-dir"
      )
    );
    expect(
      runCheckpointChild(
        fixture,
        snapshot.snapshot_id,
        receipt.import_receipt_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_CREATE"
      )
    ).toBe(106);
    const foreignTemporary = path.join(
      gitDir,
      `.goalctl-checkpoint-index-lock-${"f".repeat(64)}.tmp`
    );
    writeFileSync(foreignTemporary, "foreign checkpoint request\n", {
      mode: 0o600,
    });
    const gitDirBefore = directorySnapshot(gitDir);
    const destinationBefore = directorySnapshot(fixture.destination);
    const indexFile = gitPath(fixture.destination, "index");
    const indexBytesBefore = readFileSync(indexFile);
    const indexMtimeBefore = lstatSync(indexFile, { bigint: true }).mtimeNs;

    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "HANDOFF_GIT_INDEX_LOCKED"
    );

    expect(directorySnapshot(gitDir)).toEqual(gitDirBefore);
    expect(directorySnapshot(fixture.destination)).toEqual(destinationBefore);
    expect(readFileSync(indexFile)).toEqual(indexBytesBefore);
    expect(lstatSync(indexFile, { bigint: true }).mtimeNs).toBe(
      indexMtimeBefore
    );
  });

  it.each([
    ["GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_GIT_FENCE", 99],
    ["GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_PUBLISH", 100],
    ["GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_FENCE_COMPLETION", 101],
    ["GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_FENCE", 112],
    ["GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_LOCK", 114],
    ["GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_MUTATION", 115],
  ] as const)(
    "exact retry adopts and cleans a durable linked-worktree Git fence after abrupt %s",
    (fault, exitCode) => {
      const snapshot = exportSnapshot(fixture);
      const receipt = importSnapshot(fixture, snapshot);
      const gitDir = realpathSync(
        git(
          fixture.destination,
          "rev-parse",
          "--path-format=absolute",
          "--absolute-git-dir"
        )
      );
      const indexLock = `${gitPath(fixture.destination, "index")}.lock`;
      const originalMode = lstatSync(gitDir).mode & 0o7777;

      expect(
        runCheckpointChild(
          fixture,
          snapshot.snapshot_id,
          receipt.import_receipt_id,
          fault
        )
      ).toBe(exitCode);
      expect(lstatSync(gitDir).mode & 0o7777).toBe(
        originalMode & ~0o222
      );
      expect(existsSync(indexLock)).toBe(true);
      expect(
        listPendingTaskOperations(
          fixture.controlDir,
          "goal-handoff",
          "TASK-A"
        ).map((operation) => operation.kind)
      ).toContain("SOURCE_CHECKPOINT");

      const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
      expect(checkpoint).toMatchObject({
        parent_sha: fixture.observedHead,
        tree_sha: snapshot.expected_tree,
      });
      expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
        checkpoint.checkpoint_sha
      );
      expect(lstatSync(gitDir).mode & 0o7777).toBe(originalMode);
      expect(existsSync(indexLock)).toBe(false);
      expect(
        listPendingTaskOperations(
          fixture.controlDir,
          "goal-handoff",
          "TASK-A"
        ).map((operation) => operation.kind)
      ).not.toContain("SOURCE_CHECKPOINT");
      expect(existsSync(gitPath(fixture.destination, "BISECT_START"))).toBe(
        false
      );

      const fenceRoot = path.join(
        fixture.controlDir,
        "goals",
        "goal-handoff",
        "recovery-handoffs",
        "TASK-A",
        "checkpoint-fences"
      );
      const fenceDirectories = readdirSync(fenceRoot);
      expect(fenceDirectories).toHaveLength(1);
      const fenceDirectory = path.join(fenceRoot, fenceDirectories[0]);
      expect(
        readdirSync(fenceDirectory).sort()
      ).toEqual(["completed.json", "prepared.json"]);
    }
  );

  it("preserves a mismatched durable checkpoint fence token and refuses to guess ownership", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const gitDir = realpathSync(
      git(
        fixture.destination,
        "rev-parse",
        "--path-format=absolute",
        "--absolute-git-dir"
      )
    );
    const indexLock = `${gitPath(fixture.destination, "index")}.lock`;
    const originalMode = lstatSync(gitDir).mode & 0o7777;
    expect(
      runCheckpointChild(
        fixture,
        snapshot.snapshot_id,
        receipt.import_receipt_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_GIT_FENCE"
      )
    ).toBe(99);
    writeFileSync(indexLock, "foreign-owner-token\n");
    const foreignBytes = readFileSync(indexLock);
    const fenceRoot = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "checkpoint-fences"
    );
    const fenceBefore = directorySnapshot(fenceRoot);
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const generationBefore = JSON.parse(
      readFileSync(generationFile, "utf8")
    ).generation as number;

    try {
      expectControlCode(
        () => checkpointSnapshot(fixture, snapshot, receipt),
        "HANDOFF_GIT_INDEX_LOCK_OWNERSHIP_LOST"
      );

      expect(readFileSync(indexLock)).toEqual(foreignBytes);
      expect(lstatSync(gitDir).mode & 0o7777).toBe(
        originalMode & ~0o222
      );
      expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
        fixture.observedHead
      );
      expect(directorySnapshot(fenceRoot)).toEqual(fenceBefore);
      const generationAfter = JSON.parse(
        readFileSync(generationFile, "utf8")
      ).generation as number;
      expect(generationAfter).toBeGreaterThanOrEqual(generationBefore);
      expect(generationAfter % 2).toBe(1);
    } finally {
      chmodSync(gitDir, originalMode);
    }
  });

  it("keeps a fenced gitdir fail-closed when the durable checkpoint index lock is missing", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const gitDir = realpathSync(
      git(
        fixture.destination,
        "rev-parse",
        "--path-format=absolute",
        "--absolute-git-dir"
      )
    );
    const indexLock = `${gitPath(fixture.destination, "index")}.lock`;
    const originalMode = lstatSync(gitDir).mode & 0o7777;
    expect(
      runCheckpointChild(
        fixture,
        snapshot.snapshot_id,
        receipt.import_receipt_id,
        "GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_GIT_FENCE"
      )
    ).toBe(99);
    chmodSync(gitDir, originalMode);
    rmSync(indexLock);
    chmodSync(gitDir, originalMode & ~0o222);
    const fenceRoot = path.join(
      fixture.controlDir,
      "goals",
      "goal-handoff",
      "recovery-handoffs",
      "TASK-A",
      "checkpoint-fences"
    );
    const fenceBefore = directorySnapshot(fenceRoot);
    const generationFile = path.join(fixture.controlDir, ".generation.json");
    const generationBefore = JSON.parse(
      readFileSync(generationFile, "utf8")
    ).generation as number;

    try {
      expectControlCode(
        () => checkpointSnapshot(fixture, snapshot, receipt),
        "HANDOFF_GIT_METADATA_FENCE_INVALID"
      );

      expect(existsSync(indexLock)).toBe(false);
      expect(lstatSync(gitDir).mode & 0o7777).toBe(
        originalMode & ~0o222
      );
      expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
        fixture.observedHead
      );
      expect(directorySnapshot(fenceRoot)).toEqual(fenceBefore);
      const generationAfter = JSON.parse(
        readFileSync(generationFile, "utf8")
      ).generation as number;
      expect(generationAfter).toBeGreaterThanOrEqual(generationBefore);
      expect(generationAfter % 2).toBe(1);
    } finally {
      chmodSync(gitDir, originalMode);
    }
  });

  it("rejects bind verification while MERGE_HEAD exists and preserves the committed checkpoint", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    const sentinel = writeMergeHeadSentinel(
      fixture.destination,
      checkpoint.checkpoint_sha
    );
    const sentinelBefore = readFileSync(sentinel);
    const receiptBefore = readFileSync(receipt.import_receipt_file);
    const destinationBefore = directorySnapshot(fixture.destination);
    const headBefore = git(fixture.destination, "rev-parse", "HEAD");
    expect(git(fixture.destination, "status", "--porcelain=v1")).toBe("");

    expectControlCode(
      () =>
        verifyRecoveryHandoff(fixture.destination, {
          goalId: "goal-handoff",
          taskId: "TASK-A",
          payload: verificationPayload(
            snapshot,
            receipt,
            checkpoint.checkpoint_sha
          ),
        }),
      "HANDOFF_GIT_OPERATION_IN_PROGRESS"
    );

    expect(readFileSync(sentinel)).toEqual(sentinelBefore);
    expect(readFileSync(receipt.import_receipt_file)).toEqual(receiptBefore);
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(headBefore);
    expect(directorySnapshot(fixture.destination)).toEqual(destinationBefore);
  });

  it("rejects an extra file injected synchronously during import and never stages it", () => {
    const snapshot = exportSnapshot(fixture);
    const fsModule = nodeRequire("fs") as { writeFileSync: typeof writeFileSync };
    const originalWriteFileSync = fsModule.writeFileSync;
    const injectedPath = path.join(fixture.destination, "injected-during-import.txt");
    const snapshotBody = Buffer.from("untracked recovery note\n");
    let injected = false;
    const writeSpy = jest
      .spyOn(fsModule, "writeFileSync")
      .mockImplementation((file, data, options) => {
        originalWriteFileSync(file, data, options);
        if (!injected && Buffer.isBuffer(data) && data.equals(snapshotBody)) {
          injected = true;
          originalWriteFileSync(injectedPath, "not part of the sealed snapshot\n");
        }
      });

    try {
      expectControlCode(
        () => importSnapshot(fixture, snapshot),
        "HANDOFF_STAGE_INCOMPLETE"
      );
    } finally {
      writeSpy.mockRestore();
    }

    expect(injected).toBe(true);
    expect(
      git(fixture.destination, "diff", "--cached", "--name-only")
        .split("\n")
        .filter(Boolean)
    ).not.toContain("injected-during-import.txt");
    expect(
      git(fixture.destination, "ls-files", "--others", "--exclude-standard")
        .split("\n")
        .filter(Boolean)
    ).toContain("injected-during-import.txt");
  });

  it("replays an already accepted legacy v1 handoff only through a protocol-sealed migration binding", () => {
    const snapshot = exportSnapshot(
      fixture,
      "snapshot-accepted-legacy-migration"
    );
    const receipt = importSnapshot(
      fixture,
      snapshot,
      fixture.destination,
      "import-accepted-legacy-migration"
    );
    const checkpoint = checkpointSnapshot(fixture, snapshot, receipt);
    const expectedTree = snapshot.expected_tree;
    const expectedPaths = [...snapshot.expected_paths];

    const snapshotManifest = JSON.parse(
      readFileSync(snapshot.snapshot_file, "utf8")
    ) as Record<string, unknown>;
    const trackedPatch = snapshotManifest.tracked_patch as {
      file: string;
      size: number;
      sha256: string;
    };
    const trackedPatchFile = path.join(
      path.dirname(snapshot.snapshot_file),
      trackedPatch.file
    );
    const canonicalTrackedPatch = readFileSync(trackedPatchFile);
    const sectionStarts = [0];
    const sectionBoundary = Buffer.from("\ndiff --git ", "ascii");
    let sectionCursor = 0;
    while (true) {
      const found = canonicalTrackedPatch.indexOf(
        sectionBoundary,
        sectionCursor
      );
      if (found < 0) break;
      sectionStarts.push(found + 1);
      sectionCursor = found + sectionBoundary.length;
    }
    const rolloutStylePatch = Buffer.concat(
      sectionStarts
        .map((start, index) => canonicalTrackedPatch.subarray(
          start,
          sectionStarts[index + 1] ?? canonicalTrackedPatch.length
        ))
        .map((section) => (
          section.includes(Buffer.from("GIT binary patch", "ascii"))
            ? section
            : Buffer.from(section.toString("utf8").replace(
              /^index [0-9a-f]{40}\.\.[0-9a-f]{40}(?: [0-7]{6})?\n/gm,
              ""
            ))
        ))
        .reverse()
    );
    writeFileSync(trackedPatchFile, rolloutStylePatch);
    snapshotManifest.total_bytes =
      Number(snapshotManifest.total_bytes)
      - trackedPatch.size
      + rolloutStylePatch.length;
    trackedPatch.size = rolloutStylePatch.length;
    trackedPatch.sha256 = sha256(rolloutStylePatch);
    snapshotManifest.schema_version = 1;
    delete snapshotManifest.expected_tree;
    delete snapshotManifest.expected_paths;
    delete snapshotManifest.operation_request;
    delete snapshotManifest.acceptance_authority;
    delete snapshotManifest.snapshot_sha256;
    snapshotManifest.snapshot_sha256 = hashObject(snapshotManifest);
    writeFileSync(
      snapshot.snapshot_file,
      `${JSON.stringify(snapshotManifest, null, 2)}\n`
    );
    snapshot.snapshot_sha256 = String(snapshotManifest.snapshot_sha256);

    const receiptManifest = JSON.parse(
      readFileSync(receipt.import_receipt_file, "utf8")
    ) as Record<string, unknown>;
    receiptManifest.schema_version = 1;
    receiptManifest.snapshot_sha256 = snapshot.snapshot_sha256;
    delete receiptManifest.expected_tree;
    delete receiptManifest.materialized_tree;
    delete receiptManifest.acceptance_authority;
    delete receiptManifest.import_receipt_sha256;
    receiptManifest.import_receipt_sha256 = hashObject(receiptManifest);
    writeFileSync(
      receipt.import_receipt_file,
      `${JSON.stringify(receiptManifest, null, 2)}\n`
    );
    receipt.import_receipt_sha256 = String(
      receiptManifest.import_receipt_sha256
    );

    const payload = verificationPayload(
      snapshot,
      receipt,
      checkpoint.checkpoint_sha
    );
    const acceptedEvent = {
      eventId: "accepted-legacy-handoff",
      eventInputSha256: sha256("accepted legacy handoff input"),
      eventSha256: sha256("accepted legacy handoff envelope"),
      eventAcceptedAt: "2026-07-23T12:34:56.000Z",
      eventPayloadSha256: hashObject(payload),
    };
    const acceptedOptions = {
      goalId: "goal-handoff",
      taskId: "TASK-A",
      payload,
      ...acceptedEvent,
    };

    expectControlCode(
      () => verifyAcceptedRecoveryHandoffArtifacts(
        fixture.controlDir,
        acceptedOptions
      ),
      "HANDOFF_EXACT_TREE_REQUIRED"
    );

    git(
      fixture.repository,
      "replace",
      checkpoint.checkpoint_sha,
      fixture.baseHead
    );
    expect(
      git(
        fixture.repository,
        "rev-parse",
        `${checkpoint.checkpoint_sha}^{tree}`
      )
    ).not.toBe(expectedTree);

    const collector = new Map<string, Record<string, unknown>>();
    const objectDirectory = realpathSync(gitPath(fixture.repository, "objects"));
    const objectsBefore = gitObjectDatabaseSnapshot(objectDirectory);
    expect(
      verifyAcceptedRecoveryHandoffArtifacts(fixture.controlDir, {
        ...acceptedOptions,
        legacyRecoveryHandoffBindingCollector: collector,
        legacyRecoveryHandoffRepositoryWorktree: fixture.repository,
      })
    ).toMatchObject({
      verified: true,
      materialized_tree: expectedTree,
    });
    expect(gitObjectDatabaseSnapshot(objectDirectory)).toEqual(objectsBefore);
    expect(collector.size).toBe(1);
    expect([...collector.values()][0]).toMatchObject({
      goal_id: "goal-handoff",
      task_id: "TASK-A",
      event_id: acceptedEvent.eventId,
      event_payload_sha256: acceptedEvent.eventPayloadSha256,
      source_observed_head: snapshot.source_observed_head,
      import_commit: checkpoint.checkpoint_sha,
      expected_tree: expectedTree,
      expected_paths: expectedPaths,
      expected_paths_sha256: hashObject(expectedPaths),
      migration_repository_worktree: fixture.repository,
      migration_repository_head: fixture.baseHead,
      import_commit_object_sha256: expect.stringMatching(
        /^sha256:[0-9a-f]{64}$/
      ),
    });
    git(fixture.repository, "replace", "-d", checkpoint.checkpoint_sha);

    const repositoryCommonDir = realpathSync(
      git(
        fixture.repository,
        "rev-parse",
        "--path-format=absolute",
        "--git-common-dir"
      )
    );
    const unsignedWorktreeBinding = {
      goal_id: "goal-handoff",
      repository_worktree: fixture.repository,
      repository_common_dir: repositoryCommonDir,
      repository_head: fixture.baseHead,
      manifest_sha256: sha256("legacy handoff manifest"),
      frozen_inputs_sha256: sha256("legacy handoff frozen inputs"),
    };
    const worktreeBinding = {
      ...unsignedWorktreeBinding,
      worktree_identity_sha256: hashObject(unsignedWorktreeBinding),
    };
    const goalWorktreeMap = {
      schema_version: 1,
      mode: "SINGLE_DEFAULT",
      mapping_file: null,
      mapping_file_sha256: null,
      goal_worktrees: [worktreeBinding],
      goal_worktrees_sha256: hashObject([worktreeBinding]),
    };
    const [handoffKey, handoffBinding] = [...collector.entries()][0];
    const driftedUnsignedHandoff: Record<string, unknown> = {
      ...handoffBinding,
      migration_repository_head: "f".repeat(40),
    };
    delete driftedUnsignedHandoff.binding_sha256;
    const driftedCollector = new Map([
      [
        handoffKey,
        {
          ...driftedUnsignedHandoff,
          binding_sha256: hashObject(driftedUnsignedHandoff),
        },
      ],
    ]);
    expectControlCode(
      () => sealLegacyEvidenceAnchorIndex(
        createLegacyEvidenceMigrationCollector(),
        {
          controllerDecoderSha256: sha256("legacy migration decoder"),
          sourceStateVectorSha256: sha256("legacy migration source vector"),
          incidentRef: "incident://legacy-recovery-handoff/drift",
          oldControllerDrainAck:
            "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
          goalWorktreeMap,
          recoveryHandoffs: driftedCollector,
        }
      ),
      "STORE_MIGRATION_WORKTREE_CHANGED"
    );
    const missingGoalWorktreeMap = {
      ...goalWorktreeMap,
      goal_worktrees: [],
      goal_worktrees_sha256: hashObject([]),
    };
    expectControlCode(
      () => sealLegacyEvidenceAnchorIndex(
        createLegacyEvidenceMigrationCollector(),
        {
          controllerDecoderSha256: sha256("legacy migration decoder"),
          sourceStateVectorSha256: sha256("legacy migration source vector"),
          incidentRef: "incident://legacy-recovery-handoff/missing-goal",
          oldControllerDrainAck:
            "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
          goalWorktreeMap: missingGoalWorktreeMap,
          recoveryHandoffs: collector,
        }
      ),
      "LEGACY_HANDOFF_ANCHOR_MISMATCH"
    );
    let sealedRecoveryHandoffCount = 0;
    const protocolFile = path.join(
      fixture.controlDir,
      ".store-protocol.json"
    );
    expect(existsSync(protocolFile)).toBe(true);
    // The shared fixture bootstraps the current protocol so the other handoff
    // tests can exercise normal writers. This case specifically models a v1
    // predecessor root before protocol adoption.
    rmSync(protocolFile);
    adoptRootProtocol(fixture.controlDir, (context) => {
      const sealed = sealLegacyEvidenceAnchorIndex(
        createLegacyEvidenceMigrationCollector(),
        {
          controllerDecoderSha256: context.decoder_sha256,
          sourceStateVectorSha256: context.state_vector_sha256,
          incidentRef: "incident://legacy-recovery-handoff/test",
          oldControllerDrainAck:
            "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
          goalWorktreeMap,
          recoveryHandoffs: collector,
        }
      );
      sealedRecoveryHandoffCount = sealed.recovery_handoff_count;
      return {
        report: {
          recovery_handoff_count: sealed.recovery_handoff_count,
        },
        migration_artifacts: [sealed.migration_artifact],
      };
    });
    expect(sealedRecoveryHandoffCount).toBe(1);

    expect(
      verifyAcceptedRecoveryHandoffArtifacts(
        fixture.controlDir,
        acceptedOptions
      )
    ).toMatchObject({
      verified: true,
      materialized_tree: expectedTree,
    });
    expectControlCode(
      () => verifyAcceptedRecoveryHandoffArtifacts(fixture.controlDir, {
        ...acceptedOptions,
        eventPayloadSha256: sha256("transplanted payload"),
      }),
      "LEGACY_HANDOFF_ANCHOR_MISMATCH"
    );
    expectControlCode(
      () => verifyAcceptedRecoveryHandoffArtifacts(fixture.controlDir, {
        goalId: "goal-handoff",
        taskId: "TASK-A",
        payload,
      }),
      "HANDOFF_EXACT_TREE_REQUIRED"
    );
  });

  it("can decode a legacy v1 snapshot but refuses to import it without an expected tree", () => {
    const snapshot = exportSnapshot(fixture);
    const manifest = JSON.parse(
      readFileSync(snapshot.snapshot_file, "utf8")
    ) as Record<string, unknown>;
    manifest.schema_version = 1;
    delete manifest.expected_tree;
    delete manifest.expected_paths;
    delete manifest.operation_request;
    delete manifest.acceptance_authority;
    delete manifest.snapshot_sha256;
    manifest.snapshot_sha256 = hashObject(manifest);
    writeFileSync(
      snapshot.snapshot_file,
      `${JSON.stringify(manifest, null, 2)}\n`
    );

    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_EXACT_TREE_REQUIRED"
    );
    expect(git(fixture.destination, "status", "--porcelain=v1")).toBe("");
  });

  it("continues to import sealed v2 exact-tree artifacts but refuses to checkpoint them", () => {
    const snapshot = exportSnapshot(fixture);
    const manifest = JSON.parse(
      readFileSync(snapshot.snapshot_file, "utf8")
    ) as Record<string, unknown>;
    manifest.schema_version = 2;
    delete manifest.operation_request;
    delete manifest.acceptance_authority;
    delete manifest.snapshot_sha256;
    manifest.snapshot_sha256 = hashObject(manifest);
    writeFileSync(
      snapshot.snapshot_file,
      `${JSON.stringify(manifest, null, 2)}\n`
    );
    snapshot.snapshot_sha256 = String(manifest.snapshot_sha256);

    const receipt = importSnapshot(fixture, snapshot);
    const receiptManifest = JSON.parse(
      readFileSync(receipt.import_receipt_file, "utf8")
    ) as Record<string, unknown>;
    receiptManifest.schema_version = 2;
    delete receiptManifest.acceptance_authority;
    delete receiptManifest.import_receipt_sha256;
    receiptManifest.import_receipt_sha256 = hashObject(receiptManifest);
    writeFileSync(
      receipt.import_receipt_file,
      `${JSON.stringify(receiptManifest, null, 2)}\n`
    );
    receipt.import_receipt_sha256 = String(
      receiptManifest.import_receipt_sha256
    );

    expectControlCode(
      () => checkpointSnapshot(fixture, snapshot, receipt),
      "HANDOFF_CHECKPOINT_V3_REQUIRED"
    );
    expect(git(fixture.destination, "rev-parse", "HEAD")).toBe(
      fixture.observedHead
    );
  });

  it("rejects a tampered snapshot artifact before mutating destination", () => {
    const snapshot = exportSnapshot(fixture);
    appendFileSync(
      path.join(path.dirname(snapshot.snapshot_file), snapshot.tracked_patch.file),
      "tamper"
    );
    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_ARTIFACT_TAMPERED"
    );
    expect(git(fixture.destination, "status", "--porcelain=v1")).toBe("");
  });

  it("rejects a clean destination whose HEAD is not the predecessor launch HEAD", () => {
    const snapshot = exportSnapshot(fixture);
    writeFileSync(path.join(fixture.destination, "wrong-base.txt"), "wrong base\n");
    git(fixture.destination, "add", "wrong-base.txt");
    git(fixture.destination, "commit", "-qm", "advance wrong base");
    expectControlCode(
      () => importSnapshot(fixture, snapshot),
      "HANDOFF_BASE_MISMATCH"
    );
  });

  it("rejects a tampered sealed import receipt during final verification", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    git(fixture.destination, "commit", "-qm", "recover predecessor source");
    const importCommit = git(fixture.destination, "rev-parse", "HEAD");
    const tampered = JSON.parse(
      readFileSync(receipt.import_receipt_file, "utf8")
    ) as Record<string, unknown>;
    tampered.materialized_patch_sha256 = sha256("tampered");
    writeFileSync(
      receipt.import_receipt_file,
      `${JSON.stringify(tampered, null, 2)}\n`
    );
    expectControlCode(
      () =>
        verifyRecoveryHandoff(fixture.destination, {
          goalId: "goal-handoff",
          taskId: "TASK-A",
          payload: verificationPayload(snapshot, receipt, importCommit),
        }),
      "HANDOFF_RECEIPT_TAMPERED"
    );
  });

  it("rejects an import commit that smuggles changes after the sealed staging receipt", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    writeFileSync(path.join(fixture.destination, "smuggled.txt"), "not in receipt\n");
    git(fixture.destination, "add", "smuggled.txt");
    git(fixture.destination, "commit", "-qm", "recover source plus smuggled change");
    const importCommit = git(fixture.destination, "rev-parse", "HEAD");
    expectControlCode(
      () =>
        verifyRecoveryHandoff(fixture.destination, {
          goalId: "goal-handoff",
          taskId: "TASK-A",
          payload: verificationPayload(snapshot, receipt, importCommit),
        }),
      "HANDOFF_MATERIALIZED_DIFF_MISMATCH"
    );
  });

  it("binds the import commit to the snapshot tree even if a smuggled diff is resealed into the receipt", () => {
    const snapshot = exportSnapshot(fixture);
    const receipt = importSnapshot(fixture, snapshot);
    writeFileSync(path.join(fixture.destination, "smuggled.txt"), "not in snapshot\n");
    git(fixture.destination, "add", "smuggled.txt");
    git(fixture.destination, "commit", "-qm", "recover source plus resealed smuggle");
    const importCommit = git(fixture.destination, "rev-parse", "HEAD");
    const smuggledPatch = canonicalPatch(
      fixture.destination,
      fixture.observedHead,
      importCommit
    );
    const resealed = JSON.parse(
      readFileSync(receipt.import_receipt_file, "utf8")
    ) as Record<string, unknown>;
    resealed.materialized_patch_bytes = smuggledPatch.length;
    resealed.materialized_patch_sha256 = sha256(smuggledPatch);
    delete resealed.import_receipt_sha256;
    resealed.import_receipt_sha256 = hashObject(resealed);
    writeFileSync(
      receipt.import_receipt_file,
      `${JSON.stringify(resealed, null, 2)}\n`
    );
    receipt.import_receipt_sha256 = String(resealed.import_receipt_sha256);

    expectControlCode(
      () =>
        verifyRecoveryHandoff(fixture.destination, {
          goalId: "goal-handoff",
          taskId: "TASK-A",
          payload: verificationPayload(snapshot, receipt, importCommit),
        }),
      "HANDOFF_MATERIALIZED_TREE_MISMATCH"
    );
  });
});
