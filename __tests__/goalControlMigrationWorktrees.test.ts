import { execFileSync } from "child_process";
import { createRequire } from "module";
import { createHash } from "crypto";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const DRAIN_ACK = "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED";
const nodeRequire = createRequire(import.meta.url);
const { adoptStoreProtocol } = nodeRequire(
  "../scripts/goal-control/migration.js",
) as {
  adoptStoreProtocol: (
    cwd: string,
    options: {
      incidentRef: string;
      oldControllerDrainAcknowledgment: string;
      goalWorktreesFile: string;
    },
    hooks?: { afterReplay?: () => void },
  ) => Record<string, unknown>;
};
const {
  createLegacyEvidenceMigrationCollector,
  readLegacyEvidenceAnchorIndex,
  sealLegacyEvidenceAnchorIndex,
} = nodeRequire("../scripts/goal-control/evidence.js") as {
  createLegacyEvidenceMigrationCollector: () => {
    eventBindings: Map<string, Record<string, unknown>>;
    semanticSources: Map<string, Record<string, unknown>>;
  };
  readLegacyEvidenceAnchorIndex: (
    root: string,
  ) => { recovery_handoffs: Record<string, unknown> };
  sealLegacyEvidenceAnchorIndex: (
    entries: {
      eventBindings: Map<string, Record<string, unknown>>;
      semanticSources: Map<string, Record<string, unknown>>;
    },
    options: Record<string, unknown>,
  ) => { migration_artifact: { body: string | Buffer } };
};
const { adoptRootProtocol } = nodeRequire(
  "../scripts/goal-control/store.js",
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
    },
  ) => Record<string, unknown>;
};
const {
  canonicalJson,
  hashObject,
} = nodeRequire("../scripts/goal-control/util.js") as {
  canonicalJson: (value: unknown) => string;
  hashObject: (value: unknown) => string;
};

type CliResult = { code: number; stdout: string; stderr: string };

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

function runGoalctl(
  cwd: string,
  controlDir: string,
  args: string[],
): CliResult {
  try {
    const stdout = execFileSync("node", [GOALCTL, ...args], {
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

function writeJson(file: string, value: unknown): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function writeGoalSpec(
  repository: string,
  goalId: string,
  baseHead: string,
): { spec: string; output: string } {
  const input = `goal-inputs/${goalId}.md`;
  const spec = `goal-inputs/${goalId}.json`;
  const output = `docs/planning/goals/${goalId}`;
  mkdirSync(path.join(repository, "goal-inputs"), { recursive: true });
  writeFileSync(
    path.join(repository, input),
    `# ${goalId}\n\nComplete immutable ${goalId} packet.\n`,
  );
  writeJson(path.join(repository, spec), {
    schema_version: 1,
    goal_id: goalId,
    title: `${goalId} migration fixture`,
    mode: "shadow",
    repository: {
      name_with_owner: "example-org/example-repo",
      base_branch: "main",
    },
    base_head: baseHead,
    tasks: [{
      id: "TASK-1",
      title: `${goalId} task`,
      issue: 4242,
      dependencies: [],
      integration_order: 1,
      parallel_group: "batch-1",
      risk_class: "STANDARD",
      packet_source: input,
      packet_revision: 1,
      expected_write_set: ["scripts/goal-control/**"],
      conflict_domains: ["goal-control"],
      resource_requirements: [],
    }],
  });
  return { spec, output };
}

function scaffoldAndCommitGoal(
  repository: string,
  controlDir: string,
  goalId: string,
  baseHead: string,
): { manifest: string; head: string } {
  const { spec, output } = writeGoalSpec(repository, goalId, baseHead);
  const scaffold = runGoalctl(repository, controlDir, [
    "scaffold",
    "--spec",
    spec,
    "--output-dir",
    output,
    "--json",
  ]);
  expect(scaffold).toEqual(expect.objectContaining({ code: 0, stderr: "" }));
  git(repository, "add", spec, `goal-inputs/${goalId}.md`, output);
  git(repository, "commit", "-qm", `add ${goalId}`);
  const manifest = path.join(repository, output, "manifest.json");
  const initialized = runGoalctl(repository, controlDir, [
    "init",
    "--manifest",
    manifest,
    "--json",
  ]);
  expect(initialized).toEqual(expect.objectContaining({ code: 0, stderr: "" }));
  return { manifest, head: git(repository, "rev-parse", "HEAD") };
}

function writeWorktreeMap(
  file: string,
  entries: Array<{ goal_id: string; repository_worktree: string }>,
): void {
  writeJson(file, {
    schema_version: 1,
    goal_worktrees: entries,
  });
}

describe("goal-control multi-Goal protocol adoption", () => {
  test("binds each Goal to its own frozen worktree and rejects unsafe mappings", () => {
    const repository = realpathSync(mkdtempSync(path.join(
      tmpdir(),
      "goal-migration-repo-",
    )));
    const controlDir = realpathSync(mkdtempSync(path.join(
      tmpdir(),
      "goal-migration-state-",
    )));
    const auxiliary = realpathSync(mkdtempSync(path.join(
      tmpdir(),
      "goal-migration-aux-",
    )));
    const wrongRepository = realpathSync(mkdtempSync(path.join(
      tmpdir(),
      "goal-migration-wrong-repo-",
    )));
    const oldWorktree = path.join(auxiliary, "goal-one-worktree");
    const mapFile = path.join(auxiliary, "goal-worktrees.json");
    try {
      git(repository, "init", "-q", "-b", "main");
      git(repository, "config", "user.email", "migration@example.test");
      git(repository, "config", "user.name", "Migration Test");
      git(repository, "remote", "add", "origin", "https://github.com/example-org/example-repo.git");
      for (const relative of [
        "docs/planning/session-role-protocol.md",
        "docs/planning/session-protocol/shared.md",
        "docs/planning/session-protocol/foreman.md",
        "docs/planning/session-protocol/captain.md",
        "docs/planning/session-protocol/role-kernel.md",
      ]) {
        const file = path.join(repository, relative);
        mkdirSync(path.dirname(file), { recursive: true });
        writeFileSync(file, `# ${path.basename(relative)} v1\n`);
      }
      writeFileSync(
        path.join(repository, "pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n",
      );
      git(repository, "add", ".");
      git(repository, "commit", "-qm", "base protocol v1");

      const goalOne = scaffoldAndCommitGoal(
        repository,
        controlDir,
        "goal-one",
        git(repository, "rev-parse", "HEAD"),
      );
      writeFileSync(
        path.join(repository, "docs/planning/session-protocol/shared.md"),
        "# shared.md v2\n",
      );
      git(repository, "add", "docs/planning/session-protocol/shared.md");
      const goalTwo = scaffoldAndCommitGoal(
        repository,
        controlDir,
        "goal-two",
        goalOne.head,
      );
      const goalOneManifest = JSON.parse(
        readFileSync(
          path.join(controlDir, "goals", "goal-one", "manifest.json"),
          "utf8",
        ),
      ) as { protocol: { shared: { sha256: string } } };
      const goalTwoManifest = JSON.parse(
        readFileSync(
          path.join(controlDir, "goals", "goal-two", "manifest.json"),
          "utf8",
        ),
      ) as { protocol: { shared: { sha256: string } } };
      expect(goalOneManifest.protocol.shared.sha256).not.toBe(
        goalTwoManifest.protocol.shared.sha256,
      );

      git(repository, "worktree", "add", "--detach", oldWorktree, goalOne.head);
      expect(realpathSync(oldWorktree)).toBe(oldWorktree);
      expect(git(repository, "status", "--porcelain=v1", "--untracked-files=all")).toBe("");
      expect(git(oldWorktree, "status", "--porcelain=v1", "--untracked-files=all")).toBe("");

      rmSync(path.join(controlDir, ".store-protocol.json"), { force: true });
      rmSync(path.join(controlDir, ".generation.json"), { force: true });
      const adoptionArgs = (mapping: string | null): string[] => [
        "adopt-store-protocol",
        "--repository-worktree",
        repository,
        ...(mapping ? ["--goal-worktrees-file", mapping] : []),
        "--incident-ref",
        "incident://goal-control/multi-goal-adoption",
        "--acknowledge-old-controller-drained",
        DRAIN_ACK,
        "--json",
      ];

      const singleWorktree = runGoalctl(
        repository,
        controlDir,
        adoptionArgs(null),
      );
      expect(singleWorktree.code).toBe(2);
      expect(singleWorktree.stderr).toContain("PROTOCOL_DRIFT");

      writeWorktreeMap(mapFile, [{
        goal_id: "goal-one",
        repository_worktree: oldWorktree,
      }]);
      const missing = runGoalctl(repository, controlDir, adoptionArgs(mapFile));
      expect(missing.code).toBe(2);
      expect(missing.stderr).toContain(
        "STORE_MIGRATION_WORKTREE_MAP_INCOMPLETE",
      );

      git(wrongRepository, "init", "-q", "-b", "main");
      git(wrongRepository, "config", "user.email", "wrong@example.test");
      git(wrongRepository, "config", "user.name", "Wrong Repository");
      writeFileSync(path.join(wrongRepository, "README.md"), "wrong\n");
      git(wrongRepository, "add", ".");
      git(wrongRepository, "commit", "-qm", "wrong repo");
      writeWorktreeMap(mapFile, [
        { goal_id: "goal-one", repository_worktree: oldWorktree },
        { goal_id: "goal-two", repository_worktree: wrongRepository },
      ]);
      const wrongRepo = runGoalctl(repository, controlDir, adoptionArgs(mapFile));
      expect(wrongRepo.code).toBe(2);
      expect(wrongRepo.stderr).toContain(
        "STORE_MIGRATION_WORKTREE_REPOSITORY_MISMATCH",
      );

      const dirtyFile = path.join(oldWorktree, "dirty-untracked.txt");
      writeFileSync(dirtyFile, "dirty\n");
      writeWorktreeMap(mapFile, [
        { goal_id: "goal-one", repository_worktree: oldWorktree },
        { goal_id: "goal-two", repository_worktree: repository },
      ]);
      const dirty = runGoalctl(repository, controlDir, adoptionArgs(mapFile));
      expect(dirty.code).toBe(2);
      expect(dirty.stderr).toContain("FROZEN_WORKTREE_DIRTY");
      rmSync(dirtyFile);

      const symlinkMap = path.join(auxiliary, "goal-worktrees-symlink.json");
      symlinkSync(mapFile, symlinkMap);
      const mapSymlink = runGoalctl(
        repository,
        controlDir,
        adoptionArgs(symlinkMap),
      );
      expect(mapSymlink.code).toBe(2);
      expect(mapSymlink.stderr).toContain("STORE_MIGRATION_WORKTREE_SYMLINK");
      rmSync(symlinkMap);

      const symlinkWorktree = path.join(auxiliary, "goal-one-symlink");
      symlinkSync(oldWorktree, symlinkWorktree);
      writeWorktreeMap(mapFile, [
        { goal_id: "goal-one", repository_worktree: symlinkWorktree },
        { goal_id: "goal-two", repository_worktree: repository },
      ]);
      const symlink = runGoalctl(repository, controlDir, adoptionArgs(mapFile));
      expect(symlink.code).toBe(2);
      expect(symlink.stderr).toContain("STORE_MIGRATION_WORKTREE_SYMLINK");
      rmSync(symlinkWorktree);

      writeWorktreeMap(mapFile, [
        { goal_id: "goal-one", repository_worktree: oldWorktree },
        { goal_id: "goal-two", repository_worktree: repository },
      ]);
      const sharedProtocol = "docs/planning/session-protocol/shared.md";
      const oldSharedProtocol = path.join(oldWorktree, sharedProtocol);
      const oldSharedBytes = readFileSync(oldSharedProtocol);
      const previousControlDir = process.env.GOAL_CONTROL_DIR;
      const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
      let hiddenMutationError: unknown = null;
      git(oldWorktree, "update-index", "--assume-unchanged", sharedProtocol);
      process.env.GOAL_CONTROL_DIR = controlDir;
      process.env.GOAL_CONTROL_TEST_MODE = "1";
      try {
        adoptStoreProtocol(
          repository,
          {
            incidentRef: "incident://goal-control/multi-goal-adoption",
            oldControllerDrainAcknowledgment: DRAIN_ACK,
            goalWorktreesFile: mapFile,
          },
          {
            afterReplay: () => {
              writeFileSync(oldSharedProtocol, "# hidden drift\n");
              expect(git(
                oldWorktree,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
              )).toBe("");
            },
          },
        );
      } catch (error) {
        hiddenMutationError = error;
      } finally {
        writeFileSync(oldSharedProtocol, oldSharedBytes);
        git(oldWorktree, "update-index", "--no-assume-unchanged", sharedProtocol);
        if (previousControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
        else process.env.GOAL_CONTROL_DIR = previousControlDir;
        if (previousTestMode === undefined) {
          delete process.env.GOAL_CONTROL_TEST_MODE;
        } else {
          process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
        }
      }
      expect(hiddenMutationError).toMatchObject({ code: "PROTOCOL_DRIFT" });
      expect(existsSync(path.join(controlDir, ".store-protocol.json"))).toBe(
        false,
      );

      const adoptedResult = runGoalctl(
        repository,
        controlDir,
        adoptionArgs(mapFile),
      );
      expect(adoptedResult).toEqual(expect.objectContaining({
        code: 0,
        stderr: "",
      }));
      const adopted = JSON.parse(adoptedResult.stdout) as {
        adopted: boolean;
        validation: {
          goal_count: number;
          legacy_identity_incident_count: number;
          legacy_recovery_handoff_count: number;
          goal_worktree_map: {
            mode: string;
            mapping_file: string;
            mapping_file_sha256: string;
            goal_worktrees_sha256: string;
            goal_worktrees: Array<{
              goal_id: string;
              repository_worktree: string;
              repository_head: string;
              frozen_inputs_sha256: string;
              worktree_identity_sha256: string;
            }>;
          };
        };
      };
      expect(adopted.adopted).toBe(true);
      expect(adopted.validation.goal_count).toBe(2);
      expect(adopted.validation.legacy_identity_incident_count).toBe(0);
      expect(adopted.validation.legacy_recovery_handoff_count).toBe(0);
      expect(adopted.validation.goal_worktree_map).toMatchObject({
        mode: "EXPLICIT_MAP",
        mapping_file: mapFile,
        mapping_file_sha256: sha256(readFileSync(mapFile)),
        goal_worktrees_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      });
      expect(adopted.validation.goal_worktree_map.goal_worktrees).toEqual([
        expect.objectContaining({
          goal_id: "goal-one",
          repository_worktree: oldWorktree,
          repository_head: goalOne.head,
          frozen_inputs_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
          worktree_identity_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        }),
        expect.objectContaining({
          goal_id: "goal-two",
          repository_worktree: repository,
          repository_head: goalTwo.head,
        }),
      ]);
      const anchor = JSON.parse(readFileSync(
        path.join(controlDir, ".legacy-evidence-anchors.v1.json"),
        "utf8",
      )) as {
        migration_receipt: {
          goal_worktree_map: unknown;
        };
        recovery_handoffs: Record<string, unknown>;
      };
      expect(anchor.migration_receipt.goal_worktree_map).toEqual(
        adopted.validation.goal_worktree_map,
      );
      expect(anchor.recovery_handoffs).toEqual({});
      const identityIncidents = JSON.parse(readFileSync(
        path.join(controlDir, ".legacy-identity-incidents.v1.json"),
        "utf8",
      )) as {
        kind: string;
        incidents: Record<string, unknown>;
        incidents_sha256: string;
        sources: Record<string, string>;
        sources_sha256: string;
        receipt_sha256: string;
      };
      expect(identityIncidents).toMatchObject({
        kind: "LEGACY_IDENTITY_INCIDENT_BINDINGS",
        incidents: {},
        incidents_sha256: hashObject({}),
        sources: {},
        sources_sha256: hashObject({}),
        receipt_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      });
      const protocol = JSON.parse(readFileSync(
        path.join(controlDir, ".store-protocol.json"),
        "utf8",
      )) as {
        migration_artifacts: Array<{ relative_path: string }>;
      };
      expect(protocol.migration_artifacts.map(
        (artifact) => artifact.relative_path,
      )).toEqual([
        ".legacy-evidence-anchors.v1.json",
        ".legacy-identity-incidents.v1.json",
      ]);

      const idempotent = runGoalctl(
        repository,
        controlDir,
        adoptionArgs(mapFile),
      );
      expect(idempotent.code).toBe(0);
      expect(JSON.parse(idempotent.stdout)).toMatchObject({
        adopted: false,
        idempotent: true,
        validation: {
          legacy_identity_incident_count: 0,
          legacy_recovery_handoff_count: 0,
        },
      });

      writeFileSync(mapFile, `${readFileSync(mapFile, "utf8")} `);
      const changedMap = runGoalctl(
        repository,
        controlDir,
        adoptionArgs(mapFile),
      );
      expect(changedMap.code).toBe(2);
      expect(changedMap.stderr).toContain(
        "STORE_MIGRATION_WORKTREE_MAP_MISMATCH",
      );
    } finally {
      if (existsSync(oldWorktree)) {
        try {
          git(repository, "worktree", "remove", "--force", oldWorktree);
        } catch {
          // The enclosing temporary repository cleanup is the final fallback.
        }
      }
      rmSync(repository, { recursive: true, force: true });
      rmSync(controlDir, { recursive: true, force: true });
      rmSync(auxiliary, { recursive: true, force: true });
      rmSync(wrongRepository, { recursive: true, force: true });
    }
  });

  test("reads a sealed pre-handoff evidence index as an empty recovery binding map", () => {
    const presentRoot = realpathSync(mkdtempSync(path.join(
      tmpdir(),
      "goal-migration-present-index-",
    )));
    const legacyRoot = realpathSync(mkdtempSync(path.join(
      tmpdir(),
      "goal-migration-legacy-no-handoff-index-",
    )));
    try {
      const sealAnchorVariant = (
        root: string,
        includeRecoveryHandoffs: boolean,
      ): string => {
        adoptRootProtocol(root, (context) => {
          const unsignedWorktree = {
            goal_id: "goal-legacy-index",
            repository_worktree: root,
            repository_common_dir: root,
            repository_head: "a".repeat(40),
            manifest_sha256: sha256("legacy manifest"),
            frozen_inputs_sha256: sha256("legacy frozen inputs"),
          };
          const worktree = {
            ...unsignedWorktree,
            worktree_identity_sha256: hashObject(unsignedWorktree),
          };
          const goalWorktreeMap = {
            schema_version: 1,
            mode: "SINGLE_DEFAULT",
            mapping_file: null,
            mapping_file_sha256: null,
            goal_worktrees: [worktree],
            goal_worktrees_sha256: hashObject([worktree]),
          };
          const sealed = sealLegacyEvidenceAnchorIndex(
            createLegacyEvidenceMigrationCollector(),
            {
              controllerDecoderSha256: context.decoder_sha256,
              sourceStateVectorSha256: context.state_vector_sha256,
              incidentRef: "incident://legacy-index-compatibility",
              oldControllerDrainAck: DRAIN_ACK,
              goalWorktreeMap,
            },
          );
          const body = Buffer.isBuffer(sealed.migration_artifact.body)
            ? sealed.migration_artifact.body.toString("utf8")
            : sealed.migration_artifact.body;
          const index = JSON.parse(body) as Record<string, unknown>;
          if (!includeRecoveryHandoffs) {
            delete index.recovery_handoffs;
            delete index.index_sha256;
            index.index_sha256 = hashObject(index);
          }
          const artifactBody = `${canonicalJson(index)}\n`;
          return {
            report: {},
            migration_artifacts: [{
              relative_path: ".legacy-evidence-anchors.v1.json",
              sha256: sha256(artifactBody),
              body: artifactBody,
            }],
          };
        });
        return path.join(root, ".legacy-evidence-anchors.v1.json");
      };

      sealAnchorVariant(presentRoot, true);
      expect(
        readLegacyEvidenceAnchorIndex(presentRoot).recovery_handoffs,
      ).toEqual({});

      const legacyFile = sealAnchorVariant(legacyRoot, false);
      expect(
        readLegacyEvidenceAnchorIndex(legacyRoot).recovery_handoffs,
      ).toEqual({});

      const oldIndex = JSON.parse(
        readFileSync(legacyFile, "utf8"),
      ) as Record<string, unknown>;
      writeJson(legacyFile, {
        ...oldIndex,
        recovery_handoffs: { transplanted: {} },
      });
      let tamperError: unknown = null;
      try {
        readLegacyEvidenceAnchorIndex(legacyRoot);
      } catch (error) {
        tamperError = error;
      }
      expect(tamperError).toMatchObject({
        code: "CORRUPT_STORE_PROTOCOL",
      });
    } finally {
      rmSync(presentRoot, { recursive: true, force: true });
      rmSync(legacyRoot, { recursive: true, force: true });
    }
  });
});
