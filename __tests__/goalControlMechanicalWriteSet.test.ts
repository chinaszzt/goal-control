import { execFileSync } from "child_process";
import { createHash } from "crypto";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const nodeRequire = createRequire(import.meta.url);
const {
  assertMechanicalP1CandidateWriteSet,
} = nodeRequire("../scripts/goal-control/goal.js") as {
  assertMechanicalP1CandidateWriteSet: (
    worktree: string,
    task: Record<string, unknown>,
    state: Record<string, unknown>,
    candidateHead: string,
  ) => string[];
};
const {
  matchesMechanicalP1WritePattern,
  validateManifest,
} = nodeRequire("../scripts/goal-control/validation.js") as {
  matchesMechanicalP1WritePattern: (
    pattern: string,
    candidatePath: string,
  ) => boolean;
  validateManifest: (
    manifest: Record<string, unknown>,
    manifestFile: string,
    repositoryRoot: string,
  ) => Record<string, unknown>;
};

type RepositoryFixture = {
  root: string;
  initialHead: string;
  p1Commit: string;
};

const temporaryRoots: string[] = [];

function git(
  cwd: string,
  args: string[],
  options: { input?: string } = {},
): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    input: options.input,
    stdio: options.input === undefined
      ? ["ignore", "pipe", "pipe"]
      : ["pipe", "pipe", "pipe"],
  }).trim();
}

function write(root: string, relativePath: string, body: string): void {
  const file = path.join(root, relativePath);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, body);
}

function commitAll(root: string, message: string): string {
  git(root, ["add", "-A"]);
  git(root, ["commit", "-qm", message]);
  return git(root, ["rev-parse", "HEAD"]);
}

function createRepositoryFixture(): RepositoryFixture {
  const root = mkdtempSync(path.join(tmpdir(), "goal-p1-write-set-"));
  temporaryRoots.push(root);
  git(root, ["init", "-q", "-b", "main"]);
  git(root, ["config", "user.email", "p1-write-set@example.test"]);
  git(root, ["config", "user.name", "P1 Write Set Test"]);
  write(root, "README.md", "# fixture\n");
  write(root, "allowed/existing.ts", "export const existing = 1;\n");
  write(root, "outside/existing.ts", "export const outside = 1;\n");
  const initialHead = commitAll(root, "initial tree");
  write(root, "docs/issues/900/plan.md", "# Plan\n");
  write(root, "docs/issues/900/context.md", "# Context\n");
  const p1Commit = commitAll(root, "docs(issue-900): P1");
  return { root, initialHead, p1Commit };
}

function candidateState(
  fixture: RepositoryFixture,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    task_id: "TASK-P1-WRITE-SET",
    phase: "DEV_ACTIVE",
    base_head: fixture.p1Commit,
    full_head: fixture.p1Commit,
    p1: { commit_sha: fixture.p1Commit },
    sessions: {
      DEV: {
        role: "DEV",
        thread_id: "dev-write-set",
        host_id: "local",
        attempt: 1,
        registered_full_head: fixture.p1Commit,
      },
    },
    ...overrides,
  };
}

function mechanicalTask(patterns: string[]): Record<string, unknown> {
  return {
    id: "TASK-P1-WRITE-SET",
    p1: { producer: "CAPTAIN" },
    expected_write_set: patterns,
  };
}

function assertCandidate(
  fixture: RepositoryFixture,
  patterns: string[],
  candidateHead = git(fixture.root, ["rev-parse", "HEAD"]),
  state = candidateState(fixture),
): string[] {
  return assertMechanicalP1CandidateWriteSet(
    fixture.root,
    mechanicalTask(patterns),
    state,
    candidateHead,
  );
}

function sha256(body: string): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function manifestFixture(
  patterns: string[],
  mechanical = true,
): {
  root: string;
  file: string;
  manifest: Record<string, unknown>;
} {
  const root = mkdtempSync(path.join(tmpdir(), "goal-p1-write-manifest-"));
  temporaryRoots.push(root);
  const packetPath = "goal-inputs/task.md";
  const packetBody = "# packet\n";
  const authorityPath = "docs/planning/goals/write-set.authorization.md";
  const authorityBody = "# scoped delegation\n";
  write(root, packetPath, packetBody);
  write(root, authorityPath, authorityBody);
  const task: Record<string, unknown> = {
    id: "TASK-P1-WRITE-SET",
    issue: 900,
    dependencies: [],
    integration_order: 1,
    packet: {
      revision: 1,
      path: packetPath,
      sha256: sha256(packetBody),
    },
    expected_write_set: patterns,
    conflict_domains: [],
    resource_requirements: [],
  };
  if (mechanical) {
    task.p1 = {
      producer: "CAPTAIN",
      artifact_root: "docs/issues/900",
      authority: {
        kind: "SCOPED_DELEGATION",
        path: authorityPath,
        sha256: sha256(authorityBody),
      },
      dependency_gate: "ARCHIVED",
    };
  }
  const manifest = {
    schema_version: 1,
    goal_id: "goal-p1-write-set",
    mode: "shadow",
    repository: {
      name_with_owner: "example-org/example-repo",
      base_branch: "main",
    },
    base_head: "1".repeat(40),
    tasks: [task],
  };
  const file = path.join(root, "manifest.json");
  writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);
  return { root, file, manifest };
}

afterEach(() => {
  while (temporaryRoots.length > 0) {
    rmSync(temporaryRoots.pop() as string, {
      recursive: true,
      force: true,
    });
  }
});

describe("mechanical P1 expected_write_set pattern contract", () => {
  it.each([
    ["src/exact.ts", "src/exact.ts"],
    ["dir/**", "dir/a/b/file.ts"],
    ["prefix-*.ts", "prefix-one.ts"],
    ["*-suffix.ts", "one-suffix.ts"],
    ["src/**/leaf-*.ts", "src/a/b/leaf-one.ts"],
    ["src/**/leaf-*.ts", "src/leaf-one.ts"],
    ["**", "any/depth/file.ts"],
  ])("matches %s against %s", (pattern, candidatePath) => {
    expect(matchesMechanicalP1WritePattern(pattern, candidatePath)).toBe(true);
  });

  it.each([
    ["src/*.ts", "src/nested/file.ts"],
    ["src/**", "Src/file.ts"],
    ["prefix-*.ts", "nested/prefix-one.ts"],
    ["src/**/leaf-*.ts", "src/a/b/not-leaf.txt"],
  ])("does not match %s against %s", (pattern, candidatePath) => {
    expect(matchesMechanicalP1WritePattern(pattern, candidatePath)).toBe(
      false,
    );
  });

  it.each([
    "",
    "/absolute/path",
    "./dot/path",
    "dir/../escape",
    "dir//empty",
    "dir/",
    "dir\\windows",
    `dir/\0nul`,
    "!dir/**",
    "{src,test}/**",
    "@(src)/**",
    "+(src)/**",
    "*(src)/**",
    "[st]rc/**",
    "src/?.ts",
    "src/**.ts",
    "src/prefix**/file.ts",
    "src/***/file.ts",
  ])("rejects invalid mechanical P1 pattern %p at manifest ingress", (pattern) => {
    const fixture = manifestFixture([pattern]);
    expect(() => validateManifest(
      fixture.manifest,
      fixture.file,
      fixture.root,
    )).toThrow(expect.objectContaining({ code: "INVALID_MANIFEST" }));
  });

  it("keeps legacy expected_write_set syntax unchanged", () => {
    const fixture = manifestFixture(["[legacy]/**?/!"], false);
    expect(() => validateManifest(
      fixture.manifest,
      fixture.file,
      fixture.root,
    )).not.toThrow();
  });

  it("freezes the narrow mechanical pattern in the checked-in schema", () => {
    const schema = JSON.parse(readFileSync(path.join(
      ROOT,
      "scripts/goal-control/schemas/goal-manifest.schema.json",
    ), "utf8")) as {
      $defs: {
        p1ExpectedWritePattern: { description: string };
        task: { allOf: unknown[] };
      };
    };
    expect(schema.$defs.p1ExpectedWritePattern.description).toContain(
      "Mechanical-P1-only",
    );
    expect(JSON.stringify(schema.$defs.task.allOf)).toContain(
      "#/$defs/p1ExpectedWritePattern",
    );
  });
});

describe("mechanical P1 DEV_READY write-set boundary", () => {
  it.each([
    ["src/exact.ts", "src/exact.ts"],
    ["dir/a/b/file.ts", "dir/**"],
    ["prefix-one.ts", "prefix-*.ts"],
    ["one-suffix.ts", "*-suffix.ts"],
    ["src/a/b/leaf-one.ts", "src/**/leaf-*.ts"],
  ])("allows candidate path %s via %s", (relativePath, pattern) => {
    const fixture = createRepositoryFixture();
    write(fixture.root, relativePath, "candidate\n");
    const candidate = commitAll(fixture.root, `add ${relativePath}`);
    expect(assertCandidate(fixture, [pattern], candidate)).toEqual([
      relativePath,
    ]);
  });

  it("treats an empty set as no DEV delta", () => {
    const fixture = createRepositoryFixture();
    expect(assertCandidate(fixture, [], fixture.p1Commit)).toEqual([]);
    write(fixture.root, "allowed/new.ts", "candidate\n");
    const candidate = commitAll(fixture.root, "add candidate");
    expect(() => assertCandidate(fixture, [], candidate)).toThrow(
      expect.objectContaining({ code: "P1_WRITE_SET_VIOLATION" }),
    );
  });

  it.each(["add", "delete", "modify"] as const)(
    "rejects an outside %s",
    (operation) => {
      const fixture = createRepositoryFixture();
      if (operation === "add") {
        write(fixture.root, "outside/new.ts", "candidate\n");
      } else if (operation === "delete") {
        rmSync(path.join(fixture.root, "outside/existing.ts"));
      } else {
        write(fixture.root, "outside/existing.ts", "changed\n");
      }
      const candidate = commitAll(fixture.root, `${operation} outside path`);
      expect(() => assertCandidate(
        fixture,
        ["allowed/**"],
        candidate,
      )).toThrow(expect.objectContaining({
        code: "P1_WRITE_SET_VIOLATION",
      }));
    },
  );

  it.each([
    ["outside/existing.ts", "allowed/moved.ts", false],
    ["allowed/existing.ts", "outside/moved.ts", false],
    ["allowed/existing.ts", "allowed/moved.ts", true],
  ] as const)(
    "checks both --no-renames sides for %s -> %s",
    (source, destination, allowed) => {
      const fixture = createRepositoryFixture();
      mkdirSync(path.dirname(path.join(fixture.root, destination)), {
        recursive: true,
      });
      git(fixture.root, ["mv", source, destination]);
      const candidate = commitAll(fixture.root, "rename candidate path");
      if (allowed) {
        expect(assertCandidate(
          fixture,
          ["allowed/**"],
          candidate,
        )).toEqual(["allowed/existing.ts", "allowed/moved.ts"]);
      } else {
        expect(() => assertCandidate(
          fixture,
          ["allowed/**"],
          candidate,
        )).toThrow(expect.objectContaining({
          code: "P1_WRITE_SET_VIOLATION",
        }));
      }
    },
  );

  it("does not launder the immutable P1 baseline through a recovery checkpoint", () => {
    const fixture = createRepositoryFixture();
    write(fixture.root, "outside/laundered.ts", "outside\n");
    const recoveryCheckpoint = commitAll(
      fixture.root,
      "outside change before recovery",
    );
    write(fixture.root, "allowed/after-recovery.ts", "allowed\n");
    const candidate = commitAll(fixture.root, "allowed change after recovery");
    const recoveredState = candidateState(fixture, {
      base_head: recoveryCheckpoint,
      full_head: recoveryCheckpoint,
      sessions: {
        DEV: {
          role: "DEV",
          thread_id: "dev-recovered",
          host_id: "local",
          attempt: 2,
          registered_full_head: recoveryCheckpoint,
          activated_full_head: recoveryCheckpoint,
        },
      },
    });
    expect(() => assertCandidate(
      fixture,
      ["allowed/**"],
      candidate,
      recoveredState,
    )).toThrow(expect.objectContaining({
      code: "P1_WRITE_SET_VIOLATION",
    }));
  });

  it("proves P1 commit ancestry before inspecting candidate paths", () => {
    const fixture = createRepositoryFixture();
    const tree = git(fixture.root, ["rev-parse", `${fixture.p1Commit}^{tree}`]);
    const siblingCandidate = git(
      fixture.root,
      ["commit-tree", tree, "-p", fixture.initialHead],
      { input: "sibling candidate\n" },
    );
    expect(() => assertCandidate(
      fixture,
      ["**"],
      siblingCandidate,
    )).toThrow(expect.objectContaining({
      code: "P1_BASELINE_NOT_ANCESTOR",
    }));
  });

  it("does not enforce the new boundary for a legacy task", () => {
    const fixture = createRepositoryFixture();
    write(fixture.root, "outside/legacy.ts", "legacy\n");
    const candidate = commitAll(fixture.root, "legacy candidate");
    expect(assertMechanicalP1CandidateWriteSet(
      fixture.root,
      { id: "LEGACY", expected_write_set: [] },
      { task_id: "LEGACY", p1: {} },
      candidate,
    )).toEqual([]);
  });
});
