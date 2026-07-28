import { execFileSync } from "child_process";
import { createHash } from "crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { createRequire } from "module";
import { tmpdir } from "os";
import path from "path";

const nodeRequire = createRequire(import.meta.url);
const NATIVE_GIT_VERSION = "2.50.0";

type GitExecOptions = {
  cwd?: string;
  encoding?: BufferEncoding | null;
  env?: NodeJS.ProcessEnv;
  input?: string | Buffer;
  stdio?: unknown;
};

type GitExec = (
  executable: string,
  args: readonly string[],
  options?: GitExecOptions,
) => string | Buffer;

const childProcessModule = nodeRequire("child_process") as {
  execFileSync: GitExec;
};
const hostExecFileSync = execFileSync as unknown as GitExec;

function outputForEncoding(
  value: string,
  options?: GitExecOptions,
): string | Buffer {
  return options?.encoding === null ? Buffer.from(value) : value;
}

function optionsWithoutInput(
  options?: GitExecOptions,
): GitExecOptions {
  const result = { ...options };
  delete result.input;
  return result;
}

function isNativeSymrefTransaction(args: readonly string[]): boolean {
  return args.length === 5
    && args[0] === "-c"
    && args[1] === "core.hooksPath=/dev/null"
    && args[2] === "update-ref"
    && args[3] === "--stdin"
    && args[4] === "-z";
}

function emulateNativeSymrefTransaction(
  executable: string,
  options?: GitExecOptions,
): string | Buffer {
  const fields = Buffer.from(options?.input || "").toString("utf8")
    .split("\0")
    .filter(Boolean);
  if (
    fields.length !== 9
      || fields[0] !== "start"
      || !fields[1].startsWith("verify refs/")
      || fields[3] !== "symref-update HEAD"
      || fields[5] !== "oid"
      || fields[7] !== "prepare"
      || fields[8] !== "commit"
  ) {
    throw new Error("unexpected native symref transaction input");
  }
  const targetRef = fields[1].slice("verify ".length);
  const expectedOid = fields[2];
  if (fields[4] !== targetRef || fields[6] !== expectedOid) {
    throw new Error("native symref transaction input is inconsistent");
  }
  const commandOptions = optionsWithoutInput(options);
  const targetOid = String(hostExecFileSync(
    executable,
    ["rev-parse", targetRef],
    { ...commandOptions, encoding: "utf8" },
  )).trim();
  const headOid = String(hostExecFileSync(
    executable,
    ["rev-parse", "HEAD"],
    { ...commandOptions, encoding: "utf8" },
  )).trim();
  if (targetOid !== expectedOid || headOid !== expectedOid) {
    throw new Error("native symref transaction preimage mismatch");
  }
  hostExecFileSync(
    executable,
    [
      "-c",
      "core.hooksPath=/dev/null",
      "symbolic-ref",
      "HEAD",
      targetRef,
    ],
    { ...commandOptions, encoding: "utf8" },
  );
  return outputForEncoding("", options);
}

const gitExecSpy = jest.spyOn(
  childProcessModule,
  "execFileSync",
).mockImplementation((executable, args, options) => {
  if (args.length === 1 && args[0] === "--version") {
    return outputForEncoding(
      `git version ${NATIVE_GIT_VERSION}\n`,
      options,
    );
  }
  if (isNativeSymrefTransaction(args)) {
    return emulateNativeSymrefTransaction(executable, options);
  }
  return hostExecFileSync(executable, args, options);
});

const routerModule = nodeRequire(
  "../scripts/goal-control/worktree-bootstrap-head-router.js",
) as {
  NATIVE_TRANSACTION_PROTOCOL: string;
  attachWorktreeBootstrapHead: (
    options: Record<string, unknown>,
  ) => Record<string, unknown>;
  captureWorktreeGitdirIdentity: (
    cwd: string,
  ) => Record<string, unknown>;
  verifyWorktreeBootstrapHead: (
    options: Record<string, unknown>,
  ) => Record<string, unknown>;
};
const {
  NATIVE_TRANSACTION_PROTOCOL,
  attachWorktreeBootstrapHead,
  captureWorktreeGitdirIdentity,
  verifyWorktreeBootstrapHead,
} = routerModule;

const OPERATION_ID = "bootstrap-head-dev-a1";
const TARGET_REF = "refs/heads/codex/bootstrap-head-dev-a1";
const roots: string[] = [];

type Fixture = {
  artifactRoot: string;
  base: string;
  bindingSha256: string;
  branchFenceFile: string;
  commit: string;
  commonGitDir: string;
  gitDir: string;
  repository: string;
  worker: string;
  worktreeKeySha256: string;
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
    env: {
      PATH: "/usr/bin:/bin",
      HOME: tmpdir(),
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_COUNT: "0",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0",
      LANG: "C",
      LC_ALL: "C",
      NODE_ENV: "test",
    },
  }).trim();
}

function sha256(value: string): string {
  return `sha256:${
    createHash("sha256").update(value).digest("hex")
  }`;
}

function makeFixture(): Fixture {
  const base = mkdtempSync(
    path.join(tmpdir(), "goal-worktree-head-transaction-"),
  );
  roots.push(base);
  const repository = path.join(base, "repository");
  const worker = path.join(base, "worker");
  const artifactRoot = path.join(base, "artifacts");
  const operationRoot = path.join(artifactRoot, "operation");
  mkdirSync(repository);
  mkdirSync(artifactRoot, { mode: 0o700 });
  mkdirSync(operationRoot, { mode: 0o700 });
  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.name", "Head Transaction Test");
  git(
    repository,
    "config",
    "user.email",
    "head-transaction@example.invalid",
  );
  writeFileSync(path.join(repository, "tracked.txt"), "tracked\n");
  git(repository, "add", "tracked.txt");
  git(repository, "commit", "-qm", "fixture");
  const commit = git(repository, "rev-parse", "HEAD");
  git(
    repository,
    "worktree",
    "add",
    "--detach",
    "-q",
    worker,
    commit,
  );
  const canonicalWorker = realpathSync(worker);
  const canonicalArtifactRoot = realpathSync(artifactRoot);
  const identity = captureWorktreeGitdirIdentity(canonicalWorker);
  const targetRefFile = path.join(
    String(identity.common_git_dir),
    ...TARGET_REF.split("/"),
  );
  mkdirSync(path.dirname(targetRefFile), {
    recursive: true,
    mode: 0o700,
  });
  writeFileSync(targetRefFile, `${commit}\n`, { mode: 0o644 });
  return {
    artifactRoot: canonicalArtifactRoot,
    base,
    bindingSha256: sha256("identity-plan-and-observation"),
    branchFenceFile: path.join(
      canonicalArtifactRoot,
      "operation",
      "branch-ref-fence",
    ),
    commit,
    commonGitDir: String(identity.common_git_dir),
    gitDir: String(identity.git_dir),
    repository: realpathSync(repository),
    worker: canonicalWorker,
    worktreeKeySha256: String(identity.worktree_key_sha256),
  };
}

function detachedRegistry(fixture: Fixture): Record<string, unknown> {
  return {
    worktree: fixture.worker,
    head: fixture.commit,
    branch: null,
    detached: true,
  };
}

function attach(
  fixture: Fixture,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return attachWorktreeBootstrapHead({
    cwd: fixture.worker,
    artifactRoot: fixture.artifactRoot,
    branchFenceFile: fixture.branchFenceFile,
    operationId: OPERATION_ID,
    operationBindingSha256: fixture.bindingSha256,
    expectedWorktreeKeySha256: fixture.worktreeKeySha256,
    expectedRegistry: detachedRegistry(fixture),
    expectedDetachedOid: fixture.commit,
    targetRef: TARGET_REF,
    transactionProtocol: NATIVE_TRANSACTION_PROTOCOL,
    ...overrides,
  });
}

function rawHead(fixture: Fixture): string {
  return readFileSync(path.join(fixture.gitDir, "HEAD"), "utf8");
}

function verify(
  fixture: Fixture,
  transaction: Record<string, unknown>,
): Record<string, unknown> {
  return verifyWorktreeBootstrapHead({
    cwd: fixture.worker,
    artifactRoot: fixture.artifactRoot,
    branchFenceFile: fixture.branchFenceFile,
    operationId: OPERATION_ID,
    operationBindingSha256: fixture.bindingSha256,
    expectedWorktreeKeySha256: fixture.worktreeKeySha256,
    expectedWorktreeIdentity:
      captureWorktreeGitdirIdentity(fixture.worker),
    expectedRegistry: detachedRegistry(fixture),
    expectedDetachedOid: fixture.commit,
    targetRef: TARGET_REF,
    expectedClaimFile: transaction.claim_file,
    expectedClaimSha256: transaction.claim_sha256,
    expectedTransactionProtocol: transaction.transaction_protocol,
    expectedCompletionFile: transaction.completion_file,
    expectedCompletionSha256: transaction.completion_sha256,
  });
}

function claimFile(fixture: Fixture): string {
  return path.join(
    fixture.artifactRoot,
    "worktree-bootstrap-head-claims-v1",
    fixture.worktreeKeySha256.slice("sha256:".length),
    "claim.json",
  );
}

function claimStagingFile(fixture: Fixture): string {
  const claim = claimFile(fixture);
  const digest = sha256(readFileSync(claim, "utf8"))
    .slice("sha256:".length);
  return path.join(
    path.dirname(claim),
    `.claim.json.${digest}.tmp`,
  );
}

function expectCode(callback: () => unknown, expected: string): void {
  try {
    callback();
  } catch (error: unknown) {
    expect((error as { code?: string }).code).toBe(expected);
    return;
  }
  throw new Error(`expected ${expected}`);
}

afterEach(() => {
  while (roots.length > 0) {
    rmSync(roots.pop()!, { recursive: true, force: true });
  }
});

afterAll(() => {
  gitExecSpy.mockRestore();
});

describe("Git-native worktree bootstrap HEAD transaction", () => {
  it("durably claims and idempotently attaches the exact target symref", () => {
    const fixture = makeFixture();

    const first = attach(fixture);

    expect(first).toMatchObject({
      schema_version: 1,
      transaction_protocol: "git-update-ref-symref-v1",
      worktree_key_sha256: fixture.worktreeKeySha256,
      claim_created: true,
      operation_id: OPERATION_ID,
      operation_binding_sha256: fixture.bindingSha256,
      git_dir: fixture.gitDir,
      expected_oid: fixture.commit,
      target_ref: TARGET_REF,
      head_state: "ATTACHED",
      idempotent: false,
    });
    expect(rawHead(fixture)).toBe(`ref: ${TARGET_REF}\n`);
    expect(git(fixture.worker, "symbolic-ref", "--short", "HEAD"))
      .toBe(TARGET_REF.slice("refs/heads/".length));
    expect(existsSync(path.join(fixture.gitDir, "HEAD.lock")))
      .toBe(false);
    expect(existsSync(claimFile(fixture))).toBe(true);
    expect(verify(fixture, first)).toMatchObject({
      claim_file: first.claim_file,
      claim_sha256: first.claim_sha256,
      head_state: "ATTACHED",
    });

    const retry = attach(fixture);
    expect(retry).toMatchObject({
      claim_created: false,
      claim_file: first.claim_file,
      claim_sha256: first.claim_sha256,
      idempotent: true,
    });
    expect(rawHead(fixture)).toBe(`ref: ${TARGET_REF}\n`);
  });

  it("verification rejects missing durable owner/operation lineage", () => {
    const fixture = makeFixture();
    const transaction = attach(fixture);
    unlinkSync(path.join(path.dirname(claimFile(fixture)), "owner"));

    expectCode(
      () => verify(fixture, transaction),
      "WORKTREE_BOOTSTRAP_HEAD_CLAIM_CONFLICT",
    );
  });

  it("verification rejects foreign Git locks", () => {
    const fixture = makeFixture();
    const transaction = attach(fixture);
    writeFileSync(path.join(fixture.gitDir, "HEAD.lock"), "");

    expectCode(
      () => verify(fixture, transaction),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
    unlinkSync(path.join(fixture.gitDir, "HEAD.lock"));
    symlinkSync(
      path.join(fixture.base, "missing-index-lock-target"),
      path.join(fixture.gitDir, "index.lock"),
    );
    expectCode(
      () => verify(fixture, transaction),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
  });

  it("verification rejects a packed-only target ref", () => {
    const fixture = makeFixture();
    const transaction = attach(fixture);
    git(fixture.worker, "pack-refs", "--all");

    expectCode(
      () => verify(fixture, transaction),
      "WORKTREE_BOOTSTRAP_HEAD_TARGET_REF_INVALID",
    );
  });

  it("verification rejects a packed shadow behind the loose target ref", () => {
    const fixture = makeFixture();
    const transaction = attach(fixture);
    writeFileSync(
      path.join(fixture.commonGitDir, "packed-refs"),
      [
        "# pack-refs with: peeled fully-peeled sorted",
        `${fixture.commit} ${TARGET_REF}`,
        "",
      ].join("\n"),
    );

    expectCode(
      () => verify(fixture, transaction),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
  });

  it("verification rejects branch reflogs and reflog lock artifacts", () => {
    const fixture = makeFixture();
    const transaction = attach(fixture);
    const branchLog = path.join(
      fixture.commonGitDir,
      "logs",
      ...TARGET_REF.split("/"),
    );
    mkdirSync(path.dirname(branchLog), {
      recursive: true,
      mode: 0o700,
    });
    writeFileSync(branchLog, "foreign reflog\n");
    expectCode(
      () => verify(fixture, transaction),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
    unlinkSync(branchLog);
    symlinkSync(
      path.join(fixture.base, "missing-reflog-lock-target"),
      `${branchLog}.lock`,
    );
    expectCode(
      () => verify(fixture, transaction),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
  });

  it("verification rejects a residual branch fence or HEAD reflog lock", () => {
    const fixture = makeFixture();
    const transaction = attach(fixture);
    writeFileSync(fixture.branchFenceFile, `${fixture.commit}\n`, {
      mode: 0o600,
    });
    expectCode(
      () => verify(fixture, transaction),
      "WORKTREE_BOOTSTRAP_HEAD_ARTIFACT_INVALID",
    );
    unlinkSync(fixture.branchFenceFile);

    const headLogDirectory = path.join(fixture.gitDir, "logs");
    mkdirSync(headLogDirectory, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(headLogDirectory, "HEAD.lock"), "");
    expectCode(
      () => verify(fixture, transaction),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
  });

  it("retries both claim-before-child and committed-before-response crashes", () => {
    const beforeChild = makeFixture();
    expect(() => attach(beforeChild, {
      onStage(stage: string) {
        if (stage === "claim-published") {
          throw new Error("crash-after-claim");
        }
      },
    })).toThrow("crash-after-claim");
    expect(rawHead(beforeChild)).toBe(`${beforeChild.commit}\n`);
    expect(attach(beforeChild)).toMatchObject({
      claim_created: false,
      idempotent: false,
    });

    const afterCommit = makeFixture();
    expect(() => attach(afterCommit, {
      onStage(stage: string) {
        if (stage === "after-git-transaction") {
          throw new Error("response-lost-after-commit");
        }
      },
    })).toThrow("response-lost-after-commit");
    expect(rawHead(afterCommit)).toBe(`ref: ${TARGET_REF}\n`);
    expect(attach(afterCommit)).toMatchObject({
      claim_created: false,
      idempotent: true,
    });
  });

  it("recovers exact pending claim publication while verification stays read-only", () => {
    const fixture = makeFixture();
    expect(() => attach(fixture, {
      onStage(stage: string) {
        if (stage === "claim-record-target-published") {
          throw new Error("crash-with-claim-hardlink");
        }
      },
    })).toThrow("crash-with-claim-hardlink");
    const staging = claimStagingFile(fixture);
    expect(lstatSync(claimFile(fixture)).nlink).toBe(2);
    expect(existsSync(staging)).toBe(true);

    expectCode(
      () => verify(fixture, {
        claim_file: claimFile(fixture),
        claim_sha256: sha256(readFileSync(claimFile(fixture), "utf8")),
        transaction_protocol: "git-update-ref-symref-v1",
      }),
      "CANARY_BOOTSTRAP_ARTIFACT_INVALID",
    );
    expect(existsSync(staging)).toBe(true);
    expect(lstatSync(claimFile(fixture)).nlink).toBe(2);

    const completed = attach(fixture);
    expect(completed).toMatchObject({
      transaction_protocol: "git-update-ref-symref-v1",
      head_state: "ATTACHED",
    });
    expect(existsSync(staging)).toBe(false);
    expect(lstatSync(claimFile(fixture)).nlink).toBe(1);
    expect(verify(fixture, completed)).toMatchObject({
      claim_sha256: completed.claim_sha256,
    });
  });

  it("rejects a different operation or altered exact-operation binding", () => {
    const fixture = makeFixture();
    expect(() => attach(fixture, {
      onStage(stage: string) {
        if (stage === "claim-published") throw new Error("claim-only");
      },
    })).toThrow("claim-only");

    expectCode(
      () => attach(fixture, { operationId: "bootstrap-head-dev-a2" }),
      "WORKTREE_BOOTSTRAP_HEAD_CLAIM_CONFLICT",
    );
    expectCode(
      () => attach(fixture, {
        operationBindingSha256: sha256("altered-binding"),
      }),
      "WORKTREE_BOOTSTRAP_HEAD_CLAIM_CONFLICT",
    );
    expect(rawHead(fixture)).toBe(`${fixture.commit}\n`);
    expect(attach(fixture)).toMatchObject({ idempotent: false });
  });

  it.each(["HEAD.lock", "target-ref.lock", "packed-refs.lock"])(
    "fails closed without removing a foreign/stale %s",
    (kind) => {
      const fixture = makeFixture();
      const targetRefFile = path.join(
        fixture.commonGitDir,
        ...TARGET_REF.split("/"),
      );
      const lock = kind === "HEAD.lock"
        ? path.join(fixture.gitDir, "HEAD.lock")
        : kind === "target-ref.lock"
        ? `${targetRefFile}.lock`
        : path.join(fixture.commonGitDir, "packed-refs.lock");
      writeFileSync(lock, "foreign\n", { mode: 0o644 });

      expectCode(
        () => attach(fixture),
        "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
      );
      expect(existsSync(lock)).toBe(true);
      expect(rawHead(fixture)).toBe(`${fixture.commit}\n`);
      expect(existsSync(claimFile(fixture))).toBe(false);
    },
  );

  it("rejects a symlink lock without following or deleting it", () => {
    const fixture = makeFixture();
    const lock = path.join(fixture.gitDir, "HEAD.lock");
    symlinkSync("/dev/null", lock);

    expectCode(
      () => attach(fixture),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
    expect(lstatSync(lock).isSymbolicLink()).toBe(true);
    expect(rawHead(fixture)).toBe(`${fixture.commit}\n`);
  });

  it("rejects non-exact raw HEAD and target-ref drift before claiming", () => {
    const invalidHead = makeFixture();
    writeFileSync(
      path.join(invalidHead.gitDir, "HEAD"),
      "ref: refs/heads/foreign\n",
    );
    expectCode(
      () => attach(invalidHead),
      "WORKTREE_BOOTSTRAP_HEAD_PREIMAGE_CONFLICT",
    );
    expect(existsSync(claimFile(invalidHead))).toBe(false);

    const driftedRef = makeFixture();
    git(
      driftedRef.repository,
      "commit",
      "--allow-empty",
      "-qm",
      "different target",
    );
    git(
      driftedRef.repository,
      "update-ref",
      TARGET_REF,
      git(driftedRef.repository, "rev-parse", "HEAD"),
    );
    expectCode(
      () => attach(driftedRef),
      "WORKTREE_BOOTSTRAP_HEAD_TARGET_REF_INVALID",
    );
    expect(rawHead(driftedRef)).toBe(`${driftedRef.commit}\n`);
  });

  it("rejects delete-and-recreate ABA against the observed identity key", () => {
    const fixture = makeFixture();
    git(
      fixture.repository,
      "worktree",
      "remove",
      "--force",
      fixture.worker,
    );
    git(
      fixture.repository,
      "worktree",
      "add",
      "--detach",
      "-q",
      fixture.worker,
      fixture.commit,
    );
    const replacement = captureWorktreeGitdirIdentity(fixture.worker);
    expect(replacement.worktree_key_sha256)
      .not.toBe(fixture.worktreeKeySha256);

    expectCode(
      () => attach(fixture),
      "WORKTREE_BOOTSTRAP_HEAD_IDENTITY_INVALID",
    );
    expect(existsSync(claimFile(fixture))).toBe(false);
  });

  it("binds .git, gitdir and commondir reciprocal registry bytes", () => {
    const fixture = makeFixture();
    writeFileSync(
      path.join(fixture.gitDir, "gitdir"),
      `${path.join(fixture.base, "foreign", ".git")}\n`,
    );

    expectCode(
      () => attach(fixture),
      "WORKTREE_BOOTSTRAP_HEAD_IDENTITY_INVALID",
    );
    expect(existsSync(claimFile(fixture))).toBe(false);
    expect(rawHead(fixture)).toBe(`${fixture.commit}\n`);
  });

  it("does not backfill provenance for an unclaimed pre-attached symref", () => {
    const fixture = makeFixture();
    writeFileSync(
      path.join(fixture.gitDir, "HEAD"),
      `ref: ${TARGET_REF}\n`,
      { mode: 0o644 },
    );

    expectCode(
      () => attach(fixture),
      "WORKTREE_BOOTSTRAP_HEAD_CLAIM_CONFLICT",
    );
    expect(existsSync(claimFile(fixture))).toBe(false);
  });

  it("ignores ambient Git redirection and disables reference hooks", () => {
    const fixture = makeFixture();
    const marker = path.join(fixture.base, "hook-ran");
    const hook = path.join(
      fixture.commonGitDir,
      "hooks",
      "reference-transaction",
    );
    writeFileSync(
      hook,
      `#!/bin/sh\n/usr/bin/touch '${marker}'\n`,
      { mode: 0o700 },
    );
    chmodSync(hook, 0o700);
    git(fixture.repository, "config", "core.hooksPath", "hooks");
    const previousGitDir = process.env.GIT_DIR;
    process.env.GIT_DIR = path.join(fixture.base, "foreign.git");
    try {
      attach(fixture);
    } finally {
      if (previousGitDir === undefined) delete process.env.GIT_DIR;
      else process.env.GIT_DIR = previousGitDir;
    }

    expect(rawHead(fixture)).toBe(`ref: ${TARGET_REF}\n`);
    expect(existsSync(marker)).toBe(false);
  });
});
