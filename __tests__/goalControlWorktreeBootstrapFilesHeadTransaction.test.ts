import { execFileSync } from "child_process";
import { createHash } from "crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { createRequire } from "module";
import { tmpdir } from "os";
import path from "path";

const nodeRequire = createRequire(import.meta.url);
const FILES_GIT_VERSION = "2.43.0";
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
let simulatedGitVersion = FILES_GIT_VERSION;

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
  if (simulatedGitVersion !== NATIVE_GIT_VERSION) {
    throw new Error(
      "Git 2.43 files-fallback test unexpectedly invoked native symref",
    );
  }
  const input = options?.input;
  const fields = Buffer.from(input || "").toString("utf8")
    .split("\0")
    .filter(Boolean);
  if (
    fields.length !== 9
      || fields[0] !== "start"
      || !fields[1].startsWith("verify refs/")
      || !fields[3].startsWith("symref-update HEAD")
      || fields[5] !== "oid"
      || fields[7] !== "prepare"
      || fields[8] !== "commit"
  ) {
    throw new Error("unexpected native symref transaction input");
  }
  const targetRef = fields[1].slice("verify ".length);
  const expectedOid = fields[2];
  if (
    fields[4] !== targetRef
      || fields[6] !== expectedOid
  ) {
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
    ["symbolic-ref", "HEAD", targetRef],
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
      `git version ${simulatedGitVersion}\n`,
      options,
    );
  }
  if (isNativeSymrefTransaction(args)) {
    return emulateNativeSymrefTransaction(executable, options);
  }
  return hostExecFileSync(executable, args, options);
});

const {
  FILES_TRANSACTION_PROTOCOL,
  NATIVE_TRANSACTION_PROTOCOL,
  attachWorktreeBootstrapHead,
  captureWorktreeGitdirIdentity,
  verifyWorktreeBootstrapHead,
} = nodeRequire(
  "../scripts/goal-control/worktree-bootstrap-head-router.js",
) as {
  FILES_TRANSACTION_PROTOCOL: string;
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
const { hashObject } = nodeRequire(
  "../scripts/goal-control/util.js",
) as {
  hashObject: (value: unknown) => string;
};

const OPERATION_ID = "bootstrap-files-head-dev-a1";
const TARGET_REF = "refs/heads/codex/bootstrap-files-head-dev-a1";
const BINDING_SHA256 = sha256("files-head-operation-binding");
const roots: string[] = [];

type IndexObservation = {
  path: string;
  sha256: string;
  size: number;
  identity: Record<string, string>;
};

type Fixture = {
  artifactRoot: string;
  base: string;
  branchFenceFile: string;
  commit: string;
  commonGitDir: string;
  completionFile: string;
  expectedIndex: IndexObservation;
  gitDir: string;
  headFenceFile: string;
  repository: string;
  targetRefFile: string;
  worker: string;
  worktreeIdentity: Record<string, unknown>;
  worktreeKeySha256: string;
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("/usr/bin/git", args, {
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

function sha256(value: string | Buffer): string {
  return `sha256:${
    createHash("sha256").update(value).digest("hex")
  }`;
}

function indexObservation(gitDir: string): IndexObservation {
  const file = path.join(gitDir, "index");
  const bytes = readFileSync(file);
  const stat = lstatSync(file, { bigint: true });
  return {
    path: file,
    sha256: sha256(bytes),
    size: bytes.length,
    identity: {
      dev: stat.dev.toString(),
      ino: stat.ino.toString(),
      mode: stat.mode.toString(),
      uid: stat.uid.toString(),
      nlink: stat.nlink.toString(),
      size: stat.size.toString(),
      mtime_ns: stat.mtimeNs.toString(),
      ctime_ns: stat.ctimeNs.toString(),
    },
  };
}

function makeFixture(): Fixture {
  const base = mkdtempSync(
    path.join(tmpdir(), "goal-files-head-transaction-"),
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
  git(repository, "config", "user.name", "Files Head Test");
  git(
    repository,
    "config",
    "user.email",
    "files-head@example.invalid",
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
  const commonGitDir = String(identity.common_git_dir);
  const gitDir = String(identity.git_dir);
  const targetRefFile = path.join(
    commonGitDir,
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
    branchFenceFile: path.join(
      canonicalArtifactRoot,
      "operation",
      "branch-ref-fence",
    ),
    commit,
    commonGitDir,
    completionFile: path.join(
      canonicalArtifactRoot,
      "operation",
      "head-transaction-completion.json",
    ),
    expectedIndex: indexObservation(gitDir),
    gitDir,
    headFenceFile: path.join(
      canonicalArtifactRoot,
      "operation",
      "head-transaction.fence",
    ),
    repository: realpathSync(repository),
    targetRefFile,
    worker: canonicalWorker,
    worktreeIdentity: identity,
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
    headFenceFile: fixture.headFenceFile,
    completionFile: fixture.completionFile,
    operationId: OPERATION_ID,
    operationBindingSha256: BINDING_SHA256,
    expectedWorktreeKeySha256: fixture.worktreeKeySha256,
    expectedRegistry: detachedRegistry(fixture),
    expectedIndex: fixture.expectedIndex,
    expectedDetachedOid: fixture.commit,
    targetRef: TARGET_REF,
    transactionProtocol: FILES_TRANSACTION_PROTOCOL,
    ...overrides,
  });
}

function retry(fixture: Fixture): Record<string, unknown> {
  return attach(fixture, { transactionProtocol: undefined });
}

function verify(
  fixture: Fixture,
  transaction: Record<string, unknown>,
): Record<string, unknown> {
  return verifyWorktreeBootstrapHead({
    cwd: fixture.worker,
    artifactRoot: fixture.artifactRoot,
    branchFenceFile: fixture.branchFenceFile,
    headFenceFile: fixture.headFenceFile,
    completionFile: fixture.completionFile,
    operationId: OPERATION_ID,
    operationBindingSha256: BINDING_SHA256,
    expectedWorktreeKeySha256: fixture.worktreeKeySha256,
    expectedWorktreeIdentity: fixture.worktreeIdentity,
    expectedRegistry: detachedRegistry(fixture),
    expectedIndex: fixture.expectedIndex,
    expectedDetachedOid: fixture.commit,
    targetRef: TARGET_REF,
    expectedClaimFile: transaction.claim_file,
    expectedClaimSha256: transaction.claim_sha256,
    expectedTransactionProtocol: transaction.transaction_protocol,
    expectedCompletionFile: transaction.completion_file,
    expectedCompletionSha256: transaction.completion_sha256,
  });
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
  const digest = sha256(readFileSync(claim)).slice("sha256:".length);
  return path.join(
    path.dirname(claim),
    `.claim.json.${digest}.tmp`,
  );
}

afterEach(() => {
  while (roots.length > 0) {
    rmSync(roots.pop()!, { recursive: true, force: true });
  }
});

beforeEach(() => {
  simulatedGitVersion = FILES_GIT_VERSION;
});

afterAll(() => {
  gitExecSpy.mockRestore();
});

describe("Git files-backend worktree bootstrap HEAD transaction", () => {
  test("forced fallback seals completion and retry keeps the durable backend", () => {
    const fixture = makeFixture();

    const first = attach(fixture);

    expect(first).toMatchObject({
      schema_version: 1,
      transaction_protocol: FILES_TRANSACTION_PROTOCOL,
      git_minimum_version: "2.43",
      git_ref_backend: "files",
      head_state: "ATTACHED",
      idempotent: false,
    });
    expect(readFileSync(path.join(fixture.gitDir, "HEAD"), "utf8"))
      .toBe(`ref: ${TARGET_REF}\n`);
    expect(existsSync(fixture.headFenceFile)).toBe(false);
    expect(statSync(fixture.completionFile).mode & 0o777).toBe(0o600);
    expect(verify(fixture, first)).toMatchObject({
      transaction_protocol: FILES_TRANSACTION_PROTOCOL,
      completion_file: fixture.completionFile,
      completion_sha256: first.completion_sha256,
    });

    const second = retry(fixture);
    expect(second).toMatchObject({
      transaction_protocol: FILES_TRANSACTION_PROTOCOL,
      claim_created: false,
      claim_sha256: first.claim_sha256,
      completion_sha256: first.completion_sha256,
      idempotent: true,
    });
  });

  test.each([
    "claim-owner-acquired",
    "claim-record-staging-created",
    "claim-record-target-published",
    "claim-record-staging-unlinked",
    "claim-record-published",
    "files-fence-opened",
    "files-fence-prefix-written",
    "files-fence-created",
    "files-packed-lock-acquired",
    "files-ref-lock-acquired",
    "files-index-lock-acquired",
    "files-head-lock-acquired",
    "before-files-head-rename",
    "after-files-head-rename",
    "files-completion-staging-created",
    "files-completion-target-published",
    "files-completion-staging-unlinked",
    "files-index-lock-released",
    "files-ref-lock-released",
    "files-packed-lock-released",
    "files-fence-released",
  ])("exact retry recovers crash stage %s without backend switching", (stage) => {
    const fixture = makeFixture();
    expect(() => attach(fixture, {
      onStage(current: string) {
        if (current === stage) throw new Error(`crash:${stage}`);
      },
    })).toThrow();

    const completed = retry(fixture);
    expect(completed).toMatchObject({
      transaction_protocol: FILES_TRANSACTION_PROTOCOL,
      head_state: "ATTACHED",
    });
    expect(verify(fixture, completed)).toMatchObject({
      transaction_protocol: FILES_TRANSACTION_PROTOCOL,
    });
    expect(existsSync(path.join(fixture.gitDir, "HEAD.lock")))
      .toBe(false);
    expect(existsSync(path.join(fixture.gitDir, "index.lock")))
      .toBe(false);
    expect(existsSync(`${fixture.targetRefFile}.lock`)).toBe(false);
    expect(existsSync(
      path.join(fixture.commonGitDir, "packed-refs.lock"),
    )).toBe(false);
  });

  test("pending claim publication is attach-recoverable but verifier-read-only", () => {
    const fixture = makeFixture();
    expect(() => attach(fixture, {
      onStage(stage: string) {
        if (stage === "claim-record-target-published") {
          throw new Error("crash-with-files-claim-hardlink");
        }
      },
    })).toThrow("crash-with-files-claim-hardlink");
    const staging = claimStagingFile(fixture);
    expect(existsSync(staging)).toBe(true);
    expect(lstatSync(claimFile(fixture)).nlink).toBe(2);

    expectCode(
      () => verify(fixture, {
        claim_file: claimFile(fixture),
        claim_sha256: sha256(readFileSync(claimFile(fixture))),
        transaction_protocol: FILES_TRANSACTION_PROTOCOL,
      }),
      "CANARY_BOOTSTRAP_ARTIFACT_INVALID",
    );
    expect(existsSync(staging)).toBe(true);
    expect(lstatSync(claimFile(fixture)).nlink).toBe(2);

    const completed = retry(fixture);
    expect(completed.transaction_protocol)
      .toBe(FILES_TRANSACTION_PROTOCOL);
    expect(existsSync(staging)).toBe(false);
    expect(lstatSync(claimFile(fixture)).nlink).toBe(1);
    expect(verify(fixture, completed)).toMatchObject({
      completion_sha256: completed.completion_sha256,
    });
  });

  test.each([
    "HEAD.lock",
    "index.lock.extra",
    "packed-refs.lock.stale",
    "target-ref.lock.extra",
  ])("rejects and preserves foreign lock family member %s", (kind) => {
    const fixture = makeFixture();
    const file = kind === "HEAD.lock"
      ? path.join(fixture.gitDir, kind)
      : kind.startsWith("index")
      ? path.join(fixture.gitDir, kind)
      : kind.startsWith("packed")
      ? path.join(fixture.commonGitDir, kind)
      : `${fixture.targetRefFile}.lock.extra`;
    writeFileSync(file, "foreign\n");

    expectCode(
      () => attach(fixture),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
    expect(readFileSync(file, "utf8")).toBe("foreign\n");
  });

  test("rejects symlink locks and unknown hardlinks without cleanup", () => {
    const symlinkFixture = makeFixture();
    const symlink = path.join(symlinkFixture.gitDir, "index.lock");
    symlinkSync("/dev/null", symlink);
    expectCode(
      () => attach(symlinkFixture),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
    expect(lstatSync(symlink).isSymbolicLink()).toBe(true);

    const hardlinkFixture = makeFixture();
    expect(() => attach(hardlinkFixture, {
      onStage(stage: string) {
        if (stage === "files-fence-created") {
          throw new Error("stop-at-fence");
        }
      },
    })).toThrow();
    const foreign = path.join(
      hardlinkFixture.artifactRoot,
      "operation",
      "foreign-fence-link",
    );
    linkSync(hardlinkFixture.headFenceFile, foreign);
    expectCode(
      () => retry(hardlinkFixture),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
    expect(existsSync(foreign)).toBe(true);
    expect(existsSync(hardlinkFixture.headFenceFile)).toBe(true);
  });

  test("rejects and preserves a packed shadow behind the loose target ref", () => {
    const fixture = makeFixture();
    const packedRefs = path.join(fixture.commonGitDir, "packed-refs");
    const bytes = [
      "# pack-refs with: peeled fully-peeled sorted",
      `${fixture.commit} ${TARGET_REF}`,
      "",
    ].join("\n");
    writeFileSync(packedRefs, bytes, { mode: 0o644 });

    expectCode(
      () => attach(fixture),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
    expect(readFileSync(packedRefs, "utf8")).toBe(bytes);
    expect(existsSync(claimFile(fixture))).toBe(false);
  });

  test("rejects and preserves a residual branch-ref fence", () => {
    const before = makeFixture();
    writeFileSync(before.branchFenceFile, `${before.commit}\n`, {
      mode: 0o600,
    });
    expectCode(
      () => attach(before),
      "WORKTREE_BOOTSTRAP_HEAD_ARTIFACT_INVALID",
    );
    expect(readFileSync(before.branchFenceFile, "utf8"))
      .toBe(`${before.commit}\n`);

    const after = makeFixture();
    const completed = attach(after);
    writeFileSync(after.branchFenceFile, `${after.commit}\n`, {
      mode: 0o600,
    });
    expectCode(
      () => verify(after, completed),
      "WORKTREE_BOOTSTRAP_HEAD_ARTIFACT_INVALID",
    );
    expect(readFileSync(after.branchFenceFile, "utf8"))
      .toBe(`${after.commit}\n`);
  });

  test("rejects HEAD, target-ref, and index same-bytes ABA after claim", () => {
    const headFixture = makeFixture();
    expect(() => attach(headFixture, {
      onStage(stage: string) {
        if (stage === "claim-record-published") {
          throw new Error("stop-after-claim");
        }
      },
    })).toThrow();
    const headFile = path.join(headFixture.gitDir, "HEAD");
    const headBytes = readFileSync(headFile);
    unlinkSync(headFile);
    writeFileSync(headFile, headBytes, { mode: 0o644 });
    expectCode(
      () => retry(headFixture),
      "WORKTREE_BOOTSTRAP_HEAD_PREIMAGE_CONFLICT",
    );

    const refFixture = makeFixture();
    expect(() => attach(refFixture, {
      onStage(stage: string) {
        if (stage === "claim-record-published") {
          throw new Error("stop-after-claim");
        }
      },
    })).toThrow();
    const refBytes = readFileSync(refFixture.targetRefFile);
    unlinkSync(refFixture.targetRefFile);
    writeFileSync(refFixture.targetRefFile, refBytes, { mode: 0o644 });
    expectCode(
      () => retry(refFixture),
      "WORKTREE_BOOTSTRAP_HEAD_TARGET_REF_INVALID",
    );

    const indexFixture = makeFixture();
    expect(() => attach(indexFixture, {
      onStage(stage: string) {
        if (stage === "claim-record-published") {
          throw new Error("stop-after-claim");
        }
      },
    })).toThrow();
    const indexFile = path.join(indexFixture.gitDir, "index");
    const indexBytes = readFileSync(indexFile);
    unlinkSync(indexFile);
    writeFileSync(indexFile, indexBytes, { mode: 0o644 });
    expectCode(
      () => retry(indexFixture),
      "WORKTREE_BOOTSTRAP_HEAD_IDENTITY_INVALID",
    );
  });

  test("does not backfill completion for an attached HEAD without owned topology", () => {
    const fixture = makeFixture();
    const completed = attach(fixture);
    unlinkSync(fixture.completionFile);

    expectCode(
      () => retry(fixture),
      "WORKTREE_BOOTSTRAP_HEAD_LOCK_CONFLICT",
    );
    expect(existsSync(fixture.completionFile)).toBe(false);
    expect(readFileSync(path.join(fixture.gitDir, "HEAD"), "utf8"))
      .toBe(`ref: ${TARGET_REF}\n`);
    expect(completed.transaction_protocol)
      .toBe(FILES_TRANSACTION_PROTOCOL);
  });

  test("receipt verification is read-only and rejects completion tampering", () => {
    const fixture = makeFixture();
    const completed = attach(fixture);
    const completion = JSON.parse(
      readFileSync(fixture.completionFile, "utf8"),
    ) as Record<string, unknown>;
    completion.target_ref = "refs/heads/codex/foreign";
    writeFileSync(
      fixture.completionFile,
      `${JSON.stringify(completion, null, 2)}\n`,
      { mode: 0o600 },
    );
    expectCode(
      () => verify(fixture, {
        ...completed,
        completion_sha256: sha256(
          readFileSync(fixture.completionFile),
        ),
      }),
      "WORKTREE_BOOTSTRAP_HEAD_CLAIM_CONFLICT",
    );

    const missing = path.join(fixture.base, "missing-artifact-root");
    expectCode(
      () => verifyWorktreeBootstrapHead({
        cwd: fixture.worker,
        artifactRoot: missing,
        branchFenceFile: path.join(missing, "branch-fence"),
        operationId: OPERATION_ID,
        operationBindingSha256: BINDING_SHA256,
        expectedWorktreeKeySha256: fixture.worktreeKeySha256,
        expectedWorktreeIdentity: fixture.worktreeIdentity,
        expectedRegistry: detachedRegistry(fixture),
        expectedIndex: fixture.expectedIndex,
        expectedDetachedOid: fixture.commit,
        targetRef: TARGET_REF,
        expectedClaimFile: claimFile(fixture),
        expectedClaimSha256: completed.claim_sha256,
        expectedTransactionProtocol: FILES_TRANSACTION_PROTOCOL,
      }),
      "CANARY_BOOTSTRAP_ARTIFACT_INVALID",
    );
    expect(existsSync(missing)).toBe(false);
  });

  test("legacy claim without protocol is interpreted only as native", () => {
    simulatedGitVersion = NATIVE_GIT_VERSION;
    const fixture = makeFixture();
    const claimUnsigned = {
      schema_version: 1,
      kind: "WORKTREE_BOOTSTRAP_HEAD_CLAIM",
      worktree: fixture.worktreeIdentity,
      expected_registry: detachedRegistry(fixture),
      operation_id: OPERATION_ID,
      operation_binding_sha256: BINDING_SHA256,
      expected_worktree_key_sha256: fixture.worktreeKeySha256,
      expected_detached_oid: fixture.commit,
      target_ref: TARGET_REF,
    };
    const requestSha256 = hashObject(claimUnsigned);
    const directory = path.dirname(claimFile(fixture));
    const operations = path.join(directory, "operations");
    const anchor = path.join(
      operations,
      `${requestSha256.slice("sha256:".length)}.anchor`,
    );
    mkdirSync(operations, { recursive: true, mode: 0o700 });
    chmodSync(path.dirname(directory), 0o700);
    chmodSync(directory, 0o700);
    writeFileSync(anchor, "", { mode: 0o600 });
    linkSync(anchor, path.join(directory, "owner"));
    const claim = {
      ...claimUnsigned,
      claim_request_sha256: requestSha256,
    };
    writeFileSync(
      claimFile(fixture),
      `${JSON.stringify(claim, null, 2)}\n`,
      { mode: 0o600 },
    );
    const staging = claimStagingFile(fixture);
    linkSync(claimFile(fixture), staging);
    const legacyTransaction = {
      claim_file: claimFile(fixture),
      claim_sha256: sha256(readFileSync(claimFile(fixture))),
      transaction_protocol: NATIVE_TRANSACTION_PROTOCOL,
    };
    expectCode(
      () => verify(fixture, legacyTransaction),
      "CANARY_BOOTSTRAP_ARTIFACT_INVALID",
    );
    expect(existsSync(staging)).toBe(true);
    expect(lstatSync(claimFile(fixture)).nlink).toBe(2);

    const completed = retry(fixture);
    expect(completed).toMatchObject({
      transaction_protocol: NATIVE_TRANSACTION_PROTOCOL,
      claim_sha256: sha256(readFileSync(claimFile(fixture))),
      head_state: "ATTACHED",
    });
    expect(verify(fixture, completed)).toMatchObject({
      transaction_protocol: NATIVE_TRANSACTION_PROTOCOL,
      claim_sha256: completed.claim_sha256,
    });
    expect(existsSync(staging)).toBe(false);
  });
});
