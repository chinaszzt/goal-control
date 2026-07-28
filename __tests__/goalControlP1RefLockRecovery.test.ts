import { execFileSync } from "child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { createRequire } from "module";

type P1Intent = Record<string, unknown> & {
  intent_sha256: string;
};
type P1Preparation = Record<string, unknown> & {
  intent: P1Intent;
};

const nodeRequire = createRequire(import.meta.url);
const {
  abandonP1CommitRef,
  p1CommitPaths,
  publishP1CommitRef,
  readP1CommitIntent,
} = nodeRequire(
  "../scripts/goal-control/p1-commit-transaction.js",
) as {
  abandonP1CommitRef: (
    cwd: string,
    intent: Record<string, unknown>,
    prepared: Record<string, unknown>,
  ) => void;
  p1CommitPaths: (
    root: string,
    goalId: string,
    taskId: string,
    eventId: string,
  ) => Record<string, string>;
  publishP1CommitRef: (
    cwd: string,
    intent: Record<string, unknown>,
  ) => string;
  readP1CommitIntent: (
    root: string,
    goalId: string,
    taskId: string,
    eventId: string,
  ) => P1Preparation | null;
};
const {
  hashFile,
  hashObject,
  sha256,
} = nodeRequire("../scripts/goal-control/util.js") as {
  hashFile: (file: string) => string;
  hashObject: (value: unknown) => string;
  sha256: (value: string | Buffer) => string;
};
const {
  describeLooseRefReflog,
  executeLooseRefTransaction,
} = nodeRequire(
  "../scripts/goal-control/git-loose-ref-transaction.js",
) as {
  describeLooseRefReflog: (
    options: Record<string, unknown>,
  ) => Record<string, unknown>;
  executeLooseRefTransaction: (
    options: Record<string, unknown>,
  ) => string | null;
};

const ZERO_OID = "0".repeat(40);
const temporaryRoots: string[] = [];
const originalGoalControlDir = process.env.GOAL_CONTROL_DIR;
const originalGoalControlTestMode = process.env.GOAL_CONTROL_TEST_MODE;
const P1_REF_FAULTS = [
  "GOAL_CONTROL_TEST_FAULT_DURING_P1_REF_LOCK_FENCE",
  "GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_LOCK_FENCE",
  "GOAL_CONTROL_TEST_FAULT_AFTER_P1_PACKED_LOCK_LINK",
  "GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_LOCK_LINK",
  "GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_CANONICAL_MUTATION",
  "GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_LOCK_RELEASE",
  "GOAL_CONTROL_TEST_FAULT_AFTER_P1_PACKED_LOCK_RELEASE",
  "GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_FENCE_CLEANUP",
] as const;
const originalRefFaults = Object.fromEntries(
  P1_REF_FAULTS.map((name) => [name, process.env[name]]),
);

type Fixture = {
  base: string;
  commit: string;
  commonGitDir: string;
  controlRoot: string;
  eventId: string;
  goalId: string;
  intent: Record<string, unknown>;
  paths: Record<string, string>;
  ref: string;
  repository: string;
  taskId: string;
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

function readRef(cwd: string, ref: string): string | null {
  try {
    return git(cwd, "rev-parse", "--verify", "--quiet", ref);
  } catch (error: unknown) {
    if ((error as { status?: number }).status === 1) return null;
    throw error;
  }
}

function writePrivate(file: string, body: string | Buffer): void {
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, body, { mode: 0o600 });
  chmodSync(file, 0o600);
}

function writePrivateJson(file: string, value: unknown): void {
  writePrivate(file, `${JSON.stringify(value, null, 2)}\n`);
}

function expectCode(callback: () => unknown, code: string): void {
  let thrown: unknown = null;
  try {
    callback();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toMatchObject({ code });
}

function activate(fixture: Fixture): void {
  process.env.GOAL_CONTROL_DIR = fixture.controlRoot;
  process.env.GOAL_CONTROL_TEST_MODE = "1";
}

function makeFixture(): Fixture {
  const base = mkdtempSync(path.join(tmpdir(), "goalctl-p1-ref-lock-"));
  temporaryRoots.push(base);
  const repository = path.join(base, "repository");
  const controlRoot = path.join(base, "control");
  mkdirSync(repository, { mode: 0o700 });
  mkdirSync(controlRoot, { mode: 0o700 });
  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.email", "p1-ref-lock@example.test");
  git(repository, "config", "user.name", "P1 Ref Lock Test");
  git(repository, "commit", "--allow-empty", "-qm", "baseline");
  const commit = git(repository, "rev-parse", "HEAD");
  const commonGitDir = realpathSync(path.join(repository, ".git"));
  const goalId = "goal-ref-lock";
  const taskId = "task-ref-lock";
  const eventId = "event-ref-lock";
  const ref = [
    "refs/heads/codex/goal-control/p1",
    sha256(goalId),
    sha256(taskId),
    "cycle-1",
  ].join("/");
  const paths = p1CommitPaths(
    controlRoot,
    goalId,
    taskId,
    eventId,
  );
  mkdirSync(paths.intentDirectory, {
    recursive: true,
    mode: 0o700,
  });
  writePrivate(paths.bundle, "durable carrier\n");
  const request = {
    event_id: eventId,
    goal_id: goalId,
    task_id: taskId,
    type: "P1_COMMITTED",
  };
  const intentWithoutSeal = {
    schema_version: 1,
    kind: "P1_COMMIT_REF_INTENT",
    goal_id: goalId,
    task_id: taskId,
    task_cycle: 1,
    event_id: eventId,
    request,
    request_sha256: hashObject(request),
    task_anchor: {},
    acceptance_authority: {},
    p1_binding: {},
    ref_binding: {
      repository_root: realpathSync(repository),
      common_git_dir: commonGitDir,
      expected_old_ref: ZERO_OID,
      new_commit: commit,
      commit_ref: ref,
    },
    bundle: {
      file: "commit.bundle",
      sha256: hashFile(paths.bundle),
      head: commit,
    },
    accepted_at: "2026-07-25T00:00:00.000Z",
  };
  const preparedRequestSha256 = hashObject({
    request: intentWithoutSeal.request,
    task_anchor: intentWithoutSeal.task_anchor,
    acceptance_authority: intentWithoutSeal.acceptance_authority,
    p1_binding: intentWithoutSeal.p1_binding,
    ref_binding: intentWithoutSeal.ref_binding,
    bundle: intentWithoutSeal.bundle,
    accepted_at: intentWithoutSeal.accepted_at,
  });
  const unsigned = {
    ...intentWithoutSeal,
    prepared_request_sha256: preparedRequestSha256,
  };
  const intent = {
    ...unsigned,
    intent_sha256: hashObject(unsigned),
  };
  writePrivateJson(paths.intent, intent);
  const fixture = {
    base,
    commit,
    commonGitDir,
    controlRoot,
    eventId,
    goalId,
    intent,
    paths,
    ref,
    repository,
    taskId,
  };
  activate(fixture);
  expect(readP1CommitIntent(
    controlRoot,
    goalId,
    taskId,
    eventId,
  )).not.toBeNull();
  return fixture;
}

function refFile(fixture: Fixture): string {
  return path.join(
    fixture.commonGitDir,
    ...fixture.ref.split("/"),
  );
}

function refLock(fixture: Fixture): string {
  return `${refFile(fixture)}.lock`;
}

function writeLock(
  fixture: Fixture,
  body: string | Buffer,
  mode = 0o600,
): string {
  const lock = refLock(fixture);
  mkdirSync(path.dirname(lock), { recursive: true, mode: 0o700 });
  writeFileSync(lock, body, { mode });
  chmodSync(lock, mode);
  return lock;
}

function fenceFiles(directory: string): string[] {
  return readdirSync(directory)
    .filter((entry) => entry.startsWith(".ref-lock-fence-"));
}

function fenceFile(directory: string): string {
  const names = fenceFiles(directory);
  expect(names).toHaveLength(1);
  return path.join(directory, names[0]);
}

function packedLock(fixture: Fixture): string {
  return path.join(fixture.commonGitDir, "packed-refs.lock");
}

function refLog(fixture: Fixture): string {
  return path.join(
    fixture.commonGitDir,
    "logs",
    ...fixture.ref.split("/"),
  );
}

function expectSameInode(...files: string[]): void {
  const stats = files.map((file) => lstatSync(file));
  for (const stat of stats.slice(1)) {
    expect(stat.dev).toBe(stats[0].dev);
    expect(stat.ino).toBe(stats[0].ino);
  }
}

function faultPublish(
  fixture: Fixture,
  variable: typeof P1_REF_FAULTS[number],
  code: string,
): void {
  activate(fixture);
  process.env[variable] = "throw";
  expectCode(
    () => publishP1CommitRef(fixture.repository, fixture.intent),
    code,
  );
  delete process.env[variable];
}

function installPublishFence(fixture: Fixture): void {
  faultPublish(
    fixture,
    "GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_LOCK_FENCE",
    "TEST_FAULT_AFTER_P1_REF_LOCK_FENCE",
  );
  expect(fenceFiles(fixture.paths.intentDirectory)).toHaveLength(1);
  expect(readRef(fixture.repository, fixture.ref)).toBeNull();
}

function abandonmentIntent(
  fixture: Fixture,
): Record<string, unknown> {
  const retained = readP1CommitIntent(
    fixture.controlRoot,
    fixture.goalId,
    fixture.taskId,
    fixture.eventId,
  );
  if (!retained) throw new Error("missing retained P1 intent");
  const request = {
    abandon_event_id: "event-ref-lock-abandon",
    expected_commit_ref: fixture.ref,
    expected_intent_sha256: retained.intent.intent_sha256,
    expected_ref_head: fixture.commit,
    goal_id: fixture.goalId,
    incident_ref: "test://p1-ref-lock",
    prepared_event_id: fixture.eventId,
    reason: "exercise exact ref-lock recovery",
    task_id: fixture.taskId,
  };
  const unsignedBase = {
    schema_version: 1,
    kind: "P1_COMMIT_REF_ABANDON_INTENT",
    goal_id: fixture.goalId,
    task_id: fixture.taskId,
    prepared_event_id: fixture.eventId,
    request,
    request_sha256: hashObject(request),
    task_anchor: { task_cycle: 1 },
    foreman_authority: {},
    p1_intent_sha256: retained.intent.intent_sha256,
    accepted_at: "2026-07-25T00:01:00.000Z",
  };
  const unsigned = {
    ...unsignedBase,
    prepared_request_sha256: hashObject({
      request: unsignedBase.request,
      task_anchor: unsignedBase.task_anchor,
      foreman_authority: unsignedBase.foreman_authority,
      p1_intent_sha256: unsignedBase.p1_intent_sha256,
    }),
  };
  const intent = {
    ...unsigned,
    intent_sha256: hashObject(unsigned),
  };
  mkdirSync(fixture.paths.abandonmentDirectory, {
    recursive: true,
    mode: 0o700,
  });
  writePrivateJson(fixture.paths.abandonmentIntent, intent);
  return intent;
}

afterEach(() => {
  for (const name of P1_REF_FAULTS) delete process.env[name];
});

afterAll(() => {
  for (const root of temporaryRoots) {
    rmSync(root, { recursive: true, force: true });
  }
  if (originalGoalControlDir === undefined) {
    delete process.env.GOAL_CONTROL_DIR;
  } else {
    process.env.GOAL_CONTROL_DIR = originalGoalControlDir;
  }
  if (originalGoalControlTestMode === undefined) {
    delete process.env.GOAL_CONTROL_TEST_MODE;
  } else {
    process.env.GOAL_CONTROL_TEST_MODE = originalGoalControlTestMode;
  }
  for (const name of P1_REF_FAULTS) {
    const original = originalRefFaults[name];
    if (original === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = original;
    }
  }
});

describe("P1 transaction-owned loose ref-lock recovery", () => {
  it("refuses a first-seen lock before an exact fence exists", () => {
    const fixture = makeFixture();
    const lock = writeLock(fixture, fixture.commit.slice(0, 13));

    expectCode(
      () => publishP1CommitRef(fixture.repository, fixture.intent),
      "P1_COMMIT_REF_LOCK_CONFLICT",
    );

    expect(lstatSync(lock).isFile()).toBe(true);
    expect(fenceFiles(fixture.paths.intentDirectory)).toEqual([]);
    expect(readRef(fixture.repository, fixture.ref)).toBeNull();
  });

  it("repairs a same-inode partial durable fence before taking locks", () => {
    const fixture = makeFixture();
    faultPublish(
      fixture,
      "GOAL_CONTROL_TEST_FAULT_DURING_P1_REF_LOCK_FENCE",
      "TEST_FAULT_DURING_P1_REF_LOCK_FENCE",
    );
    const fence = fenceFile(fixture.paths.intentDirectory);
    expect(readFileSync(fence).length).toBeGreaterThan(0);
    expect(readFileSync(fence).length).toBeLessThan(41);
    expect(lstatSync(fence).nlink).toBe(1);

    expect(
      publishP1CommitRef(fixture.repository, fixture.intent),
    ).toBe(fixture.ref);

    expect(existsSync(fence)).toBe(false);
    expect(readRef(fixture.repository, fixture.ref))
      .toBe(fixture.commit);
  });

  it("recovers the packed-side-fence-only crash window", () => {
    const fixture = makeFixture();
    faultPublish(
      fixture,
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_PACKED_LOCK_LINK",
      "TEST_FAULT_AFTER_P1_PACKED_LOCK_LINK",
    );
    const fence = fenceFile(fixture.paths.intentDirectory);
    expectSameInode(fence, packedLock(fixture));
    expect(lstatSync(fence).nlink).toBe(2);
    expect(existsSync(refLock(fixture))).toBe(false);

    expect(
      publishP1CommitRef(fixture.repository, fixture.intent),
    ).toBe(fixture.ref);

    expect(existsSync(fence)).toBe(false);
    expect(existsSync(packedLock(fixture))).toBe(false);
  });

  it("recovers the dual-owned-lock crash window", () => {
    const fixture = makeFixture();
    faultPublish(
      fixture,
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_LOCK_LINK",
      "TEST_FAULT_AFTER_P1_REF_LOCK_LINK",
    );
    const fence = fenceFile(fixture.paths.intentDirectory);
    expectSameInode(
      fence,
      packedLock(fixture),
      refLock(fixture),
    );
    expect(lstatSync(fence).nlink).toBe(3);

    expect(
      publishP1CommitRef(fixture.repository, fixture.intent),
    ).toBe(fixture.ref);

    expect(readRef(fixture.repository, fixture.ref))
      .toBe(fixture.commit);
    expect(existsSync(fence)).toBe(false);
  });

  it("closes a promoted canonical that is still linked to fence and packed lock", () => {
    const fixture = makeFixture();
    faultPublish(
      fixture,
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_REF_CANONICAL_MUTATION",
      "TEST_FAULT_AFTER_P1_REF_CANONICAL_MUTATION",
    );
    const fence = fenceFile(fixture.paths.intentDirectory);
    expectSameInode(
      fence,
      packedLock(fixture),
      refFile(fixture),
    );
    expect(lstatSync(fence).nlink).toBe(3);
    expect(existsSync(refLock(fixture))).toBe(false);

    expect(
      publishP1CommitRef(fixture.repository, fixture.intent),
    ).toBe(fixture.ref);

    expect(existsSync(fence)).toBe(false);
    expect(lstatSync(refFile(fixture)).nlink).toBe(1);
    expect(existsSync(refLog(fixture))).toBe(false);
  });

  it("reacquires the packed side-fence after its cleanup crash window", () => {
    const fixture = makeFixture();
    faultPublish(
      fixture,
      "GOAL_CONTROL_TEST_FAULT_AFTER_P1_PACKED_LOCK_RELEASE",
      "TEST_FAULT_AFTER_P1_PACKED_LOCK_RELEASE",
    );
    const fence = fenceFile(fixture.paths.intentDirectory);
    expectSameInode(fence, refFile(fixture));
    expect(lstatSync(fence).nlink).toBe(2);
    expect(existsSync(packedLock(fixture))).toBe(false);

    expect(
      publishP1CommitRef(fixture.repository, fixture.intent),
    ).toBe(fixture.ref);

    expect(existsSync(fence)).toBe(false);
    expect(lstatSync(refFile(fixture)).nlink).toBe(1);
  });

  it.each([
    {
      name: "foreign bytes",
      install(fixture: Fixture) {
        writeLock(fixture, `f${fixture.commit.slice(1)}\n`);
      },
    },
    {
      name: "foreign mode",
      install(fixture: Fixture) {
        writeLock(fixture, fixture.commit.slice(0, 9), 0o644);
      },
    },
    {
      name: "symlink",
      install(fixture: Fixture) {
        const lock = refLock(fixture);
        mkdirSync(path.dirname(lock), {
          recursive: true,
          mode: 0o700,
        });
        symlinkSync("/dev/null", lock);
      },
    },
    {
      name: "multiple candidates",
      install(fixture: Fixture) {
        const lock = writeLock(fixture, fixture.commit.slice(0, 9));
        writePrivate(`${lock}.foreign`, fixture.commit.slice(0, 9));
      },
    },
    {
      name: "packed-refs.lock",
      install(fixture: Fixture) {
        writePrivate(
          path.join(fixture.commonGitDir, "packed-refs.lock"),
          "",
        );
      },
    },
  ])("fails closed on $name", ({ install }) => {
    const fixture = makeFixture();
    installPublishFence(fixture);
    install(fixture);

    expectCode(
      () => publishP1CommitRef(fixture.repository, fixture.intent),
      "P1_COMMIT_REF_LOCK_CONFLICT",
    );

    expect(readRef(fixture.repository, fixture.ref)).toBeNull();
  });

  it("releases both owned locks when pre-mutation reflog validation fails", () => {
    const fixture = makeFixture();
    installPublishFence(fixture);
    writePrivate(refLog(fixture), "foreign reflog\n");

    expectCode(
      () => publishP1CommitRef(fixture.repository, fixture.intent),
      "P1_COMMIT_REF_LOCK_CONFLICT",
    );

    expect(existsSync(refLock(fixture))).toBe(false);
    expect(existsSync(packedLock(fixture))).toBe(false);
    expect(lstatSync(
      fenceFile(fixture.paths.intentDirectory),
    ).nlink).toBe(1);
    expect(readRef(fixture.repository, fixture.ref)).toBeNull();
  });

  it("releases its packed side-fence when a packed same-ref invalidates create", () => {
    const fixture = makeFixture();
    installPublishFence(fixture);
    writePrivate(
      path.join(fixture.commonGitDir, "packed-refs"),
      [
        "# pack-refs with: peeled fully-peeled sorted",
        `${fixture.commit} ${fixture.ref}`,
        "",
      ].join("\n"),
    );

    expectCode(
      () => publishP1CommitRef(fixture.repository, fixture.intent),
      "P1_COMMIT_REF_LOCK_CONFLICT",
    );

    expect(existsSync(refLock(fixture))).toBe(false);
    expect(existsSync(packedLock(fixture))).toBe(false);
    expect(lstatSync(
      fenceFile(fixture.paths.intentDirectory),
    ).nlink).toBe(1);
    expect(readRef(fixture.repository, fixture.ref))
      .toBe(fixture.commit);
  });

  it("abandons authority without deleting the prepared audit/GC ref", () => {
    const fixture = makeFixture();
    expect(
      publishP1CommitRef(fixture.repository, fixture.intent),
    ).toBe(fixture.ref);
    const abandonIntent = abandonmentIntent(fixture);
    const retained = readP1CommitIntent(
      fixture.controlRoot,
      fixture.goalId,
      fixture.taskId,
      fixture.eventId,
    );
    if (!retained) throw new Error("missing retained P1 intent");

    abandonP1CommitRef(
      fixture.repository,
      abandonIntent,
      retained,
    );

    expect(readRef(fixture.repository, fixture.ref))
      .toBe(fixture.commit);
    expect(fenceFiles(fixture.paths.abandonmentDirectory))
      .toEqual([]);
    expect(existsSync(refLock(fixture))).toBe(false);
    expect(existsSync(packedLock(fixture))).toBe(false);
    abandonP1CommitRef(
      fixture.repository,
      abandonIntent,
      retained,
    );
  });

  it("updates a packed-only ref and accepts an exact packed-final replay", () => {
    const fixture = makeFixture();
    const ref = "refs/heads/codex/goal-control/packed-replay";
    const oldCommit = fixture.commit;
    git(
      fixture.repository,
      "commit",
      "--allow-empty",
      "-qm",
      "packed-final",
    );
    const newCommit = git(fixture.repository, "rev-parse", "HEAD");
    git(
      fixture.repository,
      "update-ref",
      "--create-reflog",
      ref,
      oldCommit,
      ZERO_OID,
    );
    git(fixture.repository, "pack-refs", "--all");
    const looseRef = path.join(
      fixture.commonGitDir,
      ...ref.split("/"),
    );
    expect(existsSync(looseRef)).toBe(false);
    expect(readRef(fixture.repository, ref)).toBe(oldCommit);

    const expectedReflog = describeLooseRefReflog({
      cwd: fixture.repository,
      commonGitDir: fixture.commonGitDir,
      ref,
      label: "packed replay",
    });
    const transactionDirectory = path.join(
      fixture.base,
      "packed-replay-transaction",
    );
    mkdirSync(transactionDirectory, { mode: 0o700 });
    const fence = path.join(transactionDirectory, "ref-fence");
    const options = {
      cwd: fixture.repository,
      commonGitDir: fixture.commonGitDir,
      ref,
      expectedOld: oldCommit,
      expectedNew: newCommit,
      fenceFile: fence,
      fenceInstalledAtEntry: false,
      reflogPolicy: "preserve",
      expectedReflog,
      label: "packed replay",
    };

    expect(executeLooseRefTransaction(options)).toBe(newCommit);
    expect(readRef(fixture.repository, ref)).toBe(newCommit);
    expect(readFileSync(looseRef, "utf8"))
      .toBe(`${newCommit}\n`);
    expect(existsSync(fence)).toBe(false);
    expect(existsSync(`${looseRef}.lock`)).toBe(false);
    expect(existsSync(packedLock(fixture))).toBe(false);

    git(fixture.repository, "pack-refs", "--all");
    expect(existsSync(looseRef)).toBe(false);
    expect(readRef(fixture.repository, ref)).toBe(newCommit);

    expect(executeLooseRefTransaction(options)).toBe(newCommit);
    expect(readRef(fixture.repository, ref)).toBe(newCommit);
    expect(existsSync(looseRef)).toBe(false);
    expect(existsSync(fence)).toBe(false);
    expect(existsSync(`${looseRef}.lock`)).toBe(false);
    expect(existsSync(packedLock(fixture))).toBe(false);
  });

  it("preserves a replacement fence and fails closed before cleanup", () => {
    const fixture = makeFixture();
    const ref = "refs/heads/codex/goal-control/fence-replacement";
    const transactionDirectory = path.join(
      fixture.base,
      "fence-replacement-transaction",
    );
    mkdirSync(transactionDirectory, { mode: 0o700 });
    const fence = path.join(transactionDirectory, "ref-fence");
    let replacementInode: bigint | null = null;

    expectCode(
      () => executeLooseRefTransaction({
        cwd: fixture.repository,
        commonGitDir: fixture.commonGitDir,
        ref,
        expectedOld: ZERO_OID,
        expectedNew: fixture.commit,
        fenceFile: fence,
        fenceInstalledAtEntry: false,
        reflogPolicy: "absent",
        label: "fence replacement",
        onStage(stage: string) {
          if (stage !== "packed-lock-released") return;
          unlinkSync(fence);
          writePrivate(fence, `${fixture.commit}\n`);
          replacementInode = lstatSync(fence, { bigint: true }).ino;
        },
      }),
      "GIT_LOOSE_REF_FENCE_CONFLICT",
    );

    expect(existsSync(fence)).toBe(true);
    expect(lstatSync(fence, { bigint: true }).ino).toBe(replacementInode);
    expect(readFileSync(fence, "utf8")).toBe(`${fixture.commit}\n`);
    expect(readRef(fixture.repository, ref)).toBe(fixture.commit);
  });
});
