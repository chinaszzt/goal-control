import { execFileSync, spawnSync } from "child_process";
import { createHash } from "crypto";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const GOAL = "captain-bootstrap";
const TASK = "TASK-CAPTAIN";
const THREAD = "captain-bootstrap-thread-1";
const HOST = "local";
const OPERATION = "captain-bootstrap-operation-1";
const CHALLENGE = "ca".repeat(32);
const CAPTAIN_PROTOCOL = "goalctl-captain-canary-bootstrap-v1";
const CAPTAIN_MARKER =
  `Captain-Canary-Bootstrap-Protocol: ${CAPTAIN_PROTOCOL}`;
const WORKER_PROTOCOL = "goalctl-worker-canary-bootstrap-v1";

type Json = Record<string, any>;
type Result = { status: number | null; stdout: string; stderr: string };
type Fixture = {
  base: string;
  repository: string;
  remote: string;
  captain: string;
  manifest: string;
  policy: string;
  policySha256: string;
  packetV2: string;
  packetV2Sha256: string;
  baseHead: string;
  head: string;
  requiredHead: string;
  controlDir: string;
  initialized?: Json;
  foreman?: Json;
  foremanThread?: string;
};

const fixtures: Fixture[] = [];
const nodeRequire = createRequire(import.meta.url);
const {
  captainRequiredStartHeadFromGoal,
} = nodeRequire("../scripts/goal-control/canary-bootstrap.js") as {
  captainRequiredStartHeadFromGoal: (
    loaded: Json,
    task: Json,
    derive: (loaded: Json, task: Json) => string,
  ) => Json;
};
const {
  completeMechanicalP1EventPayload,
  loadGoalStateReadOnly,
  mechanicalP1RequiredStartHead,
  validateP1Boundary,
} = nodeRequire("../scripts/goal-control/goal.js") as {
  completeMechanicalP1EventPayload: (
    cwd: string,
    loaded: Json,
    state: Json,
    task: Json,
    eventType: string,
    payload: Json,
  ) => Json;
  loadGoalStateReadOnly: (
    cwd: string,
    goalId: string,
    consume: (loaded: Json) => Json,
  ) => Json;
  mechanicalP1RequiredStartHead: (
    loaded: Json,
    task: Json,
  ) => string;
  validateP1Boundary: (
    cwd: string,
    loaded: Json,
    state: Json,
    event: Json,
  ) => void;
};

function sha256(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0",
      LC_ALL: "C",
    },
  }).trim();
}

function write(repository: string, relative: string, body: string): void {
  const file = path.join(repository, relative);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, body);
}

function run(
  cwd: string,
  args: string[],
  controlDir?: string,
  extraEnv: Record<string, string> = {},
): Result {
  const effectiveControlDir = controlDir || fixtures.find(
    (fixture) =>
      cwd === fixture.repository || cwd === fixture.captain,
  )?.controlDir;
  const result = spawnSync(process.execPath, [GOALCTL, ...args, "--json"], {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0",
      LC_ALL: "C",
      ...(effectiveControlDir
        ? {
          GOAL_CONTROL_DIR: effectiveControlDir,
          GOAL_CONTROL_TEST_MODE: "1",
        }
        : {}),
      ...extraEnv,
    },
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function success(cwd: string, args: string[], controlDir?: string): Json {
  const result = run(cwd, args, controlDir);
  expect({ status: result.status, stderr: result.stderr }).toEqual({
    status: 0,
    stderr: "",
  });
  return JSON.parse(result.stdout) as Json;
}

function blocked(result: Result, pattern: RegExp): void {
  expect(result.status).toBe(2);
  expect(result.stdout).toBe("");
  expect(result.stderr).toMatch(pattern);
}

function makeFixture(options: {
  captainOptIn?: boolean;
  captainPolicyLines?: string[];
  workerOptIn?: boolean;
  p1?: boolean;
  initialize?: boolean;
} = {}): Fixture {
  const base = mkdtempSync(path.join(tmpdir(), "captain-bootstrap-"));
  const repository = path.join(base, "repository");
  const captain = path.join(base, "captain");
  const remote = path.join(base, "origin.git");
  const controlDir = path.join(base, "control");
  mkdirSync(repository);
  mkdirSync(controlDir, { mode: 0o700 });
  git(base, "init", "--bare", "-q", remote);
  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.name", "Captain Bootstrap Test");
  git(repository, "config", "user.email", "captain@example.invalid");
  write(repository, "README.md", "# fixture\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "base");
  const baseHead = git(repository, "rev-parse", "HEAD");

  const protocol = {
    entry: "docs/planning/session-role-protocol.md",
    shared: "docs/planning/session-protocol/shared.md",
    foreman: "docs/planning/session-protocol/foreman.md",
    captain: "docs/planning/session-protocol/captain.md",
    role_kernel: "docs/planning/session-protocol/role-kernel.md",
  };
  for (const [name, file] of Object.entries(protocol)) {
    write(repository, file, `# ${name}\n`);
  }
  const policy = "docs/planning/goals/captain-bootstrap.policy.md";
  const markers = [
    ...(options.captainOptIn === false
      ? []
      : (options.captainPolicyLines || [CAPTAIN_MARKER])),
    ...(options.workerOptIn
      ? [`Worker-Canary-Bootstrap-Protocol: ${WORKER_PROTOCOL}`]
      : []),
  ];
  const policyBody = ["# bootstrap policy", "", ...markers, ""].join("\n");
  write(repository, policy, policyBody);
  const authority = "docs/planning/goals/captain-bootstrap.authority.md";
  const authorityBody = "# authority\n";
  write(repository, authority, authorityBody);
  const packet = "docs/planning/goals/captain-bootstrap/packet.md";
  const packetBody = "# task\n";
  write(repository, packet, packetBody);
  const packetV2 =
    "docs/planning/goals/captain-bootstrap/packet-v2.md";
  const packetV2Body = "# task revision 2\n";
  write(repository, packetV2, packetV2Body);
  const manifest = "docs/planning/goals/captain-bootstrap/manifest.json";
  const bootstrapConfigs = {
    ...(options.captainOptIn === false
      ? {}
      : {
        captain_canary_bootstrap: {
          protocol: CAPTAIN_PROTOCOL,
          policy: { path: policy, sha256: sha256(policyBody) },
        },
      }),
    ...(options.workerOptIn
      ? {
        worker_canary_bootstrap: {
          protocol: WORKER_PROTOCOL,
          policy: { path: policy, sha256: sha256(policyBody) },
        },
      }
      : {}),
  };
  write(repository, manifest, `${JSON.stringify({
    schema_version: 1,
    goal_id: GOAL,
    mode: "shadow",
    repository: {
      name_with_owner: "example/captain-bootstrap",
      base_branch: "main",
    },
    base_head: baseHead,
    protocol,
    ...bootstrapConfigs,
    tasks: [{
      id: TASK,
      issue: 5,
      dependencies: [],
      integration_order: 1,
      risk_class: "STANDARD",
      packet: {
        revision: 1,
        path: packet,
        sha256: sha256(packetBody),
      },
      ...(options.p1 === false
        ? {}
        : {
          p1: {
            producer: "CAPTAIN",
            artifact_root: "docs/issues/5",
            authority: {
              kind: "SCOPED_DELEGATION",
              path: authority,
              sha256: sha256(authorityBody),
            },
            dependency_gate: "ARCHIVED",
          },
        }),
      expected_write_set: [],
      conflict_domains: [],
      resource_requirements: [],
    }],
  }, null, 2)}\n`);
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "goal inputs");
  git(repository, "remote", "add", "origin", remote);
  git(repository, "push", "-q", "-u", "origin", "main");
  const head = git(repository, "rev-parse", "HEAD");
  git(repository, "worktree", "add", "--detach", "-q", captain, head);
  const fixture = {
    base,
    repository: realpathSync(repository),
    remote: realpathSync(remote),
    captain: realpathSync(captain),
    manifest,
    policy,
    policySha256: sha256(policyBody),
    packetV2,
    packetV2Sha256: sha256(packetV2Body),
    baseHead,
    head,
    requiredHead: options.p1 === false ? baseHead : head,
    controlDir: realpathSync(controlDir),
  };
  fixtures.push(fixture);
  if (options.initialize !== false) {
    fixture.foremanThread = `foreman-${fixtures.length}`;
    fixture.initialized = success(fixture.repository, [
      "init",
      "--manifest", fixture.manifest,
    ], fixture.controlDir);
    fixture.foreman = success(fixture.repository, [
      "register-role",
      "--goal", GOAL,
      "--task", TASK,
      "--role", "FOREMAN",
      "--thread", fixture.foremanThread,
      "--host", HOST,
      "--event-id", `register-foreman-${fixtures.length}`,
      "--bootstrap-capability-file",
      fixture.initialized.bootstrap_capability_file,
    ], fixture.controlDir);
  }
  return fixture;
}

function identityArgs(fixture: Fixture): string[] {
  return [
    "--manifest", fixture.manifest,
    "--role", "CAPTAIN",
    "--task", TASK,
    "--expected-head", fixture.requiredHead,
    "--operation-id", OPERATION,
    "--challenge", CHALLENGE,
    "--canary-policy", fixture.policy,
    "--canary-policy-sha256", fixture.policySha256,
  ];
}

function bootstrap(fixture: Fixture): {
  plan: Json;
  planSha256: string;
  observation: Json;
  observationSha256: string;
  prepared: Json;
} {
  const planned = success(fixture.repository, [
    "canary-bootstrap-plan",
    "--repository-worktree", fixture.repository,
    ...identityArgs(fixture),
  ]);
  const plan = planned.identity_plan as Json;
  const planSha256 = planned.identity_plan_sha256 as string;
  const inspected = success(fixture.captain, [
    "canary-bootstrap-inspect",
    "--goal-worktree", fixture.repository,
    ...identityArgs(fixture),
    "--expected-identity-plan-sha256", planSha256,
    "--worker-thread", THREAD,
    "--worker-host", HOST,
  ]);
  const observation = inspected.identity_observation as Json;
  const observationSha256 =
    inspected.identity_observation_sha256 as string;
  const prepared = success(fixture.repository, [
    "canary-bootstrap-prepare",
    "--repository-worktree", fixture.repository,
    ...identityArgs(fixture),
    "--expected-identity-plan-sha256", planSha256,
    "--expected-observation-sha256", observationSha256,
    "--worker-thread", THREAD,
    "--worker-host", HOST,
    "--worker-worktree", fixture.captain,
  ]);
  return {
    plan,
    planSha256,
    observation,
    observationSha256,
    prepared,
  };
}

function refs(cwd: string, prefix: string): string {
  return git(
    cwd,
    "for-each-ref",
    "--format=%(refname)%00%(objectname)",
    prefix,
  );
}

function zeroWriteSnapshot(fixture: Fixture): Json {
  const gitDir = realpathSync(git(
    fixture.captain,
    "rev-parse",
    "--absolute-git-dir",
  ));
  const common = realpathSync(path.resolve(
    fixture.repository,
    git(fixture.repository, "rev-parse", "--git-common-dir"),
  ));
  return {
    head: git(fixture.captain, "rev-parse", "HEAD"),
    branch: git(fixture.captain, "branch", "--show-current"),
    tree: git(fixture.captain, "rev-parse", "HEAD^{tree}"),
    index: sha256(readFileSync(path.join(gitDir, "index"))),
    status: git(fixture.captain, "status", "--porcelain=v2"),
    refs: refs(fixture.repository, "refs/heads"),
    remoteRefs: refs(fixture.repository, "refs/remotes"),
    originRefs: refs(fixture.remote, "refs"),
    storeEntries: readdirSync(fixture.controlDir).sort(),
    receiptRootExists: existsSync(path.join(
      common,
      "goal-control",
      "captain-canary-bootstrap-v1",
    )),
  };
}

function captainArtifactPaths(fixture: Fixture): {
  controlDir: string;
  root: string;
  operation: string;
  intent: string;
  receipt: string;
} {
  const common = realpathSync(path.resolve(
    fixture.repository,
    git(fixture.repository, "rev-parse", "--git-common-dir"),
  ));
  const controlDir = fixture.controlDir;
  const root = path.join(
    common,
    "goal-control",
    "captain-canary-bootstrap-v1",
  );
  const operation = path.join(
    root,
    "goals",
    GOAL,
    "tasks",
    TASK,
    sha256(OPERATION).slice("sha256:".length),
  );
  return {
    controlDir,
    root,
    operation,
    intent: path.join(operation, "intent.json"),
    receipt: path.join(operation, "receipt.json"),
  };
}

function planAndObserve(fixture: Fixture): {
  planSha256: string;
  observationSha256: string;
  branch: string;
} {
  const planned = success(fixture.repository, [
    "canary-bootstrap-plan",
    "--repository-worktree", fixture.repository,
    ...identityArgs(fixture),
  ]);
  const observed = success(fixture.captain, [
    "canary-bootstrap-inspect",
    "--goal-worktree", fixture.repository,
    ...identityArgs(fixture),
    "--expected-identity-plan-sha256",
    planned.identity_plan_sha256,
    "--worker-thread", THREAD,
    "--worker-host", HOST,
  ]);
  return {
    planSha256: planned.identity_plan_sha256 as string,
    observationSha256:
      observed.identity_observation_sha256 as string,
    branch: planned.identity_plan.worker_branch as string,
  };
}

function prepareArgs(
  fixture: Fixture,
  planned: {
    planSha256: string;
    observationSha256: string;
  },
  overrides: {
    thread?: string;
    host?: string;
    worktree?: string;
    observationSha256?: string;
  } = {},
): string[] {
  return [
    "canary-bootstrap-prepare",
    "--repository-worktree", fixture.repository,
    ...identityArgs(fixture),
    "--expected-identity-plan-sha256", planned.planSha256,
    "--expected-observation-sha256",
    overrides.observationSha256 || planned.observationSha256,
    "--worker-thread", overrides.thread || THREAD,
    "--worker-host", overrides.host || HOST,
    "--worker-worktree", overrides.worktree || fixture.captain,
  ];
}

function blockedPrepareWithoutWrite(
  fixture: Fixture,
  args: string[],
  pattern: RegExp,
  additionalFixtures: Fixture[] = [],
): void {
  const observedFixtures = [fixture, ...additionalFixtures];
  const before = observedFixtures.map(zeroWriteSnapshot);
  blocked(run(fixture.repository, args), pattern);
  expect(observedFixtures.map(zeroWriteSnapshot)).toEqual(before);
}

function loadFixtureGoal(fixture: Fixture): Json {
  const previousControlDir = process.env.GOAL_CONTROL_DIR;
  const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
  process.env.GOAL_CONTROL_DIR = fixture.controlDir;
  process.env.GOAL_CONTROL_TEST_MODE = "1";
  try {
    return loadGoalStateReadOnly(
      fixture.repository,
      GOAL,
      (loaded) => loaded,
    );
  } finally {
    if (previousControlDir === undefined) {
      delete process.env.GOAL_CONTROL_DIR;
    } else {
      process.env.GOAL_CONTROL_DIR = previousControlDir;
    }
    if (previousTestMode === undefined) {
      delete process.env.GOAL_CONTROL_TEST_MODE;
    } else {
      process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
    }
  }
}

afterEach(() => {
  while (fixtures.length > 0) {
    rmSync(fixtures.pop()!.base, { recursive: true, force: true });
  }
});

describe("CAPTAIN detached-worktree bootstrap", () => {
  test("worker-v1 opt-in remains unable to authorize CAPTAIN", () => {
    const fixture = makeFixture({
      captainOptIn: false,
      workerOptIn: true,
    });
    const before = {
      head: git(fixture.captain, "rev-parse", "HEAD"),
      branch: git(fixture.captain, "branch", "--show-current"),
      refs: refs(fixture.repository, "refs/heads"),
    };

    blocked(run(fixture.repository, [
      "canary-bootstrap-plan",
      "--repository-worktree", fixture.repository,
      ...identityArgs(fixture),
    ]), /CAPTAIN_CANARY_BOOTSTRAP_PROTOCOL_UNSUPPORTED|captain|未启用/i);

    expect({
      head: git(fixture.captain, "rev-parse", "HEAD"),
      branch: git(fixture.captain, "branch", "--show-current"),
      refs: refs(fixture.repository, "refs/heads"),
    }).toEqual(before);
  });

  test("wrong-but-valid CAPTAIN HEAD is rejected before refs, HEAD, store, or receipt change", () => {
    const fixture = makeFixture();
    const wrongHead = execFileSync(
      "git",
      ["commit-tree", `${fixture.head}^{tree}`, "-p", fixture.head],
      {
        cwd: fixture.repository,
        encoding: "utf8",
        input: "wrong-but-valid bootstrap head\n",
      },
    ).trim();
    const before = zeroWriteSnapshot(fixture);

    blocked(run(fixture.repository, [
      "canary-bootstrap-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", "CAPTAIN",
      "--task", TASK,
      "--expected-head", wrongHead,
      "--operation-id", OPERATION,
      "--challenge", CHALLENGE,
      "--canary-policy", fixture.policy,
      "--canary-policy-sha256", fixture.policySha256,
    ]), /CAPTAIN_BOOTSTRAP_REQUIRED_HEAD_MISMATCH|required start HEAD/i);

    expect(zeroWriteSnapshot(fixture)).toEqual(before);
  });

  test("frozen repository HEAD cannot substitute for a no-P1 Goal-state required HEAD", () => {
    const fixture = makeFixture({ p1: false });
    const before = zeroWriteSnapshot(fixture);

    blocked(run(fixture.repository, [
      "canary-bootstrap-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", "CAPTAIN",
      "--task", TASK,
      "--expected-head", fixture.head,
      "--operation-id", OPERATION,
      "--challenge", CHALLENGE,
      "--canary-policy", fixture.policy,
      "--canary-policy-sha256", fixture.policySha256,
    ]), /CAPTAIN_BOOTSTRAP_REQUIRED_HEAD_MISMATCH|Goal-state required start HEAD/i);

    expect(zeroWriteSnapshot(fixture)).toEqual(before);
  });

  test("later P1 required HEAD proof selects the highest dependency main merge", () => {
    const dependencyHead = "d".repeat(40);
    const dependency = {
      id: "TASK-DEPENDENCY",
      integration_order: 1,
      dependencies: [],
    };
    const target = {
      id: TASK,
      integration_order: 2,
      dependencies: [dependency.id],
      p1: {
        producer: "CAPTAIN",
      },
    };
    const loaded = {
      manifest: {
        goal_id: GOAL,
        tasks: [dependency, target],
      },
      meta: {
        goal_input_head: "a".repeat(40),
      },
      control: {
        epoch: 7,
      },
      snapshot: {
        tasks: {
          [dependency.id]: {
            merge: {
              main_merge_sha: dependencyHead,
            },
          },
          [TASK]: {
            state_revision: 9,
            task_cycle: 2,
            full_head: "b".repeat(40),
          },
        },
      },
    };

    expect(captainRequiredStartHeadFromGoal(
      loaded,
      target,
      mechanicalP1RequiredStartHead,
    )).toMatchObject({
      control_epoch: 7,
      state_revision: 9,
      task_cycle: 2,
      required_start_head: dependencyHead,
      source: {
        kind: "DEPENDENCY_MAIN_MERGE",
        dependency_task_id: dependency.id,
        dependency_main_merge_sha: dependencyHead,
      },
    });
  });

  test.each<[string, string[]]>([
    ["duplicate exact", [CAPTAIN_MARKER, CAPTAIN_MARKER]],
    [
      "exact plus variant",
      [
        CAPTAIN_MARKER,
        "Captain-Canary-Bootstrap-Protocol: goalctl-captain-canary-bootstrap-v2",
      ],
    ],
  ])("%s CAPTAIN policy markers reject before every bootstrap write", (
    _name,
    captainPolicyLines,
  ) => {
    const fixture = makeFixture({
      captainPolicyLines,
      initialize: false,
    });
    const before = zeroWriteSnapshot(fixture);

    blocked(run(fixture.repository, [
      "canary-bootstrap-plan",
      "--repository-worktree", fixture.repository,
      ...identityArgs(fixture),
    ]), /CAPTAIN_CANARY_BOOTSTRAP_POLICY_UNSUPPORTED|exact opt-in marker/i);

    expect(zeroWriteSnapshot(fixture)).toEqual(before);
  });

  test("CAPTAIN prepare rejects every adversarial identity before artifact publication", () => {
    const stale = makeFixture();
    const stalePlan = planAndObserve(stale);
    blockedPrepareWithoutWrite(
      stale,
      prepareArgs(stale, stalePlan, {
        observationSha256: `sha256:${"0".repeat(64)}`,
      }),
      /OBSERVATION_MISMATCH|observation/i,
    );

    const crossThread = makeFixture();
    const crossThreadPlan = planAndObserve(crossThread);
    blockedPrepareWithoutWrite(
      crossThread,
      prepareArgs(crossThread, crossThreadPlan, {
        thread: "cross-thread",
      }),
      /OBSERVATION_MISMATCH|thread|identity/i,
    );

    const crossHost = makeFixture();
    const crossHostPlan = planAndObserve(crossHost);
    blockedPrepareWithoutWrite(
      crossHost,
      prepareArgs(crossHost, crossHostPlan, {
        host: "cross-host",
      }),
      /OBSERVATION_MISMATCH|host|identity/i,
    );

    const crossCwd = makeFixture();
    const crossCwdPlan = planAndObserve(crossCwd);
    const foreign = makeFixture();
    blockedPrepareWithoutWrite(
      crossCwd,
      prepareArgs(crossCwd, crossCwdPlan, {
        worktree: foreign.captain,
      }),
      /WORKTREE|repository|common|identity|不属于/i,
      [foreign],
    );

    const dirty = makeFixture();
    const dirtyPlan = planAndObserve(dirty);
    writeFileSync(path.join(dirty.captain, "dirty.txt"), "dirty\n");
    blockedPrepareWithoutWrite(
      dirty,
      prepareArgs(dirty, dirtyPlan),
      /DIRTY|dirty|clean|工作树/i,
    );

    const raced = makeFixture();
    const racedPlan = planAndObserve(raced);
    const racedHead = execFileSync(
      "git",
      ["commit-tree", `${raced.head}^{tree}`, "-p", raced.head],
      {
        cwd: raced.repository,
        encoding: "utf8",
        input: "prepare HEAD race\n",
      },
    ).trim();
    git(raced.captain, "checkout", "--detach", "-q", racedHead);
    blockedPrepareWithoutWrite(
      raced,
      prepareArgs(raced, racedPlan),
      /HEAD|WORKTREE_DRIFT|observation|identity/i,
    );

    const manual = makeFixture();
    const manualPlan = planAndObserve(manual);
    git(manual.captain, "switch", "-c", manualPlan.branch);
    const manualObservation = success(manual.captain, [
      "canary-bootstrap-inspect",
      "--goal-worktree", manual.repository,
      ...identityArgs(manual),
      "--expected-identity-plan-sha256", manualPlan.planSha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
    ]);
    blockedPrepareWithoutWrite(
      manual,
      prepareArgs(manual, {
        ...manualPlan,
        observationSha256:
          manualObservation.identity_observation_sha256 as string,
      }),
      /BRANCH_CONFLICT|detached|absent|首次|人工/i,
    );

    const occupied = makeFixture();
    const occupiedPlan = planAndObserve(occupied);
    const occupiedWorktree = path.join(occupied.base, "occupied");
    git(
      occupied.repository,
      "worktree",
      "add",
      "-q",
      "-b",
      occupiedPlan.branch,
      occupiedWorktree,
      occupied.head,
    );
    blockedPrepareWithoutWrite(
      occupied,
      prepareArgs(occupied, occupiedPlan),
      /BRANCH_CONFLICT|occupied|worktree|占用/i,
    );
  });

  test("CAPTAIN prepare rejects wrong HEAD and policy marker variants before artifact publication", () => {
    const wrongHead = makeFixture();
    const otherCommit = execFileSync(
      "git",
      ["commit-tree", `${wrongHead.head}^{tree}`, "-p", wrongHead.head],
      {
        cwd: wrongHead.repository,
        encoding: "utf8",
        input: "wrong prepare head\n",
      },
    ).trim();
    blockedPrepareWithoutWrite(wrongHead, [
      "canary-bootstrap-prepare",
      "--repository-worktree", wrongHead.repository,
      "--manifest", wrongHead.manifest,
      "--role", "CAPTAIN",
      "--task", TASK,
      "--expected-head", otherCommit,
      "--operation-id", OPERATION,
      "--challenge", CHALLENGE,
      "--canary-policy", wrongHead.policy,
      "--canary-policy-sha256", wrongHead.policySha256,
      "--expected-identity-plan-sha256", `sha256:${"0".repeat(64)}`,
      "--expected-observation-sha256", `sha256:${"0".repeat(64)}`,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
      "--worker-worktree", wrongHead.captain,
    ], /CAPTAIN_BOOTSTRAP_REQUIRED_HEAD_MISMATCH|required start HEAD/i);

    for (const captainPolicyLines of [
      [CAPTAIN_MARKER, CAPTAIN_MARKER],
      [
        CAPTAIN_MARKER,
        "Captain-Canary-Bootstrap-Protocol: goalctl-captain-canary-bootstrap-v2",
      ],
    ]) {
      const invalidPolicy = makeFixture({
        captainPolicyLines,
        initialize: false,
      });
      blockedPrepareWithoutWrite(invalidPolicy, [
        "canary-bootstrap-prepare",
        "--repository-worktree", invalidPolicy.repository,
        ...identityArgs(invalidPolicy),
        "--expected-identity-plan-sha256", `sha256:${"0".repeat(64)}`,
        "--expected-observation-sha256", `sha256:${"0".repeat(64)}`,
        "--worker-thread", THREAD,
        "--worker-host", HOST,
        "--worker-worktree", invalidPolicy.captain,
      ], /CAPTAIN_CANARY_BOOTSTRAP_POLICY_UNSUPPORTED|exact opt-in marker/i);
    }
  });

  test.each([
    [
      "intent-only",
      "GOAL_CONTROL_TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_INTENT",
    ],
    [
      "branch-ref-created",
      "GOAL_CONTROL_TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_REF",
    ],
    [
      "head-attached",
      "GOAL_CONTROL_TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_HEAD",
    ],
    [
      "receipt-published",
      "GOAL_CONTROL_TEST_FAULT_AFTER_CAPTAIN_BOOTSTRAP_RECEIPT",
    ],
  ] as const)(
    "CAPTAIN exact retry recovers the %s crash checkpoint",
    (checkpoint, faultName) => {
      const fixture = makeFixture();
      const planned = planAndObserve(fixture);
      const paths = captainArtifactPaths(fixture);
      mkdirSync(paths.controlDir, { recursive: true, mode: 0o700 });
      const interrupted = run(
        fixture.repository,
        prepareArgs(fixture, planned),
        paths.controlDir,
        { [faultName]: "exit" },
      );
      expect(interrupted.status).toBe(86);
      expect(existsSync(paths.intent)).toBe(true);
      expect(existsSync(paths.receipt))
        .toBe(checkpoint === "receipt-published");
      const branchRef =
        `refs/heads/${planned.branch}`;
      if (checkpoint === "intent-only") {
        expect(git(
          fixture.repository,
          "for-each-ref",
          "--format=%(objectname)",
          branchRef,
        )).toBe("");
      } else {
        expect(git(fixture.repository, "rev-parse", branchRef))
          .toBe(fixture.head);
      }
      expect(git(fixture.captain, "branch", "--show-current"))
        .toBe(
          ["head-attached", "receipt-published"].includes(checkpoint)
            ? planned.branch
            : "",
        );

      const recovered = success(
        fixture.repository,
        prepareArgs(fixture, planned),
        paths.controlDir,
      );
      expect(recovered).toMatchObject({
        captain_bootstrap_receipt_file: paths.receipt,
        captain_bootstrap_receipt_sha256:
          expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        idempotent: checkpoint === "receipt-published",
      });
      expect(git(fixture.captain, "branch", "--show-current"))
        .toBe(planned.branch);

      const replay = success(
        fixture.repository,
        prepareArgs(fixture, planned),
        paths.controlDir,
      );
      expect(replay).toMatchObject({
        captain_bootstrap_receipt_file: paths.receipt,
        captain_bootstrap_receipt_sha256:
          recovered.captain_bootstrap_receipt_sha256,
        idempotent: true,
      });
    },
  );

  test("attaches, seals, exact-retries, and preserves all non-HEAD effects", () => {
    const fixture = makeFixture();
    const common = realpathSync(path.resolve(
      fixture.repository,
      git(fixture.repository, "rev-parse", "--git-common-dir"),
    ));
    const before = {
      tree: git(fixture.captain, "rev-parse", "HEAD^{tree}"),
      index: sha256(readFileSync(path.join(
        realpathSync(git(
          fixture.captain,
          "rev-parse",
          "--absolute-git-dir",
        )),
        "index",
      ))),
      status: git(fixture.captain, "status", "--porcelain=v2"),
      main: git(fixture.repository, "rev-parse", "refs/heads/main"),
      remoteRefs: refs(fixture.repository, "refs/remotes"),
      originRefs: refs(fixture.remote, "refs"),
    };
    const result = bootstrap(fixture);
    const receiptFile =
      result.prepared.captain_bootstrap_receipt_file as string;
    const receiptSha =
      result.prepared.captain_bootstrap_receipt_sha256 as string;
    const branch = result.plan.worker_branch as string;
    expect(result.plan).toMatchObject({
      kind: "CAPTAIN_CANARY_IDENTITY_PLAN",
      role: "CAPTAIN",
      expected_head: fixture.head,
      required_start_head_proof: {
        required_start_head: fixture.head,
        source: {
          kind: "GOAL_INPUT_HEAD",
          goal_input_head: fixture.head,
        },
      },
    });
    expect(receiptFile).toContain(
      `${path.sep}captain-canary-bootstrap-v1${path.sep}`,
    );
    expect(statSync(receiptFile).mode & 0o777).toBe(0o600);
    expect(sha256(readFileSync(receiptFile))).toBe(receiptSha);
    expect(JSON.parse(readFileSync(receiptFile, "utf8"))).toMatchObject({
      kind: "CAPTAIN_CANARY_PREPARE_RECEIPT",
      role: "CAPTAIN",
      thread: THREAD,
      host: HOST,
      worker: {
        cwd: fixture.captain,
        common_git_dir: common,
        head: fixture.head,
        branch,
      },
    });
    expect(git(fixture.captain, "symbolic-ref", "--short", "HEAD"))
      .toBe(branch);
    expect({
      tree: git(fixture.captain, "rev-parse", "HEAD^{tree}"),
      index: sha256(readFileSync(path.join(
        realpathSync(git(
          fixture.captain,
          "rev-parse",
          "--absolute-git-dir",
        )),
        "index",
      ))),
      status: git(fixture.captain, "status", "--porcelain=v2"),
      main: git(fixture.repository, "rev-parse", "refs/heads/main"),
      remoteRefs: refs(fixture.repository, "refs/remotes"),
      originRefs: refs(fixture.remote, "refs"),
    }).toEqual(before);

    const retry = success(fixture.repository, [
      "canary-bootstrap-prepare",
      "--repository-worktree", fixture.repository,
      ...identityArgs(fixture),
      "--expected-identity-plan-sha256", result.planSha256,
      "--expected-observation-sha256", result.observationSha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
      "--worker-worktree", fixture.captain,
    ]);
    expect(retry).toMatchObject({
      captain_bootstrap_receipt_file: receiptFile,
      captain_bootstrap_receipt_sha256: receiptSha,
      idempotent: true,
    });

    const canary = success(fixture.captain, [
      "canary-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", "CAPTAIN",
      "--task", TASK,
      "--captain-bootstrap-receipt", receiptFile,
      "--captain-bootstrap-receipt-sha256", receiptSha,
      "--captain-bootstrap-operation-id", OPERATION,
      "--captain-bootstrap-challenge", CHALLENGE,
      "--captain-bootstrap-identity-plan-sha256", result.planSha256,
      "--captain-thread", THREAD,
      "--captain-host", HOST,
    ]);
    expect(canary.canary_plan).toMatchObject({
      role: "CAPTAIN",
      captain_bootstrap: {
        receipt_file: receiptFile,
        receipt_sha256: receiptSha,
        thread: THREAD,
        host: HOST,
        worktree: fixture.captain,
        branch,
        head: fixture.head,
      },
    });

    blocked(run(fixture.captain, [
      "canary-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", "CAPTAIN",
      "--task", TASK,
      "--captain-bootstrap-receipt", receiptFile,
      "--captain-bootstrap-receipt-sha256", `sha256:${"0".repeat(64)}`,
      "--captain-bootstrap-operation-id", OPERATION,
      "--captain-bootstrap-challenge", CHALLENGE,
      "--captain-bootstrap-identity-plan-sha256", result.planSha256,
      "--captain-thread", THREAD,
      "--captain-host", HOST,
    ]), /BINDING_MISMATCH|SHA-256|receipt/i);
  });

  test("dirty, manual pre-attach, cross identity, wrong HEAD, and HEAD race reject before bootstrap write", () => {
    const dirty = makeFixture();
    writeFileSync(path.join(dirty.captain, "dirty.txt"), "dirty\n");
    const dirtyPlan = success(dirty.repository, [
      "canary-bootstrap-plan",
      "--repository-worktree", dirty.repository,
      ...identityArgs(dirty),
    ]);
    blocked(run(dirty.captain, [
      "canary-bootstrap-inspect",
      "--goal-worktree", dirty.repository,
      ...identityArgs(dirty),
      "--expected-identity-plan-sha256",
      dirtyPlan.identity_plan_sha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
    ]), /DIRTY|dirty|clean|工作树/i);

    const manual = makeFixture();
    const manualPlan = success(manual.repository, [
      "canary-bootstrap-plan",
      "--repository-worktree", manual.repository,
      ...identityArgs(manual),
    ]);
    const manualBranch = manualPlan.identity_plan.worker_branch as string;
    git(manual.captain, "switch", "-c", manualBranch);
    const manualObservation = success(manual.captain, [
      "canary-bootstrap-inspect",
      "--goal-worktree", manual.repository,
      ...identityArgs(manual),
      "--expected-identity-plan-sha256",
      manualPlan.identity_plan_sha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
    ]);
    blocked(run(manual.repository, [
      "canary-bootstrap-prepare",
      "--repository-worktree", manual.repository,
      ...identityArgs(manual),
      "--expected-identity-plan-sha256",
      manualPlan.identity_plan_sha256,
      "--expected-observation-sha256",
      manualObservation.identity_observation_sha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
      "--worker-worktree", manual.captain,
    ]), /BRANCH_CONFLICT|detached|absent|首次|人工/i);

    const crossed = makeFixture();
    const crossedPlan = success(crossed.repository, [
      "canary-bootstrap-plan",
      "--repository-worktree", crossed.repository,
      ...identityArgs(crossed),
    ]);
    const crossedObservation = success(crossed.captain, [
      "canary-bootstrap-inspect",
      "--goal-worktree", crossed.repository,
      ...identityArgs(crossed),
      "--expected-identity-plan-sha256",
      crossedPlan.identity_plan_sha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
    ]);
    blocked(run(crossed.repository, [
      "canary-bootstrap-prepare",
      "--repository-worktree", crossed.repository,
      ...identityArgs(crossed),
      "--expected-identity-plan-sha256",
      crossedPlan.identity_plan_sha256,
      "--expected-observation-sha256",
      crossedObservation.identity_observation_sha256,
      "--worker-thread", "cross-thread",
      "--worker-host", HOST,
      "--worker-worktree", crossed.captain,
    ]), /OBSERVATION_MISMATCH|identity|observation/i);

    const race = makeFixture();
    const raceResult = bootstrap(race);
    const different = execFileSync(
      "git",
      ["commit-tree", `${race.head}^{tree}`, "-p", race.head],
      {
        cwd: race.repository,
        encoding: "utf8",
        input: "different\n",
      },
    ).trim();
    git(race.captain, "checkout", "--detach", "-q", different);
    blocked(run(race.repository, [
      "canary-bootstrap-prepare",
      "--repository-worktree", race.repository,
      ...identityArgs(race),
      "--expected-identity-plan-sha256", raceResult.planSha256,
      "--expected-observation-sha256", raceResult.observationSha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
      "--worker-worktree", race.captain,
    ]), /WORKTREE_DRIFT|HEAD|branch|drift|漂移/i);
  });

  test("registration seals the identity and START_P1 rechecks the same receipt", () => {
    const fixture = makeFixture();
    const boot = bootstrap(fixture);
    const receipt =
      boot.prepared.captain_bootstrap_receipt_file as string;
    const receiptSha =
      boot.prepared.captain_bootstrap_receipt_sha256 as string;
    const foreman = fixture.foreman!;
    const captainArgs = [
      "register-role",
      "--repository-worktree", fixture.repository,
      "--goal", GOAL,
      "--task", TASK,
      "--role", "CAPTAIN",
      "--thread", THREAD,
      "--host", HOST,
      "--event-id", "register-captain-bootstrap",
      "--authorizer-capability-file", foreman.actor_capability_file,
      "--captain-bootstrap-receipt", receipt,
      "--captain-bootstrap-receipt-sha256", receiptSha,
      "--captain-bootstrap-operation-id", OPERATION,
      "--captain-bootstrap-challenge", CHALLENGE,
      "--captain-bootstrap-identity-plan-sha256", boot.planSha256,
    ];
    const captain = success(
      fixture.captain,
      captainArgs,
      fixture.controlDir,
    );
    expect(captain.session.captain_bootstrap).toMatchObject({
      receipt_file: receipt,
      receipt_sha256: receiptSha,
      thread: THREAD,
      host: HOST,
      worktree: fixture.captain,
      branch: boot.plan.worker_branch,
      head: fixture.head,
    });
    expect(success(
      fixture.captain,
      captainArgs.concat([
        "--actor-capability-file",
        captain.actor_capability_file,
      ]),
      fixture.controlDir,
    ).idempotent).toBe(true);

    const receiptBytes = readFileSync(receipt);
    const beforeRejection = success(fixture.repository, [
      "status",
      "--goal", GOAL,
      "--task", TASK,
    ], fixture.controlDir);
    const tampered = JSON.parse(receiptBytes.toString("utf8")) as Json;
    tampered.thread = "cross-thread";
    writeFileSync(receipt, `${JSON.stringify(tampered, null, 2)}\n`, {
      mode: 0o600,
    });
    blocked(run(fixture.captain, [
      "event-template",
      "--goal", GOAL,
      "--task", TASK,
      "--role", "CAPTAIN",
      "--thread", THREAD,
      "--type", "START_P1",
      "--event-id", "start-p1-captain-bootstrap",
      "--actor-capability-file", captain.actor_capability_file,
    ], fixture.controlDir), /BINDING_MISMATCH|receipt|SHA-256|bootstrap/i);
    const afterRejection = success(fixture.repository, [
      "status",
      "--goal", GOAL,
      "--task", TASK,
    ], fixture.controlDir);
    expect(afterRejection.tasks[TASK].state_revision)
      .toBe(beforeRejection.tasks[TASK].state_revision);
    writeFileSync(receipt, receiptBytes, { mode: 0o600 });
    chmodSync(receipt, 0o600);

    const template = success(fixture.captain, [
      "event-template",
      "--goal", GOAL,
      "--task", TASK,
      "--role", "CAPTAIN",
      "--thread", THREAD,
      "--type", "START_P1",
      "--event-id", "start-p1-captain-bootstrap",
      "--actor-capability-file", captain.actor_capability_file,
    ], fixture.controlDir);
    expect(template.payload).toMatchObject({
      required_start_head: fixture.head,
      p1_worktree: fixture.captain,
      p1_branch: boot.plan.worker_branch,
    });
    const eventFile = path.join(fixture.base, "start-p1.json");
    writeFileSync(eventFile, `${JSON.stringify(template, null, 2)}\n`);
    expect(success(fixture.captain, [
      "event",
      "--goal", GOAL,
      "--file", eventFile,
      "--actor-capability-file", captain.actor_capability_file,
    ], fixture.controlDir).accepted).toBe(true);
  });

  test("faulted CAPTAIN registration intent exact-retries with the same bootstrap binding", () => {
    const fixture = makeFixture();
    const boot = bootstrap(fixture);
    const receipt =
      boot.prepared.captain_bootstrap_receipt_file as string;
    const receiptSha =
      boot.prepared.captain_bootstrap_receipt_sha256 as string;
    const foreman = fixture.foreman!;
    const captainArgs = [
      "register-role",
      "--repository-worktree", fixture.repository,
      "--goal", GOAL,
      "--task", TASK,
      "--role", "CAPTAIN",
      "--thread", THREAD,
      "--host", HOST,
      "--event-id", "register-captain-bootstrap-intent-fault",
      "--authorizer-capability-file", foreman.actor_capability_file,
      "--captain-bootstrap-receipt", receipt,
      "--captain-bootstrap-receipt-sha256", receiptSha,
      "--captain-bootstrap-operation-id", OPERATION,
      "--captain-bootstrap-challenge", CHALLENGE,
      "--captain-bootstrap-identity-plan-sha256", boot.planSha256,
    ];
    const interrupted = run(
      fixture.captain,
      captainArgs,
      fixture.controlDir,
      {
        GOAL_CONTROL_TEST_FAULT_AFTER_REGISTRATION_INTENT_INSTALL:
          "exit",
      },
    );
    expect(interrupted.status).toBe(86);

    const recovered = success(
      fixture.captain,
      captainArgs,
      fixture.controlDir,
    );
    expect(recovered).toMatchObject({
      registered: true,
      idempotent: false,
      session: {
        captain_bootstrap: {
          receipt_file: receipt,
          receipt_sha256: receiptSha,
          thread: THREAD,
          host: HOST,
          worktree: fixture.captain,
          branch: boot.plan.worker_branch,
          head: fixture.head,
        },
      },
    });
    expect(success(
      fixture.captain,
      captainArgs.concat([
        "--actor-capability-file",
        recovered.actor_capability_file,
      ]),
      fixture.controlDir,
    ).idempotent).toBe(true);
  });

  test("non-P1 fallback START_P1 rechecks the same receipt before any event write", () => {
    const fixture = makeFixture({ p1: false });
    const foreman = fixture.foreman!;
    const packetUpdate = success(fixture.repository, [
      "event-template",
      "--goal", GOAL,
      "--task", TASK,
      "--role", "FOREMAN",
      "--thread", fixture.foremanThread!,
      "--type", "HEARTBEAT",
      "--event-id", "packet-update-captain-bootstrap-fallback",
      "--actor-capability-file", foreman.actor_capability_file,
    ], fixture.controlDir);
    packetUpdate.type = "PACKET_UPDATED";
    packetUpdate.full_head = fixture.head;
    packetUpdate.payload = {
      revision: 2,
      path: fixture.packetV2,
      sha256: fixture.packetV2Sha256,
      change_kind: "CONTRACT",
    };
    const packetEventFile = path.join(
      fixture.base,
      "packet-update-event.json",
    );
    writeFileSync(
      packetEventFile,
      `${JSON.stringify(packetUpdate, null, 2)}\n`,
    );
    expect(success(fixture.repository, [
      "event",
      "--goal", GOAL,
      "--file", packetEventFile,
      "--actor-capability-file", foreman.actor_capability_file,
    ], fixture.controlDir).accepted).toBe(true);
    fixture.requiredHead = fixture.head;
    const boot = bootstrap(fixture);
    expect(boot.plan.required_start_head_proof).toMatchObject({
      source: {
        kind: "TASK_FULL_HEAD",
        task_full_head: fixture.head,
      },
      required_start_head: fixture.head,
    });
    const receipt =
      boot.prepared.captain_bootstrap_receipt_file as string;
    const receiptSha =
      boot.prepared.captain_bootstrap_receipt_sha256 as string;
    const captain = success(fixture.captain, [
      "register-role",
      "--repository-worktree", fixture.repository,
      "--goal", GOAL,
      "--task", TASK,
      "--role", "CAPTAIN",
      "--thread", THREAD,
      "--host", HOST,
      "--event-id", "register-captain-bootstrap-fallback",
      "--authorizer-capability-file", foreman.actor_capability_file,
      "--captain-bootstrap-receipt", receipt,
      "--captain-bootstrap-receipt-sha256", receiptSha,
      "--captain-bootstrap-operation-id", OPERATION,
      "--captain-bootstrap-challenge", CHALLENGE,
      "--captain-bootstrap-identity-plan-sha256", boot.planSha256,
    ], fixture.controlDir);
    const loaded = loadFixtureGoal(fixture);
    const state = loaded.snapshot.tasks[TASK] as Json;
    const task = loaded.manifest.tasks.find(
      (candidate: Json) => candidate.id === TASK,
    ) as Json;
    expect(completeMechanicalP1EventPayload(
      fixture.captain,
      loaded,
      state,
      task,
      "START_P1",
      {},
    )).toEqual({});
    const startP1 = {
      type: "START_P1",
      payload: {},
    };
    expect(() => validateP1Boundary(
      fixture.captain,
      loaded,
      state,
      startP1,
    )).not.toThrow();
    const receiptBytes = readFileSync(receipt);
    const tampered = JSON.parse(receiptBytes.toString("utf8")) as Json;
    tampered.thread = "cross-thread";
    writeFileSync(receipt, `${JSON.stringify(tampered, null, 2)}\n`, {
      mode: 0o600,
    });
    const beforeRejection = success(fixture.repository, [
      "status",
      "--goal", GOAL,
      "--task", TASK,
    ], fixture.controlDir);

    expect(() => completeMechanicalP1EventPayload(
      fixture.captain,
      loaded,
      state,
      task,
      "START_P1",
      {},
    )).toThrow(/BINDING_MISMATCH|receipt|SHA-256|bootstrap/i);
    expect(() => validateP1Boundary(
      fixture.captain,
      loaded,
      state,
      startP1,
    )).toThrow(/BINDING_MISMATCH|receipt|SHA-256|bootstrap/i);
    const afterRejection = success(fixture.repository, [
      "status",
      "--goal", GOAL,
      "--task", TASK,
    ], fixture.controlDir);
    expect(afterRejection.tasks[TASK].state_revision)
      .toBe(beforeRejection.tasks[TASK].state_revision);

    writeFileSync(receipt, receiptBytes, { mode: 0o600 });
    chmodSync(receipt, 0o600);
    const restoredLoaded = loadFixtureGoal(fixture);
    expect(() => validateP1Boundary(
      fixture.captain,
      restoredLoaded,
      restoredLoaded.snapshot.tasks[TASK],
      startP1,
    )).not.toThrow();
  });

  test("legacy non-opt-in non-P1 START_P1 retains its primary-worktree path", () => {
    const fixture = makeFixture({
      captainOptIn: false,
      p1: false,
    });
    const foreman = fixture.foreman!;
    const captain = success(fixture.repository, [
      "register-role",
      "--goal", GOAL,
      "--task", TASK,
      "--role", "CAPTAIN",
      "--thread", "captain-legacy-no-p1",
      "--host", HOST,
      "--event-id", "register-captain-legacy-no-p1",
      "--authorizer-capability-file", foreman.actor_capability_file,
    ], fixture.controlDir);
    const template = success(fixture.repository, [
      "event-template",
      "--goal", GOAL,
      "--task", TASK,
      "--role", "CAPTAIN",
      "--thread", "captain-legacy-no-p1",
      "--type", "START_P1",
      "--event-id", "start-p1-legacy-no-p1",
      "--actor-capability-file", captain.actor_capability_file,
    ], fixture.controlDir);
    const eventFile = path.join(fixture.base, "start-p1-legacy.json");
    writeFileSync(eventFile, `${JSON.stringify(template, null, 2)}\n`);
    expect(success(fixture.repository, [
      "event",
      "--goal", GOAL,
      "--file", eventFile,
      "--actor-capability-file", captain.actor_capability_file,
    ], fixture.controlDir).accepted).toBe(true);
  });
});
