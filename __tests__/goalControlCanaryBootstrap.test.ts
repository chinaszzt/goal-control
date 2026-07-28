import { execFileSync, spawnSync } from "child_process";
import { createHash } from "crypto";
import {
  copyFileSync,
  existsSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { createRequire } from "module";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const nodeRequire = createRequire(import.meta.url);
const { hashObject, trustedGitExecutable } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "util.js"),
) as {
  hashObject: (value: unknown) => string;
  trustedGitExecutable: () => string;
};
const { executeLooseRefTransaction } = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "git-loose-ref-transaction.js",
  ),
) as {
  executeLooseRefTransaction: (
    options: Record<string, unknown>,
  ) => unknown;
};
const { publishPrivateJson } = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "canary-bootstrap-artifacts.js",
  ),
) as {
  publishPrivateJson: (
    target: string,
    value: unknown,
    label: string,
    conflictCode: string,
  ) => unknown;
};
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const GOAL_ID = "goal-canary-bootstrap";
const TASK_ID = "TASK-BOOTSTRAP";
const ROLE = "DEV";
const THREAD = "thread-bootstrap-dev-1";
const HOST = "local";
const OPERATION_ID = "bootstrap-task-bootstrap-dev-1";
const CHALLENGE = "ab".repeat(32);
const BOOTSTRAP_PROTOCOL = "goalctl-worker-canary-bootstrap-v1";
const BOOTSTRAP_POLICY_MARKER =
  `Worker-Canary-Bootstrap-Protocol: ${BOOTSTRAP_PROTOCOL}`;
const NATIVE_HEAD_TRANSACTION_PROTOCOL = "git-update-ref-symref-v1";
const FILES_HEAD_TRANSACTION_PROTOCOL =
  "git-files-backend-hardlink-head-v1";
const FILES_MINIMUM_GIT_VERSION = { major: 2, minor: 43 };
const NATIVE_MINIMUM_GIT_VERSION = { major: 2, minor: 50 };

type JsonRecord = Record<string, unknown>;
type GitVersion = { major: number; minor: number };

type Fixture = {
  base: string;
  repository: string;
  worker: string;
  remote: string;
  manifest: string;
  policy: string;
  policySha256: string;
  expectedHead: string;
};

type CommandResult = {
  status: number | null;
  stdout: string;
  stderr: string;
};

type BootstrapPlan = {
  output: JsonRecord;
  plan: JsonRecord;
  sha256: string;
};

type BootstrapObservation = {
  output: JsonRecord;
  observation: JsonRecord;
  sha256: string;
};

type PreparedBootstrap = {
  output: JsonRecord;
  receiptFile: string;
  receiptSha256: string;
};

type GitWitness = {
  head: string;
  tree: string;
  index: string;
  status: string;
  localRemoteRefs: string;
  remoteRefs: string;
};

const fixtures: Fixture[] = [];

type FixtureOptions = {
  bootstrapOptIn?: boolean;
  policyBody?: string;
};

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
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
    },
  }).trim();
}

function gitVersionAtLeast(
  actual: GitVersion,
  minimum: GitVersion,
): boolean {
  return actual.major > minimum.major
    || (
      actual.major === minimum.major
        && actual.minor >= minimum.minor
    );
}

function expectedHeadTransactionProtocol(cwd: string): string {
  const output = execFileSync(trustedGitExecutable(), ["--version"], {
    cwd,
    encoding: "utf8",
  }).trim();
  const match = /^git version ([0-9]+)\.([0-9]+)(?:\.|$)/.exec(output);
  expect(match).not.toBeNull();
  const version = {
    major: Number(match![1]),
    minor: Number(match![2]),
  };
  expect(gitVersionAtLeast(version, FILES_MINIMUM_GIT_VERSION))
    .toBe(true);
  return gitVersionAtLeast(version, NATIVE_MINIMUM_GIT_VERSION)
    ? NATIVE_HEAD_TRANSACTION_PROTOCOL
    : FILES_HEAD_TRANSACTION_PROTOCOL;
}

function writeRepositoryFile(
  repository: string,
  relative: string,
  body: string,
): void {
  const absolute = path.join(repository, relative);
  mkdirSync(path.dirname(absolute), { recursive: true });
  writeFileSync(absolute, body);
}

function createFixture(options: FixtureOptions = {}): Fixture {
  const base = mkdtempSync(path.join(tmpdir(), "goal-canary-bootstrap-"));
  const repository = path.join(base, "repository");
  const worker = path.join(base, "worker");
  const remote = path.join(base, "remote.git");
  mkdirSync(repository);
  git(base, "init", "--bare", "-q", remote);
  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.name", "Canary Bootstrap Test");
  git(repository, "config", "user.email", "canary-bootstrap@example.invalid");

  const protocol = {
    entry: "docs/planning/session-role-protocol.md",
    shared: "docs/planning/session-protocol/shared.md",
    foreman: "docs/planning/session-protocol/foreman.md",
    captain: "docs/planning/session-protocol/captain.md",
    role_kernel: "docs/planning/session-protocol/role-kernel.md",
  };
  for (const [name, relative] of Object.entries(protocol)) {
    writeRepositoryFile(repository, relative, `# ${name}\n`);
  }
  const policy = "docs/planning/goals/bootstrap.canary-policy.md";
  const policyBody = options.policyBody ?? [
    "# Worker canary bootstrap policy",
    "",
    BOOTSTRAP_POLICY_MARKER,
    "",
    "IDENTITY_ONLY -> PREPARE_ACTUAL_WORKTREE -> CANARY_EXECUTE",
    "",
  ].join("\n");
  writeRepositoryFile(repository, policy, policyBody);
  const packet = "docs/planning/goals/bootstrap/packets/TASK-BOOTSTRAP-r1.md";
  const packetBody = "# TASK-BOOTSTRAP\n";
  writeRepositoryFile(repository, packet, packetBody);
  const manifest = "docs/planning/goals/bootstrap/manifest.json";
  writeRepositoryFile(
    repository,
    manifest,
    `${JSON.stringify({
      schema_version: 1,
      goal_id: GOAL_ID,
      mode: "shadow",
      repository: {
        name_with_owner: "example/repository",
        base_branch: "main",
      },
      base_head: "1".repeat(40),
      protocol,
      ...(
        options.bootstrapOptIn === false
          ? {}
          : {
            worker_canary_bootstrap: {
              protocol: BOOTSTRAP_PROTOCOL,
              policy: {
                path: policy,
                sha256: sha256(policyBody),
              },
            },
          }
      ),
      tasks: [{
        id: TASK_ID,
        dependencies: [],
        integration_order: 1,
        risk_class: "STANDARD",
        packet: {
          revision: 1,
          path: packet,
          sha256: sha256(packetBody),
        },
        expected_write_set: [],
        conflict_domains: [],
        resource_requirements: [],
      }],
    }, null, 2)}\n`,
  );
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "bootstrap fixture");
  git(repository, "remote", "add", "origin", remote);
  git(repository, "push", "-q", "-u", "origin", "main");
  const expectedHead = git(repository, "rev-parse", "HEAD");
  git(repository, "worktree", "add", "--detach", "-q", worker, expectedHead);

  const fixture = {
    base,
    repository: realpathSync(repository),
    worker: realpathSync(worker),
    remote: realpathSync(remote),
    manifest,
    policy,
    policySha256: sha256(policyBody),
    expectedHead,
  };
  fixtures.push(fixture);
  return fixture;
}

function sanitizedEnvironment(): NodeJS.ProcessEnv {
  const environment = { ...process.env };
  for (const key of [
    "NODE_OPTIONS",
    "NODE_PATH",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
  ]) {
    delete environment[key];
  }
  return {
    ...environment,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    LC_ALL: "C",
  };
}

function runGoalctl(
  cwd: string,
  args: string[],
): CommandResult {
  const result = spawnSync(
    process.execPath,
    [GOALCTL, ...args, "--json"],
    {
      cwd,
      encoding: "utf8",
      env: sanitizedEnvironment(),
    },
  );
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function successfulJson(cwd: string, args: string[]): JsonRecord {
  const result = runGoalctl(cwd, args);
  expect({
    status: result.status,
    stderr: result.stderr,
  }).toEqual({
    status: 0,
    stderr: "",
  });
  return JSON.parse(result.stdout) as JsonRecord;
}

function identityBindingArgs(fixture: Fixture): string[] {
  return [
    "--manifest", fixture.manifest,
    "--role", ROLE,
    "--task", TASK_ID,
    "--expected-head", fixture.expectedHead,
    "--operation-id", OPERATION_ID,
    "--challenge", CHALLENGE,
    "--canary-policy", fixture.policy,
    "--canary-policy-sha256", fixture.policySha256,
  ];
}

function requiredString(value: JsonRecord, key: string): string {
  const candidate = value[key];
  expect(typeof candidate).toBe("string");
  return candidate as string;
}

function requiredRecord(value: JsonRecord, key: string): JsonRecord {
  const candidate = value[key];
  expect(candidate).not.toBeNull();
  expect(typeof candidate).toBe("object");
  expect(Array.isArray(candidate)).toBe(false);
  return candidate as JsonRecord;
}

function createIdentityPlan(
  fixture: Fixture,
  bindingArgs: string[] = identityBindingArgs(fixture),
): BootstrapPlan {
  const output = successfulJson(fixture.repository, [
    "canary-bootstrap-plan",
    "--repository-worktree", fixture.repository,
    ...bindingArgs,
  ]);
  return {
    output,
    plan: requiredRecord(output, "identity_plan"),
    sha256: requiredString(output, "identity_plan_sha256"),
  };
}

function inspectIdentity(
  fixture: Fixture,
  worker: string,
  planSha256: string,
  options: {
    bindingArgs?: string[];
    thread?: string;
    host?: string;
  } = {},
): BootstrapObservation {
  const output = successfulJson(worker, [
    "canary-bootstrap-inspect",
    "--goal-worktree", fixture.repository,
    ...(options.bindingArgs ?? identityBindingArgs(fixture)),
    "--expected-identity-plan-sha256", planSha256,
    "--worker-thread", options.thread ?? THREAD,
    "--worker-host", options.host ?? HOST,
  ]);
  return {
    output,
    observation: requiredRecord(output, "identity_observation"),
    sha256: requiredString(output, "identity_observation_sha256"),
  };
}

function inspectFromGeneratedTemplate(
  fixture: Fixture,
  plan: BootstrapPlan,
): CommandResult {
  const identityCapture = requiredRecord(
    plan.plan,
    "identity_capture",
  );
  const template = requiredString(
    identityCapture,
    "shell_command_template",
  );
  const command = template
    .replaceAll("<platform-thread-id>", THREAD)
    .replaceAll("<platform-host-id>", HOST);
  const result = spawnSync("/bin/sh", ["-c", command], {
    cwd: fixture.worker,
    encoding: "utf8",
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function prepareArguments(
  fixture: Fixture,
  planSha256: string,
  observationSha256: string,
  options: {
    bindingArgs?: string[];
    thread?: string;
    host?: string;
    worker?: string;
  } = {},
): string[] {
  return [
    "canary-bootstrap-prepare",
    "--repository-worktree", fixture.repository,
    ...(options.bindingArgs ?? identityBindingArgs(fixture)),
    "--expected-identity-plan-sha256", planSha256,
    "--expected-observation-sha256", observationSha256,
    "--worker-thread", options.thread ?? THREAD,
    "--worker-host", options.host ?? HOST,
    "--worker-worktree", options.worker ?? fixture.worker,
  ];
}

function prepareBootstrap(
  fixture: Fixture,
  planSha256: string,
  observationSha256: string,
  options: {
    bindingArgs?: string[];
    thread?: string;
    host?: string;
    worker?: string;
  } = {},
): PreparedBootstrap {
  const output = successfulJson(
    fixture.repository,
    prepareArguments(
      fixture,
      planSha256,
      observationSha256,
      options,
    ),
  );
  return {
    output,
    receiptFile: requiredString(
      output,
      "worker_bootstrap_receipt_file",
    ),
    receiptSha256: requiredString(
      output,
      "worker_bootstrap_receipt_sha256",
    ),
  };
}

function bootstrap(fixture: Fixture): {
  plan: BootstrapPlan;
  observation: BootstrapObservation;
  prepared: PreparedBootstrap;
} {
  const plan = createIdentityPlan(fixture);
  const observation = inspectIdentity(fixture, fixture.worker, plan.sha256);
  const prepared = prepareBootstrap(
    fixture,
    plan.sha256,
    observation.sha256,
  );
  return { plan, observation, prepared };
}

function gitWitness(fixture: Fixture, worker = fixture.worker): GitWitness {
  const gitDir = realpathSync(git(
    worker,
    "rev-parse",
    "--path-format=absolute",
    "--absolute-git-dir",
  ));
  return {
    head: git(worker, "rev-parse", "HEAD"),
    tree: git(worker, "rev-parse", "HEAD^{tree}"),
    index: sha256(readFileSync(path.join(gitDir, "index"))),
    status: git(
      worker,
      "status",
      "--porcelain=v2",
      "--untracked-files=all",
    ),
    localRemoteRefs: git(
      worker,
      "for-each-ref",
      "--format=%(refname)%00%(objectname)",
      "refs/remotes",
    ),
    remoteRefs: git(
      fixture.remote,
      "for-each-ref",
      "--format=%(refname)%00%(objectname)",
    ),
  };
}

function bootstrapOperationPaths(fixture: Fixture): {
  commonGitDir: string;
  operationDirectory: string;
  intentFile: string;
  refFenceFile: string;
} {
  const commonGitDir = realpathSync(git(
    fixture.worker,
    "rev-parse",
    "--path-format=absolute",
    "--git-common-dir",
  ));
  const operationDirectory = path.join(
    commonGitDir,
    "goal-control",
    "worker-canary-bootstrap-v1",
    "goals",
    GOAL_ID,
    "tasks",
    TASK_ID,
    sha256(OPERATION_ID).slice("sha256:".length),
  );
  return {
    commonGitDir,
    operationDirectory,
    intentFile: path.join(operationDirectory, "intent.json"),
    refFenceFile: path.join(operationDirectory, "branch-ref-fence"),
  };
}

function seedBootstrapIntent(
  fixture: Fixture,
  plan: BootstrapPlan,
  observation: BootstrapObservation,
): ReturnType<typeof bootstrapOperationPaths> {
  const paths = bootstrapOperationPaths(fixture);
  mkdirSync(paths.operationDirectory, {
    recursive: true,
    mode: 0o700,
  });
  const request = {
    schema_version: 1,
    kind: "WORKER_CANARY_PREPARE_INTENT",
    identity_plan_sha256: plan.sha256,
    identity_observation_sha256: observation.sha256,
    goal_id: GOAL_ID,
    task_id: TASK_ID,
    role: ROLE,
    operation_id: OPERATION_ID,
    challenge: CHALLENGE,
    thread: THREAD,
    host: HOST,
    worker_branch: requiredString(plan.plan, "worker_branch"),
    worker_observation: observation.observation,
    controller: requiredRecord(plan.plan, "controller"),
    canary_policy: requiredRecord(plan.plan, "canary_policy"),
  };
  publishPrivateJson(
    paths.intentFile,
    {
      ...request,
      request_sha256: hashObject(request),
    },
    "worker canary bootstrap intent",
    "CANARY_BOOTSTRAP_OPERATION_CONFLICT",
  );
  return paths;
}

function expectBlocked(
  result: CommandResult,
  detail: RegExp,
): void {
  expect(result.status).toBe(2);
  expect(result.stdout).toBe("");
  expect(result.stderr).toMatch(/^goalctl\[[A-Z0-9_]+\]:/);
  expect(result.stderr).toMatch(detail);
}

function rejectDuringInspectOrPrepare(
  fixture: Fixture,
  worker: string,
  detail: RegExp,
): void {
  const plan = createIdentityPlan(fixture);
  const inspection = runGoalctl(worker, [
    "canary-bootstrap-inspect",
    "--goal-worktree", fixture.repository,
    ...identityBindingArgs(fixture),
    "--expected-identity-plan-sha256", plan.sha256,
    "--worker-thread", THREAD,
    "--worker-host", HOST,
  ]);
  if (inspection.status !== 0) {
    expectBlocked(inspection, detail);
    return;
  }
  const observation = JSON.parse(inspection.stdout) as JsonRecord;
  const result = runGoalctl(
    fixture.repository,
    prepareArguments(
      fixture,
      plan.sha256,
      requiredString(observation, "identity_observation_sha256"),
      { worker },
    ),
  );
  expectBlocked(result, detail);
}

afterEach(() => {
  while (fixtures.length > 0) {
    rmSync(fixtures.pop()!.base, { recursive: true, force: true });
  }
});

describe("goalctl worker canary bootstrap (bootstrap-v2)", () => {
  test("rejects a legacy manifest and policy without bootstrap opt-in", () => {
    const fixture = createFixture({ bootstrapOptIn: false });

    const result = runGoalctl(fixture.repository, [
      "canary-bootstrap-plan",
      "--repository-worktree", fixture.repository,
      ...identityBindingArgs(fixture),
    ]);

    expectBlocked(
      result,
      /bootstrap|protocol|policy|unsupported|opt-in|不支持|未启用/i,
    );
  });

  test("rejects the frozen pre-bootstrap-v2 CANARY_ONLY policy even with a manifest opt-in", () => {
    const legacyPolicy = [
      "# Legacy canary-only policy",
      "",
      "Mode: CANARY_ONLY",
      "",
      "This policy intentionally predates worker bootstrap binding.",
      "",
    ].join("\n");
    const fixture = createFixture({ policyBody: legacyPolicy });

    const result = runGoalctl(fixture.repository, [
      "canary-bootstrap-plan",
      "--repository-worktree", fixture.repository,
      ...identityBindingArgs(fixture),
    ]);

    expectBlocked(
      result,
      /bootstrap|policy|marker|unsupported|opt-in|不支持|缺少/i,
    );
  });

  test("an opted-in worker canary plan cannot omit its bootstrap receipt", () => {
    const fixture = createFixture();

    const result = runGoalctl(fixture.repository, [
      "canary-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", ROLE,
      "--task", TASK_ID,
    ]);

    expectBlocked(
      result,
      /bootstrap|required|receipt|必须|缺少/i,
    );
  });

  test("bootstrap plan requires an explicit frozen repository worktree", () => {
    const fixture = createFixture();
    const before = gitWitness(fixture);

    const result = runGoalctl(fixture.repository, [
      "canary-bootstrap-plan",
      ...identityBindingArgs(fixture),
    ]);

    expectBlocked(
      result,
      /repository-worktree|repository|frozen|参数|缺少/i,
    );
    expect(gitWitness(fixture)).toEqual(before);
  });

  test("bootstrap prepare rejects a missing frozen repository before side effects", () => {
    const fixture = createFixture();
    const plan = createIdentityPlan(fixture);
    const observation = inspectIdentity(
      fixture,
      fixture.worker,
      plan.sha256,
    );
    const before = gitWitness(fixture);
    const args = prepareArguments(
      fixture,
      plan.sha256,
      observation.sha256,
    );
    const repositoryFlag = args.indexOf("--repository-worktree");
    args.splice(repositoryFlag, 2);

    const result = runGoalctl(fixture.repository, args);

    expectBlocked(
      result,
      /repository-worktree|repository|frozen|参数|缺少/i,
    );
    expect(gitWitness(fixture)).toEqual(before);
    expect(git(fixture.worker, "rev-parse", "--abbrev-ref", "HEAD"))
      .toBe("HEAD");
  });

  test("the generated IDENTITY_ONLY shell command is directly executable", () => {
    const fixture = createFixture();
    const plan = createIdentityPlan(fixture);

    const result = inspectFromGeneratedTemplate(fixture, plan);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    const output = JSON.parse(result.stdout) as JsonRecord;
    expect(output).toMatchObject({
      identity_observation: {
        identity_plan_sha256: plan.sha256,
        thread: THREAD,
        host: HOST,
        cwd: fixture.worker,
        head: fixture.expectedHead,
      },
    });
  });

  test("prepares a detached linked worktree and binds canary-plan to its actual identity", () => {
    const fixture = createFixture();
    const expectedTransactionProtocol =
      expectedHeadTransactionProtocol(fixture.worker);
    expect(git(fixture.worker, "rev-parse", "--abbrev-ref", "HEAD"))
      .toBe("HEAD");
    const beforeInspect = gitWitness(fixture);

    const plan = createIdentityPlan(fixture);
    expect(plan.plan).toMatchObject({
      phase: "IDENTITY_ONLY",
      role: ROLE,
      task_id: TASK_ID,
      expected_head: fixture.expectedHead,
      operation_id: OPERATION_ID,
      challenge: CHALLENGE,
    });
    const expectedWorkerBranch = requiredString(
      plan.plan,
      "worker_branch",
    );
    expect(expectedWorkerBranch).toMatch(/^codex\//);

    const observation = inspectIdentity(
      fixture,
      fixture.worker,
      plan.sha256,
    );
    expect(observation.observation).toMatchObject({
      thread: THREAD,
      host: HOST,
      cwd: fixture.worker,
      head: fixture.expectedHead,
      branch: null,
      clean: true,
    });
    expect(gitWitness(fixture)).toEqual(beforeInspect);

    const beforePrepare = gitWitness(fixture);
    const prepared = prepareBootstrap(
      fixture,
      plan.sha256,
      observation.sha256,
    );
    expect(statSync(prepared.receiptFile).mode & 0o777).toBe(0o600);
    expect(statSync(prepared.receiptFile).nlink).toBe(1);
    expect(sha256(readFileSync(prepared.receiptFile)))
      .toBe(prepared.receiptSha256);
    const receipt = JSON.parse(
      readFileSync(prepared.receiptFile, "utf8"),
    ) as JsonRecord;
    expect(receipt.identity_plan).toEqual(plan.plan);
    expect(receipt).toMatchObject({
      head_transaction: {
        transaction_protocol: expectedTransactionProtocol,
        operation_id: OPERATION_ID,
        expected_oid: fixture.expectedHead,
        head_state: "ATTACHED",
      },
    });
    expect(git(fixture.worker, "symbolic-ref", "--short", "HEAD"))
      .toBe(expectedWorkerBranch);
    expect(gitWitness(fixture)).toEqual(beforePrepare);

    const canary = successfulJson(fixture.worker, [
      "canary-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", ROLE,
      "--task", TASK_ID,
      "--worker-bootstrap-receipt", prepared.receiptFile,
      "--worker-bootstrap-receipt-sha256", prepared.receiptSha256,
      "--worker-bootstrap-operation-id", OPERATION_ID,
      "--worker-bootstrap-challenge", CHALLENGE,
      "--worker-bootstrap-identity-plan-sha256", plan.sha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
    ]);
    expect(canary.canary_plan).toMatchObject({
      role: ROLE,
      task_id: TASK_ID,
      worker_bootstrap: {
        receipt_sha256: prepared.receiptSha256,
        operation_id: OPERATION_ID,
        challenge: CHALLENGE,
        identity_plan_sha256: plan.sha256,
        thread: THREAD,
        host: HOST,
        worktree: fixture.worker,
        head: fixture.expectedHead,
        branch: expectedWorkerBranch,
      },
    });
    const probeBindings = requiredRecord(
      requiredRecord(canary, "canary_plan"),
      "probe_bindings",
    );
    expect(
      requiredRecord(probeBindings, "git_push_dry_run"),
    ).toMatchObject({
      destination: `refs/heads/${expectedWorkerBranch}`,
    });
    const replay = requiredRecord(
      requiredRecord(canary, "canary_plan"),
      "replay",
    );
    const replayArgv = replay.argv as unknown[];
    const bootstrapReplayStart = replayArgv.indexOf(
      "--worker-bootstrap-receipt",
    );
    expect(
      replayArgv.slice(bootstrapReplayStart, bootstrapReplayStart + 14),
    ).toEqual([
      "--worker-bootstrap-receipt",
      prepared.receiptFile,
      "--worker-bootstrap-receipt-sha256",
      prepared.receiptSha256,
      "--worker-bootstrap-operation-id",
      OPERATION_ID,
      "--worker-bootstrap-challenge",
      CHALLENGE,
      "--worker-bootstrap-identity-plan-sha256",
      plan.sha256,
      "--worker-thread",
      THREAD,
      "--worker-host",
      HOST,
    ]);
  });

  test("exact retry returns the same private receipt and same operation with different bytes is rejected", () => {
    const fixture = createFixture();
    const first = bootstrap(fixture);
    const intentFile = path.join(
      path.dirname(first.prepared.receiptFile),
      "intent.json",
    );
    const intentBytes = readFileSync(intentFile);
    const intentCrashResidual = path.join(
      path.dirname(intentFile),
      `.intent.json.${sha256(intentBytes).slice("sha256:".length)}.tmp`,
    );
    linkSync(intentFile, intentCrashResidual);
    expect(statSync(intentFile).nlink).toBe(2);
    const receiptCrashResidual = path.join(
      path.dirname(first.prepared.receiptFile),
      `.receipt.json.${
        first.prepared.receiptSha256.slice("sha256:".length)
      }.tmp`,
    );
    linkSync(first.prepared.receiptFile, receiptCrashResidual);
    expect(statSync(first.prepared.receiptFile).nlink).toBe(2);
    const retry = prepareBootstrap(
      fixture,
      first.plan.sha256,
      first.observation.sha256,
    );
    expect(statSync(intentFile).nlink).toBe(1);
    expect(statSync(first.prepared.receiptFile).nlink).toBe(1);
    expect(retry.receiptFile).toBe(first.prepared.receiptFile);
    expect(retry.receiptSha256).toBe(first.prepared.receiptSha256);
    expect(retry.output.idempotent).toBe(true);

    const alternateWorker = path.join(
      fixture.base,
      "alternate-worker",
    );
    git(
      fixture.repository,
      "worktree",
      "add",
      "--detach",
      "-q",
      alternateWorker,
      fixture.expectedHead,
    );
    const differentWorkerRetry = runGoalctl(
      fixture.repository,
      prepareArguments(
        fixture,
        first.plan.sha256,
        first.observation.sha256,
        { worker: realpathSync(alternateWorker) },
      ),
    );
    expectBlocked(
      differentWorkerRetry,
      /worker|worktree|operation|request|identity|工作树|冲突/i,
    );

    const changedChallenge = "cd".repeat(32);
    const changedBinding = identityBindingArgs(fixture).flatMap(
      (argument, index, all) => (
        index > 0 && all[index - 1] === "--challenge"
          ? [changedChallenge]
          : [argument]
      ),
    );
    const changedPlan = createIdentityPlan(fixture, changedBinding);
    const changedObservation = inspectIdentity(
      fixture,
      fixture.worker,
      changedPlan.sha256,
      { bindingArgs: changedBinding },
    );
    const conflict = runGoalctl(
      fixture.repository,
      prepareArguments(
        fixture,
        changedPlan.sha256,
        changedObservation.sha256,
        { bindingArgs: changedBinding },
      ),
    );
    expectBlocked(
      conflict,
      /operation|conflict|request|challenge|mismatch|异文|冲突/i,
    );
  });

  test("prepare recovers a branch transaction crash after canonical ref publication", () => {
    const fixture = createFixture();
    const plan = createIdentityPlan(fixture);
    const observation = inspectIdentity(
      fixture,
      fixture.worker,
      plan.sha256,
    );
    const workerBranch = requiredString(plan.plan, "worker_branch");
    const targetRef = `refs/heads/${workerBranch}`;
    const paths = seedBootstrapIntent(fixture, plan, observation);

    expect(() => executeLooseRefTransaction({
      cwd: fixture.worker,
      commonGitDir: paths.commonGitDir,
      ref: targetRef,
      expectedOld: "0".repeat(40),
      expectedNew: fixture.expectedHead,
      fenceFile: paths.refFenceFile,
      fenceInstalledAtEntry: false,
      reflogPolicy: "absent",
      onStage(stage: string) {
        if (stage === "canonical-mutated") {
          throw new Error("simulated-canonical-mutated-crash");
        }
      },
    })).toThrow("simulated-canonical-mutated-crash");
    expect(existsSync(paths.refFenceFile)).toBe(true);

    const recovered = prepareBootstrap(
      fixture,
      plan.sha256,
      observation.sha256,
    );

    expect(recovered.receiptSha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(existsSync(paths.refFenceFile)).toBe(false);
    expect(statSync(
      path.join(paths.commonGitDir, ...targetRef.split("/")),
    ).nlink).toBe(1);
  });

  test("prepare rejects an expected branch ref with a foreign reflog", () => {
    const fixture = createFixture();
    const plan = createIdentityPlan(fixture);
    const observation = inspectIdentity(
      fixture,
      fixture.worker,
      plan.sha256,
    );
    const workerBranch = requiredString(plan.plan, "worker_branch");
    const targetRef = `refs/heads/${workerBranch}`;
    const paths = seedBootstrapIntent(fixture, plan, observation);
    const targetRefFile = path.join(
      paths.commonGitDir,
      ...targetRef.split("/"),
    );
    mkdirSync(path.dirname(targetRefFile), {
      recursive: true,
      mode: 0o700,
    });
    writeFileSync(targetRefFile, `${fixture.expectedHead}\n`, {
      mode: 0o644,
    });
    const reflog = path.join(
      paths.commonGitDir,
      "logs",
      ...targetRef.split("/"),
    );
    mkdirSync(path.dirname(reflog), {
      recursive: true,
      mode: 0o700,
    });
    writeFileSync(reflog, "foreign reflog\n");

    const result = runGoalctl(
      fixture.repository,
      prepareArguments(
        fixture,
        plan.sha256,
        observation.sha256,
      ),
    );

    expectBlocked(
      result,
      /reflog|foreign|lock|日志|冲突/i,
    );
  });

  test("dirty, primary, and foreign worktrees fail closed", () => {
    const dirty = createFixture();
    writeFileSync(path.join(dirty.worker, "untracked.txt"), "dirty\n");
    rejectDuringInspectOrPrepare(
      dirty,
      dirty.worker,
      /dirty|clean|status|未提交|工作树/i,
    );

    const primary = createFixture();
    rejectDuringInspectOrPrepare(
      primary,
      primary.repository,
      /primary|main|base|linked|frozen|主工作树|基线|独立/i,
    );

    const expectedRepository = createFixture();
    const foreignRepository = createFixture();
    rejectDuringInspectOrPrepare(
      expectedRepository,
      foreignRepository.worker,
      /repository|common|linked|foreign|异仓|仓库/i,
    );
  });

  test("an occupied deterministic branch and hidden Git operation fail closed", () => {
    const occupied = createFixture();
    const occupiedPlan = createIdentityPlan(occupied);
    const workerBranch = requiredString(
      occupiedPlan.plan,
      "worker_branch",
    );
    expect(workerBranch).toMatch(/^codex\//);
    git(
      occupied.repository,
      "branch",
      workerBranch,
      occupied.expectedHead,
    );
    const occupiedWorktree = path.join(occupied.base, "occupied-worker");
    git(
      occupied.repository,
      "worktree",
      "add",
      "-q",
      occupiedWorktree,
      workerBranch,
    );
    const occupiedObservation = inspectIdentity(
      occupied,
      occupied.worker,
      occupiedPlan.sha256,
    );
    const occupiedResult = runGoalctl(
      occupied.repository,
      prepareArguments(
        occupied,
        occupiedPlan.sha256,
        occupiedObservation.sha256,
      ),
    );
    expectBlocked(
      occupiedResult,
      /branch|occupied|checked out|占用|分支/i,
    );

    const hidden = createFixture();
    const hiddenPlan = createIdentityPlan(hidden);
    const hiddenObservation = inspectIdentity(
      hidden,
      hidden.worker,
      hiddenPlan.sha256,
    );
    const workerGitDir = git(
      hidden.worker,
      "rev-parse",
      "--absolute-git-dir",
    );
    mkdirSync(path.join(workerGitDir, "rebase-merge"));
    const hiddenResult = runGoalctl(
      hidden.repository,
      prepareArguments(
        hidden,
        hiddenPlan.sha256,
        hiddenObservation.sha256,
      ),
    );
    expectBlocked(
      hiddenResult,
      /operation|rebase|merge|sequencer|Git/i,
    );
  });

  test("first prepare rejects an unclaimed pre-attached worker branch", () => {
    const fixture = createFixture();
    const plan = createIdentityPlan(fixture);
    const branch = requiredString(plan.plan, "worker_branch");
    git(fixture.worker, "branch", branch, fixture.expectedHead);
    git(
      fixture.worker,
      "symbolic-ref",
      "HEAD",
      `refs/heads/${branch}`,
    );
    const observation = inspectIdentity(
      fixture,
      fixture.worker,
      plan.sha256,
    );

    const result = runGoalctl(
      fixture.repository,
      prepareArguments(
        fixture,
        plan.sha256,
        observation.sha256,
      ),
    );

    expectBlocked(
      result,
      /first|detached|branch|provenance|首次|分支|冲突/i,
    );
  });

  test("prepare rejects a delete-and-recreate worktree ABA", () => {
    const fixture = createFixture();
    const plan = createIdentityPlan(fixture);
    const observation = inspectIdentity(
      fixture,
      fixture.worker,
      plan.sha256,
    );
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
      fixture.expectedHead,
    );

    const result = runGoalctl(
      fixture.repository,
      prepareArguments(
        fixture,
        plan.sha256,
        observation.sha256,
      ),
    );

    expectBlocked(
      result,
      /identity|observation|worktree|gitdir|ABA|身份|工作树/i,
    );
    expect(git(fixture.worker, "rev-parse", "--abbrev-ref", "HEAD"))
      .toBe("HEAD");
  });

  test("receipt is bound to thread and bytes, and canary-plan requires the actual process cwd", () => {
    const fixture = createFixture();
    const completed = bootstrap(fixture);
    const canaryArgs = [
      "canary-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", ROLE,
      "--task", TASK_ID,
      "--worker-bootstrap-receipt", completed.prepared.receiptFile,
      "--worker-bootstrap-receipt-sha256",
      completed.prepared.receiptSha256,
      "--worker-bootstrap-operation-id", OPERATION_ID,
      "--worker-bootstrap-challenge", CHALLENGE,
      "--worker-bootstrap-identity-plan-sha256",
      completed.plan.sha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
    ];

    for (const missingFlag of [
      "--worker-bootstrap-operation-id",
      "--worker-bootstrap-challenge",
      "--worker-bootstrap-identity-plan-sha256",
    ]) {
      const incompleteArgs = [...canaryArgs];
      const missingIndex = incompleteArgs.indexOf(missingFlag);
      incompleteArgs.splice(missingIndex, 2);
      expectBlocked(
        runGoalctl(fixture.worker, incompleteArgs),
        /argument|bootstrap|simultaneously|同时|参数/i,
      );
    }

    const crossThread = runGoalctl(fixture.worker, canaryArgs.map(
      (argument, index, all) => (
        index > 0 && all[index - 1] === "--worker-thread"
          ? "thread-bootstrap-dev-foreign"
          : argument
      ),
    ));
    expectBlocked(
      crossThread,
      /thread|binding|receipt|身份|绑定/i,
    );

    const wrongReceiptHash = runGoalctl(
      fixture.worker,
      canaryArgs.map((argument, index, all) => (
        index > 0
          && all[index - 1]
            === "--worker-bootstrap-receipt-sha256"
          ? `sha256:${"0".repeat(64)}`
          : argument
      )),
    );
    expectBlocked(
      wrongReceiptHash,
      /receipt|hash|sha256|摘要|绑定/i,
    );

    const wrongOperation = runGoalctl(
      fixture.worker,
      canaryArgs.map((argument, index, all) => (
        index > 0
          && all[index - 1] === "--worker-bootstrap-operation-id"
          ? `${OPERATION_ID}-foreign`
          : argument
      )),
    );
    expectBlocked(
      wrongOperation,
      /operation|receipt|binding|绑定/i,
    );

    const wrongChallenge = runGoalctl(
      fixture.worker,
      canaryArgs.map((argument, index, all) => (
        index > 0
          && all[index - 1] === "--worker-bootstrap-challenge"
          ? "cd".repeat(32)
          : argument
      )),
    );
    expectBlocked(
      wrongChallenge,
      /challenge|receipt|binding|绑定/i,
    );

    const wrongPlan = runGoalctl(
      fixture.worker,
      canaryArgs.map((argument, index, all) => (
        index > 0
          && all[index - 1]
            === "--worker-bootstrap-identity-plan-sha256"
          ? `sha256:${"0".repeat(64)}`
          : argument
      )),
    );
    expectBlocked(
      wrongPlan,
      /plan|receipt|binding|sha256|绑定/i,
    );

    const tamperedReceipt = path.join(
      fixture.base,
      "tampered-worker-bootstrap-receipt.json",
    );
    copyFileSync(completed.prepared.receiptFile, tamperedReceipt);
    const tampered = JSON.parse(
      readFileSync(tamperedReceipt, "utf8"),
    ) as JsonRecord;
    tampered.challenge = "ef".repeat(32);
    writeFileSync(
      tamperedReceipt,
      `${JSON.stringify(tampered, null, 2)}\n`,
      { mode: 0o600 },
    );
    const tamperResult = runGoalctl(
      fixture.worker,
      canaryArgs.map((argument, index, all) => (
        index > 0 && all[index - 1] === "--worker-bootstrap-receipt"
          ? tamperedReceipt
          : argument
      )),
    );
    expectBlocked(
      tamperResult,
      /receipt|hash|tamper|challenge|篡改|摘要/i,
    );

    const wrongCwd = runGoalctl(fixture.repository, canaryArgs);
    expectBlocked(
      wrongCwd,
      /cwd|worktree|process|工作树|目录/i,
    );
  });

  test("receipt cannot echo the supervisor plan hash over a different plan preimage", () => {
    const fixture = createFixture();
    const completed = bootstrap(fixture);
    const receipt = JSON.parse(
      readFileSync(completed.prepared.receiptFile, "utf8"),
    ) as JsonRecord;
    const identityPlan = requiredRecord(receipt, "identity_plan");
    identityPlan.expected_head = "f".repeat(40);
    const {
      receipt_binding_sha256: ignoredBinding,
      ...unsignedReceipt
    } = receipt;
    expect(typeof ignoredBinding).toBe("string");
    receipt.receipt_binding_sha256 = hashObject(unsignedReceipt);
    writeFileSync(
      completed.prepared.receiptFile,
      `${JSON.stringify(receipt, null, 2)}\n`,
      { mode: 0o600 },
    );
    const tamperedReceiptSha256 = sha256(
      readFileSync(completed.prepared.receiptFile),
    );

    const result = runGoalctl(fixture.worker, [
      "canary-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", ROLE,
      "--task", TASK_ID,
      "--worker-bootstrap-receipt", completed.prepared.receiptFile,
      "--worker-bootstrap-receipt-sha256", tamperedReceiptSha256,
      "--worker-bootstrap-operation-id", OPERATION_ID,
      "--worker-bootstrap-challenge", CHALLENGE,
      "--worker-bootstrap-identity-plan-sha256",
      completed.plan.sha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
    ]);

    expectBlocked(
      result,
      /identity plan|plan|preimage|hash|binding|绑定/i,
    );
  });

  test("full canary revalidates the durable claim owner and physical Git locks", () => {
    const fixture = createFixture();
    const completed = bootstrap(fixture);
    const receipt = JSON.parse(
      readFileSync(completed.prepared.receiptFile, "utf8"),
    ) as JsonRecord;
    const worker = requiredRecord(receipt, "worker");
    const headTransaction = requiredRecord(
      receipt,
      "head_transaction",
    );
    const canaryArgs = [
      "canary-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", ROLE,
      "--task", TASK_ID,
      "--worker-bootstrap-receipt", completed.prepared.receiptFile,
      "--worker-bootstrap-receipt-sha256",
      completed.prepared.receiptSha256,
      "--worker-bootstrap-operation-id", OPERATION_ID,
      "--worker-bootstrap-challenge", CHALLENGE,
      "--worker-bootstrap-identity-plan-sha256",
      completed.plan.sha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
    ];
    const headLock = path.join(
      requiredString(worker, "git_dir"),
      "HEAD.lock",
    );
    writeFileSync(headLock, "");
    expectBlocked(
      runGoalctl(fixture.worker, canaryArgs),
      /lock|Git|锁/i,
    );
    unlinkSync(headLock);

    const owner = path.join(
      path.dirname(requiredString(headTransaction, "claim_file")),
      "owner",
    );
    unlinkSync(owner);
    expectBlocked(
      runGoalctl(fixture.worker, canaryArgs),
      /claim|owner|anchor|归属|锚/i,
    );
  });

  test("full canary rejects a deterministic branch occupied by another worktree", () => {
    const fixture = createFixture();
    const completed = bootstrap(fixture);
    const workerBranch = requiredString(
      completed.plan.plan,
      "worker_branch",
    );
    const secondWorker = path.join(fixture.base, "second-worker");
    git(
      fixture.repository,
      "worktree",
      "add",
      "--detach",
      "-q",
      secondWorker,
      fixture.expectedHead,
    );
    const secondGitDir = realpathSync(git(
      secondWorker,
      "rev-parse",
      "--path-format=absolute",
      "--absolute-git-dir",
    ));
    writeFileSync(
      path.join(secondGitDir, "HEAD"),
      `ref: refs/heads/${workerBranch}\n`,
    );

    const result = runGoalctl(fixture.worker, [
      "canary-plan",
      "--repository-worktree", fixture.repository,
      "--manifest", fixture.manifest,
      "--role", ROLE,
      "--task", TASK_ID,
      "--worker-bootstrap-receipt", completed.prepared.receiptFile,
      "--worker-bootstrap-receipt-sha256",
      completed.prepared.receiptSha256,
      "--worker-bootstrap-operation-id", OPERATION_ID,
      "--worker-bootstrap-challenge", CHALLENGE,
      "--worker-bootstrap-identity-plan-sha256",
      completed.plan.sha256,
      "--worker-thread", THREAD,
      "--worker-host", HOST,
    ]);

    expectBlocked(
      result,
      /branch|occupied|worktree|占用|工作树/i,
    );
  });

  test.each([
    "intent-only",
    "branch-ref-created",
    "head-attached",
  ] as const)(
    "exact retry recovers the %s crash checkpoint",
    (checkpoint) => {
      const fixture = createFixture();
      let plan: BootstrapPlan;
      let observation: BootstrapObservation;
      let originalReceiptSha256: string | null = null;
      if (checkpoint === "head-attached") {
        const completed = bootstrap(fixture);
        plan = completed.plan;
        observation = completed.observation;
        originalReceiptSha256 = completed.prepared.receiptSha256;
        unlinkSync(completed.prepared.receiptFile);
      } else {
        plan = createIdentityPlan(fixture);
        observation = inspectIdentity(
          fixture,
          fixture.worker,
          plan.sha256,
        );
        const paths = seedBootstrapIntent(
          fixture,
          plan,
          observation,
        );
        if (checkpoint === "branch-ref-created") {
          executeLooseRefTransaction({
            cwd: fixture.worker,
            commonGitDir: paths.commonGitDir,
            ref: `refs/heads/${
              requiredString(plan.plan, "worker_branch")
            }`,
            expectedOld: "0".repeat(40),
            expectedNew: fixture.expectedHead,
            fenceFile: paths.refFenceFile,
            fenceInstalledAtEntry: false,
            reflogPolicy: "absent",
          });
        }
      }
      const branch = requiredString(plan.plan, "worker_branch");

      const recovered = prepareBootstrap(
        fixture,
        plan.sha256,
        observation.sha256,
      );
      expect(git(fixture.worker, "symbolic-ref", "--short", "HEAD"))
        .toBe(branch);
      if (originalReceiptSha256 !== null) {
        expect(recovered.receiptSha256)
          .toBe(originalReceiptSha256);
      }
      expect(recovered.output.idempotent).toBe(false);

      const replay = prepareBootstrap(
        fixture,
        plan.sha256,
        observation.sha256,
      );
      expect(replay.receiptSha256).toBe(recovered.receiptSha256);
      expect(replay.output.idempotent).toBe(true);
    },
  );
});
