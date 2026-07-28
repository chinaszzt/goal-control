import { execFileSync, spawn } from "child_process";
import { createHash } from "crypto";
import { once } from "events";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const nodeRequire = createRequire(import.meta.url);
const { goalCommand } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "cli.js"),
) as {
  goalCommand: (
    args: string[],
    cwd: string,
  ) => { value: CanaryPlanOutput; exitCode: number };
};
const { hashObject } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "util.js"),
) as {
  hashObject: (value: unknown) => string;
};
const {
  assertControllerWorktreeClean,
  canaryPolicyKnownLimitations,
  canaryPlan,
} = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "canary-plan.js"),
) as {
  assertControllerWorktreeClean: (repositoryRoot: string) => {
    closureSha256: string;
  };
  canaryPolicyKnownLimitations: (
    policyBytes: Buffer,
  ) => Array<Record<string, string>>;
  canaryPlan: (
    cwd: string,
    options: {
      manifestFile: string;
      role: CanaryRole;
      taskId: string | null;
      browserCanaryReceipt?: string | null;
    },
    dependencies?: {
      afterManifestCapture?: () => void;
      afterManifestParse?: () => void;
      beforeManifestValidation?: () => void;
      afterManifestValidation?: () => void;
      afterBrowserReceiptPathCapture?: () => void;
      afterBrowserReceiptOpen?: () => void;
      afterBrowserReceiptRead?: () => void;
    },
  ) => CanaryPlanOutput;
};
const {
  buildCanaryPage,
  deriveServeEnvironment,
  deriveServeIdentity,
  processCommandSha256,
  processCwd,
  processExecutablePath,
  processStartToken,
} = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "browser-canary-server.js"),
) as {
  buildCanaryPage: (nonce: string) => string;
  deriveServeEnvironment: (
    source?: Record<string, string | undefined>,
  ) => Record<string, string>;
  deriveServeIdentity: (options: {
    receiptFile: string;
    binding: {
      goal_id: string;
      role: Exclude<CanaryRole, "CAPTAIN">;
      task_id: string | null;
    };
    environment?: Record<string, string>;
  }) => Record<string, unknown>;
  processCommandSha256: (pid: number) => string | null;
  processCwd: (pid: number) => string | null;
  processExecutablePath: (pid: number) => string | null;
  processStartToken: (pid: number) => string | null;
};
const BROWSER_CANARY_SERVER = path.join(
  ROOT,
  "scripts",
  "goal-control",
  "browser-canary-server.js",
);
const CANARY_PLAN_LAUNCHER = path.join(
  ROOT,
  "scripts",
  "goal-control",
  "canary-plan-launch.sh",
);
const EXPLICIT_NODE_ARGS = [
  "--node-executable",
  realpathSync(process.execPath),
];
const WORKER_CANARY_BOOTSTRAP_POLICY_MARKER =
  "Worker-Canary-Bootstrap-Protocol: goalctl-worker-canary-bootstrap-v1";
const GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER =
  "GitHub-App-Known-Limitation: github_app_private_repo_404-v1";

type WorkerRole = "DEV" | "REVIEW" | "RECEIPT";
type CanaryRole = "FOREMAN" | "CAPTAIN" | WorkerRole;
type ResourceRequirement = {
  kind:
    | "PORT"
    | "BROWSER_PROFILE"
    | "ACCOUNT"
    | "TIM_SESSION"
    | "WINDOW"
    | "EXECUTABLE"
    | "TEST_DATA";
  id: string;
  access: "EXCLUSIVE" | "SHARED_READ";
  roles?: WorkerRole[];
};
type TaskSpec = {
  id: string;
  requirements: ResourceRequirement[];
};
type CanaryPlan = {
  controller: {
    root: string;
    entrypoint: string;
    repository_head: string;
    decoder_sha256: string;
    closure_sha256: string;
    modules: Record<string, string>;
  };
  repository_worktree: string;
  repository_head: string;
  repository: {
    name_with_owner: string;
    base_branch: string;
  };
  capability_targets: {
    github_app: {
      repository: string;
      pull_request: null;
      pre_registration_scope: "REPOSITORY_ONLY";
      operation_contract: {
        schema_version: 1;
        capability_plane: "GITHUB_APP_CONNECTOR";
        semantic_operation: "REPOSITORY_METADATA_READ";
        target_kind: "REPOSITORY";
        repository: string;
        read_only: true;
        interaction: "NON_INTERACTIVE";
        success_repository_identity_must_equal: true;
        forbidden_substitute_operations: [
          "COMMIT_READ",
          "PULL_REQUEST_READ",
          "FILE_READ",
          "ISSUE_READ",
        ];
      };
    };
  };
  replay: {
    node_executable: string;
    argv: string[];
    environment: {
      schema_version: 1;
      executable: string;
      clear_inherited: true;
      assignments: string[];
      sha256: string;
    };
    shell_command: string;
  };
  manifest: {
    path: string;
    sha256: string;
    validated_manifest_sha256: string;
  };
  role: CanaryRole;
  task_id: string | null;
  required_probes: string[];
  canary_policy: null | {
    path: string;
    sha256: string;
    known_limitations: Array<{
      id: "github_app_private_repo_404-v1";
      policy_marker: string;
    }>;
  };
  probe_evaluation: {
    schema_version: 1;
    replay_must_pass_before_probes: true;
    required_probe_order: "DECLARED_ARRAY_ORDER";
    session_scope: "CURRENT_ACTUAL_SESSION_ONLY";
    missing_or_skipped_probe_disposition: "CANARY_FAIL";
    non_matching_result_disposition: "CANARY_FAIL";
    final_pass_condition:
      "EVERY_REQUIRED_PROBE_PASS_OR_FINALIZED_KNOWN_LIMITATION";
    known_limitations: Array<{
      id: "github_app_private_repo_404-v1";
      probe: "GITHUB_APP_REPOSITORY_READ";
      policy_marker: string;
      exact_match: {
        semantic_operation: "REPOSITORY_METADATA_READ";
        target_kind: "REPOSITORY";
        repository: string;
        result_fingerprint: "404/repo_not_found";
        allow_dialog: false;
        authentication_prompt: false;
      };
      provisional_disposition: "PROVISIONAL_KNOWN_LIMITATION";
      compensation_probes: string[];
      terminal_mismatch_classes: [
        "ALLOW_DIALOG",
        "AUTHENTICATION_PROMPT",
        "TOKEN_REQUEST",
        "HTTP_401",
        "HTTP_403",
        "TIMEOUT",
        "NETWORK_ERROR",
        "WRONG_REPOSITORY",
        "WRONG_OPERATION",
        "DIFFERENT_FINGERPRINT",
      ];
      finalization_condition:
        "ALL_LISTED_COMPENSATION_PROBES_PASS_CURRENT_SESSION";
      final_disposition: "KNOWN_CONNECTOR_LIMITATION";
    }>;
  };
  browser: {
    decision: "REQUIRED" | "NOT_REQUIRED";
    matched_requirements: Array<{
      task_id: string;
      kind: string;
      id: string;
      roles: WorkerRole[];
    }>;
    target: null | {
      contract_version: number;
      url: string;
      expected_title: string;
      button_id: string;
      status_id: string;
      initial_status: string;
      clicked_status: string;
      screenshot_required: boolean;
      nonce: string;
      page_sha256: string;
      redirects_allowed: false;
      final_url_must_equal: true;
      receipt: {
        path: string;
        sha256: string;
        implementation_sha256: string;
        pid: number;
        process_start_token: string;
        process_executable_path: string;
        process_command_sha256: string;
        process_cwd: string;
        controller_repository_head: string;
        launch: {
          controller_root: string;
          controller_repository_head: string;
          server_script_path: string;
          server_script_sha256: string;
          node_executable_path: string;
          cwd: string;
          requested_port: 0;
          expected_argv: string[];
          expected_argv_sha256: string;
          environment: Record<string, string>;
          environment_sha256: string;
        };
        lifecycle: {
          receipt_retained: true;
          auto_shutdown_at_expires_at: true;
        };
        started_at: string;
        expires_at: string;
        listener: {
          host: "127.0.0.1";
          port: number;
        };
        binding: {
          goal_id: string;
          role: CanaryRole;
          task_id: string | null;
        };
        binding_sha256: string;
      };
      endpoint_probe: {
        schema_version: 1;
        url: string;
        status_code: 200;
        remote_address: "127.0.0.1";
        remote_port: number;
        page_sha256: string;
        nonce: string;
        redirect_followed: false;
      };
    };
  };
};
type CanaryPlanOutput = {
  canary_plan: CanaryPlan;
  canary_plan_sha256: string;
};
type Fixture = {
  root: string;
  manifest: string;
  packets: Record<string, string>;
  protocol: Record<string, string>;
  policy?: string;
};
type FixtureOptions = {
  policyBody?: string;
};

const fixtures: Fixture[] = [];
type CanaryRuntime = {
  child: ReturnType<typeof spawn>;
  receiptPath: string;
  receipt: Record<string, unknown>;
};
const canaryRuntimes: CanaryRuntime[] = [];
const auxiliaryChildren: Array<ReturnType<typeof spawn>> = [];
let receiptSequence = 0;
const syncWaitBuffer = new Int32Array(new SharedArrayBuffer(4));

jest.setTimeout(30_000);

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function writeRepositoryFile(root: string, relative: string, body: string): void {
  const absolute = path.join(root, relative);
  mkdirSync(path.dirname(absolute), { recursive: true });
  writeFileSync(absolute, body);
}

function startBrowserCanary(
  fixture: Fixture,
  role: Exclude<CanaryRole, "CAPTAIN">,
  taskId: string | null,
  receiptParent: string = fixture.root,
): CanaryRuntime {
  receiptSequence += 1;
  const receiptPath = path.join(
    realpathSync(receiptParent),
    `browser-canary-receipt-${receiptSequence}.json`,
  );
  const args = [
    BROWSER_CANARY_SERVER,
    "serve",
    "--port",
    "0",
    "--receipt-file",
    receiptPath,
    "--goal",
    "goal-canary-plan",
    "--role",
    role,
    ...(taskId === null ? [] : ["--task", taskId]),
  ];
  const child = spawn(process.execPath, args, {
    cwd: realpathSync(ROOT),
    env: deriveServeEnvironment(process.env) as NodeJS.ProcessEnv,
    stdio: "ignore",
  });
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline && !existsSync(receiptPath)) {
    Atomics.wait(syncWaitBuffer, 0, 0, 20);
  }
  if (!existsSync(receiptPath)) {
    child.kill("SIGKILL");
    throw new Error(`browser canary server did not publish ${receiptPath}`);
  }
  const runtime = {
    child,
    receiptPath: realpathSync(receiptPath),
    receipt: JSON.parse(readFileSync(receiptPath, "utf8")) as
      Record<string, unknown>,
  };
  canaryRuntimes.push(runtime);
  return runtime;
}

function startAlternateNodeListener(fixture: Fixture): {
  child: ReturnType<typeof spawn>;
  port: number;
} {
  receiptSequence += 1;
  const scriptPath = path.join(
    fixture.root,
    `alternate-listener-${receiptSequence}.cjs`,
  );
  const readyPath = path.join(
    fixture.root,
    `alternate-listener-${receiptSequence}.json`,
  );
  writeFileSync(scriptPath, [
    "'use strict';",
    "const fs = require('fs');",
    "const http = require('http');",
    "const readyFile = process.argv[2];",
    "const server = http.createServer((_request, response) => {",
    "  response.writeHead(503, { Connection: 'close' });",
    "  response.end('alternate listener\\n');",
    "});",
    "server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {",
    "  const address = server.address();",
    "  const staging = `${readyFile}.tmp`;",
    "  fs.writeFileSync(staging, JSON.stringify({ port: address.port }), {",
    "    flag: 'wx',",
    "    mode: 0o600,",
    "  });",
    "  fs.renameSync(staging, readyFile);",
    "});",
    "const close = () => server.close(() => process.exit(0));",
    "process.on('SIGTERM', close);",
    "process.on('SIGINT', close);",
    "setTimeout(close, 15 * 60 * 1000);",
    "",
  ].join("\n"));
  const child = spawn(
    process.execPath,
    [scriptPath, readyPath],
    {
      cwd: realpathSync(fixture.root),
      stdio: "ignore",
    },
  );
  auxiliaryChildren.push(child);
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline && !existsSync(readyPath)) {
    Atomics.wait(syncWaitBuffer, 0, 0, 20);
  }
  if (!existsSync(readyPath) || !child.pid) {
    child.kill("SIGKILL");
    throw new Error("alternate Node listener did not become ready");
  }
  const ready = JSON.parse(readFileSync(readyPath, "utf8")) as {
    port: number;
  };
  return { child, port: ready.port };
}

function copyBrowserReceipt(
  fixture: Fixture,
  source: CanaryRuntime,
  overrides: Record<string, unknown> = {},
): string {
  receiptSequence += 1;
  const receiptPath = path.join(
    fixture.root,
    `browser-canary-receipt-${receiptSequence}.json`,
  );
  const receipt = {
    ...source.receipt,
    ...overrides,
  };
  writeFileSync(
    receiptPath,
    `${JSON.stringify(receipt, null, 2)}\n`,
    { mode: 0o600 },
  );
  chmodSync(receiptPath, 0o600);
  return realpathSync(receiptPath);
}

function createFixture(
  tasks: TaskSpec[],
  options: FixtureOptions = {},
): Fixture {
  const root = mkdtempSync(path.join(tmpdir(), "goal-canary-plan-"));
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: root });
  execFileSync("git", ["config", "user.name", "Canary Plan Test"], {
    cwd: root,
  });
  execFileSync("git", ["config", "user.email", "canary@example.invalid"], {
    cwd: root,
  });

  const protocol = {
    entry: "docs/planning/session-role-protocol.md",
    shared: "docs/planning/session-protocol/shared.md",
    foreman: "docs/planning/session-protocol/foreman.md",
    captain: "docs/planning/session-protocol/captain.md",
    role_kernel: "docs/planning/session-protocol/role-kernel.md",
  };
  for (const [name, relative] of Object.entries(protocol)) {
    writeRepositoryFile(root, relative, `# ${name}\n`);
  }
  const policy = options.policyBody === undefined
    ? undefined
    : "docs/planning/goals/canary/canary-policy.md";
  if (policy !== undefined) {
    writeRepositoryFile(root, policy, options.policyBody!);
  }

  const packets: Record<string, string> = {};
  const manifestTasks = tasks.map((task, index) => {
    const packetPath =
      `docs/planning/goals/canary/packets/${task.id}-r1.md`;
    const packetBody = `# ${task.id}\n`;
    writeRepositoryFile(root, packetPath, packetBody);
    packets[task.id] = packetPath;
    return {
      id: task.id,
      dependencies: [],
      integration_order: index + 1,
      risk_class: "STANDARD",
      packet: {
        revision: 1,
        path: packetPath,
        sha256: sha256(packetBody),
      },
      expected_write_set: [],
      conflict_domains: [],
      resource_requirements: task.requirements,
    };
  });
  const manifest = "docs/planning/goals/canary/manifest.json";
  writeRepositoryFile(
    root,
    manifest,
    `${JSON.stringify({
      schema_version: 1,
      goal_id: "goal-canary-plan",
      mode: "shadow",
      repository: {
        name_with_owner: "example/repository",
        base_branch: "main",
      },
      base_head: "1".repeat(40),
      protocol,
      ...(policy === undefined
        ? {}
        : {
          worker_canary_bootstrap: {
            protocol: "goalctl-worker-canary-bootstrap-v1",
            policy: {
              path: policy,
              sha256: sha256(options.policyBody!),
            },
          },
        }),
      tasks: manifestTasks,
    }, null, 2)}\n`,
  );
  execFileSync("git", ["add", "."], { cwd: root });
  execFileSync("git", ["commit", "-qm", "fixture"], { cwd: root });
  const fixture = { root, manifest, packets, protocol, policy };
  fixtures.push(fixture);
  return fixture;
}

function plan(
  fixture: Fixture,
  role: CanaryRole,
  task?: string,
  browserCanaryReceipt?: string,
): CanaryPlanOutput {
  const result = goalCommand([
    "canary-plan",
    "--manifest",
    fixture.manifest,
    "--role",
    role,
    ...(task ? ["--task", task] : []),
    ...(browserCanaryReceipt
      ? ["--browser-canary-receipt", browserCanaryReceipt]
      : []),
    "--json",
  ], fixture.root);
  expect(result.exitCode).toBe(0);
  expect(result.value.canary_plan_sha256)
    .toBe(hashObject(result.value.canary_plan));
  return result.value;
}

async function stopCanaryRuntime(runtime: CanaryRuntime): Promise<void> {
  await stopChild(runtime.child);
}

async function stopChild(
  child: ReturnType<typeof spawn>,
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  const exited = once(child, "exit").then(() => undefined);
  child.kill("SIGTERM");
  await Promise.race([
    exited,
    new Promise((resolve) => setTimeout(resolve, 2_000)),
  ]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await exited;
  }
}

afterEach(async () => {
  while (canaryRuntimes.length > 0) {
    await stopCanaryRuntime(canaryRuntimes.pop()!);
  }
  while (auxiliaryChildren.length > 0) {
    await stopChild(auxiliaryChildren.pop()!);
  }
  while (fixtures.length > 0) {
    rmSync(fixtures.pop()!.root, { recursive: true, force: true });
  }
});

describe("goalctl canary-plan", () => {
  test("empty resource requirements produce a headless worker plan", () => {
    const fixture = createFixture([
      { id: "TASK-HEADLESS", requirements: [] },
    ]);
    const output = plan(fixture, "DEV", "TASK-HEADLESS");

    expect(output.canary_plan).toMatchObject({
      role: "DEV",
      task_id: "TASK-HEADLESS",
      browser: {
        decision: "NOT_REQUIRED",
        matched_requirements: [],
      },
    });
    expect(output.canary_plan.required_probes)
      .not.toContain("BROWSER_LOCALHOST_OPEN_READ_CLICK_SCREENSHOT");
    expect(output.canary_plan.manifest.path).toBe(fixture.manifest);
    expect(output.canary_plan.manifest.sha256)
      .toBe(sha256(readFileSync(path.join(fixture.root, fixture.manifest), "utf8")));
  });

  test("absolute argv and POSIX shell replay preserve a hostile split-head worktree path exactly", () => {
    const fixture = createFixture([
      { id: "TASK-SPLIT-HEAD", requirements: [] },
    ]);
    const hostileWorktree =
      `${fixture.root} space ' $(touch replay-injected) ;`;
    renameSync(fixture.root, hostileWorktree);
    fixture.root = hostileWorktree;
    const shellExecutionCwd = path.join(
      fixture.root,
      "shell-execution-cwd",
    );
    mkdirSync(shellExecutionCwd, { mode: 0o700 });
    const fakeBin = path.join(shellExecutionCwd, "fake-bin");
    const fakePathMarker = path.join(shellExecutionCwd, "fake-path-ran");
    const preloadMarker = path.join(shellExecutionCwd, "preload-ran");
    const preloadFile = path.join(shellExecutionCwd, "preload.cjs");
    const shellStartupFile = path.join(
      shellExecutionCwd,
      "shell-startup.sh",
    );
    mkdirSync(fakeBin, { mode: 0o700 });
    writeFileSync(
      preloadFile,
      `require("fs").writeFileSync(${JSON.stringify(preloadMarker)}, "bad");\n`,
    );
    writeFileSync(
      shellStartupFile,
      `/usr/bin/printf bad > ${JSON.stringify(fakePathMarker)}\n`,
    );
    for (const executable of ["node", "dirname"]) {
      const fakeExecutable = path.join(fakeBin, executable);
      writeFileSync(
        fakeExecutable,
        `#!/bin/sh\nprintf bad > ${JSON.stringify(fakePathMarker)}\nexit 99\n`,
      );
      chmodSync(fakeExecutable, 0o755);
    }
    const controllerEntrypoint = realpathSync(
      path.join(ROOT, "scripts", "goalctl.js"),
    );
    const repositoryWorktree = realpathSync(fixture.root);
    const canaryArgs = [
      "canary-plan",
      "--repository-worktree",
      repositoryWorktree,
      "--manifest",
      fixture.manifest,
      "--role",
      "DEV",
      "--task",
      "TASK-SPLIT-HEAD",
      "--json",
    ];
    const first = JSON.parse(execFileSync(
      CANARY_PLAN_LAUNCHER,
      [...EXPLICIT_NODE_ARGS, ...canaryArgs.slice(1)],
      {
        cwd: tmpdir(),
        encoding: "utf8",
        env: {
          ...process.env,
          NODE_OPTIONS: `--require=${preloadFile}`,
          NODE_PATH: shellExecutionCwd,
          PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
          BASH_ENV: shellStartupFile,
          ENV: shellStartupFile,
          SHELLOPTS: "xtrace",
          PS4: `$('/usr/bin/printf' bad > ${JSON.stringify(fakePathMarker)})`,
          "BASH_FUNC_pwd%%":
            `() { /usr/bin/printf bad > ${JSON.stringify(fakePathMarker)}; }`,
          "BASH_FUNC_cd%%":
            `() { /usr/bin/printf bad > ${JSON.stringify(fakePathMarker)}; }`,
          "BASH_FUNC_test%%":
            `() { /usr/bin/printf bad > ${JSON.stringify(fakePathMarker)}; }`,
          "BASH_FUNC_echo%%":
            `() { /usr/bin/printf bad > ${JSON.stringify(fakePathMarker)}; }`,
          GIT_OPTIONAL_LOCKS: "0",
          GIT_TERMINAL_PROMPT: "0",
        },
      },
    )) as CanaryPlanOutput;
    const replay = JSON.parse(execFileSync(
      first.canary_plan.replay.node_executable,
      first.canary_plan.replay.argv,
      {
        cwd: path.dirname(first.canary_plan.repository_worktree),
        encoding: "utf8",
        env: {
          ...process.env,
          GIT_OPTIONAL_LOCKS: "0",
          GIT_TERMINAL_PROMPT: "0",
        },
      },
    )) as CanaryPlanOutput;
    const shellReplay = JSON.parse(execFileSync(
      "/bin/sh",
      ["-c", first.canary_plan.replay.shell_command],
      {
        cwd: shellExecutionCwd,
        encoding: "utf8",
        env: {
          ...process.env,
          GIT_OPTIONAL_LOCKS: "0",
          GIT_TERMINAL_PROMPT: "0",
          NODE_OPTIONS: "--require=/definitely/not/a/replay-module.cjs",
          NODE_PATH: "/definitely/not/a/replay-node-path",
          DYLD_FAKE_REPLAY_INJECTION: "must-not-survive-env-i",
        },
      },
    )) as CanaryPlanOutput;

    const controllerHead = execFileSync(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: ROOT, encoding: "utf8" },
    ).trim();
    const frozenGoalHead = execFileSync(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: fixture.root, encoding: "utf8" },
    ).trim();
    expect(controllerHead).not.toBe(frozenGoalHead);
    expect(first).toEqual(replay);
    expect(first).toEqual(shellReplay);
    expect(existsSync(path.join(shellExecutionCwd, "replay-injected")))
      .toBe(false);
    expect(existsSync(fakePathMarker)).toBe(false);
    expect(existsSync(preloadMarker)).toBe(false);
    expect(first.canary_plan.replay.shell_command)
      .toContain("'\"'\"'");
    expect(first.canary_plan.replay.shell_command)
      .toContain("$(touch replay-injected)");
    expect(first.canary_plan.replay.shell_command)
      .toMatch(/^'\/usr\/bin\/env' '-i' /);
    const replayEnvironment = {
      schema_version: 1 as const,
      executable: "/usr/bin/env",
      clear_inherited: true as const,
      assignments: [
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_NO_REPLACE_OBJECTS=1",
        "GIT_OPTIONAL_LOCKS=0",
        "GIT_TERMINAL_PROMPT=0",
        "LANG=C",
        "LC_ALL=C",
        "PATH=/usr/bin:/bin:/usr/sbin",
        "TZ=UTC",
      ],
    };
    expect(first.canary_plan).toMatchObject({
      controller: {
        root: realpathSync(ROOT),
        entrypoint: controllerEntrypoint,
        repository_head: controllerHead,
        closure_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      },
      repository_worktree: repositoryWorktree,
      repository_head: frozenGoalHead,
      repository: {
        name_with_owner: "example/repository",
        base_branch: "main",
      },
      capability_targets: {
        github_app: {
          repository: "example/repository",
          pull_request: null,
          pre_registration_scope: "REPOSITORY_ONLY",
        },
      },
      replay: {
        node_executable: realpathSync(process.execPath),
        argv: [controllerEntrypoint, ...canaryArgs],
        environment: {
          ...replayEnvironment,
          sha256: hashObject(replayEnvironment),
        },
        shell_command: expect.any(String),
      },
    });
    expect(first.canary_plan_sha256)
      .toBe(hashObject(first.canary_plan));
  });

  test("generator rejects inherited Node, preload, loader, and inspect injection", () => {
    const fixture = createFixture([
      { id: "TASK-RUNTIME-INJECTION", requirements: [] },
    ]);
    const options = {
      manifestFile: fixture.manifest,
      role: "DEV" as const,
      taskId: "TASK-RUNTIME-INJECTION",
    };
    const environmentCases = [
      ["NODE_OPTIONS", "--require=/tmp/hostile-preload.cjs"],
      ["NODE_PATH", "/tmp/hostile-node-path"],
      ["LD_PRELOAD", "/tmp/hostile-native-preload.so"],
      ["DYLD_INSERT_LIBRARIES", "/tmp/hostile-dylib.dylib"],
    ] as const;
    for (const [key, value] of environmentCases) {
      const previous = process.env[key];
      try {
        process.env[key] = value;
        expect(() => canaryPlan(fixture.root, options))
          .toThrow(/runtime 注入|UNSAFE_NODE_RUNTIME/);
      } finally {
        if (previous === undefined) delete process.env[key];
        else process.env[key] = previous;
      }
    }

    const originalExecArgv = [...process.execArgv];
    try {
      process.execArgv.splice(
        0,
        process.execArgv.length,
        ...originalExecArgv,
        "--inspect=127.0.0.1:9229",
      );
      expect(() => canaryPlan(fixture.root, options))
        .toThrow(/runtime 注入|UNSAFE_NODE_RUNTIME/);
    } finally {
      process.execArgv.splice(
        0,
        process.execArgv.length,
        ...originalExecArgv,
      );
    }
  });

  test("Browser is role-scoped and FOREMAN uses an any-task projection", () => {
    const fixture = createFixture([
      {
        id: "TASK-DEV-UI",
        requirements: [
          {
            kind: "BROWSER_PROFILE",
            id: "dev-profile",
            access: "EXCLUSIVE",
            roles: ["DEV"],
          },
        ],
      },
      {
        id: "TASK-REVIEW-UI",
        requirements: [
          {
            kind: "WINDOW",
            id: "review-window",
            access: "EXCLUSIVE",
            roles: ["REVIEW"],
          },
        ],
      },
      {
        id: "TASK-RECEIPT-UI",
        requirements: [
          {
            kind: "WINDOW",
            id: "receipt-window",
            access: "EXCLUSIVE",
            roles: ["RECEIPT"],
          },
        ],
      },
    ]);
    const devCanary = startBrowserCanary(
      fixture,
      "DEV",
      "TASK-DEV-UI",
    );
    const reviewCanary = startBrowserCanary(
      fixture,
      "REVIEW",
      "TASK-REVIEW-UI",
    );
    const receiptCanary = startBrowserCanary(
      fixture,
      "RECEIPT",
      "TASK-RECEIPT-UI",
    );
    const foremanCanary = startBrowserCanary(fixture, "FOREMAN", null);

    const dev = plan(
      fixture,
      "DEV",
      "TASK-DEV-UI",
      devCanary.receiptPath,
    ).canary_plan;
    expect(dev.browser.decision).toBe("REQUIRED");
    expect(plan(fixture, "REVIEW", "TASK-DEV-UI").canary_plan.browser.decision)
      .toBe("NOT_REQUIRED");
    expect(plan(fixture, "RECEIPT", "TASK-REVIEW-UI").canary_plan.browser.decision)
      .toBe("NOT_REQUIRED");
    const review = plan(
      fixture,
      "REVIEW",
      "TASK-REVIEW-UI",
      reviewCanary.receiptPath,
    ).canary_plan;
    expect(review.browser.decision).toBe("REQUIRED");
    const receipt = plan(
      fixture,
      "RECEIPT",
      "TASK-RECEIPT-UI",
      receiptCanary.receiptPath,
    ).canary_plan;
    expect(receipt.browser.decision).toBe("REQUIRED");

    const foreman = plan(
      fixture,
      "FOREMAN",
      undefined,
      foremanCanary.receiptPath,
    ).canary_plan;
    expect(foreman.browser.decision).toBe("REQUIRED");
    expect(foreman.required_probes)
      .toContain("GITHUB_APP_REPOSITORY_READ");
    expect(foreman.required_probes.at(-1))
      .toBe("GITHUB_APP_REPOSITORY_READ");
    expect(foreman.required_probes.indexOf(
      "BROWSER_LOCALHOST_OPEN_READ_CLICK_SCREENSHOT",
    )).toBeLessThan(
      foreman.required_probes.indexOf("GITHUB_APP_REPOSITORY_READ"),
    );
    for (const rolePlan of [dev, review, receipt]) {
      expect(rolePlan.required_probes.at(-1))
        .toBe("GITHUB_APP_REPOSITORY_READ");
      expect(rolePlan.required_probes.indexOf(
        "BROWSER_LOCALHOST_OPEN_READ_CLICK_SCREENSHOT",
      )).toBeLessThan(
        rolePlan.required_probes.indexOf("GITHUB_APP_REPOSITORY_READ"),
      );
    }
    expect(foreman.browser.target).toEqual(expect.objectContaining({
      contract_version: 1,
      expected_title: "Codex Capability Canary",
      button_id: "codex-capability-canary-button",
      status_id: "codex-capability-canary-status",
      initial_status: "READY",
      clicked_status: "CLICKED",
      screenshot_required: true,
      redirects_allowed: false,
      final_url_must_equal: true,
    }));
    expect(foreman.browser.target?.page_sha256).toBe(
      sha256(buildCanaryPage(foreman.browser.target!.nonce)),
    );
    expect(foreman.browser.target?.receipt.binding).toEqual({
      goal_id: "goal-canary-plan",
      role: "FOREMAN",
      task_id: null,
    });
    expect(foreman.browser.target?.receipt).toMatchObject({
      process_cwd: realpathSync(ROOT),
      controller_repository_head: foreman.controller.repository_head,
      lifecycle: {
        receipt_retained: true,
        auto_shutdown_at_expires_at: true,
      },
      launch: {
        controller_root: realpathSync(ROOT),
        controller_repository_head: foreman.controller.repository_head,
        server_script_path: realpathSync(BROWSER_CANARY_SERVER),
        server_script_sha256:
          foreman.controller.modules[
            "scripts/goal-control/browser-canary-server.js"
          ],
        node_executable_path: realpathSync(process.execPath),
        cwd: realpathSync(ROOT),
        requested_port: 0,
        expected_argv: [
          realpathSync(process.execPath),
          realpathSync(BROWSER_CANARY_SERVER),
          "serve",
          "--port",
          "0",
          "--receipt-file",
          foremanCanary.receiptPath,
          "--goal",
          "goal-canary-plan",
          "--role",
          "FOREMAN",
        ],
        expected_argv_sha256:
          expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        environment: deriveServeEnvironment(process.env),
        environment_sha256:
          expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      },
    });
    expect(foreman.browser.target?.endpoint_probe).toMatchObject({
      status_code: 200,
      remote_address: "127.0.0.1",
      page_sha256: foreman.browser.target?.page_sha256,
      nonce: foreman.browser.target?.nonce,
      redirect_followed: false,
    });
    expect(foreman.controller).toEqual({
      root: realpathSync(ROOT),
      entrypoint: realpathSync(path.join(ROOT, "scripts", "goalctl.js")),
      repository_head: execFileSync(
        "git",
        ["rev-parse", "HEAD"],
        { cwd: ROOT, encoding: "utf8" },
      ).trim(),
      decoder_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      closure_sha256: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      modules: {
        "scripts/goalctl.js":
          sha256(readFileSync(path.join(ROOT, "scripts", "goalctl.js"))),
        "scripts/goal-control/browser-canary-probe.js":
          sha256(readFileSync(path.join(
            ROOT,
            "scripts",
            "goal-control",
            "browser-canary-probe.js",
          ))),
        "scripts/goal-control/browser-canary-server.js":
          sha256(readFileSync(path.join(
            ROOT,
            "scripts",
            "goal-control",
            "browser-canary-server.js",
          ))),
        "scripts/goal-control/canary-controller-attestation.js":
          sha256(readFileSync(path.join(
            ROOT,
            "scripts",
            "goal-control",
            "canary-controller-attestation.js",
          ))),
        "scripts/goal-control/canary-plan.js":
          sha256(readFileSync(path.join(
            ROOT,
            "scripts",
            "goal-control",
            "canary-plan.js",
          ))),
        "scripts/goal-control/cli.js":
          sha256(readFileSync(path.join(
            ROOT,
            "scripts",
            "goal-control",
            "cli.js",
        ))),
      },
    });
    expect(foreman.repository_worktree).toBe(realpathSync(fixture.root));
    expect(foreman.repository_head).toBe(execFileSync(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: fixture.root, encoding: "utf8" },
    ).trim());
    expect(foreman.browser.matched_requirements).toEqual([
      expect.objectContaining({
        task_id: "TASK-DEV-UI",
        kind: "BROWSER_PROFILE",
        roles: ["DEV"],
      }),
      expect.objectContaining({
        task_id: "TASK-REVIEW-UI",
        kind: "WINDOW",
        roles: ["REVIEW"],
      }),
      expect.objectContaining({
        task_id: "TASK-RECEIPT-UI",
        kind: "WINDOW",
        roles: ["RECEIPT"],
      }),
    ]);

    const captain = plan(fixture, "CAPTAIN", "TASK-DEV-UI").canary_plan;
    expect(captain.browser.decision).toBe("NOT_REQUIRED");
    expect(captain.required_probes)
      .not.toContain("BROWSER_LOCALHOST_OPEN_READ_CLICK_SCREENSHOT");
  });

  test("PORT and EXECUTABLE alone never imply Browser", () => {
    const fixture = createFixture([
      {
        id: "TASK-PORT-ONLY",
        requirements: [
          {
            kind: "PORT",
            id: "preview-port",
            access: "EXCLUSIVE",
            roles: ["DEV"],
          },
          {
            kind: "EXECUTABLE",
            id: "preview-runtime",
            access: "EXCLUSIVE",
            roles: ["DEV"],
          },
        ],
      },
    ]);

    expect(plan(fixture, "DEV", "TASK-PORT-ONLY").canary_plan.browser.decision)
      .toBe("NOT_REQUIRED");
    expect(plan(fixture, "FOREMAN").canary_plan.browser.decision)
      .toBe("NOT_REQUIRED");
  });

  test("pre-registration gh and GitHub App probes are repository-only without a PR target", () => {
    const fixture = createFixture([
      { id: "TASK-REPOSITORY-ONLY", requirements: [] },
    ]);
    const rolePlans = {
      FOREMAN: plan(fixture, "FOREMAN").canary_plan,
      CAPTAIN: plan(
        fixture,
        "CAPTAIN",
        "TASK-REPOSITORY-ONLY",
      ).canary_plan,
      DEV: plan(
        fixture,
        "DEV",
        "TASK-REPOSITORY-ONLY",
      ).canary_plan,
      REVIEW: plan(
        fixture,
        "REVIEW",
        "TASK-REPOSITORY-ONLY",
      ).canary_plan,
      RECEIPT: plan(
        fixture,
        "RECEIPT",
        "TASK-REPOSITORY-ONLY",
      ).canary_plan,
    };

    expect(rolePlans.CAPTAIN.required_probes).toEqual([
      "TASK_CREATE_SEND_WAIT_ARCHIVE",
      "GH_REPOSITORY_PERMISSION",
      "GIT_REMOTE_READ",
      "GOALCTL",
      "RESOURCECTL",
      "GITHUB_APP_REPOSITORY_READ",
    ]);
    expect(rolePlans.FOREMAN.required_probes).toEqual([
      "TASK_CREATE_SEND_WAIT_ARCHIVE",
      "GH_REPOSITORY_MERGE_PERMISSION",
      "GIT_REMOTE_READ",
      "GOALCTL",
      "GITHUB_APP_REPOSITORY_READ",
    ]);
    expect(rolePlans.DEV.required_probes).toEqual([
      "GIT_WORKTREE_WRITE",
      "GH_REPOSITORY_PERMISSION",
      "GIT_REMOTE_READ",
      "GIT_PUSH_DRY_RUN",
      "GITHUB_APP_REPOSITORY_READ",
    ]);
    expect(rolePlans.REVIEW.required_probes).toEqual([
      "GH_REPOSITORY_PERMISSION",
      "GIT_REMOTE_READ",
      "GITHUB_APP_REPOSITORY_READ",
    ]);
    expect(rolePlans.RECEIPT.required_probes).toEqual([
      "GH_REPOSITORY_PERMISSION",
      "GIT_REMOTE_READ",
      "GITHUB_APP_REPOSITORY_READ",
    ]);
    for (const rolePlan of Object.values(rolePlans)) {
      expect(rolePlan.required_probes.some(
        (probe) => probe.startsWith("GH_PR_"),
      )).toBe(false);
      expect(rolePlan.capability_targets.github_app).toEqual({
        repository: "example/repository",
        pull_request: null,
        pre_registration_scope: "REPOSITORY_ONLY",
        operation_contract: {
          schema_version: 1,
          capability_plane: "GITHUB_APP_CONNECTOR",
          semantic_operation: "REPOSITORY_METADATA_READ",
          target_kind: "REPOSITORY",
          repository: "example/repository",
          read_only: true,
          interaction: "NON_INTERACTIVE",
          success_repository_identity_must_equal: true,
          forbidden_substitute_operations: [
            "COMMIT_READ",
            "PULL_REQUEST_READ",
            "FILE_READ",
            "ISSUE_READ",
          ],
        },
      });
      expect(rolePlan.required_probes.at(-1))
        .toBe("GITHUB_APP_REPOSITORY_READ");
      expect(rolePlan.required_probes).toContain("GIT_REMOTE_READ");
      expect(rolePlan.canary_policy).toBeNull();
      expect(rolePlan.probe_evaluation.known_limitations).toEqual([]);
    }
  });

  test("emits a policy-bound provisional contract for only the exact repository metadata 404", () => {
    const policyBody = [
      "# Canary policy",
      "",
      WORKER_CANARY_BOOTSTRAP_POLICY_MARKER,
      GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
      "",
    ].join("\n");
    const fixture = createFixture(
      [{ id: "TASK-POLICY", requirements: [] }],
      { policyBody },
    );
    const captain = plan(
      fixture,
      "CAPTAIN",
      "TASK-POLICY",
    ).canary_plan;

    expect(captain.canary_policy).toEqual({
      path: fixture.policy,
      sha256: sha256(policyBody),
      known_limitations: [{
        id: "github_app_private_repo_404-v1",
        policy_marker: GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
      }],
    });
    expect(captain.probe_evaluation).toMatchObject({
      replay_must_pass_before_probes: true,
      required_probe_order: "DECLARED_ARRAY_ORDER",
      session_scope: "CURRENT_ACTUAL_SESSION_ONLY",
      missing_or_skipped_probe_disposition: "CANARY_FAIL",
      non_matching_result_disposition: "CANARY_FAIL",
      final_pass_condition:
        "EVERY_REQUIRED_PROBE_PASS_OR_FINALIZED_KNOWN_LIMITATION",
      known_limitations: [{
        id: "github_app_private_repo_404-v1",
        probe: "GITHUB_APP_REPOSITORY_READ",
        policy_marker: GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
        exact_match: {
          semantic_operation: "REPOSITORY_METADATA_READ",
          target_kind: "REPOSITORY",
          repository: "example/repository",
          result_fingerprint: "404/repo_not_found",
          allow_dialog: false,
          authentication_prompt: false,
        },
        provisional_disposition: "PROVISIONAL_KNOWN_LIMITATION",
        compensation_probes: captain.required_probes.slice(0, -1),
        terminal_mismatch_classes: [
          "ALLOW_DIALOG",
          "AUTHENTICATION_PROMPT",
          "TOKEN_REQUEST",
          "HTTP_401",
          "HTTP_403",
          "TIMEOUT",
          "NETWORK_ERROR",
          "WRONG_REPOSITORY",
          "WRONG_OPERATION",
          "DIFFERENT_FINGERPRINT",
        ],
        finalization_condition:
          "ALL_LISTED_COMPENSATION_PROBES_PASS_CURRENT_SESSION",
        final_disposition: "KNOWN_CONNECTOR_LIMITATION",
      }],
    });
    expect(captain.required_probes.at(-1))
      .toBe("GITHUB_APP_REPOSITORY_READ");
  });

  test("keeps a legacy bootstrap policy bound without retroactively granting the 404 limitation", () => {
    const policyBody = [
      "# Legacy bootstrap policy",
      "",
      WORKER_CANARY_BOOTSTRAP_POLICY_MARKER,
      "",
    ].join("\n");
    const fixture = createFixture(
      [{ id: "TASK-LEGACY-POLICY", requirements: [] }],
      { policyBody },
    );
    const captain = plan(
      fixture,
      "CAPTAIN",
      "TASK-LEGACY-POLICY",
    ).canary_plan;

    expect(captain.canary_policy).toEqual({
      path: fixture.policy,
      sha256: sha256(policyBody),
      known_limitations: [],
    });
    expect(captain.probe_evaluation.known_limitations).toEqual([]);
  });

  test("revalidates the bootstrap marker from the same stable committed policy bytes", () => {
    const knownLimitationWithoutBootstrap = Buffer.from([
      "# Invalid policy",
      "",
      GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
      "",
    ].join("\n"));

    expect(() => canaryPolicyKnownLimitations(
      knownLimitationWithoutBootstrap,
    )).toThrow(/stable committed canary policy.*worker bootstrap marker/);
  });

  test.each([
    [
      "unknown",
      "GitHub-App-Known-Limitation: github_app_private_repo_404-v2",
    ],
    [
      "duplicate",
      [
        GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
        GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
      ].join("\n"),
    ],
  ])("rejects %s GitHub App limitation policy markers", (_name, marker) => {
    const fixture = createFixture(
      [{ id: "TASK-POLICY-INVALID", requirements: [] }],
      {
        policyBody: [
          WORKER_CANARY_BOOTSTRAP_POLICY_MARKER,
          marker,
          "",
        ].join("\n"),
      },
    );

    expect(() => plan(
      fixture,
      "CAPTAIN",
      "TASK-POLICY-INVALID",
    )).toThrow(/不支持的.*marker|必须至多出现一次/);
  });

  test("rejects dirty manifest-bound canary policy bytes", () => {
    const policyBody = [
      WORKER_CANARY_BOOTSTRAP_POLICY_MARKER,
      GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
      "",
    ].join("\n");
    const fixture = createFixture(
      [{ id: "TASK-POLICY-DIRTY", requirements: [] }],
      { policyBody },
    );
    writeFileSync(
      path.join(fixture.root, fixture.policy!),
      `${policyBody}dirty\n`,
    );

    expect(() => plan(
      fixture,
      "CAPTAIN",
      "TASK-POLICY-DIRTY",
    )).toThrow(/GOAL_INPUT_DIRTY|policy/);
  });

  test("Browser receipt is live-listener-bound, fresh, role-bound, and forbidden for headless plans", async () => {
    const browser = createFixture([
      {
        id: "TASK-BROWSER",
        requirements: [
          {
            kind: "WINDOW",
            id: "browser-window",
            access: "EXCLUSIVE",
            roles: ["DEV"],
          },
        ],
      },
    ]);
    expect(() => plan(browser, "DEV", "TASK-BROWSER"))
      .toThrow(/CANARY_PLAN_BROWSER_TARGET_REQUIRED|browser-canary-receipt/);
    const live = startBrowserCanary(browser, "DEV", "TASK-BROWSER");
    for (const unsafe of [
      "http://localhost:43119/codex-capability-canary",
      "https://127.0.0.1:43119/codex-capability-canary",
      "http://127.0.0.1:43119/other",
      "http://127.0.0.1:43119/codex-capability-canary?token=secret",
      "http://user@127.0.0.1:43119/codex-capability-canary",
      "http://127.0.0.1:80/codex-capability-canary",
      "http://127.0.0.1:70000/codex-capability-canary",
      "http://127.0.0.1:43119/%63odex-capability-canary",
      "http://127.0.0.1:43119/codex-capability-canary/",
      "http://[::1]:43119/codex-capability-canary",
    ]) {
      const unsafeReceipt = copyBrowserReceipt(browser, live, { url: unsafe });
      expect(() => plan(browser, "DEV", "TASK-BROWSER", unsafeReceipt))
        .toThrow(/CANARY_PLAN_BROWSER_TARGET_INVALID|receipt URL/);
    }
    const currentPidForgery = {
      pid: process.pid,
      process_start_token: processStartToken(process.pid),
      process_executable_path: processExecutablePath(process.pid),
      process_command_sha256: processCommandSha256(process.pid),
    };
    const expiredStartedAt = new Date(Date.now() - 20 * 60 * 1000);
    for (const invalid of [
      { page_sha256: sha256("not the deterministic canary page") },
      { implementation_sha256: `sha256:${"00".repeat(32)}` },
      currentPidForgery,
      { nonce: "AA".repeat(32) },
      {
        binding: {
          goal_id: "goal-canary-plan",
          role: "REVIEW",
          task_id: "TASK-BROWSER",
        },
      },
      {
        started_at: expiredStartedAt.toISOString(),
        expires_at: new Date(
          expiredStartedAt.getTime() + 15 * 60 * 1000,
        ).toISOString(),
      },
      { unexpected: true },
    ]) {
      const invalidReceipt = copyBrowserReceipt(browser, live, invalid);
      expect(() => plan(browser, "DEV", "TASK-BROWSER", invalidReceipt))
        .toThrow(
          /CANARY_PLAN_BROWSER_RECEIPT_INVALID|字段集合不匹配|receipt .*不匹配|identity|校验失败/,
        );
    }
    const liveListener = live.receipt.listener as {
      host: string;
      port: number;
    };
    const wrongPort = liveListener.port === 65_535
      ? liveListener.port - 1
      : liveListener.port + 1;
    const wrongListenerReceipt = copyBrowserReceipt(browser, live, {
      url: `http://127.0.0.1:${wrongPort}/codex-capability-canary`,
      listener: {
        host: "127.0.0.1",
        port: wrongPort,
      },
    });
    expect(() => plan(
      browser,
      "DEV",
      "TASK-BROWSER",
      wrongListenerReceipt,
    )).toThrow(/CANARY_PLAN_BROWSER_RECEIPT_INVALID|listener|identity/);

    const publicReceipt = copyBrowserReceipt(browser, live);
    chmodSync(publicReceipt, 0o644);
    expect(() => plan(browser, "DEV", "TASK-BROWSER", publicReceipt))
      .toThrow(/CANARY_PLAN_BROWSER_RECEIPT_INVALID|0600/);

    const groupReadableParent = path.join(
      browser.root,
      "group-readable-receipt-parent",
    );
    mkdirSync(groupReadableParent, { mode: 0o750 });
    chmodSync(groupReadableParent, 0o750);
    const groupReadableReceipt = path.join(
      groupReadableParent,
      "browser-canary-receipt.json",
    );
    copyFileSync(live.receiptPath, groupReadableReceipt);
    chmodSync(groupReadableReceipt, 0o600);
    expect(() => plan(
      browser,
      "DEV",
      "TASK-BROWSER",
      realpathSync(groupReadableReceipt),
    )).toThrow(/0700|CANARY_PLAN_BROWSER_RECEIPT_INVALID/);

    const symlinkTarget = copyBrowserReceipt(browser, live);
    const symlinkReceipt = path.join(browser.root, "browser-canary-link.json");
    symlinkSync(symlinkTarget, symlinkReceipt);
    expect(() => plan(browser, "DEV", "TASK-BROWSER", symlinkReceipt))
      .toThrow(/CANARY_PLAN_BROWSER_RECEIPT_INVALID|ordinary file/);

    const headless = createFixture([
      { id: "TASK-HEADLESS-TARGET", requirements: [] },
    ]);
    const headlessReceipt = startBrowserCanary(
      headless,
      "DEV",
      "TASK-HEADLESS-TARGET",
    ).receiptPath;
    expect(() => plan(
      headless,
      "DEV",
      "TASK-HEADLESS-TARGET",
      headlessReceipt,
    )).toThrow(/CANARY_PLAN_BROWSER_TARGET_FORBIDDEN|NOT_REQUIRED/);

    const first = plan(
      browser,
      "DEV",
      "TASK-BROWSER",
      live.receiptPath,
    );
    const secondRuntime = startBrowserCanary(
      browser,
      "DEV",
      "TASK-BROWSER",
    );
    const second = plan(
      browser,
      "DEV",
      "TASK-BROWSER",
      secondRuntime.receiptPath,
    );
    expect(second.canary_plan.browser.target?.url)
      .toBe(secondRuntime.receipt.url);
    expect(second.canary_plan_sha256).not.toBe(first.canary_plan_sha256);

    const deadRuntime = startBrowserCanary(
      browser,
      "DEV",
      "TASK-BROWSER",
    );
    await stopCanaryRuntime(deadRuntime);
    expect(() => plan(
      browser,
      "DEV",
      "TASK-BROWSER",
      deadRuntime.receiptPath,
    )).toThrow(
      /CANARY_PLAN_BROWSER_RECEIPT_INVALID|LISTENER_INVALID|listener|identity|0600|单链接|ordinary file/,
    );
  });

  test("Browser receipt pathname swap cannot diverge from the opened inode", () => {
    const fixture = createFixture([
      {
        id: "TASK-RECEIPT-INODE",
        requirements: [
          {
            kind: "WINDOW",
            id: "browser-window",
            access: "EXCLUSIVE",
            roles: ["DEV"],
          },
        ],
      },
    ]);
    const runtime = startBrowserCanary(
      fixture,
      "DEV",
      "TASK-RECEIPT-INODE",
    );
    let swapped = false;
    expect(() => canaryPlan(
      fixture.root,
      {
        manifestFile: fixture.manifest,
        role: "DEV",
        taskId: "TASK-RECEIPT-INODE",
        browserCanaryReceipt: runtime.receiptPath,
      },
      {
        afterBrowserReceiptPathCapture: () => {
          if (swapped) return;
          swapped = true;
          const bytes = readFileSync(runtime.receiptPath);
          renameSync(runtime.receiptPath, `${runtime.receiptPath}.original`);
          writeFileSync(runtime.receiptPath, bytes, { mode: 0o600 });
          chmodSync(runtime.receiptPath, 0o600);
        },
      },
    )).toThrow(/GOAL_INPUT_RACE|实际打开 inode 不一致/);
    expect(swapped).toBe(true);
  });

  test("Browser receipt parent replacement cannot survive opened-fd revalidation", () => {
    const fixture = createFixture([
      {
        id: "TASK-RECEIPT-PARENT",
        requirements: [
          {
            kind: "WINDOW",
            id: "browser-window",
            access: "EXCLUSIVE",
            roles: ["DEV"],
          },
        ],
      },
    ]);
    const receiptParent = path.join(fixture.root, "private-receipt-parent");
    mkdirSync(receiptParent, { mode: 0o700 });
    chmodSync(receiptParent, 0o700);
    const runtime = startBrowserCanary(
      fixture,
      "DEV",
      "TASK-RECEIPT-PARENT",
      receiptParent,
    );
    let swapped = false;
    expect(() => canaryPlan(
      fixture.root,
      {
        manifestFile: fixture.manifest,
        role: "DEV",
        taskId: "TASK-RECEIPT-PARENT",
        browserCanaryReceipt: runtime.receiptPath,
      },
      {
        afterBrowserReceiptOpen: () => {
          if (swapped) return;
          swapped = true;
          const parent = path.dirname(runtime.receiptPath);
          const replacementSource = `${parent}.original`;
          renameSync(parent, replacementSource);
          mkdirSync(parent, { mode: 0o700 });
          chmodSync(parent, 0o700);
          const replacementReceipt = path.join(
            parent,
            path.basename(runtime.receiptPath),
          );
          writeFileSync(
            replacementReceipt,
            readFileSync(path.join(
              replacementSource,
              path.basename(runtime.receiptPath),
            )),
            { mode: 0o600 },
          );
          chmodSync(replacementReceipt, 0o600);
        },
      },
    )).toThrow(/GOAL_INPUT_RACE|parent identity|path inode/);
    expect(swapped).toBe(true);
  });

  test("an alternate Node listener cannot handcraft a canonical server receipt", () => {
    const fixture = createFixture([
      {
        id: "TASK-ALTERNATE-LISTENER",
        requirements: [
          {
            kind: "WINDOW",
            id: "browser-window",
            access: "EXCLUSIVE",
            roles: ["DEV"],
          },
        ],
      },
    ]);
    const canonical = startBrowserCanary(
      fixture,
      "DEV",
      "TASK-ALTERNATE-LISTENER",
    );
    const alternate = startAlternateNodeListener(fixture);
    const alternatePid = alternate.child.pid!;
    const forgedReceipt = copyBrowserReceipt(fixture, canonical, {
      url:
        `http://127.0.0.1:${alternate.port}/codex-capability-canary`,
      pid: alternatePid,
      process_start_token: processStartToken(alternatePid),
      process_executable_path: processExecutablePath(alternatePid),
      process_command_sha256: processCommandSha256(alternatePid),
      process_cwd: processCwd(alternatePid),
      listener: {
        host: "127.0.0.1",
        port: alternate.port,
      },
    });
    const forged = JSON.parse(readFileSync(forgedReceipt, "utf8")) as
      Record<string, unknown>;
    forged.launch = deriveServeIdentity({
      receiptFile: forgedReceipt,
      binding: {
        goal_id: "goal-canary-plan",
        role: "DEV",
        task_id: "TASK-ALTERNATE-LISTENER",
      },
    });
    writeFileSync(
      forgedReceipt,
      `${JSON.stringify(forged, null, 2)}\n`,
      { mode: 0o600 },
    );
    chmodSync(forgedReceipt, 0o600);

    expect(() => plan(
      fixture,
      "DEV",
      "TASK-ALTERNATE-LISTENER",
      forgedReceipt,
    )).toThrow(
      /CANARY_PLAN_BROWSER_RECEIPT_INVALID|server process|argv|command|identity/,
    );
  });

  test("A→B→A manifest swap cannot forge a headless decision", () => {
    const fixture = createFixture([
      {
        id: "TASK-RACE",
        requirements: [
          {
            kind: "BROWSER_PROFILE",
            id: "required-browser",
            access: "EXCLUSIVE",
            roles: ["DEV"],
          },
        ],
      },
    ]);
    const manifestFile = path.join(fixture.root, fixture.manifest);
    const committed = readFileSync(manifestFile, "utf8");
    const forged = JSON.parse(committed) as {
      tasks: Array<{ resource_requirements: ResourceRequirement[] }>;
    };
    forged.tasks[0].resource_requirements = [];

    const output = canaryPlan(
      fixture.root,
      {
        manifestFile: fixture.manifest,
        role: "DEV",
        taskId: "TASK-RACE",
        browserCanaryReceipt: startBrowserCanary(
          fixture,
          "DEV",
          "TASK-RACE",
        ).receiptPath,
      },
      {
        afterManifestCapture: () => {
          writeFileSync(manifestFile, `${JSON.stringify(forged, null, 2)}\n`);
        },
        afterManifestParse: () => {
          writeFileSync(manifestFile, committed);
        },
      },
    );

    expect(output.canary_plan.browser.decision).toBe("REQUIRED");
    expect(output.canary_plan.required_probes)
      .toContain("BROWSER_LOCALHOST_OPEN_READ_CLICK_SCREENSHOT");
  });

  test("A→B→A protocol/packet swaps cannot pass committed-input binding", () => {
    const fixture = createFixture([
      { id: "TASK-PROTOCOL-RACE", requirements: [] },
    ]);
    const protocolFile = path.join(fixture.root, fixture.protocol.shared);
    const committed = readFileSync(protocolFile, "utf8");

    expect(() => canaryPlan(
      fixture.root,
      {
        manifestFile: fixture.manifest,
        role: "DEV",
        taskId: "TASK-PROTOCOL-RACE",
      },
      {
        beforeManifestValidation: () => {
          writeFileSync(protocolFile, "# forged protocol bytes\n");
        },
        afterManifestValidation: () => {
          writeFileSync(protocolFile, committed);
        },
      },
    )).toThrow(/GOAL_INPUT_DIRTY|protocol\.shared hash/);

    const packetFixture = createFixture([
      { id: "TASK-PACKET-RACE", requirements: [] },
    ]);
    const packetFile = path.join(
      packetFixture.root,
      packetFixture.packets["TASK-PACKET-RACE"],
    );
    const packetBytes = readFileSync(packetFile, "utf8");
    expect(() => canaryPlan(
      packetFixture.root,
      {
        manifestFile: packetFixture.manifest,
        role: "DEV",
        taskId: "TASK-PACKET-RACE",
      },
      {
        beforeManifestValidation: () => {
          writeFileSync(packetFile, "# forged packet bytes\n");
        },
        afterManifestValidation: () => {
          writeFileSync(packetFile, packetBytes);
        },
      },
    )).toThrow(/PACKET_HASH_MISMATCH|packet hash/);
  });

  test("Git replace refs cannot substitute a headless commit for HEAD", () => {
    const fixture = createFixture([
      {
        id: "TASK-REPLACE",
        requirements: [
          {
            kind: "BROWSER_PROFILE",
            id: "required-browser",
            access: "EXCLUSIVE",
            roles: ["DEV"],
          },
        ],
      },
    ]);
    const manifestFile = path.join(fixture.root, fixture.manifest);
    const requiredManifest = JSON.parse(
      readFileSync(manifestFile, "utf8"),
    ) as {
      tasks: Array<{ resource_requirements: ResourceRequirement[] }>;
    };
    const requiredHead = execFileSync(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: fixture.root, encoding: "utf8" },
    ).trim();
    const headlessManifest = structuredClone(requiredManifest);
    headlessManifest.tasks[0].resource_requirements = [];
    writeFileSync(
      manifestFile,
      `${JSON.stringify(headlessManifest, null, 2)}\n`,
    );
    execFileSync("git", ["add", fixture.manifest], { cwd: fixture.root });
    execFileSync("git", ["commit", "-qm", "headless replacement"], {
      cwd: fixture.root,
    });
    const headlessHead = execFileSync(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: fixture.root, encoding: "utf8" },
    ).trim();
    execFileSync("git", ["checkout", "-q", "--detach", requiredHead], {
      cwd: fixture.root,
    });
    execFileSync("git", ["replace", requiredHead, headlessHead], {
      cwd: fixture.root,
    });

    expect(execFileSync(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: fixture.root, encoding: "utf8" },
    ).trim()).toBe(requiredHead);
    const replacedView = JSON.parse(execFileSync(
      "git",
      ["show", `HEAD:${fixture.manifest}`],
      { cwd: fixture.root, encoding: "utf8" },
    ) as string) as {
      tasks: Array<{ resource_requirements: ResourceRequirement[] }>;
    };
    expect(replacedView.tasks[0].resource_requirements).toEqual([]);

    expect(() => canaryPlan(
      fixture.root,
      {
        manifestFile: fixture.manifest,
        role: "DEV",
        taskId: "TASK-REPLACE",
      },
    )).toThrow(/CANARY_PLAN_REPLACE_REFS|禁止 Git replace refs/);
  });

  test("unknown/missing task and role/task mismatch fail closed", () => {
    const fixture = createFixture([
      { id: "TASK-KNOWN", requirements: [] },
    ]);

    expect(() => plan(fixture, "DEV"))
      .toThrow(/CANARY_PLAN_TASK_REQUIRED|必须指定 --task/);
    expect(() => plan(fixture, "CAPTAIN"))
      .toThrow(/CANARY_PLAN_TASK_REQUIRED|必须指定 --task/);
    expect(() => plan(fixture, "DEV", "TASK-UNKNOWN"))
      .toThrow(/CANARY_PLAN_UNKNOWN_TASK|不存在 task/);
    expect(() => plan(fixture, "FOREMAN", "TASK-KNOWN"))
      .toThrow(/CANARY_PLAN_ROLE_TASK_MISMATCH|不接受 --task/);
  });

  test("dirty or untracked controller dependencies fail closed", () => {
    const fixture = createFixture([
      { id: "TASK-CONTROLLER-DIRTY", requirements: [] },
    ]);
    writeRepositoryFile(
      fixture.root,
      "scripts/goal-control/untracked-controller-dependency.js",
      "'use strict';\n",
    );
    expect(() => assertControllerWorktreeClean(fixture.root))
      .toThrow(/CANARY_PLAN_CONTROLLER_DIRTY|必须全部来自当前 HEAD/);
  });

  test("controller closure rejects dirty bytes hidden by index flags", () => {
    for (const flag of ["--assume-unchanged", "--skip-worktree"]) {
      const fixture = createFixture([
        { id: `TASK-CONTROLLER-${flag}`, requirements: [] },
      ]);
      writeRepositoryFile(
        fixture.root,
        "scripts/goalctl.js",
        "'use strict';\nrequire('./goal-control/entry');\n",
      );
      writeRepositoryFile(
        fixture.root,
        "scripts/goal-control/entry.js",
        "'use strict';\nmodule.exports = 'committed';\n",
      );
      execFileSync(
        "git",
        ["add", "scripts/goalctl.js", "scripts/goal-control/entry.js"],
        { cwd: fixture.root },
      );
      execFileSync(
        "git",
        ["commit", "-qm", `controller fixture ${flag}`],
        { cwd: fixture.root },
      );
      expect(assertControllerWorktreeClean(fixture.root).closureSha256)
        .toMatch(/^sha256:[0-9a-f]{64}$/);

      const hiddenRelative = "scripts/goal-control/entry.js";
      execFileSync(
        "git",
        ["update-index", flag, hiddenRelative],
        { cwd: fixture.root },
      );
      writeFileSync(
        path.join(fixture.root, hiddenRelative),
        "'use strict';\nmodule.exports = 'hidden dirty bytes';\n",
      );
      expect(execFileSync(
        "git",
        ["status", "--porcelain=v1", "--", hiddenRelative],
        { cwd: fixture.root, encoding: "utf8" },
      )).toBe("");
      expect(() => assertControllerWorktreeClean(fixture.root))
        .toThrow(/index.*H flag|assume-unchanged|skip-worktree/);
    }
  });

  test("controller closure rejects a same-bytes hardlink alias", () => {
    const fixture = createFixture([
      { id: "TASK-CONTROLLER-HARDLINK", requirements: [] },
    ]);
    const relative = "scripts/goal-control/entry.js";
    writeRepositoryFile(
      fixture.root,
      "scripts/goalctl.js",
      "'use strict';\nrequire('./goal-control/entry');\n",
    );
    writeRepositoryFile(
      fixture.root,
      relative,
      "'use strict';\nmodule.exports = 'committed';\n",
    );
    execFileSync("git", ["add", "scripts/goalctl.js", relative], {
      cwd: fixture.root,
    });
    execFileSync("git", ["commit", "-qm", "controller hardlink fixture"], {
      cwd: fixture.root,
    });
    const tracked = path.join(fixture.root, relative);
    const alias = path.join(fixture.root, "controller-hardlink-alias.js");
    renameSync(tracked, alias);
    linkSync(alias, tracked);
    expect(execFileSync(
      "git",
      ["status", "--porcelain=v1", "--", relative],
      { cwd: fixture.root, encoding: "utf8" },
    )).toBe("");
    expect(() => assertControllerWorktreeClean(fixture.root))
      .toThrow(/单链接 ordinary file|CLOSURE_INVALID/);
  });

  test("dirty, uncommitted, and symlink committed inputs fail closed", () => {
    const dirty = createFixture([
      { id: "TASK-DIRTY", requirements: [] },
    ]);
    writeFileSync(
      path.join(dirty.root, dirty.manifest),
      `${readFileSync(path.join(dirty.root, dirty.manifest), "utf8")} `,
    );
    expect(() => plan(dirty, "DEV", "TASK-DIRTY"))
      .toThrow(/GOAL_INPUT_DIRTY|Git blob 不一致/);

    const dirtyProtocol = createFixture([
      { id: "TASK-DIRTY-PROTOCOL", requirements: [] },
    ]);
    writeFileSync(
      path.join(dirtyProtocol.root, dirtyProtocol.protocol.shared),
      "# changed shared protocol\n",
    );
    expect(() => plan(
      dirtyProtocol,
      "DEV",
      "TASK-DIRTY-PROTOCOL",
    )).toThrow(/GOAL_INPUT_DIRTY|Git blob 不一致/);

    const uncommitted = createFixture([
      { id: "TASK-UNCOMMITTED", requirements: [] },
    ]);
    const uncommittedManifest =
      "docs/planning/goals/canary/uncommitted.json";
    copyFileSync(
      path.join(uncommitted.root, uncommitted.manifest),
      path.join(uncommitted.root, uncommittedManifest),
    );
    uncommitted.manifest = uncommittedManifest;
    expect(() => plan(uncommitted, "DEV", "TASK-UNCOMMITTED"))
      .toThrow(/GOAL_INPUT_NOT_COMMITTED|尚未进入当前 HEAD/);

    const symlink = createFixture([
      { id: "TASK-SYMLINK", requirements: [] },
    ]);
    const manifestFile = path.join(symlink.root, symlink.manifest);
    const target = path.join(path.dirname(manifestFile), "manifest-target.json");
    copyFileSync(manifestFile, target);
    unlinkSync(manifestFile);
    symlinkSync("manifest-target.json", manifestFile);
    expect(() => plan(symlink, "DEV", "TASK-SYMLINK"))
      .toThrow(/GOAL_INPUT_SYMLINK|non symlink|非 symlink/);

    const packetSymlink = createFixture([
      { id: "TASK-PACKET-SYMLINK", requirements: [] },
    ]);
    const packetFile = path.join(
      packetSymlink.root,
      packetSymlink.packets["TASK-PACKET-SYMLINK"],
    );
    const packetTarget = path.join(path.dirname(packetFile), "packet-target.md");
    copyFileSync(packetFile, packetTarget);
    unlinkSync(packetFile);
    symlinkSync("packet-target.md", packetFile);
    expect(() => plan(
      packetSymlink,
      "DEV",
      "TASK-PACKET-SYMLINK",
    )).toThrow(/GOAL_INPUT_SYMLINK|non symlink|非 symlink/);
  });
});
