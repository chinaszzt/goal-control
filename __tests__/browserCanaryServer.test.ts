import { execFileSync, spawn } from "child_process";
import { createHash } from "crypto";
import { once } from "events";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "fs";
import http from "http";
import { tmpdir } from "os";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SERVER = path.join(
  ROOT,
  "scripts",
  "goal-control",
  "browser-canary-server.js",
);
const LAUNCHER = path.join(
  ROOT,
  "scripts",
  "goal-control",
  "browser-canary-launch.sh",
);
const EXPLICIT_NODE_ARGS = [
  "--node-executable",
  realpathSync(process.execPath),
];
const PROBE = path.join(
  ROOT,
  "scripts",
  "goal-control",
  "browser-canary-probe.js",
);
const RUNTIME = path.join(
  ROOT,
  "scripts",
  "goal-control",
  "browser-canary-runtime.js",
);
const nodeRequire = createRequire(import.meta.url);
const {
  CANARY_CONTRACT,
  RECEIPT_KIND,
  assertExactListenerInventory,
  assertLiveServerIdentity,
  buildCanaryPage,
  controllerRepositoryHead,
  deriveServeEnvironment,
  deriveServeIdentity,
  implementationSha256,
  inspectListenerInventory,
  parseCliArgs,
  processCommand,
  processCwd,
  processStartToken,
} = nodeRequire(SERVER) as {
  CANARY_CONTRACT: CanaryContract;
  RECEIPT_KIND: string;
  assertExactListenerInventory: (
    inventory: ListenerInventory,
    pid: number,
    port: number,
  ) => ListenerRecord;
  assertLiveServerIdentity: (
    receipt: ReadyReceipt,
    options: { receiptFile: string; binding: CanaryBinding },
  ) => {
    launch: LaunchIdentity;
    listener: ListenerRecord;
  };
  buildCanaryPage: (nonce: string) => string;
  controllerRepositoryHead: () => string;
  deriveServeEnvironment: (
    source?: Record<string, string | undefined>,
  ) => Record<string, string>;
  deriveServeIdentity: (options: {
    receiptFile: string;
    binding: CanaryBinding;
  }) => LaunchIdentity;
  implementationSha256: () => string;
  inspectListenerInventory: (port: number) => ListenerInventory;
  parseCliArgs: (argv: string[]) => {
    command: "launch" | "serve" | "stop";
    port: number | null;
    receiptFile: string;
    binding: CanaryBinding;
  };
  processCommand: (pid: number) => string | null;
  processCwd: (pid: number) => string | null;
  processStartToken: (pid: number) => string | null;
};
const { assertExactResponse: assertExactProbeResponse } = nodeRequire(PROBE) as {
  assertExactResponse: (
    response: {
      statusCode: number;
      headers: Record<string, string | undefined>;
      rawHeaders: string[];
      socket: {
        remoteAddress: string;
        remotePort: number;
      };
    },
    options: {
      port: number;
      expectedPageSha256: string;
      expectedNonce: string;
    },
    body: Buffer,
  ) => void;
};
const {
  assertCaptureStillInstalled,
  closeReceiptCapture,
  openPrivateJsonReceiptCapture,
} = nodeRequire(RUNTIME) as {
  assertCaptureStillInstalled: (
    receiptFile: string,
    capture: { descriptor: number | null },
  ) => void;
  closeReceiptCapture: (
    capture: { descriptor: number | null },
  ) => void;
  openPrivateJsonReceiptCapture: (
    receiptFile: string,
  ) => { descriptor: number | null };
};

type CanaryContract = {
  contract_version: number;
  expected_title: string;
  button_id: string;
  status_id: string;
  initial_status: string;
  clicked_status: string;
  screenshot_required: boolean;
};

type CanaryBinding = {
  goal_id: string;
  role: string;
  task_id: string | null;
};

type LaunchIdentity = {
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

type ListenerRecord = {
  pid: number;
  command: string;
  fd: string;
  protocol: string;
  name: string;
  tcp_state: string;
};

type ListenerInventory = {
  port: number;
  records: ListenerRecord[];
};

type ReadyReceipt = {
  schema_version: number;
  kind: string;
  binding: {
    goal_id: string;
    role: string;
    task_id: string | null;
  };
  binding_sha256: string;
  url: string;
  nonce: string;
  contract: CanaryContract;
  page_sha256: string;
  implementation_sha256: string;
  launch: LaunchIdentity;
  lifecycle: {
    receipt_retained: true;
    auto_shutdown_at_expires_at: true;
  };
  pid: number;
  process_start_token: string;
  process_executable_path: string;
  process_command_sha256: string;
  process_cwd: string;
  started_at: string;
  expires_at: string;
  listener: {
    host: string;
    port: number;
  };
};

type RunningServer = {
  child: ReturnType<typeof spawn>;
  receiptFile: string;
  output: {
    stdout: string;
    stderr: string;
  };
};

type HttpResult = {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
};

const temporaryDirectories: string[] = [];
const runningChildren: Array<ReturnType<typeof spawn>> = [];
const launchedServers: Array<{
  receiptFile: string;
  binding: CanaryBinding;
  pid: number;
  startToken: string;
}> = [];

jest.setTimeout(20_000);

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function newTemporaryDirectory(): string {
  const directory = realpathSync(
    mkdtempSync(path.join(tmpdir(), "browser-canary-server-")),
  );
  temporaryDirectories.push(directory);
  return directory;
}

function defaultBinding(): CanaryBinding {
  return {
    goal_id: "goal-browser-canary-test",
    role: "DEV",
    task_id: "TASK-BROWSER-CANARY",
  };
}

function bindingArgs(binding: CanaryBinding): string[] {
  return [
    "--goal",
    binding.goal_id,
    "--role",
    binding.role,
    ...(binding.task_id === null ? [] : ["--task", binding.task_id]),
  ];
}

function spawnServer(
  port: number,
  receiptFile: string,
  binding = defaultBinding(),
  environment: NodeJS.ProcessEnv = process.env,
): RunningServer {
  const child = spawn(
    realpathSync(process.execPath),
    [
      SERVER,
      "serve",
      "--port",
      String(port),
      "--receipt-file",
      receiptFile,
      ...bindingArgs(binding),
    ],
    {
      cwd: ROOT,
      env: deriveServeEnvironment(environment) as NodeJS.ProcessEnv,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  runningChildren.push(child);
  const output = { stdout: "", stderr: "" };
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    output.stdout += chunk;
  });
  child.stderr?.on("data", (chunk: string) => {
    output.stderr += chunk;
  });
  return { child, receiptFile, output };
}

function runLifecycleCommand(
  command: "launch" | "stop",
  receiptFile: string,
  binding = defaultBinding(),
  environment: NodeJS.ProcessEnv = process.env,
  directServer = false,
): Record<string, unknown> {
  const output = execFileSync(
    directServer ? realpathSync(process.execPath) : LAUNCHER,
    [
      ...(directServer ? [SERVER] : EXPLICIT_NODE_ARGS),
      command,
      "--receipt-file",
      receiptFile,
      ...bindingArgs(binding),
    ],
    {
      cwd: ROOT,
      env: environment,
      encoding: "utf8",
    },
  );
  return JSON.parse(output) as Record<string, unknown>;
}

function launchServer(
  receiptFile: string,
  binding = defaultBinding(),
  environment: NodeJS.ProcessEnv = process.env,
  directServer = false,
): {
  ready: Record<string, unknown>;
  receipt: ReadyReceipt;
} {
  const ready = runLifecycleCommand(
    "launch",
    receiptFile,
    binding,
    environment,
    directServer,
  );
  const receipt = JSON.parse(
    readFileSync(receiptFile, "utf8"),
  ) as ReadyReceipt;
  launchedServers.push({
    receiptFile,
    binding,
    pid: receipt.pid,
    startToken: receipt.process_start_token,
  });
  return { ready, receipt };
}

async function waitForReceipt(runtime: RunningServer): Promise<ReadyReceipt> {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    if (existsSync(runtime.receiptFile)) {
      return JSON.parse(readFileSync(runtime.receiptFile, "utf8")) as ReadyReceipt;
    }
    if (runtime.child.exitCode !== null || runtime.child.signalCode !== null) {
      throw new Error(
        `canary server exited before receipt: `
          + `${runtime.child.exitCode}/${runtime.child.signalCode}\n`
          + runtime.output.stderr,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`timed out waiting for receipt\n${runtime.output.stderr}`);
}

async function waitForExit(
  child: ReturnType<typeof spawn>,
  timeoutMilliseconds = 5_000,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode };
  }
  return new Promise((resolve, reject) => {
    const terminate = setTimeout(() => {
      child.kill("SIGKILL");
    }, timeoutMilliseconds);
    const fail = setTimeout(() => {
      reject(new Error("child did not exit after SIGKILL"));
    }, timeoutMilliseconds + 2_000);
    child.once("exit", (code, signal) => {
      clearTimeout(terminate);
      clearTimeout(fail);
      resolve({ code, signal });
    });
  });
}

async function waitForProcessIdentityGone(
  pid: number,
  startToken: string,
  timeoutMilliseconds = 5_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    if (processStartToken(pid) !== startToken) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`process ${pid} retained the same start token`);
}

function request(
  url: string,
  options: { method?: string; host?: string } = {},
): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const outgoing = http.request(
      {
        host: parsed.hostname,
        port: Number(parsed.port),
        path: `${parsed.pathname}${parsed.search}`,
        method: options.method ?? "GET",
        headers: options.host ? { Host: options.host } : undefined,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        response.on("end", () => {
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    outgoing.once("error", reject);
    outgoing.end();
  });
}

afterEach(async () => {
  for (const launched of launchedServers.splice(0)) {
    if (processStartToken(launched.pid) === launched.startToken) {
      try {
        runLifecycleCommand(
          "stop",
          launched.receiptFile,
          launched.binding,
        );
      } catch {
        // A failed stop is itself a test failure in lifecycle cases; cleanup
        // must never fall back to an unverified raw PID signal.
      }
    }
  }
  for (const child of runningChildren.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      try {
        await waitForExit(child, 2_000);
      } catch {
        child.kill("SIGKILL");
        if (child.exitCode === null && child.signalCode === null) {
          await once(child, "exit").catch(() => undefined);
        }
      }
    }
  }
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("repo-owned Browser canary server", () => {
  it("serves the exact isolated canary and seals a private readiness receipt", async () => {
    const directory = newTemporaryDirectory();
    const receiptFile = path.join(directory, "ready.json");
    const runtime = spawnServer(0, receiptFile);
    const receipt = await waitForReceipt(runtime);
    const port = receipt.listener.port;

    expect(Object.keys(receipt)).toEqual([
      "schema_version",
      "kind",
      "binding",
      "binding_sha256",
      "url",
      "nonce",
      "contract",
      "page_sha256",
      "implementation_sha256",
      "launch",
      "lifecycle",
      "pid",
      "process_start_token",
      "process_executable_path",
      "process_command_sha256",
      "process_cwd",
      "started_at",
      "expires_at",
      "listener",
    ]);
    expect(receipt).toMatchObject({
      schema_version: 1,
      kind: RECEIPT_KIND,
      url: `http://127.0.0.1:${port}/codex-capability-canary`,
      binding: {
        goal_id: "goal-browser-canary-test",
        role: "DEV",
        task_id: "TASK-BROWSER-CANARY",
      },
      contract: CANARY_CONTRACT,
      pid: runtime.child.pid,
      listener: {
        host: "127.0.0.1",
        port,
      },
    });
    expect(receipt.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(receipt.process_start_token).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(receipt.process_start_token).toBe(processStartToken(receipt.pid));
    expect(Number.isFinite(Date.parse(receipt.started_at))).toBe(true);
    expect(
      Date.parse(receipt.expires_at) - Date.parse(receipt.started_at),
    ).toBe(15 * 60 * 1000);
    expect(receipt.process_executable_path).toBe(
      realpathSync(process.execPath),
    );
    expect(receipt.process_cwd).toBe(ROOT);
    expect(processCwd(receipt.pid)).toBe(ROOT);
    expect(receipt.launch).toEqual(deriveServeIdentity({
      receiptFile,
      binding: defaultBinding(),
    }));
    expect(receipt.launch).toMatchObject({
      controller_root: ROOT,
      controller_repository_head: controllerRepositoryHead(),
      server_script_path: SERVER,
      server_script_sha256: implementationSha256(),
      node_executable_path: realpathSync(process.execPath),
      cwd: ROOT,
      requested_port: 0,
      expected_argv: [
        realpathSync(process.execPath),
        SERVER,
        "serve",
        "--port",
        "0",
        "--receipt-file",
        receiptFile,
        "--goal",
        "goal-browser-canary-test",
        "--role",
        "DEV",
        "--task",
        "TASK-BROWSER-CANARY",
      ],
    });
    expect(receipt.lifecycle).toEqual({
      receipt_retained: true,
      auto_shutdown_at_expires_at: true,
    });
    expect(processCommand(receipt.pid)).toBe(
      receipt.launch.expected_argv.join(" "),
    );
    expect(receipt.process_command_sha256)
      .toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(receipt.implementation_sha256).toBe(implementationSha256());
    expect(receipt.implementation_sha256).toBe(
      sha256(readFileSync(SERVER)),
    );
    expect(assertLiveServerIdentity(receipt, {
      receiptFile,
      binding: defaultBinding(),
    })).toMatchObject({
      launch: receipt.launch,
      listener: {
        pid: receipt.pid,
        protocol: "IPv4",
        name: `127.0.0.1:${port}`,
        tcp_state: "LISTEN",
      },
    });
    expect(inspectListenerInventory(port)).toEqual({
      port,
      records: [
        expect.objectContaining({
          pid: receipt.pid,
          protocol: "IPv4",
          name: `127.0.0.1:${port}`,
          tcp_state: "LISTEN",
        }),
      ],
    });

    const installed = lstatSync(receiptFile);
    expect(installed.isFile()).toBe(true);
    expect(installed.isSymbolicLink()).toBe(false);
    expect(installed.mode & 0o777).toBe(0o600);
    expect(installed.nlink).toBe(1);
    expect(readFileSync(receiptFile, "utf8")).toBe(
      `${JSON.stringify(receipt, null, 2)}\n`,
    );
    expect(readdirSync(directory)).toEqual(["ready.json"]);

    const served = await request(receipt.url);
    expect(served.status).toBe(200);
    expect(served.headers["content-type"]).toBe("text/html; charset=utf-8");
    expect(served.headers["cache-control"]).toBe("no-store, max-age=0");
    expect(served.headers["x-content-type-options"]).toBe("nosniff");
    expect(served.headers["x-codex-canary-nonce"]).toBe(receipt.nonce);
    expect(served.headers["set-cookie"]).toBeUndefined();
    expect(served.headers.location).toBeUndefined();
    expect(served.headers["content-security-policy"]).toContain(
      "default-src 'none'",
    );
    expect(served.headers["content-security-policy"]).not.toContain(
      "'unsafe-inline'",
    );
    expect(served.body).toBe(buildCanaryPage(receipt.nonce));
    expect(receipt.page_sha256).toBe(sha256(served.body));
    expect(served.body).toContain(
      `<meta name="codex-capability-canary-nonce" content="${receipt.nonce}">`,
    );
    expect(served.body).toContain(
      `<title>${CANARY_CONTRACT.expected_title}</title>`,
    );
    expect(served.body).toContain(`id="${CANARY_CONTRACT.button_id}"`);
    expect(served.body).toContain(
      `id="${CANARY_CONTRACT.status_id}" role="status">${CANARY_CONTRACT.initial_status}`,
    );
    expect(served.body).not.toMatch(/\b(?:href|src)\s*=/i);
    expect(served.body).not.toMatch(/document\.cookie|fetch\s*\(/i);

    const probe = JSON.parse(execFileSync(
      process.execPath,
      [
        PROBE,
        "--url",
        receipt.url,
        "--expected-page-sha256",
        receipt.page_sha256,
        "--expected-nonce",
        receipt.nonce,
      ],
      { encoding: "utf8" },
    )) as {
      status_code: number;
      page_sha256: string;
      nonce: string;
      redirect_followed: boolean;
    };
    expect(probe).toMatchObject({
      status_code: 200,
      page_sha256: receipt.page_sha256,
      nonce: receipt.nonce,
      redirect_followed: false,
    });

    const script = served.body.match(/<script>([\s\S]*?)<\/script>/)?.[1];
    const style = served.body.match(/<style>([\s\S]*?)<\/style>/)?.[1];
    expect(script).toBeDefined();
    expect(style).toBeDefined();
    const csp = served.headers["content-security-policy"] ?? "";
    expect(csp).toContain(
      `'sha256-${createHash("sha256").update(script!).digest("base64")}'`,
    );
    expect(csp).toContain(
      `'sha256-${createHash("sha256").update(style!).digest("base64")}'`,
    );

    const notFound = await request(
      `http://127.0.0.1:${port}/not-the-canary`,
    );
    expect(notFound.status).toBe(404);
    expect(notFound.headers.location).toBeUndefined();
    const queryRejected = await request(`${receipt.url}?unexpected=true`);
    expect(queryRejected.status).toBe(404);
    expect(queryRejected.headers.location).toBeUndefined();
    const badHost = await request(receipt.url, { host: `localhost:${port}` });
    expect(badHost.status).toBe(421);
    expect(badHost.headers.location).toBeUndefined();
    const postRejected = await request(receipt.url, { method: "POST" });
    expect(postRejected.status).toBe(405);
    expect(postRejected.headers.location).toBeUndefined();

    runtime.child.kill("SIGTERM");
    await expect(waitForExit(runtime.child)).resolves.toEqual({
      code: 0,
      signal: null,
    });
  });

  it("the button script changes only READY to CLICKED", () => {
    const page = buildCanaryPage("ab".repeat(32));
    const script = page.match(/<script>([\s\S]*?)<\/script>/)?.[1];
    if (!script) throw new Error("canary script missing");
    let click: (() => void) | undefined;
    const button = {
      addEventListener: (event: string, listener: () => void) => {
        expect(event).toBe("click");
        click = listener;
      },
    };
    const status = { textContent: CANARY_CONTRACT.initial_status };
    const document = {
      getElementById: (id: string) => {
        if (id === CANARY_CONTRACT.button_id) return button;
        if (id === CANARY_CONTRACT.status_id) return status;
        throw new Error(`unexpected element id: ${id}`);
      },
    };

    Function("document", script)(document);
    expect(status.textContent).toBe(CANARY_CONTRACT.initial_status);
    click?.();
    expect(status).toEqual({ textContent: CANARY_CONTRACT.clicked_status });
    click?.();
    expect(status).toEqual({ textContent: CANARY_CONTRACT.clicked_status });
  });

  it("the raw endpoint probe rejects redirects before following them", () => {
    const body = Buffer.from("redirect");
    expect(() => assertExactProbeResponse(
      {
        statusCode: 302,
        headers: {
          location: "https://example.invalid/",
          "content-length": String(body.length),
        },
        rawHeaders: [
          "Location",
          "https://example.invalid/",
          "Content-Length",
          String(body.length),
        ],
        socket: {
          remoteAddress: "127.0.0.1",
          remotePort: 43119,
        },
      },
      {
        port: 43119,
        expectedPageSha256: sha256(body),
        expectedNonce: "ab".repeat(32),
      },
      body,
    )).toThrow(/status\/peer\/body\/header binding/);
  });

  it("launches detached, reports READY, and stops only the attested process", async () => {
    const directory = newTemporaryDirectory();
    const receiptFile = path.join(directory, "detached-ready.json");
    const { ready, receipt } = launchServer(receiptFile);

    expect(ready).toMatchObject({
      status: "READY",
      receipt_file: receiptFile,
      pid: receipt.pid,
      url: receipt.url,
      expires_at: receipt.expires_at,
      receipt_retained: true,
      receipt_sha256: sha256(readFileSync(receiptFile)),
    });
    expect(processStartToken(receipt.pid)).toBe(receipt.process_start_token);
    expect(assertLiveServerIdentity(receipt, {
      receiptFile,
      binding: defaultBinding(),
    })).toMatchObject({
      launch: receipt.launch,
    });

    const stopped = runLifecycleCommand("stop", receiptFile);
    expect(stopped).toEqual({
      status: "STOPPED",
      receipt_file: receiptFile,
      pid: receipt.pid,
      receipt_retained: true,
      receipt_sha256: sha256(readFileSync(receiptFile)),
    });
    await waitForProcessIdentityGone(
      receipt.pid,
      receipt.process_start_token,
    );
    expect(existsSync(receiptFile)).toBe(true);
    expect(lstatSync(receiptFile).mode & 0o777).toBe(0o600);

    const exactBytesWithDifferentFormatting = Buffer.from(
      `${JSON.stringify(receipt)} \n`,
    );
    writeFileSync(receiptFile, exactBytesWithDifferentFormatting, {
      mode: 0o600,
    });
    const alreadyStopped = runLifecycleCommand("stop", receiptFile);
    expect(alreadyStopped).toEqual({
      status: "ALREADY_STOPPED",
      receipt_file: receiptFile,
      pid: receipt.pid,
      receipt_retained: true,
      receipt_sha256: sha256(exactBytesWithDifferentFormatting),
    });
    expect(alreadyStopped.receipt_sha256).toBe(
      sha256(readFileSync(receiptFile)),
    );
  });

  it("auto-stops the detached listener at TTL and retains the audit receipt", async () => {
    const directory = newTemporaryDirectory();
    const receiptFile = path.join(directory, "ttl-ready.json");
    const environment = {
      ...process.env,
      NODE_ENV: "test",
      BROWSER_CANARY_TEST_TTL_MILLISECONDS: "750",
    };
    const { receipt } = launchServer(
      receiptFile,
      defaultBinding(),
      environment,
      true,
    );
    expect(
      Date.parse(receipt.expires_at) - Date.parse(receipt.started_at),
    ).toBe(750);
    await waitForProcessIdentityGone(
      receipt.pid,
      receipt.process_start_token,
      4_000,
    );
    expect(existsSync(receiptFile)).toBe(true);
    expect(() => inspectListenerInventory(receipt.listener.port)).toThrow();

    expect(runLifecycleCommand("stop", receiptFile)).toMatchObject({
      status: "ALREADY_STOPPED",
      receipt_retained: true,
      receipt_sha256: sha256(readFileSync(receiptFile)),
    });
  });

  it("rejects ambiguous or non-Node explicit interpreter paths", () => {
    const directory = newTemporaryDirectory();
    const symlinkedNode = path.join(directory, "node-symlink");
    const fakeNode = path.join(directory, "fake-node");
    const groupWritableNode = path.join(directory, "group-writable-node");
    const hardlinkedNode = path.join(directory, "hardlinked-node");
    const hardlinkAlias = path.join(directory, "hardlinked-node-alias");
    const newlineNode = path.join(directory, "node\n");
    const strippedNode = path.join(directory, "node");
    symlinkSync(realpathSync(process.execPath), symlinkedNode);
    writeFileSync(fakeNode, "#!/bin/sh\nexit 0\n");
    writeFileSync(groupWritableNode, "#!/bin/sh\nexit 0\n");
    writeFileSync(hardlinkedNode, "#!/bin/sh\nexit 0\n");
    linkSync(hardlinkedNode, hardlinkAlias);
    writeFileSync(newlineNode, "#!/bin/sh\nexit 0\n");
    writeFileSync(strippedNode, "#!/bin/sh\nexit 99\n");
    chmodSync(fakeNode, 0o700);
    chmodSync(groupWritableNode, 0o720);
    chmodSync(hardlinkedNode, 0o700);
    chmodSync(newlineNode, 0o700);
    chmodSync(strippedNode, 0o700);

    const invoke = (nodePath: string) => () => execFileSync(
      LAUNCHER,
      ["--node-executable", nodePath, "launch"],
      { cwd: ROOT, encoding: "utf8" },
    );
    expect(invoke("relative/node")).toThrow(/must be absolute/);
    expect(invoke(symlinkedNode)).toThrow(/must be canonical/);
    expect(invoke(newlineNode)).toThrow(/control characters/);
    expect(invoke(groupWritableNode)).toThrow(/group\/other writable/);
    expect(invoke(hardlinkedNode)).toThrow(/single-link/);
    expect(invoke(fakeNode)).toThrow(/compatibility output mismatch/);
  });

  it("the shell launcher drops parent preload and credential environment", () => {
    const directory = newTemporaryDirectory();
    const receiptFile = path.join(directory, "sanitized-ready.json");
    const preloadFile = path.join(directory, "preload.cjs");
    const preloadMarker = path.join(directory, "preload-ran");
    const fakeBin = path.join(directory, "fake-bin");
    const fakePathMarker = path.join(directory, "inherited-path-ran");
    const shellStartupFile = path.join(directory, "shell-startup.sh");
    mkdirSync(fakeBin, { mode: 0o700 });
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
    writeFileSync(
      preloadFile,
      `require("fs").writeFileSync(${JSON.stringify(preloadMarker)}, "bad");\n`,
    );
    const { receipt } = launchServer(
      receiptFile,
      defaultBinding(),
      {
        ...process.env,
        GH_TOKEN: "must-not-reach-server",
        NODE_OPTIONS: `--require=${preloadFile}`,
        NODE_PATH: directory,
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
      },
    );

    expect(existsSync(preloadMarker)).toBe(false);
    expect(existsSync(fakePathMarker)).toBe(false);
    expect(receipt.launch.environment).toEqual(
      deriveServeEnvironment({}),
    );
    expect(receipt.launch.environment).not.toHaveProperty("GH_TOKEN");
    expect(receipt.launch.environment).not.toHaveProperty("NODE_OPTIONS");
    expect(runLifecycleCommand("stop", receiptFile)).toMatchObject({
      status: "STOPPED",
      receipt_sha256: sha256(readFileSync(receiptFile)),
    });
  });

  it("a held receipt fd rejects one-way pathname replacement", () => {
    const directory = newTemporaryDirectory();
    const receiptFile = path.join(directory, "held.json");
    const displacedFile = path.join(directory, "held.displaced.json");
    const bytes = Buffer.from('{"kind":"test"}\n');
    writeFileSync(receiptFile, bytes, { mode: 0o600 });
    const capture = openPrivateJsonReceiptCapture(receiptFile);
    try {
      renameSync(receiptFile, displacedFile);
      writeFileSync(receiptFile, bytes, { mode: 0o600 });
      expect(() => assertCaptureStillInstalled(receiptFile, capture))
        .toThrow(/pathname|held fd|identity/);
    } finally {
      closeReceiptCapture(capture);
    }
  });

  it("rejects ambiguous, wildcard, IPv6, or second-owner listener inventories", () => {
    const port = 43119;
    const exact: ListenerInventory = {
      port,
      records: [{
        pid: 123,
        command: "node",
        fd: "19",
        protocol: "IPv4",
        name: `127.0.0.1:${port}`,
        tcp_state: "LISTEN",
      }],
    };
    expect(assertExactListenerInventory(exact, 123, port)).toEqual(
      exact.records[0],
    );
    expect(() => assertExactListenerInventory({
      ...exact,
      records: [{ ...exact.records[0], name: `*:${port}` }],
    }, 123, port)).toThrow(/wildcard\/IPv6/);
    expect(() => assertExactListenerInventory({
      ...exact,
      records: [{
        ...exact.records[0],
        protocol: "IPv6",
        name: `[::1]:${port}`,
      }],
    }, 123, port)).toThrow(/wildcard\/IPv6/);
    expect(() => assertExactListenerInventory({
      ...exact,
      records: [exact.records[0], { ...exact.records[0], fd: "20" }],
    }, 123, port)).toThrow(/一个 socket record/);
    expect(() => assertExactListenerInventory({
      ...exact,
      records: [
        exact.records[0],
        { ...exact.records[0], pid: 456, fd: "20" },
      ],
    }, 123, port)).toThrow(/一个 socket record 和一个 owner PID/);
  });

  it("rejects an existing receipt or symlink without overwriting either", async () => {
    const directory = newTemporaryDirectory();
    const existingReceipt = path.join(directory, "existing.json");
    writeFileSync(existingReceipt, "do-not-overwrite\n");
    const existingRuntime = spawnServer(0, existingReceipt);
    await expect(waitForExit(existingRuntime.child)).resolves.toEqual({
      code: 1,
      signal: null,
    });
    expect(readFileSync(existingReceipt, "utf8")).toBe("do-not-overwrite\n");
    expect(existingRuntime.output.stderr).toMatch(/拒绝覆盖 existing path/);

    const symlinkTarget = path.join(directory, "symlink-target.json");
    const symlinkReceipt = path.join(directory, "symlink.json");
    writeFileSync(symlinkTarget, "target-must-stay\n");
    symlinkSync(symlinkTarget, symlinkReceipt);
    const symlinkRuntime = spawnServer(0, symlinkReceipt);
    await expect(waitForExit(symlinkRuntime.child)).resolves.toEqual({
      code: 1,
      signal: null,
    });
    expect(lstatSync(symlinkReceipt).isSymbolicLink()).toBe(true);
    expect(readFileSync(symlinkTarget, "utf8")).toBe("target-must-stay\n");
    expect(symlinkRuntime.output.stderr).toMatch(/拒绝覆盖 symlink/);

    const writableParent = path.join(directory, "group-writable");
    mkdirSync(writableParent, { mode: 0o770 });
    chmodSync(writableParent, 0o770);
    const unsafeRuntime = spawnServer(
      0,
      path.join(writableParent, "ready.json"),
    );
    await expect(waitForExit(unsafeRuntime.child)).resolves.toEqual({
      code: 1,
      signal: null,
    });
    expect(unsafeRuntime.output.stderr).toMatch(/mode 0700/);
  });

  it("accepts 200-character canonical IDs and rejects 201 characters", () => {
    const goal200 = `g${"a".repeat(199)}`;
    const task200 = `T${"B".repeat(199)}`;
    expect(parseCliArgs([
      "serve",
      "--port",
      "0",
      "--receipt-file",
      "/private/tmp/canary.json",
      "--goal",
      goal200,
      "--role",
      "DEV",
      "--task",
      task200,
    ])).toMatchObject({
      command: "serve",
      port: 0,
      binding: {
        goal_id: goal200,
        role: "DEV",
        task_id: task200,
      },
    });
    expect(() => parseCliArgs([
      "launch",
      "--receipt-file",
      "/private/tmp/canary.json",
      "--goal",
      `g${"a".repeat(200)}`,
      "--role",
      "FOREMAN",
    ])).toThrow(/canonical ID/);
    expect(() => parseCliArgs([
      "launch",
      "--receipt-file",
      "/private/tmp/canary.json",
      "--goal",
      "goal-test",
      "--role",
      "DEV",
      "--task",
      `T${"B".repeat(200)}`,
    ])).toThrow(/canonical --task/);
  });

  it("rejects non-canonical CLI lifecycle inputs", () => {
    expect(() => parseCliArgs([
      "serve",
      "--port",
      "1023",
      "--receipt-file",
      "/tmp/canary.json",
      "--goal",
      "goal-test",
      "--role",
      "DEV",
      "--task",
      "TASK-TEST",
    ])).toThrow(/只能是 0/);
    expect(() => parseCliArgs([
      "serve",
      "--port",
      "01024",
      "--receipt-file",
      "/tmp/canary.json",
      "--goal",
      "goal-test",
      "--role",
      "DEV",
      "--task",
      "TASK-TEST",
    ])).toThrow(/只能是 0/);
    expect(() => parseCliArgs([
      "serve",
      "--port",
      "0",
      "--receipt-file",
      "relative.json",
      "--goal",
      "goal-test",
      "--role",
      "DEV",
      "--task",
      "TASK-TEST",
    ])).toThrow(/absolute path/);
    expect(() => parseCliArgs([
      "serve",
      "--port",
      "0",
      "--port",
      "0",
      "--receipt-file",
      "/private/tmp/canary.json",
      "--goal",
      "goal-test",
      "--role",
      "FOREMAN",
    ])).toThrow(/duplicate/);
    expect(() => parseCliArgs([
      "launch",
      "--port",
      "0",
      "--receipt-file",
      "/private/tmp/canary.json",
      "--goal",
      "goal-test",
      "--role",
      "FOREMAN",
    ])).toThrow(/禁止 --port/);
    expect(() => parseCliArgs([
      "unknown",
      "--receipt-file",
      "/private/tmp/canary.json",
      "--goal",
      "goal-test",
      "--role",
      "FOREMAN",
    ])).toThrow(/usage/);
  });
});
