import { execFileSync } from "child_process";
import { createHash } from "crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { createRequire } from "module";
import { fileURLToPath } from "url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GOALCTL = path.join(ROOT, "scripts", "goalctl.js");
const nodeRequire = createRequire(import.meta.url);
const { hashObject } = nodeRequire(
  path.join(ROOT, "scripts", "goal-control", "util.js")
) as {
  hashObject: (value: unknown) => string;
};

type Fixture = {
  repository: string;
  controlDir: string;
  manifestRelative: string;
  goalDir: string;
};

type CliResult = {
  status: number;
  stdout: string;
  stderr: string;
};

const fixtures: Fixture[] = [];

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  }).trim();
}

function sha256(body: string | Buffer): string {
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}

function makeFixture(): Fixture {
  const repository = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-init-recovery-repo-"))
  );
  const controlDir = realpathSync(
    mkdtempSync(path.join(tmpdir(), "goal-init-recovery-store-"))
  );
  git(repository, "init", "-q", "-b", "main");
  git(repository, "config", "user.email", "goal-init@example.test");
  git(repository, "config", "user.name", "Goal Init Test");
  writeFileSync(path.join(repository, "README.md"), "# isolated init fixture\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "base");
  const baseHead = git(repository, "rev-parse", "HEAD");

  const manifestRelative = "docs/planning/goals/init-test/manifest.json";
  const packetRelative = "docs/planning/goals/init-test/packet.md";
  mkdirSync(path.dirname(path.join(repository, packetRelative)), {
    recursive: true,
  });
  const packetBody = "# TASK-INIT\n\nDurable init packet.\n";
  writeFileSync(path.join(repository, packetRelative), packetBody);
  writeFileSync(
    path.join(repository, manifestRelative),
    `${JSON.stringify(
      {
        schema_version: 1,
        goal_id: "init-test",
        mode: "shadow",
        repository: {
          name_with_owner: "example-org/example-repo",
          base_branch: "main",
        },
        base_head: baseHead,
        tasks: [
          {
            id: "TASK-INIT",
            dependencies: [],
            integration_order: 1,
            packet: {
              revision: 1,
              path: packetRelative,
              sha256: sha256(packetBody),
            },
          },
        ],
      },
      null,
      2
    )}\n`
  );
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "freeze init inputs");

  const fixture = {
    repository,
    controlDir,
    manifestRelative,
    goalDir: path.join(controlDir, "goals", "init-test"),
  };
  fixtures.push(fixture);
  return fixture;
}

function runGoal(
  fixture: Fixture,
  args: string[],
  extraEnv: Record<string, string> = {}
): CliResult {
  try {
    const stdout = execFileSync(
      "node",
      [GOALCTL, ...args],
      {
        cwd: fixture.repository,
        encoding: "utf8",
        stdio: "pipe",
        env: {
          ...process.env,
          GOAL_CONTROL_DIR: fixture.controlDir,
          GOAL_CONTROL_TEST_MODE: "1",
          ...extraEnv,
        },
      }
    );
    return { status: 0, stdout, stderr: "" };
  } catch (error: unknown) {
    const failure = error as {
      status?: number;
      stdout?: string;
      stderr?: string;
    };
    return {
      status: failure.status ?? 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? "",
    };
  }
}

function runInit(
  fixture: Fixture,
  extraEnv: Record<string, string> = {}
): CliResult {
  return runGoal(
    fixture,
    ["init", "--manifest", fixture.manifestRelative, "--json"],
    extraEnv
  );
}

function mode(file: string): number {
  return lstatSync(file).mode & 0o777;
}

function makePreReceiptLegacyGoal(fixture: Fixture): void {
  const metadataFile = path.join(fixture.goalDir, "goal.json");
  const metadata = JSON.parse(readFileSync(metadataFile, "utf8")) as Record<
    string,
    unknown
  >;
  delete metadata.meta_sha256;
  delete metadata.init_receipt_schema_version;
  delete metadata.init_receipt_sha256;
  delete metadata.init_receipt_adopted_at;
  delete metadata.init_receipt_legacy_source_sha256;
  metadata.meta_sha256 = hashObject(metadata);
  writeFileSync(metadataFile, `${JSON.stringify(metadata, null, 2)}\n`);
  chmodSync(metadataFile, 0o600);
  unlinkSync(path.join(fixture.goalDir, "init-receipt.json"));
  chmodSync(fixture.goalDir, 0o755);
  chmodSync(path.join(fixture.goalDir, "capabilities"), 0o755);
}

afterEach(() => {
  while (fixtures.length > 0) {
    const fixture = fixtures.pop();
    if (!fixture) continue;
    rmSync(fixture.repository, { recursive: true, force: true });
    rmSync(fixture.controlDir, { recursive: true, force: true });
  }
});

describe("goal-control init response-loss recovery", () => {
  it("recovers the exact committed init after a post-rename thrown response loss", () => {
    const fixture = makeFixture();
    const interrupted = runInit(fixture, {
      GOAL_CONTROL_TEST_FAULT_AFTER_INIT_PUBLISH: "throw",
    });
    expect(interrupted.status).toBe(2);
    expect(interrupted.stderr).toContain("TEST_FAULT_AFTER_INIT_PUBLISH");

    const receiptFile = path.join(fixture.goalDir, "init-receipt.json");
    const bootstrapFile = path.join(
      fixture.goalDir,
      "capabilities",
      "bootstrap.cap"
    );
    const recoveryFile = path.join(
      fixture.goalDir,
      "capabilities",
      "foreman-recovery.cap"
    );
    expect(existsSync(receiptFile)).toBe(true);
    expect(
      readdirSync(path.join(fixture.controlDir, "goals")).filter((name) =>
        name.startsWith(".init-")
      )
    ).toEqual([]);
    writeFileSync(
      path.join(fixture.goalDir, "state.json"),
      "{\"interrupted_projection\":true}\n",
      { mode: 0o600 },
    );
    const interruptedHeads = path.join(fixture.goalDir, "event-heads");
    mkdirSync(interruptedHeads, { mode: 0o700 });
    writeFileSync(
      path.join(interruptedHeads, "TASK-INIT.json"),
      "{\"interrupted_head\":true}\n",
      { mode: 0o600 },
    );

    const retried = runInit(fixture);
    expect({ status: retried.status, stderr: retried.stderr }).toEqual({
      status: 0,
      stderr: "",
    });
    const output = JSON.parse(retried.stdout) as Record<string, unknown>;
    expect(output).toMatchObject({
      goal_id: "init-test",
      initialized: false,
      idempotent: true,
      init_receipt_file: receiptFile,
      bootstrap_capability_file: bootstrapFile,
      bootstrap_capability_consumed: false,
      foreman_recovery_capability_file: recoveryFile,
    });
    expect(typeof output.receipt_sha256).toBe("string");
    expect(mode(fixture.goalDir)).toBe(0o700);
    expect(mode(path.join(fixture.goalDir, "capabilities"))).toBe(0o700);
    expect(mode(receiptFile)).toBe(0o600);
    expect(mode(bootstrapFile)).toBe(0o600);
    expect(mode(recoveryFile)).toBe(0o600);
    expect(readFileSync(
      path.join(fixture.goalDir, "state.json"),
      "utf8",
    )).not.toContain("interrupted_projection");
    const generation = JSON.parse(
      readFileSync(path.join(fixture.controlDir, ".generation.json"), "utf8")
    ) as { generation: number };
    expect(generation.generation % 2).toBe(0);
  });

  it("leaves a complete atomic Goal directory after an abrupt post-rename exit", () => {
    const fixture = makeFixture();
    const interrupted = runInit(fixture, {
      GOAL_CONTROL_TEST_FAULT_AFTER_INIT_PUBLISH: "exit",
    });
    expect(interrupted.status).toBe(86);
    expect(existsSync(path.join(fixture.goalDir, "manifest.json"))).toBe(true);
    expect(existsSync(path.join(fixture.goalDir, "goal.json"))).toBe(true);
    expect(existsSync(path.join(fixture.goalDir, "init-receipt.json"))).toBe(
      true
    );
    expect(
      readdirSync(path.join(fixture.controlDir, "goals")).filter((name) =>
        name.startsWith(".init-")
      )
    ).toEqual([]);
    const retried = runInit(fixture);
    expect({ status: retried.status, stderr: retried.stderr }).toEqual({
      status: 0,
      stderr: "",
    });
    expect(JSON.parse(retried.stdout)).toMatchObject({
      initialized: false,
      idempotent: true,
      receipt_publication: "ATOMIC_DIRECTORY_RENAME",
    });
  });

  it("promotes the exact sealed Goal staging without reminting identity", () => {
    const fixture = makeFixture();
    const interrupted = runInit(fixture, {
      GOAL_CONTROL_TEST_FAULT_AFTER_INIT_STAGING: "exit",
      GOAL_CONTROL_NOW: "2026-07-22T00:00:00.000Z",
    });
    expect(interrupted.status).toBe(86);
    expect(existsSync(fixture.goalDir)).toBe(false);
    const goalsDir = path.join(fixture.controlDir, "goals");
    const prepared = readdirSync(goalsDir).filter((name) =>
      name.startsWith(".init-goal-")
    );
    expect(prepared).toHaveLength(1);
    const preparedDir = path.join(goalsDir, prepared[0]);
    expect(lstatSync(preparedDir).isDirectory()).toBe(true);
    const stagedBytes = new Map([
      "manifest.json",
      "goal.json",
      "init-receipt.json",
      "capabilities/bootstrap.cap",
      "capabilities/foreman-recovery.cap",
    ].map((relative) => [
      relative,
      readFileSync(path.join(preparedDir, relative), "utf8"),
    ]));
    const stagedReceipt = JSON.parse(
      stagedBytes.get("init-receipt.json") as string,
    ) as {
      initialized_at: string;
      receipt_sha256: string;
    };

    const retried = runInit(fixture, {
      GOAL_CONTROL_NOW: "2026-07-23T00:00:00.000Z",
    });
    expect({ status: retried.status, stderr: retried.stderr }).toEqual({
      status: 0,
      stderr: "",
    });
    expect(JSON.parse(retried.stdout)).toMatchObject({
      initialized: false,
      idempotent: true,
      cache_degraded: false,
      receipt_sha256: stagedReceipt.receipt_sha256,
      receipt_publication_recorded_at: stagedReceipt.initialized_at,
    });
    expect(existsSync(preparedDir)).toBe(false);
    for (const [relative, bytes] of stagedBytes) {
      expect(readFileSync(path.join(fixture.goalDir, relative), "utf8"))
        .toBe(bytes);
    }
    for (const cacheFile of ["state.json", "ledger.json", "ledger.md"]) {
      expect(existsSync(path.join(fixture.goalDir, cacheFile))).toBe(true);
    }
    const nextProcessStatus = runGoal(fixture, [
      "status",
      "--goal", "init-test",
      "--json",
    ]);
    expect({
      status: nextProcessStatus.status,
      stderr: nextProcessStatus.stderr,
    }).toEqual({ status: 0, stderr: "" });
    expect(JSON.parse(nextProcessStatus.stdout)).toMatchObject({
      goal_id: "init-test",
      tasks: {
        "TASK-INIT": { task_id: "TASK-INIT", phase: "QUEUED" },
      },
    });
  });

  it("preserves a sealed Goal staging when committed manifest bytes change", () => {
    const fixture = makeFixture();
    const interrupted = runInit(fixture, {
      GOAL_CONTROL_TEST_FAULT_AFTER_INIT_STAGING: "exit",
    });
    expect(interrupted.status).toBe(86);
    const goalsDir = path.join(fixture.controlDir, "goals");
    const preparedName = readdirSync(goalsDir).find((name) =>
      name.startsWith(".init-goal-")
    );
    expect(preparedName).toBeDefined();
    const preparedDir = path.join(goalsDir, preparedName as string);
    const receiptBytes = readFileSync(
      path.join(preparedDir, "init-receipt.json"),
      "utf8",
    );

    const manifestFile = path.join(
      fixture.repository,
      fixture.manifestRelative,
    );
    const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));
    manifest.title = "changed prepared init request";
    writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
    git(fixture.repository, "add", fixture.manifestRelative);
    git(fixture.repository, "commit", "-qm", "change prepared init request");

    const mismatch = runInit(fixture);
    expect(mismatch.status).toBe(2);
    expect(mismatch.stderr).toContain("PREPARED_REQUEST_MISMATCH");
    expect(existsSync(fixture.goalDir)).toBe(false);
    expect(existsSync(preparedDir)).toBe(true);
    expect(readFileSync(
      path.join(preparedDir, "init-receipt.json"),
      "utf8",
    )).toBe(receiptBytes);
  });

  it("cleans only an exact unsealed init atomic temp and never adopts its bytes", () => {
    const fixture = makeFixture();
    const interrupted = runInit(fixture, {
      GOAL_CONTROL_TEST_FAULT_AFTER_INIT_STAGING: "exit",
    });
    expect(interrupted.status).toBe(86);
    const goalsDir = path.join(fixture.controlDir, "goals");
    const preparedName = readdirSync(goalsDir).find((name) =>
      name.startsWith(".init-goal-")
    );
    expect(preparedName).toBeDefined();
    const preparedDir = path.join(goalsDir, preparedName as string);
    for (const entry of readdirSync(preparedDir)) {
      rmSync(path.join(preparedDir, entry), { recursive: true, force: true });
    }
    const atomicTemp = path.join(
      preparedDir,
      `.manifest.json.4242.tmp-${"a".repeat(24)}`,
    );
    writeFileSync(atomicTemp, "{\"partial\":", { mode: 0o600 });

    const retried = runInit(fixture);
    expect({ status: retried.status, stderr: retried.stderr }).toEqual({
      status: 0,
      stderr: "",
    });
    expect(existsSync(preparedDir)).toBe(false);
    expect(JSON.parse(readFileSync(
      path.join(fixture.goalDir, "manifest.json"),
      "utf8",
    ))).toMatchObject({ goal_id: "init-test" });
    expect(readFileSync(
      path.join(fixture.goalDir, "manifest.json"),
      "utf8",
    )).not.toContain("\"partial\"");
  });

  it("recovers an exit immediately after the private capability directory is created", () => {
    const fixture = makeFixture();
    const interrupted = runInit(fixture, {
      GOAL_CONTROL_TEST_FAULT_AFTER_INIT_CAPABILITIES_DIRECTORY: "exit",
    });
    expect(interrupted.status).toBe(86);
    const goalsDir = path.join(fixture.controlDir, "goals");
    const preparedName = readdirSync(goalsDir).find((name) =>
      name.startsWith(".init-goal-")
    );
    expect(preparedName).toBeDefined();
    const preparedDir = path.join(goalsDir, preparedName as string);
    const capabilitiesDir = path.join(preparedDir, "capabilities");
    expect(mode(preparedDir)).toBe(0o700);
    expect(mode(capabilitiesDir)).toBe(0o700);
    expect(readdirSync(capabilitiesDir)).toEqual([]);
    chmodSync(capabilitiesDir, 0o755);

    const retried = runInit(fixture);
    expect({ status: retried.status, stderr: retried.stderr }).toEqual({
      status: 0,
      stderr: "",
    });
    expect(existsSync(preparedDir)).toBe(false);
    expect(mode(path.join(fixture.goalDir, "capabilities"))).toBe(0o700);
    expect(readdirSync(path.join(fixture.goalDir, "capabilities")).sort())
      .toEqual(["bootstrap.cap", "foreman-recovery.cap"]);
  });

  it("rejects a different committed manifest for the same Goal", () => {
    const fixture = makeFixture();
    expect(runInit(fixture).status).toBe(0);
    const manifestFile = path.join(
      fixture.repository,
      fixture.manifestRelative
    );
    const manifest = JSON.parse(readFileSync(manifestFile, "utf8")) as Record<
      string,
      unknown
    >;
    manifest.title = "different committed request";
    writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
    git(fixture.repository, "add", fixture.manifestRelative);
    git(fixture.repository, "commit", "-qm", "change init request");

    const conflict = runInit(fixture);
    expect(conflict.status).toBe(2);
    expect(conflict.stderr).toContain("GOAL_ALREADY_INITIALIZED");
  });

  it("rejects formatting-only committed manifest byte drift", () => {
    const fixture = makeFixture();
    expect(runInit(fixture).status).toBe(0);
    const manifestFile = path.join(
      fixture.repository,
      fixture.manifestRelative
    );
    const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));
    writeFileSync(manifestFile, `${JSON.stringify(manifest)}\n`);
    git(fixture.repository, "add", fixture.manifestRelative);
    git(fixture.repository, "commit", "-qm", "reformat init request");

    const mismatch = runInit(fixture);
    expect(mismatch.status).toBe(2);
    expect(mismatch.stderr).toContain("INIT_REQUEST_MISMATCH");
  });

  it("adopts a verified pre-receipt Goal with an unconsumed bootstrap", () => {
    const fixture = makeFixture();
    expect(runInit(fixture).status).toBe(0);
    makePreReceiptLegacyGoal(fixture);

    const adopted = runInit(fixture);
    expect({ status: adopted.status, stderr: adopted.stderr }).toEqual({
      status: 0,
      stderr: "",
    });
    expect(JSON.parse(adopted.stdout)).toMatchObject({
      initialized: false,
      idempotent: true,
      init_receipt_adopted: true,
      bootstrap_capability_consumed: false,
      receipt_publication: "LOCKED_LEGACY_ADOPTION",
    });
    expect(mode(fixture.goalDir)).toBe(0o700);
    expect(mode(path.join(fixture.goalDir, "capabilities"))).toBe(0o700);
    const metadata = JSON.parse(
      readFileSync(path.join(fixture.goalDir, "goal.json"), "utf8")
    ) as Record<string, unknown>;
    expect(metadata.init_receipt_schema_version).toBe(1);
    expect(metadata.init_receipt_sha256).toBe(
      JSON.parse(
        readFileSync(
          path.join(fixture.goalDir, "init-receipt.json"),
          "utf8"
        )
      ).receipt_sha256
    );

    unlinkSync(path.join(fixture.goalDir, "init-receipt.json"));
    const missing = runInit(fixture);
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain("INIT_RECEIPT_MISSING");
  });

  it("adopts a verified pre-receipt Goal after bootstrap consumption", () => {
    const fixture = makeFixture();
    const initialized = runInit(fixture);
    expect(initialized.status).toBe(0);
    const bootstrapFile = (
      JSON.parse(initialized.stdout) as {
        bootstrap_capability_file: string;
      }
    ).bootstrap_capability_file;
    const registered = runGoal(fixture, [
      "register-role",
      "--goal",
      "init-test",
      "--task",
      "TASK-INIT",
      "--role",
      "FOREMAN",
      "--thread",
      "legacy-foreman-1",
      "--host",
      "local",
      "--attempt",
      "1",
      "--event-id",
      "register-legacy-foreman-1",
      "--bootstrap-capability-file",
      bootstrapFile,
      "--json",
    ]);
    expect({ status: registered.status, stderr: registered.stderr }).toEqual({
      status: 0,
      stderr: "",
    });
    expect(existsSync(bootstrapFile)).toBe(false);
    const consumedRetry = runInit(fixture);
    expect({
      status: consumedRetry.status,
      stderr: consumedRetry.stderr,
    }).toEqual({ status: 0, stderr: "" });
    expect(JSON.parse(consumedRetry.stdout)).toMatchObject({
      bootstrap_capability_file: bootstrapFile,
      bootstrap_capability_consumed: true,
      receipt_publication: "ATOMIC_DIRECTORY_RENAME",
    });
    makePreReceiptLegacyGoal(fixture);

    const adopted = runInit(fixture);
    expect({ status: adopted.status, stderr: adopted.stderr }).toEqual({
      status: 0,
      stderr: "",
    });
    expect(JSON.parse(adopted.stdout)).toMatchObject({
      initialized: false,
      idempotent: true,
      init_receipt_adopted: true,
      bootstrap_capability_file: bootstrapFile,
      bootstrap_capability_consumed: true,
      receipt_publication: "LOCKED_LEGACY_ADOPTION",
    });
  });

  it("publishes private directories/files and rejects permission drift", () => {
    const fixture = makeFixture();
    const initialized = runInit(fixture);
    expect(initialized.status).toBe(0);
    const recoveryFile = path.join(
      fixture.goalDir,
      "capabilities",
      "foreman-recovery.cap"
    );
    expect(mode(fixture.goalDir)).toBe(0o700);
    expect(mode(path.join(fixture.goalDir, "capabilities"))).toBe(0o700);
    expect(mode(recoveryFile)).toBe(0o600);

    chmodSync(recoveryFile, 0o644);
    const rejected = runInit(fixture);
    expect(rejected.status).toBe(2);
    expect(rejected.stderr).toContain("INIT_PERMISSION_INVALID");
  });

  it("rejects a tampered sealed init receipt instead of re-exposing paths", () => {
    const fixture = makeFixture();
    expect(runInit(fixture).status).toBe(0);
    const receiptFile = path.join(fixture.goalDir, "init-receipt.json");
    const receipt = JSON.parse(readFileSync(receiptFile, "utf8")) as Record<
      string,
      unknown
    >;
    receipt.manifest_sha256 = sha256("tampered");
    writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`, {
      mode: 0o600,
    });
    chmodSync(receiptFile, 0o600);

    const rejected = runInit(fixture);
    expect(rejected.status).toBe(2);
    expect(rejected.stderr).toContain("INIT_RECEIPT_TAMPERED");
    expect(rejected.stdout).toBe("");
  });
});
