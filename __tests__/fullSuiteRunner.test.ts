import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const {
  compareBudgets,
  createJUnit,
  fullCiMatrixGroups,
  loadManifest,
  redact,
  redactString,
  validateCiBudgetBaseWiring,
  validateCiGroupMatrix,
  validateCiTimeoutPolicy,
  validateManifest,
  verifyPartition,
} = require("../scripts/full-suite-runner-lib.js");
const {
  isProcessAlive,
  makeLineSink,
  parseArgs,
  readBaseManifest,
  runGroup,
  settleTimedOutCleanup,
  terminateProcessGroup,
  writeBetweenEntryBudgetDiagnostic,
  writeFailureDiagnostic,
} = require("../scripts/run-full-suite.js");

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = path.join(ROOT, "config", "full-suite-groups.json");
const WORKFLOW = path.join(ROOT, ".github", "workflows", "ci.yml");

describe("full-suite runner", () => {
  it("accepts pnpm's argument separator for the stable shard entry", () => {
    expect(parseArgs(["--", "--group", "core-fsm"])).toMatchObject({
      groups: ["core-fsm"],
      validate: false,
    });
  });

  it("assigns every checked-in test file to exactly one required stable group", () => {
    expect(validateManifest(loadManifest(MANIFEST), ROOT)).toEqual([]);
  });

  it("requires the actual Full workflow matrix to equal the manifest groups", () => {
    const manifest = loadManifest(MANIFEST);
    const workflow = fs.readFileSync(WORKFLOW, "utf8");
    expect(fullCiMatrixGroups(workflow)).toEqual(manifest.groups.map((group) => group.id));
    expect(validateCiGroupMatrix(manifest.groups, workflow)).toEqual([]);
  });

  it("rejects a Full workflow matrix omission or rename", () => {
    const manifest = loadManifest(MANIFEST);
    const workflow = fs.readFileSync(WORKFLOW, "utf8");
    const omitted = workflow.replace("          - recovery-rotation\n", "");
    expect(validateCiGroupMatrix(manifest.groups, omitted)).toContain(
      "full CI matrix missing manifest group: recovery-rotation",
    );
    const renamed = workflow.replace(
      "          - recovery-rotation",
      "          - recovery-renamed",
    );
    expect(validateCiGroupMatrix(manifest.groups, renamed)).toEqual(
      expect.arrayContaining([
        "full CI matrix missing manifest group: recovery-rotation",
        "full CI matrix has unexpected group: recovery-renamed",
      ]),
    );
  });

  it("rejects a Full workflow matrix extra or duplicate", () => {
    const manifest = loadManifest(MANIFEST);
    const workflow = fs.readFileSync(WORKFLOW, "utf8");
    const extra = workflow.replace(
      "          - usability-security",
      "          - usability-security\n          - extra-not-in-manifest",
    );
    expect(validateCiGroupMatrix(manifest.groups, extra)).toContain(
      "full CI matrix has unexpected group: extra-not-in-manifest",
    );
    const duplicate = workflow.replace(
      "          - usability-security",
      "          - usability-security\n          - core-fsm",
    );
    expect(validateCiGroupMatrix(manifest.groups, duplicate)).toContain(
      "duplicate full CI matrix group: core-fsm",
    );
  });

  it("rejects missing and duplicate CI group ids", () => {
    const missing = loadManifest(MANIFEST);
    missing.groups = missing.groups.filter((group) => group.id !== "core-fsm");
    expect(validateManifest(missing, ROOT)).toContain(
      "missing required stable group: core-fsm",
    );

    const duplicate = loadManifest(MANIFEST);
    duplicate.groups.push(structuredClone(duplicate.groups[0]));
    expect(validateManifest(duplicate, ROOT)).toContain(
      "duplicate group id: core-fsm",
    );
  });

  it("rejects moving coverage into an extra group absent from the CI matrix", () => {
    const manifest = loadManifest(MANIFEST);
    const movedEntry = manifest.groups[0].entries.pop();
    manifest.groups.push({
      id: "extra-not-in-ci",
      label: "Extra group with no CI job",
      budgetSeconds: 1200,
      entries: [movedEntry],
    });
    expect(validateManifest(manifest, ROOT)).toContain(
      "unexpected stable group not present in the CI matrix: extra-not-in-ci",
    );
  });

  it("accepts the checked-in CI timeout with its named setup and artifact margin", () => {
    const { policy } = loadManifest(MANIFEST);
    expect(validateCiTimeoutPolicy(policy, fs.readFileSync(WORKFLOW, "utf8"))).toEqual([]);
  });

  it("requires explicit PR and push budget-base wiring in the checked-in workflow", () => {
    const workflow = fs.readFileSync(WORKFLOW, "utf8");
    expect(validateCiBudgetBaseWiring(workflow)).toEqual([]);
    expect(validateCiBudgetBaseWiring(
      workflow.replace("FULL_SUITE_PUSH_BEFORE_SHA", "REMOVED_PUSH_BEFORE_SHA"),
    )).toContain(
      "\"Validate checked-in groups and non-increasing budget\" env is missing "
      + "FULL_SUITE_PUSH_BEFORE_SHA",
    );
  });

  it("rejects commented, missing, or wrong-step budget-base wiring", () => {
    const workflow = fs.readFileSync(WORKFLOW, "utf8");
    const commented = workflow.replace(
      "          FULL_SUITE_PUSH_BEFORE_SHA:",
      "          # FULL_SUITE_PUSH_BEFORE_SHA:",
    );
    expect(validateCiBudgetBaseWiring(commented)).toContain(
      "\"Validate checked-in groups and non-increasing budget\" env is missing "
      + "FULL_SUITE_PUSH_BEFORE_SHA",
    );
    const wrongStep = workflow.replace(
      "Validate checked-in groups and non-increasing budget",
      "Validate something else",
    );
    expect(validateCiBudgetBaseWiring(wrongStep)).toEqual([
      "full CI requires exactly one active "
      + "\"Validate checked-in groups and non-increasing budget\" step; observed 0",
    ]);
    const moved = workflow
      .replace(
        "          FULL_SUITE_PUSH_BEFORE_SHA: ${{ github.event.before }}\n",
        "",
      )
      .replace(
        "          FULL_SUITE_ARTIFACT_DIR: artifacts/full-suite",
        "          FULL_SUITE_ARTIFACT_DIR: artifacts/full-suite\n"
        + "          FULL_SUITE_PUSH_BEFORE_SHA: ${{ github.event.before }}",
      );
    expect(validateCiBudgetBaseWiring(moved)).toContain(
      "\"Validate checked-in groups and non-increasing budget\" env is missing "
      + "FULL_SUITE_PUSH_BEFORE_SHA",
    );
  });

  it("rejects duplicate validation steps and wrong active env values", () => {
    const workflow = fs.readFileSync(WORKFLOW, "utf8");
    const duplicateStep = workflow.replace(
      "      - name: Run full compatibility group",
      [
        "      - name: Validate checked-in groups and non-increasing budget",
        "        env:",
        "          FULL_SUITE_REQUIRE_BUDGET_BASE: \"1\"",
        "          FULL_SUITE_EVENT_NAME: ${{ github.event_name }}",
        "          FULL_SUITE_PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}",
        "          FULL_SUITE_PUSH_BEFORE_SHA: ${{ github.event.before }}",
        "        run: pnpm verify:full-suite-groups",
        "      - name: Run full compatibility group",
      ].join("\n"),
    );
    expect(validateCiBudgetBaseWiring(duplicateStep)).toEqual([
      "full CI requires exactly one active "
      + "\"Validate checked-in groups and non-increasing budget\" step; observed 2",
    ]);
    const wrongValue = workflow.replace(
      "FULL_SUITE_PUSH_BEFORE_SHA: ${{ github.event.before }}",
      "FULL_SUITE_PUSH_BEFORE_SHA: ${{ github.sha }}",
    );
    expect(validateCiBudgetBaseWiring(wrongValue)).toContain(
      "\"Validate checked-in groups and non-increasing budget\" env "
      + "FULL_SUITE_PUSH_BEFORE_SHA must equal ${{ github.event.before }}; "
      + "observed ${{ github.sha }}",
    );
  });

  it("rejects conditional and continue-on-error validation-step bypasses", () => {
    const workflow = fs.readFileSync(WORKFLOW, "utf8");
    const conditional = workflow.replace(
      "        env:\n          FULL_SUITE_REQUIRE_BUDGET_BASE:",
      "        if: false\n        env:\n          FULL_SUITE_REQUIRE_BUDGET_BASE:",
    );
    expect(validateCiBudgetBaseWiring(conditional)).toContain(
      "\"Validate checked-in groups and non-increasing budget\" must not have an if condition",
    );
    const continued = workflow.replace(
      "        env:\n          FULL_SUITE_REQUIRE_BUDGET_BASE:",
      "        continue-on-error: true\n        env:\n          FULL_SUITE_REQUIRE_BUDGET_BASE:",
    );
    expect(validateCiBudgetBaseWiring(continued)).toContain(
      "\"Validate checked-in groups and non-increasing budget\" "
      + "must not have continue-on-error",
    );
  });

  it("requires one exact active validator run command", () => {
    const workflow = fs.readFileSync(WORKFLOW, "utf8");
    const changed = workflow.replace(
      "        run: pnpm verify:full-suite-groups",
      "        run: echo bypassed",
    );
    expect(validateCiBudgetBaseWiring(changed)).toContain(
      "\"Validate checked-in groups and non-increasing budget\" run must equal "
      + "pnpm verify:full-suite-groups; observed echo bypassed",
    );
    const commented = workflow.replace(
      "        run: pnpm verify:full-suite-groups",
      "        # run: pnpm verify:full-suite-groups",
    );
    expect(validateCiBudgetBaseWiring(commented)).toContain(
      "\"Validate checked-in groups and non-increasing budget\" "
      + "requires exactly one active run command; observed 0",
    );
    const missing = workflow.replace(
      "        run: pnpm verify:full-suite-groups\n",
      "",
    );
    expect(validateCiBudgetBaseWiring(missing)).toContain(
      "\"Validate checked-in groups and non-increasing budget\" "
      + "requires exactly one active run command; observed 0",
    );
    const duplicate = workflow.replace(
      "        run: pnpm verify:full-suite-groups",
      "        run: pnpm verify:full-suite-groups\n"
      + "        run: pnpm verify:full-suite-groups",
    );
    expect(validateCiBudgetBaseWiring(duplicate)).toContain(
      "\"Validate checked-in groups and non-increasing budget\" "
      + "requires exactly one active run command; observed 2",
    );
  });

  it("selects the PR base SHA for pull_request budget validation", () => {
    const prBase = "1".repeat(40);
    const pushBefore = "2".repeat(40);
    expect(parseArgs([], {
      FULL_SUITE_REQUIRE_BUDGET_BASE: "1",
      FULL_SUITE_EVENT_NAME: "pull_request",
      FULL_SUITE_PR_BASE_SHA: prBase,
      FULL_SUITE_PUSH_BEFORE_SHA: pushBefore,
    })).toMatchObject({ baseSha: prBase, requireBudgetBase: true });
  });

  it("selects the before SHA for push budget validation", () => {
    const prBase = "1".repeat(40);
    const pushBefore = "2".repeat(40);
    expect(parseArgs([], {
      FULL_SUITE_REQUIRE_BUDGET_BASE: "1",
      FULL_SUITE_EVENT_NAME: "push",
      FULL_SUITE_PR_BASE_SHA: prBase,
      FULL_SUITE_PUSH_BEFORE_SHA: pushBefore,
    })).toMatchObject({ baseSha: pushBefore, requireBudgetBase: true });
  });

  it("fails closed for an empty or all-zero required CI budget base", () => {
    expect(() => parseArgs([], {
      FULL_SUITE_REQUIRE_BUDGET_BASE: "1",
      FULL_SUITE_EVENT_NAME: "pull_request",
      FULL_SUITE_PR_BASE_SHA: "",
    })).toThrow("CI budget validation requires a non-empty PR base or push before SHA");
    expect(() => parseArgs([], {
      FULL_SUITE_REQUIRE_BUDGET_BASE: "1",
      FULL_SUITE_EVENT_NAME: "push",
      FULL_SUITE_PUSH_BEFORE_SHA: "0".repeat(40),
    })).toThrow("CI budget validation rejects the all-zero base SHA");
    expect(() => readBaseManifest("", true)).toThrow(
      "CI budget validation requires a non-empty base SHA",
    );
  });

  it("allows an explicit no-base policy only for local validation", () => {
    expect(parseArgs([], {})).toMatchObject({ baseSha: "", requireBudgetBase: false });
    expect(readBaseManifest("", false)).toBeNull();
  });

  it("rejects a CI timeout that cannot contain runner, setup, and artifact time", () => {
    const { policy } = loadManifest(MANIFEST);
    const workflow = fs.readFileSync(WORKFLOW, "utf8")
      .replace("timeout-minutes: 30", "timeout-minutes: 29");
    expect(validateCiTimeoutPolicy(policy, workflow)).toEqual([
      "full CI job timeout-minutes must be at least 30 "
      + "(1200s runner + 600s setup/post margin); observed 29",
    ]);
  });

  it("rejects silently collapsing the named setup and artifact margin", () => {
    const { policy } = loadManifest(MANIFEST);
    policy.ciSetupPostMarginSeconds = 599;
    expect(validateCiTimeoutPolicy(policy, fs.readFileSync(WORKFLOW, "utf8"))).toEqual([
      "policy.ciSetupPostMarginSeconds must be at least 600 seconds",
    ]);
  });

  it("rejects shard budget increases against the checked-in base", () => {
    const current = loadManifest(MANIFEST);
    const base = structuredClone(current);
    base.groups[0].budgetSeconds -= 1;
    expect(compareBudgets(current, base)).toEqual([
      "core-fsm: budgetSeconds may only decrease (1199 -> 1200)",
    ]);
  });

  it("recursively redacts capability, token, authorization, and GitHub credential values", () => {
    const input = {
      capability_file: "/tmp/raw.cap",
      nested: {
        token: "raw-token",
        message: [
          "Authorization: Basic dXNlcjpwYXNz",
          "Authorization=Basic dXNlcjpwYXNz trailing-secret",
          "Cookie: session=raw-one; other=raw-two",
          "Cookie=session=raw-one; other=raw-two",
          "Bearer raw-value gho_abcdefghijklmnop --capability /tmp/other.cap",
        ].join("\n"),
      },
    };
    const output = redact(input);
    expect(output.capability_file).toBe("<redacted>");
    expect(output.nested.token).toBe("<redacted>");
    expect(output.nested.message).not.toContain("raw-value");
    expect(output.nested.message).not.toContain("gho_");
    expect(output.nested.message).not.toContain("/tmp/other.cap");
    expect(output.nested.message).not.toContain("dXNlcjpwYXNz");
    expect(output.nested.message).not.toContain("trailing-secret");
    expect(output.nested.message).not.toContain("raw-one");
    expect(output.nested.message).not.toContain("raw-two");
    expect(redactString(JSON.stringify(input))).not.toContain("raw-token");
    expect(redactString("Bearer raw-bearer")).toBe("Bearer <redacted>");
    expect(redactString("github_pat_abcdefghijklmnop")).toBe("<redacted>");
  });

  it("redacts authorization and cookie material from streamed console lines", () => {
    let emitted = "";
    const tail = [];
    const sink = makeLineSink({ write: (value) => { emitted += value; } }, tail, 20);
    sink.write(Buffer.from([
      "Authorization: Basic dXNlcjpwYXNz",
      "Authorization=Basic dXNlcjpwYXNz trailing-secret",
      "Authorization: Bearer bearer-secret",
      "Cookie: session=raw-one; other=raw-two",
      "Cookie=session=raw-one; other=raw-two",
      "github_pat_abcdefghijklmnop",
      "--capability /tmp/raw.cap token=raw-token password=raw-password secret=raw-secret",
      "{\"Authorization\":\"Basic dXNlcjpwYXNz\",\"Cookie\":\"session=raw-one; other=raw-two\"}",
    ].join("\n")));
    sink.flush();
    const leaks = /dXNlcjpwYXNz|trailing-secret|bearer-secret|raw-one|raw-two|github_pat_|\/tmp\/raw\.cap|raw-token|raw-password|raw-secret/;
    expect(emitted).not.toMatch(leaks);
    expect(JSON.stringify(tail)).not.toMatch(leaks);
  });

  it("waits through SIGKILL escalation until a TERM-resistant descendant is gone", async () => {
    const childSource = [
      "const marker = 'GOAL_CONTROL_FULL_SUITE_TREE_PROBE'; void marker;",
      "process.on('SIGTERM', () => {});",
      "if (process.send) process.send({ ready: true, pid: process.pid });",
      "setInterval(() => {}, 1000);",
    ].join("");
    const leaderSource = [
      "const { spawn } = require('node:child_process');",
      `const child = spawn(process.execPath, ['-e', ${JSON.stringify(childSource)}], `,
      "{ stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });",
      "child.on('message', (message) => {",
      "  if (message.ready && process.send) {",
      "    process.send({ ready: true, descendantPid: message.pid });",
      "  }",
      "});",
      "setInterval(() => {}, 1000);",
    ].join("");
    const leader = spawn(process.execPath, ["-e", leaderSource], {
      detached: true,
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
    let descendantPid;
    try {
      descendantPid = await new Promise((resolve, reject) => {
        const deadline = setTimeout(
          () => reject(new Error("descendant readiness deadline exceeded")),
          3000,
        );
        leader.once("error", (error) => {
          clearTimeout(deadline);
          reject(error);
        });
        leader.on("message", (message) => {
          if (!message.ready) return;
          clearTimeout(deadline);
          resolve(message.descendantPid);
        });
      });
      const closePromise = new Promise((resolve, reject) => {
        const deadline = setTimeout(
          () => reject(new Error("leader close deadline exceeded")),
          3000,
        );
        leader.once("close", (code, signal) => {
          clearTimeout(deadline);
          resolve({ code, signal });
        });
      });
      const disconnectPromise = leader.connected
        ? new Promise((resolve, reject) => {
          const deadline = setTimeout(
            () => reject(new Error("leader disconnect deadline exceeded")),
            3000,
          );
          leader.once("disconnect", () => {
            clearTimeout(deadline);
            resolve(undefined);
          });
        })
        : Promise.resolve();
      const result = await terminateProcessGroup(leader, {
        termGraceMs: 100,
        killGraceMs: 3000,
        pollIntervalMs: 10,
      });
      expect(result).toMatchObject({ pid: leader.pid, termSent: true, exited: true });
      if (process.platform !== "win32") expect(result.killSent).toBe(true);
      await Promise.all([closePromise, disconnectPromise]);
      expect(leader.connected).toBe(false);
      expect(isProcessAlive(descendantPid)).toBe(false);
    } finally {
      if (leader.pid && isProcessAlive(leader.pid, true)) {
        if (process.platform === "win32") leader.kill("SIGKILL");
        else process.kill(-leader.pid, "SIGKILL");
      }
      if (descendantPid && isProcessAlive(descendantPid)) {
        process.kill(descendantPid, "SIGKILL");
      }
    }
  });

  it("hard-stops a group and updates diagnostics after mocked teardown failure", async () => {
    const artifactRoot = fs.mkdtempSync(path.join(os.tmpdir(), "full-suite-fatal-"));
    const group = {
      id: "mock-group",
      label: "Mock group",
      budgetSeconds: 1200,
      entries: [
        { id: "first", label: "First", file: "__tests__/first.test.ts" },
        { id: "second", label: "Second", file: "__tests__/second.test.ts" },
      ],
    };
    const policy = { slowestItems: 20 };
    const revision = "b".repeat(40);
    const artifactDirectory = path.join(artifactRoot, group.id);
    fs.mkdirSync(artifactDirectory, { recursive: true });
    const error = new Error(
      "Authorization=Basic dXNlcjpwYXNz trailing-cleanup-secret",
    );
    error.terminationState = {
      pid: 4242,
      termSent: true,
      killSent: true,
      exited: false,
    };
    try {
      const cleanup = await settleTimedOutCleanup({
        terminationPromise: Promise.reject(error),
        artifactDirectory,
        group,
        entry: group.entries[0],
        revision,
        activePid: 4242,
        elapsedMs: 1000,
        outputTail: ["Cookie=session=raw-one; other=raw-two"],
      });
      expect(cleanup).toMatchObject({
        status: "fatal",
        termination: {
          pid: 4242,
          termSent: true,
          killSent: true,
          exited: false,
        },
      });
      const diagnosticPath = path.join(
        artifactDirectory,
        "first.failure-diagnostic.json",
      );
      const raw = fs.readFileSync(diagnosticPath, "utf8");
      expect(fs.statSync(diagnosticPath).mode & 0o777).toBe(0o600);
      expect(JSON.parse(raw)).toMatchObject({
        kind: "cleanup-failure",
        timeout_reason: "entry-timeout-process-group-cleanup-failed",
        current_step: "first",
        revision,
        active_pid: 4242,
        termination: { termSent: true, killSent: true, exited: false },
      });
      expect(raw).not.toMatch(
        /dXNlcjpwYXNz|trailing-cleanup-secret|raw-one|raw-two/,
      );

      const calls = [];
      const passed = await runGroup(group, policy, artifactRoot, revision, {
        runEntry: async (_group, entry) => {
          calls.push(entry.id);
          return {
            entry,
            assertions: [],
            durationMs: 1,
            status: cleanup.status,
            code: null,
            signal: null,
            cleanupError: cleanup.cleanupError,
            termination: cleanup.termination,
          };
        },
      });
      expect(passed).toBe(false);
      expect(calls).toEqual(["first"]);
      const timings = JSON.parse(
        fs.readFileSync(path.join(artifactDirectory, "timings.json"), "utf8"),
      );
      expect(timings).toMatchObject({
        status: "fail",
        entries: [{ id: "first", status: "fatal" }],
      });
    } finally {
      fs.rmSync(artifactRoot, { recursive: true, force: true });
    }
  });

  it("requires every discovered test to execute exactly once across semantic entries", () => {
    const entries = [
      { id: "one", file: "__tests__/large.test.ts" },
      { id: "two", file: "__tests__/large.test.ts" },
    ];
    const assertions = new Map([
      ["one", [
        { fullName: "suite alpha", status: "passed" },
        { fullName: "suite beta", status: "pending" },
      ]],
      ["two", [
        { fullName: "suite alpha", status: "pending" },
        { fullName: "suite beta", status: "passed" },
      ]],
    ]);
    expect(verifyPartition(entries, assertions)).toEqual([]);
    assertions.get("two")[0].status = "passed";
    expect(verifyPartition(entries, assertions)).toEqual([
      '__tests__/large.test.ts: expected exactly one execution for "suite alpha", observed 2',
    ]);
    assertions.set("two", assertions.get("two").map((item) => ({ ...item, status: "pending" })));
    expect(verifyPartition(entries, assertions)).toContain(
      "__tests__/large.test.ts: semantic entry two executed no tests",
    );
  });

  it("writes redacted JUnit without capability-bearing failure text", () => {
    const xml = createJUnit(
      { label: "security" },
      [{
        fullName: "fails safely",
        title: "fails safely",
        status: "failed",
        duration: 12,
        failureMessages: [
          "--capability /tmp/raw.cap token=raw-token",
          "Authorization: Basic dXNlcjpwYXNz",
          "Authorization=Basic dXNlcjpwYXNz trailing-secret",
          "Cookie: session=raw-one; other=raw-two",
          "Cookie=session=raw-one; other=raw-two",
        ],
      }],
      20,
    );
    expect(xml).toContain("<testsuites");
    expect(xml).not.toContain("/tmp/raw.cap");
    expect(xml).not.toContain("raw-token");
    expect(xml).not.toMatch(/dXNlcjpwYXNz|trailing-secret|raw-one|raw-two/);
  });

  it("redacts secret-bearing test metadata in JUnit", () => {
    const xml = createJUnit(
      { label: "Cookie=session=raw-group; other=raw-group-two" },
      [{
        ancestorTitles: ["Authorization=Bearer raw-suite trailing-suite-secret"],
        fullName: "token=raw-full-name",
        title: "--capability /tmp/raw-title.cap",
        status: "passed",
        duration: 1,
      }],
      1,
    );
    expect(xml).not.toMatch(/raw-suite|trailing-suite-secret/);
    expect(xml).not.toContain("raw-full-name");
    expect(xml).not.toContain("/tmp/raw-title.cap");
    expect(xml).not.toMatch(/raw-group|raw-group-two/);
  });

  it("redacts secret-bearing timings JSON fields", () => {
    const timings = JSON.stringify(redact({
      label: "Authorization=Basic dXNlcjpwYXNz trailing-secret",
      slowest20: [{
        test: "Cookie=session=raw-one; other=raw-two",
        entry: "token=raw-token",
      }],
    }));
    expect(timings).not.toMatch(
      /dXNlcjpwYXNz|trailing-secret|raw-one|raw-two|raw-token/,
    );
  });

  it("redacts runner START labels and entry/partition diagnostics", () => {
    const secrets = [
      "Authorization=Basic dXNlcjpwYXNz trailing-secret",
      "Cookie=session=raw-one; other=raw-two",
      "Authorization: Bearer bearer-secret",
      "github_pat_abcdefghijklmnop",
      "--capability /tmp/raw.cap",
      "token=raw-token password=raw-password secret=raw-secret",
    ].join("\n");
    const serializedLabel = redactString(JSON.stringify(secrets));
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "full-suite-redaction-"));
    try {
      const entry = writeFailureDiagnostic(directory, "entry.failure-diagnostic.json", {
        kind: "failure",
        output_tail: [secrets],
      });
      const partition = writeFailureDiagnostic(
        directory,
        "partition.failure-diagnostic.json",
        { kind: "partition-coverage", errors: [secrets] },
      );
      const output = [
        serializedLabel,
        fs.readFileSync(entry, "utf8"),
        fs.readFileSync(partition, "utf8"),
      ].join("\n");
      expect(output).not.toMatch(
        /dXNlcjpwYXNz|trailing-secret|raw-one|raw-two|bearer-secret|github_pat_|\/tmp\/raw\.cap|raw-token|raw-password|raw-secret/,
      );
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it("writes a redacted mode-0600 diagnostic when budget expires between entries", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "full-suite-budget-"));
    try {
      const revision = "a".repeat(40);
      const target = writeBetweenEntryBudgetDiagnostic({
        artifactDirectory: directory,
        group: { id: "usability-security" },
        previousEntry: { id: "previous-step" },
        nextEntry: { id: "next-step" },
        revision,
        elapsedMs: 1200001,
        outputTail: [
          "Authorization: Basic dXNlcjpwYXNz",
          "Authorization=Basic dXNlcjpwYXNz trailing-secret",
          "Cookie=session=raw-one; other=raw-two",
        ],
      });
      const raw = fs.readFileSync(target, "utf8");
      const diagnostic = JSON.parse(raw);
      expect(path.basename(target)).toMatch(/\.failure-diagnostic\.json$/);
      expect(fs.statSync(target).mode & 0o777).toBe(0o600);
      expect(diagnostic).toMatchObject({
        kind: "timeout",
        timeout_reason: "group-budget-exhausted-between-entries",
        current_step: "previous-step",
        next_step: "next-step",
        revision,
        active_pid: null,
      });
      expect(raw).not.toMatch(/dXNlcjpwYXNz|trailing-secret|raw-one|raw-two/);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
