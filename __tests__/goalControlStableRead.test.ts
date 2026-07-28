import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "fs";
import { spawn, spawnSync } from "child_process";
import { createRequire } from "module";
import { tmpdir } from "os";
import path from "path";

const nodeRequire = createRequire(import.meta.url);
const {
  adoptRootProtocol,
  canonicalTransactionKey,
  withLock,
  withStableRead,
} = nodeRequire("../scripts/goal-control/store.js") as {
  canonicalTransactionKey: (
    kind: string,
    scope: Record<string, string>,
    stableId: string,
    requestHash: string,
  ) => TransactionKey;
  adoptRootProtocol: <T>(
    root: string,
    validationCallback: (context: {
      root: string;
      state_vector_sha256: string;
      decoder_sha256: string;
      existing_protocol: Record<string, unknown> | null;
      adopting: boolean;
    }) => {
      report: T;
      migration_artifacts: Array<{
        relative_path: string;
        sha256: string;
        body: string | Buffer;
      }>;
    },
    options?: {
      timeoutMilliseconds?: number;
      staleMilliseconds?: number;
      afterMigrationArtifactsInstalled?: () => void;
    },
  ) => {
    adopted: boolean;
    idempotent: boolean;
    protocol: Record<string, unknown>;
    state_vector_sha256?: string;
    source_state_vector_sha256?: string;
    sealed_state_vector_sha256?: string;
    migration_artifacts?: Array<Record<string, unknown>>;
    validation?: T;
  };
  withLock: <T>(
    root: string,
    callback: () => T,
    options?: {
      timeoutMilliseconds?: number;
      staleMilliseconds?: number;
      afterLockOwnerSealed?: () => void;
      afterLockBackingPublished?: () => void;
      afterLockPublished?: () => void;
      afterReaperOwnerSealed?: () => void;
      afterReaperMutexAcquired?: () => void;
      beforeLockRelease?: () => void;
      afterLockReleaseClaimed?: () => void;
      beforeGeneration?: () => void;
      afterGenerationBeforeCallback?: () => void;
      transactionKey?: TransactionKey | (() => TransactionKey);
      authorizeOddRecovery?: (context: {
        generation: number;
        state_vector_sha256: string;
        pristine_payload_vector_sha256: string;
        pre_write_vector_sha256: string | null;
        active_transaction: TransactionKey;
      }) => boolean;
      authorizePristineOddRecovery?: (context: {
        generation: number;
        state_vector_sha256: string;
        pristine_payload_vector_sha256: string;
        pre_write_vector_sha256: string | null;
        active_transaction: TransactionKey;
      }) => boolean;
      protocolBinding?: {
        readProtocol?: (root: string) => unknown;
      };
    },
  ) => T;
  withStableRead: <T>(
    root: string,
    callback: () => T,
    options?: {
      timeoutMilliseconds?: number;
      retryMilliseconds?: number;
      maxTransientRetries?: number;
    },
  ) => T;
};
type TransactionKey = {
  schema_version: 1;
  kind: string;
  scope: Record<string, string>;
  stable_operation_id_sha256: string;
  request_sha256: string;
  key_sha256: string;
};
const {
  canonicalJson,
  hashObject,
  sha256,
} = nodeRequire("../scripts/goal-control/util.js") as {
  canonicalJson: (value: unknown) => string;
  hashObject: (value: unknown) => string;
  sha256: (value: string | Buffer) => string;
};
const storeModulePath = nodeRequire.resolve("../scripts/goal-control/store.js");

const sandboxes: string[] = [];

function sandbox(): string {
  const root = mkdtempSync(path.join(tmpdir(), "goal-control-stable-read-"));
  sandboxes.push(root);
  return root;
}

async function runDuringSealedLiveWriter<T>(
  root: string,
  contender: () => T,
): Promise<{
  childCode: number | null;
  childSignal: NodeJS.Signals | null;
  childStderr: string;
  elapsedMilliseconds: number;
  error: unknown;
  value: T | undefined;
}> {
  withLock(root, () => {});
  const childScript = `
    const { withLock } = require(process.argv[1]);
    const root = process.argv[2];
    withLock(root, () => {
      process.stdout.write("LOCKED\\n");
      Atomics.wait(
        new Int32Array(new SharedArrayBuffer(4)),
        0,
        0,
        5500,
      );
    });
  `;
  const child = spawn(
    process.execPath,
    ["-e", childScript, storeModulePath, root],
    {
      env: {
        ...process.env,
        GOAL_CONTROL_TEST_MODE: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  let childStdout = "";
  let childStderr = "";
  const watchdog = setTimeout(() => {
    childStderr += "\nTEST_CHILD_TIMEOUT_AFTER_35000MS\n";
    child.kill("SIGKILL");
  }, 35_000);
  watchdog.unref();
  const childClosed = new Promise<{
    code: number | null;
    signal: NodeJS.Signals | null;
  }>((resolve) => {
    child.once("close", (code, signal) => {
      clearTimeout(watchdog);
      resolve({ code, signal });
    });
  });
  const childLocked = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.stdout.on("data", (chunk: string) => {
      childStdout += chunk;
      if (childStdout.includes("LOCKED\n")) resolve();
    });
    child.stderr.on("data", (chunk: string) => {
      childStderr += chunk;
    });
    child.once("close", (code, signal) => {
      if (!childStdout.includes("LOCKED\n")) {
        reject(new Error(
          `live writer exited before lock marker: code=${code} signal=${signal} stderr=${childStderr}`,
        ));
      }
    });
  });
  try {
    await childLocked;

    const started = Date.now();
    let error: unknown = null;
    let value: T | undefined;
    try {
      value = contender();
    } catch (caught) {
      error = caught;
    }
    const elapsedMilliseconds = Date.now() - started;
    const childOutcome = await childClosed;
    return {
      childCode: childOutcome.code,
      childSignal: childOutcome.signal,
      childStderr,
      elapsedMilliseconds,
      error,
      value,
    };
  } finally {
    clearTimeout(watchdog);
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
    await childClosed;
  }
}

function transactionKey(
  kind: string,
  stableId: string,
  request: unknown,
  scope: Record<string, string> = {
    goal_id: "goal-store-test",
    task_id: "TASK-1",
  },
): TransactionKey {
  return canonicalTransactionKey(
    kind,
    scope,
    stableId,
    hashObject(request),
  );
}

function writeLegacyGeneration(root: string, generation: number): void {
  const unsigned = {
    schema_version: 1,
    generation,
    updated_at: "2026-07-24T00:00:00.000Z",
  };
  writeFileSync(
    path.join(root, ".generation.json"),
    `${JSON.stringify({
      ...unsigned,
      seal_sha256: hashObject(unsigned),
    }, null, 2)}\n`,
  );
}

function visibleTree(root: string): Array<[string, string]> {
  return readdirSync(root)
    .sort()
    .map((name) => [name, readFileSync(path.join(root, name), "utf8")]);
}

function exactControlTree(root: string): Array<[string, string, string]> {
  const entries: Array<[string, string, string]> = [];
  const visit = (directory: string, relativeDirectory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const relative = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      if (!relativeDirectory && (
        relative === ".lock"
          || relative.startsWith(".lock.")
      )) {
        continue;
      }
      const absolute = path.join(directory, name);
      const stat = lstatSync(absolute);
      const mode = (stat.mode & 0o7777).toString(8);
      if (stat.isDirectory()) {
        entries.push(["directory", relative, mode]);
        visit(absolute, relative);
      } else if (stat.isSymbolicLink()) {
        entries.push(["symlink", relative, `${mode}:${readlinkSync(absolute)}`]);
      } else {
        entries.push([
          "file",
          relative,
          `${mode}:${readFileSync(absolute).toString("base64")}`,
        ]);
      }
    }
  };
  visit(root, "");
  return entries;
}

function withGoalControlTestMode<T>(callback: () => T): T {
  const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
  process.env.GOAL_CONTROL_TEST_MODE = "1";
  try {
    return callback();
  } finally {
    if (previousTestMode === undefined) {
      delete process.env.GOAL_CONTROL_TEST_MODE;
    } else {
      process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
    }
  }
}

function removeLockTransport(root: string): void {
  for (const name of readdirSync(root)) {
    if (name === ".lock" || name.startsWith(".lock.")) {
      rmSync(path.join(root, name), { recursive: true, force: true });
    }
  }
}

function crashAfterGenerationBeforeCallback(
  root: string,
  key: TransactionKey,
): {
  generation: number;
  pre_write_vector_sha256: string;
  updated_at: string;
} {
  if (!existsSync(path.join(root, ".generation.json"))) {
    withLock(root, () => {});
  }
  const markerRoot = sandbox();
  const boundaryMarker = path.join(markerRoot, "generation-boundary");
  const callbackMarker = path.join(markerRoot, "callback-ran");
  const childScript = `
    const fs = require("fs");
    const { withLock } = require(process.argv[1]);
    const root = process.argv[2];
    const boundaryMarker = process.argv[3];
    const callbackMarker = process.argv[4];
    const transactionKey = JSON.parse(process.argv[5]);
    withLock(root, () => {
      fs.writeFileSync(callbackMarker, "callback-ran\\n");
    }, {
      timeoutMilliseconds: 1000,
      staleMilliseconds: 0,
      transactionKey,
      afterGenerationBeforeCallback: () => {
        fs.writeFileSync(boundaryMarker, "generation-sealed\\n");
        process.kill(process.pid, "SIGKILL");
      },
    });
  `;
  const child = spawnSync(
    process.execPath,
    [
      "-e",
      childScript,
      storeModulePath,
      root,
      boundaryMarker,
      callbackMarker,
      JSON.stringify(key),
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        GOAL_CONTROL_TEST_MODE: "1",
      },
    },
  );
  expect(child.error).toBeUndefined();
  expect(child.signal).toBe("SIGKILL");
  expect(readFileSync(boundaryMarker, "utf8")).toBe("generation-sealed\n");
  expect(existsSync(callbackMarker)).toBe(false);
  const seal = JSON.parse(readFileSync(
    path.join(root, ".generation.json"),
    "utf8",
  )) as {
    schema_version: number;
    generation: number;
    active_transaction: TransactionKey;
    pre_write_vector_sha256: string;
    updated_at: string;
  };
  expect(seal).toMatchObject({
    schema_version: 3,
    active_transaction: {
      key_sha256: key.key_sha256,
    },
  });
  expect(seal.generation % 2).toBe(1);
  expect(seal.pre_write_vector_sha256)
    .toMatch(/^sha256:[0-9a-f]{64}$/);
  return {
    generation: seal.generation,
    pre_write_vector_sha256: seal.pre_write_vector_sha256,
    updated_at: seal.updated_at,
  };
}

function migrationValidationResult<T>(
  context: {
    state_vector_sha256: string;
    decoder_sha256: string;
  },
  report: T,
  sourceBodies: Buffer[] = [],
): {
  report: T;
  migration_artifacts: Array<{
    relative_path: string;
    sha256: string;
    body: string | Buffer;
  }>;
} {
  const sourceArtifacts = sourceBodies.map((body) => {
    const digest = `sha256:${sha256(body)}`;
    return {
      relative_path: `.legacy-evidence-sources.v1/${digest.slice("sha256:".length)}.artifact`,
      sha256: digest,
      body,
    };
  });
  const unsigned = {
    schema_version: 1,
    kind: "LEGACY_EVIDENCE_EVENT_BINDINGS",
    controller_decoder_sha256: context.decoder_sha256,
    source_state_vector_sha256: context.state_vector_sha256,
    events: {},
  };
  const indexBody = `${canonicalJson({
    ...unsigned,
    index_sha256: hashObject(unsigned),
  })}\n`;
  return {
    report,
    migration_artifacts: [
      {
        relative_path: ".legacy-evidence-anchors.v1.json",
        sha256: `sha256:${sha256(indexBody)}`,
        body: indexBody,
      },
      ...sourceArtifacts,
    ],
  };
}

function decoderDependencyClosure(codeRoot: string): string[] {
  const pending = [
    "store.js",
    "validation.js",
    "fsm.js",
    "goal.js",
    "evidence.js",
    "resources.js",
    "preflight.js",
    "migration.js",
    ...readdirSync(path.join(codeRoot, "schemas"))
      .filter((name) => name.endsWith(".json"))
      .sort()
      .map((name) => `schemas/${name}`),
  ];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const relative = pending.shift();
    if (relative === undefined || visited.has(relative)) continue;
    visited.add(relative);
    if (!relative.endsWith(".js")) continue;
    const absolute = path.join(codeRoot, relative);
    const source = readFileSync(absolute, "utf8");
    const localRequire = /\brequire\s*\(\s*(["'])(\.[^"']+)\1\s*\)/g;
    let match: RegExpExecArray | null;
    while ((match = localRequire.exec(source)) !== null) {
      const requested = path.resolve(path.dirname(absolute), match[2]);
      const candidates = path.extname(requested)
        ? [requested]
        : [
          requested,
          `${requested}.js`,
          `${requested}.json`,
          path.join(requested, "index.js"),
          path.join(requested, "index.json"),
        ];
      const dependency = candidates.find((candidate) => (
        existsSync(candidate) && statSync(candidate).isFile()
      ));
      if (dependency === undefined) {
        throw new Error(`unresolved local dependency ${match[2]} from ${relative}`);
      }
      pending.push(path.relative(codeRoot, dependency).split(path.sep).join("/"));
    }
  }
  return [...visited].sort();
}

afterEach(() => {
  for (const root of sandboxes.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("goal-control zero-write stable reads", () => {
  it("retries when a complete writer cycle occurs inside the read callback", () => {
    const root = sandbox();
    const stateFile = path.join(root, "state.txt");
    writeFileSync(stateFile, "old\n");
    let callbackCount = 0;
    let writerInjected = false;

    const observed = withStableRead(root, () => {
      callbackCount += 1;
      const before = readFileSync(stateFile, "utf8");
      if (!writerInjected) {
        writerInjected = true;
        withLock(root, () => {
          writeFileSync(stateFile, "new\n");
        });
      }
      const after = readFileSync(stateFile, "utf8");
      return { before, after };
    }, {
      timeoutMilliseconds: 1_000,
      retryMilliseconds: 1,
    });

    expect(callbackCount).toBe(2);
    expect(observed).toEqual({ before: "new\n", after: "new\n" });
    const seal = JSON.parse(
      readFileSync(path.join(root, ".generation.json"), "utf8"),
    ) as { generation: number; seal_sha256: string };
    expect(seal.generation).toBe(2);
    expect(seal.seal_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("does not create a generation seal or otherwise write during a legacy read", () => {
    const root = sandbox();
    writeFileSync(path.join(root, "state.txt"), "stable\n");
    const before = visibleTree(root);

    expect(withStableRead(root, () => readFileSync(
      path.join(root, "state.txt"),
      "utf8",
    ))).toBe("stable\n");

    expect(visibleTree(root)).toEqual(before);
    expect(existsSync(path.join(root, ".generation.json"))).toBe(false);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("upgrades a legacy even generation to v3 and clears its transaction/vector binding", () => {
    const root = sandbox();
    writeLegacyGeneration(root, 8);
    const key = transactionKey(
      "GOAL_EVENT",
      "legacy-even-upgrade",
      { event_id: "legacy-even-upgrade" },
    );

    expect(withLock(root, () => "committed", {
      transactionKey: key,
    })).toBe("committed");

    const generation = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      schema_version: number;
      generation: number;
      active_transaction: TransactionKey | null;
      seal_sha256: string;
    };
    expect(generation).toMatchObject({
      schema_version: 3,
      generation: 10,
      active_transaction: null,
      pre_write_vector_sha256: null,
    });
    const unsigned = { ...generation } as Record<string, unknown>;
    delete unsigned.seal_sha256;
    expect(generation.seal_sha256).toBe(hashObject(unsigned));
  });

  it("never automatically recovers a legacy v1 odd generation", () => {
    const root = sandbox();
    writeLegacyGeneration(root, 9);
    const before = exactControlTree(root);
    let authorizationCalled = false;

    let failure: unknown = null;
    try {
      withLock(root, () => "must-not-run", {
        transactionKey: transactionKey(
          "GOAL_EVENT",
          "legacy-odd",
          { event_id: "legacy-odd" },
        ),
        authorizeOddRecovery: () => {
          authorizationCalled = true;
          return true;
        },
      });
    } catch (error) {
      failure = error;
    }

    expect(failure).toMatchObject({ code: "AUDITED_REPAIR_ONLY" });
    expect(authorizationCalled).toBe(false);
    expect(exactControlTree(root)).toEqual(before);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("requires a transaction key for a pristine recovery hook without writing", () => {
    const root = sandbox();
    const before = exactControlTree(root);
    let callbackCalled = false;
    let authorizationCalled = false;
    let failure: unknown = null;

    try {
      withLock(root, () => {
        callbackCalled = true;
      }, {
        authorizePristineOddRecovery: () => {
          authorizationCalled = true;
          return true;
        },
      });
    } catch (error) {
      failure = error;
    }

    expect(failure).toMatchObject({ code: "TRANSACTION_KEY_REQUIRED" });
    expect(callbackCalled).toBe(false);
    expect(authorizationCalled).toBe(false);
    expect(exactControlTree(root)).toEqual(before);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("recovers a true SIGKILL at the generation-to-callback boundary and preserves the binding through stale reap", () => {
    const root = sandbox();
    const key = transactionKey(
      "GOAL_EVENT",
      "pristine-sigkill",
      { event_id: "pristine-sigkill", request: "exact" },
    );
    const crashed = crashAfterGenerationBeforeCallback(root, key);
    let observedRetainedGeneration = 0;
    let observedPreWriteVector = "";
    let observedRetainedUpdatedAt = "";
    const committed = path.join(
      root,
      "goals",
      "goal-store-test",
      "events",
      "TASK-1",
      "pristine-sigkill.json",
    );

    const result = withLock(root, () => {
      mkdirSync(path.dirname(committed), { recursive: true });
      writeFileSync(committed, "committed-after-pristine-retry\n");
      return "recovered";
    }, {
      timeoutMilliseconds: 1_000,
      staleMilliseconds: 0,
      beforeGeneration: () => {
        const fenced = JSON.parse(readFileSync(
          path.join(root, ".generation.json"),
          "utf8",
        )) as {
          generation: number;
          pre_write_vector_sha256: string;
          updated_at: string;
        };
        observedRetainedGeneration = fenced.generation;
        observedPreWriteVector = fenced.pre_write_vector_sha256;
        observedRetainedUpdatedAt = fenced.updated_at;
      },
      transactionKey: key,
      authorizePristineOddRecovery: () => true,
    });

    expect(result).toBe("recovered");
    expect(observedRetainedGeneration).toBe(crashed.generation);
    expect(observedPreWriteVector).toBe(crashed.pre_write_vector_sha256);
    expect(observedRetainedUpdatedAt).toBe(crashed.updated_at);
    expect(readFileSync(committed, "utf8"))
      .toBe("committed-after-pristine-retry\n");
    const completed = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      schema_version: number;
      generation: number;
      active_transaction: null;
      pre_write_vector_sha256: null;
      updated_at: string;
    };
    expect(completed).toMatchObject({
      schema_version: 3,
      generation: crashed.generation + 1,
      active_transaction: null,
      pre_write_vector_sha256: null,
    });
    expect(completed.updated_at).not.toBe(crashed.updated_at);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it.each([
    {
      label: "wrong stable operation key",
      failureCode: "STORE_TRANSACTION_MISMATCH",
      requestedKey: (exact: TransactionKey) => transactionKey(
        "GOAL_EVENT",
        "different-operation",
        { event_id: "pristine-auth", request: "exact" },
      ),
      beforeGeneration: () => {},
    },
    {
      label: "same operation with a different request",
      failureCode: "STORE_TRANSACTION_MISMATCH",
      requestedKey: (exact: TransactionKey) => transactionKey(
        exact.kind,
        "pristine-auth",
        { event_id: "pristine-auth", request: "different" },
      ),
      beforeGeneration: () => {},
    },
    {
      label: "wrong caller capability",
      failureCode: "CAPABILITY_INVALID",
      requestedKey: (exact: TransactionKey) => exact,
      beforeGeneration: () => {
        const error = new Error("wrong caller capability") as Error & {
          code?: string;
        };
        error.code = "CAPABILITY_INVALID";
        throw error;
      },
    },
  ])("keeps a pristine odd root byte-identical for $label", ({
    failureCode,
    requestedKey,
    beforeGeneration,
  }) => {
    const root = sandbox();
    const exactKey = transactionKey(
      "GOAL_EVENT",
      "pristine-auth",
      { event_id: "pristine-auth", request: "exact" },
    );
    crashAfterGenerationBeforeCallback(root, exactKey);
    removeLockTransport(root);
    const before = exactControlTree(root);
    let callbackCalled = false;
    let pristineAuthorizationCalled = false;
    let failure: unknown = null;

    try {
      withLock(root, () => {
        callbackCalled = true;
      }, {
        beforeGeneration,
        transactionKey: requestedKey(exactKey),
        authorizePristineOddRecovery: () => {
          pristineAuthorizationCalled = true;
          return true;
        },
      });
    } catch (error) {
      failure = error;
    }

    expect(failure).toMatchObject({ code: failureCode });
    expect(callbackCalled).toBe(false);
    if (failureCode === "CAPABILITY_INVALID") {
      expect(pristineAuthorizationCalled).toBe(false);
    }
    expect(exactControlTree(root)).toEqual(before);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it.each([
    {
      label: "transient payload bytes",
      mutate: (root: string) => {
        const staging = path.join(root, ".init-pristine-vector-drift");
        mkdirSync(staging, { mode: 0o700 });
        writeFileSync(path.join(staging, ".payload.tmp-drift"), "drift\n");
      },
    },
    {
      label: "authoritative directory mode",
      mutate: (root: string) => {
        chmodSync(path.join(root, "goals"), 0o711);
      },
    },
  ])("rejects pristine recovery after $label drift", ({ mutate }) => {
    const root = sandbox();
    mkdirSync(path.join(root, "goals"), { mode: 0o700 });
    const key = transactionKey(
      "GOAL_EVENT",
      "pristine-vector-drift",
      { event_id: "pristine-vector-drift" },
    );
    crashAfterGenerationBeforeCallback(root, key);
    removeLockTransport(root);
    mutate(root);
    const drifted = exactControlTree(root);
    let callbackCalled = false;
    let failure: unknown = null;

    try {
      withLock(root, () => {
        callbackCalled = true;
      }, {
        beforeGeneration: () => {},
        transactionKey: key,
        authorizePristineOddRecovery: () => true,
      });
    } catch (error) {
      failure = error;
    }

    expect(failure).toMatchObject({
      code: "STORE_PRISTINE_RECOVERY_VECTOR_MISMATCH",
    });
    expect(callbackCalled).toBe(false);
    expect(exactControlTree(root)).toEqual(drifted);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("keeps a v2 odd seal witness-only because it has no pristine vector", () => {
    const root = sandbox();
    withLock(root, () => {});
    const key = transactionKey(
      "GOAL_EVENT",
      "v2-witness-only",
      { event_id: "v2-witness-only" },
    );
    const current = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as { generation: number };
    const unsigned = {
      schema_version: 2,
      generation: current.generation + 1,
      active_transaction: key,
      updated_at: "2026-07-24T00:00:00.000Z",
    };
    writeFileSync(
      path.join(root, ".generation.json"),
      `${JSON.stringify({
        ...unsigned,
        seal_sha256: hashObject(unsigned),
      }, null, 2)}\n`,
    );
    const before = exactControlTree(root);
    let callbackCalled = false;
    let failure: unknown = null;

    try {
      withLock(root, () => {
        callbackCalled = true;
      }, {
        transactionKey: key,
        authorizePristineOddRecovery: () => true,
      });
    } catch (error) {
      failure = error;
    }

    expect(failure).toMatchObject({
      code: "STORE_PRISTINE_RECOVERY_UNAVAILABLE",
    });
    expect(callbackCalled).toBe(false);
    expect(exactControlTree(root)).toEqual(before);
  });

  it("preserves a v2 odd transaction timestamp across a rejected foreign retry and refreshes it only on even completion", () => {
    const root = sandbox();
    const exactKey = transactionKey(
      "GOAL_EVENT",
      "v2-stale-fence",
      { event_id: "v2-stale-fence", request: "exact" },
    );
    const crashed = crashAfterGenerationBeforeCallback(root, exactKey);
    const originalUpdatedAt = "2000-01-01T00:00:00.000Z";
    const unsigned = {
      schema_version: 2,
      generation: crashed.generation,
      active_transaction: exactKey,
      updated_at: originalUpdatedAt,
    };
    const v2FenceReplacement = path.join(
      root,
      ".generation.v2-fence-replacement.json",
    );
    writeFileSync(
      v2FenceReplacement,
      `${JSON.stringify({
        ...unsigned,
        seal_sha256: hashObject(unsigned),
      }, null, 2)}\n`,
      { mode: 0o600 },
    );
    renameSync(
      v2FenceReplacement,
      path.join(root, ".generation.json"),
    );

    let wrongError: unknown = null;
    try {
      withLock(root, () => {
        throw new Error("wrong transaction callback must not run");
      }, {
        timeoutMilliseconds: 1_000,
        staleMilliseconds: 0,
        transactionKey: transactionKey(
          "GOAL_EVENT",
          "v2-stale-fence",
          { event_id: "v2-stale-fence", request: "different" },
        ),
      });
    } catch (error) {
      wrongError = error;
    }
    expect(wrongError).toMatchObject({
      code: "STORE_TRANSACTION_MISMATCH",
    });
    const fenced = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      schema_version: number;
      generation: number;
      active_transaction: TransactionKey;
      updated_at: string;
    };
    expect(fenced).toMatchObject({
      schema_version: 2,
      generation: crashed.generation,
      active_transaction: {
        key_sha256: exactKey.key_sha256,
      },
    });
    expect(fenced.updated_at).toBe(originalUpdatedAt);

    expect(withLock(root, () => "recovered", {
      transactionKey: exactKey,
      authorizeOddRecovery: () => true,
    })).toBe("recovered");
    const completed = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      schema_version: number;
      generation: number;
      active_transaction: null;
      pre_write_vector_sha256: null;
      updated_at: string;
    };
    expect(completed).toMatchObject({
      schema_version: 3,
      generation: crashed.generation + 1,
      active_transaction: null,
      pre_write_vector_sha256: null,
    });
    expect(completed.updated_at).not.toBe(originalUpdatedAt);
  });

  it("marks an undeclared writer crash as audited-repair-only", () => {
    const root = sandbox();
    const witness = path.join(root, "goals", "unkeyed", "partial.json");
    withLock(root, () => {});

    expect(() => withLock(root, () => {
      mkdirSync(path.dirname(witness), { recursive: true });
      writeFileSync(witness, "partial\n");
      throw new Error("unkeyed partial write");
    })).toThrow("unkeyed partial write");

    const generation = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey;
    };
    expect(generation.generation % 2).toBe(1);
    expect(generation.active_transaction.kind).toBe("AUDITED_REPAIR_ONLY");
    const before = exactControlTree(root);
    let failure: unknown = null;
    try {
      withLock(root, () => "must-not-run", {
        transactionKey: transactionKey(
          "GOAL_EVENT",
          "claimed-retry",
          { event_id: "claimed-retry" },
        ),
        authorizeOddRecovery: () => true,
      });
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({
      code: "STORE_TRANSACTION_MISMATCH",
    });
    expect(exactControlTree(root)).toEqual(before);
  });

  it("binds odd recovery to one cross-domain operation before caller authorization", () => {
    const root = sandbox();
    const resourceWitness = path.join(
      root,
      "resources",
      "events",
      "resource-a.json",
    );
    const resourceKey = transactionKey(
      "RESOURCE_ACQUIRE",
      "resource-a",
      { event_id: "resource-a", resource: "preview-port:8123" },
      { goal_id: "goal-cross-op", task_id: "TASK-A" },
    );
    const historicalGoalEventKey = transactionKey(
      "GOAL_EVENT",
      "historical-goal-event-b",
      { event_id: "historical-goal-event-b", type: "HEARTBEAT" },
      { goal_id: "goal-cross-op", task_id: "TASK-B" },
    );
    withLock(root, () => {});

    expect(() => withLock(root, () => {
      mkdirSync(path.dirname(resourceWitness), { recursive: true });
      writeFileSync(resourceWitness, "resource-a-durable\n");
      throw new Error("resource response lost");
    }, { transactionKey: resourceKey })).toThrow("resource response lost");
    const oddTree = exactControlTree(root);

    let historicalAuthorizationCalled = false;
    let historicalFailure: unknown = null;
    try {
      withLock(root, () => "must-not-run", {
        beforeGeneration: () => {
          expect(readFileSync(resourceWitness, "utf8"))
            .toBe("resource-a-durable\n");
        },
        transactionKey: historicalGoalEventKey,
        authorizeOddRecovery: () => {
          historicalAuthorizationCalled = true;
          return true;
        },
      });
    } catch (error) {
      historicalFailure = error;
    }
    expect(historicalFailure).toMatchObject({
      code: "STORE_TRANSACTION_MISMATCH",
    });
    expect(historicalAuthorizationCalled).toBe(false);
    expect(exactControlTree(root)).toEqual(oddTree);

    const wrongResourceKey = transactionKey(
      "RESOURCE_ACQUIRE",
      "resource-a",
      { event_id: "resource-a", resource: "preview-port:9999" },
      { goal_id: "goal-cross-op", task_id: "TASK-A" },
    );
    expect(() => withLock(root, () => "must-not-run", {
      transactionKey: wrongResourceKey,
      authorizeOddRecovery: () => true,
    })).toThrow(/绑定了不同 transaction|transaction key 不匹配/);
    expect(exactControlTree(root)).toEqual(oddTree);

    expect(withLock(root, () => "resource-a-recovered", {
      beforeGeneration: () => {
        expect(readFileSync(resourceWitness, "utf8"))
          .toBe("resource-a-durable\n");
      },
      transactionKey: resourceKey,
      authorizeOddRecovery: () => true,
    })).toBe("resource-a-recovered");
    expect(JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    ))).toMatchObject({
      active_transaction: null,
    });
  });

  it("vectors every authoritative control artifact against generation-less legacy writes", () => {
    const root = sandbox();
    const authoritative = [
      "goals/goal-vector/manifest.json",
      "goals/goal-vector/goal.json",
      "goals/goal-vector/events/TASK-1/00000001-event.json",
      "goals/goal-vector/event-heads/TASK-1.json",
      "goals/goal-vector/control-events/00000001.json",
      "goals/goal-vector/control-head.json",
      "goals/goal-vector/capabilities/dev.cap",
      "goals/goal-vector/evidence/TASK-1/evidence.json",
      "goals/goal-vector/evidence/TASK-1/preflight.json",
      "goals/goal-vector/launches/TASK-1/launch.json",
      "goals/goal-vector/recovery-handoffs/TASK-1/snapshots/s1/snapshot.json",
      "goals/goal-vector/recovery-handoffs/TASK-1/import-receipts/r1.json",
      "resources/events/00000001-event.json",
      "resources/head.json",
    ].map((relative) => path.join(root, relative));
    for (const file of authoritative) {
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, "old\n");
    }

    for (const file of authoritative) {
      let callbackCount = 0;
      let legacyWriterInjected = false;
      const observed = withStableRead(root, () => {
        callbackCount += 1;
        const before = readFileSync(file, "utf8");
        if (!legacyWriterInjected) {
          legacyWriterInjected = true;
          const legacyLock = path.join(root, ".lock");
          mkdirSync(legacyLock);
          writeFileSync(path.join(legacyLock, "owner.json"), `${JSON.stringify({
            pid: process.pid,
            acquired_at: new Date().toISOString(),
          })}\n`);
          writeFileSync(file, "new\n");
          rmSync(legacyLock, { recursive: true, force: true });
        }
        return before;
      }, {
        timeoutMilliseconds: 1_000,
        retryMilliseconds: 1,
      });
      expect(callbackCount).toBe(2);
      expect(observed).toBe("new\n");
    }
    expect(existsSync(path.join(root, ".generation.json"))).toBe(false);
  });

  it("keeps an odd generation but releases its lock after an authoritative half-write", () => {
    const root = sandbox();
    const halfWrite = path.join(root, "goals", "goal-half", "events", "TASK-1", "half.json");
    let thrown: unknown = null;

    try {
      withLock(root, () => {
        mkdirSync(path.dirname(halfWrite), { recursive: true });
        writeFileSync(halfWrite, "half-installed\n");
        throw new Error("injected partial transaction");
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({ message: "injected partial transaction" });
    const generation = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as { generation: number };
    expect(generation.generation % 2).toBe(1);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
    expect(existsSync(path.join(root, ".store-protocol.json"))).toBe(false);
  });

  it("reports an unlocked odd-generation crash marker immediately", () => {
    const root = sandbox();
    expect(() => withLock(root, () => {
      const file = path.join(root, "goals", "goal-crash", "intent.json");
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, "durable half transaction\n");
      throw new Error("simulated writer crash");
    })).toThrow("simulated writer crash");
    expect(existsSync(path.join(root, ".lock"))).toBe(false);

    const started = Date.now();
    let failure: unknown = null;
    try {
      withStableRead(root, () => "must-not-run");
    } catch (error) {
      failure = error;
    }
    expect(Date.now() - started).toBeLessThan(250);
    expect(failure).toMatchObject({
      code: "STORE_REPAIR_REQUIRED",
      details: {
        writer_crash_marker: true,
        state_verified: false,
      },
    });
    expect(String((failure as Error).message)).toContain("stable operation ID");
  });

  it("leaves every pre-existing odd-generation byte unchanged without explicit exact-recovery authorization", () => {
    const root = sandbox();
    const key = transactionKey(
      "GOAL_EVENT",
      "event-1",
      { event_id: "event-1", action: "install durable operation" },
    );
    const durableWitness = path.join(
      root,
      "goals",
      "goal-odd-auth",
      "events",
      "TASK-1",
      "durable-operation.json",
    );
    withLock(root, () => {});
    expect(() => withLock(root, () => {
      mkdirSync(path.dirname(durableWitness), { recursive: true });
      writeFileSync(durableWitness, "stable-operation-id=event-1\n");
      throw new Error("response lost after durable operation");
    }, { transactionKey: key })).toThrow(
      "response lost after durable operation",
    );
    const before = exactControlTree(root);
    let callbackCalled = false;

    let failure: unknown = null;
    try {
      withLock(root, () => {
        callbackCalled = true;
      }, { transactionKey: key });
    } catch (error) {
      failure = error;
    }

    expect(failure).toMatchObject({ code: "STORE_REPAIR_REQUIRED" });
    expect(callbackCalled).toBe(false);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
    expect(exactControlTree(root)).toEqual(before);
    expect(JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )).generation % 2).toBe(1);
  });

  it("repairs an odd generation only after a read-only preflight proves the exact durable witness", () => {
    const root = sandbox();
    const key = transactionKey(
      "GOAL_EVENT",
      "event-1",
      { event_id: "event-1", action: "install durable operation" },
    );
    const durableWitness = path.join(
      root,
      "goals",
      "goal-odd-exact",
      "events",
      "TASK-1",
      "event-1.json",
    );
    withLock(root, () => {});
    expect(() => withLock(root, () => {
      mkdirSync(path.dirname(durableWitness), { recursive: true });
      writeFileSync(durableWitness, "stable-operation-id=event-1\n");
      throw new Error("response lost after durable operation");
    }, { transactionKey: key })).toThrow(
      "response lost after durable operation",
    );
    let exactWitnessProved = false;

    const result = withLock(root, () => "recovered", {
      beforeGeneration: () => {
        exactWitnessProved = readFileSync(durableWitness, "utf8")
          === "stable-operation-id=event-1\n";
      },
      authorizeOddRecovery: () => exactWitnessProved,
      transactionKey: key,
    });

    expect(result).toBe("recovered");
    expect(JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )).generation % 2).toBe(0);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("detects transient or directory writes made by an odd-generation recovery preflight", () => {
    const root = sandbox();
    const key = transactionKey(
      "GOAL_EVENT",
      "event-dirty",
      { event_id: "event-dirty", action: "install durable operation" },
    );
    withLock(root, () => {});
    expect(() => withLock(root, () => {
      const durableWitness = path.join(root, "goals", "goal-odd-dirty", "event.json");
      mkdirSync(path.dirname(durableWitness), { recursive: true });
      writeFileSync(durableWitness, "durable\n");
      throw new Error("response lost after durable operation");
    }, { transactionKey: key })).toThrow(
      "response lost after durable operation",
    );

    expect(() => withLock(root, () => "must-not-run", {
      beforeGeneration: () => {
        const staging = path.join(root, ".init-unauthorized");
        mkdirSync(staging, { mode: 0o711 });
        writeFileSync(path.join(staging, ".payload.tmp-preflight"), "mutated\n");
      },
      authorizeOddRecovery: () => true,
      transactionKey: key,
    })).toThrow(
      /STORE_ODD_RECOVERY_PREFLIGHT_MUTATED|preflight 改写|transaction preflight/,
    );
    expect(JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )).generation % 2).toBe(1);
    expect(existsSync(path.join(root, ".lock"))).toBe(true);
  });

  it("closes a rejection-only callback error without treating its audit log as a half-write", () => {
    const root = sandbox();
    let thrown: unknown = null;

    try {
      withLock(root, () => {
        const rejectionDir = path.join(
          root,
          "goals",
          "_unknown",
          "rejections",
          "_unknown",
        );
        mkdirSync(rejectionDir, { recursive: true });
        writeFileSync(path.join(rejectionDir, "rejected.json"), "audit-only\n");
        const error = new Error("expected validation rejection") as Error & {
          code?: string;
        };
        error.code = "INVALID_EVENT";
        throw error;
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({ code: "INVALID_EVENT" });
    const generation = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as { generation: number };
    expect(generation.generation % 2).toBe(0);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
    expect(existsSync(path.join(root, ".store-protocol.json"))).toBe(false);
  });

  it("never reaps an unsealed empty legacy lock by guessing from directory mtime", () => {
    const root = sandbox();
    const lockDir = path.join(root, ".lock");
    mkdirSync(lockDir);
    let callbackCalled = false;
    let thrown: unknown = null;

    try {
      withLock(root, () => {
        callbackCalled = true;
      }, {
        timeoutMilliseconds: 60,
        staleMilliseconds: 0,
      });
    } catch (error) {
      thrown = error;
    }

    expect(callbackCalled).toBe(false);
    expect(thrown).toMatchObject({ code: "LOCK_TIMEOUT" });
    expect(existsSync(lockDir)).toBe(true);
    expect(existsSync(path.join(lockDir, "owner.json"))).toBe(false);
    expect(existsSync(path.join(root, ".store-protocol.json"))).toBe(false);
  });

  it("waits on a live v2 writer without decoding protocol authority outside the lock", () => {
    const root = sandbox();
    let protocolReads = 0;
    let nestedError: unknown = null;
    let stableReadCalls = 0;
    let stableReadError: unknown = null;

    withLock(root, () => {
      try {
        withLock(root, () => {
          throw new Error("nested writer must not acquire the live lock");
        }, {
          timeoutMilliseconds: 75,
          protocolBinding: {
            readProtocol: () => {
              protocolReads += 1;
              throw new Error(
                "live-lock contender must not decode protocol authority",
              );
            },
          },
        });
      } catch (error) {
        nestedError = error;
      }
      try {
        withStableRead(root, () => {
          stableReadCalls += 1;
        }, {
          timeoutMilliseconds: 75,
          retryMilliseconds: 5,
        });
      } catch (error) {
        stableReadError = error;
      }

      expect(nestedError).toMatchObject({ code: "LOCK_TIMEOUT" });
      expect(protocolReads).toBe(0);
      expect(stableReadError).toMatchObject({ code: "LOCK_TIMEOUT" });
      expect(stableReadCalls).toBe(0);
    });
  });

  it("gives a sealed-compatible live v2 writer bounded default grace beyond five seconds", async () => {
    const root = sandbox();
    let callbackCalled = false;
    const result = await runDuringSealedLiveWriter(root, () => (
      withLock(root, () => {
        callbackCalled = true;
        return "writer-acquired";
      })
    ));

    expect(result).toMatchObject({
      childCode: 0,
      childSignal: null,
      childStderr: "",
      error: null,
      value: "writer-acquired",
    });
    expect(callbackCalled).toBe(true);
    expect(result.elapsedMilliseconds).toBeGreaterThanOrEqual(5_000);
    expect(result.elapsedMilliseconds).toBeLessThan(30_000);
  }, 45_000);

  it("gives stable reads the same bounded grace for a sealed-compatible live writer", async () => {
    const root = sandbox();
    let callbackCalls = 0;
    const result = await runDuringSealedLiveWriter(root, () => (
      withStableRead(root, () => {
        callbackCalls += 1;
        return "stable-read";
      })
    ));

    expect(result).toMatchObject({
      childCode: 0,
      childSignal: null,
      childStderr: "",
      error: null,
      value: "stable-read",
    });
    expect(callbackCalls).toBe(1);
    expect(result.elapsedMilliseconds).toBeGreaterThanOrEqual(5_000);
    expect(result.elapsedMilliseconds).toBeLessThan(30_000);
  }, 45_000);

  it("closes a rejected transaction after only rebuilding a repairable head", () => {
    const root = sandbox();
    const resourceHead = path.join(root, "resources", "head.json");
    let thrown: unknown = null;
    withLock(root, () => {});

    try {
      withLock(root, () => {
        mkdirSync(path.dirname(resourceHead), { recursive: true });
        writeFileSync(resourceHead, "repair-only head\n");
        const error = new Error("expected resource validation rejection") as Error & {
          code?: string;
        };
        error.code = "RESOURCE_NOT_DECLARED";
        throw error;
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({ code: "RESOURCE_NOT_DECLARED" });
    const generation = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as { generation: number };
    expect(generation.generation % 2).toBe(0);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
    expect(existsSync(resourceHead)).toBe(true);
  });

  it("requires audited migration before sealing a non-empty v1 control root", () => {
    const root = sandbox();
    const legacyEvent = path.join(
      root,
      "goals",
      "goal-legacy",
      "events",
      "TASK-1",
      "00000001-old.json",
    );
    mkdirSync(path.dirname(legacyEvent), { recursive: true });
    writeFileSync(legacyEvent, "{}\n");
    let callbackCalled = false;
    let thrown: unknown = null;

    try {
      withLock(root, () => {
        callbackCalled = true;
      });
    } catch (error) {
      thrown = error;
    }

    expect(callbackCalled).toBe(false);
    expect(thrown).toMatchObject({
      code: "STORE_PROTOCOL_MIGRATION_REQUIRED",
    });
    expect(existsSync(path.join(root, ".store-protocol.json"))).toBe(false);
    expect(existsSync(path.join(root, ".generation.json"))).toBe(false);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("adopts a non-empty v1 root only after a read-only replay validator passes", () => {
    const root = sandbox();
    const legacyEvent = path.join(
      root,
      "goals",
      "goal-adopt",
      "events",
      "TASK-1",
      "00000001-old.json",
    );
    mkdirSync(path.dirname(legacyEvent), { recursive: true });
    writeFileSync(legacyEvent, "legacy-authoritative-bytes\n");
    let validatorCalls = 0;

    const adopted = adoptRootProtocol(root, (context) => {
      validatorCalls += 1;
      expect(context.root).toBe(root);
      expect(context.state_vector_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(context.decoder_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(context.existing_protocol).toBeNull();
      expect(context.adopting).toBe(true);
      expect(readFileSync(legacyEvent, "utf8")).toBe(
        "legacy-authoritative-bytes\n",
      );
      return migrationValidationResult(context, {
        goals_replayed: ["goal-adopt"],
        resources_replayed: true,
      });
    });

    expect(validatorCalls).toBe(1);
    expect(adopted).toMatchObject({
      adopted: true,
      idempotent: false,
      validation: {
        goals_replayed: ["goal-adopt"],
        resources_replayed: true,
      },
    });
    expect(adopted.protocol.controller_decoder_sha256).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    expect(adopted.protocol).toMatchObject({
      schema_version: 3,
      migration_source_state_vector_sha256:
        adopted.source_state_vector_sha256,
      migration_artifacts: [{
        relative_path: ".legacy-evidence-anchors.v1.json",
      }],
    });
    expect(adopted.sealed_state_vector_sha256).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    expect(adopted.sealed_state_vector_sha256).not.toBe(
      adopted.source_state_vector_sha256,
    );
    expect(adopted.migration_artifacts).toEqual([expect.objectContaining({
      relative_path: ".legacy-evidence-anchors.v1.json",
      created: true,
      idempotent: false,
    })]);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
    expect(JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )).generation % 2).toBe(0);

    let callbackCalled = false;
    withLock(root, () => {
      callbackCalled = true;
    });
    expect(callbackCalled).toBe(true);

    let idempotentValidatorCalls = 0;
    const idempotent = adoptRootProtocol(root, (context) => {
      idempotentValidatorCalls += 1;
      expect(context.adopting).toBe(false);
      expect(context.existing_protocol).toMatchObject({
        schema_version: 3,
      });
      const descriptor = (
        context.existing_protocol?.migration_artifacts as Array<{
          relative_path: string;
          sha256: string;
        }>
      )[0];
      return {
        report: { replayed_again: true },
        migration_artifacts: [{
          ...descriptor,
          body: readFileSync(path.join(root, descriptor.relative_path)),
        }],
      };
    });
    expect(idempotentValidatorCalls).toBe(1);
    expect(idempotent).toMatchObject({
      adopted: false,
      idempotent: true,
      validation: { replayed_again: true },
      migration_artifacts: [{
        created: false,
        idempotent: true,
      }],
    });
    expect(idempotent.source_state_vector_sha256).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    expect(idempotent.sealed_state_vector_sha256).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
  });

  it("atomically anchors exact binary legacy source artifacts in the root protocol", () => {
    const root = sandbox();
    const legacyEvent = path.join(
      root,
      "goals",
      "goal-binary-source",
      "events",
      "TASK-1",
      "00000001-old.json",
    );
    mkdirSync(path.dirname(legacyEvent), { recursive: true });
    writeFileSync(legacyEvent, "legacy\n");
    const sourceBody = Buffer.from([0x00, 0xff, 0x7f, 0x0a, 0xc3, 0x28]);

    const adopted = adoptRootProtocol(root, (context) => (
      migrationValidationResult(context, { source_count: 1 }, [sourceBody])
    ));
    const sourceDescriptor = (
      adopted.protocol.migration_artifacts as Array<{
        relative_path: string;
        sha256: string;
      }>
    ).find((descriptor) => descriptor.relative_path.startsWith(
      ".legacy-evidence-sources.v1/",
    ));

    expect(sourceDescriptor).toBeDefined();
    expect(sourceDescriptor?.relative_path).toBe(
      `.legacy-evidence-sources.v1/${sourceDescriptor?.sha256.slice("sha256:".length)}.artifact`,
    );
    expect(readFileSync(
      path.join(root, sourceDescriptor?.relative_path ?? ""),
    )).toEqual(sourceBody);

    writeFileSync(
      path.join(root, sourceDescriptor?.relative_path ?? ""),
      Buffer.from("tampered"),
    );
    let callbackCalled = false;
    let thrown: unknown = null;
    try {
      withStableRead(root, () => {
        callbackCalled = true;
      });
    } catch (error) {
      thrown = error;
    }
    expect(callbackCalled).toBe(false);
    expect(thrown).toMatchObject({ code: "CORRUPT_STORE_PROTOCOL" });
  });

  it("resumes an artifact-published adoption crash only when replay reproduces exact bytes", () => {
    const testRoot = sandbox();
    const root = path.join(testRoot, "control");
    const legacyEvent = path.join(
      root,
      "goals",
      "goal-adoption-crash",
      "events",
      "TASK-1",
      "00000001-old.json",
    );
    mkdirSync(path.dirname(legacyEvent), { recursive: true });
    writeFileSync(legacyEvent, "legacy\n");
    const marker = path.join(testRoot, "artifact-published.marker");
    const childScript = `
      const fs = require("fs");
      const path = require("path");
      const storePath = process.argv[1];
      const root = process.argv[2];
      const marker = process.argv[3];
      const { adoptRootProtocol } = require(storePath);
      const { canonicalJson, hashObject, sha256 } = require(
        path.join(path.dirname(storePath), "util.js")
      );
      adoptRootProtocol(root, (context) => {
        const unsigned = {
          schema_version: 1,
          kind: "LEGACY_EVIDENCE_EVENT_BINDINGS",
          controller_decoder_sha256: context.decoder_sha256,
          source_state_vector_sha256: context.state_vector_sha256,
          events: {},
        };
        const body = canonicalJson({
          ...unsigned,
          index_sha256: hashObject(unsigned),
        }) + "\\n";
        return {
          report: { replayed: true },
          migration_artifacts: [{
            relative_path: ".legacy-evidence-anchors.v1.json",
            sha256: "sha256:" + sha256(body),
            body,
          }],
        };
      }, {
        staleMilliseconds: 0,
        afterMigrationArtifactsInstalled: () => {
          fs.writeFileSync(marker, "published\\n");
          process.kill(process.pid, "SIGKILL");
        },
      });
    `;
    const child = spawnSync(
      process.execPath,
      ["-e", childScript, storeModulePath, root, marker],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );

    expect(child.signal).toBe("SIGKILL");
    expect(readFileSync(marker, "utf8")).toBe("published\n");
    expect(existsSync(path.join(root, ".legacy-evidence-anchors.v1.json"))).toBe(
      true,
    );
    expect(existsSync(path.join(root, ".store-protocol.json"))).toBe(false);

    const resumed = adoptRootProtocol(root, (context) => (
      migrationValidationResult(context, { resumed: true })
    ), {
      timeoutMilliseconds: 1_000,
      staleMilliseconds: 0,
    });
    expect(resumed).toMatchObject({
      adopted: true,
      idempotent: false,
      validation: { resumed: true },
      migration_artifacts: [{
        created: false,
        idempotent: true,
      }],
    });
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
    expect(JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )).generation % 2).toBe(0);
  });

  it.each([
    [
      "GOAL_CONTROL_TEST_FAULT_MIGRATION_ARTIFACT_AFTER_ATOMIC_TEMP_CREATE",
      0,
      null,
    ],
    [
      "GOAL_CONTROL_TEST_FAULT_MIGRATION_PROTOCOL_AFTER_ATOMIC_TEMP_CREATE",
      0,
      null,
    ],
    [
      "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_AFTER_ATOMIC_PUBLISH",
      0,
      null,
    ],
    [
      "GOAL_CONTROL_TEST_FAULT_MIGRATION_ARTIFACT_AFTER_ATOMIC_RESERVATION",
      2,
      "2",
    ],
  ] as const)(
    "exact-replays audited adoption after SIGKILL at %s",
    (fault, sourceCount, occurrence) => {
    const testRoot = sandbox();
    const root = path.join(testRoot, "control");
    const legacyEvent = path.join(
      root,
      "goals",
      "goal-adoption-atomic",
      "events",
      "TASK-1",
      "00000001-old.json",
    );
    mkdirSync(path.dirname(legacyEvent), { recursive: true });
    writeFileSync(legacyEvent, "legacy\n");
    const childScript = `
      const path = require("path");
      const storePath = process.argv[1];
      const root = process.argv[2];
      const sourceCount = Number(process.argv[3]);
      const { adoptRootProtocol } = require(storePath);
      const { canonicalJson, hashObject, sha256 } = require(
        path.join(path.dirname(storePath), "util.js")
      );
      adoptRootProtocol(root, (context) => {
        const unsigned = {
          schema_version: 1,
          kind: "LEGACY_EVIDENCE_EVENT_BINDINGS",
          controller_decoder_sha256: context.decoder_sha256,
          source_state_vector_sha256: context.state_vector_sha256,
          events: {},
        };
        const body = canonicalJson({
          ...unsigned,
          index_sha256: hashObject(unsigned),
        }) + "\\n";
        const sources = Array.from({ length: sourceCount }, (_, index) => {
          const sourceBody = Buffer.from("legacy-source-" + index + "\\n");
          const sourceDigest = "sha256:" + sha256(sourceBody);
          return {
            relative_path: ".legacy-evidence-sources.v1/"
              + sourceDigest.slice("sha256:".length) + ".artifact",
            sha256: sourceDigest,
            body: sourceBody,
          };
        });
        return {
          report: { replayed: true },
          migration_artifacts: [{
            relative_path: ".legacy-evidence-anchors.v1.json",
            sha256: "sha256:" + sha256(body),
            body,
          }, ...sources],
        };
      }, { staleMilliseconds: 0 });
    `;
    const child = spawnSync(
      process.execPath,
      ["-e", childScript, storeModulePath, root, String(sourceCount)],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
          [fault]: "sigkill",
          ...(occurrence === null
            ? {}
            : { [`${fault}_OCCURRENCE`]: occurrence }),
        },
      },
    );
    expect(child.signal).toBe("SIGKILL");

    const resumed = adoptRootProtocol(root, (context) => (
      migrationValidationResult(
        context,
        { resumed: true },
        Array.from(
          { length: sourceCount },
          (_, index) => Buffer.from(`legacy-source-${index}\n`),
        ),
      )
    ), {
      timeoutMilliseconds: 1_000,
      staleMilliseconds: 0,
    });
    expect(resumed.validation).toEqual({ resumed: true });
    expect(JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )).generation % 2).toBe(0);
    expect(existsSync(path.join(root, ".store-protocol.json"))).toBe(true);
    },
  );

  it("refuses migration when its replay validator changes authoritative bytes", () => {
    const root = sandbox();
    const legacyEvent = path.join(
      root,
      "goals",
      "goal-mutating-validator",
      "events",
      "TASK-1",
      "00000001-old.json",
    );
    mkdirSync(path.dirname(legacyEvent), { recursive: true });
    writeFileSync(legacyEvent, "old\n");
    let thrown: unknown = null;

    try {
      adoptRootProtocol(root, (context) => {
        writeFileSync(legacyEvent, "mutated\n");
        return migrationValidationResult(context, { replayed: true });
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({
      code: "STORE_MIGRATION_VALIDATOR_MUTATED",
    });
    expect(existsSync(path.join(root, ".store-protocol.json"))).toBe(false);
    expect(existsSync(path.join(root, ".generation.json"))).toBe(false);
    expect(existsSync(path.join(root, ".lock"))).toBe(true);
  });

  it("treats projection repair by the migration validator as a forbidden write", () => {
    const root = sandbox();
    const legacyEvent = path.join(
      root,
      "goals",
      "goal-projection-repair",
      "events",
      "TASK-1",
      "00000001-old.json",
    );
    const projection = path.join(
      root,
      "goals",
      "goal-projection-repair",
      "state.json",
    );
    mkdirSync(path.dirname(legacyEvent), { recursive: true });
    writeFileSync(legacyEvent, "legacy\n");
    let thrown: unknown = null;

    try {
      adoptRootProtocol(root, (context) => {
        writeFileSync(projection, "repaired projection\n");
        return migrationValidationResult(context, { replayed: true });
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({
      code: "STORE_MIGRATION_VALIDATOR_MUTATED",
    });
    expect(existsSync(path.join(root, ".store-protocol.json"))).toBe(false);
    expect(existsSync(path.join(root, ".lock"))).toBe(true);
  });

  it("refuses an asynchronous migration validator before installing the seal", () => {
    const root = sandbox();
    const legacyEvent = path.join(
      root,
      "goals",
      "goal-async-validator",
      "events",
      "TASK-1",
      "00000001-old.json",
    );
    mkdirSync(path.dirname(legacyEvent), { recursive: true });
    writeFileSync(legacyEvent, "old\n");
    let thrown: unknown = null;

    try {
      const asyncValidator = (() => ({
        then: () => {
          throw new Error("thenable must never be awaited");
        },
      })) as unknown as Parameters<typeof adoptRootProtocol>[1];
      adoptRootProtocol(root, asyncValidator);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({
      code: "STORE_MIGRATION_VALIDATOR_ASYNC",
    });
    expect(existsSync(path.join(root, ".store-protocol.json"))).toBe(false);
    expect(existsSync(path.join(root, ".generation.json"))).toBe(false);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("seals a nonce owner in a pending directory before atomically publishing .lock", () => {
    const root = sandbox();
    const lockDir = path.join(root, ".lock");
    const order: string[] = [];
    let sealedOwner: Record<string, unknown> | null = null;

    withGoalControlTestMode(() => {
      withLock(root, () => {
        order.push("outer");
      }, {
        timeoutMilliseconds: 1_000,
        staleMilliseconds: 0,
        afterLockOwnerSealed: () => {
          expect(existsSync(lockDir)).toBe(false);
          const pending = readdirSync(root).filter((name) => (
            name.startsWith(".lock.pending.")
          ));
          expect(pending).toHaveLength(1);
          sealedOwner = JSON.parse(readFileSync(
            path.join(root, pending[0], "owner.json"),
            "utf8",
          )) as Record<string, unknown>;
          expect(sealedOwner).toMatchObject({
            schema_version: 1,
            lock_protocol_version: 2,
            kind: "WRITER",
            pid: process.pid,
          });
          expect(sealedOwner?.process_start_token).toMatch(
            /^sha256:[0-9a-f]{64}$/,
          );
          expect(sealedOwner?.nonce).toMatch(/^writer-[0-9a-f]{24}$/);
          expect(sealedOwner?.owner_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);

          withLock(root, () => {
            order.push("nested");
          }, {
            timeoutMilliseconds: 1_000,
            staleMilliseconds: 0,
          });
        },
      });
    });

    expect(order).toEqual(["nested", "outer"]);
    expect(existsSync(lockDir)).toBe(false);
    expect(readdirSync(root).some((name) => name.includes(".pending."))).toBe(false);
    expect(JSON.parse(readFileSync(
      path.join(root, ".store-protocol.json"),
      "utf8",
    ))).toMatchObject({
      schema_version: 3,
      controller_decoder_version: 3,
      lock_protocol_version: 2,
      migration_source_state_vector_sha256: null,
      migration_artifacts: [],
    });
    expect(JSON.parse(readFileSync(
      path.join(root, ".store-protocol.json"),
      "utf8",
    )).controller_decoder_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("garbage-collects sealed pending, backing, and release artifacts after owner crashes", () => {
    for (const hookName of [
      "afterLockOwnerSealed",
      "afterLockBackingPublished",
      "afterLockReleaseClaimed",
    ]) {
      const root = sandbox();
      const marker = path.join(root, `${hookName}.marker`);
      const childScript = `
        const fs = require("fs");
        const { withLock } = require(process.argv[1]);
        const root = process.argv[2];
        const marker = process.argv[3];
        const hookName = process.argv[4];
        withLock(root, () => {}, {
          timeoutMilliseconds: 1000,
          staleMilliseconds: 0,
          [hookName]: () => {
            fs.writeFileSync(marker, hookName + "\\n");
            process.kill(process.pid, "SIGKILL");
          },
        });
      `;
      const child = spawnSync(
        process.execPath,
        ["-e", childScript, storeModulePath, root, marker, hookName],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            GOAL_CONTROL_TEST_MODE: "1",
          },
        },
      );

      expect(child.error).toBeUndefined();
      expect(child.signal).toBe("SIGKILL");
      expect(readFileSync(marker, "utf8")).toBe(`${hookName}\n`);
      expect(readdirSync(root).some((name) => name.startsWith(".lock."))).toBe(
        true,
      );

      let callbackCalled = false;
      withLock(root, () => {
        callbackCalled = true;
      }, {
        timeoutMilliseconds: 1_000,
        staleMilliseconds: 0,
      });

      expect(callbackCalled).toBe(true);
      expect(
        readdirSync(root).filter((name) => name.startsWith(".lock.")),
      ).toEqual([]);
    }
  });

  it("reaps a writer that crashed after lock publication without changing its even generation", () => {
    const root = sandbox();
    const marker = path.join(root, "lock-published-before-generation");
    withLock(root, () => {});
    const generationFile = path.join(root, ".generation.json");
    const entryGeneration = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )).generation as number;
    expect(entryGeneration % 2).toBe(0);

    const childScript = `
      const fs = require("fs");
      const { withLock } = require(process.argv[1]);
      const root = process.argv[2];
      const marker = process.argv[3];
      withLock(root, () => {
        throw new Error("callback must not run");
      }, {
        timeoutMilliseconds: 1000,
        staleMilliseconds: 0,
        afterLockPublished: () => {
          fs.writeFileSync(marker, "published-before-generation\\n");
          process.kill(process.pid, "SIGKILL");
        },
      });
    `;
    const child = spawnSync(
      process.execPath,
      ["-e", childScript, storeModulePath, root, marker],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );
    expect(child.error).toBeUndefined();
    expect(child.signal).toBe("SIGKILL");
    expect(readFileSync(marker, "utf8"))
      .toBe("published-before-generation\n");
    expect(JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )).generation).toBe(entryGeneration);

    let callbackCalls = 0;
    withLock(root, () => {
      callbackCalls += 1;
    }, {
      timeoutMilliseconds: 1_000,
      staleMilliseconds: 0,
    });

    expect(callbackCalls).toBe(1);
    expect(JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )).generation).toBe(entryGeneration + 2);
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("validates protocol before publishing a reaper for a dead writer", () => {
    const root = sandbox();
    const marker = path.join(root, "dead-writer-before-protocol-corruption");
    withLock(root, () => {});

    const childScript = `
      const fs = require("fs");
      const { withLock } = require(process.argv[1]);
      const root = process.argv[2];
      const marker = process.argv[3];
      withLock(root, () => {
        throw new Error("callback must not run");
      }, {
        timeoutMilliseconds: 1000,
        staleMilliseconds: 0,
        afterLockPublished: () => {
          fs.writeFileSync(marker, "dead-writer\\n");
          process.kill(process.pid, "SIGKILL");
        },
      });
    `;
    const child = spawnSync(
      process.execPath,
      ["-e", childScript, storeModulePath, root, marker],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );
    expect(child.error).toBeUndefined();
    expect(child.signal).toBe("SIGKILL");
    expect(readFileSync(marker, "utf8")).toBe("dead-writer\n");

    const lockPath = path.join(root, ".lock");
    expect(lstatSync(lockPath).isSymbolicLink()).toBe(true);
    const deadWriterTarget = readlinkSync(lockPath);
    writeFileSync(
      path.join(root, ".store-protocol.json"),
      "{not-valid-json\n",
    );

    let callbackCalled = false;
    let thrown: unknown = null;
    try {
      withLock(root, () => {
        callbackCalled = true;
      }, {
        timeoutMilliseconds: 1_000,
        staleMilliseconds: 0,
      });
    } catch (error) {
      thrown = error;
    }

    expect(callbackCalled).toBe(false);
    expect(thrown).toMatchObject({ code: "CORRUPT_STORE_PROTOCOL" });
    expect(readlinkSync(lockPath)).toBe(deadWriterTarget);
    expect(
      readdirSync(root).filter((name) => (
        name === ".lock.reap" || name.startsWith(".lock.reap.")
      )),
    ).toEqual([]);
  });

  it("advances an odd stale writer fence but still requires an exact recovery witness", () => {
    const root = sandbox();
    const witness = path.join(root, "goals", "goal-odd-stale", "event.json");
    const exactKey = transactionKey(
      "GOAL_EVENT",
      "odd-stale",
      { event_id: "odd-stale", action: "install witness" },
    );
    const unrelatedKey = transactionKey(
      "RESOURCE_ACQUIRE",
      "unrelated",
      { event_id: "unrelated", action: "acquire resource" },
    );
    withLock(root, () => {});
    const generationFile = path.join(root, ".generation.json");
    const childScript = `
      const fs = require("fs");
      const path = require("path");
      const { withLock } = require(process.argv[1]);
      const root = process.argv[2];
      const witness = process.argv[3];
      const transactionKey = JSON.parse(process.argv[4]);
      withLock(root, () => {
        fs.mkdirSync(path.dirname(witness), { recursive: true });
        fs.writeFileSync(witness, "exact-operation-id=odd-stale\\n");
        process.kill(process.pid, "SIGKILL");
      }, {
        timeoutMilliseconds: 1000,
        staleMilliseconds: 0,
        transactionKey,
      });
    `;
    const child = spawnSync(
      process.execPath,
      [
        "-e",
        childScript,
        storeModulePath,
        root,
        witness,
        JSON.stringify(exactKey),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );
    expect(child.error).toBeUndefined();
    expect(child.signal).toBe("SIGKILL");
    const crashedGeneration = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )).generation as number;
    expect(crashedGeneration % 2).toBe(1);

    let unrelatedCallbackCalls = 0;
    let unrelatedError: unknown = null;
    try {
      withLock(root, () => {
        unrelatedCallbackCalls += 1;
      }, {
        timeoutMilliseconds: 1_000,
        staleMilliseconds: 0,
        transactionKey: unrelatedKey,
      });
    } catch (error) {
      unrelatedError = error;
    }
    expect(unrelatedError).toMatchObject({
      code: "STORE_TRANSACTION_MISMATCH",
    });
    expect(unrelatedCallbackCalls).toBe(0);
    const fencedGeneration = JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )).generation as number;
    expect(fencedGeneration).toBe(crashedGeneration);
    expect(fencedGeneration % 2).toBe(1);

    let exactWitness = false;
    const recovered = withLock(root, () => "recovered", {
      beforeGeneration: () => {
        expect(readFileSync(witness, "utf8"))
          .toBe("exact-operation-id=odd-stale\n");
        exactWitness = true;
      },
      authorizeOddRecovery: () => exactWitness,
      transactionKey: exactKey,
    });
    expect(recovered).toBe("recovered");
    expect(JSON.parse(readFileSync(
      generationFile,
      "utf8",
    )).generation).toBe(fencedGeneration + 1);
  });

  it("recovers a stale sealed .lock.reap after the reaper process crashes", () => {
    const root = sandbox();
    const lockDir = path.join(root, ".lock");
    const marker = path.join(root, "reaper-published");
    mkdirSync(lockDir);
    writeFileSync(path.join(lockDir, "owner.json"), `${JSON.stringify({
      pid: 2_147_483_647,
      acquired_at: "2000-01-01T00:00:00.000Z",
      marker: "legacy-stale-writer",
    })}\n`);

    const childScript = `
      const fs = require("fs");
      const { withLock } = require(process.argv[1]);
      const root = process.argv[2];
      const marker = process.argv[3];
      withLock(root, () => {}, {
        timeoutMilliseconds: 1000,
        staleMilliseconds: 0,
        afterReaperMutexAcquired: () => {
          fs.writeFileSync(marker, "sealed-and-published\\n");
          process.kill(process.pid, "SIGKILL");
        },
      });
    `;
    const child = spawnSync(
      process.execPath,
      ["-e", childScript, storeModulePath, root, marker],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );

    expect(child.error).toBeUndefined();
    expect(child.signal).toBe("SIGKILL");
    expect(readFileSync(marker, "utf8")).toBe("sealed-and-published\n");
    expect(existsSync(`${lockDir}.reap`)).toBe(true);

    let callbackCalled = false;
    withLock(root, () => {
      callbackCalled = true;
    }, {
      timeoutMilliseconds: 1_000,
      staleMilliseconds: 0,
    });

    expect(callbackCalled).toBe(true);
    expect(existsSync(lockDir)).toBe(false);
    expect(existsSync(`${lockDir}.reap`)).toBe(false);
    const generation = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as { generation: number };
    expect(generation.generation % 2).toBe(0);
  });

  it("reaps a dead owner even when its pid has been reused by a live process", () => {
    const root = sandbox();
    const lockDir = path.join(root, ".lock");
    let template: Record<string, unknown> = {};
    withLock(root, () => {
      template = JSON.parse(readFileSync(
        path.join(lockDir, "owner.json"),
        "utf8",
      )) as Record<string, unknown>;
    });
    const unsigned: Record<string, unknown> = {
      ...template,
      pid: process.pid,
      process_start_token: `sha256:${"0".repeat(64)}`,
      nonce: "writer-reused-pid-000000000001",
      acquired_at: "2000-01-01T00:00:00.000Z",
    };
    delete unsigned.owner_sha256;
    const reusedPidOwner = {
      ...unsigned,
      owner_sha256: hashObject(unsigned),
    };
    mkdirSync(lockDir);
    writeFileSync(
      path.join(lockDir, "owner.json"),
      `${JSON.stringify(reusedPidOwner, null, 2)}\n`,
    );
    let callbackCalled = false;

    withLock(root, () => {
      callbackCalled = true;
    }, {
      timeoutMilliseconds: 1_000,
      staleMilliseconds: 0,
    });

    expect(callbackCalled).toBe(true);
    expect(existsSync(lockDir)).toBe(false);
  });

  it("refuses to release a same-path replacement with a different nonce", () => {
    const root = sandbox();
    const lockDir = path.join(root, ".lock");
    const displaced = path.join(root, ".lock.displaced-test");
    const replacementNonce = "writer-replacement-000000000001";
    let callbackCalled = false;
    let thrown: unknown = null;

    try {
      withGoalControlTestMode(() => withLock(root, () => {
        callbackCalled = true;
      }, {
        beforeLockRelease: () => {
          const current = JSON.parse(readFileSync(
            path.join(lockDir, "owner.json"),
            "utf8",
          )) as Record<string, unknown>;
          const unsigned: Record<string, unknown> = {
            ...current,
            nonce: replacementNonce,
          };
          delete unsigned.owner_sha256;
          const replacement = {
            ...unsigned,
            owner_sha256: hashObject(unsigned),
          };
          renameSync(lockDir, displaced);
          mkdirSync(lockDir);
          writeFileSync(
            path.join(lockDir, "owner.json"),
            `${JSON.stringify(replacement, null, 2)}\n`,
          );
        },
      }));
    } catch (error) {
      thrown = error;
    }

    expect(callbackCalled).toBe(true);
    expect(thrown).toMatchObject({ code: "LOCK_OWNERSHIP_LOST" });
    expect(JSON.parse(readFileSync(
      path.join(lockDir, "owner.json"),
      "utf8",
    ))).toMatchObject({ nonce: replacementNonce });
    expect(existsSync(lockDir)).toBe(true);
  });

  it("uses the root decoder seal to block legacy owner recovery", () => {
    const root = sandbox();
    const lockDir = path.join(root, ".lock");
    withLock(root, () => {});
    mkdirSync(lockDir);
    writeFileSync(path.join(lockDir, "owner.json"), `${JSON.stringify({
      pid: 2_147_483_647,
      acquired_at: "2000-01-01T00:00:00.000Z",
      marker: "old-decoder-owner",
    })}\n`);
    let callbackCalled = false;
    let thrown: unknown = null;

    try {
      withLock(root, () => {
        callbackCalled = true;
      }, {
        timeoutMilliseconds: 100,
        staleMilliseconds: 0,
      });
    } catch (error) {
      thrown = error;
    }

    expect(callbackCalled).toBe(false);
    expect(thrown).toMatchObject({ code: "LOCK_PROTOCOL_MISMATCH" });
    expect(JSON.parse(readFileSync(
      path.join(lockDir, "owner.json"),
      "utf8",
    ))).toMatchObject({ marker: "old-decoder-owner" });
    expect(existsSync(`${lockDir}.reap`)).toBe(false);
  });

  it("fails closed when the immutable root seal requires a newer decoder", () => {
    const root = sandbox();
    const protocolFile = path.join(root, ".store-protocol.json");
    withLock(root, () => {});
    const current = JSON.parse(readFileSync(
      protocolFile,
      "utf8",
    )) as Record<string, unknown>;
    const unsigned: Record<string, unknown> = {
      ...current,
      controller_decoder_version: 999,
    };
    delete unsigned.seal_sha256;
    writeFileSync(protocolFile, `${JSON.stringify({
      ...unsigned,
      seal_sha256: hashObject(unsigned),
    }, null, 2)}\n`);
    let callbackCalled = false;
    let thrown: unknown = null;

    try {
      withLock(root, () => {
        callbackCalled = true;
      });
    } catch (error) {
      thrown = error;
    }

    expect(callbackCalled).toBe(false);
    expect(thrown).toMatchObject({ code: "STORE_PROTOCOL_UNSUPPORTED" });
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("mechanically fences every transitive decoder dependency and schema byte", () => {
    const root = sandbox();
    const copiedDecoder = path.join(root, "decoder");
    const controlRoot = path.join(root, "control");
    cpSync(path.dirname(storeModulePath), copiedDecoder, { recursive: true });
    const copiedStore = path.join(copiedDecoder, "store.js");
    const dependencies = decoderDependencyClosure(copiedDecoder);

    expect(dependencies).toEqual(expect.arrayContaining([
      "store.js",
      "auth.js",
      "candidate-lineage.js",
      "operational-scope.js",
      "source-handoff.js",
      "ledger.js",
      "util.js",
      "migration.js",
      "schemas/event.schema.json",
    ]));

    const sealScript = `
      const { withLock } = require(process.argv[1]);
      withLock(process.argv[2], () => {});
    `;
    const sealed = spawnSync(
      process.execPath,
      ["-e", sealScript, copiedStore, controlRoot],
      { encoding: "utf8" },
    );
    expect(sealed.status).toBe(0);
    expect(sealed.stderr).toBe("");

    const probeScript = `
      try {
        const { withStableRead } = require(process.argv[1]);
        withStableRead(process.argv[2], () => null, {
          timeoutMilliseconds: 50,
          retryMilliseconds: 1,
        });
        process.stdout.write("UNEXPECTED_PASS");
      } catch (error) {
        process.stdout.write(error.code || error.message);
      }
    `;
    for (const relative of dependencies) {
      const dependency = path.join(copiedDecoder, relative);
      const original = readFileSync(dependency);
      const marker = relative.endsWith(".json")
        ? Buffer.from("\n")
        : Buffer.from("\n// decoder-fingerprint-drift\n");
      writeFileSync(dependency, Buffer.concat([original, marker]));
      const probe = spawnSync(
        process.execPath,
        ["-e", probeScript, copiedStore, controlRoot],
        { encoding: "utf8" },
      );
      writeFileSync(dependency, original);

      expect(probe.status).toBe(0);
      expect(probe.stdout).toBe("STORE_PROTOCOL_UNSUPPORTED");
    }
  });

  it.each([
    {
      label: "even writer start",
      generation: Number.MAX_SAFE_INTEGER - 1,
      authorizeOddRecovery: undefined,
      expectedCode: "STORE_GENERATION_EXHAUSTED",
    },
    {
      label: "legacy odd recovery",
      generation: Number.MAX_SAFE_INTEGER,
      authorizeOddRecovery: () => true,
      expectedCode: "AUDITED_REPAIR_ONLY",
    },
  ])("rejects an exhausted generation before callback ($label)", ({
    generation,
    authorizeOddRecovery,
    expectedCode,
  }) => {
    const root = sandbox();
    const unsigned = {
      schema_version: 1,
      generation,
      updated_at: "2026-07-23T00:00:00.000Z",
    };
    writeFileSync(path.join(root, ".generation.json"), `${JSON.stringify({
      ...unsigned,
      seal_sha256: hashObject(unsigned),
    }, null, 2)}\n`);
    let callbackCalled = false;
    let thrown: unknown = null;

    try {
      withLock(root, () => {
        callbackCalled = true;
      }, {
        authorizeOddRecovery,
        transactionKey: transactionKey(
          "GOAL_EVENT",
          `generation-${generation}`,
          { generation },
        ),
      });
    } catch (error) {
      thrown = error;
    }

    expect(callbackCalled).toBe(false);
    expect(thrown).toMatchObject({ code: expectedCode });
    expect(existsSync(path.join(root, ".lock"))).toBe(false);
  });

  it("revalidates the current owner under the reaper mutex before deleting a lock", () => {
    const root = sandbox();
    const lockDir = path.join(root, ".lock");
    const ownerFile = path.join(lockDir, "owner.json");
    mkdirSync(lockDir);
    writeFileSync(ownerFile, `${JSON.stringify({
      pid: 2_147_483_647,
      acquired_at: "2000-01-01T00:00:00.000Z",
      marker: "stale-owner",
    })}\n`);
    let callbackCalled = false;
    let replacementInstalled = false;
    const previousTestMode = process.env.GOAL_CONTROL_TEST_MODE;
    process.env.GOAL_CONTROL_TEST_MODE = "1";

    try {
      expect(() => withLock(root, () => {
        callbackCalled = true;
      }, {
        timeoutMilliseconds: 75,
        staleMilliseconds: 0,
        afterReaperMutexAcquired: () => {
          if (replacementInstalled) return;
          replacementInstalled = true;
          rmSync(lockDir, { recursive: true, force: true });
          mkdirSync(lockDir);
          writeFileSync(ownerFile, `${JSON.stringify({
            pid: process.pid,
            acquired_at: new Date().toISOString(),
            marker: "fresh-owner",
          })}\n`);
        },
      })).toThrow(/LOCK_TIMEOUT|控制面锁等待/);
    } finally {
      if (previousTestMode === undefined) {
        delete process.env.GOAL_CONTROL_TEST_MODE;
      } else {
        process.env.GOAL_CONTROL_TEST_MODE = previousTestMode;
      }
    }

    expect(replacementInstalled).toBe(true);
    expect(callbackCalled).toBe(false);
    expect(JSON.parse(readFileSync(ownerFile, "utf8"))).toMatchObject({
      pid: process.pid,
      marker: "fresh-owner",
    });
    expect(existsSync(lockDir)).toBe(true);
    expect(existsSync(`${lockDir}.reap`)).toBe(false);
  });
});
