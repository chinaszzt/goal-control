import fs, {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { spawnSync } from "child_process";
import { createRequire } from "module";
import { tmpdir } from "os";
import path from "path";

const nodeRequire = createRequire(import.meta.url);
const {
  adoptSourceImportIntentPublication,
  atomicCreate,
  atomicWrite,
  canonicalTransactionKey,
  encodeAtomicCleanupManifest,
  ensureDir,
  readPrivateAtomicArtifact,
  withLock,
} = nodeRequire("../scripts/goal-control/store.js") as {
  adoptSourceImportIntentPublication: (
    file: string,
    body: string | Buffer,
  ) => { adopted: boolean; idempotent: boolean };
  atomicCreate: (
    file: string,
    body: string | Buffer,
    options?: { fault_namespace?: string },
  ) => boolean;
  atomicWrite: (
    file: string,
    body: string | Buffer,
    options?: { fault_namespace?: string },
  ) => void;
  canonicalTransactionKey: (
    kind: string,
    scope: Record<string, string>,
    stableId: string,
    requestHash: string,
  ) => TransactionKey;
  encodeAtomicCleanupManifest: (
    record: Record<string, unknown>,
  ) => Buffer;
  ensureDir: (directory: string) => void;
  readPrivateAtomicArtifact: (
    root: string,
    file: string,
    options: { operation: "CREATE" | "WRITE"; maxBytes: number },
  ) => {
    bytes: Buffer;
    ownership: {
      kind:
        | "SINGLE_LINK"
        | "ACTIVE_ODD"
        | "ACTIVE_ODD_RESIDUAL"
        | "COMPLETED_EVEN"
        | "COMPLETED_EVEN_CLEANUP"
        | "SINGLE_LINK_EVEN_CLEANUP"
        | "SINGLE_LINK_EVEN_CLEANUP_TERMINAL";
    };
  };
  withLock: <T>(
    root: string,
    callback: () => T,
    options: {
      transactionKey: TransactionKey;
      staleMilliseconds?: number;
      timeoutMilliseconds?: number;
      beforeGeneration?: (context: {
        mode: "FRESH" | "PRE_WITNESS_RETRY" | "ODD_RETRY";
        transaction_started_at: string;
      }) => void;
      authorizeOddRecovery?: () => boolean;
      authorizePristineOddRecovery?: () => boolean;
    },
  ) => T;
};
const { hashObject } = nodeRequire(
  "../scripts/goal-control/util.js",
) as {
  hashObject: (value: unknown) => string;
};
const storeModulePath = nodeRequire.resolve(
  "../scripts/goal-control/store.js",
);

type TransactionKey = {
  schema_version: 1;
  kind: string;
  scope: Record<string, string>;
  stable_operation_id_sha256: string;
  request_sha256: string;
  key_sha256: string;
};

const sandboxes: string[] = [];

function sandbox(): string {
  const root = mkdtempSync(
    path.join(tmpdir(), "goal-control-store-atomic-recovery-"),
  );
  sandboxes.push(root);
  return root;
}

function key(stableId: string): TransactionKey {
  return canonicalTransactionKey(
    "GOAL_EVENT",
    { goal_id: "goal-atomic", task_id: "TASK-1" },
    stableId,
    hashObject({
      schema_version: 1,
      stable_id: stableId,
      request: "exact",
    }),
  );
}

function sourceImportAdoptionFixture(stableId: string): {
  transactionKey: TransactionKey;
  intentRelative: string;
  intentBody: string;
} {
  const goalId = "goal-source-import";
  const taskId = "TASK-SOURCE";
  const request = {
    schema_version: 1,
    import_id: stableId,
    destination: "exact",
  };
  const requestSha256 = hashObject(request);
  const unsigned = {
    schema_version: 1,
    kind: "RECOVERY_IMPORT_INTENT",
    import_id: stableId,
    goal_id: goalId,
    task_id: taskId,
    request,
    request_sha256: requestSha256,
  };
  const intent = {
    ...unsigned,
    intent_sha256: hashObject(unsigned),
  };
  return {
    transactionKey: canonicalTransactionKey(
      "SOURCE_IMPORT",
      { goal_id: goalId, task_id: taskId },
      stableId,
      requestSha256,
    ),
    intentRelative: path.join(
      "goals",
      goalId,
      "recovery-handoffs",
      taskId,
      "import-intents",
      stableId,
      "intent.json",
    ),
    intentBody: `${JSON.stringify(intent, null, 2)}\n`,
  };
}

const DEFAULT_WITNESS_RELATIVE =
  "goals/goal-atomic/events/TASK-1/witness.json";

function witnessFile(
  root: string,
  relative = DEFAULT_WITNESS_RELATIVE,
): string {
  return path.join(root, relative);
}

function crash(
  root: string,
  transactionKey: TransactionKey,
  fault: string,
  targetRelative = DEFAULT_WITNESS_RELATIVE,
): ReturnType<typeof spawnSync> {
  const script = `
    const { atomicWrite, withLock } = require(${JSON.stringify(storeModulePath)});
    const root = process.env.ATOMIC_TEST_ROOT;
    const transactionKey = JSON.parse(process.env.ATOMIC_TEST_KEY);
    const target = process.env.ATOMIC_TEST_TARGET;
    withLock(root, () => {
      atomicWrite(
        require("path").join(root, target),
        "{\\"witness\\":true}\\n",
        { fault_namespace: "BUSINESS" },
      );
    }, {
      transactionKey,
      staleMilliseconds: 0,
      timeoutMilliseconds: 1000,
      authorizeOddRecovery: () => true,
      authorizePristineOddRecovery: () => true,
    });
  `;
  return spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    env: {
      ...process.env,
      GOAL_CONTROL_TEST_MODE: "1",
      ATOMIC_TEST_ROOT: root,
      ATOMIC_TEST_KEY: JSON.stringify(transactionKey),
      ATOMIC_TEST_TARGET: targetRelative,
      [fault]: "sigkill",
    },
  });
}

function expectSigkill(
  result: ReturnType<typeof spawnSync>,
): void {
  expect(result.signal).toBe("SIGKILL");
}

function runSourceImportAdoption(
  root: string,
  fixture: ReturnType<typeof sourceImportAdoptionFixture>,
): void {
  withLock(root, () => {
    const intent = path.join(root, fixture.intentRelative);
    if (!existsSync(intent)) {
      atomicCreate(intent, fixture.intentBody);
    }
    adoptSourceImportIntentPublication(intent, fixture.intentBody);
    atomicWrite(
      path.join(root, "source-import-adoption", "continued.json"),
      "{\"continued\":true}\n",
    );
  }, {
    transactionKey: fixture.transactionKey,
    staleMilliseconds: 0,
    timeoutMilliseconds: 1_000,
    authorizeOddRecovery: () => true,
    authorizePristineOddRecovery: () => true,
  });
}

function crashSourceImportAdoption(
  root: string,
  fixture: ReturnType<typeof sourceImportAdoptionFixture>,
  fault: string,
  occurrence?: number,
): ReturnType<typeof spawnSync> {
  const script = `
    const fs = require("fs");
    const path = require("path");
    const {
      adoptSourceImportIntentPublication,
      atomicCreate,
      atomicWrite,
      withLock,
    } = require(${JSON.stringify(storeModulePath)});
    const root = process.env.ATOMIC_TEST_ROOT;
    const transactionKey = JSON.parse(process.env.ATOMIC_TEST_KEY);
    const intent = path.join(root, process.env.ATOMIC_TEST_INTENT_RELATIVE);
    const intentBody = process.env.ATOMIC_TEST_INTENT_BODY;
    withLock(root, () => {
      if (!fs.existsSync(intent)) {
        atomicCreate(intent, intentBody);
      }
      adoptSourceImportIntentPublication(intent, intentBody);
      atomicWrite(
        path.join(root, "source-import-adoption", "continued.json"),
        "{\\"continued\\":true}\\n",
      );
    }, {
      transactionKey,
      staleMilliseconds: 0,
      timeoutMilliseconds: 1000,
      authorizeOddRecovery: () => true,
      authorizePristineOddRecovery: () => true,
    });
  `;
  return spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    env: {
      ...process.env,
      GOAL_CONTROL_TEST_MODE: "1",
      ATOMIC_TEST_ROOT: root,
      ATOMIC_TEST_KEY: JSON.stringify(fixture.transactionKey),
      ATOMIC_TEST_INTENT_RELATIVE: fixture.intentRelative,
      ATOMIC_TEST_INTENT_BODY: fixture.intentBody,
      [fault]: "sigkill",
      ...(occurrence === undefined
        ? {}
        : { [`${fault}_OCCURRENCE`]: String(occurrence) }),
    },
  });
}

function crashMultiWrite(
  root: string,
  transactionKey: TransactionKey,
  writeCount: number,
): ReturnType<typeof spawnSync> {
  const script = `
    const path = require("path");
    const { atomicWrite, withLock } = require(${JSON.stringify(storeModulePath)});
    const root = process.env.ATOMIC_TEST_ROOT;
    const transactionKey = JSON.parse(process.env.ATOMIC_TEST_KEY);
    const writeCount = Number(process.env.ATOMIC_TEST_WRITE_COUNT);
    withLock(root, () => {
      for (let index = 1; index <= writeCount; index += 1) {
        atomicWrite(
          path.join(root, "multi", "write-" + index + ".json"),
          JSON.stringify({ index }) + "\\n",
          { fault_namespace: "BUSINESS_" + index },
        );
      }
    }, {
      transactionKey,
      staleMilliseconds: 0,
      timeoutMilliseconds: 1000,
      authorizeOddRecovery: () => true,
      authorizePristineOddRecovery: () => true,
    });
  `;
  return spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    env: {
      ...process.env,
      GOAL_CONTROL_TEST_MODE: "1",
      GOAL_CONTROL_TEST_FAULT_BUSINESS_2_AFTER_ATOMIC_RESERVATION:
        "sigkill",
      ATOMIC_TEST_ROOT: root,
      ATOMIC_TEST_KEY: JSON.stringify(transactionKey),
      ATOMIC_TEST_WRITE_COUNT: String(writeCount),
    },
  });
}

function runMovedLineageScenario(
  root: string,
  transactionKey: TransactionKey,
  mode: "rename" | "remove",
  injectFault: boolean,
): ReturnType<typeof spawnSync> {
  const script = `
    const fs = require("fs");
    const path = require("path");
    const {
      atomicWrite,
      ensureDir,
      withLock,
    } = require(${JSON.stringify(storeModulePath)});
    const root = process.env.ATOMIC_TEST_ROOT;
    const transactionKey = JSON.parse(process.env.ATOMIC_TEST_KEY);
    const mode = process.env.ATOMIC_TEST_LINEAGE_MODE;
    const phaseRoot = path.join(root, "lineage-" + mode);
    const staging = path.join(phaseRoot, ".staging");
    const final = path.join(phaseRoot, "final");
    const marker = path.join(phaseRoot, "remove-complete.json");
    withLock(root, () => {
      if (
        (mode === "rename" && !fs.existsSync(final))
          || (mode === "remove" && !fs.existsSync(marker))
      ) {
        ensureDir(staging);
        atomicWrite(
          path.join(staging, "seed.json"),
          JSON.stringify({ phase: mode }) + "\\n",
        );
        if (mode === "rename") {
          fs.renameSync(staging, final);
        } else {
          atomicWrite(marker, JSON.stringify({ complete: true }) + "\\n");
          fs.rmSync(staging, { recursive: true });
        }
      }
      atomicWrite(
        path.join(phaseRoot, "later", "result.json"),
        JSON.stringify({ later: true }) + "\\n",
        { fault_namespace: "LATER" },
      );
    }, {
      transactionKey,
      staleMilliseconds: 0,
      timeoutMilliseconds: 1000,
      authorizeOddRecovery: () => true,
      authorizePristineOddRecovery: () => true,
    });
  `;
  return spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    env: {
      ...process.env,
      GOAL_CONTROL_TEST_MODE: "1",
      ...(injectFault
        ? {
          GOAL_CONTROL_TEST_FAULT_LATER_AFTER_ATOMIC_RESERVATION:
            "sigkill",
        }
        : {}),
      ATOMIC_TEST_ROOT: root,
      ATOMIC_TEST_KEY: JSON.stringify(transactionKey),
      ATOMIC_TEST_LINEAGE_MODE: mode,
    },
  });
}

function exactMultiWrite(
  root: string,
  transactionKey: TransactionKey,
  writeCount: number,
): void {
  withLock(root, () => {
    for (let index = 1; index <= writeCount; index += 1) {
      atomicWrite(
        path.join(root, "multi", `write-${index}.json`),
        `${JSON.stringify({ index })}\n`,
      );
    }
  }, {
    transactionKey,
    staleMilliseconds: 0,
    timeoutMilliseconds: 1_000,
    authorizeOddRecovery: () => true,
    authorizePristineOddRecovery: () => true,
  });
}

function exactRetry(
  root: string,
  transactionKey: TransactionKey,
  options: {
    authorizePristine?: boolean;
    offerPristineAuthority?: boolean;
    authorizeWitness?: boolean;
    beforeGeneration?: (mode: string, startedAt: string) => void;
    targetRelative?: string;
  } = {},
): void {
  withLock(root, () => {
    atomicWrite(
      witnessFile(root, options.targetRelative),
      "{\"witness\":true}\n",
    );
  }, {
    transactionKey,
    staleMilliseconds: 0,
    timeoutMilliseconds: 1_000,
    beforeGeneration: (context) => {
      options.beforeGeneration?.(
        context.mode,
        context.transaction_started_at,
      );
    },
    authorizeOddRecovery: () =>
      options.authorizeWitness !== false,
    authorizePristineOddRecovery:
      options.offerPristineAuthority === false
        ? undefined
        : () => options.authorizePristine !== false,
  });
}

function atomicTransportEntries(root: string): string[] {
  const transport = path.join(root, ".atomic-transactions");
  if (!existsSync(transport)) return [];
  const entries: string[] = [];
  const visit = (directory: string, relativeDirectory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const relative = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      const absolute = path.join(directory, name);
      const stat = lstatSync(absolute);
      entries.push(relative);
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        visit(absolute, relative);
      }
    }
  };
  visit(transport, "");
  return entries;
}

function atomicTransportFiles(root: string): string[] {
  const transport = path.join(root, ".atomic-transactions");
  if (!existsSync(transport)) return [];
  const files: string[] = [];
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const stat = lstatSync(absolute);
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        visit(absolute);
      } else {
        files.push(absolute);
      }
    }
  };
  visit(transport);
  return files;
}

afterEach(() => {
  delete process.env.GOAL_CONTROL_TEST_MODE;
  while (sandboxes.length > 0) {
    rmSync(sandboxes.pop()!, { recursive: true, force: true });
  }
});

describe("goal-control transaction-bound atomic recovery", () => {
  it("fits the legal 10k source-handoff cleanup manifest shape", () => {
    const goalId = "g".repeat(200);
    const taskId = "t".repeat(200);
    const stagingId = [
      ".init-source",
      "a".repeat(64),
      "b".repeat(64),
      "c".repeat(64),
    ].join("-");
    const payloadName = [
      ".payload-WRITE",
      "d".repeat(64),
      "e".repeat(64),
      "miss-0.published",
    ].join("-");
    const files = Array.from({ length: 10_000 }, (_unused, index) => {
      const artifact = `${String(index + 1).padStart(6, "0")}.bin`;
      const target = [
        "goals",
        goalId,
        "recovery-handoffs",
        taskId,
        "snapshots",
        stagingId,
        "untracked",
        artifact,
      ].join("/");
      return {
        relative_path: `PUBLISH_LINEAGE/WRITE/${target}/${payloadName}`,
        payload_sha256: `sha256:${"d".repeat(64)}`,
        size: 0,
        device: "1",
        inode: String(index + 1),
        link_count: 2,
        mode: 0o600,
        uid: process.getuid!(),
        publication_operation: "WRITE",
        publication_target_relative: target,
        counterpart_relative_path: target,
      };
    });
    const directories = files.map((entry) => (
      entry.relative_path.slice(0, entry.relative_path.lastIndexOf("/"))
    ));
    const body = encodeAtomicCleanupManifest({
      schema_version: 1,
      base_binding: {
        schema_version: 1,
        kind: "EVEN",
        transaction_key_sha256: `sha256:${"f".repeat(64)}`,
        generation: 2,
        generation_record_sha256: `sha256:${"0".repeat(64)}`,
        completed_generation: 2,
      },
      transaction_key_sha256: `sha256:${"f".repeat(64)}`,
      directories,
      files,
    });
    expect(body.length).toBeGreaterThan(16 * 1024 * 1024);
    expect(body.length).toBeLessThanOrEqual(64 * 1024 * 1024);
  }, 30_000);

  it("reads only exact transaction-owned multi-link private artifacts", () => {
    const root = sandbox();
    const transactionKey = key("private-artifact-ownership");
    const target = path.join(
      root,
      "goals",
      "goal-atomic",
      "events",
      "TASK-1",
      "private.json",
    );
    const foreign = path.join(root, "foreign-private-hardlink.json");
    const body = "{\"private\":true}\n";

    withLock(root, () => {
      expect(atomicCreate(target, body)).toBe(true);
      const active = readPrivateAtomicArtifact(root, target, {
        operation: "CREATE",
        maxBytes: 1024,
      });
      expect(active.bytes.toString("utf8")).toBe(body);
      expect(active.ownership.kind).toBe("ACTIVE_ODD");

      linkSync(target, foreign);
      expect(() => readPrivateAtomicArtifact(root, target, {
        operation: "CREATE",
        maxBytes: 1024,
      })).toThrow(expect.objectContaining({
        code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
      }));
      expect(readFileSync(foreign, "utf8")).toBe(body);
      unlinkSync(foreign);

      expect(readPrivateAtomicArtifact(root, target, {
        operation: "CREATE",
        maxBytes: 1024,
      }).ownership.kind).toBe("ACTIVE_ODD");
    }, {
      transactionKey,
      staleMilliseconds: 0,
      timeoutMilliseconds: 1_000,
      authorizeOddRecovery: () => true,
      authorizePristineOddRecovery: () => true,
    });

    const completed = readPrivateAtomicArtifact(root, target, {
      operation: "CREATE",
      maxBytes: 1024,
    });
    expect(completed.bytes.toString("utf8")).toBe(body);
    expect(completed.ownership.kind).toBe("SINGLE_LINK");
    expect(atomicTransportEntries(root)).toEqual([]);
  });

  it("reads a sealed completed-even cleanup claim without mutating recovery state", () => {
    const root = sandbox();
    const transactionKey = key("private-artifact-cleanup-claim");
    const nextTransactionKey = key("private-artifact-cleanup-claim-next");
    const target = witnessFile(root);
    const body = "{\"witness\":true}\n";
    expectSigkill(
      crash(
        root,
        transactionKey,
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_CLAIM",
      ),
    );

    const beforeRead = atomicTransportEntries(root);
    expect(beforeRead.some((entry) => (
      entry.includes("cleanup-EVEN-")
        && entry.includes("/PUBLISH_LINEAGE/")
        && entry.endsWith(".published")
    ))).toBe(true);
    const foreignHardlink = path.join(root, "foreign-private-hardlink.json");
    linkSync(target, foreignHardlink);
    expect(() => readPrivateAtomicArtifact(root, target, {
      operation: "WRITE",
      maxBytes: 1024,
    })).toThrow(expect.objectContaining({
      code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
    }));
    expect(readFileSync(foreignHardlink, "utf8")).toBe(body);
    unlinkSync(foreignHardlink);

    const recovered = readPrivateAtomicArtifact(root, target, {
      operation: "WRITE",
      maxBytes: 1024,
    });
    expect(recovered.bytes.toString("utf8")).toBe(body);
    expect(recovered.ownership.kind).toBe("COMPLETED_EVEN_CLEANUP");
    expect(atomicTransportEntries(root)).toEqual(beforeRead);

    const targetLineage = atomicTransportFiles(root).find((file) => (
      file.includes(`${path.sep}PUBLISH_LINEAGE${path.sep}WRITE${path.sep}`)
        && file.includes(
          `${path.sep}${DEFAULT_WITNESS_RELATIVE}${path.sep}`,
        )
        && file.endsWith(".published")
    ));
    expect(targetLineage).toBeDefined();
    unlinkSync(targetLineage!);
    const partialCleanupBeforeRead = atomicTransportEntries(root);
    expect(() => readPrivateAtomicArtifact(root, target, {
      operation: "CREATE",
      maxBytes: 1024,
    })).toThrow(expect.objectContaining({
      code: "STORE_ATOMIC_ARTIFACT_INVALID",
    }));
    const afterMarkerRemoval = readPrivateAtomicArtifact(root, target, {
      operation: "WRITE",
      maxBytes: 1024,
    });
    expect(afterMarkerRemoval.bytes.toString("utf8")).toBe(body);
    expect(afterMarkerRemoval.ownership.kind)
      .toBe("COMPLETED_EVEN_CLEANUP");
    expect(atomicTransportEntries(root)).toEqual(partialCleanupBeforeRead);

    withLock(root, () => {
      atomicWrite(path.join(root, "next.json"), "next\n");
    }, {
      transactionKey: nextTransactionKey,
      staleMilliseconds: 0,
      timeoutMilliseconds: 1_000,
      authorizeOddRecovery: () => true,
      authorizePristineOddRecovery: () => true,
    });
    expect(atomicTransportEntries(root)).toEqual([]);
  });

  it("reads through an empty terminal cleanup claim after manifest unlink", () => {
    const root = sandbox();
    const target = witnessFile(root);
    expectSigkill(crash(
      root,
      key("private-artifact-terminal-cleanup"),
      "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_MANIFEST_UNLINK",
    ));
    const beforeRead = atomicTransportEntries(root);
    expect(beforeRead).toHaveLength(1);
    expect(beforeRead[0]).toContain("cleanup-EVEN-");

    const recovered = readPrivateAtomicArtifact(root, target, {
      operation: "WRITE",
      maxBytes: 1024,
    });
    expect(recovered.bytes.toString("utf8")).toBe("{\"witness\":true}\n");
    expect(recovered.ownership.kind)
      .toBe("SINGLE_LINK_EVEN_CLEANUP_TERMINAL");
    expect(atomicTransportEntries(root)).toEqual(beforeRead);

    withLock(root, () => {
      atomicWrite(path.join(root, "terminal-next.json"), "next\n");
    }, {
      transactionKey: key("private-artifact-terminal-cleanup-next"),
      staleMilliseconds: 0,
      timeoutMilliseconds: 1_000,
      authorizeOddRecovery: () => true,
      authorizePristineOddRecovery: () => true,
    });
    expect(atomicTransportEntries(root)).toEqual([]);
  });

  it("rejects an oversized private artifact before reading its bytes", () => {
    const root = sandbox();
    const target = path.join(root, "oversized-private.json");
    writeFileSync(target, Buffer.alloc(1025, 0x61), { mode: 0o600 });
    const readSpy = jest.spyOn(fs, "readFileSync");
    try {
      expect(() => readPrivateAtomicArtifact(root, target, {
        operation: "CREATE",
        maxBytes: 1024,
      })).toThrow(expect.objectContaining({
        code: "STORE_ATOMIC_ARTIFACT_INVALID",
      }));
      expect(readSpy.mock.calls.some(([file]) => (
        typeof file === "string" && path.resolve(file) === target
      ))).toBe(false);
    } finally {
      readSpy.mockRestore();
    }
  });

  it("anchors the bounded ownership read to the prechecked inode", () => {
    const root = sandbox();
    const target = path.join(root, "private-race.json");
    const original = path.join(root, "private-race-original.json");
    writeFileSync(target, "small\n", { mode: 0o600 });
    const originalOpenSync = fs.openSync;
    let targetOpenCount = 0;
    const openSpy = jest.spyOn(fs, "openSync").mockImplementation(((
      file: fs.PathLike,
      flags: fs.OpenMode,
      mode?: fs.Mode | null,
    ) => {
      if (typeof file === "string" && path.resolve(file) === target) {
        targetOpenCount += 1;
        if (targetOpenCount === 2) {
          renameSync(target, original);
          writeFileSync(target, Buffer.alloc(2 * 1024 * 1024, 0x63), {
            mode: 0o600,
          });
        }
      }
      return mode === undefined
        ? originalOpenSync(file, flags)
        : originalOpenSync(file, flags, mode);
    }) as typeof fs.openSync);
    try {
      expect(() => readPrivateAtomicArtifact(root, target, {
        operation: "CREATE",
        maxBytes: 1024,
      })).toThrow(expect.objectContaining({
        code: "STORE_ATOMIC_ARTIFACT_INVALID",
      }));
      expect(targetOpenCount).toBeGreaterThanOrEqual(2);
      expect(lstatSync(target).size).toBe(2 * 1024 * 1024);
      expect(readFileSync(original, "utf8")).toBe("small\n");
    } finally {
      openSpy.mockRestore();
    }
  });

  it("rejects a replacement at the ownership lstat before reading its bytes", () => {
    const root = sandbox();
    const target = path.join(root, "private-lstat-race.json");
    const original = path.join(root, "private-lstat-race-original.json");
    writeFileSync(target, "small\n", { mode: 0o600 });
    const originalLstatSync = fs.lstatSync;
    let targetLstatCount = 0;
    const readSpy = jest.spyOn(fs, "readSync");
    const lstatSpy = jest.spyOn(fs, "lstatSync").mockImplementation(((
      file: fs.PathLike,
    ) => {
      if (typeof file === "string" && path.resolve(file) === target) {
        targetLstatCount += 1;
        if (targetLstatCount === 2) {
          renameSync(target, original);
          writeFileSync(target, Buffer.alloc(2 * 1024 * 1024, 0x64), {
            mode: 0o600,
          });
        }
      }
      return originalLstatSync(file);
    }) as typeof fs.lstatSync);
    try {
      expect(() => readPrivateAtomicArtifact(root, target, {
        operation: "CREATE",
        maxBytes: 1024,
      })).toThrow(expect.objectContaining({
        code: "STORE_ATOMIC_ARTIFACT_INVALID",
      }));
      expect(targetLstatCount).toBe(2);
      expect(readSpy).not.toHaveBeenCalled();
      expect(lstatSync(target).size).toBe(2 * 1024 * 1024);
      expect(readFileSync(original, "utf8")).toBe("small\n");
    } finally {
      lstatSpy.mockRestore();
      readSpy.mockRestore();
    }
  });

  it("bounds a root generation inode that grows after fstat before read", () => {
    const root = sandbox();
    const transactionKey = key("generation-grow-before-read");
    const target = path.join(root, "private-generation-grow.json");
    withLock(root, () => {
      expect(atomicCreate(target, "small\n")).toBe(true);
    }, {
      transactionKey,
      staleMilliseconds: 0,
      timeoutMilliseconds: 1_000,
      authorizeOddRecovery: () => true,
      authorizePristineOddRecovery: () => true,
    });
    const generationFile = path.join(root, ".generation.json");
    const generationStat = lstatSync(generationFile);
    const originalFstatSync = fs.fstatSync;
    let grewGeneration = false;
    const readSpy = jest.spyOn(fs, "readSync");
    const fstatSpy = jest.spyOn(fs, "fstatSync").mockImplementation(((
      descriptor: number,
    ) => {
      const opened = originalFstatSync(descriptor);
      if (
        !grewGeneration
          && opened.dev === generationStat.dev
          && opened.ino === generationStat.ino
      ) {
        grewGeneration = true;
        fs.appendFileSync(
          generationFile,
          Buffer.alloc(2 * 1024 * 1024, 0x65),
        );
      }
      return opened;
    }) as typeof fs.fstatSync);
    try {
      expect(() => readPrivateAtomicArtifact(root, target, {
        operation: "CREATE",
        maxBytes: 1024,
      })).toThrow(expect.objectContaining({
        code: "CORRUPT_STORE",
      }));
      expect(grewGeneration).toBe(true);
      const requestedBytes = (
        readSpy.mock.calls as unknown as Array<unknown[]>
      ).reduce(
        (total, call) => total + Number(call[3] || 0),
        0,
      );
      expect(requestedBytes).toBe(generationStat.size);
      expect(requestedBytes).toBeLessThan(2 * 1024 * 1024);
      expect(lstatSync(generationFile).size).toBe(
        generationStat.size + (2 * 1024 * 1024),
      );
    } finally {
      fstatSpy.mockRestore();
      readSpy.mockRestore();
    }
  });

  it("keeps the target limit separate from legal transport artifacts", () => {
    const root = sandbox();
    const transactionKey = key("private-artifact-transport-budget");
    const target = path.join(root, "private-small.json");
    const oversized = path.join(root, "private-oversized.json");
    withLock(root, () => {
      expect(atomicCreate(target, "small\n")).toBe(true);
      expect(atomicCreate(
        oversized,
        Buffer.alloc(1025, 0x62),
      )).toBe(true);
      expect(readPrivateAtomicArtifact(root, target, {
        operation: "CREATE",
        maxBytes: 1024,
      }).bytes.toString("utf8")).toBe("small\n");
    }, {
      transactionKey,
      staleMilliseconds: 0,
      timeoutMilliseconds: 1_000,
      authorizeOddRecovery: () => true,
      authorizePristineOddRecovery: () => true,
    });
  });

  it.each([
    [
      "marker unlink",
      "GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_IMPORT_ADOPTION_MARKER_UNLINK",
      undefined,
    ],
    ...Array.from({ length: 8 }, (_unused, index) => [
      `directory cleanup ${index + 1}`,
      "GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_IMPORT_ADOPTION_DIRECTORY_RMDIR",
      index + 1,
    ]),
  ] as Array<[string, string, number | undefined]>)(
    "exact-retries SOURCE_IMPORT adoption after SIGKILL at %s",
    (_label, fault, occurrence) => {
      const root = sandbox();
      const fixture = sourceImportAdoptionFixture(
        `source-import-adoption-${occurrence ?? "unlink"}`,
      );

      expectSigkill(crashSourceImportAdoption(
        root,
        fixture,
        fault,
        occurrence,
      ));
      runSourceImportAdoption(root, fixture);

      expect(readFileSync(
        path.join(root, fixture.intentRelative),
        "utf8",
      )).toBe(fixture.intentBody);
      expect(readFileSync(
        path.join(root, "source-import-adoption", "continued.json"),
        "utf8",
      )).toBe("{\"continued\":true}\n");
      expect(atomicTransportEntries(root)).toEqual([]);
      expect(
        (
          JSON.parse(readFileSync(
            path.join(root, ".generation.json"),
            "utf8",
          )) as { generation: number }
        ).generation % 2,
      ).toBe(0);
    },
  );

  it.each([
    "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_AFTER_ATOMIC_RESERVATION",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_AFTER_ATOMIC_TEMP_CREATE",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_DURING_ATOMIC_TEMP_WRITE",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_AFTER_ATOMIC_TEMP_FSYNC",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_AFTER_ATOMIC_PUBLICATION_LINK",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_AFTER_ATOMIC_PUBLISH",
  ])("recovers a real SIGKILL at %s before entering the callback", (fault) => {
    const root = sandbox();
    exactRetry(root, key(`generation-begin-setup-${fault}`));
    const transactionKey = key(`generation-begin-${fault}`);

    expectSigkill(crash(root, transactionKey, fault));
    const timestampEntry = atomicTransportEntries(root).find(
      (entry) => (
        /-time-[0-9]{13}\.tmp(?:\.reservation\.json)?$/.test(entry)
      ),
    );
    const timestampMatch = timestampEntry
      ? /-time-([0-9]{13})\.tmp(?:\.reservation\.json)?$/
        .exec(timestampEntry)
      : null;
    const originalStartedAt = timestampMatch
      ? new Date(Number(timestampMatch[1])).toISOString()
      : (JSON.parse(readFileSync(
        path.join(root, ".generation.json"),
        "utf8",
      )) as { updated_at: string }).updated_at;
    let retryMode = "";
    let retryStartedAt = "";

    exactRetry(root, transactionKey, {
      beforeGeneration: (mode, startedAt) => {
        retryMode = mode;
        retryStartedAt = startedAt;
      },
    });

    expect(readFileSync(witnessFile(root), "utf8"))
      .toBe("{\"witness\":true}\n");
    expect(atomicTransportEntries(root)).toEqual([]);
    expect(["PRE_WITNESS_RETRY", "ODD_RETRY"]).toContain(retryMode);
    expect(retryStartedAt).toBe(originalStartedAt);
    const completed = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as { generation: number; active_transaction: unknown };
    expect(completed.generation % 2).toBe(0);
    expect(completed.active_transaction).toBeNull();
  });

  it.each([
    "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_AFTER_ATOMIC_RESERVATION",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_AFTER_ATOMIC_TEMP_CREATE",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_DURING_ATOMIC_TEMP_WRITE",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_AFTER_ATOMIC_TEMP_FSYNC",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_AFTER_ATOMIC_PUBLICATION_LINK",
    "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_AFTER_ATOMIC_PUBLISH",
  ])("normalizes a real SIGKILL at %s before callback replay", (fault) => {
    const root = sandbox();
    const transactionKey = key(`generation-complete-${fault}`);

    expectSigkill(crash(root, transactionKey, fault));
    expect(readFileSync(witnessFile(root), "utf8"))
      .toBe("{\"witness\":true}\n");

    let retryMode = "";
    exactRetry(root, transactionKey, {
      beforeGeneration: (mode) => {
        retryMode = mode;
      },
    });

    expect(atomicTransportEntries(root)).toEqual([]);
    expect(["ODD_RETRY", "PRE_WITNESS_RETRY"]).toContain(retryMode);
    const completed = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as { generation: number; active_transaction: unknown };
    expect(completed.generation % 2).toBe(0);
    expect(completed.active_transaction).toBeNull();
  });

  it.each([
    {
      fault:
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_PUBLISH_LINEAGE",
      completionBoundary: false,
    },
    {
      fault:
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_PAYLOAD_UNLINK",
      completionBoundary: false,
    },
    {
      fault:
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_RESERVATION_UNLINK",
      completionBoundary: false,
    },
    {
      fault:
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_ACTIVE_DIRECTORIES",
      completionBoundary: false,
    },
    {
      fault:
        "GOAL_CONTROL_TEST_FAULT_DURING_ATOMIC_CLEANUP_LINEAGE_UNLINK",
      completionBoundary: true,
    },
    {
      fault:
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_MANIFEST_UNLINK",
      completionBoundary: true,
    },
    {
      fault:
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_FINAL_DIRECTORIES",
      completionBoundary: true,
    },
  ])(
    "recovers a real SIGKILL at publication cleanup boundary $fault",
    ({ fault, completionBoundary }) => {
      const root = sandbox();
      const transactionKey = key(`publication-cleanup-${fault}`);

      expectSigkill(crash(root, transactionKey, fault));
      const crashedTransport = atomicTransportEntries(root);
      if (![
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_MANIFEST_UNLINK",
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_FINAL_DIRECTORIES",
      ].includes(fault)) {
        expect(crashedTransport.some(
          (entry) =>
            entry.includes("/PUBLISH_LINEAGE/")
              && entry.endsWith(".published"),
        )).toBe(true);
      }
      const publishedGeneration = JSON.parse(readFileSync(
        path.join(root, ".generation.json"),
        "utf8",
      )) as { generation: number; active_transaction: unknown };
      if (completionBoundary) {
        expect(readFileSync(witnessFile(root), "utf8"))
          .toBe("{\"witness\":true}\n");
        expect(publishedGeneration.generation % 2).toBe(0);
        expect(publishedGeneration.active_transaction).toBeNull();
      } else {
        expect(publishedGeneration.generation % 2).toBe(1);
        expect(publishedGeneration.active_transaction).not.toBeNull();
      }

      exactRetry(root, transactionKey);

      expect(readFileSync(witnessFile(root), "utf8"))
        .toBe("{\"witness\":true}\n");
      expect(atomicTransportEntries(root)).toEqual([]);
      const completed = JSON.parse(readFileSync(
        path.join(root, ".generation.json"),
        "utf8",
      )) as { generation: number; active_transaction: unknown };
      expect(completed.generation % 2).toBe(0);
      expect(completed.active_transaction).toBeNull();
    },
  );

  it.each([
    "GOAL_CONTROL_TEST_FAULT_DURING_ATOMIC_MKDIR_CLAIM",
    "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_MKDIR_CLAIM",
    "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_MKDIR_INSTALL",
    "GOAL_CONTROL_TEST_FAULT_BUSINESS_AFTER_ATOMIC_TEMP_CREATE",
  ])("promotes the exact MKDIR claim inode after %s", (fault) => {
    const root = sandbox();
    const transactionKey = key(`mkdir-${fault}`);

    expectSigkill(crash(root, transactionKey, fault));
    const transportBefore = atomicTransportEntries(root);
    expect(transportBefore.length).toBeGreaterThan(0);

    exactRetry(root, transactionKey);

    expect(readFileSync(witnessFile(root), "utf8"))
      .toBe("{\"witness\":true}\n");
    expect(atomicTransportEntries(root)).toEqual([]);
  });

  it("uses the sealed reservation as exact transport authority", () => {
    const root = sandbox();
    exactRetry(root, key("directory-only-setup"));

    const transactionKey = key("directory-only");
    const targetRelative =
      "goals/goal-atomic/events/TASK-1/directory-only.json";

    expectSigkill(crash(
      root,
      transactionKey,
      "GOAL_CONTROL_TEST_FAULT_BUSINESS_AFTER_ATOMIC_RESERVATION",
      targetRelative,
    ));

    exactRetry(root, transactionKey, {
      authorizePristine: false,
      authorizeWitness: false,
      offerPristineAuthority: false,
      targetRelative,
    });
    expect(atomicTransportEntries(root)).toEqual([]);
  });

  it.each([2, 3])(
    "binds an AFTER_ATOMIC_RESERVATION crash to write 2 of %i",
    (writeCount) => {
      const root = sandbox();
      const transactionKey = key(`multi-write-${writeCount}`);

      expectSigkill(crashMultiWrite(root, transactionKey, writeCount));
      expect(readFileSync(
        path.join(root, "multi", "write-1.json"),
        "utf8",
      )).toBe(`${JSON.stringify({ index: 1 })}\n`);
      expect(existsSync(path.join(root, "multi", "write-2.json")))
        .toBe(false);
      const reservation = atomicTransportEntries(root).find(
        (entry) => entry.endsWith(".reservation.json"),
      );
      expect(reservation).toContain("write-2.json");

      exactMultiWrite(root, transactionKey, writeCount);

      for (let index = 1; index <= writeCount; index += 1) {
        expect(readFileSync(
          path.join(root, "multi", `write-${index}.json`),
          "utf8",
        )).toBe(`${JSON.stringify({ index })}\n`);
      }
      expect(atomicTransportEntries(root)).toEqual([]);
    },
  );

  it.each(["rename", "remove"] as const)(
    "retains a protocol-internal %s of an earlier MKDIR in a later reservation",
    (mode) => {
      const root = sandbox();
      const transactionKey = key(`moved-lineage-${mode}`);

      expectSigkill(runMovedLineageScenario(
        root,
        transactionKey,
        mode,
        true,
      ));
      const reservationFile = atomicTransportFiles(root).find(
        (file) => file.endsWith(".reservation.json"),
      );
      expect(reservationFile).toBeTruthy();
      const reservation = JSON.parse(
        readFileSync(reservationFile!, "utf8"),
      ) as {
        target_relative: string;
        missing_relative_directories: string[];
        pristine_missing_relative_directories: string[];
      };
      expect(reservation.target_relative)
        .toBe(`lineage-${mode}/later/result.json`);
      expect(reservation.missing_relative_directories)
        .toEqual([`lineage-${mode}/later`]);
      expect(reservation.pristine_missing_relative_directories)
        .toEqual(expect.arrayContaining([
          `lineage-${mode}`,
          `lineage-${mode}/.staging`,
          `lineage-${mode}/later`,
        ]));

      const retry = runMovedLineageScenario(
        root,
        transactionKey,
        mode,
        false,
      );
      expect({
        status: retry.status,
        signal: retry.signal,
        stderr: retry.stderr,
      }).toEqual({
        status: 0,
        signal: null,
        stderr: "",
      });
      expect(readFileSync(
        path.join(root, `lineage-${mode}`, "later", "result.json"),
        "utf8",
      )).toBe(`${JSON.stringify({ later: true })}\n`);
      expect(atomicTransportEntries(root)).toEqual([]);
    },
  );

  it("rejects a dangling symlink at a vanished historical lineage path", () => {
    const root = sandbox();
    const transactionKey = key("moved-lineage-dangling-symlink");

    expectSigkill(runMovedLineageScenario(
      root,
      transactionKey,
      "rename",
      true,
    ));
    const staging = path.join(root, "lineage-rename", ".staging");
    symlinkSync("missing-lineage-target", staging);
    const before = atomicTransportEntries(root);

    expect(() => exactRetry(root, transactionKey)).toThrow(
      expect.objectContaining({
        code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
      }),
    );
    expect(lstatSync(staging).isSymbolicLink()).toBe(true);
    expect(atomicTransportEntries(root)).toEqual(before);
  });

  it.each(["MKDIR", "RESERVATION"] as const)(
    "cleans an exact empty unpublished %s after a callback error",
    (kind) => {
      const root = sandbox();
      const transactionKey = key(`callback-error-cleanup-${kind}`);
      const targetRelative = "callback-error/new/target.json";
      process.env.GOAL_CONTROL_TEST_MODE = "1";
      if (kind === "RESERVATION") {
        process.env
          .GOAL_CONTROL_TEST_FAULT_BUSINESS_AFTER_ATOMIC_RESERVATION =
            "throw";
      }
      let failure: unknown = null;
      try {
        withLock(root, () => {
          if (kind === "MKDIR") {
            ensureDir(path.join(root, "callback-error", ".init-empty"));
            throw Object.assign(new Error("expected callback error"), {
              code: "EXPECTED_CALLBACK_ERROR",
            });
          }
          atomicWrite(
            path.join(root, targetRelative),
            "{\"callback\":true}\n",
            { fault_namespace: "BUSINESS" },
          );
        }, {
          transactionKey,
          staleMilliseconds: 0,
          timeoutMilliseconds: 1_000,
          authorizeOddRecovery: () => true,
          authorizePristineOddRecovery: () => true,
        });
      } catch (error) {
        failure = error;
      } finally {
        delete process.env
          .GOAL_CONTROL_TEST_FAULT_BUSINESS_AFTER_ATOMIC_RESERVATION;
      }

      expect(failure).toMatchObject({
        code: kind === "MKDIR"
          ? "EXPECTED_CALLBACK_ERROR"
          : "TEST_ATOMIC_FAULT",
      });
      expect(atomicTransportEntries(root)).toEqual([]);
      expect(existsSync(witnessFile(root, targetRelative))).toBe(false);
      expect(JSON.parse(readFileSync(
        path.join(root, ".generation.json"),
        "utf8",
      )).generation % 2).toBe(0);
    },
  );

  it("preserves an unpublished payload when callback cleanup is not safe", () => {
    const root = sandbox();
    const transactionKey = key("callback-error-payload-preserved");
    const targetRelative = "callback-error/payload.json";
    process.env.GOAL_CONTROL_TEST_MODE = "1";
    process.env.GOAL_CONTROL_TEST_FAULT_BUSINESS_AFTER_ATOMIC_TEMP_CREATE =
      "throw";
    let failure: unknown = null;
    try {
      withLock(root, () => {
        atomicWrite(
          witnessFile(root, targetRelative),
          "{\"witness\":true}\n",
          { fault_namespace: "BUSINESS" },
        );
      }, {
        transactionKey,
        staleMilliseconds: 0,
        timeoutMilliseconds: 1_000,
        authorizeOddRecovery: () => true,
        authorizePristineOddRecovery: () => true,
      });
    } catch (error) {
      failure = error;
    } finally {
      delete process.env
        .GOAL_CONTROL_TEST_FAULT_BUSINESS_AFTER_ATOMIC_TEMP_CREATE;
    }
    expect(failure).toMatchObject({
      code: "STORE_ATOMIC_RESIDUAL_UNCONSUMED",
      cause: expect.objectContaining({ code: "TEST_ATOMIC_FAULT" }),
    });
    const before = atomicTransportFiles(root).map(
      (file) => [file, readFileSync(file).toString("base64")],
    );
    expect(before.some(([file]) => (
      path.basename(file).startsWith(".payload-")
    ))).toBe(true);
    expect(JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )).generation % 2).toBe(1);
    expect(existsSync(path.join(root, ".lock"))).toBe(true);
  });

  it.each([
    "empty transport",
    "lone WRITE payload",
    "divergent partial chain",
  ])("preserves a foreign %s until requested transaction binding", (kind) => {
    const root = sandbox();
    exactRetry(root, key(`foreign-residual-setup-${kind}`));
    const ownerTransaction = key(`foreign-residual-owner-${kind}`);
    const requestedTransaction = key(`foreign-residual-requested-${kind}`);
    const fault = kind === "empty transport"
      ? "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_AFTER_ATOMIC_RESERVATION"
      : kind === "lone WRITE payload"
        ? "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_AFTER_ATOMIC_TEMP_CREATE"
        : "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_DURING_ATOMIC_TEMP_WRITE";
    expectSigkill(crash(root, ownerTransaction, fault));
    const reservation = atomicTransportFiles(root).find(
      (file) => file.endsWith(".reservation.json"),
    );
    expect(reservation).toBeTruthy();
    if (kind === "empty transport") {
      unlinkSync(reservation!);
    } else if (kind === "lone WRITE payload") {
      unlinkSync(reservation!);
    } else {
      const payload = atomicTransportFiles(root).find(
        (file) => path.basename(file).startsWith(".payload-"),
      );
      expect(payload).toBeTruthy();
      writeFileSync(payload!, "foreign-prefix", { mode: 0o600 });
    }
    const beforeEntries = atomicTransportEntries(root);
    const beforeFiles = atomicTransportFiles(root).map(
      (file) => [file, readFileSync(file).toString("base64")],
    );

    expect(() => exactRetry(root, requestedTransaction)).toThrow(
      expect.objectContaining({
        code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
      }),
    );
    expect(atomicTransportEntries(root)).toEqual(beforeEntries);
    expect(atomicTransportFiles(root).map(
      (file) => [file, readFileSync(file).toString("base64")],
    )).toEqual(beforeFiles);
  });

  it("rejects a mode-drifted claimed directory without cleanup", () => {
    const root = sandbox();
    const transactionKey = key("mkdir-mode-drift");

    expectSigkill(crash(
      root,
      transactionKey,
      "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_MKDIR_INSTALL",
    ));
    const claimed = path.join(root, "goals", "goal-atomic", "events", "TASK-1");
    chmodSync(claimed, 0o755);
    const before = atomicTransportEntries(root);

    expect(() => exactRetry(root, transactionKey)).toThrow(
      expect.objectContaining({
        code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
      }),
    );
    expect(atomicTransportEntries(root)).toEqual(before);
  });

  it("fails closed and preserves a divergent payload prefix", () => {
    const root = sandbox();
    const transactionKey = key("payload-prefix-tamper");

    expectSigkill(crash(
      root,
      transactionKey,
      "GOAL_CONTROL_TEST_FAULT_BUSINESS_DURING_ATOMIC_TEMP_WRITE",
    ));
    const [payload] = atomicTransportFiles(root);
    expect(payload).toBeTruthy();
    writeFileSync(payload, "foreign-prefix", { mode: 0o600 });
    const before = readFileSync(payload);

    expect(() => exactRetry(root, transactionKey)).toThrow(
      expect.objectContaining({
        code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
      }),
    );
    expect(readFileSync(payload)).toEqual(before);
  });

  it("does not seal a publication marker after its counterpart disappears", () => {
    const root = sandbox();
    const transactionKey = key("cleanup-counterpart-disappears");
    const target = path.join(root, "manifest-counterpart-race.json");
    const body = "durable-payload\n";
    const originalLstatSync = fs.lstatSync;
    let armed = false;
    let removedCounterpart = false;
    const lstatSpy = jest.spyOn(fs, "lstatSync").mockImplementation(((
      file: fs.PathLike,
    ) => {
      if (
        armed
          && !removedCounterpart
          && typeof file === "string"
          && file.includes(`${path.sep}PUBLISH_LINEAGE${path.sep}`)
          && file.includes(`${path.sep}${path.basename(target)}${path.sep}`)
          && new Error().stack?.includes("atomicCleanupManifestEntry")
      ) {
        unlinkSync(target);
        removedCounterpart = true;
      }
      return originalLstatSync(file);
    }) as typeof fs.lstatSync);
    try {
      expect(() => withLock(root, () => {
        expect(atomicCreate(target, body)).toBe(true);
        armed = true;
      }, {
        transactionKey,
        staleMilliseconds: 0,
        timeoutMilliseconds: 1_000,
        authorizeOddRecovery: () => true,
        authorizePristineOddRecovery: () => true,
      })).toThrow(expect.objectContaining({
        code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
      }));
    } finally {
      lstatSpy.mockRestore();
    }
    expect(removedCounterpart).toBe(true);
    expect(existsSync(target)).toBe(false);
    const retainedMarker = atomicTransportFiles(root).find((file) => (
      file.includes(`${path.sep}PUBLISH_LINEAGE${path.sep}`)
        && file.includes(`${path.sep}${path.basename(target)}${path.sep}`)
        && file.endsWith(".published")
    ));
    expect(retainedMarker).toBeDefined();
    expect(readFileSync(retainedMarker!, "utf8")).toBe(body);
  });

  it("does not bless a replaced mkdir lineage while sealing cleanup", () => {
    const root = sandbox();
    const transactionKey = key("cleanup-mkdir-lineage-replaced");
    const target = path.join(
      root,
      "nested",
      "manifest-mkdir-race",
      "target.json",
    );
    const originalLstatSync = fs.lstatSync;
    let armed = false;
    let replacedLineage = false;
    const lstatSpy = jest.spyOn(fs, "lstatSync").mockImplementation(((
      file: fs.PathLike,
    ) => {
      if (
        armed
          && !replacedLineage
          && typeof file === "string"
          && file.includes(`${path.sep}MKDIR_LINEAGE${path.sep}`)
          && new Error().stack?.includes("atomicCleanupManifestEntry")
      ) {
        unlinkSync(file);
        writeFileSync(file, "foreign-mkdir-lineage\n", { mode: 0o600 });
        replacedLineage = true;
      }
      return originalLstatSync(file);
    }) as typeof fs.lstatSync);
    try {
      expect(() => withLock(root, () => {
        atomicWrite(target, "payload\n");
        armed = true;
      }, {
        transactionKey,
        staleMilliseconds: 0,
        timeoutMilliseconds: 1_000,
        authorizeOddRecovery: () => true,
        authorizePristineOddRecovery: () => true,
      })).toThrow(expect.objectContaining({
        code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
      }));
    } finally {
      lstatSpy.mockRestore();
    }
    expect(replacedLineage).toBe(true);
    const retainedLineage = atomicTransportFiles(root).find((file) => (
      file.includes(`${path.sep}MKDIR_LINEAGE${path.sep}`)
    ));
    expect(retainedLineage).toBeDefined();
    expect(readFileSync(retainedLineage!, "utf8"))
      .toBe("foreign-mkdir-lineage\n");
  });

  it.each(["foreign file", "symlink"])(
    "fails closed and preserves an extra %s in strict transport",
    (kind) => {
      const root = sandbox();
      const transactionKey = key(`foreign-${kind}`);

      expectSigkill(crash(
        root,
        transactionKey,
        "GOAL_CONTROL_TEST_FAULT_BUSINESS_AFTER_ATOMIC_TEMP_CREATE",
      ));
      const [payload] = atomicTransportFiles(root);
      expect(payload).toBeTruthy();
      const foreign = path.join(path.dirname(payload), "foreign.lookalike");
      if (kind === "symlink") {
        symlinkSync(path.basename(payload), foreign);
      } else {
        writeFileSync(foreign, "foreign", { mode: 0o600 });
      }
      const before = atomicTransportEntries(root);

      expect(() => exactRetry(root, transactionKey)).toThrow(
        expect.objectContaining({
          code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
        }),
      );
      expect(atomicTransportEntries(root)).toEqual(before);
    },
  );
});
