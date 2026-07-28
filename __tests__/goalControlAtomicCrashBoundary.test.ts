import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
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

type TransactionKey = {
  schema_version: 1;
  kind: string;
  scope: Record<string, string>;
  stable_operation_id_sha256: string;
  request_sha256: string;
  key_sha256: string;
};

type Boundary = "SECOND_WRITE_RESERVATION" | "SECOND_MKDIR_CLAIM";

type SnapshotEntry = {
  relative: string;
  kind: "directory" | "file" | "symlink" | "other";
  mode: number;
  nlink: number;
  dev: string;
  ino: string;
  bytes_base64?: string;
  symlink_target?: string;
};

const nodeRequire = createRequire(import.meta.url);
const storeModulePath = nodeRequire.resolve(
  "../scripts/goal-control/store.js",
);
const {
  atomicWrite,
  canonicalTransactionKey,
  ensureDir,
  withLock,
} = nodeRequire(storeModulePath) as {
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
  ensureDir: (directory: string) => void;
  withLock: <T>(
    root: string,
    callback: () => T,
    options: {
      transactionKey: TransactionKey;
      staleMilliseconds?: number;
      timeoutMilliseconds?: number;
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

const sandboxes: string[] = [];

function sandbox(prefix: string): string {
  const root = mkdtempSync(path.join(tmpdir(), prefix));
  sandboxes.push(root);
  return root;
}

function key(stableId: string): TransactionKey {
  return canonicalTransactionKey(
    "GOAL_EVENT",
    { goal_id: "goal-crash-boundary", task_id: "TASK-BOUNDARY" },
    stableId,
    hashObject({
      schema_version: 1,
      stable_id: stableId,
      request: "exact-crash-boundary",
    }),
  );
}

function lockOptions(transactionKey: TransactionKey) {
  return {
    transactionKey,
    staleMilliseconds: 0,
    timeoutMilliseconds: 1_000,
    authorizeOddRecovery: () => true,
    authorizePristineOddRecovery: () => true,
  };
}

function runBoundaryCallback(
  root: string,
  transactionKey: TransactionKey,
  boundary: Boundary,
): void {
  withLock(root, () => {
    if (boundary === "SECOND_WRITE_RESERVATION") {
      atomicWrite(path.join(root, "multi", "write-1.json"), "one\n");
      atomicWrite(path.join(root, "multi", "write-2.json"), "two\n");
      return;
    }
    atomicWrite(path.join(root, "mkdir-first.json"), "first\n");
    ensureDir(path.join(root, "mkdir-second", "nested"));
    atomicWrite(
      path.join(root, "mkdir-second", "nested", "result.json"),
      "result\n",
    );
  }, lockOptions(transactionKey));
}

function crashBeforeSecondSeal(
  root: string,
  transactionKey: TransactionKey,
  boundary: Boundary,
): ReturnType<typeof spawnSync> {
  const script = `
    const fs = require("fs");
    const path = require("path");
    const originalOpenSync = fs.openSync;
    const boundary = process.env.ATOMIC_BOUNDARY;
    fs.openSync = function crashAtBoundary(file, ...args) {
      const candidate = String(file);
      const secondWriteMirror = path.join(
        "WRITE",
        "multi",
        "write-2.json",
      ) + path.sep;
      const secondMkdirMirror = path.join(
        "MKDIR",
        "mkdir-second",
        "nested",
      ) + path.sep;
      const matchesWrite = boundary === "SECOND_WRITE_RESERVATION"
        && candidate.includes(path.sep + secondWriteMirror)
        && candidate.endsWith(".reservation.json");
      const matchesMkdir = boundary === "SECOND_MKDIR_CLAIM"
        && candidate.includes(path.sep + secondMkdirMirror + ".mkdir-claim-")
        && candidate.endsWith(".json");
      if (matchesWrite || matchesMkdir) {
        process.kill(process.pid, "SIGKILL");
      }
      return originalOpenSync.call(fs, file, ...args);
    };
    const {
      atomicWrite,
      ensureDir,
      withLock,
    } = require(process.env.ATOMIC_STORE_MODULE);
    const root = process.env.ATOMIC_ROOT;
    const transactionKey = JSON.parse(process.env.ATOMIC_TRANSACTION_KEY);
    withLock(root, () => {
      if (boundary === "SECOND_WRITE_RESERVATION") {
        atomicWrite(path.join(root, "multi", "write-1.json"), "one\\n");
        atomicWrite(path.join(root, "multi", "write-2.json"), "two\\n");
      } else {
        atomicWrite(path.join(root, "mkdir-first.json"), "first\\n");
        ensureDir(path.join(root, "mkdir-second", "nested"));
        atomicWrite(
          path.join(root, "mkdir-second", "nested", "result.json"),
          "result\\n",
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
      ATOMIC_BOUNDARY: boundary,
      ATOMIC_ROOT: root,
      ATOMIC_STORE_MODULE: storeModulePath,
      ATOMIC_TRANSACTION_KEY: JSON.stringify(transactionKey),
    },
  });
}

function snapshotControlTree(root: string): SnapshotEntry[] {
  const output: SnapshotEntry[] = [];
  const visit = (directory: string, relativeDirectory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      if (
        relativeDirectory === ""
          && (name === ".lock" || name.startsWith(".lock."))
      ) {
        continue;
      }
      const absolute = path.join(directory, name);
      const relative = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      const stat = lstatSync(absolute);
      const base = {
        relative,
        mode: stat.mode & 0o7777,
        nlink: stat.nlink,
        dev: String(stat.dev),
        ino: String(stat.ino),
      };
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        output.push({ ...base, kind: "directory" });
        visit(absolute, relative);
      } else if (stat.isSymbolicLink()) {
        output.push({
          ...base,
          kind: "symlink",
          symlink_target: readlinkSync(absolute),
        });
      } else if (stat.isFile()) {
        output.push({
          ...base,
          kind: "file",
          bytes_base64: readFileSync(absolute).toString("base64"),
        });
      } else {
        output.push({ ...base, kind: "other" });
      }
    }
  };
  visit(root, "");
  return output;
}

function expectCleanCompletion(root: string): void {
  const generation = JSON.parse(readFileSync(
    path.join(root, ".generation.json"),
    "utf8",
  )) as {
    generation: number;
    active_transaction: unknown;
    pre_write_vector_sha256: unknown;
  };
  expect(generation.generation % 2).toBe(0);
  expect(generation.active_transaction).toBeNull();
  expect(generation.pre_write_vector_sha256).toBeNull();
  const transport = path.join(root, ".atomic-transactions");
  if (existsSync(transport)) {
    expect(readdirSync(transport)).toEqual([]);
  }
}

function crashIntoEvenCleanupClaim(
  root: string,
  transactionKey: TransactionKey,
  fault =
    "GOAL_CONTROL_TEST_FAULT_DURING_ATOMIC_CLEANUP_LINEAGE_UNLINK",
  occurrence?: number,
): ReturnType<typeof spawnSync> {
  const script = `
    const path = require("path");
    const { atomicWrite, withLock } = require(
      process.env.ATOMIC_STORE_MODULE,
    );
    const root = process.env.ATOMIC_ROOT;
    const transactionKey = JSON.parse(process.env.ATOMIC_TRANSACTION_KEY);
    withLock(root, () => {
      atomicWrite(path.join(root, "witness.json"), "witness\\n");
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
      [fault]: "sigkill",
      ...(occurrence === undefined
        ? {}
        : { [`${fault}_OCCURRENCE`]: String(occurrence) }),
      ATOMIC_ROOT: root,
      ATOMIC_STORE_MODULE: storeModulePath,
      ATOMIC_TRANSACTION_KEY: JSON.stringify(transactionKey),
    },
  });
}

function findCleanupFile(
  directory: string,
  predicate: (file: string) => boolean,
): string {
  for (const name of readdirSync(directory).sort()) {
    const candidate = path.join(directory, name);
    const stat = lstatSync(candidate);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      try {
        return findCleanupFile(candidate, predicate);
      } catch {
        continue;
      }
    }
    if (stat.isFile() && !stat.isSymbolicLink() && predicate(candidate)) {
      return candidate;
    }
  }
  throw new Error(`cleanup claim 没有匹配 file: ${directory}`);
}

function cleanupClaimDirectory(root: string): string {
  const transport = path.join(root, ".atomic-transactions");
  const claims = readdirSync(transport).filter(
    (name) => name.startsWith("cleanup-EVEN-"),
  );
  expect(claims).toHaveLength(1);
  return path.join(transport, claims[0]);
}

function firstCleanupDataFile(directory: string): string {
  for (const name of readdirSync(directory).sort()) {
    const candidate = path.join(directory, name);
    const stat = lstatSync(candidate);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      try {
        return firstCleanupDataFile(candidate);
      } catch {
        continue;
      }
    }
    if (
      stat.isFile()
        && !stat.isSymbolicLink()
        && !name.startsWith(".cleanup-manifest-")
    ) {
      return candidate;
    }
  }
  throw new Error(`cleanup claim 没有 remaining data file: ${directory}`);
}

afterEach(() => {
  while (sandboxes.length > 0) {
    rmSync(sandboxes.pop()!, { recursive: true, force: true });
  }
});

describe("goal-control atomic crash boundaries", () => {
  it.each([
    "SECOND_WRITE_RESERVATION",
    "SECOND_MKDIR_CLAIM",
  ] as const)(
    "exact-retries a real SIGKILL before sealing %s",
    (boundary) => {
      const root = sandbox("goal-control-atomic-pre-seal-");
      const transactionKey = key(`same-${boundary}`);

      const crashed = crashBeforeSecondSeal(
        root,
        transactionKey,
        boundary,
      );
      expect(crashed.error).toBeUndefined();
      expect(crashed.status).toBeNull();
      expect(crashed.signal).toBe("SIGKILL");

      runBoundaryCallback(root, transactionKey, boundary);

      if (boundary === "SECOND_WRITE_RESERVATION") {
        expect(readFileSync(
          path.join(root, "multi", "write-1.json"),
          "utf8",
        )).toBe("one\n");
        expect(readFileSync(
          path.join(root, "multi", "write-2.json"),
          "utf8",
        )).toBe("two\n");
      } else {
        expect(readFileSync(
          path.join(root, "mkdir-first.json"),
          "utf8",
        )).toBe("first\n");
        expect(readFileSync(
          path.join(root, "mkdir-second", "nested", "result.json"),
          "utf8",
        )).toBe("result\n");
      }
      expectCleanCompletion(root);
    },
  );

  it.each([
    "SECOND_WRITE_RESERVATION",
    "SECOND_MKDIR_CLAIM",
  ] as const)(
    "preserves an unsealed %s mirror for a different transaction",
    (boundary) => {
      const root = sandbox("goal-control-atomic-wrong-tx-");
      const owner = key(`owner-${boundary}`);
      const foreign = key(`foreign-${boundary}`);

      const crashed = crashBeforeSecondSeal(root, owner, boundary);
      expect(crashed.signal).toBe("SIGKILL");
      const before = snapshotControlTree(root);

      expect(() => runBoundaryCallback(root, foreign, boundary)).toThrow(
        expect.objectContaining({ code: "STORE_TRANSACTION_MISMATCH" }),
      );
      expect(snapshotControlTree(root)).toEqual(before);
    },
  );

  it.each([
    "foreign 0600 file",
    "extra hardlink",
    "symlink",
    "mode drift",
  ] as const)(
    "fails closed and preserves a cleanup claim containing %s",
    (mutation) => {
      const root = sandbox("goal-control-atomic-cleanup-claim-");
      const transactionKey = key(`cleanup-${mutation}`);
      const crashed = crashIntoEvenCleanupClaim(root, transactionKey);
      expect(crashed.error).toBeUndefined();
      expect(crashed.status).toBeNull();
      expect(crashed.signal).toBe("SIGKILL");

      const claim = cleanupClaimDirectory(root);
      const retained = firstCleanupDataFile(claim);
      if (mutation === "foreign 0600 file") {
        writeFileSync(
          path.join(claim, "foreign-0600.bin"),
          "foreign-control-state",
          { mode: 0o600 },
        );
      } else if (mutation === "extra hardlink") {
        linkSync(retained, path.join(claim, "foreign-hardlink.bin"));
      } else if (mutation === "symlink") {
        symlinkSync(
          "missing-foreign-target",
          path.join(claim, "foreign-symlink"),
        );
      } else {
        chmodSync(retained, 0o644);
      }
      const before = snapshotControlTree(root);
      let callbackEntered = false;

      expect(() => withLock(root, () => {
        callbackEntered = true;
        atomicWrite(path.join(root, "witness.json"), "witness\n");
      }, lockOptions(transactionKey))).toThrow(
        expect.objectContaining({
          code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
        }),
      );

      expect(callbackEntered).toBe(false);
      expect(snapshotControlTree(root)).toEqual(before);
    },
  );

  it.each([
    "canonical replacement while marker remains",
    "canonical payload drift after marker removal",
  ] as const)(
    "fails closed on %s in a sealed cleanup claim",
    (mutation) => {
      const root = sandbox("goal-control-atomic-cleanup-counterpart-");
      const transactionKey = key(`cleanup-counterpart-${mutation}`);
      const crashed = crashIntoEvenCleanupClaim(
        root,
        transactionKey,
        "GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_CLAIM",
      );
      expect(crashed.error).toBeUndefined();
      expect(crashed.status).toBeNull();
      expect(crashed.signal).toBe("SIGKILL");

      const claim = cleanupClaimDirectory(root);
      const canonical = path.join(root, "witness.json");
      if (mutation === "canonical replacement while marker remains") {
        renameSync(canonical, path.join(root, "moved-original.bin"));
        writeFileSync(canonical, "tampered\n", { mode: 0o600 });
      } else {
        const marker = findCleanupFile(
          claim,
          (file) => (
            file.includes(`${path.sep}PUBLISH_LINEAGE${path.sep}WRITE`)
              && file.includes(`${path.sep}witness.json${path.sep}`)
              && file.endsWith(".published")
          ),
        );
        unlinkSync(marker);
        writeFileSync(canonical, "tampered\n", { mode: 0o600 });
      }
      const before = snapshotControlTree(root);
      let callbackEntered = false;

      expect(() => withLock(root, () => {
        callbackEntered = true;
        atomicWrite(path.join(root, "next.json"), "next\n");
      }, lockOptions(key(`cleanup-counterpart-retry-${mutation}`)))).toThrow(
        expect.objectContaining({
          code: "STORE_ATOMIC_RESIDUAL_CONFLICT",
        }),
      );

      expect(callbackEntered).toBe(false);
      expect(snapshotControlTree(root)).toEqual(before);
    },
  );
});
