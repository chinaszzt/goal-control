import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const nodeRequire = createRequire(import.meta.url);
const {
  PORTABLE_DELTA_ALLOWLIST,
  assertImportedPathsClean,
  controllerIdentity,
  extractionStatus,
  importedFiles,
  portableDeltaSha256,
  productionTreeSha256,
  sha256,
  snapshotImportedEntries,
  trackedMode,
} = nodeRequire("../scripts/extraction-provenance-lib");
const {
  verifyTargetProvenance,
} = nodeRequire("../scripts/verify-extraction-provenance");

function git(root: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function commit(root: string, message: string): string {
  git(root, "add", ".");
  git(root, "commit", "-qm", message);
  return git(root, "rev-parse", "HEAD");
}

function fixture(): {
  root: string;
  provenanceFile: string;
} {
  const root = mkdtempSync(path.join(tmpdir(), "goal-control-provenance-"));
  mkdirSync(path.join(root, "scripts"), { recursive: true });
  cpSync(
    path.join(ROOT, "scripts", "goal-control"),
    path.join(root, "scripts", "goal-control"),
    { recursive: true },
  );
  cpSync(
    path.join(ROOT, "scripts", "goalctl.js"),
    path.join(root, "scripts", "goalctl.js"),
  );
  cpSync(
    path.join(ROOT, "scripts", "resourcectl.js"),
    path.join(root, "scripts", "resourcectl.js"),
  );
  chmodSync(path.join(root, "scripts", "goalctl.js"), 0o755);
  chmodSync(path.join(root, "scripts", "resourcectl.js"), 0o755);
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.email", "provenance-test@example.invalid");
  git(root, "config", "user.name", "Provenance Test");
  commit(root, "controller snapshot");
  const files = importedFiles(root).map((relative: string) => {
    const targetSha256 = sha256(path.join(root, relative));
    const targetMode = trackedMode(root, relative);
    const portable = PORTABLE_DELTA_ALLOWLIST.has(relative);
    return {
      path: relative,
      status: portable ? "PORTABLE_DELTA" : "IDENTICAL",
      source_mode: targetMode,
      target_mode: targetMode,
      source_sha256: portable
        ? `sha256:${"0".repeat(64)}`
        : targetSha256,
      target_sha256: targetSha256,
    };
  });
  const targetController = controllerIdentity(root);
  const sourceTree = files.map((entry: {
    path: string;
    source_mode: string;
    source_sha256: string;
  }) => ({
    path: entry.path,
    mode: entry.source_mode,
    sha256: entry.source_sha256,
  }));
  const provenance = {
    schema_version: 3,
    source_label: "private-production-integration",
    target_snapshot_basis: "PROVENANCE_FIRST_ADD_COMMIT",
    source_production_tree_sha256:
      productionTreeSha256(sourceTree),
    target_production_tree_sha256:
      productionTreeSha256(files),
    imported_file_count: files.length,
    portable_delta_allowlist: [...PORTABLE_DELTA_ALLOWLIST].sort(),
    portable_delta_sha256: portableDeltaSha256(files),
    source_controller: {
      decoder_sha256: `sha256:${"1".repeat(64)}`,
      controller_closure_sha256: `sha256:${"2".repeat(64)}`,
    },
    target_controller: {
      decoder_sha256: targetController.decoder_sha256,
      controller_closure_sha256:
        targetController.controller_closure_sha256,
    },
    files,
  };
  const provenanceFile = path.join(root, "extraction", "provenance.json");
  mkdirSync(path.dirname(provenanceFile), { recursive: true });
  writeFileSync(provenanceFile, `${JSON.stringify(provenance, null, 2)}\n`);
  commit(root, "record provenance");
  return { root, provenanceFile };
}

describe("extraction provenance guards", () => {
  test("treats a Git mode change as a portable delta", () => {
    expect(extractionStatus({
      source_sha256: `sha256:${"a".repeat(64)}`,
      target_sha256: `sha256:${"a".repeat(64)}`,
      source_mode: "100644",
      target_mode: "100755",
    })).toBe("PORTABLE_DELTA");
  });

  test("allows later controller evolution but rejects rewriting the historical baseline", () => {
    const current = fixture();
    try {
      expect(() => verifyTargetProvenance(
        current.root,
        current.provenanceFile,
      )).not.toThrow();

      const changed = path.join(
        current.root,
        "scripts",
        "goal-control",
        "validation.js",
      );
      writeFileSync(
        changed,
        `${readFileSync(changed, "utf8")}\n// untrusted drift\n`,
      );
      commit(current.root, "change controller");
      expect(() => verifyTargetProvenance(
        current.root,
        current.provenanceFile,
      )).not.toThrow();

      const provenance = JSON.parse(
        readFileSync(current.provenanceFile, "utf8"),
      );
      const entry = provenance.files.find(
        (candidate: { path: string }) => (
          candidate.path === "scripts/goal-control/validation.js"
        ),
      );
      entry.target_sha256 = sha256(changed);
      entry.source_sha256 = entry.target_sha256;
      entry.status = "IDENTICAL";
      const currentHead = git(current.root, "rev-parse", "HEAD");
      const currentEntries = snapshotImportedEntries(
        current.root,
        currentHead,
      );
      provenance.target_production_tree_sha256 =
        productionTreeSha256(currentEntries);
      const currentController = controllerIdentity(current.root);
      provenance.target_controller = {
        decoder_sha256: currentController.decoder_sha256,
        controller_closure_sha256:
          currentController.controller_closure_sha256,
      };
      provenance.portable_delta_sha256 =
        portableDeltaSha256(provenance.files);
      writeFileSync(
        current.provenanceFile,
        `${JSON.stringify(provenance, null, 2)}\n`,
      );
      commit(current.root, "self-report changed controller");

      expect(() => verifyTargetProvenance(
        current.root,
        current.provenanceFile,
      )).toThrow(
        "differs from its immutable first-add blob",
      );
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  test("detects dirty imported bytes hidden by assume-unchanged", () => {
    const current = fixture();
    try {
      const resourcectl = path.join(
        current.root,
        "scripts",
        "resourcectl.js",
      );
      git(
        current.root,
        "update-index",
        "--assume-unchanged",
        "scripts/resourcectl.js",
      );
      writeFileSync(
        resourcectl,
        `${readFileSync(resourcectl, "utf8")}\n// hidden dirty bytes\n`,
      );
      expect(() => assertImportedPathsClean(
        current.root,
        importedFiles(current.root),
      )).toThrow(/pinned commit|unsafe.*flag/);
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  test("detects a dirty provenance manifest hidden by assume-unchanged", () => {
    const current = fixture();
    try {
      git(
        current.root,
        "update-index",
        "--assume-unchanged",
        "extraction/provenance.json",
      );
      writeFileSync(
        current.provenanceFile,
        `${readFileSync(current.provenanceFile, "utf8")}\n`,
      );
      expect(() => verifyTargetProvenance(
        current.root,
        current.provenanceFile,
      )).toThrow(/pinned commit|unsafe.*flag/);
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  test("rejects changing the merge-stable target snapshot basis", () => {
    const current = fixture();
    try {
      const provenance = JSON.parse(
        readFileSync(current.provenanceFile, "utf8"),
      );
      provenance.target_snapshot_basis = "HEAD";
      writeFileSync(
        current.provenanceFile,
        `${JSON.stringify(provenance, null, 2)}\n`,
      );
      commit(current.root, "replace snapshot with symbolic revision");
      expect(() => verifyTargetProvenance(
        current.root,
        current.provenanceFile,
      )).toThrow("unsupported shape");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  test("rejects a source-only baseline rewrite with a recomputed aggregate", () => {
    const current = fixture();
    try {
      const provenance = JSON.parse(
        readFileSync(current.provenanceFile, "utf8"),
      );
      const delta = provenance.files.find(
        (entry: { path: string }) => (
          entry.path === "scripts/goal-control/migration.js"
        ),
      );
      delta.source_sha256 = `sha256:${"3".repeat(64)}`;
      provenance.source_production_tree_sha256 =
        productionTreeSha256(provenance.files.map((entry: {
          path: string;
          source_mode: string;
          source_sha256: string;
        }) => ({
          path: entry.path,
          mode: entry.source_mode,
          sha256: entry.source_sha256,
        })));
      provenance.portable_delta_sha256 =
        portableDeltaSha256(provenance.files);
      writeFileSync(
        current.provenanceFile,
        `${JSON.stringify(provenance, null, 2)}\n`,
      );
      commit(current.root, "rewrite source baseline");
      expect(() => verifyTargetProvenance(
        current.root,
        current.provenanceFile,
      )).toThrow("differs from its immutable first-add blob");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
    }
  });

  test("rejects a shallow clone instead of mistaking its boundary for first-add", () => {
    const current = fixture();
    const parent = mkdtempSync(
      path.join(tmpdir(), "goal-control-provenance-shallow-"),
    );
    const shallow = path.join(parent, "repo");
    try {
      git(
        current.root,
        "clone",
        "-q",
        "--depth=1",
        `file://${current.root}`,
        shallow,
      );
      expect(() => verifyTargetProvenance(
        shallow,
        path.join(shallow, "extraction", "provenance.json"),
      )).toThrow("requires complete Git history");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
      rmSync(parent, { recursive: true, force: true });
    }
  });

  test("rejects a shallow clone after a coordinated source baseline rewrite", () => {
    const current = fixture();
    const parent = mkdtempSync(
      path.join(tmpdir(), "goal-control-provenance-shallow-rewrite-"),
    );
    const shallow = path.join(parent, "repo");
    try {
      const provenance = JSON.parse(
        readFileSync(current.provenanceFile, "utf8"),
      );
      const delta = provenance.files.find(
        (entry: { path: string }) => (
          entry.path === "scripts/goal-control/migration.js"
        ),
      );
      delta.source_sha256 = `sha256:${"4".repeat(64)}`;
      provenance.source_production_tree_sha256 =
        productionTreeSha256(provenance.files.map((entry: {
          path: string;
          source_mode: string;
          source_sha256: string;
        }) => ({
          path: entry.path,
          mode: entry.source_mode,
          sha256: entry.source_sha256,
        })));
      provenance.portable_delta_sha256 =
        portableDeltaSha256(provenance.files);
      writeFileSync(
        current.provenanceFile,
        `${JSON.stringify(provenance, null, 2)}\n`,
      );
      commit(current.root, "coordinated source baseline rewrite");
      expect(() => verifyTargetProvenance(
        current.root,
        current.provenanceFile,
      )).toThrow("differs from its immutable first-add blob");

      git(
        current.root,
        "clone",
        "-q",
        "--depth=1",
        `file://${current.root}`,
        shallow,
      );
      expect(() => verifyTargetProvenance(
        shallow,
        path.join(shallow, "extraction", "provenance.json"),
      )).toThrow("requires complete Git history");
    } finally {
      rmSync(current.root, { recursive: true, force: true });
      rmSync(parent, { recursive: true, force: true });
    }
  });

  test("ignores a caller PATH entry that shadows Git", () => {
    const current = fixture();
    const fakeBin = mkdtempSync(
      path.join(tmpdir(), "goal-control-provenance-fake-git-"),
    );
    const originalPath = process.env.PATH;
    try {
      const fakeGit = path.join(fakeBin, "git");
      writeFileSync(fakeGit, "#!/bin/sh\nexit 97\n");
      chmodSync(fakeGit, 0o755);
      process.env.PATH = `${fakeBin}${path.delimiter}${originalPath ?? ""}`;
      expect(() => verifyTargetProvenance(
        current.root,
        current.provenanceFile,
      )).not.toThrow();
    } finally {
      if (originalPath === undefined) delete process.env.PATH;
      else process.env.PATH = originalPath;
      rmSync(current.root, { recursive: true, force: true });
      rmSync(fakeBin, { recursive: true, force: true });
    }
  });

  test("survives a squash merge that rewrites every branch commit ID", () => {
    const current = fixture();
    const squashed = mkdtempSync(
      path.join(tmpdir(), "goal-control-provenance-squash-"),
    );
    try {
      git(squashed, "init", "-q", "-b", "main");
      git(
        squashed,
        "config",
        "user.email",
        "provenance-squash@example.invalid",
      );
      git(squashed, "config", "user.name", "Provenance Squash Test");
      writeFileSync(path.join(squashed, "README.md"), "# base\n");
      commit(squashed, "base");
      cpSync(
        path.join(current.root, "scripts"),
        path.join(squashed, "scripts"),
        { recursive: true },
      );
      cpSync(
        path.join(current.root, "extraction"),
        path.join(squashed, "extraction"),
        { recursive: true },
      );
      chmodSync(path.join(squashed, "scripts", "goalctl.js"), 0o755);
      chmodSync(path.join(squashed, "scripts", "resourcectl.js"), 0o755);
      commit(squashed, "squash extracted controller");
      expect(() => verifyTargetProvenance(
        squashed,
        path.join(squashed, "extraction", "provenance.json"),
      )).not.toThrow();
    } finally {
      rmSync(current.root, { recursive: true, force: true });
      rmSync(squashed, { recursive: true, force: true });
    }
  });
});
