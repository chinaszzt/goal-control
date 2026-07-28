import { execFileSync } from "child_process";
import { createHash } from "crypto";
import { createRequire } from "module";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

const nodeRequire = createRequire(import.meta.url);
const { parse } = nodeRequire("@babel/parser");
const traverse = nodeRequire("@babel/traverse").default;
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const PRODUCTION_ROOT = path.join(ROOT, "scripts", "goal-control");
const {
  git: readOnlyGit,
  readOnlyGitEnvironment,
} = nodeRequire(path.join(PRODUCTION_ROOT, "util.js")) as {
  git: (cwd: string, args: string[]) => string;
  readOnlyGitEnvironment: (
    overrides?: Record<string, string>,
  ) => NodeJS.ProcessEnv;
};

type AstNode = {
  arguments?: AstNode[];
  callee?: AstNode;
  key?: AstNode;
  name?: string;
  properties?: AstNode[];
  type?: string;
  value?: AstNode | string;
};

function productionJavaScriptFiles(): string[] {
  const visit = (directory: string): string[] => readdirSync(directory)
    .sort()
    .flatMap((name) => {
      const absolute = path.join(directory, name);
      return statSync(absolute).isDirectory()
        ? visit(absolute)
        : name.endsWith(".js") ? [absolute] : [];
    });
  return visit(PRODUCTION_ROOT);
}

function objectHasProperty(node: AstNode | undefined, name: string): boolean {
  return node?.type === "ObjectExpression"
    && Boolean(node.properties?.some((property) => (
      ["ObjectProperty", "ObjectMethod"].includes(property.type || "")
        && (
          property.key?.name === name
            || property.key?.value === name
        )
    )));
}

function sha256(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function indexIdentity(file: string): Record<string, string> {
  const stat = statSync(file, { bigint: true });
  return {
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: String(stat.mode),
    size: String(stat.size),
    mtimeNs: String(stat.mtimeNs),
    ctimeNs: String(stat.ctimeNs),
    sha256: sha256(file),
  };
}

describe("goal-control read-only Git boundary", () => {
  it("requires an explicit hardened env on every literal git exec", () => {
    const missing: string[] = [];
    for (const file of productionJavaScriptFiles()) {
      const ast = parse(readFileSync(file, "utf8"), {
        sourceType: "script",
      });
      traverse(ast, {
        CallExpression({ node }: { node: AstNode }) {
          if (
            node.callee?.type !== "Identifier"
              || !["execFileSync", "spawnSync"].includes(
                node.callee.name || "",
              )
              || node.arguments?.[0]?.type !== "StringLiteral"
              || node.arguments[0].value !== "git"
          ) {
            return;
          }
          if (!objectHasProperty(node.arguments[2], "env")) {
            missing.push(path.relative(ROOT, file));
          }
        },
      });
    }
    expect(missing).toEqual([]);
  });

  it("cannot re-enable optional locks or interactive credential prompts", () => {
    const env = readOnlyGitEnvironment({
      GIT_OPTIONAL_LOCKS: "1",
      GIT_TERMINAL_PROMPT: "1",
      GIT_ASKPASS: "/tmp/hostile-askpass",
      SSH_ASKPASS: "/tmp/hostile-ssh-askpass",
      GCM_INTERACTIVE: "Always",
    });
    expect(env).toMatchObject({
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0",
      GIT_ASKPASS: "/usr/bin/false",
      SSH_ASKPASS: "/usr/bin/false",
      GCM_INTERACTIVE: "Never",
    });
  });

  it("status, rev-parse, and ls-tree preserve canonical index identity", () => {
    const repository = mkdtempSync(
      path.join(tmpdir(), "goalctl-readonly-git-"),
    );
    try {
      execFileSync("git", ["init", "-q"], { cwd: repository });
      execFileSync("git", ["config", "user.name", "Goal Control Test"], {
        cwd: repository,
      });
      execFileSync("git", ["config", "user.email", "goalctl@example.invalid"], {
        cwd: repository,
      });
      writeFileSync(path.join(repository, "tracked.txt"), "tracked");
      execFileSync("git", ["add", "tracked.txt"], { cwd: repository });
      execFileSync("git", ["commit", "-qm", "fixture"], { cwd: repository });

      const index = execFileSync(
        "git",
        ["rev-parse", "--path-format=absolute", "--git-path", "index"],
        { cwd: repository, encoding: "utf8" },
      ).trim();
      const future = new Date(Date.now() + 2_000);
      utimesSync(path.join(repository, "tracked.txt"), future, future);
      const before = indexIdentity(index);

      expect(readOnlyGit(repository, [
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
      ])).toBe("");
      expect(readOnlyGit(repository, ["rev-parse", "HEAD"]))
        .toMatch(/^[0-9a-f]{40}$/);
      expect(readOnlyGit(repository, [
        "ls-tree",
        "-z",
        "HEAD",
        "--",
        "tracked.txt",
      ])).toContain("tracked.txt");

      expect(indexIdentity(index)).toEqual(before);
    } finally {
      rmSync(repository, { recursive: true, force: true });
    }
  });
});
