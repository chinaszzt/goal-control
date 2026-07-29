import {
  readFileSync,
  readdirSync,
  statSync,
} from "fs";
import { createRequire } from "module";
import path from "path";
import { fileURLToPath } from "url";

const nodeRequire = createRequire(import.meta.url);
const { parse } = nodeRequire("@babel/parser");
const traverse = nodeRequire("@babel/traverse").default;

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const PRODUCTION_ROOT = path.join(ROOT, "scripts", "goal-control");
const KEYED_LOCK_OPTION_FACTORIES = new Set([
  "mergeLockOptions",
  "exportOddRecoveryLockOptions",
  "importOddRecoveryLockOptions",
  "checkpointOddRecoveryLockOptions",
]);
const READ_ONLY_OPTION_FACTORIES = new Set([
  "readOnlyGoalLoadOptions",
]);
const PRISTINE_RECOVERY_CALLSITES = new Set([
  "scripts/goal-control/gate-adapters.js:abortPristineGateIngress",
  "scripts/goal-control/github-merge.js:mergePullRequest",
  "scripts/goal-control/goal.js:acceptEvent",
  "scripts/goal-control/goal.js:advanceControlEpoch",
  "scripts/goal-control/goal.js:initializeGoal",
  "scripts/goal-control/goal.js:prepareProbeObservationChallenge",
  "scripts/goal-control/goal.js:recordGoalEventRejection",
  "scripts/goal-control/goal.js:recoverExpiredForeman",
  "scripts/goal-control/goal.js:rebuildLedger",
  "scripts/goal-control/goal.js:registerRole",
  "scripts/goal-control/preflight.js:abortPristinePreflightIngress",
  "scripts/goal-control/resources.js:acquireLeaseOnce",
  "scripts/goal-control/resources.js:reinitializeZeroRuntimeLeases",
  "scripts/goal-control/resources.js:releaseLease",
  "scripts/goal-control/resources.js:renewLeaseOnce",
  "scripts/goal-control/usability.js:revalidateSourceCheckpointHold",
]);
const RETRY_MODE_CALLSITE_FILES = [
  "gate-adapters.js",
  "goal.js",
  "preflight.js",
  "resources.js",
  "usability.js",
];

type AstNode = {
  arguments?: AstNode[];
  callee?: AstNode;
  id?: AstNode;
  key?: AstNode;
  loc?: { start: { line: number } };
  name?: string;
  properties?: AstNode[];
  type?: string;
  value?: AstNode | string | boolean | number | null;
};

type AstPath = {
  getFunctionParent: () => AstPath | null;
  get: (path: string) => AstPath;
  isFunction: () => boolean;
  node: AstNode;
  traverse: (visitors: AstVisitors) => void;
};

type AstVisitors = {
  CallExpression: (path: AstPath) => void;
};

type Parse = (
  source: string,
  options: { sourceType: "script" },
) => AstNode;
type Traverse = (ast: AstNode, visitors: AstVisitors) => void;

const parseProduction = parse as Parse;
const traverseProduction = traverse as Traverse;

function productionJavaScriptFiles(directory = PRODUCTION_ROOT): string[] {
  return readdirSync(directory)
    .sort()
    .flatMap((name) => {
      const absolute = path.join(directory, name);
      if (statSync(absolute).isDirectory()) {
        return productionJavaScriptFiles(absolute);
      }
      return name.endsWith(".js") ? [absolute] : [];
    });
}

function property(node: AstNode | undefined, name: string): AstNode | null {
  if (node?.type !== "ObjectExpression") return null;
  return node.properties?.find((candidate) => (
    ["ObjectProperty", "ObjectMethod"].includes(candidate.type || "")
      && (
        candidate.key?.name === name
          || candidate.key?.value === name
      )
  )) || null;
}

function literalFalse(node: AstNode | undefined, name: string): boolean {
  const value = property(node, name)?.value;
  return typeof value === "object"
    && value !== null
    && value.type === "BooleanLiteral"
    && value.value === false;
}

function literalTrue(node: AstNode | undefined, name: string): boolean {
  const value = property(node, name)?.value;
  return typeof value === "object"
    && value !== null
    && value.type === "BooleanLiteral"
    && value.value === true;
}

function explicitReadOnlyOption(
  node: AstNode | undefined,
  name: string,
): boolean {
  return literalFalse(node, name)
    || (
      node?.type === "CallExpression"
        && node.callee?.type === "Identifier"
        && READ_ONLY_OPTION_FACTORIES.has(node.callee.name || "")
    );
}

function location(file: string, node: AstNode, detail = ""): string {
  return `${path.relative(ROOT, file)}:${node.loc?.start.line || 0}${detail}`;
}

describe("goal-control transaction coverage", () => {
  it("requires a transaction key on every production withLock", () => {
    const missing: string[] = [];
    for (const file of productionJavaScriptFiles()) {
      const ast = parseProduction(readFileSync(file, "utf8"), { sourceType: "script" });
      traverseProduction(ast, {
        CallExpression({ node }) {
          if (node.callee?.type !== "Identifier" || node.callee.name !== "withLock") {
            return;
          }
          const options = node.arguments?.[2];
          const direct = property(options, "transactionKey") !== null;
          const approvedFactory = options?.type === "CallExpression"
            && options.callee?.type === "Identifier"
            && KEYED_LOCK_OPTION_FACTORIES.has(options.callee.name || "");
          if (!direct && !approvedFactory) missing.push(location(file, node));
        },
      });
    }
    expect(missing).toEqual([]);
  });

  it("forbids default-repair loaders directly inside stable-read callbacks", () => {
    const violations: string[] = [];
    for (const file of productionJavaScriptFiles()) {
      const ast = parseProduction(readFileSync(file, "utf8"), { sourceType: "script" });
      traverseProduction(ast, {
        CallExpression(stablePath) {
          const node = stablePath.node;
          if (
            node.callee?.type !== "Identifier"
              || node.callee.name !== "withStableRead"
          ) {
            return;
          }
          const callbackPath = stablePath.get("arguments.1");
          if (!callbackPath?.isFunction()) {
            violations.push(location(file, node, ":non-inline-callback"));
            return;
          }
          callbackPath.traverse({
            CallExpression(innerPath) {
              const inner = innerPath.node;
              if (inner.callee?.type !== "Identifier") return;
              const name = inner.callee.name || "";
              if (
                ["loadGoalStateUnlocked", "loadGoalUnlocked"].includes(name)
                  && (
                    !explicitReadOnlyOption(
                      inner.arguments?.[2],
                      "repairHeads",
                    )
                      || !explicitReadOnlyOption(
                        inner.arguments?.[2],
                        "repairBootstrapConsumption",
                      )
                  )
              ) {
                violations.push(location(file, inner, `:${name}`));
              }
              if (
                name === "rebuildUnlocked"
                  && !explicitReadOnlyOption(
                    inner.arguments?.[1],
                    "repairHeads",
                  )
              ) {
                violations.push(location(file, inner, `:${name}`));
              }
              if (
                name === "verifyLaunchResourceRequirementsUnlocked"
                  && !explicitReadOnlyOption(
                    inner.arguments?.[4],
                    "repairHeads",
                  )
              ) {
                violations.push(location(file, inner, `:${name}`));
              }
            },
          });
        },
      });
    }
    expect(violations).toEqual([]);
  });

  it("allows pristine odd recovery only at explicitly audited callsites", () => {
    const found: string[] = [];
    for (const file of productionJavaScriptFiles()) {
      const ast = parseProduction(readFileSync(file, "utf8"), { sourceType: "script" });
      traverseProduction(ast, {
        CallExpression(callPath) {
          const node = callPath.node;
          const options = node.arguments?.[2];
          const directPristineRecovery = property(
            options,
            "authorizePristineOddRecovery",
          ) !== null;
          const auditedMergeFactory = options?.type === "CallExpression"
            && options.callee?.type === "Identifier"
            && options.callee.name === "mergeLockOptions"
            && literalTrue(
              options.arguments?.[3],
              "allowPristineStart",
            );
          if (
            node.callee?.type !== "Identifier"
              || node.callee.name !== "withLock"
              || (!directPristineRecovery && !auditedMergeFactory)
          ) {
            return;
          }
          const functionName = callPath.getFunctionParent()?.node.id?.name;
          found.push(
            `${path.relative(ROOT, file)}:${functionName || "<anonymous>"}`,
          );
        },
      });
    }
    expect(found.sort()).toEqual([...PRISTINE_RECOVERY_CALLSITES].sort());
  });

  it("routes retry mode branches through the shared classifiers", () => {
    const violations: string[] = [];
    for (const name of RETRY_MODE_CALLSITE_FILES) {
      const file = path.join(PRODUCTION_ROOT, name);
      const source = readFileSync(file, "utf8");
      if (/['"](?:ODD_RETRY|PRE_WITNESS_RETRY)['"]/.test(source)) {
        violations.push(`${name}:raw-retry-mode-literal`);
      }
      if (
        !source.includes("isOddTransactionRetry")
          && !source.includes("isHistoricalTransactionRetry")
      ) {
        violations.push(`${name}:missing-shared-classifier`);
      }
    }
    expect(violations).toEqual([]);
  });

  it("forbids raw update-ref repair in the goal event decoder", () => {
    const source = readFileSync(
      path.join(PRODUCTION_ROOT, "goal.js"),
      "utf8",
    );
    expect(source).not.toMatch(/['"]update-ref['"]/);
    expect(source).toContain("P1_COMMIT_LEGACY_MIGRATION_REQUIRED");
  });
});
