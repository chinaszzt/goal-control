import { createRequire } from "module";
import { readFileSync, readdirSync, statSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const nodeRequire = createRequire(import.meta.url);
const { parse } = nodeRequire("@babel/parser");
const traverse = nodeRequire("@babel/traverse").default;
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const PRODUCTION_ROOT = path.join(ROOT, "scripts", "goal-control");

type AstNode = {
  callee?: AstNode;
  key?: AstNode;
  left?: AstNode;
  name?: string;
  object?: AstNode;
  property?: AstNode;
  right?: AstNode;
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

function propertyName(node: AstNode | undefined): string | null {
  if (node?.type === "Identifier") return node.name || null;
  if (node?.type === "StringLiteral" && typeof node.value === "string") {
    return node.value;
  }
  return null;
}

function expressionSignature(node: AstNode | undefined): string {
  if (!node?.type) return "UNKNOWN";
  if (node.type === "Identifier") return node.name || "Identifier";
  if (node.type === "CallExpression") {
    return `call:${expressionSignature(node.callee)}`;
  }
  if (node.type === "MemberExpression") {
    return `${expressionSignature(node.object)}.${propertyName(node.property)}`;
  }
  return node.type;
}

describe("goal-control generation boundary hook surface", () => {
  it("keeps every production hook assignment on the audited resolver allowlist", () => {
    const properties: string[] = [];
    const methods: string[] = [];
    const assignments: string[] = [];
    for (const file of productionJavaScriptFiles()) {
      const relative = path.relative(ROOT, file);
      const ast = parse(readFileSync(file, "utf8"), {
        sourceType: "script",
      });
      traverse(ast, {
        ObjectProperty({ node }: { node: AstNode }) {
          if (propertyName(node.key) !== "afterGenerationBeforeCallback") {
            return;
          }
          const value = node.value && typeof node.value === "object"
            ? node.value
            : undefined;
          properties.push(`${relative}:${expressionSignature(value)}`);
        },
        ObjectMethod({ node }: { node: AstNode }) {
          if (propertyName(node.key) === "afterGenerationBeforeCallback") {
            methods.push(relative);
          }
        },
        AssignmentExpression({ node }: { node: AstNode }) {
          if (
            node.left?.type === "MemberExpression"
              && propertyName(node.left.property)
                === "afterGenerationBeforeCallback"
          ) {
            assignments.push(
              `${relative}:${expressionSignature(node.right)}`,
            );
          }
        },
      });
    }

    expect(methods).toEqual([]);
    expect(assignments).toEqual([]);
    expect(properties.sort()).toEqual([
      "scripts/goal-control/gate-adapters.js:call:gateGenerationBoundaryFaultHook",
      "scripts/goal-control/github-merge.js:generationBoundaryFault",
      "scripts/goal-control/github-merge.js:options.afterGenerationBeforeCallback",
      "scripts/goal-control/goal.js:call:generationBoundaryFaultHook",
      "scripts/goal-control/goal.js:call:generationBoundaryFaultHook",
      "scripts/goal-control/goal.js:call:generationBoundaryFaultHook",
      "scripts/goal-control/goal.js:call:generationBoundaryFaultHook",
      "scripts/goal-control/goal.js:call:generationBoundaryFaultHook",
      "scripts/goal-control/goal.js:call:generationBoundaryFaultHook",
      "scripts/goal-control/goal.js:call:generationBoundaryFaultHook",
      "scripts/goal-control/goal.js:call:generationBoundaryFaultHook",
      "scripts/goal-control/goal.js:call:generationBoundaryFaultHook",
      "scripts/goal-control/preclaim-issues.js:call:preclaimGenerationBoundaryFaultHook",
      "scripts/goal-control/preflight.js:call:preflightGenerationBoundaryFaultHook",
      "scripts/goal-control/resources.js:call:resourceGenerationBoundaryFaultHook",
      "scripts/goal-control/resources.js:call:resourceGenerationBoundaryFaultHook",
      "scripts/goal-control/resources.js:call:resourceGenerationBoundaryFaultHook",
      "scripts/goal-control/resources.js:call:resourceGenerationBoundaryFaultHook",
      "scripts/goal-control/usability.js:call:sourceHoldGenerationBoundaryFaultHook",
    ].sort());
  });
});
