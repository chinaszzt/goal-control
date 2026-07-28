import { execFileSync, spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';

const nodeRequire = createRequire(import.meta.url);
const {
  preclaimIssues,
  verifyPreclaimReceipt,
} = nodeRequire('../scripts/goal-control/preclaim-issues.js');
const preclaimModulePath = nodeRequire.resolve(
  '../scripts/goal-control/preclaim-issues.js',
);
const { readJson } = nodeRequire('../scripts/goal-control/util.js');
const { validateManifest } = nodeRequire('../scripts/goal-control/validation.js');
const trustedGh = execFileSync('/usr/bin/which', ['gh'], {
  encoding: 'utf8',
}).trim();

type IssueState = {
  number: number;
  url: string;
  state: 'OPEN' | 'CLOSED';
  assignees: Array<{ login: string }>;
  labels: Array<{ name: string }>;
};

function git(cwd: string, args: string[]) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function write(file: string, body: string) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
}

function fixture(prepareIsolatedControl = true) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'goal-preclaim-'));
  git(root, ['init', '-b', 'main']);
  git(root, ['config', 'user.email', 'goalctl@example.invalid']);
  git(root, ['config', 'user.name', 'goalctl test']);
  git(root, ['remote', 'add', 'origin', 'git@github.com:example-org/example-repo.git']);
  const authorization = 'docs/planning/goals/test.authorization.md';
  const packet = 'docs/planning/goals/test/packets/TASK-1-r1.md';
  const manifest = 'docs/planning/goals/test/manifest.json';
  write(path.join(root, authorization), '# scoped authorization\n');
  write(path.join(root, packet), '# packet\n');
  const authHash = `sha256:${execFileSync(
    'shasum',
    ['-a', '256', path.join(root, authorization)],
    { encoding: 'utf8' },
  ).split(/\s+/)[0]}`;
  const packetHash = `sha256:${execFileSync(
    'shasum',
    ['-a', '256', path.join(root, packet)],
    { encoding: 'utf8' },
  ).split(/\s+/)[0]}`;
  write(path.join(root, manifest), `${JSON.stringify({
    schema_version: 1,
    goal_id: 'goal-preclaim-test',
    mode: 'enforce',
    repository: {
      name_with_owner: 'example-org/example-repo',
      base_branch: 'main',
    },
    base_head: '0000000000000000000000000000000000000000',
    preclaim: {
      policy: 'supervisor-exact-whitelist-v1',
      operation_id: 'preclaim-goal-preclaim-test-r1',
      requested_at: '2026-07-25T02:40:00.000Z',
      authorization: {
        path: authorization,
        sha256: authHash,
      },
      issues: [4101],
      expected_actor: 'chinaszzt',
      expected_status: 'status:doing',
    },
    tasks: [{
      id: 'TASK-1',
      issue: 4101,
      dependencies: [],
      integration_order: 1,
      packet: {
        revision: 1,
        path: packet,
        sha256: packetHash,
      },
      p1: {
        producer: 'CAPTAIN',
        artifact_root: 'docs/issues/4101',
        authority: {
          kind: 'SCOPED_DELEGATION',
          path: authorization,
          sha256: authHash,
        },
        dependency_gate: 'ARCHIVED',
      },
      expected_write_set: ['docs/issues/4101/**'],
      conflict_domains: [],
      resource_requirements: [],
    }],
  }, null, 2)}\n`);
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'fixture']);
  const head = git(root, ['rev-parse', 'HEAD']);
  const rawManifest = readJson(path.join(root, manifest));
  rawManifest.base_head = head;
  write(path.join(root, manifest), `${JSON.stringify(rawManifest, null, 2)}\n`);
  git(root, ['add', manifest]);
  git(root, ['commit', '-m', 'bind base']);
  const finalHead = git(root, ['rev-parse', 'HEAD']);
  git(root, ['update-ref', 'refs/remotes/origin/main', finalHead]);
  const controlDir = path.join(root, '.git', 'goal-control', 'v1');
  if (prepareIsolatedControl) {
    fs.mkdirSync(controlDir, { recursive: true });
  }
  return {
    root,
    controlDir,
    manifest,
    operationId: 'preclaim-goal-preclaim-test-r1',
  };
}

function fakeGh(initial: IssueState) {
  const issue = JSON.parse(JSON.stringify(initial)) as IssueState;
  const calls: string[][] = [];
  return {
    issue,
    calls,
    runGh(args: string[]) {
      calls.push(args);
      if (args[0] === 'api' && args[1] === 'user') {
        return `${JSON.stringify({ login: 'chinaszzt' })}\n`;
      }
      if (args[0] === 'repo' && args[1] === 'view') {
        return `${JSON.stringify({
          nameWithOwner: 'example-org/example-repo',
          url: 'https://github.com/example-org/example-repo',
          viewerPermission: 'ADMIN',
        })}\n`;
      }
      if (args[0] === 'issue' && args[1] === 'view') {
        return `${JSON.stringify(issue)}\n`;
      }
      if (args[0] === 'issue' && args[1] === 'edit') {
        for (let index = 0; index < args.length; index += 1) {
          if (args[index] === '--add-assignee') {
            issue.assignees = [{ login: args[index + 1] }];
          }
          if (args[index] === '--remove-label') {
            issue.labels = issue.labels.filter(
              ({ name }) => name !== args[index + 1],
            );
          }
          if (args[index] === '--add-label') {
            issue.labels.push({ name: args[index + 1] });
          }
        }
        return '';
      }
      throw new Error(`unexpected gh args: ${args.join(' ')}`);
    },
  };
}

function withIsolatedControl<T>(
  fx: ReturnType<typeof fixture>,
  callback: () => T,
): T {
  const oldControlDir = process.env.GOAL_CONTROL_DIR;
  const oldTestMode = process.env.GOAL_CONTROL_TEST_MODE;
  process.env.GOAL_CONTROL_DIR = fx.controlDir;
  process.env.GOAL_CONTROL_TEST_MODE = '1';
  try {
    return callback();
  } finally {
    if (oldControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
    else process.env.GOAL_CONTROL_DIR = oldControlDir;
    if (oldTestMode === undefined) delete process.env.GOAL_CONTROL_TEST_MODE;
    else process.env.GOAL_CONTROL_TEST_MODE = oldTestMode;
  }
}

function run(fx: ReturnType<typeof fixture>, dependencies: Record<string, unknown>) {
  return withIsolatedControl(fx, () => preclaimIssues(fx.root, {
    manifestFile: fx.manifest,
    operationId: fx.operationId,
  }, {
    resolveExecutable: () => ({ executable: trustedGh }),
    ...dependencies,
  }));
}

function crashPreclaimAfterCleanupClaim(
  fx: ReturnType<typeof fixture>,
  initialIssue: IssueState,
) {
  const stateFile = path.join(fx.root, '.preclaim-issue-state.json');
  fs.writeFileSync(stateFile, `${JSON.stringify(initialIssue)}\n`, {
    mode: 0o600,
  });
  const script = `
    const fs = require("fs");
    const { preclaimIssues } = require(process.env.PRECLAIM_MODULE);
    const stateFile = process.env.PRECLAIM_STATE_FILE;
    const issue = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    const persist = () => fs.writeFileSync(
      stateFile,
      JSON.stringify(issue) + "\\n",
      { mode: 0o600 },
    );
    const runGh = (args) => {
      if (args[0] === "api" && args[1] === "user") {
        return JSON.stringify({ login: "chinaszzt" }) + "\\n";
      }
      if (args[0] === "repo" && args[1] === "view") {
        return JSON.stringify({
          nameWithOwner: "example-org/example-repo",
          url: "https://github.com/example-org/example-repo",
          viewerPermission: "ADMIN",
        }) + "\\n";
      }
      if (args[0] === "issue" && args[1] === "view") {
        return JSON.stringify(issue) + "\\n";
      }
      if (args[0] === "issue" && args[1] === "edit") {
        for (let index = 0; index < args.length; index += 1) {
          if (args[index] === "--add-assignee") {
            issue.assignees = [{ login: args[index + 1] }];
          }
          if (args[index] === "--remove-label") {
            issue.labels = issue.labels.filter(
              ({ name }) => name !== args[index + 1],
            );
          }
          if (args[index] === "--add-label") {
            issue.labels.push({ name: args[index + 1] });
          }
        }
        persist();
        return "";
      }
      throw new Error("unexpected gh args: " + args.join(" "));
    };
    preclaimIssues(process.env.PRECLAIM_ROOT, {
      manifestFile: process.env.PRECLAIM_MANIFEST,
      operationId: process.env.PRECLAIM_OPERATION_ID,
    }, {
      resolveExecutable: () => ({ executable: process.env.PRECLAIM_GH }),
      runGh,
    });
  `;
  const result = spawnSync(process.execPath, ['-e', script], {
    cwd: fx.root,
    encoding: 'utf8',
    env: {
      ...process.env,
      GOAL_CONTROL_DIR: fx.controlDir,
      GOAL_CONTROL_TEST_MODE: '1',
      GOAL_CONTROL_TEST_FAULT_AFTER_ATOMIC_CLEANUP_CLAIM: 'sigkill',
      PRECLAIM_MODULE: preclaimModulePath,
      PRECLAIM_STATE_FILE: stateFile,
      PRECLAIM_ROOT: fx.root,
      PRECLAIM_MANIFEST: fx.manifest,
      PRECLAIM_OPERATION_ID: fx.operationId,
      PRECLAIM_GH: trustedGh,
    },
  });
  return {
    result,
    issue: JSON.parse(fs.readFileSync(stateFile, 'utf8')) as IssueState,
  };
}

describe('goalctl preclaim-issues', () => {
  test('rejects all injected dependencies before production control mutation', () => {
    const fx = fixture(false);
    const gh = fakeGh({
      number: 4101,
      url: 'https://github.com/example-org/example-repo/issues/4101',
      state: 'OPEN',
      assignees: [],
      labels: [{ name: 'status:todo' }],
    });
    const oldControlDir = process.env.GOAL_CONTROL_DIR;
    const oldTestMode = process.env.GOAL_CONTROL_TEST_MODE;
    delete process.env.GOAL_CONTROL_DIR;
    delete process.env.GOAL_CONTROL_TEST_MODE;
    let failure: unknown;
    try {
      try {
        preclaimIssues(fx.root, {
          manifestFile: fx.manifest,
          operationId: fx.operationId,
        }, {
          resolveExecutable: () => ({ executable: trustedGh }),
          runGh: gh.runGh,
        });
      } catch (error: unknown) {
        failure = error;
      }
    } finally {
      if (oldControlDir === undefined) delete process.env.GOAL_CONTROL_DIR;
      else process.env.GOAL_CONTROL_DIR = oldControlDir;
      if (oldTestMode === undefined) delete process.env.GOAL_CONTROL_TEST_MODE;
      else process.env.GOAL_CONTROL_TEST_MODE = oldTestMode;
    }
    expect(failure).toMatchObject({ code: 'TEST_MODE_FORBIDDEN' });
    expect(fs.existsSync(fx.controlDir)).toBe(false);
    expect(gh.calls).toHaveLength(0);
    fs.rmSync(fx.root, { recursive: true, force: true });
  });

  test('rejects the former public sealed-canary dependency in test mode', () => {
    const fx = fixture();
    let failure: unknown;
    try {
      withIsolatedControl(fx, () => preclaimIssues(fx.root, {
        manifestFile: fx.manifest,
        operationId: fx.operationId,
      }, {
        sealedGithubCanary: () => null,
      }));
    } catch (error: unknown) {
      failure = error;
    }
    expect(failure).toMatchObject({ code: 'INVALID_TEST_DEPENDENCY' });
    expect(fs.readdirSync(fx.controlDir)).toEqual([]);
    fs.rmSync(fx.root, { recursive: true, force: true });
  });

  test('seals CLAIMED readback, exact retry is idempotent, and init verifies receipt', () => {
    const fx = fixture();
    const gh = fakeGh({
      number: 4101,
      url: 'https://github.com/example-org/example-repo/issues/4101',
      state: 'OPEN',
      assignees: [],
      labels: [{ name: 'status:todo' }],
    });
    const first = run(fx, { runGh: gh.runGh });
    expect(first.status).toBe('PASS');
    expect(first.issues[0].result).toBe('CLAIMED');
    expect(first.issues[0].assignees).toEqual(['chinaszzt']);
    expect(first.issues[0].status).toBe('status:doing');
    const editCount = gh.calls.filter((args) => args[1] === 'edit').length;
    expect(run(fx, { runGh: gh.runGh })).toEqual(first);
    expect(gh.calls.filter((args) => args[1] === 'edit')).toHaveLength(
      editCount,
    );
    const normalized = validateManifest(
      readJson(path.join(fx.root, fx.manifest)),
      path.join(fx.root, fx.manifest),
      fx.root,
    );
    expect(() => verifyPreclaimReceipt(
      fx.root,
      normalized,
      path.join(fx.root, fx.manifest),
    )).not.toThrow();
    fs.rmSync(fx.root, { recursive: true, force: true });
  });

  test('exact retry reads a completed-even cleanup claim before lock recovery', () => {
    const fx = fixture();
    const crashed = crashPreclaimAfterCleanupClaim(fx, {
      number: 4101,
      url: 'https://github.com/example-org/example-repo/issues/4101',
      state: 'OPEN',
      assignees: [],
      labels: [{ name: 'status:todo' }],
    });
    expect(crashed.result.error).toBeUndefined();
    expect(crashed.result.status).toBeNull();
    expect(crashed.result.signal).toBe('SIGKILL');
    expect(crashed.issue.assignees).toEqual([{ login: 'chinaszzt' }]);
    expect(crashed.issue.labels).toContainEqual({ name: 'status:doing' });

    const gh = fakeGh(crashed.issue);
    const recovered = run(fx, { runGh: gh.runGh });
    expect(recovered.status).toBe('PASS');
    expect(recovered.issues[0].result).toBe('CLAIMED');
    expect(gh.calls.filter((args) => args[1] === 'edit')).toHaveLength(0);
    const normalized = validateManifest(
      readJson(path.join(fx.root, fx.manifest)),
      path.join(fx.root, fx.manifest),
      fx.root,
    );
    expect(() => verifyPreclaimReceipt(
      fx.root,
      normalized,
      path.join(fx.root, fx.manifest),
    )).not.toThrow();
    fs.rmSync(fx.root, { recursive: true, force: true });
  });

  test.each([
    ['before external mutation', 'afterIntent'],
    ['mid external mutation', 'afterAssigneeMutation'],
    ['after receipt publication', 'afterReceipt'],
  ])('exact retry recovers crash %s without changing CLAIMED result', (_label, hook) => {
    const fx = fixture();
    const gh = fakeGh({
      number: 4101,
      url: 'https://github.com/example-org/example-repo/issues/4101',
      state: 'OPEN',
      assignees: [],
      labels: [{ name: 'status:todo' }],
    });
    let injected = false;
    expect(() => run(fx, {
      runGh: gh.runGh,
      [hook]: () => {
        if (!injected) {
          injected = true;
          throw new Error(`fault:${hook}`);
        }
      },
    })).toThrow(`fault:${hook}`);
    const recovered = run(fx, { runGh: gh.runGh });
    expect(recovered.status).toBe('PASS');
    expect(recovered.issues[0].result).toBe('CLAIMED');
    expect(recovered.issues[0].valid).toBe(true);
  });

  test('MINE_NEED_CONFIRM is an authorized idempotent PASS', () => {
    const fx = fixture();
    const gh = fakeGh({
      number: 4101,
      url: 'https://github.com/example-org/example-repo/issues/4101',
      state: 'OPEN',
      assignees: [{ login: 'chinaszzt' }],
      labels: [{ name: 'status:doing' }],
    });
    const result = run(fx, { runGh: gh.runGh });
    expect(result.issues[0].result).toBe('MINE_NEED_CONFIRM');
    expect(gh.calls.filter((args) => args[1] === 'edit')).toHaveLength(0);
  });

  test('OTHERS_REJECT seals a blocking receipt and init cannot consume it', () => {
    const fx = fixture();
    const gh = fakeGh({
      number: 4101,
      url: 'https://github.com/example-org/example-repo/issues/4101',
      state: 'OPEN',
      assignees: [{ login: 'somebody-else' }],
      labels: [{ name: 'status:todo' }],
    });
    expect(() => run(fx, { runGh: gh.runGh })).toThrow('OTHERS_REJECT');
    expect(gh.calls.filter((args) => args[1] === 'edit')).toHaveLength(0);
    const normalized = validateManifest(
      readJson(path.join(fx.root, fx.manifest)),
      path.join(fx.root, fx.manifest),
      fx.root,
    );
    expect(() => verifyPreclaimReceipt(
      fx.root,
      normalized,
      path.join(fx.root, fx.manifest),
    )).toThrow('preclaim receipt');
  });

  test('tampered receipt and request identity are rejected without GitHub mutation', () => {
    const fx = fixture();
    const gh = fakeGh({
      number: 4101,
      url: 'https://github.com/example-org/example-repo/issues/4101',
      state: 'OPEN',
      assignees: [],
      labels: [],
    });
    const result = run(fx, { runGh: gh.runGh });
    const receipt = readJson(result.receipt_file);
    receipt.actor = 'attacker';
    fs.writeFileSync(result.receipt_file, `${JSON.stringify(receipt, null, 2)}\n`);
    const normalized = validateManifest(
      readJson(path.join(fx.root, fx.manifest)),
      path.join(fx.root, fx.manifest),
      fx.root,
    );
    expect(() => verifyPreclaimReceipt(
      fx.root,
      normalized,
      path.join(fx.root, fx.manifest),
    )).toThrow('hash');
    expect(() => run(fx, { runGh: gh.runGh })).toThrow('hash');
  });

  test('ignores a PATH-shadow gh and seals the trusted absolute executable', () => {
    const fx = fixture();
    const gh = fakeGh({
      number: 4101,
      url: 'https://github.com/example-org/example-repo/issues/4101',
      state: 'OPEN',
      assignees: [],
      labels: [],
    });
    const shadowDirectory = fs.mkdtempSync(
      path.join(os.tmpdir(), 'goal-preclaim-shadow-'),
    );
    const shadow = path.join(shadowDirectory, 'gh');
    fs.writeFileSync(shadow, '#!/bin/sh\nexit 99\n', { mode: 0o755 });
    const oldPath = process.env.PATH;
    process.env.PATH = `${shadowDirectory}:${oldPath}`;
    const observedExecutables: string[] = [];
    try {
      const result = withIsolatedControl(fx, () => preclaimIssues(fx.root, {
        manifestFile: fx.manifest,
        operationId: fx.operationId,
      }, {
        runGh(args: string[], executable: string) {
          observedExecutables.push(executable);
          return gh.runGh(args);
        },
      }));
      expect(result.status).toBe('PASS');
    } finally {
      process.env.PATH = oldPath;
    }
    expect(observedExecutables.length).toBeGreaterThan(0);
    expect(observedExecutables.every(
      (executable) => executable !== shadow && path.isAbsolute(executable),
    )).toBe(true);
  });
});
