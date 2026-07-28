#!/usr/bin/env node
'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const FIXTURE = path.join(__dirname, 'fixture-repo');
const GOALCTL = path.join(ROOT, 'scripts', 'goalctl.js');
const GOAL_ID = 'lab-three-task';

function run(executable, args, options = {}) {
  return execFileSync(executable, args, {
    cwd: options.cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: options.env || process.env,
  }).trim();
}

function git(cwd, ...args) {
  return run('git', args, { cwd });
}

function goalctl(repository, controlDir, ...args) {
  const output = run(process.execPath, [
    GOALCTL,
    ...args,
    '--repository-worktree',
    repository,
  ], {
    cwd: ROOT,
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      TMPDIR: process.env.TMPDIR,
      LANG: process.env.LANG || 'C.UTF-8',
      TZ: 'UTC',
      GOAL_CONTROL_DIR: controlDir,
      GOAL_CONTROL_TEST_MODE: '1',
    },
  });
  return output === '' ? null : JSON.parse(output);
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function main() {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'goal-control-lab-'));
  const repository = path.join(sandbox, 'fixture-repo');
  const controlDir = path.join(sandbox, 'control-store');
  const keep = process.env.GOAL_CONTROL_KEEP_LAB === '1';

  try {
    fs.cpSync(FIXTURE, repository, { recursive: true });
    fs.mkdirSync(controlDir, { recursive: true, mode: 0o700 });
    git(repository, 'init', '-q', '-b', 'main');
    git(repository, 'config', 'user.email', 'goal-control-lab@example.invalid');
    git(repository, 'config', 'user.name', 'Goal Control Lab');
    git(repository, 'add', '.');
    git(repository, 'commit', '-qm', 'fixture base');
    git(
      repository,
      'remote',
      'add',
      'origin',
      'https://github.com/example/fixture-repo.git',
    );
    const baseHead = git(repository, 'rev-parse', 'HEAD');

    writeJson(path.join(repository, 'goal-inputs', 'spec.json'), {
      schema_version: 1,
      goal_id: GOAL_ID,
      title: 'Anonymous three-task continuous delivery lab',
      mode: 'shadow',
      repository: {
        name_with_owner: 'example/fixture-repo',
        base_branch: 'main',
      },
      base_head: baseHead,
      tasks: [
        {
          id: 'TASK-A',
          title: 'Write deterministic value',
          issue: 4101,
          dependencies: [],
          integration_order: 1,
          parallel_group: 'batch-1',
          risk_class: 'STANDARD',
          packet_source: 'goal-inputs/TASK-A.md',
          packet_revision: 1,
          expected_write_set: ['workspace/value.json'],
          conflict_domains: ['workspace-value'],
          resource_requirements: [],
        },
        {
          id: 'TASK-B',
          title: 'Hash deterministic value',
          issue: 4102,
          dependencies: ['TASK-A'],
          integration_order: 2,
          parallel_group: 'batch-2',
          risk_class: 'STANDARD',
          packet_source: 'goal-inputs/TASK-B.md',
          packet_revision: 1,
          expected_write_set: ['workspace/value.sha256'],
          conflict_domains: ['workspace-checksum'],
          resource_requirements: [],
        },
        {
          id: 'TASK-C',
          title: 'Verify checksum',
          issue: 4103,
          dependencies: ['TASK-B'],
          integration_order: 3,
          parallel_group: 'batch-3',
          risk_class: 'STANDARD',
          packet_source: 'goal-inputs/TASK-C.md',
          packet_revision: 1,
          expected_write_set: ['workspace/verification.json'],
          conflict_domains: ['workspace-verification'],
          resource_requirements: [],
        },
      ],
    });

    const outputDir = `docs/planning/goals/${GOAL_ID}`;
    const scaffold = goalctl(
      repository,
      controlDir,
      'scaffold',
      '--spec',
      'goal-inputs/spec.json',
      '--output-dir',
      outputDir,
      '--json',
    );
    if (!scaffold || scaffold.goal_id !== GOAL_ID) {
      throw new Error('scaffold did not return the expected goal');
    }

    git(repository, 'add', 'goal-inputs', outputDir);
    git(repository, 'commit', '-qm', 'add lab goal');

    const initialized = goalctl(
      repository,
      controlDir,
      'init',
      '--manifest',
      path.join(repository, outputDir, 'manifest.json'),
      '--json',
    );
    if (!initialized || initialized.goal_id !== GOAL_ID) {
      throw new Error('init did not return the expected goal');
    }

    const next = goalctl(
      repository,
      controlDir,
      'next',
      '--goal',
      GOAL_ID,
      '--json',
    );
    const eligible = next && Array.isArray(next.eligible)
      ? next.eligible.map((task) => task.task_id)
      : [];
    if (JSON.stringify(eligible) !== JSON.stringify(['TASK-A'])) {
      throw new Error(
        `dependency gate projected unexpected runnable tasks: ${JSON.stringify(next)}`,
      );
    }

    const doctor = goalctl(
      repository,
      controlDir,
      'doctor',
      '--goal',
      GOAL_ID,
      '--json',
    );
    if (!doctor || JSON.stringify(doctor).includes('"severity":"error"')) {
      throw new Error(`doctor reported an error: ${JSON.stringify(doctor)}`);
    }

    process.stdout.write(`${JSON.stringify({
      scenario: GOAL_ID,
      result: 'PASS',
      base_head: baseHead,
      tasks: ['TASK-A', 'TASK-B', 'TASK-C'],
      runnable: ['TASK-A'],
      sandbox: keep ? sandbox : null,
    }, null, 2)}\n`);
  } finally {
    if (!keep) fs.rmSync(sandbox, { recursive: true, force: true });
  }
}

main();
