#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const {
  compareBudgets,
  createJUnit,
  loadManifest,
  redact,
  redactString,
  validateManifest,
  verifyPartition,
} = require('./full-suite-runner-lib');

const ROOT = path.resolve(__dirname, '..');
const MANIFEST_FILE = path.join(ROOT, 'config', 'full-suite-groups.json');
const ZERO_SHA = '0'.repeat(40);

function resolveBudgetBaseSha(env, explicitSha = '') {
  const requireBudgetBase = env.FULL_SUITE_REQUIRE_BUDGET_BASE === '1';
  let baseSha = explicitSha || env.FULL_SUITE_BUDGET_BASE_SHA || '';
  if (!baseSha && env.FULL_SUITE_EVENT_NAME === 'pull_request') {
    baseSha = env.FULL_SUITE_PR_BASE_SHA || '';
  } else if (!baseSha && env.FULL_SUITE_EVENT_NAME === 'push') {
    baseSha = env.FULL_SUITE_PUSH_BEFORE_SHA || '';
  }
  if (!baseSha) {
    if (requireBudgetBase) {
      throw new Error('CI budget validation requires a non-empty PR base or push before SHA');
    }
    return { baseSha: '', requireBudgetBase };
  }
  if (!/^[0-9a-f]{40}$/i.test(baseSha)) {
    throw new Error('FULL_SUITE_BUDGET_BASE_SHA must be a full commit SHA');
  }
  if (baseSha.toLowerCase() === ZERO_SHA) {
    throw new Error('CI budget validation rejects the all-zero base SHA');
  }
  return { baseSha, requireBudgetBase };
}

function parseArgs(argv, env = process.env) {
  const options = { groups: [], validate: false, baseSha: '', requireBudgetBase: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--') continue;
    if (value === '--group') options.groups.push(argv[++index]);
    else if (value === '--validate') options.validate = true;
    else if (value === '--base-sha') options.baseSha = argv[++index];
    else throw new Error(`unknown argument: ${value}`);
  }
  Object.assign(options, resolveBudgetBaseSha(env, options.baseSha));
  return options;
}

function revision() {
  const result = spawnSync('/usr/bin/git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : 'unknown';
}

function readBaseManifest(sha, requireBudgetBase = false) {
  if (!sha) {
    if (requireBudgetBase) {
      throw new Error('CI budget validation requires a non-empty base SHA');
    }
    return null;
  }
  if (!/^[0-9a-f]{40}$/i.test(sha)) throw new Error('FULL_SUITE_BUDGET_BASE_SHA must be a full commit SHA');
  if (sha.toLowerCase() === ZERO_SHA) throw new Error('CI budget validation rejects the all-zero base SHA');
  const commit = spawnSync('/usr/bin/git', ['cat-file', '-e', `${sha}^{commit}`], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  if (commit.status !== 0) {
    throw new Error(`FULL_SUITE_BUDGET_BASE_SHA is unavailable: ${sha}`);
  }
  const manifestPath = `${sha}:config/full-suite-groups.json`;
  const exists = spawnSync('/usr/bin/git', ['cat-file', '-e', manifestPath], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  if (exists.status !== 0) return null;
  const result = spawnSync('/usr/bin/git', ['show', manifestPath], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  if (result.status !== 0) throw new Error(`failed to read base full-suite manifest at ${sha}`);
  return JSON.parse(result.stdout);
}

function safeId(value) {
  return value.replace(/[^A-Za-z0-9._-]/g, '-');
}

function makeLineSink(stream, tail, maximumLines) {
  let remainder = '';
  return {
    write(chunk) {
      remainder += chunk.toString('utf8');
      const lines = remainder.split(/\r?\n/);
      remainder = lines.pop() || '';
      for (const line of lines) {
        const safe = redactString(line);
        stream.write(`${safe}\n`);
        tail.push(safe);
        if (tail.length > maximumLines) tail.splice(0, tail.length - maximumLines);
      }
    },
    flush() {
      if (!remainder) return;
      const safe = redactString(remainder);
      stream.write(`${safe}\n`);
      tail.push(safe);
      remainder = '';
      if (tail.length > maximumLines) tail.splice(0, tail.length - maximumLines);
    },
  };
}

function writeFailureDiagnostic(artifactDirectory, fileName, diagnostic) {
  const target = path.join(artifactDirectory, fileName);
  fs.writeFileSync(target, `${JSON.stringify(redact(diagnostic), null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(target, 0o600);
  return target;
}

function writeBetweenEntryBudgetDiagnostic({
  artifactDirectory,
  group,
  previousEntry,
  nextEntry,
  revision: head,
  elapsedMs,
  outputTail = [],
}) {
  return writeFailureDiagnostic(
    artifactDirectory,
    'group-budget.failure-diagnostic.json',
    {
      kind: 'timeout',
      timeout_reason: 'group-budget-exhausted-between-entries',
      group: group.id,
      current_step: previousEntry?.id || 'group-start',
      next_step: nextEntry.id,
      revision: head,
      active_pid: null,
      elapsed_ms: elapsedMs,
      output_tail: outputTail,
    }
  );
}

function isProcessAlive(pid, processGroup = false) {
  if (!pid) return false;
  try {
    process.kill(processGroup && process.platform !== 'win32' ? -pid : pid, 0);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    if (error.code === 'EPERM') return true;
    throw error;
  }
}

function signalProcessGroup(child, signal) {
  if (!child.pid) return false;
  if (process.platform === 'win32') {
    const args = ['/PID', String(child.pid), '/T'];
    if (signal === 'SIGKILL') args.push('/F');
    const result = spawnSync('taskkill', args, { encoding: 'utf8' });
    if (result.status === 0) return true;
    const output = `${result.stdout || ''}\n${result.stderr || ''}`;
    if (/not found|no running instance|not exist/i.test(output)) return false;
    throw new Error(`taskkill failed for process tree ${child.pid}: ${output.trim()}`);
  }
  try {
    process.kill(-child.pid, signal);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

async function waitForProcessExit(pid, processGroup, timeoutMs, pollIntervalMs) {
  const deadline = Date.now() + timeoutMs;
  while (isProcessAlive(pid, processGroup)) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) return false;
    await new Promise((resolve) => setTimeout(resolve, Math.min(pollIntervalMs, remaining)));
  }
  return true;
}

async function terminateProcessGroup(child, options = {}) {
  if (!child.pid) return {
    pid: null,
    termSent: false,
    killSent: false,
    exited: true,
  };
  const termGraceMs = options.termGraceMs ?? 5000;
  const killGraceMs = options.killGraceMs ?? 5000;
  const pollIntervalMs = options.pollIntervalMs ?? 25;
  const processGroup = process.platform !== 'win32';
  let termSent = false;
  let killSent = false;
  try {
    termSent = signalProcessGroup(child, 'SIGTERM');
  } catch (error) {
    error.terminationState = {
      pid: child.pid,
      termSent,
      killSent,
      exited: false,
    };
    throw error;
  }
  if (await waitForProcessExit(child.pid, processGroup, termGraceMs, pollIntervalMs)) {
    return { pid: child.pid, termSent, killSent: false, exited: true };
  }
  try {
    killSent = signalProcessGroup(child, 'SIGKILL');
  } catch (error) {
    error.terminationState = {
      pid: child.pid,
      termSent,
      killSent,
      exited: false,
    };
    throw error;
  }
  const exited = await waitForProcessExit(
    child.pid,
    processGroup,
    killGraceMs,
    pollIntervalMs
  );
  if (!exited) {
    const error = new Error(`process group ${child.pid} survived SIGKILL escalation`);
    error.terminationState = { pid: child.pid, termSent, killSent, exited };
    throw error;
  }
  return { pid: child.pid, termSent, killSent, exited };
}

async function settleTimedOutCleanup({
  terminationPromise,
  artifactDirectory,
  group,
  entry,
  revision: head,
  activePid,
  elapsedMs,
  outputTail,
}) {
  try {
    const termination = await terminationPromise;
    if (!termination?.exited) {
      const error = new Error(`process group ${activePid} cleanup did not confirm exit`);
      error.terminationState = termination;
      throw error;
    }
    return { status: 'timeout', termination, cleanupError: null };
  } catch (error) {
    const termination = error.terminationState || {
      pid: activePid,
      termSent: null,
      killSent: null,
      exited: false,
    };
    writeFailureDiagnostic(
      artifactDirectory,
      `${safeId(entry.id)}.failure-diagnostic.json`,
      {
        kind: 'cleanup-failure',
        timeout_reason: 'entry-timeout-process-group-cleanup-failed',
        group: group.id,
        current_step: entry.id,
        revision: head,
        active_pid: activePid,
        elapsed_ms: elapsedMs,
        cleanup_error: error.message,
        termination,
        output_tail: [...outputTail, error.message],
      }
    );
    return {
      status: 'fatal',
      termination,
      cleanupError: redactString(error.message),
    };
  }
}

function runEntry(group, entry, policy, artifactDirectory, remainingMs, head, runtime = {}) {
  return new Promise((resolve) => {
    const resultFile = path.join(artifactDirectory, `${safeId(entry.id)}.jest.json`);
    const jestFile = path.join(ROOT, 'node_modules', 'jest', 'bin', 'jest.js');
    const args = [
      jestFile,
      '--runInBand',
      '--runTestsByPath',
      entry.file,
      '--json',
      '--outputFile',
      resultFile,
      '--testLocationInResults',
    ];
    if (entry.testNamePattern) args.push('--testNamePattern', entry.testNamePattern);
    const startedAt = Date.now();
    const tail = [];
    const child = spawn(process.execPath, args, {
      cwd: ROOT,
      detached: process.platform !== 'win32',
      env: {
        ...process.env,
        TZ: 'Asia/Shanghai',
        NODE_OPTIONS: `${process.env.NODE_OPTIONS || ''} --experimental-vm-modules`.trim(),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = makeLineSink(process.stdout, tail, policy.diagnosticTailLines);
    const stderr = makeLineSink(process.stderr, tail, policy.diagnosticTailLines);
    child.stdout.on('data', (chunk) => stdout.write(chunk));
    child.stderr.on('data', (chunk) => stderr.write(chunk));
    const timeoutMs = Math.min(policy.entryTimeoutSeconds * 1000, remainingMs);
    let timedOut = false;
    let cleanupPromise = null;
    let finalized = false;
    const heartbeat = setInterval(() => {
      process.stdout.write(`[full-suite] HEARTBEAT group=${group.id} entry=${entry.id} pid=${child.pid || 'unavailable'} elapsed_ms=${Date.now() - startedAt} revision=${head}\n`);
    }, policy.heartbeatSeconds * 1000);
    const finalize = (code, signal, cleanup = null, detachChild = false) => {
      if (finalized) return;
      finalized = true;
      clearInterval(heartbeat);
      clearTimeout(timeout);
      stdout.flush();
      stderr.flush();
      if (detachChild) {
        child.stdout?.destroy();
        child.stderr?.destroy();
        child.unref();
      }
      let jestResult = null;
      try {
        jestResult = JSON.parse(fs.readFileSync(resultFile, 'utf8'));
      } catch {}
      try {
        fs.unlinkSync(resultFile);
      } catch {}
      const assertions = (jestResult?.testResults || []).flatMap((suite) => suite.assertionResults || []);
      const durationMs = Date.now() - startedAt;
      const status = cleanup?.status || (timedOut ? 'timeout' : code === 0 ? 'pass' : 'fail');
      if (status !== 'pass' && !timedOut) {
        writeFailureDiagnostic(
          artifactDirectory,
          `${safeId(entry.id)}.failure-diagnostic.json`,
          {
            kind: 'failure',
            group: group.id,
            current_step: entry.id,
            revision: head,
            active_pid: child.pid || null,
            exit_code: code,
            signal,
            elapsed_ms: durationMs,
            output_tail: tail,
          }
        );
      }
      process.stdout.write(
        `[full-suite] ${status.toUpperCase()} group=${group.id} `
        + `entry=${entry.id} duration_ms=${durationMs}\n`
      );
      resolve({
        entry,
        assertions,
        durationMs,
        status,
        code,
        signal,
        cleanupError: cleanup?.cleanupError || null,
        termination: cleanup?.termination || null,
      });
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      const diagnostic = redact({
        kind: 'timeout',
        group: group.id,
        current_step: entry.id,
        revision: head,
        active_pid: child.pid || null,
        elapsed_ms: Date.now() - startedAt,
        output_tail: tail,
      });
      writeFailureDiagnostic(
        artifactDirectory,
        `${safeId(entry.id)}.failure-diagnostic.json`,
        diagnostic
      );
      process.stderr.write(`[full-suite] TIMEOUT group=${group.id} current_step=${entry.id} active_pid=${child.pid || 'unavailable'} revision=${head}\n`);
      const terminationPromise = (runtime.terminateProcessGroup || terminateProcessGroup)(child);
      cleanupPromise = settleTimedOutCleanup({
        terminationPromise,
        artifactDirectory,
        group,
        entry,
        revision: head,
        activePid: child.pid || null,
        elapsedMs: Date.now() - startedAt,
        outputTail: tail,
      });
      cleanupPromise.then((cleanup) => finalize(null, null, cleanup, true));
    }, timeoutMs);
    child.on('error', (error) => {
      tail.push(redactString(error.message));
    });
    child.on('close', async (code, signal) => {
      const cleanup = cleanupPromise ? await cleanupPromise : null;
      finalize(code, signal, cleanup);
    });
  });
}

function slowestItems(results, count) {
  return results.flatMap((result) => result.assertions
    .filter((assertion) => !['pending', 'todo', 'disabled'].includes(assertion.status))
    .map((assertion) => ({
      entry: result.entry.id,
      test: assertion.fullName || assertion.title,
      durationMs: Number(assertion.duration || 0),
      status: assertion.status,
    })))
    .sort((left, right) => right.durationMs - left.durationMs)
    .slice(0, count);
}

async function runGroup(group, policy, artifactRoot, head, runtime = {}) {
  const startedAt = Date.now();
  const artifactDirectory = path.join(artifactRoot, group.id);
  fs.mkdirSync(artifactDirectory, { recursive: true, mode: 0o700 });
  const results = [];
  process.stdout.write(
    `[full-suite] START group=${group.id} label=${redactString(JSON.stringify(group.label))} `
    + `revision=${head} budget_seconds=${group.budgetSeconds}\n`
  );
  for (const entry of group.entries) {
    const elapsed = Date.now() - startedAt;
    const remainingMs = group.budgetSeconds * 1000 - elapsed;
    if (remainingMs <= 0) {
      const previousEntry = results.at(-1)?.entry;
      writeBetweenEntryBudgetDiagnostic({
        artifactDirectory,
        group,
        previousEntry,
        nextEntry: entry,
        revision: head,
        elapsedMs: elapsed,
      });
      process.stderr.write(
        `[full-suite] TIMEOUT group=${group.id} `
        + `current_step=${previousEntry?.id || 'group-start'} next_step=${entry.id} `
        + `active_pid=none revision=${head}\n`
      );
      results.push({ entry, assertions: [], durationMs: 0, status: 'timeout', code: null, signal: null });
      break;
    }
    process.stdout.write(
      `[full-suite] START group=${group.id} entry=${entry.id} `
      + `label=${redactString(JSON.stringify(entry.label))} file=${entry.file}\n`
    );
    const result = await (runtime.runEntry || runEntry)(
      group,
      entry,
      policy,
      artifactDirectory,
      remainingMs,
      head,
      runtime
    );
    results.push(result);
    if (result.status === 'timeout' || result.status === 'fatal') break;
  }
  const durationMs = Date.now() - startedAt;
  const entryAssertions = new Map(results.map((result) => [result.entry.id, result.assertions]));
  const partitionErrors = verifyPartition(group.entries, entryAssertions);
  const assertions = results.flatMap((result) => result.assertions);
  const timings = {
    schemaVersion: 1,
    group: group.id,
    label: group.label,
    revision: head,
    durationMs,
    budgetSeconds: group.budgetSeconds,
    status: results.every((result) => result.status === 'pass') && partitionErrors.length === 0 ? 'pass' : 'fail',
    entries: results.map((result) => ({
      id: result.entry.id,
      label: result.entry.label,
      file: result.entry.file,
      durationMs: result.durationMs,
      status: result.status,
      executedTests: result.assertions.filter((assertion) => !['pending', 'todo', 'disabled'].includes(assertion.status)).length,
    })),
    slowest20: slowestItems(results, policy.slowestItems),
    partitionErrors,
  };
  fs.writeFileSync(path.join(artifactDirectory, 'timings.json'), `${JSON.stringify(redact(timings), null, 2)}\n`);
  fs.writeFileSync(path.join(artifactDirectory, 'junit.xml'), createJUnit(group, assertions, durationMs));
  if (partitionErrors.length > 0) {
    const diagnostic = redact({
      kind: 'partition-coverage',
      group: group.id,
      revision: head,
      current_step: 'partition-verification',
      active_pid: null,
      errors: partitionErrors,
    });
    writeFailureDiagnostic(
      artifactDirectory,
      'partition.failure-diagnostic.json',
      diagnostic
    );
    for (const error of partitionErrors) process.stderr.write(`[full-suite] PARTITION_FAIL ${redactString(error)}\n`);
  }
  process.stdout.write(`[full-suite] ${timings.status.toUpperCase()} group=${group.id} duration_ms=${durationMs}\n`);
  process.stdout.write(
    `[full-suite] SLOWEST_20 group=${group.id} ${JSON.stringify(redact(timings.slowest20))}\n`
  );
  return timings.status === 'pass';
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const manifest = loadManifest(MANIFEST_FILE);
  const errors = validateManifest(manifest, ROOT);
  const base = readBaseManifest(options.baseSha, options.requireBudgetBase);
  if (base) errors.push(...compareBudgets(manifest, base));
  else if (options.requireBudgetBase) {
    process.stdout.write(
      `[full-suite] BUDGET_BASE_INITIAL revision=${options.baseSha} `
      + 'policy=initial-checked-in-ceiling\n'
    );
  }
  if (errors.length > 0) {
    for (const error of errors) process.stderr.write(`[full-suite] CONFIG_FAIL ${error}\n`);
    process.exitCode = 2;
    return;
  }
  if (options.validate) {
    process.stdout.write(`[full-suite] CONFIG_PASS groups=${manifest.groups.length} test_files=${new Set(manifest.groups.flatMap((group) => group.entries.map((entry) => entry.file))).size}\n`);
    return;
  }
  const selected = options.groups.length === 0
    ? manifest.groups
    : options.groups.map((id) => {
      const group = manifest.groups.find((candidate) => candidate.id === id);
      if (!group) throw new Error(`unknown full-suite group: ${id}`);
      return group;
    });
  const head = revision();
  const artifactRoot = path.resolve(
    process.env.FULL_SUITE_ARTIFACT_DIR
      || path.join(os.tmpdir(), 'goal-control-full-suite', head)
  );
  fs.mkdirSync(artifactRoot, { recursive: true, mode: 0o700 });
  let passed = true;
  for (const group of selected) {
    if (!await runGroup(group, manifest.policy, artifactRoot, head)) passed = false;
  }
  if (!passed) process.exitCode = 1;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`[full-suite] RUNNER_FAIL ${redactString(error.stack || error.message)}\n`);
    process.exitCode = 2;
  });
}

module.exports = {
  isProcessAlive,
  makeLineSink,
  parseArgs,
  readBaseManifest,
  resolveBudgetBaseSha,
  runGroup,
  settleTimedOutCleanup,
  terminateProcessGroup,
  writeBetweenEntryBudgetDiagnostic,
  writeFailureDiagnostic,
};
