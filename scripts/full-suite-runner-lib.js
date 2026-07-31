'use strict';

const fs = require('node:fs');
const path = require('node:path');

const REQUIRED_GROUPS = [
  'core-fsm',
  'git-worktree',
  'recovery-rotation',
  'source-handoff',
  'github-resource',
  'usability-security',
];
const MINIMUM_CI_SETUP_POST_MARGIN_SECONDS = 600;

const SECRET_KEY_RE = /(authorization|bearer|capabilit(?:y|ies)|cookie|password|secret|token)/i;
const SECRET_VALUE_RES = [
  /(\bAuthorization["']?\s*[:=]\s*["']?)[^"'\r\n}]+/gi,
  /(\b(?:Set-Cookie|Cookie)["']?\s*[:=]\s*["']?)[^"'\r\n}]+/gi,
  /(\b)(?:gh[opusr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})\b/g,
  /(\bBearer\s+)\S+/gi,
  /((?:--|["']?)(?:authorization|capabilit(?:y|ies)(?:[_-](?:file|path|locator))?|cookie|password|secret|token)["']?(?:\s+|["']?\s*[:=]\s*["']?))[^"',\s}]+/gi,
];

function redactString(value) {
  let output = String(value);
  for (const expression of SECRET_VALUE_RES) {
    output = output.replace(expression, '$1<redacted>');
  }
  return output;
}

function redact(value, key = '') {
  if (SECRET_KEY_RE.test(key)) return '<redacted>';
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map((item) => redact(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [childKey, redact(childValue, childKey)])
    );
  }
  return value;
}

function loadManifest(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function listTestFiles(root) {
  return fs.readdirSync(path.join(root, '__tests__'))
    .filter((name) => name.endsWith('.test.ts'))
    .map((name) => `__tests__/${name}`)
    .sort();
}

function fullCiJobBlock(workflow) {
  const lines = [];
  let inFullJob = false;
  for (const line of workflow.split(/\r?\n/)) {
    if (/^  full:\s*(?:#.*)?$/.test(line)) {
      inFullJob = true;
      lines.push(line);
      continue;
    }
    if (inFullJob && /^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(line)) break;
    if (inFullJob) lines.push(line);
  }
  return lines.join('\n');
}

function fullCiJobTimeoutMinutes(workflow) {
  let inFullJob = false;
  for (const line of workflow.split(/\r?\n/)) {
    if (/^  full:\s*(?:#.*)?$/.test(line)) {
      inFullJob = true;
      continue;
    }
    if (inFullJob && /^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(line)) break;
    if (!inFullJob) continue;
    const match = line.match(/^    timeout-minutes:\s*(\d+)\s*(?:#.*)?$/);
    if (match) return Number(match[1]);
  }
  return null;
}

function fullCiMatrixGroups(workflow) {
  let inFullJob = false;
  let inMatrix = false;
  let inGroup = false;
  const groups = [];
  for (const line of workflow.split(/\r?\n/)) {
    if (/^  full:\s*(?:#.*)?$/.test(line)) {
      inFullJob = true;
      continue;
    }
    if (inFullJob && /^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(line)) break;
    if (!inFullJob) continue;
    if (/^      matrix:\s*(?:#.*)?$/.test(line)) {
      inMatrix = true;
      inGroup = false;
      continue;
    }
    if (inMatrix && /^      [A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(line)) {
      inMatrix = false;
      inGroup = false;
      continue;
    }
    if (inMatrix && /^        group:\s*(?:#.*)?$/.test(line)) {
      inGroup = true;
      continue;
    }
    if (inGroup && /^        [A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(line)) {
      inGroup = false;
      continue;
    }
    const item = inGroup && line.match(/^          -\s+([A-Za-z0-9._-]+)\s*(?:#.*)?$/);
    if (item) groups.push(item[1]);
  }
  return groups;
}

function validateCiGroupMatrix(manifestGroups, workflow) {
  const errors = [];
  const expected = manifestGroups.map((group) => group.id);
  const actual = fullCiMatrixGroups(workflow);
  if (actual.length === 0) {
    return ['full CI strategy.matrix.group must contain the checked-in manifest groups'];
  }
  const seen = new Set();
  for (const group of actual) {
    if (seen.has(group)) errors.push(`duplicate full CI matrix group: ${group}`);
    seen.add(group);
  }
  const actualSet = new Set(actual);
  const expectedSet = new Set(expected);
  for (const group of expectedSet) {
    if (!actualSet.has(group)) errors.push(`full CI matrix missing manifest group: ${group}`);
  }
  for (const group of actualSet) {
    if (!expectedSet.has(group)) errors.push(`full CI matrix has unexpected group: ${group}`);
  }
  return errors;
}

function validateCiBudgetBaseWiring(workflow) {
  const fullJob = fullCiJobBlock(workflow);
  const lines = fullJob.split(/\r?\n/);
  const expectedStepName = 'Validate checked-in groups and non-increasing budget';
  const steps = [];
  for (let index = 0; index < lines.length; index += 1) {
    const name = lines[index].match(/^      - name:\s*(.+?)\s*$/);
    if (!name) continue;
    const rawName = name[1];
    const normalizedName = (
      (rawName.startsWith('"') && rawName.endsWith('"'))
      || (rawName.startsWith("'") && rawName.endsWith("'"))
    ) ? rawName.slice(1, -1) : rawName;
    let end = index + 1;
    while (end < lines.length && !/^      -\s+/.test(lines[end])) end += 1;
    if (normalizedName === expectedStepName) steps.push(lines.slice(index, end));
  }
  if (steps.length !== 1) {
    return [
      `full CI requires exactly one active "${expectedStepName}" step; observed ${steps.length}`,
    ];
  }
  const step = steps[0];
  const envIndexes = step
    .map((line, index) => (/^        env:\s*$/.test(line) ? index : -1))
    .filter((index) => index >= 0);
  if (envIndexes.length !== 1) {
    return [
      `"${expectedStepName}" requires exactly one active env mapping; observed ${envIndexes.length}`,
    ];
  }
  const values = new Map();
  for (let index = envIndexes[0] + 1; index < step.length; index += 1) {
    const line = step[index];
    if (/^\s*(?:#.*)?$/.test(line)) continue;
    if (/^        \S/.test(line)) break;
    const item = line.match(/^          ([A-Z0-9_]+):\s*(.*?)\s*$/);
    if (!item) continue;
    const entries = values.get(item[1]) || [];
    entries.push(item[2]);
    values.set(item[1], entries);
  }
  const expected = new Map([
    ['FULL_SUITE_REQUIRE_BUDGET_BASE', '1'],
    ['FULL_SUITE_EVENT_NAME', '${{ github.event_name }}'],
    ['FULL_SUITE_PR_BASE_SHA', '${{ github.event.pull_request.base.sha }}'],
    ['FULL_SUITE_PUSH_BEFORE_SHA', '${{ github.event.before }}'],
  ]);
  const errors = [];
  for (const [name, expectedValue] of expected) {
    const entries = values.get(name) || [];
    if (entries.length === 0) {
      errors.push(`"${expectedStepName}" env is missing ${name}`);
      continue;
    }
    if (entries.length !== 1) {
      errors.push(`"${expectedStepName}" env has duplicate ${name}`);
      continue;
    }
    const rawValue = entries[0];
    const normalizedValue = (
      (rawValue.startsWith('"') && rawValue.endsWith('"'))
      || (rawValue.startsWith("'") && rawValue.endsWith("'"))
    ) ? rawValue.slice(1, -1) : rawValue;
    if (normalizedValue !== expectedValue) {
      errors.push(
        `"${expectedStepName}" env ${name} must equal ${expectedValue}; `
        + `observed ${normalizedValue || '<empty>'}`
      );
    }
  }
  const conditions = step.filter((line) => /^        if:\s*\S/.test(line));
  if (conditions.length > 0) {
    errors.push(`"${expectedStepName}" must not have an if condition`);
  }
  const continueOnError = step.filter(
    (line) => /^        continue-on-error:\s*\S/.test(line)
  );
  if (continueOnError.length > 0) {
    errors.push(`"${expectedStepName}" must not have continue-on-error`);
  }
  const runs = step
    .map((line) => line.match(/^        run:\s*(.*?)\s*$/))
    .filter(Boolean)
    .map((match) => match[1]);
  if (runs.length !== 1) {
    errors.push(`"${expectedStepName}" requires exactly one active run command; observed ${runs.length}`);
  } else if (runs[0] !== 'pnpm verify:full-suite-groups') {
    errors.push(
      `"${expectedStepName}" run must equal pnpm verify:full-suite-groups; `
      + `observed ${runs[0] || '<empty>'}`
    );
  }
  return errors;
}

function validateCiTimeoutPolicy(policy, workflow) {
  const errors = [];
  if (!Number.isInteger(policy.ciSetupPostMarginSeconds)
      || policy.ciSetupPostMarginSeconds < MINIMUM_CI_SETUP_POST_MARGIN_SECONDS) {
    errors.push(
      `policy.ciSetupPostMarginSeconds must be at least `
      + `${MINIMUM_CI_SETUP_POST_MARGIN_SECONDS} seconds`
    );
    return errors;
  }
  const timeoutMinutes = fullCiJobTimeoutMinutes(workflow);
  if (timeoutMinutes === null) {
    errors.push('full CI job requires an explicit integer timeout-minutes');
    return errors;
  }
  if (Number.isInteger(policy.maximumShardSeconds) && policy.maximumShardSeconds > 0) {
    const minimumMinutes = Math.ceil(
      (policy.maximumShardSeconds + policy.ciSetupPostMarginSeconds) / 60
    );
    if (timeoutMinutes < minimumMinutes) {
      errors.push(
        `full CI job timeout-minutes must be at least ${minimumMinutes} `
        + `(${policy.maximumShardSeconds}s runner + `
        + `${policy.ciSetupPostMarginSeconds}s setup/post margin); observed ${timeoutMinutes}`
      );
    }
  }
  return errors;
}

function validateManifest(manifest, root) {
  const errors = [];
  if (manifest.version !== 1) errors.push('manifest version must be 1');
  const policy = manifest.policy || {};
  if (!Number.isInteger(policy.heartbeatSeconds) || policy.heartbeatSeconds < 1 || policy.heartbeatSeconds > 15) {
    errors.push('policy.heartbeatSeconds must be an integer between 1 and 15');
  }
  if (!Number.isInteger(policy.maximumShardSeconds) || policy.maximumShardSeconds < 1
      || policy.maximumShardSeconds > 1200) {
    errors.push('policy.maximumShardSeconds must be positive and at most the initial 20 minute ceiling');
  }
  if (!Number.isInteger(policy.entryTimeoutSeconds) || policy.entryTimeoutSeconds < 1
      || policy.entryTimeoutSeconds >= policy.maximumShardSeconds) {
    errors.push('policy.entryTimeoutSeconds must be positive and below the shard ceiling');
  }
  if (policy.slowestItems !== 20) errors.push('policy.slowestItems must be 20');
  if (!Array.isArray(manifest.groups)) errors.push('groups must be an array');
  const workflowFile = path.join(root, '.github', 'workflows', 'ci.yml');
  let workflow = null;
  if (!fs.existsSync(workflowFile)) {
    errors.push('checked-in CI workflow is required for timeout validation');
  } else {
    workflow = fs.readFileSync(workflowFile, 'utf8');
    errors.push(...validateCiTimeoutPolicy(policy, workflow));
    errors.push(...validateCiBudgetBaseWiring(workflow));
  }

  const groupIds = new Set();
  const entryIds = new Set();
  const fileGroups = new Map();
  for (const group of manifest.groups || []) {
    if (!group || typeof group.id !== 'string' || !group.id) {
      errors.push('every group requires an id');
      continue;
    }
    if (groupIds.has(group.id)) errors.push(`duplicate group id: ${group.id}`);
    groupIds.add(group.id);
    if (!Number.isInteger(group.budgetSeconds) || group.budgetSeconds < 1
        || group.budgetSeconds > policy.maximumShardSeconds) {
      errors.push(`${group.id}: budgetSeconds exceeds the 20 minute ceiling`);
    }
    if (!Array.isArray(group.entries) || group.entries.length === 0) {
      errors.push(`${group.id}: entries must be non-empty`);
      continue;
    }
    for (const entry of group.entries) {
      if (!entry || typeof entry.id !== 'string' || !entry.id) {
        errors.push(`${group.id}: every entry requires an id`);
        continue;
      }
      if (entryIds.has(entry.id)) errors.push(`duplicate entry id: ${entry.id}`);
      entryIds.add(entry.id);
      if (typeof entry.label !== 'string' || !entry.label) errors.push(`${entry.id}: label is required`);
      if (typeof entry.file !== 'string' || !entry.file.startsWith('__tests__/')
          || !entry.file.endsWith('.test.ts') || path.normalize(entry.file) !== entry.file) {
        errors.push(`${entry.id}: file must be a normalized __tests__/*.test.ts path`);
      } else if (!fs.existsSync(path.join(root, entry.file))) {
        errors.push(`${entry.id}: missing test file ${entry.file}`);
      }
      if (entry.testNamePattern !== undefined) {
        if (typeof entry.testNamePattern !== 'string' || !entry.testNamePattern) {
          errors.push(`${entry.id}: testNamePattern must be a non-empty string`);
        } else {
          try {
            new RegExp(entry.testNamePattern);
          } catch (error) {
            errors.push(`${entry.id}: invalid testNamePattern: ${error.message}`);
          }
        }
      }
      const owners = fileGroups.get(entry.file) || new Set();
      owners.add(group.id);
      fileGroups.set(entry.file, owners);
    }
  }
  for (const groupId of groupIds) {
    if (!REQUIRED_GROUPS.includes(groupId)) {
      errors.push(`unexpected stable group not present in the CI matrix: ${groupId}`);
    }
  }
  for (const required of REQUIRED_GROUPS) {
    if (!groupIds.has(required)) errors.push(`missing required stable group: ${required}`);
  }
  if (workflow) errors.push(...validateCiGroupMatrix(manifest.groups || [], workflow));
  const trackedTests = listTestFiles(root);
  for (const file of trackedTests) {
    const owners = fileGroups.get(file);
    if (!owners) errors.push(`unassigned test file: ${file}`);
    else if (owners.size !== 1) errors.push(`${file} is assigned to multiple groups: ${[...owners].join(', ')}`);
  }
  for (const file of fileGroups.keys()) {
    if (!trackedTests.includes(file)) errors.push(`manifest references non-test inventory: ${file}`);
  }
  return errors;
}

function compareBudgets(current, base) {
  const errors = [];
  if (current.policy.maximumShardSeconds > base.policy.maximumShardSeconds) {
    errors.push('policy.maximumShardSeconds may only decrease');
  }
  const baseGroups = new Map((base.groups || []).map((group) => [group.id, group]));
  for (const group of current.groups || []) {
    const previous = baseGroups.get(group.id);
    if (previous && group.budgetSeconds > previous.budgetSeconds) {
      errors.push(`${group.id}: budgetSeconds may only decrease (${previous.budgetSeconds} -> ${group.budgetSeconds})`);
    }
  }
  return errors;
}

function xmlEscape(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function createJUnit(group, assertions, durationMs) {
  const executed = assertions.filter((item) => !['pending', 'todo', 'disabled'].includes(item.status));
  const failures = executed.filter((item) => item.status === 'failed').length;
  const cases = executed.map((item) => {
    const duration = Number(item.duration || 0) / 1000;
    const failure = item.status === 'failed'
      ? `<failure message="test failed">${xmlEscape(redactString((item.failureMessages || []).join('\n')))}</failure>`
      : '';
    return `    <testcase classname="${xmlEscape(redactString(item.ancestorTitles?.join(' › ') || group.label))}" name="${xmlEscape(redactString(item.title || item.fullName))}" time="${duration.toFixed(3)}">${failure}</testcase>`;
  }).join('\n');
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites tests="${executed.length}" failures="${failures}" time="${(durationMs / 1000).toFixed(3)}">`,
    `  <testsuite name="${xmlEscape(redactString(group.label))}" tests="${executed.length}" failures="${failures}" time="${(durationMs / 1000).toFixed(3)}">`,
    cases,
    '  </testsuite>',
    '</testsuites>',
    '',
  ].join('\n');
}

function verifyPartition(entries, entryAssertions) {
  const byFile = new Map();
  for (const entry of entries) {
    const assertions = entryAssertions.get(entry.id) || [];
    const record = byFile.get(entry.file) || {
      discovered: new Set(),
      executed: new Map(),
      entries: [],
      emptyEntries: [],
    };
    record.entries.push(entry.id);
    let entryExecutions = 0;
    for (const assertion of assertions) {
      const fullName = assertion.fullName || assertion.title;
      if (!fullName) continue;
      record.discovered.add(fullName);
      if (!['pending', 'todo', 'disabled'].includes(assertion.status)) {
        entryExecutions += 1;
        record.executed.set(fullName, (record.executed.get(fullName) || 0) + 1);
      }
    }
    if (entryExecutions === 0) record.emptyEntries.push(entry.id);
    byFile.set(entry.file, record);
  }
  const errors = [];
  for (const [file, record] of byFile) {
    if (record.discovered.size === 0) errors.push(`${file}: Jest reported no tests`);
    for (const entry of record.emptyEntries) {
      errors.push(`${file}: semantic entry ${entry} executed no tests`);
    }
    for (const fullName of record.discovered) {
      const count = record.executed.get(fullName) || 0;
      if (count !== 1) errors.push(`${file}: expected exactly one execution for "${fullName}", observed ${count}`);
    }
  }
  return errors;
}

module.exports = {
  REQUIRED_GROUPS,
  compareBudgets,
  createJUnit,
  fullCiMatrixGroups,
  fullCiJobTimeoutMinutes,
  listTestFiles,
  loadManifest,
  redact,
  redactString,
  validateCiBudgetBaseWiring,
  validateCiGroupMatrix,
  validateCiTimeoutPolicy,
  validateManifest,
  verifyPartition,
  xmlEscape,
};
