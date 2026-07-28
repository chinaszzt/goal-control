'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const {
  authorizeGoalSession,
  authorizeSession,
  hashesEqual,
  readCapabilityFile,
} = require('./auth');
const { ControlError, assertControl } = require('./errors');
const {
  adoptSourceImportIntentPublication,
  atomicCreate,
  atomicWrite,
  atomicWriteJson,
  canonicalTransactionKey,
  ensureDir,
  isOddTransactionRetry,
  withLock,
  withStableRead,
} = require('./store');
const {
  assertFullSha,
  canonicalJson,
  controlRoot,
  hashFile,
  hashObject,
  normalizeHash,
  nowIso,
  randomId,
  readOnlyGitEnvironment,
  readJson,
  repoRoot,
  safeId,
  sha256,
  trustedGitExecutable,
  trustedTemporaryRoot,
} = require('./util');
const { validateLaunchManifest } = require('./validation');
const {
  describeLooseRefReflog,
  executeLooseRefTransaction,
} = require('./git-loose-ref-transaction');

const MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024;
const MAX_UNTRACKED_ENTRIES = 10_000;
const MAX_RELATIVE_PATH_BYTES = 1_000;
const MAX_SYMLINK_TARGET_BYTES = 4_096;
const MAX_ROLLOUT_BYTES = 128 * 1024 * 1024;
const GIT_MAX_BUFFER = MAX_SNAPSHOT_BYTES + (4 * 1024 * 1024);
const LEGACY_SNAPSHOT_SCHEMA_VERSION = 1;
const LEGACY_RECEIPT_SCHEMA_VERSION = 1;
const EXACT_TREE_SNAPSHOT_SCHEMA_VERSION = 2;
const EXACT_TREE_RECEIPT_SCHEMA_VERSION = 2;
const SNAPSHOT_SCHEMA_VERSION = 3;
const RECEIPT_SCHEMA_VERSION = 3;
const MAX_LEGACY_RECOVERY_HANDOFF_BINDINGS = 4096;
const PARTIAL_SNAPSHOT_BINDING_SCHEMA_VERSION = 1;
const PARTIAL_SNAPSHOT_BINDING_FILE = 'operation-binding.json';
const RECOVERY_CHECKPOINT_AUTHOR_NAME = 'goalctl recovery checkpoint';
const RECOVERY_CHECKPOINT_AUTHOR_EMAIL = 'goalctl@localhost';
const CHECKPOINT_GIT_FENCE_SCHEMA_VERSION = 1;
const CHECKPOINT_GIT_FENCE_KIND = 'goalctl-recovery-checkpoint-git-fence-v1';
const CHECKPOINT_GIT_FENCE_COMPLETION_KIND = 'goalctl-recovery-checkpoint-git-fence-completion-v1';
const IMPORT_ENTRY_TEMP_PREFIX = '.goalctl-source-import-entry-';
const IMPORT_TRACKED_TEMP_PREFIX = '.goalctl-source-import-tracked-';
const IMPORT_TRACKED_BASE_PREFIX = '.goalctl-source-import-base-';
const IMPORT_PARENT_MARKER_PREFIX = '.goalctl-source-import-parent-';
const IMPORT_INDEX_ANCHOR_PREFIX = '.goalctl-source-import-index-';
const CHECKPOINT_INDEX_LOCK_TEMP_PREFIX = '.goalctl-checkpoint-index-lock-';
const GIT_OPERATION_SENTINELS = Object.freeze([
  'MERGE_HEAD',
  'CHERRY_PICK_HEAD',
  'REVERT_HEAD',
  'REBASE_HEAD',
  'rebase-apply',
  'rebase-merge',
  'sequencer',
  'BISECT_START',
  'BISECT_LOG',
  'BISECT_TERMS',
  'AUTO_MERGE',
  'MERGE_AUTOSTASH',
  'rebase-apply/autostash',
  'rebase-merge/autostash',
]);
const CODEX_ROLLOUT_CAPTURE_KIND = 'codex-rollout-patch-apply-v1';
const CODEX_SHELL_AUDIT_KIND = 'codex-rollout-shell-audit-v1';
const SHELL_AUDIT_DISPOSITIONS = Object.freeze([
  'READ_ONLY',
  'IGNORED_PATH_ONLY',
  'TEST_NO_UPDATE',
]);
const CODEX_AUDITED_FUNCTION_CALLS = new Set([
  'exec_command',
  'send_message_to_thread',
  'write_stdin',
]);
const CODEX_PROVABLY_NON_SOURCE_FUNCTION_CALLS = new Set([
  'read_thread_terminal',
  'update_plan',
]);
const CODEX_NON_ACTION_RESPONSE_TYPES = new Set([
  'custom_tool_call_output',
  'function_call_output',
  'message',
  'reasoning',
  'tool_search_output',
]);

const DIFF_ARGS = Object.freeze([
  '--binary',
  '--full-index',
  '--no-ext-diff',
  '--no-textconv',
  '--no-renames',
  '--diff-algorithm=myers',
  '--no-indent-heuristic',
  '--unified=3',
  '--src-prefix=a/',
  '--dst-prefix=b/',
]);

const SOURCE_GIT_ENV = Object.freeze({
  GIT_LITERAL_PATHSPECS: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  GIT_ASKPASS: '/usr/bin/false',
  SSH_ASKPASS: '/usr/bin/false',
  GCM_INTERACTIVE: 'Never',
});

function gitRun(cwd, args, options = {}) {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: options.encoding === undefined ? 'utf8' : options.encoding,
      env: {
        ...process.env,
        ...SOURCE_GIT_ENV,
        ...(options.env || {}),
      },
      input: options.input,
      maxBuffer: GIT_MAX_BUFFER,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (error) {
    const detail = String(error.stderr || error.message || '').trim();
    throw new ControlError(
      options.code || 'GIT_FAILED',
      `${options.label || `git ${args.join(' ')}`} 失败${detail ? `: ${detail}` : ''}`,
    );
  }
}

function gitText(cwd, args, options = {}) {
  return String(gitRun(cwd, args, options)).trim();
}

function gitBuffer(cwd, args, options = {}) {
  return gitRun(cwd, args, { ...options, encoding: null });
}

function canonicalDirectory(candidate, label) {
  let resolved;
  try {
    resolved = fs.realpathSync(path.resolve(candidate));
  } catch (error) {
    throw new ControlError('HANDOFF_PATH_INVALID', `${label} 不存在或无法 canonicalize: ${error.message}`);
  }
  assertControl(fs.statSync(resolved).isDirectory(), 'HANDOFF_PATH_INVALID', `${label} 必须是目录`);
  return resolved;
}

function isolatedGitObjectEnvironment(worktree, temporaryDir, env = {}) {
  const sharedObjectDirectory = canonicalDirectory(
    gitText(
      worktree,
      ['rev-parse', '--path-format=absolute', '--git-path', 'objects'],
      {
        code: 'HANDOFF_EXPECTED_TREE_FAILED',
        label: 'resolve shared Git object database',
      },
    ),
    'shared Git object database',
  );
  const isolatedObjectDirectory = path.join(temporaryDir, 'objects');
  fs.mkdirSync(isolatedObjectDirectory, { mode: 0o700 });
  const inheritedAlternates =
    env.GIT_ALTERNATE_OBJECT_DIRECTORIES
    || process.env.GIT_ALTERNATE_OBJECT_DIRECTORIES
    || '';
  return {
    ...env,
    GIT_OBJECT_DIRECTORY: isolatedObjectDirectory,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: [
      sharedObjectDirectory,
      ...inheritedAlternates
        .split(path.delimiter)
        .filter((entry) => entry.length > 0),
    ].join(path.delimiter),
  };
}

function canonicalRegularFile(candidate, label) {
  let resolved;
  try {
    resolved = fs.realpathSync(path.resolve(candidate));
  } catch (error) {
    throw new ControlError('HANDOFF_ARTIFACT_MISSING', `${label} 不存在或无法 canonicalize: ${error.message}`);
  }
  const stat = fs.lstatSync(resolved);
  assertControl(stat.isFile() && !stat.isSymbolicLink(), 'HANDOFF_ARTIFACT_INVALID', `${label} 必须是非 symlink 普通文件`);
  return resolved;
}

function assertCanonicalDirectoryValue(value, label) {
  assertControl(typeof value === 'string' && path.isAbsolute(value), 'HANDOFF_PATH_INVALID', `${label} 必须是绝对路径`);
  const canonical = canonicalDirectory(value, label);
  assertControl(value === canonical, 'HANDOFF_PATH_INVALID', `${label} 必须是 canonical realpath`);
  return canonical;
}

function assertHistoricalDirectoryValue(value, label) {
  assertControl(
    typeof value === 'string'
      && path.isAbsolute(value)
      && path.normalize(value) === value
      && !value.includes('\0')
      && !/[\u0000-\u001f\u007f]/.test(value),
    'HANDOFF_PATH_INVALID',
    `${label} 必须是规范绝对路径`,
  );
  if (fs.existsSync(value)) return assertCanonicalDirectoryValue(value, label);
  return value;
}

function assertHistoricalAbsolutePath(value, label) {
  assertControl(
    typeof value === 'string'
      && path.isAbsolute(value)
      && path.normalize(value) === value
      && !value.includes('\0')
      && !/[\u0000-\u001f\u007f]/.test(value),
    'HANDOFF_PATH_INVALID',
    `${label} 必须是规范绝对路径`,
  );
  if (!fs.existsSync(value)) return value;
  let canonical;
  try {
    canonical = fs.realpathSync(value);
  } catch (error) {
    throw new ControlError('HANDOFF_PATH_INVALID', `${label} 无法 canonicalize: ${error.message}`);
  }
  assertControl(value === canonical, 'HANDOFF_PATH_INVALID', `${label} 必须是 canonical realpath`);
  return value;
}

function authorityFromSession(session) {
  assertControl(
    session
      && ['CAPTAIN', 'FOREMAN', 'DEV'].includes(session.role)
      && typeof session.thread_id === 'string'
      && typeof session.host_id === 'string'
      && Number.isSafeInteger(session.attempt)
      && session.attempt > 0,
    'HANDOFF_AUTHORITY_INVALID',
    'acceptance authority session identity/attempt 非法',
  );
  safeId(session.thread_id, 'acceptance authority thread_id');
  safeId(session.host_id, 'acceptance authority host_id');
  const supplied = readCapabilityFile(session.capability_file, session.capability_file);
  assertControl(
    hashesEqual(supplied.sha256, session.capability_sha256),
    'CAPABILITY_INVALID',
    'acceptance authority capability hash 与 registration 不一致',
  );
  return {
    role: session.role,
    thread_id: session.thread_id,
    host_id: session.host_id,
    attempt: session.attempt,
    capability_file: supplied.file,
    capability_sha256: normalizeHash(supplied.sha256, 'acceptance authority capability_sha256'),
  };
}

function validateAcceptanceAuthority(raw, role) {
  exactKeys(
    raw,
    [
      'role', 'thread_id', 'host_id', 'attempt',
      'capability_file', 'capability_sha256',
    ],
    `${role} acceptance authority`,
  );
  assertControl(raw.role === role, 'HANDOFF_AUTHORITY_INVALID', `acceptance authority role 不是 ${role}`);
  safeId(raw.thread_id, `${role} acceptance thread_id`);
  safeId(raw.host_id, `${role} acceptance host_id`);
  assertControl(
    Number.isSafeInteger(raw.attempt) && raw.attempt > 0,
    'HANDOFF_AUTHORITY_INVALID',
    `${role} acceptance attempt 非法`,
  );
  assertHistoricalAbsolutePath(raw.capability_file, `${role} acceptance capability_file`);
  normalizeHash(raw.capability_sha256, `${role} acceptance capability_sha256`);
  return raw;
}

function sessionIdentityMatchesAuthority(session, authority) {
  return session
    && session.role === authority.role
    && session.thread_id === authority.thread_id
    && session.host_id === authority.host_id
    && session.attempt === authority.attempt;
}

function authorizeSealedAuthority(
  state,
  capabilityFile,
  authority,
  options = {},
) {
  validateAcceptanceAuthority(authority, authority.role);
  const states = authority.role === 'FOREMAN' && options.goalSnapshot
    ? Object.values(options.goalSnapshot.tasks || {})
    : [state];
  const identityMatches = states.flatMap((candidateState) => [
    ...Object.values(candidateState.sessions || {}),
    ...Object.values(candidateState.session_history || {}).flat(),
  ]).filter((session) => sessionIdentityMatchesAuthority(session, authority));
  assertControl(
    authority.role === 'FOREMAN'
      ? identityMatches.length >= 1
      : identityMatches.length === 1,
    'CAPABILITY_INVALID',
    `${authority.role} sealed identity 不再存在于授权 scope 的 current/history`,
  );
  assertControl(
    identityMatches.every((registered) => (
      registered.capability_file === authority.capability_file
        && normalizeHash(
          registered.capability_sha256,
          `${authority.role} registered capability_sha256`,
        ) === authority.capability_sha256
    )),
    'CAPABILITY_INVALID',
    `${authority.role} historical capability replica 与 sealed authority 不一致`,
  );
  const supplied = readCapabilityFile(capabilityFile);
  assertControl(
    supplied.file === authority.capability_file
      && normalizeHash(supplied.sha256, `${authority.role} supplied capability_sha256`)
        === authority.capability_sha256,
    'CAPABILITY_INVALID',
    `${authority.role} capability 未精确匹配 sealed acceptance authority`,
  );
  return identityMatches[0];
}

function repositoryIdentity(cwd) {
  const worktree = canonicalDirectory(repoRoot(cwd), 'worktree');
  const commonGitDir = canonicalDirectory(
    gitText(worktree, ['rev-parse', '--path-format=absolute', '--git-common-dir']),
    'git common dir',
  );
  const branch = gitText(worktree, ['branch', '--show-current']);
  const head = gitText(worktree, ['rev-parse', '--verify', 'HEAD^{commit}']);
  assertControl(branch.length > 0, 'HANDOFF_DETACHED_HEAD', 'source handoff 禁止 detached HEAD');
  assertFullSha(head, 'worktree HEAD');
  return {
    worktree,
    common_git_dir: commonGitDir,
    repository_root: canonicalDirectory(path.dirname(commonGitDir), 'repository root'),
    branch,
    head,
  };
}

function safeRelativePath(value, label = 'snapshot path') {
  assertControl(typeof value === 'string' && value.length > 0, 'HANDOFF_PATH_INVALID', `${label} 不能为空`);
  const bytes = Buffer.byteLength(value);
  assertControl(bytes <= MAX_RELATIVE_PATH_BYTES, 'HANDOFF_PATH_INVALID', `${label} 超过 ${MAX_RELATIVE_PATH_BYTES} bytes`);
  assertControl(
    !value.includes('\0') && !value.includes('\\') && !/[\u0000-\u001f\u007f]/.test(value),
    'HANDOFF_PATH_INVALID',
    `${label} 含控制字符或反斜杠`,
  );
  assertControl(!path.posix.isAbsolute(value), 'HANDOFF_PATH_INVALID', `${label} 必须是相对路径`);
  const parts = value.split('/');
  assertControl(
    parts.every((part) => part.length > 0 && part !== '.' && part !== '..'),
    'HANDOFF_PATH_INVALID',
    `${label} 含空、. 或 .. 路径段`,
  );
  assertControl(path.posix.normalize(value) === value, 'HANDOFF_PATH_INVALID', `${label} 不是规范 POSIX 相对路径`);
  assertControl(parts[0] !== '.git', 'HANDOFF_PATH_INVALID', `${label} 禁止指向 .git`);
  return value;
}

function splitNullPaths(buffer, label) {
  if (buffer.length === 0) return [];
  assertControl(buffer[buffer.length - 1] === 0, 'HANDOFF_PATH_INVALID', `${label} 缺 NUL terminator`);
  const entries = [];
  let offset = 0;
  for (let index = 0; index < buffer.length; index += 1) {
    if (buffer[index] !== 0) continue;
    const raw = buffer.subarray(offset, index);
    const decoded = raw.toString('utf8');
    assertControl(Buffer.from(decoded, 'utf8').equals(raw), 'HANDOFF_PATH_INVALID', `${label} 含非 UTF-8 路径`);
    entries.push(safeRelativePath(decoded, label));
    offset = index + 1;
  }
  return entries;
}

function compareGitPaths(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalChangedPaths(paths, label) {
  const normalized = paths.map((entry) => safeRelativePath(entry, label));
  const sorted = [...normalized].sort(compareGitPaths);
  assertControl(
    sorted.every((entry, index) => index === 0 || entry !== sorted[index - 1]),
    'HANDOFF_ARTIFACT_INVALID',
    `${label} 含重复路径`,
  );
  return sorted;
}

function assertSameChangedPaths(actual, expected, code, label) {
  assertControl(
    actual.length === expected.length
      && actual.every((entry, index) => entry === expected[index]),
    code,
    `${label} 不匹配`,
  );
}

function changedPathsInIndex(worktree, baseHead, env = undefined) {
  return canonicalChangedPaths(
    splitNullPaths(
      gitBuffer(
        worktree,
        ['diff', '--cached', '--name-only', '--no-renames', '-z', baseHead, '--'],
        { env },
      ),
      'staged changed path',
    ),
    'staged changed path',
  );
}

function changedPathsInCommit(worktree, baseHead, commit) {
  return canonicalChangedPaths(
    splitNullPaths(
      gitBuffer(
        worktree,
        ['diff', '--name-only', '--no-renames', '-z', baseHead, commit, '--'],
      ),
      'commit changed path',
    ),
    'commit changed path',
  );
}

function changedPathsInPatch(worktree, patch) {
  if (patch.length === 0) return [];
  const output = gitBuffer(
    worktree,
    ['apply', '--numstat', '-z', '-'],
    {
      input: patch,
      code: 'LEGACY_HANDOFF_PATCH_INVALID',
      label: 'parse legacy handoff tracked patch paths',
    },
  );
  assertControl(
    output.length > 0 && output[output.length - 1] === 0,
    'LEGACY_HANDOFF_PATCH_INVALID',
    'legacy handoff tracked patch numstat 缺 NUL terminator',
  );
  const paths = [];
  let offset = 0;
  for (let index = 0; index < output.length; index += 1) {
    if (output[index] !== 0) continue;
    const record = output.subarray(offset, index);
    offset = index + 1;
    const firstTab = record.indexOf(0x09);
    const secondTab = firstTab < 0
      ? -1
      : record.indexOf(0x09, firstTab + 1);
    assertControl(
      firstTab > 0
        && secondTab > firstTab + 1
        && secondTab < record.length - 1,
      'LEGACY_HANDOFF_PATCH_INVALID',
      'legacy handoff tracked patch numstat record 非法',
    );
    const additions = record.subarray(0, firstTab).toString('ascii');
    const deletions = record.subarray(firstTab + 1, secondTab).toString('ascii');
    assertControl(
      (/^\d+$/.test(additions) && /^\d+$/.test(deletions))
        || (additions === '-' && deletions === '-'),
      'LEGACY_HANDOFF_PATCH_INVALID',
      'legacy handoff tracked patch numstat count 非法',
    );
    const rawPath = record.subarray(secondTab + 1);
    const decoded = rawPath.toString('utf8');
    assertControl(
      Buffer.from(decoded, 'utf8').equals(rawPath),
      'LEGACY_HANDOFF_PATCH_INVALID',
      'legacy handoff tracked patch path 不是 UTF-8',
    );
    paths.push(safeRelativePath(decoded, 'legacy handoff tracked path'));
  }
  const canonical = canonicalChangedPaths(
    paths,
    'legacy handoff tracked path',
  );
  return canonical;
}

function stageSnapshotEntriesInIndex(worktree, entries, env) {
  const indexRecords = [];
  for (const entry of entries) {
    const hashArgs = ['hash-object', '-w'];
    if (entry.type === 'regular') {
      hashArgs.push('--filters', `--path=${entry.path}`);
    } else {
      hashArgs.push('--no-filters');
    }
    hashArgs.push('--stdin');
    const blob = gitText(worktree, hashArgs, {
      env,
      input: entry.body,
      code: 'HANDOFF_EXPECTED_TREE_FAILED',
      label: `hash snapshot entry ${entry.path}`,
    });
    assertFullSha(blob, `snapshot entry ${entry.path} blob`);
    indexRecords.push(
      Buffer.from(`${entry.mode} ${blob}\t${entry.path}\0`, 'utf8'),
    );
  }
  if (indexRecords.length > 0) {
    gitRun(worktree, ['update-index', '-z', '--index-info'], {
      env,
      input: Buffer.concat(indexRecords),
      code: 'HANDOFF_EXPECTED_TREE_FAILED',
      label: 'stage snapshot entries atomically',
    });
  }
}

function expectedSnapshotTree(worktree, baseHead, patch, entries) {
  const temporaryDir = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), 'goal-handoff-index-'),
  );
  const env = isolatedGitObjectEnvironment(
    worktree,
    temporaryDir,
    { GIT_INDEX_FILE: path.join(temporaryDir, 'index') },
  );
  try {
    gitRun(worktree, ['read-tree', baseHead], {
      env,
      code: 'HANDOFF_EXPECTED_TREE_FAILED',
      label: 'initialize expected snapshot tree',
    });
    if (patch.length > 0) {
      gitRun(
        worktree,
        ['apply', '--cached', '--binary', '--whitespace=nowarn', '-'],
        {
          env,
          input: patch,
          code: 'HANDOFF_EXPECTED_TREE_FAILED',
          label: 'apply tracked patch to expected snapshot tree',
        },
      );
    }
    stageSnapshotEntriesInIndex(worktree, entries, env);
    const tree = gitText(worktree, ['write-tree'], {
      env,
      code: 'HANDOFF_EXPECTED_TREE_FAILED',
      label: 'write expected snapshot tree',
    });
    assertFullSha(tree, 'expected snapshot tree');
    return {
      tree,
      paths: changedPathsInIndex(worktree, baseHead, env),
    };
  } finally {
    fs.rmSync(temporaryDir, { recursive: true, force: true });
  }
}

function readIndexTreeWithoutCanonicalMutation(
  worktree,
  {
    code = 'HANDOFF_GIT_INDEX_DRIFT',
    label = 'read index tree through isolated index copy',
  } = {},
) {
  const indexFile = gitIndexPath(worktree);
  const before = fs.lstatSync(indexFile, { bigint: true });
  const beforeSha256 = hashFile(indexFile);
  const temporaryDir = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), 'goal-handoff-read-index-'),
  );
  const temporaryIndex = path.join(temporaryDir, 'index');
  try {
    fs.copyFileSync(
      indexFile,
      temporaryIndex,
      fs.constants.COPYFILE_EXCL,
    );
    fs.chmodSync(temporaryIndex, 0o600);
    const tree = gitText(worktree, ['write-tree'], {
      env: isolatedGitObjectEnvironment(
        worktree,
        temporaryDir,
        { GIT_INDEX_FILE: temporaryIndex },
      ),
      code,
      label,
    });
    const after = fs.lstatSync(indexFile, { bigint: true });
    assertControl(
      before.dev === after.dev
        && before.ino === after.ino
        && before.size === after.size
        && before.mtimeNs === after.mtimeNs
        && hashFile(indexFile) === beforeSha256,
      'HANDOFF_GIT_INDEX_DRIFT',
      `${label} 改写了 canonical Git index`,
    );
    return tree;
  } finally {
    fs.rmSync(temporaryDir, { recursive: true, force: true });
  }
}

function materializeWitnessedIndexTree(
  worktree,
  indexSnapshot,
  expectedTree,
) {
  const temporaryDir = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), 'goal-handoff-materialize-tree-'),
  );
  const temporaryIndex = path.join(temporaryDir, 'index');
  try {
    fs.copyFileSync(
      indexSnapshot.file,
      temporaryIndex,
      fs.constants.COPYFILE_EXCL,
    );
    fs.chmodSync(temporaryIndex, 0o600);
    const tree = gitText(worktree, ['write-tree'], {
      env: { GIT_INDEX_FILE: temporaryIndex },
      code: 'HANDOFF_CHECKPOINT_COMMIT_FAILED',
      label: 'materialize witnessed recovery checkpoint tree',
    });
    assertControl(
      tree === expectedTree,
      'HANDOFF_CHECKPOINT_TREE_MISMATCH',
      'witnessed checkpoint index 未 materialize 为 sealed expected_tree',
    );
    return tree;
  } finally {
    fs.rmSync(temporaryDir, { recursive: true, force: true });
  }
}

function strictTextLines(body, label) {
  assertControl(
    Buffer.isBuffer(body) && !body.includes(0),
    'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
    `${label} 不是可严格重放的文本 blob`,
  );
  const text = body.toString('utf8');
  assertControl(
    Buffer.from(text, 'utf8').equals(body),
    'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
    `${label} 不是 UTF-8`,
  );
  const trailingNewline = text.endsWith('\n');
  const content = trailingNewline ? text.slice(0, -1) : text;
  return {
    lines: content.length === 0 ? [] : content.split('\n'),
    trailingNewline,
  };
}

function hunkTextLines(hunk, label) {
  assertControl(
    hunk
      && Array.isArray(hunk.lines)
      && hunk.lines.length > 0
      && hunk.lines.every((line) => (
        typeof line === 'string'
          && line.length > 0
          && [' ', '+', '-'].includes(line[0])
      )),
    'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
    `${label} 含 unsupported/no-newline patch line`,
  );
  return {
    oldLines: hunk.lines
      .filter((line) => line[0] === ' ' || line[0] === '-')
      .map((line) => line.slice(1)),
    newLines: hunk.lines
      .filter((line) => line[0] === ' ' || line[0] === '+')
      .map((line) => line.slice(1)),
    mutates: hunk.lines.some((line) => line[0] === '+' || line[0] === '-'),
  };
}

function findExactHunk(lines, oldLines, start, label, options = {}) {
  assertControl(oldLines.length > 0, 'CODEX_ROLLOUT_CHANGE_UNSUPPORTED', `${label} 缺定位 context`);
  const matches = [];
  for (let index = start; index + oldLines.length <= lines.length; index += 1) {
    if (oldLines.every((line, offset) => lines[index + offset] === line)) matches.push(index);
  }
  assertControl(
    matches.length > 0 && (options.requireUnique !== true || matches.length === 1),
    'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
    `${label} 在 predecessor launch HEAD 上${matches.length === 0 ? '无法' : '不能唯一'}定位`,
  );
  return matches[0];
}

function expectedCodexCallTree(worktree, baseHead, callOperations) {
  const files = new Map();
  const loadFile = (relative) => {
    if (files.has(relative)) return files.get(relative);
    const treeEntry = gitText(worktree, ['ls-tree', baseHead, '--', relative], {
      code: 'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
      label: `read predecessor mode ${relative}`,
    });
    const match = /^(100644|100755) blob [0-9a-f]{40}\t(.+)$/.exec(treeEntry);
    assertControl(
      match && match[2] === relative,
      'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
      `Codex rollout ${relative} 不是普通 tracked blob`,
    );
    const body = gitBuffer(worktree, ['show', `${baseHead}:${relative}`], {
      code: 'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
      label: `read predecessor blob ${relative}`,
    });
    const text = strictTextLines(body, `Codex rollout ${relative}`);
    const value = {
      mode: match[1],
      lines: text.lines,
      trailingNewline: text.trailingNewline,
      changed: false,
    };
    files.set(relative, value);
    return value;
  };

  for (const operation of callOperations) {
    for (const [relative, hunks] of operation.hunks.entries()) {
      const file = loadFile(relative);
      let cursor = 0;
      let lineOffset = 0;
      for (let index = 0; index < hunks.length; index += 1) {
        const hunk = hunks[index];
        const parsed = hunkTextLines(
          hunk,
          `Codex apply_patch ${operation.call_id}/${relative}/hunk-${index + 1}`,
        );
        const numeric = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(hunk.header);
        let matchIndex;
        if (numeric) {
          const oldCount = numeric[2] === undefined ? 1 : Number(numeric[2]);
          assertControl(
            oldCount === parsed.oldLines.length,
            'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
            `Codex apply_patch ${operation.call_id}/${relative} numeric hunk count 不匹配`,
          );
          matchIndex = Number(numeric[1]) - 1 + lineOffset;
          assertControl(
            matchIndex >= cursor
              && parsed.oldLines.every((line, offset) => file.lines[matchIndex + offset] === line),
            'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
            `Codex apply_patch ${operation.call_id}/${relative} numeric hunk 未绑定 predecessor bytes`,
          );
        } else {
          const section = hunk.header.slice(2).trim();
          if (section.length > 0) {
            const sectionIndex = findExactHunk(
              file.lines,
              [section],
              cursor,
              `Codex apply_patch ${operation.call_id}/${relative}/section-${index + 1}`,
              { requireUnique: true },
            );
            cursor = sectionIndex + 1;
          }
          matchIndex = findExactHunk(
            file.lines,
            parsed.oldLines,
            cursor,
            `Codex apply_patch ${operation.call_id}/${relative}/hunk-${index + 1}`,
          );
        }
        if (parsed.mutates) {
          file.lines.splice(matchIndex, parsed.oldLines.length, ...parsed.newLines);
          file.changed = true;
          lineOffset += parsed.newLines.length - parsed.oldLines.length;
          cursor = matchIndex + parsed.newLines.length;
        } else {
          cursor = matchIndex + parsed.oldLines.length;
        }
      }
    }
  }
  const entries = [...files.entries()]
    .filter(([, file]) => file.changed)
    .map(([relative, file]) => ({
      path: relative,
      type: 'regular',
      mode: file.mode,
      body: Buffer.from(
        `${file.lines.join('\n')}${file.trailingNewline ? '\n' : ''}`,
        'utf8',
      ),
    }));
  return expectedSnapshotTree(worktree, baseHead, Buffer.alloc(0), entries);
}

function assertCodexCaptureTree(worktree, baseHead, capture) {
  const expectedFromEvent = expectedSnapshotTree(
    worktree,
    baseHead,
    capture.patch,
    [],
  );
  const expectedFromCalls = expectedCodexCallTree(
    worktree,
    baseHead,
    capture.callOperations,
  );
  assertControl(
    expectedFromCalls.tree === expectedFromEvent.tree
      && hashObject(expectedFromCalls.paths) === hashObject(expectedFromEvent.paths),
    'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
    'apply_patch call 在 predecessor launch HEAD 上的严格结果与 patch_apply_end 恢复树不一致',
  );
  return expectedFromEvent;
}

function assertExactTreeSnapshot(snapshot) {
  assertControl(
    [EXACT_TREE_SNAPSHOT_SCHEMA_VERSION, SNAPSHOT_SCHEMA_VERSION]
      .includes(snapshot.schema_version)
      && typeof snapshot.expected_tree === 'string'
      && Array.isArray(snapshot.expected_paths),
    'HANDOFF_EXACT_TREE_REQUIRED',
    'legacy recovery snapshot 未封存 expected tree，禁止继续 import/bind',
  );
}

function assertExactTreeReceipt(receipt) {
  assertControl(
    [EXACT_TREE_RECEIPT_SCHEMA_VERSION, RECEIPT_SCHEMA_VERSION]
      .includes(receipt.schema_version)
      && typeof receipt.expected_tree === 'string'
      && typeof receipt.materialized_tree === 'string',
    'HANDOFF_EXACT_TREE_REQUIRED',
    'legacy recovery receipt 未封存 expected/materialized tree，禁止继续 bind',
  );
}

function legacyRecoveryHandoffAnchorKey(request) {
  const goalId = safeId(request.goalId, 'legacy handoff goal_id');
  const taskId = safeId(request.taskId, 'legacy handoff task_id');
  const eventId = safeId(request.eventId, 'legacy handoff event_id');
  return `${goalId}/${taskId}/${eventId}`;
}

function validateLegacyRecoveryHandoffBinding(binding, expected = {}) {
  const keys = [
    'schema_version',
    'goal_id',
    'task_id',
    'event_id',
    'event_input_sha256',
    'event_sha256',
    'event_accepted_at',
    'event_payload_sha256',
    'snapshot_id',
    'snapshot_sha256',
    'snapshot_schema_version',
    'import_receipt_id',
    'import_receipt_sha256',
    'receipt_schema_version',
    'source_observed_head',
    'import_commit',
    'import_commit_object_sha256',
    'migration_repository_worktree',
    'migration_repository_common_dir',
    'migration_repository_head',
    'expected_tree',
    'expected_paths',
    'expected_paths_sha256',
    'materialized_patch_sha256',
    'materialized_patch_bytes',
    'binding_sha256',
  ];
  exactKeys(binding, keys, 'legacy recovery handoff binding');
  assertControl(
    Object.keys(binding).length === keys.length
      && binding.schema_version === 1
      && binding.snapshot_schema_version === LEGACY_SNAPSHOT_SCHEMA_VERSION
      && binding.receipt_schema_version === LEGACY_RECEIPT_SCHEMA_VERSION,
    'LEGACY_HANDOFF_ANCHOR_INVALID',
    'legacy recovery handoff binding schema 非法',
  );
  for (const key of [
    'goal_id',
    'task_id',
    'event_id',
    'snapshot_id',
    'import_receipt_id',
  ]) {
    safeId(binding[key], `legacy handoff ${key}`);
  }
  for (const key of [
    'source_observed_head',
    'import_commit',
    'expected_tree',
    'migration_repository_head',
  ]) {
    assertFullSha(binding[key], `legacy handoff ${key}`);
  }
  for (const key of [
    'event_input_sha256',
    'event_sha256',
    'event_payload_sha256',
    'snapshot_sha256',
    'import_receipt_sha256',
    'import_commit_object_sha256',
    'expected_paths_sha256',
    'materialized_patch_sha256',
  ]) {
    normalizeHash(binding[key], `legacy handoff ${key}`);
  }
  assertControl(
    typeof binding.event_accepted_at === 'string'
      && Number.isFinite(Date.parse(binding.event_accepted_at))
      && typeof binding.migration_repository_worktree === 'string'
      && path.isAbsolute(binding.migration_repository_worktree)
      && path.resolve(binding.migration_repository_worktree)
        === binding.migration_repository_worktree
      && typeof binding.migration_repository_common_dir === 'string'
      && path.isAbsolute(binding.migration_repository_common_dir)
      && path.resolve(binding.migration_repository_common_dir)
        === binding.migration_repository_common_dir
      && Array.isArray(binding.expected_paths)
      && Number.isSafeInteger(binding.materialized_patch_bytes)
      && binding.materialized_patch_bytes >= 0
      && binding.materialized_patch_bytes <= MAX_SNAPSHOT_BYTES,
    'LEGACY_HANDOFF_ANCHOR_INVALID',
    'legacy recovery handoff expected_paths/materialized_patch_bytes 非法',
  );
  const canonicalPaths = canonicalChangedPaths(
    binding.expected_paths,
    'legacy handoff expected path',
  );
  assertSameChangedPaths(
    binding.expected_paths,
    canonicalPaths,
    'LEGACY_HANDOFF_ANCHOR_INVALID',
    'legacy handoff expected_paths canonical order',
  );
  assertControl(
    hashObject(binding.expected_paths) === binding.expected_paths_sha256,
    'LEGACY_HANDOFF_ANCHOR_INVALID',
    'legacy recovery handoff expected_paths seal 不匹配',
  );
  const unsigned = { ...binding };
  delete unsigned.binding_sha256;
  assertControl(
    hashObject(unsigned) === normalizeHash(
      binding.binding_sha256,
      'legacy handoff binding_sha256',
    ),
    'LEGACY_HANDOFF_ANCHOR_INVALID',
    'legacy recovery handoff binding seal 不匹配',
  );
  for (const [key, value] of Object.entries(expected)) {
    if (value !== undefined) {
      assertControl(
        canonicalJson(binding[key]) === canonicalJson(value),
        'LEGACY_HANDOFF_ANCHOR_MISMATCH',
        `legacy recovery handoff binding ${key} 不匹配`,
      );
    }
  }
  return binding;
}

function prepareLegacyRecoveryHandoffBindings(bindings) {
  assertControl(
    bindings instanceof Map
      || (
        bindings
          && typeof bindings === 'object'
          && !Array.isArray(bindings)
      ),
    'LEGACY_HANDOFF_ANCHOR_INVALID',
    'legacy recovery handoff bindings 必须是 Map 或对象',
  );
  const entries = bindings instanceof Map
    ? [...bindings.entries()]
    : Object.entries(bindings);
  assertControl(
    entries.length <= MAX_LEGACY_RECOVERY_HANDOFF_BINDINGS,
    'LEGACY_HANDOFF_ANCHOR_INVALID',
    `legacy recovery handoff binding 超过 ${MAX_LEGACY_RECOVERY_HANDOFF_BINDINGS}`,
  );
  const handoffs = {};
  for (const [key, raw] of entries
    .sort(([left], [right]) => left.localeCompare(right))) {
    const binding = validateLegacyRecoveryHandoffBinding(raw);
    assertControl(
      key === `${binding.goal_id}/${binding.task_id}/${binding.event_id}`,
      'LEGACY_HANDOFF_ANCHOR_INVALID',
      `legacy recovery handoff collector key 非法: ${key}`,
    );
    handoffs[key] = JSON.parse(canonicalJson(binding));
  }
  return {
    handoffs,
    count: Object.keys(handoffs).length,
  };
}

function assertNoUnmerged(worktree) {
  const unmerged = gitBuffer(worktree, ['diff', '--name-only', '--diff-filter=U', '-z', '--']);
  assertControl(unmerged.length === 0, 'HANDOFF_UNMERGED_PATHS', 'source worktree 存在 unmerged paths');
}

function assertAncestor(worktree, ancestor, descendant, code = 'HANDOFF_SOURCE_HEAD_DIVERGED') {
  try {
    gitRun(worktree, ['merge-base', '--is-ancestor', ancestor, descendant], {
      code,
      label: `${ancestor} 是否为 ${descendant} 祖先`,
    });
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw error;
  }
}

function trackedPatch(worktree, sourceLaunchHead, cached = false, commit = null) {
  const args = ['diff', ...DIFF_ARGS];
  if (cached) args.push('--cached');
  args.push(sourceLaunchHead);
  if (commit) args.push(commit);
  args.push('--');
  const patch = gitBuffer(worktree, args);
  assertControl(
    !patch.includes(Buffer.from(' 160000')) && !patch.includes(Buffer.from('mode 160000')),
    'HANDOFF_SUBMODULE_UNSUPPORTED',
    'source snapshot 不支持 gitlink/submodule 变更',
  );
  return patch;
}

function readUntrackedEntries(worktree) {
  const paths = splitNullPaths(
    gitBuffer(worktree, ['ls-files', '--others', '--exclude-standard', '-z', '--']),
    'untracked path',
  );
  assertControl(paths.length <= MAX_UNTRACKED_ENTRIES, 'HANDOFF_SNAPSHOT_TOO_LARGE', `untracked 文件超过 ${MAX_UNTRACKED_ENTRIES}`);
  const entries = [];
  let totalBytes = 0;
  for (const relative of paths) {
    const absolute = path.join(worktree, ...relative.split('/'));
    const stat = fs.lstatSync(absolute);
    let body;
    let type;
    let mode;
    if (stat.isFile()) {
      type = 'regular';
      mode = (stat.mode & 0o111) === 0 ? '100644' : '100755';
      assertControl(
        stat.size <= MAX_SNAPSHOT_BYTES - totalBytes,
        'HANDOFF_SNAPSHOT_TOO_LARGE',
        `snapshot 超过 ${MAX_SNAPSHOT_BYTES} bytes`,
      );
      body = fs.readFileSync(absolute);
    } else if (stat.isSymbolicLink()) {
      type = 'symlink';
      mode = '120000';
      const target = fs.readlinkSync(absolute);
      body = Buffer.from(target, 'utf8');
      assertControl(
        body.length > 0 && body.length <= MAX_SYMLINK_TARGET_BYTES && !body.includes(0),
        'HANDOFF_SYMLINK_INVALID',
        `symlink ${relative} target 非法或超过 ${MAX_SYMLINK_TARGET_BYTES} bytes`,
      );
    } else {
      assertControl(false, 'HANDOFF_SPECIAL_FILE_FORBIDDEN', `untracked ${relative} 不是普通文件或 symlink`);
    }
    totalBytes += body.length;
    assertControl(totalBytes <= MAX_SNAPSHOT_BYTES, 'HANDOFF_SNAPSHOT_TOO_LARGE', `snapshot 超过 ${MAX_SNAPSHOT_BYTES} bytes`);
    entries.push({
      path: relative,
      type,
      mode,
      size: body.length,
      sha256: `sha256:${sha256(body)}`,
      body,
    });
  }
  return { entries, totalBytes };
}

function assertSourceStable(worktree, sourceObservedHead, sourceBranch, patch, entries) {
  assertControl(
    gitText(worktree, ['rev-parse', '--verify', 'HEAD^{commit}']) === sourceObservedHead
      && gitText(worktree, ['branch', '--show-current']) === sourceBranch,
    'HANDOFF_SOURCE_CHANGED',
    'source HEAD/branch 在 snapshot 期间发生变化',
  );
  const secondPatch = trackedPatch(worktree, sourceObservedHead);
  assertControl(secondPatch.equals(patch), 'HANDOFF_SOURCE_CHANGED', 'source tracked 内容在 snapshot 期间发生变化');
  const second = readUntrackedEntries(worktree);
  assertControl(second.entries.length === entries.length, 'HANDOFF_SOURCE_CHANGED', 'source untracked 列表在 snapshot 期间发生变化');
  for (let index = 0; index < entries.length; index += 1) {
    const left = entries[index];
    const right = second.entries[index];
    assertControl(
      left.path === right.path
        && left.type === right.type
        && left.mode === right.mode
        && left.size === right.size
        && left.sha256 === right.sha256,
      'HANDOFF_SOURCE_CHANGED',
      `source untracked ${left.path} 在 snapshot 期间发生变化`,
    );
  }
}

function exactKeys(value, allowed, label) {
  assertControl(value && typeof value === 'object' && !Array.isArray(value), 'HANDOFF_ARTIFACT_INVALID', `${label} 必须是对象`);
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  assertControl(unknown.length === 0, 'HANDOFF_ARTIFACT_INVALID', `${label} 含未知字段: ${unknown.join(', ')}`);
}

function jsonlRecords(buffer, label) {
  assertControl(Buffer.isBuffer(buffer) && buffer.length > 0, 'CODEX_ROLLOUT_INVALID', `${label} 不能为空`);
  const records = [];
  let offset = 0;
  let line = 1;
  for (let index = 0; index <= buffer.length; index += 1) {
    if (index !== buffer.length && buffer[index] !== 0x0a) continue;
    const raw = buffer.subarray(offset, index);
    offset = index + 1;
    if (raw.length === 0 && index === buffer.length) break;
    assertControl(raw.length > 0, 'CODEX_ROLLOUT_INVALID', `${label} 第 ${line} 行为空`);
    const text = raw.toString('utf8');
    assertControl(Buffer.from(text, 'utf8').equals(raw), 'CODEX_ROLLOUT_INVALID', `${label} 第 ${line} 行不是 UTF-8`);
    let value;
    try {
      value = JSON.parse(text);
    } catch (error) {
      throw new ControlError('CODEX_ROLLOUT_INVALID', `${label} 第 ${line} 行不是合法 JSON: ${error.message}`);
    }
    records.push({ line, raw, value });
    line += 1;
  }
  return records;
}

function parseApplyPatchInput(input, historicalWorktree) {
  assertControl(typeof input === 'string', 'CODEX_ROLLOUT_INVALID', 'apply_patch input 必须是字符串');
  const prefix = `${historicalWorktree}${path.sep}`;
  const paths = new Set();
  const foreignPaths = [];
  const changedLines = new Map();
  const hunks = new Map();
  let currentRelative = null;
  let currentHunk = null;
  for (const line of input.split('\n')) {
    const match = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(line);
    if (match) {
      const absolute = match[2];
      if (!absolute.startsWith(prefix)) {
        foreignPaths.push(absolute);
        currentRelative = null;
        currentHunk = null;
        continue;
      }
      assertControl(match[1] === 'Update', 'CODEX_ROLLOUT_CHANGE_UNSUPPORTED', `Codex rollout 不支持 ${match[1]}: ${absolute}`);
      currentRelative = safeRelativePath(absolute.slice(prefix.length), 'Codex apply_patch path');
      assertControl(!paths.has(currentRelative), 'CODEX_ROLLOUT_INVALID', `Codex apply_patch 重复 path: ${currentRelative}`);
      paths.add(currentRelative);
      changedLines.set(currentRelative, []);
      hunks.set(currentRelative, []);
      currentHunk = null;
      continue;
    }
    const move = /^\*\*\* Move to: (.+)$/.exec(line);
    if (move) {
      if (move[1].startsWith(prefix)) {
        assertControl(false, 'CODEX_ROLLOUT_CHANGE_UNSUPPORTED', `Codex rollout 不支持 move: ${move[1]}`);
      }
      foreignPaths.push(move[1]);
      currentRelative = null;
      currentHunk = null;
      continue;
    }
    if (line === '*** Begin Patch' || line === '*** End Patch') {
      continue;
    }
    if (line.startsWith('@@')) {
      if (currentRelative !== null) {
        currentHunk = { header: line, lines: [] };
        hunks.get(currentRelative).push(currentHunk);
      }
      continue;
    }
    if (
      currentRelative !== null
      && (line.startsWith(' ') || line.startsWith('+') || line.startsWith('-') || line.startsWith('\\'))
    ) {
      assertControl(
        currentHunk !== null,
        'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
        `Codex apply_patch ${currentRelative} 在 hunk 外含 patch line`,
      );
      currentHunk.lines.push(line);
      if (line.startsWith('+') || line.startsWith('-')) {
        changedLines.get(currentRelative).push(line);
      }
    }
  }
  if (paths.size > 0) {
    assertControl(
      foreignPaths.length === 0,
      'HANDOFF_PATH_INVALID',
      `Codex apply_patch 同时包含 predecessor worktree 外路径: ${foreignPaths.join(', ')}`,
    );
  }
  return { paths, changedLines, hunks };
}

function applyPatchInputPaths(input, historicalWorktree) {
  return parseApplyPatchInput(input, historicalWorktree).paths;
}

function validateCodexPatchCall(record, historicalWorktree, expectedCallId = undefined) {
  const item = record.value;
  const payload = item && item.payload;
  assertControl(
    item
      && item.type === 'response_item'
      && payload
      && payload.type === 'custom_tool_call'
      && payload.name === 'apply_patch'
      && payload.status === 'completed',
    'CODEX_ROLLOUT_INVALID',
    `第 ${record.line} 行不是 completed apply_patch call`,
  );
  const callId = safeId(payload.call_id, 'Codex patch call_id');
  assertControl(
    expectedCallId === undefined || callId === expectedCallId,
    'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
    `第 ${record.line} 行 apply_patch call_id 不匹配`,
  );
  const parsed = parseApplyPatchInput(payload.input, historicalWorktree);
  const { paths, changedLines, hunks } = parsed;
  assertControl(paths.size > 0, 'CODEX_ROLLOUT_INVALID', `apply_patch ${callId} 未指向 predecessor worktree`);
  for (const relative of paths) {
    assertControl(
      changedLines.get(relative).length > 0,
      'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
      `apply_patch ${callId} 的 ${relative} 缺可核对 mutation lines`,
    );
  }
  return { callId, paths, changedLines, hunks };
}

function codexPatchResultSucceeded(record, expectedCallId) {
  const item = record.value;
  const payload = item && item.payload;
  assertControl(
    item
      && item.type === 'response_item'
      && payload
      && payload.type === 'custom_tool_call_output'
      && payload.call_id === expectedCallId,
    'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
    `第 ${record.line} 行不是 ${expectedCallId} 的 apply_patch result`,
  );
  return typeof payload.output === 'string'
    && payload.output.includes('Exit code: 0')
    && payload.output.includes('Success.');
}

function validateCodexPatchResult(record, expectedCallId) {
  assertControl(
    codexPatchResultSucceeded(record, expectedCallId),
    'CODEX_ROLLOUT_PATCH_RESULT_INVALID',
    `apply_patch ${expectedCallId} 未成功完成`,
  );
}

function parseCodexFunctionArguments(record, payload) {
  assertControl(
    typeof payload.arguments === 'string',
    'CODEX_ROLLOUT_SHELL_UNVERIFIED',
    `Codex function_call ${payload.call_id || `line-${record.line}`} 缺可审计 arguments`,
  );
  let args;
  try {
    args = JSON.parse(payload.arguments);
  } catch (error) {
    throw new ControlError(
      'CODEX_ROLLOUT_SHELL_UNVERIFIED',
      `Codex function_call ${payload.call_id || `line-${record.line}`} arguments 非法: ${error.message}`,
    );
  }
  assertControl(
    args && typeof args === 'object' && !Array.isArray(args),
    'CODEX_ROLLOUT_SHELL_UNVERIFIED',
    `Codex function_call ${payload.call_id || `line-${record.line}`} arguments 必须是对象`,
  );
  return args;
}

function codexFunctionOutputs(records) {
  const byCall = new Map();
  for (const record of records) {
    const item = record.value;
    const payload = item && item.payload;
    if (
      !item
      || item.type !== 'response_item'
      || !payload
      || payload.type !== 'function_call_output'
    ) continue;
    const list = byCall.get(payload.call_id) || [];
    list.push(record);
    byCall.set(payload.call_id, list);
  }
  return byCall;
}

function isProvablyReadOnlyExec(args) {
  const command = typeof args.cmd === 'string' ? args.cmd.trim() : '';
  const shell = args.shell;
  return (command === 'pwd' || command === '/bin/pwd')
    && args.login === false
    && ['/bin/sh', '/bin/bash', '/bin/zsh'].includes(shell);
}

function assertSupportedCodexResponseItems(records) {
  const toolSearchCalls = new Map();
  const toolSearchOutputs = new Map();
  for (const record of records) {
    const item = record.value;
    const payload = item && item.payload;
    if (!item || item.type !== 'response_item') continue;
    assertControl(
      payload && typeof payload.type === 'string',
      'CODEX_ROLLOUT_TOOL_UNVERIFIED',
      `Codex response_item 第 ${record.line} 行缺 payload.type`,
    );
    if (payload.type === 'function_call') {
      assertControl(
        CODEX_AUDITED_FUNCTION_CALLS.has(payload.name)
          || CODEX_PROVABLY_NON_SOURCE_FUNCTION_CALLS.has(payload.name),
        'CODEX_ROLLOUT_TOOL_UNVERIFIED',
        `Codex rollout 第 ${record.line} 行含未建模 function_call ${String(payload.name)}；拒绝推断完整 delta`,
      );
      continue;
    }
    if (payload.type === 'custom_tool_call') {
      assertControl(
        payload.name === 'apply_patch' && payload.status === 'completed',
        'CODEX_ROLLOUT_TOOL_UNVERIFIED',
        `Codex rollout 第 ${record.line} 行含未建模或未完成 custom_tool_call ${String(payload.name)}；拒绝推断完整 delta`,
      );
      continue;
    }
    if (payload.type === 'tool_search_call') {
      const callId = safeId(payload.call_id, 'Codex tool_search call_id');
      assertControl(
        payload.status === 'completed' && !toolSearchCalls.has(callId),
        'CODEX_ROLLOUT_TOOL_UNVERIFIED',
        `Codex tool_search ${callId} 未完成或重复`,
      );
      toolSearchCalls.set(callId, record.line);
      continue;
    }
    if (payload.type === 'tool_search_output') {
      const callId = safeId(payload.call_id, 'Codex tool_search output call_id');
      assertControl(
        payload.status === 'completed' && !toolSearchOutputs.has(callId),
        'CODEX_ROLLOUT_TOOL_UNVERIFIED',
        `Codex tool_search output ${callId} 未完成或重复`,
      );
      toolSearchOutputs.set(callId, record.line);
      continue;
    }
    assertControl(
      CODEX_NON_ACTION_RESPONSE_TYPES.has(payload.type),
      'CODEX_ROLLOUT_TOOL_UNVERIFIED',
      `Codex rollout 第 ${record.line} 行含未建模 response_item ${payload.type}；拒绝推断完整 delta`,
    );
  }
  assertControl(
    toolSearchCalls.size === toolSearchOutputs.size
      && [...toolSearchCalls.entries()].every(([callId, line]) => (
        toolSearchOutputs.has(callId) && line < toolSearchOutputs.get(callId)
      )),
    'CODEX_ROLLOUT_TOOL_UNVERIFIED',
    'Codex tool_search call/output 集合不完整或乱序',
  );
}

function collectCodexTargetShellCalls(records) {
  const outputsByCall = codexFunctionOutputs(records);
  const calls = [];
  for (const record of records) {
    const item = record.value;
    const payload = item && item.payload;
    if (
      !item
      || item.type !== 'response_item'
      || !payload
      || payload.type !== 'function_call'
    ) continue;
    const callId = safeId(payload.call_id, `Codex ${payload.name} call_id`);
    const args = parseCodexFunctionArguments(record, payload);
    const outputs = outputsByCall.get(callId) || [];
    assertControl(
      outputs.length === 1 && record.line < outputs[0].line,
      'CODEX_ROLLOUT_SHELL_UNVERIFIED',
      `Codex ${payload.name} ${callId} 缺唯一且有序的 sealed result`,
    );
    const output = outputs[0].value.payload.output;
    const sessions = payload.name === 'exec_command' && typeof output === 'string'
      ? [...output.matchAll(/Process running with session ID ([0-9]+)/g)]
      : [];
    assertControl(
      sessions.length <= 1,
      'CODEX_ROLLOUT_SHELL_UNVERIFIED',
      `Codex ${payload.name} ${callId} 返回多个 terminal session id`,
    );
    const automaticallyVerified = (
      payload.name === 'exec_command'
        ? isProvablyReadOnlyExec(args) && sessions.length === 0
        : CODEX_PROVABLY_NON_SOURCE_FUNCTION_CALLS.has(payload.name)
    );
    calls.push({
      call_id: callId,
      name: payload.name,
      line: record.line,
      record_sha256: `sha256:${sha256(record.raw)}`,
      result_line: outputs[0].line,
      result_record_sha256: `sha256:${sha256(outputs[0].raw)}`,
      automatically_verified: automaticallyVerified,
      raw_records: [record.raw, outputs[0].raw],
    });
  }
  calls.sort((left, right) => left.line - right.line);
  const seen = new Set();
  let previousLine = 0;
  for (const call of calls) {
    assertControl(!seen.has(call.call_id), 'CODEX_ROLLOUT_SHELL_UNVERIFIED', `duplicate shell call_id ${call.call_id}`);
    seen.add(call.call_id);
    assertControl(
      previousLine < call.line && call.line < call.result_line,
      'CODEX_ROLLOUT_SHELL_UNVERIFIED',
      `Codex shell call ${call.call_id} line 顺序非法`,
    );
    previousLine = call.line;
  }
  return calls;
}

function assertShellCallsAutomaticallyVerified(calls) {
  const unverified = calls.find((call) => !call.automatically_verified);
  assertControl(
    !unverified,
    'CODEX_ROLLOUT_SHELL_UNVERIFIED',
    unverified
      ? `Codex rollout 第 ${unverified.line} 行 ${unverified.name} 无法证明只读；拒绝从 patch events 推断完整 delta`
      : 'Codex rollout shell audit 非法',
    unverified ? {
      call_id: unverified.call_id,
      required_witness: '提供绑定 exact rollout/launch/thread/cwd/HEAD/patch 的 --shell-audit-file，并由 active CAPTAIN + FOREMAN 双 capability 授权；audit 必须 exact 覆盖所有 target exec_command/write_stdin calls，且 asserted_untracked_empty=true。',
    } : null,
  );
}

function assertReplayableUnifiedDiff(value, relative) {
  assertControl(
    typeof value === 'string'
      && value.length > 0
      && value.endsWith('\n')
      && !value.includes('\0')
      && Buffer.byteLength(value) <= MAX_SNAPSHOT_BYTES,
    'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
    `Codex rollout ${relative} unified_diff 非法`,
  );
  let hunkCount = 0;
  const hunks = [];
  let currentHunk = null;
  for (const line of value.slice(0, -1).split('\n')) {
    if (line.startsWith('@@ ')) {
      assertControl(
        /^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@(?:.*)?$/.test(line),
        'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
        `Codex rollout ${relative} hunk header 非法`,
      );
      hunkCount += 1;
      currentHunk = { header: line, lines: [] };
      hunks.push(currentHunk);
      continue;
    }
    assertControl(
      hunkCount > 0 && [' ', '+', '-', '\\'].includes(line[0]),
      'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
      `Codex rollout ${relative} 含不可重放 diff 行`,
    );
    currentHunk.lines.push(line);
  }
  assertControl(hunkCount > 0, 'CODEX_ROLLOUT_CHANGE_UNSUPPORTED', `Codex rollout ${relative} 缺 hunk`);
  return hunks;
}

function validateCodexPatchEvent(
  record,
  historicalWorktree,
  expectedPaths,
  expectedChangedLines,
  expectedHunks,
) {
  const event = record.value;
  assertControl(
    event && event.type === 'event_msg' && event.payload && event.payload.type === 'patch_apply_end',
    'CODEX_ROLLOUT_INVALID',
    `第 ${record.line} 行不是 patch_apply_end`,
  );
  const payload = event.payload;
  assertControl(
    payload.success === true && payload.status === 'completed',
    'CODEX_ROLLOUT_INVALID',
    `第 ${record.line} 行 patch_apply_end 未成功完成`,
  );
  const callId = safeId(payload.call_id, 'Codex patch call_id');
  assertControl(
    typeof event.timestamp === 'string' && Number.isFinite(Date.parse(event.timestamp)),
    'CODEX_ROLLOUT_INVALID',
    `第 ${record.line} 行 timestamp 非法`,
  );
  assertControl(
    payload.changes && typeof payload.changes === 'object' && !Array.isArray(payload.changes),
    'CODEX_ROLLOUT_INVALID',
    `第 ${record.line} 行 changes 非法`,
  );
  const changes = Object.entries(payload.changes);
  assertControl(changes.length > 0, 'CODEX_ROLLOUT_INVALID', `第 ${record.line} 行没有 changes`);
  const prefix = `${historicalWorktree}${path.sep}`;
  const actualPaths = new Set();
  const hunkBindings = [];
  let patch = '';
  for (const [absolute, change] of changes) {
    assertControl(
      typeof absolute === 'string' && absolute.startsWith(prefix),
      'HANDOFF_PATH_INVALID',
      `Codex rollout change 不在 predecessor worktree 下: ${absolute}`,
    );
    const relative = safeRelativePath(absolute.slice(prefix.length), 'Codex rollout change path');
    assertControl(!/[\t\r\n ]/.test(relative), 'CODEX_ROLLOUT_PATH_UNSUPPORTED', `Codex rollout path 含空白: ${relative}`);
    assertControl(!actualPaths.has(relative), 'CODEX_ROLLOUT_INVALID', `Codex rollout 重复 change path: ${relative}`);
    actualPaths.add(relative);
    assertControl(
      expectedPaths.has(relative)
        && expectedHunks.has(relative)
        && expectedChangedLines.has(relative),
      'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
      `Codex rollout ${callId} 的 apply_patch input 与 patch_apply_end paths 不一致`,
    );
    exactKeys(change, ['type', 'unified_diff', 'move_path'], `Codex rollout change ${relative}`);
    assertControl(
      change.type === 'update' && change.move_path === null,
      'CODEX_ROLLOUT_CHANGE_UNSUPPORTED',
      `Codex rollout ${relative} change.type=${change.type} move_path=${change.move_path} 不可安全重放`,
    );
    const eventHunks = assertReplayableUnifiedDiff(change.unified_diff, relative);
    const callHunks = expectedHunks.get(relative)
      .filter((hunk) => hunk.lines.some((line) => line.startsWith('+') || line.startsWith('-')));
    const eventChangedLines = change.unified_diff
      .slice(0, -1)
      .split('\n')
      .filter((line) => line.startsWith('+') || line.startsWith('-'));
    assertControl(
      hashObject(eventChangedLines) === hashObject(expectedChangedLines.get(relative)),
      'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
      `Codex rollout ${callId} 的 ${relative} apply_patch input 与 patch_apply_end mutation 不一致`,
    );
    hunkBindings.push({
      relative,
      call_hunks: callHunks,
      event_hunks: eventHunks,
    });
    patch += [
      `diff --git a/${relative} b/${relative}`,
      `--- a/${relative}`,
      `+++ b/${relative}`,
      change.unified_diff,
    ].join('\n');
  }
  assertControl(
    actualPaths.size === expectedPaths.size
      && [...actualPaths].every((relative) => expectedPaths.has(relative)),
    'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
    `Codex rollout ${callId} 的 apply_patch input 与 patch_apply_end paths 不一致`,
  );
  return {
    callId,
    timestamp: event.timestamp,
    changeCount: changes.length,
    patch: Buffer.from(patch, 'utf8'),
    hunkBindings,
  };
}

function validateOutsideCodexPatchEvent(record, historicalWorktree, expectedCallId) {
  const event = record.value;
  const payload = event && event.payload;
  assertControl(
    event
      && event.type === 'event_msg'
      && payload
      && payload.type === 'patch_apply_end'
      && payload.success === true
      && payload.status === 'completed'
      && payload.call_id === expectedCallId
      && payload.changes
      && typeof payload.changes === 'object'
      && !Array.isArray(payload.changes)
      && Object.keys(payload.changes).length > 0,
    'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
    `outside apply_patch ${expectedCallId} event 非法`,
  );
  const prefix = `${historicalWorktree}${path.sep}`;
  assertControl(
    Object.keys(payload.changes).every((candidate) => (
      typeof candidate === 'string' && !candidate.startsWith(prefix)
    )),
    'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
    `outside apply_patch ${expectedCallId} 混入 predecessor worktree change`,
  );
  return {
    timestamp: event.timestamp,
    changeCount: Object.keys(payload.changes).length,
  };
}

function extractCodexRolloutCapture(
  rolloutFile,
  historicalWorktree,
  predecessorThreadId,
  options = {},
) {
  const file = canonicalRegularFile(rolloutFile, 'Codex rollout');
  const stat = fs.statSync(file);
  assertControl(
    stat.size > 0 && stat.size <= MAX_ROLLOUT_BYTES,
    'CODEX_ROLLOUT_TOO_LARGE',
    `Codex rollout 超过 ${MAX_ROLLOUT_BYTES} bytes`,
  );
  const body = fs.readFileSync(file);
  const records = jsonlRecords(body, 'Codex rollout');
  const sessionRecords = records.filter((record) => record.value && record.value.type === 'session_meta');
  const targetSessionRecords = sessionRecords.filter((record) => {
    const payload = record.value && record.value.payload;
    return payload
      && payload.session_id === predecessorThreadId
      && payload.id === predecessorThreadId;
  });
  assertControl(
    targetSessionRecords.length === 1 && targetSessionRecords[0].line === 1,
    'CODEX_ROLLOUT_SESSION_MISMATCH',
    'Codex rollout 第 1 行必须且只能精确匹配 lost predecessor session_meta',
  );
  for (const record of sessionRecords) {
    const payload = record.value && record.value.payload;
    assertControl(
      payload
        && typeof payload.session_id === 'string'
        && payload.id === payload.session_id
        && typeof payload.cwd === 'string',
      'CODEX_ROLLOUT_SESSION_MISMATCH',
      `Codex rollout 第 ${record.line} 行 session_meta identity 非法`,
    );
    assertHistoricalDirectoryValue(payload.cwd, `Codex rollout 第 ${record.line} 行 session_meta cwd`);
  }
  const sessionRecord = targetSessionRecords[0];
  const meta = sessionRecord.value.payload;
  assertControl(
    meta
      && meta.session_id === predecessorThreadId
      && meta.id === predecessorThreadId
      && meta.cwd === historicalWorktree,
    'CODEX_ROLLOUT_SESSION_MISMATCH',
    'Codex rollout session_meta 未精确绑定 lost predecessor thread/cwd',
  );
  assertSupportedCodexResponseItems(records);
  const shellCalls = collectCodexTargetShellCalls(records);

  const outputsByCall = new Map();
  for (const record of records) {
    const payload = record.value && record.value.payload;
    if (!record.value || record.value.type !== 'response_item' || !payload || payload.type !== 'custom_tool_call_output') continue;
    const list = outputsByCall.get(payload.call_id) || [];
    list.push(record);
    outputsByCall.set(payload.call_id, list);
  }
  const allPatchCalls = new Map();
  const targetPatchCalls = new Map();
  for (const record of records) {
    const payload = record.value && record.value.payload;
    if (
      !record.value
      || record.value.type !== 'response_item'
      || !payload
      || payload.type !== 'custom_tool_call'
      || payload.name !== 'apply_patch'
      || payload.status !== 'completed'
    ) continue;
    const paths = applyPatchInputPaths(payload.input, historicalWorktree);
    const hasFileDirective = typeof payload.input === 'string'
      && /^\*\*\* (?:Add|Update|Delete) File: /m.test(payload.input);
    if (paths.size === 0 && !hasFileDirective) continue;
    const outputs = outputsByCall.get(payload.call_id) || [];
    assertControl(outputs.length === 1, 'CODEX_ROLLOUT_PATCH_EVENT_MISSING', `apply_patch ${payload.call_id} 缺唯一结果记录`);
    const callId = safeId(payload.call_id, 'Codex patch call_id');
    const resultSucceeded = codexPatchResultSucceeded(outputs[0], callId);
    if (paths.size > 0) validateCodexPatchResult(outputs[0], callId);
    assertControl(!allPatchCalls.has(callId), 'CODEX_ROLLOUT_INVALID', `duplicate apply_patch call_id ${callId}`);
    const call = {
      record,
      output: outputs[0],
      paths,
      target: paths.size > 0,
      resultSucceeded,
    };
    allPatchCalls.set(callId, call);
    if (call.target) {
      const validatedCall = validateCodexPatchCall(record, historicalWorktree);
      call.paths = validatedCall.paths;
      call.changedLines = validatedCall.changedLines;
      call.hunks = validatedCall.hunks;
      targetPatchCalls.set(callId, call);
    }
  }

  const eventRecords = records.filter((record) => (
    record.value
      && record.value.type === 'event_msg'
      && record.value.payload
      && record.value.payload.type === 'patch_apply_end'
      && record.value.payload.success === true
  ));
  assertControl(eventRecords.length > 0, 'CODEX_ROLLOUT_NO_PATCHES', 'Codex rollout 没有成功 patch_apply_end');
  const seenEvents = new Set();
  const seenTargetEvents = new Set();
  const capturedEvents = [];
  const excludedPatches = [];
  const callOperations = [];
  const patchParts = [];
  for (const record of eventRecords) {
    const callId = safeId(record.value.payload.call_id, 'Codex patch call_id');
    assertControl(!seenEvents.has(callId), 'CODEX_ROLLOUT_INVALID', `duplicate patch_apply_end call_id ${callId}`);
    seenEvents.add(callId);
    const call = allPatchCalls.get(callId);
    assertControl(call, 'CODEX_ROLLOUT_PATCH_EVENT_MISSING', `patch_apply_end ${callId} 缺成功 apply_patch call`);
    assertControl(
      call.record.line < record.line && record.line < call.output.line,
      'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
      `Codex rollout ${callId} 必须严格按 call -> patch_apply_end -> result 排列`,
    );
    if (!call.target) {
      validateCodexPatchResult(call.output, callId);
      const excluded = validateOutsideCodexPatchEvent(record, historicalWorktree, callId);
      excludedPatches.push({
        call_id: callId,
        call_line: call.record.line,
        call_record_sha256: `sha256:${sha256(call.record.raw)}`,
        event_line: record.line,
        event_timestamp: excluded.timestamp,
        event_record_sha256: `sha256:${sha256(record.raw)}`,
        result_line: call.output.line,
        result_record_sha256: `sha256:${sha256(call.output.raw)}`,
        change_count: excluded.changeCount,
        raw_records: [call.record.raw, record.raw, call.output.raw],
      });
      continue;
    }
    seenTargetEvents.add(callId);
    const validated = validateCodexPatchEvent(
      record,
      historicalWorktree,
      call.paths,
      call.changedLines,
      call.hunks,
    );
    callOperations.push({ call_id: callId, hunks: call.hunks });
    patchParts.push(validated.patch);
    capturedEvents.push({
      call_id: callId,
      call_line: call.record.line,
      call_record_sha256: `sha256:${sha256(call.record.raw)}`,
      event_line: record.line,
      event_timestamp: validated.timestamp,
      event_record_sha256: `sha256:${sha256(record.raw)}`,
      result_line: call.output.line,
      result_record_sha256: `sha256:${sha256(call.output.raw)}`,
      change_count: validated.changeCount,
      raw_records: [call.record.raw, record.raw, call.output.raw],
    });
  }
  const missing = [...targetPatchCalls.keys()].filter((callId) => !seenTargetEvents.has(callId));
  assertControl(missing.length === 0, 'CODEX_ROLLOUT_PATCH_EVENT_MISSING', `缺 patch_apply_end: ${missing.join(', ')}`);
  for (const [callId, call] of allPatchCalls.entries()) {
    if (call.target || seenEvents.has(callId)) continue;
    shellCalls.push({
      call_id: callId,
      name: 'apply_patch',
      line: call.record.line,
      record_sha256: `sha256:${sha256(call.record.raw)}`,
      result_line: call.output.line,
      result_record_sha256: `sha256:${sha256(call.output.raw)}`,
      automatically_verified: false,
      required_disposition: 'IGNORED_PATH_ONLY',
      raw_records: [call.record.raw, call.output.raw],
    });
  }
  shellCalls.sort((left, right) => left.line - right.line);
  if (!options.allowShellAudit) assertShellCallsAutomaticallyVerified(shellCalls);
  assertControl(capturedEvents.length > 0, 'CODEX_ROLLOUT_NO_PATCHES', 'Codex rollout 没有 predecessor worktree patch_apply_end');
  const patch = Buffer.concat(patchParts);
  assertControl(patch.length <= MAX_SNAPSHOT_BYTES, 'HANDOFF_SNAPSHOT_TOO_LARGE', `Codex rollout patch 超过 ${MAX_SNAPSHOT_BYTES} bytes`);
  const provenance = Buffer.concat([
    sessionRecord.raw,
    Buffer.from('\n'),
    ...capturedEvents.flatMap((event) => (
      event.raw_records.flatMap((raw) => [raw, Buffer.from('\n')])
    )),
    ...excludedPatches.flatMap((event) => (
      event.raw_records.flatMap((raw) => [raw, Buffer.from('\n')])
    )),
  ]);
  assertControl(
    provenance.length <= MAX_ROLLOUT_BYTES,
    'CODEX_ROLLOUT_TOO_LARGE',
    `sealed Codex rollout provenance 超过 ${MAX_ROLLOUT_BYTES} bytes`,
  );
  const lastTimestampRecord = [...records].reverse().find((record) => (
    record.value
      && typeof record.value.timestamp === 'string'
      && Number.isFinite(Date.parse(record.value.timestamp))
  ));
  assertControl(lastTimestampRecord, 'CODEX_ROLLOUT_INVALID', 'Codex rollout 缺有效 timestamp');
  return {
    file,
    rolloutSha256: `sha256:${sha256(body)}`,
    sessionRecord,
    patch,
    provenance,
    events: capturedEvents.map(({ raw_records: _rawRecords, ...event }) => event),
    excludedPatches: excludedPatches.map(({ raw_records: _rawRecords, ...event }) => event),
    shellCalls,
    callOperations,
    observedAt: lastTimestampRecord.value.timestamp,
  };
}

function inspectCodexRolloutPatchEvents(rolloutFile, options) {
  const historicalWorktree = assertHistoricalDirectoryValue(
    options.historicalWorktree,
    'predecessor historical worktree',
  );
  const predecessorThreadId = safeId(options.predecessorThreadId, 'predecessor_thread_id');
  const capture = extractCodexRolloutCapture(
    rolloutFile,
    historicalWorktree,
    predecessorThreadId,
    { allowShellAudit: options.allowShellAudit === true },
  );
  let exactTree = null;
  const hasRepositoryBinding = options.repositoryWorktree !== undefined
    || options.predecessorHead !== undefined;
  if (hasRepositoryBinding) {
    assertControl(
      options.repositoryWorktree !== undefined && options.predecessorHead !== undefined,
      'CODEX_ROLLOUT_PATCH_EVENT_MISMATCH',
      'repositoryWorktree 与 predecessorHead 必须同时提供',
    );
    const worktree = canonicalDirectory(options.repositoryWorktree, 'Codex rollout inspection worktree');
    const baseHead = assertFullSha(options.predecessorHead, 'Codex rollout predecessor HEAD');
    gitRun(worktree, ['cat-file', '-e', `${baseHead}^{commit}`], {
      code: 'HANDOFF_BASE_MISMATCH',
      label: 'Codex rollout predecessor HEAD',
    });
    exactTree = assertCodexCaptureTree(worktree, baseHead, capture);
  }
  return {
    rollout_file: capture.file,
    rollout_file_sha256: capture.rolloutSha256,
    predecessor_thread_id: predecessorThreadId,
    historical_worktree: historicalWorktree,
    session_record_sha256: `sha256:${sha256(capture.sessionRecord.raw)}`,
    event_count: capture.events.length,
    events: capture.events,
    excluded_patch_count: capture.excludedPatches.length,
    excluded_patches: capture.excludedPatches,
    tracked_patch_bytes: capture.patch.length,
    tracked_patch_sha256: `sha256:${sha256(capture.patch)}`,
    provenance_bytes: capture.provenance.length,
    provenance_sha256: `sha256:${sha256(capture.provenance)}`,
    shell_audit_required: capture.shellCalls.some((call) => !call.automatically_verified),
    shell_call_count: capture.shellCalls.length,
    shell_calls: capture.shellCalls.map(({ raw_records: _rawRecords, ...call }) => call),
    ...(exactTree ? {
      expected_tree: exactTree.tree,
      expected_paths: exactTree.paths,
    } : {}),
  };
}

function buildCodexShellAudit(options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const predecessorLaunchId = safeId(options.predecessorLaunchId, 'predecessor_launch_id');
  const predecessorThreadId = safeId(options.predecessorThreadId, 'predecessor_thread_id');
  const captainThreadId = safeId(options.captainThreadId, 'captain_thread_id');
  const foremanThreadId = safeId(options.foremanThreadId, 'foreman_thread_id');
  const historicalWorktree = assertHistoricalDirectoryValue(
    options.historicalWorktree,
    'predecessor historical worktree',
  );
  const predecessorHead = assertFullSha(options.predecessorHead, 'predecessor_head');
  assertControl(
    typeof options.incidentRef === 'string'
      && options.incidentRef.length > 0
      && options.incidentRef.length <= 500
      && !/[\u0000-\u001f\u007f]/.test(options.incidentRef),
    'CODEX_ROLLOUT_SHELL_AUDIT_INVALID',
    'incident_ref 非法',
  );
  const dispositionsFile = canonicalRegularFile(options.dispositionsFile, 'Codex shell audit dispositions');
  const dispositionsBody = fs.readFileSync(dispositionsFile);
  assertControl(
    dispositionsBody.length > 0 && dispositionsBody.length <= MAX_ROLLOUT_BYTES,
    'CODEX_ROLLOUT_SHELL_AUDIT_INVALID',
    'Codex shell audit dispositions 为空或过大',
  );
  let dispositions;
  try {
    dispositions = JSON.parse(dispositionsBody.toString('utf8'));
  } catch (error) {
    throw new ControlError('CODEX_ROLLOUT_SHELL_AUDIT_INVALID', `dispositions 不是合法 JSON: ${error.message}`);
  }
  exactKeys(dispositions, ['asserted_untracked_empty', 'calls'], 'Codex shell audit dispositions');
  assertControl(
    dispositions.asserted_untracked_empty === true && Array.isArray(dispositions.calls),
    'CODEX_ROLLOUT_SHELL_AUDIT_INVALID',
    'dispositions 必须 asserted_untracked_empty=true 且 calls 为数组',
  );
  const capture = extractCodexRolloutCapture(
    options.rolloutFile,
    historicalWorktree,
    predecessorThreadId,
    { allowShellAudit: true },
  );
  assertControl(
    dispositions.calls.length === capture.shellCalls.length,
    'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
    'dispositions calls 数量与 rollout exact set 不匹配',
  );
  const calls = dispositions.calls.map((input, index) => {
    exactKeys(input, ['call_id', 'disposition'], 'Codex shell audit disposition');
    safeId(input.call_id, 'Codex shell audit disposition call_id');
    assertControl(
      input.call_id === capture.shellCalls[index].call_id,
      'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
      `dispositions call[${index}] 缺失、乱序或多余`,
    );
    assertControl(
      SHELL_AUDIT_DISPOSITIONS.includes(input.disposition)
        && (
          capture.shellCalls[index].required_disposition === undefined
          || input.disposition === capture.shellCalls[index].required_disposition
        ),
      'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
      `dispositions call[${index}] disposition 非法`,
    );
    const actual = capture.shellCalls[index];
    return {
      call_id: actual.call_id,
      name: actual.name,
      line: actual.line,
      record_sha256: actual.record_sha256,
      result_line: actual.result_line,
      result_record_sha256: actual.result_record_sha256,
      disposition: input.disposition,
    };
  });
  const unsigned = {
    schema_version: 1,
    kind: CODEX_SHELL_AUDIT_KIND,
    goal_id: goalId,
    task_id: taskId,
    predecessor_launch_id: predecessorLaunchId,
    predecessor_thread_id: predecessorThreadId,
    predecessor_cwd: historicalWorktree,
    predecessor_head: predecessorHead,
    rollout_file_sha256: capture.rolloutSha256,
    reconstructed_patch_sha256: `sha256:${sha256(capture.patch)}`,
    asserted_untracked_empty: true,
    incident_ref: options.incidentRef,
    captain_thread_id: captainThreadId,
    foreman_thread_id: foremanThreadId,
    calls,
    created_at: capture.observedAt,
  };
  const audit = { ...unsigned, audit_sha256: hashObject(unsigned) };
  validateShellAuditObject(audit, {
    goal_id: goalId,
    task_id: taskId,
    predecessor_launch_id: predecessorLaunchId,
    predecessor_thread_id: predecessorThreadId,
    predecessor_cwd: historicalWorktree,
    predecessor_head: predecessorHead,
    rollout_file_sha256: capture.rolloutSha256,
    reconstructed_patch_sha256: unsigned.reconstructed_patch_sha256,
    captain_thread_id: captainThreadId,
    foreman_thread_id: foremanThreadId,
  }, capture.shellCalls);
  return audit;
}

function codexShellAuditBytes(audit) {
  return Buffer.from(`${JSON.stringify(audit, null, 2)}\n`, 'utf8');
}

function auditOutputPath(candidate) {
  assertControl(
    typeof candidate === 'string'
      && path.isAbsolute(candidate)
      && path.normalize(candidate) === candidate
      && !candidate.includes('\0')
      && !/[\u0000-\u001f\u007f]/.test(candidate),
    'AUDIT_OUTPUT_INVALID',
    '--output-file 必须是规范绝对路径',
  );
  const parent = path.dirname(candidate);
  let parentStat;
  let canonicalParent;
  try {
    parentStat = fs.lstatSync(parent);
    canonicalParent = fs.realpathSync(parent);
  } catch (error) {
    throw new ControlError('AUDIT_OUTPUT_INVALID', `--output-file parent 不存在或无法读取: ${error.message}`);
  }
  assertControl(
    parentStat.isDirectory()
      && !parentStat.isSymbolicLink()
      && canonicalParent === parent,
    'AUDIT_OUTPUT_INVALID',
    '--output-file parent 必须是 canonical 非 symlink 目录',
  );
  return candidate;
}

function existingAuditOutputMatches(file, expected) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw new ControlError('AUDIT_OUTPUT_INVALID', `无法检查 --output-file: ${error.message}`);
  }
  assertControl(
    stat.isFile() && !stat.isSymbolicLink(),
    'AUDIT_OUTPUT_INVALID',
    '--output-file 已存在时必须是非 symlink 普通文件',
  );
  let actual;
  try {
    actual = fs.readFileSync(file);
  } catch (error) {
    throw new ControlError('AUDIT_OUTPUT_INVALID', `无法读取现有 --output-file: ${error.message}`);
  }
  assertControl(
    actual.equals(expected),
    'AUDIT_OUTPUT_CONFLICT',
    '--output-file 已存在且 bytes 与当前 audit 不同，拒绝覆盖',
  );
  return true;
}

function fsyncDirectory(directory) {
  let fd;
  try {
    fd = fs.openSync(directory, 'r');
    fs.fsyncSync(fd);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code)) throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function writeCodexShellAuditOutput(audit, candidate) {
  const outputFile = auditOutputPath(candidate);
  const body = codexShellAuditBytes(audit);
  if (existingAuditOutputMatches(outputFile, body)) {
    return {
      output_file: outputFile,
      audit_sha256: audit.audit_sha256,
      call_count: audit.calls.length,
    };
  }
  const parent = path.dirname(outputFile);
  const temporary = path.join(
    parent,
    `.${path.basename(outputFile)}.${process.pid}.${randomId('audit-output')}.tmp`,
  );
  let fd;
  try {
    fd = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(fd, body);
    fs.fsyncSync(fd);
  } catch (error) {
    try {
      fs.unlinkSync(temporary);
    } catch {
      // The primary write error is more useful; a later invocation uses a
      // fresh random temp name and never treats a temp file as an artifact.
    }
    throw new ControlError('AUDIT_OUTPUT_WRITE_FAILED', `无法写入 audit 临时文件: ${error.message}`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  try {
    try {
      // rename(2) may replace a racing destination. An exclusive hard-link
      // installs the completed same-filesystem temp inode atomically without
      // ever overwriting an existing audit artifact.
      fs.linkSync(temporary, outputFile);
      fsyncDirectory(parent);
    } catch (error) {
      if (error.code !== 'EEXIST') {
        throw new ControlError('AUDIT_OUTPUT_WRITE_FAILED', `无法原子创建 --output-file: ${error.message}`);
      }
      assertControl(
        existingAuditOutputMatches(outputFile, body),
        'AUDIT_OUTPUT_WRITE_FAILED',
        '--output-file 在并发创建后消失',
      );
    }
  } finally {
    try {
      fs.unlinkSync(temporary);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw new ControlError('AUDIT_OUTPUT_WRITE_FAILED', `无法清理 audit 临时文件: ${error.message}`);
      }
    }
  }
  return {
    output_file: outputFile,
    audit_sha256: audit.audit_sha256,
    call_count: audit.calls.length,
  };
}

function validateShellAuditObject(audit, expected, shellCalls) {
  exactKeys(
    audit,
    [
      'schema_version', 'kind', 'goal_id', 'task_id',
      'predecessor_launch_id', 'predecessor_thread_id', 'predecessor_cwd',
      'predecessor_head', 'rollout_file_sha256', 'reconstructed_patch_sha256',
      'asserted_untracked_empty', 'incident_ref',
      'captain_thread_id', 'foreman_thread_id', 'calls',
      'created_at', 'audit_sha256',
    ],
    'Codex shell audit',
  );
  assertControl(
    audit.schema_version === 1 && audit.kind === CODEX_SHELL_AUDIT_KIND,
    'CODEX_ROLLOUT_SHELL_AUDIT_INVALID',
    'Codex shell audit schema/kind 非法',
  );
  for (const key of [
    'goal_id', 'task_id', 'predecessor_launch_id', 'predecessor_thread_id',
    'captain_thread_id', 'foreman_thread_id',
  ]) safeId(audit[key], `Codex shell audit ${key}`);
  assertHistoricalDirectoryValue(audit.predecessor_cwd, 'Codex shell audit predecessor_cwd');
  assertFullSha(audit.predecessor_head, 'Codex shell audit predecessor_head');
  normalizeHash(audit.rollout_file_sha256, 'Codex shell audit rollout_file_sha256');
  normalizeHash(audit.reconstructed_patch_sha256, 'Codex shell audit reconstructed_patch_sha256');
  assertControl(audit.asserted_untracked_empty === true, 'CODEX_ROLLOUT_SHELL_AUDIT_INVALID', 'Codex shell audit 必须 asserted_untracked_empty=true');
  assertControl(
    typeof audit.incident_ref === 'string'
      && audit.incident_ref.length > 0
      && audit.incident_ref.length <= 500
      && !/[\u0000-\u001f\u007f]/.test(audit.incident_ref),
    'CODEX_ROLLOUT_SHELL_AUDIT_INVALID',
    'Codex shell audit incident_ref 非法',
  );
  assertControl(
    typeof audit.created_at === 'string' && Number.isFinite(Date.parse(audit.created_at)),
    'CODEX_ROLLOUT_SHELL_AUDIT_INVALID',
    'Codex shell audit created_at 非法',
  );
  for (const [key, value] of Object.entries(expected)) {
    assertControl(
      audit[key] === value,
      'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
      `Codex shell audit ${key} 不匹配`,
    );
  }
  assertControl(
    Array.isArray(audit.calls) && audit.calls.length === shellCalls.length,
    'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
    'Codex shell audit calls 集合数量不匹配',
  );
  const seen = new Set();
  let previousLine = 0;
  for (let index = 0; index < shellCalls.length; index += 1) {
    const actual = shellCalls[index];
    const asserted = audit.calls[index];
    exactKeys(
      asserted,
      [
        'call_id', 'name', 'line', 'record_sha256',
        'result_line', 'result_record_sha256', 'disposition',
      ],
      'Codex shell audit call',
    );
    safeId(asserted.call_id, 'Codex shell audit call_id');
    assertControl(!seen.has(asserted.call_id), 'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH', `duplicate audited call_id ${asserted.call_id}`);
    seen.add(asserted.call_id);
    assertControl(
      Number.isSafeInteger(asserted.line)
        && Number.isSafeInteger(asserted.result_line)
        && previousLine < asserted.line
        && asserted.line < asserted.result_line,
      'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
      `Codex shell audit call[${index}] line 顺序非法`,
    );
    previousLine = asserted.line;
    normalizeHash(asserted.record_sha256, `Codex shell audit call[${index}] record_sha256`);
    normalizeHash(asserted.result_record_sha256, `Codex shell audit call[${index}] result_record_sha256`);
    assertControl(
      SHELL_AUDIT_DISPOSITIONS.includes(asserted.disposition)
        && (actual.required_disposition === undefined || asserted.disposition === actual.required_disposition)
        && asserted.call_id === actual.call_id
        && asserted.name === actual.name
        && asserted.line === actual.line
        && asserted.record_sha256 === actual.record_sha256
        && asserted.result_line === actual.result_line
        && asserted.result_record_sha256 === actual.result_record_sha256,
      'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
      `Codex shell audit call[${index}] 未 exact 覆盖 rollout`,
    );
  }
  const unsigned = { ...audit };
  delete unsigned.audit_sha256;
  assertControl(
    hashObject(unsigned) === normalizeHash(audit.audit_sha256, 'Codex shell audit audit_sha256'),
    'CODEX_ROLLOUT_SHELL_AUDIT_TAMPERED',
    'Codex shell audit hash 不匹配',
  );
  const records = Buffer.concat(shellCalls.flatMap((call) => (
    call.raw_records.flatMap((raw) => [raw, Buffer.from('\n')])
  )));
  return { audit, records };
}

function validateShellAuditFile(fileValue, expected, shellCalls) {
  const file = canonicalRegularFile(fileValue, 'Codex shell audit');
  const body = fs.readFileSync(file);
  assertControl(
    body.length > 0 && body.length <= MAX_ROLLOUT_BYTES,
    'CODEX_ROLLOUT_SHELL_AUDIT_INVALID',
    `Codex shell audit 超过 ${MAX_ROLLOUT_BYTES} bytes 或为空`,
  );
  let audit;
  try {
    audit = JSON.parse(body.toString('utf8'));
  } catch (error) {
    throw new ControlError('CODEX_ROLLOUT_SHELL_AUDIT_INVALID', `Codex shell audit 不是合法 JSON: ${error.message}`);
  }
  const validated = validateShellAuditObject(audit, expected, shellCalls);
  return { file, body, ...validated };
}

function validateSealedInputFile(raw, label) {
  exactKeys(raw, ['path', 'sha256'], label);
  assertHistoricalAbsolutePath(raw.path, `${label} path`);
  normalizeHash(raw.sha256, `${label} sha256`);
  return raw;
}

function validateExportOperationRequest(raw, snapshot) {
  assertControl(raw && typeof raw === 'object' && !Array.isArray(raw), 'HANDOFF_ARTIFACT_INVALID', 'snapshot operation_request 必须是对象');
  const commonKeys = ['kind', 'repository_worktree', 'successor_thread_id'];
  if (raw.kind === 'SOURCE_WORKTREE') {
    exactKeys(raw, commonKeys, 'source export operation_request');
    assertHistoricalDirectoryValue(raw.repository_worktree, 'source export requested worktree');
    safeId(raw.successor_thread_id, 'source export requested successor_thread_id');
    assertControl(
      snapshot.source_capture === undefined
        && raw.repository_worktree === snapshot.source_worktree
        && raw.successor_thread_id === snapshot.successor_thread_id,
      'HANDOFF_ARTIFACT_INVALID',
      'source export operation_request 未绑定 snapshot source/successor',
    );
    return raw;
  }
  assertControl(raw.kind === 'CODEX_ROLLOUT', 'HANDOFF_ARTIFACT_INVALID', `snapshot operation kind 非法: ${String(raw.kind)}`);
  exactKeys(
    raw,
    [
      ...commonKeys,
      'predecessor_launch_id', 'predecessor_thread_id',
      'rollout_file', 'shell_audit_file',
    ],
    'Codex export operation_request',
  );
  assertHistoricalDirectoryValue(raw.repository_worktree, 'Codex export requested broker worktree');
  safeId(raw.successor_thread_id, 'Codex export requested successor_thread_id');
  safeId(raw.predecessor_launch_id, 'Codex export requested predecessor_launch_id');
  safeId(raw.predecessor_thread_id, 'Codex export requested predecessor_thread_id');
  validateSealedInputFile(raw.rollout_file, 'Codex export rollout_file');
  if (raw.shell_audit_file !== null) validateSealedInputFile(raw.shell_audit_file, 'Codex export shell_audit_file');
  assertControl(
    snapshot.source_capture !== undefined
      && raw.successor_thread_id === snapshot.successor_thread_id
      && raw.predecessor_launch_id === snapshot.predecessor_launch_id
      && raw.predecessor_thread_id === snapshot.source_capture.session_id
      && raw.rollout_file.sha256 === snapshot.source_capture.rollout_file_sha256
      && (
        raw.shell_audit_file === null
          ? snapshot.source_capture.shell_audit === undefined
          : (
            snapshot.source_capture.shell_audit !== undefined
              && raw.shell_audit_file.sha256
                === snapshot.source_capture.shell_audit.audit_sha256
          )
      ),
    'HANDOFF_ARTIFACT_INVALID',
    'Codex export operation_request 未绑定 snapshot capture/authority',
  );
  return raw;
}

function validateSnapshot(raw, expected = {}) {
  const keys = [
    'schema_version', 'snapshot_id', 'goal_id', 'task_id', 'successor_thread_id',
    'control_epoch', 'packet_revision', 'packet_sha256', 'task_full_head',
    'predecessor_launch_id', 'predecessor_launch_sha256',
    'source_worktree', 'source_branch', 'source_launch_head', 'source_observed_head',
    'repository_root', 'common_git_dir', 'tracked_patch', 'untracked',
    'source_capture', 'expected_tree', 'expected_paths',
    'operation_request', 'acceptance_authority',
    'total_bytes', 'created_at', 'snapshot_sha256',
  ];
  exactKeys(raw, keys, 'recovery snapshot');
  assertControl(
    [
      LEGACY_SNAPSHOT_SCHEMA_VERSION,
      EXACT_TREE_SNAPSHOT_SCHEMA_VERSION,
      SNAPSHOT_SCHEMA_VERSION,
    ].includes(raw.schema_version),
    'HANDOFF_ARTIFACT_INVALID',
    'snapshot schema_version 非法',
  );
  safeId(raw.snapshot_id, 'snapshot_id');
  safeId(raw.goal_id, 'snapshot goal_id');
  safeId(raw.task_id, 'snapshot task_id');
  safeId(raw.successor_thread_id, 'snapshot successor_thread_id');
  safeId(raw.predecessor_launch_id, 'snapshot predecessor_launch_id');
  assertFullSha(raw.task_full_head, 'snapshot task_full_head');
  assertFullSha(raw.source_launch_head, 'snapshot source_launch_head');
  assertFullSha(raw.source_observed_head, 'snapshot source_observed_head');
  if (
    raw.schema_version === EXACT_TREE_SNAPSHOT_SCHEMA_VERSION
    || raw.schema_version === SNAPSHOT_SCHEMA_VERSION
  ) {
    assertFullSha(raw.expected_tree, 'snapshot expected_tree');
    assertControl(Array.isArray(raw.expected_paths), 'HANDOFF_ARTIFACT_INVALID', 'snapshot expected_paths 非法');
    const expectedPaths = canonicalChangedPaths(raw.expected_paths, 'snapshot expected path');
    assertSameChangedPaths(
      raw.expected_paths,
      expectedPaths,
      'HANDOFF_ARTIFACT_INVALID',
      'snapshot expected_paths canonical order',
    );
  } else {
    assertControl(
      raw.expected_tree === undefined && raw.expected_paths === undefined,
      'HANDOFF_ARTIFACT_INVALID',
      'legacy snapshot 禁止携带 v2 exact-tree 字段',
    );
  }
  if (raw.schema_version === SNAPSHOT_SCHEMA_VERSION) {
    exactKeys(raw.acceptance_authority, ['captain', 'foreman'], 'snapshot acceptance_authority');
    validateAcceptanceAuthority(raw.acceptance_authority.captain, 'CAPTAIN');
    if (raw.acceptance_authority.foreman !== undefined) {
      validateAcceptanceAuthority(raw.acceptance_authority.foreman, 'FOREMAN');
    }
    validateExportOperationRequest(raw.operation_request, raw);
  } else {
    assertControl(
      raw.operation_request === undefined && raw.acceptance_authority === undefined,
      'HANDOFF_ARTIFACT_INVALID',
      'pre-v3 snapshot 禁止携带 operation/acceptance authority',
    );
  }
  assertHistoricalDirectoryValue(raw.source_worktree, 'snapshot source_worktree');
  assertCanonicalDirectoryValue(raw.repository_root, 'snapshot repository_root');
  assertCanonicalDirectoryValue(raw.common_git_dir, 'snapshot common_git_dir');
  assertControl(
    typeof raw.source_branch === 'string'
      && raw.source_branch.length > 0
      && raw.source_branch.length <= 300
      && !/[\u0000-\u0020\u007f]/.test(raw.source_branch),
    'HANDOFF_ARTIFACT_INVALID',
    'snapshot source_branch 非法',
  );
  normalizeHash(raw.packet_sha256, 'snapshot packet_sha256');
  normalizeHash(raw.predecessor_launch_sha256, 'snapshot predecessor_launch_sha256');
  assertControl(Number.isSafeInteger(raw.control_epoch) && raw.control_epoch >= 0, 'HANDOFF_ARTIFACT_INVALID', 'snapshot control_epoch 非法');
  assertControl(Number.isSafeInteger(raw.packet_revision) && raw.packet_revision > 0, 'HANDOFF_ARTIFACT_INVALID', 'snapshot packet_revision 非法');
  assertControl(Number.isSafeInteger(raw.total_bytes) && raw.total_bytes >= 0 && raw.total_bytes <= MAX_SNAPSHOT_BYTES, 'HANDOFF_SNAPSHOT_TOO_LARGE', 'snapshot total_bytes 非法');
  assertControl(typeof raw.created_at === 'string' && Number.isFinite(Date.parse(raw.created_at)), 'HANDOFF_ARTIFACT_INVALID', 'snapshot created_at 非法');
  exactKeys(raw.tracked_patch, ['file', 'size', 'sha256'], 'snapshot tracked_patch');
  safeRelativePath(raw.tracked_patch.file, 'tracked patch artifact path');
  assertControl(Number.isSafeInteger(raw.tracked_patch.size) && raw.tracked_patch.size >= 0, 'HANDOFF_ARTIFACT_INVALID', 'tracked patch size 非法');
  normalizeHash(raw.tracked_patch.sha256, 'tracked patch sha256');
  assertControl(Array.isArray(raw.untracked) && raw.untracked.length <= MAX_UNTRACKED_ENTRIES, 'HANDOFF_ARTIFACT_INVALID', 'snapshot untracked 非法');
  let bytes = raw.tracked_patch.size;
  const seenPaths = new Set();
  const seenArtifacts = new Set([raw.tracked_patch.file]);
  if (raw.source_capture !== undefined) {
    exactKeys(
      raw.source_capture,
      [
        'kind', 'artifact', 'size', 'sha256', 'rollout_file_sha256',
        'session_id', 'session_cwd', 'session_line', 'session_record_sha256',
        'event_count', 'events', 'excluded_patch_count', 'excluded_patches',
        'shell_audit',
      ],
      'snapshot source_capture',
    );
    assertControl(
      raw.source_capture.kind === CODEX_ROLLOUT_CAPTURE_KIND,
      'HANDOFF_ARTIFACT_INVALID',
      `source_capture kind 非法: ${raw.source_capture.kind}`,
    );
    safeRelativePath(raw.source_capture.artifact, 'source_capture artifact');
    assertControl(
      !seenArtifacts.has(raw.source_capture.artifact),
      'HANDOFF_ARTIFACT_INVALID',
      'source_capture artifact 与 tracked patch 冲突',
    );
    seenArtifacts.add(raw.source_capture.artifact);
    assertControl(
      Number.isSafeInteger(raw.source_capture.size)
        && raw.source_capture.size > 0
        && raw.source_capture.size <= MAX_ROLLOUT_BYTES,
      'HANDOFF_ARTIFACT_INVALID',
      'source_capture size 非法',
    );
    normalizeHash(raw.source_capture.sha256, 'source_capture sha256');
    normalizeHash(raw.source_capture.rollout_file_sha256, 'source_capture rollout_file_sha256');
    safeId(raw.source_capture.session_id, 'source_capture session_id');
    assertHistoricalDirectoryValue(raw.source_capture.session_cwd, 'source_capture session_cwd');
    assertControl(
      raw.source_capture.session_cwd === raw.source_worktree,
      'HANDOFF_ARTIFACT_INVALID',
      'source_capture session_cwd 与 source_worktree 不一致',
    );
    assertControl(raw.source_capture.session_line === 1, 'HANDOFF_ARTIFACT_INVALID', 'source_capture session_line 必须为 1');
    normalizeHash(raw.source_capture.session_record_sha256, 'source_capture session_record_sha256');
    assertControl(
      Number.isSafeInteger(raw.source_capture.event_count)
        && raw.source_capture.event_count > 0
        && raw.source_capture.event_count <= MAX_UNTRACKED_ENTRIES,
      'HANDOFF_ARTIFACT_INVALID',
      'source_capture event_count 非法',
    );
    assertControl(
      Array.isArray(raw.source_capture.events)
        && raw.source_capture.events.length === raw.source_capture.event_count,
      'HANDOFF_ARTIFACT_INVALID',
      'source_capture events 数量不匹配',
    );
    const seenCalls = new Set();
    let previousLine = 0;
    for (const event of raw.source_capture.events) {
      exactKeys(
        event,
        [
          'call_id', 'call_line', 'call_record_sha256',
          'event_line', 'event_timestamp', 'event_record_sha256',
          'result_line', 'result_record_sha256', 'change_count',
        ],
        'source_capture event',
      );
      safeId(event.call_id, 'source_capture call_id');
      assertControl(!seenCalls.has(event.call_id), 'HANDOFF_ARTIFACT_INVALID', `duplicate source_capture call_id ${event.call_id}`);
      seenCalls.add(event.call_id);
      assertControl(
        Number.isSafeInteger(event.call_line)
          && Number.isSafeInteger(event.event_line)
          && Number.isSafeInteger(event.result_line)
          && previousLine < event.call_line
          && event.call_line < event.event_line
          && event.event_line < event.result_line,
        'HANDOFF_ARTIFACT_INVALID',
        'source_capture records 必须严格按 call -> patch_apply_end -> result 递增',
      );
      previousLine = event.result_line;
      assertControl(
        typeof event.event_timestamp === 'string' && Number.isFinite(Date.parse(event.event_timestamp)),
        'HANDOFF_ARTIFACT_INVALID',
        'source_capture event_timestamp 非法',
      );
      normalizeHash(event.call_record_sha256, 'source_capture call_record_sha256');
      normalizeHash(event.event_record_sha256, 'source_capture event_record_sha256');
      normalizeHash(event.result_record_sha256, 'source_capture result_record_sha256');
      assertControl(
        Number.isSafeInteger(event.change_count) && event.change_count > 0,
        'HANDOFF_ARTIFACT_INVALID',
        'source_capture event change_count 非法',
      );
    }
    assertControl(
      Number.isSafeInteger(raw.source_capture.excluded_patch_count)
        && raw.source_capture.excluded_patch_count >= 0
        && raw.source_capture.excluded_patch_count <= MAX_UNTRACKED_ENTRIES
        && Array.isArray(raw.source_capture.excluded_patches)
        && raw.source_capture.excluded_patches.length === raw.source_capture.excluded_patch_count,
      'HANDOFF_ARTIFACT_INVALID',
      'source_capture excluded_patches 数量不匹配',
    );
    for (const excluded of raw.source_capture.excluded_patches) {
      exactKeys(
        excluded,
        [
          'call_id', 'call_line', 'call_record_sha256',
          'event_line', 'event_timestamp', 'event_record_sha256',
          'result_line', 'result_record_sha256', 'change_count',
        ],
        'source_capture excluded patch',
      );
      safeId(excluded.call_id, 'source_capture excluded call_id');
      assertControl(!seenCalls.has(excluded.call_id), 'HANDOFF_ARTIFACT_INVALID', `duplicate excluded call_id ${excluded.call_id}`);
      seenCalls.add(excluded.call_id);
      assertControl(
        Number.isSafeInteger(excluded.call_line)
          && Number.isSafeInteger(excluded.event_line)
          && Number.isSafeInteger(excluded.result_line)
          && excluded.call_line < excluded.event_line
          && excluded.event_line < excluded.result_line,
        'HANDOFF_ARTIFACT_INVALID',
        'excluded patch records 顺序非法',
      );
      assertControl(
        typeof excluded.event_timestamp === 'string' && Number.isFinite(Date.parse(excluded.event_timestamp)),
        'HANDOFF_ARTIFACT_INVALID',
        'excluded patch timestamp 非法',
      );
      normalizeHash(excluded.call_record_sha256, 'excluded patch call_record_sha256');
      normalizeHash(excluded.event_record_sha256, 'excluded patch event_record_sha256');
      normalizeHash(excluded.result_record_sha256, 'excluded patch result_record_sha256');
      assertControl(
        Number.isSafeInteger(excluded.change_count) && excluded.change_count > 0,
        'HANDOFF_ARTIFACT_INVALID',
        'excluded patch change_count 非法',
      );
    }
    if (raw.source_capture.shell_audit !== undefined) {
      const shellAudit = raw.source_capture.shell_audit;
      exactKeys(
        shellAudit,
        [
          'kind', 'audit_artifact', 'audit_size', 'audit_sha256',
          'records_artifact', 'records_size', 'records_sha256',
          'call_count', 'incident_ref', 'captain_thread_id', 'foreman_thread_id',
        ],
        'source_capture shell_audit',
      );
      assertControl(shellAudit.kind === CODEX_SHELL_AUDIT_KIND, 'HANDOFF_ARTIFACT_INVALID', 'shell_audit kind 非法');
      for (const key of ['audit_artifact', 'records_artifact']) {
        safeRelativePath(shellAudit[key], `shell_audit ${key}`);
        assertControl(!seenArtifacts.has(shellAudit[key]), 'HANDOFF_ARTIFACT_INVALID', `duplicate shell_audit artifact ${shellAudit[key]}`);
        seenArtifacts.add(shellAudit[key]);
      }
      for (const key of ['audit_size', 'records_size']) {
        assertControl(
          Number.isSafeInteger(shellAudit[key]) && shellAudit[key] > 0 && shellAudit[key] <= MAX_ROLLOUT_BYTES,
          'HANDOFF_ARTIFACT_INVALID',
          `shell_audit ${key} 非法`,
        );
      }
      normalizeHash(shellAudit.audit_sha256, 'shell_audit audit_sha256');
      normalizeHash(shellAudit.records_sha256, 'shell_audit records_sha256');
      assertControl(
        Number.isSafeInteger(shellAudit.call_count)
          && shellAudit.call_count > 0
          && shellAudit.call_count <= MAX_UNTRACKED_ENTRIES,
        'HANDOFF_ARTIFACT_INVALID',
        'shell_audit call_count 非法',
      );
      for (const key of ['captain_thread_id', 'foreman_thread_id']) safeId(shellAudit[key], `shell_audit ${key}`);
      assertControl(
        typeof shellAudit.incident_ref === 'string'
          && shellAudit.incident_ref.length > 0
          && shellAudit.incident_ref.length <= 500
          && !/[\u0000-\u001f\u007f]/.test(shellAudit.incident_ref),
        'HANDOFF_ARTIFACT_INVALID',
        'shell_audit incident_ref 非法',
      );
      assertControl(
        raw.source_capture.size + shellAudit.audit_size + shellAudit.records_size <= MAX_ROLLOUT_BYTES,
        'CODEX_ROLLOUT_TOO_LARGE',
        `Codex provenance + shell audit 超过 ${MAX_ROLLOUT_BYTES} bytes`,
      );
    }
  }
  if (raw.schema_version === SNAPSHOT_SCHEMA_VERSION) {
    assertControl(
      Boolean(raw.acceptance_authority.foreman)
        === Boolean(raw.source_capture && raw.source_capture.shell_audit),
      'HANDOFF_ARTIFACT_INVALID',
      'FOREMAN acceptance authority 必须且只能与 Codex shell audit 同时存在',
    );
  }
  for (const entry of raw.untracked) {
    exactKeys(entry, ['path', 'type', 'mode', 'size', 'sha256', 'artifact'], 'snapshot untracked entry');
    safeRelativePath(entry.path, 'snapshot untracked path');
    safeRelativePath(entry.artifact, 'snapshot untracked artifact path');
    assertControl(!seenPaths.has(entry.path), 'HANDOFF_ARTIFACT_INVALID', `duplicate untracked path ${entry.path}`);
    assertControl(!seenArtifacts.has(entry.artifact), 'HANDOFF_ARTIFACT_INVALID', `duplicate artifact path ${entry.artifact}`);
    seenPaths.add(entry.path);
    seenArtifacts.add(entry.artifact);
    assertControl(['regular', 'symlink'].includes(entry.type), 'HANDOFF_ARTIFACT_INVALID', `untracked ${entry.path} type 非法`);
    assertControl(
      (entry.type === 'regular' && ['100644', '100755'].includes(entry.mode))
        || (entry.type === 'symlink' && entry.mode === '120000'),
      'HANDOFF_ARTIFACT_INVALID',
      `untracked ${entry.path} mode 非法`,
    );
    assertControl(Number.isSafeInteger(entry.size) && entry.size >= 0, 'HANDOFF_ARTIFACT_INVALID', `untracked ${entry.path} size 非法`);
    if (entry.type === 'symlink') {
      assertControl(entry.size > 0 && entry.size <= MAX_SYMLINK_TARGET_BYTES, 'HANDOFF_SYMLINK_INVALID', `symlink ${entry.path} size 非法`);
    }
    normalizeHash(entry.sha256, `untracked ${entry.path} sha256`);
    bytes += entry.size;
  }
  assertControl(bytes === raw.total_bytes, 'HANDOFF_ARTIFACT_INVALID', 'snapshot total_bytes 与 artifacts 不一致');
  const unsigned = { ...raw };
  delete unsigned.snapshot_sha256;
  assertControl(hashObject(unsigned) === normalizeHash(raw.snapshot_sha256, 'snapshot_sha256'), 'HANDOFF_SNAPSHOT_TAMPERED', 'snapshot manifest hash 不匹配');
  for (const [key, value] of Object.entries(expected)) {
    if (value !== undefined) assertControl(raw[key] === value, 'HANDOFF_SNAPSHOT_MISMATCH', `snapshot ${key} 不匹配`);
  }
  return raw;
}

function validateReceipt(raw, expected = {}) {
  const keys = [
    'schema_version', 'import_receipt_id', 'snapshot_id', 'snapshot_sha256',
    'goal_id', 'task_id', 'successor_thread_id',
    'predecessor_launch_id', 'predecessor_launch_sha256',
    'source_worktree', 'source_branch', 'source_launch_head', 'source_observed_head',
    'destination_worktree', 'destination_branch', 'destination_head_before',
    'expected_tree', 'materialized_tree',
    'materialized_patch_sha256', 'materialized_patch_bytes',
    'acceptance_authority',
    'imported_at', 'import_receipt_sha256',
  ];
  exactKeys(raw, keys, 'recovery import receipt');
  assertControl(
    [
      LEGACY_RECEIPT_SCHEMA_VERSION,
      EXACT_TREE_RECEIPT_SCHEMA_VERSION,
      RECEIPT_SCHEMA_VERSION,
    ].includes(raw.schema_version),
    'HANDOFF_ARTIFACT_INVALID',
    'receipt schema_version 非法',
  );
  for (const key of ['import_receipt_id', 'snapshot_id', 'goal_id', 'task_id', 'successor_thread_id', 'predecessor_launch_id']) {
    safeId(raw[key], `receipt ${key}`);
  }
  for (const key of ['source_launch_head', 'source_observed_head', 'destination_head_before']) {
    assertFullSha(raw[key], `receipt ${key}`);
  }
  if (
    raw.schema_version === EXACT_TREE_RECEIPT_SCHEMA_VERSION
    || raw.schema_version === RECEIPT_SCHEMA_VERSION
  ) {
    assertFullSha(raw.expected_tree, 'receipt expected_tree');
    assertFullSha(raw.materialized_tree, 'receipt materialized_tree');
    assertControl(
      raw.expected_tree === raw.materialized_tree,
      'HANDOFF_MATERIALIZED_TREE_MISMATCH',
      'receipt expected_tree 与 materialized_tree 不一致',
    );
  } else {
    assertControl(
      raw.expected_tree === undefined && raw.materialized_tree === undefined,
      'HANDOFF_ARTIFACT_INVALID',
      'legacy receipt 禁止携带 v2 exact-tree 字段',
    );
  }
  if (raw.schema_version === RECEIPT_SCHEMA_VERSION) {
    exactKeys(raw.acceptance_authority, ['dev'], 'receipt acceptance_authority');
    validateAcceptanceAuthority(raw.acceptance_authority.dev, 'DEV');
    assertControl(
      raw.acceptance_authority.dev.thread_id === raw.successor_thread_id,
      'HANDOFF_ARTIFACT_INVALID',
      'receipt DEV authority 未绑定 successor_thread_id',
    );
  } else {
    assertControl(
      raw.acceptance_authority === undefined,
      'HANDOFF_ARTIFACT_INVALID',
      'pre-v3 receipt 禁止携带 acceptance_authority',
    );
  }
  assertHistoricalDirectoryValue(raw.source_worktree, 'receipt source_worktree');
  // Receipts are durable evidence and outlive disposable Codex worktrees. Current
  // destination existence is re-established by repositoryIdentity(cwd) at import/
  // bind time; replaying an older receipt must not require its archived worktree.
  assertHistoricalDirectoryValue(raw.destination_worktree, 'receipt destination_worktree');
  assertControl(raw.source_worktree !== raw.destination_worktree, 'HANDOFF_SAME_WORKTREE', 'receipt source/destination worktree 必须不同');
  for (const key of ['source_branch', 'destination_branch']) {
    assertControl(
      typeof raw[key] === 'string'
        && raw[key].length > 0
        && raw[key].length <= 300
        && !/[\u0000-\u0020\u007f]/.test(raw[key]),
      'HANDOFF_ARTIFACT_INVALID',
      `receipt ${key} 非法`,
    );
  }
  assertControl(raw.source_branch !== raw.destination_branch, 'HANDOFF_SAME_BRANCH', 'receipt source/destination branch 必须不同');
  assertControl(raw.destination_head_before === raw.source_observed_head, 'HANDOFF_RECEIPT_MISMATCH', 'receipt destination base 不是 source observed HEAD');
  for (const key of ['snapshot_sha256', 'predecessor_launch_sha256', 'materialized_patch_sha256']) {
    normalizeHash(raw[key], `receipt ${key}`);
  }
  assertControl(
    Number.isSafeInteger(raw.materialized_patch_bytes)
      && raw.materialized_patch_bytes >= 0
      && raw.materialized_patch_bytes <= MAX_SNAPSHOT_BYTES,
    'HANDOFF_ARTIFACT_INVALID',
    'receipt materialized_patch_bytes 非法',
  );
  assertControl(typeof raw.imported_at === 'string' && Number.isFinite(Date.parse(raw.imported_at)), 'HANDOFF_ARTIFACT_INVALID', 'receipt imported_at 非法');
  const unsigned = { ...raw };
  delete unsigned.import_receipt_sha256;
  assertControl(hashObject(unsigned) === normalizeHash(raw.import_receipt_sha256, 'import_receipt_sha256'), 'HANDOFF_RECEIPT_TAMPERED', 'import receipt hash 不匹配');
  for (const [key, value] of Object.entries(expected)) {
    if (value !== undefined) assertControl(raw[key] === value, 'HANDOFF_RECEIPT_MISMATCH', `receipt ${key} 不匹配`);
  }
  return raw;
}

function sourceSessionContext(loaded, taskId, successorThreadId) {
  const state = loaded.snapshot.tasks[taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
  assertControl(state.phase === 'DEV_ACTIVE', 'RECOVERY_HANDOFF_NOT_APPLICABLE', `phase=${state.phase} 不适用 source handoff`);
  const successor = state.sessions.DEV;
  assertControl(successor && successor.thread_id === successorThreadId, 'SUCCESSOR_NOT_REGISTERED', 'successor 不是当前 DEV');
  assertControl(['active', 'idle'].includes(successor.status), 'ACTOR_UNUSABLE', `DEV status=${successor.status}`);
  assertControl(successor.recovered_from && successor.recovered_from.role === 'DEV', 'RECOVERY_HANDOFF_NOT_APPLICABLE', '当前 DEV 不是 recovery successor');
  assertControl(successor.operational_scope === 'RECOVERY_BLOCKED', 'RECOVERY_HANDOFF_ALREADY_BOUND', `DEV scope=${successor.operational_scope}`);
  assertControl(successor.recovered_from.predecessor_launch_id, 'RECOVERY_PREDECESSOR_MISSING', 'recovery lineage 缺 predecessor launch');
  return { state, successor };
}

function canonicalLaunch(loaded, taskId, successor) {
  const launchId = safeId(successor.recovered_from.predecessor_launch_id, 'predecessor launch_id');
  const state = loaded.snapshot.tasks[taskId];
  const recovered = successor.recovered_from;
  assertControl(
    typeof recovered.host_id === 'string'
      && recovered.host_id.length > 0
      && Number.isSafeInteger(recovered.attempt)
      && recovered.attempt > 0,
    'RECOVERY_PREDECESSOR_MISSING',
    'recovery lineage 缺 predecessor host/attempt',
  );
  const matchingHistory = (state.session_history && state.session_history.DEV || []).filter((candidate) => (
    candidate.thread_id === recovered.thread_id
      && candidate.host_id === recovered.host_id
      && candidate.attempt === recovered.attempt
  ));
  assertControl(
    matchingHistory.length === 1 && matchingHistory[0].status === 'lost',
    'RECOVERY_PREDECESSOR_MISSING',
    'recovery lineage 未精确对应唯一 lost DEV history',
  );
  const predecessorSession = matchingHistory[0];
  assertControl(
    predecessorSession.launch_id === launchId && typeof predecessorSession.task_nonce === 'string',
    'RECOVERY_HANDOFF_MISMATCH',
    'lost DEV history 的 launch/task_nonce 与 recovery lineage 不一致',
  );
  const expected = path.join(loaded.paths.dir, 'launches', taskId, `${launchId}.json`);
  const file = canonicalRegularFile(expected, 'predecessor canonical launch');
  assertControl(file === path.resolve(expected), 'HANDOFF_ARTIFACT_INVALID', 'predecessor launch path 不是 canonical control-store path');
  const launch = validateLaunchManifest(readJson(file, 'predecessor canonical launch'));
  assertControl(
    launch.goal_id === loaded.manifest.goal_id
      && launch.task_id === taskId
      && launch.role === 'DEV'
      && launch.launch_id === launchId,
    'RECOVERY_HANDOFF_MISMATCH',
    'predecessor launch identity 与 recovery lineage 不一致',
  );
  assertControl(
    launch.thread.id === recovered.thread_id
      && launch.thread.host_id === recovered.host_id
      && launch.execution.task_nonce === predecessorSession.task_nonce,
    'RECOVERY_HANDOFF_MISMATCH',
    'predecessor launch thread/host/task_nonce 与 lost history 不一致',
  );
  if (
    recovered.predecessor_registered_head !== undefined
    && predecessorSession.registered_full_head !== undefined
  ) {
    assertControl(
      recovered.predecessor_registered_head === predecessorSession.registered_full_head,
      'RECOVERY_HANDOFF_MISMATCH',
      'predecessor registered HEAD 与 recovery lineage 不一致',
    );
  }
  const recoveredLaunchHead = recovered.predecessor_launch_head
    || (
      predecessorSession.recovery_handoff
        ? predecessorSession.recovery_handoff.import_commit
        : recovered.predecessor_registered_head
    );
  assertControl(
    typeof recoveredLaunchHead === 'string'
      && recoveredLaunchHead === launch.repository.full_head,
    'RECOVERY_HANDOFF_MISMATCH',
    'predecessor launch HEAD 与 recovery lineage 不一致',
  );
  if (predecessorSession.recovery_handoff) {
    assertControl(
      predecessorSession.operational_scope === 'FULL'
        && predecessorSession.recovery_promotion
        && predecessorSession.recovery_promotion.launch_id === launch.launch_id
        && normalizeHash(
          predecessorSession.recovery_promotion.launch_sha256,
          'predecessor promotion launch_sha256',
        ) === hashFile(file)
        && predecessorSession.recovery_handoff.import_commit === recoveredLaunchHead,
      'RECOVERY_HANDOFF_MISMATCH',
      'recovered predecessor launch checkpoint 未绑定 handoff/promotion',
    );
  }
  return { launch, file, sha256: hashFile(file), predecessorSession };
}

function assertSnapshotPredecessorBinding(snapshot, predecessor) {
  const launch = predecessor.launch;
  assertControl(
    snapshot.predecessor_launch_id === launch.launch_id
      && snapshot.predecessor_launch_sha256 === predecessor.sha256
      && snapshot.source_worktree === launch.repository.worktree
      && snapshot.source_worktree === launch.thread.cwd
      && snapshot.source_branch === launch.repository.branch
      && snapshot.source_launch_head === launch.repository.full_head
      && snapshot.repository_root === launch.repository.root,
    'RECOVERY_HANDOFF_MISMATCH',
    'snapshot source identity 未精确绑定 canonical predecessor launch',
  );
  if (snapshot.source_capture !== undefined) {
    assertControl(
      snapshot.source_capture.kind === CODEX_ROLLOUT_CAPTURE_KIND
        && snapshot.source_capture.session_id === launch.thread.id
        && snapshot.source_capture.session_cwd === launch.thread.cwd
        && snapshot.source_observed_head === launch.repository.full_head,
      'RECOVERY_HANDOFF_MISMATCH',
      'Codex rollout capture 未精确绑定 predecessor thread/cwd/HEAD',
    );
  }
}

function loadGoalUnlocked(root, goalId, options = {}) {
  // Lazy require avoids a goal.js -> source-handoff.js -> goal.js initialization cycle.
  return require('./goal').loadGoalStateUnlocked(root, goalId, options);
}

function snapshotPaths(root, goalId, taskId, snapshotId) {
  const base = path.join(root, 'goals', goalId, 'recovery-handoffs', taskId);
  return {
    base,
    snapshots: path.join(base, 'snapshots'),
    snapshotDir: path.join(base, 'snapshots', snapshotId),
    receipts: path.join(base, 'import-receipts'),
  };
}

function exportRequestWorktree(options, cwd, label) {
  return assertHistoricalDirectoryValue(
    options.repositoryWorktree === undefined
      ? canonicalDirectory(repoRoot(cwd), label)
      : options.repositoryWorktree,
    label,
  );
}

function exportRequestFile(candidate, label) {
  return assertHistoricalAbsolutePath(candidate, label);
}

function assertExistingExportRequest(snapshot, expected) {
  assertControl(
    snapshot.schema_version === SNAPSHOT_SCHEMA_VERSION,
    'HANDOFF_RETRY_AUTHORITY_REQUIRED',
    `snapshot ${snapshot.snapshot_id} 缺 v3 operation/acceptance authority，不能作为 stable operation retry`,
  );
  const actual = snapshot.operation_request;
  const sameCommon = actual.kind === expected.kind
    && actual.repository_worktree === expected.repository_worktree
    && actual.successor_thread_id === expected.successor_thread_id;
  const same = expected.kind === 'SOURCE_WORKTREE'
    ? sameCommon
    : (
      sameCommon
        && actual.predecessor_launch_id === expected.predecessor_launch_id
        && actual.predecessor_thread_id === expected.predecessor_thread_id
        && actual.rollout_file.path === expected.rollout_file
        && (
          expected.shell_audit_file === null
            ? actual.shell_audit_file === null
            : (
              actual.shell_audit_file !== null
                && actual.shell_audit_file.path === expected.shell_audit_file
            )
        )
    );
  assertControl(
    same,
    'HANDOFF_OPERATION_CONFLICT',
    `snapshot operation ${snapshot.snapshot_id} 已绑定不同 export request`,
  );
}

function exportSnapshotResult(artifacts, idempotent) {
  return {
    ...artifacts.snapshot,
    snapshot_file: artifacts.manifestFile,
    idempotent,
  };
}

function publicRecoveryHandoffResult(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => publicRecoveryHandoffResult(entry));
  }
  if (
    !value
    || typeof value !== 'object'
    || Buffer.isBuffer(value)
  ) {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => (
        key !== 'capability_file'
          && key !== 'capability_sha256'
      ))
      .map(([key, entry]) => [
        key,
        publicRecoveryHandoffResult(entry),
      ]),
  );
}

function preliminaryExportOperationRequest(operationRequest) {
  if (operationRequest.kind === 'SOURCE_WORKTREE') {
    return operationRequest;
  }
  assertControl(
    operationRequest.kind === 'CODEX_ROLLOUT',
    'HANDOFF_ARTIFACT_INVALID',
    `partial snapshot operation kind 非法: ${String(operationRequest.kind)}`,
  );
  return {
    ...operationRequest,
    rollout_file: typeof operationRequest.rollout_file === 'string'
      ? operationRequest.rollout_file
      : operationRequest.rollout_file.path,
    shell_audit_file: operationRequest.shell_audit_file === null
      ? null
      : (
        typeof operationRequest.shell_audit_file === 'string'
          ? operationRequest.shell_audit_file
          : operationRequest.shell_audit_file.path
      ),
  };
}

function sourceTransactionScope(goalId, taskId) {
  return {
    goal_id: goalId,
    task_id: taskId,
  };
}

function sourceExportTransactionKey(
  goalId,
  taskId,
  snapshotId,
  requestedOperation,
) {
  return canonicalTransactionKey(
    'SOURCE_EXPORT',
    sourceTransactionScope(goalId, taskId),
    snapshotId,
    hashObject(preliminaryExportOperationRequest(requestedOperation)),
  );
}

function preparedSourceExportGoalLoadOptions(
  prepared,
  snapshotId,
  requestedOperation,
) {
  if (!prepared) return {};
  return {
    allowPendingGoalOperation: {
      kind: 'SOURCE_EXPORT',
      operation_id: snapshotId,
      request_sha256: hashObject(
        preliminaryExportOperationRequest(requestedOperation),
      ),
    },
  };
}

function partialSnapshotExecutionSha256(snapshot) {
  const identity = { ...snapshot };
  delete identity.created_at;
  delete identity.snapshot_sha256;
  return hashObject(identity);
}

function partialSnapshotBinding(snapshot) {
  const operationRequest = preliminaryExportOperationRequest(
    snapshot.operation_request,
  );
  const unsigned = {
    schema_version: PARTIAL_SNAPSHOT_BINDING_SCHEMA_VERSION,
    snapshot_id: snapshot.snapshot_id,
    goal_id: snapshot.goal_id,
    task_id: snapshot.task_id,
    operation_kind: operationRequest.kind,
    operation_request_sha256: hashObject(operationRequest),
    execution_sha256: partialSnapshotExecutionSha256(snapshot),
  };
  return {
    ...unsigned,
    binding_sha256: hashObject(unsigned),
  };
}

function partialSnapshotStagingName(snapshotId, binding) {
  return [
    '.init-source',
    sha256(snapshotId),
    binding.operation_request_sha256.slice('sha256:'.length),
    binding.binding_sha256.slice('sha256:'.length),
  ].join('-');
}

function readPartialSnapshotBindingFile(
  bindingFile,
  goalId,
  taskId,
  snapshotId,
) {
  const stat = fs.lstatSync(bindingFile);
  assertCurrentOwnerOrdinary(
    stat,
    'file',
    'HANDOFF_STAGING_INVALID',
    `snapshot ${snapshotId} operation binding 不是当前 owner 的普通文件`,
  );
  let binding;
  try {
    binding = readJson(bindingFile, `snapshot ${snapshotId} operation binding`);
  } catch (error) {
    throw new ControlError(
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} operation binding 无法读取: ${error.message}`,
    );
  }
  const keys = [
    'schema_version',
    'snapshot_id',
    'goal_id',
    'task_id',
    'operation_kind',
    'operation_request_sha256',
    'execution_sha256',
    'binding_sha256',
  ];
  assertControl(
    binding
      && typeof binding === 'object'
      && !Array.isArray(binding)
      && Object.keys(binding).length === keys.length
      && keys.every((key) => Object.prototype.hasOwnProperty.call(binding, key)),
    'HANDOFF_STAGING_INVALID',
    `snapshot ${snapshotId} operation binding 字段不完整`,
  );
  exactKeys(binding, keys, `snapshot ${snapshotId} operation binding`);
  assertControl(
    binding.schema_version === PARTIAL_SNAPSHOT_BINDING_SCHEMA_VERSION
      && binding.snapshot_id === snapshotId
      && binding.goal_id === goalId
      && binding.task_id === taskId
      && ['SOURCE_WORKTREE', 'CODEX_ROLLOUT'].includes(binding.operation_kind),
    'HANDOFF_STAGING_INVALID',
    `snapshot ${snapshotId} operation binding identity 漂移`,
  );
  const unsigned = { ...binding };
  delete unsigned.binding_sha256;
  assertControl(
    hashObject(unsigned) === normalizeHash(
      binding.binding_sha256,
      `snapshot ${snapshotId} binding_sha256`,
    ),
    'HANDOFF_STAGING_TAMPERED',
    `snapshot ${snapshotId} operation binding seal 不匹配`,
  );
  binding.operation_request_sha256 = normalizeHash(
    binding.operation_request_sha256,
    `snapshot ${snapshotId} operation_request_sha256`,
  );
  binding.execution_sha256 = normalizeHash(
    binding.execution_sha256,
    `snapshot ${snapshotId} execution_sha256`,
  );
  return binding;
}

function readPartialSnapshotBinding(directory, goalId, taskId, snapshotId) {
  const bindingFile = path.join(directory, PARTIAL_SNAPSHOT_BINDING_FILE);
  assertControl(
    fs.existsSync(bindingFile),
    'HANDOFF_STAGING_OPERATION_UNBOUND',
    `snapshot ${snapshotId} partial staging 缺 durable operation binding`,
  );
  return readPartialSnapshotBindingFile(
    bindingFile,
    goalId,
    taskId,
    snapshotId,
  );
}

function assertPartialSnapshotBindingMatches(
  binding,
  expected,
  { requireExecution = true } = {},
) {
  assertControl(
    binding.operation_kind === expected.operation_kind
      && binding.operation_request_sha256 === expected.operation_request_sha256,
    'HANDOFF_OPERATION_CONFLICT',
    `snapshot operation ${expected.snapshot_id} partial staging 已绑定不同 export request`,
  );
  if (!requireExecution) return;
  assertControl(
    binding.execution_sha256 === expected.execution_sha256
      && binding.binding_sha256 === expected.binding_sha256,
    'HANDOFF_OPERATION_CONFLICT',
    `snapshot operation ${expected.snapshot_id} partial staging 已绑定不同 source/input/authority context`,
  );
}

function snapshotStagingCandidates(paths, snapshotId) {
  if (!fs.existsSync(paths.snapshots)) return [];
  const escaped = snapshotId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const legacyPattern = new RegExp(
    `^\\.${escaped}\\.[1-9][0-9]*\\.tmp-[0-9a-f]{24}$`,
  );
  const snapshotDigest = sha256(snapshotId);
  const v2Prefix = `.init-source-${snapshotDigest}-`;
  const v2Pattern = new RegExp(
    `^\\.init-source-${snapshotDigest}-([0-9a-f]{64})-([0-9a-f]{64})$`,
  );
  const candidates = [];
  for (const name of fs.readdirSync(paths.snapshots).sort()) {
    const legacy = legacyPattern.test(name);
    const v2 = v2Pattern.exec(name);
    if (!legacy && !v2) {
      assertControl(
        !name.startsWith(v2Prefix),
        'HANDOFF_STAGING_INVALID',
        `snapshot ${snapshotId} 含 malformed v2 staging ${name}`,
      );
      continue;
    }
    const candidate = path.join(paths.snapshots, name);
    const stat = fs.lstatSync(candidate);
    assertControl(
      stat.isDirectory()
        && !stat.isSymbolicLink()
        && (stat.mode & 0o777) === 0o700
        && (
          typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
        ),
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} staging orphan 不是当前 owner 的 0700 普通目录`,
    );
    candidates.push({
      directory: candidate,
      format: v2 ? 'v2' : 'legacy',
      operationRequestDigest: v2 ? v2[1] : null,
      bindingDigest: v2 ? v2[2] : null,
    });
  }
  return candidates;
}

function snapshotDiscardCandidates(paths, snapshotId) {
  if (!fs.existsSync(paths.snapshots)) return [];
  const snapshotDigest = sha256(snapshotId);
  const prefix = `.discard-source-${snapshotDigest}-`;
  const pattern = new RegExp(
    `^\\.discard-source-${snapshotDigest}-([0-9a-f]{64})$`,
  );
  const candidates = [];
  for (const name of fs.readdirSync(paths.snapshots).sort()) {
    const match = pattern.exec(name);
    if (!match) {
      assertControl(
        !name.startsWith(prefix),
        'HANDOFF_STAGING_INVALID',
        `snapshot ${snapshotId} 含 malformed discard residue ${name}`,
      );
      continue;
    }
    const candidate = path.join(paths.snapshots, name);
    const stat = fs.lstatSync(candidate);
    assertControl(
      stat.isDirectory()
        && !stat.isSymbolicLink()
        && (stat.mode & 0o777) === 0o700
        && (
          typeof process.getuid !== 'function'
          || stat.uid === process.getuid()
        ),
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} discard residue 不是当前 owner 的 0700 普通目录`,
    );
    candidates.push({
      directory: candidate,
      bindingDigest: match[1],
    });
  }
  return candidates;
}

function assertCurrentOwnerOrdinary(stat, expectedKind, code, message) {
  const expectedType = expectedKind === 'directory'
    ? stat.isDirectory()
    : stat.isFile();
  const expectedMode = expectedKind === 'directory' ? 0o700 : 0o600;
  assertControl(
    expectedType
      && !stat.isSymbolicLink()
      && (stat.mode & 0o777) === expectedMode
      && (
        typeof process.getuid !== 'function'
        || stat.uid === process.getuid()
      ),
    code,
    message,
  );
}

function atomicWriteStagingTarget(name) {
  const match = /^\.([^\0/]+)\.[1-9][0-9]*\.tmp-[0-9a-f]{24}$/.exec(name);
  return match ? match[1] : null;
}

function atomicWriteSnapshotProtocolJson(
  root,
  file,
  value,
  fault,
) {
  ensureDir(path.dirname(file));
  assertControl(
    !fs.existsSync(file),
    'HANDOFF_STAGING_INVALID',
    `snapshot protocol target 已存在: ${path.basename(file)}`,
  );
  const temporary = path.join(
    path.dirname(file),
    `.${path.basename(file)}.${process.pid}.${randomId('tmp')}`,
  );
  const fd = fs.openSync(temporary, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  maybeInjectHandoffFault(
    root,
    fault.variable,
    fault.code,
    fault.message,
    fault.exitCode,
  );
  fs.renameSync(temporary, file);
  fsyncDirectory(path.dirname(file));
}

function snapshotPartialFileTarget(name, directoryKind) {
  const temporaryTarget = atomicWriteStagingTarget(name);
  const target = temporaryTarget || name;
  if (directoryKind === 'root') {
    return [
      PARTIAL_SNAPSHOT_BINDING_FILE,
      'tracked.patch',
      'snapshot.json',
    ].includes(target)
      ? { target, temporary: temporaryTarget !== null }
      : null;
  }
  if (directoryKind === 'untracked') {
    return /^[0-9]{6}\.bin$/.test(target)
      ? { target, temporary: temporaryTarget !== null }
      : null;
  }
  return [
    'codex-rollout-events.jsonl',
    'codex-shell-audit.json',
    'codex-shell-records.jsonl',
  ].includes(target)
    ? { target, temporary: temporaryTarget !== null }
    : null;
}

function validateUnsealedSnapshotStaging(
  directory,
  snapshotId,
  operationKind,
  { allowSealedManifest = false } = {},
) {
  const files = [];
  const childDirectories = [];
  const seenArtifacts = new Set();
  const allowedChildDirectory = operationKind === 'SOURCE_WORKTREE'
    ? 'untracked'
    : 'provenance';
  for (const name of fs.readdirSync(directory).sort()) {
    const candidate = path.join(directory, name);
    const stat = fs.lstatSync(candidate);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      assertCurrentOwnerOrdinary(
        stat,
        'directory',
        'HANDOFF_STAGING_INVALID',
        `snapshot ${snapshotId} partial staging 子目录不是当前 owner 的普通目录`,
      );
      assertControl(
        name === allowedChildDirectory,
        'HANDOFF_STAGING_INVALID',
        `snapshot ${snapshotId} partial staging 含未知目录`,
      );
      childDirectories.push({ directory: candidate, kind: name });
      continue;
    }
    const artifact = snapshotPartialFileTarget(name, 'root');
    assertControl(
      artifact !== null
        && !(
          artifact.target === 'snapshot.json'
          && !artifact.temporary
          && !allowSealedManifest
        ),
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} partial staging 含未知文件`,
    );
    assertCurrentOwnerOrdinary(
      stat,
      'file',
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} partial staging 文件不是当前 owner 的普通文件`,
    );
    const key = `root/${artifact.target}`;
    assertControl(
      !seenArtifacts.has(key),
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} partial staging 含重复 artifact`,
    );
    seenArtifacts.add(key);
    files.push(candidate);
  }
  for (const child of childDirectories) {
    for (const name of fs.readdirSync(child.directory).sort()) {
      const candidate = path.join(child.directory, name);
      const stat = fs.lstatSync(candidate);
      const artifact = snapshotPartialFileTarget(name, child.kind);
      assertControl(
        artifact !== null,
        'HANDOFF_STAGING_INVALID',
        `snapshot ${snapshotId} partial staging 含未知 artifact`,
      );
      assertCurrentOwnerOrdinary(
        stat,
        'file',
        'HANDOFF_STAGING_INVALID',
        `snapshot ${snapshotId} partial staging artifact 不是当前 owner 的普通文件`,
      );
      const key = `${child.kind}/${artifact.target}`;
      assertControl(
        !seenArtifacts.has(key),
        'HANDOFF_STAGING_INVALID',
        `snapshot ${snapshotId} partial staging 含重复 artifact`,
      );
      seenArtifacts.add(key);
      files.push(candidate);
    }
  }
  return { files, childDirectories };
}

function removeUnsealedSnapshotStaging(
  root,
  paths,
  directory,
  snapshotId,
  operationKind,
  binding,
  expectedBinding,
  alreadyDiscarded = false,
  pathBindingDigest = null,
) {
  const expectedBindingDigest = expectedBinding.binding_sha256.slice(
    'sha256:'.length,
  );
  assertControl(
    pathBindingDigest === null || pathBindingDigest === expectedBindingDigest,
    'HANDOFF_OPERATION_CONFLICT',
    `snapshot operation ${snapshotId} staging pathname 已绑定不同 execution context`,
  );
  if (binding !== null) {
    assertPartialSnapshotBindingMatches(binding, expectedBinding);
  } else {
    assertControl(
      fs.readdirSync(directory).length === 0,
      'HANDOFF_STAGING_OPERATION_UNBOUND',
      `snapshot ${snapshotId} 无 binding 的 staging 不是空目录`,
    );
    fs.rmdirSync(directory);
    fsyncDirectory(paths.snapshots);
    return;
  }
  validateUnsealedSnapshotStaging(
    directory,
    snapshotId,
    operationKind,
  );
  let discarded = directory;
  if (!alreadyDiscarded) {
    discarded = path.join(
      paths.snapshots,
      `.discard-source-${sha256(snapshotId)}-${expectedBindingDigest}`,
    );
    assertControl(
      !fs.existsSync(discarded),
      'HANDOFF_STAGING_AMBIGUOUS',
      `snapshot ${snapshotId} discard target 已存在`,
    );
    fs.renameSync(directory, discarded);
    fsyncDirectory(paths.snapshots);
    maybeInjectHandoffFault(
      root,
      'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_DISCARD_CLAIM',
      'TEST_FAULT_AFTER_SNAPSHOT_DISCARD_CLAIM',
      'injected failure after partial snapshot discard claim',
      92,
    );
  }
  const validated = validateUnsealedSnapshotStaging(
    discarded,
    snapshotId,
    operationKind,
  );
  const bindingFile = path.join(discarded, PARTIAL_SNAPSHOT_BINDING_FILE);
  for (const file of validated.files) {
    if (file === bindingFile) continue;
    fs.unlinkSync(file);
  }
  for (const child of validated.childDirectories) {
    fsyncDirectory(child.directory);
    fs.rmdirSync(child.directory);
  }
  fsyncDirectory(discarded);
  maybeInjectHandoffFault(
    root,
    'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_DISCARD_PAYLOAD_CLEANUP',
    'TEST_FAULT_AFTER_SNAPSHOT_DISCARD_PAYLOAD_CLEANUP',
    'injected failure after discard payload cleanup before binding removal',
    97,
  );
  fs.unlinkSync(bindingFile);
  fsyncDirectory(discarded);
  fs.rmdirSync(discarded);
  fsyncDirectory(paths.snapshots);
}

function readPreparedSnapshotArtifacts(
  paths,
  goalId,
  taskId,
  snapshotId,
  requestedOperation,
  options = {},
) {
  const candidates = snapshotStagingCandidates(paths, snapshotId);
  const discardedCandidates = snapshotDiscardCandidates(paths, snapshotId);
  assertControl(
    candidates.length <= 1
      && discardedCandidates.length <= 1
      && candidates.length + discardedCandidates.length <= 1,
    'HANDOFF_STAGING_AMBIGUOUS',
    `snapshot ${snapshotId} 存在多份 durable staging/discard，禁止猜测采用`,
  );
  if (candidates.length === 0 && discardedCandidates.length === 0) return null;
  const discarded = discardedCandidates.length === 1;
  const candidate = discarded ? discardedCandidates[0] : candidates[0];
  const directory = candidate.directory;
  let entries = fs.readdirSync(directory).sort();
  if (discarded && entries.length === 0) {
    if (options.readOnly !== true) {
      fs.rmdirSync(directory);
      fsyncDirectory(paths.snapshots);
    }
    return null;
  }
  const incomingRequestSha256 = hashObject(
    preliminaryExportOperationRequest(requestedOperation),
  );
  const incomingRequestDigest = incomingRequestSha256.slice('sha256:'.length);
  if (!discarded && candidate.format === 'v2') {
    assertControl(
      candidate.operationRequestDigest === incomingRequestDigest,
      'HANDOFF_OPERATION_CONFLICT',
      `snapshot operation ${snapshotId} v2 staging 已绑定不同 export request`,
    );
  }
  assertControl(
    !discarded || !entries.includes('snapshot.json'),
    'HANDOFF_STAGING_INVALID',
    `snapshot ${snapshotId} discard residue 禁止携带 sealed manifest`,
  );

  const bindingTemporaries = entries.filter((name) => (
    atomicWriteStagingTarget(name) === PARTIAL_SNAPSHOT_BINDING_FILE
  ));
  const snapshotTemporaries = entries.filter((name) => (
    atomicWriteStagingTarget(name) === 'snapshot.json'
  ));
  const hasCanonicalBinding = entries.includes(PARTIAL_SNAPSHOT_BINDING_FILE);
  const hasCanonicalSnapshot = entries.includes('snapshot.json');
  assertControl(
    bindingTemporaries.length <= 1
      && snapshotTemporaries.length <= 1
      && !(hasCanonicalBinding && bindingTemporaries.length > 0)
      && !(hasCanonicalSnapshot && snapshotTemporaries.length > 0),
    'HANDOFF_STAGING_INVALID',
    `snapshot ${snapshotId} canonical/atomic protocol marker lineage 分叉`,
  );

  if (
    !hasCanonicalBinding
    && bindingTemporaries.length === 0
    && entries.length === 0
  ) {
    assertControl(
      !discarded && candidate.format === 'v2',
      'HANDOFF_STAGING_OPERATION_UNBOUND',
      `snapshot ${snapshotId} legacy/discord staging 缺 operation binding`,
    );
    return {
      directory,
      artifacts: null,
      binding: null,
      discarded: false,
      bindingDigest: candidate.bindingDigest,
    };
  }

  assertControl(
    hasCanonicalBinding || bindingTemporaries.length === 1,
    'HANDOFF_STAGING_OPERATION_UNBOUND',
    `snapshot ${snapshotId} partial staging 缺 operation binding`,
  );
  assertControl(
    !discarded || hasCanonicalBinding,
    'HANDOFF_STAGING_INVALID',
    `snapshot ${snapshotId} discard residue 禁止携带 binding atomic temp`,
  );
  if (bindingTemporaries.length === 1) {
    assertControl(
      entries.length === 1,
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} binding atomic temp 必须是唯一 staging entry`,
    );
  }
  const bindingFileName = hasCanonicalBinding
    ? PARTIAL_SNAPSHOT_BINDING_FILE
    : bindingTemporaries[0];
  const binding = readPartialSnapshotBindingFile(
    path.join(directory, bindingFileName),
    goalId,
    taskId,
    snapshotId,
  );
  const expected = {
    schema_version: PARTIAL_SNAPSHOT_BINDING_SCHEMA_VERSION,
    snapshot_id: snapshotId,
    goal_id: goalId,
    task_id: taskId,
    operation_kind: requestedOperation.kind,
    operation_request_sha256: incomingRequestSha256,
    execution_sha256: binding.execution_sha256,
    binding_sha256: binding.binding_sha256,
  };
  assertPartialSnapshotBindingMatches(binding, expected, {
    requireExecution: false,
  });
  const bindingDigest = binding.binding_sha256.slice('sha256:'.length);
  if (!discarded && candidate.format === 'v2') {
    assertControl(
      candidate.bindingDigest === bindingDigest,
      'HANDOFF_STAGING_TAMPERED',
      `snapshot ${snapshotId} v2 pathname/binding seal 不匹配`,
    );
  }
  if (discarded) {
    assertControl(
      candidate.bindingDigest === bindingDigest,
      'HANDOFF_STAGING_TAMPERED',
      `snapshot ${snapshotId} discard pathname/binding seal 不匹配`,
    );
  }
  validateUnsealedSnapshotStaging(
    directory,
    snapshotId,
    binding.operation_kind,
    { allowSealedManifest: hasCanonicalSnapshot },
  );

  if (bindingTemporaries.length === 1) {
    if (options.readOnly !== true) {
      fs.renameSync(
        path.join(directory, bindingTemporaries[0]),
        path.join(directory, PARTIAL_SNAPSHOT_BINDING_FILE),
      );
      fsyncDirectory(directory);
      entries = [PARTIAL_SNAPSHOT_BINDING_FILE];
    }
  }

  const promotedSnapshotTemporary = snapshotTemporaries[0] || null;
  if (hasCanonicalSnapshot || promotedSnapshotTemporary !== null) {
    assertControl(
      !discarded,
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} discard residue 禁止 sealed manifest`,
    );
    const manifestName = hasCanonicalSnapshot
      ? 'snapshot.json'
      : promotedSnapshotTemporary;
    let artifacts = readSnapshotArtifactsFromDirectory(
      directory,
      goalId,
      taskId,
      snapshotId,
      undefined,
      manifestName,
    );
    const sealedBinding = partialSnapshotBinding(artifacts.snapshot);
    assertPartialSnapshotBindingMatches(binding, sealedBinding);
    if (!discarded && candidate.format === 'v2') {
      assertControl(
        candidate.bindingDigest
          === sealedBinding.binding_sha256.slice('sha256:'.length),
        'HANDOFF_STAGING_TAMPERED',
        `snapshot ${snapshotId} sealed manifest/path binding 不匹配`,
      );
    }
    if (promotedSnapshotTemporary !== null) {
      if (options.readOnly !== true) {
        fs.renameSync(
          path.join(directory, promotedSnapshotTemporary),
          path.join(directory, 'snapshot.json'),
        );
        fsyncDirectory(directory);
        artifacts = readSnapshotArtifactsFromDirectory(
          directory,
          goalId,
          taskId,
          snapshotId,
        );
      }
    }
    return {
      directory,
      artifacts,
    };
  }

  return {
    directory,
    artifacts: null,
    binding,
    discarded,
    bindingDigest: candidate.bindingDigest,
  };
}

function publishPreparedSnapshot(paths, prepared) {
  const snapshot = prepared.artifacts.snapshot;
  assertControl(
    !fs.existsSync(paths.snapshotDir),
    'HANDOFF_ARTIFACT_EXISTS',
    `snapshot ${snapshot.snapshot_id} 已存在`,
  );
  fs.renameSync(prepared.directory, paths.snapshotDir);
  fsyncDirectory(paths.snapshots);
  return readSnapshotArtifactsFromDirectory(
    paths.snapshotDir,
    snapshot.goal_id,
    snapshot.task_id,
    snapshot.snapshot_id,
  );
}

function validatedHandoffFault(root, variable) {
  const mode = process.env[variable];
  if (mode === undefined || mode === '') return null;
  const temporaryRoot = trustedTemporaryRoot();
  const resolvedRoot = fs.realpathSync(root);
  assertControl(
    process.env.GOAL_CONTROL_TEST_MODE === '1'
      && resolvedRoot !== temporaryRoot
      && resolvedRoot.startsWith(`${temporaryRoot}${path.sep}`),
    'TEST_MODE_FORBIDDEN',
    `${variable} 只允许隔离测试 control root`,
  );
  assertControl(
    ['1', 'throw', 'exit'].includes(mode),
    'INVALID_TEST_FAULT',
    `${variable} 只能是 1/throw/exit`,
  );
  return mode;
}

function maybeInjectHandoffFault(root, variable, code, message, exitCode) {
  const mode = validatedHandoffFault(root, variable);
  if (mode === null) return;
  if (mode === 'exit') {
    throw new ControlError(code, message, {
      handoff_exit_code: exitCode,
      preserve_snapshot_staging:
        variable === 'GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH'
        || variable === 'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING',
    });
  }
  throw new ControlError(code, message);
}

function maybeExitCheckpointGitFenceForTest(root, variable, exitCode) {
  const mode = validatedHandoffFault(root, variable);
  if (mode === null) return;
  assertControl(
    mode === 'exit',
    'INVALID_TEST_FAULT',
    `${variable} 只接受 exit`,
  );
  process.exit(exitCode);
}

function exitDeferredHandoffFault(error) {
  const visited = new Set();
  let current = error;
  while (current && !visited.has(current)) {
    visited.add(current);
    const exitCode = current.details
      && current.details.handoff_exit_code;
    if (Number.isSafeInteger(exitCode)) process.exit(exitCode);
    current = current.cause;
  }
  throw error;
}

function validateCodexCaptureArtifact(snapshot, body, trackedPatch) {
  const capture = snapshot.source_capture;
  if (capture === undefined) return;
  const records = jsonlRecords(body, 'Codex rollout provenance');
  assertControl(
    records.length === ((capture.event_count + capture.excluded_patch_count) * 3) + 1,
    'HANDOFF_ARTIFACT_TAMPERED',
    'Codex rollout provenance record 数量不匹配',
  );
  const sessionRecord = records[0];
  assertControl(
    sessionRecord.line === capture.session_line
      && `sha256:${sha256(sessionRecord.raw)}` === capture.session_record_sha256,
    'HANDOFF_ARTIFACT_TAMPERED',
    'Codex rollout session_meta record hash 不匹配',
  );
  const meta = sessionRecord.value && sessionRecord.value.payload;
  assertControl(
    sessionRecord.value
      && sessionRecord.value.type === 'session_meta'
      && meta
      && meta.session_id === capture.session_id
      && meta.id === capture.session_id
      && meta.cwd === capture.session_cwd,
    'HANDOFF_ARTIFACT_TAMPERED',
    'Codex rollout provenance session_meta 不匹配',
  );
  const patchParts = [];
  for (let index = 0; index < capture.events.length; index += 1) {
    const expected = capture.events[index];
    const offset = 1 + (index * 3);
    const callRecord = records[offset];
    const eventRecord = records[offset + 1];
    const resultRecord = records[offset + 2];
    assertControl(
      `sha256:${sha256(callRecord.raw)}` === expected.call_record_sha256
        && `sha256:${sha256(eventRecord.raw)}` === expected.event_record_sha256
        && `sha256:${sha256(resultRecord.raw)}` === expected.result_record_sha256,
      'HANDOFF_ARTIFACT_TAMPERED',
      `Codex rollout ${expected.call_id} call/event/result record hash 不匹配`,
    );
    const call = validateCodexPatchCall(
      callRecord,
      snapshot.source_worktree,
      expected.call_id,
    );
    const validated = validateCodexPatchEvent(
      eventRecord,
      snapshot.source_worktree,
      call.paths,
      call.changedLines,
      call.hunks,
    );
    validateCodexPatchResult(resultRecord, expected.call_id);
    assertControl(
      callRecord.line === offset + 1
        && eventRecord.line === offset + 2
        && resultRecord.line === offset + 3
        && validated.callId === expected.call_id
        && validated.timestamp === expected.event_timestamp
        && validated.changeCount === expected.change_count,
      'HANDOFF_ARTIFACT_TAMPERED',
      `Codex rollout ${expected.call_id} sealed call/event/result 不匹配`,
    );
    patchParts.push(validated.patch);
  }
  const excludedOffset = 1 + (capture.event_count * 3);
  for (let index = 0; index < capture.excluded_patches.length; index += 1) {
    const expected = capture.excluded_patches[index];
    const offset = excludedOffset + (index * 3);
    const callRecord = records[offset];
    const eventRecord = records[offset + 1];
    const resultRecord = records[offset + 2];
    assertControl(
      `sha256:${sha256(callRecord.raw)}` === expected.call_record_sha256
        && `sha256:${sha256(eventRecord.raw)}` === expected.event_record_sha256
        && `sha256:${sha256(resultRecord.raw)}` === expected.result_record_sha256,
      'HANDOFF_ARTIFACT_TAMPERED',
      `excluded patch ${expected.call_id} record hash 不匹配`,
    );
    const callItem = callRecord.value;
    const callPayload = callItem && callItem.payload;
    assertControl(
      callItem
        && callItem.type === 'response_item'
        && callPayload
        && callPayload.type === 'custom_tool_call'
        && callPayload.name === 'apply_patch'
        && callPayload.status === 'completed'
        && callPayload.call_id === expected.call_id
        && applyPatchInputPaths(callPayload.input, snapshot.source_worktree).size === 0,
      'HANDOFF_ARTIFACT_TAMPERED',
      `excluded patch ${expected.call_id} call 非纯 outside`,
    );
    validateCodexPatchResult(resultRecord, expected.call_id);
    const excluded = validateOutsideCodexPatchEvent(
      eventRecord,
      snapshot.source_worktree,
      expected.call_id,
    );
    assertControl(
      excluded.timestamp === expected.event_timestamp
        && excluded.changeCount === expected.change_count,
      'HANDOFF_ARTIFACT_TAMPERED',
      `excluded patch ${expected.call_id} event metadata 不匹配`,
    );
  }
  assertControl(
    Buffer.concat(patchParts).equals(trackedPatch),
    'HANDOFF_ARTIFACT_TAMPERED',
    'Codex rollout provenance 重建 patch 与 tracked.patch 不一致',
  );
}

function validateSealedShellAudit(snapshot, auditBody, recordsBody) {
  const metadata = snapshot.source_capture.shell_audit;
  let audit;
  try {
    audit = JSON.parse(auditBody.toString('utf8'));
  } catch (error) {
    throw new ControlError('CODEX_ROLLOUT_SHELL_AUDIT_INVALID', `sealed shell audit 非法: ${error.message}`);
  }
  const records = jsonlRecords(recordsBody, 'Codex sealed shell records');
  assertControl(
    records.length === metadata.call_count * 2
      && Array.isArray(audit.calls)
      && audit.calls.length === metadata.call_count,
    'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
    'sealed shell records/audit call 数量不匹配',
  );
  const shellCalls = [];
  for (let index = 0; index < audit.calls.length; index += 1) {
    const asserted = audit.calls[index];
    const callRecord = records[index * 2];
    const resultRecord = records[(index * 2) + 1];
    const callItem = callRecord.value;
    const callPayload = callItem && callItem.payload;
    const resultItem = resultRecord.value;
    const resultPayload = resultItem && resultItem.payload;
    if (asserted.name === 'apply_patch') {
      assertControl(
        callItem
          && callItem.type === 'response_item'
          && callPayload
          && callPayload.type === 'custom_tool_call'
          && callPayload.name === 'apply_patch'
          && callPayload.call_id === asserted.call_id
          && applyPatchInputPaths(callPayload.input, snapshot.source_worktree).size === 0,
        'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
        `sealed outside apply_patch[${index}] identity/path 不匹配`,
      );
      assertControl(
        resultItem
          && resultItem.type === 'response_item'
          && resultPayload
          && resultPayload.type === 'custom_tool_call_output'
          && resultPayload.call_id === asserted.call_id,
        'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
        `sealed outside apply_patch result[${index}] identity 不匹配`,
      );
    } else {
      assertControl(
        callItem
          && callItem.type === 'response_item'
          && callPayload
          && callPayload.type === 'function_call'
          && (
            CODEX_AUDITED_FUNCTION_CALLS.has(callPayload.name)
            || CODEX_PROVABLY_NON_SOURCE_FUNCTION_CALLS.has(callPayload.name)
          )
          && callPayload.name === asserted.name
          && callPayload.call_id === asserted.call_id,
        'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
        `sealed Codex function call[${index}] identity 不匹配`,
      );
      parseCodexFunctionArguments(callRecord, callPayload);
      assertControl(
        resultItem
          && resultItem.type === 'response_item'
          && resultPayload
          && resultPayload.type === 'function_call_output'
          && resultPayload.call_id === asserted.call_id,
        'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
        `sealed shell result[${index}] identity 不匹配`,
      );
    }
    shellCalls.push({
      call_id: asserted.call_id,
      name: asserted.name,
      line: asserted.line,
      record_sha256: `sha256:${sha256(callRecord.raw)}`,
      result_line: asserted.result_line,
      result_record_sha256: `sha256:${sha256(resultRecord.raw)}`,
      required_disposition: asserted.name === 'apply_patch' ? 'IGNORED_PATH_ONLY' : undefined,
      raw_records: [callRecord.raw, resultRecord.raw],
    });
  }
  const validated = validateShellAuditObject(audit, {
    goal_id: snapshot.goal_id,
    task_id: snapshot.task_id,
    predecessor_launch_id: snapshot.predecessor_launch_id,
    predecessor_thread_id: snapshot.source_capture.session_id,
    predecessor_cwd: snapshot.source_worktree,
    predecessor_head: snapshot.source_launch_head,
    rollout_file_sha256: snapshot.source_capture.rollout_file_sha256,
    reconstructed_patch_sha256: snapshot.tracked_patch.sha256,
    captain_thread_id: metadata.captain_thread_id,
    foreman_thread_id: metadata.foreman_thread_id,
  }, shellCalls);
  assertControl(
    validated.audit.incident_ref === metadata.incident_ref,
    'CODEX_ROLLOUT_SHELL_AUDIT_MISMATCH',
    'sealed shell audit incident_ref 与 snapshot metadata 不匹配',
  );
}

function readSnapshotArtifactsFromDirectory(
  snapshotDirectory,
  goalId,
  taskId,
  snapshotId,
  expectedHash = undefined,
  manifestName = 'snapshot.json',
) {
  safeId(snapshotId, 'snapshot_id');
  const artifactRoot = canonicalDirectory(
    snapshotDirectory,
    'snapshot artifact directory',
  );
  const expectedManifest = path.join(artifactRoot, manifestName);
  const manifestFile = canonicalRegularFile(expectedManifest, 'recovery snapshot');
  assertControl(manifestFile === expectedManifest, 'HANDOFF_ARTIFACT_INVALID', 'snapshot manifest path 非 canonical');
  const snapshot = validateSnapshot(readJson(manifestFile, 'recovery snapshot'), {
    snapshot_id: snapshotId,
    goal_id: goalId,
    task_id: taskId,
  });
  if (expectedHash !== undefined) {
    assertControl(snapshot.snapshot_sha256 === normalizeHash(expectedHash, 'expected snapshot_sha256'), 'HANDOFF_SNAPSHOT_MISMATCH', 'snapshot hash 与请求不一致');
  }
  const readArtifact = (relative, size, digest, label) => {
    const absolute = path.join(artifactRoot, ...safeRelativePath(relative, `${label} path`).split('/'));
    const file = canonicalRegularFile(absolute, label);
    assertControl(file.startsWith(`${artifactRoot}${path.sep}`), 'HANDOFF_ARTIFACT_INVALID', `${label} 逃逸 snapshot directory`);
    const body = fs.readFileSync(file);
    assertControl(body.length === size, 'HANDOFF_ARTIFACT_TAMPERED', `${label} size 不匹配`);
    assertControl(`sha256:${sha256(body)}` === normalizeHash(digest, `${label} sha256`), 'HANDOFF_ARTIFACT_TAMPERED', `${label} hash 不匹配`);
    return body;
  };
  const patch = readArtifact(
    snapshot.tracked_patch.file,
    snapshot.tracked_patch.size,
    snapshot.tracked_patch.sha256,
    'tracked patch',
  );
  const entries = snapshot.untracked.map((entry) => ({
    ...entry,
    body: readArtifact(entry.artifact, entry.size, entry.sha256, `untracked ${entry.path}`),
  }));
  if (snapshot.source_capture !== undefined) {
    const provenance = readArtifact(
      snapshot.source_capture.artifact,
      snapshot.source_capture.size,
      snapshot.source_capture.sha256,
      'Codex rollout provenance',
    );
    validateCodexCaptureArtifact(snapshot, provenance, patch);
    if (snapshot.source_capture.shell_audit !== undefined) {
      const metadata = snapshot.source_capture.shell_audit;
      const auditBody = readArtifact(
        metadata.audit_artifact,
        metadata.audit_size,
        metadata.audit_sha256,
        'Codex shell audit',
      );
      const recordsBody = readArtifact(
        metadata.records_artifact,
        metadata.records_size,
        metadata.records_sha256,
        'Codex shell records',
      );
      validateSealedShellAudit(snapshot, auditBody, recordsBody);
    }
  }
  return { snapshot, manifestFile, patch, entries };
}

function readSnapshotArtifacts(root, goalId, taskId, snapshotId, expectedHash = undefined) {
  const paths = snapshotPaths(root, goalId, taskId, snapshotId);
  return readSnapshotArtifactsFromDirectory(
    paths.snapshotDir,
    goalId,
    taskId,
    snapshotId,
    expectedHash,
  );
}

function inspectPendingSourceSnapshotStaging(
  directory,
  goalId,
  taskId,
  snapshotId,
  manifestName = 'snapshot.json',
) {
  safeId(goalId, 'pending source goal_id');
  safeId(taskId, 'pending source task_id');
  safeId(snapshotId, 'pending source snapshot_id');
  assertControl(
    manifestName === 'snapshot.json'
      || atomicWriteStagingTarget(manifestName) === 'snapshot.json',
    'HANDOFF_STAGING_INVALID',
    `pending source manifest name 非协议 target: ${String(manifestName)}`,
  );
  assertCurrentOwnerOrdinary(
    fs.lstatSync(directory),
    'directory',
    'HANDOFF_STAGING_INVALID',
    `pending source snapshot ${snapshotId} 不是当前 owner 的 0700 普通目录`,
  );
  const entries = fs.readdirSync(directory).sort();
  const manifests = entries.filter((name) => (
    name === 'snapshot.json'
      || atomicWriteStagingTarget(name) === 'snapshot.json'
  ));
  assertControl(
    manifests.length === 1 && manifests[0] === manifestName,
    'HANDOFF_STAGING_INVALID',
    `pending source snapshot ${snapshotId} manifest lineage 分叉`,
  );
  const artifacts = readSnapshotArtifactsFromDirectory(
    directory,
    goalId,
    taskId,
    snapshotId,
    undefined,
    manifestName,
  );
  validateUnsealedSnapshotStaging(
    directory,
    snapshotId,
    artifacts.snapshot.operation_request.kind,
    { allowSealedManifest: manifestName === 'snapshot.json' },
  );
  if (entries.includes(PARTIAL_SNAPSHOT_BINDING_FILE)) {
    const binding = readPartialSnapshotBinding(
      directory,
      goalId,
      taskId,
      snapshotId,
    );
    assertPartialSnapshotBindingMatches(
      binding,
      partialSnapshotBinding(artifacts.snapshot),
    );
  }
  return {
    snapshot: artifacts.snapshot,
    manifest_file: artifacts.manifestFile,
  };
}

function receiptFile(root, goalId, taskId, receiptId) {
  safeId(receiptId, 'import_receipt_id');
  return path.join(root, 'goals', goalId, 'recovery-handoffs', taskId, 'import-receipts', `${receiptId}.json`);
}

function importIntentFile(root, goalId, taskId, importId) {
  safeId(importId, 'import_id');
  return path.join(
    root,
    'goals',
    goalId,
    'recovery-handoffs',
    taskId,
    'import-intents',
    importId,
    'intent.json',
  );
}

function validateImportIntentFile(file, goalId, taskId, importId) {
  assertCurrentOwnerOrdinary(
    fs.lstatSync(file),
    'file',
    'HANDOFF_STAGING_INVALID',
    `recovery import intent ${importId} 不是当前 owner 的 0600 普通文件`,
  );
  const intent = readJson(file, `recovery import intent ${importId}`);
  const keys = [
    'schema_version',
    'kind',
    'import_id',
    'goal_id',
    'task_id',
    'snapshot_id',
    'snapshot_sha256',
    'successor_thread_id',
    'request',
    'request_sha256',
    'prepared_request_sha256',
    'task_anchor',
    'acceptance_authority',
    'accepted_at',
    'intent_sha256',
  ];
  exactKeys(intent, keys, `recovery import intent ${importId}`);
  safeId(intent.import_id, 'recovery import intent import_id');
  safeId(intent.goal_id, 'recovery import intent goal_id');
  safeId(intent.task_id, 'recovery import intent task_id');
  safeId(intent.snapshot_id, 'recovery import intent snapshot_id');
  safeId(
    intent.successor_thread_id,
    'recovery import intent successor_thread_id',
  );
  normalizeHash(
    intent.snapshot_sha256,
    'recovery import intent snapshot_sha256',
  );
  normalizeHash(
    intent.request_sha256,
    'recovery import intent request_sha256',
  );
  normalizeHash(
    intent.prepared_request_sha256,
    'recovery import intent prepared_request_sha256',
  );
  normalizeHash(intent.intent_sha256, 'recovery import intent intent_sha256');
  exactKeys(
    intent.request,
    [
      'schema_version',
      'import_id',
      'goal_id',
      'task_id',
      'snapshot_id',
      'snapshot_sha256',
      'successor_thread_id',
      'destination',
    ],
    `recovery import intent ${importId} request`,
  );
  exactKeys(
    intent.request.destination,
    ['worktree', 'branch', 'head', 'repository_root', 'common_git_dir'],
    `recovery import intent ${importId} request destination`,
  );
  assertHistoricalDirectoryValue(
    intent.request.destination.worktree,
    `recovery import intent ${importId} destination worktree`,
  );
  assertHistoricalDirectoryValue(
    intent.request.destination.repository_root,
    `recovery import intent ${importId} destination repository_root`,
  );
  assertHistoricalDirectoryValue(
    intent.request.destination.common_git_dir,
    `recovery import intent ${importId} destination common_git_dir`,
  );
  assertFullSha(
    intent.request.destination.head,
    `recovery import intent ${importId} destination HEAD`,
  );
  assertControl(
    typeof intent.request.destination.branch === 'string'
      && intent.request.destination.branch.length > 0
      && intent.request.destination.branch.length <= 300
      && !/[\u0000-\u0020\u007f]/.test(intent.request.destination.branch),
    'HANDOFF_ARTIFACT_INVALID',
    `recovery import intent ${importId} destination branch 非法`,
  );
  exactKeys(
    intent.task_anchor,
    [
      'control_epoch',
      'state_revision',
      'packet_revision',
      'packet_sha256',
      'full_head',
    ],
    `recovery import intent ${importId} task_anchor`,
  );
  assertControl(
    Number.isSafeInteger(intent.task_anchor.control_epoch)
      && intent.task_anchor.control_epoch >= 0
      && Number.isSafeInteger(intent.task_anchor.state_revision)
      && intent.task_anchor.state_revision >= 0
      && Number.isSafeInteger(intent.task_anchor.packet_revision)
      && intent.task_anchor.packet_revision >= 0,
    'HANDOFF_ARTIFACT_INVALID',
    `recovery import intent ${importId} task_anchor revision 非法`,
  );
  normalizeHash(
    intent.task_anchor.packet_sha256,
    `recovery import intent ${importId} task_anchor packet_sha256`,
  );
  assertFullSha(
    intent.task_anchor.full_head,
    `recovery import intent ${importId} task_anchor full_head`,
  );
  exactKeys(
    intent.acceptance_authority,
    ['dev'],
    `recovery import intent ${importId} acceptance_authority`,
  );
  validateAcceptanceAuthority(intent.acceptance_authority.dev, 'DEV');
  assertControl(
    typeof intent.accepted_at === 'string'
      && Number.isFinite(Date.parse(intent.accepted_at)),
    'HANDOFF_ARTIFACT_INVALID',
    `recovery import intent ${importId} accepted_at 非法`,
  );
  const unsigned = { ...intent };
  delete unsigned.intent_sha256;
  assertControl(
    intent.schema_version === 1
      && intent.kind === 'RECOVERY_IMPORT_INTENT'
      && intent.goal_id === goalId
      && intent.task_id === taskId
      && intent.import_id === importId
      && intent.request.schema_version === 1
      && intent.request.import_id === intent.import_id
      && intent.request.goal_id === intent.goal_id
      && intent.request.task_id === intent.task_id
      && intent.request.snapshot_id === intent.snapshot_id
      && intent.request.snapshot_sha256 === intent.snapshot_sha256
      && intent.request.successor_thread_id === intent.successor_thread_id
      && intent.acceptance_authority.dev.thread_id
        === intent.successor_thread_id
      && intent.request_sha256 === hashObject(intent.request)
      && intent.prepared_request_sha256 === hashObject({
        request: intent.request,
        task_anchor: intent.task_anchor,
        acceptance_authority: intent.acceptance_authority,
      })
      && intent.intent_sha256 === hashObject(unsigned),
    'CORRUPT_STORE',
    `recovery import intent ${importId} seal 不匹配`,
  );
  return { intent, file };
}

function importIntentStagingName(
  importId,
  requestSha256,
  preparedRequestSha256,
) {
  return [
    '.init-import',
    sha256(importId),
    normalizeHash(requestSha256, 'import request_sha256')
      .slice('sha256:'.length),
    normalizeHash(preparedRequestSha256, 'import prepared_request_sha256')
      .slice('sha256:'.length),
  ].join('-');
}

function importIntentStagingDirectories(parent, importId) {
  if (!fs.existsSync(parent)) return [];
  const escaped = importId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const legacyPattern = new RegExp(
    `^\\.init-${escaped}\\.[1-9][0-9]*\\.tmp-[0-9a-f]{24}$`,
  );
  const legacyPrefix = `.init-${importId}.`;
  const importDigest = sha256(importId);
  const v2Prefix = `.init-import-${importDigest}-`;
  const v2Pattern = new RegExp(
    `^\\.init-import-${importDigest}-([0-9a-f]{64})-([0-9a-f]{64})$`,
  );
  const candidates = [];
  for (const name of fs.readdirSync(parent).sort()) {
    const legacy = legacyPattern.test(name);
    const v2 = v2Pattern.exec(name);
    if (!legacy && !v2) {
      assertControl(
        !name.startsWith(v2Prefix) && !name.startsWith(legacyPrefix),
        'HANDOFF_STAGING_INVALID',
        `import operation ${importId} 含 malformed v2 staging ${name}`,
      );
      continue;
    }
    candidates.push({
      name,
      directory: path.join(parent, name),
      format: v2 ? 'v2' : 'legacy',
      requestDigest: v2 ? v2[1] : null,
      preparedRequestDigest: v2 ? v2[2] : null,
    });
  }
  assertControl(
    candidates.length <= 1,
    'HANDOFF_STAGING_AMBIGUOUS',
    `import operation ${importId} 存在多份 durable staging`,
  );
  return candidates;
}

function recoverImportIntentStaging(
  root,
  goalId,
  taskId,
  importId,
  options = {},
) {
  const file = importIntentFile(root, goalId, taskId, importId);
  const stableDirectory = path.dirname(file);
  const parent = path.dirname(stableDirectory);
  const candidates = importIntentStagingDirectories(parent, importId);
  assertControl(
    !(fs.existsSync(stableDirectory) && candidates.length > 0),
    'HANDOFF_OPERATION_CONFLICT',
    `import operation ${importId} stable intent 与 staging 同时存在`,
  );
  if (fs.existsSync(stableDirectory)) {
    assertCurrentOwnerOrdinary(
      fs.lstatSync(stableDirectory),
      'directory',
      'HANDOFF_STAGING_INVALID',
      `import operation ${importId} stable intent 不是当前 owner 的 0700 普通目录`,
    );
    const stableEntries = fs.readdirSync(stableDirectory).sort();
    if (stableEntries.length === 0) {
      return {
        candidate: {
          directory: stableDirectory,
          format: 'atomic-stable',
          requestDigest: null,
          preparedRequestDigest: null,
        },
        directory: stableDirectory,
        sealed: false,
        empty: true,
        stable: true,
      };
    }
    assertControl(
      stableEntries.join('\0') === 'intent.json',
      'HANDOFF_STAGING_INVALID',
      `import operation ${importId} stable intent inventory 非协议状态`,
    );
    return {
      ...validateImportIntentFile(file, goalId, taskId, importId),
      directory: stableDirectory,
      sealed: true,
      stable: true,
    };
  }
  if (candidates.length === 0) return null;
  const candidate = candidates[0];
  assertCurrentOwnerOrdinary(
    fs.lstatSync(candidate.directory),
    'directory',
    'HANDOFF_STAGING_INVALID',
    `import operation ${importId} staging 不是当前 owner 的 0700 普通目录`,
  );
  const entries = fs.readdirSync(candidate.directory).sort();
  const atomicIntentTemporaries = entries.filter((entry) => (
    atomicWriteStagingTarget(entry) === 'intent.json'
  ));
  const hasCanonicalIntent = entries.includes('intent.json');
  assertControl(
    entries.length <= 1
      && atomicIntentTemporaries.length <= 1
      && !(hasCanonicalIntent && atomicIntentTemporaries.length > 0)
      && entries.every((entry) => (
        entry === 'intent.json'
          || atomicIntentTemporaries.includes(entry)
      )),
    'HANDOFF_STAGING_INVALID',
    `import operation ${importId} staging inventory 非协议状态`,
  );
  if (entries.length === 0) {
    return {
      candidate,
      directory: candidate.directory,
      sealed: false,
      empty: true,
    };
  }
  const intentName = hasCanonicalIntent
    ? 'intent.json'
    : atomicIntentTemporaries[0];
  const prepared = validateImportIntentFile(
    path.join(candidate.directory, intentName),
    goalId,
    taskId,
    importId,
  );
  if (candidate.format === 'v2') {
    assertControl(
      candidate.requestDigest
        === prepared.intent.request_sha256.slice('sha256:'.length)
        && candidate.preparedRequestDigest
          === prepared.intent.prepared_request_sha256.slice('sha256:'.length),
      'HANDOFF_STAGING_TAMPERED',
      `import operation ${importId} staging pathname/intent seal 不匹配`,
    );
  }
  if (!hasCanonicalIntent) {
    if (options.readOnly !== true) {
      fs.renameSync(
        path.join(candidate.directory, intentName),
        path.join(candidate.directory, 'intent.json'),
      );
      fsyncDirectory(candidate.directory);
    }
  }
  assertControl(
    !fs.existsSync(stableDirectory),
    'HANDOFF_OPERATION_CONFLICT',
    `import operation ${importId} stable intent 与 staging 同时存在`,
  );
  if (options.readOnly !== true) {
    fs.renameSync(candidate.directory, stableDirectory);
    fsyncDirectory(parent);
  }
  return {
    intent: prepared.intent,
    file: options.readOnly === true ? prepared.file : file,
    directory: options.readOnly === true
      ? candidate.directory
      : stableDirectory,
    sealed: true,
    stable: false,
  };
}

function publishImportIntent(root, unsigned, options = {}) {
  const file = importIntentFile(
    root,
    unsigned.goal_id,
    unsigned.task_id,
    unsigned.import_id,
  );
  const intent = {
    ...unsigned,
    intent_sha256: hashObject(unsigned),
  };
  const recovered = recoverImportIntentStaging(
    root,
    unsigned.goal_id,
    unsigned.task_id,
    unsigned.import_id,
  );
  if (recovered && recovered.sealed) {
    assertControl(
      hashObject(recovered.intent) === hashObject(intent),
      'HANDOFF_OPERATION_CONFLICT',
      `import operation ${unsigned.import_id} stable intent 不是 exact retry`,
    );
    return { intent: recovered.intent, file: recovered.file };
  }
  assertControl(
    (
      !recovered
        || (
          options.allowAtomicStableEmpty === true
            && recovered.empty === true
            && recovered.stable === true
            && recovered.candidate.format === 'atomic-stable'
        )
    )
      && !fs.existsSync(file),
    'HANDOFF_OPERATION_CONFLICT',
    `import operation ${unsigned.import_id} 含 unsealed legacy staging`,
  );
  assertControl(
    atomicCreate(
      file,
      `${JSON.stringify(intent, null, 2)}\n`,
      { fault_namespace: 'SOURCE_IMPORT_INTENT' },
    ),
    'HANDOFF_OPERATION_CONFLICT',
    `import operation ${unsigned.import_id} intent no-clobber publication 失败`,
  );
  return { intent, file };
}

function readReceipt(root, goalId, taskId, receiptId, expectedHash = undefined) {
  const expected = receiptFile(root, goalId, taskId, receiptId);
  const file = canonicalRegularFile(expected, 'recovery import receipt');
  assertControl(file === expected, 'HANDOFF_ARTIFACT_INVALID', 'import receipt path 非 canonical');
  const receipt = validateReceipt(readJson(file, 'recovery import receipt'), {
    import_receipt_id: receiptId,
    goal_id: goalId,
    task_id: taskId,
  });
  if (expectedHash !== undefined) {
    assertControl(receipt.import_receipt_sha256 === normalizeHash(expectedHash, 'expected import_receipt_sha256'), 'HANDOFF_RECEIPT_MISMATCH', 'receipt hash 与请求不一致');
  }
  return { receipt, file };
}

function findSnapshotReceipt(root, goalId, taskId, snapshotId) {
  const receiptsDir = snapshotPaths(root, goalId, taskId, snapshotId).receipts;
  if (!fs.existsSync(receiptsDir)) return null;
  let found = null;
  for (const name of fs.readdirSync(receiptsDir).filter((entry) => entry.endsWith('.json'))) {
    const expected = path.join(receiptsDir, name);
    const file = canonicalRegularFile(expected, `existing receipt ${name}`);
    assertControl(file === expected, 'HANDOFF_ARTIFACT_INVALID', `existing receipt ${name} path 非 canonical`);
    const receipt = validateReceipt(readJson(file, `existing receipt ${name}`));
    if (receipt.snapshot_id !== snapshotId) continue;
    assertControl(!found, 'HANDOFF_ARTIFACT_INVALID', `snapshot ${snapshotId} 存在多份 import receipt`);
    found = { receipt, file };
  }
  return found;
}

function exactOddRecoveryLockOptions(authorize, transactionKey) {
  let exactWitnessAuthorized = false;
  return {
    beforeGeneration: () => {
      exactWitnessAuthorized = authorize() === true;
    },
    transactionKey,
    authorizeOddRecovery: () => exactWitnessAuthorized,
    sameStableOperationMismatchCode: 'HANDOFF_OPERATION_CONFLICT',
    sameStableOperationMismatchMessage:
      'source handoff stable operation 已绑定不同 request',
  };
}

function readOnlyGoalLoadOptions(options = {}) {
  return {
    ...options,
    repairHeads: false,
    repairBootstrapConsumption: false,
  };
}

function authorizeSnapshotAcceptance(
  loaded,
  state,
  snapshot,
  captainCapabilityFile,
  foremanCapabilityFile,
) {
  authorizeSealedAuthority(
    state,
    captainCapabilityFile,
    snapshot.acceptance_authority.captain,
  );
  const sealedForeman = snapshot.acceptance_authority.foreman;
  if (sealedForeman) {
    authorizeSealedAuthority(
      state,
      foremanCapabilityFile,
      sealedForeman,
      { goalSnapshot: loaded.snapshot },
    );
  }
}

function authorizeExactExportOddRecovery(root, request) {
  const {
    goalId,
    taskId,
    snapshotId,
    successorThreadId,
    requestedOperation,
    captainCapabilityFile,
    foremanCapabilityFile,
    requireForeman,
  } = request;
  const paths = snapshotPaths(root, goalId, taskId, snapshotId);
  if (fs.existsSync(paths.snapshotDir)) {
    const artifacts = readSnapshotArtifacts(
      root,
      goalId,
      taskId,
      snapshotId,
    );
    assertExistingExportRequest(artifacts.snapshot, requestedOperation);
    const loaded = loadGoalUnlocked(
      root,
      goalId,
      readOnlyGoalLoadOptions(),
    );
    const state = loaded.snapshot.tasks[taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
    authorizeSnapshotAcceptance(
      loaded,
      state,
      artifacts.snapshot,
      captainCapabilityFile,
      foremanCapabilityFile,
    );
    return true;
  }

  const prepared = readPreparedSnapshotArtifacts(
    paths,
    goalId,
    taskId,
    snapshotId,
    requestedOperation,
    { readOnly: true },
  );
  if (!prepared) return false;
  // An empty v2 directory proves only hashes embedded in its pathname. The
  // complete execution/authority binding has not been durably published yet,
  // and recomputing the exact tree would require Git mutation. It is therefore
  // not sufficient authority to repair an already-odd control generation.
  if (!prepared.artifacts && !prepared.binding) return false;
  const loaded = loadGoalUnlocked(
    root,
    goalId,
    readOnlyGoalLoadOptions(
      preparedSourceExportGoalLoadOptions(
        prepared,
        snapshotId,
        requestedOperation,
      ),
    ),
  );
  const state = loaded.snapshot.tasks[taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
  if (prepared.artifacts) {
    const snapshot = prepared.artifacts.snapshot;
    assertExistingExportRequest(snapshot, requestedOperation);
    assertControl(
      state.phase !== 'ARCHIVED',
      'TASK_TERMINAL',
      `task ${taskId} 已 ARCHIVED，不得发布 prepared source export`,
    );
    const { successor } = sourceSessionContext(
      loaded,
      taskId,
      successorThreadId,
    );
    assertSnapshotCurrent(loaded, state, successor, snapshot);
    const predecessor = canonicalLaunch(loaded, taskId, successor);
    assertSnapshotPredecessorBinding(snapshot, predecessor);
    assertControl(
      predecessor.sha256 === snapshot.predecessor_launch_sha256,
      'HANDOFF_LAUNCH_TAMPERED',
      'prepared source export predecessor launch hash 已变化',
    );
    authorizeSnapshotAcceptance(
      loaded,
      state,
      snapshot,
      captainCapabilityFile,
      foremanCapabilityFile,
    );
    return true;
  }

  authorizeSession(
    state,
    captainCapabilityFile,
    { role: 'CAPTAIN' },
  );
  if (requireForeman) {
    authorizeGoalSession(
      loaded.snapshot,
      foremanCapabilityFile,
      { role: 'FOREMAN' },
    );
  }
  return true;
}

function exportOddRecoveryLockOptions(root, request) {
  return exactOddRecoveryLockOptions(
    () => authorizeExactExportOddRecovery(root, request),
    sourceExportTransactionKey(
      request.goalId,
      request.taskId,
      request.snapshotId,
      request.requestedOperation,
    ),
  );
}

function recoveryImportRequest(
  goalId,
  taskId,
  importId,
  snapshot,
  successorThreadId,
  destination,
) {
  return {
    schema_version: 1,
    import_id: importId,
    goal_id: goalId,
    task_id: taskId,
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    successor_thread_id: successorThreadId,
    destination: {
      worktree: destination.worktree,
      branch: destination.branch,
      head: destination.head,
      repository_root: destination.repository_root,
      common_git_dir: destination.common_git_dir,
    },
  };
}

function importRecoveryRequestContext(root, cwd, request) {
  const {
    goalId,
    taskId,
    importId,
    snapshotId,
    successorThreadId,
  } = request;
  const artifacts = readSnapshotArtifacts(
    root,
    goalId,
    taskId,
    snapshotId,
  );
  const snapshot = artifacts.snapshot;
  assertExactTreeSnapshot(snapshot);
  assertControl(
    snapshot.successor_thread_id === successorThreadId,
    'HANDOFF_SNAPSHOT_MISMATCH',
    'snapshot successor 不匹配',
  );
  const destination = repositoryIdentity(cwd);
  const importRequest = recoveryImportRequest(
    goalId,
    taskId,
    importId,
    snapshot,
    successorThreadId,
    destination,
  );
  return {
    artifacts,
    snapshot,
    destination,
    importRequest,
    requestSha256: hashObject(importRequest),
  };
}

function sourceImportTransactionKey(request, context) {
  return canonicalTransactionKey(
    'SOURCE_IMPORT',
    sourceTransactionScope(request.goalId, request.taskId),
    request.importId,
    context.requestSha256,
  );
}

function authorizeExactImportOddRecovery(
  root,
  cwd,
  request,
  recoveryContext = null,
) {
  const {
    goalId,
    taskId,
    importId,
    snapshotId,
    successorThreadId,
    actorCapabilityFile,
  } = request;
  const context = recoveryContext
    || importRecoveryRequestContext(root, cwd, request);
  const {
    snapshot,
    destination,
    importRequest,
    requestSha256: importRequestSha256,
  } = context;
  const existingImport = findSnapshotReceipt(
    root,
    goalId,
    taskId,
    snapshotId,
  );
  const requestedReceiptFile = receiptFile(root, goalId, taskId, importId);
  if (!existingImport && fs.existsSync(requestedReceiptFile)) {
    readReceipt(root, goalId, taskId, importId);
    assertControl(
      false,
      'HANDOFF_OPERATION_CONFLICT',
      `import operation ${importId} 已绑定其它 snapshot`,
    );
  }
  if (
    existingImport
      && existingImport.receipt.schema_version === RECEIPT_SCHEMA_VERSION
  ) {
    assertControl(
      existingImport.receipt.import_receipt_id === importId,
      'HANDOFF_SNAPSHOT_ALREADY_IMPORTED',
      `snapshot ${snapshotId} 已由 import operation ${existingImport.receipt.import_receipt_id} 导入`,
    );
    assertReceiptSnapshotBinding(existingImport.receipt, snapshot, {
      goalId,
      taskId,
      successorThreadId,
    });
    const loaded = loadGoalUnlocked(
      root,
      goalId,
      readOnlyGoalLoadOptions(),
    );
    const state = loaded.snapshot.tasks[taskId];
    assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
    authorizeSealedAuthority(
      state,
      actorCapabilityFile,
      existingImport.receipt.acceptance_authority.dev,
    );
    assertReceiptDestinationIdentity(
      destination,
      snapshot,
      existingImport.receipt,
    );
    return true;
  }

  const recovered = recoverImportIntentStaging(
    root,
    goalId,
    taskId,
    importId,
    { readOnly: true },
  );
  if (!recovered || !recovered.sealed) return false;
  const intent = recovered.intent;
  assertControl(
    intent.request_sha256 === importRequestSha256
      && hashObject(intent.request) === importRequestSha256
      && intent.snapshot_sha256 === snapshot.snapshot_sha256
      && intent.successor_thread_id === successorThreadId,
    'HANDOFF_OPERATION_CONFLICT',
    `import operation ${importId} 已绑定不同 request/destination`,
  );
  const loaded = loadGoalUnlocked(
    root,
    goalId,
    readOnlyGoalLoadOptions({
      allowPendingGoalOperation: {
        kind: 'SOURCE_IMPORT',
        operation_id: importId,
        request_sha256: importRequestSha256,
      },
    }),
  );
  const state = loaded.snapshot.tasks[taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
  authorizeSealedAuthority(
    state,
    actorCapabilityFile,
    intent.acceptance_authority.dev,
  );
  return true;
}

function importOddRecoveryLockOptions(root, cwd, request, retryBoundary) {
  let recoveryContext = null;
  const context = () => {
    if (recoveryContext === null) {
      recoveryContext = importRecoveryRequestContext(root, cwd, request);
    }
    return recoveryContext;
  };
  let exactWitnessAuthorized = false;
  return {
    beforeGeneration: (transaction) => {
      retryBoundary.transactionStartedAt =
        transaction.transaction_started_at;
      retryBoundary.historicalRetry =
        isOddTransactionRetry(transaction.mode);
      exactWitnessAuthorized = authorizeExactImportOddRecovery(
        root,
        cwd,
        request,
        context(),
      ) === true;
    },
    transactionKey: () => sourceImportTransactionKey(request, context()),
    authorizeOddRecovery: () => exactWitnessAuthorized,
    sameStableOperationMismatchCode: 'HANDOFF_OPERATION_CONFLICT',
    sameStableOperationMismatchMessage:
      'source import stable operation 已绑定不同 request',
  };
}

function assertReceiptSnapshotBinding(receipt, snapshot, request) {
  assertControl(
    [
      EXACT_TREE_RECEIPT_SCHEMA_VERSION,
      RECEIPT_SCHEMA_VERSION,
    ].includes(receipt.schema_version)
      && receipt.snapshot_sha256 === snapshot.snapshot_sha256
      && receipt.goal_id === request.goalId
      && receipt.task_id === request.taskId
      && receipt.successor_thread_id === request.successorThreadId
      && receipt.predecessor_launch_id === snapshot.predecessor_launch_id
      && receipt.predecessor_launch_sha256 === snapshot.predecessor_launch_sha256
      && receipt.source_worktree === snapshot.source_worktree
      && receipt.source_branch === snapshot.source_branch
      && receipt.source_launch_head === snapshot.source_launch_head
      && receipt.source_observed_head === snapshot.source_observed_head
      && receipt.expected_tree === snapshot.expected_tree
      && receipt.materialized_tree === snapshot.expected_tree,
    'HANDOFF_SNAPSHOT_ALREADY_IMPORTED',
    `snapshot ${snapshot.snapshot_id} 已由其它 import request 导入`,
  );
}

function assertReceiptDestinationIdentity(destination, snapshot, receipt) {
  assertControl(
    receipt.destination_worktree === destination.worktree
      && receipt.destination_branch === destination.branch
      && destination.common_git_dir === snapshot.common_git_dir
      && destination.repository_root === snapshot.repository_root,
    'HANDOFF_SNAPSHOT_ALREADY_IMPORTED',
    `snapshot ${snapshot.snapshot_id} 已由其它 destination identity 导入`,
  );
}

function importReceiptResult(existing, idempotent) {
  return {
    ...existing.receipt,
    import_receipt_file: existing.file,
    idempotent,
  };
}

function exportRecoverySnapshot(cwd, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const snapshotId = safeId(options.snapshotId, 'snapshot_id');
  const successorThreadId = safeId(options.successorThreadId, 'successor_thread_id');
  const requestedWorktree = exportRequestWorktree(
    options,
    cwd,
    'requested predecessor worktree',
  );
  const requestedOperation = {
    kind: 'SOURCE_WORKTREE',
    repository_worktree: requestedWorktree,
    successor_thread_id: successorThreadId,
  };
  const root = controlRoot(cwd);
  let published = false;
  let result;
  try {
    result = withLock(root, () => {
    const paths = snapshotPaths(root, goalId, taskId, snapshotId);
    ensureDir(paths.snapshots);
    if (fs.existsSync(paths.snapshotDir)) {
      const artifacts = readSnapshotArtifacts(root, goalId, taskId, snapshotId);
      assertExistingExportRequest(artifacts.snapshot, requestedOperation);
      const loaded = loadGoalUnlocked(root, goalId);
      const state = loaded.snapshot.tasks[taskId];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
      authorizeSealedAuthority(
        state,
        options.captainCapabilityFile,
        artifacts.snapshot.acceptance_authority.captain,
      );
      return exportSnapshotResult(artifacts, true);
    }

    const prepared = readPreparedSnapshotArtifacts(
      paths,
      goalId,
      taskId,
      snapshotId,
      requestedOperation,
    );
    if (prepared && prepared.artifacts) {
      assertExistingExportRequest(
        prepared.artifacts.snapshot,
        requestedOperation,
      );
      const loaded = loadGoalUnlocked(
        root,
        goalId,
        preparedSourceExportGoalLoadOptions(
          prepared,
          snapshotId,
          requestedOperation,
        ),
      );
      const state = loaded.snapshot.tasks[taskId];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
      assertControl(
        state.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${taskId} 已 ARCHIVED，不得发布 prepared source export`,
      );
      const { successor } = sourceSessionContext(
        loaded,
        taskId,
        successorThreadId,
      );
      assertSnapshotCurrent(
        loaded,
        state,
        successor,
        prepared.artifacts.snapshot,
      );
      const predecessor = canonicalLaunch(loaded, taskId, successor);
      assertSnapshotPredecessorBinding(
        prepared.artifacts.snapshot,
        predecessor,
      );
      assertControl(
        predecessor.sha256
          === prepared.artifacts.snapshot.predecessor_launch_sha256,
        'HANDOFF_LAUNCH_TAMPERED',
        'prepared source export predecessor launch hash 已变化',
      );
      authorizeSealedAuthority(
        state,
        options.captainCapabilityFile,
        prepared.artifacts.snapshot.acceptance_authority.captain,
      );
      const { assertNoPendingTaskOperations } = require('./pending-operations');
      assertNoPendingTaskOperations(root, goalId, taskId, {
        allowOperationKind: 'SOURCE_EXPORT',
        allowOperationId: snapshotId,
        allowRequestSha256: hashObject(
          preliminaryExportOperationRequest(requestedOperation),
        ),
      });
      const artifacts = publishPreparedSnapshot(paths, prepared);
      published = true;
      return exportSnapshotResult(artifacts, true);
    }

    const loaded = loadGoalUnlocked(
      root,
      goalId,
      preparedSourceExportGoalLoadOptions(
        prepared,
        snapshotId,
        requestedOperation,
      ),
    );
    const { state, successor } = sourceSessionContext(loaded, taskId, successorThreadId);
    const captain = authorizeSession(
      state,
      options.captainCapabilityFile,
      { role: 'CAPTAIN' },
    );
    const captainAuthority = authorityFromSession(captain);
    const predecessor = canonicalLaunch(loaded, taskId, successor);
    const source = repositoryIdentity(
      canonicalDirectory(requestedWorktree, 'requested predecessor worktree'),
    );
    const launchWorktree = canonicalDirectory(predecessor.launch.repository.worktree, 'predecessor launch worktree');
    const launchRoot = canonicalDirectory(predecessor.launch.repository.root, 'predecessor launch repository root');
    const launchThreadCwd = canonicalDirectory(predecessor.launch.thread.cwd, 'predecessor launch thread cwd');
    assertControl(source.worktree === launchWorktree && source.worktree === launchThreadCwd, 'HANDOFF_SOURCE_WORKTREE_MISMATCH', '只能从 predecessor canonical launch 原工作树导出');
    assertControl(source.repository_root === launchRoot, 'REPOSITORY_ROOT_MISMATCH', 'source repository root 与 predecessor launch 不一致');
    assertControl(source.branch === predecessor.launch.repository.branch, 'BRANCH_MISMATCH', 'source branch 与 predecessor launch 不一致');
    assertControl(
      source.repository_root === canonicalDirectory(loaded.meta.repository_root, 'Goal repository root'),
      'REPOSITORY_ROOT_MISMATCH',
      'source 不属于 Goal 初始化仓库',
    );
    assertAncestor(source.worktree, predecessor.launch.repository.full_head, source.head);
    assertNoUnmerged(source.worktree);

    const patch = trackedPatch(source.worktree, source.head);
    const untracked = readUntrackedEntries(source.worktree);
    const totalBytes = patch.length + untracked.totalBytes;
    assertControl(totalBytes <= MAX_SNAPSHOT_BYTES, 'HANDOFF_SNAPSHOT_TOO_LARGE', `snapshot 超过 ${MAX_SNAPSHOT_BYTES} bytes`);
    const expected = expectedSnapshotTree(
      source.worktree,
      source.head,
      patch,
      untracked.entries,
    );
    assertSourceStable(source.worktree, source.head, source.branch, patch, untracked.entries);

    const patchRelative = 'tracked.patch';
    const manifestEntries = untracked.entries.map((entry, index) => ({
      path: entry.path,
      type: entry.type,
      mode: entry.mode,
      size: entry.size,
      sha256: entry.sha256,
      artifact: `untracked/${String(index + 1).padStart(6, '0')}.bin`,
    }));
    const unsigned = {
      schema_version: SNAPSHOT_SCHEMA_VERSION,
      snapshot_id: snapshotId,
      goal_id: goalId,
      task_id: taskId,
      successor_thread_id: successorThreadId,
      control_epoch: loaded.control.epoch,
      packet_revision: state.packet.revision,
      packet_sha256: state.packet.sha256,
      task_full_head: state.full_head,
      predecessor_launch_id: predecessor.launch.launch_id,
      predecessor_launch_sha256: predecessor.sha256,
      source_worktree: source.worktree,
      source_branch: source.branch,
      source_launch_head: predecessor.launch.repository.full_head,
      source_observed_head: source.head,
      repository_root: source.repository_root,
      common_git_dir: source.common_git_dir,
      tracked_patch: {
        file: patchRelative,
        size: patch.length,
        sha256: `sha256:${sha256(patch)}`,
      },
      untracked: manifestEntries,
      expected_tree: expected.tree,
      expected_paths: expected.paths,
      operation_request: requestedOperation,
      acceptance_authority: {
        captain: captainAuthority,
      },
      total_bytes: totalBytes,
      created_at: nowIso(),
    };
    const snapshot = { ...unsigned, snapshot_sha256: hashObject(unsigned) };
    validateSnapshot(snapshot);
    const binding = partialSnapshotBinding(unsigned);
    if (prepared) {
      removeUnsealedSnapshotStaging(
        root,
        paths,
        prepared.directory,
        snapshotId,
        requestedOperation.kind,
        prepared.binding,
        binding,
        prepared.discarded,
        prepared.bindingDigest,
      );
    }
    const { assertNoPendingTaskOperations } = require('./pending-operations');
    assertNoPendingTaskOperations(root, goalId, taskId);

    const temporaryDir = path.join(
      paths.snapshots,
      partialSnapshotStagingName(snapshotId, binding),
    );
    assertControl(
      Buffer.byteLength(path.basename(temporaryDir)) <= 255,
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} staging name 超过 NAME_MAX`,
    );
    fs.mkdirSync(temporaryDir, { mode: 0o700 });
    maybeInjectHandoffFault(
      root,
      'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_STAGING_MKDIR',
      'TEST_FAULT_AFTER_SNAPSHOT_STAGING_MKDIR',
      'injected failure after recovery snapshot staging mkdir',
      93,
    );
    try {
      atomicWriteSnapshotProtocolJson(
        root,
        path.join(temporaryDir, PARTIAL_SNAPSHOT_BINDING_FILE),
        binding,
        {
          variable: 'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_TEMP_FSYNC',
          code: 'TEST_FAULT_AFTER_SNAPSHOT_BINDING_TEMP_FSYNC',
          message: 'injected failure after snapshot binding atomic temp fsync',
          exitCode: 94,
        },
      );
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_PUBLISH',
        'TEST_FAULT_AFTER_SNAPSHOT_BINDING_PUBLISH',
        'injected failure after snapshot binding publication',
        96,
      );
      atomicWrite(path.join(temporaryDir, patchRelative), patch);
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING',
        'TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING',
        'injected failure after partial recovery snapshot staging',
        91,
      );
      untracked.entries.forEach((entry, index) => {
        if (index === 0) {
          fs.mkdirSync(path.join(temporaryDir, 'untracked'), { mode: 0o700 });
        }
        atomicWrite(
          path.join(temporaryDir, manifestEntries[index].artifact),
          entry.body,
        );
      });
      atomicWriteSnapshotProtocolJson(
        root,
        path.join(temporaryDir, 'snapshot.json'),
        snapshot,
        {
          variable: 'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_MANIFEST_TEMP_FSYNC',
          code: 'TEST_FAULT_AFTER_SNAPSHOT_MANIFEST_TEMP_FSYNC',
          message: 'injected failure after snapshot manifest atomic temp fsync',
          exitCode: 95,
        },
      );
      assertControl(!fs.existsSync(paths.snapshotDir), 'HANDOFF_ARTIFACT_EXISTS', `snapshot ${snapshotId} 已存在`);
      fsyncDirectory(temporaryDir);
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH',
        'TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH',
        'injected failure before recovery snapshot publication',
        85,
      );
      fs.renameSync(temporaryDir, paths.snapshotDir);
      fsyncDirectory(paths.snapshots);
      published = true;
      return exportSnapshotResult({
        snapshot,
        manifestFile: path.join(paths.snapshotDir, 'snapshot.json'),
      }, false);
    } catch (error) {
      throw error;
    }
    }, exportOddRecoveryLockOptions(root, {
      goalId,
      taskId,
      snapshotId,
      successorThreadId,
      requestedOperation,
      captainCapabilityFile: options.captainCapabilityFile,
      foremanCapabilityFile: null,
      requireForeman: false,
    }));
  } catch (error) {
    exitDeferredHandoffFault(error);
  }
  if (published) {
    try {
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PUBLISH',
        'TEST_FAULT_AFTER_SNAPSHOT_PUBLISH',
        'injected failure after durable recovery snapshot publication',
        86,
      );
    } catch (error) {
      exitDeferredHandoffFault(error);
    }
  }
  return result;
}

function exportRecoverySnapshotFromCodexRollout(cwd, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const snapshotId = safeId(options.snapshotId, 'snapshot_id');
  const successorThreadId = safeId(options.successorThreadId, 'successor_thread_id');
  const expectedPredecessorLaunchId = safeId(options.predecessorLaunchId, 'predecessor_launch_id');
  const expectedPredecessorThreadId = safeId(options.predecessorThreadId, 'predecessor_thread_id');
  const hasShellAudit = Boolean(options.shellAuditFile || options.foremanCapabilityFile);
  assertControl(
    !hasShellAudit || (options.shellAuditFile && options.foremanCapabilityFile),
    'CODEX_ROLLOUT_SHELL_AUDIT_REQUIRED',
    '--shell-audit-file 与 --foreman-capability-file 必须同时提供',
  );
  const requestedWorktree = exportRequestWorktree(
    options,
    cwd,
    'requested Codex broker worktree',
  );
  const requestedRolloutFile = exportRequestFile(
    options.rolloutFile,
    'requested Codex rollout file',
  );
  const requestedShellAuditFile = options.shellAuditFile
    ? exportRequestFile(options.shellAuditFile, 'requested Codex shell audit file')
    : null;
  const requestedOperation = {
    kind: 'CODEX_ROLLOUT',
    repository_worktree: requestedWorktree,
    successor_thread_id: successorThreadId,
    predecessor_launch_id: expectedPredecessorLaunchId,
    predecessor_thread_id: expectedPredecessorThreadId,
    rollout_file: requestedRolloutFile,
    shell_audit_file: requestedShellAuditFile,
  };
  const root = controlRoot(cwd);
  let published = false;
  let result;
  try {
    result = withLock(root, () => {
    const paths = snapshotPaths(root, goalId, taskId, snapshotId);
    ensureDir(paths.snapshots);
    if (fs.existsSync(paths.snapshotDir)) {
      const artifacts = readSnapshotArtifacts(root, goalId, taskId, snapshotId);
      assertExistingExportRequest(artifacts.snapshot, requestedOperation);
      const loaded = loadGoalUnlocked(root, goalId);
      const state = loaded.snapshot.tasks[taskId];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
      authorizeSealedAuthority(
        state,
        options.captainCapabilityFile,
        artifacts.snapshot.acceptance_authority.captain,
      );
      const sealedForeman = artifacts.snapshot.acceptance_authority.foreman;
      if (sealedForeman) {
        authorizeSealedAuthority(
          state,
          options.foremanCapabilityFile,
          sealedForeman,
          { goalSnapshot: loaded.snapshot },
        );
      }
      return exportSnapshotResult(artifacts, true);
    }

    const prepared = readPreparedSnapshotArtifacts(
      paths,
      goalId,
      taskId,
      snapshotId,
      requestedOperation,
    );
    if (prepared && prepared.artifacts) {
      assertExistingExportRequest(
        prepared.artifacts.snapshot,
        requestedOperation,
      );
      const loaded = loadGoalUnlocked(
        root,
        goalId,
        preparedSourceExportGoalLoadOptions(
          prepared,
          snapshotId,
          requestedOperation,
        ),
      );
      const state = loaded.snapshot.tasks[taskId];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
      assertControl(
        state.phase !== 'ARCHIVED',
        'TASK_TERMINAL',
        `task ${taskId} 已 ARCHIVED，不得发布 prepared source export`,
      );
      const { successor } = sourceSessionContext(
        loaded,
        taskId,
        successorThreadId,
      );
      assertSnapshotCurrent(
        loaded,
        state,
        successor,
        prepared.artifacts.snapshot,
      );
      const predecessor = canonicalLaunch(loaded, taskId, successor);
      assertSnapshotPredecessorBinding(
        prepared.artifacts.snapshot,
        predecessor,
      );
      assertControl(
        predecessor.sha256
          === prepared.artifacts.snapshot.predecessor_launch_sha256,
        'HANDOFF_LAUNCH_TAMPERED',
        'prepared source export predecessor launch hash 已变化',
      );
      authorizeSealedAuthority(
        state,
        options.captainCapabilityFile,
        prepared.artifacts.snapshot.acceptance_authority.captain,
      );
      const sealedForeman =
        prepared.artifacts.snapshot.acceptance_authority.foreman;
      if (sealedForeman) {
        authorizeSealedAuthority(
          state,
          options.foremanCapabilityFile,
          sealedForeman,
          { goalSnapshot: loaded.snapshot },
        );
      }
      const { assertNoPendingTaskOperations } = require('./pending-operations');
      assertNoPendingTaskOperations(root, goalId, taskId, {
        allowOperationKind: 'SOURCE_EXPORT',
        allowOperationId: snapshotId,
        allowRequestSha256: hashObject(
          preliminaryExportOperationRequest(requestedOperation),
        ),
      });
      const artifacts = publishPreparedSnapshot(paths, prepared);
      published = true;
      return exportSnapshotResult(artifacts, true);
    }

    const loaded = loadGoalUnlocked(
      root,
      goalId,
      preparedSourceExportGoalLoadOptions(
        prepared,
        snapshotId,
        requestedOperation,
      ),
    );
    const { state, successor } = sourceSessionContext(loaded, taskId, successorThreadId);
    const captain = authorizeSession(state, options.captainCapabilityFile, { role: 'CAPTAIN' });
    const foreman = hasShellAudit
      ? authorizeGoalSession(loaded.snapshot, options.foremanCapabilityFile, { role: 'FOREMAN' })
      : null;
    const captainAuthority = authorityFromSession(captain);
    const foremanAuthority = foreman ? authorityFromSession(foreman) : null;
    const predecessor = canonicalLaunch(loaded, taskId, successor);
    assertControl(
      predecessor.launch.launch_id === expectedPredecessorLaunchId
        && predecessor.launch.thread.id === expectedPredecessorThreadId
        && successor.recovered_from.thread_id === expectedPredecessorThreadId,
      'RECOVERY_HANDOFF_MISMATCH',
      '请求的 predecessor launch/thread 与 recovery lineage 不一致',
    );
    const sourceWorktree = assertHistoricalDirectoryValue(
      predecessor.launch.repository.worktree,
      'predecessor historical worktree',
    );
    assertControl(
      predecessor.launch.thread.cwd === sourceWorktree,
      'RECOVERY_HANDOFF_MISMATCH',
      'predecessor launch thread.cwd 与 repository.worktree 不一致',
    );
    const currentWorktree = canonicalDirectory(
      repoRoot(canonicalDirectory(requestedWorktree, 'requested Codex broker worktree')),
      'broker repository worktree',
    );
    const commonGitDir = canonicalDirectory(
      gitText(currentWorktree, ['rev-parse', '--path-format=absolute', '--git-common-dir']),
      'broker git common dir',
    );
    const repositoryRoot = canonicalDirectory(path.dirname(commonGitDir), 'broker repository root');
    assertControl(
      repositoryRoot === canonicalDirectory(predecessor.launch.repository.root, 'predecessor repository root')
        && repositoryRoot === canonicalDirectory(loaded.meta.repository_root, 'Goal repository root'),
      'REPOSITORY_ROOT_MISMATCH',
      'rollout broker repository 与 predecessor/Goal repository 不一致',
    );
    gitRun(currentWorktree, ['cat-file', '-e', `${predecessor.launch.repository.full_head}^{commit}`], {
      code: 'HANDOFF_BASE_MISMATCH',
      label: 'predecessor launch HEAD object',
    });
    const capture = extractCodexRolloutCapture(
      requestedRolloutFile,
      sourceWorktree,
      expectedPredecessorThreadId,
      { allowShellAudit: hasShellAudit },
    );
    if (predecessor.predecessorSession.recovery_promotion) {
      const promotedAt = Date.parse(
        predecessor.predecessorSession.recovery_promotion.promoted_at,
      );
      assertControl(
        Number.isFinite(promotedAt),
        'RECOVERY_HANDOFF_MISMATCH',
        'recovered predecessor promotion timestamp 非法',
      );
      assertControl(
        capture.events.every((event) => Date.parse(event.event_timestamp) >= promotedAt),
        'CODEX_ROLLOUT_PRE_PROMOTION_PATCH',
        'rollout 含 recovery promotion 前的 target patch，拒绝事后合法化',
      );
    }
    const shellAudit = hasShellAudit
      ? validateShellAuditFile(requestedShellAuditFile, {
        goal_id: goalId,
        task_id: taskId,
        predecessor_launch_id: predecessor.launch.launch_id,
        predecessor_thread_id: predecessor.launch.thread.id,
        predecessor_cwd: sourceWorktree,
        predecessor_head: predecessor.launch.repository.full_head,
        rollout_file_sha256: capture.rolloutSha256,
        reconstructed_patch_sha256: `sha256:${sha256(capture.patch)}`,
        captain_thread_id: captain.thread_id,
        foreman_thread_id: foreman.thread_id,
      }, capture.shellCalls)
      : null;
    const expected = assertCodexCaptureTree(
      currentWorktree,
      predecessor.launch.repository.full_head,
      capture,
    );
    const patchRelative = 'tracked.patch';
    const provenanceRelative = 'provenance/codex-rollout-events.jsonl';
    const shellAuditRelative = 'provenance/codex-shell-audit.json';
    const shellRecordsRelative = 'provenance/codex-shell-records.jsonl';
    const sourceCapture = {
      kind: CODEX_ROLLOUT_CAPTURE_KIND,
      artifact: provenanceRelative,
      size: capture.provenance.length,
      sha256: `sha256:${sha256(capture.provenance)}`,
      rollout_file_sha256: capture.rolloutSha256,
      session_id: expectedPredecessorThreadId,
      session_cwd: sourceWorktree,
      session_line: capture.sessionRecord.line,
      session_record_sha256: `sha256:${sha256(capture.sessionRecord.raw)}`,
      event_count: capture.events.length,
      events: capture.events,
      excluded_patch_count: capture.excludedPatches.length,
      excluded_patches: capture.excludedPatches,
    };
    if (shellAudit) {
      sourceCapture.shell_audit = {
        kind: CODEX_SHELL_AUDIT_KIND,
        audit_artifact: shellAuditRelative,
        audit_size: shellAudit.body.length,
        audit_sha256: `sha256:${sha256(shellAudit.body)}`,
        records_artifact: shellRecordsRelative,
        records_size: shellAudit.records.length,
        records_sha256: `sha256:${sha256(shellAudit.records)}`,
        call_count: shellAudit.audit.calls.length,
        incident_ref: shellAudit.audit.incident_ref,
        captain_thread_id: captain.thread_id,
        foreman_thread_id: foreman.thread_id,
      };
    }
    const unsigned = {
      schema_version: SNAPSHOT_SCHEMA_VERSION,
      snapshot_id: snapshotId,
      goal_id: goalId,
      task_id: taskId,
      successor_thread_id: successorThreadId,
      control_epoch: loaded.control.epoch,
      packet_revision: state.packet.revision,
      packet_sha256: state.packet.sha256,
      task_full_head: state.full_head,
      predecessor_launch_id: predecessor.launch.launch_id,
      predecessor_launch_sha256: predecessor.sha256,
      source_worktree: sourceWorktree,
      source_branch: predecessor.launch.repository.branch,
      source_launch_head: predecessor.launch.repository.full_head,
      source_observed_head: predecessor.launch.repository.full_head,
      repository_root: repositoryRoot,
      common_git_dir: commonGitDir,
      tracked_patch: {
        file: patchRelative,
        size: capture.patch.length,
        sha256: `sha256:${sha256(capture.patch)}`,
      },
      untracked: [],
      source_capture: sourceCapture,
      expected_tree: expected.tree,
      expected_paths: expected.paths,
      operation_request: {
        ...requestedOperation,
        rollout_file: {
          path: requestedRolloutFile,
          sha256: capture.rolloutSha256,
        },
        shell_audit_file: shellAudit
          ? {
            path: requestedShellAuditFile,
            sha256: `sha256:${sha256(shellAudit.body)}`,
          }
          : null,
      },
      acceptance_authority: {
        captain: captainAuthority,
        ...(foremanAuthority ? { foreman: foremanAuthority } : {}),
      },
      total_bytes: capture.patch.length,
      created_at: nowIso(),
    };
    const snapshot = { ...unsigned, snapshot_sha256: hashObject(unsigned) };
    validateSnapshot(snapshot);
    const binding = partialSnapshotBinding(unsigned);
    if (prepared) {
      removeUnsealedSnapshotStaging(
        root,
        paths,
        prepared.directory,
        snapshotId,
        requestedOperation.kind,
        prepared.binding,
        binding,
        prepared.discarded,
        prepared.bindingDigest,
      );
    }
    const { assertNoPendingTaskOperations } = require('./pending-operations');
    assertNoPendingTaskOperations(root, goalId, taskId);

    const temporaryDir = path.join(
      paths.snapshots,
      partialSnapshotStagingName(snapshotId, binding),
    );
    assertControl(
      Buffer.byteLength(path.basename(temporaryDir)) <= 255,
      'HANDOFF_STAGING_INVALID',
      `snapshot ${snapshotId} staging name 超过 NAME_MAX`,
    );
    fs.mkdirSync(temporaryDir, { mode: 0o700 });
    maybeInjectHandoffFault(
      root,
      'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_STAGING_MKDIR',
      'TEST_FAULT_AFTER_SNAPSHOT_STAGING_MKDIR',
      'injected failure after recovery snapshot staging mkdir',
      93,
    );
    try {
      atomicWriteSnapshotProtocolJson(
        root,
        path.join(temporaryDir, PARTIAL_SNAPSHOT_BINDING_FILE),
        binding,
        {
          variable: 'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_TEMP_FSYNC',
          code: 'TEST_FAULT_AFTER_SNAPSHOT_BINDING_TEMP_FSYNC',
          message: 'injected failure after snapshot binding atomic temp fsync',
          exitCode: 94,
        },
      );
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_BINDING_PUBLISH',
        'TEST_FAULT_AFTER_SNAPSHOT_BINDING_PUBLISH',
        'injected failure after snapshot binding publication',
        96,
      );
      atomicWrite(path.join(temporaryDir, patchRelative), capture.patch);
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING',
        'TEST_FAULT_AFTER_SNAPSHOT_PARTIAL_STAGING',
        'injected failure after partial recovery snapshot staging',
        91,
      );
      fs.mkdirSync(path.join(temporaryDir, 'provenance'), { mode: 0o700 });
      atomicWrite(path.join(temporaryDir, provenanceRelative), capture.provenance);
      if (shellAudit) {
        atomicWrite(path.join(temporaryDir, shellAuditRelative), shellAudit.body);
        atomicWrite(path.join(temporaryDir, shellRecordsRelative), shellAudit.records);
      }
      atomicWriteSnapshotProtocolJson(
        root,
        path.join(temporaryDir, 'snapshot.json'),
        snapshot,
        {
          variable: 'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_MANIFEST_TEMP_FSYNC',
          code: 'TEST_FAULT_AFTER_SNAPSHOT_MANIFEST_TEMP_FSYNC',
          message: 'injected failure after snapshot manifest atomic temp fsync',
          exitCode: 95,
        },
      );
      assertControl(!fs.existsSync(paths.snapshotDir), 'HANDOFF_ARTIFACT_EXISTS', `snapshot ${snapshotId} 已存在`);
      fsyncDirectory(temporaryDir);
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH',
        'TEST_FAULT_BEFORE_SNAPSHOT_PUBLISH',
        'injected failure before recovery snapshot publication',
        85,
      );
      fs.renameSync(temporaryDir, paths.snapshotDir);
      fsyncDirectory(paths.snapshots);
      published = true;
      return exportSnapshotResult({
        snapshot,
        manifestFile: path.join(paths.snapshotDir, 'snapshot.json'),
      }, false);
    } catch (error) {
      throw error;
    }
    }, exportOddRecoveryLockOptions(root, {
      goalId,
      taskId,
      snapshotId,
      successorThreadId,
      requestedOperation,
      captainCapabilityFile: options.captainCapabilityFile,
      foremanCapabilityFile: options.foremanCapabilityFile,
      requireForeman: hasShellAudit,
    }));
  } catch (error) {
    exitDeferredHandoffFault(error);
  }
  if (published) {
    try {
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_SNAPSHOT_PUBLISH',
        'TEST_FAULT_AFTER_SNAPSHOT_PUBLISH',
        'injected failure after durable recovery snapshot publication',
        86,
      );
    } catch (error) {
      exitDeferredHandoffFault(error);
    }
  }
  return result;
}

function materializationTarget(worktree, relative) {
  const parts = safeRelativePath(relative, 'materialized path').split('/');
  return path.join(worktree, ...parts);
}

function validateMaterializationParents(worktree, relative) {
  const parts = safeRelativePath(relative, 'materialized path').split('/');
  let current = worktree;
  for (const part of parts.slice(0, -1)) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) return;
    const stat = fs.lstatSync(current);
    assertControl(stat.isDirectory() && !stat.isSymbolicLink(), 'HANDOFF_PATH_COLLISION', `materialized parent ${current} 不是普通目录`);
  }
}

function ensureMaterializationParents(worktree, relative) {
  const parts = safeRelativePath(relative, 'materialized path').split('/');
  let current = worktree;
  for (const part of parts.slice(0, -1)) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) {
      try {
        fs.mkdirSync(current, { mode: 0o755 });
        fsyncDirectory(path.dirname(current));
      } catch (error) {
        if (!error || error.code !== 'EEXIST') throw error;
      }
    }
    const stat = fs.lstatSync(current);
    assertControl(
      stat.isDirectory() && !stat.isSymbolicLink(),
      'HANDOFF_PATH_COLLISION',
      `materialized parent ${current} 不是普通目录`,
    );
  }
}

function importEntryBinding(intent, snapshot, entry) {
  return {
    schema_version: 1,
    kind: 'RECOVERY_IMPORT_ENTRY',
    goal_id: intent.goal_id,
    task_id: intent.task_id,
    import_id: intent.import_id,
    request_sha256: intent.request_sha256,
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    target: entry.path,
    type: entry.type,
    mode: entry.mode,
    size: entry.size,
    sha256: entry.sha256,
  };
}

function importParentAnchorFile(root, intent) {
  return importIntentFile(
    root,
    intent.goal_id,
    intent.task_id,
    intent.import_id,
  );
}

function importEntryPlans(root, destination, snapshot, intent, entries) {
  const parentAnchor = importParentAnchorFile(root, intent);
  const parentMarkerBody = fs.readFileSync(parentAnchor);
  return entries.map((entry) => {
    const target = materializationTarget(destination.worktree, entry.path);
    assertControl(
      ![
        IMPORT_ENTRY_TEMP_PREFIX,
        IMPORT_TRACKED_TEMP_PREFIX,
        IMPORT_TRACKED_BASE_PREFIX,
        IMPORT_PARENT_MARKER_PREFIX,
      ].some((prefix) => path.basename(target).startsWith(prefix)),
      'HANDOFF_ARTIFACT_INVALID',
      `snapshot entry ${entry.path} 使用了保留的 import namespace`,
    );
    const binding = importEntryBinding(intent, snapshot, entry);
    const digest = hashObject(binding).slice('sha256:'.length);
    const parentBinding = {
      schema_version: 1,
      kind: 'RECOVERY_IMPORT_PARENT',
      goal_id: intent.goal_id,
      task_id: intent.task_id,
      import_id: intent.import_id,
      request_sha256: intent.request_sha256,
      parent: path.relative(
        destination.worktree,
        path.dirname(target),
      ).split(path.sep).join('/') || '.',
    };
    const parentDigest = hashObject(parentBinding).slice('sha256:'.length);
    return {
      entry,
      binding,
      worktree: destination.worktree,
      relative: entry.path,
      target,
      temporary: entry.type === 'regular'
        ? path.join(
          path.dirname(target),
          `${IMPORT_ENTRY_TEMP_PREFIX}${digest}.tmp`,
        )
        : null,
      parentMarker: path.join(
        path.dirname(target),
        `${IMPORT_PARENT_MARKER_PREFIX}${parentDigest}.marker`,
      ),
      parentAnchor,
      parentMarkerBody,
    };
  });
}

function desiredImportEntryMode(entry) {
  return entry.mode === '100755' ? 0o755 : 0o644;
}

function assertCurrentOwnerFile(stat, modes, code, message) {
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && modes.includes(stat.mode & 0o777)
      && (
        typeof process.getuid !== 'function'
        || stat.uid === process.getuid()
      ),
    code,
    message,
  );
}

function assertExactMaterializedEntry(plan) {
  const { entry, target } = plan;
  const stat = fs.lstatSync(target);
  if (entry.type === 'regular') {
    assertCurrentOwnerFile(
      stat,
      [desiredImportEntryMode(entry)],
      'HANDOFF_IMPORT_ENTRY_CONFLICT',
      `materialized target ${entry.path} type/mode/owner 不匹配`,
    );
    const body = fs.readFileSync(target);
    assertControl(
      body.length === entry.size
        && `sha256:${sha256(body)}` === entry.sha256
        && body.equals(entry.body),
      'HANDOFF_IMPORT_ENTRY_CONFLICT',
      `materialized target ${entry.path} 内容不是 sealed entry`,
    );
    return;
  }
  assertControl(
    entry.type === 'symlink' && stat.isSymbolicLink(),
    'HANDOFF_IMPORT_ENTRY_CONFLICT',
    `materialized target ${entry.path} type 不匹配`,
  );
  const targetValue = fs.readlinkSync(target);
  assertControl(
    Buffer.from(targetValue, 'utf8').equals(entry.body),
    'HANDOFF_IMPORT_ENTRY_CONFLICT',
    `materialized symlink ${entry.path} target 不是 sealed entry`,
  );
}

function inspectImportEntryTemporary(plan) {
  if (plan.temporary === null) return null;
  if (!pathEntryExists(plan.temporary)) return null;
  const stat = fs.lstatSync(plan.temporary);
  const targetMode = desiredImportEntryMode(plan.entry);
  assertCurrentOwnerFile(
    stat,
    [0o600, targetMode],
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `import entry temp ${plan.entry.path} type/mode/owner 非法`,
  );
  assertControl(
    stat.nlink === 1 || stat.nlink === 2,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `import entry temp ${plan.entry.path} link count 非法`,
  );
  const body = fs.readFileSync(plan.temporary);
  assertControl(
    body.length <= plan.entry.body.length
      && plan.entry.body.subarray(0, body.length).equals(body),
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `import entry temp ${plan.entry.path} 不是 sealed body 的 exact prefix`,
  );
  assertControl(
    body.length === plan.entry.body.length
      || (stat.mode & 0o777) === 0o600,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `partial import entry temp ${plan.entry.path} mode 非 0600`,
  );
  return {
    body,
    complete: body.length === plan.entry.body.length,
    stat,
  };
}

function assertImportEntryTempInventory(plans) {
  const allowed = new Set(
    plans
      .map((plan) => plan.temporary)
      .filter((temporary) => temporary !== null),
  );
  const parents = [...new Set(plans.map((plan) => path.dirname(plan.target)))];
  for (const parent of parents) {
    if (!fs.existsSync(parent)) continue;
    const stat = fs.lstatSync(parent);
    assertControl(
      stat.isDirectory() && !stat.isSymbolicLink(),
      'HANDOFF_PATH_COLLISION',
      `materialized parent ${parent} 不是普通目录`,
    );
    for (const name of fs.readdirSync(parent)) {
      if (!name.startsWith(IMPORT_ENTRY_TEMP_PREFIX)) continue;
      const candidate = path.join(parent, name);
      assertControl(
        allowed.has(candidate),
        'HANDOFF_IMPORT_TEMP_CONFLICT',
        `发现 foreign import entry temp ${candidate}`,
      );
    }
  }
}

function maybeExitImportEntryForTest(root, variable, exitCode) {
  const mode = validatedHandoffFault(root, variable);
  if (mode === null) return;
  assertControl(
    mode === 'exit',
    'INVALID_TEST_FAULT',
    `${variable} 只接受 exit`,
  );
  process.exit(exitCode);
}

function maybeReplaceTrackedTargetAfterCasForTest(root, plan) {
  if (plan.relative !== 'tracked.txt') return;
  const variable =
    'GOAL_CONTROL_TEST_REPLACE_TRACKED_TARGET_AFTER_CAS';
  const mode = validatedHandoffFault(root, variable);
  if (mode === null) return;
  assertControl(
    mode === '1',
    'INVALID_TEST_FAULT',
    `${variable} 只接受 1`,
  );
  const temporary = path.join(
    path.dirname(plan.target),
    `.goalctl-test-foreign-atomic-save-${process.pid}`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.writeFileSync(
      descriptor,
      Buffer.from('foreign same-uid atomic save\n', 'utf8'),
    );
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, plan.target);
  fsyncDirectory(path.dirname(plan.target));
}

function createImportEntryTemporary(root, plan) {
  const parent = path.dirname(plan.target);
  let descriptor;
  try {
    descriptor = fs.openSync(plan.temporary, 'wx', 0o600);
    fs.fsyncSync(descriptor);
    fsyncDirectory(parent);
    maybeExitImportEntryForTest(
      root,
      'GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_CREATE',
      102,
    );
    const partialFault = validatedHandoffFault(
      root,
      'GOAL_CONTROL_TEST_EXIT_DURING_IMPORT_ENTRY_WRITE',
    );
    if (partialFault !== null) {
      assertControl(
        partialFault === 'exit',
        'INVALID_TEST_FAULT',
        'GOAL_CONTROL_TEST_EXIT_DURING_IMPORT_ENTRY_WRITE 只接受 exit',
      );
      const partialLength = Math.max(
        1,
        Math.floor(plan.entry.body.length / 2),
      );
      fs.writeSync(
        descriptor,
        plan.entry.body,
        0,
        Math.min(partialLength, plan.entry.body.length),
        0,
      );
      fs.fsyncSync(descriptor);
      process.exit(103);
    }
    fs.writeFileSync(descriptor, plan.entry.body);
    fs.fsyncSync(descriptor);
    maybeExitImportEntryForTest(
      root,
      'GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_TEMP_FSYNC',
      104,
    );
    fs.fchmodSync(descriptor, desiredImportEntryMode(plan.entry));
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function sealImportEntryTemporaryMode(plan, prepared) {
  const desiredMode = desiredImportEntryMode(plan.entry);
  if ((prepared.stat.mode & 0o777) === desiredMode) return prepared;
  assertControl(
    prepared.complete && (prepared.stat.mode & 0o777) === 0o600,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `import entry temp ${plan.entry.path} 未处于可恢复 mode`,
  );
  let descriptor;
  try {
    const before = fs.lstatSync(plan.temporary);
    descriptor = fs.openSync(
      plan.temporary,
      fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0),
    );
    const owner = fs.fstatSync(descriptor);
    assertControl(
      before.isFile()
        && !before.isSymbolicLink()
        && owner.isFile()
        && before.dev === owner.dev
        && before.ino === owner.ino
        && owner.dev === prepared.stat.dev
        && owner.ino === prepared.stat.ino
        && owner.nlink === 1
        && (owner.mode & 0o777) === 0o600
        && (
          typeof process.getuid !== 'function'
          || owner.uid === process.getuid()
        ),
      'HANDOFF_IMPORT_TEMP_CONFLICT',
      `import entry temp ${plan.entry.path} identity/mode 在 seal 前漂移`,
    );
    const body = fs.readFileSync(descriptor);
    assertControl(
      body.length === plan.entry.size
        && `sha256:${sha256(body)}` === plan.entry.sha256
        && body.equals(plan.entry.body),
      'HANDOFF_IMPORT_TEMP_CONFLICT',
      `import entry temp ${plan.entry.path} 内容在 seal 前漂移`,
    );
    fs.fchmodSync(descriptor, desiredMode);
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  return inspectImportEntryTemporary(plan);
}

function promoteImportEntryTemporary(root, plan) {
  const prepared = inspectImportEntryTemporary(plan);
  assertControl(
    prepared
      && prepared.complete
      && prepared.stat.nlink === 1
      && (prepared.stat.mode & 0o777)
        === desiredImportEntryMode(plan.entry),
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `import entry temp ${plan.entry.path} publish 前 identity/mode/body 漂移`,
  );
  try {
    fs.linkSync(plan.temporary, plan.target);
  } catch (error) {
    throw new ControlError(
      error && error.code === 'EEXIST'
        ? 'HANDOFF_IMPORT_ENTRY_CONFLICT'
        : 'HANDOFF_IMPORT_TEMP_PROMOTE_FAILED',
      error && error.code === 'EEXIST'
        ? `materialized target ${plan.entry.path} 并发出现；拒绝覆盖`
        : `无法 no-clobber publish import entry ${plan.entry.path}: ${error.message}`,
    );
  }
  fsyncDirectory(path.dirname(plan.target));
  const temporaryAfterLink = fs.lstatSync(plan.temporary);
  const targetAfterLink = fs.lstatSync(plan.target);
  assertControl(
    temporaryAfterLink.isFile()
      && targetAfterLink.isFile()
      && temporaryAfterLink.dev === prepared.stat.dev
      && temporaryAfterLink.ino === prepared.stat.ino
      && targetAfterLink.dev === prepared.stat.dev
      && targetAfterLink.ino === prepared.stat.ino
      && temporaryAfterLink.nlink === 2
      && targetAfterLink.nlink === 2,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `import entry ${plan.entry.path} hard-link publish lineage 不匹配`,
  );
  assertExactMaterializedEntry(plan);
  maybeExitImportEntryForTest(
    root,
    'GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_PROMOTE',
    105,
  );
  fs.unlinkSync(plan.temporary);
  fsyncDirectory(path.dirname(plan.target));
}

function materializeImportEntry(root, destination, plan) {
  validateMaterializationParents(
    destination.worktree,
    plan.entry.path,
  );
  ensureImportParentMarker(plan);
  assertImportParentBound(plan);
  if (plan.entry.type === 'symlink') {
    let targetExists = false;
    try {
      fs.lstatSync(plan.target);
      targetExists = true;
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }
    if (targetExists) {
      assertExactMaterializedEntry(plan);
      return;
    }
    ensureMaterializationParents(destination.worktree, plan.entry.path);
    assertImportParentBound(plan);
    const targetValue = plan.entry.body.toString('utf8');
    assertControl(
      Buffer.from(targetValue, 'utf8').equals(plan.entry.body),
      'HANDOFF_SYMLINK_INVALID',
      `symlink ${plan.entry.path} target 非 UTF-8`,
    );
    try {
      fs.symlinkSync(targetValue, plan.target);
    } catch (error) {
      throw new ControlError(
        error && error.code === 'EEXIST'
          ? 'HANDOFF_IMPORT_ENTRY_CONFLICT'
          : 'HANDOFF_IMPORT_TEMP_PROMOTE_FAILED',
        error && error.code === 'EEXIST'
          ? `materialized symlink ${plan.entry.path} 并发出现；拒绝覆盖`
          : `无法 no-clobber publish symlink ${plan.entry.path}: ${error.message}`,
      );
    }
    fsyncDirectory(path.dirname(plan.target));
    maybeExitImportEntryForTest(
      root,
      'GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_ENTRY_PROMOTE',
      105,
    );
    assertExactMaterializedEntry(plan);
    return;
  }
  const temporary = inspectImportEntryTemporary(plan);
  if (pathEntryExists(plan.target)) {
    assertExactMaterializedEntry(plan);
    if (temporary) {
      const targetStat = fs.lstatSync(plan.target);
      const samePublishedInode = temporary.complete
        && temporary.stat.dev === targetStat.dev
        && temporary.stat.ino === targetStat.ino
        && temporary.stat.nlink === 2
        && targetStat.nlink === 2;
      assertControl(
        samePublishedInode || !temporary.complete,
        'HANDOFF_IMPORT_TEMP_CONFLICT',
        `import entry ${plan.entry.path} target/temp lineage 分叉`,
      );
      fs.unlinkSync(plan.temporary);
      fsyncDirectory(path.dirname(plan.target));
    }
    return;
  }
  if (temporary && !temporary.complete) {
    fs.unlinkSync(plan.temporary);
    fsyncDirectory(path.dirname(plan.target));
  }
  ensureMaterializationParents(destination.worktree, plan.entry.path);
  assertImportParentBound(plan);
  if (!pathEntryExists(plan.temporary)) {
    createImportEntryTemporary(root, plan);
  }
  let prepared = inspectImportEntryTemporary(plan);
  assertControl(
    prepared && prepared.complete,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `import entry temp ${plan.entry.path} 未完整 seal`,
  );
  prepared = sealImportEntryTemporaryMode(plan, prepared);
  assertControl(
    prepared
      && prepared.complete
      && (prepared.stat.mode & 0o777) === desiredImportEntryMode(plan.entry),
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `import entry temp ${plan.entry.path} mode 未完整 seal`,
  );
  promoteImportEntryTemporary(root, plan);
  assertExactMaterializedEntry(plan);
}

function materializeImportEntries(root, destination, plans) {
  assertImportEntryTempInventory(plans);
  for (const plan of plans) {
    materializeImportEntry(root, destination, plan);
  }
  assertImportEntryTempInventory(plans);
}

function assertNoGitOperationInProgress(worktree) {
  const active = [];
  for (const sentinel of GIT_OPERATION_SENTINELS) {
    const resolved = gitText(
      worktree,
      [
        'rev-parse',
        '--path-format=absolute',
        '--git-path',
        sentinel,
      ],
      {
        code: 'HANDOFF_GIT_OPERATION_IN_PROGRESS',
        label: `resolve Git operation sentinel ${sentinel}`,
      },
    );
    assertControl(
      path.isAbsolute(resolved)
        && path.normalize(resolved) === resolved,
      'HANDOFF_GIT_OPERATION_IN_PROGRESS',
      `Git operation sentinel ${sentinel} 未解析为规范绝对路径`,
    );
    try {
      fs.lstatSync(resolved);
      active.push(sentinel);
    } catch (error) {
      assertControl(
        error && ['ENOENT', 'ENOTDIR'].includes(error.code),
        'HANDOFF_GIT_OPERATION_IN_PROGRESS',
        `无法安全检查 Git operation sentinel ${sentinel}`,
      );
    }
  }
  assertControl(
    active.length === 0,
    'HANDOFF_GIT_OPERATION_IN_PROGRESS',
    `destination worktree 存在进行中的 hidden Git operation: ${active.join(', ')}`,
    { sentinels: active },
  );
}

function gitIndexPath(worktree) {
  const resolved = gitText(
    worktree,
    [
      'rev-parse',
      '--path-format=absolute',
      '--git-path',
      'index',
    ],
    {
      code: 'HANDOFF_GIT_INDEX_LOCK_FAILED',
      label: 'resolve destination worktree Git index',
    },
  );
  assertControl(
    path.isAbsolute(resolved)
      && path.normalize(resolved) === resolved,
    'HANDOFF_GIT_INDEX_LOCK_FAILED',
    'destination worktree Git index 未解析为规范绝对路径',
  );
  let stat;
  try {
    stat = fs.lstatSync(resolved);
  } catch (error) {
    throw new ControlError(
      'HANDOFF_GIT_INDEX_LOCK_FAILED',
      `destination worktree Git index 不存在或无法读取: ${error.message}`,
    );
  }
  assertControl(
    stat.isFile() && !stat.isSymbolicLink(),
    'HANDOFF_GIT_INDEX_LOCK_FAILED',
    'destination worktree Git index 必须是非 symlink 普通文件',
  );
  return resolved;
}

function assertGitIndexFenceOwned(lockFile, owner) {
  let current;
  try {
    current = fs.lstatSync(lockFile);
  } catch (error) {
    throw new ControlError(
      'HANDOFF_GIT_INDEX_LOCK_OWNERSHIP_LOST',
      `checkpoint Git index fence 已消失或无法读取: ${error.message}`,
    );
  }
  assertControl(
    current.isFile()
      && !current.isSymbolicLink()
      && current.dev === owner.dev
      && current.ino === owner.ino,
    'HANDOFF_GIT_INDEX_LOCK_OWNERSHIP_LOST',
    'checkpoint Git index fence ownership 已变化；拒绝删除未知 lock',
  );
}

function checkpointGitFenceContext(worktree) {
  const indexFile = gitIndexPath(worktree);
  const gitDir = canonicalDirectory(
    gitText(
      worktree,
      ['rev-parse', '--path-format=absolute', '--absolute-git-dir'],
      {
        code: 'HANDOFF_GIT_METADATA_FENCE_FAILED',
        label: 'resolve destination linked-worktree Git dir',
      },
    ),
    'destination linked-worktree Git dir',
  );
  const commonGitDir = canonicalDirectory(
    gitText(
      worktree,
      ['rev-parse', '--path-format=absolute', '--git-common-dir'],
      {
        code: 'HANDOFF_GIT_METADATA_FENCE_FAILED',
        label: 'resolve destination Git common dir',
      },
    ),
    'destination Git common dir',
  );
  assertControl(
    gitDir !== commonGitDir && path.dirname(indexFile) === gitDir,
    'HANDOFF_GIT_METADATA_FENCE_UNAVAILABLE',
    'recovery checkpoint 只接受拥有专属 gitdir 的 linked worktree；禁止 fence common git dir',
  );
  const stat = fs.lstatSync(gitDir);
  assertControl(
    stat.isDirectory()
      && !stat.isSymbolicLink()
      && (
        typeof process.getuid !== 'function'
        || stat.uid === process.getuid()
      ),
    'HANDOFF_GIT_METADATA_FENCE_FAILED',
    'destination linked-worktree Git dir 必须由当前 owner 持有',
  );
  return {
    indexFile,
    lockFile: `${indexFile}.lock`,
    gitDir,
    commonGitDir,
    gitDirDev: String(stat.dev),
    gitDirIno: String(stat.ino),
    currentMode: stat.mode & 0o7777,
  };
}

function checkpointGitFencePaths(root, request) {
  const requestSha256 = hashObject(request);
  const digest = requestSha256.slice('sha256:'.length);
  const parent = path.join(
    root,
    'goals',
    request.goal_id,
    'recovery-handoffs',
    request.task_id,
    'checkpoint-fences',
  );
  const directory = path.join(parent, digest);
  return {
    requestSha256,
    parent,
    directory,
    prepared: path.join(directory, 'prepared.json'),
    completed: path.join(directory, 'completed.json'),
  };
}

function ensureCheckpointGitFenceDirectory(paths) {
  for (const directory of [paths.parent, paths.directory]) {
    if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o700 });
    assertCurrentOwnerOrdinary(
      fs.lstatSync(directory),
      'directory',
      'HANDOFF_GIT_METADATA_FENCE_INVALID',
      `checkpoint Git metadata fence 目录 ${directory} 不是当前 owner 的 0700 普通目录`,
    );
  }
}

function checkpointGitFenceLockBytes(marker) {
  return Buffer.from(`${marker.lock_token}\n`, 'utf8');
}

function validateCheckpointGitFenceMarker(
  marker,
  request,
  paths,
  context,
) {
  exactKeys(
    marker,
    [
      'schema_version', 'kind', 'request', 'request_sha256',
      'worktree', 'git_dir', 'git_dir_dev', 'git_dir_ino',
      'index_file', 'index_lock_file', 'index_snapshot',
      'original_git_dir_mode', 'fenced_git_dir_mode',
      'lock_token', 'ref_transaction', 'created_at', 'fence_sha256',
    ],
    'checkpoint Git metadata fence marker',
  );
  const unsigned = { ...marker };
  delete unsigned.fence_sha256;
  assertControl(
    marker.schema_version === CHECKPOINT_GIT_FENCE_SCHEMA_VERSION
      && marker.kind === CHECKPOINT_GIT_FENCE_KIND
      && marker.request_sha256 === paths.requestSha256
      && hashObject(marker.request) === paths.requestSha256
      && hashObject(unsigned) === marker.fence_sha256,
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence marker seal/request 不匹配',
  );
  assertControl(
    hashObject(request) === marker.request_sha256
      && marker.worktree === request.destination_worktree
      && marker.git_dir === context.gitDir
      && marker.git_dir_dev === context.gitDirDev
      && marker.git_dir_ino === context.gitDirIno
      && marker.index_file === context.indexFile
      && marker.index_lock_file === context.lockFile,
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence marker identity/path 已漂移',
  );
  exactKeys(
    marker.index_snapshot,
    ['file', 'sha256', 'tree'],
    'checkpoint Git metadata fence index snapshot',
  );
  assertControl(
    marker.index_snapshot.file === context.indexFile
      && typeof marker.index_snapshot.sha256 === 'string'
      && marker.index_snapshot.sha256.startsWith('sha256:')
      && /^[0-9a-f]{40}$/.test(marker.index_snapshot.tree),
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence index snapshot 非法',
  );
  assertControl(
    Number.isSafeInteger(marker.original_git_dir_mode)
      && marker.original_git_dir_mode >= 0
      && marker.original_git_dir_mode <= 0o7777
      && marker.fenced_git_dir_mode
        === (marker.original_git_dir_mode & ~0o222)
      && (marker.original_git_dir_mode & 0o700) === 0o700
      && (marker.fenced_git_dir_mode & 0o500) === 0o500,
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence mode 非法',
  );
  safeId(marker.lock_token, 'checkpoint Git metadata fence lock_token');
  exactKeys(
    marker.ref_transaction,
    ['ref', 'fence_file', 'expected_reflog'],
    'checkpoint ref transaction',
  );
  assertControl(
    marker.ref_transaction.ref === request.branch_ref
      && marker.ref_transaction.fence_file
        === path.join(paths.directory, 'ref-transaction.fence')
      && marker.ref_transaction.expected_reflog
      && typeof marker.ref_transaction.expected_reflog === 'object',
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint ref transaction durable binding 非法',
  );
  assertControl(
    typeof marker.created_at === 'string'
      && Number.isFinite(Date.parse(marker.created_at)),
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence created_at 非法',
  );
  return marker;
}

function readCheckpointGitFenceMarker(
  request,
  paths,
  context,
) {
  if (!fs.existsSync(paths.prepared)) return null;
  assertCurrentOwnerOrdinary(
    fs.lstatSync(paths.prepared),
    'file',
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence marker 不是当前 owner 的 0600 普通文件',
  );
  return validateCheckpointGitFenceMarker(
    readJson(paths.prepared, 'checkpoint Git metadata fence marker'),
    request,
    paths,
    context,
  );
}

function publishCheckpointGitFenceMarker(
  request,
  paths,
  context,
  indexSnapshot,
) {
  assertControl(
    context.currentMode & 0o200,
    'HANDOFF_GIT_METADATA_FENCE_UNAVAILABLE',
    'destination linked-worktree Git dir 缺 owner write bit，无法建立可恢复 fence',
  );
  ensureCheckpointGitFenceDirectory(paths);
  const refFenceFile = path.join(
    paths.directory,
    'ref-transaction.fence',
  );
  assertControl(
    !pathEntryExists(refFenceFile),
    'HANDOFF_CHECKPOINT_REF_LOCK_INVALID',
    'checkpoint 首次 durable marker 前已有 foreign ref transaction fence',
  );
  const expectedReflog = describeLooseRefReflog({
    cwd: request.destination_worktree,
    commonGitDir: context.commonGitDir,
    ref: request.branch_ref,
    label: `recovery checkpoint ${request.branch_ref}`,
    codes: {
      refConflict: 'HANDOFF_CHECKPOINT_CAS_FAILED',
      lockConflict: 'HANDOFF_CHECKPOINT_REF_LOCK_INVALID',
      fenceConflict: 'HANDOFF_CHECKPOINT_REF_LOCK_INVALID',
      invalidRef: 'HANDOFF_CHECKPOINT_REF_LOCK_INVALID',
    },
  });
  const unsigned = {
    schema_version: CHECKPOINT_GIT_FENCE_SCHEMA_VERSION,
    kind: CHECKPOINT_GIT_FENCE_KIND,
    request,
    request_sha256: paths.requestSha256,
    worktree: request.destination_worktree,
    git_dir: context.gitDir,
    git_dir_dev: context.gitDirDev,
    git_dir_ino: context.gitDirIno,
    index_file: context.indexFile,
    index_lock_file: context.lockFile,
    index_snapshot: indexSnapshot,
    original_git_dir_mode: context.currentMode,
    fenced_git_dir_mode: context.currentMode & ~0o222,
    lock_token: randomId('checkpoint-git-fence'),
    ref_transaction: {
      ref: request.branch_ref,
      fence_file: refFenceFile,
      expected_reflog: expectedReflog,
    },
    created_at: nowIso(),
  };
  const marker = {
    ...unsigned,
    fence_sha256: hashObject(unsigned),
  };
  assertControl(
    !fs.existsSync(paths.prepared),
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence marker 并发出现',
  );
  atomicWriteJson(paths.prepared, marker);
  return validateCheckpointGitFenceMarker(
    readJson(paths.prepared, 'checkpoint Git metadata fence marker'),
    request,
    paths,
    context,
  );
}

function readCheckpointGitFenceCompletion(paths, marker) {
  if (!fs.existsSync(paths.completed)) return null;
  assertCurrentOwnerOrdinary(
    fs.lstatSync(paths.completed),
    'file',
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence completion 不是当前 owner 的 0600 普通文件',
  );
  const completion = readJson(
    paths.completed,
    'checkpoint Git metadata fence completion',
  );
  exactKeys(
    completion,
    [
      'schema_version', 'kind', 'request_sha256', 'fence_sha256',
      'checkpoint_sha', 'completed_at', 'completion_sha256',
    ],
    'checkpoint Git metadata fence completion',
  );
  const unsigned = { ...completion };
  delete unsigned.completion_sha256;
  assertControl(
    completion.schema_version === CHECKPOINT_GIT_FENCE_SCHEMA_VERSION
      && completion.kind === CHECKPOINT_GIT_FENCE_COMPLETION_KIND
      && completion.request_sha256 === marker.request_sha256
      && completion.fence_sha256 === marker.fence_sha256
      && completion.checkpoint_sha === marker.request.checkpoint_sha
      && typeof completion.completed_at === 'string'
      && Number.isFinite(Date.parse(completion.completed_at))
      && hashObject(unsigned) === completion.completion_sha256,
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence completion seal 不匹配',
  );
  return completion;
}

function publishCheckpointGitFenceCompletion(paths, marker, result) {
  assertControl(
    result && result.checkpoint_sha === marker.request.checkpoint_sha,
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata fence callback 返回不同 checkpoint',
  );
  const existing = readCheckpointGitFenceCompletion(paths, marker);
  if (existing) return existing;
  const unsigned = {
    schema_version: CHECKPOINT_GIT_FENCE_SCHEMA_VERSION,
    kind: CHECKPOINT_GIT_FENCE_COMPLETION_KIND,
    request_sha256: marker.request_sha256,
    fence_sha256: marker.fence_sha256,
    checkpoint_sha: result.checkpoint_sha,
    completed_at: nowIso(),
  };
  const completion = {
    ...unsigned,
    completion_sha256: hashObject(unsigned),
  };
  atomicWriteJson(paths.completed, completion);
  return readCheckpointGitFenceCompletion(paths, marker);
}

function assertCheckpointGitFenceLock(marker, context, owner) {
  assertGitIndexFenceOwned(context.lockFile, owner);
  const stat = fs.lstatSync(context.lockFile);
  assertCurrentOwnerOrdinary(
    stat,
    'file',
    'HANDOFF_GIT_INDEX_LOCK_OWNERSHIP_LOST',
    'checkpoint Git index fence 不是当前 owner 的 0600 普通文件',
  );
  assertControl(
    fs.readFileSync(context.lockFile).equals(
      checkpointGitFenceLockBytes(marker),
    ),
    'HANDOFF_GIT_INDEX_LOCK_OWNERSHIP_LOST',
    'checkpoint Git index fence token 已变化',
  );
}

function pathEntryExists(file) {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

function checkpointGitFenceLockTemporary(marker, context) {
  const digest = marker.request_sha256.slice('sha256:'.length);
  return path.join(
    context.gitDir,
    `${CHECKPOINT_INDEX_LOCK_TEMP_PREFIX}${digest}.tmp`,
  );
}

function assertCheckpointLockTempInventory(marker, context) {
  const expected = checkpointGitFenceLockTemporary(marker, context);
  for (const name of fs.readdirSync(context.gitDir)) {
    if (!name.startsWith(CHECKPOINT_INDEX_LOCK_TEMP_PREFIX)) continue;
    assertControl(
      path.join(context.gitDir, name) === expected,
      'HANDOFF_GIT_INDEX_LOCKED',
      `发现 foreign checkpoint index lock temp ${name}`,
    );
  }
  return expected;
}

function inspectCheckpointLockTemporary(marker, context, temporary) {
  if (!pathEntryExists(temporary)) return null;
  const stat = fs.lstatSync(temporary);
  assertCurrentOwnerOrdinary(
    stat,
    'file',
    'HANDOFF_GIT_INDEX_LOCKED',
    'checkpoint index lock temp 不是当前 owner 的 0600 普通文件',
  );
  const expected = checkpointGitFenceLockBytes(marker);
  const body = fs.readFileSync(temporary);
  assertControl(
    body.length <= expected.length
      && expected.subarray(0, body.length).equals(body),
    'HANDOFF_GIT_INDEX_LOCKED',
    'checkpoint index lock temp 不是 exact token prefix',
  );
  return {
    body,
    complete: body.length === expected.length,
    stat,
  };
}

function createCheckpointLockTemporary(
  root,
  marker,
  context,
  temporary,
) {
  const expected = checkpointGitFenceLockBytes(marker);
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    fs.fsyncSync(descriptor);
    fsyncDirectory(context.gitDir);
    maybeExitCheckpointGitFenceForTest(
      root,
      'GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_CREATE',
      106,
    );
    const partialFault = validatedHandoffFault(
      root,
      'GOAL_CONTROL_TEST_EXIT_DURING_CHECKPOINT_INDEX_LOCK_WRITE',
    );
    if (partialFault !== null) {
      assertControl(
        partialFault === 'exit',
        'INVALID_TEST_FAULT',
        'GOAL_CONTROL_TEST_EXIT_DURING_CHECKPOINT_INDEX_LOCK_WRITE 只接受 exit',
      );
      const partialLength = Math.max(1, Math.floor(expected.length / 2));
      fs.writeSync(
        descriptor,
        expected,
        0,
        partialLength,
        0,
      );
      fs.fsyncSync(descriptor);
      process.exit(107);
    }
    fs.writeFileSync(descriptor, expected);
    fs.fsyncSync(descriptor);
    maybeExitCheckpointGitFenceForTest(
      root,
      'GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_TEMP_FSYNC',
      108,
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function publishCheckpointLockTemporary(
  root,
  marker,
  context,
  temporary,
) {
  try {
    fs.linkSync(temporary, context.lockFile);
  } catch (error) {
    throw new ControlError(
      error && error.code === 'EEXIST'
        ? 'HANDOFF_GIT_INDEX_LOCKED'
        : 'HANDOFF_GIT_INDEX_LOCK_FAILED',
      error && error.code === 'EEXIST'
        ? 'destination worktree Git index lock 并发出现；保留 temp/lock 并 fail-closed'
        : `无法 no-replace publish checkpoint index lock: ${error.message}`,
    );
  }
  fsyncDirectory(context.gitDir);
  maybeExitCheckpointGitFenceForTest(
    root,
    'GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_INDEX_LOCK_PUBLISH',
    109,
  );
  fs.unlinkSync(temporary);
  fsyncDirectory(context.gitDir);
}

function openCheckpointGitFenceLock(marker, context) {
  let descriptor;
  try {
    descriptor = fs.openSync(context.lockFile, 'r');
    const owner = fs.fstatSync(descriptor);
    assertControl(
      owner.isFile(),
      'HANDOFF_GIT_INDEX_LOCK_FAILED',
      'checkpoint Git index fence 不是普通文件',
    );
    assertCheckpointGitFenceLock(marker, context, owner);
    return { descriptor, owner };
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    throw error;
  }
}

function acquireCheckpointGitFenceLock(root, marker, context) {
  const temporary = assertCheckpointLockTempInventory(marker, context);
  const prepared = inspectCheckpointLockTemporary(
    marker,
    context,
    temporary,
  );
  if (pathEntryExists(context.lockFile)) {
    const opened = openCheckpointGitFenceLock(marker, context);
    if (prepared) {
      const samePublishedInode = prepared.complete
        && prepared.stat.dev === opened.owner.dev
        && prepared.stat.ino === opened.owner.ino;
      assertControl(
        samePublishedInode || !prepared.complete,
        'HANDOFF_GIT_INDEX_LOCKED',
        'checkpoint canonical lock/temp lineage 分叉',
      );
      fs.unlinkSync(temporary);
      fsyncDirectory(context.gitDir);
    }
    return opened;
  }
  assertControl(
    context.currentMode === marker.original_git_dir_mode,
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint Git metadata 已 fenced 但匹配 index.lock 缺失',
  );
  if (prepared && !prepared.complete) {
    fs.unlinkSync(temporary);
    fsyncDirectory(context.gitDir);
  }
  if (!pathEntryExists(temporary)) {
    createCheckpointLockTemporary(
      root,
      marker,
      context,
      temporary,
    );
  }
  const complete = inspectCheckpointLockTemporary(
    marker,
    context,
    temporary,
  );
  assertControl(
    complete && complete.complete,
    'HANDOFF_GIT_INDEX_LOCKED',
    'checkpoint index lock temp 未完整 seal',
  );
  publishCheckpointLockTemporary(
    root,
    marker,
    context,
    temporary,
  );
  return openCheckpointGitFenceLock(marker, context);
}

function withGitIndexFence(
  root,
  worktree,
  request,
  captureIndexSnapshot,
  callback,
) {
  const context = checkpointGitFenceContext(worktree);
  const paths = checkpointGitFencePaths(root, request);
  let marker = readCheckpointGitFenceMarker(
    request,
    paths,
    context,
  );
  if (!marker) {
    const indexSnapshot = captureIndexSnapshot();
    marker = publishCheckpointGitFenceMarker(
      request,
      paths,
      context,
      indexSnapshot,
    );
  }
  // A completion proves that this request published the checkpoint once; it
  // is not a lease on the branch ref. Always re-enter the callback so an
  // exact retry verifies the live ref and, when it was moved back to the
  // sealed base, republishes the same deterministic checkpoint with CAS.
  const completion = readCheckpointGitFenceCompletion(paths, marker);
  const { descriptor, owner } = acquireCheckpointGitFenceLock(
    root,
    marker,
    context,
  );
  let fenced = false;
  try {
    const beforeFence = fs.lstatSync(context.gitDir);
    const beforeMode = beforeFence.mode & 0o7777;
    assertControl(
      String(beforeFence.dev) === marker.git_dir_dev
        && String(beforeFence.ino) === marker.git_dir_ino
        && (
          beforeMode === marker.original_git_dir_mode
          || beforeMode === marker.fenced_git_dir_mode
        ),
      'HANDOFF_GIT_METADATA_FENCE_INVALID',
      'destination linked-worktree Git dir identity/mode 已漂移',
    );
    if (beforeMode === marker.original_git_dir_mode) {
      fs.chmodSync(context.gitDir, marker.fenced_git_dir_mode);
      fsyncDirectory(path.dirname(context.gitDir));
    }
    const fencedStat = fs.lstatSync(context.gitDir);
    assertControl(
      String(fencedStat.dev) === marker.git_dir_dev
        && String(fencedStat.ino) === marker.git_dir_ino
        && (fencedStat.mode & 0o7777) === marker.fenced_git_dir_mode,
      'HANDOFF_GIT_METADATA_FENCE_FAILED',
      'destination linked-worktree Git dir 未进入只读 mutation fence',
    );
    fenced = true;
    assertCheckpointGitFenceLock(marker, context, owner);
    assertControl(
      hashFile(marker.index_snapshot.file) === marker.index_snapshot.sha256,
      'HANDOFF_CHECKPOINT_INDEX_DRIFT',
      'checkpoint Git index 在 durable fence 接管前已变化',
    );
    maybeExitCheckpointGitFenceForTest(
      root,
      'GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_GIT_FENCE',
      99,
    );
    const result = callback(
      marker.index_snapshot,
      marker,
      completion,
    );
    maybeExitCheckpointGitFenceForTest(
      root,
      'GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_PUBLISH',
      100,
    );
    publishCheckpointGitFenceCompletion(paths, marker, result);
    maybeExitCheckpointGitFenceForTest(
      root,
      'GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_FENCE_COMPLETION',
      101,
    );
    return result;
  } finally {
    let releaseError = null;
    try {
      assertCheckpointGitFenceLock(marker, context, owner);
      if (fenced) {
        const current = fs.lstatSync(context.gitDir);
        assertControl(
          String(current.dev) === marker.git_dir_dev
            && String(current.ino) === marker.git_dir_ino
            && (current.mode & 0o7777) === marker.fenced_git_dir_mode,
          'HANDOFF_GIT_METADATA_FENCE_INVALID',
          'release 前 destination linked-worktree Git dir fence 已漂移',
        );
        fs.chmodSync(context.gitDir, marker.original_git_dir_mode);
        fsyncDirectory(path.dirname(context.gitDir));
      }
      const restored = fs.lstatSync(context.gitDir);
      assertControl(
        String(restored.dev) === marker.git_dir_dev
          && String(restored.ino) === marker.git_dir_ino
          && (restored.mode & 0o7777) === marker.original_git_dir_mode,
        'HANDOFF_GIT_METADATA_FENCE_FAILED',
        'destination linked-worktree Git dir 原始 mode 未恢复',
      );
      assertCheckpointGitFenceLock(marker, context, owner);
      fs.unlinkSync(context.lockFile);
      fsyncDirectory(context.gitDir);
    } catch (error) {
      releaseError = error;
    }
    try {
      fs.closeSync(descriptor);
    } catch (error) {
      if (releaseError === null) {
        releaseError = new ControlError(
          'HANDOFF_GIT_INDEX_LOCK_FAILED',
          `关闭 checkpoint Git index fence 失败: ${error.message}`,
        );
      }
    }
    if (releaseError !== null) throw releaseError;
  }
}

function assertDestinationClean(worktree, options = {}) {
  assertNoGitOperationInProgress(worktree);
  const status = gitBuffer(
    worktree,
    ['status', '--porcelain=v1', '-z', '--untracked-files=all'],
    options.gitIndexFenced
      ? { env: { GIT_OPTIONAL_LOCKS: '0' } }
      : {},
  );
  assertControl(status.length === 0, 'HANDOFF_DESTINATION_DIRTY', 'destination worktree 必须干净');
  assertNoGitOperationInProgress(worktree);
}

function parseSingleNullRecord(buffer, label) {
  if (buffer.length === 0) return null;
  assertControl(
    buffer[buffer.length - 1] === 0
      && buffer.subarray(0, buffer.length - 1).indexOf(0) === -1,
    'HANDOFF_ARTIFACT_INVALID',
    `${label} 不是 single NUL-terminated record`,
  );
  const record = buffer.subarray(0, buffer.length - 1).toString('utf8');
  assertControl(
    Buffer.from(record, 'utf8').equals(
      buffer.subarray(0, buffer.length - 1),
    ),
    'HANDOFF_PATH_INVALID',
    `${label} 含非 UTF-8 bytes`,
  );
  return record;
}

function readTreeEntry(worktree, treeish, relative) {
  const record = parseSingleNullRecord(
    gitBuffer(
      worktree,
      ['ls-tree', '-z', treeish, '--', relative],
      {
        code: 'HANDOFF_EXPECTED_TREE_FAILED',
        label: `read base tree entry ${relative}`,
      },
    ),
    `base tree entry ${relative}`,
  );
  if (record === null) return null;
  const match = /^([0-7]{6}) ([a-z]+) ([0-9a-f]{40})\t([\s\S]+)$/.exec(
    record,
  );
  assertControl(
    match
      && match[4] === relative
      && match[2] === 'blob'
      && ['100644', '100755', '120000'].includes(match[1]),
    'HANDOFF_PATCH_REJECTED',
    `base tree entry ${relative} 使用 unsupported Git type/mode`,
  );
  return { mode: match[1], oid: match[3] };
}

function readIndexEntry(worktree, relative, env) {
  const record = parseSingleNullRecord(
    gitBuffer(
      worktree,
      ['ls-files', '--stage', '-z', '--', relative],
      {
        env,
        code: 'HANDOFF_EXPECTED_TREE_FAILED',
        label: `read isolated index entry ${relative}`,
      },
    ),
    `isolated index entry ${relative}`,
  );
  if (record === null) return null;
  const match = /^([0-7]{6}) ([0-9a-f]{40}) ([0-3])\t([\s\S]+)$/.exec(
    record,
  );
  assertControl(
    match
      && match[3] === '0'
      && match[4] === relative
      && ['100644', '100755', '120000'].includes(match[1]),
    'HANDOFF_PATCH_REJECTED',
    `isolated index entry ${relative} 使用 unsupported Git stage/type/mode`,
  );
  return { mode: match[1], oid: match[2] };
}

function worktreeBodyForIndexEntry(worktree, relative, entry, env) {
  if (entry === null) return null;
  const args = entry.mode === '120000'
    ? ['cat-file', 'blob', entry.oid]
    : ['cat-file', '--filters', `--path=${relative}`, entry.oid];
  return gitBuffer(worktree, args, {
    env,
    code: 'HANDOFF_EXPECTED_TREE_FAILED',
    label: `materialize isolated index blob ${relative}`,
  });
}

function materializedGitEntry(
  worktree,
  relative,
  entry,
  env = undefined,
) {
  if (entry === null) return null;
  const body = worktreeBodyForIndexEntry(
    worktree,
    relative,
    entry,
    env,
  );
  if (entry.mode === '120000') {
    const target = body.toString('utf8');
    assertControl(
      body.length > 0
        && body.length <= MAX_SYMLINK_TARGET_BYTES
        && !body.includes(0)
        && Buffer.from(target, 'utf8').equals(body),
      'HANDOFF_SYMLINK_INVALID',
      `tracked symlink ${relative} target 非安全 UTF-8`,
    );
  }
  return {
    ...entry,
    type: entry.mode === '120000' ? 'symlink' : 'regular',
    body,
    size: body.length,
    sha256: `sha256:${sha256(body)}`,
  };
}

function importTrackedPlan(
  root,
  destination,
  snapshot,
  intent,
  relative,
  base,
  expected,
) {
  const parentAnchor = importParentAnchorFile(root, intent);
  const parentMarkerBody = fs.readFileSync(parentAnchor);
  assertControl(
    base !== null || expected !== null,
    'HANDOFF_PATCH_REJECTED',
    `tracked path ${relative} 在 base/expected 均不存在`,
  );
  const binding = {
    schema_version: 1,
    kind: 'RECOVERY_IMPORT_TRACKED_ENTRY',
    goal_id: intent.goal_id,
    task_id: intent.task_id,
    import_id: intent.import_id,
    request_sha256: intent.request_sha256,
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    target: relative,
    base: base === null
      ? null
      : { mode: base.mode, oid: base.oid, sha256: base.sha256 },
    expected: expected === null
      ? null
      : {
        mode: expected.mode,
        oid: expected.oid,
        sha256: expected.sha256,
      },
  };
  const target = materializationTarget(destination.worktree, relative);
  assertControl(
    ![
      IMPORT_ENTRY_TEMP_PREFIX,
      IMPORT_TRACKED_TEMP_PREFIX,
      IMPORT_TRACKED_BASE_PREFIX,
      IMPORT_PARENT_MARKER_PREFIX,
    ].some((prefix) => path.basename(target).startsWith(prefix)),
    'HANDOFF_PATCH_REJECTED',
    `tracked path ${relative} 使用了保留的 import namespace`,
  );
  const digest = hashObject(binding).slice('sha256:'.length);
  const parentBinding = {
    schema_version: 1,
    kind: 'RECOVERY_IMPORT_PARENT',
    goal_id: intent.goal_id,
    task_id: intent.task_id,
    import_id: intent.import_id,
    request_sha256: intent.request_sha256,
    parent: path.relative(
      destination.worktree,
      path.dirname(target),
    ).split(path.sep).join('/') || '.',
  };
  const parentDigest = hashObject(parentBinding).slice('sha256:'.length);
  return {
    relative,
    binding,
    worktree: destination.worktree,
    target,
    temporary: expected === null
      ? null
      : path.join(
        path.dirname(target),
        `${IMPORT_TRACKED_TEMP_PREFIX}${digest}.tmp`,
      ),
    baseAnchor: base === null
      ? null
      : path.join(
        path.dirname(target),
        `${IMPORT_TRACKED_BASE_PREFIX}${digest}.anchor`,
      ),
    parentMarker: path.join(
      path.dirname(target),
      `${IMPORT_PARENT_MARKER_PREFIX}${parentDigest}.marker`,
    ),
    parentAnchor,
    parentMarkerBody,
    base,
    expected,
  };
}

function assertNoTrackedPathShapeTransitions(plans) {
  const paths = plans.map((plan) => plan.relative).sort(compareGitPaths);
  for (let index = 0; index < paths.length - 1; index += 1) {
    assertControl(
      !paths[index + 1].startsWith(`${paths[index]}/`),
      'HANDOFF_PATCH_REJECTED',
      `tracked import 暂不支持 file/directory shape transition: ${paths[index]}`,
    );
  }
}

function buildIsolatedImportPlan(
  root,
  destination,
  artifacts,
  snapshot,
  intent,
) {
  const temporaryDir = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), 'goal-handoff-import-index-'),
  );
  const indexFile = path.join(temporaryDir, 'index');
  const env = { GIT_INDEX_FILE: indexFile };
  try {
    gitRun(destination.worktree, ['read-tree', snapshot.source_observed_head], {
      env,
      code: 'HANDOFF_EXPECTED_TREE_FAILED',
      label: 'initialize isolated import index',
    });
    if (artifacts.patch.length > 0) {
      gitRun(
        destination.worktree,
        [
          'apply',
          '--check',
          '--cached',
          '--binary',
          '--whitespace=nowarn',
          '-',
        ],
        {
          env,
          input: artifacts.patch,
          code: 'HANDOFF_PATCH_REJECTED',
          label: 'isolated tracked patch precheck',
        },
      );
      gitRun(
        destination.worktree,
        [
          'apply',
          '--cached',
          '--binary',
          '--whitespace=nowarn',
          '-',
        ],
        {
          env,
          input: artifacts.patch,
          code: 'HANDOFF_PATCH_REJECTED',
          label: 'isolated tracked patch apply',
        },
      );
    }
    const trackedPaths = changedPathsInIndex(
      destination.worktree,
      snapshot.source_observed_head,
      env,
    );
    const trackedTree = gitText(destination.worktree, ['write-tree'], {
      env,
      code: 'HANDOFF_EXPECTED_TREE_FAILED',
      label: 'write isolated tracked import tree',
    });
    assertFullSha(trackedTree, 'isolated tracked import tree');
    const trackedPlans = trackedPaths.map((relative) => {
      const baseEntry = readTreeEntry(
        destination.worktree,
        snapshot.source_observed_head,
        relative,
      );
      const expectedEntry = readIndexEntry(
        destination.worktree,
        relative,
        env,
      );
      return importTrackedPlan(
        root,
        destination,
        snapshot,
        intent,
        relative,
        materializedGitEntry(
          destination.worktree,
          relative,
          baseEntry,
          env,
        ),
        materializedGitEntry(
          destination.worktree,
          relative,
          expectedEntry,
          env,
        ),
      );
    });
    assertNoTrackedPathShapeTransitions(trackedPlans);
    stageSnapshotEntriesInIndex(
      destination.worktree,
      artifacts.entries,
      env,
    );
    const expectedPaths = changedPathsInIndex(
      destination.worktree,
      snapshot.source_observed_head,
      env,
    );
    assertSameChangedPaths(
      expectedPaths,
      snapshot.expected_paths,
      'HANDOFF_CHANGED_PATHS_MISMATCH',
      'isolated import changed paths',
    );
    const expectedTree = gitText(destination.worktree, ['write-tree'], {
      env,
      code: 'HANDOFF_EXPECTED_TREE_FAILED',
      label: 'write isolated complete import tree',
    });
    assertControl(
      expectedTree === snapshot.expected_tree,
      'HANDOFF_MATERIALIZED_TREE_MISMATCH',
      'isolated import tree 与 sealed snapshot expected_tree 不一致',
    );
    const indexStat = fs.lstatSync(indexFile);
    assertControl(
      indexStat.isFile()
        && !indexStat.isSymbolicLink()
        && indexStat.nlink === 1
        && (
          typeof process.getuid !== 'function'
            || indexStat.uid === process.getuid()
        ),
      'HANDOFF_GIT_INDEX_LOCK_FAILED',
      'isolated import index 不是当前 owner 的 single-link 普通文件',
    );
    return {
      baseTree: gitText(
        destination.worktree,
        ['rev-parse', `${snapshot.source_observed_head}^{tree}`],
      ),
      trackedTree,
      expectedTree,
      expectedPaths,
      trackedPlans,
      entryPlans: importEntryPlans(
        root,
        destination,
        snapshot,
        intent,
        artifacts.entries,
      ),
      indexBody: fs.readFileSync(indexFile),
    };
  } finally {
    fs.rmSync(temporaryDir, { recursive: true, force: true });
  }
}

function exactTrackedEntryAtTarget(plan, entry) {
  if (entry === null) return !pathEntryExists(plan.target);
  if (!pathEntryExists(plan.target)) return false;
  const stat = fs.lstatSync(plan.target);
  if (entry.type === 'symlink') {
    if (
      !stat.isSymbolicLink()
        || (
          typeof process.getuid === 'function'
            && stat.uid !== process.getuid()
        )
    ) return false;
    const target = fs.readlinkSync(plan.target);
    return Buffer.from(target, 'utf8').equals(entry.body);
  }
  if (
    !stat.isFile()
      || stat.isSymbolicLink()
      || (stat.mode & 0o777) !== desiredImportEntryMode(entry)
      || (
        typeof process.getuid === 'function'
          && stat.uid !== process.getuid()
      )
      || stat.size !== entry.size
  ) return false;
  return fs.readFileSync(plan.target).equals(entry.body);
}

function inspectImportParentAnchor(plan) {
  if (!pathEntryExists(plan.parentAnchor)) return null;
  const stat = fs.lstatSync(plan.parentAnchor);
  assertCurrentOwnerFile(
    stat,
    [0o600],
    'HANDOFF_PATH_COLLISION',
    `import parent anchor ${plan.parentAnchor} 不是当前 owner 的 0600 普通文件`,
  );
  assertControl(
    stat.nlink >= 1
      && fs.readFileSync(plan.parentAnchor).equals(plan.parentMarkerBody),
    'HANDOFF_PATH_COLLISION',
    `import parent anchor ${plan.parentAnchor} binding 漂移`,
  );
  return stat;
}

function inspectImportParentMarker(plan) {
  const anchor = inspectImportParentAnchor(plan);
  assertControl(
    anchor !== null,
    'HANDOFF_PATH_COLLISION',
    `import parent marker ${plan.parentMarker} 缺 durable control anchor`,
  );
  if (!pathEntryExists(plan.parentMarker)) {
    assertControl(
      anchor.nlink >= 1,
      'HANDOFF_PATH_COLLISION',
      `import parent marker ${plan.parentMarker} 缺失但 anchor link count 非法`,
    );
    return null;
  }
  const marker = fs.lstatSync(plan.parentMarker);
  assertCurrentOwnerFile(
    marker,
    [0o600],
    'HANDOFF_PATH_COLLISION',
    `import parent marker ${plan.parentMarker} 不是当前 owner 的 0600 普通文件`,
  );
  assertControl(
    marker.dev === anchor.dev
      && marker.ino === anchor.ino
      && marker.nlink >= 2
      && marker.nlink === anchor.nlink
      && fs.readFileSync(plan.parentMarker).equals(plan.parentMarkerBody),
    'HANDOFF_PATH_COLLISION',
    `import parent marker ${plan.parentMarker} 不是 durable anchor 的 same-inode hardlink`,
  );
  return { anchor, marker };
}

function ensureImportParentMarker(plan) {
  inspectImportParentAnchor(plan);
  ensureMaterializationParents(plan.worktree, plan.relative);
  const parent = path.dirname(plan.target);
  const before = fs.lstatSync(parent);
  assertControl(
    before.isDirectory() && !before.isSymbolicLink(),
    'HANDOFF_PATH_COLLISION',
    `import parent ${parent} 不是普通目录`,
  );
  if (!pathEntryExists(plan.parentMarker)) {
    try {
      fs.linkSync(plan.parentAnchor, plan.parentMarker);
    } catch (error) {
      if (!error || error.code !== 'EEXIST') {
        throw new ControlError(
          'HANDOFF_PATH_COLLISION',
          `import parent marker ${plan.parentMarker} hardlink publication 失败: ${
            error && error.message ? error.message : String(error)
          }`,
        );
      }
    }
    fsyncDirectory(parent);
  }
  const after = fs.lstatSync(parent);
  assertControl(
    after.isDirectory()
      && !after.isSymbolicLink()
      && before.dev === after.dev
      && before.ino === after.ino,
    'HANDOFF_PATH_COLLISION',
    `import parent ${parent} 在 marker publication 期间漂移`,
  );
  assertControl(
    inspectImportParentMarker(plan) !== null,
    'HANDOFF_PATH_COLLISION',
    `import parent marker ${plan.parentMarker} publication 未收敛`,
  );
}

function assertImportParentBound(plan) {
  validateMaterializationParents(plan.worktree, plan.relative);
  assertControl(
    inspectImportParentMarker(plan) !== null,
    'HANDOFF_PATH_COLLISION',
    `import parent marker ${plan.parentMarker} binding 缺失`,
  );
}

function cleanupImportParentMarkers(plans) {
  const markers = new Map();
  for (const plan of plans) {
    markers.set(plan.parentMarker, plan);
  }
  for (const plan of markers.values()) {
    const inspected = inspectImportParentMarker(plan);
    assertControl(
      inspected !== null,
      'HANDOFF_PATH_COLLISION',
      `import parent marker ${plan.parentMarker} cleanup binding 缺失`,
    );
    const markerImmediatelyBeforeUnlink = fs.lstatSync(plan.parentMarker);
    const anchorImmediatelyBeforeUnlink = fs.lstatSync(plan.parentAnchor);
    assertControl(
      markerImmediatelyBeforeUnlink.dev === inspected.marker.dev
        && markerImmediatelyBeforeUnlink.ino === inspected.marker.ino
        && anchorImmediatelyBeforeUnlink.dev === inspected.anchor.dev
        && anchorImmediatelyBeforeUnlink.ino === inspected.anchor.ino
        && markerImmediatelyBeforeUnlink.dev
          === anchorImmediatelyBeforeUnlink.dev
        && markerImmediatelyBeforeUnlink.ino
          === anchorImmediatelyBeforeUnlink.ino
        && markerImmediatelyBeforeUnlink.nlink >= 2
        && markerImmediatelyBeforeUnlink.nlink
          === anchorImmediatelyBeforeUnlink.nlink,
      'HANDOFF_PATH_COLLISION',
      `import parent marker ${plan.parentMarker} cleanup 前 same-inode binding 漂移`,
    );
    fs.unlinkSync(plan.parentMarker);
    fsyncDirectory(path.dirname(plan.parentMarker));
    const retainedAnchor = inspectImportParentAnchor(plan);
    assertControl(
      retainedAnchor !== null
        && retainedAnchor.dev === inspected.anchor.dev
        && retainedAnchor.ino === inspected.anchor.ino
        && retainedAnchor.nlink === inspected.anchor.nlink - 1,
      'HANDOFF_PATH_COLLISION',
      `import parent marker ${plan.parentMarker} cleanup 未释放 exact hardlink`,
    );
  }
  const anchors = new Map(
    [...markers.values()].map((plan) => [plan.parentAnchor, plan]),
  );
  for (const plan of anchors.values()) {
    const retainedAnchor = inspectImportParentAnchor(plan);
    assertControl(
      retainedAnchor !== null && retainedAnchor.nlink === 1,
      'HANDOFF_PATH_COLLISION',
      `import parent anchor ${plan.parentAnchor} cleanup 后仍有 foreign hardlink`,
    );
  }
}

function assertImportIntentAnchorReleased(importIntent) {
  const expected = Buffer.from(
    `${JSON.stringify(importIntent.intent, null, 2)}\n`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      importIntent.file,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    const opened = fs.fstatSync(descriptor);
    assertCurrentOwnerOrdinary(
      opened,
      'file',
      'HANDOFF_PATH_COLLISION',
      `import intent anchor ${importIntent.file} 不是当前 owner 的 0600 普通文件`,
    );
    const before = fs.lstatSync(importIntent.file);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.lstatSync(importIntent.file);
    assertControl(
      before.dev === opened.dev
        && before.ino === opened.ino
        && after.dev === opened.dev
        && after.ino === opened.ino
        && opened.nlink === 1
        && before.nlink === 1
        && after.nlink === 1
        && bytes.equals(expected),
      'HANDOFF_PATH_COLLISION',
      `import intent anchor ${importIntent.file} cleanup 后仍有 foreign hardlink 或 bytes/inode 漂移`,
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function inspectTrackedBaseAnchor(plan) {
  if (plan.baseAnchor === null || !pathEntryExists(plan.baseAnchor)) {
    return null;
  }
  const anchorPlan = { ...plan, target: plan.baseAnchor };
  assertControl(
    exactTrackedEntryAtTarget(anchorPlan, plan.base),
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import base anchor ${plan.relative} 不是 sealed base`,
  );
  const stat = fs.lstatSync(plan.baseAnchor);
  assertControl(
    stat.nlink === 1 || stat.nlink === 2,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import base anchor ${plan.relative} link count 非法`,
  );
  return stat;
}

function ensureTrackedBaseAnchor(plan) {
  assertControl(
    plan.base !== null && plan.baseAnchor !== null,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import ${plan.relative} 缺 base anchor binding`,
  );
  let anchor = inspectTrackedBaseAnchor(plan);
  if (!anchor) {
    assertControl(
      trackedMaterializationState(plan) === 'base',
      'HANDOFF_DESTINATION_DIRTY',
      `tracked import ${plan.relative} base anchor 前 target 漂移`,
    );
    try {
      fs.linkSync(plan.target, plan.baseAnchor);
    } catch (error) {
      throw new ControlError(
        error && error.code === 'EEXIST'
          ? 'HANDOFF_IMPORT_TEMP_CONFLICT'
          : 'HANDOFF_IMPORT_TEMP_PROMOTE_FAILED',
        `tracked import ${plan.relative} base anchor publication 失败: ${error.message}`,
      );
    }
    fsyncDirectory(path.dirname(plan.baseAnchor));
    anchor = inspectTrackedBaseAnchor(plan);
  }
  const target = fs.lstatSync(plan.target);
  assertControl(
    anchor
      && anchor.nlink === 2
      && target.dev === anchor.dev
      && target.ino === anchor.ino
      && target.nlink === 2,
    'HANDOFF_DESTINATION_DIRTY',
    `tracked import ${plan.relative} target/base anchor lineage 漂移`,
  );
  return anchor;
}

function cleanupTrackedBaseAnchor(plan) {
  const anchor = inspectTrackedBaseAnchor(plan);
  if (!anchor) return;
  assertControl(
    trackedMaterializationState(plan) === 'expected'
      && anchor.nlink === 1,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import ${plan.relative} base anchor cleanup 前状态非法`,
  );
  fs.unlinkSync(plan.baseAnchor);
  fsyncDirectory(path.dirname(plan.baseAnchor));
}

function trackedMaterializationState(plan) {
  const expected = exactTrackedEntryAtTarget(plan, plan.expected);
  const base = exactTrackedEntryAtTarget(plan, plan.base);
  assertControl(
    expected || base,
    'HANDOFF_DESTINATION_DIRTY',
    `tracked import target ${plan.relative} 既不是 sealed base，也不是 sealed expected`,
  );
  return expected ? 'expected' : 'base';
}

function inspectTrackedImportTemporary(plan) {
  if (plan.temporary === null || !pathEntryExists(plan.temporary)) {
    return null;
  }
  const expected = plan.expected;
  assertControl(
    expected !== null,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `deleted tracked path ${plan.relative} 不得存在 materialization temp`,
  );
  const stat = fs.lstatSync(plan.temporary);
  if (expected.type === 'symlink') {
    assertControl(
      stat.isSymbolicLink()
        && (
          typeof process.getuid !== 'function'
            || stat.uid === process.getuid()
        )
        && Buffer.from(
          fs.readlinkSync(plan.temporary),
          'utf8',
        ).equals(expected.body),
      'HANDOFF_IMPORT_TEMP_CONFLICT',
      `tracked import symlink temp ${plan.relative} identity/body 不匹配`,
    );
    return { complete: true, stat };
  }
  assertCurrentOwnerFile(
    stat,
    [0o600, desiredImportEntryMode(expected)],
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import temp ${plan.relative} type/mode/owner 非法`,
  );
  assertControl(
    stat.nlink === 1 || stat.nlink === 2,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import temp ${plan.relative} link count 非法`,
  );
  const body = fs.readFileSync(plan.temporary);
  assertControl(
    body.length <= expected.body.length
      && expected.body.subarray(0, body.length).equals(body),
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import temp ${plan.relative} 不是 sealed expected prefix`,
  );
  return {
    complete: body.length === expected.body.length,
    stat,
  };
}

function assertTrackedImportTempInventory(plans) {
  const allowed = new Set(
    plans
      .map((plan) => plan.temporary)
      .filter((temporary) => temporary !== null),
  );
  const parents = [...new Set(plans.map((plan) => path.dirname(plan.target)))];
  for (const parent of parents) {
    if (!pathEntryExists(parent)) continue;
    const parentStat = fs.lstatSync(parent);
    assertControl(
      parentStat.isDirectory() && !parentStat.isSymbolicLink(),
      'HANDOFF_PATH_COLLISION',
      `tracked import parent ${parent} 不是普通目录`,
    );
    for (const name of fs.readdirSync(parent)) {
      if (!name.startsWith(IMPORT_TRACKED_TEMP_PREFIX)) continue;
      assertControl(
        allowed.has(path.join(parent, name)),
        'HANDOFF_IMPORT_TEMP_CONFLICT',
        `发现 foreign tracked import temp ${path.join(parent, name)}`,
      );
    }
  }
}

function writeTrackedImportTemporary(plan) {
  const expected = plan.expected;
  assertControl(
    expected !== null && plan.temporary !== null,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import ${plan.relative} 缺 expected temp identity`,
  );
  ensureMaterializationParents(plan.worktree, plan.relative);
  if (expected.type === 'symlink') {
    if (!pathEntryExists(plan.temporary)) {
      fs.symlinkSync(expected.body.toString('utf8'), plan.temporary);
      fsyncDirectory(path.dirname(plan.temporary));
    }
    inspectTrackedImportTemporary(plan);
    return;
  }
  let prepared = inspectTrackedImportTemporary(plan);
  if (prepared && !prepared.complete) {
    let descriptor;
    try {
      const before = fs.lstatSync(plan.temporary);
      descriptor = fs.openSync(
        plan.temporary,
        fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0),
      );
      const opened = fs.fstatSync(descriptor);
      assertControl(
        before.dev === opened.dev
          && before.ino === opened.ino
          && opened.isFile()
          && opened.nlink === 1
          && (opened.mode & 0o777) === 0o600
          && (
            typeof process.getuid !== 'function'
              || opened.uid === process.getuid()
          ),
        'HANDOFF_IMPORT_TEMP_CONFLICT',
        `tracked import temp ${plan.relative} resume 时 inode 漂移`,
      );
      fs.ftruncateSync(descriptor, 0);
      fs.writeFileSync(descriptor, expected.body);
      fs.fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    prepared = inspectTrackedImportTemporary(plan);
  }
  if (!prepared) {
    let descriptor;
    try {
      descriptor = fs.openSync(
        plan.temporary,
        fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | (fs.constants.O_NOFOLLOW || 0),
        0o600,
      );
      fs.writeFileSync(descriptor, expected.body);
      fs.fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    fsyncDirectory(path.dirname(plan.temporary));
    prepared = inspectTrackedImportTemporary(plan);
  }
  assertControl(
    prepared && prepared.complete && prepared.stat.nlink === 1,
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import temp ${plan.relative} 未完整 seal`,
  );
  if (
    (prepared.stat.mode & 0o777) !== desiredImportEntryMode(expected)
  ) {
    let descriptor;
    try {
      const before = fs.lstatSync(plan.temporary);
      descriptor = fs.openSync(
        plan.temporary,
        fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0),
      );
      const opened = fs.fstatSync(descriptor);
      assertControl(
        before.dev === opened.dev
          && before.ino === opened.ino
          && opened.nlink === 1
          && fs.readFileSync(descriptor).equals(expected.body),
        'HANDOFF_IMPORT_TEMP_CONFLICT',
        `tracked import temp ${plan.relative} seal 前 identity/body 漂移`,
      );
      fs.fchmodSync(descriptor, desiredImportEntryMode(expected));
      fs.fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
  }
  const sealed = inspectTrackedImportTemporary(plan);
  assertControl(
    sealed
      && sealed.complete
      && sealed.stat.nlink === 1
      && (sealed.stat.mode & 0o777)
        === desiredImportEntryMode(expected),
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import temp ${plan.relative} final seal 不匹配`,
  );
}

function cleanupTrackedImportTemporary(plan) {
  const temporary = inspectTrackedImportTemporary(plan);
  if (!temporary) return;
  assertControl(
    trackedMaterializationState(plan) === 'expected',
    'HANDOFF_IMPORT_TEMP_CONFLICT',
    `tracked import temp ${plan.relative} cleanup 前 target 尚未 expected`,
  );
  if (temporary.stat.nlink === 2) {
    const target = fs.lstatSync(plan.target);
    assertControl(
      target.dev === temporary.stat.dev
        && target.ino === temporary.stat.ino
        && target.nlink === 2,
      'HANDOFF_IMPORT_TEMP_CONFLICT',
      `tracked import temp ${plan.relative} cleanup 前 hard-link lineage 分叉`,
    );
  }
  fs.unlinkSync(plan.temporary);
  fsyncDirectory(path.dirname(plan.temporary));
}

function materializeTrackedImportPlan(root, plan) {
  validateMaterializationParents(plan.worktree, plan.relative);
  ensureImportParentMarker(plan);
  assertImportParentBound(plan);
  if (trackedMaterializationState(plan) === 'expected') {
    cleanupTrackedImportTemporary(plan);
    cleanupTrackedBaseAnchor(plan);
    return;
  }
  if (plan.expected === null) {
    assertControl(
      trackedMaterializationState(plan) === 'base',
      'HANDOFF_DESTINATION_DIRTY',
      `tracked delete ${plan.relative} target 在 unlink 前漂移`,
    );
    ensureTrackedBaseAnchor(plan);
    assertImportParentBound(plan);
    ensureTrackedBaseAnchor(plan);
    fs.unlinkSync(plan.target);
    fsyncDirectory(path.dirname(plan.target));
    assertControl(
      trackedMaterializationState(plan) === 'expected',
      'HANDOFF_IMPORT_ENTRY_CONFLICT',
      `tracked delete ${plan.relative} 未收敛为 expected`,
    );
    cleanupTrackedBaseAnchor(plan);
    return;
  }
  ensureMaterializationParents(plan.worktree, plan.relative);
  writeTrackedImportTemporary(plan);
  assertControl(
    trackedMaterializationState(plan) === 'base',
    'HANDOFF_DESTINATION_DIRTY',
    `tracked import ${plan.relative} promote 前 target 漂移`,
  );
  const baseExists = plan.base !== null;
  if (baseExists) {
    ensureTrackedBaseAnchor(plan);
    assertImportParentBound(plan);
    ensureTrackedBaseAnchor(plan);
    maybeReplaceTrackedTargetAfterCasForTest(root, plan);
    // index.lock excludes ordinary Git writers.  The hard-link anchor detects
    // same-uid atomic-save substitution at each explicit check, including the
    // deterministic window above.  Node does not expose an openat2/renameat2
    // compare-and-swap that can bind the final pathname check to rename(2), so
    // a hostile same-uid writer can still race in the nanosecond after this
    // last check.  Closing that residual boundary requires a native/brokered
    // fd-relative CAS primitive; never weaken this final fail-closed check.
    ensureTrackedBaseAnchor(plan);
    fs.renameSync(plan.temporary, plan.target);
  } else if (plan.expected.type === 'symlink') {
    try {
      fs.symlinkSync(
        plan.expected.body.toString('utf8'),
        plan.target,
      );
    } catch (error) {
      throw new ControlError(
        error && error.code === 'EEXIST'
          ? 'HANDOFF_IMPORT_ENTRY_CONFLICT'
          : 'HANDOFF_IMPORT_TEMP_PROMOTE_FAILED',
        error && error.code === 'EEXIST'
          ? `tracked import target ${plan.relative} 并发出现`
          : `tracked symlink ${plan.relative} no-clobber publish 失败: ${error.message}`,
      );
    }
    assertControl(
      trackedMaterializationState(plan) === 'expected',
      'HANDOFF_IMPORT_ENTRY_CONFLICT',
      `tracked symlink ${plan.relative} no-clobber publish 未收敛`,
    );
    fs.unlinkSync(plan.temporary);
  } else {
    try {
      fs.linkSync(plan.temporary, plan.target);
    } catch (error) {
      throw new ControlError(
        error && error.code === 'EEXIST'
          ? 'HANDOFF_IMPORT_ENTRY_CONFLICT'
          : 'HANDOFF_IMPORT_TEMP_PROMOTE_FAILED',
        error && error.code === 'EEXIST'
          ? `tracked import target ${plan.relative} 并发出现`
          : `tracked import target ${plan.relative} no-clobber publish 失败: ${error.message}`,
      );
    }
    const temporary = fs.lstatSync(plan.temporary);
    const target = fs.lstatSync(plan.target);
    assertControl(
      temporary.dev === target.dev
        && temporary.ino === target.ino
        && temporary.nlink === 2
        && target.nlink === 2,
      'HANDOFF_IMPORT_TEMP_CONFLICT',
      `tracked import target ${plan.relative} hard-link lineage 不匹配`,
    );
    fs.unlinkSync(plan.temporary);
  }
  fsyncDirectory(path.dirname(plan.target));
  assertControl(
    trackedMaterializationState(plan) === 'expected',
    'HANDOFF_IMPORT_ENTRY_CONFLICT',
    `tracked import target ${plan.relative} 未收敛为 expected`,
  );
  cleanupTrackedBaseAnchor(plan);
  maybeExitImportEntryForTest(
    root,
    'GOAL_CONTROL_TEST_EXIT_AFTER_TRACKED_IMPORT_PROMOTE',
    110,
  );
}

function materializeTrackedImportPlans(root, plans) {
  assertTrackedImportTempInventory(plans);
  for (const plan of plans) {
    materializeTrackedImportPlan(root, plan);
  }
  assertTrackedImportTempInventory(plans);
}

function importIndexAnchor(destination, snapshot, intent) {
  const indexFile = gitIndexPath(destination.worktree);
  const digest = hashObject({
    schema_version: 1,
    kind: 'RECOVERY_IMPORT_INDEX',
    goal_id: intent.goal_id,
    task_id: intent.task_id,
    import_id: intent.import_id,
    request_sha256: intent.request_sha256,
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    destination_worktree: destination.worktree,
    destination_branch: destination.branch,
    index_file: indexFile,
  }).slice('sha256:'.length);
  return {
    indexFile,
    lockFile: `${indexFile}.lock`,
    anchor: path.join(
      path.dirname(indexFile),
      `${IMPORT_INDEX_ANCHOR_PREFIX}${digest}.anchor`,
    ),
  };
}

function assertImportIndexAnchorInventory(location) {
  const directory = path.dirname(location.indexFile);
  for (const name of fs.readdirSync(directory)) {
    if (!name.startsWith(IMPORT_INDEX_ANCHOR_PREFIX)) continue;
    assertControl(
      path.join(directory, name) === location.anchor,
      'HANDOFF_GIT_INDEX_LOCKED',
      `发现 foreign source import index anchor ${name}`,
    );
  }
}

function inspectImportIndexAnchor(location, expectedBody) {
  if (!pathEntryExists(location.anchor)) return null;
  const stat = fs.lstatSync(location.anchor);
  assertCurrentOwnerFile(
    stat,
    [0o600],
    'HANDOFF_GIT_INDEX_LOCKED',
    'source import index anchor 不是当前 owner 的 0600 普通文件',
  );
  assertControl(
    stat.nlink === 1 || stat.nlink === 2,
    'HANDOFF_GIT_INDEX_LOCKED',
    'source import index anchor link count 非法',
  );
  const body = fs.readFileSync(location.anchor);
  assertControl(
    body.length <= expectedBody.length
      && expectedBody.subarray(0, body.length).equals(body),
    'HANDOFF_GIT_INDEX_LOCKED',
    'source import index anchor 不是 sealed index prefix',
  );
  return {
    stat,
    complete: body.length === expectedBody.length,
  };
}

function ensureCompleteImportIndexAnchor(location, expectedBody) {
  let anchor = inspectImportIndexAnchor(location, expectedBody);
  if (anchor && !anchor.complete) {
    assertControl(
      anchor.stat.nlink === 1 && !pathEntryExists(location.lockFile),
      'HANDOFF_GIT_INDEX_LOCKED',
      'partial source import index anchor 已被 publish',
    );
    let descriptor;
    try {
      const before = fs.lstatSync(location.anchor);
      descriptor = fs.openSync(
        location.anchor,
        fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0),
      );
      const opened = fs.fstatSync(descriptor);
      assertControl(
        before.dev === opened.dev
          && before.ino === opened.ino
          && opened.nlink === 1
          && (opened.mode & 0o777) === 0o600,
        'HANDOFF_GIT_INDEX_LOCKED',
        'source import index anchor resume 时 inode 漂移',
      );
      fs.ftruncateSync(descriptor, 0);
      fs.writeFileSync(descriptor, expectedBody);
      fs.fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    anchor = inspectImportIndexAnchor(location, expectedBody);
  }
  if (!anchor) {
    let descriptor;
    try {
      descriptor = fs.openSync(
        location.anchor,
        fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | (fs.constants.O_NOFOLLOW || 0),
        0o600,
      );
      fs.writeFileSync(descriptor, expectedBody);
      fs.fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    fsyncDirectory(path.dirname(location.anchor));
    anchor = inspectImportIndexAnchor(location, expectedBody);
  }
  assertControl(
    anchor && anchor.complete && anchor.stat.nlink === 1,
    'HANDOFF_GIT_INDEX_LOCKED',
    'source import index anchor 未完整 seal',
  );
  return anchor;
}

function assertImportIndexRecoveryState(
  destination,
  snapshot,
  intent,
  indexBody,
) {
  const location = importIndexAnchor(destination, snapshot, intent);
  assertImportIndexAnchorInventory(location);
  const anchor = inspectImportIndexAnchor(location, indexBody);
  if (pathEntryExists(location.lockFile)) {
    assertControl(
      anchor && anchor.complete,
      'HANDOFF_GIT_INDEX_LOCKED',
      'destination index.lock 存在但缺 transaction-owned complete anchor',
    );
    const lock = fs.lstatSync(location.lockFile);
    assertControl(
      lock.isFile()
        && !lock.isSymbolicLink()
        && lock.dev === anchor.stat.dev
        && lock.ino === anchor.stat.ino
        && lock.nlink === 2
        && anchor.stat.nlink === 2
        && fs.readFileSync(location.lockFile).equals(indexBody),
      'HANDOFF_GIT_INDEX_LOCKED',
      'destination index.lock 不是 transaction-owned same-inode lock',
    );
    return location;
  }
  if (anchor && anchor.stat.nlink === 2) {
    const canonical = fs.lstatSync(location.indexFile);
    assertControl(
      anchor.complete
        && canonical.dev === anchor.stat.dev
        && canonical.ino === anchor.stat.ino
        && canonical.nlink === 2
        && fs.readFileSync(location.indexFile).equals(indexBody),
      'HANDOFF_GIT_INDEX_LOCKED',
      'source import index anchor 的 second link 不属于 canonical index',
    );
  }
  return location;
}

function acquireImportIndexPublicationLock(
  destination,
  snapshot,
  intent,
  indexBody,
) {
  const location = assertImportIndexRecoveryState(
    destination,
    snapshot,
    intent,
    indexBody,
  );
  const baseTree = gitText(
    destination.worktree,
    ['rev-parse', `${snapshot.source_observed_head}^{tree}`],
  );
  const currentTree = readIndexTreeWithoutCanonicalMutation(
    destination.worktree,
    {
      code: 'HANDOFF_DESTINATION_DIRTY',
      label: 'inspect canonical import index before worktree materialization',
    },
  );
  if (currentTree === snapshot.expected_tree) return location;
  assertControl(
    currentTree === baseTree,
    'HANDOFF_DESTINATION_DIRTY',
    'canonical import index 不是 sealed base/expected',
  );
  if (pathEntryExists(location.lockFile)) {
    const anchor = inspectImportIndexAnchor(location, indexBody);
    const lock = fs.lstatSync(location.lockFile);
    assertControl(
      anchor
        && anchor.complete
        && lock.isFile()
        && !lock.isSymbolicLink()
        && lock.dev === anchor.stat.dev
        && lock.ino === anchor.stat.ino
        && lock.nlink === 2
        && anchor.stat.nlink === 2
        && fs.readFileSync(location.lockFile).equals(indexBody),
      'HANDOFF_GIT_INDEX_LOCKED',
      'destination index.lock 不是 transaction-owned same-inode lock',
    );
    return location;
  }
  const anchor = ensureCompleteImportIndexAnchor(location, indexBody);
  try {
    fs.linkSync(location.anchor, location.lockFile);
  } catch (error) {
    throw new ControlError(
      error && error.code === 'EEXIST'
        ? 'HANDOFF_GIT_INDEX_LOCKED'
        : 'HANDOFF_GIT_INDEX_LOCK_FAILED',
      error && error.code === 'EEXIST'
        ? 'destination index.lock 并发出现'
        : `source import index lock hard-link publish 失败: ${error.message}`,
    );
  }
  fsyncDirectory(path.dirname(location.lockFile));
  return location;
}

function publishImportIndex(
  root,
  destination,
  snapshot,
  intent,
  indexBody,
) {
  const location = assertImportIndexRecoveryState(
    destination,
    snapshot,
    intent,
    indexBody,
  );
  const currentTree = readIndexTreeWithoutCanonicalMutation(
    destination.worktree,
    {
      code: 'HANDOFF_MATERIALIZED_TREE_MISMATCH',
      label: 'inspect canonical import index before publish',
    },
  );
  assertControl(
    currentTree === snapshot.expected_tree
      || currentTree === gitText(
        destination.worktree,
        ['rev-parse', `${snapshot.source_observed_head}^{tree}`],
      ),
    'HANDOFF_DESTINATION_DIRTY',
    'canonical import index 不是 sealed base/expected',
  );
  const baseTree = gitText(
    destination.worktree,
    ['rev-parse', `${snapshot.source_observed_head}^{tree}`],
  );
  const anchorAtEntry = inspectImportIndexAnchor(location, indexBody);
  if (currentTree === snapshot.expected_tree) {
    assertControl(
      !pathEntryExists(location.lockFile),
      'HANDOFF_GIT_INDEX_LOCKED',
      'canonical import index 已 expected 但仍存在 index.lock',
    );
    if (anchorAtEntry) {
      const canonical = fs.lstatSync(location.indexFile);
      assertControl(
        anchorAtEntry.complete
          && anchorAtEntry.stat.dev === canonical.dev
          && anchorAtEntry.stat.ino === canonical.ino
          && canonical.nlink === 2
          && fs.readFileSync(location.indexFile).equals(indexBody),
        'HANDOFF_GIT_INDEX_LOCKED',
        'expected canonical index 与 transaction anchor lineage 分叉',
      );
      fs.unlinkSync(location.anchor);
      fsyncDirectory(path.dirname(location.anchor));
    }
    return;
  }
  assertControl(
    currentTree === baseTree,
    'HANDOFF_DESTINATION_DIRTY',
    'canonical import index 不是 sealed base',
  );
  acquireImportIndexPublicationLock(
    destination,
    snapshot,
    intent,
    indexBody,
  );
  maybeExitImportEntryForTest(
    root,
    'GOAL_CONTROL_TEST_EXIT_AFTER_IMPORT_INDEX_LOCK_PUBLISH',
    111,
  );
  const beforePublishTree = readIndexTreeWithoutCanonicalMutation(
    destination.worktree,
    {
      code: 'HANDOFF_DESTINATION_DIRTY',
      label: 'recheck canonical import index before rename',
    },
  );
  assertControl(
    beforePublishTree === baseTree,
    'HANDOFF_DESTINATION_DIRTY',
    'canonical import index 在 publish 前漂移',
  );
  const lockBeforeRename = fs.lstatSync(location.lockFile);
  const anchorBeforeRename = fs.lstatSync(location.anchor);
  assertControl(
    lockBeforeRename.dev === anchorBeforeRename.dev
      && lockBeforeRename.ino === anchorBeforeRename.ino
      && lockBeforeRename.nlink === 2
      && anchorBeforeRename.nlink === 2,
    'HANDOFF_GIT_INDEX_LOCKED',
    'source import index lock/anchor publish lineage 漂移',
  );
  fs.renameSync(location.lockFile, location.indexFile);
  fsyncDirectory(path.dirname(location.indexFile));
  const canonical = fs.lstatSync(location.indexFile);
  const retainedAnchor = fs.lstatSync(location.anchor);
  assertControl(
    canonical.dev === retainedAnchor.dev
      && canonical.ino === retainedAnchor.ino
      && canonical.nlink === 2
      && retainedAnchor.nlink === 2
      && fs.readFileSync(location.indexFile).equals(indexBody),
    'HANDOFF_GIT_INDEX_LOCK_FAILED',
    'source import canonical index publish lineage 不匹配',
  );
  fs.unlinkSync(location.anchor);
  fsyncDirectory(path.dirname(location.anchor));
  assertControl(
    readIndexTreeWithoutCanonicalMutation(
      destination.worktree,
      {
        code: 'HANDOFF_MATERIALIZED_TREE_MISMATCH',
        label: 'verify published import index',
      },
    ) === snapshot.expected_tree,
    'HANDOFF_MATERIALIZED_TREE_MISMATCH',
    'published canonical import index tree 不匹配',
  );
}

function inspectImportMaterialization(
  root,
  destination,
  artifacts,
  snapshot,
  intent,
) {
  assertNoGitOperationInProgress(destination.worktree);
  const isolated = buildIsolatedImportPlan(
    root,
    destination,
    artifacts,
    snapshot,
    intent,
  );
  assertImportIndexRecoveryState(
    destination,
    snapshot,
    intent,
    isolated.indexBody,
  );
  assertControl(
    isolated.baseTree !== isolated.expectedTree
      || snapshot.expected_paths.length === 0,
    'HANDOFF_CHANGED_PATHS_MISMATCH',
    'snapshot expected_paths 非空但 isolated tree 未变化',
  );
  assertImportEntryTempInventory(isolated.entryPlans);
  assertTrackedImportTempInventory(isolated.trackedPlans);
  for (const plan of isolated.entryPlans) {
    validateMaterializationParents(
      destination.worktree,
      plan.entry.path,
    );
    let targetExists = false;
    try {
      fs.lstatSync(plan.target);
      targetExists = true;
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }
    if (targetExists) assertExactMaterializedEntry(plan);
    inspectImportEntryTemporary(plan);
  }
  for (const plan of isolated.trackedPlans) {
    validateMaterializationParents(
      destination.worktree,
      plan.relative,
    );
    trackedMaterializationState(plan);
    inspectTrackedImportTemporary(plan);
  }

  const unstaged = splitNullPaths(
    gitBuffer(
      destination.worktree,
      ['diff', '--name-only', '-z', '--'],
    ),
    'import unstaged path',
  );
  const allowedUnstaged = new Set(
    isolated.trackedPlans.map((plan) => plan.relative),
  );
  assertControl(
    unstaged.every((relative) => allowedUnstaged.has(relative)),
    'HANDOFF_DESTINATION_DIRTY',
    'destination tracked worktree 含 foreign unstaged 内容',
  );
  const untracked = splitNullPaths(
    gitBuffer(
      destination.worktree,
      ['ls-files', '--others', '--exclude-standard', '-z', '--'],
    ),
    'import untracked path',
  );
  const allowedUntracked = new Set();
  for (const plan of isolated.entryPlans) {
    allowedUntracked.add(plan.entry.path);
    allowedUntracked.add(
      path.relative(destination.worktree, plan.parentMarker)
        .split(path.sep)
        .join('/'),
    );
    if (plan.temporary !== null) {
      allowedUntracked.add(
        path.relative(destination.worktree, plan.temporary)
          .split(path.sep)
          .join('/'),
      );
    }
  }
  for (const plan of isolated.trackedPlans) {
    if (plan.base === null) allowedUntracked.add(plan.relative);
    allowedUntracked.add(
      path.relative(destination.worktree, plan.parentMarker)
        .split(path.sep)
        .join('/'),
    );
    if (plan.baseAnchor !== null) {
      allowedUntracked.add(
        path.relative(destination.worktree, plan.baseAnchor)
          .split(path.sep)
          .join('/'),
      );
    }
    if (plan.temporary !== null) {
      allowedUntracked.add(
        path.relative(destination.worktree, plan.temporary)
          .split(path.sep)
          .join('/'),
      );
    }
  }
  assertControl(
    untracked.every((relative) => allowedUntracked.has(relative)),
    'HANDOFF_DESTINATION_DIRTY',
    'destination 含 foreign untracked import 内容',
  );

  const indexTree = readIndexTreeWithoutCanonicalMutation(
    destination.worktree,
    {
      code: 'HANDOFF_MATERIALIZED_TREE_MISMATCH',
      label: 'inspect import index tree',
    },
  );
  assertFullSha(indexTree, 'import index tree');
  assertControl(
    indexTree === isolated.baseTree
      || indexTree === isolated.expectedTree,
    'HANDOFF_DESTINATION_DIRTY',
    'destination index 不是 sealed base/full exact import state',
  );
  assertNoGitOperationInProgress(destination.worktree);
  return {
    ...isolated,
    indexTree,
  };
}

function assertImportedReceiptState(destination, snapshot, receipt) {
  assertNoGitOperationInProgress(destination.worktree);
  assertControl(
    receipt.destination_worktree === destination.worktree
      && receipt.destination_branch === destination.branch
      && receipt.destination_head_before === destination.head,
    'HANDOFF_SNAPSHOT_ALREADY_IMPORTED',
    `snapshot ${snapshot.snapshot_id} 已由其它 destination identity 导入`,
  );
  const unstaged = gitBuffer(
    destination.worktree,
    ['diff', '--name-only', '-z', '--'],
  );
  const remainingUntracked = gitBuffer(
    destination.worktree,
    ['ls-files', '--others', '--exclude-standard', '-z', '--'],
  );
  assertControl(
    unstaged.length === 0 && remainingUntracked.length === 0,
    'HANDOFF_IMPORT_RETRY_MISMATCH',
    '既有 import receipt 的 destination 含额外 unstaged/untracked 内容',
  );
  const materializedTree = readIndexTreeWithoutCanonicalMutation(
    destination.worktree,
    {
      code: 'HANDOFF_IMPORT_RETRY_MISMATCH',
      label: 'write retry materialized tree',
    },
  );
  assertControl(
    materializedTree === snapshot.expected_tree
      && materializedTree === receipt.expected_tree
      && materializedTree === receipt.materialized_tree,
    'HANDOFF_IMPORT_RETRY_MISMATCH',
    '既有 import receipt 的 staged tree 已漂移',
  );
  const materializedPaths = changedPathsInIndex(
    destination.worktree,
    snapshot.source_observed_head,
  );
  assertSameChangedPaths(
    materializedPaths,
    snapshot.expected_paths,
    'HANDOFF_IMPORT_RETRY_MISMATCH',
    '既有 import receipt 的 staged paths',
  );
  const materialized = trackedPatch(
    destination.worktree,
    snapshot.source_observed_head,
    true,
  );
  assertControl(
    materialized.length === receipt.materialized_patch_bytes
      && `sha256:${sha256(materialized)}` === receipt.materialized_patch_sha256,
    'HANDOFF_IMPORT_RETRY_MISMATCH',
    '既有 import receipt 的 staged patch 已漂移',
  );
  assertNoGitOperationInProgress(destination.worktree);
}

function assertSnapshotCurrent(loaded, state, successor, snapshot) {
  assertControl(snapshot.control_epoch === loaded.control.epoch, 'STALE_CONTROL_EPOCH', 'snapshot control epoch 陈旧');
  assertControl(
    snapshot.packet_revision === state.packet.revision && snapshot.packet_sha256 === state.packet.sha256,
    'STALE_PACKET',
    'snapshot packet 陈旧',
  );
  assertControl(snapshot.task_full_head === state.full_head, 'STALE_HEAD', 'snapshot task HEAD 陈旧');
  assertControl(
    snapshot.predecessor_launch_id === successor.recovered_from.predecessor_launch_id,
    'RECOVERY_HANDOFF_MISMATCH',
    'snapshot predecessor launch 与 recovery lineage 不一致',
  );
}

function importRecoverySnapshot(cwd, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const importId = safeId(options.importId, 'import_id');
  const snapshotId = safeId(options.snapshotId, 'snapshot_id');
  const successorThreadId = safeId(options.successorThreadId, 'successor_thread_id');
  const root = controlRoot(cwd);
  let receiptPublished = false;
  const retryBoundary = {
    transactionStartedAt: null,
    historicalRetry: false,
  };
  let result;
  try {
    result = withLock(root, () => {
    const artifacts = readSnapshotArtifacts(root, goalId, taskId, snapshotId);
    const snapshot = artifacts.snapshot;
    assertExactTreeSnapshot(snapshot);
    assertControl(snapshot.successor_thread_id === successorThreadId, 'HANDOFF_SNAPSHOT_MISMATCH', 'snapshot successor 不匹配');
    const existingImport = findSnapshotReceipt(root, goalId, taskId, snapshotId);
    const requestedReceiptFile = receiptFile(root, goalId, taskId, importId);
    if (!existingImport && fs.existsSync(requestedReceiptFile)) {
      readReceipt(root, goalId, taskId, importId);
      assertControl(
        false,
        'HANDOFF_OPERATION_CONFLICT',
        `import operation ${importId} 已绑定其它 snapshot`,
      );
    }
    if (existingImport && existingImport.receipt.schema_version === RECEIPT_SCHEMA_VERSION) {
      assertControl(
        existingImport.receipt.import_receipt_id === importId,
        'HANDOFF_SNAPSHOT_ALREADY_IMPORTED',
        `snapshot ${snapshotId} 已由 import operation ${existingImport.receipt.import_receipt_id} 导入`,
      );
      assertReceiptSnapshotBinding(existingImport.receipt, snapshot, {
        goalId,
        taskId,
        successorThreadId,
      });
      const loaded = loadGoalUnlocked(root, goalId);
      const state = loaded.snapshot.tasks[taskId];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
      authorizeSealedAuthority(
        state,
        options.actorCapabilityFile,
        existingImport.receipt.acceptance_authority.dev,
      );
      const destination = repositoryIdentity(cwd);
      assertNoGitOperationInProgress(destination.worktree);
      assertReceiptDestinationIdentity(
        destination,
        snapshot,
        existingImport.receipt,
      );
      assertNoGitOperationInProgress(destination.worktree);
      return importReceiptResult(existingImport, true);
    }

    const destination = repositoryIdentity(cwd);
    assertNoGitOperationInProgress(destination.worktree);
    assertControl(destination.common_git_dir === snapshot.common_git_dir, 'REPOSITORY_ROOT_MISMATCH', 'destination 与 source 不属于同一 Git common dir');
    assertControl(destination.repository_root === snapshot.repository_root, 'REPOSITORY_ROOT_MISMATCH', 'destination repository root 不匹配');
    assertControl(destination.worktree !== snapshot.source_worktree, 'HANDOFF_SAME_WORKTREE', 'source handoff 必须导入不同 worktree');
    assertControl(destination.branch !== snapshot.source_branch, 'HANDOFF_SAME_BRANCH', 'source handoff 必须导入不同命名分支');
    assertControl(destination.head === snapshot.source_observed_head, 'HANDOFF_BASE_MISMATCH', `destination HEAD 必须精确等于 ${snapshot.source_observed_head}`);
    assertAncestor(destination.worktree, snapshot.source_launch_head, snapshot.source_observed_head);
    const importRequest = recoveryImportRequest(
      goalId,
      taskId,
      importId,
      snapshot,
      successorThreadId,
      destination,
    );
    const importRequestSha256 = hashObject(importRequest);
    const recoveredImportIntent = recoverImportIntentStaging(
      root,
      goalId,
      taskId,
      importId,
    );
    let importIntent = recoveredImportIntent && recoveredImportIntent.sealed
      ? {
        intent: recoveredImportIntent.intent,
        file: recoveredImportIntent.file,
      }
      : null;
    let goalLoadOptions = {};
    if (recoveredImportIntent) {
      if (recoveredImportIntent.sealed) {
        goalLoadOptions = {
          allowPendingGoalOperation: {
            kind: 'SOURCE_IMPORT',
            operation_id: importId,
            request_sha256: recoveredImportIntent.intent.request_sha256,
          },
        };
      } else if (
        recoveredImportIntent.stable === true
          && recoveredImportIntent.candidate.format === 'atomic-stable'
      ) {
        assertControl(
          retryBoundary.historicalRetry,
          'HANDOFF_OPERATION_CONFLICT',
          `import operation ${importId} 含无 transaction recovery authority 的空 stable intent 目录`,
        );
        goalLoadOptions = {
          allowIncompleteGoalOperationRead: true,
        };
      } else {
        assertControl(
          recoveredImportIntent.candidate.format === 'v2',
          'HANDOFF_STAGING_INVALID',
          `import operation ${importId} legacy empty staging 无 durable request identity`,
        );
        goalLoadOptions = {
          allowPendingGoalOperation: {
            kind: 'SOURCE_IMPORT',
            operation_id: importId,
            request_sha256:
              `sha256:${recoveredImportIntent.candidate.requestDigest}`,
          },
        };
      }
    }
    const loaded = loadGoalUnlocked(
      root,
      goalId,
      goalLoadOptions,
    );
    const { state, successor } = sourceSessionContext(
      loaded,
      taskId,
      successorThreadId,
    );
    assertSnapshotCurrent(loaded, state, successor, snapshot);
    const predecessor = canonicalLaunch(loaded, taskId, successor);
    assertSnapshotPredecessorBinding(snapshot, predecessor);
    assertControl(predecessor.sha256 === snapshot.predecessor_launch_sha256, 'HANDOFF_LAUNCH_TAMPERED', 'predecessor launch hash 已变化');
    assertControl(
      predecessor.launch.repository.full_head === snapshot.source_launch_head,
      'RECOVERY_HANDOFF_MISMATCH',
      'snapshot source launch HEAD 与 canonical launch 不一致',
    );
    let actorAuthority;
    let importedAt;
    if (importIntent) {
      const sealed = importIntent.intent;
      assertControl(
        sealed.request_sha256 === importRequestSha256
          && hashObject(sealed.request) === hashObject(importRequest)
          && sealed.snapshot_sha256 === snapshot.snapshot_sha256
          && sealed.successor_thread_id === successorThreadId,
        'HANDOFF_OPERATION_CONFLICT',
        `import operation ${importId} 已绑定不同 request/destination`,
      );
      authorizeSealedAuthority(
        state,
        options.actorCapabilityFile,
        sealed.acceptance_authority.dev,
      );
      assertControl(
        sealed.task_anchor.control_epoch === loaded.control.epoch
          && sealed.task_anchor.state_revision === state.state_revision
          && sealed.task_anchor.packet_revision === state.packet.revision
          && sealed.task_anchor.packet_sha256 === state.packet.sha256
          && sealed.task_anchor.full_head === state.full_head,
        'HANDOFF_IMPORT_INTENT_DIVERGED',
        `import operation ${importId} 后 task state 已漂移`,
      );
      actorAuthority = sealed.acceptance_authority.dev;
      importedAt = sealed.accepted_at;
    } else {
      if (retryBoundary.historicalRetry) {
        actorAuthority = authorityFromSession(successor);
        authorizeSealedAuthority(
          state,
          options.actorCapabilityFile,
          actorAuthority,
        );
        assertControl(
          typeof retryBoundary.transactionStartedAt === 'string'
            && Number.isFinite(
              Date.parse(retryBoundary.transactionStartedAt),
            )
            && Date.parse(successor.lease_until)
              > Date.parse(retryBoundary.transactionStartedAt),
          'ACTOR_LEASE_EXPIRED',
          `DEV 在 sealed import transaction boundary 已过期: ${successor.lease_until}`,
        );
      } else {
        const actor = authorizeSession(
          state,
          options.actorCapabilityFile,
          { role: 'DEV', threadId: successorThreadId },
        );
        actorAuthority = authorityFromSession(actor);
      }
      importedAt = retryBoundary.transactionStartedAt || nowIso();
      const taskAnchor = {
        control_epoch: loaded.control.epoch,
        state_revision: state.state_revision,
        packet_revision: state.packet.revision,
        packet_sha256: state.packet.sha256,
        full_head: state.full_head,
      };
      const acceptanceAuthority = { dev: actorAuthority };
      const preparedRequestSha256 = hashObject({
        request: importRequest,
        task_anchor: taskAnchor,
        acceptance_authority: acceptanceAuthority,
      });
      let allowAtomicStableEmpty = false;
      if (recoveredImportIntent && recoveredImportIntent.empty === true) {
        if (
          recoveredImportIntent.stable === true
            && recoveredImportIntent.candidate.format === 'atomic-stable'
        ) {
          allowAtomicStableEmpty = retryBoundary.historicalRetry;
        } else {
          assertControl(
            recoveredImportIntent.candidate.format === 'v2'
              && recoveredImportIntent.candidate.requestDigest
                === importRequestSha256.slice('sha256:'.length)
              && recoveredImportIntent.candidate.preparedRequestDigest
                === preparedRequestSha256.slice('sha256:'.length),
            'HANDOFF_OPERATION_CONFLICT',
            `import operation ${importId} empty staging 不是 exact prepared request`,
          );
          fs.rmdirSync(recoveredImportIntent.directory);
          fsyncDirectory(path.dirname(recoveredImportIntent.directory));
        }
      }
      importIntent = publishImportIntent(root, {
        schema_version: 1,
        kind: 'RECOVERY_IMPORT_INTENT',
        import_id: importId,
        goal_id: goalId,
        task_id: taskId,
        snapshot_id: snapshotId,
        snapshot_sha256: snapshot.snapshot_sha256,
        successor_thread_id: successorThreadId,
        request: importRequest,
        request_sha256: importRequestSha256,
        prepared_request_sha256: preparedRequestSha256,
        task_anchor: taskAnchor,
        acceptance_authority: acceptanceAuthority,
        accepted_at: importedAt,
      }, { allowAtomicStableEmpty });
    }
    adoptSourceImportIntentPublication(
      importIntent.file,
      `${JSON.stringify(importIntent.intent, null, 2)}\n`,
    );
    const { assertNoPendingTaskOperations } = require('./pending-operations');
    assertNoPendingTaskOperations(root, goalId, taskId, {
      allowOperationKind: 'SOURCE_IMPORT',
      allowOperationId: importId,
      allowRequestSha256: importRequestSha256,
    });
    if (existingImport) {
      const existing = existingImport.receipt;
      assertControl(
        existing.import_receipt_id === importId,
        'HANDOFF_SNAPSHOT_ALREADY_IMPORTED',
        `snapshot ${snapshotId} 已由 import operation ${existing.import_receipt_id} 导入`,
      );
      assertReceiptSnapshotBinding(existing, snapshot, {
        goalId,
        taskId,
        successorThreadId,
      });
      assertImportedReceiptState(destination, snapshot, existing);
      return importReceiptResult(existingImport, true);
    }
    const materialization = inspectImportMaterialization(
      root,
      destination,
      artifacts,
      snapshot,
      importIntent.intent,
    );
    acquireImportIndexPublicationLock(
      destination,
      snapshot,
      importIntent.intent,
      materialization.indexBody,
    );
    materializeTrackedImportPlans(
      root,
      materialization.trackedPlans,
    );
    materializeImportEntries(
      root,
      destination,
      materialization.entryPlans,
    );
    assertControl(
      materialization.trackedPlans.every((plan) => (
        trackedMaterializationState(plan) === 'expected'
      )),
      'HANDOFF_STAGE_INCOMPLETE',
      'tracked import worktree 未全量收敛为 expected',
    );
    publishImportIndex(
      root,
      destination,
      snapshot,
      importIntent.intent,
      materialization.indexBody,
    );
    cleanupImportParentMarkers([
      ...materialization.trackedPlans,
      ...materialization.entryPlans,
    ]);
    assertImportIntentAnchorReleased(importIntent);
    const materializedPaths = changedPathsInIndex(
      destination.worktree,
      snapshot.source_observed_head,
    );
    assertSameChangedPaths(
      materializedPaths,
      snapshot.expected_paths,
      'HANDOFF_CHANGED_PATHS_MISMATCH',
      'import staged changed paths 与 snapshot expected_paths',
    );
    const unstaged = gitBuffer(destination.worktree, ['diff', '--name-only', '-z', '--']);
    const remainingUntracked = gitBuffer(destination.worktree, ['ls-files', '--others', '--exclude-standard', '-z', '--']);
    assertControl(unstaged.length === 0 && remainingUntracked.length === 0, 'HANDOFF_STAGE_INCOMPLETE', 'snapshot 未被全量 stage');
    const materializedTree = readIndexTreeWithoutCanonicalMutation(
      destination.worktree,
      {
        code: 'HANDOFF_MATERIALIZED_TREE_MISMATCH',
        label: 'write materialized snapshot tree',
      },
    );
    assertFullSha(materializedTree, 'materialized snapshot tree');
    assertControl(
      materializedTree === snapshot.expected_tree,
      'HANDOFF_MATERIALIZED_TREE_MISMATCH',
      'import index tree 与 snapshot expected_tree 不一致',
    );
    const materialized = trackedPatch(
      destination.worktree,
      snapshot.source_observed_head,
      true,
    );
    assertControl(materialized.length <= MAX_SNAPSHOT_BYTES, 'HANDOFF_SNAPSHOT_TOO_LARGE', `materialized patch 超过 ${MAX_SNAPSHOT_BYTES} bytes`);
    assertNoGitOperationInProgress(destination.worktree);
    maybeInjectHandoffFault(
      root,
      'GOAL_CONTROL_TEST_FAULT_AFTER_IMPORT_MATERIALIZATION',
      'TEST_FAULT_AFTER_IMPORT_MATERIALIZATION',
      'injected failure after exact import materialization before receipt',
      88,
    );

    const receiptId = importId;
    const unsigned = {
      schema_version: RECEIPT_SCHEMA_VERSION,
      import_receipt_id: receiptId,
      snapshot_id: snapshot.snapshot_id,
      snapshot_sha256: snapshot.snapshot_sha256,
      goal_id: goalId,
      task_id: taskId,
      successor_thread_id: successorThreadId,
      predecessor_launch_id: snapshot.predecessor_launch_id,
      predecessor_launch_sha256: snapshot.predecessor_launch_sha256,
      source_worktree: snapshot.source_worktree,
      source_branch: snapshot.source_branch,
      source_launch_head: snapshot.source_launch_head,
      source_observed_head: snapshot.source_observed_head,
      destination_worktree: destination.worktree,
      destination_branch: destination.branch,
      destination_head_before: destination.head,
      expected_tree: snapshot.expected_tree,
      materialized_tree: materializedTree,
      materialized_patch_sha256: `sha256:${sha256(materialized)}`,
      materialized_patch_bytes: materialized.length,
      acceptance_authority: {
        dev: actorAuthority,
      },
      imported_at: importedAt,
    };
    const receipt = { ...unsigned, import_receipt_sha256: hashObject(unsigned) };
    const file = receiptFile(root, goalId, taskId, receiptId);
    assertControl(!fs.existsSync(file), 'HANDOFF_ARTIFACT_EXISTS', `import receipt ${receiptId} 已存在`);
    atomicWriteJson(file, receipt);
    receiptPublished = true;
    return {
      ...receipt,
      import_receipt_file: file,
      idempotent: false,
    };
    }, importOddRecoveryLockOptions(root, cwd, {
      goalId,
      taskId,
      importId,
      snapshotId,
      successorThreadId,
      actorCapabilityFile: options.actorCapabilityFile,
    }, retryBoundary));
  } catch (error) {
    exitDeferredHandoffFault(error);
  }
  if (receiptPublished) {
    try {
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_RECEIPT_PUBLISH',
        'TEST_FAULT_AFTER_RECEIPT_PUBLISH',
        'injected failure after durable recovery import receipt publication',
        87,
      );
    } catch (error) {
      exitDeferredHandoffFault(error);
    }
  }
  return result;
}

function recoveryCheckpointCommitSpec(snapshot, receipt) {
  const importedAt = Date.parse(receipt.imported_at);
  assertControl(
    Number.isFinite(importedAt) && importedAt >= 0,
    'HANDOFF_CHECKPOINT_RECEIPT_INVALID',
    'import receipt imported_at 不能生成 deterministic checkpoint date',
  );
  const timestamp = Math.floor(importedAt / 1000);
  const date = `@${timestamp} +0000`;
  const message = [
    `goalctl recovery checkpoint ${receipt.import_receipt_id}`,
    '',
    `Goal: ${receipt.goal_id}`,
    `Task: ${receipt.task_id}`,
    `Successor-Thread: ${receipt.successor_thread_id}`,
    `Snapshot: ${snapshot.snapshot_id}`,
    `Snapshot-SHA256: ${snapshot.snapshot_sha256}`,
    `Import-Receipt: ${receipt.import_receipt_id}`,
    `Import-Receipt-SHA256: ${receipt.import_receipt_sha256}`,
    `Expected-Tree: ${snapshot.expected_tree}`,
    `Imported-At: ${receipt.imported_at}`,
    '',
  ].join('\n');
  const identity = [
    RECOVERY_CHECKPOINT_AUTHOR_NAME,
    `<${RECOVERY_CHECKPOINT_AUTHOR_EMAIL}>`,
    timestamp,
    '+0000',
  ].join(' ');
  const body = Buffer.from([
    `tree ${snapshot.expected_tree}`,
    `parent ${snapshot.source_observed_head}`,
    `author ${identity}`,
    `committer ${identity}`,
    '',
    message,
  ].join('\n'));
  return {
    body,
    message,
    env: {
      GIT_AUTHOR_NAME: RECOVERY_CHECKPOINT_AUTHOR_NAME,
      GIT_AUTHOR_EMAIL: RECOVERY_CHECKPOINT_AUTHOR_EMAIL,
      GIT_AUTHOR_DATE: date,
      GIT_COMMITTER_NAME: RECOVERY_CHECKPOINT_AUTHOR_NAME,
      GIT_COMMITTER_EMAIL: RECOVERY_CHECKPOINT_AUTHOR_EMAIL,
      GIT_COMMITTER_DATE: date,
    },
  };
}

function assertRecoveryCheckpointIndex(
  destination,
  snapshot,
  receipt,
  options = {},
) {
  if (options.indexSnapshot) {
    const indexFile = gitIndexPath(destination.worktree);
    assertControl(
      indexFile === options.indexSnapshot.file
        && hashFile(indexFile) === options.indexSnapshot.sha256,
      'HANDOFF_CHECKPOINT_INDEX_DRIFT',
      'checkpoint Git index 在验证与 fence 之间已变化',
    );
  }
  assertNoGitOperationInProgress(destination.worktree);
  const unmerged = gitBuffer(
    destination.worktree,
    ['diff', '--name-only', '--diff-filter=U', '-z', '--'],
  );
  const unstaged = gitBuffer(
    destination.worktree,
    ['diff', '--name-only', '-z', '--'],
  );
  const untracked = gitBuffer(
    destination.worktree,
    ['ls-files', '--others', '--exclude-standard', '-z', '--'],
  );
  assertControl(
    unmerged.length === 0
      && unstaged.length === 0
      && untracked.length === 0,
    'HANDOFF_CHECKPOINT_DIRTY',
    'checkpoint destination 含 unmerged/unstaged/untracked 内容；拒绝 reset 或覆盖',
  );
  const indexTree = options.indexSnapshot
    ? options.indexSnapshot.tree
    : readIndexTreeWithoutCanonicalMutation(
      destination.worktree,
      {
        code: 'HANDOFF_CHECKPOINT_TREE_MISMATCH',
        label: 'write recovery checkpoint index tree',
      },
    );
  assertFullSha(indexTree, 'recovery checkpoint index tree');
  assertControl(
    indexTree === snapshot.expected_tree
      && indexTree === receipt.expected_tree
      && indexTree === receipt.materialized_tree,
    'HANDOFF_CHECKPOINT_TREE_MISMATCH',
    'checkpoint index tree 与 sealed snapshot/receipt 不一致',
  );
  const paths = changedPathsInIndex(
    destination.worktree,
    snapshot.source_observed_head,
  );
  assertSameChangedPaths(
    paths,
    snapshot.expected_paths,
    'HANDOFF_CHECKPOINT_PATHS_MISMATCH',
    'checkpoint index changed paths 与 snapshot expected_paths',
  );
  const patch = trackedPatch(
    destination.worktree,
    snapshot.source_observed_head,
    true,
  );
  assertControl(
    patch.length === receipt.materialized_patch_bytes
      && `sha256:${sha256(patch)}` === receipt.materialized_patch_sha256,
    'HANDOFF_CHECKPOINT_RECEIPT_MISMATCH',
    'checkpoint index diff 与 sealed import receipt 不一致',
  );
  assertNoGitOperationInProgress(destination.worktree);
  if (options.indexSnapshot) {
    assertControl(
      hashFile(options.indexSnapshot.file) === options.indexSnapshot.sha256,
      'HANDOFF_CHECKPOINT_INDEX_DRIFT',
      'checkpoint Git index 在 fence 内验证期间已变化',
    );
  }
  return indexTree;
}

function captureRecoveryCheckpointIndex(destination, snapshot, receipt) {
  const indexFile = gitIndexPath(destination.worktree);
  const lockFile = `${indexFile}.lock`;
  try {
    fs.lstatSync(lockFile);
    throw new ControlError(
      'HANDOFF_GIT_INDEX_LOCKED',
      'destination worktree Git index 已由另一 mutation 持有；保留现有 lock 并 fail-closed',
    );
  } catch (error) {
    if (error instanceof ControlError) throw error;
    assertControl(
      error && error.code === 'ENOENT',
      'HANDOFF_GIT_INDEX_LOCK_FAILED',
      '无法安全检查 destination worktree Git index lock',
    );
  }
  const before = hashFile(indexFile);
  const tree = assertRecoveryCheckpointIndex(
    destination,
    snapshot,
    receipt,
  );
  const after = hashFile(indexFile);
  assertControl(
    before === after,
    'HANDOFF_CHECKPOINT_INDEX_DRIFT',
    'checkpoint Git index 在初始验证期间已变化',
  );
  return {
    file: indexFile,
    sha256: after,
    tree,
  };
}

function assertRecoveryCheckpointCommit(
  destination,
  checkpointSha,
  expectedBody,
) {
  const body = gitBuffer(
    destination.worktree,
    ['cat-file', 'commit', checkpointSha],
    {
      code: 'HANDOFF_CHECKPOINT_COMMIT_MISMATCH',
      label: 'read deterministic recovery checkpoint commit',
    },
  );
  assertControl(
    body.equals(expectedBody),
    'HANDOFF_CHECKPOINT_COMMIT_MISMATCH',
    'checkpoint commit author/committer/date/message/tree/parent 与 sealed receipt 不一致',
  );
}

function checkpointRecoveryRequestContext(cwd, root, request) {
  const {
    goalId,
    taskId,
    successorThreadId,
    snapshotId,
    importReceiptId,
  } = request;
  const artifacts = readSnapshotArtifacts(
    root,
    goalId,
    taskId,
    snapshotId,
  );
  const snapshot = artifacts.snapshot;
  assertControl(
    snapshot.schema_version === SNAPSHOT_SCHEMA_VERSION,
    'HANDOFF_CHECKPOINT_V3_REQUIRED',
    'recovery checkpoint 只接受 sealed v3 snapshot',
  );
  const receiptRecord = readReceipt(
    root,
    goalId,
    taskId,
    importReceiptId,
  );
  const receipt = receiptRecord.receipt;
  assertControl(
    receipt.schema_version === RECEIPT_SCHEMA_VERSION,
    'HANDOFF_CHECKPOINT_V3_REQUIRED',
    'recovery checkpoint 只接受 sealed v3 import receipt',
  );
  assertReceiptSnapshotBinding(receipt, snapshot, {
    goalId,
    taskId,
    successorThreadId,
  });
  const uniqueReceipt = findSnapshotReceipt(
    root,
    goalId,
    taskId,
    snapshotId,
  );
  assertControl(
    uniqueReceipt
      && uniqueReceipt.receipt.import_receipt_id === importReceiptId
      && uniqueReceipt.receipt.import_receipt_sha256
        === receipt.import_receipt_sha256,
    'HANDOFF_CHECKPOINT_RECEIPT_MISMATCH',
    'snapshot 未精确绑定唯一指定 import receipt',
  );
  const destination = repositoryIdentity(cwd);
  assertControl(
    destination.worktree === receipt.destination_worktree,
    'HANDOFF_DESTINATION_MISMATCH',
    'checkpoint 必须在 receipt sealed destination worktree 执行',
  );
  assertReceiptDestinationIdentity(destination, snapshot, receipt);
  assertControl(
    receipt.destination_head_before === snapshot.source_observed_head,
    'HANDOFF_CHECKPOINT_RECEIPT_MISMATCH',
    'receipt destination base 不是 snapshot source_observed_head',
  );
  assertAncestor(
    destination.worktree,
    snapshot.source_launch_head,
    snapshot.source_observed_head,
  );
  const branchRef = gitText(
    destination.worktree,
    ['symbolic-ref', '--quiet', 'HEAD'],
    {
      code: 'BRANCH_MISMATCH',
      label: 'resolve recovery checkpoint branch ref',
    },
  );
  assertControl(
    branchRef === `refs/heads/${receipt.destination_branch}`,
    'BRANCH_MISMATCH',
    'checkpoint HEAD symbolic ref 与 receipt destination branch 不一致',
  );
  const spec = recoveryCheckpointCommitSpec(snapshot, receipt);
  const expectedCheckpoint = gitText(
    destination.worktree,
    ['hash-object', '-t', 'commit', '--stdin'],
    {
      input: spec.body,
      code: 'HANDOFF_CHECKPOINT_COMMIT_MISMATCH',
      label: 'hash deterministic recovery checkpoint commit',
    },
  );
  assertFullSha(expectedCheckpoint, 'deterministic recovery checkpoint');
  assertControl(
    destination.head === expectedCheckpoint
      || destination.head === snapshot.source_observed_head,
    'HANDOFF_CHECKPOINT_HEAD_MISMATCH',
    'checkpoint destination HEAD 既不是 source_observed_head，也不是确定性 checkpoint',
  );
  return {
    artifacts,
    snapshot,
    receiptRecord,
    receipt,
    destination,
    branchRef,
    spec,
    expectedCheckpoint,
    fenceRequest: {
      goal_id: goalId,
      task_id: taskId,
      successor_thread_id: successorThreadId,
      snapshot_id: snapshotId,
      import_receipt_id: importReceiptId,
      destination_worktree: destination.worktree,
      destination_branch: receipt.destination_branch,
      branch_ref: branchRef,
      source_observed_head: snapshot.source_observed_head,
      checkpoint_sha: expectedCheckpoint,
    },
  };
}

function checkpointPreparedGoalLoadOptions(root, fenceRequest) {
  const paths = checkpointGitFencePaths(root, fenceRequest);
  if (!fs.existsSync(paths.prepared)) return {};
  return {
    allowPendingGoalOperation: {
      kind: 'SOURCE_CHECKPOINT',
      operation_id: canonicalJson(fenceRequest),
      request_sha256: paths.requestSha256,
    },
  };
}

function assertCheckpointGitFenceRecoveryOwnership(marker, context) {
  const temporaryPath = assertCheckpointLockTempInventory(marker, context);
  const temporary = inspectCheckpointLockTemporary(
    marker,
    context,
    temporaryPath,
  );
  assertControl(
    context.currentMode === marker.original_git_dir_mode
      || context.currentMode === marker.fenced_git_dir_mode,
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'destination linked-worktree Git dir identity/mode 已漂移',
  );
  if (!fs.existsSync(context.lockFile)) {
    assertControl(
      context.currentMode === marker.original_git_dir_mode,
      'HANDOFF_GIT_METADATA_FENCE_INVALID',
      'checkpoint Git metadata 已 fenced 但匹配 index.lock 缺失',
    );
    return;
  }
  const owner = fs.lstatSync(context.lockFile);
  assertCheckpointGitFenceLock(marker, context, owner);
  if (temporary && temporary.complete) {
    assertControl(
      temporary.stat.dev === owner.dev
        && temporary.stat.ino === owner.ino,
      'HANDOFF_GIT_INDEX_LOCKED',
      'checkpoint canonical lock/temp lineage 分叉',
    );
  }
}

function sourceCheckpointTransactionKey(root, request, checkpoint) {
  const paths = checkpointGitFencePaths(root, checkpoint.fenceRequest);
  return canonicalTransactionKey(
    'SOURCE_CHECKPOINT',
    sourceTransactionScope(request.goalId, request.taskId),
    paths.requestSha256,
    paths.requestSha256,
  );
}

function authorizeExactCheckpointOddRecovery(
  root,
  cwd,
  request,
  recoveryCheckpoint = null,
) {
  const checkpoint = recoveryCheckpoint
    || checkpointRecoveryRequestContext(cwd, root, request);
  const paths = checkpointGitFencePaths(root, checkpoint.fenceRequest);
  if (!fs.existsSync(paths.prepared)) return false;
  const fenceContext = checkpointGitFenceContext(
    checkpoint.destination.worktree,
  );
  const marker = readCheckpointGitFenceMarker(
    checkpoint.fenceRequest,
    paths,
    fenceContext,
  );
  assertControl(
    marker,
    'HANDOFF_GIT_METADATA_FENCE_INVALID',
    'checkpoint exact recovery witness 缺 prepared marker',
  );
  readCheckpointGitFenceCompletion(paths, marker);
  assertCheckpointGitFenceRecoveryOwnership(marker, fenceContext);
  const loaded = loadGoalUnlocked(
    root,
    request.goalId,
    readOnlyGoalLoadOptions(
      checkpointPreparedGoalLoadOptions(root, checkpoint.fenceRequest),
    ),
  );
  const state = loaded.snapshot.tasks[request.taskId];
  assertControl(state, 'UNKNOWN_TASK', `未知 task ${request.taskId}`);
  authorizeSealedAuthority(
    state,
    request.actorCapabilityFile,
    checkpoint.receipt.acceptance_authority.dev,
  );
  return true;
}

function checkpointOddRecoveryLockOptions(root, cwd, request) {
  let recoveryCheckpoint = null;
  const checkpoint = () => {
    if (recoveryCheckpoint === null) {
      recoveryCheckpoint = checkpointRecoveryRequestContext(
        cwd,
        root,
        request,
      );
    }
    return recoveryCheckpoint;
  };
  return exactOddRecoveryLockOptions(
    () => authorizeExactCheckpointOddRecovery(
      root,
      cwd,
      request,
      checkpoint(),
    ),
    () => sourceCheckpointTransactionKey(root, request, checkpoint()),
  );
}

function checkpointRecoverySource(cwd, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const successorThreadId = safeId(
    options.successorThreadId,
    'successor_thread_id',
  );
  const snapshotId = safeId(options.snapshotId, 'snapshot_id');
  const importReceiptId = safeId(
    options.importReceiptId,
    'import_receipt_id',
  );
  const root = controlRoot(cwd);
  let checkpointPublished = false;
  let result;
  try {
    result = withLock(root, () => {
      const checkpointRequest = checkpointRecoveryRequestContext(
        cwd,
        root,
        {
          goalId,
          taskId,
          successorThreadId,
          snapshotId,
          importReceiptId,
        },
      );
      const loaded = loadGoalUnlocked(
        root,
        goalId,
        checkpointPreparedGoalLoadOptions(
          root,
          checkpointRequest.fenceRequest,
        ),
      );
      const state = loaded.snapshot.tasks[taskId];
      assertControl(state, 'UNKNOWN_TASK', `未知 task ${taskId}`);
      const artifacts = readSnapshotArtifacts(
        root,
        goalId,
        taskId,
        snapshotId,
      );
      const snapshot = artifacts.snapshot;
      assertControl(
        snapshot.schema_version === SNAPSHOT_SCHEMA_VERSION,
        'HANDOFF_CHECKPOINT_V3_REQUIRED',
        'recovery checkpoint 只接受 sealed v3 snapshot',
      );
      const receiptRecord = readReceipt(
        root,
        goalId,
        taskId,
        importReceiptId,
      );
      const receipt = receiptRecord.receipt;
      assertControl(
        receipt.schema_version === RECEIPT_SCHEMA_VERSION,
        'HANDOFF_CHECKPOINT_V3_REQUIRED',
        'recovery checkpoint 只接受 sealed v3 import receipt',
      );
      assertReceiptSnapshotBinding(receipt, snapshot, {
        goalId,
        taskId,
        successorThreadId,
      });
      const uniqueReceipt = findSnapshotReceipt(
        root,
        goalId,
        taskId,
        snapshotId,
      );
      assertControl(
        uniqueReceipt
          && uniqueReceipt.receipt.import_receipt_id === importReceiptId
          && uniqueReceipt.receipt.import_receipt_sha256
            === receipt.import_receipt_sha256,
        'HANDOFF_CHECKPOINT_RECEIPT_MISMATCH',
        'snapshot 未精确绑定唯一指定 import receipt',
      );
      authorizeSealedAuthority(
        state,
        options.actorCapabilityFile,
        receipt.acceptance_authority.dev,
      );

      const destination = repositoryIdentity(cwd);
      assertControl(
        destination.worktree === receipt.destination_worktree,
        'HANDOFF_DESTINATION_MISMATCH',
        'checkpoint 必须在 receipt sealed destination worktree 执行',
      );
      assertReceiptDestinationIdentity(destination, snapshot, receipt);
      assertControl(
        receipt.destination_head_before === snapshot.source_observed_head,
        'HANDOFF_CHECKPOINT_RECEIPT_MISMATCH',
        'receipt destination base 不是 snapshot source_observed_head',
      );
      assertAncestor(
        destination.worktree,
        snapshot.source_launch_head,
        snapshot.source_observed_head,
      );
      const branchRef = gitText(
        destination.worktree,
        ['symbolic-ref', '--quiet', 'HEAD'],
        {
          code: 'BRANCH_MISMATCH',
          label: 'resolve recovery checkpoint branch ref',
        },
      );
      assertControl(
        branchRef === `refs/heads/${receipt.destination_branch}`,
        'BRANCH_MISMATCH',
        'checkpoint HEAD symbolic ref 与 receipt destination branch 不一致',
      );

      const spec = recoveryCheckpointCommitSpec(snapshot, receipt);
      const expectedCheckpoint = gitText(
        destination.worktree,
        ['hash-object', '-t', 'commit', '--stdin'],
        {
          input: spec.body,
          code: 'HANDOFF_CHECKPOINT_COMMIT_MISMATCH',
          label: 'hash deterministic recovery checkpoint commit',
        },
      );
      assertFullSha(expectedCheckpoint, 'deterministic recovery checkpoint');
      assertControl(
        destination.head === expectedCheckpoint
          || destination.head === snapshot.source_observed_head,
        'HANDOFF_CHECKPOINT_HEAD_MISMATCH',
        'checkpoint destination HEAD 既不是 source_observed_head，也不是确定性 checkpoint',
      );
      const fenceRequest = {
        goal_id: goalId,
        task_id: taskId,
        successor_thread_id: successorThreadId,
        snapshot_id: snapshotId,
        import_receipt_id: importReceiptId,
        destination_worktree: destination.worktree,
        destination_branch: receipt.destination_branch,
        branch_ref: branchRef,
        source_observed_head: snapshot.source_observed_head,
        checkpoint_sha: expectedCheckpoint,
      };
      assertControl(
        hashObject(fenceRequest)
          === hashObject(checkpointRequest.fenceRequest),
        'HANDOFF_GIT_METADATA_FENCE_INVALID',
        'checkpoint request 在 lock-in preflight 后漂移',
      );
      return withGitIndexFence(
        root,
        destination.worktree,
        fenceRequest,
        () => captureRecoveryCheckpointIndex(
          destination,
          snapshot,
          receipt,
        ),
        (
          indexSnapshot,
          gitFenceMarker,
          gitFenceCompletion,
        ) => {
        const fencedDestination = repositoryIdentity(destination.worktree);
        assertReceiptDestinationIdentity(
          fencedDestination,
          snapshot,
          receipt,
        );
        const fencedBranchRef = gitText(
          fencedDestination.worktree,
          ['symbolic-ref', '--quiet', 'HEAD'],
          {
            code: 'BRANCH_MISMATCH',
            label: 'recheck recovery checkpoint branch ref under Git index fence',
          },
        );
        assertControl(
          fencedBranchRef === branchRef,
          'BRANCH_MISMATCH',
          'checkpoint Git index fence 前后 symbolic branch ref 已变化',
        );
        assertNoGitOperationInProgress(fencedDestination.worktree);
        const closeCheckpointRefTransaction = (checkpointSha) => {
          const checkpointRef = executeLooseRefTransaction({
            cwd: fencedDestination.worktree,
            commonGitDir: fencedDestination.common_git_dir,
            ref: fencedBranchRef,
            expectedOld: snapshot.source_observed_head,
            expectedNew: checkpointSha,
            fenceFile: gitFenceMarker.ref_transaction.fence_file,
            fenceInstalledAtEntry: pathEntryExists(
              gitFenceMarker.ref_transaction.fence_file,
            ),
            reflogPolicy: 'preserve',
            expectedReflog:
              gitFenceMarker.ref_transaction.expected_reflog,
            allowedReflogExtension: gitFenceCompletion
              ? {
                old: checkpointSha,
                new: snapshot.source_observed_head,
              }
              : null,
            assertRefPolicy(candidate) {
              assertControl(
                candidate === fencedBranchRef,
                'HANDOFF_CHECKPOINT_REF_LOCK_INVALID',
                'checkpoint ref transaction 尝试 mutation 非 sealed branch ref',
              );
            },
            onStage(stage) {
              const faults = {
                'fence-durable':
                  ['GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_FENCE', 112],
                'packed-lock-linked':
                  ['GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_PACKED_LOCK', 113],
                'ref-lock-linked':
                  ['GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_LOCK', 114],
                'canonical-mutated':
                  ['GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_MUTATION', 115],
                'ref-lock-released':
                  ['GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_LOCK_RELEASE', 116],
                'packed-lock-released':
                  ['GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_PACKED_LOCK_RELEASE', 117],
                'fence-cleaned':
                  ['GOAL_CONTROL_TEST_EXIT_AFTER_CHECKPOINT_REF_FENCE_CLEANUP', 118],
              };
              if (!faults[stage]) return;
              maybeExitCheckpointGitFenceForTest(
                root,
                faults[stage][0],
                faults[stage][1],
              );
            },
            codes: {
              refConflict: 'HANDOFF_CHECKPOINT_CAS_FAILED',
              lockConflict: 'HANDOFF_CHECKPOINT_REF_LOCK_INVALID',
              fenceConflict: 'HANDOFF_CHECKPOINT_REF_LOCK_INVALID',
              invalidRef: 'HANDOFF_CHECKPOINT_REF_LOCK_INVALID',
            },
            label: `recovery checkpoint ${fencedBranchRef}`,
          });
          assertControl(
            checkpointRef === checkpointSha
              && !pathEntryExists(
                gitFenceMarker.ref_transaction.fence_file,
              ),
            'HANDOFF_CHECKPOINT_CAS_FAILED',
            'checkpoint ref transaction 未收敛为 sealed checkpoint',
          );
        };
        if (fencedDestination.head === expectedCheckpoint) {
          assertRecoveryCheckpointCommit(
            fencedDestination,
            expectedCheckpoint,
            spec.body,
          );
          assertRecoveryCheckpointIndex(
            fencedDestination,
            snapshot,
            receipt,
            { indexSnapshot },
          );
          closeCheckpointRefTransaction(expectedCheckpoint);
          assertDestinationClean(
            fencedDestination.worktree,
            { gitIndexFenced: true },
          );
          return {
            schema_version: 1,
            goal_id: goalId,
            task_id: taskId,
            successor_thread_id: successorThreadId,
            snapshot_id: snapshotId,
            import_receipt_id: importReceiptId,
            checkpoint_sha: expectedCheckpoint,
            parent_sha: snapshot.source_observed_head,
            tree_sha: snapshot.expected_tree,
            idempotent: true,
          };
        }
        assertControl(
          fencedDestination.head === snapshot.source_observed_head,
          'HANDOFF_CHECKPOINT_HEAD_MISMATCH',
          'checkpoint destination HEAD 既不是 source_observed_head，也不是确定性 checkpoint',
        );

        const context = sourceSessionContext(
          loaded,
          taskId,
          successorThreadId,
        );
        assertSnapshotCurrent(loaded, state, context.successor, snapshot);
        const predecessor = canonicalLaunch(
          loaded,
          taskId,
          context.successor,
        );
        assertSnapshotPredecessorBinding(snapshot, predecessor);
        assertControl(
          predecessor.sha256 === snapshot.predecessor_launch_sha256,
          'HANDOFF_LAUNCH_TAMPERED',
          'checkpoint predecessor launch hash 已变化',
        );
        assertRecoveryCheckpointIndex(
          fencedDestination,
          snapshot,
          receipt,
          { indexSnapshot },
        );
        assertNoGitOperationInProgress(fencedDestination.worktree);
        materializeWitnessedIndexTree(
          fencedDestination.worktree,
          indexSnapshot,
          snapshot.expected_tree,
        );

        const checkpointSha = gitText(
          fencedDestination.worktree,
          [
            '-c',
            'commit.gpgSign=false',
            '-c',
            'i18n.commitEncoding=UTF-8',
            'commit-tree',
            snapshot.expected_tree,
            '-p',
            snapshot.source_observed_head,
          ],
          {
            input: spec.message,
            env: spec.env,
            code: 'HANDOFF_CHECKPOINT_COMMIT_FAILED',
            label: 'create deterministic recovery checkpoint commit',
          },
        );
        assertControl(
          checkpointSha === expectedCheckpoint,
          'HANDOFF_CHECKPOINT_COMMIT_MISMATCH',
          'commit-tree 输出不是预计算的 deterministic checkpoint',
        );
        assertRecoveryCheckpointCommit(
          fencedDestination,
          checkpointSha,
          spec.body,
        );
        assertNoGitOperationInProgress(fencedDestination.worktree);
        closeCheckpointRefTransaction(checkpointSha);
        checkpointPublished = true;
        assertNoGitOperationInProgress(fencedDestination.worktree);
        const published = repositoryIdentity(fencedDestination.worktree);
        assertControl(
          published.branch === receipt.destination_branch
            && published.head === checkpointSha,
          'HANDOFF_CHECKPOINT_CAS_FAILED',
          'checkpoint ref 发布后 branch/HEAD 不匹配',
        );
        assertDestinationClean(
          fencedDestination.worktree,
          { gitIndexFenced: true },
        );
        return {
          schema_version: 1,
          goal_id: goalId,
          task_id: taskId,
          successor_thread_id: successorThreadId,
          snapshot_id: snapshotId,
          import_receipt_id: importReceiptId,
          checkpoint_sha: checkpointSha,
          parent_sha: snapshot.source_observed_head,
          tree_sha: snapshot.expected_tree,
          idempotent: false,
        };
        },
      );
    }, checkpointOddRecoveryLockOptions(root, cwd, {
      goalId,
      taskId,
      successorThreadId,
      snapshotId,
      importReceiptId,
      actorCapabilityFile: options.actorCapabilityFile,
    }));
  } catch (error) {
    exitDeferredHandoffFault(error);
  }
  if (checkpointPublished) {
    try {
      maybeInjectHandoffFault(
        root,
        'GOAL_CONTROL_TEST_FAULT_AFTER_SOURCE_CHECKPOINT_PUBLISH',
        'TEST_FAULT_AFTER_SOURCE_CHECKPOINT_PUBLISH',
        'injected failure after deterministic source checkpoint publication',
        98,
      );
    } catch (error) {
      exitDeferredHandoffFault(error);
    }
  }
  return result;
}

function normalizedVerificationRequest(options, loaded, state) {
  const payload = options.payload || {};
  const read = (camel, snake) => options[camel] !== undefined ? options[camel] : payload[snake];
  return {
    goalId: options.goalId || (loaded && loaded.manifest && loaded.manifest.goal_id),
    taskId: options.taskId || (state && state.task_id),
    successorThreadId: read('successorThreadId', 'successor_thread_id'),
    snapshotId: read('snapshotId', 'snapshot_id'),
    snapshotSha256: read('snapshotSha256', 'snapshot_sha256'),
    importReceiptId: read('importReceiptId', 'import_receipt_id'),
    importReceiptSha256: read('importReceiptSha256', 'import_receipt_sha256'),
    predecessorLaunchId: read('predecessorLaunchId', 'predecessor_launch_id'),
    predecessorLaunchSha256: read('predecessorLaunchSha256', 'predecessor_launch_sha256'),
    sourceWorktree: read('sourceWorktree', 'source_worktree'),
    sourceBranch: read('sourceBranch', 'source_branch'),
    sourceLaunchHead: read('sourceLaunchHead', 'source_launch_head'),
    sourceObservedHead: read('sourceObservedHead', 'source_observed_head'),
    destinationWorktree: read('destinationWorktree', 'destination_worktree'),
    destinationBranch: read('destinationBranch', 'destination_branch'),
    importCommit: read('importCommit', 'import_commit'),
    eventId: options.eventId,
    eventInputSha256: options.eventInputSha256,
    eventSha256: options.eventSha256,
    eventAcceptedAt: options.eventAcceptedAt,
    eventPayloadSha256: options.eventPayloadSha256,
    legacyRecoveryHandoffBindingCollector:
      options.legacyRecoveryHandoffBindingCollector,
    legacyRecoveryHandoffRepositoryWorktree:
      options.legacyRecoveryHandoffRepositoryWorktree,
  };
}

function legacyCommitEntry(worktree, commit, relative, required = true) {
  const output = gitBuffer(
    worktree,
    ['ls-tree', '-z', commit, '--', relative],
    {
      code: 'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
      label: `inspect legacy handoff import entry ${relative}`,
    },
  );
  if (output.length === 0 && !required) return null;
  assertControl(
    output.length > 0
      && output[output.length - 1] === 0
      && output.subarray(0, -1).indexOf(0) === -1,
    'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
    `legacy handoff import entry ${relative} 不唯一或不存在`,
  );
  const record = output.subarray(0, -1);
  const tab = record.indexOf(0x09);
  assertControl(
    tab > 0 && tab < record.length - 1,
    'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
    `legacy handoff import entry ${relative} ls-tree record 非法`,
  );
  const metadata = record.subarray(0, tab).toString('ascii').split(' ');
  const rawPath = record.subarray(tab + 1);
  const decodedPath = rawPath.toString('utf8');
  assertControl(
    metadata.length === 3
      && /^[0-7]{6}$/.test(metadata[0])
      && metadata[1] === 'blob'
      && /^[0-9a-f]{40}$/.test(metadata[2])
      && Buffer.from(decodedPath, 'utf8').equals(rawPath)
      && decodedPath === relative,
    'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
    `legacy handoff import entry ${relative} identity 非法`,
  );
  return {
    mode: metadata[0],
    oid: metadata[2],
    body: gitBuffer(worktree, ['cat-file', 'blob', metadata[2]], {
      code: 'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
      label: `read legacy handoff import entry ${relative}`,
    }),
  };
}

function ensureLegacyPatchParent(root, relative) {
  let current = root;
  for (const part of relative.split('/').slice(0, -1)) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) {
      fs.mkdirSync(current, { mode: 0o700 });
      continue;
    }
    const stat = fs.lstatSync(current);
    assertControl(
      stat.isDirectory() && !stat.isSymbolicLink(),
      'LEGACY_HANDOFF_PATCH_INVALID',
      `legacy handoff patch parent ${relative} 不是普通目录`,
    );
  }
}

function writeLegacyPatchBaseEntry(root, relative, entry) {
  if (!entry) return;
  const target = path.join(root, relative);
  ensureLegacyPatchParent(root, relative);
  if (entry.mode === '120000') {
    const link = entry.body.toString('utf8');
    assertControl(
      Buffer.from(link, 'utf8').equals(entry.body),
      'LEGACY_HANDOFF_PATCH_INVALID',
      `legacy handoff base symlink ${relative} 不是 UTF-8`,
    );
    fs.symlinkSync(link, target);
    return;
  }
  assertControl(
    ['100644', '100755'].includes(entry.mode),
    'LEGACY_HANDOFF_PATCH_INVALID',
    `legacy handoff base entry ${relative} mode 不支持`,
  );
  fs.writeFileSync(target, entry.body, {
    mode: entry.mode === '100755' ? 0o755 : 0o644,
  });
  fs.chmodSync(target, entry.mode === '100755' ? 0o755 : 0o644);
}

function legacyPatchResultEntry(root, relative) {
  let parent = root;
  for (const part of relative.split('/').slice(0, -1)) {
    parent = path.join(parent, part);
    let parentStat;
    try {
      parentStat = fs.lstatSync(parent);
    } catch (error) {
      if (error && error.code === 'ENOENT') return null;
      throw error;
    }
    assertControl(
      parentStat.isDirectory() && !parentStat.isSymbolicLink(),
      'LEGACY_HANDOFF_PATCH_INVALID',
      `legacy handoff patch result ${relative} parent 非普通目录`,
    );
  }
  const target = path.join(root, relative);
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
  if (stat.isSymbolicLink()) {
    return {
      mode: '120000',
      body: Buffer.from(fs.readlinkSync(target), 'utf8'),
    };
  }
  assertControl(
    stat.isFile(),
    'LEGACY_HANDOFF_PATCH_INVALID',
    `legacy handoff patch result ${relative} 不是普通文件/symlink`,
  );
  return {
    mode: (stat.mode & 0o111) !== 0 ? '100755' : '100644',
    body: fs.readFileSync(target),
  };
}

function legacyPatchLeafPaths(root) {
  const leaves = [];
  const visit = (directory, prefix) => {
    for (const name of fs.readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const relative = prefix ? `${prefix}/${name}` : name;
      const stat = fs.lstatSync(absolute);
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        visit(absolute, relative);
      } else {
        leaves.push(safeRelativePath(relative, 'legacy patch result path'));
      }
    }
  };
  visit(root, '');
  return canonicalChangedPaths(leaves, 'legacy patch result path');
}

function verifyLegacyTrackedPatch(
  worktree,
  baseCommit,
  importCommit,
  patch,
  trackedPaths,
) {
  // Git object writes freshen matching loose/packed objects even when the
  // shared ODB is only an alternate. Replay the sealed patch in a private
  // filesystem instead; every Git command against the shared ODB stays read-only.
  const temporaryDir = fs.mkdtempSync(
    path.join(trustedTemporaryRoot(), 'goal-legacy-handoff-patch-'),
  );
  try {
    for (const relative of trackedPaths) {
      writeLegacyPatchBaseEntry(
        temporaryDir,
        relative,
        legacyCommitEntry(worktree, baseCommit, relative, false),
      );
    }
    if (patch.length > 0) {
      try {
        execFileSync(
          trustedGitExecutable(),
          ['apply', '--no-index', '--binary', '--whitespace=nowarn', '-'],
          {
            cwd: temporaryDir,
            encoding: null,
            env: {
              ...readOnlyGitEnvironment(),
              GIT_LITERAL_PATHSPECS: '1',
              GIT_NO_REPLACE_OBJECTS: '1',
            },
            input: patch,
            maxBuffer: GIT_MAX_BUFFER,
            stdio: ['pipe', 'pipe', 'pipe'],
          },
        );
      } catch (error) {
        const detail = String(error.stderr || error.message || '').trim();
        throw new ControlError(
          'LEGACY_HANDOFF_PATCH_INVALID',
          `legacy handoff tracked patch 无法在 isolated filesystem 重放${detail ? `: ${detail}` : ''}`,
        );
      }
    }
    const expectedLeaves = [];
    for (const relative of trackedPaths) {
      const imported = legacyCommitEntry(
        worktree,
        importCommit,
        relative,
        false,
      );
      const materialized = legacyPatchResultEntry(temporaryDir, relative);
      assertControl(
        (!imported && !materialized)
          || (
            imported
              && materialized
              && imported.mode === materialized.mode
              && imported.body.equals(materialized.body)
          ),
        'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
        `legacy handoff tracked path ${relative} patch result 与 import commit 不一致`,
      );
      if (materialized) expectedLeaves.push(relative);
    }
    assertSameChangedPaths(
      legacyPatchLeafPaths(temporaryDir),
      canonicalChangedPaths(expectedLeaves, 'legacy patch expected leaf'),
      'LEGACY_HANDOFF_PATCH_INVALID',
      'legacy handoff patch result inventory',
    );
  } finally {
    fs.rmSync(temporaryDir, { recursive: true, force: true });
  }
}

function deriveLegacyRecoveryHandoffBinding(
  request,
  artifacts,
  receipt,
  repositoryWorktree,
) {
  assertControl(
    typeof repositoryWorktree === 'string'
      && path.isAbsolute(repositoryWorktree),
    'LEGACY_HANDOFF_MIGRATION_WORKTREE_REQUIRED',
    'legacy handoff migration 缺 frozen repository worktree',
  );
  const worktree = canonicalDirectory(
    repositoryWorktree,
    'legacy handoff migration repository worktree',
  );
  const repositoryCommonDir = canonicalDirectory(
    gitText(
      worktree,
      ['rev-parse', '--path-format=absolute', '--git-common-dir'],
      {
        code: 'LEGACY_HANDOFF_MIGRATION_WORKTREE_INVALID',
        label: 'resolve legacy handoff migration common dir',
      },
    ),
    'legacy handoff migration common dir',
  );
  const repositoryHead = gitText(worktree, ['rev-parse', 'HEAD'], {
    code: 'LEGACY_HANDOFF_MIGRATION_WORKTREE_INVALID',
    label: 'resolve legacy handoff migration HEAD',
  });
  assertFullSha(repositoryHead, 'legacy handoff migration repository HEAD');
  const snapshot = artifacts.snapshot;
  const commitBody = gitBuffer(
    worktree,
    ['cat-file', 'commit', request.importCommit],
    {
      code: 'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
      label: 'read legacy handoff import commit object',
    },
  );
  const canonicalCommitOid = gitText(
    worktree,
    ['hash-object', '-t', 'commit', '--stdin'],
    {
      input: commitBody,
      code: 'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
      label: 'hash legacy handoff import commit object',
    },
  );
  const headerEnd = commitBody.indexOf(Buffer.from('\n\n', 'ascii'));
  assertControl(
    headerEnd > 0 && canonicalCommitOid === request.importCommit,
    'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
    'legacy handoff import commit raw object/hash 非法',
  );
  const headerLines = commitBody
    .subarray(0, headerEnd)
    .toString('utf8')
    .split('\n');
  const treeHeaders = headerLines.filter((line) => line.startsWith('tree '));
  const parentHeaders = headerLines.filter((line) => line.startsWith('parent '));
  assertControl(
    treeHeaders.length === 1
      && /^tree [0-9a-f]{40}$/.test(treeHeaders[0])
      && parentHeaders.length === 1
      && parentHeaders[0] === `parent ${snapshot.source_observed_head}`,
    'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
    'legacy handoff import commit raw object 必须且只能以 source_observed_head 为 parent',
  );
  const importTree = treeHeaders[0].slice('tree '.length);
  const trackedPaths = changedPathsInPatch(worktree, artifacts.patch);
  const untrackedPaths = artifacts.entries.map((entry) => entry.path);
  const trackedSet = new Set(trackedPaths);
  assertControl(
    untrackedPaths.every((relative) => !trackedSet.has(relative)),
    'LEGACY_HANDOFF_PATCH_INVALID',
    'legacy handoff tracked patch 与 untracked artifacts 路径重叠',
  );
  const expected = {
    tree: importTree,
    paths: canonicalChangedPaths(
      [...trackedPaths, ...untrackedPaths],
      'legacy handoff expected path',
    ),
  };
  const importPaths = changedPathsInCommit(
    worktree,
    snapshot.source_observed_head,
    request.importCommit,
  );
  assertSameChangedPaths(
    importPaths,
    expected.paths,
    'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
    'legacy handoff import commit changed paths 与 snapshot artifacts',
  );
  verifyLegacyTrackedPatch(
    worktree,
    snapshot.source_observed_head,
    request.importCommit,
    artifacts.patch,
    trackedPaths,
  );
  for (const entry of artifacts.entries) {
    const imported = legacyCommitEntry(
      worktree,
      request.importCommit,
      entry.path,
    );
    assertControl(
      imported.mode === entry.mode
        && imported.body.length === entry.size
        && `sha256:${sha256(imported.body)}` === entry.sha256
        && imported.body.equals(entry.body),
      'LEGACY_HANDOFF_IMPORT_COMMIT_MISMATCH',
      `legacy handoff import entry ${entry.path} 与 sealed artifact 不一致`,
    );
  }
  const materialized = trackedPatch(
    worktree,
    snapshot.source_observed_head,
    false,
    request.importCommit,
  );
  assertControl(
    materialized.length === receipt.materialized_patch_bytes
      && `sha256:${sha256(materialized)}`
        === receipt.materialized_patch_sha256,
    'LEGACY_HANDOFF_MATERIALIZED_DIFF_MISMATCH',
    'legacy handoff import commit diff 与 sealed receipt 不一致',
  );
  const commitObject = Buffer.concat([
    Buffer.from(`commit ${commitBody.length}\0`, 'utf8'),
    commitBody,
  ]);
  const unsigned = {
    schema_version: 1,
    goal_id: request.goalId,
    task_id: request.taskId,
    event_id: request.eventId,
    event_input_sha256: normalizeHash(
      request.eventInputSha256,
      'legacy handoff event input sha256',
    ),
    event_sha256: normalizeHash(
      request.eventSha256,
      'legacy handoff event sha256',
    ),
    event_accepted_at: request.eventAcceptedAt,
    event_payload_sha256: normalizeHash(
      request.eventPayloadSha256,
      'legacy handoff event payload sha256',
    ),
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    snapshot_schema_version: snapshot.schema_version,
    import_receipt_id: receipt.import_receipt_id,
    import_receipt_sha256: receipt.import_receipt_sha256,
    receipt_schema_version: receipt.schema_version,
    source_observed_head: snapshot.source_observed_head,
    import_commit: request.importCommit,
    import_commit_object_sha256: `sha256:${sha256(commitObject)}`,
    migration_repository_worktree: worktree,
    migration_repository_common_dir: repositoryCommonDir,
    migration_repository_head: repositoryHead,
    expected_tree: expected.tree,
    expected_paths: expected.paths,
    expected_paths_sha256: hashObject(expected.paths),
    materialized_patch_sha256: receipt.materialized_patch_sha256,
    materialized_patch_bytes: receipt.materialized_patch_bytes,
  };
  return validateLegacyRecoveryHandoffBinding({
    ...unsigned,
    binding_sha256: hashObject(unsigned),
  });
}

function resolveLegacyRecoveryHandoffBinding(
  root,
  request,
  artifacts,
  receipt,
) {
  assertControl(
    typeof request.eventId === 'string'
      && typeof request.eventInputSha256 === 'string'
      && typeof request.eventSha256 === 'string'
      && typeof request.eventAcceptedAt === 'string'
      && typeof request.eventPayloadSha256 === 'string',
    'HANDOFF_EXACT_TREE_REQUIRED',
    'legacy recovery handoff 只允许重放已接受 event 的 audited migration binding',
  );
  const key = legacyRecoveryHandoffAnchorKey(request);
  const expectedIdentity = {
    goal_id: request.goalId,
    task_id: request.taskId,
    event_id: request.eventId,
    event_input_sha256: normalizeHash(
      request.eventInputSha256,
      'legacy handoff event input sha256',
    ),
    event_sha256: normalizeHash(
      request.eventSha256,
      'legacy handoff event sha256',
    ),
    event_accepted_at: request.eventAcceptedAt,
    event_payload_sha256: normalizeHash(
      request.eventPayloadSha256,
      'legacy handoff event payload sha256',
    ),
    snapshot_id: artifacts.snapshot.snapshot_id,
    snapshot_sha256: artifacts.snapshot.snapshot_sha256,
    snapshot_schema_version: artifacts.snapshot.schema_version,
    import_receipt_id: receipt.import_receipt_id,
    import_receipt_sha256: receipt.import_receipt_sha256,
    receipt_schema_version: receipt.schema_version,
    source_observed_head: artifacts.snapshot.source_observed_head,
    import_commit: request.importCommit,
    materialized_patch_sha256: receipt.materialized_patch_sha256,
    materialized_patch_bytes: receipt.materialized_patch_bytes,
  };
  if (request.legacyRecoveryHandoffBindingCollector instanceof Map) {
    const binding = deriveLegacyRecoveryHandoffBinding(
      request,
      artifacts,
      receipt,
      request.legacyRecoveryHandoffRepositoryWorktree,
    );
    const existing = request.legacyRecoveryHandoffBindingCollector.get(key);
    assertControl(
      !existing || hashObject(existing) === hashObject(binding),
      'LEGACY_HANDOFF_ANCHOR_MISMATCH',
      `legacy recovery handoff ${key} migration collector 冲突`,
    );
    request.legacyRecoveryHandoffBindingCollector.set(key, binding);
    return binding;
  }
  let index;
  try {
    const { readLegacyEvidenceAnchorIndex } = require('./evidence');
    index = readLegacyEvidenceAnchorIndex(root);
  } catch (error) {
    if (error instanceof ControlError
      && error.code === 'LEGACY_EVIDENCE_ANCHOR_REQUIRED') {
      throw new ControlError(
        'HANDOFF_EXACT_TREE_REQUIRED',
        'legacy accepted recovery handoff 缺 protocol-sealed migration binding',
      );
    }
    throw error;
  }
  const goalWorktree = index.migration_receipt.goal_worktree_map
    .goal_worktrees
    .find((entry) => entry.goal_id === request.goalId);
  assertControl(
    goalWorktree,
    'LEGACY_HANDOFF_ANCHOR_MISMATCH',
    `legacy recovery handoff ${key} 缺 sealed Goal worktree identity`,
  );
  Object.assign(expectedIdentity, {
    migration_repository_worktree: goalWorktree.repository_worktree,
    migration_repository_common_dir: goalWorktree.repository_common_dir,
    migration_repository_head: goalWorktree.repository_head,
  });
  const binding = index.recovery_handoffs[key];
  assertControl(
    binding,
    'HANDOFF_EXACT_TREE_REQUIRED',
    `legacy accepted recovery handoff ${key} 缺 protocol-sealed exact-tree binding`,
  );
  return validateLegacyRecoveryHandoffBinding(
    binding,
    expectedIdentity,
  );
}

function readBoundRecoveryHandoffArtifacts(root, request) {
  const goalId = safeId(request.goalId, 'goal_id');
  const taskId = safeId(request.taskId, 'task_id');
  const successorThreadId = safeId(request.successorThreadId, 'successor_thread_id');
  const snapshotId = safeId(request.snapshotId, 'snapshot_id');
  const receiptId = safeId(request.importReceiptId, 'import_receipt_id');
  assertFullSha(request.importCommit, 'import_commit');
  const artifacts = readSnapshotArtifacts(
    root,
    goalId,
    taskId,
    snapshotId,
    request.snapshotSha256,
  );
  const snapshot = artifacts.snapshot;
  assertControl(
    snapshot.successor_thread_id === successorThreadId,
    'HANDOFF_SNAPSHOT_MISMATCH',
    'snapshot successor identity 与 handoff 不一致',
  );
  const receipt = readReceipt(
    root,
    goalId,
    taskId,
    receiptId,
    request.importReceiptSha256,
  ).receipt;
  assertControl(
    receipt.snapshot_id === snapshotId
      && receipt.snapshot_sha256 === snapshot.snapshot_sha256
      && receipt.successor_thread_id === successorThreadId,
    'HANDOFF_RECEIPT_MISMATCH',
    'receipt 未绑定当前 snapshot/successor',
  );
  const legacy = snapshot.schema_version === LEGACY_SNAPSHOT_SCHEMA_VERSION
    || receipt.schema_version === LEGACY_RECEIPT_SCHEMA_VERSION;
  let exactTree;
  if (legacy) {
    assertControl(
      snapshot.schema_version === LEGACY_SNAPSHOT_SCHEMA_VERSION
        && receipt.schema_version === LEGACY_RECEIPT_SCHEMA_VERSION,
      'HANDOFF_EXACT_TREE_REQUIRED',
      'legacy recovery handoff snapshot/receipt schema 必须成对出现',
    );
    exactTree = resolveLegacyRecoveryHandoffBinding(
      root,
      request,
      artifacts,
      receipt,
    );
  } else {
    assertExactTreeSnapshot(snapshot);
    assertExactTreeReceipt(receipt);
    exactTree = {
      expected_tree: snapshot.expected_tree,
      expected_paths: snapshot.expected_paths,
    };
  }
  const expectedPayload = {
    predecessorLaunchId: snapshot.predecessor_launch_id,
    predecessorLaunchSha256: snapshot.predecessor_launch_sha256,
    sourceWorktree: snapshot.source_worktree,
    sourceBranch: snapshot.source_branch,
    sourceLaunchHead: snapshot.source_launch_head,
    sourceObservedHead: snapshot.source_observed_head,
    destinationWorktree: receipt.destination_worktree,
    destinationBranch: receipt.destination_branch,
  };
  for (const [key, value] of Object.entries(expectedPayload)) {
    assertControl(
      request[key] === value,
      'RECOVERY_HANDOFF_MISMATCH',
      `handoff payload ${key} 不匹配`,
    );
  }
  assertControl(
    receipt.predecessor_launch_id === snapshot.predecessor_launch_id
      && receipt.predecessor_launch_sha256 === snapshot.predecessor_launch_sha256
      && receipt.source_worktree === snapshot.source_worktree
      && receipt.source_branch === snapshot.source_branch
      && receipt.source_launch_head === snapshot.source_launch_head
      && receipt.source_observed_head === snapshot.source_observed_head
      && (
        legacy
          || (
            receipt.expected_tree === snapshot.expected_tree
              && receipt.materialized_tree === snapshot.expected_tree
          )
      ),
    'HANDOFF_RECEIPT_MISMATCH',
    'receipt source identity/exact tree 与 snapshot 不一致',
  );
  return {
    request,
    goalId,
    taskId,
    successorThreadId,
    snapshotId,
    receiptId,
    artifacts,
    snapshot,
    receipt,
    expectedTree: exactTree.expected_tree,
    expectedPaths: exactTree.expected_paths,
  };
}

function verifyAcceptedRecoveryHandoffArtifacts(root, options) {
  const request = normalizedVerificationRequest(options, null, null);
  const verified = readBoundRecoveryHandoffArtifacts(root, request);
  return {
    verified: true,
    goal_id: verified.goalId,
    task_id: verified.taskId,
    successor_thread_id: verified.successorThreadId,
    snapshot_id: verified.snapshotId,
    snapshot_sha256: verified.snapshot.snapshot_sha256,
    import_receipt_id: verified.receiptId,
    import_receipt_sha256: verified.receipt.import_receipt_sha256,
    import_commit: verified.request.importCommit,
    materialized_tree: verified.expectedTree,
    materialized_patch_sha256: verified.receipt.materialized_patch_sha256,
  };
}

function verifyRecoveryHandoffUnlocked(cwd, options, loaded) {
  const state = options.state || loaded.snapshot.tasks[options.taskId];
  const request = normalizedVerificationRequest(options, loaded, state);
  const root = controlRoot(cwd);
  const bound = readBoundRecoveryHandoffArtifacts(root, request);
  const {
    goalId,
    taskId,
    successorThreadId,
    snapshotId,
    receiptId,
    snapshot,
    receipt,
  } = bound;
  const context = sourceSessionContext(loaded, taskId, successorThreadId);
  assertControl(context.state === state || context.state.task_id === state.task_id, 'RECOVERY_HANDOFF_MISMATCH', 'verify state 与 loaded task 不一致');
  assertSnapshotCurrent(loaded, state, context.successor, snapshot);
  const predecessor = canonicalLaunch(loaded, taskId, context.successor);
  assertSnapshotPredecessorBinding(snapshot, predecessor);
  assertControl(predecessor.sha256 === snapshot.predecessor_launch_sha256, 'HANDOFF_LAUNCH_TAMPERED', 'predecessor launch hash 已变化');
  assertControl(
    predecessor.launch.repository.full_head === snapshot.source_launch_head,
    'RECOVERY_HANDOFF_MISMATCH',
    'snapshot source launch HEAD 与 canonical launch 不一致',
  );
  assertControl(request.predecessorLaunchId === predecessor.launch.launch_id, 'RECOVERY_HANDOFF_MISMATCH', 'payload predecessor launch identity 不匹配');

  const destination = repositoryIdentity(receipt.destination_worktree);
  assertNoGitOperationInProgress(destination.worktree);
  assertControl(destination.worktree === receipt.destination_worktree, 'HANDOFF_DESTINATION_MISMATCH', 'destination worktree canonical identity 不匹配');
  assertControl(destination.common_git_dir === snapshot.common_git_dir, 'REPOSITORY_ROOT_MISMATCH', 'destination 已不属于 source Git common dir');
  assertControl(destination.worktree !== snapshot.source_worktree, 'HANDOFF_SAME_WORKTREE', 'source 与 destination 必须不同');
  assertControl(destination.branch === receipt.destination_branch && destination.branch === request.destinationBranch, 'BRANCH_MISMATCH', 'destination branch 不匹配');
  assertControl(destination.head === request.importCommit, 'HANDOFF_IMPORT_COMMIT_MISMATCH', 'destination HEAD 不是声明的 import commit');
  assertAncestor(destination.worktree, snapshot.source_launch_head, snapshot.source_observed_head);
  assertDestinationClean(destination.worktree);

  const parents = gitText(destination.worktree, ['rev-list', '--parents', '-n', '1', request.importCommit]).split(/\s+/);
  assertControl(
    parents.length === 2 && parents[0] === request.importCommit && parents[1] === snapshot.source_observed_head,
    'HANDOFF_IMPORT_PARENT_MISMATCH',
    'import commit 必须且只能以 source_observed_head 为 parent',
  );
  const materialized = trackedPatch(destination.worktree, snapshot.source_observed_head, false, request.importCommit);
  assertControl(materialized.length === receipt.materialized_patch_bytes, 'HANDOFF_MATERIALIZED_DIFF_MISMATCH', 'import commit diff size 与 receipt 不一致');
  assertControl(
    `sha256:${sha256(materialized)}` === receipt.materialized_patch_sha256,
    'HANDOFF_MATERIALIZED_DIFF_MISMATCH',
    'import commit diff hash 与 receipt 不一致',
  );
  const importTree = gitText(destination.worktree, ['rev-parse', `${request.importCommit}^{tree}`], {
    code: 'HANDOFF_MATERIALIZED_TREE_MISMATCH',
    label: 'resolve import commit tree',
  });
  assertFullSha(importTree, 'import commit tree');
  assertControl(
    importTree === snapshot.expected_tree
      && importTree === receipt.expected_tree
      && importTree === receipt.materialized_tree,
    'HANDOFF_MATERIALIZED_TREE_MISMATCH',
    'import commit tree 与 snapshot/receipt expected tree 不一致',
  );
  const importPaths = changedPathsInCommit(
    destination.worktree,
    snapshot.source_observed_head,
    request.importCommit,
  );
  assertSameChangedPaths(
    importPaths,
    snapshot.expected_paths,
    'HANDOFF_CHANGED_PATHS_MISMATCH',
    'import commit changed paths 与 snapshot expected_paths',
  );
  assertControl(
    snapshot.schema_version === SNAPSHOT_SCHEMA_VERSION
      && receipt.schema_version === RECEIPT_SCHEMA_VERSION,
    'HANDOFF_CHECKPOINT_V3_REQUIRED',
    'recovery bind 只接受 fixed checkpoint adapter 生成的 sealed v3 handoff',
  );
  const checkpointSpec = recoveryCheckpointCommitSpec(snapshot, receipt);
  const expectedCheckpoint = gitText(
    destination.worktree,
    ['hash-object', '-t', 'commit', '--stdin'],
    {
      input: checkpointSpec.body,
      code: 'HANDOFF_CHECKPOINT_COMMIT_MISMATCH',
      label: 'hash expected recovery checkpoint commit',
    },
  );
  assertControl(
    request.importCommit === expectedCheckpoint,
    'HANDOFF_CHECKPOINT_COMMIT_MISMATCH',
    'import commit 不是 sealed snapshot/receipt 唯一确定的 checkpoint',
  );
  assertRecoveryCheckpointCommit(
    destination,
    expectedCheckpoint,
    checkpointSpec.body,
  );
  assertNoGitOperationInProgress(destination.worktree);
  return {
    verified: true,
    goal_id: goalId,
    task_id: taskId,
    successor_thread_id: successorThreadId,
    snapshot_id: snapshotId,
    snapshot_sha256: snapshot.snapshot_sha256,
    import_receipt_id: receiptId,
    import_receipt_sha256: receipt.import_receipt_sha256,
    import_commit: request.importCommit,
    materialized_tree: receipt.materialized_tree,
    materialized_patch_sha256: receipt.materialized_patch_sha256,
  };
}

function verifyRecoveryHandoff(cwd, options) {
  if (options.loaded) {
    const state = options.state || options.loaded.snapshot.tasks[options.taskId];
    const normalized = normalizedVerificationRequest(options, options.loaded, state);
    return verifyRecoveryHandoffUnlocked(cwd, { ...options, ...normalized, state }, options.loaded);
  }
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const root = controlRoot(cwd);
  return withStableRead(root, () => {
    const loaded = loadGoalUnlocked(
      root,
      goalId,
      readOnlyGoalLoadOptions(),
    );
    const state = loaded.snapshot.tasks[taskId];
    const normalized = normalizedVerificationRequest({ ...options, goalId, taskId }, loaded, state);
    return verifyRecoveryHandoffUnlocked(cwd, { ...options, ...normalized, state }, loaded);
  });
}

function buildRecoveryHandoffPayload(cwd, options) {
  const goalId = safeId(options.goalId, 'goal_id');
  const taskId = safeId(options.taskId, 'task_id');
  const successorThreadId = safeId(options.successorThreadId, 'successor_thread_id');
  const snapshotId = safeId(options.snapshotId, 'snapshot_id');
  const importReceiptId = safeId(options.importReceiptId, 'import_receipt_id');
  assertFullSha(options.importCommit, 'import_commit');
  const root = controlRoot(cwd);
  return withStableRead(root, () => {
    const loaded = loadGoalUnlocked(
      root,
      goalId,
      readOnlyGoalLoadOptions(),
    );
    const { state } = sourceSessionContext(loaded, taskId, successorThreadId);
    authorizeSession(state, options.captainCapabilityFile, {
      role: 'CAPTAIN',
      threadId: options.captainThreadId || null,
    });
    const snapshot = readSnapshotArtifacts(root, goalId, taskId, snapshotId).snapshot;
    const receipt = readReceipt(root, goalId, taskId, importReceiptId).receipt;
    const payload = {
      successor_thread_id: successorThreadId,
      snapshot_id: snapshot.snapshot_id,
      snapshot_sha256: snapshot.snapshot_sha256,
      import_receipt_id: receipt.import_receipt_id,
      import_receipt_sha256: receipt.import_receipt_sha256,
      predecessor_launch_id: snapshot.predecessor_launch_id,
      predecessor_launch_sha256: snapshot.predecessor_launch_sha256,
      source_worktree: snapshot.source_worktree,
      source_branch: snapshot.source_branch,
      source_launch_head: snapshot.source_launch_head,
      source_observed_head: snapshot.source_observed_head,
      destination_worktree: receipt.destination_worktree,
      destination_branch: receipt.destination_branch,
      import_commit: options.importCommit,
    };
    verifyRecoveryHandoffUnlocked(cwd, {
      loaded,
      state,
      payload,
    }, loaded);
    return payload;
  });
}

module.exports = {
  MAX_SNAPSHOT_BYTES,
  buildCodexShellAudit,
  buildRecoveryHandoffPayload,
  checkpointRecoverySource,
  exportRecoverySnapshot,
  exportRecoverySnapshotFromCodexRollout,
  importRecoverySnapshot,
  inspectCodexRolloutPatchEvents,
  inspectPendingSourceSnapshotStaging,
  prepareLegacyRecoveryHandoffBindings,
  publicRecoveryHandoffResult,
  verifyAcceptedRecoveryHandoffArtifacts,
  verifyRecoveryHandoff,
  writeCodexShellAuditOutput,
};
