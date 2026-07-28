'use strict';

const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ControlError, assertControl } = require('./errors');
const { ensurePrivateDirectory } = require('./init-receipt');
const {
  atomicCreate,
  canonicalTransactionKey,
  ensureDir,
  readPrivateAtomicArtifact,
  withLock,
} = require('./store');
const {
  assertIsolatedTestMode,
  controlRoot,
  git,
  hashFile,
  hashObject,
  readOnlyGitEnvironment,
  readJson,
  repoRoot,
  safeId,
} = require('./util');
const { validateManifest } = require('./validation');
const { trustedExecutableCandidates } = require('./gate-adapters');

const POLICY = 'supervisor-exact-whitelist-v1';
const INTENT_KIND = 'PRECLAIM_ISSUES_INTENT';
const OBSERVATION_KIND = 'PRECLAIM_ISSUE_OBSERVATION';
const RECEIPT_KIND = 'PRECLAIM_ISSUES_RECEIPT';
const TEST_DEPENDENCY_KEYS = new Set([
  'afterAssigneeMutation',
  'afterGenerationBeforeCallback',
  'afterIntent',
  'afterIssueMutation',
  'afterIssueReadback',
  'afterReceipt',
  'beforeIssueMutation',
  'resolveExecutable',
  'runGh',
]);
const NO_TEST_DEPENDENCIES = Object.freeze(Object.create(null));

function resolveTestDependencies(cwd, dependencies) {
  assertControl(
    dependencies
      && typeof dependencies === 'object'
      && !Array.isArray(dependencies)
      && [Object.prototype, null].includes(
        Object.getPrototypeOf(dependencies),
      ),
    'INVALID_TEST_DEPENDENCY',
    'preclaim test dependencies 必须是 plain object',
  );
  const keys = Reflect.ownKeys(dependencies);
  if (keys.length === 0) return NO_TEST_DEPENDENCIES;
  assertIsolatedTestMode(cwd);
  const resolved = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(dependencies, key);
    assertControl(
      typeof key === 'string'
        && TEST_DEPENDENCY_KEYS.has(key)
        && descriptor
        && Object.hasOwn(descriptor, 'value')
        && typeof descriptor.value === 'function',
      'INVALID_TEST_DEPENDENCY',
      `preclaim test dependency 非法: ${String(key)}`,
    );
    resolved[key] = descriptor.value;
  }
  return Object.freeze(resolved);
}

function canonicalRepository(value) {
  const normalized = String(value || '')
    .trim()
    .replace(/^git@github\.com:/i, 'https://github.com/')
    .replace(/^ssh:\/\/git@github\.com\//i, 'https://github.com/')
    .replace(/\.git$/i, '')
    .replace(/\/$/, '');
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new ControlError(
      'PRECLAIM_REPOSITORY_MISMATCH',
      'origin 不是 canonical GitHub repository',
    );
  }
  const match = parsed.pathname.match(
    /^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/,
  );
  assertControl(
    parsed.protocol === 'https:'
      && parsed.hostname.toLowerCase() === 'github.com'
      && !parsed.username
      && !parsed.password
      && !parsed.search
      && !parsed.hash
      && match,
    'PRECLAIM_REPOSITORY_MISMATCH',
    'origin 必须是无凭证 GitHub repository',
  );
  return `${match[1]}/${match[2]}`;
}

function assertCommittedFile(repositoryRoot, file, label) {
  const root = fs.realpathSync(repositoryRoot);
  const stat = fs.lstatSync(file);
  assertControl(
    stat.isFile() && !stat.isSymbolicLink(),
    'PRECLAIM_INPUT_SYMLINK',
    `${label} 必须是普通文件`,
  );
  const canonical = fs.realpathSync(file);
  const relative = path.relative(root, canonical).split(path.sep).join('/');
  assertControl(
    relative
      && !relative.startsWith('../')
      && !path.isAbsolute(relative),
    'PRECLAIM_INPUT_OUTSIDE_REPO',
    `${label} 必须位于 repository 内`,
  );
  let committed;
  try {
    const treeEntry = execFileSync(
      'git',
      ['ls-tree', '-z', 'HEAD', '--', relative],
      {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: readOnlyGitEnvironment(),
      },
    );
    assertControl(
      /^(100644|100755) blob [0-9a-f]{40}\t[^\0]+\0$/.test(treeEntry),
      'PRECLAIM_INPUT_SYMLINK',
      `${label} 在 HEAD 中必须是 ordinary blob`,
    );
    committed = execFileSync('git', ['show', `HEAD:${relative}`], {
      cwd: root,
      encoding: null,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: readOnlyGitEnvironment(),
    });
  } catch {
    throw new ControlError(
      'PRECLAIM_INPUT_NOT_COMMITTED',
      `${label} 尚未进入当前 HEAD: ${relative}`,
    );
  }
  assertControl(
    Buffer.compare(committed, fs.readFileSync(file)) === 0,
    'PRECLAIM_INPUT_DIRTY',
    `${label} 与当前 HEAD bytes 不一致: ${relative}`,
  );
  return relative;
}

function preclaimPaths(root, goalId, operationId) {
  safeId(goalId, 'preclaim goal_id');
  safeId(operationId, 'preclaim operation_id');
  const directory = path.join(root, 'preclaim-issues', goalId, operationId);
  return {
    directory,
    intent: path.join(directory, 'intent.json'),
    receipt: path.join(directory, 'receipt.json'),
  };
}

function readPrivateJson(root, file, label) {
  let body;
  try {
    body = readPrivateAtomicArtifact(root, file, {
      operation: 'CREATE',
      maxBytes: 1024 * 1024,
    }).bytes;
  } catch (error) {
    throw new ControlError(
      'PRECLAIM_ARTIFACT_INVALID',
      `${label} ownership/identity 非法: ${
        error && error.message ? error.message : String(error)
      }`,
      {
        store_error_code: error && error.code ? error.code : null,
      },
    );
  }
  try {
    return JSON.parse(body.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'PRECLAIM_ARTIFACT_INVALID',
      `${label} JSON 非法: ${error.message}`,
    );
  }
}

function ensurePrivateDir(directory) {
  const existed = fs.existsSync(directory);
  if (!existed) ensureDir(directory);
  ensurePrivateDirectory(directory, { repair: !existed });
}

function assertArtifactInventory(paths, issues, create = false) {
  if (create) {
    ensurePrivateDir(paths.directory);
  } else {
    ensurePrivateDirectory(paths.directory);
  }
  const top = fs.readdirSync(paths.directory).sort();
  const allowed = new Set([
    'intent.json',
    'receipt.json',
    ...issues.map((issue) => `observation-${issue}.json`),
    ...issues.map((issue) => `final-${issue}.json`),
  ]);
  assertControl(
    top.every((name) => allowed.has(name)),
    'PRECLAIM_ARTIFACT_FOREIGN',
    'preclaim artifact directory 含 foreign entry',
  );
}

function seal(value, hashKey) {
  const sealed = { ...value };
  sealed[hashKey] = hashObject(sealed);
  return sealed;
}

function verifySeal(value, hashKey, label) {
  assertControl(
    value && typeof value === 'object' && !Array.isArray(value),
    'PRECLAIM_ARTIFACT_INVALID',
    `${label} 不是 object`,
  );
  const unsigned = { ...value };
  const actual = unsigned[hashKey];
  delete unsigned[hashKey];
  assertControl(
    typeof actual === 'string' && actual === hashObject(unsigned),
    'PRECLAIM_ARTIFACT_INVALID',
    `${label} hash 漂移`,
  );
  return value;
}

function resolveGh(dependencies) {
  if (typeof dependencies.resolveExecutable === 'function') {
    const resolved = dependencies.resolveExecutable('gh');
    assertControl(
      resolved && path.isAbsolute(resolved.executable),
      'PRECLAIM_GH_UNTRUSTED',
      'test gh resolver 必须返回绝对路径',
    );
    return fs.realpathSync(resolved.executable);
  }
  for (const candidate of trustedExecutableCandidates('gh', os.userInfo().homedir)) {
    try {
      const stat = fs.statSync(candidate);
      if (
        stat.isFile()
          && (stat.mode & 0o111) !== 0
      ) return fs.realpathSync(candidate);
    } catch {
      // Try the next fixed absolute candidate. PATH is intentionally ignored.
    }
  }
  throw new ControlError(
    'PRECLAIM_GH_UNTRUSTED',
    '固定可信绝对路径中找不到 gh',
  );
}

function githubCanary(repositoryRoot, manifest, executable, dependencies) {
  const actor = runGhJson(
    executable,
    ['api', 'user'],
    repositoryRoot,
    dependencies,
  );
  const repository = runGhJson(
    executable,
    [
      'repo',
      'view',
      manifest.repository.name_with_owner,
      '--json',
      'nameWithOwner,url,viewerPermission',
    ],
    repositoryRoot,
    dependencies,
  );
  assertControl(
    actor.login === manifest.preclaim.expected_actor,
    'PRECLAIM_ACTOR_MISMATCH',
    'gh authenticated login 与 manifest expected_actor 不一致',
  );
  assertControl(
    typeof repository.nameWithOwner === 'string'
      && repository.nameWithOwner.toLowerCase()
        === manifest.repository.name_with_owner.toLowerCase()
      && repository.url
        === `https://github.com/${manifest.repository.name_with_owner}`
      && ['WRITE', 'MAINTAIN', 'ADMIN'].includes(repository.viewerPermission),
    'PRECLAIM_REPOSITORY_PERMISSION',
    'GitHub repo identity 或 viewerPermission 不满足 claim',
  );
  return {
    gh_executable: executable,
    gh_executable_sha256: hashFile(executable),
    actor: actor.login,
    repository: repository.nameWithOwner,
    repository_url: repository.url,
    viewer_permission: repository.viewerPermission,
    observed_at: manifest.preclaim.requested_at,
  };
}

function requestFor(
  repositoryRoot,
  manifestFile,
  manifest,
  operationId,
  dependencies = NO_TEST_DEPENDENCIES,
  sealedGithubCanary = null,
) {
  assertControl(
    manifest.preclaim,
    'PRECLAIM_NOT_CONFIGURED',
    'manifest 未配置 preclaim',
  );
  assertControl(
    manifest.preclaim.policy === POLICY,
    'PRECLAIM_POLICY_MISMATCH',
    `preclaim policy 必须是 ${POLICY}`,
  );
  assertControl(
    operationId === manifest.preclaim.operation_id,
    'PRECLAIM_OPERATION_MISMATCH',
    'operation id 与 manifest.preclaim.operation_id 不一致',
  );
  const authorizationFile = path.join(
    repositoryRoot,
    manifest.preclaim.authorization.path,
  );
  const sourceManifest = assertCommittedFile(
    repositoryRoot,
    manifestFile,
    'preclaim manifest',
  );
  const sourceAuthorization = assertCommittedFile(
    repositoryRoot,
    authorizationFile,
    'preclaim authorization',
  );
  assertControl(
    hashFile(authorizationFile)
      === manifest.preclaim.authorization.sha256,
    'PRECLAIM_AUTHORITY_HASH_MISMATCH',
    'preclaim authorization hash 漂移',
  );
  const origin = canonicalRepository(
    git(repositoryRoot, ['remote', 'get-url', 'origin']),
  );
  assertControl(
    origin.toLowerCase()
      === manifest.repository.name_with_owner.toLowerCase(),
    'PRECLAIM_REPOSITORY_MISMATCH',
    'origin 与 manifest repository 不一致',
  );
  const ghExecutable = resolveGh(dependencies);
  const canary = sealedGithubCanary || githubCanary(
    repositoryRoot,
    manifest,
    ghExecutable,
    dependencies,
  );
  assertControl(
    canary
      && canary.gh_executable === ghExecutable
      && canary.gh_executable_sha256 === hashFile(ghExecutable)
      && canary.actor === manifest.preclaim.expected_actor
      && typeof canary.repository === 'string'
      && canary.repository.toLowerCase()
        === manifest.repository.name_with_owner.toLowerCase()
      && canary.repository_url
        === `https://github.com/${manifest.repository.name_with_owner}`
      && ['WRITE', 'MAINTAIN', 'ADMIN'].includes(canary.viewer_permission)
      && canary.observed_at === manifest.preclaim.requested_at,
    'PRECLAIM_CANARY_INVALID',
    'sealed GitHub canary 与 manifest/executable 不一致',
  );
  return {
    schema_version: 1,
    kind: 'PRECLAIM_ISSUES_REQUEST',
    operation_id: operationId,
    requested_at: manifest.preclaim.requested_at,
    goal_id: manifest.goal_id,
    repository: manifest.repository.name_with_owner,
    canonical_remote: `https://github.com/${origin}`,
    manifest: {
      path: sourceManifest,
      source_sha256: hashFile(manifestFile),
      normalized_sha256: manifest.manifest_sha256,
    },
    authorization: {
      path: sourceAuthorization,
      sha256: manifest.preclaim.authorization.sha256,
    },
    issues: [...manifest.preclaim.issues],
    expected_actor: manifest.preclaim.expected_actor,
    expected_status: manifest.preclaim.expected_status,
    github_canary: canary,
  };
}

function runGh(executable, args, cwd, dependencies) {
  if (typeof dependencies.runGh === 'function') {
    return dependencies.runGh([...args], executable);
  }
  const result = spawnSync(executable, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      GH_PROMPT_DISABLED: '1',
      GIT_TERMINAL_PROMPT: '0',
    },
    timeout: 30_000,
  });
  assertControl(
    result.status === 0,
    'PRECLAIM_GH_FAILED',
    `gh ${args.slice(0, 3).join(' ')} 失败 (exit=${result.status})`,
  );
  return String(result.stdout || '');
}

function runGhJson(executable, args, cwd, dependencies) {
  try {
    return JSON.parse(runGh(executable, args, cwd, dependencies));
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'PRECLAIM_GH_INVALID_JSON',
      `gh JSON 非法: ${error.message}`,
    );
  }
}

function observeIssue(cwd, request, issue, dependencies) {
  const raw = runGhJson(request.github_canary.gh_executable, [
    'issue',
    'view',
    String(issue),
    '--repo',
    request.repository,
    '--json',
    'number,url,state,assignees,labels',
  ], cwd, dependencies);
  assertControl(
    raw.number === issue
      && typeof raw.url === 'string'
      && ['OPEN', 'CLOSED'].includes(raw.state)
      && Array.isArray(raw.assignees)
      && Array.isArray(raw.labels),
    'PRECLAIM_ISSUE_INVALID',
    `issue #${issue} readback 非法`,
  );
  assertControl(
    raw.url === `https://github.com/${request.repository}/issues/${issue}`,
    'PRECLAIM_ISSUE_INVALID',
    `issue #${issue} URL 未绑定 exact repository`,
  );
  return {
    issue,
    url: raw.url,
    state: raw.state,
    assignees: raw.assignees
      .map((item) => item && item.login)
      .filter((item) => typeof item === 'string')
      .sort(),
    labels: raw.labels
      .map((item) => item && item.name)
      .filter((item) => typeof item === 'string')
      .sort(),
  };
}

function invokeFault(dependencies, name, detail = null) {
  if (typeof dependencies[name] === 'function') dependencies[name](detail);
}

function readExactArtifact(
  root,
  file,
  hashKey,
  label,
  expectedRequestSha256,
) {
  if (!fs.existsSync(file)) return null;
  const value = verifySeal(
    readPrivateJson(root, file, label),
    hashKey,
    label,
  );
  assertControl(
    value.request_sha256 === expectedRequestSha256,
    'PRECLAIM_REQUEST_CONFLICT',
    `${label} 已绑定不同 request`,
  );
  return value;
}

function ensureIntent(root, paths, request) {
  assertArtifactInventory(paths, request.issues, true);
  const requestSha256 = hashObject(request);
  const existing = readExactArtifact(
    root,
    paths.intent,
    'intent_sha256',
    'preclaim intent',
    requestSha256,
  );
  if (existing) {
    assertControl(
      hashObject(existing.request) === requestSha256,
      'PRECLAIM_REQUEST_CONFLICT',
      'preclaim intent request 漂移',
    );
    return existing;
  }
  const intent = seal({
    schema_version: 1,
    kind: INTENT_KIND,
    operation_id: request.operation_id,
    goal_id: request.goal_id,
    request,
    request_sha256: requestSha256,
    prepared_at: request.requested_at,
  }, 'intent_sha256');
  atomicCreate(paths.intent, `${JSON.stringify(intent, null, 2)}\n`);
  return readExactArtifact(
    root,
    paths.intent,
    'intent_sha256',
    'preclaim intent',
    requestSha256,
  );
}

function issueObservation(
  root,
  paths,
  request,
  issue,
  cwd,
  dependencies,
) {
  const requestSha256 = hashObject(request);
  const file = path.join(paths.directory, `observation-${issue}.json`);
  const existing = readExactArtifact(
    root,
    file,
    'observation_sha256',
    `preclaim issue #${issue} observation`,
    requestSha256,
  );
  if (existing) return existing;
  const before = observeIssue(cwd, request, issue, dependencies);
  assertControl(
    before.state === 'OPEN',
    'PRECLAIM_ISSUE_NOT_OPEN',
    `issue #${issue} 不是 OPEN`,
  );
  const actorPresent = before.assignees.includes(request.expected_actor);
  const foreignOnly = before.assignees.length > 0 && !actorPresent;
  const observation = seal({
    schema_version: 1,
    kind: OBSERVATION_KIND,
    operation_id: request.operation_id,
    request_sha256: requestSha256,
    issue,
    observed_before: before,
    result: foreignOnly
      ? 'OTHERS_REJECT'
      : actorPresent
        ? 'MINE_NEED_CONFIRM'
        : 'CLAIMED',
    observed_at: request.requested_at,
  }, 'observation_sha256');
  atomicCreate(file, `${JSON.stringify(observation, null, 2)}\n`);
  return readExactArtifact(
    root,
    file,
    'observation_sha256',
    `preclaim issue #${issue} observation`,
    requestSha256,
  );
}

function mutateIssue(cwd, request, observation, dependencies) {
  if (observation.result === 'OTHERS_REJECT') return;
  const issue = observation.issue;
  let current = observeIssue(cwd, request, issue, dependencies);
  invokeFault(dependencies, 'beforeIssueMutation', { issue, current });
  if (!current.assignees.includes(request.expected_actor)) {
    assertControl(
      current.assignees.length === 0,
      'PRECLAIM_OTHERS_REJECT',
      `issue #${issue} 已由其它 actor 认领`,
    );
    runGh(request.github_canary.gh_executable, [
      'issue',
      'edit',
      String(issue),
      '--repo',
      request.repository,
      '--add-assignee',
      request.expected_actor,
    ], cwd, dependencies);
    invokeFault(dependencies, 'afterAssigneeMutation', { issue });
    current = observeIssue(cwd, request, issue, dependencies);
  }
  const statusLabels = current.labels.filter((label) => label.startsWith('status:'));
  if (
    statusLabels.length !== 1
      || statusLabels[0] !== request.expected_status
  ) {
    const args = [
      'issue',
      'edit',
      String(issue),
      '--repo',
      request.repository,
    ];
    for (const label of statusLabels) args.push('--remove-label', label);
    args.push('--add-label', request.expected_status);
    runGh(request.github_canary.gh_executable, args, cwd, dependencies);
  }
  invokeFault(dependencies, 'afterIssueMutation', { issue });
}

function issueReceipt(request, observation, final) {
  const readback = final.readback;
  const valid = readback.state === 'OPEN'
    && readback.assignees.includes(request.expected_actor)
    && readback.labels.filter((label) => label.startsWith('status:')).length === 1
    && readback.labels.includes(request.expected_status);
  return {
    issue: observation.issue,
    url: readback.url,
    state: readback.state,
    assignees: readback.assignees,
    status: readback.labels.find((label) => label.startsWith('status:')) || null,
    result: observation.result,
    observed_at: final.observed_at,
    observation_sha256: observation.observation_sha256,
    final_readback_sha256: final.final_readback_sha256,
    valid,
  };
}

function sealFinalReadback(
  root,
  paths,
  request,
  observation,
  readback,
) {
  const requestSha256 = hashObject(request);
  const file = path.join(
    paths.directory,
    `final-${observation.issue}.json`,
  );
  const existing = readExactArtifact(
    root,
    file,
    'final_readback_sha256',
    `preclaim issue #${observation.issue} final readback`,
    requestSha256,
  );
  if (existing) {
    assertControl(
      existing.observation_sha256 === observation.observation_sha256,
      'PRECLAIM_ARTIFACT_INVALID',
      `issue #${observation.issue} final readback observation 漂移`,
    );
    return existing;
  }
  const final = seal({
    schema_version: 1,
    kind: 'PRECLAIM_ISSUE_FINAL_READBACK',
    operation_id: request.operation_id,
    request_sha256: requestSha256,
    issue: observation.issue,
    observation_sha256: observation.observation_sha256,
    readback,
    observed_at: request.requested_at,
  }, 'final_readback_sha256');
  atomicCreate(file, `${JSON.stringify(final, null, 2)}\n`);
  return readExactArtifact(
    root,
    file,
    'final_readback_sha256',
    `preclaim issue #${observation.issue} final readback`,
    requestSha256,
  );
}

function authorizeOddRetry(root, paths, request) {
  try {
    const intent = readExactArtifact(
      root,
      paths.intent,
      'intent_sha256',
      'preclaim intent',
      hashObject(request),
    );
    return Boolean(intent && hashObject(intent.request) === hashObject(request));
  } catch {
    return false;
  }
}

function preclaimGenerationBoundaryFaultHook(cwd, dependencies) {
  const hook = dependencies.afterGenerationBeforeCallback;
  if (hook === undefined) return undefined;
  assertControl(
    typeof hook === 'function',
    'INVALID_TEST_DEPENDENCY',
    'preclaim generation boundary hook 必须是 function',
  );
  assertIsolatedTestMode(cwd);
  return hook;
}

function preclaimIssues(cwd, options, dependencies = {}) {
  const testDependencies = resolveTestDependencies(cwd, dependencies);
  const repositoryRoot = fs.realpathSync(repoRoot(cwd));
  const manifestFile = fs.realpathSync(path.resolve(cwd, options.manifestFile));
  const manifest = validateManifest(
    readJson(manifestFile, 'Goal manifest'),
    manifestFile,
    repositoryRoot,
  );
  const operationId = safeId(
    options.operationId || (manifest.preclaim && manifest.preclaim.operation_id),
    'preclaim operation_id',
  );
  const root = controlRoot(cwd);
  const paths = preclaimPaths(root, manifest.goal_id, operationId);
  let sealedGithubCanary = null;
  if (fs.existsSync(paths.intent)) {
    assertArtifactInventory(paths, manifest.preclaim.issues);
    const existingIntent = verifySeal(
      readPrivateJson(root, paths.intent, 'preclaim intent'),
      'intent_sha256',
      'preclaim intent',
    );
    sealedGithubCanary = existingIntent.request.github_canary;
  }
  const request = requestFor(
    repositoryRoot,
    manifestFile,
    manifest,
    operationId,
    testDependencies,
    sealedGithubCanary,
  );
  const transactionKey = canonicalTransactionKey(
    'PRECLAIM_ISSUES',
    {
      goal_id: manifest.goal_id,
      operation_id: operationId,
    },
    operationId,
    hashObject(request),
  );
  const receipt = withLock(root, () => {
    assertArtifactInventory(paths, request.issues, true);
    const existingReceipt = readExactArtifact(
      root,
      paths.receipt,
      'receipt_sha256',
      'preclaim receipt',
      hashObject(request),
    );
    if (existingReceipt) return existingReceipt;
    ensureIntent(root, paths, request);
    invokeFault(testDependencies, 'afterIntent', { request });
    const issues = [];
    for (const issue of request.issues) {
      const observation = issueObservation(
        root,
        paths,
        request,
        issue,
        repositoryRoot,
        testDependencies,
      );
      if (observation.result === 'OTHERS_REJECT') {
        const final = sealFinalReadback(
          root,
          paths,
          request,
          observation,
          observation.observed_before,
        );
        issues.push(issueReceipt(
          request,
          observation,
          final,
        ));
        break;
      }
      mutateIssue(
        repositoryRoot,
        request,
        observation,
        testDependencies,
      );
      const final = observeIssue(
        repositoryRoot,
        request,
        issue,
        testDependencies,
      );
      invokeFault(
        testDependencies,
        'afterIssueReadback',
        { issue, final },
      );
      const sealedFinal = sealFinalReadback(
        root,
        paths,
        request,
        observation,
        final,
      );
      issues.push(issueReceipt(request, observation, sealedFinal));
      assertControl(
        issues[issues.length - 1].valid,
        'PRECLAIM_READBACK_FAILED',
        `issue #${issue} claim readback 未满足预期`,
      );
    }
    const passed = issues.length === request.issues.length
      && issues.every((item) => item.valid);
    const sealedReceipt = seal({
      schema_version: 1,
      kind: RECEIPT_KIND,
      operation_id: operationId,
      goal_id: manifest.goal_id,
      policy: POLICY,
      repository: request.repository,
      canonical_remote: request.canonical_remote,
      actor: request.expected_actor,
      expected_status: request.expected_status,
      manifest_sha256: request.manifest.normalized_sha256,
      authorization_sha256: request.authorization.sha256,
      request_sha256: hashObject(request),
      intent_sha256: readPrivateJson(
        root,
        paths.intent,
        'preclaim intent',
      ).intent_sha256,
      issues,
      status: passed ? 'PASS' : 'BLOCKED',
      observed_at: request.requested_at,
    }, 'receipt_sha256');
    atomicCreate(
      paths.receipt,
      `${JSON.stringify(sealedReceipt, null, 2)}\n`,
    );
    invokeFault(
      testDependencies,
      'afterReceipt',
      { receipt: sealedReceipt },
    );
    return readExactArtifact(
      root,
      paths.receipt,
      'receipt_sha256',
      'preclaim receipt',
      hashObject(request),
    );
  }, {
    transactionKey,
    authorizeOddRecovery: () => authorizeOddRetry(root, paths, request),
    afterGenerationBeforeCallback:
      preclaimGenerationBoundaryFaultHook(cwd, testDependencies),
  });
  assertControl(
    receipt.status === 'PASS',
    'PRECLAIM_BLOCKED',
    'preclaim 遇到 OTHERS_REJECT；现场已 seal，禁止继续 Goal init',
    { receipt_file: paths.receipt, receipt_sha256: receipt.receipt_sha256 },
  );
  return {
    goal_id: manifest.goal_id,
    operation_id: operationId,
    receipt_file: paths.receipt,
    receipt_sha256: receipt.receipt_sha256,
    request_sha256: receipt.request_sha256,
    status: receipt.status,
    issues: receipt.issues,
  };
}

function verifyPreclaimReceipt(cwd, manifest, manifestFile) {
  if (!manifest.preclaim) return null;
  const repositoryRoot = fs.realpathSync(repoRoot(cwd));
  const canonicalManifestFile = fs.realpathSync(manifestFile);
  const root = controlRoot(cwd);
  const paths = preclaimPaths(
    root,
    manifest.goal_id,
    manifest.preclaim.operation_id,
  );
  assertArtifactInventory(paths, manifest.preclaim.issues);
  assertControl(
    fs.existsSync(paths.intent),
    'PRECLAIM_RECEIPT_REQUIRED',
    'Goal init 缺 preclaim intent',
  );
  const sealedIntent = verifySeal(
    readPrivateJson(root, paths.intent, 'preclaim intent'),
    'intent_sha256',
    'preclaim intent',
  );
  const request = requestFor(
    repositoryRoot,
    canonicalManifestFile,
    manifest,
    manifest.preclaim.operation_id,
    NO_TEST_DEPENDENCIES,
    sealedIntent.request.github_canary,
  );
  const intent = readExactArtifact(
    root,
    paths.intent,
    'intent_sha256',
    'preclaim intent',
    hashObject(request),
  );
  const receipt = readExactArtifact(
    root,
    paths.receipt,
    'receipt_sha256',
    'preclaim receipt',
    hashObject(request),
  );
  assertControl(intent && receipt, 'PRECLAIM_RECEIPT_REQUIRED', 'Goal init 缺 exact preclaim intent/receipt');
  for (const item of receipt.issues) {
    const observation = readExactArtifact(
      root,
      path.join(paths.directory, `observation-${item.issue}.json`),
      'observation_sha256',
      `preclaim issue #${item.issue} observation`,
      receipt.request_sha256,
    );
    const final = readExactArtifact(
      root,
      path.join(paths.directory, `final-${item.issue}.json`),
      'final_readback_sha256',
      `preclaim issue #${item.issue} final readback`,
      receipt.request_sha256,
    );
    assertControl(
      observation
        && final
        && observation.observation_sha256 === item.observation_sha256
        && final.final_readback_sha256 === item.final_readback_sha256
        && final.observation_sha256 === observation.observation_sha256,
      'PRECLAIM_RECEIPT_INVALID',
      `issue #${item.issue} observation/final hash chain 不完整`,
    );
  }
  assertControl(
    receipt.status === 'PASS'
      && receipt.intent_sha256 === intent.intent_sha256
      && receipt.manifest_sha256 === manifest.manifest_sha256
      && receipt.authorization_sha256 === manifest.preclaim.authorization.sha256
      && receipt.repository.toLowerCase()
        === manifest.repository.name_with_owner.toLowerCase()
      && receipt.actor === manifest.preclaim.expected_actor
      && receipt.expected_status === manifest.preclaim.expected_status
      && receipt.issues.length === manifest.preclaim.issues.length
      && receipt.issues.every(
        (item, index) => item.issue === manifest.preclaim.issues[index]
          && item.valid === true
          && ['CLAIMED', 'MINE_NEED_CONFIRM'].includes(item.result),
      ),
    'PRECLAIM_RECEIPT_INVALID',
    'Goal init preclaim receipt 未绑定 exact policy/request/whitelist/readback',
  );
  return {
    operation_id: manifest.preclaim.operation_id,
    receipt_file: paths.receipt,
    receipt_sha256: receipt.receipt_sha256,
    request_sha256: receipt.request_sha256,
  };
}

module.exports = {
  POLICY,
  preclaimIssues,
  verifyPreclaimReceipt,
};
