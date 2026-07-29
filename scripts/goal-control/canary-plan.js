'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const {
  assertControllerProvenanceStable,
  assertSafeGeneratorNodeRuntime,
  controllerProvenanceCapture,
  replayEnvironmentContract,
  replayShellCommand,
} = require('./canary-controller-attestation');
const { ControlError, assertControl } = require('./errors');
const {
  WORKER_ROLES: BOOTSTRAP_WORKER_ROLES,
  loadCaptainRequiredStartHeadProof,
  validateCaptainBootstrapReceipt,
  validateWorkerBootstrapReceipt,
} = require('./canary-bootstrap');
const {
  CANARY_CONTRACT,
  RECEIPT_TTL_MILLISECONDS,
  RECEIPT_KIND,
  assertLiveServerIdentity,
  bindingSha256,
  buildCanaryPage,
  deriveServeIdentity,
  implementationSha256,
} = require('./browser-canary-server');
const {
  hashObject,
  readOnlyGitEnvironment,
  repoRoot,
  sha256,
  trustedGitExecutable,
} = require('./util');
const {
  CAPTAIN_CANARY_BOOTSTRAP_POLICY_MARKER,
  WORKER_CANARY_BOOTSTRAP_POLICY_MARKER,
  validateManifest,
} = require('./validation');

const CANARY_ROLES = Object.freeze([
  'FOREMAN',
  'CAPTAIN',
  'DEV',
  'REVIEW',
  'RECEIPT',
]);
const WORKER_ROLES = Object.freeze(['DEV', 'REVIEW', 'RECEIPT']);
const TASK_SCOPED_ROLES = Object.freeze([
  'CAPTAIN',
  ...WORKER_ROLES,
]);
const BROWSER_RESOURCE_KINDS = new Set(['BROWSER_PROFILE', 'WINDOW']);
const REPO_PATH_RE =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const GITHUB_APP_PROBE = 'GITHUB_APP_REPOSITORY_READ';
const GITHUB_APP_KNOWN_LIMITATION_ID =
  'github_app_private_repo_404-v1';
const GITHUB_APP_KNOWN_LIMITATION_POLICY_PREFIX =
  'GitHub-App-Known-Limitation:';
const GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER =
  `${GITHUB_APP_KNOWN_LIMITATION_POLICY_PREFIX} `
  + GITHUB_APP_KNOWN_LIMITATION_ID;
const WORKER_CANARY_BOOTSTRAP_POLICY_PREFIX =
  'Worker-Canary-Bootstrap-Protocol:';
const CAPTAIN_CANARY_BOOTSTRAP_POLICY_PREFIX =
  'Captain-Canary-Bootstrap-Protocol:';

const ROLE_PROBES = Object.freeze({
  FOREMAN: Object.freeze([
    'TASK_CREATE_SEND_WAIT_ARCHIVE',
    'GH_REPOSITORY_MERGE_PERMISSION',
    'GIT_REMOTE_READ',
    'GOALCTL',
    GITHUB_APP_PROBE,
  ]),
  CAPTAIN: Object.freeze([
    'TASK_CREATE_SEND_WAIT_ARCHIVE',
    'GH_REPOSITORY_PERMISSION',
    'GIT_REMOTE_READ',
    'GOALCTL',
    'RESOURCECTL',
    GITHUB_APP_PROBE,
  ]),
  DEV: Object.freeze([
    'GIT_WORKTREE_WRITE',
    'GH_REPOSITORY_PERMISSION',
    'GIT_REMOTE_READ',
    'GIT_PUSH_DRY_RUN',
    GITHUB_APP_PROBE,
  ]),
  REVIEW: Object.freeze([
    'GH_REPOSITORY_PERMISSION',
    'GIT_REMOTE_READ',
    GITHUB_APP_PROBE,
  ]),
  RECEIPT: Object.freeze([
    'GH_REPOSITORY_PERMISSION',
    'GIT_REMOTE_READ',
    GITHUB_APP_PROBE,
  ]),
});

const BROWSER_PROBE = 'BROWSER_LOCALHOST_OPEN_READ_CLICK_SCREENSHOT';
const BROWSER_CANARY_URL_RE =
  /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/codex-capability-canary$/;
const MAX_BROWSER_CANARY_RECEIPT_BYTES = 64 * 1024;
const MAX_BROWSER_CANARY_PROBE_OUTPUT_BYTES = 64 * 1024;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;

function gitBytes(repositoryRoot, args, label) {
  try {
    return execFileSync(trustedGitExecutable(), args, {
      cwd: repositoryRoot,
      encoding: null,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...readOnlyGitEnvironment(),
        GIT_LITERAL_PATHSPECS: '1',
        GIT_NO_REPLACE_OBJECTS: '1',
      },
    });
  } catch (error) {
    const detail = String(error.stderr || error.message || '').trim();
    throw new ControlError(
      'GOAL_INPUT_NOT_COMMITTED',
      `${label} 尚未进入当前 HEAD${detail ? ` (${detail})` : ''}`,
    );
  }
}

function assertNoReplaceRefs(repositoryRoot) {
  const replaceRef = gitBytes(
    repositoryRoot,
    [
      'for-each-ref',
      '--count=1',
      '--format=%(refname)',
      'refs/replace',
    ],
    'Git replace ref inventory',
  ).toString('utf8').trim();
  assertControl(
    replaceRef.length === 0,
    'CANARY_PLAN_REPLACE_REFS',
    `canary-plan 禁止 Git replace refs: ${replaceRef}`,
  );
}

function assertRepoRelativePath(relative, label) {
  assertControl(
    typeof relative === 'string' && REPO_PATH_RE.test(relative),
    'INVALID_ARGUMENT',
    `${label} 必须是 canonical repo-relative path`,
  );
  return relative;
}

function statIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  };
}

function sameStatIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function readOrdinaryFileStable(absolute, relative, label) {
  let before;
  try {
    before = fs.lstatSync(absolute, { bigint: true });
  } catch (error) {
    throw new ControlError(
      'GOAL_INPUT_NOT_COMMITTED',
      `${label} 当前文件不存在: ${relative} (${error.message})`,
    );
  }
  assertControl(
    before.isFile() && !before.isSymbolicLink(),
    'GOAL_INPUT_SYMLINK',
    `${label} 必须是仓库内非 symlink 普通文件: ${relative}`,
  );
  const beforeIdentity = statIdentity(before);
  const noFollow = typeof fs.constants.O_NOFOLLOW === 'number'
    ? fs.constants.O_NOFOLLOW
    : 0;
  let descriptor;
  try {
    descriptor = fs.openSync(
      absolute,
      fs.constants.O_RDONLY | noFollow,
    );
  } catch (error) {
    throw new ControlError(
      'GOAL_INPUT_SYMLINK',
      `${label} 无法以 no-follow ordinary file 打开: ${relative} (${error.message})`,
    );
  }
  try {
    const openedBefore = fs.fstatSync(descriptor, { bigint: true });
    assertControl(
      openedBefore.isFile()
        && sameStatIdentity(beforeIdentity, statIdentity(openedBefore)),
      'GOAL_INPUT_RACE',
      `${label} 在 lstat/open 之间发生 identity 漂移: ${relative}`,
    );
    const bytes = fs.readFileSync(descriptor);
    const openedAfter = fs.fstatSync(descriptor, { bigint: true });
    assertControl(
      sameStatIdentity(
        statIdentity(openedBefore),
        statIdentity(openedAfter),
      ),
      'GOAL_INPUT_RACE',
      `${label} 在读取期间发生 identity/content 漂移: ${relative}`,
    );
    let pathAfter;
    try {
      pathAfter = fs.lstatSync(absolute, { bigint: true });
    } catch (error) {
      throw new ControlError(
        'GOAL_INPUT_RACE',
        `${label} path 在读取期间消失: ${relative} (${error.message})`,
      );
    }
    assertControl(
      pathAfter.isFile()
        && !pathAfter.isSymbolicLink()
        && sameStatIdentity(
          statIdentity(openedAfter),
          statIdentity(pathAfter),
        ),
      'GOAL_INPUT_RACE',
      `${label} path 在读取期间发生 identity 漂移: ${relative}`,
    );
    return {
      bytes,
      identity: statIdentity(openedAfter),
    };
  } finally {
    fs.closeSync(descriptor);
  }
}

function assertCommittedOrdinaryFile(
  repositoryRoot,
  relative,
  label,
  repositoryHeadSha,
) {
  assertRepoRelativePath(relative, label);
  const absolute = path.join(repositoryRoot, relative);
  const resolvedRoot = fs.realpathSync(repositoryRoot);
  let resolvedFile;
  try {
    resolvedFile = fs.realpathSync(absolute);
  } catch (error) {
    throw new ControlError(
      'GOAL_INPUT_NOT_COMMITTED',
      `${label} 当前文件不存在: ${relative} (${error.message})`,
    );
  }
  assertControl(
    resolvedFile.startsWith(`${resolvedRoot}${path.sep}`),
    'PATH_OUTSIDE_REPO',
    `${label} 必须位于仓库内: ${relative}`,
  );

  const entry = gitBytes(
    repositoryRoot,
    ['ls-tree', '-z', repositoryHeadSha, '--', relative],
    label,
  ).toString('utf8');
  const match = /^(100644|100755) blob ([0-9a-f]{40})\t([^\0]+)\0$/.exec(entry);
  assertControl(
    match && match[3] === relative,
    entry.length === 0 ? 'GOAL_INPUT_NOT_COMMITTED' : 'GOAL_INPUT_SYMLINK',
    entry.length === 0
      ? `${label} 尚未进入当前 HEAD: ${relative}`
      : `${label} 在当前 HEAD 中必须是 ordinary blob: ${relative}`,
  );
  const committed = gitBytes(
    repositoryRoot,
    ['cat-file', 'blob', `${repositoryHeadSha}:${relative}`],
    label,
  );
  const current = readOrdinaryFileStable(absolute, relative, label);
  const committedSha256 = `sha256:${sha256(committed)}`;
  const currentSha256 = `sha256:${sha256(current.bytes)}`;
  assertControl(
    currentSha256 === committedSha256,
    'GOAL_INPUT_DIRTY',
    `${label} 与当前 HEAD 中的 Git blob 不一致: ${relative}`,
  );
  return {
    absolute,
    bytes: Buffer.from(current.bytes),
    identity: current.identity,
    sha256: currentSha256,
  };
}

function parseManifest(bytes, relative) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'INVALID_JSON',
      `Goal manifest 不是合法 JSON: ${relative} (${error.message})`,
    );
  }
}

function repositoryHead(repositoryRoot) {
  const head = gitBytes(
    repositoryRoot,
    ['rev-parse', 'HEAD'],
    'repository HEAD',
  ).toString('utf8').trim();
  assertControl(
    /^[0-9a-f]{40}$/.test(head),
    'CANARY_PLAN_HEAD_MISMATCH',
    'repository HEAD 不是完整 SHA',
  );
  return head;
}

function committedInputs(manifest) {
  const inputs = new Map([[manifest.source_manifest, 'manifest']]);
  for (const [name, protocol] of Object.entries(manifest.protocol || {})) {
    inputs.set(protocol.path, `protocol.${name}`);
  }
  if (manifest.worker_canary_bootstrap) {
    inputs.set(
      manifest.worker_canary_bootstrap.policy.path,
      'worker_canary_bootstrap.policy',
    );
  }
  if (manifest.captain_canary_bootstrap) {
    inputs.set(
      manifest.captain_canary_bootstrap.policy.path,
      'captain_canary_bootstrap.policy',
    );
  }
  for (const task of manifest.tasks) {
    inputs.set(task.packet.path, `${task.id}.packet`);
    if (task.p1) {
      inputs.set(task.p1.authority.path, `${task.id}.p1.authority`);
    }
  }
  return inputs;
}

function canaryPolicyKnownLimitations(
  policyBytes,
  bootstrapPolicy = {
    prefix: WORKER_CANARY_BOOTSTRAP_POLICY_PREFIX,
    marker: WORKER_CANARY_BOOTSTRAP_POLICY_MARKER,
    label: 'worker',
  },
) {
  const lines = policyBytes.toString('utf8').split(/\r?\n/);
  const bootstrapMarkers = lines.filter(
    (line) => line.startsWith(bootstrapPolicy.prefix),
  );
  assertControl(
    bootstrapMarkers.length === 1
      && bootstrapMarkers[0] === bootstrapPolicy.marker,
    'CANARY_POLICY_BOOTSTRAP_MARKER_INVALID',
    `stable committed canary policy 必须且只能包含一个 exact ${bootstrapPolicy.label} bootstrap marker`,
  );
  const declaredKnownLimitations = lines.filter(
    (line) => line.startsWith(GITHUB_APP_KNOWN_LIMITATION_POLICY_PREFIX),
  );
  assertControl(
    declaredKnownLimitations.length <= 1,
    'CANARY_POLICY_MARKER_DUPLICATE',
    'GitHub App known-limitation policy marker 必须至多出现一次',
  );
  if (declaredKnownLimitations.length === 1) {
    assertControl(
      declaredKnownLimitations[0]
        === GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
      'CANARY_POLICY_MARKER_UNSUPPORTED',
      `不支持的 GitHub App known-limitation policy marker: ${
        declaredKnownLimitations[0]
      }`,
    );
  }
  return declaredKnownLimitations.length === 0
    ? []
    : [{
      id: GITHUB_APP_KNOWN_LIMITATION_ID,
      policy_marker: GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
    }];
}

function canaryPolicyContract(manifest, inputCaptures, role) {
  const captainBootstrap = role === 'CAPTAIN'
    && manifest.captain_canary_bootstrap;
  const worker = BOOTSTRAP_WORKER_ROLES.includes(role)
    && manifest.worker_canary_bootstrap;
  // Preserve the frozen bootstrap-v1 policy contract for every legacy role.
  // Before CAPTAIN bootstrap existed, CAPTAIN and FOREMAN still consumed
  // worker_canary_bootstrap.policy for the exact repository-metadata 404
  // known-limitation contract. Only the new CAPTAIN bootstrap profile selects
  // the separate captain policy marker.
  const config = captainBootstrap
    || worker
    || manifest.worker_canary_bootstrap;
  if (!config) return null;
  const policy = config.policy;
  const capture = inputCaptures.get(policy.path);
  assertControl(
    capture && capture.sha256 === policy.sha256,
    'GOAL_INPUT_DIRTY',
    'role bootstrap policy hash 与 committed capture 不一致',
  );
  return {
    path: policy.path,
    sha256: policy.sha256,
    known_limitations: canaryPolicyKnownLimitations(
      capture.bytes,
      captainBootstrap
        ? {
          prefix: CAPTAIN_CANARY_BOOTSTRAP_POLICY_PREFIX,
          marker: CAPTAIN_CANARY_BOOTSTRAP_POLICY_MARKER,
          label: 'captain',
        }
        : undefined,
    ),
  };
}

function orderedRequiredProbes(role, browserRequired) {
  const roleProbes = ROLE_PROBES[role];
  assertControl(
    roleProbes[roleProbes.length - 1] === GITHUB_APP_PROBE
      && roleProbes.filter((probe) => probe === GITHUB_APP_PROBE).length === 1,
    'CANARY_PLAN_PROBE_ORDER_INVALID',
    `${role} GitHub App probe 必须是 role probe 的最后一项`,
  );
  return [
    ...roleProbes.slice(0, -1),
    ...(browserRequired ? [BROWSER_PROBE] : []),
    GITHUB_APP_PROBE,
  ];
}

function probeEvaluationContract(
  repository,
  requiredProbes,
  canaryPolicy,
) {
  const policyAllowsKnownLimitation = canaryPolicy !== null
    && canaryPolicy.known_limitations.some(
      (limitation) => limitation.id === GITHUB_APP_KNOWN_LIMITATION_ID,
    );
  return {
    schema_version: 1,
    replay_must_pass_before_probes: true,
    required_probe_order: 'DECLARED_ARRAY_ORDER',
    session_scope: 'CURRENT_ACTUAL_SESSION_ONLY',
    missing_or_skipped_probe_disposition: 'CANARY_FAIL',
    non_matching_result_disposition: 'CANARY_FAIL',
    final_pass_condition:
      'EVERY_REQUIRED_PROBE_PASS_OR_FINALIZED_KNOWN_LIMITATION',
    known_limitations: (
      policyAllowsKnownLimitation
        ? [{
          id: GITHUB_APP_KNOWN_LIMITATION_ID,
          probe: GITHUB_APP_PROBE,
          policy_marker: GITHUB_APP_KNOWN_LIMITATION_POLICY_MARKER,
          exact_match: {
            semantic_operation: 'REPOSITORY_METADATA_READ',
            target_kind: 'REPOSITORY',
            repository,
            result_fingerprint: '404/repo_not_found',
            allow_dialog: false,
            authentication_prompt: false,
          },
          provisional_disposition: 'PROVISIONAL_KNOWN_LIMITATION',
          compensation_probes: requiredProbes.filter(
            (probe) => probe !== GITHUB_APP_PROBE,
          ),
          terminal_mismatch_classes: [
            'ALLOW_DIALOG',
            'AUTHENTICATION_PROMPT',
            'TOKEN_REQUEST',
            'HTTP_401',
            'HTTP_403',
            'TIMEOUT',
            'NETWORK_ERROR',
            'WRONG_REPOSITORY',
            'WRONG_OPERATION',
            'DIFFERENT_FINGERPRINT',
          ],
          finalization_condition:
            'ALL_LISTED_COMPENSATION_PROBES_PASS_CURRENT_SESSION',
          final_disposition: 'KNOWN_CONNECTOR_LIMITATION',
        }]
        : []
    ),
  };
}

function requirementAppliesToWorker(requirement, role) {
  return requirement.roles === undefined || requirement.roles.includes(role);
}

function browserRequirements(manifest, role, selectedTask) {
  if (role === 'CAPTAIN') return [];
  if (role === 'FOREMAN') {
    return manifest.tasks.flatMap((task) => task.resource_requirements
      .filter((requirement) => BROWSER_RESOURCE_KINDS.has(requirement.kind))
      .map((requirement) => ({ task, requirement })));
  }
  return selectedTask.resource_requirements
    .filter((requirement) => (
      BROWSER_RESOURCE_KINDS.has(requirement.kind)
        && requirementAppliesToWorker(requirement, role)
    ))
    .map((requirement) => ({ task: selectedTask, requirement }));
}

function publicRequirement({ task, requirement }) {
  return {
    task_id: task.id,
    kind: requirement.kind,
    id: requirement.id,
    access: requirement.access,
    roles: requirement.roles || [...WORKER_ROLES],
  };
}

function assertExactKeys(value, expected, label) {
  assertControl(
    value !== null
      && typeof value === 'object'
      && !Array.isArray(value)
      && hashObject(Object.keys(value).sort()) === hashObject([...expected].sort()),
    'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
    `${label} 字段集合不匹配`,
  );
}

function privateReceiptIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    uid: stat.uid,
    nlink: stat.nlink,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  };
}

function privateReceiptParentIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    uid: stat.uid,
  };
}

function assertPrivateReceiptFile(stat, label) {
  const currentUid = typeof process.getuid === 'function'
    ? BigInt(process.getuid())
    : null;
  assertControl(
    stat.isFile()
      && !stat.isSymbolicLink()
      && stat.nlink === 1n
      && (stat.mode & 0o777n) === 0o600n
      && stat.size > 0n
      && stat.size <= BigInt(MAX_BROWSER_CANARY_RECEIPT_BYTES)
      && (currentUid === null || stat.uid === currentUid),
    'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
    `${label} 必须是当前用户拥有的 0600 单链接 ordinary file，且大小受限`,
  );
}

function assertPrivateReceiptParent(stat, label) {
  const currentUid = typeof process.getuid === 'function'
    ? BigInt(process.getuid())
    : null;
  assertControl(
    stat.isDirectory()
      && !stat.isSymbolicLink()
      && (stat.mode & 0o777n) === 0o700n
      && (currentUid === null || stat.uid === currentUid),
    'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
    `${label} 必须是当前用户拥有、exact mode 0700 的非 symlink 目录`,
  );
}

function readPrivateBrowserReceipt(receiptFile, dependencies = {}) {
  assertControl(
    typeof receiptFile === 'string'
      && path.isAbsolute(receiptFile)
      && path.resolve(receiptFile) === receiptFile,
    'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
    '--browser-canary-receipt 必须是 canonical absolute path',
  );
  const parent = path.dirname(receiptFile);
  let pathBefore;
  let parentBefore;
  try {
    pathBefore = fs.lstatSync(receiptFile, { bigint: true });
    parentBefore = fs.lstatSync(parent, { bigint: true });
    assertControl(
      fs.realpathSync(receiptFile) === receiptFile
        && fs.realpathSync(parent) === parent,
      'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
      'browser canary receipt 必须是 canonical non-symlink ordinary file path，'
        + 'parent 必须是 canonical non-symlink directory path',
    );
  } catch (error) {
    if (error instanceof ControlError) throw error;
    throw new ControlError(
      'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
      `browser canary receipt 无法读取: ${error.message}`,
    );
  }
  assertPrivateReceiptFile(pathBefore, 'browser canary receipt');
  assertPrivateReceiptParent(parentBefore, 'browser canary receipt parent');
  assertControl(
    pathBefore.dev === parentBefore.dev,
    'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
    'browser canary receipt 必须与 private parent 位于同一 filesystem',
  );
  const pathBeforeIdentity = privateReceiptIdentity(pathBefore);
  const parentBeforeIdentity = privateReceiptParentIdentity(parentBefore);
  if (dependencies.afterBrowserReceiptPathCapture) {
    dependencies.afterBrowserReceiptPathCapture({ receiptFile });
  }

  const noFollow = typeof fs.constants.O_NOFOLLOW === 'number'
    ? fs.constants.O_NOFOLLOW
    : 0;
  const closeOnExec = typeof fs.constants.O_CLOEXEC === 'number'
    ? fs.constants.O_CLOEXEC
    : 0;
  let descriptor;
  try {
    descriptor = fs.openSync(
      receiptFile,
      fs.constants.O_RDONLY | noFollow | closeOnExec,
    );
  } catch (error) {
    throw new ControlError(
      'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
      `browser canary receipt 无法以 O_NOFOLLOW 打开: ${error.message}`,
    );
  }
  try {
    const openedBefore = fs.fstatSync(descriptor, { bigint: true });
    assertPrivateReceiptFile(openedBefore, 'opened browser canary receipt');
    assertControl(
      sameStatIdentity(
        pathBeforeIdentity,
        privateReceiptIdentity(openedBefore),
      ),
      'GOAL_INPUT_RACE',
      'browser canary receipt pathname 与实际打开 inode 不一致',
    );
    if (dependencies.afterBrowserReceiptOpen) {
      dependencies.afterBrowserReceiptOpen({ receiptFile });
    }
    const bytes = fs.readFileSync(descriptor);
    const openedAfter = fs.fstatSync(descriptor, { bigint: true });
    assertPrivateReceiptFile(openedAfter, 'opened browser canary receipt');
    assertControl(
      sameStatIdentity(
        privateReceiptIdentity(openedBefore),
        privateReceiptIdentity(openedAfter),
      )
        && BigInt(bytes.length) === openedAfter.size,
      'GOAL_INPUT_RACE',
      'browser canary receipt opened inode 在读取期间发生变化',
    );
    if (dependencies.afterBrowserReceiptRead) {
      dependencies.afterBrowserReceiptRead({ receiptFile });
    }

    let pathAfter;
    let parentAfter;
    try {
      pathAfter = fs.lstatSync(receiptFile, { bigint: true });
      parentAfter = fs.lstatSync(parent, { bigint: true });
      assertControl(
        fs.realpathSync(receiptFile) === receiptFile
          && fs.realpathSync(parent) === parent,
        'GOAL_INPUT_RACE',
        'browser canary receipt 或 parent canonical path 在读取期间漂移',
      );
    } catch (error) {
      if (error instanceof ControlError) throw error;
      throw new ControlError(
        'GOAL_INPUT_RACE',
        `browser canary receipt 或 parent 在读取期间消失: ${error.message}`,
      );
    }
    assertPrivateReceiptFile(pathAfter, 'browser canary receipt');
    assertPrivateReceiptParent(parentAfter, 'browser canary receipt parent');
    assertControl(
      sameStatIdentity(
        privateReceiptIdentity(openedAfter),
        privateReceiptIdentity(pathAfter),
      )
        && pathAfter.dev === parentAfter.dev
        && sameStatIdentity(
          parentBeforeIdentity,
          privateReceiptParentIdentity(parentAfter),
        ),
      'GOAL_INPUT_RACE',
      'browser canary receipt path inode 或 parent identity 在读取期间漂移',
    );
    return {
      bytes,
      identity: privateReceiptIdentity(openedAfter),
    };
  } finally {
    fs.closeSync(descriptor);
  }
}

function probeBrowserCanaryEndpoint(receipt) {
  let output;
  try {
    output = execFileSync(
      process.execPath,
      [
        path.join(__dirname, 'browser-canary-probe.js'),
        '--url',
        receipt.url,
        '--expected-page-sha256',
        receipt.page_sha256,
        '--expected-nonce',
        receipt.nonce,
      ],
      {
        cwd: path.resolve(__dirname, '..', '..'),
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 5_000,
        maxBuffer: MAX_BROWSER_CANARY_PROBE_OUTPUT_BYTES,
        env: {
          PATH: '/usr/bin:/bin:/usr/sbin',
          LANG: 'C',
          LC_ALL: 'C',
          TZ: 'UTC',
        },
      },
    );
  } catch (error) {
    const detail = String(error.stderr || error.message || '').trim();
    throw new ControlError(
      'CANARY_PLAN_BROWSER_LISTENER_INVALID',
      `browser canary endpoint exact probe 失败${detail ? `: ${detail}` : ''}`,
    );
  }
  let result;
  try {
    result = JSON.parse(output);
  } catch (error) {
    throw new ControlError(
      'CANARY_PLAN_BROWSER_LISTENER_INVALID',
      `browser canary endpoint probe 输出非法: ${error.message}`,
    );
  }
  assertExactKeys(result, [
    'schema_version',
    'url',
    'status_code',
    'remote_address',
    'remote_port',
    'page_sha256',
    'nonce',
    'redirect_followed',
  ], 'browser canary endpoint probe');
  assertControl(
    result.schema_version === 1
      && result.url === receipt.url
      && result.status_code === 200
      && result.remote_address === '127.0.0.1'
      && result.remote_port === receipt.listener.port
      && result.page_sha256 === receipt.page_sha256
      && result.nonce === receipt.nonce
      && result.redirect_followed === false,
    'CANARY_PLAN_BROWSER_LISTENER_INVALID',
    'browser canary endpoint probe 与 receipt 不匹配',
  );
  return result;
}

function verifyBrowserLiveServer(receipt, receiptFile, expectedBinding) {
  try {
    return assertLiveServerIdentity(receipt, {
      receiptFile,
      binding: expectedBinding,
    });
  } catch (error) {
    throw new ControlError(
      'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
      `browser canary live server identity 校验失败: ${error.message}`,
    );
  }
}

function parseBrowserReceipt(
  capture,
  receiptFile,
  expectedBinding,
  expectedController,
) {
  let receipt;
  try {
    receipt = JSON.parse(capture.bytes.toString('utf8'));
  } catch (error) {
    throw new ControlError(
      'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
      `browser canary receipt 不是合法 JSON: ${error.message}`,
    );
  }
  assertExactKeys(receipt, [
    'schema_version',
    'kind',
    'binding',
    'binding_sha256',
    'url',
    'nonce',
    'contract',
    'page_sha256',
    'implementation_sha256',
    'launch',
    'lifecycle',
    'pid',
    'process_start_token',
    'process_executable_path',
    'process_command_sha256',
    'process_cwd',
    'started_at',
    'expires_at',
    'listener',
  ], 'browser canary receipt');
  assertExactKeys(
    receipt.binding,
    ['goal_id', 'role', 'task_id'],
    'browser canary receipt binding',
  );
  assertExactKeys(receipt.contract, [
    'contract_version',
    'expected_title',
    'button_id',
    'status_id',
    'initial_status',
    'clicked_status',
    'screenshot_required',
  ], 'browser canary receipt contract');
  assertExactKeys(receipt.listener, ['host', 'port'], 'browser canary listener');
  assertExactKeys(receipt.launch, [
    'controller_root',
    'controller_repository_head',
    'server_script_path',
    'server_script_sha256',
    'node_executable_path',
    'cwd',
    'requested_port',
    'expected_argv',
    'expected_argv_sha256',
    'environment',
    'environment_sha256',
  ], 'browser canary launch');
  assertExactKeys(receipt.lifecycle, [
    'receipt_retained',
    'auto_shutdown_at_expires_at',
  ], 'browser canary lifecycle');

  const match = typeof receipt.url === 'string'
    ? BROWSER_CANARY_URL_RE.exec(receipt.url)
    : null;
  const port = match ? Number(match[1]) : null;
  let parsed = null;
  try {
    parsed = new URL(receipt.url);
  } catch (_) {}
  assertControl(
    receipt.schema_version === 1
      && receipt.kind === RECEIPT_KIND
      && match !== null
      && Number.isSafeInteger(port)
      && port >= 1024
      && port <= 65535
      && parsed !== null
      && parsed.href === receipt.url
      && parsed.protocol === 'http:'
      && parsed.hostname === '127.0.0.1'
      && parsed.port === String(port)
      && parsed.pathname === '/codex-capability-canary'
      && parsed.username === ''
      && parsed.password === ''
      && parsed.search === ''
      && parsed.hash === ''
      && receipt.listener.host === '127.0.0.1'
      && receipt.listener.port === port,
    'CANARY_PLAN_BROWSER_TARGET_INVALID',
    'browser canary receipt URL/listener 必须精确绑定 '
      + 'http://127.0.0.1:<1024-65535>/codex-capability-canary',
  );
  const startedAt = Date.parse(receipt.started_at);
  const expiresAt = Date.parse(receipt.expires_at);
  const now = Date.now();
  let expectedLaunch;
  try {
    expectedLaunch = deriveServeIdentity({
      receiptFile,
      binding: expectedBinding,
      environment: receipt.launch.environment,
    });
  } catch (error) {
    throw new ControlError(
      'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
      `browser canary canonical launch 无法派生: ${error.message}`,
    );
  }
  const controllerServerRelative =
    'scripts/goal-control/browser-canary-server.js';
  assertControl(
    /^[0-9a-f]{64}$/.test(receipt.nonce)
      && SHA256_RE.test(receipt.page_sha256)
      && receipt.page_sha256
        === `sha256:${sha256(buildCanaryPage(receipt.nonce))}`
      && SHA256_RE.test(receipt.implementation_sha256)
      && receipt.implementation_sha256 === implementationSha256()
      && hashObject(receipt.contract) === hashObject(CANARY_CONTRACT)
      && receipt.lifecycle.receipt_retained === true
      && receipt.lifecycle.auto_shutdown_at_expires_at === true
      && Number.isSafeInteger(receipt.pid)
      && receipt.pid > 0
      && SHA256_RE.test(receipt.process_start_token)
      && SHA256_RE.test(receipt.process_command_sha256)
      && typeof receipt.process_cwd === 'string'
      && path.isAbsolute(receipt.process_cwd)
      && receipt.binding_sha256 === bindingSha256(receipt.binding)
      && hashObject(receipt.binding) === hashObject(expectedBinding)
      && hashObject(receipt.launch) === hashObject(expectedLaunch)
      && receipt.launch.controller_root === expectedController.root
      && receipt.launch.controller_repository_head
        === expectedController.repository_head
      && receipt.launch.server_script_path
        === path.join(expectedController.root, controllerServerRelative)
      && receipt.launch.server_script_sha256
        === expectedController.modules[controllerServerRelative]
      && receipt.launch.server_script_sha256
        === receipt.implementation_sha256
      && repositoryHead(receipt.launch.controller_root)
        === expectedController.repository_head
      && typeof receipt.started_at === 'string'
      && typeof receipt.expires_at === 'string'
      && Number.isFinite(startedAt)
      && Number.isFinite(expiresAt)
      && expiresAt - startedAt === RECEIPT_TTL_MILLISECONDS
      && startedAt <= now + 5_000
      && expiresAt > now,
    'CANARY_PLAN_BROWSER_RECEIPT_INVALID',
    'browser canary receipt nonce/page/implementation/process/listener/'
      + 'binding/freshness 不匹配',
  );
  const liveBefore = verifyBrowserLiveServer(
    receipt,
    receiptFile,
    expectedBinding,
  );
  const endpointProbeBefore = probeBrowserCanaryEndpoint(receipt);
  const liveBetween = verifyBrowserLiveServer(
    receipt,
    receiptFile,
    expectedBinding,
  );
  const endpointProbeAfter = probeBrowserCanaryEndpoint(receipt);
  const liveAfter = verifyBrowserLiveServer(
    receipt,
    receiptFile,
    expectedBinding,
  );
  assertControl(
    hashObject(liveBefore) === hashObject(liveBetween)
      && hashObject(liveBetween) === hashObject(liveAfter)
      && hashObject(endpointProbeBefore) === hashObject(endpointProbeAfter),
    'CANARY_PLAN_BROWSER_LISTENER_INVALID',
    'browser canary listener/process/endpoint 在双重 probe 前后漂移',
  );
  return {
    ...CANARY_CONTRACT,
    url: receipt.url,
    nonce: receipt.nonce,
    page_sha256: receipt.page_sha256,
    redirects_allowed: false,
    final_url_must_equal: true,
    receipt: {
      path: receiptFile,
      sha256: `sha256:${sha256(capture.bytes)}`,
      implementation_sha256: receipt.implementation_sha256,
      pid: receipt.pid,
      process_start_token: receipt.process_start_token,
      process_executable_path: receipt.process_executable_path,
      process_command_sha256: receipt.process_command_sha256,
      process_cwd: receipt.process_cwd,
      launch: receipt.launch,
      lifecycle: receipt.lifecycle,
      controller_repository_head: expectedController.repository_head,
      started_at: receipt.started_at,
      expires_at: receipt.expires_at,
      listener: receipt.listener,
      binding: receipt.binding,
      binding_sha256: receipt.binding_sha256,
    },
    endpoint_probe: endpointProbeAfter,
  };
}

function browserCanaryTarget(
  browserRequired,
  receiptFile,
  expectedBinding,
  expectedController,
  dependencies = {},
) {
  if (!browserRequired) {
    assertControl(
      receiptFile === null || receiptFile === undefined,
      'CANARY_PLAN_BROWSER_TARGET_FORBIDDEN',
      'Browser NOT_REQUIRED 时禁止传 --browser-canary-receipt',
    );
    return { target: null, capture: null };
  }
  assertControl(
    typeof receiptFile === 'string' && receiptFile.length > 0,
    'CANARY_PLAN_BROWSER_TARGET_REQUIRED',
    'Browser REQUIRED 时必须传 --browser-canary-receipt',
  );
  const capture = readPrivateBrowserReceipt(receiptFile, dependencies);
  return {
    target: parseBrowserReceipt(
      capture,
      receiptFile,
      expectedBinding,
      expectedController,
    ),
    capture,
  };
}

function assertControllerWorktreeClean(controllerRoot) {
  const canonicalRoot = fs.realpathSync(repoRoot(controllerRoot));
  const head = repositoryHead(canonicalRoot);
  assertNoReplaceRefs(canonicalRoot);
  return require('./canary-controller-attestation')
    .assertControllerControlPathsCommitted(canonicalRoot, head);
}

function canaryPlan(
  cwd,
  options,
  dependencies = {},
  invocationCwd = cwd,
) {
  assertSafeGeneratorNodeRuntime();
  const controllerCapture = controllerProvenanceCapture();
  const repositoryRoot = fs.realpathSync(repoRoot(cwd));
  assertNoReplaceRefs(repositoryRoot);
  const initialHead = repositoryHead(repositoryRoot);
  const manifestRelative = assertRepoRelativePath(
    options.manifestFile,
    '--manifest',
  );
  const role = options.role;
  assertControl(
    CANARY_ROLES.includes(role),
    'INVALID_ROLE',
    `未知 canary role: ${role}`,
  );
  const taskId = options.taskId || null;
  if (TASK_SCOPED_ROLES.includes(role)) {
    assertControl(
      taskId !== null,
      'CANARY_PLAN_TASK_REQUIRED',
      `${role} canary-plan 必须指定 --task`,
    );
  } else {
    assertControl(
      taskId === null,
      'CANARY_PLAN_ROLE_TASK_MISMATCH',
      `${role} canary-plan 不接受 --task`,
    );
  }

  const firstManifestCheck = assertCommittedOrdinaryFile(
    repositoryRoot,
    manifestRelative,
    'manifest',
    initialHead,
  );
  if (dependencies.afterManifestCapture) {
    dependencies.afterManifestCapture({
      manifestFile: firstManifestCheck.absolute,
      manifestSha256: firstManifestCheck.sha256,
    });
  }
  let sourceManifest;
  try {
    sourceManifest = parseManifest(
      firstManifestCheck.bytes,
      manifestRelative,
    );
  } finally {
    if (dependencies.afterManifestParse) {
      dependencies.afterManifestParse({
        manifestFile: firstManifestCheck.absolute,
      });
    }
  }
  if (dependencies.beforeManifestValidation) {
    dependencies.beforeManifestValidation({
      manifestFile: firstManifestCheck.absolute,
      sourceManifest,
    });
  }
  let manifest;
  try {
    manifest = validateManifest(
      sourceManifest,
      firstManifestCheck.absolute,
      repositoryRoot,
    );
  } finally {
    if (dependencies.afterManifestValidation) {
      dependencies.afterManifestValidation({
        manifestFile: firstManifestCheck.absolute,
      });
    }
  }
  assertControl(
    manifest.source_manifest === manifestRelative,
    'CANARY_PLAN_MANIFEST_MISMATCH',
    'validated manifest path 与 --manifest 不一致',
  );

  const inputs = committedInputs(manifest);
  const inputCaptures = new Map();
  for (const [relative, label] of inputs) {
    inputCaptures.set(
      relative,
      assertCommittedOrdinaryFile(
        repositoryRoot,
        relative,
        label,
        initialHead,
      ),
    );
  }
  assertControl(
    inputCaptures.get(manifestRelative).sha256 === firstManifestCheck.sha256,
    'GOAL_INPUT_DIRTY',
    `manifest 在 canary-plan 计算期间发生变化: ${manifestRelative}`,
  );
  for (const [name, protocol] of Object.entries(manifest.protocol || {})) {
    assertControl(
      inputCaptures.get(protocol.path).sha256 === protocol.sha256,
      'GOAL_INPUT_DIRTY',
      `protocol.${name} hash 在 canary-plan 计算期间发生变化`,
    );
  }
  if (manifest.worker_canary_bootstrap) {
    assertControl(
      inputCaptures.get(manifest.worker_canary_bootstrap.policy.path).sha256
        === manifest.worker_canary_bootstrap.policy.sha256,
      'GOAL_INPUT_DIRTY',
      'worker_canary_bootstrap.policy hash 在 canary-plan 计算期间发生变化',
    );
  }
  for (const task of manifest.tasks) {
    assertControl(
      inputCaptures.get(task.packet.path).sha256 === task.packet.sha256,
      'GOAL_INPUT_DIRTY',
      `${task.id}.packet hash 在 canary-plan 计算期间发生变化`,
    );
    if (task.p1) {
      assertControl(
        inputCaptures.get(task.p1.authority.path).sha256
          === task.p1.authority.sha256,
        'GOAL_INPUT_DIRTY',
        `${task.id}.p1.authority hash 在 canary-plan 计算期间发生变化`,
      );
    }
  }
  assertControl(
    repositoryHead(repositoryRoot) === initialHead,
    'CANARY_PLAN_HEAD_MISMATCH',
    'repository HEAD 在 canary-plan 计算期间发生变化',
  );

  const selectedTask = taskId === null
    ? null
    : manifest.tasks.find((task) => task.id === taskId);
  if (taskId !== null) {
    assertControl(
      selectedTask,
      'CANARY_PLAN_UNKNOWN_TASK',
      `manifest 中不存在 task: ${taskId}`,
    );
  }
  const bootstrapArgumentsPresent = [
    options.workerBootstrapReceipt,
    options.workerBootstrapReceiptSha256,
    options.workerBootstrapOperationId,
    options.workerBootstrapChallenge,
    options.workerBootstrapIdentityPlanSha256,
    options.workerThread,
    options.workerHost,
  ].filter((value) => value !== null && value !== undefined).length;
  const captainBootstrapArgumentsPresent = [
    options.captainBootstrapReceipt,
    options.captainBootstrapReceiptSha256,
    options.captainBootstrapOperationId,
    options.captainBootstrapChallenge,
    options.captainBootstrapIdentityPlanSha256,
    options.captainThread,
    options.captainHost,
  ].filter((value) => value !== null && value !== undefined).length;
  assertControl(
    bootstrapArgumentsPresent === 0 || bootstrapArgumentsPresent === 7,
    'CANARY_BOOTSTRAP_ARGUMENT_MISMATCH',
    'worker bootstrap receipt/hash/operation/challenge/plan/thread/host 必须同时提供或同时省略',
  );
  assertControl(
    captainBootstrapArgumentsPresent === 0
      || captainBootstrapArgumentsPresent === 7,
    'CANARY_BOOTSTRAP_ARGUMENT_MISMATCH',
    'captain bootstrap receipt/hash/operation/challenge/plan/thread/host 必须同时提供或同时省略',
  );
  assertControl(
    captainBootstrapArgumentsPresent === 0 || role === 'CAPTAIN',
    'CANARY_BOOTSTRAP_ROLE_INVALID',
    'captain bootstrap receipt 只允许 CAPTAIN',
  );
  assertControl(
    !(bootstrapArgumentsPresent > 0
      && captainBootstrapArgumentsPresent > 0),
    'CANARY_BOOTSTRAP_ARGUMENT_MISMATCH',
    'worker 与 captain bootstrap binding 不得同时提供',
  );
  assertControl(
    bootstrapArgumentsPresent === 0
      || BOOTSTRAP_WORKER_ROLES.includes(role),
    'CANARY_BOOTSTRAP_ROLE_INVALID',
    'worker bootstrap receipt 只允许 DEV/REVIEW/RECEIPT',
  );
  const workerBootstrapProtocolEnabled =
    manifest.worker_canary_bootstrap !== undefined;
  if (workerBootstrapProtocolEnabled
    && BOOTSTRAP_WORKER_ROLES.includes(role)) {
    assertControl(
      bootstrapArgumentsPresent === 7,
      'CANARY_BOOTSTRAP_REQUIRED',
      'manifest 启用 worker canary bootstrap 后，worker role 必须提供 receipt/hash/operation/challenge/plan/thread/host',
    );
  } else {
    assertControl(
      bootstrapArgumentsPresent === 0,
      'WORKER_CANARY_BOOTSTRAP_PROTOCOL_UNSUPPORTED',
      '当前 manifest/role 不接受 worker canary bootstrap receipt',
    );
  }
  const captainBootstrapProtocolEnabled =
    manifest.captain_canary_bootstrap !== undefined;
  if (captainBootstrapProtocolEnabled && role === 'CAPTAIN') {
    assertControl(
      captainBootstrapArgumentsPresent === 7,
      'CANARY_BOOTSTRAP_REQUIRED',
      'manifest 启用 captain canary bootstrap 后，CAPTAIN 必须提供 receipt/hash/operation/challenge/plan/thread/host',
    );
  } else {
    assertControl(
      captainBootstrapArgumentsPresent === 0,
      'CAPTAIN_CANARY_BOOTSTRAP_PROTOCOL_UNSUPPORTED',
      '当前 manifest/role 不接受 captain canary bootstrap receipt',
    );
  }
  const workerBootstrapValidation = bootstrapArgumentsPresent === 0
    ? null
    : {
      receiptFile: options.workerBootstrapReceipt,
      expectedReceiptSha256:
        options.workerBootstrapReceiptSha256,
      expectedOperationId: options.workerBootstrapOperationId,
      expectedChallenge: options.workerBootstrapChallenge,
      expectedIdentityPlanSha256:
        options.workerBootstrapIdentityPlanSha256,
      workerThread: options.workerThread,
      workerHost: options.workerHost,
      invocationCwd,
      controller: controllerCapture.provenance,
      repositoryRoot,
      repositoryHead: initialHead,
      manifestPath: manifestRelative,
      manifestSha256: firstManifestCheck.sha256,
      validatedManifestSha256: manifest.manifest_sha256,
      repositoryNameWithOwner:
        manifest.repository.name_with_owner,
      baseBranch: manifest.repository.base_branch,
      goalId: manifest.goal_id,
      taskId,
      role,
      canaryPolicy: manifest.worker_canary_bootstrap.policy,
    };
  const workerBootstrap = workerBootstrapValidation === null
    ? null
    : validateWorkerBootstrapReceipt(workerBootstrapValidation);
  const captainBootstrapValidation =
    captainBootstrapArgumentsPresent === 0
      ? null
      : {
        receiptFile: options.captainBootstrapReceipt,
        expectedReceiptSha256:
          options.captainBootstrapReceiptSha256,
        expectedOperationId: options.captainBootstrapOperationId,
        expectedChallenge: options.captainBootstrapChallenge,
        expectedIdentityPlanSha256:
          options.captainBootstrapIdentityPlanSha256,
        workerThread: options.captainThread,
        workerHost: options.captainHost,
        invocationCwd,
        controller: controllerCapture.provenance,
        repositoryRoot,
        repositoryHead: initialHead,
        manifestPath: manifestRelative,
        manifestSha256: firstManifestCheck.sha256,
        validatedManifestSha256: manifest.manifest_sha256,
        repositoryNameWithOwner:
          manifest.repository.name_with_owner,
        baseBranch: manifest.repository.base_branch,
        goalId: manifest.goal_id,
        taskId,
        role,
        canaryPolicy: manifest.captain_canary_bootstrap.policy,
        requiredStartHeadProof:
          loadCaptainRequiredStartHeadProof(
            repositoryRoot,
            manifest,
            selectedTask,
          ),
      };
  const captainBootstrap = captainBootstrapValidation === null
    ? null
    : validateCaptainBootstrapReceipt(
      captainBootstrapValidation,
    );
  const matches = browserRequirements(manifest, role, selectedTask);
  const browserRequired = matches.length > 0;
  const browserBinding = {
    goal_id: manifest.goal_id,
    role,
    task_id: taskId,
  };
  const browserTarget = browserCanaryTarget(
    browserRequired,
    options.browserCanaryReceipt,
    browserBinding,
    controllerCapture.provenance,
    dependencies,
  );
  const canaryPolicy = canaryPolicyContract(
    manifest,
    inputCaptures,
    role,
  );
  const requiredProbes = orderedRequiredProbes(role, browserRequired);
  for (const [relative, label] of inputs) {
    const finalInput = assertCommittedOrdinaryFile(
      repositoryRoot,
      relative,
      label,
      initialHead,
    );
    assertControl(
      finalInput.sha256 === inputCaptures.get(relative).sha256
        && sameStatIdentity(
          finalInput.identity,
          inputCaptures.get(relative).identity,
        ),
      'GOAL_INPUT_RACE',
      `${label} 在 canary-plan 计算期间发生变化: ${relative}`,
    );
  }
  assertControl(
    repositoryHead(repositoryRoot) === initialHead,
    'CANARY_PLAN_HEAD_MISMATCH',
    'repository HEAD 在 canary-plan 输出前发生变化',
  );
  assertNoReplaceRefs(repositoryRoot);
  if (browserTarget.capture) {
    const finalBrowserTarget = browserCanaryTarget(
      true,
      options.browserCanaryReceipt,
      browserBinding,
      controllerCapture.provenance,
      dependencies,
    );
    assertControl(
      hashObject(finalBrowserTarget.target) === hashObject(browserTarget.target)
        && sameStatIdentity(
          finalBrowserTarget.capture.identity,
          browserTarget.capture.identity,
        ),
      'GOAL_INPUT_RACE',
      'browser canary receipt 在 plan 计算期间变化',
    );
  }
  if (workerBootstrapValidation !== null) {
    const finalWorkerBootstrap = validateWorkerBootstrapReceipt(
      workerBootstrapValidation,
    );
    assertControl(
      hashObject(finalWorkerBootstrap) === hashObject(workerBootstrap),
      'CANARY_BOOTSTRAP_RECEIPT_BINDING_MISMATCH',
      'worker bootstrap receipt/live worktree 在 plan 计算期间漂移',
    );
  }
  if (captainBootstrapValidation !== null) {
    const finalCaptainBootstrap = validateCaptainBootstrapReceipt(
      captainBootstrapValidation,
    );
    assertControl(
      hashObject(finalCaptainBootstrap)
        === hashObject(captainBootstrap),
      'CANARY_BOOTSTRAP_RECEIPT_BINDING_MISMATCH',
      'captain bootstrap receipt/live worktree 在 plan 计算期间漂移',
    );
  }
  assertControllerProvenanceStable(controllerCapture);
  const replayArgv = [
    controllerCapture.provenance.entrypoint,
    'canary-plan',
    '--repository-worktree',
    repositoryRoot,
    '--manifest',
    manifestRelative,
    '--role',
    role,
    ...(taskId === null ? [] : ['--task', taskId]),
    ...(
      browserTarget.target === null
        ? []
        : [
          '--browser-canary-receipt',
          browserTarget.target.receipt.path,
        ]
    ),
    ...(
      workerBootstrap === null
        ? []
        : [
          '--worker-bootstrap-receipt',
          workerBootstrap.receipt_file,
          '--worker-bootstrap-receipt-sha256',
          workerBootstrap.receipt_sha256,
          '--worker-bootstrap-operation-id',
          workerBootstrap.operation_id,
          '--worker-bootstrap-challenge',
          workerBootstrap.challenge,
          '--worker-bootstrap-identity-plan-sha256',
          workerBootstrap.identity_plan_sha256,
          '--worker-thread',
          workerBootstrap.thread,
          '--worker-host',
          workerBootstrap.host,
        ]
    ),
    ...(
      captainBootstrap === null
        ? []
        : [
          '--captain-bootstrap-receipt',
          captainBootstrap.receipt_file,
          '--captain-bootstrap-receipt-sha256',
          captainBootstrap.receipt_sha256,
          '--captain-bootstrap-operation-id',
          captainBootstrap.operation_id,
          '--captain-bootstrap-challenge',
          captainBootstrap.challenge,
          '--captain-bootstrap-identity-plan-sha256',
          captainBootstrap.identity_plan_sha256,
          '--captain-thread',
          captainBootstrap.thread,
          '--captain-host',
          captainBootstrap.host,
        ]
    ),
    '--json',
  ];
  const replayNodeExecutable = fs.realpathSync(process.execPath);
  const replayEnvironment = replayEnvironmentContract();
  const replayShell = replayShellCommand(
    replayEnvironment,
    replayNodeExecutable,
    replayArgv,
  );
  const plan = {
    schema_version: 1,
    controller: controllerCapture.provenance,
    repository_worktree: repositoryRoot,
    repository_head: initialHead,
    repository: {
      name_with_owner: manifest.repository.name_with_owner,
      base_branch: manifest.repository.base_branch,
    },
    capability_targets: {
      github_app: {
        repository: manifest.repository.name_with_owner,
        pull_request: null,
        pre_registration_scope: 'REPOSITORY_ONLY',
        operation_contract: {
          schema_version: 1,
          capability_plane: 'GITHUB_APP_CONNECTOR',
          semantic_operation: 'REPOSITORY_METADATA_READ',
          target_kind: 'REPOSITORY',
          repository: manifest.repository.name_with_owner,
          read_only: true,
          interaction: 'NON_INTERACTIVE',
          success_repository_identity_must_equal: true,
          forbidden_substitute_operations: [
            'COMMIT_READ',
            'PULL_REQUEST_READ',
            'FILE_READ',
            'ISSUE_READ',
          ],
        },
      },
    },
    replay: {
      node_executable: replayNodeExecutable,
      argv: replayArgv,
      environment: replayEnvironment,
      shell_command: replayShell,
    },
    manifest: {
      path: manifestRelative,
      sha256: firstManifestCheck.sha256,
      validated_manifest_sha256: manifest.manifest_sha256,
    },
    goal_id: manifest.goal_id,
    role,
    task_id: taskId,
    worker_bootstrap: workerBootstrap,
    captain_bootstrap: captainBootstrap,
    canary_policy: canaryPolicy,
    probe_bindings: {
      git_push_dry_run: (
        role === 'DEV' && workerBootstrap !== null
          ? {
            remote: 'origin',
            source: 'HEAD',
            destination: `refs/heads/${workerBootstrap.branch}`,
            argv_suffix: [
              '--dry-run',
              '--no-verify',
              'origin',
              `HEAD:refs/heads/${workerBootstrap.branch}`,
            ],
            remote_refs_must_remain_unchanged: true,
          }
          : null
      ),
    },
    required_probes: requiredProbes,
    probe_evaluation: probeEvaluationContract(
      manifest.repository.name_with_owner,
      requiredProbes,
      canaryPolicy,
    ),
    browser: {
      decision: browserRequired ? 'REQUIRED' : 'NOT_REQUIRED',
      trigger_kinds: ['BROWSER_PROFILE', 'WINDOW'],
      matched_requirements: matches.map(publicRequirement),
      target: browserTarget.target,
    },
  };
  return {
    canary_plan: plan,
    canary_plan_sha256: hashObject(plan),
  };
}

module.exports = {
  BROWSER_PROBE,
  CANARY_ROLES,
  ROLE_PROBES,
  TASK_SCOPED_ROLES,
  assertControllerWorktreeClean,
  canaryPolicyKnownLimitations,
  canaryPlan,
};
