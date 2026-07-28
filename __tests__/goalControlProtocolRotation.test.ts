import {
  chmodSync,
  cpSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { execFileSync, spawn, spawnSync } from "child_process";
import { createRequire } from "module";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";

const nodeRequire = createRequire(import.meta.url);
const {
  canonicalTransactionKey,
  controllerDecoderFingerprint,
  controllerDecoderFingerprintAt,
  readRootProtocolSeal,
  rotateRootProtocol,
} = nodeRequire("../scripts/goal-control/store.js") as {
  canonicalTransactionKey: (
    kind: string,
    scope: Record<string, string>,
    stableId: string,
    requestHash: string,
  ) => TransactionKey;
  controllerDecoderFingerprint: () => string;
  controllerDecoderFingerprintAt: (decoderDirectory: string) => string;
  readRootProtocolSeal: (root: string) => RootProtocol | null;
  rotateRootProtocol: (
    root: string,
    validator: (context: {
      root: string;
      source_state_vector_sha256: string;
      target_decoder_sha256: string;
      predecessor_protocol: RootProtocol;
      current_protocol: RootProtocol;
    }) => { report: RotationReport },
    request: RotationRequest,
    options?: {
      staleMilliseconds?: number;
      timeoutMilliseconds?: number;
      afterRotationGenerationStarted?: () => void;
      afterRotationReceiptInstalled?: () => void;
      afterRotationProtocolInstalled?: () => void;
      beforeRotationGenerationComplete?: () => void;
    },
  ) => {
    rotated: boolean;
    idempotent: boolean;
    predecessor_protocol: Record<string, unknown>;
    protocol: RootProtocol;
    entry_generation: number;
    exit_generation: number;
    source_state_vector_sha256: string;
    sealed_state_vector_sha256: string;
    rotation_receipt: RotationDescriptor;
    validation: RotationReport;
  };
};
const {
  canonicalJson,
  hashObject,
  sha256,
} = nodeRequire("../scripts/goal-control/util.js") as {
  canonicalJson: (value: unknown) => string;
  hashObject: (value: unknown) => string;
  sha256: (value: string | Buffer) => string;
};
const {
  collectLegacySemanticEvidenceSources,
  createLegacyEvidenceMigrationCollector,
  sealLegacyEvidenceAnchorIndex,
} = nodeRequire("../scripts/goal-control/evidence.js") as {
  collectLegacySemanticEvidenceSources: (
    root: string,
    collector: {
      eventBindings: Map<string, unknown>;
      semanticSources: Map<string, unknown>;
    },
  ) => unknown;
  createLegacyEvidenceMigrationCollector: () => {
    eventBindings: Map<string, unknown>;
    semanticSources: Map<string, unknown>;
  };
  sealLegacyEvidenceAnchorIndex: (
    entries: {
      eventBindings: Map<string, unknown>;
      semanticSources: Map<string, unknown>;
    },
    options: Record<string, unknown>,
  ) => {
    index: Record<string, unknown> & {
      semantic_sources: Record<string, Record<string, unknown>>;
      migration_receipt: {
        goal_worktree_map: Record<string, unknown>;
      };
      index_sha256: string;
    };
    migration_artifact: {
      relative_path: string;
      sha256: string;
      body: string | Buffer;
    };
    migration_artifacts: Array<{
      relative_path: string;
      sha256: string;
      body: string | Buffer;
    }>;
  };
};
const {
  assertSuccessorCompatibleActiveDevLaunches,
} = nodeRequire("../scripts/goal-control/migration.js") as {
  assertSuccessorCompatibleActiveDevLaunches: (
    root: string,
    loaded: {
      manifest: {
        goal_id: string;
        tasks: Array<{ id: string }>;
      };
      snapshot: {
        tasks: Record<string, {
          sessions: {
            DEV?: {
              status: string;
              launch_id: string;
              thread_id: string;
              host_id: string;
            };
          };
        }>;
      };
    },
  ) => void;
};
const {
  inspectSourceCheckpointHold,
  loadGoalStateUnlocked,
} = nodeRequire("../scripts/goal-control/goal.js") as {
  inspectSourceCheckpointHold: (
    paths: Record<string, string>,
    state: Record<string, unknown>,
    goalId: string,
    task: Record<string, unknown>,
  ) => Record<string, unknown> | null;
  loadGoalStateUnlocked: (
    root: string,
    goalId: string,
    options?: Record<string, unknown>,
  ) => {
    paths: Record<string, string>;
    manifest: {
      goal_id: string;
      tasks: Array<Record<string, unknown> & { id: string }>;
    };
    snapshot: { tasks: Record<string, Record<string, unknown>> };
  };
};
const {
  parentCandidateHeadBinding,
  validateLegacyIdentityIncidentReceipt,
} = nodeRequire(
  "../scripts/goal-control/launch-source-checkpoint.js",
) as {
  parentCandidateHeadBinding: (
    parent: Record<string, unknown>,
    candidate: Record<string, unknown>,
    failed: Array<Record<string, unknown>>,
    canonical: Record<string, unknown>,
  ) => boolean;
  validateLegacyIdentityIncidentReceipt: (
    receipt: Record<string, unknown>,
    options?: { root?: string },
  ) => Record<string, unknown>;
};

type TransactionKey = {
  schema_version: 1;
  kind: string;
  scope: Record<string, string>;
  stable_operation_id_sha256: string;
  request_sha256: string;
  key_sha256: string;
};

type MigrationDescriptor = {
  relative_path: string;
  sha256: string;
};

type RotationDescriptor = {
  relative_path: string;
  sha256: string;
};

type RootProtocol = {
  schema_version: number;
  controller_decoder_version: number;
  controller_decoder_sha256: string;
  lock_protocol_version: number;
  migration_source_state_vector_sha256: string | null;
  migration_artifacts: MigrationDescriptor[];
  protocol_rotations?: RotationDescriptor[];
  seal_sha256: string;
};

type RotationRequest = {
  rotationId: string;
  incidentRef: string;
  oldControllerDrainAcknowledgment:
    "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED";
  expectedPredecessorSealSha256: string;
  operatorRequestSha256: string;
};

type RotationReport = {
  schema_version: 1;
  goal_worktree_map: Record<string, {
    repository_worktree: string;
    head_sha256: string;
  }>;
  replay: {
    predecessor: "PASS";
    successor: "PASS";
  };
  oversized_evidence?: string;
};

type RotationReceipt = {
  schema_version: number;
  rotation_id: string;
  requested_at: string;
  incident_ref: string;
  old_controller_drain_ack: string;
  predecessor_protocol: {
    schema_version: number;
    controller_decoder_version: number;
    controller_decoder_sha256: string;
    lock_protocol_version: number;
    seal_sha256: string;
  };
  successor_protocol: {
    schema_version: number;
    controller_decoder_version: number;
    controller_decoder_sha256: string;
    lock_protocol_version: number;
  };
  migration_artifacts_sha256: string;
  source_state_vector_sha256: string;
  validation_report: RotationReport;
  validation_report_sha256: string;
  goal_worktree_map: RotationReport["goal_worktree_map"];
  goal_worktree_map_sha256: string;
  entry_generation: number;
  exit_generation: number;
  operator_request_sha256: string;
  request_sha256: string;
  receipt_sha256: string;
};

const sandboxes: string[] = [];

function sandbox(): string {
  const root = mkdtempSync(path.join(tmpdir(), "goal-control-protocol-rotation-"));
  sandboxes.push(root);
  return root;
}

function writeSealedJson(
  file: string,
  unsigned: Record<string, unknown>,
): void {
  writeFileSync(
    file,
    `${JSON.stringify({
      ...unsigned,
      seal_sha256: hashObject(unsigned),
    }, null, 2)}\n`,
  );
}

function createSchema2Predecessor(root: string): {
  protocol: RootProtocol;
  artifact: string;
} {
  mkdirSync(root, { recursive: true });
  const artifact = path.join(root, ".legacy-evidence-anchors.v1.json");
  const artifactBody = Buffer.from(
    "{\"kind\":\"LEGACY_EVIDENCE_EVENT_BINDINGS\",\"version\":1}\n",
  );
  writeFileSync(artifact, artifactBody);
  chmodSync(artifact, 0o640);
  const artifactDescriptor = {
    relative_path: ".legacy-evidence-anchors.v1.json",
    sha256: `sha256:${sha256(artifactBody)}`,
  };
  const unsigned = {
    schema_version: 2,
    controller_decoder_version: 2,
    controller_decoder_sha256:
      hashObject({ decoder: "sealed-schema-2-predecessor" }),
    lock_protocol_version: 2,
    migration_source_state_vector_sha256:
      hashObject({ source: "legacy-migration-input" }),
    migration_artifacts: [artifactDescriptor],
  };
  const protocol = {
    ...unsigned,
    seal_sha256: hashObject(unsigned),
  };
  writeFileSync(
    path.join(root, ".store-protocol.json"),
    `${JSON.stringify(protocol, null, 2)}\n`,
    { mode: 0o600 },
  );
  expect(readRootProtocolSeal(root)).toEqual(protocol);
  return { protocol, artifact };
}

function createSchema3Predecessor(root: string): {
  protocol: RootProtocol;
  artifact: string;
} {
  const { protocol: legacyProtocol, artifact } =
    createSchema2Predecessor(root);
  const unsigned = {
    schema_version: 3,
    controller_decoder_version: 3,
    controller_decoder_sha256:
      hashObject({ decoder: "sealed-schema-3-predecessor" }),
    lock_protocol_version: 2,
    migration_source_state_vector_sha256:
      legacyProtocol.migration_source_state_vector_sha256,
    migration_artifacts: legacyProtocol.migration_artifacts,
    protocol_rotations: [],
  };
  const protocol = {
    ...unsigned,
    seal_sha256: hashObject(unsigned),
  };
  writeFileSync(
    path.join(root, ".store-protocol.json"),
    `${JSON.stringify(protocol, null, 2)}\n`,
    { mode: 0o600 },
  );
  expect(readRootProtocolSeal(root)).toEqual(protocol);
  return { protocol, artifact };
}

function requestFor(protocol: RootProtocol): RotationRequest {
  return {
    rotationId: "rotate-schema-2-to-3-20260725",
    incidentRef: "incident://goal-control/schema2-decoder-rollout",
    oldControllerDrainAcknowledgment:
      "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
    expectedPredecessorSealSha256: protocol.seal_sha256,
    operatorRequestSha256:
      hashObject({ operator_request: "audited-schema-3-rollout" }),
  };
}

function validationReport(root: string): RotationReport {
  return {
    schema_version: 1,
    goal_worktree_map: {
      "goal-existing": {
        repository_worktree: path.join(root, "frozen-goal-input"),
        head_sha256: hashObject({ head: "existing" }),
      },
      "goal-continuous-trial": {
        repository_worktree: path.join(root, "continuous-goal-input"),
        head_sha256: hashObject({ head: "continuous" }),
      },
    },
    replay: {
      predecessor: "PASS",
      successor: "PASS",
    },
  };
}

function validatorFor(root: string): () => { report: RotationReport } {
  return () => ({ report: validationReport(root) });
}

function artifactIdentity(file: string): {
  inode: number;
  mode: number;
  bytes: Buffer;
} {
  const stat = lstatSync(file);
  return {
    inode: stat.ino,
    mode: stat.mode & 0o7777,
    bytes: readFileSync(file),
  };
}

function payloadTree(root: string): Array<[string, string, string]> {
  const entries: Array<[string, string, string]> = [];
  const visit = (directory: string, relativeDirectory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      if (!relativeDirectory && (
        name === ".lock" || name.startsWith(".lock.")
      )) {
        continue;
      }
      const relative = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      const absolute = path.join(directory, name);
      const stat = lstatSync(absolute);
      const mode = (stat.mode & 0o7777).toString(8);
      if (stat.isDirectory()) {
        entries.push(["directory", relative, mode]);
        visit(absolute, relative);
      } else {
        entries.push([
          "file",
          relative,
          `${mode}:${readFileSync(absolute).toString("base64")}`,
        ]);
      }
    }
  };
  visit(root, "");
  return entries;
}

function writeOddGeneration(
  root: string,
  transaction: TransactionKey,
): void {
  const unsigned = {
    schema_version: 3,
    generation: 1,
    active_transaction: transaction,
    pre_write_vector_sha256:
      hashObject({ pristine_payload: transaction.key_sha256 }),
    updated_at: "2026-07-25T00:00:00.000Z",
  };
  writeSealedJson(path.join(root, ".generation.json"), unsigned);
}

function expectTransportClean(root: string): void {
  expect(readdirSync(root).filter((name) => (
    name === ".lock" || name.startsWith(".lock.")
  ))).toEqual([]);
  const atomicTransport = path.join(root, ".atomic-transactions");
  if (existsSync(atomicTransport)) {
    expect(readdirSync(atomicTransport)).toEqual([]);
  }
}

function installForeignRequestWriterArtifact(
  root: string,
  sourceBacking: string,
): {
  artifact: string;
  bytes: Buffer;
  nonce: string;
} {
  const ownerFile = path.join(sourceBacking, "owner.json");
  const owner = JSON.parse(readFileSync(ownerFile, "utf8")) as
    Record<string, unknown>;
  const sourceNonce = String(owner.nonce);
  const sourcePrefix = sourceNonce.match(
    /^writer-rotation-([0-9a-f]{20})-attempt-[0-9a-f]{24}$/,
  )?.[1];
  if (!sourcePrefix) {
    throw new Error("source writer nonce is not request-bound");
  }
  const foreignPrefix = sourcePrefix === "0".repeat(20)
    ? "1".repeat(20)
    : "0".repeat(20);
  const nonce =
    `writer-rotation-${foreignPrefix}-attempt-${"f".repeat(24)}`;
  const unsigned: Record<string, unknown> = {
    ...owner,
    nonce,
  };
  delete unsigned.owner_sha256;
  const sealed = {
    ...unsigned,
    owner_sha256: hashObject(unsigned),
  };
  const artifact = path.join(root, `.lock.owner.${nonce}`);
  mkdirSync(artifact, { mode: 0o700 });
  const bytes = Buffer.from(`${JSON.stringify(sealed, null, 2)}\n`);
  writeFileSync(path.join(artifact, "owner.json"), bytes, {
    mode: 0o600,
  });
  return { artifact, bytes, nonce };
}

function withGoalControlTestMode<T>(callback: () => T): T {
  const previous = process.env.GOAL_CONTROL_TEST_MODE;
  process.env.GOAL_CONTROL_TEST_MODE = "1";
  try {
    return callback();
  } finally {
    if (previous === undefined) {
      delete process.env.GOAL_CONTROL_TEST_MODE;
    } else {
      process.env.GOAL_CONTROL_TEST_MODE = previous;
    }
  }
}

const storeModulePath = nodeRequire.resolve(
  "../scripts/goal-control/store.js",
);
const successorSourceRoot = path.resolve(
  path.dirname(storeModulePath),
  "..",
  "..",
);

type CliResult = {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
};

type PendingBootstrapRotationFixture = {
  repository: string;
  controlRoot: string;
  goalctl: string;
  predecessorWorktree: string;
  predecessorProtocol: RootProtocol;
  goalIds: string[];
  primaryGoalId: string;
  primaryTaskId: string;
  foremanThreadId: string;
  foremanCapability: string;
  bootstrapCapability: string;
  bootstrapCapabilityBytes: Buffer;
  goalMetadata: string;
};

type RotationFixtureOptions = {
  pendingBootstrapRepair?: boolean;
  hangingPredecessorProbe?: boolean;
  hangingPredecessorReplay?: boolean;
  predecessorValidatesAllPreflightRegistries?: boolean;
  additionalGoal?: boolean;
  historicalGoalMapSubset?: boolean;
  markerlessIdentityIncidentPredecessor?: boolean;
  sourceOnlyIdentityIncidentPredecessor?: boolean;
  invalidIdentityIncidentMarkerPredecessor?: boolean;
  emptyIdentityIncidentChecksPredecessor?: boolean;
};

function fixtureGit(cwd: string, ...args: string[]): string {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} failed: ${result.stderr || result.stdout}`,
    );
  }
  return result.stdout.trim();
}

function runFixtureGoalctl(
  goalctl: string,
  cwd: string,
  controlRoot: string,
  args: string[],
  extraEnvironment: Record<string, string | undefined> = {},
): CliResult {
  const result = spawnSync(
    process.execPath,
    [goalctl, ...args],
    {
      cwd,
      encoding: "utf8",
      env: {
        ...process.env,
        GOAL_CONTROL_DIR: controlRoot,
        GOAL_CONTROL_TEST_MODE: "1",
        ...extraEnvironment,
      },
      maxBuffer: 32 * 1024 * 1024,
    },
  );
  return {
    status: result.status,
    signal: result.signal,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function writeFixtureJson(file: string, value: unknown): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, {
    mode: path.basename(file) === ".store-protocol.json"
      ? 0o600
      : 0o644,
  });
  if (path.basename(file) === ".store-protocol.json") {
    chmodSync(file, 0o600);
  }
}

function installFixtureController(
  repository: string,
  legacySchema2: boolean,
): void {
  const targetScripts = path.join(repository, "scripts");
  const targetDecoder = path.join(targetScripts, "goal-control");
  rmSync(targetDecoder, { recursive: true, force: true });
  mkdirSync(targetScripts, { recursive: true });
  cpSync(
    path.join(successorSourceRoot, "scripts", "goal-control"),
    targetDecoder,
    { recursive: true },
  );
  cpSync(
    path.join(successorSourceRoot, "scripts", "goalctl.js"),
    path.join(targetScripts, "goalctl.js"),
  );
  if (legacySchema2) {
    const storeFile = path.join(targetDecoder, "store.js");
    const source = readFileSync(storeFile, "utf8");
    const transformed = source.replace(
      "const ROOT_PROTOCOL_SCHEMA_VERSION = 3;",
      "const ROOT_PROTOCOL_SCHEMA_VERSION = 2;",
    ).replace(
      "const CONTROLLER_DECODER_VERSION = 3;",
      "const CONTROLLER_DECODER_VERSION = 2;",
    );
    expect(transformed).not.toBe(source);
    writeFileSync(storeFile, transformed);
  }
}

function createIndependentControllerRepository(
  parent: string,
  name: string,
  decoderMarker: string | null = null,
): {
  repository: string;
  goalctl: string;
  commonDir: string;
  head: string;
  decoderSha256: string;
} {
  const repository = path.join(parent, name);
  mkdirSync(repository, { recursive: true });
  fixtureGit(repository, "init", "-q", "-b", "main");
  fixtureGit(
    repository,
    "config",
    "user.email",
    `${name}@example.test`,
  );
  fixtureGit(
    repository,
    "config",
    "user.name",
    "Independent Controller Test",
  );
  installFixtureController(repository, false);
  if (decoderMarker !== null) {
    const decoderFile = path.join(
      repository,
      "scripts",
      "goal-control",
      "validation.js",
    );
    writeFileSync(
      decoderFile,
      `${readFileSync(decoderFile, "utf8")}\n// ${decoderMarker}\n`,
    );
  }
  writeFileSync(
    path.join(repository, "README.md"),
    `# ${name}\n`,
  );
  fixtureGit(repository, "add", ".");
  fixtureGit(
    repository,
    "commit",
    "-qm",
    `install ${name}`,
  );
  const decoderDirectory = path.join(
    repository,
    "scripts",
    "goal-control",
  );
  return {
    repository: realpathSync(repository),
    goalctl: path.join(repository, "scripts", "goalctl.js"),
    commonDir: realpathSync(fixtureGit(
      repository,
      "rev-parse",
      "--path-format=absolute",
      "--git-common-dir",
    )),
    head: fixtureGit(repository, "rev-parse", "HEAD"),
    decoderSha256:
      controllerDecoderFingerprintAt(decoderDirectory),
  };
}

function createPendingBootstrapRotationFixture(
  options: RotationFixtureOptions = {},
):
PendingBootstrapRotationFixture {
  const pendingBootstrapRepair =
    options.pendingBootstrapRepair ?? true;
  const primaryGoalId = "goal-bootstrap-pending";
  const primaryTaskId = "TASK-A";
  const foremanThreadId = "foreman-bootstrap-pending";
  const root = realpathSync(sandbox());
  const repository = path.join(root, "repository");
  const controlRoot = path.join(root, "control");
  const predecessorWorktree = path.join(
    root,
    "predecessor-controller",
  );
  mkdirSync(repository, { recursive: true });
  mkdirSync(controlRoot, { recursive: true });
  const identityIncidentFixture =
    options.markerlessIdentityIncidentPredecessor === true
    || options.sourceOnlyIdentityIncidentPredecessor === true
    || options.invalidIdentityIncidentMarkerPredecessor === true;
  expect(
    options.markerlessIdentityIncidentPredecessor === true
      && options.invalidIdentityIncidentMarkerPredecessor === true,
  ).toBe(false);
  fixtureGit(repository, "init", "-q", "-b", "main");
  fixtureGit(
    repository,
    "config",
    "user.email",
    "protocol-rotation@example.test",
  );
  fixtureGit(
    repository,
    "config",
    "user.name",
    "Protocol Rotation Test",
  );
  if (identityIncidentFixture) {
    fixtureGit(
      repository,
      "remote",
      "add",
      "origin",
      "https://github.com/example-org/example-repo.git",
    );
  }
  installFixtureController(repository, true);
  if (options.markerlessIdentityIncidentPredecessor === true) {
    const predecessorGoal = path.join(
      repository,
      "scripts",
      "goal-control",
      "goal.js",
    );
    const source = readFileSync(predecessorGoal, "utf8");
    const markerBlock = [
      "      if (preparedIdentityIncident) {",
      "        event.prepared_identity_incident_authority = {",
    ].join("\n");
    expect(source.split(markerBlock)).toHaveLength(2);
    const transformed = source.replace(
      markerBlock,
      [
        "      if (false && preparedIdentityIncident) {",
        "        event.prepared_identity_incident_authority = {",
      ].join("\n"),
    );
    expect(transformed).not.toBe(source);
    writeFileSync(predecessorGoal, transformed);
  }
  if (options.invalidIdentityIncidentMarkerPredecessor === true) {
    const predecessorGoal = path.join(
      repository,
      "scripts",
      "goal-control",
      "goal.js",
    );
    const source = readFileSync(predecessorGoal, "utf8");
    const markerLine =
      "          authority_sha256: preparedIdentityIncident.authoritySha256,";
    expect(source.split(markerLine)).toHaveLength(2);
    const transformed = source.replace(
      markerLine,
      "          authority_sha256: `sha256:${'0'.repeat(64)}`,",
    );
    expect(transformed).not.toBe(source);
    writeFileSync(predecessorGoal, transformed);
  }
  if (options.emptyIdentityIncidentChecksPredecessor === true) {
    const predecessorPreflight = path.join(
      repository,
      "scripts",
      "goal-control",
      "preflight.js",
    );
    const source = readFileSync(predecessorPreflight, "utf8");
    expect(source.match(/checks: failures,/g)).toHaveLength(2);
    const transformed = source.replace(
      /checks: failures,/g,
      "checks: [],",
    );
    expect(transformed).not.toBe(source);
    writeFileSync(predecessorPreflight, transformed);
  }
  if (options.sourceOnlyIdentityIncidentPredecessor === true) {
    const predecessorPreflight = path.join(
      repository,
      "scripts",
      "goal-control",
      "preflight.js",
    );
    const source = readFileSync(predecessorPreflight, "utf8");
    const sourceCheckpointDefault =
      "    allowSourceCheckpoint = true,";
    expect(source.split(sourceCheckpointDefault)).toHaveLength(2);
    const transformed = source.replace(
      sourceCheckpointDefault,
      "    allowSourceCheckpoint = false,",
    );
    expect(transformed).not.toBe(source);
    writeFileSync(predecessorPreflight, transformed);
  }
  if (identityIncidentFixture) {
    writeFileSync(
      path.join(repository, "pnpm-lock.yaml"),
      "lockfileVersion: '9.0'\n",
    );
  }
  if (options.hangingPredecessorProbe === true) {
    const predecessorStore = path.join(
      repository,
      "scripts",
      "goal-control",
      "store.js",
    );
    writeFileSync(
      predecessorStore,
      `${readFileSync(predecessorStore, "utf8")}
if (process.env.GOAL_CONTROL_TEST_HANG_PREDECESSOR_PROBE === '1') {
  while (true) {
    // Deliberate isolated-test hang; the successor must SIGKILL us.
  }
}
`,
    );
  }
  if (options.hangingPredecessorReplay === true) {
    const predecessorGoal = path.join(
      repository,
      "scripts",
      "goal-control",
      "goal.js",
    );
    writeFileSync(
      predecessorGoal,
      `${readFileSync(predecessorGoal, "utf8")}
if (process.env.GOAL_CONTROL_TEST_HANG_PREDECESSOR_REPLAY === '1') {
  while (true) {
    // Deliberate isolated-test hang; the successor must SIGKILL us.
  }
}
`,
    );
  }
  if (options.predecessorValidatesAllPreflightRegistries === true) {
    const predecessorGoal = path.join(
      repository,
      "scripts",
      "goal-control",
      "goal.js",
    );
    writeFileSync(
      predecessorGoal,
      `${readFileSync(predecessorGoal, "utf8")}
const compatibilityFs = require('fs');
const compatibilityPath = require('path');
const compatibilityUrl = require('url');
const compatibilityUtil = require('./util');
const compatibilityOriginalLoadGoalStateUnlocked =
  module.exports.loadGoalStateUnlocked;
module.exports.loadGoalStateUnlocked = function compatibilityReplayLoad(
  root,
  goalId,
  options,
) {
  const loaded = compatibilityOriginalLoadGoalStateUnlocked(
    root,
    goalId,
    options,
  );
  const handoffCanaryFile = compatibilityPath.join(
    root,
    'goals',
    goalId,
    '.absolute-handoff-canary.json',
  );
  if (compatibilityFs.existsSync(handoffCanaryFile)) {
    const handoffCanary = JSON.parse(
      compatibilityFs.readFileSync(handoffCanaryFile, 'utf8'),
    );
    if (
      root !== handoffCanary.control_root
        || !compatibilityPath.isAbsolute(handoffCanary.receipt_path)
        || compatibilityPath.resolve(handoffCanary.receipt_path)
          !== handoffCanary.receipt_path
        || compatibilityUtil.hashFile(handoffCanary.receipt_path)
          !== handoffCanary.receipt_sha256
    ) {
      throw new Error(
        'HANDOFF_ARTIFACT_INVALID absolute import receipt path drift',
      );
    }
  }
  const evidenceRoot = compatibilityPath.join(
    root,
    'goals',
    goalId,
    'evidence',
  );
  if (!compatibilityFs.existsSync(evidenceRoot)) return loaded;
  for (const taskId of compatibilityFs.readdirSync(evidenceRoot)) {
    const taskDirectory = compatibilityPath.join(evidenceRoot, taskId);
    for (const name of compatibilityFs.readdirSync(taskDirectory)) {
      if (!name.endsWith('.json')) continue;
      const registryFile = compatibilityPath.join(taskDirectory, name);
      const record = JSON.parse(
        compatibilityFs.readFileSync(registryFile, 'utf8'),
      );
      if (record.kind !== 'PREFLIGHT') continue;
      const unsigned = { ...record };
      delete unsigned.registry_sha256;
      if (compatibilityUtil.hashObject(unsigned) !== record.registry_sha256) {
        throw new Error(
          'predecessor compatibility registry seal mismatch',
        );
      }
      const launchFile = compatibilityUrl.fileURLToPath(
        new URL(record.launch_uri),
      );
      if (
        compatibilityUtil.hashFile(launchFile)
          !== record.launch_sha256
      ) {
        throw new Error(
          'predecessor compatibility launch hash mismatch',
        );
      }
    }
  }
  return loaded;
};
`,
    );
  }
  writeFileSync(
    path.join(repository, "README.md"),
    "# protocol rotation bootstrap fixture\n",
  );
  const protocolPaths = {
    entry: "docs/protocol/entry.md",
    shared: "docs/protocol/shared.md",
    foreman: "docs/protocol/foreman.md",
    captain: "docs/protocol/captain.md",
    role_kernel: "docs/protocol/role-kernel.md",
  };
  for (const [name, relative] of Object.entries(protocolPaths)) {
    const file = path.join(repository, relative);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, `# ${name}\n`);
  }
  fixtureGit(repository, "add", ".");
  fixtureGit(repository, "commit", "-qm", "schema2 controller base");
  const baseHead = fixtureGit(repository, "rev-parse", "HEAD");

  const goalDirectory = path.join(
    repository,
    "docs",
    "planning",
    "goals",
    primaryGoalId,
  );
  const packetRelative =
    `docs/planning/goals/${primaryGoalId}/packets/${primaryTaskId}-r1.md`;
  const packetBody = "# TASK-A r1\n\nImmutable rotation fixture.\n";
  mkdirSync(path.join(goalDirectory, "packets"), {
    recursive: true,
  });
  writeFileSync(path.join(repository, packetRelative), packetBody);
  const manifest = path.join(goalDirectory, "manifest.json");
  writeFixtureJson(manifest, {
    schema_version: 1,
    goal_id: primaryGoalId,
    mode: "shadow",
    repository: {
      name_with_owner: "example-org/example-repo",
      base_branch: "main",
    },
    base_head: baseHead,
    protocol: protocolPaths,
    tasks: [{
      id: primaryTaskId,
      dependencies: [],
      integration_order: 1,
      packet: {
        revision: 1,
        path: packetRelative,
        sha256: `sha256:${sha256(packetBody)}`,
      },
    }],
  });
  const manifests = [manifest];
  const goalIds = [primaryGoalId];
  if (options.additionalGoal === true) {
    const additionalGoalId = "goal-continuous-extra";
    const additionalTaskId = "TASK-B";
    const additionalDirectory = path.join(
      repository,
      "docs",
      "planning",
      "goals",
      additionalGoalId,
    );
    const additionalPacketRelative =
      `docs/planning/goals/${additionalGoalId}/packets/${additionalTaskId}-r1.md`;
    const additionalPacketBody =
      "# TASK-B r1\n\nAdditional immutable rotation fixture.\n";
    mkdirSync(path.join(additionalDirectory, "packets"), {
      recursive: true,
    });
    writeFileSync(
      path.join(repository, additionalPacketRelative),
      additionalPacketBody,
    );
    const additionalManifest = path.join(
      additionalDirectory,
      "manifest.json",
    );
    writeFixtureJson(additionalManifest, {
      schema_version: 1,
      goal_id: additionalGoalId,
      mode: "shadow",
      repository: {
        name_with_owner: "example-org/example-repo",
        base_branch: "main",
      },
      base_head: baseHead,
      protocol: protocolPaths,
      tasks: [{
        id: additionalTaskId,
        dependencies: [],
        integration_order: 1,
        packet: {
          revision: 1,
          path: additionalPacketRelative,
          sha256: `sha256:${sha256(additionalPacketBody)}`,
        },
      }],
    });
    manifests.push(additionalManifest);
    goalIds.push(additionalGoalId);
  }
  fixtureGit(repository, "add", ".");
  fixtureGit(repository, "commit", "-qm", "freeze bootstrap goal input");
  const predecessorCommit = fixtureGit(
    repository,
    "rev-parse",
    "HEAD",
  );

  installFixtureController(repository, false);
  fixtureGit(repository, "add", "scripts");
  fixtureGit(repository, "commit", "-qm", "install schema3 successor");
  fixtureGit(
    repository,
    "worktree",
    "add",
    "--detach",
    predecessorWorktree,
    predecessorCommit,
  );
  if (identityIncidentFixture) {
    fixtureGit(
      predecessorWorktree,
      "switch",
      "-c",
      "codex/markerless-runtime",
    );
  }
  const goalctl = path.join(repository, "scripts", "goalctl.js");
  const initializedResults = manifests.map((manifestFile) => (
    runFixtureGoalctl(
      goalctl,
      repository,
      controlRoot,
      ["init", "--manifest", manifestFile, "--json"],
    )
  ));
  for (const initializedResult of initializedResults) {
    expect(initializedResult).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
  }
  const initialized = initializedResults[0];
  expect(initialized).toMatchObject({
    status: 0,
    signal: null,
    stderr: "",
  });
  const initializedValue = JSON.parse(initialized.stdout) as {
    bootstrap_capability_file: string;
  };
  const bootstrapCapability =
    initializedValue.bootstrap_capability_file;
  const bootstrapCapabilityBytes = readFileSync(bootstrapCapability);
  const registered = runFixtureGoalctl(
    goalctl,
    repository,
    controlRoot,
    [
      "register-role",
      "--goal",
      primaryGoalId,
      "--task",
      primaryTaskId,
      "--role",
      "FOREMAN",
      "--thread",
      foremanThreadId,
      "--host",
      "local",
      "--attempt",
      "1",
      "--event-id",
      "register-foreman-bootstrap-pending",
      "--bootstrap-capability-file",
      bootstrapCapability,
      "--json",
    ],
  );
  expect(registered).toMatchObject({
    status: 0,
    signal: null,
    stderr: "",
  });
  const registeredValue = JSON.parse(registered.stdout) as {
    actor_capability_file: string;
  };
  expect(existsSync(bootstrapCapability)).toBe(false);

  const goalMetadata = path.join(
    controlRoot,
    "goals",
    primaryGoalId,
    "goal.json",
  );
  if (pendingBootstrapRepair) {
    // After this boundary the repairable state is manufactured only by direct
    // byte writes. No Goal read/status/replay API gets a chance to reconcile it
    // before rotate-store-protocol performs its own read-only replay.
    const metadata = JSON.parse(readFileSync(
      goalMetadata,
      "utf8",
    )) as Record<string, unknown>;
    expect(typeof metadata.bootstrap_consumed_at).toBe("string");
    delete metadata.bootstrap_consumed_at;
    delete metadata.meta_sha256;
    writeFixtureJson(goalMetadata, {
      ...metadata,
      meta_sha256: hashObject(metadata),
    });
    writeFileSync(bootstrapCapability, bootstrapCapabilityBytes);
    chmodSync(bootstrapCapability, 0o600);
  }

  const predecessorDecoder = path.join(
    predecessorWorktree,
    "scripts",
    "goal-control",
  );
  const predecessorDecoderSha256 =
    controllerDecoderFingerprintAt(predecessorDecoder);
  let migrationSourceStateVectorSha256: string | null = null;
  let migrationArtifacts: MigrationDescriptor[] = [];
  if (options.historicalGoalMapSubset === true) {
    const controlManifest = JSON.parse(readFileSync(
      path.join(
        controlRoot,
        "goals",
        primaryGoalId,
        "manifest.json",
      ),
      "utf8",
    )) as {
      manifest_sha256: string;
      protocol: Record<string, {
        path: string;
        sha256: string;
      }>;
      tasks: Array<{
        id: string;
        packet: {
          path: string;
          revision: number;
          sha256: string;
        };
      }>;
    };
    const frozenInputs = [
      ...Object.entries(controlManifest.protocol)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([name, value]) => ({
          kind: "PROTOCOL",
          name,
          path: value.path,
          sha256: value.sha256,
        })),
      ...controlManifest.tasks
        .map((task) => ({
          kind: "PACKET",
          task_id: task.id,
          path: task.packet.path,
          revision: task.packet.revision,
          sha256: task.packet.sha256,
        }))
        .sort((left, right) => (
          left.task_id.localeCompare(right.task_id)
        )),
    ];
    const unsignedBinding = {
      goal_id: primaryGoalId,
      repository_worktree: predecessorWorktree,
      repository_common_dir: realpathSync(fixtureGit(
        predecessorWorktree,
        "rev-parse",
        "--path-format=absolute",
        "--git-common-dir",
      )),
      repository_head: fixtureGit(
        predecessorWorktree,
        "rev-parse",
        "HEAD",
      ),
      manifest_sha256: controlManifest.manifest_sha256,
      frozen_inputs_sha256: hashObject(frozenInputs),
    };
    const historicalBinding = {
      ...unsignedBinding,
      worktree_identity_sha256: hashObject(unsignedBinding),
    };
    const historicalGoalWorktreeMap = {
      schema_version: 1,
      mode: "SINGLE_DEFAULT",
      mapping_file: null,
      mapping_file_sha256: null,
      goal_worktrees: [historicalBinding],
      goal_worktrees_sha256: hashObject([historicalBinding]),
    };
    migrationSourceStateVectorSha256 = hashObject({
      fixture: "historical-schema2-adoption",
    });
    const sealedLegacyIndex = sealLegacyEvidenceAnchorIndex(
      createLegacyEvidenceMigrationCollector(),
      {
        controllerDecoderSha256: predecessorDecoderSha256,
        sourceStateVectorSha256:
          migrationSourceStateVectorSha256,
        incidentRef:
          "incident://goal-control/historical-schema2-adoption",
        oldControllerDrainAck:
          "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
        goalWorktreeMap: historicalGoalWorktreeMap,
        recoveryHandoffs: new Map(),
      },
    );
    const artifact = sealedLegacyIndex.migration_artifact;
    const artifactFile = path.join(
      controlRoot,
      artifact.relative_path,
    );
    writeFileSync(artifactFile, artifact.body, { mode: 0o600 });
    migrationArtifacts = [{
      relative_path: artifact.relative_path,
      sha256: artifact.sha256,
    }];
  }
  const predecessorUnsigned = {
    schema_version: 2,
    controller_decoder_version: 2,
    controller_decoder_sha256: predecessorDecoderSha256,
    lock_protocol_version: 2,
    migration_source_state_vector_sha256:
      migrationSourceStateVectorSha256,
    migration_artifacts: migrationArtifacts,
  };
  const predecessorProtocol = {
    ...predecessorUnsigned,
    seal_sha256: hashObject(predecessorUnsigned),
  };
  writeFixtureJson(
    path.join(controlRoot, ".store-protocol.json"),
    predecessorProtocol,
  );
  expect(fixtureGit(
    repository,
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
  )).toBe("");
  expect(fixtureGit(
    predecessorWorktree,
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
  )).toBe("");
  return {
    repository,
    controlRoot,
    goalctl,
    predecessorWorktree,
    predecessorProtocol,
    goalIds,
    primaryGoalId,
    primaryTaskId,
    foremanThreadId,
    foremanCapability: registeredValue.actor_capability_file,
    bootstrapCapability,
    bootstrapCapabilityBytes,
    goalMetadata,
  };
}

function installFixtureLegacyEvidenceAnchor(
  fixture: PendingBootstrapRotationFixture,
  corruptEvidenceId: string | null = null,
): void {
  const existingIndexFile = path.join(
    fixture.controlRoot,
    ".legacy-evidence-anchors.v1.json",
  );
  const existingIndex = JSON.parse(readFileSync(
    existingIndexFile,
    "utf8",
  )) as {
    migration_receipt: {
      goal_worktree_map: {
        goal_worktrees: Array<Record<string, unknown> & {
          goal_id: string;
        }>;
        goal_worktrees_sha256: string;
      };
    };
  };
  const goalWorktreeMap = JSON.parse(JSON.stringify(
    existingIndex.migration_receipt.goal_worktree_map,
  )) as typeof existingIndex.migration_receipt.goal_worktree_map;
  const currentHead = fixtureGit(
    fixture.predecessorWorktree,
    "rev-parse",
    "HEAD",
  );
  goalWorktreeMap.goal_worktrees =
    goalWorktreeMap.goal_worktrees.map((binding) => {
      const {
        worktree_identity_sha256: _previousIdentitySha256,
        ...bindingWithoutIdentity
      } = binding;
      const unsigned = {
        ...bindingWithoutIdentity,
        repository_head: currentHead,
      };
      return {
        ...unsigned,
        worktree_identity_sha256: hashObject(unsigned),
      };
    });
  goalWorktreeMap.goal_worktrees_sha256 =
    hashObject(goalWorktreeMap.goal_worktrees);
  const collector = createLegacyEvidenceMigrationCollector();
  for (const goalId of fixture.goalIds) {
    loadGoalStateUnlocked(
      fixture.controlRoot,
      goalId,
      {
        repairHeads: false,
        repairBootstrapConsumption: false,
        legacyEvidenceBindingCollector: collector,
      },
    );
  }
  collectLegacySemanticEvidenceSources(
    fixture.controlRoot,
    collector,
  );
  const sourceStateVectorSha256 = hashObject({
    fixture: "dual-proof-precedence",
    goal_ids: fixture.goalIds,
    repository_head: currentHead,
  });
  const sealed = sealLegacyEvidenceAnchorIndex(
    collector,
    {
      controllerDecoderSha256:
        fixture.predecessorProtocol.controller_decoder_sha256,
      sourceStateVectorSha256,
      incidentRef:
        "incident://goal-control/dual-proof-precedence",
      oldControllerDrainAck:
        "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
      goalWorktreeMap,
      recoveryHandoffs: new Map(),
    },
  );
  let migrationArtifacts = sealed.migration_artifacts;
  if (corruptEvidenceId !== null) {
    const semanticKey = Object.keys(
      sealed.index.semantic_sources,
    ).find((key) => key.endsWith(`/${corruptEvidenceId}`));
    if (!semanticKey) {
      throw new Error(
        `legacy semantic binding ${corruptEvidenceId} missing`,
      );
    }
    sealed.index.semantic_sources[semanticKey].registry_sha256 =
      `sha256:${"0".repeat(64)}`;
    const {
      index_sha256: _previousIndexSha256,
      ...unsignedIndex
    } = sealed.index;
    sealed.index.index_sha256 = hashObject(unsignedIndex);
    const anchorBody = `${canonicalJson(sealed.index)}\n`;
    const anchorSha256 = `sha256:${sha256(anchorBody)}`;
    migrationArtifacts = migrationArtifacts.map((artifact) => (
      artifact.relative_path ===
        ".legacy-evidence-anchors.v1.json"
        ? {
            ...artifact,
            sha256: anchorSha256,
            body: anchorBody,
          }
        : artifact
    ));
  }
  for (const artifact of migrationArtifacts) {
    const artifactFile = path.join(
      fixture.controlRoot,
      artifact.relative_path,
    );
    mkdirSync(path.dirname(artifactFile), { recursive: true });
    writeFileSync(artifactFile, artifact.body, { mode: 0o600 });
  }
  const protocolUnsigned = {
    schema_version: fixture.predecessorProtocol.schema_version,
    controller_decoder_version:
      fixture.predecessorProtocol.controller_decoder_version,
    controller_decoder_sha256:
      fixture.predecessorProtocol.controller_decoder_sha256,
    lock_protocol_version:
      fixture.predecessorProtocol.lock_protocol_version,
    migration_source_state_vector_sha256:
      sourceStateVectorSha256,
    migration_artifacts: migrationArtifacts.map((artifact) => ({
      relative_path: artifact.relative_path,
      sha256: artifact.sha256,
    })).sort((left, right) => (
      left.relative_path.localeCompare(right.relative_path)
    )),
  };
  const protocol = {
    ...protocolUnsigned,
    seal_sha256: hashObject(protocolUnsigned),
  };
  Object.assign(fixture.predecessorProtocol, protocol);
  writeFixtureJson(
    path.join(fixture.controlRoot, ".store-protocol.json"),
    protocol,
  );
}

type HistoricalPreflightOverwrite = {
  evidenceId: string;
  registryFile: string;
  canonicalLaunchFile: string;
  immutableLaunchFile: string;
  handoffCanaryFile: string;
  handoffReceiptFile: string;
  record: Record<string, unknown>;
  canonicalLaunchSha256: string;
  immutableLaunchSha256: string;
};

type AcceptedHistoricalPreflightOverwrite = Omit<
  HistoricalPreflightOverwrite,
  "handoffCanaryFile" | "handoffReceiptFile"
> & {
  acceptedEventFile: string;
  acceptedEvent: Record<string, unknown>;
};

type RotationTaskState = {
  state_revision: number;
  control_epoch: number;
  base_head: string;
  full_head: string;
  packet: {
    revision: number;
    sha256: string;
  };
  holds?: Array<{
    hold_id: string;
    kind: string;
  }>;
  sessions: Record<string, {
    thread_id: string;
    host_id: string;
    registered_state_revision: number;
    task_nonce?: string;
  }>;
};

function predecessorGoalctl(
  fixture: PendingBootstrapRotationFixture,
): string {
  return path.join(
    fixture.predecessorWorktree,
    "scripts",
    "goalctl.js",
  );
}

function predecessorTaskState(
  fixture: PendingBootstrapRotationFixture,
): RotationTaskState {
  const result = runFixtureGoalctl(
    predecessorGoalctl(fixture),
    fixture.predecessorWorktree,
    fixture.controlRoot,
    ["status", "--goal", fixture.primaryGoalId, "--json"],
  );
  if (result.status !== 0) {
    throw new Error(
      `predecessor status failed: ${result.stderr || result.stdout}`,
    );
  }
  const body = JSON.parse(result.stdout) as {
    tasks:
      | RotationTaskState[]
      | Record<string, RotationTaskState>;
  };
  const state = Array.isArray(body.tasks)
    ? body.tasks.find((task) => (
      (task as RotationTaskState & { task_id?: string }).task_id
        === fixture.primaryTaskId
    ))
    : body.tasks[fixture.primaryTaskId];
  if (!state) throw new Error("predecessor task state missing");
  return state;
}

function submitPredecessorEvent(
  fixture: PendingBootstrapRotationFixture,
  options: {
    eventId: string;
    type: string;
    role: string;
    threadId: string;
    actorSequence: number;
    capabilityFile: string;
    payload?: Record<string, unknown>;
    fullHead?: string;
  },
): {
  result: CliResult;
  acceptedEventFile: string | null;
} {
  const state = predecessorTaskState(fixture);
  const event = {
    schema_version: 1,
    event_id: options.eventId,
    goal_id: fixture.primaryGoalId,
    task_id: fixture.primaryTaskId,
    type: options.type,
    actor: {
      role: options.role,
      thread_id: options.threadId,
      host_id: "local",
    },
    actor_sequence: options.actorSequence,
    expected_state_revision: state.state_revision,
    control_epoch: state.control_epoch,
    packet: {
      revision: state.packet.revision,
      sha256: state.packet.sha256,
    },
    base_head: state.base_head,
    full_head: options.fullHead ?? state.full_head,
    payload: options.payload ?? {},
  };
  const inputFile = path.join(
    path.dirname(fixture.controlRoot),
    "event-inputs",
    `${options.eventId}.json`,
  );
  writeFixtureJson(inputFile, event);
  const result = runFixtureGoalctl(
    predecessorGoalctl(fixture),
    fixture.predecessorWorktree,
    fixture.controlRoot,
    [
      "event",
      "--goal",
      fixture.primaryGoalId,
      "--file",
      inputFile,
      "--actor-capability-file",
      options.capabilityFile,
      "--json",
    ],
  );
  const eventDirectory = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "events",
    fixture.primaryTaskId,
  );
  const acceptedName = existsSync(eventDirectory)
    ? readdirSync(eventDirectory).find((name) => (
      name.endsWith(`-${options.eventId}.json`)
    ))
    : undefined;
  return {
    result,
    acceptedEventFile: acceptedName
      ? path.join(eventDirectory, acceptedName)
      : null,
  };
}

function registerPredecessorRole(
  fixture: PendingBootstrapRotationFixture,
  options: {
    role: "CAPTAIN" | "DEV";
    threadId: string;
    authorizerCapabilityFile: string;
    launchId?: string;
    attempt?: number;
  },
): {
  actor_capability_file: string;
  session: {
    registered_state_revision: number;
    task_nonce: string;
  };
} {
  const result = runFixtureGoalctl(
    predecessorGoalctl(fixture),
    fixture.predecessorWorktree,
    fixture.controlRoot,
    [
      "register-role",
      "--goal",
      fixture.primaryGoalId,
      "--task",
      fixture.primaryTaskId,
      "--role",
      options.role,
      "--thread",
      options.threadId,
      "--host",
      "local",
      "--attempt",
      String(options.attempt ?? 1),
      ...(options.launchId
        ? ["--launch-id", options.launchId]
        : []),
      "--authorizer-capability-file",
      options.authorizerCapabilityFile,
      "--json",
    ],
  );
  if (result.status !== 0) {
    throw new Error(
      `predecessor ${options.role} registration failed: ${
        result.stderr || result.stdout
      }`,
    );
  }
  return JSON.parse(result.stdout);
}

function installMarkerlessRuntimeIdentityIncident(
  fixture: PendingBootstrapRotationFixture,
  options: {
    expectPreparedMarker?: boolean;
    conflictKind?:
      | "RUNTIME_IDENTITY"
      | "SOURCE_ONLY"
      | "CANONICAL_STALE_HEAD";
  } = {},
): {
  runtime: ReturnType<typeof spawn>;
  sourceFile: string;
  sourceBody: Buffer;
  holdId: string;
  captainThreadId: string;
  captainCapability: string;
  incidentEvent: Record<string, unknown>;
  candidateHead: string;
  canonicalHead: string;
  observedHead: string;
} {
  const captainThreadId = "captain-markerless-runtime";
  const devThreadId = "dev-markerless-runtime";
  const launchId = "launch-markerless-runtime-dev";
  const planPath = "docs/issues/4243/plan.md";
  const contextPath = "docs/issues/4243/context.md";
  const planBody = "# Markerless runtime rotation plan\n";
  const contextBody = "# Markerless runtime rotation context\n";
  mkdirSync(
    path.dirname(path.join(fixture.predecessorWorktree, planPath)),
    { recursive: true },
  );
  writeFileSync(
    path.join(fixture.predecessorWorktree, planPath),
    planBody,
  );
  writeFileSync(
    path.join(fixture.predecessorWorktree, contextPath),
    contextBody,
  );
  fixtureGit(
    fixture.predecessorWorktree,
    "add",
    planPath,
    contextPath,
  );
  fixtureGit(
    fixture.predecessorWorktree,
    "commit",
    "-qm",
    "freeze markerless runtime inputs",
  );
  const candidateHead = fixtureGit(
    fixture.predecessorWorktree,
    "rev-parse",
    "HEAD",
  );
  const p1Payload = {
    plan_path: planPath,
    plan_sha256: `sha256:${sha256(planBody)}`,
    context_path: contextPath,
    context_sha256: `sha256:${sha256(contextBody)}`,
  };
  const captain = registerPredecessorRole(fixture, {
    role: "CAPTAIN",
    threadId: captainThreadId,
    authorizerCapabilityFile: fixture.foremanCapability,
  });
  const p1Events = [
    {
      eventId: "start-p1-markerless-runtime",
      type: "START_P1",
      role: "CAPTAIN",
      threadId: captainThreadId,
      actorSequence: 1,
      capabilityFile: captain.actor_capability_file,
    },
    {
      eventId: "p1-ready-markerless-runtime",
      type: "P1_READY",
      role: "CAPTAIN",
      threadId: captainThreadId,
      actorSequence: 2,
      capabilityFile: captain.actor_capability_file,
      payload: p1Payload,
    },
    {
      eventId: "p1-approved-markerless-runtime",
      type: "P1_APPROVED",
      role: "FOREMAN",
      threadId: fixture.foremanThreadId,
      actorSequence: 1,
      capabilityFile: fixture.foremanCapability,
      payload: {
        ...p1Payload,
        approval_ref:
          "user://goal-control/markerless-runtime-approved",
      },
    },
    {
      eventId: "p1-committed-markerless-runtime",
      type: "P1_COMMITTED",
      role: "CAPTAIN",
      threadId: captainThreadId,
      actorSequence: 3,
      capabilityFile: captain.actor_capability_file,
      fullHead: candidateHead,
      payload: {
        ...p1Payload,
        approval_event_id: "p1-approved-markerless-runtime",
      },
    },
  ];
  for (const event of p1Events) {
    const submitted = submitPredecessorEvent(fixture, event);
    if (submitted.result.status !== 0) {
      throw new Error(
        `${event.type} failed: ${
          submitted.result.stderr || submitted.result.stdout
        }`,
      );
    }
  }
  const dev = registerPredecessorRole(fixture, {
    role: "DEV",
    threadId: devThreadId,
    authorizerCapabilityFile: captain.actor_capability_file,
    launchId,
  });
  const ps = existsSync("/bin/ps") ? "/bin/ps" : "/usr/bin/ps";
  const started = execFileSync(
    ps,
    ["-p", String(process.pid), "-o", "lstart="],
    {
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        TZ: "UTC",
        NODE_ENV: "test",
      },
    },
  ).trim();
  const launchInputFile = path.join(
    path.dirname(fixture.controlRoot),
    "markerless-runtime-launch-input.json",
  );
  writeFixtureJson(launchInputFile, {
    execution: {
      environment: "none",
      write_mode: "NONE",
      target: {
        kind: "PREVIEW",
        executable_path: realpathSync(process.execPath),
        pid: process.pid,
        started_at:
          new Date(Date.parse(`${started} UTC`)).toISOString(),
        preview_url: "http://127.0.0.1:8123",
        build_head: candidateHead,
      },
    },
    resource_leases: [],
  });
  const launchTemplate = runFixtureGoalctl(
    predecessorGoalctl(fixture),
    fixture.predecessorWorktree,
    fixture.controlRoot,
    [
      "launch-template",
      "--goal",
      fixture.primaryGoalId,
      "--task",
      fixture.primaryTaskId,
      "--role",
      "DEV",
      "--thread",
      devThreadId,
      "--actor-capability-file",
      dev.actor_capability_file,
      "--input-file",
      launchInputFile,
      "--json",
    ],
  );
  if (launchTemplate.status !== 0) {
    throw new Error(
      `markerless runtime launch template failed: ${
        launchTemplate.stderr || launchTemplate.stdout
      }`,
    );
  }
  const launch = JSON.parse(launchTemplate.stdout);
  const initialLaunchFile = path.join(
    path.dirname(fixture.controlRoot),
    "markerless-runtime-initial-launch.json",
  );
  writeFileSync(initialLaunchFile, launchTemplate.stdout);
  const initialPreflight = runFixtureGoalctl(
    predecessorGoalctl(fixture),
    fixture.predecessorWorktree,
    fixture.controlRoot,
    [
      "preflight",
      "--goal",
      fixture.primaryGoalId,
      "--task",
      fixture.primaryTaskId,
      "--launch",
      initialLaunchFile,
      "--stage",
      "DEV",
      "--evidence-id",
      "preflight-markerless-runtime-initial",
      "--actor-capability-file",
      dev.actor_capability_file,
      "--json",
    ],
  );
  if (initialPreflight.status !== 0) {
    throw new Error(
      `initial markerless runtime preflight failed: ${
        initialPreflight.stderr || initialPreflight.stdout
      }`,
    );
  }
  const launched = submitPredecessorEvent(fixture, {
    eventId: "launch-dev-markerless-runtime",
    type: "LAUNCH_DEV",
    role: "CAPTAIN",
    threadId: captainThreadId,
    actorSequence: 4,
    capabilityFile: captain.actor_capability_file,
    payload: { launch_id: launchId },
  });
  if (launched.result.status !== 0) {
    throw new Error(
      `markerless runtime LAUNCH_DEV failed: ${
        launched.result.stderr || launched.result.stdout
      }`,
    );
  }
  let conflictCandidateHead = candidateHead;
  if (
    options.conflictKind === "SOURCE_ONLY"
      || options.conflictKind === "CANONICAL_STALE_HEAD"
  ) {
    const sourceChange = "source-checkpoint-change.txt";
    writeFileSync(
      path.join(fixture.predecessorWorktree, sourceChange),
      "source checkpoint candidate\n",
    );
    fixtureGit(fixture.predecessorWorktree, "add", sourceChange);
    fixtureGit(
      fixture.predecessorWorktree,
      "commit",
      "-qm",
      "advance source checkpoint candidate",
    );
    conflictCandidateHead = fixtureGit(
      fixture.predecessorWorktree,
      "rev-parse",
      "HEAD",
    );
  }
  const runtime = spawn(
    process.execPath,
    ["-e", "setInterval(() => {}, 1000)"],
    { stdio: "ignore" },
  );
  if (!runtime.pid) throw new Error("fresh markerless runtime missing PID");
  const freshStarted = execFileSync(
    ps,
    ["-p", String(runtime.pid), "-o", "lstart="],
    {
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        TZ: "UTC",
        NODE_ENV: "test",
      },
    },
  ).trim();
  const candidate = JSON.parse(JSON.stringify(launch));
  if (options.conflictKind === "SOURCE_ONLY") {
    candidate.repository.full_head = conflictCandidateHead;
    candidate.execution.target.build_head = conflictCandidateHead;
  } else if (options.conflictKind !== "CANONICAL_STALE_HEAD") {
    candidate.execution.target.pid = runtime.pid;
    candidate.execution.target.started_at =
      new Date(Date.parse(`${freshStarted} UTC`)).toISOString();
    candidate.execution.target.preview_url =
      "http://127.0.0.1:8124";
    candidate.created_at = "2026-07-26T02:00:01.000Z";
  }
  const candidateFile = path.join(
    path.dirname(fixture.controlRoot),
    "markerless-runtime-candidate-launch.json",
  );
  writeFixtureJson(candidateFile, candidate);
  const rejected = runFixtureGoalctl(
    predecessorGoalctl(fixture),
    fixture.predecessorWorktree,
    fixture.controlRoot,
    [
      "preflight",
      "--goal",
      fixture.primaryGoalId,
      "--task",
      fixture.primaryTaskId,
      "--launch",
      candidateFile,
      "--stage",
      "DEV",
      "--evidence-id",
      "preflight-markerless-runtime-conflict",
      "--actor-capability-file",
      dev.actor_capability_file,
      "--json",
    ],
  );
  const rejectedEvidence = rejected.stdout
    ? JSON.parse(rejected.stdout) as {
      checks?: Array<{
        name: string;
        status: string;
        detail?: string;
      }>;
    }
    : {};
  const failedChecks = (rejectedEvidence.checks ?? []).filter(
    (check) => check.status === "FAIL",
  );
  const expectedFailure = options.conflictKind === "CANONICAL_STALE_HEAD"
    ? (
      rejected.status !== 0
        && JSON.stringify(failedChecks) === JSON.stringify([
          {
            name: "repository-identity",
            status: "FAIL",
            detail:
              `STALE_HEAD: 当前 HEAD ${conflictCandidateHead} 与 launch 不一致`,
          },
          {
            name: "execution-target",
            status: "FAIL",
            detail:
              "TARGET_BUILD_HEAD_MISMATCH: 候选 build HEAD 与当前 HEAD 不一致",
          },
        ])
    )
    : (
      rejected.status !== 0
        && `${rejected.stdout}\n${rejected.stderr}`.includes(
          "LAUNCH_ID_CONFLICT",
        )
    );
  if (
    !expectedFailure
  ) {
    runtime.kill("SIGTERM");
    throw new Error(
      `markerless runtime conflict did not fail closed: ${
        rejected.stderr || rejected.stdout
      }`,
    );
  }
  const held = predecessorTaskState(fixture);
  const heldWithEvidence = held as unknown as {
    holds: Array<{
      hold_id: string;
      kind: string;
      evidence: { uri: string };
    }>;
  };
  const hold = heldWithEvidence.holds.find((candidateHold) => (
    candidateHold.kind === "ENV_IDENTITY_INCIDENT"
  ));
  if (!hold) {
    runtime.kill("SIGTERM");
    throw new Error("markerless runtime hold missing");
  }
  const eventDirectory = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "events",
    fixture.primaryTaskId,
  );
  const incident = readdirSync(eventDirectory)
    .map((name) => JSON.parse(readFileSync(
      path.join(eventDirectory, name),
      "utf8",
    )))
    .find((event) => (
      event.type === "ADD_HOLD"
        && event.payload?.hold_id === hold.hold_id
    ));
  if (!incident) {
    runtime.kill("SIGTERM");
    throw new Error("markerless runtime accepted incident missing");
  }
  if (options.expectPreparedMarker === true) {
    expect(incident.prepared_identity_incident_authority)
      .toBeDefined();
  } else {
    expect(incident.prepared_identity_incident_authority)
      .toBeUndefined();
  }
  const incidentUnsigned = { ...incident };
  delete incidentUnsigned.event_sha256;
  expect(incident.event_sha256).toBe(hashObject(incidentUnsigned));
  const sourceFile = fileURLToPath(new URL(hold.evidence.uri));
  return {
    runtime,
    sourceFile,
    sourceBody: readFileSync(sourceFile),
    holdId: hold.hold_id,
    captainThreadId,
    captainCapability: captain.actor_capability_file,
    incidentEvent: incident,
    candidateHead: conflictCandidateHead,
    canonicalHead: candidateHead,
    observedHead: conflictCandidateHead,
  };
}

function writeFixtureEvidence(
  fixture: PendingBootstrapRotationFixture,
  options: {
    evidenceId: string;
    kind: string;
    status: "PASS" | "BLOCKED";
    producerRole: string;
    producerThreadId: string;
    state: RotationTaskState;
    fullHead?: string;
    launch?: Record<string, unknown>;
    pullRequest?: boolean;
  },
): {
  record: Record<string, unknown>;
  registryFile: string;
  immutableLaunchFile: string | null;
} {
  const registryDirectory = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "evidence",
    fixture.primaryTaskId,
  );
  const artifactDirectory = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "evidence-artifacts",
    fixture.primaryTaskId,
  );
  const sourceDirectory = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "evidence-sources",
    fixture.primaryTaskId,
  );
  const registryFile = path.join(
    registryDirectory,
    `${options.evidenceId}.json`,
  );
  const fullHead = options.fullHead ?? options.state.full_head;
  const unsigned: Record<string, unknown> = {
    schema_version: 1,
    evidence_id: options.evidenceId,
    goal_id: fixture.primaryGoalId,
    task_id: fixture.primaryTaskId,
    kind: options.kind,
    status: options.status,
    producer: {
      role: options.producerRole,
      thread_id: options.producerThreadId,
      host_id: "local",
    },
    state_revision: options.state.state_revision,
    packet: {
      revision: options.state.packet.revision,
      sha256: options.state.packet.sha256,
    },
    packet_sha256: options.state.packet.sha256,
    base_head: options.state.base_head,
    full_head: fullHead,
    created_at: "2026-07-26T02:00:00.000Z",
  };
  let immutableLaunchFile: string | null = null;
  if (options.kind === "PREFLIGHT") {
    if (!options.launch) {
      throw new Error("PREFLIGHT fixture evidence requires launch");
    }
    const launchId = String(options.launch.launch_id);
    const canonicalLaunchFile = path.join(
      fixture.controlRoot,
      "goals",
      fixture.primaryGoalId,
      "launches",
      fixture.primaryTaskId,
      `${launchId}.json`,
    );
    immutableLaunchFile = path.join(
      artifactDirectory,
      `${options.evidenceId}-launch.json`,
    );
    writeFixtureJson(immutableLaunchFile, options.launch);
    Object.assign(unsigned, {
      stage: "DEV",
      launch_id: launchId,
      uri: pathToFileURL(registryFile).href,
      checks: [],
      attestation: {
        controller: "goalctl",
        adapter: "PREFLIGHT",
      },
      launch_sha256:
        `sha256:${sha256(readFileSync(immutableLaunchFile))}`,
      launch_uri: pathToFileURL(canonicalLaunchFile).href,
    });
  } else {
    const artifactFile = path.join(
      sourceDirectory,
      `${options.evidenceId}.artifact`,
    );
    writeFixtureJson(artifactFile, {
      kind: options.kind,
      status: options.status,
    });
    Object.assign(unsigned, {
      uri: pathToFileURL(artifactFile).href,
      source_sha256: `sha256:${sha256(readFileSync(artifactFile))}`,
    });
    if (["FAST", "FULL_CI", "AC_AUDIT"].includes(options.kind)) {
      Object.assign(unsigned, {
        attestation: {
          controller: "goalctl",
          adapter: options.kind,
        },
      });
    }
    if (options.pullRequest === true) {
      Object.assign(unsigned, {
        pull_request: {
          repository: "example-org/example-repo",
          number: 999,
          url: "https://github.com/example-org/example-repo/pull/999",
          base: "main",
          head: fullHead,
        },
      });
    }
  }
  const record = {
    ...unsigned,
    registry_sha256: hashObject(unsigned),
  };
  writeFixtureJson(registryFile, record);
  return { record, registryFile, immutableLaunchFile };
}

function installHistoricalPreflightOverwrite(
  fixture: PendingBootstrapRotationFixture,
): HistoricalPreflightOverwrite {
  const manifest = JSON.parse(readFileSync(
    path.join(
      fixture.controlRoot,
      "goals",
      fixture.primaryGoalId,
      "manifest.json",
    ),
    "utf8",
  )) as {
    base_head: string;
    tasks: Array<{
      id: string;
      packet: { revision: number; sha256: string };
    }>;
  };
  const task = manifest.tasks.find(
    (candidate) => candidate.id === fixture.primaryTaskId,
  );
  if (!task) throw new Error("fixture task missing");
  const evidenceId = "preflight-historical-overwritten-canonical";
  const launchId = "launch-historical-dev-a1";
  const threadId = "historical-dev-thread";
  const immutableLaunchFile = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "evidence-artifacts",
    fixture.primaryTaskId,
    `${evidenceId}-launch.json`,
  );
  const canonicalLaunchFile = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "launches",
    fixture.primaryTaskId,
    `${launchId}.json`,
  );
  const registryFile = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "evidence",
    fixture.primaryTaskId,
    `${evidenceId}.json`,
  );
  const handoffReceiptFile = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "evidence-artifacts",
    fixture.primaryTaskId,
    "historical-import-receipt.json",
  );
  const handoffCanaryFile = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    ".absolute-handoff-canary.json",
  );
  const immutableLaunch = {
    schema_version: 1,
    launch_id: launchId,
    goal_id: fixture.primaryGoalId,
    task_id: fixture.primaryTaskId,
    role: "DEV",
    thread: {
      id: threadId,
      host_id: "local",
    },
    packet: task.packet,
    repository: {
      base_head: manifest.base_head,
      full_head: manifest.base_head,
      worktree: "/frozen/historical-dev-worktree",
      branch: "codex/historical-dev",
    },
    execution: {
      task_nonce: "historical-task-nonce",
      target: {
        kind: "PREVIEW",
        pid: 101,
        started_at: "2026-07-26T00:00:00.000Z",
        build_head: manifest.base_head,
      },
    },
    runtime: {
      node: "v25.8.2",
      pnpm: "10.33.0",
    },
    resource_leases: [{
      lease_id: "lease-historical-preview",
      revision: 1,
    }],
    created_at: "2026-07-26T00:00:00.000Z",
  };
  const overwrittenCanonicalLaunch = {
    ...immutableLaunch,
    repository: {
      ...immutableLaunch.repository,
      full_head: "f".repeat(40),
    },
    execution: {
      ...immutableLaunch.execution,
      target: {
        ...immutableLaunch.execution.target,
        pid: 202,
        started_at: "2026-07-26T01:00:00.000Z",
        build_head: "f".repeat(40),
      },
    },
    created_at: "2026-07-26T01:00:00.000Z",
  };
  writeFixtureJson(immutableLaunchFile, immutableLaunch);
  writeFixtureJson(canonicalLaunchFile, overwrittenCanonicalLaunch);
  const immutableLaunchSha256 =
    `sha256:${sha256(readFileSync(immutableLaunchFile))}`;
  const canonicalLaunchSha256 =
    `sha256:${sha256(readFileSync(canonicalLaunchFile))}`;
  expect(canonicalLaunchSha256).not.toBe(immutableLaunchSha256);
  const unsigned = {
    schema_version: 1,
    evidence_id: evidenceId,
    goal_id: fixture.primaryGoalId,
    task_id: fixture.primaryTaskId,
    kind: "PREFLIGHT",
    stage: "INITIAL",
    status: "PASS",
    producer: {
      role: "DEV",
      thread_id: threadId,
      host_id: "local",
    },
    state_revision: 1,
    packet: task.packet,
    packet_sha256: task.packet.sha256,
    base_head: manifest.base_head,
    full_head: manifest.base_head,
    launch_id: launchId,
    created_at: "2026-07-26T00:00:01.000Z",
    uri: pathToFileURL(registryFile).href,
    checks: [],
    attestation: {
      controller: "goalctl",
      adapter: "PREFLIGHT",
    },
    launch_sha256: immutableLaunchSha256,
    launch_uri: pathToFileURL(canonicalLaunchFile).href,
  };
  const record = {
    ...unsigned,
    registry_sha256: hashObject(unsigned),
  };
  writeFixtureJson(registryFile, record);
  writeFixtureJson(handoffReceiptFile, {
    schema_version: 1,
    kind: "RECOVERY_IMPORT_RECEIPT",
    goal_id: fixture.primaryGoalId,
    task_id: fixture.primaryTaskId,
    import_commit: manifest.base_head,
  });
  writeFixtureJson(handoffCanaryFile, {
    schema_version: 1,
    control_root: fixture.controlRoot,
    receipt_path: handoffReceiptFile,
    receipt_sha256:
      `sha256:${sha256(readFileSync(handoffReceiptFile))}`,
  });
  return {
    evidenceId,
    registryFile,
    canonicalLaunchFile,
    immutableLaunchFile,
    handoffCanaryFile,
    handoffReceiptFile,
    record,
    canonicalLaunchSha256,
    immutableLaunchSha256,
  };
}

function installAcceptedHistoricalPreflightOverwrite(
  fixture: PendingBootstrapRotationFixture,
): AcceptedHistoricalPreflightOverwrite {
  const captainThreadId = "captain-historical-preflight";
  const devThreadId = "dev-historical-preflight";
  const launchId = "launch-historical-accepted-dev";
  const planPath = "docs/issues/4242/plan.md";
  const contextPath = "docs/issues/4242/context.md";
  const planBody = "# Historical accepted preflight plan\n";
  const contextBody = "# Historical accepted preflight context\n";
  mkdirSync(
    path.dirname(path.join(fixture.predecessorWorktree, planPath)),
    { recursive: true },
  );
  writeFileSync(
    path.join(fixture.predecessorWorktree, planPath),
    planBody,
  );
  writeFileSync(
    path.join(fixture.predecessorWorktree, contextPath),
    contextBody,
  );
  fixtureGit(
    fixture.predecessorWorktree,
    "add",
    planPath,
    contextPath,
  );
  fixtureGit(
    fixture.predecessorWorktree,
    "commit",
    "-qm",
    "freeze historical accepted preflight inputs",
  );
  const candidateHead = fixtureGit(
    fixture.predecessorWorktree,
    "rev-parse",
    "HEAD",
  );
  const p1Payload = {
    plan_path: planPath,
    plan_sha256: `sha256:${sha256(planBody)}`,
    context_path: contextPath,
    context_sha256: `sha256:${sha256(contextBody)}`,
  };
  const captain = registerPredecessorRole(fixture, {
    role: "CAPTAIN",
    threadId: captainThreadId,
    authorizerCapabilityFile: fixture.foremanCapability,
  });
  const start = submitPredecessorEvent(fixture, {
    eventId: "start-p1-historical-preflight",
    type: "START_P1",
    role: "CAPTAIN",
    threadId: captainThreadId,
    actorSequence: 1,
    capabilityFile: captain.actor_capability_file,
  });
  if (start.result.status !== 0) {
    throw new Error(
      `historical START_P1 failed: ${
        start.result.stderr || start.result.stdout
      }`,
    );
  }
  const ready = submitPredecessorEvent(fixture, {
    eventId: "p1-ready-historical-preflight",
    type: "P1_READY",
    role: "CAPTAIN",
    threadId: captainThreadId,
    actorSequence: 2,
    capabilityFile: captain.actor_capability_file,
    payload: p1Payload,
  });
  if (ready.result.status !== 0) {
    throw new Error(
      `historical P1_READY failed: ${
        ready.result.stderr || ready.result.stdout
      }`,
    );
  }
  const approvalEventId = "p1-approved-historical-preflight";
  const approved = submitPredecessorEvent(fixture, {
    eventId: approvalEventId,
    type: "P1_APPROVED",
    role: "FOREMAN",
    threadId: fixture.foremanThreadId,
    actorSequence: 1,
    capabilityFile: fixture.foremanCapability,
    payload: {
      ...p1Payload,
      approval_ref:
        "user://goal-control/historical-preflight-approved",
    },
  });
  if (approved.result.status !== 0) {
    throw new Error(
      `historical P1_APPROVED failed: ${
        approved.result.stderr || approved.result.stdout
      }`,
    );
  }
  const committed = submitPredecessorEvent(fixture, {
    eventId: "p1-committed-historical-preflight",
    type: "P1_COMMITTED",
    role: "CAPTAIN",
    threadId: captainThreadId,
    actorSequence: 3,
    capabilityFile: captain.actor_capability_file,
    fullHead: candidateHead,
    payload: {
      ...p1Payload,
      approval_event_id: approvalEventId,
    },
  });
  if (committed.result.status !== 0) {
    throw new Error(
      `historical P1_COMMITTED failed: ${
        committed.result.stderr || committed.result.stdout
      }`,
    );
  }
  const dev = registerPredecessorRole(fixture, {
    role: "DEV",
    threadId: devThreadId,
    authorizerCapabilityFile: captain.actor_capability_file,
    launchId,
  });
  const registeredState = predecessorTaskState(fixture);
  const launch = {
    schema_version: 1,
    launch_id: launchId,
    goal_id: fixture.primaryGoalId,
    task_id: fixture.primaryTaskId,
    role: "DEV",
    control_epoch: registeredState.control_epoch,
    state_revision: dev.session.registered_state_revision,
    thread: {
      id: devThreadId,
      host_id: "local",
      cwd: fixture.predecessorWorktree,
    },
    packet: {
      ...registeredState.packet,
      path:
        `docs/planning/goals/${fixture.primaryGoalId}/packets/`
        + `${fixture.primaryTaskId}-r1.md`,
    },
    repository: {
      name_with_owner: "example-org/example-repo",
      origin_url: "https://github.com/example-org/example-repo.git",
      base_branch: "main",
      base_head: registeredState.base_head,
      full_head: candidateHead,
      branch: "codex/historical-accepted-preflight",
      root: fixture.predecessorWorktree,
      worktree: fixture.predecessorWorktree,
    },
    runtime: {
      node_version: process.version,
      pnpm_version: "10.0.0-test",
      lockfile_sha256: hashObject({
        fixture: "historical-accepted-preflight",
      }),
    },
    execution: {
      environment: "none",
      write_mode: "NONE",
      task_nonce: dev.session.task_nonce,
      target: {
        kind: "NONE",
      },
    },
    pull_request: null,
    resource_leases: [],
    created_at: "2026-07-26T02:00:00.000Z",
  };
  const canonicalLaunchFile = path.join(
    fixture.controlRoot,
    "goals",
    fixture.primaryGoalId,
    "launches",
    fixture.primaryTaskId,
    `${launchId}.json`,
  );
  writeFixtureJson(canonicalLaunchFile, launch);
  const launched = submitPredecessorEvent(fixture, {
    eventId: "launch-dev-historical-preflight",
    type: "LAUNCH_DEV",
    role: "CAPTAIN",
    threadId: captainThreadId,
    actorSequence: 4,
    capabilityFile: captain.actor_capability_file,
    payload: { launch_id: launchId },
  });
  if (launched.result.status !== 0) {
    throw new Error(
      `historical LAUNCH_DEV failed: ${
        launched.result.stderr || launched.result.stdout
      }`,
    );
  }
  const devActive = predecessorTaskState(fixture);
  const evidenceId =
    "preflight-accepted-historical-overwritten-canonical";
  const preflight = writeFixtureEvidence(fixture, {
    evidenceId,
    kind: "PREFLIGHT",
    status: "PASS",
    producerRole: "DEV",
    producerThreadId: devThreadId,
    state: devActive,
    fullHead: candidateHead,
    launch,
  });
  if (!preflight.immutableLaunchFile) {
    throw new Error("historical immutable launch missing");
  }
  const fast = writeFixtureEvidence(fixture, {
    evidenceId: "fast-accepted-historical-preflight",
    kind: "FAST",
    status: "PASS",
    producerRole: "DEV",
    producerThreadId: devThreadId,
    state: devActive,
    fullHead: candidateHead,
  });
  const fullCi = writeFixtureEvidence(fixture, {
    evidenceId: "full-ci-accepted-historical-preflight",
    kind: "FULL_CI",
    status: "PASS",
    producerRole: "CAPTAIN",
    producerThreadId: captainThreadId,
    state: devActive,
    fullHead: candidateHead,
    pullRequest: true,
  });
  const acAudit = writeFixtureEvidence(fixture, {
    evidenceId: "ac-audit-accepted-historical-preflight",
    kind: "AC_AUDIT",
    status: "PASS",
    producerRole: "CAPTAIN",
    producerThreadId: captainThreadId,
    state: devActive,
    fullHead: candidateHead,
    pullRequest: true,
  });
  const accepted = submitPredecessorEvent(fixture, {
    eventId: "dev-ready-accepted-historical-preflight",
    type: "DEV_READY",
    role: "DEV",
    threadId: devThreadId,
    actorSequence: 1,
    capabilityFile: dev.actor_capability_file,
    fullHead: candidateHead,
    payload: {
      pr: "https://github.com/example-org/example-repo/pull/999",
      evidence: {
        preflight: evidenceId,
        fast: fast.record.evidence_id,
        full_ci: fullCi.record.evidence_id,
        ac_audit: acAudit.record.evidence_id,
      },
    },
  });
  if (accepted.result.status !== 0 || !accepted.acceptedEventFile) {
    throw new Error(
      `historical DEV_READY failed: ${
        accepted.result.stderr || accepted.result.stdout
      }`,
    );
  }
  const acceptedEvent = JSON.parse(readFileSync(
    accepted.acceptedEventFile,
    "utf8",
  )) as Record<string, unknown>;
  const overwrittenLaunch = {
    ...launch,
    repository: {
      ...launch.repository,
      full_head: "f".repeat(40),
    },
    created_at: "2026-07-26T03:00:00.000Z",
  };
  writeFixtureJson(canonicalLaunchFile, overwrittenLaunch);
  const immutableLaunchSha256 =
    `sha256:${sha256(readFileSync(preflight.immutableLaunchFile))}`;
  const canonicalLaunchSha256 =
    `sha256:${sha256(readFileSync(canonicalLaunchFile))}`;
  if (immutableLaunchSha256 === canonicalLaunchSha256) {
    throw new Error("historical canonical launch was not overwritten");
  }
  return {
    evidenceId,
    registryFile: preflight.registryFile,
    canonicalLaunchFile,
    immutableLaunchFile: preflight.immutableLaunchFile,
    record: preflight.record,
    canonicalLaunchSha256,
    immutableLaunchSha256,
    acceptedEventFile: accepted.acceptedEventFile,
    acceptedEvent,
  };
}

function completeControlTree(
  root: string,
): Array<[string, string, string]> {
  const entries: Array<[string, string, string]> = [];
  const visit = (directory: string, relativeDirectory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const relative = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      const absolute = path.join(directory, name);
      const stat = lstatSync(absolute);
      const mode = (stat.mode & 0o7777).toString(8);
      if (stat.isDirectory()) {
        entries.push(["directory", relative, mode]);
        visit(absolute, relative);
      } else if (stat.isSymbolicLink()) {
        entries.push([
          "symlink",
          relative,
          `${mode}:${readlinkSync(absolute)}`,
        ]);
      } else {
        entries.push([
          "file",
          relative,
          `${mode}:${readFileSync(absolute).toString("base64")}`,
        ]);
      }
    }
  };
  visit(root, "");
  return entries;
}

function writeFixtureGoalWorktreeMap(
  fixture: PendingBootstrapRotationFixture,
): string {
  const file = path.join(
    path.dirname(fixture.repository),
    "goal-worktrees.json",
  );
  writeFixtureJson(file, {
    schema_version: 1,
    goal_worktrees: fixture.goalIds.map((goalId) => ({
      goal_id: goalId,
      repository_worktree: fixture.predecessorWorktree,
    })),
  });
  return realpathSync(file);
}

function fixtureRotationArgs(
  fixture: PendingBootstrapRotationFixture,
  options: {
    goalWorktreesFile?: string | null;
    expectedPredecessorSealSha256?: string;
    predecessorControllerWorktree?: string;
    rotationId?: string;
    incidentRef?: string;
  } = {},
): string[] {
  const args = [
    "rotate-store-protocol",
    "--repository-worktree",
    fixture.predecessorWorktree,
    "--rotation-id",
    options.rotationId ?? "rotation-cli-success",
    "--predecessor-controller-worktree",
    options.predecessorControllerWorktree
      ?? fixture.predecessorWorktree,
  ];
  if (options.goalWorktreesFile !== null) {
    args.push(
      "--goal-worktrees-file",
      options.goalWorktreesFile
        ?? writeFixtureGoalWorktreeMap(fixture),
    );
  }
  args.push(
    "--expected-predecessor-seal-sha256",
    options.expectedPredecessorSealSha256
      ?? fixture.predecessorProtocol.seal_sha256,
    "--incident-ref",
    options.incidentRef
      ?? "incident://goal-control/rotation-cli-success",
    "--acknowledge-old-controller-drained",
    "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
    "--json",
  );
  return args;
}

function exactRetryAfterGenerationCompleteCrash(
  fault: string,
  expectedCrashedGeneration: 1 | 2,
): void {
  const root = sandbox();
  const { protocol: predecessor, artifact } =
    createSchema2Predecessor(root);
  const request = requestFor(predecessor);
  const report = validationReport(root);
  const artifactBefore = artifactIdentity(artifact);
  const crashScript = `
    const { rotateRootProtocol } = require(process.argv[1]);
    const root = process.argv[2];
    const request = JSON.parse(process.argv[3]);
    const report = JSON.parse(process.argv[4]);
    rotateRootProtocol(
      root,
      () => ({ report }),
      request,
      {
        staleMilliseconds: 0,
        timeoutMilliseconds: 2000,
      },
    );
  `;
  const crashed = spawnSync(
    process.execPath,
    [
      "-e",
      crashScript,
      storeModulePath,
      root,
      JSON.stringify(request),
      JSON.stringify(report),
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        GOAL_CONTROL_TEST_MODE: "1",
        [fault]: "sigkill",
      },
    },
  );

  expect(crashed.error).toBeUndefined();
  expect(crashed.status).toBeNull();
  expect(crashed.signal).toBe("SIGKILL");
  const crashedGeneration = JSON.parse(readFileSync(
    path.join(root, ".generation.json"),
    "utf8",
  )) as {
    generation: number;
    active_transaction: TransactionKey | null;
    pre_write_vector_sha256: string | null;
  };
  expect(crashedGeneration.generation).toBe(expectedCrashedGeneration);
  if (expectedCrashedGeneration === 1) {
    expect(crashedGeneration.active_transaction).toMatchObject({
      kind: "PROTOCOL_ROTATION",
    });
    expect(crashedGeneration.pre_write_vector_sha256)
      .toMatch(/^sha256:[0-9a-f]{64}$/);
  } else {
    expect(crashedGeneration.active_transaction).toBeNull();
    expect(crashedGeneration.pre_write_vector_sha256).toBeNull();
  }
  const crashedProtocolFile = path.join(root, ".store-protocol.json");
  const crashedProtocolBytes = readFileSync(crashedProtocolFile);
  const crashedProtocol = JSON.parse(
    crashedProtocolBytes.toString("utf8"),
  ) as RootProtocol;
  const receiptDescriptor = crashedProtocol.protocol_rotations?.[0];
  if (!receiptDescriptor) {
    throw new Error("generation-complete crash lost rotation receipt");
  }
  const receiptFile = path.join(root, receiptDescriptor.relative_path);
  const receiptBytes = readFileSync(receiptFile);
  const receipt = JSON.parse(
    receiptBytes.toString("utf8"),
  ) as RotationReceipt;
  expect(receipt.entry_generation).toBe(0);
  expect(receipt.exit_generation).toBe(2);
  expect(readRootProtocolSeal(root)).toEqual(crashedProtocol);
  const atomicTransport = path.join(root, ".atomic-transactions");
  expect(existsSync(atomicTransport)).toBe(true);
  expect(readdirSync(atomicTransport).length).toBeGreaterThan(0);
  expect(lstatSync(path.join(root, ".lock")).isSymbolicLink()).toBe(true);

  let retryValidatorCalls = 0;
  const recovered = rotateRootProtocol(
    root,
    () => {
      retryValidatorCalls += 1;
      return { report };
    },
    request,
    {
      staleMilliseconds: 0,
      timeoutMilliseconds: 2000,
    },
  );

  expect(retryValidatorCalls).toBe(0);
  expect(recovered).toMatchObject({
    rotated: false,
    idempotent: true,
    entry_generation: 0,
    exit_generation: 2,
    rotation_receipt: receiptDescriptor,
    validation: report,
  });
  const completedGeneration = JSON.parse(readFileSync(
    path.join(root, ".generation.json"),
    "utf8",
  )) as {
    generation: number;
    active_transaction: unknown;
    pre_write_vector_sha256: unknown;
  };
  expect(completedGeneration).toMatchObject({
    generation: receipt.exit_generation,
    active_transaction: null,
    pre_write_vector_sha256: null,
  });
  expect(readFileSync(crashedProtocolFile)).toEqual(crashedProtocolBytes);
  expect(readFileSync(receiptFile)).toEqual(receiptBytes);
  expect(artifactIdentity(artifact)).toEqual(artifactBefore);
  expectTransportClean(root);
}

afterEach(() => {
  for (const root of sandboxes.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("goal-control root protocol rotation", () => {
  it("accepts only an exact canonical STALE_HEAD parent/candidate mismatch", () => {
    const observedHead = "1".repeat(40);
    const launchHead = "2".repeat(40);
    const canonical = {
      repository: { full_head: launchHead },
      execution: {
        target: {
          kind: "PREVIEW",
          build_head: launchHead,
          pid: 123,
        },
      },
      marker: "canonical",
    };
    const candidate = JSON.parse(JSON.stringify(canonical));
    const staleFailure = {
      name: "repository-identity",
      status: "FAIL",
      detail:
        `STALE_HEAD: 当前 HEAD ${observedHead} 与 launch 不一致`,
    };
    const parent = { full_head: observedHead };

    expect(parentCandidateHeadBinding(
      parent,
      candidate,
      [staleFailure],
      canonical,
    )).toBe(true);
    expect(parentCandidateHeadBinding(
      parent,
      candidate,
      [{
        ...staleFailure,
        detail:
          `STALE_HEAD: 当前 HEAD ${"3".repeat(40)} 与 launch 不一致`,
      }],
      canonical,
    )).toBe(false);
    expect(parentCandidateHeadBinding(
      parent,
      {
        ...candidate,
        repository: { full_head: observedHead },
        execution: {
          target: {
            ...candidate.execution.target,
            build_head: observedHead,
          },
        },
      },
      [staleFailure],
      canonical,
    )).toBe(false);
    expect(parentCandidateHeadBinding(
      parent,
      {
        ...candidate,
        execution: {
          target: {
            ...candidate.execution.target,
            pid: 456,
          },
        },
      },
      [staleFailure],
      canonical,
    )).toBe(false);
    expect(parentCandidateHeadBinding(
      parent,
      candidate,
      [staleFailure, { ...staleFailure }],
      canonical,
    )).toBe(false);
    expect(parentCandidateHeadBinding(
      parent,
      candidate,
      [{
        ...staleFailure,
        detail: "BRANCH_MISMATCH: 当前 branch 与 launch 不一致",
      }],
      canonical,
    )).toBe(false);
    expect(parentCandidateHeadBinding(
      { full_head: launchHead },
      candidate,
      [],
      canonical,
    )).toBe(true);
    expect(parentCandidateHeadBinding(
      parent,
      candidate,
      [],
      canonical,
    )).toBe(false);
  });

  it("fails closed before adoption or rotation when legacy REVIEW_REWORK left an active DEV canonical launch with a PR binding", () => {
    const root = sandbox();
    const goalId = "goal-legacy-review-rework";
    const taskId = "TASK-LEGACY";
    const launchId = "launch-legacy-dev-with-pr";
    const threadId = "legacy-dev-thread";
    const launchFile = path.join(
      root,
      "goals",
      goalId,
      "launches",
      taskId,
      `${launchId}.json`,
    );
    writeFixtureJson(launchFile, {
      schema_version: 1,
      goal_id: goalId,
      task_id: taskId,
      launch_id: launchId,
      role: "DEV",
      thread: {
        id: threadId,
        host_id: "local",
      },
      pull_request: {
        repository: "example-org/example-repo",
        number: 4342,
        base: "main",
        head: "a".repeat(40),
      },
    });
    const loaded = {
      manifest: {
        goal_id: goalId,
        tasks: [{ id: taskId }],
      },
      snapshot: {
        tasks: {
          [taskId]: {
            sessions: {
              DEV: {
                status: "active",
                launch_id: launchId,
                thread_id: threadId,
                host_id: "local",
              },
            },
          },
        },
      },
    };

    let rejected: unknown = null;
    try {
      assertSuccessorCompatibleActiveDevLaunches(root, loaded);
    } catch (error) {
      rejected = error;
    }

    expect(rejected).toMatchObject({
      code: "STORE_MIGRATION_ACTIVE_DEV_PR_LAUNCH_UNSUPPORTED",
      message: expect.stringContaining(
        "禁止直接删除/覆盖 canonical launch 或 append-only ledger",
      ),
    });

    writeFixtureJson(launchFile, {
      schema_version: 1,
      goal_id: goalId,
      task_id: taskId,
      launch_id: launchId,
      role: "DEV",
      thread: {
        id: threadId,
        host_id: "local",
      },
      pull_request: null,
    });
    expect(() => assertSuccessorCompatibleActiveDevLaunches(root, loaded))
      .not.toThrow();

    writeFixtureJson(launchFile, {
      schema_version: 1,
      goal_id: goalId,
      task_id: taskId,
      launch_id: launchId,
      role: "DEV",
      thread: {
        id: threadId,
        host_id: "local",
      },
      pull_request: {
        repository: "example-org/example-repo",
        number: 4342,
        base: "main",
        head: "a".repeat(40),
      },
    });
    loaded.snapshot.tasks[taskId].sessions.DEV.status = "terminal";
    expect(() => assertSuccessorCompatibleActiveDevLaunches(root, loaded))
      .not.toThrow();
  });

  it("rotates a schema-3 predecessor without rejecting its own pending receipt inventory", () => {
    const root = sandbox();
    const { protocol: predecessor } =
      createSchema3Predecessor(root);
    const request = {
      ...requestFor(predecessor),
      rotationId: "rotate-schema-3-decoder-20260726",
    };

    const rotated = rotateRootProtocol(
      root,
      validatorFor(root),
      request,
    );

    expect(rotated).toMatchObject({
      rotated: true,
      idempotent: false,
      predecessor_protocol: {
        schema_version: 3,
        seal_sha256: predecessor.seal_sha256,
      },
      protocol: {
        schema_version: 3,
        protocol_rotations: [rotated.rotation_receipt],
      },
    });
    expect(readRootProtocolSeal(root)).toEqual(rotated.protocol);
    expectTransportClean(root);
  });

  it("exact-retries a schema-3 rotation interrupted after pending receipt publication", () => {
    const root = sandbox();
    const { protocol: predecessor } =
      createSchema3Predecessor(root);
    const request = {
      ...requestFor(predecessor),
      rotationId: "retry-schema-3-pending-receipt-20260726",
    };
    let interrupted = false;
    let validatorCalls = 0;
    const validator = (): { report: RotationReport } => {
      validatorCalls += 1;
      return { report: validationReport(root) };
    };

    expect(() => withGoalControlTestMode(() => (
      rotateRootProtocol(
        root,
        validator,
        request,
        {
          afterRotationReceiptInstalled: () => {
            if (interrupted) return;
            interrupted = true;
            throw new Error(
              "interrupt after pending receipt publication",
            );
          },
        },
      )
    ))).toThrow("interrupt after pending receipt publication");
    expect(validatorCalls).toBe(1);

    expect(() => readRootProtocolSeal(root)).toThrow(
      expect.objectContaining({ code: "CORRUPT_STORE_PROTOCOL" }),
    );
    expect(readdirSync(
      path.join(root, ".protocol-rotations.v1"),
    )).toHaveLength(1);
    expect(() => rotateRootProtocol(
      root,
      validator,
      {
        ...request,
        incidentRef: "incident://different-rotation-request",
      },
    )).toThrow(
      expect.objectContaining({ code: "CORRUPT_STORE_PROTOCOL" }),
    );

    const retried = rotateRootProtocol(
      root,
      validator,
      request,
    );
    expect(validatorCalls).toBe(1);

    expect(retried).toMatchObject({
      rotated: true,
      idempotent: false,
      predecessor_protocol: {
        schema_version: 3,
        seal_sha256: predecessor.seal_sha256,
      },
      protocol: {
        schema_version: 3,
        protocol_rotations: [retried.rotation_receipt],
      },
    });
    expect(readRootProtocolSeal(root)).toEqual(retried.protocol);
    expectTransportClean(root);
  });

  it("rejects a digest-valid receipt without exact odd rotation lineage", () => {
    const root = sandbox();
    const { protocol: predecessor } =
      createSchema3Predecessor(root);
    const request = {
      ...requestFor(predecessor),
      rotationId: "reject-unowned-schema-3-receipt-20260726",
    };

    rotateRootProtocol(
      root,
      validatorFor(root),
      request,
    );
    writeFileSync(
      path.join(root, ".store-protocol.json"),
      `${JSON.stringify(predecessor, null, 2)}\n`,
      { mode: 0o600 },
    );

    expect(() => readRootProtocolSeal(root)).toThrow(
      expect.objectContaining({ code: "CORRUPT_STORE_PROTOCOL" }),
    );
    const beforeRejectedRetry = payloadTree(root);
    expect(() => rotateRootProtocol(
      root,
      validatorFor(root),
      request,
    )).toThrow(
      expect.objectContaining({ code: "CORRUPT_STORE_PROTOCOL" }),
    );
    expect(payloadTree(root)).toEqual(beforeRejectedRetry);
  });

  it("rotates an even schema-2 predecessor to a self-bound schema-3 protocol and retries idempotently", () => {
    const root = sandbox();
    const { protocol: predecessor, artifact } =
      createSchema2Predecessor(root);
    const request = requestFor(predecessor);
    const report = validationReport(root);
    const artifactBefore = artifactIdentity(artifact);
    let validatorCalls = 0;

    const rotated = rotateRootProtocol(
      root,
      () => {
        validatorCalls += 1;
        return { report };
      },
      request,
    );

    expect(validatorCalls).toBe(1);
    expect(rotated).toMatchObject({
      rotated: true,
      idempotent: false,
      entry_generation: 0,
      exit_generation: 2,
      predecessor_protocol: {
        schema_version: 2,
        seal_sha256: predecessor.seal_sha256,
      },
      validation: report,
    });
    expect(rotated.source_state_vector_sha256)
      .toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(rotated.sealed_state_vector_sha256)
      .toMatch(/^sha256:[0-9a-f]{64}$/);

    const protocol = JSON.parse(readFileSync(
      path.join(root, ".store-protocol.json"),
      "utf8",
    )) as RootProtocol;
    const protocolUnsigned = { ...protocol } as Record<string, unknown>;
    delete protocolUnsigned.seal_sha256;
    expect(protocol).toMatchObject({
      schema_version: 3,
      controller_decoder_version: 3,
      controller_decoder_sha256: controllerDecoderFingerprint(),
      lock_protocol_version: 2,
      migration_source_state_vector_sha256:
        predecessor.migration_source_state_vector_sha256,
      migration_artifacts: predecessor.migration_artifacts,
      protocol_rotations: [rotated.rotation_receipt],
    });
    expect(protocol.seal_sha256).toBe(hashObject(protocolUnsigned));
    expect(readRootProtocolSeal(root)).toEqual(protocol);

    const receiptDescriptor = protocol.protocol_rotations?.[0];
    expect(receiptDescriptor).toBeDefined();
    const receiptFile = path.join(
      root,
      receiptDescriptor?.relative_path ?? "",
    );
    const receiptBody = readFileSync(receiptFile);
    const receipt = JSON.parse(
      receiptBody.toString("utf8"),
    ) as RotationReceipt;
    expect(receiptBody).toEqual(
      Buffer.from(`${canonicalJson(receipt)}\n`),
    );
    expect(receiptDescriptor?.sha256)
      .toBe(`sha256:${sha256(receiptBody)}`);
    expect(path.basename(receiptFile)).toBe(
      `${receiptDescriptor?.sha256.slice("sha256:".length)}.json`,
    );
    expect(lstatSync(receiptFile).mode & 0o777).toBe(0o600);
    const receiptUnsigned = { ...receipt } as Record<string, unknown>;
    delete receiptUnsigned.receipt_sha256;
    expect(receipt.receipt_sha256).toBe(hashObject(receiptUnsigned));
    expect(receipt).toMatchObject({
      rotation_id: request.rotationId,
      incident_ref: request.incidentRef,
      old_controller_drain_ack:
        request.oldControllerDrainAcknowledgment,
      predecessor_protocol: {
        schema_version: 2,
        seal_sha256: predecessor.seal_sha256,
      },
      successor_protocol: {
        schema_version: 3,
        controller_decoder_sha256: controllerDecoderFingerprint(),
      },
      migration_artifacts_sha256:
        hashObject(predecessor.migration_artifacts),
      validation_report: report,
      validation_report_sha256: hashObject(report),
      goal_worktree_map: report.goal_worktree_map,
      goal_worktree_map_sha256:
        hashObject(report.goal_worktree_map),
      entry_generation: 0,
      exit_generation: 2,
      operator_request_sha256: request.operatorRequestSha256,
    });
    const receiptRequest = {
      schema_version: 1,
      rotation_id: receipt.rotation_id,
      incident_ref: receipt.incident_ref,
      old_controller_drain_ack: receipt.old_controller_drain_ack,
      expected_predecessor_seal_sha256:
        receipt.predecessor_protocol.seal_sha256,
      operator_request_sha256: receipt.operator_request_sha256,
      predecessor_protocol: receipt.predecessor_protocol,
      successor_protocol: receipt.successor_protocol,
      migration_artifacts_sha256:
        receipt.migration_artifacts_sha256,
      source_state_vector_sha256:
        receipt.source_state_vector_sha256,
      validation_report_sha256:
        receipt.validation_report_sha256,
      goal_worktree_map_sha256:
        receipt.goal_worktree_map_sha256,
    };
    expect(receipt.request_sha256).toBe(hashObject(receiptRequest));

    const artifactAfter = artifactIdentity(artifact);
    expect(artifactAfter.inode).toBe(artifactBefore.inode);
    expect(artifactAfter.mode).toBe(artifactBefore.mode);
    expect(artifactAfter.bytes).toEqual(artifactBefore.bytes);
    const generation = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      schema_version: number;
      generation: number;
      active_transaction: unknown;
      pre_write_vector_sha256: unknown;
    };
    expect(generation).toMatchObject({
      schema_version: 3,
      generation: 2,
      active_transaction: null,
      pre_write_vector_sha256: null,
    });
    expect(generation.generation % 2).toBe(0);
    expectTransportClean(root);

    const retry = rotateRootProtocol(
      root,
      () => {
        validatorCalls += 1;
        return { report };
      },
      request,
    );
    expect(validatorCalls).toBe(1);
    expect(retry).toMatchObject({
      rotated: false,
      idempotent: true,
      entry_generation: 0,
      exit_generation: 2,
      rotation_receipt: receiptDescriptor,
      validation: report,
    });
    expect(readFileSync(receiptFile)).toEqual(receiptBody);
    expect(artifactIdentity(artifact)).toEqual(artifactBefore);
    expectTransportClean(root);
  });

  it("fails closed on weak protocol bytes or an unsealed rotation namespace entry", () => {
    const root = sandbox();
    const { protocol: predecessor } = createSchema2Predecessor(root);
    const rotated = rotateRootProtocol(
      root,
      validatorFor(root),
      requestFor(predecessor),
    );
    const protocolFile = path.join(root, ".store-protocol.json");
    const protocolBytes = readFileSync(protocolFile);
    const protocol = JSON.parse(
      protocolBytes.toString("utf8"),
    ) as RootProtocol;
    const receiptDescriptor = rotated.rotation_receipt;
    const receiptFile = path.join(root, receiptDescriptor.relative_path);
    const receiptBytes = readFileSync(receiptFile);
    const rotationDirectory = path.dirname(receiptFile);
    const expectRejected = (): void => {
      expect(() => readRootProtocolSeal(root)).toThrow(
        expect.objectContaining({ code: "CORRUPT_STORE_PROTOCOL" }),
      );
    };
    const expectRestored = (): void => {
      expect(readRootProtocolSeal(root)).toEqual(protocol);
    };

    chmodSync(protocolFile, 0o666);
    expectRejected();
    chmodSync(protocolFile, 0o600);
    expectRestored();

    const protocolLink = path.join(root, ".foreign-protocol-link");
    linkSync(protocolFile, protocolLink);
    expectRejected();
    unlinkSync(protocolLink);
    expectRestored();

    const protocolBackup = path.join(root, ".protocol-authority-backup");
    renameSync(protocolFile, protocolBackup);
    symlinkSync(path.basename(protocolBackup), protocolFile);
    expectRejected();
    unlinkSync(protocolFile);
    renameSync(protocolBackup, protocolFile);
    expectRestored();

    renameSync(protocolFile, protocolBackup);
    writeFileSync(
      protocolFile,
      Buffer.alloc((16 * 1024 * 1024) + 1, 0x70),
      { mode: 0o600 },
    );
    expectRejected();
    unlinkSync(protocolFile);
    renameSync(protocolBackup, protocolFile);
    expect(readFileSync(protocolFile)).toEqual(protocolBytes);
    expectRestored();

    chmodSync(receiptFile, 0o666);
    expectRejected();
    chmodSync(receiptFile, 0o600);
    expectRestored();

    const receiptLink = path.join(root, ".foreign-receipt-link");
    linkSync(receiptFile, receiptLink);
    expectRejected();
    unlinkSync(receiptLink);
    expectRestored();

    const receiptBackup = path.join(root, ".receipt-authority-backup");
    renameSync(receiptFile, receiptBackup);
    symlinkSync(
      path.relative(rotationDirectory, receiptBackup),
      receiptFile,
    );
    expectRejected();
    unlinkSync(receiptFile);
    renameSync(receiptBackup, receiptFile);
    expectRestored();

    renameSync(receiptFile, receiptBackup);
    writeFileSync(
      receiptFile,
      Buffer.alloc((16 * 1024 * 1024) + 1, 0x72),
      { mode: 0o600 },
    );
    expectRejected();
    unlinkSync(receiptFile);
    renameSync(receiptBackup, receiptFile);
    expect(readFileSync(receiptFile)).toEqual(receiptBytes);
    expectRestored();

    const foreignFile = path.join(rotationDirectory, "foreign.json");
    writeFileSync(foreignFile, "{}\n", { mode: 0o600 });
    expectRejected();
    unlinkSync(foreignFile);
    expectRestored();

    const foreignDirectory = path.join(rotationDirectory, "foreign-dir");
    mkdirSync(foreignDirectory, { mode: 0o700 });
    expectRejected();
    rmSync(foreignDirectory, { recursive: true, force: true });
    expectRestored();

    const foreignSymlink = path.join(rotationDirectory, "foreign-link");
    symlinkSync(path.basename(receiptFile), foreignSymlink);
    expectRejected();
    unlinkSync(foreignSymlink);
    expectRestored();

    chmodSync(rotationDirectory, 0o755);
    expectRejected();
    chmodSync(rotationDirectory, 0o700);
    expectRestored();
  }, 30_000);

  it.each([
    ["GOAL_INIT", "STORE_PROTOCOL_ROTATION_EVEN_REQUIRED"],
    ["PROTOCOL_ROTATION", "STORE_TRANSACTION_MISMATCH"],
  ])(
    "rejects foreign %s odd state without changing payload bytes",
    (kind, expectedCode) => {
      const root = sandbox();
      const { protocol: predecessor } =
        createSchema2Predecessor(root);
      const request = requestFor(predecessor);
      const foreignTransaction = canonicalTransactionKey(
        kind,
        { control_root: path.resolve(root) },
        `foreign-${kind.toLowerCase()}`,
        hashObject({ foreign: kind }),
      );
      writeOddGeneration(root, foreignTransaction);
      const before = payloadTree(root);
      let validatorCalls = 0;
      let thrown: unknown = null;

      try {
        rotateRootProtocol(
          root,
          () => {
            validatorCalls += 1;
            return { report: validationReport(root) };
          },
          request,
        );
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toMatchObject({ code: expectedCode });
      expect(payloadTree(root)).toEqual(before);
      expect(validatorCalls).toBe(kind === "PROTOCOL_ROTATION" ? 1 : 0);
      expectTransportClean(root);
    },
  );

  it("recovers only the exact request after successor publication at an odd generation", () => {
    const root = sandbox();
    const { protocol: predecessor, artifact } =
      createSchema2Predecessor(root);
    const request = requestFor(predecessor);
    const artifactBefore = artifactIdentity(artifact);
    const injected = new Error("injected protocol-publication crash");

    expect(() => withGoalControlTestMode(() => rotateRootProtocol(
      root,
      validatorFor(root),
      request,
      {
        afterRotationProtocolInstalled: () => {
          throw injected;
        },
      },
    ))).toThrow(injected);

    const crashedProtocol = readRootProtocolSeal(root);
    expect(crashedProtocol).toMatchObject({
      schema_version: 3,
      protocol_rotations: [expect.any(Object)],
    });
    const crashedGeneration = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey;
    };
    expect(crashedGeneration.generation % 2).toBe(1);
    expect(crashedGeneration.active_transaction).toMatchObject({
      kind: "PROTOCOL_ROTATION",
    });
    expectTransportClean(root);

    const wrongRequest = {
      ...request,
      operatorRequestSha256:
        hashObject({ operator_request: "foreign-recovery" }),
    };
    const beforeWrongRetry = payloadTree(root);
    let wrongError: unknown = null;
    try {
      rotateRootProtocol(
        root,
        validatorFor(root),
        wrongRequest,
      );
    } catch (error) {
      wrongError = error;
    }
    expect(wrongError).toMatchObject({
      code: "STORE_PROTOCOL_ROTATION_PREDECESSOR_MISMATCH",
    });
    expect(payloadTree(root)).toEqual(beforeWrongRetry);
    expectTransportClean(root);

    const recovered = rotateRootProtocol(
      root,
      validatorFor(root),
      request,
    );
    expect(recovered).toMatchObject({
      rotated: true,
      idempotent: false,
      entry_generation: 0,
      exit_generation: 2,
    });
    const recoveredGeneration = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      generation: number;
      active_transaction: unknown;
      pre_write_vector_sha256: unknown;
    };
    expect(recoveredGeneration).toMatchObject({
      generation: 2,
      active_transaction: null,
      pre_write_vector_sha256: null,
    });
    expect(artifactIdentity(artifact)).toEqual(artifactBefore);
    expectTransportClean(root);
  });

  it("exact-retries through a crashed request-bound reaper without consuming a foreign-prefix artifact", () => {
    const root = sandbox();
    const { protocol: predecessor, artifact } =
      createSchema2Predecessor(root);
    const request = requestFor(predecessor);
    const report = validationReport(root);
    const artifactBefore = artifactIdentity(artifact);
    const crashScript = `
      const { rotateRootProtocol } = require(process.argv[1]);
      const root = process.argv[2];
      const request = JSON.parse(process.argv[3]);
      const report = JSON.parse(process.argv[4]);
      rotateRootProtocol(
        root,
        () => ({ report }),
        request,
        {
          staleMilliseconds: 0,
          timeoutMilliseconds: 2000,
          afterRotationProtocolInstalled: () => {
            process.kill(process.pid, "SIGKILL");
          },
        },
      );
    `;
    const crashed = spawnSync(
      process.execPath,
      [
        "-e",
        crashScript,
        storeModulePath,
        root,
        JSON.stringify(request),
        JSON.stringify(report),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );

    expect(crashed.error).toBeUndefined();
    expect(crashed.status).toBeNull();
    expect(crashed.signal).toBe("SIGKILL");
    const lock = path.join(root, ".lock");
    expect(lstatSync(lock).isSymbolicLink()).toBe(true);
    const backingName = readlinkSync(lock);
    expect(backingName).toMatch(
      /^\.lock\.owner\.writer-rotation-[0-9a-f]{20}-attempt-[0-9a-f]{24}$/,
    );
    const backing = path.join(root, backingName);
    expect(lstatSync(backing).isDirectory()).toBe(true);
    const staleOwner = JSON.parse(readFileSync(
      path.join(backing, "owner.json"),
      "utf8",
    )) as {
      pid: number;
      nonce: string;
      kind: string;
    };
    expect(staleOwner).toMatchObject({
      pid: crashed.pid,
      kind: "WRITER",
      nonce: backingName.slice(".lock.owner.".length),
    });
    expect(staleOwner.nonce).toMatch(
      /^writer-rotation-[0-9a-f]{20}-attempt-[0-9a-f]{24}$/,
    );
    const crashedGeneration = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      generation: number;
      active_transaction: TransactionKey;
    };
    expect(crashedGeneration.generation % 2).toBe(1);
    expect(crashedGeneration.active_transaction.kind)
      .toBe("PROTOCOL_ROTATION");
    expect(readRootProtocolSeal(root)).toMatchObject({
      schema_version: 3,
      protocol_rotations: [expect.any(Object)],
    });
    const protocolAfterWriterCrash = readFileSync(
      path.join(root, ".store-protocol.json"),
    );
    const receiptDescriptor = (
      JSON.parse(protocolAfterWriterCrash.toString("utf8")) as RootProtocol
    ).protocol_rotations?.[0];
    if (!receiptDescriptor) {
      throw new Error("writer crash lost protocol rotation receipt");
    }
    const receiptFile = path.join(root, receiptDescriptor.relative_path);
    const receiptAfterWriterCrash = readFileSync(receiptFile);
    const payloadAfterWriterCrash = payloadTree(root);
    const foreign = installForeignRequestWriterArtifact(root, backing);
    expect(foreign.nonce).not.toContain(
      staleOwner.nonce.match(
        /^writer-(rotation-[0-9a-f]{20}-)attempt-/,
      )?.[1] ?? "missing-request-prefix",
    );

    const reaperCrashScript = `
      const { rotateRootProtocol } = require(process.argv[1]);
      const root = process.argv[2];
      const request = JSON.parse(process.argv[3]);
      rotateRootProtocol(
        root,
        () => {
          throw new Error("sealed exact recovery must not replay validator");
        },
        request,
        {
          staleMilliseconds: 0,
          timeoutMilliseconds: 2000,
          afterReaperMutexAcquired: () => {
            process.kill(process.pid, "SIGKILL");
          },
        },
      );
    `;
    const crashedReaper = spawnSync(
      process.execPath,
      [
        "-e",
        reaperCrashScript,
        storeModulePath,
        root,
        JSON.stringify(request),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );

    expect(crashedReaper.error).toBeUndefined();
    expect(crashedReaper.status).toBeNull();
    expect(crashedReaper.signal).toBe("SIGKILL");
    expect(readlinkSync(lock)).toBe(backingName);
    expect(existsSync(backing)).toBe(true);
    const reaperMutex = path.join(root, ".lock.reap");
    expect(lstatSync(reaperMutex).isSymbolicLink()).toBe(true);
    const reaperBackingName = readlinkSync(reaperMutex);
    expect(reaperBackingName).toMatch(
      /^\.lock\.reap\.owner\.reaper-rotation-[0-9a-f]{20}-attempt-[0-9a-f]{24}$/,
    );
    const reaperBacking = path.join(root, reaperBackingName);
    const reaperOwner = JSON.parse(readFileSync(
      path.join(reaperBacking, "owner.json"),
      "utf8",
    )) as {
      pid: number;
      nonce: string;
    };
    expect(reaperOwner).toMatchObject({
      pid: crashedReaper.pid,
      nonce: reaperBackingName.slice(
        ".lock.reap.owner.".length,
      ),
    });
    expect(reaperOwner.nonce.replace(/^reaper-/, "writer-").slice(
      0,
      -"attempt-".length - 24,
    )).toBe(staleOwner.nonce.slice(
      0,
      -"attempt-".length - 24,
    ));
    expect(payloadTree(root)).toEqual(payloadAfterWriterCrash);
    expect(readFileSync(
      path.join(foreign.artifact, "owner.json"),
    )).toEqual(foreign.bytes);

    const recoverScript = `
      const { rotateRootProtocol } = require(process.argv[1]);
      const root = process.argv[2];
      const request = JSON.parse(process.argv[3]);
      try {
        const result = rotateRootProtocol(
          root,
          () => {
            throw new Error("sealed exact recovery must not replay validator");
          },
          request,
          {
            staleMilliseconds: 0,
            timeoutMilliseconds: 2000,
          },
        );
        process.stdout.write(JSON.stringify(result));
      } catch (error) {
        process.stderr.write(JSON.stringify({
          code: error && error.code,
          message: error && error.message,
          stack: error && error.stack,
        }));
        process.exit(1);
      }
    `;
    const recoveredChild = spawnSync(
      process.execPath,
      [
        "-e",
        recoverScript,
        storeModulePath,
        root,
        JSON.stringify(request),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );

    expect(recoveredChild.error).toBeUndefined();
    expect(recoveredChild.status).toBe(0);
    expect(recoveredChild.stderr).toBe("");
    const recovered = JSON.parse(recoveredChild.stdout) as {
      rotated: boolean;
      idempotent: boolean;
      entry_generation: number;
      exit_generation: number;
    };
    expect(recovered).toMatchObject({
      rotated: true,
      idempotent: false,
      entry_generation: 0,
      exit_generation: 2,
    });
    const generation = JSON.parse(readFileSync(
      path.join(root, ".generation.json"),
      "utf8",
    )) as {
      generation: number;
      active_transaction: unknown;
      pre_write_vector_sha256: unknown;
    };
    expect(generation).toMatchObject({
      generation: 2,
      active_transaction: null,
      pre_write_vector_sha256: null,
    });
    expect((
      readRootProtocolSeal(root)?.protocol_rotations ?? []
    )).toEqual([receiptDescriptor]);
    expect(readFileSync(
      path.join(root, ".store-protocol.json"),
    )).toEqual(protocolAfterWriterCrash);
    expect(readFileSync(receiptFile)).toEqual(receiptAfterWriterCrash);
    expect(artifactIdentity(artifact)).toEqual(artifactBefore);
    expect(existsSync(lock)).toBe(false);
    expect(existsSync(backing)).toBe(false);
    expect(existsSync(reaperMutex)).toBe(false);
    expect(existsSync(reaperBacking)).toBe(false);
    expect(readdirSync(root).filter((name) => (
      name === ".lock" || name.startsWith(".lock.")
    ))).toEqual([path.basename(foreign.artifact)]);
    expect(readFileSync(
      path.join(foreign.artifact, "owner.json"),
    )).toEqual(foreign.bytes);
    rmSync(foreign.artifact, { recursive: true, force: true });
    expectTransportClean(root);
  });

  it("cleans an orphaned request-bound release claim and idempotently returns without consuming a foreign prefix", () => {
    const root = sandbox();
    const { protocol: predecessor, artifact } =
      createSchema2Predecessor(root);
    const request = requestFor(predecessor);
    const report = validationReport(root);
    const artifactBefore = artifactIdentity(artifact);
    const releaseCrashScript = `
      const fs = require("fs");
      const path = require("path");
      const renameSync = fs.renameSync;
      fs.renameSync = function(source, destination) {
        const sourcePath = String(source);
        const destinationPath = String(destination);
        let expectedRelease = null;
        if (path.basename(sourcePath) === ".lock") {
          try {
            const target = fs.readlinkSync(sourcePath);
            const marker = ".lock.owner.";
            if (target.startsWith(marker)) {
              expectedRelease =
                ".lock.release." + target.slice(marker.length);
            }
          } catch {}
        }
        const shouldCrash = expectedRelease !== null
          && path.basename(destinationPath) === expectedRelease;
        const result = renameSync.apply(fs, arguments);
        if (shouldCrash) {
          process.kill(process.pid, "SIGKILL");
        }
        return result;
      };
      const { rotateRootProtocol } = require(process.argv[1]);
      const root = process.argv[2];
      const request = JSON.parse(process.argv[3]);
      const report = JSON.parse(process.argv[4]);
      rotateRootProtocol(root, () => ({ report }), request, {
        staleMilliseconds: 0,
        timeoutMilliseconds: 2000,
      });
    `;
    const crashed = spawnSync(
      process.execPath,
      [
        "-e",
        releaseCrashScript,
        storeModulePath,
        root,
        JSON.stringify(request),
        JSON.stringify(report),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );

    expect(crashed.error).toBeUndefined();
    expect(crashed.status).toBeNull();
    expect(crashed.signal).toBe("SIGKILL");
    const lock = path.join(root, ".lock");
    expect(existsSync(lock)).toBe(false);
    const releaseClaims = readdirSync(root).filter((name) => (
      /^\.lock\.release\.writer-rotation-[0-9a-f]{20}-attempt-[0-9a-f]{24}$/
        .test(name)
    ));
    expect(releaseClaims).toHaveLength(1);
    const releaseClaim = path.join(root, releaseClaims[0]);
    expect(lstatSync(releaseClaim).isSymbolicLink()).toBe(true);
    const backingName = readlinkSync(releaseClaim);
    const nonce = releaseClaims[0].slice(".lock.release.".length);
    expect(backingName).toBe(`.lock.owner.${nonce}`);
    const backing = path.join(root, backingName);
    expect(existsSync(backing)).toBe(true);
    const owner = JSON.parse(readFileSync(
      path.join(backing, "owner.json"),
      "utf8",
    )) as {
      pid: number;
      nonce: string;
      kind: string;
    };
    expect(owner).toMatchObject({
      pid: crashed.pid,
      nonce,
      kind: "WRITER",
    });
    const generationFile = path.join(root, ".generation.json");
    const generationBytes = readFileSync(generationFile);
    expect(JSON.parse(generationBytes.toString("utf8"))).toMatchObject({
      generation: 2,
      active_transaction: null,
      pre_write_vector_sha256: null,
    });
    const protocolFile = path.join(root, ".store-protocol.json");
    const protocolBytes = readFileSync(protocolFile);
    const protocol = JSON.parse(
      protocolBytes.toString("utf8"),
    ) as RootProtocol;
    expect(protocol.protocol_rotations).toHaveLength(1);
    const receiptDescriptor = protocol.protocol_rotations?.[0];
    if (!receiptDescriptor) {
      throw new Error("release crash lost protocol rotation receipt");
    }
    const receiptFile = path.join(root, receiptDescriptor.relative_path);
    const receiptBytes = readFileSync(receiptFile);
    expect(JSON.parse(receiptBytes.toString("utf8"))).toMatchObject({
      rotation_id: request.rotationId,
      entry_generation: 0,
      exit_generation: 2,
    });
    const foreign = installForeignRequestWriterArtifact(root, backing);

    const retryScript = `
      const { rotateRootProtocol } = require(process.argv[1]);
      const root = process.argv[2];
      const request = JSON.parse(process.argv[3]);
      try {
        const result = rotateRootProtocol(
          root,
          () => {
            throw new Error("completed retry must not replay validator");
          },
          request,
          {
            staleMilliseconds: 0,
            timeoutMilliseconds: 2000,
          },
        );
        process.stdout.write(JSON.stringify(result));
      } catch (error) {
        process.stderr.write(JSON.stringify({
          code: error && error.code,
          message: error && error.message,
          stack: error && error.stack,
        }));
        process.exit(1);
      }
    `;
    const retried = spawnSync(
      process.execPath,
      [
        "-e",
        retryScript,
        storeModulePath,
        root,
        JSON.stringify(request),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );

    expect(retried.error).toBeUndefined();
    expect(retried.status).toBe(0);
    expect(retried.signal).toBeNull();
    expect(retried.stderr).toBe("");
    expect(JSON.parse(retried.stdout)).toMatchObject({
      rotated: false,
      idempotent: true,
      entry_generation: 0,
      exit_generation: 2,
    });
    expect(existsSync(releaseClaim)).toBe(false);
    expect(existsSync(backing)).toBe(false);
    expect(readFileSync(generationFile)).toEqual(generationBytes);
    expect(readFileSync(protocolFile)).toEqual(protocolBytes);
    expect(readFileSync(receiptFile)).toEqual(receiptBytes);
    expect(artifactIdentity(artifact)).toEqual(artifactBefore);
    expect(readdirSync(root).filter((name) => (
      name === ".lock" || name.startsWith(".lock.")
    ))).toEqual([path.basename(foreign.artifact)]);
    expect(readFileSync(
      path.join(foreign.artifact, "owner.json"),
    )).toEqual(foreign.bytes);
    rmSync(foreign.artifact, { recursive: true, force: true });
    expectTransportClean(root);
  });

  it("exact-retries a real protocol publication crash after canonical publish without replaying validation", () => {
    const root = sandbox();
    const { protocol: predecessor, artifact } =
      createSchema2Predecessor(root);
    const sourceCanary = path.join(root, "source-canary.json");
    writeFixtureJson(sourceCanary, {
      schema_version: 1,
      value: "sealed-source",
    });
    const request = requestFor(predecessor);
    const report = validationReport(root);
    const artifactBefore = artifactIdentity(artifact);
    const crashScript = `
      const { rotateRootProtocol } = require(process.argv[1]);
      const root = process.argv[2];
      const request = JSON.parse(process.argv[3]);
      const report = JSON.parse(process.argv[4]);
      rotateRootProtocol(
        root,
        () => ({ report }),
        request,
        {
          staleMilliseconds: 0,
          timeoutMilliseconds: 2000,
        },
      );
    `;
    const crashed = spawnSync(
      process.execPath,
      [
        "-e",
        crashScript,
        storeModulePath,
        root,
        JSON.stringify(request),
        JSON.stringify(report),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
          GOAL_CONTROL_TEST_FAULT_PROTOCOL_ROTATION_PROTOCOL_AFTER_ATOMIC_PUBLISH:
            "sigkill",
        },
      },
    );

    expect(crashed.error).toBeUndefined();
    expect(crashed.status).toBeNull();
    expect(crashed.signal).toBe("SIGKILL");
    const generationFile = path.join(root, ".generation.json");
    expect(JSON.parse(readFileSync(
      generationFile,
      "utf8",
    ))).toMatchObject({
      generation: 1,
      active_transaction: {
        kind: "PROTOCOL_ROTATION",
      },
    });
    const protocolFile = path.join(root, ".store-protocol.json");
    const protocolBytes = readFileSync(protocolFile);
    const protocol = JSON.parse(
      protocolBytes.toString("utf8"),
    ) as RootProtocol;
    expect(protocol).toMatchObject({
      schema_version: 3,
      protocol_rotations: [expect.any(Object)],
    });
    const receiptDescriptor = protocol.protocol_rotations?.[0];
    if (!receiptDescriptor) {
      throw new Error("protocol publication crash lost receipt");
    }
    const receiptFile = path.join(root, receiptDescriptor.relative_path);
    const receiptBytes = readFileSync(receiptFile);
    expect(JSON.parse(receiptBytes.toString("utf8"))).toMatchObject({
      rotation_id: request.rotationId,
      entry_generation: 0,
      exit_generation: 2,
    });
    const transport = path.join(root, ".atomic-transactions");
    expect(existsSync(transport)).toBe(true);
    expect(readdirSync(transport).length).toBeGreaterThan(0);
    expect(lstatSync(path.join(root, ".lock")).isSymbolicLink())
      .toBe(true);

    const retryScript = `
      const { rotateRootProtocol } = require(process.argv[1]);
      const root = process.argv[2];
      const request = JSON.parse(process.argv[3]);
      try {
        const result = rotateRootProtocol(
          root,
          () => {
            throw new Error("published residual retry must not validate");
          },
          request,
          {
            staleMilliseconds: 0,
            timeoutMilliseconds: 2000,
          },
        );
        process.stdout.write(JSON.stringify(result));
      } catch (error) {
        process.stderr.write(JSON.stringify({
          code: error && error.code,
          message: error && error.message,
          stack: error && error.stack,
        }));
        process.exit(1);
      }
    `;
    const sourceCanaryBytes = readFileSync(sourceCanary);
    writeFileSync(
      sourceCanary,
      Buffer.concat([sourceCanaryBytes, Buffer.from(" ")]),
    );
    const completeTreeWithSourceDrift = completeControlTree(root);
    const sourceDriftRetry = spawnSync(
      process.execPath,
      [
        "-e",
        retryScript,
        storeModulePath,
        root,
        JSON.stringify(request),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );
    expect(sourceDriftRetry).toMatchObject({
      status: 1,
      signal: null,
      stdout: "",
    });
    expect(sourceDriftRetry.stderr).toContain(
      "STORE_PROTOCOL_ROTATION_SOURCE_CHANGED",
    );
    expect(completeControlTree(root))
      .toEqual(completeTreeWithSourceDrift);
    writeFileSync(sourceCanary, sourceCanaryBytes);

    const retried = spawnSync(
      process.execPath,
      [
        "-e",
        retryScript,
        storeModulePath,
        root,
        JSON.stringify(request),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GOAL_CONTROL_TEST_MODE: "1",
        },
      },
    );

    expect(retried.error).toBeUndefined();
    expect(retried.status).toBe(0);
    expect(retried.signal).toBeNull();
    expect(retried.stderr).toBe("");
    expect(JSON.parse(retried.stdout)).toMatchObject({
      rotated: true,
      idempotent: false,
      entry_generation: 0,
      exit_generation: 2,
    });
    expect(JSON.parse(readFileSync(
      generationFile,
      "utf8",
    ))).toMatchObject({
      generation: 2,
      active_transaction: null,
      pre_write_vector_sha256: null,
    });
    expect(readFileSync(protocolFile)).toEqual(protocolBytes);
    expect(readFileSync(receiptFile)).toEqual(receiptBytes);
    expect(artifactIdentity(artifact)).toEqual(artifactBefore);
    expectTransportClean(root);
  });

  it.each([
    {
      stage: "generation begin",
      fault:
        "GOAL_CONTROL_TEST_FAULT_GENERATION_BEGIN_DURING_ATOMIC_RESERVATION_WRITE",
      crashGeneration: null,
      receiptInstalled: false,
      successorInstalled: false,
      finalValidatorCalls: 2,
      retryRotated: true,
    },
    {
      stage: "receipt publication",
      fault:
        "GOAL_CONTROL_TEST_FAULT_PROTOCOL_ROTATION_RECEIPT_DURING_ATOMIC_RESERVATION_WRITE",
      crashGeneration: 1,
      receiptInstalled: false,
      successorInstalled: false,
      finalValidatorCalls: 2,
      retryRotated: true,
    },
    {
      stage: "protocol publication",
      fault:
        "GOAL_CONTROL_TEST_FAULT_PROTOCOL_ROTATION_PROTOCOL_DURING_ATOMIC_RESERVATION_WRITE",
      crashGeneration: 1,
      receiptInstalled: true,
      successorInstalled: false,
      finalValidatorCalls: 1,
      retryRotated: true,
    },
    {
      stage: "generation completion",
      fault:
        "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_DURING_ATOMIC_RESERVATION_WRITE",
      crashGeneration: 1,
      receiptInstalled: true,
      successorInstalled: true,
      finalValidatorCalls: 1,
      retryRotated: false,
    },
  ] as const)(
    "exact-retries a half-written atomic reservation at $stage",
    ({
      fault,
      crashGeneration,
      receiptInstalled,
      successorInstalled,
      finalValidatorCalls,
      retryRotated,
    }) => {
      const root = sandbox();
      const evidenceRoot = sandbox();
      const validatorCountFile = path.join(
        evidenceRoot,
        "validator-count.txt",
      );
      writeFileSync(validatorCountFile, "0");
      const { protocol: predecessor, artifact } =
        createSchema2Predecessor(root);
      const request = requestFor(predecessor);
      const report = validationReport(root);
      const artifactBefore = artifactIdentity(artifact);
      const protocolFile = path.join(root, ".store-protocol.json");
      const predecessorProtocolBytes = readFileSync(protocolFile);
      const crashScript = `
        const fs = require("fs");
        const { rotateRootProtocol } = require(process.argv[1]);
        const root = process.argv[2];
        const request = JSON.parse(process.argv[3]);
        const report = JSON.parse(process.argv[4]);
        const validatorCountFile = process.argv[5];
        rotateRootProtocol(
          root,
          () => {
            const count = Number(
              fs.readFileSync(validatorCountFile, "utf8"),
            );
            fs.writeFileSync(validatorCountFile, String(count + 1));
            return { report };
          },
          request,
          {
            staleMilliseconds: 0,
            timeoutMilliseconds: 2000,
          },
        );
      `;
      const crashed = spawnSync(
        process.execPath,
        [
          "-e",
          crashScript,
          storeModulePath,
          root,
          JSON.stringify(request),
          JSON.stringify(report),
          validatorCountFile,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            GOAL_CONTROL_TEST_MODE: "1",
            [fault]: "sigkill",
          },
        },
      );

      expect(crashed.error).toBeUndefined();
      expect(crashed.status).toBeNull();
      expect(crashed.signal).toBe("SIGKILL");
      expect(readFileSync(validatorCountFile, "utf8")).toBe("1");
      const generationFile = path.join(root, ".generation.json");
      if (crashGeneration === null) {
        expect(existsSync(generationFile)).toBe(false);
      } else {
        expect(JSON.parse(readFileSync(
          generationFile,
          "utf8",
        ))).toMatchObject({
          generation: crashGeneration,
          active_transaction: {
            kind: "PROTOCOL_ROTATION",
          },
        });
      }
      expect(lstatSync(path.join(root, ".lock")).isSymbolicLink())
        .toBe(true);
      const transport = path.join(root, ".atomic-transactions");
      const reservations = completeControlTree(transport).filter(
        ([kind, relative]) => (
          kind === "file"
            && relative.endsWith(".reservation.json")
        ),
      );
      expect(reservations).toHaveLength(1);
      const partialReservation = readFileSync(path.join(
        transport,
        reservations[0][1],
      ));
      expect(partialReservation.length).toBeGreaterThan(0);
      expect(() => JSON.parse(
        partialReservation.toString("utf8"),
      )).toThrow();

      const crashProtocolBytes = readFileSync(protocolFile);
      const crashProtocol = JSON.parse(
        crashProtocolBytes.toString("utf8"),
      ) as RootProtocol;
      expect(crashProtocol.schema_version).toBe(
        successorInstalled ? 3 : 2,
      );
      if (!successorInstalled) {
        expect(crashProtocolBytes).toEqual(
          predecessorProtocolBytes,
        );
      }
      const receiptDirectory = path.join(
        root,
        ".protocol-rotations.v1",
      );
      const crashReceiptFiles = existsSync(receiptDirectory)
        ? readdirSync(receiptDirectory).filter(
          (name) => name.endsWith(".json"),
        )
        : [];
      expect(crashReceiptFiles).toHaveLength(
        receiptInstalled ? 1 : 0,
      );
      const crashReceiptBytes = receiptInstalled
        ? readFileSync(path.join(
          receiptDirectory,
          crashReceiptFiles[0],
        ))
        : null;

      const retryScript = `
        const fs = require("fs");
        const { rotateRootProtocol } = require(process.argv[1]);
        const root = process.argv[2];
        const request = JSON.parse(process.argv[3]);
        const report = JSON.parse(process.argv[4]);
        const validatorCountFile = process.argv[5];
        try {
          const result = rotateRootProtocol(
            root,
            () => {
              const count = Number(
                fs.readFileSync(validatorCountFile, "utf8"),
              );
              fs.writeFileSync(validatorCountFile, String(count + 1));
              return { report };
            },
            request,
            {
              staleMilliseconds: 0,
              timeoutMilliseconds: 2000,
            },
          );
          process.stdout.write(JSON.stringify(result));
        } catch (error) {
          process.stderr.write(JSON.stringify({
            code: error && error.code,
            message: error && error.message,
            stack: error && error.stack,
          }));
          process.exit(1);
        }
      `;
      const retried = spawnSync(
        process.execPath,
        [
          "-e",
          retryScript,
          storeModulePath,
          root,
          JSON.stringify(request),
          JSON.stringify(report),
          validatorCountFile,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            GOAL_CONTROL_TEST_MODE: "1",
          },
        },
      );

      expect(retried.error).toBeUndefined();
      expect(retried.stderr).toBe("");
      expect(retried.status).toBe(0);
      expect(retried.signal).toBeNull();
      expect(JSON.parse(retried.stdout)).toMatchObject({
        rotated: retryRotated,
        idempotent: !retryRotated,
        entry_generation: 0,
        exit_generation: 2,
      });
      expect(readFileSync(validatorCountFile, "utf8")).toBe(
        String(finalValidatorCalls),
      );
      const finalGenerationBytes = readFileSync(generationFile);
      expect(JSON.parse(
        finalGenerationBytes.toString("utf8"),
      )).toMatchObject({
        generation: 2,
        active_transaction: null,
        pre_write_vector_sha256: null,
      });
      const finalProtocolBytes = readFileSync(protocolFile);
      const finalProtocol = JSON.parse(
        finalProtocolBytes.toString("utf8"),
      ) as RootProtocol;
      expect(readRootProtocolSeal(root)).toEqual(finalProtocol);
      expect(finalProtocol).toMatchObject({
        schema_version: 3,
        protocol_rotations: [expect.any(Object)],
      });
      const descriptor = finalProtocol.protocol_rotations?.[0];
      if (!descriptor) {
        throw new Error("reservation retry lost rotation receipt");
      }
      const finalReceiptFile = path.join(
        root,
        descriptor.relative_path,
      );
      const finalReceiptBytes = readFileSync(finalReceiptFile);
      expect(descriptor.sha256).toBe(
        `sha256:${sha256(finalReceiptBytes)}`,
      );
      expect(JSON.parse(
        finalReceiptBytes.toString("utf8"),
      )).toMatchObject({
        rotation_id: request.rotationId,
        entry_generation: 0,
        exit_generation: 2,
        validation_report: report,
      });
      if (successorInstalled) {
        expect(finalProtocolBytes).toEqual(crashProtocolBytes);
      }
      if (crashReceiptBytes) {
        expect(finalReceiptBytes).toEqual(crashReceiptBytes);
      }
      expect(artifactIdentity(artifact)).toEqual(artifactBefore);
      expectTransportClean(root);

      const idempotent = rotateRootProtocol(
        root,
        () => {
          throw new Error("completed rotation must not revalidate");
        },
        request,
      );
      expect(idempotent).toMatchObject({
        rotated: false,
        idempotent: true,
        entry_generation: 0,
        exit_generation: 2,
      });
      expect(readFileSync(validatorCountFile, "utf8")).toBe(
        String(finalValidatorCalls),
      );
      expect(readFileSync(generationFile)).toEqual(
        finalGenerationBytes,
      );
      expect(readFileSync(protocolFile)).toEqual(finalProtocolBytes);
      expect(readFileSync(finalReceiptFile)).toEqual(
        finalReceiptBytes,
      );
      expectTransportClean(root);
    },
  );

  it("exact-retries only the completion payload residual while canonical generation is still odd", () => {
    exactRetryAfterGenerationCompleteCrash(
      "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_AFTER_ATOMIC_TEMP_FSYNC",
      1,
    );
  });

  it("exact-retries only transport cleanup after canonical generation is already even", () => {
    exactRetryAfterGenerationCompleteCrash(
      "GOAL_CONTROL_TEST_FAULT_GENERATION_COMPLETE_AFTER_ATOMIC_PUBLISH",
      2,
    );
  });

  it("rejects an oversized validation report before any generation, protocol, or receipt payload write", () => {
    const root = sandbox();
    const { protocol: predecessor, artifact } =
      createSchema2Predecessor(root);
    const request = requestFor(predecessor);
    const before = payloadTree(root);
    const artifactBefore = artifactIdentity(artifact);
    const oversizedReport: RotationReport = {
      ...validationReport(root),
      oversized_evidence: "x".repeat((16 * 1024 * 1024) + 1),
    };
    let thrown: unknown = null;

    try {
      rotateRootProtocol(
        root,
        () => ({ report: oversizedReport }),
        request,
      );
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({
      code: "STORE_PROTOCOL_ROTATION_RECEIPT_LIMIT",
    });
    expect(payloadTree(root)).toEqual(before);
    expect(readFileSync(
      path.join(root, ".store-protocol.json"),
      "utf8",
    )).toContain(`"seal_sha256": "${predecessor.seal_sha256}"`);
    expect(existsSync(path.join(root, ".generation.json"))).toBe(false);
    expect(existsSync(
      path.join(root, ".protocol-rotations.v1"),
    )).toBe(false);
    expect(artifactIdentity(artifact)).toEqual(artifactBefore);
    expectTransportClean(root);
  });

  it("CLI exact-recovers a stale-lock schema-3 pending receipt with historical receipt and absolute handoff evidence", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      predecessorValidatesAllPreflightRegistries: true,
    });
    const historical = installHistoricalPreflightOverwrite(fixture);
    const handoffCanaryBefore = artifactIdentity(
      historical.handoffCanaryFile,
    );
    const handoffReceiptBefore = artifactIdentity(
      historical.handoffReceiptFile,
    );
    const firstRotation = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture),
    );
    expect(firstRotation).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const firstValue = JSON.parse(firstRotation.stdout) as {
      protocol: RootProtocol;
      rotation_receipt: RotationDescriptor;
      exit_generation: number;
    };
    expect(firstValue.protocol.protocol_rotations).toEqual([
      firstValue.rotation_receipt,
    ]);
    const historicalRotationReceiptFile = path.join(
      fixture.controlRoot,
      firstValue.rotation_receipt.relative_path,
    );
    const historicalRotationReceiptBefore = artifactIdentity(
      historicalRotationReceiptFile,
    );

    const schema3PredecessorWorktree = path.join(
      path.dirname(fixture.repository),
      "schema3-predecessor-controller",
    );
    fixtureGit(
      fixture.repository,
      "worktree",
      "add",
      "--detach",
      schema3PredecessorWorktree,
      "HEAD",
    );
    const successorStoreFile = path.join(
      fixture.repository,
      "scripts",
      "goal-control",
      "store.js",
    );
    writeFileSync(
      successorStoreFile,
      `${readFileSync(successorStoreFile, "utf8")}
// Isolated fixture-only decoder incarnation.
`,
    );
    fixtureGit(fixture.repository, "add", successorStoreFile);
    fixtureGit(
      fixture.repository,
      "commit",
      "-qm",
      "fixture successor decoder incarnation",
    );
    const sealedSuccessorWorktree = path.join(
      path.dirname(fixture.repository),
      "sealed-successor-controller",
    );
    fixtureGit(
      fixture.repository,
      "worktree",
      "add",
      "--detach",
      sealedSuccessorWorktree,
      "HEAD",
    );
    const sealedSuccessorDecoderSha256 =
      controllerDecoderFingerprintAt(path.join(
        sealedSuccessorWorktree,
        "scripts",
        "goal-control",
      ));

    const secondGoalWorktreeMap = path.join(
      path.dirname(fixture.repository),
      "schema3-goal-worktrees.json",
    );
    writeFixtureJson(secondGoalWorktreeMap, {
      schema_version: 1,
      goal_worktrees: fixture.goalIds.map((goalId) => ({
        goal_id: goalId,
        repository_worktree: schema3PredecessorWorktree,
      })),
    });
    const secondArgs = fixtureRotationArgs(fixture, {
      goalWorktreesFile: realpathSync(secondGoalWorktreeMap),
      expectedPredecessorSealSha256:
        firstValue.protocol.seal_sha256,
      predecessorControllerWorktree:
        schema3PredecessorWorktree,
      rotationId: "rotation-cli-schema3-pending-r2",
      incidentRef:
        "incident://goal-control/schema3-pending-r2",
    });
    const crashed = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      secondArgs,
      {
        GOAL_CONTROL_TEST_FAULT_PROTOCOL_ROTATION_PROTOCOL_DURING_ATOMIC_RESERVATION_WRITE:
          "sigkill",
      },
    );
    expect(crashed).toMatchObject({
      status: null,
      signal: "SIGKILL",
    });
    expect(() => readRootProtocolSeal(fixture.controlRoot)).toThrow(
      expect.objectContaining({ code: "CORRUPT_STORE_PROTOCOL" }),
    );
    const rotationDirectory = path.join(
      fixture.controlRoot,
      ".protocol-rotations.v1",
    );
    const rotationFiles = readdirSync(rotationDirectory).sort();
    expect(rotationFiles).toHaveLength(2);
    const pendingName = rotationFiles.find(
      (name) => (
        name !== path.basename(
          firstValue.rotation_receipt.relative_path,
        )
      ),
    );
    if (!pendingName) {
      throw new Error("schema-3 pending rotation receipt missing");
    }
    const pendingReceiptFile = path.join(
      rotationDirectory,
      pendingName,
    );
    const pendingReceiptBefore = artifactIdentity(pendingReceiptFile);
    const pendingReceipt = JSON.parse(readFileSync(
      pendingReceiptFile,
      "utf8",
    )) as RotationReceipt;
    expect(pendingReceipt).toMatchObject({
      rotation_id: "rotation-cli-schema3-pending-r2",
      predecessor_protocol: {
        seal_sha256: firstValue.protocol.seal_sha256,
      },
      successor_protocol: {
        controller_decoder_sha256:
          sealedSuccessorDecoderSha256,
      },
      entry_generation: firstValue.exit_generation,
      exit_generation: firstValue.exit_generation + 2,
    });
    expect(lstatSync(
      path.join(fixture.controlRoot, ".lock"),
    ).isSymbolicLink()).toBe(true);
    const staleLock = path.join(fixture.controlRoot, ".lock");
    const staleOwnerFile = path.join(
      fixture.controlRoot,
      readlinkSync(staleLock),
      "owner.json",
    );
    const staleOwnerBeforeWrongRetry = artifactIdentity(
      staleOwnerFile,
    );
    const completeTreeBeforeWrongRetry =
      completeControlTree(fixture.controlRoot);
    const wrongArgs = [...secondArgs];
    const incidentOption = wrongArgs.indexOf("--incident-ref");
    expect(incidentOption).toBeGreaterThanOrEqual(0);
    wrongArgs[incidentOption + 1] =
      "incident://goal-control/schema3-pending-r2-wrong";
    const wrongRetry = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      wrongArgs,
    );
    expect(wrongRetry).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(wrongRetry.stderr).toContain(
      "goalctl[CORRUPT_STORE_PROTOCOL]",
    );
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(completeTreeBeforeWrongRetry);
    expect(artifactIdentity(staleOwnerFile))
      .toEqual(staleOwnerBeforeWrongRetry);
    const sourceBytes = readFileSync(fixture.goalMetadata);
    writeFileSync(
      fixture.goalMetadata,
      Buffer.concat([sourceBytes, Buffer.from(" ")]),
    );
    const staleOwnerBeforeSourceDrift = artifactIdentity(
      staleOwnerFile,
    );
    const completeTreeWithSourceDrift =
      completeControlTree(fixture.controlRoot);
    const sourceDriftRetry = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      secondArgs,
    );
    expect(sourceDriftRetry).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(sourceDriftRetry.stderr).toContain(
      "goalctl[STORE_PROTOCOL_ROTATION_SOURCE_CHANGED]",
    );
    expect(lstatSync(staleLock).isSymbolicLink()).toBe(true);
    expect(artifactIdentity(staleOwnerFile))
      .toEqual(staleOwnerBeforeSourceDrift);
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(completeTreeWithSourceDrift);
    writeFileSync(fixture.goalMetadata, sourceBytes);
    const foreignReceiptFile = path.join(
      rotationDirectory,
      `${"f".repeat(64)}.json`,
    );
    writeFileSync(foreignReceiptFile, "{}\n", { mode: 0o600 });
    const completeTreeWithForeignReceipt =
      completeControlTree(fixture.controlRoot);
    const staleOwnerBeforeForeignReceipt = artifactIdentity(
      staleOwnerFile,
    );
    const foreignReceiptRetry = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      secondArgs,
    );
    expect(foreignReceiptRetry).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(foreignReceiptRetry.stderr).toContain(
      "goalctl[CORRUPT_STORE_PROTOCOL]",
    );
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(completeTreeWithForeignReceipt);
    expect(artifactIdentity(staleOwnerFile))
      .toEqual(staleOwnerBeforeForeignReceipt);
    unlinkSync(foreignReceiptFile);
    const generationFile = path.join(
      fixture.controlRoot,
      ".generation.json",
    );
    const oddGenerationBytes = readFileSync(generationFile);
    const oddGeneration = JSON.parse(
      oddGenerationBytes.toString("utf8"),
    ) as {
      updated_at: string;
    };
    writeSealedJson(generationFile, {
      schema_version: 3,
      generation: pendingReceipt.exit_generation,
      active_transaction: null,
      pre_write_vector_sha256: null,
      updated_at: oddGeneration.updated_at,
    });
    const completeTreeWithEvenGeneration =
      completeControlTree(fixture.controlRoot);
    const staleOwnerBeforeEvenGeneration = artifactIdentity(
      staleOwnerFile,
    );
    const evenGenerationRetry = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      secondArgs,
    );
    expect(evenGenerationRetry).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(completeTreeWithEvenGeneration);
    expect(artifactIdentity(staleOwnerFile))
      .toEqual(staleOwnerBeforeEvenGeneration);
    writeFileSync(generationFile, oddGenerationBytes);

    writeFileSync(
      successorStoreFile,
      `${readFileSync(successorStoreFile, "utf8")}
// Isolated fixture-only recovery broker incarnation.
`,
    );
    fixtureGit(fixture.repository, "add", successorStoreFile);
    fixtureGit(
      fixture.repository,
      "commit",
      "-qm",
      "fixture recovery broker decoder incarnation",
    );
    const recoveryBrokerDecoderSha256 =
      controllerDecoderFingerprintAt(path.join(
        fixture.repository,
        "scripts",
        "goal-control",
      ));
    expect(recoveryBrokerDecoderSha256)
      .not.toBe(sealedSuccessorDecoderSha256);

    const predecessorStoreFile = path.join(
      schema3PredecessorWorktree,
      "scripts",
      "goal-control",
      "store.js",
    );
    writeFileSync(
      predecessorStoreFile,
      `${readFileSync(predecessorStoreFile, "utf8")}
// Dirty after the validation report was durably sealed.
`,
    );
    expect(fixtureGit(
      schema3PredecessorWorktree,
      "status",
      "--porcelain=v1",
      "--untracked-files=all",
    )).not.toBe("");

    const retried = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      secondArgs,
    );
    expect(retried).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const retryValue = JSON.parse(retried.stdout) as {
      protocol: RootProtocol;
      validation: RotationReport;
      entry_generation: number;
      exit_generation: number;
    };
    expect(retryValue).toMatchObject({
      entry_generation: firstValue.exit_generation,
      exit_generation: firstValue.exit_generation + 2,
      protocol: {
        controller_decoder_sha256:
          sealedSuccessorDecoderSha256,
        protocol_rotations: [
          firstValue.rotation_receipt,
          {
            relative_path:
              `.protocol-rotations.v1/${pendingName}`,
          },
        ],
      },
      validation: pendingReceipt.validation_report,
    });
    expect(artifactIdentity(historicalRotationReceiptFile))
      .toEqual(historicalRotationReceiptBefore);
    expect(artifactIdentity(pendingReceiptFile))
      .toEqual(pendingReceiptBefore);
    expect(artifactIdentity(historical.handoffCanaryFile))
      .toEqual(handoffCanaryBefore);
    expect(artifactIdentity(historical.handoffReceiptFile))
      .toEqual(handoffReceiptBefore);
    expectTransportClean(fixture.controlRoot);

    const thirdGoalWorktreeMap = path.join(
      path.dirname(fixture.repository),
      "schema3-current-goal-worktrees.json",
    );
    writeFixtureJson(thirdGoalWorktreeMap, {
      schema_version: 1,
      goal_worktrees: fixture.goalIds.map((goalId) => ({
        goal_id: goalId,
        repository_worktree: sealedSuccessorWorktree,
      })),
    });
    const thirdArgs = fixtureRotationArgs(fixture, {
      goalWorktreesFile: realpathSync(thirdGoalWorktreeMap),
      expectedPredecessorSealSha256:
        retryValue.protocol.seal_sha256,
      predecessorControllerWorktree:
        sealedSuccessorWorktree,
      rotationId: "rotation-cli-schema3-current-r3",
      incidentRef:
        "incident://goal-control/schema3-current-r3",
    });
    const upgraded = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      thirdArgs,
    );
    expect(upgraded).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const upgradedValue = JSON.parse(upgraded.stdout) as {
      protocol: RootProtocol;
      entry_generation: number;
      exit_generation: number;
    };
    expect(upgradedValue).toMatchObject({
      entry_generation: retryValue.exit_generation,
      exit_generation: retryValue.exit_generation + 2,
      protocol: {
        controller_decoder_sha256:
          recoveryBrokerDecoderSha256,
        protocol_rotations: [
          firstValue.rotation_receipt,
          {
            relative_path:
              `.protocol-rotations.v1/${pendingName}`,
          },
          expect.any(Object),
        ],
      },
    });
    expectTransportClean(fixture.controlRoot);
  }, 60_000);

  it("replays an overwritten historical PREFLIGHT launch through an audited temp-copy overlay without mutating live evidence", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      predecessorValidatesAllPreflightRegistries: true,
    });
    const historical = installHistoricalPreflightOverwrite(fixture);
    const registryBefore = artifactIdentity(historical.registryFile);
    const canonicalBefore = artifactIdentity(
      historical.canonicalLaunchFile,
    );
    const immutableBefore = artifactIdentity(
      historical.immutableLaunchFile,
    );
    const handoffCanaryBefore = artifactIdentity(
      historical.handoffCanaryFile,
    );
    const handoffReceiptBefore = artifactIdentity(
      historical.handoffReceiptFile,
    );
    const args = fixtureRotationArgs(fixture);

    const rotated = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      args,
    );

    expect(rotated).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const value = JSON.parse(rotated.stdout) as {
      rotated: boolean;
      validation: {
        protocol_rotation: {
          predecessor_compatibility_overlay: {
            schema_version: number;
            kind: string;
            scope: string;
            live_root_mutated: boolean;
            record_count: number;
            records: Array<Record<string, unknown>>;
            records_sha256: string;
            overlay_sha256: string;
          };
        };
      };
      protocol: RootProtocol;
      rotation_receipt: RotationDescriptor;
    };
    const overlay =
      value.validation.protocol_rotation
        .predecessor_compatibility_overlay;
    const overlaidUnsigned: Record<string, unknown> = {
      ...historical.record,
      launch_uri: pathToFileURL(historical.immutableLaunchFile).href,
    };
    delete overlaidUnsigned.registry_sha256;
    const expectedOverlayRegistrySha256 = hashObject(overlaidUnsigned);
    expect(value.rotated).toBe(true);
    expect(overlay).toMatchObject({
      schema_version: 1,
      kind: "PREFLIGHT_LAUNCH_URI_COMPATIBILITY_OVERLAY",
      scope: "PREDECESSOR_SEMANTIC_REPLAY_IN_MEMORY_READ_ONLY",
      live_root_mutated: false,
      record_count: 1,
      records: [{
        goal_id: fixture.primaryGoalId,
        task_id: fixture.primaryTaskId,
        evidence_id: historical.evidenceId,
        source_registry_sha256:
          historical.record.registry_sha256,
        source_launch_uri:
          pathToFileURL(historical.canonicalLaunchFile).href,
        overwritten_canonical_launch_sha256:
          historical.canonicalLaunchSha256,
        sealed_launch_sha256:
          historical.immutableLaunchSha256,
        allowed_overwrite_fields: [
          "created_at",
          "repository.full_head",
          "execution.target.pid",
          "execution.target.started_at",
          "execution.target.build_head",
        ],
        observed_overwrite_fields: [
          "created_at",
          "repository.full_head",
          "execution.target.pid",
          "execution.target.started_at",
          "execution.target.build_head",
        ],
        stable_launch_structure_sha256:
          expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        overlay_launch_uri:
          pathToFileURL(historical.immutableLaunchFile).href,
        overlay_registry_sha256:
          expectedOverlayRegistrySha256,
      }],
    });
    expect(overlay.records_sha256).toBe(hashObject(overlay.records));
    const overlayUnsigned = { ...overlay } as Record<string, unknown>;
    delete overlayUnsigned.overlay_sha256;
    expect(overlay.overlay_sha256).toBe(hashObject(overlayUnsigned));

    expect(artifactIdentity(historical.registryFile))
      .toEqual(registryBefore);
    expect(artifactIdentity(historical.canonicalLaunchFile))
      .toEqual(canonicalBefore);
    expect(artifactIdentity(historical.immutableLaunchFile))
      .toEqual(immutableBefore);
    expect(artifactIdentity(historical.handoffCanaryFile))
      .toEqual(handoffCanaryBefore);
    expect(artifactIdentity(historical.handoffReceiptFile))
      .toEqual(handoffReceiptBefore);

    const receiptFile = path.join(
      fixture.controlRoot,
      value.rotation_receipt.relative_path,
    );
    const receipt = JSON.parse(readFileSync(
      receiptFile,
      "utf8",
    )) as RotationReceipt & {
      validation_report: {
        protocol_rotation: {
          predecessor_compatibility_overlay: unknown;
        };
      };
    };
    expect(
      receipt.validation_report.protocol_rotation
        .predecessor_compatibility_overlay,
    ).toEqual(overlay);

    const retry = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      args,
    );
    expect(retry).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    expect(
      JSON.parse(retry.stdout).validation.protocol_rotation
        .predecessor_compatibility_overlay,
    ).toEqual(overlay);
    expect(artifactIdentity(historical.registryFile))
      .toEqual(registryBefore);
    expect(artifactIdentity(historical.canonicalLaunchFile))
      .toEqual(canonicalBefore);
    expect(artifactIdentity(historical.immutableLaunchFile))
      .toEqual(immutableBefore);
    expect(artifactIdentity(historical.handoffCanaryFile))
      .toEqual(handoffCanaryBefore);
    expect(artifactIdentity(historical.handoffReceiptFile))
      .toEqual(handoffReceiptBefore);
    expectTransportClean(fixture.controlRoot);
  });

  it("keeps a real predecessor active ADD_HOLD snapshot byte-equivalent across rotation", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
    });
    const beforeHold = predecessorTaskState(fixture);
    const evidence = writeFixtureEvidence(fixture, {
      evidenceId: "hold-active-predecessor-rotation",
      kind: "HOLD_ASSERTION",
      status: "BLOCKED",
      producerRole: "FOREMAN",
      producerThreadId: fixture.foremanThreadId,
      state: beforeHold,
    });
    const held = submitPredecessorEvent(fixture, {
      eventId: "add-hold-active-predecessor-rotation",
      type: "ADD_HOLD",
      role: "FOREMAN",
      threadId: fixture.foremanThreadId,
      actorSequence: 1,
      capabilityFile: fixture.foremanCapability,
      payload: {
        hold_id: "hold-active-predecessor-rotation",
        kind: "BLOCKED_SECURITY",
        reason: "retain append-only active hold across decoder rotation",
        evidence_id: evidence.record.evidence_id,
      },
    });
    expect(held.result).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    expect(predecessorTaskState(fixture).holds).toEqual([
      expect.objectContaining({
        hold_id: "hold-active-predecessor-rotation",
        kind: "BLOCKED_SECURITY",
      }),
    ]);

    const rotated = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        rotationId: "rotation-active-add-hold",
        incidentRef:
          "incident://goal-control/active-add-hold-replay",
      }),
    );
    expect(rotated).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const value = JSON.parse(rotated.stdout) as {
      validation: {
        protocol_rotation: {
          predecessor_semantic_replay_sha256: string;
          successor_semantic_replay_sha256: string;
          semantic_replay_match: boolean;
        };
      };
    };
    const replay = value.validation.protocol_rotation;
    expect(replay.semantic_replay_match).toBe(true);
    expect(replay.predecessor_semantic_replay_sha256)
      .toBe(replay.successor_semantic_replay_sha256);

    const successor = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      [
        "status",
        "--repository-worktree",
        fixture.predecessorWorktree,
        "--goal",
        fixture.primaryGoalId,
        "--json",
      ],
    );
    expect(successor).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    expect(JSON.parse(successor.stdout)).toMatchObject({
      tasks: {
        [fixture.primaryTaskId]: {
          holds: [
            expect.objectContaining({
              hold_id: "hold-active-predecessor-rotation",
              kind: "BLOCKED_SECURITY",
            }),
          ],
        },
      },
    });
    expectTransportClean(fixture.controlRoot);
  });

  it("rotates a predecessor-generated markerless runtime identity hold and survives source URI loss", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      markerlessIdentityIncidentPredecessor: true,
    });
    const markerless = installMarkerlessRuntimeIdentityIncident(
      fixture,
    );
    try {
      const rotated = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        fixtureRotationArgs(fixture, {
          rotationId: "rotation-markerless-runtime",
          incidentRef:
            "incident://goal-control/markerless-runtime",
        }),
      );
      if (rotated.status !== 0) {
        throw new Error(
          `markerless rotation failed: ${
            rotated.stderr || rotated.stdout
          }`,
        );
      }
      const value = JSON.parse(rotated.stdout) as {
        validation: {
          legacy_identity_incident_count: number;
          legacy_identity_incident_skipped_semantic_count: number;
          legacy_identity_incident_receipt: {
            incidents: Record<string, Record<string, unknown> & {
              goal_id: string;
              task_id: string;
              hold_id: string;
              source_sha256: string;
              parent_evidence_id: string;
              parent_registry_sha256: string;
              candidate_launch_sha256: string;
              entry_sha256: string;
            }>;
            sources: Record<string, string>;
            incidents_sha256: string;
            sources_sha256: string;
            receipt_sha256: string;
          } & Record<string, unknown>;
        };
      };
      expect(value.validation).toMatchObject({
        legacy_identity_incident_count: 1,
        legacy_identity_incident_skipped_semantic_count: 0,
      });
      const entries = Object.values(
        value.validation.legacy_identity_incident_receipt.incidents,
      );
      expect(entries).toEqual([
        expect.objectContaining({ hold_id: markerless.holdId }),
      ]);
      expect(
        value.validation.legacy_identity_incident_receipt.sources[
          entries[0].source_sha256
        ],
      ).toBe(markerless.sourceBody.toString("base64"));
      const forgeReceiptContext = (
        field: "goal_id" | "hold_id",
        forgedValue: string,
      ): Record<string, unknown> => {
        const receipt = JSON.parse(JSON.stringify(
          value.validation.legacy_identity_incident_receipt,
        )) as typeof value.validation.legacy_identity_incident_receipt;
        const originalKey = Object.keys(receipt.incidents)[0];
        const entry = receipt.incidents[originalKey];
        entry[field] = forgedValue;
        const {
          entry_sha256: _previousEntrySha256,
          ...unsignedEntry
        } = entry;
        entry.entry_sha256 = hashObject(unsignedEntry);
        delete receipt.incidents[originalKey];
        receipt.incidents[
          `${entry.goal_id}/${entry.task_id}/${entry.hold_id}`
        ] = entry;
        receipt.incidents_sha256 = hashObject(receipt.incidents);
        receipt.sources_sha256 = hashObject(receipt.sources);
        const {
          receipt_sha256: _previousReceiptSha256,
          ...unsignedReceipt
        } = receipt;
        receipt.receipt_sha256 = hashObject(unsignedReceipt);
        return receipt;
      };
      expect(() => validateLegacyIdentityIncidentReceipt(
        forgeReceiptContext(
          "goal_id",
          fixture.goalIds.find(
            (goalId) => goalId !== fixture.primaryGoalId,
          ) ?? `${fixture.primaryGoalId}-forged`,
        ),
        { root: fixture.controlRoot },
      )).toThrow(/source context binding 非法/);
      expect(() => validateLegacyIdentityIncidentReceipt(
        forgeReceiptContext(
          "hold_id",
          `${markerless.holdId}-forged`,
        ),
        { root: fixture.controlRoot },
      )).toThrow(/source context binding 非法/);
      const emptyChecksReceipt = JSON.parse(JSON.stringify(
        value.validation.legacy_identity_incident_receipt,
      )) as typeof value.validation.legacy_identity_incident_receipt;
      const emptyChecksEntry = Object.values(
        emptyChecksReceipt.incidents,
      )[0];
      const previousSourceSha256 = emptyChecksEntry.source_sha256;
      const emptyChecksSource = JSON.parse(Buffer.from(
        emptyChecksReceipt.sources[previousSourceSha256],
        "base64",
      ).toString("utf8")) as {
        request: { checks: unknown[] };
      };
      emptyChecksSource.request.checks = [];
      const emptyChecksBody = Buffer.from(
        `${JSON.stringify(emptyChecksSource, null, 2)}\n`,
      );
      const emptyChecksSourceSha256 =
        `sha256:${sha256(emptyChecksBody)}`;
      delete emptyChecksReceipt.sources[previousSourceSha256];
      emptyChecksReceipt.sources[emptyChecksSourceSha256] =
        emptyChecksBody.toString("base64");
      emptyChecksEntry.source_sha256 = emptyChecksSourceSha256;
      const {
        entry_sha256: _emptyChecksEntrySha256,
        ...emptyChecksUnsignedEntry
      } = emptyChecksEntry;
      emptyChecksEntry.entry_sha256 =
        hashObject(emptyChecksUnsignedEntry);
      emptyChecksReceipt.incidents_sha256 =
        hashObject(emptyChecksReceipt.incidents);
      emptyChecksReceipt.sources_sha256 =
        hashObject(emptyChecksReceipt.sources);
      const {
        receipt_sha256: _emptyChecksReceiptSha256,
        ...emptyChecksUnsignedReceipt
      } = emptyChecksReceipt;
      emptyChecksReceipt.receipt_sha256 =
        hashObject(emptyChecksUnsignedReceipt);
      expect(() => validateLegacyIdentityIncidentReceipt(
        emptyChecksReceipt,
        { root: fixture.controlRoot },
      )).toThrow(/source context binding 非法/);
      const crossStateRoot = path.join(
        path.dirname(fixture.controlRoot),
        "cross-state-receipt-root",
      );
      mkdirSync(crossStateRoot, { recursive: true });
      cpSync(
        path.join(fixture.controlRoot, "goals"),
        path.join(crossStateRoot, "goals"),
        { recursive: true },
      );
      const crossStateReceipt = JSON.parse(JSON.stringify(
        value.validation.legacy_identity_incident_receipt,
      )) as typeof value.validation.legacy_identity_incident_receipt;
      const crossStateEntry = Object.values(
        crossStateReceipt.incidents,
      )[0];
      const crossStateCandidateFile = path.join(
        crossStateRoot,
        "goals",
        crossStateEntry.goal_id,
        "evidence-artifacts",
        crossStateEntry.task_id,
        `${crossStateEntry.parent_evidence_id}-launch.json`,
      );
      const crossStateCandidate = JSON.parse(readFileSync(
        crossStateCandidateFile,
        "utf8",
      )) as Record<string, unknown> & { state_revision: number };
      crossStateCandidate.state_revision += 1;
      writeFixtureJson(crossStateCandidateFile, crossStateCandidate);
      const crossStateCandidateSha256 =
        `sha256:${sha256(readFileSync(crossStateCandidateFile))}`;
      const crossStateParentFile = path.join(
        crossStateRoot,
        "goals",
        crossStateEntry.goal_id,
        "evidence",
        crossStateEntry.task_id,
        `${crossStateEntry.parent_evidence_id}.json`,
      );
      const crossStateParent = JSON.parse(readFileSync(
        crossStateParentFile,
        "utf8",
      )) as Record<string, unknown>;
      crossStateParent.launch_uri =
        pathToFileURL(crossStateCandidateFile).href;
      crossStateParent.launch_sha256 = crossStateCandidateSha256;
      delete crossStateParent.registry_sha256;
      crossStateParent.registry_sha256 = hashObject(crossStateParent);
      writeFixtureJson(crossStateParentFile, crossStateParent);
      crossStateEntry.parent_registry_sha256 =
        crossStateParent.registry_sha256 as string;
      crossStateEntry.candidate_launch_sha256 =
        crossStateCandidateSha256;
      const {
        entry_sha256: _crossStateEntrySha256,
        ...crossStateUnsignedEntry
      } = crossStateEntry;
      crossStateEntry.entry_sha256 = hashObject(
        crossStateUnsignedEntry,
      );
      crossStateReceipt.incidents_sha256 =
        hashObject(crossStateReceipt.incidents);
      crossStateReceipt.sources_sha256 =
        hashObject(crossStateReceipt.sources);
      const {
        receipt_sha256: _crossStateReceiptSha256,
        ...crossStateUnsignedReceipt
      } = crossStateReceipt;
      crossStateReceipt.receipt_sha256 =
        hashObject(crossStateUnsignedReceipt);
      expect(() => validateLegacyIdentityIncidentReceipt(
        crossStateReceipt,
        { root: crossStateRoot },
      )).toThrow(/candidate launch context 非法/);

      unlinkSync(markerless.sourceFile);
      const status = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        [
          "status",
          "--goal",
          fixture.primaryGoalId,
          "--task",
          fixture.primaryTaskId,
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--json",
        ],
      );
      if (status.status !== 0) {
        throw new Error(
          `post-rotation markerless status failed: ${
            status.stderr || status.stdout
          }`,
        );
      }
      const statusValue = JSON.parse(status.stdout) as {
        tasks: Record<string, {
          maintenance_actions: Array<{ type: string }>;
        }>;
      };
      expect(
        statusValue.tasks[fixture.primaryTaskId].maintenance_actions,
      ).toEqual(expect.arrayContaining([
        expect.objectContaining({
          type: "REQUEST_RUNTIME_ROTATION",
        }),
      ]));
      const actions = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        [
          "actions",
          "--goal",
          fixture.primaryGoalId,
          "--task",
          fixture.primaryTaskId,
          "--role",
          "CAPTAIN",
          "--thread",
          markerless.captainThreadId,
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--json",
        ],
      );
      expect(actions.status).toBe(0);
      expect(
        (JSON.parse(actions.stdout) as {
          maintenance_actions: Array<{ type: string }>;
        }).maintenance_actions,
      ).toEqual(expect.arrayContaining([
        expect.objectContaining({
          type: "REQUEST_RUNTIME_ROTATION",
        }),
      ]));
      const doctor = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        [
          "doctor",
          "--goal",
          fixture.primaryGoalId,
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--json",
        ],
      );
      // An unresolved runtime-identity hard hold is intentionally unhealthy;
      // the safety property here is that it remains classified after the
      // predecessor source URI has disappeared.
      expect(doctor.status).toBe(1);
      expect(`${doctor.stdout}\n${doctor.stderr}`)
        .not.toContain("LAUNCH_IDENTITY_HOLD_UNCLASSIFIED");
    } finally {
      markerless.runtime.kill("SIGTERM");
    }
  });

  it("revalidates an active markerless source-only hold after rotation and source URI loss", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      markerlessIdentityIncidentPredecessor: true,
      sourceOnlyIdentityIncidentPredecessor: true,
    });
    const sourceOnly = installMarkerlessRuntimeIdentityIncident(
      fixture,
      { conflictKind: "SOURCE_ONLY" },
    );
    try {
      const rotated = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        fixtureRotationArgs(fixture, {
          rotationId: "rotation-markerless-source-only",
          incidentRef:
            "incident://goal-control/markerless-source-only",
        }),
      );
      if (rotated.status !== 0) {
        throw new Error(
          `markerless source-only rotation failed: ${
            rotated.stderr || rotated.stdout
          }`,
        );
      }
      expect(JSON.parse(rotated.stdout)).toMatchObject({
        validation: {
          legacy_identity_incident_count: 1,
          legacy_identity_incident_skipped_semantic_count: 0,
        },
      });

      unlinkSync(sourceOnly.sourceFile);
      const loaded = loadGoalStateUnlocked(
        fixture.controlRoot,
        fixture.primaryGoalId,
        {
          repairHeads: false,
          repairBootstrapConsumption: false,
        },
      );
      expect(inspectSourceCheckpointHold(
        loaded.paths,
        loaded.snapshot.tasks[fixture.primaryTaskId],
        fixture.primaryGoalId,
        loaded.manifest.tasks.find(
          (candidate) => candidate.id === fixture.primaryTaskId,
        ) as Record<string, unknown>,
      )).toMatchObject({
        hold_event_id: sourceOnly.incidentEvent.event_id,
        candidate_head: sourceOnly.candidateHead,
      });
      const status = runFixtureGoalctl(
        fixture.goalctl,
        fixture.predecessorWorktree,
        fixture.controlRoot,
        [
          "status",
          "--goal",
          fixture.primaryGoalId,
          "--task",
          fixture.primaryTaskId,
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--json",
        ],
      );
      if (status.status !== 0) {
        throw new Error(
          `post-rotation source-only status failed: ${
            status.stderr || status.stdout
          }`,
        );
      }
      const task = JSON.parse(status.stdout).tasks[
        fixture.primaryTaskId
      ] as {
        maintenance_actions: Array<Record<string, unknown>>;
      };
      const actions = task.maintenance_actions.filter((action) => (
        action.type === "REQUEST_CANDIDATE_HOLD_REVALIDATION"
      ));
      if (actions.length !== 1) {
        throw new Error(
          `expected one source revalidation action: ${JSON.stringify(
            task,
            null,
            2,
          )}`,
        );
      }
      expect(actions[0]).toMatchObject({
        actor_role: "FOREMAN",
        requested_action: "REVALIDATE_SOURCE_CHECKPOINT_HOLD",
        hold_id: sourceOnly.holdId,
        candidate_head: sourceOnly.candidateHead,
        forbidden_action: "ROTATE_RUNTIME",
      });
      const action = actions[0] as {
        operation_id: string;
        hold_id: string;
        hold_event_id: string;
        canonical_launch_sha256: string;
        candidate_head: string;
      };
      const revalidated = runFixtureGoalctl(
        fixture.goalctl,
        fixture.predecessorWorktree,
        fixture.controlRoot,
        [
          "revalidate-source-checkpoint-hold",
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--goal",
          fixture.primaryGoalId,
          "--task",
          fixture.primaryTaskId,
          "--thread",
          fixture.foremanThreadId,
          "--operation-id",
          action.operation_id,
          "--hold",
          action.hold_id,
          "--expected-hold-event-id",
          action.hold_event_id,
          "--expected-canonical-launch-sha256",
          action.canonical_launch_sha256,
          "--expected-candidate-head",
          action.candidate_head,
          "--actor-capability-file",
          fixture.foremanCapability,
          "--json",
        ],
      );
      if (revalidated.status !== 0) {
        throw new Error(
          `post-rotation source-only revalidation failed: ${
            revalidated.stderr || revalidated.stdout
          }`,
        );
      }
      expect(JSON.parse(revalidated.stdout)).toMatchObject({
        operation: "SOURCE_CHECKPOINT_HOLD_REVALIDATION",
        operation_id: action.operation_id,
        resolution_evidence_id: expect.stringMatching(
          /^source-checkpoint-resolution-[0-9a-f]{32}$/,
        ),
        resolve_event_id: expect.stringMatching(
          /^resolve-source-checkpoint-hold-[0-9a-f]{32}$/,
        ),
      });

      const after = runFixtureGoalctl(
        fixture.goalctl,
        fixture.predecessorWorktree,
        fixture.controlRoot,
        [
          "status",
          "--goal",
          fixture.primaryGoalId,
          "--task",
          fixture.primaryTaskId,
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--json",
        ],
      );
      expect(after.status).toBe(0);
      expect(JSON.parse(after.stdout)).toMatchObject({
        tasks: {
          [fixture.primaryTaskId]: {
            holds: [],
          },
        },
      });
    } finally {
      sourceOnly.runtime.kill("SIGTERM");
    }
  });

  it("rotates a markerless canonical launch whose worktree HEAD became stale", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      markerlessIdentityIncidentPredecessor: true,
    });
    const stale = installMarkerlessRuntimeIdentityIncident(
      fixture,
      { conflictKind: "CANONICAL_STALE_HEAD" },
    );
    try {
      expect(stale.observedHead).not.toBe(stale.canonicalHead);
      const rotated = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        fixtureRotationArgs(fixture, {
          rotationId: "rotation-markerless-canonical-stale-head",
          incidentRef:
            "incident://goal-control/markerless-canonical-stale-head",
        }),
      );
      if (rotated.status !== 0) {
        throw new Error(
          `markerless canonical stale-head rotation failed: ${
            rotated.stderr || rotated.stdout
          }`,
        );
      }
      const value = JSON.parse(rotated.stdout) as {
        validation: {
          legacy_identity_incident_count: number;
          legacy_identity_incident_skipped_semantic_count: number;
          legacy_identity_incident_receipt: {
            incidents: Record<string, {
              candidate_launch_sha256: string;
              hold_id: string;
            }>;
          };
        };
      };
      expect(value.validation).toMatchObject({
        legacy_identity_incident_count: 1,
        legacy_identity_incident_skipped_semantic_count: 0,
      });
      expect(
        Object.values(
          value.validation.legacy_identity_incident_receipt.incidents,
        ),
      ).toEqual([
        expect.objectContaining({
          hold_id: stale.holdId,
          candidate_launch_sha256: expect.stringMatching(
            /^sha256:[0-9a-f]{64}$/,
          ),
        }),
      ]);
      const status = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        [
          "status",
          "--goal",
          fixture.primaryGoalId,
          "--task",
          fixture.primaryTaskId,
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--json",
        ],
      );
      expect(status.status).toBe(0);
      const maintenanceActions = (
        JSON.parse(status.stdout) as {
          tasks: Record<string, {
            maintenance_actions: Array<{ type: string }>;
          }>;
        }
      ).tasks[fixture.primaryTaskId].maintenance_actions;
      expect(maintenanceActions).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "REQUEST_RUNTIME_ROTATION" }),
      ]));
      expect(maintenanceActions).not.toEqual(expect.arrayContaining([
        expect.objectContaining({
          type: "REQUEST_CANDIDATE_HOLD_REVALIDATION",
        }),
      ]));
    } finally {
      stale.runtime.kill("SIGTERM");
    }
  });

  it("rejects a controller identity event whose stored prepared marker binds the wrong authority", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      invalidIdentityIncidentMarkerPredecessor: true,
    });
    const incident = installMarkerlessRuntimeIdentityIncident(
      fixture,
      { expectPreparedMarker: true },
    );
    try {
      const rotated = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        fixtureRotationArgs(fixture, {
          rotationId: "rotation-invalid-identity-marker",
          incidentRef:
            "incident://goal-control/invalid-identity-marker",
        }),
      );
      expect(rotated.status).toBe(2);
      expect(`${rotated.stdout}\n${rotated.stderr}`).toContain(
        "INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT",
      );
      expect(readRootProtocolSeal(fixture.controlRoot))
        .toEqual(fixture.predecessorProtocol);
    } finally {
      incident.runtime.kill("SIGTERM");
    }
  });

  it("rejects a markerless controller-shaped identity event with empty FAIL checks", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      markerlessIdentityIncidentPredecessor: true,
      emptyIdentityIncidentChecksPredecessor: true,
    });
    const incident = installMarkerlessRuntimeIdentityIncident(fixture);
    try {
      const source = JSON.parse(
        incident.sourceBody.toString("utf8"),
      ) as { request?: { checks?: unknown[] } };
      expect(source.request?.checks).toEqual([]);
      const rotated = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        fixtureRotationArgs(fixture, {
          rotationId: "rotation-empty-identity-checks",
          incidentRef:
            "incident://goal-control/empty-identity-checks",
        }),
      );
      expect(rotated.status).toBe(2);
      expect(`${rotated.stdout}\n${rotated.stderr}`).toContain(
        "INVALID_LEGACY_IDENTITY_INCIDENT_RECEIPT",
      );
      expect(readRootProtocolSeal(fixture.controlRoot))
        .toEqual(fixture.predecessorProtocol);
    } finally {
      incident.runtime.kill("SIGTERM");
    }
  });

  it("does not let a valid rotation receipt mask a corrupt adoption source binding", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      historicalGoalMapSubset: true,
      markerlessIdentityIncidentPredecessor: true,
    });
    const incident = installMarkerlessRuntimeIdentityIncident(fixture);
    try {
      const incidentSource = JSON.parse(
        incident.sourceBody.toString("utf8"),
      ) as {
        incident_event: {
          payload: { evidence_id: string };
        };
      };
      installFixtureLegacyEvidenceAnchor(
        fixture,
        incidentSource.incident_event.payload.evidence_id,
      );
      const firstRotation = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        fixtureRotationArgs(fixture, {
          rotationId: "rotation-corrupt-adoption-binding",
          incidentRef:
            "incident://goal-control/corrupt-adoption-binding",
        }),
      );
      if (firstRotation.status !== 0) {
        throw new Error(
          `dual-proof first rotation failed: ${
            firstRotation.stderr || firstRotation.stdout
          }`,
        );
      }
      expect(JSON.parse(firstRotation.stdout)).toMatchObject({
        validation: {
          legacy_identity_incident_count: 1,
        },
      });
      unlinkSync(incident.sourceFile);
      const replayed = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        [
          "status",
          "--goal",
          fixture.primaryGoalId,
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--json",
        ],
      );
      expect(replayed.status).toBe(2);
      expect(`${replayed.stdout}\n${replayed.stderr}`).toContain(
        "LEGACY_EVIDENCE_SOURCE_MISMATCH",
      );
    } finally {
      incident.runtime.kill("SIGTERM");
    }
  });

  it("does not let a valid adoption source binding mask a corrupt rotation receipt", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      historicalGoalMapSubset: true,
      markerlessIdentityIncidentPredecessor: true,
    });
    const incident = installMarkerlessRuntimeIdentityIncident(fixture);
    try {
      installFixtureLegacyEvidenceAnchor(fixture);
      const firstRotation = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        fixtureRotationArgs(fixture, {
          rotationId: "rotation-corrupt-identity-receipt",
          incidentRef:
            "incident://goal-control/corrupt-identity-receipt",
        }),
      );
      if (firstRotation.status !== 0) {
        throw new Error(
          `dual-proof first rotation failed: ${
            firstRotation.stderr || firstRotation.stdout
          }`,
        );
      }
      const protocol = readRootProtocolSeal(fixture.controlRoot);
      const rotationDescriptor = protocol?.protocol_rotations?.[0];
      if (!protocol || !rotationDescriptor) {
        throw new Error("dual-proof rotation receipt missing");
      }
      const rotationFile = path.join(
        fixture.controlRoot,
        rotationDescriptor.relative_path,
      );
      const rotation = JSON.parse(readFileSync(
        rotationFile,
        "utf8",
      )) as Record<string, unknown> & {
        validation_report: Record<string, unknown> & {
          legacy_identity_incident_receipt:
            Record<string, unknown> & {
              incidents: Record<string, Record<string, unknown> & {
                parent_evidence_id: string;
                entry_sha256: string;
              }>;
              incidents_sha256: string;
              sources: Record<string, string>;
              sources_sha256: string;
              receipt_sha256: string;
            };
        };
        validation_report_sha256: string;
        receipt_sha256: string;
      };
      const identityReceipt =
        rotation.validation_report
          .legacy_identity_incident_receipt;
      const entry = Object.values(identityReceipt.incidents)[0];
      entry.parent_evidence_id =
        `${entry.parent_evidence_id}-forged`;
      const {
        entry_sha256: _previousEntrySha256,
        ...unsignedEntry
      } = entry;
      entry.entry_sha256 = hashObject(unsignedEntry);
      identityReceipt.incidents_sha256 =
        hashObject(identityReceipt.incidents);
      identityReceipt.sources_sha256 =
        hashObject(identityReceipt.sources);
      const {
        receipt_sha256: _previousIdentityReceiptSha256,
        ...unsignedIdentityReceipt
      } = identityReceipt;
      identityReceipt.receipt_sha256 =
        hashObject(unsignedIdentityReceipt);
      rotation.validation_report_sha256 =
        hashObject(rotation.validation_report);
      rotation.request_sha256 = hashObject({
        schema_version: 1,
        rotation_id: rotation.rotation_id,
        incident_ref: rotation.incident_ref,
        old_controller_drain_ack:
          rotation.old_controller_drain_ack,
        expected_predecessor_seal_sha256:
          (
            rotation.predecessor_protocol as {
              seal_sha256: string;
            }
          ).seal_sha256,
        operator_request_sha256:
          rotation.operator_request_sha256,
        predecessor_protocol: rotation.predecessor_protocol,
        successor_protocol: rotation.successor_protocol,
        migration_artifacts_sha256:
          rotation.migration_artifacts_sha256,
        source_state_vector_sha256:
          rotation.source_state_vector_sha256,
        validation_report_sha256:
          rotation.validation_report_sha256,
        goal_worktree_map_sha256:
          rotation.goal_worktree_map_sha256,
      });
      const {
        receipt_sha256: _previousRotationReceiptSha256,
        ...unsignedRotation
      } = rotation;
      rotation.receipt_sha256 = hashObject(unsignedRotation);
      const rotationBody = `${canonicalJson(rotation)}\n`;
      const rotationSha256 = `sha256:${sha256(rotationBody)}`;
      const forgedRotationRelativePath =
        `.protocol-rotations.v1/${
          rotationSha256.slice("sha256:".length)
        }.json`;
      const forgedRotationFile = path.join(
        fixture.controlRoot,
        forgedRotationRelativePath,
      );
      writeFileSync(forgedRotationFile, rotationBody, {
        mode: 0o600,
      });
      unlinkSync(rotationFile);
      rotationDescriptor.relative_path =
        forgedRotationRelativePath;
      rotationDescriptor.sha256 = rotationSha256;
      const {
        seal_sha256: _previousProtocolSealSha256,
        ...unsignedProtocol
      } = protocol;
      protocol.seal_sha256 = hashObject(unsignedProtocol);
      writeFixtureJson(
        path.join(fixture.controlRoot, ".store-protocol.json"),
        protocol,
      );
      unlinkSync(incident.sourceFile);
      const replayed = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        [
          "status",
          "--goal",
          fixture.primaryGoalId,
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--json",
        ],
      );
      expect(replayed.status).toBe(2);
      expect(`${replayed.stdout}\n${replayed.stderr}`).toContain(
        "source context binding 非法",
      );
    } finally {
      incident.runtime.kill("SIGTERM");
    }
  });

  it("seals a resolved historical canonical stale-head incident and replays it across a later worker and decoder", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      markerlessIdentityIncidentPredecessor: true,
    });
    const incident = installMarkerlessRuntimeIdentityIncident(
      fixture,
      { conflictKind: "CANONICAL_STALE_HEAD" },
    );
    try {
      const held = predecessorTaskState(fixture);
      const resolutionEvidenceId =
        "resolution-markerless-historical";
      writeFixtureEvidence(fixture, {
        evidenceId: resolutionEvidenceId,
        kind: "HOLD_RESOLUTION",
        status: "PASS",
        producerRole: "FOREMAN",
        producerThreadId: fixture.foremanThreadId,
        state: held,
      });
      const resolved = submitPredecessorEvent(fixture, {
        eventId: "resolve-markerless-historical",
        type: "RESOLVE_HOLD",
        role: "FOREMAN",
        threadId: fixture.foremanThreadId,
        actorSequence: 2,
        capabilityFile: fixture.foremanCapability,
        payload: {
          hold_id: incident.holdId,
          authority:
            "historical markerless incident fixed before decoder rotation",
          resolution_evidence_id: resolutionEvidenceId,
          disposition: "FIXED",
        },
      });
      if (resolved.result.status !== 0) {
        throw new Error(
          `historical hold resolution failed: ${
            resolved.result.stderr || resolved.result.stdout
          }`,
        );
      }
      const d1 = predecessorTaskState(fixture).sessions.DEV;
      const lost = submitPredecessorEvent(fixture, {
        eventId: "role-lost-markerless-dev-d1",
        type: "ROLE_LOST",
        role: "CAPTAIN",
        threadId: incident.captainThreadId,
        actorSequence: 5,
        capabilityFile: incident.captainCapability,
        payload: {
          role: "DEV",
          reason: "replace producer after resolved historical incident",
          expected_thread_id: d1.thread_id,
          expected_host_id: d1.host_id,
          expected_attempt: 1,
          expected_lease_until: (
            d1 as typeof d1 & { lease_until: string }
          ).lease_until,
        },
      });
      if (lost.result.status !== 0) {
        throw new Error(
          `historical producer ROLE_LOST failed: ${
            lost.result.stderr || lost.result.stdout
          }`,
        );
      }
      const d2ThreadId = "dev-markerless-runtime-successor";
      registerPredecessorRole(fixture, {
        role: "DEV",
        threadId: d2ThreadId,
        authorizerCapabilityFile: incident.captainCapability,
        launchId: "launch-markerless-runtime-dev-successor",
        attempt: 2,
      });
      const recovered = submitPredecessorEvent(fixture, {
        eventId: "role-recovered-markerless-dev-d2",
        type: "ROLE_RECOVERED",
        role: "CAPTAIN",
        threadId: incident.captainThreadId,
        actorSequence: 6,
        capabilityFile: incident.captainCapability,
        payload: {
          successor_thread_id: d2ThreadId,
        },
      });
      if (recovered.result.status !== 0) {
        throw new Error(
          `historical producer ROLE_RECOVERED failed: ${
            recovered.result.stderr || recovered.result.stdout
          }`,
        );
      }
      expect(predecessorTaskState(fixture)).toMatchObject({
        holds: [],
        sessions: {
          DEV: {
            thread_id: d2ThreadId,
          },
        },
      });

      const firstRotation = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        fixtureRotationArgs(fixture, {
          rotationId: "rotation-resolved-markerless-first",
          incidentRef:
            "incident://goal-control/resolved-markerless-first",
        }),
      );
      if (firstRotation.status !== 0) {
        throw new Error(
          `first resolved markerless rotation failed: ${
            firstRotation.stderr || firstRotation.stdout
          }`,
        );
      }
      expect(JSON.parse(firstRotation.stdout)).toMatchObject({
        validation: {
          legacy_identity_incident_count: 1,
        },
      });
      unlinkSync(incident.sourceFile);

      const futureController = path.join(
        path.dirname(fixture.controlRoot),
        "future-controller",
      );
      fixtureGit(
        fixture.repository,
        "worktree",
        "add",
        "--detach",
        futureController,
        "HEAD",
      );
      installFixtureController(futureController, false);
      const futureDecoder = path.join(
        futureController,
        "scripts",
        "goal-control",
        "validation.js",
      );
      const futureSource = readFileSync(futureDecoder, "utf8");
      const futureTransformed =
        `${futureSource}\n// isolated-test successor decoder fingerprint\n`;
      expect(futureTransformed).not.toBe(futureSource);
      writeFileSync(futureDecoder, futureTransformed);
      fixtureGit(futureController, "add", "scripts");
      fixtureGit(
        futureController,
        "commit",
        "-qm",
        "install next decoder successor",
      );
      const firstProtocol = readRootProtocolSeal(fixture.controlRoot);
      if (!firstProtocol) throw new Error("first protocol seal missing");
      const futureGoalctl = path.join(
        futureController,
        "scripts",
        "goalctl.js",
      );
      const secondRotation = runFixtureGoalctl(
        futureGoalctl,
        fixture.repository,
        fixture.controlRoot,
        fixtureRotationArgs(fixture, {
          rotationId: "rotation-resolved-markerless-second",
          incidentRef:
            "incident://goal-control/resolved-markerless-second",
          expectedPredecessorSealSha256:
            firstProtocol.seal_sha256,
          predecessorControllerWorktree: fixture.repository,
        }),
      );
      if (secondRotation.status !== 0) {
        throw new Error(
          `second resolved markerless rotation failed: ${
            secondRotation.stderr || secondRotation.stdout
          }`,
        );
      }
      expect(JSON.parse(secondRotation.stdout)).toMatchObject({
        validation: {
          legacy_identity_incident_count: 0,
        },
      });
      const replayed = runFixtureGoalctl(
        futureGoalctl,
        fixture.repository,
        fixture.controlRoot,
        [
          "status",
          "--goal",
          fixture.primaryGoalId,
          "--repository-worktree",
          fixture.predecessorWorktree,
          "--json",
        ],
      );
      expect(replayed.status).toBe(0);
      expect(JSON.parse(replayed.stdout)).toMatchObject({
        tasks: {
          [fixture.primaryTaskId]: {
            holds: [],
            sessions: {
              DEV: {
                thread_id: d2ThreadId,
              },
            },
          },
        },
      });
    } finally {
      incident.runtime.kill("SIGTERM");
    }
  });

  it("rotates a predecessor-accepted overwritten PASS PREFLIGHT without weakening live runtime binding", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
    });
    const historical =
      installAcceptedHistoricalPreflightOverwrite(fixture);
    const registryBefore = artifactIdentity(historical.registryFile);
    const canonicalBefore = artifactIdentity(
      historical.canonicalLaunchFile,
    );
    const immutableBefore = artifactIdentity(
      historical.immutableLaunchFile,
    );
    const acceptedEventBefore = artifactIdentity(
      historical.acceptedEventFile,
    );
    expect(historical.record).toMatchObject({
      status: "PASS",
      launch_uri:
        pathToFileURL(historical.canonicalLaunchFile).href,
      launch_sha256: historical.immutableLaunchSha256,
    });
    expect(historical.record).not.toHaveProperty(
      "runtime_launch_uri",
    );
    expect(historical.record).not.toHaveProperty(
      "runtime_launch_sha256",
    );
    expect(historical.acceptedEvent).toMatchObject({
      event_id: "dev-ready-accepted-historical-preflight",
      evidence_registry_sha256:
        expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      payload: {
        evidence: {
          preflight: historical.evidenceId,
        },
      },
    });

    const args = fixtureRotationArgs(fixture, {
      rotationId: "rotation-accepted-overwritten-preflight",
      incidentRef:
        "incident://goal-control/accepted-overwritten-preflight",
    });
    const rotated = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      args,
    );

    expect(rotated).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const value = JSON.parse(rotated.stdout) as {
      rotated: boolean;
      validation: {
        protocol_rotation: {
          predecessor_compatibility_overlay: {
            live_root_mutated: boolean;
            predecessor_protocol_seal_sha256: string;
            record_count: number;
            read_overlay_record_count: number;
            records: Array<Record<string, unknown>>;
          };
          predecessor_semantic_replay_sha256: string;
          successor_semantic_replay_sha256: string;
          semantic_replay_match: boolean;
        };
      };
    };
    const protocolRotation = value.validation.protocol_rotation;
    expect(value.rotated).toBe(true);
    expect(protocolRotation.semantic_replay_match).toBe(true);
    expect(protocolRotation.predecessor_semantic_replay_sha256)
      .toBe(protocolRotation.successor_semantic_replay_sha256);
    expect(
      protocolRotation.predecessor_compatibility_overlay,
    ).toMatchObject({
      live_root_mutated: false,
      predecessor_protocol_seal_sha256:
        fixture.predecessorProtocol.seal_sha256,
      record_count: 1,
      read_overlay_record_count: 0,
      records: [{
        goal_id: fixture.primaryGoalId,
        task_id: fixture.primaryTaskId,
        evidence_id: historical.evidenceId,
        source_registry_sha256:
          historical.record.registry_sha256,
        source_launch_uri:
          pathToFileURL(historical.canonicalLaunchFile).href,
        overwritten_canonical_launch_sha256:
          historical.canonicalLaunchSha256,
        sealed_launch_sha256:
          historical.immutableLaunchSha256,
        observed_overwrite_fields: [
          "created_at",
          "repository.full_head",
        ],
        accepted_event_replay: true,
        predecessor_protocol_seal_sha256:
          fixture.predecessorProtocol.seal_sha256,
        read_overlay_kind:
          "SEALED_ACCEPTED_REPLAY_NO_OVERLAY",
        read_overlay_relative_path: null,
        overlay_launch_uri:
          pathToFileURL(historical.canonicalLaunchFile).href,
        overlay_registry_sha256:
          historical.record.registry_sha256,
      }],
    });
    expect(artifactIdentity(historical.registryFile))
      .toEqual(registryBefore);
    expect(artifactIdentity(historical.canonicalLaunchFile))
      .toEqual(canonicalBefore);
    expect(artifactIdentity(historical.immutableLaunchFile))
      .toEqual(immutableBefore);
    expect(artifactIdentity(historical.acceptedEventFile))
      .toEqual(acceptedEventBefore);

    const successorReplay = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      [
        "status",
        "--repository-worktree",
        fixture.predecessorWorktree,
        "--goal",
        fixture.primaryGoalId,
        "--json",
      ],
    );
    expect(successorReplay).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    expect(JSON.parse(successorReplay.stdout)).toMatchObject({
      tasks: {
        [fixture.primaryTaskId]: {
          phase: "DEV_READY",
        },
      },
    });

    const retry = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      args,
    );
    expect(retry).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    expect(JSON.parse(retry.stdout)).toMatchObject({
      rotated: false,
      idempotent: true,
    });
    expect(artifactIdentity(historical.registryFile))
      .toEqual(registryBefore);
    expect(artifactIdentity(historical.canonicalLaunchFile))
      .toEqual(canonicalBefore);
    expect(artifactIdentity(historical.immutableLaunchFile))
      .toEqual(immutableBefore);
    expect(artifactIdentity(historical.acceptedEventFile))
      .toEqual(acceptedEventBefore);
    expectTransportClean(fixture.controlRoot);
  });

  it("rejects a PREFLIGHT compatibility overlay when the immutable launch no longer matches the sealed hash", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      predecessorValidatesAllPreflightRegistries: true,
    });
    const historical = installHistoricalPreflightOverwrite(fixture);
    writeFileSync(
      historical.immutableLaunchFile,
      `${readFileSync(historical.immutableLaunchFile, "utf8")} `,
    );
    const registryBefore = artifactIdentity(historical.registryFile);
    const canonicalBefore = artifactIdentity(
      historical.canonicalLaunchFile,
    );
    const immutableBefore = artifactIdentity(
      historical.immutableLaunchFile,
    );

    const rejected = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture),
    );

    expect(rejected).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(rejected.stderr).toContain(
      "goalctl[STORE_PROTOCOL_ROTATION_PREFLIGHT_OVERLAY_REJECTED]",
    );
    expect(artifactIdentity(historical.registryFile))
      .toEqual(registryBefore);
    expect(artifactIdentity(historical.canonicalLaunchFile))
      .toEqual(canonicalBefore);
    expect(artifactIdentity(historical.immutableLaunchFile))
      .toEqual(immutableBefore);
    expect(
      readRootProtocolSeal(fixture.controlRoot)?.protocol_rotations ?? [],
    ).toEqual([]);
    expectTransportClean(fixture.controlRoot);
  });

  it("runs the CLI wrapper through explicit-map rotation, exact retry, mismatch rejection, and post-rotation canaries", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      additionalGoal: true,
      historicalGoalMapSubset: true,
    });
    const goalWorktreesFile =
      writeFixtureGoalWorktreeMap(fixture);
    const pristine = completeControlTree(fixture.controlRoot);
    const canonicalArgs = fixtureRotationArgs(fixture, {
      goalWorktreesFile,
    });
    const mapOptionIndex = canonicalArgs.indexOf(
      "--goal-worktrees-file",
    );
    expect(mapOptionIndex).toBeGreaterThan(0);

    const missingMapValue = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      canonicalArgs.filter((_, index) => (
        index !== mapOptionIndex + 1
      )),
    );
    expect(missingMapValue).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(missingMapValue.stderr).toContain(
      "goalctl[ARG_REQUIRED]",
    );
    expect(missingMapValue.stderr).toContain(
      "--goal-worktrees-file",
    );
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(pristine);

    const relativeMap = path.relative(
      fixture.repository,
      goalWorktreesFile,
    );
    expect(path.isAbsolute(relativeMap)).toBe(false);
    const nonCanonicalMap = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        goalWorktreesFile: relativeMap,
      }),
    );
    expect(nonCanonicalMap).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(nonCanonicalMap.stderr).toContain(
      "goalctl[INVALID_ARGUMENT]",
    );
    expect(nonCanonicalMap.stderr).toContain(
      "--goal-worktrees-file",
    );
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(pristine);

    const predecessorDecoderMismatch = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        goalWorktreesFile,
        predecessorControllerWorktree: fixture.repository,
      }),
    );
    expect(predecessorDecoderMismatch).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(predecessorDecoderMismatch.stderr).toContain(
      "goalctl[STORE_PROTOCOL_ROTATION_PREDECESSOR_DECODER_MISMATCH]",
    );
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(pristine);

    const predecessorMismatch = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        goalWorktreesFile,
        expectedPredecessorSealSha256:
          `sha256:${"0".repeat(64)}`,
      }),
    );
    expect(predecessorMismatch).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(predecessorMismatch.stderr).toContain(
      "goalctl[STORE_PROTOCOL_ROTATION_PREDECESSOR_MISMATCH]",
    );
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(pristine);

    const first = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      canonicalArgs,
    );
    expect(first).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const firstValue = JSON.parse(first.stdout) as {
      operation: string;
      rotated: boolean;
      idempotent: boolean;
      entry_generation: number;
      exit_generation: number;
      source_state_vector_sha256: string;
      protocol: RootProtocol;
      rotation_receipt: RotationDescriptor;
      validation: {
        goal_count: number;
        legacy_identity_incident_receipt: {
          kind: string;
          controller_decoder_sha256: string;
          source_state_vector_sha256: string;
          predecessor_protocol_seal_sha256: string;
          migration_receipt: {
            incident_ref: string;
            old_controller_drain_ack: string;
          };
          incidents: Record<string, unknown>;
          sources: Record<string, string>;
          receipt_sha256: string;
        };
        goal_worktree_map: {
          goal_worktrees: Array<{
            goal_id: string;
            repository_worktree: string;
          }>;
        };
        protocol_rotation: {
          semantic_replay_match: boolean;
          predecessor_strict_probe: { status: string };
        };
      };
    };
    expect(firstValue).toMatchObject({
      operation: "STORE_PROTOCOL_ROTATION",
      rotated: true,
      idempotent: false,
      protocol: {
        schema_version: 3,
        migration_artifacts:
          fixture.predecessorProtocol.migration_artifacts,
        protocol_rotations: [firstValue.rotation_receipt],
      },
      validation: {
        goal_count: fixture.goalIds.length,
        legacy_identity_incident_receipt: {
          kind: "LEGACY_IDENTITY_INCIDENT_BINDINGS",
          controller_decoder_sha256:
            firstValue.protocol.controller_decoder_sha256,
          source_state_vector_sha256:
            firstValue.source_state_vector_sha256,
          predecessor_protocol_seal_sha256:
            fixture.predecessorProtocol.seal_sha256,
          migration_receipt: {
            incident_ref:
              "incident://goal-control/rotation-cli-success",
            old_controller_drain_ack:
              "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
          },
          incidents: {},
          sources: {},
          receipt_sha256:
            expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        },
        protocol_rotation: {
          semantic_replay_match: true,
          predecessor_strict_probe: { status: "PASS" },
        },
      },
    });
    expect(firstValue.exit_generation)
      .toBe(firstValue.entry_generation + 2);
    expect(firstValue.validation.goal_worktree_map.goal_worktrees)
      .toEqual(fixture.goalIds.map((goalId) => (
        expect.objectContaining({
          goal_id: goalId,
          repository_worktree: fixture.predecessorWorktree,
        })
      )));

    const retry = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      canonicalArgs,
    );
    expect(retry).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    expect(JSON.parse(retry.stdout)).toMatchObject({
      operation: "STORE_PROTOCOL_ROTATION",
      rotated: false,
      idempotent: true,
      entry_generation: firstValue.entry_generation,
      exit_generation: firstValue.exit_generation,
      rotation_receipt: firstValue.rotation_receipt,
    });

    const canaries = [
      [
        "status",
        "--goal",
        fixture.primaryGoalId,
        "--json",
      ],
      [
        "next",
        "--goal",
        fixture.primaryGoalId,
        "--json",
      ],
      [
        "doctor",
        "--goal",
        fixture.primaryGoalId,
        "--json",
      ],
      [
        "actions",
        "--goal",
        fixture.primaryGoalId,
        "--task",
        fixture.primaryTaskId,
        "--role",
        "FOREMAN",
        "--thread",
        fixture.foremanThreadId,
        "--json",
      ],
    ];
    for (const canaryArgs of canaries) {
      const canary = runFixtureGoalctl(
        fixture.goalctl,
        fixture.repository,
        fixture.controlRoot,
        [
          ...canaryArgs,
          "--repository-worktree",
          fixture.predecessorWorktree,
        ],
      );
      expect(canary).toMatchObject({
        status: 0,
        signal: null,
        stderr: "",
      });
      expect(() => JSON.parse(canary.stdout)).not.toThrow();
    }

    const predecessorGoalctl = path.join(
      fixture.predecessorWorktree,
      "scripts",
      "goalctl.js",
    );
    const predecessorCanary = runFixtureGoalctl(
      predecessorGoalctl,
      fixture.predecessorWorktree,
      fixture.controlRoot,
      [
        "status",
        "--repository-worktree",
        fixture.predecessorWorktree,
        "--goal",
        fixture.primaryGoalId,
        "--json",
      ],
    );
    expect(predecessorCanary).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(predecessorCanary.stderr).toMatch(
      /goalctl\[(?:STORE_PROTOCOL_UNSUPPORTED|CORRUPT_STORE_PROTOCOL)\]/,
    );

    const generation = JSON.parse(readFileSync(
      path.join(fixture.controlRoot, ".generation.json"),
      "utf8",
    )) as {
      generation: number;
      active_transaction: unknown;
      pre_write_vector_sha256: unknown;
    };
    expect(generation).toMatchObject({
      generation: firstValue.exit_generation,
      active_transaction: null,
      pre_write_vector_sha256: null,
    });
    expect(generation.generation % 2).toBe(0);
    expectTransportClean(fixture.controlRoot);
  });

  it("rotates from a clean committed controller in an independent Git repository", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
    });
    const independentController = path.join(
      path.dirname(fixture.repository),
      "independent-successor-controller",
    );
    mkdirSync(independentController, { recursive: true });
    fixtureGit(independentController, "init", "-q", "-b", "main");
    fixtureGit(
      independentController,
      "config",
      "user.email",
      "independent-controller@example.test",
    );
    fixtureGit(
      independentController,
      "config",
      "user.name",
      "Independent Controller Test",
    );
    installFixtureController(independentController, false);
    writeFileSync(
      path.join(independentController, "README.md"),
      "# independent successor controller\n",
    );
    fixtureGit(independentController, "add", ".");
    fixtureGit(
      independentController,
      "commit",
      "-qm",
      "install independent successor controller",
    );
    const independentGoalctl = path.join(
      independentController,
      "scripts",
      "goalctl.js",
    );
    const controlledCommonDir = realpathSync(fixtureGit(
      fixture.repository,
      "rev-parse",
      "--path-format=absolute",
      "--git-common-dir",
    ));
    const controllerCommonDir = realpathSync(fixtureGit(
      independentController,
      "rev-parse",
      "--path-format=absolute",
      "--git-common-dir",
    ));
    expect(controllerCommonDir).not.toBe(controlledCommonDir);

    const pristine = completeControlTree(fixture.controlRoot);
    const dirtyMarker = path.join(
      independentController,
      "uncommitted-controller-change.txt",
    );
    writeFileSync(dirtyMarker, "must fail closed\n");
    const dirty = runFixtureGoalctl(
      independentGoalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        rotationId: "rotation-independent-controller",
        incidentRef:
          "incident://goal-control/independent-controller",
      }),
    );
    expect(dirty).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(dirty.stderr).toContain(
      "goalctl[FROZEN_WORKTREE_DIRTY]",
    );
    expect(completeControlTree(fixture.controlRoot)).toEqual(pristine);
    rmSync(dirtyMarker);

    const rotated = runFixtureGoalctl(
      independentGoalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        rotationId: "rotation-independent-controller",
        incidentRef:
          "incident://goal-control/independent-controller",
      }),
    );
    expect(rotated).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const value = JSON.parse(rotated.stdout) as {
      rotated: boolean;
      validation: {
        protocol_rotation: {
          predecessor_controller: {
            repository_worktree: string;
            repository_common_dir: string;
          };
          successor_controller: {
            repository_worktree: string;
            repository_common_dir: string;
            repository_head: string;
            decoder_directory: string;
            decoder_sha256: string;
            controller_closure_sha256: string;
          };
          semantic_replay_match: boolean;
        };
      };
    };
    const successor =
      value.validation.protocol_rotation.successor_controller;
    expect(value.rotated).toBe(true);
    expect(
      value.validation.protocol_rotation.semantic_replay_match,
    ).toBe(true);
    expect(successor).toEqual({
      repository_worktree: realpathSync(independentController),
      repository_common_dir: controllerCommonDir,
      repository_head: fixtureGit(
        independentController,
        "rev-parse",
        "HEAD",
      ),
      decoder_directory: realpathSync(path.join(
        independentController,
        "scripts",
        "goal-control",
      )),
      decoder_sha256: controllerDecoderFingerprintAt(path.join(
        independentController,
        "scripts",
        "goal-control",
      )),
      controller_closure_sha256:
        expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    });
    expect(
      value.validation.protocol_rotation
        .predecessor_controller.repository_common_dir,
    ).toBe(controlledCommonDir);
    expect(
      value.validation.protocol_rotation
        .predecessor_controller.repository_worktree,
    ).toBe(fixture.predecessorWorktree);
    expectTransportClean(fixture.controlRoot);
  });

  it("rotates between independent predecessor and successor controller repositories while Goal worktrees stay controlled", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
    });
    const parent = path.dirname(fixture.repository);
    const predecessor = createIndependentControllerRepository(
      parent,
      "independent-controller-v01",
    );
    const successor = createIndependentControllerRepository(
      parent,
      "independent-controller-v02",
      "independent controller v0.2 fingerprint",
    );
    const controlledCommonDir = realpathSync(fixtureGit(
      fixture.repository,
      "rev-parse",
      "--path-format=absolute",
      "--git-common-dir",
    ));
    expect(new Set([
      controlledCommonDir,
      predecessor.commonDir,
      successor.commonDir,
    ]).size).toBe(3);
    expect(predecessor.decoderSha256)
      .not.toBe(successor.decoderSha256);

    const first = runFixtureGoalctl(
      predecessor.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        rotationId: "rotation-independent-v01",
        incidentRef:
          "incident://goal-control/independent-v01",
      }),
    );
    expect(first).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const firstValue = JSON.parse(first.stdout) as {
      protocol: RootProtocol;
      validation: {
        protocol_rotation: {
          successor_controller: {
            repository_worktree: string;
            repository_common_dir: string;
            repository_head: string;
            decoder_sha256: string;
          };
        };
      };
    };
    expect(
      firstValue.validation.protocol_rotation.successor_controller,
    ).toMatchObject({
      repository_worktree: predecessor.repository,
      repository_common_dir: predecessor.commonDir,
      repository_head: predecessor.head,
      decoder_sha256: predecessor.decoderSha256,
    });

    const pristineAfterFirst =
      completeControlTree(fixture.controlRoot);
    const secondRotationOptions = {
      expectedPredecessorSealSha256:
        firstValue.protocol.seal_sha256,
      rotationId: "rotation-independent-v02",
      incidentRef:
        "incident://goal-control/independent-v02",
    };
    const wrongRepository = runFixtureGoalctl(
      successor.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        ...secondRotationOptions,
        predecessorControllerWorktree: successor.repository,
      }),
    );
    expect(wrongRepository).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(wrongRepository.stderr).toContain(
      "goalctl[STORE_PROTOCOL_ROTATION_PREDECESSOR_DECODER_MISMATCH]",
    );
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(pristineAfterFirst);

    const dirtyMarker = path.join(
      predecessor.repository,
      "uncommitted-predecessor-change.txt",
    );
    writeFileSync(dirtyMarker, "must fail closed\n");
    const dirtyPredecessor = runFixtureGoalctl(
      successor.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        ...secondRotationOptions,
        predecessorControllerWorktree: predecessor.repository,
      }),
    );
    expect(dirtyPredecessor).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(dirtyPredecessor.stderr).toContain(
      "goalctl[FROZEN_WORKTREE_DIRTY]",
    );
    expect(completeControlTree(fixture.controlRoot))
      .toEqual(pristineAfterFirst);
    rmSync(dirtyMarker);

    const second = runFixtureGoalctl(
      successor.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        ...secondRotationOptions,
        predecessorControllerWorktree: predecessor.repository,
      }),
    );
    expect(second).toMatchObject({
      status: 0,
      signal: null,
      stderr: "",
    });
    const secondValue = JSON.parse(second.stdout) as {
      rotated: boolean;
      validation: {
        goal_worktree_map: {
          goal_worktrees: Array<{
            repository_worktree: string;
            repository_common_dir: string;
          }>;
        };
        protocol_rotation: {
          predecessor_controller: {
            repository_worktree: string;
            repository_common_dir: string;
            repository_head: string;
            decoder_sha256: string;
            controller_closure_sha256: string;
          };
          successor_controller: {
            repository_worktree: string;
            repository_common_dir: string;
            repository_head: string;
            decoder_sha256: string;
            controller_closure_sha256: string;
          };
          semantic_replay_match: boolean;
        };
      };
    };
    expect(secondValue.rotated).toBe(true);
    expect(secondValue.validation.protocol_rotation).toMatchObject({
      predecessor_controller: {
        repository_worktree: predecessor.repository,
        repository_common_dir: predecessor.commonDir,
        repository_head: predecessor.head,
        decoder_sha256: predecessor.decoderSha256,
        controller_closure_sha256:
          expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      },
      successor_controller: {
        repository_worktree: successor.repository,
        repository_common_dir: successor.commonDir,
        repository_head: successor.head,
        decoder_sha256: successor.decoderSha256,
        controller_closure_sha256:
          expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      },
      semantic_replay_match: true,
    });
    expect(
      secondValue.validation.goal_worktree_map.goal_worktrees,
    ).toEqual(fixture.goalIds.map(() => expect.objectContaining({
      repository_worktree: fixture.predecessorWorktree,
      repository_common_dir: controlledCommonDir,
    })));
    expectTransportClean(fixture.controlRoot);
  });

  it("SIGKILLs a hung predecessor replay, releases the writer lock, and preserves all control bytes", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      hangingPredecessorReplay: true,
    });
    const before = completeControlTree(fixture.controlRoot);

    const rotated = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        goalWorktreesFile: null,
        rotationId: "rotation-hung-predecessor-replay",
        incidentRef:
          "incident://goal-control/hung-predecessor-replay",
      }),
      {
        GOAL_CONTROL_TEST_HANG_PREDECESSOR_REPLAY: "1",
        GOAL_CONTROL_TEST_PREDECESSOR_REPLAY_TIMEOUT_MILLISECONDS:
          "100",
      },
    );

    expect(rotated).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(rotated.stderr).toContain(
      "goalctl[STORE_PROTOCOL_ROTATION_PREDECESSOR_REPLAY_FAILED]",
    );
    expect(rotated.stderr).toContain("SIGKILL");
    expect(completeControlTree(fixture.controlRoot)).toEqual(before);
    expectTransportClean(fixture.controlRoot);
  });

  it("SIGKILLs a hung predecessor strict probe before lock acquisition and preserves all control bytes", () => {
    const fixture = createPendingBootstrapRotationFixture({
      pendingBootstrapRepair: false,
      hangingPredecessorProbe: true,
    });
    const before = completeControlTree(fixture.controlRoot);

    const rotated = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      fixtureRotationArgs(fixture, {
        goalWorktreesFile: null,
        rotationId: "rotation-hung-predecessor-probe",
        incidentRef:
          "incident://goal-control/hung-predecessor-probe",
      }),
      {
        GOAL_CONTROL_TEST_HANG_PREDECESSOR_PROBE: "1",
        GOAL_CONTROL_TEST_PREDECESSOR_PROBE_TIMEOUT_MILLISECONDS:
          "100",
      },
    );

    expect(rotated).toMatchObject({
      status: 2,
      signal: null,
      stdout: "",
    });
    expect(rotated.stderr).toContain(
      "goalctl[STORE_PROTOCOL_ROTATION_PREDECESSOR_PROBE_FAILED]",
    );
    expect(rotated.stderr).toContain("SIGKILL");
    expect(completeControlTree(fixture.controlRoot)).toEqual(before);
    expectTransportClean(fixture.controlRoot);
  });

  it("keeps a pending BOOTSTRAP consumption repair byte-exact when rotate-store-protocol replay fails closed", () => {
    const fixture = createPendingBootstrapRotationFixture();
    const before = completeControlTree(fixture.controlRoot);
    const metadataBefore = readFileSync(fixture.goalMetadata);
    const capabilityBefore = readFileSync(
      fixture.bootstrapCapability,
    );
    const generationBefore = readFileSync(path.join(
      fixture.controlRoot,
      ".generation.json",
    ));
    const protocolBefore = readFileSync(path.join(
      fixture.controlRoot,
      ".store-protocol.json",
    ));

    const rotated = runFixtureGoalctl(
      fixture.goalctl,
      fixture.repository,
      fixture.controlRoot,
      [
        "rotate-store-protocol",
        "--repository-worktree",
        fixture.repository,
        "--rotation-id",
        "rotation-bootstrap-pending",
        "--predecessor-controller-worktree",
        fixture.predecessorWorktree,
        "--expected-predecessor-seal-sha256",
        fixture.predecessorProtocol.seal_sha256,
        "--incident-ref",
        "incident://goal-control/bootstrap-pending-read-only-replay",
        "--acknowledge-old-controller-drained",
        "ALL_OLD_CONTROLLERS_DRAINED_AND_ISOLATED",
        "--json",
      ],
    );

    expect(rotated.status).toBe(2);
    expect(rotated.signal).toBeNull();
    expect(rotated.stdout).toBe("");
    expect(rotated.stderr).toMatch(
      /(?:BOOTSTRAP|bootstrap).*(?:REPAIR|repair|consum)/,
    );
    expect(completeControlTree(fixture.controlRoot)).toEqual(before);
    expect(readFileSync(fixture.bootstrapCapability))
      .toEqual(capabilityBefore);
    expect(capabilityBefore).toEqual(
      fixture.bootstrapCapabilityBytes,
    );
    const metadataAfter = JSON.parse(readFileSync(
      fixture.goalMetadata,
      "utf8",
    )) as Record<string, unknown>;
    expect(metadataAfter.bootstrap_consumed_at).toBeUndefined();
    expect(readFileSync(fixture.goalMetadata)).toEqual(metadataBefore);
    expect(readFileSync(path.join(
      fixture.controlRoot,
      ".generation.json",
    ))).toEqual(generationBefore);
    expect(readFileSync(path.join(
      fixture.controlRoot,
      ".store-protocol.json",
    ))).toEqual(protocolBefore);
    expect(existsSync(path.join(
      fixture.controlRoot,
      ".protocol-rotations.v1",
    ))).toBe(false);
    expectTransportClean(fixture.controlRoot);
  });
});
