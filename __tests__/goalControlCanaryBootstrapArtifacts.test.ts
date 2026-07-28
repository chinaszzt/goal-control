import { createHash } from "crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "fs";
import { createRequire } from "module";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";

type JsonRecord = Record<string, unknown>;

type PublicationInspection = {
  state:
    | "ABSENT"
    | "STAGING_ONLY"
    | "STABLE"
    | "PUBLISHED_TEMP_PENDING_UNLINK";
  target: string;
  temporary: string | null;
  parse_ready: boolean;
  recoverable: boolean;
  recovered?: boolean;
  bytes?: Buffer;
};

type ParsedPrivateJson = {
  value: JsonRecord;
  bytes: Buffer;
  sha256: string;
};

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const nodeRequire = createRequire(import.meta.url);
const {
  inspectPrivateJsonPublication,
  parsePrivateJson,
  publishPrivateJson,
  recoverPrivateJsonPublication,
} = nodeRequire(
  path.join(
    ROOT,
    "scripts",
    "goal-control",
    "canary-bootstrap-artifacts.js",
  ),
) as {
  inspectPrivateJsonPublication: (
    target: string,
    label: string,
    conflictCode?: string,
  ) => PublicationInspection;
  parsePrivateJson: (
    target: string,
    label: string,
  ) => ParsedPrivateJson;
  publishPrivateJson: (
    target: string,
    value: JsonRecord,
    label: string,
    conflictCode: string,
  ) => { created: boolean; bytes: Buffer };
  recoverPrivateJsonPublication: (
    target: string,
    label: string,
    conflictCode?: string,
  ) => PublicationInspection & { recovered: boolean };
};

const roots: string[] = [];

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function privateJsonBytes(value: JsonRecord): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

function createPublicationFixture(basename: string): {
  directory: string;
  target: string;
  temporary: string;
  value: JsonRecord;
  bytes: Buffer;
} {
  const directory = realpathSync(
    mkdtempSync(path.join(tmpdir(), "canary-bootstrap-artifacts-")),
  );
  roots.push(directory);
  chmodSync(directory, 0o700);
  const target = path.join(directory, basename);
  const value = {
    schema_version: 1,
    kind: basename === "intent.json"
      ? "WORKER_CANARY_BOOTSTRAP_INTENT"
      : "WORKER_CANARY_BOOTSTRAP_RECEIPT",
    operation_id: "bootstrap-artifact-mid-publication",
  };
  const bytes = privateJsonBytes(value);
  const temporary = path.join(
    directory,
    `.${basename}.${sha256(bytes)}.tmp`,
  );
  return {
    directory,
    target,
    temporary,
    value,
    bytes,
  };
}

function expectControlCode(
  operation: () => unknown,
  code: string,
): void {
  try {
    operation();
  } catch (error) {
    expect(error).toMatchObject({ code });
    return;
  }
  throw new Error(`expected ${code}`);
}

afterEach(() => {
  while (roots.length > 0) {
    rmSync(roots.pop()!, { recursive: true, force: true });
  }
});

describe("canary bootstrap private artifact publication recovery", () => {
  test.each(["__proto__", "constructor", "prototype"])(
    "rejects canonical JSON dangerous key %s",
    (dangerousKey) => {
      const fixture = createPublicationFixture("receipt.json");
      const bytes = Buffer.from(
        `{"schema_version":1,"nested":{"${dangerousKey}":{"x":1}}}\n`,
      );
      writeFileSync(fixture.target, bytes, { mode: 0o600 });

      expectControlCode(
        () => parsePrivateJson(fixture.target, "dangerous JSON"),
        "CANARY_BOOTSTRAP_ARTIFACT_INVALID",
      );
    },
  );

  test.each(["1e400", "-0", "9007199254740993"])(
    "rejects non-canonical JSON number %s",
    (numberLiteral) => {
      const fixture = createPublicationFixture("receipt.json");
      writeFileSync(
        fixture.target,
        `{"schema_version":1,"value":${numberLiteral}}\n`,
        { mode: 0o600 },
      );

      expectControlCode(
        () => parsePrivateJson(fixture.target, "dangerous number"),
        "CANARY_BOOTSTRAP_ARTIFACT_INVALID",
      );
    },
  );

  test.each(["intent.json", "receipt.json"])(
    "recovers an exact %s target+deterministic-temp hardlink residue before parse",
    (basename) => {
      const fixture = createPublicationFixture(basename);
      writeFileSync(fixture.temporary, fixture.bytes, { mode: 0o600 });
      linkSync(fixture.temporary, fixture.target);
      expect(statSync(fixture.target).dev)
        .toBe(statSync(fixture.temporary).dev);
      expect(statSync(fixture.target).ino)
        .toBe(statSync(fixture.temporary).ino);
      expect(statSync(fixture.target).nlink).toBe(2);
      expect(statSync(fixture.temporary).nlink).toBe(2);
      expectControlCode(
        () => parsePrivateJson(
          fixture.target,
          `${basename} artifact`,
        ),
        "CANARY_BOOTSTRAP_ARTIFACT_INVALID",
      );

      const inspected = inspectPrivateJsonPublication(
        fixture.target,
        `${basename} artifact`,
        "TEST_PUBLICATION_CONFLICT",
      );
      expect(inspected).toMatchObject({
        state: "PUBLISHED_TEMP_PENDING_UNLINK",
        target: fixture.target,
        temporary: fixture.temporary,
        parse_ready: false,
        recoverable: true,
      });
      expect(statSync(fixture.target).nlink).toBe(2);
      expect(statSync(fixture.temporary).nlink).toBe(2);

      const recovered = recoverPrivateJsonPublication(
        fixture.target,
        `${basename} artifact`,
        "TEST_PUBLICATION_CONFLICT",
      );
      expect(recovered).toMatchObject({
        state: "STABLE",
        target: fixture.target,
        temporary: null,
        parse_ready: true,
        recoverable: false,
        recovered: true,
      });
      expect(existsSync(fixture.temporary)).toBe(false);
      expect(statSync(fixture.target).nlink).toBe(1);
      expect(readFileSync(fixture.target)).toEqual(fixture.bytes);

      const parsed = parsePrivateJson(
        fixture.target,
        `${basename} artifact`,
      );
      expect(parsed.value).toEqual(fixture.value);
      expect(parsed.bytes).toEqual(fixture.bytes);
      expect(parsed.sha256).toBe(`sha256:${sha256(fixture.bytes)}`);
    },
  );

  test("fails closed when target and deterministic temp have equal bytes but different inodes", () => {
    const fixture = createPublicationFixture("intent.json");
    writeFileSync(fixture.target, fixture.bytes, { mode: 0o600 });
    writeFileSync(fixture.temporary, fixture.bytes, { mode: 0o600 });
    expect(statSync(fixture.target).ino)
      .not.toBe(statSync(fixture.temporary).ino);

    expectControlCode(
      () => inspectPrivateJsonPublication(
        fixture.target,
        "intent artifact",
        "TEST_PUBLICATION_CONFLICT",
      ),
      "TEST_PUBLICATION_CONFLICT",
    );
    expectControlCode(
      () => recoverPrivateJsonPublication(
        fixture.target,
        "intent artifact",
        "TEST_PUBLICATION_CONFLICT",
      ),
      "TEST_PUBLICATION_CONFLICT",
    );
    expectControlCode(
      () => publishPrivateJson(
        fixture.target,
        fixture.value,
        "intent artifact",
        "TEST_PUBLICATION_CONFLICT",
      ),
      "TEST_PUBLICATION_CONFLICT",
    );
    expect(existsSync(fixture.target)).toBe(true);
    expect(existsSync(fixture.temporary)).toBe(true);
  });

  test("fails closed without cleanup when a different deterministic staging artifact exists", () => {
    const fixture = createPublicationFixture("receipt.json");
    const foreignBytes = privateJsonBytes({
      ...fixture.value,
      operation_id: "different-operation",
    });
    const foreignTemporary = path.join(
      fixture.directory,
      `.receipt.json.${sha256(foreignBytes)}.tmp`,
    );
    writeFileSync(fixture.target, fixture.bytes, { mode: 0o600 });
    writeFileSync(foreignTemporary, foreignBytes, { mode: 0o600 });

    expectControlCode(
      () => inspectPrivateJsonPublication(
        fixture.target,
        "receipt artifact",
        "TEST_PUBLICATION_CONFLICT",
      ),
      "TEST_PUBLICATION_CONFLICT",
    );
    expectControlCode(
      () => recoverPrivateJsonPublication(
        fixture.target,
        "receipt artifact",
        "TEST_PUBLICATION_CONFLICT",
      ),
      "TEST_PUBLICATION_CONFLICT",
    );
    expect(existsSync(fixture.target)).toBe(true);
    expect(existsSync(foreignTemporary)).toBe(true);
    expect(readFileSync(fixture.target)).toEqual(fixture.bytes);
    expect(readFileSync(foreignTemporary)).toEqual(foreignBytes);
  });

  test("rejects an artifact path whose private parent traverses a symlink", () => {
    const parent = realpathSync(
      mkdtempSync(path.join(tmpdir(), "canary-bootstrap-artifact-alias-")),
    );
    roots.push(parent);
    const realDirectory = path.join(parent, "real");
    const aliasDirectory = path.join(parent, "alias");
    mkdirSync(realDirectory, { mode: 0o700 });
    symlinkSync(realDirectory, aliasDirectory);
    const target = path.join(aliasDirectory, "intent.json");
    writeFileSync(
      target,
      privateJsonBytes({
        schema_version: 1,
        kind: "WORKER_CANARY_BOOTSTRAP_INTENT",
      }),
      { mode: 0o600 },
    );

    expectControlCode(
      () => inspectPrivateJsonPublication(
        target,
        "aliased intent artifact",
      ),
      "CANARY_BOOTSTRAP_ARTIFACT_INVALID",
    );
    expectControlCode(
      () => parsePrivateJson(target, "aliased intent artifact"),
      "CANARY_BOOTSTRAP_ARTIFACT_INVALID",
    );
  });
});
