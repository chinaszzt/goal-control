#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { execFileSync, spawn } = require('child_process');
const {
  RECEIPT_TTL_MILLISECONDS,
  assertCanonicalServeEnvironment,
  assertCaptureStillInstalled: assertReceiptCaptureStillInstalled,
  assertCurrentServeEnvironment,
  assertSafeLauncherRuntime,
  closeReceiptCapture,
  deriveServeEnvironment,
  openPrivateJsonReceiptCapture: readReceiptSecure,
  validateTestTtl,
} = require('./browser-canary-runtime');
const {
  assertControllerControlPathsCommitted,
} = require('./canary-controller-attestation');

const LISTENER_HOST = '127.0.0.1';
const CANARY_PATH = '/codex-capability-canary';
const RECEIPT_KIND = 'BROWSER_CANARY_SERVER_READY';
const CANARY_ROLES = new Set(['FOREMAN', 'DEV', 'REVIEW', 'RECEIPT']);
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
const SERVER_SCRIPT_PATH = fs.realpathSync(__filename);
const CONTROLLER_ROOT = fs.realpathSync(
  path.resolve(path.dirname(SERVER_SCRIPT_PATH), '..', '..'),
);
const NODE_EXECUTABLE_PATH = fs.realpathSync(process.execPath);
const CANARY_CONTRACT = Object.freeze({
  contract_version: 1,
  expected_title: 'Codex Capability Canary',
  button_id: 'codex-capability-canary-button',
  status_id: 'codex-capability-canary-status',
  initial_status: 'READY',
  clicked_status: 'CLICKED',
  screenshot_required: true,
});

const CANARY_STYLE = [
  ':root { color-scheme: light; }',
  'body {',
  '  align-items: center;',
  '  background: #f5f7fa;',
  '  display: flex;',
  '  font-family: system-ui, sans-serif;',
  '  justify-content: center;',
  '  margin: 0;',
  '  min-height: 100vh;',
  '}',
  'main {',
  '  background: #ffffff;',
  '  border: 1px solid #d8dee8;',
  '  border-radius: 12px;',
  '  box-shadow: 0 8px 24px rgb(15 23 42 / 8%);',
  '  padding: 32px;',
  '  text-align: center;',
  '}',
  'button {',
  '  background: #155eef;',
  '  border: 0;',
  '  border-radius: 8px;',
  '  color: #ffffff;',
  '  cursor: pointer;',
  '  font: inherit;',
  '  padding: 12px 20px;',
  '}',
  '[role="status"] { font-weight: 700; margin-top: 20px; }',
].join('\n');

const CANARY_SCRIPT = [
  '(() => {',
  `  const button = document.getElementById('${CANARY_CONTRACT.button_id}');`,
  `  const status = document.getElementById('${CANARY_CONTRACT.status_id}');`,
  "  button.addEventListener('click', () => {",
  `    if (status.textContent === '${CANARY_CONTRACT.initial_status}') {`,
  `      status.textContent = '${CANARY_CONTRACT.clicked_status}';`,
  '    }',
  '  });',
  '})();',
].join('\n');

function sha256(value) {
  const input = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
  return crypto.createHash('sha256').update(input).digest('hex');
}

function isCanonicalId(value) {
  return typeof value === 'string' && ID_RE.test(value);
}

function assertCanaryBinding(binding) {
  if (
    !binding
      || !isCanonicalId(binding.goal_id)
      || !CANARY_ROLES.has(binding.role)
      || (
        (binding.role === 'FOREMAN' && binding.task_id !== null)
          || (
            binding.role !== 'FOREMAN'
            && !isCanonicalId(binding.task_id)
          )
      )
  ) {
    throw new Error('canary binding 非法');
  }
}

function implementationSha256() {
  return `sha256:${sha256(fs.readFileSync(SERVER_SCRIPT_PATH))}`;
}

function lsofExecutable() {
  for (const candidate of ['/usr/sbin/lsof', '/usr/bin/lsof']) {
    try {
      if (fs.realpathSync(candidate) === candidate) return candidate;
    } catch {}
  }
  throw new Error('缺少受信任的 lsof，无法验证 canary listener owner');
}

function processStartToken(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const started = execFileSync(
      '/bin/ps',
      ['-p', String(pid), '-o', 'lstart='],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        env: {
          PATH: '/usr/bin:/bin',
          LANG: 'C',
          LC_ALL: 'C',
          TZ: 'UTC',
        },
      },
    ).trim().replace(/\s+/g, ' ');
    return started.length > 0
      ? `sha256:${sha256(`${pid}\n${started}`)}`
      : null;
  } catch {
    return null;
  }
}

function processCommand(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const command = execFileSync(
      '/bin/ps',
      ['-ww', '-p', String(pid), '-o', 'command='],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        env: {
          PATH: '/usr/bin:/bin',
          LANG: 'C',
          LC_ALL: 'C',
          TZ: 'UTC',
        },
      },
    ).trim();
    return command.length > 0 ? command : null;
  } catch {
    return null;
  }
}

function processCommandSha256(pid) {
  const command = processCommand(pid);
  return command ? `sha256:${sha256(command)}` : null;
}

function processExecutablePath(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const output = execFileSync(
      lsofExecutable(),
      ['-nP', '-a', '-p', String(pid), '-d', 'txt', '-Fn'],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        env: {
          PATH: '/usr/bin:/bin:/usr/sbin',
          LANG: 'C',
          LC_ALL: 'C',
        },
      },
    );
    const firstPath = output
      .split('\n')
      .find((line) => line.startsWith('n/') && line.length > 2)
      ?.slice(1);
    if (
      !firstPath
        || !path.isAbsolute(firstPath)
        || fs.realpathSync(firstPath) !== firstPath
    ) {
      return null;
    }
    return firstPath;
  } catch {
    return null;
  }
}

function processCwd(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const output = execFileSync(
      lsofExecutable(),
      ['-nP', '-a', '-p', String(pid), '-d', 'cwd', '-Fn'],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        env: {
          PATH: '/usr/bin:/bin:/usr/sbin',
          LANG: 'C',
          LC_ALL: 'C',
        },
      },
    );
    const paths = output
      .split('\n')
      .filter((line) => line.startsWith('n/') && line.length > 2)
      .map((line) => line.slice(1));
    if (
      paths.length !== 1
        || !path.isAbsolute(paths[0])
        || fs.realpathSync(paths[0]) !== paths[0]
    ) {
      return null;
    }
    return paths[0];
  } catch {
    return null;
  }
}

function parseLsofListenerInventory(output, port) {
  if (typeof output !== 'string') {
    throw new Error('lsof listener inventory 不是文本');
  }
  const records = [];
  let processRecord = null;
  let socketRecord = null;
  const finishSocket = () => {
    if (!socketRecord) return;
    records.push(Object.freeze({
      pid: socketRecord.pid,
      command: socketRecord.command,
      fd: socketRecord.fd,
      protocol: socketRecord.protocol,
      name: socketRecord.name,
      tcp_state: socketRecord.tcp_state,
    }));
    socketRecord = null;
  };
  for (const rawLine of output.split('\n')) {
    if (rawLine.length === 0) continue;
    const field = rawLine[0];
    const value = rawLine.slice(1);
    if (field === 'p') {
      finishSocket();
      if (!/^[1-9][0-9]*$/.test(value)) {
        throw new Error('lsof listener inventory 含非法 PID');
      }
      const pid = Number(value);
      if (!Number.isSafeInteger(pid)) {
        throw new Error('lsof listener inventory PID 超出安全整数');
      }
      processRecord = { pid, command: null };
      continue;
    }
    if (field === 'c') {
      if (!processRecord || processRecord.command !== null || value.length === 0) {
        throw new Error('lsof listener inventory command 结构非法');
      }
      processRecord.command = value;
      continue;
    }
    if (field === 'f') {
      finishSocket();
      if (!processRecord || value.length === 0) {
        throw new Error('lsof listener inventory fd 缺少 process');
      }
      socketRecord = {
        pid: processRecord.pid,
        command: processRecord.command,
        fd: value,
        protocol: null,
        name: null,
        tcp_state: null,
      };
      continue;
    }
    if (!socketRecord) {
      throw new Error(`lsof listener inventory 字段 ${field} 缺少 socket record`);
    }
    if (field === 't') {
      if (socketRecord.protocol !== null || value.length === 0) {
        throw new Error('lsof listener inventory protocol 结构非法');
      }
      socketRecord.protocol = value;
    } else if (field === 'n') {
      if (socketRecord.name !== null || value.length === 0) {
        throw new Error('lsof listener inventory name 结构非法');
      }
      socketRecord.name = value;
    } else if (field === 'T' && value.startsWith('ST=')) {
      if (socketRecord.tcp_state !== null) {
        throw new Error('lsof listener inventory TCP state 重复');
      }
      socketRecord.tcp_state = value.slice(3);
    }
  }
  finishSocket();
  if (records.length === 0) {
    throw new Error(`端口 ${port} 没有 LISTEN socket record`);
  }
  return records;
}

function validateListenerPort(port) {
  if (
    !Number.isSafeInteger(port)
      || port < 1024
      || port > 65535
  ) {
    throw new Error('listener port 必须是 1024..65535 的整数');
  }
}

function readLsofListenerInventory(port, allowEmpty) {
  validateListenerPort(port);
  let output;
  try {
    const [executable, ...args] = listenerInventoryCommand(port);
    output = execFileSync(
      executable,
      args,
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          PATH: '/usr/bin:/bin:/usr/sbin',
          LANG: 'C',
          LC_ALL: 'C',
        },
      },
    );
  } catch (error) {
    if (
      allowEmpty
        && error.status === 1
        && String(error.stdout || '').length === 0
        && String(error.stderr || '').length === 0
    ) {
      return '';
    }
    throw error;
  }
  return output;
}

function inspectListenerInventory(port) {
  const output = readLsofListenerInventory(port, false);
  return Object.freeze({
    port,
    records: Object.freeze(parseLsofListenerInventory(output, port)),
  });
}

function inspectListenerInventoryAllowEmpty(port) {
  const output = readLsofListenerInventory(port, true);
  return Object.freeze({
    port,
    records: Object.freeze(
      output.length === 0 ? [] : parseLsofListenerInventory(output, port),
    ),
  });
}

/*
 * Keep the exact lsof invocation in one place. This deliberately inventories
 * the port globally instead of filtering to the claimed PID first: a second
 * owner, wildcard, IPv6 listener, or duplicate socket record must stay visible
 * and make the attestation fail closed.
 */
function listenerInventoryCommand(port) {
  validateListenerPort(port);
  return Object.freeze([
    lsofExecutable(),
    '-nP',
    `-iTCP:${port}`,
    '-sTCP:LISTEN',
    '-FpcfntT',
  ]);
}

function assertExactListenerInventory(inventory, pid, port) {
  if (!Number.isSafeInteger(pid) || pid <= 0) {
    throw new Error('listener owner PID 非法');
  }
  if (
    !inventory
      || inventory.port !== port
      || !Array.isArray(inventory.records)
  ) {
    throw new Error('listener inventory 结构/端口非法');
  }
  const ownerPids = new Set(inventory.records.map((record) => record.pid));
  if (
    inventory.records.length !== 1
      || ownerPids.size !== 1
      || !ownerPids.has(pid)
  ) {
    throw new Error('listener 必须只有一个 socket record 和一个 owner PID');
  }
  const [record] = inventory.records;
  if (
    typeof record.command !== 'string'
      || record.command.length === 0
      || typeof record.fd !== 'string'
      || !/^[0-9]+$/.test(record.fd)
      || record.protocol !== 'IPv4'
      || record.name !== `${LISTENER_HOST}:${port}`
      || record.tcp_state !== 'LISTEN'
  ) {
    throw new Error(
      'listener 必须唯一精确绑定 IPv4 127.0.0.1:<port> LISTEN，拒绝 wildcard/IPv6',
    );
  }
  return record;
}

function assertUniqueLoopbackListener(pid, port) {
  return assertExactListenerInventory(
    inspectListenerInventory(port),
    pid,
    port,
  );
}

function processOwnsListener(pid, port) {
  try {
    assertUniqueLoopbackListener(pid, port);
    return true;
  } catch {
    return false;
  }
}

function argvSha256(argv) {
  return `sha256:${sha256(JSON.stringify(argv))}`;
}

function gitExecutable() {
  for (const candidate of ['/usr/bin/git', '/opt/homebrew/bin/git']) {
    try {
      if (fs.realpathSync(candidate) === candidate) return candidate;
    } catch {}
  }
  throw new Error('缺少受信任的 git，无法绑定 controller repository HEAD');
}

function controllerRepositoryHead() {
  const git = gitExecutable();
  const commonOptions = {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: '/usr/bin:/bin',
      LANG: 'C',
      LC_ALL: 'C',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_NO_REPLACE_OBJECTS: '1',
    },
  };
  const runGit = (args) => execFileSync(
    git,
    ['-C', CONTROLLER_ROOT, ...args],
    commonOptions,
  );
  const repositoryRoot = runGit(
    ['rev-parse', '--show-toplevel'],
  ).trim();
  if (
    !path.isAbsolute(repositoryRoot)
      || fs.realpathSync(repositoryRoot) !== CONTROLLER_ROOT
  ) {
    throw new Error('controller root 不是当前 canonical Git worktree root');
  }
  const before = runGit(
    ['rev-parse', '--verify', 'HEAD^{commit}'],
  ).trim();
  if (!/^[0-9a-f]{40,64}$/.test(before)) {
    throw new Error('controller repository HEAD 非法');
  }
  assertControllerControlPathsCommitted(CONTROLLER_ROOT, before);
  const after = runGit(
    ['rev-parse', '--verify', 'HEAD^{commit}'],
  ).trim();
  if (after !== before) {
    throw new Error('controller repository HEAD 在 identity capture 期间变化');
  }
  return before;
}

function deriveServeIdentity({
  receiptFile,
  binding,
  environment = deriveServeEnvironment(),
}) {
  assertCanaryBinding(binding);
  const serveEnvironment = assertCanonicalServeEnvironment(environment);
  if (
    typeof receiptFile !== 'string'
      || !path.isAbsolute(receiptFile)
      || path.resolve(receiptFile) !== receiptFile
  ) {
    throw new Error('receipt-file 必须是规范化 absolute path');
  }
  const expectedArgv = [
    NODE_EXECUTABLE_PATH,
    SERVER_SCRIPT_PATH,
    'serve',
    '--port',
    '0',
    '--receipt-file',
    receiptFile,
    '--goal',
    binding.goal_id,
    '--role',
    binding.role,
    ...(
      binding.task_id === null
        ? []
        : ['--task', binding.task_id]
    ),
  ];
  return Object.freeze({
    controller_root: CONTROLLER_ROOT,
    controller_repository_head: controllerRepositoryHead(),
    server_script_path: SERVER_SCRIPT_PATH,
    server_script_sha256: implementationSha256(),
    node_executable_path: NODE_EXECUTABLE_PATH,
    cwd: CONTROLLER_ROOT,
    requested_port: 0,
    expected_argv: Object.freeze(expectedArgv),
    expected_argv_sha256: argvSha256(expectedArgv),
    environment: serveEnvironment,
    environment_sha256: argvSha256(
      Object.entries(serveEnvironment).map(([key, value]) => `${key}=${value}`),
    ),
  });
}

function bindingSha256(binding) {
  return `sha256:${sha256(JSON.stringify(binding))}`;
}

function buildCanaryPage(nonce) {
  if (typeof nonce !== 'string' || !/^[0-9a-f]{64,}$/.test(nonce)) {
    throw new Error('nonce 必须是至少 32-byte 的小写 hex');
  }
  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="referrer" content="no-referrer">',
    `<meta name="codex-capability-canary-nonce" content="${nonce}">`,
    `<title>${CANARY_CONTRACT.expected_title}</title>`,
    `<style>${CANARY_STYLE}</style>`,
    '</head>',
    '<body>',
    '<main>',
    `<h1>${CANARY_CONTRACT.expected_title}</h1>`,
    `<button id="${CANARY_CONTRACT.button_id}" type="button">Run canary</button>`,
    `<p id="${CANARY_CONTRACT.status_id}" role="status">${CANARY_CONTRACT.initial_status}</p>`,
    '</main>',
    `<script>${CANARY_SCRIPT}</script>`,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

function contentSecurityPolicy() {
  const scriptHash = crypto
    .createHash('sha256')
    .update(CANARY_SCRIPT)
    .digest('base64');
  const styleHash = crypto
    .createHash('sha256')
    .update(CANARY_STYLE)
    .digest('base64');
  return [
    "default-src 'none'",
    `script-src 'sha256-${scriptHash}'`,
    `style-src 'sha256-${styleHash}'`,
    "img-src 'none'",
    "font-src 'none'",
    "connect-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ');
}

function securityHeaders() {
  return {
    'Cache-Control': 'no-store, max-age=0',
    'Content-Security-Policy': contentSecurityPolicy(),
    Expires: '0',
    Pragma: 'no-cache',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  };
}

function requestHasExactHost(request, expectedHost) {
  const rawHosts = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (String(request.rawHeaders[index]).toLowerCase() === 'host') {
      rawHosts.push(String(request.rawHeaders[index + 1]));
    }
  }
  return rawHosts.length === 1 && rawHosts[0] === expectedHost;
}

function sendRejected(response, statusCode, message) {
  const body = Buffer.from(`${message}\n`);
  response.writeHead(statusCode, {
    ...securityHeaders(),
    Connection: 'close',
    'Content-Length': String(body.length),
    'Content-Type': 'text/plain; charset=utf-8',
  });
  response.end(body);
}

function createRequestHandler({ port, page, nonce }) {
  const expectedHost = `${LISTENER_HOST}:${port}`;
  const pageBytes = Buffer.from(page);
  return (request, response) => {
    if (!requestHasExactHost(request, expectedHost)) {
      sendRejected(response, 421, 'Misdirected Request');
      return;
    }
    if (request.url !== CANARY_PATH) {
      sendRejected(response, 404, 'Not Found');
      return;
    }
    if (request.method !== 'GET') {
      sendRejected(response, 405, 'Method Not Allowed');
      return;
    }
    response.writeHead(200, {
      ...securityHeaders(),
      Connection: 'close',
      'Content-Length': String(pageBytes.length),
      'Content-Type': 'text/html; charset=utf-8',
      'X-Codex-Canary-Nonce': nonce,
    });
    response.end(pageBytes);
  };
}

function directoryIdentity(directory, stat) {
  return Object.freeze({
    path: directory,
    dev: stat.dev,
    ino: stat.ino,
    uid: stat.uid,
    mode: stat.mode & 0o777,
  });
}

function assertPrivateDirectoryStat(directory, stat) {
  if (
    !stat.isDirectory()
      || stat.isSymbolicLink()
      || (
        typeof process.getuid === 'function'
        && stat.uid !== process.getuid()
      )
      || (stat.mode & 0o777) !== 0o700
  ) {
    throw new Error(
      'receipt parent 必须是当前用户拥有且 mode 0700 的 canonical 非 symlink 目录',
    );
  }
  return directoryIdentity(directory, stat);
}

function sameDirectoryIdentity(left, right) {
  return left.path === right.path
    && left.dev === right.dev
    && left.ino === right.ino
    && left.uid === right.uid
    && left.mode === right.mode;
}

function assertReceiptParentIdentity(receiptFile, expectedIdentity = null) {
  if (!path.isAbsolute(receiptFile) || path.resolve(receiptFile) !== receiptFile) {
    throw new Error('--receipt-file 必须是规范化 absolute path');
  }
  const directory = path.dirname(receiptFile);
  const directoryStat = fs.lstatSync(directory);
  if (fs.realpathSync(directory) !== directory) {
    throw new Error('receipt parent 必须是 canonical 非 symlink 目录');
  }
  const actualIdentity = assertPrivateDirectoryStat(directory, directoryStat);
  if (
    expectedIdentity
      && !sameDirectoryIdentity(actualIdentity, expectedIdentity)
  ) {
    throw new Error('receipt parent dev/ino/uid/mode 在发布期间发生变化');
  }
  return actualIdentity;
}

function fsyncDirectory(directory, expectedIdentity) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      directory,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const openedIdentity = assertPrivateDirectoryStat(
      directory,
      fs.fstatSync(descriptor),
    );
    if (!sameDirectoryIdentity(openedIdentity, expectedIdentity)) {
      throw new Error('receipt parent fd identity 与路径 identity 不一致');
    }
    fs.fsyncSync(descriptor);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code)) throw error;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  assertReceiptParentIdentity(
    path.join(directory, '__receipt-parent-revalidation__'),
    expectedIdentity,
  );
}

function assertReceiptDestination(receiptFile) {
  const parentIdentity = assertReceiptParentIdentity(receiptFile);
  try {
    const current = fs.lstatSync(receiptFile);
    const kind = current.isSymbolicLink() ? 'symlink' : 'existing path';
    throw new Error(`receipt-file 拒绝覆盖 ${kind}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return parentIdentity;
}

function assertReceiptFileStat(stat, expectedNlink) {
  if (
    !stat.isFile()
      || stat.isSymbolicLink()
      || (
        typeof process.getuid === 'function'
        && stat.uid !== process.getuid()
      )
      || (stat.mode & 0o777) !== 0o600
      || stat.nlink !== expectedNlink
  ) {
    throw new Error('receipt file fd identity/owner/mode/link count 验证失败');
  }
}

function assertReceiptPathMatchesStat(receiptFile, expectedStat) {
  const pathStat = fs.lstatSync(receiptFile);
  assertReceiptFileStat(pathStat, 1);
  if (
    fs.realpathSync(receiptFile) !== receiptFile
      || pathStat.dev !== expectedStat.dev
      || pathStat.ino !== expectedStat.ino
      || pathStat.uid !== expectedStat.uid
      || pathStat.size !== expectedStat.size
  ) {
    throw new Error('receipt pathname 与已验证 file fd identity 不一致');
  }
}

function writeReceiptExclusive(receiptFile, receipt) {
  const parentIdentity = assertReceiptDestination(receiptFile);
  const directory = parentIdentity.path;
  const body = Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`);
  const temporary = path.join(
    directory,
    `.${path.basename(receiptFile)}.canary-${process.pid}-${crypto.randomBytes(12).toString('hex')}.tmp`,
  );
  let descriptor;
  let installedDescriptor;
  let temporaryIdentity;
  let installed = false;
  try {
    assertReceiptParentIdentity(receiptFile, parentIdentity);
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.fchmodSync(descriptor, 0o600);
    const created = fs.fstatSync(descriptor);
    assertReceiptFileStat(created, 1);
    if (created.dev !== parentIdentity.dev) {
      throw new Error('receipt temporary 与 parent 不在同一 device');
    }
    temporaryIdentity = { dev: created.dev, ino: created.ino };
    assertReceiptParentIdentity(receiptFile, parentIdentity);
    fs.writeFileSync(descriptor, body);
    fs.fsyncSync(descriptor);
    const written = fs.fstatSync(descriptor);
    assertReceiptFileStat(written, 1);
    if (
      written.dev !== temporaryIdentity.dev
        || written.ino !== temporaryIdentity.ino
        || written.size !== body.length
    ) {
      throw new Error('receipt temporary fd identity/size 写入后变化');
    }
    fs.closeSync(descriptor);
    descriptor = undefined;
    assertReceiptParentIdentity(receiptFile, parentIdentity);
    fsyncDirectory(directory, parentIdentity);

    assertReceiptParentIdentity(receiptFile, parentIdentity);
    try {
      fs.linkSync(temporary, receiptFile);
      installed = true;
    } catch (error) {
      if (error.code === 'EEXIST') {
        throw new Error('receipt-file 拒绝覆盖 existing path');
      }
      throw error;
    }
    assertReceiptParentIdentity(receiptFile, parentIdentity);
    fsyncDirectory(directory, parentIdentity);
    installedDescriptor = fs.openSync(
      receiptFile,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const linked = fs.fstatSync(installedDescriptor);
    assertReceiptFileStat(linked, 2);
    if (
      linked.dev !== temporaryIdentity.dev
        || linked.ino !== temporaryIdentity.ino
    ) {
      throw new Error('receipt installed fd 与 temporary inode 不一致');
    }

    assertReceiptParentIdentity(receiptFile, parentIdentity);
    fs.unlinkSync(temporary);
    assertReceiptParentIdentity(receiptFile, parentIdentity);
    fsyncDirectory(directory, parentIdentity);

    const installedStat = fs.fstatSync(installedDescriptor);
    assertReceiptFileStat(installedStat, 1);
    if (
      installedStat.dev !== temporaryIdentity.dev
        || installedStat.ino !== temporaryIdentity.ino
        || !fs.readFileSync(installedDescriptor).equals(body)
    ) {
      throw new Error('receipt publication identity/mode/bytes 验证失败');
    }
    assertReceiptPathMatchesStat(receiptFile, installedStat);
    assertReceiptParentIdentity(receiptFile, parentIdentity);
    fs.closeSync(installedDescriptor);
    installedDescriptor = undefined;
    assertReceiptParentIdentity(receiptFile, parentIdentity);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (installedDescriptor !== undefined) fs.closeSync(installedDescriptor);
    let removedTemporary = false;
    try {
      if (
        temporaryIdentity
          && sameDirectoryIdentity(
            assertReceiptParentIdentity(receiptFile),
            parentIdentity,
          )
      ) {
        const temporaryStat = fs.lstatSync(temporary);
        if (
          temporaryStat.dev === temporaryIdentity.dev
            && temporaryStat.ino === temporaryIdentity.ino
        ) {
          fs.unlinkSync(temporary);
          removedTemporary = true;
        }
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (removedTemporary) fsyncDirectory(directory, parentIdentity);
    if (!installed) {
      assertReceiptParentIdentity(receiptFile, parentIdentity);
    }
  }
}

function cliUsage() {
  return 'usage: browser-canary-server.js <launch|serve|stop> '
    + '[--port 0 (serve only)] --receipt-file <canonical-absolute> '
    + '--goal <id> --role <FOREMAN|DEV|REVIEW|RECEIPT> [--task <id>]';
}

function parseCliArgs(argv) {
  if (
    !Array.isArray(argv)
      || argv.length < 1
      || !['launch', 'serve', 'stop'].includes(argv[0])
      || (argv.length - 1) % 2 !== 0
  ) {
    throw new Error(cliUsage());
  }
  const command = argv[0];
  const parsed = new Map();
  for (let index = 1; index < argv.length; index += 2) {
    const option = argv[index];
    const value = argv[index + 1];
    if (
      !['--port', '--receipt-file', '--goal', '--role', '--task']
        .includes(option)
        || parsed.has(option)
        || typeof value !== 'string'
        || value.length === 0
    ) {
      throw new Error(`invalid or duplicate option: ${option}`);
    }
    parsed.set(option, value);
  }
  const rawPort = parsed.get('--port') || null;
  if (command === 'serve' && rawPort !== '0') {
    throw new Error('serve 的 --port 必须且只能是 0');
  }
  if (command !== 'serve' && rawPort !== null) {
    throw new Error(`${command} 禁止 --port；端口只能由 serve 以 0 分配`);
  }
  const receiptFile = parsed.get('--receipt-file');
  if (
    typeof receiptFile !== 'string'
      || !path.isAbsolute(receiptFile)
      || path.resolve(receiptFile) !== receiptFile
  ) {
    throw new Error('--receipt-file 必须是规范化 absolute path');
  }
  const goalId = parsed.get('--goal');
  const role = parsed.get('--role');
  const taskId = parsed.get('--task') || null;
  if (!isCanonicalId(goalId)) throw new Error('--goal 不是 canonical ID');
  if (!CANARY_ROLES.has(role)) throw new Error('--role 不支持 Browser canary');
  if (
    (role === 'FOREMAN' && taskId !== null)
      || (role !== 'FOREMAN' && !isCanonicalId(taskId))
  ) {
    throw new Error('FOREMAN 禁止 --task；worker role 必须提供 canonical --task');
  }
  const expectedOptions = new Set([
    '--receipt-file',
    '--goal',
    '--role',
    ...(command === 'serve' ? ['--port'] : []),
    ...(taskId === null ? [] : ['--task']),
  ]);
  if (
    parsed.size !== expectedOptions.size
      || [...expectedOptions].some((option) => !parsed.has(option))
  ) {
    throw new Error(`${command} 缺少必需 option 或含多余 option`);
  }
  const binding = {
    goal_id: goalId,
    role,
    task_id: taskId,
  };
  assertCanaryBinding(binding);
  return {
    command,
    port: command === 'serve' ? 0 : null,
    receiptFile,
    binding,
  };
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen({
      host: LISTENER_HOST,
      port,
      exclusive: true,
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
    if (typeof server.closeIdleConnections === 'function') {
      server.closeIdleConnections();
    }
  });
}

function assertExactObject(actual, expected, label) {
  if (
    !actual
      || typeof actual !== 'object'
      || Array.isArray(actual)
      || JSON.stringify(actual) !== JSON.stringify(expected)
  ) {
    throw new Error(`${label} 与 canonical 派生值不一致`);
  }
}

function assertExpectedProcessIdentity(pid, startToken, launch) {
  const expectedCommand = launch.expected_argv.join(' ');
  const actualCommand = processCommand(pid);
  const mismatches = [
    processStartToken(pid) === startToken ? null : 'start',
    processExecutablePath(pid) === launch.node_executable_path
      ? null : 'executable',
    processCwd(pid) === launch.cwd ? null : 'cwd',
    actualCommand === expectedCommand ? null : 'command',
    processCommandSha256(pid) === `sha256:${sha256(expectedCommand)}`
      ? null : 'command_sha256',
  ].filter(Boolean);
  if (mismatches.length !== 0) {
    throw new Error(
      `live process identity 与 canonical launch 不一致: ${mismatches.join(',')}`,
    );
  }
}

function assertStaticReceiptIdentity(
  receipt,
  { receiptFile, binding = null } = {},
) {
  if (
    !receipt
      || typeof receipt !== 'object'
      || Array.isArray(receipt)
      || receipt.schema_version !== 1
      || receipt.kind !== RECEIPT_KIND
  ) {
    throw new Error('Browser canary receipt schema/kind 非法');
  }
  assertCanaryBinding(receipt.binding);
  if (binding !== null) {
    assertCanaryBinding(binding);
    assertExactObject(receipt.binding, binding, 'receipt binding');
  }
  if (receipt.binding_sha256 !== bindingSha256(receipt.binding)) {
    throw new Error('receipt binding_sha256 不匹配');
  }
  const expectedLaunch = deriveServeIdentity({
    receiptFile,
    binding: receipt.binding,
    environment: receipt.launch && receipt.launch.environment,
  });
  assertExactObject(receipt.launch, expectedLaunch, 'receipt launch');
  if (
    receipt.implementation_sha256 !== expectedLaunch.server_script_sha256
      || !Number.isSafeInteger(receipt.pid)
      || receipt.pid <= 0
      || typeof receipt.process_start_token !== 'string'
      || receipt.process_executable_path !== expectedLaunch.node_executable_path
      || receipt.process_cwd !== expectedLaunch.cwd
      || receipt.process_command_sha256
        !== `sha256:${sha256(expectedLaunch.expected_argv.join(' '))}`
  ) {
    throw new Error('receipt process/script identity 非法');
  }
  if (
    !receipt.listener
      || receipt.listener.host !== LISTENER_HOST
      || !Number.isSafeInteger(receipt.listener.port)
  ) {
    throw new Error('receipt listener identity 非法');
  }
  return expectedLaunch;
}

function assertLiveServerIdentity(
  receipt,
  { receiptFile, binding = null } = {},
) {
  const expectedLaunch = assertStaticReceiptIdentity(
    receipt,
    { receiptFile, binding },
  );
  assertExpectedProcessIdentity(
    receipt.pid,
    receipt.process_start_token,
    expectedLaunch,
  );
  const listener = assertUniqueLoopbackListener(
    receipt.pid,
    receipt.listener.port,
  );
  return Object.freeze({
    launch: expectedLaunch,
    listener,
  });
}

function cliTtlMilliseconds() {
  const raw = process.env.BROWSER_CANARY_TEST_TTL_MILLISECONDS;
  if (process.env.NODE_ENV !== 'test' || raw === undefined) {
    return RECEIPT_TTL_MILLISECONDS;
  }
  return Number(validateTestTtl(raw));
}

async function startCanaryServer({
  port,
  receiptFile,
  binding,
  ttlMilliseconds = RECEIPT_TTL_MILLISECONDS,
}) {
  assertReceiptDestination(receiptFile);
  assertCanaryBinding(binding);
  if (port !== 0) {
    throw new Error('Browser canary serve 只允许 requested port 0');
  }
  if (
    !Number.isSafeInteger(ttlMilliseconds)
      || ttlMilliseconds < 50
      || ttlMilliseconds > RECEIPT_TTL_MILLISECONDS
  ) {
    throw new Error('Browser canary receipt TTL 非法');
  }
  const launch = deriveServeIdentity({ receiptFile, binding });
  const nonce = crypto.randomBytes(32).toString('hex');
  const page = buildCanaryPage(nonce);
  const server = http.createServer();
  server.headersTimeout = 5_000;
  server.requestTimeout = 5_000;
  server.keepAliveTimeout = 1_000;
  server.on('clientError', (_error, socket) => socket.destroy());

  await listen(server, port);
  try {
    const address = server.address();
    if (
      address === null
        || typeof address === 'string'
        || address.address !== LISTENER_HOST
        || address.port < 1024
        || address.port > 65535
    ) {
      throw new Error('listener 未精确绑定 127.0.0.1:<ephemeral-port>');
    }
    const actualPort = address.port;
    server.on(
      'request',
      createRequestHandler({ port: actualPort, page, nonce }),
    );
    const startToken = processStartToken(process.pid);
    if (!startToken) throw new Error('无法读取 canary server process start token');
    const executablePath = processExecutablePath(process.pid);
    const cwd = processCwd(process.pid);
    const command = processCommand(process.pid);
    const commandSha256 = processCommandSha256(process.pid);
    if (
      executablePath !== launch.node_executable_path
        || cwd !== launch.cwd
        || command !== launch.expected_argv.join(' ')
        || commandSha256 !== `sha256:${sha256(command)}`
    ) {
      throw new Error('无法证明 canary server canonical argv/executable/cwd identity');
    }
    assertUniqueLoopbackListener(process.pid, actualPort);
    const startedAt = new Date().toISOString();
    const expiresAt = new Date(
      Date.parse(startedAt) + ttlMilliseconds,
    ).toISOString();
    const receipt = {
      schema_version: 1,
      kind: RECEIPT_KIND,
      binding: { ...binding },
      binding_sha256: bindingSha256(binding),
      url: `http://${LISTENER_HOST}:${actualPort}${CANARY_PATH}`,
      nonce,
      contract: { ...CANARY_CONTRACT },
      page_sha256: `sha256:${sha256(page)}`,
      implementation_sha256: implementationSha256(),
      launch: {
        ...launch,
        expected_argv: [...launch.expected_argv],
      },
      lifecycle: {
        receipt_retained: true,
        auto_shutdown_at_expires_at: true,
      },
      pid: process.pid,
      process_start_token: startToken,
      process_executable_path: executablePath,
      process_command_sha256: commandSha256,
      process_cwd: cwd,
      started_at: startedAt,
      expires_at: expiresAt,
      listener: {
        host: LISTENER_HOST,
        port: actualPort,
      },
    };
    writeReceiptExclusive(receiptFile, receipt);
    assertLiveServerIdentity(receipt, { receiptFile, binding });
    return {
      server,
      receipt,
      close: () => closeServer(server),
    };
  } catch (error) {
    await closeServer(server);
    throw error;
  }
}

async function runServe(options) {
  assertCurrentServeEnvironment();
  const runtime = await startCanaryServer({
    ...options,
    ttlMilliseconds: cliTtlMilliseconds(),
  });
  let closing = false;
  let expiryTimer;
  const shutdown = async () => {
    if (closing) return;
    closing = true;
    if (expiryTimer) clearTimeout(expiryTimer);
    try {
      await runtime.close();
      process.exitCode = 0;
    } catch (error) {
      console.error(`browser-canary-server: ${error.message}`);
      process.exitCode = 1;
    }
  };
  expiryTimer = setTimeout(
    shutdown,
    Math.max(0, Date.parse(runtime.receipt.expires_at) - Date.now()),
  );
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
  return runtime;
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function receiptSha256(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    throw new Error('receiptSha256 只接受从已验证 fd 读取的 exact bytes');
  }
  return `sha256:${sha256(bytes)}`;
}

async function waitForLaunchedReceipt(
  { receiptFile, binding },
  pid,
  startToken,
  launch,
) {
  const deadline = Date.now() + 10_000;
  let lastReceiptError = null;
  while (Date.now() < deadline) {
    let capture = null;
    try {
      capture = readReceiptSecure(receiptFile);
      const { receipt } = capture;
      if (
        receipt.pid !== pid
          || receipt.process_start_token !== startToken
      ) {
        throw new Error('launched receipt PID/start token 不匹配');
      }
      assertLiveServerIdentity(receipt, { receiptFile, binding });
      assertReceiptCaptureStillInstalled(receiptFile, capture);
      return capture;
    } catch (error) {
      closeReceiptCapture(capture);
      lastReceiptError = error;
    }
    if (processStartToken(pid) !== startToken) {
      throw new Error(
        'detached serve 在发布 readiness receipt 前退出'
          + (
            lastReceiptError
              ? `: ${lastReceiptError.message}`
              : ''
          ),
      );
    }
    assertExpectedProcessIdentity(pid, startToken, launch);
    await wait(25);
  }
  throw new Error(
    '等待 detached serve readiness receipt 超时'
      + (lastReceiptError ? `: ${lastReceiptError.message}` : ''),
  );
}

async function stopExpectedProcess(
  pid,
  startToken,
  launch,
  listenerPort = null,
  beforeSignal = null,
) {
  assertExpectedProcessIdentity(pid, startToken, launch);
  if (beforeSignal !== null) beforeSignal();
  assertExpectedProcessIdentity(pid, startToken, launch);
  process.kill(pid, 'SIGTERM');
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    if (processStartToken(pid) !== startToken) {
      if (listenerPort !== null) {
        const inventory = inspectListenerInventoryAllowEmpty(listenerPort);
        if (inventory.records.length !== 0) {
          throw new Error(
            'validated process 已退出但 exact port 仍有 listener；拒绝报告 STOPPED',
          );
        }
      }
      return;
    }
    await wait(25);
  }
  throw new Error('validated canary server 未在 SIGTERM 后退出；拒绝 raw PID SIGKILL');
}

async function runLaunch(options) {
  assertSafeLauncherRuntime();
  assertReceiptDestination(options.receiptFile);
  const launch = deriveServeIdentity(options);
  const child = spawn(
    launch.node_executable_path,
    launch.expected_argv.slice(1),
    {
      cwd: launch.cwd,
      detached: true,
      stdio: 'ignore',
      env: { ...launch.environment },
    },
  );
  child.unref();
  let startToken = null;
  const startDeadline = Date.now() + 2_000;
  while (Date.now() < startDeadline && startToken === null) {
    startToken = processStartToken(child.pid);
    if (startToken === null) await wait(10);
  }
  if (startToken === null) {
    throw new Error('无法读取 detached serve process start token');
  }
  let capture = null;
  try {
    assertExpectedProcessIdentity(child.pid, startToken, launch);
    capture = await waitForLaunchedReceipt(
      options,
      child.pid,
      startToken,
      launch,
    );
    const { receipt } = capture;
    assertReceiptCaptureStillInstalled(options.receiptFile, capture);
    process.stdout.write(`${JSON.stringify({
      status: 'READY',
      receipt_file: options.receiptFile,
      pid: receipt.pid,
      url: receipt.url,
      expires_at: receipt.expires_at,
      receipt_retained: true,
      receipt_sha256: capture.sha256,
    })}\n`);
    return receipt;
  } catch (error) {
    if (processStartToken(child.pid) === startToken) {
      try {
        await stopExpectedProcess(child.pid, startToken, launch);
      } catch (cleanupError) {
        error.message += `; cleanup failed: ${cleanupError.message}`;
      }
    }
    throw error;
  } finally {
    closeReceiptCapture(capture);
  }
}

async function runStop(options) {
  const capture = readReceiptSecure(options.receiptFile);
  try {
    const { receipt } = capture;
    const launch = assertStaticReceiptIdentity(receipt, options);
    assertReceiptCaptureStillInstalled(options.receiptFile, capture);
    if (
      processStartToken(receipt.pid) !== receipt.process_start_token
    ) {
      const terminalInventory = inspectListenerInventoryAllowEmpty(
        receipt.listener.port,
      );
      if (terminalInventory.records.length !== 0) {
        throw new Error(
          'receipt process identity 已终止但 claimed port 仍有 listener；拒绝 signal',
        );
      }
      assertReceiptCaptureStillInstalled(options.receiptFile, capture);
      process.stdout.write(`${JSON.stringify({
        status: 'ALREADY_STOPPED',
        receipt_file: options.receiptFile,
        pid: receipt.pid,
        receipt_retained: true,
        receipt_sha256: capture.sha256,
      })}\n`);
      return;
    }
    assertLiveServerIdentity(receipt, options);
    assertLiveServerIdentity(receipt, options);
    await stopExpectedProcess(
      receipt.pid,
      receipt.process_start_token,
      launch,
      receipt.listener.port,
      () => assertReceiptCaptureStillInstalled(
        options.receiptFile,
        capture,
      ),
    );
    assertReceiptCaptureStillInstalled(options.receiptFile, capture);
    process.stdout.write(`${JSON.stringify({
      status: 'STOPPED',
      receipt_file: options.receiptFile,
      pid: receipt.pid,
      receipt_retained: true,
      receipt_sha256: capture.sha256,
    })}\n`);
  } finally {
    closeReceiptCapture(capture);
  }
}

async function runCli(argv) {
  const options = parseCliArgs(argv);
  if (options.command === 'launch') return runLaunch(options);
  if (options.command === 'stop') return runStop(options);
  return runServe(options);
}

module.exports = {
  CANARY_CONTRACT,
  CANARY_PATH,
  LISTENER_HOST,
  RECEIPT_TTL_MILLISECONDS,
  RECEIPT_KIND,
  assertExactListenerInventory,
  assertLiveServerIdentity,
  assertReceiptParentIdentity,
  assertStaticReceiptIdentity,
  assertUniqueLoopbackListener,
  argvSha256,
  bindingSha256,
  buildCanaryPage,
  controllerRepositoryHead,
  deriveServeEnvironment,
  deriveServeIdentity,
  implementationSha256,
  inspectListenerInventory,
  inspectListenerInventoryAllowEmpty,
  parseCliArgs,
  parseLsofListenerInventory,
  processCommand,
  processCommandSha256,
  processCwd,
  processExecutablePath,
  processOwnsListener,
  processStartToken,
  readReceiptSecure,
  receiptSha256,
  runCli,
  startCanaryServer,
  writeReceiptExclusive,
};

if (require.main === module) {
  runCli(process.argv.slice(2)).catch((error) => {
    console.error(`browser-canary-server: ${error.message}`);
    process.exitCode = 1;
  });
}
