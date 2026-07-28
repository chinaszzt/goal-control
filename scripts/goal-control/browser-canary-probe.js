#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const http = require('http');

const CANARY_URL_RE =
  /^http:\/\/127\.0\.0\.1:([1-9][0-9]{3,4})\/codex-capability-canary$/;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const NONCE_RE = /^[0-9a-f]{64}$/;
const MAX_PAGE_BYTES = 64 * 1024;

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function parseArgs(argv) {
  if (!Array.isArray(argv) || argv.length !== 6) {
    throw new Error(
      'usage: browser-canary-probe.js --url <exact-localhost-url> '
        + '--expected-page-sha256 <sha256> --expected-nonce <64-hex>',
    );
  }
  const parsed = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const value = argv[index + 1];
    if (
      !['--url', '--expected-page-sha256', '--expected-nonce']
        .includes(option)
        || parsed.has(option)
        || typeof value !== 'string'
        || value.length === 0
    ) {
      throw new Error(`invalid or duplicate option: ${option}`);
    }
    parsed.set(option, value);
  }
  const url = parsed.get('--url');
  const expectedPageSha256 = parsed.get('--expected-page-sha256');
  const expectedNonce = parsed.get('--expected-nonce');
  const match = CANARY_URL_RE.exec(url);
  const port = match ? Number(match[1]) : null;
  if (
    !match
      || !Number.isSafeInteger(port)
      || port < 1024
      || port > 65535
      || !SHA256_RE.test(expectedPageSha256)
      || !NONCE_RE.test(expectedNonce)
  ) {
    throw new Error('probe 参数不是 exact canary target');
  }
  return {
    url,
    port,
    expectedPageSha256,
    expectedNonce,
  };
}

function rawHeaderValues(rawHeaders, name) {
  const values = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (String(rawHeaders[index]).toLowerCase() === name.toLowerCase()) {
      values.push(String(rawHeaders[index + 1]));
    }
  }
  return values;
}

function assertExactResponse(response, options, body) {
  const exactHeaders = {
    'cache-control': 'no-store, max-age=0',
    'content-type': 'text/html; charset=utf-8',
    'x-codex-canary-nonce': options.expectedNonce,
    'x-content-type-options': 'nosniff',
  };
  if (
    response.statusCode !== 200
      || response.headers.location !== undefined
      || response.headers['set-cookie'] !== undefined
      || response.socket.remoteAddress !== '127.0.0.1'
      || response.socket.remotePort !== options.port
      || body.length === 0
      || body.length > MAX_PAGE_BYTES
      || sha256(body) !== options.expectedPageSha256
      || response.headers['content-length'] !== String(body.length)
  ) {
    throw new Error('canary endpoint status/peer/body/header binding 不匹配');
  }
  for (const [name, expected] of Object.entries(exactHeaders)) {
    const values = rawHeaderValues(response.rawHeaders, name);
    if (values.length !== 1 || values[0] !== expected) {
      throw new Error(`canary endpoint header 不匹配: ${name}`);
    }
  }
  for (const forbidden of ['location', 'set-cookie']) {
    if (rawHeaderValues(response.rawHeaders, forbidden).length !== 0) {
      throw new Error(`canary endpoint 禁止 header: ${forbidden}`);
    }
  }
  const csp = rawHeaderValues(
    response.rawHeaders,
    'content-security-policy',
  );
  if (
    csp.length !== 1
      || !csp[0].includes("default-src 'none'")
      || csp[0].includes("'unsafe-inline'")
  ) {
    throw new Error('canary endpoint CSP 不匹配');
  }
}

function probe(options) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        agent: false,
        host: '127.0.0.1',
        port: options.port,
        path: '/codex-capability-canary',
        method: 'GET',
        headers: {
          Accept: 'text/html',
          Connection: 'close',
          Host: `127.0.0.1:${options.port}`,
        },
        maxHeaderSize: 16 * 1024,
      },
      (response) => {
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_PAGE_BYTES) {
            request.destroy(new Error('canary endpoint body 超出上限'));
            return;
          }
          chunks.push(Buffer.from(chunk));
        });
        response.on('end', () => {
          try {
            const body = Buffer.concat(chunks);
            assertExactResponse(response, options, body);
            resolve({
              schema_version: 1,
              url: options.url,
              status_code: response.statusCode,
              remote_address: response.socket.remoteAddress,
              remote_port: response.socket.remotePort,
              page_sha256: sha256(body),
              nonce: options.expectedNonce,
              redirect_followed: false,
            });
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    request.setTimeout(2_000, () => {
      request.destroy(new Error('canary endpoint probe timeout'));
    });
    request.once('error', reject);
    request.end();
  });
}

async function runMain(argv) {
  const result = await probe(parseArgs(argv));
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

module.exports = {
  assertExactResponse,
  parseArgs,
  probe,
  rawHeaderValues,
};

if (require.main === module) {
  runMain(process.argv.slice(2)).catch((error) => {
    console.error(`browser-canary-probe: ${error.message}`);
    process.exitCode = 1;
  });
}
