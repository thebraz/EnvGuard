import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fsPromises from 'node:fs/promises';
import { link, mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { defaultConfig, loadConfig } from '../dist/config.js';
import { discoverFiles } from '../dist/project.js';
import { applyPolicy, runChecks } from '../dist/scan.js';
import { analyzeSecrets } from '../dist/secrets.js';
import { analyzeSource } from '../dist/source.js';

const binary = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const canary = 'Q7m2K8'; // Deliberately fake; assertions never print its value.
const keyBody = 'U1lOVEhFVElDX0ZBS0VfS0VZXzgyMzQ3Mw==';
const escape = (value, prefix, width) => [...value].map(c => `\\${prefix}${c.charCodeAt(0).toString(16).padStart(width, '0')}`).join('');
const percent = value => [...Buffer.from(value)].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join('');

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'eg-hardening-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function cli(root, format = 'json', extra = []) {
  const result = spawnSync(process.execPath, [binary, 'scan', '--root', root, '--format', format, ...extra], {
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot }, encoding: 'utf8', timeout: 20000, windowsHide: true,
  });
  assert.equal(Boolean(result.error), false, 'CLI must finish without a subprocess exception.');
  return result;
}

function opaque(result, values) {
  const outputs = [result.stdout, result.stderr, result.error?.message ?? ''];
  if (result.stdout.startsWith('{')) outputs.push(JSON.stringify(JSON.parse(result.stdout)));
  for (const output of outputs) {
    for (const value of values) assert.equal(output.includes(value), false, 'Observable output disclosed synthetic material.');
  }
}

test('metadata checks original and composed lexical spellings without changing benign paths', () => {
  const encodings = [escape(canary, 'x', 2), escape(canary, 'u', 4), [...canary].map(c => `\\u{${c.charCodeAt(0).toString(16)}}`).join(''), [...canary].map(c => `\\u{000000${c.charCodeAt(0).toString(16)}}`).join(''), [...canary].map(c => `\\${c.charCodeAt(0).toString(8)}`).join(''), [...'FAKEKEY'].map(c => `\\${c}`).join(''), '\\L\\a\\P\\e\\N', `Q7m\\\u20282K8`, `Q7m\\\u20292K8`];
  for (const spelling of encodings) {
    for (const file of [spelling, percent(spelling), escape(percent(canary), 'x', 2)]) {
      const result = applyPolicy('scan', [{ ruleId: 'secret/weak', severity: 'error', message: 'Fixed message.', location: { path: `${file}.ts` } }], defaultConfig(), [canary, 'FAKEKEY', 'LaPeN']);
      assert.equal(result.findings[0].location.path === '[redacted-path]', true, 'Lexical metadata representation must remain opaque.');
    }
  }
  const benign = 'local\\secret.env';
  const result = applyPolicy('scan', [{ ruleId: 'git/env-tracked', severity: 'critical', message: 'Fixed message.', location: { path: benign } }], defaultConfig(), [canary]);
  assert.equal(result.findings[0].location.path === benign, true);
});

test('POSIX raw source, JSON, dotenv and embedded-credential filename spellings stay opaque', { skip: process.platform === 'win32' ? 'POSIX literal-backslash filenames' : false }, async t => {
  const hex = escape(canary, 'x', 2);
  const unicode = escape(canary, 'u', 4);
  const url = `https://user:${canary}@example.invalid/path`;
  const files = [
    [`${hex}.ts`, `const password = "${hex}";`, 'secret/weak'],
    [`${unicode}.json`, `{"password":"${unicode}"}`, 'secret/weak'],
    [`${hex}-url.ts`, `send("${escape(url, 'x', 2)}");`, 'secret/credentials-url'],
    [`${unicode}-url.json`, `{"caption":"${escape(url, 'u', 4)}"}`, 'secret/credentials-url'],
    ['fake\\\\value.env', 'PASSWORD="fake\\\\value"\nMALFORMED ENTRY\n', 'env/malformed'],
    ['\\L\\a\\P\\e\\N.ts', 'const password = "\\L\\a\\P\\e\\N";', 'secret/weak'],
    [`Q7m\\\u20282K8.ts`, `const password = "Q7m\\\u20282K8";`, 'secret/weak'],
    [`Q7m\\\u20292K8.ts`, `const password = "Q7m\\\u20292K8";`, 'secret/weak'],
    [[...canary].map(c => `\\u{000000${c.charCodeAt(0).toString(16)}}`).join('') + '.ts', 'const password = "' + [...canary].map(c => `\\u{000000${c.charCodeAt(0).toString(16)}}`).join('') + '";', 'secret/weak'],
  ];
  for (const [name, content, rule] of files) {
    const root = await fixture(t);
    await writeFile(path.join(root, name), content);
    for (const format of ['text', 'json']) {
      const result = cli(root, format);
      opaque(result, [canary, hex, unicode, 'fake\\\\value', 'fake\\value']);
      assert.equal(result.status, 1);
      assert.equal(result.stdout.includes('[redacted-path]'), true);
      if (format === 'json') {
        const findings = JSON.parse(result.stdout).findings;
        assert.equal(findings.some(f => f.ruleId === rule), true, 'Fixture source must actually be analyzed.');
        for (const finding of findings) {
          for (const value of [hex, unicode, 'fake\\\\value']) assert.equal(finding.location?.path?.includes(value) ?? false, false, 'Parsed JSON location disclosed lexical material.');
        }
      }
    }
  }
});

test('private-key metadata protects body lines, compact material and later bounded lines', async t => {
  const half = Math.floor(keyBody.length / 2);
  const longBody = `${'A'.repeat(64)}\n`.repeat(260) + keyBody;
  for (const content of [
    `-----BEGIN PRIVATE KEY-----\r\n${keyBody.slice(0, half)}\r\n${keyBody.slice(half)}\r\n-----END PRIVATE KEY-----`,
    `-----BEGIN OPENSSH PRIVATE KEY-----\n${longBody}\n-----END OPENSSH PRIVATE KEY-----`,
    `-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: synthetic test\n\n${keyBody}`,
    `-----BEGIN PRIVATE KEY-----\r${keyBody}\r-----END PRIVATE KEY-----`,
    `-----BEGIN PRIVATE KEY-----\n${keyBody.slice(0, half)} \t${keyBody.slice(half)}\n-----END PRIVATE KEY-----`,
    `-----BEGIN PGP PRIVATE KEY BLOCK-----\n${keyBody.slice(0, half)}\n${keyBody.slice(half)}\n=FAKE\n-----END PGP PRIVATE KEY BLOCK-----`,
  ]) {
    const root = await fixture(t);
    await writeFile(path.join(root, `${keyBody}.txt`), content);
    for (const format of ['text', 'json']) {
      const result = cli(root, format);
      opaque(result, [keyBody]);
      assert.equal(result.status, 1);
      assert.equal(result.stdout.includes('[redacted-path]'), true);
    }
  }
  assert.equal(analyzeSecrets(`-----BEGIN PGP PUBLIC KEY BLOCK-----\n${keyBody}\n-----END PGP PUBLIC KEY BLOCK-----`, 'public.txt').findings.length, 0);
});

test('native process bindings resolve through runtime imports, const aliases and native require', () => {
  const forms = [
    'import proc from "node:process"; proc.env.KEY;',
    'import * as proc from "process"; proc["env"]["KEY"];',
    'import {env as settings} from "node:process"; settings.KEY;',
    'import {default as proc} from "process"; proc.env.KEY;',
    'const proc = require("node:process"); const alias = proc; alias.env.KEY;',
    'const {env: settings} = require("process"); settings.KEY;',
    'import proc = require("node:process"); proc.env.KEY;',
    'const proc = process; const {env} = proc; env.KEY;',
    'import * as native from "node:process"; native.default.env.KEY;',
    'import * as native from "node:process"; const proc = native.default; proc.env.KEY;',
    'import * as native from "node:process"; const alias = native; alias.default.env.KEY;',
    'const {env: {KEY}} = require("node:process");',
  ];
  for (const source of forms) assert.equal(analyzeSource(source, 'config.ts').usages.some(u => u.name === 'KEY' && u.provider === 'process'), true, 'Native provider was silently omitted.');
  for (const source of [
    'import proc from "mock"; proc.env.KEY;',
    'function f(require) { const proc = require("node:process"); proc.env.KEY; }',
    'import type proc from "node:process"; proc.env.KEY;',
    'import {type env as settings} from "node:process"; settings.KEY;',
    'const {other: settings} = process; settings.KEY;',
    'import * as native from "mock"; native.default.env.KEY;',
  ]) assert.equal(analyzeSource(source, 'config.ts').usages.length, 0, 'Local or erased provider must stay excluded.');
});

test('native public-secret access fails the critical CLI gate in both reporters', async t => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'config.ts'), 'import {env as settings} from "node:process"; settings.NEXT_PUBLIC_JWT_SECRET;');
  for (const format of ['text', 'json']) {
    const result = cli(root, format, ['--fail-on', 'critical']);
    assert.equal(result.status, 1);
    assert.equal(result.stdout.includes('secret/public-exposure'), true);
  }
});

test('complete fallback value branches retain context without reading conditions or assembled fragments', () => {
  for (const value of [`supplied || "${canary}"`, `supplied ?? "${canary}"`, `ready ? supplied : "${canary}"`, `supplied ?? (ready ? "${canary}" : other)`]) {
    const source = analyzeSource(`const password = ${value};`, 'config.ts');
    const detected = analyzeSecrets('', 'config.ts', { assignments: source.assignments });
    assert.equal(detected.findings.some(f => f.ruleId === 'secret/weak'), true, 'Sensitive complete fallback was omitted.');
    assert.equal(JSON.stringify(detected.findings).includes(canary), false, 'Finding must contain metadata only.');
  }
  for (const source of [`const password = input === "${canary}" ? supplied : other;`, `const caption = supplied || "${canary}";`, 'const password = "pre" + supplied;']) {
    const analysis = analyzeSource(source, 'config.ts');
    assert.equal(analyzeSecrets('', 'config.ts', { assignments: analysis.assignments }).findings.length, 0);
  }
});

test('case-only Git rename remains tracked under explicit selection and critical gate', { skip: process.platform !== 'win32' ? 'Windows case-insensitive fixture' : false }, async t => {
  const root = await fixture(t);
  for (const args of [['init', '--quiet'], ['config', 'core.ignorecase', 'true']]) assert.equal(spawnSync('git', args, { cwd: root, windowsHide: true }).status, 0);
  await writeFile(path.join(root, '.ENV'), 'API_URL=https://example.invalid\n');
  assert.equal(spawnSync('git', ['add', '--', '.ENV'], { cwd: root, windowsHide: true }).status, 0);
  await rename(path.join(root, '.ENV'), path.join(root, 'case-temp'));
  await rename(path.join(root, 'case-temp'), path.join(root, '.env'));
  await writeFile(path.join(root, '.gitignore'), '*\n');
  await writeFile(path.join(root, '.envguard.json'), JSON.stringify({ envFiles: ['.env'] }));
  const result = cli(root, 'json', ['--fail-on', 'critical']);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).findings.some(f => f.ruleId === 'git/env-tracked' && f.location.path === '.ENV'), true);
});

test('distinct case-sensitive files do not share Git identity under explicit selection', { skip: process.platform === 'win32' ? 'POSIX case-sensitive fixture' : false }, async t => {
  const root = await fixture(t);
  assert.equal(spawnSync('git', ['init', '--quiet'], { cwd: root }).status, 0);
  await writeFile(path.join(root, '.ENV'), 'API_URL=https://example.invalid\n');
  await writeFile(path.join(root, '.env'), 'API_URL=https://example.invalid\n');
  assert.equal(spawnSync('git', ['add', '--', '.ENV'], { cwd: root }).status, 0);
  await writeFile(path.join(root, '.gitignore'), '*\n');
  await writeFile(path.join(root, '.envguard.json'), JSON.stringify({ envFiles: ['.env'] }));
  const result = cli(root, 'json', ['--fail-on', 'critical']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).findings.some(f => f.ruleId === 'git/env-tracked'), false);
});

test('large nested repositories cannot bypass the streamed directory-entry budget', { skip: process.platform === 'win32' ? 'Linux native filesystem stress fixture' : false, timeout: 120000 }, async t => {
  const root = await fixture(t);
  const nested = path.join(root, 'nested');
  await mkdir(path.join(nested, '.git'), { recursive: true });
  const seeds = [];
  for (let i = 0; i < 4; i++) {
    const seed = path.join(nested, `seed-${i}`);
    await writeFile(seed, '');
    seeds.push(seed);
  }
  for (let start = 0; start < 100000; start += 256) {
    await Promise.all(Array.from({ length: Math.min(256, 100000 - start) }, (_, i) => link(seeds[(start + i) % 4], path.join(nested, `entry-${start + i}`))));
  }
  await assert.rejects(discoverFiles(root, defaultConfig()), error => error instanceof Error && error.message === 'Project entry count exceeds the scan limit. Narrow the include paths.');
});

test('case-alias resolution work stays linear across selected and deleted index variants', { skip: process.platform === 'win32' ? 'POSIX case-distinct fixture' : false }, async t => {
  const root = await fixture(t);
  assert.equal(spawnSync('git', ['init', '--quiet'], { cwd: root }).status, 0);
  const variants = Array.from({ length: 64 }, (_, bits) => [...'aliascase'].map((c, i) => bits & (1 << i) ? c.toUpperCase() : c).join('') + '.env');
  const indexed = variants.slice(0, 32);
  const selected = variants.slice(32);
  for (const file of indexed) await writeFile(path.join(root, file), 'API_URL=https://example.invalid\n');
  assert.equal(spawnSync('git', ['add', '--', ...indexed], { cwd: root }).status, 0);
  for (const file of indexed) await rm(path.join(root, file));
  for (const file of selected) await writeFile(path.join(root, file), 'API_URL=https://example.invalid\n');
  await writeFile(path.join(root, '.envguard.json'), JSON.stringify({ envFiles: selected }));
  const config = await loadConfig(root);
  const original = fsPromises.lstat;
  let calls = 0;
  fsPromises.lstat = (...args) => { calls++; return original(...args); };
  syncBuiltinESMExports();
  try {
    const result = await runChecks(root, config, 'scan', {});
    assert.equal(result.findings.some(f => f.ruleId === 'git/env-tracked'), false);
    assert.equal(calls > 0 && calls < (indexed.length + selected.length) * 20, true, 'Alias resolution must avoid a selection-by-index filesystem cross-product.');
  } finally {
    fsPromises.lstat = original;
    syncBuiltinESMExports();
  }
});
