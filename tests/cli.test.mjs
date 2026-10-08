import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { defaultConfig } from '../dist/config.js';
import { applyPolicy, validateEnvironment } from '../dist/scan.js';
import { report } from '../dist/report.js';

const binary = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const canary = 'ghp_' + 'A7b9C1d3E5f7G9h1J3k5L7m9N1p3Q5r7S9t1';
async function fixture(t, files = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envguard-cli-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [name, text] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, name)), { recursive: true });
    await writeFile(path.join(root, name), text);
  }
  return root;
}
function cli(root, args, environment = {}) {
  const result = spawnSync(process.execPath, [binary, ...args, '--root', root], { encoding: 'utf8', env: environment, timeout: 20000 });
  assert.equal(result.error, undefined, 'CLI must execute without a subprocess error');
  assert.ok(!`${result.stdout}${result.stderr}`.includes(canary), 'credential canary must not reach observable output');
  return result;
}
function json(result) { return JSON.parse(result.stdout || result.stderr); }

test('init discovers templates/source roots and is idempotent without touching env', async t => {
  const root = await fixture(t, { 'src/index.ts': 'process.env.DATABASE_URL', '.env.example': 'DATABASE_URL=\n', '.env': 'DATABASE_URL=local-only\n' });
  assert.equal(cli(root, ['init']).status, 0);
  const before = await readFile(path.join(root, '.envguard.json'), 'utf8');
  assert.deepEqual(JSON.parse(before).include, ['src']);
  assert.equal(cli(root, ['init', '--format', 'json']).status, 0);
  assert.equal(await readFile(path.join(root, '.envguard.json'), 'utf8'), before);
  assert.equal(await readFile(path.join(root, '.env'), 'utf8'), 'DATABASE_URL=local-only\n');
});

test('init retains current source outside common directories', async t => {
  const root = await fixture(t, {
    'src/index.ts': 'process.env.API_URL;',
    'packages/service/index.ts': 'process.env.SERVICE_URL;',
    '.env.example': 'API_URL=\n',
  });
  assert.equal(cli(root, ['init']).status, 0);
  const result = cli(root, ['scan', '--format', 'json']);
  assert.equal(result.status, 1);
  assert.ok(json(result).findings.some(f => f.ruleId === 'env/missing' && f.location.path === 'packages/service/index.ts'));
});

test('init infers source roots using effective Git ignore rules', async t => {
  const root = await fixture(t, {
    'src/index.ts': 'process.env.NODE_ENV;',
    'app/generated.ts': 'process.env.GENERATED_ONLY;',
    '.gitignore': 'app/\n',
  });
  const environment = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot };
  execFileSync('git', ['init', '--quiet'], { cwd: root, env: environment, windowsHide: true });
  assert.equal(cli(root, ['init'], environment).status, 0);
  assert.deepEqual(JSON.parse(await readFile(path.join(root, '.envguard.json'), 'utf8')).include, ['src']);
});

test('init keeps later conventional environment files and templates eligible', async t => {
  const value = 'synthetic-strong-runtime-credential';
  const root = await fixture(t, {
    'src/index.ts': 'process.env.API_URL;',
    '.env': `PASSWORD=${value}\n`,
    '.env.example': 'API_URL=\n',
    '.gitignore': '.env\n.env.production\n',
  });
  const environment = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot };
  execFileSync('git', ['init', '--quiet'], { cwd: root, env: environment, windowsHide: true });
  assert.equal(cli(root, ['init'], environment).status, 0);
  assert.equal((await readFile(path.join(root, '.envguard.json'), 'utf8')).includes(value), false);
  await writeFile(path.join(root, '.env.production'), `PASSWORD=${value}\n`);
  await writeFile(path.join(root, '.env.production.example'), 'ADDED_URL=\n');
  await writeFile(path.join(root, 'src/index.ts'), 'process.env.API_URL; process.env.ADDED_URL;');
  execFileSync('git', ['-c', 'core.autocrlf=false', 'add', '--force', '--', '.env.production'], { cwd: root, env: environment, windowsHide: true });
  const result = cli(root, ['scan', '--format', 'json', '--fail-on', 'critical'], environment);
  assert.equal(`${result.stdout}${result.stderr}`.includes(value), false);
  assert.equal(result.status, 1);
  assert.ok(json(result).findings.some(f => f.ruleId === 'git/env-tracked' && f.location.path === '.env.production'));
  assert.ok(!json(result).findings.some(f => f.ruleId === 'env/missing'));
});

test('clean non-Git fixture scans and validates controlled runtime values', async t => {
  const root = await fixture(t, { 'src/app.ts': 'process.env.API_URL', '.env.example': 'API_URL=\n' });
  for (const command of ['scan', 'validate', 'ci']) {
    const result = cli(root, [command, '--format', 'json'], { API_URL: 'https://example.invalid' });
    assert.equal(result.status, 0);
    assert.equal(json(result).exitCode, 0);
  }
});

test('missing/unused/dynamic rules and conservative unused analysis', async t => {
  const root = await fixture(t, { 'src/app.ts': 'process.env.MISSING;', '.env.example': 'OLD=\n' });
  let result = json(cli(root, ['scan', '--format', 'json']));
  assert.ok(result.findings.some(f => f.ruleId === 'env/missing'));
  assert.ok(result.findings.some(f => f.ruleId === 'env/unused'));
  await writeFile(path.join(root, 'src/app.ts'), 'process.env[key];');
  result = json(cli(root, ['scan', '--format', 'json']));
  assert.ok(result.findings.some(f => f.ruleId === 'env/dynamic'));
  assert.ok(!result.findings.some(f => f.ruleId === 'env/unused'));
});

test('token canary, credentials, private key, weak secret, and public exposure are detected safely', async t => {
  const root = await fixture(t, {
    'src/app.ts': `const access_token = '${canary}'; const db = 'postgres://user:fake-canary-password@localhost/db'; const pem = '-----BEGIN PRIVATE KEY-----\\nFAKEKEY\\n-----END PRIVATE KEY-----'; process.env.NEXT_PUBLIC_JWT_SECRET;`,
    '.env': 'JWT_SECRET=changeme\n',
    '.env.example': 'NEXT_PUBLIC_JWT_SECRET=\n',
  });
  for (const format of ['text', 'json']) {
    const result = cli(root, ['scan', '--format', format]);
    assert.equal(result.status, 1);
    assert.ok(!`${result.stdout}${result.stderr}`.includes('fake-canary-password'));
    if (format === 'json') {
      const ids = new Set(json(result).findings.map(f => f.ruleId));
      for (const id of ['secret/hardcoded-token', 'secret/credentials-url', 'secret/private-key', 'secret/weak', 'secret/public-exposure']) assert.ok(ids.has(id), `rule ${id} must detect the fixture`);
    }
  }
});

test('malformed dotenv reports safe diagnostics and policy findings exit 1', async t => {
  const root = await fixture(t, { '.env': `BROKEN ${canary}\nKEY='unterminated\n` });
  const result = cli(root, ['scan', '--format', 'json']);
  assert.equal(result.status, 1);
  assert.ok(json(result).findings.some(f => f.ruleId === 'env/malformed'));
});

test('secret-bearing path metadata is opaque in both reporters', async t => {
  const root = await fixture(t, { [`src/${canary}.ts`]: `const api_key = '${canary}';` });
  for (const format of ['text', 'json']) {
    const result = cli(root, ['scan', '--format', format]);
    assert.equal(result.status, 1);
    assert.ok(result.stdout.includes('[redacted-path]'));
  }
});

test('invalid configuration/arguments never echo repository-controlled values and exit 2', async t => {
  const root = await fixture(t, { '.envguard.json': `{ "${canary}": true }` });
  for (const format of ['text', 'json']) assert.equal(cli(root, ['scan', '--format', format]).status, 2);
  await rm(path.join(root, '.envguard.json'));
  assert.equal(cli(root, [canary, '--format', 'json']).status, 2);
  assert.equal(cli(root, ['scan', '--format', canary]).status, 2);
  assert.equal(cli(root, ['scan', '--config', '../outside.json']).status, 2);
  assert.equal(cli(root, ['scan', '--fail-on', 'bad']).status, 2);
});

test('validate uses runtime environment and only loads dotenv when explicitly requested', async t => {
  const root = await fixture(t, { '.env.example': 'NEEDED=\n', '.env': 'NEEDED=from-file\n' });
  assert.equal(cli(root, ['validate']).status, 1);
  assert.equal(cli(root, ['validate'], { NEEDED: 'from-runtime' }).status, 0);
  assert.equal(cli(root, ['validate', '--dotenv', '.env']).status, 0);
});

test('schema validation/prohibited variables do not disclose active values', async t => {
  const root = await fixture(t, { '.envguard.json': JSON.stringify({ required: ['PORT'], prohibited: ['DISALLOWED'], schema: { PORT: { type: 'number' }, FLAG: { type: 'boolean' }, URL: { type: 'url' } } }) });
  const result = cli(root, ['validate', '--format', 'json'], { PORT: canary, DISALLOWED: canary, FLAG: 'maybe', URL: canary });
  assert.equal(result.status, 1);
  assert.ok(json(result).findings.some(f => f.ruleId === 'env/schema'));
  assert.ok(json(result).findings.some(f => f.ruleId === 'env/prohibited'));
});

test('policy override/suppression counts are deterministic and text/JSON share findings', () => {
  const config = defaultConfig();
  const raw = [{ ruleId: 'env/missing', severity: 'error', message: 'Static diagnostic.', location: { path: 'src/app.ts', line: 1 } }];
  const base = applyPolicy('scan', raw, config);
  assert.equal(base.exitCode, 1);
  assert.equal(JSON.parse(report(base, 'json')).findings.length, 1);
  assert.ok(report(base, 'text').includes('env/missing'));
  config.failOn = 'critical';
  assert.equal(applyPolicy('scan', raw, config).exitCode, 0);
  config.suppressions = [{ ruleId: 'env/missing', path: 'src/app.ts', reason: 'External contract' }];
  const suppressed = applyPolicy('scan', raw, config);
  assert.equal(suppressed.suppressed, 1);
  assert.equal(suppressed.findings.length, 0);
});

test('runtime object prototype values do not satisfy required variables', () => {
  const config = defaultConfig();
  config.required = ['toString'];
  assert.equal(validateEnvironment(config, new Map(), {}).findings[0].ruleId, 'env/required');
});

test('dependencies, generated/minified files, and nested repositories are excluded', async t => {
  const root = await fixture(t, { 'node_modules/pkg/a.ts': `const key = '${canary}'`, 'dist/a.ts': `const key = '${canary}'`, 'public/bundle.min.js': `const key = '${canary}'`, 'nested/.git/config': '', 'nested/a.ts': `const key = '${canary}'`, 'app.ts': 'process.env.NODE_ENV' });
  const result = json(cli(root, ['scan', '--format', 'json']));
  assert.ok(!result.findings.some(f => f.ruleId === 'secret/hardcoded-token'));
  assert.equal(result.filesScanned, 1);
});

test('huge candidates and invalid UTF8 fail visibly without crashes', async t => {
  const root = await fixture(t, { 'huge.ts': 'a'.repeat(1024 * 1024 + 1), 'broken.ts': Buffer.from([0xff, 0xfe, 0xfa]) });
  const result = cli(root, ['scan', '--format', 'json']);
  assert.equal(result.status, 1);
  assert.equal(json(result).findings.filter(f => f.ruleId === 'scan/skipped').length, 2);
});

test('symlink escape and loop are not followed', async t => {
  const root = await fixture(t, { 'outside-target.txt': `password=${canary}` });
  try { await symlink(root, path.join(root, 'loop'), process.platform === 'win32' ? 'junction' : 'dir'); }
  catch { t.skip('OS does not permit symlink creation'); return; }
  const result = cli(root, ['scan', '--format', 'json']);
  assert.ok(json(result).findings.some(f => f.ruleId === 'scan/skipped'));
});

test('version/help/unknown-command contract', async t => {
  const root = await fixture(t);
  assert.equal(cli(root, ['--version']).stdout.trim(), '0.1.1');
  assert.ok(cli(root, ['scan', '--help']).stdout.includes('Usage:'));
  assert.equal(cli(root, ['no-such-command']).status, 2);
  assert.equal(cli(root, ['scan', '--format', 'json', '--format', 'text']).status, 2);
});
