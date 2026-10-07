import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import { copyFile, mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { defaultConfig, loadConfig, resolveProjectPath, validateConfig } from '../dist/config.js';
import { inspectGit } from '../dist/git.js';

const execute = promisify(execFile);
const binary = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const canary = 'controlled-config-canary-never-report-this';
async function temporary(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envguard-config-git-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
function safeError(error) {
  assert.equal(String(error).includes(canary), false, 'Configuration diagnostics disclosed sensitive input.');
  assert.equal(error instanceof Error, true);
  return true;
}

test('configuration defaults are independent and explicit settings normalize literal paths', () => {
  const first = defaultConfig();
  first.include.push('changed');
  assert.deepEqual(defaultConfig().include, ['.']);
  const configured = validateConfig({
    include: ['src\\config'], exclude: ['dist'], envFiles: ['.env'], templateFiles: ['.env.example'],
    required: ['DATABASE_URL'], prohibited: ['OLD_PASSWORD'],
    schema: { DATABASE_URL: { required: true, type: 'url', minLength: 1 } },
    rules: { 'env/unused': false }, severity: { 'secret/weak': 'critical' }, failOn: 'warning',
    suppressions: [{ ruleId: 'env/unused', path: '.env.example', line: 1, reason: 'Controlled exception' }],
  });
  assert.deepEqual(configured.include, ['src/config']);
  assert.equal(configured.schema.DATABASE_URL.type, 'url');
  assert.equal(configured.failOn, 'warning');
  const prototypeKey = validateConfig(JSON.parse('{"schema":{"__proto__":{"required":true}}}'));
  assert.equal(Object.hasOwn(prototypeKey.schema, '__proto__'), true);
  assert.equal(Object.getPrototypeOf(prototypeKey.schema), Object.prototype);
});

test('strict configuration rejects invalid options, scopes, names and traversal without echoing input', () => {
  const cases = [
    null, [], { [canary]: true }, { include: [] }, { include: canary },
    { include: ['../outside'] }, { include: ['nested/../outside'] }, { include: ['/outside'] },
    { include: ['C:\\outside'] }, { include: ['C:outside'] }, { include: ['\\\\host\\share'] },
    { exclude: ['*.js'] }, { envFiles: ['.'] }, { include: ['bad\0name'] },
    { include: ['src', 'src/'] }, { required: ['INVALID-NAME'] }, { required: ['x'.repeat(129)] },
    { required: Array.from({ length: 257 }, (_, index) => `KEY_${index}`) },
    { required: ['KEY'], prohibited: ['KEY'] }, { prohibited: ['KEY'], schema: { KEY: { required: true } } },
    { rules: { [canary]: true } }, { rules: { 'env/missing': canary } },
    { severity: { 'env/missing': canary } }, { failOn: canary },
    { schema: { KEY: { type: canary } } }, { schema: { KEY: { regex: canary } } },
    { schema: { KEY: { minLength: -1 } } }, { schema: { KEY: { required: canary } } },
    { suppressions: [{ ruleId: 'env/missing', reason: '' }] },
    { suppressions: [{ ruleId: 'env/missing', reason: canary, line: 1 }] },
    { suppressions: [{ ruleId: 'env/missing', reason: canary, path: 'src/a.ts', line: 0 }] },
    { suppressions: [{ ruleId: 'env/missing', reason: canary, path: '../outside' }] },
    { suppressions: [{ ruleId: 'env/missing', reason: canary }, { ruleId: 'env/missing', reason: 'Other reason' }] },
  ];
  for (const input of cases) assert.throws(() => validateConfig(input), safeError);
  assert.throws(() => validateConfig({ get include() { throw new Error(canary); } }), safeError);
});

test('configuration loading enforces size, JSON, existence, regular files and safe diagnostics', async t => {
  const root = await temporary(t);
  assert.deepEqual(await loadConfig(root), defaultConfig());
  await assert.rejects(loadConfig(root, 'missing.json'), safeError);
  await assert.rejects(loadConfig(root, `../${canary}`), safeError);
  const filename = path.join(root, '.envguard.json');
  await writeFile(filename, `{${canary}`);
  await assert.rejects(loadConfig(root), safeError);
  await writeFile(filename, canary.repeat(3000));
  await assert.rejects(loadConfig(root), safeError);
  await mkdir(path.join(root, 'src'));
  await writeFile(path.join(root, '.env'), 'CONTROLLED=fixture');
  await writeFile(filename, JSON.stringify({ include: ['src'], exclude: ['absent'], envFiles: ['.env'] }));
  assert.deepEqual((await loadConfig(root)).include, ['src']);
  if (process.platform === 'win32') {
    await writeFile(filename, JSON.stringify({ include: ['SRC'], envFiles: ['.ENV'] }));
    const canonical = await loadConfig(root);
    assert.deepEqual(canonical.include, ['src']);
    assert.deepEqual(canonical.envFiles, ['.env']);
  }
  await writeFile(filename, JSON.stringify({ include: ['absent'] }));
  await assert.rejects(loadConfig(root), safeError);
  await writeFile(filename, JSON.stringify({ envFiles: ['src'] }));
  await assert.rejects(loadConfig(root), safeError);
});

test('project paths reject symlink components and symlinked configuration', async t => {
  const root = await temporary(t);
  const outside = await temporary(t);
  await writeFile(path.join(outside, 'config.json'), '{}');
  await symlink(outside, path.join(root, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(resolveProjectPath(root, 'linked/config.json'), safeError);
  await assert.rejects(loadConfig(root, 'linked/config.json'), safeError);
  assert.equal(await resolveProjectPath(root, '.'), root);
  await assert.rejects(resolveProjectPath(root, 'missing'), safeError);
});

test('real Git distinguishes tracking and effective ignore rules with spaces and leading hyphens', async t => {
  const root = await temporary(t);
  try { await execute('git', ['--version'], { windowsHide: true }); }
  catch (error) {
    if (error.code === 'ENOENT') { t.skip('Git is not installed.'); return; }
    throw new Error('Git test prerequisite failed.');
  }
  await execute('git', ['init', '--quiet'], { cwd: root, windowsHide: true });
  await writeFile(path.join(root, '.gitignore'), '.env\nsecret dir/\n-ignored.env\n');
  await mkdir(path.join(root, 'secret dir'));
  await writeFile(path.join(root, '.env'), 'CONTROLLED=fixture');
  await writeFile(path.join(root, '.env.example'), 'CONTROLLED=');
  await writeFile(path.join(root, '-ignored.env'), 'CONTROLLED=fixture');
  await writeFile(path.join(root, 'secret dir', 'local.env'), 'CONTROLLED=fixture');
  await execute('git', ['add', '--force', '--', '.env', '.env.example'], { cwd: root, windowsHide: true });
  const result = await inspectGit(root, ['.env', '.env.example', '-ignored.env', 'secret dir/local.env']);
  assert.equal(result.status, 'available');
  assert.deepEqual([...result.tracked].sort(), ['.env', '.env.example']);
  assert.deepEqual([...result.ignored].sort(), ['-ignored.env', '.env', 'secret dir/local.env']);
  if (process.platform === 'win32') {
    await writeFile(path.join(root, '.envguard.json'), JSON.stringify({ envFiles: ['.ENV'] }));
    const canonical = await loadConfig(root);
    assert.equal((await inspectGit(root, canonical.envFiles)).tracked.has('.env'), true);
  }
  await assert.rejects(inspectGit(root, [`../${canary}`]), safeError);
  await writeFile(path.join(root, '.git', 'config'), `[${canary}\n`);
  await assert.rejects(inspectGit(root, ['.env']), safeError);
});

test('non-Git directories retain useful deterministic status', async t => {
  const root = await temporary(t);
  const result = await inspectGit(root, ['.env']);
  assert.equal(['missing', 'not-repository'].includes(result.status), true);
  assert.equal(result.tracked.size, 0);
  assert.equal(result.ignored.size, 0);
});

test('missing Git is handled using a controlled empty executable search path', async t => {
  const root = await temporary(t);
  const moduleUrl = new URL('../dist/git.js', import.meta.url).href;
  const script = `const { inspectGit } = await import(${JSON.stringify(moduleUrl)}); const result = await inspectGit(process.cwd(), ['.env']); console.log(result.status);`;
  const result = await execute(process.execPath, ['--input-type=module', '-e', script], { cwd: root, env: { PATH: '' }, windowsHide: true });
  assert.equal(result.stdout.trim(), 'missing');
  assert.equal(result.stderr, '');
});

test('Git resolution never executes a repository-local binary or relative PATH entry', async t => {
  const root = await temporary(t);
  await copyFile(process.execPath, path.join(root, process.platform === 'win32' ? 'git.exe' : 'git'));
  const moduleUrl = new URL('../dist/git.js', import.meta.url).href;
  const script = `const { inspectGit } = await import(${JSON.stringify(moduleUrl)}); const result = await inspectGit(process.cwd(), ['.env']); console.log(result.status);`;
  for (const searchPath of ['', '.', root]) {
    const result = await execute(process.execPath, ['--input-type=module', '-e', script], { cwd: root, env: { PATH: searchPath }, windowsHide: true });
    assert.equal(result.stdout.trim(), 'missing');
    assert.equal(result.stderr, '');
  }
});

test('nonregular configuration is rejected before opening', async t => {
  const root = await temporary(t);
  await mkdir(path.join(root, '.envguard.json'));
  await assert.rejects(loadConfig(root), safeError);
});

test('POSIX config FIFOs return controlled errors without waiting for writers', { skip: process.platform === 'win32' ? 'POSIX special-file semantics' : false, timeout: 10000 }, async t => {
  const root = await temporary(t);
  for (const filename of ['.envguard.json', 'explicit.json']) {
    await execute('mkfifo', ['--', path.join(root, filename)]);
    const args = [binary, 'scan', '--format', 'json', ...(filename === 'explicit.json' ? ['--config', filename] : [])];
    const result = spawnSync(process.execPath, args, { cwd: root, env: {}, encoding: 'utf8', timeout: 3000 });
    assert.equal(result.error, undefined, 'Configuration must fail before a FIFO timeout');
    assert.equal(result.status, 2);
    assert.equal(JSON.parse(result.stderr).exitCode, 2);
  }
});

test('current-index environment violations survive missing working-tree files and respect scope', async t => {
  const root = await temporary(t);
  await execute('git', ['init', '--quiet'], { cwd: root, windowsHide: true });
  const files = ['.env', 'src/deleted.env', 'outside/.env', 'nested/.env', 'node_modules/pkg/.env', 'nestedrepo/.env', '.env.example'];
  const fixtureValue = 'synthetic-index-credential';
  await writeFile(path.join(root, '.gitignore'), '.env\n');
  for (const file of files) {
    await mkdir(path.dirname(path.join(root, file)), { recursive: true });
    await writeFile(path.join(root, file), file.endsWith('.example') ? 'PASSWORD=\n' : `PASSWORD=${fixtureValue}\n`);
  }
  await execute('git', ['add', '--force', '--', ...files], { cwd: root, windowsHide: true });
  for (const file of files) await rm(path.join(root, file));
  await mkdir(path.join(root, 'nestedrepo', '.git'));
  if (process.platform !== 'win32') {
    // Excluded index paths below a symlink must never reach check-ignore.
    await rm(path.join(root, 'outside'), { recursive: true });
    await symlink(path.join(root, 'nested'), path.join(root, 'outside'), 'dir');
  }
  for (const policy of [{ include: ['src'], exclude: ['outside'] }, { include: ['.'], exclude: ['outside', 'nested'] }]) {
    await writeFile(path.join(root, '.envguard.json'), JSON.stringify(policy));
    const result = spawnSync(process.execPath, [binary, 'scan', '--format', 'json'], { cwd: root, encoding: 'utf8', timeout: 20000, windowsHide: true });
    assert.equal(result.error, undefined);
    assert.equal(`${result.stdout}${result.stderr}`.includes(fixtureValue), false);
    assert.equal(result.status, 1);
    assert.deepEqual(JSON.parse(result.stdout).findings.filter(f => f.ruleId === 'git/env-tracked').map(f => f.location.path).sort(), ['.env', 'src/deleted.env']);
    assert.equal(JSON.parse(result.stdout).findings.some(f => f.ruleId === 'git/env-not-ignored' && f.location.path === '.env'), false, 'Index-only paths still use effective ignore rules');
  }
  await writeFile(path.join(root, '.envguard.json'), JSON.stringify({ envFiles: [] }));
  const selected = spawnSync(process.execPath, [binary, 'scan', '--format', 'json'], { cwd: root, encoding: 'utf8', timeout: 20000, windowsHide: true });
  assert.equal(selected.status, 0, 'Explicit environment selection remains operator-owned policy');
  assert.equal(`${selected.stdout}${selected.stderr}`.includes(fixtureValue), false);
});

test('POSIX literal-backslash filenames retain Git identity under a critical-only gate', { skip: process.platform === 'win32' ? 'POSIX filename semantics' : false }, async t => {
  const root = await temporary(t);
  await execute('git', ['init', '--quiet'], { cwd: root });
  const file = 'local\\secret.env';
  const fixtureValue = 'synthetic-backslash-credential';
  await writeFile(path.join(root, file), `PASSWORD=${fixtureValue}\n`);
  await execute('git', ['add', '--', file], { cwd: root });
  const result = spawnSync(process.execPath, [binary, 'scan', '--format', 'json', '--fail-on', 'critical'], { cwd: root, encoding: 'utf8', timeout: 20000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).findings.some(f => f.ruleId === 'git/env-tracked' && f.location.path === file), true);
  assert.equal(`${result.stdout}${result.stderr}`.includes(fixtureValue), false);
});
