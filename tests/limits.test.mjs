import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { analyzeSource } from '../dist/source.js';
import { EnvGuardError } from '../dist/types.js';
import { applyPolicy } from '../dist/scan.js';
import { defaultConfig } from '../dist/config.js';

test('source usage retains its provider so framework builtins do not hide process variables', () => {
  const result = analyzeSource('process.env.MODE; import.meta.env.MODE; const env = import.meta.env; env.DEV; function f({MODE} = import.meta.env) {}', 'app.ts');
  assert.deepEqual(result.usages.filter(item => item.name === 'MODE').map(item => item.provider), ['process', 'import-meta', 'import-meta']);
  assert.equal(result.usages.find(item => item.name === 'DEV').provider, 'import-meta');
});

test('source AST complexity has a controlled exception before unbounded diagnostic retention', () => {
  const input = Array.from({ length: 22000 }, (_, index) => `const item${index} = 'ordinary';`).join('\n');
  assert.throws(() => analyzeSource(input, 'large.ts'), error => error instanceof EnvGuardError && /limit/.test(error.message));
});

test('real CLI treats only provider-specific builtins as documented', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envguard-builtins-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, 'app.ts'), 'process.env.MODE; process.env.DEV; import.meta.env.NODE_ENV; import.meta.env.MODE; process.env.NODE_ENV;');
  const executable = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const result = spawnSync(process.execPath, [executable, 'scan', '--format', 'json'], { cwd: root, env: {}, encoding: 'utf8', timeout: 20000 });
  assert.equal(result.status, 1);
  assert.deepEqual(JSON.parse(result.stdout).findings.filter(item => item.ruleId === 'env/missing').map(item => item.variable).sort(), ['DEV', 'MODE', 'NODE_ENV']);
});

test('global finding amplification ends with a safe execution failure', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envguard-limit-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const canary = 'controlled-limit-canary-value';
  const content = Array.from({ length: 5000 }, (_, index) => `NEXT_PUBLIC_SECRET_${index}=${canary}`).join('\n');
  for (let index = 0; index < 6; index++) await writeFile(path.join(root, `.env.case${index}`), content);
  const executable = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const result = spawnSync(process.execPath, [executable, 'scan', '--format', 'json'], { cwd: root, env: {}, encoding: 'utf8', timeout: 20000 });
  assert.equal(result.error, undefined, 'Resource limit must be enforced before a timeout or crash');
  assert.equal(result.status, 2);
  assert.ok(!`${result.stdout}${result.stderr}`.includes(canary), 'Resource diagnostics must omit the credential canary');
  assert.equal(JSON.parse(result.stderr).exitCode, 2);
});

test('final assembly also enforces finding and candidate aggregate limits', () => {
  const row = { ruleId: 'env/unused', severity: 'warning', message: 'Fixed diagnostic.' };
  assert.throws(() => applyPolicy('ci', Array(25001).fill(row), defaultConfig()), error => error instanceof EnvGuardError);
  assert.throws(() => applyPolicy('validate', [], defaultConfig(), Array(100001).fill('fixture-value')), error => {
    assert.equal(String(error).includes('fixture-value'), false);
    return error instanceof EnvGuardError;
  });
});
