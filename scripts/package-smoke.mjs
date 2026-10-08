import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const nodeDirectory = path.dirname(process.execPath);
const npm = [
  path.join(nodeDirectory, 'node_modules/npm/bin/npm-cli.js'),
  path.join(nodeDirectory, '../lib/node_modules/npm/bin/npm-cli.js'),
].find(existsSync);
assert.ok(npm, 'npm CLI must be installed beside Node.js');
const temporary = await mkdtemp(path.join(os.tmpdir(), 'envguard-package-'));
const cache = path.join(root, '.npm-cache');
const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const documents = ['README.md', 'SECURITY.md', 'ARCHITECTURE.md', 'TESTING.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'LICENSE'];
const canary = 'ghp_' + 'B2c4D6e8F1g3H5i7J9k2L4m6N8p1Q3r5S7t9';

function run(executable, args, options = {}) {
  const result = spawnSync(executable, args, { cwd: root, encoding: 'utf8', timeout: 90000, ...options });
  assert.ok(!`${result.stdout ?? ''}${result.stderr ?? ''}`.includes(canary), 'Package subprocess must not disclose a credential canary');
  assert.ok(!result.error, 'Package subprocess must start and complete');
  if (options.expected !== undefined) assert.equal(result.status, options.expected, 'Packed CLI exit status must match the contract');
  else assert.equal(result.status, 0, 'Package operation must succeed');
  return result;
}

try {
  await mkdir(path.join(root, 'dist'), { recursive: true });
  const stale = path.join(root, 'dist', `obsolete-smoke-${process.pid}.js`);
  assert.ok(!existsSync(stale), 'Build regression sentinel must not overwrite a file');
  await writeFile(stale, '// Obsolete generated output.\n');
  run(process.execPath, [npm, 'run', 'build']);
  assert.ok(!existsSync(stale), 'Build must remove obsolete generated modules');
  const packed = JSON.parse(run(process.execPath, [npm, 'pack', '--json', '--ignore-scripts', '--pack-destination', temporary, '--cache', path.join(temporary, 'cache')]).stdout)[0];
  const distributed = packed.files.map(file => file.path);
  const modules = (await readdir(path.join(root, 'src'))).filter(file => file.endsWith('.ts')).map(file => `dist/${file.slice(0, -3)}.js`);
  assert.deepEqual(distributed.toSorted(), [...modules, ...documents, 'package.json'].toSorted(), 'Distribution must contain exactly the current runtime modules and public documents');
  for (const document of documents.filter(file => file.endsWith('.md'))) {
    const contents = await readFile(path.join(root, document), 'utf8');
    for (const link of contents.matchAll(/\]\(([^)]+)\)/g)) {
      const target = link[1].split('#')[0];
      if (target && !/^[a-z][a-z0-9+.-]*:/i.test(target)) assert.ok(distributed.includes(target), 'Relative documentation links must resolve inside the installed package');
    }
  }
  assert.ok(!distributed.some(file => /(?:\.env|tests|fixtures|AGENTS|PROMPTS|CODEX|cache|coverage)/i.test(file)), 'Development and environment artifacts must be absent');
  const consumer = path.join(temporary, 'consumer');
  await mkdir(consumer);
  await writeFile(path.join(consumer, 'package.json'), '{"name":"envguard-local-smoke","private":true}\n');
  const installArgs = [npm, 'install', '--ignore-scripts', '--no-audit', '--no-fund', path.join(temporary, packed.filename)];
  if (existsSync(cache)) installArgs.push('--offline', '--cache', cache);
  run(process.execPath, installArgs, { cwd: consumer });
  const executable = path.join(consumer, 'node_modules', manifest.name, 'dist/cli.js');
  const installed = JSON.parse(await readFile(path.join(consumer, 'node_modules', manifest.name, 'package.json'), 'utf8'));
  assert.equal(installed.name, manifest.name);
  assert.equal(installed.version, manifest.version);
  assert.equal(installed.license, 'MIT');
  assert.ok((await readFile(executable, 'utf8')).startsWith('#!/usr/bin/env node'));
  const shim = path.join(consumer, 'node_modules/.bin', process.platform === 'win32' ? 'envguard.cmd' : 'envguard');
  assert.ok(existsSync(shim), 'Installation must expose the envguard executable');
  // npm exec resolves the installed binary/shim rather than the workspace source.
  await writeFile(path.join(consumer, '.env.example'), 'API_URL=\n');
  await writeFile(path.join(consumer, 'app.ts'), 'process.env.API_URL;\n');
  await writeFile(path.join(consumer, '.env.local'), 'API_URL=https://example.invalid\n');
  const cli = (args, expected = 0, env = { API_URL: 'https://example.invalid' }) => {
    const environment = { PATH: process.env.PATH ?? process.env.Path, ...env };
    if (process.platform === 'win32') environment.SystemRoot = process.env.SystemRoot;
    const result = run(process.execPath, [npm, 'exec', '--offline', '--cache', path.join(temporary, 'cache'), '--', 'envguard', ...args], { cwd: consumer, env: environment, expected });
    return result;
  };
  assert.ok(cli(['--help']).stdout.includes('Usage: envguard'));
  assert.equal(cli(['--version']).stdout.trim(), manifest.version);
  for (const command of ['init', 'scan', 'validate', 'ci']) assert.ok(cli([command, '--help']).stdout.includes('Usage: envguard'));
  cli(['no-such-command'], 2);
  cli(['scan', '--format', 'invalid'], 2);
  assert.equal(JSON.parse(cli(['init', '--format', 'json']).stdout).version, manifest.version);
  cli(['init']);
  cli(['init']);
  cli(['scan']);
  const clean = JSON.parse(cli(['scan', '--format', 'json']).stdout);
  assert.equal(clean.version, manifest.version);
  assert.equal(clean.summary.critical, 0);
  cli(['validate']);
  cli(['ci']);
  cli(['validate'], 1, {});
  cli(['ci', '--format', 'json'], 1, {});
  cli(['validate', '--dotenv', '.env.local'], 0, {});
  cli(['ci', '--dotenv', '.env.local'], 0, {});
  await writeFile(path.join(consumer, 'credential.ts'), `const access_token = '${canary}';\n`);
  cli(['scan'], 1);
  assert.ok(JSON.parse(cli(['scan', '--format', 'json'], 1).stdout).findings.some(finding => finding.ruleId === 'secret/hardcoded-token'));
  cli(['ci', '--format', 'json'], 1);
  cli(['scan', '--fail-on', 'none'], 0);
  await writeFile(path.join(consumer, '.envguard.json'), '{"unknown":true}');
  cli(['ci', '--format', 'json'], 2);
  process.stdout.write(`Packed installation passed; ${distributed.length} distributed files; commands and exit codes 0/1/2 verified.\n`);
} finally {
  const tempRoot = path.resolve(os.tmpdir());
  const resolved = path.resolve(temporary);
  assert.ok(resolved.startsWith(`${tempRoot}${path.sep}`) && path.basename(resolved).startsWith('envguard-package-'));
  await rm(resolved, { recursive: true, force: true });
}
