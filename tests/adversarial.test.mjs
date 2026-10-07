import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { analyzeSecrets } from '../dist/secrets.js';
import { defaultConfig } from '../dist/config.js';
import { applyPolicy } from '../dist/scan.js';

const binary = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const shortCanary = 'Q7m2K8';
const tokenCanary = ['ghp_', 'aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3aB5'].join('');
const escapeLiteral = value => [...value].map(character => `\\x${character.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
const encodeAll = value => [...value].map(character => `%${character.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');

async function fixture(t, files) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'eg-a-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) await writeFile(path.join(root, name), content);
  return root;
}

function execute(root, command = 'scan', format = 'json', environment = {}, extra = []) {
  const result = spawnSync(process.execPath, [binary, command, '--root', root, '--format', format, ...extra], {
    env: environment, encoding: 'utf8', timeout: 20_000, windowsHide: true,
  });
  assert.equal(Boolean(result.error), false, 'The CLI subprocess did not complete normally.');
  return result;
}

function assertNoDisclosure(result, canaries) {
  let observable = `${result.stdout}${result.stderr}`;
  for (let iteration = 0; iteration < 5; iteration++) {
    for (const canary of canaries) assert.equal(observable.includes(canary), false, 'Observable output disclosed fixture material.');
    try {
      const decoded = decodeURIComponent(observable);
      if (decoded === observable) break;
      observable = decoded;
    } catch { break; }
  }
}

test('decoded short sensitive literal also present in the filename stays opaque', async t => {
  const root = await fixture(t, { [`${shortCanary}.ts`]: `const password = "${escapeLiteral(shortCanary)}";` });
  for (const format of ['text', 'json']) {
    const result = execute(root, 'scan', format);
    assertNoDisclosure(result, [shortCanary]);
    assert.equal(result.status, 1);
    assert.equal(result.stdout.includes('[redacted-path]'), true);
  }
});

test('encoded token filenames are opaque even when binary candidates cannot be inspected', async t => {
  const once = encodeAll(tokenCanary);
  const twice = once.replaceAll('%', '%25');
  const root = await fixture(t, { [`${once}.ts`]: Buffer.from([0]), [`${twice}.ts`]: Buffer.from([0]) });
  for (const format of ['text', 'json']) {
    const result = execute(root, 'scan', format);
    assertNoDisclosure(result, [tokenCanary, once, twice]);
    assert.equal(result.stdout.includes('[redacted-path]'), true);
  }
});

test('decoded known credentials in unassigned source literals are detected', async t => {
  const root = await fixture(t, {
    'call.ts': `send("${escapeLiteral(tokenCanary)}");`,
    'array.ts': `export const fixtures = ["${escapeLiteral(tokenCanary)}"];`,
    'default.ts': `export default "${escapeLiteral(tokenCanary)}";`,
  });
  const result = execute(root);
  assertNoDisclosure(result, [tokenCanary]);
  const output = JSON.parse(result.stdout);
  for (const file of ['call.ts', 'array.ts', 'default.ts']) {
    assert.equal(output.findings.some(finding => finding.ruleId === 'secret/hardcoded-token' && finding.location?.path === file), true, 'A decoded credential literal bypassed scanning.');
  }
  assert.equal(result.status, 1);
});

test('runtime short sensitive values cannot leak through malformed template filenames', async t => {
  const root = await fixture(t, {
    [`.env.${shortCanary}.example`]: 'MALFORMED DEFINITION\n',
    '.envguard.json': JSON.stringify({ required: ['JWT_SECRET'], schema: { JWT_SECRET: { minLength: 8 } } }),
  });
  for (const format of ['text', 'json']) {
    const result = execute(root, 'validate', format, { JWT_SECRET: shortCanary });
    assertNoDisclosure(result, [shortCanary]);
    assert.equal(result.status, 1);
  }
});

test('ordinary source literal values do not become secret metadata candidates', () => {
  const assignments = [
    { name: 'caption', value: 'config', location: { path: 'config.ts', line: 1 } },
    { name: 'password', value: shortCanary, location: { path: 'config.ts', line: 2 } },
  ];
  const result = analyzeSecrets('', 'config.ts', { assignments });
  assert.equal(result.secrets.includes('config'), false);
  assert.equal(result.secrets.includes(shortCanary), true);
  assert.equal(JSON.stringify(result.findings).includes(shortCanary), false);
});

test('sensitive name metadata is omitted from required-variable diagnostics', async t => {
  const variableName = `JWT_SECRET_${shortCanary}`;
  const root = await fixture(t, { '.env.example': `${variableName}=${shortCanary}\n${tokenCanary}=\n` });
  for (const format of ['text', 'json']) {
    const result = execute(root, 'validate', format);
    assertNoDisclosure(result, [shortCanary, variableName, tokenCanary]);
    assert.equal(result.status, 1);
  }
});

test('public URL and endpoint metadata stays useful while embedded credentials remain detected', () => {
  const names = ['NEXT_PUBLIC_PASSWORD_RESET_URL', 'VITE_AUTH_TOKEN_ENDPOINT', 'REACT_APP_SECRET_HOST', 'NEXT_PUBLIC_API_KEY_PORT', 'VITE_TOKEN_URI'];
  for (const name of names) {
    const result = analyzeSecrets('', '.env.example', {
      template: true, assignments: [{ name, value: 'https://example.invalid', location: { path: '.env.example' } }],
    });
    assert.equal(result.findings.length, 0, 'Public configuration metadata was misclassified as a credential.');
  }
  const credentialUrl = ['https://', 'fixture:fixture-password@example.invalid'].join('');
  const result = analyzeSecrets('', '.env.example', {
    template: true, assignments: [{ name: 'NEXT_PUBLIC_PASSWORD_RESET_URL', value: credentialUrl, location: { path: '.env.example' } }],
  });
  assert.equal(result.findings.some(finding => finding.ruleId === 'secret/credentials-url'), true);
  assert.equal(JSON.stringify(result.findings).includes('fixture-password'), false);
});

test('large groups of findings sharing one file retain safe metadata', { timeout: 10_000 }, () => {
  const count = 15_000;
  const candidatePrefix = 'fixture-sensitive-value-';
  const candidates = Array.from({ length: count }, (_, index) => `${candidatePrefix}${index}`);
  const raw = Array.from({ length: count }, (_, index) => ({
    ruleId: 'secret/public-exposure', severity: 'critical', message: 'Sensitive public configuration.',
    location: { path: '.env', line: index + 1 },
  }));
  const result = applyPolicy('scan', raw, defaultConfig(), candidates);
  assert.equal(result.findings.length, count);
  assert.equal(result.exitCode, 1);
  assert.equal(JSON.stringify(result).includes(candidatePrefix), false, 'A batch finding exposed a fixture credential.');
});

test('dotenv record amplification fails at the execution boundary without fixture disclosure', async t => {
  const definitions = Array.from({ length: 10_000 }, (_, index) => `KEY_${index}=`).join('\n');
  const root = await fixture(t, { '.env': `${definitions}\nPASSWORD=${shortCanary}` });
  for (const format of ['text', 'json']) {
    const result = execute(root, 'scan', format);
    assertNoDisclosure(result, [shortCanary]);
    assert.equal(result.status, 2);
    assert.equal(result.stderr.includes('10,000 definition limit'), true);
  }
});

test('malformed percent and UTF8 escapes cannot disable encoded-path confidentiality', async t => {
  const encoded = encodeAll(tokenCanary);
  const root = await fixture(t, {
    [`%oops_${encoded}.ts`]: `send('${tokenCanary}');`,
    [`%ff_${encoded}.ts`]: Buffer.from([0]),
  });
  for (const format of ['text', 'json']) {
    const result = execute(root, 'scan', format);
    assertNoDisclosure(result, [tokenCanary, encoded]);
    assert.equal(result.stdout.includes('[redacted-path]'), true);
    assert.equal(result.status, 1);
  }
});

test('quoted YAML and TOML values protect decoded and raw credential representations', async t => {
  const unicode = [...shortCanary].map(character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  const hexadecimal = escapeLiteral(shortCanary);
  const wide = [...shortCanary].map(character => `\\U${character.charCodeAt(0).toString(16).padStart(8, '0')}`).join('');
  const apostropheCanary = "Q7m'2K8";
  const adjacentDigitsCanary = 'Q0034-fixture';
  const root = await fixture(t, {
    [`${shortCanary}-unicode.yaml`]: `PASSWORD: "${unicode}" # ordinary comment\n`,
    [`${shortCanary}-hex.yaml`]: `PASSWORD: "${hexadecimal}"\n`,
    [`${shortCanary}-wide.toml`]: `PASSWORD = "${wide}"\n`,
    [`${apostropheCanary}.yaml`]: `PASSWORD: '${apostropheCanary.replaceAll("'", "''")}'\n`,
    [`${adjacentDigitsCanary}.toml`]: 'PASSWORD = "\\u00510034-fixture"\n',
  });
  for (const format of ['text', 'json']) {
    const result = execute(root, 'scan', format);
    assertNoDisclosure(result, [shortCanary, apostropheCanary, adjacentDigitsCanary, unicode, hexadecimal, wide]);
    assert.equal(result.status, 1);
    assert.equal(result.stdout.includes('[redacted-path]'), true);
  }
  const literal = analyzeSecrets("PASSWORD = 'fixture\\u0041'", 'literal.toml');
  assert.equal(literal.secrets.includes('fixture\\u0041'), true);
  assert.equal(literal.secrets.includes('fixtureA'), false, 'TOML literal strings must retain backslashes');
  const bracketed = analyzeSecrets('PASSWORD: "\\u005Bfixture-value\\u005D"', 'bracketed.yaml');
  assert.equal(bracketed.secrets.includes('[fixture-value]'), true, 'Quoted container-like strings remain scalar values');
  assert.equal(JSON.stringify(literal.findings).includes('fixture\\u0041'), false);
  assert.equal(JSON.stringify(bracketed.findings).includes('[fixture-value]'), false);
});

test('short undeclared explicit dotenv defaults are protected in syntax locations', async t => {
  const file = `${shortCanary}.env`;
  const root = await fixture(t, { [file]: `PASSWORD=${shortCanary}\nBROKEN INPUT\n` });
  for (const format of ['text', 'json']) {
    const result = execute(root, 'validate', format, {}, ['--dotenv', file]);
    assertNoDisclosure(result, [shortCanary]);
    assert.equal(result.status, 1);
    assert.equal(result.stdout.includes('[redacted-path]'), true);
  }
});

test('unexpected deep AST failure is a safe execution error even with findings disabled', async t => {
  const content = `${'('.repeat(4000)}"${escapeLiteral(tokenCanary)}"${')'.repeat(4000)};`;
  const root = await fixture(t, { 'deep.ts': content });
  for (const format of ['text', 'json']) {
    const result = execute(root, 'scan', format, {}, ['--fail-on', 'none']);
    assertNoDisclosure(result, [tokenCanary, escapeLiteral(tokenCanary)]);
    assert.equal(result.status, 2);
    assert.equal(result.stderr.includes('Source parsing could not complete safely'), true);
  }
});

test('diverse secret lengths and unique long paths have a bounded metadata work budget', { timeout: 10_000 }, () => {
  const prefix = 'fixture-candidate-';
  const candidates = Array.from({ length: 1024 }, (_, index) => prefix + 'z'.repeat(index));
  const raw = Array.from({ length: 8 }, (_, index) => ({
    ruleId: 'env/missing', severity: 'error', message: 'Fixed diagnostic.',
    location: { path: `${index}/${'a'.repeat(1000)}.ts` },
  }));
  assert.throws(() => applyPolicy('scan', raw, defaultConfig(), candidates), error => {
    assert.equal(String(error).includes(prefix), false, 'Resource error disclosed a fixture value');
    return /safe matching limit/.test(error.message);
  });
});
