import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSource } from '../dist/source.js';

const names = source => analyzeSource(source, 'src/config.ts').usages.map(usage => usage.name).filter(Boolean);

test('discovers AST environment access variants and decoded literal names', () => {
  const source = [
    'process.env.DATABASE_URL;',
    'process.env["API_KEY"];',
    "process.env['JWT_SECRET'];",
    'process.env[`CACHE_URL`];',
    'process["env"]["QUEUE_URL"];',
    'global.process.env.GLOBAL_KEY;',
    'globalThis["process"].env.GLOBAL_THIS_KEY;',
    'import.meta.env.VITE_API_URL;',
    'import.meta.env["VITE_CLIENT_ID"];',
    'process?.env?.OPTIONAL_KEY;',
    'process.env["ESCAPED\\u005fKEY"];',
    'const { HOST, PORT: localPort, USER = "guest" } = process.env;',
    'const env = process.env; const same = env; same.ALIASED_KEY;',
  ].join('\n');
  assert.deepEqual(names(source), [
    'DATABASE_URL', 'API_KEY', 'JWT_SECRET', 'CACHE_URL', 'QUEUE_URL',
    'GLOBAL_KEY', 'GLOBAL_THIS_KEY', 'VITE_API_URL', 'VITE_CLIENT_ID',
    'OPTIONAL_KEY', 'ESCAPED_KEY', 'HOST', 'PORT', 'USER', 'ALIASED_KEY',
  ]);
  const analysis = analyzeSource(source, 'src/config.ts');
  assert.deepEqual(analysis.usages[0].location, { path: 'src/config.ts', line: 1, column: 1 });
  assert.deepEqual(analysis.findings, []);
});

test('does not count comments, string contents, local objects, or shadowed aliases', () => {
  const source = [
    '// process.env.COMMENT',
    'const text = "process.env.STRING";',
    'function a(process) { return process.env.PARAMETER; }',
    'function b() { const process = { env: {} }; return process.env.LOCAL; }',
    'function c(global) { return global.process.env.GLOBAL_PARAMETER; }',
    'const env = process.env;',
    'function d(env) { return env.SHADOW; }',
    '{ const env = {}; env.BLOCK_SHADOW; }',
    'env.OUTER;',
    'function e() { process.env.HOISTED; var process = {}; }',
    'type Config = { process: { env: { TYPE: string } } };',
  ].join('\n');
  assert.deepEqual(names(source), ['OUTER']);
});

test('handles lexical scope imports, catch bindings, loops, and function names', () => {
  assert.deepEqual(names('import process from "mock"; process.env.LOCAL;'), []);
  assert.deepEqual(names('try {} catch (process) { process.env.LOCAL; } process.env.OUTER;'), ['OUTER']);
  assert.deepEqual(names('for (const process of items) { process.env.LOCAL; } process.env.OUTER;'), ['OUTER']);
  assert.deepEqual(names('const fn = function process() { return process.env.LOCAL; }; process.env.OUTER;'), ['OUTER']);
  assert.deepEqual(names('function f() { const env = process.env; return env.INNER; }'), ['INNER']);
});

test('reports dynamic access, spread, and escaped objects without raw expressions', () => {
  const canary = 'DO_NOT_REPORT_SOURCE_CANARY_823743';
  const analysis = analyzeSource([
    `process.env["${canary}" + runtimeKey];`,
    'const { KNOWN, ...rest } = process.env;',
    'send(process.env);',
    'const env = process.env; send(env);',
    'const copied = { ...process.env };',
  ].join('\n'), 'src/config.ts');
  assert.deepEqual(analysis.usages.filter(usage => usage.name).map(usage => usage.name), ['KNOWN']);
  assert.equal(analysis.usages.filter(usage => usage.dynamic).length, 5);
  assert.equal(analysis.findings.filter(finding => finding.ruleId === 'env/dynamic').length, 5);
  assert.equal(JSON.stringify(analysis.findings).includes(canary), false);
  assert.ok(analysis.findings.every(finding => finding.severity === 'info'));
});

test('extracts string assignments with security context and decoded values', () => {
  const analysis = analyzeSource([
    'const API_TOKEN = "fake\\ncredential";',
    'const options = { password: `local-password`, ["private_key"]: "test-key" };',
    'options.secret = "assigned";',
    'options["client_secret"] = "bracket-assignment";',
    'class Config { privateKey = "class-key"; }',
    'const { JWT_SECRET: jwtSecret = "binding-default" } = process.env;',
    'function configure(password = "parameter-default", { HOST } = process.env) {}',
    'const computed = `prefix-${runtime}`;',
    'type Secret = "not-an-assignment";',
  ].join('\n'), 'src/config.ts');
  assert.deepEqual(analysis.assignments.map(({ name, value }) => ({ name, value })), [
    { name: 'API_TOKEN', value: 'fake\ncredential' },
    { name: 'password', value: 'local-password' },
    { name: 'private_key', value: 'test-key' },
    { name: 'secret', value: 'assigned' },
    { name: 'client_secret', value: 'bracket-assignment' },
    { name: 'privateKey', value: 'class-key' },
    { name: 'JWT_SECRET', value: 'binding-default' },
    { name: 'password', value: 'parameter-default' },
  ]);
  assert.deepEqual(analysis.findings, []);
});

test('handles wrappers, assignment destructuring, and CRLF locations', () => {
  const analysis = analyzeSource([
    'const env = (process.env as Record<string, string>);',
    '(env!).FIRST;',
    '({ SECOND, THIRD: local } = process.env);',
    'const { ["FOURTH"]: another } = import.meta.env;',
  ].join('\r\n'), 'src/config.ts');
  assert.deepEqual(analysis.usages.map(usage => usage.name), ['FIRST', 'SECOND', 'THIRD', 'FOURTH']);
  assert.equal(analysis.usages[1].location.line, 3);
  assert.deepEqual(analysis.findings, []);
});

test('malformed source diagnostics omit source material', () => {
  const canary = 'DO_NOT_REPORT_PARSE_CANARY_823743';
  const analysis = analyzeSource(`const secret = "${canary}`, 'src/broken.ts');
  assert.ok(analysis.findings.some(finding => finding.ruleId === 'env/source-syntax'));
  assert.equal(JSON.stringify(analysis.findings).includes(canary), false);
  assert.equal(analysis.findings[0].location.path, 'src/broken.ts');
});
