import assert from 'node:assert/strict';
import test from 'node:test';
import { parseEnv } from '../dist/dotenv.js';
import { analyzeSecrets, isPlaceholder, isPublicSecret, isSensitiveName } from '../dist/secrets.js';
import { EnvGuardError } from '../dist/types.js';

const githubCanary = ['ghp_', 'aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3aB5'].join('');
const gitlabCanary = ['glpat-', 'AbCdEf1234567890GhIjKlMn'].join('');
const slackCanary = ['xoxb-', '123456789012-987654321098-AbCdEfGhIjKlMnOp'].join('');
const patCanary = ['github_pat_', '11AA22bb33CC44dd55EE66ff77GG88hh99II'].join('');
const privateCanary = ['-----BEGIN ', 'RSA PRIVATE KEY-----\n', 'ZmFrZS1maXh0dXJlLW1hdGVyaWFs\n', '-----END ', 'RSA PRIVATE KEY-----'].join('');
const urlCanary = ['postgres://', 'fixture:fixture-password@example.invalid/database'].join('');

function assertSafe(findings, secrets) {
  const observable = JSON.stringify(findings);
  for (const candidate of secrets) {
    assert.equal(observable.includes(candidate), false, 'A diagnostic disclosed a fixture credential.');
  }
  for (const finding of findings) {
    assert.equal(Object.hasOwn(finding, 'value'), false, 'A finding retained a value field.');
    assert.equal(Object.hasOwn(finding, 'matchedText'), false, 'A finding retained source material.');
  }
}

test('dotenv supports BOM, export, whitespace, comments, CRLF, quotes and empty values', () => {
  const parsed = parseEnv('\uFEFF# comment\r\n export APP_NAME = demo # note\r\nEMPTY=\r\nQUOTED="a # b" # comment\r\nSINGLE=\'line\\ntext\'\r\nESCAPED="a\\nb\\tc\\\\d\\\"e"\r\n', '.env');
  assert.equal(parsed.findings.length, 0);
  assert.deepEqual(parsed.definitions.map(({ name, value }) => [name, value]), [
    ['APP_NAME', 'demo'], ['EMPTY', ''], ['QUOTED', 'a # b'], ['SINGLE', 'line\\ntext'], ['ESCAPED', 'a\nb\tc\\d"e'],
  ]);
  assert.deepEqual(parsed.definitions[0].location, { path: '.env', line: 2, column: 9 });
});

test('dotenv tracks multiline locations and duplicate/conflicting definitions', () => {
  const parsed = parseEnv('MULTI="first\nsecond"\nAPP=demo\nAPP=demo\nAPP=other\nAFTER=done\n', '.env');
  assert.equal(parsed.definitions[0].value, 'first\nsecond');
  assert.equal(parsed.definitions.at(-1).location.line, 6);
  assert.equal(parsed.findings.filter((finding) => finding.ruleId === 'env/duplicate').length, 2);
  assert.equal(parsed.findings.filter((finding) => finding.ruleId === 'env/conflict').length, 1);
});

test('dotenv rejects malformed syntax and NUL without echoing input', () => {
  const parsed = parseEnv(`BROKEN ${githubCanary}\nBAD="${gitlabCanary}" trailing\nNUL=a\0b\n9INVALID=bad\nVALID=okay\nUNCLOSED="${slackCanary}`, '.env');
  assert.equal(parsed.findings.length, 5);
  assert.equal(parsed.definitions.length, 1);
  assert.equal(parsed.definitions[0].name, 'VALID');
  assertSafe(parsed.findings, [githubCanary, gitlabCanary, slackCanary]);
  assert.equal(parsed.findings.every((finding) => finding.location?.line > 0), true);
});

test('high-confidence formats emit located safe findings', () => {
  const source = [githubCanary, gitlabCanary, slackCanary, patCanary, privateCanary, urlCanary].join('\n');
  const result = analyzeSecrets(source, 'src/config.ts');
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'secret/hardcoded-token').length, 4);
  assert.equal(result.findings.some((finding) => finding.ruleId === 'secret/private-key'), true);
  assert.equal(result.findings.some((finding) => finding.ruleId === 'secret/credentials-url'), true);
  assert.equal(result.findings.find((finding) => finding.message.includes('GitLab')).location.line, 2);
  assertSafe(result.findings, [githubCanary, gitlabCanary, slackCanary, patCanary, privateCanary, urlCanary, 'fixture-password']);
});

test('sensitive assignments require literal values and names respect word boundaries', () => {
  const assignments = [
    { name: 'databasePassword', value: 'fixture-only-canary', location: { path: 'config.ts', line: 1 } },
    { name: 'JWT_SECRET', value: 'test', location: { path: 'config.ts', line: 2 } },
    { name: 'secretary', value: 'ordinary-word', location: { path: 'config.ts', line: 3 } },
    { name: 'API_URL', value: 'https://example.invalid', location: { path: 'config.ts', line: 4 } },
  ];
  const result = analyzeSecrets('', 'config.ts', { assignments });
  assert.deepEqual(result.findings.map((finding) => finding.ruleId), ['secret/hardcoded', 'secret/weak']);
  assertSafe(result.findings, ['fixture-only-canary']);
  assert.equal(isSensitiveName('apiKey'), true);
  assert.equal(isSensitiveName('APIKey'), true);
  assert.equal(isSensitiveName('JWTSecret'), true);
  assert.equal(isSensitiveName('DBPassword'), true);
  assert.equal(isSensitiveName('client_secret'), true);
  assert.equal(isSensitiveName('password_file'), false);
  assert.equal(isSensitiveName('secretary'), false);
});

test('public configuration flags sensitive names, including empty templates', () => {
  const result = analyzeSecrets('', '.env.example', { template: true, assignments: [
    { name: 'NEXT_PUBLIC_JWT_SECRET', value: '', location: { path: '.env.example', line: 1 } },
    { name: 'VITE_API_KEY', value: '<your-key>', location: { path: '.env.example', line: 2 } },
    { name: 'REACT_APP_API_URL', value: '', location: { path: '.env.example', line: 3 } },
  ] });
  assert.equal(result.findings.length, 2);
  assert.equal(result.findings.every((finding) => finding.ruleId === 'secret/public-exposure'), true);
  assert.equal(isPublicSecret('NEXT_PUBLIC_API_URL'), false);
});

test('templates tolerate placeholders while detecting genuine credentials', () => {
  for (const value of ['', '${API_KEY}', '<your-key>', 'replace_me', 'changeme', 'your_api_key', 'xxxxxxxx']) {
    assert.equal(isPlaceholder(value), true, 'A documented placeholder was not recognized.');
    assert.equal(analyzeSecrets('', '.env.example', { template: true, assignments: [{ name: 'API_KEY', value, location: { path: '.env.example' } }] }).findings.length, 0);
  }
  const result = analyzeSecrets('', '.env.example', { template: true, assignments: [{ name: 'API_KEY', value: githubCanary, location: { path: '.env.example', line: 1 } }] });
  assert.equal(result.findings.some((finding) => finding.ruleId === 'secret/hardcoded-token'), true);
  assertSafe(result.findings, [githubCanary]);
  const placeholderUrl = ['postgres://', 'user:password@localhost/db'].join('');
  assert.equal(analyzeSecrets(placeholderUrl, '.env.example', { template: true }).findings.length, 0);
});

test('active dotenv credentials are expected, with weak values still rejected', () => {
  const result = analyzeSecrets('', '.env', { environment: true, assignments: [
    { name: 'DB_PASSWORD', value: 'fixture-long-canary', location: { path: '.env', line: 1 } },
    { name: 'JWT_SECRET', value: 'short', location: { path: '.env', line: 2 } },
  ] });
  assert.deepEqual(result.findings.map((finding) => finding.ruleId), ['secret/weak']);
  assertSafe(result.findings, ['fixture-long-canary', 'short']);
});

test('AWS identifiers require context and entropy never supplies proof', () => {
  const awsCanary = ['AKIA', 'AB12CD34EF56GH78'].join('');
  assert.equal(analyzeSecrets(awsCanary, 'config.ts').findings.length, 0);
  const result = analyzeSecrets('', 'config.ts', { assignments: [{ name: 'AWS_ACCESS_KEY_ID', value: awsCanary, location: { path: 'config.ts', line: 1 } }] });
  assert.equal(result.findings[0].severity, 'warning');
  assertSafe(result.findings, [awsCanary]);
  assert.equal(analyzeSecrets('a9Qx7Kr1Bv3Mn8Tz5Wp2Ls6Yh4Jd0CfE', 'config.ts').findings.length, 0);
});

test('JSON, YAML and TOML supply context without parsing JavaScript text with regex', () => {
  for (const [path, source] of [
    ['config.json', '{"nested":{"password":"fixture-config-canary"}}'],
    ['config.yaml', 'database:\n  password: fixture-config-canary'],
    ['config.toml', 'password = "fixture-config-canary"'],
  ]) {
    const result = analyzeSecrets(source, path);
    assert.equal(result.findings.some((finding) => finding.ruleId === 'secret/hardcoded'), true);
    assertSafe(result.findings, ['fixture-config-canary']);
  }
  assert.equal(analyzeSecrets('const content = \'password: fixture-config-canary\';', 'config.ts').findings.length, 0);
});

test('adversarial unterminated input and repeated key markers remain bounded', { timeout: 10_000 }, () => {
  const malformed = `PASSWORD="${'\\'.repeat(200_000)}`;
  assert.equal(parseEnv(malformed, '.env').findings.length, 1);
  const markers = ['-----BEGIN ', 'PRIVATE KEY-----\n'].join('').repeat(3_000);
  const result = analyzeSecrets(markers, 'keys.txt');
  assert.equal(result.findings.length, 3_000);
  const whitespace = `password:${' '.repeat(200_000)}fixture-config-canary`;
  assert.equal(analyzeSecrets(whitespace, 'config.yaml').findings.length, 1);
});

test('OpenPGP private armor is distinguished from public-key armor and safely reported', () => {
  const privateArmor = ['-----BEGIN ', 'PGP PRIVATE KEY BLOCK-----\n', 'ZmFrZS1wZ3AtcHJpdmF0ZS1maXh0dXJl\n', '-----END ', 'PGP PRIVATE KEY BLOCK-----'].join('');
  const publicArmor = ['-----BEGIN ', 'PGP PUBLIC KEY BLOCK-----\n', 'fixture-public-material\n', '-----END ', 'PGP PUBLIC KEY BLOCK-----'].join('');
  const result = analyzeSecrets(privateArmor, 'keys.txt');
  assert.equal(result.findings.some(finding => finding.ruleId === 'secret/private-key'), true);
  assertSafe(result.findings, [privateArmor, 'ZmFrZS1wZ3AtcHJpdmF0ZS1maXh0dXJl']);
  assert.equal(analyzeSecrets(publicArmor, 'keys.txt').findings.length, 0);
});

test('decoded JSON literals retain format detection under ordinary keys and arrays', () => {
  const encoded = [...githubCanary].map(character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  for (const text of [`{"payload":"${encoded}"}`, `["${encoded}"]`, `"${encoded}"`]) {
    const result = analyzeSecrets(text, 'config.json');
    assert.equal(result.findings.some(finding => finding.ruleId === 'secret/hardcoded-token'), true);
    assertSafe(result.findings, [githubCanary]);
  }
  const url = ['https://', 'fixture:fixture-json-password@example.invalid'].join('');
  const escapedUrl = JSON.stringify(url).replaceAll('/', '\\/');
  const result = analyzeSecrets(`{"passwordResetUrl":${escapedUrl},"caption":"ordinary-caption"}`, 'config.json');
  assert.equal(result.findings.some(finding => finding.ruleId === 'secret/credentials-url'), true);
  assert.equal(result.secrets.includes('ordinary-caption'), false);
  assertSafe(result.findings, [url, 'fixture-json-password']);
});

function safeLimitError(expected, canaries = []) {
  return error => {
    assert.equal(error instanceof EnvGuardError, true, 'Resource limits must use the safe shared error boundary.');
    assert.equal(error.message === expected, true, 'Resource-limit diagnostics must remain fixed.');
    for (const canary of canaries) assert.equal(String(error).includes(canary), false, 'A limit error disclosed fixture material.');
    return true;
  };
}

test('dotenv definition and finding limits reject amplification with safe errors', () => {
  const definitions = Array.from({ length: 10_000 }, (_, index) => `KEY_${index}=value`).join('\n');
  assert.equal(parseEnv(definitions, '.env').definitions.length, 10_000);
  assert.throws(() => parseEnv(`${definitions}\nPASSWORD=${githubCanary}`, '.env'), safeLimitError('Environment file exceeds the 10,000 definition limit.', [githubCanary]));
  const malformed = 'INVALID DEFINITION\n'.repeat(10_000);
  assert.equal(parseEnv(malformed, '.env').findings.length, 10_000);
  assert.throws(() => parseEnv(`${malformed}BROKEN ${githubCanary}`, '.env'), safeLimitError('Environment file exceeds the 10,000 finding limit.', [githubCanary]));
});

test('secret candidate and finding limits hold independently without leaking values', () => {
  const assignments = Array.from({ length: 20_000 }, (_, index) => ({ name: `SECRET_${index}`, value: `fixture-private-value-${index}`, location: { path: '.env', line: index + 1 } }));
  assert.equal(analyzeSecrets('', '.env', { environment: true, assignments }).secrets.length, 20_000);
  assert.throws(() => analyzeSecrets('', '.env', { environment: true, assignments: [...assignments, { name: 'PASSWORD', value: githubCanary, location: { path: '.env', line: 20_001 } }] }), safeLimitError('Secret analysis exceeds the 20,000 candidate limit.', [githubCanary, 'fixture-private-value-']));
  const repeatedToken = Array(20_000).fill(githubCanary).join('\n');
  assert.equal(analyzeSecrets(repeatedToken, 'fixture.txt').findings.length, 20_000);
  assert.throws(() => analyzeSecrets(`${repeatedToken}\n${githubCanary}`, 'fixture.txt'), safeLimitError('Secret analysis exceeds the 20,000 finding limit.', [githubCanary]));
});
