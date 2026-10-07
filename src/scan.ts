import { parseEnv } from './dotenv.js';
import { ignoredPaths, inspectGit } from './git.js';
import { analyzeSecrets, isPublicSecret, isSensitiveName } from './secrets.js';
import { analyzeSource } from './source.js';
import { discoverFiles, environmentInScope, included, isEnvFile, isSourceFile, isTemplateFile, readProjectText } from './project.js';
import { resolveProjectPath } from './config.js';
import { EnvGuardError, SEVERITIES, VERSION, type Config, type EnvDefinition, type Finding, type ScanResult } from './types.js';

interface Analysis { findings: Finding[]; secrets: string[]; definitions: Map<string, EnvDefinition>; filesScanned: number }
const BUILTINS = new Set(['NODE_ENV']);
const CLIENT_BUILTINS = new Set(['DEV', 'PROD', 'MODE', 'SSR', 'BASE_URL']);

async function analyze(root: string, config: Config, staticScan: boolean): Promise<Analysis> {
  const discovered = await discoverFiles(root, config);
  const templateFiles = config.templateFiles ?? discovered.files.filter(isTemplateFile);
  const envFiles = config.envFiles ?? discovered.files.filter(file => isEnvFile(file) && !isTemplateFile(file));
  const git = staticScan ? await inspectGit(root, [...new Set([...discovered.files, ...envFiles, ...templateFiles])]) : undefined;
  const selected = staticScan
    ? discovered.files.filter(file => (isEnvFile(file) || included(file, config)) && (isEnvFile(file) || !git?.ignored.has(file)))
    : templateFiles;
  const files = [...new Set([...selected, ...templateFiles, ...(staticScan ? envFiles : [])])].sort();
  const loaded = await readProjectText(root, files);
  const findings = [...(staticScan ? discovered.findings : []), ...loaded.findings];
  const secrets: string[] = [];
  const definitions = new Map<string, EnvDefinition>();
  const used = new Map<string, Finding['location']>();
  const undocumented = new Map<string, Finding['location']>();
  let dynamic = false;
  let hasSource = false;
  for (const [file, text] of loaded.texts) {
    if (templateFiles.includes(file) || envFiles.includes(file) || isEnvFile(file)) {
      const parsed = parseEnv(text, file);
      findings.push(...parsed.findings);
      secrets.push(...parsed.definitions.filter(definition => definition.value.length >= 8 || (definition.value.length > 0 && isSensitiveName(definition.name))).map(definition => definition.value));
      if (templateFiles.includes(file)) {
        for (const definition of parsed.definitions) {
          const previous = definitions.get(definition.name);
          if (previous && previous.value && definition.value && previous.value !== definition.value) {
            findings.push({ ruleId: 'env/conflict', severity: 'warning', message: 'Environment templates declare conflicting defaults.', location: definition.location });
          }
          definitions.set(definition.name, definition);
        }
      }
      if (staticScan) {
        const detected = analyzeSecrets(text, file, { template: templateFiles.includes(file), environment: true, assignments: parsed.definitions });
        findings.push(...detected.findings);
        secrets.push(...detected.secrets);
        for (const definition of parsed.definitions) {
          if ((config.required.includes(definition.name) || config.schema[definition.name]?.required) && !definition.value.trim()) {
            findings.push({ ruleId: 'env/required', severity: 'error', message: 'A required environment definition is empty.', location: definition.location });
          }
        }
      }
    } else if (staticScan) {
      const source = isSourceFile(file) ? analyzeSource(text, file) : undefined;
      if (source) {
        hasSource = true;
        findings.push(...source.findings);
        for (const usage of source.usages) {
          if (usage.dynamic) dynamic = true;
          else if (usage.name) {
            if (!used.has(usage.name)) used.set(usage.name, usage.location);
            if (!(usage.provider === 'process' && BUILTINS.has(usage.name)) && !(usage.provider === 'import-meta' && CLIENT_BUILTINS.has(usage.name))) undocumented.set(usage.name, usage.location);
            if (isPublicSecret(usage.name)) findings.push({ ruleId: 'secret/public-exposure', severity: 'critical', message: 'A sensitive environment variable is exposed through a public client prefix.', location: usage.location });
          }
        }
      }
      const detected = analyzeSecrets(text, file, source ? { assignments: [...source.assignments, ...source.literals] } : undefined);
      findings.push(...detected.findings);
      secrets.push(...detected.secrets);
    }
    if (findings.length > 25000 || secrets.length > 100000 || used.size > 25000 || definitions.size > 25000) throw new EnvGuardError('Analysis exceeds the finding or candidate limit. Narrow the scan scope.');
  }
  if (staticScan) {
    const declared = new Set([...definitions.keys(), ...config.required, ...Object.keys(config.schema)]);
    for (const [name, location] of undocumented) {
      if (!declared.has(name)) findings.push({ ruleId: 'env/missing', severity: 'error', variable: name, message: 'An environment variable used in source is absent from the environment contract.', location });
      if (findings.length > 25000) throw new EnvGuardError('Analysis exceeds the finding or candidate limit. Narrow the scan scope.');
    }
    if (hasSource && !dynamic) {
      for (const [name, definition] of definitions) {
        if (!used.has(name) && !BUILTINS.has(name) && !config.required.includes(name) && !config.schema[name]?.required) {
          findings.push({ ruleId: 'env/unused', severity: 'warning', variable: name, message: 'A template variable has no discovered static source usage. External consumers may still use it.', location: definition.location });
        }
      }
    }
    if (git?.status === 'available') {
      const indexedEnvFiles = [...git.tracked].filter(file => environmentInScope(file, config)
        && !discovered.nestedRepositories.some(directory => file.startsWith(`${directory}/`)));
      const policyEnvFiles = config.envFiles ? [...config.envFiles] : [...new Set([...envFiles, ...indexedEnvFiles])];
      if (config.envFiles) {
        const policyPaths = new Set(policyEnvFiles);
        const selected = new Set<string>();
        const folded = new Set<string>();
        for (const file of config.envFiles) {
          selected.add(await resolveProjectPath(root, file));
          folded.add(file.toLowerCase());
          folded.add(file.toUpperCase());
        }
        for (const indexed of git.tracked) {
          if (policyPaths.has(indexed) || (!folded.has(indexed.toLowerCase()) && !folded.has(indexed.toUpperCase()))) continue;
          try {
            if (selected.has(await resolveProjectPath(root, indexed))) {
              policyEnvFiles.push(indexed);
              policyPaths.add(indexed);
            }
          } catch { /* Index-only paths use exact identity; missing files cannot alias a selection. */ }
        }
      }
      const indexOnly = policyEnvFiles.filter(file => !envFiles.includes(file));
      for (const file of await ignoredPaths(root, indexOnly)) git.ignored.add(file);
      for (const file of policyEnvFiles) {
        if (git.tracked.has(file)) findings.push({ ruleId: 'git/env-tracked', severity: 'critical', message: 'A sensitive environment file is tracked by Git. Remove it from the index and review exposed credentials.', location: { path: file } });
        if (!git.ignored.has(file)) findings.push({ ruleId: 'git/env-not-ignored', severity: 'error', message: 'A sensitive environment file is not effectively ignored by Git.', location: { path: file } });
      }
    } else findings.push({ ruleId: 'git/unavailable', severity: 'info', message: git?.status === 'missing' ? 'Git is unavailable; tracking and ignore checks could not run.' : 'This directory is not a Git repository; tracking and ignore checks could not run.' });
  }
  return { findings, secrets, definitions, filesScanned: loaded.texts.size };
}

export function validateEnvironment(config: Config, definitions: Map<string, EnvDefinition>, environment: Record<string, string | undefined>): { findings: Finding[]; secrets: string[] } {
  const findings: Finding[] = [];
  const secrets: string[] = [];
  const required = new Set([...definitions.keys(), ...config.required, ...Object.keys(config.schema).filter(name => config.schema[name]?.required)]);
  for (const name of Object.keys(config.schema)) {
    if (config.schema[name]?.required === false && !config.required.includes(name)) required.delete(name);
  }
  const names = new Set([...required, ...config.prohibited, ...Object.keys(config.schema)]);
  for (const name of names) {
    const value = Object.hasOwn(environment, name) ? environment[name] : undefined;
    if (value) secrets.push(value);
    if (required.has(name) && (value === undefined || value.trim() === '')) {
      findings.push({ ruleId: 'env/required', severity: 'error', variable: name, message: 'A required variable is missing or empty in the active environment.' });
      continue;
    }
    if (config.prohibited.includes(name) && value !== undefined) findings.push({ ruleId: 'env/prohibited', severity: 'error', variable: name, message: 'A prohibited variable is present in the active environment.' });
    if (value === undefined) continue;
    const schema = config.schema[name];
    if (!schema) continue;
    let valid = true;
    if (schema.type === 'number') valid = value.trim() !== '' && Number.isFinite(Number(value));
    if (schema.type === 'boolean') valid = value === 'true' || value === 'false';
    if (schema.type === 'url') {
      try { const url = new URL(value); valid = !!url.protocol && !!url.hostname; } catch { valid = false; }
    }
    if (schema.minLength !== undefined && value.length < schema.minLength) valid = false;
    if (!valid) findings.push({ ruleId: 'env/schema', severity: 'error', variable: name, message: 'An active environment variable violates its configured validation rule.' });
  }
  return { findings, secrets };
}

function metadataEscapes(value: string, structured: boolean): string {
  const escapes: Record<string, string> = { '0': '\0', b: '\b', t: '\t', n: '\n', v: '\v', f: '\f', r: '\r', ' ': ' ', '"': '"', '/': '/', '\\': '\\' };
  if (structured) Object.assign(escapes, { a: '\x07', e: '\x1b', N: '\x85', L: '\u2028', P: '\u2029' });
  return value.replace(/\\(?:u\{([0-9a-fA-F]+)\}|U([0-9a-fA-F]{8})|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|([0-3][0-7]{0,2}|[4-7][0-7]?)|(\r\n|[\s\S]))/g,
      (match, brace: string | undefined, wide: string | undefined, unicode: string | undefined, hex: string | undefined, octal: string | undefined, character: string | undefined) => {
        if (!structured && wide !== undefined) return `U${wide}`;
        if (structured && octal !== undefined) return octal.startsWith('0') ? `\0${octal.slice(1)}` : match;
        const digits = brace ?? wide ?? unicode ?? hex ?? octal;
        if (digits !== undefined) {
          const point = Number.parseInt(digits, octal === undefined ? 16 : 8);
          return point <= 0x10ffff ? String.fromCodePoint(point) : match;
        }
        if (character === '\n' || character === '\r' || character === '\r\n' || character === '\u2028' || character === '\u2029') return '';
        return escapes[character ?? ''] ?? (structured ? match : character ?? match);
      });
}

function safeLocation(file: string, secrets: Set<string>, lengths: number[], budget: { remaining: number }): string {
  if (file.length > 4096) return '[redacted-path]';
  const inputs = new Set([file]);
  for (const structured of [false, true]) {
    let decoded = file;
    for (let round = 0; round < 8; round++) {
      const previous = decoded;
      try { decoded = decodeURIComponent(decoded); } catch { return '[redacted-path]'; }
      inputs.add(decoded);
      decoded = metadataEscapes(decoded, structured);
      inputs.add(decoded);
      if (decoded === previous) break;
      if (round === 7) return '[redacted-path]';
    }
    if (/%[0-9a-f]{2}/i.test(decoded)) return '[redacted-path]';
  }
  for (const input of inputs) {
    for (const length of lengths) {
      if (length > input.length) break;
      for (let offset = 0; offset <= input.length - length; offset++) {
        budget.remaining -= length;
        if (budget.remaining < 0) throw new EnvGuardError('Diagnostic metadata exceeds the safe matching limit. Narrow the scan scope.');
        if (secrets.has(input.slice(offset, offset + length))) return '[redacted-path]';
      }
    }
  }
  if (/[\x00-\x1f\x7f]/.test(file)) return '[unsafe-path]';
  // A token-bearing filename can be discovered even when the corresponding file is skipped.
  if ([...inputs].some(input => /gh[pousr]_|github_pat_|glpat-|xox[baprs]-|(?:AKIA|ASIA)[A-Z0-9]{16}/i.test(input))) return '[redacted-path]';
  return file;
}

export function applyPolicy(command: string, raw: Finding[], config: Config, secrets: string[] = [], filesScanned = 0): ScanResult {
  if (raw.length > 25000 || secrets.length > 100000) throw new EnvGuardError('Analysis exceeds the finding or candidate limit. Narrow the scan scope.');
  let suppressed = 0;
  let disabled = 0;
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const privateCandidates = new Set(secrets.filter(value => value.length > 0));
  const candidateLengths = [...new Set([...privateCandidates].map(value => value.length))].sort((a, b) => a - b);
  const metadataCache = new Map<string, string>();
  const budget = { remaining: 64 * 1024 * 1024 };
  const metadata = (input: string): string => {
    const cached = metadataCache.get(input);
    if (cached !== undefined) return cached;
    const safe = safeLocation(input, privateCandidates, candidateLengths, budget);
    metadataCache.set(input, safe);
    return safe;
  };
  for (const finding of raw) {
    if (config.rules[finding.ruleId] === false) { disabled++; continue; }
    if (config.suppressions.some(suppression => suppression.ruleId === finding.ruleId && (!suppression.path || suppression.path === finding.location?.path) && (suppression.line === undefined || suppression.line === finding.location?.line))) { suppressed++; continue; }
    const safe: Finding = { ruleId: finding.ruleId, severity: config.severity[finding.ruleId] ?? finding.severity, message: finding.message };
    if (finding.variable) safe.variable = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(finding.variable) ? metadata(finding.variable).replace('[redacted-path]', '[redacted-variable]') : '[redacted-variable]';
    if (finding.location) safe.location = { ...finding.location, path: metadata(finding.location.path) };
    const key = JSON.stringify(safe);
    if (!seen.has(key)) { seen.add(key); findings.push(safe); }
  }
  findings.sort((a, b) => {
    const aKey = `${a.location?.path ?? ''}\0${String(a.location?.line ?? 0).padStart(8, '0')}\0${a.ruleId}\0${a.message}`;
    const bKey = `${b.location?.path ?? ''}\0${String(b.location?.line ?? 0).padStart(8, '0')}\0${b.ruleId}\0${b.message}`;
    return aKey < bKey ? -1 : aKey > bKey ? 1 : 0;
  });
  const summary = { info: 0, warning: 0, error: 0, critical: 0 };
  for (const finding of findings) summary[finding.severity]++;
  const failure = config.failOn !== 'none' && findings.some(finding => SEVERITIES.indexOf(finding.severity) >= SEVERITIES.indexOf(config.failOn as typeof finding.severity));
  return { version: VERSION, command, summary, findings, suppressed, disabled, filesScanned, exitCode: failure ? 1 : 0 };
}

export async function runChecks(root: string, config: Config, command: 'scan' | 'validate' | 'ci', environment: Record<string, string | undefined>, envFile?: string): Promise<ScanResult> {
  const result = await analyze(root, config, command !== 'validate');
  if (command !== 'scan') {
    let active = environment;
    if (envFile) {
      await resolveProjectPath(root, envFile);
      const loaded = await readProjectText(root, [envFile.replaceAll('\\', '/')]);
      result.findings.push(...loaded.findings);
      const text = loaded.texts.values().next().value as string | undefined;
      if (text !== undefined) {
        const parsed = parseEnv(text, envFile.replaceAll('\\', '/'));
        result.findings.push(...parsed.findings);
        // Explicit dotenv values are defaults; supplied runtime variables take precedence.
        active = Object.assign(Object.create(null), Object.fromEntries(parsed.definitions.map(item => [item.name, item.value])), environment);
        result.secrets.push(...parsed.definitions.filter(item => item.value.length >= 8 || (item.value.length > 0 && isSensitiveName(item.name))).map(item => item.value));
      }
    }
    const validated = validateEnvironment(config, result.definitions, active);
    result.findings.push(...validated.findings);
    result.secrets.push(...validated.secrets);
  }
  return applyPolicy(command, result.findings, config, result.secrets, result.filesScanned);
}
