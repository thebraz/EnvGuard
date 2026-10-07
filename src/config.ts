import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { EnvGuardError, RULE_IDS, SEVERITIES, type Config, type RuleId, type Severity, type VariableSchema } from './types.js';

const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_ENTRIES = 256;
const CONFIG_KEYS = ['include', 'exclude', 'envFiles', 'templateFiles', 'required', 'prohibited', 'schema', 'rules', 'severity', 'suppressions', 'failOn'];
class ConfigurationError extends EnvGuardError {}
function invalid(message: string): never { throw new ConfigurationError(message); }

export function defaultConfig(): Config {
  return { include: ['.'], exclude: [], required: [], prohibited: [], schema: {}, rules: {}, severity: {}, suppressions: [], failOn: 'error' };
}

function object(input: unknown, keys?: readonly string[]): Record<string, unknown> {
  if (input === null || typeof input !== 'object' || Array.isArray(input) || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) {
    invalid('Configuration sections must be JSON objects.');
  }
  const result = input as Record<string, unknown>;
  if (Object.keys(result).length > MAX_ENTRIES) invalid('Configuration contains too many entries.');
  if (keys && Object.keys(result).some(key => !keys.includes(key))) invalid('Configuration contains an unsupported option.');
  return result;
}

function relativePath(input: unknown, allowRoot = true): string {
  if (typeof input !== 'string' || input.length === 0 || input.length > 1024 || /[\x00-\x1f\x7f*?\[\]{}]/u.test(input) || path.posix.isAbsolute(input) || path.win32.isAbsolute(input) || /^[A-Za-z]:/u.test(input)) {
    invalid('Configuration paths must be relative literal paths within the project.');
  }
  const normalized = input.replaceAll('\\', '/');
  if (normalized.split('/').includes('..')) invalid('Configuration paths cannot traverse parent directories.');
  const result = path.posix.normalize(normalized);
  if (!allowRoot && result === '.') invalid('Configuration file paths must identify a file.');
  return result.replace(/\/$/u, '');
}

function array(input: unknown, parse: (value: unknown) => string): string[] {
  if (!Array.isArray(input) || input.length > MAX_ENTRIES) invalid('Configuration lists must contain at most 256 entries.');
  const entries = input.map(parse);
  if (new Set(entries).size !== entries.length) invalid('Configuration lists cannot contain duplicate entries.');
  return entries;
}

function name(input: unknown): string {
  if (typeof input !== 'string' || input.length > 128 || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(input)) invalid('Configuration variable names must be valid identifiers of at most 128 characters.');
  return input;
}

function ruleId(input: unknown): RuleId {
  if (typeof input !== 'string' || !RULE_IDS.includes(input as RuleId)) invalid('Configuration contains an unknown rule identifier.');
  return input as RuleId;
}

function severity(input: unknown): Severity {
  if (typeof input !== 'string' || !SEVERITIES.includes(input as Severity)) invalid('Configuration severity must be info, warning, error, or critical.');
  return input as Severity;
}

function validate(input: unknown): Config {
  const source = object(input, CONFIG_KEYS);
  const config = defaultConfig();
  for (const key of ['include', 'exclude', 'envFiles', 'templateFiles'] as const) {
    if (Object.hasOwn(source, key)) config[key] = array(source[key], value => relativePath(value, key === 'include' || key === 'exclude'));
  }
  if (config.include.length === 0) invalid('Configuration include must contain at least one path.');
  for (const key of ['required', 'prohibited'] as const) {
    if (Object.hasOwn(source, key)) config[key] = array(source[key], name);
  }
  if (Object.hasOwn(source, 'schema')) {
    config.schema = Object.fromEntries(Object.entries(object(source.schema)).map(([key, value]) => {
      name(key);
      const entry = object(value, ['required', 'type', 'minLength']);
      const schema: VariableSchema = {};
      if (Object.hasOwn(entry, 'required')) {
        if (typeof entry.required !== 'boolean') invalid('Schema required must be a boolean.');
        schema.required = entry.required;
      }
      if (Object.hasOwn(entry, 'type')) {
        if (typeof entry.type !== 'string' || !['string', 'number', 'boolean', 'url'].includes(entry.type)) invalid('Schema type must be string, number, boolean, or url.');
        schema.type = entry.type as VariableSchema['type'];
      }
      if (Object.hasOwn(entry, 'minLength')) {
        if (typeof entry.minLength !== 'number' || !Number.isSafeInteger(entry.minLength) || entry.minLength < 0 || entry.minLength > 1_048_576) invalid('Schema minLength must be an integer between 0 and 1048576.');
        schema.minLength = entry.minLength;
      }
      return [key, schema];
    }));
  }
  if (config.prohibited.some(key => config.required.includes(key) || config.schema[key]?.required)) invalid('A variable cannot be both required and prohibited.');
  if (Object.hasOwn(source, 'rules')) {
    config.rules = Object.fromEntries(Object.entries(object(source.rules)).map(([key, value]) => {
      ruleId(key);
      if (typeof value !== 'boolean') invalid('Rule settings must be booleans.');
      return [key, value];
    }));
  }
  if (Object.hasOwn(source, 'severity')) config.severity = Object.fromEntries(Object.entries(object(source.severity)).map(([key, value]) => [ruleId(key), severity(value)]));
  if (Object.hasOwn(source, 'failOn')) config.failOn = source.failOn === 'none' ? 'none' : severity(source.failOn);
  if (Object.hasOwn(source, 'suppressions')) {
    if (!Array.isArray(source.suppressions) || source.suppressions.length > MAX_ENTRIES) invalid('Suppressions must contain at most 256 entries.');
    config.suppressions = source.suppressions.map(value => {
      const entry = object(value, ['ruleId', 'path', 'line', 'reason']);
      const result: Config['suppressions'][number] = { ruleId: ruleId(entry.ruleId), reason: '' };
      if (typeof entry.reason !== 'string' || entry.reason.trim().length === 0 || entry.reason.length > 256 || /[\x00-\x1f\x7f]/u.test(entry.reason)) invalid('Suppression reasons must contain between 1 and 256 printable characters.');
      result.reason = entry.reason;
      if (Object.hasOwn(entry, 'path')) result.path = relativePath(entry.path, false);
      if (Object.hasOwn(entry, 'line')) {
        if (typeof entry.line !== 'number' || !Number.isSafeInteger(entry.line) || entry.line < 1 || !result.path) invalid('Suppression lines must be positive integers scoped to a file path.');
        result.line = entry.line;
      }
      return result;
    });
    const scopes = config.suppressions.map(entry => JSON.stringify([entry.ruleId, entry.path ?? null, entry.line ?? null]));
    if (new Set(scopes).size !== scopes.length) invalid('Duplicate suppression scopes are not allowed.');
  }
  return config;
}

export function validateConfig(input: unknown): Config {
  try { return validate(input); }
  catch (error) {
    if (error instanceof ConfigurationError) throw error;
    throw new ConfigurationError('Invalid EnvGuard configuration.');
  }
}

/** Resolve an existing project path without following any symlink component. */
export async function resolveProjectPath(root: string, relative: string): Promise<string> {
  const normalized = relativePath(relative);
  try {
    const absoluteRoot = path.resolve(root);
    const rootStat = await lstat(absoluteRoot);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) invalid('Project root must be an existing directory without symlinks.');
    const canonicalRoot = await realpath(absoluteRoot);
    let current = canonicalRoot;
    if (normalized !== '.') {
      const components = normalized.split('/');
      for (const [index, component] of components.entries()) {
        current = path.join(current, component);
        const stat = await lstat(current);
        if (stat.isSymbolicLink()) invalid('Project paths cannot contain symlinks.');
        if (index < components.length - 1 && !stat.isDirectory()) invalid('Project path components must be directories.');
      }
    }
    current = await realpath(current);
    const within = path.relative(canonicalRoot, current);
    if (within === '..' || within.startsWith(`..${path.sep}`) || path.isAbsolute(within)) invalid('Project paths must remain within the project root.');
    return current;
  } catch (error) {
    if (error instanceof ConfigurationError) throw error;
    throw new ConfigurationError('Project path does not exist or cannot be accessed.');
  }
}

export async function loadConfig(root: string, configFile?: string): Promise<Config> {
  const projectRoot = await resolveProjectPath(root, '.');
  const relative = configFile === undefined ? '.envguard.json' : relativePath(configFile, false);
  if (configFile === undefined) {
    try { await lstat(path.join(projectRoot, relative)); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return defaultConfig();
      throw new ConfigurationError('EnvGuard configuration cannot be accessed.');
    }
  }
  const filename = await resolveProjectPath(projectRoot, relative);
  let config: Config;
  try {
    const info = await lstat(filename);
    if (!info.isFile() || info.size > MAX_CONFIG_BYTES) invalid('EnvGuard configuration must be a regular JSON file of at most 64 KiB.');
    const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > MAX_CONFIG_BYTES) invalid('EnvGuard configuration must be a regular JSON file of at most 64 KiB.');
      const buffer = Buffer.alloc(MAX_CONFIG_BYTES + 1);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      if (bytesRead > MAX_CONFIG_BYTES) invalid('EnvGuard configuration must be at most 64 KiB.');
      let input: unknown;
      try { input = JSON.parse(buffer.subarray(0, bytesRead).toString('utf8').replace(/^\uFEFF/u, '')); }
      catch { invalid('EnvGuard configuration must contain valid JSON.'); }
      config = validateConfig(input);
    } finally { await handle.close(); }
  } catch (error) {
    if (error instanceof ConfigurationError) throw error;
    throw new ConfigurationError('EnvGuard configuration cannot be read.');
  }
  const projectRelative = (absolute: string): string => path.relative(projectRoot, absolute).replaceAll(path.sep, '/') || '.';
  for (const [index, relativeInclude] of config.include.entries()) {
    config.include[index] = projectRelative(await resolveProjectPath(projectRoot, relativeInclude));
  }
  for (const key of ['envFiles', 'templateFiles'] as const) {
    for (const [index, relativeFile] of (config[key] ?? []).entries()) {
      const file = await resolveProjectPath(projectRoot, relativeFile);
      try {
        if (!(await lstat(file)).isFile()) invalid('Configured environment paths must identify regular files.');
      } catch (error) {
        if (error instanceof ConfigurationError) throw error;
        throw new ConfigurationError('Configured environment paths cannot be accessed.');
      }
      config[key]![index] = projectRelative(file);
    }
  }
  return config;
}
