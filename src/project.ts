import type { Dirent } from 'node:fs';
import { lstat, opendir, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Config, Finding } from './types.js';
import { validateConfig } from './config.js';
import { inspectGit } from './git.js';

export const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 25000;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt', '.cache', '.npm-cache', '.turbo', 'vendor', 'bower_components']);
const TEXT_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.config', '.txt', '.md']);
const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb']);
export const isSourceFile = (file: string): boolean => /\.(?:[cm]?[jt]s|[jt]sx)$/i.test(file);
export const isTemplateFile = (file: string): boolean => /(?:^|\.)env(?:\.[^.]+)*\.(?:example|sample|template)$/i.test(path.posix.basename(file));
export const isEnvFile = (file: string): boolean => /^\.env(?:\..+)?$/i.test(path.posix.basename(file)) || /\.env$/i.test(file) || isTemplateFile(file);
const within = (file: string, prefix: string): boolean => prefix === '.' || file === prefix || file.startsWith(`${prefix}/`);

export async function projectRoot(input: string): Promise<string> {
  try {
    const resolved = await realpath(path.resolve(input));
    if (!(await lstat(resolved)).isDirectory()) throw new Error();
    return resolved;
  } catch { throw new Error('Project root must be an accessible directory.'); }
}

export async function discoverFiles(root: string, config: Pick<Config, 'include' | 'exclude' | 'envFiles' | 'templateFiles'>): Promise<{ files: string[]; findings: Finding[]; nestedRepositories: string[] }> {
  const files: string[] = [];
  const findings: Finding[] = [];
  const nestedRepositories: string[] = [];
  let entriesSeen = 0;
  const requested = [...config.include, ...(config.envFiles ?? []), ...(config.templateFiles ?? [])];
  async function walk(relative: string, depth: number): Promise<void> {
    if (depth > 64) throw new Error('Project directory depth exceeds the scan limit.');
    const absolute = path.join(root, relative);
    const entries: Dirent[] = [];
    try {
      for await (const entry of await opendir(absolute)) {
        if (++entriesSeen > MAX_FILES * 4) throw new Error('Project entry count exceeds the scan limit. Narrow the include paths.');
        entries.push(entry);
      }
    } catch (error) {
      if (entriesSeen > MAX_FILES * 4) throw error;
      throw new Error('A project directory could not be read. Check filesystem permissions.');
    }
    entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    const nestedGit = relative !== '' && entries.some(entry => entry.name === '.git');
    if (nestedGit) {
      nestedRepositories.push(relative);
      findings.push({ ruleId: 'scan/skipped', severity: 'info', message: 'A nested Git repository was excluded from the scan.', location: { path: relative } });
      return;
    }
    for (const entry of entries) {
      const file = relative ? `${relative}/${entry.name}` : entry.name;
      if (config.exclude.some(prefix => within(file, prefix))) continue;
      if (entry.isSymbolicLink()) {
        findings.push({ ruleId: 'scan/skipped', severity: 'warning', message: 'A symbolic link was excluded from the scan.', location: { path: file } });
        continue;
      }
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && requested.some(prefix => within(file, prefix) || within(prefix, file))) await walk(file, depth + 1);
      } else if (entry.isFile()) {
        if (LOCKFILES.has(entry.name) || /(?:\.min\.[jt]s|\.map)$/i.test(entry.name) || file === '.envguard.json') continue;
        if (isEnvFile(file) || TEXT_EXTENSIONS.has(path.extname(file).toLowerCase())) {
          files.push(file);
          if (files.length > MAX_FILES) throw new Error('Project file count exceeds the scan limit. Narrow the include paths.');
        }
      }
    }
  }
  await walk('', 0);
  return { files, findings, nestedRepositories };
}

export async function readProjectText(root: string, files: string[]): Promise<{ texts: Map<string, string>; findings: Finding[] }> {
  const texts = new Map<string, string>();
  const findings: Finding[] = [];
  let totalBytes = 0;
  for (const file of files) {
    try {
      const absolute = path.join(root, file);
      const info = await lstat(absolute);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error();
      if (info.size > MAX_FILE_BYTES) {
        findings.push({ ruleId: 'scan/skipped', severity: 'error', message: 'A candidate file exceeds the one MiB scan limit.', location: { path: file } });
        continue;
      }
      totalBytes += info.size;
      if (totalBytes > MAX_TOTAL_BYTES) throw new Error('resource-limit');
      const buffer = await readFile(absolute);
      if (buffer.length > MAX_FILE_BYTES) throw new Error();
      const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
      if (text.includes('\0') && !isEnvFile(file)) {
        findings.push({ ruleId: 'scan/skipped', severity: 'warning', message: 'A binary candidate file was excluded.', location: { path: file } });
        continue;
      }
      texts.set(file, text);
    } catch {
      if (totalBytes > MAX_TOTAL_BYTES) throw new Error('Project text size exceeds the scan limit. Narrow the include paths.');
      findings.push({ ruleId: 'scan/skipped', severity: 'error', message: 'A candidate file could not be read as UTF-8 text.', location: { path: file } });
    }
  }
  return { texts, findings };
}

export async function initialize(root: string): Promise<'created' | 'exists'> {
  const target = path.join(root, '.envguard.json');
  try { await lstat(target); return 'exists'; } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('Configuration location is inaccessible.');
  }
  const { files } = await discoverFiles(root, { include: ['.'], exclude: [] });
  const git = await inspectGit(root, files);
  const sourceFiles = files.filter(file => isSourceFile(file) && !git.ignored.has(file));
  const roots: string[] = [];
  for (const candidate of ['src', 'app', 'pages', 'lib', 'server', 'scripts']) {
    if (sourceFiles.some(file => file.startsWith(`${candidate}/`))) roots.push(candidate);
  }
  const needsRoot = [...sourceFiles, ...files.filter(isEnvFile)].some(file => file.includes('/')
    ? !roots.some(prefix => file.startsWith(`${prefix}/`))
    : isSourceFile(file));
  // Keep conventional discovery live instead of freezing the files present at init.
  const config = { include: needsRoot || roots.length === 0 ? ['.'] : roots, failOn: 'error' };
  validateConfig(config);
  try { await writeFile(target, `${JSON.stringify(config, null, 2)}\n`, { flag: 'wx', mode: 0o600 }); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return 'exists';
    throw new Error('Configuration could not be created. Check filesystem permissions.');
  }
  return 'created';
}

export function included(file: string, config: Config): boolean {
  return config.include.some(prefix => within(file, prefix)) && !config.exclude.some(prefix => within(file, prefix));
}

/** Match conventional environment discovery without requiring an index entry to exist on disk. */
export function environmentInScope(file: string, config: Config): boolean {
  if (!isEnvFile(file) || isTemplateFile(file) || config.exclude.some(prefix => within(file, prefix))) return false;
  if (file.split('/').slice(0, -1).some(component => SKIP_DIRS.has(component))) return false;
  const directory = path.posix.dirname(file);
  const requested = [...config.include, ...(config.templateFiles ?? [])];
  return directory === '.' || requested.some(prefix => within(directory, prefix) || within(prefix, directory));
}
