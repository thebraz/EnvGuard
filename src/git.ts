import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { access, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { EnvGuardError } from './types.js';

export interface GitInspection {
  status: 'available' | 'missing' | 'not-repository';
  tracked: Set<string>;
  ignored: Set<string>;
}

interface GitOutput { code: number; stdout: Buffer; stderr: Buffer }
class GitUnavailable extends EnvGuardError {}
const MAX_OUTPUT = 8 * 1024 * 1024;

function inside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

async function gitExecutable(root: string): Promise<string> {
  let canonicalRoot: string;
  try { canonicalRoot = await realpath(root); }
  catch { throw new EnvGuardError('Git inspection requires an accessible project root.'); }
  // Windows searches cwd before PATH for bare executable names; never execute repository content.
  for (const entry of (process.env.PATH ?? '').split(path.delimiter)) {
    const directory = entry.replace(/^"(.*)"$/u, '$1');
    if (!path.isAbsolute(directory)) continue;
    try {
      const candidate = await realpath(path.join(directory, process.platform === 'win32' ? 'git.exe' : 'git'));
      if (inside(canonicalRoot, candidate) || !(await stat(candidate)).isFile()) continue;
      await access(candidate, constants.X_OK);
      return candidate;
    } catch { /* An inaccessible PATH candidate cannot supply Git. */ }
  }
  throw new GitUnavailable('Git is unavailable.');
}

async function git(root: string, args: string[], input?: Buffer): Promise<GitOutput> {
  const executable = await gitExecutable(root);
  return new Promise((resolve, reject) => {
    // Exclude GIT_DIR, GIT_WORK_TREE, injected config and global fsmonitor hooks.
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      LC_ALL: 'C', LANG: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    };
    const child = spawn(executable, ['--no-optional-locks', '-c', 'core.fsmonitor=false', ...args], { cwd: root, shell: false, windowsHide: true, env, stdio: ['pipe', 'pipe', 'pipe'] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let failure: Error | undefined;
    const stop = (message: string) => { failure = new EnvGuardError(message); child.kill(); };
    const timer = setTimeout(() => stop('Git inspection exceeded its time limit.'), 10_000);
    const collect = (target: Buffer[], chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT) stop('Git inspection exceeded its output limit.');
      else target.push(chunk);
    };
    child.stdout.on('data', (chunk: Buffer) => collect(stdout, chunk));
    child.stderr.on('data', (chunk: Buffer) => collect(stderr, chunk));
    child.stdin.on('error', () => { /* A failed command may close stdin before consuming paths. */ });
    child.on('error', (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(error.code === 'ENOENT' ? new GitUnavailable('Git is unavailable.') : new EnvGuardError('Git inspection could not start.'));
    });
    child.on('close', code => {
      clearTimeout(timer);
      if (failure) reject(failure);
      else if (code === null) reject(new EnvGuardError('Git inspection did not complete.'));
      else resolve({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    });
    child.stdin.end(input);
  });
}

function checkedPaths(paths: string[]): string[] {
  if (paths.length > 100_000) throw new EnvGuardError('Git inspection received too many paths.');
  const result = paths.map(value => {
    if (typeof value !== 'string' || value.length === 0 || value.length > 4096 || value.includes('\0') || path.isAbsolute(value) || (process.platform === 'win32' && /^[A-Za-z]:/u.test(value))) throw new EnvGuardError('Git inspection requires relative project paths.');
    const normalized = process.platform === 'win32' ? value.replaceAll('\\', '/') : value;
    if (normalized.split('/').includes('..')) throw new EnvGuardError('Git inspection paths must remain within the project.');
    return path.posix.normalize(normalized);
  });
  if (Buffer.byteLength(result.join('\0')) > MAX_OUTPUT) throw new EnvGuardError('Git inspection received too many path bytes.');
  return [...new Set(result)];
}

function nullPaths(buffer: Buffer): Set<string> {
  return new Set(buffer.toString('utf8').split('\0').filter(Boolean));
}

async function checkIgnored(root: string, paths: string[]): Promise<Set<string>> {
  if (paths.length === 0) return new Set();
  const result = await git(root, ['check-ignore', '--no-index', '-z', '--stdin'], Buffer.from(`${paths.join('\0')}\0`));
  if (result.code !== 0 && result.code !== 1) throw new EnvGuardError('Git ignore inspection failed.');
  const requested = new Set(paths);
  return new Set([...nullPaths(result.stdout)].filter(value => requested.has(value)));
}

export async function inspectGit(root: string, paths: string[]): Promise<GitInspection> {
  const requested = checkedPaths(paths);
  const empty = { tracked: new Set<string>(), ignored: new Set<string>() };
  let repository: GitOutput;
  try { repository = await git(root, ['rev-parse', '--is-inside-work-tree']); }
  catch (error) {
    if (error instanceof GitUnavailable) return { status: 'missing', ...empty };
    throw error;
  }
  if (repository.code === 128 && repository.stderr.toString('utf8').startsWith('fatal: not a git repository')) return { status: 'not-repository', ...empty };
  if (repository.code !== 0) throw new EnvGuardError('Git repository inspection failed.');
  if (repository.stdout.toString('utf8').trim() !== 'true') return { status: 'not-repository', ...empty };
  const tracked = await git(root, ['ls-files', '-z']);
  if (tracked.code !== 0) throw new EnvGuardError('Git tracked-file inspection failed.');
  const trackedPaths = checkedPaths([...nullPaths(tracked.stdout)]);
  return { status: 'available', tracked: new Set(trackedPaths), ignored: await checkIgnored(root, requested) };
}

export async function ignoredPaths(root: string, paths: string[]): Promise<Set<string>> {
  return checkIgnored(root, checkedPaths(paths));
}
