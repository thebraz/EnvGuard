#!/usr/bin/env node
import { loadConfig } from './config.js';
import { initialize, projectRoot } from './project.js';
import { errorReport, report } from './report.js';
import { runChecks } from './scan.js';
import { EnvGuardError, SEVERITIES, VERSION, type Severity } from './types.js';

const HELP = `EnvGuard ${VERSION}
Usage: envguard <init|scan|validate|ci> [options]

  init        Create a minimal .envguard.json without changing environment files
  scan        Scan repository source, environment files, and Git configuration
  validate    Validate the runtime environment against templates and schema
  ci          Run scan and runtime validation without interaction

Options:
  --root <directory>    Project root (defaults to the current directory)
  --config <path>       Project-relative configuration file
  --format <text|json>  Output format (defaults to text)
  --fail-on <level>     info, warning, error, critical, or none
  --dotenv <path>       Explicit dotenv defaults for validate/ci only
  --help, -h           Show help
  --version, -v        Show version

Exit codes: 0 passed, 1 policy findings, 2 execution/configuration failure.
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let format: 'text' | 'json' = 'text';
  // Recognize JSON even when another argument is invalid, without echoing input.
  if (args.some((arg, index) => arg === '--format' && args[index + 1] === 'json')) format = 'json';
  try {
    let command: string | undefined;
    let rootInput = '.';
    let configFile: string | undefined;
    let envFile: string | undefined;
    let failOn: Severity | 'none' | undefined;
    let help = false;
    let version = false;
    const seen = new Set<string>();
    for (let index = 0; index < args.length; index++) {
      const arg = args[index]!;
      if (arg === '--help' || arg === '-h') { help = true; continue; }
      if (arg === '--version' || arg === '-v') { version = true; continue; }
      if (['--root', '--config', '--dotenv', '--format', '--fail-on'].includes(arg)) {
        if (seen.has(arg)) throw new Error('Duplicate CLI option.');
        seen.add(arg);
        const value = args[++index];
        if (!value || value.startsWith('--')) throw new Error('An option requires a value. Use --help for syntax.');
        if (arg === '--root') rootInput = value;
        if (arg === '--config') configFile = value;
        if (arg === '--dotenv') envFile = value;
        if (arg === '--format') {
          if (value !== 'text' && value !== 'json') throw new Error('Output format must be text or json.');
          format = value;
        }
        if (arg === '--fail-on') {
          if (![...SEVERITIES, 'none'].includes(value)) throw new Error('Failure threshold must be info, warning, error, critical, or none.');
          failOn = value as Severity | 'none';
        }
      } else if (['init', 'scan', 'validate', 'ci'].includes(arg) && !command) command = arg;
      else throw new Error('Unknown command or option. Use --help for syntax.');
    }
    if (version) { process.stdout.write(`${VERSION}\n`); return; }
    if (help || args.length === 0) { process.stdout.write(HELP); return; }
    if (!command) throw new Error('A command is required. Use --help for syntax.');
    if (envFile && command !== 'validate' && command !== 'ci') throw new Error('--dotenv is supported only by validate and ci.');
    if (command === 'init' && (configFile || envFile || failOn)) throw new Error('init accepts only --root and --format.');
    const root = await projectRoot(rootInput);
    if (command === 'init') {
      const status = await initialize(root);
      process.stdout.write(format === 'json' ? `${JSON.stringify({ version: VERSION, command, status, exitCode: 0 })}\n` : status === 'created' ? 'EnvGuard configuration created.\n' : 'EnvGuard configuration already exists; kept unchanged.\n');
      return;
    }
    const config = await loadConfig(root, configFile);
    if (failOn) config.failOn = failOn;
    const result = await runChecks(root, config, command as 'scan' | 'validate' | 'ci', process.env, envFile);
    process.stdout.write(report(result, format));
    process.exitCode = result.exitCode;
  } catch (error) {
    // Only our deliberately authored diagnostics are observable; OS/Git/AST errors never escape.
    const message = error instanceof EnvGuardError || (error instanceof Error && SAFE_ERRORS.has(error.message)) ? error.message : 'Execution failed. Check project paths, configuration, and filesystem permissions.';
    process.stderr.write(errorReport(message, format));
    process.exitCode = 2;
  }
}

const SAFE_ERRORS = new Set([
  'Duplicate CLI option.', 'An option requires a value. Use --help for syntax.',
  'Output format must be text or json.', 'Failure threshold must be info, warning, error, critical, or none.',
  'Unknown command or option. Use --help for syntax.', 'A command is required. Use --help for syntax.',
  '--dotenv is supported only by validate and ci.', 'init accepts only --root and --format.',
  'Project root must be an accessible directory.',
]);
await main();
