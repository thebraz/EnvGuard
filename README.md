# EnvGuard

EnvGuard is a deterministic, local-first CLI for environment configuration checks and secret detection in JavaScript and TypeScript projects. It compares source usage with an environment contract, validates deployment variables, and checks whether sensitive environment files are tracked or effectively ignored by Git.

It runs locally without telemetry, remote APIs, accounts, or AI services. Secret detection uses known formats and assignment context; it cannot detect every credential.

## Install

Requires Node.js 22 or newer; the verification matrix uses the [supported Node.js 22 and 24 release lines](https://github.com/nodejs/Release). The parser/compiler dependency is [TypeScript 6](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-6-0.html).

```sh
npm install --save-dev envguard
npx envguard init
npx envguard scan
```

To build and install a local checkout instead:

```sh
npm ci --ignore-scripts
npm run check
npm pack
# In the project you want to check:
npm install --save-dev /path/to/envguard-0.1.0.tgz
```

`init` detects common source directories using effective Git ignore rules, then creates `.envguard.json`. Mixed layouts with source or environment files outside those directories use the project root. Conventional environment files and templates remain automatically discoverable when added later; initialization does not freeze a list of current filenames. It preserves existing configuration and never edits `.env` files. Review the generated include paths before using the tool as a security gate.

## Quick start

In the project where the package is installed, create an environment template `.env.example`:

```dotenv
API_URL=
```

Use that variable in `app.ts`:

```ts
const apiUrl = process.env.API_URL;
```

For this example, create `.env.local` with a public, non-credential value:

```dotenv
API_URL=https://example.invalid
```

```sh
npx envguard init
npx envguard scan
npx envguard validate --dotenv .env.local
npx envguard ci --dotenv .env.local
```

Each command exits with `0` for this example. In a Git repository, keep local environment files untracked and ignored; commit the template with empty values. Real deployment values belong in the deployment environment or an intentionally selected local file.

## Commands

| Command | Behavior |
| --- | --- |
| `init` | Create a minimal configuration; repeated execution preserves the existing file. |
| `scan` | Check source usage, templates, environment files, hardcoded secrets, and Git tracking/ignore behavior. |
| `validate` | Check the active process environment against templates, required/prohibited variables, and schema. |
| `ci` | Combine `scan` and runtime validation without interaction. |

```sh
npx envguard scan --format json
npx envguard scan --root ./service --fail-on warning
npx envguard validate --dotenv .env.local
npx envguard ci --format json
npx envguard --help
npx envguard --version
```

`validate` does not load `.env` automatically. `--dotenv` explicitly supplies dotenv defaults for `validate` or `ci`; runtime variables take precedence, including an explicitly empty runtime value. Template values never supply runtime defaults. Every template variable is required unless its schema sets `required: false`; the explicit `required` list takes precedence.

Options are `--root`, `--config`, `--format text|json`, `--fail-on info|warning|error|critical|none`, and `--dotenv`. Configuration and environment-file paths are relative to the selected project root. `init` accepts only `--root` and `--format`, plus help/version options.

## Findings and exit codes

```text
ERROR env/missing
src/database.ts:12
DATABASE_URL
An environment variable used in source is absent from the environment contract.

CRITICAL secret/public-exposure
src/client.ts:8
A sensitive environment variable is exposed through a public client prefix.
```

Messages omit source snippets and values. Missing/unused/runtime-contract findings identify the affected variable separately when its name is a bounded identifier. Names and paths that match sensitive candidates or recognized token shapes are replaced with opaque markers. Runtime validation does not require a source location.

| Exit code | Meaning |
| --- | --- |
| `0` | No remaining finding meets the failure threshold. |
| `1` | At least one finding meets the failure threshold. |
| `2` | Invalid arguments/configuration, inaccessible project paths, or another execution failure. |

The default threshold is `error`. Severity order is `info`, `warning`, `error`, `critical`; `--fail-on none` keeps findings visible while disabling policy failure. It does not suppress execution failures.

For `scan`, `validate`, and `ci`, JSON contains `version`, `command`, severity `summary`, canonical `findings`, `suppressed`, `disabled`, `filesScanned`, and `exitCode`. Findings contain `ruleId`, `severity`, `message`, and optional sanitized `variable`/`location` metadata. `init` returns `version`, `command`, `status`, and `exitCode`. Execution failures write a separate `{ "error": { "code": "execution-error", "message": "..." }, "exitCode": 2 }` object to stderr. Text and JSON use the same findings.

## Configuration

Without `.envguard.json`, EnvGuard uses defaults and discovers environment files. A minimal explicit configuration for a project with a `src` directory:

```json
{
  "include": ["src"],
  "exclude": ["src/generated"],
  "templateFiles": [".env.example"],
  "required": ["API_URL"],
  "failOn": "error"
}
```

Policy options can be added when needed:

```json
{
  "rules": { "env/unused": true },
  "severity": { "env/unused": "info" },
  "suppressions": [
    {
      "ruleId": "env/unused",
      "path": ".env.example",
      "reason": "Used by the external deployment process"
    }
  ]
}
```

Paths are literal project-relative file or directory prefixes, **not globs**. `include` defaults to `["."]`; `exclude` defaults to `[]`. Include paths and selected environment/template files must exist; exclusion and suppression paths may name files that do not exist yet. Parent traversal, absolute paths, and symlink components are rejected. Unknown configuration keys/rule IDs, invalid types, duplicate list entries, conflicting required/prohibited declarations, and duplicate suppression scopes fail with exit code `2`.

Omitted `templateFiles` and `envFiles` use conventional automatic discovery within the selected scope. Explicit lists replace automatic selection, including an empty list, and intentionally selected environment/template files remain eligible despite discovery exclusions.

Schema supports only `required`, `type`, and `minLength`. Number values must convert to a finite number; booleans must be exactly `true` or `false`; URLs must have a protocol and hostname. Schema entries are optional unless required by a template, the explicit list, or `required: true`.

For example, `"schema": { "API_URL": { "type": "url" }, "PORT": { "type": "number" }, "FEATURE_ENABLED": { "type": "boolean", "required": false } }` checks those types. `prohibited` lists variables that must be absent from the active runtime environment.

`rules` disables a rule with `false`; `severity` changes its severity. Suppressions require a reason and match an exact rule ID, optionally an exact path and line. A line requires a path. Omit the path only when intentionally suppressing that rule throughout the project. Reports count suppressed and disabled findings. [Architecture](ARCHITECTURE.md) lists the stable rule IDs.

## Supported analysis

JavaScript/TypeScript discovery uses the TypeScript AST, including JSX/TSX:

```ts
process.env.DATABASE_URL
process.env["DATABASE_URL"]
process.env[`DATABASE_URL`]
process["env"]["DATABASE_URL"]
global.process.env.DATABASE_URL
process?.env?.DATABASE_URL
const { DATABASE_URL: databaseUrl } = process.env
const env = process.env
env.DATABASE_URL
import.meta.env.VITE_API_URL
import { env as settings } from "node:process"
settings.DATABASE_URL
const native = require("node:process")
native.env.DATABASE_URL
```

Local bindings and parameters that shadow `process`, `global`, or an alias are respected. Dynamic keys, environment-object escapes, and destructuring spreads produce `env/dynamic`; dynamic access disables speculative `env/unused` findings for that scan. `process.env.NODE_ENV` and the `import.meta.env` builtins `DEV`, `PROD`, `MODE`, `SSR`, and `BASE_URL` do not require contract entries. The same names through another provider are checked normally.

Runtime imports from `process`/`node:process` support default, namespace (including `.default`), named `env`, and import-equals forms. Unshadowed literal `require` calls and simple const aliases also resolve; mock and type-only imports stay excluded. Complete literal values in `||`, `??`, and conditional result branches retain sensitive assignment context. Conditions, arbitrary calls, and assembled-string fragments are not evaluated.

Dotenv parsing supports comments, whitespace, `export`, empty values, BOM, LF/CRLF, single/double/backtick quotes, supported escapes, and quoted multiline values. It reports duplicates, conflicts, and malformed definitions without quoting their contents. It does not expand `${VARIABLE}` references or execute shell expressions.

Secret checks recognize selected token formats, private-key blocks, URL credentials, sensitive literal assignments, weak/default values, and sensitive public names such as `NEXT_PUBLIC_JWT_SECRET`. Public URLs/IDs are not flagged merely for using `NEXT_PUBLIC_`, `VITE_`, or `REACT_APP_`. Arbitrary high entropy alone is not a finding.

## Scope and limitations

- Source discovery covers JS/TS only; there is no cross-file data-flow analysis, arbitrary computed-key evaluation, or runtime execution. Simple const aliases are supported; mutable aliases and escaped environment objects cannot be fully resolved.
- Known formats are checked in decoded JS/TS and JSON string literals, including escaped characters. Sensitive simple YAML/TOML scalar assignments also decode quoted escapes; YAML doubled apostrophes and TOML literal strings retain their format semantics. Other encodings, assembled strings, YAML/TOML multiline assignments, other languages, and unsupported formats can escape detection.
- Git checks inspect current index entries even when their working-tree files are absent, within selected scope. Templates are exempt from sensitive-file tracking rules. Ignore checks use Git with system/global configuration disabled and filesystem monitors disabled; put required ignore rules in the repository. Commit history is outside scope. Without Git or outside a repository, other checks run and `git/unavailable` is informational.
- Dependency/vendor/cache directories, common build outputs, lockfiles, source maps, minified bundles, nested Git repositories, and symlinks are excluded. Ignored ordinary source files are skipped; environment files remain eligible for safety checks.
- Candidate text is limited to 1 MiB per file, 64 MiB total, 25,000 files, 100,000 directory entries, and directory depth 64. Entries are counted during iteration before sorting or excluding a nested repository. Binary/invalid UTF-8/oversized candidates report `scan/skipped`; global limits cause execution failure. Narrow include paths for large projects.
- Dotenv files allow at most 10,000 definitions and 10,000 parser findings. Source analysis limits each file to 100,000 AST nodes and 20,000 usages, assignments, or decoded literals. Secret analysis caps per-file findings and candidates at 20,000; aggregate analysis caps findings and contract/usage keys at 25,000 and candidate entries at 100,000. Exceeding a record limit returns exit code `2` with a controlled diagnostic.
- Unexpected parser failures and metadata matching-budget exhaustion also return exit `2`, even with `--fail-on none`. Malformed or excessively encoded filename metadata is conservatively hidden.

Diagnostic metadata checks percent and literal escape representations before either reporter runs, including differing JS and structured-data escape semantics. Private-key material lines and compact bodies remain internal redaction candidates. Explicit environment selections are matched to Git's original index names through existing-file identity, preserving distinct files on case-sensitive filesystems.

## CI and development

Provide required runtime variables through the deployment environment, then run:

```sh
npx envguard ci --format json
```

Never place credential values in command arguments or committed workflow files. Policy configuration determines which findings fail CI; review exclusions and suppressions as part of that policy.

```sh
npm run typecheck
npm run lint
npm test
npm run test:package
npm run check
```

Tests use Node's built-in runner and temporary repositories with fake values. The package smoke test packs the artifact, installs it into a temporary project, and exercises the installed executable. [Testing](TESTING.md) describes verification; [Security](SECURITY.md) describes guarantees and boundaries.

## License and reporting

[MIT](LICENSE), copyright 2026 braz. The repository is [thebraz/EnvGuard](https://github.com/thebraz/EnvGuard). See [Security](SECURITY.md) for the selected private reporting workflow and its current availability. Publishing to npm is a separate maintainer action.
