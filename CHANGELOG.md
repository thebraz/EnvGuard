# Changelog

## 0.1.1 — 2026-10-07

- Publish as `@thebraz/envguard` because the npm registry rejects `envguard` as too similar to the existing `env-guard` package; retain the `envguard` command and braz authorship.
- Align installation documentation and packed-package verification with the scoped package.
- Preserve the previously published GitHub `v0.1.0` tag and release.

## 0.1.0 — 2026-10-07

- Add local `init`, `scan`, `validate`, and `ci` commands with text/JSON reports and stable policy/execution exit codes.
- Parse dotenv definitions, detect duplicates/conflicts/malformed input, and discover JS/TS environment usage through AST analysis with lexical shadowing and const aliases.
- Detect selected hardcoded credentials, private keys, URL credentials, weak defaults, and sensitive client-visible configuration.
- Validate runtime required/prohibited variables and a small schema; support explicit dotenv defaults without automatic `.env` loading.
- Inspect Git tracking/effective ignore rules, constrain project traversal and candidate input, and count explicit suppressions/disabled findings.
- Keep initialization aware of effective Git ignores and mixed source layouts, without freezing conventional environment/template filenames.
- Add deterministic temporary-fixture tests, secret-disclosure regressions, packed executable verification, and a limited Node.js/OS CI matrix.
- Harden encoded-path/structured-value confidentiality, short explicit dotenv defaults, unexpected AST failures, configuration special files, metadata work budgets, and current-index tracking across missing files and POSIX filename forms.
- Protect literal escape spellings and private-key bodies in diagnostic metadata, stream bounded directory enumeration, preserve Git index identity across case-only renames, and resolve native process providers and contextual literal fallbacks.
- Prepare MIT licensing and repository metadata, clean obsolete build output, include linked engineering documents, and verify the installed executable and version against package metadata.
