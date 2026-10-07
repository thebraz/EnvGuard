# Security

EnvGuard checks local environment configuration and selected secret patterns. It does not execute scanned source, expand dotenv expressions, contact external services, or collect telemetry. It is a preventive check, not a replacement for credential rotation, access controls, or a broader security review.

## Diagnostic confidentiality

EnvGuard findings must not intentionally disclose discovered secret values. Analysis holds candidate values only long enough to apply rules and protect metadata. Findings use fixed messages and never include source excerpts, raw parser errors, environment dumps, or secret-derived identifiers. A separate variable field can identify a bounded contract name after confidentiality checks. Text and JSON share the same sanitized findings. CLI errors expose only authored diagnostic messages; raw OS, Git, and parser exceptions are not printed.

Locations are project-relative. Paths matching detected sensitive candidates or recognized token-shaped names are replaced with `[redacted-path]`; paths containing control characters use `[unsafe-path]`. Variable names must be ASCII identifiers of at most 128 characters; names that fail validation or match sensitive candidates/token shapes use `[redacted-variable]`. Detection cannot prove an otherwise ordinary filename or arbitrary unknown string is a credential. Review report destinations and repository naming conventions when handling sensitive projects.

Runtime validation checks only variables named by the contract/schema/prohibited lists. Explicit `--dotenv` defaults are merged with runtime own properties locally; that merged object is never serialized. It does not load `.env` automatically. Use `--dotenv` only when intentionally providing local defaults, and avoid placing secrets in command arguments, committed configuration, suppression reasons, or CI examples.

## Untrusted input boundaries

- Project/configuration paths must remain within the selected root. Configured paths are literal and reject absolute paths, parent traversal, and symlink components. Discovery excludes symlinks and nested Git repositories.
- Candidate input, traversal, configuration, Git output, final finding assembly, and diagnostic metadata matching have bounded resource limits. Unreadable, binary, malformed, and oversized input produces controlled diagnostics or execution failure. Unexpected AST failures cannot pass through a below-threshold warning; configuration rejects special files before nonblocking/no-follow opening and validates the descriptor again.
- Git runs with an absolute host executable outside the target, argument arrays, and `shell: false`. Repository filenames are passed with NUL delimiters and preserve POSIX literal backslashes; they do not become shell commands or options. Injected Git environment, all system/global configuration, and filesystem monitors are excluded. Git owns its administrative/index/ignore resource resolution. Sensitive tracking checks use in-scope current index entries independently of working-tree file presence.
- Configuration accepts a fixed set of fields and stable rule IDs. Suppressions match an exact rule and optional exact file/line, require a reason, and are counted in reports. A pathless suppression intentionally covers the whole project; rule disabling is also counted.

The caller controls the target root and security policy. Review exclusions, disabled rules, severity overrides, and suppressions before treating a passing result as a CI security gate. A scan is not an immutable filesystem snapshot; avoid changing the target while checks run.

## Detection boundaries

Secret detection is heuristic and cannot guarantee detection of every credential. Selected token formats, private keys, URL credentials, sensitive assignments, weak defaults, and public secret-associated names receive checks. Random-looking strings alone do not become findings. Placeholders in templates receive different treatment from weak active secrets.

JS/TS environment discovery uses local AST scopes and simple const aliases. It does not perform arbitrary execution, cross-file data flow, decoding of every credential encoding, or complete analysis of assembled strings. Dynamic access is reported as unresolved and prevents unreliable unused-variable warnings. Git checks cover current tracking/ignore behavior, not historical commits. Excluded/ignored/generated files and other programming languages are outside the source-analysis scope.

If a credential has been committed or exposed, remove it from the tracked files and rotate/revoke it through the provider. Merely adding an ignore rule or obtaining a passing scan does not undo exposure.

## Reporting and release policy

The selected private reporting channel is [GitHub Security Advisories for thebraz/EnvGuard](https://github.com/thebraz/EnvGuard/security/advisories). Use **Report a vulnerability** when that private reporting option is available. Do not open a public issue containing vulnerability details or credentials. Prepare a minimal reproduction using fake values, affected versions, expected behavior, actual rule/exit status, and the tool version.

GitHub [supports private vulnerability reporting for public repositories](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately). Maintainers must enable and verify that workflow before a public release. No alternate private contact has been designated.

The package uses the MIT license, with copyright held by braz. Public release requires a passing verification/security gate, confirmed npm publishing access, and an operational private reporting channel. Package metadata alone does not establish npm ownership or prove that publication has occurred.
