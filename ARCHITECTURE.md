# Architecture

EnvGuard is an ESM TypeScript CLI targeting Node.js 22+. Its only runtime dependency is TypeScript, used to parse JavaScript/TypeScript without executing project code. Filesystem access and Git inspection use Node's standard library. Analysis remains local and deterministic for the same project contents, runtime inputs, and policy.

## Boundaries

| Module | Responsibility |
| --- | --- |
| `cli.ts` | Parse arguments, select the command, write the report, and set the process exit status. |
| `config.ts` | Validate the small JSON policy and resolve literal paths within the project. |
| `project.ts` | Initialize configuration, discover candidate files, apply traversal exclusions, and read bounded UTF-8 input. |
| `dotenv.ts` | Parse definitions and produce value-free syntax/duplicate/conflict findings. |
| `source.ts` | Discover JS/TS environment usage with AST lexical scopes and extract decoded contextual literals. |
| `secrets.ts` | Detect known token/private-key/URL formats and sensitive assignments/defaults. |
| `git.ts` | Inspect Git tracking and effective ignore behavior with argument-array subprocesses. |
| `scan.ts` | Build the environment contract, combine static/runtime analysis, apply policy, and sanitize diagnostic metadata. |
| `report.ts` | Format the same canonical result as text or JSON. |
| `types.ts` | Define rule IDs, severity, configuration, locations, and public report shapes. |

There are no plugin registries, remote services, filesystem mutations during checks, or duplicate reporter-specific analysis paths. `init` writes only its new configuration file, using exclusive creation.

Initialization infers common source roots from discovered nonignored JS/TS files. If existing source or conventional environment files lie outside those roots, it uses the project root instead of dropping them. Its generated configuration leaves conventional dotenv/template discovery enabled, so later files remain eligible; explicit file lists remain an operator choice. Git absence does not prevent initialization.

## Data flow

`scan` discovers candidates, obtains Git metadata, reads allowed text, parses environment definitions/source usage, and runs secret rules. Template definitions plus explicit required/schema names form the static environment contract. Usage absent from that contract produces `env/missing`. A template definition with no usage produces `env/unused` only when JS/TS source exists and no unresolved dynamic environment access was discovered.

`validate` reads templates to establish required names and validates the supplied runtime object. It does not use template values or automatically load a real `.env` file. An explicitly selected `--dotenv` provides defaults; runtime entries override them. Templates are required unless schema declares an optional variable, while the explicit required list retains precedence. Schema rules cover finite numbers, exact boolean literals, URLs with a protocol/hostname, and minimum string length.

`ci` combines both paths, then applies the policy once. Disabled rules and exact rule/path/line suppressions are counted, severity overrides applied, duplicate findings removed, and findings sorted by location/rule/message. The selected severity threshold determines exit `0` or `1`; controlled execution/configuration failures use exit `2`.

Candidate source strings, dotenv values, and runtime values remain inside analysis. Findings contain fixed diagnostic messages, stable IDs, severity, and optional variable/location metadata; they never contain raw values. Variable names are restricted to bounded identifiers. Names or paths matching sensitive candidates/token shapes become opaque markers before formatting. Both reporters consume only the canonical sanitized report.

Metadata normalization compares original and intermediate percent/escape spellings, with bounded independent JS and structured-data interpretations. It never rewrites a safe filename's identity. Private-key candidates include the bounded full armor, material lines, and compact body, including CR-only and whitespace forms; no key material reaches reporters. Native process imports/require aliases reuse AST lexical scopes, and complete fallback/conditional value branches reuse contextual literal extraction.

## Stable rules

| Rule ID | Meaning | Default severity |
| --- | --- | --- |
| `env/missing` | Static source usage is absent from the contract. | error |
| `env/unused` | A template variable has no discovered static consumer. | warning |
| `env/duplicate` | A dotenv variable appears more than once. | warning |
| `env/conflict` | Repeated definitions or template defaults disagree. | error; warning between templates |
| `env/malformed` | A dotenv definition is malformed. | error |
| `env/dynamic` | An environment access/escape cannot be resolved statically. | info |
| `env/source-syntax` | Source cannot be fully parsed. | warning |
| `env/required` | A required definition or runtime variable is missing/empty. | error |
| `env/schema` | Runtime data violates its schema. | error |
| `env/prohibited` | A prohibited runtime variable is present. | error |
| `secret/hardcoded-token` | A selected known credential format appears. | critical; warning for contextual cloud access identifiers |
| `secret/private-key` | Private-key material appears. | critical |
| `secret/credentials-url` | A URL embeds credentials. | error |
| `secret/hardcoded` | A literal is assigned to a sensitive name. | error |
| `secret/weak` | Sensitive configuration uses a weak/default value. | error |
| `secret/public-exposure` | A client-visible name suggests sensitive configuration. | critical |
| `git/env-tracked` | A sensitive environment file is tracked. | critical |
| `git/env-not-ignored` | A sensitive environment file is not effectively ignored. | error |
| `git/unavailable` | Git is missing or the directory is not a work tree. | info |
| `scan/skipped` | A nested repository, symlink, binary, unreadable, or oversized candidate is skipped. | info, warning, or error by reason |

Rule IDs and JSON fields are integration contracts. Change them deliberately and document incompatible behavior.

## Operational limits

Configuration files are capped at 64 KiB, and configuration lists/maps at 256 entries. Candidate input is capped at 1 MiB per file, 64 MiB total, 25,000 candidate files, 100,000 directory entries, and depth 64. Oversized/read failures produce error findings; aggregate traversal/input limits stop execution. Git subprocesses have a 10-second timeout, an 8 MiB combined output/input-path limit, and at most 100,000 validated paths.

Directory iteration uses `opendir`, counts each consumed entry before retaining it, and sorts only the bounded collection. Nested repository entries consume the same budget. Explicit Git selections are canonicalized once; each potentially aliased index path is resolved at most once, preventing a selection-by-index filesystem cross-product. Actual canonical identity decides a match; case folding only selects candidates.

Dotenv permits 10,000 definitions/findings per file. Source analysis permits 100,000 AST nodes and 20,000 usages, assignments, or decoded literals per file. Secret analysis permits 20,000 findings/candidates per file. Analysis and final assembly enforce 25,000 findings/contract/usage keys and 100,000 candidate entries. Metadata substring matching shares a 64×1,024×1,024 character work budget; exhaustion returns a fixed execution error rather than bypassing redaction. Unexpected parser/traversal exceptions also fail execution safely.

Symlinks are excluded; configured paths reject symlink components and traversal outside the root. Configuration rejects nonregular files before opening with nonblocking/no-follow flags where supported, then checks descriptor type/size. Discovery skips dependency/vendor/cache directories, build outputs, nested Git repositories, lockfiles, minified bundles, and source maps. Git uses exact platform-appropriate NUL-delimited paths and its own ignore engine with system/global configuration disabled. Ignored ordinary candidates are omitted; environment files remain available for security checks. In-scope current index environment entries are also checked when absent from disk; they are not loaded as text. Explicit environment lists (including an empty list) replace conventional selection and override discovery exclusions for the selected files; they remain operator-owned policy within the root boundary.

Static analysis intentionally stops at local JS/TS syntax and simple const aliases. Unsupported/dynamic access is an explicit limitation, not an inferred variable name. Secret rules combine known formats and sensitive context rather than classifying arbitrary entropy. [SECURITY.md](SECURITY.md) records the corresponding trust boundaries.
