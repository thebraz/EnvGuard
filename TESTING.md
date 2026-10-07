# Testing

Requires Node.js 22+ and npm. Install the locked dependencies without lifecycle scripts:

```sh
npm ci --ignore-scripts
npm run check
```

`check` runs TypeScript type checking, compiler-based lint diagnostics, built unit/integration tests, and packed-package verification. `lint` uses unused-symbol/parameter and switch-fallthrough diagnostics; the project does not install ESLint or a separate test framework.

| Command | Verification |
| --- | --- |
| `npm run typecheck` | Strict TypeScript compilation without emission. |
| `npm run lint` | Compiler unused/fallthrough diagnostics. |
| `npm run build` | Remove previous generated output, then build the ESM CLI and modules into `dist`. |
| `npm test` | Build, then run `node:test` unit and subprocess integration tests. |
| `npm run test:package` | Pack, inspect, install into a temporary project, and execute the installed CLI. |
| `npm pack --dry-run` | Inspect the proposed distributed file list. |

## Test design

Tests create temporary repositories and use synthetic values. CLI subprocesses receive controlled environments; tests do not depend on a developer's deployment variables or `.env`. Git tests use local fixture repositories without commits or remote operations. Symlink tests may skip when the operating system does not permit creating them.

Coverage includes dotenv quoting/escapes/multiline/BOM/duplicates/conflicts/malformed input; JS/TS static access, aliases, shadowing and dynamic access; known secret formats, public names, placeholders and harmless identifiers; configuration/path validation; Git tracking and effective ignore behavior; runtime schemas; exclusions and resource limits; reporter parity; and exact exit codes.

Initialization regressions cover mixed source layouts, effective Git ignore rules, and conventional environment files/templates added after initialization. A real Git fixture verifies that a later tracked environment variant still fails a critical-only gate.

Secret canaries are fake credentials. Tests assert they cannot appear in observable stdout, stderr, serialized findings, unsafe path metadata, or controlled error output. Add a regression whenever a discovered leak/bypass can be reproduced deterministically. Assertions must not print candidate credential contents when they fail.

Adversarial regressions cover malformed/invalid UTF-8 percent escapes, decoded YAML/TOML scalar values, short undeclared explicit dotenv defaults, unexpected deep AST failures, diverse-length metadata amplification, current index entries missing on disk, aggregate final-assembly limits, POSIX configuration FIFOs, and literal POSIX backslash filenames.

`tests/hardening.test.mjs` adds isolated lexical-spelling disclosure attempts, composed percent/escape forms, JS/YAML dialect collisions, leading-zero Unicode braces and Unicode continuations; private-key body/compact/CR/whitespace/incomplete/PGP-checksum forms; native providers and mocks; complete fallback branches and benign conditions; real Git case-only renames and distinct-case controls; 100,000 nested-directory entries; and filesystem-call counts preventing case-alias work amplification. Platform-specific tests must pass on their owning OS; Windows and Linux complement each other. The directory stress fixture uses bounded batches of hard links to empty seed files.

## Packed executable gate

The package smoke test verifies the distribution itself rather than relying on source-tree resolution. It verifies removal of an obsolete generated module, builds/packs EnvGuard, checks the exact archive file list and relative documentation links, and installs the archive into a disposable project outside the checkout. Every CLI command uses the installed npm executable shim, including help/version, command help, idempotent initialization, scan/text and JSON, runtime validation, explicit dotenv defaults, CI, invalid arguments, and policy/execution failures. The installed manifest, CLI version, and JSON version must agree. A failed install, missing runtime file, secret leak, or incorrect exit status fails the gate.

Published contents are limited by `package.json` to compiled JavaScript, README, security, architecture, testing, contribution and changelog documents, the MIT license, and npm's required package metadata. Tests, fixture credentials, source tooling, local environment files, caches, temporary archives, and internal development files must not enter the artifact.

The workflow tests Node.js 22 on Ubuntu and Windows, and Node.js 24 on Ubuntu. Each job has a 15-minute timeout and runs the complete check, including all canary regressions and packed installation. A configured workflow is not evidence that hosted CI has run; review its actual results separately. Local verification also does not establish npm publishing access.
