# Contributing

EnvGuard is a small local developer-security CLI. Keep changes focused on a concrete configuration or security problem. Prefer the Node standard library and the existing TypeScript parser over new runtime dependencies or extension frameworks.

Before changing behavior, read [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md), then run:

```sh
npm ci --ignore-scripts
npm run check
```

Preserve the command, rule-ID, JSON, and exit-code contracts. Separate input parsing/analysis from filesystem/Git boundaries and reporting. Never introduce telemetry, remote scanning, execution of repository code, or diagnostic output containing source/environment values.

Use fake values and temporary repositories for regressions. Security fixes need a check that demonstrates the original failure and verifies safe stdout/stderr/JSON after the fix. Avoid assertions, snapshots, or exception construction that would echo credential canaries. Document concrete limitations and policy changes without claiming universal credential detection.

Check `npm pack --dry-run` and the installation smoke gate when changing packaging, runtime dependencies, executable paths, or build output. Keep fixtures, environment files, caches, and local development artifacts outside the distribution.

Contributions are covered by the [MIT license](LICENSE). Report vulnerabilities using the private workflow described in [SECURITY.md](SECURITY.md). Maintainers handle npm publication, repository publication, tags, and releases separately from routine code changes.
