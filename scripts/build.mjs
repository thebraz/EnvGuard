import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('../', import.meta.url)));
const output = path.resolve(root, 'dist');
assert.ok(path.dirname(output) === root && path.basename(output) === 'dist');
await rm(output, { recursive: true, force: true });
const result = spawnSync(process.execPath, [path.join(root, 'node_modules/typescript/bin/tsc'), '-p', path.join(root, 'tsconfig.json')], {
  cwd: root,
  stdio: 'inherit',
  windowsHide: true,
});
if (result.error) process.stderr.write('Build compiler could not start.\n');
process.exitCode = result.status ?? 1;
