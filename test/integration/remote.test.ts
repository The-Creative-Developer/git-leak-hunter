/**
 * Exercises the remote-URL path (validation, authorization notice, bare clone into a temp dir,
 * credential stripping, cleanup) without network access: a `git` shim placed first on PATH
 * rewrites `clone` of https://fixtures.invalid/<name>.git to a local clone of that fixture and
 * logs the argv it received. Every other git command is passed to the real binary unchanged.
 */
import { existsSync } from 'node:fs';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { main } from '../../src/cli.js';
import { liveTempDirCount } from '../../src/git/repo.js';
import { useFixtures } from '../helpers/fixtures.js';
import { expectNoLeak } from '../helpers/noLeak.js';
import { scanRepo } from '../helpers/scan.js';

const fx = useFixtures();
let savedPath: string | undefined;
let shimLog = '';

function findRealGit(): string {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    const candidate = path.join(dir, 'git');
    if (dir && existsSync(candidate)) return candidate;
  }
  throw new Error('git not found on PATH');
}

const SHIM = `#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.GLH_SHIM_LOG, JSON.stringify(args) + '\\n');
const i = args.indexOf('clone');
if (i >= 0) {
  const dash = args.indexOf('--', i);
  const m = /^https:\\/\\/(?:[^@/]+@)?fixtures\\.invalid\\/([a-z-]+)\\.git$/.exec(args[dash + 1] || '');
  if (!m) { process.stderr.write('fatal: repository not found\\n'); process.exit(128); }
  args[dash + 1] = process.env.GLH_FIXTURE_ROOT + '/' + m[1];
  args.unshift('-c', 'protocol.file.allow=always');
}
const r = spawnSync(process.env.GLH_REAL_GIT, args, { stdio: 'inherit' });
process.exit(r.status === null ? 1 : r.status);
`;

beforeAll(async () => {
  const shimDir = path.join(fx.tmp(), 'shim');
  const { mkdir } = await import('node:fs/promises');
  await mkdir(shimDir, { recursive: true });
  await writeFile(path.join(shimDir, 'git'), SHIM);
  await chmod(path.join(shimDir, 'git'), 0o755);
  shimLog = path.join(fx.tmp(), 'shim.log');
  process.env.GLH_REAL_GIT = findRealGit();
  process.env.GLH_SHIM_LOG = shimLog;
  process.env.GLH_FIXTURE_ROOT = path.dirname(fx.get().fixtures.clean.dir);
  savedPath = process.env.PATH;
  process.env.PATH = `${shimDir}${path.delimiter}${savedPath ?? ''}`;
});

afterAll(() => {
  process.env.PATH = savedPath;
  delete process.env.GLH_REAL_GIT;
  delete process.env.GLH_SHIM_LOG;
  delete process.env.GLH_FIXTURE_ROOT;
});

async function cloneArgs(): Promise<string[][]> {
  return (await readFile(shimLog, 'utf8'))
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as string[])
    .filter((a) => a.includes('clone'));
}

describe('remote targets', () => {
  it('prints a notice, bare-clones safely, scans full history, strips credentials, cleans up', async () => {
    const token = ['to', 'ken', '123'].join('');
    const url = `https://user:${token}@fixtures.invalid/history-only.git`;
    const notices: string[] = [];
    const res = await scanRepo(
      url,
      path.join(fx.tmp(), 'remote-out'),
      {},
      {},
      { onBeforeClone: (u) => notices.push(u) },
    );

    expect(notices).toEqual(['https://fixtures.invalid/history-only.git']);
    expect(res.report.repository.target).toBe('https://fixtures.invalid/history-only.git');
    expect(res.report.findings).toHaveLength(3);
    expect(res.report.findings.every((f) => f.presence === 'history-only')).toBe(true);
    const json = await readFile(res.written.json!, 'utf8');
    expect(json).not.toContain(token);
    expectNoLeak(json, fx.get().fixtures['history-only'].rawSecrets, 'remote report.json');

    const [args] = await cloneArgs();
    expect(args).toBeDefined();
    expect(args).toEqual(
      expect.arrayContaining([
        'core.hooksPath=/dev/null',
        'protocol.allow=never',
        '--bare',
        '--template=',
        '--',
      ]),
    );
    const dest = args!.at(-1)!;
    expect(existsSync(dest)).toBe(false);
    expect(liveTempDirCount()).toBe(0);
  });

  it('cleans up the temp dir when the clone fails, without leaking URL credentials', async () => {
    const token = ['sec', 'ret', '999'].join('');
    await expect(
      scanRepo(
        `https://me:${token}@fixtures.invalid/does-not-exist.git`,
        path.join(fx.tmp(), 'remote-bad'),
      ),
    ).rejects.toThrow(/git clone failed/);
    expect(liveTempDirCount()).toBe(0);
  });

  it('CLI prints the authorization notice on stderr before cloning', async () => {
    let out = '';
    let err = '';
    const code = await main(
      [
        'node',
        'git-leak-hunter',
        'scan',
        'https://fixtures.invalid/clean.git',
        '--out',
        path.join(fx.tmp(), 'remote-cli'),
      ],
      { out: (s) => (out += s), err: (s) => (err += s) },
    );
    expect(code).toBe(0);
    expect(err).toContain('Only scan repositories you own or are explicitly authorized to scan');
    expect(out).toContain('0 findings detected');
  });
});
