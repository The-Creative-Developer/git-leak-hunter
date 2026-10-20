import { execFile } from 'node:child_process';
import { cp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FIXTURE_NAMES } from '../fixtures/buildRepos.js';
import { useFixtures } from '../helpers/fixtures.js';
import { git } from '../helpers/git.js';
import { scanRepo } from '../helpers/scan.js';

const fx = useFixtures();

/** Every blob reachable from any ref, as git itself sees it. */
async function reachableBlobs(dir: string): Promise<Set<string>> {
  const objects = (await git(dir, ['rev-list', '--objects', '--all']))
    .split('\n')
    .map((l) => l.slice(0, 40))
    .filter((l) => /^[0-9a-f]{40}$/.test(l));
  const out = new Set<string>();
  // Classify all objects in one batch call via stdin.
  const types: string = await new Promise((resolve, reject) => {
    const child = execFile(
      'git',
      ['cat-file', '--batch-check=%(objectname) %(objecttype)'],
      { cwd: dir, maxBuffer: 64 << 20 },
      (err, stdout) => (err ? reject(err) : resolve(stdout)),
    );
    child.stdin?.end(objects.join('\n') + '\n');
  });
  for (const line of types.split('\n')) {
    const [oid, type] = line.split(' ');
    if (oid && type === 'blob') out.add(oid);
  }
  return out;
}

const sorted = (s: Iterable<string>): string[] => [...s].sort();

describe('reachable-blob invariant', () => {
  it.each(FIXTURE_NAMES.map((n) => [n]))(
    '%s: scanned ∪ skipped ∪ ignored == git rev-list --objects --all (blobs)',
    async (name) => {
      const f = fx.get().fixtures[name];
      const res = await scanRepo(f.dir, path.join(fx.tmp(), 'inv', name));
      const reachable = await reachableBlobs(f.dir);
      const covered = new Set([...res.scannedBlobs, ...res.skippedBlobs, ...res.ignoredBlobs]);
      expect(sorted(covered)).toEqual(sorted(reachable));
      for (const b of res.skippedBlobs) expect(res.scannedBlobs.has(b)).toBe(false);
      expect(res.scannedBlobs.size).toBe(res.report.stats.uniqueBlobsScanned);
    },
  );

  it('holds with ignore rules: ignored-only blobs are accounted for, not lost', async () => {
    const f = fx.get().fixtures['ci-configs'];
    const ignoreFile = path.join(fx.tmp(), 'inv-ignore.txt');
    await writeFile(ignoreFile, '.github/\nDockerfile\n');
    const res = await scanRepo(f.dir, path.join(fx.tmp(), 'inv-ign'), {}, { ignoreFile });
    const reachable = await reachableBlobs(f.dir);
    expect(res.ignoredBlobs.size).toBeGreaterThan(0);
    expect(
      sorted(new Set([...res.scannedBlobs, ...res.skippedBlobs, ...res.ignoredBlobs])),
    ).toEqual(sorted(reachable));
    expect(res.report.findings.some((x) => x.filePath === 'Dockerfile')).toBe(false);
  });
});

describe('damaged repositories', () => {
  it('counts a missing blob object instead of crashing', async () => {
    const src = fx.get().fixtures['history-only'].dir;
    const dir = path.join(fx.tmp(), 'damaged');
    await cp(src, dir, { recursive: true });
    const oid = (await git(dir, ['rev-parse', 'HEAD:README.md'])).trim();
    await rm(path.join(dir, '.git', 'objects', oid.slice(0, 2), oid.slice(2)));
    const res = await scanRepo(dir, path.join(fx.tmp(), 'damaged-out'));
    expect(res.report.stats.skipped.missing).toBe(1);
    expect(res.report.findings).toHaveLength(3);
  });
});
