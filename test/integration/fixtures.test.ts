import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  FIXTURE_NAMES,
  HUGE_FILE_BYTES,
  buildAllFixtures,
  buildFixture,
  type BuiltFixtures,
  type GroundTruth,
} from '../fixtures/buildRepos.js';
import { expectNoLeak } from '../helpers/noLeak.js';
import { git, gitOk } from '../helpers/git.js';

let tmp: string;
let built: BuiltFixtures;

beforeAll(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'glh-fixtures-'));
  built = await buildAllFixtures(path.join(tmp, 'a'));
});

afterAll(async () => {
  await rm(tmp, { recursive: true, force: true });
});

/** True if one of `values` starts on line `line` (1-based) of `<rev>:<file>`. */
async function startsOnLine(
  dir: string,
  rev: string,
  file: string,
  line: number,
  values: Iterable<string>,
) {
  const content = await git(dir, ['cat-file', 'blob', `${rev}:${file}`]);
  const lines = content.split('\n');
  const lineStart = lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0);
  const lineEnd = lineStart + (lines[line - 1]?.length ?? 0);
  for (const v of values) {
    for (let i = content.indexOf(v); i >= 0; i = content.indexOf(v, i + 1)) {
      if (i >= lineStart && i <= lineEnd) return true;
    }
  }
  return false;
}

describe('fixture repo builder', () => {
  it('builds every fixture and a parseable ground-truth manifest', async () => {
    const manifest = JSON.parse(await readFile(built.manifestPath, 'utf8')) as GroundTruth;
    expect(manifest.format).toBe('git-leak-hunter/ground-truth@1');
    expect(manifest.repos.map((r) => r.name)).toEqual([...FIXTURE_NAMES]);
    for (const repo of manifest.repos) {
      expect(repo.head).toMatch(/^[0-9a-f]{40}$/);
      expect(Object.keys(repo)).not.toContain('rawSecrets');
    }
  });

  it('never writes raw secret values into the manifest', async () => {
    const manifestText = await readFile(built.manifestPath, 'utf8');
    const all = Object.values(built.fixtures).flatMap((f) => f.rawSecrets);
    expect(all.length).toBeGreaterThan(20);
    expectNoLeak(manifestText, all, 'ground-truth.json');
  });

  it('places every planted secret at the recorded commit, path and line', async () => {
    for (const f of Object.values(built.fixtures)) {
      for (const item of f.items.filter((i) => i.kind === 'secret')) {
        const ok = await startsOnLine(f.dir, item.commit, item.filePath, item.line, f.rawSecrets);
        expect(ok, `${f.name}/${item.id}`).toBe(true);
      }
    }
  });

  it('places every bait at a real line of the recorded commit', async () => {
    for (const f of Object.values(built.fixtures)) {
      for (const item of f.items.filter((i) => i.kind === 'bait')) {
        const content = await git(f.dir, ['cat-file', 'blob', `${item.commit}:${item.filePath}`]);
        expect(content.split('\n')[item.line - 1]?.length, `${f.name}/${item.id}`).toBeGreaterThan(
          0,
        );
        expect(await startsOnLine(f.dir, item.commit, item.filePath, item.line, f.rawSecrets)).toBe(
          false,
        );
      }
    }
  });

  it('records presence correctly: history-only secrets are gone from HEAD', async () => {
    for (const f of Object.values(built.fixtures)) {
      for (const item of f.items) {
        if (item.kind !== 'secret') continue;
        const inHeadTree = await gitOk(f.dir, ['cat-file', '-e', `HEAD:${item.filePath}`]);
        let atHead = false;
        if (inHeadTree) {
          const content = await git(f.dir, ['cat-file', 'blob', `HEAD:${item.filePath}`]);
          atHead = content.includes(f.secretValues.get(item.id)!);
        }
        expect(atHead ? 'in-HEAD' : 'history-only', `${f.name}/${item.id}`).toBe(item.presence);
      }
    }
  });

  it('covers every required scenario', () => {
    const fx = built.fixtures;
    const secrets = (n: keyof typeof fx) => fx[n].items.filter((i) => i.kind === 'secret');
    expect(
      secrets('history-only').every((i) => i.kind === 'secret' && i.presence === 'history-only'),
    ).toBe(true);
    expect(secrets('head-secrets').length).toBeGreaterThanOrEqual(6);
    expect(new Set(secrets('blob-reuse').map((i) => i.filePath)).size).toBe(4);
    expect(fx['blob-reuse'].branches).toEqual(['feature', 'main']);
    expect(secrets('ci-configs').map((i) => i.filePath)).toEqual(
      expect.arrayContaining([
        '.github/workflows/deploy.yml',
        '.gitlab-ci.yml',
        'Dockerfile',
        '.env',
        '.ssh/id_rsa',
      ]),
    );
    expect(secrets('false-positives')).toHaveLength(0);
    expect(fx['false-positives'].items.length).toBeGreaterThanOrEqual(15);
    expect(fx.clean.items).toHaveLength(0);
  });

  it('introduces the merge-conflict secret only in the two-parent merge commit', async () => {
    const f = built.fixtures['merge-conflict'];
    const item = f.items.find((i) => i.id === 'resolution-token');
    expect(item).toBeDefined();
    const parents = (await git(f.dir, ['rev-list', '--parents', '-n', '1', item!.commit]))
      .trim()
      .split(' ');
    expect(parents).toHaveLength(3);
    for (const parent of parents.slice(1)) {
      expect(await startsOnLine(f.dir, parent, item!.filePath, item!.line, f.rawSecrets)).toBe(
        false,
      );
    }
  });

  it('reuses one blob across paths and commits in blob-reuse', async () => {
    const f = built.fixtures['blob-reuse'];
    const blobs = new Set<string>();
    for (const item of f.items) {
      blobs.add((await git(f.dir, ['rev-parse', `${item.commit}:${item.filePath}`])).trim());
    }
    expect(blobs.size).toBe(1);
    const commits = Number((await git(f.dir, ['rev-list', '--all', '--count'])).trim());
    expect(commits).toBeGreaterThanOrEqual(15);
  });

  it('builds hostile paths, a huge file and a binary', async () => {
    const f = built.fixtures.hostile;
    const paths = (await git(f.dir, ['ls-tree', '-r', '-z', '--name-only', 'HEAD'])).split('\0');
    expect(paths).toContain('odd/new\nline\tand-tab.txt');
    expect(paths).toContain('<img src=x onerror=alert(1)>.js');
    expect(paths).toContain('-rf --output=pwned.txt');
    const size = Number((await git(f.dir, ['cat-file', '-s', 'HEAD:data/huge.txt'])).trim());
    expect(size).toBeGreaterThanOrEqual(HUGE_FILE_BYTES);
    const subject = (await git(f.dir, ['log', '-1', '--format=%s', 'HEAD~1'])).trim();
    expect(subject).toContain('<script>');
  });

  it('is deterministic for a given seed', async () => {
    const again = await buildFixture(path.join(tmp, 'b'), 'history-only');
    expect(again.head).toBe(built.fixtures['history-only'].head);
    const other = await buildFixture(path.join(tmp, 'c'), 'history-only', 42);
    expect(other.head).not.toBe(built.fixtures['history-only'].head);
  });
});
