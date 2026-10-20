import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildSyntheticRepo, type SynthRepo } from '../fixtures/synthRepo.js';
import { expectNoLeak } from '../helpers/noLeak.js';
import { scanRepo } from '../helpers/scan.js';

let tmp: string;
let repo: SynthRepo;

beforeAll(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'glh-scale-'));
  repo = await buildSyntheticRepo(path.join(tmp, 'repo'), {
    commits: 2000,
    paths: 300,
    filesPerCommit: 5,
    poolSize: 150,
    secretEvery: 10,
  });
});

afterAll(async () => {
  await rm(tmp, { recursive: true, force: true });
});

describe('scale: synthetic history with heavy blob reuse', () => {
  it('walks every commit, scans each unique blob once and matches the simulated ground truth', async () => {
    const res = await scanRepo(repo.dir, path.join(tmp, 'out'));
    const s = res.report.stats;
    expect(s.commitsWalked).toBe(2000);
    expect(s.fileVersionsSeen).toBe(repo.fileVersions);
    expect(s.uniqueBlobsScanned).toBe(repo.distinctBlobs);
    expect(s.uniqueBlobsScanned + s.cacheHits).toBe(s.fileVersionsSeen);
    expect(res.report.findings).toHaveLength(repo.expectedFindings);
    expect(res.report.summary.inHead).toBe(repo.expectedInHead);
    expectNoLeak(await readFile(res.written.json!, 'utf8'), repo.rawSecrets, 'scale report.json');
  });

  it('produces identical findings with --no-cache', async () => {
    const on = await scanRepo(repo.dir, path.join(tmp, 'on'), {}, { formats: [] });
    const off = await scanRepo(repo.dir, path.join(tmp, 'off'), { cache: false }, { formats: [] });
    expect(off.report.stats.cacheHits).toBe(0);
    expect(off.report.findings.map((f) => f.fingerprint).sort()).toEqual(
      on.report.findings.map((f) => f.fingerprint).sort(),
    );
  });
});
