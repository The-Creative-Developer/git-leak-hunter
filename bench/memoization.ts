/**
 * Memoization benchmark: history scan time with the blob cache on vs `--no-cache`, on synthetic
 * repos of increasing size, for a high-reuse and a low-reuse profile. Runs alternate on/off to
 * limit drift; one unrecorded warm-up per configuration. Reports median and min of the measured
 * engine time (stats.durationMs) plus the measured counters.
 *
 *   npx tsx bench/memoization.ts [runs]   → bench/results/memoization.{json,csv}
 */
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { DEFAULT_MAX_FILE_BYTES } from '../src/config.js';
import { DEFAULT_ENTROPY } from '../src/detect/entropy.js';
import { runScan } from '../src/pipeline.js';
import type { ScanStats } from '../src/types.js';
import { buildSyntheticRepo } from '../test/fixtures/synthRepo.js';
import { collectEnv } from './env.js';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const RESULTS = path.join(ROOT, 'bench', 'results');
const RUNS = Number(process.argv[2] ?? 5);

const PROFILES = [
  {
    name: 'high-reuse',
    poolSize: 150,
    description: '150 distinct file contents reused across 300 paths',
  },
  {
    name: 'low-reuse',
    poolSize: 50_000,
    description: 'up to 50,000 distinct contents (almost every write is new)',
  },
] as const;
const SIZES = [500, 1000, 2000, 4000];
const PATHS = 300;
const FILES_PER_COMMIT = 5;

export interface MemoRow {
  profile: string;
  commits: number;
  mode: 'cache' | 'no-cache';
  runs: number;
  medianMs: number;
  minMs: number;
  samplesMs: number[];
  fileVersionsSeen: number;
  uniqueBlobsScanned: number;
  cacheHits: number;
  bytesScanned: number;
  findings: number;
  /** Files a full-snapshot scan would read: Σ over commits of `git ls-tree -r` entries (measured). */
  snapshotFileVersions: number;
}

/** Measured with git: total tree entries over every commit (what a checkout-per-commit scan reads). */
async function snapshotFileVersions(dir: string): Promise<number> {
  const { stdout } = await run('git', ['rev-list', '--all'], { cwd: dir, maxBuffer: 64 << 20 });
  let total = 0;
  for (const commit of stdout.split('\n').filter(Boolean)) {
    const tree = await run('git', ['ls-tree', '-r', '--name-only', commit], {
      cwd: dir,
      maxBuffer: 64 << 20,
    });
    total += tree.stdout.split('\n').filter(Boolean).length;
  }
  return total;
}

const median = (xs: number[]): number => {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
};

async function scan(dir: string, cache: boolean): Promise<{ stats: ScanStats; findings: number }> {
  const res = await runScan({
    target: dir,
    outDir: '',
    formats: [],
    options: {
      entropy: { ...DEFAULT_ENTROPY },
      ci: true,
      cache,
      verify: false,
      maxFileBytes: DEFAULT_MAX_FILE_BYTES,
    },
  });
  return { stats: res.report.stats, findings: res.report.findings.length };
}

async function main(): Promise<void> {
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'glh-bench-memo-'));
  const rows: MemoRow[] = [];
  try {
    for (const profile of PROFILES) {
      for (const commits of SIZES) {
        const repo = await buildSyntheticRepo(path.join(tmp, `${profile.name}-${commits}`), {
          commits,
          paths: PATHS,
          filesPerCommit: FILES_PER_COMMIT,
          poolSize: profile.poolSize,
          secretEvery: 10,
          seed: 2026,
        });
        const snapshot = await snapshotFileVersions(repo.dir);
        await scan(repo.dir, true); // warm-up (not recorded)
        await scan(repo.dir, false);
        const samples = { cache: [] as number[], 'no-cache': [] as number[] };
        const last: Partial<Record<'cache' | 'no-cache', { stats: ScanStats; findings: number }>> =
          {};
        for (let i = 0; i < RUNS; i++) {
          for (const mode of ['cache', 'no-cache'] as const) {
            const r = await scan(repo.dir, mode === 'cache');
            samples[mode].push(r.stats.durationMs);
            last[mode] = r;
          }
        }
        for (const mode of ['cache', 'no-cache'] as const) {
          const r = last[mode]!;
          rows.push({
            profile: profile.name,
            commits,
            mode,
            runs: RUNS,
            medianMs: median(samples[mode]),
            minMs: Math.min(...samples[mode]),
            samplesMs: samples[mode],
            fileVersionsSeen: r.stats.fileVersionsSeen,
            uniqueBlobsScanned: r.stats.uniqueBlobsScanned,
            cacheHits: r.stats.cacheHits,
            bytesScanned: r.stats.bytesScanned,
            findings: r.findings,
            snapshotFileVersions: snapshot,
          });
        }
        process.stderr.write(
          `${profile.name} ${commits}: cache median ${median(samples.cache)} ms, no-cache median ${median(samples['no-cache'])} ms\n`,
        );
      }
    }
    await mkdir(RESULTS, { recursive: true });
    const meta = {
      generatedAt: new Date().toISOString(),
      env: await collectEnv(),
      runs: RUNS,
      shape: { paths: PATHS, filesPerCommit: FILES_PER_COMMIT, secretEvery: 10, seed: 2026 },
      profiles: PROFILES,
    };
    await writeFile(
      path.join(RESULTS, 'memoization.json'),
      JSON.stringify({ ...meta, rows }, null, 2) + '\n',
    );
    const header =
      'profile,commits,mode,runs,median_ms,min_ms,snapshot_file_versions,file_versions_seen,unique_blobs_scanned,cache_hits,bytes_scanned,findings';
    const csv = [
      header,
      ...rows.map((r) =>
        [
          r.profile,
          r.commits,
          r.mode,
          r.runs,
          r.medianMs,
          r.minMs,
          r.snapshotFileVersions,
          r.fileVersionsSeen,
          r.uniqueBlobsScanned,
          r.cacheHits,
          r.bytesScanned,
          r.findings,
        ].join(','),
      ),
    ];
    await writeFile(path.join(RESULTS, 'memoization.csv'), csv.join('\n') + '\n');
    process.stderr.write('wrote bench/results/memoization.{json,csv}\n');
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

await main();
