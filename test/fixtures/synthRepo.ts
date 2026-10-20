/**
 * Synthetic repositories of arbitrary size, built with `git fast-import` (fast: no working tree,
 * no per-commit process). Used by the scale test and by the memoization benchmark.
 *
 * Shape: a fixed pool of distinct file contents; every commit rewrites `filesPerCommit` paths with
 * contents drawn from the pool, so the same blobs recur across many commits and paths — the case
 * blob memoization is designed for. Every `secretEvery`-th pool entry carries a fabricated GitHub
 * token. The generator simulates the tree to return exact expectations (in memory only).
 */
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { Rng, SecretFactory } from './secretFactory.js';

export interface SynthOptions {
  commits: number;
  paths: number;
  filesPerCommit: number;
  poolSize: number;
  secretEvery: number;
  seed?: number;
}

export interface SynthRepo {
  dir: string;
  /** Path/blob changes actually recorded (a rewrite with identical content is not a change). */
  fileVersions: number;
  /** Distinct pool entries that were ever committed. */
  distinctBlobs: number;
  /** Distinct (path, pool entry with a secret) pairs ever committed = expected findings. */
  expectedFindings: number;
  /** Of those, how many are still present at HEAD. */
  expectedInHead: number;
  rawSecrets: string[];
}

function run(cwd: string, args: string[], input?: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, {
      cwd,
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_CONFIG_NOSYSTEM: '1',
      },
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    child.on('error', reject);
    child.on('close', (code) =>
      code === 0 ? resolve() : reject(new Error(`git ${args[0]} failed (${code})`)),
    );
    child.stdin.on('error', () => undefined);
    child.stdin.end(input ?? '');
  });
}

export async function buildSyntheticRepo(dir: string, o: SynthOptions): Promise<SynthRepo> {
  const rng = new Rng(o.seed ?? 7);
  const f = new SecretFactory(rng);
  await mkdir(dir, { recursive: true });
  await run(dir, ['init', '-q', '--template=', '-b', 'main']);

  const rawSecrets: string[] = [];
  const pool: string[] = [];
  for (let i = 0; i < o.poolSize; i++) {
    const lines = [`// module ${i}`, `export const id${i} = ${i};`];
    if (i % o.secretEvery === 0) {
      const tok = f.githubToken();
      rawSecrets.push(tok);
      lines.push(`export const TOKEN_${i} = '${tok}';`);
    }
    for (let k = 0; k < 20; k++) lines.push(`export const v${k} = ${rng.int(1000)};`);
    pool.push(lines.join('\n') + '\n');
  }
  const pathOf = (p: number): string => `src/pkg${p % 10}/file${p}.ts`;

  const chunks: Buffer[] = [];
  const emit = (s: string | Buffer): void => {
    chunks.push(typeof s === 'string' ? Buffer.from(s) : s);
  };
  pool.forEach((content, i) => {
    const data = Buffer.from(content);
    emit(`blob\nmark :${i + 1}\ndata ${data.length}\n`);
    emit(data);
    emit('\n');
  });

  const tree = new Map<number, number>(); // path index → pool index
  const everCommitted = new Set<number>();
  const secretPairs = new Set<string>();
  let fileVersions = 0;
  const base = 1_736_150_400; // 2025-01-06T08:00:00Z
  for (let c = 0; c < o.commits; c++) {
    const msg = `commit ${c}`;
    emit(`commit refs/heads/main\nmark :${o.poolSize + c + 1}\n`);
    emit(`author Synth <synth@example.test> ${base + c * 60} +0000\n`);
    emit(`committer Synth <synth@example.test> ${base + c * 60} +0000\n`);
    emit(`data ${Buffer.byteLength(msg)}\n${msg}\n`);
    if (c > 0) emit(`from :${o.poolSize + c}\n`);
    const touched = new Set<number>();
    while (touched.size < Math.min(o.filesPerCommit, o.paths)) touched.add(rng.int(o.paths));
    for (const p of touched) {
      const blob = rng.int(o.poolSize);
      emit(`M 100644 :${blob + 1} ${pathOf(p)}\n`);
      if (tree.get(p) !== blob) {
        fileVersions++;
        tree.set(p, blob);
        everCommitted.add(blob);
        if (blob % o.secretEvery === 0) secretPairs.add(`${p}:${blob}`);
      }
    }
    emit('\n');
  }
  await run(dir, ['fast-import', '--quiet'], Buffer.concat(chunks));

  let expectedInHead = 0;
  for (const [p, blob] of tree)
    if (blob % o.secretEvery === 0 && secretPairs.has(`${p}:${blob}`)) expectedInHead++;
  return {
    dir,
    fileVersions,
    distinctBlobs: everCommitted.size,
    expectedFindings: secretPairs.size,
    expectedInHead,
    rawSecrets,
  };
}
