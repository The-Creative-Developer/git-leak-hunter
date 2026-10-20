/**
 * Stage 1 — Git Engine. Walks history (or one branch), reads each changed blob once via
 * `cat-file`, and memoizes the detection result per (config, blob, file kind): the scan cost is
 * O(unique blobs) instead of O(commits × files). Counters are measured, never estimated.
 */
import { performance } from 'node:perf_hooks';
import type { CommitMeta, ContentUnit, SkipCounts, SuppressionReason } from '../types.js';
import type { BlobScanResult, FileKind } from '../detect/types.js';
import { computeLineOffsets } from '../text.js';
import { CatFile } from './catFile.js';
import { gitText } from './exec.js';
import { listTree, walkLog, type WalkOptions } from './log.js';

export interface GitEngineCounters {
  commitsWalked: number;
  fileVersionsSeen: number;
  uniqueBlobsScanned: number;
  cacheHits: number;
  bytesScanned: number;
  durationMs: number;
}

/** A file version and the (possibly shared, cached) scan result of its blob. */
export interface Occurrence {
  commit: CommitMeta;
  path: string;
  blob: string;
  origin: 'history' | 'head';
  result: BlobScanResult;
}

export type BlobScanner = (unit: ContentUnit, kind: FileKind) => BlobScanResult;

export interface GitEngineOptions {
  dir: string;
  repoName: string;
  head: string | null;
  walk: WalkOptions;
  /** null = path ignored by ignore rules. */
  classify: (path: string) => FileKind | null;
  scan: BlobScanner;
  cache: boolean;
  /** Cache-key prefix: hash of ruleset + config. */
  configHash: string;
  maxFileBytes: number;
}

export interface HistoryScan {
  occurrences: Occurrence[];
  /** HEAD tree: path → result for that path's blob (for in-HEAD vs history-only). */
  headResults: Map<string, BlobScanResult>;
  counters: GitEngineCounters;
  skipped: SkipCounts;
  suppressed: Partial<Record<SuppressionReason, number>>;
  /** Blob ids actually scanned / deliberately skipped (for the reachable-blob invariant). */
  scannedBlobs: Set<string>;
  skippedBlobs: Set<string>;
}

/** 'missing' covers objects absent from a partial/shallow clone; they are neither scanned nor counted. */
type Outcome = BlobScanResult | 'binary' | 'oversize' | 'missing';

const BINARY_SNIFF_BYTES = 8000;

export function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, BINARY_SNIFF_BYTES).includes(0);
}

export async function readCommitMeta(dir: string, oid: string): Promise<CommitMeta> {
  const out = await gitText(
    [
      'log',
      '-1',
      '-z',
      '--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%s',
      '--end-of-options',
      oid,
      '--',
    ],
    dir,
  );
  const [hash = oid, parents = '', name = '', email = '', date = '', subject = ''] =
    out.split('\0');
  return {
    hash,
    parents: parents.split(' ').filter(Boolean),
    author: { name, email },
    date,
    subject,
  };
}

export async function scanHistory(opts: GitEngineOptions): Promise<HistoryScan> {
  const t0 = performance.now();
  const cat = new CatFile(opts.dir);
  const cache = new Map<string, Outcome>();
  const commits = new Set<string>();
  const occurrences: Occurrence[] = [];
  const scannedBlobs = new Set<string>();
  const skippedBlobs = new Set<string>();
  const skipped: SkipCounts = { binary: 0, oversize: 0, ignored: 0 };
  const suppressed: Partial<Record<SuppressionReason, number>> = {};
  const counters: GitEngineCounters = {
    commitsWalked: 0,
    fileVersionsSeen: 0,
    uniqueBlobsScanned: 0,
    cacheHits: 0,
    bytesScanned: 0,
    durationMs: 0,
  };
  const seenKeys = new Set<string>();

  const scanOne = async (
    commit: CommitMeta,
    path: string,
    blob: string,
    kind: FileKind,
    origin: Occurrence['origin'],
  ): Promise<Outcome> => {
    const key = `${opts.configHash}:${blob}:${kind}`;
    const cached = cache.get(key);
    if (opts.cache && cached !== undefined) {
      counters.cacheHits++;
      return cached;
    }
    const firstTime = !seenKeys.has(key);
    seenKeys.add(key);
    let outcome: Outcome;
    const info = await cat.info(blob);
    if (!info) {
      outcome = 'missing';
    } else if (info.size > opts.maxFileBytes) {
      outcome = 'oversize';
    } else {
      const buf = (await cat.contents(blob)) ?? Buffer.alloc(0);
      if (isBinary(buf)) {
        outcome = 'binary';
      } else {
        const content = buf.toString('utf8');
        counters.bytesScanned += buf.length;
        outcome = opts.scan(
          {
            repo: opts.repoName,
            commitHash: commit.hash,
            author: commit.author,
            date: commit.date,
            filePath: path,
            blobHash: blob,
            content,
            origin,
            lineOffsets: computeLineOffsets(content),
          },
          kind,
        );
      }
    }
    if (firstTime && outcome !== 'missing') {
      if (outcome === 'binary' || outcome === 'oversize') {
        skipped[outcome]++;
        skippedBlobs.add(blob);
      } else {
        counters.uniqueBlobsScanned++;
        scannedBlobs.add(blob);
        for (const [r, n] of Object.entries(outcome.suppressed)) {
          const reason = r as SuppressionReason;
          suppressed[reason] = (suppressed[reason] ?? 0) + (n ?? 0);
        }
      }
    }
    cache.set(key, outcome);
    return outcome;
  };

  const headResults = new Map<string, BlobScanResult>();
  try {
    for await (const entry of walkLog(opts.dir, opts.walk)) {
      commits.add(entry.commit.hash);
      counters.fileVersionsSeen++;
      const kind = opts.classify(entry.path);
      if (kind === null) {
        skipped.ignored++;
        continue;
      }
      const outcome = await scanOne(entry.commit, entry.path, entry.blob, kind, 'history');
      if (typeof outcome === 'string') continue;
      occurrences.push({
        commit: entry.commit,
        path: entry.path,
        blob: entry.blob,
        origin: 'history',
        result: outcome,
      });
    }

    // HEAD tree: presence lookups hit the cache; blobs not reached by a limited walk are scanned.
    if (opts.head) {
      const headMeta = await readCommitMeta(opts.dir, opts.head);
      for (const e of await listTree(opts.dir, opts.head)) {
        const kind = opts.classify(e.path);
        if (kind === null) continue;
        const key = `${opts.configHash}:${e.blob}:${kind}`;
        let outcome = cache.get(key);
        if (outcome === undefined) {
          counters.fileVersionsSeen++;
          outcome = await scanOne(headMeta, e.path, e.blob, kind, 'head');
          if (typeof outcome !== 'string') {
            occurrences.push({
              commit: headMeta,
              path: e.path,
              blob: e.blob,
              origin: 'head',
              result: outcome,
            });
          }
        }
        if (typeof outcome !== 'string') headResults.set(e.path, outcome);
      }
    }
  } finally {
    await cat.close();
  }

  counters.commitsWalked = commits.size;
  counters.durationMs = Math.round((performance.now() - t0) * 10) / 10;
  return { occurrences, headResults, counters, skipped, suppressed, scannedBlobs, skippedBlobs };
}
