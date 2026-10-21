/**
 * `git-leak-hunter dork --owner <name>` (optional stretch): find candidate leaks with the GitHub
 * code-search API, only within an owner the token's account controls. Matched files are fetched
 * by blob SHA and run through the same detection engine as `scan`, producing the same redacted
 * Finding schema and reports.
 *
 * Scope note: GitHub code search indexes default branches only, so dork findings describe the
 * current default-branch content. Use `scan <repo-url>` for full-history results.
 */
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import type {
  CommitMeta,
  EntropyThresholds,
  Report,
  ScanStats,
  SuppressionReason,
} from '../types.js';
import { analyze } from '../analyze.js';
import { configHashOf } from '../pipeline.js';
import { scanBlob } from '../detect/engine.js';
import { fileKindOf } from '../detect/fileKind.js';
import type { BlobScanResult } from '../detect/types.js';
import { isBinary, type Occurrence } from '../git/index.js';
import { renderHtml } from '../report/html.js';
import { buildReport, renderJson } from '../report/json.js';
import { computeLineOffsets } from '../text.js';
import type { FetchLike } from '../verify/http.js';
import { GitHubApi, RateLimitedError, type CodeSearchItem } from './github.js';
import { DORK_TERMS, buildQuery, validateOwner, type OwnerType } from './queries.js';

export { DorkScopeError, DORK_TERMS, assertScopedQuery, buildQuery } from './queries.js';

export interface DorkRequest {
  owner: string;
  ownerType: OwnerType;
  /** Replaces the built-in terms when given; the owner qualifier is always added. */
  terms?: readonly string[];
  maxResults: number;
  outDir: string;
  formats: ReadonlyArray<'html' | 'json'>;
  entropy: EntropyThresholds;
  maxFileBytes: number;
  token: string;
}

export interface DorkHooks {
  fetchImpl?: FetchLike;
  searchDelayMs?: number;
  coreDelayMs?: number;
  onProgress?: (message: string) => void;
}

export interface DorkResult {
  report: Report;
  written: { html?: string; json?: string };
  queries: number;
  filesMatched: number;
  apiCalls: { search: number; core: number };
  /** Set when results are partial (rate limit, or GitHub reported incomplete results). */
  incomplete?: string;
}

export async function runDork(req: DorkRequest, hooks: DorkHooks = {}): Promise<DorkResult> {
  validateOwner(req.owner);
  const startedAt = new Date();
  const t0 = performance.now();
  const api = new GitHubApi({
    token: req.token,
    ...(hooks.fetchImpl ? { fetchImpl: hooks.fetchImpl } : {}),
    ...(hooks.searchDelayMs === undefined ? {} : { searchDelayMs: hooks.searchDelayMs }),
    ...(hooks.coreDelayMs === undefined ? {} : { coreDelayMs: hooks.coreDelayMs }),
  });

  await api.assertControls(req.owner, req.ownerType);
  hooks.onProgress?.(`owner verified (${req.ownerType})`);

  // Build every query first: a scope violation aborts before any search request is made.
  const queries = (req.terms?.length ? req.terms : DORK_TERMS).map((t) =>
    buildQuery(t, req.owner, req.ownerType),
  );
  let incomplete: string | undefined;
  const items = new Map<string, CodeSearchItem>();
  try {
    for (const q of queries) {
      if (items.size >= req.maxResults) break;
      const res = await api.searchCode(q, req.maxResults);
      if (res.incomplete) incomplete = 'GitHub reported incomplete search results';
      for (const item of res.items) {
        // Defence in depth: only keep results inside the requested owner.
        if (item.repository.full_name.split('/')[0]?.toLowerCase() !== req.owner.toLowerCase())
          continue;
        const key = `${item.repository.full_name}\0${item.path}\0${item.sha}`;
        if (!items.has(key) && items.size < req.maxResults) items.set(key, item);
      }
    }
  } catch (err) {
    if (!(err instanceof RateLimitedError)) throw err;
    incomplete = err.message;
  }
  hooks.onProgress?.(`code search (${queries.length} queries, ${items.size} files matched)`);

  const detectCfg = { entropy: req.entropy, runKey: randomBytes(32) };
  const cache = new Map<string, BlobScanResult | 'skip'>();
  const occurrences: Occurrence[] = [];
  const headResults = new Map<string, BlobScanResult>();
  const suppressed: Partial<Record<SuppressionReason, number>> = {};
  const skipped = { binary: 0, oversize: 0, ignored: 0, missing: 0 };
  const commits = new Set<string>();
  let bytesScanned = 0;
  let cacheHits = 0;
  let uniqueBlobsScanned = 0;

  try {
    for (const item of items.values()) {
      const full = item.repository.full_name;
      const kind = fileKindOf(item.path);
      const cacheKey = `${item.sha}:${kind}`;
      let result = cache.get(cacheKey);
      if (result !== undefined) {
        cacheHits++;
      } else {
        const buf = await api.blob(full, item.sha);
        if (!buf) {
          skipped.missing++;
          result = 'skip';
        } else if (buf.length > req.maxFileBytes) {
          skipped.oversize++;
          result = 'skip';
        } else if (isBinary(buf)) {
          skipped.binary++;
          result = 'skip';
        } else {
          const content = buf.toString('utf8');
          bytesScanned += buf.length;
          uniqueBlobsScanned++;
          result = scanBlob(
            {
              repo: full,
              commitHash: '',
              author: { name: '', email: '' },
              date: '',
              filePath: item.path,
              blobHash: item.sha,
              content,
              origin: 'head',
              lineOffsets: computeLineOffsets(content),
            },
            kind,
            detectCfg,
          );
          for (const [r, n] of Object.entries(result.suppressed)) {
            suppressed[r as SuppressionReason] =
              (suppressed[r as SuppressionReason] ?? 0) + (n ?? 0);
          }
        }
        cache.set(cacheKey, result);
      }
      if (result === 'skip' || result.matches.length === 0) continue;

      // Attribute to the latest commit touching the path (code search has no commit info).
      const c = await api.lastCommit(full, item.path);
      if (!c) continue;
      commits.add(c.sha);
      const commit: CommitMeta = {
        hash: c.sha,
        parents: [],
        author: { name: c.commit.author?.name ?? '', email: c.commit.author?.email ?? '' },
        date: c.commit.author?.date ?? startedAt.toISOString(),
        subject: (c.commit.message ?? '').split('\n')[0] ?? '',
      };
      const filePath = `${full}/${item.path}`;
      occurrences.push({ commit, path: filePath, blob: item.sha, origin: 'head', result });
      headResults.set(filePath, result);
    }
  } catch (err) {
    if (!(err instanceof RateLimitedError)) throw err;
    incomplete = err.message;
  }
  hooks.onProgress?.(`scanned ${uniqueBlobsScanned} files`);

  const { findings } = analyze({ occurrences, headResults });
  const stats: ScanStats = {
    commitsWalked: commits.size,
    fileVersionsSeen: items.size,
    uniqueBlobsScanned,
    cacheHits,
    bytesScanned,
    durationMs: Math.round((performance.now() - t0) * 10) / 10,
    skipped,
    suppressed,
  };
  const options = {
    entropy: req.entropy,
    ci: true,
    cache: true,
    verify: false,
    maxFileBytes: req.maxFileBytes,
  };
  const report = buildReport({
    target: `github.com/${req.owner} (code search, default branches)`,
    head: null,
    startedAt,
    finishedAt: new Date(),
    configHash: configHashOf(options),
    options,
    stats,
    findings,
  });

  const written: DorkResult['written'] = {};
  if (req.formats.length > 0) await mkdir(req.outDir, { recursive: true });
  if (req.formats.includes('json')) {
    written.json = path.join(req.outDir, 'report.json');
    await writeFile(written.json, renderJson(report));
  }
  if (req.formats.includes('html')) {
    written.html = path.join(req.outDir, 'report.html');
    await writeFile(written.html, renderHtml(report));
  }
  return {
    report,
    written,
    queries: queries.length,
    filesMatched: items.size,
    apiCalls: { ...api.calls },
    ...(incomplete ? { incomplete } : {}),
  };
}
