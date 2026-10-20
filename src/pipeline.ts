/**
 * Wires the four stages: DETECT (git walk + detection) → ANALYZE (attribution, presence,
 * severity) → VERIFY (Phase 3, opt-in) → REPORT (JSON + HTML).
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Report, ScanOptions, ScanStats, SuppressionReason } from './types.js';
import { analyze } from './analyze.js';
import { gitlabLocalIncludes } from './ci/index.js';
import { scanBlob, type DetectConfig } from './detect/engine.js';
import { LENGTH_FACTOR } from './detect/entropy.js';
import { fileKindOf } from './detect/fileKind.js';
import { emptyIgnoreRules, isIgnoredPath, parseIgnore, type IgnoreRules } from './detect/ignore.js';
import type { SeverityOverrides } from './detect/severity.js';
import type { FileKind } from './detect/types.js';
import { runGit } from './git/exec.js';
import { scanHistory, type BlobScanner } from './git/index.js';
import { openRepository, resolveRef } from './git/repo.js';
import { renderHtml } from './report/html.js';
import { buildReport, renderJson } from './report/json.js';
import {
  Vault,
  VERIFIABLE_RULES,
  verifyFindings,
  type VerifyOptions,
  type VerifySummary,
} from './verify/index.js';

/** Bump when detection rules change: invalidates cached results (part of the cache key). */
export const RULESET_VERSION = '1';

export const CI_KINDS: ReadonlySet<FileKind> = new Set([
  'github-actions',
  'gitlab-ci',
  'dockerfile',
]);

export interface ScanRequest {
  target: string;
  outDir: string;
  formats: ReadonlyArray<'html' | 'json'>;
  options: ScanOptions;
  /** Extra ignore file (`--ignore`). */
  ignoreFile?: string;
  /** Ignore patterns from the config file. */
  ignorePatterns?: readonly string[];
  severityOverrides?: SeverityOverrides;
}

export interface ScanHooks {
  onBeforeClone?: (safeUrl: string) => void;
  /** Test seam: wrap or replace the per-blob scanner (e.g. to count calls). */
  wrapScanner?: (scanner: BlobScanner) => BlobScanner;
  /** Called before any verification request, with the number of verifiable findings. */
  onVerifyStart?: (verifiable: number) => void;
  /** Verification transport/timing (tests inject a mock fetch and zero delay). */
  verify?: VerifyOptions;
}

export interface ScanResult {
  report: Report;
  written: { html?: string; json?: string };
  /** Distinct paths parsed as CI/CD configuration. */
  ciFiles: number;
  /** Blob ids scanned / skipped (for the reachable-blob invariant test). */
  scannedBlobs: Set<string>;
  skippedBlobs: Set<string>;
  ignoredBlobs: Set<string>;
  /** Present when `--verify` ran. */
  verification?: VerifySummary;
}

export function configHashOf(options: ScanOptions): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        ruleset: RULESET_VERSION,
        entropy: options.entropy,
        lengthFactor: LENGTH_FACTOR,
        maxFileBytes: options.maxFileBytes,
        ci: options.ci,
      }),
    )
    .digest('hex')
    .slice(0, 16);
}

async function readHeadFile(
  dir: string,
  head: string | null,
  file: string,
): Promise<string | null> {
  if (!head) return null;
  const res = await runGit(['cat-file', 'blob', '--end-of-options', `${head}:${file}`], {
    dir,
    allowFail: true,
  });
  return res.code === 0 ? res.stdout.toString('utf8') : null;
}

export async function runScan(req: ScanRequest, hooks: ScanHooks = {}): Promise<ScanResult> {
  const startedAt = new Date();
  const repo = await openRepository(
    req.target,
    hooks.onBeforeClone ? { onBeforeClone: hooks.onBeforeClone } : {},
  );
  // Raw verifiable secrets are kept only when the user opted in, and cleared before returning.
  const vault = req.options.verify ? new Vault() : undefined;
  try {
    const opts = req.options;
    const tip = opts.branch ? await resolveRef(repo.dir, opts.branch) : repo.head;

    const ignore: IgnoreRules = emptyIgnoreRules();
    const repoIgnore = await readHeadFile(repo.dir, tip, '.leakhunterignore');
    if (repoIgnore) parseIgnore(repoIgnore, ignore);
    if (req.ignoreFile) parseIgnore(await readFile(req.ignoreFile, 'utf8'), ignore);
    if (req.ignorePatterns?.length) parseIgnore(req.ignorePatterns.join('\n'), ignore);

    const gitlabRoot = opts.ci ? await readHeadFile(repo.dir, tip, '.gitlab-ci.yml') : null;
    const gitlabIncludes = new Set(gitlabRoot ? gitlabLocalIncludes(gitlabRoot) : []);

    const ciPaths = new Set<string>();
    const classify = (p: string): FileKind | null => {
      if (isIgnoredPath(ignore, p)) return null;
      const kind = fileKindOf(p, { ci: opts.ci, gitlabIncludes });
      if (CI_KINDS.has(kind)) ciPaths.add(p);
      return kind;
    };

    const detectCfg: DetectConfig = {
      entropy: opts.entropy,
      runKey: randomBytes(32),
      ...(vault ? { vault } : {}),
    };
    const baseScanner: BlobScanner = (unit, kind) => scanBlob(unit, kind, detectCfg);
    const scanner = hooks.wrapScanner ? hooks.wrapScanner(baseScanner) : baseScanner;
    const configHash = configHashOf(opts);

    const history = await scanHistory({
      dir: repo.dir,
      repoName: repo.displayName,
      head: tip,
      walk: {
        ...(tip && opts.branch ? { revs: [tip] } : {}),
        ...(opts.maxCommits === undefined ? {} : { maxCommits: opts.maxCommits }),
        ...(opts.since === undefined ? {} : { since: opts.since }),
      },
      classify,
      scan: scanner,
      cache: opts.cache,
      configHash,
      maxFileBytes: opts.maxFileBytes,
    });

    const analyzed = analyze({
      occurrences: history.occurrences,
      headResults: history.headResults,
      ...(req.severityOverrides ? { severityOverrides: req.severityOverrides } : {}),
      ignore,
    });
    const { ignoredByFingerprint } = analyzed;
    let { findings } = analyzed;

    // VERIFY (opt-in): read-only, allowlisted calls; the vault is cleared inside.
    let verification: VerifySummary | undefined;
    if (vault) {
      hooks.onVerifyStart?.(findings.filter((f) => VERIFIABLE_RULES.has(f.ruleId)).length);
      ({ findings, summary: verification } = await verifyFindings(
        findings,
        analyzed.vaultRefs,
        vault,
        hooks.verify,
      ));
    }

    const suppressed: Partial<Record<SuppressionReason, number>> = { ...history.suppressed };
    if (ignoredByFingerprint > 0)
      suppressed['ignore-file'] = (suppressed['ignore-file'] ?? 0) + ignoredByFingerprint;
    const stats: ScanStats = { ...history.counters, skipped: history.skipped, suppressed };

    const report = buildReport({
      target: repo.target,
      head: tip,
      startedAt,
      finishedAt: new Date(),
      configHash,
      options: opts,
      stats,
      findings,
    });

    const written: ScanResult['written'] = {};
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
      ciFiles: ciPaths.size,
      scannedBlobs: history.scannedBlobs,
      skippedBlobs: history.skippedBlobs,
      ignoredBlobs: history.ignoredBlobs,
      ...(verification ? { verification } : {}),
    };
  } finally {
    vault?.clear();
    await repo.cleanup();
  }
}
