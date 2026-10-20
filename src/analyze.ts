/**
 * ANALYZE: turn per-blob matches (cached, attribution-free) into Findings with per-commit
 * attribution: the first commit that introduced the secret at a path, how many other commits
 * carry it there, and whether it is still present at HEAD or recoverable from history only.
 *
 * Occurrences of the same secret at the same path and rule — across file versions whose blobs
 * differ only elsewhere — are one finding. They are grouped by a keyed HMAC of the value with a
 * per-run random key; the digest is never serialised.
 */
import { createHash } from 'node:crypto';
import type { Finding } from './types.js';
import type { BlobMatch } from './detect/types.js';
import type { Occurrence } from './git/index.js';
import { classifySeverity, type SeverityOverrides } from './detect/severity.js';
import { pathClassOf } from './detect/fileKind.js';
import type { IgnoreRules } from './detect/ignore.js';
import { sanitizeFreeText } from './report/sanitize.js';
import type { BlobScanResult } from './detect/types.js';

export function fingerprintOf(
  ruleId: string,
  blobHash: string,
  filePath: string,
  line: number,
  column: number,
): string {
  return createHash('sha256')
    .update(`${ruleId}\0${blobHash}\0${filePath}\0${line}\0${column}`)
    .digest('hex')
    .slice(0, 32);
}

interface Group {
  fingerprint: string;
  first: Occurrence;
  match: BlobMatch;
  pairKey?: string;
  commits: Set<string>;
}

const groupKey = (path: string, ruleId: string, digest: string): string =>
  `${path}\0${ruleId}\0${digest}`;

export interface AnalyzeInput {
  occurrences: readonly Occurrence[];
  headResults: ReadonlyMap<string, BlobScanResult>;
  severityOverrides?: SeverityOverrides;
  ignore?: IgnoreRules;
}

export interface AnalyzeOutput {
  findings: Finding[];
  /** Findings dropped by `fingerprint:` ignore rules. */
  ignoredByFingerprint: number;
  /** fingerprint → vault reference, for findings whose raw value is held for verification. */
  vaultRefs: Map<string, string>;
}

export function analyze(input: AnalyzeInput): AnalyzeOutput {
  const groups = new Map<string, Group>();
  for (const occ of input.occurrences) {
    const { matches } = occ.result;
    for (const m of matches) {
      const key = groupKey(occ.path, m.ruleId, m.digest);
      let g = groups.get(key);
      if (!g) {
        const paired = m.pair === undefined ? undefined : matches[m.pair];
        g = {
          fingerprint: fingerprintOf(m.ruleId, occ.blob, occ.path, m.line, m.column),
          first: occ,
          match: m,
          ...(paired ? { pairKey: groupKey(occ.path, paired.ruleId, paired.digest) } : {}),
          commits: new Set(),
        };
        groups.set(key, g);
      }
      g.commits.add(occ.commit.hash);
    }
  }

  const headKeys = new Set<string>();
  for (const [path, result] of input.headResults) {
    for (const m of result.matches) headKeys.add(groupKey(path, m.ruleId, m.digest));
  }

  const findings: Finding[] = [];
  let ignoredByFingerprint = 0;
  const vaultRefs = new Map<string, string>();
  for (const [key, g] of groups) {
    const { fingerprint } = g;
    if (input.ignore?.fingerprints.has(fingerprint)) {
      ignoredByFingerprint++;
      continue;
    }
    const presence = headKeys.has(key) ? 'in-HEAD' : 'history-only';
    const m = g.match;
    const severity = classifySeverity(
      {
        ruleId: m.ruleId,
        detector: m.detector,
        presence,
        verificationStatus: 'NOT_CHECKED',
        pathClass: pathClassOf(g.first.path),
        weak: m.weak,
      },
      input.severityOverrides,
    );
    const paired = g.pairKey ? groups.get(g.pairKey)?.fingerprint : undefined;
    if (m.vaultRef) vaultRefs.set(fingerprint, m.vaultRef);
    findings.push({
      fingerprint,
      ruleId: m.ruleId,
      secretType: m.secretType,
      detector: m.detector,
      severity,
      filePath: g.first.path,
      commitHash: g.first.commit.hash,
      line: m.line,
      column: m.column,
      redactedPreview: m.redactedPreview,
      ...(m.redactedContext ? { redactedContext: m.redactedContext } : {}),
      ...(m.entropy === undefined ? {} : { entropy: m.entropy }),
      blobHash: g.first.blob,
      author: {
        name: sanitizeFreeText(g.first.commit.author.name, 120),
        email: sanitizeFreeText(g.first.commit.author.email, 120),
      },
      date: g.first.commit.date,
      commitSubject: sanitizeFreeText(g.first.commit.subject),
      firstSeenCommit: g.first.commit.hash,
      otherCommitCount: g.commits.size - 1,
      presence,
      verificationStatus: 'NOT_CHECKED',
      ...(paired ? { pairedFingerprint: paired } : {}),
    });
  }
  return { findings: sortFindings(findings), ignoredByFingerprint, vaultRefs };
}

const RANK = { critical: 4, high: 3, medium: 2, low: 1 } as const;

/** Severity (desc), then recency (desc), then path and line. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      RANK[b.severity] - RANK[a.severity] ||
      Date.parse(b.date) - Date.parse(a.date) ||
      a.filePath.localeCompare(b.filePath) ||
      a.line - b.line ||
      a.ruleId.localeCompare(b.ruleId),
  );
}
