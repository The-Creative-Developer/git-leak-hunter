/**
 * Stage 2 — Detection engine for one blob: signatures + structured CI/credential parsing +
 * generic key=value candidates → overlap resolution → suppression → entropy → BlobMatch[].
 * The result depends only on (content, file kind, config), so it is cached per blob.
 */
import { createHmac } from 'node:crypto';
import type { ContentUnit, EntropyThresholds, SuppressionReason } from '../types.js';
import { CiParseError, structuredCandidates } from '../ci/index.js';
import { lineColumn, lineText } from '../text.js';
import { redact, redactLine, type Span } from '../report/redact.js';
import { scoreEntropy } from './entropy.js';
import { genericCandidates } from './generic.js';
import { findSignatureCandidates } from './signatures.js';
import { isVendorPath, suppressionReason } from './suppress.js';
import type { BlobMatch, BlobScanResult, Candidate, FileKind } from './types.js';
import { VERIFIABLE_RULES, type Vault } from '../verify/vault.js';

export interface DetectConfig {
  entropy: EntropyThresholds;
  /** Per-run random key for the occurrence-grouping HMAC. Never serialised. */
  runKey: Buffer;
  /** Present only with `--verify`: raw values of verifiable credentials are stored here. */
  vault?: Vault;
}

/** Values with a secret-like key shorter than this are dropped instead of reported as weak. */
const MIN_WEAK_LENGTH = 8;

const DETECTOR_PRIORITY = { signature: 0, 'credential-file': 1, ci: 2, entropy: 3 } as const;

const SIGNATURE_PREFIX =
  /^(?:(?:sk|rk)_(?:live|test)_|gh[pousr]_|github_pat_|xox[abprs]-|AKIA|ASIA|AIDA|https:\/\/hooks\.slack\.com\/services\/)/;

/** Keep the highest-priority candidate where spans overlap (signature > credential-file > ci > entropy). */
export function resolveOverlaps(candidates: Candidate[]): Candidate[] {
  const order = candidates
    .map((c, i) => ({ c, i }))
    .sort(
      (a, b) =>
        DETECTOR_PRIORITY[a.c.detector] - DETECTOR_PRIORITY[b.c.detector] || a.c.start - b.c.start,
    );
  // `kept` stays sorted by start and its spans are disjoint, so only the two neighbours of the
  // insertion point can overlap a new span (binary search instead of a quadratic scan).
  const kept: Array<{ c: Candidate; i: number }> = [];
  for (const entry of order) {
    let lo = 0;
    let hi = kept.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((kept[mid]?.c.start ?? 0) < entry.c.start) lo = mid + 1;
      else hi = mid;
    }
    const before = kept[lo - 1];
    const after = kept[lo];
    if (before && before.c.end > entry.c.start) continue;
    if (after && after.c.start < entry.c.end) continue;
    kept.splice(lo, 0, entry);
  }
  // Re-map pair indices to positions in the returned array.
  const pos = new Map(kept.map((k, idx) => [k.i, idx]));
  return kept.map(({ c }) => {
    const pair = c.pairWith === undefined ? undefined : pos.get(c.pairWith);
    const { pairWith: _drop, ...rest } = c;
    return pair === undefined ? rest : { ...rest, pairWith: pair };
  });
}

function gatherCandidates(content: string, kind: FileKind, cfg: DetectConfig): Candidate[] {
  const out = findSignatureCandidates(content);
  if (kind !== 'generic' && kind !== 'lockfile') {
    try {
      out.push(...structuredCandidates(kind, content));
    } catch (err) {
      if (!(err instanceof CiParseError)) throw err;
      // Malformed YAML: fall back to text scanning, attributed to the CI detector.
      out.push(
        ...genericCandidates(content, {
          minLength: cfg.entropy.minLength,
          detector: 'ci',
          ruleId: `${kind}-literal`,
          secretType: 'CI Config Secret (unparsed)',
        }),
      );
    }
  }
  out.push(...genericCandidates(content, { minLength: cfg.entropy.minLength }));
  return out;
}

/** Characters of context kept on each side of a match. */
const CONTEXT_RADIUS = 100;
const TOKEN_CHAR = /[A-Za-z0-9+/=_-]/;

/**
 * Window [from, to) around a match within its line. Edges never cut through a token, so a clipped
 * fragment of an undetected secret cannot slip past residual masking.
 */
export function contextWindow(
  content: string,
  lineStart: number,
  lineEnd: number,
  start: number,
  end: number,
): [number, number] {
  let from = Math.max(lineStart, start - CONTEXT_RADIUS);
  let to = Math.min(lineEnd, Math.max(end, start) + CONTEXT_RADIUS);
  if (from > lineStart) while (from < start && TOKEN_CHAR.test(content.charAt(from - 1))) from++;
  if (to < lineEnd) while (to > end && TOKEN_CHAR.test(content.charAt(to))) to--;
  return [from, to];
}

export function digestOf(runKey: Buffer, value: string): string {
  return createHmac('sha256', runKey).update(value).digest('hex');
}

export function scanBlob(unit: ContentUnit, kind: FileKind, cfg: DetectConfig): BlobScanResult {
  const { content, lineOffsets } = unit;
  const suppressed: Partial<Record<SuppressionReason, number>> = {};
  const count = (r: SuppressionReason): void => {
    suppressed[r] = (suppressed[r] ?? 0) + 1;
  };

  const candidates = resolveOverlaps(gatherCandidates(content, kind, cfg));
  const keptIndex = new Map<number, number>();
  const matches: BlobMatch[] = [];
  const kept: Candidate[] = [];

  candidates.forEach((c, idx) => {
    const quiet = c.secretLikeKey === false;
    if (c.minLengthApplies && [...c.value].length < cfg.entropy.minLength) return;
    const { line, column } = lineColumn(lineOffsets, c.start);
    const text = lineText(content, lineOffsets, line);
    const signature = c.detector === 'signature';
    const body = signature ? c.value.replace(SIGNATURE_PREFIX, '') : undefined;
    const reason = suppressionReason(c.value, {
      lineText: text,
      signature,
      ...(body === undefined ? {} : { body }),
    });
    if (reason) {
      if (!quiet) count(reason);
      return;
    }
    if (!signature && kind === 'lockfile') {
      count('lockfile');
      return;
    }
    if (c.detector === 'entropy' && isVendorPath(unit.filePath)) {
      count('vendor-path');
      return;
    }
    let weak = false;
    let entropy: number | undefined;
    if (c.entropyRequired) {
      const verdict = scoreEntropy(c.value, cfg.entropy);
      entropy = Math.round(verdict.entropy * 1000) / 1000;
      if (!verdict.passes) {
        if (c.allowWeak && c.value.length >= MIN_WEAK_LENGTH) {
          weak = true;
        } else {
          if (!quiet) count('low-entropy');
          return;
        }
      }
    }
    keptIndex.set(idx, matches.length);
    kept.push(c);
    matches.push({
      ruleId: c.ruleId,
      secretType: c.secretType,
      detector: c.detector,
      line,
      column,
      redactedPreview: c.preview ?? redact(c.value),
      redactedContext: '',
      ...(entropy === undefined ? {} : { entropy }),
      weak,
      digest: digestOf(cfg.runKey, c.value),
      ...(cfg.vault && VERIFIABLE_RULES.has(c.ruleId) ? { vaultRef: cfg.vault.put(c.value) } : {}),
    });
  });

  // Pairing (AWS key ID ↔ secret key) only when both sides survived.
  candidates.forEach((c, idx) => {
    const self = keptIndex.get(idx);
    const other = c.pairWith === undefined ? undefined : keptIndex.get(c.pairWith);
    const target = self === undefined ? undefined : matches[self];
    if (target && other !== undefined) target.pair = other;
  });

  // Context: a bounded window of the match's line, with every kept span in it replaced by its
  // preview. Bounding the window keeps this linear even for one huge line with many matches.
  matches.forEach((m, i) => {
    const c = kept[i];
    if (!c) return;
    const lineStart = lineOffsets[m.line - 1] ?? 0;
    const lineEnd = lineStart + lineText(content, lineOffsets, m.line).length;
    const [from, to] = contextWindow(
      content,
      lineStart,
      lineEnd,
      c.start,
      Math.min(c.end, lineEnd),
    );
    const spans: Span[] = [];
    // `kept` is sorted by start with disjoint spans; walk outwards from this match.
    for (let j = i; j >= 0 && (kept[j]?.end ?? 0) > from; j--) spans.push(spanOf(j));
    for (let j = i + 1; j < kept.length && (kept[j]?.start ?? to) < to; j++) spans.push(spanOf(j));
    m.redactedContext =
      (from > lineStart ? '…' : '') +
      redactLine(content.slice(from, to), spans) +
      (to < lineEnd ? '…' : '');

    function spanOf(j: number): Span {
      const k = kept[j] as Candidate;
      return {
        start: k.start - from,
        end: k.end - from,
        preview: matches[j]?.redactedPreview ?? '',
      };
    }
  });

  return { matches, suppressed };
}
