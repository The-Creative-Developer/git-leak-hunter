/**
 * Stage 2 — Detection engine for one blob: signatures + structured CI/credential parsing +
 * generic key=value candidates → overlap resolution → suppression → entropy → BlobMatch[].
 * The result depends only on (content, file kind, config), so it is cached per blob.
 */
import { createHmac } from 'node:crypto';
import type { ContentUnit, EntropyThresholds, SuppressionReason } from '../types.js';
import { CiParseError, structuredCandidates } from '../ci/index.js';
import { lineColumn, lineText } from '../text.js';
import { redact, redactLine } from '../report/redact.js';
import { scoreEntropy } from './entropy.js';
import { genericCandidates } from './generic.js';
import { findSignatureCandidates } from './signatures.js';
import { isVendorPath, suppressionReason } from './suppress.js';
import type { BlobMatch, BlobScanResult, Candidate, FileKind } from './types.js';

export interface DetectConfig {
  entropy: EntropyThresholds;
  /** Per-run random key for the occurrence-grouping HMAC. Never serialised. */
  runKey: Buffer;
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
  const kept: Array<{ c: Candidate; i: number }> = [];
  for (const entry of order) {
    if (kept.some((k) => entry.c.start < k.c.end && k.c.start < entry.c.end)) continue;
    kept.push(entry);
  }
  // Re-map pair indices to positions in the returned array.
  kept.sort((a, b) => a.c.start - b.c.start);
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
    });
  });

  // Pairing (AWS key ID ↔ secret key) only when both sides survived.
  candidates.forEach((c, idx) => {
    const self = keptIndex.get(idx);
    const other = c.pairWith === undefined ? undefined : keptIndex.get(c.pairWith);
    const target = self === undefined ? undefined : matches[self];
    if (target && other !== undefined) target.pair = other;
  });

  // Context lines: every kept span on the same line is replaced by its preview.
  for (const m of matches) {
    const lineStart = lineOffsets[m.line - 1] ?? 0;
    const text = lineText(content, lineOffsets, m.line);
    const spans = kept
      .map((c, j) => ({ c, preview: matches[j]?.redactedPreview ?? '' }))
      .filter(({ c }) => c.start < lineStart + text.length + 1 && c.end > lineStart)
      .map(({ c, preview }) => ({ start: c.start - lineStart, end: c.end - lineStart, preview }));
    m.redactedContext = redactLine(text, spans);
  }

  return { matches, suppressed };
}
