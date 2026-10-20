/**
 * Generic secret: a secret-like key name assigned a value of length ≥ minLength. Not reported
 * directly — every candidate goes through suppression and entropy analysis.
 */
import type { Detector } from '../types.js';
import type { Candidate } from './types.js';
import { isSecretLikeKey } from '../ci/common.js';

// key ("quoted" or bare), an assignment operator, then a quoted or bare value — all on one line.
// ReDoS guards (scanned content is attacker-controlled): a key may only start at an identifier
// boundary, keys are at most 128 chars and values at most 512, so matching stays linear in the
// line length. Unquoted values exclude brackets, so type annotations such as
// `tokens: AsyncIterable<string>` are not taken for secrets.
const ASSIGNMENT =
  /(?<![A-Za-z0-9_.-])["']?([A-Za-z_][A-Za-z0-9_.-]{0,127})["']?[ \t]*(?:=>|:=|\?\?=|=|:)[ \t]*(?:(["'`])((?:\\.|(?!\2)[^\\\n]){0,512})\2|([^\s"'`,;()[\]{}<>]{1,512}))/g;

export interface GenericOptions {
  minLength: number;
  ruleId?: string;
  secretType?: string;
  detector?: Detector;
}

export function genericCandidates(content: string, opts: GenericOptions): Candidate[] {
  const out: Candidate[] = [];
  for (const m of content.matchAll(ASSIGNMENT)) {
    const key = m[1] ?? '';
    if (!isSecretLikeKey(key)) continue;
    const quoted = m[3] !== undefined;
    const value = quoted ? (m[3] ?? '') : (m[4] ?? '');
    if ([...value].length < opts.minLength) continue;
    const end = (m.index ?? 0) + m[0].length - (quoted ? 1 : 0);
    const start = end - value.length;
    out.push({
      ruleId: opts.ruleId ?? 'generic-secret',
      secretType: opts.secretType ?? 'Generic Secret',
      detector: opts.detector ?? 'entropy',
      start,
      end,
      value,
      entropyRequired: true,
      minLengthApplies: true,
    });
  }
  return out;
}
