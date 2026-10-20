/**
 * Redaction. Rule 1: no output ever carries a full secret.
 *
 * - ≥ 12 chars: first 4 + 16 stars + last 4 (fixed star count, so the length is not revealed),
 *   e.g. `AKIA****************WXYZ`.
 * - < 12 chars: at most 2 leading chars + 8 stars.
 */
import { shannonEntropy } from '../detect/entropy.js';

export const STARS = 16;

export function redact(secret: string): string {
  const chars = [...secret];
  if (chars.length >= 12) {
    return chars.slice(0, 4).join('') + '*'.repeat(STARS) + chars.slice(-4).join('');
  }
  const reveal = Math.min(2, Math.floor(chars.length / 4));
  return chars.slice(0, reveal).join('') + '*'.repeat(8);
}

const TOKENISH = /[A-Za-z0-9+/=_-]{16,}/g;

/** Mask any remaining token-like run (≥ 16 chars, mixed digits/letters or high entropy). */
export function maskResidual(text: string): string {
  return text.replace(TOKENISH, (run) => {
    const hasDigit = /\d/.test(run);
    const hasLetter = /[A-Za-z]/.test(run);
    const mixedCase = /[a-z]/.test(run) && /[A-Z]/.test(run);
    if ((hasDigit && hasLetter) || (mixedCase && shannonEntropy(run) >= 3.5)) return redact(run);
    return run;
  });
}

const PLACEHOLDER = '';

export interface Span {
  start: number;
  end: number;
  preview: string;
}

/**
 * Build a one-line context: replace each secret span on the line with its preview, then mask
 * residual token-like runs, then cap the length around the first span.
 */
export function redactLine(line: string, spans: readonly Span[], maxLength = 240): string {
  const sorted = [...spans].sort((a, b) => b.start - a.start);
  let out = line;
  for (const s of sorted) {
    const start = Math.max(0, s.start);
    const end = Math.min(line.length, s.end);
    if (end <= start) continue;
    // Private-use placeholder: cannot occur in maskResidual's token class.
    out = out.slice(0, start) + PLACEHOLDER + out.slice(end);
  }
  // Mask before re-inserting previews so previews themselves are not re-redacted.
  out = maskResidual(out);
  const previews = [...spans].sort((a, b) => a.start - b.start).map((s) => s.preview);
  let i = 0;
  out = out.replace(//g, () => previews[i++] ?? '');
  out = out.replace(/\s+$/, '');
  if (out.length > maxLength) {
    const first = Math.max(0, (spans[0]?.start ?? 0) - 40);
    out = (first > 0 ? '…' : '') + out.slice(first, first + maxLength) + '…';
  }
  return out;
}
