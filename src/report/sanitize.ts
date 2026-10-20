/** Free text from the repository (commit subjects) may itself contain a secret: mask it. */
import { findSignatureCandidates } from '../detect/signatures.js';
import { maskResidual, redact } from './redact.js';

export function sanitizeFreeText(input: string, maxLength = 200): string {
  // Only the displayed prefix (plus margin for a token straddling the cut) is ever scanned.
  const text = input.slice(0, maxLength + 512);
  const spans = findSignatureCandidates(text).sort((a, b) => b.start - a.start);
  let out = text;
  for (const s of spans)
    out = out.slice(0, s.start) + (s.preview ?? redact(s.value)) + out.slice(s.end);
  out = maskResidual(out);
  return out.length > maxLength ? `${out.slice(0, maxLength)}…` : out;
}
