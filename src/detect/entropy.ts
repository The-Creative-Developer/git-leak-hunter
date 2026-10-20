/**
 * Layer 2 — Shannon entropy, H(X) = −Σ p(xᵢ)·log₂ p(xᵢ), in bits per character.
 *
 * Length gotcha: a string of length n has at most log₂(n) bits/char (every character distinct),
 * and a random string's *measured* entropy sits well below that cap. A fixed 4.5 base64 threshold
 * is unreachable below 23 characters and rejects most random 24–32 character secrets. We therefore
 * use a length-normalised threshold:
 *
 *   T_eff = min(T_charset, LENGTH_FACTOR · log₂(min(max(n, minLength), alphabetSize)))
 *
 * so long strings are held to the configured threshold and short ones to a fraction of the
 * maximum a minLength-character string could reach (normalising below minLength would make
 * short words like "postgres1" pass). See docs/RULES.md for the measurements behind the factor.
 */
import type { EntropyThresholds } from '../types.js';

export const LENGTH_FACTOR = 0.85;

export type Charset = 'hex' | 'base64' | 'other';

const ALPHABET_SIZE: Readonly<Record<Charset, number>> = { hex: 16, base64: 64, other: 94 };

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = [...s].length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

export function classifyCharset(s: string): Charset {
  if (/^[0-9a-fA-F]+$/.test(s)) return 'hex';
  if (/^[A-Za-z0-9+/=_-]+$/.test(s)) return 'base64';
  return 'other';
}

export function effectiveThreshold(s: string, cfg: EntropyThresholds): number {
  const charset = classifyCharset(s);
  const configured = charset === 'hex' ? cfg.hex : cfg.base64;
  const n = Math.max([...s].length, cfg.minLength);
  const cap = Math.log2(Math.max(2, Math.min(n, ALPHABET_SIZE[charset])));
  return Math.min(configured, LENGTH_FACTOR * cap);
}

export interface EntropyVerdict {
  entropy: number;
  threshold: number;
  charset: Charset;
  passes: boolean;
}

/** `minLength` is checked by callers that apply it (generic candidates), not here. */
export function scoreEntropy(s: string, cfg: EntropyThresholds): EntropyVerdict {
  const entropy = shannonEntropy(s);
  const threshold = effectiveThreshold(s, cfg);
  return { entropy, threshold, charset: classifyCharset(s), passes: entropy >= threshold };
}

export const DEFAULT_ENTROPY: EntropyThresholds = { hex: 3.0, base64: 4.5, minLength: 20 };
