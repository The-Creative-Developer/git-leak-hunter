/** Shared helpers for CI/CD and credential-file parsers. */
import type { Detector } from '../types.js';
import type { Candidate } from '../detect/types.js';

const SECRET_KEY =
  /(api[_.-]?key|apikey|secret|token|passw(?:or)?d|passphrase|pwd|auth(?!ors?\b|or_?(?:name|email)\b)|credential|access[_.-]?key|private[_.-]?key)/i;
const NON_SECRET_SUFFIX =
  /(?:url|uri|path|file|dir|name|type|endpoint|header|length|count|expiry|expires|ttl|key_?id|_id|enabled|method)$/i;

/** True if a variable/key name suggests its value is a credential. */
export function isSecretLikeKey(key: string): boolean {
  return SECRET_KEY.test(key) && !NON_SECRET_SUFFIX.test(key);
}

export interface LiteralSpec {
  ruleId: string;
  secretType: string;
  detector: Detector;
  key: string;
  value: string;
  start: number;
}

/**
 * Candidate for a literal value assigned to `key`. Values with a secret-like key are always
 * evaluated (and may be reported as weak); other values are only reported if they pass entropy.
 */
export function literalCandidate(spec: LiteralSpec): Candidate | null {
  const value = spec.value.trim();
  if (value.length === 0) return null;
  const start = spec.start + spec.value.indexOf(value);
  const secretLikeKey = isSecretLikeKey(spec.key);
  return {
    ruleId: spec.ruleId,
    secretType: spec.secretType,
    detector: spec.detector,
    start,
    end: start + value.length,
    value,
    entropyRequired: true,
    allowWeak: secretLikeKey,
    secretLikeKey,
    // Without a secret-like key name, only long high-entropy values are worth reporting.
    minLengthApplies: !secretLikeKey,
  };
}

export class CiParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CiParseError';
  }
}
