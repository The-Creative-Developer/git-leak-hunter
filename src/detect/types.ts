/** Internal detection types. `Candidate.value` is the only place a raw secret exists. */
import type { Detector, SuppressionReason } from '../types.js';

/** How a file is parsed, decided from its path. Part of the blob-cache key. */
export type FileKind =
  | 'generic'
  | 'lockfile'
  | 'github-actions'
  | 'gitlab-ci'
  | 'dockerfile'
  | 'dotenv'
  | 'npmrc'
  | 'credentials-json'
  | 'docker-config'
  | 'ssh-key'
  | 'pgpass'
  | 'netrc'
  | 'git-credentials';

/** A possible secret before suppression/entropy evaluation. Never leaves the detection engine. */
export interface Candidate {
  ruleId: string;
  secretType: string;
  detector: Detector;
  /** Span of the secret value in the file content. */
  start: number;
  end: number;
  /** Raw value — internal only, never serialised. */
  value: string;
  /** The value must pass the entropy check (all non-signature candidates, AWS secret keys). */
  entropyRequired: boolean;
  /** Key name looked secret-like, so a low-entropy literal is reported as a weak (Low) finding. */
  allowWeak?: boolean;
  /**
   * false for literals whose key name is not secret-like: they are reported only when the value
   * passes entropy, and dropping them is not counted as a suppression.
   */
  secretLikeKey?: boolean;
  /** Generic key=value candidates must also satisfy `minLength`. */
  minLengthApplies?: boolean;
  /** Overrides the default redacted preview (private keys). */
  preview?: string;
  /** Index of a paired candidate (AWS access key ID ↔ secret access key). */
  pairWith?: number;
}

/** One detected secret inside one blob. Cached per (blob, file kind). Contains no raw value. */
export interface BlobMatch {
  ruleId: string;
  secretType: string;
  detector: Detector;
  line: number;
  column: number;
  redactedPreview: string;
  redactedContext: string;
  entropy?: number;
  weak: boolean;
  /** Keyed HMAC of the raw value with a per-run random key; used only to group occurrences. */
  digest: string;
  /** Opaque vault reference (only with `--verify`, only for verifiable rules). */
  vaultRef?: string;
  /** Index into the same result's `matches` of the paired match, if any. */
  pair?: number;
}

export interface BlobScanResult {
  matches: BlobMatch[];
  suppressed: Partial<Record<SuppressionReason, number>>;
}
