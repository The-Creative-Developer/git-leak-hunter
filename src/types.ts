/**
 * Shared data model: Repository → ContentUnit → Finding → Report.
 *
 * Invariant: no type in this file carries a raw secret value. Raw values exist only inside the
 * detection engine while a blob is being scanned and in the verification vault (src/verify), and
 * are never attached to a Finding, so serialising a Finding cannot leak one.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Higher number = more severe. Used for sorting and `--fail-on`. */
export const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export const DETECTORS = ['signature', 'entropy', 'ci', 'credential-file'] as const;
export type Detector = (typeof DETECTORS)[number];

export const VERIFICATION_STATUSES = ['NOT_CHECKED', 'ACTIVE', 'INACTIVE', 'UNVERIFIABLE'] as const;
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];

/** Whether the secret is still reachable from HEAD or only recoverable from history. */
export const PRESENCES = ['in-HEAD', 'history-only'] as const;
export type Presence = (typeof PRESENCES)[number];

/** Where a ContentUnit came from: a commit's changed file, or the HEAD tree. */
export type Origin = 'history' | 'head';

export interface GitIdentity {
  name: string;
  email: string;
}

/** Metadata for one commit, as read from `git log`. All strings are attacker-controlled. */
export interface CommitMeta {
  hash: string;
  parents: string[];
  author: GitIdentity;
  /** ISO-8601 author date. */
  date: string;
  subject: string;
}

/**
 * One version of one file, as seen in one commit. The detection engine scans `content` keyed by
 * `blobHash`; commit/path attribution is applied on top, so a blob is scanned once no matter how
 * many commits or paths reference it.
 */
export interface ContentUnit {
  /** Display name of the repository (never contains URL credentials). */
  repo: string;
  commitHash: string;
  author: GitIdentity;
  date: string;
  filePath: string;
  blobHash: string;
  content: string;
  origin: Origin;
  /** String index (UTF-16 code units) where each line starts; `lineOffsets[0] === 0`. */
  lineOffsets: number[];
}

/** Why a candidate was dropped instead of becoming a Finding. Every reason is counted in stats. */
export const SUPPRESSION_REASONS = [
  'uuid',
  'git-sha',
  'lockfile',
  'placeholder',
  'known-example',
  'repeated-chars',
  'data-uri',
  'ci-expression',
  'env-reference',
  'low-entropy',
  'ignore-file',
  'inline-ignore',
  'vendor-path',
] as const;
export type SuppressionReason = (typeof SUPPRESSION_REASONS)[number];

export interface Finding {
  /** Hash of (ruleId, blobHash, filePath, line, column) — location-based, never derived from the secret. */
  fingerprint: string;
  ruleId: string;
  /** Human label, e.g. "AWS Access Key". */
  secretType: string;
  detector: Detector;
  severity: Severity;
  filePath: string;
  /** Commit the finding is attributed to (the commit that introduced it at this path). */
  commitHash: string;
  /** 1-based, file-relative. */
  line: number;
  /** 1-based column of the match start. */
  column: number;
  redactedPreview: string;
  /** The source line with the secret already replaced by its redacted preview. */
  redactedContext?: string;
  /** Shannon entropy in bits/char, when the entropy layer was involved. */
  entropy?: number;
  blobHash: string;
  author: GitIdentity;
  date: string;
  commitSubject: string;
  firstSeenCommit: string;
  /** Number of other commits in which the same blob appears at this path. */
  otherCommitCount: number;
  presence: Presence;
  verificationStatus: VerificationStatus;
  /** Short, non-sensitive verification note (no account IDs or usernames in clear). */
  verificationNote?: string;
  /** Fingerprint of a paired finding (e.g. AWS access key ID ↔ secret access key). */
  pairedFingerprint?: string;
}

/** Unique blobs skipped as binary/oversize/missing; `ignored` counts file versions on ignored paths. */
export interface SkipCounts {
  binary: number;
  oversize: number;
  ignored: number;
  /** Objects absent from the object store (partial or shallow clone). */
  missing: number;
}

/** Measured counters for one scan. Never estimated. */
export interface ScanStats {
  commitsWalked: number;
  fileVersionsSeen: number;
  uniqueBlobsScanned: number;
  cacheHits: number;
  bytesScanned: number;
  durationMs: number;
  skipped: SkipCounts;
  suppressed: Partial<Record<SuppressionReason, number>>;
}

export interface EntropyThresholds {
  /** bits/char for hex-charset candidates. */
  hex: number;
  /** bits/char for base64-like candidates. */
  base64: number;
  /** Minimum candidate length. */
  minLength: number;
}

export interface ScanOptions {
  entropy: EntropyThresholds;
  maxCommits?: number;
  since?: string;
  branch?: string;
  ci: boolean;
  cache: boolean;
  verify: boolean;
  maxFileBytes: number;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Report {
  schemaVersion: '1.0';
  tool: { name: 'git-leak-hunter'; version: string };
  repository: {
    /** Path or URL as given, with any userinfo (credentials) stripped. */
    target: string;
    /** HEAD commit at scan time, or null for an empty repository. */
    head: string | null;
  };
  scan: {
    startedAt: string;
    finishedAt: string;
    /** Hash of ruleset + config; also the blob-cache key prefix. */
    configHash: string;
    options: ScanOptions;
  };
  summary: {
    total: number;
    bySeverity: SeverityCounts;
    inHead: number;
    historyOnly: number;
  };
  stats: ScanStats;
  findings: Finding[];
}
