// Stage 2 — Detection Engine. Input: ContentUnit (+ file kind). Output: per-blob matches that the
// analysis step turns into Finding[] (signatures, Shannon entropy, suppression, severity).
export { scanBlob, digestOf, type DetectConfig } from './engine.js';
export { fileKindOf, pathClassOf, type PathClass } from './fileKind.js';
export { classifySeverity, SEVERITY_TABLE, type SeverityOverrides } from './severity.js';
export { emptyIgnoreRules, isIgnoredPath, parseIgnore, type IgnoreRules } from './ignore.js';
export { DEFAULT_ENTROPY, LENGTH_FACTOR, shannonEntropy, scoreEntropy } from './entropy.js';
export type { BlobMatch, BlobScanResult, FileKind } from './types.js';
