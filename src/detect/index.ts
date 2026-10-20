// Stage 2 — Detection Engine. Input: ContentUnit. Output: Finding[].
// Implemented in Phase 2: signatures, Shannon entropy, false-positive suppression, severity table.
import type { ContentUnit, Finding } from '../types.js';

export type DetectFn = (unit: ContentUnit) => Finding[];
