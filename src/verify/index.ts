// Stage 3b — optional live verification. Input: Finding[] + in-memory vault. Output: enriched
// Finding[]. Implemented in Phase 3: opt-in only (--verify --confirm-authorized), read-only calls,
// hard host allowlist.
import type { Finding } from '../types.js';

export const VERIFY_HOST_ALLOWLIST: readonly string[] = ['sts.amazonaws.com', 'api.github.com'];

export type VerifyFn = (findings: Finding[]) => Promise<Finding[]>;
