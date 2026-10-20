// Stage 1 — Git Engine. Input: target repository. Output: ContentUnit[] (streamed).
// Implemented in Phase 2: `git log --all -m --raw -z` walk, `git cat-file --batch` reads,
// blob-hash memoization, presence (in-HEAD / history-only) tracking and measured counters.
import type { ContentUnit } from '../types.js';

export interface GitEngineCounters {
  commitsWalked: number;
  fileVersionsSeen: number;
  uniqueBlobsScanned: number;
  cacheHits: number;
  bytesScanned: number;
}

export interface GitEngine {
  units(): AsyncIterable<ContentUnit>;
  counters(): GitEngineCounters;
  close(): Promise<void>;
}
