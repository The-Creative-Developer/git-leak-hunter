import { randomBytes } from 'node:crypto';
import type { ContentUnit } from '../../src/types.js';
import { computeLineOffsets } from '../../src/text.js';
import { DEFAULT_ENTROPY } from '../../src/detect/entropy.js';
import type { DetectConfig } from '../../src/detect/engine.js';

export function unitOf(content: string, filePath = 'src/app.ts'): ContentUnit {
  return {
    repo: 'unit',
    commitHash: 'a'.repeat(40),
    author: { name: 'Unit', email: 'unit@example.test' },
    date: '2025-01-06T09:00:00Z',
    filePath,
    blobHash: 'b'.repeat(40),
    content,
    origin: 'history',
    lineOffsets: computeLineOffsets(content),
  };
}

export function detectConfig(): DetectConfig {
  return { entropy: { ...DEFAULT_ENTROPY }, runKey: randomBytes(32) };
}
