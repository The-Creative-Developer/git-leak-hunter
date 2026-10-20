import path from 'node:path';
import { DEFAULT_ENTROPY } from '../../src/detect/entropy.js';
import { DEFAULT_MAX_FILE_BYTES } from '../../src/config.js';
import { runScan, type ScanHooks, type ScanRequest, type ScanResult } from '../../src/pipeline.js';
import type { ScanOptions } from '../../src/types.js';

export function defaultOptions(over: Partial<ScanOptions> = {}): ScanOptions {
  return {
    entropy: { ...DEFAULT_ENTROPY },
    ci: true,
    cache: true,
    verify: false,
    maxFileBytes: DEFAULT_MAX_FILE_BYTES,
    ...over,
  };
}

export function scanRepo(
  dir: string,
  outDir: string,
  over: Partial<ScanOptions> = {},
  extra: Partial<ScanRequest> = {},
  hooks: ScanHooks = {},
): Promise<ScanResult> {
  return runScan(
    {
      target: dir,
      outDir: path.join(outDir),
      formats: ['html', 'json'],
      options: defaultOptions(over),
      ...extra,
    },
    hooks,
  );
}
