// Wires DETECT → ANALYZE → VERIFY → REPORT. Implemented in Phase 2.
import type { Report, ScanOptions } from './types.js';

export interface ScanRequest {
  target: string;
  outDir: string;
  formats: ReadonlyArray<'html' | 'json'>;
  options: ScanOptions;
}

export type RunScan = (request: ScanRequest) => Promise<Report>;
