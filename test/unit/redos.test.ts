import { describe, expect, it } from 'vitest';
import { scanBlob } from '../../src/detect/engine.js';
import type { FileKind } from '../../src/detect/types.js';
import { sanitizeFreeText } from '../../src/report/sanitize.js';
import { privateKeyHeader } from '../fixtures/secretFactory.js';
import { detectConfig, unitOf } from '../helpers/unit.js';

/**
 * Scanned content is attacker-controlled. Each input below made a detector quadratic before the
 * Phase 3 hardening (up to ~65 s for the long identifier); all must now finish well inside the
 * budget. The budget is generous to stay stable on slow CI machines.
 */
const N = 100_000;
const BUDGET_MS = 2_000;

const INPUTS: Record<string, string> = {
  'one long identifier': 'a'.repeat(2 * N),
  'dash-joined run': 'xoxb-' + 'a1-'.repeat(N / 3) + '!',
  'dotted run': 'a.'.repeat(N),
  'unterminated quotes': 'a="'.repeat(N / 3),
  'thousands of AWS key IDs on one line': ('AKIA' + 'B'.repeat(16) + ' ').repeat(N / 21),
  'backslashes in a value': 'key = "' + '\\'.repeat(N),
  'PEM header without footer': privateKeyHeader('RSA') + '\n' + 'QUJD\n'.repeat(N / 5),
  'PEM-like label run': '-----BEGIN ' + 'A '.repeat(N / 2),
  'webhook-like run': 'https://hooks.slack.com/services/T' + 'A'.repeat(N),
  'Dockerfile continuations': 'ENV A=1 \\\n'.repeat(N / 10),
  'deep YAML nesting': '['.repeat(5000) + ']'.repeat(5000),
};

const KINDS: Array<[string, FileKind]> = [
  ['src/a.ts', 'generic'],
  ['Dockerfile', 'dockerfile'],
  ['.github/workflows/a.yml', 'github-actions'],
  ['.env', 'dotenv'],
];

describe('detectors stay fast on adversarial input', () => {
  it.each(Object.entries(INPUTS))('%s', (_name, content) => {
    for (const [p, kind] of KINDS) {
      const t = performance.now();
      scanBlob(unitOf(content, p), kind, detectConfig());
      expect(performance.now() - t, `${kind}`).toBeLessThan(BUDGET_MS);
    }
    const t = performance.now();
    sanitizeFreeText(content);
    expect(performance.now() - t).toBeLessThan(BUDGET_MS);
  });
});
