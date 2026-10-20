import { readFile } from 'node:fs/promises';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import type { Report } from '../../src/types.js';

const schema = JSON.parse(
  await readFile(new URL('../../schema/report.schema.json', import.meta.url), 'utf8'),
);
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(schema);

const oid = (c: string): string => c.repeat(40);

function sampleReport(): Report {
  return {
    schemaVersion: '1.0',
    tool: { name: 'git-leak-hunter', version: '0.1.0' },
    repository: { target: '/tmp/example-project', head: oid('a') },
    scan: {
      startedAt: '2026-01-01T00:00:00.000Z',
      finishedAt: '2026-01-01T00:00:01.000Z',
      configHash: '0123456789abcdef',
      options: {
        entropy: { hex: 3, base64: 4.5, minLength: 20 },
        ci: true,
        cache: true,
        verify: false,
        maxFileBytes: 2_097_152,
      },
    },
    summary: {
      total: 1,
      bySeverity: { critical: 0, high: 1, medium: 0, low: 0 },
      inHead: 0,
      historyOnly: 1,
    },
    stats: {
      commitsWalked: 4,
      fileVersionsSeen: 7,
      uniqueBlobsScanned: 6,
      cacheHits: 1,
      bytesScanned: 1234,
      durationMs: 12.5,
      skipped: { binary: 0, oversize: 0, ignored: 0 },
      suppressed: { uuid: 2, placeholder: 1 },
    },
    findings: [
      {
        fingerprint: 'fedcba9876543210',
        ruleId: 'aws-access-key-id',
        secretType: 'AWS Access Key',
        detector: 'signature',
        severity: 'high',
        filePath: 'config/aws.ts',
        commitHash: oid('b'),
        line: 42,
        column: 16,
        redactedPreview: 'AKIA****************WXYZ',
        blobHash: oid('c'),
        author: { name: 'Dev', email: 'dev@example.test' },
        date: '2025-01-06T09:00:00Z',
        commitSubject: 'Add AWS config',
        firstSeenCommit: oid('b'),
        otherCommitCount: 0,
        presence: 'history-only',
        verificationStatus: 'NOT_CHECKED',
      },
    ],
  };
}

describe('report.schema.json', () => {
  it('accepts a well-formed report', () => {
    const ok = validate(sampleReport());
    expect(validate.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
  });

  it('rejects unknown finding fields, so a raw-secret field cannot slip in', () => {
    const r = sampleReport() as unknown as { findings: Record<string, unknown>[] };
    r.findings[0]!.secret = 'raw-value';
    expect(validate(r)).toBe(false);
  });

  it('rejects an invalid severity and a missing required field', () => {
    const bad = sampleReport() as unknown as { findings: Record<string, unknown>[] };
    bad.findings[0]!.severity = 'urgent';
    expect(validate(bad)).toBe(false);
    const missing = sampleReport() as unknown as { findings: Record<string, unknown>[] };
    delete missing.findings[0]!.verificationStatus;
    expect(validate(missing)).toBe(false);
  });

  it('rejects unknown suppression reasons', () => {
    const r = sampleReport() as unknown as { stats: { suppressed: Record<string, number> } };
    r.stats.suppressed['made-up'] = 1;
    expect(validate(r)).toBe(false);
  });
});
