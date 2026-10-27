import { describe, expect, it } from 'vitest';
import { renderHtml } from '../../src/report/html.js';
import { buildReport } from '../../src/report/json.js';
import type { Finding, Report } from '../../src/types.js';

const oid = (c: string): string => c.repeat(40);
let n = 0;
function finding(over: Partial<Finding> = {}): Finding {
  n++;
  return {
    fingerprint: n.toString(16).padStart(32, '0'),
    ruleId: 'github-token',
    secretType: 'GitHub Token',
    detector: 'signature',
    severity: 'high',
    filePath: `src/f${n}.ts`,
    commitHash: oid('a'),
    line: 3,
    column: 7,
    redactedPreview: 'ghp_****************AB12',
    redactedContext: "const t = 'ghp_****************AB12';",
    blobHash: oid('b'),
    author: { name: 'Dev', email: 'dev@example.test' },
    date: '2025-01-06T09:00:00Z',
    commitSubject: 'add token',
    firstSeenCommit: oid('a'),
    otherCommitCount: 0,
    presence: 'in-HEAD',
    verificationStatus: 'NOT_CHECKED',
    ...over,
  };
}

function report(findings: Finding[]): Report {
  return buildReport({
    target: '/tmp/demo-repo',
    head: oid('c'),
    startedAt: new Date('2026-01-01T00:00:00Z'),
    finishedAt: new Date('2026-01-01T00:00:01Z'),
    configHash: '0123456789abcdef',
    options: {
      entropy: { hex: 3, base64: 4.5, minLength: 20 },
      ci: true,
      cache: true,
      verify: false,
      maxFileBytes: 2 << 20,
    },
    stats: {
      commitsWalked: 4,
      fileVersionsSeen: 10,
      uniqueBlobsScanned: 7,
      cacheHits: 3,
      bytesScanned: 4096,
      durationMs: 42,
      skipped: { binary: 0, oversize: 0, ignored: 0, missing: 0 },
      suppressed: { uuid: 2 },
    },
    findings,
  });
}

describe('report.html', () => {
  const hostile = '"><svg onload=alert(1)>';
  const html = renderHtml(
    report([
      finding({
        severity: 'critical',
        ruleId: 'private-key',
        secretType: 'Private Key',
        redactedPreview: 'BEGIN RSA PRIVATE KEY [REDACTED, 14 lines]',
      }),
      finding({
        presence: 'history-only',
        filePath: `x/${hostile}.ts`,
        commitSubject: hostile,
        otherCommitCount: 2,
      }),
      finding({
        severity: 'low',
        detector: 'entropy',
        ruleId: 'generic-secret',
        secretType: 'Generic Secret',
        entropy: 4.71,
      }),
    ]),
  );

  it('renders one card per finding, each with a text severity label', () => {
    const cards = html.match(/<article class="card sev-/g) ?? [];
    expect(cards).toHaveLength(3);
    for (const label of ['CRITICAL', 'HIGH', 'LOW']) expect(html).toContain(`Severity: ${label}.`);
  });

  it('includes overview, findings explorer and scan details', () => {
    for (const id of [
      'id="overview"',
      'id="findings"',
      'id="details"',
      'id="q"',
      'data-sev-chip="critical"',
      'data-presence-btn="history-only"',
    ]) {
      expect(html).toContain(id);
    }
    expect(html).toContain('Critical exposure');
    expect(html).toContain('30% reused'); // 3 cache hits of 10 file versions
    expect(html).toContain('History-only · deleted, still recoverable');
    expect(html).toContain('Remediation');
    expect(html).toContain('a history rewrite must cover all of them');
  });

  it('keeps attacker-controlled strings inside escaped text and attributes', () => {
    expect(html).not.toContain('<svg onload');
    expect(html).toContain('&quot;&gt;&lt;svg onload=alert(1)&gt;');
    // Only the tool's own inline SVG elements exist.
    const svgs = html.match(/<svg\b[^>]*>/g) ?? [];
    for (const s of svgs) expect(s).not.toMatch(/onload|onerror|href/i);
  });

  it('draws the redaction bar without dropping the stars from the text', () => {
    expect(html).toContain(
      'ghp_<span class="blk" aria-label="redacted">****************</span>AB12',
    );
    expect(html).toContain('<span class="blk" aria-label="redacted">[REDACTED, 14 lines]</span>');
  });

  it('shows a clean state with no findings', () => {
    const clean = renderHtml(report([]));
    expect(clean).toContain('No secrets found');
    expect(clean).toContain('No findings');
    expect(clean).not.toContain('<article');
  });
});
