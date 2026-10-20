import { describe, expect, it } from 'vitest';
import { classifySeverity, SEVERITY_TABLE, type SeverityInput } from '../../src/detect/severity.js';

const base: SeverityInput = {
  ruleId: 'github-token',
  detector: 'signature',
  presence: 'in-HEAD',
  verificationStatus: 'NOT_CHECKED',
  pathClass: 'app',
  weak: false,
};
const sev = (over: Partial<SeverityInput>) => classifySeverity({ ...base, ...over });

describe('severity table', () => {
  it('Critical: verified ACTIVE, private key / live key at HEAD', () => {
    expect(
      sev({
        verificationStatus: 'ACTIVE',
        detector: 'entropy',
        ruleId: 'generic-secret',
        pathClass: 'docs',
      }),
    ).toBe('critical');
    expect(sev({ ruleId: 'private-key' })).toBe('critical');
    expect(sev({ ruleId: 'stripe-live-key' })).toBe('critical');
  });

  it('High: real-format credentials (incl. private/live keys in history only), CI literals, credential files', () => {
    expect(sev({ ruleId: 'private-key', presence: 'history-only' })).toBe('high');
    expect(sev({ ruleId: 'stripe-live-key', presence: 'history-only' })).toBe('high');
    for (const ruleId of [
      'aws-access-key-id',
      'aws-secret-access-key',
      'github-token',
      'slack-token',
      'slack-webhook',
    ]) {
      expect(sev({ ruleId })).toBe('high');
    }
    expect(sev({ ruleId: 'github-actions-literal', detector: 'ci' })).toBe('high');
    expect(sev({ ruleId: 'dotenv-secret', detector: 'credential-file' })).toBe('high');
  });

  it('Medium: entropy in app code, Stripe test keys', () => {
    expect(sev({ ruleId: 'generic-secret', detector: 'entropy' })).toBe('medium');
    expect(sev({ ruleId: 'stripe-test-key' })).toBe('medium');
  });

  it('Low: entropy in tests/docs/examples/fixtures, weak literals', () => {
    for (const pathClass of ['test', 'docs', 'example', 'fixture'] as const) {
      expect(sev({ ruleId: 'generic-secret', detector: 'entropy', pathClass })).toBe('low');
    }
    expect(sev({ ruleId: 'dotenv-secret', detector: 'credential-file', weak: true })).toBe('low');
  });

  it('applies per-rule overrides, but never below a verified ACTIVE', () => {
    expect(
      classifySeverity({ ...base, ruleId: 'stripe-test-key' }, { 'stripe-test-key': 'high' }),
    ).toBe('high');
    expect(
      classifySeverity({ ...base, verificationStatus: 'ACTIVE' }, { 'github-token': 'low' }),
    ).toBe('critical');
  });

  it('is a pure table with a catch-all row', () => {
    expect(SEVERITY_TABLE.at(-1)!.id).toBe('default');
    expect(new Set(SEVERITY_TABLE.map((r) => r.id)).size).toBe(SEVERITY_TABLE.length);
  });
});
