import { describe, expect, it } from 'vitest';
import { maskResidual, redact, redactLine, STARS } from '../../src/report/redact.js';
import { sanitizeFreeText } from '../../src/report/sanitize.js';
import { Rng, SecretFactory } from '../fixtures/secretFactory.js';
import { expectNoLeak } from '../helpers/noLeak.js';

const f = new SecretFactory(new Rng(21));

describe('redact', () => {
  it('shows first 4 + 16 stars + last 4 for secrets of 12+ chars', () => {
    const id = f.awsAccessKeyId();
    const r = redact(id);
    expect(r).toBe(`${id.slice(0, 4)}${'*'.repeat(STARS)}${id.slice(-4)}`);
    expect(r).toMatch(/^AKIA\*{16}[A-Z2-7]{4}$/);
    expect(redact('abcdefghijkl')).toBe('abcd****************ijkl');
  });

  it('reveals at most 2 leading chars for short secrets', () => {
    expect(redact('abcdefghijk')).toBe('ab********');
    expect(redact('abcd')).toBe('a********');
    expect(redact('abc')).toBe('********');
    expect(redact('')).toBe('********');
  });

  it('hides the secret length', () => {
    expect(redact(f.generic(20)).length).toBe(redact(f.generic(64)).length);
  });
});

describe('redactLine / maskResidual', () => {
  it('replaces the secret span and masks other token-like runs', () => {
    const a = f.githubToken();
    const b = f.generic(30);
    const line = `call(${a}, "${b}") // ok`;
    const start = line.indexOf(a);
    const out = redactLine(line, [{ start, end: start + a.length, preview: redact(a) }]);
    expectNoLeak(out, [a, b], 'context');
    expect(out).toContain(redact(a));
    expect(out).toContain('// ok');
  });

  it('keeps ordinary words and identifiers', () => {
    expect(maskResidual('process.env.AWS_SECRET_ACCESS_KEY is read here')).toBe(
      'process.env.AWS_SECRET_ACCESS_KEY is read here',
    );
  });

  it('truncates long lines', () => {
    const line = 'x '.repeat(400);
    expect(redactLine(line, [{ start: 0, end: 1, preview: 'x' }]).length).toBeLessThanOrEqual(242);
  });
});

describe('sanitizeFreeText', () => {
  it('masks secrets pasted into commit messages', () => {
    const tok = f.githubToken();
    const key = f.awsAccessKeyId();
    const out = sanitizeFreeText(`oops, committed ${tok} and ${key}`);
    expectNoLeak(out, [tok, key], 'subject');
    expect(out).toContain('oops, committed');
  });
});
