import { describe, expect, it } from 'vitest';
import {
  DEFAULT_ENTROPY,
  LENGTH_FACTOR,
  classifyCharset,
  effectiveThreshold,
  scoreEntropy,
  shannonEntropy,
} from '../../src/detect/entropy.js';
import { ALNUM, HEX, Rng } from '../fixtures/secretFactory.js';

describe('shannonEntropy', () => {
  it('matches known values', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
    expect(shannonEntropy('ab')).toBe(1);
    expect(shannonEntropy('aabb')).toBe(1);
    expect(shannonEntropy('abcd')).toBe(2);
    expect(shannonEntropy('0123456789abcdef')).toBe(4);
    // p = {a: 1/2, b: 1/4, c: 1/4} → 1.5 bits
    expect(shannonEntropy('aabc')).toBeCloseTo(1.5, 10);
  });

  it('never exceeds log2(n)', () => {
    const rng = new Rng(3);
    for (const n of [5, 20, 40]) {
      const s = rng.chars(ALNUM, n);
      expect(shannonEntropy(s)).toBeLessThanOrEqual(Math.log2(n) + 1e-9);
    }
  });
});

describe('charset and thresholds', () => {
  it('classifies hex, base64-like and other', () => {
    expect(classifyCharset('deadBEEF0123')).toBe('hex');
    expect(classifyCharset('abc+/XYZ_-=')).toBe('base64');
    expect(classifyCharset('p@ss w0rd!')).toBe('other');
  });

  it('normalises the base64 threshold for short strings (length gotcha)', () => {
    // 20 chars can reach at most log2(20) ≈ 4.32 < 4.5
    const s20 = 'Z'.repeat(20);
    expect(effectiveThreshold(s20, DEFAULT_ENTROPY)).toBeCloseTo(LENGTH_FACTOR * Math.log2(20), 10);
    expect(effectiveThreshold(s20, DEFAULT_ENTROPY)).toBeLessThan(Math.log2(20));
    // Long strings use the configured threshold.
    expect(effectiveThreshold('Z'.repeat(64), DEFAULT_ENTROPY)).toBe(4.5);
    expect(effectiveThreshold('z'.repeat(64), { ...DEFAULT_ENTROPY, base64: 5.5 })).toBeCloseTo(
      LENGTH_FACTOR * 6,
      10,
    );
  });

  it('does not normalise below minLength', () => {
    expect(effectiveThreshold('Z'.repeat(9), DEFAULT_ENTROPY)).toBeCloseTo(
      LENGTH_FACTOR * Math.log2(20),
      10,
    );
    expect(scoreEntropy('postgres1', DEFAULT_ENTROPY).passes).toBe(false);
  });

  it('uses the hex threshold for hex strings', () => {
    expect(effectiveThreshold('ab'.repeat(16), DEFAULT_ENTROPY)).toBe(3.0);
    expect(effectiveThreshold('ab'.repeat(16), { ...DEFAULT_ENTROPY, hex: 3.3 })).toBe(3.3);
  });

  it('passes random secrets and rejects ordinary identifiers', () => {
    const rng = new Rng(11);
    expect(scoreEntropy(rng.chars(ALNUM, 24), DEFAULT_ENTROPY).passes).toBe(true);
    expect(scoreEntropy(rng.chars(ALNUM, 40), DEFAULT_ENTROPY).passes).toBe(true);
    expect(scoreEntropy(rng.chars(HEX, 32), DEFAULT_ENTROPY).passes).toBe(true);
    expect(scoreEntropy('getUserAccountSettingsForTenant', DEFAULT_ENTROPY).passes).toBe(false);
    expect(scoreEntropy('ProductionDatabaseHostname', DEFAULT_ENTROPY).passes).toBe(false);
  });
});
