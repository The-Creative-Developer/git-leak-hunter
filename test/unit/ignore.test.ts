import { describe, expect, it } from 'vitest';
import { isIgnoredPath, parseIgnore } from '../../src/detect/ignore.js';

describe('ignore rules', () => {
  const rules = parseIgnore(
    [
      '# comment',
      'docs/',
      '*.snap',
      '/build/output.txt',
      'src/**/generated/*.ts',
      '!negated',
      'fingerprint:0123456789abcdef0123',
    ].join('\n'),
  );

  it.each([
    ['docs/readme.md', true],
    ['pkg/docs/a.txt', true], // like .gitignore, `docs/` matches at any depth
    ['a/b/c.snap', true],
    ['build/output.txt', true],
    ['x/build/output.txt', false],
    ['src/a/b/generated/x.ts', true],
    ['src/generated/x.ts', true],
    ['src/generated/x.js', false],
    ['negated', false],
  ])('%s → %s', (p, expected) => {
    expect(isIgnoredPath(rules, p)).toBe(expected);
  });

  it('collects fingerprints', () => {
    expect(rules.fingerprints.has('0123456789abcdef0123')).toBe(true);
  });
});
