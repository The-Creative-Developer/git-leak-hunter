import { describe, expect, it } from 'vitest';
import { isLockfilePath, isVendorPath, suppressionReason } from '../../src/detect/suppress.js';
import { AWS_DOC_EXAMPLE, Rng, SecretFactory } from '../fixtures/secretFactory.js';

const f = new SecretFactory(new Rng(1));
const reason = (value: string, lineText = `x = "${value}"`) =>
  suppressionReason(value, { lineText, signature: false });

describe('suppressionReason', () => {
  it.each([
    ['uuid', f.uuid()],
    ['git-sha', f.gitSha()],
    ['lockfile', f.integritySha512()],
    ['lockfile', f.goSumHash()],
    ['placeholder', 'your_api_key_here'],
    ['placeholder', 'changeme_changeme_changeme'],
    ['placeholder', 'xxxxxxxxxxxxxxxxxxxxxxxx'],
    ['placeholder', '<TOKEN>'],
    ['ci-expression', '${{ secrets.DEPLOY_TOKEN }}'],
    ['env-reference', '${API_TOKEN}'],
    ['env-reference', '$CI_REGISTRY_PASSWORD'],
    ['env-reference', 'process.env.APP_SECRET'],
    ['env-reference', '%APPDATA_SECRET%'],
    ['repeated-chars', 'abababababababababababab'],
    ['known-example', AWS_DOC_EXAMPLE.keyId],
    ['known-example', AWS_DOC_EXAMPLE.secret],
  ])('%s: %#', (expected, value) => {
    expect(reason(value)).toBe(expected);
  });

  it('suppresses base64 after a data: URI', () => {
    const uri = f.dataUriPng(60);
    const body = uri.split(',')[1]!;
    expect(reason(body, `const LOGO = '${uri}';`)).toBe('data-uri');
  });

  it('honours the inline leakhunter:ignore comment, also for signatures', () => {
    const tok = f.githubToken();
    expect(
      suppressionReason(tok, { lineText: `t = "${tok}" // leakhunter:ignore`, signature: true }),
    ).toBe('inline-ignore');
  });

  it('leaves a random secret alone', () => {
    expect(reason(f.generic(32))).toBeNull();
  });

  it('applies only format-safe checks to signature matches', () => {
    expect(
      suppressionReason('A'.repeat(20), { lineText: '', signature: true, body: 'A'.repeat(16) }),
    ).toBe('repeated-chars');
    const tok = f.githubToken();
    expect(
      suppressionReason(tok, { lineText: tok, signature: true, body: tok.slice(4) }),
    ).toBeNull();
  });
});

describe('path helpers', () => {
  it('recognises lockfiles and vendor paths', () => {
    expect(isLockfilePath('a/b/package-lock.json')).toBe(true);
    expect(isLockfilePath('Cargo.lock')).toBe(true);
    expect(isLockfilePath('src/lock.ts')).toBe(false);
    expect(isVendorPath('node_modules/x/index.js')).toBe(true);
    expect(isVendorPath('static/app.min.js')).toBe(true);
    expect(isVendorPath('src/app.js')).toBe(false);
  });
});
