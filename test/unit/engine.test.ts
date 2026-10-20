import { describe, expect, it } from 'vitest';
import { resolveOverlaps, scanBlob } from '../../src/detect/engine.js';
import type { Candidate } from '../../src/detect/types.js';
import { AWS_DOC_EXAMPLE, Rng, SecretFactory } from '../fixtures/secretFactory.js';
import { expectNoLeak } from '../helpers/noLeak.js';
import { detectConfig, unitOf } from '../helpers/unit.js';

const f = new SecretFactory(new Rng(41));
const text = (...l: string[]) => l.join('\n') + '\n';

describe('scanBlob', () => {
  it('finds signatures and generic secrets with file-relative line/column', () => {
    const gh = f.githubToken();
    // 48 chars: random 20–40 char values miss the default 4.5 cap ~1–3% of the time (docs/RULES.md).
    const g = f.generic(48);
    const r = scanBlob(
      unitOf(text('// header', `const t = '${gh}';`, `const apiSecret = "${g}";`)),
      'generic',
      detectConfig(),
    );
    expect(r.matches.map((m) => [m.ruleId, m.line, m.column])).toEqual([
      ['github-token', 2, 12],
      ['generic-secret', 3, 20],
    ]);
  });

  it('never puts a raw secret into its result', () => {
    const secrets = [f.githubToken(), f.generic(40), f.awsAccessKeyId(), f.awsSecretAccessKey()];
    const content = text(
      `a = '${secrets[0]}'`,
      `api_key = "${secrets[1]}"`,
      `id = ${secrets[2]}`,
      `secret = ${secrets[3]}`,
    );
    const r = scanBlob(unitOf(content), 'generic', detectConfig());
    expect(r.matches.length).toBe(4);
    expectNoLeak(JSON.stringify(r), secrets, 'BlobScanResult');
  });

  it('pairs the AWS key ID with its secret key', () => {
    const r = scanBlob(
      unitOf(text(`id = ${f.awsAccessKeyId()}`, `secret = ${f.awsSecretAccessKey()}`)),
      'generic',
      detectConfig(),
    );
    const id = r.matches.findIndex((m) => m.ruleId === 'aws-access-key-id');
    const sk = r.matches.findIndex((m) => m.ruleId === 'aws-secret-access-key');
    expect(r.matches[id]!.pair).toBe(sk);
    expect(r.matches[sk]!.pair).toBe(id);
  });

  it('suppresses the AWS documentation example pair', () => {
    const r = scanBlob(
      unitOf(
        text(`id = ${AWS_DOC_EXAMPLE.keyId}`, `aws_secret_access_key = ${AWS_DOC_EXAMPLE.secret}`),
      ),
      'generic',
      detectConfig(),
    );
    expect(r.matches).toEqual([]);
    expect(r.suppressed['known-example']).toBe(2);
  });

  it('counts low-entropy generic candidates and inline ignores', () => {
    const r = scanBlob(
      unitOf(
        text(
          'password = "ProductionDatabaseHostname"',
          `token = "${f.generic(40)}" # leakhunter:ignore`,
        ),
      ),
      'generic',
      detectConfig(),
    );
    expect(r.matches).toEqual([]);
    expect(r.suppressed).toEqual({ 'low-entropy': 1, 'inline-ignore': 1 });
  });

  it('suppresses generic candidates in lockfiles but still reports signatures', () => {
    const gh = f.githubToken();
    const r = scanBlob(
      unitOf(text(`"token": "${f.generic(40)}"`, `"auth": "${gh}"`), 'package-lock.json'),
      'lockfile',
      detectConfig(),
    );
    expect(r.matches.map((m) => m.ruleId)).toEqual(['github-token']);
    expect(r.suppressed.lockfile).toBe(1);
  });

  it('suppresses entropy-only candidates in vendored code', () => {
    const r = scanBlob(
      unitOf(`api_key = "${f.generic(40)}"\n`, 'node_modules/x/index.js'),
      'generic',
      detectConfig(),
    );
    expect(r.matches).toEqual([]);
    expect(r.suppressed['vendor-path']).toBe(1);
  });

  it('produces the same digest for the same value under one run key', () => {
    const cfg = detectConfig();
    const gh = f.githubToken();
    const a = scanBlob(unitOf(`x = '${gh}'\n`), 'generic', cfg);
    const b = scanBlob(unitOf(`\n\ny = "${gh}"\n`), 'generic', cfg);
    expect(a.matches[0]!.digest).toBe(b.matches[0]!.digest);
    const other = scanBlob(unitOf(`x = '${gh}'\n`), 'generic', detectConfig());
    expect(other.matches[0]!.digest).not.toBe(a.matches[0]!.digest);
  });
});

describe('resolveOverlaps', () => {
  const c = (detector: Candidate['detector'], start: number, end: number): Candidate => ({
    ruleId: detector,
    secretType: detector,
    detector,
    start,
    end,
    value: 'v',
    entropyRequired: false,
  });

  it('prefers signature > credential-file > ci > entropy', () => {
    const out = resolveOverlaps([
      c('entropy', 0, 10),
      c('ci', 2, 8),
      c('signature', 5, 9),
      c('entropy', 20, 30),
    ]);
    expect(out.map((x) => x.detector)).toEqual(['signature', 'entropy']);
  });
});
