import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { FIXTURE_NAMES, type BuiltFixture, type FixtureName } from '../fixtures/buildRepos.js';
import type { BlobScanner } from '../../src/git/index.js';
import type { ScanResult } from '../../src/pipeline.js';
import { useFixtures } from '../helpers/fixtures.js';
import { git } from '../helpers/git.js';
import { expectNoLeak } from '../helpers/noLeak.js';
import { scanRepo } from '../helpers/scan.js';

const fx = useFixtures();
const schema = JSON.parse(
  await readFile(new URL('../../schema/report.schema.json', import.meta.url), 'utf8'),
);
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

const results = new Map<FixtureName, ScanResult>();
async function scanned(name: FixtureName): Promise<{ fixture: BuiltFixture; result: ScanResult }> {
  const fixture = fx.get().fixtures[name];
  let result = results.get(name);
  if (!result) {
    result = await scanRepo(fixture.dir, path.join(fx.tmp(), 'out', name));
    results.set(name, result);
  }
  return { fixture, result };
}

const key = (p: string, line: number, presence: string) =>
  `${JSON.stringify(p)}:${line}:${presence}`;

describe('end-to-end scan against ground truth', () => {
  it.each(FIXTURE_NAMES.map((n) => [n]))(
    '%s: findings match planted secrets exactly',
    async (name) => {
      const { fixture, result } = await scanned(name);
      const expected = fixture.items
        .filter((i) => i.kind === 'secret')
        .map((i) => key(i.filePath, i.line, i.presence));
      const actual = result.report.findings.map((f) => key(f.filePath, f.line, f.presence));
      expect(actual.sort()).toEqual(expected.sort());
    },
  );

  it.each(FIXTURE_NAMES.map((n) => [n]))(
    '%s: attributes each finding to the introducing commit',
    async (name) => {
      const { fixture, result } = await scanned(name);
      for (const item of fixture.items) {
        if (item.kind !== 'secret') continue;
        const f = result.report.findings.find(
          (x) => x.filePath === item.filePath && x.line === item.line,
        );
        expect(f?.commitHash, `${name}/${item.id}`).toBe(item.commit);
        expect(f?.firstSeenCommit).toBe(item.commit);
      }
    },
  );

  it.each(FIXTURE_NAMES.map((n) => [n]))(
    '%s: report.json is schema-valid and leak-free',
    async (name) => {
      const { fixture, result } = await scanned(name);
      const json = await readFile(result.written.json!, 'utf8');
      const ok = validate(JSON.parse(json));
      expect(validate.errors ?? []).toEqual([]);
      expect(ok).toBe(true);
      expectNoLeak(json, fixture.rawSecrets, `${name} report.json`);
    },
  );

  it.each(FIXTURE_NAMES.map((n) => [n]))(
    '%s: report.html is self-contained and leak-free',
    async (name) => {
      const { fixture, result } = await scanned(name);
      const html = await readFile(result.written.html!, 'utf8');
      expectNoLeak(html, fixture.rawSecrets, `${name} report.html`);
      expect(html).toContain(
        `content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"`,
      );
      // No external resources of any kind.
      expect(html).not.toMatch(/\b(?:src|href|action|poster|data)\s*=\s*["']?\s*(?:https?:)?\/\//i);
      expect(html).not.toMatch(/url\(\s*["']?\s*(?:https?:)?\/\//i);
      expect(html).not.toMatch(/@import|<link\b|<iframe\b|<img\b|<object\b|<embed\b/i);
      expect(html.match(/<script\b/gi)).toHaveLength(1);
    },
  );
});

describe('severity and presence', () => {
  it('labels history-only secrets and keeps severity table semantics', async () => {
    const { result } = await scanned('history-only');
    expect(
      result.report.findings.every((f) => f.presence === 'history-only' && f.severity === 'high'),
    ).toBe(true);
    const id = result.report.findings.find((f) => f.ruleId === 'aws-access-key-id')!;
    const sk = result.report.findings.find((f) => f.ruleId === 'aws-secret-access-key')!;
    expect(id.pairedFingerprint).toBe(sk.fingerprint);
    expect(sk.pairedFingerprint).toBe(id.fingerprint);
  });

  it('rates HEAD private keys and live keys Critical, test keys Medium, docs entropy Low', async () => {
    const { result } = await scanned('head-secrets');
    const by = (rule: string, p?: string) =>
      result.report.findings.find((f) => f.ruleId === rule && (!p || f.filePath === p))!.severity;
    expect(by('private-key')).toBe('critical');
    expect(by('stripe-live-key')).toBe('critical');
    expect(by('stripe-test-key')).toBe('medium');
    expect(by('generic-secret', 'src/client.ts')).toBe('medium');
    expect(by('generic-secret', 'docs/examples/usage.md')).toBe('low');
    expect(result.report.findings[0]!.severity).toBe('critical');
  });

  it('counts other commits carrying the same secret at a path', async () => {
    const { result } = await scanned('blob-reuse');
    const a = result.report.findings.find((f) => f.filePath === 'services/a/settings.js')!;
    expect(a.otherCommitCount).toBe(1); // deleted, then restored with the identical blob
  });

  it('suppresses all false-positive bait with counted reasons', async () => {
    const { result } = await scanned('false-positives');
    expect(result.report.findings).toEqual([]);
    const s = result.report.stats.suppressed;
    expect(s['known-example']).toBe(2);
    expect(s['ci-expression']).toBeGreaterThanOrEqual(3);
    expect(s['env-reference']).toBeGreaterThanOrEqual(3);
  });

  it('skips the binary and the oversize file in the hostile repo', async () => {
    const { result } = await scanned('hostile');
    expect(result.report.stats.skipped).toEqual({ binary: 1, oversize: 1, ignored: 0 });
  });
});

describe('XSS hardening', () => {
  it('escapes hostile file names, author names and commit messages', async () => {
    const { result } = await scanned('hostile');
    const html = await readFile(result.written.html!, 'utf8');
    expect(html).not.toContain("<script>alert('xss')</script>");
    expect(html).not.toContain('<script>alert("author")</script>');
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<svg onload');
    expect(html).not.toContain('</textarea>');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;.js');
    expect(html).toContain('&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;');
    expect(html).toContain('odd/new\\x0aline\\x09and-tab.txt');
  });
});

describe('blob memoization', () => {
  function spy(): { wrap: (s: BlobScanner) => BlobScanner; calls: Map<string, number> } {
    const calls = new Map<string, number>();
    return {
      calls,
      wrap: (s) => (unit, kind) => {
        const k = `${unit.blobHash}:${kind}`;
        calls.set(k, (calls.get(k) ?? 0) + 1);
        return s(unit, kind);
      },
    };
  }

  it('scans each unique blob exactly once with the cache on', async () => {
    const fixture = fx.get().fixtures['blob-reuse'];
    const s = spy();
    const res = await scanRepo(
      fixture.dir,
      path.join(fx.tmp(), 'cache-on'),
      {},
      {},
      { wrapScanner: s.wrap },
    );
    const st = res.report.stats;
    expect([...s.calls.values()].every((n) => n === 1)).toBe(true);
    expect(s.calls.size).toBe(st.uniqueBlobsScanned);
    expect(st.cacheHits).toBeGreaterThan(0);
    expect(st.uniqueBlobsScanned + st.cacheHits).toBe(st.fileVersionsSeen);
    expect(st.uniqueBlobsScanned).toBeLessThan(st.fileVersionsSeen);
  });

  it('--no-cache rescans every file version but yields the same findings', async () => {
    const fixture = fx.get().fixtures['blob-reuse'];
    const s = spy();
    const off = await scanRepo(
      fixture.dir,
      path.join(fx.tmp(), 'cache-off'),
      { cache: false },
      {},
      { wrapScanner: s.wrap },
    );
    const on = (await scanned('blob-reuse')).result;
    const total = [...s.calls.values()].reduce((a, b) => a + b, 0);
    expect(off.report.stats.cacheHits).toBe(0);
    expect(total).toBe(off.report.stats.fileVersionsSeen);
    expect(off.report.stats.uniqueBlobsScanned).toBe(on.report.stats.uniqueBlobsScanned);
    expect(off.report.stats.bytesScanned).toBeGreaterThan(on.report.stats.bytesScanned);
    expect(off.report.findings.map((f) => f.fingerprint).sort()).toEqual(
      on.report.findings.map((f) => f.fingerprint).sort(),
    );
  });
});

describe('scan options', () => {
  it('--no-ci drops CI findings', async () => {
    const fixture = fx.get().fixtures['ci-configs'];
    const res = await scanRepo(fixture.dir, path.join(fx.tmp(), 'no-ci'), { ci: false });
    expect(res.report.findings.some((f) => f.detector === 'ci')).toBe(false);
    expect(res.ciFiles).toBe(0);
  });

  it('--branch walks one branch only', async () => {
    const fixture = fx.get().fixtures['blob-reuse'];
    const res = await scanRepo(fixture.dir, path.join(fx.tmp(), 'branch'), { branch: 'main' });
    expect(res.report.findings.map((f) => f.filePath)).not.toContain('services/d/settings.js');
    await expect(
      scanRepo(fixture.dir, path.join(fx.tmp(), 'b2'), { branch: '--upload-pack=x' }),
    ).rejects.toThrow(/invalid ref/);
    await expect(
      scanRepo(fixture.dir, path.join(fx.tmp(), 'b3'), { branch: 'nope' }),
    ).rejects.toThrow(/unknown branch/);
  });

  it('--max-commits limits the walk; HEAD blobs are still checked', async () => {
    const fixture = fx.get().fixtures['history-only'];
    const res = await scanRepo(fixture.dir, path.join(fx.tmp(), 'max'), { maxCommits: 1 });
    expect(res.report.stats.commitsWalked).toBe(1);
    expect(res.report.findings).toEqual([]);
  });

  it('ignore file: path globs skip files, fingerprints drop findings', async () => {
    const fixture = fx.get().fixtures['ci-configs'];
    const base = (await scanned('ci-configs')).result.report.findings;
    const fp = base.find((f) => f.filePath === 'Dockerfile')!.fingerprint;
    const ignoreFile = path.join(fx.tmp(), 'ignore.txt');
    await writeFile(ignoreFile, `.env\n.ssh/\nfingerprint:${fp}\n`);
    const res = await scanRepo(fixture.dir, path.join(fx.tmp(), 'ign'), {}, { ignoreFile });
    const paths = res.report.findings.map((f) => f.filePath);
    expect(paths).not.toContain('.env');
    expect(paths).not.toContain('.ssh/id_rsa');
    expect(res.report.findings).toHaveLength(base.length - 3);
    expect(res.report.stats.skipped.ignored).toBe(2);
    expect(res.report.stats.suppressed['ignore-file']).toBe(1);
  });

  it('severity overrides from config', async () => {
    const fixture = fx.get().fixtures['head-secrets'];
    const res = await scanRepo(
      fixture.dir,
      path.join(fx.tmp(), 'sev'),
      {},
      { severityOverrides: { 'stripe-test-key': 'high' } },
    );
    expect(res.report.findings.find((f) => f.ruleId === 'stripe-test-key')!.severity).toBe('high');
  });

  it('handles an empty repository (no commits, no HEAD)', async () => {
    const dir = path.join(fx.tmp(), 'empty-repo');
    await git(fx.tmp(), ['init', '-q', dir]);
    const res = await scanRepo(dir, path.join(fx.tmp(), 'empty-out'));
    expect(res.report.repository.head).toBeNull();
    expect(res.report.findings).toEqual([]);
    expect(res.report.stats.commitsWalked).toBe(0);
  });

  it('rejects a non-repository target', async () => {
    await expect(scanRepo(fx.tmp(), path.join(fx.tmp(), 'x'))).rejects.toThrow(
      /not a git repository/,
    );
  });
});
