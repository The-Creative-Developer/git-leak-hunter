import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { main } from '../../src/cli.js';
import { DEFAULT_MAX_FILE_BYTES } from '../../src/config.js';
import { DEFAULT_ENTROPY } from '../../src/detect/entropy.js';
import {
  assertScopedQuery,
  buildQuery,
  DorkScopeError,
  runDork,
  type DorkRequest,
} from '../../src/dork/index.js';
import { VERIFY_HOST_ALLOWLIST, type FetchLike } from '../../src/verify/http.js';
import { Rng, SecretFactory } from '../fixtures/secretFactory.js';
import { expectNoLeak } from '../helpers/noLeak.js';

const f = new SecretFactory(new Rng(4242));
const TOKEN = ['tok', 'en-for-tests-', 'only'].join('');
const GH = f.githubToken();
const DB_PASSWORD = f.generic(28);
const RAW = [GH, DB_PASSWORD, TOKEN];
const sha = (c: string) => c.repeat(40);

const FILES: Record<string, { repo: string; path: string; content: string }> = {
  [sha('a')]: {
    repo: 'alice/app',
    path: 'src/config.js',
    content: `module.exports = { token: '${GH}' };\n`,
  },
  [sha('b')]: {
    repo: 'alice/app',
    path: '.env',
    content: `DB_HOST=localhost\nDB_PASSWORD=${DB_PASSWORD}\n`,
  },
  [sha('c')]: {
    repo: 'alice/app',
    path: 'README.md',
    content: '# app\nUse AKIA… keys from the vault.\n',
  },
  [sha('d')]: { repo: 'mallory/evil', path: 'x.js', content: `t='${f.githubToken()}'\n` },
};

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });

interface MockOptions {
  login?: string;
  orgRole?: string | null;
  rateLimitSearchAfter?: number;
}

/** A tiny fake of the GitHub REST API; fails the test on any non-allowlisted host. */
function mockGitHub(o: MockOptions = {}) {
  const queries: string[] = [];
  const paths: string[] = [];
  let searches = 0;
  const fn = vi.fn<FetchLike>(async (input, init) => {
    const url = new URL(input);
    if (!VERIFY_HOST_ALLOWLIST.has(url.hostname) || url.protocol !== 'https:')
      throw new Error(`TEST FAILURE: host ${url.hostname}`);
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`);
    paths.push(url.pathname);
    if (url.pathname === '/user') return json({ login: o.login ?? 'alice' });
    if (url.pathname.startsWith('/user/memberships/orgs/')) {
      return o.orgRole
        ? json({ state: 'active', role: o.orgRole })
        : json({ message: 'Not Found' }, 404);
    }
    if (url.pathname === '/search/code') {
      searches++;
      if (o.rateLimitSearchAfter !== undefined && searches > o.rateLimitSearchAfter) {
        return json({ message: 'rate limited' }, 403, { 'x-ratelimit-remaining': '0' });
      }
      queries.push(url.searchParams.get('q') ?? '');
      const items = Object.entries(FILES).map(([s, v]) => ({
        path: v.path,
        sha: s,
        repository: { full_name: v.repo },
      }));
      return json({ total_count: items.length, incomplete_results: false, items });
    }
    const blob = /^\/repos\/([^/]+\/[^/]+)\/git\/blobs\/([0-9a-f]{40})$/.exec(url.pathname);
    if (blob) {
      const file = FILES[blob[2]!];
      if (!file || file.repo !== blob[1]) return json({ message: 'Not Found' }, 404);
      return json({ content: Buffer.from(file.content).toString('base64'), encoding: 'base64' });
    }
    if (/^\/repos\/[^/]+\/[^/]+\/commits$/.test(url.pathname)) {
      return json([
        {
          sha: sha('e'),
          commit: {
            author: { name: 'Alice', email: 'alice@example.test', date: '2026-01-02T03:04:05Z' },
            message: 'Add config\n\nbody',
          },
        },
      ]);
    }
    return json({ message: 'unexpected' }, 500);
  });
  return { fn, queries, paths };
}

let tmp: string;
beforeAll(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), 'glh-dork-'));
});
afterAll(async () => {
  await rm(tmp, { recursive: true, force: true });
});

const request = (over: Partial<DorkRequest> = {}): DorkRequest => ({
  owner: 'alice',
  ownerType: 'user',
  maxResults: 100,
  outDir: path.join(tmp, 'out'),
  formats: ['html', 'json'],
  entropy: { ...DEFAULT_ENTROPY },
  maxFileBytes: DEFAULT_MAX_FILE_BYTES,
  token: TOKEN,
  ...over,
});
const fast = { searchDelayMs: 0, coreDelayMs: 0 };

describe('dork query scoping', () => {
  it('always adds exactly one owner qualifier', () => {
    expect(buildQuery('filename:.env', 'alice', 'user')).toBe('filename:.env user:alice');
    expect(buildQuery('password', 'acme-corp', 'org')).toBe('password org:acme-corp');
  });

  it.each([
    ['AKIA', ''],
    ['AKIA user:alice user:bob', 'alice'],
    ['AKIA org:alice', 'alice'],
    ['AKIA repo:bob/x user:alice', 'alice'],
    ['AKIA OR ghp user:alice', 'alice'],
    ['AKIA -user:bob user:alice', 'alice'],
  ])('refuses %j', (q) => {
    expect(() => assertScopedQuery(q, 'alice', 'user')).toThrow(DorkScopeError);
  });

  it('refuses user-supplied scope qualifiers and invalid owners', () => {
    expect(() => buildQuery('AKIA user:mallory', 'alice', 'user')).toThrow(/qualifiers/);
    for (const bad of ['', '-alice', 'alice-', 'a--b', 'x'.repeat(40), 'alice bob', 'alice/app']) {
      expect(() => buildQuery('AKIA', bad, 'user')).toThrow(DorkScopeError);
    }
  });
});

describe('dork (mocked GitHub API)', () => {
  it('produces redacted, schema-valid findings for the owner only', async () => {
    const gh = mockGitHub();
    const res = await runDork(request({ terms: ['filename:.env', 'module.exports'] }), {
      fetchImpl: gh.fn,
      ...fast,
    });

    expect(gh.queries).toEqual(['filename:.env user:alice', 'module.exports user:alice']);
    for (const q of gh.queries) expect(() => assertScopedQuery(q, 'alice', 'user')).not.toThrow();
    // The out-of-scope result was dropped before any fetch of its content.
    expect(gh.paths.some((p) => p.includes('mallory'))).toBe(false);

    const findings = res.report.findings;
    expect(findings.map((x) => [x.ruleId, x.filePath, x.line])).toEqual(
      expect.arrayContaining([
        ['github-token', 'alice/app/src/config.js', 1],
        ['dotenv-secret', 'alice/app/.env', 2],
      ]),
    );
    expect(findings).toHaveLength(2);
    for (const x of findings) {
      expect(x.presence).toBe('in-HEAD');
      expect(x.commitHash).toBe(sha('e'));
      expect(x.commitSubject).toBe('Add config');
    }
    // Both queries return the same files: deduplicated, each blob fetched exactly once.
    expect(gh.paths.filter((p) => p.includes('/git/blobs/'))).toHaveLength(3);
    expect(res.filesMatched).toBe(3);

    const reportJson = await readFile(res.written.json!, 'utf8');
    const html = await readFile(res.written.html!, 'utf8');
    expectNoLeak(reportJson + html, RAW, 'dork reports');
    const schema = JSON.parse(
      await readFile(new URL('../../schema/report.schema.json', import.meta.url), 'utf8'),
    );
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    expect(validate(JSON.parse(reportJson))).toBe(true);
  });

  it('refuses an owner the token does not control, before any search', async () => {
    const gh = mockGitHub({ login: 'mallory' });
    await expect(runDork(request(), { fetchImpl: gh.fn, ...fast })).rejects.toThrow(DorkScopeError);
    expect(gh.paths).toEqual(['/user']);
  });

  it('orgs: requires active admin membership', async () => {
    const member = mockGitHub({ orgRole: 'member' });
    await expect(
      runDork(request({ owner: 'acme', ownerType: 'org' }), { fetchImpl: member.fn, ...fast }),
    ).rejects.toThrow(/admin/);
    const outsider = mockGitHub({ orgRole: null });
    await expect(
      runDork(request({ owner: 'acme', ownerType: 'org' }), { fetchImpl: outsider.fn, ...fast }),
    ).rejects.toThrow(/admin/);
    const admin = mockGitHub({ orgRole: 'admin' });
    await runDork(request({ owner: 'acme', ownerType: 'org', terms: ['password'] }), {
      fetchImpl: admin.fn,
      ...fast,
    });
    expect(admin.queries).toEqual(['password org:acme']);
  });

  it('refuses scoped user terms before searching', async () => {
    const gh = mockGitHub();
    await expect(
      runDork(request({ terms: ['AKIA user:mallory'] }), { fetchImpl: gh.fn, ...fast }),
    ).rejects.toThrow(/qualifiers/);
    expect(gh.paths).not.toContain('/search/code');
  });

  it('stops at a search rate limit without retrying and reports partial results', async () => {
    const gh = mockGitHub({ rateLimitSearchAfter: 1 });
    const res = await runDork(request({ terms: ['a', 'b', 'c'] }), { fetchImpl: gh.fn, ...fast });
    expect(gh.paths.filter((p) => p === '/search/code')).toHaveLength(2);
    expect(res.incomplete).toMatch(/rate limit/);
    expect(res.report.findings.length).toBeGreaterThan(0);
  });

  it('paces code-search requests (10/minute budget)', async () => {
    const gh = mockGitHub();
    const t0 = performance.now();
    await runDork(request({ terms: ['a', 'b'], formats: [] }), {
      fetchImpl: gh.fn,
      searchDelayMs: 80,
      coreDelayMs: 0,
    });
    expect(performance.now() - t0).toBeGreaterThanOrEqual(70);
  });
});

describe('dork CLI', () => {
  async function capture(args: string[]) {
    let out = '';
    let err = '';
    const code = await main(['node', 'git-leak-hunter', ...args], {
      out: (s) => (out += s),
      err: (s) => (err += s),
    });
    return { code, out, err };
  }

  it('requires --confirm-authorized and a token', async () => {
    expect((await capture(['dork', '--owner', 'alice'])).code).toBe(2);
    const saved = { a: process.env.GITHUB_TOKEN, b: process.env.GH_TOKEN };
    delete process.env.GITHUB_TOKEN;
    delete process.env.GH_TOKEN;
    try {
      const res = await capture(['dork', '--owner', 'alice', '--confirm-authorized']);
      expect(res.code).toBe(2);
      expect(res.err).toContain('GITHUB_TOKEN');
    } finally {
      if (saved.a !== undefined) process.env.GITHUB_TOKEN = saved.a;
      if (saved.b !== undefined) process.env.GH_TOKEN = saved.b;
    }
  });

  it('runs end-to-end with the global fetch guarded and never prints the token', async () => {
    const gh = mockGitHub();
    vi.stubGlobal('fetch', gh.fn);
    process.env.GITHUB_TOKEN = TOKEN;
    try {
      const res = await capture([
        'dork',
        '--owner',
        'alice',
        '--confirm-authorized',
        '--term',
        'module.exports',
        '--out',
        path.join(tmp, 'cli'),
        '--fail-on',
        'high',
      ]);
      expect(res.code).toBe(1);
      expect(res.out).toContain('owner verified (user)');
      expect(res.out).toContain('2 findings detected');
      expectNoLeak(res.out + res.err, RAW, 'dork CLI output');
      const mismatch = mockGitHub({ login: 'mallory' });
      vi.stubGlobal('fetch', mismatch.fn);
      const refused = await capture([
        'dork',
        '--owner',
        'alice',
        '--confirm-authorized',
        '--out',
        path.join(tmp, 'cli2'),
      ]);
      expect(refused.code).toBe(2);
      expect(refused.err).toMatch(/refusing/);
      expectNoLeak(refused.err, [TOKEN], 'refusal message');
    } finally {
      delete process.env.GITHUB_TOKEN;
      vi.unstubAllGlobals();
    }
  });
});
