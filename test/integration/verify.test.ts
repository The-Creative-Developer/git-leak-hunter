import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FIXTURE_NAMES } from '../fixtures/buildRepos.js';
import { VERIFY_HOST_ALLOWLIST, type FetchLike } from '../../src/verify/http.js';
import { useFixtures } from '../helpers/fixtures.js';
import { expectNoLeak } from '../helpers/noLeak.js';
import { scanRepo } from '../helpers/scan.js';

const fx = useFixtures();

/** A fetch mock that FAILS THE TEST if anything outside the allowlist is contacted. */
function allowlistGuard(respond: (url: URL) => Response) {
  const hosts: string[] = [];
  const fn = vi.fn<FetchLike>(async (input) => {
    const url = new URL(input);
    hosts.push(url.hostname);
    if (!VERIFY_HOST_ALLOWLIST.has(url.hostname) || url.protocol !== 'https:') {
      throw new Error(`TEST FAILURE: non-allowlisted host contacted: ${url.hostname}`);
    }
    return respond(url);
  });
  return { fn, hosts };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('--verify end-to-end (mocked HTTP)', () => {
  it('never touches the network without --verify', async () => {
    const spy = vi.fn();
    vi.stubGlobal('fetch', spy);
    for (const name of FIXTURE_NAMES) {
      await scanRepo(
        fx.get().fixtures[name].dir,
        path.join(fx.tmp(), 'noverify', name),
        {},
        { formats: [] },
      );
    }
    expect(spy).not.toHaveBeenCalled();
  });

  it('only ever contacts allowlisted hosts (global fetch guarded)', async () => {
    const guard = allowlistGuard((url) =>
      url.hostname === 'api.github.com'
        ? new Response(null, { status: 401 })
        : new Response('<Code>InvalidClientTokenId</Code>', { status: 403 }),
    );
    vi.stubGlobal('fetch', guard.fn);
    for (const name of FIXTURE_NAMES) {
      await scanRepo(
        fx.get().fixtures[name].dir,
        path.join(fx.tmp(), 'guard', name),
        { verify: true },
        { formats: [] },
        { verify: { delayMs: 0 } },
      );
    }
    expect(guard.fn).toHaveBeenCalled();
    expect(new Set(guard.hosts)).toEqual(new Set(['api.github.com', 'sts.amazonaws.com']));
  });

  it('history-only: AWS pair and GitHub token verified once each; ACTIVE becomes Critical; no leaks', async () => {
    const fixture = fx.get().fixtures['history-only'];
    const guard = allowlistGuard((url) =>
      url.hostname === 'api.github.com'
        ? new Response('{"login":"octo-someone"}', { status: 200 })
        : new Response('<Code>InvalidClientTokenId</Code>', { status: 403 }),
    );
    const res = await scanRepo(
      fixture.dir,
      path.join(fx.tmp(), 'verify-ho'),
      { verify: true },
      {},
      { verify: { fetchImpl: guard.fn, delayMs: 0 } },
    );
    expect(res.verification).toEqual({
      active: 1,
      inactive: 2,
      unverifiable: 0,
      calls: { aws: 1, github: 1 },
    });
    const gh = res.report.findings.find((f) => f.ruleId === 'github-token')!;
    expect(gh).toMatchObject({ verificationStatus: 'ACTIVE', severity: 'critical' });
    expect(res.report.findings[0]!.ruleId).toBe('github-token');
    for (const f of res.report.findings.filter((x) => x.ruleId.startsWith('aws-'))) {
      expect(f).toMatchObject({ verificationStatus: 'INACTIVE', severity: 'high' });
    }
    expect(res.report.scan.options.verify).toBe(true);
    const json = await readFile(res.written.json!, 'utf8');
    const html = await readFile(res.written.html!, 'utf8');
    expect(json).not.toContain('octo-someone');
    expectNoLeak(json + html, fixture.rawSecrets, 'verified report');
    expect(html).toContain('ACTIVE');
  });

  it('blob-reuse: the same token at four paths is checked with a single request', async () => {
    const guard = allowlistGuard(() => new Response(null, { status: 401 }));
    const res = await scanRepo(
      fx.get().fixtures['blob-reuse'].dir,
      path.join(fx.tmp(), 'verify-br'),
      { verify: true },
      { formats: [] },
      { verify: { fetchImpl: guard.fn, delayMs: 0 } },
    );
    expect(guard.fn).toHaveBeenCalledTimes(1);
    expect(res.report.findings.every((f) => f.verificationStatus === 'INACTIVE')).toBe(true);
  });

  it('hostile: a GitHub rate limit stops further GitHub calls', async () => {
    const guard = allowlistGuard(() => new Response(null, { status: 429 }));
    const res = await scanRepo(
      fx.get().fixtures.hostile.dir,
      path.join(fx.tmp(), 'verify-rl'),
      { verify: true },
      { formats: [] },
      { verify: { fetchImpl: guard.fn, delayMs: 0 } },
    );
    expect(guard.fn).toHaveBeenCalledTimes(1);
    const gh = res.report.findings.filter((f) => f.ruleId === 'github-token');
    expect(gh).toHaveLength(2);
    expect(gh.every((f) => f.verificationStatus === 'UNVERIFIABLE')).toBe(true);
  });

  it('non-verifiable rule types stay NOT_CHECKED', async () => {
    const guard = allowlistGuard(() => new Response(null, { status: 401 }));
    const res = await scanRepo(
      fx.get().fixtures['ci-configs'].dir,
      path.join(fx.tmp(), 'verify-ci'),
      { verify: true },
      { formats: [] },
      { verify: { fetchImpl: guard.fn, delayMs: 0 } },
    );
    expect(guard.fn).not.toHaveBeenCalled();
    expect(res.report.findings.every((f) => f.verificationStatus === 'NOT_CHECKED')).toBe(true);
  });
});
