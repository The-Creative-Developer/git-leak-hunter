import { describe, expect, it, vi } from 'vitest';
import type { Finding } from '../../src/types.js';
import { checkAws, STS_URL } from '../../src/verify/aws.js';
import { checkGitHub, GITHUB_USER_URL } from '../../src/verify/github.js';
import {
  assertAllowedUrl,
  guardedFetch,
  HostNotAllowedError,
  type FetchLike,
} from '../../src/verify/http.js';
import { verifyFindings } from '../../src/verify/index.js';
import { signRequest, signingKey } from '../../src/verify/sigv4.js';
import { Vault } from '../../src/verify/vault.js';
import { Rng, SecretFactory } from '../fixtures/secretFactory.js';
import { expectNoLeak } from '../helpers/noLeak.js';

const f = new SecretFactory(new Rng(77));
// AWS documentation example credentials (not real).
const DOC_SECRET = ['wJalrXUtnFEMI/K7MDENG+', 'bPxRfiCY', 'EXAMPLEKEY'].join('');

describe('SigV4 signer matches AWS documentation vectors', () => {
  it('derives the documented signing key', () => {
    expect(signingKey(DOC_SECRET, '20150830', 'us-east-1', 'iam').toString('hex')).toBe(
      'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9',
    );
  });

  it('signs the get-vanilla test case', () => {
    const { signature } = signRequest({
      method: 'GET',
      host: 'example.amazonaws.com',
      path: '/',
      query: '',
      headers: {},
      body: '',
      region: 'us-east-1',
      service: 'service',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: DOC_SECRET,
      amzDate: '20150830T123600Z',
    });
    expect(signature).toBe('5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
  });

  it('signs the IAM ListUsers example', () => {
    const { signature, headers } = signRequest({
      method: 'GET',
      host: 'iam.amazonaws.com',
      path: '/',
      query: 'Action=ListUsers&Version=2010-05-08',
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: '',
      region: 'us-east-1',
      service: 'iam',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: DOC_SECRET,
      amzDate: '20150830T123600Z',
    });
    expect(signature).toBe('5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7');
    expect(headers.authorization).toBe(
      `AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=${signature}`,
    );
  });
});

describe('host allowlist', () => {
  it.each(['https://sts.amazonaws.com/', 'https://api.github.com/user'])('allows %s', (u) => {
    expect(() => assertAllowedUrl(u)).not.toThrow();
  });

  it.each([
    'http://api.github.com/user',
    'https://evil.test/',
    'https://api.github.com.evil.test/user',
    'https://user:pw@api.github.com/user',
    'https://api.github.com:8443/user',
    'https://sts.us-east-1.amazonaws.com/',
    'not a url',
  ])('refuses %s without making a request', async (u) => {
    const fetchSpy = vi.fn<FetchLike>();
    await expect(guardedFetch(fetchSpy, u, {})).rejects.toBeInstanceOf(HostNotAllowedError);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('disables redirects and sets a timeout', async () => {
    const fetchSpy = vi.fn<FetchLike>(async () => new Response(null, { status: 204 }));
    await guardedFetch(fetchSpy, GITHUB_USER_URL, { method: 'GET' });
    const init = fetchSpy.mock.calls[0]![1];
    expect(init.redirect).toBe('error');
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });
});

describe('GitHub check (GET /user only)', () => {
  const respond = (status: number, headers: Record<string, string> = {}) =>
    vi.fn<FetchLike>(async () => new Response('{"login":"someone"}', { status, headers }));

  it('sends one read-only request with the token', async () => {
    const tok = f.githubToken();
    const fetchSpy = respond(200);
    expect((await checkGitHub(fetchSpy, tok)).status).toBe('ACTIVE');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(url).toBe(GITHUB_USER_URL);
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${tok}`);
  });

  it.each([
    [401, {}, 'INACTIVE', false],
    [403, { 'x-ratelimit-remaining': '0' }, 'UNVERIFIABLE', true],
    [429, {}, 'UNVERIFIABLE', true],
    [500, {}, 'UNVERIFIABLE', false],
  ] as const)('HTTP %i → %s', async (status, headers, expected, stop) => {
    const r = await checkGitHub(respond(status, headers), f.githubToken());
    expect(r.status).toBe(expected);
    expect(Boolean(r.stop)).toBe(stop);
  });

  it('never stores the account name from the response', async () => {
    const r = await checkGitHub(respond(200), f.githubToken());
    expect(JSON.stringify(r)).not.toContain('someone');
  });

  it('maps network errors and timeouts to UNVERIFIABLE', async () => {
    const fail = vi.fn<FetchLike>(async () => {
      throw new DOMException('timed out', 'TimeoutError');
    });
    expect((await checkGitHub(fail, f.githubToken())).status).toBe('UNVERIFIABLE');
  });
});

describe('AWS check (sts:GetCallerIdentity only)', () => {
  const xml = (code: string) =>
    `<ErrorResponse><Error><Code>${code}</Code></Error></ErrorResponse>`;

  it('signs a POST GetCallerIdentity to the global STS endpoint', async () => {
    const id = f.awsAccessKeyId();
    const fetchSpy = vi.fn<FetchLike>(
      async () =>
        new Response(
          '<GetCallerIdentityResponse><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/x</Arn></GetCallerIdentityResponse>',
          { status: 200 },
        ),
    );
    const r = await checkAws(
      fetchSpy,
      id,
      f.awsSecretAccessKey(),
      new Date('2026-01-02T03:04:05Z'),
    );
    expect(r.status).toBe('ACTIVE');
    expect(JSON.stringify(r)).not.toContain('123456789012');
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(url).toBe(STS_URL);
    expect(init.method).toBe('POST');
    expect(init.body).toBe('Action=GetCallerIdentity&Version=2011-06-15');
    const h = init.headers as Record<string, string>;
    expect(h['x-amz-date']).toBe('20260102T030405Z');
    expect(h.authorization).toMatch(
      new RegExp(
        `^AWS4-HMAC-SHA256 Credential=${id}/20260102/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[0-9a-f]{64}$`,
      ),
    );
  });

  it.each([
    [403, 'InvalidClientTokenId', 'INACTIVE', false],
    [403, 'SignatureDoesNotMatch', 'INACTIVE', false],
    [400, 'Throttling', 'UNVERIFIABLE', true],
    [503, 'ServiceUnavailable', 'UNVERIFIABLE', false],
  ] as const)('HTTP %i %s → %s', async (status, code, expected, stop) => {
    const r = await checkAws(
      vi.fn<FetchLike>(async () => new Response(xml(code), { status })),
      f.awsAccessKeyId(),
      f.awsSecretAccessKey(),
    );
    expect(r.status).toBe(expected);
    expect(Boolean(r.stop)).toBe(stop);
  });
});

describe('vault', () => {
  it('dedupes values, clears, and never serialises its contents', () => {
    const v = new Vault();
    const tok = f.githubToken();
    const a = v.put(tok);
    expect(v.put(tok)).toBe(a);
    expect(v.get(a) === tok).toBe(true);
    expectNoLeak(JSON.stringify({ v }), [tok], 'vault JSON');
    v.clear();
    expect(v.size).toBe(0);
    expect(v.get(a)).toBeUndefined();
  });
});

describe('verifyFindings orchestration', () => {
  let n = 0;
  const finding = (ruleId: string, over: Partial<Finding> = {}): Finding => ({
    fingerprint: (++n).toString(16).padStart(16, '0'),
    ruleId,
    secretType: ruleId,
    detector: 'signature',
    severity: 'high',
    filePath: `f${n}.ts`,
    commitHash: 'a'.repeat(40),
    line: 1,
    column: 1,
    redactedPreview: 'x',
    blobHash: 'b'.repeat(40),
    author: { name: 'a', email: 'a@example.test' },
    date: '2025-01-01T00:00:00Z',
    commitSubject: 's',
    firstSeenCommit: 'a'.repeat(40),
    otherCommitCount: 0,
    presence: 'in-HEAD',
    verificationStatus: 'NOT_CHECKED',
    ...over,
  });

  function setup(entries: Array<[Finding, string | undefined]>) {
    const vault = new Vault();
    const refs = new Map<string, string>();
    for (const [fd, raw] of entries) if (raw) refs.set(fd.fingerprint, vault.put(raw));
    return { vault, refs, findings: entries.map(([fd]) => fd) };
  }

  it('marks ACTIVE as critical, leaves other rules unchecked, and clears the vault', async () => {
    const gh = finding('github-token');
    const other = finding('stripe-live-key');
    const { vault, refs, findings } = setup([
      [gh, f.githubToken()],
      [other, undefined],
    ]);
    const fetchSpy = vi.fn<FetchLike>(async () => new Response(null, { status: 200 }));
    const { findings: out, summary } = await verifyFindings(findings, refs, vault, {
      fetchImpl: fetchSpy,
      delayMs: 0,
    });
    const g = out.find((x) => x.ruleId === 'github-token')!;
    expect(g.verificationStatus).toBe('ACTIVE');
    expect(g.severity).toBe('critical');
    expect(out.find((x) => x.ruleId === 'stripe-live-key')!.verificationStatus).toBe('NOT_CHECKED');
    expect(summary).toEqual({
      active: 1,
      inactive: 0,
      unverifiable: 0,
      calls: { aws: 0, github: 1 },
    });
    expect(vault.size).toBe(0);
  });

  it('checks an AWS pair once and applies the result to both findings', async () => {
    const id = finding('aws-access-key-id');
    const sk = finding('aws-secret-access-key');
    id.pairedFingerprint = sk.fingerprint;
    sk.pairedFingerprint = id.fingerprint;
    const { vault, refs, findings } = setup([
      [id, f.awsAccessKeyId()],
      [sk, f.awsSecretAccessKey()],
    ]);
    const fetchSpy = vi.fn<FetchLike>(
      async () => new Response('<Code>InvalidClientTokenId</Code>', { status: 403 }),
    );
    const { findings: out, summary } = await verifyFindings(findings, refs, vault, {
      fetchImpl: fetchSpy,
      delayMs: 0,
    });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(out.map((x) => x.verificationStatus)).toEqual(['INACTIVE', 'INACTIVE']);
    expect(summary.calls.aws).toBe(1);
  });

  it('does not call AWS for unpaired or temporary keys', async () => {
    const lone = finding('aws-access-key-id');
    const tmpId = finding('aws-access-key-id');
    const tmpSk = finding('aws-secret-access-key');
    tmpId.pairedFingerprint = tmpSk.fingerprint;
    const temporary = ['AS', 'IA'].join('') + f.awsAccessKeyId().slice(4);
    const { vault, refs, findings } = setup([
      [lone, f.awsAccessKeyId()],
      [tmpId, temporary],
      [tmpSk, f.awsSecretAccessKey()],
    ]);
    const fetchSpy = vi.fn<FetchLike>();
    const { findings: out } = await verifyFindings(findings, refs, vault, {
      fetchImpl: fetchSpy,
      delayMs: 0,
    });
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(out.every((x) => x.verificationStatus === 'UNVERIFIABLE')).toBe(true);
  });

  it('stops calling a provider after a rate-limit response, and respects the call cap', async () => {
    const tokens = [f.githubToken(), f.githubToken(), f.githubToken()];
    const fds = tokens.map(() => finding('github-token'));
    const limited = setup(fds.map((fd, i) => [fd, tokens[i]] as [Finding, string]));
    const rateLimited = vi.fn<FetchLike>(
      async () => new Response(null, { status: 403, headers: { 'x-ratelimit-remaining': '0' } }),
    );
    const r1 = await verifyFindings(limited.findings, limited.refs, limited.vault, {
      fetchImpl: rateLimited,
      delayMs: 0,
    });
    expect(rateLimited).toHaveBeenCalledTimes(1);
    expect(r1.findings.every((x) => x.verificationStatus === 'UNVERIFIABLE')).toBe(true);

    const fds2 = tokens.map(() => finding('github-token'));
    const capped = setup(fds2.map((fd, i) => [fd, tokens[i]] as [Finding, string]));
    const ok = vi.fn<FetchLike>(async () => new Response(null, { status: 200 }));
    const r2 = await verifyFindings(capped.findings, capped.refs, capped.vault, {
      fetchImpl: ok,
      delayMs: 0,
      maxCallsPerProvider: 2,
    });
    expect(ok).toHaveBeenCalledTimes(2);
    expect(r2.summary).toMatchObject({ active: 2, unverifiable: 1 });
  });

  it('waits between calls (sequential, no bursts)', async () => {
    const tokens = [f.githubToken(), f.githubToken()];
    const { vault, refs, findings } = setup(
      tokens.map((t) => [finding('github-token'), t] as [Finding, string]),
    );
    const times: number[] = [];
    const fetchSpy = vi.fn<FetchLike>(async () => {
      times.push(performance.now());
      return new Response(null, { status: 401 });
    });
    await verifyFindings(findings, refs, vault, { fetchImpl: fetchSpy, delayMs: 60 });
    expect(times[1]! - times[0]!).toBeGreaterThanOrEqual(50);
  });
});
