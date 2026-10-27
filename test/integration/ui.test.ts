import { request } from 'node:http';
import path from 'node:path';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { readFile } from 'node:fs/promises';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultConfig } from '../../src/config.js';
import { ScanManager, BusyError, parseScanRequest, ValidationError } from '../../src/ui/scans.js';
import { startUiServer, type UiServer } from '../../src/ui/server.js';
import type { ScanResult } from '../../src/pipeline.js';
import { useFixtures } from '../helpers/fixtures.js';
import { expectNoLeak } from '../helpers/noLeak.js';

const fx = useFixtures();
const TOKEN = 'a'.repeat(48);
let ui: UiServer;

beforeAll(async () => {
  ui = await startUiServer({
    port: 0,
    cwd: path.dirname(fx.get().fixtures.clean.dir),
    config: defaultConfig(),
    token: TOKEN,
  });
});
afterAll(async () => {
  await ui?.close();
});

interface Res {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/** Raw HTTP so tests can forge Host / Origin / Sec-Fetch-Site like an attacking page would. */
function raw(
  method: string,
  p: string,
  headers: Record<string, string> = {},
  body?: string,
): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port: ui.port,
        method,
        path: p,
        headers: { host: `127.0.0.1:${ui.port}`, ...headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

const auth = { 'x-glh-token': TOKEN };
const post = (body: unknown, extra: Record<string, string> = {}) =>
  raw(
    'POST',
    '/api/scans',
    { ...auth, 'content-type': 'application/json', ...extra },
    JSON.stringify(body),
  );

async function waitDone(id: string): Promise<Record<string, unknown>> {
  for (let i = 0; i < 200; i++) {
    const r = await raw('GET', `/api/scans/${id}`, auth);
    const s = JSON.parse(r.body) as Record<string, unknown>;
    if (s.state !== 'running') return s;
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error('scan did not finish');
}

describe('ui server: network exposure', () => {
  it('listens on 127.0.0.1 only and prints a fragment-token link', () => {
    const addr = ui.server.address();
    expect(typeof addr === 'object' && addr?.address).toBe('127.0.0.1');
    expect(ui.url).toBe(`http://127.0.0.1:${ui.port}/#token=${TOKEN}`);
  });

  it('serves the app shell with a strict CSP and anti-framing headers', async () => {
    const r = await raw('GET', '/');
    expect(r.status).toBe(200);
    const csp = String(r.headers['content-security-policy']);
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).toContain("frame-ancestors 'none'");
    expect(r.headers['x-frame-options']).toBe('DENY');
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    expect(r.body).not.toMatch(/<script>|style="/); // no inline script or style attributes
    expect((await raw('GET', '/app.js')).headers['content-type']).toContain('javascript');
    expect((await raw('GET', '/app.css')).status).toBe(200);
  });

  it('rejects a foreign Host header (DNS rebinding)', async () => {
    expect((await raw('GET', '/', { host: `evil.test:${ui.port}` })).status).toBe(403);
    expect(
      (await raw('GET', '/api/session', { ...auth, host: `evil.test:${ui.port}` })).status,
    ).toBe(403);
  });

  it('requires the session token for the API and reports', async () => {
    expect((await raw('GET', '/api/session')).status).toBe(401);
    expect((await raw('GET', '/api/session', { 'x-glh-token': 'b'.repeat(48) })).status).toBe(401);
    expect((await raw('GET', '/api/session', { 'x-glh-token': 'short' })).status).toBe(401);
    const ok = await raw('GET', '/api/session', auth);
    expect(ok.status).toBe(200);
    expect(JSON.parse(ok.body)).toMatchObject({ busy: false });
  });

  it('refuses cross-site requests even with a token', async () => {
    expect((await post({ target: '.' }, { origin: 'https://evil.test' })).status).toBe(403);
    expect((await post({ target: '.' }, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    expect(
      (await raw('POST', '/api/scans', { ...auth, 'content-type': 'text/plain' }, '{"target":"."}'))
        .status,
    ).toBe(415);
    expect((await raw('OPTIONS', '/api/scans', { origin: 'https://evil.test' })).status).toBe(403);
    expect((await raw('DELETE', '/api/scans', auth)).status).toBe(405);
  });

  it('validates bodies: size, JSON, fields, remote and verification gates', async () => {
    expect((await post({ target: 'x'.repeat(20_000) })).status).toBe(413);
    expect(
      (await raw('POST', '/api/scans', { ...auth, 'content-type': 'application/json' }, '{nope'))
        .status,
    ).toBe(400);
    const bad = async (b: unknown) => JSON.parse((await post(b)).body).error as string;
    expect(await bad({})).toMatch(/enter a repository/);
    expect(await bad({ target: '.', evil: 1 })).toMatch(/unknown field/);
    expect(await bad({ target: '.', maxCommits: 0 })).toMatch(/max commits/);
    expect(await bad({ target: '.', since: '--all' })).toMatch(/since/);
    expect(await bad({ target: 'https://example.test/r.git' })).toMatch(/authorized to scan/);
    expect(await bad({ target: '.', verify: true })).toMatch(/authorized to test/);
  });
});

describe('ui server: scanning', () => {
  it('scans a repo end-to-end and serves sandboxed, leak-free reports', async () => {
    const f = fx.get().fixtures['history-only'];
    const start = await post({ target: f.dir });
    expect(start.status).toBe(202);
    const id = (JSON.parse(start.body) as { id: string }).id;
    const done = await waitDone(id);
    expect(done).toMatchObject({
      state: 'done',
      phase: 'done',
      summary: { total: 3, historyOnly: 3 },
    });
    expect((done.counters as { commitsWalked: number }).commitsWalked).toBe(4);
    expectNoLeak(JSON.stringify(done), f.rawSecrets, 'scan state');

    const html = await raw('GET', `/scans/${id}/report.html?t=${TOKEN}`);
    expect(html.status).toBe(200);
    expect(String(html.headers['content-security-policy'])).toContain('sandbox allow-scripts');
    expect(html.headers['content-disposition']).toBeUndefined();
    expectNoLeak(html.body, f.rawSecrets, 'served report.html');

    const dl = await raw('GET', `/scans/${id}/report.html?t=${TOKEN}&download=1`);
    expect(String(dl.headers['content-disposition'])).toMatch(
      /^attachment; filename="git-leak-hunter-history-only-report\.html"$/,
    );
    const js = await raw('GET', `/scans/${id}/report.json?t=${TOKEN}`);
    const schema = JSON.parse(
      await readFile(new URL('../../schema/report.schema.json', import.meta.url), 'utf8'),
    );
    expect(new Ajv2020({ strict: true }).compile(schema)(JSON.parse(js.body))).toBe(true);

    expect((await raw('GET', `/scans/${id}/report.html`)).status).toBe(401);
    expect((await raw('GET', `/scans/${id}/report.html?t=${'b'.repeat(48)}`)).status).toBe(401);
    const list = JSON.parse((await raw('GET', '/api/scans', auth)).body) as {
      scans: Array<{ id: string }>;
    };
    expect(list.scans[0]?.id).toBe(id);
  });

  it('resolves relative paths against the launch folder and reports scan errors cleanly', async () => {
    const ok = JSON.parse((await post({ target: 'clean' })).body) as { id: string; target: string };
    expect(ok.target).toBe(fx.get().fixtures.clean.dir);
    expect(await waitDone(ok.id)).toMatchObject({ state: 'done', summary: { total: 0 } });

    const missing = JSON.parse((await post({ target: 'does-not-exist' })).body) as { id: string };
    const failed = await waitDone(missing.id);
    expect(failed.state).toBe('error');
    expect(String(failed.error)).toMatch(/not a directory/);
    expect((await raw('GET', `/scans/${missing.id}/report.html?t=${TOKEN}`)).status).toBe(404);
  });
});

describe('ui server: folder browser', () => {
  it('lists sub-folders only and marks repositories', async () => {
    const root = path.dirname(fx.get().fixtures.clean.dir);
    const r = await raw('GET', `/api/browse?path=${encodeURIComponent(root)}`, auth);
    const d = JSON.parse(r.body) as {
      entries: Array<{ name: string; isRepo: boolean }>;
      isRepo: boolean;
    };
    expect(d.isRepo).toBe(false);
    const names = d.entries.map((e) => e.name);
    expect(names).toEqual(expect.arrayContaining(['clean', 'history-only', 'hostile']));
    expect(names).not.toContain('ground-truth.json');
    expect(d.entries.every((e) => e.isRepo)).toBe(true);
  });

  it('rejects relative or missing paths', async () => {
    expect((await raw('GET', '/api/browse?path=relative/dir', auth)).status).toBe(400);
    expect(
      (await raw('GET', `/api/browse?path=${encodeURIComponent('/no/such/dir/x')}`, auth)).status,
    ).toBe(404);
    expect((await raw('GET', '/api/browse?path=/', {})).status).toBe(401);
  });
});

describe('scan manager', () => {
  it('runs one scan at a time', async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    const fake = async (): Promise<ScanResult> => {
      await gate;
      throw new Error('stopped');
    };
    const m = new ScanManager({ cwd: '/', config: defaultConfig(), runScanImpl: fake });
    await m.start(parseScanRequest({ target: '/tmp' }));
    await expect(m.start(parseScanRequest({ target: '/tmp' }))).rejects.toBeInstanceOf(BusyError);
    release();
    await new Promise((r) => setTimeout(r, 20));
    expect(m.busy).toBe(false);
    await m.dispose();
  });

  it('parses and normalises requests', () => {
    expect(
      parseScanRequest({ target: ' ./x ', branch: 'main', maxCommits: 5, ci: false }),
    ).toMatchObject({
      target: './x',
      branch: 'main',
      maxCommits: 5,
      ci: false,
      cache: true,
      verify: false,
    });
    expect(() => parseScanRequest('nope')).toThrow(ValidationError);
    expect(() => parseScanRequest({ target: '.', ci: 'yes' })).toThrow(/ci must be/);
    expect(
      parseScanRequest({ target: 'git@github.com:a/b.git', authorized: true }).authorized,
    ).toBe(true);
  });
});
