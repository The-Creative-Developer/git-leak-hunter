/**
 * Local web UI server (`git-leak-hunter ui`). Built on node:http with no extra dependencies.
 *
 * A local server that can scan any folder must not be usable by other websites the user visits,
 * which can send requests to localhost. Guards, applied to every request:
 * - Listens on 127.0.0.1 only (never 0.0.0.0).
 * - Host header must be 127.0.0.1:<port> or localhost:<port> (blocks DNS rebinding).
 * - API and report routes require a random per-session token (constant-time compare). The token
 *   travels in the launch URL's #fragment (never sent to the server or logged by it) and then in
 *   an `x-glh-token` header; report files take it as `?t=` because iframes cannot set headers.
 * - Cross-site requests are refused: Sec-Fetch-Site must be same-origin/none when present, a
 *   present Origin must be this server, and POST bodies must be application/json (so a
 *   cross-site form cannot send one without a CORS preflight, which is never granted).
 * - The app page has a strict CSP (no inline script or style) and cannot be framed. Reports are
 *   served with a CSP `sandbox`, so their script runs in an opaque origin and cannot call the API.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import type { FileConfig } from '../config.js';
import { VERSION } from '../version.js';
import { listDirectory, NotFoundError } from './browse.js';
import { APP_CSS, APP_JS, FAVICON_SVG, PAGE_HTML } from './client.js';
import { BusyError, parseScanRequest, ScanManager, ValidationError } from './scans.js';

export const DEFAULT_UI_PORT = 7420;
const MAX_BODY_BYTES = 16 * 1024;

const APP_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const REPORT_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'self'; sandbox allow-scripts allow-modals allow-popups allow-downloads";

export interface UiServerOptions {
  /** 0 = any free port. */
  port?: number;
  cwd: string;
  config: FileConfig;
  /** Test seams. */
  token?: string;
  manager?: ScanManager;
}

export interface UiServer {
  url: string;
  port: number;
  token: string;
  server: Server;
  manager: ScanManager;
  close(): Promise<void>;
}

const BASE_HEADERS: Readonly<Record<string, string>> = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
  'cross-origin-resource-policy': 'same-origin',
};

function send(
  res: ServerResponse,
  status: number,
  body: string | Buffer,
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, { ...BASE_HEADERS, ...headers });
  res.end(body);
}

function json(res: ServerResponse, status: number, value: unknown): void {
  send(res, status, JSON.stringify(value), { 'content-type': 'application/json; charset=utf-8' });
}

function sameToken(given: string | undefined | null, token: string): boolean {
  if (!given) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const type = (req.headers['content-type'] ?? '').split(';')[0]?.trim().toLowerCase();
  if (type !== 'application/json')
    throw Object.assign(new Error('content-type must be application/json'), { status: 415 });
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES)
      throw Object.assign(new Error('request body too large'), { status: 413 });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw Object.assign(new Error('request body is not valid JSON'), { status: 400 });
  }
}

export async function startUiServer(opts: UiServerOptions): Promise<UiServer> {
  const token = opts.token ?? randomBytes(24).toString('hex');
  const manager = opts.manager ?? new ScanManager({ cwd: opts.cwd, config: opts.config });
  let port = 0;

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const host = req.headers.host ?? '';
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) {
      send(res, 403, 'forbidden host', { 'content-type': 'text/plain' });
      return;
    }
    const site = req.headers['sec-fetch-site'];
    if (typeof site === 'string' && site !== 'same-origin' && site !== 'none') {
      send(res, 403, 'cross-site request refused', { 'content-type': 'text/plain' });
      return;
    }
    const origin = req.headers.origin;
    if (
      origin !== undefined &&
      origin !== `http://127.0.0.1:${port}` &&
      origin !== `http://localhost:${port}`
    ) {
      send(res, 403, 'cross-origin request refused', { 'content-type': 'text/plain' });
      return;
    }

    const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
    const method = req.method ?? 'GET';
    const p = url.pathname;

    // ---- public, static app shell (contains no data) ----
    if (method === 'GET' && (p === '/' || p === '/index.html')) {
      send(res, 200, PAGE_HTML, {
        'content-type': 'text/html; charset=utf-8',
        'content-security-policy': APP_CSP,
        'x-frame-options': 'DENY',
        'cross-origin-opener-policy': 'same-origin',
      });
      return;
    }
    if (method === 'GET' && p === '/app.js') {
      send(res, 200, APP_JS, { 'content-type': 'text/javascript; charset=utf-8' });
      return;
    }
    if (method === 'GET' && p === '/app.css') {
      send(res, 200, APP_CSS, { 'content-type': 'text/css; charset=utf-8' });
      return;
    }
    if (method === 'GET' && p === '/favicon.svg') {
      send(res, 200, FAVICON_SVG, { 'content-type': 'image/svg+xml' });
      return;
    }

    // ---- reports: token in query (iframes cannot send headers), sandboxed ----
    const reportMatch = /^\/scans\/([0-9a-f-]{36})\/report\.(html|json)$/.exec(p);
    if (reportMatch && method === 'GET') {
      if (!sameToken(url.searchParams.get('t'), token)) {
        send(res, 401, 'missing or invalid session token', { 'content-type': 'text/plain' });
        return;
      }
      const kind = reportMatch[2] as 'html' | 'json';
      const file = manager.reportPath(reportMatch[1] ?? '', kind);
      if (!file) {
        send(res, 404, 'report not found', { 'content-type': 'text/plain' });
        return;
      }
      const name = (manager.get(reportMatch[1] ?? '')?.name ?? 'repo')
        .replace(/[^A-Za-z0-9._-]/g, '_')
        .slice(0, 60);
      const headers: Record<string, string> =
        kind === 'html'
          ? { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': REPORT_CSP }
          : { 'content-type': 'application/json; charset=utf-8' };
      if (url.searchParams.get('download') === '1' || kind === 'json') {
        headers['content-disposition'] =
          `attachment; filename="git-leak-hunter-${name}-report.${kind}"`;
      }
      send(res, 200, await readFile(file), headers);
      return;
    }

    // ---- API: token header required ----
    if (p.startsWith('/api/')) {
      const given = req.headers['x-glh-token'];
      if (!sameToken(typeof given === 'string' ? given : undefined, token)) {
        json(res, 401, {
          error: 'missing or invalid session token — open the link printed in your terminal',
        });
        return;
      }
      if (method === 'GET' && p === '/api/session') {
        json(res, 200, { version: VERSION, cwd: opts.cwd, home: os.homedir(), busy: manager.busy });
        return;
      }
      if (method === 'GET' && p === '/api/browse') {
        json(res, 200, await listDirectory(url.searchParams.get('path') ?? opts.cwd));
        return;
      }
      if (method === 'GET' && p === '/api/scans') {
        json(res, 200, { scans: manager.list() });
        return;
      }
      const one = /^\/api\/scans\/([0-9a-f-]{36})$/.exec(p);
      if (method === 'GET' && one) {
        const s = manager.get(one[1] ?? '');
        if (s) json(res, 200, s);
        else json(res, 404, { error: 'scan not found' });
        return;
      }
      if (method === 'POST' && p === '/api/scans') {
        const body = await readJson(req);
        json(res, 202, await manager.start(parseScanRequest(body)));
        return;
      }
      json(res, method === 'GET' || method === 'POST' ? 404 : 405, { error: 'not found' });
      return;
    }
    send(res, method === 'GET' ? 404 : 405, 'not found', { 'content-type': 'text/plain' });
  };

  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      const status =
        err instanceof ValidationError
          ? 400
          : err instanceof NotFoundError
            ? 404
            : err instanceof BusyError
              ? 409
              : ((err as { status?: number }).status ?? 500);
      const message =
        status === 500 ? 'internal error' : err instanceof Error ? err.message : 'error';
      if (!res.headersSent) json(res, status, { error: message });
      else res.end();
    });
  });

  const listen = (p: number): Promise<void> =>
    new Promise((resolve, reject) => {
      const onError = (e: Error): void => {
        server.off('listening', onListening);
        reject(e);
      };
      const onListening = (): void => {
        server.off('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(p, '127.0.0.1');
    });

  const wanted = opts.port ?? DEFAULT_UI_PORT;
  try {
    await listen(wanted);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EADDRINUSE' || wanted === 0) throw err;
    await listen(0); // preferred port taken: fall back to any free port
  }
  port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}/#token=${token}`,
    port,
    token,
    server,
    manager,
    close: async () => {
      const closed = new Promise<void>((resolve) => server.close(() => resolve()));
      server.closeAllConnections();
      await closed;
      await manager.dispose();
    },
  };
}
