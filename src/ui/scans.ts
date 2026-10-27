/**
 * Scan manager for the local web UI: validates requests, runs one scan at a time through the same
 * pipeline as the CLI, keeps live phase/counters for polling, and stores each scan's reports in a
 * private temp directory that is removed when the server stops.
 */
import { randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { FileConfig } from '../config.js';
import { stripUrlCredentials } from '../git/exec.js';
import { isRemoteTarget } from '../git/repo.js';
import type { GitEngineCounters } from '../git/index.js';
import {
  runScan,
  type ScanPhase,
  type ScanRequest,
  type ScanResult,
  type ScanHooks,
} from '../pipeline.js';
import type { ScanOptions, SeverityCounts } from '../types.js';
import type { VerifySummary } from '../verify/index.js';

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/** Report temp dirs of every manager; removed synchronously on process exit (incl. Ctrl-C). */
const liveDirs = new Set<string>();
let exitHook = false;

function trackDir(dir: string): void {
  liveDirs.add(dir);
  if (exitHook) return;
  exitHook = true;
  process.once('exit', () => {
    for (const d of liveDirs) rmSync(d, { recursive: true, force: true });
  });
}

async function removeDir(dir: string): Promise<void> {
  await rm(dir, { recursive: true, force: true });
  liveDirs.delete(dir);
}

export class BusyError extends Error {
  constructor() {
    super('a scan is already running; wait for it to finish');
    this.name = 'BusyError';
  }
}

/** A scan request as sent by the web UI, after validation. */
export interface UiScanRequest {
  target: string;
  branch?: string;
  since?: string;
  maxCommits?: number;
  ci: boolean;
  cache: boolean;
  entropyHex?: number;
  entropyBase64?: number;
  minLength?: number;
  /** Required for remote URLs: the user confirms they may scan this repository. */
  authorized: boolean;
  verify: boolean;
  /** Required with `verify`: the user confirms they may test these credentials. */
  confirmAuthorized: boolean;
}

export type UiScanStateName = 'running' | 'done' | 'error';

export interface UiScanState {
  id: string;
  /** Target as given, URL credentials stripped. */
  target: string;
  name: string;
  state: UiScanStateName;
  phase: ScanPhase | 'queued' | 'done';
  counters: Pick<
    GitEngineCounters,
    'commitsWalked' | 'fileVersionsSeen' | 'uniqueBlobsScanned' | 'cacheHits'
  >;
  startedAt: string;
  finishedAt?: string;
  durationMs?: number;
  summary?: { total: number; bySeverity: SeverityCounts; inHead: number; historyOnly: number };
  verification?: VerifySummary;
  verified: boolean;
  error?: string;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function optNum(v: unknown, name: string, min: number, integer: boolean): number | undefined {
  if (v === undefined || v === null || v === '') return undefined;
  if (
    typeof v !== 'number' ||
    !Number.isFinite(v) ||
    v < min ||
    (integer && !Number.isInteger(v))
  ) {
    throw new ValidationError(`${name} must be ${integer ? 'an integer' : 'a number'} ≥ ${min}`);
  }
  return v;
}

function optStr(v: unknown, name: string, max: number): string | undefined {
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v !== 'string' || v.length > max || /[\0\n\r]/.test(v))
    throw new ValidationError(`${name} is invalid`);
  return v.trim() || undefined;
}

function bool(v: unknown, name: string, dflt: boolean): boolean {
  if (v === undefined) return dflt;
  if (typeof v !== 'boolean') throw new ValidationError(`${name} must be true or false`);
  return v;
}

/** Validate an untrusted JSON body from the browser. */
export function parseScanRequest(body: unknown): UiScanRequest {
  if (!isObj(body)) throw new ValidationError('request body must be a JSON object');
  const allowed = [
    'target',
    'branch',
    'since',
    'maxCommits',
    'ci',
    'cache',
    'entropyHex',
    'entropyBase64',
    'minLength',
    'authorized',
    'verify',
    'confirmAuthorized',
  ];
  for (const k of Object.keys(body))
    if (!allowed.includes(k)) throw new ValidationError(`unknown field "${k.slice(0, 40)}"`);
  const target = optStr(body.target, 'target', 2048);
  if (!target) throw new ValidationError('enter a repository path or URL');
  const since = optStr(body.since, 'since', 64);
  if (since?.startsWith('-')) throw new ValidationError('since is invalid');
  const branch = optStr(body.branch, 'branch', 255);
  const maxCommits = optNum(body.maxCommits, 'max commits', 1, true);
  const entropyHex = optNum(body.entropyHex, 'hex entropy threshold', 0, false);
  const entropyBase64 = optNum(body.entropyBase64, 'base64 entropy threshold', 0, false);
  const minLength = optNum(body.minLength, 'minimum length', 1, true);
  const req: UiScanRequest = {
    target,
    ci: bool(body.ci, 'ci', true),
    cache: bool(body.cache, 'cache', true),
    authorized: bool(body.authorized, 'authorized', false),
    verify: bool(body.verify, 'verify', false),
    confirmAuthorized: bool(body.confirmAuthorized, 'confirmAuthorized', false),
    ...(branch ? { branch } : {}),
    ...(since ? { since } : {}),
    ...(maxCommits === undefined ? {} : { maxCommits }),
    ...(entropyHex === undefined ? {} : { entropyHex }),
    ...(entropyBase64 === undefined ? {} : { entropyBase64 }),
    ...(minLength === undefined ? {} : { minLength }),
  };
  if (isRemoteTarget(target) && !req.authorized) {
    throw new ValidationError(
      'confirm that you own or are explicitly authorized to scan this remote repository',
    );
  }
  if (req.verify && !req.confirmAuthorized) {
    throw new ValidationError(
      'live verification needs your confirmation that you are authorized to test these credentials',
    );
  }
  return req;
}

function displayName(target: string): string {
  const trimmed = stripUrlCredentials(target).replace(/[/\\]+$/, '');
  return (trimmed.split(/[/\\:]/).pop() ?? trimmed).replace(/\.git$/, '') || trimmed;
}

export interface ScanManagerOptions {
  /** Directory relative local paths are resolved against (where `ui` was launched). */
  cwd: string;
  config: FileConfig;
  maxKept?: number;
  /** Test seam. */
  runScanImpl?: (req: ScanRequest, hooks: ScanHooks) => Promise<ScanResult>;
}

interface Entry {
  state: UiScanState;
  dir: string;
  written?: ScanResult['written'];
}

export class ScanManager {
  private readonly scans = new Map<string, Entry>();
  private running: string | null = null;
  private readonly runScanImpl: NonNullable<ScanManagerOptions['runScanImpl']>;

  constructor(private readonly opts: ScanManagerOptions) {
    this.runScanImpl = opts.runScanImpl ?? runScan;
  }

  /** Resolve `~` and relative local paths; remote URLs pass through unchanged. */
  resolveTarget(target: string): string {
    if (isRemoteTarget(target)) return target;
    const home =
      target === '~' || target.startsWith('~/') ? path.join(os.homedir(), target.slice(1)) : target;
    return path.resolve(this.opts.cwd, home);
  }

  async start(req: UiScanRequest): Promise<UiScanState> {
    if (this.running) throw new BusyError();
    const id = randomUUID();
    const target = this.resolveTarget(req.target);
    const dir = await mkdtemp(path.join(os.tmpdir(), 'glh-ui-'));
    trackDir(dir);
    const cfg = this.opts.config;
    const options: ScanOptions = {
      entropy: {
        hex: req.entropyHex ?? cfg.entropy.hex,
        base64: req.entropyBase64 ?? cfg.entropy.base64,
        minLength: req.minLength ?? cfg.entropy.minLength,
      },
      ...(req.maxCommits === undefined ? {} : { maxCommits: req.maxCommits }),
      ...(req.since === undefined ? {} : { since: req.since }),
      ...(req.branch === undefined ? {} : { branch: req.branch }),
      ci: req.ci,
      cache: req.cache,
      verify: req.verify,
      maxFileBytes: cfg.maxFileBytes,
    };
    const state: UiScanState = {
      id,
      target: stripUrlCredentials(target),
      name: displayName(target),
      state: 'running',
      phase: 'queued',
      counters: { commitsWalked: 0, fileVersionsSeen: 0, uniqueBlobsScanned: 0, cacheHits: 0 },
      startedAt: new Date().toISOString(),
      verified: req.verify,
    };
    const entry: Entry = { state, dir };
    this.scans.set(id, entry);
    this.running = id;
    await this.prune();

    const t0 = Date.now();
    void this.runScanImpl(
      {
        target,
        outDir: dir,
        formats: ['html', 'json'],
        options,
        ...(cfg.ignore.length ? { ignorePatterns: cfg.ignore } : {}),
        severityOverrides: cfg.severity,
      },
      {
        onPhase: (p) => {
          state.phase = p;
        },
        onProgress: (c) => {
          state.counters = {
            commitsWalked: c.commitsWalked,
            fileVersionsSeen: c.fileVersionsSeen,
            uniqueBlobsScanned: c.uniqueBlobsScanned,
            cacheHits: c.cacheHits,
          };
        },
      },
    )
      .then((result) => {
        const s = result.report.stats;
        state.counters = {
          commitsWalked: s.commitsWalked,
          fileVersionsSeen: s.fileVersionsSeen,
          uniqueBlobsScanned: s.uniqueBlobsScanned,
          cacheHits: s.cacheHits,
        };
        state.summary = result.report.summary;
        if (result.verification) state.verification = result.verification;
        entry.written = result.written;
        state.state = 'done';
        state.phase = 'done';
      })
      .catch((err: unknown) => {
        state.state = 'error';
        // Messages are built by this tool (git errors are summarised and credential-stripped).
        state.error = stripUrlCredentials(err instanceof Error ? err.message : 'scan failed').slice(
          0,
          400,
        );
      })
      .finally(() => {
        state.finishedAt = new Date().toISOString();
        state.durationMs = Date.now() - t0;
        if (this.running === id) this.running = null;
      });
    return state;
  }

  get(id: string): UiScanState | undefined {
    return this.scans.get(id)?.state;
  }

  list(): UiScanState[] {
    return [...this.scans.values()].map((e) => e.state).reverse();
  }

  reportPath(id: string, kind: 'html' | 'json'): string | undefined {
    const e = this.scans.get(id);
    return e?.state.state === 'done' ? e.written?.[kind] : undefined;
  }

  get busy(): boolean {
    return this.running !== null;
  }

  private async prune(): Promise<void> {
    const max = this.opts.maxKept ?? 20;
    for (const [id, e] of this.scans) {
      if (this.scans.size <= max) break;
      if (id === this.running) continue;
      this.scans.delete(id);
      await removeDir(e.dir);
    }
  }

  async dispose(): Promise<void> {
    await Promise.all([...this.scans.values()].map((e) => removeDir(e.dir)));
    this.scans.clear();
  }
}
