#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Command, InvalidArgumentError, Option } from 'commander';
import pc from 'picocolors';
import { loadConfig } from './config.js';
import { runDork } from './dork/index.js';
import { runScan, type ScanResult } from './pipeline.js';
import { SEVERITIES, SEVERITY_RANK, type ScanOptions, type Severity } from './types.js';
import { VERSION } from './version.js';

export const EXIT_CLEAN = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_ERROR = 2;

export const RESPONSIBLE_USE = `
Responsible use:
  - Scan only repositories you own or are explicitly authorized to scan.
  - Use fabricated, non-functional secrets in test repositories.
  - Live verification is read-only and opt-in (--verify --confirm-authorized).
  - Never exploit discovered credentials.
  - Report any genuinely live finding privately to the repository owner.
  - Secrets are always redacted in console, JSON and HTML output.
`;

function parsePositiveInt(value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) throw new InvalidArgumentError('must be a positive integer');
  return n;
}

function parseNonNegativeNumber(value: string): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) throw new InvalidArgumentError('must be a number >= 0');
  return n;
}

function parseFormats(value: string): Array<'html' | 'json'> {
  const parts = value.split(',').map((s) => s.trim().toLowerCase());
  for (const p of parts) {
    if (p !== 'html' && p !== 'json') throw new InvalidArgumentError('formats: html, json');
  }
  return parts as Array<'html' | 'json'>;
}

interface ScanCliOptions {
  out: string;
  format: Array<'html' | 'json'>;
  maxCommits?: number;
  since?: string;
  branch?: string;
  ci: boolean;
  cache: boolean;
  entropyHex?: number;
  entropyBase64?: number;
  minLength?: number;
  ignore?: string;
  config?: string;
  failOn?: Severity;
  verify?: boolean;
  confirmAuthorized?: boolean;
  quiet?: boolean;
  verbose?: boolean;
}

export interface Io {
  out: (s: string) => void;
  err: (s: string) => void;
}

const defaultIo: Io = {
  out: (s) => process.stdout.write(s),
  err: (s) => process.stderr.write(s),
};

function validateSince(since: string | undefined): void {
  if (since === undefined) return;
  if (since.startsWith('-') || /[\0\n]/.test(since) || since.length > 64) {
    throw new InvalidArgumentError('--since: invalid date');
  }
}

export function verifyBanner(verifiable: number): string {
  return [
    `! LIVE VERIFICATION ENABLED for ${verifiable} candidate credential${verifiable === 1 ? '' : 's'}`,
    '  Read-only checks only: AWS sts:GetCallerIdentity and GitHub GET /user (no other calls).',
    '  Only verify credentials you own or are explicitly authorized to test.',
    '  Never use a live credential; report it privately to the owner and have it rotated.',
    '',
  ].join('\n');
}

/** Console summary mirroring the demo: real counters only, never secret values. */
function printSummary(io: Io, result: ScanResult, opts: ScanCliOptions): void {
  const { report, written, ciFiles } = result;
  const s = report.stats;
  const ok = pc.green('✓');
  const line = (mark: string, text: string, detail: string): void =>
    io.out(`${mark} ${text}${detail ? pc.dim(`  (${detail})`) : ''}\n`);
  const suppressedTotal = Object.values(s.suppressed).reduce((a, b) => a + (b ?? 0), 0);
  if (!opts.quiet) {
    line(
      ok,
      'walking commit history',
      `${s.commitsWalked} commits, ${s.fileVersionsSeen} file versions`,
    );
    line(
      ok,
      'regex signature scan',
      `${s.uniqueBlobsScanned} unique blobs, ${s.cacheHits} cache hits`,
    );
    line(
      ok,
      'entropy analysis',
      `${suppressedTotal} candidate${suppressedTotal === 1 ? '' : 's'} suppressed`,
    );
    if (opts.ci) line(ok, 'CI/CD config scan', `${ciFiles} CI/CD files`);
    else line(pc.dim('-'), 'CI/CD config scan skipped', '--no-ci');
  }
  const n = report.summary.total;
  const bySev = SEVERITIES.map((sev) => `${report.summary.bySeverity[sev]} ${sev}`).join(', ');
  const detail = n > 0 ? `${bySev}; ${report.summary.historyOnly} history-only` : '';
  line(n > 0 ? pc.yellow('!') : ok, `${n} finding${n === 1 ? '' : 's'} detected`, detail);
  if (result.verification) {
    const v = result.verification;
    line(
      v.active > 0 ? pc.red('!') : ok,
      'live verification',
      `${v.active} active, ${v.inactive} inactive, ${v.unverifiable} unverifiable; ${v.calls.aws} AWS + ${v.calls.github} GitHub calls`,
    );
  }
  if (written.html) line(ok, 'report.html generated', written.html);
  if (written.json) line(ok, 'report.json generated', written.json);
  if (opts.verbose) {
    io.out(pc.dim(`  bytes scanned: ${s.bytesScanned}, duration: ${s.durationMs} ms\n`));
    io.out(
      pc.dim(
        `  skipped: ${s.skipped.binary} binary, ${s.skipped.oversize} oversize, ${s.skipped.ignored} ignored, ${s.skipped.missing} missing\n`,
      ),
    );
    const reasons = Object.entries(s.suppressed)
      .map(([k, v]) => `${k}=${v}`)
      .join(', ');
    io.out(pc.dim(`  suppressed: ${reasons || 'none'}\n`));
  }
}

async function scanAction(target: string, opts: ScanCliOptions, io: Io): Promise<number> {
  if (opts.verify && !opts.confirmAuthorized) {
    io.err(
      'error: --verify requires --confirm-authorized (you must be authorized to test these credentials)\n',
    );
    return EXIT_ERROR;
  }
  validateSince(opts.since);
  const cfg = await loadConfig(opts.config);
  const options: ScanOptions = {
    entropy: {
      hex: opts.entropyHex ?? cfg.entropy.hex,
      base64: opts.entropyBase64 ?? cfg.entropy.base64,
      minLength: opts.minLength ?? cfg.entropy.minLength,
    },
    ...(opts.maxCommits === undefined ? {} : { maxCommits: opts.maxCommits }),
    ...(opts.since === undefined ? {} : { since: opts.since }),
    ...(opts.branch === undefined ? {} : { branch: opts.branch }),
    ci: opts.ci,
    cache: opts.cache,
    verify: opts.verify === true,
    maxFileBytes: cfg.maxFileBytes,
  };
  const result = await runScan(
    {
      target,
      outDir: opts.out,
      formats: [...new Set(opts.format)],
      options,
      ...(opts.ignore ? { ignoreFile: opts.ignore } : {}),
      ignorePatterns: cfg.ignore,
      severityOverrides: cfg.severity,
    },
    {
      onVerifyStart: (n) => io.err(pc.yellow(verifyBanner(n))),
      onBeforeClone: (url) =>
        io.err(
          pc.yellow(
            `! Cloning remote repository ${url}\n  Only scan repositories you own or are explicitly authorized to scan.\n`,
          ),
        ),
    },
  );
  printSummary(io, result, opts);
  if (opts.failOn) {
    const threshold = SEVERITY_RANK[opts.failOn];
    if (result.report.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold))
      return EXIT_FINDINGS;
  }
  return EXIT_CLEAN;
}

interface DorkCliOptions {
  owner: string;
  org?: boolean;
  term?: string[];
  maxResults: number;
  out: string;
  format: Array<'html' | 'json'>;
  config?: string;
  failOn?: Severity;
  confirmAuthorized?: boolean;
  quiet?: boolean;
}

async function dorkAction(opts: DorkCliOptions, io: Io): Promise<number> {
  if (!opts.confirmAuthorized) {
    io.err(
      'error: dork requires --confirm-authorized (only search an owner you control: yourself or an org you administer)\n',
    );
    return EXIT_ERROR;
  }
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (!token) {
    io.err('error: set GITHUB_TOKEN (or GH_TOKEN) to a token for the owner you control\n');
    return EXIT_ERROR;
  }
  const cfg = await loadConfig(opts.config);
  const ok = pc.green('✓');
  const result = await runDork(
    {
      owner: opts.owner,
      ownerType: opts.org ? 'org' : 'user',
      ...(opts.term ? { terms: opts.term } : {}),
      maxResults: opts.maxResults,
      outDir: opts.out,
      formats: [...new Set(opts.format)],
      entropy: cfg.entropy,
      maxFileBytes: cfg.maxFileBytes,
      token,
    },
    { onProgress: (m) => (opts.quiet ? undefined : io.out(`${ok} ${m}\n`)) },
  );
  const r = result.report;
  const bySev = SEVERITIES.map((sev) => `${r.summary.bySeverity[sev]} ${sev}`).join(', ');
  io.out(
    `${r.summary.total > 0 ? pc.yellow('!') : ok} ${r.summary.total} finding${r.summary.total === 1 ? '' : 's'} detected${r.summary.total ? pc.dim(`  (${bySev})`) : ''}\n`,
  );
  if (result.incomplete) io.err(pc.yellow(`! results incomplete: ${result.incomplete}\n`));
  if (result.written.html)
    io.out(`${ok} report.html generated${pc.dim(`  (${result.written.html})`)}\n`);
  if (result.written.json)
    io.out(`${ok} report.json generated${pc.dim(`  (${result.written.json})`)}\n`);
  if (opts.failOn) {
    const threshold = SEVERITY_RANK[opts.failOn];
    if (r.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold)) return EXIT_FINDINGS;
  }
  return EXIT_CLEAN;
}

export function buildProgram(
  io: Io = defaultIo,
  setExit: (code: number) => void = () => undefined,
): Command {
  const program = new Command();
  program
    .name('git-leak-hunter')
    .description('Defensive scanner for secrets exposed anywhere in Git history and CI/CD config.')
    .version(VERSION)
    .addHelpText('after', RESPONSIBLE_USE)
    .exitOverride();

  program
    .command('scan')
    .description('Scan the full reachable history of a local repository path or a remote URL')
    .argument('<path-or-url>', 'local repository path, or a URL to clone (bare, hooks disabled)')
    .option('--out <dir>', 'output directory', './leak-report')
    .option('--format <list>', 'comma-separated output formats: html,json', parseFormats, [
      'html',
      'json',
    ])
    .option('--max-commits <n>', 'stop after walking n commits', parsePositiveInt)
    .option('--since <date>', 'only walk commits after this date')
    .option('--branch <name>', 'walk only this branch (default: all refs)')
    .option('--no-ci', 'skip CI/CD configuration scanning')
    .option('--no-cache', 'disable blob-hash memoization (benchmark use)')
    .option('--entropy-hex <n>', 'hex entropy threshold, bits/char', parseNonNegativeNumber)
    .option('--entropy-base64 <n>', 'base64 entropy threshold, bits/char', parseNonNegativeNumber)
    .option('--min-length <n>', 'minimum entropy candidate length', parsePositiveInt)
    .option('--ignore <file>', 'extra ignore rules file')
    .option('--config <file>', 'JSON config file (entropy thresholds, severity overrides, ignores)')
    .addOption(
      new Option(
        '--fail-on <severity>',
        'exit 1 if any finding is at or above this severity',
      ).choices([...SEVERITIES]),
    )
    .option('--verify', 'opt-in, read-only live verification (AWS STS, GitHub /user)')
    .option('--confirm-authorized', 'acknowledge you are authorized to verify these credentials')
    .option('--quiet', 'only print errors and the final summary')
    .option('--verbose', 'print progress details')
    .addHelpText('after', RESPONSIBLE_USE)
    .action(async (target: string, opts: ScanCliOptions) => {
      setExit(await scanAction(target, opts, io));
    });

  program
    .command('dork')
    .description(
      'Optional: search GitHub code (default branches) for candidate leaks within an owner YOU control',
    )
    .requiredOption(
      '--owner <name>',
      'GitHub user or org to search (must be you, or an org you administer)',
    )
    .option(
      '--org',
      'the owner is an organization (requires admin membership; token needs read:org)',
    )
    .option('--term <term...>', 'replace the built-in search terms (owner scope is always added)')
    .option('--max-results <n>', 'maximum files to fetch and scan', parsePositiveInt, 100)
    .option('--out <dir>', 'output directory', './leak-report')
    .option('--format <list>', 'comma-separated output formats: html,json', parseFormats, [
      'html',
      'json',
    ])
    .option('--config <file>', 'JSON config file (entropy thresholds, max file size)')
    .addOption(
      new Option(
        '--fail-on <severity>',
        'exit 1 if any finding is at or above this severity',
      ).choices([...SEVERITIES]),
    )
    .option('--confirm-authorized', 'acknowledge you control this owner and may search it')
    .option('--quiet', 'only print errors and the final summary')
    .addHelpText(
      'after',
      `
Token: read from GITHUB_TOKEN (or GH_TOKEN); it is never printed.
Every query is scoped to exactly user:<owner> or org:<owner>; unscoped queries are refused.
GitHub code search indexes default branches only — use \`scan <repo-url>\` for full history.
${RESPONSIBLE_USE}`,
    )
    .action(async (opts: DorkCliOptions) => {
      setExit(await dorkAction(opts, io));
    });

  return program;
}

export async function main(argv: readonly string[], io: Io = defaultIo): Promise<number> {
  let exit = EXIT_CLEAN;
  const program = buildProgram(io, (code) => {
    exit = code;
  });
  program.configureOutput({ writeOut: io.out, writeErr: io.err });
  try {
    await program.parseAsync([...argv], { from: 'node' });
    return exit;
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === 'commander.helpDisplayed' || code === 'commander.version') return EXIT_CLEAN;
    // commander already printed its own usage error.
    if (typeof code === 'string' && code.startsWith('commander.')) return EXIT_ERROR;
    // Messages are built by this tool (never from file content); no stack traces are printed.
    io.err(`error: ${err instanceof Error ? err.message : 'unknown error'}\n`);
    return EXIT_ERROR;
  }
}

function invokedDirectly(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    // realpath resolves the npm bin symlink to this file.
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  // Exit through process.exit so 'exit' hooks (temp clone cleanup) run on Ctrl-C / SIGTERM.
  process.once('SIGINT', () => process.exit(130));
  process.once('SIGTERM', () => process.exit(143));
  process.exitCode = await main(process.argv);
}
