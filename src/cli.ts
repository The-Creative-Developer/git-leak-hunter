#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Command, InvalidArgumentError, Option } from 'commander';
import pc from 'picocolors';
import { SEVERITIES, type Severity } from './types.js';
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

export function buildProgram(): Command {
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
    .addOption(
      new Option('--fail-on <severity>', 'exit 1 if any finding is at or above this severity')
        .choices([...SEVERITIES])
        .argParser((v) => v.toLowerCase() as Severity),
    )
    .option('--verify', 'opt-in, read-only live verification (AWS STS, GitHub /user)')
    .option('--confirm-authorized', 'acknowledge you are authorized to verify these credentials')
    .option('--quiet', 'only print errors and the final summary')
    .option('--verbose', 'print progress details')
    .addHelpText('after', RESPONSIBLE_USE)
    .action(() => {
      process.stderr.write(pc.yellow('scan is not implemented yet (Phase 2).\n'));
      process.exitCode = EXIT_ERROR;
    });

  return program;
}

export async function main(argv: readonly string[]): Promise<number> {
  const program = buildProgram();
  try {
    await program.parseAsync([...argv], { from: 'node' });
    return typeof process.exitCode === 'number' ? process.exitCode : EXIT_CLEAN;
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === 'commander.helpDisplayed' || code === 'commander.version') return EXIT_CLEAN;
    // commander already printed its own usage error.
    if (typeof code === 'string' && code.startsWith('commander.')) return EXIT_ERROR;
    process.stderr.write(`error: ${err instanceof Error ? err.message : 'unknown error'}\n`);
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
  process.exitCode = await main(process.argv);
}
