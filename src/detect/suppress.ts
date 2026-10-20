/**
 * False-positive suppression. Each check returns the reason it fired so the stats can count it.
 */
import type { SuppressionReason } from '../types.js';

const j = (...p: string[]): string => p.join('');

/** Well-known documentation keys (assembled from fragments: rule 4). */
export const KNOWN_EXAMPLES: ReadonlySet<string> = new Set([
  j('AKIA', 'IOSFODNN7', 'EXAMPLE'),
  j('wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCY', 'EXAMPLEKEY'),
  j('AKIA', 'I44QH8DHB', 'EXAMPLE'),
  j('je7MtGbClwBF/2Zp9Utk/', 'h3yCo8nvb', 'EXAMPLEKEY'),
]);

export const LOCKFILE_NAMES: ReadonlySet<string> = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
  'Cargo.lock',
  'go.sum',
  'poetry.lock',
  'Pipfile.lock',
  'composer.lock',
  'Gemfile.lock',
  'packages.lock.json',
  'mix.lock',
  'pubspec.lock',
  'Podfile.lock',
  'flake.lock',
]);

const PLACEHOLDER_WORDS =
  /(changeme|change_me|your[_-]?(?:api[_-]?)?(?:key|token|secret|password)|_here\b|example|sample|dummy|placeholder|redacted|insert[_-]?|replace[_-]?me|todo|fixme|not[_-]?a[_-]?(?:real|secret)|xxxx|\*\*\*\*|\.\.\.\.)/i;
const ANGLE_PLACEHOLDER = /^<[^<>]+>$/;
const CI_EXPRESSION = /\$\{\{.*\}\}/;
const ENV_REFERENCE =
  /^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|\{\{.*\}\})$|process\.env\.|os\.environ|getenv\(|ENV\[/;
const INTERPOLATION = /\$\{[^}]+\}/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GIT_SHA = /^[0-9a-f]{40}$/;
const INTEGRITY = /^(?:sha(?:1|256|384|512)-[A-Za-z0-9+/=]+|h1:[A-Za-z0-9+/=]+)$/;
const DATA_URI = /data:[a-z]+\/[a-z0-9.+-]+;base64,/i;

/** Distinct characters at or below this count makes a long value "repeated characters". */
const MAX_DISTINCT_FOR_REPEAT = 3;

export function isRepeated(value: string): boolean {
  return new Set(value).size <= MAX_DISTINCT_FOR_REPEAT;
}

export interface SuppressContext {
  /** The full source line containing the value. */
  lineText: string;
  /** Signature matches only get the checks that make sense for a known format. */
  signature: boolean;
  /** Body of a signature match after its vendor prefix (for repeated/placeholder checks). */
  body?: string;
}

/** Reason the value should not be reported, or null. Entropy is checked separately. */
export function suppressionReason(value: string, ctx: SuppressContext): SuppressionReason | null {
  if (ctx.lineText.includes('leakhunter:ignore')) return 'inline-ignore';
  if (KNOWN_EXAMPLES.has(value)) return 'known-example';
  if (ctx.signature) {
    const body = ctx.body ?? value;
    if (isRepeated(body)) return 'repeated-chars';
    if (/x{6,}|EXAMPLE/i.test(body)) return 'placeholder';
    return null;
  }
  if (CI_EXPRESSION.test(value)) return 'ci-expression';
  if (ENV_REFERENCE.test(value)) return 'env-reference';
  // Interpolated strings (`Bearer ${token}`, shell "${A}:${B}") are built at runtime, not literals.
  if (INTERPOLATION.test(value)) return 'env-reference';
  if (ANGLE_PLACEHOLDER.test(value) || PLACEHOLDER_WORDS.test(value)) return 'placeholder';
  if (UUID.test(value)) return 'uuid';
  if (GIT_SHA.test(value)) return 'git-sha';
  if (INTEGRITY.test(value)) return 'lockfile';
  if (isRepeated(value)) return 'repeated-chars';
  if (DATA_URI.test(ctx.lineText) && ctx.lineText.indexOf(value) > ctx.lineText.search(DATA_URI)) {
    return 'data-uri';
  }
  return null;
}

export function isLockfilePath(filePath: string): boolean {
  return LOCKFILE_NAMES.has(filePath.split('/').pop() ?? '');
}

/** Vendored or minified code: entropy-only candidates there are suppressed. */
export function isVendorPath(filePath: string): boolean {
  return (
    /(^|\/)(node_modules|vendor|third_party|bower_components)\//.test(filePath) ||
    /\.min\.(js|css)$/.test(filePath)
  );
}
