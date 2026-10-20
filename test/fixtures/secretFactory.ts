/**
 * Fabricated, non-functional secret generators for fixture repos.
 *
 * Rule 4: no token-looking literal may exist in this project's source or history, so every vendor
 * prefix is assembled from fragments at runtime and every body comes from a seeded PRNG. The values
 * have valid *formats* only — random bodies carry no valid checksums and belong to no account.
 */

/** mulberry32 — small, fast, deterministic 32-bit PRNG. */
export class Rng {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  int(maxExclusive: number): number {
    return Math.floor(this.next() * maxExclusive);
  }

  chars(alphabet: string, length: number): string {
    let out = '';
    for (let i = 0; i < length; i++) out += alphabet[this.int(alphabet.length)];
    return out;
  }

  bytes(length: number): Buffer {
    const buf = Buffer.alloc(length);
    for (let i = 0; i < length; i++) buf[i] = this.int(256);
    return buf;
  }
}

export const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export const LOWER = 'abcdefghijklmnopqrstuvwxyz';
export const DIGITS = '0123456789';
export const ALNUM = UPPER + LOWER + DIGITS;
export const BASE64 = ALNUM + '+/';
export const BASE32 = UPPER + '234567';
export const HEX = '0123456789abcdef';

const j = (...parts: string[]): string => parts.join('');

/** Vendor prefixes, assembled so that no source line contains a token-shaped literal. */
export const PREFIX = {
  awsKeyId: j('AK', 'IA'),
  github: j('gh', 'p_'),
  stripeLive: j('sk', '_li', 've_'),
  stripeTest: j('sk', '_te', 'st_'),
  slackBot: j('xo', 'xb-'),
  slackWebhook: j('https://hooks', '.slack', '.com/services/'),
  npmToken: j('np', 'm_'),
} as const;

export function privateKeyHeader(kind: 'RSA' | 'EC' | 'OPENSSH'): string {
  return j('-----BEGIN ', kind, ' PRIVATE', ' KEY-----');
}

export function privateKeyFooter(kind: 'RSA' | 'EC' | 'OPENSSH'): string {
  return j('-----END ', kind, ' PRIVATE', ' KEY-----');
}

/** AWS's own documentation example key pair — a well-known placeholder, never a real credential. */
export const AWS_DOC_EXAMPLE = {
  keyId: j(PREFIX.awsKeyId, 'IOSFODNN7', 'EXAMPLE'),
  secret: j('wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCY', 'EXAMPLEKEY'),
} as const;

export interface PrivateKeyBlock {
  /** The full PEM block (header, body, footer) joined with "\n". */
  pem: string;
  /** Lines of the PEM block. */
  lines: string[];
  /** Body lines only — each must also never appear in output. */
  bodyLines: string[];
}

export class SecretFactory {
  constructor(readonly rng: Rng) {}

  awsAccessKeyId(): string {
    return PREFIX.awsKeyId + this.rng.chars(BASE32, 16);
  }

  awsSecretAccessKey(): string {
    return this.rng.chars(BASE64, 40);
  }

  githubToken(): string {
    return PREFIX.github + this.rng.chars(ALNUM, 36);
  }

  stripeLiveKey(): string {
    return PREFIX.stripeLive + this.rng.chars(ALNUM, 24);
  }

  stripeTestKey(): string {
    return PREFIX.stripeTest + this.rng.chars(ALNUM, 24);
  }

  slackBotToken(): string {
    return `${PREFIX.slackBot}${this.rng.chars(DIGITS, 11)}-${this.rng.chars(DIGITS, 13)}-${this.rng.chars(ALNUM, 24)}`;
  }

  slackWebhook(): string {
    return `${PREFIX.slackWebhook}T${this.rng.chars(UPPER + DIGITS, 8)}/B${this.rng.chars(UPPER + DIGITS, 10)}/${this.rng.chars(ALNUM, 24)}`;
  }

  npmToken(): string {
    return PREFIX.npmToken + this.rng.chars(ALNUM, 36);
  }

  /** A random high-entropy secret with no vendor prefix (target of the entropy layer). */
  generic(length = 40): string {
    return this.rng.chars(ALNUM, length);
  }

  privateKey(kind: 'RSA' | 'EC' | 'OPENSSH' = 'RSA', bodyLineCount = 12): PrivateKeyBlock {
    const bodyLines: string[] = [];
    for (let i = 0; i < bodyLineCount; i++) bodyLines.push(this.rng.chars(BASE64, 64));
    const lines = [privateKeyHeader(kind), ...bodyLines, privateKeyFooter(kind)];
    return { pem: lines.join('\n'), lines, bodyLines };
  }

  // ---- false-positive bait -------------------------------------------------------------------

  uuid(): string {
    const h = (n: number): string => this.rng.chars(HEX, n);
    return `${h(8)}-${h(4)}-4${h(3)}-${'89ab'[this.rng.int(4)]}${h(3)}-${h(12)}`;
  }

  gitSha(): string {
    return this.rng.chars(HEX, 40);
  }

  integritySha512(): string {
    return `sha512-${this.rng.bytes(64).toString('base64')}`;
  }

  goSumHash(): string {
    return `h1:${this.rng.bytes(32).toString('base64')}`;
  }

  dataUriPng(byteLength = 180): string {
    return `data:image/png;base64,${this.rng.bytes(byteLength).toString('base64')}`;
  }
}
