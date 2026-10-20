/**
 * In-memory vault for raw secrets needed by live verification. It exists only when the user
 * opted in to `--verify`, holds only verifiable credential types, is never serialised, and is
 * cleared as soon as verification finishes. Findings reference entries by an opaque random id.
 */
import { randomBytes } from 'node:crypto';

export class Vault {
  private readonly byRef = new Map<string, string>();
  private readonly refByValue = new Map<string, string>();

  /** Store a raw value; the same value always maps to the same opaque reference. */
  put(raw: string): string {
    const existing = this.refByValue.get(raw);
    if (existing) return existing;
    const ref = randomBytes(12).toString('hex');
    this.byRef.set(ref, raw);
    this.refByValue.set(raw, ref);
    return ref;
  }

  get(ref: string): string | undefined {
    return this.byRef.get(ref);
  }

  get size(): number {
    return this.byRef.size;
  }

  clear(): void {
    this.byRef.clear();
    this.refByValue.clear();
  }

  /** Never let a vault end up in logs or JSON by accident. */
  toJSON(): string {
    return `[Vault: ${this.byRef.size} entries]`;
  }
}

/** Rule ids whose raw values are kept for verification (nothing else is ever stored). */
export const VERIFIABLE_RULES: ReadonlySet<string> = new Set([
  'aws-access-key-id',
  'aws-secret-access-key',
  'github-token',
  'github-fine-grained-pat',
]);
