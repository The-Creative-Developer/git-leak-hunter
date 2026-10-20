/**
 * Leak assertions that never print the secret they are looking for. `expect(out).not.toContain(s)`
 * would echo `s` into the test output on failure, which violates rule 1.
 */

function describe(secret: string): string {
  return `${secret.slice(0, 2)}…(${secret.length} chars)`;
}

/** Returns non-sensitive descriptions of every secret found in `haystack`. */
export function findLeaks(haystack: string, secrets: Iterable<string>): string[] {
  const leaks: string[] = [];
  for (const s of secrets) {
    if (s.length > 0 && haystack.includes(s)) leaks.push(describe(s));
  }
  return leaks;
}

export function expectNoLeak(haystack: string, secrets: Iterable<string>, label: string): void {
  const leaks = findLeaks(haystack, secrets);
  if (leaks.length > 0) {
    throw new Error(`${label}: ${leaks.length} full secret(s) leaked: ${leaks.join(', ')}`);
  }
}
