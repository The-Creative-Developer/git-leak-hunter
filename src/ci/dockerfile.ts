/**
 * Dockerfile `ENV` / `ARG` with literal values: `ENV K=V [K2=V2…]`, legacy `ENV K V`, `ARG K=V`,
 * with backslash line continuations. Offsets map back to the original text for line numbers.
 */
import type { Candidate } from '../detect/types.js';
import { literalCandidate } from './common.js';

const RULE = {
  ruleId: 'dockerfile-literal',
  secretType: 'Dockerfile ENV/ARG Secret',
  detector: 'ci',
} as const;

interface LogicalLine {
  text: string;
  /** Original content index for each character of `text`. */
  map: number[];
}

/** Join continuation lines into logical instructions, remembering original offsets. */
export function logicalLines(content: string): LogicalLine[] {
  const out: LogicalLine[] = [];
  let cur: LogicalLine | null = null;
  let offset = 0;
  for (const physical of content.split('\n')) {
    const lineStart = offset;
    offset += physical.length + 1;
    const line = physical.replace(/\r$/, '');
    if (cur && /^\s*#/.test(line)) continue; // comments inside a continuation are dropped
    const continues = /\\\s*$/.test(line);
    const body = continues ? line.replace(/\\\s*$/, '') : line;
    if (!cur) cur = { text: '', map: [] };
    for (let i = 0; i < body.length; i++) {
      cur.text += body[i];
      cur.map.push(lineStart + i);
    }
    if (continues) {
      cur.text += ' ';
      cur.map.push(lineStart + body.length);
    } else {
      out.push(cur);
      cur = null;
    }
  }
  if (cur) out.push(cur);
  return out;
}

/** Split `K=V K2="V 2"` into pairs with their start index in `s`. */
function keyValuePairs(s: string, base: number): Array<{ key: string; value: string; at: number }> {
  const out: Array<{ key: string; value: string; at: number }> = [];
  const re = /([A-Za-z_][A-Za-z0-9_.-]*)=("(?:\\.|[^"\\])*"|'[^']*'|[^\s"']*)/g;
  for (const m of s.matchAll(re)) {
    const key = m[1] ?? '';
    let value = m[2] ?? '';
    let at = base + (m.index ?? 0) + key.length + 1;
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
      at += 1;
    }
    out.push({ key, value, at });
  }
  return out;
}

export function dockerfileCandidates(content: string): Candidate[] {
  const out: Candidate[] = [];
  for (const ll of logicalLines(content)) {
    const m = /^\s*(ENV|ARG)\s+(.*)$/i.exec(ll.text);
    if (!m) continue;
    const args = m[2] ?? '';
    const argsStart = ll.text.length - args.length;
    const pairs: Array<{ key: string; value: string; at: number }> = [];
    const legacy = /^([A-Za-z_][A-Za-z0-9_.-]*)\s+(\S.*)$/.exec(args);
    if (
      (m[1] ?? '').toUpperCase() === 'ENV' &&
      legacy &&
      !(legacy[1] ?? '').includes('=') &&
      !args.split(/\s+/)[0]?.includes('=')
    ) {
      const key = legacy[1] ?? '';
      const value = (legacy[2] ?? '').trim();
      pairs.push({ key, value, at: argsStart + args.indexOf(value, key.length) });
    } else {
      pairs.push(...keyValuePairs(args, argsStart));
    }
    for (const p of pairs) {
      const start = ll.map[p.at];
      const endMapped = ll.map[p.at + p.value.length - 1];
      // Skip values that span a continuation (offsets would not be contiguous in the source).
      if (
        start === undefined ||
        endMapped === undefined ||
        endMapped - start !== p.value.length - 1
      )
        continue;
      const c = literalCandidate({ ...RULE, key: p.key, value: p.value, start });
      if (c) out.push(c);
    }
  }
  return out;
}
