/**
 * GitLab CI: literal values under `variables:` (global and per job, including the
 * `{ value: … }` form). `$VAR` / `${VAR}` references are suppressed.
 */
import { isMap, isScalar, isSeq } from 'yaml';
import type { Candidate } from '../detect/types.js';
import { literalCandidate } from './common.js';
import { mapEntries, mapGet, parseYaml, scalarEntries } from './yamlUtil.js';

const RULE = {
  ruleId: 'gitlab-ci-literal',
  secretType: 'GitLab CI Literal Secret',
  detector: 'ci',
} as const;

function variableCandidates(variables: unknown, content: string, out: Candidate[]): void {
  for (const e of scalarEntries(variables, content)) {
    const c = literalCandidate({ ...RULE, key: e.key, value: e.value, start: e.start });
    if (c) out.push(c);
  }
  // `NAME: { value: "…", description: "…" }`
  for (const [key, node] of mapEntries(variables)) {
    if (!isMap(node)) continue;
    for (const e of scalarEntries(node, content)) {
      if (e.key !== 'value') continue;
      const c = literalCandidate({ ...RULE, key, value: e.value, start: e.start });
      if (c) out.push(c);
    }
  }
}

export function gitlabCiCandidates(content: string): Candidate[] {
  const doc = parseYaml(content);
  const out: Candidate[] = [];
  const root = doc.contents;
  variableCandidates(mapGet(root, 'variables'), content, out);
  for (const [name, job] of mapEntries(root)) {
    if (name === 'variables') continue;
    variableCandidates(mapGet(job, 'variables'), content, out);
  }
  return out;
}

/** In-repo files pulled in with `include: local` (or a bare `/path.yml` string). */
export function gitlabLocalIncludes(content: string): string[] {
  let root: unknown;
  try {
    root = parseYaml(content).contents;
  } catch {
    return [];
  }
  const include = mapGet(root, 'include');
  const items: unknown[] = isSeq(include) ? include.items : include ? [include] : [];
  const out: string[] = [];
  for (const item of items) {
    let p: unknown = null;
    if (isScalar(item)) p = item.value;
    else {
      const local = mapGet(item, 'local');
      if (isScalar(local)) p = local.value;
    }
    if (typeof p === 'string' && !/^[a-z]+:\/\//i.test(p) && !p.includes('*')) {
      out.push(p.replace(/^\/+/, ''));
    }
  }
  return out;
}
