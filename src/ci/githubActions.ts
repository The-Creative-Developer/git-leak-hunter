/**
 * GitHub Actions workflows: literal values in `env:` (workflow, job, step, container, services)
 * and hardcoded `with:` inputs / container `credentials:`. `${{ … }}` expressions are suppressed.
 */
import { isSeq, type Node } from 'yaml';
import type { Candidate } from '../detect/types.js';
import { literalCandidate } from './common.js';
import { mapEntries, mapGet, parseYaml, scalarEntries } from './yamlUtil.js';

const RULE = {
  ruleId: 'github-actions-literal',
  secretType: 'GitHub Actions Literal Secret',
  detector: 'ci',
} as const;

export function githubActionsCandidates(content: string): Candidate[] {
  const doc = parseYaml(content);
  const out: Candidate[] = [];
  const add = (node: Node | null): void => {
    for (const e of scalarEntries(node, content)) {
      const c = literalCandidate({ ...RULE, key: e.key, value: e.value, start: e.start });
      if (c) out.push(c);
    }
  };
  const addContainer = (container: Node | null): void => {
    add(mapGet(container, 'env'));
    add(mapGet(container, 'credentials'));
  };

  const root = doc.contents;
  add(mapGet(root, 'env'));
  for (const [, job] of mapEntries(mapGet(root, 'jobs'))) {
    add(mapGet(job, 'env'));
    add(mapGet(job, 'with'));
    addContainer(mapGet(job, 'container'));
    for (const [, service] of mapEntries(mapGet(job, 'services'))) addContainer(service);
    const steps = mapGet(job, 'steps');
    if (isSeq(steps)) {
      for (const step of steps.items) {
        add(mapGet(step, 'env'));
        add(mapGet(step, 'with'));
      }
    }
  }
  return out;
}
