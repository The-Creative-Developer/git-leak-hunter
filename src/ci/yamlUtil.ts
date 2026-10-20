/** Small helpers over the `yaml` AST: source offsets for scalars, safe map access. */
import { isMap, isScalar, parseDocument, type Document, type Node, type YAMLMap } from 'yaml';
import { CiParseError } from './common.js';

export function parseYaml(content: string): Document.Parsed {
  const doc = parseDocument(content, { uniqueKeys: false, strict: false, prettyErrors: false });
  if (doc.errors.length > 0) throw new CiParseError('malformed YAML');
  return doc;
}

export function mapGet(node: unknown, key: string): Node | null {
  if (!isMap(node)) return null;
  const v = (node as YAMLMap).get(key, true);
  return (v as Node | undefined) ?? null;
}

export interface ScalarEntry {
  key: string;
  value: string;
  /** Index in the source text where `value` starts (best effort for escaped scalars). */
  start: number;
}

/** String/number scalar pairs of a mapping, with source offsets. Nested values are skipped. */
export function scalarEntries(node: unknown, content: string): ScalarEntry[] {
  if (!isMap(node)) return [];
  const out: ScalarEntry[] = [];
  for (const pair of (node as YAMLMap).items) {
    if (!isScalar(pair.key) || !isScalar(pair.value)) continue;
    const raw = pair.value.value;
    if (typeof raw !== 'string' && typeof raw !== 'number') continue;
    const value = String(raw);
    const from = pair.value.range?.[0] ?? 0;
    const found = content.indexOf(value, from);
    out.push({ key: String(pair.key.value), value, start: found >= 0 ? found : from });
  }
  return out;
}

export function mapEntries(node: unknown): Array<[string, Node]> {
  if (!isMap(node)) return [];
  const out: Array<[string, Node]> = [];
  for (const pair of (node as YAMLMap).items) {
    if (isScalar(pair.key) && pair.value) out.push([String(pair.key.value), pair.value as Node]);
  }
  return out;
}
