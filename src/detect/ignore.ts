/**
 * `.leakhunterignore` / `--ignore <file>`:
 *   - one gitignore-style path glob per line (`*`, `**`, `?`, leading `/` anchors, trailing `/`
 *     matches a directory); a pattern without `/` matches the basename at any depth
 *   - `fingerprint:<hex>` ignores one specific finding
 *   - `#` starts a comment. Negation (`!`) is not supported.
 */

export interface IgnoreRules {
  paths: RegExp[];
  fingerprints: Set<string>;
}

export function emptyIgnoreRules(): IgnoreRules {
  return { paths: [], fingerprints: new Set() };
}

function globToRegExp(glob: string): RegExp {
  let g = glob;
  const anchored = g.startsWith('/');
  if (anchored) g = g.slice(1);
  const dirOnly = g.endsWith('/');
  if (dirOnly) g = g.slice(0, -1);
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const ch = g.charAt(i);
    if (ch === '*') {
      if (g[i + 1] === '*') {
        i++;
        if (g[i + 1] === '/') {
          i++;
          re += '(?:.*/)?';
        } else {
          re += '.*';
        }
      } else {
        re += '[^/]*';
      }
    } else if (ch === '?') {
      re += '[^/]';
    } else {
      re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  const prefix = anchored || g.includes('/') ? '^' : '^(?:.*/)?';
  const suffix = dirOnly ? '/' : '(?:$|/)';
  return new RegExp(prefix + re + suffix);
}

export function parseIgnore(text: string, into: IgnoreRules = emptyIgnoreRules()): IgnoreRules {
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const fp = /^fingerprint:([0-9a-f]{16,64})$/.exec(line);
    if (fp?.[1]) {
      into.fingerprints.add(fp[1]);
      continue;
    }
    if (line.startsWith('!')) continue;
    into.paths.push(globToRegExp(line));
  }
  return into;
}

export function isIgnoredPath(rules: IgnoreRules, filePath: string): boolean {
  return rules.paths.some((re) => re.test(filePath));
}
