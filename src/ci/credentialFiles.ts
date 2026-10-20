/**
 * Committed credential files, recognised by path (see detect/fileKind.ts): `.env*`, `.npmrc`,
 * `credentials*.json`, docker config, `id_rsa`-style keys, `.pgpass`, `.netrc`, `.git-credentials`.
 */
import type { Candidate, FileKind } from '../detect/types.js';
import { literalCandidate } from './common.js';

const detector = 'credential-file' as const;

function lines(content: string): Array<{ text: string; start: number }> {
  const out: Array<{ text: string; start: number }> = [];
  let start = 0;
  for (const text of content.split('\n')) {
    out.push({ text: text.replace(/\r$/, ''), start });
    start += text.length + 1;
  }
  return out;
}

function dotenv(content: string): Candidate[] {
  const out: Candidate[] = [];
  for (const { text, start } of lines(content)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(text);
    if (!m) continue;
    const key = m[1] ?? '';
    let value = m[2] ?? '';
    let at = start + text.length - value.length;
    const quoted = /^(["'])(.*)\1\s*(?:#.*)?$/.exec(value);
    if (quoted) {
      value = quoted[2] ?? '';
      at += 1;
    } else {
      value = value.replace(/\s+#.*$/, '');
    }
    const c = literalCandidate({
      ruleId: 'dotenv-secret',
      secretType: 'Secret in .env File',
      detector,
      key,
      value,
      start: at,
    });
    if (c) out.push(c);
  }
  return out;
}

function npmrc(content: string): Candidate[] {
  const out: Candidate[] = [];
  for (const { text, start } of lines(content)) {
    const m = /(?:^|:)(_authToken|_auth|_password)\s*=\s*(\S+)/.exec(text);
    if (!m) continue;
    const value = m[2] ?? '';
    const at = start + (m.index ?? 0) + m[0].length - value.length;
    const c = literalCandidate({
      ruleId: 'npmrc-auth-token',
      secretType: 'npm Auth Token',
      detector,
      key: 'auth_token',
      value,
      start: at,
    });
    if (c) out.push({ ...c, allowWeak: true, secretLikeKey: true });
  }
  return out;
}

function jsonSecrets(content: string, ruleId: string, secretType: string): Candidate[] {
  const out: Candidate[] = [];
  for (const m of content.matchAll(/"([A-Za-z0-9_.-]+)"\s*:\s*"((?:\\.|[^"\\])*)"/g)) {
    const key = m[1] ?? '';
    const value = m[2] ?? '';
    const at = (m.index ?? 0) + m[0].length - value.length - 1;
    const c = literalCandidate({ ruleId, secretType, detector, key, value, start: at });
    if (c) out.push(key === 'auth' ? { ...c, allowWeak: true, secretLikeKey: true } : c);
  }
  return out;
}

function pgpass(content: string): Candidate[] {
  const out: Candidate[] = [];
  for (const { text, start } of lines(content)) {
    if (!text.trim() || text.startsWith('#')) continue;
    const fields = text.split(/(?<!\\):/);
    if (fields.length < 5) continue;
    const value = fields.slice(4).join(':');
    const c = literalCandidate({
      ruleId: 'pgpass-password',
      secretType: 'PostgreSQL Password File',
      detector,
      key: 'password',
      value,
      start: start + text.length - value.length,
    });
    if (c) out.push(c);
  }
  return out;
}

function netrc(content: string): Candidate[] {
  const out: Candidate[] = [];
  for (const m of content.matchAll(/\bpassword\s+(\S+)/g)) {
    const value = m[1] ?? '';
    const c = literalCandidate({
      ruleId: 'netrc-password',
      secretType: '.netrc Password',
      detector,
      key: 'password',
      value,
      start: (m.index ?? 0) + m[0].length - value.length,
    });
    if (c) out.push(c);
  }
  return out;
}

function gitCredentials(content: string): Candidate[] {
  const out: Candidate[] = [];
  for (const m of content.matchAll(/[a-z][a-z0-9+.-]*:\/\/[^:/\s@]+:([^@\s]+)@/gi)) {
    const value = m[1] ?? '';
    const c = literalCandidate({
      ruleId: 'git-credentials-password',
      secretType: 'Git Credential Store Password',
      detector,
      key: 'password',
      value,
      start: (m.index ?? 0) + m[0].length - value.length - 1,
    });
    if (c) out.push(c);
  }
  return out;
}

/** An `id_rsa`-style file without a PEM block (otherwise the private-key signature covers it). */
function sshKeyFile(content: string): Candidate[] {
  const trimmed = content.trim();
  if (!trimmed || /PRIVATE KEY-----/.test(content)) return [];
  const firstLine = trimmed.split('\n')[0] ?? trimmed;
  const start = content.indexOf(firstLine);
  return [
    {
      ruleId: 'ssh-private-key-file',
      secretType: 'SSH Private Key File',
      detector,
      start,
      end: start + firstLine.length,
      value: trimmed,
      entropyRequired: false,
      preview: '[credential file contents]',
    },
  ];
}

export function credentialFileCandidates(kind: FileKind, content: string): Candidate[] {
  switch (kind) {
    case 'dotenv':
      return dotenv(content);
    case 'npmrc':
      return npmrc(content);
    case 'credentials-json':
      return jsonSecrets(content, 'credentials-json-secret', 'Secret in Credentials File');
    case 'docker-config':
      return jsonSecrets(content, 'docker-config-auth', 'Docker Registry Auth');
    case 'pgpass':
      return pgpass(content);
    case 'netrc':
      return netrc(content);
    case 'git-credentials':
      return gitCredentials(content);
    case 'ssh-key':
      return sshKeyFile(content);
    default:
      return [];
  }
}
