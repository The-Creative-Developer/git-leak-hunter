import { describe, expect, it } from 'vitest';
import { gitEnv, stripUrlCredentials } from '../../src/git/exec.js';
import { isRemoteTarget, validateRemoteUrl } from '../../src/git/repo.js';

describe('remote targets', () => {
  it('recognises URLs and scp-like ssh targets', () => {
    expect(isRemoteTarget('https://github.com/a/b.git')).toBe(true);
    expect(isRemoteTarget('git@github.com:a/b.git')).toBe(true);
    expect(isRemoteTarget('./local/repo')).toBe(false);
    expect(isRemoteTarget('/abs/path')).toBe(false);
  });

  it('accepts https and ssh only', () => {
    expect(() => validateRemoteUrl('https://github.com/a/b.git')).not.toThrow();
    expect(() => validateRemoteUrl('ssh://git@example.test/a.git')).not.toThrow();
    expect(() => validateRemoteUrl('git@github.com:a/b.git')).not.toThrow();
  });

  it.each([
    'ext::sh -c touch% /tmp/pwned',
    'file:///etc/passwd',
    'http://example.test/a.git',
    'git://example.test/a.git',
    '--upload-pack=touch /tmp/x',
    'https://exa mple.test/a.git',
  ])('rejects %s', (url) => {
    expect(() => validateRemoteUrl(url)).toThrow();
  });

  it('strips credentials from URLs before display', () => {
    expect(stripUrlCredentials('https://user:tok3n@github.com/a/b.git')).toBe(
      'https://github.com/a/b.git',
    );
    expect(stripUrlCredentials('see https://x@h.test and ssh://u:p@h.test/r')).toBe(
      'see https://h.test and ssh://h.test/r',
    );
  });

  it('removes repository-redirecting GIT_* variables from the git environment', () => {
    process.env.GIT_DIR = '/elsewhere';
    process.env.GIT_SSH_COMMAND = 'ssh -i key';
    try {
      const env = gitEnv();
      expect(env.GIT_DIR).toBeUndefined();
      expect(env.GIT_SSH_COMMAND).toBe('ssh -i key');
      expect(env.GIT_TERMINAL_PROMPT).toBe('0');
    } finally {
      delete process.env.GIT_DIR;
      delete process.env.GIT_SSH_COMMAND;
    }
  });
});
