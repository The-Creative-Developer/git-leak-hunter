import { describe, expect, it } from 'vitest';
import { findSignatureCandidates } from '../../src/detect/signatures.js';
import { PREFIX, Rng, SecretFactory, ALNUM } from '../fixtures/secretFactory.js';

const f = new SecretFactory(new Rng(99));
const ids = (content: string): string[] => findSignatureCandidates(content).map((c) => c.ruleId);

describe('signatures: positives', () => {
  it.each([
    ['aws-access-key-id', () => f.awsAccessKeyId()],
    ['github-token', () => f.githubToken()],
    ['stripe-live-key', () => f.stripeLiveKey()],
    ['stripe-test-key', () => f.stripeTestKey()],
    ['slack-token', () => f.slackBotToken()],
    ['slack-webhook', () => f.slackWebhook()],
  ])('%s', (rule, make) => {
    const secret = make();
    const found = findSignatureCandidates(`const x = "${secret}";`);
    expect(found.map((c) => c.ruleId)).toContain(rule);
    const c = found.find((x) => x.ruleId === rule)!;
    expect(c.value === secret).toBe(true);
    expect(c.start).toBe(11);
  });

  it('matches other AWS and GitHub prefixes', () => {
    const rng = new Rng(5);
    for (const p of [
      ['AS', 'IA'],
      ['AI', 'DA'],
    ]) {
      const id = p.join('') + rng.chars('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16);
      expect(ids(`key=${id}`)).toContain('aws-access-key-id');
    }
    for (const p of ['o', 'u', 's', 'r']) {
      expect(ids(`t=gh${p}_${rng.chars(ALNUM, 36)}`)).toContain('github-token');
    }
    const fine = ['github', '_pat_'].join('') + rng.chars(ALNUM, 22) + '_' + rng.chars(ALNUM, 59);
    expect(ids(fine)).toContain('github-fine-grained-pat');
  });

  it('captures a private key block with its line count', () => {
    const key = f.privateKey('EC', 5);
    const found = findSignatureCandidates(`x\n${key.pem}\ny`);
    const pk = found.find((c) => c.ruleId === 'private-key')!;
    expect(pk.value === key.pem).toBe(true);
    expect(pk.preview).toBe('BEGIN EC PRIVATE KEY [REDACTED, 7 lines]');
  });

  it('pairs an AWS secret access key within the window', () => {
    const content = `id = ${f.awsAccessKeyId()}\nregion = us-east-1\nsecret = ${f.awsSecretAccessKey()}\n`;
    const found = findSignatureCandidates(content);
    const id = found.findIndex((c) => c.ruleId === 'aws-access-key-id');
    const secret = found.findIndex((c) => c.ruleId === 'aws-secret-access-key');
    expect(secret).toBeGreaterThanOrEqual(0);
    expect(found[id]!.pairWith).toBe(secret);
    expect(found[secret]!.pairWith).toBe(id);
  });

  it('does not pair a secret far away or a hex string', () => {
    const far = `id = ${f.awsAccessKeyId()}\n${'\n'.repeat(10)}secret = ${f.awsSecretAccessKey()}\n`;
    expect(ids(far)).not.toContain('aws-secret-access-key');
    const hex = `id = ${f.awsAccessKeyId()}\nsha = ${'ab12'.repeat(10)}\n`;
    expect(ids(hex)).not.toContain('aws-secret-access-key');
  });
});

describe('signatures: negatives', () => {
  const rng = new Rng(7);
  it.each([
    ['too short AWS', PREFIX.awsKeyId + rng.chars('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 12)],
    [
      'AWS inside a longer token',
      'X' + PREFIX.awsKeyId + rng.chars('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 16),
    ],
    ['short GitHub body', PREFIX.github + rng.chars(ALNUM, 30)],
    ['GitHub body too long', PREFIX.github + rng.chars(ALNUM, 40)],
    ['unknown GitHub prefix', 'ghx_' + rng.chars(ALNUM, 36)],
    ['Stripe publishable key', 'pk_live_' + rng.chars(ALNUM, 24)],
    ['Stripe short body', PREFIX.stripeLive + rng.chars(ALNUM, 8)],
    ['Slack without segments', 'xoxb' + rng.chars(ALNUM, 20)],
    ['public key block', '-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----'],
    ['plain prose', 'the secret token is stored in the vault'],
  ])('%s', (_name, text) => {
    expect(findSignatureCandidates(text)).toEqual([]);
  });
});
