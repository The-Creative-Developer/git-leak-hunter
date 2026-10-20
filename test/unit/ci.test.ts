import { describe, expect, it } from 'vitest';
import { scanBlob } from '../../src/detect/engine.js';
import { fileKindOf } from '../../src/detect/fileKind.js';
import { CiParseError, structuredCandidates } from '../../src/ci/index.js';
import { gitlabLocalIncludes } from '../../src/ci/gitlabCi.js';
import { logicalLines } from '../../src/ci/dockerfile.js';
import { Rng, SecretFactory } from '../fixtures/secretFactory.js';
import { detectConfig, unitOf } from '../helpers/unit.js';

const f = new SecretFactory(new Rng(31));
const text = (...l: string[]) => l.join('\n') + '\n';

/** Findings (rule, line) for `content` parsed as the kind implied by `path`. */
function scan(content: string, path: string) {
  const kind = fileKindOf(path);
  return scanBlob(unitOf(content, path), kind, detectConfig());
}

describe('file kinds', () => {
  it.each([
    ['.github/workflows/ci.yml', 'github-actions'],
    ['.github/workflows/nested/ci.yml', 'generic'],
    ['.gitlab-ci.yml', 'gitlab-ci'],
    ['ci/deploy.gitlab-ci.yml', 'gitlab-ci'],
    ['Dockerfile', 'dockerfile'],
    ['app.Dockerfile', 'dockerfile'],
    ['Dockerfile.prod', 'dockerfile'],
    ['.env', 'dotenv'],
    ['config/.env.production', 'dotenv'],
    ['.env.example', 'generic'],
    ['.npmrc', 'npmrc'],
    ['home/.ssh/id_ed25519', 'ssh-key'],
    ['home/.ssh/id_ed25519.pub', 'generic'],
    ['config/credentials.json', 'credentials-json'],
    ['.pgpass', 'pgpass'],
    ['.netrc', 'netrc'],
    ['.git-credentials', 'git-credentials'],
    ['yarn.lock', 'lockfile'],
  ])('%s → %s', (p, kind) => {
    expect(fileKindOf(p)).toBe(kind);
  });

  it('treats CI files as generic with --no-ci', () => {
    expect(fileKindOf('Dockerfile', { ci: false })).toBe('generic');
    expect(fileKindOf('.github/workflows/a.yml', { ci: false })).toBe('generic');
  });
});

describe('GitHub Actions', () => {
  it('flags literals in env (workflow/job/step) and with:, ignores expressions', () => {
    const [a, b, c, d] = [f.generic(32), f.generic(28), f.generic(30), f.generic(26)];
    const wf = text(
      'on: push',
      'env:',
      `  API_KEY: ${a}`,
      '  DEPLOY_TOKEN: ${{ secrets.API_KEY }}',
      'jobs:',
      '  build:',
      '    runs-on: ubuntu-latest',
      '    env:',
      `      DB_PASSWORD: "${b}"`,
      '      NODE_ENV: production',
      '    steps:',
      '      - uses: x/y@v1',
      '        env:',
      `          STEP_TOKEN: '${c}'`,
      '        with:',
      `          password: ${d}`,
      '          region: us-east-1',
    );
    const r = scan(wf, '.github/workflows/ci.yml');
    expect(r.matches.map((m) => [m.ruleId, m.line])).toEqual([
      ['github-actions-literal', 3],
      ['github-actions-literal', 9],
      ['github-actions-literal', 14],
      ['github-actions-literal', 16],
    ]);
    expect(r.suppressed['ci-expression']).toBe(1);
  });

  it('flags a short literal password under a secret-like key as weak', () => {
    const r = scan(text('env:', '  DB_PASSWORD: postgres1'), '.github/workflows/ci.yml');
    expect(r.matches).toHaveLength(1);
    expect(r.matches[0]!.weak).toBe(true);
  });

  it('falls back to text scanning on malformed YAML instead of crashing', () => {
    const tok = f.generic(32);
    const broken = text('env:', `  API_TOKEN: "${tok}"`, '  bad: [unclosed', 'jobs: {');
    expect(() => structuredCandidates('github-actions', broken)).toThrow(CiParseError);
    const r = scan(broken, '.github/workflows/ci.yml');
    expect(r.matches.map((m) => [m.ruleId, m.detector, m.line])).toEqual([
      ['github-actions-literal', 'ci', 2],
    ]);
  });
});

describe('GitLab CI', () => {
  it('flags global and job variables, including the value: form; ignores $VAR', () => {
    const [a, b, c] = [f.generic(32), f.generic(32), f.generic(32)];
    const yml = text(
      'variables:',
      `  REGISTRY_PASSWORD: "${a}"`,
      '  OTHER: $CI_JOB_TOKEN',
      'deploy:',
      '  script: [echo]',
      '  variables:',
      `    SONAR_TOKEN: ${b}`,
      '    API_SECRET:',
      `      value: "${c}"`,
      '      description: secret',
    );
    const r = scan(yml, '.gitlab-ci.yml');
    expect(r.matches.map((m) => m.line)).toEqual([2, 7, 9]);
  });

  it('collects local includes', () => {
    const yml = text(
      'include:',
      '  - local: /ci/build.yml',
      '  - "/ci/test.yml"',
      '  - remote: https://example.test/x.yml',
      '  - project: a/b',
    );
    expect(gitlabLocalIncludes(yml)).toEqual(['ci/build.yml', 'ci/test.yml']);
    expect(fileKindOf('ci/build.yml', { gitlabIncludes: new Set(['ci/build.yml']) })).toBe(
      'gitlab-ci',
    );
  });
});

describe('Dockerfile', () => {
  it('joins continuation lines with an offset map', () => {
    const ll = logicalLines('ENV A=1 \\\n    B=2\nRUN x');
    expect(ll.map((l) => l.text)).toEqual(['ENV A=1      B=2', 'RUN x']);
  });

  it('handles ENV K=V, legacy ENV K V, ARG K=V and continuations', () => {
    const [a, b, c] = [f.generic(32), f.generic(32), f.generic(24)];
    const df = text(
      'FROM node:20',
      `ARG NPM_TOKEN=${a}`,
      'ARG BUILD_ONLY',
      'ENV APP_ENV=production \\',
      `    API_SECRET="${b}"`,
      `ENV SERVICE_PASSWORD ${c}`,
      'ENV API_KEY=${API_KEY}',
    );
    const r = scan(df, 'Dockerfile');
    expect(r.matches.map((m) => [m.line, m.column])).toEqual([
      [2, 15],
      [5, 17],
      [6, 22],
    ]);
    expect(r.suppressed['env-reference']).toBe(1);
  });
});

describe('credential files', () => {
  it('.env: secret-like keys and high-entropy values; not hostnames', () => {
    const [a, b] = [f.generic(24), f.generic(40)];
    const r = scan(
      text('DB_HOST=localhost', `DB_PASSWORD=${a}`, `export SESSION="${b}"`, 'EMPTY='),
      '.env',
    );
    expect(r.matches.map((m) => [m.ruleId, m.line])).toEqual([
      ['dotenv-secret', 2],
      ['dotenv-secret', 3],
    ]);
  });

  it('.npmrc auth token', () => {
    const r = scan(
      text(
        'registry=https://registry.npmjs.org/',
        `//registry.npmjs.org/:_authToken=${f.npmToken()}`,
      ),
      '.npmrc',
    );
    expect(r.matches.map((m) => m.ruleId)).toEqual(['npmrc-auth-token']);
  });

  it('credentials.json secret fields only', () => {
    const r = scan(
      text('{', '  "type": "service_account",', `  "client_secret": "${f.generic(40)}"`, '}'),
      'credentials.json',
    );
    expect(r.matches.map((m) => [m.ruleId, m.line])).toEqual([['credentials-json-secret', 3]]);
  });

  it('.pgpass, .netrc, .git-credentials', () => {
    expect(
      scan(`db:5432:app:admin:${f.generic(24)}\n`, '.pgpass').matches.map((m) => m.ruleId),
    ).toEqual(['pgpass-password']);
    expect(
      scan(`machine example.test login me password ${f.generic(24)}\n`, '.netrc').matches.map(
        (m) => m.ruleId,
      ),
    ).toEqual(['netrc-password']);
    expect(
      scan(`https://me:${f.generic(24)}@example.test\n`, '.git-credentials').matches.map(
        (m) => m.ruleId,
      ),
    ).toEqual(['git-credentials-password']);
  });

  it('id_rsa: private-key signature when PEM, credential-file otherwise', () => {
    const pem = f.privateKey('OPENSSH').pem;
    expect(scan(pem + '\n', '.ssh/id_rsa').matches.map((m) => m.ruleId)).toEqual(['private-key']);
    expect(scan(`${f.generic(60)}\n`, '.ssh/id_rsa').matches.map((m) => m.ruleId)).toEqual([
      'ssh-private-key-file',
    ]);
  });
});
