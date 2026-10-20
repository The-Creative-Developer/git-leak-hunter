/**
 * Builds the fixture Git repositories on the fly, using real `git` commands in a temp directory,
 * and writes a ground-truth manifest (`ground-truth.json`) listing every planted secret and bait.
 *
 * All secrets are fabricated at runtime by SecretFactory (seeded, deterministic). Raw values are
 * returned in memory only (`BuiltFixture.rawSecrets`) so leak tests can search outputs for them;
 * they are never written to the manifest.
 */
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Presence } from '../../src/types.js';
import { AWS_DOC_EXAMPLE, Rng, SecretFactory } from './secretFactory.js';

export const FIXTURE_NAMES = [
  'history-only',
  'head-secrets',
  'blob-reuse',
  'merge-conflict',
  'ci-configs',
  'false-positives',
  'hostile',
  'clean',
] as const;
export type FixtureName = (typeof FIXTURE_NAMES)[number];

export const SECRET_CATEGORIES = [
  'aws-access-key-id',
  'aws-secret-access-key',
  'github-token',
  'stripe-live-key',
  'stripe-test-key',
  'slack-token',
  'slack-webhook',
  'private-key',
  'generic-high-entropy',
  'ci-literal',
  'dockerfile-literal',
  'credential-file',
] as const;
export type SecretCategory = (typeof SECRET_CATEGORIES)[number];

export const BAIT_CATEGORIES = [
  'uuid',
  'lockfile-hash',
  'placeholder',
  'known-example',
  'ci-expression',
  'env-reference',
  'env-example',
  'repeated-chars',
  'git-sha',
  'data-uri',
] as const;
export type BaitCategory = (typeof BAIT_CATEGORIES)[number];

interface PlantedBase {
  /** Stable, human-readable id, unique within the repo. */
  id: string;
  filePath: string;
  /** 1-based line in the file as committed. */
  line: number;
  /** Commit that introduced this item at this path. */
  commit: string;
  note?: string;
}

export interface PlantedSecret extends PlantedBase {
  kind: 'secret';
  category: SecretCategory;
  presence: Presence;
}

export interface PlantedBait extends PlantedBase {
  kind: 'bait';
  category: BaitCategory;
}

export type PlantedItem = PlantedSecret | PlantedBait;

export interface ExpectedSkip {
  filePath: string;
  reason: 'binary' | 'oversize';
}

export interface GroundTruthRepo {
  name: FixtureName;
  /** Repo directory relative to the manifest. */
  path: string;
  description: string;
  head: string;
  branches: string[];
  items: PlantedItem[];
  expectedSkips: ExpectedSkip[];
}

export interface GroundTruth {
  format: 'git-leak-hunter/ground-truth@1';
  seed: number;
  repos: GroundTruthRepo[];
}

export interface BuiltFixture extends GroundTruthRepo {
  dir: string;
  /** Every raw secret value planted in this repo (in memory only — never serialise). */
  rawSecrets: readonly string[];
  /** Raw value of each planted secret, keyed by item id (in memory only — never serialise). */
  secretValues: ReadonlyMap<string, string>;
}

export interface BuiltFixtures {
  root: string;
  manifestPath: string;
  fixtures: Record<FixtureName, BuiltFixture>;
}

/** Fixtures larger than this are expected to be skipped by the scanner's default size cap. */
export const HUGE_FILE_BYTES = 3 * 1024 * 1024;

const BASE_EPOCH = Date.UTC(2025, 0, 6, 9, 0, 0) / 1000;
const DEFAULT_AUTHOR = { name: 'Fixture Bot', email: 'fixture-bot@example.test' };

/** Git environment isolated from the user's global/system config, hooks and templates. */
function isolatedGitEnv(): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    LC_ALL: 'C',
  };
}

interface GitResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runGit(
  cwd: string,
  args: readonly string[],
  opts: { env?: NodeJS.ProcessEnv; input?: Buffer | string; allowFail?: boolean } = {},
): Promise<GitResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'git',
      ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', ...args],
      { cwd, env: { ...isolatedGitEnv(), ...opts.env }, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on('data', (d: Buffer) => out.push(d));
    child.stderr.on('data', (d: Buffer) => err.push(d));
    child.on('error', reject);
    child.on('close', (code) => {
      const result = {
        code: code ?? -1,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      };
      if (result.code !== 0 && !opts.allowFail) {
        // Only the subcommand name is reported; arguments may contain fixture content.
        reject(new Error(`git ${args[0] ?? ''} failed (${result.code}) in ${cwd}`));
      } else {
        resolve(result);
      }
    });
    child.stdin.end(opts.input ?? '');
  });
}

/** 1-based number of the first line containing `needle` (in-memory only; never printed). */
export function lineOf(content: string, needle: string): number {
  const idx = content.indexOf(needle);
  if (idx < 0) throw new Error('fixture bug: planted value not found in its file');
  return content.slice(0, idx).split('\n').length;
}

const text = (...lines: string[]): string => lines.join('\n') + '\n';

type PendingItem = Omit<PlantedSecret, 'commit' | 'line'> | Omit<PlantedBait, 'commit' | 'line'>;

class FixtureRepo {
  private tick = 0;
  private pending: PlantedItem[] = [];
  readonly items: PlantedItem[] = [];
  readonly raw = new Set<string>();
  readonly values = new Map<string, string>();
  readonly expectedSkips: ExpectedSkip[] = [];

  private constructor(readonly dir: string) {}

  static async create(dir: string): Promise<FixtureRepo> {
    await mkdir(dir, { recursive: true });
    await runGit(dir, ['init', '-q', '--template=', '-b', 'main']);
    return new FixtureRepo(dir);
  }

  git(args: readonly string[], opts?: { input?: Buffer | string; allowFail?: boolean }) {
    return runGit(this.dir, args, opts);
  }

  async write(filePath: string, content: string | Buffer): Promise<void> {
    const abs = path.join(this.dir, filePath);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, content);
    await this.git(['add', '--', filePath]);
  }

  async remove(filePath: string): Promise<void> {
    await this.git(['rm', '-q', '--', filePath]);
  }

  /** Stage a file purely through plumbing — used for names the filesystem may not accept. */
  async addRaw(filePath: string, content: string | Buffer): Promise<void> {
    const { stdout } = await this.git(['hash-object', '-w', '--stdin'], { input: content });
    const record = `100644 ${stdout.trim()}\t${filePath}\0`;
    await this.git(['update-index', '--add', '-z', '--index-info'], { input: record });
  }

  /** Record a planted item whose line is located by `needle` in `content`. */
  plant(item: PendingItem, content: string, needle: string): void {
    this.pending.push({ ...item, line: lineOf(content, needle) } as PlantedItem);
    if (item.kind === 'secret') this.values.set(item.id, needle);
  }

  /** Register raw secret values for leak tests (in memory only). */
  secret(...values: string[]): void {
    for (const v of values) this.raw.add(v);
  }

  private commitEnv(author = DEFAULT_AUTHOR): NodeJS.ProcessEnv {
    const date = `@${BASE_EPOCH + this.tick++ * 3600} +0000`;
    return {
      GIT_AUTHOR_NAME: author.name,
      GIT_AUTHOR_EMAIL: author.email,
      GIT_AUTHOR_DATE: date,
      GIT_COMMITTER_NAME: DEFAULT_AUTHOR.name,
      GIT_COMMITTER_EMAIL: DEFAULT_AUTHOR.email,
      GIT_COMMITTER_DATE: date,
    };
  }

  async commit(message: string, author?: { name: string; email: string }): Promise<string> {
    await runGit(this.dir, ['commit', '-q', '--no-verify', '--allow-empty', '-m', message], {
      env: this.commitEnv(author),
    });
    return this.flush();
  }

  /** Merge `branch` into the current branch. Returns false on conflict (left for resolution). */
  async merge(branch: string): Promise<boolean> {
    const res = await runGit(this.dir, ['merge', '-q', '--no-ff', '--no-edit', branch], {
      env: this.commitEnv(),
      allowFail: true,
    });
    if (res.code === 0) await this.flush();
    return res.code === 0;
  }

  async checkout(branch: string, create = false): Promise<void> {
    await this.git(create ? ['checkout', '-q', '-b', branch] : ['checkout', '-q', branch]);
  }

  private async flush(): Promise<string> {
    const head = (await this.git(['rev-parse', 'HEAD'])).stdout.trim();
    for (const p of this.pending) this.items.push({ ...p, commit: head });
    this.pending = [];
    return head;
  }

  async head(): Promise<string> {
    return (await this.git(['rev-parse', 'HEAD'])).stdout.trim();
  }

  async branches(): Promise<string[]> {
    const { stdout } = await this.git(['for-each-ref', '--format=%(refname:short)', 'refs/heads']);
    return stdout.split('\n').filter(Boolean).sort();
  }
}

interface FixtureSpec {
  description: string;
  build(repo: FixtureRepo, f: SecretFactory): Promise<void>;
}

const FIXTURES: Record<FixtureName, FixtureSpec> = {
  // (a) Secrets added, then removed in a later commit: recoverable from history only.
  'history-only': {
    description: 'AWS key pair and GitHub token committed, then removed in a later commit.',
    async build(repo, f) {
      await repo.write('README.md', text('# billing-service', '', 'Internal billing API.'));
      await repo.write('src/index.ts', text("export const main = (): string => 'hello';"));
      await repo.commit('Initial commit');

      const keyId = f.awsAccessKeyId();
      const secretKey = f.awsSecretAccessKey();
      const aws = text(
        '// AWS client configuration',
        'export const awsConfig = {',
        "  region: 'us-east-1',",
        `  accessKeyId: '${keyId}',`,
        `  secretAccessKey: '${secretKey}',`,
        '};',
      );
      await repo.write('config/aws.ts', aws);
      repo.plant(
        {
          id: 'aws-key-id',
          kind: 'secret',
          category: 'aws-access-key-id',
          filePath: 'config/aws.ts',
          presence: 'history-only',
        },
        aws,
        keyId,
      );
      repo.plant(
        {
          id: 'aws-secret',
          kind: 'secret',
          category: 'aws-secret-access-key',
          filePath: 'config/aws.ts',
          presence: 'history-only',
        },
        aws,
        secretKey,
      );
      const gh = f.githubToken();
      const ghFile = text(`const GITHUB_TOKEN = '${gh}';`, 'export default GITHUB_TOKEN;');
      await repo.write('src/github.ts', ghFile);
      repo.plant(
        {
          id: 'github-token',
          kind: 'secret',
          category: 'github-token',
          filePath: 'src/github.ts',
          presence: 'history-only',
        },
        ghFile,
        gh,
      );
      repo.secret(keyId, secretKey, gh);
      await repo.commit('Add AWS and GitHub configuration');

      await repo.write(
        'config/aws.ts',
        text(
          '// AWS client configuration',
          'export const awsConfig = {',
          "  region: 'us-east-1',",
          '  accessKeyId: process.env.AWS_ACCESS_KEY_ID,',
          '  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,',
          '};',
        ),
      );
      await repo.remove('src/github.ts');
      await repo.commit('Move credentials to environment variables');

      await repo.write(
        'README.md',
        text('# billing-service', '', 'Credentials come from the environment.'),
      );
      await repo.commit('Update README');
    },
  },

  // (b) Secrets still present at HEAD, across signature and entropy layers.
  'head-secrets': {
    description:
      'Stripe, Slack, private key and generic high-entropy secrets still present at HEAD.',
    async build(repo, f) {
      await repo.write('README.md', text('# storefront'));
      await repo.commit('Initial commit');

      const live = f.stripeLiveKey();
      const billing = text(
        "import Stripe from 'stripe';",
        '',
        `export const stripe = new Stripe('${live}');`,
      );
      await repo.write('src/billing.ts', billing);
      repo.plant(
        {
          id: 'stripe-live',
          kind: 'secret',
          category: 'stripe-live-key',
          filePath: 'src/billing.ts',
          presence: 'in-HEAD',
        },
        billing,
        live,
      );
      const testKey = f.stripeTestKey();
      const billingTest = text(
        "import { it } from 'vitest';",
        '',
        `const key = '${testKey}';`,
        "it('charges', () => key);",
      );
      await repo.write('test/billing.test.ts', billingTest);
      repo.plant(
        {
          id: 'stripe-test',
          kind: 'secret',
          category: 'stripe-test-key',
          filePath: 'test/billing.test.ts',
          presence: 'in-HEAD',
        },
        billingTest,
        testKey,
      );
      repo.secret(live, testKey);
      await repo.commit('Add billing');

      const hook = f.slackWebhook();
      const bot = f.slackBotToken();
      const notify = text(
        `const WEBHOOK_URL = '${hook}';`,
        `const SLACK_BOT_TOKEN = '${bot}';`,
        'export { WEBHOOK_URL, SLACK_BOT_TOKEN };',
      );
      await repo.write('src/notify.ts', notify);
      repo.plant(
        {
          id: 'slack-webhook',
          kind: 'secret',
          category: 'slack-webhook',
          filePath: 'src/notify.ts',
          presence: 'in-HEAD',
        },
        notify,
        hook,
      );
      repo.plant(
        {
          id: 'slack-bot',
          kind: 'secret',
          category: 'slack-token',
          filePath: 'src/notify.ts',
          presence: 'in-HEAD',
        },
        notify,
        bot,
      );
      repo.secret(hook, bot);
      await repo.commit('Add Slack notifications');

      const key = f.privateKey('RSA');
      const pem = key.pem + '\n';
      await repo.write('deploy/deploy_key.pem', pem);
      repo.plant(
        {
          id: 'deploy-key',
          kind: 'secret',
          category: 'private-key',
          filePath: 'deploy/deploy_key.pem',
          presence: 'in-HEAD',
        },
        pem,
        key.pem,
      );
      repo.secret(key.pem, ...key.bodyLines);
      await repo.commit('Add deploy key');

      const generic = f.generic(40);
      const client = text(
        'export const client = {',
        "  baseUrl: 'https://api.internal.example.test',",
        `  apiSecret: "${generic}",`,
        '};',
      );
      await repo.write('src/client.ts', client);
      repo.plant(
        {
          id: 'generic-app',
          kind: 'secret',
          category: 'generic-high-entropy',
          filePath: 'src/client.ts',
          presence: 'in-HEAD',
        },
        client,
        generic,
      );
      const docGeneric = f.generic(40);
      const usage = text('# Usage', '', '```ini', `api_token = "${docGeneric}"`, '```');
      await repo.write('docs/examples/usage.md', usage);
      repo.plant(
        {
          id: 'generic-docs',
          kind: 'secret',
          category: 'generic-high-entropy',
          filePath: 'docs/examples/usage.md',
          presence: 'in-HEAD',
        },
        usage,
        docGeneric,
      );
      repo.secret(generic, docGeneric);
      await repo.commit('Add API client and usage docs');
    },
  },

  // (c) The same blob appears across many commits and paths (memoization test).
  'blob-reuse': {
    description:
      'One secret-bearing blob copied to several paths, deleted, re-added and branched; plus toggling blobs.',
    async build(repo, f) {
      const gh = f.githubToken();
      repo.secret(gh);
      const shared = text('module.exports = {', "  service: 'reports',", `  token: '${gh}',`, '};');
      const plantAt = (p: string, presence: Presence, note?: string): void =>
        repo.plant(
          {
            id: `token-${p.split('/')[1] ?? p}`,
            kind: 'secret',
            category: 'github-token',
            filePath: p,
            presence,
            ...(note ? { note } : {}),
          },
          shared,
          gh,
        );

      await repo.write('services/a/settings.js', shared);
      plantAt('services/a/settings.js', 'in-HEAD', 'deleted then re-added with the identical blob');
      await repo.commit('Add service a');

      await repo.write('services/b/settings.js', shared);
      await repo.write('services/c/settings.js', shared);
      plantAt('services/b/settings.js', 'in-HEAD');
      plantAt('services/c/settings.js', 'history-only', 'removed from main later');
      await repo.commit('Copy settings to services b and c');

      for (let i = 0; i < 10; i++) {
        await repo.write('counter.txt', text(i % 2 === 0 ? 'state: on' : 'state: off'));
        await repo.commit(`Toggle counter ${i}`);
      }

      await repo.remove('services/a/settings.js');
      await repo.commit('Remove service a');
      await repo.write('services/a/settings.js', shared);
      await repo.commit('Restore service a');

      await repo.checkout('feature', true);
      await repo.write('services/d/settings.js', shared);
      plantAt(
        'services/d/settings.js',
        'history-only',
        'only reachable from branch "feature", not from HEAD',
      );
      await repo.commit('Add service d');
      await repo.checkout('main');

      await repo.remove('services/c/settings.js');
      await repo.commit('Remove service c');
    },
  },

  // (d) A secret that exists only in a merge commit's conflict resolution.
  'merge-conflict': {
    description:
      'GitHub token introduced only while resolving a merge conflict, plus an evil-merge file.',
    async build(repo, f) {
      const base = (tokenExpr: string): string =>
        text(
          'export const config = {',
          "  endpoint: 'https://api.example.test',",
          `  token: ${tokenExpr},`,
          '};',
        );
      await repo.write('src/config.js', base('process.env.API_TOKEN'));
      await repo.commit('Add config');

      await repo.checkout('topic', true);
      await repo.write('src/config.js', base("readTokenFromVault('topic')"));
      await repo.commit('Read token from vault');

      await repo.checkout('main');
      await repo.write('src/config.js', base("readTokenFromFile('main')"));
      await repo.commit('Read token from file');

      const merged = await repo.merge('topic');
      if (merged) throw new Error('fixture bug: expected a merge conflict');

      const gh = f.githubToken();
      const resolved = base(`'${gh}'`);
      await repo.write('src/config.js', resolved);
      repo.plant(
        {
          id: 'resolution-token',
          kind: 'secret',
          category: 'github-token',
          filePath: 'src/config.js',
          presence: 'in-HEAD',
          note: 'present in neither merge parent',
        },
        resolved,
        gh,
      );
      const bot = f.slackBotToken();
      const notes = text('Merge notes', `slack: ${bot}`);
      await repo.write('ops/merge-notes.txt', notes);
      repo.plant(
        {
          id: 'evil-merge-slack',
          kind: 'secret',
          category: 'slack-token',
          filePath: 'ops/merge-notes.txt',
          presence: 'in-HEAD',
          note: 'file added only in the merge commit',
        },
        notes,
        bot,
      );
      repo.secret(gh, bot);
      await repo.commit("Merge branch 'topic'");
    },
  },

  // (e) Literal secrets in CI/CD configuration and committed credential files.
  'ci-configs': {
    description:
      'Literal secrets in GitHub Actions, GitLab CI, Dockerfile, and committed .env/id_rsa/.npmrc/credentials.json.',
    async build(repo, f) {
      const wfKey = f.generic(32);
      const jobPass = f.generic(24);
      const withToken = f.generic(32);
      const workflow = (workflowEnv: string): string =>
        text(
          'name: deploy',
          'on: [push]',
          'env:',
          `  DEPLOY_API_KEY: ${workflowEnv}`,
          'jobs:',
          '  deploy:',
          '    runs-on: ubuntu-latest',
          '    env:',
          `      DATABASE_PASSWORD: "${jobPass}"`,
          '    steps:',
          '      - uses: actions/checkout@v4',
          '      - name: Publish',
          '        uses: example/publish-action@v1',
          '        with:',
          `          api_token: ${withToken}`,
          '          region: us-east-1',
        );
      const wf1 = workflow(wfKey);
      await repo.write('.github/workflows/deploy.yml', wf1);
      repo.plant(
        {
          id: 'gha-workflow-env',
          kind: 'secret',
          category: 'ci-literal',
          filePath: '.github/workflows/deploy.yml',
          presence: 'history-only',
          note: 'replaced by ${{ secrets.X }} later',
        },
        wf1,
        wfKey,
      );
      repo.plant(
        {
          id: 'gha-job-env',
          kind: 'secret',
          category: 'ci-literal',
          filePath: '.github/workflows/deploy.yml',
          presence: 'in-HEAD',
        },
        wf1,
        jobPass,
      );
      repo.plant(
        {
          id: 'gha-with-input',
          kind: 'secret',
          category: 'ci-literal',
          filePath: '.github/workflows/deploy.yml',
          presence: 'in-HEAD',
        },
        wf1,
        withToken,
      );
      repo.secret(wfKey, jobPass, withToken);
      await repo.commit('Add deploy workflow');

      const glGlobal = f.generic(28);
      const glJob = f.generic(32);
      const gitlab = text(
        'variables:',
        `  REGISTRY_PASSWORD: "${glGlobal}"`,
        '  DOCKER_DRIVER: overlay2',
        'build:',
        '  stage: build',
        '  script:',
        '    - echo build',
        '  variables:',
        `    SONAR_TOKEN: ${glJob}`,
      );
      await repo.write('.gitlab-ci.yml', gitlab);
      repo.plant(
        {
          id: 'gitlab-global',
          kind: 'secret',
          category: 'ci-literal',
          filePath: '.gitlab-ci.yml',
          presence: 'in-HEAD',
        },
        gitlab,
        glGlobal,
      );
      repo.plant(
        {
          id: 'gitlab-job',
          kind: 'secret',
          category: 'ci-literal',
          filePath: '.gitlab-ci.yml',
          presence: 'in-HEAD',
        },
        gitlab,
        glJob,
      );

      const argTok = f.generic(32);
      const envSecret = f.generic(32);
      const envPass = f.generic(24);
      const dockerfile = text(
        'FROM node:20-alpine',
        `ARG NPM_TOKEN=${argTok}`,
        'ENV APP_ENV=production \\',
        `    API_SECRET=${envSecret}`,
        `ENV SERVICE_PASSWORD ${envPass}`,
        'CMD ["node", "server.js"]',
      );
      await repo.write('Dockerfile', dockerfile);
      repo.plant(
        {
          id: 'docker-arg',
          kind: 'secret',
          category: 'dockerfile-literal',
          filePath: 'Dockerfile',
          presence: 'in-HEAD',
        },
        dockerfile,
        argTok,
      );
      repo.plant(
        {
          id: 'docker-env-continuation',
          kind: 'secret',
          category: 'dockerfile-literal',
          filePath: 'Dockerfile',
          presence: 'in-HEAD',
        },
        dockerfile,
        envSecret,
      );
      repo.plant(
        {
          id: 'docker-env-space',
          kind: 'secret',
          category: 'dockerfile-literal',
          filePath: 'Dockerfile',
          presence: 'in-HEAD',
        },
        dockerfile,
        envPass,
      );
      repo.secret(glGlobal, glJob, argTok, envSecret, envPass);
      await repo.commit('Add GitLab CI and Dockerfile');

      const dbPass = f.generic(24);
      const dotenv = text('DB_HOST=localhost', `DB_PASSWORD=${dbPass}`);
      await repo.write('.env', dotenv);
      repo.plant(
        {
          id: 'dotenv',
          kind: 'secret',
          category: 'credential-file',
          filePath: '.env',
          presence: 'in-HEAD',
        },
        dotenv,
        dbPass,
      );
      const key = f.privateKey('OPENSSH');
      const idRsa = key.pem + '\n';
      await repo.write('.ssh/id_rsa', idRsa);
      repo.plant(
        {
          id: 'id-rsa',
          kind: 'secret',
          category: 'private-key',
          filePath: '.ssh/id_rsa',
          presence: 'in-HEAD',
        },
        idRsa,
        key.pem,
      );
      const npm = f.npmToken();
      const npmrc = text(`//registry.npmjs.org/:_authToken=${npm}`);
      await repo.write('.npmrc', npmrc);
      repo.plant(
        {
          id: 'npmrc',
          kind: 'secret',
          category: 'credential-file',
          filePath: '.npmrc',
          presence: 'in-HEAD',
        },
        npmrc,
        npm,
      );
      const clientSecret = f.generic(40);
      const creds = text(
        '{',
        '  "type": "service_account",',
        `  "client_secret": "${clientSecret}"`,
        '}',
      );
      await repo.write('config/credentials.json', creds);
      repo.plant(
        {
          id: 'credentials-json',
          kind: 'secret',
          category: 'credential-file',
          filePath: 'config/credentials.json',
          presence: 'in-HEAD',
        },
        creds,
        clientSecret,
      );
      repo.secret(dbPass, key.pem, ...key.bodyLines, npm, clientSecret);
      await repo.commit('Add local environment files');

      await repo.write('.github/workflows/deploy.yml', workflow('${{ secrets.DEPLOY_API_KEY }}'));
      await repo.commit('Use repository secret for deploy key');
    },
  },

  // (f) False-positive bait only: a correct scanner reports nothing here.
  'false-positives': {
    description:
      'UUIDs, lockfile hashes, placeholders, CI expressions, .env.example, repeated chars, git SHAs, data URIs.',
    async build(repo, f) {
      const bait = (
        id: string,
        category: BaitCategory,
        filePath: string,
        content: string,
        needle: string,
      ): void => repo.plant({ id, kind: 'bait', category, filePath }, content, needle);

      const u1 = f.uuid();
      const u2 = f.uuid();
      const ids = text(`export const TENANT_ID = '${u1}';`, `export const REQUEST_ID = "${u2}";`);
      await repo.write('src/ids.ts', ids);
      bait('uuid-1', 'uuid', 'src/ids.ts', ids, u1);
      bait('uuid-2', 'uuid', 'src/ids.ts', ids, u2);

      const i1 = f.integritySha512();
      const lock = text(
        '{',
        '  "name": "storefront",',
        '  "lockfileVersion": 3,',
        '  "packages": {',
        '    "node_modules/left-pad": {',
        '      "version": "1.3.0",',
        `      "integrity": "${i1}"`,
        '    }',
        '  }',
        '}',
      );
      await repo.write('package-lock.json', lock);
      bait('npm-integrity', 'lockfile-hash', 'package-lock.json', lock, i1);
      const i2 = f.integritySha512();
      const yarn = text('left-pad@^1.3.0:', '  version "1.3.0"', `  integrity ${i2}`);
      await repo.write('yarn.lock', yarn);
      bait('yarn-integrity', 'lockfile-hash', 'yarn.lock', yarn, i2);
      const h = f.goSumHash();
      const gosum = text(`golang.org/x/text v0.14.0 ${h}`);
      await repo.write('go.sum', gosum);
      bait('go-sum', 'lockfile-hash', 'go.sum', gosum, h);
      await repo.commit('Add ids and lockfiles');

      const placeholders = text(
        'export const settings = {',
        '  apiKey: "your_api_key_here",',
        '  password: "changeme",',
        '  token: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",',
        '  auth: "<TOKEN>",',
        '  apiToken: "${API_TOKEN}",',
        '  secret: process.env.APP_SECRET,',
        '};',
      );
      await repo.write('src/settings.ts', placeholders);
      bait('ph-your-key', 'placeholder', 'src/settings.ts', placeholders, 'your_api_key_here');
      bait('ph-changeme', 'placeholder', 'src/settings.ts', placeholders, 'changeme');
      bait('ph-xxxx', 'placeholder', 'src/settings.ts', placeholders, 'xxxxxxxx');
      bait('ph-angle', 'placeholder', 'src/settings.ts', placeholders, '<TOKEN>');
      bait('ph-shell-var', 'env-reference', 'src/settings.ts', placeholders, '${API_TOKEN}');
      bait(
        'ph-process-env',
        'env-reference',
        'src/settings.ts',
        placeholders,
        'process.env.APP_SECRET',
      );

      const awsDoc = text(
        '# AWS setup',
        '',
        '```ini',
        `aws_access_key_id = ${AWS_DOC_EXAMPLE.keyId}`,
        `aws_secret_access_key = ${AWS_DOC_EXAMPLE.secret}`,
        '```',
      );
      await repo.write('docs/aws.md', awsDoc);
      bait('aws-doc-key-id', 'known-example', 'docs/aws.md', awsDoc, AWS_DOC_EXAMPLE.keyId);
      bait('aws-doc-secret', 'known-example', 'docs/aws.md', awsDoc, AWS_DOC_EXAMPLE.secret);
      await repo.commit('Add settings and AWS docs');

      const wf = text(
        'name: ci',
        'on: [push]',
        'env:',
        '  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}',
        'jobs:',
        '  test:',
        '    runs-on: ubuntu-latest',
        '    env:',
        '      API_KEY: ${{ env.DEPLOY_TOKEN }}',
        '    steps:',
        '      - uses: actions/checkout@v4',
        '      - uses: example/deploy@v1',
        '        with:',
        '          token: ${{ secrets.GITHUB_TOKEN }}',
      );
      await repo.write('.github/workflows/ci.yml', wf);
      bait(
        'gha-secrets-ref',
        'ci-expression',
        '.github/workflows/ci.yml',
        wf,
        '${{ secrets.DEPLOY_TOKEN }}',
      );
      bait(
        'gha-env-ref',
        'ci-expression',
        '.github/workflows/ci.yml',
        wf,
        '${{ env.DEPLOY_TOKEN }}',
      );
      bait(
        'gha-with-ref',
        'ci-expression',
        '.github/workflows/ci.yml',
        wf,
        '${{ secrets.GITHUB_TOKEN }}',
      );
      const gitlab = text(
        'variables:',
        '  REGISTRY_PASSWORD: $CI_REGISTRY_PASSWORD',
        '  SONAR_TOKEN: "${SONAR_TOKEN}"',
      );
      await repo.write('.gitlab-ci.yml', gitlab);
      bait('gitlab-var-ref', 'env-reference', '.gitlab-ci.yml', gitlab, '$CI_REGISTRY_PASSWORD');
      bait('gitlab-braced-ref', 'env-reference', '.gitlab-ci.yml', gitlab, '${SONAR_TOKEN}');
      const dockerfile = text('FROM node:20-alpine', 'ARG NPM_TOKEN', 'ENV API_KEY=${API_KEY}');
      await repo.write('Dockerfile', dockerfile);
      bait('docker-env-ref', 'env-reference', 'Dockerfile', dockerfile, '${API_KEY}');
      const example = text('API_KEY=changeme', 'DB_PASSWORD=your_password_here');
      await repo.write('.env.example', example);
      bait('env-example', 'env-example', '.env.example', example, 'API_KEY=changeme');
      await repo.commit('Add CI config using secret references');

      const repeated = text('export const filler = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";');
      await repo.write('src/filler.ts', repeated);
      bait('repeated', 'repeated-chars', 'src/filler.ts', repeated, 'aaaaaaaa');
      const sha = f.gitSha();
      const changelog = text('# Changelog', '', `- Fixed race condition (commit ${sha})`);
      await repo.write('CHANGELOG.md', changelog);
      bait('git-sha', 'git-sha', 'CHANGELOG.md', changelog, sha);
      const uri = f.dataUriPng();
      const logo = text(`export const LOGO = '${uri}';`);
      await repo.write('src/logo.ts', logo);
      bait('data-uri', 'data-uri', 'src/logo.ts', logo, 'data:image/png;base64,');
      await repo.commit('Add filler, changelog and logo');
    },
  },

  // (g) Attacker-controlled names and content: XSS payloads, odd paths, a huge file, a binary.
  hostile: {
    description:
      'Malicious HTML in file names, author and commit messages; odd paths; a huge file; a binary.',
    async build(repo, f) {
      const xssAuthor = {
        name: '<script>alert("author")</script>',
        email: 'x"><img src=x>@example.test',
      };

      const gh = f.githubToken();
      const xssName = '<img src=x onerror=alert(1)>.js';
      const xssFile = text(`const t = '${gh}';`);
      await repo.write(xssName, xssFile);
      repo.plant(
        {
          id: 'xss-filename',
          kind: 'secret',
          category: 'github-token',
          filePath: xssName,
          presence: 'in-HEAD',
        },
        xssFile,
        gh,
      );

      const live = f.stripeLiveKey();
      const dashName = '-rf --output=pwned.txt';
      const dashFile = text(`stripe_key=${live}`);
      await repo.write(dashName, dashFile);
      repo.plant(
        {
          id: 'dash-filename',
          kind: 'secret',
          category: 'stripe-live-key',
          filePath: dashName,
          presence: 'in-HEAD',
        },
        dashFile,
        live,
      );

      const bot = f.slackBotToken();
      const uniName = "docs/unicode-ñ-文件 with spaces & 'quotes'.txt";
      const uniFile = text('notes', `token=${bot}`);
      await repo.write(uniName, uniFile);
      repo.plant(
        {
          id: 'unicode-filename',
          kind: 'secret',
          category: 'slack-token',
          filePath: uniName,
          presence: 'in-HEAD',
        },
        uniFile,
        bot,
      );

      const gh2 = f.githubToken();
      const nlName = 'odd/new\nline\tand-tab.txt';
      const nlFile = text(`GITHUB_TOKEN=${gh2}`);
      await repo.addRaw(nlName, nlFile);
      repo.plant(
        {
          id: 'newline-filename',
          kind: 'secret',
          category: 'github-token',
          filePath: nlName,
          presence: 'in-HEAD',
          note: 'path contains a newline and a tab',
        },
        nlFile,
        gh2,
      );
      repo.secret(gh, live, bot, gh2);

      await repo.commit(
        `<script>alert('xss')</script> "><img src=x onerror=alert(1)> & 'quotes'`,
        xssAuthor,
      );

      const line = 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod\n';
      await repo.write('data/huge.txt', line.repeat(Math.ceil(HUGE_FILE_BYTES / line.length)));
      repo.expectedSkips.push({ filePath: 'data/huge.txt', reason: 'oversize' });
      const bin = f.rng.bytes(4096);
      bin[0] = 0x89;
      bin[1] = 0x00;
      await repo.write('assets/blob.bin', bin);
      repo.expectedSkips.push({ filePath: 'assets/blob.bin', reason: 'binary' });
      await repo.commit('Add data files\n\n</textarea><svg onload=alert(document.domain)>');
    },
  },

  // (h) Ordinary code with no secrets: must produce zero findings.
  clean: {
    description: 'Ordinary code and docs with no secrets; must yield zero findings.',
    async build(repo) {
      await repo.write('README.md', text('# calculator', '', 'A tiny calculator library.'));
      await repo.write(
        'package.json',
        text('{', '  "name": "calculator",', '  "version": "1.0.0",', '  "type": "module"', '}'),
      );
      await repo.write(
        'src/math.ts',
        text(
          'export const add = (a: number, b: number): number => a + b;',
          'export const mul = (a: number, b: number): number => a * b;',
        ),
      );
      await repo.commit('Initial commit');
      await repo.write(
        'test/math.test.ts',
        text(
          "import { add } from '../src/math';",
          "if (add(2, 2) !== 4) throw new Error('add is broken');",
        ),
      );
      await repo.write('docs/usage.md', text('# Usage', '', 'Call `add(1, 2)` to get `3`.'));
      await repo.commit('Add tests and docs');
    },
  },
};

function seedFor(seed: number, name: FixtureName): number {
  return (seed ^ ((FIXTURE_NAMES.indexOf(name) + 1) * 0x9e3779b1)) >>> 0;
}

export async function buildFixture(
  root: string,
  name: FixtureName,
  seed = 1337,
): Promise<BuiltFixture> {
  const dir = path.join(root, name);
  const repo = await FixtureRepo.create(dir);
  await FIXTURES[name].build(repo, new SecretFactory(new Rng(seedFor(seed, name))));
  return {
    name,
    path: name,
    description: FIXTURES[name].description,
    head: await repo.head(),
    branches: await repo.branches(),
    items: repo.items,
    expectedSkips: repo.expectedSkips,
    dir,
    rawSecrets: [...repo.raw],
    secretValues: repo.values,
  };
}

/** Build all fixture repos under `root` and write `root/ground-truth.json`. */
export async function buildAllFixtures(root: string, seed = 1337): Promise<BuiltFixtures> {
  await mkdir(root, { recursive: true });
  const built = await Promise.all(FIXTURE_NAMES.map((n) => buildFixture(root, n, seed)));
  const fixtures = Object.fromEntries(built.map((b) => [b.name, b])) as Record<
    FixtureName,
    BuiltFixture
  >;
  const manifest: GroundTruth = {
    format: 'git-leak-hunter/ground-truth@1',
    seed,
    repos: built.map(({ dir: _dir, rawSecrets: _raw, secretValues: _values, ...repo }) => repo),
  };
  const manifestPath = path.join(root, 'ground-truth.json');
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  return { root, manifestPath, fixtures };
}
