# Demo script

A reproducible walkthrough from a clean clone. It shows:

1. a **history-only** secret, deleted in a later commit but still found;
2. **CI/CD findings** in GitHub Actions, GitLab CI and a Dockerfile, plus committed credential
   files;
3. the **HTML report**, with redacted previews, severity labels and presence badges.

All secrets in the demo repositories are fabricated at build time and non-functional.

## 0. Setup (once)

```bash
git clone https://github.com/The-Creative-Developer/git-leak-hunter.git
```

```bash
cd git-leak-hunter && npm ci && npm run build
```

```bash
npm run fixtures -- demo-repos
```

The last command builds eight small repositories under `demo-repos/` plus
`demo-repos/ground-truth.json` (`demo-repos/` is git-ignored). It prints one line per repository
with its secret and bait counts.

## 1. "Deleting it is not enough": history-only detection

Show the repository's history: the AWS key pair and GitHub token were added in commit 2 and
removed in commit 3.

```bash
git -C demo-repos/history-only log --oneline --stat
```

```bash
node dist/cli.js scan demo-repos/history-only --out leak-report/history-only
```

Expected console output: 3 findings, all `history-only`, severity High. The AWS key ID and
secret key are reported as a pair.

```
✓ walking commit history  (4 commits, 6 file versions)
✓ regex signature scan  (6 unique blobs, 0 cache hits)
✓ entropy analysis  (1 candidate suppressed)
✓ CI/CD config scan  (0 CI/CD files)
! 3 findings detected  (0 critical, 3 high, 0 medium, 0 low; 3 history-only)
✓ report.html generated  (leak-report/history-only/report.html)
✓ report.json generated  (leak-report/history-only/report.json)
```

Point out:

- the working tree is clean (`git -C demo-repos/history-only grep -n AKIA` finds nothing);
- the commit hash in each finding is the commit that introduced the secret;
- the presence badge reads **HISTORY-ONLY · deleted but still recoverable**.

## 2. CI/CD configuration and credential files

```bash
node dist/cli.js scan demo-repos/ci-configs --out leak-report/ci-configs --fail-on high
```

Expected: 12 findings (1 Critical, 11 High, 1 history-only); exit code `1` because of
`--fail-on high`. Findings come from:

- `.github/workflows/deploy.yml`: workflow-level `env:` (**history-only**: replaced by
  `${{ secrets.DEPLOY_API_KEY }}` in the last commit), job-level `env:`, and a `with:` input;
- `.gitlab-ci.yml`: global and job `variables:`;
- `Dockerfile`: `ARG NPM_TOKEN=…`, a continued `ENV … \` line, and legacy `ENV KEY value`;
- `.env`, `.npmrc`, `config/credentials.json`, and `.ssh/id_rsa` (Critical: a private key still at
  HEAD).

Contrast with the bait repository: the same constructs written with `${{ secrets.X }}`, `$VAR`,
placeholders, UUIDs and lockfile hashes give **0 findings**, and the suppressions are counted:

```bash
node dist/cli.js scan demo-repos/false-positives --out leak-report/fp --verbose
```

## 3. The HTML report

Open `leak-report/ci-configs/report.html` in a browser by double-clicking it. No server is needed.

- **Header:** repository, scan date, counts per severity, scan stats (commits, unique blobs, cache
  hits, duration).
- **Finding cards**, as on slide 10: secret type, severity label, file path, commit hash, line
  number, redacted preview (`AKIA****************WXYZ` style), verification status.
- **Filters:** severity buttons, a present-at-HEAD / history-only selector, and severity or
  recency sorting.
- **Details:** entropy, first-seen commit, other commits containing the secret, fingerprint, and a
  redacted context line.

A copy generated from the same fixture is committed as `examples/report.html`.

## 4. The same, without the terminal (web UI)

```bash
node dist/cli.js ui
```

Your browser opens the local console; if it doesn't, open the printed link.

1. Click **Browse…**, open `demo-repos`, and pick `ci-configs` (marked `git`). Press **Scan
   repository**.
2. Show the live progress steps, then the result card: verdict stamp, severity counts, top
   findings.
3. Scroll to the embedded full report. **Open full report ↗** gives the same page in its own tab.
4. Scan `history-only` as well to show the session history list.
5. Stop the console with Ctrl+C; the session's reports are deleted.

## 5. Optional extras

- **Memoization:** scanning `demo-repos/blob-reuse` reports 3 unique blobs and 12 cache hits. One
  secret-bearing blob is copied to four paths, deleted, restored and branched.
  - Run it with `--no-cache` to compare.
  - Run `npm run bench:memo` for the full benchmark.
- **Merge-only secret:**
  - `node dist/cli.js scan demo-repos/merge-conflict` finds a token that exists only in a merge
    commit's conflict resolution.
  - `docs/BENCHMARK.md` shows Gitleaks' default `git` mode missing it.
- **XSS-safe report:** scan `demo-repos/hostile`. File names, the author name and the commit
  message contain HTML/JS payloads; the report shows them as inert text.
- **Live verification** is opt-in (`--verify --confirm-authorized`) and must not be run against
  credentials you do not own. The demo secrets are fabricated, so verifying them would only report
  `INACTIVE`, at the cost of real requests to AWS and GitHub. Skip it in the demo.

## Reset

```bash
rm -rf demo-repos leak-report
```
