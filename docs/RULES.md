# Detection rules

How Git Leak Hunter decides that something is a secret, how it suppresses false positives, and
how it assigns severity. Code references are relative to `src/`.

## Pipeline per blob (`detect/engine.ts`)

1. **Candidates** are gathered from three sources:
   - signatures for known formats (`detect/signatures.ts`)
   - structured parsing of CI/CD and credential files (`ci/`)
   - generic `key = value` assignments whose key name looks secret-like (`detect/generic.ts`)
2. **Overlap resolution.** Where spans overlap, one candidate wins: signature > credential-file > ci > entropy.
3. **Suppression** (below). Each dropped candidate increments a counted reason.
4. **Entropy** for every non-signature candidate, and for the AWS secret access key.
5. The surviving candidates become `BlobMatch`es, which carry no raw value. The result depends
   only on (content, file kind, config), so it is cached per blob.

## Layer 1 — signatures

| Rule id                   | Secret type               | Pattern (summary)                                                                                                               |
| ------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `aws-access-key-id`       | AWS Access Key            | `AKIA` / `ASIA` / `AIDA` + 16 `[A-Z0-9]` (20 chars), not inside a longer token                                                  |
| `aws-secret-access-key`   | AWS Secret Access Key     | 40 chars `[A-Za-z0-9/+]`, **only within 5 lines of a key ID**, not all-hex, must pass entropy                                   |
| `github-token`            | GitHub Token              | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` + 36 alphanumerics                                                                           |
| `github-fine-grained-pat` | GitHub Fine-grained Token | `github_pat_` + 22 + `_` + 59 alphanumerics                                                                                     |
| `stripe-live-key`         | Stripe Live Key           | `sk_live_` / `rk_live_` + ≥ 16 alphanumerics                                                                                    |
| `stripe-test-key`         | Stripe Test Key           | `sk_test_` / `rk_test_` + ≥ 16 alphanumerics                                                                                    |
| `slack-token`             | Slack Token               | `xox[abprs]-` + dash-separated alphanumeric segments                                                                            |
| `slack-webhook`           | Slack Webhook             | `https://hooks.slack.com/services/T…/B…/…`                                                                                      |
| `private-key`             | Private Key               | `-----BEGIN … PRIVATE KEY-----` (RSA/EC/DSA/OPENSSH/PGP/ENCRYPTED/PKCS#8) through the matching `-----END …-----` (or 200 lines) |

- **AWS pairing.** Each key ID is paired with the nearest unclaimed 40-char candidate within
  `AWS_PAIR_WINDOW = 5` lines. Both findings record `pairedFingerprint`. Live verification
  (Phase 3) needs the pair.
- **Private keys.** The whole block is one finding at the header line. Its preview is the header
  label without the PEM armor dashes plus the line count, e.g.
  `BEGIN RSA PRIVATE KEY [REDACTED, 14 lines]`. The dashes are dropped deliberately, so a report
  never looks like a key file to other scanners.
- **Generic secret** (`generic-secret`). A key name matching
  `api_key|apikey|secret|token|passw(or)d|passphrase|pwd|auth|credential|access_key|private_key`
  (case-insensitive; not `author`; not ending in `url`, `path`, `file`, `name`, `type`, `_id`, …),
  assigned with `=`, `:`, `:=` or `=>` on the same line, to a quoted or bare value of length
  ≥ `minLength`. These candidates are **never reported directly**: they must survive suppression and
  entropy.

## Layer 2 — Shannon entropy (`detect/entropy.ts`)

`H(X) = −Σ p(xᵢ)·log₂ p(xᵢ)` in bits per character. The charset is classified as **hex** (only
`0-9a-fA-F`), **base64-like** (`A-Za-z0-9+/=_-`) or **other**.

Spec starting thresholds (all configurable via `--entropy-hex`, `--entropy-base64`, `--min-length`
or the config file): **hex 3.0**, **base64 4.5**, **minimum length 20**.

### The length gotcha, and how it is handled

A string of length _n_ cannot exceed log₂(n) bits/char, and random strings measure well below that
cap. A fixed 4.5 threshold is therefore unreachable for 20–22 char strings and rejects most random
24–32 char secrets. We use a **length-normalised threshold**:

```
T_eff = min(T_charset, LENGTH_FACTOR · log₂(min(max(n, minLength), alphabetSize)))
LENGTH_FACTOR = 0.85; alphabetSize = 16 (hex), 64 (base64-like), 94 (other)
```

- Long strings are held to the configured threshold.
- Shorter strings must reach 85% of the maximum entropy a string of that length could have.
- Normalisation never goes below `minLength`. Normalising at the true length made short words
  pass (e.g. `postgres1`, 9 chars: H = 2.948 vs 0.85·log₂ 9 = 2.69), so they are held to the
  threshold for a `minLength`-char string instead.

### Calibration (measured)

Generated by `npx tsx bench/entropy-calibration.ts 10000` on 2026-10-20T16:26:49Z, Node v24.21.0,
Darwin 27.0.0 arm64 (Apple M1). Thresholds: hex 3, base64 4.5, minLength 20, LENGTH_FACTOR 0.85.
Each cell is 10,000 seeded random strings (seed 2026).

Share of random strings that **fail** the entropy check (would be missed):

| Charset     | Threshold                          | n=16    | n=20    | n=24   | n=28   | n=32   | n=40  | n=48  | n=64  |
| ----------- | ---------------------------------- | ------- | ------- | ------ | ------ | ------ | ----- | ----- | ----- |
| alnum (62)  | length-normalised (shipped)        | 25.41%  | 1.15%   | 1.67%  | 1.71%  | 2.02%  | 2.56% | 0.04% | 0.00% |
| alnum (62)  | fixed threshold (no normalisation) | 100.00% | 100.00% | 95.21% | 72.71% | 33.25% | 2.56% | 0.04% | 0.00% |
| base64 (64) | length-normalised (shipped)        | 23.80%  | 1.11%   | 1.43%  | 1.48%  | 1.58%  | 1.83% | 0.04% | 0.00% |
| base64 (64) | fixed threshold (no normalisation) | 100.00% | 100.00% | 94.65% | 70.57% | 29.92% | 1.83% | 0.04% | 0.00% |
| hex (16)    | length-normalised (shipped)        | 14.77%  | 2.94%   | 0.55%  | 0.11%  | 0.00%  | 0.00% | 0.00% | 0.00% |
| hex (16)    | fixed threshold (no normalisation) | 14.77%  | 2.94%   | 0.55%  | 0.11%  | 0.00%  | 0.00% | 0.00% | 0.00% |

Ordinary strings against the shipped thresholds:

| Ordinary string                     | Length | Entropy | Threshold | Reported |
| ----------------------------------- | ------ | ------- | --------- | -------- |
| `getUserAccountSettingsForTenant`   | 31     | 3.741   | 4.211     | no       |
| `this_is_not_a_secret_value`        | 26     | 3.551   | 3.995     | no       |
| `ProductionDatabaseHostname`        | 26     | 3.796   | 3.995     | no       |
| `AbstractSingletonProxyFactoryBean` | 33     | 4.044   | 4.288     | no       |
| `Password1234567890Password`        | 26     | 3.931   | 3.995     | no       |
| `com.example.service.Config`        | 26     | 3.902   | 3.995     | no       |
| `abcdefghijklmnopqrstuvwxyz`        | 26     | 4.700   | 3.995     | yes      |

**Known limitation.** At the spec's default 4.5 base64 threshold, roughly 1–3% of random
20–40 char secrets still fail the entropy check (the table above). This applies only to
entropy-layer candidates, never to signature matches. Lowering `--entropy-base64` or
`LENGTH_FACTOR` trades this for more false positives on identifiers. The defaults were kept as
the spec suggests, and the trade-off is documented here instead of hidden.

### Tuning changes made against the fixture repos

| Change                                                                    | Why                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Length-normalised threshold (`LENGTH_FACTOR = 0.85`)                      | The fixed 4.5 threshold missed nearly all 24-char and a third of 32-char random secrets (table above).                                                                                                                                         |
| Normalise at `max(n, minLength)`, not `n`                                 | A 9-char literal (`DB_PASSWORD: postgres1`) passed the normalised check and was rated High. It is now reported as a weak literal (Low).                                                                                                        |
| Values under keys that do not look secret-like must also be ≥ `minLength` | On `ci-configs`, `DB_HOST=localhost`, `"type": "service_account"`, `DOCKER_DRIVER: overlay2`, `APP_ENV=production` and `region: us-east-1` were reported (5 false positives). After the change the repo yields exactly its 12 planted secrets. |

## CI/CD and credential files (`ci/`, `detect/fileKind.ts`)

The file kind is chosen from the path and is part of the blob-cache key. All of these are scanned
**across history** through the same blob cache, not only at HEAD.

| Kind                                    | Paths                                                                                                      | What is flagged                                                                                                    | Rule id                                                         |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| GitHub Actions                          | `.github/workflows/*.yml\|yaml`                                                                            | literal scalars in `env:` (workflow, job, step, `container`, `services`), `with:` inputs, container `credentials:` | `github-actions-literal`                                        |
| GitLab CI                               | `.gitlab-ci.yml`, `*.gitlab-ci.yml`, `.gitlab/**.yml`, `include: local` files from HEAD's `.gitlab-ci.yml` | literals under global and job `variables:` (incl. `{ value: … }`)                                                  | `gitlab-ci-literal`                                             |
| Dockerfile                              | `Dockerfile`, `Containerfile`, `*.Dockerfile`, `Dockerfile.*`                                              | `ENV K=V …`, legacy `ENV K V`, `ARG K=V`, with `\` continuations                                                   | `dockerfile-literal`                                            |
| dotenv                                  | `.env`, `.env.*` (not `.example`, `.sample`, `.template`, `.dist`, `.defaults`, `.schema`)                 | `KEY=value` / `export KEY=value`                                                                                   | `dotenv-secret`                                                 |
| npm                                     | `.npmrc`                                                                                                   | `_authToken`, `_auth`, `_password`                                                                                 | `npmrc-auth-token`                                              |
| credentials JSON                        | `credentials*.json`, `client_secret*.json`, `service-account*.json`                                        | string fields with secret-like keys                                                                                | `credentials-json-secret`                                       |
| docker config                           | `.dockercfg`, `.docker/config.json`                                                                        | `"auth"` fields                                                                                                    | `docker-config-auth`                                            |
| SSH keys                                | `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` (+ `_sk`)                                                     | PEM block → `private-key`; otherwise the file itself                                                               | `ssh-private-key-file`                                          |
| `.pgpass`, `.netrc`, `.git-credentials` | by name                                                                                                    | password fields                                                                                                    | `pgpass-password`, `netrc-password`, `git-credentials-password` |

A literal is evaluated as follows:

- **Key looks secret-like** (`DB_PASSWORD`, `SONAR_TOKEN`, …):
  - passes entropy → normal finding;
  - fails entropy but ≥ 8 chars → **weak** finding (Low);
  - shorter → suppressed (`low-entropy`).
- **Key does not look secret-like:** reported only if the value is ≥ `minLength` and passes
  entropy. Dropping it is not counted as a suppression.

Expressions and references are suppressed: `${{ … }}` (`ci-expression`), and `$VAR`, `${VAR}`,
`%VAR%` or `{{ … }}` (`env-reference`). `--no-ci` makes CI files plain generic files.

**Malformed YAML** never crashes the scan. The structured parser raises `CiParseError`, and the
file is re-scanned as text with the generic key=value matcher, attributed to the `ci` detector.

## False-positive suppression (`detect/suppress.ts`)

Every reason is counted in `stats.suppressed`, once per unique blob scanned.

| Reason           | Applies to    | What                                                                                                                                                                                                                            |
| ---------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `inline-ignore`  | all           | the source line contains `leakhunter:ignore`                                                                                                                                                                                    |
| `known-example`  | all           | documentation keys, e.g. AWS's `…EXAMPLE` key pair                                                                                                                                                                              |
| `repeated-chars` | all           | ≤ 3 distinct characters (`aaaa…`, `abab…`); for signatures, checked on the body after the prefix                                                                                                                                |
| `placeholder`    | all           | `changeme`, `your_api_key_here`, `example`, `sample`, `dummy`, `placeholder`, `redacted`, `xxxx`, `<TOKEN>`, …; signature bodies only for `xxxxxx` / `EXAMPLE`                                                                  |
| `ci-expression`  | non-signature | `${{ … }}`                                                                                                                                                                                                                      |
| `env-reference`  | non-signature | `$VAR`, `${VAR}`, `%VAR%`, `{{ … }}`, `process.env.X`, `os.environ`, `getenv(`, `ENV[`                                                                                                                                          |
| `uuid`           | non-signature | RFC 4122-shaped UUIDs                                                                                                                                                                                                           |
| `git-sha`        | non-signature | 40 lowercase hex chars                                                                                                                                                                                                          |
| `lockfile`       | non-signature | `sha512-…`/`h1:…` integrity values anywhere; **every** non-signature candidate in `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `poetry.lock`, `Pipfile.lock`, `composer.lock`, `Gemfile.lock`, … |
| `data-uri`       | non-signature | value follows `data:<mime>;base64,` on the same line                                                                                                                                                                            |
| `vendor-path`    | entropy only  | `node_modules/`, `vendor/`, `third_party/`, `bower_components/`, `*.min.js`, `*.min.css`                                                                                                                                        |
| `low-entropy`    | non-signature | below the effective threshold (and not eligible for a weak finding)                                                                                                                                                             |
| `ignore-file`    | findings      | a `fingerprint:<hex>` line in an ignore file                                                                                                                                                                                    |

Signature matches are not subject to the UUID/SHA/lockfile checks. A real token inside a lockfile
is still reported.

### Ignore files

`.leakhunterignore` (read from the scanned HEAD), `--ignore <file>` and the config file's `ignore`
list all share one format:

- one gitignore-style glob per line. `*`, `**` and `?` are supported; a leading `/` anchors the
  pattern; a trailing `/` matches a directory; a pattern without `/` matches the basename at any
  depth;
- `fingerprint:<hex>` drops one finding;
- `#` starts a comment; negation (`!`) is not supported.

Ignored paths are not read at all (`stats.skipped.ignored`, counted per file version).

## Severity (`detect/severity.ts`)

A pure, table-driven function: the first matching row wins. Per-rule overrides come from the config
file's `severity` map (`{"stripe-test-key": "high"}`). A verified-ACTIVE credential is always
Critical, whatever the overrides say.

| #   | Row id                     | Severity     | Condition                                                                                 |
| --- | -------------------------- | ------------ | ----------------------------------------------------------------------------------------- |
| 1   | `verified-active`          | **Critical** | live verification returned `ACTIVE` (Phase 3)                                             |
| 2   | `private-key-at-head`      | **Critical** | `private-key` still present at HEAD                                                       |
| 3   | `live-payment-key-at-head` | **Critical** | `stripe-live-key` still present at HEAD                                                   |
| 4   | `weak-literal`             | **Low**      | secret-like key with a low-entropy literal                                                |
| 5   | `real-format-credential`   | **High**     | signature match for AWS, GitHub, Slack, `sk_live_`, or a private key (incl. history-only) |
| 6   | `ci-literal`               | **High**     | literal secret in GitHub Actions, GitLab CI or a Dockerfile                               |
| 7   | `credential-file`          | **High**     | committed `.env`, `.npmrc`, `credentials.json`, `id_rsa`, …                               |
| 8   | `test-payment-key`         | **Medium**   | `stripe-test-key`                                                                         |
| 9   | `entropy-non-app`          | **Low**      | entropy-only candidate in tests, docs, examples or fixtures                               |
| 10  | `entropy-app`              | **Medium**   | entropy-only candidate in application code                                                |
| 11  | `default`                  | **Low**      | anything else                                                                             |

Path classes (`detect/fileKind.ts`):

- **fixture**: `fixtures/`, `testdata/`, `mocks/`;
- **test**: `test/`, `tests/`, `__tests__/`, `spec/`, `e2e/`, `*.test.*`, `*.spec.*`;
- **example**: `examples/`, `samples/`, `demo/`, `*example*`;
- **docs**: `docs/`, `*.md`, `*.rst`, `*.txt`, `*.adoc`;
- **app**: anything else.

Deviation from the starting policy: rows 2–3 need the secret to be **at HEAD**, as the spec says.
The same key types found only in history fall to row 5 (High), because a deleted-but-recoverable
key still needs rotating but is no longer shipped.

## Findings, attribution and presence (`analyze.ts`)

- A **finding** is one secret at one path under one rule. Occurrences in different file versions,
  where the blob changed elsewhere in the file, are grouped. Grouping uses a keyed HMAC of the
  value with a per-run random key; the digest is never written anywhere.
- **commitHash / firstSeenCommit**: the first commit, in `--topo-order --reverse` walk order, that
  introduced the secret at that path.
- **otherCommitCount**: the other commits that added or modified that path with the secret still
  in it.
- **presence**: `in-HEAD` if the HEAD tree (or the `--branch` tip) has the same secret at the same
  path, otherwise `history-only`. A secret that lives only on a side branch is `history-only` with
  respect to HEAD.
- **fingerprint**: the first 32 hex chars of `sha256(ruleId, blobHash, filePath, line, column)` for
  the first occurrence. It is location-based, so it is stable across runs with the same history.

## Redaction (`report/redact.ts`)

- **12 or more chars:** first 4 + **16 stars** + last 4, e.g. `AKIA****************WXYZ`. The star
  count is fixed so the preview does not reveal the length.
- **Shorter:** at most 2 leading chars + 8 stars.
- **Context lines:** every detected span is replaced by its preview. Then any remaining token-like
  run (≥ 16 chars mixing letters and digits, or mixed-case with entropy ≥ 3.5) is redacted too, so
  an undetected secret on the same line cannot leak. Lines are capped at 240 chars.
- **Commit subjects and author fields** are attacker-controlled and may contain pasted secrets.
  They are passed through the same signature + residual masking before output.
