# Git Leak Hunter — working rules

Defensive supply-chain secret-exposure scanner. Ethical Hacking course project, Group 34
(Guide: Prof. Jyoti Yadav; team: Pruthvi Gangapure, Prathamesh Yewale, Yash Waghmare, Chetan Thakur).

Pipeline: `DETECT → ANALYZE → VERIFY → REPORT`. Data model: `Repository → ContentUnit → Finding → Report`.

## Non-negotiable rules (re-read at the start of every phase)

1. **Never output a full secret** — not in HTML, JSON, console, logs, error messages, stack traces,
   snapshots, or test output. Redacted preview only. In tests, use `test/helpers/noLeak.ts`
   (`expectNoLeak`) instead of `expect(x).not.toContain(secret)`, because a failing assertion would
   print the secret.
2. **Never fabricate numbers.** No invented accuracy percentages, timings, or "typical results"
   anywhere (README, docs, slides, comments). Every figure comes from a benchmark script that
   actually ran, and the docs name the tool versions, commands, machine and date. A competitor
   tool that isn't installed is reported as "not run".
3. **Live verification is opt-in, read-only, and allowlisted.** Never on by default. It requires
   `--verify --confirm-authorized`; only `sts.amazonaws.com` (GetCallerIdentity) and
   `api.github.com` (`GET /user`) may be contacted.
4. **Test fixtures contain only fabricated, non-functional secrets, generated at test time**
   (`test/fixtures/secretFactory.ts` + `buildRepos.ts`). Never commit a token-looking literal to this
   repo — assemble prefixes from fragments (e.g. `['gh', 'p_'].join('')`).
5. **Scanned repositories are untrusted input.** Spawn `git` with `execFile`/`spawn` and an argv
   array (never a shell string, never `exec`). Disable hooks, no submodule recursion, never execute
   anything from the target, put `--` before positional args, validate refs/paths, use `-z` output,
   cap file size, skip binaries. HTML-escape every dynamic value.
6. Don't invent features beyond the spec without asking. Don't skip a phase's tests to move faster.

`Finding` objects have **no raw-secret field**. Raw values live only in the in-memory verification
vault and are dropped afterwards. The JSON schema uses `additionalProperties: false` so a stray field
fails validation.

## Commands

| Task                                   | Command                                 |
| -------------------------------------- | --------------------------------------- |
| Install (lockfile, no install scripts) | `npm ci`                                |
| Typecheck                              | `npm run typecheck`                     |
| Lint / format check                    | `npm run lint` / `npm run format:check` |
| Tests                                  | `npm test`                              |
| Coverage                               | `npm run coverage`                      |
| Build                                  | `npm run build`                         |
| Run CLI from source                    | `npm run dev -- scan <path>`            |
| Build fixture repos to a dir           | `npm run fixtures -- <outDir>`          |
| Entropy calibration table              | `npx tsx bench/entropy-calibration.ts`  |
| Audit                                  | `npm audit`                             |

Requirements: runtime Node ≥ 20; development tooling (Vitest 5, ESLint 10) needs Node ≥ 22.12.
Dependencies are pinned exactly (`save-exact`), install scripts are disabled (`ignore-scripts`), and
new versions are only adopted after they have been published for at least 14 days.

## Structure

```
src/
  cli.ts            commander entry; exit codes (0 clean, 1 findings >= --fail-on, 2 error)
  pipeline.ts       wires the four stages
  analyze.ts        per-blob matches → Findings (first commit, presence, severity, pairing)
  config.ts         --config JSON (thresholds, severity overrides, ignores); never read from the target
  types.ts          ContentUnit, Finding, Report, enums
  git/              Stage 1: GitEngine (log/diff-tree walk, cat-file --batch, blob cache, counters)
  detect/           Stage 2: signatures, entropy, suppression, severity, engine
  ci/               Stage 3a: githubActions, gitlabCi, dockerfile, credentialFiles
  verify/           Stage 3b: aws, github, index (allowlist + guardrails)
  report/           Stage 4: redact, json, html
schema/report.schema.json
test/  fixtures/ (repo builder + ground truth), unit/, integration/, helpers/
bench/  docs/  examples/
```

## Workflow

Work in phases (Foundation → Core build → Integration + stretch → Polish). After each phase: run
typecheck + lint + tests, commit with a conventional-commit message, summarise in 5 lines (done,
deferred, decisions), then stop and wait for "continue".
