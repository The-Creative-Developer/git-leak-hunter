# Responsible use

Git Leak Hunter is a **defensive** tool. Its purpose is to help repository owners find and rotate
credentials that leaked into Git history or CI/CD configuration. It is not for collecting other
people's secrets.

## Rules

1. **Scan only repositories you own or are explicitly authorized to scan.** A repository being
   public does not authorize you to harvest credentials from it.
2. **Use fabricated, non-functional secrets in test repositories.** Never plant a real credential to
   "see if the tool finds it".
3. **Live verification is read-only and opt-in.** Use `--verify --confirm-authorized` only for
   credentials you own or are authorized to test.
4. **Never exploit discovered credentials.** Do not log in with them, list resources, or make any
   call beyond the single read-only check the tool performs.
5. **Report genuinely live findings privately** to the repository owner or the provider's security
   contact. Do not post them in public issues, chats or reports.
6. **Secrets stay redacted.** Share reports, not secrets. A report never contains a full secret.
7. **Rotate, then clean.** A secret found in history is compromised. Revoke or rotate it first.
   Rewriting history (e.g. `git filter-repo`) is secondary and does not undo the exposure.

## How the code enforces these rules

| Rule                                  | Enforcement                                                                                                                                                                                                       | Where                                                  |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| Authorization before scanning remotes | An authorization notice is printed before any clone; `--help` lists the rules                                                                                                                                     | `src/cli.ts`, `src/git/repo.ts`                        |
| Fabricated test secrets only          | Fixtures generate format-valid random values at test time; a hygiene test fails if a token-shaped literal is ever committed                                                                                       | `test/fixtures/`, `test/unit/hygiene.test.ts`          |
| Verification is opt-in                | Requires both `--verify` and `--confirm-authorized`; prints a warning banner; off by default                                                                                                                      | `src/cli.ts`, `src/pipeline.ts`                        |
| Verification is read-only and minimal | Exactly one call per unique credential: AWS `sts:GetCallerIdentity` or GitHub `GET /user`. Exact-host allowlist, https only, no redirects, 10 s timeout, no retries, per-provider call cap, stop on rate limiting | `src/verify/`                                          |
| No exploitation, no data collection   | Account IDs, ARNs and usernames from responses are discarded; the GitHub response body is never read                                                                                                              | `src/verify/aws.ts`, `src/verify/github.ts`            |
| Raw secrets never persisted           | `Finding` has no raw-secret field; raw values exist only inside one function call or, with `--verify`, in an in-memory vault cleared right after verification                                                     | `src/detect/engine.ts`, `src/verify/vault.ts`          |
| Redacted by default                   | First 4 + 16 stars + last 4 (≤ 2 chars for short values); context lines and commit messages are masked as well                                                                                                    | `src/report/redact.ts`, `src/report/sanitize.ts`       |
| Leak-free outputs                     | Tests assert that no planted secret appears in HTML, JSON, stdout or stderr, and test helpers never print the secret they search for                                                                              | `test/integration/*.test.ts`, `test/helpers/noLeak.ts` |
| `dork` stays inside your own account  | Before any search, the token's account must be the owner (or an active admin of the org); every query is scoped to exactly that owner; results from other owners are dropped; requires `--confirm-authorized`     | `src/dork/`                                            |
| No telemetry                          | The only network access is `git clone` of a URL you supply, the opt-in verification calls, and `dork` (when you run it)                                                                                           | `src/git/repo.ts`, `src/verify/http.ts`                |

## If you find a live credential

1. Stop. Do not use it.
2. Note the redacted preview, file path, commit and fingerprint from the report.
3. Contact the owner privately (security contact, `SECURITY.md`, or the provider's reporting
   channel). Include the location, not the secret.
4. Let the owner rotate it. Delete your local scan outputs once the issue is resolved.
