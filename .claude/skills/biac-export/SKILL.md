---
name: biac-export
description: Options, architecture and revision workflow for the biac-export Go tool (exports Starburst Enterprise BIAC roles, grants, column masks, row filters, role assignments). Use when asked what the tool can do, how to run/build/ship it, how to adopt a new API spec version, or how to add/remove an exported service.
---

# biac-export: options and how to evolve it

Go (stdlib only) CLI in `cmd/biac-export/`. Exports SEP built-in access control into a compact, ID-free artifact (JSON, gzip if `.gz`) meant for fast import into another SEP.

When the user asks "what are the options", answer from the sections below, then offer the next concrete step.

## Architecture (three layers)
| File | Role |
|---|---|
| `embedded/api.spec` | OpenAPI 3 spec (copy of `Reference/api.spec`), embedded; `--spec` overrides |
| `embedded/plan.json` | WHAT to export: resources, parent/child (`per`), path-param mapping, ID->name `rewrite`, `drop`, `optional`, `selectKey`; `--plan` overrides |
| `spec.go`, `plan.go` | Spec index by `operationId`; plan validation (GET only, no `/internal/`, params covered) |
| `engine.go` | Generic fetch (pagination from spec envelope), child fetch, rewrites, drops; JSON kept generic so new API fields flow through |
| `specdiff.go` | Compare two specs, flag impact on the plan |
| `client.go` | HTTP: Basic or Bearer, TLS>=1.2, https-only (`--allow-http` for tests), no redirects, retries 429/5xx |

## Commands and flags
- `export --url --out [--select roles=a,b] [--spec] [--plan] [--concurrency 16] [--ca-cert] [--timeout] [--allow-http]`
- `import --in art.biac [--url TARGET] [--role sysadmin] [--overwrite] [--dry-run | --compare] [--snapshot f] [--refresh-snapshot] [--yes]` (import.go).
  - REAL run: create-first. Every role/expression is POSTed; on failure ONE cached lookup (loadLive) decides "already exists" (skip, or with `--overwrite` sync IN PLACE: description, grants, location grants, masks, filters, assignments; extras removed) vs a genuine failure (reported at the end). No up-front reads, never deletes/recreates roles or expressions. Creates before deletes, DENY grants first, confirmation unless `--yes`.
  - `--dry-run` / `--compare` never write. They use a SNAPSHOT = full export of the target saved as `./target-<host>.snapshot.biac` (0600): read live once, reused offline afterwards (no creds needed); `--refresh-snapshot` re-reads; user may delete it any time. `--live` = online compare: fresh read of the target for this run only, no snapshot used/written, implies `--compare`, rejects --snapshot/--refresh-snapshot. A real run that writes deletes it (stale). `--compare` additionally reports existing roles/expressions as identical / DIFFERS (per-kind missing/extra counts). Snapshot contains the target's access policy: treat as sensitive.
  - A role left half-built by a failed run looks "exists" to the next default run; failures are listed, re-run with `--overwrite` to converge.
  - Adding a child resource to the plan does NOT auto-import it: add handling in import.go (`knownChildren`, `createOp/deleteOp/deleteParam`) or it is warned as unsupported. Required write ops: `importOps`, checked against the spec.
- `validate [--spec] [--plan]`: offline plan-vs-spec check
- `spec-diff [--plan] OLD NEW`: exit code 2 if plan impacted
- `--role sysadmin` (env `STARBURST_ROLE`): sends `X-Trino-Role: system=ROLE{sysadmin}` per request. Needed because sysadmin is never auto-enabled (docs: starburst-rest-api, biac-roles); without it BIAC lists are filtered by the other roles the account holds, so column-mask expressions can be missing.
- Credentials ONLY via env: `STARBURST_URL`, `STARBURST_TOKEN` (bearer) or `STARBURST_USER` + `STARBURST_PASSWORD`. Never add secret flags; never echo secrets.

## Artifact (logical format v2; default container = binary `.biac`)
Container chosen by extension: `.biac` (default, binary) | `.json` | `.json.gz`. `export --debug` also writes `<out>.debug.json` next to the binary. `convert IN OUT` switches between them (input sniffed by content). Importer must use `loadArtifact(path)` (binfmt.go), which accepts all three and returns the same Go types (int64/float64).
Binary spec is in the header comment of `binfmt.go`: magic `BIAC`, global frequency-ordered string table (keys + values interned), varint tagged values, sorted keys (deterministic bytes), SHA-256 trailer (integrity, NOT authenticity; use signing for that). Decoder treats input as untrusted (bounds-checked, depth-limited, tested against truncation/bit-flips). Benchmarked on 5000 roles: 1.8 MB JSON -> 0.42 MB, load ~4x faster than encoding/json.
Logical shape: `{v, exportedAt, source, specVersion, order, resources:{...}}`. Roles nest `grants, locationGrants, columnMasks, rowFilters, assignments`. All numeric IDs replaced by names. `order` = import order. Output file mode 0600.

## Revision playbooks
**Adopt a new spec version**
1. `go run ./cmd/biac-export spec-diff Reference/api.spec NEW.spec` (exit 2 = plan affected).
2. Fix `plan.json` for marked items (renamed op, changed params, removed fields).
3. Copy NEW.spec to `Reference/api.spec` and `cmd/biac-export/embedded/api.spec`.
4. `validate`, `go test -race ./...`, rebuild.

**Add a service**: add a resource to `plan.json` (see existing entries), run `validate`. New ops appear in the spec-diff "added" list. Add a mock path in `main_test.go` and an assertion.

**Remove/retire a service**: set `"optional": true` (skipped with a warning if op missing or 404) or delete the entry.

**Add a field-ID rewrite**: use `rewrite` {field (dotted ok), to, from (earlier top-level resource), use}.

## Build and ship (Linux, from macOS)
`CGO_ENABLED=0 GOOS=linux GOARCH=amd64|arm64 go build -trimpath -ldflags="-s -w" -o dist/biac-export-linux-<arch> ./cmd/biac-export`
Static, distro-independent; one build per CPU arch. Ship binary + SHA256SUMS + README. `-trimpath` avoids leaking local paths. Check module path (`github.com/starburstdata/...`) is OK to expose externally.

## Known gaps / open items
- Import is built and tested only against an in-memory fake (import_test.go), not yet a real cluster. forceNone cannot be set via the mask/filter payload (warned). Grants on ROLES/USERS entities are imported verbatim (warned).
- Grant/mask/filter `entity` blocks stored as returned. For categories ROLES/USERS/COLUMN_MASK_EXPRESSIONS the `entityKey` may be an ID (unverified); may need translation on import.
- Never run against a real cluster yet; tests use a mock built from the spec schemas.
- Nothing committed to git yet.

## Guardrails (org policy)
Treat exports as confidential (role/table names, SQL). Fail closed, least privilege (read-only service account), no hardcoded secrets, no permissive TLS. For external delivery, don't include internal hostnames, usernames or project codenames; confirm artifacts are internal-only before sharing.
