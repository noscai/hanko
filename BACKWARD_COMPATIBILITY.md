# Backward Compatibility (Canary) — hanko

> ClinicOS-specific note. This file adopts the **ClinicOS-wide backward-compatibility
> standard** for this repo. It does **not** change any upstream `teamhanko/hanko` file, so
> it does not conflict when `main` merges upstream.

## Why this matters for hanko

hanko is the **auth service** — the **highest-blast-radius** service under Canary. During a
canary rollout, `main` (stable) and `canary` (new) run **at the same time in Production**,
both reading and writing the **same auth database**, and the same clients call **either**
version across the rollout window (and any rollback). A schema or API/token-contract change
that only the new version tolerates **locks users out**.

Reason from **bidirectional tolerance, not additivity**: a change is safe to ship in a single
release only if the currently-deployed version tolerates it on both its read and write paths
**and** the new version tolerates the old data/requests. Adding a required request field, a
new enum value old readers can't handle, relaxing `NOT NULL` when old code assumes non-null,
or adding a `UNIQUE` constraint are all additive **yet break coexistence**.

## The canonical standard

The full decision matrix (schema + API change-kind → verdict) and the
**Expand → Migrate → Contract** SOP live once, ClinicOS-wide, in the backend repo:

- **`clinic-os/docs/guides/backward-compatibility.md`** — the standard + both decision matrices.
- **`clinic-os/docs/guides/backward-compat-matrix.yaml`** — the machine-readable golden fixture
  (stack-agnostic: the verdicts classify DDL/contract *semantics*, so they hold for hanko too).

Do **not** duplicate the matrix here — it has a single source of truth so it can't drift.

## hanko's migration stack — pop / fizz (not golang-migrate)

> Correction for Archon #1643 §3.5: hanko's migrations are **gobuffalo/pop (fizz)**
> (`backend/persistence/migrations/*.up.fizz` / `*.down.fizz`), not `golang-migrate`. The
> Expand → Migrate → Contract phases are identical; only the DSL differs. Please confirm this
> row in the §3.5 owner review.

| Phase | hanko (pop / fizz) |
|-------|--------------------|
| **Expand** (additive, single-release-safe) | New `*.up.fizz`: `add_column("t", "c", "type", {"null": true})`, or `create_table(...)`. Old code ignores the new column/table. |
| **Migrate** (backfill / read-switch) | Backfill via `sql("UPDATE ...")` in a fizz migration (or a one-off job); dual-write in code; switch reads behind an env/config flag. |
| **Contract** (destructive — later release only) | Only after the old version is fully drained: `change_column(... {"null": false})`, `drop_column`, rename, add `UNIQUE`. Never in the same release as the Expand. |

**hanko-specific coexistence hot spots** to treat with extra care: the session/token tables
and the 7-day device-trust `trusted_devices` table + `clinicos-2fa-device-token` cookie
contract — a shape change here that only the new version understands fails auth for users
still routed to the old version.

## PR self-certification checklist

hanko's PR template is upstream-shared, so paste this block into the PR **description** for any
PR that touches `backend/persistence/migrations/` or an API/token/event contract:

```md
### Backward Compatibility (Canary)
- [ ] N/A — no schema change (`persistence/migrations/`) and no API/token/event contract change.
- [ ] This PR changes schema and/or a contract. Certified against `clinic-os/docs/guides/backward-compatibility.md`:
  - [ ] Every change is single-release safe per the matrix, OR split into expand → migrate → contract (this PR ships only the safe Expand).
  - [ ] No "additive but unsafe" change ships in one release (no new required field, no new enum value old readers can't handle, no relax-NOT-NULL with pre-existing readers, no new UNIQUE, no dropped/renamed column or response/token field).
  - [ ] Deprecated columns/fields stay operational for one full rollout cycle before the Contract phase removes them.
```

## AI-agent guardrail

Coding agents working in this repo: when changing `backend/persistence/migrations/` or any
API / token / event contract, follow the standard above — additive-first, and split
non-tolerable changes into expand → migrate → contract. See
`clinic-os/docs/guides/backward-compatibility.md` for the decision matrix.

---

_Adopted per Archon [#1643](https://github.com/noscai/archon/issues/1643) (Canary B6) ·
ClickUp 869e3x7xu · canonical guide: backend PR clinic-os#5091._
