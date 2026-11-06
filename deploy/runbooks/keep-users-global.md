# Runbook: turn on `keep_users_global` and un-adopt users

ClinicOS archon#1085 task 34 (https://github.com/noscai/archon/issues/1085). One person, one global
Hanko user, signing in to every clinic they belong to. Run it per cluster in order: **dev, then
staging, then prod**, each green before the next.

**Door: one-way after step 5.** Until then, setting the flag back to `false` restores the old
behaviour. After it, un-adopted users stay global; with the flag off they are adopted again into
whichever clinic they next sign in to, which locks them out of the others (the bug this fixes).

## What changes

| Step | Change | Undo |
|---|---|---|
| 3 | Image with migration `20261106065051` drops `trusted_devices_token_user_idx` | The migration's down, **before** any image older than hanko#17 runs |
| 4 | `multi_tenant.keep_users_global: true` | Set `false` (safe only before step 5) |
| 5 | `unadopt-users.sql`: `tenant_id = NULL` on every tenant-bound user and their emails, usernames, identities, credentials, OTP secrets; their tenantless trust rows deleted | A reverse runbook (none today); restore the snapshot only in a maintenance window, since it discards every login since |

Not touched: `sessions`, `flows`, `audit_logs` and `trusted_devices.tenant_id` keep the clinic they
ran in.

## Order matters, twice

1. **Flag before un-adopt.** With the flag off, `action_continue_with_login_identifier.go` adopts a
   global user into the login's tenant, so an un-adopt run first is undone user by user on their
   next sign-in.
2. **hanko#17 image before this image.** Migration `20261106065051` drops the index that the
   images before hanko#17 (`20261101235835`) need for their trust upsert. Rolled straight from an
   older image, new pods drop the index while old pods are still serving, and every trusted-browser
   write fails for the rest of the rollout. A cluster on an older image first gets a hanko#17-only
   image (built from `ea331cde`, without `20261106065051`; dev runs `05112026-1`), fully rolled out,
   then this one. That image's init container runs `20261101235835`, which has its own size gate:
   above 50,000 live trust rows it refuses under live traffic
   (`trusted_devices is too large to migrate under live login traffic`). Count first:
   `SELECT count(*) FROM trusted_devices WHERE expires_at > (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');`.
   Above the gate, drain Hanko and run the migrate once with
   `-c hanko.trusted_device_maintenance=on` (and `-c hanko.trust_migration_statement_timeout=5min`
   for a large table), as the migration's comment describes.

## Steps (per cluster)

`<env>` is `dev`, `staging` or `prod`. Every mutating step needs the go-ahead for that cluster;
prod steps are run by a person with prod access.

1. **Preconditions.** `kubectl --context aws-<env> -n hanko get pods -o jsonpath='{..image}'`
   shows one image, hanko#17 or later, and no older pod. ClinicOS on this cluster checks the
   session's tenant claim (archon#1085 tasks 17 and 20 deployed).
2. **Snapshot and count.**
   ```sh
   aws rds create-db-snapshot --profile <env> --db-instance-identifier hanko-<env> \
     --db-snapshot-identifier hanko-<env>-pre-unadopt-$(date -u +%Y%m%d%H%M)
   aws rds wait db-snapshot-available --profile <env> --db-snapshot-identifier <that id>
   psql "$HANKO_DB_URL" -X -f unadopt-precheck.sql    # save the output
   ```
   The snapshot must report `available` before going on. Record `tenant_bound_users` and
   `blocked_tenant_bound_users`.
3. **Deploy this image.** Its init container runs `20261106065051`. Re-run the precheck:
   `pair_index_drop_applied = 1`, `pair_index_left = 0`. Then re-run the trust backfill once (the
   guide's per-cluster step):
   `UPDATE trusted_devices SET tenant_id = users.tenant_id FROM users WHERE trusted_devices.user_id = users.id AND users.tenant_id IS NOT NULL AND trusted_devices.tenant_id IS NULL;`
4. **Turn the flag on.** `noscai-kubernetes-manifest` PR setting `keep_users_global: true` under
   `multi_tenant` in `clusters/aws-<env>/third-party/hanko/hanko-config.yaml` (needs
   `allow_global_users: true`, already set). Merge, wait for every pod to restart on it.
5. **Un-adopt, right after step 4.**
   ```sh
   psql "$HANKO_DB_URL" -X -f unadopt-users.sql               # dry run, ends in ROLLBACK
   psql "$HANKO_DB_URL" -X -v commit=1 -f unadopt-users.sql   # apply
   ```
   The dry run's `users_to_unadopt` must equal `tenant_bound_users - blocked_tenant_bound_users`
   from a precheck run just before. If it doesn't, stop. The script is idempotent: a second run
   changes nothing.
6. **Verify.** The precheck again: `tenant_bound_users = blocked_tenant_bound_users`.
   archon#1085 §6.2 #19 on this cluster: a person with rows in clinics A and B signs in to A, then
   to B, with the same login. Watch Hanko's logs for trust-write errors for 30 minutes.

## Blocked users

`blocked_tenant_bound_users` counts people whose address (or username) is held by another Hanko
user, almost always a separate Hanko user per clinic. Un-adopting them would break
`emails_address_global_idx`, so the script leaves them bound, and they keep signing in to their
own clinic as today. Merging such a pair is a per-person job (which user's credentials survive,
which ClinicOS rows to repoint), outside this runbook. Report the count with the run; list the ids
locally with the precheck's `blocked` CTE, never in a ticket or Slack.

## Rollback

- **Before step 5:** set `keep_users_global: false`. Users stay as they are.
- **Image rollback after step 3:** an image older than hanko#17 needs `20261106065051`'s down
  first (`hanko migrate down 1`, which keeps the latest trust row per browser and user and
  recreates the index).
- **After step 5:** keep the flag on. Turning it off adopts each un-adopted user into the clinic
  they next sign in to.
