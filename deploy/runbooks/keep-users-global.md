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
| 3 | Image with migration `20261106065051`: backfills bound users' leftover tenantless trust rows, then drops `trusted_devices_token_user_idx` | The migration's down, **before** any image older than hanko#17 runs |
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
   Above the gate, drain Hanko (scale it to 0) and run the migrate once with the settings as
   Postgres connection options in its database URL, the way
   `trusted_device_migration_integration_test.go` does:
   `…?sslmode=require&options=-c%20hanko.trusted_device_maintenance%3Don%20-c%20hanko.trust_migration_statement_timeout%3D5min`.
   They are not `hanko migrate` flags. Keep Hanko drained until every pod runs the hanko#17 image,
   then remove the options again: left in place, every later migrate skips the gate. Hanko is one
   Deployment shared by every clinic on the cluster, so draining it is a login outage for all of
   them: on staging and prod it needs an announced maintenance window.

## Reaching the database

The database is the `hanko-<env>` RDS instance (`rds.force_ssl` on). The app's credential is the
Vault static role `static-creds/hanko-<env>-app`, which rotates; it is rendered into the Secret
`hanko-db` (key `database-url`) in the `hanko` namespace, and it owns the tables, so it runs both
the precheck and the un-adopt. The Hanko image is distroless (no shell, no `psql`), so run `psql` in
a throwaway pod in that namespace that takes the URL from the Secret, with the two SQL files mounted
from a ConfigMap made from this directory:

```sh
kubectl --context aws-<env> -n hanko create configmap unadopt-sql \
  --from-file=unadopt-precheck.sql --from-file=unadopt-users.sql
kubectl --context aws-<env> -n hanko run unadopt-psql --rm -it --restart=Never \
  --image=postgres:16-alpine --overrides='{"spec":{"containers":[{"name":"unadopt-psql",
  "image":"postgres:16-alpine","stdin":true,"tty":true,"command":["sh"],
  "env":[{"name":"HANKO_DB_URL","valueFrom":{"secretKeyRef":{"name":"hanko-db","key":"database-url"}}}],
  "volumeMounts":[{"name":"sql","mountPath":"/sql"}]}],
  "volumes":[{"name":"sql","configMap":{"name":"unadopt-sql"}}]}}'
# inside the pod: psql "$HANKO_DB_URL" -X -f /sql/unadopt-precheck.sql
kubectl --context aws-<env> -n hanko delete configmap unadopt-sql   # afterwards
```

Never print, copy or paste the URL: it carries the live password. Creating the pod and the
ConfigMap is a mutation on the cluster and needs the go-ahead like every other step; prod is run by
a person with prod access.

## Steps (per cluster)

`<env>` is `dev`, `staging` or `prod`. Every mutating step needs the go-ahead for that cluster;
prod steps are run by a person with prod access.

1. **Preconditions.**
   - `kubectl --context aws-<env> -n hanko get pods -o jsonpath='{..image}'` shows one image,
     built from hanko#17 (`ea331cde`) or later, and no older pod.
   - clinic-os on this cluster's branch contains clinic-os #8469 (`switch-complete` checks the
     session's `tenant_id` claim; check that `services/temp-token.ts` there issues a `jti`). It is
     the only route that checks the claim until clinic-os #8626 runs with
     `is_second_factor_enforced` on for a clinic.
2. **Snapshot and count.**
   ```sh
   aws rds create-db-snapshot --profile <env> --db-instance-identifier hanko-<env> \
     --db-snapshot-identifier hanko-<env>-pre-unadopt-$(date -u +%Y%m%d%H%M)
   aws rds wait db-snapshot-available --profile <env> --db-snapshot-identifier <that id>
   psql "$HANKO_DB_URL" -X -f /sql/unadopt-precheck.sql    # in the psql pod; save the output
   ```
   The snapshot must report `available` before going on. Record `tenant_bound_users` and
   `blocked_tenant_bound_users`.
3. **Deploy this image.** Its init container runs `20261106065051`, which first gives bound users'
   leftover tenantless trust rows their tenant (the guide's per-cluster backfill, done while the
   pair index still rules out a collision) and then drops the index. Re-run the precheck:
   `pair_index_drop_applied = 1`, `pair_index_left = 0`. There is no hand-run backfill.
4. **Turn the flag on.** `noscai-kubernetes-manifest` PR setting `keep_users_global: true` under
   `multi_tenant` in `clusters/aws-<env>/third-party/hanko/hanko-config.yaml` (needs
   `allow_global_users: true`, already set). `hanko-config` is a plain ConfigMap that Hanko reads
   once at start, with no reloader, so **the same PR must roll the pods**: bump the pod-template
   annotation `clinicos.dev/hanko-config-revision` in `hanko-deployment.yaml` (aws-dev has it), or
   add it (aws-staging and aws-prod don't have it yet), e.g. `"keep-users-global"`. A PR that
   changes only the ConfigMap leaves every pod running with the flag off.

   **Gate before step 5: the flag is live on every pod.**
   - Every Hanko pod started after that PR's ArgoCD sync, on the expected image:
     `kubectl --context aws-<env> -n hanko get pods -o custom-columns=NAME:.metadata.name,START:.status.startTime,IMAGE:.spec.containers[0].image`.
   - The ConfigMap they mount carries the flag:
     `kubectl --context aws-<env> -n hanko get configmap hanko-config -o yaml | grep keep_users_global`.
     (The image is distroless, so `kubectl exec … cat` doesn't work.)
   - Functional check: a throwaway global test user (`@test.nosc.ai`, created through the admin
     API) signs in to one clinic with `X-Tenant-ID`, and afterwards `SELECT tenant_id FROM users
     WHERE id = '<id>'` is still `NULL`. Delete the test user afterwards. If it came back bound, the
     flag is not live: stop, do not run step 5.
5. **Un-adopt, right after step 4's gate.**
   ```sh
   psql "$HANKO_DB_URL" -X -f /sql/unadopt-users.sql               # dry run, ends in ROLLBACK
   psql "$HANKO_DB_URL" -X -v commit=1 -f /sql/unadopt-users.sql   # apply
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
  recreates the index). Above 50,000 live trust rows the down refuses under live traffic: drain
  Hanko and pass `-c hanko.trusted_device_maintenance=on` in the database URL's `options`, as for
  hanko#17's size gate above.
- **After step 5:** keep the flag on. Turning it off adopts each un-adopted user into the clinic
  they next sign in to.
- **After step 4, never roll the image back below hanko#17 (`ea331cde`).** Older images don't know
  `keep_users_global`, start cleanly with it in their config, ignore it and adopt users again, with
  no error anywhere. Before step 5, set the flag to `false` first and then roll back. After step 5,
  roll forward only.
