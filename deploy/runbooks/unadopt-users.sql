-- keep_users_global rollout: the one-way un-adopt (archon#1085 task 34).
-- Run ONLY after keep_users_global is on and rolled out on this cluster (runbook step 5); with the
-- flag off, the next login adopts the user again.
--
-- Dry run (default, ends in ROLLBACK):   psql "$HANKO_DB_URL" -X -f unadopt-users.sql
-- Commit:                                psql "$HANKO_DB_URL" -X -v commit=1 -f unadopt-users.sql
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- Every tenant-bound user, except those whose address or username another row holds (the
-- precheck's blocked_tenant_bound_users): those stay bound and are listed for a merge by hand.
-- Un-adopting every bound user, not only those shared by 2+ clinics, is Q21's resolution: once
-- everyone is global, emails_address_global_idx covers every address and registration under the
-- flag cannot create a second Hanko user for someone bound elsewhere.
CREATE TEMP TABLE unadopt ON COMMIT DROP AS
WITH dup_email AS (SELECT address FROM emails GROUP BY address HAVING count(*) > 1),
     dup_username AS (SELECT username FROM usernames GROUP BY username HAVING count(*) > 1),
     blocked AS (
       SELECT e.user_id FROM emails e JOIN dup_email USING (address) WHERE e.user_id IS NOT NULL
       UNION
       SELECT n.user_id FROM usernames n JOIN dup_username USING (username))
SELECT u.id FROM users u
WHERE u.tenant_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM blocked b WHERE b.user_id = u.id);

SELECT count(*) AS users_to_unadopt FROM unadopt;

-- Lock the users first, in id order, so a login that touches the same user waits instead of
-- interleaving (AdoptUserToTenant locks the user row the same way).
SELECT count(*) AS users_locked FROM (SELECT id FROM users WHERE id IN (SELECT id FROM unadopt) ORDER BY id FOR UPDATE) l;

-- Trust: rows keep the clinic that trusted them. A bound user's rows without a tenant answered
-- only header-less flows; once the user is global they would answer every header-less flow, so
-- they are deleted, not kept (MULTI_TENANT_DOCKER_GUIDE.md).
WITH d AS (DELETE FROM trusted_devices WHERE tenant_id IS NULL AND user_id IN (SELECT id FROM unadopt) RETURNING 1)
SELECT count(*) AS trusted_devices_deleted FROM d;

WITH r AS (UPDATE emails SET tenant_id = NULL WHERE tenant_id IS NOT NULL AND user_id IN (SELECT id FROM unadopt) RETURNING 1)
SELECT count(*) AS emails_unadopted FROM r;
WITH r AS (UPDATE usernames SET tenant_id = NULL WHERE tenant_id IS NOT NULL AND user_id IN (SELECT id FROM unadopt) RETURNING 1)
SELECT count(*) AS usernames_unadopted FROM r;
WITH r AS (UPDATE identities SET tenant_id = NULL WHERE tenant_id IS NOT NULL AND user_id IN (SELECT id FROM unadopt) RETURNING 1)
SELECT count(*) AS identities_unadopted FROM r;
WITH r AS (UPDATE webauthn_credentials SET tenant_id = NULL WHERE tenant_id IS NOT NULL AND user_id IN (SELECT id FROM unadopt) RETURNING 1)
SELECT count(*) AS webauthn_credentials_unadopted FROM r;
WITH r AS (UPDATE otp_secrets SET tenant_id = NULL WHERE tenant_id IS NOT NULL AND user_id IN (SELECT id FROM unadopt) RETURNING 1)
SELECT count(*) AS otp_secrets_unadopted FROM r;
WITH r AS (UPDATE password_credentials SET tenant_id = NULL WHERE tenant_id IS NOT NULL AND user_id IN (SELECT id FROM unadopt) RETURNING 1)
SELECT count(*) AS password_credentials_unadopted FROM r;
WITH r AS (UPDATE users SET tenant_id = NULL WHERE id IN (SELECT id FROM unadopt) RETURNING 1)
SELECT count(*) AS users_unadopted FROM r;
-- sessions, flows and audit_logs keep their tenant: each records the clinic it ran in.

\if :{?commit}
COMMIT;
\echo 'COMMITTED'
\else
ROLLBACK;
\echo 'DRY RUN: rolled back. Re-run with -v commit=1 to apply.'
\endif
