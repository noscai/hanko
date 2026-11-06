-- READ ONLY. keep_users_global rollout, pre- and post-check (archon#1085 task 34).
-- psql "$HANKO_DB_URL" -X -f unadopt-precheck.sql
-- Prints counts only: no address, username or name leaves the database.
\set ON_ERROR_STOP on
BEGIN READ ONLY;

-- 1. The pair-index drop has run here (migration 20261106065051).
SELECT
  (SELECT count(*) FROM schema_migration WHERE version = '20261106065051') AS pair_index_drop_applied,
  (SELECT count(*) FROM pg_indexes WHERE indexname = 'trusted_devices_token_user_idx') AS pair_index_left;

-- 2. Users by binding.
SELECT
  count(*) FILTER (WHERE tenant_id IS NULL)     AS global_users,
  count(*) FILTER (WHERE tenant_id IS NOT NULL) AS tenant_bound_users
FROM users;

-- 3. Tenant-bound users the un-adopt must skip: one of their addresses or usernames is held by
--    another row, so making theirs global would break emails_address_global_idx /
--    usernames_username_global_idx. Each is a person with a separate Hanko user per clinic.
WITH dup_email AS (SELECT address FROM emails GROUP BY address HAVING count(*) > 1),
     dup_username AS (SELECT username FROM usernames GROUP BY username HAVING count(*) > 1),
     blocked AS (
       SELECT e.user_id FROM emails e JOIN dup_email USING (address) WHERE e.user_id IS NOT NULL
       UNION
       SELECT n.user_id FROM usernames n JOIN dup_username USING (username))
SELECT count(*) AS blocked_tenant_bound_users
FROM users u JOIN blocked b ON b.user_id = u.id
WHERE u.tenant_id IS NOT NULL;

-- 4. Tenant-bound rows per table (what the un-adopt sets to NULL, before skipping blocked users).
SELECT 'emails' AS tbl, count(*) FROM emails WHERE tenant_id IS NOT NULL AND user_id IS NOT NULL
UNION ALL SELECT 'usernames', count(*) FROM usernames WHERE tenant_id IS NOT NULL
UNION ALL SELECT 'identities', count(*) FROM identities WHERE tenant_id IS NOT NULL
UNION ALL SELECT 'webauthn_credentials', count(*) FROM webauthn_credentials WHERE tenant_id IS NOT NULL
UNION ALL SELECT 'otp_secrets', count(*) FROM otp_secrets WHERE tenant_id IS NOT NULL
UNION ALL SELECT 'password_credentials', count(*) FROM password_credentials WHERE tenant_id IS NOT NULL
UNION ALL SELECT 'trusted_devices_without_tenant_of_bound_users', count(*)
  FROM trusted_devices t JOIN users u ON u.id = t.user_id
  WHERE u.tenant_id IS NOT NULL AND t.tenant_id IS NULL;

ROLLBACK;
