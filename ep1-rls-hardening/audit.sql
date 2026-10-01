-- Supabase RLS audit. Read-only: safe to run against any project in the SQL editor.
-- Edit the "exposed" list to match the schemas in your API settings (Settings > API > Exposed schemas).
-- Returns one row per finding, most severe first. An empty result means none of these checks fired,
-- not that the project is secure: pair it with the manual checklist in audit_checklist.md.
with exposed(schema_name) as (
  values ('public')
),
findings(severity, check_name, object, detail) as (
  -- 1. Tables with RLS off: reachable through the API, guarded only by grants (anon has them by default).
  select 'HIGH', 'RLS disabled', format('%I.%I', schemaname, tablename),
         'Any client holding the anon key can read and write this table'
  from pg_tables
  where schemaname in (select schema_name from exposed) and not rowsecurity

  union all
  -- 2. Policies that are always true.
  select 'HIGH', 'Always-true policy', format('%I.%I "%s"', schemaname, tablename, policyname),
         format('%s for %s: USING %s / CHECK %s', cmd, array_to_string(roles, ','), coalesce(qual, '-'), coalesce(with_check, '-'))
  from pg_policies
  where schemaname in (select schema_name from exposed)
    and (qual = 'true' or with_check = 'true')

  union all
  -- 3. Authorization read from user_metadata, which the user can rewrite with auth.updateUser().
  select 'HIGH', 'Policy trusts user_metadata', format('%I.%I "%s"', schemaname, tablename, policyname),
         'Use app_metadata (server-set only) or a membership table instead'
  from pg_policies
  where schemaname in (select schema_name from exposed)
    and (coalesce(qual, '') ~* 'user_metadata|raw_user_meta_data'
      or coalesce(with_check, '') ~* 'user_metadata|raw_user_meta_data')

  union all
  -- 4. SECURITY DEFINER functions in an exposed schema are callable via /rest/v1/rpc and skip RLS.
  select 'HIGH', 'SECURITY DEFINER function exposed via /rpc',
         format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)),
         'Runs as its owner and bypasses RLS. Move it to a non-exposed schema or make it SECURITY INVOKER'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where p.prosecdef and n.nspname in (select schema_name from exposed)

  union all
  -- 5. Views run as their owner (usually postgres) unless security_invoker is set, so they bypass RLS.
  select 'HIGH', 'View bypasses RLS', format('%I.%I', n.nspname, c.relname),
         case when c.relkind = 'm'
              then 'Materialized view: cannot use security_invoker; revoke API access or move it'
              else 'Set: alter view ... set (security_invoker = true)' end
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where c.relkind in ('v', 'm')
    and n.nspname in (select schema_name from exposed)
    and not coalesce(c.reloptions @> array['security_invoker=true'], false)

  union all
  -- 6. UPDATE policies without WITH CHECK reuse USING for the new row. Safe only if USING pins the tenant.
  select 'MEDIUM', 'UPDATE policy without WITH CHECK', format('%I.%I "%s"', schemaname, tablename, policyname),
         format('USING %s: verify a row cannot be moved to another tenant', qual)
  from pg_policies
  where schemaname in (select schema_name from exposed)
    and cmd in ('UPDATE', 'ALL') and with_check is null

  union all
  -- 7. Policies that also apply to logged-out visitors.
  select 'MEDIUM', 'Policy applies to anon/public', format('%I.%I "%s"', schemaname, tablename, policyname),
         format('%s for %s: confirm this data is meant to be public', cmd, array_to_string(roles, ','))
  from pg_policies
  where schemaname in (select schema_name from exposed)
    and roles && array['public', 'anon']::name[]

  union all
  -- 8. Tables with RLS on but no policies: deny-all. Fine if intended; often later "fixed" with USING (true).
  select 'LOW', 'RLS on, no policies', format('%I.%I', t.schemaname, t.tablename),
         'Deny-all for API users. Confirm intent'
  from pg_tables t
  where t.schemaname in (select schema_name from exposed) and t.rowsecurity
    and not exists (select 1 from pg_policies p where p.schemaname = t.schemaname and p.tablename = t.tablename)

  union all
  -- 9. auth.uid()/auth.jwt() called per row instead of once per query.
  select 'PERF', 'auth function evaluated per row', format('%I.%I "%s"', schemaname, tablename, policyname),
         'Wrap as (select auth.uid()) / (select auth.jwt()) so Postgres caches it for the query'
  from pg_policies
  where schemaname in (select schema_name from exposed)
    and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~ 'auth\.(uid|jwt)\(\)'
    and regexp_replace(coalesce(qual, '') || ' ' || coalesce(with_check, ''),
                       'SELECT auth\.(uid|jwt)\(\)', '', 'g') ~ 'auth\.(uid|jwt)\(\)'

  union all
  -- 10. Table grants to anon. Supabase's default; only RLS stands between these and the data.
  select 'INFO', 'anon has table privileges', format('%I.%I', table_schema, table_name),
         string_agg(privilege_type, ', ' order by privilege_type)
  from information_schema.role_table_grants
  where grantee = 'anon' and table_schema in (select schema_name from exposed)
  group by table_schema, table_name
)
select severity, check_name, object, detail
from findings
order by array_position(array['HIGH', 'MEDIUM', 'LOW', 'PERF', 'INFO'], severity), check_name, object;
