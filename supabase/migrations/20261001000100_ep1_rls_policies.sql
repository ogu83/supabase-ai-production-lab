-- Episode 1: hardened Row-Level Security.
-- Idempotent on purpose: scripts/apply-sql.mjs re-applies this file to restore the hardened
-- state after ep1-rls-hardening/before/vulnerable.sql has been applied for the demo.

------------------------------------------------------------------------------------------
-- 1. Helper functions live in a schema PostgREST does not expose (only "public" and
--    "graphql_public" are in config.toml [api] schemas), so they cannot be called via /rpc.
--    SECURITY DEFINER lets them read memberships without re-entering the memberships
--    policy, which is what causes "infinite recursion detected in policy" errors.
------------------------------------------------------------------------------------------
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create or replace function private.user_org_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select m.org_id
  from public.memberships m
  where m.user_id = (select auth.uid());
$$;

create or replace function private.user_admin_org_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select m.org_id
  from public.memberships m
  where m.user_id = (select auth.uid())
    and m.role in ('owner', 'admin');
$$;

revoke all on function private.user_org_ids() from public;
revoke all on function private.user_admin_org_ids() from public;
grant execute on function private.user_org_ids() to authenticated;
grant execute on function private.user_admin_org_ids() to authenticated;

------------------------------------------------------------------------------------------
-- 2. RLS on every table, and no table privileges at all for anon: nothing in this app is
--    public, so an RLS mistake still cannot leak data to a logged-out visitor.
------------------------------------------------------------------------------------------
alter table public.organizations enable row level security;
alter table public.memberships   enable row level security;
alter table public.documents     enable row level security;
alter table public.chat_threads  enable row level security;
alter table public.chat_messages enable row level security;

revoke all on public.organizations, public.memberships, public.documents,
              public.chat_threads, public.chat_messages
  from anon;

------------------------------------------------------------------------------------------
-- 3. Start from a clean slate so re-running this file never leaves a stale policy behind.
--    A forgotten permissive policy is enough to leak data: policies are OR-ed together.
------------------------------------------------------------------------------------------
do $$
declare
  p record;
begin
  for p in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in ('organizations', 'memberships', 'documents', 'chat_threads', 'chat_messages')
  loop
    execute format('drop policy %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end
$$;

------------------------------------------------------------------------------------------
-- 4. Policies. Tenancy comes from the memberships table, never from user_metadata, which
--    any signed-in user can rewrite with supabase.auth.updateUser().
--    auth.uid() is wrapped in (select ...) so Postgres evaluates it once per query instead
--    of once per row.
------------------------------------------------------------------------------------------

-- organizations
create policy "members read their orgs"
  on public.organizations for select to authenticated
  using (id in (select private.user_org_ids()));

create policy "admins rename their orgs"
  on public.organizations for update to authenticated
  using (id in (select private.user_admin_org_ids()))
  with check (id in (select private.user_admin_org_ids()));

-- memberships
create policy "members see co-members"
  on public.memberships for select to authenticated
  using (org_id in (select private.user_org_ids()));

create policy "admins add members"
  on public.memberships for insert to authenticated
  with check (org_id in (select private.user_admin_org_ids()));

create policy "admins change roles"
  on public.memberships for update to authenticated
  using (org_id in (select private.user_admin_org_ids()))
  with check (org_id in (select private.user_admin_org_ids()));

create policy "admins remove members"
  on public.memberships for delete to authenticated
  using (org_id in (select private.user_admin_org_ids()));

-- documents
create policy "members read org documents"
  on public.documents for select to authenticated
  using (org_id in (select private.user_org_ids()));

create policy "members add documents to their org"
  on public.documents for insert to authenticated
  with check (
    org_id in (select private.user_org_ids())
    and created_by = (select auth.uid())
  );

-- WITH CHECK is what stops "update documents set org_id = <someone else's org>".
-- USING alone only controls which rows you can target, not what they may become.
create policy "members edit org documents"
  on public.documents for update to authenticated
  using (org_id in (select private.user_org_ids()))
  with check (org_id in (select private.user_org_ids()));

create policy "authors and admins delete documents"
  on public.documents for delete to authenticated
  using (
    org_id in (select private.user_admin_org_ids())
    or (created_by = (select auth.uid()) and org_id in (select private.user_org_ids()))
  );

-- chat_threads: private to the user who started them, inside an org they belong to
create policy "users read their own threads"
  on public.chat_threads for select to authenticated
  using (user_id = (select auth.uid()));

create policy "users start threads in their orgs"
  on public.chat_threads for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and org_id in (select private.user_org_ids())
  );

create policy "users rename their own threads"
  on public.chat_threads for update to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and org_id in (select private.user_org_ids())
  );

create policy "users delete their own threads"
  on public.chat_threads for delete to authenticated
  using (user_id = (select auth.uid()));

-- chat_messages: visible only through a thread you own; immutable once written
create policy "users read messages in their threads"
  on public.chat_messages for select to authenticated
  using (thread_id in (select t.id from public.chat_threads t where t.user_id = (select auth.uid())));

create policy "users write messages in their threads"
  on public.chat_messages for insert to authenticated
  with check (thread_id in (select t.id from public.chat_threads t where t.user_id = (select auth.uid())));
