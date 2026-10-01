-- Episode 1, BEFORE state: what a typical vibe-coded Supabase app ships with.
-- DEMO ONLY. Never run this against a real project.
-- Restore the hardened state with:  npm run demo:after   (or: npx supabase db reset)
--
-- Four mistakes, each one common on its own, and they chain:
--   1. RLS never enabled on a table added later (chat_messages)       -> anyone with the anon key reads every chat
--   2. "Enable read access for all users" template policies           -> anyone can list every customer org and its members
--   3. Tenancy read from user_metadata                                 -> a user rewrites their own org_id and reads another tenant
--   4. "Users can update their own documents" with no tenant check     -> a user moves a document into another tenant's knowledge base

-- Start from a clean slate.
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

-- Supabase's default: anon and authenticated get full table privileges and RLS is the only guard.
grant select, insert, update, delete
  on public.organizations, public.memberships, public.documents,
     public.chat_threads, public.chat_messages
  to anon, authenticated;

alter table public.organizations enable row level security;
alter table public.memberships   enable row level security;
alter table public.documents     enable row level security;
alter table public.chat_threads  enable row level security;

-- Mistake 1: chat_messages was created later in the SQL editor and RLS was never turned on.
alter table public.chat_messages disable row level security;

-- Mistake 2: the dashboard template, applied to make an "it doesn't load" error go away.
create policy "Enable read access for all users"
  on public.organizations for select
  using (true);

create policy "Enable read access for all users"
  on public.memberships for select
  using (true);

-- Mistake 3: the org id was stored in user_metadata at signup, so the policy trusts it.
-- user_metadata is writable by the user themselves via supabase.auth.updateUser({ data: ... }).
-- ("Authors can always see their own documents" is a common, reasonable-looking addition; it is
--  also what makes mistake 4 exploitable, see below.)
create policy "Users can read their org documents"
  on public.documents for select to authenticated
  using (
    created_by = auth.uid()
    or org_id = (auth.jwt() -> 'user_metadata' ->> 'org_id')::uuid
  );

create policy "Users can create documents in their org"
  on public.documents for insert to authenticated
  with check (org_id = (auth.jwt() -> 'user_metadata' ->> 'org_id')::uuid);

-- Mistake 4: ownership checked, tenancy not. With no WITH CHECK, Postgres reuses USING for the
-- new row, and created_by doesn't change, so "set org_id = <victim org>" passes.
-- Postgres also checks the updated row against the SELECT policy whenever the UPDATE has a WHERE
-- clause (always true through the REST API). The "authors can always see their own documents"
-- clause above keeps the moved row visible to the attacker, so that check passes too.
create policy "Users can update their own documents"
  on public.documents for update to authenticated
  using (created_by = auth.uid());

-- Threads are fine in this state; not every table is broken, which is why these slip through review.
create policy "Users can manage their own threads"
  on public.chat_threads for all to authenticated
  using (user_id = auth.uid());
