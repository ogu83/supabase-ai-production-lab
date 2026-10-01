-- Episode 1: schema for a multi-tenant AI knowledge assistant.
-- Organizations own documents and chat threads; users reach an organization only through memberships.

create table public.organizations (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  created_at timestamptz not null default now()
);

create table public.memberships (
  org_id     uuid not null references public.organizations (id) on delete cascade,
  user_id    uuid not null references auth.users (id) on delete cascade,
  role       text not null default 'member' check (role in ('owner', 'admin', 'member')),
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);

create table public.documents (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references public.organizations (id) on delete cascade,
  title      text not null,
  content    text not null,
  created_by uuid not null default auth.uid() references auth.users (id),
  created_at timestamptz not null default now()
);

create table public.chat_threads (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references public.organizations (id) on delete cascade,
  user_id    uuid not null default auth.uid() references auth.users (id) on delete cascade,
  title      text not null,
  created_at timestamptz not null default now()
);

create table public.chat_messages (
  id         bigint generated always as identity primary key,
  thread_id  uuid not null references public.chat_threads (id) on delete cascade,
  role       text not null check (role in ('user', 'assistant')),
  content    text not null,
  created_at timestamptz not null default now()
);

-- Every column an RLS policy filters on is indexed. Policies run on every row a query touches,
-- so an unindexed org_id turns a tenant-scoped read into a full table scan.
create index memberships_user_id_idx  on public.memberships (user_id);
create index documents_org_id_idx     on public.documents (org_id);
create index chat_threads_org_id_idx  on public.chat_threads (org_id);
create index chat_threads_user_id_idx on public.chat_threads (user_id);
create index chat_messages_thread_idx on public.chat_messages (thread_id);
