# Supabase AI Production Lab

Companion repository for the **Production Supabase for AI Apps** YouTube series by [Beyond The Developer](https://www.youtube.com/@BeyondTheDeveloper).

Your AI app works in the demo. This series is about what breaks when real users and real data hit it, and how to fix it in Supabase. One realistic app runs through every episode: a multi-tenant AI knowledge assistant (organizations, members, documents, chat threads), first in the state a typical Lovable / Bolt / Cursor build ships in, then hardened.

## Series

| Episode | Folder | Topic |
| --- | --- | --- |
| Ep 1 ; Your AI App Leaks Data: Supabase RLS Done Right | [`ep1-rls-hardening/`](ep1-rls-hardening) | Four RLS mistakes exploited live, the hardened policies, pgTAP tenant-isolation tests, a reusable audit |
| Ep 2 ; RAG Inside Postgres *(coming)* | `ep2-rag-in-postgres/` | pgvector + full-text hybrid search with RRF in SQL, tenant-scoped retrieval, vs Qdrant |
| Ep 3 ; Supabase + FastAPI *(coming)* | `ep3-fastapi-backend/` | Verifying Supabase JWTs in Python, keeping RLS behind your own API, Realtime agent status |

## Quick Start

Requires Docker and Node 20+. The Supabase CLI is a dev dependency, so nothing installs globally.

```bash
npm install
npm run db:start      # local Supabase stack (API :44321, Postgres :44322, Studio :44323)
npm run db:test       # pgTAP tenant-isolation tests

npm run demo:before   # switch to the vulnerable state, run the five attacks
npm run demo:after    # restore the hardened policies, run the same attacks
npm run state:before  # just switch states (e.g. to run db:test or audit:db against the vulnerable version)
npm run state:after

npm run audit:db                                              # read-only RLS audit of the database
npm run audit:keys -- ep1-rls-hardening/before/web-sample     # find RLS-bypassing keys in a frontend
```

`npm run db:reset` rebuilds the database from the migrations at any point.

## Layout

```
supabase/
  migrations/          # schema + hardened RLS, the source of truth
  tests/database/      # pgTAP tests, run by `supabase test db`
ep1-rls-hardening/
  before/              # the vulnerable state + a leaky frontend sample (demo only)
  exploit/             # the attack runner
  audit.sql            # read-only audit, works on any Supabase project
  audit_checklist.md   # first-hour checklist for a Supabase rescue
scripts/               # local helpers: read keys from `supabase status`, apply SQL, scan for keys
```

Everything runs against the **local** stack. `scripts/apply-sql.mjs` refuses any non-local database host.

## Stack

- **Supabase** (Postgres 17, PostgREST, GoTrue) via the Supabase CLI
- **pgTAP** for database tests
- **@supabase/supabase-js** for the exploit runner
- **Node** 20+

## Author

Oguz Koroglu ; [Upwork](https://www.upwork.com/freelancers/oguzkoroglu) · [YouTube](https://www.youtube.com/@BeyondTheDeveloper) · [oguzkoroglu.dev](https://oguzkoroglu.dev)
