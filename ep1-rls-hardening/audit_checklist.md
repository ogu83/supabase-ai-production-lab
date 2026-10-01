# Supabase RLS Audit Checklist

What to check in the first hour of a Supabase rescue engagement, roughly in order of how often each one turns out to be the leak. Steps 1 and 2 are automated; the rest need someone who knows what the app is supposed to do.

## 1. Run the automated checks

```bash
npm run audit:db                    # runs audit.sql against the local stack
npm run audit:keys -- ./path/to/web # scans a frontend or build output for RLS-bypassing keys
```

On a hosted project, paste [`audit.sql`](audit.sql) into the SQL editor; it is read-only. It reports, by severity:

| Severity | Check | Why it matters |
| --- | --- | --- |
| HIGH | RLS disabled on an exposed table | The anon key, which ships in every frontend, can read and write it |
| HIGH | Always-true policy (`using (true)`) | Usually the dashboard template, added to make an error go away |
| HIGH | Policy trusts `user_metadata` | Users can rewrite it themselves with `auth.updateUser()` |
| HIGH | `SECURITY DEFINER` function in an exposed schema | Callable via `/rpc` and skips RLS |
| HIGH | View without `security_invoker = true` | Views run as their owner, so they skip RLS |
| MEDIUM | `UPDATE` policy without `WITH CHECK` | Safe only if `USING` pins the tenant; otherwise rows can be moved across tenants |
| MEDIUM | Policy that applies to `anon`/`public` | Confirm the data is meant to be public |
| LOW | RLS on with no policies | Deny-all; fine if intended |
| PERF | `auth.uid()` evaluated per row | Wrap as `(select auth.uid())` |
| INFO | `anon` table grants | Supabase default; only RLS stands between them and the data |

## 2. Check the frontend for the service key

Search the repo and the deployed bundle (view-source, `.next/`, `dist/`) for the service role key or an `sb_secret_` key. If either ever shipped, **rotate it in the dashboard**; removing it from the code does not un-leak it. A common sign is a `NEXT_PUBLIC_` or `VITE_` env var with `SERVICE_ROLE` in the name, often added to "fix" a permission error.

## 3. Find where tenancy actually comes from

For each table holding customer data, answer: *which column ties a row to a tenant, and what proves the caller belongs to that tenant?*

- Good: a membership table checked through a `SECURITY DEFINER` helper in a non-exposed schema, or `app_metadata` (only your server can write it).
- Bad: `user_metadata`, a client-supplied header or parameter, or "the frontend only ever asks for the right rows".

## 4. Try to break it as a real user

Static checks miss logic errors. Sign up two users in two tenants and, as tenant A:

- [ ] Read tenant B's rows on every table (select with no filter, then filter by B's ids)
- [ ] Insert a row carrying tenant B's id
- [ ] Update your own row so it carries tenant B's id (the "move" attack)
- [ ] Add yourself to tenant B through the membership table
- [ ] Promote yourself to admin inside your own tenant
- [ ] Rewrite your own `user_metadata` and repeat the reads
- [ ] As a logged-out visitor with only the anon key, read every table

[`exploit/run.mjs`](exploit/run.mjs) automates this pattern for the demo schema; adapt it to the client's tables.

## 5. Check everything that sidesteps the table policies

- [ ] **Storage**: public buckets, and `storage.objects` policies (they are separate from table policies)
- [ ] **Edge Functions** that use the service role key: does each one check the caller's identity and tenant before acting on ids it was sent?
- [ ] **RPC functions**: every function in `public` is an API endpoint
- [ ] **Realtime**: which tables are in the `supabase_realtime` publication, and does RLS cover them?
- [ ] **AI features**: retrieval queries for RAG must be tenant-scoped too. A cross-tenant leak through the vector search is the same leak as through a `select`.

## 6. Lock it in

- [ ] Policies written as SQL migrations, never only in the dashboard
- [ ] Tenant-isolation tests in CI ([`supabase/tests/database/ep1_rls.test.sql`](../supabase/tests/database/ep1_rls.test.sql) is a template), including structural checks: every table has RLS, no policy trusts `user_metadata`, every `UPDATE` policy has `WITH CHECK`
- [ ] Policy columns indexed (`org_id`, `user_id`)
