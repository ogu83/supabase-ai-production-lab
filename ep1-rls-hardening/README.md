# Episode 1 ; Your AI App Leaks Data: Supabase RLS Done Right

A multi-tenant AI knowledge assistant, first in the state a typical Lovable / Bolt / Cursor build ships in, then hardened. Every attack below runs against the local stack using only what a real attacker has: the public anon key (it ships in every Supabase frontend) and their own login.

## Run it

```bash
npm install && npm run db:start

npm run demo:before   # apply before/vulnerable.sql, run the attacks
npm run demo:after    # re-apply the hardened migration, run the same attacks

npm run state:before  # switch to the vulnerable state without running the attacks
npm run state:after   # switch back to the hardened state
npm run db:test       # 20 pgTAP tests
npm run audit:db      # read-only audit (audit.sql)
npm run audit:keys -- ep1-rls-hardening/before/web-sample
```

## Before

```
┌─────────────────────────────────────────────────────────┬────────┬────────────────────────────────────────────────────────────────────────┐
│ attack                                                  │ result │ detail                                                                 │
├─────────────────────────────────────────────────────────┼────────┼────────────────────────────────────────────────────────────────────────┤
│ 1. Logged-out visitor reads chat messages               │ LEAKED │ "Draft the Henderson settlement offer; our ceiling is 1.2M."           │
│ 2. Logged-out visitor lists every customer org          │ LEAKED │ Acme Realty, Globex Legal                                              │
│ 3. Alice discovers other tenants and their ids          │ LEAKED │ Globex id b1366ee4...                                                  │
│ 4. Alice forges user_metadata.org_id, reads Globex docs │ LEAKED │ "Henderson settlement terms": Confidential: client authorizes settl... │
│ 5. Alice plants a prompt-injection doc in Globex RAG    │ LEAKED │ Bob's knowledge base now returns it                                    │
└─────────────────────────────────────────────────────────┴────────┴────────────────────────────────────────────────────────────────────────┘

5 of 5 attacks leaked data across tenants.
```

## After

```
┌─────────────────────────────────────────────────────────┬─────────┬──────────────────────────────────────────────────────────────────┐
│ attack                                                  │ result  │ detail                                                           │
├─────────────────────────────────────────────────────────┼─────────┼──────────────────────────────────────────────────────────────────┤
│ 1. Logged-out visitor reads chat messages               │ blocked │ permission denied for table chat_messages                        │
│ 2. Logged-out visitor lists every customer org          │ blocked │ permission denied for table organizations                        │
│ 3. Alice discovers other tenants and their ids          │ blocked │ 0 rows                                                           │
│ 4. Alice forges user_metadata.org_id, reads Globex docs │ blocked │ 0 rows                                                           │
│ 5. Alice plants a prompt-injection doc in Globex RAG    │ blocked │ new row violates row-level security policy for table "documents" │
└─────────────────────────────────────────────────────────┴─────────┴──────────────────────────────────────────────────────────────────┘

All 5 attacks blocked.
```

## The mistakes, and the fixes

| # | Mistake (in [`before/vulnerable.sql`](before/vulnerable.sql)) | Fix (in [`20261001000100_ep1_rls_policies.sql`](../supabase/migrations/20261001000100_ep1_rls_policies.sql)) |
| --- | --- | --- |
| 1 | RLS never enabled on a table added later (`chat_messages`) | RLS on every table, and no table privileges for `anon` at all |
| 2 | Dashboard template "Enable read access for all users" (`using (true)`) | Membership-scoped `SELECT` policies, `to authenticated` only |
| 3 | Tenancy read from `user_metadata`, which users can rewrite with `auth.updateUser()` | Tenancy from the `memberships` table through `SECURITY DEFINER` helpers in a schema the API doesn't expose |
| 4 | "Users can update their own documents": ownership checked, tenancy not | Explicit `WITH CHECK` pinning the row to an org the caller belongs to |
| 5 | Service role key in the frontend (`NEXT_PUBLIC_..._SERVICE_ROLE_KEY`) | Not fixable in SQL. Caught by `audit:keys`; rotate the key |

Two details worth knowing:

- **Why mistake 4 needs a second ingredient.** When an `UPDATE` has a `WHERE` clause (always true through the REST API), Postgres also checks the *updated* row against the `SELECT` policy. The move attack only works because the vulnerable app also lets authors always read their own documents, so the moved row stays visible to the attacker. Remove either half and it fails; the hardened version doesn't rely on that.
- **Why the helpers live in `private` and are `SECURITY DEFINER`.** A `memberships` policy that queries `memberships` recurses ("infinite recursion detected in policy"). The helper reads `memberships` as its owner, and because `private` isn't an exposed schema, nobody can call it through `/rpc`.

## Tests that go red when they should

[`supabase/tests/database/ep1_rls.test.sql`](../supabase/tests/database/ep1_rls.test.sql) has 20 pgTAP tests: four structural checks (every table has RLS, `anon` has no grants, no policy trusts `user_metadata`, every `UPDATE` policy has a `WITH CHECK`) plus behavioral tests as three users and as `anon`.

Against the hardened state all 20 pass. Against `before/vulnerable.sql`, 12 fail, and every planted mistake trips at least one of them. The other 8 stay green because those paths really are closed in the before state too.

## Audit a real project

- [`audit.sql`](audit.sql) is read-only and runs on any Supabase project. Against the before state it reports 18 findings (5 high); against the hardened state, none.
- [`audit_checklist.md`](audit_checklist.md) covers what a query can't: where tenancy actually comes from, trying to break it as two real users, Storage, Edge Functions, RPC, Realtime, and tenant-scoped retrieval for AI features.
