// "Fixed" a permission error by switching to the service role key.
// Every visitor now has full admin access to the database: RLS is skipped entirely.
import { createClient } from '@supabase/supabase-js';

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY,
);
