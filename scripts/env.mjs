// Reads the local Supabase stack's URL and keys from `supabase status -o env`,
// so nothing secret is hard-coded or committed. Local dev only.
import { execSync } from 'node:child_process';

let cached;

export function localEnv() {
  if (cached) return cached;
  let raw;
  try {
    raw = execSync('npx supabase status -o env', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    throw new Error('Could not read the local Supabase status. Is the stack running?  npm run db:start\n' + err.stderr);
  }
  const vars = {};
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(/^([A-Z_]+)="?(.*?)"?$/);
    if (m) vars[m[1]] = m[2];
  }
  cached = {
    apiUrl: vars.API_URL,
    dbUrl: vars.DB_URL,
    anonKey: vars.ANON_KEY ?? vars.PUBLISHABLE_KEY,
    serviceRoleKey: vars.SERVICE_ROLE_KEY ?? vars.SECRET_KEY,
  };
  for (const [k, v] of Object.entries(cached)) {
    if (!v) throw new Error(`Missing ${k} in \`supabase status -o env\` output`);
  }
  return cached;
}
