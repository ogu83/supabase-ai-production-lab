// Scans a frontend source tree or build output for Supabase keys that bypass RLS.
// No policy can protect you once the service_role key is in the browser: it skips RLS entirely.
//
//   node scripts/audit-client-keys.mjs <dir>        e.g. ./web  or  ./dist  or  ./.next
//
// Flags:
//   - any JWT whose payload has "role": "service_role" (legacy service key)
//   - any sb_secret_... key (new-style secret key)
//   - env vars that expose a service/secret key through a client-side prefix
//     (NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_, PUBLIC_, NUXT_PUBLIC_)
// Exits 1 when anything is found, so it can gate CI.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { printTable } from './table.mjs';

const root = process.argv[2];
if (!root) {
  console.error('usage: node scripts/audit-client-keys.mjs <dir>');
  process.exit(2);
}

const SKIP_DIRS = new Set(['node_modules', '.git', '.supabase']);
const TEXT_EXT = new Set(['', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.html',
  '.json', '.env', '.local', '.example', '.txt', '.map', '.md']);
const JWT = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g;
const SECRET_KEY = /sb_secret_[A-Za-z0-9_-]{10,}/g;
const PUBLIC_SECRET_ENV = /\b(NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(SERVICE_ROLE|SECRET)[A-Z0-9_]*\b/g;

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(name)) yield* walk(full);
    } else if (st.size < 5_000_000 && (TEXT_EXT.has(extname(name)) || name.startsWith('.env'))) {
      yield full;
    }
  }
}

function jwtRole(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    return payload.role ?? null;
  } catch {
    return null;
  }
}

const findings = [];
for (const file of walk(root)) {
  const lines = readFileSync(file, 'utf8').split(/\r?\n/);
  lines.forEach((line, i) => {
    const where = `${relative(root, file)}:${i + 1}`;
    for (const token of line.match(JWT) ?? []) {
      if (jwtRole(token) === 'service_role') {
        findings.push({ where, issue: 'JWT with role=service_role (bypasses RLS)' });
      }
    }
    if (SECRET_KEY.test(line)) findings.push({ where, issue: 'sb_secret_ key (bypasses RLS)' });
    SECRET_KEY.lastIndex = 0;
    for (const name of line.match(PUBLIC_SECRET_ENV) ?? []) {
      findings.push({ where, issue: `${name} exposes a secret through a client-side env prefix` });
    }
  });
}

if (findings.length === 0) {
  console.log(`No RLS-bypassing keys found under ${root}.`);
} else {
  printTable(findings);
  console.log(`\n${findings.length} finding(s). Rotate the key in the Supabase dashboard; deleting it from the code is not enough once it has shipped.`);
  process.exit(1);
}
