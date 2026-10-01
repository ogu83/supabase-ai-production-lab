// Applies a SQL file to the LOCAL Supabase database. Used to switch the demo between
// the vulnerable "before" state and the hardened "after" state without a full reset.
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { localEnv } from './env.mjs';
import { printTable } from './table.mjs';

const file = process.argv[2];
if (!file) {
  console.error('usage: node scripts/apply-sql.mjs <file.sql>');
  process.exit(1);
}

const { dbUrl } = localEnv();
const host = new URL(dbUrl).hostname;
if (!['127.0.0.1', 'localhost'].includes(host)) {
  console.error(`Refusing to run against non-local database host "${host}".`);
  process.exit(1);
}

const client = new pg.Client({ connectionString: dbUrl });
await client.connect();
try {
  const res = await client.query(readFileSync(file, 'utf8'));
  const last = Array.isArray(res) ? res[res.length - 1] : res;
  if (last?.command === 'SELECT') {
    if (last.rows.length === 0) console.log(`${file}: no rows`);
    else printTable(last.rows);
  } else {
    console.log(`applied ${file}`);
  }
} finally {
  await client.end();
}
