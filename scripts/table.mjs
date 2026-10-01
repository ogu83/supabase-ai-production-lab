// Prints rows as a plain box table: no index column, no quotes around strings.
// Used instead of console.table so the demo output reads cleanly on screen.
export function printTable(rows) {
  if (rows.length === 0) return;
  const cols = Object.keys(rows[0]);
  const cell = (v) => (v === null || v === undefined ? '' : String(v));
  const widths = cols.map((c) => Math.max(c.length, ...rows.map((r) => cell(r[c]).length)));
  const rule = (l, m, r) => l + widths.map((w) => '─'.repeat(w + 2)).join(m) + r;
  const fmt = (vals) => '│' + vals.map((v, i) => ' ' + v.padEnd(widths[i]) + ' ').join('│') + '│';
  console.log(rule('┌', '┬', '┐'));
  console.log(fmt(cols));
  console.log(rule('├', '┼', '┤'));
  for (const r of rows) console.log(fmt(cols.map((c) => cell(r[c]))));
  console.log(rule('└', '┴', '┘'));
}
