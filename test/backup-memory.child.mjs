// Child process for backup-memory.test.js: runs one backup operation and
// prints its own peak RSS (KB) as JSON on the last line of stdout.
const [mode, root, archive] = process.argv.slice(2);
process.env.DATA_DIR = root;

const { initDb } = await import('../server/db.js');
initDb();
const { exportDataArchive, importDataArchive } = await import('../server/services/configBackup.js');

let out = {};
if (mode === 'export') {
  const r = await exportDataArchive({ version: 'rss-test' });
  out = { path: r.path, bytes: r.bytes };
} else if (mode === 'import') {
  const r = await importDataArchive(archive, { restoreEnv: false });
  out = { dataFiles: r.dataFiles };
} else if (mode !== 'baseline') {
  throw new Error(`unknown mode ${mode}`);
}
console.log(JSON.stringify({ mode, maxRSS: process.resourceUsage().maxRSS, ...out }));
