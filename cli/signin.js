import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

// Host break-glass for the per-account password lockout
// (server/services/signinRisk/lockout.js). A direct database write, like
// `crane sso enforce`: it needs a shell on the AppCrane host and makes no
// network request, so it works when every platform admin is locked out of the
// web UI. Audited as signin-unlock with via: 'cli'.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

async function openLocalDb(out) {
  const { openDb, getDb, pendingMigrationNames } = await import(join(ROOT, 'server', 'db.js'));
  openDb();
  const pending = pendingMigrationNames();
  if (pending.length) {
    out.err(`The database is ${pending.length} migration(s) behind this code.`);
    out.dim(`First pending: ${pending[0]}`);
    out.dim('Start AppCrane to apply them (the server migrates on boot). This command does not.');
    process.exit(1);
  }
  return getDb();
}

function findUser(db, who) {
  const s = String(who || '').trim();
  if (/^\d+$/.test(s)) return db.prepare('SELECT * FROM users WHERE id = ?').get(Number(s)) || null;
  return db.prepare('SELECT * FROM users WHERE lower(email) = lower(?) OR username = ?').get(s, s) || null;
}

export function registerSignin(program, out) {
  const signin = program.command('signin').description('Sign-in risk: password lockouts (must run on server)');

  signin
    .command('unlock <user>')
    .description('Lift every password lock on an account (user id, username or e-mail)')
    .action(async (who) => {
      try {
        const db = await openLocalDb(out);
        const user = findUser(db, who);
        if (!user) { out.err(`No user matches ${who}.`); process.exit(1); }
        const { unlockUser } = await import(join(ROOT, 'server', 'services', 'signinRisk', 'lockout.js'));
        const n = unlockUser(db, user.id, { actorId: null, via: 'cli' });
        out.ok(`Unlocked ${user.name || user.username} (id ${user.id}): ${n} lock record(s) cleared.`);
      } catch (e) {
        out.err(`Failed: ${e.message}`);
        out.dim('Make sure you run this from the appCrane directory.');
        process.exit(1);
      }
    });

  signin
    .command('locked')
    .description('List accounts whose password sign-in is locked right now')
    .action(async () => {
      try {
        const db = await openLocalDb(out);
        const { listLocked } = await import(join(ROOT, 'server', 'services', 'signinRisk', 'lockout.js'));
        const rows = listLocked(db);
        if (!rows.length) { out.ok('No account is locked.'); return; }
        out.table(['id', 'user', 'scope', 'locked until'], rows.map((r) => [r.user_id, r.username || r.email || r.name, r.scope, r.locked_until]));
      } catch (e) {
        out.err(`Failed: ${e.message}`);
        process.exit(1);
      }
    });
}
