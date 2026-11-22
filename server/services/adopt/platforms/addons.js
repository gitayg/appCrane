// Heroku add-on names -> the AppCrane managed database engine that replaces
// them. app.json: "plan: (string, required) The add-on and plan to provision.
// This string should be in the format addon:plan or addon."
// "as: (string, optional) The attachment name for the new add-on."
// https://devcenter.heroku.com/articles/app-json-schema#add-ons
// Heroku's own data add-ons set <ATTACHMENT>_URL (DATABASE_URL, REDIS_URL by
// default). Third-party add-ons choose their own variable names, so for those
// the engine is suggested and the variable is left for the user to confirm.

const ADDONS = [
  { re: /^heroku-postgresql$/, engine: 'postgres', attach: 'DATABASE' },
  { re: /^(?:heroku-redis|heroku-key-value-store)$/, engine: 'redis', attach: 'REDIS' },
  { re: /^(?:rediscloud|redistogo|openredis|redisgreen)$/, engine: 'redis', attach: null },
  { re: /^(?:mongolab|mongohq|ormongo|objectrocket)$/, engine: 'mongo', attach: null },
  { re: /^(?:jawsdb-maria|jawsdb|cleardb)$/, engine: 'mariadb', attach: null },
];

/** { name, plan, engine|null, url_env|null, vendor } for an app.json / heroku.yml add-on entry. */
export function herokuAddon(entry) {
  const plan = typeof entry === 'string' ? entry : entry && typeof entry.plan === 'string' ? entry.plan : null;
  if (!plan) return null;
  const name = plan.split(':')[0].trim();
  const as = entry && typeof entry === 'object' && typeof entry.as === 'string' ? entry.as.trim().toUpperCase().replace(/-/g, '_') : null;
  const hit = ADDONS.find((a) => a.re.test(name));
  if (!hit) return { name, plan, engine: null, url_env: null, vendor: null };
  const attach = hit.attach ? (as || hit.attach) : null;
  return { name, plan, engine: hit.engine, url_env: attach ? `${attach}_URL` : null, vendor: hit.attach ? 'heroku' : 'third-party' };
}
