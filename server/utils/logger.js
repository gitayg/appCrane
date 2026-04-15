const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const COLORS = { error: '\x1b[31m', warn: '\x1b[33m', info: '\x1b[36m', debug: '\x1b[90m' };
const RESET = '\x1b[0m';

const level = process.env.LOG_LEVEL || 'info';

function log(lvl, msg, meta) {
  if (LEVELS[lvl] > LEVELS[level]) return;
  const ts = new Date().toISOString().slice(11, 19);
  const color = COLORS[lvl] || '';
  const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
  console.log(`${color}[${ts}] [${lvl.toUpperCase()}]${RESET} ${msg}${metaStr}`);
}

export default {
  error: (msg, meta) => log('error', msg, meta),
  warn:  (msg, meta) => log('warn', msg, meta),
  info:  (msg, meta) => log('info', msg, meta),
  debug: (msg, meta) => log('debug', msg, meta),
};
