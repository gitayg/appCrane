import chalk from 'chalk';

export const ok = (msg) => console.log(chalk.green('✓'), msg);
export const err = (msg) => console.error(chalk.red('✗'), msg);
export const warn = (msg) => console.log(chalk.yellow('!'), msg);
export const info = (msg) => console.log(chalk.cyan('→'), msg);
export const dim = (msg) => console.log(chalk.dim(msg));

export function table(headers, rows) {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map(r => String(r[i] || '').length))
  );

  const divider = widths.map(w => '─'.repeat(w + 2)).join('┼');
  const formatRow = (row) => row.map((cell, i) => ` ${String(cell || '').padEnd(widths[i])} `).join('│');

  console.log(chalk.bold(formatRow(headers)));
  console.log(divider);
  rows.forEach(row => console.log(formatRow(row)));
}

export function json(data) {
  console.log(JSON.stringify(data, null, 2));
}

export function header(title) {
  console.log('');
  console.log(chalk.bold.cyan(`  ${title}`));
  console.log(chalk.dim('  ' + '─'.repeat(title.length + 4)));
}

export function keyValue(pairs) {
  const maxKey = Math.max(...Object.keys(pairs).map(k => k.length));
  for (const [key, value] of Object.entries(pairs)) {
    console.log(`  ${chalk.dim(key.padEnd(maxKey))}  ${value}`);
  }
}

export function statusBadge(status) {
  const badges = {
    'healthy': chalk.green('● healthy'),
    'running': chalk.green('● running'),
    'live': chalk.green('● live'),
    'ok': chalk.green('● ok'),
    'down': chalk.red('● down'),
    'failed': chalk.red('● failed'),
    'stopped': chalk.dim('○ stopped'),
    'unknown': chalk.dim('? unknown'),
    'building': chalk.yellow('◉ building'),
    'deploying': chalk.yellow('◉ deploying'),
    'pending': chalk.yellow('○ pending'),
    'rolled_back': chalk.dim('↩ rolled_back'),
  };
  return badges[status] || chalk.dim(status);
}
