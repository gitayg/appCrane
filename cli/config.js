import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const CONFIG_DIR = join(homedir(), '.cloudcrane');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

const DEFAULTS = {
  api_url: 'http://localhost:5001',
  api_key: '',
};

export function getConfig() {
  if (!existsSync(CONFIG_FILE)) return { ...DEFAULTS };
  try {
    return { ...DEFAULTS, ...JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) };
  } catch (e) {
    return { ...DEFAULTS };
  }
}

export function saveConfig(config) {
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
  try { chmodSync(CONFIG_FILE, 0o600); } catch (_) {}
}

export function getApiUrl() {
  return process.env.CC_API_URL || getConfig().api_url;
}

export function getApiKey() {
  return process.env.CC_API_KEY || getConfig().api_key;
}
