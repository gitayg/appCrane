// What `crane rotate-key` re-encrypts. Every value here is an encryption.js
// encrypt() blob ("iv:tag:data" hex) under the instance ENCRYPTION_KEY.
// test/key-rotation.test.js fails when a migration adds a *_enc / *_encrypted
// column that is not listed here, and rotate-key itself refuses when it finds
// a decryptable blob anywhere it does not cover.

export const ENCRYPTED_RE = /^[0-9a-f]{32}:[0-9a-f]{32}:[0-9a-f]+$/;
export const EMBEDDED_RE = /[0-9a-f]{32}:[0-9a-f]{32}:[0-9a-f]+/g;

// [table, [columns]]: the whole cell is one blob (or NULL / '').
export const COLUMNS = [
  ['env_vars', ['value_encrypted']],
  ['app_env_files', ['content_encrypted']],
  ['apps', ['github_token_encrypted', 'claude_credentials_encrypted', 'service_token_encrypted']],
  ['users', ['api_key_encrypted']],
  ['user_claude_tokens', ['token_encrypted']],
  ['llm_gateway_tokens', ['token_encrypted']],
  ['app_identity_secrets', ['secret_encrypted']],
  ['github_app_config', ['client_secret_enc', 'webhook_secret_enc', 'private_key_enc']],
  ['siem_sinks', ['secrets_enc']],
  ['managed_databases', ['password_enc', 'app_password_enc']],
  ['managed_db_servers', ['admin_password_enc']],
  ['managed_db_certs', ['key_enc']],
  ['user_mfa', ['totp_secret_enc', 'pending_secret_enc']],
  ['crew_push_configs', ['token_enc', 'auth_credentials_enc']],
];

// settings: every value shaped like a blob is one (the same structural rule
// configMigration.js uses), so a new encrypted setting is covered without a
// list. These settings hold JSON with blobs inside, at the given paths.
export const SETTINGS_JSON = [
  { key: 'llm_gateway', paths: [['providers', 'anthropic', 'key_encrypted'], ['providers', 'openai', 'key_encrypted']] },
];

// Rows rotate-key writes itself (see rotate.js), not by the generic pass.
export const SETTINGS_HANDLED = new Set(['mfa_recovery_legacy_secrets_enc']);

// Tables never rewritten: a blob found there is left as it is and reported.
// audit_log and events are sealed into the tamper-evident chain, so editing a
// row would break it; a copy of ciphertext in a log line decrypts nothing.
export const INERT_TABLES = new Set(['audit_log', 'events', 'audit_chain', 'audit_chain_checkpoints', '_migrations']);

export function coveredColumn(table, column) {
  if (table === 'settings' && column === 'value') return true;
  return COLUMNS.some(([t, cols]) => t === table && cols.includes(column));
}
