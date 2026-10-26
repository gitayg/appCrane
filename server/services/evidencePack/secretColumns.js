// Table columns that hold a hash or ciphertext; their stored values must never appear in a pack.
export const SECRET_COLUMNS = [
  ['users', ['api_key_hash', 'api_key_encrypted', 'api_key_expired_hash', 'password_hash']],
  ['user_mcp_keys', ['key_hash']],
  ['crew_agent_tokens', ['token_hash']],
  ['env_vars', ['value_encrypted']],
  ['apps', ['github_token_encrypted', 'claude_credentials_encrypted', 'service_token_hash', 'service_token_encrypted']],
  ['managed_databases', ['password_enc', 'app_password_enc']],
  ['siem_sinks', ['secrets_enc']],
  ['user_mfa', ['totp_secret_enc', 'pending_secret_enc']],
];
