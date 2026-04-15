-- Store encrypted API keys so admin can reveal them
ALTER TABLE users ADD COLUMN api_key_encrypted TEXT;
