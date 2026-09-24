-- v2.91.0 — per-message coder mode (Auto / Edits only / Plan).
--
-- Stored beside `model` for the same reason: a transcript where one turn could
-- run commands and the next could only propose a plan has to say which was
-- which. NULL on older rows means Auto, the only behaviour there was.
ALTER TABLE coder_session_messages ADD COLUMN mode TEXT;
ALTER TABLE coder_session_followups ADD COLUMN mode TEXT;

