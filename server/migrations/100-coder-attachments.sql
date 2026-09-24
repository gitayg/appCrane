-- v2.91.0 — files attached to a coder message.
--
-- Files attached to a message (pasted, dropped or picked in the panel): a JSON
-- list of {id, name, is_image}. The files themselves live on the host under
-- DATA_DIR/app-containers/<slug>/attachments/<session>, never in the workspace.
ALTER TABLE coder_session_messages ADD COLUMN attachments TEXT;
ALTER TABLE coder_session_followups ADD COLUMN attachments TEXT;
