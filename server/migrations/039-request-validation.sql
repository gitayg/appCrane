-- v1.27.89: Simplify Requests to 4-bucket lifecycle.
-- Adds validated_at + validated_by so the existing detailed `status`
-- column (planning, coding, sandbox_ready, merged, etc.) can be
-- collapsed to {triage, in_progress, shipped, validated} in views
-- without losing the underlying detail.
ALTER TABLE enhancement_requests ADD COLUMN validated_at TEXT;
ALTER TABLE enhancement_requests ADD COLUMN validated_by INTEGER REFERENCES users(id);
