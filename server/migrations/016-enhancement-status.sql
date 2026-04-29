ALTER TABLE enhancement_requests ADD COLUMN status TEXT NOT NULL DEFAULT 'consideration';
UPDATE enhancement_requests SET status = 'in_progress' WHERE in_development = 1;
