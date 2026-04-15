-- Extend webhook_deliveries with sig_valid, action_taken, deploy_id
-- for full audit coverage on every inbound webhook request.
ALTER TABLE webhook_deliveries ADD COLUMN sig_valid INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN action_taken TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN deploy_id INTEGER REFERENCES deployments(id) ON DELETE SET NULL;
