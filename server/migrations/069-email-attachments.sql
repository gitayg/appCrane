-- Email attachments (v2.25.1): apps can attach files to a /api/service/email
-- send. Stored as a JSON array of { filename, content(base64), contentType }
-- on the queue row, threaded to both transports (Graph fileAttachment /
-- nodemailer). Cleared to NULL once the row is 'sent' so blobs don't linger.
ALTER TABLE email_queue ADD COLUMN attachments TEXT;
