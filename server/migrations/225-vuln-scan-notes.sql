-- What a dependency scan did not cover, as a JSON array of sentences: today the
-- requirements.txt lines that are not pinned with == (never queried, since a
-- range names no installed version). NULL means nothing was left out. The
-- release check shows notes as a warning.
ALTER TABLE app_vuln_scans ADD COLUMN notes TEXT;
