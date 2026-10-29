-- surveys.position: where in the app the survey card appears (a corner or the
-- centre). Before this it was always bottom right, where it can cover an app's
-- own controls. surveys.block_until_answered: 1 dims the app behind the card
-- and drops "Not now", so the person answers before using the app.
ALTER TABLE surveys ADD COLUMN position TEXT NOT NULL DEFAULT 'bottom-right'
  CHECK (position IN ('bottom-right', 'bottom-left', 'top-right', 'top-left', 'center'));
ALTER TABLE surveys ADD COLUMN block_until_answered INTEGER NOT NULL DEFAULT 0
  CHECK (block_until_answered IN (0, 1));
