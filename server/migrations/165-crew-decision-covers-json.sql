-- Crew: a declared question covers exactly the messages it showed.
--
-- covers_json is the question's plan, {"ids": [...], "more": N}: the messages
-- shown to the person in full, in display order, and how many were left out
-- (services/crewQuestionView.js). An approval covers those ids and no others;
-- the left-out ones are checked again afterwards. Replaces covers_msg_id (164,
-- "everything up to an id"), which covered messages past the display budget.
-- covers_msg_id is kept for questions asked under 164.
ALTER TABLE crew_decisions ADD COLUMN covers_json TEXT;
