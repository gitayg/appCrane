CREATE TABLE notes (
  id         bigserial PRIMARY KEY,
  body       text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
  author_id  text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
