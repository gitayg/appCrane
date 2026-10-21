import express from "express";
import session from "express-session";
import pg from "pg";

const app = express();
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
app.use(session({ secret: process.env.SESSION_SECRET!, resave: false, saveUninitialized: false }));

app.get("/api/items", async (_req, res) => {
  const { rows } = await pool.query("select * from items");
  res.json(rows);
});

const port = 5000;
app.listen(port, "0.0.0.0", () => console.log(`serving on port ${port}`));
