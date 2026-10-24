const path = require("path");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const JWT_EXPIRES_IN = "1h";
const MAX_BCRYPT_BYTES = 72;

const db = new Database(process.env.DB_PATH || "users.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  )
`);

// Used to keep login timing similar when the email doesn't exist
const DUMMY_HASH = bcrypt.hashSync("dummy-password", 12);

// ---------- JWT helpers ----------
function createToken(userId) {
  return jwt.sign({ sub: String(userId) }, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: JWT_EXPIRES_IN,
  });
}

function tokenRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }

  try {
    const payload = jwt.verify(auth.slice("Bearer ".length), JWT_SECRET, {
      algorithms: ["HS256"], // never trust the alg from the token header
    });
    req.userId = Number(payload.sub);
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired" });
    }
    return res.status(401).json({ error: "Invalid token" });
  }
}

app.post("/signup", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!email.includes("@") || email.length > 254) {
    return res.status(400).json({ error: "Invalid email" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }
  if (Buffer.byteLength(password) > MAX_BCRYPT_BYTES) {
    return res.status(400).json({ error: "Password is too long" });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db
      .prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)")
      .run(email, hash);

    return res.status(201).json({ id: Number(result.lastInsertRowid), email });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error(err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  try {
    if (Buffer.byteLength(password) > MAX_BCRYPT_BYTES) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const row = db
      .prepare("SELECT id, password_hash FROM users WHERE email = ?")
      .get(email);

    const valid = await bcrypt.compare(password, row ? row.password_hash : DUMMY_HASH);

    if (!row || !valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    return res.json({
      access_token: createToken(row.id),
      token_type: "Bearer",
      expires_in: 3600,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/me", tokenRequired, (req, res) => {
  const user = db
    .prepare("SELECT id, email FROM users WHERE id = ?")
    .get(req.userId);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  return res.json(user);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});