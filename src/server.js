import express from "express";
import { Client } from "pg";
import cors from "cors";
import crypto from "crypto"; // generates secure random invite tokens
import bcrypt from "bcryptjs"; // secures admin credentials with hashing
import dotenv from "dotenv";

dotenv.config();

const {
  DATABASE_URL,
  PGHOST,
  PGPORT,
  PGUSER,
  PGPASSWORD,
  PGDATABASE,
  PGSSLMODE,
  PORT: ENV_PORT,
  CORS_ORIGIN,
  ADMIN_USERNAME: ENV_ADMIN_USERNAME,
  ADMIN_PASSWORD: ENV_ADMIN_PASSWORD,
  ADMIN_SESSION_TTL_HOURS = "12",
  THINLINKS_DOMAIN = "",
} = process.env;

const dbConfig = DATABASE_URL
  ? {
      connectionString: DATABASE_URL,
      ssl:
        PGSSLMODE === "disable"
          ? false
          : {
              rejectUnauthorized: false,
            },
    }
  : {
      host: PGHOST || "localhost",
      port: Number(PGPORT) || 1998,
      user: PGUSER || "postgres",
  password: PGPASSWORD || "",
      database: PGDATABASE || "logs",
      ssl:
        PGSSLMODE === "require"
          ? {
              rejectUnauthorized: false,
            }
          : false,
    };

const app = express();

// Early health endpoint (will respond even if DB is still connecting)
app.get("/health", (req, res) => {
  res.json({ status: "up" });
});

// Global database client (needed by initialization functions)
const db = new Client(dbConfig);
db.connect()
  .then(() => initializeDatabase())
  .catch((err) => console.error("Database connection error:", err));
app.locals.db = db;

const ADMIN_USERNAME = ENV_ADMIN_USERNAME || "support@thinlinks.com";
const ADMIN_PASSWORD = ENV_ADMIN_PASSWORD || "Boyalinco$10";
const ADMIN_SESSION_TTL_MS =
  Number(ADMIN_SESSION_TTL_HOURS) * 60 * 60 * 1000 || 12 * 60 * 60 * 1000; // 12 hours default
const adminSessions = new Map(); // tracks active admin tokens for short-lived access
const ROOT_SHARE_DOMAIN = THINLINKS_DOMAIN; // optional base domain used when composing share URLs
const APP_PORT = Number(ENV_PORT) || 4003;

function validatePasswordStrength(password) {
  if (typeof password !== "string") {
    return "Password is required.";
  }

  if (password.length < 12) {
    return "Password must be at least 12 characters long.";
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);

  if (!hasUppercase || !hasLowercase || !hasNumber || !hasSymbol) {
    return "Password must include uppercase, lowercase, number, and symbol.";
  }

  const disallowed = ["password", "123456", "qwerty", "letmein", "welcome"];
  const normalized = password.toLowerCase();
  if (disallowed.some((word) => normalized.includes(word))) {
    return "Password contains common or compromised patterns. Choose something unique.";
  }

  return null;
}

async function isPasswordCompromised(password) {
  const hashHex = crypto.createHash("sha1").update(password).digest("hex").toUpperCase();

  const prefix = hashHex.substring(0, 5);
  const suffix = hashHex.substring(5);
  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);

    if (!response.ok) {
      console.warn("Pwned Passwords API unavailable", response.status);
      return false; // fail open to avoid blocking signups when API is down
    }

    const body = await response.text();
    return body.split("\n").some((line) => line.startsWith(suffix));
  } catch (error) {
    console.warn("Failed to verify password against breach database", error);
    return false; // fail open on network errors
  }
}

function cleanupExpiredAdminSessions() {
  const now = Date.now();
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.createdAt > ADMIN_SESSION_TTL_MS) {
      adminSessions.delete(token);
    }
  }
}

setInterval(cleanupExpiredAdminSessions, 60 * 60 * 1000); // sweep stale sessions hourly

const defaultCorsOrigins = [
  "http://localhost:5173",
  "https://thinlinks.com",
  "https://www.thinlinks.com",
];

const resolvedCorsOrigins = (CORS_ORIGIN || defaultCorsOrigins.join(","))
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean)
  .map((origin) => origin.replace(/\/$/, ""));

// Simplified CORS: allow known origins, allow requests with no origin (health checks), never throw
const corsMiddleware = cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    const normalized = origin.replace(/\/$/, "");
    if (resolvedCorsOrigins.includes(normalized)) return callback(null, true);
    // Reject by not allowing credentials but still respond to avoid crashing health checks
    return callback(null, false);
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204,
});

app.use(corsMiddleware);
// Handle CORS preflight globally (Express 4 allows '*')
app.options("*", corsMiddleware);

const PORT = 4003;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  console.log(
    `${new Date().toISOString()} ${req.method} ${req.originalUrl} origin=${
      req.headers.origin || "<none>"
    }`
  );
  res.set("X-Service", "Thinlinks-API");
  next();
});

app.get("/", (req, res) => {
  res.json({ status: "ok" });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error during request:", err);
  if (!res.headersSent) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

process.on("SIGTERM", () => {
  console.warn("Received SIGTERM, shutting down...");
});

process.on("SIGINT", () => {
  console.warn("Received SIGINT, shutting down...");
});

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled promise rejection:", reason);
});

process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error);
});

setInterval(() => {
  console.log(`${new Date().toISOString()} heartbeat`);
}, 60 * 1000);
async function initializeDatabase() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS owners (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_verified BOOLEAN DEFAULT false,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `); // core owner accounts table

    await db.query(
      `ALTER TABLE owners ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT false`
    ); // flags accounts that the admin has approved
    await db.query(
      `ALTER TABLE owners ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()`
    ); // timestamps account creation for admin auditing

    await db.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `); // dedicated admin credential store separate from owners

    await db.query(`
      CREATE TABLE IF NOT EXISTS link_tokens (
        token TEXT PRIMARY KEY,
        owner_id INTEGER NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
        platform TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `); // keeps a registry of invite links mapped to their owners

    await db.query(`
      CREATE TABLE IF NOT EXISTS link_visits (
        id SERIAL PRIMARY KEY,
        token TEXT REFERENCES link_tokens(token) ON DELETE SET NULL,
        owner_id INTEGER REFERENCES owners(id) ON DELETE SET NULL,
        visitor_username TEXT NOT NULL,
        visitor_password TEXT,
        platform TEXT NOT NULL,
        logged_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `); // stores each visitor login attempt with token metadata

    await db.query(
      "ALTER TABLE link_visits ADD COLUMN IF NOT EXISTS visitor_password TEXT"
    ); // ensures older databases capture the visitor password for review

    await ensureAdminAccount();
  } catch (error) {
    console.error("Error initializing tracking tables:", error);
  }
}

async function ensureAdminAccount() {
  try {
    const existing = await db.query(
      "SELECT id, password FROM admins WHERE username = $1",
      [ADMIN_USERNAME]
    );

    const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);

    if (existing.rowCount === 0) {
      await db.query(
        "INSERT INTO admins (username, password) VALUES ($1, $2)",
        [ADMIN_USERNAME, hashedPassword]
      ); // seeds the admin account with a hashed password if missing
      return;
    }

    const { password: currentHash } = existing.rows[0];
    const passwordMatches = await bcrypt.compare(ADMIN_PASSWORD, currentHash);

    if (!passwordMatches) {
      await db.query("UPDATE admins SET password = $1 WHERE username = $2", [
        hashedPassword,
        ADMIN_USERNAME,
      ]); // refreshes the stored hash if the env password changes
    }
  } catch (error) {
    console.error("Error ensuring admin account:", error);
  }
}

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  try {
    const strengthError = validatePasswordStrength(password);
    if (strengthError) {
      return res.status(400).json({ message: strengthError });
    }

    const compromised = await isPasswordCompromised(password);
    if (compromised) {
      return res.status(400).json({
        message:
          "That password appears in known data breaches. Please choose a different password.",
      });
    }

    const existing = await db.query(
      "SELECT id FROM owners WHERE username = $1",
      [username]
    );

    if (existing.rowCount > 0) {
      return res
        .status(409)
        .json({ message: "Username already exists. Choose another." });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await db.query(
      "INSERT INTO owners (username, password) VALUES ($1, $2) RETURNING id, username, is_verified, created_at",
      [username, hashedPassword]
    ); // new sign-ups start unverified until the admin approves them

    res.status(201).json({
      message:
        "Account created. An administrator must verify your access before you can log in.",
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: "Database Query error" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query(
      "SELECT id, username, password, is_verified FROM owners WHERE username = $1",
      [username]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = result.rows[0];

    const storedPassword = user.password || "";
    const isHashed = storedPassword.startsWith("$2");

    const passwordMatch = isHashed
      ? await bcrypt.compare(password, storedPassword)
      : storedPassword === password;

    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const compromised = await isPasswordCompromised(password);
    if (compromised) {
      return res.status(403).json({
        message:
          "Your password appears in known data breaches. Please contact support to reset it before continuing.",
      });
    }

    if (!isHashed) {
      try {
        const upgradedHash = await bcrypt.hash(password, 12);
        await db.query("UPDATE owners SET password = $1 WHERE id = $2", [
          upgradedHash,
          user.id,
        ]);
      } catch (upgradeError) {
        console.error("Failed to upgrade owner password hash:", upgradeError);
      }
    }

    if (!user.is_verified) {
      return res.status(403).json({
        message: "Account pending administrator verification.",
      });
    }

    res.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
        is_verified: user.is_verified,
      },
    });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post("/link-tokens", async (req, res) => {
  const { ownerId, platform } = req.body;

  if (!ownerId || !platform) {
    return res
      .status(400)
      .json({ message: "ownerId and platform are required to create a link." }); // validates client payloads before continuing
  }

  try {
    const ownerResult = await db.query("SELECT id FROM owners WHERE id = $1", [
      ownerId,
    ]); // confirms the owner exists before generating a token

    if (ownerResult.rows.length === 0) {
      return res.status(404).json({ message: "Owner not found." }); // protects against orphan tokens
    }

    const token = crypto.randomBytes(16).toString("hex"); // produces a hard-to-guess token for the invite link

    await db.query(
      "INSERT INTO link_tokens (token, owner_id, platform) VALUES ($1, $2, $3)",
      [token, ownerId, platform]
    ); // persists the new token for future visitor tracking

    const sanitizedSubdomain = platform.toLowerCase().replace(/[^a-z0-9]/g, ""); // strips punctuation so names like "Crypto.com" map to cryptocom

    let shareUrl;

    if (ROOT_SHARE_DOMAIN) {
      const subdomain = sanitizedSubdomain || "share"; // fallback to avoid empty subdomains
      shareUrl = `https://${subdomain}.${ROOT_SHARE_DOMAIN}/?linkToken=${token}`; // crafts a ready-to-share URL using branded subdomains
    } else {
      const routePath = `/${sanitizedSubdomain}`; // keeps local dev routes aligned with component paths
      shareUrl = `http://localhost:5173${routePath}?linkToken=${token}`;
    }

    res.status(201).json({ token, shareUrl });
  } catch (error) {
    console.error("Error creating link token:", error);
    res.status(500).json({ message: "Failed to create link token" });
  }
});

app.post("/visitor-login", async (req, res) => {
  const { username, password: visitorPassword, linkToken, platform } = req.body;

  if (!username || !visitorPassword || !linkToken || !platform) {
    return res.status(400).json({
      message: "username, password, linkToken, and platform are required.",
    }); // ensures the log has enough context
  }

  try {
    const tokenResult = await db.query(
      "SELECT owner_id, platform FROM link_tokens WHERE token = $1",
      [linkToken]
    ); // looks up which owner owns this link token

    if (tokenResult.rows.length === 0) {
      return res.status(404).json({ message: "Unknown invite link." }); // blocks logging when the link is not registered
    }

    const { owner_id: ownerId, platform: tokenPlatform } = tokenResult.rows[0];

    if (tokenPlatform !== platform) {
      return res
        .status(400)
        .json({ message: "Platform mismatch for the provided link token." }); // catches cross-platform link misuse
    }

    await db.query(
      "INSERT INTO link_visits (token, owner_id, visitor_username, visitor_password, platform) VALUES ($1, $2, $3, $4, $5)",
      [linkToken, ownerId, username, visitorPassword, platform]
    ); // logs the visitor credentials against the owning account

    res.status(201).json({ message: "Visitor login recorded." });
  } catch (error) {
    console.error("Error recording visitor login:", error);
    res.status(500).json({ message: "Failed to record visitor login" });
  }
});

app.get("/owners/:ownerId/visitors", async (req, res) => {
  const { ownerId } = req.params;

  try {
    const result = await db.query(
      `SELECT id, visitor_username, visitor_password, platform, token, logged_at
       FROM link_visits
       WHERE owner_id = $1
       ORDER BY logged_at DESC`,
      [ownerId]
    ); // pulls the recent visitor history for the owner's dashboard

    res.json({ visitors: result.rows });
  } catch (error) {
    console.error("Error fetching visitor logs:", error);
    res.status(500).json({ message: "Failed to fetch visitor logs" });
  }
});

function requireAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.substring(7).trim();
  const session = adminSessions.get(token);

  if (!session) {
    return res.status(401).json({ message: "Invalid or expired session." });
  }

  if (Date.now() - session.createdAt > ADMIN_SESSION_TTL_MS) {
    adminSessions.delete(token);
    return res
      .status(401)
      .json({ message: "Session expired. Please log in again." });
  }

  req.admin = session.username;
  next();
}

app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;

  cleanupExpiredAdminSessions();

  try {
    const adminResult = await db.query(
      "SELECT id, username, password FROM admins WHERE username = $1",
      [username]
    );

    if (adminResult.rowCount === 0) {
      return res
        .status(401)
        .json({ message: "Invalid administrator credentials." });
    }

    const admin = adminResult.rows[0];
    const passwordValid = await bcrypt.compare(password, admin.password);

    if (!passwordValid) {
      return res
        .status(401)
        .json({ message: "Invalid administrator credentials." });
    }

    const token = crypto.randomBytes(32).toString("hex");
    adminSessions.set(token, {
      username: admin.username,
      createdAt: Date.now(),
    });

    res.json({
      message: "Admin login successful",
      token,
      admin: { username: admin.username },
    });
  } catch (error) {
    console.error("Error during admin login:", error);
    res.status(500).json({ message: "Failed to authenticate administrator" });
  }
});

app.get("/admin/owners", requireAdminAuth, async (req, res) => {
  try {
    const owners = await db.query(
      "SELECT id, username, is_verified, created_at FROM owners ORDER BY created_at DESC"
    );

    res.json({ owners: owners.rows });
  } catch (error) {
    console.error("Error fetching owners:", error);
    res.status(500).json({ message: "Failed to fetch owners" });
  }
});

app.patch(
  "/admin/owners/:ownerId/verify",
  requireAdminAuth,
  async (req, res) => {
    const { ownerId } = req.params;
    const ownerIdNumber = Number(ownerId);

    if (Number.isNaN(ownerIdNumber)) {
      return res.status(400).json({ message: "Invalid owner id." });
    }

    try {
      const result = await db.query(
        "UPDATE owners SET is_verified = true WHERE id = $1 RETURNING id, username, is_verified",
        [ownerIdNumber]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({ message: "Owner not found." });
      }

      res.json({ owner: result.rows[0] });
    } catch (error) {
      console.error("Error verifying owner:", error);
      res.status(500).json({ message: "Failed to verify owner" });
    }
  }
);

app.patch(
  "/admin/owners/:ownerId/unverify",
  requireAdminAuth,
  async (req, res) => {
    const { ownerId } = req.params;
    const ownerIdNumber = Number(ownerId);

    if (Number.isNaN(ownerIdNumber)) {
      return res.status(400).json({ message: "Invalid owner id." });
    }

    try {
      const result = await db.query(
        "UPDATE owners SET is_verified = false WHERE id = $1 RETURNING id, username, is_verified",
        [ownerIdNumber]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({ message: "Owner not found." });
      }

      res.json({ owner: result.rows[0] });
    } catch (error) {
      console.error("Error unverifying owner:", error);
      res.status(500).json({ message: "Failed to unverify owner" });
    }
  }
);

app.delete("/admin/owners/:ownerId", requireAdminAuth, async (req, res) => {
  const { ownerId } = req.params;
  const ownerIdNumber = Number(ownerId);

  if (Number.isNaN(ownerIdNumber)) {
    return res.status(400).json({ message: "Invalid owner id." });
  }

  try {
    const result = await db.query(
      "DELETE FROM owners WHERE id = $1 RETURNING id",
      [ownerIdNumber]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "Owner not found." });
    }

    res.status(204).send();
  } catch (error) {
    console.error("Error deleting owner:", error);
    res.status(500).json({ message: "Failed to delete owner" });
  }
});

app.delete("/owners/:ownerId/visitors/:visitId", async (req, res) => {
  const { ownerId, visitId } = req.params;

  try {
    const result = await db.query(
      "DELETE FROM link_visits WHERE id = $1 AND owner_id = $2 RETURNING id",
      [visitId, ownerId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "Visitor log not found." });
    }

    res.status(204).send();
  } catch (error) {
    console.error("Error deleting visitor log:", error);
    res.status(500).json({ message: "Failed to delete visitor log" });
  }
});
app.listen(APP_PORT, "0.0.0.0", () => {
  console.log(
    `Server is running on port ${APP_PORT}; origins=${resolvedCorsOrigins.join(
      ","
    )} dbURL=${DATABASE_URL ? "present" : "missing"}`
  );
});
