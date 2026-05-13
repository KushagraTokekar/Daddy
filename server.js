require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const generateOTP = require("./utils/generateOTP");
const transporter = require("./services/emailService");
const { db, testDbConnection, closeDbPool } = require("./db");

// ─── ENV VALIDATION ─────────────────────────────

const REQUIRED_ENV = ["JWT_SECRET", "BREVO_API_KEY", "EMAIL_FROM", "DB_HOST", "DB_USER", "DB_PASS", "DB_NAME"];
const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]?.toString().trim());

console.log("[ENV_CHECK]", {
  nodeEnv: process.env.NODE_ENV || "undefined",
  requiredPresent: REQUIRED_ENV.filter((key) => !missingEnv.includes(key)),
  missing: missingEnv,
});

if (missingEnv.length) {
  console.error(`[ENV_ERROR] Missing required ENV variables: ${missingEnv.join(", ")}`);
  process.exit(1);
}

// ─── CONFIG ─────────────────────────────────────

const PORT = process.env.PORT || 3000;
const dbc = db.promise();

const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:8081",
  "http://localhost:19006",
  "http://localhost:3000",
  "http://127.0.0.1:8081",
  "http://127.0.0.1:19006",
  "http://10.0.2.2:8081",
  "http://10.0.2.2:19006",
];

const allowedOrigins = new Set(
  [
    ...DEFAULT_ALLOWED_ORIGINS,
    ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL.trim()] : []),
    ...(process.env.CORS_ORIGINS
      ? process.env.CORS_ORIGINS.split(",").map((o) => o.trim()).filter(Boolean)
      : []),
  ].filter(Boolean)
);

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

// ─── EXPRESS INIT ───────────────────────────────

const app = express();
app.set("trust proxy", 1);
app.use(cors(corsOptions));
app.use(express.json());
app.use(helmet());
app.use(compression());

// ─── RATE LIMITERS ──────────────────────────────

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: "Too many login attempts. Try again later." });
const otpLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3, message: "Too many OTP requests." });
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: "Too many requests. Try again later." });

// ─── VALIDATORS ─────────────────────────────────

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
const validateEmail = (e) => emailRegex.test(e);
const validatePassword = (p) => passwordRegex.test(p);

// ─── ERROR HELPERS ──────────────────────────────

function logError(scope, err, extra = {}) {
  console.error(`[${scope}]`, err?.stack || err, extra);
}

function sendSilentError(res, statusCode, scope, err, message = "Server error") {
  if (err) logError(scope, err);
  return res.status(statusCode).json({ success: false, message });
}

// ─── TOKEN ──────────────────────────────────────

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, superuser: user.superuser, role: user.superuser ? "super_admin" : "user", iss: "library-locator", aud: "mobile-app" },
    process.env.JWT_SECRET,
    { expiresIn: "8h" }
  );
}

// ─── AUTH MIDDLEWARE ─────────────────────────────

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ success: false, message: "Missing token" });
  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, { issuer: "library-locator", audience: "mobile-app" });
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") return res.status(401).json({ success: false, message: "Token expired" });
    return res.status(401).json({ success: false, message: "Invalid token" });
  }
}

function requireSuperAdmin(req, res, next) {
  if (!req.user || Number(req.user.superuser) !== 1) return res.status(403).json({ success: false, message: "Super admin access required" });
  next();
}

// ─── HEALTH CHECK ───────────────────────────────

app.get("/health", (_, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

// ─── SIGNUP ─────────────────────────────────────

app.post("/signup", generalLimiter, async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password;
    const username = req.body.username?.trim() || email;

    if (!email || !password) return res.status(400).json({ success: false, message: "Missing email or password" });
    if (!validateEmail(email)) return res.status(400).json({ success: false, message: "Invalid email format" });
    if (!validatePassword(password)) return res.status(400).json({ success: false, message: "Weak password" });

    const [rows] = await dbc.query("SELECT * FROM yii_users WHERE email=?", [email]);

    if (rows.length) {
      const existing = rows[0];
      if (existing.email_verified) return res.status(409).json({ success: false, message: "Email already registered" });
      if (existing.otp_expiry && new Date(existing.otp_expiry) > new Date()) {
        return res.status(429).json({ success: false, message: "OTP already sent. Please wait before requesting again." });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const hashedOTP = await bcrypt.hash(otp.toString(), 10);
    const expiry = new Date(Date.now() + 3 * 60 * 1000);
    const activkey = crypto.randomBytes(32).toString("hex");

    let insertId;
    if (rows.length) {
      await dbc.query(
        "UPDATE yii_users SET username=?, password=?, otp_code=?, otp_expiry=?, otp_attempts=0 WHERE email=?",
        [username.substring(0, 20), hashedPassword, hashedOTP, expiry, email]
      );
      insertId = rows[0].id;
    } else {
      const [result] = await dbc.query(
        "INSERT INTO yii_users (username, email, password, activkey, status, superuser, otp_code, otp_expiry, email_verified, otp_attempts, login_attempts, lock_until) VALUES (?, ?, ?, ?, 1, 0, ?, ?, false, 0, 0, NULL)",
        [username.substring(0, 20), email, hashedPassword, activkey, hashedOTP, expiry]
      );
      insertId = result.insertId;
    }

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
        to: email,
        subject: "Library Locator Verification Code",
        text: `Your verification code is ${otp}`,
      });
    } catch (emailError) {
      await dbc.query("DELETE FROM yii_users WHERE id=?", [insertId]);
      return sendSilentError(res, 500, "SIGNUP_EMAIL", emailError, "Email delivery failed");
    }

    return res.json({ success: true });
  } catch (err) {
    return sendSilentError(res, 500, "SIGNUP", err);
  }
});

// ─── VERIFY EMAIL ───────────────────────────────

app.post("/verify-email", generalLimiter, async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const otp = req.body.otp;
    if (!email || !otp) return res.status(400).json({ success: false, message: "Missing email or OTP" });

    const [rows] = await dbc.query("SELECT * FROM yii_users WHERE email=?", [email]);
    if (!rows.length) return res.status(404).json({ success: false, message: "User not found" });

    const user = rows[0];
    if (user.email_verified) return res.status(400).json({ success: false, message: "Email already verified" });
    if (!user.otp_code || !user.otp_expiry) return res.status(400).json({ success: false, message: "OTP not available" });
    if (user.otp_attempts >= 5) return res.status(403).json({ success: false, message: "Too many OTP attempts" });
    if (new Date(user.otp_expiry) < new Date()) return res.status(410).json({ success: false, message: "OTP expired" });

    const validOTP = await bcrypt.compare(otp.toString(), user.otp_code);
    if (!validOTP) {
      await dbc.query("UPDATE yii_users SET otp_attempts=otp_attempts+1 WHERE email=?", [email]);
      return res.status(401).json({ success: false, message: "Invalid OTP" });
    }

    await dbc.query("UPDATE yii_users SET email_verified=true, otp_code=NULL, otp_expiry=NULL, otp_attempts=0 WHERE email=?", [email]);
    return res.json({ success: true, token: generateToken(user) });
  } catch (err) {
    return sendSilentError(res, 500, "VERIFY", err);
  }
});

// ─── LOGIN ──────────────────────────────────────

app.post("/login", loginLimiter, async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password;
    if (!email || !password) return res.status(400).json({ success: false, message: "Missing email or password" });

    const [rows] = await dbc.query("SELECT * FROM yii_users WHERE email=?", [email]);
    if (!rows.length) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const user = rows[0];
    if (!user.email_verified) return res.status(403).json({ success: false, message: "Email not verified" });
    if (user.lock_until && new Date(user.lock_until) > new Date()) return res.status(403).json({ success: false, message: "Account locked" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      const attempts = (user.login_attempts || 0) + 1;
      if (attempts >= 5) {
        await dbc.query("UPDATE yii_users SET login_attempts=?, lock_until=? WHERE email=?", [attempts, new Date(Date.now() + 15 * 60 * 1000), email]);
      } else {
        await dbc.query("UPDATE yii_users SET login_attempts=? WHERE email=?", [attempts, email]);
      }
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    await dbc.query("UPDATE yii_users SET login_attempts=0, lock_until=NULL WHERE email=?", [email]);
    return res.json({ success: true, token: generateToken(user) });
  } catch (err) {
    return sendSilentError(res, 500, "LOGIN", err);
  }
});

// ─── RESEND OTP ─────────────────────────────────

app.post("/resend-otp", otpLimiter, async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    if (!email) return res.status(400).json({ success: false, message: "Missing email" });

    const [rows] = await dbc.query("SELECT * FROM yii_users WHERE email=?", [email]);
    if (!rows.length) return res.status(404).json({ success: false, message: "User not found" });
    if (rows[0].email_verified) return res.status(400).json({ success: false, message: "Email already verified" });

    const otp = generateOTP();
    const hashedOTP = await bcrypt.hash(otp.toString(), 10);
    const expiry = new Date(Date.now() + 3 * 60 * 1000);

    const [updateResult] = await dbc.query(
      "UPDATE yii_users SET otp_code=?, otp_expiry=?, otp_attempts=0 WHERE email=? AND email_verified=false",
      [hashedOTP, expiry, email]
    );
    if (!updateResult.affectedRows) return res.status(404).json({ success: false, message: "User not found" });

    await transporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: "Library Locator Verification Code",
      text: `Your verification code is ${otp}`,
    });

    return res.json({ success: true });
  } catch (err) {
    return sendSilentError(res, 500, "RESEND", err);
  }
});

// ─── FORGOT PASSWORD ────────────────────────────

app.post("/forgot-password", generalLimiter, async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    if (!email) return res.status(400).json({ success: false, message: "Missing email" });

    const [rows] = await dbc.query("SELECT * FROM yii_users WHERE email=?", [email]);
    if (!rows.length) return res.status(404).json({ success: false, message: "User not found" });
    if (!rows[0].email_verified) return res.status(403).json({ success: false, message: "Email not verified" });

    const otp = generateOTP();
    const hashedOTP = await bcrypt.hash(otp.toString(), 10);
    const expiry = new Date(Date.now() + 3 * 60 * 1000);

    await dbc.query("UPDATE yii_users SET otp_code=?, otp_expiry=?, otp_attempts=0 WHERE email=?", [hashedOTP, expiry, email]);

    await transporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset OTP",
      text: `Your password reset code is ${otp}`,
    });

    return res.json({ success: true });
  } catch (err) {
    return sendSilentError(res, 500, "FORGOT", err);
  }
});

// ─── RESET PASSWORD ─────────────────────────────

app.post("/reset-password", generalLimiter, async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const otp = req.body.otp;
    const newPassword = req.body.newPassword;

    if (!email || !otp || !newPassword) return res.status(400).json({ success: false, message: "Missing fields" });
    if (!validatePassword(newPassword)) return res.status(400).json({ success: false, message: "Weak password" });

    const [rows] = await dbc.query("SELECT * FROM yii_users WHERE email=?", [email]);
    if (!rows.length) return res.status(404).json({ success: false, message: "User not found" });

    const user = rows[0];
    if (user.otp_attempts >= 5) return res.status(403).json({ success: false, message: "Too many OTP attempts" });
    if (!user.otp_code || !user.otp_expiry) return res.status(400).json({ success: false, message: "OTP not available" });
    if (new Date(user.otp_expiry) < new Date()) return res.status(410).json({ success: false, message: "OTP expired" });

    const validOTP = await bcrypt.compare(otp.toString(), user.otp_code);
    if (!validOTP) {
      await dbc.query("UPDATE yii_users SET otp_attempts=otp_attempts+1 WHERE email=?", [email]);
      return res.status(401).json({ success: false, message: "Invalid OTP" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await dbc.query("UPDATE yii_users SET password=?, otp_code=NULL, otp_expiry=NULL, otp_attempts=0 WHERE email=?", [hashed, email]);
    return res.json({ success: true });
  } catch (err) {
    return sendSilentError(res, 500, "RESET_PASSWORD", err);
  }
});

// ─── CHANGE PASSWORD ────────────────────────────

app.post("/change-password", requireAuth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ success: false, message: "Missing password fields" });
    if (!validatePassword(newPassword)) return res.status(400).json({ success: false, message: "Weak password" });

    const [rows] = await dbc.query("SELECT password FROM yii_users WHERE id=?", [req.user.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: "User not found" });

    const valid = await bcrypt.compare(oldPassword, rows[0].password);
    if (!valid) return res.status(401).json({ success: false, message: "Incorrect old password" });

    const hashed = await bcrypt.hash(newPassword, 10);
    await dbc.query("UPDATE yii_users SET password=? WHERE id=?", [hashed, req.user.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendSilentError(res, 500, "CHANGE_PASSWORD", err);
  }
});

// ─── DELETE ACCOUNT ─────────────────────────────

app.post("/delete-account", requireAuth, async (req, res) => {
  try {
    if (Number(req.user.superuser) === 1) return res.status(403).json({ success: false, message: "Super admin account cannot be deleted" });

    const { password } = req.body;
    if (!password) return res.status(400).json({ success: false, message: "Password required" });

    const [rows] = await dbc.query("SELECT password FROM yii_users WHERE id=?", [req.user.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: "User not found" });

    const valid = await bcrypt.compare(password, rows[0].password);
    if (!valid) return res.status(401).json({ success: false, message: "Incorrect password" });

    const [result] = await dbc.query("DELETE FROM yii_users WHERE id=? LIMIT 1", [req.user.id]);
    if (!result.affectedRows) return res.status(404).json({ success: false, message: "User already deleted or not found" });

    return res.json({ success: true });
  } catch (err) {
    return sendSilentError(res, 500, "DELETE_ACCOUNT", err);
  }
});

// ─── SEARCH ─────────────────────────────────────

app.get("/search", requireAuth, async (req, res) => {
  try {
    const term = req.query.book?.trim();
    if (!term) return res.status(400).json({ success: false, message: "Missing search term" });

    const pattern = `%${term}%`;
    const [results] = await dbc.query(
      "SELECT bookname, bookauthor, bookpublisher, bookshelf, oldbookid, subject FROM yii_book JOIN yii_subject USING (idsubject) WHERE bookname LIKE ? OR bookauthor LIKE ? ORDER BY bookname ASC LIMIT 50",
      [pattern, pattern]
    );
    console.log(`[SEARCH] term="${term}" results=${results.length}`);
    return res.json({ success: true, data: results });
  } catch (err) {
    if (err.code === "ER_BAD_FIELD_ERROR") return res.status(500).json({ success: false, message: "Database schema mismatch: oldbookid column not found" });
    return sendSilentError(res, 500, "SEARCH", err);
  }
});

// ─── BOOKS PAGINATION ───────────────────────────

app.get("/books", requireAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    if (page < 1) return res.status(400).json({ success: false, message: "Invalid page value" });
    if (limit < 1) return res.status(400).json({ success: false, message: "Invalid limit value" });

    const offset = (page - 1) * limit;
    const [results] = await dbc.query(
      "SELECT bookname, bookauthor, bookpublisher, bookshelf, oldbookid, subject FROM yii_book JOIN yii_subject USING (idsubject) ORDER BY bookname ASC LIMIT ? OFFSET ?",
      [limit, offset]
    );
    console.log(`[BOOKS] page=${page} limit=${limit} results=${results.length}`);
    return res.json({ success: true, data: results, page, limit });
  } catch (err) {
    if (err.code === "ER_BAD_FIELD_ERROR") return res.status(500).json({ success: false, message: "Database schema mismatch: oldbookid column not found" });
    return sendSilentError(res, 500, "BOOKS", err);
  }
});

// ─── ADMIN: GET ALL USERS ────────────────────────

app.get("/admin/users", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const [rows] = await dbc.query("SELECT id, email, superuser, email_verified, create_at FROM yii_users ORDER BY id DESC");
    return res.json({ success: true, users: rows });
  } catch (err) {
    return sendSilentError(res, 500, "ADMIN_USERS", err);
  }
});

// ─── ADMIN: DELETE USER ──────────────────────────

app.post("/admin/delete-user", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ success: false, message: "Missing userId" });

    const [result] = await dbc.query("DELETE FROM yii_users WHERE id=? LIMIT 1", [userId]);
    if (!result.affectedRows) return res.status(404).json({ success: false, message: "User not found" });

    return res.json({ success: true });
  } catch (err) {
    return sendSilentError(res, 500, "ADMIN_DELETE_USER", err);
  }
});

// ─── ADMIN: PROMOTE USER ─────────────────────────

app.post("/admin/promote-user", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ success: false, message: "Missing userId" });

    const [result] = await dbc.query("UPDATE yii_users SET superuser=1 WHERE id=?", [userId]);
    if (!result.affectedRows) return res.status(404).json({ success: false, message: "User not found" });

    return res.json({ success: true });
  } catch (err) {
    return sendSilentError(res, 500, "ADMIN_PROMOTE_USER", err);
  }
});

// ─── CLEANUP JOB ─────────────────────────────────

setInterval(async () => {
  try {
    const [result] = await dbc.query("DELETE FROM yii_users WHERE email_verified=false AND otp_expiry IS NOT NULL AND otp_expiry < NOW()");
    if (result.affectedRows) console.log(`[CLEANUP] Deleted ${result.affectedRows} expired unverified users`);
  } catch (err) {
    logError("CLEANUP", err);
  }
}, 10 * 60 * 1000);

// ─── 404 HANDLER ────────────────────────────────

app.use((req, res) => res.status(404).json({ success: false, message: "Route not found" }));

// ─── GLOBAL ERROR HANDLER ───────────────────────

app.use((err, req, res, next) => {
  logError("GLOBAL_ERROR", err);
  if (res.headersSent) return next(err);
  return res.status(err.status || 500).json({ success: false, message: "Server error" });
});

// ─── SERVER START ───────────────────────────────

async function startServer() {
  try {
    await testDbConnection();
    app.listen(PORT, "0.0.0.0", () => console.log(`[SERVER RUNNING] http://0.0.0.0:${PORT}`));
  } catch (err) {
    logError("SERVER_START", err);
    process.exit(1);
  }
}

startServer();

process.on("unhandledRejection", (reason) => logError("UNHANDLED_REJECTION", reason));
process.on("uncaughtException", async (err) => { logError("UNCAUGHT_EXCEPTION", err); await closeDbPool(); process.exit(1); });
process.on("SIGINT", async () => { await closeDbPool(); process.exit(0); });
process.on("SIGTERM", async () => { await closeDbPool(); process.exit(0); });
