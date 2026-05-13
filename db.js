require("dotenv").config();
const mysql = require("mysql2");

const REQUIRED_DB_ENV = ["DB_HOST", "DB_USER", "DB_PASS", "DB_NAME"];

for (const key of REQUIRED_DB_ENV) {
  if (!process.env[key]) {
    console.error(`Missing ENV variable: ${key}`);
    process.exit(1);
  }
}

const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,

  waitForConnections: true,
  connectionLimit: Number(process.env.DB_POOL_LIMIT) || 10,
  queueLimit: 0,

  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

// Optional pool events for logging
db.on("connection", () => {
  console.log("[DB] New connection created");
});

db.on("acquire", () => {
  console.log("[DB] Connection acquired");
});

db.on("release", () => {
  console.log("[DB] Connection released");
});

db.on("enqueue", () => {
  console.log("[DB] Waiting for available connection");
});

// Simple startup test
async function testDbConnection() {
  try {
    const [rows] = await db.promise().query("SELECT 1 AS ok");
    if (!rows?.length || rows[0].ok !== 1) {
      throw new Error("Test query failed");
    }
    console.log("[DB] Pool connected successfully");
  } catch (err) {
    console.error("[DB] Pool connection failed", {
      message: err.message,
      code: err.code,
      errno: err.errno,
      sqlState: err.sqlState,
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT) || 3306,
      user: process.env.DB_USER,
      database: process.env.DB_NAME,
    });
    throw err;
  }
}

// Graceful shutdown
async function closeDbPool() {
  try {
    await db.promise().end();
    console.log("[DB] Pool closed");
  } catch (err) {
    console.error("[DB] Error while closing pool:", err.message);
  }
}

module.exports = {
  db,
  testDbConnection,
  closeDbPool
};
