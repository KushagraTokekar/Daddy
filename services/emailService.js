const nodemailer = require("nodemailer");

const smtpHost = process.env.EMAIL_HOST || "smtp.gmail.com";
const smtpPort = Number(process.env.EMAIL_PORT) || 587;
const smtpSecure = ["1", "true", "yes", "on"].includes(
  String(process.env.EMAIL_SECURE || "").trim().toLowerCase()
) || smtpPort === 465;

const transporter = nodemailer.createTransport({
  host: smtpHost,
  port: smtpPort,
  secure: smtpSecure,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  family: 4,
  connectionTimeout: Number(process.env.EMAIL_CONNECTION_TIMEOUT_MS) || 15000,
  greetingTimeout: Number(process.env.EMAIL_GREETING_TIMEOUT_MS) || 10000,
  socketTimeout: Number(process.env.EMAIL_SOCKET_TIMEOUT_MS) || 20000,
});

module.exports = transporter;
