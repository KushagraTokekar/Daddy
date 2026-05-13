const https = require("https");

const transporter = {
  sendMail: async ({ from, to, subject, text }) => {
    const payload = JSON.stringify({
      sender: { email: from },
      to: [{ email: to }],
      subject,
      textContent: text,
    });

    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: "api.brevo.com",
          path: "/v3/smtp/email",
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "api-key": process.env.BREVO_API_KEY,
            "Content-Length": Buffer.byteLength(payload),
          },
        },
        (res) => {
          let data = "";
          res.on("data", (c) => (data += c));
          res.on("end", () => {
            const parsed = JSON.parse(data);
            if (res.statusCode >= 400) return reject(new Error(parsed.message || "Brevo API error"));
            resolve({ messageId: parsed.messageId });
          });
        }
      );
      req.on("error", reject);
      req.write(payload);
      req.end();
    });
  },
};

module.exports = transporter;
