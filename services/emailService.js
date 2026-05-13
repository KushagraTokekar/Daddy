const { Resend } = require("resend");

const resend = new Resend(process.env.EMAIL_PASS);

const transporter = {
  sendMail: async ({ from, to, subject, text }) => {
    const { data, error } = await resend.emails.send({ from, to, subject, text });
    if (error) throw new Error(error.message);
    return { messageId: data.id };
  },
};

module.exports = transporter;
