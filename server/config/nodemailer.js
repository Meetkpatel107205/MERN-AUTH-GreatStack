
// 📦 Import Nodemailer library to handle email sending
import nodemailer from 'nodemailer';

// ✉️ Create and configure the transporter object using Brevo (formerly Sendinblue) SMTP service
const transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com', // Brevo's SMTP server
    port: 587,                    // 🔐 SMTP port (587 is commonly used for TLS: Transport Layer Security)
    auth: {
        user: process.env.SMTP_USER, // 🔑 SMTP username (stored in .env for security)
        pass: process.env.SMTP_PASS  // 🔒 SMTP password (stored in .env for security)
    }
});

// 🚀 Export the transporter to be used for sending emails throughout the application
export default transporter;
