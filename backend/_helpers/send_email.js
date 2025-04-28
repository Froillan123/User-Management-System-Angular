const nodemailer = require('nodemailer');
const config = require('../config.json');

// Determine environment
const env = process.env.NODE_ENV === 'production' ? 'production' : 'development';
const envConfig = config[env];

module.exports = sendEmail;

async function sendEmail({ to, subject, html, from = process.env.EMAIL_FROM || envConfig.emailFrom }) {
    try {
        // Get SMTP options from environment variables or config file
        const smtpOptions = {
            host: process.env.SMTP_HOST || envConfig.smtpOptions.host,
            port: process.env.SMTP_PORT || envConfig.smtpOptions.port,
            secure: process.env.SMTP_SECURE === 'false' ? false : 
                   (process.env.SMTP_SECURE === 'true' ? true : envConfig.smtpOptions.secure),
            auth: {
                user: process.env.SMTP_USER || envConfig.smtpOptions.auth.user,
                pass: process.env.SMTP_PASS || envConfig.smtpOptions.auth.pass
            }
        };

        // Log SMTP configuration (without password)
        console.log('Using SMTP configuration:', {
            host: smtpOptions.host,
            port: smtpOptions.port,
            secure: smtpOptions.secure,
            auth: { user: smtpOptions.auth.user, pass: '******' }
        });

        const transporter = nodemailer.createTransport(smtpOptions);
        
        // Verify connection configuration
        await transporter.verify();
        
        // Clean html content - remove potentially dangerous elements
        const safeHtml = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                             .replace(/javascript:/gi, 'removed:');
        
        // Extract plain text from HTML
        const plainText = safeHtml.replace(/<[^>]*>?/gm, '')
                               .replace(/\s+/g, ' ')
                               .trim();
        
        // Build the email with security headers
        const mailOptions = {
            from: {
                name: 'User-Management',
                address: from
            },
            to,
            subject,
            text: plainText,
            html: safeHtml,
            headers: {
                'X-Priority': '1',
                'X-MSMail-Priority': 'High',
                'Importance': 'High',
                'X-Mailer': 'User-Management Authentication System',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Strict-Transport-Security': 'max-age=31536000',
                'X-XSS-Protection': '1; mode=block'
            },
            // Accessibility and security additions
            contentType: 'text/html; charset=utf-8',
            dsn: {
                id: true,
                return: 'headers',
                notify: ['failure', 'delay'],
                recipient: from
            }
        };
        
        console.log(`Sending email to ${to} with subject "${subject}"`);
        const result = await transporter.sendMail(mailOptions);
        console.log(`Email sent successfully to ${to}. Message ID: ${result.messageId}`);
        return result;
    } catch (error) {
        console.error('Error sending email:', error);
        // Don't throw the error - just log it so the app doesn't crash
        // This allows registration to continue even if email sending fails
        return { error: error.message, messageId: null, success: false };
    }
}