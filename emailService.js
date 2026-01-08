const nodemailer = require('nodemailer');

const createTransporter = () => {
    // Configuración para Gmail u otro servicio SMTP
    // Asegúrate de tener estas variables en tu .env
    if (process.env.SMTP_HOST && process.env.SMTP_USER) {
        return nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: process.env.SMTP_PORT || 587,
            secure: process.env.SMTP_SECURE === 'true', // true para 465, false para otros
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
        });
    } else {
        // Fallback para desarrollo (Ethereal Email) o consola
        console.warn('⚠️ SMTP credentials not found. Using console Mock for emails.');
        return {
            sendMail: async (mailOptions) => {
                const link = mailOptions.html.match(/href="([^"]*)"/)?.[1] || 'No link found';
                console.log('\n\n');
                console.log('╔══════════════════════════════════════════════════════════════════════╗');
                console.log('║                   📧 MOCK EMAIL INTERCEPTED 📧                       ║');
                console.log('╠══════════════════════════════════════════════════════════════════════╣');
                console.log('║ To:      ' + mailOptions.to.padEnd(52) + '║');
                console.log('║ Subject: ' + mailOptions.subject.padEnd(52) + '║');
                console.log('╠══════════════════════════════════════════════════════════════════════╣');
                console.log('║  🔗 ACTION LINK (Click or Copy):                                     ║');
                console.log('║  ' + link.padEnd(68) + '║');
                console.log('╚══════════════════════════════════════════════════════════════════════╝');
                console.log('\n\n');
                return { messageId: 'mock-id' };
            }
        };
    }
};

const { WelcomeTemplate } = require('./templates/welcome');
const { ResetPasswordTemplate } = require('./templates/reset_password');

const sendWelcomeEmail = async (email, resetLink) => {
    const transporter = createTransporter();
    
    try {
        const htmlContent = WelcomeTemplate(resetLink);

        await transporter.sendMail({
            from: process.env.SMTP_FROM || '"Aphelion Security" <noreply@aphelion.com>',
            to: email,
            subject: 'Invitación a Aphelion - Configura tu Acceso',
            html: htmlContent,
        });
        console.log(`📨 Invitation email sent to ${email}`);
        return true;
    } catch (error) {
        console.error('❌ Error sending email:', error);
        return false;
    }
};


const sendResetPasswordEmail = async (email, resetLink) => {
    const transporter = createTransporter();
    
    try {
        const htmlContent = ResetPasswordTemplate(resetLink);

        await transporter.sendMail({
            from: process.env.SMTP_FROM || '"Aphelion Security" <noreply@aphelion.com>',
            to: email,
            subject: 'Restablecer Contraseña - NAR Valencia',
            html: htmlContent,
        });
        console.log(`📨 Reset password email sent to ${email}`);
        return true;
    } catch (error) {
        console.error('❌ Error sending reset email:', error);
        return false;
    }
};

module.exports = { sendWelcomeEmail, sendResetPasswordEmail };
