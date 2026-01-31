const nodemailer = require('nodemailer');

const createTransporter = () => {
    // Configuración para Gmail u otro servicio SMTP
    // Asegúrate de tener estas variables en tu .env
    // Configuración más robusta para SMTP
    const smtpHost = process.env.SMTP_HOST;
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    const smtpService = process.env.SMTP_SERVICE; // ej: 'gmail'
    const smtpPort = Number(process.env.SMTP_PORT) || 587;
    const smtpSecure = process.env.SMTP_SECURE === 'true' || smtpPort === 465;

    if (smtpUser && (smtpHost || smtpService)) {
        const config = {
            auth: {
                user: smtpUser,
                pass: smtpPass,
            }
        };

        if (smtpService || smtpHost === 'smtp.gmail.com') {
            config.service = smtpService || 'gmail';
        } else {
            config.host = smtpHost;
            config.port = smtpPort;
            config.secure = smtpSecure;
        }

        return nodemailer.createTransport(config);
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
    
    // Debug connection
    try {
        console.log('Testing SMTP Connection (Welcome Email)...');
        await transporter.verify();
        console.log('SMTP Connection OK');
    } catch (verifyError) {
        console.error('❌ SMTP Connection Failed:', verifyError);
        // Don't return false yet, let sendMail try and fail with more details or maybe succeed
    }
    
    try {
        const htmlContent = WelcomeTemplate(resetLink);

        await transporter.sendMail({
            from: process.env.SMTP_FROM || '"Sonar Security" <noreply@sonar.com>',
            to: email,
            subject: 'Invitación a Sonar - Configura tu Acceso',
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
            from: process.env.SMTP_FROM || '"Sonar Security" <noreply@sonar.com>',
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
