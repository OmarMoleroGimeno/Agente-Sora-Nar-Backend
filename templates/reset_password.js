
const ResetPasswordTemplate = (link) => `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recuperar Contraseña</title>
</head>
<body style="background-color: #f3f4f6; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; margin: 0; padding: 0;">
    
    <div style="max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);">
        
        <!-- Header with Logo -->
        <div style="background-color: #ffffff; padding: 40px 40px 20px; text-align: center; border-bottom: 1px solid #f0f0f0;">
             <img 
                src="${process.env.SERVER_URL}/logo-nar.png" 
                alt="NAR Valencia"
                style="margin: 0 auto 20px; width: 80px; height: auto; display: block;"
            />
        </div>

        <!-- Main Content -->
        <div style="padding: 40px 48px;">
            <h1 style="margin: 0 0 24px; font-size: 24px; font-weight: 600; color: #111827; letter-spacing: -0.5px; text-align: center;">
                Recuperación de Contraseña
            </h1>
            
            <p style="margin: 0 0 24px; font-size: 16px; line-height: 1.6; color: #374151; text-align: left;">
                Hola,
            </p>
            
            <p style="margin: 0 0 24px; font-size: 16px; line-height: 1.6; color: #374151; text-align: left;">
                Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en <strong>Aphelion</strong>.
            </p>

            <p style="margin: 0 0 32px; font-size: 16px; line-height: 1.6; color: #374151; text-align: left;">
                Haz clic en el botón de abajo para crear una nueva contraseña:
            </p>

            <div style="text-align: center; margin: 32px 0;">
                <a href="${link}" style="background-color: #0f172a; color: #ffffff; padding: 14px 32px; border-radius: 6px; font-weight: 600; font-size: 15px; text-decoration: none; display: inline-block; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
                    Restablecer Contraseña
                </a>
            </div>

            <p style="margin: 0 0 24px; font-size: 14px; line-height: 1.6; color: #6b7280; text-align: left;">
                Si no solicitaste este cambio, puedes ignorar este correo de forma segura.
            </p>

            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 32px 0 24px;" />

            <p style="margin: 0; font-size: 13px; color: #6b7280; text-align: left; line-height: 1.5;">
                O copia y pega este enlace:<br>
                <a href="${link}" style="color: #2563eb; text-decoration: underline;">${link}</a>
            </p>
        </div>

        <div style="background-color: #f9fafb; padding: 32px 40px; text-align: center; border-top: 1px solid #e5e7eb;">
             <p style="margin: 0; font-size: 11px; color: #d1d5db; text-transform: uppercase; letter-spacing: 1px;">
                Powered by Aphelion Core
            </p>
        </div>
    </div>
</body>
</html>
`;

module.exports = { ResetPasswordTemplate };
