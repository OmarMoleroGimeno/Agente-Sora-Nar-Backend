const WelcomeTemplate = (link) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bienvenido a NAR</title>
</head>
<body style="background-color: #f3f4f6; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; margin: 0; padding: 0;">
    
    <div style="display: none; max-height: 0; overflow: hidden;">
        Bienvenido a la plataforma digital de NAR. Active su acceso seguro aquí.
    </div>

    <div style="max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);">
        
        <!-- Header with Logo -->
        <div style="background-color: #ffffff; padding: 40px 40px 20px; text-align: center; border-bottom: 1px solid #f0f0f0;">
            <img 
                src="${process.env.SERVER_URL || 'http://localhost:3000'}/logo-nar.png" 
                alt="NAR Valencia"
                style="margin: 0 auto 20px; width: 150px; height: auto; display: block;"
            />
        </div>

        <!-- Main Content -->
        <div style="padding: 40px 48px;">
            <h1 style="margin: 0 0 24px; font-size: 24px; font-weight: 600; color: #111827; letter-spacing: -0.5px; text-align: center;">
                Bienvenido a NAR
            </h1>
            
            <p style="margin: 0 0 24px; font-size: 16px; line-height: 1.6; color: #374151; text-align: left;">
                Hola,
            </p>
            
            <p style="margin: 0 0 24px; font-size: 16px; line-height: 1.6; color: #374151; text-align: left;">
                Su perfil ha sido pre-aprobado por nuestro equipo de administración. Le invitamos a activar su cuenta para acceder al sistema de gestión centralizado <strong>Aphelion</strong>.
            </p>

            <p style="margin: 0 0 32px; font-size: 16px; line-height: 1.6; color: #374151; text-align: left;">
                Por favor, haga clic en el siguiente botón para configurar sus credenciales y confirmar su acceso.
            </p>

            <div style="text-align: center; margin: 32px 0;">
                <a href="${link}" style="background-color: #0f172a; color: #ffffff; padding: 14px 32px; border-radius: 6px; font-weight: 600; font-size: 15px; text-decoration: none; display: inline-block; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
                    Activar Cuenta Corporativa
                </a>
            </div>

            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 32px 0 24px;" />

            <p style="margin: 0; font-size: 13px; color: #6b7280; text-align: left; line-height: 1.5;">
                Si tiene problemas con el botón, copie y pegue el siguiente enlace en su navegador:<br>
                <a href="${link}" style="color: #2563eb; text-decoration: underline;">${link}</a>
            </p>
        </div>

        <!-- Footer -->
        <div style="background-color: #f9fafb; padding: 32px 40px; text-align: center; border-top: 1px solid #e5e7eb;">
            <p style="margin: 0 0 16px; font-size: 12px; color: #9ca3af;">
                &copy; ${new Date().getFullYear()} NAR Valencia. Todos los derechos reservados.
            </p>
            
            <p style="margin: 0 0 8px; font-size: 12px; color: #9ca3af;">
                Este es un mensaje automático del sistema de seguridad. Por favor no responda a este correo.
            </p>
            
            <p style="margin: 0; font-size: 11px; color: #d1d5db; text-transform: uppercase; letter-spacing: 1px;">
                Powered by Aphelion Core
            </p>
        </div>

    </div>
    
    <div style="padding-bottom: 40px; text-align: center;">
         <p style="font-size: 12px; color: #9ca3af; margin: 0;">
             Valencia, España
         </p>
    </div>

</body>
</html>
`;

module.exports = { WelcomeTemplate };
