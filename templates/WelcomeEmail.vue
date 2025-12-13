<template>
  <EHtml>
    <EHead />
    <EBody style="background-color: #f3f4f6; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; margin: 0; padding: 0;">
      
      <div style="display: none; max-height: 0; overflow: hidden;">
        Bienvenido a la plataforma digital de NAR. Active su acceso seguro aquí.
      </div>

      <EContainer style="max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);">
        
        <ESection style="background-color: #ffffff; padding: 40px 40px 20px; text-align: center; border-bottom: 1px solid #f0f0f0;">
            <EImg 
                src="../assets/img/logo-nar.png" 
                alt="NAR Valencia"
                style="margin: 0 auto 20px; width: 80px; height: auto; display: block;"
            />
        </ESection>

        <ESection style="padding: 40px 48px;">
            <EHeading style="margin: 0 0 24px; font-size: 24px; font-weight: 600; color: #111827; letter-spacing: -0.5px; text-align: center;">
                Bienvenido a NAR
            </EHeading>
            
            <EText style="margin: 0 0 24px; font-size: 16px; line-height: 1.6; color: #374151; text-align: left;">
                Hola,
            </EText>
            
            <EText style="margin: 0 0 24px; font-size: 16px; line-height: 1.6; color: #374151; text-align: left;">
                Su perfil ha sido pre-aprobado por nuestro equipo de administración. Le invitamos a activar su cuenta para acceder al sistema de gestión centralizado <strong>Aphelion</strong>.
            </EText>

            <EText style="margin: 0 0 32px; font-size: 16px; line-height: 1.6; color: #374151; text-align: left;">
                Por favor, haga clic en el siguiente botón para configurar sus credenciales y confirmar su acceso.
            </EText>

            <ESection style="text-align: center; margin: 32px 0;">
                <EButton 
                    :href="link"
                    style="background-color: #0f172a; color: #ffffff; padding: 14px 32px; border-radius: 6px; font-weight: 600; font-size: 15px; text-decoration: none; display: inline-block; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);"
                >
                    Activar Cuenta Corporativa
                </EButton>
            </ESection>

            <EHr style="border-color: #e5e7eb; margin: 32px 0 24px;" />

            <EText style="margin: 0; font-size: 13px; color: #6b7280; text-align: left; line-height: 1.5;">
                Si tiene problemas con el botón, copie y pegue el siguiente enlace en su navegador:<br>
                <ELink :href="link" style="color: #2563eb; text-decoration: underline;">{{ link }}</ELink>
            </EText>
        </ESection>

        <ESection style="background-color: #f9fafb; padding: 32px 40px; text-align: center; border-top: 1px solid #e5e7eb;">
            <EText style="margin: 0 0 16px; font-size: 12px; color: #9ca3af;">
                &copy; {{ new Date().getFullYear() }} NAR Valencia. Todos los derechos reservados.
            </EText>
            
            <EText style="margin: 0 0 8px; font-size: 12px; color: #9ca3af;">
                Este es un mensaje automático del sistema de seguridad. Por favor no responda a este correo.
            </EText>
            
            <EText style="margin: 0; font-size: 11px; color: #d1d5db; text-transform: uppercase; letter-spacing: 1px;">
                Powered by Aphelion Core
            </EText>
        </ESection>

      </EContainer>
      
      <ESection style="padding-bottom: 40px; text-align: center;">
         <EText style="font-size: 12px; color: #9ca3af;">
             Valencia, España
         </EText>
      </ESection>

    </EBody>
  </EHtml>
</template>

<script setup>
import { EBody, EContainer, EHead, EHeading, EHtml, EImg, ELink, ESection, EText, EButton, EHr } from 'vue-email';

defineProps({
  link: String,
});
</script>