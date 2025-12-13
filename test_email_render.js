
const { render } = require('@vue-email/render');
const fs = require('fs');
const path = require('path');

(async () => {
    try {
        console.log('Testing render...');
        const templatePath = path.join(__dirname, 'templates/WelcomeEmail.vue');
        const templateContent = fs.readFileSync(templatePath, 'utf-8');
        
        // Hypothetical usage: pass content directly? 
        // Note: usage of @vue-email/render usually requires a deeper integration or import.
        // But let's see if we can use the compiled output.
        
        console.log('Reading file success.');
        
        // Just printing this to check if require worked.
        console.log('Render function loaded:', typeof render);

    } catch (e) {
        console.error('Error:', e);
    }
})();
