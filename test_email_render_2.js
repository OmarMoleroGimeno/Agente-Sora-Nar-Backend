
const { render } = require('@vue-email/render');
const fs = require('fs');
const path = require('path');

(async () => {
    try {
        const templatePath = path.join(__dirname, 'templates/WelcomeEmail.vue');
        // This is what we want to verify: can we pass the path or content?
        // Most likely NO with just 'render'. 
        
        console.log('Trying to render with path...');
        // This will likely fail or return the path string if not handled.
        // But let's see. 
        // NOTE: Providing a component object is the standard way. 
        
        // Let's try to simulate a simple component if we can't load .vue
        const SimpleComponent = {
            template: `<div>Hello {{ link }}</div>`,
            props: ['link']
        };
        
        const html = await render(SimpleComponent, { link: 'https://example.com' });
        console.log('Rendered HTML:', html);
        
    } catch (e) {
        console.error('Error:', e);
    }
})();
