import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
    resolve: {
        alias: { '~': fileURLToPath(new URL('.', import.meta.url)) }
    },
    test: {
        globals: true,
        environment: 'node',
        include: ['lib/**/*.spec.ts'],
        // The auth SDK ships extensionless ESM imports, which Node refuses;
        // let Vite resolve it like the Next build does.
        server: { deps: { inline: [/@privasys//] } }
    }
});
