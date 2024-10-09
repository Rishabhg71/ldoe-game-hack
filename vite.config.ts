import { defineConfig } from 'vite'

export default defineConfig({
    build: {
        lib: {
            entry: 'src/main.ts',
            formats: ['cjs'],
            fileName: () => 'agent.js'
        },
        rollupOptions: {
            output: {
                format: 'cjs'
            }
        },
        minify: false,
        sourcemap: true,
        watch: {}
    }
})