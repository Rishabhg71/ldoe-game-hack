const { execSync } = require('child_process');
const { context } = require('esbuild');

async function build() {
  try {
    // Run TypeScript compiler to check for errors
    execSync('npx tsc --noEmit', { stdio: 'inherit' });

    // If no errors, proceed with esbuild
    const ctx = await context({
      entryPoints: ['./src/index.ts'],
      bundle: true,
      platform: 'node',
      outfile: './dist/agent.js',
      sourcemap: true,
      target: 'esnext',
    });

    await ctx.watch();
  } catch (error) {
    // If tsc throws an error, exit the process
    process.exit(1);
  }
}

build().catch(() => process.exit(1));