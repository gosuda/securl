import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  // The SvelteKit plugin resolves `$app/tsconfig` and `#lib` for test transforms.
  plugins: [sveltekit()],
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node'
  }
});
