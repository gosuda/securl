import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

const apiBaseUrl = process.env.PUBLIC_SECURL_API_BASE_URL ?? '';
// URL.origin is always `scheme://host[:port]`, which is a valid CSP host source.
const apiOrigin = (apiBaseUrl === '' ? '' : new URL(apiBaseUrl).origin) as `${string}://${string}.${string}` | '';

export default defineConfig({
  plugins: [
    sveltekit({
      adapter: adapter({
        pages: '../internal/frontend/dist',
        assets: '../internal/frontend/dist',
        precompress: true,
        strict: true
      }),

      csp: {
        mode: 'hash',
        directives: {
          'default-src': ['self'],
          'base-uri': ['none'],
          'object-src': ['none'],
          'frame-ancestors': ['none'],
          'form-action': ['self'],
          'img-src': ['self', 'data:'],
          'style-src': ['self'],
          'font-src': ['self'],
          'script-src': [
            'self',
            'https://challenges.cloudflare.com',
            'https://www.google.com',
            'https://www.gstatic.com'
          ],
          'frame-src': [
            'https://challenges.cloudflare.com',
            'https://www.google.com'
          ],
          'connect-src': [
            'self',
            ...(apiOrigin === '' ? [] : [apiOrigin]),
            'https://challenges.cloudflare.com',
            'https://www.google.com'
          ]
        }
      }
    })
  ]
});
