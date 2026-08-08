import adapter from '@sveltejs/adapter-static';

const apiBaseUrl = process.env.PUBLIC_SECURL_API_BASE_URL ?? '';
const apiOrigin = apiBaseUrl === '' ? '' : new URL(apiBaseUrl).origin;

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
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
  }
};

export default config;
