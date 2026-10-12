import { defineEnvVars } from '@sveltejs/kit/env';

// An empty API base URL means the API is served from the page origin.
export const variables = defineEnvVars({
	PUBLIC_SECURL_API_BASE_URL: { public: true, schema: (input) => input ?? '' }
});
