<script lang="ts" context="module">
  declare global {
    interface Window {
      turnstile?: {
        render(element: HTMLElement, options: Record<string, unknown>): string;
        remove(widgetId: string | number): void;
      };
      grecaptcha?: {
        ready(callback: () => void): void;
        render(element: HTMLElement, options: Record<string, unknown>): number;
        reset(widgetId: string | number): void;
      };
    }
  }
</script>

<script lang="ts">
  import { createEventDispatcher, onDestroy, onMount } from 'svelte';
  import { CaptchaProvider } from '$lib/gen/securl/v1/api_pb.js';
  import Panel from '../ui/Panel.svelte';
  import Spinner from '../ui/Spinner.svelte';

  export let provider: CaptchaProvider;
  export let siteKey: string;

  const dispatch = createEventDispatcher<{ verified: string; error: string }>();
  let container: HTMLDivElement;
  let widgetId: string | number | undefined;
  let script: HTMLScriptElement | undefined;
  let createdScript = false;
  let destroyed = false;
  let status = 'Loading CAPTCHA…';

  function loadScript(source: string): Promise<void> {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${source}"]`);
    if (existing?.dataset.loaded === 'true') return Promise.resolve();
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    script = existing ?? document.createElement('script');
    script.src = source;
    script.async = true;
    script.defer = true;
    script.addEventListener('load', () => {
      script!.dataset.loaded = 'true';
      resolve();
    }, { once: true });
    script.addEventListener(
      'error',
      () => reject(new Error('CAPTCHA script failed to load.')),
      { once: true }
    );
    if (!existing) {
      createdScript = true;
      document.head.append(script);
    }
    return promise;
  }

  onMount(async () => {
    try {
      if (provider === CaptchaProvider.TURNSTILE) {
        await loadScript('https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit');
        if (destroyed) return;
        status = 'Complete the Cloudflare Turnstile challenge.';
        widgetId = window.turnstile!.render(container, {
          sitekey: siteKey,
          callback: (token: string) => !destroyed && dispatch('verified', token),
          'error-callback': () => !destroyed && dispatch('error', 'CAPTCHA verification failed.')
        });
      } else if (provider === CaptchaProvider.RECAPTCHA) {
        await loadScript('https://www.google.com/recaptcha/api.js?render=explicit');
        if (destroyed) return;
        status = 'Complete the Google reCAPTCHA challenge.';
        window.grecaptcha!.ready(() => {
          if (destroyed) return;
          widgetId = window.grecaptcha!.render(container, {
            sitekey: siteKey,
            callback: (token: string) => !destroyed && dispatch('verified', token),
            'error-callback': () => !destroyed && dispatch('error', 'CAPTCHA verification failed.')
          });
        });
      } else {
        if (!destroyed) dispatch('error', 'CAPTCHA protection is unavailable.');
      }
    } catch (error) {
      if (!destroyed) dispatch('error', error instanceof Error ? error.message : 'CAPTCHA failed to load.');
    }
  });

  onDestroy(() => {
    destroyed = true;
    if (createdScript && script?.dataset.loaded !== 'true') script?.remove();
    if (provider === CaptchaProvider.TURNSTILE && widgetId !== undefined) {
      window.turnstile?.remove(widgetId);
    }
    if (provider === CaptchaProvider.RECAPTCHA && widgetId !== undefined) {
      window.grecaptcha?.reset(widgetId);
    }
  });
</script>

<Panel>
  <h2 tabindex="-1">Human verification required</h2>
  <p>{status}</p>
  {#if status.startsWith('Loading')}<Spinner />{/if}
  <div bind:this={container} class="captcha-container"></div>
</Panel>
