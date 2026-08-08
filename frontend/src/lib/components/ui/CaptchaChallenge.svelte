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
  import Button from './Button.svelte';
  import Spinner from './Spinner.svelte';

  export let provider: CaptchaProvider;
  export let siteKey: string;

  const dispatch = createEventDispatcher<{ verified: string; error: string; retry: void }>();
  let container: HTMLDivElement;
  let widgetId: string | number | undefined;
  let script: HTMLScriptElement | undefined;
  let createdScript = false;
  let destroyed = false;
  let failed = false;
  let status = 'Loading verification…';

  function fail(message: string) {
    failed = true;
    status = message;
    dispatch('error', message);
  }

  function verified(token: string) {
    failed = false;
    status = 'Verification complete.';
    dispatch('verified', token);
  }

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
    script.addEventListener('error', () => {
      if (script?.dataset.loaded !== 'true') script?.remove();
      reject(new Error('Verification couldn’t load.'));
    }, { once: true });
    if (!existing) {
      createdScript = true;
      document.head.append(script);
    }
    return promise;
  }

  onMount(async () => {
    try {
      const options = {
        sitekey: siteKey,
        callback: (token: string) => !destroyed && verified(token),
        'expired-callback': () => !destroyed && fail('Verification expired. Complete it again.'),
        'error-callback': () => !destroyed && fail('Verification failed. Try again.')
      };
      if (provider === CaptchaProvider.TURNSTILE) {
        await loadScript('https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit');
        if (destroyed) return;
        status = 'Complete the check below.';
        widgetId = window.turnstile!.render(container, options);
      } else if (provider === CaptchaProvider.RECAPTCHA) {
        await loadScript('https://www.google.com/recaptcha/api.js?render=explicit');
        if (destroyed) return;
        status = 'Complete the check below.';
        window.grecaptcha!.ready(() => {
          if (!destroyed) widgetId = window.grecaptcha!.render(container, options);
        });
      } else {
        fail('Verification isn’t available right now.');
      }
    } catch (error) {
      if (!destroyed) fail(error instanceof Error ? error.message : 'Verification couldn’t load.');
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

<div class="captcha-challenge">
  <p class="status-line" role={failed ? 'alert' : undefined}>
    {#if status.startsWith('Loading')}<Spinner />{/if}{status}
  </p>
  <div bind:this={container} class="captcha-container"></div>
  {#if failed}
    <Button type="button" variant="secondary" on:click={() => dispatch('retry')}>Try verification again</Button>
  {/if}
</div>
