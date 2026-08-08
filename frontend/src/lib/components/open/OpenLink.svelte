<script lang="ts">
  import { afterUpdate, onDestroy, onMount } from 'svelte';
  import { accessEnvelope, getEnvelope, getEnvelopeMetadata, getRuntimeConfig } from '$lib/api/client';
  import { parseFragment } from '$lib/crypto/id';
  import { derivePasswordKeyInWorker } from '$lib/crypto/password';
  import { decryptEnvelope, deriveStorageKey, encodeStorageKey, validateEnvelopeMetadata } from '$lib/crypto/protocol';
  import { FeatureFlag, type EnvelopeMetadata } from '$lib/gen/securl/v1/envelope_pb.js';
  import { CaptchaProvider, type RuntimeConfig } from '$lib/gen/securl/v1/api_pb.js';
  import { normalizeServiceDomain } from '$lib/security/domain';
  import { validateDestination } from '$lib/security/url';
  import Panel from '../ui/Panel.svelte';
  import Spinner from '../ui/Spinner.svelte';
  import CaptchaGate from './CaptchaGate.svelte';
  import PasswordGate from './PasswordGate.svelte';
  import RedirectGate from './RedirectGate.svelte';
  import TerminalNotice from './TerminalNotice.svelte';

  type OpenState =
    | 'parsing'
    | 'metadata'
    | 'gate'
    | 'fetching'
    | 'consuming'
    | 'decrypting'
    | 'redirect-check'
    | 'terminal-error';
  type Gate = 'captcha' | 'password' | 'none';

  const controller = new AbortController();
  let state: OpenState = 'parsing';
  let gate: Gate = 'none';
  let config: RuntimeConfig | undefined;
  let metadata: EnvelopeMetadata | undefined;
  let idBytes: Uint8Array | undefined;
  let storageKey = '';
  let captchaToken = '';
  let password = '';
  let destination: URL | undefined;
  let errorMessage = '';
  let captchaEnabled = false;
  let passwordEnabled = false;
  let burnAfterRead = false;
  let root: HTMLElement;
  let focusedState: OpenState = state;


  onMount(async () => {
    try {
      state = 'parsing';
      idBytes = parseFragment(window.location.hash);
      const serviceDomain = normalizeServiceDomain(window.location.hostname);
      storageKey = encodeStorageKey(deriveStorageKey(idBytes, serviceDomain));
      state = 'metadata';
      const [runtimeConfig, metadataResponse] = await Promise.all([
        getRuntimeConfig(controller.signal),
        getEnvelopeMetadata(storageKey, controller.signal)
      ]);
      if (!metadataResponse.metadata) throw new Error('Envelope metadata is missing.');
      config = runtimeConfig;
      metadata = metadataResponse.metadata;
      validateEnvelopeMetadata(metadata);
      captchaEnabled = (metadata.featureFlags & FeatureFlag.CAPTCHA) !== 0;
      passwordEnabled = (metadata.featureFlags & FeatureFlag.PASSWORD) !== 0;
      burnAfterRead = (metadata.featureFlags & FeatureFlag.BURN_AFTER_READ) !== 0;
      if (captchaEnabled && config.captchaProvider === CaptchaProvider.NONE) {
        throw new Error('CAPTCHA protection is unavailable.');
      }
      state = 'gate';
      if (captchaEnabled) gate = 'captcha';
      else if (passwordEnabled) gate = 'password';
      else await retrieveAndDecrypt();
    } catch (error) {
      fail(error);
    }
  });

  onDestroy(() => {
    controller.abort();
    idBytes?.fill(0);
  });

  afterUpdate(() => {
    if (state === focusedState) return;
    focusedState = state;
    root.querySelector<HTMLElement>('h2[tabindex="-1"], h1[tabindex="-1"]')?.focus();
  });

  async function captchaVerified(token: string) {
    captchaToken = token;
    if (passwordEnabled) gate = 'password';
    else await retrieveAndDecrypt();
  }

  async function passwordSubmitted(value: string) {
    password = value;
    await retrieveAndDecrypt();
  }

  async function retrieveAndDecrypt() {
    if (!metadata || !config || !idBytes) return;
    let passwordKey: Uint8Array | undefined;
    let captchaKey: Uint8Array | undefined;
    try {
      if (passwordEnabled) {
        passwordKey = await derivePasswordKeyInWorker(password, metadata.password!.salt, controller.signal);
        password = '';
      }
      state = burnAfterRead ? 'consuming' : 'fetching';
      let envelope;
      if (captchaEnabled || burnAfterRead) {
        const response = await accessEnvelope(storageKey, captchaToken, controller.signal);
        envelope = response.envelope;
        captchaKey = response.captchaKey;
      } else {
        envelope = await getEnvelope(storageKey, controller.signal);
      }
      state = 'decrypting';
      const destinationText = decryptEnvelope(envelope, idBytes, { passwordKey, captchaKey });
      destination = validateDestination(destinationText);
      state = 'redirect-check';
      gate = 'none';
    } catch (error) {
      fail(error);
    } finally {
      passwordKey?.fill(0);
      captchaKey?.fill(0);
      if (state === 'redirect-check' || state === 'terminal-error') idBytes?.fill(0);
    }
  }

  function fail(error: unknown) {
    state = 'terminal-error';
    errorMessage = error instanceof Error ? error.message : 'This protected link could not be opened.';
  }
</script>

<main bind:this={root} class="shell" aria-busy={['parsing', 'metadata', 'fetching', 'consuming', 'decrypting'].includes(state)}>
  <header class="page-header">
    <p class="eyebrow">Protected link</p>
    <h1 tabindex="-1">Open a protected link</h1>
  </header>

  {#if state === 'terminal-error'}
    <TerminalNotice message={errorMessage} />
  {:else if state === 'gate' && gate === 'captcha' && config}
    <CaptchaGate
      provider={config.captchaProvider}
      siteKey={config.captchaSiteKey}
      on:verified={(event) => captchaVerified(event.detail)}
      on:error={(event) => fail(new Error(event.detail))}
    />
  {:else if state === 'gate' && gate === 'password'}
    <PasswordGate {burnAfterRead} on:submit={(event) => passwordSubmitted(event.detail)} />
  {:else if state === 'redirect-check' && destination && config}
    <RedirectGate {destination} enabled={config.safeBrowsingEnabled} />
  {:else}
    <Panel>
      <h2 tabindex="-1">
        {state === 'parsing' ? 'Reading the link secret' :
         state === 'metadata' ? 'Loading encrypted metadata' :
         state === 'consuming' ? 'Retrieving and deleting encrypted data' :
         state === 'decrypting' ? 'Decrypting in this browser' : 'Retrieving encrypted data'}
      </h2>
      <p class="status-line"><Spinner /> Please wait…</p>
    </Panel>
  {/if}
</main>
