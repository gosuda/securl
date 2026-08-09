<script lang="ts">
  import { afterUpdate, onDestroy, onMount } from 'svelte';
  import { accessEnvelope, getEnvelope, getEnvelopeMetadata, getRuntimeConfig } from '$lib/api/client';
  import { parseFragment } from '$lib/crypto/id';
  import { derivePasswordKey } from '$lib/crypto/password';
  import {
    IncorrectPasswordError,
    decryptEnvelope,
    encodeStorageKey,
    validateEnvelopeMetadata
  } from '$lib/crypto/protocol';
  import { deriveRootLinkKeys } from '$lib/crypto/root-key';
  import { FeatureFlag, type Envelope, type EnvelopeMetadata } from '$lib/gen/securl/v1/envelope_pb.js';
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
    | 'redirect-check'
    | 'terminal-error';
  type Gate = 'captcha' | 'password' | 'none';

  export let fragment: string;

  const controller = new AbortController();
  let state: OpenState = 'parsing';
  let gate: Gate = 'none';
  let config: RuntimeConfig | undefined;
  let metadata: EnvelopeMetadata | undefined;
  let idBytes: Uint8Array | undefined;
  let encryptionKeyMaterial: Uint8Array | undefined;
  let storageKey = '';
  let captchaToken = '';
  let password = '';
  let passwordError = '';
  let cachedEnvelope: Envelope | undefined;
  let cachedCaptchaKey: Uint8Array | undefined;
  let destination: URL | undefined;
  let destinationPromise: Promise<URL> | undefined;
  let initialRedirectDeadline = 0;
  let redirectDeadline = 0;
  let errorMessage = '';
  let captchaEnabled = false;
  let passwordEnabled = false;
  let burnAfterRead = false;
  let root: HTMLElement;
  let focusedState: OpenState = state;


  onMount(async () => {
    initialRedirectDeadline = Date.now() + 5000;
    try {
      state = 'parsing';
      idBytes = parseFragment(fragment);
      const serviceDomain = normalizeServiceDomain(window.location.hostname);
      state = 'metadata';
      const [runtimeConfig, keys] = await Promise.all([
        getRuntimeConfig(controller.signal),
        deriveRootLinkKeys(idBytes, serviceDomain, controller.signal)
      ]);
      storageKey = encodeStorageKey(keys.storageKey);
      keys.storageKey.fill(0);
      encryptionKeyMaterial = keys.encryptionKeyMaterial;
      const metadataResponse = await getEnvelopeMetadata(storageKey, controller.signal);
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
      else startOpening(initialRedirectDeadline);
    } catch (error) {
      fail(error);
    }
  });

  onDestroy(() => {
    controller.abort();
    clearLinkMaterial();
  });

  afterUpdate(() => {
    if (state === focusedState) return;
    focusedState = state;
    root.querySelector<HTMLElement>('h2[tabindex="-1"], h1[tabindex="-1"]')?.focus();
  });

  function captchaVerified(token: string) {
    captchaToken = token;
    if (passwordEnabled) gate = 'password';
    else startOpening(Date.now() + 5000);
  }

  function passwordSubmitted(value: string) {
    password = value;
    passwordError = '';
    startOpening(Date.now() + 5000);
  }

  function startOpening(deadline: number) {
    if (!metadata || !config || !idBytes || !encryptionKeyMaterial) return;
    redirectDeadline = deadline;
    gate = 'none';
    state = 'redirect-check';
    destination = undefined;
    destinationPromise = retrieveAndDecrypt();
    destinationPromise.then(
      (resolved) => (destination = resolved),
      (error) => {
        if (error instanceof IncorrectPasswordError) retryPassword();
        else fail(error);
      }
    );
  }

  async function loadEnvelope(): Promise<void> {
    if (cachedEnvelope) return;
    if (captchaEnabled || burnAfterRead) {
      const response = await accessEnvelope(storageKey, captchaToken, controller.signal);
      cachedEnvelope = response.envelope;
      cachedCaptchaKey = response.captchaKey.length === 0 ? undefined : response.captchaKey;
      captchaToken = '';
      return;
    }
    cachedEnvelope = await getEnvelope(storageKey, controller.signal);
  }

  async function retrieveAndDecrypt(): Promise<URL> {
    if (!idBytes || !encryptionKeyMaterial || !metadata) {
      throw new Error('Link key material is missing.');
    }
    let passwordKey: Uint8Array | undefined;
    try {
      const passwordKeyPromise = passwordEnabled
        ? derivePasswordKey(password, metadata.password!.salt, controller.signal)
        : Promise.resolve(undefined);
      password = '';

      if (burnAfterRead && passwordEnabled && !cachedEnvelope) {
        passwordKey = await passwordKeyPromise;
        await loadEnvelope();
      } else {
        const [derivedPasswordKey] = await Promise.all([passwordKeyPromise, loadEnvelope()]);
        passwordKey = derivedPasswordKey;
      }
      if (!cachedEnvelope) throw new Error('Envelope is missing required data.');

      const destinationText = decryptEnvelope(
        cachedEnvelope,
        idBytes,
        encryptionKeyMaterial,
        { passwordKey, captchaKey: cachedCaptchaKey }
      );
      const resolved = validateDestination(destinationText);
      clearLinkMaterial();
      return resolved;
    } finally {
      passwordKey?.fill(0);
    }
  }

  function retryPassword() {
    password = '';
    passwordError = 'Incorrect password. Try again.';
    destination = undefined;
    destinationPromise = undefined;
    redirectDeadline = 0;
    gate = 'password';
    state = 'gate';
  }

  function clearLinkMaterial() {
    cachedEnvelope?.ciphertext.fill(0);
    cachedEnvelope = undefined;
    cachedCaptchaKey?.fill(0);
    cachedCaptchaKey = undefined;
    encryptionKeyMaterial?.fill(0);
    encryptionKeyMaterial = undefined;
    idBytes?.fill(0);
    idBytes = undefined;
    password = '';
    captchaToken = '';
  }

  function fail(error: unknown) {
    state = 'terminal-error';
    clearLinkMaterial();
    const message = error instanceof Error ? error.message : '';
    if (message === 'Envelope not found.') {
      errorMessage = 'This link is no longer available.';
    } else if (passwordEnabled) {
      errorMessage = 'This link couldn’t be opened. Check the password or ask for a new link.';
    } else {
      errorMessage = 'This link couldn’t be opened. Ask for a new link.';
    }
  }
</script>

<main
  bind:this={root}
  class="shell"
  data-state={state}
  aria-busy={['parsing', 'metadata'].includes(state) || (state === 'redirect-check' && !destination)}
>
  <header class="page-header">
    <h1 tabindex="-1">Open a protected link</h1>
    <p>We’ll take you to the destination when it’s ready.</p>
  </header>

  {#if state === 'terminal-error'}
    <TerminalNotice message={errorMessage} />
  {:else if state === 'gate' && gate === 'captcha' && config}
    <CaptchaGate
      provider={config.captchaProvider}
      siteKey={config.captchaSiteKey}
      on:verified={(event) => captchaVerified(event.detail)}
    />
  {:else if state === 'gate' && gate === 'password'}
    <PasswordGate
      {burnAfterRead}
      error={passwordError}
      on:edit={() => (passwordError = '')}
      on:submit={(event) => passwordSubmitted(event.detail)}
    />
  {:else if state === 'redirect-check' && destinationPromise && config}
    <RedirectGate {destinationPromise} enabled={config.safeBrowsingEnabled} deadline={redirectDeadline} />
  {:else}
    <Panel>
      <h2 tabindex="-1">Opening your link</h2>
      <p class="status-line"><Spinner /> Please wait…</p>
    </Panel>
  {/if}
</main>
