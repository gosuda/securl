<script lang="ts">
  import { create } from '@bufbuild/protobuf';
  import { afterUpdate, onDestroy, onMount } from 'svelte';
  import { getRuntimeConfig, submitEnvelope } from '$lib/api/client';
  import {
    CreateConflictError,
    createWithCollisionRetries
  } from '$lib/api/create';
  import { encodeId, generateIdBytes } from '$lib/crypto/id';
  import { derivePasswordKeyInWorker } from '$lib/crypto/password';
  import {
    deriveStorageKey,
    encryptEnvelope,
    type PasswordEncryptionLayer
  } from '$lib/crypto/protocol';
  import { CreateEnvelopeRequestSchema, type CreateEnvelopeRequest, type RuntimeConfig } from '$lib/gen/securl/v1/api_pb.js';
  import { normalizeServiceDomain } from '$lib/security/domain';
  import { validateDestination } from '$lib/security/url';
  import Button from '../ui/Button.svelte';
  import Field from '../ui/Field.svelte';
  import Panel from '../ui/Panel.svelte';
  import Spinner from '../ui/Spinner.svelte';
  import SecurityOptions from './SecurityOptions.svelte';
  import ShortUrlResult from './ShortUrlResult.svelte';

  type CreateState =
    | 'idle'
    | 'validating'
    | 'encrypting'
    | 'submitting'
    | 'retrying'
    | 'success'
    | 'error';

  interface CreateArtifact {
    idBytes: Uint8Array;
    encodedId: string;
    request: CreateEnvelopeRequest;
  }

  const controller = new AbortController();
  let state: CreateState = 'idle';
  let config: RuntimeConfig | undefined;
  let destinationInput = '';
  let passwordEnabled = false;
  let password = '';
  let captchaEnabled = false;
  let burnAfterRead = false;
  let ttlSeconds = 0;
  let protectedUrl = '';
  let errorMessage = '';
  let root: HTMLElement;
  let focusedState: CreateState = state;
  let buildCount = 0;

  onMount(async () => {
    try {
      config = await getRuntimeConfig(controller.signal);
      ttlSeconds = config.defaultTtlSeconds;
    } catch (error) {
      state = 'error';
      errorMessage = error instanceof Error ? error.message : 'Could not load SecURL configuration.';
    }
  });

  onDestroy(() => controller.abort());

  afterUpdate(() => {
    if (state === focusedState) return;
    focusedState = state;
    root.querySelector<HTMLElement>('h2[tabindex="-1"], h1[tabindex="-1"]')?.focus();
  });

  async function buildArtifact(canonicalUrl: URL, serviceDomain: string): Promise<CreateArtifact> {
    buildCount += 1;
    if (buildCount === 1) state = 'encrypting';
    const idBytes = generateIdBytes();
    const encodedId = encodeId(idBytes);
    const storageKey = deriveStorageKey(idBytes, serviceDomain);
    let passwordLayer: PasswordEncryptionLayer | undefined;
    let passwordKey: Uint8Array | undefined;
    if (passwordEnabled) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      passwordKey = await derivePasswordKeyInWorker(password, salt, controller.signal);
      passwordLayer = { key: passwordKey, salt };
    }
    const captchaKey = captchaEnabled
      ? crypto.getRandomValues(new Uint8Array(32))
      : undefined;
    try {
      const envelope = encryptEnvelope(canonicalUrl.href, idBytes, {
        ttlSeconds,
        password: passwordLayer,
        captchaKey,
        burnAfterRead
      });
      return {
        idBytes,
        encodedId,
        request: create(CreateEnvelopeRequestSchema, {
          storageKey,
          envelope,
          captchaKey: captchaKey ?? new Uint8Array()
        })
      };
    } finally {
      passwordKey?.fill(0);
    }
  }

  async function submit() {
    if (!config || !['idle', 'error'].includes(state)) return;
    errorMessage = '';
    protectedUrl = '';
    buildCount = 0;
    state = 'validating';
    let canonicalUrl: URL;
    try {
      canonicalUrl = validateDestination(destinationInput);
      const serviceDomain = normalizeServiceDomain(window.location.hostname);
      const result = await createWithCollisionRetries(
        () => buildArtifact(canonicalUrl, serviceDomain),
        async (artifact) => {
          if (buildCount === 1) state = 'submitting';
          else state = 'retrying';
          try {
            return await submitEnvelope(artifact.request, controller.signal);
          } catch (error) {
            if (error instanceof CreateConflictError) {
              artifact.idBytes.fill(0);
              artifact.request.captchaKey.fill(0);
            }
            throw error;
          }
        }
      );
      protectedUrl = `${window.location.origin}/#${result.artifact.encodedId}`;
      result.artifact.idBytes.fill(0);
      result.artifact.request.captchaKey.fill(0);
      state = 'success';
    } catch (error) {
      state = 'error';
      errorMessage = error instanceof Error ? error.message : 'Could not create the protected link.';
    }
  }

  function reset() {
    state = 'idle';
    protectedUrl = '';
    errorMessage = '';
  }
</script>
<main bind:this={root} class="shell" aria-busy={['validating', 'encrypting', 'submitting', 'retrying'].includes(state)}>
  <header class="page-header">
    <p class="eyebrow">Zero-knowledge link protection</p>
    <h1 tabindex="-1">Create a protected link</h1>
    <p>Encrypt a destination in this browser. SecURL stores only an opaque key and ciphertext.</p>
  </header>

  {#if state === 'success'}
    <ShortUrlResult url={protectedUrl} />
    <Button variant="secondary" on:click={reset}>Create another link</Button>
  {:else}
    <form on:submit|preventDefault={submit}>
      <Panel>
        <Field id="destination" label="Destination URL" hint="Protocol defaults to https://. Only public HTTP and HTTPS destinations are accepted.">
          <input id="destination" type="text" inputmode="url" bind:value={destinationInput} autocomplete="url" autocapitalize="none" spellcheck="false" required />
        </Field>

        {#if config}
          <SecurityOptions
            {config}
            bind:passwordEnabled
            bind:password
            bind:captchaEnabled
            bind:burnAfterRead
            bind:ttlSeconds
          />
        {:else if state !== 'error'}
          <p class="status-line"><Spinner /> Loading security options…</p>
        {/if}

        {#if state === 'error'}
          <p class="error-message" role="alert">{errorMessage}</p>
        {/if}

        <Button type="submit" disabled={!config || !destinationInput || !['idle', 'error'].includes(state)}>
          {#if ['validating', 'encrypting', 'submitting', 'retrying'].includes(state)}<Spinner />{/if}
          {state === 'retrying' ? 'Retrying with a new secret…' : 'Create protected link'}
        </Button>
      </Panel>
    </form>
  {/if}
</main>
