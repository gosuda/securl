<script lang="ts">
  import { create } from '@bufbuild/protobuf';
  import { afterUpdate, onDestroy, onMount } from 'svelte';
  import { ApiError, getRuntimeConfig, submitEnvelope } from '#lib/api/client.js';
  import {
    CreateConflictError,
    createWithCollisionRetries
  } from '#lib/api/create.js';
  import { encodeId, generateIdBytes } from '#lib/crypto/id.js';
  import { derivePasswordKey } from '#lib/crypto/password.js';
  import {
    encryptEnvelope,
    type EnvelopeContent,
    type PasswordEncryptionLayer
  } from '#lib/crypto/protocol.js';
  import { deflateMarkdown } from '#lib/paste/compression.js';
  import { deriveRootLinkKeys } from '#lib/crypto/root-key.js';
  import { CreateEnvelopeRequestSchema, type CreateEnvelopeRequest, type RuntimeConfig } from '#lib/gen/securl/v1/api_pb.js';
  import { normalizeServiceDomain } from '#lib/security/domain.js';
  import { validateDestination } from '#lib/security/url.js';
  import Button from '../ui/Button.svelte';
  import CaptchaChallenge from '../ui/CaptchaChallenge.svelte';
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

  type CreateMode = 'url' | 'markdown';

  interface CreateArtifact {
    idBytes: Uint8Array;
    encodedId: string;
    request: CreateEnvelopeRequest;
  }

  class PasteTooLargeError extends Error {
    readonly compressedBytes: number;

    constructor(compressedBytes: number) {
      super('Compressed Markdown exceeds the server limit.');
      this.compressedBytes = compressedBytes;
    }
  }

  const controller = new AbortController();
  let state: CreateState = 'idle';
  let config: RuntimeConfig | undefined;
  let mode: CreateMode = 'url';
  let destinationInput = '';
  let markdownInput = '';
  let previewHtml: string | undefined;
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
  let createCaptchaToken = '';
  let createCaptchaGeneration = 0;

  $: pasteEnabled = (config?.maxPasteBytes ?? 0) > 0;
  $: hasInput = mode === 'url' ? destinationInput !== '' : markdownInput.trim() !== '';

  function formatBytes(bytes: number): string {
    return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`;
  }

  function selectMode(next: CreateMode) {
    mode = next;
    previewHtml = undefined;
    if (state === 'error') {
      state = 'idle';
      errorMessage = '';
    }
  }

  async function togglePreview() {
    if (previewHtml !== undefined) {
      previewHtml = undefined;
      return;
    }
    // Code-split: marked + DOMPurify load only when a creator asks for a preview.
    const { renderMarkdown } = await import('#lib/paste/render.js');
    previewHtml = renderMarkdown(markdownInput);
  }

  onMount(async () => {
    try {
      config = await getRuntimeConfig(controller.signal);
      ttlSeconds = config.defaultTtlSeconds;
    } catch {
      state = 'error';
      errorMessage = 'SecURL isn’t available right now. Try again shortly.';
    }
  });

  onDestroy(() => controller.abort());

  afterUpdate(() => {
    if (state === focusedState) return;
    focusedState = state;
    root.querySelector<HTMLElement>('h2[tabindex="-1"], h1[tabindex="-1"]')?.focus();
  });

  async function buildArtifact(content: EnvelopeContent, serviceDomain: string): Promise<CreateArtifact> {
    buildCount += 1;
    if (buildCount === 1) state = 'encrypting';
    const idBytes = generateIdBytes();
    const encodedId = encodeId(idBytes);
    const keys = await deriveRootLinkKeys(idBytes, serviceDomain, controller.signal);
    let passwordLayer: PasswordEncryptionLayer | undefined;
    let passwordKey: Uint8Array | undefined;
    try {
      if (passwordEnabled) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        passwordKey = await derivePasswordKey(password, salt, controller.signal);
        passwordLayer = { key: passwordKey, salt };
      }
      const captchaKey = captchaEnabled
        ? crypto.getRandomValues(new Uint8Array(32))
        : undefined;
      const envelope = encryptEnvelope(
        content,
        idBytes,
        keys.encryptionKeyMaterial,
        {
          ttlSeconds,
          password: passwordLayer,
          captchaKey,
          burnAfterRead
        }
      );
      return {
        idBytes,
        encodedId,
        request: create(CreateEnvelopeRequestSchema, {
          storageKey: keys.storageKey,
          envelope,
          captchaKey: captchaKey ?? new Uint8Array(),
          captchaToken: createCaptchaToken
        })
      };
    } finally {
      passwordKey?.fill(0);
      keys.encryptionKeyMaterial.fill(0);
    }
  }

  async function prepareContent(): Promise<EnvelopeContent> {
    if (mode === 'url') return { kind: 'url', url: validateDestination(destinationInput).href };
    const maxPasteBytes = config?.maxPasteBytes ?? 0;
    const deflated = await deflateMarkdown(markdownInput);
    if (deflated.length > maxPasteBytes) {
      deflated.fill(0);
      throw new PasteTooLargeError(deflated.length);
    }
    return { kind: 'markdown', deflated };
  }

  function describeError(error: unknown): string {
    const limit = formatBytes(config?.maxPasteBytes ?? 0);
    if (error instanceof PasteTooLargeError) {
      return `This paste is ${formatBytes(error.compressedBytes)} after compression; the limit is ${limit}. Shorten it and try again.`;
    }
    if (error instanceof ApiError && error.code === 'envelope_too_large') {
      return mode === 'url'
        ? 'This destination is too long to store.'
        : `This paste is over the ${limit} compressed limit. Shorten it and try again.`;
    }
    if (error instanceof ApiError && error.code === 'feature_unavailable' && mode === 'markdown') {
      return 'Markdown pastes are turned off on this server.';
    }
    if (error instanceof Error && error.message.startsWith('Destination')) {
      return 'Enter a public web address.';
    }
    if (error instanceof Error && error.message === 'Markdown exceeds the size limit.') {
      return 'This paste is too large to compress in the browser. Shorten it and try again.';
    }
    return mode === 'url' ? 'Couldn’t create the link. Try again.' : 'Couldn’t create the paste. Try again.';
  }

  async function submit() {
    if (!config || !hasInput || !['idle', 'error'].includes(state) ||
      (config.createCaptchaRequired && !createCaptchaToken)) return;
    errorMessage = '';
    protectedUrl = '';
    buildCount = 0;
    state = 'validating';
    let requestStarted = false;
    let content: EnvelopeContent | undefined;
    try {
      content = await prepareContent();
      const serviceDomain = normalizeServiceDomain(window.location.hostname);
      const preparedContent = content;
      const result = await createWithCollisionRetries(
        () => buildArtifact(preparedContent, serviceDomain),
        async (artifact) => {
          if (buildCount === 1) state = 'submitting';
          else state = 'retrying';
          requestStarted = true;
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
      if (requestStarted && config.createCaptchaRequired) resetCreateCaptcha();
      errorMessage = describeError(error);
    } finally {
      if (content?.kind === 'markdown') content.deflated.fill(0);
    }
  }

  function captchaVerified(token: string) {
    createCaptchaToken = token;
  }

  function captchaFailed() {
    createCaptchaToken = '';
  }

  function resetCreateCaptcha() {
    createCaptchaToken = '';
    createCaptchaGeneration += 1;
  }

  function reset() {
    state = 'idle';
    protectedUrl = '';
    errorMessage = '';
    markdownInput = '';
    previewHtml = undefined;
    resetCreateCaptcha();
  }
</script>
<main
  bind:this={root}
  class="shell"
  data-state={state}
  aria-busy={['validating', 'encrypting', 'submitting', 'retrying'].includes(state)}
>
  <header class="page-header">
    <h1 tabindex="-1">{mode === 'url' ? 'Create a protected link' : 'Create an encrypted paste'}</h1>
    <p>{mode === 'url'
      ? 'Paste a destination. Share the link that comes back.'
      : 'Write Markdown. It’s compressed and encrypted before it leaves your browser.'}</p>
  </header>

  {#if state === 'success'}
    <div class="result-stack">
      <ShortUrlResult url={protectedUrl} />
      <Button variant="secondary" on:click={reset}>{mode === 'url' ? 'Create another link' : 'Create another paste'}</Button>
    </div>
  {:else}
    <form on:submit|preventDefault={submit}>
      <Panel>
        {#if pasteEnabled}
          <div class="mode-switch" role="radiogroup" aria-label="What to protect">
            <label class:selected={mode === 'url'}>
              <input type="radio" name="mode" value="url" checked={mode === 'url'} on:change={() => selectMode('url')} />
              Link
            </label>
            <label class:selected={mode === 'markdown'}>
              <input type="radio" name="mode" value="markdown" checked={mode === 'markdown'} on:change={() => selectMode('markdown')} />
              Markdown paste
            </label>
          </div>
        {/if}

        {#if mode === 'url'}
          <Field id="destination" label="Destination URL" hint="We’ll add https:// when it’s missing.">
            <input
              id="destination"
              type="text"
              inputmode="url"
              bind:value={destinationInput}
              autocomplete="url"
              autocapitalize="none"
              spellcheck="false"
              aria-describedby="destination-hint"
              required
            />
          </Field>
        {:else}
          <Field
            id="markdown"
            label="Markdown"
            hint={`Up to ${formatBytes(config?.maxPasteBytes ?? 0)} after compression.`}
          >
            {#if previewHtml === undefined}
              <textarea
                id="markdown"
                class="paste-input"
                bind:value={markdownInput}
                rows="14"
                spellcheck="true"
                aria-describedby="markdown-hint"
                required
              ></textarea>
            {:else}
              <div class="markdown-body paste-preview" aria-label="Preview">{@html previewHtml}</div>
            {/if}
          </Field>
          <Button variant="secondary" disabled={!hasInput} on:click={togglePreview}>
            {previewHtml === undefined ? 'Preview' : 'Edit'}
          </Button>
        {/if}

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
          <p class="status-line"><Spinner /> Loading options…</p>
        {/if}

        {#if config?.createCaptchaRequired}
          <section class="create-captcha" aria-labelledby="create-captcha-title">
            <h2 id="create-captcha-title">Confirm you’re human</h2>
            <p>Complete this check before creating the link.</p>
            {#key createCaptchaGeneration}
              <CaptchaChallenge
                provider={config.captchaProvider}
                siteKey={config.captchaSiteKey}
                on:verified={(event) => captchaVerified(event.detail)}
                on:error={captchaFailed}
                on:retry={resetCreateCaptcha}
              />
            {/key}
          </section>
        {/if}

        {#if state === 'error'}
          <p class="error-message" role="alert">{errorMessage}</p>
        {/if}

        <Button
          type="submit"
          disabled={!config || !hasInput || !['idle', 'error'].includes(state) ||
            (config.createCaptchaRequired && !createCaptchaToken)}
          aria-busy={['validating', 'encrypting', 'submitting', 'retrying'].includes(state)}
        >
          {#if ['validating', 'encrypting', 'submitting', 'retrying'].includes(state)}<Spinner />{/if}
          {state === 'retrying' ? 'Trying again…' : mode === 'url' ? 'Create protected link' : 'Create encrypted paste'}
        </Button>
      </Panel>
    </form>
  {/if}
</main>
