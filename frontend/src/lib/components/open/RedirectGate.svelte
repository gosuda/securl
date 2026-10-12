<script lang="ts">
  import { afterUpdate, onDestroy, onMount } from 'svelte';
  import { API_BASE_URL } from '#lib/api/client.js';
  import { lookupSafeBrowsingPrefixes } from '#lib/safe-browsing/client.js';
  import { RedirectCoordinator, type ScanState } from '#lib/safe-browsing/redirect.js';
  import { findBlockingMatch, hashSafeBrowsingUrl } from '#lib/safe-browsing/url-hash.js';
  import Button from '../ui/Button.svelte';
  import Panel from '../ui/Panel.svelte';
  import Spinner from '../ui/Spinner.svelte';
  import MaliciousWarning from './MaliciousWarning.svelte';

  export let destinationPromise: Promise<URL>;
  export let enabled: boolean;

  let coordinator: RedirectCoordinator | undefined;
  let destination: URL | undefined;
  let scanState: ScanState = 'scanning';
  let root: HTMLDivElement;
  let focusedView = '';
  $: view = !enabled ? 'disabled' : scanState;

  function redirect() {
    void destinationPromise
      .then((resolved) => window.location.replace(resolved.href))
      .catch(() => {});
  }

  function goBack() {
    if (window.history.length > 1) window.history.back();
    else window.location.replace('/');
  }

  onMount(() => {
    void destinationPromise.then(
      (resolved) => (destination = resolved),
      () => {}
    );
    if (!enabled) return;
    coordinator = new RedirectCoordinator(
      async (signal) => {
        const resolved = await destinationPromise;
        if (signal.aborted) throw signal.reason;
        const localHashes = await hashSafeBrowsingUrl(resolved.href);
        const response = await lookupSafeBrowsingPrefixes(API_BASE_URL, localHashes, signal);
        return findBlockingMatch(localHashes, response.fullHashes) ? 'threat' : 'clean';
      },
      redirect,
      (next) => (scanState = next)
    );
    coordinator.start();
  });

  onDestroy(() => coordinator?.cancel());

  afterUpdate(() => {
    if (view === focusedView) return;
    focusedView = view;
    root.querySelector<HTMLElement>('h2[tabindex="-1"]')?.focus();
  });
</script>

<div bind:this={root}>
{#if !enabled}
  <Panel>
    <h2 tabindex="-1">Safety check is off</h2>
    {#if destination}
      <p>Review the destination before opening it.</p>
      <code class="hostname">{destination.hostname}</code>
      <Button on:click={redirect}>Open destination</Button>
    {:else}
      <p class="status-line"><Spinner /> Decrypting destination…</p>
    {/if}
  </Panel>
{:else if scanState === 'threat' && destination}
  <MaliciousWarning hostname={destination.hostname} />
{:else if scanState === 'error' && destination}
  <Panel tone="warning">
    <h2 tabindex="-1">Safety check unavailable</h2>
    <p>We couldn’t check this destination.</p>
    <code class="hostname">{destination.hostname}</code>
    <div class="actions">
      <Button on:click={() => coordinator?.openWithoutSafetyCheck()}>Open without safety check</Button>
      <Button variant="secondary" on:click={goBack}>Go back</Button>
    </div>
  </Panel>
{:else}
  <Panel>
    <h2 tabindex="-1">Checking destination safety</h2>
    {#if destination}
      <code class="hostname">{destination.hostname}</code>
      <p class="status-line"><Spinner /> Checking the destination…</p>
    {:else}
      <p class="status-line"><Spinner /> Decrypting destination…</p>
    {/if}
  </Panel>
{/if}
</div>
