<script lang="ts">
  import { afterUpdate, onDestroy, onMount } from 'svelte';
  import { API_BASE_URL } from '$lib/api/client';
  import { lookupSafeBrowsingPrefixes } from '$lib/safe-browsing/client';
  import { RedirectCoordinator, type RedirectSnapshot } from '$lib/safe-browsing/redirect';
  import { findBlockingMatch, hashSafeBrowsingUrl } from '$lib/safe-browsing/url-hash';
  import Button from '../ui/Button.svelte';
  import Panel from '../ui/Panel.svelte';
  import ProgressCountdown from '../ui/ProgressCountdown.svelte';
  import Spinner from '../ui/Spinner.svelte';
  import MaliciousWarning from './MaliciousWarning.svelte';

  export let destinationPromise: Promise<URL>;
  export let enabled: boolean;
  export let deadline: number;

  let coordinator: RedirectCoordinator | undefined;
  let destination: URL | undefined;
  let openingWithoutScan = false;
  let snapshot: RedirectSnapshot = {
    remainingSeconds: 5,
    countdownDone: false,
    scanState: 'scanning'
  };
  let root: HTMLDivElement;
  let focusedView = '';
  $: view = !enabled ? 'disabled' : snapshot.scanState;

  function redirect() {
    void destinationPromise
      .then((resolved) => window.location.replace(resolved.href))
      .catch(() => {});
  }

  function goBack() {
    if (window.history.length > 1) window.history.back();
    else window.location.replace('/');
  }

  function openWithoutScanning() {
    openingWithoutScan = true;
    coordinator?.openWithoutSafetyCheck();
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
      (next) => (snapshot = next)
    );
    coordinator.start(deadline);
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
{:else if snapshot.scanState === 'threat' && destination}
  <MaliciousWarning hostname={destination.hostname} />
{:else if snapshot.scanState === 'error' && destination}
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
    {:else}
      <p class="status-line"><Spinner /> Decrypting destination…</p>
    {/if}
    <ProgressCountdown remaining={snapshot.remainingSeconds} />
    <p>{!destination
      ? 'Preparing the destination while the safety delay runs.'
      : snapshot.countdownDone && snapshot.scanState === 'scanning'
        ? 'Finishing the check…'
        : 'We’ll open it when the check finishes.'}</p>
    {#if !snapshot.countdownDone}
      <div class="redirect-actions">
        <Button
          variant="secondary"
          disabled={openingWithoutScan}
          on:click={() => coordinator?.openAfterSafetyCheck()}
        >
          Check now and open
        </Button>
        <Button variant="danger" disabled={openingWithoutScan} on:click={openWithoutScanning}>
          {openingWithoutScan ? 'Opening…' : 'Open without scanning'}
        </Button>
      </div>
    {/if}
  </Panel>
{/if}
</div>
