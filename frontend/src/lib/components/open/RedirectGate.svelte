<script lang="ts">
  import { afterUpdate, onDestroy, onMount } from 'svelte';
  import { API_BASE_URL } from '$lib/api/client';
  import { lookupSafeBrowsingPrefixes } from '$lib/safe-browsing/client';
  import { RedirectCoordinator, type RedirectSnapshot } from '$lib/safe-browsing/redirect';
  import { findBlockingMatch, hashSafeBrowsingUrl } from '$lib/safe-browsing/url-hash';
  import Button from '../ui/Button.svelte';
  import Panel from '../ui/Panel.svelte';
  import ProgressCountdown from '../ui/ProgressCountdown.svelte';
  import MaliciousWarning from './MaliciousWarning.svelte';

  export let destination: URL;
  export let enabled: boolean;

  let coordinator: RedirectCoordinator | undefined;
  let snapshot: RedirectSnapshot = {
    remainingSeconds: 5,
    countdownDone: false,
    scanState: 'scanning'
  };
  let root: HTMLDivElement;
  let focusedView = '';
  $: view = !enabled ? 'disabled' : snapshot.scanState;

  function redirect() {
    window.location.replace(destination.href);
  }

  function goBack() {
    if (window.history.length > 1) window.history.back();
    else window.location.replace('/');
  }

  onMount(() => {
    if (!enabled) return;
    coordinator = new RedirectCoordinator(
      async (signal) => {
        const localHashes = await hashSafeBrowsingUrl(destination.href);
        const response = await lookupSafeBrowsingPrefixes(API_BASE_URL, localHashes, signal);
        return findBlockingMatch(localHashes, response.fullHashes) ? 'threat' : 'clean';
      },
      redirect,
      (next) => (snapshot = next)
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
    <h2 tabindex="-1">Safety check is disabled</h2>
    <p>SecURL cannot automatically verify this destination.</p>
    <code class="hostname">{destination.hostname}</code>
    <Button on:click={redirect}>Open destination</Button>
  </Panel>
{:else if snapshot.scanState === 'threat'}
  <MaliciousWarning hostname={destination.hostname} />
{:else if snapshot.scanState === 'error'}
  <Panel tone="warning">
    <h2 tabindex="-1">Safety check unavailable</h2>
    <p>Safety check unavailable. SecURL could not verify this destination.</p>
    <code class="hostname">{destination.hostname}</code>
    <div class="actions">
      <Button on:click={() => coordinator?.openWithoutSafetyCheck()}>Open without safety check</Button>
      <Button variant="secondary" on:click={goBack}>Go back</Button>
    </div>
  </Panel>
{:else}
  <Panel>
    <h2 tabindex="-1">Checking destination safety</h2>
    <code class="hostname">{destination.hostname}</code>
    <ProgressCountdown remaining={snapshot.remainingSeconds} />
    <p>{snapshot.countdownDone && snapshot.scanState === 'scanning' ? 'Finishing the safety check…' : 'Google Safe Browsing check in progress.'}</p>
    {#if !snapshot.countdownDone}
      <Button variant="secondary" on:click={() => coordinator?.openAfterSafetyCheck()}>
        Check now and open
      </Button>
    {/if}
  </Panel>
{/if}
</div>
