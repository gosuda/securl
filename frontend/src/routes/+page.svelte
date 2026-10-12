<script lang="ts">
  import { page } from '$app/state';
  import { onMount } from 'svelte';

  let mounted = $state(false);
  let fragment = $state('');

  // Client-side navigation updates page.url; manual hash edits fire hashchange.
  $effect(() => {
    fragment = page.url.hash;
  });

  onMount(() => {
    const syncFragment = () => {
      fragment = window.location.hash;
    };
    syncFragment();
    window.addEventListener('hashchange', syncFragment);
    mounted = true;
    return () => window.removeEventListener('hashchange', syncFragment);
  });
</script>

{#snippet loading()}
  <main class="shell shell--loading" aria-busy="true">
    <div class="loading-block">
      <h1>SecURL</h1>
      <p>Getting things ready…</p>
    </div>
  </main>
{/snippet}

{#snippet loadFailed()}
  <main class="shell">
    <div class="loading-block">
      <h1>SecURL</h1>
      <p>SecURL could not load. Check your connection and reload the page.</p>
    </div>
  </main>
{/snippet}

<!-- Dynamic imports are deliberate code-split points: openers never download the creator, and vice versa. -->
{#if !mounted}
  {@render loading()}
{:else if fragment.length > 1}
  {#key fragment}
    {#await import('#lib/components/open/OpenLink.svelte')}
      {@render loading()}
    {:then { default: OpenLink }}
      <OpenLink {fragment} />
    {:catch}
      {@render loadFailed()}
    {/await}
  {/key}
{:else}
  {#await import('#lib/components/create/CreateLink.svelte')}
    {@render loading()}
  {:then { default: CreateLink }}
    <CreateLink />
  {:catch}
    {@render loadFailed()}
  {/await}
{/if}
