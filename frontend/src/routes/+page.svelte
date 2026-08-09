<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import CreateLink from '$lib/components/create/CreateLink.svelte';
  import OpenLink from '$lib/components/open/OpenLink.svelte';

  let mounted = false;
  let fragment = '';
  let hasFragment = false;

  $: hasFragment = mounted && fragment.length > 1;

  onMount(() => {
    const syncFragment = () => {
      fragment = window.location.hash;
    };
    const unsubscribe = page.subscribe((currentPage) => {
      fragment = currentPage.url.hash;
    });
    syncFragment();
    window.addEventListener('hashchange', syncFragment);
    mounted = true;
    return () => {
      unsubscribe();
      window.removeEventListener('hashchange', syncFragment);
    };
  });
</script>

{#if !mounted}
  <main class="shell shell--loading" aria-busy="true">
    <div class="loading-block">
      <h1>SecURL</h1>
      <p>Getting things ready…</p>
    </div>
  </main>
{:else if hasFragment}
  {#key fragment}
    <OpenLink {fragment} />
  {/key}
{:else}
  <CreateLink />
{/if}
