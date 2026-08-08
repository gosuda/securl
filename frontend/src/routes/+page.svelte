<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import CreateLink from '$lib/components/create/CreateLink.svelte';
  import OpenLink from '$lib/components/open/OpenLink.svelte';

  let mounted = false;
  let hasFragment = false;

  $: hasFragment = mounted && $page.url.hash.length > 1;

  onMount(() => {
    mounted = true;
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
  <OpenLink />
{:else}
  <CreateLink />
{/if}
