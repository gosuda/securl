<script lang="ts">
  import { onMount } from 'svelte';
  import CreateLink from '$lib/components/create/CreateLink.svelte';
  import OpenLink from '$lib/components/open/OpenLink.svelte';

  let mounted = false;
  let hasFragment = false;

  onMount(() => {
    hasFragment = window.location.hash.length > 1;
    mounted = true;
  });
</script>

{#if !mounted}
  <main class="shell" aria-busy="true">
    <h1>SecURL</h1>
    <p>Preparing secure browser processing…</p>
  </main>
{:else if hasFragment}
  <OpenLink />
{:else}
  <CreateLink />
{/if}
