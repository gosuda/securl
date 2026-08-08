<script lang="ts">
  import { onDestroy } from 'svelte';
  import Button from './Button.svelte';

  export let value: string;
  let copied = false;
  let resetTimer: number | undefined;

  async function copy() {
    await navigator.clipboard.writeText(value);
    copied = true;
    clearTimeout(resetTimer);
    resetTimer = window.setTimeout(() => (copied = false), 2000);
  }

  onDestroy(() => clearTimeout(resetTimer));
</script>

<Button variant="secondary" on:click={copy}>{copied ? 'Copied' : 'Copy link'}</Button>
