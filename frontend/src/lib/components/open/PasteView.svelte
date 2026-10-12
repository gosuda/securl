<script lang="ts">
  import { renderMarkdown } from '#lib/paste/render.js';
  import CopyButton from '../ui/CopyButton.svelte';
  import Button from '../ui/Button.svelte';
  import Panel from '../ui/Panel.svelte';

  export let markdown: string;
  export let burnAfterRead: boolean;

  let showSource = false;
  $: html = renderMarkdown(markdown);

  function download() {
    const url = URL.createObjectURL(new Blob([markdown], { type: 'text/markdown;charset=utf-8' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'paste.md';
    anchor.click();
    // Safari cancels the download if the URL is revoked synchronously after click().
    setTimeout(() => URL.revokeObjectURL(url));
  }
</script>

<Panel>
  <h2 tabindex="-1">Encrypted paste</h2>
  {#if burnAfterRead}
    <p class="inline-warning">This paste was deleted from the server when you opened it. Copy it now if you need it.</p>
  {/if}
  {#if showSource}
    <pre class="paste-source">{markdown}</pre>
  {:else}
    <article class="markdown-body">{@html html}</article>
  {/if}
  <div class="paste-actions">
    <Button variant="secondary" on:click={() => (showSource = !showSource)}>
      {showSource ? 'Show rendered' : 'Show Markdown'}
    </Button>
    <Button variant="secondary" on:click={download}>Download .md</Button>
    <CopyButton value={markdown} />
  </div>
</Panel>
