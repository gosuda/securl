<script lang="ts">
  import CopyButton from '../ui/CopyButton.svelte';
  import Panel from '../ui/Panel.svelte';

  export let url: string;
</script>

<Panel tone="success">
  <h2 tabindex="-1">Protected link ready</h2>
  <div class="result-row">
    <code>{url}</code>
    <p>Share the whole link exactly as shown.</p>
    <CopyButton value={url} />
  </div>
</Panel>
