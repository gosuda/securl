<script lang="ts">
  import Button from '../ui/Button.svelte';
  import Panel from '../ui/Panel.svelte';
  export let hostname: string;
</script>

<Panel tone="danger">
  <h2 tabindex="-1">Deceptive site ahead</h2>
  <p>This destination was flagged as harmful, so SecURL stopped here.</p>
  <code class="hostname">{hostname}</code>
  <Button variant="secondary" on:click={() => window.location.replace('/')}>Return to SecURL</Button>
</Panel>
