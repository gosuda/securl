<script lang="ts">
  import Button from '../ui/Button.svelte';
  import Panel from '../ui/Panel.svelte';

  export let title = 'Unable to open this link';
  export let message: string;
</script>

<Panel tone="danger">
  <h2 tabindex="-1">{title}</h2>
  <p>{message}</p>
  <Button variant="secondary" on:click={() => window.location.replace('/')}>Return to SecURL</Button>
</Panel>
