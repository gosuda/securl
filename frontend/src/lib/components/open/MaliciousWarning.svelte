<script lang="ts">
  import Button from '../ui/Button.svelte';
  import Panel from '../ui/Panel.svelte';
  export let hostname: string;
</script>

<Panel tone="danger">
  <p class="eyebrow">Blocked destination</p>
  <h2 tabindex="-1">Deceptive site ahead</h2>
  <p>Google Safe Browsing identified this destination as potentially harmful. SecURL blocked the redirect.</p>
  <code class="hostname">{hostname}</code>
  <Button variant="secondary" on:click={() => window.location.replace('/')}>Return to SecURL</Button>
</Panel>
