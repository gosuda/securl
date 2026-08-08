<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Button from '../ui/Button.svelte';
  import Field from '../ui/Field.svelte';
  import Panel from '../ui/Panel.svelte';

  export let burnAfterRead = false;
  const dispatch = createEventDispatcher<{ submit: string }>();
  let password = '';
</script>

<Panel>
  <h2 tabindex="-1">Password required</h2>
  {#if burnAfterRead}
    <p class="warning-text">This link is deleted when its encrypted data is retrieved. A wrong password cannot be retried.</p>
  {/if}
  <form on:submit|preventDefault={() => dispatch('submit', password)}>
    <Field id="open-password" label="Password">
      <input id="open-password" type="password" bind:value={password} autocomplete="current-password" required />
    </Field>
    <Button type="submit" disabled={!password}>Continue</Button>
  </form>
</Panel>
