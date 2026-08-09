<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Button from '../ui/Button.svelte';
  import Field from '../ui/Field.svelte';
  import Panel from '../ui/Panel.svelte';

  export let burnAfterRead = false;
  export let error = '';
  const dispatch = createEventDispatcher<{ submit: string; edit: void }>();
  let password = '';
</script>

<Panel>
  <h2 tabindex="-1">Password required</h2>
  <form on:submit|preventDefault={() => dispatch('submit', password)}>
    <Field
      id="open-password"
      label="Password"
      hint={burnAfterRead ? 'For one-time links, retries stay in this tab.' : ''}
      {error}
    >
      <input
        id="open-password"
        type="password"
        bind:value={password}
        autocomplete="current-password"
        aria-invalid={error ? 'true' : undefined}
        aria-describedby={error ? 'open-password-error' : 'open-password-hint'}
        on:input={() => dispatch('edit')}
        required
      />
    </Field>
    <Button type="submit" disabled={!password}>Continue</Button>
  </form>
</Panel>
