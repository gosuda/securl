<script lang="ts">
  import type { RuntimeConfig } from '$lib/gen/securl/v1/api_pb.js';
  import Field from '../ui/Field.svelte';

  export let config: RuntimeConfig;
  export let passwordEnabled: boolean;
  export let password: string;
  export let captchaEnabled: boolean;
  export let burnAfterRead: boolean;
  export let ttlSeconds: number;
</script>

<div class="options">
  <label class="check-row">
    <input type="checkbox" bind:checked={passwordEnabled} />
    <span><strong>Password</strong><small>Only people with the password can open it.</small></span>
  </label>
  {#if passwordEnabled}
    <Field id="password" label="Password" hint="Share it separately from the link.">
      <input id="password" type="password" bind:value={password} autocomplete="new-password" aria-describedby="password-hint" required />
    </Field>
  {/if}

  <label class="check-row" class:disabled={config.captchaProvider === 0}>
    <input type="checkbox" bind:checked={captchaEnabled} disabled={config.captchaProvider === 0} />
    <span><strong>CAPTCHA</strong><small>Ask visitors to prove they’re human.</small></span>
  </label>

  <label class="check-row">
    <input type="checkbox" bind:checked={burnAfterRead} />
    <span><strong>Burn after reading</strong><small>The link disappears after it’s opened once.</small></span>
  </label>

  {#if burnAfterRead && passwordEnabled}
    <p class="inline-warning">A one-time link can’t be tried again after a wrong password.</p>
  {/if}

  <Field id="ttl" label="Time to live">
    <select id="ttl" bind:value={ttlSeconds}>
      {#each config.allowedTtlSeconds as ttl}
        <option value={ttl}>{ttl === 0 ? 'Forever' : `${ttl / 3600} ${ttl === 3600 ? 'hour' : 'hours'}`}</option>
      {/each}
    </select>
  </Field>
</div>
