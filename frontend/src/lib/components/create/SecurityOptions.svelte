<script lang="ts">
  import type { RuntimeConfig } from '$lib/gen/securl/v1/api_pb.js';
  import Field from '../ui/Field.svelte';
  import Panel from '../ui/Panel.svelte';

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
    <span><strong>Password</strong><small>Add a browser-derived encryption layer.</small></span>
  </label>
  {#if passwordEnabled}
    <Field id="password" label="Password" hint="1–1024 UTF-8 bytes. SecURL never receives it.">
      <input id="password" type="password" bind:value={password} autocomplete="new-password" required />
    </Field>
  {/if}

  <label class="check-row" class:disabled={config.captchaProvider === 0}>
    <input type="checkbox" bind:checked={captchaEnabled} disabled={config.captchaProvider === 0} />
    <span><strong>CAPTCHA</strong><small>Require a challenge before releasing the final browser key.</small></span>
  </label>

  <label class="check-row">
    <input type="checkbox" bind:checked={burnAfterRead} />
    <span><strong>Burn after reading</strong><small>Delete the encrypted envelope after its first protected retrieval.</small></span>
  </label>

  {#if burnAfterRead && passwordEnabled}
    <Panel tone="warning">
      <strong>This link is deleted when its encrypted data is retrieved. A wrong password cannot be retried.</strong>
    </Panel>
  {/if}

  <Field id="ttl" label="Time to live">
    <select id="ttl" bind:value={ttlSeconds}>
      {#each config.allowedTtlSeconds as ttl}
        <option value={ttl}>{ttl === 0 ? 'Forever' : `${ttl / 3600} hours`}</option>
      {/each}
    </select>
  </Field>
</div>
