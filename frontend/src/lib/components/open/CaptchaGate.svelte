<script lang="ts">
  import { CaptchaProvider } from '$lib/gen/securl/v1/api_pb.js';
  import CaptchaChallenge from '../ui/CaptchaChallenge.svelte';
  import Panel from '../ui/Panel.svelte';

  export let provider: CaptchaProvider;
  export let siteKey: string;

  let challengeGeneration = 0;
</script>

<Panel>
  <h2 tabindex="-1">One quick check</h2>
  {#key challengeGeneration}
    <CaptchaChallenge
      {provider}
      {siteKey}
      on:verified
      on:retry={() => challengeGeneration += 1}
    />
  {/key}
</Panel>
