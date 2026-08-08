<script lang="ts">
  export let remaining: number;
  const total = 5;
  $: elapsed = total - remaining;
</script>

<div class="countdown">
  <div
    class="progress-track"
    role="progressbar"
    aria-valuemin="0"
    aria-valuemax={total}
    aria-valuenow={elapsed}
    aria-label="Safety delay"
  >
    <span style={`--progress: ${elapsed / total}`}></span>
  </div>
  <p aria-live="polite">{remaining > 0 ? `${remaining} seconds remaining` : 'Safety delay complete'}</p>
</div>
