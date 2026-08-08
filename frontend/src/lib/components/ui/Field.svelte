<script lang="ts">
  export let id: string;
  export let label: string;
  export let hint = '';
  export let error = '';
</script>

<div class="field">
  <label for={id}>{label}</label>
  <slot />
  {#if error}
    <p class="field-error" id={`${id}-error`} role="alert">{error}</p>
  {:else}
    <p class="hint" id={`${id}-hint`}>{hint}</p>
  {/if}
</div>
