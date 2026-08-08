<script lang="ts">
  export let type: 'button' | 'submit' = 'button';
  export let variant: 'primary' | 'secondary' | 'danger' = 'primary';
  export let disabled = false;
</script>

<button
  {type}
  {disabled}
  class="btn"
  class:secondary={variant === 'secondary'}
  class:danger={variant === 'danger'}
  aria-disabled={disabled}
  on:click
  {...$$restProps}
>
  <slot />
</button>
