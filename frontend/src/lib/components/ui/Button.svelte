<script lang="ts">
  export let type: 'button' | 'submit' = 'button';
  export let variant: 'primary' | 'secondary' | 'danger' = 'primary';
  export let disabled = false;
</script>

<button {type} {disabled} class:secondary={variant === 'secondary'} class:danger={variant === 'danger'} on:click {...$$restProps}>
  <slot />
</button>
