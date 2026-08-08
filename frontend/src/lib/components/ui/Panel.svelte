<script lang="ts">
  export let tone: 'default' | 'success' | 'warning' | 'danger' = 'default';
</script>

<section class="panel" class:success={tone === 'success'} class:warning={tone === 'warning'} class:danger={tone === 'danger'}>
  <slot />
</section>
