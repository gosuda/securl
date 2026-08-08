<script lang="ts">
  import '../app.css';
</script>

<div class="app-frame">
  <header class="site-nav">
    <div class="site-nav__inner">
      <a class="wordmark" href="/" aria-label="SecURL home">
        <span class="brand-mark" aria-hidden="true"></span>
        <span>SecURL</span>
      </a>
      <a class="nav-action" href="/">New link</a>
    </div>
  </header>

  <slot />

  <footer class="bottom-bar">
    <div class="bottom-bar__inner">
      <span>© 2026 SecURL</span>
      <a href="https://github.com/gosuda/securl" target="_blank" rel="noreferrer">
        GitHub <span aria-hidden="true">↗</span>
      </a>
    </div>
  </footer>
</div>
