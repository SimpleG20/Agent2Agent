<script lang="ts">
  import { currentPath } from './stores/router'
  import Nav from './lib/components/Nav.svelte'
  import Dashboard from './routes/dashboard/+page.svelte'
  import Admin from './routes/admin/+page.svelte'
  import Playground from './routes/playground/+page.svelte'

  let path = $derived($currentPath)
</script>

<div class="flex h-full">
  <Nav {path} />
  <main class="flex-1 overflow-auto p-8">
    {#if path === '/dashboard'}
      <Dashboard />
    {:else if path === '/admin'}
      <Admin />
    {:else if path === '/playground'}
      <Playground />
    {/if}
  </main>
</div>
