<script lang="ts">
  import { currentPath } from '../../stores/router'

  let { path }: { path: string } = $props()

  const items = [
    { href: '/dashboard', label: 'Dashboard', icon: '📊' },
    { href: '/admin', label: 'Admin', icon: '🛡️' },
    { href: '/playground', label: 'Playground', icon: '🧪' }
  ]

  function go(href: string) {
    currentPath.navigate(href)
  }
</script>

<aside class="w-60 bg-slate-900 border-r border-slate-800 flex flex-col">
  <div class="p-6 border-b border-slate-800">
    <h1 class="text-xl font-bold text-blue-400">A2A</h1>
    <p class="text-xs text-slate-500 mt-1">Key Guard Console</p>
  </div>
  <nav class="flex-1 p-4 space-y-1">
    {#each items as item}
      <button
        onclick={() => go(item.href)}
        class="w-full text-left px-4 py-2.5 rounded-lg flex items-center gap-3 transition-colors {path ===
        item.href
          ? 'bg-blue-600 text-white'
          : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'}"
      >
        <span class="text-lg">{item.icon}</span>
        <span class="font-medium">{item.label}</span>
      </button>
    {/each}
  </nav>
  <div class="p-4 border-t border-slate-800 text-xs text-slate-500">
    v0.1.0 · Stumgart
  </div>
</aside>
