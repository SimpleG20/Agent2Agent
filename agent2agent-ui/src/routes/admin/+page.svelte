<script lang="ts">
  import { onMount, onDestroy } from 'svelte'
  import { api } from '../../lib/api/client'
  import type { Revocation } from '../../lib/api/types'
  import StatusBadge from '../../lib/components/StatusBadge.svelte'

  let revocations = $state<Revocation[]>([])
  let did = $state('')
  let status = $state<'revoked' | 'suspended'>('revoked')
  let ttl = $state(300)
  let reason = $state('')
  let loading = $state(false)
  let message = $state<{ type: 'success' | 'error'; text: string } | null>(null)
  let interval: ReturnType<typeof setInterval> | null = null

  async function refresh() {
    try {
      const r = await api.listRevocations()
      revocations = r.revocations
    } catch (e) {
      console.error(e)
    }
  }

  async function handleRevoke(e: Event) {
    e.preventDefault()
    if (!did.trim()) return
    loading = true
    message = null
    try {
      await api.revoke({
        did: did.trim(),
        status,
        ttl_seconds: ttl,
        reason: reason.trim() || undefined
      })
      message = { type: 'success', text: `DID ${did} marcado como ${status}` }
      did = ''
      reason = ''
      await refresh()
    } catch (e) {
      message = { type: 'error', text: (e as Error).message }
    } finally {
      loading = false
    }
  }

  async function handleRestore(d: string) {
    if (!confirm(`Restaurar ${d}?`)) return
    try {
      await api.restore(d)
      message = { type: 'success', text: `DID ${d} restaurado` }
      await refresh()
    } catch (e) {
      message = { type: 'error', text: (e as Error).message }
    }
  }

  onMount(() => {
    refresh()
    interval = setInterval(refresh, 5_000)
  })

  onDestroy(() => {
    if (interval) clearInterval(interval)
  })
</script>

<div class="space-y-8 max-w-5xl">
  <header>
    <h2 class="text-3xl font-bold text-slate-100">Admin</h2>
    <p class="text-slate-400 mt-1">Gerenciar revogações de credenciais</p>
  </header>

  {#if message}
    <div
      class="rounded-lg p-3 text-sm border {message.type === 'success'
        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
        : 'bg-rose-500/10 border-rose-500/30 text-rose-400'}"
    >
      {message.text}
    </div>
  {/if}

  <section class="bg-slate-900 border border-slate-800 rounded-xl p-6">
    <h3 class="text-lg font-semibold text-slate-100 mb-4">Revogar um DID</h3>
    <form onsubmit={handleRevoke} class="space-y-4">
      <div>
        <label for="did-input" class="block text-sm font-medium text-slate-300 mb-1.5"
          >DID do agente</label
        >
        <input
          id="did-input"
          type="text"
          bind:value={did}
          placeholder="did:peer:2.Ez6LSbys..."
          class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      <div class="grid grid-cols-2 gap-4">
        <div>
          <label for="status-select" class="block text-sm font-medium text-slate-300 mb-1.5"
            >Status</label
          >
          <select
            id="status-select"
            bind:value={status}
            class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
          >
            <option value="revoked">Revoked (permanente até TTL)</option>
            <option value="suspended">Suspended (temporário)</option>
          </select>
        </div>
        <div>
          <label for="ttl-input" class="block text-sm font-medium text-slate-300 mb-1.5"
            >TTL (segundos)</label
          >
          <input
            id="ttl-input"
            type="number"
            bind:value={ttl}
            min="1"
            class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      <div>
        <label for="reason-input" class="block text-sm font-medium text-slate-300 mb-1.5"
          >Motivo (opcional)</label
        >
        <input
          id="reason-input"
          type="text"
          bind:value={reason}
          placeholder="Ex: prompt injection detectada"
          class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      <button
        type="submit"
        disabled={loading || !did.trim()}
        class="bg-rose-600 hover:bg-rose-500 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors"
      >
        {loading ? 'Revogando...' : 'Revogar'}
      </button>
    </form>
  </section>

  <section class="bg-slate-900 border border-slate-800 rounded-xl p-6">
    <h3 class="text-lg font-semibold text-slate-100 mb-4">
      Revogações Ativas ({revocations.length})
    </h3>
    {#if revocations.length === 0}
      <p class="text-slate-500 text-sm">Nenhuma revogação ativa.</p>
    {:else}
      <div class="space-y-2">
        {#each revocations as rev}
          <div
            class="flex items-center justify-between bg-slate-800/50 border border-slate-700 rounded-lg p-3"
          >
            <div class="flex-1 min-w-0">
              <p class="font-mono text-xs text-slate-200 truncate">{rev.did}</p>
              <div class="flex items-center gap-3 mt-1">
                <StatusBadge status={rev.status} />
                <span class="text-xs text-slate-500">{rev.ttl_seconds}s restantes</span>
                {#if rev.reason}
                  <span class="text-xs text-slate-400 truncate">— {rev.reason}</span>
                {/if}
              </div>
            </div>
            <button
              onclick={() => handleRestore(rev.did)}
              class="ml-4 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition-colors"
            >
              Restaurar
            </button>
          </div>
        {/each}
      </div>
    {/if}
  </section>
</div>
