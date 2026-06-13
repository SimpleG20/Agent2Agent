<script lang="ts">
  import { onMount, onDestroy } from 'svelte'
  import { api } from '../../lib/api/client'
  import type { HealthResponse, DIDResponse, Revocation } from '../../lib/api/types'
  import StatusBadge from '../../lib/components/StatusBadge.svelte'
  import MetricCard from '../../lib/components/MetricCard.svelte'

  let health = $state<HealthResponse | null>(null)
  let did = $state<DIDResponse | null>(null)
  let revocations = $state<Revocation[]>([])
  let signRate = $state<number>(0)
  let signHistory = $state<number[]>(Array(60).fill(0))
  let loading = $state(true)
  let error = $state<string | null>(null)
  let interval: ReturnType<typeof setInterval> | null = null

  async function refresh() {
    try {
      const [h, d, r, m] = await Promise.all([
        api.health(),
        api.did(),
        api.listRevocations().catch(() => ({ revocations: [] })),
        api.metrics().catch(() => '')
      ])
      health = h
      did = d
      revocations = r.revocations

      // Extract sign_requests_total from Prometheus
      const match = m.match(/sign_requests_total\{[^}]*outcome="accepted"[^}]*\}\s+(\d+)/)
      const total = match ? parseInt(match[1]) : 0
      const prev = signHistory[signHistory.length - 1] || 0
      const newCount = total - (signHistory[0] || 0)
      const delta = total - prev
      signRate = delta
      signHistory = [...signHistory.slice(1), delta]
      // store total implicitly via first slot
      signHistory[0] = total

      error = null
    } catch (e) {
      error = (e as Error).message
    } finally {
      loading = false
    }
  }

  onMount(() => {
    refresh()
    interval = setInterval(refresh, 10_000)
  })

  onDestroy(() => {
    if (interval) clearInterval(interval)
  })

  let maxRate = $derived(Math.max(...signHistory, 1))
</script>

<div class="space-y-8">
  <header>
    <h2 class="text-3xl font-bold text-slate-100">Dashboard</h2>
    <p class="text-slate-400 mt-1">Visão geral do Key Guard e revogações ativas</p>
  </header>

  {#if error}
    <div class="bg-rose-500/10 border border-rose-500/30 rounded-lg p-4 text-rose-400">
      ⚠️ Key Guard indisponível: {error}
    </div>
  {/if}

  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    <MetricCard
      label="Status do Serviço"
      value={health?.key_loaded ? 'Operacional' : 'Sem chave'}
      icon="🔐"
      accent={health?.key_loaded ? 'green' : 'rose'}
    />
    <MetricCard
      label="Redis"
      value={health?.redis_connected ? 'Conectado' : 'Desconectado'}
      icon="💾"
      accent={health?.redis_connected ? 'green' : 'rose'}
    />
    <MetricCard
      label="Uptime"
      value="{Math.floor((health?.uptime_seconds ?? 0) / 60)} min"
      icon="⏱️"
      accent="blue"
    />
    <MetricCard
      label="Revogações Ativas"
      value={revocations.length}
      icon="🚫"
      accent={revocations.length > 0 ? 'amber' : 'green'}
    />
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <section class="bg-slate-900 border border-slate-800 rounded-xl p-6">
      <h3 class="text-lg font-semibold text-slate-100 mb-4">Identidade do Serviço</h3>
      <div class="space-y-3 text-sm">
        <div>
          <span class="text-slate-500">DID</span>
          <p class="font-mono text-xs text-blue-400 break-all mt-1">{did?.did ?? '—'}</p>
        </div>
        <div>
          <span class="text-slate-500">Algoritmo</span>
          <p class="text-slate-200 mt-1">{did?.key_type ?? '—'}</p>
        </div>
        <div>
          <span class="text-slate-500">Public Key (multibase)</span>
          <p class="font-mono text-xs text-slate-300 break-all mt-1">
            {did?.public_key_multibase ?? '—'}
          </p>
        </div>
      </div>
    </section>

    <section class="bg-slate-900 border border-slate-800 rounded-xl p-6">
      <h3 class="text-lg font-semibold text-slate-100 mb-4">
        Taxa de Assinaturas (últimos 60min)
      </h3>
      <div class="h-32 flex items-end gap-0.5">
        {#each signHistory as count}
          <div
            class="flex-1 bg-blue-500/60 rounded-t transition-all hover:bg-blue-400"
            style="height: {(count / maxRate) * 100}%"
            title="{count} sign(s)"
          ></div>
        {/each}
      </div>
      <p class="text-xs text-slate-500 mt-2">Última janela: {signRate} assinatura(s)</p>
    </section>
  </div>

  <section class="bg-slate-900 border border-slate-800 rounded-xl p-6">
    <h3 class="text-lg font-semibold text-slate-100 mb-4">Revogações Ativas</h3>
    {#if revocations.length === 0}
      <p class="text-slate-500 text-sm">Nenhuma revogação ativa no momento.</p>
    {:else}
      <div class="space-y-2">
        {#each revocations as rev}
          <div
            class="flex items-center justify-between bg-slate-800/50 border border-slate-700 rounded-lg p-3"
          >
            <div class="flex-1 min-w-0">
              <p class="font-mono text-xs text-slate-300 truncate">{rev.did}</p>
              {#if rev.reason}
                <p class="text-xs text-slate-500 mt-1">Motivo: {rev.reason}</p>
              {/if}
            </div>
            <div class="flex items-center gap-3 ml-4">
              <span class="text-xs text-slate-500">{rev.ttl_seconds}s restantes</span>
              <StatusBadge status={rev.status} />
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </section>
</div>
