<script lang="ts">
  import { api } from '../../lib/api/client'
  import type { SigningIntent, SignResult } from '../../lib/api/types'
  import StatusBadge from '../../lib/components/StatusBadge.svelte'

  let action = $state<'a2a.message.sign' | 'a2a.credential.issue' | 'did.update'>(
    'a2a.message.sign'
  )
  let content = $state('Hello from Agent Alpha')
  let contentType = $state('text/plain')
  let recipientDid = $state('did:peer:2.Ez6LSbysY2xF4hDAdYxQ7Y2Lc9M3Wq6u5xj4PxK2C4H5N8mZkV')
  let agentId = $state('agent-alpha')
  let nonce = $state(crypto.randomUUID())
  let loading = $state(false)
  let result = $state<SignResult | null>(null)
  let error = $state<string | null>(null)
  let history = $state<Array<{ intent: SigningIntent; result: SignResult; ts: number }>>([])

  function randomizeNonce() {
    nonce = crypto.randomUUID()
  }

  async function handleSign(e: Event) {
    e.preventDefault()
    loading = true
    error = null
    result = null

    const intent: SigningIntent = {
      action,
      payload: {
        content,
        content_type: contentType,
        recipient_did: recipientDid
      },
      agent_id: agentId,
      timestamp: Math.floor(Date.now() / 1000),
      nonce
    }

    try {
      const res = await api.sign(intent)
      result = res
      history = [{ intent, result: res, ts: Date.now() }, ...history].slice(0, 10)
    } catch (e) {
      error = (e as Error).message
    } finally {
      loading = false
    }
  }
</script>

<div class="space-y-8 max-w-6xl">
  <header>
    <h2 class="text-3xl font-bold text-slate-100">Playground</h2>
    <p class="text-slate-400 mt-1">Construa um SigningIntent e teste a assinatura JWS</p>
  </header>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <section class="bg-slate-900 border border-slate-800 rounded-xl p-6">
      <h3 class="text-lg font-semibold text-slate-100 mb-4">SigningIntent</h3>
      <form onsubmit={handleSign} class="space-y-4">
        <div>
          <label for="action-select" class="block text-sm font-medium text-slate-300 mb-1.5"
            >Ação</label
          >
          <select
            id="action-select"
            bind:value={action}
            class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
          >
            <option value="a2a.message.sign">a2a.message.sign</option>
            <option value="a2a.credential.issue">a2a.credential.issue</option>
            <option value="did.update">did.update</option>
          </select>
        </div>

        <div>
          <label for="content-input" class="block text-sm font-medium text-slate-300 mb-1.5"
            >Content</label
          >
          <textarea
            id="content-input"
            bind:value={content}
            rows="3"
            class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 font-mono focus:outline-none focus:border-blue-500"
          ></textarea>
        </div>

        <div>
          <label for="contenttype-input" class="block text-sm font-medium text-slate-300 mb-1.5"
            >Content Type</label
          >
          <input
            id="contenttype-input"
            type="text"
            bind:value={contentType}
            class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div>
          <label for="recipient-input" class="block text-sm font-medium text-slate-300 mb-1.5"
            >Recipient DID</label
          >
          <input
            id="recipient-input"
            type="text"
            bind:value={recipientDid}
            class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label for="agent-input" class="block text-sm font-medium text-slate-300 mb-1.5"
              >Agent ID</label
            >
            <input
              id="agent-input"
              type="text"
              bind:value={agentId}
              class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label for="nonce-input" class="block text-sm font-medium text-slate-300 mb-1.5"
              >Nonce</label
            >
            <div class="flex gap-1">
              <input
                id="nonce-input"
                type="text"
                bind:value={nonce}
                class="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-blue-500"
              />
              <button
                type="button"
                onclick={randomizeNonce}
                class="bg-slate-700 hover:bg-slate-600 text-slate-200 px-2 rounded-lg text-xs"
                title="Gerar novo nonce"
              >
                🎲
              </button>
            </div>
          </div>
        </div>

        <button
          type="submit"
          disabled={loading}
          class="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-medium px-4 py-2.5 rounded-lg text-sm transition-colors"
        >
          {loading ? 'Assinando...' : '✍️ Assinar Intent'}
        </button>
      </form>
    </section>

    <section class="bg-slate-900 border border-slate-800 rounded-xl p-6">
      <h3 class="text-lg font-semibold text-slate-100 mb-4">Resultado</h3>
      {#if error}
        <div
          class="bg-rose-500/10 border border-rose-500/30 rounded-lg p-4 text-rose-400 text-sm"
        >
          <p class="font-semibold mb-1">Erro</p>
          <p class="font-mono text-xs">{error}</p>
        </div>
      {/if}

      {#if result}
        <div class="space-y-3">
          <div class="flex items-center gap-2">
            <StatusBadge status={result.status === 'signed' ? 'success' : 'error'} />
            <span class="text-xs text-slate-500">request_id: {result.request_id}</span>
          </div>

          {#if result.did}
            <div>
              <span class="text-xs text-slate-500">DID</span>
              <p class="font-mono text-xs text-blue-400 break-all">{result.did}</p>
            </div>
          {/if}

          {#if result.envelope}
            <div>
              <span class="text-xs text-slate-500">Envelope JWS</span>
              <pre
                class="mt-1 bg-slate-950 border border-slate-800 rounded p-3 text-xs font-mono text-emerald-300 overflow-x-auto">{JSON.stringify(
                  result.envelope,
                  null,
                  2
                )}</pre>
            </div>
          {/if}

          {#if result.reason}
            <div>
              <span class="text-xs text-slate-500">Motivo</span>
              <p class="text-sm text-amber-400">{result.reason}</p>
            </div>
          {/if}
        </div>
      {:else if !error}
        <p class="text-slate-500 text-sm">Aguardando primeira assinatura...</p>
      {/if}
    </section>
  </div>

  {#if history.length > 0}
    <section class="bg-slate-900 border border-slate-800 rounded-xl p-6">
      <h3 class="text-lg font-semibold text-slate-100 mb-4">Histórico (sessão)</h3>
      <div class="space-y-2">
        {#each history as h}
          <div
            class="flex items-center justify-between bg-slate-800/30 border border-slate-700/50 rounded p-2 text-xs"
          >
            <span class="text-slate-500">
              {new Date(h.ts).toLocaleTimeString()}
            </span>
            <span class="font-mono text-slate-400">{h.intent.action}</span>
            <StatusBadge status={h.result.status === 'signed' ? 'success' : 'error'} />
          </div>
        {/each}
      </div>
    </section>
  {/if}
</div>
