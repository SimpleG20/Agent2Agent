<script lang="ts">
  let {
    status = 'ok',
    label = ''
  }: {
    status?: 'ok' | 'error' | 'warning' | 'revoked' | 'suspended' | 'pending' | 'success'
    label?: string
  } = $props()

  const colors: Record<string, string> = {
    ok: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    success: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    error: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
    warning: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    revoked: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
    suspended: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    pending: 'bg-slate-500/20 text-slate-400 border-slate-500/30'
  }
</script>

<span
  class="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full border {colors[
    status
  ]}"
>
  <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
  {label || status}
</span>
