<script lang="ts">
  let {
    label,
    value,
    icon = '',
    accent = 'blue'
  }: { label: string; value: string | number; icon?: string; accent?: 'blue' | 'green' | 'amber' | 'rose' } =
    $props()

  const accentColors: Record<string, string> = {
    blue: 'from-blue-500/20 to-blue-600/5 border-blue-500/30 text-blue-400',
    green: 'from-emerald-500/20 to-emerald-600/5 border-emerald-500/30 text-emerald-400',
    amber: 'from-amber-500/20 to-amber-600/5 border-amber-500/30 text-amber-400',
    rose: 'from-rose-500/20 to-rose-600/5 border-rose-500/30 text-rose-400'
  }
</script>

<div
  class="bg-gradient-to-br {accentColors[
    accent
  ]} border rounded-xl p-5"
>
  <div class="flex items-start justify-between">
    <div>
      <p class="text-sm text-slate-400 font-medium">{label}</p>
      <p class="text-3xl font-bold text-slate-100 mt-2">{value}</p>
    </div>
    {#if icon}
      <span class="text-2xl opacity-60">{icon}</span>
    {/if}
  </div>
</div>
