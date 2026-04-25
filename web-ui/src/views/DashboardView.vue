<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { api, useAsync } from '@/composables/useApi'
import StatusBadge from '@/components/ui/StatusBadge.vue'

const router = useRouter()
const { data: stats, loading, execute } = useAsync(() => api.getDashboardStats())

onMounted(execute)

function formatTime(s: string) {
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(new Date(s))
}

function formatElapsed(sec: number | null) {
  if (sec == null) return '—'
  if (sec < 60) return `${sec.toFixed(0)}s`
  return `${Math.floor(sec / 60)}m ${(sec % 60).toFixed(0)}s`
}

function formatCost(usd: number | null) {
  if (usd == null || usd === 0) return '—'
  return `$${usd.toFixed(4)}`
}

function formatTokens(n: number | null) {
  if (n == null || n === 0) return '—'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

const successRate = computed(() => {
  if (!stats.value) return null
  const total = stats.value.success_count + stats.value.failed_count
  if (!total) return null
  return Math.round((stats.value.success_count / total) * 100)
})

interface StatCard {
  label: string
  value: string | number
  color: string
  accentColor: string
  icon: string
  small?: boolean
}

const statCards = computed((): StatCard[] => {
  if (!stats.value) return []
  const s = stats.value
  return [
    { label: 'Total Challenges', value: s.total_challenges, color: 'text-white/90', accentColor: 'rgba(255,255,255,0.3)', icon: '⬡' },
    { label: 'Success', value: s.success_count, color: 'text-[var(--accent-green)]', accentColor: 'var(--accent-green)', icon: '✓' },
    { label: 'Failed', value: s.failed_count, color: 'text-[#ff4d4d]', accentColor: '#ff4d4d', icon: '✗' },
    { label: 'Running', value: s.running_count, color: 'text-[var(--accent-cyan)]', accentColor: 'var(--accent-cyan)', icon: '◎' },
    { label: 'Discoveries', value: s.total_discoveries, color: 'text-[var(--accent-purple)]', accentColor: 'var(--accent-purple)', icon: '◈' },
    { label: 'Writeups', value: s.total_writeups, color: 'text-[var(--accent-orange)]', accentColor: 'var(--accent-orange)', icon: '◧' },
    { label: 'Total Cost', value: formatCost(s.total_cost_usd), color: 'text-[#eab308]', accentColor: '#eab308', icon: '$', small: true },
    { label: 'Total Tokens', value: formatTokens((s.total_input_tokens || 0) + (s.total_output_tokens || 0)), color: 'text-[#94a3b8]', accentColor: '#94a3b8', icon: '◫', small: true },
  ]
})
</script>

<template>
  <div class="space-y-8">

    <!-- Page header -->
    <div class="flex items-end justify-between">
      <div>
        <p class="text-xs text-white/30 uppercase tracking-widest font-medium mb-1">Overview</p>
        <h1 class="font-heading text-2xl font-bold text-white">Dashboard</h1>
      </div>
      <!-- Success rate pill -->
      <div
        v-if="successRate !== null"
        class="flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-semibold"
        style="background: rgba(0,255,65,0.08); border: 1px solid rgba(0,255,65,0.2); color: var(--accent-green);"
      >
        <span class="status-dot status-dot-success"></span>
        {{ successRate }}% success rate
      </div>
    </div>

    <!-- Stats Grid -->
    <div v-if="loading" class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
      <div v-for="i in 8" :key="i" class="skeleton h-[88px] rounded-xl"></div>
    </div>

    <div v-else-if="stats" class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
      <div
        v-for="card in statCards"
        :key="card.label"
        class="glass glass-hover glow-border rounded-xl px-4 py-4 cursor-default relative overflow-hidden"
      >
        <!-- Accent top bar -->
        <div
          class="absolute top-0 left-0 right-0 h-[2px] rounded-t-xl opacity-60"
          :style="`background: ${card.accentColor};`"
        />
        <!-- Subtle glow blob -->
        <div
          class="absolute -top-4 -right-4 w-16 h-16 rounded-full opacity-10 blur-xl pointer-events-none"
          :style="`background: ${card.accentColor};`"
        />

        <div class="relative">
          <div class="text-[10px] text-white/35 uppercase tracking-wider font-medium mb-2 leading-none">
            {{ card.label }}
          </div>
          <div
            class="font-heading font-bold leading-none"
            :class="[card.color, card.small ? 'text-[1.35rem]' : 'text-[1.75rem]']"
          >
            {{ card.value }}
          </div>
        </div>
      </div>
    </div>

    <!-- Recent Executions -->
    <div>
      <div class="flex items-center justify-between mb-3">
        <h2 class="font-heading text-base font-semibold text-white/80">Recent Executions</h2>
        <router-link
          to="/challenges"
          class="text-xs text-white/35 hover:text-white/70 transition-colors"
        >
          View all →
        </router-link>
      </div>

      <!-- Loading -->
      <div v-if="loading" class="glass rounded-xl overflow-hidden">
        <div class="p-5 space-y-3">
          <div v-for="i in 5" :key="i" class="skeleton h-9 rounded-lg"></div>
        </div>
      </div>

      <!-- Table -->
      <div v-else-if="stats && stats.recent_executions.length > 0" class="glass rounded-xl overflow-hidden">
        <table class="w-full text-sm" role="table">
          <thead>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
              <th class="text-left px-5 py-3 text-[10px] uppercase tracking-wider text-white/30 font-medium">ID</th>
              <th class="text-left px-5 py-3 text-[10px] uppercase tracking-wider text-white/30 font-medium">Challenge</th>
              <th class="text-left px-5 py-3 text-[10px] uppercase tracking-wider text-white/30 font-medium">Status</th>
              <th class="text-left px-5 py-3 text-[10px] uppercase tracking-wider text-white/30 font-medium hidden md:table-cell">Flag</th>
              <th class="text-right px-5 py-3 text-[10px] uppercase tracking-wider text-white/30 font-medium hidden sm:table-cell">Duration</th>
              <th class="text-right px-5 py-3 text-[10px] uppercase tracking-wider text-white/30 font-medium hidden sm:table-cell">Cost</th>
              <th class="text-right px-5 py-3 text-[10px] uppercase tracking-wider text-white/30 font-medium">Started</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="ex in stats.recent_executions"
              :key="ex.id"
              class="group cursor-pointer transition-colors duration-100"
              style="border-bottom: 1px solid rgba(255,255,255,0.025);"
              :style="{ background: 'transparent' }"
              @mouseenter="($event.currentTarget as HTMLElement).style.background='rgba(255,255,255,0.025)'"
              @mouseleave="($event.currentTarget as HTMLElement).style.background='transparent'"
              @click="router.push(`/executions/${ex.id}`)"
            >
              <td class="px-5 py-3 font-mono text-[11px] text-white/35">#{{ ex.id }}</td>
              <td class="px-5 py-3">
                <router-link
                  :to="`/challenges/${ex.challenge_id}`"
                  class="font-mono text-[11px] transition-colors"
                  style="color: var(--accent-cyan);"
                  @click.stop
                >
                  #{{ ex.challenge_id }}
                </router-link>
              </td>
              <td class="px-5 py-3">
                <StatusBadge :status="ex.status" size="sm" pill />
              </td>
              <td class="px-5 py-3 hidden md:table-cell">
                <span
                  v-if="ex.flag"
                  class="font-mono text-[11px] max-w-[180px] truncate block"
                  style="color: var(--accent-green);"
                >{{ ex.flag }}</span>
                <span v-else class="text-white/20 text-[11px]">—</span>
              </td>
              <td class="px-5 py-3 text-right text-white/40 text-[11px] font-mono hidden sm:table-cell">
                {{ formatElapsed(ex.elapsed_seconds) }}
              </td>
              <td class="px-5 py-3 text-right text-[11px] font-mono font-medium hidden sm:table-cell"
                  style="color: #eab308;">
                {{ formatCost(ex.total_cost_usd) }}
              </td>
              <td class="px-5 py-3 text-right text-white/30 text-[11px]">
                {{ formatTime(ex.started_at) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-3">
        <div class="text-3xl opacity-20">◎</div>
        <p class="text-white/30 text-sm">No executions yet</p>
      </div>
    </div>

  </div>
</template>
