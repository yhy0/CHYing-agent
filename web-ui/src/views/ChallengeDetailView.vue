<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import MarkdownRender from 'markstream-vue'
import 'markstream-vue/index.css'
import { api, type Challenge, type Execution, type Discovery, type Writeup } from '@/composables/useApi'
import StatusBadge from '@/components/ui/StatusBadge.vue'

const route = useRoute()
const router = useRouter()
const id = computed(() => Number(route.params.id))

const challenge = ref<Challenge | null>(null)
const executions = ref<Execution[]>([])
const discoveries = ref<Discovery[]>([])
const writeup = ref<Writeup | null>(null)
const loading = ref(true)
const generating = ref(false)
const activeTab = ref<'executions' | 'discoveries' | 'writeup'>('executions')

async function fetchData() {
  loading.value = true
  try {
    const res = await api.getChallenge(id.value)
    challenge.value = res.challenge
    executions.value = res.executions
    discoveries.value = res.discoveries
    writeup.value = res.writeup
  } finally {
    loading.value = false
  }
}

async function generateWriteup() {
  generating.value = true
  try {
    writeup.value = await api.generateWriteup(id.value)
    activeTab.value = 'writeup'
  } catch (e) {
    console.error('Writeup generation failed:', e)
  } finally {
    generating.value = false
  }
}

onMounted(fetchData)

function formatTime(s: string) {
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
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

const challengeTotalCost = computed(() =>
  executions.value.reduce((sum, ex) => sum + (ex.total_cost_usd || 0), 0)
)

const challengeTotalTokens = computed(() => ({
  input:  executions.value.reduce((sum, ex) => sum + (ex.input_tokens || 0), 0),
  output: executions.value.reduce((sum, ex) => sum + (ex.output_tokens || 0), 0),
}))

const successCount = computed(() => executions.value.filter(e => e.status === 'success').length)

const severityConfig: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: '#f87171', bg: 'rgba(248,113,113,0.08)', border: 'rgba(248,113,113,0.25)' },
  high:     { text: '#fb923c', bg: 'rgba(251,146,60,0.08)',  border: 'rgba(251,146,60,0.25)'  },
  medium:   { text: '#fbbf24', bg: 'rgba(251,191,36,0.08)', border: 'rgba(251,191,36,0.25)' },
  low:      { text: '#60a5fa', bg: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.25)' },
  info:     { text: '#94a3b8', bg: 'rgba(148,163,184,0.06)', border: 'rgba(148,163,184,0.18)' },
}

function getSeverityStyle(s: string | null) {
  return severityConfig[s || ''] ?? severityConfig['info']!
}
</script>

<template>
  <div class="space-y-6">

    <!-- Back navigation -->
    <button
      class="flex items-center gap-1.5 text-sm text-white/35 hover:text-white/70 transition-colors group cursor-pointer"
      @click="router.push('/challenges')"
    >
      <svg class="w-4 h-4 transition-transform group-hover:-translate-x-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
        <path d="M15 19l-7-7 7-7" />
      </svg>
      Challenges
    </button>

    <!-- Loading state -->
    <div v-if="loading" class="space-y-4">
      <div class="skeleton h-36 rounded-xl"></div>
      <div class="skeleton h-72 rounded-xl"></div>
    </div>

    <template v-else-if="challenge">

      <!-- Challenge header card -->
      <div class="glass rounded-xl overflow-hidden">
        <!-- Top accent bar with gradient -->
        <div
          class="h-[3px]"
          :style="challenge.latest_status === 'success'
            ? 'background: linear-gradient(90deg, rgba(0,255,65,0.8), rgba(0,255,65,0.2));'
            : challenge.latest_status === 'failed'
              ? 'background: linear-gradient(90deg, rgba(255,77,77,0.8), rgba(255,77,77,0.2));'
              : challenge.latest_status === 'running'
                ? 'background: linear-gradient(90deg, rgba(0,212,255,0.8), rgba(0,212,255,0.2));'
                : 'background: linear-gradient(90deg, rgba(255,255,255,0.2), rgba(255,255,255,0.05));'"
        />

        <div class="p-6">
          <!-- Title row -->
          <div class="flex items-start justify-between gap-4 mb-4">
            <div class="min-w-0">
              <div class="flex items-center gap-2.5 flex-wrap mb-2">
                <h1 class="font-heading text-xl font-bold text-white/95">{{ challenge.challenge_code }}</h1>
                <span class="tag text-white/40" style="background:rgba(255,255,255,0.04);border-color:rgba(255,255,255,0.09);">
                  {{ challenge.mode }}
                </span>
                <span
                  v-if="challenge.difficulty"
                  class="tag capitalize"
                  :style="challenge.difficulty === 'hard' || challenge.difficulty === 'expert'
                    ? 'color:#f97316;background:rgba(249,115,22,0.08);border-color:rgba(249,115,22,0.2);'
                    : challenge.difficulty === 'medium'
                      ? 'color:#eab308;background:rgba(234,179,8,0.08);border-color:rgba(234,179,8,0.2);'
                      : 'color:#3b82f6;background:rgba(59,130,246,0.08);border-color:rgba(59,130,246,0.2);'"
                >{{ challenge.difficulty }}</span>
                <span
                  v-if="challenge.points"
                  class="tag"
                  style="color:var(--accent-purple);background:rgba(168,85,247,0.08);border-color:rgba(168,85,247,0.2);"
                >{{ challenge.points }} pts</span>
              </div>
            </div>
            <StatusBadge :status="challenge.latest_status" pill />
          </div>

          <!-- Target info -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-sm mb-4">
            <div v-if="challenge.target_url" class="kv-row">
              <span class="kv-label">URL</span>
              <span class="kv-value" style="color: var(--accent-cyan);">{{ challenge.target_url }}</span>
            </div>
            <div v-if="challenge.target_ip" class="kv-row">
              <span class="kv-label">IP</span>
              <span class="kv-value">{{ challenge.target_ip }}</span>
            </div>
            <div v-if="challenge.flag" class="kv-row sm:col-span-2">
              <span class="kv-label">Flag</span>
              <span class="kv-value font-semibold" style="color: var(--accent-green);">{{ challenge.flag }}</span>
            </div>
            <div v-if="challenge.hint_content" class="kv-row sm:col-span-2">
              <span class="kv-label">Hint</span>
              <span class="text-xs text-white/55 leading-relaxed">{{ challenge.hint_content }}</span>
            </div>
          </div>

          <!-- Stats row -->
          <div
            v-if="executions.length > 0"
            class="flex flex-wrap items-center gap-5 pt-4"
            style="border-top: 1px solid rgba(255,255,255,0.05);"
          >
            <div class="flex items-baseline gap-1.5">
              <span class="text-lg font-heading font-bold" style="color: #eab308;">{{ formatCost(challengeTotalCost) }}</span>
              <span class="text-[11px] text-white/30">total cost</span>
            </div>
            <div v-if="challengeTotalTokens.input > 0" class="flex items-baseline gap-1.5">
              <span class="text-sm font-mono font-medium text-white/60">{{ challengeTotalTokens.input.toLocaleString() }}</span>
              <span class="text-[11px] text-white/30">in</span>
              <span class="text-sm font-mono font-medium text-white/60">{{ challengeTotalTokens.output.toLocaleString() }}</span>
              <span class="text-[11px] text-white/30">out tokens</span>
            </div>
            <div class="flex items-baseline gap-1.5">
              <span class="text-sm font-mono font-medium text-white/60">{{ executions.length }}</span>
              <span class="text-[11px] text-white/30">run{{ executions.length !== 1 ? 's' : '' }}</span>
            </div>
            <div v-if="successCount > 0" class="flex items-baseline gap-1.5">
              <span class="text-sm font-mono font-medium" style="color: var(--accent-green);">{{ successCount }}</span>
              <span class="text-[11px] text-white/30">success</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab strip -->
      <div class="tab-strip w-fit">
        <button
          v-for="tab in (['executions', 'discoveries', 'writeup'] as const)"
          :key="tab"
          class="tab-btn capitalize flex items-center gap-1.5"
          :class="activeTab === tab ? 'active' : ''"
          @click="activeTab = tab"
        >
          {{ tab }}
          <span
            v-if="tab === 'executions' && executions.length"
            class="badge badge-muted"
          >{{ executions.length }}</span>
          <span
            v-if="tab === 'discoveries' && discoveries.length"
            class="badge badge-muted"
          >{{ discoveries.length }}</span>
        </button>
      </div>

      <!-- ── Executions Tab ── -->
      <div v-if="activeTab === 'executions'">
        <div v-if="executions.length > 0" class="glass rounded-xl overflow-hidden">
          <div
            v-for="ex in executions"
            :key="ex.id"
            class="flex items-center justify-between gap-4 px-5 py-3.5 cursor-pointer transition-colors duration-100 group"
            style="border-bottom: 1px solid rgba(255,255,255,0.025);"
            :style="{ background: 'transparent' }"
            @mouseenter="($event.currentTarget as HTMLElement).style.background='rgba(255,255,255,0.025)'"
            @mouseleave="($event.currentTarget as HTMLElement).style.background='transparent'"
            @click="router.push(`/executions/${ex.id}`)"
          >
            <div class="flex items-center gap-3">
              <span class="font-mono text-[11px] text-white/30 w-10 shrink-0">#{{ ex.id }}</span>
              <StatusBadge :status="ex.status" size="sm" pill />
              <span class="text-[11px] text-white/25">Attempt {{ ex.attempt_number }}</span>
            </div>
            <div class="flex items-center gap-4 text-[11px]">
              <span v-if="ex.flag" class="font-mono max-w-[160px] truncate hidden sm:inline" style="color: var(--accent-green);">
                {{ ex.flag }}
              </span>
              <span v-if="ex.total_cost_usd" class="font-mono font-medium hidden sm:inline" style="color: #eab308;">
                {{ formatCost(ex.total_cost_usd) }}
              </span>
              <span class="font-mono text-white/35">{{ formatElapsed(ex.elapsed_seconds) }}</span>
              <span class="text-white/20">{{ formatTime(ex.started_at) }}</span>
              <svg class="w-3.5 h-3.5 text-white/15 transition-transform group-hover:translate-x-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                <path d="M9 5l7 7-7 7" />
              </svg>
            </div>
          </div>
        </div>
        <div v-else class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-2">
          <div class="text-3xl opacity-15">◎</div>
          <p class="text-white/30 text-sm">No executions yet</p>
        </div>
      </div>

      <!-- ── Discoveries Tab ── -->
      <div v-if="activeTab === 'discoveries'">
        <div v-if="discoveries.length > 0" class="space-y-3">
          <div
            v-for="d in discoveries"
            :key="d.id"
            class="glass rounded-xl p-5"
          >
            <!-- Header -->
            <div class="flex items-start justify-between gap-3 mb-3">
              <div class="flex items-center gap-2 flex-wrap">
                <span
                  class="tag capitalize"
                  :style="`color:${getSeverityStyle(d.severity).text};background:${getSeverityStyle(d.severity).bg};border-color:${getSeverityStyle(d.severity).border};`"
                >{{ d.severity || 'info' }}</span>
                <span class="font-mono text-[11px] text-white/35 px-1.5 py-0.5 rounded bg-white/4">{{ d.discovery_type }}</span>
              </div>
              <span class="text-[11px] text-white/20 shrink-0">Exec #{{ d.execution_id }}</span>
            </div>
            <h3 class="text-sm font-semibold text-white/90 mb-2">{{ d.title }}</h3>
            <p v-if="d.description" class="text-xs text-white/50 leading-relaxed mb-3">{{ d.description }}</p>
            <div v-if="d.evidence" class="rounded-lg overflow-hidden" style="background:rgba(0,0,0,0.4);border:1px solid rgba(255,255,255,0.06);">
              <div class="px-3 py-1.5 border-b border-white/5 text-[10px] text-white/30 uppercase tracking-wider font-medium">Evidence</div>
              <pre class="font-mono text-[11px] text-white/55 p-3 whitespace-pre-wrap break-all leading-relaxed">{{ d.evidence }}</pre>
            </div>
          </div>
        </div>
        <div v-else class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-2">
          <div class="text-3xl opacity-15">◈</div>
          <p class="text-white/30 text-sm">No discoveries recorded</p>
        </div>
      </div>

      <!-- ── Writeup Tab ── -->
      <div v-if="activeTab === 'writeup'">
        <div v-if="writeup" class="glass rounded-xl p-6">
          <div class="flex items-center justify-between mb-5" style="border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 1rem;">
            <span class="text-xs text-white/30">Generated {{ formatTime(writeup.generated_at) }}</span>
            <button
              class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-all"
              style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);color:rgba(255,255,255,0.5);"
              :disabled="generating"
              @mouseenter="($event.currentTarget as HTMLElement).style.borderColor='rgba(255,255,255,0.15)'"
              @mouseleave="($event.currentTarget as HTMLElement).style.borderColor='rgba(255,255,255,0.08)'"
              @click="generateWriteup"
            >
              <svg v-if="generating" class="w-3 h-3 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
                <path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {{ generating ? 'Regenerating…' : 'Regenerate' }}
            </button>
          </div>
          <MarkdownRender :content="writeup.content_markdown" class="markdown-body" />
        </div>
        <div v-else class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-4">
          <div class="text-4xl opacity-15">◧</div>
          <p class="text-white/30 text-sm">No writeup generated yet</p>
          <button
            class="px-5 py-2 rounded-lg text-sm font-semibold cursor-pointer transition-all"
            style="background:rgba(0,255,65,0.1);border:1px solid rgba(0,255,65,0.25);color:var(--accent-green);"
            :disabled="generating"
            @mouseenter="($event.currentTarget as HTMLElement).style.background='rgba(0,255,65,0.15)'"
            @mouseleave="($event.currentTarget as HTMLElement).style.background='rgba(0,255,65,0.1)'"
            @click="generateWriteup"
          >
            {{ generating ? 'Generating…' : 'Generate Writeup' }}
          </button>
        </div>
      </div>

    </template>
  </div>
</template>
