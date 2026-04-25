<script setup lang="ts">
import { ref, onMounted, computed, nextTick, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import MarkdownRender from 'markstream-vue'
import 'markstream-vue/index.css'
import { api, type Execution, type Discovery, type TranscriptResponse, type SessionStep, type LogResponse } from '@/composables/useApi'
import { useFlowGraph } from '@/composables/useFlowGraph'
import StatusBadge from '@/components/ui/StatusBadge.vue'
import FlowDiagram from '@/components/flow/FlowDiagram.vue'

const route = useRoute()
const router = useRouter()
const id = computed(() => Number(route.params.id))

const execution = ref<Execution | null>(null)
const discoveries = ref<Discovery[]>([])
const transcript = ref<TranscriptResponse | null>(null)
const loading = ref(true)
const transcriptLoading = ref(false)
const transcriptPage = ref(1)
const activeTab = ref<'transcript' | 'log' | 'discoveries' | 'subagents' | 'writeup'>('transcript')
const expandedSubagent = ref<string | null>(null)
const writeupMarkdown = ref<string | null>(null)
const writeupLoading = ref(false)

// Log tab state
const logData = ref<LogResponse | null>(null)
const logLoading = ref(false)
const logPage = ref(1)
const expandedLogIdx = ref<Set<number>>(new Set())

// Categorize log entries for conversation layout
type ChatSide = 'right' | 'left' | 'center'

const RIGHT_TYPES = new Set(['system_init', 'prompt_ready', 'challenge_start', 'header'])
const LEFT_TYPES  = new Set(['thinking', 'text_response', 'tool_call', 'tool_result', 'tool_error', 'orchestrator_event'])
// Everything else → center

function getChatSide(entry: { event_type: string; source: string }): ChatSide {
  if (RIGHT_TYPES.has(entry.event_type)) return 'right'
  if (LEFT_TYPES.has(entry.event_type))  return 'left'
  if (entry.source === 'TOOL')           return 'left'
  return 'center'
}

function getKvText(entry: { event_type: string; kv: Record<string, unknown> }): string | null {
  if (entry.event_type === 'thinking') {
    // Reassemble thinking across _extra_N keys
    const parts: string[] = []
    const base = entry.kv['thinking']
    if (typeof base === 'string' && base) parts.push(base)
    let i = 1
    while (true) {
      const extra = entry.kv[`thinking_extra_${i}`]
      if (extra === undefined) break
      if (typeof extra === 'string' && extra) parts.push(extra)
      i++
    }
    return parts.length ? parts.join('') : null
  }
  if (entry.event_type === 'text_response') {
    const t = entry.kv['text']
    return typeof t === 'string' ? t : null
  }
  return null
}

// Flow graph interaction state
const highlightedNodeId = ref<string | null>(null)
const highlightedSteps = ref<Set<number>>(new Set())
const stepRefs = ref<Record<number, HTMLElement>>({})

const { getNodeIdForStep } = useFlowGraph(transcript)

async function fetchData() {
  loading.value = true
  try {
    const res = await api.getExecution(id.value)
    execution.value = res.execution
    discoveries.value = res.discoveries
    if (res.execution.has_transcript) {
      await fetchTranscript()
    }
    await fetchWriteup()
  } finally {
    loading.value = false
  }
}

async function fetchTranscript() {
  transcriptLoading.value = true
  try {
    transcript.value = await api.getTranscript(id.value, transcriptPage.value, 50)
  } catch { /* no transcript */ } finally {
    transcriptLoading.value = false
  }
}

async function fetchWriteup() {
  writeupLoading.value = true
  try {
    const res = await api.getExecutionWriteup(id.value)
    writeupMarkdown.value = res.content
  } catch { /* no writeup */ } finally {
    writeupLoading.value = false
  }
}

async function fetchLog() {
  logLoading.value = true
  try {
    logData.value = await api.getLog(id.value, logPage.value, 500)
  } catch { /* no log */ } finally {
    logLoading.value = false
  }
}

onMounted(fetchData)

watch(activeTab, (tab) => {
  if (tab === 'log' && logData.value === null && !logLoading.value) {
    fetchLog()
  }
})

function changeLogPage(p: number) {
  logPage.value = p
  fetchLog()
}

function toggleLogEntry(idx: number) {
  const s = new Set(expandedLogIdx.value)
  s.has(idx) ? s.delete(idx) : s.add(idx)
  expandedLogIdx.value = s
}

// ── Per-agent color system ──
interface AgentStyle { dotClass: string; badgeStyle: string; borderStyle: string }
function getAgentStyle(source: string, agent: string | null, eventType: string): AgentStyle {
  const ag = (agent || '').toLowerCase()
  const mk = (dotClass: string, color: string): AgentStyle => ({
    dotClass,
    badgeStyle: `color:${color};background:${color}18;`,
    borderStyle: `border-left-color:${color}60;`,
  })

  if (source === 'TOOL') {
    if (eventType === 'tool_call')   return { dotClass: 'bg-[#f97316]',              badgeStyle: 'color:#f97316;background:#f9731618;',  borderStyle: 'border-left-color:#f9731650;' }
    if (eventType === 'tool_result') return { dotClass: 'bg-[var(--accent-purple)]', badgeStyle: 'color:#a855f7;background:#a855f718;', borderStyle: 'border-left-color:#a855f750;' }
    if (eventType === 'tool_error')  return { dotClass: 'bg-red-400',                badgeStyle: 'color:#f87171;background:#f8717118;',  borderStyle: 'border-left-color:#f8717150;' }
    return { dotClass: 'bg-white/20', badgeStyle: 'color:rgba(255,255,255,0.35);background:rgba(255,255,255,0.05);', borderStyle: 'border-left-color:rgba(255,255,255,0.08);' }
  }
  if (source === 'RAW') return { dotClass: 'bg-white/15', badgeStyle: 'color:rgba(255,255,255,0.25);background:rgba(255,255,255,0.04);', borderStyle: 'border-left-color:rgba(255,255,255,0.05);' }

  if (ag.includes('promptcompiler') || ag.includes('prompt'))
    return mk('bg-[var(--accent-green)]', 'var(--accent-green)')
  if (ag.includes('orchestrator'))
    return mk('bg-[var(--accent-cyan)]', 'var(--accent-cyan)')
  if (ag.includes('executor'))
    return mk('bg-[#f97316]', '#f97316')
  if (ag.includes('browser'))
    return mk('bg-[var(--accent-purple)]', '#a855f7')
  if (ag.includes('reverse'))
    return mk('bg-[#ec4899]', '#ec4899')
  if (ag.includes('recon') || ag.includes('侦察'))
    return mk('bg-[#3b82f6]', '#3b82f6')
  if (ag.includes('httpx') || ag.includes('mcp'))
    return mk('bg-[#a78bfa]', '#a78bfa')

  return { dotClass: 'bg-white/20', badgeStyle: 'color:rgba(255,255,255,0.35);background:rgba(255,255,255,0.05);', borderStyle: 'border-left-color:rgba(255,255,255,0.07);' }
}

const eventTypeIcon: Record<string, string> = {
  thinking: '💭', tool_call: '🔧', tool_result: '✅', tool_error: '❌',
  token_usage: '💰', text_response: '📝', header: '📌', system_init: '🚀',
  recon: '🔍', compile: '⚙️', exec_done: '🏁', prompt_ready: '📋', challenge_start: '🎯',
}

// ── Step type → visual ──
const stepTypeConfig: Record<string, { borderStyle: string; color: string; label: string; icon: string }> = {
  user_message: { borderStyle: 'border-left-color:var(--accent-cyan);',    color: 'var(--accent-cyan)',    label: 'User',        icon: 'U' },
  thinking:     { borderStyle: 'border-left-color:var(--accent-green);',   color: 'var(--accent-green)',   label: 'Thinking',    icon: '💭' },
  tool_call:    { borderStyle: 'border-left-color:#f97316;',               color: '#f97316',               label: 'Tool Call',   icon: '🔧' },
  tool_result:  { borderStyle: 'border-left-color:var(--accent-purple);',  color: 'var(--accent-purple)',  label: 'Result',      icon: '✅' },
  summary:      { borderStyle: 'border-left-color:rgba(255,255,255,0.15);',color: 'rgba(255,255,255,0.4)', label: 'Summary',     icon: '📋' },
}

function getStepConfig(type: string) {
  return stepTypeConfig[type] || {
    borderStyle: 'border-left-color:rgba(255,255,255,0.08);',
    color: 'rgba(255,255,255,0.35)',
    label: type,
    icon: '·',
  }
}

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

function formatTokens(n: number | null) {
  if (n == null || n === 0) return '—'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

function formatContent(v: unknown): string {
  if (v == null) return ''
  if (typeof v === 'string') return v
  return JSON.stringify(v, null, 2)
}

function changePage(p: number) {
  transcriptPage.value = p
  highlightedNodeId.value = null
  highlightedSteps.value = new Set()
  fetchTranscript()
}

function toggleSubagent(agentId: string | null) {
  if (!agentId) return
  expandedSubagent.value = expandedSubagent.value === agentId ? null : agentId
}

function onFlowNodeClick(nodeId: string, stepIndices: number[]) {
  highlightedNodeId.value = nodeId
  highlightedSteps.value = new Set(stepIndices)
  if (stepIndices.length > 0) {
    nextTick(() => {
      const el = stepRefs.value[stepIndices[0]!]
      el?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    })
  }
}

function onStepClick(step: SessionStep, idx: number) {
  const nodeId = getNodeIdForStep(step)
  if (nodeId) {
    highlightedNodeId.value = highlightedNodeId.value === nodeId ? null : nodeId
    highlightedSteps.value = highlightedNodeId.value ? new Set([idx]) : new Set()
  }
}

function setStepRef(idx: number, el: any) {
  if (el) stepRefs.value[idx] = el
}

// Severity config shared between discoveries
const severityConfig: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: '#f87171', bg: 'rgba(248,113,113,0.08)', border: 'rgba(248,113,113,0.25)' },
  high:     { text: '#fb923c', bg: 'rgba(251,146,60,0.08)',  border: 'rgba(251,146,60,0.25)'  },
  medium:   { text: '#fbbf24', bg: 'rgba(251,191,36,0.08)', border: 'rgba(251,191,36,0.25)' },
  low:      { text: '#60a5fa', bg: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.25)' },
  info:     { text: '#94a3b8', bg: 'rgba(148,163,184,0.06)', border: 'rgba(148,163,184,0.18)' },
}
function getSev(s: string | null) { return severityConfig[s || ''] ?? severityConfig['info']! }
</script>

<template>
  <div class="space-y-5">

    <!-- Back nav -->
    <button
      class="flex items-center gap-1.5 text-sm text-white/35 hover:text-white/70 transition-colors group cursor-pointer"
      @click="router.back()"
    >
      <svg class="w-4 h-4 transition-transform group-hover:-translate-x-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
        <path d="M15 19l-7-7 7-7" />
      </svg>
      Back
    </button>

    <!-- Loading -->
    <div v-if="loading" class="space-y-4">
      <div class="skeleton h-36 rounded-xl"></div>
      <div class="skeleton h-10 rounded-xl w-2/3"></div>
      <div class="skeleton h-80 rounded-xl"></div>
    </div>

    <template v-else-if="execution">

      <!-- ── Header card ── -->
      <div class="glass rounded-xl overflow-hidden">
        <!-- Status gradient top bar -->
        <div
          class="h-[3px]"
          :style="execution.status === 'success'
            ? 'background: linear-gradient(90deg, rgba(0,255,65,0.9), rgba(0,255,65,0.1));'
            : execution.status === 'failed'
              ? 'background: linear-gradient(90deg, rgba(255,77,77,0.9), rgba(255,77,77,0.1));'
              : execution.status === 'running'
                ? 'background: linear-gradient(90deg, rgba(0,212,255,0.9), rgba(0,212,255,0.1));'
                : 'background: rgba(255,255,255,0.1);'"
        />

        <div class="p-6">
          <!-- Title + status -->
          <div class="flex items-start justify-between gap-4 mb-5">
            <div>
              <div class="text-[10px] text-white/30 uppercase tracking-widest font-medium mb-1">Execution</div>
              <h1 class="font-heading text-xl font-bold text-white">#{{ execution.id }}</h1>
            </div>
            <StatusBadge :status="execution.status" pill />
          </div>

          <!-- Metadata grid -->
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
            <div>
              <div class="text-[10px] text-white/30 uppercase tracking-wider mb-1">Challenge</div>
              <router-link
                :to="`/challenges/${execution.challenge_id}`"
                class="font-mono text-sm font-medium transition-colors cursor-pointer"
                style="color: var(--accent-cyan);"
              >#{{ execution.challenge_id }}</router-link>
            </div>
            <div>
              <div class="text-[10px] text-white/30 uppercase tracking-wider mb-1">Attempt</div>
              <span class="font-mono text-sm text-white/70">#{{ execution.attempt_number }}</span>
            </div>
            <div>
              <div class="text-[10px] text-white/30 uppercase tracking-wider mb-1">Duration</div>
              <span class="font-mono text-sm text-white/70">{{ formatElapsed(execution.elapsed_seconds) }}</span>
            </div>
            <div>
              <div class="text-[10px] text-white/30 uppercase tracking-wider mb-1">Started</div>
              <span class="text-xs text-white/50">{{ formatTime(execution.started_at) }}</span>
            </div>
          </div>

          <!-- Cost & tokens -->
          <div
            v-if="execution.total_cost_usd || execution.input_tokens || execution.output_tokens"
            class="flex flex-wrap items-center gap-5 py-4"
            style="border-top: 1px solid rgba(255,255,255,0.05); border-bottom: 1px solid rgba(255,255,255,0.05);"
          >
            <div v-if="execution.total_cost_usd" class="flex items-baseline gap-1.5">
              <span class="text-lg font-heading font-bold" style="color:#eab308;">{{ formatCost(execution.total_cost_usd) }}</span>
              <span class="text-[10px] text-white/25">cost</span>
            </div>
            <div v-if="execution.input_tokens" class="flex items-baseline gap-1.5">
              <span class="font-mono text-sm font-medium text-white/60">{{ formatTokens(execution.input_tokens) }}</span>
              <span class="text-[10px] text-white/25">in</span>
            </div>
            <div v-if="execution.output_tokens" class="flex items-baseline gap-1.5">
              <span class="font-mono text-sm font-medium text-white/60">{{ formatTokens(execution.output_tokens) }}</span>
              <span class="text-[10px] text-white/25">out</span>
            </div>
          </div>

          <!-- Flag -->
          <div v-if="execution.flag" class="flex items-center gap-2.5 mt-4">
            <span class="text-[10px] text-white/30 uppercase tracking-wider">Flag</span>
            <code class="font-mono text-sm font-semibold" style="color: var(--accent-green);">{{ execution.flag }}</code>
          </div>

          <!-- Error -->
          <div v-if="execution.error_message" class="mt-4 flex items-start gap-2.5">
            <span class="text-[10px] text-white/30 uppercase tracking-wider shrink-0 mt-0.5">Error</span>
            <span class="text-xs text-red-400 leading-relaxed">{{ execution.error_message }}</span>
          </div>
        </div>
      </div>

      <!-- ── Session summary mini-stats ── -->
      <div v-if="transcript?.summary" class="grid grid-cols-2 sm:grid-cols-5 gap-2">
        <div
          v-for="(item, i) in [
            { label: 'Steps',     value: transcript.summary.total_steps,    color: 'text-white/80' },
            { label: 'Thinking',  value: transcript.summary.thinking_count,  color: 'text-[var(--accent-green)]' },
            { label: 'Tool Calls',value: transcript.summary.tool_calls,      color: 'text-[#f97316]' },
            { label: 'Results',   value: transcript.summary.tool_results,    color: 'text-[var(--accent-purple)]' },
            { label: 'Duration',  value: formatElapsed(transcript.summary.duration_seconds), color: 'text-white/60' },
          ]"
          :key="i"
          class="glass rounded-xl px-4 py-3 text-center"
        >
          <div class="text-[9px] uppercase tracking-widest text-white/25 font-medium mb-1.5">{{ item.label }}</div>
          <div class="font-heading text-lg font-bold" :class="item.color">{{ item.value }}</div>
        </div>
      </div>

      <!-- Session metadata chips -->
      <div v-if="transcript?.metadata" class="flex flex-wrap items-center gap-1.5">
        <span v-if="transcript.metadata.model" class="glass rounded-full px-2.5 py-1 font-mono text-[10px] text-white/35">
          {{ transcript.metadata.model }}
        </span>
        <span v-if="transcript.metadata.session_id" class="glass rounded-full px-2.5 py-1 font-mono text-[10px] text-white/25 truncate max-w-56">
          {{ transcript.metadata.session_id }}
        </span>
        <span v-if="transcript.subagents.length > 0" class="glass rounded-full px-2.5 py-1 text-[10px]" style="color:var(--accent-purple);">
          {{ transcript.subagents.length }} subagent{{ transcript.subagents.length !== 1 ? 's' : '' }}
        </span>
      </div>

      <!-- ── Tab strip ── -->
      <div class="tab-strip w-fit flex-wrap">
        <button
          v-for="tab in (['transcript', 'log', 'subagents', 'discoveries', 'writeup'] as const)"
          :key="tab"
          class="tab-btn flex items-center gap-1.5 capitalize"
          :class="activeTab === tab ? 'active' : ''"
          @click="activeTab = tab"
        >
          {{ tab }}
          <span v-if="tab === 'transcript' && transcript" class="badge badge-muted">{{ transcript.total_steps }}</span>
          <span v-if="tab === 'subagents' && transcript && transcript.subagents.length" class="badge badge-muted">{{ transcript.subagents.length }}</span>
          <span v-if="tab === 'discoveries' && discoveries.length" class="badge badge-muted">{{ discoveries.length }}</span>
          <span v-if="tab === 'log' && logData" class="badge badge-muted">{{ logData.total }}</span>
        </button>
      </div>

      <!-- ═══════════════════════════════════════════ -->
      <!-- ── Transcript Tab ──                       -->
      <!-- ═══════════════════════════════════════════ -->
      <div v-if="activeTab === 'transcript'">
        <div v-if="!execution.has_transcript" class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-2">
          <div class="text-3xl opacity-15">◎</div>
          <p class="text-white/30 text-sm">No transcript available</p>
        </div>
        <div v-else-if="transcriptLoading" class="space-y-2.5">
          <div v-for="i in 8" :key="i" class="skeleton h-14 rounded-xl"></div>
        </div>
        <div v-else-if="transcript && transcript.steps.length > 0" class="flex flex-col lg:flex-row gap-4">

          <!-- Left: step list -->
          <div class="w-full lg:w-1/2 max-h-[calc(100vh-300px)] overflow-y-auto space-y-1.5 pr-1">
            <div
              v-for="(step, idx) in transcript.steps"
              :key="idx"
              :ref="(el: any) => setStepRef(idx, el)"
              class="glass rounded-xl p-3.5 border-l-[3px] cursor-pointer transition-all duration-150"
              :style="getStepConfig(step.type).borderStyle"
              :class="highlightedSteps.has(idx) ? 'ring-1 ring-white/20' : ''"
              @click="onStepClick(step, idx)"
            >
              <!-- Step header -->
              <div class="flex items-center gap-2 mb-2 flex-wrap">
                <span
                  class="text-[10px] font-semibold px-2 py-0.5 rounded-full border"
                  :style="`color:${getStepConfig(step.type).color};background:${getStepConfig(step.type).color}15;border-color:${getStepConfig(step.type).color}35;`"
                >
                  {{ getStepConfig(step.type).label }}
                </span>
                <span v-if="step.tool" class="code-inline text-[10px] text-white/50">{{ step.tool }}</span>
                <span
                  v-if="step.type === 'tool_result' && step.success !== null"
                  class="text-[10px] px-1.5 py-0.5 rounded-full border font-semibold"
                  :style="step.success
                    ? 'color:var(--accent-green);background:rgba(0,255,65,0.1);border-color:rgba(0,255,65,0.3);'
                    : 'color:#f87171;background:rgba(248,113,113,0.1);border-color:rgba(248,113,113,0.3);'"
                >{{ step.success ? 'OK' : 'ERR' }}</span>
                <span v-if="step.timestamp" class="ml-auto font-mono text-[10px] text-white/15 shrink-0">
                  {{ step.timestamp }}
                </span>
              </div>

              <!-- Content -->
              <div v-if="step.content" class="font-mono text-[11px] text-white/55 whitespace-pre-wrap break-all leading-relaxed max-h-56 overflow-y-auto">{{ step.content }}</div>

              <!-- Tool input -->
              <details v-if="step.input" class="mt-2">
                <summary class="text-[10px] text-white/30 cursor-pointer hover:text-white/55 transition-colors select-none">
                  ▶ Input
                </summary>
                <pre class="font-mono text-[10px] text-white/40 mt-1.5 whitespace-pre-wrap break-all max-h-40 overflow-y-auto p-2 rounded-lg" style="background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.05);">{{ formatContent(step.input) }}</pre>
              </details>

              <!-- Tool output -->
              <details v-if="step.output" class="mt-2" open>
                <summary class="text-[10px] text-white/30 cursor-pointer hover:text-white/55 transition-colors select-none">
                  ▶ Output
                </summary>
                <pre class="font-mono text-[10px] text-white/40 mt-1.5 whitespace-pre-wrap break-all max-h-56 overflow-y-auto p-2 rounded-lg" style="background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.05);">{{ formatContent(step.output) }}</pre>
              </details>
            </div>

            <!-- Pagination -->
            <div v-if="transcript.total_pages > 1" class="flex items-center justify-center gap-1.5 py-3">
              <button
                v-for="p in Math.min(transcript.total_pages, 10)"
                :key="p"
                class="glass rounded-lg w-8 h-8 text-xs flex items-center justify-center cursor-pointer transition-colors"
                :class="p === transcriptPage ? 'text-white font-semibold' : 'text-white/40 hover:text-white/70'"
                :style="p === transcriptPage ? 'background:rgba(0,212,255,0.12);border-color:rgba(0,212,255,0.25);' : ''"
                @click="changePage(p)"
              >{{ p }}</button>
              <span v-if="transcript.total_pages > 10" class="text-white/20 text-xs font-mono">…{{ transcript.total_pages }}</span>
            </div>
          </div>

          <!-- Right: flow diagram -->
          <div class="w-full lg:w-1/2 lg:sticky lg:top-20 lg:self-start">
            <div class="glass rounded-xl p-4 h-[400px] lg:h-[calc(100vh-300px)] overflow-hidden flex flex-col">
              <div class="text-[10px] uppercase tracking-widest text-white/25 font-medium mb-3">Agent Flow</div>
              <div class="flex-1">
                <FlowDiagram
                  :transcript="transcript"
                  :highlighted-node-id="highlightedNodeId"
                  @node-click="onFlowNodeClick"
                />
              </div>
            </div>
          </div>
        </div>
        <div v-else class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-2">
          <div class="text-3xl opacity-15">◎</div>
          <p class="text-white/30 text-sm">Transcript is empty</p>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════ -->
      <!-- ── Log Tab ──                              -->
      <!-- ═══════════════════════════════════════════ -->
      <div v-if="activeTab === 'log'">
        <div v-if="logLoading" class="space-y-3">
          <div v-for="i in 8" :key="i" class="skeleton h-12 rounded-xl"></div>
        </div>
        <div v-else-if="logData && !logData.success" class="glass rounded-xl flex flex-col items-center justify-center py-12 gap-2">
          <p class="text-red-400 text-sm">{{ logData.error || 'Failed to load log' }}</p>
        </div>
        <div v-else-if="!logData || logData.entries.length === 0" class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-2">
          <div class="text-3xl opacity-15">📋</div>
          <p class="text-white/30 text-sm">{{ !logData ? 'Log not available' : 'No log entries' }}</p>
        </div>

        <!-- ── Conversation view ── -->
        <div v-else class="flex flex-col gap-0">

          <!-- Scroll container -->
          <div class="max-h-[calc(100vh-280px)] overflow-y-auto px-2 py-3 space-y-2" style="scroll-behavior:smooth;">

            <template v-for="(entry, idx) in logData.entries" :key="idx">

              <!-- ── CENTER system pill ── -->
              <div
                v-if="getChatSide(entry) === 'center'"
                class="flex justify-center py-0.5"
              >
                <span class="chat-center-pill">
                  <span>{{ eventTypeIcon[entry.event_type] || '·' }}</span>
                  <span>{{ entry.event_text || entry.event_type }}</span>
                  <span class="font-mono opacity-50 text-[9px]">{{ entry.timestamp.slice(11,19) }}</span>
                </span>
              </div>

              <!-- ── RIGHT bubble (system input / prompt) ── -->
              <div v-else-if="getChatSide(entry) === 'right'" class="flex justify-end gap-2.5">
                <div class="flex flex-col items-end gap-1 max-w-[75%]">
                  <!-- Label row -->
                  <div class="flex items-center gap-1.5 text-[10px] text-white/35">
                    <span class="font-mono text-[9px] opacity-60">{{ entry.timestamp.slice(11,19) }}</span>
                    <span class="uppercase tracking-wide text-[9px]">{{ entry.event_type }}</span>
                    <span>{{ eventTypeIcon[entry.event_type] || '📥' }}</span>
                  </div>
                  <!-- Bubble -->
                  <div
                    class="chat-bubble chat-bubble-right cursor-pointer select-text"
                    @click="toggleLogEntry(idx)"
                  >
                    <div
                      class="font-mono text-[11px] leading-relaxed"
                      :class="expandedLogIdx.has(idx) ? 'whitespace-pre-wrap break-all' : 'line-clamp-5'"
                    >{{ entry.event_text || Object.keys(entry.kv).map(k => `${k}: ${entry.kv[k]}`).join('\n') || entry.event_type }}</div>

                    <!-- KV expanded -->
                    <div v-if="expandedLogIdx.has(idx) && Object.keys(entry.kv).length > 0" class="mt-2.5 pt-2 space-y-1" style="border-top:1px solid rgba(0,212,255,0.12);">
                      <div v-for="(val, key) in entry.kv" :key="String(key)" class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-[10px] font-mono text-white/30 truncate">{{ key }}</span>
                        <pre class="text-[10px] font-mono text-white/55 whitespace-pre-wrap break-all">{{ typeof val === 'string' ? val : JSON.stringify(val, null, 2) }}</pre>
                      </div>
                    </div>
                  </div>
                </div>
                <!-- Avatar -->
                <div class="w-7 h-7 rounded-full shrink-0 flex items-center justify-center text-[10px] mt-5" style="background:rgba(0,212,255,0.15);border:1px solid rgba(0,212,255,0.3);color:var(--accent-cyan);">
                  SYS
                </div>
              </div>

              <!-- ── LEFT bubble (agent output: thinking / text / tool) ── -->
              <div v-else class="flex gap-2.5">
                <!-- Avatar -->
                <div
                  class="w-7 h-7 rounded-full shrink-0 flex items-center justify-center text-[10px] mt-5 font-semibold"
                  :class="getAgentStyle(entry.source, entry.agent, entry.event_type).dotClass"
                  style="border:1px solid rgba(255,255,255,0.1);opacity:0.85;"
                >
                  {{ (entry.agent || entry.source || '?').slice(0,2).toUpperCase() }}
                </div>

                <div class="flex flex-col gap-1 max-w-[78%]">
                  <!-- Label row -->
                  <div class="flex items-center gap-1.5 text-[10px] text-white/35">
                    <span>{{ eventTypeIcon[entry.event_type] || '·' }}</span>
                    <span
                      v-if="entry.agent"
                      class="font-mono px-1.5 py-0.5 rounded text-[9px]"
                      :style="getAgentStyle(entry.source, entry.agent, entry.event_type).badgeStyle"
                    >{{ entry.agent }}</span>
                    <span class="uppercase tracking-wide text-[9px]">{{ entry.event_type }}</span>
                    <span class="font-mono text-[9px] opacity-50">{{ entry.timestamp.slice(11,19) }}</span>
                  </div>

                  <!-- ── Thinking bubble ── -->
                  <div
                    v-if="entry.event_type === 'thinking'"
                    class="chat-bubble chat-bubble-thinking cursor-pointer select-text"
                    @click="toggleLogEntry(idx)"
                  >
                    <div class="text-[10px] font-semibold mb-1.5 opacity-60 uppercase tracking-wider">Thinking…</div>
                    <div
                      class="font-mono text-[11px] leading-relaxed"
                      :class="expandedLogIdx.has(idx) ? 'whitespace-pre-wrap break-all' : 'line-clamp-6'"
                      style="color: rgba(0,255,65,0.80);"
                    >{{ getKvText(entry) || entry.event_text }}</div>
                    <div v-if="!expandedLogIdx.has(idx)" class="text-[9px] mt-1.5 opacity-40">click to expand</div>
                  </div>

                  <!-- ── Text response bubble ── -->
                  <div
                    v-else-if="entry.event_type === 'text_response'"
                    class="chat-bubble chat-bubble-left cursor-pointer select-text"
                    @click="toggleLogEntry(idx)"
                  >
                    <div
                      class="text-[11px] leading-relaxed"
                      :class="expandedLogIdx.has(idx) ? 'whitespace-pre-wrap break-all' : 'line-clamp-8'"
                    >{{ getKvText(entry) || entry.event_text }}</div>
                    <div v-if="!expandedLogIdx.has(idx) && (getKvText(entry) || entry.event_text || '').length > 280" class="text-[9px] mt-1.5 opacity-40">click to expand</div>
                  </div>

                  <!-- ── Tool call bubble ── -->
                  <div
                    v-else-if="entry.event_type === 'tool_call' || entry.event_type === 'tool_error'"
                    class="chat-bubble chat-bubble-tool-call cursor-pointer select-text"
                    @click="toggleLogEntry(idx)"
                  >
                    <div class="flex items-center gap-2 mb-2">
                      <span class="text-xs">🔧</span>
                      <span class="font-mono text-[11px] font-semibold" style="color:#f97316;">
                        {{ entry.kv['tool_name'] || entry.event_text }}
                      </span>
                      <span v-if="entry.event_type === 'tool_error'" class="text-[9px] px-1.5 rounded" style="background:rgba(248,113,113,0.15);color:#f87171;">ERROR</span>
                    </div>
                    <div v-if="expandedLogIdx.has(idx)">
                      <div v-for="(val, key) in entry.kv" :key="String(key)" class="grid grid-cols-[100px_1fr] gap-1.5 mb-1">
                        <span class="text-[9px] font-mono text-white/35 truncate">{{ key }}</span>
                        <pre class="text-[10px] font-mono text-white/60 whitespace-pre-wrap break-all">{{ typeof val === 'string' ? val : JSON.stringify(val, null, 2) }}</pre>
                      </div>
                    </div>
                    <div v-else class="font-mono text-[10px] text-white/45 truncate">{{ entry.event_text }}</div>
                  </div>

                  <!-- ── Tool result bubble ── -->
                  <div
                    v-else-if="entry.event_type === 'tool_result'"
                    class="chat-bubble chat-bubble-tool-result cursor-pointer select-text"
                    @click="toggleLogEntry(idx)"
                  >
                    <div class="flex items-center gap-2 mb-2">
                      <span class="text-xs">✅</span>
                      <span class="font-mono text-[11px] font-semibold" style="color:#a855f7;">Result</span>
                    </div>
                    <div
                      class="font-mono text-[10px] text-white/60 leading-relaxed"
                      :class="expandedLogIdx.has(idx) ? 'whitespace-pre-wrap break-all' : 'line-clamp-5'"
                    >{{ entry.kv['output'] || entry.event_text }}</div>
                    <div v-if="expandedLogIdx.has(idx) && Object.keys(entry.kv).length > 1" class="mt-2 pt-1.5 space-y-1" style="border-top:1px solid rgba(168,85,247,0.15);">
                      <div v-for="(val, key) in entry.kv" :key="String(key)">
                        <template v-if="key !== 'output'">
                          <span class="text-[9px] font-mono text-white/30">{{ key }}: </span>
                          <span class="text-[9px] font-mono text-white/45">{{ typeof val === 'string' ? val : JSON.stringify(val) }}</span>
                        </template>
                      </div>
                    </div>
                  </div>

                  <!-- ── Generic left bubble ── -->
                  <div
                    v-else
                    class="chat-bubble chat-bubble-left cursor-pointer select-text"
                    @click="toggleLogEntry(idx)"
                  >
                    <div
                      class="font-mono text-[11px] leading-relaxed text-white/65"
                      :class="expandedLogIdx.has(idx) ? 'whitespace-pre-wrap break-all' : 'line-clamp-5'"
                    >{{ entry.event_text }}</div>
                    <div v-if="expandedLogIdx.has(idx) && Object.keys(entry.kv).length > 0" class="mt-2.5 pt-2 space-y-1" style="border-top:1px solid rgba(255,255,255,0.07);">
                      <div v-for="(val, key) in entry.kv" :key="String(key)" class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-[10px] font-mono text-white/25 truncate">{{ key }}</span>
                        <pre class="text-[10px] font-mono text-white/50 whitespace-pre-wrap break-all">{{ typeof val === 'string' ? val : JSON.stringify(val, null, 2) }}</pre>
                      </div>
                    </div>
                  </div>

                </div>
              </div>

            </template>
          </div>

          <!-- Log pagination -->
          <div v-if="logData.total_pages > 1" class="flex items-center justify-center gap-1.5 mt-3">
            <button
              v-for="p in Math.min(logData.total_pages, 10)"
              :key="p"
              class="glass rounded-lg w-8 h-8 text-xs flex items-center justify-center cursor-pointer transition-colors"
              :class="p === logPage ? 'text-white font-semibold' : 'text-white/40 hover:text-white/70'"
              :style="p === logPage ? 'background:rgba(0,212,255,0.12);border-color:rgba(0,212,255,0.25);' : ''"
              @click="changeLogPage(p)"
            >{{ p }}</button>
            <span v-if="logData.total_pages > 10" class="text-white/20 text-xs font-mono">…{{ logData.total_pages }}</span>
          </div>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════ -->
      <!-- ── Subagents Tab ──                        -->
      <!-- ═══════════════════════════════════════════ -->
      <div v-if="activeTab === 'subagents'">
        <div v-if="transcript && transcript.subagents.length > 0" class="space-y-2.5">
          <div
            v-for="sa in transcript.subagents"
            :key="sa.agent_id || 'unknown'"
            class="glass rounded-xl overflow-hidden"
          >
            <!-- Subagent header -->
            <button
              class="w-full flex items-center justify-between gap-4 px-5 py-4 cursor-pointer transition-colors text-left"
              :style="{ background: 'transparent' }"
              @mouseenter="($event.currentTarget as HTMLElement).style.background='rgba(255,255,255,0.02)'"
              @mouseleave="($event.currentTarget as HTMLElement).style.background='transparent'"
              @click="toggleSubagent(sa.agent_id)"
            >
              <div class="flex items-center gap-3">
                <div class="w-1.5 h-1.5 rounded-full shrink-0" style="background:var(--accent-purple);box-shadow:0 0 6px rgba(168,85,247,0.5);"></div>
                <span class="font-mono text-sm font-medium" style="color:var(--accent-purple);">
                  {{ sa.agent_id || 'subagent' }}
                </span>
                <span v-if="sa.metadata.model" class="text-[10px] text-white/30 font-mono">{{ sa.metadata.model }}</span>
              </div>
              <div class="flex items-center gap-4 text-[11px] text-white/35">
                <span class="font-mono">{{ sa.summary.tool_calls }} calls</span>
                <span class="font-mono">{{ formatElapsed(sa.summary.duration_seconds) }}</span>
                <span class="font-mono">{{ sa.summary.total_steps }} steps</span>
                <svg
                  class="w-4 h-4 text-white/25 transition-transform duration-200 shrink-0"
                  :class="expandedSubagent === sa.agent_id ? 'rotate-90' : ''"
                  fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"
                >
                  <path d="M9 5l7 7-7 7" />
                </svg>
              </div>
            </button>

            <!-- Expanded steps -->
            <div
              v-if="expandedSubagent === sa.agent_id"
              class="px-5 pb-5 space-y-1.5"
              style="border-top: 1px solid rgba(255,255,255,0.05);"
            >
              <div class="pt-3"></div>
              <div
                v-for="(step, idx) in sa.steps"
                :key="idx"
                class="rounded-lg px-3 py-2.5 border-l-[2px]"
                :style="`background:rgba(0,0,0,0.25);${getStepConfig(step.type).borderStyle}`"
              >
                <div class="flex items-center gap-2 mb-1">
                  <span
                    class="text-[9px] uppercase tracking-wider font-semibold px-1.5 py-0.5 rounded-full border"
                    :style="`color:${getStepConfig(step.type).color};background:${getStepConfig(step.type).color}12;border-color:${getStepConfig(step.type).color}30;`"
                  >{{ getStepConfig(step.type).label }}</span>
                  <span v-if="step.tool" class="code-inline text-[9px] text-white/40">{{ step.tool }}</span>
                </div>
                <div v-if="step.content" class="font-mono text-[10px] text-white/50 whitespace-pre-wrap break-all max-h-28 overflow-y-auto leading-relaxed">{{ step.content }}</div>
                <div v-if="step.output" class="font-mono text-[10px] text-white/35 whitespace-pre-wrap break-all max-h-28 overflow-y-auto mt-1 leading-relaxed">{{ formatContent(step.output) }}</div>
              </div>
            </div>
          </div>
        </div>
        <div v-else class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-2">
          <div class="text-3xl opacity-15">◈</div>
          <p class="text-white/30 text-sm">No subagents in this execution</p>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════ -->
      <!-- ── Discoveries Tab ──                      -->
      <!-- ═══════════════════════════════════════════ -->
      <div v-if="activeTab === 'discoveries'">
        <div v-if="discoveries.length > 0" class="space-y-3">
          <div v-for="d in discoveries" :key="d.id" class="glass rounded-xl p-5">
            <div class="flex items-start justify-between gap-3 mb-3">
              <div class="flex items-center gap-2 flex-wrap">
                <span
                  class="tag capitalize"
                  :style="`color:${getSev(d.severity).text};background:${getSev(d.severity).bg};border-color:${getSev(d.severity).border};`"
                >{{ d.severity || 'info' }}</span>
                <span class="code-inline text-[10px] text-white/35">{{ d.discovery_type }}</span>
              </div>
            </div>
            <h3 class="text-sm font-semibold text-white/90 mb-2">{{ d.title }}</h3>
            <p v-if="d.description" class="text-xs text-white/50 leading-relaxed mb-3">{{ d.description }}</p>
            <div v-if="d.evidence" class="rounded-lg overflow-hidden" style="background:rgba(0,0,0,0.4);border:1px solid rgba(255,255,255,0.06);">
              <div class="px-3 py-1.5 text-[9px] uppercase tracking-wider text-white/25 font-medium" style="border-bottom:1px solid rgba(255,255,255,0.05);">Evidence</div>
              <pre class="font-mono text-[10px] text-white/50 p-3 whitespace-pre-wrap break-all leading-relaxed">{{ d.evidence }}</pre>
            </div>
          </div>
        </div>
        <div v-else class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-2">
          <div class="text-3xl opacity-15">◈</div>
          <p class="text-white/30 text-sm">No discoveries recorded</p>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════ -->
      <!-- ── Writeup Tab ──                          -->
      <!-- ═══════════════════════════════════════════ -->
      <div v-if="activeTab === 'writeup'">
        <div v-if="writeupLoading" class="space-y-3">
          <div v-for="i in 4" :key="i" class="skeleton h-14 rounded-xl"></div>
        </div>
        <div v-else-if="writeupMarkdown" class="glass rounded-xl p-6">
          <MarkdownRender :content="writeupMarkdown" class="markdown-body" />
        </div>
        <div v-else class="glass rounded-xl flex flex-col items-center justify-center py-16 gap-2">
          <div class="text-3xl opacity-15">◧</div>
          <p class="text-white/30 text-sm">No writeup available for this execution</p>
        </div>
      </div>

    </template>
  </div>
</template>
