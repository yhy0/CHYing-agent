<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api, type Challenge, type PaginatedResponse } from '@/composables/useApi'
import StatusBadge from '@/components/ui/StatusBadge.vue'

const router = useRouter()

const data = ref<PaginatedResponse<Challenge> | null>(null)
const loading = ref(false)
const filterMode = ref<string>('')
const filterStatus = ref<string>('')
const page = ref(1)

const MODES = ['ctf', 'ctf-web', 'pentest']
const STATUSES = ['success', 'failed', 'running', 'pending']

async function fetchData() {
  loading.value = true
  try {
    data.value = await api.getChallenges({
      mode: filterMode.value || undefined,
      status: filterStatus.value || undefined,
      page: page.value,
      page_size: 20,
    })
  } finally {
    loading.value = false
  }
}

onMounted(fetchData)
watch([filterMode, filterStatus], () => { page.value = 1; fetchData() })
watch(page, fetchData)

function formatTime(s: string) {
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(new Date(s))
}

// Left-border color based on status
const statusAccent: Record<string, string> = {
  success: 'rgba(0,255,65,0.5)',
  failed:  'rgba(255,77,77,0.5)',
  running: 'rgba(0,212,255,0.5)',
  pending: 'rgba(255,255,255,0.12)',
  timeout: 'rgba(249,115,22,0.5)',
}

function accentForStatus(s: string | null) {
  return statusAccent[s || ''] || statusAccent.pending
}
</script>

<template>
  <div class="space-y-6">

    <!-- Header row -->
    <div class="flex items-end justify-between gap-4 flex-wrap">
      <div>
        <p class="text-xs text-white/30 uppercase tracking-widest font-medium mb-1">Library</p>
        <h1 class="font-heading text-2xl font-bold text-white">Challenges</h1>
      </div>

      <!-- Filter chips -->
      <div class="flex flex-wrap items-center gap-2">
        <!-- Mode filter -->
        <div class="flex items-center gap-1">
          <button
            class="tab-btn text-[11px] px-2.5 py-1 rounded-md"
            :class="filterMode === '' ? 'active' : ''"
            @click="filterMode = ''"
          >All</button>
          <button
            v-for="m in MODES"
            :key="m"
            class="tab-btn text-[11px] px-2.5 py-1 rounded-md capitalize"
            :class="filterMode === m ? 'active' : ''"
            @click="filterMode = filterMode === m ? '' : m"
          >{{ m }}</button>
        </div>

        <!-- Divider -->
        <div class="h-5 w-px bg-white/10"></div>

        <!-- Status filter -->
        <div class="flex items-center gap-1">
          <button
            v-for="s in STATUSES"
            :key="s"
            class="tab-btn text-[11px] px-2.5 py-1 rounded-md capitalize"
            :class="filterStatus === s ? 'active' : ''"
            @click="filterStatus = filterStatus === s ? '' : s"
          >{{ s }}</button>
        </div>
      </div>
    </div>

    <!-- Loading skeletons -->
    <div v-if="loading" class="space-y-2.5">
      <div v-for="i in 6" :key="i" class="skeleton h-[72px] rounded-xl"></div>
    </div>

    <!-- Challenge list -->
    <div v-else-if="data && data.items.length > 0" class="space-y-2">
      <div
        v-for="ch in data.items"
        :key="ch.id"
        class="glass glass-hover glow-border rounded-xl px-5 py-4 cursor-pointer relative overflow-hidden"
        style="transition: all 0.2s cubic-bezier(0.4,0,0.2,1);"
        @click="router.push(`/challenges/${ch.id}`)"
      >
        <!-- Status left accent bar -->
        <div
          class="absolute top-0 left-0 bottom-0 w-[3px] rounded-l-xl"
          :style="`background: ${accentForStatus(ch.latest_status)};`"
        />

        <div class="flex items-center justify-between gap-4 pl-1">
          <!-- Left: name + meta -->
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2 mb-1.5">
              <span class="font-heading text-sm font-semibold text-white/90 truncate">
                {{ ch.challenge_code }}
              </span>
              <span
                class="tag text-white/40"
                style="background: rgba(255,255,255,0.04); border-color: rgba(255,255,255,0.08);"
              >{{ ch.mode }}</span>
              <span
                v-if="ch.difficulty"
                class="tag"
                :style="ch.difficulty === 'hard' || ch.difficulty === 'expert'
                  ? 'color:#f97316;background:rgba(249,115,22,0.08);border-color:rgba(249,115,22,0.2);'
                  : ch.difficulty === 'medium'
                    ? 'color:#eab308;background:rgba(234,179,8,0.08);border-color:rgba(234,179,8,0.2);'
                    : 'color:#3b82f6;background:rgba(59,130,246,0.08);border-color:rgba(59,130,246,0.2);'"
              >{{ ch.difficulty }}</span>
            </div>
            <div class="flex items-center gap-3 text-[11px] text-white/35 font-mono">
              <span v-if="ch.target_url" class="truncate max-w-72">{{ ch.target_url }}</span>
              <span v-else-if="ch.target_ip">{{ ch.target_ip }}</span>
              <span class="shrink-0">{{ ch.execution_count }} run{{ ch.execution_count !== 1 ? 's' : '' }}</span>
              <span class="shrink-0 font-sans">{{ formatTime(ch.created_at) }}</span>
            </div>
          </div>

          <!-- Right: flag + status -->
          <div class="flex items-center gap-3 shrink-0">
            <span
              v-if="ch.flag"
              class="font-mono text-[11px] max-w-[180px] truncate hidden sm:inline"
              style="color: var(--accent-green);"
            >{{ ch.flag }}</span>
            <StatusBadge :status="ch.latest_status" size="sm" pill />
            <svg class="w-3.5 h-3.5 text-white/20 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
              <path d="M9 5l7 7-7 7" />
            </svg>
          </div>
        </div>
      </div>
    </div>

    <!-- Empty state -->
    <div v-else class="glass rounded-xl flex flex-col items-center justify-center py-20 gap-3">
      <div class="text-4xl opacity-15">◈</div>
      <p class="text-white/30 text-sm">No challenges found</p>
      <button
        v-if="filterMode || filterStatus"
        class="text-xs mt-1 transition-colors"
        style="color: var(--accent-cyan);"
        @click="filterMode = ''; filterStatus = ''"
      >Clear filters</button>
    </div>

    <!-- Pagination -->
    <div v-if="data && data.total_pages > 1" class="flex items-center justify-center gap-1.5 pt-2">
      <button
        class="glass rounded-lg w-8 h-8 text-sm flex items-center justify-center cursor-pointer transition-colors"
        :class="page === 1 ? 'opacity-30 cursor-not-allowed' : 'hover:bg-white/8 text-white/50 hover:text-white/80'"
        :disabled="page === 1"
        @click="page > 1 && (page--)"
      >‹</button>
      <button
        v-for="p in data.total_pages"
        :key="p"
        class="glass rounded-lg w-8 h-8 text-sm flex items-center justify-center cursor-pointer transition-colors"
        :class="p === page
          ? 'text-white font-semibold'
          : 'text-white/40 hover:text-white/70 hover:bg-white/5'"
        :style="p === page ? 'background: rgba(0,212,255,0.12); border-color: rgba(0,212,255,0.25);' : ''"
        @click="page = p"
      >{{ p }}</button>
      <button
        class="glass rounded-lg w-8 h-8 text-sm flex items-center justify-center cursor-pointer transition-colors"
        :class="page === data.total_pages ? 'opacity-30 cursor-not-allowed' : 'hover:bg-white/8 text-white/50 hover:text-white/80'"
        :disabled="page === data.total_pages"
        @click="page < (data?.total_pages ?? 1) && (page++)"
      >›</button>
    </div>

  </div>
</template>
