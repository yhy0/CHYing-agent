import { ref, type Ref } from 'vue'

const BASE = '/api'

async function fetchJson<T>(url: string): Promise<T> {
  const resp = await fetch(`${BASE}${url}`)
  if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`)
  return resp.json()
}

async function postJson<T>(url: string, body?: unknown): Promise<T> {
  const resp = await fetch(`${BASE}${url}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`)
  return resp.json()
}

export interface DashboardStats {
  total_challenges: number
  success_count: number
  failed_count: number
  running_count: number
  pending_count: number
  total_discoveries: number
  total_writeups: number
  total_cost_usd: number
  total_input_tokens: number
  total_output_tokens: number
  recent_executions: Execution[]
}

export interface Challenge {
  id: number
  challenge_code: string
  target_url: string | null
  target_ip: string | null
  target_ports: number[] | null
  difficulty: string
  points: number
  hint_content: string | null
  mode: string
  created_at: string
  execution_count: number
  latest_status: string | null
  flag: string | null
}

export interface Execution {
  id: number
  challenge_id: number
  attempt_number: number
  status: string
  flag: string | null
  score: number
  transcript_path: string | null
  error_message: string | null
  started_at: string
  finished_at: string | null
  elapsed_seconds: number | null
  total_cost_usd: number | null
  input_tokens: number | null
  output_tokens: number | null
  has_transcript: boolean
}

export interface Discovery {
  id: number
  execution_id: number
  discovery_type: string
  title: string
  description: string | null
  severity: string | null
  evidence: string | null
  meta: Record<string, unknown> | null
  created_at: string
}

export interface Writeup {
  id: number
  challenge_id: number
  content_markdown: string
  generated_at: string
  updated_at: string
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

// ─── Session / Transcript types (backed by SessionParser) ───

export interface SessionStep {
  type: 'user_message' | 'thinking' | 'tool_call' | 'tool_result' | 'summary' | string
  timestamp: string | null
  content: string | null
  // tool_call
  tool: string | null
  tool_use_id: string | null
  input: unknown | null
  // tool_result
  output: unknown | null
  success: boolean | null
}

export interface SessionSummary {
  total_steps: number
  user_messages: number
  thinking_count: number
  tool_calls: number
  tool_results: number
  duration_seconds: number | null
  tool_breakdown: Record<string, number>
}

export interface SessionMeta {
  file_path: string | null
  session_id: string | null
  agent_id: string | null
  model: string | null
  start_time: string | null
  end_time: string | null
  is_subagent: boolean
}

export interface SubagentInfo {
  agent_id: string | null
  summary: SessionSummary
  metadata: SessionMeta
  steps: SessionStep[]
}

export interface TranscriptResponse {
  success: boolean
  error: string | null
  steps: SessionStep[]
  summary: SessionSummary | null
  metadata: SessionMeta | null
  subagents: SubagentInfo[]
  total_steps: number
  page: number
  page_size: number
  total_pages: number
}

// ─── Log types ───

export interface LogEntry {
  timestamp: string
  level: string
  source: string           // SYSTEM / TOOL / USER / RAW
  agent: string | null     // Orchestrator / Subagent:executor / PromptCompiler / …
  event_type: string       // thinking / tool_call / tool_result / recon / header / …
  event_text: string
  kv: Record<string, unknown>
}

export interface LogResponse {
  success: boolean
  error: string | null
  total: number
  entries: LogEntry[]
  page: number
  page_size: number
  total_pages: number
}

// Composable for loading state
export function useAsync<T>(fn: () => Promise<T>) {
  const data: Ref<T | null> = ref(null)
  const loading = ref(false)
  const error: Ref<string | null> = ref(null)

  async function execute() {
    loading.value = true
    error.value = null
    try {
      data.value = await fn()
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e)
    } finally {
      loading.value = false
    }
  }

  return { data, loading, error, execute }
}

// API functions
export const api = {
  getDashboardStats: () => fetchJson<DashboardStats>('/dashboard/stats'),

  getChallenges: (params?: { mode?: string; status?: string; page?: number; page_size?: number }) => {
    const q = new URLSearchParams()
    if (params?.mode) q.set('mode', params.mode)
    if (params?.status) q.set('status', params.status)
    if (params?.page) q.set('page', String(params.page))
    if (params?.page_size) q.set('page_size', String(params.page_size))
    const qs = q.toString()
    return fetchJson<PaginatedResponse<Challenge>>(`/challenges${qs ? '?' + qs : ''}`)
  },

  getChallenge: (id: number) => fetchJson<{
    challenge: Challenge
    executions: Execution[]
    discoveries: Discovery[]
    writeup: Writeup | null
  }>(`/challenges/${id}`),

  getExecution: (id: number) => fetchJson<{
    execution: Execution
    discoveries: Discovery[]
  }>(`/executions/${id}`),

  getTranscript: (id: number, page = 1, pageSize = 50) =>
    fetchJson<TranscriptResponse>(`/executions/${id}/transcript?page=${page}&page_size=${pageSize}`),

  getExecutionWriteup: (executionId: number) => fetchJson<{ content: string | null }>(`/executions/${executionId}/writeup`),

  getLog: (id: number, page = 1, pageSize = 200) =>
    fetchJson<LogResponse>(`/executions/${id}/log?page=${page}&page_size=${pageSize}`),

  getWriteup: (challengeId: number) => fetchJson<Writeup | null>(`/writeups/${challengeId}`),

  generateWriteup: (challengeId: number) => postJson<Writeup>(`/writeups/${challengeId}/generate`),
}
