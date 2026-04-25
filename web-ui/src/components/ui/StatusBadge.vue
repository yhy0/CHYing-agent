<script setup lang="ts">
defineProps<{
  status: string | null | undefined
  size?: 'sm' | 'md'
  pill?: boolean
}>()

interface StatusInfo {
  dot: string
  text: string
  badge: string
  label: string
}

const statusMap: Record<string, StatusInfo> = {
  success:   { dot: 'status-dot-success', text: 'status-success', badge: 'status-badge-success', label: 'Success' },
  failed:    { dot: 'status-dot-failed',  text: 'status-failed',  badge: 'status-badge-failed',  label: 'Failed' },
  running:   { dot: 'status-dot-running', text: 'status-running', badge: 'status-badge-running', label: 'Running' },
  pending:   { dot: 'status-dot-pending', text: 'status-pending', badge: 'status-badge-pending', label: 'Pending' },
  timeout:   { dot: 'status-dot-timeout', text: 'status-timeout', badge: 'status-badge-timeout', label: 'Timeout' },
  cancelled: { dot: 'status-dot-failed',  text: 'status-failed',  badge: 'status-badge-failed',  label: 'Cancelled' },
}

function getInfo(s: string | null | undefined): StatusInfo {
  return statusMap[s || ''] || { dot: 'status-dot-pending', text: 'status-pending', badge: 'status-badge-pending', label: s || '—' }
}
</script>

<template>
  <!-- Pill variant: colored background + border -->
  <span
    v-if="pill"
    class="inline-flex items-center gap-1.5 border rounded-full font-medium"
    :class="[
      getInfo(status).badge,
      getInfo(status).text,
      size === 'sm' ? 'text-[10px] px-2 py-0.5' : 'text-xs px-2.5 py-1',
    ]"
  >
    <span class="status-dot" :class="getInfo(status).dot"></span>
    {{ getInfo(status).label }}
  </span>

  <!-- Default dot + text -->
  <span
    v-else
    class="inline-flex items-center gap-1.5"
    :class="size === 'sm' ? 'text-xs' : 'text-sm'"
  >
    <span class="status-dot" :class="getInfo(status).dot"></span>
    <span :class="getInfo(status).text" class="font-medium">{{ getInfo(status).label }}</span>
  </span>
</template>
