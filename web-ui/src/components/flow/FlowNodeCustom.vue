<script setup lang="ts">
import { computed } from 'vue'
import { Handle, Position } from '@vue-flow/core'
import type { FlowNodeData } from '@/composables/useFlowGraph'

const props = defineProps<{
  data: FlowNodeData
  selected?: boolean
}>()

const borderColor = computed(() => props.data.color)
const isTerminal = computed(() => props.data.nodeKind === 'start' || props.data.nodeKind === 'end')
</script>

<template>
  <div
    class="flow-node glass rounded-lg px-3 py-2 min-w-[100px] text-center transition-all duration-200 cursor-pointer select-none"
    :class="{
      'flow-node--selected': selected,
      'flow-node--terminal': isTerminal,
    }"
    :style="{
      borderColor: borderColor,
      '--node-color': borderColor,
    }"
  >
    <Handle v-if="data.nodeKind !== 'start'" type="target" :position="Position.Top" class="!bg-white/20 !border-white/30 !w-2 !h-2" />

    <div class="flex items-center justify-center gap-1.5">
      <span class="text-sm">{{ data.icon }}</span>
      <span class="text-xs font-medium text-white/80 font-mono truncate max-w-[120px]">
        {{ data.label }}
      </span>
    </div>

    <div v-if="data.count > 0" class="text-[10px] mt-0.5 font-mono" :style="{ color: borderColor }">
      {{ data.count }}x
    </div>

    <Handle v-if="data.nodeKind !== 'end'" type="source" :position="Position.Bottom" class="!bg-white/20 !border-white/30 !w-2 !h-2" />
  </div>
</template>

<style scoped>
.flow-node {
  border: 1px solid var(--node-color, rgba(255, 255, 255, 0.1));
  background: rgba(255, 255, 255, 0.03);
  backdrop-filter: blur(12px);
}

.flow-node--selected {
  border-width: 2px;
  box-shadow: 0 0 16px color-mix(in srgb, var(--node-color) 40%, transparent),
              0 0 32px color-mix(in srgb, var(--node-color) 15%, transparent);
  background: rgba(255, 255, 255, 0.06);
}

.flow-node--terminal {
  border-radius: 999px;
  min-width: 64px;
  padding: 6px 12px;
}
</style>
