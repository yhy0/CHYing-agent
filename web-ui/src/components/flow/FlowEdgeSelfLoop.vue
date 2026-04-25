<script setup lang="ts">
import { computed } from 'vue'
import { BaseEdge, type EdgeProps } from '@vue-flow/core'

const props = defineProps<EdgeProps>()

// Self-loop: draw arc from top-right, loop around, back to top-left
const path = computed(() => {
  const { sourceX, sourceY } = props
  const ox = sourceX
  const oy = sourceY - 10
  const r = 28
  return `M ${ox + 15} ${oy} C ${ox + 15 + r} ${oy - r * 1.5}, ${ox - 15 - r} ${oy - r * 1.5}, ${ox - 15} ${oy}`
})

const labelX = computed(() => props.sourceX)
const labelY = computed(() => props.sourceY - 52)
</script>

<template>
  <BaseEdge :path="path" :style="{ stroke: '#00e5ff', strokeWidth: 1.5, strokeDasharray: '4 3' }" />
  <text
    v-if="props.label"
    :x="labelX"
    :y="labelY"
    text-anchor="middle"
    dominant-baseline="middle"
    class="flow-edge-label"
  >
    {{ props.label }}
  </text>
</template>

<style scoped>
.flow-edge-label {
  fill: rgba(255, 255, 255, 0.5);
  font-size: 10px;
  font-family: 'Fira Code', monospace;
}
</style>
