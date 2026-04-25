<script setup lang="ts">
import { ref, watch, nextTick, toRef } from 'vue'
import { VueFlow, useVueFlow, type Node, type Edge } from '@vue-flow/core'
import '@vue-flow/core/dist/style.css'
import '@vue-flow/core/dist/theme-default.css'
import dagre from 'dagre'
import FlowNodeCustom from './FlowNodeCustom.vue'
import FlowEdgeSelfLoop from './FlowEdgeSelfLoop.vue'
import type { TranscriptResponse } from '@/composables/useApi'
import { useFlowGraph } from '@/composables/useFlowGraph'

const props = defineProps<{
  transcript: TranscriptResponse
  highlightedNodeId: string | null
}>()

const emit = defineEmits<{
  'node-click': [nodeId: string, stepIndices: number[]]
}>()

const transcriptRef = toRef(props, 'transcript')
const { nodes: rawNodes, edges: rawEdges, getStepIndicesForNode } = useFlowGraph(
  transcriptRef as any
)

const layoutedNodes = ref<Node[]>([])
const layoutedEdges = ref<Edge[]>([])

const { fitView } = useVueFlow({ id: 'flow-diagram' })

function applyDagreLayout(nodes: Node[], edges: Edge[]): Node[] {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'TB', nodesep: 40, ranksep: 60, marginx: 20, marginy: 20 })

  for (const node of nodes) {
    g.setNode(node.id, { width: 140, height: 56 })
  }

  for (const edge of edges) {
    // Skip self-loop for dagre layout
    if (edge.source === edge.target) continue
    g.setEdge(edge.source, edge.target)
  }

  dagre.layout(g)

  return nodes.map((node) => {
    const pos = g.node(node.id)
    return {
      ...node,
      position: { x: pos.x - 70, y: pos.y - 28 },
    }
  })
}

watch(
  [rawNodes, rawEdges],
  ([nodes, edges]) => {
    if (nodes.length === 0) return
    layoutedNodes.value = applyDagreLayout([...nodes], edges)
    layoutedEdges.value = edges.map((e) => ({
      ...e,
      style: {
        ...((e.style as Record<string, string>) || {}),
        stroke: 'rgba(255, 255, 255, 0.2)',
        strokeWidth: '1.5',
      },
      labelStyle: { fill: 'rgba(255, 255, 255, 0.4)', fontSize: '10px' },
    }))
    nextTick(() => {
      fitView({ padding: 0.2, duration: 300 })
    })
  },
  { immediate: true },
)

function onNodeClick(event: { node: Node }) {
  const indices = getStepIndicesForNode(event.node.id)
  emit('node-click', event.node.id, indices)
}
</script>

<template>
  <VueFlow
    id="flow-diagram"
    :nodes="layoutedNodes"
    :edges="layoutedEdges"
    :default-viewport="{ zoom: 1, x: 0, y: 0 }"
    :min-zoom="0.3"
    :max-zoom="2"
    :nodes-draggable="false"
    :nodes-connectable="false"
    :elements-selectable="true"
    fit-view-on-init
    class="vue-flow-dark"
    @node-click="onNodeClick"
  >
    <template #node-custom="nodeProps">
      <FlowNodeCustom
        :data="nodeProps.data"
        :selected="nodeProps.id === highlightedNodeId"
      />
    </template>
    <template #edge-selfLoop="edgeProps">
      <FlowEdgeSelfLoop v-bind="edgeProps" />
    </template>
  </VueFlow>
</template>
