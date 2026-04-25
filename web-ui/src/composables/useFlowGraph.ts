import { computed, type Ref } from 'vue'
import type { Node, Edge } from '@vue-flow/core'
import type { TranscriptResponse, SessionStep } from './useApi'

export interface FlowNodeData {
  label: string
  count: number
  nodeKind: 'start' | 'end' | 'orchestrator' | 'tool' | 'subagent'
  color: string
  icon: string
}

export interface StepNodeMapping {
  stepIndex: number
  nodeId: string
}

const NODE_COLORS: Record<FlowNodeData['nodeKind'], string> = {
  start: '#00ff41',
  end: '#ff4444',
  orchestrator: '#00e5ff',
  tool: '#ff8800',
  subagent: '#a855f7',
}

const NODE_ICONS: Record<FlowNodeData['nodeKind'], string> = {
  start: '▶',
  end: '■',
  orchestrator: '🧠',
  tool: '⚙',
  subagent: '🤖',
}

export function useFlowGraph(
  transcript: Ref<TranscriptResponse | null>,
) {
  const graph = computed(() => {
    const t = transcript.value
    if (!t || !t.success || !t.summary) {
      return { nodes: [] as Node[], edges: [] as Edge[], stepNodeMap: [] as StepNodeMapping[] }
    }

    const nodes: Node[] = []
    const edges: Edge[] = []
    const stepNodeMap: StepNodeMapping[] = []

    // __start__ node
    nodes.push({
      id: '__start__',
      type: 'custom',
      position: { x: 0, y: 0 },
      data: {
        label: 'Start',
        count: 0,
        nodeKind: 'start',
        color: NODE_COLORS.start,
        icon: NODE_ICONS.start,
      } satisfies FlowNodeData,
    })

    // orchestrator node
    const thinkingCount = t.summary.thinking_count
    nodes.push({
      id: 'orchestrator',
      type: 'custom',
      position: { x: 0, y: 0 },
      data: {
        label: 'Orchestrator',
        count: thinkingCount,
        nodeKind: 'orchestrator',
        color: NODE_COLORS.orchestrator,
        icon: NODE_ICONS.orchestrator,
      } satisfies FlowNodeData,
    })

    // tool nodes from tool_breakdown
    const toolBreakdown = t.summary.tool_breakdown || {}
    for (const [toolName, count] of Object.entries(toolBreakdown)) {
      const nodeId = `tool:${toolName}`
      nodes.push({
        id: nodeId,
        type: 'custom',
        position: { x: 0, y: 0 },
        data: {
          label: toolName,
          count,
          nodeKind: 'tool',
          color: NODE_COLORS.tool,
          icon: NODE_ICONS.tool,
        } satisfies FlowNodeData,
      })
    }

    // subagent nodes
    for (const sa of t.subagents) {
      const agentId = sa.agent_id || 'unknown'
      const nodeId = `subagent:${agentId}`
      nodes.push({
        id: nodeId,
        type: 'custom',
        position: { x: 0, y: 0 },
        data: {
          label: agentId.length > 12 ? agentId.slice(0, 12) + '…' : agentId,
          count: sa.summary.total_steps,
          nodeKind: 'subagent',
          color: NODE_COLORS.subagent,
          icon: NODE_ICONS.subagent,
        } satisfies FlowNodeData,
      })
    }

    // __end__ node
    nodes.push({
      id: '__end__',
      type: 'custom',
      position: { x: 0, y: 0 },
      data: {
        label: 'End',
        count: 0,
        nodeKind: 'end',
        color: NODE_COLORS.end,
        icon: NODE_ICONS.end,
      } satisfies FlowNodeData,
    })

    // Edges
    // start → orchestrator
    edges.push({
      id: 'e-start-orch',
      source: '__start__',
      target: 'orchestrator',
      animated: true,
    })

    // orchestrator → each tool (bidirectional)
    for (const toolName of Object.keys(toolBreakdown)) {
      const nodeId = `tool:${toolName}`
      edges.push({
        id: `e-orch-${nodeId}`,
        source: 'orchestrator',
        target: nodeId,
        label: `${toolBreakdown[toolName]}`,
      })
      edges.push({
        id: `e-${nodeId}-orch`,
        source: nodeId,
        target: 'orchestrator',
        style: { strokeDasharray: '5 5' },
      })
    }

    // orchestrator → each subagent (bidirectional)
    for (const sa of t.subagents) {
      const agentId = sa.agent_id || 'unknown'
      const nodeId = `subagent:${agentId}`
      edges.push({
        id: `e-orch-${nodeId}`,
        source: 'orchestrator',
        target: nodeId,
        label: `${sa.summary.total_steps}`,
      })
      edges.push({
        id: `e-${nodeId}-orch`,
        source: nodeId,
        target: 'orchestrator',
        style: { strokeDasharray: '5 5' },
      })
    }

    // orchestrator self-loop (if thinking > 1)
    if (thinkingCount > 1) {
      edges.push({
        id: 'e-orch-self',
        source: 'orchestrator',
        target: 'orchestrator',
        type: 'selfLoop',
        label: `×${thinkingCount}`,
      })
    }

    // orchestrator → end
    edges.push({
      id: 'e-orch-end',
      source: 'orchestrator',
      target: '__end__',
      animated: true,
    })

    // Build step → node mapping from current page steps
    t.steps.forEach((step: SessionStep, idx: number) => {
      let nodeId: string | null = null
      if (step.type === 'thinking' || step.type === 'user_message') {
        nodeId = 'orchestrator'
      } else if (step.type === 'tool_call' && step.tool) {
        nodeId = `tool:${step.tool}`
      } else if (step.type === 'tool_result') {
        // tool_result doesn't have a direct tool name, map to orchestrator
        nodeId = 'orchestrator'
      }
      if (nodeId) {
        stepNodeMap.push({ stepIndex: idx, nodeId })
      }
    })

    return { nodes, edges, stepNodeMap }
  })

  function getNodeIdForStep(step: SessionStep): string | null {
    if (step.type === 'thinking' || step.type === 'user_message') {
      return 'orchestrator'
    }
    if (step.type === 'tool_call' && step.tool) {
      return `tool:${step.tool}`
    }
    return null
  }

  function getStepIndicesForNode(nodeId: string): number[] {
    return graph.value.stepNodeMap
      .filter((m) => m.nodeId === nodeId)
      .map((m) => m.stepIndex)
  }

  return {
    nodes: computed(() => graph.value.nodes),
    edges: computed(() => graph.value.edges),
    stepNodeMap: computed(() => graph.value.stepNodeMap),
    getNodeIdForStep,
    getStepIndicesForNode,
  }
}
