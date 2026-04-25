<script setup lang="ts">
defineProps<{
  class?: string
  variant?: 'default' | 'raised' | 'flat'
  accent?: 'none' | 'green' | 'cyan' | 'purple' | 'orange' | 'yellow'
  noPad?: boolean
}>()
</script>

<template>
  <div
    :class="[
      'rounded-xl',
      variant === 'raised' ? 'glass-md' : variant === 'flat' ? 'border border-white/6 bg-white/2' : 'glass',
      noPad ? '' : 'p-5',
      accent && accent !== 'none' ? `accent-border-${accent}` : '',
      $props.class,
    ]"
  >
    <slot />
  </div>
</template>

<style scoped>
/* Accent left-border variants */
.accent-border-green  { border-left: 2px solid rgba(0, 255, 65, 0.5); }
.accent-border-cyan   { border-left: 2px solid rgba(0, 212, 255, 0.5); }
.accent-border-purple { border-left: 2px solid rgba(168, 85, 247, 0.5); }
.accent-border-orange { border-left: 2px solid rgba(249, 115, 22, 0.5); }
.accent-border-yellow { border-left: 2px solid rgba(234, 179, 8, 0.5); }
</style>
