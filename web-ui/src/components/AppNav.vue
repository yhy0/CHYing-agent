<script setup lang="ts">
import { useRoute } from 'vue-router'

const route = useRoute()

const links = [
  { to: '/', label: 'Dashboard' },
  { to: '/challenges', label: 'Challenges' },
]

function isActive(to: string) {
  return to === '/' ? route.path === '/' : route.path.startsWith(to)
}
</script>

<template>
  <nav
    class="fixed top-0 left-0 right-0 z-50"
    style="background: rgba(5, 8, 13, 0.85); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-bottom: 1px solid rgba(255,255,255,0.06);"
  >
    <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div class="flex h-14 items-center justify-between">

        <!-- Brand -->
        <router-link to="/" class="flex items-center gap-2.5 group cursor-pointer select-none">
          <div
            class="flex h-7 w-7 items-center justify-center rounded-lg transition-all duration-200"
            style="background: rgba(0,255,65,0.1); border: 1px solid rgba(0,255,65,0.2);"
          >
            <!-- Hex/target icon -->
            <svg viewBox="0 0 20 20" fill="none" class="h-4 w-4" style="color: var(--accent-green);">
              <path d="M10 2L3 6v8l7 4 7-4V6L10 2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
              <circle cx="10" cy="10" r="2.5" fill="currentColor" opacity="0.7" />
            </svg>
          </div>
          <div class="flex items-baseline gap-0">
            <span class="font-heading text-sm font-bold tracking-tight text-white/90 transition-colors group-hover:text-white">
              CHYing
            </span>
            <span class="font-heading text-sm font-bold" style="color: var(--accent-green);">Agent</span>
          </div>
        </router-link>

        <!-- Nav Links -->
        <div class="flex items-center">
          <router-link
            v-for="link in links"
            :key="link.to"
            :to="link.to"
            class="relative px-3.5 py-2 text-sm font-medium transition-colors duration-150 cursor-pointer"
            :class="isActive(link.to) ? 'text-white' : 'text-white/45 hover:text-white/80'"
          >
            {{ link.label }}
            <!-- Active underline -->
            <span
              v-if="isActive(link.to)"
              class="absolute bottom-0 left-3.5 right-3.5 h-[2px] rounded-full"
              style="background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan));"
            />
          </router-link>
        </div>

      </div>
    </div>
  </nav>
</template>
