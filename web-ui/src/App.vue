<script setup lang="ts">
import { useRoute } from 'vue-router'
import AppNav from './components/AppNav.vue'

const route = useRoute()
</script>

<template>
  <div class="mesh-bg min-h-screen">
    <AppNav />
    <main class="mx-auto max-w-7xl px-4 pt-20 pb-12 sm:px-6 lg:px-8">
      <router-view v-slot="{ Component }">
        <transition name="page" mode="out-in">
          <component :is="Component" :key="route.path" />
        </transition>
      </router-view>
    </main>
  </div>
</template>
