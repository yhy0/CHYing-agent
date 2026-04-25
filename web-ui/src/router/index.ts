import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('@/views/DashboardView.vue'),
  },
  {
    path: '/challenges',
    name: 'Challenges',
    component: () => import('@/views/ChallengesView.vue'),
  },
  {
    path: '/challenges/:id',
    name: 'ChallengeDetail',
    component: () => import('@/views/ChallengeDetailView.vue'),
    props: true,
  },
  {
    path: '/executions/:id',
    name: 'ExecutionDetail',
    component: () => import('@/views/ExecutionDetailView.vue'),
    props: true,
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
