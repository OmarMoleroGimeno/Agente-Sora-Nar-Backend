<script setup>
import { computed, ref, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { useThemeStore } from '@/stores/theme';
import { useChatStore } from '@/stores/chat';
import Button from 'primevue/button';import IconField from 'primevue/iconfield';
import InputIcon from 'primevue/inputicon';
import InputText from 'primevue/inputtext';import { storeToRefs } from 'pinia';const router = useRouter();
const route = useRoute();
const apiUrl = import.meta.env.VITE_SERVER_URL || 'http://localhost:3000';
const authStore = useAuthStore();
const themeStore = useThemeStore();
const chatStore = useChatStore();
const { isDark, isSidebarExpanded } = storeToRefs(themeStore);
const isAdmin = computed(() => authStore.userRole === 'admin');
const isMobileMenuOpen = ref(false);

const toggleSidebar = () => {
    themeStore.toggleSidebar();
};

const handleSidebarClick = () => {
    if (!isSidebarExpanded.value) {
        themeStore.setSidebarExpanded(true);
    }
};

const handleLogout = () => {
  authStore.logout();
  router.push('/login');
};onMounted(async () => {
    if (authStore.token) {
        await chatStore.fetchThreads();
    }
});
</script><template>
  <div class="flex flex-col md:flex-row h-screen w-full bg-light-bg dark:bg-dark-bg transition-colors duration-300 font-sans overflow-hidden">
    
    <!-- Context Menu (Shared) -->
    <!-- Mobile Header -->
    <header class="md:hidden bg-white dark:bg-[#1E1E1E] border-b border-gray-100 dark:border-gray-800/50 px-4 py-3 flex items-center justify-between z-30 shrink-0">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 bg-gradient-to-br from-orange-500 to-orange-600 rounded-lg flex items-center justify-center shadow-lg shadow-orange-500/20">
                <i class="pi pi-bolt text-lg text-white"></i>
            </div>
            <span class="font-bold text-lg text-gray-900 dark:text-white tracking-tight">Aphelion</span>
        </div>
        <div class="flex items-center gap-2">
            <Button 
                :icon="isDark ? 'pi pi-sun' : 'pi pi-moon'" 
                text 
                rounded 
                @click="themeStore.toggleTheme()" 
                class="!text-gray-600 dark:!text-gray-300"
            />
            <Button icon="pi pi-ellipsis-v" text rounded @click="isMobileMenuOpen = !isMobileMenuOpen" class="!text-gray-600 dark:!text-gray-300" />
        </div>
    </header>    <!-- Desktop Sidebar (Left) -->
    <aside 
        class="hidden md:flex fixed hover:cursor-pointer inset-y-0 left-0 z-40 bg-white dark:bg-[#1E1E1E] border-r border-gray-100 dark:border-gray-800/50 flex-col shadow-sm transition-all duration-300 ease-in-out overflow-hidden relative"
        :class="isSidebarExpanded ? 'w-64' : 'w-20'"
        @click="handleSidebarClick"
    >
      <!-- Logo & Toggle -->
      <div 
        class="flex items-center h-20 pl-5 pr-4 relative cursor-pointer" 
        @click="!isSidebarExpanded && toggleSidebar()"
      >
        <div class="flex items-center gap-3 shrink-0 w-full pt-4">
        <img 
            :src="`${apiUrl}/logo-nar.png`" 
            alt="NAR Valencia"
            class="transition-all duration-300 dark:brightness-0 dark:invert"
            style="margin: 0 auto 20px; width: 130px; height: auto; display: block;"
        />
        </div>
        
        <Button 
            icon="pi pi-angle-left" 
            text 
            rounded 
            severity="secondary" 
            class="!absolute !right-3 !w-8 !h-8 !text-gray-400 hover:!bg-gray-100 dark:hover:!bg-[#2b2b40] transition-all duration-300"
            :class="isSidebarExpanded ? 'opacity-100 scale-100' : 'opacity-0 scale-75 pointer-events-none'"
            @click.stop="toggleSidebar"
        />
      </div>      <!-- Navigation (Desktop) -->
      <nav class="flex-1 flex flex-col px-3 py-4 min-h-0 overflow-hidden">
        <!-- Users (Admin) - Fixed at top -->
        <div class="shrink-0 mb-2">
            <router-link 
              v-if="isAdmin"
              to="/users"
              class="flex items-center py-3 rounded-xl transition-all duration-200 group relative"
              :class="[
                route.path === '/users' 
                  ? 'bg-orange-50 dark:bg-gray-500/30 text-orange-600 dark:text-orange-400' 
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-500/30 hover:text-gray-900 dark:hover:text-gray-200',
                isSidebarExpanded ? 'px-3 gap-3' : 'justify-center'
              ]"
              @click.stop
            >
              <i class="pi pi-users text-xl shrink-0"></i>
              <span 
                class="font-medium whitespace-nowrap transition-all duration-300 origin-left"
                :class="isSidebarExpanded ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4 w-0 overflow-hidden'"
              >
                Users
              </span>
              <span v-if="!isSidebarExpanded" class="absolute left-16 bg-gray-900 dark:bg-gray-500/30 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50 pointer-events-none">Users</span>
            </router-link>
        </div>        <!-- Knowledge Base -->
        <div class="shrink-0 mb-2">
            <router-link 
              v-if="isAdmin"
              to="/knowledge"
              class="flex items-center py-3 rounded-xl transition-all duration-200 group relative"
              :class="[
                route.path === '/knowledge' 
                  ? 'bg-orange-50 dark:bg-gray-500/30 text-orange-600 dark:text-orange-400' 
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-500/30 hover:text-gray-900 dark:hover:text-gray-200',
                isSidebarExpanded ? 'px-3 gap-3' : 'justify-center'
              ]"
              @click.stop
            >
              <i class="pi pi-book text-xl shrink-0"></i>
              <span 
                class="font-medium whitespace-nowrap transition-all duration-300 origin-left"
                :class="isSidebarExpanded ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4 w-0 overflow-hidden'"
              >
                Knowledge Base
              </span>
              <span v-if="!isSidebarExpanded" class="absolute left-16 bg-gray-900 dark:bg-gray-500/30 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50 pointer-events-none">Knowledge Base</span>
            </router-link>
        </div>        <!-- Tool Advisor -->
        <div class="shrink-0 mb-2">
            <router-link 
              to="/tool-advisor"
              class="flex items-center py-3 rounded-xl transition-all duration-200 group relative"
              :class="[
                route.path === '/tool-advisor' 
                  ? 'bg-orange-50 dark:bg-gray-500/30 text-orange-600 dark:text-orange-400' 
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-500/30 hover:text-gray-900 dark:hover:text-gray-200',
                isSidebarExpanded ? 'px-3 gap-3' : 'justify-center'
              ]"
              @click.stop
            >
              <i class="pi pi-compass text-xl shrink-0"></i>
              <span 
                class="font-medium whitespace-nowrap transition-all duration-300 origin-left"
                :class="isSidebarExpanded ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4 w-0 overflow-hidden'"
              >
                Tool Advisor
              </span>
              <span v-if="!isSidebarExpanded" class="absolute left-16 bg-gray-900 dark:bg-gray-500/30 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50 pointer-events-none">Tool Advisor</span>
            </router-link>
        </div>        <!-- Chats Link -->
        <div class="shrink-0 mb-2">
            <router-link 
              to="/chats"
              class="flex items-center py-3 rounded-xl transition-all duration-200 group relative"
              :class="[
                route.path === '/chats' 
                  ? 'bg-orange-50 dark:bg-gray-500/30 text-orange-600 dark:text-orange-400' 
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-500/30 hover:text-gray-900 dark:hover:text-gray-200',
                isSidebarExpanded ? 'px-3 gap-3' : 'justify-center'
              ]"
              @click.stop
            >
              <i class="pi pi-comments text-xl shrink-0"></i>
              <span 
                class="font-medium whitespace-nowrap transition-all duration-300 origin-left"
                :class="isSidebarExpanded ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4 w-0 overflow-hidden'"
              >
                Chats
              </span>
              <span v-if="!isSidebarExpanded" class="absolute left-16 bg-gray-900 dark:bg-gray-500/30 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50 pointer-events-none">Chats</span>
            </router-link>
        </div>
      </nav>      <!-- User Profile / Footer (Desktop) -->
      <div class="p-4 border-t border-gray-100 dark:border-gray-600/50">
        <div class="flex items-center rounded-xl transition-colors" :class="[
            isSidebarExpanded ? 'p-2 gap-3 bg-gray-50 dark:bg-gray-500/30' : 'py-2 justify-center'
        ]">
            <div class="w-9 h-9 rounded-lg bg-gray-200 dark:bg-[#151521] flex items-center justify-center text-gray-500 dark:text-gray-400 font-bold text-sm shrink-0 overflow-hidden">
                <img v-if="authStore.image" :src="authStore.image" alt="User" class="w-full h-full object-cover" />
                <span v-else>{{ authStore.user?.charAt(0).toUpperCase() || 'U' }}</span>
            </div>
            
            <div 
                class="flex flex-col min-w-0 flex-1 transition-all duration-300 origin-left"
                :class="isSidebarExpanded ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4 w-0 overflow-hidden'"
            >
                <span class="text-sm font-semibold text-gray-900 dark:text-white truncate">{{ authStore.user || 'User' }}</span>
                <span class="text-xs text-gray-500 dark:text-gray-400 truncate">{{ isAdmin ? 'Administrator' : 'User' }}</span>
            </div>            <div 
                class="flex items-center gap-1 transition-all duration-300"
                :class="isSidebarExpanded ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'"
            >
                <Button 
                    icon="pi pi-sign-out" 
                    text 
                    rounded 
                    severity="secondary" 
                    class="!w-7 !h-7 !text-gray-400 hover:!text-red-500"
                    @click="handleLogout"
                />
            </div>
        </div>
      </div>
    </aside>    <!-- Mobile Right Sidebar (Drawer) -->
    <div 
        class="md:hidden fixed inset-y-0 right-0 z-50 w-72 bg-white dark:bg-dark-surface shadow-2xl transform transition-transform duration-300 ease-in-out flex flex-col border-l border-gray-100 dark:border-gray-800/50"
        :class="isMobileMenuOpen ? 'translate-x-0' : 'translate-x-full'"
    >
        <div class="p-4 flex items-center justify-between border-b border-gray-100 dark:border-gray-800/50">
            <span class="font-bold text-lg text-gray-900 dark:text-white">Menu</span>
            <Button icon="pi pi-times" text rounded @click="isMobileMenuOpen = false" class="!text-gray-500 dark:!text-gray-400" />
        </div>        <nav class="flex-1 px-4 py-4 overflow-y-auto custom-scrollbar space-y-4">
             <!-- User Info Mobile -->
            <div class="flex items-center gap-3 p-3 rounded-xl bg-gray-50 dark:bg-[#151521]">
                <div class="w-10 h-10 rounded-lg bg-gray-200 dark:bg-gray-700 flex items-center justify-center text-gray-500 dark:text-gray-400 font-bold text-sm shrink-0 overflow-hidden">
                    <img v-if="authStore.image" :src="authStore.image" alt="User" class="w-full h-full object-cover" />
                    <span v-else>{{ authStore.user?.charAt(0).toUpperCase() || 'U' }}</span>
                </div>
                <div class="flex flex-col min-w-0 flex-1">
                    <span class="text-sm font-semibold text-gray-900 dark:text-white truncate">{{ authStore.user || 'User' }}</span>
                    <span class="text-xs text-gray-500 dark:text-gray-400 truncate">{{ isAdmin ? 'Administrator' : 'User' }}</span>
                </div>
            </div>            <!-- Navigation Links -->
            <router-link 
                v-if="isAdmin"
                to="/users"
                class="flex items-center gap-3 px-3 py-3 rounded-xl text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-[#2b2b40]/50 hover:text-gray-900 dark:hover:text-gray-200"
                @click="isMobileMenuOpen = false"
            >
                <i class="pi pi-users text-xl"></i>
                <span class="font-medium">Users</span>
            </router-link>            <router-link 
                v-if="isAdmin"
                to="/knowledge"
                class="flex items-center gap-3 px-3 py-3 rounded-xl text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-[#2b2b40]/50 hover:text-gray-900 dark:hover:text-gray-200"
                @click="isMobileMenuOpen = false"
            >
                <i class="pi pi-book text-xl"></i>
                <span class="font-medium">Knowledge Base</span>
            </router-link>            <div class="border-t border-gray-100 dark:border-gray-800/50 my-2"></div>            <router-link 
                to="/tool-advisor"
                class="flex items-center gap-3 px-3 py-3 rounded-xl text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-[#2b2b40]/50 hover:text-gray-900 dark:hover:text-gray-200"
                @click="isMobileMenuOpen = false"
            >
                <i class="pi pi-compass text-xl"></i>
                <span class="font-medium">Tool Advisor</span>
            </router-link>            <!-- Chats List Mobile -->
            <router-link 
                to="/chats"
                class="flex items-center gap-3 px-3 py-3 rounded-xl text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-[#2b2b40]/50 hover:text-gray-900 dark:hover:text-gray-200"
                @click="isMobileMenuOpen = false"
            >
                <i class="pi pi-comments text-xl"></i>
                <span class="font-medium">Chats</span>
            </router-link>
        </nav>        <div class="p-4 border-t border-gray-100 dark:border-gray-800/50 flex gap-2">
            <Button 
                icon="pi pi-sign-out" 
                label="Logout"
                severity="danger"
                outlined
                class="flex-1"
                @click="handleLogout"
            />
        </div>
    </div>    <!-- Overlay for mobile -->
    <div 
        v-if="isMobileMenuOpen" 
        class="fixed inset-0 bg-black/50 z-40 md:hidden backdrop-blur-sm"
        @click="isMobileMenuOpen = false"
    ></div>    <!-- Main Content -->
    <main 
        class="flex-1 flex flex-col min-w-0 overflow-hidden relative transition-all duration-300 ease-in-out"
    >
        <!-- Floating Dark Mode Toggle (Desktop) -->
        <div class="hidden md:block fixed top-4 right-6 z-50">
            <Button 
                :icon="isDark ? 'pi pi-sun' : 'pi pi-moon'" 
                rounded 
                @click="themeStore.toggleTheme()" 
                class="!bg-white/80 dark:!bg-zinc-800/80 backdrop-blur-md !border !border-gray-200 dark:!border-gray-700 !text-gray-600 dark:!text-gray-300 shadow-lg hover:!bg-white dark:hover:!bg-zinc-800 transition-all"
            />
        </div>
        <Transition name="page" mode="out-in">
            <slot />
        </Transition>
    </main>
  </div>
</template>
