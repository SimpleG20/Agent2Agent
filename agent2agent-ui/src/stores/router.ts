import { writable } from 'svelte/store'

function createRouter() {
  const { subscribe, set } = writable(window.location.pathname)

  window.addEventListener('popstate', () => {
    set(window.location.pathname)
  })

  return {
    subscribe,
    navigate: (path: string) => {
      window.history.pushState({}, '', path)
      set(path)
    }
  }
}

export const currentPath = createRouter()
