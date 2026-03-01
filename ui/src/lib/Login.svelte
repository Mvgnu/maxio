<script lang="ts">
  import { Button } from "$lib/components/ui/button";
  import { Input } from "$lib/components/ui/input";
  import Eye from "lucide-svelte/icons/eye";
  import EyeOff from "lucide-svelte/icons/eye-off";
  import { authLogin } from "$lib/api";

  let accessKey = $state('')
  let secretKey = $state('')
  let error = $state('')
  let loading = $state(false)
  let showSecret = $state(false)

  interface Props {
    onLogin: (accessKey: string) => void
  }
  let { onLogin }: Props = $props()

  async function handleSubmit(e: Event) {
    e.preventDefault()
    error = ''
    loading = true
    try {
      const result = await authLogin(accessKey, secretKey)
      if (result.ok) {
        onLogin(result.data.accessKey)
      } else {
        error = result.error || 'Invalid credentials'
      }
    } catch (err) {
      console.error('Login failed:', err)
      error = 'Connection failed'
    } finally {
      loading = false
    }
  }
</script>

<div class="flex min-h-screen w-full items-center justify-center bg-background">
  <div class="w-full max-w-lg px-6">
    <!-- Title -->
    <h1 class="mb-10 text-center text-4xl font-bold text-foreground">MaxIO</h1>

    <form onsubmit={handleSubmit} class="flex flex-col gap-6">
      <!-- Access Key -->
      <div class="flex flex-col gap-1.5">
        <label for="accessKey" class="text-sm text-muted-foreground">
          Access Key <span class="text-primary">*</span>
        </label>
        <Input
          id="accessKey"
          type="text"
          bind:value={accessKey}
          autocomplete="username"
          required
        />
      </div>

      <!-- Secret Key -->
      <div class="flex flex-col gap-1.5">
        <label for="secretKey" class="text-sm text-muted-foreground">
          Secret Key <span class="text-primary">*</span>
        </label>
        <div class="relative">
          <Input
            id="secretKey"
            type={showSecret ? 'text' : 'password'}
            bind:value={secretKey}
            autocomplete="current-password"
            class="pr-10"
            required
          />
          <button
            type="button"
            onclick={() => showSecret = !showSecret}
            class="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground transition-colors hover:text-foreground"
          >
            {#if showSecret}
              <EyeOff class="size-4" />
            {:else}
              <Eye class="size-4" />
            {/if}
          </button>
        </div>
      </div>

      {#if error}
        <p class="text-sm text-destructive">{error}</p>
      {/if}

      <!-- Login button — large highlighted style -->
      <Button type="submit" variant="brand" class="mt-2 h-16 w-full rounded text-sm font-medium" disabled={loading}>
        {loading ? 'Signing in...' : 'Login'}
      </Button>
    </form>
  </div>
</div>
