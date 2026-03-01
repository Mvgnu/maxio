<script lang="ts">
  import { onMount } from 'svelte'
  import { toast } from '$lib/toast'
  import {
    getBucketLifecycleApi,
    getBucketVersioningApi,
    setBucketLifecycleApi,
    setBucketVersioningApi,
    type LifecycleRuleRecord,
  } from '$lib/api'

  interface Props {
    bucket: string
    onBack: () => void
  }
  let { bucket, onBack }: Props = $props()

  let versioningEnabled = $state(false)
  let versioningLoading = $state(true)
  let versioningSaving = $state(false)
  let error = $state<string | null>(null)
  let lifecycleRules = $state<LifecycleRuleRecord[]>([])
  let lifecycleLoading = $state(true)
  let lifecycleSaving = $state(false)
  let lifecycleError = $state<string | null>(null)

  async function fetchVersioning() {
    versioningLoading = true
    error = null
    try {
      const result = await getBucketVersioningApi(bucket)
      if (result.ok) {
        versioningEnabled = result.data.enabled
      } else {
        error = result.error || 'Failed to load versioning status'
      }
    } catch (err) {
      console.error('fetchVersioning failed:', err)
      error = 'Failed to connect to server'
    } finally {
      versioningLoading = false
    }
  }

  async function toggleVersioning() {
    const newState = !versioningEnabled
    if (versioningEnabled && !newState) {
      if (
        !confirm(
          'Suspend versioning?\n\nNew uploads will overwrite the current object version until versioning is enabled again. Existing object versions are preserved.'
        )
      ) {
        return
      }
    }
    versioningSaving = true
    try {
      const result = await setBucketVersioningApi(bucket, newState)
      if (result.ok) {
        versioningEnabled = newState
        toast.success(newState ? 'Versioning enabled' : 'Versioning disabled')
      } else {
        toast.error(result.error || 'Failed to update versioning')
      }
    } catch (err) {
      console.error('toggleVersioning failed:', err)
      toast.error('Failed to connect to server')
    } finally {
      versioningSaving = false
    }
  }

  async function fetchLifecycle() {
    lifecycleLoading = true
    lifecycleError = null
    try {
      const result = await getBucketLifecycleApi(bucket)
      if (result.ok) {
        lifecycleRules = result.data.rules
      } else {
        lifecycleError = result.error || 'Failed to load lifecycle rules'
      }
    } catch (err) {
      console.error('fetchLifecycle failed:', err)
      lifecycleError = 'Failed to connect to server'
    } finally {
      lifecycleLoading = false
    }
  }

  function nextRuleId(): string {
    let idx = lifecycleRules.length + 1
    while (lifecycleRules.some((rule) => rule.id === `rule-${idx}`)) {
      idx += 1
    }
    return `rule-${idx}`
  }

  function addLifecycleRule() {
    lifecycleRules = [
      ...lifecycleRules,
      {
        id: nextRuleId(),
        prefix: '',
        expirationDays: 30,
        enabled: true,
      },
    ]
  }

  function removeLifecycleRule(index: number) {
    lifecycleRules = lifecycleRules.filter((_, i) => i !== index)
  }

  function updateLifecycleRule(index: number, patch: Partial<LifecycleRuleRecord>) {
    lifecycleRules = lifecycleRules.map((rule, i) =>
      i === index ? { ...rule, ...patch } : rule
    )
  }

  function normalizedLifecycleRules(): LifecycleRuleRecord[] | null {
    const normalized = lifecycleRules.map((rule) => ({
      id: rule.id.trim(),
      prefix: rule.prefix.trim(),
      expirationDays: Math.floor(rule.expirationDays),
      enabled: rule.enabled,
    }))

    for (const rule of normalized) {
      if (!rule.id) {
        toast.error('Lifecycle rule ID is required')
        return null
      }
      if (!Number.isFinite(rule.expirationDays) || rule.expirationDays <= 0) {
        toast.error(`Lifecycle rule "${rule.id}" needs expiration days > 0`)
        return null
      }
    }

    const ids = new Set<string>()
    for (const rule of normalized) {
      if (ids.has(rule.id)) {
        toast.error(`Lifecycle rule ID "${rule.id}" is duplicated`)
        return null
      }
      ids.add(rule.id)
    }

    return normalized
  }

  async function saveLifecycleRules() {
    const normalized = normalizedLifecycleRules()
    if (!normalized) return

    lifecycleSaving = true
    try {
      const result = await setBucketLifecycleApi(bucket, normalized)
      if (result.ok) {
        lifecycleRules = normalized
        lifecycleError = null
        toast.success('Lifecycle rules updated')
      } else {
        toast.error(result.error || 'Failed to save lifecycle rules')
      }
    } catch (err) {
      console.error('saveLifecycleRules failed:', err)
      toast.error('Failed to connect to server')
    } finally {
      lifecycleSaving = false
    }
  }

  onMount(() => {
    fetchVersioning()
    fetchLifecycle()
  })
</script>

<div class="flex flex-col gap-6 max-w-2xl">
  {#if error}
    <div class="rounded-sm border border-destructive/50 bg-destructive/10 px-4 py-2 text-sm text-destructive">
      {error}
    </div>
  {/if}

  <div class="flex flex-col gap-4">
    <h3 class="text-sm font-medium text-muted-foreground uppercase tracking-wide">General</h3>

    <div class="flex items-center justify-between">
      <div class="flex flex-col gap-0.5">
        <span class="text-sm font-medium">Versioning</span>
        <span class="text-sm text-muted-foreground">
          {#if versioningLoading}
            Loading...
          {:else if versioningEnabled}
            Every upload creates a new version. Deleted files become delete markers.
          {:else}
            Versioning is currently suspended. New uploads overwrite the current version, and previously created versions remain available.
          {/if}
        </span>
      </div>
      {#if !versioningLoading}
        <button
          class="relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors {versioningEnabled ? 'dark:bg-brand bg-foreground' : 'bg-muted-foreground/30'}"
          onclick={toggleVersioning}
          disabled={versioningSaving}
          role="switch"
          aria-checked={versioningEnabled}
          aria-label={versioningEnabled ? 'Disable versioning' : 'Enable versioning'}
          title={versioningEnabled ? 'Disable versioning' : 'Enable versioning'}
        >
          <span
            class="pointer-events-none inline-block size-4 rounded-full bg-background shadow transition-transform {versioningEnabled ? 'translate-x-6' : 'translate-x-1'}"
          ></span>
        </button>
      {/if}
    </div>
  </div>

  <div class="flex flex-col gap-4">
    <div class="flex items-center justify-between">
      <h3 class="text-sm font-medium text-muted-foreground uppercase tracking-wide">Lifecycle</h3>
      <button class="btn-cool h-8 px-3 text-xs" onclick={addLifecycleRule} type="button">
        Add Rule
      </button>
    </div>

    {#if lifecycleError}
      <div class="rounded-sm border border-destructive/50 bg-destructive/10 px-4 py-2 text-sm text-destructive">
        {lifecycleError}
      </div>
    {/if}

    {#if lifecycleLoading}
      <p class="text-sm text-muted-foreground">Loading lifecycle rules...</p>
    {:else if lifecycleRules.length === 0}
      <p class="text-sm text-muted-foreground">
        No lifecycle rules configured. Add a rule to expire objects by prefix and age.
      </p>
    {:else}
      <div class="flex flex-col gap-2">
        {#each lifecycleRules as rule, index (`${rule.id}-${index}`)}
          <div class="grid gap-2 rounded-sm border border-border p-3 md:grid-cols-[1fr_1fr_140px_90px_70px]">
            <input
              class="input-cool h-8"
              type="text"
              placeholder="Rule ID"
              value={rule.id}
              oninput={(event) =>
                updateLifecycleRule(index, {
                  id: (event.currentTarget as HTMLInputElement).value,
                })}
            />
            <input
              class="input-cool h-8"
              type="text"
              placeholder="Prefix (e.g. logs/)"
              value={rule.prefix}
              oninput={(event) =>
                updateLifecycleRule(index, {
                  prefix: (event.currentTarget as HTMLInputElement).value,
                })}
            />
            <input
              class="input-cool h-8"
              type="number"
              min="1"
              step="1"
              value={String(rule.expirationDays)}
              oninput={(event) => {
                const parsed = Number.parseInt(
                  (event.currentTarget as HTMLInputElement).value,
                  10
                )
                updateLifecycleRule(index, {
                  expirationDays: Number.isFinite(parsed) ? parsed : 0,
                })
              }}
            />
            <button
              type="button"
              class="relative inline-flex h-8 w-14 shrink-0 cursor-pointer items-center rounded-full transition-colors {rule.enabled ? 'dark:bg-brand bg-foreground' : 'bg-muted-foreground/30'}"
              onclick={() => updateLifecycleRule(index, { enabled: !rule.enabled })}
              role="switch"
              aria-checked={rule.enabled}
              title={rule.enabled ? 'Disable rule' : 'Enable rule'}
            >
              <span
                class="pointer-events-none inline-block size-4 rounded-full bg-background shadow transition-transform {rule.enabled ? 'translate-x-9' : 'translate-x-1'}"
              ></span>
            </button>
            <button
              class="btn-cool h-8 px-2 text-xs"
              type="button"
              onclick={() => removeLifecycleRule(index)}
            >
              Remove
            </button>
          </div>
        {/each}
      </div>
    {/if}

    <div class="flex justify-end">
      <button
        class="btn-cool h-8 px-3 text-xs"
        type="button"
        disabled={lifecycleSaving || lifecycleLoading}
        onclick={saveLifecycleRules}
      >
        {lifecycleSaving ? 'Saving...' : 'Save Lifecycle Rules'}
      </button>
    </div>
  </div>
</div>
