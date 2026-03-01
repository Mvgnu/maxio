<script lang="ts">
  import { onMount } from "svelte";
  import RefreshCw from "lucide-svelte/icons/refresh-cw";
  import { toast } from "svelte-sonner";
  import { getRuntimeHealthApi, getRuntimeMetricsApi } from "./api";

  let loading = $state(true);
  let requestsTotal = $state<number | null>(null);
  let uptimeSeconds = $state<number | null>(null);
  let version = $state<string | null>(null);
  let mode = $state<'standalone' | 'distributed' | null>(null);
  let nodeId = $state<string | null>(null);
  let clusterPeerCount = $state<number | null>(null);
  let healthOk = $state<boolean | null>(null);
  let raw = $state("");

  function formatUptime(seconds: number): string {
    const total = Math.max(0, Math.floor(seconds));
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const secs = total % 60;
    if (days > 0) return `${days}d ${hours}h ${minutes}m ${secs}s`;
    if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
    if (minutes > 0) return `${minutes}m ${secs}s`;
    return `${secs}s`;
  }

  async function loadMetrics() {
    loading = true;
    const [metricsResult, healthResult] = await Promise.all([
      getRuntimeMetricsApi(),
      getRuntimeHealthApi(),
    ]);

    if (!metricsResult.ok) {
      toast.error(metricsResult.error);
      loading = false;
      return;
    }

    requestsTotal = metricsResult.data.requestsTotal;
    uptimeSeconds = metricsResult.data.uptimeSeconds;
    version = metricsResult.data.version;
    mode = metricsResult.data.mode;
    nodeId = metricsResult.data.nodeId;
    clusterPeerCount = metricsResult.data.clusterPeerCount;
    raw = metricsResult.data.raw;

    if (healthResult.ok) {
      healthOk = healthResult.data.ok;
      if (uptimeSeconds === null) {
        uptimeSeconds = healthResult.data.uptimeSeconds;
      }
      if (mode === null) {
        mode = healthResult.data.mode;
      }
      if (nodeId === null) {
        nodeId = healthResult.data.nodeId;
      }
      if (clusterPeerCount === null) {
        clusterPeerCount = healthResult.data.clusterPeerCount;
      }
    } else {
      healthOk = null;
    }

    loading = false;
  }

  onMount(loadMetrics);
</script>

<div class="flex flex-col gap-6 max-w-4xl">
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold">Runtime Metrics</h2>
    <button
      onclick={loadMetrics}
      disabled={loading}
      class="inline-flex items-center gap-2 rounded-sm border px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground disabled:opacity-60"
      style="border-color: var(--cool-sidebar-border);"
    >
      <RefreshCw class="size-4" />
      Refresh
    </button>
  </div>

  <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
    <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
      <p class="text-xs text-muted-foreground">Health</p>
      <p class="mt-1 text-2xl font-semibold">
        {#if healthOk === true}
          OK
        {:else if healthOk === false}
          Degraded
        {:else}
          --
        {/if}
      </p>
    </div>
    <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
      <p class="text-xs text-muted-foreground">Requests Total</p>
      <p class="mt-1 text-2xl font-semibold">
        {#if requestsTotal !== null}{requestsTotal.toLocaleString()}{:else}--{/if}
      </p>
    </div>
    <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
      <p class="text-xs text-muted-foreground">Uptime</p>
      <p class="mt-1 text-2xl font-semibold">
        {#if uptimeSeconds !== null}{formatUptime(uptimeSeconds)}{:else}--{/if}
      </p>
    </div>
    <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
      <p class="text-xs text-muted-foreground">Version</p>
      <p class="mt-1 text-2xl font-semibold">{version ?? "--"}</p>
    </div>
    <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
      <p class="text-xs text-muted-foreground">Mode</p>
      <p class="mt-1 text-2xl font-semibold">{mode ?? "--"}</p>
    </div>
    <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
      <p class="text-xs text-muted-foreground">Cluster Peers</p>
      <p class="mt-1 text-2xl font-semibold">
        {#if clusterPeerCount !== null}{clusterPeerCount}{:else}--{/if}
      </p>
      {#if nodeId}
        <p class="mt-1 text-xs text-muted-foreground truncate" title={nodeId}>Node {nodeId}</p>
      {/if}
    </div>
  </div>

  <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
    <p class="mb-2 text-xs text-muted-foreground">Raw metrics payload</p>
    <pre class="overflow-x-auto text-xs leading-5 text-foreground whitespace-pre-wrap break-all">{raw || (loading ? "Loading..." : "No metrics available.")}</pre>
  </div>
</div>
