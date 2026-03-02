<script lang="ts">
  import { onMount } from "svelte";
  import RefreshCw from "lucide-svelte/icons/refresh-cw";
  import { toast } from "svelte-sonner";
  import { getRuntimePlacementApi, getRuntimeRebalanceApi } from "./api";
  import type { RuntimeRebalanceLocalAction } from "./api";
  import { loadSystemMetricsSnapshot } from "./system-metrics";
  import { errorMessageOrFallback } from "./error-message";
  import { parsePlacementLookupRequest } from "./system-placement";
  import { parseRebalanceLookupRequest } from "./system-rebalance";

  let loading = $state(true);
  let requestsTotal = $state<number | null>(null);
  let uptimeSeconds = $state<number | null>(null);
  let version = $state<string | null>(null);
  let mode = $state<'standalone' | 'distributed' | null>(null);
  let nodeId = $state<string | null>(null);
  let clusterPeerCount = $state<number | null>(null);
  let placementEpoch = $state<number | null>(null);
  let membershipViewId = $state<string | null>(null);
  let membershipProtocol = $state<string | null>(null);
  let coordinatorNodeId = $state<string | null>(null);
  let leaderNodeId = $state<string | null>(null);
  let membershipNodeCount = $state<number | null>(null);
  let healthOk = $state<boolean | null>(null);
  let healthStatus = $state<string | null>(null);
  let healthWarnings = $state<string[]>([]);
  let healthChecks = $state<{
    dataDirAccessible: boolean | null;
    dataDirWritable: boolean | null;
    storageDataPathReadable: boolean | null;
    diskHeadroomSufficient: boolean | null;
    peerConnectivityReady: boolean | null;
    membershipProtocolReady: boolean | null;
  } | null>(null);
  let raw = $state("");
  let placementLoading = $state(false);
  let placementKey = $state("");
  let placementReplicaCount = $state("2");
  let placementChunkIndex = $state("");
  let placementOwners = $state<string[]>([]);
  let placementMode = $state<string | null>(null);
  let placementAppliedReplicaCount = $state<number | null>(null);
  let placementWriteQuorumSize = $state<number | null>(null);
  let placementWriteAckPolicy = $state<string | null>(null);
  let placementNonOwnerMutationPolicy = $state<string | null>(null);
  let placementNonOwnerReadPolicy = $state<string | null>(null);
  let placementNonOwnerBatchMutationPolicy = $state<string | null>(null);
  let placementMixedOwnerBatchMutationPolicy = $state<string | null>(null);
  let placementReplicaFanoutOperations = $state<string[]>([]);
  let placementPendingReplicaFanoutOperations = $state<string[]>([]);
  let placementMembershipViewId = $state<string | null>(null);
  let placementPrimaryOwner = $state<string | null>(null);
  let placementForwardTarget = $state<string | null>(null);
  let placementIsLocalPrimaryOwner = $state<boolean | null>(null);
  let placementIsLocalReplicaOwner = $state<boolean | null>(null);
  let rebalanceLoading = $state(false);
  let rebalanceKey = $state("");
  let rebalanceReplicaCount = $state("2");
  let rebalanceChunkIndex = $state("");
  let rebalanceOperation = $state<"join" | "leave">("join");
  let rebalancePeer = $state("");
  let rebalanceSourcePeers = $state<string[]>([]);
  let rebalanceTargetPeers = $state<string[]>([]);
  let rebalancePrevOwners = $state<string[]>([]);
  let rebalanceNextOwners = $state<string[]>([]);
  let rebalanceAddedOwners = $state<string[]>([]);
  let rebalanceRemovedOwners = $state<string[]>([]);
  let rebalanceTransferCount = $state<number | null>(null);
  let rebalanceLocalActions = $state<RuntimeRebalanceLocalAction[]>([]);

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
    const result = await loadSystemMetricsSnapshot();
    if (!result.ok) {
      toast.error(errorMessageOrFallback(result.error, "Failed to load metrics."));
      loading = false;
      return;
    }

    requestsTotal = result.data.requestsTotal;
    uptimeSeconds = result.data.uptimeSeconds;
    version = result.data.version;
    mode = result.data.mode;
    nodeId = result.data.nodeId;
    clusterPeerCount = result.data.clusterPeerCount;
    placementEpoch = result.data.placementEpoch;
    membershipViewId = result.data.membershipViewId;
    membershipProtocol = result.data.membershipProtocol;
    coordinatorNodeId = result.data.coordinatorNodeId;
    leaderNodeId = result.data.leaderNodeId;
    membershipNodeCount = result.data.membershipNodeCount;
    healthOk = result.data.healthOk;
    healthStatus = result.data.healthStatus;
    healthWarnings = result.data.healthWarnings;
    healthChecks = result.data.healthChecks;
    raw = result.data.raw;

    loading = false;
  }

  async function lookupPlacement() {
    const parsedRequest = parsePlacementLookupRequest({
      key: placementKey,
      replicaCountInput: placementReplicaCount,
      chunkIndexInput: placementChunkIndex,
    });
    if (!parsedRequest.ok) {
      toast.error(parsedRequest.error);
      return;
    }

    placementLoading = true;
    const result = await getRuntimePlacementApi({
      key: parsedRequest.data.key,
      replicaCount: parsedRequest.data.replicaCount,
      chunkIndex: parsedRequest.data.chunkIndex,
    });
    placementLoading = false;

    if (!result.ok) {
      toast.error(errorMessageOrFallback(result.error, "Failed to load placement preview."));
      return;
    }

    placementOwners = result.data.owners;
    placementMode = result.data.mode;
    placementAppliedReplicaCount = result.data.replicaCountApplied;
    placementWriteQuorumSize = result.data.writeQuorumSize;
    placementWriteAckPolicy = result.data.writeAckPolicy;
    placementNonOwnerMutationPolicy = result.data.nonOwnerMutationPolicy;
    placementNonOwnerReadPolicy = result.data.nonOwnerReadPolicy;
    placementNonOwnerBatchMutationPolicy = result.data.nonOwnerBatchMutationPolicy;
    placementMixedOwnerBatchMutationPolicy = result.data.mixedOwnerBatchMutationPolicy;
    placementReplicaFanoutOperations = result.data.replicaFanoutOperations;
    placementPendingReplicaFanoutOperations = result.data.pendingReplicaFanoutOperations;
    placementMembershipViewId = result.data.membershipViewId;
    placementPrimaryOwner = result.data.primaryOwner;
    placementForwardTarget = result.data.forwardTarget;
    placementIsLocalPrimaryOwner = result.data.isLocalPrimaryOwner;
    placementIsLocalReplicaOwner = result.data.isLocalReplicaOwner;
  }

  async function lookupRebalance() {
    const parsedRequest = parseRebalanceLookupRequest({
      key: rebalanceKey,
      replicaCountInput: rebalanceReplicaCount,
      chunkIndexInput: rebalanceChunkIndex,
      operationInput: rebalanceOperation,
      peerInput: rebalancePeer,
    });
    if (!parsedRequest.ok) {
      toast.error(parsedRequest.error);
      return;
    }

    rebalanceLoading = true;
    const result = await getRuntimeRebalanceApi({
      key: parsedRequest.data.key,
      replicaCount: parsedRequest.data.replicaCount,
      chunkIndex: parsedRequest.data.chunkIndex,
      operation: parsedRequest.data.operation,
      peer: parsedRequest.data.peer,
    });
    rebalanceLoading = false;

    if (!result.ok) {
      toast.error(errorMessageOrFallback(result.error, "Failed to load rebalance preview."));
      return;
    }

    rebalanceSourcePeers = result.data.source.clusterPeers;
    rebalanceTargetPeers = result.data.target.clusterPeers;
    rebalancePrevOwners = result.data.plan.previousOwners;
    rebalanceNextOwners = result.data.plan.nextOwners;
    rebalanceAddedOwners = result.data.plan.addedOwners;
    rebalanceRemovedOwners = result.data.plan.removedOwners;
    rebalanceTransferCount = result.data.plan.transferCount;
    rebalanceLocalActions = result.data.plan.localActions;
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
        {#if healthStatus}
          {healthStatus}
        {:else if healthOk === true}
          OK
        {:else if healthOk === false}
          Degraded
        {:else}
          --
        {/if}
      </p>
      {#if healthWarnings.length > 0}
        <p class="mt-1 text-xs text-muted-foreground">{healthWarnings.length} warning(s)</p>
      {/if}
      {#if healthChecks}
        <p class="mt-1 text-xs text-muted-foreground">
          Data dir writable: {healthChecks.dataDirWritable === null ? "--" : healthChecks.dataDirWritable ? "yes" : "no"}
        </p>
        <p class="mt-1 text-xs text-muted-foreground">
          Data path readable: {healthChecks.storageDataPathReadable === null ? "--" : healthChecks.storageDataPathReadable ? "yes" : "no"}
        </p>
        <p class="mt-1 text-xs text-muted-foreground">
          Disk headroom: {healthChecks.diskHeadroomSufficient === null ? "--" : healthChecks.diskHeadroomSufficient ? "yes" : "no"}
        </p>
        <p class="mt-1 text-xs text-muted-foreground">
          Peer connectivity: {healthChecks.peerConnectivityReady === null ? "--" : healthChecks.peerConnectivityReady ? "yes" : "no"}
        </p>
        <p class="mt-1 text-xs text-muted-foreground">
          Protocol ready: {healthChecks.membershipProtocolReady === null ? "--" : healthChecks.membershipProtocolReady ? "yes" : "no"}
        </p>
      {/if}
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
      {#if membershipProtocol}
        <p class="mt-1 text-xs text-muted-foreground truncate" title={membershipProtocol}>
          Protocol {membershipProtocol}
        </p>
      {/if}
      {#if placementEpoch !== null}
        <p class="mt-1 text-xs text-muted-foreground">Epoch {placementEpoch}</p>
      {/if}
      {#if membershipViewId}
        <p class="mt-1 text-xs text-muted-foreground truncate" title={membershipViewId}>
          View {membershipViewId}
        </p>
      {/if}
    </div>
    <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
      <p class="text-xs text-muted-foreground">Cluster Peers</p>
      <p class="mt-1 text-2xl font-semibold">
        {#if clusterPeerCount !== null}{clusterPeerCount}{:else}--{/if}
      </p>
      {#if nodeId}
        <p class="mt-1 text-xs text-muted-foreground truncate" title={nodeId}>Node {nodeId}</p>
      {/if}
      {#if coordinatorNodeId}
        <p class="mt-1 text-xs text-muted-foreground truncate" title={coordinatorNodeId}>
          Coordinator {coordinatorNodeId}
        </p>
      {/if}
      {#if leaderNodeId}
        <p class="mt-1 text-xs text-muted-foreground truncate" title={leaderNodeId}>
          Leader {leaderNodeId}
        </p>
      {/if}
      {#if membershipNodeCount !== null}
        <p class="mt-1 text-xs text-muted-foreground">Members {membershipNodeCount}</p>
      {/if}
    </div>
  </div>

  <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
    <p class="mb-2 text-xs text-muted-foreground">Raw metrics payload</p>
    <pre class="overflow-x-auto text-xs leading-5 text-foreground whitespace-pre-wrap break-all">{raw || (loading ? "Loading..." : "No metrics available.")}</pre>
  </div>

  <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
    <p class="mb-3 text-xs text-muted-foreground">Placement preview</p>
    <div class="grid gap-3 md:grid-cols-[2fr_1fr_1fr_auto]">
      <input
        bind:value={placementKey}
        placeholder="Object key (for example videos/movie.mp4)"
        class="w-full rounded-sm border bg-transparent px-3 py-2 text-sm outline-none"
        style="border-color: var(--cool-sidebar-border);"
      />
      <input
        bind:value={placementReplicaCount}
        placeholder="Replicas"
        class="w-full rounded-sm border bg-transparent px-3 py-2 text-sm outline-none"
        style="border-color: var(--cool-sidebar-border);"
      />
      <input
        bind:value={placementChunkIndex}
        placeholder="Chunk index (optional)"
        class="w-full rounded-sm border bg-transparent px-3 py-2 text-sm outline-none"
        style="border-color: var(--cool-sidebar-border);"
      />
      <button
        onclick={lookupPlacement}
        disabled={placementLoading}
        class="inline-flex items-center justify-center rounded-sm border px-3 py-2 text-sm text-muted-foreground transition-colors hover:text-foreground disabled:opacity-60"
        style="border-color: var(--cool-sidebar-border);"
      >
        {#if placementLoading}Loading...{:else}Lookup{/if}
      </button>
    </div>
    {#if placementMode || placementAppliedReplicaCount !== null}
      <div class="mt-3 text-xs text-muted-foreground">
        <p>Mode: {placementMode ?? "--"}</p>
        <p>Applied replicas: {placementAppliedReplicaCount ?? "--"}</p>
        <p>Write quorum size: {placementWriteQuorumSize ?? "--"}</p>
        <p>Write ack policy: {placementWriteAckPolicy ?? "--"}</p>
        <p>
          Non-owner mutation policy: {placementNonOwnerMutationPolicy ?? "--"}
        </p>
        <p>
          Non-owner read policy: {placementNonOwnerReadPolicy ?? "--"}
        </p>
        <p>
          Non-owner batch mutation policy: {placementNonOwnerBatchMutationPolicy ?? "--"}
        </p>
        <p>
          Mixed-owner batch mutation policy: {placementMixedOwnerBatchMutationPolicy ?? "--"}
        </p>
        <p>
          Replica fanout operations: {placementReplicaFanoutOperations.length === 0 ? "--" : placementReplicaFanoutOperations.join(", ")}
        </p>
        <p>
          Pending fanout operations: {placementPendingReplicaFanoutOperations.length === 0 ? "--" : placementPendingReplicaFanoutOperations.join(", ")}
        </p>
        <p class="truncate" title={placementPrimaryOwner ?? undefined}>
          Primary owner: {placementPrimaryOwner ?? "--"}
        </p>
        <p class="truncate" title={placementForwardTarget ?? undefined}>
          Forward target: {placementForwardTarget ?? "--"}
        </p>
        <p>
          Local primary owner: {placementIsLocalPrimaryOwner === null ? "--" : placementIsLocalPrimaryOwner ? "yes" : "no"}
        </p>
        <p>
          Local replica owner: {placementIsLocalReplicaOwner === null ? "--" : placementIsLocalReplicaOwner ? "yes" : "no"}
        </p>
        {#if placementMembershipViewId}
          <p class="truncate" title={placementMembershipViewId}>View: {placementMembershipViewId}</p>
        {/if}
      </div>
    {/if}
    <div class="mt-3">
      <p class="mb-1 text-xs text-muted-foreground">Owners</p>
      {#if placementOwners.length === 0}
        <p class="text-xs text-muted-foreground">No owners resolved yet.</p>
      {:else}
        <ul class="space-y-1 text-sm">
          {#each placementOwners as owner, index}
            <li class="truncate" title={owner}>#{index + 1} {owner}</li>
          {/each}
        </ul>
      {/if}
    </div>
  </div>

  <div class="rounded-sm border p-4" style="border-color: var(--cool-sidebar-border);">
    <p class="mb-3 text-xs text-muted-foreground">Rebalance preview</p>
    <div class="grid gap-3 md:grid-cols-[2fr_1fr_1fr_1fr_2fr_auto]">
      <input
        bind:value={rebalanceKey}
        placeholder="Object key"
        class="w-full rounded-sm border bg-transparent px-3 py-2 text-sm outline-none"
        style="border-color: var(--cool-sidebar-border);"
      />
      <input
        bind:value={rebalanceReplicaCount}
        placeholder="Replicas"
        class="w-full rounded-sm border bg-transparent px-3 py-2 text-sm outline-none"
        style="border-color: var(--cool-sidebar-border);"
      />
      <input
        bind:value={rebalanceChunkIndex}
        placeholder="Chunk index"
        class="w-full rounded-sm border bg-transparent px-3 py-2 text-sm outline-none"
        style="border-color: var(--cool-sidebar-border);"
      />
      <select
        bind:value={rebalanceOperation}
        class="w-full rounded-sm border bg-transparent px-3 py-2 text-sm outline-none"
        style="border-color: var(--cool-sidebar-border);"
      >
        <option value="join">join</option>
        <option value="leave">leave</option>
      </select>
      <input
        bind:value={rebalancePeer}
        placeholder="Peer host:port"
        class="w-full rounded-sm border bg-transparent px-3 py-2 text-sm outline-none"
        style="border-color: var(--cool-sidebar-border);"
      />
      <button
        onclick={lookupRebalance}
        disabled={rebalanceLoading}
        class="inline-flex items-center justify-center rounded-sm border px-3 py-2 text-sm text-muted-foreground transition-colors hover:text-foreground disabled:opacity-60"
        style="border-color: var(--cool-sidebar-border);"
      >
        {#if rebalanceLoading}Loading...{:else}Preview{/if}
      </button>
    </div>
    {#if rebalanceTransferCount !== null}
      <div class="mt-3 text-xs text-muted-foreground">
        <p>Transfers: {rebalanceTransferCount}</p>
        <p>Source peers: {rebalanceSourcePeers.length}</p>
        <p>Target peers: {rebalanceTargetPeers.length}</p>
      </div>
    {/if}
    <div class="mt-3 grid gap-3 md:grid-cols-2">
      <div>
        <p class="mb-1 text-xs text-muted-foreground">Previous owners</p>
        {#if rebalancePrevOwners.length === 0}
          <p class="text-xs text-muted-foreground">No owners resolved.</p>
        {:else}
          <ul class="space-y-1 text-sm">
            {#each rebalancePrevOwners as owner}
              <li class="truncate" title={owner}>{owner}</li>
            {/each}
          </ul>
        {/if}
      </div>
      <div>
        <p class="mb-1 text-xs text-muted-foreground">Next owners</p>
        {#if rebalanceNextOwners.length === 0}
          <p class="text-xs text-muted-foreground">No owners resolved.</p>
        {:else}
          <ul class="space-y-1 text-sm">
            {#each rebalanceNextOwners as owner}
              <li class="truncate" title={owner}>{owner}</li>
            {/each}
          </ul>
        {/if}
      </div>
      <div>
        <p class="mb-1 text-xs text-muted-foreground">Added owners</p>
        {#if rebalanceAddedOwners.length === 0}
          <p class="text-xs text-muted-foreground">No added owners.</p>
        {:else}
          <ul class="space-y-1 text-sm">
            {#each rebalanceAddedOwners as owner}
              <li class="truncate" title={owner}>{owner}</li>
            {/each}
          </ul>
        {/if}
      </div>
      <div>
        <p class="mb-1 text-xs text-muted-foreground">Removed owners</p>
        {#if rebalanceRemovedOwners.length === 0}
          <p class="text-xs text-muted-foreground">No removed owners.</p>
        {:else}
          <ul class="space-y-1 text-sm">
            {#each rebalanceRemovedOwners as owner}
              <li class="truncate" title={owner}>{owner}</li>
            {/each}
          </ul>
        {/if}
      </div>
      <div class="md:col-span-2">
        <p class="mb-1 text-xs text-muted-foreground">Local actions</p>
        {#if rebalanceLocalActions.length === 0}
          <p class="text-xs text-muted-foreground">No local actions for this node.</p>
        {:else}
          <ul class="space-y-1 text-sm">
            {#each rebalanceLocalActions as action}
              <li class="truncate" title={`${action.action} ${action.from ?? "--"} -> ${action.to}`}>
                {action.action}: {action.from ?? "--"} -> {action.to}
              </li>
            {/each}
          </ul>
        {/if}
      </div>
    </div>
  </div>
</div>
