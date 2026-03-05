import {
  getRuntimeHealthApi,
  getRuntimeMembershipApi,
  getRuntimeMetricsApi,
  getRuntimeSummaryApi,
  type ApiResult,
  type RuntimeHealth,
  type RuntimeMembership,
  type RuntimeMetrics,
  type RuntimeSummary,
} from './api'

export interface SystemMetricsSnapshot {
  requestsTotal: number | null
  uptimeSeconds: number | null
  version: string | null
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number | null
  placementEpoch: number | null
  membershipViewId: string | null
  membershipLastUpdateAgeMs: number | null
  membershipProtocol: string | null
  coordinatorNodeId: string | null
  leaderNodeId: string | null
  membershipNodeCount: number | null
  healthOk: boolean | null
  healthStatus: string | null
  clusterPeerAuthProductionReady: boolean | null
  clusterAuthProductionReason: string | null
  healthWarnings: string[]
  healthChecks: RuntimeHealth['checks']
  raw: string
}

interface SystemMetricsLoaders {
  getSummary: () => Promise<ApiResult<RuntimeSummary>>
  getMetrics: () => Promise<ApiResult<RuntimeMetrics>>
  getHealth: () => Promise<ApiResult<RuntimeHealth>>
  getMembership: () => Promise<ApiResult<RuntimeMembership>>
}

function checksWithFallback(
  checks: RuntimeHealth['checks'],
  metricsProtocolReady: boolean | null,
  metricsClusterPeerAuthProductionReady: boolean | null
): RuntimeHealth['checks'] {
  if (checks !== null) {
    return checks
  }
  if (metricsProtocolReady === null && metricsClusterPeerAuthProductionReady === null) {
    return null
  }
  return {
    dataDirAccessible: null,
    dataDirWritable: null,
    storageDataPathReadable: null,
    diskHeadroomSufficient: null,
    peerConnectivityReady: null,
    membershipProtocolReady: metricsProtocolReady,
    clusterPeerAuthProductionReady: metricsClusterPeerAuthProductionReady,
  }
}

const defaultLoaders: SystemMetricsLoaders = {
  getSummary: getRuntimeSummaryApi,
  getMetrics: getRuntimeMetricsApi,
  getHealth: getRuntimeHealthApi,
  getMembership: getRuntimeMembershipApi,
}

export async function loadSystemMetricsSnapshot(
  loaders: SystemMetricsLoaders = defaultLoaders
): Promise<ApiResult<SystemMetricsSnapshot>> {
  const summaryResult = await loaders.getSummary()
  if (summaryResult.ok) {
    let membership = summaryResult.data.membership
    if (membership === null) {
      const membershipResult = await loaders.getMembership()
      if (membershipResult.ok) {
        membership = membershipResult.data
      }
    }

    return {
      ok: true,
      status: summaryResult.status,
      data: {
        requestsTotal: summaryResult.data.metrics.requestsTotal,
        uptimeSeconds:
          summaryResult.data.metrics.uptimeSeconds ??
          summaryResult.data.health.uptimeSeconds,
        version: summaryResult.data.metrics.version ?? summaryResult.data.health.version,
        mode: summaryResult.data.topology.mode,
        nodeId: summaryResult.data.topology.nodeId,
        clusterPeerCount: summaryResult.data.topology.clusterPeerCount,
        placementEpoch:
          summaryResult.data.topology.placementEpoch ??
          summaryResult.data.health.placementEpoch,
        membershipViewId:
          membership?.viewId ??
          summaryResult.data.health.membershipViewId,
        membershipLastUpdateAgeMs:
          summaryResult.data.metrics.membershipLastUpdateAgeMs ??
          summaryResult.data.health.membershipLastUpdateAgeMs,
        membershipProtocol:
          membership?.protocol ??
          summaryResult.data.health.membershipProtocol ??
          summaryResult.data.topology.membershipProtocol ??
          summaryResult.data.metrics.membershipProtocol,
        coordinatorNodeId:
          membership?.coordinatorNodeId ??
          summaryResult.data.topology.nodeId,
        leaderNodeId:
          membership?.leaderNodeId ??
          (summaryResult.data.topology.mode === 'standalone'
            ? summaryResult.data.topology.nodeId
            : null),
        membershipNodeCount: membership?.nodes.length ?? null,
        healthOk: summaryResult.data.health.ok,
        healthStatus: summaryResult.data.health.status,
        clusterPeerAuthProductionReady:
          summaryResult.data.health.checks?.clusterPeerAuthProductionReady ??
          summaryResult.data.metrics.clusterPeerAuthProductionReady,
        clusterAuthProductionReason:
          summaryResult.data.health.clusterAuthProductionReason ??
          summaryResult.data.metrics.clusterAuthProductionReason,
        healthWarnings: summaryResult.data.health.warnings,
        healthChecks: checksWithFallback(
          summaryResult.data.health.checks,
          summaryResult.data.metrics.membershipProtocolReady,
          summaryResult.data.metrics.clusterPeerAuthProductionReady
        ),
        raw: JSON.stringify(
          {
            health: summaryResult.data.health.raw,
            metrics: summaryResult.data.metrics.raw,
            topology: summaryResult.data.topology.raw,
            membership: membership?.raw ?? null,
          },
          null,
          2
        ),
      },
    }
  }

  const [metricsResult, healthResult, fallbackMembershipResult] = await Promise.all([
    loaders.getMetrics(),
    loaders.getHealth(),
    loaders.getMembership(),
  ])

  if (!metricsResult.ok) {
    return {
      ok: false,
      status: metricsResult.status,
      error: metricsResult.error || summaryResult.error,
      data: metricsResult.data,
    }
  }

  return {
    ok: true,
    status: metricsResult.status,
    data: {
      requestsTotal: metricsResult.data.requestsTotal,
      uptimeSeconds:
        metricsResult.data.uptimeSeconds ??
        (healthResult.ok ? healthResult.data.uptimeSeconds : null),
      version:
        metricsResult.data.version ??
        (healthResult.ok ? healthResult.data.version : null),
      mode: metricsResult.data.mode ?? (healthResult.ok ? healthResult.data.mode : null),
      nodeId:
        metricsResult.data.nodeId ?? (healthResult.ok ? healthResult.data.nodeId : null),
      clusterPeerCount:
        metricsResult.data.clusterPeerCount ??
        (healthResult.ok ? healthResult.data.clusterPeerCount : null),
      placementEpoch:
        metricsResult.data.placementEpoch ??
        (healthResult.ok ? healthResult.data.placementEpoch : null),
      membershipViewId:
        (fallbackMembershipResult.ok ? fallbackMembershipResult.data.viewId : null) ??
        (healthResult.ok ? healthResult.data.membershipViewId : null),
      membershipLastUpdateAgeMs:
        (healthResult.ok ? healthResult.data.membershipLastUpdateAgeMs : null) ??
        metricsResult.data.membershipLastUpdateAgeMs,
      membershipProtocol: fallbackMembershipResult.ok
        ? fallbackMembershipResult.data.protocol
        : (healthResult.ok
            ? healthResult.data.membershipProtocol
            : metricsResult.data.membershipProtocol),
      coordinatorNodeId:
        (fallbackMembershipResult.ok
          ? fallbackMembershipResult.data.coordinatorNodeId
          : null) ??
        (metricsResult.data.nodeId ?? (healthResult.ok ? healthResult.data.nodeId : null)),
      leaderNodeId:
        (fallbackMembershipResult.ok ? fallbackMembershipResult.data.leaderNodeId : null) ??
        ((metricsResult.data.mode ?? (healthResult.ok ? healthResult.data.mode : null)) ===
        'standalone'
          ? metricsResult.data.nodeId ?? (healthResult.ok ? healthResult.data.nodeId : null)
          : null),
      membershipNodeCount: fallbackMembershipResult.ok
        ? fallbackMembershipResult.data.nodes.length
        : null,
      healthOk: healthResult.ok ? healthResult.data.ok : null,
      healthStatus: healthResult.ok ? healthResult.data.status : null,
      clusterPeerAuthProductionReady:
        (healthResult.ok
          ? healthResult.data.checks?.clusterPeerAuthProductionReady ?? null
          : null) ?? metricsResult.data.clusterPeerAuthProductionReady,
      clusterAuthProductionReason:
        (healthResult.ok ? healthResult.data.clusterAuthProductionReason : null) ??
        metricsResult.data.clusterAuthProductionReason,
      healthWarnings: healthResult.ok ? healthResult.data.warnings : [],
      healthChecks: checksWithFallback(
        healthResult.ok ? healthResult.data.checks : null,
        metricsResult.data.membershipProtocolReady,
        metricsResult.data.clusterPeerAuthProductionReady
      ),
      raw: metricsResult.data.raw,
    },
  }
}
