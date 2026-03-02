export type ApiSuccess<T> = {
  ok: true
  status: number
  data: T
}

export type ApiFailure = {
  ok: false
  status: number
  error: string
  data: unknown
}

export type ApiResult<T> = ApiSuccess<T> | ApiFailure

function encodePathPreservingDelimiters(path: string): string {
  return path
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/')
}

function objectPath(bucket: string, namespace: string, key: string): string {
  return `/api/buckets/${encodeURIComponent(bucket)}/${namespace}/${encodePathPreservingDelimiters(key)}`
}

async function requestJson<T>(input: RequestInfo, init?: RequestInit): Promise<ApiResult<T>> {
  let response: Response
  try {
    response = await fetch(input, init)
  } catch (error) {
    return {
      ok: false,
      status: 0,
      error: error instanceof Error ? error.message : 'Network request failed',
      data: null,
    }
  }

  let data: unknown = null
  try {
    data = await response.json()
  } catch {
    data = null
  }

  if (response.ok) {
    return {
      ok: true,
      status: response.status,
      data: (data ?? {}) as T,
    }
  }

  const message =
    typeof data === 'object' &&
    data !== null &&
    'error' in data &&
    typeof (data as { error: unknown }).error === 'string'
      ? (data as { error: string }).error
      : `Request failed (${response.status})`

  return {
    ok: false,
    status: response.status,
    error: message,
    data,
  }
}

async function requestText(input: RequestInfo, init?: RequestInit): Promise<ApiResult<string>> {
  let response: Response
  try {
    response = await fetch(input, init)
  } catch (error) {
    return {
      ok: false,
      status: 0,
      error: error instanceof Error ? error.message : 'Network request failed',
      data: null,
    }
  }

  const data = await response.text()
  if (response.ok) {
    return {
      ok: true,
      status: response.status,
      data,
    }
  }

  return {
    ok: false,
    status: response.status,
    error: `Request failed (${response.status})`,
    data,
  }
}

export interface BucketRecord {
  name: string
  createdAt: string
  versioning: boolean
}

export interface ObjectRecord {
  key: string
  size: number
  lastModified: string
  etag: string
}

export interface ObjectListResponse {
  files: ObjectRecord[]
  prefixes: string[]
  emptyPrefixes: string[]
}

export interface VersionRecord {
  versionId: string | null
  lastModified: string
  size: number
  etag: string
  isDeleteMarker: boolean
}

export interface RuntimeMetrics {
  requestsTotal: number | null
  uptimeSeconds: number | null
  version: string | null
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number | null
  clusterPeers: string[]
  membershipProtocol: string | null
  placementEpoch: number | null
  raw: string
}

export interface RuntimeTopology {
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number | null
  clusterPeers: string[]
  membershipProtocol: string | null
  placementEpoch: number | null
  raw: unknown
}

export interface RuntimeHealth {
  ok: boolean
  status: string | null
  version: string | null
  uptimeSeconds: number | null
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number | null
  clusterPeers: string[]
  membershipProtocol: string | null
  membershipViewId: string | null
  placementEpoch: number | null
  checks: {
    dataDirAccessible: boolean | null
    dataDirWritable: boolean | null
    storageDataPathReadable: boolean | null
    diskHeadroomSufficient: boolean | null
    peerConnectivityReady: boolean | null
    membershipProtocolReady: boolean | null
  } | null
  warnings: string[]
  raw: unknown
}

export interface RuntimeMembershipNode {
  nodeId: string
  role: 'self' | 'peer' | null
  status: string | null
}

export interface RuntimeMembership {
  mode: 'standalone' | 'distributed' | null
  protocol: string | null
  viewId: string | null
  leaderNodeId: string | null
  coordinatorNodeId: string | null
  nodes: RuntimeMembershipNode[]
  raw: unknown
}

export interface RuntimeSummary {
  health: RuntimeHealth
  metrics: RuntimeMetrics
  topology: RuntimeTopology
  membership: RuntimeMembership | null
}

export interface RuntimePlacement {
  key: string
  chunkIndex: number | null
  replicaCountRequested: number | null
  replicaCountApplied: number | null
  writeQuorumSize: number | null
  writeAckPolicy: string | null
  nonOwnerMutationPolicy: string | null
  owners: string[]
  primaryOwner: string | null
  forwardTarget: string | null
  isLocalPrimaryOwner: boolean | null
  isLocalReplicaOwner: boolean | null
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number | null
  clusterPeers: string[]
  membershipProtocol: string | null
  membershipViewId: string | null
  raw: unknown
}

export interface RuntimeRebalanceMembershipSnapshot {
  nodeId: string | null
  clusterPeerCount: number | null
  clusterPeers: string[]
  membershipViewId: string | null
  membershipNodes: string[]
}

export interface RuntimeRebalanceTransfer {
  from: string | null
  to: string
}

export interface RuntimeRebalancePlan {
  previousOwners: string[]
  nextOwners: string[]
  retainedOwners: string[]
  removedOwners: string[]
  addedOwners: string[]
  transferCount: number | null
  transfers: RuntimeRebalanceTransfer[]
}

export interface RuntimeRebalance {
  key: string
  chunkIndex: number | null
  replicaCountRequested: number | null
  replicaCountApplied: number | null
  operation: 'join' | 'leave' | null
  operationPeer: string | null
  source: RuntimeRebalanceMembershipSnapshot
  target: RuntimeRebalanceMembershipSnapshot
  plan: RuntimeRebalancePlan
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number | null
  clusterPeers: string[]
  membershipProtocol: string | null
  membershipViewId: string | null
  raw: unknown
}

export interface LifecycleRuleRecord {
  id: string
  prefix: string
  expirationDays: number
  enabled: boolean
}

export interface AuthSessionIdentity {
  accessKey: string
  sessionIssuedAt: number
  sessionExpiresAt: number
}

export function authCheck() {
  return requestJson<{ ok: true } & AuthSessionIdentity>('/api/auth/check')
}

export function authLogin(accessKey: string, secretKey: string) {
  return requestJson<{ ok: true } & AuthSessionIdentity>('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accessKey, secretKey }),
  })
}

export function authLogout() {
  return requestJson<{ ok: true }>('/api/auth/logout', { method: 'POST' })
}

export function authMe() {
  return requestJson<AuthSessionIdentity>('/api/auth/me')
}

export function listBucketsApi() {
  return requestJson<{ buckets: BucketRecord[] }>('/api/buckets')
}

export function createBucketApi(name: string) {
  return requestJson<{ ok: true }>('/api/buckets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
}

export function deleteBucketApi(name: string) {
  return requestJson<{ ok: true }>(`/api/buckets/${encodeURIComponent(name)}`, {
    method: 'DELETE',
  })
}

export function getBucketVersioningApi(bucket: string) {
  return requestJson<{ enabled: boolean }>(
    `/api/buckets/${encodeURIComponent(bucket)}/versioning`
  )
}

export function setBucketVersioningApi(bucket: string, enabled: boolean) {
  return requestJson<{ ok: true }>(`/api/buckets/${encodeURIComponent(bucket)}/versioning`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled }),
  })
}

export function getBucketLifecycleApi(bucket: string) {
  return requestJson<{ rules: LifecycleRuleRecord[] }>(
    `/api/buckets/${encodeURIComponent(bucket)}/lifecycle`
  )
}

export function setBucketLifecycleApi(bucket: string, rules: LifecycleRuleRecord[]) {
  return requestJson<{ ok: true }>(`/api/buckets/${encodeURIComponent(bucket)}/lifecycle`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rules }),
  })
}

export function listObjectsApi(bucket: string, prefix: string, delimiter = '/') {
  const params = new URLSearchParams({ prefix, delimiter })
  return requestJson<ObjectListResponse>(
    `/api/buckets/${encodeURIComponent(bucket)}/objects?${params}`
  )
}

export function uploadObjectApi(
  bucket: string,
  key: string,
  body: BodyInit,
  contentType: string
) {
  return requestJson<{ ok: true; etag: string; size: number }>(
    objectPath(bucket, 'upload', key),
    {
      method: 'PUT',
      headers: { 'Content-Type': contentType },
      body,
    }
  )
}

export function deleteObjectApi(bucket: string, key: string) {
  return requestJson<{ ok: true }>(objectPath(bucket, 'objects', key), {
    method: 'DELETE',
  })
}

export function createFolderApi(bucket: string, name: string) {
  return requestJson<{ ok: true }>(`/api/buckets/${encodeURIComponent(bucket)}/folders`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
}

export function presignObjectApi(bucket: string, key: string, expires: number) {
  return requestJson<{ url: string; expiresIn: number }>(
    `${objectPath(bucket, 'presign', key)}?expires=${expires}`
  )
}

export function buildObjectDownloadUrl(bucket: string, key: string): string {
  return objectPath(bucket, 'download', key)
}

export function listVersionsApi(bucket: string, key: string) {
  return requestJson<{ versions: VersionRecord[] }>(
    `/api/buckets/${encodeURIComponent(bucket)}/versions?key=${encodeURIComponent(key)}`
  )
}

export function deleteVersionApi(bucket: string, versionId: string, key: string) {
  return requestJson<{ ok: true }>(
    `/api/buckets/${encodeURIComponent(bucket)}/versions/${encodeURIComponent(versionId)}/objects/${encodePathPreservingDelimiters(key)}`,
    { method: 'DELETE' }
  )
}

export function buildVersionDownloadUrl(
  bucket: string,
  versionId: string,
  key: string
): string {
  return `/api/buckets/${encodeURIComponent(bucket)}/versions/${encodeURIComponent(versionId)}/download/${encodePathPreservingDelimiters(key)}`
}

function normalizeRuntimeTopology(data: {
  mode?: unknown
  nodeId?: unknown
  clusterPeerCount?: unknown
  clusterPeers?: unknown
  membershipProtocol?: unknown
  placementEpoch?: unknown
}): {
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number
  clusterPeers: string[]
  membershipProtocol: string | null
  placementEpoch: number | null
} {
  const mode: 'standalone' | 'distributed' | null =
    data.mode === 'distributed' || data.mode === 'standalone'
      ? data.mode
      : null
  const clusterPeers = Array.isArray(data.clusterPeers)
    ? data.clusterPeers.filter((p): p is string => typeof p === 'string')
    : []

  return {
    mode,
    nodeId: typeof data.nodeId === 'string' ? data.nodeId : null,
    clusterPeerCount:
      typeof data.clusterPeerCount === 'number' ? data.clusterPeerCount : clusterPeers.length,
    clusterPeers,
    membershipProtocol:
      typeof data.membershipProtocol === 'string' ? data.membershipProtocol : null,
    placementEpoch:
      typeof data.placementEpoch === 'number' ? Math.trunc(data.placementEpoch) : null,
  }
}

function parseRuntimeMembershipPayload(data: {
  mode?: unknown
  protocol?: unknown
  viewId?: unknown
  leaderNodeId?: unknown
  coordinatorNodeId?: unknown
  nodes?: unknown
}): RuntimeMembership {
  const topology = normalizeRuntimeTopology(data)
  const nodes = Array.isArray(data.nodes)
    ? data.nodes
        .filter((node): node is { nodeId?: unknown; role?: unknown; status?: unknown } => {
          return typeof node === 'object' && node !== null
        })
        .filter((node): node is { nodeId: string; role?: unknown; status?: unknown } => {
          return typeof node.nodeId === 'string' && node.nodeId.length > 0
        })
        .map((node): RuntimeMembershipNode => {
          let role: RuntimeMembershipNode['role'] = null
          if (node.role === 'self') {
            role = 'self'
          } else if (node.role === 'peer') {
            role = 'peer'
          }

          return {
            nodeId: node.nodeId,
            role,
            status: typeof node.status === 'string' ? node.status : null,
          }
        })
    : []

  return {
    mode: topology.mode,
    protocol: typeof data.protocol === 'string' ? data.protocol : null,
    viewId: typeof data.viewId === 'string' ? data.viewId : null,
    leaderNodeId: typeof data.leaderNodeId === 'string' ? data.leaderNodeId : null,
    coordinatorNodeId:
      typeof data.coordinatorNodeId === 'string' ? data.coordinatorNodeId : null,
    nodes,
    raw: data,
  }
}

export async function getRuntimeSummaryApi(): Promise<ApiResult<RuntimeSummary>> {
  const result = await requestJson<{
    health?: {
      ok?: boolean
      status?: string
      version?: string
      uptimeSeconds?: number
      mode?: string
      nodeId?: string
      clusterPeerCount?: number
      clusterPeers?: string[]
      membershipProtocol?: string
      placementEpoch?: number
        checks?: {
          dataDirAccessible?: boolean
          dataDirWritable?: boolean
          storageDataPathReadable?: boolean
          diskHeadroomSufficient?: boolean
          peerConnectivityReady?: boolean
          membershipProtocolReady?: boolean
        }
      warnings?: string[]
    }
    metrics?: {
      requestsTotal?: number
      uptimeSeconds?: number
      version?: string
      mode?: string
      nodeId?: string
      clusterPeerCount?: number
      clusterPeers?: string[]
      membershipProtocol?: string
      placementEpoch?: number
    }
    topology?: {
      mode?: string
      nodeId?: string
      clusterPeerCount?: number
      clusterPeers?: string[]
      membershipProtocol?: string
      placementEpoch?: number
    }
    membership?: {
      mode?: string
      protocol?: string
      viewId?: string
      leaderNodeId?: string | null
      coordinatorNodeId?: string
      nodes?: Array<{
        nodeId?: string
        role?: string
        status?: string
      }>
    }
  }>('/api/system/summary')

  if (!result.ok) {
    return result
  }

  const rawHealth = result.data.health ?? {}
  const rawMetrics = result.data.metrics ?? {}
  const rawTopology = result.data.topology ?? {}
  const rawMembership = result.data.membership
  const topology = normalizeRuntimeTopology(rawTopology)

  return {
    ok: true,
    status: result.status,
    data: {
      health: {
        ok: rawHealth.ok === true,
        status: typeof rawHealth.status === 'string' ? rawHealth.status : null,
        version: typeof rawHealth.version === 'string' ? rawHealth.version : null,
        uptimeSeconds:
          typeof rawHealth.uptimeSeconds === 'number' ? rawHealth.uptimeSeconds : null,
        mode: topology.mode,
        nodeId: topology.nodeId,
        clusterPeerCount: topology.clusterPeerCount,
        clusterPeers: topology.clusterPeers,
        membershipProtocol: topology.membershipProtocol,
        placementEpoch:
          typeof (rawHealth as { placementEpoch?: unknown }).placementEpoch === 'number'
            ? Math.trunc((rawHealth as { placementEpoch: number }).placementEpoch)
            : topology.placementEpoch,
        membershipViewId:
          typeof (rawHealth as { membershipViewId?: unknown }).membershipViewId === 'string'
            ? (rawHealth as { membershipViewId: string }).membershipViewId
            : null,
        checks:
          typeof rawHealth.checks === 'object' && rawHealth.checks !== null
            ? {
                dataDirAccessible:
                  typeof rawHealth.checks.dataDirAccessible === 'boolean'
                    ? rawHealth.checks.dataDirAccessible
                    : null,
                dataDirWritable:
                  typeof rawHealth.checks.dataDirWritable === 'boolean'
                    ? rawHealth.checks.dataDirWritable
                    : null,
                storageDataPathReadable:
                  typeof rawHealth.checks.storageDataPathReadable === 'boolean'
                    ? rawHealth.checks.storageDataPathReadable
                    : null,
                diskHeadroomSufficient:
                  typeof rawHealth.checks.diskHeadroomSufficient === 'boolean'
                    ? rawHealth.checks.diskHeadroomSufficient
                    : null,
                peerConnectivityReady:
                  typeof rawHealth.checks.peerConnectivityReady === 'boolean'
                    ? rawHealth.checks.peerConnectivityReady
                    : null,
                membershipProtocolReady:
                  typeof rawHealth.checks.membershipProtocolReady === 'boolean'
                    ? rawHealth.checks.membershipProtocolReady
                    : null,
              }
            : null,
        warnings: Array.isArray(rawHealth.warnings)
          ? rawHealth.warnings.filter(
              (warning): warning is string => typeof warning === 'string'
            )
          : [],
        raw: rawHealth,
      },
      metrics: {
        requestsTotal:
          typeof rawMetrics.requestsTotal === 'number' ? rawMetrics.requestsTotal : null,
        uptimeSeconds:
          typeof rawMetrics.uptimeSeconds === 'number' ? rawMetrics.uptimeSeconds : null,
        version: typeof rawMetrics.version === 'string' ? rawMetrics.version : null,
        mode: topology.mode,
        nodeId: topology.nodeId,
        clusterPeerCount: topology.clusterPeerCount,
        clusterPeers: topology.clusterPeers,
        membershipProtocol: topology.membershipProtocol,
        placementEpoch: topology.placementEpoch,
        raw: JSON.stringify(rawMetrics, null, 2),
      },
      topology: {
        mode: topology.mode,
        nodeId: topology.nodeId,
        clusterPeerCount: topology.clusterPeerCount,
        clusterPeers: topology.clusterPeers,
        membershipProtocol: topology.membershipProtocol,
        placementEpoch: topology.placementEpoch,
        raw: rawTopology,
      },
      membership:
        rawMembership && typeof rawMembership === 'object'
          ? parseRuntimeMembershipPayload(rawMembership)
          : null,
    },
  }
}

export async function getRuntimeMetricsApi(): Promise<ApiResult<RuntimeMetrics>> {
  const consoleResult = await requestJson<{
    requestsTotal: number
    uptimeSeconds: number
    version: string
    mode?: string
    nodeId?: string
    clusterPeerCount?: number
    clusterPeers?: string[]
    membershipProtocol?: string
    placementEpoch?: number
  }>('/api/system/metrics')
  if (consoleResult.ok) {
    const topology = normalizeRuntimeTopology(consoleResult.data)

    return {
      ok: true,
      status: consoleResult.status,
      data: {
        requestsTotal:
          typeof consoleResult.data.requestsTotal === 'number'
            ? consoleResult.data.requestsTotal
            : null,
        uptimeSeconds:
          typeof consoleResult.data.uptimeSeconds === 'number'
            ? consoleResult.data.uptimeSeconds
            : null,
        version:
          typeof consoleResult.data.version === 'string'
            ? consoleResult.data.version
            : null,
        mode: topology.mode,
        nodeId: topology.nodeId,
        clusterPeerCount: topology.clusterPeerCount,
        clusterPeers: topology.clusterPeers,
        membershipProtocol: topology.membershipProtocol,
        placementEpoch: topology.placementEpoch,
        raw: JSON.stringify(consoleResult.data, null, 2),
      },
    }
  }

  const result = await requestText('/metrics')
  if (!result.ok) {
    return {
      ok: false,
      status: result.status,
      error: consoleResult.error || result.error,
      data: result.data,
    }
  }

  const raw = result.data
  const requestsMatch = raw.match(/^maxio_requests_total\s+([0-9]+(?:\.[0-9]+)?)$/m)
  const uptimeMatch = raw.match(/^maxio_uptime_seconds\s+([0-9]+(?:\.[0-9]+)?)$/m)
  const versionMatch = raw.match(/^maxio_build_info\{version="([^"]+)"\}\s+1$/m)
  const membershipProtocolMatch = raw.match(
    /^maxio_membership_protocol_info\{protocol="([^"]+)"\}\s+1(?:\.0+)?$/m
  )
  const placementEpochMatch = raw.match(/^maxio_placement_epoch\s+([0-9]+(?:\.[0-9]+)?)$/m)

  const requestsTotal = requestsMatch ? Number(requestsMatch[1]) : null
  const uptimeSeconds = uptimeMatch ? Number(uptimeMatch[1]) : null
  const version = versionMatch ? versionMatch[1] : null
  const membershipProtocol = membershipProtocolMatch ? membershipProtocolMatch[1] : null
  const placementEpoch = placementEpochMatch ? Number(placementEpochMatch[1]) : null

  return {
    ok: true,
    status: result.status,
    data: {
      requestsTotal: Number.isFinite(requestsTotal ?? NaN) ? requestsTotal : null,
      uptimeSeconds: Number.isFinite(uptimeSeconds ?? NaN) ? uptimeSeconds : null,
      version,
      mode: null,
      nodeId: null,
      clusterPeerCount: null,
      clusterPeers: [],
      membershipProtocol,
      placementEpoch:
        typeof placementEpoch === 'number' && Number.isFinite(placementEpoch)
          ? Math.trunc(placementEpoch)
          : null,
      raw,
    },
  }
}

export async function getRuntimeTopologyApi(): Promise<ApiResult<RuntimeTopology>> {
  const result = await requestJson<{
    mode?: string
    nodeId?: string
    clusterPeerCount?: number
    clusterPeers?: string[]
    membershipProtocol?: string
    placementEpoch?: number
  }>('/api/system/topology')

  if (!result.ok) {
    return result
  }

  const topology = normalizeRuntimeTopology(result.data)

  return {
    ok: true,
    status: result.status,
    data: {
      mode: topology.mode,
      nodeId: topology.nodeId,
      clusterPeerCount: topology.clusterPeerCount,
      clusterPeers: topology.clusterPeers,
      membershipProtocol: topology.membershipProtocol,
      placementEpoch: topology.placementEpoch,
      raw: result.data,
    },
  }
}

export async function getRuntimeHealthApi(): Promise<ApiResult<RuntimeHealth>> {
  const result = await requestJson<{
    ok?: boolean
    status?: string
    version?: string
    uptimeSeconds?: number
    mode?: string
    nodeId?: string
    clusterPeerCount?: number
    clusterPeers?: string[]
    membershipProtocol?: string
    placementEpoch?: number
    checks?: {
      dataDirAccessible?: boolean
      dataDirWritable?: boolean
      storageDataPathReadable?: boolean
      diskHeadroomSufficient?: boolean
      peerConnectivityReady?: boolean
      membershipProtocolReady?: boolean
    }
    warnings?: string[]
  }>('/api/system/health')

  if (!result.ok) {
    return result
  }

  const topology = normalizeRuntimeTopology(result.data)

  return {
    ok: true,
    status: result.status,
    data: {
      ok: result.data.ok === true,
      status: typeof result.data.status === 'string' ? result.data.status : null,
      version: typeof result.data.version === 'string' ? result.data.version : null,
      uptimeSeconds:
        typeof result.data.uptimeSeconds === 'number' ? result.data.uptimeSeconds : null,
      mode: topology.mode,
      nodeId: topology.nodeId,
      clusterPeerCount: topology.clusterPeerCount,
      clusterPeers: topology.clusterPeers,
      membershipProtocol: topology.membershipProtocol,
      placementEpoch:
        typeof (result.data as { placementEpoch?: unknown }).placementEpoch === 'number'
          ? Math.trunc((result.data as { placementEpoch: number }).placementEpoch)
          : topology.placementEpoch,
      membershipViewId:
        typeof (result.data as { membershipViewId?: unknown }).membershipViewId === 'string'
          ? (result.data as { membershipViewId: string }).membershipViewId
          : null,
      checks:
        typeof result.data.checks === 'object' && result.data.checks !== null
          ? {
              dataDirAccessible:
                typeof result.data.checks.dataDirAccessible === 'boolean'
                  ? result.data.checks.dataDirAccessible
                  : null,
              dataDirWritable:
                typeof result.data.checks.dataDirWritable === 'boolean'
                  ? result.data.checks.dataDirWritable
                  : null,
              storageDataPathReadable:
                typeof result.data.checks.storageDataPathReadable === 'boolean'
                  ? result.data.checks.storageDataPathReadable
                  : null,
              diskHeadroomSufficient:
                typeof result.data.checks.diskHeadroomSufficient === 'boolean'
                  ? result.data.checks.diskHeadroomSufficient
                  : null,
              peerConnectivityReady:
                typeof result.data.checks.peerConnectivityReady === 'boolean'
                  ? result.data.checks.peerConnectivityReady
                  : null,
              membershipProtocolReady:
                typeof result.data.checks.membershipProtocolReady === 'boolean'
                  ? result.data.checks.membershipProtocolReady
                  : null,
            }
          : null,
      warnings: Array.isArray(result.data.warnings)
        ? result.data.warnings.filter((warning): warning is string => typeof warning === 'string')
        : [],
      raw: result.data,
    },
  }
}

export async function getRuntimeMembershipApi(): Promise<ApiResult<RuntimeMembership>> {
  const result = await requestJson<{
    mode?: string
    protocol?: string
    viewId?: string
    leaderNodeId?: string | null
    coordinatorNodeId?: string
    nodes?: Array<{
      nodeId?: string
      role?: string
      status?: string
    }>
  }>('/api/system/membership')

  if (!result.ok) {
    return result
  }

  return {
    ok: true,
    status: result.status,
    data: parseRuntimeMembershipPayload(result.data),
  }
}

export async function getRuntimePlacementApi(args: {
  key: string
  replicaCount?: number
  chunkIndex?: number
}): Promise<ApiResult<RuntimePlacement>> {
  const params = new URLSearchParams()
  params.set('key', args.key)
  if (typeof args.replicaCount === 'number' && Number.isFinite(args.replicaCount)) {
    params.set('replicaCount', `${Math.trunc(args.replicaCount)}`)
  }
  if (typeof args.chunkIndex === 'number' && Number.isFinite(args.chunkIndex)) {
    params.set('chunkIndex', `${Math.trunc(args.chunkIndex)}`)
  }

  const result = await requestJson<{
    key?: string
    chunkIndex?: number | null
    replicaCountRequested?: number
    replicaCountApplied?: number
    writeQuorumSize?: number
    writeAckPolicy?: string
    nonOwnerMutationPolicy?: string
    owners?: unknown
    primaryOwner?: string | null
    forwardTarget?: string | null
    isLocalPrimaryOwner?: boolean
    isLocalReplicaOwner?: boolean
    mode?: string
    nodeId?: string
    clusterPeerCount?: number
    clusterPeers?: string[]
    membershipProtocol?: string
    membershipViewId?: string
  }>(`/api/system/placement?${params.toString()}`)

  if (!result.ok) {
    return result
  }

  const topology = normalizeRuntimeTopology(result.data)
  const owners = Array.isArray(result.data.owners)
    ? result.data.owners.filter((owner): owner is string => typeof owner === 'string')
    : []

  return {
    ok: true,
    status: result.status,
    data: {
      key: typeof result.data.key === 'string' ? result.data.key : args.key,
      chunkIndex:
        typeof result.data.chunkIndex === 'number' ? Math.trunc(result.data.chunkIndex) : null,
      replicaCountRequested:
        typeof result.data.replicaCountRequested === 'number'
          ? Math.trunc(result.data.replicaCountRequested)
          : null,
      replicaCountApplied:
        typeof result.data.replicaCountApplied === 'number'
          ? Math.trunc(result.data.replicaCountApplied)
          : null,
      writeQuorumSize:
        typeof result.data.writeQuorumSize === 'number'
          ? Math.trunc(result.data.writeQuorumSize)
          : null,
      writeAckPolicy:
        typeof result.data.writeAckPolicy === 'string' ? result.data.writeAckPolicy : null,
      nonOwnerMutationPolicy:
        typeof result.data.nonOwnerMutationPolicy === 'string'
          ? result.data.nonOwnerMutationPolicy
          : null,
      owners,
      primaryOwner: typeof result.data.primaryOwner === 'string' ? result.data.primaryOwner : null,
      forwardTarget: typeof result.data.forwardTarget === 'string' ? result.data.forwardTarget : null,
      isLocalPrimaryOwner:
        typeof result.data.isLocalPrimaryOwner === 'boolean'
          ? result.data.isLocalPrimaryOwner
          : null,
      isLocalReplicaOwner:
        typeof result.data.isLocalReplicaOwner === 'boolean'
          ? result.data.isLocalReplicaOwner
          : null,
      mode: topology.mode,
      nodeId: topology.nodeId,
      clusterPeerCount: topology.clusterPeerCount,
      clusterPeers: topology.clusterPeers,
      membershipProtocol: topology.membershipProtocol,
      membershipViewId:
        typeof result.data.membershipViewId === 'string' ? result.data.membershipViewId : null,
      raw: result.data,
    },
  }
}

export async function getRuntimeRebalanceApi(args: {
  key: string
  operation: 'join' | 'leave'
  peer: string
  replicaCount?: number
  chunkIndex?: number
}): Promise<ApiResult<RuntimeRebalance>> {
  const params = new URLSearchParams()
  params.set('key', args.key)
  if (typeof args.replicaCount === 'number' && Number.isFinite(args.replicaCount)) {
    params.set('replicaCount', `${Math.trunc(args.replicaCount)}`)
  }
  if (typeof args.chunkIndex === 'number' && Number.isFinite(args.chunkIndex)) {
    params.set('chunkIndex', `${Math.trunc(args.chunkIndex)}`)
  }
  if (args.operation === 'join') {
    params.set('addPeer', args.peer)
  } else {
    params.set('removePeer', args.peer)
  }

  const result = await requestJson<{
    key?: string
    chunkIndex?: number | null
    replicaCountRequested?: number
    replicaCountApplied?: number
    operation?: string
    operationPeer?: string
    source?: {
      nodeId?: string
      clusterPeerCount?: number
      clusterPeers?: unknown
      membershipViewId?: string
      membershipNodes?: unknown
    }
    target?: {
      nodeId?: string
      clusterPeerCount?: number
      clusterPeers?: unknown
      membershipViewId?: string
      membershipNodes?: unknown
    }
    plan?: {
      previousOwners?: unknown
      nextOwners?: unknown
      retainedOwners?: unknown
      removedOwners?: unknown
      addedOwners?: unknown
      transferCount?: number
      transfers?: Array<{
        from?: string | null
        to?: string
      }>
    }
    mode?: string
    nodeId?: string
    clusterPeerCount?: number
    clusterPeers?: string[]
    membershipProtocol?: string
    membershipViewId?: string
  }>(`/api/system/rebalance?${params.toString()}`)

  if (!result.ok) {
    return result
  }

  const topology = normalizeRuntimeTopology(result.data)
  const parseStringArray = (value: unknown): string[] =>
    Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []

  const source = result.data.source ?? {}
  const target = result.data.target ?? {}
  const plan = result.data.plan ?? {}
  const transfers = Array.isArray(plan.transfers)
    ? plan.transfers
        .filter(
          (transfer): transfer is { from?: string | null; to?: string } =>
            typeof transfer === 'object' && transfer !== null
        )
        .filter((transfer): transfer is { from?: string | null; to: string } => {
          return typeof transfer.to === 'string'
        })
        .map((transfer): RuntimeRebalanceTransfer => ({
          from: typeof transfer.from === 'string' ? transfer.from : null,
          to: transfer.to,
        }))
    : []

  return {
    ok: true,
    status: result.status,
    data: {
      key: typeof result.data.key === 'string' ? result.data.key : args.key,
      chunkIndex:
        typeof result.data.chunkIndex === 'number' ? Math.trunc(result.data.chunkIndex) : null,
      replicaCountRequested:
        typeof result.data.replicaCountRequested === 'number'
          ? Math.trunc(result.data.replicaCountRequested)
          : null,
      replicaCountApplied:
        typeof result.data.replicaCountApplied === 'number'
          ? Math.trunc(result.data.replicaCountApplied)
          : null,
      operation:
        result.data.operation === 'join' || result.data.operation === 'leave'
          ? result.data.operation
          : null,
      operationPeer:
        typeof result.data.operationPeer === 'string' ? result.data.operationPeer : null,
      source: {
        nodeId: typeof source.nodeId === 'string' ? source.nodeId : null,
        clusterPeerCount:
          typeof source.clusterPeerCount === 'number'
            ? Math.trunc(source.clusterPeerCount)
            : null,
        clusterPeers: parseStringArray(source.clusterPeers),
        membershipViewId:
          typeof source.membershipViewId === 'string' ? source.membershipViewId : null,
        membershipNodes: parseStringArray(source.membershipNodes),
      },
      target: {
        nodeId: typeof target.nodeId === 'string' ? target.nodeId : null,
        clusterPeerCount:
          typeof target.clusterPeerCount === 'number'
            ? Math.trunc(target.clusterPeerCount)
            : null,
        clusterPeers: parseStringArray(target.clusterPeers),
        membershipViewId:
          typeof target.membershipViewId === 'string' ? target.membershipViewId : null,
        membershipNodes: parseStringArray(target.membershipNodes),
      },
      plan: {
        previousOwners: parseStringArray(plan.previousOwners),
        nextOwners: parseStringArray(plan.nextOwners),
        retainedOwners: parseStringArray(plan.retainedOwners),
        removedOwners: parseStringArray(plan.removedOwners),
        addedOwners: parseStringArray(plan.addedOwners),
        transferCount:
          typeof plan.transferCount === 'number' ? Math.trunc(plan.transferCount) : null,
        transfers,
      },
      mode: topology.mode,
      nodeId: topology.nodeId,
      clusterPeerCount: topology.clusterPeerCount,
      clusterPeers: topology.clusterPeers,
      membershipProtocol: topology.membershipProtocol,
      membershipViewId:
        typeof result.data.membershipViewId === 'string' ? result.data.membershipViewId : null,
      raw: result.data,
    },
  }
}
