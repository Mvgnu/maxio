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
  raw: string
}

export interface RuntimeTopology {
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number | null
  clusterPeers: string[]
  raw: unknown
}

export interface RuntimeHealth {
  ok: boolean
  version: string | null
  uptimeSeconds: number | null
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number | null
  clusterPeers: string[]
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
    `/api/buckets/${encodeURIComponent(bucket)}/upload/${key}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': contentType },
      body,
    }
  )
}

export function deleteObjectApi(bucket: string, key: string) {
  return requestJson<{ ok: true }>(`/api/buckets/${encodeURIComponent(bucket)}/objects/${key}`, {
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
    `/api/buckets/${encodeURIComponent(bucket)}/presign/${key}?expires=${expires}`
  )
}

export function listVersionsApi(bucket: string, key: string) {
  return requestJson<{ versions: VersionRecord[] }>(
    `/api/buckets/${encodeURIComponent(bucket)}/versions?key=${encodeURIComponent(key)}`
  )
}

export function deleteVersionApi(bucket: string, versionId: string, key: string) {
  return requestJson<{ ok: true }>(
    `/api/buckets/${encodeURIComponent(bucket)}/versions/${encodeURIComponent(versionId)}/objects/${encodeURIComponent(key)}`,
    { method: 'DELETE' }
  )
}

function normalizeRuntimeTopology(data: {
  mode?: unknown
  nodeId?: unknown
  clusterPeerCount?: unknown
  clusterPeers?: unknown
}): {
  mode: 'standalone' | 'distributed' | null
  nodeId: string | null
  clusterPeerCount: number
  clusterPeers: string[]
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

  const requestsTotal = requestsMatch ? Number(requestsMatch[1]) : null
  const uptimeSeconds = uptimeMatch ? Number(uptimeMatch[1]) : null
  const version = versionMatch ? versionMatch[1] : null

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
      raw: result.data,
    },
  }
}

export async function getRuntimeHealthApi(): Promise<ApiResult<RuntimeHealth>> {
  const result = await requestJson<{
    ok?: boolean
    version?: string
    uptimeSeconds?: number
    mode?: string
    nodeId?: string
    clusterPeerCount?: number
    clusterPeers?: string[]
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
      version: typeof result.data.version === 'string' ? result.data.version : null,
      uptimeSeconds:
        typeof result.data.uptimeSeconds === 'number' ? result.data.uptimeSeconds : null,
      mode: topology.mode,
      nodeId: topology.nodeId,
      clusterPeerCount: topology.clusterPeerCount,
      clusterPeers: topology.clusterPeers,
      raw: result.data,
    },
  }
}
