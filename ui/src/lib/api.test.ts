import { afterEach, describe, expect, it } from 'bun:test'

import {
  authCheck,
  buildObjectDownloadUrl,
  buildVersionDownloadUrl,
  deleteObjectApi,
  getRuntimeHealthApi,
  getRuntimeMetricsApi,
  getRuntimeTopologyApi,
  presignObjectApi,
  uploadObjectApi,
} from './api'

const originalFetch = globalThis.fetch

function mockFetchSequence(items: Array<Response | Error>) {
  let index = 0
  globalThis.fetch = (async () => {
    const item = items[index]
    index += 1
    if (item instanceof Error) {
      throw item
    }
    return item
  }) as unknown as typeof fetch
}

function mockFetchCapture(calls: Array<{ url: string; init?: RequestInit }>, response: Response) {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    calls.push({ url, init })
    return response
  }) as unknown as typeof fetch
}

afterEach(() => {
  globalThis.fetch = originalFetch
})

describe('api client', () => {
  it('maps auth error JSON payloads', async () => {
    mockFetchSequence([
      new Response(JSON.stringify({ error: 'Invalid credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    ])

    const result = await authCheck()
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('Invalid credentials')
    }
  })

  it('uses /api/system/metrics JSON when available', async () => {
    mockFetchSequence([
      new Response(
        JSON.stringify({
          requestsTotal: 12,
          uptimeSeconds: 3.5,
          version: '0.1.0',
          mode: 'distributed',
          nodeId: 'node-a',
          clusterPeerCount: 2,
          clusterPeers: ['node-b:9000', 'node-c:9000'],
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    ])

    const result = await getRuntimeMetricsApi()
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.requestsTotal).toBe(12)
      expect(result.data.uptimeSeconds).toBe(3.5)
      expect(result.data.version).toBe('0.1.0')
      expect(result.data.mode).toBe('distributed')
      expect(result.data.nodeId).toBe('node-a')
      expect(result.data.clusterPeerCount).toBe(2)
      expect(result.data.clusterPeers).toEqual(['node-b:9000', 'node-c:9000'])
    }
  })

  it('falls back to /metrics text parsing when console metrics fails', async () => {
    mockFetchSequence([
      new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
      new Response(
        [
          '# HELP maxio_requests_total Total HTTP requests observed by MaxIO.',
          'maxio_requests_total 15',
          '# HELP maxio_uptime_seconds MaxIO process uptime in seconds.',
          'maxio_uptime_seconds 9.25',
          '# HELP maxio_build_info Build and version information for MaxIO.',
          'maxio_build_info{version="0.9.9"} 1',
        ].join('\n'),
        {
          status: 200,
          headers: { 'Content-Type': 'text/plain' },
        }
      ),
    ])

    const result = await getRuntimeMetricsApi()
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.status).toBe(200)
      expect(result.data.requestsTotal).toBe(15)
      expect(result.data.uptimeSeconds).toBe(9.25)
      expect(result.data.version).toBe('0.9.9')
      expect(result.data.mode).toBeNull()
      expect(result.data.clusterPeers).toEqual([])
    }
  })

  it('returns a failure when both metrics endpoints fail', async () => {
    mockFetchSequence([
      new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
      new Response('internal error', {
        status: 500,
        headers: { 'Content-Type': 'text/plain' },
      }),
    ])

    const result = await getRuntimeMetricsApi()
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(500)
      expect(result.error).toBe('Unauthorized')
    }
  })

  it('parses topology JSON payload into typed topology data', async () => {
    mockFetchSequence([
      new Response(
        JSON.stringify({
          mode: 'distributed',
          nodeId: 'node-a',
          clusterPeerCount: 3,
          clusterPeers: ['node-b:9000', 'node-c:9000', 'node-d:9000'],
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    ])

    const result = await getRuntimeTopologyApi()
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.mode).toBe('distributed')
      expect(result.data.nodeId).toBe('node-a')
      expect(result.data.clusterPeerCount).toBe(3)
      expect(result.data.clusterPeers).toEqual([
        'node-b:9000',
        'node-c:9000',
        'node-d:9000',
      ])
    }
  })

  it('propagates topology request failures', async () => {
    mockFetchSequence([
      new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    ])

    const result = await getRuntimeTopologyApi()
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('Unauthorized')
    }
  })

  it('parses health JSON payload into typed health data', async () => {
    mockFetchSequence([
      new Response(
        JSON.stringify({
          ok: true,
          version: '0.1.0',
          uptimeSeconds: 42.5,
          mode: 'distributed',
          nodeId: 'node-a',
          clusterPeers: ['node-b:9000', 'node-c:9000'],
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    ])

    const result = await getRuntimeHealthApi()
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.ok).toBe(true)
      expect(result.data.version).toBe('0.1.0')
      expect(result.data.uptimeSeconds).toBe(42.5)
      expect(result.data.mode).toBe('distributed')
      expect(result.data.nodeId).toBe('node-a')
      // clusterPeerCount should be derived from peers when omitted.
      expect(result.data.clusterPeerCount).toBe(2)
      expect(result.data.clusterPeers).toEqual(['node-b:9000', 'node-c:9000'])
    }
  })

  it('propagates health request failures', async () => {
    mockFetchSequence([
      new Response(JSON.stringify({ error: 'Not authenticated' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    ])

    const result = await getRuntimeHealthApi()
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('Not authenticated')
    }
  })

  it('encodes object-key path segments for object endpoints', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    const okResponse = new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
    mockFetchCapture(calls, okResponse)

    await uploadObjectApi(
      'bucket name',
      'nested/path/my file #1.txt',
      new Blob(['hello'], { type: 'text/plain' }),
      'text/plain'
    )
    await deleteObjectApi('bucket name', 'nested/path/my file #1.txt')
    await presignObjectApi('bucket name', 'nested/path/my file #1.txt', 3600)

    expect(calls.map((c) => c.url)).toEqual([
      '/api/buckets/bucket%20name/upload/nested/path/my%20file%20%231.txt',
      '/api/buckets/bucket%20name/objects/nested/path/my%20file%20%231.txt',
      '/api/buckets/bucket%20name/presign/nested/path/my%20file%20%231.txt?expires=3600',
    ])
  })

  it('builds encoded download URLs for object and version routes', () => {
    expect(buildObjectDownloadUrl('bucket name', 'folder/a b#1.txt')).toBe(
      '/api/buckets/bucket%20name/download/folder/a%20b%231.txt'
    )
    expect(buildVersionDownloadUrl('bucket name', 'ver/1', 'folder/a b#1.txt')).toBe(
      '/api/buckets/bucket%20name/versions/ver%2F1/download/folder/a%20b%231.txt'
    )
  })
})
