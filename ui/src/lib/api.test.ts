import { afterEach, describe, expect, it } from 'bun:test'

import {
  authCheck,
  buildObjectDownloadUrl,
  buildVersionDownloadUrl,
  deleteObjectApi,
  getRuntimeHealthApi,
  getRuntimeMembershipApi,
  getRuntimeMetricsApi,
  getRuntimePlacementApi,
  getRuntimeRebalanceApi,
  getRuntimeSummaryApi,
  getRuntimeTopologyApi,
  listObjectsApi,
  listVersionsApi,
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
          membershipProtocol: 'gossip',
          membershipProtocolReady: true,
          clusterPeerAuthProductionReady: false,
          clusterAuthProductionReason: 'transport-policy-not-required',
          membershipLastUpdateAgeMs: 2100,
          placementEpoch: 7,
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
      expect(result.data.membershipProtocol).toBe('gossip')
      expect(result.data.membershipProtocolReady).toBe(true)
      expect(result.data.clusterPeerAuthProductionReady).toBe(false)
      expect(result.data.clusterAuthProductionReason).toBe('transport-policy-not-required')
      expect(result.data.membershipLastUpdateAgeMs).toBe(2100)
      expect(result.data.placementEpoch).toBe(7)
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
          '# HELP maxio_membership_protocol_info Membership protocol configuration for runtime topology convergence.',
          '# TYPE maxio_membership_protocol_info gauge',
          'maxio_membership_protocol_info{protocol="gossip"} 1',
          '# HELP maxio_membership_protocol_ready Membership protocol readiness (1=implemented/active, 0=placeholder/unimplemented).',
          '# TYPE maxio_membership_protocol_ready gauge',
          'maxio_membership_protocol_ready 0',
          '# HELP maxio_cluster_peer_auth_production_ready Whether cluster peer auth posture is production-ready for distributed mode (1=true, 0=false).',
          '# TYPE maxio_cluster_peer_auth_production_ready gauge',
          'maxio_cluster_peer_auth_production_ready 1',
          '# HELP maxio_cluster_peer_auth_production_reason_info Cluster peer auth production-readiness reason for current runtime state.',
          '# TYPE maxio_cluster_peer_auth_production_reason_info gauge',
          'maxio_cluster_peer_auth_production_reason_info{reason="ready"} 1',
          '# TYPE maxio_placement_epoch gauge',
          'maxio_placement_epoch 9',
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
      expect(result.data.membershipProtocol).toBe('gossip')
      expect(result.data.membershipProtocolReady).toBe(false)
      expect(result.data.clusterPeerAuthProductionReady).toBe(true)
      expect(result.data.clusterAuthProductionReason).toBe('ready')
      expect(result.data.membershipLastUpdateAgeMs).toBeNull()
      expect(result.data.placementEpoch).toBe(9)
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
          membershipProtocol: 'raft',
          placementEpoch: 11,
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
      expect(result.data.membershipProtocol).toBe('raft')
      expect(result.data.placementEpoch).toBe(11)
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
          status: 'degraded',
          version: '0.1.0',
          uptimeSeconds: 42.5,
          mode: 'distributed',
          nodeId: 'node-a',
          clusterPeers: ['node-b:9000', 'node-c:9000'],
          membershipProtocol: 'gossip',
          clusterAuthProductionReason: 'transport-not-ready',
          membershipLastUpdateAgeMs: 1750,
          placementEpoch: 3,
          checks: {
            dataDirAccessible: true,
            dataDirWritable: false,
            storageDataPathReadable: false,
            diskHeadroomSufficient: false,
            peerConnectivityReady: false,
            membershipProtocolReady: false,
            clusterPeerAuthProductionReady: false,
          },
          warnings: ['Data directory write probe failed'],
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
      expect(result.data.membershipProtocol).toBe('gossip')
      expect(result.data.clusterAuthProductionReason).toBe('transport-not-ready')
      expect(result.data.membershipLastUpdateAgeMs).toBe(1750)
      expect(result.data.placementEpoch).toBe(3)
      expect(result.data.status).toBe('degraded')
      expect(result.data.checks).toEqual({
        dataDirAccessible: true,
        dataDirWritable: false,
        storageDataPathReadable: false,
        diskHeadroomSufficient: false,
        peerConnectivityReady: false,
        membershipProtocolReady: false,
        clusterPeerAuthProductionReady: false,
      })
      expect(result.data.warnings).toEqual(['Data directory write probe failed'])
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

  it('parses summary JSON payload into typed summary data', async () => {
    mockFetchSequence([
      new Response(
        JSON.stringify({
          health: {
            ok: true,
            status: 'ok',
            version: '0.1.0',
            uptimeSeconds: 51.25,
            membershipViewId: 'view-123',
            membershipProtocol: 'raft',
            clusterAuthProductionReason: 'ready',
            membershipLastUpdateAgeMs: 2400,
            placementEpoch: 14,
            checks: {
              dataDirAccessible: true,
              dataDirWritable: true,
              storageDataPathReadable: true,
              diskHeadroomSufficient: true,
              peerConnectivityReady: true,
              membershipProtocolReady: true,
              clusterPeerAuthProductionReady: true,
            },
            warnings: [],
          },
          metrics: {
            requestsTotal: 120,
            uptimeSeconds: 50.5,
            version: '0.1.0',
            membershipProtocol: 'raft',
            membershipProtocolReady: true,
            clusterPeerAuthProductionReady: true,
            clusterAuthProductionReason: 'ready',
            membershipLastUpdateAgeMs: 3200,
          },
          topology: {
            mode: 'distributed',
            nodeId: 'node-a',
            clusterPeerCount: 2,
            clusterPeers: ['node-b:9000', 'node-c:9000'],
            membershipProtocol: 'raft',
            placementEpoch: 14,
          },
          membership: {
            mode: 'distributed',
            protocol: 'static-bootstrap',
            viewId: 'view-123',
            leaderNodeId: null,
            coordinatorNodeId: 'node-a',
            nodes: [
              { nodeId: 'node-a', role: 'self', status: 'alive' },
              { nodeId: 'node-b:9000', role: 'peer', status: 'configured' },
            ],
          },
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    ])

    const result = await getRuntimeSummaryApi()
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.health.ok).toBe(true)
      expect(result.data.health.version).toBe('0.1.0')
      expect(result.data.health.uptimeSeconds).toBe(51.25)
      expect(result.data.health.membershipViewId).toBe('view-123')
      expect(result.data.health.membershipProtocol).toBe('raft')
      expect(result.data.health.clusterAuthProductionReason).toBe('ready')
      expect(result.data.health.membershipLastUpdateAgeMs).toBe(2400)
      expect(result.data.health.placementEpoch).toBe(14)
      expect(result.data.health.status).toBe('ok')
      expect(result.data.health.checks).toEqual({
        dataDirAccessible: true,
        dataDirWritable: true,
        storageDataPathReadable: true,
        diskHeadroomSufficient: true,
        peerConnectivityReady: true,
        membershipProtocolReady: true,
        clusterPeerAuthProductionReady: true,
      })
      expect(result.data.health.warnings).toEqual([])

      expect(result.data.metrics.requestsTotal).toBe(120)
      expect(result.data.metrics.uptimeSeconds).toBe(50.5)
      expect(result.data.metrics.version).toBe('0.1.0')
      expect(result.data.metrics.mode).toBe('distributed')
      expect(result.data.metrics.nodeId).toBe('node-a')
      expect(result.data.metrics.membershipProtocol).toBe('raft')
      expect(result.data.metrics.membershipProtocolReady).toBe(true)
      expect(result.data.metrics.clusterPeerAuthProductionReady).toBe(true)
      expect(result.data.metrics.clusterAuthProductionReason).toBe('ready')
      expect(result.data.metrics.membershipLastUpdateAgeMs).toBe(3200)
      expect(result.data.metrics.placementEpoch).toBe(14)

      expect(result.data.topology.mode).toBe('distributed')
      expect(result.data.topology.nodeId).toBe('node-a')
      expect(result.data.topology.clusterPeerCount).toBe(2)
      expect(result.data.topology.clusterPeers).toEqual([
        'node-b:9000',
        'node-c:9000',
      ])
      expect(result.data.topology.membershipProtocol).toBe('raft')
      expect(result.data.topology.placementEpoch).toBe(14)

      expect(result.data.membership).not.toBeNull()
      expect(result.data.membership?.mode).toBe('distributed')
      expect(result.data.membership?.protocol).toBe('static-bootstrap')
      expect(result.data.membership?.viewId).toBe('view-123')
      expect(result.data.membership?.coordinatorNodeId).toBe('node-a')
      expect(result.data.membership?.leaderNodeId).toBeNull()
      expect(result.data.membership?.nodes).toEqual([
        { nodeId: 'node-a', role: 'self', status: 'alive' },
        { nodeId: 'node-b:9000', role: 'peer', status: 'configured' },
      ])
    }
  })

  it('propagates summary request failures', async () => {
    mockFetchSequence([
      new Response(JSON.stringify({ error: 'Not authenticated' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    ])

    const result = await getRuntimeSummaryApi()
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('Not authenticated')
    }
  })

  it('parses membership JSON payload into typed membership data', async () => {
    mockFetchSequence([
      new Response(
        JSON.stringify({
          mode: 'distributed',
          protocol: 'static-bootstrap',
          viewId: 'view-123',
          leaderNodeId: null,
          coordinatorNodeId: 'node-a',
          nodes: [
            { nodeId: 'node-a', role: 'self', status: 'alive' },
            { nodeId: 'node-b:9000', role: 'peer', status: 'configured' },
          ],
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    ])

    const result = await getRuntimeMembershipApi()
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.mode).toBe('distributed')
      expect(result.data.protocol).toBe('static-bootstrap')
      expect(result.data.viewId).toBe('view-123')
      expect(result.data.leaderNodeId).toBeNull()
      expect(result.data.coordinatorNodeId).toBe('node-a')
      expect(result.data.nodes).toEqual([
        { nodeId: 'node-a', role: 'self', status: 'alive' },
        { nodeId: 'node-b:9000', role: 'peer', status: 'configured' },
      ])
    }
  })

  it('propagates membership request failures', async () => {
    mockFetchSequence([
      new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    ])

    const result = await getRuntimeMembershipApi()
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(401)
      expect(result.error).toBe('Unauthorized')
    }
  })

  it('parses placement JSON payload into typed placement data', async () => {
    mockFetchSequence([
      new Response(
        JSON.stringify({
          key: 'videos/movie.mp4',
          chunkIndex: 3,
          replicaCountRequested: 2,
          replicaCountApplied: 2,
          writeQuorumSize: 2,
          writeAckPolicy: 'majority',
          nonOwnerMutationPolicy: 'forward-single-write',
          nonOwnerReadPolicy: 'forward-single-read',
          nonOwnerBatchMutationPolicy: 'forward-multi-target-batch',
          mixedOwnerBatchMutationPolicy: 'forward-mixed-owner-batch',
          replicaFanoutOperations: ['put-object', 'copy-object'],
          pendingReplicaFanoutOperations: [],
          replicaFanoutExecution: {
            writeDurabilityMode: 'degraded-success',
            pendingReplicationQueueReadable: true,
            pendingReplicationBacklogOperations: 3,
            pendingReplicationBacklogPendingTargets: 5,
            pendingReplicationBacklogDueTargets: 2,
            pendingReplicationBacklogFailedTargets: 1,
            pendingReplicationReplayCyclesTotal: 8,
            pendingReplicationReplayCyclesSucceeded: 7,
            pendingReplicationReplayCyclesFailed: 1,
            pendingReplicationReplayLastSuccessUnixMs: 1709500000000,
          },
          owners: ['node-a:9000', 'node-b:9000'],
          primaryOwner: 'node-b:9000',
          forwardTarget: 'node-b:9000',
          isLocalPrimaryOwner: false,
          isLocalReplicaOwner: true,
          mode: 'distributed',
          nodeId: 'node-a:9000',
          clusterPeerCount: 1,
          clusterPeers: ['node-b:9000'],
          membershipProtocol: 'gossip',
          membershipViewId: 'view-456',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    ])

    const result = await getRuntimePlacementApi({
      key: 'videos/movie.mp4',
      chunkIndex: 3,
      replicaCount: 2,
    })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.key).toBe('videos/movie.mp4')
      expect(result.data.chunkIndex).toBe(3)
      expect(result.data.replicaCountRequested).toBe(2)
      expect(result.data.replicaCountApplied).toBe(2)
      expect(result.data.writeQuorumSize).toBe(2)
      expect(result.data.writeAckPolicy).toBe('majority')
      expect(result.data.nonOwnerMutationPolicy).toBe('forward-single-write')
      expect(result.data.nonOwnerReadPolicy).toBe('forward-single-read')
      expect(result.data.nonOwnerBatchMutationPolicy).toBe('forward-multi-target-batch')
      expect(result.data.mixedOwnerBatchMutationPolicy).toBe('forward-mixed-owner-batch')
      expect(result.data.replicaFanoutOperations).toEqual(['put-object', 'copy-object'])
      expect(result.data.pendingReplicaFanoutOperations).toEqual([])
      expect(result.data.replicaFanoutExecution).not.toBeNull()
      expect(result.data.replicaFanoutExecution?.writeDurabilityMode).toBe('degraded-success')
      expect(result.data.replicaFanoutExecution?.pendingReplicationQueueReadable).toBe(true)
      expect(result.data.replicaFanoutExecution?.pendingReplicationBacklogOperations).toBe(3)
      expect(result.data.replicaFanoutExecution?.pendingReplicationReplayCyclesTotal).toBe(8)
      expect(result.data.owners).toEqual(['node-a:9000', 'node-b:9000'])
      expect(result.data.primaryOwner).toBe('node-b:9000')
      expect(result.data.forwardTarget).toBe('node-b:9000')
      expect(result.data.isLocalPrimaryOwner).toBe(false)
      expect(result.data.isLocalReplicaOwner).toBe(true)
      expect(result.data.mode).toBe('distributed')
      expect(result.data.nodeId).toBe('node-a:9000')
      expect(result.data.clusterPeerCount).toBe(1)
      expect(result.data.clusterPeers).toEqual(['node-b:9000'])
      expect(result.data.membershipProtocol).toBe('gossip')
      expect(result.data.membershipViewId).toBe('view-456')
    }
  })

  it('propagates placement request failures', async () => {
    mockFetchSequence([
      new Response(JSON.stringify({ error: 'Missing required query parameter: key' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    ])

    const result = await getRuntimePlacementApi({ key: '' })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(400)
      expect(result.error).toContain('key')
    }
  })

  it('encodes placement query parameters', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    const okResponse = new Response(
      JSON.stringify({
        key: 'folder/my file #1.txt',
        owners: [],
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    )
    mockFetchCapture(calls, okResponse)

    await getRuntimePlacementApi({
      key: 'folder/my file #1.txt',
      replicaCount: 2,
      chunkIndex: 7,
    })

    expect(calls.map((c) => c.url)).toEqual([
      '/api/system/placement?key=folder%2Fmy+file+%231.txt&replicaCount=2&chunkIndex=7',
    ])
  })

  it('parses rebalance JSON payload into typed rebalance data', async () => {
    mockFetchSequence([
      new Response(
        JSON.stringify({
          key: 'videos/movie.mp4',
          chunkIndex: 2,
          replicaCountRequested: 2,
          replicaCountApplied: 1,
          operation: 'join',
          operationPeer: 'node-b:9000',
          source: {
            nodeId: 'node-a:9000',
            clusterPeerCount: 0,
            clusterPeers: [],
            membershipViewId: 'view-a',
            membershipNodes: ['node-a:9000'],
          },
          target: {
            nodeId: 'node-a:9000',
            clusterPeerCount: 1,
            clusterPeers: ['node-b:9000'],
            membershipViewId: 'view-b',
            membershipNodes: ['node-a:9000', 'node-b:9000'],
          },
          plan: {
            previousOwners: ['node-a:9000'],
            nextOwners: ['node-b:9000'],
            retainedOwners: [],
            removedOwners: ['node-a:9000'],
            addedOwners: ['node-b:9000'],
            transferCount: 1,
            localActions: [
              { action: 'send', from: 'node-a:9000', to: 'node-b:9000' },
              { action: 'receive', from: null, to: 'node-a:9000' },
            ],
            transfers: [{ from: 'node-a:9000', to: 'node-b:9000' }],
          },
          mode: 'distributed',
          nodeId: 'node-a:9000',
          clusterPeerCount: 1,
          clusterPeers: ['node-b:9000'],
          membershipProtocol: 'gossip',
          membershipViewId: 'view-a',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    ])

    const result = await getRuntimeRebalanceApi({
      key: 'videos/movie.mp4',
      chunkIndex: 2,
      replicaCount: 2,
      operation: 'join',
      peer: 'node-b:9000',
    })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.operation).toBe('join')
      expect(result.data.operationPeer).toBe('node-b:9000')
      expect(result.data.source.clusterPeers).toEqual([])
      expect(result.data.target.clusterPeers).toEqual(['node-b:9000'])
      expect(result.data.plan.previousOwners).toEqual(['node-a:9000'])
      expect(result.data.plan.nextOwners).toEqual(['node-b:9000'])
      expect(result.data.plan.transferCount).toBe(1)
      expect(result.data.plan.localActions).toEqual([
        { action: 'send', from: 'node-a:9000', to: 'node-b:9000' },
        { action: 'receive', from: null, to: 'node-a:9000' },
      ])
      expect(result.data.plan.transfers).toEqual([
        { from: 'node-a:9000', to: 'node-b:9000' },
      ])
    }
  })

  it('encodes rebalance query parameters', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    const okResponse = new Response(
      JSON.stringify({
        key: 'folder/my file #1.txt',
        source: {},
        target: {},
        plan: {},
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    )
    mockFetchCapture(calls, okResponse)

    const result = await getRuntimeRebalanceApi({
      key: 'folder/my file #1.txt',
      replicaCount: 2,
      chunkIndex: 7,
      operation: 'leave',
      peer: 'node-b.internal:9000',
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.plan.localActions).toEqual([])
    }

    expect(calls.map((c) => c.url)).toEqual([
      '/api/system/rebalance?key=folder%2Fmy+file+%231.txt&replicaCount=2&chunkIndex=7&removePeer=node-b.internal%3A9000',
    ])
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

  it('parses object list metadata coverage from console response', async () => {
    mockFetchSequence([
      new Response(
        JSON.stringify({
          files: [
            {
              key: 'docs/a.txt',
              size: 10,
              lastModified: '2026-03-03T00:00:00Z',
              etag: '"etag-a"',
            },
            {
              key: 42,
              size: 'bad',
              lastModified: null,
              etag: false,
            },
          ],
          prefixes: ['docs/'],
          emptyPrefixes: ['docs/empty/'],
          metadataCoverage: {
            complete: false,
            expectedNodes: ['node-a:9000', 'node-b:9000'],
            respondedNodes: ['node-a:9000'],
            missingNodes: ['node-b:9000'],
            source: 'local-node-only',
          },
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    ])

    const result = await listObjectsApi('bucket-a', 'docs/', '/')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.files).toEqual([
        {
          key: 'docs/a.txt',
          size: 10,
          lastModified: '2026-03-03T00:00:00Z',
          etag: '"etag-a"',
        },
      ])
      expect(result.data.prefixes).toEqual(['docs/'])
      expect(result.data.emptyPrefixes).toEqual(['docs/empty/'])
      expect(result.data.metadataCoverage).toEqual({
        complete: false,
        expectedNodes: ['node-a:9000', 'node-b:9000'],
        respondedNodes: ['node-a:9000'],
        missingNodes: ['node-b:9000'],
        source: 'local-node-only',
      })
    }
  })

  it('parses version list metadata coverage with null fallback for invalid payloads', async () => {
    mockFetchSequence([
      new Response(
        JSON.stringify({
          versions: [
            {
              versionId: 'v1',
              lastModified: '2026-03-03T00:00:00Z',
              size: 99,
              etag: '"etag-v1"',
              isDeleteMarker: false,
            },
            {
              versionId: 7,
              lastModified: 9,
              size: 'nope',
              etag: null,
              isDeleteMarker: 'false',
            },
          ],
          metadataCoverage: {
            complete: 'no',
            expectedNodes: ['node-a:9000'],
          },
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      ),
    ])

    const result = await listVersionsApi('bucket-a', 'docs/a.txt')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.versions).toEqual([
        {
          versionId: 'v1',
          lastModified: '2026-03-03T00:00:00Z',
          size: 99,
          etag: '"etag-v1"',
          isDeleteMarker: false,
        },
      ])
      expect(result.data.metadataCoverage).toBeNull()
    }
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
