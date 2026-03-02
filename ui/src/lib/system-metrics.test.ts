import { describe, expect, it } from 'bun:test'

import { loadSystemMetricsSnapshot } from './system-metrics'
import type {
  ApiResult,
  RuntimeHealth,
  RuntimeMembership,
  RuntimeMetrics,
  RuntimeSummary,
} from './api'

function ok<T>(status: number, data: T): ApiResult<T> {
  return { ok: true, status, data }
}

function fail(status: number, error: string): ApiResult<never> {
  return { ok: false, status, error, data: null }
}

describe('system metrics loader', () => {
  it('uses summary payload when available', async () => {
    const summary: RuntimeSummary = {
      health: {
        ok: true,
        status: 'ok',
        version: '0.1.0',
        uptimeSeconds: 42,
        mode: 'distributed',
        nodeId: 'node-a',
        clusterPeerCount: 2,
        clusterPeers: ['node-b:9000', 'node-c:9000'],
        membershipProtocol: 'raft',
        placementEpoch: 4,
        membershipViewId: null,
        checks: null,
        warnings: [],
        raw: { ok: true },
      },
      metrics: {
        requestsTotal: 12,
        uptimeSeconds: 40,
        version: '0.1.0',
        mode: 'distributed',
        nodeId: 'node-a',
        clusterPeerCount: 2,
        clusterPeers: ['node-b:9000', 'node-c:9000'],
        membershipProtocol: 'raft',
        placementEpoch: 4,
        raw: '{"requestsTotal":12}',
      },
      topology: {
        mode: 'distributed',
        nodeId: 'node-a',
        clusterPeerCount: 2,
        clusterPeers: ['node-b:9000', 'node-c:9000'],
        membershipProtocol: 'raft',
        placementEpoch: 4,
        raw: { mode: 'distributed' },
      },
      membership: {
        mode: 'distributed',
        protocol: 'static-bootstrap',
        viewId: 'view-abc',
        leaderNodeId: null,
        coordinatorNodeId: 'node-a',
        nodes: [
          { nodeId: 'node-a', role: 'self', status: 'alive' },
          { nodeId: 'node-b:9000', role: 'peer', status: 'configured' },
        ],
        raw: { viewId: 'view-abc' },
      },
    }
    let membershipCalls = 0

    const result = await loadSystemMetricsSnapshot({
      getSummary: async () => ok(200, summary),
      getMetrics: async () => fail(500, 'should not call metrics'),
      getHealth: async () => fail(500, 'should not call health'),
      getMembership: async () => {
        membershipCalls += 1
        return fail(500, 'should not call membership')
      },
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.requestsTotal).toBe(12)
      expect(result.data.uptimeSeconds).toBe(40)
      expect(result.data.version).toBe('0.1.0')
      expect(result.data.mode).toBe('distributed')
      expect(result.data.nodeId).toBe('node-a')
      expect(result.data.clusterPeerCount).toBe(2)
      expect(result.data.placementEpoch).toBe(4)
      expect(result.data.membershipViewId).toBe('view-abc')
      expect(result.data.membershipProtocol).toBe('static-bootstrap')
      expect(result.data.coordinatorNodeId).toBe('node-a')
      expect(result.data.leaderNodeId).toBeNull()
      expect(result.data.membershipNodeCount).toBe(2)
      expect(result.data.healthOk).toBe(true)
      expect(result.data.healthStatus).toBe('ok')
      expect(result.data.healthWarnings).toEqual([])
      expect(result.data.healthChecks).toBeNull()
      expect(result.data.raw).toContain('"health"')
      expect(result.data.raw).toContain('"topology"')
      expect(result.data.raw).toContain('"membership"')
    }
    expect(membershipCalls).toBe(0)
  })

  it('fetches membership separately when summary omits membership payload', async () => {
    const summary: RuntimeSummary = {
      health: {
        ok: true,
        status: 'ok',
        version: '0.1.0',
        uptimeSeconds: 42,
        mode: 'distributed',
        nodeId: 'node-a',
        clusterPeerCount: 2,
        clusterPeers: ['node-b:9000', 'node-c:9000'],
        membershipProtocol: 'gossip',
        placementEpoch: 6,
        membershipViewId: null,
        checks: null,
        warnings: [],
        raw: { ok: true },
      },
      metrics: {
        requestsTotal: 12,
        uptimeSeconds: 40,
        version: '0.1.0',
        mode: 'distributed',
        nodeId: 'node-a',
        clusterPeerCount: 2,
        clusterPeers: ['node-b:9000', 'node-c:9000'],
        membershipProtocol: 'gossip',
        placementEpoch: 6,
        raw: '{"requestsTotal":12}',
      },
      topology: {
        mode: 'distributed',
        nodeId: 'node-a',
        clusterPeerCount: 2,
        clusterPeers: ['node-b:9000', 'node-c:9000'],
        membershipProtocol: 'gossip',
        placementEpoch: 6,
        raw: { mode: 'distributed' },
      },
      membership: null,
    }
    let membershipCalls = 0

    const result = await loadSystemMetricsSnapshot({
      getSummary: async () => ok(200, summary),
      getMetrics: async () => fail(500, 'should not call metrics'),
      getHealth: async () => fail(500, 'should not call health'),
      getMembership: async () => {
        membershipCalls += 1
        return ok(200, {
          mode: 'distributed',
          protocol: 'static-bootstrap',
          viewId: 'view-fallback',
          leaderNodeId: null,
          coordinatorNodeId: 'node-a',
          nodes: [
            { nodeId: 'node-a', role: 'self', status: 'alive' },
            { nodeId: 'node-b:9000', role: 'peer', status: 'configured' },
          ],
          raw: { viewId: 'view-fallback' },
        })
      },
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.membershipViewId).toBe('view-fallback')
      expect(result.data.placementEpoch).toBe(6)
      expect(result.data.membershipProtocol).toBe('static-bootstrap')
      expect(result.data.membershipNodeCount).toBe(2)
    }
    expect(membershipCalls).toBe(1)
  })

  it('falls back to summary membershipProtocol when membership payload is unavailable', async () => {
    const summary: RuntimeSummary = {
      health: {
        ok: true,
        status: 'ok',
        version: '0.1.0',
        uptimeSeconds: 42,
        mode: 'distributed',
        nodeId: 'node-a',
        clusterPeerCount: 2,
        clusterPeers: ['node-b:9000', 'node-c:9000'],
        membershipProtocol: 'gossip',
        placementEpoch: 8,
        membershipViewId: 'view-summary',
        checks: null,
        warnings: [],
        raw: { ok: true },
      },
      metrics: {
        requestsTotal: 12,
        uptimeSeconds: 40,
        version: '0.1.0',
        mode: 'distributed',
        nodeId: 'node-a',
        clusterPeerCount: 2,
        clusterPeers: ['node-b:9000', 'node-c:9000'],
        membershipProtocol: 'gossip',
        placementEpoch: 8,
        raw: '{"requestsTotal":12}',
      },
      topology: {
        mode: 'distributed',
        nodeId: 'node-a',
        clusterPeerCount: 2,
        clusterPeers: ['node-b:9000', 'node-c:9000'],
        membershipProtocol: 'gossip',
        placementEpoch: 8,
        raw: { mode: 'distributed' },
      },
      membership: null,
    }

    const result = await loadSystemMetricsSnapshot({
      getSummary: async () => ok(200, summary),
      getMetrics: async () => fail(500, 'should not call metrics'),
      getHealth: async () => fail(500, 'should not call health'),
      getMembership: async () => fail(503, 'membership unavailable'),
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.membershipProtocol).toBe('gossip')
      expect(result.data.placementEpoch).toBe(8)
      expect(result.data.membershipViewId).toBe('view-summary')
      expect(result.data.membershipNodeCount).toBeNull()
    }
  })

  it('falls back to metrics + health when summary fails', async () => {
    const metrics: RuntimeMetrics = {
      requestsTotal: 99,
      uptimeSeconds: null,
      version: null,
      mode: null,
      nodeId: null,
      clusterPeerCount: null,
      clusterPeers: [],
      membershipProtocol: null,
      placementEpoch: 10,
      raw: 'raw metrics payload',
    }
    const health: RuntimeHealth = {
      ok: true,
      status: 'ok',
      version: '0.9.9',
      uptimeSeconds: 3600,
      mode: 'distributed',
      nodeId: 'node-z',
      clusterPeerCount: 3,
      clusterPeers: ['a', 'b', 'c'],
      membershipProtocol: 'raft',
      placementEpoch: 10,
      membershipViewId: 'view-z',
      checks: null,
      warnings: [],
      raw: { ok: true },
    }
    const membership: RuntimeMembership = {
      mode: 'distributed',
      protocol: 'static-bootstrap',
      viewId: 'view-z',
      leaderNodeId: null,
      coordinatorNodeId: 'node-z',
      nodes: [
        { nodeId: 'node-z', role: 'self', status: 'alive' },
        { nodeId: 'a', role: 'peer', status: 'configured' },
        { nodeId: 'b', role: 'peer', status: 'configured' },
      ],
      raw: { viewId: 'view-z' },
    }

    const result = await loadSystemMetricsSnapshot({
      getSummary: async () => fail(401, 'Not authenticated'),
      getMetrics: async () => ok(200, metrics),
      getHealth: async () => ok(200, health),
      getMembership: async () => ok(200, membership),
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.data.requestsTotal).toBe(99)
      expect(result.data.uptimeSeconds).toBe(3600)
      expect(result.data.version).toBe('0.9.9')
      expect(result.data.mode).toBe('distributed')
      expect(result.data.nodeId).toBe('node-z')
      expect(result.data.clusterPeerCount).toBe(3)
      expect(result.data.placementEpoch).toBe(10)
      expect(result.data.membershipViewId).toBe('view-z')
      expect(result.data.membershipProtocol).toBe('static-bootstrap')
      expect(result.data.coordinatorNodeId).toBe('node-z')
      expect(result.data.leaderNodeId).toBeNull()
      expect(result.data.membershipNodeCount).toBe(3)
      expect(result.data.healthOk).toBe(true)
      expect(result.data.healthStatus).toBe('ok')
      expect(result.data.healthWarnings).toEqual([])
      expect(result.data.raw).toBe('raw metrics payload')
    }
  })

  it('returns failure when summary and metrics fail', async () => {
    const result = await loadSystemMetricsSnapshot({
      getSummary: async () => fail(401, 'Not authenticated'),
      getMetrics: async () => fail(500, 'Metrics unavailable'),
      getHealth: async () => fail(503, 'Health unavailable'),
      getMembership: async () => fail(401, 'Not authenticated'),
    })

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(500)
      expect(result.error).toBe('Metrics unavailable')
    }
  })
})
