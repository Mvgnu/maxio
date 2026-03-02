export interface RebalanceLookupRequest {
  key: string
  replicaCountInput: string
  chunkIndexInput: string
  operationInput: string
  peerInput: string
}

export interface RebalanceLookupParams {
  key: string
  replicaCount: number
  chunkIndex?: number
  operation: 'join' | 'leave'
  peer: string
}

const U32_MAX = 4_294_967_295

interface ParseSuccess {
  ok: true
  data: RebalanceLookupParams
}

interface ParseFailure {
  ok: false
  error: string
}

export type RebalanceLookupParseResult = ParseSuccess | ParseFailure

export function parseRebalanceLookupRequest(
  request: RebalanceLookupRequest
): RebalanceLookupParseResult {
  if (request.key.trim().length === 0) {
    return {
      ok: false,
      error: 'Enter an object key to inspect rebalance.',
    }
  }

  const replicaRaw = request.replicaCountInput.trim()
  if (!/^\d+$/.test(replicaRaw)) {
    return {
      ok: false,
      error: 'Replica count must be a positive integer.',
    }
  }
  const replicaCount = Number(replicaRaw)
  if (!Number.isSafeInteger(replicaCount) || replicaCount <= 0) {
    return {
      ok: false,
      error: 'Replica count must be a positive integer.',
    }
  }

  const chunkRaw = request.chunkIndexInput.trim()
  let chunkIndex: number | undefined
  if (chunkRaw.length > 0) {
    if (!/^\d+$/.test(chunkRaw)) {
      return {
        ok: false,
        error: 'Chunk index must be a non-negative integer.',
      }
    }
    chunkIndex = Number(chunkRaw)
    if (!Number.isSafeInteger(chunkIndex) || chunkIndex > U32_MAX) {
      return {
        ok: false,
        error: 'Chunk index must be a non-negative integer.',
      }
    }
  }

  const operationRaw = request.operationInput.trim().toLowerCase()
  const operation =
    operationRaw === 'join' || operationRaw === 'leave' ? operationRaw : null
  if (operation === null) {
    return {
      ok: false,
      error: 'Operation must be join or leave.',
    }
  }

  const peer = request.peerInput.trim()
  if (peer.length === 0) {
    return {
      ok: false,
      error: 'Enter a peer endpoint (host:port).',
    }
  }
  if (!isValidPeerEndpoint(peer)) {
    return {
      ok: false,
      error: 'Peer endpoint must be host:port.',
    }
  }

  return {
    ok: true,
    data: {
      key: request.key,
      replicaCount,
      chunkIndex,
      operation,
      peer,
    },
  }
}

function isValidPeerEndpoint(value: string): boolean {
  const parts = value.split(':')
  if (parts.length < 2) {
    return false
  }
  const port = parts[parts.length - 1]
  const host = parts.slice(0, -1).join(':').trim()
  if (host.length === 0 || !/^\d+$/.test(port)) {
    return false
  }
  const portValue = Number(port)
  return Number.isInteger(portValue) && portValue > 0 && portValue <= 65535
}
