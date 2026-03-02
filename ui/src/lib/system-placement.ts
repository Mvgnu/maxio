export interface PlacementLookupRequest {
  key: string
  replicaCountInput: string
  chunkIndexInput: string
}

export interface PlacementLookupParams {
  key: string
  replicaCount: number
  chunkIndex?: number
}

const U32_MAX = 4_294_967_295

interface ParseSuccess {
  ok: true
  data: PlacementLookupParams
}

interface ParseFailure {
  ok: false
  error: string
}

export type PlacementLookupParseResult = ParseSuccess | ParseFailure

export function parsePlacementLookupRequest(
  request: PlacementLookupRequest
): PlacementLookupParseResult {
  if (request.key.trim().length === 0) {
    return {
      ok: false,
      error: 'Enter an object key to inspect placement.',
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
  if (chunkRaw.length === 0) {
    return {
      ok: true,
      data: {
        key: request.key,
        replicaCount,
      },
    }
  }
  if (!/^\d+$/.test(chunkRaw)) {
    return {
      ok: false,
      error: 'Chunk index must be a non-negative integer.',
    }
  }
  const chunkIndex = Number(chunkRaw)
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex > U32_MAX) {
    return {
      ok: false,
      error: 'Chunk index must be a non-negative integer.',
    }
  }

  return {
    ok: true,
    data: {
      key: request.key,
      replicaCount,
      chunkIndex,
    },
  }
}
