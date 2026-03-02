import { describe, expect, it } from 'bun:test'
import { parsePlacementLookupRequest } from './system-placement'

describe('parsePlacementLookupRequest', () => {
  it('rejects empty or whitespace-only keys', () => {
    expect(
      parsePlacementLookupRequest({
        key: '',
        replicaCountInput: '2',
        chunkIndexInput: '',
      })
    ).toEqual({
      ok: false,
      error: 'Enter an object key to inspect placement.',
    })

    expect(
      parsePlacementLookupRequest({
        key: '   ',
        replicaCountInput: '2',
        chunkIndexInput: '',
      })
    ).toEqual({
      ok: false,
      error: 'Enter an object key to inspect placement.',
    })
  })

  it('preserves non-empty key bytes while trimming numeric inputs', () => {
    expect(
      parsePlacementLookupRequest({
        key: ' docs/readme.txt ',
        replicaCountInput: ' 3 ',
        chunkIndexInput: ' 7 ',
      })
    ).toEqual({
      ok: true,
      data: {
        key: ' docs/readme.txt ',
        replicaCount: 3,
        chunkIndex: 7,
      },
    })
  })

  it('rejects parseInt-prefix numeric garbage values', () => {
    expect(
      parsePlacementLookupRequest({
        key: 'docs/readme.txt',
        replicaCountInput: '3abc',
        chunkIndexInput: '',
      })
    ).toEqual({
      ok: false,
      error: 'Replica count must be a positive integer.',
    })

    expect(
      parsePlacementLookupRequest({
        key: 'docs/readme.txt',
        replicaCountInput: '3',
        chunkIndexInput: '7abc',
      })
    ).toEqual({
      ok: false,
      error: 'Chunk index must be a non-negative integer.',
    })
  })

  it('rejects out-of-range chunk index values', () => {
    expect(
      parsePlacementLookupRequest({
        key: 'docs/readme.txt',
        replicaCountInput: '3',
        chunkIndexInput: '4294967296',
      })
    ).toEqual({
      ok: false,
      error: 'Chunk index must be a non-negative integer.',
    })
  })
})
