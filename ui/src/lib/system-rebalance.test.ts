import { describe, expect, it } from 'bun:test'
import { parseRebalanceLookupRequest } from './system-rebalance'

describe('parseRebalanceLookupRequest', () => {
  it('rejects empty key and invalid operation', () => {
    expect(
      parseRebalanceLookupRequest({
        key: '',
        replicaCountInput: '2',
        chunkIndexInput: '',
        operationInput: 'join',
        peerInput: 'node-b:9000',
      })
    ).toEqual({
      ok: false,
      error: 'Enter an object key to inspect rebalance.',
    })

    expect(
      parseRebalanceLookupRequest({
        key: 'docs/readme.txt',
        replicaCountInput: '2',
        chunkIndexInput: '',
        operationInput: 'move',
        peerInput: 'node-b:9000',
      })
    ).toEqual({
      ok: false,
      error: 'Operation must be join or leave.',
    })
  })

  it('accepts valid join input and trims numeric/peer values', () => {
    expect(
      parseRebalanceLookupRequest({
        key: ' docs/readme.txt ',
        replicaCountInput: ' 3 ',
        chunkIndexInput: ' 7 ',
        operationInput: ' JOIN ',
        peerInput: ' node-b.internal:9000 ',
      })
    ).toEqual({
      ok: true,
      data: {
        key: ' docs/readme.txt ',
        replicaCount: 3,
        chunkIndex: 7,
        operation: 'join',
        peer: 'node-b.internal:9000',
      },
    })
  })

  it('rejects invalid peer endpoint and numeric garbage', () => {
    expect(
      parseRebalanceLookupRequest({
        key: 'docs/readme.txt',
        replicaCountInput: '3abc',
        chunkIndexInput: '',
        operationInput: 'join',
        peerInput: 'node-b:9000',
      })
    ).toEqual({
      ok: false,
      error: 'Replica count must be a positive integer.',
    })

    expect(
      parseRebalanceLookupRequest({
        key: 'docs/readme.txt',
        replicaCountInput: '3',
        chunkIndexInput: '7abc',
        operationInput: 'join',
        peerInput: 'node-b:9000',
      })
    ).toEqual({
      ok: false,
      error: 'Chunk index must be a non-negative integer.',
    })

    expect(
      parseRebalanceLookupRequest({
        key: 'docs/readme.txt',
        replicaCountInput: '3',
        chunkIndexInput: '',
        operationInput: 'leave',
        peerInput: 'bad-peer',
      })
    ).toEqual({
      ok: false,
      error: 'Peer endpoint must be host:port.',
    })
  })
})
