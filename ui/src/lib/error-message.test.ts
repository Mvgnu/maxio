import { describe, expect, it } from 'bun:test'

import { errorMessageOrFallback } from './error-message'

describe('errorMessageOrFallback', () => {
  it('returns fallback for nullish values', () => {
    expect(errorMessageOrFallback(undefined, 'fallback')).toBe('fallback')
    expect(errorMessageOrFallback(null, 'fallback')).toBe('fallback')
  })

  it('returns fallback for empty and whitespace-only values', () => {
    expect(errorMessageOrFallback('', 'fallback')).toBe('fallback')
    expect(errorMessageOrFallback('   ', 'fallback')).toBe('fallback')
  })

  it('returns trimmed message when present', () => {
    expect(errorMessageOrFallback('  invalid credentials ', 'fallback')).toBe(
      'invalid credentials'
    )
  })
})
