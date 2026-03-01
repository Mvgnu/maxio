import { describe, expect, it } from 'bun:test'
import {
  buildObjectBreadcrumbs,
  formatObjectSize,
  objectDisplayName,
  parentObjectPrefix,
} from './object-browser'

describe('object-browser helpers', () => {
  it('builds breadcrumbs for root and nested prefixes', () => {
    expect(buildObjectBreadcrumbs('bucket-a', '')).toEqual([{ label: 'bucket-a', prefix: '' }])
    expect(buildObjectBreadcrumbs('bucket-a', 'docs/reports/')).toEqual([
      { label: 'bucket-a', prefix: '' },
      { label: 'docs', prefix: 'docs/' },
      { label: 'reports', prefix: 'docs/reports/' },
    ])
  })

  it('calculates parent prefixes safely', () => {
    expect(parentObjectPrefix('')).toBe('')
    expect(parentObjectPrefix('docs/')).toBe('')
    expect(parentObjectPrefix('docs/reports/')).toBe('docs/')
    expect(parentObjectPrefix('docs/reports')).toBe('docs/')
  })

  it('derives display names from object and folder paths', () => {
    expect(objectDisplayName('plain.txt')).toBe('plain.txt')
    expect(objectDisplayName('docs/report.pdf')).toBe('report.pdf')
    expect(objectDisplayName('docs/reports/')).toBe('reports')
  })

  it('formats object sizes across units', () => {
    expect(formatObjectSize(512)).toBe('512 B')
    expect(formatObjectSize(2048)).toBe('2.0 KB')
    expect(formatObjectSize(5 * 1024 * 1024)).toBe('5.0 MB')
    expect(formatObjectSize(3 * 1024 * 1024 * 1024)).toBe('3.0 GB')
  })
})
