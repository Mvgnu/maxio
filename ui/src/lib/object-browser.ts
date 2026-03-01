export interface ObjectBreadcrumb {
  label: string
  prefix: string
}

export function buildObjectBreadcrumbs(bucket: string, prefix: string): ObjectBreadcrumb[] {
  const parts = prefix.split('/').filter(Boolean)
  const breadcrumbs: ObjectBreadcrumb[] = [{ label: bucket, prefix: '' }]
  let accumulated = ''

  for (const part of parts) {
    accumulated += `${part}/`
    breadcrumbs.push({ label: part, prefix: accumulated })
  }

  return breadcrumbs
}

export function parentObjectPrefix(prefix: string): string {
  if (!prefix) {
    return ''
  }
  const trimmed = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix
  const lastSlash = trimmed.lastIndexOf('/')
  return lastSlash >= 0 ? `${trimmed.slice(0, lastSlash)}/` : ''
}

export function objectDisplayName(fullPath: string): string {
  const trimmed = fullPath.endsWith('/') ? fullPath.slice(0, -1) : fullPath
  const lastSlash = trimmed.lastIndexOf('/')
  return lastSlash >= 0 ? trimmed.slice(lastSlash + 1) : trimmed
}

export function formatObjectSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
}
