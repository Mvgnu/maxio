export function errorMessageOrFallback(
  message: string | null | undefined,
  fallback: string
): string {
  if (typeof message !== 'string') {
    return fallback
  }

  const trimmed = message.trim()
  return trimmed.length > 0 ? trimmed : fallback
}
