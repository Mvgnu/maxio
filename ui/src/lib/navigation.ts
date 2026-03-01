export type AppView = "objects" | "settings" | "metrics";

export interface ParsedRoute {
  bucket: string | null;
  view: AppView;
  prefix: string;
}

export function parseHashRoute(hash: string): ParsedRoute {
  const normalized = hash.startsWith("#") ? hash.slice(1) : hash;
  const route = normalized || "/";

  if (route === "/") {
    return { bucket: null, view: "objects", prefix: "" };
  }

  if (route === "/metrics") {
    return { bucket: null, view: "metrics", prefix: "" };
  }

  const parts = route.slice(1).split("/");
  const bucket = decodeURIComponent(parts[0] ?? "");
  const rest = parts.slice(1).join("/");

  if (rest === "settings") {
    return { bucket, view: "settings", prefix: "" };
  }

  return { bucket, view: "objects", prefix: rest };
}

export function buildHashRoute(
  view: AppView,
  bucket: string | null,
  prefix: string
): string {
  if (view === "metrics") {
    return "/metrics";
  }

  if (!bucket) {
    return "/";
  }

  if (view === "settings") {
    return `/${encodeURIComponent(bucket)}/settings`;
  }

  if (prefix) {
    return `/${encodeURIComponent(bucket)}/${prefix}`;
  }

  return `/${encodeURIComponent(bucket)}`;
}
