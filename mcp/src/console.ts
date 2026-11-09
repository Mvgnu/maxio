export const MAX_BYTES = 1024 * 1024;
export type ConsoleConfig = {
  endpoint: string;
  accessKey: string;
  secretKey: string;
};
export function canonicalOrigin(endpoint: string): string {
  const u = new URL(endpoint);
  if (
    (endpoint !== u.origin && endpoint !== u.origin + "/") ||
    u.username ||
    u.password ||
    u.pathname !== "/" ||
    u.search ||
    u.hash ||
    !["http:", "https:"].includes(u.protocol)
  )
    throw new Error("Console endpoint must be a canonical origin");
  if (
    u.protocol === "http:" &&
    !["127.0.0.1", "localhost", "[::1]"].includes(u.hostname)
  )
    throw new Error("Remote console requires HTTPS");
  return u.origin;
}
export function segment(value: string): string {
  if (
    !value ||
    value === "." ||
    value === ".." ||
    /[/\\\u0000-\u001f]/.test(value)
  )
    throw new Error("Invalid path component");
  return encodeURIComponent(value);
}
export function objectPath(
  bucket: string,
  action: string,
  key: string,
): string {
  const parts = key.split("/");
  // Folder markers have one final slash; interior empty components are forbidden.
  if (parts.at(-1) === "") parts.pop();
  if (!parts.length) throw new Error("Invalid object key");
  return `/api/buckets/${segment(bucket)}/${segment(action)}/${parts.map(segment).join("/")}${key.endsWith("/") ? "/" : ""}`;
}
export async function boundedBody(
  response: Response,
  limit = MAX_BYTES,
): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) throw new Error(`Response exceeds ${limit} byte limit`);
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
export class ConsoleClient {
  private readonly origin: string;
  private cookie?: string;
  private loginPending?: Promise<void>;
  constructor(private readonly config: ConsoleConfig) {
    this.origin = canonicalOrigin(config.endpoint);
  }
  private async fetch(path: string, init: RequestInit): Promise<Response> {
    const u = new URL(path, this.origin);
    if (
      u.origin !== this.origin ||
      !path.startsWith("/api/") ||
      path.includes("\\")
    )
      throw new Error("Invalid console route");
    try {
      return await fetch(u, {
        ...init,
        redirect: "manual",
        signal: AbortSignal.timeout(10000),
      });
    } catch {
      throw new Error(
        "Console transport failed; mutation outcome may be unknown. Inspect state before retrying",
      );
    }
  }
  private async login(): Promise<void> {
    if (this.loginPending) return this.loginPending;
    this.loginPending = (async () => {
      const response = await this.fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          accessKey: this.config.accessKey,
          secretKey: this.config.secretKey,
        }),
      });
      await boundedBody(response);
      if (!response.ok)
        throw new Error(`Console login HTTP ${response.status}`);
      const cookie = response.headers
        .getSetCookie()
        .map((x) => x.split(";")[0])
        .find((x) => x.startsWith("maxio_session="));
      if (!cookie || cookie.length > 4096)
        throw new Error("Console login did not issue a valid session");
      this.cookie = cookie;
    })();
    try {
      await this.loginPending;
    } finally {
      this.loginPending = undefined;
    }
  }
  async request(
    method: string,
    path: string,
    body?: BodyInit,
    contentType?: string,
  ): Promise<Uint8Array> {
    if (!this.cookie) await this.login();
    const send = () =>
      this.fetch(path, {
        method,
        headers: {
          cookie: this.cookie!,
          ...(contentType ? { "content-type": contentType } : {}),
        },
        body,
      });
    let response = await send();
    // Retry only observations. Mutations are never automatically replayed, even after 401.
    if (response.status === 401) {
      this.cookie = undefined;
      await boundedBody(response);
      await this.login();
      if (method === "GET") response = await send();
      else
        throw new Error(
          "Console HTTP 401; session refreshed, mutation was not retried",
        );
    }
    const bytes = await boundedBody(response);
    if (!response.ok) throw new Error(`Console HTTP ${response.status}`);
    return bytes;
  }
  async json(method: string, path: string, body?: unknown): Promise<unknown> {
    const bytes = await this.request(
      method,
      path,
      body === undefined ? undefined : JSON.stringify(body),
      body === undefined ? undefined : "application/json",
    );
    try {
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      throw new Error("Invalid console JSON response");
    }
  }
}
