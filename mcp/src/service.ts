import type { Config } from "./config";
type Child = Bun.Subprocess<"ignore", "pipe", "pipe">;
const live = (child?: Child) =>
  !!child && child.exitCode === null && child.signalCode === null;

export class Service {
  private child?: Child;
  private logs = "";
  private disposed = false;
  private transition: Promise<unknown> = Promise.resolve();
  private serialize<T>(action: () => Promise<T>): Promise<T> {
    const next = this.transition.then(action);
    this.transition = next.catch(() => {});
    return next;
  }
  constructor(
    private config: Config["service"],
    private consoleConfig: Config["console"],
  ) {}

  private async external() {
    try {
      const response = await fetch(
        new URL("/api/auth/check", this.consoleConfig.endpoint),
        {
          redirect: "manual",
          signal: AbortSignal.timeout(1000),
        },
      );
      await response.body?.cancel();
      return true;
    } catch {
      return false;
    }
  }
  status() {
    return {
      configured: !!this.config,
      owned: live(this.child),
      running: live(this.child),
      exitCode: this.child?.exitCode ?? null,
      signal: this.child?.signalCode ?? null,
    };
  }
  async observedStatus() {
    const status = this.status();
    if (status.owned)
      return {
        ...status,
        state: (await this.external())
          ? "reachable"
          : "starting-or-unreachable",
      };
    const external = await this.external();
    return {
      ...status,
      running: external,
      external,
      state: external ? "external" : "stopped",
    };
  }
  tail() {
    const secrets = [
      this.consoleConfig.secretKey,
      this.consoleConfig.accessKey,
    ];
    for (let i = 0; i < (this.config?.args.length ?? 0); i++) {
      if (/secret|password|token|access-key/i.test(this.config!.args[i])) {
        const [flag, value] = this.config!.args[i].split("=", 2);
        if (value) secrets.push(value);
        else if (this.config!.args[i + 1])
          secrets.push(this.config!.args[i + 1]);
        void flag;
      }
    }
    let logs = this.logs;
    for (const secret of secrets)
      if (secret) logs = logs.split(secret).join("[REDACTED]");
    return { logs, ...this.status() };
  }
  private async drain(stream: ReadableStream<Uint8Array>) {
    const reader = stream.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      this.logs = (this.logs + new TextDecoder().decode(value)).slice(-16384);
    }
  }
  private async startChild() {
    if (this.disposed) throw new Error("Service session is closing");
    if (!this.config)
      throw new Error("Service unavailable: no owner-configured command");
    if (live(this.child)) return this.observedStatus();
    {
      if (await this.external())
        return {
          ...this.status(),
          external: true,
          running: true,
          state: "external",
        };
      this.child = Bun.spawn([this.config.command, ...this.config.args], {
        cwd: this.config.cwd,
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
      });
      void this.drain(this.child.stdout);
      void this.drain(this.child.stderr);
      return { ...this.status(), state: "starting" };
    }
  }
  private async stopChild() {
    const child = this.child;
    if (!child || !live(child)) {
      if (await this.external())
        throw new Error(
          "External server is not owned by this MCP session; stop/restart refused",
        );
      return this.status();
    }
    {
      child.kill("SIGTERM");
      await Promise.race([child.exited, Bun.sleep(3000)]);
      if (live(child)) {
        child.kill("SIGKILL");
        await child.exited;
      }
      return this.status();
    }
  }
  dispose() {
    this.disposed = true;
    return this.serialize(async () => {
      if (live(this.child)) await this.stopChild();
    });
  }
  start() {
    return this.serialize(() => this.startChild());
  }
  stop() {
    return this.serialize(() => this.stopChild());
  }
  restart() {
    return this.serialize(async () => {
      await this.stopChild();
      return this.startChild();
    });
  }
}
