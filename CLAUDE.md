# MaxIO agent entry point

Follow [AGENTS.md](AGENTS.md). It is the shared instruction entry point for every
agent, independent of model or provider.

Architecture and product guarantees: [specs/00_system.md](specs/00_system.md).
Scoped development: [lop.md](lop.md). Independent judgment: [gauntlet.md](gauntlet.md).
Build and user commands: [README.md](README.md).

Use **Bun**, never npm, for the console. Build `ui/dist/` before compiling Rust;
release builds embed those assets. Do not commit generated output or local data.
