# Changelog

## 2026-06-04 - Native Chisel Interoperability And Performance Hardening

### Added

- Added reverse SOCKS channel handling on the C# client path so native chisel servers can open
  `payload="socks"` channels for `R:socks` remotes.
- Added client-side SOCKS5 request parsing over SSH channels, including IPv4, IPv6, and domain
  address handling.
- Added client-side channel stream support for reverse SOCKS channel IO.
- Added .NET Framework v4.0 compatibility shims for async/task APIs used by the tunnel code.
- Added shared async concurrency limiting for burst-sensitive tunnel paths.
- Added TCP connect timeout helpers for .NET Framework 4.x target dials.

### Changed

- Reworked WebSocket transport to use raw WebSocket frame handling instead of `System.Net.WebSockets`
  APIs, preserving compatibility with .NET Framework v4.0.
- Increased TCP listener backlog values to handle bursts of concurrent tunnel connections.
- Increased runtime ThreadPool minimum worker and IO completion thread counts.
- Increased `ServicePointManager.DefaultConnectionLimit`.
- Replaced hot-path blocking SSH channel receives with async channel receive notifications.
- Batched SSH channel window adjustment messages to avoid sending late window updates for already
  closed short-lived channels.
- Added a client-side forward-channel concurrency limiter so bursty SOCKS clients queue locally
  instead of overloading one native chisel SSH session.
- Added inbound SOCKS channel limits on client and server paths to keep failed CONNECT bursts from
  exhausting a native chisel session.
- Added bounded TCP target dials for SOCKS, reverse TCP, direct TCP, WebSocket, and legacy tunnel
  helper paths.
- Serialized SSH channel-open confirmation before channel handler dispatch so close/failure paths
  cannot overtake confirmation packets during high concurrent native chisel opens.
- Moved remaining unavoidable blocking SSH channel receive paths onto long-running tasks to reduce
  ThreadPool starvation.
- Drained bidirectional pipe tasks before closing SSH channels to reduce close races under load.
- Adjusted server `--socks5` behavior so it enables SOCKS channel support without creating an
  unrelated default local SOCKS listener.

### Removed

- Removed unused legacy WebSocket wrapper sources that referenced newer .NET WebSocket APIs.
- Removed non-ASCII punctuation from source comments to keep the codebase friendly to older tooling.

### Validation

- Build matrix passed for:
  - `Debug|Any CPU`
  - `Debug|x64`
  - `Debug|x86`
  - `Release|Any CPU`
  - `Release|x64`
  - `Release|x86`
- Target framework override builds passed for:
  - `.NET Framework v4.0`
  - `.NET Framework v4.5`
  - `.NET Framework v4.5.1`
  - `.NET Framework v4.5.2`
  - `.NET Framework v4.6`
  - `.NET Framework v4.6.1`
  - `.NET Framework v4.6.2`
  - `.NET Framework v4.7.1`
  - `.NET Framework v4.7.2`
  - `.NET Framework v4.8`
- Native chisel 1.10.1 interoperability tests passed with 24 concurrent TCP requests per scenario:
  - C# client to native server direct TCP.
  - Native client to C# server direct TCP.
  - C# client to native server forward SOCKS.
  - Native client to C# server forward SOCKS.
  - C# client to native server reverse SOCKS (`R:socks`).
  - Native client to C# server reverse SOCKS (`R:socks`).
- High-burst SOCKS regression tests passed with 200 concurrent requests across repeated waves for:
  - C# client to native server forward SOCKS.
  - C# client to native server reverse SOCKS (`R:socks`).
  - Native client to C# server reverse SOCKS (`R:socks`).
  - Native client to C# server forward SOCKS.
- Failed-target SOCKS storm regression tests passed with native chisel 1.10.1:
  - Native server + C# client reverse SOCKS: 600 failed CONNECT attempts, then 1 recovery request,
    then 200 successful proxied echo requests.
  - C# server + native client forward SOCKS: 600 failed CONNECT attempts, then 1 recovery request,
    then 200 successful proxied echo requests.
