# chiselSharp

chiselSharp is a C#/.NET Framework port of the core client/server tunneling behavior from
[jpillora/chisel](https://github.com/jpillora/chisel). The project focuses on native chisel
interoperability, legacy .NET Framework compatibility, and stable multi-connection TCP/SOCKS
tunneling.

## Intended Use

This project is intended for authorized network administration, lab testing, and interoperability
research with native chisel deployments. Operators are responsible for using it only in environments
where they have permission.

## What This Project Does

- Runs in `server` and `client` modes with chisel-style command-line arguments.
- Speaks the native chisel `chisel-v3` WebSocket transport protocol.
- Implements the SSH transport and channel layer required by chisel tunnels.
- Supports TCP forward tunnels and reverse TCP tunnels.
- Supports forward SOCKS5 tunnels through a native-compatible server-side SOCKS channel.
- Supports reverse SOCKS5 tunnels (`R:socks`) with both native chisel servers and clients.
- Parses common chisel remote specs such as `3000`, `3000:host:80`, `socks`, and `R:socks`.
- Builds against .NET Framework v4.0 while also compiling through common .NET Framework 4.x targets.

## Compatibility Goals

The main compatibility target is interoperability with native chisel 1.10.x for TCP and SOCKS
tunneling. The code avoids newer WebSocket APIs so the project can compile for .NET Framework
v4.0 and run in older Windows environments where newer framework APIs may not be available.

## Major Implementation Notes

- `Transport/WebSocketFrameStream.cs` implements raw client/server WebSocket framing, including
  masked client frames and the `chisel-v3` subprotocol.
- `SSH/SshTransport.cs` and `SSH/SshConnection.cs` provide the SSH handshake, authentication,
  channel open/confirm/close handling, channel data, EOF, and window adjustment behavior used by
  chisel.
- `Client/ChiselClient.cs` handles native chisel config exchange, local forward listeners,
  reverse TCP channels, forward SOCKS channels, and reverse SOCKS channel handling.
- `Server/ChiselServer.cs` and `Server/ServerSession.cs` handle server-side WebSocket accept,
  SSH session setup, remote configuration, direct channel handling, reverse listeners, and
  server-side SOCKS channel handling.
- `Utils/Net40Compat.cs` provides .NET 4.0 compatibility shims for async/await support,
  stream async helpers, TCP accept/connect helpers, UDP async helpers, and task utilities.

## Performance And Stability Optimizations

- Raised TCP listener backlog values for high connection bursts.
- Raised process ThreadPool minimum worker and IO completion thread counts at startup.
- Increased `ServicePointManager.DefaultConnectionLimit` for concurrent outbound connections.
- Replaced per-read blocking channel receive workers with async channel receive notifications.
- Batches SSH channel window adjustments so short-lived SOCKS connections do not race channel close.
- Bounds concurrent client-side forward channels to avoid overloading a single native chisel session
  during large SOCKS request bursts.
- Moved remaining unavoidable blocking channel receive loops to long-running tasks to reduce
  ThreadPool starvation.
- Added pipe-drain behavior before closing SSH channels to reduce close races and invalid-channel
  errors under concurrent load.
- Enabled `TcpClient.NoDelay` on tunnel sockets where low-latency forwarding matters.
- Removed unused legacy `System.Net.WebSockets` wrapper code so .NET Framework v4.0 builds do not
  accidentally depend on newer WebSocket APIs.

## Build

Use MSBuild from the .NET Framework toolchain:

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe chiselSharp.sln /p:Configuration=Release /p:Platform=x64 /t:Rebuild
```

The default project target is .NET Framework v4.0. The code has also been build-checked with
target framework overrides from v4.0 through v4.8.

## Validation Summary

The current implementation was tested against native chisel 1.10.1 with 24 concurrent TCP requests
per scenario:

- C# client to native server, direct TCP tunnel: passed.
- Native client to C# server, direct TCP tunnel: passed.
- C# client to native server, forward SOCKS tunnel: passed.
- Native client to C# server, forward SOCKS tunnel: passed.
- C# client to native server, reverse SOCKS tunnel (`R:socks`): passed.
- Native client to C# server, reverse SOCKS tunnel (`R:socks`): passed.
- High-burst SOCKS regression tests with 200 concurrent requests across repeated waves: passed.

UDP and TLS/mTLS paths are implemented or parsed in parts of the project, but they have not received
the same full native interoperability load audit as TCP and SOCKS.
