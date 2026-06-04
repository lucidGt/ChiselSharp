using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using ChiselSharp.Server;
using ChiselSharp.Client;
using ChiselSharp.Settings;
using ChiselSharp.Tunnels;
using ChiselSharp.Utils;

namespace ChiselSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            ConfigureRuntime();

            if (args.Length == 0)
            {
                PrintUsage();
                return;
            }

            string command = args[0].ToLower();

            if (command == "server")
            {
                RunServer(ParseServerArgs(args));
            }
            else if (command == "client")
            {
                RunClient(ParseClientArgs(args));
            }
            else if (command == "--version" || command == "-v")
            {
                Console.WriteLine("chiselSharp 1.0.0 (C# port of jpillora/chisel)");
            }
            else if (command == "--help" || command == "-h")
            {
                PrintUsage();
            }
            else
            {
                Console.WriteLine("Unknown command: " + command);
                PrintUsage();
            }
        }

        private static void ConfigureRuntime()
        {
            int workerThreads;
            int completionPortThreads;
            ThreadPool.GetMinThreads(out workerThreads, out completionPortThreads);

            int minWorker = workerThreads < 64 ? 64 : workerThreads;
            int minIo = completionPortThreads < 64 ? 64 : completionPortThreads;
            ThreadPool.SetMinThreads(minWorker, minIo);
            ServicePointManager.DefaultConnectionLimit = 1024;
        }

        static Config ParseServerArgs(string[] args)
        {
            var config = new Config { IsServer = true };

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--port":
                    case "-p":
                        if (i + 1 < args.Length) config.Port = int.Parse(args[++i]);
                        break;
                    case "--host":
                        if (i + 1 < args.Length) config.Host = args[++i];
                        break;
                    case "--key":
                        if (i + 1 < args.Length) config.Key = args[++i];
                        break;
                    case "--keyfile":
                        if (i + 1 < args.Length) config.KeyFile = args[++i];
                        break;
                    case "--auth":
                        if (i + 1 < args.Length) config.Auth = args[++i];
                        break;
                    case "--authfile":
                        if (i + 1 < args.Length) config.AuthFile = args[++i];
                        break;
                    case "--socks5":
                        config.Socks5 = true;
                        break;
                    case "--reverse":
                        config.Reverse = true;
                        break;
                    case "--keepalive":
                        if (i + 1 < args.Length) config.Keepalive = TimeSpan.Parse(args[++i]);
                        break;
                    case "--backend":
                        if (i + 1 < args.Length) config.Backend = args[++i];
                        break;
                    case "--tls-key":
                        if (i + 1 < args.Length) config.TlsKey = args[++i];
                        break;
                    case "--tls-cert":
                        if (i + 1 < args.Length) config.TlsCert = args[++i];
                        break;
                    case "--tls-domain":
                        if (i + 1 < args.Length) config.TlsDomain = args[++i];
                        break;
                    case "--tls-ca":
                        if (i + 1 < args.Length) config.TlsCA = args[++i];
                        break;
                    case "-v":
                    case "--verbose":
                        config.Verbose = true;
                        break;
                }
            }

            return config;
        }

        static Config ParseClientArgs(string[] args)
        {
            var config = new Config { IsClient = true };
            bool serverUrlFound = false;

            for (int i = 1; i < args.Length; i++)
            {
                string arg = args[i];

                if (!serverUrlFound && !arg.StartsWith("-") && arg.IndexOf(":") < 0 && arg.IndexOf(".") < 0)
                {
                    // Might be a remote spec without flags - could be a port number
                    config.Remotes.Add(arg);
                    continue;
                }

                switch (arg)
                {
                    case "--fingerprint":
                        if (i + 1 < args.Length) config.Fingerprint = args[++i];
                        break;
                    case "--auth":
                        if (i + 1 < args.Length) config.Auth = args[++i];
                        break;
                    case "--keepalive":
                        if (i + 1 < args.Length) config.Keepalive = TimeSpan.Parse(args[++i]);
                        break;
                    case "--max-retry-count":
                        if (i + 1 < args.Length) config.MaxRetryCount = int.Parse(args[++i]);
                        break;
                    case "--max-retry-interval":
                        if (i + 1 < args.Length) config.MaxRetryInterval = TimeSpan.Parse(args[++i]);
                        break;
                    case "--proxy":
                        if (i + 1 < args.Length) config.Proxy = args[++i];
                        break;
                    case "--header":
                        if (i + 1 < args.Length)
                        {
                            string header = args[++i];
                            string[] parts = header.Split(new[] { ':' }, 2);
                            if (parts.Length == 2)
                                config.Headers[parts[0].Trim()] = parts[1].Trim();
                        }
                        break;
                    case "--hostname":
                        // Hostname is parsed but applied via WebSocket headers; stored for future use
                        if (i + 1 < args.Length) { i++; } // skip value without storing (not yet implemented)
                        break;
                    case "--tls-skip-verify":
                        config.TlsSkipVerify = true;
                        break;
                    case "--tls-key":
                        if (i + 1 < args.Length) config.TlsKey = args[++i];
                        break;
                    case "--tls-cert":
                        if (i + 1 < args.Length) config.TlsCert = args[++i];
                        break;
                    case "--tls-ca":
                        if (i + 1 < args.Length) config.TlsCA = args[++i];
                        break;
                    case "-v":
                    case "--verbose":
                        config.Verbose = true;
                        break;
                    default:
                        if (!arg.StartsWith("-"))
                        {
                            if (!serverUrlFound)
                            {
                                config.ServerUrl = arg;
                                serverUrlFound = true;
                            }
                            else
                            {
                                config.Remotes.Add(arg);
                            }
                        }
                        break;
                }
            }

            if (string.IsNullOrEmpty(config.ServerUrl))
            {
                Console.Error.WriteLine("Error: server URL is required");
                Console.Error.WriteLine("Usage: chiselSharp client <server-url> <remote> [<remote>...]");
                Environment.Exit(1);
            }

            return config;
        }

        static void RunServer(Config config)
        {
            Logger.Verbose = config.Verbose;

            var server = new ChiselServer(config);

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                server.Stop();
            };

            try
            {
                server.StartAsync().GetAwaiter().GetResult();

                // Keep running until Ctrl+C
                var waitHandle = new ManualResetEvent(false);
                waitHandle.WaitOne();
            }
            catch (Exception ex)
            {
                Logger.Error("Server error: " + ex.Message);
                Environment.Exit(1);
            }
        }

        static void RunClient(Config config)
        {
            Logger.Verbose = config.Verbose;

            if (config.Remotes.Count == 0)
            {
                Console.Error.WriteLine("Error: at least one remote is required");
                Console.Error.WriteLine("Usage: chiselSharp client <server-url> <remote> [<remote>...]");
                Environment.Exit(1);
            }

            var client = new ChiselClient(config);

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                client.Stop();
            };

            try
            {
                client.RunAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Logger.Error("Client error: " + ex.Message);
                Environment.Exit(1);
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine(@"
  chiselSharp - C# port of jpillora/chisel (TCP/UDP tunnel over HTTP)

  Usage: chiselSharp server [options]
         chiselSharp client [options] <server-url> <remote> [<remote>...]

  Server options:
    --port PORT          Listening port (default: 8080)
    --host HOST          Listening host (default: 0.0.0.0)
    --key KEY            Seed for server key generation
    --keyfile PATH       Path to PEM-encoded server key
    --auth USER:PASS     Single user/password credential
    --authfile PATH      Path to users.json auth file
    --socks5             Enable SOCKS5 proxy on server
    --reverse            Allow reverse tunnels
    --keepalive DUR      Keepalive interval (default: 25s)
    --backend URL        Reverse proxy normal HTTP to backend
    --tls-key FILE       TLS private key file
    --tls-cert FILE      TLS certificate file
    --tls-domain DOMAIN  Auto-TLS domain (Let's Encrypt)
    --tls-ca FILE        TLS CA for mTLS
    -v, --verbose        Verbose logging

  Client options:
    --fingerprint FP      Server fingerprint to verify
    --auth USER:PASS      Authentication credential
    --keepalive DUR       Keepalive interval (default: 25s)
    --max-retry-count N   Max reconnection attempts (-1=infinite)
    --max-retry-interval DUR  Max time between retries (default: 5m)
    --proxy URL           Upstream HTTP/SOCKS5 proxy
    --header ""K: V""      Custom HTTP header (repeatable)
    --hostname HOST       HTTP host header to use
    --tls-skip-verify     Skip TLS certificate verification
    --tls-key FILE        mTLS client key
    --tls-cert FILE       mTLS client cert
    --tls-ca FILE         mTLS CA cert
    -v, --verbose         Verbose logging

  Remote specs:
    3000                    Forward server:3000 to client:3000
    example.com:3000        Forward example.com:3000 to client:3000
    3000:google.com:80      Forward google.com:80 via server to client:3000
    192.168.0.5:3000:g:80   Bind to specific local address
    R:2222:localhost:22     Reverse tunnel: server:2222 -> client:22
    socks                   Forward SOCKS5 proxy
    R:socks                 Reverse SOCKS5 proxy
    stdio:example.com:22    Pipe stdin/stdout to example.com:22
    1.1.1.1:53/udp          UDP tunnel
");
        }
    }
}
