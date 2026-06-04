using System;

namespace ChiselSharp.Settings
{
    /// <summary>
    /// Parses chisel remote specification strings into a RemoteSpec object.
    /// </summary>
    public static class RemoteParser
    {
        /// <summary>
        /// Parse a chisel remote string into a RemoteSpec.
        /// Returns null on invalid input.
        /// </summary>
        public static RemoteSpec Parse(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return null;

            var spec = new RemoteSpec();
            string remainder = raw.Trim();

            // 1. Check for "R:" prefix -> reverse tunnel
            if (remainder.StartsWith("R:", StringComparison.Ordinal))
            {
                spec.IsReverse = true;
                remainder = remainder.Substring(2);
            }

            // 2. Check for "stdio:" prefix -> stdio tunnel
            if (remainder.StartsWith("stdio:", StringComparison.Ordinal))
            {
                spec.IsStdio = true;
                string stdioPart = remainder.Substring(6);

                // Parse host:port from the remainder
                string[] stdioParts = stdioPart.Split(':');
                if (stdioParts.Length != 2)
                    return null;

                spec.RemoteHost = stdioParts[0];
                int port;
                if (!int.TryParse(stdioParts[1], out port) || port < 0 || port > 65535)
                    return null;
                spec.RemotePort = port;
                return spec;
            }

            // 3. Check for protocol suffix "/udp" or "/tcp"
            if (remainder.EndsWith("/udp", StringComparison.OrdinalIgnoreCase))
            {
                spec.Protocol = TunnelProtocol.UDP;
                remainder = remainder.Substring(0, remainder.Length - 4);
            }
            else if (remainder.EndsWith("/tcp", StringComparison.OrdinalIgnoreCase))
            {
                spec.Protocol = TunnelProtocol.TCP;
                remainder = remainder.Substring(0, remainder.Length - 4);
            }

            // 4. Check for "socks" keyword
            int socksIndex = remainder.IndexOf(":socks", StringComparison.Ordinal);
            if (socksIndex >= 0)
            {
                spec.IsSocks = true;
                string beforeSocks = remainder.Substring(0, socksIndex);

                if (beforeSocks.Length > 0)
                {
                    string[] socksParts = beforeSocks.Split(':');
                    if (socksParts.Length == 1)
                    {
                        int socksPort;
                        if (!int.TryParse(socksParts[0], out socksPort) || socksPort < 0 || socksPort > 65535)
                            return null;
                        spec.LocalPort = socksPort;
                    }
                    else if (socksParts.Length == 2)
                    {
                        int socksPort;
                        if (!int.TryParse(socksParts[1], out socksPort) || socksPort < 0 || socksPort > 65535)
                            return null;
                        spec.LocalHost = socksParts[0];
                        spec.LocalPort = socksPort;
                    }
                    else
                    {
                        return null;
                    }
                }

                ApplySocksDefaults(spec);
                return spec;
            }

            // Also handle bare "socks" without colon prefix
            if (remainder.Equals("socks", StringComparison.Ordinal))
            {
                spec.IsSocks = true;
                ApplySocksDefaults(spec);
                return spec;
            }

            // 5. Split on ":" for regular tunnel specifications
            string[] segments = remainder.Split(':');

            // 1 segment: just a port
            //   Examples: "3000" -> localhost:3000 -> client:3000
            if (segments.Length == 1)
            {
                int singlePort;
                if (!int.TryParse(segments[0], out singlePort) || singlePort < 0 || singlePort > 65535)
                    return null;
                spec.LocalPort = singlePort;
                spec.RemotePort = singlePort;
                spec.RemoteHost = "127.0.0.1";
                return spec;
            }

            // 2 segments: host:port
            //   Examples: "example.com:3000" -> forward example.com:3000 to client:3000
            if (segments.Length == 2)
            {
                string host = segments[0];
                int port;
                if (!int.TryParse(segments[1], out port) || port < 0 || port > 65535)
                    return null;
                spec.RemoteHost = host;
                spec.RemotePort = port;
                spec.LocalPort = port;
                return spec;
            }

            // 3 segments: port:host:port
            //   Examples: "3000:google.com:80" -> forward google.com:80 to client:3000
            if (segments.Length == 3)
            {
                int localPort;
                if (!int.TryParse(segments[0], out localPort) || localPort < 0 || localPort > 65535)
                    return null;
                string remoteHost = segments[1];
                int remotePort;
                if (!int.TryParse(segments[2], out remotePort) || remotePort < 0 || remotePort > 65535)
                    return null;
                spec.LocalPort = localPort;
                spec.RemoteHost = remoteHost;
                spec.RemotePort = remotePort;
                return spec;
            }

            // 4 segments: host:port:host:port
            //   Examples: "192.168.0.5:3000:google.com:80"
            if (segments.Length == 4)
            {
                string localHost = segments[0];
                int localPort;
                if (!int.TryParse(segments[1], out localPort) || localPort < 0 || localPort > 65535)
                    return null;
                string remoteHost = segments[2];
                int remotePort;
                if (!int.TryParse(segments[3], out remotePort) || remotePort < 0 || remotePort > 65535)
                    return null;
                spec.LocalHost = localHost;
                spec.LocalPort = localPort;
                spec.RemoteHost = remoteHost;
                spec.RemotePort = remotePort;
                return spec;
            }

            // More than 4 segments is invalid
            return null;
        }

        private static void ApplySocksDefaults(RemoteSpec spec)
        {
            if (string.IsNullOrEmpty(spec.LocalHost) || spec.LocalHost == "0.0.0.0")
                spec.LocalHost = "127.0.0.1";
            if (spec.LocalPort <= 0)
                spec.LocalPort = 1080;
        }
    }
}
