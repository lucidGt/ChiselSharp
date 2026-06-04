using System;
using System.Collections.Generic;

namespace ChiselSharp.Settings
{
    public enum TunnelProtocol { TCP, UDP }

    public class Config
    {
        // Common
        public bool IsServer { get; set; }
        public bool IsClient { get; set; }
        public bool Verbose { get; set; }

        // Server options
        public int Port { get; set; }
        public string Host { get; set; }
        public string Key { get; set; }
        public string KeyFile { get; set; }
        public string Auth { get; set; }
        public string AuthFile { get; set; }
        public bool Socks5 { get; set; }
        public bool Reverse { get; set; }
        public TimeSpan Keepalive { get; set; }
        public string Backend { get; set; }
        public string TlsKey { get; set; }
        public string TlsCert { get; set; }
        public string TlsDomain { get; set; }
        public string TlsCA { get; set; }

        // Client options
        public string Fingerprint { get; set; }
        public int MaxRetryCount { get; set; }
        public TimeSpan MaxRetryInterval { get; set; }
        public string Proxy { get; set; }
        public Dictionary<string, string> Headers { get; set; }
        public bool TlsSkipVerify { get; set; }
        public string ServerUrl { get; set; }
        public List<string> Remotes { get; set; }

        public Config()
        {
            Port = 8080;
            Host = "0.0.0.0";
            Keepalive = TimeSpan.FromSeconds(25);
            MaxRetryCount = -1;
            MaxRetryInterval = TimeSpan.FromMinutes(5);
            Headers = new Dictionary<string, string>();
            Remotes = new List<string>();
        }
    }
}
