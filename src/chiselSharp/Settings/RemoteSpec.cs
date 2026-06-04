namespace ChiselSharp.Settings
{
    public class RemoteSpec
    {
        public bool IsReverse { get; set; }
        public string LocalHost { get; set; }
        public int LocalPort { get; set; }
        public string RemoteHost { get; set; }
        public int RemotePort { get; set; }
        public TunnelProtocol Protocol { get; set; }
        public bool IsSocks { get; set; }
        public bool IsStdio { get; set; }

        public RemoteSpec()
        {
            LocalHost = "0.0.0.0";
            RemoteHost = "127.0.0.1";
            Protocol = TunnelProtocol.TCP;
        }

        public override string ToString()
        {
            string prefix = IsReverse ? "R:" : "";
            string proto = Protocol == TunnelProtocol.UDP ? "/udp" : "";
            if (IsSocks)
                return string.Format("{0}{1}:socks", prefix, LocalPort);
            if (IsStdio)
                return string.Format("stdio:{0}:{1}", RemoteHost, RemotePort);
            if (LocalPort > 0)
                return string.Format("{0}{1}:{2}:{3}:{4}{5}", prefix, LocalHost, LocalPort, RemoteHost, RemotePort, proto);
            return string.Format("{0}{1}:{2}{3}", prefix, RemoteHost, RemotePort, proto);
        }
    }
}
