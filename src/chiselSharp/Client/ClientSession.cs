using System;

namespace ChiselSharp.Client
{
    /// <summary>
    /// Tracks client session state for reconnect purposes.
    /// </summary>
    public class ClientSession
    {
        public string SessionId { get; set; }
        public DateTime ConnectedAt { get; set; }
        public DateTime? DisconnectedAt { get; set; }
        public bool IsConnected { get; set; }
        public int ReconnectCount { get; set; }

        public ClientSession()
        {
            SessionId = Guid.NewGuid().ToString("N").Substring(0, 8);
            ConnectedAt = DateTime.UtcNow;
            IsConnected = true;
        }
    }
}
