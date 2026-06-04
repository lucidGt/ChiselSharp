using System;

namespace ChiselSharp.Utils
{
    public static class PortAllocator
    {
        public static int AllocatePort(int preferred = 0)
        {
            if (preferred > 0)
                return preferred;
            // Return a random high port
            return new Random().Next(30000, 60000);
        }
    }
}
