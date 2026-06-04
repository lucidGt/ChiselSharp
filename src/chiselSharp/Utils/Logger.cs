using System;

namespace ChiselSharp.Utils
{
    /// <summary>
    /// Simple console logger with chisel-style output.
    /// </summary>
    public static class Logger
    {
        public static bool Verbose { get; set; }

        public static void Info(string message)
        {
            Console.WriteLine(message);
        }

        public static void Debug(string message)
        {
            if (Verbose)
                Console.WriteLine("[DEBUG] " + message);
        }

        public static void Error(string message)
        {
            var fg = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine("[ERROR] " + message);
            Console.ForegroundColor = fg;
        }

        public static void Warn(string message)
        {
            var fg = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[WARN] " + message);
            Console.ForegroundColor = fg;
        }
    }
}
