using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;

namespace ChiselSharp.Utils
{
    /// <summary>
    /// Minimal JSON helper using built-in .NET JavaScriptSerializer.
    /// Provides simple Parse/Serialize for the JSON structures used in chiselSharp.
    ///
    /// Type mapping:
    ///   JSON object -> Dictionary&lt;string, object&gt;
    ///   JSON array  -> ArrayList
    ///   JSON string -> string
    ///   JSON number -> int or double
    ///   JSON bool   -> bool
    ///   JSON null   -> null
    /// </summary>
    public static class Json
    {
        private static readonly JavaScriptSerializer Serializer = new JavaScriptSerializer();

        /// <summary>
        /// Create a new JSON object (Dictionary).
        /// </summary>
        public static Dictionary<string, object> NewObject()
        {
            return new Dictionary<string, object>(StringComparer.Ordinal);
        }

        /// <summary>
        /// Create a new JSON array (ArrayList).
        /// </summary>
        public static ArrayList NewArray()
        {
            return new ArrayList();
        }

        /// <summary>
        /// Create a JSON array from a list of strings.
        /// </summary>
        public static ArrayList NewArray(IEnumerable<string> items)
        {
            var arr = new ArrayList();
            foreach (var item in items)
                arr.Add(item);
            return arr;
        }

        /// <summary>
        /// Parse a JSON string to a Dictionary.
        /// </summary>
        public static Dictionary<string, object> Parse(string json)
        {
            try
            {
                return Serializer.Deserialize<Dictionary<string, object>>(json);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Deserialize JSON to a specific type.
        /// </summary>
        public static T Deserialize<T>(string json)
        {
            try
            {
                return Serializer.Deserialize<T>(json);
            }
            catch
            {
                return default(T);
            }
        }

        /// <summary>
        /// Serialize an object to JSON string.
        /// </summary>
        public static string Serialize(object obj)
        {
            return Serializer.Serialize(obj);
        }

        /// <summary>
        /// Get a string value from a JSON dictionary, safely.
        /// </summary>
        public static string GetString(Dictionary<string, object> obj, string key)
        {
            if (obj == null) return null;
            object val;
            obj.TryGetValue(key, out val);
            return val != null ? val.ToString() : null;
        }

        /// <summary>
        /// Get an int value from a JSON dictionary, safely.
        /// </summary>
        public static int GetInt(Dictionary<string, object> obj, string key, int defaultValue = 0)
        {
            if (obj == null) return defaultValue;
            object val;
            obj.TryGetValue(key, out val);
            if (val is int) return (int)val;
            if (val is double) return (int)(double)val;
            int parsedValue;
            if (val != null && int.TryParse(val.ToString(), out parsedValue)) return parsedValue;
            return defaultValue;
        }

        /// <summary>
        /// Get a list from a JSON dictionary, safely.
        /// </summary>
        public static ArrayList GetArray(Dictionary<string, object> obj, string key)
        {
            if (obj == null) return null;
            object val;
            obj.TryGetValue(key, out val);
            return val as ArrayList;
        }

        /// <summary>
        /// Convert Dictionary to JSON bytes.
        /// </summary>
        public static byte[] ToBytes(Dictionary<string, object> obj)
        {
            return Encoding.UTF8.GetBytes(Serialize(obj));
        }

        /// <summary>
        /// Parse JSON bytes to Dictionary.
        /// </summary>
        public static Dictionary<string, object> FromBytes(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return null;
            return Parse(Encoding.UTF8.GetString(bytes));
        }
    }
}
