using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using ChiselSharp.Utils;

namespace ChiselSharp.Settings
{
    /// <summary>
    /// Parses and validates chisel users.json authentication files.
    /// Supports auto-reload via FileSystemWatcher.
    /// </summary>
    public class AuthFile : IDisposable
    {
        private readonly object _lock = new object();
        private Dictionary<string, AuthEntry> _entries;
        private FileSystemWatcher _watcher;
        private string _filePath;
        private bool _disposed;

        /// <summary>
        /// An individual auth entry containing the password and allowed remote patterns.
        /// </summary>
        private class AuthEntry
        {
            public string Password { get; set; }
            public List<Regex> Patterns { get; set; }
        }

        /// <summary>
        /// Fired when the auth file is reloaded due to a file change.
        /// </summary>
        public event EventHandler Reloaded;

        /// <summary>
        /// Fired when the auth file fails to reload.
        /// </summary>
        public event EventHandler<UnhandledExceptionEventArgs> ReloadError;

        /// <summary>
        /// Path to the currently loaded auth file.
        /// </summary>
        public string FilePath
        {
            get { return _filePath; }
        }

        /// <summary>
        /// Load an auth file from the specified path.
        /// </summary>
        /// <param name="path">Path to users.json file.</param>
        /// <param name="watch">If true, watch the file for changes and auto-reload.</param>
        public static AuthFile Load(string path, bool watch = true)
        {
            var authFile = new AuthFile();
            authFile.LoadFromFile(path);
            if (watch)
                authFile.StartWatching(path);
            return authFile;
        }

        /// <summary>
        /// Load auth entries from a JSON string (for testing).
        /// </summary>
        public static AuthFile FromJson(string json)
        {
            var authFile = new AuthFile();
            authFile.ParseEntries(json);
            return authFile;
        }

        private AuthFile()
        {
            _entries = new Dictionary<string, AuthEntry>(StringComparer.Ordinal);
        }

        private void LoadFromFile(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException("Auth file not found.", path);

            _filePath = Path.GetFullPath(path);
            string json = File.ReadAllText(_filePath);
            ParseEntries(json);
        }

        private void ParseEntries(string json)
        {
            var raw = Json.Deserialize<Dictionary<string, List<string>>>(json);
            if (raw == null)
            {
                lock (_lock)
                {
                    _entries = new Dictionary<string, AuthEntry>(StringComparer.Ordinal);
                }
                return;
            }

            var parsed = new Dictionary<string, AuthEntry>(StringComparer.Ordinal);

            foreach (var kvp in raw)
            {
                string userPass = kvp.Key;
                List<string> patternStrings = kvp.Value ?? new List<string>();

                // Split "user:password" - only split on the first colon
                int colonIndex = userPass.IndexOf(':');
                if (colonIndex < 0)
                    continue; // invalid entry, skip

                string password = userPass.Substring(colonIndex + 1);

                var regexes = new List<Regex>();
                foreach (string pattern in patternStrings)
                {
                    try
                    {
                        regexes.Add(new Regex(pattern, RegexOptions.Compiled));
                    }
                    catch (ArgumentException)
                    {
                        // Skip invalid regex patterns
                    }
                }

                parsed[userPass] = new AuthEntry
                {
                    Password = password,
                    Patterns = regexes
                };
            }

            lock (_lock)
            {
                _entries = parsed;
            }
        }

        private void StartWatching(string path)
        {
            string directory = Path.GetDirectoryName(path);
            string fileName = Path.GetFileName(path);

            if (string.IsNullOrEmpty(directory))
                directory = ".";

            _watcher = new FileSystemWatcher
            {
                Path = Path.GetFullPath(directory),
                Filter = fileName,
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                EnableRaisingEvents = false
            };

            _watcher.Changed += OnFileChanged;
            _watcher.Created += OnFileChanged;
            _watcher.Deleted += OnFileChanged;
            _watcher.Error += OnWatcherError;

            // Debounce: wait 500ms after last change before reloading
            _watcher.EnableRaisingEvents = true;
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            // FileSystemWatcher fires multiple events for a single save.
            // Use a simple debounce: if the file doesn't exist or isn't ready, skip.
            try
            {
                // Attempt to reload
                string json;
                lock (_lock)
                {
                    json = File.ReadAllText(_filePath);
                }
                ParseEntries(json);

                var handler = Reloaded;
                if (handler != null)
                    handler(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                var handler = ReloadError;
                if (handler != null)
                    handler(this, new UnhandledExceptionEventArgs(ex, false));
            }
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            var handler = ReloadError;
            if (handler != null)
                handler(this, new UnhandledExceptionEventArgs(e.GetException(), false));
        }

        /// <summary>
        /// Validate only the user/password combination (no remote check).
        /// </summary>
        public bool ValidateUser(string user, string password)
        {
            if (string.IsNullOrEmpty(user))
                return false;

            string userPassKey = user + ":" + password;

            lock (_lock)
            {
                return _entries.ContainsKey(userPassKey);
            }
        }

        /// <summary>
        /// Validate a user/password combination and remote specification.
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="password">The password.</param>
        /// <param name="remote">The remote specification to validate against. If null, only checks user/pass.</param>
        /// <returns>True if the user is authenticated and authorized for this remote.</returns>
        public bool Validate(string user, string password, RemoteSpec remote)
        {
            if (string.IsNullOrEmpty(user))
                return false;

            string userPassKey = user + ":" + password;

            AuthEntry entry;
            lock (_lock)
            {
                if (!_entries.TryGetValue(userPassKey, out entry))
                    return false;
            }

            // Build the address string to check against patterns
            string address;
            if (remote == null)
            {
                address = null;
            }
            else if (remote.IsReverse)
            {
                // Reverse tunnels check "R:localHost:localPort"
                address = "R:" + remote.LocalHost + ":" + remote.LocalPort;
            }
            else
            {
                // Forward tunnels check "remoteHost:remotePort"
                address = remote.RemoteHost + ":" + remote.RemotePort;
            }

            // If there are no patterns, anything is allowed (as long as user/pass match)
            if (entry.Patterns.Count == 0)
                return true;

            // If no address built, but patterns exist, reject
            if (address == null)
                return false;

            // Check if the address matches any of the allowed patterns
            return entry.Patterns.Any(p => p.IsMatch(address));
        }

        /// <summary>
        /// Force a reload of the auth file.
        /// </summary>
        public void Reload()
        {
            if (_filePath != null)
                LoadFromFile(_filePath);
        }

        /// <summary>
        /// Returns the number of loaded auth entries.
        /// </summary>
        public int EntryCount
        {
            get
            {
                lock (_lock)
                {
                    return _entries.Count;
                }
            }
        }

        /// <summary>
        /// Returns the list of usernames currently loaded.
        /// </summary>
        public IEnumerable<string> Users
        {
            get
            {
                lock (_lock)
                {
                    // Extract just the username part before the colon
                    return _entries.Keys.Select(k => k.Split(':')[0]).Distinct().ToList();
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_watcher != null)
                {
                    _watcher.EnableRaisingEvents = false;
                    _watcher.Changed -= OnFileChanged;
                    _watcher.Created -= OnFileChanged;
                    _watcher.Deleted -= OnFileChanged;
                    _watcher.Error -= OnWatcherError;
                    _watcher.Dispose();
                    _watcher = null;
                }
            }

            _disposed = true;
        }
    }
}
