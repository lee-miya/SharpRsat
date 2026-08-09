using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading;

namespace SharpRsat
{
    /// <summary>
    /// In-process Windows PowerShell host for ActiveDirectory cmdlets and recon scripts.
    /// </summary>
    internal sealed class AdPowerShellHost : IDisposable
    {
        private const string AdModuleName = "ActiveDirectory";
        private const int OutStringWidth = 4096;

        private readonly Runspace _runspace;
        private readonly HashSet<string> _allowedCommands;
        private bool _disposed;

        private AdPowerShellHost(Runspace runspace, HashSet<string> allowedCommands)
        {
            _runspace = runspace;
            _allowedCommands = allowedCommands;
        }

        /// <summary>When false, non-read-only AD cmdlets are rejected.</summary>
        public bool AllowWrite { get; set; }

        /// <summary>Milliseconds to sleep before each PowerShell invoke (0 = none).</summary>
        public int DelayMs { get; set; }

        /// <summary>Max objects written to stdout (0 = unlimited).</summary>
        public int MaxResults { get; set; }

        /// <summary>
        /// Opens a runspace, imports ActiveDirectory, and builds the exported-command whitelist.
        /// </summary>
        public static AdPowerShellHost Create(out string errorMessage)
        {
            errorMessage = null;
            Runspace runspace = null;

            try
            {
                runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();

                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = runspace;
                    ps.AddCommand("Import-Module")
                        .AddParameter("Name", AdModuleName)
                        .AddParameter("ErrorAction", ActionPreference.Stop);

                    ps.Invoke();
                    if (ps.HadErrors)
                    {
                        errorMessage = "Failed to Import-Module " + AdModuleName + ": " + CollectErrors(ps);
                        runspace.Dispose();
                        return null;
                    }

                    ps.Commands.Clear();
                    ps.Streams.ClearStreams();

                    ps.AddCommand("Get-Module").AddParameter("Name", AdModuleName);
                    var modules = ps.Invoke();
                    if (ps.HadErrors || modules == null || modules.Count == 0)
                    {
                        errorMessage = "ActiveDirectory module is not loaded after Import-Module.";
                        runspace.Dispose();
                        return null;
                    }

                    HashSet<string> allowed = BuildWhitelist(modules[0]);
                    if (allowed.Count == 0)
                    {
                        errorMessage = "ActiveDirectory module has no ExportedCommands.";
                        runspace.Dispose();
                        return null;
                    }

                    return new AdPowerShellHost(runspace, allowed);
                }
            }
            catch (Exception ex)
            {
                if (runspace != null)
                {
                    runspace.Dispose();
                }

                errorMessage = "Failed to initialize ActiveDirectory PowerShell host: " + ex.Message;
                return null;
            }
        }

        /// <summary>
        /// True when <paramref name="commandName"/> is an ActiveDirectory exported command.
        /// </summary>
        public bool IsAllowedCmdlet(string commandName)
        {
            EnsureNotDisposed();
            if (string.IsNullOrWhiteSpace(commandName))
            {
                return false;
            }

            return _allowedCommands.Contains(commandName);
        }

        /// <summary>
        /// True for read-oriented AD cmdlets (Get-/Search-/Measure-/Test-/Find- prefixes
        /// or known read-only names such as Sync-ADObject).
        /// </summary>
        public static bool IsReadOnlyCmdlet(string commandName)
        {
            if (string.IsNullOrWhiteSpace(commandName))
            {
                return false;
            }

            if (StartsWithOrdinalIgnoreCase(commandName, "Get-")
                || StartsWithOrdinalIgnoreCase(commandName, "Search-")
                || StartsWithOrdinalIgnoreCase(commandName, "Measure-")
                || StartsWithOrdinalIgnoreCase(commandName, "Test-")
                || StartsWithOrdinalIgnoreCase(commandName, "Find-"))
            {
                return true;
            }

            return string.Equals(commandName, "Sync-ADObject", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Invokes an AD module cmdlet. <paramref name="args"/>[0] is the cmdlet name;
        /// remaining tokens are named (-Name value / -Switch) or positional arguments.
        /// Writes formatted results to stdout and errors to stderr.
        /// </summary>
        /// <returns>0 on success; non-zero on rejection or cmdlet error.</returns>
        public int InvokeCmdlet(string[] args)
        {
            EnsureNotDisposed();

            if (args == null || args.Length == 0 || string.IsNullOrWhiteSpace(args[0]))
            {
                Console.Error.WriteLine("Cmdlet name is required.");
                return 1;
            }

            string cmdletName = args[0];
            if (!IsAllowedCmdlet(cmdletName))
            {
                Console.Error.WriteLine(
                    "Command '{0}' is not an ActiveDirectory module command and is not allowed.",
                    cmdletName);
                return 1;
            }

            if (!AllowWrite && !IsReadOnlyCmdlet(cmdletName))
            {
                Console.Error.WriteLine("Write operations require --allow-write.");
                return 1;
            }

            using (PowerShell ps = PowerShell.Create())
            {
                ps.Runspace = _runspace;
                ps.AddCommand(cmdletName);

                try
                {
                    ApplyArguments(ps, args, 1);
                }
                catch (ArgumentException ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    return 1;
                }

                return InvokeAndWrite(ps);
            }
        }

        /// <summary>
        /// Invokes a script in the same runspace (ActiveDirectory already imported).
        /// Used by recon presets.
        /// </summary>
        public int InvokeScript(string script)
        {
            EnsureNotDisposed();

            if (string.IsNullOrWhiteSpace(script))
            {
                Console.Error.WriteLine("Script is required.");
                return 1;
            }

            using (PowerShell ps = PowerShell.Create())
            {
                ps.Runspace = _runspace;
                ps.AddScript(script);
                return InvokeAndWrite(ps);
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_runspace != null)
            {
                _runspace.Dispose();
            }
        }

        private int InvokeAndWrite(PowerShell ps)
        {
            ApplyDelay();

            try
            {
                var results = ps.Invoke();
                WriteErrors(ps);

                var objects = new List<PSObject>();
                if (results != null)
                {
                    foreach (PSObject result in results)
                    {
                        if (result != null)
                        {
                            objects.Add(result);
                        }
                    }
                }

                if (MaxResults > 0 && objects.Count > MaxResults)
                {
                    Console.Error.WriteLine(
                        "Result truncated to {0} object(s); pass --max-results 0 for unlimited.",
                        MaxResults);
                    objects.RemoveRange(MaxResults, objects.Count - MaxResults);
                }

                if (objects.Count > 0)
                {
                    WriteFormatted(objects);
                }

                return ps.HadErrors ? 1 : 0;
            }
            catch (Exception ex)
            {
                WriteErrors(ps);
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        }

        private void ApplyDelay()
        {
            if (DelayMs > 0)
            {
                Thread.Sleep(DelayMs);
            }
        }

        private void WriteFormatted(IList<PSObject> objects)
        {
            using (PowerShell format = PowerShell.Create())
            {
                format.Runspace = _runspace;
                format.AddCommand("Out-String").AddParameter("Width", OutStringWidth);
                var formatted = format.Invoke(objects);
                if (formatted == null)
                {
                    return;
                }

                foreach (PSObject result in formatted)
                {
                    if (result == null)
                    {
                        continue;
                    }

                    string text = result.ToString();
                    if (!string.IsNullOrEmpty(text))
                    {
                        Console.Write(text);
                        if (!text.EndsWith("\n", StringComparison.Ordinal) &&
                            !text.EndsWith("\r", StringComparison.Ordinal))
                        {
                            Console.WriteLine();
                        }
                    }
                }
            }
        }

        private static bool StartsWithOrdinalIgnoreCase(string value, string prefix)
        {
            return value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Binds CLI tokens to the cmdlet. Consecutive non-named tokens are joined with a
        /// single space so values like Domain Admins still work when an upstream loader
        /// (e.g. Sliver execute-assembly) splits on spaces and drops quotes.
        /// </summary>
        private static void ApplyArguments(PowerShell ps, string[] args, int startIndex)
        {
            int i = startIndex;
            while (i < args.Length)
            {
                string token = args[i];
                if (IsNamedParameter(token))
                {
                    string name = token.TrimStart('-');
                    if (string.IsNullOrEmpty(name))
                    {
                        throw new ArgumentException("Invalid parameter token: " + token);
                    }

                    i++;
                    string value;
                    int consumed = TakeJoinedValue(args, i, out value);
                    if (consumed == 0)
                    {
                        ps.AddParameter(name, true);
                    }
                    else
                    {
                        ps.AddParameter(name, value);
                        i += consumed;
                    }
                }
                else
                {
                    string value;
                    int consumed = TakeJoinedValue(args, i, out value);
                    if (consumed == 0)
                    {
                        throw new ArgumentException("Unexpected empty argument at index " + i + ".");
                    }

                    ps.AddArgument(value);
                    i += consumed;
                }
            }
        }

        /// <summary>
        /// Joins consecutive non-named tokens from <paramref name="startIndex"/> with spaces.
        /// Returns how many tokens were consumed (0 if none / next token is named).
        /// </summary>
        private static int TakeJoinedValue(string[] args, int startIndex, out string value)
        {
            value = null;
            if (startIndex >= args.Length || IsNamedParameter(args[startIndex]))
            {
                return 0;
            }

            var parts = new List<string>();
            int i = startIndex;
            while (i < args.Length && !IsNamedParameter(args[i]))
            {
                parts.Add(StripWrappingQuotes(args[i]));
                i++;
            }

            value = string.Join(" ", parts.ToArray());
            return parts.Count;
        }

        private static string StripWrappingQuotes(string token)
        {
            if (string.IsNullOrEmpty(token) || token.Length < 2)
            {
                return token;
            }

            char first = token[0];
            char last = token[token.Length - 1];
            if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
            {
                return token.Substring(1, token.Length - 2);
            }

            return token;
        }

        private static bool IsNamedParameter(string token)
        {
            if (string.IsNullOrEmpty(token)
                || token[0] != '-'
                || token.Length <= 1
                || char.IsDigit(token[1]))
            {
                return false;
            }

            // PowerShell comparison/logical operators inside -Filter values (e.g. Name -eq foo)
            // must not be treated as cmdlet parameter names when quotes were stripped upstream.
            string name = token.TrimStart('-');
            return !IsPowerShellOperatorName(name);
        }

        private static bool IsPowerShellOperatorName(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return false;
            }

            return string.Equals(name, "eq", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "ne", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "gt", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "ge", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "lt", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "le", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "like", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "notlike", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "match", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "notmatch", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "contains", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "notcontains", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "in", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "notin", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "and", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "or", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "not", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "xor", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "bor", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "band", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "bnot", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "is", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "isnot", StringComparison.OrdinalIgnoreCase);
        }

        private static HashSet<string> BuildWhitelist(PSObject module)
        {
            var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (module == null)
            {
                return allowed;
            }

            PSPropertyInfo prop = module.Properties["ExportedCommands"];
            if (prop == null || prop.Value == null)
            {
                return allowed;
            }

            IDictionary commands = prop.Value as IDictionary;
            if (commands != null)
            {
                foreach (object key in commands.Keys)
                {
                    if (key != null)
                    {
                        allowed.Add(key.ToString());
                    }
                }

                return allowed;
            }

            // Fallback: enumerate via PSObject base if typed as CommandCollection-like.
            var enumerable = prop.Value as IEnumerable;
            if (enumerable != null && !(prop.Value is string))
            {
                foreach (object entry in enumerable)
                {
                    if (entry == null)
                    {
                        continue;
                    }

                    var entryObj = entry as PSObject ?? PSObject.AsPSObject(entry);
                    PSPropertyInfo keyProp = entryObj.Properties["Key"];
                    if (keyProp != null && keyProp.Value != null)
                    {
                        allowed.Add(keyProp.Value.ToString());
                        continue;
                    }

                    PSPropertyInfo nameProp = entryObj.Properties["Name"];
                    if (nameProp != null && nameProp.Value != null)
                    {
                        allowed.Add(nameProp.Value.ToString());
                    }
                }
            }

            return allowed;
        }

        private static void WriteErrors(PowerShell ps)
        {
            if (ps.Streams.Error == null)
            {
                return;
            }

            foreach (ErrorRecord record in ps.Streams.Error)
            {
                Console.Error.WriteLine(record.ToString());
            }
        }

        private static string CollectErrors(PowerShell ps)
        {
            if (ps.Streams.Error == null || ps.Streams.Error.Count == 0)
            {
                return "(no error records)";
            }

            var sb = new StringBuilder();
            foreach (ErrorRecord record in ps.Streams.Error)
            {
                if (sb.Length > 0)
                {
                    sb.Append("; ");
                }

                sb.Append(record.ToString());
            }

            return sb.ToString();
        }

        private void EnsureNotDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("AdPowerShellHost");
            }
        }
    }
}
