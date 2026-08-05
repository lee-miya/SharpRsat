using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

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
            ps.AddCommand("Out-String").AddParameter("Width", OutStringWidth);

            try
            {
                var results = ps.Invoke();
                WriteErrors(ps);

                if (results != null)
                {
                    foreach (PSObject result in results)
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

                return ps.HadErrors ? 1 : 0;
            }
            catch (Exception ex)
            {
                WriteErrors(ps);
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        }

        private static void ApplyArguments(PowerShell ps, string[] args, int startIndex)
        {
            for (int i = startIndex; i < args.Length; i++)
            {
                string token = args[i];
                if (IsNamedParameter(token))
                {
                    string name = token.TrimStart('-');
                    if (string.IsNullOrEmpty(name))
                    {
                        throw new ArgumentException("Invalid parameter token: " + token);
                    }

                    if (i + 1 < args.Length && !IsNamedParameter(args[i + 1]))
                    {
                        ps.AddParameter(name, args[i + 1]);
                        i++;
                    }
                    else
                    {
                        ps.AddParameter(name, true);
                    }
                }
                else
                {
                    ps.AddArgument(token);
                }
            }
        }

        private static bool IsNamedParameter(string token)
        {
            return !string.IsNullOrEmpty(token)
                && token[0] == '-'
                && token.Length > 1
                && !char.IsDigit(token[1]);
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
