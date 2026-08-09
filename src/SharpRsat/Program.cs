using System;
using SharpRsat.Recon;

namespace SharpRsat
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            CliOptions options;
            string parseError;
            if (CliOptions.Parse(args, out options, out parseError) != 0)
            {
                Console.Error.WriteLine(parseError);
                return 1;
            }

            string[] commandArgs = options.CommandArgs;

            if (commandArgs == null || commandArgs.Length == 0 || IsHelpFlag(commandArgs[0]))
            {
                WriteUsage(Console.Out, options.Quiet);
                return 0;
            }

            if (IsListRequest(commandArgs))
            {
                ReconCatalog.WriteList(Console.Out, options.Quiet);
                return 0;
            }

            string ensureError;
            if (!RsatFeatureInstaller.EnsureActiveDirectoryModule(
                    options.InstallRsat, options.Quiet, out ensureError))
            {
                Console.Error.WriteLine(ensureError);
                return 1;
            }

            string hostError;
            using (AdPowerShellHost host = AdPowerShellHost.Create(out hostError))
            {
                if (host == null)
                {
                    Console.Error.WriteLine(hostError ?? "Failed to create ActiveDirectory PowerShell host.");
                    return 1;
                }

                host.AllowWrite = options.AllowWrite;
                host.DelayMs = options.DelayMs;
                host.MaxResults = options.MaxResults;

                return Route(commandArgs, host, options.Quiet);
            }
        }

        private static int Route(string[] args, AdPowerShellHost host, bool quiet)
        {
            string first = args[0];

            if (string.Equals(first, "recon", StringComparison.OrdinalIgnoreCase))
            {
                if (args.Length < 2 || IsListToken(args[1]))
                {
                    ReconCatalog.WriteList(Console.Out, quiet);
                    return 0;
                }

                return ReconCatalog.Execute(args[1], host);
            }

            if (ReconCatalog.IsPreset(first))
            {
                return ReconCatalog.Execute(first, host);
            }

            if (!host.IsAllowedCmdlet(first))
            {
                Console.Error.WriteLine(
                    "Unknown command '{0}'. Use an ActiveDirectory cmdlet, a recon preset, or run 'recon list'.",
                    first);
                return 1;
            }

            if (!host.AllowWrite && !AdPowerShellHost.IsReadOnlyCmdlet(first))
            {
                Console.Error.WriteLine("Write operations require --allow-write.");
                return 1;
            }

            return host.InvokeCmdlet(args);
        }

        private static bool IsListRequest(string[] args)
        {
            if (args.Length == 1 && IsListToken(args[0]))
            {
                return true;
            }

            if (args.Length >= 1 &&
                string.Equals(args[0], "recon", StringComparison.OrdinalIgnoreCase))
            {
                if (args.Length == 1)
                {
                    return true;
                }

                if (args.Length == 2 && IsListToken(args[1]))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsListToken(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return false;
            }

            return string.Equals(token, "list", StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, "-list", StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, "--list", StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, "/list", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsHelpFlag(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return false;
            }

            return string.Equals(token, "-h", StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, "-?", StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, "/?", StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, "--help", StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, "-help", StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, "help", StringComparison.OrdinalIgnoreCase);
        }

        private static void WriteUsage(System.IO.TextWriter writer, bool quiet)
        {
            if (quiet)
            {
                writer.WriteLine("SharpRsat.exe <AD-Cmdlet|preset|recon> [args...]");
                writer.WriteLine("SharpRsat.exe -list");
                writer.WriteLine("Flags: --install-rsat --allow-write --quiet|-q --delay <ms> --max-results <n>");
                writer.WriteLine("Run -list for presets. Default: no RSAT install, read-only passthrough.");
                return;
            }

            writer.WriteLine("SharpRsat — Active Directory PowerShell passthrough and directory recon presets");
            writer.WriteLine();
            writer.WriteLine("Usage:");
            writer.WriteLine("  SharpRsat.exe <AD-Cmdlet> [arguments...]");
            writer.WriteLine("  SharpRsat.exe recon [list|<preset>]");
            writer.WriteLine("  SharpRsat.exe <preset>");
            writer.WriteLine("  SharpRsat.exe -list");
            writer.WriteLine();
            writer.WriteLine("Global flags (any position):");
            writer.WriteLine("  --install-rsat       Install RSAT AD PowerShell when the module is missing (elevated)");
            writer.WriteLine("  --allow-write        Allow non-read-only ActiveDirectory cmdlets");
            writer.WriteLine("  --quiet, -q          Short help/list; suppress install progress");
            writer.WriteLine("  --delay <ms>         Sleep before each PowerShell invoke (0-" + CliOptions.MaxDelayMs + ")");
            writer.WriteLine("  --max-results <n>    Cap objects written to stdout (0 = unlimited)");
            writer.WriteLine();
            writer.WriteLine("Examples (passthrough):");
            writer.WriteLine("  SharpRsat.exe Get-ADUser support");
            writer.WriteLine("  SharpRsat.exe Get-ADUser -Identity support -Properties *");
            writer.WriteLine("  SharpRsat.exe Get-ADGroupMember \"Domain Admins\"");
            writer.WriteLine("  SharpRsat.exe Get-ADGroupMember -Identity Domain Admins");
            writer.WriteLine("  SharpRsat.exe --allow-write Set-ADUser -Identity support -Description test");
            writer.WriteLine();
            writer.WriteLine("Examples (recon):");
            writer.WriteLine("  SharpRsat.exe recon list");
            writer.WriteLine("  SharpRsat.exe --quiet --delay 500 da");
            writer.WriteLine("  SharpRsat.exe recon kerberoast");
            writer.WriteLine("  SharpRsat.exe kerberoast");
            writer.WriteLine();
            writer.WriteLine("Notes:");
            writer.WriteLine("  - Only ActiveDirectory module commands are allowed for passthrough.");
            writer.WriteLine("  - Passthrough defaults to read-only (Get-/Search-/Measure-/Test-/Find-); use --allow-write for others.");
            writer.WriteLine("  - RSAT is not installed unless --install-rsat is set (requires elevation).");
            writer.WriteLine("  - Domain credentials / connectivity are required to query directory objects.");
            writer.WriteLine("  - Run 'recon list' or '-list' for all recon presets.");
        }
    }
}
