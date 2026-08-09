using System;
using SharpRsat.Recon;

namespace SharpRsat
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args == null || args.Length == 0 || IsHelpFlag(args[0]))
            {
                WriteUsage(Console.Out);
                return 0;
            }

            if (IsListRequest(args))
            {
                ReconCatalog.WriteList(Console.Out);
                return 0;
            }

            string ensureError;
            if (!RsatFeatureInstaller.EnsureActiveDirectoryModule(out ensureError))
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

                return Route(args, host);
            }
        }

        private static int Route(string[] args, AdPowerShellHost host)
        {
            string first = args[0];

            if (string.Equals(first, "recon", StringComparison.OrdinalIgnoreCase))
            {
                if (args.Length < 2 || IsListToken(args[1]))
                {
                    ReconCatalog.WriteList(Console.Out);
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

        private static void WriteUsage(System.IO.TextWriter writer)
        {
            writer.WriteLine("SharpRsat — Active Directory PowerShell passthrough and recon presets");
            writer.WriteLine();
            writer.WriteLine("Usage:");
            writer.WriteLine("  SharpRsat.exe <AD-Cmdlet> [arguments...]");
            writer.WriteLine("  SharpRsat.exe recon [list|<preset>]");
            writer.WriteLine("  SharpRsat.exe <preset>");
            writer.WriteLine("  SharpRsat.exe -list");
            writer.WriteLine();
            writer.WriteLine("Examples (passthrough):");
            writer.WriteLine("  SharpRsat.exe Get-ADUser support");
            writer.WriteLine("  SharpRsat.exe Get-ADUser -Identity support -Properties *");
            writer.WriteLine("  SharpRsat.exe Get-ADGroupMember \"Domain Admins\"");
            writer.WriteLine("  SharpRsat.exe Get-ADGroupMember -Identity Domain Admins");
            writer.WriteLine();
            writer.WriteLine("Examples (recon):");
            writer.WriteLine("  SharpRsat.exe recon list");
            writer.WriteLine("  SharpRsat.exe recon kerberoast");
            writer.WriteLine("  SharpRsat.exe kerberoast");
            writer.WriteLine("  SharpRsat.exe da");
            writer.WriteLine();
            writer.WriteLine("Notes:");
            writer.WriteLine("  - Only ActiveDirectory module commands are allowed for passthrough.");
            writer.WriteLine("  - RSAT AD PowerShell is installed automatically when missing (requires elevation).");
            writer.WriteLine("  - Domain credentials / connectivity are required to query directory objects.");
            writer.WriteLine("  - Run 'recon list' or '-list' for all recon presets.");
        }
    }
}
