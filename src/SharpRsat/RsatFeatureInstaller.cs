using System;
using System.Management.Automation;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace SharpRsat
{
    /// <summary>
    /// Detects the ActiveDirectory PowerShell module and optionally installs RSAT when missing.
    /// </summary>
    internal static class RsatFeatureInstaller
    {
        private const string AdModuleName = "ActiveDirectory";
        private const string ServerFeatureName = "RSAT-AD-PowerShell";
        private const string ClientCapabilityName = "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0";

        /// <summary>
        /// Ensures the ActiveDirectory module is available. Installs RSAT only when
        /// <paramref name="allowInstall"/> is true.
        /// </summary>
        /// <param name="allowInstall">When false, missing module fails with a hint to use --install-rsat.</param>
        /// <param name="quiet">When true, suppress install progress messages.</param>
        /// <param name="errorMessage">Human-readable failure reason when returning false.</param>
        /// <returns>True when the module is listable after ensure.</returns>
        public static bool EnsureActiveDirectoryModule(bool allowInstall, bool quiet, out string errorMessage)
        {
            errorMessage = null;

            if (IsActiveDirectoryModuleAvailable())
            {
                return true;
            }

            if (!allowInstall)
            {
                errorMessage =
                    "ActiveDirectory module not found. Install RSAT AD PowerShell tools, or re-run with --install-rsat (requires Administrator).";
                return false;
            }

            if (!IsElevated())
            {
                errorMessage =
                    "ActiveDirectory module not found. Run elevated (Administrator) with --install-rsat to install RSAT AD PowerShell tools.";
                return false;
            }

            string installationType = GetInstallationType();
            if (string.IsNullOrEmpty(installationType))
            {
                errorMessage =
                    "Unable to read HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\InstallationType; " +
                    "cannot choose Server vs Client RSAT install method.";
                return false;
            }

            bool isServer = IsServerInstallation(installationType);

            if (!quiet)
            {
                Console.Error.WriteLine(
                    "ActiveDirectory module not found. Installing RSAT AD PowerShell ({0}: {1})...",
                    isServer ? "Server feature" : "Client capability",
                    isServer ? ServerFeatureName : ClientCapabilityName);
            }

            string installError;
            if (!TryInstallRsat(isServer, out installError))
            {
                errorMessage = installError;
                return false;
            }

            if (!IsActiveDirectoryModuleAvailable())
            {
                errorMessage =
                    "RSAT install finished but ActiveDirectory module is still unavailable. " +
                    "A reboot may be required, or this OS edition may lack the feature/capability.";
                return false;
            }

            return true;
        }

        internal static bool IsActiveDirectoryModuleAvailable()
        {
            using (PowerShell ps = PowerShell.Create())
            {
                ps.AddCommand("Get-Module")
                    .AddParameter("ListAvailable", true)
                    .AddParameter("Name", AdModuleName);

                var results = ps.Invoke();
                if (ps.HadErrors)
                {
                    return false;
                }

                return results != null && results.Count > 0;
            }
        }

        private static bool TryInstallRsat(bool isServer, out string errorMessage)
        {
            errorMessage = null;

            using (PowerShell ps = PowerShell.Create())
            {
                if (isServer)
                {
                    ps.AddCommand("Install-WindowsFeature")
                        .AddParameter("Name", ServerFeatureName);
                }
                else
                {
                    ps.AddCommand("Add-WindowsCapability")
                        .AddParameter("Online", true)
                        .AddParameter("Name", ClientCapabilityName);
                }

                try
                {
                    ps.Invoke();
                }
                catch (Exception ex)
                {
                    errorMessage = FormatInstallFailure(isServer, ex.Message, null);
                    return false;
                }

                if (ps.HadErrors)
                {
                    errorMessage = FormatInstallFailure(isServer, null, CollectErrors(ps));
                    return false;
                }

                return true;
            }
        }

        private static string FormatInstallFailure(bool isServer, string exceptionMessage, string streamErrors)
        {
            var sb = new StringBuilder();
            sb.Append("Failed to install RSAT AD PowerShell. ");

            if (!string.IsNullOrEmpty(exceptionMessage))
            {
                sb.Append(exceptionMessage);
                sb.Append(' ');
            }

            if (!string.IsNullOrEmpty(streamErrors))
            {
                sb.Append(streamErrors);
                sb.Append(' ');
            }

            if (isServer)
            {
                sb.Append("Verify Server Manager / Install-WindowsFeature is available and the feature name ")
                    .Append(ServerFeatureName)
                    .Append(" exists on this SKU. Elevated rights are required.");
            }
            else
            {
                sb.Append("Verify Add-WindowsCapability can reach Windows Update / FODs for ")
                    .Append(ClientCapabilityName)
                    .Append(". Elevated rights and a supported client edition are required.");
            }

            return sb.ToString().Trim();
        }

        private static string CollectErrors(PowerShell ps)
        {
            if (ps.Streams.Error == null || ps.Streams.Error.Count == 0)
            {
                return null;
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

        private static bool IsElevated()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static string GetInstallationType()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                if (key == null)
                {
                    return null;
                }

                return key.GetValue("InstallationType") as string;
            }
        }

        private static bool IsServerInstallation(string installationType)
        {
            return installationType.StartsWith("Server", StringComparison.OrdinalIgnoreCase);
        }
    }
}
