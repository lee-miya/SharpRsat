using System;
using System.Collections.Generic;
using System.IO;

namespace SharpRsat.Recon
{
    /// <summary>
    /// Registry of red-team AD recon presets (read-only Get-AD* / LDAP queries).
    /// </summary>
    internal static class ReconCatalog
    {
        private static readonly List<ReconCommand> Commands;
        private static readonly Dictionary<string, ReconCommand> Lookup;

        static ReconCatalog()
        {
            Commands = BuildCommands();
            Lookup = new Dictionary<string, ReconCommand>(StringComparer.OrdinalIgnoreCase);
            foreach (ReconCommand cmd in Commands)
            {
                Register(cmd.Name, cmd);
                if (cmd.Aliases == null)
                {
                    continue;
                }

                foreach (string alias in cmd.Aliases)
                {
                    Register(alias, cmd);
                }
            }
        }

        /// <summary>
        /// Resolves a preset by primary name or alias.
        /// </summary>
        public static bool TryGet(string name, out ReconCommand command)
        {
            command = null;
            if (string.IsNullOrWhiteSpace(name))
            {
                return false;
            }

            return Lookup.TryGetValue(name.Trim(), out command);
        }

        /// <summary>
        /// Unique presets in registration order (aliases are not duplicated).
        /// </summary>
        public static IList<ReconCommand> List()
        {
            return Commands.AsReadOnly();
        }

        /// <summary>
        /// True when <paramref name="name"/> is a registered preset or alias.
        /// </summary>
        public static bool IsPreset(string name)
        {
            ReconCommand unused;
            return TryGet(name, out unused);
        }

        /// <summary>
        /// Runs the preset script on <paramref name="host"/>. Returns host exit code,
        /// or 1 if the name is unknown.
        /// </summary>
        public static int Execute(string name, AdPowerShellHost host)
        {
            if (host == null)
            {
                Console.Error.WriteLine("ActiveDirectory host is required.");
                return 1;
            }

            ReconCommand command;
            if (!TryGet(name, out command))
            {
                Console.Error.WriteLine(
                    "Unknown recon preset '{0}'. Run 'recon list' to see available presets.",
                    name);
                return 1;
            }

            return host.InvokeScript(command.Script);
        }

        /// <summary>
        /// Writes preset names (with aliases) and descriptions to <paramref name="writer"/>.
        /// </summary>
        public static void WriteList(TextWriter writer)
        {
            if (writer == null)
            {
                throw new ArgumentNullException("writer");
            }

            foreach (ReconCommand cmd in Commands)
            {
                string label = cmd.Name;
                if (cmd.Aliases != null && cmd.Aliases.Length > 0)
                {
                    label = cmd.Name + " (" + string.Join(", ", cmd.Aliases) + ")";
                }

                writer.WriteLine("{0,-28} {1}", label, cmd.Description);
            }
        }

        private static void Register(string key, ReconCommand command)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                return;
            }

            string normalized = key.Trim();
            if (Lookup.ContainsKey(normalized))
            {
                throw new InvalidOperationException(
                    "Duplicate recon preset name or alias: " + normalized);
            }

            Lookup.Add(normalized, command);
        }

        private static List<ReconCommand> BuildCommands()
        {
            var list = new List<ReconCommand>();

            list.Add(new ReconCommand(
                "domain",
                "Current domain information",
                "Get-ADDomain"));

            list.Add(new ReconCommand(
                "forest",
                "Current forest information",
                "Get-ADForest"));

            list.Add(new ReconCommand(
                "dcs",
                "Domain controllers",
                "Get-ADDomainController -Filter * | Select-Object Name,HostName,IPv4Address,OperatingSystem,OperatingSystemVersion,IsGlobalCatalog,Site,Domain"));

            list.Add(new ReconCommand(
                "trusts",
                "Domain trusts",
                "Get-ADTrust -Filter * | Select-Object Name,Source,Target,Direction,TrustType,DisallowTransivity,UplevelOnly,SIDFilteringForestAware,SIDFilteringQuarantined"));

            list.Add(new ReconCommand(
                "pwdpolicy",
                "Default domain password policy",
                "Get-ADDefaultDomainPasswordPolicy"));

            list.Add(new ReconCommand(
                "users",
                "Enabled user accounts (overview)",
                "Get-ADUser -Filter 'Enabled -eq $true' -Properties SamAccountName,UserPrincipalName,Enabled,PasswordLastSet,LastLogonDate,Description,adminCount,DistinguishedName | Select-Object SamAccountName,UserPrincipalName,Enabled,PasswordLastSet,LastLogonDate,Description,adminCount,DistinguishedName"));

            list.Add(new ReconCommand(
                "computers",
                "Computer accounts with OS info",
                "Get-ADComputer -Filter * -Properties DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled,LastLogonDate,DistinguishedName | Select-Object Name,DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled,LastLogonDate,DistinguishedName"));

            list.Add(new ReconCommand(
                "groups",
                "Security and distribution groups",
                "Get-ADGroup -Filter * -Properties GroupCategory,GroupScope,Description,DistinguishedName | Select-Object Name,GroupCategory,GroupScope,Description,DistinguishedName"));

            list.Add(new ReconCommand(
                "ous",
                "Organizational unit structure",
                "Get-ADOrganizationalUnit -Filter * -Properties Description,DistinguishedName | Select-Object Name,Description,DistinguishedName"));

            list.Add(new ReconCommand(
                "domain-admins",
                "Domain Admins group members (recursive)",
                "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName",
                "da"));

            list.Add(new ReconCommand(
                "enterprise-admins",
                "Enterprise Admins group members (recursive)",
                "Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName",
                "ea"));

            list.Add(new ReconCommand(
                "schema-admins",
                "Schema Admins group members (recursive)",
                "Get-ADGroupMember -Identity 'Schema Admins' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName"));

            list.Add(new ReconCommand(
                "account-operators",
                "Account Operators group members (recursive)",
                "Get-ADGroupMember -Identity 'Account Operators' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName"));

            list.Add(new ReconCommand(
                "admincount",
                "Accounts with adminCount=1",
                "Get-ADUser -LDAPFilter '(adminCount=1)' -Properties SamAccountName,adminCount,Enabled,PasswordLastSet,DistinguishedName | Select-Object SamAccountName,adminCount,Enabled,PasswordLastSet,DistinguishedName"));

            list.Add(new ReconCommand(
                "kerberoast",
                "Users with SPN (Kerberoastable), excluding krbtgt",
                "Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))' -Properties SamAccountName,servicePrincipalName,PasswordLastSet,Enabled,DistinguishedName | Select-Object SamAccountName,servicePrincipalName,PasswordLastSet,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "asreproast",
                "Users that do not require Kerberos preauth (AS-REP Roastable)",
                "Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' -Properties SamAccountName,DoesNotRequirePreAuth,UserAccountControl,Enabled,DistinguishedName | Select-Object SamAccountName,DoesNotRequirePreAuth,UserAccountControl,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "spn",
                "Directory objects with servicePrincipalName set",
                "Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName,objectClass,DistinguishedName | Select-Object Name,objectClass,servicePrincipalName,DistinguishedName"));

            list.Add(new ReconCommand(
                "unconstrained",
                "Users and computers trusted for unconstrained delegation",
                "Get-ADUser -Filter 'TrustedForDelegation -eq $true' -Properties SamAccountName,TrustedForDelegation,Enabled,DistinguishedName | Select-Object @{n='ObjectType';e={'User'}},SamAccountName,TrustedForDelegation,Enabled,DistinguishedName; Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties Name,TrustedForDelegation,Enabled,DistinguishedName | Select-Object @{n='ObjectType';e={'Computer'}},@{n='SamAccountName';e={$_.Name}},TrustedForDelegation,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "constrained",
                "Objects with constrained delegation (msDS-AllowedToDelegateTo)",
                "Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties 'msDS-AllowedToDelegateTo',objectClass,DistinguishedName | Select-Object Name,objectClass,'msDS-AllowedToDelegateTo',DistinguishedName"));

            list.Add(new ReconCommand(
                "rbcd",
                "Objects with resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)",
                "Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity',objectClass,DistinguishedName | Select-Object Name,objectClass,DistinguishedName,'msDS-AllowedToActOnBehalfOfOtherIdentity'"));

            list.Add(new ReconCommand(
                "pass-never-expires",
                "Users with PasswordNeverExpires set",
                "Get-ADUser -Filter 'PasswordNeverExpires -eq $true' -Properties SamAccountName,PasswordNeverExpires,Enabled,PasswordLastSet,DistinguishedName | Select-Object SamAccountName,PasswordNeverExpires,Enabled,PasswordLastSet,DistinguishedName",
                "dont-expire"));

            list.Add(new ReconCommand(
                "pass-not-required",
                "Users with PasswordNotRequired (empty password allowed)",
                "Get-ADUser -Filter 'PasswordNotRequired -eq $true' -Properties SamAccountName,PasswordNotRequired,Enabled,DistinguishedName | Select-Object SamAccountName,PasswordNotRequired,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "desc-users",
                "Users with a non-empty Description (often leaks secrets)",
                "Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(description=*))' -Properties SamAccountName,Description,Enabled,DistinguishedName | Select-Object SamAccountName,Description,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "gpos",
                "Group Policy container objects",
                "Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties DisplayName,Name,whenCreated,whenChanged,DistinguishedName | Select-Object DisplayName,Name,whenCreated,whenChanged,DistinguishedName"));

            list.Add(new ReconCommand(
                "server-computers",
                "Computers whose OS name contains Server",
                "Get-ADComputer -Filter 'OperatingSystem -like \"*Server*\"' -Properties DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled,LastLogonDate,DistinguishedName | Select-Object Name,DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled,LastLogonDate,DistinguishedName"));

            return list;
        }
    }
}
