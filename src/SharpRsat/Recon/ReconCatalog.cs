using System;
using System.Collections.Generic;
using System.IO;

namespace SharpRsat.Recon
{
    /// <summary>
    /// Registry of directory recon presets (read-only Get-AD* / LDAP queries).
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
        /// When <paramref name="quiet"/> is true, prints names/aliases only.
        /// </summary>
        public static void WriteList(TextWriter writer)
        {
            WriteList(writer, false);
        }

        /// <summary>
        /// Writes preset names (with aliases) and optionally descriptions to <paramref name="writer"/>.
        /// </summary>
        public static void WriteList(TextWriter writer, bool quiet)
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

                if (quiet)
                {
                    writer.WriteLine(label);
                }
                else
                {
                    writer.WriteLine("{0,-36} {1}", label, cmd.Description);
                }
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
                "backup-operators",
                "Backup Operators group members (recursive)",
                "Get-ADGroupMember -Identity 'Backup Operators' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName",
                "bo"));

            list.Add(new ReconCommand(
                "server-operators",
                "Server Operators group members (recursive)",
                "Get-ADGroupMember -Identity 'Server Operators' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName"));

            list.Add(new ReconCommand(
                "print-operators",
                "Print Operators group members (recursive)",
                "Get-ADGroupMember -Identity 'Print Operators' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName"));

            list.Add(new ReconCommand(
                "dns-admins",
                "DnsAdmins group members (recursive)",
                "Get-ADGroupMember -Identity 'DnsAdmins' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName"));

            list.Add(new ReconCommand(
                "gpo-creators",
                "Group Policy Creator Owners members (recursive)",
                "Get-ADGroupMember -Identity 'Group Policy Creator Owners' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName"));

            list.Add(new ReconCommand(
                "builtin-admins",
                "Built-in Administrators group members (recursive)",
                "Get-ADGroupMember -Identity 'Administrators' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName"));

            list.Add(new ReconCommand(
                "protected-users",
                "Protected Users group members (recursive)",
                "Get-ADGroupMember -Identity 'Protected Users' -Recursive | Select-Object Name,SamAccountName,objectClass,distinguishedName"));

            list.Add(new ReconCommand(
                "admincount",
                "Accounts with adminCount=1",
                "Get-ADUser -LDAPFilter '(adminCount=1)' -Properties SamAccountName,adminCount,Enabled,PasswordLastSet,DistinguishedName | Select-Object SamAccountName,adminCount,Enabled,PasswordLastSet,DistinguishedName"));

            list.Add(new ReconCommand(
                "fsmo",
                "FSMO role holders (domain + forest)",
                "$d = Get-ADDomain; $f = Get-ADForest; [PSCustomObject]@{PDCEmulator=$d.PDCEmulator; RIDMaster=$d.RIDMaster; InfrastructureMaster=$d.InfrastructureMaster; SchemaMaster=$f.SchemaMaster; DomainNamingMaster=$f.DomainNamingMaster; Domain=$d.DNSRoot; Forest=$f.Name}"));

            list.Add(new ReconCommand(
                "sites",
                "AD replication sites",
                "Get-ADReplicationSite -Filter * | Select-Object Name,Description,DistinguishedName"));

            list.Add(new ReconCommand(
                "subnets",
                "AD replication subnets",
                "Get-ADReplicationSubnet -Filter * | Select-Object Name,Site,Location,DistinguishedName"));

            list.Add(new ReconCommand(
                "rodc",
                "Read-only domain controllers",
                "Get-ADDomainController -Filter 'IsReadOnly -eq $true' | Select-Object Name,HostName,IPv4Address,OperatingSystem,Site,Domain"));

            list.Add(new ReconCommand(
                "maq",
                "Domain ms-DS-MachineAccountQuota (non-admins can join N computers)",
                "(Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota') | Select-Object DistinguishedName,@{n='MachineAccountQuota';e={$_.'ms-DS-MachineAccountQuota'}}"));

            list.Add(new ReconCommand(
                "dns",
                "AD-integrated DNS zones and domain controller DNS endpoints",
                "$domain = Get-ADDomain; $forestRootDn = (Get-ADDomain -Identity (Get-ADForest).RootDomain).DistinguishedName; Write-Output '=== DNS endpoints (domain controllers) ==='; Get-ADDomainController -Filter * | Select-Object Name,HostName,IPv4Address,Site,Domain; Write-Output ''; Write-Output ('=== AD-integrated DNS zones (DNSRoot={0}) ===' -f $domain.DNSRoot); $bases = @(('DC=DomainDnsZones,{0}' -f $domain.DistinguishedName), ('DC=ForestDnsZones,{0}' -f $forestRootDn), ('CN=MicrosoftDNS,CN=System,{0}' -f $domain.DistinguishedName)); foreach ($searchBase in $bases) { Get-ADObject -SearchBase $searchBase -LDAPFilter '(objectClass=dnsZone)' -SearchScope Subtree -Properties Name,whenCreated,whenChanged,DistinguishedName -ErrorAction SilentlyContinue | Select-Object Name,@{n='SearchBase';e={$searchBase}},whenCreated,whenChanged,DistinguishedName }",
                "dns-zones"));

            list.Add(new ReconCommand(
                "dns-records",
                "AD-integrated DNS node names (non-tombstoned; no binary RR decode)",
                "$domain = Get-ADDomain; $forestRootDn = (Get-ADDomain -Identity (Get-ADForest).RootDomain).DistinguishedName; $bases = @(('DC=DomainDnsZones,{0}' -f $domain.DistinguishedName), ('DC=ForestDnsZones,{0}' -f $forestRootDn), ('CN=MicrosoftDNS,CN=System,{0}' -f $domain.DistinguishedName)); foreach ($searchBase in $bases) { Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))' -SearchScope Subtree -Properties Name,whenChanged,DistinguishedName -ErrorAction SilentlyContinue | Select-Object Name,@{n='SearchBase';e={$searchBase}},whenChanged,DistinguishedName }"));

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
                "krbtgt",
                "krbtgt account (PasswordLastSet indicates golden-ticket validity window)",
                "Get-ADUser -Identity krbtgt -Properties SamAccountName,PasswordLastSet,PasswordNeverExpires,Enabled,Created,Modified,DistinguishedName | Select-Object SamAccountName,PasswordLastSet,PasswordNeverExpires,Enabled,Created,Modified,DistinguishedName"));

            list.Add(new ReconCommand(
                "gmsa",
                "Group/managed service accounts",
                "Get-ADServiceAccount -Filter * -Properties SamAccountName,DNSHostName,Enabled,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames,DistinguishedName | Select-Object Name,SamAccountName,DNSHostName,Enabled,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames,DistinguishedName"));

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
                "trusted-to-auth",
                "Objects trusted to authenticate for delegation (protocol transition)",
                "Get-ADUser -Filter 'TrustedToAuthForDelegation -eq $true' -Properties SamAccountName,TrustedToAuthForDelegation,Enabled,DistinguishedName | Select-Object @{n='ObjectType';e={'User'}},SamAccountName,TrustedToAuthForDelegation,Enabled,DistinguishedName; Get-ADComputer -Filter 'TrustedToAuthForDelegation -eq $true' -Properties Name,TrustedToAuthForDelegation,Enabled,DistinguishedName | Select-Object @{n='ObjectType';e={'Computer'}},@{n='SamAccountName';e={$_.Name}},TrustedToAuthForDelegation,Enabled,DistinguishedName",
                "t2a"));

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
                "reversible",
                "Users with reversible password encryption allowed",
                "Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq $true' -Properties SamAccountName,AllowReversiblePasswordEncryption,Enabled,PasswordLastSet,DistinguishedName | Select-Object SamAccountName,AllowReversiblePasswordEncryption,Enabled,PasswordLastSet,DistinguishedName"));

            list.Add(new ReconCommand(
                "des-only",
                "Accounts restricted to DES Kerberos keys",
                "Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))' -Properties SamAccountName,UserAccountControl,Enabled,DistinguishedName | Select-Object SamAccountName,UserAccountControl,Enabled,DistinguishedName; Get-ADComputer -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2097152)' -Properties Name,UserAccountControl,Enabled,DistinguishedName | Select-Object Name,UserAccountControl,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "sid-history",
                "Principals with SIDHistory (migration / possible injection)",
                "Get-ADObject -LDAPFilter '(sidHistory=*)' -Properties SamAccountName,SIDHistory,objectClass,DistinguishedName | Select-Object Name,SamAccountName,objectClass,SIDHistory,DistinguishedName"));

            list.Add(new ReconCommand(
                "disabled-users",
                "Disabled user accounts",
                "Get-ADUser -Filter 'Enabled -eq $false' -Properties SamAccountName,Enabled,PasswordLastSet,LastLogonDate,Description,DistinguishedName | Select-Object SamAccountName,Enabled,PasswordLastSet,LastLogonDate,Description,DistinguishedName"));

            list.Add(new ReconCommand(
                "locked-users",
                "Currently locked-out user accounts",
                "Search-ADAccount -LockedOut -UsersOnly | Select-Object Name,SamAccountName,LockedOut,Enabled,LastLogonDate,DistinguishedName",
                "locked"));

            list.Add(new ReconCommand(
                "inactive-users",
                "Enabled users with no logon in 90+ days (or never)",
                "$ts = (Get-Date).AddDays(-90).ToFileTime(); Get-ADUser -LDAPFilter \"(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=$ts)))\" -Properties SamAccountName,LastLogonDate,PasswordLastSet,Enabled,DistinguishedName | Select-Object SamAccountName,LastLogonDate,PasswordLastSet,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "stale-computers",
                "Enabled computers with no logon in 90+ days (or never)",
                "$ts = (Get-Date).AddDays(-90).ToFileTime(); Get-ADComputer -LDAPFilter \"(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=$ts)))\" -Properties DNSHostName,OperatingSystem,LastLogonDate,Enabled,DistinguishedName | Select-Object Name,DNSHostName,OperatingSystem,LastLogonDate,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "desc-users",
                "Users with a non-empty Description (often leaks secrets)",
                "Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(description=*))' -Properties SamAccountName,Description,Enabled,DistinguishedName | Select-Object SamAccountName,Description,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "info-users",
                "Users with a non-empty Notes/info attribute",
                "Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(info=*))' -Properties SamAccountName,info,Enabled,DistinguishedName | Select-Object SamAccountName,info,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "scriptpath",
                "Users with a logon script path set",
                "Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(scriptPath=*))' -Properties SamAccountName,ScriptPath,HomeDirectory,Enabled,DistinguishedName | Select-Object SamAccountName,ScriptPath,HomeDirectory,Enabled,DistinguishedName"));

            list.Add(new ReconCommand(
                "gpos",
                "Group Policy container objects",
                "Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties DisplayName,Name,whenCreated,whenChanged,DistinguishedName | Select-Object DisplayName,Name,whenCreated,whenChanged,DistinguishedName"));

            list.Add(new ReconCommand(
                "fine-grained-pwd",
                "Fine-grained password policies (PSO)",
                "Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name,Precedence,MinPasswordLength,PasswordHistoryCount,LockoutThreshold,AppliesTo,DistinguishedName",
                "fgpp"));

            list.Add(new ReconCommand(
                "laps",
                "Computers with legacy or Windows LAPS expiration set (no password dump)",
                "Get-ADComputer -LDAPFilter '(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))' -Properties DNSHostName,OperatingSystem,'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime',Enabled,DistinguishedName | Select-Object Name,DNSHostName,OperatingSystem,Enabled,'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime',DistinguishedName"));

            list.Add(new ReconCommand(
                "bitlocker",
                "BitLocker recovery information objects (metadata only)",
                "Get-ADObject -LDAPFilter '(objectClass=msFVE-RecoveryInformation)' -Properties whenCreated,whenChanged,DistinguishedName | Select-Object Name,whenCreated,whenChanged,DistinguishedName"));

            list.Add(new ReconCommand(
                "foreign-principals",
                "Foreign security principals (trust principals in this domain)",
                "Get-ADObject -LDAPFilter '(objectClass=foreignSecurityPrincipal)' -Properties Name,objectSid,whenCreated,DistinguishedName | Select-Object Name,objectSid,whenCreated,DistinguishedName",
                "fsp"));

            list.Add(new ReconCommand(
                "server-computers",
                "Computers whose OS name contains Server",
                "Get-ADComputer -Filter 'OperatingSystem -like \"*Server*\"' -Properties DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled,LastLogonDate,DistinguishedName | Select-Object Name,DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled,LastLogonDate,DistinguishedName"));

            list.Add(new ReconCommand(
                "workstations",
                "Enabled computers whose OS name does not contain Server",
                "Get-ADComputer -Filter 'Enabled -eq $true -and OperatingSystem -notlike \"*Server*\"' -Properties DNSHostName,OperatingSystem,OperatingSystemVersion,LastLogonDate,DistinguishedName | Select-Object Name,DNSHostName,OperatingSystem,OperatingSystemVersion,LastLogonDate,DistinguishedName"));

            list.Add(new ReconCommand(
                "legacy-os",
                "Computers with legacy OS strings (XP/Vista/7/8/2000/2003/2008/2012)",
                "Get-ADComputer -LDAPFilter '(|(operatingSystem=*Windows XP*)(operatingSystem=*Windows Vista*)(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)(operatingSystem=*Windows 2000*)(operatingSystem=*Windows Server 2003*)(operatingSystem=*Windows Server 2008*)(operatingSystem=*Windows Server 2012*))' -Properties DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled,LastLogonDate,DistinguishedName | Select-Object Name,DNSHostName,OperatingSystem,OperatingSystemVersion,Enabled,LastLogonDate,DistinguishedName"));

            return list;
        }
    }
}
