namespace SharpRsat.Recon
{
    /// <summary>
    /// A read-only AD recon preset: primary name, optional aliases, description, and script.
    /// </summary>
    internal sealed class ReconCommand
    {
        public ReconCommand(string name, string description, string script, params string[] aliases)
        {
            Name = name;
            Description = description;
            Script = script;
            Aliases = aliases ?? new string[0];
        }

        /// <summary>Canonical preset name (e.g. kerberoast).</summary>
        public string Name { get; private set; }

        /// <summary>Alternate names that resolve to this preset (e.g. da for domain-admins).</summary>
        public string[] Aliases { get; private set; }

        /// <summary>One-line description for recon list.</summary>
        public string Description { get; private set; }

        /// <summary>PowerShell script executed via AdPowerShellHost.InvokeScript.</summary>
        public string Script { get; private set; }
    }
}
