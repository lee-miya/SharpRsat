using System;
using System.Collections.Generic;

namespace SharpRsat
{
    /// <summary>
    /// Global CLI flags stripped from the command argument list before routing.
    /// </summary>
    internal sealed class CliOptions
    {
        public const int MaxDelayMs = 60000;

        public bool InstallRsat { get; private set; }
        public bool AllowWrite { get; private set; }
        public bool Quiet { get; private set; }
        public int DelayMs { get; private set; }
        public int MaxResults { get; private set; }

        /// <summary>
        /// Remaining tokens after global flags are removed (cmdlet / recon / preset route).
        /// </summary>
        public string[] CommandArgs { get; private set; }

        private CliOptions()
        {
            CommandArgs = new string[0];
        }

        /// <summary>
        /// Parses known global flags from any position. Unknown <c>--*</c> tokens that are not
        /// in the fixed set are left for the AD cmdlet (except parse errors on known flags).
        /// </summary>
        /// <returns>0 on success; non-zero when a known flag has an invalid value.</returns>
        public static int Parse(string[] args, out CliOptions options, out string errorMessage)
        {
            options = new CliOptions();
            errorMessage = null;

            if (args == null || args.Length == 0)
            {
                options.CommandArgs = new string[0];
                return 0;
            }

            var remaining = new List<string>(args.Length);
            int delayMs = 0;
            int maxResults = 0;

            for (int i = 0; i < args.Length; i++)
            {
                string token = args[i];
                if (string.IsNullOrEmpty(token))
                {
                    remaining.Add(token);
                    continue;
                }

                if (string.Equals(token, "--install-rsat", StringComparison.OrdinalIgnoreCase))
                {
                    options.InstallRsat = true;
                    continue;
                }

                if (string.Equals(token, "--allow-write", StringComparison.OrdinalIgnoreCase))
                {
                    options.AllowWrite = true;
                    continue;
                }

                if (string.Equals(token, "--quiet", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(token, "-q", StringComparison.OrdinalIgnoreCase))
                {
                    options.Quiet = true;
                    continue;
                }

                if (string.Equals(token, "--delay", StringComparison.OrdinalIgnoreCase))
                {
                    string value;
                    if (!TryTakeValue(args, ref i, out value))
                    {
                        errorMessage = "Option --delay requires an integer milliseconds value.";
                        return 1;
                    }

                    int parsed;
                    if (!int.TryParse(value, out parsed) || parsed < 0 || parsed > MaxDelayMs)
                    {
                        errorMessage = "Option --delay must be an integer between 0 and " + MaxDelayMs + ".";
                        return 1;
                    }

                    delayMs = parsed;
                    continue;
                }

                if (string.Equals(token, "--max-results", StringComparison.OrdinalIgnoreCase))
                {
                    string value;
                    if (!TryTakeValue(args, ref i, out value))
                    {
                        errorMessage = "Option --max-results requires a non-negative integer.";
                        return 1;
                    }

                    int parsed;
                    if (!int.TryParse(value, out parsed) || parsed < 0)
                    {
                        errorMessage = "Option --max-results must be a non-negative integer (0 = unlimited).";
                        return 1;
                    }

                    maxResults = parsed;
                    continue;
                }

                remaining.Add(token);
            }

            options.DelayMs = delayMs;
            options.MaxResults = maxResults;
            options.CommandArgs = remaining.ToArray();
            return 0;
        }

        private static bool TryTakeValue(string[] args, ref int index, out string value)
        {
            value = null;
            if (index + 1 >= args.Length)
            {
                return false;
            }

            index++;
            value = args[index];
            return !string.IsNullOrEmpty(value);
        }
    }
}
