using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

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
        /// Supports <c>--flag value</c> and <c>--flag=value</c>; tolerant of loader quoting/nulls.
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

            // Some loaders (e.g. execute-assembly) pass the whole tail as one argv, or pack
            // "--delay 5000" into a single token. Expand those before flag parsing.
            args = FlattenLoaderArgs(args);

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

                string flag;
                string inlineValue;
                SplitFlagToken(NormalizeToken(token), out flag, out inlineValue);

                // Attached numerics: --delay5000 / --max-results50 (no '=' / ':')
                if (inlineValue == null)
                {
                    TrySplitAttachedNumericFlag("--delay", flag, out flag, out inlineValue);
                }

                if (inlineValue == null)
                {
                    string maxFlag = flag;
                    string maxInline = null;
                    if (TrySplitAttachedNumericFlag("--max-results", maxFlag, out maxFlag, out maxInline))
                    {
                        flag = maxFlag;
                        inlineValue = maxInline;
                    }
                }

                if (string.Equals(flag, "--install-rsat", StringComparison.OrdinalIgnoreCase))
                {
                    options.InstallRsat = true;
                    continue;
                }

                if (string.Equals(flag, "--allow-write", StringComparison.OrdinalIgnoreCase))
                {
                    options.AllowWrite = true;
                    continue;
                }

                if (string.Equals(flag, "--quiet", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(flag, "-q", StringComparison.OrdinalIgnoreCase))
                {
                    options.Quiet = true;
                    continue;
                }

                if (string.Equals(flag, "--delay", StringComparison.OrdinalIgnoreCase))
                {
                    string value;
                    if (!TryResolveOptionValue(args, ref i, inlineValue, out value))
                    {
                        errorMessage = "Option --delay requires an integer milliseconds value.";
                        return 1;
                    }

                    int parsed;
                    if (!TryParseBoundedInt(value, 0, MaxDelayMs, out parsed))
                    {
                        errorMessage = "Option --delay must be an integer between 0 and " + MaxDelayMs
                            + " (got '" + SanitizeForError(value) + "').";
                        return 1;
                    }

                    delayMs = parsed;
                    continue;
                }

                if (string.Equals(flag, "--max-results", StringComparison.OrdinalIgnoreCase))
                {
                    string value;
                    if (!TryResolveOptionValue(args, ref i, inlineValue, out value))
                    {
                        errorMessage = "Option --max-results requires a non-negative integer.";
                        return 1;
                    }

                    int parsed;
                    if (!TryParseBoundedInt(value, 0, int.MaxValue, out parsed))
                    {
                        errorMessage = "Option --max-results must be a non-negative integer (0 = unlimited)"
                            + " (got '" + SanitizeForError(value) + "').";
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

        /// <summary>
        /// Expands loader-packed argv forms without breaking normal quoted multi-word values
        /// (only splits a sole command-line blob, or tokens that begin with a known global flag).
        /// </summary>
        private static string[] FlattenLoaderArgs(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                return args;
            }

            // Single blob: "recon dns-records --quiet --delay 5000"
            if (args.Length == 1 && args[0] != null && IndexOfAsciiWhitespace(args[0]) >= 0)
            {
                return SplitOnAsciiWhitespace(args[0]);
            }

            var expanded = new List<string>(args.Length + 4);
            for (int i = 0; i < args.Length; i++)
            {
                string token = args[i];
                if (string.IsNullOrEmpty(token))
                {
                    expanded.Add(token);
                    continue;
                }

                string normalized = NormalizeToken(token);
                if (LooksLikePackedGlobalFlag(normalized))
                {
                    expanded.AddRange(SplitOnAsciiWhitespace(normalized));
                }
                else
                {
                    expanded.Add(token);
                }
            }

            return expanded.ToArray();
        }

        private static bool LooksLikePackedGlobalFlag(string token)
        {
            if (string.IsNullOrEmpty(token) || IndexOfAsciiWhitespace(token) < 0)
            {
                return false;
            }

            return StartsWithFlagWord(token, "--delay")
                || StartsWithFlagWord(token, "--max-results")
                || StartsWithFlagWord(token, "--quiet")
                || StartsWithFlagWord(token, "--install-rsat")
                || StartsWithFlagWord(token, "--allow-write")
                || StartsWithFlagWord(token, "-q");
        }

        private static bool StartsWithFlagWord(string token, string flag)
        {
            if (!token.StartsWith(flag, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (token.Length == flag.Length)
            {
                return true;
            }

            char next = token[flag.Length];
            return char.IsWhiteSpace(next) || next == '=' || next == ':';
        }

        private static int IndexOfAsciiWhitespace(string value)
        {
            if (value == null)
            {
                return -1;
            }

            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
                {
                    return i;
                }
            }

            return -1;
        }

        private static string[] SplitOnAsciiWhitespace(string value)
        {
            var parts = new List<string>();
            if (string.IsNullOrEmpty(value))
            {
                return parts.ToArray();
            }

            int i = 0;
            while (i < value.Length)
            {
                while (i < value.Length && char.IsWhiteSpace(value[i]))
                {
                    i++;
                }

                if (i >= value.Length)
                {
                    break;
                }

                int start = i;
                while (i < value.Length && !char.IsWhiteSpace(value[i]))
                {
                    i++;
                }

                parts.Add(value.Substring(start, i - start));
            }

            return parts.ToArray();
        }

        /// <summary>
        /// Splits <c>--flag=value</c> / <c>--flag:value</c>; otherwise returns the token as flag.
        /// </summary>
        private static void SplitFlagToken(string token, out string flag, out string inlineValue)
        {
            flag = token;
            inlineValue = null;

            if (string.IsNullOrEmpty(token) || token[0] != '-')
            {
                return;
            }

            int sep = token.IndexOf('=');
            if (sep < 0)
            {
                sep = token.IndexOf(':');
            }

            if (sep <= 1)
            {
                return;
            }

            flag = token.Substring(0, sep);
            inlineValue = token.Substring(sep + 1);
        }

        /// <summary>
        /// Splits <c>--delay5000</c> style tokens into flag + numeric value.
        /// </summary>
        private static bool TrySplitAttachedNumericFlag(
            string flagName,
            string token,
            out string flag,
            out string inlineValue)
        {
            flag = token;
            inlineValue = null;

            if (string.IsNullOrEmpty(token)
                || !token.StartsWith(flagName, StringComparison.OrdinalIgnoreCase)
                || token.Length <= flagName.Length)
            {
                return false;
            }

            string suffix = token.Substring(flagName.Length);
            if (!IsAllDigits(suffix))
            {
                return false;
            }

            flag = flagName;
            inlineValue = suffix;
            return true;
        }

        private static bool TryResolveOptionValue(
            string[] args,
            ref int index,
            string inlineValue,
            out string value)
        {
            if (!string.IsNullOrEmpty(inlineValue))
            {
                value = NormalizeToken(inlineValue);
                return value.Length > 0;
            }

            return TryTakeValue(args, ref index, out value);
        }

        private static bool TryTakeValue(string[] args, ref int index, out string value)
        {
            value = null;
            if (index + 1 >= args.Length)
            {
                return false;
            }

            index++;
            value = NormalizeToken(args[index]);
            if (value.Length == 0)
            {
                return false;
            }

            // Loader may split a number across tokens (rare); join consecutive digit-only pieces.
            while (index + 1 < args.Length)
            {
                string next = NormalizeToken(args[index + 1]);
                if (next.Length == 0 || !IsAllDigits(next))
                {
                    break;
                }

                if (!IsAllDigits(value))
                {
                    break;
                }

                index++;
                value = value + next;
            }

            return true;
        }

        private static string NormalizeToken(string token)
        {
            if (token == null)
            {
                return string.Empty;
            }

            // Drop embedded NULs from unmanaged / implant argument marshalling.
            if (token.IndexOf('\0') >= 0)
            {
                token = token.Replace("\0", string.Empty);
            }

            token = token.Trim();
            token = StripWrappingQuotes(token);
            return token.Trim();
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

        private static bool TryParseBoundedInt(string value, int min, int max, out int parsed)
        {
            parsed = 0;
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            // Accept leading/trailing junk only if a clean digit run remains (e.g. "5000ms").
            string digits = ExtractLeadingInteger(value);
            if (digits.Length == 0)
            {
                return false;
            }

            if (!int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out parsed))
            {
                return false;
            }

            return parsed >= min && parsed <= max;
        }

        private static string ExtractLeadingInteger(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            int i = 0;
            while (i < value.Length && char.IsWhiteSpace(value[i]))
            {
                i++;
            }

            int start = i;
            while (i < value.Length && char.IsDigit(value[i]))
            {
                i++;
            }

            if (i == start)
            {
                return string.Empty;
            }

            if (i < value.Length)
            {
                string rest = value.Substring(i).Trim();
                if (rest.Length > 0
                    && !string.Equals(rest, "ms", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(rest, "msec", StringComparison.OrdinalIgnoreCase))
                {
                    return string.Empty;
                }
            }

            return value.Substring(start, i - start);
        }

        private static bool IsAllDigits(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            for (int i = 0; i < value.Length; i++)
            {
                if (!char.IsDigit(value[i]))
                {
                    return false;
                }
            }

            return true;
        }

        private static string SanitizeForError(string value)
        {
            if (value == null)
            {
                return string.Empty;
            }

            var sb = new StringBuilder(value.Length);
            for (int i = 0; i < value.Length && i < 64; i++)
            {
                char c = value[i];
                if (c >= 32 && c < 127)
                {
                    sb.Append(c);
                }
                else
                {
                    sb.Append('\\');
                    sb.Append('x');
                    sb.Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
                }
            }

            if (value.Length > 64)
            {
                sb.Append("...");
            }

            return sb.ToString();
        }
    }
}
