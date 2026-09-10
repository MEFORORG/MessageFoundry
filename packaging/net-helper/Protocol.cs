// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Web.Script.Serialization;

namespace MessageFoundry.NetHelper
{
    // The wire contract (ADR 0056): one newline-terminated JSON object per connection, UTF-8, no byte order
    // mark, and a response of {"ok":true} or {"ok":false,"error":"..."}. Error text is always a fixed phrase
    // from this program, never an exception's message or stack trace.
    internal static class Protocol
    {
        internal const string Success = "{\"ok\":true}";

        internal static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        // Parses a request and checks it against the configured scope. Only the op name leaves this method,
        // so no value a caller sent can reach anything downstream, the OS included.
        internal static string TryParse(byte[] line, HelperConfig config, out string op)
        {
            op = null;
            if (line.Length >= 3 && line[0] == 0xEF && line[1] == 0xBB && line[2] == 0xBF)
            {
                return "request must be UTF-8 without a byte order mark";
            }

            string text;
            try
            {
                text = StrictUtf8.GetString(line);
            }
            catch (DecoderFallbackException)
            {
                return "request is not valid UTF-8";
            }

            object parsed;
            try
            {
                // DeserializeObject with no type resolver yields only dictionaries, arrays and primitives, so
                // no caller can name a type for this process to build.
                parsed = new JavaScriptSerializer { RecursionLimit = 2 }.DeserializeObject(text);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException || ex is FormatException || ex is OverflowException)
            {
                return "request is not valid JSON";
            }

            var fields = parsed as IDictionary<string, object>;
            if (fields == null)
            {
                return "request must be a JSON object";
            }

            foreach (object value in fields.Values)
            {
                if (!(value is string))
                {
                    return "every request field must be a string";
                }
            }

            string name = Field(fields, "op");
            string[] expected;
            switch (name)
            {
                case "ping":
                    expected = new[] { "op" };
                    break;
                case "bind":
                    expected = new[] { "op", "address", "interface", "mask" };
                    break;
                case "release":
                case "arp":
                    expected = new[] { "op", "address", "interface" };
                    break;
                default:
                    return "unknown or missing op";
            }

            // Exactly the named fields: a field this contract does not define means the caller and the
            // helper disagree about the contract, and guessing which one is right is not this process's job.
            if (fields.Count != expected.Length || Array.Exists(expected, key => !fields.ContainsKey(key)))
            {
                return "fields do not match op " + name;
            }

            string error = name == "ping" ? null : CheckScope(fields, name == "bind", config);
            if (error == null)
            {
                op = name;
            }

            return error;
        }

        internal static string Pong(string version)
        {
            return new JavaScriptSerializer().Serialize(new Dictionary<string, object> { { "ok", true }, { "version", version } });
        }

        internal static string Failure(string error)
        {
            return new JavaScriptSerializer().Serialize(new Dictionary<string, object> { { "ok", false }, { "error", error } });
        }

        // The scope check ADR 0056 makes non-optional: a request must name exactly the configured address,
        // interface and (for bind) mask. Anything else is refused and never attempted.
        private static string CheckScope(IDictionary<string, object> fields, bool hasMask, HelperConfig config)
        {
            IPAddress address;
            if (!Ipv4.TryParseStrict(Field(fields, "address"), out address))
            {
                return "address must be dotted-decimal IPv4";
            }

            if (!address.Equals(config.Address))
            {
                return "address is outside this helper's scope";
            }

            if (!string.Equals(Field(fields, "interface"), config.Interface, StringComparison.Ordinal))
            {
                return "interface is outside this helper's scope";
            }

            if (hasMask)
            {
                IPAddress mask;
                if (!Ipv4.TryParseStrict(Field(fields, "mask"), out mask))
                {
                    return "mask must be dotted-decimal IPv4";
                }

                if (!mask.Equals(config.Mask))
                {
                    return "mask does not match this helper's configuration";
                }
            }

            return null;
        }

        private static string Field(IDictionary<string, object> fields, string key)
        {
            object value;
            return fields.TryGetValue(key, out value) ? value as string : null;
        }
    }
}
