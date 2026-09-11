// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Unicode;

namespace MessageFoundry.NetHelper
{
    // The wire contract (ADR 0056): one newline-terminated JSON object per connection, UTF-8, no byte order
    // mark, and a response of {"ok":true} or {"ok":false,"error":"..."}. Error text is always a fixed phrase
    // from this program, never an exception's message or stack trace.
    internal static class Protocol
    {
        internal const string Success = "{\"ok\":true}";

        internal static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        // A request is a flat object of strings. Depth 2 lets a value nested one level parse far enough to be
        // refused as a non-string; anything deeper is refused as invalid JSON.
        private static readonly JsonDocumentOptions ParseOptions = new JsonDocumentOptions { MaxDepth = 2 };

        // Parses a request and checks it against the configured scope. Only the op name leaves this method,
        // so no value a caller sent can reach anything downstream, the OS included.
        internal static string TryParse(byte[] line, HelperConfig config, out string op)
        {
            op = null;
            if (line.Length >= 3 && line[0] == 0xEF && line[1] == 0xBB && line[2] == 0xBF)
            {
                return "request must be UTF-8 without a byte order mark";
            }

            if (!Utf8.IsValid(line))
            {
                return "request is not valid UTF-8";
            }

            // JsonDocument maps the JSON onto no type, so no caller can name a type for this process to build, and
            // nothing here needs the reflection NativeAOT does not provide. A repeated name keeps its last value.
            // A value that is not a string is kept as null, which no JSON string produces. System.Text.Json refuses
            // to decode an escaped lone surrogate: GetString and Name throw InvalidOperationException for one.
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            try
            {
                using (JsonDocument document = JsonDocument.Parse(line, ParseOptions))
                {
                    if (document.RootElement.ValueKind != JsonValueKind.Object)
                    {
                        return "request must be a JSON object";
                    }

                    foreach (JsonProperty property in document.RootElement.EnumerateObject())
                    {
                        fields[property.Name] =
                            property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null;
                    }
                }
            }
            catch (Exception ex) when (ex is JsonException || ex is InvalidOperationException)
            {
                return "request is not valid JSON";
            }

            if (fields.ContainsValue(null))
            {
                return "every request field must be a string";
            }

            string name = fields.GetValueOrDefault("op");
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
            return Response(true, "version", version);
        }

        internal static string Failure(string error)
        {
            return Response(false, "error", error);
        }

        // Utf8JsonWriter escapes the value as JSON requires and uses no reflection, so NativeAOT compiles it.
        private static string Response(bool ok, string name, string value)
        {
            var buffer = new ArrayBufferWriter<byte>();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteBoolean("ok", ok);
                writer.WriteString(name, value);
                writer.WriteEndObject();
            }

            return StrictUtf8.GetString(buffer.WrittenSpan);
        }

        // The scope check ADR 0056 makes non-optional: a request must name exactly the configured address,
        // interface and (for bind) mask. Anything else is refused and never attempted.
        private static string CheckScope(Dictionary<string, string> fields, bool hasMask, HelperConfig config)
        {
            IPAddress address;
            if (!Ipv4.TryParseStrict(fields["address"], out address))
            {
                return "address must be dotted-decimal IPv4";
            }

            if (!address.Equals(config.Address))
            {
                return "address is outside this helper's scope";
            }

            if (!string.Equals(fields["interface"], config.Interface, StringComparison.Ordinal))
            {
                return "interface is outside this helper's scope";
            }

            if (hasMask)
            {
                IPAddress mask;
                if (!Ipv4.TryParseStrict(fields["mask"], out mask))
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
    }
}
