// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;

namespace MessageFoundry.NetHelper
{
    internal sealed class ConfigException : Exception
    {
        internal ConfigException(string message) : base(message) { }
    }

    // The helper's scope, read once at start from mefor-net-helper.conf beside the executable. This file is
    // the trusted source ADR 0056 requires: the address comes from here, never from a caller. It is only as
    // trusted as its directory, so install where only administrators can write (README.md).
    internal sealed class HelperConfig
    {
        internal const string FileName = "mefor-net-helper.conf";

        private static readonly string[] Keys = { "address", "interface", "mask", "client_account" };

        // Groups a client_account must never name. Each would admit callers other than the engine and turn
        // the helper into an administrator-rights oracle for them.
        private static readonly WellKnownSidType[] BroadGroups =
        {
            WellKnownSidType.WorldSid, WellKnownSidType.AuthenticatedUserSid, WellKnownSidType.BuiltinUsersSid,
            WellKnownSidType.BuiltinGuestsSid, WellKnownSidType.InteractiveSid, WellKnownSidType.NetworkSid,
            WellKnownSidType.AnonymousSid, WellKnownSidType.LocalSid,
        };

        internal IPAddress Address { get; private set; }

        internal string Interface { get; private set; }

        internal IPAddress Mask { get; private set; }

        internal SecurityIdentifier ClientSid { get; private set; }

        internal string ClientName { get; private set; }

        // The address and interface, as log lines name them.
        internal string Scope
        {
            get { return "address=" + Address + " interface=\"" + Interface + "\""; }
        }

        internal static HelperConfig Load(string path)
        {
            string[] lines;
            try
            {
                lines = File.ReadAllLines(path, Protocol.StrictUtf8);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is DecoderFallbackException)
            {
                throw new ConfigException("cannot read " + path + ": " + ex.Message);
            }

            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();
                if (line.Length == 0 || line[0] == '#')
                {
                    continue;
                }

                int equals = line.IndexOf('=');
                string where = "line " + (i + 1).ToString(CultureInfo.InvariantCulture) + ": ";
                if (equals <= 0)
                {
                    throw new ConfigException(where + "expected key = value");
                }

                string key = line.Substring(0, equals).Trim();
                if (Array.IndexOf(Keys, key) < 0)
                {
                    throw new ConfigException(where + "unknown key '" + key + "'");
                }

                if (values.ContainsKey(key))
                {
                    throw new ConfigException(where + "duplicate key '" + key + "'");
                }

                values[key] = line.Substring(equals + 1).Trim();
            }

            foreach (string key in Keys)
            {
                if (!values.ContainsKey(key))
                {
                    throw new ConfigException("missing key '" + key + "'");
                }
            }

            return new HelperConfig
            {
                Address = ParseAddress(values["address"]),
                Interface = ParseInterface(values["interface"]),
                Mask = ParseMask(values["mask"]),
                ClientSid = ParseClient(values["client_account"]),
                ClientName = values["client_account"],
            };
        }

        private static IPAddress ParseAddress(string text)
        {
            IPAddress address;
            if (!Ipv4.TryParseStrict(text, out address))
            {
                throw new ConfigException("address must be a dotted-decimal IPv4 address");
            }

            // 0/8 (this network), 127/8 (loopback) and 224.0.0.0 upward (multicast, reserved, broadcast)
            // can never be a VIP.
            byte first = address.GetAddressBytes()[0];
            if (first == 0 || first == 127 || first >= 224)
            {
                throw new ConfigException("address " + text + " cannot be a VIP");
            }

            return address;
        }

        private static IPAddress ParseMask(string text)
        {
            IPAddress mask;
            if (!Ipv4.TryParseStrict(text, out mask))
            {
                throw new ConfigException("mask must be a dotted-decimal IPv4 netmask, for example 255.255.255.0");
            }

            byte[] b = mask.GetAddressBytes();
            uint bits = (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
            uint host = ~bits;
            if (bits == 0 || (host & (host + 1)) != 0)
            {
                throw new ConfigException("mask " + text + " is not a contiguous netmask");
            }

            return mask;
        }

        private static string ParseInterface(string text)
        {
            if (text.Length == 0 || text.Length > 256)
            {
                throw new ConfigException("interface must be 1 to 256 characters");
            }

            foreach (char ch in text)
            {
                // The name is quoted onto netsh's command line. A quote, a backslash or a control character
                // could end or bend that argument.
                if (ch == '"' || ch == '\\' || char.IsControl(ch))
                {
                    throw new ConfigException("interface must not contain a quote, a backslash or a control character");
                }
            }

            return text;
        }

        private static SecurityIdentifier ParseClient(string text)
        {
            SecurityIdentifier sid;
            try
            {
                sid = text.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
                    ? new SecurityIdentifier(text)
                    : (SecurityIdentifier)new NTAccount(text).Translate(typeof(SecurityIdentifier));
            }
            catch (Exception ex) when (ex is ArgumentException || ex is IdentityNotMappedException)
            {
                throw new ConfigException("client_account '" + text + "' does not resolve to an account: " + ex.Message);
            }

            foreach (WellKnownSidType group in BroadGroups)
            {
                if (sid.IsWellKnown(group))
                {
                    throw new ConfigException("client_account '" + text + "' is a broad group; name the engine's service account");
                }
            }

            return sid;
        }
    }

    internal static class Ipv4
    {
        // Canonical dotted decimal only. IPAddress.TryParse alone also accepts "10.1", "0x0A.0.0.1", and leading
        // zeros that other parsers read as octal. Requiring the parsed address to print back as the same text
        // rejects every such form, so two programs cannot disagree about which address a string names.
        internal static bool TryParseStrict(string text, out IPAddress address)
        {
            if (text != null && IPAddress.TryParse(text, out address) &&
                address.AddressFamily == AddressFamily.InterNetwork && address.ToString() == text)
            {
                return true;
            }

            address = null;
            return false;
        }
    }
}
