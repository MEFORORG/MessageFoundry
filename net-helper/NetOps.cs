// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace MessageFoundry.NetHelper
{
    internal static class NetOps
    {
        // A cap on one netsh run, so a hung netsh cannot hold the pipe indefinitely. PipeServer states the
        // longest wait this adds for a queued caller.
        internal static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(10);

        // Runs one operation. Every value passed to Windows comes from HelperConfig: the request only chose the
        // op, after its fields matched the configuration exactly.
        internal static string Apply(string op, HelperConfig config)
        {
            NetworkInterface nic = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => string.Equals(n.Name, config.Interface, StringComparison.Ordinal));
            if (nic == null)
            {
                return "interface not found";
            }

            bool held = nic.GetIPProperties().UnicastAddresses.Any(u => u.Address.Equals(config.Address));
            switch (op)
            {
                case "bind":
                    // "Ensure present", so a repeated bind succeeds without running netsh.
                    // store=active: the address does not survive a reboot, so a restarted node never comes back
                    // holding the VIP without winning the lease again.
                    // skipassource=true: the engine's own outbound connections, its lease heartbeat to the
                    // database among them, must not choose the VIP as their source address, or releasing the VIP
                    // would cut the very connection that renews the lease.
                    return held ? null : RunNetsh(
                        "interface ipv4 add address name=\"" + config.Interface + "\" address=" + config.Address +
                        " mask=" + config.Mask + " store=active skipassource=true");
                case "release":
                    // "Ensure absent", so the self-fence path can call it without asking whether a bind happened.
                    return held ? RunNetsh(
                        "interface ipv4 delete address name=\"" + config.Interface + "\" address=" + config.Address +
                        " store=active") : null;
                case "arp":
                    // Announcing an address this node does not hold would pull its traffic from the node that does.
                    return held ? Announce(nic, config) : "address is not bound on the interface, so it is not announced";
                default:
                    return "unknown op";
            }
        }

        private static string Announce(NetworkInterface nic, HelperConfig config)
        {
            IPAddress gateway = nic.GetIPProperties().GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
            if (gateway == null)
            {
                return "interface has no IPv4 gateway to announce the address to";
            }

            // WHY NOT SendARP(vip, vip), the usual way to ask for a gratuitous ARP: Windows answers a request for
            // one of its own addresses without transmitting anything (measured; ADR 0056, "The helper as built").
            // So this sends an ARP request to the gateway with the VIP as its source instead. Under RFC 826 the
            // gateway, and any host already caching the VIP, update that entry from the sender fields. Whether
            // Windows puts the VIP in the sender field is NOT yet verified on the wire.
            var mac = new byte[8];
            int length = 6;
            int result = SendARP(ToIpAddr(gateway), ToIpAddr(config.Address), mac, ref length);
            return result == 0 ? null : "SendARP to the gateway failed with Windows error " + result;
        }

        private static string RunNetsh(string arguments)
        {
            // A full path, never PATH lookup. This process runs as administrator, and resolving "netsh" by
            // search would run whatever a writable directory offered under that name.
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"), arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Environment.SystemDirectory,
            };

            Process process;
            try
            {
                process = Process.Start(start);
            }
            catch (Win32Exception ex)
            {
                Log.Error("could not start netsh: " + ex.Message);
                return "could not start netsh";
            }

            using (process)
            {
                Task<string> stdout = process.StandardOutput.ReadToEndAsync();
                Task<string> stderr = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit((int)CommandTimeout.TotalMilliseconds))
                {
                    try
                    {
                        process.Kill();
                    }
                    catch (InvalidOperationException)
                    {
                        // It exited between the wait and the kill.
                    }
                    catch (Win32Exception ex)
                    {
                        Log.Error("could not stop a hung netsh: " + ex.Message);
                    }

                    return "netsh did not finish within " + CommandTimeout.TotalSeconds + " seconds";
                }

                if (process.ExitCode == 0)
                {
                    return null;
                }

                // netsh output names adapters and errors, nothing more, but it can span lines.
                string output = (stdout.Result + " " + stderr.Result).Replace('\r', ' ').Replace('\n', ' ').Trim();
                Log.Error("netsh exited " + process.ExitCode + ": " + (output.Length > 300 ? output.Substring(0, 300) : output));
                return "netsh failed with exit code " + process.ExitCode;
            }
        }

        // IPAddr is an IPv4 address in network byte order, read as a native little-endian DWORD.
        private static uint ToIpAddr(IPAddress address)
        {
            return BitConverter.ToUInt32(address.GetAddressBytes(), 0);
        }

        // System32 only: an iphlpapi.dll planted beside the executable must never load into this process. This
        // attribute covers an import bound at run time. NativeAOT binds this one when it links, so the csproj's
        // /DEPENDENTLOADFLAG is what enforces it in the published binary.
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddress, ref int macAddressLength);
    }
}
