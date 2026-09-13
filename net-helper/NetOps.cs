// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace MessageFoundry.NetHelper
{
    internal static class NetOps
    {
        // A budget for ONE REQUEST, not one netsh run, so a hung netsh cannot hold the pipe indefinitely.
        // `bind` runs netsh twice when it re-plumbs, and PipeServer publishes a worst-case queued wait built
        // on this number; a per-run cap would silently double it and make that published figure wrong.
        internal static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(10);

        // Runs one operation. Every value passed to Windows comes from HelperConfig: the request only chose the
        // op, after its fields matched the configuration exactly.
        internal static string Apply(string op, HelperConfig config)
        {
            DateTime deadline = DateTime.UtcNow + CommandTimeout;

            NetworkInterface nic = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => string.Equals(n.Name, config.Interface, StringComparison.Ordinal));
            if (nic == null)
            {
                return "interface not found";
            }

            // Presence, nothing more. `release` depends on this being true for an address in ANY state: an
            // address that failed duplicate detection is still plumbed, and must still be removable.
            bool held = nic.GetIPProperties().UnicastAddresses.Any(u => u.Address.Equals(config.Address));

            // store=active: the address does not survive a reboot, so a restarted node never comes back
            // holding the VIP without winning the lease again.
            // skipassource=true: the engine's own outbound connections, its lease heartbeat to the
            // database among them, must not choose the VIP as their source address, or releasing the VIP
            // would cut the very connection that renews the lease.
            string add = "interface ipv4 add address name=\"" + config.Interface + "\" address=" + config.Address +
                " mask=" + config.Mask + " store=active skipassource=true";
            string delete = "interface ipv4 delete address name=\"" + config.Interface + "\" address=" + config.Address +
                " store=active";

            switch (op)
            {
                case "bind":
                    // "Ensure present AND announced."
                    //
                    // Windows emits the gratuitous ARP that ADR 0056 AC-1 requires as a side effect of PLUMBING
                    // the address -- duplicate-address probes, then `who-has <vip> tell <vip>`. It emits nothing
                    // when the address is already there. So the old "return success having run nothing" path was
                    // silent on the wire in exactly the case that matters: a node promoting while it still holds
                    // the VIP from a crashed failover, a failed release, or an operator's hand. Every peer's ARP
                    // cache stayed stale and no error was raised.
                    //
                    // Measured on Windows Server 2025 build 26100.33296 on 2026-09-11 (BACKLOG #1522): a repeated
                    // bind put no ARP frame on the wire at all, while delete-then-add emitted the full probe and
                    // announce sequence. Re-plumbing is therefore what makes the announcement unconditional.
                    //
                    // The announcement is NOT complete when this returns: it trails the add by roughly 5 seconds,
                    // with about 3 seconds of duplicate detection inside that. A successful bind means the stack
                    // accepted the address, never that peers have converged.
                    if (held)
                    {
                        string removed = RunNetsh(delete, deadline);
                        if (removed != null)
                        {
                            return removed;
                        }
                    }

                    return RunNetsh(add, deadline);
                case "release":
                    // "Ensure absent", so the self-fence path can call it without asking whether a bind happened.
                    return held ? RunNetsh(delete, deadline) : null;
                default:
                    return "unknown op";
            }
        }

        private static string RunNetsh(string arguments, DateTime deadline)
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

                // What is left of the REQUEST's budget, so a re-plumb's two runs cannot outlast one request.
                // Clamped at zero: a budget already spent still gets a kill and the same message, never a
                // negative timeout (which WaitForExit would read as "wait forever").
                TimeSpan remaining = deadline - DateTime.UtcNow;
                int budget = remaining > TimeSpan.Zero ? (int)remaining.TotalMilliseconds : 0;
                if (!process.WaitForExit(budget))
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
    }
}
