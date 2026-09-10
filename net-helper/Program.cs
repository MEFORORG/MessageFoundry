// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
//
// mefor-net-helper: the privileged helper ADR 0056 specifies for engine-managed VIP failover.
//
// The engine runs least-privileged (DEPLOY-1), and moving an IP address needs administrator rights. This
// process holds those rights and does four things for one caller: report its version, bind one configured
// IPv4 address, release it, and announce it. Every request arrives over a named pipe and runs as
// administrator, so every byte on that pipe is untrusted input.
//
// PATIENT DATA: this binary never sees any, by construction. A request carries an operation name, an IPv4
// address, an interface name and a netmask, and any other field is refused. Log only those validated
// fields and the caller's account, so no later change can route message content through here.

using System;
using System.Globalization;
using System.IO;
using System.Reflection;

namespace MessageFoundry.NetHelper
{
    internal static class Program
    {
        // The csproj <Version> as major.minor.patch, which `ping` reports.
        internal static readonly string Version = Assembly.GetExecutingAssembly().GetName().Version.ToString(3);

        private static int Main()
        {
            AppDomain.CurrentDomain.UnhandledException += (sender, e) => Log.Error("fatal: " + e.ExceptionObject);

            HelperConfig config;
            try
            {
                config = HelperConfig.Load(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, HelperConfig.FileName));
            }
            catch (ConfigException ex)
            {
                // Refuse to start rather than serve with a scope that was guessed.
                Log.Error("startup refused: " + ex.Message);
                return 2;
            }

            Log.Info("version " + Version + " starting; scope " + config.Scope + " mask=" + config.Mask +
                     " client=\"" + config.ClientName + "\"");
            return PipeServer.Run(config);
        }
    }

    // One line per event on stdout, which NSSM redirects to a file (README.md). UTC, labelled with Z.
    internal static class Log
    {
        private static readonly object Gate = new object();

        internal static void Info(string message) { Write("INFO", message); }

        internal static void Warn(string message) { Write("WARN", message); }

        internal static void Error(string message) { Write("ERROR", message); }

        private static void Write(string level, string message)
        {
            string stamp = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            lock (Gate)
            {
                Console.Out.WriteLine(stamp + " " + level + " " + message);
                Console.Out.Flush();
            }
        }
    }
}
