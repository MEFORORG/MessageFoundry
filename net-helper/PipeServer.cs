// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors

using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace MessageFoundry.NetHelper
{
    internal static class PipeServer
    {
        // Fixed by the wire contract. Deliberately not configurable.
        private const string PipeName = "mefor-net-helper";
        private const string PipePath = @"\\.\pipe\" + PipeName;

        // A request is one short JSON line. Anything longer is not a request.
        private const int MaxRequestBytes = 1024;

        // How long a connected caller has to send its request, and later to close after reading the reply.
        // Callers are served one at a time, so a queued caller can wait for Deadline (the current caller's
        // read), plus NetOps.CommandTimeout (its netsh run), plus Deadline again (its close): 20 seconds with
        // today's values. The engine-side controller owns the release deadline and must budget for that.
        private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(5);

        private static readonly SecurityIdentifier Administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier Network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);

        // A read that outlived its deadline. Disconnecting completes it; the next caller is not accepted
        // until it has, so its late bytes can never be read as that caller's request.
        private static IAsyncResult abandonedRead;

        // Returns only when the pipe cannot be created. Otherwise it serves until the process is stopped.
        internal static int Run(HelperConfig config)
        {
            // FirstPipeInstance (FILE_FLAG_FIRST_PIPE_INSTANCE) makes start-up FAIL if another process already
            // holds this pipe name, instead of joining an instance whose ACL that process chose. This one instance
            // then serves every caller in turn, so the name is never free for another process to take while the
            // helper runs.
            NamedPipeServerStream pipe;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(
                    PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                    MaxRequestBytes, MaxRequestBytes, BuildAcl(config.ClientSid));
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                // A name that already exists fails here either way: as "All pipe instances are busy" when the
                // existing pipe is at its instance limit (measured with a second helper running), or as
                // ERROR_ACCESS_DENIED from FILE_FLAG_FIRST_PIPE_INSTANCE when it allows more instances.
                Log.Error("startup refused: cannot create " + PipePath + ", so another process may hold the name: " + ex.Message);
                return 3;
            }

            using (pipe)
            {
                Log.Info("listening on " + PipePath);
                while (true)
                {
                    pipe.WaitForConnection();
                    try
                    {
                        Serve(pipe, config);
                    }
                    catch (IOException ex)
                    {
                        // The caller went away. An operation that already ran stays applied and was logged.
                        Log.Warn("connection dropped: " + ex.Message);
                    }
                    finally
                    {
                        Reset(pipe);
                    }
                }
            }
        }

        // The pipe ACL: deny network logons, allow the configured client account and Administrators to read
        // and write, and keep full control for this process's own account.
        private static PipeSecurity BuildAcl(SecurityIdentifier client)
        {
            var acl = new PipeSecurity();

            // A named pipe is reachable from other machines over SMB unless something refuses it.
            acl.AddAccessRule(new PipeAccessRule(Network, PipeAccessRights.FullControl, AccessControlType.Deny));
            acl.AddAccessRule(new PipeAccessRule(client, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            acl.AddAccessRule(new PipeAccessRule(Administrators, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            using (WindowsIdentity self = WindowsIdentity.GetCurrent())
            {
                acl.AddAccessRule(new PipeAccessRule(self.User, PipeAccessRights.FullControl, AccessControlType.Allow));
            }

            return acl;
        }

        private static void Serve(NamedPipeServerStream pipe, HelperConfig config)
        {
            byte[] line;
            int bytesRead;
            string readError = ReadRequest(pipe, out line, out bytesRead);
            if (bytesRead == 0)
            {
                // Windows allows identifying a pipe client only after reading from it, so there is no caller
                // to name and nothing is owed a reply.
                Log.Warn("outcome=dropped reason=\"" + readError + "\"");
                return;
            }

            string callerName;
            string refusal = Authorize(pipe, config, out callerName);
            string who = "caller=\"" + callerName + "\"";
            if (refusal != null)
            {
                Log.Warn(who + " outcome=refused reason=\"" + refusal + "\"");
                Respond(pipe, Protocol.Failure("caller is not authorized"));
                return;
            }

            // Only now, with the caller authenticated, are its bytes parsed.
            string op = null;
            string error = readError ?? Protocol.TryParse(line, config, out op);
            if (error != null)
            {
                Log.Warn(who + " outcome=refused reason=\"" + error + "\"");
                Respond(pipe, Protocol.Failure(error));
                return;
            }

            if (op == "ping")
            {
                Log.Info("op=ping " + who + " outcome=ok");
                Respond(pipe, Protocol.Pong(Program.Version));
                return;
            }

            string subject = "op=" + op + " " + who + " " + config.Scope;
            string failure = NetOps.Apply(op, config);
            if (failure == null)
            {
                Log.Info(subject + " outcome=ok");
                Respond(pipe, Protocol.Success);
            }
            else
            {
                Log.Error(subject + " outcome=failed error=\"" + failure + "\"");
                Respond(pipe, Protocol.Failure(failure));
            }
        }

        private static string ReadRequest(PipeStream pipe, out byte[] line, out int total)
        {
            line = null;
            total = 0;
            var buffer = new byte[MaxRequestBytes];
            DateTime deadline = DateTime.UtcNow + Deadline;
            while (true)
            {
                if (total == buffer.Length)
                {
                    return "request is longer than " + MaxRequestBytes + " bytes";
                }

                int read;
                if (!TryRead(pipe, buffer, total, deadline, out read))
                {
                    return "request not completed within " + Deadline.TotalSeconds + " seconds";
                }

                if (read == 0)
                {
                    return "connection closed before the request's newline";
                }

                int newline = Array.IndexOf(buffer, (byte)'\n', total, read);
                total += read;
                if (newline >= 0)
                {
                    if (newline != total - 1)
                    {
                        return "one request per connection: bytes follow the newline";
                    }

                    line = new byte[newline];
                    Array.Copy(buffer, line, newline);
                    return null;
                }
            }
        }

        // Reads once, bounded by the deadline. False means the deadline passed with the read still pending.
        private static bool TryRead(PipeStream pipe, byte[] buffer, int offset, DateTime deadline, out int read)
        {
            read = 0;
            IAsyncResult pending = pipe.BeginRead(buffer, offset, buffer.Length - offset, null, null);
            TimeSpan remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero || !pending.AsyncWaitHandle.WaitOne(remaining))
            {
                abandonedRead = pending;
                return false;
            }

            read = pipe.EndRead(pending);
            return true;
        }

        // The pipe ACL already admits only these callers. This check runs anyway, on the caller's own token,
        // because an ACL protects only the pipe instance that carries it.
        private static string Authorize(NamedPipeServerStream pipe, HelperConfig config, out string callerName)
        {
            string name = "unknown";
            string refusal = "caller token was not read";
            pipe.RunAsClient(() =>
            {
                // ifImpersonating: true returns null rather than falling back to this process's own token,
                // which belongs to an administrator and would pass every check below.
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent(true))
                {
                    if (identity == null)
                    {
                        return;
                    }

                    // The configured account's name is already known. Any other caller is logged by SID, because
                    // turning a SID into a name can wait on a domain controller, and the release path cannot.
                    bool isClient = identity.User == config.ClientSid;
                    name = isClient ? config.ClientName : (identity.User == null ? "unknown" : identity.User.Value);
                    var principal = new WindowsPrincipal(identity);
                    if (identity.IsAnonymous)
                    {
                        refusal = "anonymous callers are refused";
                    }
                    else if (principal.IsInRole(Network))
                    {
                        refusal = "remote callers are refused";
                    }
                    else if (isClient || principal.IsInRole(Administrators))
                    {
                        // IsInRole checks token membership, which ignores a deny-only Administrators group,
                        // so an administrator's un-elevated token does not pass here.
                        refusal = null;
                    }
                    else
                    {
                        refusal = "caller is neither the configured client account nor an elevated administrator";
                    }
                }
            });
            callerName = name;
            return refusal;
        }

        private static void Respond(PipeStream pipe, string json)
        {
            byte[] bytes = Protocol.StrictUtf8.GetBytes(json + "\n");
            pipe.Write(bytes, 0, bytes.Length);
            pipe.Flush();
            if (abandonedRead != null)
            {
                // The request read timed out and is still pending, and it will observe the close itself.
                return;
            }

            // Disconnecting discards anything the caller has not read yet, so wait for the caller to close
            // its end first. Bounded, so a caller that never closes cannot hold the pipe.
            var probe = new byte[1];
            int ignored;
            try
            {
                TryRead(pipe, probe, 0, DateTime.UtcNow + Deadline, out ignored);
            }
            catch (IOException)
            {
                // The caller closed its end, which is the normal finish.
            }
        }

        private static void Reset(NamedPipeServerStream pipe)
        {
            try
            {
                pipe.Disconnect();
            }
            catch (InvalidOperationException)
            {
                // Already disconnected, which is the state wanted.
            }

            IAsyncResult pending = abandonedRead;
            abandonedRead = null;
            if (pending != null && !pending.AsyncWaitHandle.WaitOne(Deadline))
            {
                // Should not happen: a disconnect completes pending reads. If one survives, stop rather than
                // risk handing its bytes to the next caller. The service manager restarts the helper.
                throw new IOException("a timed-out read did not complete after disconnect");
            }
        }
    }
}
