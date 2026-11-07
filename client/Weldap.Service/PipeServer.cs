using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using static Weldap.Service.Native;

namespace Weldap.Service;

/// <summary>
/// \\.\pipe\weldap (SR-5): <see cref="Instances"/> instances, the first created with FILE_FLAG_FIRST_PIPE_INSTANCE,
/// all with PIPE_REJECT_REMOTE_CLIENTS and the DACL allow SYSTEM / deny NETWORK (so only SYSTEM can add an
/// instance), each served by its own loop and reused for every connection, so the name is never free for another
/// process to take while we run. Several instances, because sign-ins on several sessions at once (RDP, fast user
/// switching, a lock screen) must not queue behind one another's server round trip.
///
/// Stability rule: nothing a client does can stop the loop. A client may leave at any moment -- before it is
/// accepted, mid-request, while the reply is written -- and .NET then marks the pipe Broken, which makes the next
/// accept throw. So after every client the instance is reset whatever state it is in (<see cref="Reset"/>), every
/// per-client fault is contained, and every wait is bounded by the serve deadline.
/// </summary>
internal sealed partial class PipeServer(Func<LoginRequest, LoginReply> handle, ILogger<PipeServer> log)
{
    private const string Sddl = "O:SYG:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)";
    // Per-connection serve deadline, inside the credential provider's 15 s end-to-end budget
    // (WELDAP_CLIENT_DEADLINE_MS); the server round trip within it is capped at LoginSettings.ServerBudgetSeconds.
    private const int DeadlineSeconds = 14;
    // Accept failures in a row before the instance is treated as unusable (the service then exits non-zero and the
    // Service Control Manager restarts it). One client coming and going before it is accepted is one failure.
    private const int MaxAcceptFailures = 50;
    private const int Instances = 8;
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    public async Task RunAsync(CancellationToken stop)
    {
        var pipes = new List<NamedPipeServerStream>();
        try
        {
            pipes.Add(await CreatePipeAsync(stop).ConfigureAwait(false));
            for (var i = 1; i < Instances; i++)
                pipes.Add(TryCreatePipe(first: false, out var error) ?? throw new InvalidOperationException($"pipe instance: {error}"));
            await Task.WhenAll(pipes.Select(p => ServeAsync(p, stop))).ConfigureAwait(false);
        }
        finally
        {
            foreach (var p in pipes) await p.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>One instance's loop: accept, serve, reset, for as long as the service runs.</summary>
    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stop)
    {
        var failures = 0;
        while (!stop.IsCancellationRequested)
        {
            try
            {
                await pipe.WaitForConnectionAsync(stop).ConfigureAwait(false);
                failures = 0;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException ex)
            {
                // A client connected and left before we accepted it (ERROR_NO_DATA): reset and wait for the next.
                Reset(pipe);
                if (++failures >= MaxAcceptFailures) throw new InvalidOperationException("pipe: accept keeps failing", ex);
                await Task.Delay(TimeSpan.FromMilliseconds(100), stop).ConfigureAwait(false);
                continue;
            }

            try
            {
                if (IsSystemClient(pipe)) await ServeOneAsync(pipe, stop).ConfigureAwait(false);
                else LogRejectedClient(log);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
                // Client went away or blew the deadline: nothing to answer.
            }
#pragma warning disable CA1031 // one client must never stop the loop (and with it every sign-in on this PC)
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                LogRequestFailed(log, ex.GetType().Name); // type only: messages are not ours to vouch for
            }
#pragma warning restore CA1031
            finally
            {
                Reset(pipe);
            }
        }
    }

    /// <summary>
    /// Ready the one instance for the next client, whatever the last one left it as. .NET's Disconnect also
    /// works on a Broken pipe (IsConnected is false then, which is why it must not be the test); a connect that
    /// failed before .NET counted it as connected needs the native call.
    /// </summary>
    private static void Reset(NamedPipeServerStream pipe)
    {
        try
        {
            pipe.Disconnect();
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException)
        {
            _ = DisconnectNamedPipe(pipe.SafePipeHandle);
        }
    }

    private async Task ServeOneAsync(NamedPipeServerStream pipe, CancellationToken stop)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop);
        deadline.CancelAfter(TimeSpan.FromSeconds(DeadlineSeconds));

        var frame = await ProtocolCodec.ReadFrameAsync(pipe, deadline.Token).ConfigureAwait(false);
        if (frame is null) return;
        LoginRequest? request;
        try
        {
            request = ProtocolCodec.TryParseRequest(frame);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frame);
        }
        if (request is null) return; // malformed: drop, no reply

        LoginReply reply;
        using (request)
        {
            try
            {
                reply = handle(request);
            }
#pragma warning disable CA1031 // one bad request must never stop the service (and with it every sign-in)
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                LogRequestFailed(log, ex.GetType().Name);
                reply = LoginReply.Error("Sign-in failed on this PC. Try again, or contact IT.");
            }
#pragma warning restore CA1031
        }
        // The reply (and its encoding) may hold the local account password: zero both once it is sent.
        using (reply)
        {
            var payload = ProtocolCodec.EncodeReply(reply);
            try
            {
                await ProtocolCodec.WriteFrameAsync(pipe, payload, deadline.Token).ConfigureAwait(false);
                // Wait, within the deadline, for the client to close its end: disconnecting first would discard a
                // reply it has not read yet. (Not WaitForPipeDrain, which has no timeout: a hung client would hold
                // the only pipe instance, and every sign-in, for ever.)
                var eof = new byte[1];
                _ = await pipe.ReadAsync(eof, deadline.Token).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
    }

    /// <summary>
    /// Creates the instance. While another process holds the name (squatting while we were stopped or restarting),
    /// retry with backoff instead of exiting: the provider refuses a pipe server that is not SYSTEM, so a squatter
    /// can delay sign-ins but never answer them, and exiting would make the delay permanent.
    /// </summary>
    private async Task<NamedPipeServerStream> CreatePipeAsync(CancellationToken stop)
    {
        for (var delay = TimeSpan.FromSeconds(1); ; delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 30)))
        {
            if (TryCreatePipe(first: true, out var error) is { } pipe) return pipe;
            LogPipeUnavailable(log, error);
            await Task.Delay(delay, stop).ConfigureAwait(false);
        }
    }

    private static unsafe NamedPipeServerStream? TryCreatePipe(bool first, out int error)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(Sddl, 1, out var sd, IntPtr.Zero))
            throw new InvalidOperationException($"SDDL: {Marshal.GetLastPInvokeError()}");
        try
        {
            var sa = new SECURITY_ATTRIBUTES { nLength = sizeof(SECURITY_ATTRIBUTES), lpSecurityDescriptor = sd };
            var handle = CreateNamedPipe($@"\\.\pipe\{Protocol.PipeName}",
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                Instances, Protocol.MaxMessageBytes + 4, Protocol.MaxMessageBytes + 4, 0, &sa);
            error = Marshal.GetLastPInvokeError();
            if (handle.IsInvalid)
            {
                handle.Dispose();
                return null;
            }
            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
        }
        finally
        {
            LocalFree(sd);
        }
    }

    private static bool IsSystemClient(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid)) return false;
        using var process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process.IsInvalid) return false;
        if (!OpenProcessToken(process, TOKEN_QUERY, out var token)) return false;
        using (token)
        using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
        {
            return identity.User == LocalSystem;
        }
    }

    [LoggerMessage(EventId = 1510, Level = LogLevel.Error, Message = "Request failed: {ExceptionType}")]
    private static partial void LogRequestFailed(ILogger logger, string exceptionType);

    [LoggerMessage(EventId = 1511, Level = LogLevel.Warning, Message = "Rejected pipe client not running as SYSTEM")]
    private static partial void LogRejectedClient(ILogger logger);

    [LoggerMessage(EventId = 1512, Level = LogLevel.Error, Message = "Cannot create the WELDAP pipe (error {Error}; is another process holding the name?); retrying")]
    private static partial void LogPipeUnavailable(ILogger logger, int error);
}
