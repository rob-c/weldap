using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using static Weldap.Service.Native;

namespace Weldap.Service;

/// <summary>
/// \\.\pipe\weldap (SR-5). One instance, created with FILE_FLAG_FIRST_PIPE_INSTANCE and
/// PIPE_REJECT_REMOTE_CLIENTS, DACL allow SYSTEM / deny NETWORK, and the same handle reused for
/// every connection, so the name is never free for another process to take while we run.
/// </summary>
internal sealed partial class PipeServer(Func<LoginRequest, LoginReply> handle, ILogger<PipeServer> log)
{
    private const string Sddl = "O:SYG:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)";
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    public async Task RunAsync(CancellationToken stop)
    {
        using var pipe = CreatePipe();
        while (!stop.IsCancellationRequested)
        {
            try
            {
                await pipe.WaitForConnectionAsync(stop).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
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
            finally
            {
                if (pipe.IsConnected) pipe.Disconnect();
            }
        }
    }

    private async Task ServeOneAsync(NamedPipeServerStream pipe, CancellationToken stop)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop);
        deadline.CancelAfter(TimeSpan.FromSeconds(14)); // inside the client's 15 s end-to-end budget

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
                LogRequestFailed(log, ex.GetType().Name); // type only: messages are not ours to vouch for
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
                pipe.WaitForPipeDrain();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
    }

    private static unsafe NamedPipeServerStream CreatePipe()
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(Sddl, 1, out var sd, IntPtr.Zero))
            throw new InvalidOperationException($"SDDL: {Marshal.GetLastPInvokeError()}");
        try
        {
            var sa = new SECURITY_ATTRIBUTES { nLength = sizeof(SECURITY_ATTRIBUTES), lpSecurityDescriptor = sd };
            var handle = CreateNamedPipe($@"\\.\pipe\{Protocol.PipeName}",
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1, Protocol.MaxMessageBytes + 4, Protocol.MaxMessageBytes + 4, 0, &sa);
            if (handle.IsInvalid)
                throw new InvalidOperationException($"CreateNamedPipe: {Marshal.GetLastPInvokeError()} (is another instance running?)");
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

    [LoggerMessage(Level = LogLevel.Error, Message = "Request failed: {ExceptionType}")]
    private static partial void LogRequestFailed(ILogger logger, string exceptionType);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Rejected pipe client not running as SYSTEM")]
    private static partial void LogRejectedClient(ILogger logger);
}
