using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Weldap;

namespace Weldap.Service;

/// <summary>
/// This device's only network peer: the WELDAP server, over TLS 1.2/1.3 with the device's registered
/// certificate (SR-14). The server is trusted by its key pin alone (no CA, no name check), so no certificate
/// authority can stand in for it. This class is the Windows-only shell — pick the device certificate, open the
/// TCP socket and the pinned TLS stream — and then hands the stream to <see cref="ServerTransport"/> (in
/// Weldap.Core), which does the framing and turns every wire fault into "no answer" (the offline path). It
/// carries the sealed password, which this process cannot open.
///
/// Every step is bounded by one budget (<see cref="LoginSettings.ServerBudgetSeconds"/>): a server that accepts
/// TCP and then stalls -- a paused container, a path lost mid-handshake, a middlebox holding the connection --
/// costs a sign-in at most that long, never the account lock and the pipe for the keep-alive horizon.
/// </summary>
internal sealed class ServerClient(LoginSettings settings) : IWeldapServer
{
    public ServerAnswer Authenticate(string uun, Scenario scenario, SealedPassword sealedPassword) =>
        ServerTransport.ToAuthAnswer(Exchange(ServerMessages.Auth(uun, scenario, sealedPassword)));

    public StatusSnapshot? ReadStatus(IReadOnlyCollection<string> uuns) =>
        ServerTransport.ToStatus(Exchange(ServerMessages.Status(uuns)), uuns);

    /// <summary>Opens the pinned TLS stream and exchanges one framed request/reply over it, within the budget.</summary>
    private ServerReply Exchange(byte[] body)
    {
        using var cert = DeviceCertificate(out var why);
        if (cert is null) return ServerReply.NoAnswer(why);

        var serverOk = false;
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(LoginSettings.ServerBudgetSeconds));
        try
        {
            return ExchangeAsync(body, cert, ok => serverOk = ok, budget).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            return ServerReply.NoAnswer("server: timeout");
        }
        catch (AuthenticationException)
        {
            return ServerReply.NoAnswer(serverOk ? "tls: handshake refused" : "tls: server key does not match the pin");
        }
#pragma warning disable CA1031 // deliberately broad: any failure to reach the server is "no answer"
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Connect/socket errors and TLS alerts during the handshake (e.g. a refused device certificate).
            return ServerReply.NoAnswer($"server: {ex.GetType().Name}");
        }
#pragma warning restore CA1031
    }

    private async Task<ServerReply> ExchangeAsync(byte[] body, X509Certificate2 cert, Action<bool> pinned, CancellationTokenSource budget)
    {
        using var tcp = await ConnectAsync(budget.Token).ConfigureAwait(false);
        if (tcp is null) return ServerReply.NoAnswer("server: connect timeout");

        using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = settings.ServerHost,
            ClientCertificates = [cert],
            LocalCertificateSelectionCallback = (_, _, _, _, _) => cert,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            {
                var ok = certificate is not null && ServerMessages.MatchesPin(certificate, settings.ServerPins);
                pinned(ok);
                return ok;
            },
        }, budget.Token).ConfigureAwait(false);

        // The rest of the budget for the request and reply; a deadline here is "no answer" (ServerTransport).
        return await ServerTransport.ExchangeAsync(tls, body, TimeSpan.FromSeconds(LoginSettings.ServerBudgetSeconds),
            budget.Token).ConfigureAwait(false);
    }

    /// <summary>
    /// A connection to the first of the server's addresses that answers, or null. Each address gets its own
    /// ConnectTimeoutSeconds (within the overall budget), so one that never answers -- an IPv6 black hole, a dead
    /// node of a round-robin pair -- cannot use up the time before a working one is tried.
    /// </summary>
    private async Task<TcpClient?> ConnectAsync(CancellationToken budget)
    {
        var addresses = IPAddress.TryParse(settings.ServerHost, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(settings.ServerHost, budget).ConfigureAwait(false);
        foreach (var address in addresses)
        {
            var tcp = new TcpClient(address.AddressFamily);
            var connected = false;
            try
            {
                tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(budget);
                attempt.CancelAfter(TimeSpan.FromSeconds(LoginSettings.ConnectTimeoutSeconds));
                await tcp.ConnectAsync(address, settings.ServerPort, attempt.Token).ConfigureAwait(false);
                connected = true;
                return tcp;
            }
            catch (Exception ex) when (ex is SocketException || (ex is OperationCanceledException && !budget.IsCancellationRequested))
            {
                // This address does not answer: try the next.
            }
            finally
            {
                if (!connected) tcp.Dispose();
            }
        }
        return null;
    }

    /// <summary>The newest currently valid LocalMachine\My certificate named "WELDAP device" (register-device.ps1)
    /// that has its private key; null (with the reason) if there is none.</summary>
    private static X509Certificate2? DeviceCertificate(out string why)
    {
        var now = DateTime.Now;
        X509Certificate2? best = null;
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var cert in store.Certificates)
            {
                if (cert.FriendlyName == LoginSettings.DeviceCertificateName && cert.NotBefore <= now && now < cert.NotAfter
                    && cert.HasPrivateKey && (best is null || cert.NotBefore > best.NotBefore))
                {
                    best?.Dispose();
                    best = cert;
                }
                else
                {
                    cert.Dispose();
                }
            }
        }
        catch (CryptographicException ex)
        {
            best?.Dispose();
            why = $"device-cert: store: {ex.Message}";
            return null;
        }
        why = best is null ? "device-cert: this device is not registered" : "";
        return best;
    }
}
