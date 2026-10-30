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
/// TCP socket (connect timeout, keep-alive) and the pinned TLS stream — and then hands the stream to
/// <see cref="ServerTransport"/> (in Weldap.Core), which does the framing and turns every wire fault into
/// "no answer" (the offline path). It carries the sealed password, which this process cannot open.
/// </summary>
internal sealed class ServerClient(LoginSettings settings) : IWeldapServer
{
    public ServerAnswer Authenticate(string uun, Scenario scenario, SealedPassword sealedPassword) =>
        ServerTransport.ToAuthAnswer(Exchange(ServerMessages.Auth(uun, scenario, sealedPassword)));

    public StatusSnapshot? ReadStatus(IReadOnlyCollection<string> uuns) =>
        ServerTransport.ToStatus(Exchange(ServerMessages.Status(uuns)), uuns);

    /// <summary>Opens the pinned TLS stream and exchanges one framed request/reply over it.</summary>
    private ServerReply Exchange(byte[] body)
    {
        using var cert = DeviceCertificate(out var why);
        if (cert is null) return ServerReply.NoAnswer(why);

        var serverOk = false;
        try
        {
            using var tcp = new TcpClient();
            tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            if (!tcp.ConnectAsync(settings.ServerHost, settings.ServerPort)
                    .Wait(TimeSpan.FromSeconds(LoginSettings.ConnectTimeoutSeconds)))
                return ServerReply.NoAnswer("server: connect timeout");

            using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            tls.AuthenticateAsClient(new SslClientAuthenticationOptions
            {
                TargetHost = settings.ServerHost,
                ClientCertificates = [cert],
                LocalCertificateSelectionCallback = (_, _, _, _, _) => cert,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    serverOk = certificate is not null && ServerMessages.MatchesPin(certificate, settings.ServerPins),
            });

            return ServerTransport.ExchangeAsync(tls, body, TimeSpan.FromSeconds(LoginSettings.TimeoutSeconds),
                CancellationToken.None).GetAwaiter().GetResult();
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
