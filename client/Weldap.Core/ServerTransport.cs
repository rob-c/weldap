using System.Buffers.Binary;

namespace Weldap;

/// <summary>
/// One framed request/reply over an already-connected, already-authenticated stream to the WELDAP server
/// (server/src/server.rs): a 4-byte <b>big-endian</b> length, then that many bytes of JSON, both ways. This is
/// the Windows-independent half of <c>ServerClient</c>: ServerClient opens the TCP socket and the pinned TLS
/// stream, then hands it here. Everything that can go wrong on the wire — a stuck or truncating link, a
/// middlebox that injects bytes or lies about the length, a reset connection — is turned into a "no answer"
/// result (with a short, non-secret reason), which the login flow treats as the offline path. It never throws
/// for an I/O or protocol fault, and never blocks past the deadline.
/// </summary>
public static class ServerTransport
{
    /// <summary>The reply is small JSON; anything larger is a broken or hostile peer, not the real server.</summary>
    public const int MaxReplyBytes = 64 * 1024;

    /// <summary>
    /// Sends <paramref name="request"/> and reads exactly one reply frame, giving up after <paramref name="deadline"/>.
    /// Trailing bytes after the frame are left unread (one request, one reply per connection), so a peer that
    /// appends garbage cannot corrupt the reply.
    /// </summary>
    public static async Task<ServerReply> ExchangeAsync(Stream stream, byte[] request, TimeSpan deadline, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(request);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (deadline > TimeSpan.Zero) cts.CancelAfter(deadline);
        var token = cts.Token;
        try
        {
            var header = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(header, (uint)request.Length);
            await stream.WriteAsync(header, token).ConfigureAwait(false);
            await stream.WriteAsync(request, token).ConfigureAwait(false);
            await stream.FlushAsync(token).ConfigureAwait(false);

            await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadUInt32BigEndian(header);
            if (length is 0 or > MaxReplyBytes) return ServerReply.NoAnswer("server: bad reply length");

            var reply = new byte[length];
            await stream.ReadExactlyAsync(reply, token).ConfigureAwait(false);
            return ServerReply.Ok(reply);
        }
        // The caller's own cancellation (service stopping) propagates; only our deadline becomes "no answer".
        catch (OperationCanceledException) when (cts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return ServerReply.NoAnswer("server: timeout");
        }
        catch (EndOfStreamException)
        {
            return ServerReply.NoAnswer("server: connection closed");
        }
#pragma warning disable CA1031 // deliberately broad: any failure to talk to the server is "no answer" (the offline path)
        catch (Exception ex) when (ex is not OutOfMemoryException and not OperationCanceledException)
        {
            // IOException/SocketException, and anything else a broken link throws after the handshake.
            return ServerReply.NoAnswer($"server: {ex.GetType().Name}");
        }
#pragma warning restore CA1031
    }

    /// <summary>Maps a transport result to a login answer: a reply is parsed, no reply is the offline path.</summary>
    public static ServerAnswer ToAuthAnswer(ServerReply result) =>
        result.Reply is { } reply ? ServerMessages.ParseAuthReply(reply) : ServerAnswer.NoAnswer(result.Why);

    /// <summary>Maps a transport result to a status snapshot: null (no change) when there was no usable answer.</summary>
    public static StatusSnapshot? ToStatus(ServerReply result, IReadOnlyCollection<string> asked) =>
        result.Reply is { } reply ? ServerMessages.ParseStatusReply(reply, asked) : null;
}

/// <summary>A server reply body, or null with a one-line (non-secret) reason when there was no usable answer.</summary>
public readonly record struct ServerReply(byte[]? Reply, string Why)
{
    public static ServerReply NoAnswer(string why) => new(null, why);
    public static ServerReply Ok(byte[] reply) => new(reply, "");
}
