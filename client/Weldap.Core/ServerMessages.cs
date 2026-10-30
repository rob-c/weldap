using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Weldap;

/// <summary>
/// The client side of the server protocol (server/src/server.rs), kept free of I/O so every byte of it is
/// unit-tested: request bodies, strict reply parsing, and the server key pin.
/// </summary>
public static class ServerMessages
{
    public const int MaxStatusUuns = 100;

    public static byte[] Auth(string uun, Scenario scenario, SealedPassword s) => Json(w =>
    {
        w.WriteString("op", "auth");
        w.WriteNumber("v", 1);
        w.WriteString("uun", uun);
        w.WriteString("scenario", scenario == Scenario.Unlock ? "unlock" : "logon");
        w.WriteString("kid", s.Kid);
        w.WriteString("enc", Convert.ToBase64String(s.Enc));
        w.WriteString("ct", Convert.ToBase64String(s.Ct));
        w.WriteNumber("ts", s.Ts);
        w.WriteString("rid", Convert.ToBase64String(s.Rid));
    });

    public static byte[] Status(IReadOnlyCollection<string> uuns) => Json(w =>
    {
        w.WriteString("op", "status");
        w.WriteNumber("v", 1);
        w.WriteStartArray("uuns");
        foreach (var u in uuns.Take(MaxStatusUuns)) w.WriteStringValue(u);
        w.WriteEndArray();
    });

    public static ServerAnswer ParseAuthReply(byte[] reply)
    {
        try
        {
            using var doc = JsonDocument.Parse(reply, Strict);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !IsV1(root)) return ServerAnswer.Failed("server: malformed reply");
            return Str(root, "result") switch
            {
                "ok" when Bool(root, "user") is { } user && Bool(root, "admin") is { } admin =>
                    new ServerAnswer(ServerOutcome.Success, new UserFlags(user, user && admin)),
                "invalid" => new ServerAnswer(ServerOutcome.InvalidCredentials),
                "throttled" => new ServerAnswer(ServerOutcome.Throttled, null, "server: throttled"),
                "unavailable" => ServerAnswer.NoAnswer("server: back end unavailable"),
                "denied" => ServerAnswer.Failed("server: account refused"),
                _ => ServerAnswer.Failed("server: error"),
            };
        }
        catch (JsonException)
        {
            return ServerAnswer.Failed("server: malformed reply");
        }
    }

    /// <summary>The snapshot, or null unless the reply is ok and names only UUNs that were asked about.</summary>
    public static StatusSnapshot? ParseStatusReply(byte[] reply, IReadOnlyCollection<string> asked)
    {
        try
        {
            using var doc = JsonDocument.Parse(reply, Strict);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !IsV1(root) || Str(root, "result") != "ok") return null;
            var known = asked.ToHashSet(StringComparer.Ordinal);
            HashSet<string>? List(string name)
            {
                if (!root.TryGetProperty(name, out var arr) || arr.ValueKind != JsonValueKind.Array) return null;
                var set = new HashSet<string>(StringComparer.Ordinal);
                foreach (var e in arr.EnumerateArray())
                {
                    if (e.ValueKind != JsonValueKind.String || e.GetString() is not { } uun || !known.Contains(uun)) return null;
                    set.Add(uun);
                }
                return set;
            }
            return List("users") is { } users && List("admins") is { } admins ? new StatusSnapshot(users, admins) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>SHA-256 of the certificate's SubjectPublicKeyInfo (base64): the pin form.</summary>
    public static string Pin(X509Certificate certificate)
    {
        using var cert = new X509Certificate2(certificate);
        return Convert.ToBase64String(SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo()));
    }

    public static bool MatchesPin(X509Certificate certificate, IReadOnlyList<string> pins)
    {
        var actual = Pin(certificate);
        return pins.Any(p => CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(p), System.Text.Encoding.ASCII.GetBytes(actual)));
    }

    // A duplicated member ({"result":"invalid","result":"ok"}) is malformed, never resolved in favour of one copy.
    private static readonly JsonDocumentOptions Strict = new() { AllowDuplicateProperties = false };

    private static bool IsV1(JsonElement root) => root.TryGetProperty("v", out var v) && v.ValueKind == JsonValueKind.Number
        && v.TryGetInt32(out var n) && n == 1;

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static bool? Bool(JsonElement e, string name) =>
        e.TryGetProperty(name, out var p) ? p.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null } : null;

    private static byte[] Json(Action<Utf8JsonWriter> body)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            body(w);
            w.WriteEndObject();
        }
        return ms.ToArray();
    }
}
