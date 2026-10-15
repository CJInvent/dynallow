using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text;
namespace DynAllow;
// Portable cryptographic tests use ephemeral keys; never touch machine identity or service APIs.
internal static class SelfTest
{
    static void Check(bool b, string name) { if (!b) throw new Exception("FAIL: " + name); Console.WriteLine("PASS: " + name); }
    static void Reject(Action a, string name) { try { a(); } catch { Console.WriteLine("PASS: " + name); return; } throw new Exception("FAIL accepted: " + name); }
    public static void Run(string[] args)
    {
        using var server = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var state = new JsonObject { ["server_key"] = Crypto.B64(Crypto.Raw(server.ExportParameters(false))), ["server_key_id"] = "test-server" };
        var plain = new JsonObject { ["nonce"] = "abcdef0123456789abcdef0123456789", ["type"] = "checkin" };
        var (body, ctx) = Wire.Seal(state, plain, d => signer.SignData(d, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        var env = J.Obj(body); using var eph = ECDiffieHellman.Create(Crypto.Params(Crypto.B(env.S("epk"))));
        var k = server.DeriveKeyFromHash(eph.PublicKey, HashAlgorithmName.SHA256, Crypto.U("IPF1"), Crypto.B(env.S("epk")));
        var enc = Crypto.H(k, Crypto.U("req-enc"));
        Check(Encoding.UTF8.GetString(Crypto.Decrypt(enc, Crypto.B(env.S("iv")), Crypto.B(env.S("ct")))) == plain.ToJsonString(), "IPF1 ECDH/AES request round trip");
        var resp = new JsonObject { ["req_nonce"] = plain.S("nonce"), ["ok"] = true };
        var iv = RandomNumberGenerator.GetBytes(16); var ct = Crypto.Encrypt(ctx.ResponseEnc, iv, Crypto.U(resp.ToJsonString()));
        var wire = new JsonObject { ["v"] = 1, ["iv"] = Crypto.B64(iv), ["ct"] = Crypto.B64(ct), ["mac"] = Crypto.B64(Crypto.H(ctx.ResponseMac, Crypto.Join(Crypto.U("IPF1|resp|"), ctx.Epk, iv, ct))) };
        Check(Wire.Open(ctx, wire.ToJsonString()).B("ok"), "authenticated response");
        Reject(() => Wire.Open(ctx with { Nonce = "wrong" }, wire.ToJsonString()), "response nonce binding");
        wire["mac"] = Crypto.B64(new byte[32]); Reject(() => Wire.Open(ctx, wire.ToJsonString()), "tampered MAC");
        using var release = ECDsa.Create(ECCurve.NamedCurves.nistP256); var bytes = Crypto.U("test executable");
        var m = new JsonObject { ["format"] = "dynallow-release-v1", ["target"] = "windows-x64", ["sequence"] = 2, ["version"] = "3.0.1", ["files"] = new JsonArray(new JsonObject { ["name"] = "DynAllow.Agent.exe", ["size"] = bytes.Length, ["sha256"] = Crypto.Hex(SHA256.HashData(bytes)) }) };
        byte[] raw = Crypto.U(m.ToJsonString()); var b = new JsonObject { ["manifest"] = Crypto.B64(raw), ["signature"] = Crypto.B64(release.SignData(raw, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)), ["files"] = new JsonObject { ["DynAllow.Agent.exe"] = Crypto.B64(bytes) } };
        string pem = release.ExportSubjectPublicKeyInfoPem();
        Check(Updates.Verify(b.ToJsonString(), pem, "windows-x64", 1, "3.0.0").Executable.SequenceEqual(bytes), "offline signed release accepted");
        Reject(() => Updates.Verify(b.ToJsonString(), signer.ExportSubjectPublicKeyInfoPem(), "windows-x64", 1, "3.0.0"), "wrong offline public key");
        Reject(() => Updates.Verify(b.ToJsonString(), pem, "windows-arm64", 1, "3.0.0"), "wrong architecture");
        Reject(() => Updates.Verify(b.ToJsonString(), pem, "windows-x64", 2, "3.0.0"), "sequence rollback/replay");
        Reject(() => Updates.Verify(b.ToJsonString(), pem, "windows-x64", 1, "3.0.1"), "version rollback/replay");
        b["files"]!["DynAllow.Agent.exe"] = Crypto.B64(Crypto.U("tampered"));
        Reject(() => Updates.Verify(b.ToJsonString(), pem, "windows-x64", 1, "3.0.0"), "tampered executable");
        if (args.Length > 0) {
            Directory.CreateDirectory(args[0]);
            File.WriteAllText(Path.Combine(args[0], "csharp-request.json"), body);
            File.WriteAllText(Path.Combine(args[0], "server-private.pem"), server.ExportECPrivateKeyPem());
            File.WriteAllText(Path.Combine(args[0], "agent-public.pem"), signer.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(Path.Combine(args[0], "release-public.pem"), pem);
            b["files"]!["DynAllow.Agent.exe"] = Crypto.B64(bytes);
            File.WriteAllText(Path.Combine(args[0], "csharp-release.json"), b.ToJsonString());
        }
    }
}
