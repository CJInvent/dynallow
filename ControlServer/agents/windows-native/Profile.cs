using System.Security.Cryptography;
using System.Text.Json.Nodes;
namespace DynAllow;
// The ONE place a provisioning profile is judged. The installer, the service and the
// cross-language contract test (tests/run_v3.py) all call this, so they cannot drift apart.
internal static class Profile
{
    public const string Format = "dynallow-provisioning";
    // Profiles issued before the rename are still honored; nothing else is.
    const string LegacyFormat = "ipfailover-provisioning";
    public static JsonObject Validate(JsonObject p)
    {
        if (p.S("format") is not (Format or LegacyFormat)) throw new InvalidDataException("Not a DynAllow provisioning profile (format '" + AgentLog.Clean(p.S("format")) + "', expected '" + Format + "')");
        if (p.S("enroll_token") == "" || p.S("agent_uid") == "") throw new InvalidDataException("Provisioning profile is missing its enrollment token or site id");
        if (!Uri.TryCreate(p.S("control_url"), UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https") || uri.UserInfo != "") throw new InvalidDataException("Provisioning profile has an invalid control server URL");
        using var pub = ECDsa.Create(Crypto.Params(Crypto.B(p.S("server_key")))); // pinned server key must be a valid P-256 point
        return p;
    }
}
