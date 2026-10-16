namespace DynAllow;
internal static partial class BuildInfo
{
#if DYNALLOW_DEV_UPDATES
    public static readonly bool DevelopmentUpdates = true;
#else
    public static readonly bool DevelopmentUpdates = false;
#endif
    public static string UpdateChannel => DevelopmentUpdates ? "dev-sha256" : "signed";
}
