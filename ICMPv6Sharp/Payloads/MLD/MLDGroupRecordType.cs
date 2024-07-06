namespace ICMPv6DotNet.Payloads.MLD
{
    public enum MLDGroupRecordType
    {
        Invalid = 0,
        ModeIsInclude = 1,
        ModeIsExcluse = 2,
        ChangeToIncludeMode = 3,
        ChangeToExcludeMode = 4,
        AllowNewSources = 5,
        BlockOldSources = 6
    }
}
