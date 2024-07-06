namespace ICMPv6DotNet.Payloads.NDP
{
    public enum NeighborDiscoveryOption
    {
        Invalid = 0,
        SourceLinklayerAddress = 1, //RFC 4861
        TargetLinkLayerAddress = 2, //RFC 4861
        PrefixInformation = 3, //RFC 4861
        RedirectedHeader = 4, //RFC 4861
        MTU = 5 //RFC 4861
    }
}
