namespace ICMPv6DotNet.Payloads
{
    public enum ErrorReason
    {
        NoRouteToDestination = 0x100,
        CommunicationWithDestinationAdministrativelyProhibited = 0x101,
        BeyondScopeOfSourceAddress = 0x102,
        AddressUnreachable = 0x103,
        PortUnreachable = 0x104,
        SourceAddressFailedIngressEgressPolicy = 0x105,
        RejectRouteToDestination = 0x106,
        ErrorInSourceRoutingHeader = 0x107,
        HeadersTooLong = 0x108,
        HopLimitExceededInTransit = 0x300,
        FragmentReassemblyTimeExceeded = 0x301,
        ErroneousHeaderFieldEncountered = 0x400,
        UnrecognizedNextHeaderTypeEncountered = 0x401,
        UnrecognizedIPv6OptionEncountered = 0x402,
        FirstFragmentHasIncompleteIPv6HeaderChain = 0x403,
        SRUpperLayerHeaderError = 0x404,
        UnrecognizedNextHeadeTypeEncounteredByIntermediateNode = 0x405,
        ExtensionHeaderTooBig = 0x406,
        ExtensionHeaderChainTooLong = 0x407,
        TooManyExtensionHeaders = 0x408,
        TooManyOptionsInExtensionHeader = 0x409,
        OptionTooBig = 0x410
    }
}
