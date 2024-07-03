namespace ICMPv6DotNet.Packets
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
        HopLimitExceededInTransit = 0x300,
        FragmentReassemblyTimeExceeded = 0x301,
        ErroneousHeaderFieldEncountered = 0x400,
        UnrecognizedNextHeaderTypeEncountered = 0x401,
        UnrecognizedIPv6OptionEncountered = 0x402
    }
}
