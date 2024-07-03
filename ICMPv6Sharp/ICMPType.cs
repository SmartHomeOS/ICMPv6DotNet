﻿namespace ICMPv6DotNet
{
    public enum ICMPType
    {
        Invalid = 0,
        DestinationUnreachable = 1,
        PacketTooBig = 2,
        TimeExceeded = 3,
        ParameterProblem = 4,
        PrivateExperimentationError = 100,
        PrivateExperimentationError2 = 101,
        EchoRequest= 128,
        EchoReply = 129,
        MLDQuery = 130,
        MLDReport = 131,
        MLDDone = 132,
        RouterSolicitation = 133,
        RouterAdvertisement = 134,
        NeighborSolicitation = 135,
        NeighborAdvertisement = 136,
        RedirectMessage = 137,
        RouterRenumbering = 138,
        NodeInformationQuery = 139,
        NodeInformationResponse = 140,
        InverseNeighborDiscoverySolicitation = 141,
        InverseNeighborDiscoveryAdvertisement = 142,
        MLDv2Report = 143,
        HomeAgentAddressDiscoveryRequest = 144,
        HomeAgentAddressDiscoveryReply = 145,
        MobilePrefixSolicitation = 146,
        MobilePrefixReply = 147,
        CertificationPathSolicitation = 148,
        CertificationPathAdvertisement = 149,
        MulticastRouterAdvertisement = 151,
        MulticastRouterSolicitation = 152,
        MulticastRouterTermination = 153,
        RPLControl = 155,
        PrivateExperimentationInfo = 200,
        PrivateExperimentationInfo2 = 201,
    }
}
