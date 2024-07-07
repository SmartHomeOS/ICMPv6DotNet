// ICMPv6DotNet Copyright (C) 2024
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY, without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

namespace ICMPv6DotNet
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
        ExperimentalMobilityProtocols = 150,
        MulticastRouterAdvertisement = 151,
        MulticastRouterSolicitation = 152,
        MulticastRouterTermination = 153,
        RPLControl = 155,
        ILNPv6LocatorUpdate = 156,
        DuplicateAddressRequest = 157,
        DuplicateAddressConfirmation = 158,
        MPLControl = 159,
        ExtendedEchoRequest = 160,
        ExtendedEchoReply = 161,
        PrivateExperimentationInfo = 200,
        PrivateExperimentationInfo2 = 201,
    }
}
