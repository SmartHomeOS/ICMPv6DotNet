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
