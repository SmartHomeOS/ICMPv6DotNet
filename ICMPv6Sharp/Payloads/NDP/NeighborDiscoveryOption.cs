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

namespace ICMPv6DotNet.Payloads.NDP
{
    public enum NeighborDiscoveryOption
    {
        Invalid = 0,
        SourceLinklayerAddress = 1, //RFC 4861
        TargetLinkLayerAddress = 2, //RFC 4861
        PrefixInformation = 3, //RFC 4861
        RedirectedHeader = 4, //RFC 4861
        MTU = 5, //RFC 4861
        NBMAShortcutLimit = 6, //RFC 2491 TODO
        AdvertisementInterval = 7, //RFC 6275 TODO
        HomeAgentInformation = 8, //RFC 6275 TODO
        SourceAddressList = 9, //RFC 3122
        TargetAddressList = 10, //RFC 3122
        //Skipped SEC Extensions
        IPAddressPrefix = 17, //RFC 5568 TODO
        NewRouterPrefixInformation = 18, //RFC 4068 TODO
        LinkLayerAddress = 19, //RFC 5568 TODO
        NeighborAdvertisementAcknowledgment = 20, //RFC 5568 TODO
        RecursiveDNSServer = 25, //RFC 8106 TODO
        DNSSearchList = 31, //RFC 8106 TODO
        ProxySignature = 32, //RFC 6496 TODO
        DHCPCaptivePortal = 37, //RFC 8910 TODO
    }
}
