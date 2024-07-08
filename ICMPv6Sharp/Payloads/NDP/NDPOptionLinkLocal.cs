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

using System.Net.NetworkInformation;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPOptionLinkLocal : NDPOption
    {
        public NDPOptionLinkLocal(Span<byte> buffer, bool source)
        {
            if (source)
                SourceAddress = new PhysicalAddress(buffer.Slice(2, buffer.Length - 2).ToArray());
            else
                TargetAddress = new PhysicalAddress(buffer.Slice(2, buffer.Length - 2).ToArray());
        }

        public NDPOptionLinkLocal(PhysicalAddress? address, bool source)
        {
            if (source)
                this.SourceAddress = address;
            else
                this.TargetAddress = address;
        }

        public override int WritePacket(Span<byte> buffer)
        {
            buffer[1] = 1;
            if (SourceAddress != null)
            {
                buffer[0] = (byte)NeighborDiscoveryOption.SourceLinklayerAddress;
                SourceAddress.GetAddressBytes().CopyTo(buffer.Slice(2, 6));
            }
            else if (TargetAddress != null)
            {
                buffer[0] = (byte)NeighborDiscoveryOption.TargetLinkLayerAddress;
                TargetAddress.GetAddressBytes().CopyTo(buffer.Slice(2, 6));
            }
            else
                throw new InvalidDataException("Source and Target Address are not defined");
            return 8;
        }

        public override string ToString()
        {
            if (SourceAddress != null)
                return "Source: " + SourceAddress;
            if (TargetAddress != null)
                return "Target: " + TargetAddress;
            return string.Empty;
        }

        public PhysicalAddress? SourceAddress { get; private set; }
        public PhysicalAddress? TargetAddress { get; private set; }
    }
}
