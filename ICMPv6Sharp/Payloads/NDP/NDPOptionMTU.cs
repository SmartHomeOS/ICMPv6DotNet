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

using System.Buffers.Binary;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPOptionMTU : NDPOption
    {
        public NDPOptionMTU(Span<byte> buffer)
        {
            MTU = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(4, 4));
        }

        public NDPOptionMTU(uint mtu)
        {
            MTU = mtu;
        }

        public override string ToString()
        {
            return $"MTU: {MTU}";
        }

        public override int WritePacket(Span<byte> buffer)
        {
            buffer[0] = (byte)NeighborDiscoveryOption.MTU;
            buffer[1] = 1;
            buffer.Slice(2, 2).Clear();
            BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(4), MTU);
            return 8;
        }

        public uint MTU { get; private set; }
    }
}
