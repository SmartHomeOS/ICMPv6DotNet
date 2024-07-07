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

namespace ICMPv6DotNet.Payloads
{
    public class MulticastRouterAdvertisement : ICMPV6Payload
    {
        readonly bool valid = true;
        public MulticastRouterAdvertisement(Memory<byte> buffer, byte code) : base()
        {
            if (buffer.Length < 4)
            {
                valid = false;
                return;
            }
            AdvertisementInterval = code;
            QueryInterval = BinaryPrimitives.ReadUInt16BigEndian(buffer.Span);
            Robustness = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2).Span);
        }

        public override int WritePacket(Span<byte> buffer)
        {
            //TODO - Ensure code is propagated back up to the packet
            BinaryPrimitives.WriteUInt16BigEndian(buffer, QueryInterval);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2, 2), Robustness);
            return 4;
        }

        public override string ToString()
        {
            return $"Advertisement Interval: {AdvertisementInterval}, Query Interval: {QueryInterval}, Robustness: {Robustness}";
        }

        public override bool IsValid => valid;

        public byte AdvertisementInterval { get; private set; }
        public ushort QueryInterval { get; private set; }
        public ushort Robustness { get; private set; }
    }
}
