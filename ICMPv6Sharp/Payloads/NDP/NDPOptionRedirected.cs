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
    public class NDPOptionRedirected : NDPOption
    {
        public NDPOptionRedirected(Span<byte> buffer)
        {
            RedirectedPacket = buffer.Slice(8).ToArray();
        }

        public NDPOptionRedirected(byte[] packet)
        {
            RedirectedPacket = packet;
        }

        public override int WritePacket(Span<byte> buffer)
        {
            buffer[0] = (byte)NeighborDiscoveryOption.RedirectedHeader;
            buffer[1] = (byte)((RedirectedPacket.Length + 9) / 8);
            RedirectedPacket.CopyTo(buffer.Slice(2));
            int padding = (buffer[2] * 8) - 2 - RedirectedPacket.Length;
            if (padding > 0)
                buffer.Slice(RedirectedPacket.Length + 2, padding).Clear();
            return buffer[1] * 8;
        }

        public override string ToString()
        {
            if (RedirectedPacket != null)
                return $"Packet Length: {RedirectedPacket.Length}";
            return string.Empty;
        }

        public byte[] RedirectedPacket { get; private set; }
    }
}
