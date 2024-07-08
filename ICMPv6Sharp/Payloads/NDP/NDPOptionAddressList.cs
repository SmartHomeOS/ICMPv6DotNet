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

using System.Net;
using System.Text;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPOptionAddressList : NDPOption
    {
        public NDPOptionAddressList(Span<byte> buffer)
        {
            Source = (buffer[0] == (byte)NeighborDiscoveryOption.SourceAddressList);
            int len = 8 * buffer[1];
            if (buffer.Length < len)
                throw new InvalidDataException("Length does not match packet size");
            Addresses = new List<IPAddress>(len / 16);
            for (int i = 8; i < len; i += 16)
                Addresses.Add(new IPAddress(buffer.Slice(i, 16)));
        }

        public NDPOptionAddressList(List<IPAddress> addresses, bool source)
        {
            Source = source;
            Addresses = addresses;
        }

        public override int WritePacket(Span<byte> buffer)
        {
            if (Source)
                buffer[0] = (byte)NeighborDiscoveryOption.SourceAddressList;
            else
                buffer[0] = (byte)NeighborDiscoveryOption.TargetAddressList;
            buffer[1] = (byte)(1 + (2 * Addresses.Count));
            buffer.Slice(2, 6).Clear();
            for (int i = 0; i < Addresses.Count; i++)
            {
                if (!Addresses[i].TryWriteBytes(buffer.Slice(8 + (16 * i), 16), out _))
                    throw new ArgumentException("Unable to write Addresses");
            }
            return buffer[1] * 8;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            if (Source)
                sb.Append("Sources: ");
            else
                sb.Append("Targets: ");
            for (int i = 0; i < Addresses.Count; i++)
            {
                if (i > 0) sb.Append(", ");
                sb.Append(Addresses[i]);
            }
            return sb.ToString();
        }

        public List<IPAddress> Addresses { get; private set; }
        /// <summary>
        /// True if this is a Source Address List. False if it is a Target Address Lisr
        /// </summary>
        public bool Source { get; private set; }
    }
}
