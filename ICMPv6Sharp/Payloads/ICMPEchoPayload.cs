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
using System.Net;
using System.Text;

namespace ICMPv6DotNet.Payloads
{
    public class ICMPEchoPayload : ICMPV6Payload
    {
        public ICMPEchoPayload(Span<byte> buffer) : base()
        {
            Identifier = BinaryPrimitives.ReadUInt16BigEndian(buffer);
            SequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2));
            if (buffer.Length > 4)
                Data = buffer.Slice(4).ToArray();
            else
                Data = [];
        }
        protected ICMPEchoPayload(ushort id, ushort seq, byte[] data)
        {
            this.Identifier = id;
            this.SequenceNumber = seq;
            this.Data = data;
        }

        public override string ToString()
        {
            return $"ID: {Identifier}, SEQ: {SequenceNumber}, Payload: " + Encoding.ASCII.GetString(Data);
        }

        public override int WritePacket(Span<byte> buffer)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buffer, Identifier);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), SequenceNumber);
            Data.CopyTo(buffer.Slice(4));
            return Data.Length + 4;
        }

        public static ICMPPacket CreateRequest(IPAddress source, IPAddress destination, ushort identifier, ushort sequence, byte[] data)
        {
            ICMPEchoPayload payload = new ICMPEchoPayload(identifier, sequence, data);
            return new ICMPPacket(source, destination, ICMPType.EchoRequest, 0, payload);
        }

        public static ICMPPacket CreateResponse(IPAddress source, IPAddress destination, ushort identifier, ushort sequence, byte[] data)
        {
            ICMPEchoPayload payload = new ICMPEchoPayload(identifier, sequence, data);
            return new ICMPPacket(source, destination, ICMPType.EchoReply, 0, payload);
        }

        public ushort Identifier { get; set; }
        public ushort SequenceNumber { get; set; }
        public byte[] Data { get; set; }
    }
}
