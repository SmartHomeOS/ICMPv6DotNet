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
    public class ICMPErrorPayload : ICMPV6Payload
    {
        public ICMPErrorPayload(Span<byte> buffer, ICMPType type, byte code) : base()
        {
            if (type == ICMPType.PacketTooBig)
            {
                MTU = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(0, 4));
            }
            else if (type == ICMPType.ParameterProblem)
            {
                Pointer = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(0, 4));
            }
            Reason = (ErrorReason)(((int)type << 8) + code);
            if (buffer.Length > 4)
                Message = Encoding.UTF8.GetString(buffer.Slice(4));
        }

        protected ICMPErrorPayload(ErrorReason reason, string? message = null, uint? mtu = null, uint? pointer = null)
        {
            this.Reason = reason;
            this.MTU = mtu;
            this.Pointer = pointer;
            this.Message = message;
        }

        public override int WritePacket(Span<byte> buffer)
        {
            ICMPType type = (ICMPType)((int)Reason >> 8);
            if (type == ICMPType.PacketTooBig)
            {
                if (MTU == null)
                    throw new InvalidDataException("MTU is missing");
                BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)MTU);
            }
            else if (type == ICMPType.ParameterProblem)
            {
                if (Pointer == null)
                    throw new InvalidDataException("Pointer is missing");
                BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)Pointer);
            }
            if (Message != null)
            {
                Encoding.UTF8.GetBytes(Message).CopyTo(buffer.Slice(4));
                return 4 + Message.Length;
            }
            return 4;
        }

        public static ICMPPacket CreateError(IPAddress source, IPAddress destination, ErrorReason reason, string? message = null, uint? mtu = null, uint? pointer = null)
        {
            ICMPErrorPayload payload = new ICMPErrorPayload(reason, message, mtu, pointer);
            return new ICMPPacket(source, destination, (ICMPType)((int)reason >> 8), (byte)((int)reason & 0xFF), payload);
        }

        public override string ToString()
        {
            return $"Reason: {Reason}, MTU: {MTU}, Packet: {Message}";
        }

        public uint? MTU { get; private set; }
        public uint? Pointer { get; private set; }
        public string? Message { get; private set; }
        public ErrorReason Reason { get; private set; }
    }
}
