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
using ICMPv6DotNet.Payloads;

namespace ICMPv6DotNet
{
    public class ICMPPacket
    {
        //protected Memory<byte> buffer;
        protected IPAddress source;
        protected IPAddress destination;
        protected bool valid = false;
        protected ICMPV6Payload? payload;
        protected ICMPType type;
        protected ushort checksum;
        protected Memory<byte>? payloadBytes;
        protected byte code;

        public ICMPPacket(Span<byte> bytes, IPAddress source, IPAddress destination)
        {
            if (bytes.Length < 4)
            {
                this.source = IPAddress.None;
                this.destination = IPAddress.None;
                return;
            }
            this.source = source;
            this.destination = destination;
            this.checksum = BitConverter.ToUInt16(bytes.Slice(2, 2));
            this.type = (ICMPType)bytes[0];
            this.code = bytes[1];
            if (bytes.Length > 4)
                this.payloadBytes = bytes.Slice(4).ToArray();
            else
                this.payloadBytes = Memory<byte>.Empty;
            this.valid = Validate(bytes);
        }

        public ICMPPacket(IPAddress source, IPAddress destination, ICMPType type, byte code, ICMPV6Payload payload)
        {
            this.source = source;
            this.destination = destination;
            this.type = type;
            this.code = code;
            this.payload = payload;
            this.valid = true;
            //Checksum calculated on send
        }

        public int WritePacket(Span<byte> buffer)
        {
            int size = 4;
            buffer[0] = (byte)type;
            buffer[1] = code;
            if (payload != null)
                size += payload.WritePacket(buffer.Slice(4));
            else
            {
                buffer.Slice(4, 4).Clear();
                size += 4;
            }
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2, 2), GetChecksum(buffer.Slice(0, size)));
            return size;
        }

        public bool IsValid
        {
            get
            {
                if (type == ICMPType.Invalid)
                    return false;
                return valid;
            }
        }

        private bool Validate(Span<byte> buffer)
        {
            
            return ((SumBytes(buffer, true) & 0xFFFF) == 0xFFFF);
            //To Calculate a checksum 0 out checksum field and then
            //checksum = (ushort)~checksum;
        }

        private ushort GetChecksum(Span<byte> buffer)
        {
            uint checksum = SumBytes(buffer, false);
            return (ushort)~checksum;
        }

        private uint SumBytes(Span<byte> buffer, bool includeChecksum)
        {
            uint checksum = 0;
            Span<byte> sourceBytes = source.GetAddressBytes();
            Span<byte> destBytes = destination.GetAddressBytes();
            Span<byte> lengthBytes = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, (uint)buffer.Length);
            for (var i = 0; i < 16; i += 2)
            {
                checksum += BinaryPrimitives.ReadUInt16BigEndian(sourceBytes.Slice(i));
                checksum += BinaryPrimitives.ReadUInt16BigEndian(destBytes.Slice(i));
            }
            checksum += BinaryPrimitives.ReadUInt16BigEndian(lengthBytes.Slice(0));
            checksum += BinaryPrimitives.ReadUInt16BigEndian(lengthBytes.Slice(2));
            checksum += (ushort)58;
            for (var i = 0; i < buffer.Length; i += 2)
            {
                if (i != 2 || includeChecksum)
                    checksum += BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(i));
            }
            if (buffer.Length % 2 != 0)
                checksum += buffer[buffer.Length - 1];

            while (checksum > 0xFFFF)
                checksum = (checksum & 0xFFFF) + (checksum >> 16);
            return checksum;
        }

        public IPAddress Source { get { return source; } }
        public IPAddress Destination { get { return destination; } }
        public ICMPType Type { get { return type; } }
        public bool IsError { get { return type > ICMPType.Invalid && (int)type < 128; } }
        public bool IsInfo { get { return (int)type > 127; } }
        public ushort Checksum { get { return checksum; } }
        public ICMPV6Payload? Payload
        { 
            get
            {
                if (!IsValid)
                    return null;
                if (payload == null && payloadBytes != null)
                    payload = ICMPV6Payload.Create(((Memory<byte>)payloadBytes).Span, Type, code);
                if (payload == null || !payload.IsValid)
                    return null;
                return payload;
            }
        }

        public override string ToString()
        {
            if (!IsValid)
                return $"Invalid Packet";
            if (Payload == null)
                return $"{Type} from {Source} to {Destination}";

            return $"{Type} from {Source}: {Payload}";
        }
    }
}
