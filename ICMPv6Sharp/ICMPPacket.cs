using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using ICMPv6DotNet.Packets;

namespace ICMPv6DotNet
{
    public class ICMPPacket
    {
        protected Memory<byte> buffer;
        protected IPAddress source;
        protected IPAddress destination;
        protected bool valid = false;
        protected ICMPV6Payload? payload;

        public ICMPPacket(Span<byte> bytes, IPAddress source, IPAddress destination)
        {
            if (bytes.Length < 4)
                buffer = new byte[4];
            else
                buffer = bytes.ToArray();
            this.source = source;
            this.destination = destination;
        }

        public bool IsValid
        {
            get
            {
                if (buffer.Span[0] == 0)
                    return false;
                if (!valid)
                {
                    lock (source)
                    {
                        valid = Validate();
                    }
                }
                return valid;
            }
        }

        private bool Validate()
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
                checksum += BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(i).Span);
            if (buffer.Length % 2 != 0)
                checksum += buffer.Span[buffer.Length - 1];

            while (checksum > 0xFFFF)
                checksum = (checksum & 0xFFFF) + (checksum >> 16);
            return ((checksum & 0xFFFF) == 0xFFFF);
            //To Calculate a checksum 0 out checksum field and then
            //checksum = (ushort)~checksum;
        }

        public IPAddress Source { get { return source; } }
        public IPAddress Destination { get { return destination; } }
        public ICMPType Type { get { return (ICMPType)buffer.Span[0]; } }
        public bool IsError { get { return buffer.Span[0] > 0 && buffer.Span[0] < 128; } }
        public bool IsInfo { get { return buffer.Span[0] > 127; } }
        public ushort Checksum { get { return BitConverter.ToUInt16(buffer.Slice(2, 2).Span); } }
        public ICMPV6Payload? Payload
        { 
            get
            {
                if (!IsValid)
                    return null;
                payload ??= ICMPV6Payload.Create(buffer, Type);
                return payload;
            }
        }

        public override string ToString()
        {
            if (!IsValid)
                return $"Invalid Packet [Length: {buffer.Length}]";
            if (Payload == null)
                return $"{Type} from {Source} to {Destination}";

            return $"{Type} from {Source}: {Payload}";
        }
    }
}
