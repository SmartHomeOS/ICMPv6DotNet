using System.Buffers.Binary;
using System.Net;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPOptionPrefixInformation : NDPOption
    {
        public NDPOptionPrefixInformation(Memory<byte> buffer, int start, int len)
        {
            byte prefixSize = buffer.Span[start + 2];
            PrefixLength = prefixSize;
            prefixSize = (byte)((prefixSize + 7) / 8);
            if (prefixSize > 16 || len != 32)
            {
                throw new InvalidDataException();
            }
            OnLink = (buffer.Span[start + 3] & 0x80) == 0x80;
            AutonomousAddress = (buffer.Span[start + 3] & 0x40) == 0x40;
            ValidLifetime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(start + 4).Span);
            PreferredLifetime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(start + 8).Span);
            Memory<byte> prefix = new byte[16];
            buffer.Slice(start + 16, prefixSize).CopyTo(prefix);
            Prefix = new IPAddress(prefix.Span);
        }

        public override int WritePacket(Span<byte> buffer)
        {
            buffer[0] = (byte)NeighborDiscoveryOption.PrefixInformation;
            buffer[1] = 4; //32 bytes
            buffer[2] = PrefixLength;
            if (OnLink)
                buffer[3] |= 0x80;
            if (AutonomousAddress)
                buffer[3] |= 0x40;
            BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(4), ValidLifetime);
            BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(8), PreferredLifetime);
            if (!Prefix.TryWriteBytes(buffer.Slice(16), out _))
                throw new InvalidDataException("Unable to write Prefix");
            return 32;
        }

        public override string ToString()
        {
            return $"{((bool)OnLink ? "[O]" : "")}{((bool)AutonomousAddress ? "[A]" : "")} Valid: {ValidLifetime} Preferred: {PreferredLifetime} Prefix: {Prefix}";
        }

        public bool OnLink { get; private set; }
        public bool AutonomousAddress { get; private set; }
        public uint ValidLifetime { get; private set; }
        public uint PreferredLifetime { get; private set; }
        public IPAddress Prefix { get; private set; }
        public byte PrefixLength { get; private set; }
    }
}
