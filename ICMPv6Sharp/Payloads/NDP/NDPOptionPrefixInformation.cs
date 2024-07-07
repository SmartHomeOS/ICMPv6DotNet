using System.Buffers.Binary;
using System.Net;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPOptionPrefixInformation : NDPOption
    {
        public NDPOptionPrefixInformation(Span<byte> buffer)
        {
            byte prefixSize = buffer[2];
            PrefixLength = prefixSize;
            prefixSize = (byte)((prefixSize + 7) / 8);
            if (prefixSize > 16 || buffer.Length != 32)
            {
                throw new InvalidDataException();
            }
            OnLink = (buffer[3] & 0x80) == 0x80;
            AutonomousAddress = (buffer[3] & 0x40) == 0x40;
            ValidLifetime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(4));
            PreferredLifetime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(8));
            Span<byte> prefix = new byte[16];
            buffer.Slice(16, prefixSize).CopyTo(prefix);
            Prefix = new IPAddress(prefix);
        }

        public NDPOptionPrefixInformation(IPAddress prefix, byte prefixLength, uint validLifetime, uint preferredLifetime, bool onLink = false, bool autonomousAddress = false)
        {
            OnLink = onLink;
            AutonomousAddress = autonomousAddress;
            ValidLifetime = validLifetime;
            PreferredLifetime = preferredLifetime;
            Prefix = prefix;
            PrefixLength = prefixLength;
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
