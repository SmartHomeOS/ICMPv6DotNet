using System.Buffers.Binary;
using System.Net;

namespace ICMPv6DotNet.Packets.NDPOptions
{
    public class NDPOptionPrefixInformation : NDPOption
    {
        public NDPOptionPrefixInformation(Memory<byte> buffer, int start, int len)
        {
            int prefixLen = buffer.Span[start + 2];
            if (prefixLen % 8 != 0)
                prefixLen = prefixLen / 8 + 1;
            else
                prefixLen = prefixLen / 8;
            if (prefixLen > 16 || len != 32)
            {
                throw new InvalidDataException();
            }
            OnLink = (buffer.Span[start + 3] & 0x80) == 0x80;
            AutonomousAddress = (buffer.Span[start + 3] & 0x40) == 0x40;
            ValidLifetime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(start + 4).Span);
            PreferredLifetime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(start + 8).Span);
            Memory<byte> prefix = new byte[16];
            buffer.Slice(start + 16, prefixLen).CopyTo(prefix);
            Prefix = new IPAddress(prefix.Span);
        }

        public override string ToString()
        {
            if (OnLink == null || AutonomousAddress == null)
                return string.Empty;
            return $"{((bool)OnLink ? "[O]" : "")}{((bool)AutonomousAddress ? "[A]" : "")} Valid: {ValidLifetime} Preferred: {PreferredLifetime} Prefix: {Prefix}";
        }

        public bool? OnLink { get; private set; }
        public bool? AutonomousAddress { get; private set; }
        public uint? ValidLifetime { get; private set; }
        public uint? PreferredLifetime { get; private set; }
        public IPAddress? Prefix { get; private set; }
    }
}
