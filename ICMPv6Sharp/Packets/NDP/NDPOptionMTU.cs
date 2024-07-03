using System.Buffers.Binary;

namespace ICMPv6DotNet.Packets.NDPOptions
{
    public class NDPOptionMTU : NDPOption
    {
        public NDPOptionMTU(Memory<byte> buffer, int start, int len)
        {
            MTU = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(start + 4, len - 2).Span);
        }

        public override string ToString()
        {
            if (MTU != null)
                return $"MTU: {MTU}";
            return string.Empty;
        }

        public uint? MTU { get; private set; }
    }
}
