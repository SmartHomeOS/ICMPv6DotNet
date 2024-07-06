using System.Buffers.Binary;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPOptionMTU : NDPOption
    {
        public NDPOptionMTU(Memory<byte> buffer, int start)
        {
            MTU = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(start + 4, 4).Span);
        }

        public override string ToString()
        {
            return $"MTU: {MTU}";
        }

        public override int WritePacket(Span<byte> buffer)
        {
            buffer[0] = (byte)NeighborDiscoveryOption.MTU;
            buffer[1] = 1;
            buffer.Slice(2, 2).Clear();
            BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(4), MTU);
            return 8;
        }

        public uint MTU { get; private set; }
    }
}
