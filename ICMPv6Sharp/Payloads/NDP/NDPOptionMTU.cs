using System.Buffers.Binary;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPOptionMTU : NDPOption
    {
        public NDPOptionMTU(Span<byte> buffer)
        {
            MTU = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(4, 4));
        }

        public NDPOptionMTU(uint mtu)
        {
            MTU = mtu;
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
