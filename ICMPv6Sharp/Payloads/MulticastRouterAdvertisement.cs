using System.Buffers.Binary;

namespace ICMPv6DotNet.Payloads
{
    public class MulticastRouterAdvertisement : ICMPV6Payload
    {
        readonly bool valid = true;
        public MulticastRouterAdvertisement(Memory<byte> buffer, byte code) : base(buffer)
        {
            if (buffer.Length < 4)
            {
                valid = false;
                return;
            }
            AdvertisementInterval = code;
            QueryInterval = BinaryPrimitives.ReadUInt16BigEndian(buffer.Span);
            Robustness = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2).Span);
        }

        public override int WritePacket(Span<byte> buffer)
        {
            //TODO - Ensure code is propagated back up to the packet
            BinaryPrimitives.WriteUInt16BigEndian(buffer, QueryInterval);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2, 2), Robustness);
            return 4;
        }

        public override string ToString()
        {
            return $"Advertisement Interval: {AdvertisementInterval}, Query Interval: {QueryInterval}, Robustness: {Robustness}";
        }

        public override bool IsValid => valid;

        public byte AdvertisementInterval { get; private set; }
        public ushort QueryInterval { get; private set; }
        public ushort Robustness { get; private set; }
    }
}
