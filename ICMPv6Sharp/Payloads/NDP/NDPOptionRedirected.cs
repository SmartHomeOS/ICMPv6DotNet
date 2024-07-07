namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPOptionRedirected : NDPOption
    {
        public NDPOptionRedirected(Span<byte> buffer)
        {
            RedirectedPacket = buffer.Slice(8).ToArray();
        }

        public NDPOptionRedirected(byte[] packet)
        {
            RedirectedPacket = packet;
        }

        public override int WritePacket(Span<byte> buffer)
        {
            buffer[0] = (byte)NeighborDiscoveryOption.RedirectedHeader;
            buffer[1] = (byte)((RedirectedPacket.Length + 9) / 8);
            RedirectedPacket.CopyTo(buffer.Slice(2));
            int padding = (buffer[2] * 8) - 2 - RedirectedPacket.Length;
            if (padding > 0)
                buffer.Slice(RedirectedPacket.Length + 2, padding).Clear();
            return buffer[1] * 8;
        }

        public override string ToString()
        {
            if (RedirectedPacket != null)
                return $"Packet Length: {RedirectedPacket.Length}";
            return string.Empty;
        }

        public byte[] RedirectedPacket { get; private set; }
    }
}
