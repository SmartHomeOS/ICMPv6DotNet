namespace ICMPv6DotNet.Packets.NDPOptions
{
    public class NDPOptionRedirected : NDPOption
    {
        public NDPOptionRedirected(Memory<byte> buffer, int start, int len)
        {
            RedirectedPacket = buffer.Slice(start + 8, len - 6).ToArray();
        }

        public override string ToString()
        {
            if (RedirectedPacket != null)
                return $"Packet Length: {RedirectedPacket.Length}";
            return string.Empty;
        }

        public byte[]? RedirectedPacket { get; private set; }
    }
}
