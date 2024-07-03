namespace ICMPv6DotNet.Packets.NDPOptions
{
    public class NDPOptionLinkLocal : NDPOption
    {
        public NDPOptionLinkLocal(Memory<byte> buffer, int start, int len, bool source)
        {
            if (source)
                SourceAddress = buffer.Slice(start + 2, len - 2).ToArray();
            else
                DestinationAddress = buffer.Slice(start + 2, len - 2).ToArray();
        }

        public override string ToString()
        {
            if (SourceAddress != null)
                return "Source: " + BitConverter.ToString(SourceAddress);
            if (DestinationAddress != null)
                return "Destination: " + BitConverter.ToString(DestinationAddress);
            return string.Empty;
        }

        public byte[]? SourceAddress { get; private set; }
        public byte[]? DestinationAddress { get; private set; }
    }
}
