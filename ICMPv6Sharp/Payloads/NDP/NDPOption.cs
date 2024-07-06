
namespace ICMPv6DotNet.Payloads.NDP
{
    public abstract class NDPOption
    {
        //Base Class
        public abstract int WritePacket(Span<byte> buffer);
    }
}
