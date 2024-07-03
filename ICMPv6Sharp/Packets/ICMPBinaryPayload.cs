using System.Text;

namespace ICMPv6DotNet.Packets
{
    public class ICMPBinaryPayload : ICMPV6Payload
    {
        public ICMPBinaryPayload(Memory<byte> buffer) : base(buffer) { }
        public override string ToString()
        {
            return "Payload: " + Encoding.ASCII.GetString(buffer.Slice(4).Span);
        }
    }
}
