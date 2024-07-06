using System.Text;

namespace ICMPv6DotNet.Payloads
{
    public class ICMPBinaryPayload : ICMPV6Payload
    {
        public ICMPBinaryPayload(Memory<byte> buffer) : base(buffer) { }
        public override string ToString()
        {
            return "Payload: " + Encoding.ASCII.GetString(buffer.Span);
        }

        public override int WritePacket(Span<byte> buffer)
        {
            this.buffer.Span.CopyTo(buffer);
            return this.buffer.Length;
        }
    }
}
