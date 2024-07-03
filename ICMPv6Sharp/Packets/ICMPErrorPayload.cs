using ICMPv6DotNet.Packets;
using System.Buffers.Binary;
using System.Text;

namespace ICMPv6DotNet
{
    public class ICMPErrorPayload : ICMPV6Payload
    {
        public ICMPErrorPayload(Memory<byte> buffer, ICMPType type) : base(buffer)
        {
            if (type == ICMPType.PacketTooBig)
                MTU = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(4, 4).Span);
            else if (type == ICMPType.ParameterProblem)
                Pointer = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(4, 4).Span);
            Reason = (ErrorReason)(((int)type << 8) + Code);
        }
        public override string ToString()
        {
            return $"Reason: {Reason}, MTU: {MTU}, Packet: {Encoding.ASCII.GetString(buffer.Slice(8).Span)}";
        }

        public uint? MTU { get; private set; }
        public uint? Pointer { get; private set; }
        public ErrorReason Reason { get; private set; }
    }
}
