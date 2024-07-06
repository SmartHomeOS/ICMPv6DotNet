using ICMPv6DotNet.Payloads;
using System.Buffers.Binary;
using System.Text;

namespace ICMPv6DotNet.Payloads
{
    public class ICMPErrorPayload : ICMPV6Payload
    {
        public ICMPErrorPayload(Memory<byte> buffer, ICMPType type, byte code) : base()
        {
            if (type == ICMPType.PacketTooBig)
            {
                MTU = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(0, 4).Span);
            }
            else if (type == ICMPType.ParameterProblem)
            {
                Pointer = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(0, 4).Span);
            }
            Reason = (ErrorReason)(((int)type << 8) + code);
            if (buffer.Length > 4)
                Message = Encoding.ASCII.GetString(buffer.Slice(4).Span);
        }

        public override int WritePacket(Span<byte> buffer)
        {
            ICMPType type = (ICMPType)((int)Reason >> 8);
            if (type == ICMPType.PacketTooBig)
            {
                if (MTU == null)
                    throw new InvalidDataException("MTU is missing");
                BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)MTU);
            }
            else if (type == ICMPType.ParameterProblem)
            {
                if (Pointer == null)
                    throw new InvalidDataException("Pointer is missing");
                BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)Pointer);
            }
            return 4;
        }

        public override string ToString()
        {
            return $"Reason: {Reason}, MTU: {MTU}, Packet: {Message}";
        }

        public uint? MTU { get; private set; }
        public uint? Pointer { get; private set; }
        public string? Message { get; private set; }
        public ErrorReason Reason { get; private set; }
    }
}
