using ICMPv6DotNet.Payloads;
using System.Buffers.Binary;
using System.Net;
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
                Message = Encoding.UTF8.GetString(buffer.Slice(4).Span);
        }

        protected ICMPErrorPayload(ErrorReason reason, string? message = null, uint? mtu = null, uint? pointer = null)
        {
            this.Reason = reason;
            this.MTU = mtu;
            this.Pointer = pointer;
            this.Message = message;
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
            if (Message != null)
            {
                Encoding.UTF8.GetBytes(Message).CopyTo(buffer.Slice(4));
                return 4 + Message.Length;
            }
            return 4;
        }

        public static ICMPPacket CreateError(IPAddress source, IPAddress destination, ErrorReason reason, string? message = null, uint? mtu = null, uint? pointer = null)
        {
            ICMPErrorPayload payload = new ICMPErrorPayload(reason, message, mtu, pointer);
            return new ICMPPacket(source, destination, (ICMPType)((int)reason >> 8), (byte)((int)reason & 0xFF), payload);
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
