using ICMPv6DotNet.Packets.MLD;
using ICMPv6DotNet.Packets.NDPOptions;

namespace ICMPv6DotNet.Packets
{
    public abstract class ICMPV6Payload
    {
        protected Memory<byte> buffer;

        internal ICMPV6Payload(Memory<byte> buffer)
        {
            this.buffer = buffer;
        }

        internal static ICMPV6Payload? Create(Memory<byte> buffer, ICMPType type)
        {
            switch (type)
            {
                case ICMPType.DestinationUnreachable:
                case ICMPType.TimeExceeded:
                case ICMPType.PacketTooBig:
                case ICMPType.ParameterProblem:
                    return new ICMPErrorPayload(buffer, type);
                case ICMPType.EchoReply:
                case ICMPType.EchoRequest:
                    return new ICMPBinaryPayload(buffer);
                case ICMPType.NeighborAdvertisement:
                case ICMPType.NeighborSolicitation:
                case ICMPType.RouterAdvertisement:
                case ICMPType.RouterSolicitation:
                case ICMPType.RedirectMessage:
                    return new NDPPayload(buffer, type);
                case ICMPType.MLDv2Report:
                    return new MLDReportPayload(buffer, type);
                default:
                    return null;
            }
        }

        public byte Code { get { return buffer.Span[1]; } }
        public virtual bool IsValid { get { return true; } }

        public abstract override string ToString();
    }
}
