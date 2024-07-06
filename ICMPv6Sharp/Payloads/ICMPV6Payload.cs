using ICMPv6DotNet.Payloads.MLD;
using ICMPv6DotNet.Payloads.NDP;

namespace ICMPv6DotNet.Payloads
{
    public abstract class ICMPV6Payload
    {
        internal static ICMPV6Payload? Create(Memory<byte> buffer, ICMPType type, byte code)
        {
            switch (type)
            {
                case ICMPType.DestinationUnreachable:
                case ICMPType.TimeExceeded:
                case ICMPType.PacketTooBig:
                case ICMPType.ParameterProblem:
                    return new ICMPErrorPayload(buffer, type, code);
                case ICMPType.EchoReply:
                case ICMPType.EchoRequest:
                    return new ICMPEchoPayload(buffer);
                case ICMPType.NeighborAdvertisement:
                case ICMPType.NeighborSolicitation:
                case ICMPType.RouterAdvertisement:
                case ICMPType.RouterSolicitation:
                case ICMPType.RedirectMessage:
                    return new NDPPayload(buffer, type);
                case ICMPType.MulticastRouterAdvertisement:
                    return new MulticastRouterAdvertisement(buffer, code);
                case ICMPType.MLDQuery:
                    //TODO - This is the V2 query
                    return null;
                case ICMPType.MLDv2Report:
                    return new MLDReportPayload(buffer, type);
                //MLD V1 - MLDQuery, MLDReport, MLDDone
                case ICMPType.MulticastRouterSolicitation: //No Payload or Options
                case ICMPType.MulticastRouterTermination:
                    return null;
                default:
                    return null;
            }
        }

        public virtual bool IsValid { get { return true; } }

        public abstract override string ToString();

        public virtual int WritePacket(Span<byte> buffer)
        {
            return 0;
        }
    }
}
