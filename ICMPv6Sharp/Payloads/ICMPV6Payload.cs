// ICMPv6DotNet Copyright (C) 2024
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY, without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

using ICMPv6DotNet.Payloads.MLD;
using ICMPv6DotNet.Payloads.NDP;

namespace ICMPv6DotNet.Payloads
{
    public abstract class ICMPV6Payload
    {
        internal static ICMPV6Payload? Create(Span<byte> buffer, ICMPType type, byte code)
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
                case ICMPType.MLDQuery: //V2 Query
                    return new MLDQueryPayload(buffer, type);
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
