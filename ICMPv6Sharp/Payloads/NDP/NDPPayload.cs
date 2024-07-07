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

using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPPayload : ICMPV6Payload
    {
        bool valid = true;
        readonly List<NDPOption> options = [];
        readonly ICMPType type;

        public NDPPayload(Memory<byte> buffer, ICMPType type) : base()
        {
            this.type = type;
            switch (type)
            {
                case ICMPType.RouterSolicitation:
                    ParseOptions(buffer.Slice(4).Span);
                    break;
                case ICMPType.RouterAdvertisement:
                    if (buffer.Length < 12)
                    {
                        valid = false;
                        return;
                    }
                    CurrentHopLimit = buffer.Span[0];
                    ManagedAddressConfiguration = (buffer.Span[1] & 0x80) == 0x80;
                    OtherConfiguration = (buffer.Span[1] & 0x40) == 0x40;
                    RouterLifetime = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2).Span);
                    ReachableTime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(4).Span);
                    RetransTime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(8).Span);
                    ParseOptions(buffer.Slice(12).Span);
                    break;
                case ICMPType.NeighborSolicitation:
                case ICMPType.NeighborAdvertisement:
                    if (buffer.Length < 20)
                    {
                        valid = false;
                        return;
                    }
                    TargetAddress = new IPAddress(buffer.Slice(4, 16).Span);
                    if (type == ICMPType.NeighborAdvertisement)
                    {
                        Router = (buffer.Span[0] & 0x80) == 0x80;
                        Solicited = (buffer.Span[0] & 0x40) == 0x40;
                        Override = (buffer.Span[0] & 0x20) == 0x20;
                    }
                    ParseOptions(buffer.Slice(20).Span);
                    break;
                case ICMPType.RedirectMessage:
                    if (buffer.Length < 36)
                    {
                        valid = false;
                        return;
                    }
                    TargetAddress = new IPAddress(buffer.Slice(4, 16).Span);
                    DestinationAddress = new IPAddress(buffer.Slice(20, 16).Span);
                    ParseOptions(buffer.Slice(36).Span);
                    break;
            }
        }

        protected NDPPayload(ICMPType type, List<NDPOption> options)
        {
            this.type = type;
            this.options = options;
        }

        public override int WritePacket(Span<byte> buffer)
        {
            switch (type)
            {
                case ICMPType.RouterSolicitation:
                    buffer.Slice(0, 4).Clear();
                    if (4 >= buffer.Length)
                        return 4;
                    return 4 + WriteOptions(buffer.Slice(4));
                case ICMPType.RouterAdvertisement:
                    buffer[0] = CurrentHopLimit ?? 0;
                    if (ManagedAddressConfiguration == true)
                        buffer[1] |= 0x80;
                    if (OtherConfiguration == true)
                        buffer[1] |= 0x40;
                    BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), RouterLifetime ?? 0);
                    BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(4), ReachableTime ?? 0);
                    BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(8), RetransTime ?? 0);
                    if (12 >= buffer.Length)
                        return 12;
                    return 12 + WriteOptions(buffer.Slice(12));
                case ICMPType.NeighborSolicitation:
                case ICMPType.NeighborAdvertisement:
                    if (TargetAddress == null)
                        throw new ArgumentException("TargetAddress is not set");
                    TargetAddress.TryWriteBytes(buffer.Slice(4, 16), out _);
                    if (type == ICMPType.NeighborAdvertisement)
                    {
                        if (Router == true)
                            buffer[0] |= 0x80;
                        if (Solicited == true)
                            buffer[0] |= 0x40;
                        if (Override == true)
                            buffer[0] |= 0x20;
                    }
                    if (20 >= buffer.Length)
                        return 20;
                    return 20 + WriteOptions(buffer.Slice(20));
                case ICMPType.RedirectMessage:
                    if (TargetAddress == null)
                        throw new ArgumentException("TargetAddress is not set");
                    TargetAddress.TryWriteBytes(buffer.Slice(4, 16), out _);
                    if (DestinationAddress == null)
                        throw new ArgumentException("DestinationAddress is not set");
                    DestinationAddress.TryWriteBytes(buffer.Slice(20, 16), out _);
                    if (36 >= buffer.Length)
                        return 36;
                    return 36 + WriteOptions(buffer.Slice(36));
                default:
                    throw new InvalidOperationException("Unknown Payload Type");
            }
        }

        private void ParseOptions(Span<byte> buffer)
        {
            if (buffer.Length == 0)
                return;
            int len = buffer[1] * 8;
            if (len == 0 || len > buffer.Length)
            {
                valid = false;
                return;
            }
            try
            {
                switch ((NeighborDiscoveryOption)buffer[0])
                {
                    case NeighborDiscoveryOption.SourceLinklayerAddress:
                        lock (options)
                            options.Add(new NDPOptionLinkLocal(buffer.Slice(0, len), true));
                        break;
                    case NeighborDiscoveryOption.TargetLinkLayerAddress: //Destination LL Address
                        lock (options)
                            options.Add(new NDPOptionLinkLocal(buffer.Slice(0, len), false));
                        break;
                    case NeighborDiscoveryOption.PrefixInformation:
                        lock (options)
                            options.Add(new NDPOptionPrefixInformation(buffer.Slice(0, len)));
                        break;
                    case NeighborDiscoveryOption.RedirectedHeader:
                        lock (options)
                            options.Add(new NDPOptionRedirected(buffer.Slice(0, len)));
                        break;
                    case NeighborDiscoveryOption.MTU:
                        lock (options)
                            options.Add(new NDPOptionMTU(buffer.Slice(0, len)));
                        break;
                }
            }
            catch (InvalidDataException)
            {
                valid = false;
                return;
            }
            if (len < buffer.Length)
                ParseOptions(buffer.Slice(len));
        }

        private int WriteOptions(Span<byte> buffer)
        {
            int len = 0;
            foreach(var option in options)
                len += option.WritePacket(buffer);
            return len;
        }

        public byte? CurrentHopLimit { get; private set; }
        public bool? ManagedAddressConfiguration { get; private set; }
        public bool? OtherConfiguration { get; private set; }
        public ushort? RouterLifetime { get; private set; }
        public uint? ReachableTime { get; private set; }
        public uint? RetransTime { get; private set; }
        public IPAddress? TargetAddress { get; private set; }
        public IPAddress? DestinationAddress { get; private set; }
        public bool? Router { get; private set; }
        public bool? Solicited { get; private set; }
        public bool? Override { get; private set; }

        public ReadOnlyCollection<NDPOption> Options { get { return new ReadOnlyCollection<NDPOption>(options); } }

        public override bool IsValid { get { return valid; } }
        public override string ToString()
        {
            if (!IsValid)
                return "Invalid";
            StringBuilder ret = new StringBuilder();
            switch (type)
            {
                case ICMPType.RouterAdvertisement:
                    ret.Append($"Hop Limit: {CurrentHopLimit}");
                    if (ManagedAddressConfiguration == true)
                        ret.Append(", Managed Address Config");
                    if (OtherConfiguration == true)
                        ret.Append(", Other Config");
                    ret.Append($", Router Lifetime: {RouterLifetime}s, Reachable: {ReachableTime}s, Retrans Time: {RetransTime}s");
                    break;
                case ICMPType.NeighborSolicitation:
                    ret.Append($"Target: {TargetAddress}");
                    break;
                case ICMPType.NeighborAdvertisement:
                    string opts = "";
                    if (Router == true)
                        opts += "[R]";
                    if (Solicited == true)
                        opts += "[S]";
                    if (Override == true)
                        opts += "[O]";
                    ret.Append($"{TargetAddress} {opts} has physical address ");
                    break;
                case ICMPType.RedirectMessage:
                    ret.Append($"Target: {TargetAddress}, Destination: {TargetAddress}");
                    break;
                default:
                    return string.Empty;
            }
            if (options.Count > 0)
                ret.Append(" Options:");
            for (var i = 0; i < options.Count; i++)
            {
                if (i > 0)
                    ret.Append(", ");
                ret.Append($"[{options[i]}]");
            }
            return ret.ToString();
        }

        public static ICMPPacket CreateNeighborSolicitation(IPAddress source, IPAddress destination, IPAddress target, PhysicalAddress sourceMAC)
        {
            NDPPayload payload = new NDPPayload(ICMPType.NeighborSolicitation, [new NDPOptionLinkLocal(sourceMAC)]);
            payload.TargetAddress = target;
            return new ICMPPacket(source, destination, ICMPType.NeighborSolicitation, 0, payload);
        }

        public static ICMPPacket CreateNeighborAdvertisement(IPAddress source, IPAddress destination, PhysicalAddress sourceMAC, bool solicited = false, bool router = false, bool over = false)
        {
            NDPPayload payload = new NDPPayload(ICMPType.NeighborAdvertisement, [new NDPOptionLinkLocal(sourceMAC)]);
            payload.TargetAddress = source;
            payload.Solicited = solicited;
            payload.Router = router;
            payload.Override = over;
            return new ICMPPacket(source, destination, ICMPType.NeighborAdvertisement, 0, payload);
        }
    }
}
