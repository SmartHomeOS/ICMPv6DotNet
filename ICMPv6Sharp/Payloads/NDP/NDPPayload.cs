using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Net;
using System.Text;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPPayload : ICMPV6Payload
    {
        bool valid = true;
        readonly List<NDPOption> options = [];
        readonly ICMPType type;

        public NDPPayload(Memory<byte> buffer, ICMPType type) : base(buffer)
        {
            this.type = type;
            switch (type)
            {
                case ICMPType.RouterSolicitation:
                    ParseOptions(4);
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
                    ParseOptions(12);
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
                    ParseOptions(20);
                    break;
                case ICMPType.RedirectMessage:
                    if (buffer.Length < 36)
                    {
                        valid = false;
                        return;
                    }
                    TargetAddress = new IPAddress(buffer.Slice(4, 16).Span);
                    DestinationAddress = new IPAddress(buffer.Slice(20, 16).Span);
                    ParseOptions(36);
                    break;
            }
        }

        public override int WritePacket(Span<byte> buffer)
        {
            switch (type)
            {
                case ICMPType.RouterSolicitation:
                    buffer.Slice(0, 4).Clear();
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
                    return WriteOptions(buffer.Slice(12));
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
                    return WriteOptions(buffer.Slice(20));
                case ICMPType.RedirectMessage:
                    if (TargetAddress == null)
                        throw new ArgumentException("TargetAddress is not set");
                    TargetAddress.TryWriteBytes(buffer.Slice(4, 16), out _);
                    if (DestinationAddress == null)
                        throw new ArgumentException("DestinationAddress is not set");
                    DestinationAddress.TryWriteBytes(buffer.Slice(20, 16), out _);
                    return WriteOptions(buffer.Slice(36));
                default:
                    throw new InvalidOperationException("Unknown Payload Type");
            }
        }

        private void ParseOptions(int start)
        {
            if (start >= buffer.Length)
                return;
            int len = buffer.Span[start + 1] * 8;
            if (len == 0 || start + len > buffer.Length)
            {
                valid = false;
                return;
            }
            try
            {
                switch ((NeighborDiscoveryOption)buffer.Span[start])
                {
                    case NeighborDiscoveryOption.SourceLinklayerAddress:
                        lock (options)
                            options.Add(new NDPOptionLinkLocal(buffer, start, len, true));
                        break;
                    case NeighborDiscoveryOption.TargetLinkLayerAddress: //Destination LL Address
                        lock (options)
                            options.Add(new NDPOptionLinkLocal(buffer, start, len, false));
                        break;
                    case NeighborDiscoveryOption.PrefixInformation:
                        lock (options)
                            options.Add(new NDPOptionPrefixInformation(buffer, start, len));
                        break;
                    case NeighborDiscoveryOption.RedirectedHeader:
                        lock (options)
                            options.Add(new NDPOptionRedirected(buffer, start, len));
                        break;
                    case NeighborDiscoveryOption.MTU:
                        lock (options)
                            options.Add(new NDPOptionMTU(buffer, start));
                        break;
                }
                start += len;
            }
            catch (InvalidDataException)
            {
                valid = false;
                return;
            }
            if (start < buffer.Length)
                ParseOptions(start);
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
    }
}
