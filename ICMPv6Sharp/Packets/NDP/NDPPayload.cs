using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Net;
using System.Text;

namespace ICMPv6DotNet.Packets.NDPOptions
{
    public class NDPPayload : ICMPV6Payload
    {
        bool valid = true;
        readonly List<NDPOption> options = new List<NDPOption>();
        readonly ICMPType type;

        public NDPPayload(Memory<byte> buffer, ICMPType type) : base(buffer)
        {
            this.type = type;
            switch (type)
            {
                case ICMPType.RouterSolicitation:
                    ParseOptions(8);
                    break;
                case ICMPType.RouterAdvertisement:
                    if (buffer.Length < 16)
                    {
                        valid = false;
                        return;
                    }
                    CurrentHopLimit = buffer.Span[4];
                    ManagedAddressConfiguration = (buffer.Span[5] & 0x80) == 0x80;
                    OtherConfiguration = (buffer.Span[5] & 0x40) == 0x40;
                    RouterLifetime = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(6).Span);
                    ReachableTime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(8).Span);
                    RetransTime = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(12).Span);
                    ParseOptions(16);
                    break;
                case ICMPType.NeighborSolicitation:
                case ICMPType.NeighborAdvertisement:
                    if (buffer.Length < 24)
                    {
                        valid = false;
                        return;
                    }
                    TargetAddress = new IPAddress(buffer.Slice(8, 16).Span);
                    if (type == ICMPType.NeighborAdvertisement)
                    {
                        Router = (buffer.Span[4] & 0x80) == 0x80;
                        Solicited = (buffer.Span[4] & 0x40) == 0x40;
                        Override = (buffer.Span[4] & 0x20) == 0x20;
                    }
                    ParseOptions(24);
                    break;
                case ICMPType.RedirectMessage:
                    if (buffer.Length < 40)
                    {
                        valid = false;
                        return;
                    }
                    TargetAddress = new IPAddress(buffer.Slice(8, 16).Span);
                    DestinationAddress = new IPAddress(buffer.Slice(24, 16).Span);
                    ParseOptions(40);
                    break;
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
                switch (buffer.Span[start])
                {
                    case 1: //Source LL Address
                        lock (options)
                            options.Add(new NDPOptionLinkLocal(buffer, start, len, true));
                        break;
                    case 2: //Destination LL Address
                        lock (options)
                            options.Add(new NDPOptionLinkLocal(buffer, start, len, false));
                        break;
                    case 3: //Prefix Information
                        lock (options)
                            options.Add(new NDPOptionPrefixInformation(buffer, start, len));
                        break;
                    case 4: //Redirected Header
                        lock (options)
                            options.Add(new NDPOptionRedirected(buffer, start, len));
                        break;
                    case 5: //MTU
                        lock (options)
                            options.Add(new NDPOptionMTU(buffer, start, len));
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
                case ICMPType.NeighborAdvertisement:
                    ret.Append($"Target: {TargetAddress}");
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
