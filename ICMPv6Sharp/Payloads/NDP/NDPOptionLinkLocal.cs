using System.Net.NetworkInformation;

namespace ICMPv6DotNet.Payloads.NDP
{
    public class NDPOptionLinkLocal : NDPOption
    {
        public NDPOptionLinkLocal(Memory<byte> buffer, int start, int len, bool source)
        {
            if (source)
                SourceAddress = new PhysicalAddress(buffer.Slice(start + 2, len - 2).ToArray());
            else
                DestinationAddress = new PhysicalAddress(buffer.Slice(start + 2, len - 2).ToArray());
        }

        public override int WritePacket(Span<byte> buffer)
        {
            buffer[1] = 1;
            if (SourceAddress != null)
            {
                buffer[0] = (byte)NeighborDiscoveryOption.SourceLinklayerAddress;
                SourceAddress.GetAddressBytes().CopyTo(buffer.Slice(2, 6));
            }
            else if (DestinationAddress != null)
            {
                buffer[0] = (byte)NeighborDiscoveryOption.TargetLinkLayerAddress;
                DestinationAddress.GetAddressBytes().CopyTo(buffer.Slice(2, 6));
            }
            else
                throw new InvalidDataException("Source and Target Address are not defined");
            return 8;
        }

        public override string ToString()
        {
            if (SourceAddress != null)
                return "Source: " + SourceAddress;
            if (DestinationAddress != null)
                return "Destination: " + DestinationAddress;
            return string.Empty;
        }

        public PhysicalAddress? SourceAddress { get; private set; }
        public PhysicalAddress? DestinationAddress { get; private set; }
    }
}
