using ICMPv6DotNet.Payloads;
using ICMPv6DotNet.Payloads.NDP;
using System.Net;
using System.Net.NetworkInformation;

namespace ICMPv6DotNet.Net
{
    public class NeighborDiscovery
    {
        protected ICMPv6Socket socket;

        private static readonly IPAddress SOLICITED_NODE = IPAddress.Parse("FF02:0:0:0:0:1:FF00:0000");

        public NeighborDiscovery(int nicIndex, bool linkLocal) : this(ICMPv6Socket.GetNicAddress(nicIndex, linkLocal)) { }

        public NeighborDiscovery(IPAddress nicAddress)
        {
            //TODO - Promiscious mode required on windows, verify if this is needed on other platforms
            socket = new ICMPv6Socket(nicAddress, true);
        }

        public async Task<PhysicalAddress?> ResolveLinkAddress(IPAddress address, int timeout = 10000)
        {
            PhysicalAddress? sourceMAC = ICMPv6Socket.GetNicPhysicalAddress(socket.ListenAddress);
            if (sourceMAC == null)
                return null;
            CancellationTokenSource cts = new CancellationTokenSource(timeout);
            byte[] destGroup = SOLICITED_NODE.GetAddressBytes();
            Array.Copy(address.GetAddressBytes(), 13, destGroup, 13, 3);
            IPAddress destIP = new IPAddress(destGroup);
            ICMPPacket neighborSolicitation = NDPPayload.CreateNeighborSolicitation(socket.ListenAddress, destIP, address, sourceMAC);
            await socket.SendAsync(neighborSolicitation, destIP);
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    ICMPPacket packet = await socket.ReceiveAsync(false, cts.Token);
                    if (packet.Type == ICMPType.NeighborAdvertisement &&
                        (packet.Payload != null) &&
                        (((NDPPayload)packet.Payload).Solicited == true && address.Equals(((NDPPayload)packet.Payload).TargetAddress)))
                    {
                        foreach (var option in ((NDPPayload)packet.Payload).Options)
                        {
                            if (option is NDPOptionLinkLocal ll)
                                return ll.DestinationAddress;
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            return null;
        }

        public void Stop()
        {
            socket.Close();
        }
    }
}
