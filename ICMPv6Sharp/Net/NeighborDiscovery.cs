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

using ICMPv6DotNet.Payloads.NDP;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;

namespace ICMPv6DotNet.Net
{
    public class NeighborDiscovery
    {
        protected ICMPv6Socket socket;

        private static readonly IPAddress SOLICITED_NODE = IPAddress.Parse("FF02:0:0:0:0:1:FF00:0000");
        private static readonly IPAddress ALL_NODES = IPAddress.Parse("FF02::1");

        public NeighborDiscovery(int nicIndex, bool linkLocal) : this(ICMPv6Socket.GetNicAddress(nicIndex, linkLocal)) { }

        public NeighborDiscovery(IPAddress nicAddress)
        {
            //TODO - Promiscious mode required on windows, verify if this is needed on other platforms
            socket = new ICMPv6Socket(nicAddress, true);
        }

        public async Task<List<IPAddress>> GetAddresses(PhysicalAddress target, CancellationToken token = default)
        {
            PhysicalAddress? sourceMAC = ICMPv6Socket.GetNicPhysicalAddress(socket.ListenAddress);
            if (sourceMAC == null)
                return [];
            ICMPPacket IND = NDPPayload.CreateInverseNeighborSolicitation(socket.ListenAddress, ALL_NODES, target, sourceMAC);
            await socket.SendAsync(IND, ALL_NODES, token);
            try
            {
                while (!token.IsCancellationRequested)
                {
                    ICMPPacket packet = await socket.ReceiveAsync(false, token);
                    if (packet.Type == ICMPType.InverseNeighborDiscoveryAdvertisement && (packet.Payload != null))
                    {
                        NDPPayload ndp = (NDPPayload)packet.Payload;
                        bool valid = false;
                        foreach (var option in ndp.Options)
                        {
                            if (option is NDPOptionLinkLocal ll)
                            {
                                if (ll.TargetAddress == target)
                                { 
                                    valid = true;
                                    break;
                                }
                            }
                        }
                        if (valid)
                        {
                            foreach (var option in ndp.Options)
                                if (option is NDPOptionAddressList al)
                                    return al.Addresses;
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            return [];
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
                                return ll.TargetAddress;
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
