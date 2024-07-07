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
using System.Net;

namespace ICMPv6DotNet.Net
{
    public class MulticastDiscovery
    {
        protected ICMPv6Socket socket;

        private static readonly IPAddress ALL_NODES = IPAddress.Parse("FF02::1");
        private static readonly IPAddress ALL_MLDV2_ROUTERS = IPAddress.Parse("FF02::16");

        public MulticastDiscovery(int nicIndex, bool linkLocal) : this(ICMPv6Socket.GetNicAddress(nicIndex, linkLocal)) { }

        public MulticastDiscovery(IPAddress nicAddress)
        {
            //TODO - Promiscious mode required on windows, verify if this is needed on other platforms
            socket = new ICMPv6Socket(nicAddress, true);
            socket.JoinMulticast(ALL_MLDV2_ROUTERS);
        }

        public async Task<HashSet<IPAddress>> GeneralQuery(int timeout = 10000)
        {
            CancellationTokenSource cts = new CancellationTokenSource(timeout);
            ICMPPacket multicastQuery = MLDQueryPayload.CreateGeneralQuery(socket.ListenAddress, ALL_NODES, 30, 30, 0, false);
            await socket.SendAsync(multicastQuery, ALL_NODES, cts.Token);
            HashSet<IPAddress> sources = new HashSet<IPAddress>();
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    ICMPPacket packet = await socket.ReceiveAsync(false, cts.Token);
                    if (packet.Type == ICMPType.MLDv2Report && (packet.Payload != null))
                    {
                        foreach (var option in ((MLDReportPayload)packet.Payload).Groups)
                            sources.UnionWith(option.SourceAddresses);
                        sources.Add(packet.Source);
                    }
                }
            }
            catch (OperationCanceledException) { }
            return sources;
        }

        public void Stop()
        {
            socket.Close();
        }
    }
}
