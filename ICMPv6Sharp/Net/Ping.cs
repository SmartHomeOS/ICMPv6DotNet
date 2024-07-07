﻿// ICMPv6DotNet Copyright (C) 2024
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

using ICMPv6DotNet.Payloads;
using System.Net;

namespace ICMPv6DotNet.Net
{
    public class Ping
    {
        protected ICMPv6Socket socket;
        private ushort identifier;
        private ushort sequence;

        public Ping(int nicIndex, bool linkLocal) : this(ICMPv6Socket.GetNicAddress(nicIndex, linkLocal)) { }

        public Ping(IPAddress nicAddress)
        {
            socket = new ICMPv6Socket(nicAddress, false);
            identifier = (ushort)new Random().Next();
            sequence = 0;
        }

        public async Task<TimeSpan> PingAsync(IPAddress address, int payloadSize = 64, int timeout = 3000)
        {
            CancellationTokenSource cts = new CancellationTokenSource(timeout);
            EndPoint ep = new IPEndPoint(IPAddress.IPv6Any, 0);
            byte[] data = Enumerable.Repeat((byte)'J', payloadSize).ToArray();
            ICMPPacket echoRequest = ICMPEchoPayload.CreateRequest(socket.ListenAddress, address, identifier, sequence, data);
            sequence++;
            await socket.SendAsync(echoRequest, address);
            DateTime start = DateTime.Now;
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    ICMPPacket packet = await socket.ReceiveAsync(false, cts.Token);
                    if (packet.Type == ICMPType.EchoReply && (packet.Payload != null) && ((ICMPEchoPayload)packet.Payload).Identifier == identifier)
                        return DateTime.Now - start;
                }
            }
            catch (OperationCanceledException) { }
            return new TimeSpan(-1);
        }

        public void Stop()
        {
            socket.Close();
        }
    }
}
