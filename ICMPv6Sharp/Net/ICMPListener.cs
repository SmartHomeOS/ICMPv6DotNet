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

using System.Net;

namespace ICMPv6DotNet.Net
{
    public class ICMPListener
    {
        protected ICMPv6Socket socket;

        public ICMPListener(int nicIndex, bool linkLocal) : this(ICMPv6Socket.GetNicAddress(nicIndex, linkLocal))  {  }

        public ICMPListener(IPAddress nicAddress)
        {
            socket = new ICMPv6Socket(nicAddress, true);
        }

        public ICMPPacket ReceivePacket(int timeout)
        {
            return socket.Receive(timeout, true);
        }

        public async Task<ICMPPacket> ReceivePacketAsync(CancellationToken token = default)
        {
            return await socket.ReceiveAsync(true, token);
        }

        public void Stop()
        {
            socket.Close();
        }
    }
}
