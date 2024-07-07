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
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ICMPv6DotNet.Net
{
    public class ICMPv6Socket
    {
        private Socket socket;
        private Memory<byte> buffer;
        IPAddress listenAddress;

        public ICMPv6Socket(IPAddress listenAddress, bool listenAll)
        {
            socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
            socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, (short)255);
            socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.PacketInformation, true);
            socket.Bind(new IPEndPoint(listenAddress, 0));
            buffer = new byte[65535];
            this.listenAddress = listenAddress;

            if (listenAll)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(3), null);
            }
        }


        public static IPAddress GetNicAddress(int nicIndex, bool linkLocal)
        {
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            if (!nics[nicIndex].Supports(NetworkInterfaceComponent.IPv6))
                throw new ArgumentException("Selected interface does not support IPv6");
            foreach (UnicastIPAddressInformation adddress in nics[nicIndex].GetIPProperties().UnicastAddresses)
            {
                if (adddress.Address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    if (!linkLocal || adddress.Address.IsIPv6LinkLocal)
                        return adddress.Address;
                }
            }
            throw new ArgumentException("Specified Network Interface does not contain IPv6 Addresses");
        }

        public static PhysicalAddress? GetNicPhysicalAddress(IPAddress address)
        {
            IEnumerable<NetworkInterface> nics = NetworkInterface.GetAllNetworkInterfaces().Where(nic => nic.OperationalStatus == OperationalStatus.Up);
            foreach (NetworkInterface nic in nics)
            {
                if (nic.GetIPProperties().UnicastAddresses.Any(adr => adr.Address.Equals(address)))
                    return nic.GetPhysicalAddress();
            }
            return null;
        }

        public async Task SendAsync(ICMPPacket packet, IPAddress destination)
        {
            int len = packet.WritePacket(buffer.Span);
            await socket.SendToAsync(buffer.Slice(0, len), new IPEndPoint(destination, 0));
        }

        public void Send(ICMPPacket packet, IPAddress destination)
        {
            int len = packet.WritePacket(buffer.Span);
            socket.SendTo(buffer.Slice(0, len).Span, new IPEndPoint(destination, 0));
        }

        public async Task<ICMPPacket> ReceiveAsync(bool includeInvalid = false, CancellationToken token = default)
        {
            EndPoint ep = new IPEndPoint(IPAddress.IPv6Any, 0);
            ICMPPacket? packet = null;
            while (packet == null || (!includeInvalid && !packet.IsValid))
            {
                var result = await socket.ReceiveMessageFromAsync(buffer, SocketFlags.None, ep, token);
                packet = new ICMPPacket(buffer.Slice(0, result.ReceivedBytes).Span, ((IPEndPoint)result.RemoteEndPoint).Address, result.PacketInformation.Address);
                if (packet == null || !packet.IsValid)
                    Console.WriteLine("Invalid Packet");
            }
            return packet;
        }

        public ICMPPacket Receive(int timeout, bool includeInvalid = false)
        {
            socket.ReceiveTimeout = timeout;
            SocketFlags none = SocketFlags.None;
            EndPoint ep = new IPEndPoint(IPAddress.IPv6Any, 0);
            ICMPPacket? packet = null;
            while (packet == null || (!includeInvalid && !packet.IsValid))
            {
                var len = socket.ReceiveMessageFrom(buffer.Span, ref none, ref ep, out IPPacketInformation info);
                packet = new ICMPPacket(buffer.Slice(0, len).Span, ((IPEndPoint)ep).Address,  info.Address);
            }
            return packet;
        }

        public void Close()
        {
            socket.Shutdown(SocketShutdown.Both);
            socket.Close();
        }

        public IPAddress ListenAddress { get { return this.listenAddress; } }
    }
}
