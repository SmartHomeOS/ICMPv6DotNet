using System;
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
        bool listenAll;
        public ICMPv6Socket(IPAddress listenAddress, bool listenAll)
        {
            socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
            socket.Bind(new IPEndPoint(listenAddress, 0));
            buffer = new byte[65535];
            this.listenAddress = listenAddress;
            this.listenAll = listenAll;

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
                packet = new ICMPPacket(buffer.Slice(0, result.ReceivedBytes).Span, ((IPEndPoint)result.RemoteEndPoint).Address, listenAll ? result.PacketInformation.Address : listenAddress);
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
                packet = new ICMPPacket(buffer.Slice(0, len).Span, ((IPEndPoint)ep).Address, listenAll ? info.Address : listenAddress);
            }
            return packet;
        }

        public IPAddress ListenAddress { get { return this.listenAddress; } }
    }
}
