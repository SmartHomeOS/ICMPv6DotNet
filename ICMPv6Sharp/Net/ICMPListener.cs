using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ICMPv6DotNet.Net
{
    public class ICMPListener
    {
        protected Socket socket;
        private readonly Memory<Byte> buffer = new byte[65535];

        public ICMPListener(int nicIndex, bool linkLocal) : this(GetNicAddress(nicIndex, linkLocal))  {  }

        public ICMPListener(IPAddress nicAddress)
        {
            socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
            socket.Bind(new IPEndPoint(nicAddress, 0));

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(3), null);
        }

        private static IPAddress GetNicAddress(int nicIndex, bool linkLocal)
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

        public ICMPPacket ReceivePacket(int timeout)
        {
            socket.ReceiveTimeout = timeout;
            SocketFlags none = SocketFlags.None;
            EndPoint ep = new IPEndPoint(IPAddress.IPv6Any, 0);
            var len = socket.ReceiveMessageFrom(buffer.Span, ref none, ref ep, out IPPacketInformation info);
            return new ICMPPacket(buffer.Slice(0, len).Span, ((IPEndPoint)ep).Address, info.Address);
        }

        public async Task<ICMPPacket> ReceivePacketAsync(CancellationToken token = default)
        {
            EndPoint ep = new IPEndPoint(IPAddress.IPv6Any, 0);
            var result = await socket.ReceiveMessageFromAsync(buffer, SocketFlags.None, ep, token);
            return new ICMPPacket(buffer.Slice(0, result.ReceivedBytes).Span, ((IPEndPoint)result.RemoteEndPoint).Address, result.PacketInformation.Address);
        }
    }
}
