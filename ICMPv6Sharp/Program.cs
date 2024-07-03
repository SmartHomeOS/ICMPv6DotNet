

using ICMPv6DotNet;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

var sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);

sock.Bind(new IPEndPoint(IPAddress.Parse("fe80::1c2:fcbb:146a:a709%16"), 0));
if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
{
    sock.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(3), null);
}
Span<Byte> buff = new byte[8192];
EndPoint ep = new IPEndPoint(IPAddress.IPv6Any, 0);
Console.WriteLine("Running...");
while (true)
{
    SocketFlags none = SocketFlags.None;
    var len = sock.ReceiveMessageFrom(buff, ref none, ref ep, out IPPacketInformation info);
    ICMPPacket packet = new ICMPPacket(buff.Slice(0, len), ((IPEndPoint)ep).Address, info.Address);
    Console.WriteLine(packet.ToString());
    Console.WriteLine();
}
