

using ICMPv6DotNet;
using ICMPv6DotNet.Net;

internal class Program
{
    private static async Task Main(string[] args)
    {
        Console.WriteLine("Running...");
        ICMPListener listener = new ICMPListener(0, true);
        while (true)
        {
            ICMPPacket packet = await listener.ReceivePacketAsync();
            Console.WriteLine(packet.ToString());
            Console.WriteLine();
        }
    }
}