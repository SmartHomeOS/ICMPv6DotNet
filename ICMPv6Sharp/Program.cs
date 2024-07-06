

using ICMPv6DotNet;
using ICMPv6DotNet.Net;
using System.Net;

internal class Program
{
    private static async Task Main(string[] args)
    {
        await ListenerExample();
    }

    private static async Task PingExample()
    {
        IPAddress dest = IPAddress.Parse("fe80::8ab7:f6ff:fe03:c32c");
        Console.WriteLine("Running...");
        Ping pinger = new Ping(0, true);
        
        Console.WriteLine($"Pinging {dest} with 32 bytes of data:");
        double total = 0;
        int success = 0;
        double min = double.MaxValue;
        double max = 0;
        for (int i = 0; i < 4; i++)
        {
            TimeSpan ts = await pinger.PingAsync(dest, 32);
            if (ts.TotalMilliseconds >= 0)
            {
                success++;
                total += ts.TotalMilliseconds;
                if (ts.TotalMilliseconds > max)
                    max = ts.TotalMilliseconds;
                if (ts.TotalMilliseconds < min)
                    min = ts.TotalMilliseconds;
                Console.WriteLine($"Reply from {dest}: Time={ts.TotalMilliseconds:F}ms");
            }
            else
                Console.WriteLine("Request timed out");
        }
        Console.WriteLine($"\nPing statistics for {dest}:");
        Console.WriteLine($"    Packets: Sent = 4, Received = {success}, Lost = {4 - success} ({(int)(((4-success) / 4.0) * 100)}% loss),");
        if (success > 0)
        {
            Console.WriteLine($"Approximate round trip times in milli-seconds:");
            Console.WriteLine($"    Minimum = {min:F}ms, Maximum = {max:F}ms, Average = {(total / 4):F}ms");
        }
        Console.ReadLine();
    }

    private static async Task ListenerExample()
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