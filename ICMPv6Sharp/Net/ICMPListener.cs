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
