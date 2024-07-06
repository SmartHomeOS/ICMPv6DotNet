using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace ICMPv6DotNet.Payloads
{
    public class ICMPEchoPayload : ICMPV6Payload
    {
        public ICMPEchoPayload(Memory<byte> buffer) : base()
        {
            Identifier = BinaryPrimitives.ReadUInt16BigEndian(buffer.Span);
            SequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2).Span);
            if (buffer.Length > 4)
                Data = buffer.Slice(4).ToArray();
            else
                Data = [];
        }
        protected ICMPEchoPayload(ushort id, ushort seq, byte[] data)
        {
            this.Identifier = id;
            this.SequenceNumber = seq;
            this.Data = data;
        }

        public override string ToString()
        {
            return $"ID: {Identifier}, SEQ: {SequenceNumber}, Payload: " + Encoding.ASCII.GetString(Data);
        }

        public override int WritePacket(Span<byte> buffer)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buffer, Identifier);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), SequenceNumber);
            Data.CopyTo(buffer.Slice(4));
            return Data.Length + 4;
        }

        public static ICMPPacket CreateRequest(IPAddress source, IPAddress destination, ushort identifier, ushort sequence, byte[] data)
        {
            ICMPEchoPayload payload = new ICMPEchoPayload(identifier, sequence, data);
            return new ICMPPacket(source, destination, ICMPType.EchoRequest, 0, payload);
        }

        public static ICMPPacket CreateResponse(IPAddress source, IPAddress destination, ushort identifier, ushort sequence, byte[] data)
        {
            ICMPEchoPayload payload = new ICMPEchoPayload(identifier, sequence, data);
            return new ICMPPacket(source, destination, ICMPType.EchoReply, 0, payload);
        }

        public ushort Identifier { get; set; }
        public ushort SequenceNumber { get; set; }
        public byte[] Data { get; set; }
    }
}
