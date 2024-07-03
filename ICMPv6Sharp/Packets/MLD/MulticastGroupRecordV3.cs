using System.Buffers.Binary;
using System.Net;

namespace ICMPv6DotNet.Packets.MLD
{
    public class MulticastGroupRecordV3
    {
        public MLDGroupRecordType RecordType { get; protected set; }
        public IPAddress MulticastAddress { get; protected set; }
        public IPAddress[] SourceAddresses { get; protected set; }
        public MulticastGroupRecordV3(Memory<byte> buffer, ref int start)
        {
            if (buffer.Length < start + 8)
                throw new InvalidDataException();
            RecordType = (MLDGroupRecordType)buffer.Span[start++];
            byte auxLen = buffer.Span[start++];
            ushort numSources = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(start).Span);
            start += 2;
            MulticastAddress = new IPAddress(buffer.Slice(start, 16).Span);
            start += 16;
            SourceAddresses = new IPAddress[numSources];
            for (int i = 0; i < numSources; i++)
            {
                if (buffer.Length < start + 16)
                    throw new InvalidDataException("Multicast v3 sources truncated");
                SourceAddresses[i] = new IPAddress(buffer.Slice(start, 16).Span);
                start += 16;
            }
            start += auxLen;
        }

        public override string ToString()
        {
            return $"Type: {RecordType}, Multicast: {MulticastAddress}, Sources: {string.Join(',', SourceAddresses.ToList())}";
        }
    }
}
