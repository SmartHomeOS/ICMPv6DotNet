using System.Buffers.Binary;
using System.Net;

namespace ICMPv6DotNet.Payloads.MLD
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

        public int WritePacket(Span<byte> buffer)
        {
            int len = 0;
            buffer[len++] = (byte)RecordType;
            buffer[len++] = 0; //Aux Data isn't defined yet
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(len), (ushort)SourceAddresses.Length);
            len += 2;
            if (!MulticastAddress.TryWriteBytes(buffer.Slice(len), out _))
                throw new InvalidDataException("Could not write multicast to buffer");
            len += 16;
            foreach (var source in SourceAddresses)
            {
                if (!source.TryWriteBytes(buffer.Slice(len), out _))
                    throw new InvalidDataException("Could not write multicast to buffer");
                len += 16;
            }
            return len;
        }

        public override string ToString()
        {
            return $"Type: {RecordType}, Multicast: {MulticastAddress}, Sources: {string.Join(',', SourceAddresses.ToList())}";
        }
    }
}
