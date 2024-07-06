using System.Buffers.Binary;
using System.Text;

namespace ICMPv6DotNet.Payloads.MLD
{
    public class MLDReportPayload : ICMPV6Payload
    {
        protected readonly bool valid = true;
        protected readonly List<MulticastGroupRecordV3> groups;

        public MLDReportPayload(Memory<byte> buffer, ICMPType type) : base()
        {
            if (buffer.Length < 8)
            {
                valid = false;
                groups = new List<MulticastGroupRecordV3>();
                return;
            }
            ushort count = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2).Span);
            groups = new List<MulticastGroupRecordV3>(count);
            int start = 4;
            try
            {
                for (int i = 0; i < count; i++)
                    groups.Add(new MulticastGroupRecordV3(buffer, ref start));
            }
            catch (InvalidDataException)
            {
                valid = false;
            }
        }

        public override int WritePacket(Span<byte> buffer)
        {
            int len = 4;
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2, 2), (ushort)groups.Count);
            foreach (MulticastGroupRecordV3 group in groups)
            {
                len += group.WritePacket(buffer);
            }
            return len;
        }

        public override string ToString()
        {
            if (groups.Count == 0)
                return string.Empty;
            if (!valid)
                return "Invalid MLD Report";
            StringBuilder str = new StringBuilder();
            str.Append("Multicast Groups: ");
            for (int i = 0; i < groups.Count; i++)
            {
                if (i > 0)
                    str.Append(", ");
                str.Append($"[{groups[i]}]");
            }
            return str.ToString();
        }
    }
}
