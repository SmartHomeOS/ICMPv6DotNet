// ICMPv6DotNet Copyright (C) 2024
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY, without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

using System.Buffers.Binary;
using System.Text;

namespace ICMPv6DotNet.Payloads.MLD
{
    public class MLDV2ReportPayload : ICMPV6Payload
    {
        protected readonly bool valid = true;

        public MLDV2ReportPayload(Span<byte> buffer) : base()
        {
            if (buffer.Length < 8)
            {
                valid = false;
                Groups = [];
                return;
            }
            ushort count = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2));
            Groups = new List<MulticastGroupRecordV3>(count);
            int start = 4;
            try
            {
                for (int i = 0; i < count; i++)
                    Groups.Add(new MulticastGroupRecordV3(buffer, ref start));
            }
            catch (InvalidDataException)
            {
                valid = false;
            }
        }

        public override int WritePacket(Span<byte> buffer)
        {
            int len = 4;
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2, 2), (ushort)Groups.Count);
            foreach (MulticastGroupRecordV3 group in Groups)
            {
                len += group.WritePacket(buffer);
            }
            return len;
        }

        public override bool IsValid => valid;

        public override string ToString()
        {
            if (Groups.Count == 0)
                return string.Empty;
            if (!valid)
                return "Invalid MLD Report";
            StringBuilder str = new StringBuilder();
            str.Append("Multicast Groups: ");
            for (int i = 0; i < Groups.Count; i++)
            {
                if (i > 0)
                    str.Append(", ");
                str.Append($"[{Groups[i]}]");
            }
            return str.ToString();
        }

        public List<MulticastGroupRecordV3> Groups;
    }
}
