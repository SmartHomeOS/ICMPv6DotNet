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
using System.Net;
using System.Text;

namespace ICMPv6DotNet.Payloads.MLD
{
    public class MLDPayload : ICMPV6Payload
    {
        protected readonly bool valid = true;

        public MLDPayload(Span<byte> buffer) : base()
        {
            if (buffer.Length < 20)
            {
                valid = false;
                Sources = [];
                MulticastAddress = IPAddress.None;
                return;
            }
            MaxResponseDelay = BinaryPrimitives.ReadUInt16BigEndian(buffer);
            MulticastAddress = new IPAddress(buffer.Slice(4, 16));
            if (buffer.Length < 24)
            {
                Sources = [];
                Version = 1;
                return;
            }
            ushort maxResponse = (ushort)MaxResponseDelay;
            if (maxResponse <= short.MaxValue)
                MaxResponseDelay = maxResponse;
            else
            {
                int mant = (maxResponse & 0xFFF) | 0x1000;
                int exp = (maxResponse & 0x7000) >> 12;
                MaxResponseDelay = (uint)(mant << (exp + 3));
            }
            Suppress = (buffer[20] & 0x8) == 0x8;
            Robustness = (byte)(buffer[20] & 0x7);
            if (buffer[21] <= sbyte.MaxValue)
                QueryInterval = buffer[21];
            else
            {
                int exp = (buffer[21] & 0x70) >> 4;
                QueryInterval = (ushort)(((buffer[21] & 0x7) | 0x10) << (exp + 3));
            }
            ushort count = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(22));
            Sources = new List<IPAddress>(count);
            try
            {
                for (int i = 0; i < count; i++)
                    Sources.Add(new IPAddress(buffer.Slice(24 + (i * 16), 16)));
            }
            catch (Exception)
            {
                valid = false;
            }
            Version = 2;
        }

        public MLDPayload(uint maxResponseDelay, ushort queryInterval, byte robustness, bool suppress, IPAddress multicast, List<IPAddress> sources)
        {
            MaxResponseDelay = maxResponseDelay;
            QueryInterval = queryInterval;
            Robustness = robustness;
            Suppress = suppress;
            MulticastAddress = multicast;
            Sources = sources;
        }

        public override int WritePacket(Span<byte> buffer)
        {
            if (MaxResponseDelay <= short.MaxValue)
                BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)MaxResponseDelay);
            else
            {
                int exp = getExponent(MaxResponseDelay);
                int mant = getMantissa((int)MaxResponseDelay, exp);
                if (mant > 0x1FFF)
                    mant = 0xFFF;
                buffer[0] = (byte)(0x80 | exp);
                buffer[0] |= (byte)((mant >> 8) & 0xF);
                buffer[1] = (byte)(mant & 0xFF);
            }
            if (!MulticastAddress.TryWriteBytes(buffer.Slice(4, 16), out _))
                throw new InvalidDataException("Unable to write Multicast Address");
            buffer[20] = (byte)(0x7 & Robustness);
            if (Suppress)
                buffer[20] |= 0x8;
            if (QueryInterval <= sbyte.MaxValue)
                buffer[21] = (byte)QueryInterval;
            else
            {
                int exp = getExponent(QueryInterval);
                int mant = getMantissa(QueryInterval, exp);
                buffer[21] = (byte)(0x80 | (exp << 4));
                if (mant <= 0x1FF)
                    buffer[21] |= (byte)(mant & 0xF);
                else
                    buffer[21] |= 0xF;
            }
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(22, 2), (ushort)Sources.Count);
            for (int i = 0; i < Sources.Count; i++)
                Sources[i].TryWriteBytes(buffer.Slice(24 + (16 * i), 16), out _);
            return 24 + (16 * Sources.Count);
        }

        public override bool IsValid => valid;

        protected static int getMantissa(int number, int exponent)
        {
            int mant = number >> (3 + exponent);
            int mask = 0x3FF >> (7 - exponent);
            if ((number & mask) >= (mask >> 1))
                mant++; //Round to minimize loss of precision
            return mant;
        }

        protected static int getExponent(uint val)
        {
            for (int i = 0; i < 7; i++)
            {
                if ((val >> (i + 3)) <= 0x1FFF)
                    return i;
            }
            return 7;
        }

        protected static int getExponent(ushort val)
        {
            for (int i = 0; i < 7; i++)
            {
                if ((val >> (i + 3)) <= 0x1F)
                    return i;
            }
            return 7;
        }

        public override string ToString()
        {
            if (!valid)
                return "Invalid MLD Query";
            StringBuilder str = new StringBuilder();
            str.Append($"V{Version} Multicast: {MulticastAddress}");
            if (Version > 1)
            {
                if (Suppress)
                    str.Append(" [S]");
                str.Append($", QRV: {Robustness}, QQIC: {QueryInterval}, Sources: ");
                for (int i = 0; i < Sources.Count; i++)
                {
                    if (i > 0)
                        str.Append(", ");
                    str.Append(Sources[i]);
                }
            }
            return str.ToString();
        }

        public static ICMPPacket CreateGeneralQuery(IPAddress source, IPAddress destination, uint maxResponseDelay, ushort queryInterval, byte robustness, bool suppress)
        {
            MLDPayload query = new MLDPayload(maxResponseDelay, queryInterval, robustness, suppress, IPAddress.IPv6None, []);
            return new ICMPPacket(source, destination, ICMPType.MLDQuery, 0, query);
        }

        public static ICMPPacket CreateMulticastQuery(IPAddress source, IPAddress destination, IPAddress multicastAddress, uint maxResponseDelay, ushort queryInterval, byte robustness, bool suppress)
        {
            MLDPayload query = new MLDPayload(maxResponseDelay, queryInterval, robustness, suppress, multicastAddress, []);
            return new ICMPPacket(source, destination, ICMPType.MLDQuery, 0, query);
        }

        public static ICMPPacket CreateSourceQuery(IPAddress source, IPAddress destination, IPAddress multicastAddress, List<IPAddress> sources, uint maxResponseDelay, ushort queryInterval, byte robustness, bool suppress)
        {
            MLDPayload query = new MLDPayload(maxResponseDelay, queryInterval, robustness, suppress, multicastAddress, sources);
            return new ICMPPacket(source, destination, ICMPType.MLDQuery, 0, query);
        }

        public List<IPAddress> Sources { get; private set; }
        public IPAddress MulticastAddress { get; private set; }
        public uint MaxResponseDelay { get; private set; }
        public bool Suppress {  get; private set; }
        public byte Robustness{ get; private set; }
        public ushort QueryInterval { get; private set; }
        public byte Version { get; private set; }
    }
}
