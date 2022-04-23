using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace IPK2.Zeta
{
    public class PacketData
    {
        public DateTime Timestamp { get; set; }
        public PhysicalAddress Source { get; set; } = null!;
        public PhysicalAddress Destination { get; set; } = null!;
        public int FrameLength { get; set; }
        public IPAddress? SourceAddress { get; set; }
        public IPAddress? DestinationAddress { get; set; }
        public int? SourcePort { get; set; }
        public int? DestinationPort { get; set; }
        public byte[] Bytes { get; set; } = null!;

        public override string ToString()
        {
            var result = "";

            result += $"timestamp: {Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.ffffffK")}\n";
            result += $"src MAC: {FormatMac(Source)}\n";
            result += $"dest MAC: {FormatMac(Destination)}\n";
            result += $"frame length: {FrameLength} bytes\n";
            if (SourceAddress != null)
                result += $"src IP: {SourceAddress}\n";
            if (DestinationAddress != null)
                result += $"dest IP: {DestinationAddress}\n";
            if (SourcePort != null)
                result += $"src port: {SourcePort}\n";
            if (DestinationPort != null)
                result += $"dest port: {DestinationPort}\n";

            result += FormatBytes() + "\n";

            return result;
        }

        /// <summary>
        ///     Converts PhysicalAddress to a ':' separated string.
        /// </summary>
        private string FormatMac(PhysicalAddress mac)
        {
            var macParts = (from part in mac.GetAddressBytes() select part.ToString("X2")).ToArray();
            return string.Join(":", macParts);
        }

        /// <summary>
        ///     Formats packet bytes: 16 bytes per line, offset, hex and char values
        /// </summary>
        private string FormatBytes()
        {
            var result = "";
            var hexes = new List<string>();
            var chars = new List<char>();

            var offset = 0;
            for (var currentByte = 0; currentByte < Bytes.Length; ++currentByte)
            {
                if (currentByte != 0 && currentByte % 16 == 0)
                {
                    result += $"0x{offset:X4}: {string.Join(' ', hexes)} {string.Join(' ', chars)}\n";
                    hexes.Clear();
                    chars.Clear();
                }

                hexes.Add(Bytes[currentByte].ToString("X2"));
                chars.Add(ByteToChar(Bytes[currentByte]));

                if (currentByte % 16 == 0)
                    offset = currentByte;
            }

            if (hexes.Any())
                result += $"0x{offset:X4}: {string.Join(' ', hexes)} {string.Join(' ', chars)}\n";

            return result;
        }

        /// <summary>
        ///     Converts byte to char
        /// </summary>
        /// <returns>Char representation of the specified byte or '.' if byte is lower than 32</returns>
        private char ByteToChar(byte b)
        {
            if (b < 32)
                return '.';

            return (char) b;
        }
    }
}