using System.Net;
using System.Net.NetworkInformation;

namespace IPK2.Zeta;

public record PacketData
{
    public DateTime Timestamp { get; set; }
    public PhysicalAddress Source { get; set; }
    public PhysicalAddress Destination { get; set; }
    public int FrameLength { get; set; }
    public IPAddress? SourceAddress { get; set; }
    public IPAddress? DestinationAddress { get; set; }
    public int? SourcePort { get; set; }
    public int? DestinationPort { get; set; }

    public override string ToString()
    {
        string result = "";

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
            result += $"dest port: {DestinationPort}\n\n";

        return result;
    }

    private string FormatMac(PhysicalAddress mac)
    {
        string[] macParts = (from part in mac.GetAddressBytes() select part.ToString("X2")).ToArray();
        return String.Join(":", macParts);   
    }
}