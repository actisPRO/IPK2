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
}