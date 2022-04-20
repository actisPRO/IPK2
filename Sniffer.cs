using PacketDotNet;
using SharpPcap;

namespace IPK2.Zeta;

public class Sniffer
{
    public readonly Settings Settings;
    private readonly ILiveDevice _interface;
    private int _packetsCatched = 0;

    public Sniffer(Settings settings)
    {
        Settings = settings;

        _interface = CaptureDeviceList.Instance.FirstOrDefault(i => i.Name == settings.Interface) ??
                     throw new InvalidOperationException();
    }

    private string BuildFilter()
    {
        List<string> filters = new List<string>();
        if (Settings.ARP)
            filters.Add(BuildPortProtocolFilter("ether proto \\arp"));
        if (Settings.ICMP)
            filters.Add(BuildPortProtocolFilter("icmp"));
        if (Settings.TCP)
            filters.Add(BuildPortProtocolFilter("tcp"));
        if (Settings.UDP)
            filters.Add(BuildPortProtocolFilter("udp"));

        return String.Join(" or ", filters);
    }

    private string BuildPortProtocolFilter(string protocol)
    {
        if (Settings.Port <= 0 || Settings.Port >= 65535)
            return protocol;
        else
            return $"port {Settings.Port} and {protocol}";
    }

    public void StartCapture()
    {
        _interface.Open();
        _interface.Filter = BuildFilter();
        _interface.OnPacketArrival += InterfaceOnOnPacketArrival;
        _interface.StartCapture();
    }

    public void StopCapture()
    {
        _interface.StopCapture();
        _interface.Dispose();
    }

    private void InterfaceOnOnPacketArrival(object sender, PacketCapture e)
    {
        var rawPacket = e.GetPacket();
        var data = new PacketData
        {
            Timestamp = rawPacket.Timeval.Date,
            FrameLength = rawPacket.PacketLength
        };
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

        data = TryReadTransportData(packet, data);
        
        Console.WriteLine(data);

        _packetsCatched += 1;
        if (_packetsCatched >= Settings.NumberOfPackets)
            StopCapture();
    }

    private PacketData TryReadTransportData(Packet packet, PacketData existingData)
    {
        var transportPacket = packet.Extract<TransportPacket>();
        if (transportPacket != null)
        {
            var ethPacket = packet.Extract<EthernetPacket>();
            var ipPacket = (IPPacket) transportPacket.ParentPacket;

            var data = existingData with
            {
                Source = ethPacket.SourceHardwareAddress,
                Destination = ethPacket.DestinationHardwareAddress,
                SourceAddress = ipPacket.SourceAddress,
                DestinationAddress = ipPacket.DestinationAddress,
                SourcePort = transportPacket.SourcePort,
                DestinationPort = transportPacket.DestinationPort
            };
            return data;
        }
        
        return existingData;
    }
}