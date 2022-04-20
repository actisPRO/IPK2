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

    public void StartCapture()
    {
        _interface.Open();
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
        var rawCapture = e.GetPacket();
        if (rawCapture.LinkLayerType != LinkLayers.Ethernet)
            return;
        var packet = (EthernetPacket) rawCapture.GetPacket();

        if (packet.Type == EthernetType.Arp && Settings.ARP)
        {
            PrintArpData((ArpPacket) rawCapture.GetPacket());
        }
        else if (packet.Type == EthernetType.IPv4)
        {
            var ipv4 = (IPv4Packet) rawCapture.GetPacket();
            if (ipv4.Protocol == ProtocolType.Icmp && !Settings.ICMP)
                PrintIcmpData((IcmpV4Packet) rawCapture.GetPacket());
            else if (ipv4.Protocol == ProtocolType.Udp && !Settings.UDP)
                PrintUdpData((UdpPacket) rawCapture.GetPacket());
            else if (ipv4.Protocol == ProtocolType.Tcp && !Settings.TCP)
                PrintTcpData((TcpPacket) rawCapture.GetPacket());
            else
                return;
        }
        else
        {
            return;
        }
        
        _packetsCatched += 1;
        if (_packetsCatched >= Settings.NumberOfPackets)
            StopCapture();
    }

    private void PrintArpData(ArpPacket packet)
    {
        
    }

    private void PrintIcmpData(IcmpV4Packet packet)
    {
        
    }

    private void PrintUdpData(UdpPacket packet)
    {
        
    }

    private void PrintTcpData(TcpPacket packet)
    {
        
    }
}