using System;
using System.Collections.Generic;
using System.Linq;
using PacketDotNet;
using SharpPcap;

namespace IPK2.Zeta
{
    public class Sniffer
    {
        private readonly ILiveDevice _interface;
        public readonly Settings Settings;
        private int _packetsCatched;

        public Sniffer(Settings settings)
        {
            Settings = settings;

            _interface = CaptureDeviceList.Instance.FirstOrDefault(i => i.Name == settings.Interface) ??
                         throw new InvalidOperationException();
        }

        /// <summary>
        ///     Builds a Berkley Packet Filter (based on setting parameter)
        /// </summary>
        private string BuildFilter()
        {
            var filters = new List<string>();
            if (Settings.ARP)
                filters.Add(BuildPortProtocolFilter("ether proto \\arp"));
            if (Settings.ICMP)
            {
                filters.Add(BuildPortProtocolFilter("icmp"));
                filters.Add(BuildPortProtocolFilter("icmp6"));
            }
            if (Settings.TCP)
                filters.Add(BuildPortProtocolFilter("tcp"));
            if (Settings.UDP)
                filters.Add(BuildPortProtocolFilter("udp"));

            return string.Join(" or ", filters);
        }

        /// <summary>
        ///     Builds an AND part of BPF
        /// </summary>
        private string BuildPortProtocolFilter(string protocol)
        {
            if (Settings.Port <= 0 || Settings.Port >= 65535)
                return protocol;
            return $"port {Settings.Port} and {protocol}";
        }

        public void StartCapture()
        {
            _interface.Open(DeviceModes.Promiscuous);
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
            data = TryReadIcmpData(packet, data);
            data = TryReadArpData(packet, data);

            Console.WriteLine(data);

            _packetsCatched += 1;
            if (_packetsCatched >= Settings.NumberOfPackets)
                StopCapture();
        }

        /// <summary>
        ///     Tries to read the provided packet as a transport packet.
        /// </summary>
        /// <returns>Filled PacketData or existingData if not a transport packet</returns>
        private PacketData TryReadTransportData(Packet packet, PacketData existingData)
        {
            var transportPacket = packet.Extract<TransportPacket>();
            if (transportPacket != null)
            {
                var ethPacket = packet.Extract<EthernetPacket>();
                var ipPacket = (IPPacket) transportPacket.ParentPacket;

                var data = existingData;

                data.Source = ethPacket.SourceHardwareAddress;
                data.Destination = ethPacket.DestinationHardwareAddress;
                data.SourceAddress = ipPacket.SourceAddress;
                data.DestinationAddress = ipPacket.DestinationAddress;
                data.SourcePort = transportPacket.SourcePort;
                data.DestinationPort = transportPacket.DestinationPort;
                data.Bytes = transportPacket.Bytes;

                return data;
            }

            return existingData;
        }

        /// <summary>
        ///     Tries to read the provided packet as an ICMP packet
        /// </summary>
        /// <returns>Filled PacketData or existingData if not an ICMP packet</returns>
        private PacketData TryReadIcmpData(Packet packet, PacketData existingData)
        {
            var icmp4Packet = packet.Extract<IcmpV4Packet>();
            var icmp6Packet = packet.Extract<IcmpV6Packet>();
            if (icmp4Packet != null || icmp6Packet != null)
            {
                var ipPacket = packet.Extract<IPPacket>();
                var ethPacket = packet.Extract<EthernetPacket>();
                var data = existingData;

                data.Source = ethPacket.SourceHardwareAddress;
                data.Destination = ethPacket.DestinationHardwareAddress;
                data.SourceAddress = ipPacket.SourceAddress;
                data.DestinationAddress = ipPacket.DestinationAddress;
                data.Bytes = ipPacket.Bytes;

                return data;
            }

            return existingData;
        }

        /// <summary>
        ///     Tries to read the provided packet as an ARP packet
        /// </summary>
        /// <returns>Filled PacketData or existingData if not an ARP packet</returns>
        private PacketData TryReadArpData(Packet packet, PacketData existingData)
        {
            var arpPacket = packet.Extract<ArpPacket>();
            if (arpPacket != null)
            {
                var data = existingData;

                data.Source = arpPacket.SenderHardwareAddress;
                data.Destination = arpPacket.TargetHardwareAddress;
                data.SourceAddress = arpPacket.SenderProtocolAddress;
                data.DestinationAddress = arpPacket.TargetProtocolAddress;
                data.Bytes = arpPacket.Bytes;
                    
                return data;
            }

            return existingData;
        }
    }
}