using SharpPcap;

namespace IPK2.Zeta;

internal class Program
{
    public static void Main(string[] args)
    {
        var settings = ParseArgs(args);
        if (settings.Failed) return;

        if (settings.Interface == default)
        {
            PrintInterfaces();
            return;
        }

        try
        {
            var sniffer = new Sniffer(settings);
            sniffer.StartCapture();
        }
        catch (InvalidOperationException)
        {
            Console.Error.WriteLine($"Unknown interface: {settings.Interface}.\n" +
                                    "Use -i argument without value to get a list of available interfaces.");
        }
        catch (PcapException)
        {
            Console.Error.WriteLine("Can't activate the adapter. Try running application with admin rights.");
        }
    }

    private static Settings ParseArgs(string[] args)
    {
        var settings = new Settings();
        try
        {
            for (var i = 0; i < args.Length; ++i)
                if (args[i].StartsWith('-'))
                {
                    var argName = args[i].Replace("-", "");
                    if (argName is "i" or "interface" && i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                    {
                        settings.Interface = args[i + 1];
                        i += 1;
                    }
                    else if (argName is "p" && i + 1 < args.Length)
                    {
                        settings.Port = Convert.ToInt32(args[i + 1]);
                        i += 1;
                    }
                    else if (argName is "t" or "tcp")
                    {
                        settings.TCP = true;
                    }
                    else if (argName is "u" or "udp")
                    {
                        settings.UDP = true;
                    }
                    else if (argName is "icmp")
                    {
                        settings.ICMP = true;
                    }
                    else if (argName is "arp")
                    {
                        settings.ARP = true;
                    }
                    else if (argName is "n" && i + 1 < args.Length)
                    {
                        settings.NumberOfPackets = Convert.ToInt32(args[i + 1]);
                        i += 1;
                    }
                }
        }
        catch (InvalidOperationException)
        {
            Console.Error.WriteLine("Some argument had an incorrect value");
            settings.Failed = true;
            return settings;
        }

        // Set-up default values
        if (settings.NumberOfPackets == default)
            settings.NumberOfPackets = 1;

        if (!settings.TCP && !settings.UDP && !settings.ICMP && !settings.ARP)
        {
            settings.TCP = true;
            settings.UDP = true;
            settings.ICMP = true;
            settings.ARP = true;
        }

        settings.Failed = false;
        return settings;
    }

    private static void PrintInterfaces()
    {
        var devices = CaptureDeviceList.Instance;

        foreach (var dev in devices)
            Console.WriteLine(dev.Name);
    }
}