using System;

namespace IPK2.Zeta;

class Program
{
    public static void Main(string[] args)
    {
        var settings = ParseArgs(args);
    }
    
    static Settings ParseArgs(string[] args)
    {
        var settings = new Settings();
        for (int i = 0; i < args.Length; ++i)
        {
            if (args[i].StartsWith('-'))
            {
                string argName = args[i].Replace("-", "");
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
                    settings.TCP = true;
                else if (argName is "u" or "udp")
                    settings.UDP = true;
                else if (argName is "icmp")
                    settings.ICMP = true;
                else if (argName is "arp")
                    settings.ARP = true;
                else if (argName is "n" && i + 1 < args.Length)
                {
                    settings.Count = Convert.ToInt32(args[i + 1]);
                    i += 1;
                }
            }
        }

        if (settings.Count == default)
            settings.Count = 1;

        // if no protocol specified, all protocols will be printed
        if (!settings.TCP && !settings.UDP && !settings.ICMP && !settings.ARP)
        {
            settings.TCP = true;
            settings.UDP = true;
            settings.ICMP = true;
            settings.ARP = true;
        }

        return settings;
    }
}