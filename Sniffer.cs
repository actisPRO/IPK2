using SharpPcap;

namespace IPK2.Zeta;

public class Sniffer
{
    public readonly Settings Settings;
    private readonly ILiveDevice _interface;

    public Sniffer(Settings settings)
    {
        Settings = settings;

        _interface = CaptureDeviceList.Instance.FirstOrDefault(i => i.Name == settings.Interface) ??
                     throw new InvalidOperationException();
    }
}