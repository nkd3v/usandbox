using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace USandbox;

record BlockedConnection(DateTime Time, string Protocol, IPEndPoint Remote, IPEndPoint? Local, string? Application, bool Inbound);

/// <summary>
/// Blocks every non-loopback connection made or accepted by one account, using Windows Filtering
/// Platform filters in a dynamic session: Windows deletes the filters itself as soon as the session
/// handle closes, including when usandbox crashes. Drops are reported through WFP net events.
/// </summary>
sealed class WfpEgressLock : IDisposable
{
    // Struct offsets below are for 64-bit Windows and were taken from the SDK headers.
    static readonly Guid LayerConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    static readonly Guid LayerConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid LayerRecvAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    static readonly Guid LayerRecvAcceptV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");
    static readonly Guid ConditionAleUserId = new("af043a0a-b34d-4f86-979c-c90371af6e66");
    static readonly Guid ConditionFlags = new("632ce23b-5167-435c-86d7-e903684aa80c");

    const int FWP_UINT8 = 1, FWP_UINT32 = 3, FWP_SECURITY_DESCRIPTOR_TYPE = 14;
    const int FWP_MATCH_EQUAL = 0, FWP_MATCH_FLAGS_NONE_SET = 8;
    const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x1;
    const uint FWP_ACTION_BLOCK = 0x1001;
    const int FWPM_NET_EVENT_TYPE_CLASSIFY_DROP = 3;
    const int FWPM_ENGINE_COLLECT_NET_EVENTS = 0;

    IntPtr engine;
    readonly HashSet<ulong> filterIds = new();
    readonly List<IntPtr> allocations = new();
    readonly Native.FwpmNetEventCallback0? callback;
    IntPtr subscription;

    public event Action<BlockedConnection>? Blocked;

    /// <summary>False when Windows is configured not to record firewall drops, so none can be reported.</summary>
    public bool ReportsDrops { get; }

    public WfpEgressLock(string sid, string name)
    {
        IntPtr session = Alloc(72);
        Marshal.WriteIntPtr(session, 16, Str(name));
        Marshal.WriteInt32(session, 32, (int)Native.FWPM_SESSION_FLAG_DYNAMIC);
        Native.CheckFwp(Native.FwpmEngineOpen0(null, Native.RPC_C_AUTHN_WINNT, IntPtr.Zero, session, out engine), "FwpmEngineOpen0");

        try
        {
            var subLayerKey = Guid.NewGuid();
            IntPtr subLayer = Alloc(72);
            WriteGuid(subLayer, 0, subLayerKey);
            Marshal.WriteIntPtr(subLayer, 16, Str(name));
            Marshal.WriteInt16(subLayer, 64, unchecked((short)0xFFFF));
            Native.CheckFwp(Native.FwpmSubLayerAdd0(engine, subLayer, IntPtr.Zero), "FwpmSubLayerAdd0");

            // Condition 1: the connection belongs to the sandbox account. WFP matches the
            // process token against a security descriptor that grants FWP_ACTRL_MATCH_FILTER (CC).
            var sd = new RawSecurityDescriptor($"D:(A;;CC;;;{sid})");
            var sdBytes = new byte[sd.BinaryLength];
            sd.GetBinaryForm(sdBytes, 0);
            IntPtr sdData = Alloc(sdBytes.Length);
            Marshal.Copy(sdBytes, 0, sdData, sdBytes.Length);
            IntPtr sdBlob = Alloc(16);
            Marshal.WriteInt32(sdBlob, 0, sdBytes.Length);
            Marshal.WriteIntPtr(sdBlob, 8, sdData);

            IntPtr conditions = Alloc(2 * 40);
            WriteGuid(conditions, 0, ConditionAleUserId);
            Marshal.WriteInt32(conditions, 16, FWP_MATCH_EQUAL);
            Marshal.WriteInt32(conditions, 24, FWP_SECURITY_DESCRIPTOR_TYPE);
            Marshal.WriteIntPtr(conditions, 32, sdBlob);

            // Condition 2: it is not loopback traffic (the proxy listens on loopback).
            WriteGuid(conditions, 40, ConditionFlags);
            Marshal.WriteInt32(conditions, 40 + 16, FWP_MATCH_FLAGS_NONE_SET);
            Marshal.WriteInt32(conditions, 40 + 24, FWP_UINT32);
            Marshal.WriteInt32(conditions, 40 + 32, (int)FWP_CONDITION_FLAG_IS_LOOPBACK);

            foreach (var layer in new[] { LayerConnectV4, LayerConnectV6, LayerRecvAcceptV4, LayerRecvAcceptV6 })
            {
                IntPtr filter = Alloc(200);
                WriteGuid(filter, 0, Guid.NewGuid());
                Marshal.WriteIntPtr(filter, 16, Str(name));
                WriteGuid(filter, 64, layer);
                WriteGuid(filter, 80, subLayerKey);
                Marshal.WriteInt32(filter, 96, FWP_UINT8);
                Marshal.WriteByte(filter, 104, 15);
                Marshal.WriteInt32(filter, 112, 2);
                Marshal.WriteIntPtr(filter, 120, conditions);
                Marshal.WriteInt32(filter, 128, unchecked((int)FWP_ACTION_BLOCK));
                Native.CheckFwp(Native.FwpmFilterAdd0(engine, filter, IntPtr.Zero, out ulong id), "FwpmFilterAdd0");
                filterIds.Add(id);
            }

            ReportsDrops = CollectsNetEvents();
            if (ReportsDrops)
            {
                callback = OnNetEvent;
                IntPtr template = Alloc(32);                       // FWPM_NET_EVENT_ENUM_TEMPLATE0
                Marshal.WriteInt64(template, 8, long.MaxValue);    // endTime; no conditions = every event
                IntPtr sub = Alloc(32);                            // FWPM_NET_EVENT_SUBSCRIPTION0
                Marshal.WriteIntPtr(sub, 0, template);
                Native.CheckFwp(Native.FwpmNetEventSubscribe0(engine, sub, callback, IntPtr.Zero, out subscription), "FwpmNetEventSubscribe0");
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    bool CollectsNetEvents()
    {
        if (Native.FwpmEngineGetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, out IntPtr value) != 0) return true;
        try { return Marshal.ReadInt32(value, 8) != 0; }
        finally { Native.FwpmFreeMemory0(ref value); }
    }

    void OnNetEvent(IntPtr context, IntPtr ev)
    {
        try
        {
            if (Marshal.ReadInt32(ev, 144) != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) return;
            IntPtr drop = Marshal.ReadIntPtr(ev, 152);
            if (drop == IntPtr.Zero || !filterIds.Contains((ulong)Marshal.ReadInt64(drop))) return;

            long fileTime = Marshal.ReadInt64(ev, 0);
            bool v6 = Marshal.ReadInt32(ev, 12) == 1;
            int protocol = Marshal.ReadByte(ev, 16);
            IPAddress local = v6 ? new IPAddress(Bytes(ev + 20, 16)) : V4(Marshal.ReadInt32(ev, 20));
            IPAddress remote = v6 ? new IPAddress(Bytes(ev + 36, 16)) : V4(Marshal.ReadInt32(ev, 36));
            int localPort = (ushort)Marshal.ReadInt16(ev, 52), remotePort = (ushort)Marshal.ReadInt16(ev, 54);

            string? app = null;
            int appSize = Marshal.ReadInt32(ev, 64);
            IntPtr appData = Marshal.ReadIntPtr(ev, 72);
            if (appSize > 2 && appData != IntPtr.Zero)
                app = ProcessInfo.DevicePathToDos(Marshal.PtrToStringUni(appData, appSize / 2).TrimEnd('\0'));

            // msFwpDirection (FWP_DIRECTION_INBOUND = 0x3FFF) tells listening sockets apart.
            int direction = Marshal.ReadInt32(drop, 24);
            Blocked?.Invoke(new BlockedConnection(DateTime.FromFileTime(fileTime),
                protocol switch { 6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6", _ => $"IP/{protocol}" },
                new IPEndPoint(remote, remotePort), new IPEndPoint(local, localPort), app, direction == 0x3FFF));
        }
        catch
        {
            // Never let an exception escape into the WFP callback thread.
        }
    }

    // WFP stores IPv4 addresses as host-order integers.
    static IPAddress V4(int hostOrder) => new(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(hostOrder)));

    static byte[] Bytes(IntPtr p, int n) { var b = new byte[n]; Marshal.Copy(p, b, 0, n); return b; }

    IntPtr Alloc(int size)
    {
        IntPtr p = Marshal.AllocHGlobal(size);
        allocations.Add(p);
        unsafe { new Span<byte>((void*)p, size).Clear(); }
        return p;
    }

    IntPtr Str(string s)
    {
        IntPtr p = Marshal.StringToHGlobalUni(s);
        allocations.Add(p);
        return p;
    }

    static void WriteGuid(IntPtr p, int offset, Guid g) => Marshal.Copy(g.ToByteArray(), 0, p + offset, 16);

    public void Dispose()
    {
        if (subscription != IntPtr.Zero) { Native.FwpmNetEventUnsubscribe0(engine, subscription); subscription = IntPtr.Zero; }
        // Closing a dynamic session removes its sublayer and filters.
        if (engine != IntPtr.Zero) { Native.FwpmEngineClose0(engine); engine = IntPtr.Zero; }
        foreach (var p in allocations) Marshal.FreeHGlobal(p);
        allocations.Clear();
        GC.KeepAlive(callback);
    }
}
