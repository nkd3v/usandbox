using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace USandbox;

/// <summary>Where a redirected connection was really going.</summary>
sealed record RedirectedConnection(IPEndPoint Original, IPEndPoint Client, int Pid, DateTime Started);

/// <summary>
/// Transparent capture with WinDivert: every outbound TCP connection made by a sandbox process is
/// turned around to the proxy's transparent listener, whatever the program thinks of proxy
/// settings. Nothing is changed inside the program, and no proxy settings are needed.
///
/// An outbound packet A:sp -> B:dp from a sandbox process is rewritten to 127.0.0.1:sp -> 127.0.0.1:P
/// and sent on loopback, so the proxy listening on 127.0.0.1:P accepts a connection from port sp and
/// looks up B:dp in the table here. The proxy's answers 127.0.0.1:P -> 127.0.0.1:sp are rewritten to
/// B:dp -> A:sp and injected inbound on the program's interface, so it sees its server answering.
/// Going through loopback matters: Windows Firewall does not filter loopback, whereas connections
/// "from" B to a listener on a real address (the WinDivert "streamdump" layout) are re-checked and
/// cut by its per-program prompt logic a few seconds after the listener starts.
/// The decision is made once per SYN, from the process that owns the socket (WinDivert's socket
/// layer, with the TCP table as a fallback), so other programs' traffic is passed through untouched.
/// </summary>
sealed class Redirector : IDisposable
{
    readonly Func<int, bool> isSandboxProcess;
    readonly Action<string> warn;
    readonly IntPtr network, socket, dns;
    readonly Thread networkThread, socketThread;
    readonly Thread? dnsThread;
    readonly ConcurrentDictionary<(bool V6, int ClientPort), Entry> table = new();
    readonly ConcurrentDictionary<(int LocalPort, int RemotePort, IPAddress Remote), (int Pid, long Ticks)> connects = new();
    readonly ConcurrentDictionary<IPAddress, string> names = new();
    volatile bool stopping;
    long synsSeen, redirected, toProxy, toProgram, sendErrors, unknownOwner;
    int lastSendError;

    /// <summary>Counters for diagnosing redirection.</summary>
    public string Stats =>
        $"{Interlocked.Read(ref synsSeen)} new outbound TCP connection(s) seen, {Interlocked.Read(ref redirected)} redirected, " +
        $"{Interlocked.Read(ref toProxy)} packet(s) to usandbox, {Interlocked.Read(ref toProgram)} back to the program, " +
        $"{Interlocked.Read(ref unknownOwner)} with an unknown owner, {Interlocked.Read(ref sendErrors)} reinjection error(s)" +
        (lastSendError != 0 ? $" (last: {new Win32Exception(lastSendError).Message})" : "");

    sealed class Entry
    {
        public required IPAddress Local;
        public required IPAddress Remote;
        public required uint IfIdx, SubIfIdx;
        public required int ClientPort;
        public required int OriginalPort;
        public required int Pid;
        public required DateTime Started;
        public long LastSeen;
    }

    /// <summary>The proxy's transparent listener ports (IPv4 and IPv6).</summary>
    public int Port4 { get; }
    public int Port6 { get; }

    /// <summary>Raised when a sandbox connection is redirected (for logging).</summary>
    public event Action<RedirectedConnection>? Redirected;

    Redirector(int port4, int port6, Func<int, bool> isSandboxProcess, Action<string> warn)
    {
        Port4 = port4;
        Port6 = port6;
        this.isSandboxProcess = isSandboxProcess;
        this.warn = warn;

        // Outbound TCP only: inbound packets are never touched. Loopback is left alone (it never
        // leaves the machine, and the explicit proxy lives there).
        network = Open($"outbound and tcp and (!loopback or tcp.SrcPort == {port4} or tcp.SrcPort == {port6})", Layer.Network, 0, 0);
        try
        {
            WinDivert.WinDivertSetParam(network, 0 /* QUEUE_LENGTH */, 16384);
            WinDivert.WinDivertSetParam(network, 2 /* QUEUE_SIZE */, 33554432);
            socket = Open("event == CONNECT and tcp and !loopback", Layer.Socket, 1, Flags.Sniff | Flags.RecvOnly);
            try { dns = Open("inbound and udp.SrcPort == 53", Layer.Network, 2, Flags.Sniff | Flags.RecvOnly); }
            catch { dns = IntPtr.Zero; } // names are only for display
        }
        catch
        {
            if (network != IntPtr.Zero) WinDivert.WinDivertClose(network);
            if (socket != IntPtr.Zero) WinDivert.WinDivertClose(socket);
            throw;
        }

        socketThread = new Thread(SocketLoop) { IsBackground = true, Name = "usandbox socket events", Priority = ThreadPriority.AboveNormal };
        networkThread = new Thread(NetworkLoop) { IsBackground = true, Name = "usandbox redirector", Priority = ThreadPriority.Highest };
        if (dns != IntPtr.Zero) dnsThread = new Thread(DnsLoop) { IsBackground = true, Name = "usandbox dns names" };
        socketThread.Start();
        networkThread.Start();
        dnsThread?.Start();
    }

    /// <summary>Opens the redirector, or returns null with the reason when WinDivert cannot be used.</summary>
    public static Redirector? TryStart(int port4, int port6, Func<int, bool> isSandboxProcess, Action<string> warn, out string? error)
    {
        error = null;
        string dir = AppContext.BaseDirectory;
        if (!File.Exists(Path.Combine(dir, "WinDivert.dll")) || !File.Exists(Path.Combine(dir, "WinDivert64.sys")))
        {
            error = "WinDivert.dll and WinDivert64.sys are not next to usandbox.exe";
            return null;
        }
        if (!Environment.Is64BitOperatingSystem || !Environment.Is64BitProcess)
        {
            error = "transparent capture needs 64-bit Windows";
            return null;
        }
        try { return new Redirector(port4, port6, isSandboxProcess, warn); }
        catch (Exception e) when (e is Win32Exception or DllNotFoundException or EntryPointNotFoundException)
        {
            error = e.Message;
            return null;
        }
    }

    static IntPtr Open(string filter, Layer layer, short priority, Flags flags)
    {
        IntPtr h = WinDivert.WinDivertOpen(filter, layer, priority, (ulong)flags);
        if (h == new IntPtr(-1))
        {
            int error = Marshal.GetLastWin32Error();
            string why = error switch
            {
                5 => "access denied (needs admin rights)",
                577 => "the WinDivert driver signature was rejected (Secure Boot / driver blocklist?)",
                654 => "an incompatible WinDivert driver version is already loaded",
                1275 => "the WinDivert driver is blocked by security software",
                1753 => "the Base Filtering Engine service is not running",
                _ => new Win32Exception(error).Message,
            };
            throw new Win32Exception(error, $"WinDivert ({layer}): {why}");
        }
        return h;
    }

    /// <summary>The original destination of a connection the proxy accepted on its transparent port.</summary>
    public RedirectedConnection? Lookup(IPEndPoint acceptedFrom)
    {
        var address = acceptedFrom.Address.IsIPv4MappedToIPv6 ? acceptedFrom.Address.MapToIPv4() : acceptedFrom.Address;
        if (!IPAddress.IsLoopback(address)) return null;
        if (!table.TryGetValue((address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6, acceptedFrom.Port), out var e)) return null;
        return new RedirectedConnection(new IPEndPoint(e.Remote, e.OriginalPort), new IPEndPoint(e.Local, e.ClientPort), e.Pid, e.Started);
    }

    /// <summary>True when the program's own socket (local port, remote endpoint) is being redirected.</summary>
    public bool IsRedirected(IPEndPoint local, IPEndPoint remote) =>
        table.TryGetValue((remote.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6, local.Port), out var e) &&
        e.OriginalPort == remote.Port && e.Remote.Equals(remote.Address);

    /// <summary>A host name for an address, from DNS answers seen on the machine (display only).</summary>
    public string? NameOf(IPAddress address) => names.TryGetValue(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address, out var n) ? n : null;

    // ---- packets -------------------------------------------------------------------------------

    const int AddrSize = 80, Batch = 64, MaxPacket = 65535;

    unsafe void NetworkLoop()
    {
        var packets = new byte[Batch * MaxPacket / 4];   // batches of large packets are rare; WinDivert fills what fits
        var addrs = new byte[Batch * AddrSize];
        long lastSweep = Environment.TickCount64;
        fixed (byte* p = packets, a = addrs)
        {
            while (!stopping)
            {
                uint addrLen = (uint)addrs.Length;
                if (!WinDivert.WinDivertRecvEx(network, p, (uint)packets.Length, out uint recvLen, 0, a, ref addrLen, IntPtr.Zero))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (stopping || err is 232 or 6 or 995) break;   // shut down / handle closed
                    continue;
                }
                int count = (int)(addrLen / AddrSize), offset = 0;
                for (int i = 0; i < count && offset < recvLen; i++)
                {
                    int length = PacketLength(p + offset, (int)recvLen - offset);
                    if (length <= 0) break;
                    try { Process(p + offset, length, a + i * AddrSize); }
                    catch (Exception e) { Debug.WriteLine(e); }
                    offset += length;
                }
                if (!WinDivert.WinDivertSendEx(network, p, (uint)offset, out _, 0, a, (uint)(count * AddrSize), IntPtr.Zero))
                {
                    Interlocked.Increment(ref sendErrors);
                    lastSendError = Marshal.GetLastWin32Error();
                }

                long now = Environment.TickCount64;
                if (now - lastSweep > 30_000)
                {
                    lastSweep = now;
                    foreach (var (key, e) in table)
                        if (now - Volatile.Read(ref e.LastSeen) > 10 * 60_000) table.TryRemove(key, out _);
                    long cutoff = Stopwatch.GetTimestamp() - Stopwatch.Frequency * 60;
                    foreach (var (key, v) in connects)
                        if (v.Ticks < cutoff) connects.TryRemove(key, out _);
                }
            }
        }
    }

    static unsafe int PacketLength(byte* ip, int available)
    {
        if (available < 20) return -1;
        int version = ip[0] >> 4;
        int length = version == 4 ? (ip[2] << 8) | ip[3] : version == 6 && available >= 40 ? 40 + ((ip[4] << 8) | ip[5]) : -1;
        return length > available ? -1 : length;
    }

    /// <summary>Rewrites one outbound TCP packet in place when it belongs to a redirected connection.</summary>
    unsafe void Process(byte* ip, int length, byte* addr)
    {
        bool v6 = (ip[0] >> 4) == 6;
        int ipHeader, srcOffset, dstOffset, addressLength;
        if (v6)
        {
            if (ip[6] != 6 || length < 60) return;   // TCP directly after the IPv6 header only
            ipHeader = 40; srcOffset = 8; dstOffset = 24; addressLength = 16;
        }
        else
        {
            ipHeader = (ip[0] & 0xF) * 4;
            if (ip[9] != 6 || length < ipHeader + 20) return;
            srcOffset = 12; dstOffset = 16; addressLength = 4;
        }
        byte* tcp = ip + ipHeader;
        int srcPort = (tcp[0] << 8) | tcp[1], dstPort = (tcp[2] << 8) | tcp[3];
        byte flags = tcp[13];
        bool syn = (flags & 0x02) != 0, ack = (flags & 0x10) != 0;
        int proxyPort = v6 ? Port6 : Port4;
        var src = new IPAddress(new ReadOnlySpan<byte>(ip + srcOffset, addressLength));
        var dst = new IPAddress(new ReadOnlySpan<byte>(ip + dstOffset, addressLength));

        bool loopback = (addr[10] & 0x04) != 0;
        Entry? entry;
        if (loopback)
        {
            // Proxy -> program: 127.0.0.1:P -> 127.0.0.1:sp becomes B:dp -> A:sp, inbound on A's interface.
            if (srcPort != proxyPort || !table.TryGetValue((v6, dstPort), out entry)) return;
            Volatile.Write(ref entry.LastSeen, Environment.TickCount64);
            entry.Remote.TryWriteBytes(new Span<byte>(ip + srcOffset, addressLength), out _);
            entry.Local.TryWriteBytes(new Span<byte>(ip + dstOffset, addressLength), out _);
            tcp[0] = (byte)(entry.OriginalPort >> 8);
            tcp[1] = (byte)entry.OriginalPort;
            addr[10] = (byte)(addr[10] & ~(0x02 | 0x04));          // Outbound = 0, Loopback = 0
            *(uint*)(addr + 16) = entry.IfIdx;
            *(uint*)(addr + 20) = entry.SubIfIdx;
            WinDivert.WinDivertHelperCalcChecksums(ip, (uint)length, addr, 0);
            Interlocked.Increment(ref toProgram);
            return;
        }

        if (syn && !ack)
        {
            // A new connection: decide whether it is the sandbox's.
            Interlocked.Increment(ref synsSeen);
            int? pid = OwnerOf(srcPort, dst, dstPort);
            if (pid is int owner && isSandboxProcess(owner))
            {
                var e = new Entry
                {
                    Local = src, Remote = dst, ClientPort = srcPort, OriginalPort = dstPort, Pid = owner, Started = DateTime.Now,
                    IfIdx = *(uint*)(addr + 16), SubIfIdx = *(uint*)(addr + 20), LastSeen = Environment.TickCount64,
                };
                bool fresh = !table.TryGetValue((v6, srcPort), out var old) || old.OriginalPort != dstPort || !old.Remote.Equals(dst);
                table[(v6, srcPort)] = e;
                Interlocked.Increment(ref redirected);
                if (fresh) Redirected?.Invoke(new RedirectedConnection(new IPEndPoint(dst, dstPort), new IPEndPoint(src, srcPort), owner, e.Started));
            }
            else
            {
                if (table.TryGetValue((v6, srcPort), out var stale) && stale.Remote.Equals(dst)) table.TryRemove((v6, srcPort), out _);
                return;
            }
        }

        // Program -> server: A:sp -> B:dp becomes 127.0.0.1:sp -> 127.0.0.1:P, sent on loopback.
        if (!table.TryGetValue((v6, srcPort), out entry) || entry.OriginalPort != dstPort || !entry.Remote.Equals(dst) || !entry.Local.Equals(src)) return;
        Volatile.Write(ref entry.LastSeen, Environment.TickCount64);
        var lo = v6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        lo.TryWriteBytes(new Span<byte>(ip + srcOffset, addressLength), out _);
        lo.TryWriteBytes(new Span<byte>(ip + dstOffset, addressLength), out _);
        tcp[2] = (byte)(proxyPort >> 8);
        tcp[3] = (byte)proxyPort;
        addr[10] = (byte)(addr[10] | 0x04);                         // Loopback = 1 (still outbound)
        WinDivert.WinDivertHelperCalcChecksums(ip, (uint)length, addr, 0);
        Interlocked.Increment(ref toProxy);
    }

    /// <summary>The process that owns a new outbound connection.</summary>
    int? OwnerOf(int localPort, IPAddress remote, int remotePort)
    {
        // The socket-layer event is raised before the SYN is sent, but on another queue; give it a moment.
        for (int i = 0; i < 20; i++)
        {
            if (connects.TryGetValue((localPort, remotePort, remote), out var c)) return c.Pid;
            if (i == 0) Thread.Yield(); else Thread.Sleep(1);
        }
        foreach (var row in ProcessInfo.GetTcpTable())
        {
            var r = row.Remote.Address.IsIPv4MappedToIPv6 ? row.Remote.Address.MapToIPv4() : row.Remote.Address;
            if (row.Local.Port == localPort && row.Remote.Port == remotePort && r.Equals(remote)) return row.Pid;
        }
        Interlocked.Increment(ref unknownOwner);
        return null;
    }

    unsafe void SocketLoop()
    {
        var addr = new byte[AddrSize];
        fixed (byte* a = addr)
        {
            while (!stopping)
            {
                if (!WinDivert.WinDivertRecv(socket, null, 0, out _, a))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (stopping || err is 232 or 6 or 995) break;
                    continue;
                }
                int pid = *(int*)(a + 32);
                var remote = HostOrderAddress(a + 52);
                int localPort = *(ushort*)(a + 68), remotePort = *(ushort*)(a + 70);
                connects[(localPort, remotePort, remote)] = (pid, Stopwatch.GetTimestamp());
            }
        }
    }

    /// <summary>WinDivert's socket-layer addresses: four host-order words, least significant first; IPv4 is mapped.</summary>
    static unsafe IPAddress HostOrderAddress(byte* p)
    {
        Span<byte> bytes = stackalloc byte[16];
        for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32BigEndian(bytes[(4 * i)..], *(uint*)(p + 4 * (3 - i)));
        var address = new IPAddress(bytes);
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    // ---- DNS names (display only) ------------------------------------------------------------------

    unsafe void DnsLoop()
    {
        var packet = new byte[MaxPacket];
        var addr = new byte[AddrSize];
        fixed (byte* p = packet, a = addr)
        {
            while (!stopping)
            {
                if (!WinDivert.WinDivertRecv(dns, p, (uint)packet.Length, out uint len, a))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (stopping || err is 232 or 6 or 995) break;
                    continue;
                }
                try
                {
                    int ipHeader = (p[0] >> 4) == 6 ? 40 : (p[0] & 0xF) * 4;
                    if (len > ipHeader + 8) ParseDnsAnswer(packet.AsSpan(ipHeader + 8, (int)len - ipHeader - 8));
                }
                catch { }
            }
        }
    }

    void ParseDnsAnswer(ReadOnlySpan<byte> m)
    {
        if (m.Length < 12 || (m[2] & 0x80) == 0) return;
        int questions = (m[4] << 8) | m[5], answers = (m[6] << 8) | m[7];
        int pos = 12;
        string? asked = null;
        for (int i = 0; i < questions; i++)
        {
            asked ??= ReadName(m, ref pos);
            if (i > 0) ReadName(m, ref pos);
            pos += 4;
        }
        if (asked == null) return;
        for (int i = 0; i < answers && pos < m.Length; i++)
        {
            ReadName(m, ref pos);
            int type = (m[pos] << 8) | m[pos + 1];
            int rdLength = (m[pos + 8] << 8) | m[pos + 9];
            pos += 10;
            if ((type == 1 && rdLength == 4) || (type == 28 && rdLength == 16))
                names[new IPAddress(m.Slice(pos, rdLength))] = asked;
            pos += rdLength;
        }
    }

    static string ReadName(ReadOnlySpan<byte> m, ref int pos)
    {
        var sb = new StringBuilder();
        int p = pos, jumps = 0;
        bool jumped = false;
        while (p < m.Length && m[p] != 0)
        {
            if ((m[p] & 0xC0) == 0xC0)
            {
                if (!jumped) pos = p + 2;
                jumped = true;
                p = ((m[p] & 0x3F) << 8) | m[p + 1];
                if (++jumps > 20) break;
                continue;
            }
            int len = m[p];
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(m.Slice(p + 1, len)));
            p += 1 + len;
        }
        if (!jumped) pos = p + 1;
        return sb.ToString();
    }

    public void Dispose()
    {
        stopping = true;
        foreach (var h in new[] { network, socket, dns })
            if (h != IntPtr.Zero) WinDivert.WinDivertShutdown(h, 3);
        networkThread.Join(2000);
        socketThread.Join(2000);
        dnsThread?.Join(2000);
        foreach (var h in new[] { network, socket, dns })
            if (h != IntPtr.Zero) WinDivert.WinDivertClose(h);
    }

    enum Layer { Network = 0, NetworkForward = 1, Flow = 2, Socket = 3, Reflect = 4 }

    [Flags]
    enum Flags : ulong { None = 0, Sniff = 1, Drop = 2, RecvOnly = 4, SendOnly = 8 }

    static unsafe class WinDivert
    {
        [DllImport("WinDivert.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr WinDivertOpen(string filter, Layer layer, short priority, ulong flags);

        [DllImport("WinDivert.dll", SetLastError = true)]
        public static extern bool WinDivertRecv(IntPtr handle, byte* packet, uint packetLen, out uint recvLen, byte* addr);

        [DllImport("WinDivert.dll", SetLastError = true)]
        public static extern bool WinDivertRecvEx(IntPtr handle, byte* packet, uint packetLen, out uint recvLen, ulong flags, byte* addr, ref uint addrLen, IntPtr overlapped);

        [DllImport("WinDivert.dll", SetLastError = true)]
        public static extern bool WinDivertSendEx(IntPtr handle, byte* packet, uint packetLen, out uint sendLen, ulong flags, byte* addr, uint addrLen, IntPtr overlapped);

        [DllImport("WinDivert.dll", SetLastError = true)]
        public static extern bool WinDivertShutdown(IntPtr handle, int how);

        [DllImport("WinDivert.dll", SetLastError = true)]
        public static extern bool WinDivertClose(IntPtr handle);

        [DllImport("WinDivert.dll", SetLastError = true)]
        public static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);

        [DllImport("WinDivert.dll")]
        public static extern bool WinDivertHelperCalcChecksums(byte* packet, uint packetLen, byte* addr, ulong flags);
    }
}
