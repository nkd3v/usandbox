using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace USandbox;

record SandboxProcessInfo(int Id, string Name, string? Path);

record TcpRow(IPEndPoint Local, IPEndPoint Remote, int State, int Pid)
{
    public const int Listen = 2, Established = 5;
}

/// <summary>Finds processes by owning account and maps TCP connections to processes.</summary>
static class ProcessInfo
{
    public static string? GetOwnerSid(int pid)
    {
        IntPtr process = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            if (!Native.OpenProcessToken(process, Native.TOKEN_QUERY, out IntPtr token)) return null;
            try
            {
                Native.GetTokenInformation(token, Native.TokenUser, IntPtr.Zero, 0, out int size);
                if (size == 0) return null;
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (!Native.GetTokenInformation(token, Native.TokenUser, buffer, size, out _)) return null;
                    // TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first field is the SID pointer.
                    return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { Native.CloseHandle(token); }
        }
        finally { Native.CloseHandle(process); }
    }

    public static string? GetPath(int pid)
    {
        IntPtr process = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return Native.QueryFullProcessImageNameW(process, 0, sb, ref size) ? sb.ToString(0, size) : null;
        }
        finally { Native.CloseHandle(process); }
    }

    public static List<SandboxProcessInfo> FindByOwner(string sid)
    {
        var result = new List<SandboxProcessInfo>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id <= 4) continue;
                if (GetOwnerSid(p.Id) == sid) result.Add(new SandboxProcessInfo(p.Id, p.ProcessName, GetPath(p.Id)));
            }
        }
        return result;
    }

    public static List<TcpRow> GetTcpTable()
    {
        var rows = new List<TcpRow>();
        ReadTable(Native.AF_INET, 24, buffer =>
        {
            int n = Marshal.ReadInt32(buffer);
            for (int i = 0; i < n; i++)
            {
                IntPtr row = buffer + 4 + i * 24;
                int state = Marshal.ReadInt32(row);
                var local = new IPEndPoint(new IPAddress((uint)Marshal.ReadInt32(row + 4)), PortOf(row + 8));
                var remote = new IPEndPoint(new IPAddress((uint)Marshal.ReadInt32(row + 12)), PortOf(row + 16));
                rows.Add(new TcpRow(local, remote, state, Marshal.ReadInt32(row + 20)));
            }
        });
        ReadTable(Native.AF_INET6, 56, buffer =>
        {
            int n = Marshal.ReadInt32(buffer);
            for (int i = 0; i < n; i++)
            {
                IntPtr row = buffer + 4 + i * 56;
                var local = new IPEndPoint(new IPAddress(Bytes(row, 16), (uint)Marshal.ReadInt32(row + 16)), PortOf(row + 20));
                var remote = new IPEndPoint(new IPAddress(Bytes(row + 24, 16), (uint)Marshal.ReadInt32(row + 40)), PortOf(row + 44));
                rows.Add(new TcpRow(local, remote, Marshal.ReadInt32(row + 48), Marshal.ReadInt32(row + 52)));
            }
        });
        return rows;
    }

    /// <summary>The process that owns the client side of a loopback connection to <paramref name="serverPort"/>.</summary>
    public static int? FindClientPid(IPEndPoint client, int serverPort)
    {
        foreach (var row in GetTcpTable())
        {
            if (row.Local.Port == client.Port && row.Remote.Port == serverPort &&
                (row.Local.Address.Equals(client.Address) || IPAddress.IsLoopback(row.Local.Address)))
                return row.Pid;
        }
        return null;
    }

    static int PortOf(IntPtr p) => (Marshal.ReadByte(p) << 8) | Marshal.ReadByte(p + 1);

    static byte[] Bytes(IntPtr p, int n) { var b = new byte[n]; Marshal.Copy(p, b, 0, n); return b; }

    static void ReadTable(int af, int rowSize, Action<IntPtr> read)
    {
        int size = 0;
        Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, Native.TCP_TABLE_OWNER_PID_ALL, 0);
        for (int attempt = 0; attempt < 5; attempt++)
        {
            size += 16 * rowSize;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                int rc = Native.GetExtendedTcpTable(buffer, ref size, false, af, Native.TCP_TABLE_OWNER_PID_ALL, 0);
                if (rc == 0) { read(buffer); return; }
                if (rc != 122) return; // ERROR_INSUFFICIENT_BUFFER: the table grew, try again
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    static readonly Lazy<List<(string Device, string Drive)>> DosDevices = new(() =>
    {
        var map = new List<(string, string)>();
        foreach (var drive in Environment.GetLogicalDrives())
        {
            string letter = drive.TrimEnd('\\');
            var sb = new StringBuilder(512);
            if (Native.QueryDosDeviceW(letter, sb, sb.Capacity) > 0) map.Add((sb.ToString(), letter));
        }
        return map;
    });

    /// <summary>Turns \device\harddiskvolume3\x into C:\x (WFP reports application paths in NT form).</summary>
    public static string DevicePathToDos(string path)
    {
        foreach (var (device, drive) in DosDevices.Value)
        {
            if (path.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
                return drive + path[device.Length..];
        }
        return path;
    }
}
