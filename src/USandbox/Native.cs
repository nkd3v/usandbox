using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace USandbox;

/// <summary>Win32 declarations used across usandbox.</summary>
static class Native
{
    // ---- netapi32: local accounts ------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1
    {
        public string usri1_name;
        public string usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        public string? usri1_home_dir;
        public string? usri1_comment;
        public uint usri1_flags;
        public string? usri1_script_path;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOCALGROUP_MEMBERS_INFO_0 { public IntPtr lgrmi0_sid; }

    public const uint USER_PRIV_USER = 1;
    public const uint UF_SCRIPT = 0x1, UF_PASSWD_CANT_CHANGE = 0x40, UF_NORMAL_ACCOUNT = 0x200, UF_DONT_EXPIRE_PASSWD = 0x10000;
    public const int NERR_Success = 0, ERROR_MEMBER_IN_ALIAS = 1378;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUserAdd(string? server, int level, ref USER_INFO_1 buf, out int parmErr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUserDel(string? server, string userName);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupAddMembers(string? server, string groupName, int level,
        ref LOCALGROUP_MEMBERS_INFO_0 buf, int totalEntries);

    // ---- advapi32 / userenv: logon and profiles ------------------------------------------------

    public const int LOGON32_LOGON_INTERACTIVE = 2, LOGON32_PROVIDER_DEFAULT = 0;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LogonUserW(string user, string domain, IntPtr password, int logonType, int provider, out IntPtr token);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROFILEINFO
    {
        public int dwSize, dwFlags;
        public string lpUserName;
        public string? lpProfilePath, lpDefaultPath, lpServerName, lpPolicyPath;
        public IntPtr hProfile;
    }

    public const int PI_NOUI = 1;

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LoadUserProfileW(IntPtr token, ref PROFILEINFO profile);

    [DllImport("userenv.dll", SetLastError = true)]
    public static extern bool UnloadUserProfile(IntPtr token, IntPtr profile);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool DeleteProfileW(string sid, string? profilePath, string? computerName);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool GetProfilesDirectoryW(StringBuilder? dir, ref int size);

    // ---- process creation -----------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    public const int LOGON_WITH_PROFILE = 0x1, CREATE_NEW_CONSOLE = 0x10, CREATE_UNICODE_ENVIRONMENT = 0x400;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessWithLogonW(string username, string domain, IntPtr password, int logonFlags,
        string applicationName, StringBuilder commandLine, int creationFlags, IntPtr environment,
        string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    // ---- process inspection ----------------------------------------------------------------

    public const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, TOKEN_QUERY = 0x8, TokenUser = 1;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int length, out int returned);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool QueryFullProcessImageNameW(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int QueryDosDeviceW(string? device, StringBuilder target, int max);

    // ---- console (the exe is a GUI app; --no-gui borrows or creates a console) -----------------

    [DllImport("kernel32.dll")] public static extern bool AttachConsole(int pid);
    [DllImport("kernel32.dll")] public static extern bool AllocConsole();

    // ---- iphlpapi: TCP connection tables ---------------------------------------------------

    public const int AF_INET = 2, AF_INET6 = 23, TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll")]
    public static extern int GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, int reserved);

    // ---- crypt32 ---------------------------------------------------------------------------

    public const int CERT_STORE_PROV_REG = 4;

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern IntPtr CertOpenStore(IntPtr storeProvider, int encodingType, IntPtr cryptProv, int flags, IntPtr para);

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CertCloseStore(IntPtr store, int flags);

    // ---- fwpuclnt: Windows Filtering Platform -----------------------------------------------

    public const uint RPC_C_AUTHN_WINNT = 10;
    public const uint FWPM_SESSION_FLAG_DYNAMIC = 0x1;

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engine);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmEngineClose0(IntPtr engine);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmEngineGetOption0(IntPtr engine, int option, out IntPtr value);

    [DllImport("fwpuclnt.dll")]
    public static extern void FwpmFreeMemory0(ref IntPtr p);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmSubLayerAdd0(IntPtr engine, IntPtr subLayer, IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmFilterAdd0(IntPtr engine, IntPtr filter, IntPtr sd, out ulong id);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void FwpmNetEventCallback0(IntPtr context, IntPtr netEvent);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmNetEventSubscribe0(IntPtr engine, IntPtr subscription, FwpmNetEventCallback0 callback, IntPtr context, out IntPtr handle);

    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmNetEventUnsubscribe0(IntPtr engine, IntPtr handle);

    public static void Check(bool ok, string what)
    {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), $"{what}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
    }

    public static void CheckNet(int status, string what)
    {
        if (status != 0) throw new Win32Exception(status, $"{what}: {new Win32Exception(status).Message}");
    }

    public static void CheckFwp(uint status, string what)
    {
        if (status != 0) throw new Win32Exception((int)status, $"{what} failed with 0x{status:X8}");
    }

    /// <summary>Copies a SecureString into unmanaged memory, runs <paramref name="use"/>, then zeroes it.</summary>
    public static T WithPassword<T>(SecureString password, Func<IntPtr, T> use)
    {
        IntPtr pw = Marshal.SecureStringToGlobalAllocUnicode(password);
        try { return use(pw); } finally { Marshal.ZeroFreeGlobalAllocUnicode(pw); }
    }
}
