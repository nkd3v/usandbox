using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace USandbox;

/// <summary>
/// A local standard user with a random name and password, hidden from the sign-in screen,
/// that exists only for one run.
/// </summary>
sealed class SandboxAccount
{
    const string HideKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

    readonly SecureString password;
    IntPtr token, profile;

    public string UserName { get; }
    public string Computer { get; } = Environment.MachineName;
    public string QualifiedName => $"{Computer}\\{UserName}";
    public string Sid { get; }
    public string? ProfilePath { get; private set; }

    SandboxAccount(string userName, SecureString password, string sid)
    {
        UserName = userName;
        this.password = password;
        Sid = sid;
    }

    public static SandboxAccount Create()
    {
        string userName = "usbx-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();
        string plain = NewPassword();
        var info = new Native.USER_INFO_1
        {
            usri1_name = userName,
            usri1_password = plain,
            usri1_priv = Native.USER_PRIV_USER,
            usri1_comment = "Throwaway account created by usandbox",
            usri1_flags = Native.UF_SCRIPT | Native.UF_PASSWD_CANT_CHANGE | Native.UF_NORMAL_ACCOUNT | Native.UF_DONT_EXPIRE_PASSWD,
        };
        Native.CheckNet(Native.NetUserAdd(null, 1, ref info, out _), "Could not create the throwaway account");

        var password = new SecureString();
        foreach (char c in plain) password.AppendChar(c);
        password.MakeReadOnly();

        string sid = new NTAccount(Environment.MachineName, userName).Translate(typeof(SecurityIdentifier)).Value;
        var account = new SandboxAccount(userName, password, sid);
        try
        {
            // New local accounts normally join Users already; make sure, by SID so it works on any Windows language.
            string users = new SecurityIdentifier("S-1-5-32-545").Translate(typeof(NTAccount)).Value.Split('\\')[^1];
            var sidBytes = new byte[SecurityIdentifier.MaxBinaryLength];
            var sidObject = new SecurityIdentifier(sid);
            sidObject.GetBinaryForm(sidBytes, 0);
            var handle = GCHandle.Alloc(sidBytes, GCHandleType.Pinned);
            try
            {
                var member = new Native.LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid = handle.AddrOfPinnedObject() };
                int rc = Native.NetLocalGroupAddMembers(null, users, 0, ref member, 1);
                if (rc != 0 && rc != Native.ERROR_MEMBER_IN_ALIAS) Native.CheckNet(rc, "Could not add the account to Users");
            }
            finally { handle.Free(); }

            using var hide = Registry.LocalMachine.CreateSubKey(HideKey);
            hide.SetValue(userName, 0, RegistryValueKind.DWord);
        }
        catch
        {
            account.Delete(_ => { });
            throw;
        }
        return account;
    }

    static string NewPassword()
    {
        string[] sets = { "ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!#%+-=?@_~" };
        string all = string.Concat(sets);
        var bytes = RandomNumberGenerator.GetBytes(32);
        var chars = new char[bytes.Length];
        // The first characters come one from each set, so complexity rules are always met.
        for (int i = 0; i < bytes.Length; i++)
        {
            string set = i < sets.Length ? sets[i] : all;
            chars[i] = set[bytes[i] % set.Length];
        }
        return new string(chars);
    }

    /// <summary>Logs the account on and loads (first creating) its profile, so its registry hive can be prepared.</summary>
    public void LoadProfile()
    {
        bool ok = Native.WithPassword(password, pw => Native.LogonUserW(UserName, ".", pw,
            Native.LOGON32_LOGON_INTERACTIVE, Native.LOGON32_PROVIDER_DEFAULT, out token));
        Native.Check(ok, "LogonUser");

        var info = new Native.PROFILEINFO { dwSize = Marshal.SizeOf<Native.PROFILEINFO>(), dwFlags = Native.PI_NOUI, lpUserName = UserName };
        Native.Check(Native.LoadUserProfileW(token, ref info), "LoadUserProfile");
        profile = info.hProfile;

        using var list = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{Sid}");
        ProfilePath = list?.GetValue("ProfileImagePath") as string;
    }

    /// <summary>The account's HKEY_CURRENT_USER (available after <see cref="LoadProfile"/>).</summary>
    public RegistryKey OpenHive() =>
        Registry.Users.OpenSubKey(Sid, writable: true) ?? throw new InvalidOperationException("The account's registry hive is not loaded.");

    /// <summary>Points WinINet/WinHTTP (system proxy settings) and common environment variables at the proxy.</summary>
    public void ConfigureProxy(int port, IDictionary<string, string> environment)
    {
        using var hive = OpenHive();
        string server = $"127.0.0.1:{port}";
        using (var settings = hive.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
        {
            settings.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            settings.SetValue("ProxyServer", server, RegistryValueKind.String);
            settings.SetValue("ProxyOverride", "", RegistryValueKind.String);
            settings.DeleteValue("AutoConfigURL", false);
            using var connections = settings.CreateSubKey("Connections");
            // The binary form WinINet actually reads: version, counter, flags (direct | proxy), proxy, bypass, PAC URL.
            var blob = new List<byte>();
            void Dword(int v) => blob.AddRange(BitConverter.GetBytes(v));
            void Text(string s) { Dword(s.Length); blob.AddRange(Encoding.ASCII.GetBytes(s)); }
            Dword(0x46); Dword(1); Dword(0x3); Text(server); Text(""); Text("");
            blob.AddRange(new byte[32]);
            connections.SetValue("DefaultConnectionSettings", blob.ToArray(), RegistryValueKind.Binary);
            connections.SetValue("SavedLegacySettings", blob.ToArray(), RegistryValueKind.Binary);
        }
        SetEnvironment(environment);
    }

    public void SetEnvironment(IDictionary<string, string> environment)
    {
        using var hive = OpenHive();
        using var env = hive.CreateSubKey("Environment");
        foreach (var (name, value) in environment) env.SetValue(name, value, RegistryValueKind.String);
    }

    /// <summary>
    /// Makes this account (and only this account) trust <paramref name="ca"/>. The certificate goes into
    /// the account's own root store under HKEY_USERS\&lt;sid&gt;, which is deleted with the profile.
    /// Nothing is added to the machine's stores or to any other user's stores.
    /// </summary>
    /// <remarks>
    /// Windows guards a user's root store with a "protected roots" list and a confirmation prompt.
    /// For a new profile that list does not exist yet: it is created the first time the store is
    /// opened, from the roots already present. Writing the certificate before anything runs as the
    /// account therefore makes it trusted without a prompt. (The per-user policy root store is not
    /// part of the user's Root store, so it cannot be used for this.)
    /// </remarks>
    /// <returns>False if the protected roots list already existed, in which case the certificate may be ignored.</returns>
    public bool TrustRootCertificate(X509Certificate2 ca)
    {
        using var hive = OpenHive();
        using var key = hive.CreateSubKey(@"Software\Microsoft\SystemCertificates\Root");
        bool fresh;
        using (var protectedRoots = key.OpenSubKey("ProtectedRoots")) fresh = protectedRoots == null;
        IntPtr store = Native.CertOpenStore((IntPtr)Native.CERT_STORE_PROV_REG, 0, IntPtr.Zero, 0, key.Handle.DangerousGetHandle());
        Native.Check(store != IntPtr.Zero, "CertOpenStore");
        try
        {
            using var x509 = new X509Store(store);
            x509.Add(ca);
        }
        finally { Native.CertCloseStore(store, 0); }

        using var check = key.OpenSubKey($@"Certificates\{ca.Thumbprint}");
        if (check?.GetValue("Blob") == null) throw new InvalidOperationException("The CA certificate did not reach the account's root store.");
        return fresh;
    }

    public SandboxProcess Start(string program, string commandLine, string directory)
    {
        var si = new Native.STARTUPINFO { cb = Marshal.SizeOf<Native.STARTUPINFO>() };
        Native.PROCESS_INFORMATION pi = default;
        bool ok = Native.WithPassword(password, pw =>
            // A null environment means "build it from the user's profile", including its Environment key.
            Native.CreateProcessWithLogonW(UserName, Computer, pw, Native.LOGON_WITH_PROFILE, program,
                new StringBuilder(commandLine), Native.CREATE_NEW_CONSOLE | Native.CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero, directory, ref si, out pi));
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
        Native.CloseHandle(pi.hThread);
        return new SandboxProcess(pi.hProcess, pi.dwProcessId);
    }

    /// <summary>Deletes the profile, the account and its sign-in screen entry. Each step is attempted even if one fails.</summary>
    public void Delete(Action<string> warn)
    {
        void Step(string what, Action action)
        {
            try { action(); } catch (Exception e) { warn($"Could not {what}: {e.Message}"); }
        }

        Step("unload the user profile", () =>
        {
            if (profile != IntPtr.Zero) { Native.UnloadUserProfile(token, profile); profile = IntPtr.Zero; }
            if (token != IntPtr.Zero) { Native.CloseHandle(token); token = IntPtr.Zero; }
        });

        Step("delete the user profile", () =>
        {
            // The hive unloads shortly after the last process exits.
            for (int i = 0; ; i++)
            {
                using (var list = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{Sid}"))
                {
                    if (list == null) break;
                }
                if (Native.DeleteProfileW(Sid, null, null)) break;
                int error = Marshal.GetLastWin32Error();
                if (i >= 20) throw new Win32Exception(error, $"{new Win32Exception(error).Message} (profile: {ProfilePath})");
                Thread.Sleep(1000);
            }
        });

        Step("delete the user account", () =>
        {
            int rc = Native.NetUserDel(null, UserName);
            if (rc != 0 && rc != 2221) Native.CheckNet(rc, "NetUserDel"); // 2221: no such user
        });

        Step("remove the sign-in screen entry", () =>
        {
            using var hide = Registry.LocalMachine.OpenSubKey(HideKey, writable: true);
            hide?.DeleteValue(UserName, false);
        });

        password.Dispose();
    }
}

/// <summary>A process started as the sandbox account (keeps its handle so the exit code can be read).</summary>
sealed class SandboxProcess : IDisposable
{
    [DllImport("kernel32.dll", SetLastError = true)] static extern int WaitForSingleObject(IntPtr handle, int ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out int code);

    IntPtr handle;
    public int Id { get; }

    public SandboxProcess(IntPtr handle, int id) { this.handle = handle; Id = id; }

    public bool HasExited => WaitForSingleObject(handle, 0) == 0;

    public int ExitCode
    {
        get
        {
            Native.Check(GetExitCodeProcess(handle, out int code), "GetExitCodeProcess");
            return code;
        }
    }

    public void Dispose()
    {
        if (handle != IntPtr.Zero) { Native.CloseHandle(handle); handle = IntPtr.Zero; }
    }
}
