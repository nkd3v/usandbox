using System.Diagnostics;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;

namespace USandbox;

enum StageMode { None, File, Folder }

/// <summary>
/// filter: traffic must go through the proxy; anything else is blocked and reported.
/// open:   the proxy is configured, but programs that ignore it may still connect directly (reported, not blocked).
/// off:    no proxy and no blocking, as in the original script; direct connections are still reported.
/// none:   no network at all apart from loopback.
/// </summary>
enum NetworkMode { Filter, Open, Off, None }

sealed class SessionOptions
{
    public string Program { get; set; } = "";
    /// <summary>Appended to the quoted program path as is.</summary>
    public string Arguments { get; set; } = "";
    public StageMode Stage { get; set; } = StageMode.None;
    public string? WorkingDirectory { get; set; }
    public NetworkMode Network { get; set; } = NetworkMode.Filter;
    public bool InspectTls { get; set; } = true;
    public bool AutoPassthrough { get; set; } = true;
}

/// <summary>One run: create the account, set up the network, run the program, wait, clean up.</summary>
sealed class SandboxSession
{
    readonly SessionOptions options;
    readonly Monitor monitor;
    readonly Func<RuleSet> rules;
    readonly HashSet<string> seenDirect = new();
    readonly HashSet<int> seenListen = new();
    readonly Dictionary<string, Flow> recentBlocks = new();

    public string State { get; private set; } = "starting";
    public string? UserName { get; private set; }
    public int? MainPid { get; private set; }
    public int? ExitCode { get; private set; }
    public int? ProxyPort { get; private set; }
    public IReadOnlyList<SandboxProcessInfo> Processes { get; private set; } = Array.Empty<SandboxProcessInfo>();
    public SessionOptions Options => options;

    public event Action? Changed;

    public SandboxSession(SessionOptions options, Monitor monitor, Func<RuleSet> rules)
    {
        this.options = options;
        this.monitor = monitor;
        this.rules = rules;
    }

    void SetState(string state) { State = state; Changed?.Invoke(); }

    public async Task RunAsync(CancellationToken stop)
    {
        string program = Path.GetFullPath(options.Program);
        if (!File.Exists(program)) throw new FileNotFoundException($"Not a file: {program}");

        SandboxAccount? account = null;
        ProxyServer? proxy = null;
        CertificateAuthority? ca = null;
        WfpEgressLock? egress = null;
        SandboxProcess? main = null;
        string stageRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "usandbox");
        string? stageDir = null;

        try
        {
            // --- Account ---------------------------------------------------------------------
            account = SandboxAccount.Create();
            UserName = account.QualifiedName;
            monitor.Info($"Created throwaway user {account.QualifiedName} ({account.Sid}).");
            account.LoadProfile();
            monitor.Info($"Created its profile at {account.ProfilePath}.");
            Changed?.Invoke();

            // --- Staging folder (also holds the CA files) --------------------------------------
            stageDir = Path.Combine(stageRoot, account.UserName);
            Directory.CreateDirectory(stageRoot);
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            // Only SYSTEM, Administrators and the throwaway user can see the folder.
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-18"), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-544"), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(account.Sid), FileSystemRights.Modify, inherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(stageDir).Create(security);

            if (options.Stage != StageMode.None)
            {
                string programDir = Path.Combine(stageDir, "program");
                Directory.CreateDirectory(programDir);
                if (options.Stage == StageMode.File) File.Copy(program, Path.Combine(programDir, Path.GetFileName(program)));
                else CopyDirectory(Path.GetDirectoryName(program)!, programDir);
                program = Path.Combine(programDir, Path.GetFileName(program));
                monitor.Info($"Staged program at {program}.");
            }

            // --- Network ---------------------------------------------------------------------
            if (options.Network is NetworkMode.Filter or NetworkMode.Open)
            {
                proxy = new ProxyServer(monitor, rules, account.Sid) { InspectTls = options.InspectTls, AutoPassthrough = options.AutoPassthrough };
                ProxyPort = proxy.Port;
                var env = new Dictionary<string, string>
                {
                    ["HTTP_PROXY"] = $"http://127.0.0.1:{proxy.Port}",
                    ["HTTPS_PROXY"] = $"http://127.0.0.1:{proxy.Port}",
                    ["ALL_PROXY"] = $"http://127.0.0.1:{proxy.Port}",
                    ["NODE_USE_ENV_PROXY"] = "1",
                };
                if (options.InspectTls)
                {
                    ca = new CertificateAuthority(account.UserName, proxy.CrlUrl);
                    proxy.Ca = ca;
                    string caFile = Path.Combine(stageDir, "usandbox-ca.pem"), bundleFile = Path.Combine(stageDir, "usandbox-ca-bundle.pem");
                    File.WriteAllText(caFile, ca.CertificatePem);
                    File.WriteAllText(bundleFile, ca.BuildPemBundle());
                    if (!account.TrustRootCertificate(ca.Certificate))
                        monitor.Warn("The account's root store was already initialised; programs may not trust the usandbox CA.");
                    env["SSL_CERT_FILE"] = bundleFile;
                    env["REQUESTS_CA_BUNDLE"] = bundleFile;
                    env["NODE_EXTRA_CA_CERTS"] = caFile;
                    env["JAVA_TOOL_OPTIONS"] = "-Djavax.net.ssl.trustStoreType=Windows-ROOT -Djava.net.useSystemProxies=true";
                    monitor.Info($"HTTPS inspection: per-run CA \"{ca.Certificate.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false)}\" " +
                                 $"is trusted by {account.UserName} only (thumbprint {ca.Certificate.Thumbprint}).");
                }
                account.ConfigureProxy(proxy.Port, env);
                proxy.Start();
                monitor.Info($"Proxy listening on 127.0.0.1:{proxy.Port}.");
            }

            if (options.Network is NetworkMode.Filter or NetworkMode.None)
            {
                egress = new WfpEgressLock(account.Sid, $"usandbox {account.UserName}");
                egress.Blocked += OnBlocked;
                monitor.Info(options.Network == NetworkMode.None
                    ? "Network locked: the program can only reach loopback addresses."
                    : "Network locked: the program can only reach the internet through the proxy.");
                if (!egress.ReportsDrops) monitor.Warn("Windows is not recording firewall events, so blocked direct connections will not be listed.");
            }

            // --- Run -------------------------------------------------------------------------
            string workingDirectory = options.WorkingDirectory ?? Path.GetDirectoryName(program)!;
            string commandLine = CommandLine.Quote(program) + (string.IsNullOrWhiteSpace(options.Arguments) ? "" : " " + options.Arguments);
            try
            {
                main = account.Start(program, commandLine, workingDirectory);
            }
            catch (Exception e)
            {
                string hint = options.Stage == StageMode.None ? " If the program is inside your profile, stage it (File or Folder)." : "";
                throw new InvalidOperationException($"Could not start {program} as {account.QualifiedName}: {e.Message}.{hint}", e);
            }
            MainPid = main.Id;
            SetState("running");
            monitor.Info($"Running {program} as {account.QualifiedName} (PID {main.Id}).");

            bool announcedWait = false;
            while (!stop.IsCancellationRequested)
            {
                Poll(account.Sid, proxy?.Port);
                if (ExitCode == null && main.HasExited)
                {
                    ExitCode = main.ExitCode;
                    monitor.Info($"Program exited with code {ExitCode}.");
                    Changed?.Invoke();
                }
                if (ExitCode != null)
                {
                    if (Processes.Count == 0) break;
                    if (!announcedWait)
                    {
                        // Launchers often start the real program and exit; wait for anything left.
                        monitor.Info($"Waiting for processes still running as {account.QualifiedName}: " +
                                     string.Join(", ", Processes.Select(p => $"{p.Name} ({p.Id})")));
                        announcedWait = true;
                    }
                }
                try { await Task.Delay(1000, stop); } catch (OperationCanceledException) { }
            }
        }
        finally
        {
            SetState("cleaning up");
            if (account != null)
            {
                monitor.Info($"Cleaning up {account.QualifiedName}...");
                foreach (var p in ProcessInfo.FindByOwner(account.Sid))
                {
                    try { using var proc = Process.GetProcessById(p.Id); proc.Kill(); } catch { }
                }
                // Give the killed processes a moment so the profile can unload.
                for (int i = 0; i < 20 && ProcessInfo.FindByOwner(account.Sid).Count > 0; i++) await Task.Delay(250);
                Processes = Array.Empty<SandboxProcessInfo>();
            }
            if (main != null && ExitCode == null && main.HasExited) ExitCode = main.ExitCode;
            main?.Dispose();
            egress?.Dispose();
            proxy?.Dispose();
            ca?.Dispose();
            account?.Delete(monitor.Warn);
            if (stageDir != null)
            {
                try
                {
                    if (Directory.Exists(stageDir)) Directory.Delete(stageDir, true);
                    if (Directory.Exists(stageRoot) && !Directory.EnumerateFileSystemEntries(stageRoot).Any()) Directory.Delete(stageRoot);
                }
                catch (Exception e) { monitor.Warn($"Could not remove the staging folder: {e.Message}"); }
            }
            if (account != null) monitor.Info("Cleanup finished.");
            SetState("finished");
        }
    }

    /// <summary>Asks to stop: kills the sandbox processes (cleanup then runs as usual).</summary>
    public void Kill()
    {
        foreach (var p in Processes)
        {
            try { using var proc = Process.GetProcessById(p.Id); proc.Kill(); } catch { }
        }
    }

    void Poll(string sid, int? proxyPort)
    {
        var processes = ProcessInfo.FindByOwner(sid);
        bool changed = processes.Count != Processes.Count || processes.Select(p => p.Id).Except(Processes.Select(p => p.Id)).Any();
        Processes = processes;
        if (changed) Changed?.Invoke();

        var byPid = processes.ToDictionary(p => p.Id);
        foreach (var row in ProcessInfo.GetTcpTable())
        {
            if (!byPid.TryGetValue(row.Pid, out var owner)) continue;
            if (row.State == TcpRow.Listen)
            {
                if (seenListen.Add(row.Local.Port))
                {
                    var flow = new Flow
                    {
                        Kind = "listen", Pid = row.Pid, Process = owner.Name, Host = row.Local.Address.ToString(), Port = row.Local.Port,
                        Outcome = IPAddress.IsLoopback(row.Local.Address) || options.Network is NetworkMode.Open or NetworkMode.Off ? "allowed" : "blocked",
                        Note = IPAddress.IsLoopback(row.Local.Address) || options.Network is NetworkMode.Open or NetworkMode.Off
                            ? "The program is listening for connections."
                            : "The program is listening; connections from other computers are blocked.",
                    };
                    monitor.Add(flow);
                    monitor.Complete(flow);
                }
                continue;
            }
            if (IPAddress.IsLoopback(row.Remote.Address) || row.Remote.Address.Equals(IPAddress.Any) || row.Remote.Address.Equals(IPAddress.IPv6Any)) continue;
            string key = $"{row.Pid}|{row.Local}|{row.Remote}";
            if (!seenDirect.Add(key)) continue;
            var direct = new Flow
            {
                Kind = "direct", Pid = row.Pid, Process = owner.Name, Host = row.Remote.Address.ToString(), Port = row.Remote.Port,
                Outcome = "allowed", Note = "Direct TCP connection that did not use the proxy (contents not visible).",
            };
            monitor.Add(direct);
            monitor.Complete(direct);
        }
    }

    void OnBlocked(BlockedConnection b)
    {
        string app = b.Application ?? "unknown program";
        // Programs retry; merge repeats of the same attempt within a minute into one entry.
        string key = $"{app}|{b.Protocol}|{(b.Inbound ? b.Local : b.Remote)}|{b.Inbound}";
        lock (recentBlocks)
        {
            if (recentBlocks.TryGetValue(key, out var previous) && (b.Time - previous.Time).TotalSeconds < 60)
            {
                previous.Count++;
                monitor.Update(previous);
                return;
            }
        }
        var flow = new Flow
        {
            Time = b.Time,
            Kind = "direct",
            Process = Path.GetFileNameWithoutExtension(app),
            Host = b.Inbound ? b.Local?.Address.ToString() ?? "" : b.Remote.Address.ToString(),
            Port = b.Inbound ? b.Local?.Port ?? 0 : b.Remote.Port,
            Outcome = "blocked",
            Rule = options.Network == NetworkMode.None ? "network: none" : "network lock (did not use the proxy)",
            Note = b.Inbound
                ? $"Blocked incoming {b.Protocol} connection from {b.Remote} to {app}."
                : $"Blocked direct {b.Protocol} connection by {app}.",
        };
        lock (recentBlocks) recentBlocks[key] = flow;
        monitor.Add(flow);
        monitor.Complete(flow);
    }

    static void CopyDirectory(string from, string to)
    {
        foreach (var dir in Directory.EnumerateDirectories(from, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(to, Path.GetRelativePath(from, dir)));
        foreach (var file in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
            File.Copy(file, Path.Combine(to, Path.GetRelativePath(from, file)), true);
    }
}
