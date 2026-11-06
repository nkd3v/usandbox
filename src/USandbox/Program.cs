using System.Diagnostics;
using System.Security.Principal;
using System.Text;

namespace USandbox;

sealed class AppOptions
{
    public SessionOptions Session { get; } = new();
    public bool HasProgram => Session.Program.Length > 0;
    public bool NoGui { get; set; }
    public bool Pause { get; set; }
    public string RulesPath { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "usandbox", "rules.json");
    public string? LogPath { get; set; }
    /// <summary>Hidden testing aid: exposes the WebView2 page on a DevTools port.</summary>
    public int? UiDebugPort { get; set; }
}

/// <summary>The current rules, shared by the proxy and the GUI; edits apply to new requests immediately.</summary>
sealed class RuleStore
{
    volatile RuleSet current;
    public string Path { get; }
    public RuleSet Current => current;

    public RuleStore(string path)
    {
        Path = path;
        current = RuleSet.Load(path);
    }

    /// <summary>Validates and saves new rules. Throws FormatException/JsonException when they are invalid.</summary>
    public void Save(string json)
    {
        var parsed = RuleSet.Parse(json);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        File.WriteAllText(Path, parsed.ToJson());
        current = parsed;
    }

    public void Add(Rule rule)
    {
        var next = RuleSet.Parse(current.ToJson());
        next.Rules.Insert(0, rule);
        Save(next.ToJson());
    }
}

static class CommandLine
{
    public const string Usage = """
        usandbox - run a program as a throwaway Windows user, watching and filtering its network traffic.

        usage: usandbox [options] [--] <program> [arguments...]
               usandbox                      (opens the window and asks for the program)

          --stage none|file|folder   copy the program somewhere the throwaway user can read it
                                     (needed for programs inside your profile: Downloads, Desktop, ...)
          --cwd <dir>                working directory (default: the program's folder)
          --network <mode>           filter (default)  all traffic must go through the usandbox proxy;
                                                       anything else is blocked and listed
                                     open              proxy is set up, direct connections are allowed (listed)
                                     off               no proxy, no blocking (direct connections listed)
                                     none              no network except loopback
          --no-tls-inspect           do not decrypt HTTPS: only host names are visible and only
                                     host rules apply to HTTPS
          --strict-tls               if a program rejects the usandbox certificate, keep failing
                                     instead of passing that host through undecrypted
          --rules <file>             rules file (default: %APPDATA%\usandbox\rules.json)
          --log <file>               append every request/connection as a JSON line
          --no-gui                   console only; Ctrl+C stops the program and cleans up
        """;

    public static AppOptions Parse(string[] args)
    {
        var o = new AppOptions();
        int i = 0;
        string Next(string name) => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{name} needs a value.");
        for (; i < args.Length; i++)
        {
            string a = args[i];
            if (a == "--") { i++; break; }
            if (!a.StartsWith("--") && !(a.StartsWith('-') && a.Length == 2)) break;
            switch (a.ToLowerInvariant())
            {
                case "--stage": o.Session.Stage = Enum.Parse<StageMode>(Next(a), true); break;
                case "--cwd": o.Session.WorkingDirectory = Path.GetFullPath(Next(a)); break;
                case "--network": o.Session.Network = Enum.Parse<NetworkMode>(Next(a), true); break;
                case "--no-tls-inspect": o.Session.InspectTls = false; break;
                case "--strict-tls": o.Session.AutoPassthrough = false; break;
                case "--rules": o.RulesPath = Path.GetFullPath(Next(a)); break;
                case "--log": o.LogPath = Path.GetFullPath(Next(a)); break;
                case "--no-gui": o.NoGui = true; break;
                case "--pause": o.Pause = true; break;
                case "--ui-debug-port": o.UiDebugPort = int.Parse(Next(a)); break;
                case "-h": case "--help": case "-?": throw new HelpRequested();
                default: throw new ArgumentException($"Unknown option {a}.");
            }
        }
        if (i < args.Length)
        {
            o.Session.Program = Path.GetFullPath(args[i].Trim('"'));
            o.Session.Arguments = string.Join(' ', args.Skip(i + 1).Select(Quote));
        }
        return o;
    }

    public sealed class HelpRequested : Exception { }

    /// <summary>Quotes one argument the way CommandLineToArgvW / the C runtime will split it again.</summary>
    public static string Quote(string arg)
    {
        if (arg.Length > 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) return arg;
        var sb = new StringBuilder("\"");
        for (int i = 0; i < arg.Length; i++)
        {
            int backslashes = 0;
            while (i < arg.Length && arg[i] == '\\') { backslashes++; i++; }
            if (i == arg.Length) { sb.Append('\\', backslashes * 2); break; }
            if (arg[i] == '"') sb.Append('\\', backslashes * 2 + 1).Append('"');
            else sb.Append('\\', backslashes).Append(arg[i]);
        }
        return sb.Append('"').ToString();
    }
}

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length > 0 && args[0].Equals("--proxy-only", StringComparison.OrdinalIgnoreCase)) return RunProxyOnly(args[1..]);

        AppOptions options;
        try { options = CommandLine.Parse(args); }
        catch (CommandLine.HelpRequested) { Console(attachOnly: true); System.Console.WriteLine(CommandLine.Usage); return 0; }
        catch (Exception e) when (e is ArgumentException or FormatException)
        {
            Console(attachOnly: true);
            System.Console.Error.WriteLine($"usandbox: {e.Message}\n\n{CommandLine.Usage}");
            if (!options_NoGuiRequested(args)) MessageBox.Show($"{e.Message}\n\n{CommandLine.Usage}", "usandbox", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 2;
        }

        if (!IsAdmin())
        {
            // Creating accounts and firewall filters needs admin rights; ask through UAC and continue in the new process.
            if (options.NoGui) Console(attachOnly: true);
            var extra = options.NoGui ? new[] { "--pause" } : Array.Empty<string>();
            try
            {
                Process.Start(new ProcessStartInfo(Environment.ProcessPath!)
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    Arguments = string.Join(' ', extra.Concat(args).Select(CommandLine.Quote)),
                    WorkingDirectory = Environment.CurrentDirectory,
                });
                if (options.NoGui) System.Console.WriteLine("usandbox: continuing in the elevated window.");
                return 0;
            }
            catch (Exception e)
            {
                string message = $"Could not get admin rights: {e.Message}";
                if (options.NoGui) System.Console.Error.WriteLine($"usandbox: {message}");
                else MessageBox.Show(message, "usandbox", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }

        if (options.NoGui) return RunConsole(options);

        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        using var form = new MainForm(options);
        Application.Run(form);
        return form.ExitCode ?? 0;
    }

    static bool options_NoGuiRequested(string[] args) => args.Any(a => a.Equals("--no-gui", StringComparison.OrdinalIgnoreCase));

    static bool IsAdmin() => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    /// <summary>The exe is a GUI app; borrow the console it was started from, or open one.</summary>
    static void Console(bool attachOnly)
    {
        // Output that is already redirected (a pipe or file) is used as is.
        if (System.Console.IsOutputRedirected) return;
        if (!Native.AttachConsole(-1) && !attachOnly) Native.AllocConsole();
        var stdout = new StreamWriter(System.Console.OpenStandardOutput()) { AutoFlush = true };
        System.Console.SetOut(stdout);
        System.Console.SetError(new StreamWriter(System.Console.OpenStandardError()) { AutoFlush = true });
        System.Console.OutputEncoding = Encoding.UTF8;
    }

    static void PrintTo(Monitor monitor)
    {
        var printLock = new object();
        monitor.Logged += l =>
        {
            lock (printLock)
            {
                System.Console.ForegroundColor = l.Level switch { "warn" => ConsoleColor.Yellow, "error" => ConsoleColor.Red, _ => ConsoleColor.Gray };
                System.Console.WriteLine($"{l.Time:HH:mm:ss} {l.Text}");
                System.Console.ResetColor();
            }
        };
        monitor.FlowCompleted += f =>
        {
            lock (printLock)
            {
                System.Console.ForegroundColor = f.Outcome switch
                {
                    "blocked" => ConsoleColor.Red, "error" => ConsoleColor.Yellow, "passthrough" => ConsoleColor.Cyan, _ => ConsoleColor.Green,
                };
                System.Console.Write($"{f.Time:HH:mm:ss} {f.Outcome.ToUpperInvariant(),-11}");
                System.Console.ResetColor();
                string what = f.Url != null ? $"{f.Method} {f.Url}" : $"{f.Kind} {f.Host}:{f.Port}";
                System.Console.WriteLine($" {what}{(f.Status is int s ? $" -> {s}" : "")}" +
                    $"{(f.Process != null ? $"  [{f.Process}]" : "")}{(f.Rule != null ? $"  rule: {f.Rule}" : "")}{(f.Note != null ? $"  ({f.Note})" : "")}");
            }
        };

    }

    /// <summary>
    /// Testing aid: runs only the proxy, for the current user, with no account and no firewall lock.
    /// Point a client at the printed port (and trust the printed CA file) to try rules out.
    /// </summary>
    static int RunProxyOnly(string[] args)
    {
        Console(attachOnly: false);
        var options = CommandLine.Parse(args);
        var rules = new RuleStore(options.RulesPath);
        using var monitor = new Monitor(options.LogPath);
        PrintTo(monitor);
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        using var proxy = new ProxyServer(monitor, () => rules.Current, sid)
        {
            InspectTls = options.Session.InspectTls, AutoPassthrough = options.Session.AutoPassthrough,
        };
        using var ca = new CertificateAuthority("proxy-only", proxy.CrlUrl);
        proxy.Ca = ca;
        string caFile = Path.Combine(Path.GetTempPath(), "usandbox-proxy-only-ca.pem");
        File.WriteAllText(caFile, ca.CertificatePem);
        proxy.Start();
        System.Console.WriteLine($"PROXY 127.0.0.1:{proxy.Port}");
        System.Console.WriteLine($"CA {caFile}");
        System.Console.WriteLine($"RULES {rules.Path} ({rules.Current.Rules.Count})");
        using var stop = new ManualResetEventSlim();
        System.Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Set(); };
        // Also stop when standard input closes, so scripts can end it.
        _ = Task.Run(() => { try { while (System.Console.In.ReadLine() != null) { } } catch { } stop.Set(); });
        stop.Wait();
        return 0;
    }

    static int RunConsole(AppOptions options)
    {
        Console(attachOnly: false);
        int code = 1;
        try
        {
            while (!options.HasProgram)
            {
                System.Console.Write("Path of the program to run: ");
                string answer = (System.Console.ReadLine() ?? "").Trim().Trim('"', '\'');
                if (answer.Length == 0) continue;
                if (File.Exists(answer)) options.Session.Program = Path.GetFullPath(answer);
                else System.Console.WriteLine($"Not a file: {answer}");
            }

            var rules = new RuleStore(options.RulesPath);
            if (rules.Current.Rules.Count > 0) System.Console.WriteLine($"Loaded {rules.Current.Rules.Count} rule(s) from {rules.Path}.");
            using var monitor = new Monitor(options.LogPath);
            PrintTo(monitor);

            using var stop = new CancellationTokenSource();
            System.Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                System.Console.WriteLine("Stopping...");
                stop.Cancel();
            };
            var session = new SandboxSession(options.Session, monitor, () => rules.Current);
            System.Console.WriteLine("Press Ctrl+C to stop the program and clean up.");
            session.RunAsync(stop.Token).GetAwaiter().GetResult();
            code = session.ExitCode ?? 1;
        }
        catch (Exception e)
        {
            System.Console.ForegroundColor = ConsoleColor.Red;
            System.Console.Error.WriteLine($"usandbox: {e.Message}");
            System.Console.ResetColor();
        }
        if (options.Pause)
        {
            System.Console.Write("Press Enter to close this window");
            System.Console.ReadLine();
        }
        return code;
    }
}
