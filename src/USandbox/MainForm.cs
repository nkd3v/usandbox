using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace USandbox;

/// <summary>The window: a WebView2 page (ui\index.html) talking to this host through web messages.</summary>
sealed class MainForm : Form
{
    readonly AppOptions options;
    readonly WebView2 web = new() { Dock = DockStyle.Fill };
    readonly RuleStore rules;
    readonly Monitor monitor;
    readonly ConcurrentDictionary<long, Flow> dirtyFlows = new();
    readonly ConcurrentQueue<LogLine> logLines = new();
    readonly System.Windows.Forms.Timer flushTimer = new() { Interval = 250 };
    SandboxSession? session;
    CancellationTokenSource? stop;
    bool pageReady, closeWhenDone, sessionDirty;

    public int? ExitCode { get; private set; }

    public MainForm(AppOptions options)
    {
        this.options = options;
        Text = "usandbox";
        Width = 1280;
        Height = 820;
        MinimumSize = new Size(760, 480);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(0x17, 0x19, 0x1d);
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!); } catch { }
        Controls.Add(web);

        monitor = new Monitor(options.LogPath);
        monitor.FlowChanged += f => dirtyFlows[f.Id] = f;
        monitor.Logged += l => logLines.Enqueue(l);
        try { rules = new RuleStore(options.RulesPath); }
        catch (Exception e)
        {
            MessageBox.Show($"The rules file {options.RulesPath} is not valid and was not loaded:\n\n{e.Message}", "usandbox", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            rules = new RuleStore(Path.Combine(Path.GetTempPath(), $"usandbox-rules-{Guid.NewGuid():N}.json"));
        }

        flushTimer.Tick += (_, _) => Flush();
        Load += async (_, _) => await InitAsync();
        FormClosing += OnClosing;
    }

    async Task InitAsync()
    {
        try
        {
            string dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "usandbox", "WebView2");
            var envOptions = new CoreWebView2EnvironmentOptions(
                options.UiDebugPort is int port ? $"--remote-debugging-port={port} --remote-allow-origins=*" : null);
            var env = await CoreWebView2Environment.CreateAsync(null, dataDir, envOptions);
            await web.EnsureCoreWebView2Async(env);
        }
        catch (Exception e)
        {
            MessageBox.Show($"Could not start WebView2 (is the Microsoft Edge WebView2 Runtime installed?)\n\n{e.Message}\n\nYou can still use usandbox --no-gui.",
                "usandbox", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Close();
            return;
        }

        var core = web.CoreWebView2;
        core.Settings.IsStatusBarEnabled = false;
        core.Settings.AreDefaultContextMenusEnabled = true;
        core.Settings.IsZoomControlEnabled = true;
        core.SetVirtualHostNameToFolderMapping("usandbox.ui", Path.Combine(AppContext.BaseDirectory, "ui"), CoreWebView2HostResourceAccessKind.DenyCors);
        core.WebMessageReceived += (_, e) => OnMessage(e.WebMessageAsJson);
        core.NewWindowRequested += (_, e) => e.Handled = true;
        core.Navigate("https://usandbox.ui/index.html");
        flushTimer.Start();
    }

    void Post(object message) => web.CoreWebView2?.PostWebMessageAsJson(JsonSerializer.Serialize(message, Monitor.Json));

    void Flush()
    {
        if (!pageReady) return;
        var flows = new List<Flow>();
        foreach (var id in dirtyFlows.Keys.ToArray())
        {
            if (dirtyFlows.TryRemove(id, out var f)) flows.Add(f);
        }
        var logs = new List<LogLine>();
        while (logLines.TryDequeue(out var l)) logs.Add(l);
        if (flows.Count > 0 || logs.Count > 0) Post(new { type = "batch", flows, logs });
        if (sessionDirty) { sessionDirty = false; Post(new { type = "session", session = SessionInfo() }); }
    }

    object? SessionInfo() => session == null ? null : new
    {
        state = session.State,
        user = session.UserName,
        program = session.Options.Program,
        arguments = session.Options.Arguments,
        network = session.Options.Network.ToString().ToLowerInvariant(),
        inspectTls = session.Options.InspectTls,
        pid = session.MainPid,
        exitCode = session.ExitCode,
        proxyPort = session.ProxyPort,
        processes = session.Processes,
    };

    void OnMessage(string json)
    {
        JsonNode? msg;
        try { msg = JsonNode.Parse(json); } catch { return; }
        if (msg == null) return;
        try
        {
            switch ((string?)msg["type"])
            {
                case "ready":
                    pageReady = true;
                    Post(new
                    {
                        type = "init",
                        defaults = new
                        {
                            program = options.Session.Program,
                            arguments = options.Session.Arguments,
                            stage = options.Session.Stage.ToString().ToLowerInvariant(),
                            network = options.Session.Network.ToString().ToLowerInvariant(),
                            inspectTls = options.Session.InspectTls,
                            autoPassthrough = options.Session.AutoPassthrough,
                            workingDirectory = options.Session.WorkingDirectory,
                        },
                        rules = rules.Current.ToJson(),
                        rulesPath = rules.Path,
                        logPath = options.LogPath,
                    });
                    sessionDirty = true;
                    if (options.HasProgram && session == null) StartSession(options.Session);
                    break;

                case "start":
                    var s = new SessionOptions
                    {
                        Program = ((string?)msg["program"] ?? "").Trim().Trim('"'),
                        Arguments = (string?)msg["arguments"] ?? "",
                        Stage = Enum.Parse<StageMode>((string?)msg["stage"] ?? "none", true),
                        Network = Enum.Parse<NetworkMode>((string?)msg["network"] ?? "filter", true),
                        InspectTls = (bool?)msg["inspectTls"] ?? true,
                        AutoPassthrough = (bool?)msg["autoPassthrough"] ?? true,
                        WorkingDirectory = string.IsNullOrWhiteSpace((string?)msg["workingDirectory"]) ? null : ((string?)msg["workingDirectory"])!.Trim().Trim('"'),
                    };
                    StartSession(s);
                    break;

                case "stop":
                    StopSession();
                    break;

                case "browse":
                    using (var dialog = new OpenFileDialog { Title = "Program to run in the sandbox", Filter = "Programs (*.exe;*.com;*.bat;*.cmd)|*.exe;*.com;*.bat;*.cmd|All files|*.*" })
                    {
                        if (dialog.ShowDialog(this) == DialogResult.OK) Post(new { type = "browsed", path = dialog.FileName });
                    }
                    break;

                case "detail":
                    var flow = monitor.Get((long?)msg["id"] ?? -1);
                    if (flow != null)
                    {
                        Post(new
                        {
                            type = "detail",
                            flow,
                            requestHeaders = flow.RequestHeaders,
                            requestBody = BodyView(flow.RequestBody),
                            responseHeaders = flow.ResponseHeaders,
                            responseBody = BodyView(flow.ResponseBody),
                        });
                    }
                    break;

                case "saveRules":
                    try
                    {
                        rules.Save((string?)msg["json"] ?? "{}");
                        Post(new { type = "rules", rules = rules.Current.ToJson(), saved = true });
                    }
                    catch (Exception e) when (e is FormatException or JsonException)
                    {
                        Post(new { type = "rulesError", message = e.Message });
                    }
                    break;

                case "addRule":
                    var rule = msg["rule"].Deserialize<Rule>(new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
                    if (rule != null)
                    {
                        try
                        {
                            rules.Add(rule);
                            Post(new { type = "rules", rules = rules.Current.ToJson(), saved = true });
                        }
                        catch (Exception e) when (e is FormatException or JsonException)
                        {
                            Post(new { type = "rulesError", message = e.Message });
                        }
                    }
                    break;
            }
        }
        catch (Exception e)
        {
            Post(new { type = "error", message = e.Message });
        }
    }

    static object? BodyView(byte[]? body)
    {
        if (body == null || body.Length == 0) return null;
        bool truncated = body.Length >= Monitor.PreviewBytes;
        int control = 0;
        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(body);
            foreach (char c in text) if (c < 0x20 && c is not ('\r' or '\n' or '\t')) control++;
        }
        catch (DecoderFallbackException)
        {
            text = "";
            control = int.MaxValue;
        }
        // A cut-off preview can end inside a UTF-8 sequence; fall back to lenient decoding before calling it binary.
        if (control == int.MaxValue && truncated)
        {
            text = Encoding.UTF8.GetString(body);
            control = text.Count(c => c == '�') > body.Length / 50 ? int.MaxValue : 0;
        }
        if (control <= text.Length / 100) return new { kind = "text", size = body.Length, truncated, text };

        var sb = new StringBuilder();
        int max = Math.Min(body.Length, 16 * 1024);
        for (int i = 0; i < max; i += 16)
        {
            sb.Append($"{i:x8}  ");
            for (int j = 0; j < 16; j++) sb.Append(i + j < max ? $"{body[i + j]:x2} " : "   ");
            sb.Append(' ');
            for (int j = 0; j < 16 && i + j < max; j++) sb.Append(body[i + j] is >= 0x20 and < 0x7f ? (char)body[i + j] : '.');
            sb.Append('\n');
        }
        return new { kind = "binary", size = body.Length, truncated = truncated || max < body.Length, text = sb.ToString() };
    }

    void StartSession(SessionOptions s)
    {
        if (session != null && session.State != "finished") return;
        if (string.IsNullOrWhiteSpace(s.Program) || !File.Exists(s.Program))
        {
            Post(new { type = "error", message = $"Not a file: {s.Program}" });
            return;
        }
        stop = new CancellationTokenSource();
        session = new SandboxSession(s, monitor, () => rules.Current);
        session.Changed += () => sessionDirty = true;
        sessionDirty = true;
        Text = $"usandbox - {Path.GetFileName(s.Program)}";
        var current = session;
        var token = stop.Token;
        _ = Task.Run(async () =>
        {
            try { await current.RunAsync(token); }
            catch (Exception e) { monitor.Error(e.Message); }
            finally
            {
                ExitCode = current.ExitCode;
                sessionDirty = true;
                BeginInvoke(() =>
                {
                    Text = $"usandbox - {Path.GetFileName(current.Options.Program)} (finished)";
                    if (closeWhenDone) { Flush(); Close(); }
                });
            }
        });
    }

    void StopSession()
    {
        if (session == null || session.State == "finished") return;
        monitor.Info("Stopping the program...");
        stop?.Cancel();
        session.Kill();
    }

    void OnClosing(object? sender, FormClosingEventArgs e)
    {
        if (session != null && session.State != "finished")
        {
            // Never leave the throwaway account behind: stop, clean up, then close.
            e.Cancel = true;
            closeWhenDone = true;
            StopSession();
            Text = "usandbox - cleaning up before closing...";
            return;
        }
        flushTimer.Stop();
        monitor.Dispose();
    }
}
