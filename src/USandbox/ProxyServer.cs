using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace USandbox;

/// <summary>
/// The HTTP(S) proxy the sandboxed account is pointed at. It records every request, applies the
/// rules, and for HTTPS either decrypts with the run's own CA ("inspect") or forwards the encrypted
/// bytes untouched ("passthrough"), in which case only the host name is visible.
/// </summary>
sealed class ProxyServer : IDisposable
{
    public const string CrlPath = "/usandbox-ca.crl", CertPath = "/usandbox-ca.crt";

    readonly TcpListener listener;
    readonly Monitor monitor;
    readonly Func<RuleSet> rules;
    readonly string sandboxSid;
    readonly CancellationTokenSource cts = new();
    readonly ConcurrentDictionary<string, string> autoPassthrough = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentDictionary<int, string> processNames = new();

    public int Port { get; }
    public CertificateAuthority? Ca { get; set; }

    /// <summary>Decrypt HTTPS (needs <see cref="Ca"/>). When false, HTTPS is passed through.</summary>
    public bool InspectTls { get; set; } = true;

    /// <summary>When the program refuses the usandbox certificate, stop decrypting that host instead of failing every time.</summary>
    public bool AutoPassthrough { get; set; } = true;

    public string CrlUrl => $"http://127.0.0.1:{Port}{CrlPath}";

    /// <summary>When set, TLS that is passed through is recorded and decrypted with keys from the program's memory.</summary>
    public KeyExtractor? Extractor { get; set; }

    /// <summary>Never decrypt by impersonating servers; pass all TLS through and rely on <see cref="Extractor"/>.</summary>
    public bool PassiveTls { get; set; }

    /// <summary>Set for transparent capture: tells where redirected connections were going.</summary>
    public Redirector? Redirector { get; set; }

    Socket? transparent4, transparent6;

    /// <summary>
    /// Reserves the loopback ports redirected connections arrive on (IPv4 and IPv6) without listening yet.
    /// </summary>
    public (int Port4, int Port6) BindTransparent()
    {
        transparent4 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        transparent4.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        int port4 = ((IPEndPoint)transparent4.LocalEndPoint!).Port;
        transparent6 = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        transparent6.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
        try { transparent6.Bind(new IPEndPoint(IPAddress.IPv6Loopback, port4)); }
        catch (SocketException) { transparent6.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0)); }
        return (port4, ((IPEndPoint)transparent6.LocalEndPoint!).Port);
    }

    public void StartTransparent()
    {
        foreach (var socket in new[] { transparent4, transparent6 })
        {
            if (socket == null) continue;
            socket.Listen(512);
            _ = Task.Run(async () =>
            {
                while (!cts.IsCancellationRequested)
                {
                    Socket accepted;
                    try { accepted = await socket.AcceptAsync(cts.Token); }
                    catch { break; }
                    _ = Task.Run(() => HandleTransparentAsync(accepted));
                }
            });
        }
    }

    public ProxyServer(Monitor monitor, Func<RuleSet> rules, string sandboxSid)
    {
        this.monitor = monitor;
        this.rules = rules;
        this.sandboxSid = sandboxSid;
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(512);
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public void Start() => _ = AcceptLoopAsync();

    async Task AcceptLoopAsync()
    {
        while (!cts.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(cts.Token); }
            catch { break; }
            _ = Task.Run(() => HandleClientAsync(client));
        }
    }

    sealed class Client
    {
        public int? Pid;
        public string? Process;
        public bool Trusted;
    }

    async Task HandleClientAsync(TcpClient tcp)
    {
        var ct = cts.Token;
        using (tcp)
        {
            try
            {
                tcp.NoDelay = true;
                var client = Identify((IPEndPoint)tcp.Client.RemoteEndPoint!);
                var stream = tcp.GetStream();
                var reader = new HttpReader(stream);
                var head = await reader.ReadHeadAsync(ct);
                if (head == null) return;

                if (IsLocal(head, out string? path))
                {
                    await ServeLocalAsync(stream, path!, ct);
                    return;
                }
                if (!client.Trusted)
                {
                    monitor.Warn($"Refused a proxy connection from {client.Process ?? "an unknown process"} (PID {client.Pid}), which does not run as the sandbox account.");
                    await stream.WriteAsync(HttpUtil.SimpleResponse(403, "Forbidden", "This proxy only serves the usandbox sandbox account.\n"), ct);
                    return;
                }

                if (head.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                    await HandleConnectAsync(client, reader, stream, head, ct);
                else
                    await HandleHttpAsync(client, reader, stream, head, null, null, ct);
            }
            catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or ObjectDisposedException or AuthenticationException)
            {
                // The program or the server went away; nothing to report beyond what the flow already shows.
            }
            catch (Exception e)
            {
                monitor.Error($"Proxy error: {e}");
            }
        }
    }

    async Task HandleTransparentAsync(Socket socket)
    {
        var ct = cts.Token;
        using var tcp = new TcpClient { Client = socket };
        try
        {
            tcp.NoDelay = true;
            var redirected = Redirector?.Lookup((IPEndPoint)socket.RemoteEndPoint!);
            if (redirected == null) return;   // not a redirected connection
            var client = new Client { Pid = redirected.Pid, Trusted = true };
            client.Process = processNames.GetOrAdd(redirected.Pid, p =>
            {
                try { using var proc = Process.GetProcessById(p); return proc.ProcessName; } catch { return $"pid {p}"; }
            });
            string ip = redirected.Original.Address.ToString();
            int port = redirected.Original.Port;
            string shown = Redirector!.NameOf(redirected.Original.Address) ?? ip;
            var flow = NewFlow(client, "tunnel", shown, port);
            flow.Url = $"{shown}:{port}";
            flow.Note = (shown == ip ? $"redirected connection to {ip}:{port}" : $"redirected connection to {ip}:{port} ({shown} by DNS)") + $" from port {redirected.Client.Port}";

            var rule = rules().MatchConnection(shown);
            if (rule == null && shown != ip) rule = rules().MatchConnection(ip);
            if (rule?.Action == "block") { Block(flow, rule, null); return; }

            var stream = tcp.GetStream();
            await HandleTunnelAsync(client, flow, rule, new HttpReader(stream), stream, ip, port, ct);
        }
        catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or ObjectDisposedException or AuthenticationException)
        {
        }
        catch (Exception e)
        {
            monitor.Error($"Proxy error (redirected connection): {e}");
        }
    }

    Client Identify(IPEndPoint remote)
    {
        var client = new Client();
        client.Pid = ProcessInfo.FindClientPid(remote, Port);
        if (client.Pid is int pid)
        {
            client.Trusted = ProcessInfo.GetOwnerSid(pid) == sandboxSid;
            client.Process = processNames.GetOrAdd(pid, p =>
            {
                try { using var proc = Process.GetProcessById(p); return proc.ProcessName; } catch { return $"pid {p}"; }
            });
        }
        return client;
    }

    bool IsLocal(HttpHead head, out string? path)
    {
        path = null;
        string target = head.Target;
        if (target.StartsWith('/')) { path = target; return true; }
        if (Uri.TryCreate(target, UriKind.Absolute, out var uri) && uri.Scheme == "http" && uri.Port == Port &&
            (uri.Host == "127.0.0.1" || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)))
        {
            path = uri.AbsolutePath;
            return true;
        }
        return false;
    }

    async Task ServeLocalAsync(Stream stream, string path, CancellationToken ct)
    {
        (string type, byte[]? body) = path switch
        {
            CrlPath => ("application/pkix-crl", Ca?.Crl),
            CertPath => ("application/x-x509-ca-cert", Ca?.Certificate.RawData),
            _ => ("", null),
        };
        if (body == null)
        {
            await stream.WriteAsync(HttpUtil.SimpleResponse(404, "Not Found", "Not found.\n"), ct);
            return;
        }
        var head = $"HTTP/1.1 200 OK\r\nContent-Type: {type}\r\nContent-Length: {body.Length}\r\nCache-Control: max-age=86400\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(head), ct);
        await stream.WriteAsync(body, ct);
    }

    static (string Host, int Port) SplitHostPort(string value, int defaultPort)
    {
        if (value.StartsWith('['))
        {
            int close = value.IndexOf(']');
            string h = value[1..close];
            return (h, close + 2 <= value.Length && value.Length > close + 1 && value[close + 1] == ':' ? int.Parse(value[(close + 2)..]) : defaultPort);
        }
        int colon = value.LastIndexOf(':');
        if (colon > 0 && value.IndexOf(':') == colon && int.TryParse(value[(colon + 1)..], out int port)) return (value[..colon], port);
        return (value, defaultPort);
    }

    Flow NewFlow(Client client, string kind, string host, int port) => new()
    {
        Kind = kind, Pid = client.Pid, Process = client.Process, Host = host, Port = port,
    };

    // ---- CONNECT -----------------------------------------------------------------------------

    async Task HandleConnectAsync(Client client, HttpReader reader, NetworkStream stream, HttpHead head, CancellationToken ct)
    {
        var (host, port) = SplitHostPort(head.Target, 443);
        var flow = NewFlow(client, "tunnel", host, port);
        flow.Method = "CONNECT";
        flow.Url = $"{host}:{port}";
        flow.RequestHeaders = head.HeaderText();
        var started = Stopwatch.StartNew();

        var rule = rules().MatchConnection(host);
        if (rule?.Action == "block")
        {
            Block(flow, rule, 403);
            await stream.WriteAsync(HttpUtil.SimpleResponse(403, "Forbidden", $"Blocked by usandbox rule: {rule.Describe()}\n"), ct);
            return;
        }

        await stream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), ct);
        await HandleTunnelAsync(client, flow, rule, reader, stream, host, port, ct);
    }

    /// <summary>
    /// A byte stream from the program to <paramref name="host"/>:<paramref name="port"/> (a CONNECT
    /// tunnel, or a redirected connection): decides between decrypting, passing through and reading HTTP.
    /// </summary>
    async Task HandleTunnelAsync(Client client, Flow flow, Rule? rule, HttpReader reader, NetworkStream stream, string host, int port, CancellationToken ct)
    {
        var started = Stopwatch.StartNew();

        // Look at what the program sends first. Some protocols wait for the server to speak, so do not wait forever.
        bool gotData;
        using (var peek = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            peek.CancelAfter(TimeSpan.FromSeconds(3));
            try { gotData = await reader.EnsureAsync(1, peek.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { gotData = true; }
        }
        if (reader.Buffered.Length == 0)
        {
            if (!gotData) return; // closed without sending anything
            if (flow.Method == null) flow.Kind = "tcp";
            await RawTunnelAsync(flow, reader, stream, host, port, "the program waited for the server to speak first", ct, capture: true);
            return;
        }

        if (TlsClientHello.LooksLikeTls(reader.Buffered.Span))
        {
            int recordLength = TlsClientHello.RecordLength(reader.Buffered.Span);
            if (recordLength > 0) await reader.EnsureAsync(recordLength, ct);
            var (sni, alpn) = TlsClientHello.Parse(reader.Buffered.Span);
            string name = string.IsNullOrEmpty(sni) ? (flow.Host.Length > 0 ? flow.Host : host) : sni;
            if (sni != null) { flow.Host = sni; flow.Url = $"{sni}:{port}"; }
            if (sni != null && !sni.Equals(host, StringComparison.OrdinalIgnoreCase))
            {
                var sniRule = rules().MatchConnection(sni);
                if (sniRule?.Action == "block") { Block(flow, sniRule, null); flow.Note = $"TLS server name {sni}"; return; }
                rule ??= sniRule;
            }

            string key = $"{name}:{port}";
            string? passthroughWhy =
                PassiveTls ? "passive TLS mode" :
                !InspectTls || Ca == null ? "TLS inspection is off" :
                rule?.Action == "passthrough" ? $"rule: {rule.Describe()}" :
                autoPassthrough.TryGetValue(key, out var why) ? why :
                alpn.Count > 0 && !alpn.Contains("http/1.1") ? $"the program only speaks {string.Join(", ", alpn)}" :
                null;

            if (passthroughWhy != null)
            {
                flow.Note = (flow.Note == null ? "" : flow.Note + "; ") + $"TLS{(sni != null ? $", server name {sni}" : "")}; not intercepted: {passthroughWhy}";
                TlsRecording? recording = Extractor != null ? new TlsRecording(flow, name, Math.Max(rules().MaxInspectBytes, 1 << 20)) : null;
                await RawTunnelAsync(flow, reader, stream, host, port, null, ct, recording: recording);
                return;
            }

            await InspectTlsAsync(client, flow, reader, stream, host, port, name, alpn.Count > 0, key, started, ct);
            return;
        }

        if (LooksLikeHttp(reader.Buffered.Span))
        {
            var first = await reader.ReadHeadAsync(ct);
            if (first != null) await HandleHttpAsync(client, reader, stream, first, (host, port, null), null, ct);
            return;
        }

        if (flow.Method == null) flow.Kind = "tcp";
        await RawTunnelAsync(flow, reader, stream, host, port, "not HTTP or TLS", ct, capture: true);
    }

    static bool LooksLikeHttp(ReadOnlySpan<byte> data)
    {
        int i = 0;
        while (i < data.Length && i < 10 && data[i] is >= (byte)'A' and <= (byte)'Z') i++;
        return i >= 3 && (i == data.Length || data[i] == ' ');
    }

    async Task InspectTlsAsync(Client client, Flow flow, HttpReader reader, NetworkStream stream, string host, int port,
                               string name, bool clientUsesAlpn, string key, Stopwatch started, CancellationToken ct)
    {
        Upstream? upstream = null;
        Exception? upstreamError = null;
        try { upstream = await Upstream.ConnectAsync(host, port, name, ct); }
        catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested) { upstreamError = e; }

        var ssl = new SslStream(new PrefixStream(reader.TakeBuffered(), stream), false);
        try
        {
            using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                handshake.CancelAfter(TimeSpan.FromSeconds(20));
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = Ca!.GetServerContext(name),
                    ApplicationProtocols = clientUsesAlpn ? new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 } : null,
                    ClientCertificateRequired = false,
                }, handshake.Token);
            }
        }
        catch (Exception e) when (e is AuthenticationException or IOException or OperationCanceledException)
        {
            upstream?.Dispose();
            await ssl.DisposeAsync();
            if (ct.IsCancellationRequested) return;
            flow.Outcome = "error";
            flow.Note = $"The program rejected the usandbox certificate for {name} ({e.GetBaseException().Message}). " +
                        "It probably pins certificates or uses its own list of trusted roots.";
            if (AutoPassthrough)
            {
                autoPassthrough[key] = "the program rejected the usandbox certificate earlier";
                flow.Note += $" Later connections to {key} are passed through without decryption.";
            }
            flow.DurationMs = started.Elapsed.TotalMilliseconds;
            monitor.Add(flow);
            monitor.Complete(flow);
            return;
        }

        await using (ssl)
        {
            var clientReader = new HttpReader(ssl);
            var first = await clientReader.ReadHeadAsync(ct);
            if (first == null) { upstream?.Dispose(); return; }

            if (upstreamError != null)
            {
                var errorFlow = NewFlow(client, "https", host, port);
                errorFlow.Method = first.Method;
                errorFlow.Url = $"https://{name}{(port == 443 ? "" : $":{port}")}{first.Target}";
                errorFlow.Outcome = "error";
                errorFlow.Status = 502;
                errorFlow.Note = $"Could not connect to the real server: {upstreamError.GetBaseException().Message}";
                errorFlow.RequestHeaders = first.HeaderText();
                monitor.Add(errorFlow);
                monitor.Complete(errorFlow);
                await ssl.WriteAsync(HttpUtil.SimpleResponse(502, "Bad Gateway", $"usandbox could not connect to {name}:{port}: {upstreamError.GetBaseException().Message}\n"), ct);
                return;
            }

            await HandleHttpAsync(client, clientReader, ssl, first, (host, port, name), upstream, ct);
        }
    }

    // ---- raw tunnels -------------------------------------------------------------------------

    /// <param name="capture">keep the first bytes of each direction for display (unknown protocols)</param>
    /// <param name="recording">record TLS for decryption with keys from memory</param>
    async Task RawTunnelAsync(Flow flow, HttpReader reader, Stream clientStream, string host, int port, string? why, CancellationToken ct,
                              bool capture = false, TlsRecording? recording = null)
    {
        var started = Stopwatch.StartNew();
        flow.Outcome = "passthrough";
        if (why != null) flow.Note = (flow.Note == null ? "" : flow.Note + "; ") + $"forwarded unread: {why}";
        monitor.Add(flow);

        TcpClient upstream;
        try
        {
            upstream = new TcpClient();
            using var connect = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connect.CancelAfter(TimeSpan.FromSeconds(20));
            await upstream.ConnectAsync(host, port, connect.Token);
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            flow.Outcome = "error";
            flow.Note = (flow.Note == null ? "" : flow.Note + "; ") + $"could not connect: {e.GetBaseException().Message}";
            monitor.Complete(flow);
            return;
        }

        MemoryStream? sentData = capture ? new() : null, receivedData = capture ? new() : null;
        static void Keep(MemoryStream? into, ReadOnlySpan<byte> data)
        {
            if (into != null && into.Length < Monitor.PreviewBytes) into.Write(data[..(int)Math.Min(data.Length, Monitor.PreviewBytes - into.Length)]);
        }
        using (upstream)
        {
            upstream.NoDelay = true;
            var up = upstream.GetStream();
            var prefix = reader.TakeBuffered();
            if (prefix.Length > 0)
            {
                recording?.Feed(true, prefix);
                Keep(sentData, prefix);
                await up.WriteAsync(prefix, ct);
                flow.BytesSent += prefix.Length;
            }
            var extractor = Extractor;
            await PipeAsync(clientStream, up,
                d => { Keep(sentData, d.Span); flow.BytesSent += d.Length; },
                d =>
                {
                    if (recording != null && recording.Feed(false, d.Span)) _ = extractor!.CaptureAsync(recording);
                    Keep(receivedData, d.Span);
                    flow.BytesReceived += d.Length;
                }, ct,
                beforeSend: recording == null ? null : async d =>
                {
                    // Hold the program's first application data until its memory is captured (see KeyExtractor.CaptureAsync).
                    if (recording.Feed(true, d.Span))
                        await extractor!.CaptureAsync(recording).WaitAsync(TimeSpan.FromSeconds(3), ct).ContinueWith(_ => { });
                });
        }
        if (sentData != null) flow.RequestBody = sentData.ToArray();
        if (receivedData != null) flow.ResponseBody = receivedData.ToArray();
        flow.DurationMs = started.Elapsed.TotalMilliseconds;
        monitor.Complete(flow);
        if (recording != null) Extractor?.Closed(recording);
    }

    static Task PipeAsync(Stream client, Stream server, Action<int> sent, Action<int> received, CancellationToken ct) =>
        PipeAsync(client, server, (ReadOnlyMemory<byte> d) => sent(d.Length), (ReadOnlyMemory<byte> d) => received(d.Length), ct);

    /// <summary>Copies both ways until either side closes; the callbacks see each chunk after it was forwarded.</summary>
    static async Task PipeAsync(Stream client, Stream server, Action<ReadOnlyMemory<byte>> sent, Action<ReadOnlyMemory<byte>> received, CancellationToken ct,
                                Func<ReadOnlyMemory<byte>, Task>? beforeSend = null)
    {
        using var done = CancellationTokenSource.CreateLinkedTokenSource(ct);
        async Task Copy(Stream from, Stream to, Action<ReadOnlyMemory<byte>> count, Func<ReadOnlyMemory<byte>, Task>? before)
        {
            var buffer = new byte[64 * 1024];
            try
            {
                int n;
                while ((n = await from.ReadAsync(buffer, done.Token)) > 0)
                {
                    if (before != null) await before(buffer.AsMemory(0, n));
                    await to.WriteAsync(buffer.AsMemory(0, n), done.Token);
                    count(buffer.AsMemory(0, n));
                }
            }
            catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException or SocketException) { }
            finally { done.Cancel(); }
        }
        await Task.WhenAll(Copy(client, server, sent, beforeSend), Copy(server, client, received, null));
    }

    // ---- HTTP --------------------------------------------------------------------------------

    sealed class Body
    {
        public byte[] Data = Array.Empty<byte>();
        public bool Complete = true;
        public IAsyncEnumerator<ReadOnlyMemory<byte>>? Rest;
        public Framing Framing;
    }

    static async Task<Body> BufferBodyAsync(HttpReader reader, Framing framing, long length, int limit, CancellationToken ct)
    {
        var body = new Body { Framing = framing };
        if (framing == Framing.None) return body;
        var buffer = new MemoryStream();
        var e = reader.ReadBodyAsync(framing, length, ct).GetAsyncEnumerator(ct);
        while (await e.MoveNextAsync())
        {
            buffer.Write(e.Current.Span);
            if (buffer.Length >= limit)
            {
                body.Complete = false;
                body.Rest = e;
                break;
            }
        }
        if (body.Complete) await e.DisposeAsync();
        body.Data = buffer.ToArray();
        return body;
    }

    /// <summary>Sends a head and a held-back body, keeping the original framing if the body was not read to the end.</summary>
    static async Task<long> SendAsync(Stream to, HttpHead head, Body body, bool hadLengthHeader, CancellationToken ct)
    {
        long bytes = 0;
        if (body.Complete)
        {
            head.Remove("Transfer-Encoding");
            if (body.Data.Length > 0 || hadLengthHeader) head.Set("Content-Length", body.Data.Length.ToString());
            await to.WriteAsync(head.ToBytes(), ct);
            await to.WriteAsync(body.Data, ct);
            await to.FlushAsync(ct);
            return body.Data.Length;
        }

        await to.WriteAsync(head.ToBytes(), ct);
        var writer = new BodyWriter(to, body.Framing == Framing.Chunked);
        await writer.WriteAsync(body.Data, ct);
        bytes += body.Data.Length;
        try
        {
            while (await body.Rest!.MoveNextAsync())
            {
                await writer.WriteAsync(body.Rest.Current, ct);
                bytes += body.Rest.Current.Length;
            }
        }
        finally { await body.Rest!.DisposeAsync(); }
        await writer.FinishAsync(ct);
        return bytes;
    }

    void Block(Flow flow, Rule rule, int? status)
    {
        flow.Outcome = "blocked";
        flow.Rule = rule.Describe();
        flow.Status = status;
        monitor.Add(flow);
        monitor.Complete(flow);
    }

    /// <summary>
    /// Handles requests on one client connection. <paramref name="target"/> is set inside a CONNECT
    /// tunnel (host, port, TLS server name or null for plain HTTP); otherwise requests carry absolute URLs.
    /// </summary>
    async Task HandleHttpAsync(Client client, HttpReader clientReader, Stream clientStream, HttpHead? request,
                               (string Host, int Port, string? TlsName)? target, Upstream? upstream, CancellationToken ct)
    {
        try
        {
            for (; request != null; request = await clientReader.ReadHeadAsync(ct))
            {
                var started = Stopwatch.StartNew();
                string method = request.Method;
                string host, pathAndQuery, url;
                string? shownHost = null;
                int port;
                bool tls = target?.TlsName != null;

                if (target is { } t)
                {
                    host = t.Host;
                    port = t.Port;
                    pathAndQuery = request.Target;
                    string authority = t.TlsName ?? request.Get("Host") ?? host;
                    if (authority.Contains(':') && !authority.StartsWith('[')) authority = authority[..authority.LastIndexOf(':')];
                    shownHost = authority;
                    url = $"{(tls ? "https" : "http")}://{authority}{((tls && port == 443) || (!tls && port == 80) ? "" : $":{port}")}{pathAndQuery}";
                }
                else if (IsLocal(request, out string? localPath))
                {
                    await ServeLocalAsync(clientStream, localPath!, ct);
                    return;
                }
                else if (Uri.TryCreate(request.Target, UriKind.Absolute, out var uri) && uri.Scheme == "http")
                {
                    host = uri.IdnHost;
                    port = uri.Port;
                    pathAndQuery = uri.PathAndQuery;
                    url = uri.AbsoluteUri;
                    request.StartLine = $"{method} {pathAndQuery} {request.RequestVersion}";
                }
                else
                {
                    await clientStream.WriteAsync(HttpUtil.SimpleResponse(400, "Bad Request", "usandbox proxy: expected an absolute http:// URL.\n"), ct);
                    return;
                }

                var flow = NewFlow(client, tls ? "https" : "http", shownHost ?? host, port);
                flow.Method = method;
                flow.Url = url;
                monitor.Add(flow);

                request.Remove("Proxy-Connection");
                request.Remove("Proxy-Authorization");
                bool clientWantsClose = request.HasToken("Connection", "close") ||
                    (request.RequestVersion == "HTTP/1.0" && !request.HasToken("Connection", "keep-alive"));

                if (request.Get("Expect") is { } expect && expect.Contains("100-continue", StringComparison.OrdinalIgnoreCase))
                {
                    request.Remove("Expect");
                    await clientStream.WriteAsync("HTTP/1.1 100 Continue\r\n\r\n"u8.ToArray(), ct);
                }

                var ruleSet = rules();
                var (requestFraming, requestLength) = HttpUtil.RequestFraming(request);
                var requestBody = await BufferBodyAsync(clientReader, requestFraming, requestLength, ruleSet.MaxInspectBytes, ct);
                byte[] decodedRequest = HttpUtil.Decode(requestBody.Data, request.Get("Content-Encoding"), ruleSet.MaxInspectBytes);
                flow.RequestHeaders = request.HeaderText();
                flow.RequestBody = Monitor.Preview(decodedRequest);
                if (!requestBody.Complete) flow.Note = $"request body is larger than {ruleSet.MaxInspectBytes / 1024 / 1024} MB; only the start was checked";

                string requestText = flow.RequestHeaders;
                string? requestBodyText = null;
                string RequestBodyText() => requestBodyText ??= HttpUtil.Text(decodedRequest);

                var rule = ruleSet.MatchMessage(shownHost ?? host, method, url, requestText, RequestBodyText);
                if (rule?.Action == "block")
                {
                    flow.Outcome = "blocked";
                    flow.Rule = rule.Describe();
                    flow.Status = 403;
                    flow.BytesSent = 0;
                    flow.DurationMs = started.Elapsed.TotalMilliseconds;
                    monitor.Complete(flow);
                    await clientStream.WriteAsync(HttpUtil.SimpleResponse(403, "Forbidden", $"Blocked by usandbox rule: {rule.Describe()}\n",
                        close: !requestBody.Complete || clientWantsClose), ct);
                    await clientStream.FlushAsync(ct);
                    if (requestBody.Rest != null) await requestBody.Rest.DisposeAsync();
                    if (!requestBody.Complete || clientWantsClose) return;
                    continue;
                }
                if (rule?.Action == "allow") flow.Rule = rule.Describe();

                // Connect (or reconnect) to the real server.
                if (upstream != null && (upstream.Closed || upstream.Host != host || upstream.Port != port)) { upstream.Dispose(); upstream = null; }
                if (upstream == null)
                {
                    try { upstream = await Upstream.ConnectAsync(host, port, target?.TlsName, ct); }
                    catch (Exception e) when (!ct.IsCancellationRequested)
                    {
                        flow.Outcome = "error";
                        flow.Status = 502;
                        flow.Note = $"Could not connect: {e.GetBaseException().Message}";
                        flow.DurationMs = started.Elapsed.TotalMilliseconds;
                        monitor.Complete(flow);
                        if (requestBody.Rest != null) await requestBody.Rest.DisposeAsync();
                        await clientStream.WriteAsync(HttpUtil.SimpleResponse(502, "Bad Gateway", $"usandbox could not connect to {host}:{port}: {e.GetBaseException().Message}\n"), ct);
                        return;
                    }
                }

                if (request.Get("Host") == null) request.Headers.Insert(0, new("Host", port == (tls ? 443 : 80) ? host : $"{host}:{port}"));
                flow.BytesSent = await SendAsync(upstream.Stream, request, requestBody, request.Get("Content-Length") != null, ct);

                // Read the response, passing interim (1xx) responses straight through.
                HttpHead? response;
                while (true)
                {
                    response = await upstream.Reader.ReadHeadAsync(ct);
                    if (response == null || response.Status is < 100 or >= 200 or 101) break;
                    await clientStream.WriteAsync(response.ToBytes(), ct);
                }
                if (response == null)
                {
                    flow.Outcome = "error";
                    flow.Status = 502;
                    flow.Note = "The server closed the connection without answering.";
                    flow.DurationMs = started.Elapsed.TotalMilliseconds;
                    monitor.Complete(flow);
                    await clientStream.WriteAsync(HttpUtil.SimpleResponse(502, "Bad Gateway", "usandbox: the server closed the connection without answering.\n"), ct);
                    return;
                }

                flow.Status = response.Status;
                flow.ResponseHeaders = response.HeaderText();
                flow.ContentType = response.Get("Content-Type");
                monitor.Update(flow);

                if (response.Status == 101)
                {
                    flow.Kind = "websocket";
                    flow.Note = "Switched protocols; the rest of the connection is forwarded unread.";
                    await clientStream.WriteAsync(response.ToBytes(), ct);
                    var toServer = clientReader.TakeBuffered();
                    if (toServer.Length > 0) await upstream.Stream.WriteAsync(toServer, ct);
                    var toClient = upstream.Reader.TakeBuffered();
                    if (toClient.Length > 0) await clientStream.WriteAsync(toClient, ct);
                    await PipeAsync(clientStream, upstream.Stream, n => flow.BytesSent += n, n => flow.BytesReceived += n, ct);
                    flow.DurationMs = started.Elapsed.TotalMilliseconds;
                    monitor.Complete(flow);
                    return;
                }

                var (responseFraming, responseLength) = HttpUtil.ResponseFraming(response, method);
                bool closeAfter = clientWantsClose || responseFraming == Framing.UntilClose;
                bool upstreamCloses = response.HasToken("Connection", "close") || response.ResponseVersion == "HTTP/1.0" || responseFraming == Framing.UntilClose;
                bool streaming = (flow.ContentType ?? "").Contains("text/event-stream", StringComparison.OrdinalIgnoreCase);

                if (ruleSet.HasResponseContentRules && responseFraming != Framing.None && !streaming)
                {
                    var responseBody = await BufferBodyAsync(upstream.Reader, responseFraming, responseLength, ruleSet.MaxInspectBytes, ct);
                    byte[] decoded = HttpUtil.Decode(responseBody.Data, response.Get("Content-Encoding"), ruleSet.MaxInspectBytes);
                    flow.ResponseBody = Monitor.Preview(decoded);
                    var responseRule = ruleSet.MatchMessage(shownHost ?? host, method, url, requestText, RequestBodyText,
                        flow.ResponseHeaders, () => HttpUtil.Text(decoded));
                    if (responseRule?.Action == "block")
                    {
                        flow.Outcome = "blocked";
                        flow.Rule = responseRule.Describe();
                        flow.Note = $"Response from the server ({response.Status}) was replaced.";
                        flow.Status = 403;
                        flow.DurationMs = started.Elapsed.TotalMilliseconds;
                        monitor.Complete(flow);
                        if (responseBody.Rest != null) await responseBody.Rest.DisposeAsync();
                        upstream.Dispose();
                        upstream = null;
                        await clientStream.WriteAsync(HttpUtil.SimpleResponse(403, "Forbidden", $"Blocked by usandbox rule: {responseRule.Describe()}\n"), ct);
                        return;
                    }
                    if (responseRule?.Action == "allow") flow.Rule ??= responseRule.Describe();
                    if (!responseBody.Complete)
                    {
                        // Only the start was checked; keep the original framing for the rest.
                        if (responseFraming == Framing.UntilClose) closeAfter = true;
                    }
                    flow.BytesReceived = await SendAsync(clientStream, response, responseBody, response.Get("Content-Length") != null, ct);
                }
                else
                {
                    if (responseFraming == Framing.UntilClose) response.Set("Connection", "close");
                    await clientStream.WriteAsync(response.ToBytes(), ct);
                    var preview = new MemoryStream();
                    var writer = new BodyWriter(clientStream, responseFraming == Framing.Chunked);
                    await foreach (var piece in upstream.Reader.ReadBodyAsync(responseFraming, responseLength, ct))
                    {
                        if (preview.Length < Monitor.PreviewBytes) preview.Write(piece.Span[..(int)Math.Min(piece.Length, Monitor.PreviewBytes - preview.Length)]);
                        await writer.WriteAsync(piece, ct);
                        flow.BytesReceived += piece.Length;
                        if (streaming) await clientStream.FlushAsync(ct);
                    }
                    if (responseFraming != Framing.None) await writer.FinishAsync(ct);
                    else await clientStream.FlushAsync(ct);
                    flow.ResponseBody = HttpUtil.Decode(preview.ToArray(), response.Get("Content-Encoding"), Monitor.PreviewBytes);
                }

                flow.DurationMs = started.Elapsed.TotalMilliseconds;
                monitor.Complete(flow);

                if (upstreamCloses) { upstream.Dispose(); upstream = null; }
                if (closeAfter) return;
            }
        }
        finally
        {
            upstream?.Dispose();
        }
    }

    public void Dispose()
    {
        cts.Cancel();
        listener.Stop();
        transparent4?.Dispose();
        transparent6?.Dispose();
    }
}

/// <summary>A connection from the proxy to the real server.</summary>
sealed class Upstream : IDisposable
{
    readonly TcpClient tcp;
    public string Host { get; }
    public int Port { get; }
    public Stream Stream { get; }
    public HttpReader Reader { get; }
    public bool Closed => !tcp.Connected;

    Upstream(TcpClient tcp, Stream stream, string host, int port)
    {
        this.tcp = tcp;
        Stream = stream;
        Reader = new HttpReader(stream);
        Host = host;
        Port = port;
    }

    /// <summary>Connects; with <paramref name="tlsName"/> set, also does a normal, fully verified TLS handshake.</summary>
    public static async Task<Upstream> ConnectAsync(string host, int port, string? tlsName, CancellationToken ct)
    {
        var tcp = new TcpClient();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            await tcp.ConnectAsync(host, port, timeout.Token);
            tcp.NoDelay = true;
            Stream stream = tcp.GetStream();
            if (tlsName != null)
            {
                var ssl = new SslStream(stream, false);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = tlsName,
                    ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
                    CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                }, timeout.Token);
                stream = ssl;
            }
            return new Upstream(tcp, stream, host, port);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Stream.Dispose();
        tcp.Dispose();
    }
}
