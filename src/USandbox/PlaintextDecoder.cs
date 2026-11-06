using System.Text;

namespace USandbox;

/// <summary>
/// Turns the two decrypted byte streams of a connection into flow records: HTTP/1.1 exchanges,
/// HTTP/2 streams (frames + HPACK), or, for anything else, one record holding the raw bytes.
/// </summary>
static class PlaintextDecoder
{
    static readonly byte[] H2Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

    /// <summary>Adds the flows to the monitor and returns how many there were.</summary>
    public static int Emit(Monitor monitor, RuleSet rules, TlsRecording rec, byte[] client, byte[] server, string note)
    {
        var tunnel = rec.Flow;
        List<Flow> flows;
        try
        {
            flows = client.AsSpan().StartsWith(H2Preface) ? Http2(tunnel, rec.Name, client, server)
                  : LooksLikeHttp(client) ? Http1(tunnel, rec.Name, client, server)
                  : new List<Flow>();
        }
        catch (Exception e)
        {
            flows = new List<Flow>();
            note += $" Could not parse the decrypted data as HTTP: {e.Message}.";
        }
        if (flows.Count == 0) flows.Add(Raw(tunnel, rec.Name, client, server));

        foreach (var flow in flows)
        {
            flow.Note = flow.Note == null ? note : $"{note} {flow.Note}";
            if (flow.Method != null && flow.Url != null)
            {
                var match = rules.MatchMessage(flow.Host, flow.Method, flow.Url, flow.RequestHeaders ?? "", () => HttpUtil.Text(flow.RequestBody ?? Array.Empty<byte>()));
                if (match == null && flow.ResponseHeaders != null)
                    match = rules.MatchMessage(flow.Host, flow.Method, flow.Url, flow.RequestHeaders ?? "", () => HttpUtil.Text(flow.RequestBody ?? Array.Empty<byte>()),
                        flow.ResponseHeaders, () => HttpUtil.Text(flow.ResponseBody ?? Array.Empty<byte>()));
                if (match != null)
                {
                    flow.Rule = match.Describe();
                    if (match.Action == "block") flow.Note += " A block rule matches this request, but it was not stopped.";
                }
            }
            flow.Outcome = "allowed";
            monitor.Add(flow);
            monitor.Complete(flow);
        }
        return flows.Count;
    }

    static Flow NewFlow(Flow tunnel, string name) => new()
    {
        Time = tunnel.Time, Kind = "https", Pid = tunnel.Pid, Process = tunnel.Process, Host = name, Port = tunnel.Port,
    };

    static string Authority(string name, int port) => port == 443 ? name : $"{name}:{port}";

    static bool LooksLikeHttp(byte[] data)
    {
        int i = 0;
        while (i < data.Length && i < 10 && data[i] is >= (byte)'A' and <= (byte)'Z') i++;
        return i >= 3 && i < data.Length && data[i] == ' ';
    }

    static Flow Raw(Flow tunnel, string name, byte[] client, byte[] server)
    {
        var flow = NewFlow(tunnel, name);
        flow.Kind = "tls-data";
        flow.Url = $"tls://{Authority(name, tunnel.Port)}";
        flow.BytesSent = client.Length;
        flow.BytesReceived = server.Length;
        flow.RequestBody = Monitor.Preview(client);
        flow.ResponseBody = Monitor.Preview(server);
        flow.Note = "Not HTTP; the decrypted bytes are shown as they are.";
        return flow;
    }

    // ---- HTTP/1.1 --------------------------------------------------------------------------------

    static List<Flow> Http1(Flow tunnel, string name, byte[] client, byte[] server)
    {
        var flows = new List<Flow>();
        var requests = new HttpReader(new MemoryStream(client));
        var responses = new HttpReader(new MemoryStream(server));
        var ct = CancellationToken.None;
        while (true)
        {
            HttpHead? request;
            try { request = requests.ReadHeadAsync(ct).GetAwaiter().GetResult(); }
            catch (IOException) { break; }
            if (request == null) break;

            var flow = NewFlow(tunnel, name);
            flow.Method = request.Method;
            string host = request.Get("Host") ?? Authority(name, tunnel.Port);
            flow.Url = request.Target.StartsWith('/') ? $"https://{host}{request.Target}" : request.Target;
            flow.RequestHeaders = request.HeaderText();
            var (rf, rl) = HttpUtil.RequestFraming(request);
            var body = ReadBody(requests, rf, rl, out long sent);
            flow.BytesSent = sent;
            flow.RequestBody = Monitor.Preview(HttpUtil.Decode(body, request.Get("Content-Encoding"), Monitor.PreviewBytes));
            flows.Add(flow);

            HttpHead? response = null;
            try
            {
                do response = responses.ReadHeadAsync(ct).GetAwaiter().GetResult();
                while (response != null && response.Status is >= 100 and < 200 and not 101);
            }
            catch (IOException) { }
            if (response == null) { flow.Note = "No response was recorded."; continue; }
            flow.Status = response.Status;
            flow.ResponseHeaders = response.HeaderText();
            flow.ContentType = response.Get("Content-Type");
            if (response.Status == 101) { flow.Kind = "websocket"; break; }
            var (sf, sl) = HttpUtil.ResponseFraming(response, request.Method);
            var responseBody = ReadBody(responses, sf, sl, out long received);
            flow.BytesReceived = received;
            flow.ResponseBody = Monitor.Preview(HttpUtil.Decode(responseBody, response.Get("Content-Encoding"), Monitor.PreviewBytes));
        }
        return flows;
    }

    static byte[] ReadBody(HttpReader reader, Framing framing, long length, out long total)
    {
        total = 0;
        var data = new MemoryStream();
        if (framing == Framing.None) return Array.Empty<byte>();
        try
        {
            var e = reader.ReadBodyAsync(framing, length, CancellationToken.None).GetAsyncEnumerator();
            while (e.MoveNextAsync().AsTask().GetAwaiter().GetResult())
            {
                total += e.Current.Length;
                if (data.Length < Monitor.PreviewBytes) data.Write(e.Current.Span);
            }
        }
        catch (IOException) { }   // the recording ended inside the body
        return data.ToArray();
    }

    // ---- HTTP/2 ----------------------------------------------------------------------------------

    sealed class H2Stream
    {
        public readonly List<(string Name, string Value)> RequestHeaders = new(), ResponseHeaders = new();
        public readonly MemoryStream RequestBody = new(), ResponseBody = new();
        public long Sent, Received;
    }

    static List<Flow> Http2(Flow tunnel, string name, byte[] client, byte[] server)
    {
        var streams = new SortedDictionary<int, H2Stream>();
        H2Stream Get(int id) => streams.TryGetValue(id, out var s) ? s : streams[id] = new H2Stream();
        ReadFrames(client.AsSpan(H2Preface.Length).ToArray(), new Hpack(), true, Get);
        ReadFrames(server, new Hpack(), false, Get);

        var flows = new List<Flow>();
        foreach (var (id, s) in streams)
        {
            if (s.RequestHeaders.Count == 0) continue;
            string? H(List<(string Name, string Value)> list, string key) => list.FirstOrDefault(h => h.Name == key).Value;
            var flow = NewFlow(tunnel, name);
            flow.Method = H(s.RequestHeaders, ":method") ?? "?";
            string authority = H(s.RequestHeaders, ":authority") ?? Authority(name, tunnel.Port);
            flow.Url = $"{H(s.RequestHeaders, ":scheme") ?? "https"}://{authority}{H(s.RequestHeaders, ":path") ?? ""}";
            flow.RequestHeaders = $"{flow.Method} {H(s.RequestHeaders, ":path")} HTTP/2\r\n" +
                string.Concat(s.RequestHeaders.Where(h => !h.Name.StartsWith(':')).Select(h => $"{h.Name}: {h.Value}\r\n"));
            flow.RequestBody = Monitor.Preview(HttpUtil.Decode(s.RequestBody.ToArray(), H(s.RequestHeaders, "content-encoding"), Monitor.PreviewBytes));
            flow.BytesSent = s.Sent;
            if (int.TryParse(H(s.ResponseHeaders, ":status"), out int status))
            {
                flow.Status = status;
                flow.ResponseHeaders = $"HTTP/2 {status}\r\n" +
                    string.Concat(s.ResponseHeaders.Where(h => !h.Name.StartsWith(':')).Select(h => $"{h.Name}: {h.Value}\r\n"));
                flow.ContentType = H(s.ResponseHeaders, "content-type");
                flow.ResponseBody = Monitor.Preview(HttpUtil.Decode(s.ResponseBody.ToArray(), H(s.ResponseHeaders, "content-encoding"), Monitor.PreviewBytes));
                flow.BytesReceived = s.Received;
            }
            else flow.Note = "No response was recorded.";
            flow.Note = (flow.Note == null ? "" : flow.Note + " ") + $"HTTP/2 stream {id}.";
            flows.Add(flow);
        }
        return flows;
    }

    static void ReadFrames(byte[] data, Hpack hpack, bool fromClient, Func<int, H2Stream> get)
    {
        int pos = 0;
        var block = new MemoryStream();
        int blockStream = 0;
        while (pos + 9 <= data.Length)
        {
            int length = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
            byte type = data[pos + 3], flags = data[pos + 4];
            int id = ((data[pos + 5] & 0x7F) << 24) | (data[pos + 6] << 16) | (data[pos + 7] << 8) | data[pos + 8];
            if (pos + 9 + length > data.Length) break;
            var payload = data.AsSpan(pos + 9, length);
            pos += 9 + length;

            switch (type)
            {
                case 0: // DATA
                {
                    var body = Unpad(payload, flags);
                    var s = get(id);
                    if (fromClient) { s.Sent += body.Length; if (s.RequestBody.Length < Monitor.PreviewBytes) s.RequestBody.Write(body); }
                    else { s.Received += body.Length; if (s.ResponseBody.Length < Monitor.PreviewBytes) s.ResponseBody.Write(body); }
                    break;
                }
                case 1: // HEADERS
                {
                    var p = Unpad(payload, flags);
                    if ((flags & 0x20) != 0) p = p[5..];   // priority
                    block.SetLength(0);
                    block.Write(p);
                    blockStream = id;
                    if ((flags & 0x4) != 0) Headers(hpack, block, fromClient, get(id));
                    break;
                }
                case 9: // CONTINUATION
                    if (id != blockStream) break;
                    block.Write(payload);
                    if ((flags & 0x4) != 0) Headers(hpack, block, fromClient, get(id));
                    break;
                case 5: // PUSH_PROMISE: decode to keep the HPACK state right, then ignore
                {
                    var p = Unpad(payload, flags);
                    if (p.Length >= 4)
                    {
                        var promised = new H2Stream();
                        var tmp = new MemoryStream(p[4..].ToArray());
                        if ((flags & 0x4) != 0) Headers(hpack, tmp, false, promised);
                    }
                    break;
                }
            }
        }
    }

    static ReadOnlySpan<byte> Unpad(ReadOnlySpan<byte> payload, byte flags)
    {
        if ((flags & 0x8) == 0 || payload.Length == 0) return payload;
        int pad = payload[0];
        return pad + 1 > payload.Length ? ReadOnlySpan<byte>.Empty : payload[1..^pad];
    }

    static void Headers(Hpack hpack, MemoryStream block, bool fromClient, H2Stream s)
    {
        var fields = hpack.Decode(block.ToArray());
        var target = fromClient ? s.RequestHeaders : s.ResponseHeaders;
        // A second HEADERS block on a stream is trailers (or the final response after 1xx); keep the latest status.
        if (!fromClient && fields.Any(f => f.Name == ":status")) target.RemoveAll(h => h.Name == ":status");
        target.AddRange(fields);
    }

    /// <summary>HPACK decoder (RFC 7541), one per direction.</summary>
    sealed class Hpack
    {
        readonly List<(string Name, string Value)> dynamic = new();
        int size, maxSize = 4096;

        public List<(string Name, string Value)> Decode(byte[] b)
        {
            var result = new List<(string, string)>();
            int pos = 0;
            while (pos < b.Length)
            {
                byte first = b[pos];
                if ((first & 0x80) != 0)
                {
                    result.Add(Entry((int)Integer(b, ref pos, 7)));
                }
                else if ((first & 0x40) != 0)
                {
                    var f = Literal(b, ref pos, 6);
                    result.Add(f);
                    Insert(f);
                }
                else if ((first & 0x20) != 0)
                {
                    maxSize = (int)Integer(b, ref pos, 5);
                    Evict();
                }
                else
                {
                    result.Add(Literal(b, ref pos, 4));
                }
            }
            return result;
        }

        (string, string) Literal(byte[] b, ref int pos, int prefix)
        {
            int index = (int)Integer(b, ref pos, prefix);
            string name = index == 0 ? String(b, ref pos) : Entry(index).Name;
            return (name, String(b, ref pos));
        }

        (string Name, string Value) Entry(int index)
        {
            if (index >= 1 && index <= HpackTables.Static.Length) return HpackTables.Static[index - 1];
            int d = index - HpackTables.Static.Length - 1;
            return d >= 0 && d < dynamic.Count ? dynamic[d] : ("?", "?");
        }

        void Insert((string Name, string Value) f)
        {
            dynamic.Insert(0, f);
            size += f.Name.Length + f.Value.Length + 32;
            Evict();
        }

        void Evict()
        {
            while (size > maxSize && dynamic.Count > 0)
            {
                var last = dynamic[^1];
                dynamic.RemoveAt(dynamic.Count - 1);
                size -= last.Name.Length + last.Value.Length + 32;
            }
        }

        static long Integer(byte[] b, ref int pos, int prefix)
        {
            int mask = (1 << prefix) - 1;
            long value = b[pos++] & mask;
            if (value < mask) return value;
            int shift = 0;
            while (pos < b.Length)
            {
                byte next = b[pos++];
                value += (long)(next & 0x7F) << shift;
                shift += 7;
                if ((next & 0x80) == 0) break;
            }
            return value;
        }

        static string String(byte[] b, ref int pos)
        {
            bool huffman = (b[pos] & 0x80) != 0;
            int length = (int)Integer(b, ref pos, 7);
            var raw = b.AsSpan(pos, Math.Min(length, b.Length - pos));
            pos += length;
            return huffman ? Huffman.Decode(raw) : Encoding.Latin1.GetString(raw);
        }
    }

    static class Huffman
    {
        // Decoding tree: node i has children Tree[2i] / Tree[2i+1]; a value below zero is a leaf (~symbol).
        static readonly int[] Tree = Build();

        static int[] Build()
        {
            var tree = new List<int> { 0, 0 };
            int nodes = 1;
            for (int sym = 0; sym < 256; sym++)
            {
                uint code = HpackTables.Codes[sym];
                int len = HpackTables.Lengths[sym], node = 0;
                for (int i = len - 1; i >= 0; i--)
                {
                    int bit = (int)((code >> i) & 1);
                    int slot = 2 * node + bit;
                    if (i == 0) { tree[slot] = ~sym; break; }
                    if (tree[slot] == 0)
                    {
                        tree[slot] = nodes++;
                        tree.Add(0);
                        tree.Add(0);
                    }
                    node = tree[slot];
                }
            }
            return tree.ToArray();
        }

        public static string Decode(ReadOnlySpan<byte> data)
        {
            var sb = new StringBuilder();
            int node = 0;
            foreach (byte b in data)
            {
                for (int i = 7; i >= 0; i--)
                {
                    int next = Tree[2 * node + ((b >> i) & 1)];
                    if (next < 0) { sb.Append((char)~next); node = 0; }
                    else if (next == 0) return sb.ToString();
                    else node = next;
                }
            }
            return sb.ToString();   // trailing bits are the EOS padding
        }
    }
}
