using System.Buffers;
using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace USandbox;

/// <summary>Start line and headers of an HTTP/1.x message, kept in their original order and spelling.</summary>
sealed class HttpHead
{
    public string StartLine { get; set; } = "";
    public List<KeyValuePair<string, string>> Headers { get; } = new();

    string[] Parts => StartLine.Split(' ', 3);
    public string Method => Parts[0];
    public string Target => Parts.Length > 1 ? Parts[1] : "";
    public string RequestVersion => Parts.Length > 2 ? Parts[2] : "HTTP/1.0";
    public int Status => Parts.Length > 1 && int.TryParse(Parts[1], out int s) ? s : 0;
    public string ResponseVersion => Parts[0];

    public string? Get(string name)
    {
        foreach (var h in Headers) if (h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return h.Value;
        return null;
    }

    public bool HasToken(string name, string token) =>
        Headers.Any(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase) &&
                         h.Value.Split(',').Any(v => v.Trim().Equals(token, StringComparison.OrdinalIgnoreCase)));

    public void Remove(string name) => Headers.RemoveAll(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase));

    public void Set(string name, string value)
    {
        int i = Headers.FindIndex(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (i < 0) { Headers.Add(new(name, value)); return; }
        Headers[i] = new(Headers[i].Key, value);
        for (int j = Headers.Count - 1; j > i; j--)
            if (Headers[j].Key.Equals(name, StringComparison.OrdinalIgnoreCase)) Headers.RemoveAt(j);
    }

    public string HeaderText()
    {
        var sb = new StringBuilder(StartLine).Append("\r\n");
        foreach (var h in Headers) sb.Append(h.Key).Append(": ").Append(h.Value).Append("\r\n");
        return sb.ToString();
    }

    public byte[] ToBytes() => Encoding.Latin1.GetBytes(HeaderText() + "\r\n");
}

enum Framing { None, Length, Chunked, UntilClose }

/// <summary>Buffered reader over a connection, able to read HTTP heads and bodies.</summary>
sealed class HttpReader
{
    const int MaxHead = 256 * 1024;
    readonly Stream stream;
    byte[] buffer = new byte[16 * 1024];
    int start, end;

    public HttpReader(Stream stream) => this.stream = stream;

    public Stream BaseStream => stream;

    /// <summary>Bytes read from the connection but not consumed yet.</summary>
    public ReadOnlyMemory<byte> Buffered => buffer.AsMemory(start, end - start);

    public byte[] TakeBuffered()
    {
        var data = Buffered.ToArray();
        start = end = 0;
        return data;
    }

    async ValueTask<bool> FillAsync(CancellationToken ct)
    {
        if (start > 0 && start == end) start = end = 0;
        if (end == buffer.Length)
        {
            if (start > 0) { Buffer.BlockCopy(buffer, start, buffer, 0, end - start); end -= start; start = 0; }
            else Array.Resize(ref buffer, buffer.Length * 2);
        }
        int n = await stream.ReadAsync(buffer.AsMemory(end), ct);
        end += n;
        return n > 0;
    }

    /// <summary>Waits for at least <paramref name="count"/> buffered bytes; false if the connection ends first.</summary>
    public async ValueTask<bool> EnsureAsync(int count, CancellationToken ct)
    {
        while (end - start < count)
        {
            if (!await FillAsync(ct)) return false;
        }
        return true;
    }

    /// <summary>Reads a request or response head. Null when the connection closes before a new message starts.</summary>
    public async Task<HttpHead?> ReadHeadAsync(CancellationToken ct)
    {
        // How far past `start` has already been searched. Relative, because FillAsync may move the data.
        int scanned = 0;
        while (true)
        {
            // Tolerate stray CRLFs between messages.
            while (end - start >= 2 && buffer[start] == '\r' && buffer[start + 1] == '\n') { start += 2; scanned = 0; }
            int from = start + scanned;
            int idx = buffer.AsSpan(from, end - from).IndexOf("\r\n\r\n"u8);
            if (idx >= 0)
            {
                int headEnd = from + idx;
                string text = Encoding.Latin1.GetString(buffer, start, headEnd - start);
                start = headEnd + 4;
                return Parse(text);
            }
            scanned = Math.Max(0, end - start - 3);
            if (end - start > MaxHead) throw new IOException("HTTP head too large.");
            if (!await FillAsync(ct))
            {
                if (end == start) return null;
                throw new IOException("Connection closed in the middle of an HTTP head.");
            }
        }
    }

    static HttpHead Parse(string text)
    {
        var lines = text.Split("\r\n");
        var head = new HttpHead { StartLine = lines[0] };
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            if (line.Length > 0 && (line[0] == ' ' || line[0] == '\t') && head.Headers.Count > 0)
            {
                var last = head.Headers[^1];
                head.Headers[^1] = new(last.Key, last.Value + " " + line.Trim());
                continue;
            }
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            head.Headers.Add(new(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }
        return head;
    }

    public async ValueTask<int> ReadAsync(Memory<byte> into, CancellationToken ct)
    {
        if (end > start)
        {
            int n = Math.Min(into.Length, end - start);
            buffer.AsMemory(start, n).CopyTo(into);
            start += n;
            return n;
        }
        return await stream.ReadAsync(into, ct);
    }

    async Task<string> ReadLineAsync(CancellationToken ct)
    {
        while (true)
        {
            int idx = buffer.AsSpan(start, end - start).IndexOf("\r\n"u8);
            if (idx >= 0)
            {
                string line = Encoding.Latin1.GetString(buffer, start, idx);
                start += idx + 2;
                return line;
            }
            if (end - start > 64 * 1024) throw new IOException("Line too long.");
            if (!await FillAsync(ct)) throw new IOException("Connection closed in the middle of a chunked body.");
        }
    }

    /// <summary>Yields the decoded body of a message piece by piece.</summary>
    public async IAsyncEnumerable<ReadOnlyMemory<byte>> ReadBodyAsync(Framing framing, long length,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var chunk = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            switch (framing)
            {
                case Framing.Length:
                    for (long left = length; left > 0;)
                    {
                        int n = await ReadAsync(chunk.AsMemory(0, (int)Math.Min(chunk.Length, left)), ct);
                        if (n == 0) throw new IOException("Connection closed before the whole body arrived.");
                        left -= n;
                        yield return chunk.AsMemory(0, n);
                    }
                    break;

                case Framing.UntilClose:
                    while (true)
                    {
                        int n = await ReadAsync(chunk, ct);
                        if (n == 0) break;
                        yield return chunk.AsMemory(0, n);
                    }
                    break;

                case Framing.Chunked:
                    while (true)
                    {
                        string sizeLine = await ReadLineAsync(ct);
                        int semi = sizeLine.IndexOf(';');
                        if (semi >= 0) sizeLine = sizeLine[..semi];
                        if (!long.TryParse(sizeLine.Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long size) || size < 0)
                            throw new IOException($"Bad chunk size \"{sizeLine}\".");
                        if (size == 0)
                        {
                            while ((await ReadLineAsync(ct)).Length > 0) { } // trailers are dropped
                            break;
                        }
                        for (long left = size; left > 0;)
                        {
                            int n = await ReadAsync(chunk.AsMemory(0, (int)Math.Min(chunk.Length, left)), ct);
                            if (n == 0) throw new IOException("Connection closed in the middle of a chunk.");
                            left -= n;
                            yield return chunk.AsMemory(0, n);
                        }
                        await ReadLineAsync(ct);
                    }
                    break;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunk);
        }
    }
}

/// <summary>Writes a message body with the given framing.</summary>
sealed class BodyWriter
{
    readonly Stream stream;
    readonly bool chunked;

    public BodyWriter(Stream stream, bool chunked) { this.stream = stream; this.chunked = chunked; }

    public async Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        if (data.Length == 0) return;
        if (chunked) await stream.WriteAsync(Encoding.ASCII.GetBytes($"{data.Length:x}\r\n"), ct);
        await stream.WriteAsync(data, ct);
        if (chunked) await stream.WriteAsync("\r\n"u8.ToArray(), ct);
    }

    public async Task FinishAsync(CancellationToken ct)
    {
        if (chunked) await stream.WriteAsync("0\r\n\r\n"u8.ToArray(), ct);
        await stream.FlushAsync(ct);
    }
}

static class HttpUtil
{
    public static (Framing, long) RequestFraming(HttpHead head)
    {
        if (head.Get("Transfer-Encoding") is { } te && te.Contains("chunked", StringComparison.OrdinalIgnoreCase)) return (Framing.Chunked, 0);
        if (long.TryParse(head.Get("Content-Length"), out long n) && n > 0) return (Framing.Length, n);
        return (Framing.None, 0);
    }

    public static (Framing, long) ResponseFraming(HttpHead head, string requestMethod)
    {
        int status = head.Status;
        if (requestMethod.Equals("HEAD", StringComparison.OrdinalIgnoreCase) || status is >= 100 and < 200 or 204 or 304) return (Framing.None, 0);
        if (head.Get("Transfer-Encoding") is { } te && te.Contains("chunked", StringComparison.OrdinalIgnoreCase)) return (Framing.Chunked, 0);
        if (long.TryParse(head.Get("Content-Length"), out long n)) return n > 0 ? (Framing.Length, n) : (Framing.None, 0);
        return (Framing.UntilClose, 0);
    }

    /// <summary>Undoes Content-Encoding so rules and previews see the real content. Returns the input if it cannot.</summary>
    public static byte[] Decode(byte[] body, string? contentEncoding, int limit)
    {
        if (string.IsNullOrWhiteSpace(contentEncoding) || body.Length == 0) return body;
        try
        {
            byte[] data = body;
            foreach (var enc in contentEncoding.Split(',').Select(e => e.Trim().ToLowerInvariant()).Reverse())
            {
                using var input = new MemoryStream(data);
                using Stream decoder = enc switch
                {
                    "gzip" or "x-gzip" => new GZipStream(input, CompressionMode.Decompress),
                    "deflate" => new ZLibStream(input, CompressionMode.Decompress),
                    "br" => new BrotliStream(input, CompressionMode.Decompress),
                    "identity" => input,
                    _ => throw new NotSupportedException(),
                };
                using var output = new MemoryStream();
                var buf = new byte[81920];
                int n;
                while ((n = decoder.Read(buf, 0, buf.Length)) > 0)
                {
                    output.Write(buf, 0, n);
                    if (output.Length > limit) break;
                }
                data = output.ToArray();
            }
            return data;
        }
        catch
        {
            return body;
        }
    }

    public static string Text(byte[] data) => Encoding.UTF8.GetString(data);

    public static byte[] SimpleResponse(int status, string reason, string body, bool close = true)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        var head = $"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {bytes.Length}\r\n" +
                   (close ? "Connection: close\r\n" : "") + "X-USandbox: 1\r\n\r\n";
        return [.. Encoding.ASCII.GetBytes(head), .. bytes];
    }
}

/// <summary>A stream that first returns some already-read bytes, then continues with the inner stream.</summary>
sealed class PrefixStream : Stream
{
    readonly Stream inner;
    byte[] prefix;
    int pos;

    public PrefixStream(byte[] prefix, Stream inner) { this.prefix = prefix; this.inner = inner; }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> span)
    {
        if (pos < prefix.Length)
        {
            int n = Math.Min(span.Length, prefix.Length - pos);
            prefix.AsSpan(pos, n).CopyTo(span);
            pos += n;
            return n;
        }
        return inner.Read(span);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> memory, CancellationToken ct = default)
    {
        if (pos < prefix.Length) return Read(memory.Span);
        return await inner.ReadAsync(memory, ct);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => inner.WriteAsync(buffer, ct);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => inner.WriteAsync(buffer, offset, count, ct);
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) inner.Dispose();
        base.Dispose(disposing);
    }
}

/// <summary>Reads the server name (SNI) and ALPN protocols from a TLS ClientHello.</summary>
static class TlsClientHello
{
    public static bool LooksLikeTls(ReadOnlySpan<byte> data) => data.Length >= 3 && data[0] == 0x16 && data[1] == 0x03;

    /// <summary>Total length of the first TLS record, or -1 when the header is incomplete.</summary>
    public static int RecordLength(ReadOnlySpan<byte> data) => data.Length < 5 ? -1 : 5 + ((data[3] << 8) | data[4]);

    public static (string? Sni, List<string> Alpn) Parse(ReadOnlySpan<byte> record)
    {
        string? sni = null;
        var alpn = new List<string>();
        try
        {
            var p = record[5..];                          // record header
            if (p[0] != 1) return (null, alpn);           // not a ClientHello
            p = p[4..];                                   // handshake header
            p = p[(2 + 32)..];                            // version + random
            p = p[(1 + p[0])..];                          // session id
            p = p[(2 + ((p[0] << 8) | p[1]))..];          // cipher suites
            p = p[(1 + p[0])..];                          // compression methods
            int extLen = (p[0] << 8) | p[1];
            p = p.Slice(2, Math.Min(extLen, p.Length - 2));
            while (p.Length >= 4)
            {
                int type = (p[0] << 8) | p[1], len = (p[2] << 8) | p[3];
                var ext = p.Slice(4, len);
                if (type == 0 && ext.Length > 5 && ext[2] == 0)
                {
                    int nameLen = (ext[3] << 8) | ext[4];
                    sni = Encoding.ASCII.GetString(ext.Slice(5, nameLen));
                }
                else if (type == 16 && ext.Length > 2)
                {
                    var list = ext[2..];
                    while (list.Length > 0)
                    {
                        int l = list[0];
                        alpn.Add(Encoding.ASCII.GetString(list.Slice(1, l)));
                        list = list[(1 + l)..];
                    }
                }
                p = p[(4 + len)..];
            }
        }
        catch (ArgumentOutOfRangeException)
        {
            // Truncated or odd hello; use what was found.
        }
        return (sni, alpn);
    }
}
