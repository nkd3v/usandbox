using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace USandbox;

/// <summary>One observed network exchange: an HTTP request, a tunnel, or a direct connection attempt.</summary>
sealed class Flow
{
    static long nextId;

    public long Id { get; } = Interlocked.Increment(ref nextId);
    public DateTime Time { get; init; } = DateTime.Now;

    /// <summary>http, https, tunnel, websocket, direct, listen or local.</summary>
    public string Kind { get; set; } = "http";

    public int? Pid { get; set; }
    public string? Process { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string? Method { get; set; }
    public string? Url { get; set; }
    public int? Status { get; set; }

    /// <summary>allowed, blocked, passthrough, error or pending.</summary>
    public string Outcome { get; set; } = "pending";
    public string? Rule { get; set; }
    public string? Note { get; set; }
    public string? ContentType { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public double? DurationMs { get; set; }

    /// <summary>How many identical events this flow stands for (repeated blocked attempts are merged).</summary>
    public int Count { get; set; } = 1;

    [JsonIgnore] public string? RequestHeaders { get; set; }
    [JsonIgnore] public byte[]? RequestBody { get; set; }
    [JsonIgnore] public string? ResponseHeaders { get; set; }
    [JsonIgnore] public byte[]? ResponseBody { get; set; }
}

record LogLine(DateTime Time, string Level, string Text);

/// <summary>Collects flows and log lines and hands them to whoever displays them (GUI or console).</summary>
sealed class Monitor : IDisposable
{
    public const int PreviewBytes = 256 * 1024;
    const int MaxFlows = 20000;

    readonly ConcurrentDictionary<long, Flow> flows = new();
    readonly ConcurrentQueue<long> order = new();
    readonly StreamWriter? jsonLog;
    readonly object logLock = new();

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Raised when a flow is created or changes.</summary>
    public event Action<Flow>? FlowChanged;
    /// <summary>Raised once per flow, when it is finished.</summary>
    public event Action<Flow>? FlowCompleted;
    public event Action<LogLine>? Logged;

    public Monitor(string? jsonLogPath)
    {
        if (jsonLogPath != null)
        {
            jsonLog = new StreamWriter(new FileStream(jsonLogPath, FileMode.Append, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        }
    }

    public Flow Add(Flow flow)
    {
        flows[flow.Id] = flow;
        order.Enqueue(flow.Id);
        while (order.Count > MaxFlows && order.TryDequeue(out long old)) flows.TryRemove(old, out _);
        FlowChanged?.Invoke(flow);
        return flow;
    }

    public void Update(Flow flow) => FlowChanged?.Invoke(flow);

    /// <summary>Marks a flow finished: updates displays and appends it to the JSON log.</summary>
    public void Complete(Flow flow)
    {
        if (flow.Outcome == "pending") flow.Outcome = "allowed";
        FlowChanged?.Invoke(flow);
        FlowCompleted?.Invoke(flow);
        if (jsonLog != null)
        {
            lock (logLock) jsonLog.WriteLine(JsonSerializer.Serialize(flow, Json));
        }
    }

    public Flow? Get(long id) => flows.TryGetValue(id, out var f) ? f : null;

    public void Info(string text) => Log("info", text);
    public void Warn(string text) => Log("warn", text);
    public void Error(string text) => Log("error", text);

    void Log(string level, string text) => Logged?.Invoke(new LogLine(DateTime.Now, level, text));

    public static byte[] Preview(ReadOnlySpan<byte> data) => data[..Math.Min(data.Length, PreviewBytes)].ToArray();

    public void Dispose() => jsonLog?.Dispose();
}
