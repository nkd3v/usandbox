using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace USandbox;

/// <summary>
/// Decrypts TLS that usandbox could not intercept (pinned certificates, private trust lists,
/// HTTP/2-only clients, or <c>--passive-tls</c>) using keys read from the program's own memory.
///
/// To speak TLS a program must hold its record keys for as long as a connection lives. When a
/// recorded connection starts sending application data, the program's address space is captured
/// (a copy-on-write clone through the Process Snapshotting API, so the program is not paused) and
/// scanned twice over:
///   1. for expanded AES key schedules, which every mainstream library keeps for AES-GCM
///      (OpenSSL, BoringSSL/ring/rustls, Go, Schannel/SymCrypt) even after it wiped the TLS secret,
///      and which are recognised from 176/240 self-consistent bytes. A raw AES key is then
///      confirmed against a recorded record by recovering the GCM nonce from its tag;
///   2. if that is not enough (ChaCha20 suites, unusual layouts), for TLS secrets: 32/48-byte
///      high-entropy windows tried as TLS 1.3 traffic secrets or the TLS 1.2 master secret.
/// A key is only accepted when it authenticates a recorded record (the AEAD tag), so there are no
/// false positives. Nothing is injected into the program and it is never modified.
///
/// This observes; it cannot block. Records are decrypted after they have been forwarded.
/// </summary>
sealed class KeyExtractor : IDisposable
{
    const int MaxAttempts = 4;
    const long MaxScanBytes = 4L << 30;
    const int ChunkSize = 16 << 20, Overlap = 256;
    const int MaxSecretCandidates = 4_000_000;
    static readonly TimeSpan SecretScanBudget = TimeSpan.FromSeconds(45);

    readonly Monitor monitor;
    readonly Func<RuleSet> rules;
    readonly object gate = new();
    readonly Dictionary<TlsRecording, State> states = new();
    readonly AutoResetEvent wake = new(false);
    readonly Thread worker;
    volatile bool stopping;

    sealed class State
    {
        public int Attempts;
        public DateTime? Due;
        public bool Emitted;
        public readonly Keys Client = new(), Server = new();
        public readonly List<string> Methods = new();
        public readonly List<ProcessMemory> Captured = new();
        public string? LastError;
    }

    int pendingClones;
    const int MaxPendingClones = 16;

    /// <summary>Keys found for one direction of one connection.</summary>
    sealed class Keys
    {
        public readonly List<byte[]> Aes = new();                                   // nonce recovered per record
        public readonly List<(TlsCrypto.RecordKey Key, int Start)> Sequenced = new(); // seq counted from record Start (1.3) or from CCS (1.2)
        public bool Any => Aes.Count > 0 || Sequenced.Count > 0;
    }

    public KeyExtractor(Monitor monitor, Func<RuleSet> rules)
    {
        this.monitor = monitor;
        this.rules = rules;
        worker = new Thread(Run) { IsBackground = true, Name = "usandbox key extractor", Priority = ThreadPriority.BelowNormal };
        worker.Start();
    }

    /// <summary>Enables SeDebugPrivilege, which reading another account's process needs. False when it could not be enabled.</summary>
    public static bool EnableDebugPrivilege() => Native.EnablePrivilege("SeDebugPrivilege");

    /// <summary>
    /// The program has started sending application data, so its traffic keys are in memory right
    /// now: capture a copy-on-write clone of its address space. The returned task completes as soon
    /// as the clone exists (typically tens of milliseconds); scanning happens later, on the clone.
    /// The proxy holds back the program's first application record until then, which guarantees
    /// the keys are captured even from programs that exit right after their request.
    /// </summary>
    public Task CaptureAsync(TlsRecording rec) => Task.Run(() =>
    {
        State state;
        lock (gate)
        {
            if (!states.TryGetValue(rec, out state!)) states[rec] = state = new State();
            if (pendingClones >= MaxPendingClones || rec.Pid is not int) { state.Due = DateTime.UtcNow; wake.Set(); return; }
            pendingClones++;
        }
        var memory = ProcessMemory.Open(rec.Pid!.Value, out string? error);
        lock (gate)
        {
            if (memory != null) state.Captured.Add(memory);
            else { pendingClones--; state.LastError = $"could not read the memory of PID {rec.Pid}: {error}"; }
            state.Due = DateTime.UtcNow;
        }
        wake.Set();
    });

    /// <summary>The connection ended: decrypt what was recorded (after one last look for keys if needed).</summary>
    public void Closed(TlsRecording recording)
    {
        recording.Closed = true;
        lock (gate)
        {
            if (!states.TryGetValue(recording, out var s))
            {
                if (recording.Client.Encrypted.Count == 0 && recording.Server.Encrypted.Count == 0) return;
                states[recording] = s = new State();
            }
            s.Due = DateTime.UtcNow;
        }
        wake.Set();
    }

    void Schedule(TlsRecording r, TimeSpan delay)
    {
        lock (gate)
        {
            if (!states.TryGetValue(r, out var s)) states[r] = s = new State();
            s.Due = DateTime.UtcNow + delay;
        }
        wake.Set();
    }

    void Run()
    {
        while (!stopping)
        {
            TimeSpan wait = TimeSpan.FromSeconds(1);
            List<(TlsRecording Rec, State State)> due;
            lock (gate)
            {
                var now = DateTime.UtcNow;
                due = states.Where(kv => kv.Value.Due is DateTime d && d <= now && !kv.Value.Emitted).Select(kv => (kv.Key, kv.Value)).ToList();
                var next = states.Values.Where(s => s.Due is DateTime d && d > now && !s.Emitted).Select(s => s.Due!.Value).DefaultIfEmpty(now + wait).Min();
                wait = next - now;
                foreach (var (_, s) in due) s.Due = null;
            }
            if (due.Count == 0)
            {
                wake.WaitOne(wait < TimeSpan.Zero ? TimeSpan.Zero : wait > TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : wait);
                continue;
            }
            Thread.Sleep(30); // let connections that started together be handled by one snapshot
            try { Process(due); }
            catch (Exception e) { monitor.Error($"Key extraction failed: {e}"); }
        }
    }

    void Process(List<(TlsRecording Rec, State State)> due)
    {
        foreach (var group in due.GroupBy(d => d.Rec.Pid))
        {
            var needKeys = group.Where(d => !Resolved(d.Rec, d.State) && d.State.Attempts < MaxAttempts).ToList();
            if (group.Key is int pid && needKeys.Count > 0)
            {
                foreach (var d in needKeys) d.State.Attempts++;
                Attempt(pid, needKeys);
            }
            foreach (var (rec, state) in group)
            {
                bool resolved = Resolved(rec, state);
                if (rec.Closed || (state.Attempts >= MaxAttempts && rec.Closed))
                {
                    Emit(rec, state);
                    lock (gate)
                    {
                        state.Emitted = true;
                        states.Remove(rec);
                        foreach (var m in state.Captured) m.Dispose();
                        pendingClones -= state.Captured.Count;
                        state.Captured.Clear();
                    }
                }
                else if (!resolved && state.Attempts < MaxAttempts)
                {
                    // Keys may not be in memory yet (or were missed); look again while the connection lives.
                    Schedule(rec, TimeSpan.FromMilliseconds(400 * state.Attempts * state.Attempts));
                }
            }
        }
    }

    // ---- finding keys ----------------------------------------------------------------------------

    void Attempt(int pid, List<(TlsRecording Rec, State State)> items)
    {
        // Clones captured when the connections started sending data, or a fresh look now.
        var memories = new List<ProcessMemory>();
        lock (gate)
        {
            foreach (var (_, s) in items)
            {
                memories.AddRange(s.Captured);
                pendingClones -= s.Captured.Count;
                s.Captured.Clear();
            }
        }
        if (memories.Count == 0)
        {
            var fresh = ProcessMemory.Open(pid, out string? error);
            if (fresh == null)
            {
                foreach (var (_, s) in items) s.LastError ??= $"could not read the memory of PID {pid}: {error}";
                return;
            }
            memories.Add(fresh);
        }
        foreach (var memory in memories)
        {
            using (memory)
            {
                if (items.All(i => Resolved(i.Rec, i.State))) continue;
                Attempt(pid, items, memory);
            }
        }
    }

    void Attempt(int pid, List<(TlsRecording Rec, State State)> items, ProcessMemory memory)
    {
        var started = Stopwatch.StartNew();

        // Pass 1: AES key schedules (fast, and works for every library that keeps its expanded key).
        var aesKeys = new HashSet<KeyBytes>();
        long scanned = memory.Scan((chunk, _) => TlsCrypto.FindAesSchedules(chunk, aesKeys));
        foreach (var (rec, state) in items)
        {
            lock (rec.Gate)
            {
                MatchAes(rec, rec.Client, state.Client, aesKeys);
                MatchAes(rec, rec.Server, state.Server, aesKeys);
                if (state.Client.Aes.Count + state.Server.Aes.Count > 0 && !state.Methods.Contains("AES key schedule")) state.Methods.Add("AES key schedule");
            }
        }

        // Pass 2: TLS secrets, only for connections pass 1 could not resolve.
        var rest = items.Where(i => !Resolved(i.Rec, i.State) && i.Rec.Suite != null && (i.Rec.Tls13 || i.Rec.ClientRandom != null && i.Rec.ServerRandom != null)).ToList();
        if (rest.Count > 0) ScanSecrets(memory, rest);

        foreach (var (rec, state) in items)
            if (!Resolved(rec, state))
                state.LastError = $"no key in {scanned / (1024 * 1024)} MB of memory of PID {pid} opened its records " +
                                  $"({aesKeys.Count} AES key schedule(s) found; {rec.Suite?.Name ?? $"suite 0x{rec.SuiteId:X4}"})";
        Debug.WriteLine($"key scan of {pid}: {scanned} bytes, {aesKeys.Count} aes keys, {started.ElapsedMilliseconds} ms");
    }

    static IEnumerable<int> TestIndexes(TlsRecording.Direction d)
    {
        var e = d.Encrypted;
        var picked = new HashSet<int>();
        for (int i = 0; i < Math.Min(6, e.Count); i++) picked.Add(i);
        foreach (var i in Enumerable.Range(0, e.Count).OrderBy(i => e[i].Record.Payload.Length).Take(3)) picked.Add(i);
        if (e.Count > 0) picked.Add(e.Count - 1);
        return picked.OrderBy(i => i);
    }

    static void MatchAes(TlsRecording rec, TlsRecording.Direction d, Keys keys, HashSet<KeyBytes> candidates)
    {
        int keyLength = rec.Suite?.KeyLength ?? 0;
        if (rec.Suite is { Aead: not AeadKind.AesGcm }) return;
        foreach (int i in TestIndexes(d))
        {
            var (record, seq, _) = d.Encrypted[i];
            if (Opens(rec, d, keys, i)) continue;
            foreach (var candidate in candidates)
            {
                if (keyLength != 0 && candidate.Value.Length != keyLength) continue;
                if (TlsCrypto.RecoverGcmNonce(candidate.Value, record, rec.Tls13, seq) != null)
                {
                    if (!keys.Aes.Any(k => k.AsSpan().SequenceEqual(candidate.Value))) keys.Aes.Add(candidate.Value);
                    break;
                }
            }
        }
    }

    void ScanSecrets(ProcessMemory memory, List<(TlsRecording Rec, State State)> items)
    {
        var deadline = Stopwatch.StartNew();
        var seen = new HashSet<KeyBytes>();
        bool want32 = items.Any(i => i.Rec.Tls13 && i.Rec.Suite!.HashLength == 32);
        bool want48 = items.Any(i => !i.Rec.Tls13 || i.Rec.Suite!.HashLength == 48);
        int tried = 0;
        memory.Scan((chunk, _) =>
        {
            if (tried > MaxSecretCandidates || deadline.Elapsed > SecretScanBudget) return;
            for (int o = 0; o + 32 <= chunk.Length; o += 4)
            {
                var w = chunk.Slice(o);
                if (want32 && LooksRandom(w[..32], 24)) Try(w[..32].ToArray());
                if (want48 && o + 48 <= chunk.Length && LooksRandom(w[..48], 36)) Try(w[..48].ToArray());
                if ((o & 0xFFFF) == 0 && (tried > MaxSecretCandidates || deadline.Elapsed > SecretScanBudget)) return;
            }
        });

        void Try(byte[] secret)
        {
            if (!seen.Add(new KeyBytes(secret))) return;
            tried++;
            foreach (var (rec, state) in items)
            {
                if (Resolved(rec, state)) continue;
                var suite = rec.Suite!;
                lock (rec.Gate)
                {
                    if (rec.Tls13)
                    {
                        if (secret.Length != suite.HashLength) continue;
                        var key = TlsCrypto.FromTrafficSecret(suite, secret);
                        TrySequenced(rec.Client, state.Client, key, ClientStarts(rec));
                        TrySequenced(rec.Server, state.Server, key, ServerStarts(rec));
                    }
                    else
                    {
                        if (secret.Length != 48 || rec.Client.Encrypted.Count == 0) continue;
                        var (client, server) = TlsCrypto.FromMasterSecret(suite, secret, rec.ClientRandom!, rec.ServerRandom!);
                        var first = rec.Client.Encrypted[0];
                        if (!TlsCrypto.Verifies(client, first.Record, first.Seq12)) continue;
                        state.Client.Sequenced.Add((client, 0));
                        state.Server.Sequenced.Add((server, 0));
                    }
                    if (!state.Methods.Contains("TLS secret")) state.Methods.Add("TLS secret");
                }
            }
        }
    }

    static void TrySequenced(TlsRecording.Direction d, Keys keys, TlsCrypto.RecordKey key, IEnumerable<int> starts)
    {
        foreach (int start in starts)
        {
            if (start >= d.Encrypted.Count) continue;
            if (TlsCrypto.Verifies(key, d.Encrypted[start].Record, 0))
            {
                keys.Sequenced.Add((key, start));
                return;
            }
        }
    }

    /// <summary>TLS 1.3: where the client's application records probably start (after its Finished).</summary>
    static IEnumerable<int> ClientStarts(TlsRecording r) => new[] { 1, 0, 2 };

    /// <summary>TLS 1.3: the server's first application record follows the client's Finished.</summary>
    static IEnumerable<int> ServerStarts(TlsRecording r)
    {
        var starts = new List<int>();
        if (r.Client.Encrypted.Count > 0)
        {
            long after = r.Client.Encrypted[0].Order;
            int i = r.Server.Encrypted.FindIndex(e => e.Order > after);
            if (i >= 0) starts.Add(i);
        }
        // Some servers (Go, for one) send session tickets under the application key straight after
        // their own Finished, before the client's Finished arrives, so try the first few records too.
        for (int i = 0; i < Math.Min(8, r.Server.Encrypted.Count); i++) starts.Add(i);
        return starts.Distinct();
    }

    static bool LooksRandom(ReadOnlySpan<byte> w, int minDistinct)
    {
        Span<ulong> seen = stackalloc ulong[4];
        int distinct = 0, zeros = 0;
        foreach (byte b in w)
        {
            if (b == 0 && ++zeros > 3) return false;
            ref ulong word = ref seen[b >> 6];
            ulong bit = 1UL << (b & 63);
            if ((word & bit) == 0) { word |= bit; distinct++; }
        }
        return distinct >= minDistinct;
    }

    // ---- decrypting ------------------------------------------------------------------------------

    static bool Resolved(TlsRecording rec, State state)
    {
        lock (rec.Gate)
        {
            return DirectionResolved(rec, rec.Client, state.Client) && DirectionResolved(rec, rec.Server, state.Server);
        }
    }

    static bool DirectionResolved(TlsRecording rec, TlsRecording.Direction d, Keys keys) =>
        d.Encrypted.Count == 0 || (keys.Any && Opens(rec, d, keys, d.Encrypted.Count - 1));

    static bool Opens(TlsRecording rec, TlsRecording.Direction d, Keys keys, int index) => Decrypt(rec, d, keys, index) != null;

    /// <summary>Opens record <paramref name="index"/> of direction <paramref name="d"/> with the keys found for it.</summary>
    static byte[]? Decrypt(TlsRecording rec, TlsRecording.Direction d, Keys keys, int index)
    {
        if (index >= d.Encrypted.Count) return null;
        var (record, seq12, _) = d.Encrypted[index];
        var layoutSuite = rec.Suite ?? TlsSuite.Find(rec.Tls13 ? (ushort)0x1301 : (ushort)0xC02F)!;
        foreach (var aes in keys.Aes)
        {
            var nonce = TlsCrypto.RecoverGcmNonce(aes, record, rec.Tls13, seq12);
            if (nonce == null) continue;
            var key = new TlsCrypto.RecordKey(layoutSuite with { Aead = AeadKind.AesGcm, KeyLength = aes.Length, IvLength = 12 }, aes, nonce);
            var plain = TlsCrypto.Open(key, record, rec.Tls13 ? 0 : seq12);
            if (plain != null) return plain;
        }
        foreach (var (key, start) in keys.Sequenced)
        {
            if (key.Suite.Tls13)
            {
                if (index < start) continue;
                var plain = TlsCrypto.Open(key, record, (ulong)(index - start));
                if (plain != null) return plain;
            }
            else
            {
                var plain = TlsCrypto.Open(key, record, seq12);
                if (plain != null) return plain;
            }
        }
        return null;
    }

    /// <summary>The application data of one direction, and how many records could not be opened.</summary>
    static (byte[] Data, int Opened, int Failed) Stream(TlsRecording rec, TlsRecording.Direction d, Keys keys)
    {
        var data = new MemoryStream();
        int opened = 0, failed = 0;
        for (int i = 0; i < d.Encrypted.Count; i++)
        {
            var plain = Decrypt(rec, d, keys, i);
            if (plain == null) { failed++; continue; }
            opened++;
            byte type = d.Encrypted[i].Record.Type;
            int length = plain.Length;
            if (rec.Tls13)
            {
                // TLSInnerPlaintext: content, then the real content type, then zero padding.
                while (length > 0 && plain[length - 1] == 0) length--;
                if (length == 0) continue;
                type = plain[length - 1];
                length--;
            }
            if (type == 23) data.Write(plain, 0, length);
        }
        return (data.ToArray(), opened, failed);
    }

    void Emit(TlsRecording rec, State state)
    {
        byte[] client, server;
        int opened, failed;
        lock (rec.Gate)
        {
            var c = Stream(rec, rec.Client, state.Client);
            var s = Stream(rec, rec.Server, state.Server);
            client = c.Data;
            server = s.Data;
            opened = c.Opened + s.Opened;
            failed = c.Failed + s.Failed;
        }

        var tunnel = rec.Flow;
        string what = $"{rec.Version}, {rec.Suite?.Name ?? $"suite 0x{rec.SuiteId:X4}"}";
        if (opened == 0)
        {
            string why = state.LastError ?? (rec.Suite == null ? $"unsupported cipher suite 0x{rec.SuiteId:X4}" : "the program never sent application data");
            tunnel.Note = Append(tunnel.Note, $"keys not recovered from memory: {why}");
            monitor.Update(tunnel);
            monitor.Warn($"TLS to {rec.Name}:{tunnel.Port} from {tunnel.Process ?? "?"} was not decrypted: {why}.");
            return;
        }

        int count = PlaintextDecoder.Emit(monitor, rules(), rec, client, server,
            $"Decrypted with keys found in the program's memory ({string.Join(" + ", state.Methods)}; {what}). " +
            "Observed only: the connection was passed through, so it could not be blocked.");
        tunnel.Note = Append(tunnel.Note,
            $"decrypted with keys from memory ({string.Join(" + ", state.Methods)}): {count} message(s)" +
            (failed > 0 ? $", {failed} record(s) not opened (handshake records or rotated keys)" : "") +
            (rec.Truncated ? "; recording was truncated" : ""));
        monitor.Update(tunnel);
    }

    static string Append(string? note, string text) => string.IsNullOrEmpty(note) ? text : $"{note}; {text}";

    public void Dispose()
    {
        stopping = true;
        wake.Set();
        worker.Join(5000);
        // Decrypt what is left before going away.
        List<(TlsRecording, State)> left;
        lock (gate) left = states.Where(kv => !kv.Value.Emitted).Select(kv => (kv.Key, kv.Value)).ToList();
        foreach (var (rec, state) in left)
        {
            try { rec.Closed = true; Emit(rec, state); } catch { }
            foreach (var m in state.Captured) m.Dispose();
        }
    }
}

/// <summary>Read access to another process's memory, preferably through a copy-on-write clone.</summary>
sealed class ProcessMemory : IDisposable
{
    readonly IntPtr process, snapshot, target;

    ProcessMemory(IntPtr process, IntPtr snapshot, IntPtr target)
    {
        this.process = process;
        this.snapshot = snapshot;
        this.target = target;
    }

    public bool Cloned => snapshot != IntPtr.Zero;

    public static ProcessMemory? Open(int pid, out string? error)
    {
        error = null;
        const int PROCESS_CREATE_PROCESS = 0x80, PROCESS_VM_READ = 0x10, PROCESS_QUERY_INFORMATION = 0x400, PROCESS_DUP_HANDLE = 0x40;
        IntPtr process = Native.OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, pid);
        if (process != IntPtr.Zero)
        {
            // PSS_CAPTURE_VA_CLONE: a point-in-time, copy-on-write clone of the address space.
            if (Native.PssCaptureSnapshot(process, 0x1, 0, out IntPtr snap) == 0)
            {
                if (Native.PssQuerySnapshot(snap, 1 /* PSS_QUERY_VA_CLONE_INFORMATION */, out IntPtr clone, IntPtr.Size) == 0 && clone != IntPtr.Zero)
                    return new ProcessMemory(process, snap, clone);
                Native.PssFreeSnapshot(Native.GetCurrentProcess(), snap);
            }
            return new ProcessMemory(process, IntPtr.Zero, process);
        }
        process = Native.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (process == IntPtr.Zero)
        {
            error = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message;
            return null;
        }
        return new ProcessMemory(process, IntPtr.Zero, process);
    }

    /// <summary>
    /// Calls <paramref name="visit"/> for every committed, readable, private region, in chunks that
    /// overlap a little so nothing that straddles a chunk boundary is missed. Returns the bytes read.
    /// </summary>
    public long Scan(Action<ReadOnlySpan<byte>, ulong> visit)
    {
        const uint MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000, PAGE_GUARD = 0x100, PAGE_NOACCESS = 0x1;
        const uint Readable = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;
        long total = 0;
        var buffer = new byte[16 << 20];
        ulong address = 0;
        while (total < (4L << 30))
        {
            if (Native.VirtualQueryEx(target, (IntPtr)(long)address, out var mbi, Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>()) == 0) break;
            ulong next = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
            if (next <= address) break;
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && (mbi.Protect & Readable) != 0 && (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0)
            {
                ulong start = (ulong)mbi.BaseAddress, end = next;
                for (ulong at = start; at < end;)
                {
                    int want = (int)Math.Min((ulong)buffer.Length, end - at);
                    if (Native.ReadProcessMemory(target, (IntPtr)(long)at, buffer, want, out IntPtr got) && (int)got > 0)
                    {
                        visit(buffer.AsSpan(0, (int)got), at);
                        total += (int)got;
                    }
                    if (at + (ulong)want >= end) break;
                    at += (ulong)(want - 256);   // overlap: a key schedule is at most 240 bytes
                }
            }
            address = next;
        }
        return total;
    }

    public void Dispose()
    {
        if (snapshot != IntPtr.Zero) Native.PssFreeSnapshot(Native.GetCurrentProcess(), snapshot);
        Native.CloseHandle(process);
    }
}
