using System.Buffers.Binary;

namespace USandbox;

/// <summary>
/// A TLS connection that is forwarded without decryption, recorded so that it can be decrypted
/// later with keys found in the program's memory. Forwarding is never held up: the copy loops
/// hand every chunk to <see cref="Feed"/>, which only splits it into records and keeps them.
/// </summary>
sealed class TlsRecording
{
    public sealed class Direction
    {
        internal readonly List<byte> Partial = new();
        internal bool ChangeCipherSpec;
        internal ulong SequenceSinceCcs;

        /// <summary>Protected records in the order they were sent.</summary>
        public List<(TlsCrypto.WireRecord Record, ulong Seq12, long Order)> Encrypted { get; } = new();
        public long Bytes;
    }

    readonly object gate = new();
    readonly long budget;
    long recorded, order;

    public Flow Flow { get; }
    public int? Pid => Flow.Pid;
    public string Name { get; }
    public Direction Client { get; } = new();
    public Direction Server { get; } = new();
    public byte[]? ClientRandom { get; private set; }
    public byte[]? ServerRandom { get; private set; }
    public TlsSuite? Suite { get; private set; }
    public ushort SuiteId { get; private set; }
    public bool Tls13 { get; private set; }
    public bool Truncated { get; private set; }
    public bool Closed { get; set; }
    public DateTime Started { get; } = DateTime.Now;

    bool keysInUseRaised;

    public TlsRecording(Flow flow, string name, long budget)
    {
        Flow = flow;
        Name = name;
        this.budget = budget;
    }

    public object Gate => gate;

    /// <summary>Records a chunk. Returns true once: when the program has sent application data, so its traffic keys exist.</summary>
    public bool Feed(bool fromClient, ReadOnlySpan<byte> data)
    {
        bool raise = false;
        lock (gate)
        {
            var d = fromClient ? Client : Server;
            d.Bytes += data.Length;
            if (Truncated) return false;
            d.Partial.AddRange(data);
            while (d.Partial.Count >= 5)
            {
                int length = (d.Partial[3] << 8) | d.Partial[4];
                if (d.Partial.Count < 5 + length) break;
                var header = d.Partial.GetRange(0, 5).ToArray();
                var payload = d.Partial.GetRange(5, length).ToArray();
                d.Partial.RemoveRange(0, 5 + length);
                if (header[1] != 3) { Truncated = true; return false; }   // not TLS after all
                Record(fromClient, d, header, payload);
            }
            raise = !keysInUseRaised && (Client.Encrypted.Count >= 2 ||
                    (Client.Encrypted.Count >= 1 && Server.Encrypted.Any(r => r.Order > Client.Encrypted[0].Order)));
            if (raise) keysInUseRaised = true;
        }
        return raise;
    }

    void Record(bool fromClient, Direction d, byte[] header, byte[] payload)
    {
        byte type = header[0];
        if (type == 20) { d.ChangeCipherSpec = true; d.SequenceSinceCcs = 0; return; }
        bool encrypted = Tls13 ? type == 23 : d.ChangeCipherSpec && type is 21 or 22 or 23;
        if (!encrypted)
        {
            if (type == 22) Handshake(fromClient, payload);
            return;
        }
        if (recorded + payload.Length > budget) { Truncated = true; return; }
        recorded += payload.Length;
        d.Encrypted.Add((new TlsCrypto.WireRecord(type, header, payload), d.SequenceSinceCcs++, order++));
    }

    static readonly byte[] HelloRetryRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    void Handshake(bool fromClient, byte[] p)
    {
        try
        {
            if (p.Length < 4 + 2 + 32) return;
            if (fromClient && p[0] == 1) { ClientRandom = p[6..38]; return; }
            if (fromClient || p[0] != 2) return;
            var random = p[6..38];
            if (random.AsSpan().SequenceEqual(HelloRetryRandom)) return;
            ServerRandom = random;
            int pos = 38;
            pos += 1 + p[pos];                                       // session id
            SuiteId = BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(pos));
            Suite = TlsSuite.Find(SuiteId);
            pos += 3;                                                // suite + compression
            if (pos + 2 > p.Length) return;
            int end = Math.Min(p.Length, pos + 2 + BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(pos)));
            pos += 2;
            while (pos + 4 <= end)
            {
                int type = BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(pos)), len = BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(pos + 2));
                if (type == 43 && len == 2 && BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(pos + 4)) == 0x0304) Tls13 = true;
                pos += 4 + len;
            }
        }
        catch (ArgumentOutOfRangeException) { }
    }

    public string Version => Tls13 ? "TLS 1.3" : "TLS 1.2";
}
