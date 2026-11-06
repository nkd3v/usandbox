using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace USandbox;

enum AeadKind { AesGcm, ChaCha20Poly1305 }

/// <summary>A TLS cipher suite usandbox can decrypt (modern AEAD suites only).</summary>
sealed record TlsSuite(ushort Id, string Name, bool Tls13, AeadKind Aead, int KeyLength, int IvLength, HashAlgorithmName Hash)
{
    public int HashLength => Hash == HashAlgorithmName.SHA384 ? 48 : 32;

    static readonly Dictionary<ushort, TlsSuite> All = new[]
    {
        new TlsSuite(0x1301, "TLS_AES_128_GCM_SHA256", true, AeadKind.AesGcm, 16, 12, HashAlgorithmName.SHA256),
        new TlsSuite(0x1302, "TLS_AES_256_GCM_SHA384", true, AeadKind.AesGcm, 32, 12, HashAlgorithmName.SHA384),
        new TlsSuite(0x1303, "TLS_CHACHA20_POLY1305_SHA256", true, AeadKind.ChaCha20Poly1305, 32, 12, HashAlgorithmName.SHA256),
        new TlsSuite(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", false, AeadKind.AesGcm, 16, 4, HashAlgorithmName.SHA256),
        new TlsSuite(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false, AeadKind.AesGcm, 16, 4, HashAlgorithmName.SHA256),
        new TlsSuite(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", false, AeadKind.AesGcm, 32, 4, HashAlgorithmName.SHA384),
        new TlsSuite(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", false, AeadKind.AesGcm, 32, 4, HashAlgorithmName.SHA384),
        new TlsSuite(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", false, AeadKind.AesGcm, 16, 4, HashAlgorithmName.SHA256),
        new TlsSuite(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", false, AeadKind.AesGcm, 32, 4, HashAlgorithmName.SHA384),
        new TlsSuite(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", false, AeadKind.AesGcm, 16, 4, HashAlgorithmName.SHA256),
        new TlsSuite(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", false, AeadKind.AesGcm, 32, 4, HashAlgorithmName.SHA384),
        new TlsSuite(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", false, AeadKind.ChaCha20Poly1305, 32, 12, HashAlgorithmName.SHA256),
        new TlsSuite(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", false, AeadKind.ChaCha20Poly1305, 32, 12, HashAlgorithmName.SHA256),
        new TlsSuite(0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", false, AeadKind.ChaCha20Poly1305, 32, 12, HashAlgorithmName.SHA256),
    }.ToDictionary(s => s.Id);

    public static TlsSuite? Find(ushort id) => All.GetValueOrDefault(id);
}

/// <summary>
/// The cryptography needed to decrypt recorded TLS records once a key has been found in memory:
/// TLS 1.3 HKDF-Expand-Label, the TLS 1.2 PRF, AES-GCM and ChaCha20-Poly1305 record opening, and
/// the two library-independent ways to recognise a key: AES key schedules and GCM nonce recovery.
/// Everything that runs once per candidate is allocation-light and never throws on a wrong key.
/// </summary>
static class TlsCrypto
{
    // ---- key derivation ------------------------------------------------------------------------

    /// <summary>RFC 8446 7.1 HKDF-Expand-Label.</summary>
    public static byte[] ExpandLabel(HashAlgorithmName hash, ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> context, int length)
    {
        int labelLength = 6 + label.Length;
        Span<byte> info = stackalloc byte[2 + 1 + labelLength + 1 + context.Length];
        BinaryPrimitives.WriteUInt16BigEndian(info, (ushort)length);
        info[2] = (byte)labelLength;
        Encoding.ASCII.GetBytes("tls13 " + label, info[3..]);
        info[3 + labelLength] = (byte)context.Length;
        context.CopyTo(info[(4 + labelLength)..]);
        var output = new byte[length];
        HKDF.Expand(hash, secret, output, info);
        return output;
    }

    /// <summary>TLS 1.2 PRF (RFC 5246 5): P_hash(secret, label + seed).</summary>
    public static byte[] Prf12(HashAlgorithmName hash, ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> seed, int length)
    {
        byte[] labelSeed = new byte[label.Length + seed.Length];
        Encoding.ASCII.GetBytes(label, labelSeed);
        seed.CopyTo(labelSeed.AsSpan(label.Length));
        int hashLength = hash == HashAlgorithmName.SHA384 ? 48 : 32;
        var output = new byte[length];
        byte[] a = labelSeed;
        byte[] block = new byte[hashLength + labelSeed.Length];
        for (int done = 0; done < length;)
        {
            a = Hmac(hash, secret, a);
            a.CopyTo(block, 0);
            labelSeed.CopyTo(block, hashLength);
            byte[] p = Hmac(hash, secret, block);
            int n = Math.Min(p.Length, length - done);
            p.AsSpan(0, n).CopyTo(output.AsSpan(done));
            done += n;
        }
        return output;
    }

    static byte[] Hmac(HashAlgorithmName hash, ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) =>
        hash == HashAlgorithmName.SHA384 ? HMACSHA384.HashData(key, data) : HMACSHA256.HashData(key, data);

    /// <summary>Record keys for one direction.</summary>
    public sealed record RecordKey(TlsSuite Suite, byte[] Key, byte[] Iv);

    /// <summary>TLS 1.3: a traffic secret gives that direction's key and IV.</summary>
    public static RecordKey FromTrafficSecret(TlsSuite suite, ReadOnlySpan<byte> secret) =>
        new(suite, ExpandLabel(suite.Hash, secret, "key", default, suite.KeyLength), ExpandLabel(suite.Hash, secret, "iv", default, suite.IvLength));

    /// <summary>TLS 1.2: the master secret gives both directions' keys.</summary>
    public static (RecordKey Client, RecordKey Server) FromMasterSecret(TlsSuite suite, ReadOnlySpan<byte> master, ReadOnlySpan<byte> clientRandom, ReadOnlySpan<byte> serverRandom)
    {
        Span<byte> seed = stackalloc byte[64];
        serverRandom.CopyTo(seed);
        clientRandom.CopyTo(seed[32..]);
        int k = suite.KeyLength, iv = suite.IvLength;
        byte[] block = Prf12(suite.Hash, master, "key expansion", seed, 2 * k + 2 * iv);
        return (new RecordKey(suite, block[..k], block[(2 * k)..(2 * k + iv)]),
                new RecordKey(suite, block[k..(2 * k)], block[(2 * k + iv)..(2 * k + 2 * iv)]));
    }

    // ---- record protection ---------------------------------------------------------------------

    /// <summary>
    /// One protected record as it was on the wire: <paramref name="Header"/> is the 5-byte record
    /// header, <paramref name="Payload"/> what followed it.
    /// </summary>
    public readonly record struct WireRecord(byte Type, byte[] Header, byte[] Payload);

    /// <summary>Nonce and additional data for record <paramref name="seq"/>; null when the record cannot be this suite's.</summary>
    static bool Layout(RecordKey key, in WireRecord record, ulong seq, Span<byte> nonce, out byte[] aad, out ReadOnlyMemory<byte> ciphertext, out ReadOnlyMemory<byte> tag)
    {
        aad = Array.Empty<byte>();
        ciphertext = default;
        tag = default;
        var payload = record.Payload;
        if (key.Suite.Tls13 || key.Suite.Aead == AeadKind.ChaCha20Poly1305)
        {
            // TLS 1.3 (all suites) and TLS 1.2 ChaCha20: nonce = iv XOR seq.
            if (payload.Length < 16) return false;
            key.Iv.CopyTo(nonce);
            for (int i = 0; i < 8; i++) nonce[11 - i] ^= (byte)(seq >> (8 * i));
            ciphertext = payload.AsMemory(0, payload.Length - 16);
            tag = payload.AsMemory(payload.Length - 16);
            aad = key.Suite.Tls13 ? record.Header : Aad12(seq, record, payload.Length - 16);
            return true;
        }
        // TLS 1.2 AES-GCM: nonce = 4-byte salt + 8-byte explicit nonce from the record.
        if (payload.Length < 8 + 16) return false;
        key.Iv.CopyTo(nonce);
        payload.AsSpan(0, 8).CopyTo(nonce[4..]);
        ciphertext = payload.AsMemory(8, payload.Length - 24);
        tag = payload.AsMemory(payload.Length - 16);
        aad = Aad12(seq, record, payload.Length - 24);
        return true;
    }

    static byte[] Aad12(ulong seq, in WireRecord record, int plaintextLength)
    {
        var aad = new byte[13];
        BinaryPrimitives.WriteUInt64BigEndian(aad, seq);
        aad[8] = record.Type;
        aad[9] = record.Header[1];
        aad[10] = record.Header[2];
        BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(11), (ushort)plaintextLength);
        return aad;
    }

    /// <summary>Cheap check that never throws: does <paramref name="key"/> open this record at <paramref name="seq"/>?</summary>
    public static bool Verifies(RecordKey key, in WireRecord record, ulong seq)
    {
        Span<byte> nonce = stackalloc byte[12];
        if (!Layout(key, record, seq, nonce, out var aad, out var ciphertext, out var tag)) return false;
        if (key.Suite.Aead == AeadKind.AesGcm)
        {
            var aes = new SoftAes(key.Key);
            Span<byte> h = stackalloc byte[16], j0 = stackalloc byte[16], expected = stackalloc byte[16];
            h.Clear();
            aes.EncryptBlock(h, h);
            nonce.CopyTo(j0);
            j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
            aes.EncryptBlock(j0, expected);
            Ghash(h, aad, ciphertext.Span, j0);
            for (int i = 0; i < 16; i++) expected[i] ^= j0[i];
            return expected.SequenceEqual(tag.Span);
        }
        return ChaCha20Poly1305Soft.Verify(key.Key, nonce, aad, ciphertext.Span, tag.Span);
    }

    /// <summary>Decrypts a record (null when the key or sequence number is wrong).</summary>
    public static byte[]? Open(RecordKey key, in WireRecord record, ulong seq)
    {
        Span<byte> nonce = stackalloc byte[12];
        if (!Layout(key, record, seq, nonce, out var aad, out var ciphertext, out var tag)) return null;
        var plaintext = new byte[ciphertext.Length];
        if (key.Suite.Aead == AeadKind.AesGcm)
        {
            try
            {
                using var gcm = new AesGcm(key.Key, 16);
                gcm.Decrypt(nonce, ciphertext.Span, tag.Span, plaintext, aad);
                return plaintext;
            }
            catch (CryptographicException) { return null; }
        }
        if (!ChaCha20Poly1305Soft.Verify(key.Key, nonce, aad, ciphertext.Span, tag.Span)) return null;
        ChaCha20Poly1305Soft.Xor(key.Key, nonce, 1, ciphertext.Span, plaintext);
        return plaintext;
    }

    // ---- GCM nonce recovery ----------------------------------------------------------------------

    /// <summary>
    /// Given only a raw AES key (no IV), recovers the nonce of one AES-GCM record from its tag:
    /// tag = E(K, J0) xor GHASH(H, A, C), so J0 = D(K, tag xor GHASH). A right key yields a J0 that
    /// ends in the 32-bit counter 1, and for TLS 1.2 whose middle matches the explicit nonce on the wire.
    /// This makes any AES key schedule found in memory testable without the IV or the TLS secret.
    /// </summary>
    public static byte[]? RecoverGcmNonce(byte[] aesKey, in WireRecord record, bool tls13, ulong seq12)
    {
        var payload = record.Payload;
        int start = tls13 ? 0 : 8;
        if (payload.Length < start + 16) return null;
        var ciphertext = payload.AsSpan(start, payload.Length - start - 16);
        var tag = payload.AsSpan(payload.Length - 16);
        byte[] aad = tls13 ? record.Header : Aad12(seq12, record, ciphertext.Length);

        var aes = new SoftAes(aesKey);
        Span<byte> h = stackalloc byte[16], s = stackalloc byte[16];
        h.Clear();
        aes.EncryptBlock(h, h);
        Ghash(h, aad, ciphertext, s);
        for (int i = 0; i < 16; i++) s[i] ^= tag[i];
        aes.DecryptBlock(s, s);
        if (s[12] != 0 || s[13] != 0 || s[14] != 0 || s[15] != 1) return null;
        if (!tls13 && !s.Slice(4, 8).SequenceEqual(payload.AsSpan(0, 8))) return null;
        return s[..12].ToArray();
    }

    /// <summary>GHASH(H, A, C) per NIST SP 800-38D.</summary>
    static void Ghash(ReadOnlySpan<byte> h, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, Span<byte> result)
    {
        ulong hHi = BinaryPrimitives.ReadUInt64BigEndian(h), hLo = BinaryPrimitives.ReadUInt64BigEndian(h[8..]);
        ulong yHi = 0, yLo = 0;
        GhashAbsorb(aad, ref yHi, ref yLo, hHi, hLo);
        GhashAbsorb(ciphertext, ref yHi, ref yLo, hHi, hLo);
        yHi ^= (ulong)aad.Length * 8;
        yLo ^= (ulong)ciphertext.Length * 8;
        GfMul(ref yHi, ref yLo, hHi, hLo);
        BinaryPrimitives.WriteUInt64BigEndian(result, yHi);
        BinaryPrimitives.WriteUInt64BigEndian(result[8..], yLo);
    }

    static void GhashAbsorb(ReadOnlySpan<byte> data, ref ulong yHi, ref ulong yLo, ulong hHi, ulong hLo)
    {
        Span<byte> block = stackalloc byte[16];
        for (int i = 0; i < data.Length; i += 16)
        {
            int n = Math.Min(16, data.Length - i);
            if (n == 16)
            {
                yHi ^= BinaryPrimitives.ReadUInt64BigEndian(data[i..]);
                yLo ^= BinaryPrimitives.ReadUInt64BigEndian(data[(i + 8)..]);
            }
            else
            {
                block.Clear();
                data.Slice(i, n).CopyTo(block);
                yHi ^= BinaryPrimitives.ReadUInt64BigEndian(block);
                yLo ^= BinaryPrimitives.ReadUInt64BigEndian(block[8..]);
            }
            GfMul(ref yHi, ref yLo, hHi, hLo);
        }
    }

    static void GfMul(ref ulong xHi, ref ulong xLo, ulong yHi, ulong yLo)
    {
        ulong zHi = 0, zLo = 0, vHi = yHi, vLo = yLo;
        for (int i = 0; i < 128; i++)
        {
            ulong bit = i < 64 ? (xHi >> (63 - i)) & 1 : (xLo >> (127 - i)) & 1;
            ulong mask = 0 - bit;
            zHi ^= vHi & mask;
            zLo ^= vLo & mask;
            ulong lsb = vLo & 1;
            vLo = (vLo >> 1) | (vHi << 63);
            vHi = (vHi >> 1) ^ (0xE100000000000000UL & (0 - lsb));
        }
        xHi = zHi;
        xLo = zLo;
    }

    // ---- AES key schedules in memory ---------------------------------------------------------------

    /// <summary>
    /// Finds expanded AES-128/256 encryption key schedules in a block of memory and returns their
    /// keys. Libraries keep the expanded schedule for as long as a connection lives (OpenSSL,
    /// BoringSSL/ring, Go, SymCrypt/Schannel), even when they have wiped the TLS secret it came
    /// from. Schedules stored as big-endian words (generic C and Go code) are found too.
    /// </summary>
    public static void FindAesSchedules(ReadOnlySpan<byte> memory, HashSet<KeyBytes> found)
    {
        for (int o = 0; o + 176 <= memory.Length; o += 4)
        {
            var w = memory.Slice(o);
            // Cheapest possible reject first: the 5th word of AES-128 / 9th word of AES-256.
            if (Check128(w, false) || Check128(w, true)) found.Add(new KeyBytes(Key(w, 16, BigEndianWords(w, 16))));
            if (o + 240 <= memory.Length && (Check256(w, false) || Check256(w, true))) found.Add(new KeyBytes(Key(w, 32, BigEndianWords(w, 32))));
        }
    }

    static bool BigEndianWords(ReadOnlySpan<byte> w, int keyLength) =>
        keyLength == 16 ? !Check128(w, false) : !Check256(w, false);

    static byte[] Key(ReadOnlySpan<byte> w, int length, bool swapped)
    {
        var key = w[..length].ToArray();
        if (swapped)
            for (int i = 0; i < length; i += 4) Array.Reverse(key, i, 4);
        return key;
    }

    static uint Word(ReadOnlySpan<byte> w, int i, bool swapped) =>
        swapped ? BinaryPrimitives.ReadUInt32LittleEndian(w[(4 * i)..]) : BinaryPrimitives.ReadUInt32BigEndian(w[(4 * i)..]);

    static readonly uint[] Rcon = { 0, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000 };

    static uint SubWord(uint x) =>
        ((uint)SoftAes.Sbox[x >> 24] << 24) | ((uint)SoftAes.Sbox[(x >> 16) & 0xFF] << 16) | ((uint)SoftAes.Sbox[(x >> 8) & 0xFF] << 8) | SoftAes.Sbox[x & 0xFF];

    static uint RotWord(uint x) => (x << 8) | (x >> 24);

    static bool Check128(ReadOnlySpan<byte> w, bool swapped)
    {
        uint w0 = Word(w, 0, swapped), w3 = Word(w, 3, swapped);
        if (Word(w, 4, swapped) != (w0 ^ SubWord(RotWord(w3)) ^ Rcon[1])) return false;
        // Reject degenerate memory (all zero words expand to themselves only with the round constant).
        if ((w0 | Word(w, 1, swapped) | Word(w, 2, swapped) | w3) == 0) return false;
        for (int i = 5; i < 44; i++)
        {
            uint prev = Word(w, i - 1, swapped);
            uint t = i % 4 == 0 ? SubWord(RotWord(prev)) ^ Rcon[i / 4] : prev;
            if (Word(w, i, swapped) != (Word(w, i - 4, swapped) ^ t)) return false;
        }
        return true;
    }

    static bool Check256(ReadOnlySpan<byte> w, bool swapped)
    {
        uint w7 = Word(w, 7, swapped);
        if (Word(w, 8, swapped) != (Word(w, 0, swapped) ^ SubWord(RotWord(w7)) ^ Rcon[1])) return false;
        for (int i = 9; i < 60; i++)
        {
            uint prev = Word(w, i - 1, swapped);
            uint t = i % 8 == 0 ? SubWord(RotWord(prev)) ^ Rcon[i / 8] : i % 8 == 4 ? SubWord(prev) : prev;
            if (Word(w, i, swapped) != (Word(w, i - 8, swapped) ^ t)) return false;
        }
        return true;
    }
}

/// <summary>Key bytes with value equality, for de-duplicating candidates.</summary>
readonly struct KeyBytes : IEquatable<KeyBytes>
{
    public readonly byte[] Value;
    public KeyBytes(byte[] value) => Value = value;
    public bool Equals(KeyBytes other) => Value.AsSpan().SequenceEqual(other.Value);
    public override bool Equals(object? obj) => obj is KeyBytes k && Equals(k);
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Value);
        return h.ToHashCode();
    }
}

/// <summary>
/// A small table-free AES used to test candidate keys without the exceptions and object setup of
/// the platform API (a scan may try many thousands of keys). Not constant time; never used to protect data.
/// </summary>
readonly struct SoftAes
{
    public static readonly byte[] Sbox = new byte[256], InvSbox = new byte[256];

    static SoftAes()
    {
        // S-box from its definition: multiplicative inverse in GF(2^8), then the affine transform.
        for (int x = 0; x < 256; x++)
        {
            byte inv = x == 0 ? (byte)0 : Pow((byte)x, 254);
            int s = inv ^ Rotl(inv, 1) ^ Rotl(inv, 2) ^ Rotl(inv, 3) ^ Rotl(inv, 4) ^ 0x63;
            Sbox[x] = (byte)s;
            InvSbox[s] = (byte)x;
        }
    }

    static int Rotl(byte b, int n) => ((b << n) | (b >> (8 - n))) & 0xFF;

    static byte Mul(byte a, byte b)
    {
        int p = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((b & 1) != 0) p ^= a;
            bool hi = (a & 0x80) != 0;
            a <<= 1;
            if (hi) a ^= 0x1B;
            b >>= 1;
        }
        return (byte)p;
    }

    static byte Pow(byte a, int e)
    {
        byte r = 1;
        while (e > 0)
        {
            if ((e & 1) != 0) r = Mul(r, a);
            a = Mul(a, a);
            e >>= 1;
        }
        return r;
    }

    readonly byte[] roundKeys;
    readonly int rounds;

    /// <summary>The expanded encryption key schedule, in byte order (for the self-test).</summary>
    public byte[] Schedule => roundKeys;

    public SoftAes(ReadOnlySpan<byte> key)
    {
        int nk = key.Length / 4;
        rounds = nk + 6;
        int words = 4 * (rounds + 1);
        roundKeys = new byte[words * 4];
        key.CopyTo(roundKeys);
        byte rcon = 1;
        Span<byte> t = stackalloc byte[4];
        for (int i = nk; i < words; i++)
        {
            roundKeys.AsSpan(4 * (i - 1), 4).CopyTo(t);
            if (i % nk == 0)
            {
                byte first = t[0];
                t[0] = (byte)(Sbox[t[1]] ^ rcon); t[1] = Sbox[t[2]]; t[2] = Sbox[t[3]]; t[3] = Sbox[first];
                rcon = Mul(rcon, 2);
            }
            else if (nk > 6 && i % nk == 4)
            {
                for (int j = 0; j < 4; j++) t[j] = Sbox[t[j]];
            }
            for (int j = 0; j < 4; j++) roundKeys[4 * i + j] = (byte)(roundKeys[4 * (i - nk) + j] ^ t[j]);
        }
    }

    public void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> s = stackalloc byte[16];
        input[..16].CopyTo(s);
        AddRoundKey(s, 0);
        for (int r = 1; r <= rounds; r++)
        {
            for (int i = 0; i < 16; i++) s[i] = Sbox[s[i]];
            ShiftRows(s);
            if (r != rounds) MixColumns(s);
            AddRoundKey(s, r);
        }
        s.CopyTo(output);
    }

    public void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> s = stackalloc byte[16];
        input[..16].CopyTo(s);
        AddRoundKey(s, rounds);
        for (int r = rounds - 1; r >= 0; r--)
        {
            InvShiftRows(s);
            for (int i = 0; i < 16; i++) s[i] = InvSbox[s[i]];
            AddRoundKey(s, r);
            if (r != 0) InvMixColumns(s);
        }
        s.CopyTo(output);
    }

    void AddRoundKey(Span<byte> s, int round)
    {
        var k = roundKeys.AsSpan(16 * round, 16);
        for (int i = 0; i < 16; i++) s[i] ^= k[i];
    }

    // State is column-major: byte (row r, column c) is s[4c + r].
    static void ShiftRows(Span<byte> s)
    {
        Span<byte> t = stackalloc byte[16];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++) t[4 * c + r] = s[4 * ((c + r) % 4) + r];
        t.CopyTo(s);
    }

    static void InvShiftRows(Span<byte> s)
    {
        Span<byte> t = stackalloc byte[16];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++) t[4 * ((c + r) % 4) + r] = s[4 * c + r];
        t.CopyTo(s);
    }

    static void MixColumns(Span<byte> s)
    {
        for (int c = 0; c < 4; c++)
        {
            byte a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
            s[4 * c] = (byte)(Mul(a0, 2) ^ Mul(a1, 3) ^ a2 ^ a3);
            s[4 * c + 1] = (byte)(a0 ^ Mul(a1, 2) ^ Mul(a2, 3) ^ a3);
            s[4 * c + 2] = (byte)(a0 ^ a1 ^ Mul(a2, 2) ^ Mul(a3, 3));
            s[4 * c + 3] = (byte)(Mul(a0, 3) ^ a1 ^ a2 ^ Mul(a3, 2));
        }
    }

    static void InvMixColumns(Span<byte> s)
    {
        for (int c = 0; c < 4; c++)
        {
            byte a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
            s[4 * c] = (byte)(Mul(a0, 14) ^ Mul(a1, 11) ^ Mul(a2, 13) ^ Mul(a3, 9));
            s[4 * c + 1] = (byte)(Mul(a0, 9) ^ Mul(a1, 14) ^ Mul(a2, 11) ^ Mul(a3, 13));
            s[4 * c + 2] = (byte)(Mul(a0, 13) ^ Mul(a1, 9) ^ Mul(a2, 14) ^ Mul(a3, 11));
            s[4 * c + 3] = (byte)(Mul(a0, 11) ^ Mul(a1, 13) ^ Mul(a2, 9) ^ Mul(a3, 14));
        }
    }
}

/// <summary>
/// ChaCha20 and Poly1305 (RFC 8439). The platform's ChaCha20Poly1305 needs a newer Windows 10
/// build than usandbox supports, and candidate testing must not throw, so this is done here.
/// </summary>
static class ChaCha20Poly1305Soft
{
    static uint Rotl(uint v, int n) => (v << n) | (v >> (32 - n));

    static void Block(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, Span<byte> output)
    {
        Span<uint> s = stackalloc uint[16], x = stackalloc uint[16];
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4 * i)..]);
        s[12] = counter;
        for (int i = 0; i < 3; i++) s[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(4 * i)..]);
        s.CopyTo(x);
        static void Q(Span<uint> v, int a, int b, int c, int d)
        {
            v[a] += v[b]; v[d] = Rotl(v[d] ^ v[a], 16);
            v[c] += v[d]; v[b] = Rotl(v[b] ^ v[c], 12);
            v[a] += v[b]; v[d] = Rotl(v[d] ^ v[a], 8);
            v[c] += v[d]; v[b] = Rotl(v[b] ^ v[c], 7);
        }
        for (int i = 0; i < 10; i++)
        {
            Q(x, 0, 4, 8, 12); Q(x, 1, 5, 9, 13); Q(x, 2, 6, 10, 14); Q(x, 3, 7, 11, 15);
            Q(x, 0, 5, 10, 15); Q(x, 1, 6, 11, 12); Q(x, 2, 7, 8, 13); Q(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(output[(4 * i)..], x[i] + s[i]);
    }

    public static void Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> stream = stackalloc byte[64];
        for (int i = 0; i < input.Length; i += 64, counter++)
        {
            Block(key, nonce, counter, stream);
            int n = Math.Min(64, input.Length - i);
            for (int j = 0; j < n; j++) output[i + j] = (byte)(input[i + j] ^ stream[j]);
        }
    }

    public static bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag) =>
        Tag(key, nonce, aad, ciphertext).AsSpan().SequenceEqual(tag);

    public static byte[] Tag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext)
    {
        Span<byte> polyKey = stackalloc byte[64];
        Block(key, nonce, 0, polyKey);
        var mac = new Poly1305(polyKey[..32]);
        mac.UpdatePadded(aad);
        mac.UpdatePadded(ciphertext);
        Span<byte> lengths = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(lengths, (ulong)aad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)ciphertext.Length);
        mac.UpdatePadded(lengths);
        var computed = new byte[16];
        mac.Finish(computed);
        return computed;
    }

    /// <summary>Poly1305 with 26-bit limbs (the "donna" 32-bit layout).</summary>
    struct Poly1305
    {
        readonly uint r0, r1, r2, r3, r4, s1, s2, s3, s4, pad0, pad1, pad2, pad3;
        uint h0, h1, h2, h3, h4;

        public Poly1305(ReadOnlySpan<byte> key)
        {
            r0 = Le(key, 0) & 0x3ffffff;
            r1 = (Le(key, 3) >> 2) & 0x3ffff03;
            r2 = (Le(key, 6) >> 4) & 0x3ffc0ff;
            r3 = (Le(key, 9) >> 6) & 0x3f03fff;
            r4 = (Le(key, 12) >> 8) & 0x00fffff;
            s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;
            pad0 = Le(key, 16); pad1 = Le(key, 20); pad2 = Le(key, 24); pad3 = Le(key, 28);
            h0 = h1 = h2 = h3 = h4 = 0;
        }

        static uint Le(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);

        /// <summary>Absorbs data zero-padded to a multiple of 16 bytes (as the AEAD construction does).</summary>
        public void UpdatePadded(ReadOnlySpan<byte> data)
        {
            Span<byte> block = stackalloc byte[16];
            for (int i = 0; i < data.Length; i += 16)
            {
                int n = Math.Min(16, data.Length - i);
                block.Clear();
                data.Slice(i, n).CopyTo(block);
                Absorb(block, 1u << 24);
            }
        }

        /// <summary>Plain Poly1305 message input: a short last block gets the 0x01 pad byte instead of the high bit.</summary>
        public void UpdateUnpadded(ReadOnlySpan<byte> data)
        {
            Span<byte> block = stackalloc byte[16];
            for (int i = 0; i < data.Length; i += 16)
            {
                int n = Math.Min(16, data.Length - i);
                block.Clear();
                data.Slice(i, n).CopyTo(block);
                if (n == 16) Absorb(block, 1u << 24);
                else { block[n] = 1; Absorb(block, 0); }
            }
        }

        void Absorb(ReadOnlySpan<byte> m, uint hibit)
        {
            const uint mask = 0x3ffffff;
            h0 += Le(m, 0) & mask;
            h1 += (Le(m, 3) >> 2) & mask;
            h2 += (Le(m, 6) >> 4) & mask;
            h3 += (Le(m, 9) >> 6) & mask;
            h4 += (Le(m, 12) >> 8) | hibit;

            ulong d0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
            ulong d1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
            ulong d2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
            ulong d3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
            ulong d4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;

            uint c = (uint)(d0 >> 26); h0 = (uint)d0 & mask;
            d1 += c; c = (uint)(d1 >> 26); h1 = (uint)d1 & mask;
            d2 += c; c = (uint)(d2 >> 26); h2 = (uint)d2 & mask;
            d3 += c; c = (uint)(d3 >> 26); h3 = (uint)d3 & mask;
            d4 += c; c = (uint)(d4 >> 26); h4 = (uint)d4 & mask;
            h0 += c * 5; c = h0 >> 26; h0 &= mask;
            h1 += c;
        }

        public void Finish(Span<byte> tag)
        {
            const uint mask = 0x3ffffff;
            uint c = h1 >> 26; h1 &= mask;
            h2 += c; c = h2 >> 26; h2 &= mask;
            h3 += c; c = h3 >> 26; h3 &= mask;
            h4 += c; c = h4 >> 26; h4 &= mask;
            h0 += c * 5; c = h0 >> 26; h0 &= mask;
            h1 += c;

            uint g0 = h0 + 5; c = g0 >> 26; g0 &= mask;
            uint g1 = h1 + c; c = g1 >> 26; g1 &= mask;
            uint g2 = h2 + c; c = g2 >> 26; g2 &= mask;
            uint g3 = h3 + c; c = g3 >> 26; g3 &= mask;
            uint g4 = h4 + c - (1u << 26);

            uint select = (g4 >> 31) - 1;   // all ones when h >= p (use g), zero otherwise
            uint keep = ~select;
            h0 = (h0 & keep) | (g0 & select);
            h1 = (h1 & keep) | (g1 & select);
            h2 = (h2 & keep) | (g2 & select);
            h3 = (h3 & keep) | (g3 & select);
            h4 = (h4 & keep) | (g4 & select);

            uint t0 = h0 | (h1 << 26);
            uint t1 = (h1 >> 6) | (h2 << 20);
            uint t2 = (h2 >> 12) | (h3 << 14);
            uint t3 = (h3 >> 18) | (h4 << 8);

            ulong f = (ulong)t0 + pad0; BinaryPrimitives.WriteUInt32LittleEndian(tag, (uint)f);
            f = (ulong)t1 + pad1 + (f >> 32); BinaryPrimitives.WriteUInt32LittleEndian(tag[4..], (uint)f);
            f = (ulong)t2 + pad2 + (f >> 32); BinaryPrimitives.WriteUInt32LittleEndian(tag[8..], (uint)f);
            f = (ulong)t3 + pad3 + (f >> 32); BinaryPrimitives.WriteUInt32LittleEndian(tag[12..], (uint)f);
        }
    }

    /// <summary>RFC 8439 test vectors, for the self-test.</summary>
    public static bool SelfTest()
    {
        var key = Convert.FromHexString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        var mac = new Poly1305(key);
        // Message is 34 bytes, so absorb 2 full blocks then the 2-byte tail with the 0x01 pad bit set.
        var msg = Encoding.ASCII.GetBytes("Cryptographic Forum Research Group");
        mac.UpdateUnpadded(msg);
        Span<byte> tag = stackalloc byte[16];
        mac.Finish(tag);
        if (Convert.ToHexString(tag) != "A8061DC1305136C6C22B8BAF0C0127A9") return false;

        Span<byte> block = stackalloc byte[64];
        var k = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        Block(k, Convert.FromHexString("000000090000004a00000000"), 1, block);
        return Convert.ToHexString(block[..16]) == "10F1E7E4D13B5915500FDD1FA32071C4";
    }
}
