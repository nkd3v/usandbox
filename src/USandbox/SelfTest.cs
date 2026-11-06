using System.Security.Cryptography;

namespace USandbox;

/// <summary><c>usandbox --selftest</c>: checks the TLS key-extraction cryptography against known answers and the platform.</summary>
static class SelfTest
{
    public static int Run()
    {
        int failures = 0;
        void Check(string name, bool ok)
        {
            System.Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {name}");
            if (!ok) failures++;
        }

        Check("ChaCha20 block and Poly1305 (RFC 8439 vectors)", ChaCha20Poly1305Soft.SelfTest());

        // RFC 8448 "Simple 1-RTT Handshake": server handshake traffic secret -> key and iv.
        var secret = Convert.FromHexString("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        Check("TLS 1.3 HKDF-Expand-Label (RFC 8448)",
            Convert.ToHexString(TlsCrypto.ExpandLabel(HashAlgorithmName.SHA256, secret, "key", default, 16)) == "3FCE516009C21727D0F2E4E86EE403BC" &&
            Convert.ToHexString(TlsCrypto.ExpandLabel(HashAlgorithmName.SHA256, secret, "iv", default, 12)) == "5D313EB2671276EE13000B30");

        var rng = RandomNumberGenerator.Create();
        bool aesOk = true, scheduleOk = true, nonceOk = true, verifyOk = true;
        foreach (int keyLength in new[] { 16, 32 })
        {
            for (int round = 0; round < 20; round++)
            {
                var key = RandomNumberGenerator.GetBytes(keyLength);
                var block = RandomNumberGenerator.GetBytes(16);
                using var aes = Aes.Create();
                aes.Key = key;
                var expected = aes.EncryptEcb(block, PaddingMode.None);
                var soft = new SoftAes(key);
                var got = new byte[16];
                soft.EncryptBlock(block, got);
                var back = new byte[16];
                soft.DecryptBlock(got, back);
                aesOk &= got.AsSpan().SequenceEqual(expected) && back.AsSpan().SequenceEqual(block);

                // A schedule hidden in random memory, in byte order and as big-endian words.
                foreach (bool swapped in new[] { false, true })
                {
                    var memory = RandomNumberGenerator.GetBytes(4096);
                    var schedule = (byte[])soft.Schedule.Clone();
                    if (swapped) for (int i = 0; i < schedule.Length; i += 4) Array.Reverse(schedule, i, 4);
                    int at = 4 * RandomNumberGenerator.GetInt32(100, 700);
                    schedule.CopyTo(memory, at);
                    var found = new HashSet<KeyBytes>();
                    TlsCrypto.FindAesSchedules(memory, found);
                    scheduleOk &= found.Count == 1 && found.First().Value.AsSpan().SequenceEqual(key);
                }

                // GCM nonce recovery and the cheap tag check, against the platform's AES-GCM.
                foreach (bool tls13 in new[] { true, false })
                {
                    var iv = RandomNumberGenerator.GetBytes(12);
                    var plaintext = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(1, 300));
                    ulong seq = (ulong)RandomNumberGenerator.GetInt32(0, 1000);
                    var nonce = (byte[])iv.Clone();
                    int bodyLength = (tls13 ? 0 : 8) + plaintext.Length + 16;
                    var header = new byte[] { tls13 ? (byte)23 : (byte)23, 3, 3, (byte)(bodyLength >> 8), (byte)bodyLength };
                    byte[] aad;
                    if (tls13)
                    {
                        for (int i = 0; i < 8; i++) nonce[11 - i] ^= (byte)(seq >> (8 * i));
                        aad = header;
                    }
                    else
                    {
                        aad = new byte[13];
                        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(aad, seq);
                        aad[8] = 23; aad[9] = 3; aad[10] = 3;
                        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(11), (ushort)plaintext.Length);
                    }
                    var ciphertext = new byte[plaintext.Length];
                    var tag = new byte[16];
                    using (var gcm = new AesGcm(key, 16)) gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                    byte[] payload = tls13 ? [.. ciphertext, .. tag] : [.. nonce[4..], .. ciphertext, .. tag];
                    var record = new TlsCrypto.WireRecord(23, header, payload);
                    var recovered = TlsCrypto.RecoverGcmNonce(key, record, tls13, seq);
                    nonceOk &= recovered != null && recovered.AsSpan().SequenceEqual(nonce);
                    var wrong = RandomNumberGenerator.GetBytes(keyLength);
                    nonceOk &= TlsCrypto.RecoverGcmNonce(wrong, record, tls13, seq) == null;

                    var suite = TlsSuite.Find(tls13 ? (keyLength == 16 ? (ushort)0x1301 : (ushort)0x1302) : (keyLength == 16 ? (ushort)0xC02F : (ushort)0xC030))!;
                    var recordKey = new TlsCrypto.RecordKey(suite, key, tls13 ? iv : iv[..4]);
                    verifyOk &= TlsCrypto.Verifies(recordKey, record, seq) && !TlsCrypto.Verifies(recordKey, record, seq + 1);
                    var opened = TlsCrypto.Open(recordKey, record, seq);
                    verifyOk &= opened != null && opened.AsSpan().SequenceEqual(plaintext);
                }
            }
        }
        Check("software AES matches the platform (AES-128/256)", aesOk);
        Check("AES key schedules found in memory (byte order and big-endian words)", scheduleOk);
        Check("AES-GCM nonce recovered from the tag (TLS 1.2 and 1.3 layouts)", nonceOk);
        Check("AES-GCM record check and decryption match the platform", verifyOk);

        // ChaCha20-Poly1305 seal/open round trip through our own primitives (the AEAD construction).
        bool chachaOk = true;
        for (int round = 0; round < 20; round++)
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var iv = RandomNumberGenerator.GetBytes(12);
            var plaintext = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(1, 300));
            var header = new byte[] { 23, 3, 3, (byte)((plaintext.Length + 16) >> 8), (byte)(plaintext.Length + 16) };
            var ciphertext = new byte[plaintext.Length];
            ChaCha20Poly1305Soft.Xor(key, iv, 1, plaintext, ciphertext);
            var tag = ChaCha20Poly1305Soft.Tag(key, iv, header, ciphertext);
            var suite = TlsSuite.Find(0x1303)!;
            var record = new TlsCrypto.WireRecord(23, header, [.. ciphertext, .. tag]);
            var opened = TlsCrypto.Open(new TlsCrypto.RecordKey(suite, key, iv), record, 0);
            chachaOk &= opened != null && opened.AsSpan().SequenceEqual(plaintext);
            chachaOk &= TlsCrypto.Open(new TlsCrypto.RecordKey(suite, key, iv), record, 1) == null;
        }
        Check("ChaCha20-Poly1305 record round trip", chachaOk);

        System.Console.WriteLine(failures == 0 ? "All checks passed." : $"{failures} check(s) failed.");
        return failures == 0 ? 0 : 1;
    }
}
