# Design note: TLS key extraction from sandbox process memory

Status: **implemented** (`KeyExtractor.cs`, `TlsRecording.cs`, `TlsCrypto.cs`, `PlaintextDecoder.cs`;
see the README's "Keys from memory"). Kept below as the design record. Where the build differs:

- **On by default** (`--no-extract-keys` turns it off; `--passive-tls` relies on it alone), not opt-in.
- **AES key schedules first.** Besides the 32/48-byte secret scan of §3.3, the scan looks for expanded
  AES-128/256 key schedules (both byte orders) and confirms a raw AES key without the IV by recovering
  the GCM nonce from the tag (`J0 = AES⁻¹(tag ⊕ GHASH)` must end in counter 1). This finds keys after
  the TLS secret is wiped, and works for Schannel, whose secrets live in LSASS but whose record keys
  are in the process. The secret scan remains for ChaCha20-Poly1305.
- **Snapshot timing (§3.2).** The program's first application-data chunk is held until a PSS VA clone
  is captured (tens of ms), so short-lived clients that exit right after their request are still
  caught. Retries follow on the live process while the connection is open.
- **HTTP/2 (§3.5) is decoded** (frames + HPACK), since pinned Go/rustls clients usually negotiate it.
- **Transparent redirect** (the "related work" in §7) is implemented in `Redirector.cs` with WinDivert,
  reflecting through loopback so Windows Firewall stays out of the path.

Validated against pinning clients: Go (TLS 1.2/1.3, AES-GCM/ChaCha20, HTTP/1.1 and HTTP/2), OpenSSL 3.5
(TLS 1.3 ChaCha20 and AES-256), Python 3.10, Windows curl and PowerShell 5.1 (Schannel), and inside the
sandbox with transparent capture. `usandbox --selftest` covers the crypto (RFC 8439/8448 vectors).

Audience: whoever implements the adversarial-grade HTTPS inspection path.

## 1. Why

Today's HTTPS inspection decrypts by standing in the middle with a per-run CA
(`CertificateAuthority.cs`, `ProxyServer.InspectTlsAsync`). That works for anything that
honours the throwaway account's trust store. It fails for an **adversarial** sample:

- it **pins** a certificate or key, so it rejects the usandbox cert and we fall back to
  passthrough (`RawTunnelAsync`), seeing only the host name; or
- it carries its **own trust list** (statically-linked rustls/BoringSSL, Go's embedded roots),
  so our env vars and account root store never apply; or
- it is **stripped and static**, so there are no exported `SSL_write`/`SSL_read` symbols to
  hook and it ignores `SSLKEYLOGFILE`; or
- it treats the presence of `SSLKEYLOGFILE`, a proxy env var, or an injected module as a signal
  that it is being watched and goes quiet.

What every one of those still cannot avoid: to speak TLS, the process **must hold the session
keys in its own address space** for the life of each connection. usandbox runs elevated and owns
the account the sample runs as, so it can read that memory. This note specifies recovering the
keys from memory and decrypting the ciphertext we already record — needing **nothing from the
process and leaving no artifact inside it.**

Relationship to the other options discussed:
- `SSLKEYLOGFILE` capture — cooperative only; defeated by static linking and by an evasive sample. Not this.
- In-process API hooking / DLL injection — the only path that can **block inline**, but detectable and fragile. A separate, later tier.
- **This note** — observation only (bytes are already forwarded), but robust against static/stripped/pinning binaries and invisible from inside the process.

Non-goal: this path **cannot block** a request on a pinned host, because decryption happens
out-of-band after the bytes are forwarded. Inline blocking stays with the MITM path and the
future hook tier. Say so in the README.

## 2. Threat model and scope

In scope: a hostile binary that pins / brings its own roots / is static+stripped, using a
**modern AEAD cipher suite** over TLS 1.2 or TLS 1.3. That covers essentially all current real
traffic.

Explicitly deferred (document as limits, do not block v1):
- Legacy CBC / MAC-then-encrypt suites.
- A binary that **zeroes keys immediately** after each record, or rolls its own crypto whose
  keys never sit in a scannable contiguous form.
- A sample that detects the whole analysis environment and refuses to run. Against that, the
  honest fallback is the behavioural signal usandbox already has (destinations, ports, timing,
  volume, blocked direct-connect attempts via `Wfp.cs`).

The AEAD tag is our friend: a correct key makes the record authentication tag verify, so we get a
**built-in, library-agnostic oracle** for "is this candidate the right key?" — no heuristics, no
guessing. This is the backbone of the whole technique.

## 3. How it works, end to end

```
 proxy sees passthrough TLS          snapshot sample's memory           decrypt recorded records
 ├─ record both byte streams         ├─ walk private committed regions  ├─ for each candidate secret:
 ├─ parse ClientHello  → client_rnd  ├─ entropy-filter windows            derive key+iv, AEAD-open
 ├─ parse ServerHello  → server_rnd, │   (32/48-byte, aligned)            first app record
 │                        cipher,    └─ collect key-sized candidates     ├─ tag verifies → keep secret
 │                        version                                        └─ decrypt whole stream
 └─ remember PID of the client
                                                                         reassemble → HTTP → Flow(s)
```

Four pieces:

1. **Recording** (extend the passthrough path). When a TLS connection is going to be passed
   through *and* extraction is enabled, do not blind-pipe. Forward in real time (never stall the
   sample) but also tee both directions into a bounded per-connection buffer, and parse the
   visible handshake for the inputs decryption needs.
2. **Snapshot** the sample's process memory at a moment when the keys are present.
3. **Scan** the snapshot for candidate secrets and **confirm** each by trial-decrypting the first
   application record (AEAD tag oracle).
4. **Decrypt + reassemble** the recorded records with the confirmed secret, decode the inner
   application protocol, and emit flow records.

### 3.1 What the proxy must record per connection

From the observed, un-decrypted handshake (all in cleartext on the wire):

- `client_random` — 32 bytes at a fixed offset in the ClientHello. `TlsClientHello.Parse` in
  `Http.cs` currently *skips* the random (`p = p[(2 + 32)..]`); add a variant or out-param that
  returns it.
- `server_random` — 32 bytes in the ServerHello. Needs a new small parser for the server's first
  handshake record (ServerHello): version, `server_random`, chosen `cipher_suite`, and detection
  of the `supported_versions` extension that marks **TLS 1.3** (the record-layer version stays
  0x0303 in 1.3, so you must read the extension, not the legacy version field).
- `cipher_suite` and negotiated TLS version — from ServerHello.
- The **ciphertext application records**, both directions, with their record sequence order
  preserved (sequence numbers are implicit: first application record in a direction is seq 0 for
  TLS 1.3 app keys; for TLS 1.2 GCM the per-record explicit nonce is on the wire and the 64-bit
  sequence number feeds the additional-data).
- The **client PID** (already on the `Flow`, from `ProxyServer.Identify` →
  `ProcessInfo.FindClientPid`). This is the process to snapshot.

Buffer bound: reuse `RuleSet.maxInspectBytes` semantics (see `Rules.cs` / README) so a long-lived
stream cannot grow memory without limit; once over budget, keep the first N bytes (enough to carry
the first app records for the oracle and a useful transcript prefix) and mark the flow truncated.

### 3.2 When to snapshot

Keys for TLS 1.3 are the most ephemeral (a careful library wipes the traffic secrets, and a key
update rotates them). Strategy:

- Trigger a snapshot **as soon as the first application-data record is seen** in either direction
  (handshake is done, app keys exist). Do not wait for connection close.
- If the first extraction attempt fails and the connection is still live, allow a small number of
  **repeat snapshots** on a timer; keep the most recent. Make cadence and count tunable.
- Prefer the **Process Snapshotting API** (`PssCaptureSnapshot` / `PssQuerySnapshot` /
  `PssFreeSnapshot`, kernel32) for a consistent, low-impact point-in-time view, or suspend the
  process' threads around a manual region walk. Avoid a full `MiniDumpWriteDump` to disk — it is
  slow, large, and a bigger observable event; read regions straight into our own memory.

### 3.3 Scanning the snapshot

Walk the address space with `VirtualQueryEx` + `MEMORY_BASIC_INFORMATION`; for each region that is
`MEM_COMMIT`, readable (`PAGE_READ*`/`PAGE_WRITECOPY`, not `PAGE_NOACCESS`/`PAGE_GUARD`), and
**`MEM_PRIVATE`** (session keys live on the heap, not in `MEM_IMAGE`/`MEM_MAPPED`), call
`ReadProcessMemory`.

Within each region, collect key-sized candidate windows:

- TLS 1.3: secret length = hash length of the suite's HKDF — 32 bytes (SHA-256 suites) or 48
  (SHA-384, e.g. `TLS_AES_256_GCM_SHA384`).
- TLS 1.2: the 48-byte `master_secret`.

Cut the cost (a browser heap is large):
- **Entropy pre-filter** — secrets are high-entropy random; skip windows whose Shannon entropy is
  below a threshold (drops code, zeroes, ASCII, pointers). Tunable.
- **Alignment** — scan pointer-aligned offsets (8, then 4) first; fall back to byte stride only if
  needed. Keys sit at allocation granularity.
- **Library fast-path (optional)** — if the suite/library is identifiable (e.g. OpenSSL's
  `SSL_SESSION` has a known `master_key` + `master_key_length` layout), jump straight to the field.
  Keep the generic brute scan as the fallback that works on static/stripped binaries.

### 3.4 Confirming a candidate (the oracle)

For each candidate secret, derive the record-protection keys and try to open the **first
application record** in the matching direction:

- **TLS 1.3** — `key = HKDF-Expand-Label(secret, "key", "", key_len)`,
  `iv  = HKDF-Expand-Label(secret, "iv",  "", iv_len)`; per-record nonce = `iv XOR seq`
  (seq starts at 0 with the app traffic keys). There are two app secrets to find:
  `client_application_traffic_secret_0` and `server_application_traffic_secret_0` — scan for both.
- **TLS 1.2** — PRF: `key_block = PRF(master_secret, "key expansion", server_random + client_random)`,
  split into the client/server write keys and (for GCM) salts; the explicit nonce is on the wire,
  the 64-bit sequence number feeds the AEAD additional-data.

Open the record with the derived key. **Tag verifies ⇒ correct secret.** No valid tag on any
candidate in the snapshot ⇒ record it as not-recoverable and move on (likely wiped-too-fast or an
unsupported suite).

Primitives available in .NET without extra dependencies:
- `System.Security.Cryptography.HKDF` (TLS 1.3 Expand-Label is HKDF-Expand with the structured
  `HkdfLabel` info — implement the label wrapper).
- `System.Security.Cryptography.AesGcm` and `ChaCha20Poly1305`.
- TLS 1.2 PRF (`P_hash` over HMAC-SHA256/384) is a short manual implementation.

v1 suite coverage (modern AEAD only):
`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3);
`ECDHE_*_AES_128_GCM_SHA256`, `ECDHE_*_AES_256_GCM_SHA384`, `ECDHE_*_CHACHA20_POLY1305` (TLS 1.2).

### 3.5 Decrypt, reassemble, surface

With the confirmed secret, decrypt every recorded record in order per direction, concatenate the
plaintext into the application stream, then decode:

- **HTTP/1.1** — reuse `HttpReader` / `HttpHead` in `Http.cs` over a stream wrapping the decrypted
  bytes.
- **HTTP/2** — pinned apps often negotiate h2 (ALPN is visible in the ClientHello). Needs a frame
  + HPACK decoder. **Defer to a follow-up milestone**; in v1, if the decrypted stream is h2, still
  report success with host, byte counts and a note, and optionally raw decrypted bytes, rather than
  parsed requests.

Emit via `Monitor`:
- `Flow.Kind = "https"`, `Flow.Outcome = "allowed"` (observation only — see §2),
- `Flow.Note = "decrypted via memory key extraction"`,
- headers/body on the `Flow` as the MITM path already populates them, so the WebView2 UI and JSON
  log need no change.

Rules still apply for **matching/reporting** (so `block`-intent rules can be surfaced as "would
have blocked"), but **enforcement is not possible** here; make that explicit in the flow note so
the UI does not imply a request was stopped when it was not.

## 4. Integration points (exact)

| Where | Change |
|---|---|
| `Http.cs` `TlsClientHello` | return `client_random`; add a `TlsServerHello` parser (server_random, cipher_suite, TLS1.3 via `supported_versions`). |
| `ProxyServer.cs` `RawTunnelAsync` / `HandleConnectAsync` | when extraction is enabled and the path is TLS passthrough, tee both directions into a bounded buffer and record handshake params + client PID; keep forwarding live. |
| **new** `KeyExtractor.cs` | input: PID + handshake params + recorded records; snapshot → scan → confirm → decrypt → reassemble; output plaintext streams or "not recoverable". |
| **new** `TlsCrypto.cs` | HKDF-Expand-Label, TLS 1.2 PRF, AEAD record open for the supported suites. |
| `Native.cs` | add `ReadProcessMemory`, `VirtualQueryEx` + `MEMORY_BASIC_INFORMATION`, PSS functions; access constants `PROCESS_VM_READ (0x10)` + `PROCESS_QUERY_INFORMATION (0x400)`; and **`AdjustTokenPrivileges` to enable `SeDebugPrivilege`** (admins hold it disabled by default; opening another user's process for VM_READ needs it on). |
| `SandboxSession.cs` | own the `KeyExtractor`, pass it to the proxy; gate on the new option. |
| `Program.cs` | new CLI flag, e.g. `--extract-keys` (alias `--deep`); mention it only works with `--network filter`/`open`. |
| `MainForm.cs` / `ui/` | no schema change needed; decrypted flows look like MITM flows but with the distinguishing note. Optionally a badge. |
| `README.md` | new subsection under HTTPS: what it does, that it is observation-only (no inline block), and the ceiling. |

Privilege note: usandbox already self-elevates via UAC (`app.manifest`, `Program.cs`). Enabling
`SeDebugPrivilege` is the one extra token step; do it once at session start when extraction is on,
and degrade gracefully (warn, skip extraction) if it cannot be enabled.

## 5. Milestones

1. **Crypto core** — `TlsCrypto.cs` + unit tests against known TLS 1.2/1.3 test vectors
   (RFC 8448 has full TLS 1.3 traces). No process memory yet; prove key→plaintext.
2. **Handshake capture** — client/server random, cipher, version, ciphertext recording on the
   passthrough path; log the captured params for a real passthrough connection.
3. **Memory snapshot + scan** — PSS snapshot, region walk, entropy/alignment filter, AEAD oracle;
   confirm against milestone-1 crypto. Target: find the key for a cooperative test client first.
4. **End-to-end on a pinning client** — a Go or rustls client with its own pinned root; confirm
   plaintext recovered while the MITM path fails. TLS 1.2 + 1.3, GCM + ChaCha20.
5. **HTTP/2 decode** (follow-up) — frame + HPACK so h2 flows parse into requests.

Each milestone should leave a runnable `--extract-keys` that is strictly additive to current
behaviour (off by default).

## 6. Open decisions for the implementer

- Snapshot mechanism: PSS vs thread-suspend + manual walk. (Recommend PSS.)
- Snapshot cadence and retention when the first attempt misses.
- Ciphertext buffer budget per connection and truncation policy.
- Entropy threshold and scan stride defaults (make them constants, easy to tune).
- Whether to ship the OpenSSL `SSL_SESSION` fast-path in v1 or rely on the generic scan only.
- h2 in v1 or deferred (recommended: deferred).
- Behaviour when the TLS-terminating process differs from the connecting PID (rare; a helper
  process). Start with the `Flow.Pid`; revisit if a real case appears.

## 7. Test plan

- Crypto unit tests on RFC 8448 (TLS 1.3) and a captured TLS 1.2 GCM session.
- A pinning client (Go with pinned cert; rustls with built-in roots) — the whole point: MITM
  fails, extraction succeeds.
- Matrix: TLS 1.2 and 1.3 × AES-GCM and ChaCha20-Poly1305.
- Negative: a client that wipes keys fast / an unsupported suite — confirm clean "not recoverable"
  with a useful note, no crash.
- Performance: scan wall-time and peak extra memory on a browser-sized heap; confirm the live
  forwarding is never stalled by snapshotting.
- Confirm no in-process artifact (no injected module, and in transparent mode no proxy env tell —
  note that transparent redirect is separate, related work).

## 8. The ceiling, stated plainly (for the README too)

This recovers keys the process is holding; it does not break cryptography. A binary that zeroes
keys the instant a record is sealed, uses custom crypto whose keys never form a scannable
contiguous secret, or detects and refuses the analysis environment, can still deny plaintext.
usandbox should say so, and lean on the behavioural signal it already collects for those cases.
