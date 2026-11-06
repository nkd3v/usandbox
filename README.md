# usandbox

Run a program as a throwaway standard Windows user that is deleted afterwards, and watch and filter
everything it does on the network, including HTTPS, without installing a certificate on your machine.

- **Throwaway account.** A hidden local standard user with a random name and password. The program runs
  as that user; when it and everything else running as that user have exited, the account, its profile
  and its staging folder are deleted.
- **Transparent capture.** Every TCP connection the program makes is turned around into usandbox,
  whether or not it honours proxy settings (raw Winsock, WinHTTP, custom C2 protocols), with no
  proxy settings or other changes visible to the program. Needs the bundled WinDivert driver.
- **Endpoint monitoring.** Every request, tunnel and connection attempt, with the process that made it.
  The *Endpoints* view sums them up per host:port. Non-HTTP TCP is recorded too (first 256 KB each way).
- **Blocking by content.** Rules match on host, URL, method, headers and body (text or regex, after
  undoing gzip/deflate/br), for what the program sends and, optionally, what it receives.
- **HTTPS without touching your certificate stores.** See [HTTPS](#https) below.
- **HTTPS from pinning programs too.** TLS that cannot be intercepted is decrypted afterwards with the
  keys read out of the program's own memory. See [Keys from memory](#keys-from-memory).
- **WebView2 window** with live traffic, request/response details, endpoints, a rules editor and the
  sandbox's processes. A console mode (`--no-gui`) is also available.

usandbox is developed as a C# (.NET 9) app in `src/USandbox`. The earlier PowerShell script,
`usandbox.ps1`, has been removed; it is in the Git history if you need it.

## Build

Needs Windows 10/11 x64, the .NET 9 SDK, and the Microsoft Edge WebView2 Runtime (already installed
with Edge on current Windows). Publishing writes to `dist\` at the repository root:

```bash
dotnet publish src/USandbox -c Release
```

`dist\usandbox.exe` is the program. The machine that runs it needs the .NET 9 Desktop Runtime.
`WinDivert.dll` and `WinDivert64.sys` (from `third_party/WinDivert`, see its README for provenance)
are copied next to it; without them usandbox falls back to proxy settings.

## Use

Double-click `usandbox.exe`, pick a program and press *Run in sandbox*, or pass the program on the
command line. usandbox asks for admin rights through UAC, because creating accounts and firewall
filters needs them; the sandboxed program itself runs without admin rights.

```
usandbox [options] [--] <program> [arguments...]

  --stage none|file|folder   copy the program somewhere the throwaway user can read it
                             (needed for programs inside your profile: Downloads, Desktop, ...)
  --cwd <dir>                working directory (default: the program's folder)
  --network <mode>           filter (default)  all traffic must go through usandbox;
                                               anything else is blocked and listed
                             open              proxy is set up, direct connections are allowed (listed)
                             off               no proxy, no blocking (direct connections listed)
                             none              no network except loopback
  --capture <how>            how traffic reaches usandbox in filter mode:
                             transparent (default)  every TCP connection is redirected, even from
                                                    programs that ignore proxy settings
                             proxy                  proxy settings only; anything else is blocked
  --proxy-settings           with transparent capture, also give the program proxy settings
  --no-tls-inspect           do not decrypt HTTPS by impersonating servers
  --passive-tls              never impersonate servers or install a certificate: pass all TLS
                             through and decrypt it only with keys read from the program's memory
  --no-extract-keys          do not read TLS keys from the program's memory
  --strict-tls               if a program rejects the usandbox certificate, keep failing
                             instead of passing that host through
  --rules <file>             rules file (default: %APPDATA%\usandbox\rules.json)
  --log <file>               append every request/connection as a JSON line
  --no-gui                   console only; Ctrl+C stops the program and cleans up
```

Examples:

```bash
usandbox C:\Windows\System32\notepad.exe
```

```bash
usandbox --stage folder --no-gui --log flows.jsonl %USERPROFILE%\Downloads\tool\tool.exe --verbose input.txt
```

Closing the window while the program runs stops it and cleans up first.

## How the network part works

```
 sandboxed program ──(any TCP connection)──► WinDivert redirect ──► usandbox (transparent listener) ──► internet
        │                                                            records, applies rules, decrypts HTTPS
        ├──(proxy settings, if any)──► usandbox proxy (127.0.0.1) ──► internet
        └──(UDP, ICMP, inbound…)──► WFP filter for the throwaway account's SID: blocked, and listed
```

1. **Transparent capture (`filter`, the default).** usandbox opens WinDivert on outbound TCP. For
   each new connection (SYN) it looks up the owning process (WinDivert's socket events, with the TCP
   table as a fallback); if that process runs as the throwaway account, the connection is turned
   around through loopback: `A:sp → B:dp` becomes `127.0.0.1:sp → 127.0.0.1:P`, where usandbox
   listens, and usandbox's answers are rewritten to `B:dp → A:sp` and injected on the program's
   network interface, so the program sees `B:dp` answering. usandbox knows the real destination,
   connects there itself, and handles the stream like a proxy tunnel: TLS is intercepted or passed
   through and recorded, HTTP is parsed, anything else is forwarded and its first bytes are kept.
   Other programs' packets are reinjected untouched. Host names come from the TLS SNI, the HTTP
   `Host` header or, for raw TCP, DNS answers seen on the machine. No proxy settings are given to
   the program (`--proxy-settings` adds them), so there is less for it to notice. Going through
   loopback keeps Windows Firewall out of the way: it does not filter loopback, and the listener is
   never reachable from the network. (Reflecting to a listener on the real address, as the
   WinDivert "streamdump" sample does, works for a second or two and is then cut off by the
   firewall's per-program "Query User" filter.)
2. **Proxy (`--capture proxy`, `open`, or when WinDivert cannot load).** The throwaway account's own
   registry hive is set up before the program starts: the Windows proxy settings (used by WinINet,
   WinHTTP's IE-settings mode, .NET, Chrome/Edge, PowerShell…) and
   `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NODE_USE_ENV_PROXY` (curl, Python, Node, Go…). The proxy
   only accepts connections from processes running as the throwaway account; it finds the owner of
   each connection in the TCP table.
3. **Lock (`filter` and `none`).** A Windows Filtering Platform filter blocks every non-loopback
   connection made or accepted by the throwaway account's SID (with transparent capture: everything
   but outgoing TCP, which is redirected). The filters live in a *dynamic* WFP session, which Windows
   removes on its own when usandbox exits, even if it crashes. Blocked attempts are read back from
   WFP's own drop events and listed with the program path and destination (TCP and UDP). A sandbox
   TCP connection that somehow escaped redirection is listed as *Direct … NOT redirected*.
4. **Direct connections (`open` and `off`)** are found by polling the TCP table for the sandbox's
   processes. Their contents are not visible.

## HTTPS

Content rules need to see plaintext, and HTTPS hides it. The usual fix is to install a man-in-the-middle
root certificate into your certificate store. usandbox does not do that:

- **Each run makes its own certificate authority.** Its private key is generated in memory, never
  exported and never written to disk, and is gone when usandbox exits.
- **Only the throwaway account trusts it.** The CA certificate goes into that account's own root store,
  in its registry hive under `HKEY_USERS\<sid>`. It is written right after the profile is created and
  before anything runs as that account, so Windows includes it when it first sets up that store, with
  no prompt. Your account's stores and the machine's stores are not touched, and the hive is deleted
  with the profile.
- **The CRL is served by the proxy.** The per-host certificates point to a CRL at
  `http://127.0.0.1:<port>/usandbox-ca.crl`, so clients that insist on revocation checks (Windows curl,
  Schannel) pass them.
- **The proxy verifies real servers itself** against your machine's normal trusted roots before
  forwarding anything.
- **Programs with their own trust lists** are pointed at a PEM bundle in the staging folder through
  `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` (OpenSSL, Python), `NODE_EXTRA_CA_CERTS` (Node) and
  `JAVA_TOOL_OPTIONS` (Java uses the Windows store).

Tested inside the sandbox: Windows PowerShell 5.1, PowerShell 7 (.NET HttpClient), Windows curl.exe
(Schannel), plus Python requests, websockets and Node fetch (through the proxy).

Some programs will not accept the certificate: they pin certificates, or bring a trust list that
ignores these settings (Rust's rustls with built-in roots, for example). They also may only speak
HTTP/2 (gRPC). For those hosts usandbox falls back to **passthrough**: it forwards the encrypted bytes
untouched, shows the host name (from CONNECT and the TLS SNI), still applies host rules, and
decrypts the recording with [keys from memory](#keys-from-memory). The first connection fails and
later ones work. `--strict-tls` turns that fallback off, and a `passthrough` rule sets it up in
advance for hosts you know. `--no-tls-inspect` passes all HTTPS through; `--passive-tls` also leaves
out the certificate and its environment variables, for programs that look for signs of interception.

### Keys from memory

A program cannot speak TLS without holding the record keys in its own memory. For every TLS
connection that is passed through, usandbox records both directions and the handshake (randoms,
version, cipher suite). When the program sends its first application data, that one chunk is held
back for the moment it takes to capture a copy-on-write clone of the program's address space
(Process Snapshotting API, `PssCaptureSnapshot` with `PSS_CAPTURE_VA_CLONE`); the program is
waiting for its answer at that point, so its keys are certainly there. The clone is then scanned
in the background:

1. **AES key schedules.** Every mainstream TLS library keeps the expanded AES key schedule for as
   long as a connection lives (OpenSSL, BoringSSL/ring/rustls, Go, SymCrypt under Schannel), even
   when it has wiped the TLS secret it came from. A schedule is 176 or 240 self-consistent bytes,
   so it is found reliably in any byte order. A raw AES key is checked without knowing the IV: the
   GCM tag gives `J0 = AES⁻¹(tag ⊕ GHASH)`, and only the right key yields a `J0` ending in the
   counter `00000001` (and, for TLS 1.2, containing the explicit nonce on the wire).
2. **TLS secrets**, when AES schedules are not enough (ChaCha20-Poly1305 suites): high-entropy
   32/48-byte windows are tried as TLS 1.3 traffic secrets (HKDF-Expand-Label) or as the TLS 1.2
   master secret (PRF), and kept only if the record's authentication tag verifies.

A key is accepted only when it authenticates a recorded record, so there are no false positives.
Decrypted traffic is decoded as HTTP/1.1, HTTP/2 (frames and HPACK) or kept as raw bytes, and listed
like intercepted HTTPS with a note saying it came from memory keys. Nothing is injected into the
program and it is never modified. Reading another account's processes needs `SeDebugPrivilege`,
which usandbox enables (it already runs elevated).

Covers TLS 1.2 and 1.3 with AES-128/256-GCM and ChaCha20-Poly1305. Tested against pinning clients:
Go (TLS 1.2 and 1.3, HTTP/1.1 and HTTP/2), OpenSSL 3.5 `s_client`, Python 3.10, Windows curl and
Windows PowerShell 5.1 (Schannel).

What this cannot do:

- **Block.** Records are decrypted after they were forwarded. Rules are still matched and a `block`
  match is reported, but the request was not stopped. Interception (above) is what blocks.
- **Every program.** Legacy CBC suites are not supported. A program that wipes its keys the moment a
  record is sealed, uses its own crypto with keys that never sit in memory as one piece, or refuses
  to run under analysis can still deny plaintext; usandbox then shows host, timing and volume only.
- **Long-lived connections in real time.** A connection is decrypted when it closes (or when usandbox
  stops). TLS 1.3 key updates are followed only if the new key is found by a later look.

## Rules

Rules are JSON (`%APPDATA%\usandbox\rules.json` by default, editable in the window). They are tried from
top to bottom and the first match decides; with no match, the request is allowed and recorded. Every
field that is set must match:

| field      | meaning |
|------------|---------|
| `action`   | `block`, `allow` (skip the rules below), or `passthrough` (don't decrypt this host) |
| `host`     | glob(s): `*.example.com`, `a.com b.com` |
| `url`      | regular expression on the full URL |
| `method`   | `GET`, `POST`, … |
| `contains` | case-insensitive text |
| `regex`    | .NET regular expression |
| `target`   | where `contains`/`regex` look: `any` (default), `headers`, `body` |
| `stage`    | `request` (default), `response`, `both` |
| `enabled`  | `false` to keep a rule but switch it off |

```json
{
  "rules": [
    { "name": "No uploads of private keys", "action": "block", "regex": "-----BEGIN [A-Z ]*PRIVATE KEY-----", "target": "body" },
    { "name": "Telemetry", "action": "block", "host": "*.telemetry.example.com" },
    { "name": "Read-only API", "action": "block", "host": "api.example.com", "method": "POST" },
    { "name": "Pinned app", "action": "passthrough", "host": "*.pinned.example.org" }
  ],
  "maxInspectBytes": 8388608
}
```

A blocked request gets `403 Blocked by usandbox rule: …` and never reaches the server. A response
blocked by a `response` rule is replaced by that 403. A rule with only `host` refuses the connection
itself. Bodies up to `maxInspectBytes` are held back and checked whole; for larger ones only the start
is checked. Responses are held back only when a response rule exists, and server-sent event streams are
never held back. See `src/USandbox/rules.example.json` for more.

## Limits

- After a WebSocket upgrade, the connection is forwarded without being read. Non-HTTP data is
  forwarded as is; only its first 256 KB in each direction is kept for display.
- Transparent capture sends all of the machine's outgoing TCP packets through usandbox while a
  sandbox runs (other programs' packets are reinjected unchanged), which costs some throughput.
  Connections to the machine's own addresses are loopback and are not redirected. TCP over IPv6 is
  redirected the same way (to `::1`); TCP Fast Open and IPv6 extension headers before TCP are not.
- DNS lookups go through the Windows DNS Client service, not the sandboxed account, so they are neither
  listed nor blocked.
- Loopback (127.0.0.1, ::1) is not blocked, so the program can reach services listening locally.
- The firewall lock is per account. It is not a security boundary against a program that can escalate
  privileges.
- If usandbox is killed, the WFP filters disappear with it, but the account may be left behind. It is
  named `usbx-…`, with the description "Throwaway account created by usandbox".

## Testing aids

- `usandbox --proxy-only [--rules f] [--log f] [--no-tls-inspect] [--passive-tls]` runs just the proxy
  for the current user: no account, no lock, no admin rights. It prints the port and the CA file, so you
  can try rules with, for example, `curl -x 127.0.0.1:<port> --cacert <ca file> https://…`. Key
  extraction works here too (same-user processes can be read without elevation).
- `usandbox --selftest` checks the key-extraction cryptography (RFC 8439/8448 vectors, and AES, AES-GCM
  and key-schedule detection against the platform's own AES).
- `--transcript <file>` (with `--no-gui`) also writes the console output to a file and logs every
  redirected connection; useful because the elevated console closes with the run.
- `tools/tlsprobe` is a Go TLS server and pinning client (TLS 1.2/1.3, any suite, HTTP/1.1 or HTTP/2)
  for testing key extraction and transparent capture.
- Opening `src/USandbox/ui/index.html` through any local web server shows the window with sample data.

## Layout

| file | what it does |
|------|--------------|
| `src/USandbox/Program.cs` | command line, self-elevation, console mode, proxy-only mode |
| `src/USandbox/SandboxSession.cs` | one run: account → staging → proxy/CA/lock → program → cleanup |
| `src/USandbox/SandboxAccount.cs` | the throwaway account, its profile, hive settings and root store |
| `src/USandbox/Wfp.cs` | the WFP egress lock and its drop events |
| `src/USandbox/ProxyServer.cs` | HTTP/HTTPS proxy and transparent listener, TLS inspection and passthrough, rule enforcement |
| `src/USandbox/Redirector.cs` | transparent capture with WinDivert (per-process redirect, DNS names) |
| `src/USandbox/TlsRecording.cs` | records passed-through TLS (records, randoms, suite) |
| `src/USandbox/KeyExtractor.cs` | memory snapshots, key search, decryption of recorded TLS |
| `src/USandbox/TlsCrypto.cs` | HKDF/PRF, AES-GCM/ChaCha20-Poly1305 records, key schedules, GCM nonce recovery |
| `src/USandbox/PlaintextDecoder.cs`, `HpackTables.cs` | decrypted bytes to HTTP/1.1 and HTTP/2 flows |
| `src/USandbox/Http.cs` | HTTP/1.1 parsing, chunked bodies, decompression, TLS ClientHello parsing |
| `src/USandbox/CertificateAuthority.cs` | the per-run CA, per-host certificates and CRL |
| `src/USandbox/Rules.cs` | rule matching |
| `src/USandbox/Monitor.cs` | flow records and the JSON log |
| `src/USandbox/MainForm.cs`, `ui/` | the WebView2 window |
