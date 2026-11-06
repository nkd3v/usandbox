# usandbox

Run a program as a throwaway standard Windows user that is deleted afterwards, and watch and filter
everything it does on the network, including HTTPS, without installing a certificate on your machine.

- **Throwaway account.** A hidden local standard user with a random name and password. The program runs
  as that user; when it and everything else running as that user have exited, the account, its profile
  and its staging folder are deleted.
- **Endpoint monitoring.** Every request, tunnel and connection attempt, with the process that made it.
  The *Endpoints* view sums them up per host:port.
- **Blocking by content.** Rules match on host, URL, method, headers and body (text or regex, after
  undoing gzip/deflate/br), for what the program sends and, optionally, what it receives.
- **HTTPS without touching your certificate stores.** See [HTTPS](#https) below.
- **WebView2 window** with live traffic, request/response details, endpoints, a rules editor and the
  sandbox's processes. A console mode (`--no-gui`) is also available.

`usandbox.ps1`, the original script, is still here. It does the throwaway-account part only, with no
network features and nothing to build.

## Build

Needs Windows 10/11 x64, the .NET 9 SDK, and the Microsoft Edge WebView2 Runtime (already installed
with Edge on current Windows).

```bash
dotnet publish src/USandbox -c Release -o dist
```

`dist\usandbox.exe` is the program. The machine that runs it needs the .NET 9 Desktop Runtime.

## Use

Double-click `usandbox.exe`, pick a program and press *Run in sandbox*, or pass the program on the
command line. usandbox asks for admin rights through UAC, because creating accounts and firewall
filters needs them; the sandboxed program itself runs without admin rights.

```
usandbox [options] [--] <program> [arguments...]

  --stage none|file|folder   copy the program somewhere the throwaway user can read it
                             (needed for programs inside your profile: Downloads, Desktop, ...)
  --cwd <dir>                working directory (default: the program's folder)
  --network <mode>           filter (default)  all traffic must go through the usandbox proxy;
                                               anything else is blocked and listed
                             open              proxy is set up, direct connections are allowed (listed)
                             off               no proxy, no blocking (direct connections listed)
                             none              no network except loopback
  --no-tls-inspect           do not decrypt HTTPS: only host names are visible and only
                             host rules apply to HTTPS
  --strict-tls               if a program rejects the usandbox certificate, keep failing
                             instead of passing that host through undecrypted
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
 sandboxed program ──(proxy settings)──► usandbox proxy (127.0.0.1, random port) ──► internet
        │                                  records, applies rules, decrypts HTTPS
        └──(anything else)──► WFP filter for the throwaway account's SID: blocked, and listed
```

1. **Proxy.** The throwaway account's own registry hive is set up before the program starts: the
   Windows proxy settings (used by WinINet, WinHTTP's IE-settings mode, .NET, Chrome/Edge, PowerShell…)
   and `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NODE_USE_ENV_PROXY` (curl, Python, Node, Go…). The proxy
   only accepts connections from processes running as the throwaway account; it finds the owner of
   each connection in the TCP table.
2. **Lock (`filter` and `none`).** A Windows Filtering Platform filter blocks every non-loopback
   connection made or accepted by the throwaway account's SID, so programs that ignore proxy settings
   cannot get around the proxy. The filters live in a *dynamic* WFP session, which Windows removes on
   its own when usandbox exits, even if it crashes. Blocked attempts are read back from WFP's own drop
   events and listed with the program path and destination (TCP and UDP). Nothing else on the machine
   is affected.
3. **Direct connections (`open` and `off`)** are found by polling the TCP table for the sandbox's
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
untouched, shows the host name (from CONNECT and the TLS SNI), and still applies host rules. The first
connection fails and later ones work. `--strict-tls` turns that fallback off, and a `passthrough` rule
sets it up in advance for hosts you know. `--no-tls-inspect` passes all HTTPS through.

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

- After a WebSocket upgrade, the connection is forwarded without being read. Non-HTTP data inside a
  tunnel, and HTTPS that is passed through, is forwarded without being read too.
- DNS lookups go through the Windows DNS Client service, not the sandboxed account, so they are neither
  listed nor blocked.
- Loopback (127.0.0.1, ::1) is not blocked, so the program can reach services listening locally.
- The firewall lock is per account. It is not a security boundary against a program that can escalate
  privileges.
- If usandbox is killed, the WFP filters disappear with it, but the account may be left behind, as with
  the original script. It is named `usbx-…`, with the description "Throwaway account created by
  usandbox".

## Testing aids

- `usandbox --proxy-only [--rules f] [--log f] [--no-tls-inspect]` runs just the proxy for the current
  user: no account, no lock, no admin rights. It prints the port and the CA file, so you can try rules
  with, for example, `curl -x 127.0.0.1:<port> --cacert <ca file> https://…`.
- Opening `src/USandbox/ui/index.html` through any local web server shows the window with sample data.

## Layout

| file | what it does |
|------|--------------|
| `src/USandbox/Program.cs` | command line, self-elevation, console mode, proxy-only mode |
| `src/USandbox/SandboxSession.cs` | one run: account → staging → proxy/CA/lock → program → cleanup |
| `src/USandbox/SandboxAccount.cs` | the throwaway account, its profile, hive settings and root store |
| `src/USandbox/Wfp.cs` | the WFP egress lock and its drop events |
| `src/USandbox/ProxyServer.cs` | HTTP/HTTPS proxy, TLS inspection and passthrough, rule enforcement |
| `src/USandbox/Http.cs` | HTTP/1.1 parsing, chunked bodies, decompression, TLS ClientHello parsing |
| `src/USandbox/CertificateAuthority.cs` | the per-run CA, per-host certificates and CRL |
| `src/USandbox/Rules.cs` | rule matching |
| `src/USandbox/Monitor.cs` | flow records and the JSON log |
| `src/USandbox/MainForm.cs`, `ui/` | the WebView2 window |
