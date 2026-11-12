# Trainspotter build plan

Written for the agent who builds this. Read all of it before writing code.

## What it is

A program you run on your own computer. It watches which hosts the machine contacts and draws them live as stops on a transit map, in your browser. It only watches. It never changes, blocks or sends traffic.

## Priorities, in order

1. **Trust.** Security people must be able to read the whole thing. Zero third-party packages. Small code. No outbound connections, ever. If a feature costs trust, drop the feature.
2. **A live map of real stops.** Every host the machine contacts shows up within a second or two.
3. **What leaks at each stop.** Filled in from the ETA data set and always labelled as inferred.
4. **Easy to run.** Double-click, give permission once, map opens. Mac first, then Linux, then Windows.

When two of these conflict, the lower number wins.

## Hard rules

- Go standard library only. `go.mod` has no `require` lines. Not even `golang.org/x/...`.
- No cgo (`CGO_ENABLED=0`).
- The web page is plain HTML, CSS and JS. No framework, no build step, no external fonts, scripts or images.
- The program opens no outbound connection. No update check, no telemetry, no reverse DNS lookups, no fetching the registry. The host registry ships inside the binary.
- No proxy, no certificate, no decryption. Host names only.
- The web server binds to `127.0.0.1` only.
- Nothing is written to disk unless the user clicks export.
- Never show made-up data. An unknown host is shown as unknown.
- Code that runs as root or admin stays tiny and does no parsing (see Privilege).

## Not building

- Phones.
- Blocking or firewall rules.
- Telling which browser extension made a request. The OS only knows "Chrome".
- Reading what is inside a request.

## How it works

```
network card
   │  raw packets
   ▼
capture helper (root, tiny, per OS)  ──frames over a local pipe──▶  main program (normal user)
                                                                     ├─ decode IP / TCP / UDP
                                                                     ├─ find the host name
                                                                     ├─ look it up in the registry
                                                                     └─ local web server ──SSE──▶ map page
```

### 1. Capture (one small file per OS)

Read raw packets with system calls from the `syscall` package.

- **macOS:** open `/dev/bpfN`, bind it to an interface, read. One device per interface. Handle link types Ethernet, NULL (loopback, `utun` VPN tunnels) and RAW. Check whether `syscall` still exposes the BPF helpers on darwin (`SetBpfInterface`, `SetBpfImmediate`, `BpfBuflen`); if not, call `ioctl` directly.
- **Linux:** `AF_PACKET` socket. `SOCK_DGRAM` strips the link header, which removes a parsing step. Needs root or `CAP_NET_RAW`.
- **Windows:** unverified, do a spike before committing. Options, in order of preference:
  1. Raw socket with `SIO_RCVALL`. No driver, needs admin. Check it sees outbound packets, IPv6, and works with the firewall on.
  2. ETW providers `Microsoft-Windows-DNS-Client` and `Microsoft-Windows-Kernel-Network`. No packets at all, gives names and process ids, but needs callback plumbing through `syscall`.
  3. The built-in `pktmon` tool in real-time mode, parsed from its output.
  
  Do not require Npcap. A driver install breaks priority 1.

Watch every active interface, and notice when interfaces come and go (Wi-Fi change, VPN connect).

### 2. Find the host name

For each new outbound flow, try these in order. Record which one worked.

1. **TLS server name (SNI)** from the ClientHello. Try this on any TCP port, not just 443.
   - Chrome's ClientHello no longer fits in one packet (post-quantum key share) and it shuffles extension order, so the server name is often in the second packet. Keep the first few kilobytes of each new flow, in sequence order, until the ClientHello is complete. Then forget the flow's payload.
2. **QUIC** (UDP 443). The ClientHello is inside the Initial packet, encrypted with keys derived from a public value in the packet itself (RFC 9001 section 5; version 2 uses a different salt, RFC 9369). Decrypting it needs HKDF-SHA256, AES-128-GCM and AES-ECB, all in the standard library (`crypto/hkdf` needs Go 1.24+). Chrome splits the ClientHello across several Initial packets and scrambles the CRYPTO frame order, so reassemble by offset. This is the hardest parser. It gets its own milestone.
3. **HTTP Host header** for plaintext port 80.
4. **DNS answers** seen on port 53: keep a table of IP → name and use it when 1 to 3 give nothing. This is a fallback only. Chrome often uses encrypted DNS, so many lookups never appear on port 53.
5. **Nothing worked:** show the stop as its IP address and port, labelled "name hidden". If the SNI is an Encrypted Client Hello front (for example `cloudflare-ech.com`), say so.

Every outbound connection becomes an event, named or not. A connection we cannot name is still a stop.

### 3. Registry: from host to stop

The ETA data set already maps hosts to actors, actors to categories, and actors to the kinds of data they were seen receiving in lab captures. Files: `actors-computed.json` (hosts and `datatypes` per actor), `categories.json` (category, `zero_option` grade), `datatypes.json` (names and grades).

- Write a small Go tool (`go run ./internal/tools/registry <path to ETA data dir>`) that reduces those three files to one `registry/registry.json`. Commit the output so changes are reviewable in a diff. Embed it with `embed`.
- The ETA Live browser extension already does this for its own format in `build_registry.py`, including suffix rules for hosts like `*.ingest.sentry.io`. Port its matching rules.
- On the maintainer's machine the data is at `../strawmapuserflow/data/` and the extension at `../strawmapuserflow/extension/`. The published per-route data is at github.com/austintgriffith/ethereum-transit-authority under `data/`.
- A host not in the registry is its own stop, labelled "not in registry". Do not guess its owner.

### 4. What each stop shows

Keep observed and inferred visibly separate.

| Observed on this machine | Inferred from the registry |
|---|---|
| Host name, or IP if hidden | Who runs it (actor, company) |
| How the name was found (SNI, QUIC, HTTP, DNS) | Category and its line on the map |
| First and last contact, number of connections | Data this actor typically receives |
| That it received your IP address | How hard it is to do without (`zero_option`) |

### 5. Web server and page

- `net/http` on `127.0.0.1`, random free port. Live events over Server-Sent Events. No WebSocket (it would need a package or a lot of code).
- Any website open in the user's browser can try to call a localhost server. Defend against it:
  - Require a random per-run token in the URL. Reject requests without it.
  - Reject any request whose `Host` header is not `127.0.0.1:<port>`. This stops DNS rebinding.
  - Send no CORS headers. Set `Content-Security-Policy: default-src 'self'`.
- The page: port the ETA Live side panel (`panel.html`, `panel.css`, `panel.js`, about 265 lines). It already draws stations grouped into category lines and already runs as a standalone page with a replay mode. Replace its `chrome.runtime` port with `EventSource`. Keep the replay mode; it is the easiest way to test the page.
- Event shape, kept close to the panel's existing `net` events:
  ```json
  {"t": 1760000000000, "kind": "conn", "host": "mainnet.infura.io", "ip": "…", "port": 443,
   "proto": "tcp", "named_by": "sni", "actor": "infura", "cat": "rpc"}
  ```
- Copy rules for the page: plain words, no filler, no callout boxes.
- Export button: saves the session as a JSON file the replay mode can load.

### 6. Privilege

Reading packets needs root or admin. Parsing untrusted packets as root is the classic way packet tools get exploited, so split it:

- **Helper** (`trainspotter capture`): the same binary re-run with elevated rights. It opens the capture handle and copies raw frames to a local pipe. Nothing else. No parsing, no network, no files. Target under 200 lines per OS, so anyone can read the entire root surface.
- **Main program:** runs as the normal user. Does all parsing, the registry lookup and the web server.
- The pipe is a Unix socket in a directory only the user can read (named pipe on Windows). The helper exits when the pipe closes.
- Asking for permission:
  - macOS: `osascript` "do shell script … with administrator privileges" shows the standard password box.
  - Linux: `pkexec` if present, otherwise print the `sudo` command. Document `setcap cap_net_raw+ep` as the no-password option.
  - Windows: relaunch the helper with `ShellExecuteW` and the `runas` verb, which shows the UAC prompt.

For the first milestone, skip the prompt: run `sudo ./trainspotter`, open the capture handle, then drop to the calling user before parsing anything.

## Suggested layout

```
cmd/trainspotter/        main, flags, opens the browser
internal/capture/        capture.go + capture_darwin.go, _linux.go, _windows.go
internal/packet/         IP, TCP, UDP decoding
internal/flows/          flow table, first-bytes reassembly
internal/names/          tls.go, quic.go, http.go, dns.go
internal/registry/       embedded data + host matching
internal/server/         HTTP, SSE, token and Host checks
internal/elevate/        per-OS permission prompt
internal/tools/registry/ builds registry/registry.json from ETA data
web/                     index.html, map.js, map.css
registry/registry.json   generated, committed
testdata/                captured packets as fixtures
```

## Milestones

Each one ends with something that runs.

1. **Mac spike: names in a terminal.** `sudo ./trainspotter` prints one line per new outbound connection with its host name, from TLS SNI, HTTP and DNS. No web page. Then measure: run a wallet send in Chrome, and report what share of connections got a name and what share of the hosts in the matching lab capture were seen. This number decides how urgent QUIC is. Do not continue until it is known.
2. **Live page.** Local server, token and Host checks, SSE, a plain live list of stops in the browser.
3. **Registry and map.** Build tool, embedded registry, ported transit-map page, observed versus inferred shown separately.
4. **QUIC names.**
5. **Privilege split and double-click on Mac.** Helper process, password prompt, `.app` bundle (a folder with an `Info.plist` and the binary; build it with a shell script).
6. **Linux.**
7. **Windows.** Starts with the capture spike above.
8. **Releases.** Reproducible builds (`-trimpath`, pinned Go version, `CGO_ENABLED=0`), published checksums, signing.

Later, not planned: which app made each connection (per-OS process lookup); letting the ETA Live extension feed page-level detail into the same map.

## Testing

- Parsers are tested against real captured packets stored in `testdata/`. Include a Chrome ClientHello split across two packets and a Chrome QUIC Initial split across several.
- Fuzz every parser with `go test -fuzz`. They read hostile input.
- Server tests: wrong token, wrong `Host`, cross-site request all rejected.
- A test that fails the build if `go.mod` gains a dependency or any file under `web/` references an external URL.
- A test that runs the program and fails if it opens any socket other than the capture handle and the localhost listener.

## Decisions the maintainer still has to make

- **Signing.** Without an Apple Developer ID and a Windows certificate, both systems warn before opening the app. Both cost money.
- **Publishing the registry.** `registry.json` puts the actor and data-type rollup in this public repo. The route data is already public; the rollup file is not.
- **Minimum Go version.** 1.24 or later if `crypto/hkdf` is used for QUIC.
