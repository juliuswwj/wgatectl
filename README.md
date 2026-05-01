# wgatectl

A C daemon for a NanoPi R5C home gateway.  It sniffs LAN traffic on the
LAN interface, aggregates per-client traffic by DNS name, exposes a
per-minute JSONL event stream, gates FORWARD traffic through `iptables`
+ `ipset` so that OS connection checks keep working even when a device
is otherwise blocked, and ARP-pins the static-assignment zone so that
spoofing is not possible.

wgatectl is self-contained: it owns the packet capture, iptables/ipset
reconciliation, static-zone ARP binding, metrics, JSONL stream, the
Unix-socket control plane, **and** the time-of-day scheduler that drives
the dhcp-range between three modes.

## Build

```sh
make            # produces ./wgatectl
make asan       # ASAN+UBSAN build for development
make test       # build and run unit tests
sudo make install
```

Requires `libpcap`, `iptables`, `ipset`.

## Run

```sh
sudo cp systemd/wgatectl.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wgatectl
```

Manually (needs `CAP_NET_ADMIN` + `CAP_NET_RAW`, typically root):

```sh
sudo ./wgatectl -v
```

## Configuration

`/etc/wgatectl.conf` (`KEY=VALUE`); environment variables of the same name
override the file.  See `examples/wgatectl.conf.example`.

State lives under `/opt/wgatectl/`:

| File              | Contents                                          |
|-------------------|---------------------------------------------------|
| `schedule.json`   | weekly base transitions + pending one-shot overrides |
| `filterd.json`    | domain suffixes whose A-record IPs are dropped in `filtered` mode |
| `pins.json`       | per-host fixed-mode pins (mode + expiry)          |
| `hosts.json`      | per-MAC `first_seen`/`last_seen` (epoch seconds) for the `/hosts` timestamps; survives restarts |

Alongside the JSONL event files and the Unix socket.  All four JSON
files are optional at startup — missing files are treated as empty (or,
for `schedule.json`, the hard-coded defaults).

A legacy `supervised.json` from the previous design is silently imported
as `filterd.json` on first start and a one-shot `INFO` log is emitted;
rename it to `filterd.json` to silence the message.

## Modes and schedule

Three dhcp-range modes:

- **closed** (全禁, sleep) — every non-static IP in the dhcp-range is blocked.
- **filtered** (过滤, no games) — only traffic to IPs that resolved from
  domains listed in `filterd.json` is dropped; everything else passes.
  Passive DNS sniffing populates the `wgate_filterd` ipset; entries age
  out after 10 minutes if a domain stops being resolved.
- **open** (全开) — no global filter; only per-host pins apply.

Default weekly base (local time):

| Time   | Days              | Mode      |
|--------|-------------------|-----------|
| 07:00  | daily             | filtered  |
| 09:00  | Sat/Sun           | open      |
| 18:00  | daily             | open      |
| 23:00  | Sun/Mon/Wed/Thu   | closed    |
| 23:30  | Tue               | closed    |
| 00:00  | Sat/Sun           | closed    |

One-shot overrides (`{at, mode, expires_at, reason}`) stack on top of the
base and are walked as a single sorted timeline — the latest entry with
`at <= now` and `(expires_at == 0 || expires_at > now)` wins.

Per-host **fixed-mode pin**: `POST /hosts/{key}/mode` body
`{"mode":"closed|filtered|open","minutes":N|"until":<epoch>,"reason":"..."}`.
A pin overrides the global mode for that host until expiry. There is
**no permanent pin** — `until` (or `minutes`) MUST resolve to a future
timestamp; if you need a permanent allow for a host put it in
`WG_STATIC_CIDR`. `until` wins over `minutes` when both are given.
`DELETE /hosts/{key}/mode` removes the pin. Pins are realised via the
`wgate_pin_open` / `wgate_pin_closed` / `wgate_pin_filt` ipsets.

## Socket API

JSON over HTTP/1.1 over a Unix socket.  A Go client with a custom
`DialContext` calls `http://wgatectl/...` directly.

Ad-hoc shell:

```sh
curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/status
curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/hosts | jq .
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST -H 'content-type: application/json' \
  http://x/hosts/alice/mode \
  -d '{"mode":"open","minutes":30,"reason":"homework"}'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST -H 'content-type: application/json' \
  http://x/hosts/KP115/mode \
  -d '{"mode":"closed","minutes":120,"reason":"noisy"}'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XDELETE http://x/hosts/alice/mode
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST 'http://x/hosts/10.6.6.42/name?name=alice-phone'

curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/schedule | jq .
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/mode/closed
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST 'http://x/mode/open?until=1745629200'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST -H 'content-type: application/json' \
  http://x/schedule/override \
  -d '{"at":1745625600,"expires_at":1745629200,"mode":"closed","reason":"exam"}'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XDELETE http://x/schedule/override/ov_abc

curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/filtered | jq .
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/filtered/epicgames.com
curl --unix-socket /opt/wgatectl/wgatectl.sock -XDELETE http://x/filtered/epicgames.com

curl --unix-socket /opt/wgatectl/wgatectl.sock 'http://x/metrics/tail?since=0'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/reload

curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/pve | jq .
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/pve/wake
```

Routes:

| Method | Path                              | Purpose                                                 |
|--------|-----------------------------------|---------------------------------------------------------|
| GET    | `/status`                         | liveness, counters, current mode, next transition       |
| GET    | `/hosts`                          | every lease; entries carry `first_seen_unix` / `last_seen_unix` when the MAC is known; pinned entries carry `pinned: true` and `pin_mode` |
| POST   | `/hosts/{ip\|name}/mode`           | pin this host to a fixed mode for a time window — JSON body `{mode, minutes\|until, reason}` |
| DELETE | `/hosts/{ip\|name}/mode`           | remove the active pin                                   |
| POST   | `/hosts/{ip\|name\|mac}/name?name=<new>` | set the DHCP-reservation name for this device — rewrites `dnsmasq.conf` + debounced reload |
| GET    | `/schedule`                       | current mode + base + pending overrides                 |
| POST   | `/schedule/override`              | add one-shot override (JSON body `{at,mode,expires_at,reason}`) |
| DELETE | `/schedule/override/{id}`         | remove a pending override                               |
| POST   | `/mode/{closed\|filtered\|open}`   | force mode now; optional `?until=<epoch>`                |
| GET    | `/filtered`                       | list filterd domain targets                             |
| POST   | `/filtered/{domain}`              | add target                                              |
| DELETE | `/filtered/{domain}`              | remove target                                           |
| GET    | `/metrics/tail?since=<ts>`        | NDJSON tail of today's event file                       |
| POST   | `/reload`                         | re-read dnsmasq.conf, `schedule.json`, `filterd.json`, `pins.json` (also runs automatically when `dnsmasq.conf` / `dnsmasq.leases` mtime changes) |
| GET    | `/pve`                            | parallel `ping` of `pve` / `mint` / `twin` (looked up in leases) — each entry is `up`, `down`, or `unknown` |
| POST   | `/pve/wake`                       | send a WoL magic packet to `WG_PVE_MAC` on the LAN broadcast (UDP/9) |

Endpoints that don't need a body accept bodyless requests.
`POST /schedule/override` and `POST /hosts/{key}/mode` *require* a JSON
body (`content-type: application/json`).

## JSONL events

Written to `/opt/wgatectl/events-YYYYMMDD.jsonl`, one JSON object per
line.  `kind` is `traffic`, `system`, `control`, or `lease`.

```json
{"ts":"2026-04-20T15:43:00-07:00","kind":"traffic","ip":"10.6.6.161",
 "name":"oneplus11","mac":"aa:bb:cc:dd:ee:ff",
 "domains":[{"name":"tiktok.com","bytes":3083371,"pkts":2417},
            {"name":"gstatic.com","bytes":12000,"pkts":30},
            {"name":"8.8.8.8","bytes":500,"pkts":5}]}

{"ts":"...","kind":"system","cpu_pct":12.3,"load":[0.42,0.31,0.28],
 "mem":{"used":..., "total":...},"disk":[...],"temp_c":[...],
 "uptime_s":184322,"iface":[...]}

{"ts":"...","kind":"control","action":"pin","name":"alice",
 "ip":"10.6.6.12","reason":"open"}

{"ts":"...","kind":"control","action":"closed",
 "name":"dhcp-range","reason":"schedule"}

{"ts":"...","kind":"lease","action":"add","mac":"aa:bb:cc:dd:ee:01",
 "ip":"10.6.6.5","name":"ipad"}

{"ts":"...","kind":"lease","action":"remove","mac":"aa:bb:cc:dd:ee:01",
 "ip":"10.6.6.5","name":"ipad","reason":"expired"}
```

For `control` events `action` is `pin` / `unpin` for per-host mode pins,
or one of `closed` / `filtered` / `open` for global mode transitions
(then `name="dhcp-range"`). `reason` is `api` for socket calls,
`schedule` for mode-transition edges, or the chosen mode name for pins.

For `kind=lease`, `action` is `add` (a MAC just appeared in
`dnsmasq.leases`) or `remove`. On `remove`, optional `reason` is
`replaced` if a different MAC now holds the same IP, else `expired`.
The events fire whenever `dnsmasq.leases` changes on disk
(mtime-driven, no polling).

Domain labelling comes solely from sniffed DNS responses; unresolved
server IPs appear as their dotted-quad string.  The top 64 domains per
client per minute are emitted verbatim; anything beyond is folded into a
single `{"name":"...other",...}` tail entry.

## FORWARD layout

At every reconcile, wgatectl removes its own rules from FORWARD and
appends a fresh, contiguous block at the tail.  External rules
(DOCKER-*, `-i wan` …) stay untouched.  Each wgatectl rule is tagged
with `-m comment --comment wgatectl`, which is what lets us identify
ours without clashing.

A per-state signature is cached, so when the desired set is unchanged
the entire `iptables -S FORWARD` + delete + re-append pass is skipped.
The `iptables: +N -M` log line therefore only appears when something
real changed (block/allow, override, trigger fired/expired, mode
edge).  The downside: external tampering — e.g. someone manually
flushing FORWARD — is not auto-healed until the next real change or a
`POST /reload`.

The tail of FORWARD (after external rules) looks like:

```
-A FORWARD -i <lan> -m set --match-set wgate_allow      dst -j ACCEPT
-A FORWARD -s <WG_STATIC_CIDR> -j ACCEPT                                # (if set)
-A FORWARD -i <lan> -m set --match-set wgate_pin_open   src -j ACCEPT
-A FORWARD -i <lan> -m set --match-set wgate_pin_closed src -j DROP
-A FORWARD -i <lan> -m set --match-set wgate_pin_filt   src \
                    -m set --match-set wgate_filterd    dst -j DROP
-A FORWARD -i <lan> -m set --match-set wgate_pin_filt   src -j ACCEPT
# global mode tail:
-A FORWARD -i <lan> -j DROP                                             # closed
# or:
-A FORWARD -i <lan> -m set --match-set wgate_filterd dst -j DROP        # filtered
# or nothing (open).
```

The chain is stateless (no `-m state`). When a pin or global mode flips,
in-flight TCP fails through retransmission/RST — same behaviour as before.

FORWARD's default policy is ACCEPT, so traffic that falls off the end
of our block is already allowed; we deliberately do not append a
trailing `-j ACCEPT` that would mask admin-added DROPs below.

Requires the `iptables-mod-comment` (xt_comment) module, which is
standard in modern iptables installs.

## Captive-check model

`ipset wgate_allow hash:ip` plus the two `-i <lan> --match-set wgate_allow`
ACCEPT rules above let traffic to/from known captive-check FQDNs through
before any DROP fires.  A static list of captive-check hostnames
(`connectivitycheck.gstatic.com`, `captive.apple.com`,
`www.msftconnecttest.com`, …) lives in `ipset_mgr.c`; when a DNS response
for any of those names is observed, every returned A record is added to
`wgate_allow`, so per-host `-s <ip>/32 -j DROP` rules still let OS
connectivity probes succeed — blocked devices stay "online" from the
OS's point of view.

## Static-zone ARP binding

Set `WG_STATIC_CIDR` (e.g. `10.6.6.0/27`) and wgatectl proactively pins
the whole range in the LAN interface's ARP cache using `ip neigh
replace … nud permanent`.  For each IP inside the CIDR:

- if dnsmasq.conf has a `dhcp-host=MAC,IP,NAME` entry, the real MAC is
  pinned so spoofing is impossible;
- otherwise the slot is pinned to a DUMMY MAC (`02:00:00:00:de:ad`) so
  traffic to it black-holes.

`dhcp-host` entries whose IP falls outside the CIDR are pinned too for
defense-in-depth.  Bindings are refreshed on startup, SIGHUP, after
`POST /reload`, and automatically when `dnsmasq.conf`'s mtime changes
(picked up at the next minute boundary, so external edits + a dnsmasq
restart don't need a manual signal).  On graceful shutdown they are
removed.

## Tests

```sh
make test          # builds + runs tests/test_schedule, test_pins, test_filterd, test_dnsmasq_conf
```
