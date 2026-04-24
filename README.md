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
| `blocks.json`     | per-device blocks (cleared on next supervised/open entry) |
| `schedule.json`   | weekly base transitions + pending one-shot overrides |
| `supervised.json` | domain suffixes that count as supervised targets  |
| `grants.json`     | per-device timed opens set via `POST /hosts/.../allow?minutes=` |
| `triggers.json`   | auto-issued 1-hour blocks from the supervisor     |

Alongside the JSONL event files and the Unix socket.  All five JSON files
are optional at startup — missing files are treated as empty (or, for
`schedule.json`, the hard-coded defaults).

## Modes and schedule

Three dhcp-range modes:

- **closed** (全禁, sleep) — every non-static IP in the dhcp-range is blocked.
- **supervised** (监管, no games) — passive: everyone is allowed *by default*,
  but the traffic aggregator watches per-device per-minute traffic.  A device
  whose traffic includes any domain listed in `supervised.json` for **5
  consecutive minutes** gets fully blocked for **1 hour**; after the hour is
  up, the counter resets (another 5 straight minutes are required to re-fire).
- **open** (全开) — mode contributes no blocks; only `blocks.json` applies.

Default weekly base (local time):

| Time   | Days              | Mode        |
|--------|-------------------|-------------|
| 07:00  | daily             | supervised  |
| 18:00  | daily             | open        |
| 22:30  | Mon/Wed/Thu/Sun   | closed      |
| 23:30  | Tue/Fri/Sat       | closed      |

One-shot overrides (`{at, mode, expires_at, reason}`) stack on top of the
base and are walked as a single sorted timeline — the latest entry with
`at <= now` and `(expires_at == 0 || expires_at > now)` wins.

Per-device **block / allow** semantics:

- `POST /hosts/{key}/block?reason=...` — disable the device. The entry
  lives in `blocks.json` and is **cleared automatically** the next time
  the mode transitions into supervised or open (i.e., at the morning
  wake, or whenever an override/manual mode change lifts closed).
  There is no permanent block; use a block to mean "pause until
  naturally reopened".
- `POST /hosts/{key}/allow?reason=...` — immediately undo the block.
  No time parameter, pure unblock.
- `POST /hosts/{key}/allow?minutes=N[&reason=...]` or `?until=<epoch>` —
  unblock **and** install a timed grant that punches through closed-mode
  too, i.e., the device stays online for N minutes even if the schedule
  is in closed. Grants persist in `grants.json`.
- `DELETE /hosts/{key}/allow` — revoke any active grant for this key
  (does not re-block; call `/block` if that's what you want).

## Socket API

JSON over HTTP/1.1 over a Unix socket.  A Go client with a custom
`DialContext` calls `http://wgatectl/...` directly.

Ad-hoc shell:

```sh
curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/status
curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/hosts | jq .
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST 'http://x/hosts/KP115/block?reason=noisy'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST 'http://x/hosts/KP115/allow?reason=unblocked-by-mom'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST 'http://x/hosts/alice/allow?minutes=30&reason=homework'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XDELETE http://x/hosts/alice/allow

curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/schedule | jq .
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/mode/closed
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST 'http://x/mode/open?until=1745629200'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST -H 'content-type: application/json' \
  http://x/schedule/override \
  -d '{"at":1745625600,"expires_at":1745629200,"mode":"closed","reason":"exam"}'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XDELETE http://x/schedule/override/ov_abc

curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/supervised | jq .
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/supervised/epicgames.com
curl --unix-socket /opt/wgatectl/wgatectl.sock -XDELETE http://x/supervised/epicgames.com

curl --unix-socket /opt/wgatectl/wgatectl.sock 'http://x/metrics/tail?since=0'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/reload
```

Routes:

| Method | Path                              | Purpose                                                 |
|--------|-----------------------------------|---------------------------------------------------------|
| GET    | `/status`                         | liveness, counters, current mode, next transition       |
| GET    | `/hosts`                          | every lease + any extra blocked keys; blocked entries carry `block_reason` / `block_added_at` |
| POST   | `/hosts/{ip\|name}/block`          | block this device (optional `?reason=`); cleared on next supervised/open entry |
| POST   | `/hosts/{ip\|name}/allow`          | unblock; with `?minutes=N` or `?until=<epoch>` also install a grant that survives closed mode (optional `?reason=`) |
| DELETE | `/hosts/{ip\|name}/allow`          | revoke an active grant (does not re-block)              |
| GET    | `/schedule`                       | current mode + base + pending overrides + active grants |
| POST   | `/schedule/override`              | add one-shot override (JSON body `{at,mode,expires_at,reason}`) |
| DELETE | `/schedule/override/{id}`         | remove a pending override                               |
| POST   | `/mode/{closed\|supervised\|open}` | force mode now; optional `?until=<epoch>`                |
| GET    | `/supervised`                     | list supervised domain targets + active triggers        |
| POST   | `/supervised/{domain}`            | add target                                              |
| DELETE | `/supervised/{domain}`            | remove target                                           |
| GET    | `/metrics/tail?since=<ts>`        | NDJSON tail of today's event file                       |
| POST   | `/reload`                         | re-read dnsmasq.conf, `schedule.json`, `supervised.json` |

Endpoints that don't need a body accept bodyless requests (as before).
`POST /schedule/override` is the only endpoint that *requires* a JSON
body (`content-type: application/json`).  The previous `POST /dhcp-range/block`
and `POST /dhcp-range/allow` routes are **removed** — use
`/mode/closed` and `/mode/open` instead.

## JSONL events

Written to `/opt/wgatectl/events-YYYYMMDD.jsonl`, one JSON object per
line.  `kind` is `traffic`, `system`, or `control`.

```json
{"ts":"2026-04-20T15:43:00-07:00","kind":"traffic","ip":"10.6.6.161",
 "name":"oneplus11","mac":"aa:bb:cc:dd:ee:ff","blocked":false,
 "domains":[{"name":"tiktok.com","bytes":3083371,"pkts":2417},
            {"name":"gstatic.com","bytes":12000,"pkts":30},
            {"name":"8.8.8.8","bytes":500,"pkts":5}]}

{"ts":"...","kind":"system","cpu_pct":12.3,"load":[0.42,0.31,0.28],
 "mem":{"used":..., "total":...},"disk":[...],"temp_c":[...],
 "uptime_s":184322,"iface":[...]}

{"ts":"...","kind":"control","action":"block","name":"KP115",
 "ip":"10.6.6.97","reason":"api"}

{"ts":"...","kind":"control","action":"closed",
 "name":"dhcp-range","reason":"schedule"}

{"ts":"...","kind":"control","action":"block","name":"alice",
 "ip":"10.6.6.12","reason":"supervised"}
```

`reason` is `api` for direct socket calls, `schedule` for mode-transition
edges, and `supervised` for trigger-fires from the supervisor.

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

The tail of FORWARD (after external rules) looks like:

```
-A FORWARD -i <lan> -m set --match-set wgate_allow dst -j ACCEPT
-A FORWARD -i <lan> -m set --match-set wgate_allow src -j ACCEPT
-A FORWARD -s <WG_STATIC_CIDR> -j ACCEPT                 # (if set)
-A FORWARD -i <lan> -s 10.6.6.99/32 -j ACCEPT            # active grant, only when mode=closed
-A FORWARD -s 10.6.6.159/32 -j DROP                      # per-device block
 …
-A FORWARD -i <lan> -j DROP                              # only when mode=closed
```

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
defense-in-depth.  Bindings are refreshed on startup, SIGHUP, and after
`POST /reload`; on graceful shutdown they are removed.

## Tests

```sh
make test          # builds + runs tests/test_schedule and tests/test_supervisor
```
