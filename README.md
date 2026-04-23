# wgatectl

A C daemon for a NanoPi R5C home gateway.  It sniffs LAN traffic on the
LAN interface (`eth1` by default), aggregates per-client traffic by DNS
name, exposes a per-minute JSONL event stream, and gates FORWARD traffic
per host through `iptables` + `ipset` so that OS connection checks keep
working even when a device is otherwise blocked.

wgatectl is the mechanical back-end for a sibling Go daemon,
`wgate-agent`, which owns all time-based policy (credit, schedules,
expiry).  wgatectl itself has **no scheduler**: it maintains a persisted
set of blocked hosts, applies it to iptables, and answers imperative
`block` / `allow` commands over a Unix-domain HTTP socket at
`/opt/wgatectl/wgatectl.sock`.

## Build

```sh
make            # produces ./wgatectl
make asan       # ASAN+UBSAN build for development
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

State lives at `/opt/wgatectl/blocks.json` (a plain JSON array of
blocked keys — IPs or names — persisted across restarts), alongside the
JSONL event files and the Unix socket.

## Socket API

JSON over HTTP/1.1 over a Unix socket.  A Go client with a custom
`DialContext` calls `http://wgatectl/...` directly.

Ad-hoc shell:

```sh
curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/status
curl --unix-socket /opt/wgatectl/wgatectl.sock http://x/hosts | jq .
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/hosts/KP115/block
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/hosts/KP115/allow
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/hosts/10.6.6.161/block
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/dhcp-range/block
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/dhcp-range/allow
curl --unix-socket /opt/wgatectl/wgatectl.sock 'http://x/metrics/tail?since=0'
curl --unix-socket /opt/wgatectl/wgatectl.sock -XPOST http://x/reload
```

Routes:

| Method | Path                          | Purpose                                    |
|--------|-------------------------------|--------------------------------------------|
| GET    | `/status`                     | liveness + counters                        |
| GET    | `/hosts`                      | every lease + any extra blocked keys       |
| POST   | `/hosts/{ip\|name}/block`      | add to block list, apply DROP rule         |
| POST   | `/hosts/{ip\|name}/allow`      | remove from block list, drop DROP rule     |
| POST   | `/dhcp-range/block`           | block every dynamic-range IP (non-static)  |
| POST   | `/dhcp-range/allow`           | unblock every dynamic-range IP             |
| GET    | `/metrics/tail?since=<ts>`    | NDJSON tail of today's event file          |
| POST   | `/reload`                     | re-read dnsmasq.conf                       |

No request body is required on any endpoint.  The set of blocked keys is
the single source of truth; the agent is responsible for any time-based
grants (it schedules its own follow-up `block` call).

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
```

Domain labelling comes solely from sniffed DNS responses; unresolved
server IPs appear as their dotted-quad string.  The top 64 domains per
client per minute are emitted verbatim; anything beyond is folded into a
single `{"name":"...other",...}` tail entry.

## Captive-check model

At start, wgatectl creates `ipset wgate_allow hash:ip` and inserts two
ACCEPT rules at FORWARD slots 1 and 2:

```
-I FORWARD 1 -m set --match-set wgate_allow dst -j ACCEPT
-I FORWARD 2 -m set --match-set wgate_allow src -j ACCEPT
```

A static list of captive-check FQDNs (`connectivitycheck.gstatic.com`,
`captive.apple.com`, `www.msftconnecttest.com`, and friends) lives in
`ipset_mgr.c`.  When a DNS response for any of those names is observed,
every returned A record is added to `wgate_allow`, so per-host
`-A FORWARD -s <ip> -j DROP` rules still let OS connectivity probes
succeed — blocked devices stay "online" from the OS's point of view.

## Tests

```sh
make asan
tests/test_revmap   # DNS reverse-map unit test (TODO)
```
