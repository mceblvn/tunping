# tunping

If `ping` shows `0.01 ms` with `ttl=64` after you enable the VPN, the ping is
intercepted and answered locally. ICMP lies.
`tunping` measures the real latency instead.

> This is **NOT ICMP.** `tunping` times an HTTPS round-trip (`HEAD /` → first
> response byte) over one persistent connection.

## Background

- SOCKS-TUN mode (`tun2socks`/XRay-style): `ping` and `hping -S` /
  `mtr --tcp` are all answered by the local TUN device, so they report
  garbage, typically under 1 ms.
- `tunping` works in that case because it times payload, not handshake.

## What it looks like

With the VPN on, `ping` outputs:

```
$ ping 1.1.1.1
64 bytes from 1.1.1.1: icmp_seq=1 ttl=64 time=0.01 ms

$ ping 192.0.2.1    # TEST-NET answers (it should never)
64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.01 ms

$ traceroute -n 1.1.1.1
 1  * * *
 2  * * *
```

The true round-trip is way slower:

```
$ tunping 1.1.1.1 -c 1
response from 1.1.1.1 (1.1.1.1): seq=1 ttfb=100.0 ms
```

## Install

```bash
pip install -e .
```

Python >= 3.10, stdlib only, no deps.

## Use

```bash
tunping 1.1.1.1 -c 4
tunping 1.1.1.1 -c 4 --json
tunping example.com -c 10 -i 0.5 --port 443 --timeout 5
tunping 1.1.1.1 --proto http --port 80 -c 2
tunping 1.1.1.1 --sni cloudflare-dns.com --insecure -c 2  # SNI override
```

Output mimics ping by default:

```
TUNPING 1.1.1.1 (1.1.1.1:443) with HTTPS TTFB (not ICMP; for TUNs that answer ping locally)
response from 1.1.1.1 (1.1.1.1): seq=1 ttfb=182.4 ms
...
--- 1.1.1.1 tunping statistics ---
4 transmitted, 4 received, 0.0% loss
rtt min/avg/max/mdev = 181.2/183.1/185.4/1.5 ms
jitter = 2.1 ms
```

JSON (`--json`): one object per probe `{"type":"probe",...}` plus final
`{"type":"summary",...}` — handy for graphs.

Exit codes: `0` if any probe succeeded, `1` if all lost, `2` on usage error.

## License

MIT.
