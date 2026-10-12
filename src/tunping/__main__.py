"""tunping: ping-like HTTPS TTFB probe for VPNs that answer ICMP locally.

TUN/SOCKS stacks (tun2socks/XRay-style) answer ICMP and TCP SYN on the
local device (~0.1ms to anything, even TEST-NET), so `ping` and `hping -S`
are unusable there. This tool times a full request -> first response byte,
which goes through the real tunnel/proxy.

Method: one persistent TLS connection, loop of `HEAD /` with
`Connection: keep-alive`; time from end-of-send to first-byte-received
with time.monotonic(). Works via SOCKS-TUN and via plain L3 tunnels.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import socket
import ssl
import statistics
import sys
import time

from tunping import __version__

USER_AGENT = f"tunping/{__version__}"
DRAIN_LIMIT = 16 * 1024


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def build_request(host_header: str) -> bytes:
    return (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode("ascii")


def calc_stats(rtts: list[float]) -> dict | None:
    """Return min/avg/max/mdev (population stdev, like ping) or None if empty."""
    if not rtts:
        return None
    avg = statistics.fmean(rtts)
    mdev = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
    return {"min": min(rtts), "avg": avg, "max": max(rtts), "mdev": mdev}


def calc_jitter(rtts: list[float]) -> float | None:
    """Mean absolute delta between successive samples, None if < 2 samples."""
    if len(rtts) < 2:
        return None
    diffs = [abs(b - a) for a, b in zip(rtts, rtts[1:])]
    return statistics.fmean(diffs)


def drain_headers(sock: socket.socket) -> bool:
    """Read until end-of-headers (b'\\r\\n\\r\\n') to keep keep-alive in sync.

    Returns True on clean drain, False on timeout/close/oversize.
    Not counted in RTT; failure just forces a reconnect next seq.
    """
    buf = bytearray()
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return False
            buf += chunk
            if b"\r\n\r\n" in buf:
                return True
            if len(buf) > DRAIN_LIMIT:
                return False
    except (socket.timeout, OSError):
        return False


def bind_to_device(sock: socket.socket, ifname: str) -> None:
    """Pin socket egress to an interface, bypassing the routing table.

    Unprivileged since Linux 5.7 as long as the socket is not already
    bound, so always call on a fresh socket before connect().
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode() + b"\x00")


def validate_iface(ifname: str) -> None:
    """Fail fast if an interface cannot be bound. Raises OSError."""
    if not hasattr(socket, "SO_BINDTODEVICE"):
        raise OSError("SO_BINDTODEVICE is not available on this OS")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bind_to_device(probe, ifname)
    except OSError as e:
        if e.errno in (errno.EPERM, errno.EACCES):
            raise OSError(
                f"cannot bind to '{ifname}': denied "
                f"(old kernel or restricted policy)"
            ) from e
        raise OSError(f"cannot bind to '{ifname}': {e}") from e
    finally:
        probe.close()


def ttfb_probe(sock: socket.socket, request: bytes,
               timeout: float) -> tuple[bool, float, str, bool]:
    """One HEAD -> first-byte measurement on a live socket.

    Returns (ok, rtt_ms, err, conn_dead). conn_dead tells the caller to
    reconnect before the next probe; the current probe may still be ok.
    """
    try:
        sock.settimeout(timeout)
        t0 = time.monotonic()
        sock.sendall(request)
        first = sock.recv(1)
        t1 = time.monotonic()
        if not first:
            return False, 0.0, "connection closed before first byte", True
        dead = not drain_headers(sock)
        return True, (t1 - t0) * 1000.0, "", dead
    except (socket.timeout, OSError) as e:
        err = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        return False, 0.0, err, True


def create_connection(
    host: str,
    port: int,
    timeout: float,
    use_tls: bool,
    sni: str | None,
    insecure: bool,
    bind_if: str | None = None,
) -> tuple[socket.socket, str]:
    """Try all getaddrinfo results, return (sock, ip_str) or raise OSError."""
    server_hostname = sni or host
    errors: list[str] = []
    for res in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        family, socktype, proto, _canon, sockaddr = res
        ip_str = sockaddr[0]
        try:
            raw = socket.socket(family, socktype, proto)
            raw.settimeout(timeout)
            if bind_if:
                try:
                    bind_to_device(raw, bind_if)
                except OSError:
                    raw.close()
                    raise
            raw.connect(sockaddr)
            if not use_tls:
                return raw, ip_str
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            # NOTE: for IP literals the IP is sent as SNI too;
            # most endpoints accept it when the cert carries an IP SAN.
            tls = ctx.wrap_socket(raw, server_hostname=server_hostname)
            return tls, ip_str
        except OSError as e:
            errors.append(f"{ip_str}: {e}")
            try:
                raw.close()
            except Exception:
                pass
            continue
    raise OSError("; ".join(errors) if errors else "resolution/connection failed")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tunping",
        description=(
            "ping-like L7 RTT probe (HTTPS TTFB) for VPNs where ICMP lies. "
            "Not ICMP: measures HEAD request -> first response byte over a "
            "persistent connection."
        ),
    )
    p.add_argument("host", help="target hostname or IP (e.g. 1.1.1.1)")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="stop after N probes (default 0 = infinite until Ctrl-C)")
    p.add_argument("-i", "--interval", type=float, default=1.0,
                   help="seconds between probes (default 1.0)")
    p.add_argument("--port", type=int, default=443, help="TCP port (default 443)")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="per-probe timeout in seconds (default 5.0)")
    p.add_argument("--proto", choices=["https", "http"], default="https",
                   help="use TLS (https, default) or plain (http)")
    p.add_argument("--sni", default=None,
                   help="TLS SNI / HTTP Host override (default: same as host)")
    p.add_argument("--insecure", action="store_true",
                   help="skip TLS cert verification (useful with IP + custom SNI)")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON lines output")
    p.add_argument("--compare", nargs=2, metavar=("IFACE1", "IFACE2"), default=None,
                   help="pin probes to two interfaces and compare TTFB side by side, "
                        "e.g. --compare amn0 enp14s0 (unprivileged on Linux >= 5.7)")
    p.add_argument("--warmup", type=int, default=1,
                   help="skip first N rounds in stats (cold start, default 1); 0 disables")
    p.add_argument("-v", "--version", action="version", version=f"tunping {__version__}")
    args = p.parse_args(argv)
    if args.count < 0:
        p.error("count must be >= 0")
    if args.warmup < 0:
        p.error("warmup must be >= 0")
    if args.interval < 0 or args.timeout <= 0:
        p.error("interval must be >= 0 and timeout > 0")
    if not 1 <= args.port <= 65535:
        p.error("port must be 1..65535")
    return args


def print_summary(args: argparse.Namespace, transmitted: int,
                  rtts: list[float], resolved_ip: str) -> int:
    received = len(rtts)
    loss = 100.0 * (transmitted - received) / transmitted if transmitted else 0.0
    stats = calc_stats(rtts)
    jitter = calc_jitter(rtts)
    if args.json:
        payload = {
            "type": "summary",
            "host": args.host,
            "ip": resolved_ip,
            "port": args.port,
            "proto": args.proto,
            "transmitted": transmitted,
            "received": received,
            "loss_pct": round(loss, 2),
            "rtt_min_ms": round(stats["min"], 3) if stats else None,
            "rtt_avg_ms": round(stats["avg"], 3) if stats else None,
            "rtt_max_ms": round(stats["max"], 3) if stats else None,
            "rtt_mdev_ms": round(stats["mdev"], 3) if stats else None,
            "jitter_ms": round(jitter, 3) if jitter is not None else None,
        }
        print(json.dumps(payload), flush=True)
    else:
        print(f"--- {args.host} tunping statistics ---")
        print(f"{transmitted} transmitted, {received} received, {loss:.1f}% loss")
        if stats:
            print(
                f"rtt min/avg/max/mdev = "
                f"{stats['min']:.3f}/{stats['avg']:.3f}/"
                f"{stats['max']:.3f}/{stats['mdev']:.3f} ms"
            )
            if jitter is not None:
                print(f"jitter = {jitter:.3f} ms")
    return 0 if received > 0 else 1


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.compare:
        return run_compare(args)
    use_tls = args.proto == "https"
    host_header = args.sni or args.host
    if args.port not in (80, 443):
        host_header = f"{host_header}:{args.port}"
    request = build_request(host_header)

    resolved_ip = "?"
    try:
        infos = socket.getaddrinfo(args.host, args.port, type=socket.SOCK_STREAM)
        if infos:
            resolved_ip = infos[0][4][0]
    except OSError:
        pass

    if not args.json:
        print(f"TUNPING {args.host} ({resolved_ip}:{args.port}) with HTTPS TTFB")

    transmitted = 0
    rtts: list[float] = []
    sock: socket.socket | None = None
    sock_ip = resolved_ip
    seq = 0
    counted = 0

    try:
        while True:
            if args.count and counted >= args.count:
                break
            seq += 1
            is_warm = seq <= args.warmup
            loop_start = time.monotonic()
            ok = False
            rtt_ms = 0.0
            err = ""

            if sock is None:
                try:
                    sock, sock_ip = create_connection(
                        args.host, args.port, args.timeout, use_tls,
                        args.sni, args.insecure,
                    )
                    resolved_ip = sock_ip
                except OSError as e:
                    err = f"connect failed: {e}"
                    sock = None

            if sock is not None:
                ok, rtt_ms, err, dead = ttfb_probe(sock, request, args.timeout)
                if ok and not is_warm:
                    rtts.append(rtt_ms)
                if dead:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = None
            if not is_warm:
                counted += 1
                transmitted += 1

            if args.json:
                rec: dict = {"type": "probe", "seq": seq, "ok": ok,
                             "host": args.host, "ip": sock_ip, "port": args.port,
                             "warmup": is_warm}
                if ok:
                    rec["ttfb_ms"] = round(rtt_ms, 3)
                else:
                    rec["error"] = err or "timeout"
                print(json.dumps(rec), flush=True)
            else:
                tag = " (warmup)" if is_warm else ""
                if ok:
                    print(f"response from {args.host} ({sock_ip}): "
                          f"seq={seq} ttfb={rtt_ms:.1f} ms{tag}")
                else:
                    print(f"request timeout for seq={seq} ({err or 'timeout'}){tag}")

            if args.count and counted >= args.count:
                break
            elapsed = time.monotonic() - loop_start
            to_sleep = args.interval - elapsed
            if to_sleep > 0:
                time.sleep(to_sleep)
    except KeyboardInterrupt:
        if not args.json:
            print()
    finally:
        try:
            if sock is not None:
                sock.close()
        except OSError:
            pass

    return print_summary(args, transmitted, rtts, resolved_ip)


def print_compare_summary(args: argparse.Namespace, ifaces: list[str],
                            transmitted: list[int],
                            rtts: list[list[float]]) -> int:
    a, b = ifaces
    received_total = len(rtts[0]) + len(rtts[1])
    stats = [calc_stats(r) for r in rtts]
    jitters = [calc_jitter(r) for r in rtts]
    overhead = None
    if stats[0] and stats[1]:
        overhead = stats[0]["avg"] - stats[1]["avg"]
    if args.json:
        series = {}
        for idx, ifname in enumerate(ifaces):
            t = transmitted[idx]
            r = len(rtts[idx])
            st, jt = stats[idx], jitters[idx]
            series[ifname] = {
                "transmitted": t,
                "received": r,
                "loss_pct": round(100.0 * (t - r) / t, 2) if t else 0.0,
                "rtt_min_ms": round(st["min"], 3) if st else None,
                "rtt_avg_ms": round(st["avg"], 3) if st else None,
                "rtt_max_ms": round(st["max"], 3) if st else None,
                "rtt_mdev_ms": round(st["mdev"], 3) if st else None,
                "jitter_ms": round(jt, 3) if jt is not None else None,
            }
        print(json.dumps({
            "type": "summary",
            "mode": "compare",
            "host": args.host,
            "port": args.port,
            "proto": args.proto,
            "ifaces": ifaces,
            "series": series,
            "overhead_ms": round(overhead, 3) if overhead is not None else None,
        }), flush=True)
    else:
        print(f"--- {args.host} tunping compare statistics ({a} vs {b}) ---")
        for idx, ifname in enumerate(ifaces):
            t = transmitted[idx]
            r = len(rtts[idx])
            st = stats[idx]
            loss = 100.0 * (t - r) / t if t else 0.0
            print(f"{ifname}: {t} transmitted, {r} received, {loss:.1f}% loss")
            if st:
                print(
                    f"{ifname}: rtt min/avg/max/mdev = "
                    f"{st['min']:.3f}/{st['avg']:.3f}/"
                    f"{st['max']:.3f}/{st['mdev']:.3f} ms"
                )
        if overhead is not None:
            print(f"overhead ({a}-{b}) = {overhead:+.3f} ms")
    return 0 if received_total > 0 else 1


def run_compare(args: argparse.Namespace) -> int:
    ifaces = list(args.compare)
    use_tls = args.proto == "https"
    host_header = args.sni or args.host
    if args.port not in (80, 443):
        host_header = f"{host_header}:{args.port}"
    request = build_request(host_header)

    for ifname in ifaces:
        try:
            validate_iface(ifname)
        except OSError as e:
            if args.json:
                print(json.dumps({"type": "error", "error": str(e)}), flush=True)
            else:
                print(f"tunping: {e}", file=sys.stderr)
            return 2

    conns: list[socket.socket | None] = [None] * len(ifaces)
    sock_ips: list[str] = ["?"] * len(ifaces)
    rtts: list[list[float]] = [[] for _ in ifaces]
    transmitted: list[int] = [0] * len(ifaces)

    if not args.json:
        print(f"TUNPING {args.host} ({args.port}) compare {' vs '.join(ifaces)} with HTTPS TTFB")

    seq = 0
    counted = 0
    try:
        while True:
            if args.count and counted >= args.count:
                break
            seq += 1
            is_warm = seq <= args.warmup
            round_start = time.monotonic()
            results: list[tuple[bool, float, str]] = []
            for idx, ifname in enumerate(ifaces):
                if not is_warm:
                    transmitted[idx] += 1
                if conns[idx] is None:
                    try:
                        conns[idx], sock_ips[idx] = create_connection(
                            args.host, args.port, args.timeout, use_tls,
                            args.sni, args.insecure, bind_if=ifname,
                        )
                    except OSError as e:
                        results.append((False, 0.0, f"connect failed: {e}"))
                        continue
                ok, rtt, err, dead = ttfb_probe(conns[idx], request, args.timeout)
                if dead:
                    try:
                        conns[idx].close()
                    except OSError:
                        pass
                    conns[idx] = None
                if ok and not is_warm:
                    rtts[idx].append(rtt)
                results.append((ok, rtt, err))
            if not is_warm:
                counted += 1

            if args.json:
                for idx, ifname in enumerate(ifaces):
                    ok, rtt, err = results[idx]
                    rec: dict = {"type": "probe", "seq": seq, "iface": ifname,
                                 "ok": ok, "host": args.host,
                                 "ip": sock_ips[idx], "port": args.port,
                                 "warmup": is_warm}
                    if ok:
                        rec["ttfb_ms"] = round(rtt, 3)
                    else:
                        rec["error"] = err or "timeout"
                    print(json.dumps(rec), flush=True)
            else:
                parts = []
                for idx, ifname in enumerate(ifaces):
                    ok, rtt, err = results[idx]
                    parts.append(f"{ifname}={rtt:.1f} ms" if ok else f"{ifname}=timeout")
                line = f"seq={seq} " + " ".join(parts)
                both_ok = [r for ok_, r, _ in results if ok_]
                if len(both_ok) == 2:
                    line += f" delta={both_ok[0] - both_ok[1]:+.1f} ms"
                if is_warm:
                    line += " (warmup)"
                print(line)

            if args.count and counted >= args.count:
                break
            elapsed = time.monotonic() - round_start
            to_sleep = args.interval - elapsed
            if to_sleep > 0:
                time.sleep(to_sleep)
    except KeyboardInterrupt:
        if not args.json:
            print()
    finally:
        for sock in conns:
            try:
                if sock is not None:
                    sock.close()
            except OSError:
                pass

    return print_compare_summary(args, ifaces, transmitted, rtts)


if __name__ == "__main__":
    raise SystemExit(main())
