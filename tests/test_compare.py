import json
import socket
import threading

import pytest

from tunping.__main__ import (
    bind_to_device,
    main,
    parse_args,
    ttfb_probe,
    validate_iface,
)


def test_parse_args_compare():
    args = parse_args(["1.1.1.1", "--compare", "amn0", "enp14s0", "-c", "2"])
    assert args.compare == ["amn0", "enp14s0"]
    assert args.count == 2


def test_bind_to_device_lo():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bind_to_device(s, "lo")  # unprivileged since Linux 5.7
    finally:
        s.close()


def test_bind_to_device_missing_iface():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(OSError):
            bind_to_device(s, "no-such-iface-xyz")
    finally:
        s.close()


def test_validate_iface_bad():
    with pytest.raises(OSError):
        validate_iface("no-such-iface-xyz")


def test_ttfb_probe_local():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)
    port = srv.getsockname()[1]

    def serve_once():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            return
        with conn:
            conn.settimeout(5)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )

    t = threading.Thread(target=serve_once, daemon=True)
    t.start()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            ok, rtt, err, dead = ttfb_probe(
                s, b"HEAD / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n", 5)
            assert ok and err == "" and rtt >= 0
        finally:
            s.close()
    finally:
        srv.close()


def _handle_conn(conn, stop):
    conn.settimeout(2)
    try:
        while not stop.is_set():
            buf = b""
            try:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
            except (socket.timeout, OSError):
                return
            if not buf:
                return
            try:
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                )
            except OSError:
                return
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _run_fake_http_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    srv.settimeout(0.5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # one thread per connection: --compare holds two keep-alives
            threading.Thread(target=_handle_conn, args=(conn, stop),
                             daemon=True).start()
        try:
            srv.close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    return port, stop


def test_compare_localhost_human(capsys):
    port, stop = _run_fake_http_server()
    try:
        rc = main(["127.0.0.1", "-c", "2", "--proto", "http",
                   "--port", str(port), "-i", "0", "--timeout", "3",
                   "--compare", "lo", "lo"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "compare lo vs lo" in out
        assert "delta=" in out
        assert "overhead (lo-lo)" in out
    finally:
        stop.set()


def test_compare_localhost_json(capsys):
    port, stop = _run_fake_http_server()
    try:
        rc = main(["127.0.0.1", "-c", "2", "--proto", "http",
                   "--port", str(port), "-i", "0", "--timeout", "3",
                   "--compare", "lo", "lo", "--json", "--warmup", "0"])
        assert rc == 0
        lines = capsys.readouterr().out.strip().splitlines()
        assert len(lines) == 5  # 2 rounds x 2 ifaces + summary
        summary = json.loads(lines[-1])
        assert summary["type"] == "summary"
        assert summary["mode"] == "compare"
        assert set(summary["series"]) == {"lo"}
        assert summary["overhead_ms"] is not None
        probes = [json.loads(line) for line in lines[:-1]]
        assert all(p["ok"] and "ttfb_ms" in p for p in probes)
        assert {p["iface"] for p in probes} == {"lo"}
    finally:
        stop.set()


def test_compare_bad_iface(capsys):
    rc = main(["127.0.0.1", "-c", "1", "--proto", "http",
               "--compare", "no-such-iface-xyz", "lo"])
    assert rc == 2
    assert "cannot bind" in capsys.readouterr().err
