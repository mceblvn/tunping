import json
import socket
import threading

import pytest

from tunping.__main__ import (
    create_connection,
    drain_headers,
    main,
    parse_args,
    print_summary,
)


def test_parse_args_defaults():
    args = parse_args(["example.com"])
    assert args.host == "example.com"
    assert args.count == 0
    assert args.interval == 1.0
    assert args.port == 443
    assert args.timeout == 5.0
    assert args.proto == "https"
    assert args.json is False


def test_parse_args_rejects_bad_values():
    with pytest.raises(SystemExit):
        parse_args(["h", "-c", "-1"])
    with pytest.raises(SystemExit):
        parse_args(["h", "--port", "0"])
    with pytest.raises(SystemExit):
        parse_args(["h", "--port", "99999"])
    with pytest.raises(SystemExit):
        parse_args(["h", "--timeout", "0"])


def test_print_summary_empty_is_loss(capsys):
    args = parse_args(["example.com"])
    rc = print_summary(args, 3, [], "?")
    assert rc == 1
    out = capsys.readouterr().out
    assert "3 transmitted, 0 received, 100.0% loss" in out


def test_print_summary_human_stats(capsys):
    args = parse_args(["example.com"])
    rc = print_summary(args, 2, [100.0, 110.0], "93.0.0.1")
    assert rc == 0
    out = capsys.readouterr().out
    assert "2 transmitted, 2 received, 0.0% loss" in out
    assert "min/avg/max/mdev" in out
    assert "jitter" in out


def test_print_summary_json(capsys):
    args = parse_args(["example.com", "--json"])
    rc = print_summary(args, 2, [100.0, 110.0], "93.0.0.1")
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["type"] == "summary"
    assert payload["transmitted"] == 2
    assert payload["received"] == 2
    assert payload["loss_pct"] == 0.0
    assert payload["rtt_avg_ms"] == pytest.approx(105.0)


def test_drain_headers_ok():
    a, b = socket.socketpair()
    try:
        a.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nEXTRA")
        assert drain_headers(b) is True
    finally:
        a.close()
        b.close()


def test_drain_headers_closed_is_false():
    a, b = socket.socketpair()
    a.close()
    try:
        # peer closed -> recv returns b"" -> False (fast, set timeout)
        b.settimeout(2)
        assert drain_headers(b) is False
    finally:
        b.close()


def test_create_connection_refused_raises():
    # closed port on loopback: bind(0) then close to grab a free port
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(OSError):
        create_connection("127.0.0.1", port, 1.0, False, None, False)


def _run_fake_http_server():
    """Minimal keep-alive HTTP server for HEAD; returns (port, stop_event)."""
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
            conn.settimeout(2)
            try:
                while not stop.is_set():
                    buf = b""
                    try:
                        while b"\r\n\r\n" not in buf:
                            chunk = conn.recv(4096)
                            if not chunk:
                                break
                            buf += chunk
                    except (socket.timeout, OSError):
                        break
                    if not buf:
                        break
                    try:
                        conn.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                            b"Connection: keep-alive\r\n\r\n"
                        )
                    except OSError:
                        break
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        try:
            srv.close()
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, stop


def test_main_against_local_http_json(capsys):
    port, stop = _run_fake_http_server()
    try:
        rc = main(["127.0.0.1", "-c", "2", "--proto", "http",
                   "--port", str(port), "-i", "0", "--timeout", "3", "--json"])
        assert rc == 0
        lines = capsys.readouterr().out.strip().splitlines()
        assert len(lines) == 3
        probes = [json.loads(lines[0]), json.loads(lines[1])]
        summary = json.loads(lines[2])
        assert all(p["ok"] and p["ttfb_ms"] >= 0 for p in probes)
        assert summary["type"] == "summary"
        assert summary["received"] == 2
        assert summary["loss_pct"] == 0.0
    finally:
        stop.set()


def test_main_against_local_http_human(capsys):
    port, stop = _run_fake_http_server()
    try:
        rc = main(["127.0.0.1", "-c", "2", "--proto", "http",
                   "--port", str(port), "-i", "0", "--timeout", "3"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "2 transmitted, 2 received" in out
        assert "ttfb=" in out
    finally:
        stop.set()


def test_main_closed_port_is_loss(capsys):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    rc = main(["127.0.0.1", "-c", "1", "--proto", "http",
               "--port", str(port), "-i", "0", "--timeout", "1"])
    assert rc == 1
    assert "100.0% loss" in capsys.readouterr().out
