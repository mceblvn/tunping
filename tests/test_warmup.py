import json
import socket
import threading

from tunping.__main__ import main


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


def test_warmup_default_skips_first_single(capsys):
    port, stop = _run_fake_http_server()
    try:
        rc = main(["127.0.0.1", "-c", "2", "--proto", "http",
                   "--port", str(port), "-i", "0", "--timeout", "3"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "seq=1" in out and "(warmup)" in out
        assert out.index("(warmup)") < out.index("seq=2")
        assert "2 transmitted, 2 received, 0.0% loss" in out
    finally:
        stop.set()


def test_warmup_zero_marks_nothing(capsys):
    port, stop = _run_fake_http_server()
    try:
        rc = main(["127.0.0.1", "-c", "2", "--proto", "http",
                   "--port", str(port), "-i", "0", "--timeout", "3",
                   "--warmup", "0"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "(warmup)" not in out
        assert "2 transmitted, 2 received" in out
    finally:
        stop.set()


def test_warmup_json_excluded_from_summary(capsys):
    port, stop = _run_fake_http_server()
    try:
        rc = main(["127.0.0.1", "-c", "2", "--proto", "http",
                   "--port", str(port), "-i", "0", "--timeout", "3", "--json"])
        assert rc == 0
        lines = capsys.readouterr().out.strip().splitlines()
        assert len(lines) == 4  # 1 warmup + 2 counted + summary
        first = json.loads(lines[0])
        assert first["warmup"] is True
        rest = [json.loads(line) for line in lines[1:-1]]
        assert all(p["warmup"] is False for p in rest)
        summary = json.loads(lines[-1])
        assert summary["received"] == 2
        assert summary["transmitted"] == 2
    finally:
        stop.set()


def test_warmup_compare_excluded_from_overhead(capsys):
    port, stop = _run_fake_http_server()
    try:
        rc = main(["127.0.0.1", "-c", "2", "--proto", "http",
                   "--port", str(port), "-i", "0", "--timeout", "3",
                   "--compare", "lo", "lo"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "seq=1" in out and "(warmup)" in out
        assert "lo: 2 transmitted, 2 received" in out
        assert "overhead (lo-lo)" in out
    finally:
        stop.set()
