import math

from tunping.__main__ import build_request, calc_jitter, calc_stats, is_ip_literal


def test_calc_stats_basic():
    s = calc_stats([10.0, 20.0, 30.0])
    assert s is not None
    assert s["min"] == 10.0
    assert s["max"] == 30.0
    assert abs(s["avg"] - 20.0) < 1e-9
    # population stdev of [10,20,30] = sqrt(200/3)
    assert abs(s["mdev"] - math.sqrt(200 / 3)) < 1e-9


def test_calc_stats_single():
    s = calc_stats([76.1])
    assert s is not None
    assert s["min"] == s["avg"] == s["max"] == 76.1
    assert s["mdev"] == 0.0


def test_calc_stats_empty():
    assert calc_stats([]) is None


def test_calc_jitter():
    assert calc_jitter([]) is None
    assert calc_jitter([100.0]) is None
    # |110-100|=10, |105-110|=5 -> mean 7.5
    assert abs(calc_jitter([100.0, 110.0, 105.0]) - 7.5) < 1e-9


def test_build_request_keepalive():
    req = build_request("1.1.1.1").decode()
    assert req.startswith("HEAD / HTTP/1.1\r\n")
    assert "Host: 1.1.1.1\r\n" in req
    assert "Connection: keep-alive\r\n" in req
    assert "tunping/" in req


def test_is_ip_literal():
    assert is_ip_literal("1.1.1.1")
    assert not is_ip_literal("cloudflare-dns.com")
    assert not is_ip_literal("not a host!!..")
