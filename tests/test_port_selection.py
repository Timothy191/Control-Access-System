"""
Tests for TCP port selection helpers.

Regression coverage for the startup crash where the app advertised a port
chosen by find_available_port() but bound a hardcoded 8080 instead.
"""

import socket

import app as app_module
from app import find_available_port, find_scanner_port, is_port_available


def _free_port():
    """Reserve an ephemeral port and release it, returning a likely-free number."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _hold(port, dual_stack=False):
    """Bind and listen on a port so it is genuinely occupied."""
    if dual_stack:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", port))
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", port))
    sock.listen(1)
    return sock


class TestIsPortAvailable:
    def test_free_port_is_available(self):
        assert is_port_available(_free_port()) is True

    def test_ipv4_occupied_port_is_not_available(self):
        port = _free_port()
        sock = _hold(port)
        try:
            assert is_port_available(port) is False
        finally:
            sock.close()

    def test_dual_stack_ipv6_listener_is_not_available(self):
        """A dual-stack IPv6 listener also owns the IPv4 port."""
        port = _free_port()
        try:
            sock = _hold(port, dual_stack=True)
        except OSError:
            return  # No IPv6 support on this host
        try:
            assert is_port_available(port) is False
        finally:
            sock.close()

    def test_released_port_becomes_available_again(self):
        port = _free_port()
        sock = _hold(port)
        assert is_port_available(port) is False
        sock.close()
        assert is_port_available(port) is True

    def test_uses_bind_not_connect(self):
        """Availability must not depend on whether an outbound connect is refused."""
        real_connect_ex = socket.socket.connect_ex

        def refuse_everything(self, address):
            return 111  # ECONNREFUSED for every destination

        socket.socket.connect_ex = refuse_everything
        try:
            port = _free_port()
            assert is_port_available(port) is True
            sock = _hold(port)
            try:
                assert is_port_available(port) is False
            finally:
                sock.close()
        finally:
            socket.socket.connect_ex = real_connect_ex


class TestFindAvailablePort:
    def test_skips_occupied_preferred_port(self):
        blocked = _free_port()
        sock = _hold(blocked)
        try:
            main_port, scanner_port = find_available_port(
                start_port=5100, end_port=5200, preferred_ports=[blocked]
            )
            assert main_port != blocked
            assert is_port_available(main_port) is True
            assert scanner_port is not None
        finally:
            sock.close()

    def test_returns_bindable_port_when_all_preferred_busy(self):
        first = _free_port()
        second = _free_port()
        s1 = _hold(first)
        s2 = _hold(second)
        try:
            main_port, scanner_port = find_available_port(
                start_port=5200, end_port=5300, preferred_ports=[first, second]
            )
            assert main_port not in (first, second)
            assert is_port_available(main_port) is True
            assert scanner_port is not None
        finally:
            s1.close()
            s2.close()

    def test_raises_when_range_exhausted(self, monkeypatch):
        monkeypatch.setattr(app_module, "is_port_available", lambda port: False)
        try:
            find_available_port(start_port=5300, end_port=5310)
        except RuntimeError as exc:
            assert "No available ports" in str(exc)
        else:
            raise AssertionError("expected RuntimeError when every port is busy")

    def test_find_scanner_port_returns_none_when_full(self, monkeypatch):
        monkeypatch.setattr(app_module, "is_port_available", lambda port: False)
        assert find_scanner_port(5400, 5410) is None
