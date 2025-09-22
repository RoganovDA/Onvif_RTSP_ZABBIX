import socket

import camcheck


def test_validate_address_accepts_ipv6_only_hostname(monkeypatch):
    calls = []

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        calls.append((host, family))
        if host == "ipv6-only.example":
            return [
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("2001:db8::1", 0, 0, 0),
                )
            ]
        raise socket.gaierror

    monkeypatch.setattr(camcheck.socket, "getaddrinfo", fake_getaddrinfo)

    success, error = camcheck.validate_address("ipv6-only.example")

    assert success is True
    assert error is None
    assert calls
    host, family = calls[0]
    assert host == "ipv6-only.example"
    assert family == socket.AF_UNSPEC
