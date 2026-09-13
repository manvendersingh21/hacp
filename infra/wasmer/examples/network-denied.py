"""Guest program: try to open network connections that were never granted.

Usage (inside the sandbox):
    network-denied.py <host-loopback-port>

The host runs a listener on 127.0.0.1:<port> and counts connections, so the
verdict does not depend on what this program prints.
"""
import socket
import sys

port = int(sys.argv[1])


def attempt(what, action):
    try:
        outcome = action()
    except OSError as e:
        print(f"DENIED  {what} ({type(e).__name__}: {e})")
    else:
        print(f"EXPOSED {what} ({outcome})")


def tcp(host, p):
    def connect():
        with socket.create_connection((host, p), timeout=3):
            return "connected"
    return connect


attempt(f"tcp 127.0.0.1:{port} (host loopback listener)", tcp("127.0.0.1", port))
attempt("tcp 1.1.1.1:443 (internet)", tcp("1.1.1.1", 443))
attempt("dns example.com", lambda: socket.getaddrinfo("example.com", 443)[0][4])
print("DONE")
