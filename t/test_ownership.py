import http.client
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Backend(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), BackendHandler)
        self.authenticated = {}
        self.changed = threading.Condition()


class BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with self.server.changed:
            auth = self.headers.get("Authorization")
            if auth:
                self.server.authenticated.setdefault(self.connection, auth)
                self.server.changed.notify_all()
            token = self.server.authenticated.get(self.connection)

        self.send_response(200)
        if token:
            self.send_header("X-NGX-NTLM-AUTH", token)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def finish(self):
        try:
            super().finish()
        finally:
            with self.server.changed:
                self.server.authenticated.pop(self.connection, None)
                self.server.changed.notify_all()

    def log_message(self, format, *args):
        pass


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        nginx = shutil.which(os.environ.get("TEST_NGINX_BINARY", "nginx"))
        if nginx is None:
            self.fail("nginx is required; build it with this module first")

        self.backend = Backend()
        thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.backend.server_close)
        self.addCleanup(self.backend.shutdown)

        self.directory = tempfile.TemporaryDirectory(prefix="ntlm-ownership-")
        self.addCleanup(self.directory.cleanup)
        prefix = Path(self.directory.name)
        self.error_log = prefix / "error.log"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]

        backend_port = self.backend.server_address[1]
        (prefix / "nginx.conf").write_text(
            f"""
daemon off;
master_process off;
pid {prefix}/nginx.pid;
error_log {self.error_log} info;
events {{ worker_connections 128; }}
http {{
    access_log off;
    upstream backend_a {{
        server 127.0.0.1:{backend_port};
        ntlm 1;
    }}
    upstream backend_b {{
        server 127.0.0.1:{backend_port};
        ntlm 1;
    }}
    server {{
        listen 127.0.0.1:{self.port};
        location /a {{ proxy_pass http://backend_a; }}
        location /b {{ proxy_pass http://backend_b; }}
        location /health {{ return 200 "ready"; }}
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }}
}}
""",
            encoding="ascii",
        )
        self.process = subprocess.Popen(
            [nginx, "-p", str(prefix), "-c", str(prefix / "nginx.conf")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop_nginx)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail(self.process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.01)
        self.fail("nginx did not become ready")

    def stop_nginx(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.communicate(timeout=5)

    def client(self):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        self.addCleanup(client.close)
        return client

    def request(self, client, path, token=None):
        headers = {"Authorization": f"NTLM {token}"} if token else {}
        client.request("GET", path, headers=headers)
        response = client.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"OK")
        return response.getheader("X-NGX-NTLM-AUTH")

    def disconnect(self, client):
        # Wait for nginx to close the socket, not just for the client to send FIN.
        client.sock.sendall(
            b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        while client.sock.recv(4096):
            pass
        client.close()

    def wait_for_sessions(self, count):
        with self.backend.changed:
            matched = self.backend.changed.wait_for(
                lambda: len(self.backend.authenticated) == count, timeout=2
            )
            self.assertTrue(
                matched,
                f"expected {count} authenticated backend connections, "
                f"got {len(self.backend.authenticated)}",
            )

    def test_disconnect_cleans_every_upstream_group(self):
        client = self.client()
        self.assertEqual(self.request(client, "/a", "alpha"), "NTLM alpha")
        self.assertEqual(self.request(client, "/b", "beta"), "NTLM beta")
        self.assertEqual(self.request(client, "/a"), "NTLM alpha")
        self.assertEqual(self.request(client, "/b"), "NTLM beta")
        self.wait_for_sessions(2)
        self.disconnect(client)
        self.wait_for_sessions(0)

    def test_old_cleanup_does_not_close_reassigned_cache_slot(self):
        old_client = self.client()
        new_client = self.client()
        self.assertEqual(self.request(old_client, "/a", "alpha"), "NTLM alpha")
        self.assertEqual(self.request(new_client, "/a", "beta"), "NTLM beta")
        self.wait_for_sessions(1)
        self.disconnect(old_client)
        self.assertEqual(self.request(new_client, "/a"), "NTLM beta")
        self.disconnect(new_client)
        self.wait_for_sessions(0)

    def test_new_clients_do_not_inherit_disconnected_client_sessions(self):
        for index in range(20):
            owner = self.client()
            self.request(owner, "/a", f"alpha-{index}")
            self.request(owner, "/b", f"beta-{index}")
            self.disconnect(owner)

            stranger = self.client()
            self.assertIsNone(self.request(stranger, "/a"))
            self.assertIsNone(self.request(stranger, "/b"))
            self.disconnect(stranger)
        self.wait_for_sessions(0)


if __name__ == "__main__":
    unittest.main()
