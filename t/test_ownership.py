import http.client
import os
from pathlib import Path
import shutil
import socket
import ssl
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
        self.holding = threading.Event()
        self.release = threading.Event()


class BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.endswith("/hold"):
            self.server.holding.set()
            if not self.server.release.wait(timeout=5):
                self.send_error(504)
                return
        with self.server.changed:
            auth = self.headers.get("Authorization")
            if auth:
                self.server.authenticated.setdefault(self.connection, auth)
                self.server.changed.notify_all()
            token = self.server.authenticated.get(self.connection)

        if token and self.path.endswith("/drop"):
            self.close_connection = True
            return
        if token and self.path.endswith("/next"):
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        if self.path.endswith("/close"):
            self.send_header("Connection", "close")
            self.close_connection = True
        self.send_header("X-NGX-CONNECTION-ID", str(self.client_address[1]))
        self.send_header("X-Backend-Port", str(self.server.server_address[1]))
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


class OwnershipTestCase(unittest.TestCase):
    upstream_options = ""
    server_options = ""
    nginx_environment = "TEST_NGINX_BINARY"
    backend_count = 1
    upstream_tls = False
    event_options = ""
    proxy_options = ""
    ntlm_first = False
    max_cached = 1

    def setUp(self):
        nginx = shutil.which(os.environ.get(self.nginx_environment, "nginx"))
        if nginx is None:
            self.fail("nginx is required; build it with this module first")

        self.directory = tempfile.TemporaryDirectory(prefix="ntlm-ownership-")
        self.addCleanup(self.directory.cleanup)
        prefix = Path(self.directory.name)
        context = None
        if self.upstream_tls:
            cert, key = prefix / "cert.pem", prefix / "key.pem"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(key), "-out", str(cert), "-days", "1",
                 "-subj", "/CN=localhost"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
        self.backends = []
        for _ in range(self.backend_count):
            backend = Backend()
            if context:
                backend.socket = context.wrap_socket(backend.socket, server_side=True)
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join)
            self.addCleanup(backend.server_close)
            self.addCleanup(backend.shutdown)
            self.addCleanup(backend.release.set)
            self.backends.append(backend)
        self.backend = self.backends[0]
        self.error_log = prefix / "error.log"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]

        servers = "\n".join(
            f"server 127.0.0.1:{backend.server_address[1]} {self.server_options};"
            for backend in self.backends
        )
        scheme = "https" if self.upstream_tls else "http"
        options = (
            f"ntlm {self.max_cached}; {self.upstream_options}" if self.ntlm_first
            else f"{self.upstream_options} ntlm {self.max_cached};"
        )
        (prefix / "nginx.conf").write_text(
            f"""
{f'load_module {os.environ["TEST_NGINX_MODULE"]};' if os.environ.get("TEST_NGINX_MODULE") else ""}
daemon off;
master_process off;
pid {prefix}/nginx.pid;
error_log {self.error_log} info;
events {{ worker_connections 128; {self.event_options} }}
http {{
    access_log off;
    upstream backend_a {{
        {servers}
        {options}
    }}
    upstream backend_b {{
        {servers}
        {options}
    }}
    server {{
        listen 127.0.0.1:{self.port};
        location /a {{ proxy_pass {scheme}://backend_a; }}
        location /b {{ proxy_pass {scheme}://backend_b; }}
        location /c {{ proxy_pass {scheme}://backend_a; }}
        location /health {{ return 200 "ready"; }}
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        add_header X-Upstream $upstream_addr always;
        {self.proxy_options}
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


class OwnershipTests(OwnershipTestCase):
    def test_duplicate_ntlm_directive_is_rejected_without_recursion(self):
        prefix = Path(self.directory.name)
        config = prefix / "nginx.conf"
        invalid = prefix / "duplicate.conf"
        invalid.write_text(config.read_text().replace("ntlm 1;", "ntlm 1; ntlm;"))
        result = subprocess.run(
            [shutil.which(os.environ.get(self.nginx_environment, "nginx")),
             "-t", "-p", str(prefix), "-c", str(invalid)],
            capture_output=True, timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'"ntlm" directive is duplicate', result.stderr)

    def test_other_explicit_credentials_do_not_inherit_the_ntlm_session(self):
        owner = self.client()
        self.request(owner, "/a", "alpha")
        owner.request("GET", "/a", headers={"Authorization": "Basic YmV0YTo="})
        response = owner.getresponse()
        self.assertEqual(response.status, 200)
        response.read()
        self.assertEqual(response.getheader("X-NGX-NTLM-AUTH"), "Basic YmV0YTo=")

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


class SharedCacheTests(OwnershipTestCase):
    upstream_options = "keepalive 16; keepalive_requests 100; ntlm_requests 3;"
    server_options = "max_conns=1"

    def test_failed_pinned_socket_can_retry_without_freeing_an_unselected_peer(self):
        owner = self.client()
        self.request(owner, "/a", "alpha")
        self.assertIsNone(self.request(owner, "/a/drop"))
        self.assertIsNone(self.request(self.client(), "/a"))
        self.assertEqual(self.request(owner, "/a", "beta"), "NTLM beta")

    def test_backend_close_retires_the_private_session(self):
        owner = self.client()
        self.request(owner, "/a", "alpha")
        self.assertEqual(self.request(owner, "/a/close"), "NTLM alpha")
        self.wait_for_sessions(0)
        self.assertIsNone(self.request(owner, "/a"))
        self.assertIsNone(self.request(self.client(), "/a"))

    def test_request_limit_closes_session_without_sharing_it(self):
        owner = self.client()
        self.assertEqual(self.request(owner, "/a", "alpha"), "NTLM alpha")
        self.assertEqual(self.request(owner, "/a"), "NTLM alpha")
        self.assertEqual(self.request(owner, "/a"), "NTLM alpha")

        stranger = self.client()
        self.assertIsNone(self.request(stranger, "/a"))
        self.wait_for_sessions(0)
        self.assertIsNone(self.request(owner, "/a"))
        self.assertEqual(self.request(owner, "/a", "beta"), "NTLM beta")

    def test_plain_requests_still_use_shared_keepalive(self):
        connection_ids = []
        for _ in range(5):
            client = self.client()
            client.request("GET", "/a")
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"OK")
            self.assertIsNone(response.getheader("X-NGX-NTLM-AUTH"))
            connection_ids.append(response.getheader("X-NGX-CONNECTION-ID"))
        self.assertIsNotNone(connection_ids[0])
        self.assertEqual(len(set(connection_ids)), 1)


class SessionAgeTests(OwnershipTestCase):
    upstream_options = "keepalive 16; keepalive_time 1h; ntlm_time 10ms;"
    server_options = "max_conns=1"

    def test_expired_session_is_closed_without_sharing_it(self):
        owner = self.client()
        self.assertEqual(self.request(owner, "/a", "alpha"), "NTLM alpha")
        time.sleep(0.05)
        self.assertIsNone(self.request(owner, "/a"))
        self.assertIsNone(self.request(self.client(), "/a"))
        self.wait_for_sessions(0)
        self.assertIsNone(self.request(owner, "/a"))


class ReverseDirectiveTests(OwnershipTestCase):
    upstream_options = "keepalive 16;"
    ntlm_first = True

    def test_ntlm_before_keepalive_preserves_private_and_shared_reuse(self):
        owner = self.client()
        self.assertEqual(self.request(owner, "/a", "alpha"), "NTLM alpha")
        for _ in range(3):
            self.assertIsNone(self.request(self.client(), "/a"))
            self.assertEqual(self.request(owner, "/a"), "NTLM alpha")


class ProxyConfigurationTests(OwnershipTestCase):
    max_cached = 4
    upstream_options = "keepalive 16;"

    def test_locations_using_one_upstream_have_separate_sessions(self):
        owner = self.client()
        self.assertEqual(self.request(owner, "/a", "alpha"), "NTLM alpha")
        self.assertIsNone(self.request(owner, "/c"))
        self.assertEqual(self.request(owner, "/c", "beta"), "NTLM beta")
        self.assertEqual(self.request(owner, "/a"), "NTLM alpha")
        self.assertEqual(self.request(owner, "/c"), "NTLM beta")
        self.wait_for_sessions(2)
        self.disconnect(owner)
        self.wait_for_sessions(0)


class RetryPolicyTests(OwnershipTestCase):
    backend_count = 2
    upstream_options = "keepalive 16;"
    proxy_options = "proxy_next_upstream http_403;"

    def test_next_upstream_policy_does_not_recache_the_rejected_private_socket(self):
        owner = self.client()
        self.request(owner, "/a", "alpha")
        owner.request("GET", "/a/next")
        response = owner.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"OK")
        self.assertIsNone(response.getheader("X-NGX-NTLM-AUTH"))
        self.assertIsNone(self.request(owner, "/a"))


class BalancerTests(OwnershipTestCase):
    backend_count = 2
    upstream_options = "keepalive 16;"

    def test_pinned_peer_metadata_matches_the_actual_backend(self):
        owner = self.client()
        self.request(owner, "/a", "alpha")
        for _ in range(6):
            owner.request("GET", "/a")
            response = owner.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            self.assertEqual(
                response.getheader("X-Upstream"),
                "127.0.0.1:" + response.getheader("X-Backend-Port"),
            )
            self.assertEqual(response.getheader("X-NGX-NTLM-AUTH"), "NTLM alpha")


class BalancerDirectiveTests(BalancerTests):
    upstream_options = "least_conn; keepalive 16;"
    ntlm_first = True


class BusyBalancerTests(OwnershipTestCase):
    server_options = "max_conns=1"
    upstream_options = "keepalive 16;"

    def test_pinned_session_is_available_while_new_peer_selection_is_busy(self):
        owner, blocker = self.client(), self.client()
        self.request(owner, "/a", "alpha")
        blocker.request("GET", "/a/hold")
        self.assertTrue(self.backend.holding.wait(timeout=2))
        try:
            self.assertEqual(self.request(owner, "/a"), "NTLM alpha")
        finally:
            self.backend.release.set()
            response = blocker.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        self.assertIsNone(self.request(self.client(), "/a"))


class TLSLifecycleTests(OwnershipTestCase):
    upstream_tls = True
    upstream_options = "zone tls_peers 64k; keepalive 16; ntlm_timeout 100ms;"
    proxy_options = "proxy_ssl_session_reuse on;"

    def test_tls_reuse_expiry_and_disconnect_remain_isolated(self):
        for index in range(5):
            owner = self.client()
            token = f"tls-{index}"
            self.assertEqual(self.request(owner, "/a", token), f"NTLM {token}")
            self.assertEqual(self.request(owner, "/a"), f"NTLM {token}")
            self.assertIsNone(self.request(self.client(), "/a"))
            self.disconnect(owner)
            self.wait_for_sessions(0)
        owner = self.client()
        self.request(owner, "/a", "expiring")
        self.wait_for_sessions(0)
        self.assertIsNone(self.request(owner, "/a"))


class SelectLifecycleTests(TLSLifecycleTests):
    event_options = "use select;"


@unittest.skipUnless(
    os.environ.get("TEST_NGINX_CLEANUP_NULL_BINARY"),
    "requires nginx built with -DNGX_NTLM_TEST_CLEANUP_NULL",
)
class CleanupFailureTests(OwnershipTestCase):
    upstream_options = "keepalive 16; keepalive_requests 100;"
    server_options = "max_conns=1"
    nginx_environment = "TEST_NGINX_CLEANUP_NULL_BINARY"

    def test_cleanup_failure_closes_session_without_sharing_it(self):
        owner = self.client()
        for index in range(3):
            token = f"alpha-{index}"
            self.assertEqual(self.request(owner, "/a", token), f"NTLM {token}")
            self.assertIsNone(self.request(self.client(), "/a"))
            self.wait_for_sessions(0)
            self.assertIsNone(self.request(owner, "/a"))
        self.assertIn(
            "ntlm: failed to allocate cleanup handler",
            self.error_log.read_text(),
        )


if __name__ == "__main__":
    unittest.main()
