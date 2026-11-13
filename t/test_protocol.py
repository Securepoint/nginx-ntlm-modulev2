import asyncio
import base64
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import asynccontextmanager, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import spnego
from spnego.exceptions import SpnegoError
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


USERNAME = "AUDIT\\test"
PASSWORD = "SyntheticRuntimeTestOnly-123!"


class NTLMHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.context = None

    def finish(self):
        try:
            super().finish()
        finally:
            with self.server.changed:
                self.server.authenticated.discard(self.connection)
                self.server.changed.notify_all()

    def do_GET(self):
        self.server.requests.append(self.path)
        authorization = self.headers.get("Authorization")
        status, challenge = 200, None
        extra_challenge = None
        if not authorization:
            if not self.context or not self.context.complete:
                status, challenge = 401, "NTLM"
        else:
            scheme, encoded = authorization.split(" ", 1)
            message = base64.b64decode(encoded)
            message_type = (
                int.from_bytes(message[8:12], "little")
                if message.startswith(b"NTLMSSP\0") else 0
            )
            self.server.messages.append((message_type, self.client_address[1]))
            if self.context is None:
                self.context = spnego.server(
                    protocol="negotiate" if scheme == "Negotiate" else "ntlm"
                )
            try:
                if scheme == "NTLM" and (
                    not message.startswith(b"NTLMSSP\0")
                    or message_type not in (1, 3)
                ):
                    raise ValueError("Invalid client NTLM message")
                output = self.context.step(message)
                if output:
                    challenge = scheme + " " + base64.b64encode(output).decode()
                if not self.context.complete:
                    status = 401
            except (SpnegoError, ValueError, StopIteration) as error:
                self.server.errors.append(str(error))
                status = 401
        if self.headers.get("X-Audit-Challenge"):
            status, challenge = 401, "NTLM"
        if self.headers.get("X-Audit-Status"):
            status = int(self.headers["X-Audit-Status"])
            if self.headers.get("X-Audit-No-Challenge"):
                challenge = None
        if challenge and " " in challenge:
            self.server.challenges.append(challenge)
            layout = self.headers.get("X-Audit-Challenge-Layout")
            if layout == "combined":
                challenge = 'Basic realm="audit, escaped \\" realm", ' + challenge
            elif layout in (
                "duplicate-combined", "duplicate-separate",
                "invalid-combined", "invalid-separate",
                "reject-combined", "reject-separate",
            ):
                prefix = challenge.split(" ", 1)[0]
                if layout.startswith("invalid-"):
                    prefix += " !!!"
                elif layout.startswith("reject-"):
                    prefix += " " + base64.b64encode(
                        b"\xa1\x07\x30\x05\xa0\x03\x0a\x01\x02"
                    ).decode()
                if layout.endswith("-combined"):
                    challenge = prefix + ", " + challenge
                else:
                    extra_challenge = prefix
            elif layout == "quoted-only":
                challenge = 'Basic realm="audit, ' + challenge + '"'
            elif layout == "different-scheme":
                challenge = "NTLM " + challenge.split(" ", 1)[1]
            elif layout == "other-scheme":
                challenge = "Negotiate " + challenge.split(" ", 1)[1]
            elif layout == "bare":
                challenge = challenge.split(" ", 1)[0]
            elif layout == "reject":
                challenge = "Negotiate " + base64.b64encode(
                    b"\xa1\x07\x30\x05\xa0\x03\x0a\x01\x02"
                ).decode()
            elif layout == "truncated":
                challenge = "Negotiate " + base64.b64encode(b"\xa1\x82\xff\xff").decode()
            elif layout == "empty-field":
                challenge = "Negotiate " + base64.b64encode(
                    b"\xa1\x06\x30\x04\xa2\x02\x04\x00"
                ).decode()
            elif layout == "trailing-state":
                challenge = "Negotiate " + base64.b64encode(
                    b"\xa1\x0a\x30\x08\xa0\x03\x0a\x01\x01\xff\xff\xff"
                ).decode()
        complete = bool(self.context and self.context.complete)
        if complete:
            with self.server.changed:
                self.server.authenticated.add(self.connection)
                self.server.changed.notify_all()
        body = b"OK"
        name = self.path.rsplit("/", 1)[-1]
        if self.path.startswith("/auth/parallel/") and name in self.server.parallel:
            action = self.server.parallel_actions.get(name)
            if action == "retry":
                status = 403
            record = {
                "name": name,
                "status": status,
                "connection": self.client_address[1],
                "backend": self.server.server_address[1],
                "authenticated": complete,
                "principal": self.context.client_principal if complete else None,
                "challenge": challenge,
                "action": action,
            }
            with self.server.changed:
                self.server.parallel_records.append(record)
                self.server.parallel_sockets[name] = self.connection
                self.server.changed.notify_all()
            arrived, release = self.server.parallel[name]
            arrived.set()
            if not release.wait(timeout=8):
                self.send_error(504)
                return
            if action in ("drop", "abort"):
                self.close_connection = True
                return
            body = (json.dumps(record) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Connection-ID", str(self.client_address[1]))
        if challenge:
            if self.headers.get("X-Audit-Challenge-Layout") == "separate":
                self.send_header("WWW-Authenticate", 'Basic realm="audit"')
            if extra_challenge:
                self.send_header("WWW-Authenticate", extra_challenge)
            self.send_header("WWW-Authenticate", challenge)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending = {}

    async def request(self, path, message=None):
        stream = self._quic.get_next_available_stream_id()
        future = asyncio.get_running_loop().create_future()
        self.pending[stream] = [future, {}]
        headers = [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", path.encode()),
        ]
        if message:
            headers.append((b"authorization", b"NTLM " + base64.b64encode(message)))
        self.http.send_headers(stream, headers, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(future, timeout=5)

    def quic_event_received(self, event):
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, (HeadersReceived, DataReceived)):
                pending = self.pending.get(http_event.stream_id)
                if pending is None:
                    continue
                if isinstance(http_event, HeadersReceived):
                    pending[1].update(
                        {key.decode(): value.decode() for key, value in http_event.headers}
                    )
                if http_event.stream_ended:
                    pending[0].set_result(pending[1])
                    del self.pending[http_event.stream_id]


@asynccontextmanager
async def connect_h3(port, configuration):
    # Use IPv4 directly: aioquic's convenience connector requires IPv6 support.
    connection = QuicConnection(configuration=configuration)
    transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: H3Client(connection),
        local_addr=("127.0.0.1", 0),
        family=socket.AF_INET,
    )
    try:
        protocol.connect(("127.0.0.1", port))
        await asyncio.wait_for(protocol.wait_connected(), timeout=5)
        yield protocol
    finally:
        protocol.close()
        await asyncio.wait_for(protocol.wait_closed(), timeout=5)
        transport.close()


class ProtocolTestCase(unittest.TestCase):
    def setUp(self):
        previous = os.environ.get("NTLM_USER_FILE")
        self.addCleanup(self.restore_credentials, previous)

    @staticmethod
    def restore_credentials(previous):
        if previous is None:
            os.environ.pop("NTLM_USER_FILE", None)
        else:
            os.environ["NTLM_USER_FILE"] = previous

    def start(self, shared=True, server_options="", upstream_tls=None,
              backend_count=1, extra_http_config="", extra_server_config="",
              proxy_options="", debug=False):
        nginx = shutil.which(os.environ.get("TEST_NGINX_BINARY", "nginx"))
        self.assertIsNotNone(nginx, "build nginx with TLS, HTTP/2 and HTTP/3 first")
        directory = tempfile.TemporaryDirectory(prefix="ntlm-protocol-")
        self.addCleanup(directory.cleanup)
        prefix = Path(directory.name)
        credentials = prefix / "users"
        credentials.write_text(f"AUDIT:test:{PASSWORD}\n", encoding="ascii")
        os.environ["NTLM_USER_FILE"] = str(credentials)
        backends = [
            ThreadingHTTPServer(("127.0.0.1", 0), NTLMHandler)
            for _ in range(backend_count)
        ]
        backend = backends[0]
        backend.peers = backends
        backend.changed = threading.Condition()
        backend.authenticated = set()
        backend.parallel = {
            name: (threading.Event(), threading.Event())
            for name in ("first", "second")
        }
        backend.parallel_records = []
        backend.parallel_sockets = {}
        cert, key = prefix / "cert.pem", prefix / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if upstream_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = upstream_tls
            context.load_cert_chain(cert, key)
        for peer in backends:
            peer.daemon_threads = True
            peer.messages, peer.errors, peer.requests, peer.challenges = [], [], [], []
            peer.changed = backend.changed
            peer.authenticated = backend.authenticated
            peer.parallel = backend.parallel
            peer.parallel_records = backend.parallel_records
            peer.parallel_sockets = backend.parallel_sockets
            peer.parallel_actions = {}
            if upstream_tls:
                peer.socket = context.wrap_socket(peer.socket, server_side=True)
            thread = threading.Thread(target=peer.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join)
            self.addCleanup(peer.server_close)
            self.addCleanup(peer.shutdown)
        for _, release in backend.parallel.values():
            self.addCleanup(release.set)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            quic_port = reservation.getsockname()[1]
        options = "" if shared is None else (
            "keepalive 16;" if shared else "keepalive 1; keepalive_requests 1;"
        )
        scheme = "https" if upstream_tls else "http"
        config = prefix / "nginx.conf"
        error_log = prefix / "error.log"
        servers = "\n".join(
            f"server 127.0.0.1:{peer.server_address[1]} "
            f"{server_options if index == 0 else 'backup'};"
            for index, peer in enumerate(backends)
        )
        config.write_text(
            f"""
{f'load_module {os.environ["TEST_NGINX_MODULE"]};' if os.environ.get("TEST_NGINX_MODULE") else ""}
daemon off;
master_process off;
pid {prefix}/nginx.pid;
error_log {error_log} {"debug" if debug else "info"};
events {{ worker_connections 256; }}
http {{
    access_log off;
    {extra_http_config}
    upstream backend {{
        zone protocol_peers 64k;
        {servers}
        {options}
        ntlm 16;
    }}
    server {{
        listen 127.0.0.1:{port};
        http2 on;
        listen 127.0.0.1:{quic_port} quic;
        ssl_certificate {cert};
        ssl_certificate_key {key};
        ssl_protocols TLSv1.3;
        location /auth {{ proxy_pass {scheme}://backend; }}
        location /plain {{ return 200 "OK"; }}
        {extra_server_config}
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_ssl_session_reuse on;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate {cert};
        proxy_ssl_name localhost;
        proxy_ssl_server_name on;
        {proxy_options}
    }}
}}
""", encoding="ascii")
        process = subprocess.Popen(
            [nginx, "-p", str(prefix), "-c", str(config)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop_nginx, process)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail(process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return backend, port, quic_port, cert, error_log
            except ConnectionRefusedError:
                time.sleep(0.01)
        self.fail("nginx readiness timeout")

    @staticmethod
    def stop_nginx(process):
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)

    def client(self, port):
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        self.addCleanup(client.close)
        return client

    @staticmethod
    def request(client, message=None, force_challenge=False, scheme="NTLM",
                status=None, no_challenge=False, challenge_layout=None):
        headers = {}
        if force_challenge:
            headers["X-Audit-Challenge"] = "1"
        if message:
            headers["Authorization"] = scheme + " " + base64.b64encode(message).decode()
        if status is not None:
            headers["X-Audit-Status"] = str(status)
        if no_challenge:
            headers["X-Audit-No-Challenge"] = "1"
        if challenge_layout:
            headers["X-Audit-Challenge-Layout"] = challenge_layout
        client.request("GET", "/auth", headers=headers)
        response = client.getresponse()
        response.read()
        return response.status, dict(response.getheaders())

    def handshake(self, client):
        context = spnego.client(USERNAME, PASSWORD, protocol="ntlm")
        status, challenge = self.request(client, context.step())
        self.assertEqual(status, 401)
        message = context.step(
            base64.b64decode(challenge["WWW-Authenticate"].split(" ", 1)[1])
        )
        status, authenticated = self.request(client, message)
        self.assertEqual(status, 200)
        self.assertEqual(
            challenge["X-Connection-ID"], authenticated["X-Connection-ID"]
        )
        return authenticated


class ProtocolTests(ProtocolTestCase):
    def test_two_live_clients_retain_separate_authenticated_sockets(self):
        backend, port, _, _, _ = self.start()
        alice, bob = self.client(port), self.client(port)
        alice_id = self.handshake(alice)["X-Connection-ID"]
        bob_id = self.handshake(bob)["X-Connection-ID"]
        self.assertNotEqual(alice_id, bob_id)

        for _ in range(3):
            for client, expected_id in ((alice, alice_id), (bob, bob_id)):
                status, headers = self.request(client)
                self.assertEqual(status, 200)
                self.assertEqual(headers["X-Connection-ID"], expected_id)

        self.assertEqual(self.request(self.client(port))[0], 401)
        self.assertFalse(backend.errors)

    def test_challenge_first_and_preemptive_ntlm_keep_the_handshake_socket(self):
        for shared, challenge_first in [(False, True), (True, False), (True, True), (None, True)]:
            with self.subTest(shared=shared, challenge_first=challenge_first):
                backend, port, _, _, _ = self.start(shared=shared)
                client = self.client(port)
                if challenge_first:
                    self.assertEqual(self.request(client)[0], 401)
                self.handshake(client)
                self.assertEqual([kind for kind, _ in backend.messages], [1, 3])
                self.assertFalse(backend.errors)
                self.assertEqual(self.request(client)[0], 200)

    def test_real_ntlm_over_verified_tls_with_shared_zone_and_session_reuse(self):
        for tls in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            with self.subTest(tls=tls):
                backend, port, _, _, _ = self.start(upstream_tls=tls)
                for _ in range(5):
                    owner = self.client(port)
                    authenticated = self.handshake(owner)
                    self.assertEqual(self.request(owner)[0], 200)
                    status, anonymous = self.request(self.client(port))
                    self.assertEqual(status, 401)
                    self.assertNotEqual(
                        authenticated["X-Connection-ID"], anonymous["X-Connection-ID"]
                    )
                    owner.close()
                self.assertFalse(backend.errors)

    def test_shared_pool_cannot_displace_a_real_authenticated_session(self):
        backend, port, _, _, _ = self.start(server_options="max_conns=2")
        owner, stranger = self.client(port), self.client(port)
        authenticated = self.handshake(owner)
        self.assertEqual(self.request(owner)[0], 200)
        status, shared = self.request(stranger)
        self.assertEqual(status, 401)
        self.assertNotEqual(authenticated["X-Connection-ID"], shared["X-Connection-ID"])
        for _ in range(5):
            status, pinned = self.request(owner)
            self.assertEqual(status, 200)
            self.assertEqual(authenticated["X-Connection-ID"], pinned["X-Connection-ID"])
            self.assertEqual(self.request(stranger)[0], 401)
        self.assertFalse(backend.errors)

    def test_new_credentials_restart_an_authenticated_session(self):
        backend, port, _, _, _ = self.start()
        client = self.client(port)
        first = self.handshake(client)
        self.assertEqual(self.request(client, force_challenge=True)[0], 401)
        second = self.handshake(client)
        self.assertNotEqual(first["X-Connection-ID"], second["X-Connection-ID"])
        self.assertEqual([kind for kind, _ in backend.messages], [1, 3, 1, 3])
        self.assertFalse(backend.errors)

    def test_error_or_public_response_does_not_finish_ntlm_negotiation(self):
        backend, port, _, _, _ = self.start()
        for status in (200, 403, 429, 500):
            with self.subTest(status=status):
                client = self.client(port)
                context = spnego.client(USERNAME, PASSWORD, protocol="ntlm")
                actual, challenge = self.request(client, context.step())
                self.assertEqual(actual, 401)
                actual, intermediate = self.request(
                    client, status=status, no_challenge=True
                )
                self.assertEqual(actual, status)
                self.assertEqual(
                    challenge["X-Connection-ID"], intermediate["X-Connection-ID"]
                )
                message = context.step(
                    base64.b64decode(challenge["WWW-Authenticate"].split(" ", 1)[1])
                )
                actual, completed = self.request(client, message)
                self.assertEqual(actual, 200)
                self.assertEqual(
                    challenge["X-Connection-ID"], completed["X-Connection-ID"]
                )
        self.assertFalse(backend.errors)

    def test_ntlm_type1_without_a_matching_challenge_does_not_allow_type3_reuse(self):
        backend, port, _, _, _ = self.start()
        for layout in (None, "bare", "other-scheme"):
            with self.subTest(layout=layout):
                client = self.client(port)
                context = spnego.client(USERNAME, PASSWORD, protocol="ntlm")
                _, first = self.request(
                    client, context.step(), status=200,
                    no_challenge=layout is None, challenge_layout=layout,
                )
                # The verifier made a real challenge even if nginx never saw it.
                if layout is None:
                    message = b"NTLMSSP\0\x03\0\0\0"
                else:
                    message = context.step(
                        base64.b64decode(backend.challenges[-1].split(" ", 1)[1])
                    )
                status, final = self.request(client, message)
                self.assertEqual(status, 401)
                self.assertNotEqual(first["X-Connection-ID"], final["X-Connection-ID"])

    def test_malformed_spnego_response_envelopes_restart_the_socket(self):
        _, port, _, _, _ = self.start()
        for malformed in (
            b"\xa1\x82\xff", b"\xa1\x02\x30\x00",
            b"\xa1\x07\x30\x05\xa0\x03\x0a\x01\x01",
        ):
            with self.subTest(malformed=malformed):
                client = self.client(port)
                context = spnego.client(USERNAME, PASSWORD, protocol="negotiate")
                _, first = self.request(client, context.step(), scheme="Negotiate")
                status, final = self.request(client, malformed, scheme="Negotiate")
                self.assertEqual(status, 401)
                self.assertNotEqual(first["X-Connection-ID"], final["X-Connection-ID"])

    def test_type1_restarts_even_an_unfinished_ntlm_exchange(self):
        backend, port, _, _, _ = self.start()
        client = self.client(port)
        context = spnego.client(USERNAME, PASSWORD, protocol="ntlm")
        status, first = self.request(client, context.step())
        self.assertEqual(status, 401)
        second = self.handshake(client)
        self.assertNotEqual(first["X-Connection-ID"], second["X-Connection-ID"])
        self.assertEqual([kind for kind, _ in backend.messages], [1, 1, 3])
        self.assertFalse(backend.errors)

    def test_spnego_challenges_continue_and_initial_tokens_restart(self):
        backend, port, _, _, _ = self.start()
        client = self.client(port)
        previous = None
        for response_status in (401, 200, 403, 429, 500):
            with self.subTest(response_status=response_status):
                context = spnego.client(USERNAME, PASSWORD, protocol="negotiate")
                initial = context.step()
                self.assertEqual(initial[0], 0x60)
                status, challenge = self.request(
                    client, initial, scheme="Negotiate", status=response_status
                )
                self.assertEqual(status, response_status)
                current = challenge["X-Connection-ID"]
                if previous is not None:
                    self.assertNotEqual(previous, current)
                message = context.step(
                    base64.b64decode(challenge["WWW-Authenticate"].split(" ", 1)[1])
                )
                status, completed = self.request(client, message, scheme="Negotiate")
                self.assertEqual(status, 200)
                self.assertEqual(current, completed["X-Connection-ID"])
                previous = current
        self.assertFalse(backend.errors)

    def test_switching_authentication_schemes_restarts_the_connection(self):
        backend, port, _, _, _ = self.start()
        client = self.client(port)
        context = spnego.client(USERNAME, PASSWORD, protocol="negotiate")
        status, first = self.request(client, context.step(), scheme="Negotiate")
        self.assertEqual(status, 401)
        second = self.handshake(client)
        self.assertNotEqual(first["X-Connection-ID"], second["X-Connection-ID"])
        self.assertFalse(backend.errors)

    def test_only_matching_token_bearing_challenges_allow_spnego_continuation(self):
        backend, port, _, _, _ = self.start()
        for layout, expected in [
            ("combined", 200), ("separate", 200), ("quoted-only", 401),
            ("different-scheme", 401), ("bare", 401), ("reject", 401),
            ("truncated", 401), ("empty-field", 401), ("trailing-state", 401)
        ]:
            with self.subTest(layout=layout):
                client = self.client(port)
                context = spnego.client(USERNAME, PASSWORD, protocol="negotiate")
                status, first = self.request(
                    client, context.step(), scheme="Negotiate",
                    challenge_layout=layout
                )
                self.assertEqual(status, 401)
                message = context.step(
                    base64.b64decode(backend.challenges[-1].split(" ", 1)[1])
                )
                status, final = self.request(client, message, scheme="Negotiate")
                self.assertEqual(status, expected)
                self.assertEqual(
                    first["X-Connection-ID"] == final["X-Connection-ID"],
                    expected == 200,
                )

    def test_raw_ntlm_inside_negotiate_preserves_type3_and_restarts_type1(self):
        backend, port, _, _, _ = self.start()
        client = self.client(port)
        ids = []
        for _ in range(2):
            context = spnego.client(USERNAME, PASSWORD, protocol="ntlm")
            status, first = self.request(client, context.step(), scheme="Negotiate")
            self.assertEqual(status, 401)
            message = context.step(
                base64.b64decode(first["WWW-Authenticate"].split(" ", 1)[1])
            )
            status, final = self.request(client, message, scheme="Negotiate")
            self.assertEqual(status, 200)
            self.assertEqual(first["X-Connection-ID"], final["X-Connection-ID"])
            ids.append(final["X-Connection-ID"])
        self.assertNotEqual(ids[0], ids[1])
        self.assertFalse(backend.errors)

    def test_later_matching_challenges_are_not_hidden_by_bare_or_invalid_entries(self):
        backend, port, _, _, _ = self.start()
        for scheme in ("NTLM", "Negotiate"):
            for layout in (
                "duplicate-combined", "duplicate-separate",
                "invalid-combined", "invalid-separate",
            ):
                with self.subTest(scheme=scheme, layout=layout):
                    client = self.client(port)
                    context = spnego.client(
                        USERNAME, PASSWORD, protocol=scheme.lower()
                    )
                    status, first = self.request(
                        client, context.step(), scheme=scheme, challenge_layout=layout
                    )
                    self.assertEqual(status, 401)
                    message = context.step(base64.b64decode(
                        backend.challenges[-1].split(" ", 1)[1]
                    ))
                    status, final = self.request(client, message, scheme=scheme)
                    self.assertEqual(status, 200)
                    self.assertEqual(first["X-Connection-ID"], final["X-Connection-ID"])
        self.assertFalse(backend.errors)

    def test_spnego_rejection_before_a_challenge_blocks_continuation(self):
        backend, port, _, _, _ = self.start()
        for layout in ("reject-combined", "reject-separate"):
            with self.subTest(layout=layout):
                client = self.client(port)
                context = spnego.client(USERNAME, PASSWORD, protocol="negotiate")
                status, first = self.request(
                    client, context.step(), scheme="Negotiate", challenge_layout=layout
                )
                self.assertEqual(status, 401)
                message = context.step(base64.b64decode(
                    backend.challenges[-1].split(" ", 1)[1]
                ))
                status, final = self.request(client, message, scheme="Negotiate")
                self.assertEqual(status, 401)
                self.assertNotEqual(first["X-Connection-ID"], final["X-Connection-ID"])

    def test_completed_spnego_token_does_not_authorize_another_continuation(self):
        backend, port, _, _, _ = self.start()
        client = self.client(port)
        context = spnego.client(USERNAME, PASSWORD, protocol="negotiate")
        status, challenge = self.request(client, context.step(), scheme="Negotiate")
        self.assertEqual(status, 401)
        message = context.step(
            base64.b64decode(challenge["WWW-Authenticate"].split(" ", 1)[1])
        )
        status, completed = self.request(client, message, scheme="Negotiate")
        self.assertEqual(status, 200)
        context.step(
            base64.b64decode(completed["WWW-Authenticate"].split(" ", 1)[1])
        )
        self.assertTrue(context.complete)
        self.assertFalse(backend.errors)
        status, replay = self.request(client, message, scheme="Negotiate")
        self.assertEqual(status, 401)
        self.assertNotEqual(completed["X-Connection-ID"], replay["X-Connection-ID"])

    def test_unrecognized_credentials_do_not_inherit_the_old_session(self):
        _, port, _, _, _ = self.start()
        client = self.client(port)
        authenticated = self.handshake(client)
        status, rejected = self.request(client, b"unrecognized-authentication-token")
        self.assertEqual(status, 401)
        self.assertNotEqual(
            authenticated["X-Connection-ID"], rejected["X-Connection-ID"]
        )

    def test_http3_rejects_ntlm_without_disabling_other_streams(self):
        backend, _, port, cert, error_log = self.start()

        async def exercise():
            configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
            configuration.server_name = "localhost"
            configuration.load_verify_locations(str(cert))
            async with connect_h3(port, configuration) as client:
                message = spnego.client(USERNAME, PASSWORD, protocol="ntlm").step()
                for token in (None, message):
                    response = await client.request("/auth", token)
                    self.assertEqual(response[":status"], "500")
                    self.assertFalse(backend.requests)
                    plain = await client.request("/plain")
                    self.assertEqual(plain[":status"], "200")

        asyncio.run(exercise())
        self.assertIn("requests are not supported", error_log.read_text())


    def test_http2_rejects_ntlm_without_disabling_other_streams(self):
        backend, port, _, _, error_log = self.start()

        def frame(kind, flags, stream, data):
            return (
                len(data).to_bytes(3, "big") + bytes([kind, flags])
                + stream.to_bytes(4, "big") + data
            )

        def receive(connection, length):
            data = b""
            while len(data) < length:
                chunk = connection.recv(length - len(data))
                self.assertTrue(chunk, "HTTP/2 connection closed unexpectedly")
                data += chunk
            return data

        with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
            connection.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b""))
            for stream, path, expected in [(1, b"/auth", 500), (3, b"/plain", 200)]:
                headers = b"\x82\x86\x04" + bytes([len(path)]) + path + b"\x01\x09localhost"
                connection.sendall(frame(1, 5, stream, headers))
                status = None
                while True:
                    header = receive(connection, 9)
                    payload = receive(connection, int.from_bytes(header[:3], "big"))
                    kind, flags = header[3:5]
                    received_stream = int.from_bytes(header[5:], "big") & 0x7FFFFFFF
                    if kind == 4 and not flags & 1:
                        connection.sendall(frame(4, 1, 0, b""))
                    if received_stream != stream:
                        continue
                    if kind == 1:
                        status = {0x88: 200, 0x8E: 500}.get(payload[0])
                    if kind in (0, 1) and flags & 1:
                        break
                self.assertEqual(status, expected)
        self.assertFalse(backend.requests)
        self.assertIn("requests are not supported", error_log.read_text())


class ParallelProtocolTests(ProtocolTestCase):
    def start_parallel(self, **options):
        return self.start(
            debug=True,
            extra_http_config="""
                log_format parallel '$uri $upstream_status $upstream_addr';
            """,
            extra_server_config="""
                log_subrequest on;
                access_log parallel-access.log parallel;
                location = /parallel {
                    default_type text/html;
                    ssi on;
                    return 200 '<!--# include virtual="/auth/parallel/first" wait="no" --><!--# include virtual="/auth/parallel/second" wait="no" -->';
                }
            """,
            **options,
        )

    def wait_until(self, predicate, message):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail(message)

    @staticmethod
    def reset_parallel(backend):
        backend.parallel_records.clear()
        backend.parallel_sockets.clear()
        for arrived, release in backend.parallel.values():
            arrived.clear()
            release.clear()

    def wait_for_overlap(self, backend):
        for arrived, _ in backend.parallel.values():
            self.assertTrue(arrived.wait(timeout=3), "subrequests did not overlap")
        first, second = backend.parallel_records
        self.assertNotEqual(first["connection"], second["connection"])

    @contextmanager
    def parallel_request(self, owner, backend, error_log, headers=None):
        self.reset_parallel(backend)
        offset = error_log.stat().st_size

        def fetch():
            owner.request("GET", "/parallel", headers=headers or {})
            response = owner.getresponse()
            return response.status, response.read()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(fetch)
            try:
                self.wait_for_overlap(backend)
                yield future, offset
            finally:
                for _, release in backend.parallel.values():
                    release.set()

    def finish_first(self, backend, error_log, name, offset, rc=0):
        backend.parallel[name][1].set()
        # Core logs this after upstream free_peer; SSI access logging can wait
        # for the other subrequest's output and cannot establish this ordering.
        marker = f'http finalize request: {rc}, "/auth/parallel/{name}?'
        self.wait_until(
            lambda: marker in error_log.read_text()[offset:],
            f"{name} did not finalize while the other response was held",
        )

    def response_records(self, future):
        status, body = future.result(timeout=3)
        self.assertEqual(status, 200)
        records = [json.loads(line) for line in body.splitlines()]
        self.assertEqual([record["name"] for record in records], ["first", "second"])
        return records

    def assert_recovery(self, backend, port, owner):
        self.assertEqual(self.request(owner)[0], 401)
        self.handshake(owner)
        self.assertEqual(self.request(owner)[0], 200)
        self.assertEqual(self.request(self.client(port))[0], 401)
        self.assertFalse(any(peer.errors for peer in backend.peers))

    def test_authenticated_parallel_requests_preserve_only_the_pinned_identity(self):
        for finishes_first in ("first", "second"):
            with self.subTest(finishes_first=finishes_first):
                backend, port, _, _, log = self.start_parallel()
                owner = self.client(port)
                authenticated = self.handshake(owner)
                with self.parallel_request(owner, backend, log) as (future, offset):
                    self.finish_first(backend, log, finishes_first, offset)
                first, second = self.response_records(future)
                self.assertEqual(first["status"], 200)
                self.assertTrue(first["authenticated"])
                self.assertEqual(first["principal"], USERNAME)
                self.assertEqual(
                    str(first["connection"]), authenticated["X-Connection-ID"]
                )
                self.assertEqual(second["status"], 401)
                self.assertFalse(second["authenticated"])
                self.assertIsNone(second["principal"])
                status, followup = self.request(owner)
                self.assertEqual(status, 200)
                self.assertEqual(
                    followup["X-Connection-ID"], authenticated["X-Connection-ID"]
                )
                self.assertEqual(self.request(self.client(port))[0], 401)
                self.assertFalse(backend.errors)

    def test_parallel_real_handshakes_cannot_retain_both_challenge_sockets(self):
        for retained, finishes_first in (
            ("first", "first"), ("first", "second"),
            ("second", "first"), ("second", "second"),
        ):
            with self.subTest(retained=retained, finishes_first=finishes_first):
                backend, port, _, _, log = self.start_parallel()
                owner = self.client(port)
                context = spnego.client(USERNAME, PASSWORD, protocol="ntlm")
                headers = {
                    "Authorization": "NTLM " + base64.b64encode(context.step()).decode()
                }
                challenge_finishes_first = "second" if retained == "first" else "first"
                with self.parallel_request(
                    owner, backend, log, headers
                ) as (future, offset):
                    self.finish_first(backend, log, challenge_finishes_first, offset)
                challenges = self.response_records(future)
                for record in challenges:
                    self.assertEqual(record["status"], 401)
                    self.assertFalse(record["authenticated"])
                # Both subrequests inherit the real downstream Authorization.
                # Continue the first challenge, whether or not its socket won.
                token = context.step(
                    base64.b64decode(challenges[0]["challenge"].split(" ", 1)[1])
                )
                headers["Authorization"] = "NTLM " + base64.b64encode(token).decode()

                with self.parallel_request(
                    owner, backend, log, headers
                ) as (future, offset):
                    self.finish_first(backend, log, finishes_first, offset)
                completed = self.response_records(future)
                # The first continuation takes the sole retained socket even
                # when its Type 3 belongs to the other, discarded challenge.
                self.assertEqual(
                    completed[0]["connection"],
                    next(r["connection"] for r in challenges if r["name"] == retained),
                )
                expected = [200, 401] if retained == "first" else [401, 401]
                self.assertEqual([r["status"] for r in completed], expected)
                self.assertEqual(
                    [r["authenticated"] for r in completed],
                    [retained == "first", False],
                )
                self.assertEqual(len(backend.errors), 1 if retained == "first" else 2)
                self.assertEqual([kind for kind, _ in backend.messages], [1, 1, 3, 3])
                # A failed continuation that finishes last can also replace a
                # concurrently authenticated socket with its unauthenticated one.
                status, followup = self.request(owner)
                survives = retained == "first" and finishes_first == "second"
                self.assertEqual(status, 200 if survives else 401)
                if survives:
                    self.assertEqual(
                        followup["X-Connection-ID"], str(completed[0]["connection"])
                    )
                self.handshake(owner)
                self.assertEqual(self.request(owner)[0], 200)
                self.assertEqual(self.request(self.client(port))[0], 401)

    def test_client_abort_closes_active_authenticated_upstream(self):
        backend, port, _, _, log = self.start_parallel()
        owner = self.client(port)
        self.handshake(owner)
        backend.parallel_actions.update(first="abort", second="abort")
        self.reset_parallel(backend)
        try:
            owner.request("GET", "/parallel")
            self.wait_for_overlap(backend)
            sockets = list(backend.parallel_sockets.values())
            self.assertEqual(sum(r["authenticated"] for r in backend.parallel_records), 1)
            owner.sock.shutdown(socket.SHUT_RDWR)
            owner.close()

            def disconnected(connection):
                if not select.select([connection], [], [], 0)[0]:
                    return False
                try:
                    return connection.recv(1, socket.MSG_PEEK) == b""
                except ConnectionResetError:
                    return True

            self.wait_until(
                lambda: all(disconnected(connection) for connection in sockets),
                "nginx kept an active upstream open after downstream abort",
            )
        finally:
            for _, release in backend.parallel.values():
                release.set()
        with backend.changed:
            self.assertTrue(
                backend.changed.wait_for(lambda: not backend.authenticated, timeout=3),
                "authenticated socket survived client abort",
            )
        self.assert_recovery(backend, port, self.client(port))

    def exercise_upstream_failure(self, action, retry):
        backend, port, _, _, log = self.start_parallel(
            backend_count=2 if retry else 1,
            server_options="max_conns=1" if retry else "",
            proxy_options=(
                "proxy_next_upstream error timeout http_403; "
                "proxy_next_upstream_tries 2;"
                if retry else "proxy_next_upstream off;"
            ),
        )
        owner = self.client(port)
        self.handshake(owner)
        backend.parallel_actions["first"] = action
        with self.parallel_request(owner, backend, log) as (future, offset):
            self.finish_first(backend, log, "first", offset, rc=0 if retry else 502)
        status, _ = future.result(timeout=3)
        self.assertEqual(status, 200)
        attempts = [r for r in backend.parallel_records if r["name"] == "first"]
        self.assertTrue(attempts[0]["authenticated"])
        self.assertEqual(attempts[0]["action"], action)
        self.assertEqual(len(attempts), 2 if retry else 1)
        if retry:
            self.assertEqual(attempts[1]["backend"], backend.peers[1].server_address[1])
            self.assertEqual(attempts[1]["status"], 401)
            self.assertFalse(attempts[1]["authenticated"])
        other = [r for r in backend.parallel_records if r["name"] == "second"]
        self.assertEqual(len(other), 1)
        self.assertEqual(other[0]["status"], 401)
        self.assertFalse(other[0]["authenticated"])
        access_log = log.parent / "parallel-access.log"
        expected = (
            f"/auth/parallel/first {'403' if action == 'retry' else '502'}, 401 "
            if retry else "/auth/parallel/first 502 "
        )
        self.wait_until(
            lambda: expected in access_log.read_text(),
            "unexpected upstream retry/status chain",
        )
        with backend.changed:
            self.assertTrue(
                backend.changed.wait_for(lambda: not backend.authenticated, timeout=3),
                "failed authenticated socket was retained",
            )
        self.assert_recovery(backend, port, owner)

    def test_backend_disconnect_without_retry_requires_reauthentication(self):
        self.exercise_upstream_failure("drop", retry=False)

    def test_backend_disconnect_retries_on_an_unauthenticated_backup(self):
        self.exercise_upstream_failure("drop", retry=True)

    def test_next_upstream_403_rejects_the_authenticated_socket_before_retry(self):
        self.exercise_upstream_failure("retry", retry=True)
