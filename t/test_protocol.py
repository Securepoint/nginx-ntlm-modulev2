import asyncio
import base64
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
from contextlib import asynccontextmanager
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

    def do_GET(self):
        self.server.requests.append(self.path)
        authorization = self.headers.get("Authorization")
        status, challenge = 200, None
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
            elif layout == "quoted-only":
                challenge = 'Basic realm="audit, ' + challenge + '"'
            elif layout == "different-scheme":
                challenge = "NTLM " + challenge.split(" ", 1)[1]
            elif layout == "bare":
                challenge = challenge.split(" ", 1)[0]
            elif layout == "reject":
                challenge = "Negotiate " + base64.b64encode(
                    b"\xa1\x07\x30\x05\xa0\x03\x0a\x01\x02"
                ).decode()
            elif layout == "truncated":
                challenge = "Negotiate " + base64.b64encode(b"\xa1\x82\xff\xff").decode()
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.send_header("X-Connection-ID", str(self.client_address[1]))
        if challenge:
            if self.headers.get("X-Audit-Challenge-Layout") == "separate":
                self.send_header("WWW-Authenticate", 'Basic realm="audit"')
            self.send_header("WWW-Authenticate", challenge)
        self.end_headers()
        self.wfile.write(b"OK")

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


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        previous = os.environ.get("NTLM_USER_FILE")
        self.addCleanup(self.restore_credentials, previous)

    @staticmethod
    def restore_credentials(previous):
        if previous is None:
            os.environ.pop("NTLM_USER_FILE", None)
        else:
            os.environ["NTLM_USER_FILE"] = previous

    def start(self, shared=True, server_options=""):
        nginx = shutil.which(os.environ.get("TEST_NGINX_BINARY", "nginx"))
        self.assertIsNotNone(nginx, "build nginx with TLS, HTTP/2 and HTTP/3 first")
        directory = tempfile.TemporaryDirectory(prefix="ntlm-protocol-")
        self.addCleanup(directory.cleanup)
        prefix = Path(directory.name)
        credentials = prefix / "users"
        credentials.write_text(f"AUDIT:test:{PASSWORD}\n", encoding="ascii")
        os.environ["NTLM_USER_FILE"] = str(credentials)
        backend = ThreadingHTTPServer(("127.0.0.1", 0), NTLMHandler)
        backend.daemon_threads = True
        backend.messages, backend.errors, backend.requests, backend.challenges = [], [], [], []
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(backend.server_close)
        self.addCleanup(backend.shutdown)
        cert, key = prefix / "cert.pem", prefix / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            quic_port = reservation.getsockname()[1]
        options = "" if shared is None else f"keepalive {16 if shared else 0};"
        config = prefix / "nginx.conf"
        error_log = prefix / "error.log"
        config.write_text(
            f"""
daemon off;
master_process off;
pid {prefix}/nginx.pid;
error_log {error_log} info;
events {{ worker_connections 256; }}
http {{
    access_log off;
    upstream backend {{
        server 127.0.0.1:{backend.server_address[1]} {server_options};
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
        location /auth {{ proxy_pass http://backend; }}
        location /plain {{ return 200 "OK"; }}
        proxy_http_version 1.1;
        proxy_set_header Connection "";
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
            ("truncated", 401)
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
