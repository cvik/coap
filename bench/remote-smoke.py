#!/usr/bin/env python3
"""Local two-process integration checks. Requires built bench and bench-server."""
import json
from pathlib import Path
import re
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import sys

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / 'zig-out/bin'
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def free_port(family):
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0))
        return s.getsockname()[1]


def client(port, flags, ok=True):
    p = subprocess.run([str(BIN / 'bench'), '--no-server', '--port', str(port),
                        '--count', '4099', '--warmup', '37', '--payload-only', '100',
                        '--allocator', 'smp', *flags], capture_output=True, text=True, timeout=25)
    output = ANSI.sub('', p.stdout + p.stderr)
    assert (p.returncode == 0) == ok, output
    return output


RPC_MID = 1000

def rpc(s, port, action, body=b''):
    # CON with two-byte token; monotonically unique MID across these test calls.
    global RPC_MID
    RPC_MID += 1
    mid = RPC_MID
    token = mid.to_bytes(2, 'big')
    parts = (b'__bench', b'v1', action.encode())
    options = bytes([0xB0 | len(parts[0])]) + parts[0]
    for part in parts[1:]:
        options += bytes([len(part)]) + part
    wire = b'\x42' + bytes([1 if action == 'info' else 2]) + token + token + options
    if body:
        wire += b'\xff' + body
    s.sendto(wire, ('127.0.0.1', port))
    data, _ = s.recvfrom(2048)
    assert data[4:6] == token
    return data[1]


for flag, value in (('--window', '0'), ('--multi-window', '16385'), ('--threads', '257'), ('--count', 'bad'), ('--port', '0')):
    client(1, [flag, value], ok=False)
client(1, ['--window'], ok=False)
print('PASS invalid client arguments are rejected before startup', flush=True)

with tempfile.TemporaryDirectory(prefix='coap-remote-') as directory:
    secret = Path(directory) / 'psk.json'
    secret.write_text(json.dumps({'identity': 'custom-smoke-identity', 'key_hex': secrets.token_hex(32)}))
    secret.chmod(0o600)
    for ipv6 in (False, True):
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        host = '::1' if ipv6 else '127.0.0.1'
        for secure in (False, True):
            port = free_port(family)
            server_args = [str(BIN / 'bench-server'), '--bind', host, '--port', str(port),
                           '--threads', '2', '--max-requests', '20000', '--session-timeout-ms', '1000' if not ipv6 and not secure else '30000']
            if secure:
                server_args += ['--psk-file', str(secret)]
            server = subprocess.Popen(server_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                time.sleep(.4)
                assert server.poll() is None, server.communicate()
                for con in (False, True):
                    for multi in (False, True):
                        flags = ['--host', host, '--dtls-only' if secure else '--plain-only',
                                 '--con-only' if con else '--non-only', '--multi-only' if multi else '--single-only',
                                 '--threads', '2', '--window', '17', '--multi-window', '19']
                        if secure:
                            flags += ['--psk-file', str(secret)]
                        output = client(port, flags)
                        if not con:
                            rows = [json.loads(line.removeprefix('REMOTE_BENCHMARK ')) for line in output.splitlines() if line.startswith('REMOTE_BENCHMARK ')]
                            assert len(rows) == 1, output
                            r = rows[0]
                            assert r['sent'] == 4099 and r['local_errors'] == 0, r
                            assert r['received'] + r['missing'] == r['sent'] and r['duplicates'] == 0, r
                            assert r['threads'] == (2 if multi else 1) and r['payload'] == 100, r
                        else:
                            assert re.search(r'\b[12]T\s+100B\s+[^\n]*\s0\s*$', output, re.MULTILINE), output
                        print(f'PASS {host} {"DTLS" if secure else "plain"} {"CON" if con else "NON"} {"multi" if multi else "single"}', flush=True)
                if not ipv6 and not secure:
                    # Capacity rejection must not fall back to send-rate reporting.
                    output = client(port, ['--plain-only', '--non-only', '--single-only', '--count', '20001'], ok=False)
                    assert 'BenchmarkCapacityExceeded' in output
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
                        control.settimeout(3)
                        nonce = secrets.token_bytes(16)
                        start = nonce + struct.pack('!I', 4096) + b'\x01'
                        assert rpc(control, port, 'start', start) == 69
                        output = client(port, ['--plain-only', '--non-only', '--single-only'], ok=False)
                        assert 'BenchmarkBusy' in output
                        assert rpc(control, port, 'finish', nonce) == 69
                        assert rpc(control, port, 'start', nonce + struct.pack('!I', 4096) + b'\x01') == 69
                        # Simulate a disappeared coordinator: no finish, then wait past lease.
                        time.sleep(1.1)
                        client(port, ['--plain-only', '--non-only', '--single-only'])
                    print('PASS capacity, overlap rejection, abandoned-run lease recovery', flush=True)
            finally:
                server.send_signal(signal.SIGINT if secure else signal.SIGTERM)
                try:
                    out, err = server.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill(); out, err = server.communicate()
                    raise AssertionError('server did not stop on SIGINT/SIGTERM: ' + err)
                assert server.returncode == 0, out + err

# A generic echo server remains usable for CON. Duplicate replies must not
# manufacture completions; an arbitrary window must survive the 16-bit MID wrap.
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as legacy:
    legacy.bind(('127.0.0.1', 0)); legacy.settimeout(.1)
    stop = threading.Event()
    data_requests = [0]
    def echo():
        while not stop.is_set():
            try:
                data, peer = legacy.recvfrom(2048)
            except (socket.timeout, ConnectionRefusedError):
                continue
            if len(data) < 6:
                continue
            length = data[0] & 15
            offset = 4 + length
            marker = data.find(b'\xff', offset)
            body = data[marker:] if marker >= 0 else b''
            response = bytes([0x60 | length, 69]) + data[2:offset] + body
            if marker >= 0:
                data_requests[0] += 1
            try:
                legacy.sendto(response, peer)
                if marker >= 0:
                    legacy.sendto(response, peer)
            except ConnectionRefusedError:
                pass
    thread = threading.Thread(target=echo)
    thread.start()
    try:
        output = client(legacy.getsockname()[1], ['--plain-only', '--con-only', '--single-only', '--window', '17', '--warmup', '0', '--count', '70000'])
        assert 'generic echo server' in output
        assert data_requests[0] == 70000, data_requests
        assert re.search(r'\b1T\s+100B\s+[^\n]*\s0\s*$', output, re.MULTILINE), output
        output = client(legacy.getsockname()[1], ['--plain-only', '--non-only', '--single-only'], ok=False)
        assert 'NotBenchmarkServer' in output and 'REMOTE_BENCHMARK ' not in output
    finally:
        stop.set(); thread.join(timeout=2)
    print('PASS legacy CON, duplicate replies, arbitrary window/MID wrap, unsupported NON rejection', flush=True)
print('Remote benchmark integration checks passed.')
