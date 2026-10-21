import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import struct
import time


def parse_request(packet):
    if len(packet) < 4 or struct.unpack('!H', packet[:2])[0] != 1:
        raise ValueError('Only read requests are supported')
    fields = packet[2:].split(b'\0')
    if fields[-1] != b'':
        raise ValueError('Request is not null-terminated')
    fields.pop()
    if len(fields) < 2 or (len(fields) - 2) % 2:
        raise ValueError('Malformed request fields')
    filename, mode = (field.decode('ascii') for field in fields[:2])
    if filename != 'tp_recovery.bin' or mode.lower() != 'octet':
        raise ValueError('Only tp_recovery.bin in octet mode is available')
    options = {}
    for index in range(2, len(fields), 2):
        name = fields[index].decode('ascii').lower()
        if name in options:
            raise ValueError('Duplicate option')
        options[name] = fields[index + 1].decode('ascii')
    return options


def negotiate(options, size):
    accepted = {}
    if 'blksize' in options:
        requested = int(options['blksize'])
        if not 8 <= requested <= 65464:
            raise ValueError('Invalid block size')
        accepted['blksize'] = str(min(requested, 1468))
    if 'timeout' in options:
        timeout = int(options['timeout'])
        if not 1 <= timeout <= 5:
            raise ValueError('Timeout must be between one and five seconds')
        accepted['timeout'] = str(timeout)
    if 'tsize' in options:
        if int(options['tsize']) != 0:
            raise ValueError('Read request transfer size must be zero')
        accepted['tsize'] = str(size)
    return accepted


def send_and_ack(connection, peer, packet, block, timeout):
    for attempt in range(10):
        connection.sendto(packet, peer)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            connection.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                response, sender = connection.recvfrom(2048)
            except socket.timeout:
                break
            if sender != peer:
                continue
            if len(response) >= 2 and struct.unpack('!H', response[:2])[0] == 5:
                raise RuntimeError('The bootloader returned a TFTP error')
            if len(response) == 4 and struct.unpack('!HH', response) == (4, block):
                return
    raise TimeoutError(f'No acknowledgement for block {block}')


def serve(arguments):
    address = str(ipaddress.IPv4Address(arguments.bind))
    client = str(ipaddress.IPv4Address(arguments.client))
    if address == '0.0.0.0' or client == '0.0.0.0':
        raise ValueError('Explicit server and client addresses are required')
    data = arguments.image.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if not data or len(data) > 16 * 1024 * 1024 or digest != arguments.sha256:
        raise ValueError('Image size/hash validation failed')

    def status(state, **details):
        record = {'state': state, 'timestamp': time.time(), **details}
        print(json.dumps(record), flush=True)
        if arguments.status:
            temporary = arguments.status.with_suffix('.tmp')
            temporary.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
            temporary.replace(arguments.status)

    deadline = time.monotonic() + arguments.wait_seconds
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind((address, arguments.port))
        status('waiting', bind=address, client=client, size=len(data), sha256=digest)
        while time.monotonic() < deadline:
            listener.settimeout(min(5, max(0.01, deadline - time.monotonic())))
            try:
                request, peer = listener.recvfrom(2048)
            except socket.timeout:
                continue
            if peer[0] != client:
                continue
            try:
                options = negotiate(parse_request(request), len(data))
            except (UnicodeError, ValueError) as error:
                listener.sendto(struct.pack('!HH', 5, 4) + str(error).encode('ascii', 'replace') + b'\0', peer)
                continue
            block_size = int(options.get('blksize', 512))
            timeout = int(options.get('timeout', 2))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as transfer:
                transfer.bind((address, arguments.transfer_port))
                status('transferring', peer=list(peer), size=len(data), block_size=block_size)
                try:
                    if options:
                        acknowledgement = struct.pack('!H', 6) + b''.join(
                            name.encode('ascii') + b'\0' + value.encode('ascii') + b'\0'
                            for name, value in options.items())
                        send_and_ack(transfer, peer, acknowledgement, 0, timeout)
                    offset = 0
                    block = 1
                    while True:
                        chunk = data[offset:offset + block_size]
                        send_and_ack(transfer, peer, struct.pack('!HH', 3, block) + chunk, block, timeout)
                        offset += len(chunk)
                        if len(chunk) < block_size:
                            break
                        block = (block + 1) % 65536
                    status('complete', bytes_sent=offset, last_block=block, sha256=digest)
                    return
                except (OSError, RuntimeError) as error:
                    status('transfer-error', error=str(error))
                    raise
    status('expired')
    raise TimeoutError('No valid bootloader request arrived before the deadline')


def main():
    parser = argparse.ArgumentParser(description='Serve one verified TP-Link recovery image to one client')
    parser.add_argument('--bind', required=True)
    parser.add_argument('--client', required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--port', type=int, default=69)
    parser.add_argument('--transfer-port', type=int, default=60069)
    parser.add_argument('--wait-seconds', type=int, default=1200)
    parser.add_argument('--status', type=Path)
    arguments = parser.parse_args()
    if not 1 <= arguments.port <= 65535 or not 1 <= arguments.transfer_port <= 65535 or arguments.wait_seconds < 1:
        parser.error('Invalid port or waiting time')
    serve(arguments)


if __name__ == '__main__':
    main()
