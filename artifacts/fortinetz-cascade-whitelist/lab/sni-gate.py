#!/usr/bin/env python3
import argparse
import ipaddress
import json
import select
import socket
import struct
import sys
import time

SO_ORIGINAL_DST = 80
BUFFER_SIZE = 65536


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        data += chunk
    return data


def original_destination(sock):
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    family = struct.unpack_from("H", raw, 0)[0]
    if family != socket.AF_INET:
        raise RuntimeError(f"unsupported original destination family: {family}")
    port = struct.unpack_from("!H", raw, 2)[0]
    host = socket.inet_ntoa(raw[4:8])
    return host, port


def recv_client_hello(sock):
    sock.settimeout(5)
    data = b""
    while len(data) < 5:
        chunk = sock.recv(5 - len(data))
        if not chunk:
            break
        data += chunk
    if len(data) < 5:
        return data
    record_len = int.from_bytes(data[3:5], "big")
    wanted = 5 + record_len
    while len(data) < wanted:
        chunk = sock.recv(min(BUFFER_SIZE, wanted - len(data)))
        if not chunk:
            break
        data += chunk
    return data


def parse_sni(data):
    try:
        if len(data) < 9 or data[0] != 0x16:
            return ""
        pos = 5
        if data[pos] != 0x01:
            return ""
        handshake_len = int.from_bytes(data[pos + 1:pos + 4], "big")
        end = min(len(data), pos + 4 + handshake_len)
        pos += 4
        pos += 2 + 32
        if pos >= end:
            return ""
        session_len = data[pos]
        pos += 1 + session_len
        if pos + 2 > end:
            return ""
        cipher_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cipher_len
        if pos >= end:
            return ""
        compression_len = data[pos]
        pos += 1 + compression_len
        if pos + 2 > end:
            return ""
        extensions_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        extensions_end = min(end, pos + extensions_len)
        while pos + 4 <= extensions_end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            ext_end = pos + ext_len
            if ext_end > extensions_end:
                return ""
            if ext_type == 0:
                if pos + 2 > ext_end:
                    return ""
                list_len = int.from_bytes(data[pos:pos + 2], "big")
                name_pos = pos + 2
                list_end = min(ext_end, name_pos + list_len)
                while name_pos + 3 <= list_end:
                    name_type = data[name_pos]
                    name_len = int.from_bytes(data[name_pos + 1:name_pos + 3], "big")
                    name_pos += 3
                    if name_pos + name_len > list_end:
                        return ""
                    if name_type == 0:
                        return data[name_pos:name_pos + name_len].decode("ascii", "ignore").lower()
                    name_pos += name_len
            pos = ext_end
    except Exception:
        return ""
    return ""


def resolves_to(sni, host):
    if not sni:
        return False
    try:
        target = ipaddress.ip_address(host)
    except ValueError:
        return False
    try:
        infos = socket.getaddrinfo(sni, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return False
    resolved = {ipaddress.ip_address(info[4][0]) for info in infos}
    return target in resolved


def socks5_connect_destination(sock):
    header = recv_exact(sock, 2)
    version, methods_len = header[0], header[1]
    if version != 5:
        raise RuntimeError(f"unsupported SOCKS version: {version}")
    _ = recv_exact(sock, methods_len)
    sock.sendall(b"\x05\x00")

    request = recv_exact(sock, 4)
    version, command, _, address_type = request
    if version != 5 or command != 1:
        sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        raise RuntimeError("unsupported SOCKS command")

    if address_type == 1:
        host = socket.inet_ntoa(recv_exact(sock, 4))
    elif address_type == 3:
        host_len = recv_exact(sock, 1)[0]
        host = recv_exact(sock, host_len).decode("idna").lower()
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
        raise RuntimeError(f"unsupported SOCKS address type: {address_type}")

    port = int.from_bytes(recv_exact(sock, 2), "big")
    sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    return host, port


def decision(policy, sni, original_host, original_port):
    sni = (sni or "").lower().rstrip(".")
    if policy == "strict_ru_sni":
        return sni.endswith(".ru") or sni.endswith(".xn--p1ai")
    if policy == "popular_sni_allow":
        return sni in {
            "www.amazon.com",
            "www.bing.com",
            "www.microsoft.com",
            "www.cloudflare.com",
            "www.apple.com",
        }
    if policy == "sni_ip_match":
        return resolves_to(sni, original_host)
    if policy == "entry_ip_block":
        return not (original_host == "83.222.9.217" and original_port == 443)
    raise RuntimeError(f"unknown policy: {policy}")


def pipe(client, remote):
    sockets = [client, remote]
    while sockets:
        readable, _, _ = select.select(sockets, [], [], 30)
        if not readable:
            break
        for source in readable:
            try:
                data = source.recv(BUFFER_SIZE)
            except OSError:
                data = b""
            if not data:
                sockets = []
                break
            dest = remote if source is client else client
            dest.sendall(data)


def log_event(path, event):
    event["ts"] = time.time()
    line = json.dumps(event, sort_keys=True)
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    print(line, flush=True)


def serve(args):
    host, port_text = args.listen.rsplit(":", 1)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, int(port_text)))
    listener.listen(128)
    log_event(args.log, {"event": "listening", "listen": args.listen, "policy": args.policy})
    while True:
        client, peer = listener.accept()
        try:
            if args.socks5:
                original_host, original_port = socks5_connect_destination(client)
            else:
                original_host, original_port = original_destination(client)
            hello = recv_client_hello(client)
            sni = parse_sni(hello)
            allowed = decision(args.policy, sni, original_host, original_port)
            log_event(args.log, {
                "event": "decision",
                "peer": f"{peer[0]}:{peer[1]}",
                "original_host": original_host,
                "original_port": original_port,
                "policy": args.policy,
                "sni": sni,
                "allowed": allowed,
            })
            if not allowed:
                client.close()
                continue
            remote = socket.create_connection((original_host, original_port), timeout=10)
            remote.sendall(hello)
            pipe(client, remote)
        except Exception as exc:
            log_event(args.log, {"event": "error", "error": str(exc), "policy": args.policy})
        finally:
            try:
                client.close()
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1:18080")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--log", default="")
    parser.add_argument("--socks5", action="store_true")
    args = parser.parse_args()
    serve(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
