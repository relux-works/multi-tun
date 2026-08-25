#!/usr/bin/env python3
"""Read a Google Authenticator migration URL from stdin and print one base32 secret."""

import argparse
import base64
import sys
import urllib.parse


def fail(message: str) -> "NoReturn":
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            fail("unexpected end of protobuf while reading a varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            fail("protobuf varint is too large")


def read_message(data: bytes, offset: int) -> tuple[bytes, int]:
    size, offset = read_varint(data, offset)
    end = offset + size
    if end > len(data):
        fail("unexpected end of protobuf while reading a message")
    return data[offset:end], end


def fields(data: bytes):
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        number = tag >> 3
        wire = tag & 0x07
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire == 2:
            value, offset = read_message(data, offset)
        else:
            fail(f"unsupported protobuf wire type: {wire}")
        yield number, wire, value


def parse_entry(data: bytes) -> dict[str, object]:
    entry: dict[str, object] = {"secret": b"", "account": "", "issuer": ""}
    for number, wire, value in fields(data):
        if wire != 2:
            continue
        if number == 1:
            entry["secret"] = value
        elif number == 2:
            entry["account"] = value.decode("utf-8", errors="strict")
        elif number == 3:
            entry["issuer"] = value.decode("utf-8", errors="strict")
    return entry


def decode_source(source: str) -> list[dict[str, object]]:
    source = source.strip()
    if not source:
        fail("input is empty")
    if not source.startswith("otpauth-migration://"):
        fail("expected an otpauth-migration URL")
    raw_query = urllib.parse.urlsplit(source).query
    values = [
        urllib.parse.unquote(part.removeprefix("data="))
        for part in raw_query.split("&")
        if part.startswith("data=")
    ]
    if len(values) != 1 or not values[0]:
        fail("migration URL must contain exactly one data parameter")
    encoded = values[0]
    encoded += "=" * (-len(encoded) % 4)
    try:
        payload = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        fail(f"invalid migration payload encoding: {error}")
    entries = [parse_entry(value) for number, wire, value in fields(payload) if number == 1 and wire == 2]
    if not entries:
        fail("no OTP entries found in migration payload")
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--entry-index", type=int)
    parser.add_argument("--issuer")
    parser.add_argument("--account")
    args = parser.parse_args()

    entries = decode_source(sys.stdin.read())
    if args.issuer is not None:
        entries = [entry for entry in entries if entry["issuer"] == args.issuer]
    if args.account is not None:
        entries = [entry for entry in entries if entry["account"] == args.account]
    if args.entry_index is not None:
        if args.entry_index < 1 or args.entry_index > len(entries):
            fail("entry index is outside the filtered export")
        entries = [entries[args.entry_index - 1]]
    if not entries:
        fail("no entries matched the requested selector")
    if len(entries) != 1:
        fail("multiple entries found; use an index, issuer, or account selector")
    secret = entries[0]["secret"]
    if not isinstance(secret, bytes) or not secret:
        fail("selected entry has no secret")
    sys.stdout.write(base64.b32encode(secret).decode("ascii").rstrip("="))


if __name__ == "__main__":
    main()
