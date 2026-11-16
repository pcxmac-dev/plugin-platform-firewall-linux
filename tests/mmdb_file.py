"""A tiny GeoIP file in the MaxMind DB format (2.0), written by hand with records of DB-IP's Lite City shape, so the World
Wide Web tab's places are looked up through maxminddb as the real file's would be. The library's test_geo writes its
files the same way. Nothing is downloaded."""
from __future__ import annotations

import ipaddress
import struct
from datetime import datetime, timezone

OCTOBER = int(datetime(2026, 10, 1, 7, 41, tzinfo=timezone.utc).timestamp())  # when DB-IP built a month's file
NOVEMBER = int(datetime(2026, 11, 1, 7, 41, tzinfo=timezone.utc).timestamp())


def uint(kind: int, n: int) -> tuple:
    """An unsigned integer of one width: the metadata's are typed (uint16: 5, uint32: 6, uint64: 9)."""
    return ("uint", kind, n)


def control(kind: int, size: int) -> bytes:
    """A value's control byte: its type in the top 3 bits (0 for an extended type, whose number - 7 is the next byte),
    its size in the low 5 (29, 30 and 31: the size is in one, two or three more bytes)."""
    first, extended = (kind << 5, b"") if kind <= 7 else (0, bytes([kind - 7]))
    if size < 29:
        return bytes([first | size]) + extended
    if size < 285:
        return bytes([first | 29]) + extended + bytes([size - 29])
    if size < 65821:
        return bytes([first | 30]) + extended + (size - 285).to_bytes(2, "big")
    return bytes([first | 31]) + extended + (size - 65821).to_bytes(3, "big")


def encode(value) -> bytes:
    """One value of the data section: a map, an array, a string, a double, an unsigned integer or a boolean."""
    if isinstance(value, tuple):
        _, kind, n = value
        width = (n.bit_length() + 7) // 8
        return control(kind, width) + n.to_bytes(width, "big")
    if isinstance(value, bool):
        return control(14, int(value))
    if isinstance(value, int):
        return encode(uint(6, value))
    if isinstance(value, float):
        return control(3, 8) + struct.pack(">d", value)
    if isinstance(value, str):
        data = value.encode("utf-8")
        return control(2, len(data)) + data
    if isinstance(value, dict):
        return control(7, len(value)) + b"".join(encode(str(k)) + encode(v) for k, v in value.items())
    if isinstance(value, list):
        return control(11, len(value)) + b"".join(encode(v) for v in value)
    raise TypeError(value)


def mmdb(networks, built: int = NOVEMBER) -> bytes:
    """A MaxMind DB file of `networks` ([(cidr, record)], a broader network before a narrower one inside it): a binary
    tree over IPv6's bits with 24-bit records (IPv4 under ::/96), 16 zero bytes, the records, then the metadata after its
    marker, as DB-IP's Lite City has it."""
    data, offsets, root = b"", {}, [None, None]
    for cidr, record in networks:
        net = ipaddress.ip_network(cidr)
        value, length = int(net.network_address), net.prefixlen + (96 if net.version == 4 else 0)
        blob = encode(record)
        if blob not in offsets:
            offsets[blob], data = len(data), data + blob
        node = root
        for i in range(length):
            bit = (value >> (127 - i)) & 1
            if i == length - 1:
                node[bit] = ("data", offsets[blob])
            else:
                if not isinstance(node[bit], list):
                    node[bit] = [node[bit], node[bit]]  # a broader network's record goes down both sides
                node = node[bit]
    nodes, queue, number = [], [root], {}
    while queue:  # numbered breadth first: the root is node 0
        node = queue.pop(0)
        number[id(node)] = len(nodes)
        nodes.append(node)
        queue += [child for child in node if isinstance(child, list)]
    count = len(nodes)

    def record(child) -> int:  # a node's number; node_count for nothing; past it, 16 + the record's place in the data
        if child is None:
            return count
        return number[id(child)] if isinstance(child, list) else count + 16 + child[1]

    tree = b"".join(record(left).to_bytes(3, "big") + record(right).to_bytes(3, "big") for left, right in nodes)
    metadata = {"binary_format_major_version": uint(5, 2), "binary_format_minor_version": uint(5, 0),
                "build_epoch": uint(9, built), "database_type": "DBIP-City-Lite",
                "description": {"en": "written by the Linux firewall's tests"}, "ip_version": uint(5, 6),
                "languages": ["en"], "node_count": uint(6, count), "record_size": uint(5, 24)}
    return tree + bytes(16) + data + b"\xab\xcd\xefMaxMind.com" + encode(metadata)


def city(iso: str, country: str, name: str, lat: float, lon: float) -> dict:
    """A record as DB-IP's Lite City holds one."""
    return {"city": {"names": {"en": name}}, "continent": {"code": "EU", "geoname_id": 1, "names": {"en": "a continent"}},
            "country": {"geoname_id": 2, "is_in_european_union": False, "iso_code": iso, "names": {"en": country}},
            "location": {"latitude": lat, "longitude": lon}, "subdivisions": [{"names": {"en": "a province"}}]}
