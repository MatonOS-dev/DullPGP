#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Small packet edits for negative OpenPGP regression fixtures."""
import sys


def read_packet(data):
	if not data or data[0] & 0x80 == 0:
		raise ValueError("invalid packet header")
	if data[0] & 0x40:
		tag = data[0] & 0x3f
		i = 1
		first = data[i]
		i += 1
		if first < 192:
			size = first
		elif first < 224:
			size, i = ((first - 192) << 8) + data[i] + 192, i + 1
		elif first == 255:
			size = int.from_bytes(data[i:i+4], "big")
			i += 4
		else:
			raise ValueError("partial packet length unsupported")
	else:
		tag = (data[0] >> 2) & 0x0f
		kind = data[0] & 3
		i = 1
		if kind == 0:
			size = data[i]
			i += 1
		elif kind == 1:
			size = int.from_bytes(data[i:i+2], "big")
			i += 2
		elif kind == 2:
			size = int.from_bytes(data[i:i+4], "big")
			i += 4
		else:
			raise ValueError("indeterminate packet length unsupported")
	return tag, data[i:i+size], i + size


def encode_packet(tag, body):
	return bytes((0xc0 | tag, 255)) + len(body).to_bytes(4, "big") + body


def subpackets(data):
	i = 0
	while i < len(data):
		start = i
		first = data[i]
		i += 1
		if first < 192:
			length = first
		elif first < 255:
			length = ((first - 192) << 8) + data[i] + 192
			i += 1
		else:
			length = int.from_bytes(data[i:i+4], "big")
			i += 4
		if length < 1 or i + length - 1 > len(data):
			raise ValueError("invalid subpacket length")
		raw = data[start:i+length]
		type_octet = data[i]
		body = data[i+1:i+length]
		i += length
		yield (type_octet & 0x7f), raw, body


def main():
	mode, source, destination = sys.argv[1:4]
	data = open(source, "rb").read()
	if mode == "strip-crosscert":
		out = bytearray()
		found = False
		while data:
			tag, body, used = read_packet(data)
			data = data[used:]
			if tag == 2 and len(body) >= 6 and body[1] == 0x18:
				hashed_len = int.from_bytes(body[4:6], "big")
				u_at = 6 + hashed_len
				u_len = int.from_bytes(body[u_at:u_at+2], "big")
				unhashed = body[u_at+2:u_at+2+u_len]
				kept = b"".join(raw for typ, raw, _ in subpackets(unhashed)
						 if typ != 32)
				found |= len(kept) != len(unhashed)
				body = (body[:u_at] + len(kept).to_bytes(2, "big") + kept +
					body[u_at+2+u_len:])
			out.extend(encode_packet(tag, body))
		if not found:
			raise SystemExit("no embedded 0x19 signature found")
		open(destination, "wb").write(out)
	elif mode == "move-revocation-after-binding":
		packets = []
		while data:
			tag, body, used = read_packet(data)
			packets.append((tag, body))
			data = data[used:]
		revocation = next((i for i, (tag, body) in enumerate(packets)
				   if tag == 2 and len(body) > 1 and body[1] == 0x28), None)
		binding = next((i for i, (tag, body) in enumerate(packets)
				if tag == 2 and len(body) > 1 and body[1] == 0x18), None)
		if revocation is None or binding is None:
			raise SystemExit("subkey revocation or binding signature missing")
		packet = packets.pop(revocation)
		binding = next(i for i, (tag, body) in enumerate(packets)
			       if tag == 2 and len(body) > 1 and body[1] == 0x18)
		packets.insert(binding + 1, packet)
		open(destination, "wb").write(b"".join(
			encode_packet(tag, body) for tag, body in packets))
	elif mode == "append-signature-tail":
		tag, body, used = read_packet(data)
		if tag != 2 or used != len(data):
			raise SystemExit("expected one signature packet")
		open(destination, "wb").write(encode_packet(tag, body + b"\x00"))
	elif mode in ("strip-hashed-creation", "zero-created", "wrong-algorithm"):
		tag, body, used = read_packet(data)
		if tag != 2 or used != len(data) or len(body) < 6:
			raise SystemExit("expected one signature packet")
		if mode == "wrong-algorithm":
			body = body[:2] + b"\x01" + body[3:]
		else:
			hashed_len = int.from_bytes(body[4:6], "big")
			hashed = body[6:6+hashed_len]
			rebuilt = bytearray()
			found = False
			for typ, raw, _ in subpackets(hashed):
				if typ == 2:
					found = True
					if mode == "zero-created":
						raw = raw[:-4] + b"\x00\x00\x00\x00"
					else:
						continue
				rebuilt.extend(raw)
			if not found:
				raise SystemExit("hashed creation-time subpacket missing")
			body = (body[:4] + len(rebuilt).to_bytes(2, "big") + bytes(rebuilt) +
				body[6+hashed_len:])
		open(destination, "wb").write(encode_packet(tag, body))
	else:
		raise SystemExit("unknown mode")


if __name__ == "__main__":
	main()
