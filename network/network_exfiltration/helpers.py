import math
import hashlib
from pathlib import Path


def decode_hex_string_field(s: str):
    if not s:
        return None
    # remove colons, spaces
    s2 = s.replace(":", "").replace(" ", "").strip()
    # sometimes prefixed with 0x
    if s2.startswith("0x") or s2.startswith("0X"):
        s2 = s2[2:]
    if len(s2) % 2 != 0:
        # odd length - try trimming last nibble
        s2 = s2[:-1]
    try:
        return bytes.fromhex(s2)
    except Exception as e:
        print(f'Exception in "decode_hex_string_field()" function: {e}')
        return None


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(data)
    for v in counts.values():
        p = v / length
        entropy -= p * math.log2(p)
    return entropy


def nice_bytes(n):
    for unit in ['B','KB','MB','GB','TB']:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ensure_unique_filename(outdir: Path, filename: str) -> Path:
    safe = "".join(c for c in filename if c not in "\/:*?\"<>|")
    p = outdir / safe
    if not p.exists():
        return p
    stem = p.stem
    suffix = p.suffix
    i = 1
    while True:
        candidate = outdir / f"{stem}({i}){suffix}"
        if not candidate.exists():
            return candidate
        i += 1
