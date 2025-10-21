import re
import subprocess
from pathlib import Path
from network.network_exfiltration.helpers import decode_hex_string_field, sha256_bytes, ensure_unique_filename


try:
    import magic
except Exception as e:
    print(f'Exception while importing "magic" library: {e}')
    magic = None


_boundary_re = re.compile(r'Boundary=(?P<b>.+)', flags=re.IGNORECASE)
_filename_re = re.compile(r'filename\*?=(?:UTF-8\'\')?"?(?P<f>[^";\r\n]+)"?', flags=re.IGNORECASE)


def parse_content_type_for_boundary(ct_header: str | None):
    if not ct_header:
        return None
    m = _boundary_re.search(ct_header)
    if not m:
        return None
    b = m.group("b").strip()
    # strip optional quotes
    if b.startswith('"') and b.endswith('"'):
        b = b[1:-1]
    # Do NOT lstrip here: the token may legitimately start with hyphens.
    # The separator prefixes -- to the raw token.
    return b.encode('utf-8', errors='ignore')


def split_multipart(body: bytes, boundary: bytes):
    if not body or not boundary:
        return []
    sep = b'--' + boundary
    parts = body.split(sep)
    # drop first preamble and last epilogue markers if present
    clean = []
    for part in parts:
        # part may start with CRLF
        part = part.lstrip(b'\r\n')
        # NO rstrip() here: avoid over-trimming content endings
        if not part or part == b'--':
            continue
        clean.append(part)
    return clean


def parse_part_headers_and_body(part: bytes):
    # header/body separator is double CRLF
    sep = b'\r\n\r\n'
    idx = part.find(sep)
    if idx == -1:
        # maybe LF-only
        sep2 = b'\n\n'
        idx = part.find(sep2)
        if idx == -1:
            return {}, part
        else:
            hdr_raw = part[:idx]
            body = part[idx + 2:]
    else:
        hdr_raw = part[:idx]
        body = part[idx + 4:]

    if body.endswith(b'\r\n'):
        body = body[:-2]

    headers = {}
    try:
        hdr_text = hdr_raw.decode('utf-8', errors='ignore')
        for line in hdr_text.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
    except Exception:
        pass
    return headers, body


def extract_filename_from_headers(headers: dict):
    cd = headers.get('content-disposition') or headers.get('content-disposition'.lower())
    if not cd:
        return None
    m = _filename_re.search(cd)
    if m:
        fname = m.group('f')
        return fname
    return None


def get_http_raw_body_bytes(pkt):
    try:
        http = pkt.http
    except Exception:
        return None

    # 1) http.file_data (Wireshark sometimes exposes the body bytes here)
    try:
        if hasattr(http, 'file_data') and getattr(http, 'file_data'):
            b = decode_hex_string_field(http.file_data)
            if b:
                return b
    except Exception:
        pass

    # 2) http.file_data_hex variants or http.line or http.file_data part (treat generically)
    # Check for any attribute that contains 'file_data' or 'raw' and looks hex-like
    try:
        for attr in dir(http):
            if 'file_data' in attr or 'raw' in attr or 'payload' in attr:
                val = getattr(http, attr, None)
                if isinstance(val, str) and val:
                    b = decode_hex_string_field(val)
                    if b:
                        return b
    except Exception:
        pass

    # 3) tcp.payload fallback (reassembled payload may be presented)
    try:
        if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload') and getattr(pkt.tcp, 'payload'):
            b = decode_hex_string_field(pkt.tcp.payload)
            if b:
                return b
    except Exception:
        pass

    # 4) try the highest layer raw data
    try:
        if hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
            b = decode_hex_string_field(pkt.data.data)
            if b:
                return b
    except Exception:
        pass

    return None


def extract_and_save_multipart(body_bytes: bytes, content_type_header: str, outdir: Path, pkt_info: dict):
    saved = []
    boundary = parse_content_type_for_boundary(content_type_header)
    if not boundary:
        return saved

    parts = split_multipart(body_bytes, boundary)
    for part in parts:
        headers, body = parse_part_headers_and_body(part)
        fname = extract_filename_from_headers(headers)
        if not fname:
            continue
        # save the body as the file content
        target = ensure_unique_filename(outdir, fname)
        try:
            target.write_bytes(body)
        except Exception:
            # attempt raw dump if write fails
            try:
                target.write_bytes(b"")
            except Exception:
                continue
        sha = sha256_bytes(body)
        ftype = None
        if magic:
            try:
                ftype = magic.from_buffer(body)
            except Exception:
                ftype = None
        rec = {
            "filename": target.name,
            "original_filename": fname,
            "size": len(body),
            "sha256": sha,
            "filetype": ftype,
            "saved_path": str(target),
            "pkt": pkt_info
        }
        saved.append(rec)
    return saved


def export_http_objects_from_pcap(pcap_path, outdir):
    cmd = ["tshark", "-r", pcap_path, "--export-objects", f"http,{outdir}"]
    subprocess.run(cmd, check=True)


def process_http_packet(pkt, host: str, http_objects_outdir: Path, report: dict, totals: dict, saved_files: list,
                        outbound_by_dst: dict, large_upload_threshold_bytes: int):
    try:
        http = pkt.http
    except Exception:
        return

    # method detection & counters
    method = None
    try:
        if hasattr(http, "request_method"):
            method = str(http.request_method).upper()
            if method == "POST":
                totals["http_posts"] = totals.get("http_posts", 0) + 1
            elif method == "PUT":
                totals["http_puts"] = totals.get("http_puts", 0) + 1

            # detect large content-length in requests (heuristic)
            if hasattr(http, "content_length"):
                try:
                    clen = int(str(http.content_length))
                    # identify uploads originating from host
                    ip_layer = pkt.ip if hasattr(pkt, "ip") else (pkt.ipv6 if hasattr(pkt, "ipv6") else None)
                    src = getattr(ip_layer, "src", None) if ip_layer else None
                    dst = getattr(ip_layer, "dst", None) if ip_layer else None
                    if src == host and clen >= large_upload_threshold_bytes:
                        report["suspicious_requests"].append({
                            "proto": "HTTP",
                            "method": method,
                            "src": src,
                            "dst": dst,
                            "content_length": clen,
                            "note": "Large HTTP request body"
                        })
                except Exception:
                    pass
    except Exception:
        pass

    # Attempt to read IP src/dst for pkt_info
    ip_layer = None
    if hasattr(pkt, "ip"):
        ip_layer = pkt.ip
    elif hasattr(pkt, "ipv6"):
        ip_layer = pkt.ipv6

    try:
        src = ip_layer.src if ip_layer else None
        dst = ip_layer.dst if ip_layer else None
    except Exception:
        src = None
        dst = None

    # If we saw bytes from host, increment outbound_by_dst aggregator (caller may already do this,
    # but keep here for safety if called elsewhere).
    try:
        if src == host:
            flen = int(getattr(pkt, "length", 0) or 0)
            outbound_by_dst[dst] = outbound_by_dst.get(dst, 0) + flen
    except Exception:
        pass

    # Raw body + headers
    try:
        body_bytes = get_http_raw_body_bytes(pkt)
    except Exception:
        body_bytes = None

    try:
        content_type_hdr = getattr(http, "content_type", "") or ""
    except Exception:
        content_type_hdr = ""
    try:
        content_disp_hdr = getattr(http, "content_disposition", "") or ""
    except Exception:
        content_disp_hdr = ""

    # If request with multipart/form-data, try to parse parts and save files
    try:
        if body_bytes and 'multipart/form-data' in content_type_hdr.lower():
            pkt_info = {"src": src, "dst": dst, "method": method, "proto": "HTTP"}
            new_saved = extract_and_save_multipart(body_bytes, content_type_hdr, http_objects_outdir, pkt_info)
            if new_saved:
                saved_files.extend(new_saved)
                for rec in new_saved:
                    report["suspicious_requests"].append({
                        "proto": "HTTP",
                        "src": src,
                        "dst": dst,
                        "filename": rec.get("original_filename") or rec.get("filename"),
                        "saved_as": rec.get("filename"),
                        "note": "Saved file from multipart/form-data in HTTP request"
                    })
            else:
                # As a fallback, try to extract an embedded file using extract_multipart
                peeled = extract_multipart_file(body_bytes)
                if peeled and peeled != body_bytes:
                    # try to save peeled content if we can determine a filename from Content-Disposition
                    fname = None
                    m = _filename_re.search(content_disp_hdr)
                    if m:
                        fname = m.group('f')
                    else:
                        # try to find filename inside the multipart headers if possible
                        try:
                            # naive search for filename= within body_bytes (decoded tolerant)
                            txt = body_bytes.decode('utf-8', errors='ignore')
                            m2 = _filename_re.search(txt)
                            if m2:
                                fname = m2.group('f')
                        except Exception:
                            pass
                    if fname:
                        target = ensure_unique_filename(http_objects_outdir, fname)
                        try:
                            target.write_bytes(peeled)
                            sha = sha256_bytes(peeled)
                            ftype = None
                            if magic:
                                try:
                                    ftype = magic.from_buffer(peeled)
                                except Exception:
                                    ftype = None
                            rec = {
                                "filename": target.name,
                                "original_filename": fname,
                                "size": len(peeled),
                                "sha256": sha,
                                "filetype": ftype,
                                "saved_path": str(target),
                                "pkt": pkt_info
                            }
                            saved_files.append(rec)
                            report["suspicious_requests"].append({
                                "proto": "HTTP",
                                "src": src,
                                "dst": dst,
                                "filename": fname,
                                "saved_as": target.name,
                                "note": "Saved file after peeling multipart from HTTP request"
                            })
                        except Exception:
                            pass

    except Exception:
        # keep going
        pass

    # If this is a response that uses Content-Disposition with filename=, try to save response body
    try:
        if hasattr(http, "response_code") and content_disp_hdr:
            m = _filename_re.search(content_disp_hdr)
            if m:
                fname = m.group('f')
                # ensure body present (try a second time using get_http_raw_body_bytes)
                if not body_bytes:
                    body_bytes = get_http_raw_body_bytes(pkt)
                # if still missing, try to look for multipart embedding
                if body_bytes:
                    # as some responses contain multipart wrappers around file - try to peel
                    peeled = extract_multipart_file(body_bytes)
                    final_bytes = peeled if peeled else body_bytes
                    # save file
                    try:
                        target = ensure_unique_filename(http_objects_outdir, fname)
                        target.write_bytes(final_bytes)
                        sha = sha256_bytes(final_bytes)
                        ftype = None
                        if magic:
                            try:
                                ftype = magic.from_buffer(final_bytes)
                            except Exception:
                                ftype = None
                        rec = {
                            "filename": target.name,
                            "original_filename": fname,
                            "size": len(final_bytes),
                            "sha256": sha,
                            "filetype": ftype,
                            "saved_path": str(target),
                            "pkt": {"src": src, "dst": dst, "proto": "HTTP", "note": "response Content-Disposition"}
                        }
                        saved_files.append(rec)
                        report["suspicious_requests"].append({
                            "proto": "HTTP",
                            "src": src,
                            "dst": dst,
                            "filename": fname,
                            "saved_as": target.name,
                            "note": "Saved file from HTTP response Content-Disposition"
                        })
                    except Exception:
                        pass
    except Exception:
        pass

    # If we saw a Content-Disposition with filename but no saved file, still record the filename as an indicator
    try:
        if content_disp_hdr and _filename_re.search(content_disp_hdr):
            fname = _filename_re.search(content_disp_hdr).group('f')
            report["suspicious_requests"].append({
                "proto": "HTTP",
                "src": src,
                "dst": dst,
                "filename": fname,
                "note": "Filename seen in Content-Disposition header (no body saved)"
            })
    except Exception:
        pass


def extract_multipart_file(data: bytes) -> bytes:
    # Try to detect multipart boundary
    m = re.search(rb'------[^\r\n]+', data)
    if not m:
        return data  # no boundary found → return as-is

    boundary = m.group(0)
    # Look for Content-Disposition with filename
    parts = data.split(boundary)
    for part in parts:
        if b'Content-Disposition:' in part and b'filename=' in part:
            # Find start of actual file data
            hdr_end = part.find(b"\r\n\r\n")
            if hdr_end != -1:
                file_bytes = part[hdr_end+4:]
                # Strip trailing CRLF if boundary follows
                return file_bytes.strip(b"\r\n")
    return data  # fallback
