from pathlib import Path
import subprocess
import re

try:
    import pyshark
except Exception:
    pyshark = None

try:
    import magic
except Exception:
    magic = None

from network.network_exfiltration.helpers import decode_hex_string_field, ensure_unique_filename, sha256_bytes


_stor_re = re.compile(r'^STOR\s+(?P<fname>.+)$', flags=re.IGNORECASE)
_retr_re = re.compile(r'^RETR\s+(?P<fname>.+)$', flags=re.IGNORECASE)


def extract_ftp_objects_from_pcap(pcap_path: str, outdir: str):
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)
    cmd = ["tshark", "-r", str(pcap_path), "--export-objects", f"ftp-data,{str(outdir)}"]
    subprocess.run(cmd, check=True)
    written = []
    for p in outdir_p.iterdir():
        if p.is_file():
            written.append(p)
    return written


def extract_tftp_objects_from_pcap(pcap_path: str, outdir: str):
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)
    cmd = ["tshark", "-r", str(pcap_path), "--export-objects", f"tftp,{str(outdir)}"]
    subprocess.run(cmd, check=True)
    written = []
    for p in outdir_p.iterdir():
        if p.is_file():
            written.append(p)
    return written


def _save_blob(outdir: Path, hint_name: str, data: bytes):
    outdir.mkdir(parents=True, exist_ok=True)
    target = ensure_unique_filename(outdir, hint_name)
    target.write_bytes(data)
    sha = sha256_bytes(data)
    ftype = None
    if magic:
        try:
            ftype = magic.from_buffer(data)
        except Exception:
            ftype = None
    return {"filename": target.name, "saved_path": str(target), "size": len(data), "sha256": sha, "filetype": ftype}


def process_ftp_packet(pkt, host: str, report: dict, totals: dict, saved_files: list, outdir: Path):
    try:
        if not hasattr(pkt, "ftp"):
            return
        ftp = pkt.ftp
    except Exception:
        return

    # attempt to get IPs
    src = dst = None
    try:
        if hasattr(pkt, "ip"):
            src, dst = pkt.ip.src, pkt.ip.dst
        elif hasattr(pkt, "ipv6"):
            src, dst = pkt.ipv6.src, pkt.ipv6.dst
    except Exception:
        pass

    # command detection (control channel)
    try:
        if hasattr(ftp, "request_command"):
            cmd = str(ftp.request_command).upper()
            arg = getattr(ftp, "request_arg", None)
            if cmd == "STOR" and src == host:
                totals["ftp_stor"] = totals.get("ftp_stor", 0) + 1
                report.setdefault("suspicious_requests", []).append({
                    "proto": "FTP", "command": "STOR", "src": src, "dst": dst, "filename": arg,
                    "note": "FTP file upload (STOR) from host"
                })
            elif cmd in ("RETR", "STOR"):
                report.setdefault("suspicious_requests", []).append({
                    "proto": "FTP", "command": cmd, "src": src, "dst": dst, "filename": arg,
                    "note": "FTP transfer filename observed"
                })
    except Exception:
        pass

    # Opportunistic: if there's an encapsulated payload on the TCP packet, save it
    # try:
    #     if hasattr(pkt, "tcp"):
    #         # try several possible fields
    #         for fld in ("payload", "raw", "data"):
    #             if hasattr(pkt.tcp, fld):
    #                 raw = getattr(pkt.tcp, fld)
    #                 b = decode_hex_string_field(raw)
    #                 if b:
    #                     rec = _save_blob(outdir, f"ftp_pkt_{getattr(pkt.tcp, 'stream', 'unknown')}.bin", b)
    #                     rec["proto"] = "FTP"
    #                     saved_files.append(rec)
    #                     report.setdefault("suspicious_requests", []).append({
    #                         "proto": "FTP", "src": src, "dst": dst, "filename": rec["filename"], "note": "Saved raw FTP TCP payload (opportunistic)"
    #                     })
    #                     break
    #         # also try highest-layer data
    #         if hasattr(pkt, "data") and hasattr(pkt.data, "data"):
    #             b = decode_hex_string_field(pkt.data.data)
    #             if b:
    #                 rec = _save_blob(outdir, f"ftp_data_{pkt.number}.bin", b)
    #                 rec["proto"] = "FTP"
    #                 saved_files.append(rec)
    #                 report.setdefault("suspicious_requests", []).append({
    #                     "proto": "FTP", "src": src, "dst": dst, "filename": rec["filename"], "note": "Saved FTP data layer payload (opportunistic)"
    #                 })
    # except Exception:
    #     pass


# ---------------------- TFTP helpers ----------------------
# Reconstruct TFTP WRQ+DATA transfers by iterating TFTP packets (pyshark captures)


def parse_tftp_packets_and_save(cap_or_pcap, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    saved = []
    if pyshark is None:
        return saved

    # If cap_or_pcap is a path, open pyshark capture
    opened_here = False
    if isinstance(cap_or_pcap, (str, Path)):
        cap = pyshark.FileCapture(str(cap_or_pcap), display_filter="tftp", keep_packets=False)
        opened_here = True
    else:
        cap = cap_or_pcap

    # Track transfers keyed by (client_ip, server_ip, client_port)
    transfers = {}

    for pkt in cap:
        try:
            if not hasattr(pkt, "tftp"):
                continue
            tftp = pkt.tftp
            try:
                opcode = int(getattr(tftp, "opcode", 0) or 0)
            except Exception:
                # skip if opcode not present
                continue

            # IPs and ports
            client = getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else (getattr(pkt.ipv6, "src", None) if hasattr(pkt, "ipv6") else None)
            server = getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else (getattr(pkt.ipv6, "dst", None) if hasattr(pkt, "ipv6") else None)
            sport = int(getattr(pkt.udp, "srcport", 0) or 0)
            dport = int(getattr(pkt.udp, "dstport", 0) or 0)

            if opcode == 2:  # WRQ (write request)
                # More robust filename extraction (consistent with main loop)
                fname = None
                if hasattr(tftp, "filename"):
                    try:
                        fname = str(tftp.filename).strip()
                    except (AttributeError, ValueError):
                        fname = None
                # Fallback: try to extract from tftp string representation
                if not fname:
                    try:
                        tftp_str = str(tftp)
                        match = re.search(r'File:\s*([^\s,]+)', tftp_str)
                        if match:
                            fname = match.group(1)
                    except Exception:
                        pass
                fname = fname or f"tftp_wrq_{sport}.bin"
                key = (client, server, sport)
                transfers[key] = {"filename": fname, "blocks": {}, "last_block": None}
            elif opcode == 3:  # DATA
                try:
                    blk = int(getattr(tftp, "block", 0) or 0)
                except Exception:
                    blk = None
                data = decode_hex_string_field(getattr(tftp, "data", None))
                # find matching transfer
                potential_keys = [(client, server, dport), (client, server, sport)]
                found = None
                for k in potential_keys:
                    if k in transfers:
                        found = k
                        break
                if not found:
                    for k in list(transfers.keys()):
                        if k[0] == client and k[1] == server:
                            found = k
                            break
                if found and data is not None and blk is not None:
                    transfers[found]["blocks"][blk] = data
                    transfers[found]["last_block"] = blk
                    if len(data) < 512:  # final block
                        blocks = transfers[found]["blocks"]
                        ordered = b"".join(blocks[i] for i in sorted(blocks.keys()) if i in blocks)
                        fname = transfers[found]["filename"]
                        rec = _save_blob(outdir, fname, ordered)
                        rec["proto"] = "TFTP"
                        saved.append(rec)
                        try:
                            del transfers[found]
                        except Exception:
                            pass
        except Exception:
            continue

    # At end, check for incomplete transfers and save what we have
    for key, transfer in list(transfers.items()):
        if transfer["blocks"]:
            ordered = b"".join(transfer["blocks"][i] for i in sorted(transfer["blocks"].keys()))
            fname = transfer["filename"]
            rec = _save_blob(outdir, f"incomplete_{fname}", ordered)
            rec["proto"] = "TFTP"
            rec["note"] = "Incomplete TFTP transfer (saved partial data)"
            saved.append(rec)

    if opened_here and cap is not None:
        try:
            cap.close()
        except Exception:
            pass
    return saved


# ---------------------- UFTP (best-effort) ----------------------


def best_effort_uftp_parse(cap_or_pcap, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    saved = []
    if pyshark is None:
        return saved

    opened_here = False
    if isinstance(cap_or_pcap, (str, Path)):
        # Filter on standard UFTP port
        cap = pyshark.FileCapture(str(cap_or_pcap), display_filter="udp.port==1044", keep_packets=False)
        opened_here = True
    else:
        cap = cap_or_pcap

    counter = 0
    for pkt in cap:
        try:
            if not hasattr(pkt, "udp"):
                continue
            if hasattr(pkt, "data") and hasattr(pkt.data, "data"):
                payload = decode_hex_string_field(pkt.data.data)
            else:
                payload = decode_hex_string_field(getattr(pkt.udp, "payload", None))
            if not payload:
                continue

            # Method 1: Use UFTP dissector if available (v3+)
            fname = None
            if hasattr(pkt, "uftp") and hasattr(pkt.uftp, "filename"):
                try:
                    fname = str(pkt.uftp.filename).strip()
                except Exception:
                    pass

            # Method 2: Heuristic regex for File Info (type 0x0A, then filename as null-terminated string)
            if not fname and payload:
                # Look for File Info type (0x0A) followed by filename (ASCII until \x00)
                if len(payload) > 10 and payload[1] == 0x0A:  # Type byte
                    # Skip header (assume ~8-10 bytes), extract until null
                    start = 10
                    end = payload.find(b'\x00', start)
                    if end > start:
                        potential_fname = payload[start:end].decode('ascii', errors='ignore').strip()
                        if potential_fname and not potential_fname.startswith('UFTP'):  # Avoid false positives
                            fname = potential_fname

            # Method 3: Original heuristic (backup)
            if not fname:
                header = payload[:64]
                if b"UFTP" in header or b"uftp" in header:
                    fname = f"uftp_unknown_{counter}.bin"  # Default if no better

            if fname:
                counter += 1
                note = "UFTP filename extracted" if "uftp" in str(pkt) else "UFTP-like payload (heuristic)"
                rec = _save_blob(outdir, fname, payload)  # Or just metadata if full file not here
                rec["proto"] = "UFTP"
                rec["note"] = note
                saved.append(rec)
                # Log to report (pass report/totals if needed)
        except Exception:
            continue

    if opened_here and cap is not None:
        cap.close()
    return saved


# ---------------------- Combined postprocessing helper ----------------------


def postprocess_ftp_transfers(pcap_path: str, cap, outdir: Path, report: dict,
                              totals: dict, saved_files: list, export_objects: bool = True):
    report.setdefault("errors", [])
    # TFTP
    try:
        tftp_saved = parse_tftp_packets_and_save(cap, outdir)
        if tftp_saved:
            saved_files.extend(tftp_saved)
            totals["tftp_files"] = totals.get("tftp_files", 0) + len(tftp_saved)
            for r in tftp_saved:
                report.setdefault("suspicious_requests", []).append({
                    "proto": "TFTP", "filename": r.get("filename"), "saved_path": r.get("saved_path"),
                    "note": "TFTP transfer reconstructed"
                })
    except Exception as e:
        report["errors"].append(f"TFTP parsing failed: {e}")

    if export_objects:
        # FTP via tshark export
        try:
            tshark_dir = outdir / "tshark_ftp_objects"
            tshark_dir.mkdir(parents=True, exist_ok=True)
            ftp_objs = extract_ftp_objects_from_pcap(pcap_path, str(tshark_dir))
            for f in ftp_objs:
                saved_files.append({
                    "filename": f.name,
                    "saved_path": str(f),
                    "size": f.stat().st_size,
                    "sha256": sha256_bytes(f.read_bytes()),
                    "proto": "FTP",
                    "note": "extracted via tshark --export-objects"
                })
            totals["ftp_files"] = totals.get("ftp_files", 0) + len(ftp_objs)
        except subprocess.CalledProcessError as e:
            report["errors"].append(f"FTP tshark export failed: {e}")
        except Exception as e:
            report["errors"].append(f"FTP export/parsing failed: {e}")

        # TFTP via tshark export (additional reliable extraction)
        try:
            tshark_tftp_dir = outdir / "tshark_tftp_objects"
            tshark_tftp_dir.mkdir(parents=True, exist_ok=True)
            tftp_objs = extract_tftp_objects_from_pcap(pcap_path, str(tshark_tftp_dir))
            for f in tftp_objs:
                saved_files.append({
                    "filename": f.name,
                    "saved_path": str(f),
                    "size": f.stat().st_size,
                    "sha256": sha256_bytes(f.read_bytes()),
                    "proto": "TFTP",
                    "note": "extracted via tshark --export-objects"
                })
            totals["tftp_files"] = totals.get("tftp_files", 0) + len(tftp_objs)
        except subprocess.CalledProcessError as e:
            report["errors"].append(f"TFTP tshark export failed: {e}")
        except Exception as e:
            report["errors"].append(f"TFTP export/parsing failed: {e}")
