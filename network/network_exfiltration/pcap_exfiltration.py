import argparse
import re
import shutil
import subprocess
import tempfile
import csv
from network.network_exfiltration.helpers import nice_bytes, sha256_bytes
from pathlib import Path
from tqdm import tqdm
import ipaddress
import magic
import pyshark

from network.network_exfiltration.investigation_http import (
    process_http_packet,
    export_http_objects_from_pcap,
    extract_multipart_file,
)
from network.network_exfiltration.investigation_ftp import (
    process_ftp_packet,
    postprocess_ftp_transfers
)
from network.network_exfiltration.investigation_smb import (
    process_smb_packet,
    export_smb_objects_from_pcap
)


def run_tshark_filter(in_pcap, out_pcap, expression):
    cmd = ["tshark", "-r", in_pcap, "-Y", expression, "-w", out_pcap]
    subprocess.run(cmd, check=True)


def analyze_with_pyshark(pcap_path, host, report, http_objects_outdir: Path,
                         ftp_objects_outdir: Path, smb_objects_outdir: Path, export_objects: bool = True):
    if pyshark is None:
        print("[!] pyshark not available; skipping per-packet protocol heuristics.")
        return []

    cap = pyshark.FileCapture(pcap_path, keep_packets=False)  # streaming
    totals = {
        "frames": 0,
        "bytes_from_host": 0,
        "bytes_to_host": 0,
        "http_posts": 0,
        "http_puts": 0,
        "ftp_stor": 0,
        "tftp_wrq": 0,
        "smb_write_create": 0,
        "dns_queries": 0,
        "dns_suspected_tunnel": 0,
    }

    large_upload_threshold_bytes = 5 * 1024 * 1024  # 5 MB by single flow heuristic

    outbound_by_dst = {}
    saved_files = []  # list of dicts describing files we saved by protocol-aware parsing

    print("[*] Scanning packets with pyshark (this can be slow on large pcaps)...")
    for pkt in tqdm(cap):
        totals["frames"] += 1
        try:
            flen = int(pkt.length)
        except Exception:
            flen = 0

        # Capture IP src/dst for flow aggregations
        ip_layer = None
        if hasattr(pkt, "ip"):
            ip_layer = pkt.ip
        elif hasattr(pkt, "ipv6"):
            ip_layer = pkt.ipv6

        try:
            src = ip_layer.src
            dst = ip_layer.dst
        except Exception:
            src = None
            dst = None

        if src == host:
            totals["bytes_from_host"] += flen
            if dst:
                outbound_by_dst[dst] = outbound_by_dst.get(dst, 0) + flen
        elif dst == host:
            totals["bytes_to_host"] += flen

        # ----- HTTP: delegate to process_http_packet() - investigation_http.py module -----

        try:
            if hasattr(pkt, "http"):
                process_http_packet(pkt, host, http_objects_outdir, report, totals,
                                    saved_files, outbound_by_dst, large_upload_threshold_bytes)
        except Exception:
            # keep going even on HTTP processing errors
            pass

        # ----- FTP: delegate to process_ftp_packet() - investigation_ftp.py module -----

        try:
            if hasattr(pkt, 'ftp') or hasattr(pkt, 'tftp') or hasattr(pkt, 'uftp'):
                process_ftp_packet(pkt, host, report, totals, saved_files, ftp_objects_outdir)
        except Exception:
            pass

        # --- TFTP heuristics: detect WRQ ---

        try:
            if hasattr(pkt, "tftp"):
                tftp = pkt.tftp
                opcode = int(getattr(tftp, "opcode", 0))
                if opcode == 2:  # WRQ (write request)
                    fname = None
                    if hasattr(tftp, "filename"):
                        try:
                            fname = str(tftp.filename).strip()
                        except Exception:
                            pass
                    if not fname and hasattr(tftp, "destination_file"):  # Explicit check for "Destination File"
                        try:
                            fname = str(tftp.destination_file).strip()
                        except Exception:
                            pass
                    if not fname:
                        try:
                            tftp_str = str(tftp)
                            match = re.search(r'File:\s*([^\s,]+)', tftp_str)
                            if match:
                                fname = match.group(1)
                        except:
                            pass
                    if src == host:
                        totals["tftp_wrq"] = totals.get("tftp_wrq", 0) + 1
                        report.setdefault("suspicious_requests", []).append({
                            "proto": "TFTP",
                            "command": "WRQ",
                            "src": src,
                            "dst": dst,
                            "filename": fname,
                            "note": "TFTP file upload (WRQ) from host"
                        })
        except Exception:
            pass

        # --- SMB: delegate to process_smb_packet() - investigation_smb.py module ---

        try:
            if hasattr(pkt, "smb") or hasattr(pkt, "smb2"):
                process_smb_packet(pkt, host, report, totals, saved_files, smb_objects_outdir, large_upload_threshold_bytes)
        except Exception:
            pass

    cap.close()

    # Run FTP/TFTP postprocessing using the same pcap (open a new capture inside helper if needed)
    try:
        # We pass the original cap object only if we still have it; helper accepts path or capture
        # Using pcap_path is enough (helper will open pyshark when required)
        postprocess_ftp_transfers(pcap_path, pcap_path, ftp_objects_outdir, report,
                                  totals, saved_files, export_objects=export_objects)
    except Exception as e:
        report.setdefault("errors", []).append(f"postprocess_ftp_transfers failed: {e}")

    # add totals and outbound_by_dst to report (caller expects these)
    report["totals"] = totals
    report["outbound_by_dst"] = sorted(outbound_by_dst.items(), key=lambda x: x[1], reverse=True)
    return saved_files


def hash_and_describe_files(path):
    res = []
    for p in sorted(Path(path).iterdir()):
        if p.is_file():
            b = p.read_bytes()
            # Try to clean multipart wrapper
            clean_b = extract_multipart_file(b)
            if clean_b != b:
                # Save cleaned version next to original
                clean_path = p.with_name(p.stem + "_cleaned" + p.suffix)
                clean_path.write_bytes(clean_b)
                print(f"[*] Cleaned multipart wrapper from {p.name} -> {clean_path.name}")
                b = clean_b
                p = clean_path  # update reference

            sha = sha256_bytes(b)
            ftype = None
            if magic:
                try:
                    ftype = magic.from_buffer(b)
                except Exception:
                    ftype = None
            res.append({
                "filename": p.name,
                "size": len(b),
                "sha256": sha,
                "filetype": ftype
            })
    return res


def write_csv_report(outdir, findings, exported_http_info, parsed_saved_files, exported_ftp_tftp_info, exported_smb_info):
    csvf = Path(outdir) / "exfil_report.csv"
    with open(csvf, "w", newline='', encoding='utf-8') as cf:
        writer = csv.writer(cf)
        writer.writerow(["Section", "Key", "Value"])
        # Totals
        for k, v in findings.get("totals", {}).items():
            writer.writerow(["Totals", k, v])
        for dst, b in findings.get("outbound_by_dst", [])[:50]:
            writer.writerow(["TopDest", dst, b])
        # Suspicious requests
        writer.writerow(["SuspiciousRequests", "count", len(findings.get("suspicious_requests", []))])
        for idx, item in enumerate(findings.get("suspicious_requests", [])):
            writer.writerow(["SuspReq", idx, str(item)])
        # Exported HTTP objects (tshark)
        writer.writerow(["Exported HTTP objects (tshark)", "count", len(exported_http_info)])
        for info in exported_http_info:
            writer.writerow(["ExportedHTTPFile", info.get("filename"), f"{info.get('size')} bytes; sha256={info.get('sha256')}; type={info.get('filetype')}"])
        # Exported FTP/TFTP objects (tshark)
        writer.writerow(["Exported FTP/TFTP objects (tshark)", "count", len(exported_ftp_tftp_info)])
        for info in exported_ftp_tftp_info:
            writer.writerow(["ExportedFTPFile", info.get("filename"), f"{info.get('size')} bytes; sha256={info.get('sha256')}; type={info.get('filetype')}"])
        writer.writerow(["Exported SMB objects (tshark)", "count", len(exported_smb_info)])
        # Exported SMB objects (tshark)
        for info in exported_smb_info:
            writer.writerow(["ExportedSMBFile", info.get("filename"),
                             f"{info.get('size')} bytes; sha256={info.get('sha256')}; type={info.get('filetype')}"])
        # Parsed & saved files via protocol-aware parsing
        writer.writerow(["ParsedSavedFiles", "count", len(parsed_saved_files)])
        for info in parsed_saved_files:
            writer.writerow(["ParsedFile", info.get("original_filename") or info.get("filename"), f"saved_as={info.get('filename')}; {info.get('size')} bytes; sha256={info.get('sha256')}; type={info.get('filetype')}; pkt={info.get('pkt')}"])
    print(f"CSV report saved to: {csvf}")


# ---------- CLI ----------


def main():
    ap = argparse.ArgumentParser(description="PCAP exfiltration triage for a specific host")
    ap.add_argument("-p", "--pcap", required=True, help="Input pcap file")
    ap.add_argument("-t", "--target", required=True, help="Target host (IP or MAC). Example: 192.168.1.42 or aa:bb:cc:dd:ee:ff")
    ap.add_argument("-o", "--outdir", default="exfil_triage_out", help="Output directory")
    ap.add_argument("--no-export", action="store_true", help="Do not attempt to export HTTP/FTP/TFTP objects (skip tshark --export-objects)")
    ap.add_argument("--large-upload-threshold-mb", type=int, default=5, help="Threshold in MB to mark a single HTTP request body as large")
    args = ap.parse_args()

    pcap = args.pcap
    host = args.target
    outdir = Path(args.outdir)
    if outdir.exists():
        print("[*] Cleaning output dir...")
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Prepare filtered pcap that contains traffic where ip.addr==host OR eth.addr==host
    tmpdir = tempfile.mkdtemp(prefix="pcap_exfil_")
    filtered_pcap = Path(tmpdir) / "filtered_host.pcap"
    try:
        ip_obj = ipaddress.ip_address(host)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            host_expr = f"ip.addr=={host}"
        else:
            host_expr = f"ipv6.addr=={host}"
    except ValueError:
        # Not an IP, assume MAC
        host_expr = f"eth.addr=={host}"
    print(f"[*] Creating filtered pcap for host {host} ...")
    try:
        run_tshark_filter(pcap, str(filtered_pcap), host_expr)
    except subprocess.CalledProcessError as e:
        print("[!] Error running tshark to filter pcap. Is tshark installed and in PATH?")
        print(e)
        return

    findings = {"suspicious_requests": []}

    # Prepare http objects dir (where we will save files we parse)
    http_objects_dir = outdir / "http_objects"
    http_objects_dir.mkdir(parents=True, exist_ok=True)

    # Prepare ftp objects dir
    ftp_objects_dir = outdir / "ftp_objects"
    ftp_objects_dir.mkdir(parents=True, exist_ok=True)

    # Prepare smb objects dir
    smb_objects_dir = outdir / "smb_objects"
    smb_objects_dir.mkdir(parents=True, exist_ok=True)

    # Analyze filtered pcap with pyshark heuristics and parsing
    parsed_saved_files = analyze_with_pyshark(str(filtered_pcap), host, findings, http_objects_dir, ftp_objects_dir,
                                              smb_objects_outdir=smb_objects_dir, export_objects=not args.no_export)
    print("PARSED FILES: ", parsed_saved_files)

    # Export HTTP objects from filtered pcap (if requested) using tshark as before
    exported_http_info = []
    if not args.no_export:
        print("[*] Attempting to export HTTP objects from filtered pcap (using tshark --export-objects)...")
        try:
            # use a separate dir for tshark exports to avoid overwriting our parsed files
            tshark_http_export_dir = http_objects_dir / "tshark_http_objects"
            tshark_http_export_dir.mkdir(exist_ok=True)
            export_http_objects_from_pcap(str(filtered_pcap), str(tshark_http_export_dir))
            # describe exported files
            exported_http_info = hash_and_describe_files(tshark_http_export_dir)
            print(f"[*] Exported {len(exported_http_info)} HTTP objects to {tshark_http_export_dir}")
        except Exception as e:
            print("[!] HTTP object export failed or produced no objects:", e)

    # Exported FTP/TFTP info from tshark subdirs (if exported)
    exported_ftp_tftp_info = []
    if not args.no_export:
        try:
            tshark_ftp_dir = ftp_objects_dir / "tshark_ftp_objects"
            exported_ftp_tftp_info += hash_and_describe_files(tshark_ftp_dir)
        except Exception as e:
            print("[!] Failed to describe tshark FTP objects:", e)
        try:
            tshark_tftp_dir = ftp_objects_dir / "tshark_tftp_objects"
            exported_ftp_tftp_info += hash_and_describe_files(tshark_tftp_dir)
        except Exception as e:
            print("[!] Failed to describe tshark TFTP objects:", e)

    # Exported SMB info from tshark (if exported)
    exported_smb_info = []
    if not args.no_export:
        print("[*] Attempting to export SMB objects from filtered pcap (using tshark --export-objects)...")
        try:
            tshark_smb_export_dir = smb_objects_dir / "tshark_smb_objects"
            tshark_smb_export_dir.mkdir(exist_ok=True)

            tmpdir = tempfile.mkdtemp(prefix="pcap_exfil_")
            filtered_pcap_smb = Path(tmpdir) / "filtered_smb.pcap"
            run_tshark_filter(filtered_pcap, filtered_pcap_smb, "!(smb.cmd == 0x2e || smb2.cmd == 8)")

            export_smb_objects_from_pcap(str(filtered_pcap_smb), str(tshark_smb_export_dir))
            exported_smb_info = hash_and_describe_files(tshark_smb_export_dir)
            print(f"[*] Exported {len(exported_smb_info)} SMB objects to {tshark_smb_export_dir}")
        except Exception as e:
            print("[!] SMB object export failed or produced no objects:", e)

    # Hash & describe files we parsed and saved
    parsed_descriptions = []
    for rec in parsed_saved_files:
        parsed_descriptions.append({
            "filename": rec.get("filename"),
            "original_filename": rec.get("original_filename"),
            "size": rec.get("size"),
            "sha256": rec.get("sha256"),
            "filetype": rec.get("filetype"),
            "saved_path": rec.get("saved_path")
        })

    # Add some final heuristics: large total outbound bytes
    totals = findings.get("totals", {})
    bytes_out = totals.get("bytes_from_host", 0)
    if bytes_out > args.large_upload_threshold_mb * 1024 * 1024:
        findings["suspicious_requests"].append({
            "proto": "FLOW",
            "note": f"Host sent a large total of outbound data: {nice_bytes(bytes_out)}"
        })

    # Write CSV report (includes both tshark-exported and parsed-saved files)
    write_csv_report(outdir, findings, exported_http_info, parsed_descriptions, exported_ftp_tftp_info, exported_smb_info)

    # Print quick console summary
    print("\n=== Quick summary ===")
    print(f"Host: {host}")
    print(f"Frames inspected (approx): {totals.get('frames','n/a')}")
    print(f"Outbound bytes (from host): {nice_bytes(bytes_out)}")
    print(f"HTTP POSTs: {totals.get('http_posts',0)}, HTTP PUTs: {totals.get('http_puts',0)}")
    print(f"FTP STOR observed: {totals.get('ftp_stor',0)}")
    print(f"TFTP WRQ observed: {totals.get('tftp_wrq',0)}")
    print(f"SMB create/write observed: {totals.get('smb_write_create',0)}")
    print(f"DNS queries suspected tunneling: {totals.get('dns_suspected_tunnel',0)}")
    print(f"Top outbound destinations (top 10):")
    for dst, b in findings.get("outbound_by_dst", [])[:10]:
        print(f"  {dst}: {nice_bytes(b)}")
    print(f"Parsed objects saved to: {http_objects_dir} (count={len(parsed_descriptions)})")
    if exported_http_info:
        print(f"tshark-exported HTTP objects saved to: {http_objects_dir / 'tshark_http_objects'} (count={len(exported_http_info)})")
    if exported_ftp_tftp_info:
        print(f"tshark-exported FTP/TFTP objects saved to: {ftp_objects_dir} (count={len(exported_ftp_tftp_info)})")
    if exported_smb_info:
        print(f"tshark-exported SMB objects saved to: {smb_objects_dir} (count={len(exported_smb_info)})")
    print(f"CSV report: {outdir / 'exfil_report.csv'}")

    print("\nSuspicious items (sample):")
    for item in findings.get("suspicious_requests", [])[:20]:
        print(" -", item)

    print("\nDone. Temporary files at:", tmpdir)
    print("You can remove them when finished.")


if __name__ == "__main__":
    main()
