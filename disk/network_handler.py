import re
import csv

def analyze_pcap(pcap_csv_path, target_hashes):
    results = []
    matches = []
    pcap_csv_path = f'{pcap_csv_path}/exfil_report.csv'

    with open(pcap_csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            # Only consider lines starting with ParsedFile
            if not row or len(row) < 3 or row[0] != "ParsedFile":
                continue

            filename = row[1].strip()
            metadata = row[2]

            # Extract details
            sha_match = re.search(r"sha256=([a-fA-F0-9]{64})", metadata)
            size_match = re.search(r"(\d+)\s+bytes", metadata)
            type_match = re.search(r"type=([\w\d\-_.]+)", metadata)

            sha256 = sha_match.group(1) if sha_match else None
            size = int(size_match.group(1)) if size_match else None
            ftype = type_match.group(1) if type_match and type_match.group(1) != "None" else None

            entry = {
                "name": filename,
                "size": size,
                "sha256": sha256,
                "md5": None,
                "ftype": ftype
            }

            results.append(entry)

            # If the hash matches a known target hash, add to matches
            if sha256 and sha256 in target_hashes:
                matches.append(entry)

    return matches