def generate_report(matches, usb_history, network_events, output_path="report.txt"):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("===== FORENSIC REPORT =====\n\n")
        f.write("=== FILE MATCHES ===\n")
        if matches.empty:
            f.write("No matching files found.\n\n")
        else:
            for idx, row in matches.iterrows():
                f.write(f"Path: {row['path']}\n")
                f.write(f"Size: {row['size']} bytes\n")
                f.write(f"Modified: {row['mtime']}\n")
                f.write(f"File Type: {row['ftype']}\n")
                f.write(f"SHA256: {row['sha256']}\n")
                f.write(f"MD5: {row['md5']}\n\n")

        f.write("=== NETWORK EXFILTRATION MATCHES ===\n")
        if not network_events:
            f.write("No suspicious network events found.\n\n")
        else:
            for event in network_events:
                f.write(f"Name: {event.get('name')}\n")
                f.write(f"Size: {event.get('size')}\n")
                f.write(f"SHA256: {event.get('sha256')}\n")
                f.write(f"Filetype: {event.get('ftype')}\n\n")

        f.write("=== USB HISTORY ===\n")
        if not usb_history:
            f.write("No USB activity detected.\n")
        else:
            for usb in usb_history:
                f.write(f"Device: {usb.get('device_name')}\n")
                f.write(f"Instance: {usb.get('instance')}\n")
                for k, v in usb.get('values', {}).items():
                    f.write(f"    {k}: {v}\n")
                f.write("\n")
