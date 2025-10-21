import subprocess
from disk.input_handler import run_analysis
from disk.network_handler import analyze_pcap
from disk.hash_matcher import match_hashes
from disk.report_generator import generate_report
import time


if __name__ == "__main__":
    start_time = time.time()
    image_path = "C:\\Users\\poops\\PycharmProjects\\exfiltration_forensics\\inputs\\vmFTImage.dd"
    file_list_csv = "../inputs/input_file.csv"
    file_metadata_csv = "../outputs/files_metadata.csv"
    registry_json = "../outputs/registries/registries.json"
    pcap_file = "../network/complete.pcapng"
    network_report_input_dir = "../inputs/network_report"
    src_ip = '192.168.8.141'
    report_path = "../outputs/report.txt"
    matches_dir = "../outputs/matches"

    # Step 1 — Disk + Registry Analysis
    result_df, registries, input_df, usb_history = run_analysis(
        image_path,
        file_list_csv,
        file_metadata_csv,
        registry_json
    )

    print(f"[+] Extracted {len(result_df)} files metadata")
    print(f"[+] Found {len(registries)} registry hives")

    print(input_df)
    print('-------------')
    print(result_df)

    # Step 2 — Network Forensics
    target_hashes = set(input_df["sha256"].dropna())
    cmd = [
        "python",
        "../network/network_exfiltration/pcap_exfiltration.py",
        "-p", pcap_file,
        "-t", src_ip,
        "-o", network_report_input_dir
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("returncode:", result.returncode)
    print("stdout:\n", result.stdout)
    print("stderr:\n", result.stderr)

    network_matches = analyze_pcap(network_report_input_dir, target_hashes)

    # Step 3 — Match hashes in file system
    matches = match_hashes(input_df, result_df, matches_dir)

    # Step 4 — Generate report
    generate_report(matches, usb_history, network_matches, report_path)

    print(f"[+] Report generated at {report_path}")

    end_time = time.time()

    print(f'The exfiltration detection took {end_time-start_time}.')