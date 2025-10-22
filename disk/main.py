import subprocess
from disk.input_handler import run_analysis
from disk.network_handler import analyze_pcap
from disk.hash_matcher import match_hashes
from disk.report_generator import generate_report
import time, argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detect potential data exfiltration from disk image and network capture."
    )

    parser.add_argument(
        "-i", "--image",
        default="C:\\Users\\poops\\PycharmProjects\\exfiltration_forensics\\inputs\\vmFTImage.dd",
        help="Path to the disk image (.dd or .img)"
    )
    parser.add_argument(
        "-f", "--file-list",
        default="../inputs/input_file.csv",
        help="Path to CSV file containing target file list (hashes, names, types)"
    )
    parser.add_argument(
        "-m", "--metadata-csv",
        default="../outputs/files_metadata.csv",
        help="Output path for file metadata CSV"
    )
    parser.add_argument(
        "-r", "--registry-json",
        default="../outputs/registries/registries.json",
        help="Output path for registry JSON file"
    )
    parser.add_argument(
        "-p", "--pcap",
        default="../network/complete.pcapng",
        help="Path to network traffic capture (.pcapng)"
    )
    parser.add_argument(
        "-n", "--network-report-dir",
        default="../inputs/network_report",
        help="Directory for intermediate network analysis output"
    )
    parser.add_argument(
        "-s", "--src-ip",
        default="192.168.8.141",
        help="Source IP address of the suspected machine to filter network traffic"
    )
    parser.add_argument(
        "-o", "--report-path",
        default="../outputs/report.txt",
        help="Path to final text report"
    )
    parser.add_argument(
        "-d", "--matches-dir",
        default="../outputs/matches",
        help="Directory to store hash match results"
    )

    args = parser.parse_args()
    start_time = time.time()

    image_path = args.image
    file_list_csv = args.file_list
    file_metadata_csv = args.metadata_csv
    registry_json = args.registry_json
    pcap_file = args.pcap
    network_report_input_dir = args.network_report_dir
    src_ip = args.src_ip
    report_path = args.report_path
    matches_dir = args.matches_dir

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