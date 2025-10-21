import pandas as pd
from disk.image_handler import walk_and_collect

def read_input_file(file_list_csv):
    df = pd.read_csv(file_list_csv)
    hashes = df[['sha256', 'md5']].dropna().to_dict(orient='records') if 'sha256' in df.columns else []
    if "ftype" in df.columns:
        types = df["ftype"].dropna().unique().tolist()
    else:
        types = []
    return df, types, hashes

def run_analysis(image_path, file_list_csv, out_csv, registry_json):
    df, types, hashes = read_input_file(file_list_csv)
    print(f"[+] Found {len(types)} unique file types in input list.")
    result_df, registries, usb_history = walk_and_collect(
        image_path=image_path,
        allowed_types=types,
        out_csv=out_csv,
        registry_output_json=registry_json,
        max_files=None
    )
    return result_df, registries, df, usb_history
