import pandas as pd
import os

def match_hashes(input_df, result_df, output_dir):
    required_cols = {"path", "sha256", "md5"}
    if not required_cols.issubset(result_df.columns) or not required_cols.issubset(input_df.columns):
        raise KeyError(f"Missing required columns: {required_cols}")

    matches_sha = result_df[result_df["sha256"].isin(input_df["sha256"].dropna())].copy()
    matches_sha["match_type"] = "sha256"

    matches_md5 = result_df[result_df["md5"].isin(input_df["md5"].dropna())].copy()
    matches_md5["match_type"] = "md5"

    matches = pd.concat([matches_sha, matches_md5], ignore_index=True)
    matches = matches.drop_duplicates(subset=["path"])

    os.makedirs(output_dir, exist_ok=True)
    matches_path = os.path.join(output_dir, "matches.csv")
    matches.to_csv(matches_path, index=False)

    print(f"[+] Found {len(matches)} matching files. Saved to {matches_path}")
    return matches
