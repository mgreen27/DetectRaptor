import csv
import sys
from pathlib import Path

def load_csv(filepath):
    with open(filepath, newline='', encoding='utf-8') as f:
        return [tuple(row) for row in csv.reader(f) if row and any(cell.strip() for cell in row)]

def diff_csv_files(local_path, upstream_path):
    local_rows = set(load_csv(local_path))
    upstream_rows = set(load_csv(upstream_path))

    new_in_upstream = upstream_rows - local_rows
    removed_from_upstream = local_rows - upstream_rows

    print(f"\n🟢 New rows in upstream ({upstream_path.name}):")
    for row in new_in_upstream:
        print("  +", row)

    print(f"\n🔴 Rows removed or changed in upstream:")
    for row in removed_from_upstream:
        print("  -", row)

    return new_in_upstream, removed_from_upstream

def write_diff_file(rows, output_path):
    with open(output_path, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        for row in sorted(rows):
            writer.writerow(row)
    print(f"\n✅ Saved diff file to: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_csv_diffs.py <filename.csv>")
        sys.exit(1)

    filename = sys.argv[1]
    local_csv = Path("csv") / filename
    upstream_csv = Path("tmp/upstream/csv") / filename  # clone upstream-sync here
    diff_csv = Path("csv") / f"{filename.replace('.csv', '')}_upstream_changes.csv"

    if not local_csv.exists() or not upstream_csv.exists():
        print("❌ One of the files is missing:")
        print(f" - {local_csv.exists()=}, {upstream_csv.exists()=}")
        sys.exit(1)

    new_rows, _ = diff_csv_files(local_csv, upstream_csv)

    if new_rows:
        write_diff_file(new_rows, diff_csv)
    else:
        print("✅ No new rows from upstream.")
