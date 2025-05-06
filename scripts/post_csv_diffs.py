import os
import subprocess
import requests
from pathlib import Path

CSV_FILES = os.listdir("csv")
DIFF_DIR = Path("csv")
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
PR_NUMBER = os.environ["PR_NUMBER"]
REPO_NAME = os.environ["REPO_NAME"]

def run_diff(filename):
    result = subprocess.run(
        ["python", "scripts/detect_csv_diffs.py", filename],
        capture_output=True,
        text=True
    )
    return result.stdout.strip()

def post_comment(body):
    url = f"https://api.github.com/repos/{REPO_NAME}/issues/{PR_NUMBER}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.post(url, headers=headers, json={"body": body})
    if response.status_code == 201:
        print("✅ Comment posted.")
    else:
        print(f"❌ Failed to post comment: {response.status_code}")
        print(response.text)

def main():
    comments = []
    for csv_file in CSV_FILES:
        print(f"🔍 Diffing {csv_file}...")
        diff_output = run_diff(csv_file)
        if "🟢 New rows in upstream" in diff_output:
            comments.append(f"### 📄 `{csv_file}`\n```\n{diff_output}\n```")

    if comments:
        full_comment = (
            "## 🔍 CSV Diff Report from Upstream\n"
            + "\n---\n".join(comments)
            + "\n\n📝 Please review and merge if appropriate."
        )
        post_comment(full_comment)
    else:
        print("✅ No diffs found in any CSV files.")

if __name__ == "__main__":
    main()
