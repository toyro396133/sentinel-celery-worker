import subprocess

def get_modified_files(temp_path: str, latest_commit_sha: str = None) -> list:
    """
    Leverages git diff structures to isolate line-by-line regex parsing, SCA checks,
    and secret rules exclusively to newly appended or modified source files.
    """
    print(f"[Git Helper] Fetching modified files for repository: {temp_path}")
    try:
        # If no commit is defined or git history is single-committed, fall back to comparing against HEAD~1 or HEAD diffs
        if latest_commit_sha:
            cmd = ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", latest_commit_sha]
        else:
            # Check local uncommitted diffs or last commit files
            cmd = ["git", "diff", "--name-only", "HEAD~1", "HEAD"]
        
        proc = subprocess.run(cmd, cwd=temp_path, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            print(f"[Git Helper] Discovered {len(files)} modified files in delta state check.")
            return files
        else:
            # Fallback to local unstaged diffs
            cmd_fallback = ["git", "diff", "--name-only"]
            proc_fb = subprocess.run(cmd_fallback, cwd=temp_path, capture_output=True, text=True, timeout=10)
            if proc_fb.returncode == 0:
                files = [line.strip() for line in proc_fb.stdout.splitlines() if line.strip()]
                return files
    except Exception as e:
        print(f"[Git Helper Warning] Failed to fetch git diff: {e}")
    return None
