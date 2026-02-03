#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

FSTAB_PATH = "/etc/fstab"
DEFAULT_REGION = "us-east-2"
DEFAULT_CREDS = "/root/.smbcreds"
DEFAULT_MNT_ROOT = "/mnt"

CIFS_OPTS = "credentials={creds},vers=3.1.1,sec=ntlmssp,iocharset=utf8,_netdev,cache=none,nofail,x-systemd.idle-timeout=20s"

FB_INPUT_BLOCK_TEMPLATE = """\
- name: tail
  tag: iis.logs
  path: '{path}'
  parser: iis_parser
  db: '/var/lib/fluent-bit/iis-all.db'
  db.sync: normal
  storage.type: filesystem
  mem_buf_limit: 64MB
  inotify_watcher: false
  read_from_head: false
  buffer_chunk_size: 128KB
  buffer_max_size: 256KB
"""

class DryRunPrinter:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def run(self, cmd: List[str]) -> Tuple[int, str, str]:
        if self.enabled:
            print(f"[DRY-RUN] would run: {' '.join(cmd)}")
            return 0, "", ""
        proc = subprocess.run(cmd, text=True, capture_output=True)
        return proc.returncode, proc.stdout, proc.stderr

    def mkdir(self, path: str):
        if self.enabled:
            print(f"[DRY-RUN] would mkdir -p {path}")
        else:
            os.makedirs(path, exist_ok=True)

    def mount_single(self, mount_point: str):
        if self.enabled:
            print(f"[DRY-RUN] would mount {mount_point} (or mount -a fallback)")
            return
        # Try single mount first; fallback to mount -a
        rc, _, _ = self.run(["mount", mount_point])
        if rc != 0:
            print(f"[INFO] single mount failed for {mount_point}, trying mount -a...")
            self.run(["mount", "-a"])

def read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except Exception as e:
        print(f"[ERROR] reading {path}: {e}", file=sys.stderr)
        sys.exit(2)

def write_file(path: str, content: str, dry: DryRunPrinter):
    if dry.enabled:
        print(f"\n===== [DRY-RUN] would write: {path} =====")
        print(content.rstrip() + "\n")
        print("===== [END] =====\n")
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def backup(path: str, dry: DryRunPrinter) -> Optional[str]:
    if not os.path.exists(path):
        return None
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = f"{path}.bak-{ts}"
    if dry.enabled:
        print(f"[DRY-RUN] would backup {path} -> {backup_path}")
        return backup_path
    shutil.copy2(path, backup_path)
    print(f"[OK] backup: {backup_path}")
    return backup_path

def aws_describe_instances(region: str, name_contains: Optional[str]) -> List[dict]:
    cmd = ["aws", "ec2", "describe-instances", "--region", region, "--output", "json"]
    # We want running/stopped/etc. (exclude terminated by default)
    filters = []
    if name_contains:
        filters.append(f"Name=tag:Name,Values=*{name_contains}*")
    if filters:
        for f in filters:
            cmd.extend(["--filters", f])
    try:
        out = subprocess.check_output(cmd, text=True)
        data = json.loads(out)
    except FileNotFoundError:
        print("[ERROR] AWS CLI not found. Install awscli v2 and configure credentials.", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] AWS CLI failed: {e}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError:
        print("[ERROR] Failed to parse AWS CLI JSON output.", file=sys.stderr)
        sys.exit(2)

    instances = []
    for r in data.get("Reservations", []):
        for inst in r.get("Instances", []):
            instances.append(inst)
    return instances

def extract_name_tag(tags: List[dict]) -> Optional[str]:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value")
    return None

def extract_host_from_name(name: Optional[str]) -> str:
    """
    Extract the trailing parenthesized token from the Name tag, e.g. "app-web (host123)" -> "host123".
    If not present, fall back to the provided name. Sanitizes to remove special characters
    (allows A-Z a-z 0-9 _ and -).
    """
    if not name:
        return ""
    # look for last parenthesized group at end
    m = re.search(r"\(([^)]*)\)\s*$", name)
    token = m.group(1) if m else name
    token = token.strip()
    # allow letters, digits, underscore, hyphen; drop everything else
    sanitized = re.sub(r"[^A-Za-z0-9_-]", "", token)
    if sanitized:
        return sanitized
    # fallback: sanitize the whole name
    sanitized = re.sub(r"[^A-Za-z0-9_-]", "", name)
    if sanitized:
        return sanitized
    # ultimate fallback: remove spaces
    return name.replace(" ", "")

def build_targets(instances: List[dict], mnt_root: str, creds_file: str) -> List[dict]:
    """
    Return list of targets:
    { ip, name_orig, name_clean, mnt_path, fstab_line }
    """
    targets = []
    for i in instances:
        ip = i.get("PrivateIpAddress")
        if not ip:
            continue
        name = extract_name_tag(i.get("Tags")) or i.get("InstanceId") or ip
        # name_clean now comes from the trailing parenthesized token (sanitized)
        name_clean = extract_host_from_name(name)
        if not name_clean:
            # ensure some non-empty name
            name_clean = (i.get("InstanceId") or ip).replace(" ", "")
        mnt_path = os.path.join(mnt_root, name_clean)
        fstab_line = f"//{ip}/LogFiles {mnt_path} cifs {CIFS_OPTS.format(creds=creds_file)} 0 0"
        targets.append({
            "ip": ip,
            "name_orig": name,
            "name_clean": name_clean,
            "mnt_path": mnt_path,
            "fstab_line": fstab_line
        })
    # de-dup by mount path
    uniq = {(t["mnt_path"], t["ip"]): t for t in targets}
    return list(uniq.values())

def ensure_fstab(updated_lines: List[str], target: dict) -> Tuple[List[str], bool]:
    """
    Return (new_lines, changed)
    Add entry if not present; warn if mount path already used with different IP.
    """
    mnt = target["mnt_path"]
    ip = target["ip"]
    fstab_line = target["fstab_line"]

    # Exact line present?
    if any(line.strip() == fstab_line.strip() for line in updated_lines):
        return updated_lines, False

    # Mount path already present with cifs?
    mount_re = re.compile(rf"^\s*//[^\s]+/LogFiles\s+{re.escape(mnt)}\s+cifs\b")
    for line in updated_lines:
        if mount_re.search(line):
            # already has a CIFS entry for this mount path; do nothing
            return updated_lines, False

    # Append our line
    return updated_lines + [fstab_line], True

def file_has_fb_path(yaml_text: str, fb_path: str) -> bool:
    # Simple literal check is enough for idempotence:
    return f"path: '{fb_path}'" in yaml_text or f'path: "{fb_path}"' in yaml_text

def insert_fb_input(yaml_text: str, block_text: str):
    """
    Insert the given input block under pipeline.inputs.
    Ensures list items under inputs are indented by *four* spaces.
    """
    lines = yaml_text.splitlines()
    changed = False

    # Find 'pipeline:'
    try:
        idx_pipeline = next(i for i, l in enumerate(lines) if re.match(r"^\s*pipeline:\s*$", l))
    except StopIteration:
        # No pipeline: append minimal structure
        add = []
        if not yaml_text.endswith("\n"):
            add.append("")
        add.extend([
            "pipeline:",
            "  inputs:",
        ])
        # four-space indent under '  inputs:'
        add.extend(["    " + l for l in block_text.splitlines()])
        new_text = yaml_text + "\n" + "\n".join(add) + "\n"
        return new_text, True

    # Find '  inputs:' under pipeline
    idx_inputs = None
    for i in range(idx_pipeline + 1, len(lines)):
        # next top-level section ends the search
        if re.match(r"^\S", lines[i]) and not re.match(r"^\s", lines[i]):
            break
        if re.match(r"^\s{2}inputs:\s*$", lines[i]):
            idx_inputs = i
            break

    if idx_inputs is None:
        # Add '  inputs:' right after pipeline and our block
        insert_at = idx_pipeline + 1
        to_insert = ["  inputs:"] + ["    " + l for l in block_text.splitlines()]
        lines[insert_at:insert_at] = to_insert
        changed = True
        return "\n".join(lines) + ("\n" if not yaml_text.endswith("\n") else ""), changed

    # Find where inputs section ends (before '  filters:' or '  outputs:' at same indent)
    end_inputs = idx_inputs + 1
    for j in range(idx_inputs + 1, len(lines)):
        if re.match(r"^\s{2}(filters|outputs):\s*$", lines[j]):
            end_inputs = j
            break
        if re.match(r"^\S", lines[j]) and not re.match(r"^\s", lines[j]):
            end_inputs = j
            break
        end_inputs = j + 1  # grow until we find a boundary

    # Insert our block at end of inputs — four-space indent
    to_insert = ["    " + l for l in block_text.splitlines()]
    lines[end_inputs:end_inputs] = to_insert
    changed = True
    return "\n".join(lines) + ("\n" if not yaml_text.endswith("\n") else ""), changed

def main():
    ap = argparse.ArgumentParser(description="Sync IIS CIFS mounts and Fluent Bit inputs from EC2 instances.")
    ap.add_argument("--pattern", help="Substring to match in EC2 Name tag (optional). If omitted, all instances are considered.")
    ap.add_argument("--region", default=DEFAULT_REGION, help=f"AWS region (default: {DEFAULT_REGION})")
    ap.add_argument("--creds-file", default=DEFAULT_CREDS, help=f"SMB creds file (default: {DEFAULT_CREDS})")
    ap.add_argument("--mnt-root", default=DEFAULT_MNT_ROOT, help=f"Mount root (default: {DEFAULT_MNT_ROOT})")
    ap.add_argument("--fb-yaml", help="Path to fluent-bit.yaml (default: next to this script)")
    ap.add_argument("--dry-run", action="store_true", help="Print modified file contents without writing or mounting")
    args = ap.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    fb_yaml_path = args.fb_yaml or os.path.join(script_dir, "fluent-bit.yaml")

    if not os.path.exists(args.creds_file):
        print(f"[ERROR] creds file not found: {args.creds_file}", file=sys.stderr)
        sys.exit(2)
    if not os.path.exists(fb_yaml_path):
        print(f"[ERROR] fluent-bit.yaml not found at: {fb_yaml_path}", file=sys.stderr)
        sys.exit(2)

    dry = DryRunPrinter(args.dry_run)

    # Fetch instances (via AWS CLI)
    print(f"[INFO] Discovering instances in {args.region} (pattern: {args.pattern or 'ALL'}) ...")
    instances = aws_describe_instances(args.region, args.pattern)

    if not instances:
        print("[INFO] No instances returned.")
        sys.exit(0)

    targets = build_targets(instances, args.mnt_root, args.creds_file)
    if not targets:
        print("[INFO] No instances with PrivateIpAddress.")
        sys.exit(0)

    # --- Update /etc/fstab ---
    orig_fstab = read_file(FSTAB_PATH)
    fstab_lines = [l for l in orig_fstab.splitlines()]
    changed_fstab = False

    for t in targets:
        # make mount dir
        dry.mkdir(t["mnt_path"])
        # ensure fstab has entry
        new_lines, changed = ensure_fstab(fstab_lines, t)
        if changed:
            fstab_lines = new_lines
            changed_fstab = True

    new_fstab = "\n".join(fstab_lines) + ("\n" if not orig_fstab.endswith("\n") else "")

    if changed_fstab:
        print("[INFO] /etc/fstab will be updated.")
        backup(FSTAB_PATH, dry)
        write_file(FSTAB_PATH, new_fstab, dry)
    else:
        print("[INFO] /etc/fstab already contains all required entries.")

    # --- Update fluent-bit.yaml ---
    fb_yaml_text = read_file(fb_yaml_path)
    fb_changed = False
    fb_working = fb_yaml_text

    for t in targets:
        fb_path = f"/mnt/{t['name_clean']}/W3SVC*/*.log"
        if file_has_fb_path(fb_working, fb_path):
            print(f"[INFO] fluent-bit.yaml already has input for {fb_path}")
            continue
        block = FB_INPUT_BLOCK_TEMPLATE.format(path=fb_path)
        fb_working, inserted = insert_fb_input(fb_working, block)
        if inserted:
            print(f"[INFO] will add Fluent Bit input for {fb_path}")
            fb_changed = True

    if fb_changed:
        backup(fb_yaml_path, dry)
        write_file(fb_yaml_path, fb_working, dry)
    else:
        print("[INFO] fluent-bit.yaml already had all needed inputs. No changes.")

    # --- Mount targets (skip in dry-run) ---
    for t in targets:
        # If fstab had (or now has) the entry, try to mount it
        if args.dry_run:
            dry.mount_single(t["mnt_path"])
        else:
            # Only try mount if a corresponding CIFS line exists now
            # (We already added if missing above)
            dry.mount_single(t["mnt_path"])

    print("[DONE]")

if __name__ == "__main__":
    # Must be root when not dry-run (writing /etc/fstab and mounting)
    if "--dry-run" not in sys.argv and os.geteuid() != 0:
        print("[ERROR] please run as root (or add --dry-run to preview changes).", file=sys.stderr)
        sys.exit(1)
    main()