#!/usr/bin/env python3
"""Pull trustpositifkominfo over AXFR and publish AdGuard Home filters."""

import argparse
import fcntl
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ZONE = "trustpositifkominfo"
DATA_DIR = ROOT / "data"
CONFIG_PATH = DATA_DIR / "sync.conf"
ZONE_FILE = DATA_DIR / "trustpositifkominfo.zone"
RULES_FILE = DATA_DIR / "adguard-rules.txt"
ADGUARD_DIR = ROOT / "adguard"
README_PATH = ROOT / "README.md"
MAX_PART_BYTES = 45 * 1024 * 1024
MASTERS = ()
AUTHOR_NAME = ""
AUTHOR_EMAIL = ""
CNAME_RE = re.compile(r"^(?P<owner>\S+)\s+(?:\d+\s+)?(?:IN\s+)?CNAME\s+\S+", re.IGNORECASE)
SOA_SERIAL_RE = re.compile(r"\bSOA\b\s+\S+\s+\S+\s+(\d+)", re.IGNORECASE)
SOA_LINE_RE = re.compile(
    rf"^{ZONE}\.?\s+(?:\d+\s+)?(?:IN\s+)?SOA\s+\S+\s+\S+\s+(\d+)\b",
    re.IGNORECASE,
)
README_SERIAL_RE = re.compile(r"Serial:\s*`(\d+)`")
LABEL_RE = re.compile(r"[a-z0-9_-]+")
GITHUB_FILE_LIMIT = 50 * 1000 * 1000


def log(message):
    print(message, flush=True)


def load_config():
    global MASTERS, AUTHOR_NAME, AUTHOR_EMAIL
    if not CONFIG_PATH.exists():
        raise RuntimeError(f"Missing {CONFIG_PATH}")
    values = {}
    for raw in CONFIG_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    masters = [item for item in values.get("MASTERS", "").replace(",", " ").split() if item]
    name = values.get("AUTHOR_NAME", "")
    email = values.get("AUTHOR_EMAIL", "")
    if not masters or not name or not email:
        raise RuntimeError("sync.conf requires MASTERS, AUTHOR_NAME, and AUTHOR_EMAIL")
    MASTERS = tuple(masters)
    AUTHOR_NAME = name
    AUTHOR_EMAIL = email


def repository_raw_prefix():
    proc = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    match = re.search(r"github\.com[:/]([^/\s]+)/([^/\s.]+)", proc.stdout.strip())
    if proc.returncode != 0 or match is None:
        raise RuntimeError("Origin is not a GitHub repository URL")
    owner, repo = match.group(1), match.group(2)
    return f"https://raw.githubusercontent.com/{owner}/{repo}/main/adguard"


def git_env():
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = AUTHOR_NAME
    env["GIT_AUTHOR_EMAIL"] = AUTHOR_EMAIL
    env["GIT_COMMITTER_NAME"] = AUTHOR_NAME
    env["GIT_COMMITTER_EMAIL"] = AUTHOR_EMAIL
    env["GIT_TERMINAL_PROMPT"] = "0"
    key = Path("/root/.ssh/trustpositif_ed25519")
    if key.exists():
        env["GIT_SSH_COMMAND"] = f"ssh -i {key} -o IdentitiesOnly=yes"
    return env


def run(cmd, check=True, capture=False):
    return subprocess.run(
        cmd,
        cwd=ROOT,
        env=git_env(),
        check=check,
        text=True,
        capture_output=capture,
    )


def query_serial(master):
    proc = subprocess.run(
        [
            "dig",
            "+tcp",
            "+time=8",
            "+tries=1",
            "+norecurse",
            "+nocmd",
            "+noall",
            "+answer",
            f"@{master}",
            ZONE,
            "SOA",
        ],
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    match = SOA_SERIAL_RE.search(proc.stdout)
    if proc.returncode != 0 or match is None:
        detail = (proc.stderr or proc.stdout).strip()
        raise RuntimeError(detail or f"SOA query failed for {master}")
    return int(match.group(1))


def masters_for_serial():
    found = []
    errors = []
    for master in MASTERS:
        try:
            found.append((query_serial(master), master))
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{master}: {exc}")
    if not found:
        raise RuntimeError("No master answered SOA. " + " | ".join(errors))
    best = max(serial for serial, _master in found)
    ordered = [master for serial, master in found if serial == best]
    for message in errors:
        log(f"warning: {message}")
    return best, ordered


def local_serial():
    if not README_PATH.exists():
        return None
    match = README_SERIAL_RE.search(README_PATH.read_text(encoding="utf-8"))
    return int(match.group(1)) if match else None


def ensure_disk_space():
    usage = shutil.disk_usage(DATA_DIR if DATA_DIR.exists() else ROOT)
    incoming = ZONE_FILE.stat().st_size if ZONE_FILE.exists() else 2 * 1024**3
    needed = incoming + 1024**3
    if usage.free < needed:
        raise RuntimeError(
            f"Not enough disk space for a zone transfer: {usage.free} bytes free, need {needed}"
        )


def soa_serial(line):
    match = SOA_LINE_RE.search(line.strip())
    return int(match.group(1)) if match else None


def axfr(master, serial):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    partial = ZONE_FILE.with_suffix(".partial")
    partial.unlink(missing_ok=True)
    ensure_disk_space()
    error_path = DATA_DIR / "axfr.err"
    cmd = [
        "dig",
        "+tcp",
        "+time=30",
        "+tries=1",
        "+nocmd",
        "+nocomments",
        "+nostats",
        f"@{master}",
        ZONE,
        "AXFR",
    ]
    first_line = ""
    last_line = ""
    record_count = 0
    log(f"AXFR {ZONE} from {master}")
    error_handle = error_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=error_handle, text=True)
    assert proc.stdout is not None
    try:
        with partial.open("w", encoding="utf-8", errors="replace") as output:
            for line in proc.stdout:
                if not line.strip() or line.startswith(";"):
                    continue
                output.write(line)
                record_count += 1
                if not first_line:
                    first_line = line
                last_line = line
    finally:
        proc.stdout.close()
        error_handle.close()
        return_code = proc.wait()
    error = error_path.read_text(encoding="utf-8", errors="replace") if error_path.exists() else ""
    start_serial = soa_serial(first_line)
    end_serial = soa_serial(last_line)
    complete = (
        return_code == 0
        and "Transfer failed" not in error
        and record_count > 2
        and start_serial == serial
        and end_serial == serial
    )
    if not complete:
        partial.unlink(missing_ok=True)
        detail = error.strip() or f"dig exited {return_code}; SOA {start_serial}..{end_serial}"
        raise RuntimeError(f"AXFR from {master} failed: {detail}")
    partial.replace(ZONE_FILE)
    log(f"saved {ZONE_FILE}")


def presentation_labels(text):
    labels = []
    buf = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char == ".":
            labels.append(buf)
            buf = bytearray()
            index += 1
            continue
        if char == "\\":
            digits = text[index + 1 : index + 4]
            if len(digits) == 3 and digits.isdigit():
                value = int(digits)
                if value > 255:
                    return None
                buf.append(value)
                index += 4
                continue
            if index + 1 >= len(text) or text[index + 1] == "." or ord(text[index + 1]) > 255:
                return None
            buf.append(ord(text[index + 1]))
            index += 2
            continue
        buf.extend(char.encode("utf-8"))
        index += 1
    labels.append(buf)
    decoded = []
    for raw in labels:
        if not raw:
            return None
        try:
            decoded.append(raw.decode("utf-8"))
        except UnicodeError:
            return None
    return decoded


def domain_from_owner(owner):
    name = owner.rstrip(".").lower()
    suffix = f".{ZONE}"
    if name == ZONE:
        return None
    if name.endswith(suffix):
        name = name[: -len(suffix)]
    if name.startswith("*."):
        name = name[2:]
    if not name or name == "*":
        return None
    labels = presentation_labels(name)
    if labels is None:
        return None
    ascii_labels = []
    for label in labels:
        if any(ord(char) > 127 for char in label):
            try:
                label = label.encode("idna").decode("ascii")
            except UnicodeError:
                return None
        if LABEL_RE.fullmatch(label) is None or len(label) > 63:
            return None
        ascii_labels.append(label)
    domain = ".".join(ascii_labels)
    if not domain or len(domain) > 253:
        return None
    return domain


def iter_domains(zone_path):
    seen = set()
    skipped = 0
    iter_domains.skipped = 0
    with zone_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = CNAME_RE.match(line)
            if match is None:
                continue
            domain = domain_from_owner(match.group("owner"))
            if domain is None:
                skipped += 1
                continue
            if domain in seen:
                continue
            seen.add(domain)
            yield domain
    iter_domains.skipped = skipped


def write_rules(zone_path):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    count = 0
    with RULES_FILE.open("w", encoding="utf-8") as output:
        for domain in iter_domains(zone_path):
            output.write(f"||{domain}^\n")
            count += 1
    if count == 0:
        raise RuntimeError("Zone file produced no AdGuard rules")
    log(f"rules: {count}; skipped: {iter_domains.skipped}")
    return count


def header_text(part, total, serial, width):
    part_label = f"{part:0{width}d}"
    total_label = f"{total:0{width}d}"
    return (
        f"! Title: Trust Positif Kominfo part {part_label} of {total_label}\n"
        f"! Description: Blocklist converted from RPZ trustpositifkominfo for AdGuard Home\n"
        f"! Serial: {serial}\n"
        f"! Part: {part_label}/{total_label}\n"
    )


def part_ranges(rule_path, serial):
    sizes = []
    with rule_path.open("rb") as handle:
        for line in handle:
            sizes.append(len(line))
    guess = 1
    ranges = [(0, len(sizes))]
    width = 2
    for _attempt in range(8):
        width = max(2, len(str(guess)))
        ranges = []
        index = 0
        part = 1
        while index < len(sizes):
            used = len(header_text(part, guess, serial, width).encode())
            start = index
            while index < len(sizes) and (used + sizes[index] <= MAX_PART_BYTES or index == start):
                used += sizes[index]
                index += 1
            ranges.append((start, index))
            part += 1
        if len(ranges) == guess:
            return ranges, width
        guess = len(ranges)
    raise RuntimeError("Could not split the AdGuard list under the size limit")


def write_parts(serial):
    ranges, width = part_ranges(RULES_FILE, serial)
    total = len(ranges)
    ADGUARD_DIR.mkdir(parents=True, exist_ok=True)
    names = []
    written = []
    try:
        with RULES_FILE.open("r", encoding="utf-8") as rules:
            index = 0
            for part, (start, end) in enumerate(ranges, start=1):
                while index < start:
                    if not rules.readline():
                        break
                    index += 1
                name = f"trustpositif-{part:0{width}d}.txt"
                names.append(name)
                temporary = ADGUARD_DIR / f".tmp-{name}"
                with temporary.open("w", encoding="utf-8") as output:
                    output.write(header_text(part, total, serial, width))
                    while index < end:
                        line = rules.readline()
                        if not line:
                            break
                        output.write(line)
                        index += 1
                written.append(temporary)
        for temporary in written:
            final = ADGUARD_DIR / temporary.name.removeprefix(".tmp-")
            temporary.replace(final)
            if final.stat().st_size >= GITHUB_FILE_LIMIT:
                raise RuntimeError(f"{final.name} is at least 50 MB")
    except Exception:
        for temporary in written:
            temporary.unlink(missing_ok=True)
        raise
    for path in ADGUARD_DIR.glob("trustpositif-*.txt"):
        if path.name not in names:
            path.unlink()
            log(f"removed {path.name}")
    log(f"parts: {total}")
    return names


def write_readme(serial, names):
    lines = [
        "# Trust Positif",
        "",
        "Daftar blokir AdGuard Home dari zona RPZ `trustpositifkominfo`.",
        f"Serial: `{serial}`.",
        "",
    ]
    lines.extend(f"- {repository_raw_prefix()}/{name}" for name in names)
    README_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def stage_updates(include_lists):
    paths = [".gitignore", "systemd"]
    if include_lists:
        paths.extend(["README.md", "adguard"])
    for path in paths:
        result = run(["git", "add", "--", path], check=False)
        if result.returncode != 0:
            log(f"warning: could not stage {path}")


def commit_and_push(serial, lists_changed):
    stage_updates(include_lists=lists_changed)
    staged = run(["git", "diff", "--cached", "--quiet"], check=False)
    if staged.returncode == 0:
        push_if_needed()
        return
    message = (
        f"Update Trust Positif AdGuard list to serial {serial}."
        if lists_changed
        else "Add automatic Trust Positif zone sync."
    )
    run(
        [
            "git",
            "-c",
            f"user.name={AUTHOR_NAME}",
            "-c",
            f"user.email={AUTHOR_EMAIL}",
            "commit",
            "-m",
            message,
        ]
    )
    message_body = run(["git", "log", "-1", "--format=%B"], capture=True).stdout
    if "Co-authored-by:" in message_body:
        raise RuntimeError("Commit contains a Co-authored-by trailer")
    push_if_needed()


def push_if_needed():
    ahead = run(["git", "rev-list", "--count", "origin/main..HEAD"], capture=True).stdout.strip()
    if ahead == "0":
        log("already pushed")
        return
    message_body = run(["git", "log", "origin/main..HEAD", "--format=%B"], capture=True).stdout
    if "Co-authored-by:" in message_body:
        raise RuntimeError("Refusing to push a commit that contains a Co-authored-by trailer")
    log(f"pushing {ahead} commit(s)")
    run(["git", "push", "origin", "HEAD:main"])


def restore_published_lists():
    run(["git", "checkout", "--", "README.md", "adguard"], check=False)
    run(["git", "clean", "-f", "--", "adguard"], check=False)


def sync_lists(serial, masters):
    last_error = None
    for master in masters:
        try:
            axfr(master, serial)
            break
        except RuntimeError as exc:
            last_error = exc
            log(f"warning: {exc}")
    else:
        raise RuntimeError(str(last_error))
    write_rules(ZONE_FILE)
    names = write_parts(serial)
    write_readme(serial, names)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Transfer and rewrite filters even when the serial is unchanged",
    )
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_file = open(DATA_DIR / "sync.lock", "w", encoding="utf-8")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("another sync is running")
        return 0

    load_config()
    restore_published_lists()
    run(["git", "fetch", "origin"])
    run(["git", "pull", "--ff-only", "origin", "main"])
    current = local_serial()
    serial, masters = masters_for_serial()
    log(f"master serial {serial}; published serial {current}")
    if current == serial and not args.rebuild:
        log("serial unchanged")
        commit_and_push(serial, lists_changed=False)
        return 0
    if current is not None and serial < current and not args.rebuild:
        log("master serial is older than the published list")
        return 0
    try:
        sync_lists(serial, masters)
    except Exception:
        restore_published_lists()
        raise
    commit_and_push(serial, lists_changed=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        log(f"error: {exc}")
        sys.exit(1)
