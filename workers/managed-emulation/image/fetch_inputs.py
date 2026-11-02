"""CI/developer input fetch only. No application download/install route is added."""
import hashlib
import json
from pathlib import Path
import sys
import time
import urllib.request
from urllib.parse import urlparse

LOCK = Path(__file__).with_name("inputs.lock.json")


def download(item, destination):
    url = item["url"]
    if urlparse(url).scheme != "https" or urlparse(url).hostname not in {"deb.debian.org", "security.debian.org"}:
        raise ValueError("Unreviewed input origin")
    deadline = time.monotonic() + 180
    data = bytearray()
    with urllib.request.urlopen(url, timeout=20) as response:
        if urlparse(response.geturl()).scheme != "https":
            raise ValueError("Insecure input redirect")
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("Input deadline")
            chunk = response.read(min(65536, item["size"] + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > item["size"]:
                raise ValueError("Input size")
    if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise ValueError("Input integrity")
    # Caller creates a new, private build directory. Never overwrite cached inputs.
    with destination.open("xb") as output:
        output.write(data)


def main():
    if len(sys.argv) != 2:
        raise ValueError("Private build directory required")
    directory = Path(sys.argv[1])
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    lock = json.loads(LOCK.read_text())
    for label in ("kernel", "busybox"):
        download(lock["packages"][label], directory / (label + ".deb"))


if __name__ == "__main__":
    main()
