"""Downloads the small country flags into src/NetWarden.Client/Assets/Flags. flagcdn.com's images are public domain."""
import json
import pathlib
import time
import urllib.request

OUT = pathlib.Path(__file__).resolve().parent.parent / "src" / "NetWarden.Client" / "Assets" / "Flags"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "NetWarden build script"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    codes = json.loads(fetch("https://flagcdn.com/en/codes.json"))
    count = 0
    for code in sorted(codes):
        # Two-letter countries only; "us-ca" style subdivisions are never returned by the country database.
        if len(code) != 2:
            continue
        (OUT / f"{code}.png").write_bytes(fetch(f"https://flagcdn.com/w20/{code}.png"))
        count += 1
        time.sleep(0.02)
    print(f"{count} flags in {OUT}")


if __name__ == "__main__":
    main()
