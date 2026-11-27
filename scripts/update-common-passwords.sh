#!/usr/bin/env bash
# Regenerates internal/modules/identity/internal/policy/common_passwords.txt
# from SecLists (MIT License), filtered to >= 12 characters and <= 800 KiB.
set -euo pipefail

URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt"
OUT="internal/modules/identity/internal/policy/common_passwords.txt"
MAX_BYTES=819200

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

curl -fsSL "$URL" -o "$tmp"

{
  printf '# Source: SecLists (danielmiessler/SecLists) - xato-net-10-million-passwords-1000000.txt\n'
  printf '# License: MIT License (https://github.com/danielmiessler/SecLists/blob/master/LICENSE)\n'
  printf '# Filtered: lowercase, trimmed, >= 12 characters, deduplicated, capped <= 800 KiB.\n'
  printf '# Regenerate: bash scripts/update-common-passwords.sh\n'
  awk '
    {
      gsub(/\r$/, "")
      s = tolower($0)
      if (length(s) >= 12 && !seen[s]++) {
        bytes += length(s) + 1
        if (bytes > '"$MAX_BYTES"') exit
        print s
      }
    }
  ' "$tmp"
} > "$OUT"

echo "Generated $OUT ($(wc -l < "$OUT") lines, $(wc -c < "$OUT") bytes)"
