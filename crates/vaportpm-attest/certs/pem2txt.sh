#!/bin/bash
# Convert all .pem certificates to human-readable .txt files
# Usage: ./pem2txt.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for pem in "$SCRIPT_DIR"/*.pem; do
    [ -f "$pem" ] || continue
    txt="${pem%.pem}.txt"
    echo "Converting: $(basename "$pem") -> $(basename "$txt")"
    openssl x509 -in "$pem" -text -noout > "$txt"
done

echo "Done."
