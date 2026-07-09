#!/bin/sh
set -eu

# Start Cloudflare WARP daemon inside the container when present.
# The panel controls it through warp-cli from the Settings page.
if command -v warp-svc >/dev/null 2>&1; then
    mkdir -p /var/lib/cloudflare-warp
    warp-svc >/tmp/warp-svc.log 2>&1 &
    echo "$!" >/tmp/warp-svc.pid

    # Best-effort short wait: app can still start even if WARP service needs more time.
    i=0
    while [ "$i" -lt 10 ]; do
        if warp-cli --accept-tos status >/tmp/warp-cli-status.log 2>&1; then
            break
        fi
        i=$((i + 1))
        sleep 1
    done
fi

exec "$@"
