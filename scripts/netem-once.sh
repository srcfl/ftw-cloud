#!/usr/bin/env bash
# Times the watch's one-shot read over HTTP/1.1, HTTP/2 and HTTP/3 on a slow,
# lossy link (TestOnceReadTimes). The test binary runs in a Linux container
# whose loopback carries netem: 20 ms each way is a 40 ms round trip, and a
# loss applies to each packet. Needs Docker. Each run ends by itself.
#
#   scripts/netem-once.sh [reads per row]

set -euo pipefail

n=${1:-200}
case $(docker info --format '{{.Architecture}}') in
  aarch64 | arm64) arch=arm64 ;;
  x86_64 | amd64) arch=amd64 ;;
  *) echo "netem-once: unknown Docker architecture" >&2; exit 1 ;;
esac

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go test -c -o "$out/server.test" ./internal/server

run() {
  docker run --rm --cap-add NET_ADMIN -v "$out:/w:ro" alpine:3.20 sh -c "
    apk add -q iproute2-tc >/dev/null &&
    tc qdisc add dev lo root netem $2 &&
    FTW_BENCH_ONCE=$n FTW_BENCH_LABEL='$1' /w/server.test -test.run '^TestOnceReadTimes\$' -test.timeout 15m" |
    grep '^| [0-9]'
}

echo '| link | read | n | p50 ms | p95 ms | max ms | failed |'
echo '|---|---|---|---|---|---|---|'
run '40 ms' 'delay 20ms'
run '40 ms, 1 % loss' 'delay 20ms loss 1%'
run '40 ms, 5 % loss' 'delay 20ms loss 5%'
