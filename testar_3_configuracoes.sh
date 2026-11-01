#!/bin/bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"  # runs from project root after copying script there
if [ ! -f go.mod ]; then echo 'ERROR: place this script next to go.mod' >&2; exit 1; fi
TMPDIR_SUITE=$(mktemp -d /tmp/ssc_3configs.XXXXXX)
cp config/proxycrypto.config "$TMPDIR_SUITE/proxy.config"
cp config/servercrypto.config "$TMPDIR_SUITE/server.config"
server_pid=''; proxy_pid=''
restore() {
  [ -z "$proxy_pid" ] || kill "$proxy_pid" 2>/dev/null || true
  [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
  cp "$TMPDIR_SUITE/proxy.config" config/proxycrypto.config
  cp "$TMPDIR_SUITE/server.config" config/servercrypto.config
  rm -rf "$TMPDIR_SUITE"
}
trap restore EXIT INT TERM
if [ ! -f media/dante.mp4 ]; then echo 'ERROR: media/dante.mp4 not found' >&2; exit 1; fi
printf 'Compilando...\n'
go build -o "$TMPDIR_SUITE/server" ./stream-server
go build -o "$TMPDIR_SUITE/proxy" ./stream-proxy
set_size() {
 local file="$1" bits="$2"
 perl -0777 -i -pe "s#<Keysize>\\s*\\d+\\s*</Keysize>#<Keysize>$bits</Keysize>#g" "$file"
}
start_servers(){
 "$TMPDIR_SUITE/server" 19881 media > "$TMPDIR_SUITE/server.log" 2>&1 & server_pid=$!
 "$TMPDIR_SUITE/proxy" 19880 localhost 19881 0 > "$TMPDIR_SUITE/proxy.log" 2>&1 & proxy_pid=$!
 sleep 0.45
}
stop_servers(){
 kill "$proxy_pid" "$server_pid" 2>/dev/null || true
 wait "$proxy_pid" "$server_pid" 2>/dev/null || true
 server_pid=''; proxy_pid=''
 sleep 0.2
}
for bits in 128 192 256; do
 set_size config/proxycrypto.config "$bits"
 set_size config/servercrypto.config "$bits"
 start_servers
 curl --silent --show-error --fail --max-time 20 -o "$TMPDIR_SUITE/received.mp4" 'http://localhost:19880/video/dante.mp4'
 cmp media/dante.mp4 "$TMPDIR_SUITE/received.mp4"
 echo "PASS AES-${bits}-GCM — video identical ($(wc -c < "$TMPDIR_SUITE/received.mp4" | tr -d ' ') bytes)"
 stop_servers
done
set_size config/proxycrypto.config 128
set_size config/servercrypto.config 256
start_servers
curl --silent --max-time 5 -o /dev/null 'http://localhost:19880/video/dante.mp4' 2>/dev/null || true
if grep -q 'Authenticated Stream Server error alert: handshake negotiation failed' "$TMPDIR_SUITE/proxy.log"; then
  echo 'PASS XML incompatible => authenticated Type 255'
else
  echo 'FAIL: no authenticated Type 255 with mismatched XML' >&2
  cat "$TMPDIR_SUITE/server.log" "$TMPDIR_SUITE/proxy.log" >&2
  exit 1
fi
stop_servers
echo 'PASS All configurations. Original XML files will now be restored.'
