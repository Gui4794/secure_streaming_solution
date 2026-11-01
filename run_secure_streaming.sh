#!/bin/bash
clear

pkill -f "stream-server" 2>/dev/null
pkill -f "stream-proxy" 2>/dev/null
sleep 1

if [ "$#" -gt 7 ]; then
  echo "Usage: $0 [stream_server_port] [stream_media_folder] [proxy_port] [origin_host] [origin_port] [block_delay] [show_experiments]"
  exit 1
fi

STREAM_PORT="${1:-8081}"
STREAM_MEDIA="${2:-media}"
PROXY_PORT="${3:-8080}"
PROXY_ORIGIN="${4:-localhost}"
LISTENING_PORT="${5:-8081}"
BLOCK_DELAY="${6:-2000}"
SHOW_OUTPUT="${7:-0}"

kill -9 $(lsof -t -i:"$STREAM_PORT") 1>/dev/null 2>/dev/null
kill -9 $(lsof -t -i:"$PROXY_PORT") 1>/dev/null 2>/dev/null

if [ "$SHOW_OUTPUT" -ne 0 ] && [ "$SHOW_OUTPUT" -ne 1 ]; then
  echo "show experiments must be either 0 or 1"
  exit 1
fi

echo "Starting the stream server on port $STREAM_PORT (dir: $STREAM_MEDIA)..."
go run ./stream-server/ "$STREAM_PORT" "$STREAM_MEDIA" &
SERVER_PID=$!

sleep 2

echo "Starting the stream proxy on port $PROXY_PORT pointing to $PROXY_ORIGIN:$LISTENING_PORT (delay: ${BLOCK_DELAY}ms)..."
go run ./stream-proxy/ "$PROXY_PORT" "$PROXY_ORIGIN" "$LISTENING_PORT" "$BLOCK_DELAY" &
PROXY_PID=$!

echo "Press CTRL+C to terminate"

trap "kill $SERVER_PID $PROXY_PID 2>/dev/null; exit" INT TERM
wait
