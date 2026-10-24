#!/usr/bin/env bash
set -e

mkdir -p /app/docs/screenshots

echo "[*] Starting Xvfb virtual framebuffer on :99..."
Xvfb :99 -screen 0 1024x768x24 &
XVFB_PID=$!
export DISPLAY=:99
export LIBGL_ALWAYS_SOFTWARE=1
sleep 1.5

echo "[*] Starting window manager (openbox)..."
openbox &
WM_PID=$!
sleep 1

echo "[*] Launching MX Detective GUI..."
/app/target/release/mx-detective --gui &
APP_PID=$!
sleep 3

echo "[*] Capturing 01-main-window.png..."
import -window root /app/docs/screenshots/01-main-window.png

# Click "Inspect MX" button (around x=900, y=75)
echo "[*] Triggering diagnostic run..."
xdotool mousemove 900 75 click 1
sleep 4

echo "[*] Capturing 02-overview-findings.png..."
import -window root /app/docs/screenshots/02-overview-findings.png

# Click "SMTP Behavior & Anomalies" tab (around x=260, y=115)
echo "[*] Switching to SMTP Behavior tab..."
xdotool mousemove 260 115 click 1
sleep 1.5
import -window root /app/docs/screenshots/03-smtp-behavior.png

# Click "DNS & Reverse DNS" tab (around x=430, y=115)
echo "[*] Switching to DNS & Reverse DNS tab..."
xdotool mousemove 430 115 click 1
sleep 1.5
import -window root /app/docs/screenshots/04-dns-records.png

# Click "Port Reachability" tab (around x=570, y=115)
echo "[*] Switching to Port Reachability tab..."
xdotool mousemove 570 115 click 1
sleep 1.5
import -window root /app/docs/screenshots/05-port-reachability.png

# Click "Raw Transcript" tab (around x=690, y=115)
echo "[*] Switching to Raw Transcript tab..."
xdotool mousemove 690 115 click 1
sleep 1.5
import -window root /app/docs/screenshots/06-raw-transcript.png

echo "[*] All screenshots captured successfully!"
kill $APP_PID 2>/dev/null || true
kill $WM_PID 2>/dev/null || true
kill $XVFB_PID 2>/dev/null || true
sleep 1
