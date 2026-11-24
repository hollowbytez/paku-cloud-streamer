# Paku Cloud Streamer (Render Engine)

24/7 Discord Live Streamer powered by headless Gateway + Voice UDP WebRTC engine and Cloudflare Edge WebSocket bridge.

## Architecture
- **Control Plane**: Cloudflare Workers (`paku-prime-cloudflare`) handles `/stream` and `.stream` slash/prefix commands and concurrency locks.
- **Data Plane (UDP)**: Hosted on Render Docker container. Establishes Voice Gateway connection, selects UDP media port with IP discovery, and pumps real H.264 video frames and Opus audio packets directly into Discord SFU.
- **Edge Bridge**: The container maintains a persistent WebSocket bridge to `wss://paku-prime-cloudflare.pagalonetap7770.workers.dev/stream/bridge/:accountId` to receive instant stream triggers from anywhere.

## Deployment on Render
1. Push this repository to GitHub.
2. In [Render Dashboard](https://dashboard.render.com), click **New +** -> **Web Service**.
3. Select this repository (`paku-cloud-streamer`).
4. Select **Docker** environment.
5. Set Plan to **Free**.
6. (Optional) Set `AUTO_STREAM=true` if you want the stream to start automatically upon service boot, or keep `AUTO_STREAM=false` to trigger it via Discord `/stream`.
7. Click **Deploy Web Service**.
