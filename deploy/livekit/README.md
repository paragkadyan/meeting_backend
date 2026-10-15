# Self-hosted LiveKit (calls) on the production server, without Docker

Runs LiveKit on our own Linux server next to the backend, with no LiveKit Cloud
account and no Docker. LiveKit is a single program, run as a systemd service.
Browsers and the mobile app connect to `wss://livekit.heyllow.com` (nginx,
HTTPS), and call audio/video flows directly to the server's public IP.

Assumes the same server that runs `api.heyllow.com` (nginx, certbot, backend on
port 3000). Run the commands as a user with sudo, from this folder of the
backend checkout (`deploy/livekit`).

## 1. DNS

Add an **A record**: `livekit.heyllow.com` → the server's public IP (same as `api.heyllow.com`).

## 2. Firewall

```bash
sudo ufw allow 7881/tcp          # call media over TCP (fallback)
sudo ufw allow 50000:60000/udp   # call media
sudo ufw allow 3478/udp          # TURN relay for strict networks
# 80/443 are already open for nginx. Keep 7880 closed: only nginx talks to it.
```

If the hosting provider has its own firewall panel, open the same ports there.

## 3. Install LiveKit and its config

```bash
# Installs the livekit-server program to /usr/local/bin
curl -sSL https://get.livekit.io | bash
livekit-server --version

# A dedicated user with no login, so the service doesn't run as root
sudo useradd --system --no-create-home --shell /usr/sbin/nologin livekit

# Config, readable only by root and the livekit user
sudo mkdir -p /etc/livekit
sudo cp livekit.example.yaml /etc/livekit/livekit.yaml
openssl rand -hex 32               # this is your secret
sudo nano /etc/livekit/livekit.yaml   # replace REPLACE_KEY (e.g. heyllow) and REPLACE_SECRET
sudo chown root:livekit /etc/livekit/livekit.yaml
sudo chmod 640 /etc/livekit/livekit.yaml
```

## 4. Run it as a service

```bash
sudo cp livekit.service /etc/systemd/system/livekit.service
sudo systemctl daemon-reload
sudo systemctl enable --now livekit      # starts now and on every boot
sudo systemctl status livekit            # should be "active (running)"
journalctl -u livekit -n 30              # logs; look for "starting LiveKit server"
```

## 5. nginx + HTTPS

```bash
sudo cp nginx-livekit.conf /etc/nginx/sites-available/livekit
sudo ln -s /etc/nginx/sites-available/livekit /etc/nginx/sites-enabled/livekit
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d livekit.heyllow.com
curl https://livekit.heyllow.com     # should print: OK
```

## 6. Backend `.env` (on the server)

```env
# The backend talks to LiveKit locally; apps and browsers get the public address.
LIVEKIT_URL=http://127.0.0.1:7880
LIVEKIT_PUBLIC_URL=wss://livekit.heyllow.com
LIVEKIT_API_KEY=<the key name from /etc/livekit/livekit.yaml>
LIVEKIT_API_SECRET=<the secret from /etc/livekit/livekit.yaml>
```

Don't set `LIVEKIT_NODE_IP` or `LIVEKIT_BIND_IP` here: those are only for the
local development `docker-compose.yml` in the repo root.

Restart the backend afterwards.

## 7. Check

- Start a call from the website: both sides should see and hear each other.
- `journalctl -u livekit -f` shows participants joining.
- The webhook works if a call ends by itself when one side closes the tab.

## Day to day

| Task | Command |
|---|---|
| Logs | `journalctl -u livekit -f` |
| Restart (after editing the config) | `sudo systemctl restart livekit` |
| Update to the latest LiveKit | `curl -sSL https://get.livekit.io \| bash && sudo systemctl restart livekit` |
| Stop | `sudo systemctl stop livekit` |

## Notes

- **Server size**: each person in a call uses roughly 1–2 Mbps for video. A small
  VPS handles a handful of simultaneous calls; watch CPU and bandwidth as usage grows.
- **If calls connect but there's no audio/video**: the UDP/TCP ports above are
  blocked. Check `sudo ufw status` and the provider's firewall.
- **If the service won't start**: `journalctl -u livekit -n 50` usually names the
  problem (most often a typo in `/etc/livekit/livekit.yaml`).
