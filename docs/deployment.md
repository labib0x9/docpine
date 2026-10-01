```bash
---
## Deployment Notes & Production Recommendations

### Cloudflare Tunnel Usage (Recommended)
Dockpine is designed to run behind a Cloudflare Tunnel for security and routing:

1. **Install `cloudflared` on the host:**
   ```bash
   curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloudflare-main.gpg
   echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
   sudo apt update
   sudo apt install cloudflared
   ```

2. **Login to Cloudflare:**
   ```bash
   cloudflared tunnel login
   ```

3. **Create a tunnel configuration:**
   ```bash
   cloudflared tunnel create <tunnel-name>
   ```

4. **Configure the tunnel:**
   Create `~/.cloudflared/config.yml` with:
   ```yaml
   tunnel: <tunnel-id>
   credentials-file: /root/.cloudflared/<tunnel-id>.json
   
   ingress:
     - hostname: [EMAIL_ADDRESS]
       service: http://localhost:8080
     - service: http_status:404
   ```

5. **Run the tunnel:**
   ```bash
   cloudflared tunnel run
   ```

6. **Add DNS record:**
   In Cloudflare dashboard, create CNAME record pointing `[EMAIL_ADDRESS]` to `<tunnel-id>.cfargotunnel.com`.

### Docker Compose with Cloudflare Tunnel
You can run the tunnel as a separate container:
```bash
docker run -d \
  --name cloudflared \
  -v /root/.cloudflared/:/etc/cloudflared/ \
  -e TUNNEL_TOKEN=<tunnel-id> \
  cloudflare/cloudflared tunnel run
```

### Production Settings Recommendation
```bash
RUNTIME_NAME=gvisor                     # Security: user-space kernel
SESSION_TTL=10m                         # Longer sessions for productivity
MAX_SESSIONS=50                         # Higher concurrency for more users
RATE_LIMIT_BURST=10
RATE_LIMIT_REFILL=60s
ALLOWED_ORIGINS=https://yourdomain.com
LOG_LEVEL=info
LOG_MAX_AGE=30
LOG_MAX_BACKUPS=7
```

### File Transfer Workflow (Windows Client)
**Windows-only 1-liner to get files from Docker container:**
```bash
powershell -NoProfile -Command "$sid = [System.Guid]::NewGuid().ToString(); docker cp dockpine-backend:web/download/$sid ./; Start-Sleep -Seconds 2; docker exec dockpine-backend rm -rf /web/download/$sid; Invoke-Item ./$sid"
```
This creates a random session ID, copies the downloaded file to Windows, removes it from the container, and opens it automatically.

### Build Arguments
```bash
# Rebuild with fresh cache (updates Dockerfile, go.mod, or frontend files)
docker compose build --build-arg CACHE_BUST=$(date +%s)

# Rebuild only frontend with cache bust
docker compose build --build-arg CACHE_BUST=$(date +%s) docpine-frontend

# Build with specific Git ref
docker compose build --build-arg GIT_REF=develop
```

### Troubleshooting
- **Container starts but no shell:** Check Docker daemon health (`docker ps`), container logs (`docker logs docpine-backend`), and runtime prerequisites.
- **Cloudflare authentication issues:** Ensure `cloudflared` is logged in (`cloudflared tunnel list`) and config file has correct permissions.
- **WebSocket disconnects:** Verify WebSocket URL in frontend points to correct host/port and that Cloudflare tunnel is routing traffic correctly.
- **Turnstile errors:** Check `cf-turnstile-response` header is sent from frontend and secret key is valid in `.env`.
```