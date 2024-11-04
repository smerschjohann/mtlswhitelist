
# Test

1. Put Client-CA at `/config/certs/ca.pem`

2. Put [localhost.direct cert](https://get.localhost.direct) to /config as `/config/certs/localhost.direct.crt` and `/config/certs/localhost.direct.key`.

3. Modify the whitelists according to your network configuration and test scenario.

4. Start Traefik and whoami using:

```bash
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
docker-compose up -d
```

5. Test with e.g. `curl https://whoami.localhost.direct:8140`

