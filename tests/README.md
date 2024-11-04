
# Test

1. Put Client-CA at /config/ca.pem

2. Put [localhost.direct cert](https://get.localhost.direct) to /config as localhost.direct.crt and localhost.direct.key

3. Start Traefik and whoami using:

```bash
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
docker-compose up -d
```

4. Test with e.g. `curl https://whoami.localhost.direct:8140`

