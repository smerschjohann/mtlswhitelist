
## Usage

This plugin is meant to be used in combination with the mTLS settings of Traefik.

If a mTLS certificate was provided, it is expected to be checked by Traefik already, as it would be the case with the configuration parameter `VerifyClientCertIfGiven`.

If no Client certificate is provided, this plugin will check if the Client-IP is in a configured whitelist. There are currently two modes:

1. Either you can define a list manually
2. You enable `whitelistInterface`, which will discover the default network interface (interface with route 0.0.0.0/0) and whitelist the configured IP ranges. This will allow all local traffic to be whitelisted.

### Configuration

static configuration

```yaml
log:
  level: DEBUG

accessLog: {}

entryPoints:
  web:
    address: :8180
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: :8140

providers:
  file:
    filename: "traefik.yml"

experimental:
  plugins:
    example:
      moduleName: github.com/smerschjohann/mtlswhitelist
      version: v0.0.1

#experimental:
#  localPlugins:
#    mtlswhitelist:
#      moduleName: github.com/smerschjohann/mtlswhitelist
```

dynamic configuration

```yaml
http:
  services:
    service1:
      loadBalancer:
        servers:
          - url: "http://localhost:8888/"
  routers:
    router1:
      rule: "Host(`whoami.localhost.direct`)"
      service: service1
      tls:
        options: clientca
      middlewares:
        - mtlswhitelist

  middlewares:
    mtlswhitelist:
      plugin:
        mtlswhitelist:
          whitelistInterface: true
          allowedCidrs:
            - "192.168.100.0/24"
            - "127.0.0.0/8"

tls:
  certificates:
    - certFile: localhost.direct.crt
      keyFile: localhost.direct.key

  options:
    clientca:
      clientAuth:
        caFiles:
          - clientca/yourclientca.crt
        clientAuthType: VerifyClientCertIfGiven
```

The used localhost.direct certificate can be freely retrieved by: [get.localhost.direct](https://get.localhost.direct)


For test purposes you can run the whoami service like this: `podman run -d -p 8888:80 containous/whoami`