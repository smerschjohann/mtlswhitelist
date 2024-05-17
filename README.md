
## Usage

This plugin is meant to be used in combination with the mTLS settings of Traefik.

If a mTLS certificate was provided, it is expected to be checked by Traefik already, as it would be the case with the configuration parameter `VerifyClientCertIfGiven`.

If no Client certificate is provided, this plugin will grant access based on the whitelist provided.

### Rule Types

This plugin supports the following rule types:

- `AllOf`: This rule type matches if all of the sub-rules are true. It is defined with a `Rules` field which is an array of other rule types. For example:

```json
{
  "type": "allOf",
  "rules": [
    {"type": "ipRange", "ranges": ["192.168.1.1/24"]},
    {"type": "header", "headers": {"User-Agent": ".*Firefox.*"}}
  ]
}
```

- `AnyOf`: This rule type matches if any of the sub-rules are true. It is defined similarly to `AllOf`, but the match is successful if any of the rules in the `Rules` array are true. For example:

```json
{
  "type": "anyOf",
  "rules": [
    {"type": "ipRange", "ranges": ["192.168.1.1/24"]},
    {"type": "header", "headers": {"User-Agent": ".*Firefox.*"}}
  ]
}
```

- `NoneOf`: This rule type matches if none of the sub-rules are true. It is defined similarly to `AllOf` and `AnyOf`, but the match is successful if none of the rules in the `Rules` array are true. For example:

```json
{
  "type": "noneOf",
  "rules": [
    {"type": "ipRange", "ranges": ["192.168.1.1/24"]},
    {"type": "header", "headers": {"User-Agent": ".*Firefox.*"}}
  ]
}
```

- `IPRange`: This rule type matches if the client's IP address is within one of the specified ranges. It is defined with the following fields:

  - `Ranges`: An array of IP ranges in CIDR notation. For example: `["192.168.1.1/24", "10.0.0.0/8"]`.

  - `AddInterface`: An optional boolean field. If set to `true`, the IP addresses of the network interface with the default route on the system will be added to the list of allowed ranges. If this field is not specified, it defaults to `false`.

Here's an example of how to configure an `IPRange` rule:

```json
{
  "type": "ipRange",
  "ranges": ["192.168.1.1/24", "10.0.0.0/8"],
  "addInterface": true
}
```

This will allow any clients on the provided local networks access. If traefik is hosted on a machine in the network 172.16.0.0/24, this would be added as well.

Please note if you configure traefik without host network inside a container, it will just detect it's local container network.

- `Header`: This rule type matches if the client's request headers meet certain conditions. It is defined with a `Headers` field which is a map where the keys are the names of the headers and the values are regular expressions that the header values should match. For example:

```json
{
  "type": "header",
  "headers": {
    "User-Agent": ".*Firefox.*",
    "Accept-Language": "en-US,en;q=0.5"
  }
}
```

In this example, the `Header` rule will match any request where the `User-Agent` header contains the string "Firefox" and the `Accept-Language` header exactly matches the string "en-US,en;q=0.5".


  

### Configuration Example

#### static configuration

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
    mtlswhitelist:
      moduleName: github.com/smerschjohann/mtlswhitelist
      version: v0.0.1

#experimental:
#  localPlugins:
#    mtlswhitelist:
#      moduleName: github.com/smerschjohann/mtlswhitelist
```

#### dynamic configuration

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
          rules:
          - type: ipRange
            addInterface: true # adds the ip ranges of the default route to the whitelist
            ranges: []
            # - 192.168.0.0/24
          - type: header
            headers:
              Custom-Header: "prefix.*"
              Second-Header: ".*" # this only checks if the header is present, it will reject if the header is not sent
          

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