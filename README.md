
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


### External Data

The external configuration allows you to fetch data from an external source and use it in the plugin. In the provided example, the external data is fetched from the Kubernetes API and the data is stored in a ConfigMap.

```yaml
externalData:
  skipTlsVerify: true
  url: https://1.2.3.4:6443/api/v1/namespaces/code/configmaps/whitelist # should return a json document
  dataKey: data # a key that holds relevant data
  headers:
    Content-Type: "application/json"
    Authorization: Bearer [[ file "/var/run/secrets/kubernetes.io/serviceaccount/token" ]] # if used like this, the SA of traefik needs to have read permission for this specific URL/configmap
```

To configure the external data, you need to provide the following information:

- `skipTlsVerify`: A boolean field indicating whether to skip TLS verification when fetching the data. Set it to true if you want to skip verification.
`url`: The URL from which to fetch the data. In the example, it is set to https://1.2.3.4:6443/api/v1/namespaces/code/configmaps/whitelist.
- `dataKey`: The key in the fetched JSON document that holds the relevant data. In the example, it is set to data.
- `headers`: Additional headers to include in the request. In the example, Content-Type and Authorization headers are included.

The external data can be used for types `ipRange` and `header`.

### Refresh Interval

The plugin allows you to define a refresh interval for the external data. The refresh interval is defined in the `RefreshInterval` field, which is a duration string that specifies how often the external data should be fetched. The duration string should be in the format accepted by Go's time.ParseDuration function. For example:

```yaml
refreshInterval: 30m
```

### Request Headers

The plugin allows you to define request headers that should be passed to the backend. The headers are defined in the `RequestHeaders` field, which is a map where the keys are the names of the headers and the values are Go template strings that will be evaluated at runtime. The Go template strings can include variables that are provided by Traefik, such as the client certificate information.

Defined are the following variables:

- `Cert`: The client certificate information. This variable provides access to the client certificate's subject, issuer, and other fields. For example, to access the client certificate's Common Name, you can use `[[.Cert.Subject.CommonName]]`.
- `Req`: The HTTP request information. This variable provides access to the HTTP request's headers, method, and other fields.

```yaml
requestHeaders:
  X-Cert-Mail: "[[.Cert.Subject.CommonName]]@domain.tld"
```

In this example, the `X-Cert-Mail` header will be added to the request with the value of the client's Common Name from the certificate appended with "@domain.tld".

### Reject Message

The Middleware allows you to define a custom reject message that is shown, when the Middleware rejects the request. By default the following values are set:

```yaml
rejectMessage:
  message: "Forbidden"
  code: 403
```

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
      version: v0.3.0

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
          rejectMessage:
            message: Forbidden
            code: 403
          requestHeaders:
            X-Cert-Mail: "[[.Cert.Subject.CommonName]]@domain.tld"
          refreshInterval: 30m # if you are using files or external data you can update it periodically, skip if not required
          externalData:
            skipTlsVerify: true
            url: https://1.2.3.4:6443/api/v1/namespaces/default/configmaps/whitelist # should return a json document
            dataKey: data # a key that holds relevant data
            headers:
              Content-Type: "application/json"
              Authorization: Bearer [[ file "/var/run/secrets/kubernetes.io/serviceaccount/token" ]] # if used like this, the SA of traefik needs to have read permission for this specific URL/configmap
          rules:
          - type: ipRange
            addInterface: true # adds the ip ranges of the default route to the whitelist
            ranges:
            - "192.168.0.0/24"
            - "[[ .data.ipRange ]]" # .data is from the external resource (e.g. Kubernetes ConfigMap)
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