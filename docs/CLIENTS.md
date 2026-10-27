# CONNECT client examples

Start Certainted with `certainted serve` (or `certainted.exe serve` on Windows), then configure a client to use the default HTTP proxy at `127.0.0.1:8080` for an **HTTPS-over-TCP** destination. Use `serve -proxy 127.0.0.1:PORT` for another loopback port; `serve -noproxy` disables the listener. Certainted accepts conventional HTTP CONNECT; language does not determine compatibility. The proxy relays encrypted application bytes without terminating the application's TLS session, while a separate TLS probe records its own certificate observation.

The defaults permit public destination IPs on ports 443 and 8443. To exercise a local test server, add an explicit authorized `-allow-cidr 127.0.0.0/8` and the test port to `-ports`. Some clients have `NO_PROXY` settings that bypass proxying local addresses; review them during tests. Do not disable certificate verification in the application to make a proxy test pass.

## curl

```bash
curl --proxy http://127.0.0.1:8080 https://example.com/
```

Or, for curl sessions that honor this variable:

```bash
HTTPS_PROXY=http://127.0.0.1:8080 curl https://example.com/
```

For local fixture tests, an existing `NO_PROXY` setting may bypass the proxy; `--noproxy ''` can override that intentionally. See [curl's proxy option](https://curl.se/docs/manpage.html#-x).

## Python (Requests)

Configure Requests explicitly per call:

```python
import requests

response = requests.get(
    "https://example.com/",
    proxies={"https": "http://127.0.0.1:8080"},
    timeout=15,
)
print(response.status_code)
```

Requests can also read proxy environment variables unless a session or call overrides them. See [Requests proxy configuration](https://requests.readthedocs.io/en/latest/user/advanced/#proxies).

## Java (JDK `HttpClient`)

Use an explicit proxy selector for the client:

```java
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

var client = HttpClient.newBuilder()
    .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", 8080)))
    .build();
var request = HttpRequest.newBuilder(URI.create("https://example.com/"))
    .GET().build();
var response = client.send(request, HttpResponse.BodyHandlers.discarding());
System.out.println(response.statusCode());
```

See the [JDK `HttpClient.Builder.proxy` documentation](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpClient.Builder.html#proxy(java.net.ProxySelector)). A different Java HTTP library may have its own proxy setting.

## Go (`net/http`)

```go
proxyURL, err := url.Parse("http://127.0.0.1:8080")
if err != nil { log.Fatal(err) }
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.Proxy = http.ProxyURL(proxyURL)
client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
response, err := client.Get("https://example.com/")
if err != nil { log.Fatal(err) }
defer response.Body.Close()
fmt.Println(response.StatusCode)
```

The snippet uses `fmt`, `log`, `net/http`, `net/url`, and `time`. Go's default transport can also use proxy environment variables, but an explicit `Transport.Proxy` makes this example deterministic. See the [Go `net/http` documentation](https://pkg.go.dev/net/http#Transport).

## Node.js

For current Node.js runtimes with built-in environment proxy support, opt in when starting the process:

```bash
HTTPS_PROXY=http://127.0.0.1:8080 NODE_USE_ENV_PROXY=1 node client.mjs
```

```javascript
// client.mjs
const response = await fetch("https://example.com/");
console.log(response.status);
```

This opt-in covers supported built-in HTTP, HTTPS, and `fetch()` paths; a custom agent or third-party client may need its own proxy configuration. See [Node.js proxy configuration](https://nodejs.org/learn/http/enterprise-network-configuration) and the [HTTP API](https://nodejs.org/api/http.html#built-in-proxy-support).

## Coverage boundaries

An application that makes direct connections, ignores the proxy setting, uses a different proxy protocol, or sends direct UDP/QUIC traffic is outside this CONNECT collector's coverage. CONNECT authority gives a destination hostname when supplied; it does not reveal which certificate the application received. It can carry multiple application requests, none of which Certainted reads or counts. Metadata-only JSONL ingestion is available when an enterprise egress source already provides destination events and application traffic should not pass through Certainted at all.
