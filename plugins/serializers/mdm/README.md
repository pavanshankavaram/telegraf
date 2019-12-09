# MDM Metrics serializer

The MDM Metrics serializer outputs metrics in the MDM format

It can be used to write to a file using the file output, or for sending metrics to a MID Server with Enable REST endpoint activated using the standard telegraf HTTP output.
If you're using the HTTP output, this serializer knows how to batch the metrics so you don't end up with an HTTP POST per metric.

An example event looks like:
```javascript
[
  {
    "type": "ConnectedClusterAgent",
    "MetricName": "process_uptime_seconds",
    "value": 90,
    "dimensions": null
  },
  {
    "type": "ConnectedClusterAgent",
    "MetricName": "process_resident_memory_bytes",
    "value": 90,
    "dimensions": null
  },
  {
    "type": "ConnectedClusterAgent",
    "MetricName": "process_cpu_seconds_total",
    "value": 90,
    "dimensions": null
  }
]
```
## Using with the HTTP output

```toml
[[outputs.http]]
  ## URL is the address to send metrics to
  url = "http://<mid server fqdn or ip address>:9082/api/mid/sa/metrics"

  ## Timeout for HTTP message
  # timeout = "5s"

  ## HTTP method, one of: "POST" or "PUT"
  method = "POST"

  ## HTTP Basic Auth credentials
  username = 'evt.integration'
  password = 'P@$$w0rd!'

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false

  ## Data format to output.
  data_format = "mdm"
  
  ## Additional HTTP headers
  [outputs.http.headers]
  #   # Should be set manually to "application/json" for json data_format
  Content-Type = "application/json"
  Accept = "application/json"

## Using with the File output

You can use the file output to output the payload in a file. 
In this case, just add the following section to your telegraf config file

```toml
[[outputs.file]]
  ## Files to write to, "stdout" is a specially handled file.
  files = ["C:/Telegraf/metrics.out"]

  ## Data format to output.
  data_format = "mdm"
```
