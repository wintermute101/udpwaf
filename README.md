## UDPWAF
Listens for UDP taffic and forwards it to specific host.</br>
Acts like proxy with additional optional WAF.</br>
Calls python script with data and if it returns bytes object it will forward that data,</br>
if it gets None packet will be dropped.

### Remarks

Currently it only only reloads python when new client is created.</br>
If python script is changed when application is running it will affect new clients.</br>
Clients are dropped if there is no activity for number of seconds, set in tiemout.</br>
</br>
Logger can be configured for trace messages</br>
run ```RUST_LOG=trace cargo run -r```

### Usage:

```Usage: udpwaf [OPTIONS]

Options:
  -b, --bind <BIND>              Server bind address [default: [::]:8080]
  -f, --forward <FORWARD>        Where to forward messages [default: [::1]:8000]
  -l, --local-bind <LOCAL_BIND>  Where to listent to for forwarder [default: [::1]:0]
  -t, --timeout <TIMEOUT>        After this time client connection will be dropped [default: 10]
  -h, --help                     Print help
  -V, --version                  Print version
