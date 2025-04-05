## UDPWAF
Listens for UDP taffic and forwards it to specific host.  
Acts like proxy with additional optional WAF.   
Calls python script with data and if it returns bytes object it will forward that data,  
if it gets None packet will be dropped.

### Remarks

Currently it only only reloads python when new client is created.  
If python script is changed when application is running it will affect new clients.  
Clients are dropped if there is no activity for number of seconds, set in tiemout.

### Usage:

```Usage: udpwaf [OPTIONS]

Options:
  -b, --bind <BIND>              Server bind address [default: [::]:8080]
  -f, --forward <FORWARD>        Where to forward messages [default: [::1]:8000]
  -l, --local-bind <LOCAL_BIND>  Where to listent to for forwarder [default: [::1]:0]
  -t, --timeout <TIMEOUT>        After this time client connection will be dropped [default: 10]
  -h, --help                     Print help
  -V, --version                  Print version
