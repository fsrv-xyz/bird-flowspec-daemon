# bird-flowspec-daemon

This is a daemon that connects to the Bird (version 2 required) routing daemon and regularly applies the flowspec rules to the host.
Currently, the following actions are supported (see https://datatracker.ietf.org/doc/html/rfc8955#traffic_extended_communities for more information):
- `traffic-rate-bytes`
- `traffic-rate-packets`

### Requirements
- Bird 2 or newer
- Nftables (see installation instructions for further information)

### Installation
This project requires the following structure in nftables:
```shell
#!/usr/sbin/nft -f

table inet filter {
  chain flowspec {} # Flowspec rules will be managed in here
  chain input {
    type filter hook input priority filter; policy accept;
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    jump flowspec # Jump to the flowspec chain to apply the rules
  }
  chain output {
    type filter hook output priority filter; policy accept;
  }
}
```
The flowspec rules will be inserted into the `flowspec` chain. A jump / goto to this chain is required in order to apply the rules.

### Configuration
Configuration can be done via command line arguments or environment variables.
This repository contains an example systemd service file that can be used to start the daemon.

The following options are available:
```
Flags:
  -h, --[no-]help            Show context-sensitive help (also try --help-long and --help-man).
  -d, --[no-]debug           Enable debug mode
      --bird-socket=/run/bird/bird.ctl
                             Path to BIRD socket ($BIRD_SOCKET_PATH)
      --metrics.listen-address="127.0.0.1:9302"
                             Address to listen on for metrics
      --interval=10s         Interval to check for new routes ($CHECK_INTERVAL)
      --[no-]enable-counter  Enable counter in nftables rules ($ENABLE_COUNTER)
```
