# parpd

parpd is a Proxy ARP Daemon and complies with
[RFC 1027](http://tools.ietf.org/html/rfc1027).
parpd is released under the
[2 clause BSD license](http://www.freebsd.org/copyright/freebsd-license.html).

## Configuring

Configuration is found in the file `/etc/parpd.conf`  
Comment lines should start with `#` or `;`  
Each line compromises of two or three words:  
`<command> <inet address> [<hardware address>]`

Here are some examples:

```sh
# parpd.conf example

# These two do the same thing
proxy 192.168.0.0/24
proxy 192.168.0.0/255.255.255.0

# Send this hardware address to this host
proxy 192.168.0.5 aa:bb:cc:dd:ee:ff

# Ignore a host
ignore 192.168.0.8
```

```sh
# another parpd.conf example

# This one is more interesting - it tells parpd to proxy all ARP requests
# except for a specific subnet.
proxy 0.0.0.0/0
ignore 10.0.0.0/24
```

```sh
# attack example, useful for testing IPv4 Address Conflict Resolution
attack 169.254.0.0/16
```

parpd [Verstable](https://github.com/JacksonAllan/Verstable) to manage
large rulesets and addresses so it remains performant in the most challenging
of networks.
