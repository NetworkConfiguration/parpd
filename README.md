# parpd

parpd is a Proxy ARP Daemon and complies with
[RFC 1027](http://tools.ietf.org/html/rfc1027).
parpd is released under the
[2 clause BSD license](http://www.freebsd.org/copyright/freebsd-license.html).

## Installing parpd

Change the version as required.

```
cd /tmp
tar xvjpf /path/to/parpd-1.5.tar.bz2
cd parpd-1.5
make install
```

## Configuring

Configuration is found in the file `/etc/parpd.conf`  
Comment lines should start with `#` or `;`  
Each line compromises of two or three words:  
`<command> <inet address> [<hardware address>]`

Here are some examples:

```
# parpd.conf example

# These two do the same thing
proxy 192.168.0.0/24
proxy 192.168.0.0/255.255.255.0

# Send this hardware address to this host
proxy 192.168.0.5 aa:bb:cc:dd:ee:ff

# Ignore a host
ignore 192.168.0.8
```

```
# another parpd.conf example

# This one is more interesting - it tells parpd to proxy all ARP requests
# except for a specific subnet.
proxy 0.0.0.0
ignore 10.0.0.0/24
```
