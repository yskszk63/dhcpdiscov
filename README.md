# dhcpdiscov

Dump `DHCPDISCOVER`.

No IP required.

## Example

```
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: enp3s0f0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether xx:xx:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff
3: wlp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether xx:xx:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff
    inet6 fe80::xxx:xxxx:xxxx:xxx/64 scope link
       valid_lft forever preferred_lft forever
$ sudo dhcping wlp2s0
server: 192.168.10.1
leasetime: 14400s
subnet mask: 255.255.255.0
router: 192.168.10.1
domain name server: 192.168.10.1
renewaltime: 7200s
rebindtime: 12600s
$
```
