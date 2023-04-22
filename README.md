## Description

IP-Block is an XDP program, that is an IP firewall. use rules to allow/deny access to a range of IP addresses.

Block ip behavior use XDP package drop.

### Build

```shell
$ git submodule update
$ make
```

After compilation, two executable programs are generated:

- *src/ipblock-loader* is XDP loader, which is used to load and unload XDP program.
- *src/ipblock-rule* is used to control the add and remove of rules.


### Usage

#### ipblock-loader

##### Attach XDP program

attach the ipblock XDP program on the eth2

```shell
# ./ipblock-loader -d eth2
```

##### Detach XDP program

detach the XDP program for the eth2

```shell
# ./ipblock-loader -d eth2 -u
```


#### ipblock-rule

##### Insert rules

droping IP packets for the ::ffff:c612:13/128

```shell
$ ./ipblock-rule -a ::ffff:c612:13/128 -p deny
```

allow IP packets for the 192.168.31.0/24

```shell
$ ./ipblock-rule -a 192.168.31.0/24 -p allow
```


##### Delete rules

```shell
$ ./ipblock-rule -d ::ffff:c612:13/128
$ ./ipblock-rule -d 192.168.31.0/24
```


### Reference

[BPF and XDP Reference Guide](https://docs.cilium.io/en/v1.10/bpf/)

[github libbpf](https://github.com/libbpf/libbpf)

[BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)

