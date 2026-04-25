# Linux Capabilities - CAP NET AND IO

## CAP_SYS_RAWIO


[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) provides a number of sensitive operations including access to `/dev/mem`, `/dev/kmem` or `/proc/kcore`, modify `mmap_min_addr`, access `ioperm(2)` and `iopl(2)` system calls, and various disk commands. The `FIBMAP ioctl(2)` is also enabled via this capability, which has caused issues in the [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). As per the man page, this also allows the holder to descriptively `perform a range of device-specific operations on other devices`.

This can be useful for **privilege escalation** and **Docker breakout.**


## CAP_KILL


**This means that it's possible to kill any process.**

**Example with binary**

Lets suppose the **`python`** binary has this capability. If you could **also modify some service or socket configuration** (or any configuration file related to a service) file, you could backdoor it, and then kill the process related to that service and wait for the new configuration file to be executed with your backdoor.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

If you have kill capabilities and there is a **node program running as root** (or as a different user)you could probably **send** it the **signal SIGUSR1** and make it **open the node debugger** to where you can connect.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


## CAP_NET_BIND_SERVICE


**This means that it's possible to listen in any port (even in privileged ones).** You cannot escalate privileges directly with this capability.

**Example with binary**

If **`python`** has this capability it will be able to listen on any port and even connect from it to any other port (some services require connections from specific privileges ports)

{{#tabs}}
{{#tab name="Listen"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
        output = connection.recv(1024).strip();
        print(output)
```

{{#endtab}}

{{#tab name="Connect"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```

{{#endtab}}
{{#endtabs}}


## CAP_NET_RAW


[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability permits processes to **create RAW and PACKET sockets**, enabling them to generate and send arbitrary network packets. This can lead to security risks in containerized environments, such as packet spoofing, traffic injection, and bypassing network access controls. Malicious actors could exploit this to interfere with container routing or compromise host network security, especially without adequate firewall protections. Additionally, **CAP_NET_RAW** is crucial for privileged containers to support operations like ping via RAW ICMP requests.

**This means that it's possible to sniff traffic.** You cannot escalate privileges directly with this capability.

**Example with binary**

If the binary **`tcpdump`** has this capability you will be able to use it to capture network information.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Note that if the **environment** is giving this capability you could also use **`tcpdump`** to sniff traffic.

**Example with binary 2**

The following example is **`python2`** code that can be useful to intercept traffic of the "**lo**" (**localhost**) interface. The code is from the lab "_The Basics: CAP-NET_BIND + NET_RAW_" from [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)

```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
    flag=""
    for i in xrange(8,-1,-1):
        if( flag_value & 1 <<i ):
            flag= flag + flags[8-i] + ","
    return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
    frame=s.recv(4096)
    ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
    proto=ip_header[6]
    ip_header_size = (ip_header[0] & 0b1111) * 4
    if(proto==6):
        protocol="TCP"
        tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
        tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
        dst_port=tcp_header[0]
        src_port=tcp_header[1]
        flag=" FLAGS: "+getFlag(tcp_header[4])

    elif(proto==17):
        protocol="UDP"
        udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
        udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
        dst_port=udp_header[0]
        src_port=udp_header[1]

    if (proto == 17 or proto == 6):
        print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
        count=count+1
```


## CAP_NET_ADMIN + CAP_NET_RAW


[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability grants the holder the power to **alter network configurations**, including firewall settings, routing tables, socket permissions, and network interface settings within the exposed network namespaces. It also enables turning on **promiscuous mode** on network interfaces, allowing for packet sniffing across namespaces.

**Example with binary**

Lets suppose that the **python binary** has these capabilities.

```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
