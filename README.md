# pcap2xdp - Compile and load PCAP filter expression as XDP BPF program

pcap2xdp will take a [pcap/tcpdump filter
expression](http://www.tcpdump.org/manpages/pcap-filter.7.html), compile it to
classical BPF (cBPF) using libpcap, convert it to eBPF and load it as an XDP
BPF program. By default, the XDP program will only pass packets to the Linux
network stack which match the filter expression. If the XDP program is loaded
using the `--invert` option, the filter is reversed and the program will drop
all packets matching the filter expression.

This is work in progress and only rudimentarily tested. Feedback, suggestions
and patches are welcome!

Usage
=====

```
Usage: pcap2xdp [OPTIONS...] -i <dev> FILTER
Options:
  -i/--interface <dev>  Network device (required)
  -n/--invert           Invert filter, drop matching packets
  -v/--verbose          Verbose mode
  -h/--help             Show this help message
```

Prerequisites
=============

* Linux Kernel 4.8+
* libpcap (development library and headers)

License
=======

pcap2xdp is subject to the GPL, version 2.

Please see the [COPYING](https://github.com/tklauser/pcap2xdp/blob/master/COPYING)
file for the full license text.
