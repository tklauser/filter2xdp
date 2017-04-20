# filter2xdp

filter2xdp will take a [pcap/tcpdump filter
expression](http://www.tcpdump.org/manpages/pcap-filter.7.html), compile it to
classical BPF (cBPF) using libpcap, convert it to extended BPF (eBPF) and load
it as an XDP BPF program. By default, the XDP program will only pass packets to
the Linux network stack which match the filter expression. If the XDP program
is loaded using the `--invert` option, the filter is reversed and the program
will drop all packets matching the filter expression.

*Note*: This is work in progress and not working yet as intended (i.e. no valid
XDP eBPF programs are generated). However, Feedback, suggestions and patches
are already welcome!

Usage
=====

```
Usage: filter2xdp [OPTIONS...] -i <dev> FILTER
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

filter2xdp is subject to the GPL, version 2.

Please see the [COPYING](https://github.com/tklauser/filter2xdp/blob/master/COPYING)
file for the full license text.

Resources
=========

* [eBPF docs](https://prototype-kernel.readthedocs.io/en/latest/bpf/index.html) and [XDP docs](https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/index.html) in the Linux Networking Subsystem documentation by Jesper Dangaard Brouer
* [BPF and XDP Reference Guide](http://cilium.readthedocs.io/en/latest/bpf/#bpf-and-xdp-reference-guide) from the [Cilium](https://github.com/cilium/cilium) developer's guide
