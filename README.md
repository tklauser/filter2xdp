# pcap2xdp - Compile and load PCAP filter expression as XDP BPF program

Work in progress. Feedback, suggestions and patches are welcome!

Usage
=====

```
Usage: pcap2xdp [OPTIONS...] -i <dev> FILTER
Options:
  -i/--interface <dev>  Network device (required)
  -n/--invert           Invert filter, drop non-matching packets
  -v/--verbose          Verbose mode
  -h/--help             Show this help message
```

License
=======

pcap2xdp is subject to the GPL, version 2.

Please see the [COPYING](https://github.com/tklauser/pcap2xdp/blob/master/COPYING)
file for the full license text.
