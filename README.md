# passive-network-monitoring

The program 'mydump', will capture the traffic from a network interface in promiscuous mode (or read the
packets from a pcap trace file) and print a record for each packet in its
standard output, much like a simplified version of tcpdump. The user will be
able to specify a BPF filter for capturing a subset of the traffic, and/or a
string pattern for capturing only packets with matching payloads.

The program conforms to the following specification:

go run mydump.go [-i interface] [-r file] [-s string] expression

-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, mydump will automatically select a default interface to
    listen on. Capture will continue indefinitely until the user
    terminates the program.

-r  Read packets from <file> in tcpdump format.

-s  Keep only packets that contain <string> in their payload (after any BPF
    filter is applied).
