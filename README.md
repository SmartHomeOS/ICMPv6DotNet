# ICMPv6DotNet

A C# implementation of the ICMPv6 protocol (WIP)

Implemented RFCs:
* RFC 4443 (ICMPv6 Spec)
* RFC 2710 (Multicast Listener Discovery)
* RFC 3810 (Multicast Listener Discovery Version 2)
* RFC 4861 (Neighbor Discovery)
* RFC 4286 (Multicast Router Discovery)
* RFC 4291 (IPv6 Multicast Addressing)

Example Programs:
* Ping Utility (generates and processes ICMP packets in .Net - works on all platforms)
* NeighborDiscovery (Resolves IPv6 IPs to MAC/physical addresses by querying the network)
* Listener (Promiscuous mode monitoring and logging of all ICMP traffic)