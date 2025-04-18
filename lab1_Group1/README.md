## Protocol Compliance and Scalability

This controller-based router implementation follows the protocol specifications outlined in:

- RFC 826 (Address Resolution Protocol): ARP requests and replies are handled dynamically to resolve IP-to-MAC mappings.
- RFC 791 (Internet Protocol): IPv4 forwarding is implemented based on destination IP subnets. Each host can reach its own gateway, and filtering rules enforce secure inter-subnet communication.

Features:
- Subnet-aware routing and MAC learning
- ARP-based forwarding with queuing for unresolved MACs
- OpenFlow-based flow installation to offload repeated traffic from the controller

Limitations:
- TTL is not decremented (can be added for full RFC 791 compliance)
- ICMP error handling (e.g., TTL exceeded) is not implemented
- ARP responses are not validated for spoofing

While designed for a small emulated lab environment, this controller-based architecture can be extended for distributed control, load balancing, and replication. ARP state, flow rules, and filtering logic can be pushed closer to the data plane to improve performance and fault tolerance in large-scale deployments.

Written by Jakob Al Khuzayi, see Git history for full contributions.