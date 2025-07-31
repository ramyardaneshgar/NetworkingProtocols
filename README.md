# NetworkingProtocols

Packet-level walkthrough of core networking protocols (DHCP, ARP, ICMP, Routing, NAT) with security analysis, diagnostics, and mitigation techniques using tcpdump, Wireshark, and traceroute.

By Ramyar Daneshgar

---

## Task 2 – DHCP: Dynamic Host Configuration Protocol

### Objective

My goal in this task was to understand how devices on a network obtain their Layer 3 configuration automatically using DHCP. This includes the IP address, subnet mask, default gateway, and DNS server. In enterprise environments and public networks such as coffee shops, DHCP is the protocol responsible for assigning each client a unique IP address dynamically without manual intervention.

### Analysis

I reviewed a packet capture (`DHCP-G5000.pcap`) and used `tshark` to examine the four-step DORA sequence, which stands for Discover, Offer, Request, and Acknowledge. This sequence allows a client to find a DHCP server, receive an IP configuration, and formally accept it. I validated each step based on UDP port behavior and IP addressing.

**Step-by-step behavior**:

1. **Discover**: The client sends a broadcast from `0.0.0.0` to `255.255.255.255` over UDP port 68. Because the client does not yet have an IP address, the message is sent using Layer 2 and Layer 3 broadcast values.
2. **Offer**: The DHCP server responds to the client's MAC address with an IP address offer using UDP port 67.
3. **Request**: The client sends another broadcast explicitly requesting the offered IP, including the server’s identifier in the payload.
4. **Acknowledge**: The server confirms the IP lease, and the client finalizes its network configuration.

### Command Used

```bash
tshark -r DHCP-G5000.pcap -n
```

### Security Implications

DHCP is vulnerable by design because it lacks authentication. A malicious actor could deploy a rogue DHCP server to assign false gateways or DNS servers. This could lead to DNS hijacking, interception of HTTP traffic, or full redirection of traffic via a controlled router. Attacks like DHCP starvation can exhaust the DHCP address pool and prevent legitimate clients from joining the network. In high-security environments, features such as DHCP snooping and port-based ACLs are necessary to restrict DHCP responses to trusted interfaces.

---

## Task 3 – ARP: Bridging Layer 3 to Layer 2

### Objective

Here I examined the Address Resolution Protocol (ARP), which operates between the Internet Layer and the Data Link Layer. When a host knows the IP address of a destination within the same broadcast domain but does not know the destination MAC address, it uses ARP to retrieve that information and construct a valid Ethernet frame.

### Analysis

I used `tcpdump` to analyze an ARP exchange where a host at `192.168.66.89` needed to send data to `192.168.66.1`. The host sent an ARP request frame to the broadcast MAC address, asking "Who has 192.168.66.1?" The system at that address replied with its MAC address `44:df:65:d8:fe:6c`.

This exchange does not involve IP or UDP encapsulation. ARP requests and replies are transmitted directly over Ethernet using EtherType `0x0806`.

### Command Used

```bash
tcpdump -r arp.pcapng -n -v
```

### Security Implications

ARP is stateless and lacks any authentication, which makes it highly susceptible to ARP poisoning. In an ARP poisoning attack, an adversary can respond to ARP requests with their own MAC address, impersonating other systems such as the gateway. This enables man-in-the-middle attacks or traffic redirection. To mitigate this, dynamic ARP inspection (DAI) should be configured on managed switches, and systems should be monitored for sudden changes in ARP cache entries.

---

## Task 4 – ICMP: Troubleshooting Networks

### Objective

I focused on how ICMP supports connectivity testing and path discovery. ICMP operates within the Internet Layer and is not used for application data transport, but rather for network diagnostics, such as confirming reachability or understanding routing paths.

### Analysis

I used `ping` to send ICMP Echo Requests to `192.168.11.1`. I observed that the host replied with ICMP Echo Replies, each containing a TTL (Time to Live) and round-trip time, which helped confirm bidirectional communication. I also executed `traceroute` to discover the path between my machine and `example.com`. This tool works by sending packets with increasing TTL values and capturing ICMP Time Exceeded messages from each router that discards the packet.

### Commands Used

```bash
ping 192.168.11.1 -c 4
traceroute example.com
```

### Security Implications

Although ICMP is critical for diagnostics, attackers often use it for reconnaissance. Tools such as Nmap use ICMP Echo Requests to identify live hosts during scanning. ICMP can also be used in covert channels, including data exfiltration using ICMP tunnels. Firewalls should log ICMP traffic and apply rate limiting or filtering where appropriate, without completely disabling ICMP since doing so would obstruct legitimate operational monitoring.

---

## Task 5 – Routing

### Objective

I reviewed how routers forward packets across networks and how they determine optimal paths using routing protocols. Routing is essential for scalability, efficiency, and resilience in both enterprise and internet-wide environments.

### Protocols Analyzed

* **OSPF (Open Shortest Path First)**: A link-state protocol where each router advertises its local topology via Link State Advertisements (LSAs). Each router builds a complete view of the network and uses Dijkstra’s algorithm to calculate the shortest path.
* **EIGRP (Enhanced Interior Gateway Routing Protocol)**: A Cisco-specific protocol that combines distance-vector and link-state principles. It uses a composite metric based on bandwidth and delay, and maintains backup paths for fast convergence.
* **BGP (Border Gateway Protocol)**: Used between autonomous systems (such as different Internet Service Providers). BGP decisions are made using policy-driven attributes like AS-Path, Local Preference, and MED (Multi-Exit Discriminator).
* **RIP (Routing Information Protocol)**: A legacy distance-vector protocol where routers periodically broadcast their entire routing table. It uses hop count as its sole metric and caps at 15 hops, which limits its use in large networks.

### Security Implications

Routing protocols can be attacked via route injection or manipulation. For example, BGP hijacking has been used to redirect internet traffic through malicious networks. All routing protocols should be configured with authentication mechanisms such as MD5 hashing for OSPF or TCP MD5 signatures for BGP. Route filtering and prefix validation are also important defenses.

---

## Task 6 – NAT: Network Address Translation

### Objective

I examined how Network Address Translation allows multiple devices in a private network to share a single public IPv4 address. NAT is crucial in conserving IP address space and adds an abstraction layer between internal systems and the public internet.

### Analysis

I reviewed a diagram in which multiple internal devices used the same external IP (`212.3.4.5`) to communicate with the internet. Each internal device had its source IP and port mapped to a unique public port by the NAT router. This method, known as Port Address Translation (PAT), allows thousands of simultaneous connections to be tracked.

### Key Concept

TCP uses 16-bit source ports. This results in 65,536 possible values per source IP address. Excluding well-known ports and reserved system ranges, a router can realistically track approximately 60,000 concurrent outbound TCP connections per public IP address.

### Security Implications

NAT does not provide security by itself. It simply masks internal IP addresses. Attackers cannot initiate inbound connections through NAT without explicit port forwarding, but traffic initiated from inside is still subject to compromise. Stateful firewalls and proper egress filtering must be implemented in NAT environments. NAT traversal techniques like STUN, TURN, and UPnP must be tightly controlled, as they can re-open internal hosts to the internet.

# Lessons Learned

## 1. DHCP – Dynamic Host Configuration Protocol

- DHCP automates IP address assignment and reduces manual configuration errors and conflicts in dynamic or large-scale networks.
- The DORA process (Discover, Offer, Request, Acknowledge) facilitates seamless IP allocation without requiring static configuration.
- DHCP uses broadcast traffic and lacks authentication, making it vulnerable to:
  - **Rogue DHCP servers** distributing malicious configurations.
  - **DHCP starvation attacks** exhausting available leases.
- Defensive measures:
  - Enable **DHCP snooping** on switches.
  - Enforce **trusted ports** for DHCP responses.
  - Monitor leases and assign static IPs for critical infrastructure.

---

## 2. ARP – Address Resolution Protocol

- ARP resolves IP addresses to MAC addresses for local communication on Ethernet/Wi-Fi networks.
- It operates at Layer 2 with no authentication, making it susceptible to:
  - **ARP poisoning attacks** used for traffic redirection and Man-in-the-Middle (MitM) attacks.
- ARP replies can be forged and injected into a network without verification.
- Defensive measures:
  - Implement **Dynamic ARP Inspection (DAI)**.
  - Use **static ARP entries** for critical hosts.
  - Monitor ARP cache changes for anomalies.

---

## 3. ICMP – Internet Control Message Protocol

- ICMP enables essential diagnostics such as host reachability and network path discovery using:
  - **Ping** (Echo Request/Reply – Types 8 and 0)
  - **Traceroute** (Time Exceeded – Type 11)
- ICMP is often abused in:
  - **Reconnaissance scans** to discover live hosts.
  - **ICMP tunneling** for data exfiltration or C2 channels.
- While ICMP blocking enhances security, over-restricting it can break network diagnostics.
- Defensive measures:
  - Apply **rate limiting** and **logging**.
  - Allow only necessary ICMP types through firewalls.

---

## 4. Routing Protocols – OSPF, EIGRP, BGP, RIP

- Routing protocols allow routers to exchange topology data and determine the best forwarding paths.
- Key distinctions:
  - **OSPF**: Link-state, fast convergence, suitable for hierarchical enterprise networks.
  - **EIGRP**: Cisco proprietary, composite metric based on bandwidth/delay, fast failover.
  - **BGP**: Border routing between autonomous systems, path-vector, policy-based.
  - **RIP**: Legacy protocol, hop count-based, max 15 hops, not suitable for large networks.
- Common attacks include:
  - **BGP hijacking**
  - **OSPF LSA injection**
  - **Unsecured redistribution between protocols**
- Defensive measures:
  - Use **authentication** (MD5/SHA) for routing updates.
  - Filter routes using **prefix-lists** or **route-maps**.
  - Apply **route validation** at AS boundaries.

---

## 5. NAT – Network Address Translation

- NAT allows multiple private hosts to share one public IP, preserving IPv4 space and adding abstraction.
- PAT (Port Address Translation) maps internal IP:port pairs to public IP:port pairs, supporting up to ~65,000 concurrent connections per public IP.
- NAT hides internal IPs but does not provide inherent security.
- Risks include:
  - **State table exhaustion attacks**
  - **Unrestricted UPnP or port forwarding** exposing internal hosts
- Defensive measures:
  - Treat NAT as a **translation mechanism**, not a security control.
  - Use **stateful firewalls** to monitor NAT sessions.
  - Disable or tightly control NAT traversal features (STUN, TURN, UPnP).



