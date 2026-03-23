# Lab 3: Network Layer — Data Plane — Kurose/Ross Chapter 4

## Objective

In this lab you will simulate IPv4 forwarding and fragmentation using ns-3 and analyse the results in Wireshark. You will observe how packets are forwarded hop-by-hop through routers, how the TTL field changes, and how large datagrams are fragmented when they exceed a link's MTU.

## What you need

- ns-3.46 built and working (see the root README for setup instructions).
- Wireshark installed ([download](https://www.wireshark.org/download.html)).
- Textbook: Kurose & Ross, *Computer Networking: A Top-Down Approach*, Chapter 4.

## How to run

From the ns-3 root directory (`ns-allinone-3.46.1/ns-3.46.1/`):

```bash
# Build
./ns3 build

# Run individual scenarios
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=basic-forwarding --pcap=1"
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=fragmentation --pcap=1"
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=routing --pcap=1"
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=ttl-expiry --pcap=1"

# Run all scenarios at once
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=all --pcap=1"
```

Additional options: `--verbose=true`, `--packetSize=3500`, `--mtu=1500`.

**Note:** The `--pcap=1` flag is required to enable PCAP capture.

## How to analyse

Running the simulation produces `.pcap` files in the `scratch/d0002e/lab 3 output/` directory (relative to the ns-3 root). Capture files include `client-0-0.pcap`, `router*-0-0.pcap`, and `server-0-0.pcap`. Open these in Wireshark. Useful display filters:

- `ip.flags.mf || ip.frag_offset > 0` — show fragmented packets
- `icmp.type == 11` — show ICMP Time Exceeded messages

---

## Questions

### Basic IPv4 Forwarding

1. [C] What are the IPv4 addresses assigned to each interface in the topology?
2. [B] What is the TTL value set in the first ICMP Echo Request transmitted by the source node?
3. [W] What protocol number is shown in the IPv4 header for the ICMP Echo Request?
4. [B] Does the TTL field change as the packet traverses routers? Explain.
5. [W] What is the value of the Header Length field (IHL) in the IPv4 header?

### IPv4 Fragmentation

6. [C] What packet size is configured in the script to trigger IPv4 fragmentation?
7. [B] How many IP fragments are generated for the large packet?
8. [W] Which fields in the IP header indicate that fragmentation has occurred?
9. [W] How can you identify the last fragment of a fragmented datagram?
10. [V] Why must fragment offsets be multiples of 8 bytes?

---

## Tag legend

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`lab3-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations
