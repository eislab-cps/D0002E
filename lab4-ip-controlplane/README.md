# Lab 4: Network Layer — Control Plane — Kurose/Ross Chapter 5

## Objective

In this lab you will simulate routing algorithms (link-state and distance-vector), OSPF-like behaviour, and ICMP TTL expiry using ns-3. You will observe how routers exchange control packets, how routing tables converge after link failures, and how ICMP Time Exceeded messages are generated.

## What you need

- ns-3.46 built and working (see the root README for setup instructions).
- Wireshark installed ([download](https://www.wireshark.org/download.html)).
- Textbook: Kurose & Ross, *Computer Networking: A Top-Down Approach*, Chapter 5.

## How to run

From the ns-3 root directory (`ns-allinone-3.46.1/ns-3.46.1/`):

```bash
# Build
./ns3 build

# Run individual scenarios
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=lsdv --pcap=1"
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=lsdv --mode=dv --pcap=1"
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=ospf-like --pcap=1"
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=ttl-icmp --pcap=1"
```

Additional options: `--verbose=true`, `--mode=ls` (default) or `--mode=dv`.

**Note:** The `--pcap=1` flag is required to enable PCAP capture.

## How to analyse

Running the simulation produces `.pcap` files in the `scratch/d0002e/lab 4 output/` directory (relative to the ns-3 root), organised in subfolders by scenario (`lsdv/`, `ospf-like/`, `ttl-icmp/`). Open the `.pcap` files in Wireshark. Useful display filters:

- `rip` — show RIP (distance-vector) updates
- `udp.port==50001` — show LSA packets in the OSPF-like scenario
- `icmp.type==11` — show ICMP Time Exceeded messages

---

## Questions

### Routing Algorithms: Link-State vs Distance-Vector

1. [C] Which routing algorithm is configured in the script for each scenario?
2. [W] After a link failure event, do routing control packets appear in the PCAP?
3. [B] Compare convergence behavior after a link failure in LS and DV.
4. [V] According to Chapter 5, why does LS typically converge faster than DV?

### OSPF-like Behavior (Intra-AS Routing)

5. [C] Where in the script are link weights configured?
6. [W] Do routers exchange periodic control packets even without topology changes?
7. [V] Why does OSPF flood link-state information throughout the AS?

### ICMP: TTL Expiry and Error Messages

8. [C] How is the initial TTL value set in the simulation?
9. [W] What ICMP message is generated when TTL reaches zero?
10. [W] What protocol number identifies ICMP in the IPv4 header?
11. [B] Which router generates the ICMP Time Exceeded message?
12. [W] Does the ICMP message include part of the original datagram?

---

## Tag legend

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`lab4-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations
