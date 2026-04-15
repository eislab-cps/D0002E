# Lab 4: Network Layer — Control Plane — Kurose/Ross Chapter 5

## Objective

In this lab you will simulate routing algorithms (link-state and distance-vector), OSPF-like behaviour, and ICMP TTL expiry using ns-3. You will observe how routers exchange control packets, how routing tables converge after link failures, and how ICMP Time Exceeded messages are generated. The script supports reproducible seeded runs and a small set of parameter knobs so you can compare outcomes across experiments.

## What you need

- ns-3.46 built and working (see the root README for setup instructions).
- Wireshark installed ([download](https://www.wireshark.org/download.html)).
- Textbook: Kurose & Ross, *Computer Networking: A Top-Down Approach*, Chapter 5.

## How to run

From the ns-3 root directory (`ns-allinone-3.46.1/ns-3.46.1/`):

```bash
# Use your lab group number as the seed throughout the lab
GROUP=42

# Build
./ns3 build

# Link State vs Distance Vector
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=lsdv --mode=ls --seed=$GROUP --pcap=1"
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=lsdv --mode=dv --seed=$GROUP --pcap=1"

# OSPF-like LSA flooding
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=ospf-like --seed=$GROUP --pcap=1"

# TTL and ICMP Time Exceeded
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=ttl-icmp --seed=$GROUP --pcap=1"

# --- Parameter sweep examples (used by Q2, Q11, Q12) ---

# DV-mode convergence experiment (keep r3r4Metric ≤ 12 in DV mode)
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=lsdv --mode=dv --r3r4Metric=5  --seed=$GROUP --pcap=1"

# TTL sweep: shortened list versus the full default list
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=ttl-icmp --ttlList=1,2,3        --seed=$GROUP --pcap=1"
./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=ttl-icmp --ttlList=1,2,3,4,64   --seed=$GROUP --pcap=1"
```

Additional options: `--verbose=true`, `--pingInterval=<seconds>`, `--failureTime=<seconds>`, `--lsaInterval=<seconds>`, `--r2r4Metric=<int>`.

Use the same seed to reproduce an identical run. Different seeds introduce small timing jitter but do not change routing decisions or topology.

**Note:** `--pcap=1` is required to enable PCAP capture.

## How to analyse

Running a scenario writes `.pcap` files to `scratch/d0002e/lab 4 output/` (relative to the ns-3 root), organised in subfolders by scenario (`lsdv/`, `ospf-like/`, `ttl-icmp/`). Each output folder also contains `topology-info.txt` with the effective parameter values used, and the `lsdv/` folder additionally contains `routing-tables.txt` with routing-table snapshots taken before and after the link failure. Useful Wireshark display filters:

- `rip` — RIP (distance-vector) update messages
- `udp.port==50001` — LSA packets in the OSPF-like scenario
- `icmp.type==11` — ICMP Time Exceeded messages

---

## Questions

### Routing Algorithms: Link-State vs Distance-Vector

1. [C] Which routing algorithm is configured in the script for LS mode, and which for DV mode? Name the ns-3 helper class used in each case.

2. [B+X] Run the lsdv scenario in both LS and DV mode. After the R2-R4 link fails, how does convergence differ between the two modes? Compare the `routing-tables.txt` snapshots and any control traffic visible in the PCAP.

   Hint (2): Look for RIP update messages (`rip` filter) in DV mode. In LS mode there are no such messages — check whether pings recover more quickly. Note: for DV mode keep `r3r4Metric ≤ 12`; if `3 + r3r4Metric ≥ 16` (RIP infinity), the backup path via R3 is considered unreachable and DV mode will never converge after the failure.

3. [V] According to Chapter 5, why does link-state routing typically converge faster than distance-vector routing after a topology change?

4. [C] Where in the script is the R2-R4 link failure scheduled? Which function is called, and what arguments does it take?

### OSPF-like Behaviour (Intra-AS Routing)

5. [C] Where in the script are the link costs for the OSPF-like scenario configured? Which port number is used for LSA messages, and why is port 9 intentionally avoided?

6. [W] Open a PCAP from the ospf-like scenario. Do routers send LSA packets even when there is no topology change? How often?

7. [V] Why does OSPF flood link-state information throughout the AS rather than only to direct neighbours?

### ICMP: TTL Expiry and Error Messages

8. [C] How is the initial TTL value set for each test packet in the script? Which ns-3 method call controls this?

9. [W] What ICMP message type and code is generated when a packet's TTL reaches zero at a router?

10. [W] What protocol number appears in the IPv4 Protocol field for an ICMP packet?

11. [B] For TTL=1, TTL=2, and TTL=3 packets, which router generates the ICMP Time Exceeded reply? How can you identify the router from the ICMP source address?

12. [W+X] Run the ttl-icmp scenario with `--ttlList=1,2,3` and then with `--ttlList=1,2,3,4,64`. For the TTL values that reach the destination, what do you observe in the PCAP — is there an ICMP reply?

    Hint (12): Filter `icmp` and compare what appears at the `ttl-icmp-dst` capture point between the two runs.

## Tag legend

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`lab4-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations
- `[_+X]` — In addition to what is instructed at `_`, experiment with different input parameters
