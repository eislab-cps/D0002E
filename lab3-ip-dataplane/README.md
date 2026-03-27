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
# Use your lab group number as the seed
GROUP=42

# Build
./ns3 build

# Run individual scenarios
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=basic-forwarding --seed=$GROUP"
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=fragmentation --seed=$GROUP"
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=routing --seed=$GROUP"
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=ttl-expiry --seed=$GROUP"

# Example parameter experiments
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=fragmentation --packetSize=600 --seed=$GROUP"
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=fragmentation --packetSize=3500 --mtu=576 --seed=$GROUP"

# Run all scenarios at once
./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=all --seed=$GROUP"
```

Additional options: `--pcap=0`, `--verbose=true`, `--packetSize=3500`, `--mtu=1500`, `--seed=<group-number>`.

PCAP capture is enabled by default. Use the same seed to reproduce the same run; different seeds change timing slightly and write to separate `seed<N>/` output folders.

## How to analyse

Running a single scenario writes capture files to `scratch/d0002e/lab 3 output/seed<group>/` (relative to the ns-3 root). Running `--scenario=all` creates one subfolder per scenario under the same seed directory. Capture files include `client-0-0.pcap`, `router*-0-0.pcap`, and `server-0-0.pcap`. Each output folder also contains `netanim.xml` for NetAnim. Open these in Wireshark. Useful display filters:

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
7. [B+X] How many IP fragments are generated for the large packet under different conditions?

Hint (7): Consider varying the datagram size from slightly above the MTU to significantly larger values (e.g., a few hundred bytes above up to several times the MTU) using a parameter such as --packetSize. You may also explore different MTU values using --mtu.

8. [W+X] Which fields in the IP header indicate that fragmentation has occurred?

Hint (8): Observe how these fields change when the packet size exceeds the MTU (controlled via --packetSize and --mtu).

9. [W+X] How can you identify the last fragment of a fragmented datagram?

Hint (9): Compare fragments generated under different packet sizes (via --packetSize) and observe how specific header flags differ between fragments.

10. [V+X] Why must fragment offsets be multiples of 8 bytes?

Hint (10): Examine how fragment sizes and offsets relate when varying packet size and MTU (e.g., using --packetSize and --mtu), and relate this to alignment constraints in IPv4.


---

## Tag legend

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`lab3-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations
- `[_+X]` — In addtion to what is instructed at "_", experiment with different input parameters
