# Lab 5: Link Layer and LANs — Kurose/Ross Chapter 6

## Objective

In this lab you will simulate Ethernet, ARP, switch MAC-learning, CRC error detection, and VLAN tagging using ns-3. You will capture and analyse link-layer frames in Wireshark to understand how MAC addresses are used, how ARP resolves IP-to-MAC mappings, how switches learn forwarding tables, and how VLANs segment broadcast domains.

## What you need

- ns-3.46 built and working (see the root README for setup instructions).
- Wireshark installed ([download](https://www.wireshark.org/download.html)).
- Textbook: Kurose & Ross, *Computer Networking: A Top-Down Approach*, Chapter 6.

## How to run

From the ns-3 root directory (`ns-allinone-3.46.1/ns-3.46.1/`):

```bash
# Use your lab group number as the seed
GROUP=42

# Build
./ns3 build

# Run individual scenarios
./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=ethernet-basic --seed=$GROUP"
./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=arp --seed=$GROUP"
./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=switch-learning --seed=$GROUP"
./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=crc --seed=$GROUP"
./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=vlan --seed=$GROUP"

# Example parameter experiments
./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=crc --errorRate=0.05 --seed=$GROUP"
./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=crc --errorRate=0.30 --seed=$GROUP"

# Run all scenarios at once
./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=all --seed=$GROUP"
```

Additional options: `--pcap=0`, `--verbose=1`, `--seed=<group-number>`, `--errorRate=0.10`.

PCAP capture is enabled by default. Use the same seed to reproduce the same run; different seeds change timing slightly and write to separate `seed<N>/` output folders.

## How to analyse

Running a single scenario writes `.pcap` files to `scratch/d0002e/lab 5 output/seed<group>/` (relative to the ns-3 root). Running `--scenario=all` creates one subfolder per scenario under the same seed directory. Each output folder also contains `netanim.xml` for NetAnim. Open the `.pcap` files in Wireshark. Useful display filters:

- `eth` — Ethernet headers
- `arp` — ARP packets; `arp.opcode==1` for requests, `arp.opcode==2` for replies
- `eth.dst == ff:ff:ff:ff:ff:ff` — broadcast frames
- `vlan` — 802.1Q VLAN-tagged frames; `vlan.id==10` for VLAN 10

For the switch-learning scenario, compare `sw-observer*.pcap` (sees flooded traffic only) with `sw-target*.pcap` (sees all data).
For CRC, compare `crc-sender*.pcap` vs `crc-receiver*.pcap` (receiver has fewer packets due to error-model drops).

---

## Questions

### Basic Ethernet Frame Structure

1. [W] What are the source and destination MAC addresses in the first Ethernet frame?
2. [V] What EtherType value is used for IPv4?
3. [W] What is the total length of the Ethernet frame (excluding preamble)?
4. [V] Why is the minimum Ethernet payload 46 bytes?

### ARP Resolution

5. [W] What is the destination MAC address in the ARP Request?
6. [W] What opcode value is used for ARP Request and ARP Reply?
7. [B] Why does the ARP Request use a broadcast MAC address?
8. [B] Does the ARP Reply use broadcast or unicast?
9. [V] Why is ARP needed before sending the first IP packet?

### Switch Forwarding and MAC Learning

10. [W] Is the first frame forwarded as broadcast or selective unicast?
11. [B] Why does the switch flood the first frame?
12. [W] Are subsequent frames forwarded only to one output port?
13. [V] How does a switch learn MAC addresses?

### Ethernet CRC and Error Detection

14. [V] What error-detection mechanism is used in Ethernet?
15. [C] Is CRC computation implemented in the application code?

### VLAN Tagging

16. [V] Why are VLANs used in LANs?

---

## Tag legend

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`lab5-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations
