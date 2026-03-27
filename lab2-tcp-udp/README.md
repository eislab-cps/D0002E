# Lab 2: TCP and UDP — Kurose/Ross Chapter 3

## Objective

In this lab you will simulate TCP and UDP traffic using ns-3, then analyse the captured packets in Wireshark. You will observe TCP connection establishment, data segmentation, retransmission under loss, and congestion control behaviour. You will also compare TCP with the simpler, connectionless UDP protocol.

## What you need

- ns-3.46 built and working (see the root README for setup instructions).
- Wireshark installed ([download](https://www.wireshark.org/download.html)).
- Textbook: Kurose & Ross, *Computer Networking: A Top-Down Approach*, Chapter 3.

## How to run

From the ns-3 root directory (`ns-allinone-3.46.1/ns-3.46.1/`):

```bash
# Use your lab group number as the seed
GROUP=42

# Build
./ns3 build

# Run individual scenarios
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-handshake --seed=$GROUP"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-data --seed=$GROUP"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-loss --seed=$GROUP"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-congestion --seed=$GROUP"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=udp-basic --seed=$GROUP"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=udp-loss --seed=$GROUP"

# Example parameter experiments
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-data --payloadSize=100000 --seed=$GROUP"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-congestion --lossRate=0.01 --seed=$GROUP"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=udp-basic --linkDelay=50ms --seed=$GROUP"

# Run all scenarios at once
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=all --seed=$GROUP"
```

Additional options: `--verbose=true`, `--payloadSize=50000`, `--lossRate=0.05`, `--linkDelay=2ms`, `--serverPort=5001`, `--seed=<group-number>`.

Use the same seed to reproduce the same run. Different seeds change timing slightly and write to separate `seed<N>/` output folders.

## How to analyse

Running a single scenario writes `.pcap` files to `scratch/d0002e/lab 2 output/seed<group>/` (relative to the ns-3 root). Running `--scenario=all` creates one subfolder per scenario under the same seed directory. Each output folder also contains `netanim.xml` for NetAnim. Open the `.pcap` files in Wireshark. For congestion control analysis, use Wireshark's Statistics > TCP Stream Graphs > Time-Sequence Graph (Stevens).

---

## Questions

### TCP Connection Establishment

1. [V] Which TCP flags are set in the first three segments of the connection?
2. [W] What are the initial sequence numbers (raw, not relative) chosen by client and server?
3. [B] How is the server port number determined?
4. [C] Where in the code is the TCP socket created and connected?

### TCP Data Transfer and Segmentation

5. [W+X] How many TCP segments carry application data from client to server for different payload sizes?

Hint (5): Consider varying the application data size over a small-to-large range (e.g., a few KB up to hundreds of KB) using a parameter such as --payloadSize.

6. [T] Why is the application data divided into multiple TCP segments?
7. [W+X] What is the advertised receiver window size in the first ACK, and does it change with different payload sizes or transmission conditions?

Hint (7): Observe how this value behaves when increasing the payload size and/or modifying traffic intensity (e.g., via --payloadSize).

### TCP Reliability and Retransmission

8. [W+X] Are any TCP segments retransmitted under different packet loss conditions? How can this be verified?

Hint (8): Introduce packet loss over a range from very low to moderate levels (e.g., around 1–10%) using a parameter such as --lossRate.

9. [W+X] What event likely caused the retransmission (timeout or duplicate ACKs), and how does this change as loss increases?

Hint (9): Compare behavior at lower versus higher loss rates (controlled via --lossRate) and look for patterns in ACK sequences.

10. [W+X] What is the sequence number of the first retransmitted segment, and does it vary across different runs or loss conditions?

Hint (10): Repeat experiments with different loss levels and optionally different seeds (e.g., --seed) to observe variability.

### TCP Flow and Congestion Control

11. [W+X] At what point does congestion avoidance begin, and how does this change under different network conditions?

Hint (11): Explore scenarios with increasing packet loss (e.g., low to moderate loss using --lossRate) and/or different delays if available.

12. [B+X] How does induced packet loss affect the congestion window evolution (e.g., slow start vs congestion avoidance behavior)?

Hint (12): Compare congestion window behavior across runs with different loss levels (controlled via --lossRate), and observe transitions between phases.

13. [C] Which TCP variant is configured in the script (e.g., NewReno)?

### Basic UDP Transmission

14. [V] How many fields are present in the UDP header? Name them.
15. [W] What is the protocol number for UDP in the IP header?
16. [B] How is the UDP destination port determined?

### UDP Loss Behavior

17. [W+X] Are lost UDP packets retransmitted under different packet loss conditions?

Hint (17): Apply a range of loss rates (e.g., from near-zero up to noticeable levels such as 1–10%) using --lossRate and compare sent vs received packets.

18. [B] Compare UDP and TCP behavior under identical packet loss conditions.

### Conceptual Comparison

19. [B] Compare TCP and UDP in terms of reliability, flow control, and congestion control based on your observations.

---

## Tag legend

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`lab2-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations
- `[_+X]` — In addtion to what is instructed at "_", experiment with different input parameters
