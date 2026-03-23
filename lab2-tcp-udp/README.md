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
# Build
./ns3 build

# Run individual scenarios
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-handshake"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-data"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-loss"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-congestion"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=udp-basic"
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=udp-loss"

# Run all scenarios at once
./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=all"
```

Additional options: `--verbose=true`, `--payloadSize=50000`, `--lossRate=0.05`.

## How to analyse

Running the simulation produces `.pcap` files in the `scratch/d0002e/lab 2 output/` directory (relative to the ns-3 root). Each scenario creates `client-0-0.pcap` and `server-0-0.pcap`. Open these in Wireshark. For congestion control analysis, use Wireshark's Statistics > TCP Stream Graphs > Time-Sequence Graph (Stevens).

---

## Questions

### TCP Connection Establishment

1. [V] Which TCP flags are set in the first three segments of the connection?
2. [W] What are the initial sequence numbers (raw, not relative) chosen by client and server?
3. [B] How is the server port number determined?
4. [C] Where in the code is the TCP socket created and connected?

### TCP Data Transfer and Segmentation

5. [W] How many TCP segments carry application data from client to server?
6. [T] Why is the application data divided into multiple TCP segments?
7. [W] What is the advertised receiver window size in the first ACK?

### TCP Reliability and Retransmission

8. [W] Are any TCP segments retransmitted? How can this be verified?
9. [W] What event likely caused the retransmission (timeout or duplicate ACKs)?
10. [W] What is the sequence number of the first retransmitted segment?

### TCP Flow and Congestion Control

11. [W] At what point does congestion avoidance begin?
12. [B] How does induced packet loss affect the congestion window?
13. [C] Which TCP variant is configured in the script (e.g., NewReno)?

### Basic UDP Transmission

14. [V] How many fields are present in the UDP header? Name them.
15. [W] What is the protocol number for UDP in the IP header?
16. [B] How is the UDP destination port determined?

### UDP Loss Behavior

17. [W] Are lost UDP packets retransmitted?
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
