# Lab 1: HTTP and DNS — Kurose/Ross Chapter 2

## Objective

In this lab you will run an ns-3 simulation that generates HTTP and DNS traffic, capture the resulting packets, and analyse them in Wireshark. You will study how HTTP requests and responses work (including conditional GETs, long documents, embedded objects, and authentication), and how DNS name resolution operates alongside HTTP.

## What you need

- ns-3.46 built and working (see the root README for setup instructions).
- Wireshark installed ([download](https://www.wireshark.org/download.html)).
- Textbook: Kurose & Ross, *Computer Networking: A Top-Down Approach*, Chapter 2.

## How to run

From the ns-3 root directory (`ns-allinone-3.46.1/ns-3.46.1/`):

```bash
# Build
./ns3 build

# Use your lab group number as the seed
GROUP=42

# Run individual scenarios
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=basic --seed=$GROUP"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=conditional --seed=$GROUP"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=long --seed=$GROUP"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=embedded --parallel=false --seed=$GROUP"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=embedded --parallel=true --seed=$GROUP"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=auth --seed=$GROUP"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=dns --seed=$GROUP"

# Run all scenarios at once
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=all --seed=$GROUP"
```

Additional options: `--verbose=true`, `--dnsTTL=300`, `--mss=536`, `--seed=<group-number>`.

Use the lab group number as the seed. The same seed gives the same run again, while different seeds produce different packet timings and DNS transaction IDs. Output files are prefixed with the seed, for example `seed42-client-0-0.pcap`.

## Optional NetAnim support

The script always produces the seed-prefixed `.pcap` files. It also produces a seed-prefixed NetAnim XML file such as `seed42-netanim.xml` if your ns-3 build includes the `netanim` module.

To enable that XML output, reconfigure ns-3 once and rebuild:

```bash
./ns3 configure --enable-examples --enable-modules="applications;antenna;bridge;buildings;config-store;core;csma;csma-layout;energy;flow-monitor;internet;internet-apps;mobility;netanim;network;nix-vector-routing;point-to-point;point-to-point-layout;propagation;spectrum;stats;traffic-control;virtual-net-device;wifi"
./ns3 build
```

To install the NetAnim GUI itself on Ubuntu, the following worked for us:

```bash
sudo apt update && sudo apt install -y build-essential qt5-default qtchooser qt5-qmake qtbase5-dev-tools git && \
git clone https://gitlab.com/nsnam/netanim.git && \
cd netanim && \
qmake NetAnim.pro && \
make
```

Then open the generated XML file in NetAnim.

## How to analyse

Running the simulation produces `.pcap` files in the `scratch/d0002e/lab 1 output/` directory (relative to the ns-3 root). Open these files in Wireshark (File > Open or Ctrl+O). Key capture files include `seed<group>-client-*.pcap`, `seed<group>-dns-server-*.pcap`, and `seed<group>-http-server1-*.pcap`.

If NetAnim support is enabled, the same directory also contains `seed<group>-netanim.xml`.

---

## Questions

### Basic HTTP GET/Response

1. [W] What HTTP version is used by client and server?
2. [W] What are the IP addresses of client and server?
3. [C] Where in the code is the HTTP request line constructed?
4. [C] How does the client decide which server IP/port to connect to?

### Conditional GET

5. [B] Why does the second GET include If-Modified-Since?
6. [B] Why does the server return 304 Not Modified?
7. [W] Is the response body present in the second response?

### Long Document Retrieval

8. [W] How many TCP segments carry the response body?
9. [B] Why is the response split across multiple TCP segments?
10. [W] What status code is returned?

### Embedded Objects

11. [W] How many GET requests are sent in total?
12. [B] Why are requests sent to two different IP addresses?
13. [B] Are objects fetched serially or in parallel?

### HTTP Authentication

14. [W] What status code is returned for the first request?
15. [B] Why does the second request succeed?
16. [W] What new header appears in the second request?

### Basic DNS Queries

17. [W] Are DNS messages sent over UDP or TCP?
18. [B] What destination port is used for DNS queries?
19. [B] To which IP address is the DNS query sent?
20. [W] Does a DNS query contain answers?

### Query Types

21. [C] Where is the DNS query type (A or NS) selected?

### DNS Caching

22. [C] How does the DNS client cache work?
23. [B] Are new DNS queries issued before fetching embedded objects?

### DNS and HTTP Interaction

24. [C] How is the Transaction ID generated?
25. [X] How would lowering TTL affect observed traffic?

For question 25, recommended TTL values are `300`, `60`, `10`, and `1` seconds.

---

## Tag legend

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`lab1-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations
- `[X]` — Answer by reading the simulation source code and experimenting with different input parameters
