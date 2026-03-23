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

# Run individual scenarios
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=basic"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=conditional"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=long"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=embedded --parallel=false"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=embedded --parallel=true"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=auth"
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=dns"

# Run all scenarios at once
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=all"
```

Additional options: `--verbose=true`, `--dnsTTL=300`, `--mss=536`.

## How to analyse

Running the simulation produces `.pcap` files in the `scratch/d0002e/lab 1 output/` directory (relative to the ns-3 root). Open these files in Wireshark (File > Open or Ctrl+O). Key capture files include `client-*.pcap`, `dns-server-*.pcap`, and `http-server1-*.pcap`.

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
25. [C] How would lowering TTL affect observed traffic?

---

## Tag legend

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`lab1-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations
