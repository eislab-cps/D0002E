# Lab 6: Transport Layer Security (TLS) — Kurose/Ross Chapter 8

## Objective

In this lab you will simulate a TLS 1.2 handshake and encrypted data exchange using ns-3. You will observe TLS handshake messages, server certificate contents, cipher suite negotiation, and the encryption of application data. You will also examine how TLS relies on TCP for reliable transport.

## What you need

- ns-3.46 built and working (see the root README for setup instructions).
- Wireshark installed ([download](https://www.wireshark.org/download.html)).
- Textbook: Kurose & Ross, *Computer Networking: A Top-Down Approach*, Chapter 8.

## How to run

From the ns-3 root directory (`ns-allinone-3.46.1/ns-3.46.1/`):

```bash
# Use your lab group number as the seed
GROUP=42

# Build
./ns3 build

# Run individual scenarios
./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=handshake --seed=$GROUP"
./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=certificate --seed=$GROUP"
./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=data --seed=$GROUP"
./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=cipher --seed=$GROUP"
./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=tls-tcp --seed=$GROUP"

# Example parameter experiments
./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=cipher --cipher256=1 --seed=$GROUP"
./ns3 run "scratch/d0002e/lab6-with-guidance --tlsTcp=1 --seed=$GROUP"

# Run all scenarios at once
./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=all --seed=$GROUP"
```

Additional options: `--pcap=0`, `--cipher256=1`, `--tlsTcp=1`, `--seed=<group-number>`.

PCAP capture is enabled by default. The executable name is `lab6-with-guidance`, but the output directory still uses the historical `lab 7` name.

## How to analyse

Running the simulation produces `.pcap` files in `scratch/d0002e/lab 7 output/seed<group>/<scenario>/` (relative to the ns-3 root). Each scenario folder also contains `netanim.xml` for NetAnim. Open the `-0-0.pcap` file (server-side capture) in Wireshark. The display filter `tls` shows TLS records. Wireshark's TLS dissector recognises TLS 1.2 records by ContentType and ProtocolVersion fields in the record header.

---

## Questions

### Basic TLS Handshake

1. [W] Which TLS handshake messages are exchanged before encrypted application data is sent?
2. [W] What version of TLS is negotiated?
3. [V] Why does TLS use a handshake phase before sending application data?

### Server Authentication and Certificates

4. [W] What information can be extracted from the server certificate in Wireshark?
5. [B] Does the certificate contain a public key and how is it used?
6. [V] Why is public key cryptography used only during the handshake phase?

### Encrypted Application Data

7. [W] Can the HTTP payload be read directly in Wireshark after the TLS handshake?
8. [B] How can you identify that application data is encrypted?
9. [V] Why does TLS provide confidentiality and integrity for application data?

### Key Exchange and Cipher Suites

10. [W+X] Which cipher suite is negotiated between client and server?

Hint (10): Compare different runs using stronger or alternative cipher configurations (e.g., enabling a higher-security option such as --cipher256). Observe how the negotiated cipher suite changes in the ServerHello message.

11. [V] Why is symmetric cryptography preferred for bulk data encryption in TLS?

### TLS and TCP Interaction

12. [W+X] Does TLS run directly over IP or over TCP?

Hint (12): Compare different scenarios (e.g., standard TLS communication vs variations such as --tlsTcp) and observe whether a TCP handshake precedes TLS records in the packet trace.

13. [V] Why does TLS rely on TCP rather than UDP for reliable transport?

---

## Tag legend

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`lab6-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations
- `[_+X]` — In addtion to what is instructed at "_", experiment with different input parameters
