# D0002E Computer Networking — Lab Simulations

Luleå University of Technology

This repository contains ns-3 simulation scripts and lab questions for 6 labs covering Chapters 2--6 and 8 of Kurose & Ross, *Computer Networking: A Top-Down Approach* (8th edition). Each lab generates PCAP files that you analyse in Wireshark to answer questions about network protocol behaviour.

## Prerequisites

- **Textbook:** Kurose & Ross, *Computer Networking: A Top-Down Approach*, 8th edition. Chapter numbers may vary between editions.
- **Wireshark:** Free packet analyser. Download from <https://www.wireshark.org/download.html>.
- **ns-3.46:** Network simulator. Setup instructions below.

## ns-3 setup

### System requirements

Linux is required. Ubuntu 22.04 or 24.04 are recommended and known to work.

### Install dependencies

```bash
sudo apt install g++ python3 cmake ninja-build git
```

### Download and build ns-3

```bash
# Download ns-allinone-3.46.1
wget https://www.nsnam.org/releases/ns-allinone-3.46.1.tar.bz2
tar xvf ns-allinone-3.46.1.tar.bz2
cd ns-allinone-3.46.1/ns-3.46.1

# Configure and build
./ns3 configure --enable-examples
./ns3 build
```

### Place the lab files

The simulation files must be placed in the `scratch/d0002e/` directory inside the ns-3 tree. Create the directory and copy the contents of this repository into it:

```bash
# From the ns-3 root (ns-allinone-3.46.1/ns-3.46.1/):
mkdir -p scratch/d0002e

# Copy everything from this repository into that directory:
cp -r /path/to/this/repo/* scratch/d0002e/
```

After copying, the structure inside ns-3 should look like:

```
ns-3.46.1/scratch/d0002e/
  CMakeLists.txt
  lab1-http-dns/lab1-with-guidance.cc
  lab2-tcp-udp/lab2-with-guidance.cc
  lab3-ip-dataplane/lab3-with-guidance.cc
  lab4-ip-controlplane/lab4-with-guidance.cc
  lab5-link-layer/lab5-with-guidance.cc
  lab6-tls/lab6-with-guidance.cc
```

Then rebuild ns-3 so it picks up the new targets:

```bash
./ns3 configure --enable-examples
./ns3 build
```

### Verify the install

```bash
# Run a default ns-3 example to check everything works:
./ns3 run first

# Then try one of the lab simulations:
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=basic"
```

## Repository structure

```
README.md                              ← This file
CMakeLists.txt                         ← ns-3 build configuration for all labs
.gitignore
lab1-http-dns/
  README.md                            ← Lab 1 instructions and questions
  lab1-with-guidance.cc                ← Lab 1 simulation source
lab2-tcp-udp/
  README.md                            ← Lab 2 instructions and questions
  lab2-with-guidance.cc                ← Lab 2 simulation source
lab3-ip-dataplane/
  README.md                            ← Lab 3 instructions and questions
  lab3-with-guidance.cc                ← Lab 3 simulation source
lab4-ip-controlplane/
  README.md                            ← Lab 4 instructions and questions
  lab4-with-guidance.cc                ← Lab 4 simulation source
lab5-link-layer/
  README.md                            ← Lab 5 instructions and questions
  lab5-with-guidance.cc                ← Lab 5 simulation source
lab6-tls/
  README.md                            ← Lab 6 instructions and questions
  lab6-with-guidance.cc                ← Lab 6 simulation source
archive/
  questionsSubset_Eric.md              ← Original question source (not needed for labs)
```

## Lab overview

| Lab | Topic | Chapter | Questions |
|-----|-------|---------|-----------|
| 1 | HTTP and DNS | 2 | 25 |
| 2 | TCP and UDP | 3 | 19 |
| 3 | IP Data Plane | 4 | 10 |
| 4 | IP Control Plane | 5 | 12 |
| 5 | Link Layer and LANs | 6 | 16 |
| 6 | Transport Layer Security | 8 | 13 |
| **Total** | | | **95** |

## Tag legend

Each question is tagged to indicate how it should be answered:

- `[W]` — Answer using Wireshark capture analysis
- `[C]` — Answer by reading the simulation source code (`labN-with-guidance.cc`)
- `[B]` — Answer using both Wireshark and source code
- `[T]` — Answer from textbook theory
- `[V]` — Verify Wireshark observations against textbook explanations

## How to work through a lab

1. Read the lab README in the corresponding directory.
2. Read the `.cc` source file — the comments at the top describe the network topology, available scenarios, and expected output.
3. Build and run the simulation using the commands shown in the lab README.
4. Open the generated `.pcap` files in Wireshark.
5. Answer the questions using the approach indicated by each question's tag.
